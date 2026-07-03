//! Intruder / fuzzer orchestration: build a request template from a stored flow
//! (or raw bytes), run [`burpwn_proxy::run_attack`] through the proxy's replay
//! transport, and persist the attack + per-payload results to the session store.
//!
//! The engine itself lives in `burpwn_proxy::fuzz` (pure, network-only via the
//! pluggable sender). This module is the glue both the CLI (`fuzz …`) and the MCP
//! tools (`fuzz`, `fuzz_results`) call: it resolves the base request + transport
//! target the way `req replay` does, drives the attack, and writes an `attacks`
//! row plus one `attack_results` row per result.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use burpwn_proxy::{run_attack, AttackMode, FuzzConfig, HttpReplaySender, Template};
use burpwn_store::model::{NewAttack, NewAttackResult, RequestData};
use burpwn_store::Store;

use crate::paths::Paths;

/// Everything needed to launch one attack. The base request is either read from
/// a stored flow (`flow_id`, which also supplies the transport target) or, as an
/// override, raw `request_bytes` (still routed to `flow_id`'s destination).
#[derive(Debug, Clone)]
pub struct FuzzSpec {
    /// Stored flow supplying the base request and transport target (required).
    pub flow_id: i64,
    /// Optional raw request bytes overriding the flow's request as the template.
    pub request_bytes: Option<Vec<u8>>,
    /// Explicit `(start, end)` injection positions into the clean template. When
    /// empty, positions are taken from `marker` (`§…§`) instead.
    pub positions: Vec<(usize, usize)>,
    /// Custom position marker; `None` uses the default `§`.
    pub marker: Option<Vec<u8>>,
    /// The payload set (one list, shared across positions per the engine).
    pub payloads: Vec<Vec<u8>>,
    /// Attack mode.
    pub mode: AttackMode,
    /// Max in-flight requests.
    pub concurrency: Option<usize>,
    /// Pacing delay between launches, in milliseconds.
    pub delay_ms: Option<u64>,
    /// Human-readable attack name.
    pub name: Option<String>,
}

impl Default for FuzzSpec {
    fn default() -> Self {
        Self {
            flow_id: 0,
            request_bytes: None,
            positions: Vec::new(),
            marker: None,
            payloads: Vec::new(),
            mode: AttackMode::Sniper,
            concurrency: None,
            delay_ms: None,
            name: None,
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn open_store(paths: &Paths, session: &str) -> Result<Store> {
    let db = paths.session_db(session);
    Store::open(&db).with_context(|| format!("opening session store {}", db.display()))
}

/// Synthesize raw HTTP/1 request bytes from a stored request (request line +
/// header block + blank line + body), injecting a `Host` header if the recorded
/// block lacks one (h2 captures keep authority as a pseudo-header).
pub fn flow_request_bytes(req: &RequestData) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    let has_host = String::from_utf8_lossy(&req.headers)
        .split(['\r', '\n'])
        .filter_map(|l| l.split_once(':'))
        .any(|(n, _)| n.trim().eq_ignore_ascii_case("host"));
    out.extend_from_slice(&req.headers);
    if !out.ends_with(b"\r\n") && !req.headers.is_empty() {
        out.extend_from_slice(b"\r\n");
    }
    if !has_host && !req.authority.is_empty() {
        out.extend_from_slice(format!("Host: {}\r\n", req.authority).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

/// Build a [`Template`] from clean/marked bytes: explicit `positions` win;
/// otherwise the `§…§` (or custom) markers delimit the positions.
pub fn build_template(bytes: &[u8], positions: &[(usize, usize)], marker: Option<&[u8]>) -> Template {
    if !positions.is_empty() {
        Template::from_offsets(bytes, positions)
    } else {
        Template::parse_with_marker(bytes, marker.unwrap_or(burpwn_proxy::fuzz::DEFAULT_MARKER))
    }
}

/// Run an attack described by `spec` and persist it to the session store,
/// returning a structured summary (the new attack id + a ranked results table).
pub async fn fuzz_run(
    paths: &Paths,
    session: &str,
    spec: FuzzSpec,
    cancel: CancellationToken,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();

    let Some(detail) = reader.get_flow(spec.flow_id)? else {
        bail!("no such flow: {}", spec.flow_id);
    };
    let Some(req) = detail.request.clone() else {
        bail!("flow {} has no recorded request to fuzz", spec.flow_id);
    };

    // Template bytes: the raw override, else synthesized from the flow request.
    let base_bytes = spec
        .request_bytes
        .clone()
        .unwrap_or_else(|| flow_request_bytes(&req));
    let template = build_template(&base_bytes, &spec.positions, spec.marker.as_deref());
    if template.num_positions() == 0 {
        bail!("no injection positions: pass --position start:end pairs or embed § markers");
    }
    if spec.payloads.is_empty() {
        bail!("no payloads: pass --payload <p> (repeatable) or --payloads <file>");
    }

    // Transport target: same resolution as `req replay`.
    let addr: SocketAddr = format!("{}:{}", detail.flow.dst_ip, detail.flow.dst_port)
        .parse()
        .with_context(|| {
            format!(
                "flow {} has an unparseable destination {}:{}",
                detail.flow.id, detail.flow.dst_ip, detail.flow.dst_port
            )
        })?;
    let host = detail
        .flow
        .sni
        .clone()
        .or_else(|| (!req.authority.is_empty()).then(|| req.authority.clone()))
        .or_else(|| detail.flow.authority.clone())
        .unwrap_or_else(|| detail.flow.dst_ip.clone());

    let sender = Arc::new(HttpReplaySender {
        scheme: detail.flow.scheme.clone(),
        sni: host,
        addr,
    });

    let config = FuzzConfig {
        mode: spec.mode,
        concurrency: spec.concurrency.unwrap_or(8).max(1),
        delay: spec.delay_ms.map(Duration::from_millis),
    };

    // Resolve the owning workspace NAME for the attack row.
    let workspace = reader
        .list_workspaces()?
        .into_iter()
        .find(|w| w.id == detail.flow.workspace_id)
        .map(|w| w.name)
        .unwrap_or_else(|| "default".to_string());

    // Persist the attack row up front (status=running) so it's discoverable even
    // if the run is cancelled midway.
    let positions_json = serde_json::to_string(&template.positions)?;
    let config_json = json!({
        "mode": spec.mode,
        "concurrency": config.concurrency,
        "delay_ms": spec.delay_ms,
        "positions": template.num_positions(),
        "payloads": spec.payloads.len(),
    })
    .to_string();
    let name = spec
        .name
        .clone()
        .unwrap_or_else(|| format!("attack on flow {}", spec.flow_id));
    let attack_id = store
        .writer()
        .create_attack(NewAttack {
            workspace,
            name: name.clone(),
            base_flow_id: Some(spec.flow_id),
            positions: positions_json,
            config: config_json,
            status: "running".into(),
            created_ts: now_ms(),
        })
        .await?;

    // Run the attack (baseline-first, bounded concurrency, cancellable).
    let report = run_attack(&template, &spec.payloads, &config, sender, cancel.clone()).await;

    // Persist one row per result.
    for r in &report.results {
        store
            .writer()
            .insert_attack_result(NewAttackResult {
                attack_id,
                payload: serde_json::to_string(&r.payloads).unwrap_or_else(|_| "[]".into()),
                flow_id: None,
                status_code: Some(r.status as i64),
                resp_len: Some(r.resp_len as i64),
                latency_ms: Some(r.latency_ms as i64),
                anomaly_score: Some(r.anomaly),
                ts: now_ms(),
            })
            .await?;
    }

    let final_status = if cancel.is_cancelled() {
        "cancelled"
    } else {
        "done"
    };
    store
        .writer()
        .update_attack_status(attack_id, final_status)
        .await?;

    // Ranked (anomaly desc) results for the summary.
    let mut ranked: Vec<&burpwn_proxy::FuzzResult> = report.results.iter().collect();
    ranked.sort_by(|a, b| {
        b.anomaly
            .partial_cmp(&a.anomaly)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let results_json: Vec<Value> = ranked
        .iter()
        .map(|r| {
            json!({
                "index": r.index,
                "payloads": r.payloads,
                "status": r.status,
                "resp_len": r.resp_len,
                "latency_ms": r.latency_ms,
                "anomaly": r.anomaly,
                "error": r.error,
            })
        })
        .collect();

    Ok(json!({
        "attack_id": attack_id,
        "name": name,
        "base_flow_id": spec.flow_id,
        "mode": spec.mode,
        "positions": report.positions,
        "payloads": report.payloads,
        "status": final_status,
        "baseline": report.baseline.as_ref().map(|b| json!({
            "status": b.status,
            "resp_len": b.resp_len,
            "latency_ms": b.latency_ms,
        })),
        "results": results_json,
    }))
}

/// List stored attacks (optionally by workspace name) with a result count each.
pub fn fuzz_list(paths: &Paths, session: &str, workspace: Option<&str>) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let attacks = reader.list_attacks(workspace)?;
    let rows: Vec<Value> = attacks
        .iter()
        .map(|a| {
            let count = reader.attack_results(a.id).map(|r| r.len()).unwrap_or(0);
            json!({
                "id": a.id,
                "name": a.name,
                "workspace": a.workspace,
                "base_flow_id": a.base_flow_id,
                "status": a.status,
                "results": count,
                "created_ts": a.created_ts,
            })
        })
        .collect();
    Ok(json!({ "attacks": rows, "count": rows.len() }))
}

/// Sort key for [`fuzz_show`].
#[derive(Debug, Clone, Copy)]
pub enum ResultSort {
    /// By anomaly score, descending (default — most interesting first).
    Anomaly,
    /// By status code, ascending.
    Status,
    /// By response length, descending.
    Len,
}

impl ResultSort {
    /// Parse from `--sort`; unknown → `None`.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "anomaly" | "" => Some(Self::Anomaly),
            "status" => Some(Self::Status),
            "len" | "length" | "resp_len" => Some(Self::Len),
            _ => None,
        }
    }
}

/// Show one attack's results, sorted and optionally limited.
pub fn fuzz_show(
    paths: &Paths,
    session: &str,
    attack_id: i64,
    sort: ResultSort,
    limit: Option<usize>,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let Some(attack) = reader.attack_get(attack_id)? else {
        bail!("no such attack: {attack_id}");
    };
    let mut results = reader.attack_results(attack_id)?;
    match sort {
        ResultSort::Anomaly => results.sort_by(|a, b| {
            b.anomaly_score
                .partial_cmp(&a.anomaly_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        ResultSort::Status => results.sort_by_key(|r| r.status_code.unwrap_or(0)),
        ResultSort::Len => results.sort_by(|a, b| b.resp_len.cmp(&a.resp_len)),
    }
    if let Some(n) = limit {
        results.truncate(n);
    }
    Ok(json!({
        "attack": attack,
        "results": results,
        "count": results.len(),
    }))
}

/// Parse a `start:end` position spec into a `(usize, usize)` byte-offset pair.
pub fn parse_position(spec: &str) -> Result<(usize, usize)> {
    let (s, e) = spec
        .split_once(':')
        .or_else(|| spec.split_once('-'))
        .ok_or_else(|| anyhow::anyhow!("position must be start:end, got {spec:?}"))?;
    let start: usize = s
        .trim()
        .parse()
        .with_context(|| format!("invalid position start in {spec:?}"))?;
    let end: usize = e
        .trim()
        .parse()
        .with_context(|| format!("invalid position end in {spec:?}"))?;
    if start > end {
        bail!("position start {start} > end {end}");
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_store::model::{
        FlowStart, Protocol, RequestData, ResponseData,
    };

    fn base_req() -> RequestData {
        RequestData {
            method: "GET".into(),
            authority: "example.com".into(),
            path: "/api?id=5&q=x".into(),
            http_version: "HTTP/1.1".into(),
            headers: b"Accept: */*\r\n".to_vec(),
            body: Vec::new(),
        }
    }

    #[test]
    fn flow_request_bytes_synthesizes_and_injects_host() {
        let raw = flow_request_bytes(&base_req());
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("GET /api?id=5&q=x HTTP/1.1\r\n"));
        assert!(s.contains("Accept: */*\r\n"));
        // Host injected because the recorded block lacked it.
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn flow_request_bytes_keeps_existing_host() {
        let mut req = base_req();
        req.headers = b"Host: other.test\r\nAccept: */*\r\n".to_vec();
        let s = String::from_utf8_lossy(&flow_request_bytes(&req)).into_owned();
        assert_eq!(s.matches("Host:").count(), 1);
        assert!(s.contains("Host: other.test"));
    }

    #[test]
    fn build_template_from_positions_and_markers() {
        let bytes = b"id=5&q=x";
        // Explicit offsets for the `5` and the `x`.
        let t = build_template(bytes, &[(3, 4), (7, 8)], None);
        assert_eq!(t.num_positions(), 2);
        assert_eq!(t.originals, vec![b"5".to_vec(), b"x".to_vec()]);

        // Marker-based.
        let marked = "id=§5§&q=§x§".as_bytes();
        let t2 = build_template(marked, &[], None);
        assert_eq!(t2.num_positions(), 2);
        assert_eq!(t2.clean, b"id=5&q=x");
    }

    #[test]
    fn parse_position_accepts_forms_and_rejects_bad() {
        assert_eq!(parse_position("3:4").unwrap(), (3, 4));
        assert_eq!(parse_position("10-20").unwrap(), (10, 20));
        assert!(parse_position("nope").is_err());
        assert!(parse_position("5:2").is_err());
    }

    /// Position-building from a real flow: synthesize the request, mark the query
    /// value with an explicit offset, and confirm the template targets it.
    #[test]
    fn template_from_flow_targets_query_value() {
        let raw = flow_request_bytes(&base_req());
        let s = String::from_utf8_lossy(&raw).into_owned();
        // Offset of the "5" in "id=5".
        let idx = s.find("id=").unwrap() + 3;
        let t = build_template(&raw, &[(idx, idx + 1)], None);
        assert_eq!(t.num_positions(), 1);
        assert_eq!(t.originals[0], b"5");
    }

    async fn seed_flow(paths: &Paths, session: &str) -> i64 {
        let store = open_store(paths, session).unwrap();
        let w = store.writer();
        let fid = w
            .flow_start(FlowStart {
                workspace_id: 1,
                ts_start: 0,
                exec_id: None,
                client_addr: "127.0.0.1:1".into(),
                dst_ip: "127.0.0.1".into(),
                dst_port: 9,
                sni: Some("example.com".into()),
                scheme: "http".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(fid, base_req()).await.unwrap();
        w.response(
            fid,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"content-type: text/plain\r\n".to_vec(),
                body: b"ok".to_vec(),
                timing_ms: Some(1),
            },
        )
        .await
        .unwrap();
        fid
    }

    /// End-to-end persistence wiring WITHOUT the network: cancel immediately so
    /// `run_attack` sends at most the baseline, then confirm the attack row +
    /// status transitions and list/show read it back.
    #[tokio::test]
    async fn fuzz_run_persists_attack_even_when_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = seed_flow(&paths, "default").await;

        let raw = flow_request_bytes(&base_req());
        let s = String::from_utf8_lossy(&raw).into_owned();
        let idx = s.find("id=").unwrap() + 3;

        let cancel = CancellationToken::new();
        cancel.cancel(); // no expansion requests; baseline goes to a dead port.

        let spec = FuzzSpec {
            flow_id: fid,
            request_bytes: None,
            positions: vec![(idx, idx + 1)],
            marker: None,
            payloads: vec![b"1".to_vec(), b"2".to_vec()],
            mode: AttackMode::Sniper,
            concurrency: Some(2),
            delay_ms: None,
            name: Some("t".into()),
        };
        let v = fuzz_run(&paths, "default", spec, cancel).await.unwrap();
        let attack_id = v["attack_id"].as_i64().unwrap();
        assert!(attack_id > 0);
        assert_eq!(v["status"], "cancelled");
        assert_eq!(v["positions"], 1);
        assert_eq!(v["payloads"], 2);

        // list shows the attack.
        let listed = fuzz_list(&paths, "default", None).unwrap();
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["attacks"][0]["id"], attack_id);
        assert_eq!(listed["attacks"][0]["status"], "cancelled");

        // show returns the (possibly empty) results + the attack.
        let shown = fuzz_show(&paths, "default", attack_id, ResultSort::Anomaly, None).unwrap();
        assert_eq!(shown["attack"]["id"], attack_id);
    }

    #[tokio::test]
    async fn fuzz_run_errors_without_positions() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = seed_flow(&paths, "default").await;
        let spec = FuzzSpec {
            flow_id: fid,
            payloads: vec![b"x".to_vec()],
            mode: AttackMode::Sniper,
            ..Default::default()
        };
        let err = fuzz_run(&paths, "default", spec, CancellationToken::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no injection positions"), "got: {err}");
    }
}
