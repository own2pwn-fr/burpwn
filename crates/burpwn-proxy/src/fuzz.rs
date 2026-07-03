//! Fuzzer / Intruder core engine.
//!
//! A pure attack engine, decoupled from the store (the CLI layer persists
//! results). Given a base request template, a set of injection POSITIONS, a
//! payload set, and an attack MODE, it expands the positions × payloads per the
//! mode, sends each request through a pluggable [`RequestSender`] (the real one
//! reuses the proxy's own [`crate::replay_once`] upstream path), and reports per
//! request: status, response length, latency, and a heuristic anomaly score
//! relative to a baseline (the unmodified request, sent once first).
//!
//! # Positions
//!
//! Two ways to mark where payloads are injected:
//! - Burp-style `§…§` markers embedded in the template (the bytes between a
//!   marker pair are the position's *original value*, used for the baseline and
//!   for non-targeted positions in `sniper`).
//! - Explicit `(start, end)` byte-offset pairs into a clean template.
//!
//! # Modes
//!
//! | mode            | requests (n positions, P payloads) |
//! |-----------------|------------------------------------|
//! | `sniper`        | n · P (one position at a time)     |
//! | `battering_ram` | P (same payload in every position) |
//! | `pitchfork`     | P (payload i in every position)    |
//! | `cluster_bomb`  | Pⁿ (cartesian product)             |
//!
//! Everything except [`HttpReplaySender`] is network-free and unit-tested.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// The default Burp-style position marker (`§`, U+00A7).
pub const DEFAULT_MARKER: &[u8] = "§".as_bytes();

/// Attack mode controlling how positions × payloads expand into requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    /// One position at a time; every other position keeps its original value.
    Sniper,
    /// The same payload placed in every position simultaneously.
    BatteringRam,
    /// Payload `i` placed in every position (parallel iteration).
    Pitchfork,
    /// Cartesian product of the payload set across all positions.
    ClusterBomb,
}

impl AttackMode {
    /// Parse from a lowercase string (`sniper`, `battering_ram`, …).
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "sniper" => Some(Self::Sniper),
            "battering_ram" | "batteringram" | "ram" => Some(Self::BatteringRam),
            "pitchfork" => Some(Self::Pitchfork),
            "cluster_bomb" | "clusterbomb" | "cluster" => Some(Self::ClusterBomb),
            _ => None,
        }
    }
}

/// A single injection position: a byte span `[start, end)` into the clean
/// template whose contents are replaced by a payload (or kept as the original).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// Inclusive start offset into the clean template.
    pub start: usize,
    /// Exclusive end offset into the clean template.
    pub end: usize,
}

/// A parsed request template: the marker-free bytes plus the positions and the
/// original value of each position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// The template bytes with any `§…§` markers removed.
    pub clean: Vec<u8>,
    /// Injection positions, in ascending order.
    pub positions: Vec<Position>,
    /// The original value occupying each position (parallel to `positions`).
    pub originals: Vec<Vec<u8>>,
}

impl Template {
    /// Parse a template with the default `§…§` markers.
    pub fn parse(template: &[u8]) -> Self {
        Self::parse_with_marker(template, DEFAULT_MARKER)
    }

    /// Parse a template delimiting positions with an arbitrary `marker` byte
    /// sequence. An unbalanced trailing marker is treated as literal text.
    pub fn parse_with_marker(template: &[u8], marker: &[u8]) -> Self {
        let mut clean = Vec::with_capacity(template.len());
        let mut positions = Vec::new();
        let mut originals = Vec::new();
        let mut i = 0;
        while i < template.len() {
            if marker_at(template, i, marker) {
                // Find the closing marker.
                let value_start = i + marker.len();
                if let Some(close) = find_marker(template, value_start, marker) {
                    let value = &template[value_start..close];
                    let start = clean.len();
                    clean.extend_from_slice(value);
                    let end = clean.len();
                    positions.push(Position { start, end });
                    originals.push(value.to_vec());
                    i = close + marker.len();
                    continue;
                }
            }
            clean.push(template[i]);
            i += 1;
        }
        Self {
            clean,
            positions,
            originals,
        }
    }

    /// Build a template from a clean byte string + explicit offset pairs. Pairs
    /// are sorted; overlapping / out-of-range pairs are dropped.
    pub fn from_offsets(clean: &[u8], offsets: &[(usize, usize)]) -> Self {
        let mut pairs: Vec<(usize, usize)> = offsets
            .iter()
            .copied()
            .filter(|&(s, e)| s <= e && e <= clean.len())
            .collect();
        pairs.sort_unstable();
        // Drop overlaps (keep the earlier of any overlapping pair).
        let mut positions = Vec::new();
        let mut originals = Vec::new();
        let mut last_end = 0usize;
        for (s, e) in pairs {
            if s < last_end {
                continue;
            }
            positions.push(Position { start: s, end: e });
            originals.push(clean[s..e].to_vec());
            last_end = e;
        }
        Self {
            clean: clean.to_vec(),
            positions,
            originals,
        }
    }

    /// Number of injection positions.
    pub fn num_positions(&self) -> usize {
        self.positions.len()
    }

    /// Render a concrete request from an assignment: for each position, `Some(p)`
    /// inserts `payloads[p]`, `None` keeps the position's original value.
    fn render(&self, assignment: &[Option<usize>], payloads: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.clean.len());
        let mut cursor = 0usize;
        for (idx, pos) in self.positions.iter().enumerate() {
            out.extend_from_slice(&self.clean[cursor..pos.start]);
            match assignment.get(idx).copied().flatten() {
                Some(pi) => {
                    out.extend_from_slice(payloads.get(pi).map(|v| v.as_slice()).unwrap_or(b""))
                }
                None => out.extend_from_slice(&self.originals[idx]),
            }
            cursor = pos.end;
        }
        out.extend_from_slice(&self.clean[cursor..]);
        out
    }
}

/// Return true if `marker` occurs at byte offset `i` in `buf`.
fn marker_at(buf: &[u8], i: usize, marker: &[u8]) -> bool {
    !marker.is_empty() && buf.len() >= i + marker.len() && &buf[i..i + marker.len()] == marker
}

/// Find the next occurrence of `marker` at/after `from`.
fn find_marker(buf: &[u8], from: usize, marker: &[u8]) -> Option<usize> {
    if marker.is_empty() {
        return None;
    }
    (from..=buf.len().saturating_sub(marker.len())).find(|&j| &buf[j..j + marker.len()] == marker)
}

/// Expand the per-request assignments for `mode` over `n` positions and `p`
/// payloads. Each assignment is a `Vec<Option<usize>>` of length `n`.
pub fn expand(mode: AttackMode, n: usize, p: usize) -> Vec<Vec<Option<usize>>> {
    if n == 0 || p == 0 {
        return Vec::new();
    }
    match mode {
        AttackMode::Sniper => {
            let mut out = Vec::with_capacity(n * p);
            for pos in 0..n {
                for pi in 0..p {
                    let mut a = vec![None; n];
                    a[pos] = Some(pi);
                    out.push(a);
                }
            }
            out
        }
        AttackMode::BatteringRam => (0..p).map(|pi| vec![Some(pi); n]).collect(),
        AttackMode::Pitchfork => (0..p).map(|pi| vec![Some(pi); n]).collect(),
        AttackMode::ClusterBomb => {
            // Cartesian product of payload indices across the n positions.
            let mut out: Vec<Vec<Option<usize>>> = vec![Vec::new()];
            for _ in 0..n {
                let mut next = Vec::with_capacity(out.len() * p);
                for prefix in &out {
                    for pi in 0..p {
                        let mut a = prefix.clone();
                        a.push(Some(pi));
                        next.push(a);
                    }
                }
                out = next;
            }
            out
        }
    }
}

/// Knobs for an attack run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    /// Attack mode.
    pub mode: AttackMode,
    /// Max in-flight requests (clamped to ≥ 1).
    pub concurrency: usize,
    /// Optional pacing delay applied between request launches (rate limit).
    #[serde(default, with = "opt_millis")]
    pub delay: Option<Duration>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            mode: AttackMode::Sniper,
            concurrency: 8,
            delay: None,
        }
    }
}

/// A response observed by the engine for one sent request.
#[derive(Debug, Clone)]
pub struct SentResponse {
    /// HTTP status code (0 if the sender could not determine one).
    pub status: u16,
    /// The raw response bytes (status line + headers + body, best-effort).
    pub raw_response: Vec<u8>,
    /// Response length in bytes used for anomaly scoring (typically body length).
    pub resp_len: usize,
}

/// Pluggable request transport. The real implementation ([`HttpReplaySender`])
/// routes through the proxy's upstream path; tests use an in-memory stub.
#[async_trait]
pub trait RequestSender: Send + Sync {
    /// Send one raw request and return the observed response.
    async fn send(&self, raw_request: &[u8]) -> anyhow::Result<SentResponse>;
}

/// A single per-request result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Zero-based request index (baseline is not included in results).
    pub index: usize,
    /// The payload string placed at each injected position for this request.
    pub payloads: Vec<String>,
    /// Response status code.
    pub status: u16,
    /// Response length in bytes.
    pub resp_len: usize,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// Heuristic anomaly score in `[0, 1]` relative to the baseline.
    pub anomaly: f64,
    /// The raw request bytes sent.
    #[serde(skip)]
    pub raw_request: Vec<u8>,
    /// The raw response bytes received.
    #[serde(skip)]
    pub raw_response: Vec<u8>,
    /// Transport error, if the request failed.
    pub error: Option<String>,
}

/// Baseline statistics from the unmodified request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    /// Baseline status code.
    pub status: u16,
    /// Baseline response length.
    pub resp_len: usize,
    /// Baseline latency in milliseconds.
    pub latency_ms: u64,
}

/// The full outcome of an attack run: the echoed config + baseline + results.
#[derive(Debug, Clone)]
pub struct AttackReport {
    /// The config the attack ran with (echoed back).
    pub config: FuzzConfig,
    /// Number of injection positions.
    pub positions: usize,
    /// Number of payloads.
    pub payloads: usize,
    /// Baseline stats, if the baseline request succeeded.
    pub baseline: Option<BaselineStats>,
    /// Per-request results, ascending by index.
    pub results: Vec<FuzzResult>,
}

/// Run an attack: send the baseline, expand positions × payloads per the mode,
/// send every request through `sender` under the concurrency cap, and score each
/// against the baseline. `cancel` stops launching new requests when triggered.
pub async fn run_attack(
    template: &Template,
    payloads: &[Vec<u8>],
    config: &FuzzConfig,
    sender: Arc<dyn RequestSender>,
    cancel: CancellationToken,
) -> AttackReport {
    let n = template.num_positions();
    let p = payloads.len();

    // Baseline: the unmodified request (all positions keep their original value).
    let baseline = if n > 0 {
        let base_req = template.render(&vec![None; n], payloads);
        measure(sender.as_ref(), &base_req)
            .await
            .ok()
            .map(|(r, ms)| BaselineStats {
                status: r.status,
                resp_len: r.resp_len,
                latency_ms: ms,
            })
    } else {
        None
    };

    let assignments = expand(config.mode, n, p);
    let concurrency = config.concurrency.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut inflight = FuturesUnordered::new();
    let mut results: Vec<FuzzResult> = Vec::with_capacity(assignments.len());

    for (index, assignment) in assignments.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        // acquire_owned only errors if the semaphore is closed, which we never do.
        let Ok(permit) = sem.clone().acquire_owned().await else {
            break;
        };
        let raw = template.render(&assignment, payloads);
        let payload_strs: Vec<String> = assignment
            .iter()
            .filter_map(|a| a.map(|pi| String::from_utf8_lossy(&payloads[pi]).into_owned()))
            .collect();
        let sender = sender.clone();
        let baseline = baseline.clone();
        inflight.push(async move {
            let _permit = permit; // released on completion
            let (res, ms) = match measure(sender.as_ref(), &raw).await {
                Ok((r, ms)) => (Ok(r), ms),
                Err(e) => (Err(e), 0),
            };
            (index, payload_strs, raw, res, ms, baseline)
        });

        if let Some(delay) = config.delay {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = cancel.cancelled() => {}
            }
        }
    }

    while let Some((index, payloads_used, raw, res, ms, baseline)) = inflight.next().await {
        let result = match res {
            Ok(r) => {
                let anomaly = baseline
                    .as_ref()
                    .map(|b| anomaly_score(b, r.status, r.resp_len, ms))
                    .unwrap_or(0.0);
                FuzzResult {
                    index,
                    payloads: payloads_used,
                    status: r.status,
                    resp_len: r.resp_len,
                    latency_ms: ms,
                    anomaly,
                    raw_request: raw,
                    raw_response: r.raw_response,
                    error: None,
                }
            }
            Err(e) => FuzzResult {
                index,
                payloads: payloads_used,
                status: 0,
                resp_len: 0,
                latency_ms: ms,
                anomaly: 1.0,
                raw_request: raw,
                raw_response: Vec::new(),
                error: Some(e.to_string()),
            },
        };
        results.push(result);
    }

    results.sort_by_key(|r| r.index);
    AttackReport {
        config: config.clone(),
        positions: n,
        payloads: p,
        baseline,
        results,
    }
}

/// Send one request and time it.
async fn measure(sender: &dyn RequestSender, raw: &[u8]) -> anyhow::Result<(SentResponse, u64)> {
    let started = Instant::now();
    let resp = sender.send(raw).await?;
    let ms = started.elapsed().as_millis() as u64;
    Ok((resp, ms))
}

/// Heuristic anomaly score in `[0, 1]`: a weighted blend of status change,
/// response-length deviation, and a positive latency spike vs. the baseline.
fn anomaly_score(base: &BaselineStats, status: u16, resp_len: usize, latency_ms: u64) -> f64 {
    let status_dev = if status != base.status { 1.0 } else { 0.0 };
    let len_dev = if base.resp_len == 0 {
        if resp_len == 0 {
            0.0
        } else {
            1.0
        }
    } else {
        ((resp_len as f64 - base.resp_len as f64).abs() / base.resp_len as f64).min(1.0)
    };
    let time_dev = if base.latency_ms == 0 {
        0.0
    } else {
        ((latency_ms as f64 - base.latency_ms as f64) / base.latency_ms as f64).clamp(0.0, 1.0)
    };
    (0.5 * status_dev + 0.35 * len_dev + 0.15 * time_dev).clamp(0.0, 1.0)
}

/// A [`RequestSender`] that parses a raw HTTP/1-style request and sends it via
/// the proxy's own [`crate::replay_once`] upstream path (real TLS/h1/h2).
pub struct HttpReplaySender {
    /// `http` or `https`.
    pub scheme: String,
    /// SNI / server name for TLS.
    pub sni: String,
    /// Resolved origin address.
    pub addr: std::net::SocketAddr,
}

#[async_trait]
impl RequestSender for HttpReplaySender {
    async fn send(&self, raw_request: &[u8]) -> anyhow::Result<SentResponse> {
        let parsed = parse_raw_request(raw_request)?;
        let resp = crate::replay_once(
            &self.scheme,
            &self.sni,
            self.addr,
            &parsed.method,
            &parsed.authority,
            &parsed.path,
            parsed.headers,
            parsed.body,
        )
        .await?;
        // Render the response head + body into raw bytes for display/storage.
        let mut raw = Vec::new();
        raw.extend_from_slice(format!("{} {}\r\n", resp.http_version, resp.status).as_bytes());
        for (name, value) in &resp.headers {
            raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        let body_len = resp.body.len();
        raw.extend_from_slice(&resp.body);
        Ok(SentResponse {
            status: resp.status,
            raw_response: raw,
            resp_len: body_len,
        })
    }
}

/// A minimally-parsed raw HTTP request.
struct ParsedRequest {
    method: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Parse a raw HTTP/1 request (`METHOD SP TARGET SP VERSION\r\n` + headers +
/// blank line + body). Best-effort; used by [`HttpReplaySender`].
fn parse_raw_request(raw: &[u8]) -> anyhow::Result<ParsedRequest> {
    let split = find_subsequence(raw, b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&raw[..i], raw[i + 4..].to_vec()),
        None => (raw, Vec::new()),
    };
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("no method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("no request target"))?
        .to_string();

    let mut headers = Vec::new();
    let mut authority = String::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("host") {
                authority = value.clone();
            }
            headers.push((name, value));
        }
    }
    Ok(ParsedRequest {
        method,
        authority,
        path,
        headers,
        body,
    })
}

/// Find the first index of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// serde helper: serialize `Option<Duration>` as optional whole milliseconds.
mod opt_millis {
    use super::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(d) => s.serialize_some(&(d.as_millis() as u64)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        let ms: Option<u64> = Option::deserialize(d)?;
        Ok(ms.map(Duration::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parses_marker_positions_and_originals() {
        let tpl = Template::parse("GET /?id=§5§&q=§x§ HTTP/1.1".as_bytes());
        assert_eq!(tpl.num_positions(), 2);
        // Markers are stripped from the clean template.
        assert_eq!(tpl.clean, b"GET /?id=5&q=x HTTP/1.1");
        assert_eq!(tpl.originals, vec![b"5".to_vec(), b"x".to_vec()]);
        // Positions delimit the original values in the clean template.
        assert_eq!(
            &tpl.clean[tpl.positions[0].start..tpl.positions[0].end],
            b"5"
        );
        assert_eq!(
            &tpl.clean[tpl.positions[1].start..tpl.positions[1].end],
            b"x"
        );
    }

    #[test]
    fn unbalanced_marker_is_literal() {
        let tpl = Template::parse("no §close here".as_bytes());
        assert_eq!(tpl.num_positions(), 0);
        assert_eq!(tpl.clean, "no §close here".as_bytes());
    }

    #[test]
    fn from_offsets_builds_positions() {
        let tpl = Template::from_offsets(b"id=5&q=x", &[(3, 4), (7, 8)]);
        assert_eq!(tpl.num_positions(), 2);
        assert_eq!(tpl.originals, vec![b"5".to_vec(), b"x".to_vec()]);
    }

    #[test]
    fn render_substitutes_and_keeps_original() {
        let tpl = Template::parse("a=§1§&b=§2§".as_bytes());
        let payloads = vec![b"AAA".to_vec()];
        // Sniper-style: only position 0 gets the payload, position 1 keeps orig.
        let req = tpl.render(&[Some(0), None], &payloads);
        assert_eq!(req, b"a=AAA&b=2");
        // Both positions get the payload.
        let req2 = tpl.render(&[Some(0), Some(0)], &payloads);
        assert_eq!(req2, b"a=AAA&b=AAA");
    }

    #[test]
    fn expand_counts_per_mode() {
        // 2 positions, 3 payloads.
        let (n, p) = (2, 3);
        assert_eq!(expand(AttackMode::Sniper, n, p).len(), n * p); // 6
        assert_eq!(expand(AttackMode::BatteringRam, n, p).len(), p); // 3
        assert_eq!(expand(AttackMode::Pitchfork, n, p).len(), p); // 3
        assert_eq!(expand(AttackMode::ClusterBomb, n, p).len(), p * p); // 9
    }

    #[test]
    fn expand_sniper_targets_one_position_at_a_time() {
        let asg = expand(AttackMode::Sniper, 2, 2);
        // Every sniper assignment must have exactly one Some().
        for a in &asg {
            assert_eq!(a.iter().filter(|x| x.is_some()).count(), 1);
        }
    }

    #[test]
    fn expand_battering_ram_fills_all_positions() {
        let asg = expand(AttackMode::BatteringRam, 3, 2);
        for a in &asg {
            assert!(a.iter().all(|x| x.is_some()));
            // Same payload index everywhere.
            assert!(a.windows(2).all(|w| w[0] == w[1]));
        }
    }

    #[test]
    fn expand_empty_when_no_positions_or_payloads() {
        assert!(expand(AttackMode::Sniper, 0, 5).is_empty());
        assert!(expand(AttackMode::Sniper, 3, 0).is_empty());
    }

    /// Stub sender: echoes the request length as status/body, counts calls.
    struct StubSender {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl RequestSender for StubSender {
        async fn send(&self, raw_request: &[u8]) -> anyhow::Result<SentResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Return 500 + longer body when the payload "boom" is present.
            let boom = find_subsequence(raw_request, b"boom").is_some();
            Ok(SentResponse {
                status: if boom { 500 } else { 200 },
                raw_response: raw_request.to_vec(),
                resp_len: if boom { 999 } else { 10 },
            })
        }
    }

    #[tokio::test]
    async fn run_attack_sends_baseline_plus_expansion_and_scores() {
        let tpl = Template::parse("q=§orig§".as_bytes());
        let payloads = vec![b"safe".to_vec(), b"boom".to_vec()];
        let sender = Arc::new(StubSender {
            calls: AtomicUsize::new(0),
        });
        let cfg = FuzzConfig {
            mode: AttackMode::Sniper,
            concurrency: 4,
            delay: None,
        };
        let report = run_attack(
            &tpl,
            &payloads,
            &cfg,
            sender.clone(),
            CancellationToken::new(),
        )
        .await;

        // Baseline (1) + sniper 1 position × 2 payloads (2) = 3 sends.
        assert_eq!(sender.calls.load(Ordering::SeqCst), 3);
        assert_eq!(report.results.len(), 2);
        assert!(report.baseline.is_some());

        // The "boom" payload must score higher than the "safe" one.
        let boom = report
            .results
            .iter()
            .find(|r| r.payloads == vec!["boom".to_string()])
            .unwrap();
        let safe = report
            .results
            .iter()
            .find(|r| r.payloads == vec!["safe".to_string()])
            .unwrap();
        assert_eq!(boom.status, 500);
        assert!(boom.anomaly > safe.anomaly);
        // Results are returned ascending by index.
        assert!(report.results.windows(2).all(|w| w[0].index <= w[1].index));
    }

    #[tokio::test]
    async fn run_attack_respects_cancellation() {
        let tpl = Template::parse("q=§o§".as_bytes());
        // Many payloads, but cancel immediately: baseline may run, expansion should
        // be skipped.
        let payloads: Vec<Vec<u8>> = (0..1000).map(|i| format!("p{i}").into_bytes()).collect();
        let sender = Arc::new(StubSender {
            calls: AtomicUsize::new(0),
        });
        let cancel = CancellationToken::new();
        cancel.cancel();
        let report = run_attack(
            &tpl,
            &payloads,
            &FuzzConfig::default(),
            sender.clone(),
            cancel,
        )
        .await;
        assert!(report.results.is_empty());
        // At most the baseline send happened.
        assert!(sender.calls.load(Ordering::SeqCst) <= 1);
    }

    #[test]
    fn parse_raw_request_extracts_parts() {
        let raw = b"POST /login?x=1 HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        let p = parse_raw_request(raw).unwrap();
        assert_eq!(p.method, "POST");
        assert_eq!(p.path, "/login?x=1");
        assert_eq!(p.authority, "api.test");
        assert_eq!(p.body, b"{\"a\":1}");
        assert!(p.headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn attack_mode_parses() {
        assert_eq!(AttackMode::from_str_opt("sniper"), Some(AttackMode::Sniper));
        assert_eq!(
            AttackMode::from_str_opt("cluster-bomb"),
            Some(AttackMode::ClusterBomb)
        );
        assert_eq!(AttackMode::from_str_opt("nope"), None);
    }
}
