//! `req replay` (Repeater): rebuild a stored request, apply edits, send it and
//! return the response.
//!
//! ## Transport
//!
//! Replay routes through [`burpwn_proxy::replay_once`], which owns the TLS/h1/h2
//! client machinery the proxy already uses. This handles **every** scheme —
//! cleartext HTTP, HTTPS and HTTP/2 — by dialing `dst_ip:dst_port`, using the
//! flow's host as both SNI and `:authority`. The edit-application and
//! request-shaping logic below is transport-agnostic and unit-tested in
//! isolation.

use std::net::SocketAddr;

use anyhow::{anyhow, bail, Context, Result};

use burpwn_store::model::{FlowDetail, RequestData};

/// One header edit applied to the rebuilt request.
#[derive(Debug, Clone)]
pub struct ReplayEdit {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// The result of a replay: status + response head/body bytes.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    /// Parsed status code (0 if unparseable).
    pub status: u16,
    /// The full raw response bytes (head + body).
    pub raw_response: Vec<u8>,
}

/// Parse a `K=V` or `K: V` header spec into a [`ReplayEdit`].
pub fn parse_header_spec(spec: &str) -> Result<ReplayEdit> {
    let (name, value) = spec
        .split_once(':')
        .or_else(|| spec.split_once('='))
        .ok_or_else(|| anyhow!("header must be `Name: value` or `Name=value`: {spec:?}"))?;
    let name = name.trim();
    if name.is_empty() {
        bail!("empty header name in {spec:?}");
    }
    let value = value.trim();
    // Reject CRLF / NUL injection: a `\r`/`\n` in name or value would smuggle
    // extra header lines (or split the request) into the request we build/send
    // (CRLF header injection). (`split_once(':')` already excludes `:` from the
    // name, but the value and the `=`-form name can still carry control chars.)
    if name.contains('\r')
        || name.contains('\n')
        || name.contains('\0')
        || value.contains('\r')
        || value.contains('\n')
        || value.contains('\0')
    {
        bail!("header name/value must not contain CR, LF or NUL: {spec:?}");
    }
    Ok(ReplayEdit {
        name: name.to_string(),
        value: value.to_string(),
    })
}

/// Apply the method/header/body edits onto a base [`RequestData`].
pub fn apply_edits(
    mut req: RequestData,
    method: Option<&str>,
    headers: &[ReplayEdit],
    body: Option<Vec<u8>>,
) -> RequestData {
    if let Some(m) = method {
        req.method = m.to_string();
    }
    if let Some(b) = body {
        req.body = b;
    }
    for h in headers {
        set_header(&mut req.headers, &h.name, &h.value);
    }
    req
}

/// Set (replace existing, case-insensitively, or append) a header line in a raw
/// `Name: value\r\n` header block.
fn set_header(raw: &mut Vec<u8>, name: &str, value: &str) {
    let text = String::from_utf8_lossy(raw).into_owned();
    let mut out = String::new();
    let mut replaced = false;
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if let Some((n, _)) = line.split_once(':') {
            if n.trim().eq_ignore_ascii_case(name) {
                if !replaced {
                    out.push_str(&format!("{name}: {value}\r\n"));
                    replaced = true;
                }
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !replaced {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    *raw = out.into_bytes();
}

/// Parse a raw `Name: value\r\n` header block into ordered `(name, value)`
/// pairs, dropping pseudo-headers and the hop-by-hop `Host`/`Content-Length`
/// (the transport recomputes those). Lines without a colon are skipped.
pub fn parse_request_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            // Skip pseudo-headers (`:method` etc.) and length/host the transport
            // derives itself; keep everything else verbatim.
            if name.is_empty()
                || name.starts_with(':')
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("host")
            {
                continue;
            }
            out.push((name.to_string(), value.trim().to_string()));
        }
    }
    out
}

/// The destination socket address parsed from the flow's `dst_ip:dst_port`.
fn dst_addr(detail: &FlowDetail) -> Result<SocketAddr> {
    format!("{}:{}", detail.flow.dst_ip, detail.flow.dst_port)
        .parse()
        .with_context(|| {
            format!(
                "flow {} has an unparseable destination {}:{}",
                detail.flow.id, detail.flow.dst_ip, detail.flow.dst_port
            )
        })
}

/// The host used for SNI and `:authority`: the recorded SNI, else the request
/// authority, else the destination ip.
fn replay_host(detail: &FlowDetail, req: &RequestData) -> String {
    detail
        .flow
        .sni
        .clone()
        .or_else(|| (!req.authority.is_empty()).then(|| req.authority.clone()))
        .or_else(|| detail.flow.authority.clone())
        .unwrap_or_else(|| detail.flow.dst_ip.clone())
}

/// Replay the (already-edited) request from `detail` to its destination through
/// the proxy's transport ([`burpwn_proxy::replay_once`]), which speaks the right
/// scheme (cleartext / TLS) and HTTP version for the flow. Works for every
/// scheme; the response is reassembled into raw bytes for display.
pub async fn replay(detail: &FlowDetail, req: &RequestData) -> Result<ReplayResult> {
    let addr = dst_addr(detail)?;
    let host = replay_host(detail, req);
    if host.is_empty() {
        bail!("flow {} has no host to replay to", detail.flow.id);
    }
    let headers = parse_request_headers(&req.headers);

    let resp = burpwn_proxy::replay_once(
        &detail.flow.scheme,
        &host,
        addr,
        &req.method,
        &host,
        &req.path,
        headers,
        req.body.clone(),
    )
    .await
    .map_err(|e| anyhow!("replay of flow {} failed: {e}", detail.flow.id))?;

    let raw_response = render_response(&resp);
    Ok(ReplayResult {
        status: resp.status,
        raw_response,
    })
}

/// Reassemble a [`burpwn_proxy::ReplayResponse`] into raw HTTP-ish bytes (status
/// line + headers + blank line + body) for human/`--raw` display.
fn render_response(resp: &burpwn_proxy::ReplayResponse) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{} {}\r\n", resp.http_version, resp.status).as_bytes());
    for (name, value) in &resp.headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&resp.body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_req() -> RequestData {
        RequestData {
            method: "GET".into(),
            authority: "example.com".into(),
            path: "/".into(),
            http_version: "HTTP/1.1".into(),
            headers: b"Host: example.com\r\nUser-Agent: orig\r\n".to_vec(),
            body: Vec::new(),
        }
    }

    #[test]
    fn parse_header_spec_accepts_both_forms() {
        assert_eq!(parse_header_spec("X-A: b").unwrap().name, "X-A");
        assert_eq!(parse_header_spec("X-A=b").unwrap().value, "b");
        assert!(parse_header_spec("nope").is_err());
        assert!(parse_header_spec(": v").is_err());
    }

    /// CRLF header injection: a `\r`/`\n`/NUL in the header value (or in the
    /// `=`-form name) must be rejected, so `--set-header` can't smuggle extra
    /// header lines into the rebuilt request.
    #[test]
    fn parse_header_spec_rejects_crlf_injection() {
        assert!(parse_header_spec("X-A: b\r\nX-Injected: 1").is_err());
        assert!(parse_header_spec("X-A: b\nc").is_err());
        assert!(parse_header_spec("X-A=b\rc").is_err());
        assert!(parse_header_spec("X-Bad\nName=v").is_err());
        assert!(parse_header_spec("X-A: b\0c").is_err());
        // A clean header still parses.
        assert!(parse_header_spec("X-A: b").is_ok());
    }

    #[test]
    fn set_header_replaces_then_appends() {
        let req = apply_edits(
            base_req(),
            Some("POST"),
            &[
                ReplayEdit {
                    name: "User-Agent".into(),
                    value: "burpwn".into(),
                },
                ReplayEdit {
                    name: "X-New".into(),
                    value: "1".into(),
                },
            ],
            Some(b"hello".to_vec()),
        );
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"hello");
        let h = String::from_utf8_lossy(&req.headers);
        assert!(h.contains("User-Agent: burpwn"));
        assert!(!h.contains("User-Agent: orig"));
        assert!(h.contains("X-New: 1"));
    }

    #[test]
    fn parse_request_headers_drops_host_length_and_pseudo() {
        let raw = b":method: GET\r\nHost: example.com\r\nContent-Length: 3\r\n\
                   User-Agent: orig\r\nAccept: */*\r\n";
        let pairs = parse_request_headers(raw);
        let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["User-Agent", "Accept"]);
        assert_eq!(pairs[0].1, "orig");
    }

    fn detail_for(scheme: &str, port: u16) -> FlowDetail {
        FlowDetail {
            flow: burpwn_store::model::FlowRow {
                id: 1,
                workspace_id: 1,
                ts_start: 0,
                ts_end: None,
                protocol: burpwn_store::model::Protocol::H1,
                scheme: scheme.into(),
                dst_ip: "127.0.0.1".into(),
                dst_port: port,
                sni: Some("example.com".into()),
                method: Some("GET".into()),
                authority: Some("example.com".into()),
                path: Some("/".into()),
                status: None,
                intercepted: false,
            },
            exec_id: None,
            client_addr: "127.0.0.1:1".into(),
            request: Some(base_req()),
            response: None,
            tags: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn replay_host_prefers_sni_then_authority_then_ip() {
        let mut d = detail_for("https", 443);
        assert_eq!(replay_host(&d, &base_req()), "example.com");
        d.flow.sni = None;
        // falls back to the request authority.
        assert_eq!(replay_host(&d, &base_req()), "example.com");
        let mut req = base_req();
        req.authority = String::new();
        d.flow.authority = None;
        assert_eq!(replay_host(&d, &req), "127.0.0.1");
    }

    #[test]
    fn render_response_builds_raw_bytes() {
        let resp = burpwn_proxy::ReplayResponse {
            status: 200,
            http_version: "HTTP/1.1".into(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: b"hi".to_vec(),
        };
        let raw = render_response(&resp);
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("HTTP/1.1 200\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.ends_with("\r\nhi"));
    }

    /// Live replay requires network/a listening origin; gate it off by default.
    #[tokio::test]
    #[ignore = "needs a live origin / network"]
    async fn replay_round_trips_against_live_origin() {
        let d = detail_for("http", 80);
        let res = replay(&d, &base_req()).await;
        // We only assert it returns; the actual status depends on the network.
        let _ = res;
    }
}
