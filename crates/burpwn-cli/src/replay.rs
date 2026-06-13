//! `req replay` (Repeater): rebuild a stored request, apply edits, send it and
//! record the result as a new flow.
//!
//! ## v1 transport (documented limitation)
//!
//! Replay sends via a **direct tokio TCP client** speaking raw HTTP/1.1 to the
//! flow's destination. This is fully implemented for **cleartext HTTP** flows
//! (`scheme == "http"`, protocol `h1`). HTTPS and HTTP/2 replay are intentionally
//! out of v1 scope (they need the TLS/h2 stack the proxy already owns); they
//! return a clear "not yet implemented" error rather than sending plaintext to a
//! TLS port. A later version should route replay through the proxy's own client
//! path so TLS/h2 are handled by the existing machinery.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use burpwn_store::model::{FlowDetail, Protocol, RequestData};

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
    Ok(ReplayEdit {
        name: name.to_string(),
        value: value.trim().to_string(),
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

/// Serialize a [`RequestData`] into raw HTTP/1.1 wire bytes for the origin: a
/// request line, the (Content-Length-corrected) header block, a blank line, and
/// the body. The `Host` header is ensured from the authority.
pub fn serialize_request(req: &RequestData) -> Vec<u8> {
    let mut headers = req.headers.clone();
    // Ensure Host and a correct Content-Length.
    if !has_header(&headers, "host") && !req.authority.is_empty() {
        set_header(&mut headers, "Host", &req.authority);
    }
    set_header(&mut headers, "Content-Length", &req.body.len().to_string());
    // Connection: close so the origin ends the response and we can read to EOF.
    set_header(&mut headers, "Connection", "close");

    let mut out = Vec::new();
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    out.extend_from_slice(&headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

fn has_header(raw: &[u8], name: &str) -> bool {
    let text = String::from_utf8_lossy(raw);
    text.split("\r\n").any(|l| {
        l.split_once(':')
            .map(|(n, _)| n.trim().eq_ignore_ascii_case(name))
            .unwrap_or(false)
    })
}

/// Replay the (already-edited) request from `detail` to its destination.
///
/// Only cleartext HTTP/1.x is supported in v1; other schemes/protocols error.
pub async fn replay(detail: &FlowDetail, req: &RequestData) -> Result<ReplayResult> {
    if detail.flow.scheme.eq_ignore_ascii_case("https")
        || detail.flow.protocol == Protocol::H2
        || detail.flow.protocol == Protocol::TlsPassthru
    {
        bail!(
            "replay over TLS/HTTP2 is not yet implemented (flow {} is {} / {:?}); \
             v1 replays cleartext HTTP only",
            detail.flow.id,
            detail.flow.scheme,
            detail.flow.protocol
        );
    }
    let dst = format!("{}:{}", detail.flow.dst_ip, detail.flow.dst_port);
    let wire = serialize_request(req);

    let mut stream = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(&dst))
        .await
        .map_err(|_| anyhow!("connect to {dst} timed out"))?
        .map_err(|e| anyhow!("connect to {dst} failed: {e}"))?;

    stream.write_all(&wire).await?;
    stream.flush().await?;

    let mut raw_response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(30),
        stream.read_to_end(&mut raw_response),
    )
    .await
    .map_err(|_| anyhow!("reading response from {dst} timed out"))??;

    let status = parse_status(&raw_response);
    Ok(ReplayResult {
        status,
        raw_response,
    })
}

/// Parse the status code from a raw HTTP/1.1 response (`HTTP/1.1 200 OK`).
fn parse_status(raw: &[u8]) -> u16 {
    let head = &raw[..raw.len().min(64)];
    let line = String::from_utf8_lossy(head);
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
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
    fn serialize_adds_content_length_and_connection_close() {
        let mut req = base_req();
        req.body = b"abc".to_vec();
        let wire = serialize_request(&req);
        let s = String::from_utf8_lossy(&wire);
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Content-Length: 3"));
        assert!(s.contains("Connection: close"));
        assert!(s.ends_with("\r\nabc"));
    }

    #[test]
    fn parse_status_reads_code() {
        assert_eq!(parse_status(b"HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(parse_status(b"garbage"), 0);
    }

    #[tokio::test]
    async fn replay_rejects_https() {
        let detail = FlowDetail {
            flow: burpwn_store::model::FlowRow {
                id: 1,
                workspace_id: 1,
                ts_start: 0,
                ts_end: None,
                protocol: Protocol::H1,
                scheme: "https".into(),
                dst_ip: "1.2.3.4".into(),
                dst_port: 443,
                sni: None,
                method: Some("GET".into()),
                authority: Some("x".into()),
                path: Some("/".into()),
                status: None,
                intercepted: false,
            },
            exec_id: None,
            client_addr: "127.0.0.1:1".into(),
            request: Some(base_req()),
            response: None,
        };
        let err = replay(&detail, &base_req()).await.unwrap_err();
        assert!(err.to_string().contains("not yet implemented"));
    }
}
