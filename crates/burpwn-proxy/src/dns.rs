//! DNS decode-and-forward UDP front-end.
//!
//! The sandbox redirects the workload's UDP/53 traffic to this listener. For
//! each datagram we:
//! 1. decode the query with `hickory-proto` (decode only — we never synthesize
//!    answers),
//! 2. forward the raw query bytes to a real upstream resolver (the host's first
//!    `/etc/resolv.conf` nameserver, falling back to `1.1.1.1:53`),
//! 3. decode the answer for logging,
//! 4. record a `Protocol::Dns` flow (query name/type as request, answer records
//!    as the response body),
//! 5. return the upstream answer bytes verbatim to the client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::net::UdpSocket;

use burpwn_store::model::{FlowStart, Protocol, RequestData, ResponseData};
use burpwn_store::WriteHandle;

use crate::util::now_millis;

/// Configuration for the DNS front-end.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Upstream resolver to forward to.
    pub upstream: SocketAddr,
    /// Default workspace id for logged flows.
    pub workspace_id: i64,
    /// Optional exec correlation id.
    pub exec_id: Option<String>,
    /// Per-query upstream timeout.
    pub timeout: Duration,
}

impl DnsConfig {
    /// Build a config using the host's first configured nameserver, or
    /// `1.1.1.1:53` if `/etc/resolv.conf` has none.
    pub fn from_host(workspace_id: i64, exec_id: Option<String>) -> Self {
        Self {
            upstream: host_upstream(),
            workspace_id,
            exec_id,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Read the first `nameserver` line from `/etc/resolv.conf`; fallback 1.1.1.1.
fn host_upstream() -> SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    return SocketAddr::new(ip, 53);
                }
            }
        }
    }
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
}

/// Bind a UDP DNS server on `addr` and serve until the socket errors.
pub async fn serve(addr: SocketAddr, cfg: DnsConfig, writer: WriteHandle) -> std::io::Result<()> {
    let sock = UdpSocket::bind(addr).await?;
    tracing::info!(%addr, upstream = %cfg.upstream, "DNS front-end listening");
    serve_socket(sock, cfg, writer).await
}

/// Serve DNS over an ALREADY-BOUND socket — used for the transparent sandbox
/// path, where the in-netns agent binds `127.0.0.1:dns_port` (the nftables
/// `udp/53` redirect target) and passes the fd to the host proxy via SCM_RIGHTS.
/// Stops after [`IDLE_TIMEOUT`] with no query, which bounds the per-exec task
/// leak once the sandbox netns is gone (the passed fd then never sees traffic).
pub async fn serve_socket(
    sock: UdpSocket,
    cfg: DnsConfig,
    writer: WriteHandle,
) -> std::io::Result<()> {
    let sock = Arc::new(sock);
    let cfg = Arc::new(cfg);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match tokio::time::timeout(IDLE_TIMEOUT, sock.recv_from(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()), // idle → stop serving this socket
        };
        let query = buf[..n].to_vec();
        let sock = sock.clone();
        let cfg = cfg.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_query(&sock, peer, query, &cfg, &writer).await {
                tracing::debug!(error = %e, "dns query handling failed");
            }
        });
    }
}

/// Stop serving a (passed) DNS socket after this long with no query.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

async fn handle_query(
    sock: &UdpSocket,
    peer: SocketAddr,
    query: Vec<u8>,
    cfg: &DnsConfig,
    writer: &WriteHandle,
) -> std::io::Result<()> {
    let answer = forward_upstream(&query, cfg).await?;
    // Reply to the client first (latency), then log.
    sock.send_to(&answer, peer).await?;

    let (qname, qtype) = describe_query(&query);
    let answer_text = describe_answer(&answer);

    let flow_id = writer
        .flow_start(FlowStart {
            workspace_id: cfg.workspace_id,
            ts_start: now_millis(),
            exec_id: cfg.exec_id.clone(),
            client_addr: peer.to_string(),
            dst_ip: cfg.upstream.ip().to_string(),
            dst_port: cfg.upstream.port(),
            sni: None,
            scheme: "dns".into(),
            protocol: Protocol::Dns,
            intercepted: false,
        })
        .await
        .map_err(to_io)?;
    let _ = writer
        .request(
            flow_id,
            RequestData {
                method: "QUERY".into(),
                authority: qname.clone(),
                // Path is the record type only — the authority already carries the
                // qname, so `req list` renders `dns://example.com./A` (not a
                // doubled `dns://example.com.example.com./A`).
                path: format!("/{qtype}"),
                http_version: "DNS".into(),
                headers: Vec::new(),
                body: query,
            },
        )
        .await;
    let _ = writer
        .response(
            flow_id,
            ResponseData {
                status: 0,
                http_version: "DNS".into(),
                headers: Vec::new(),
                body: answer_text.into_bytes(),
                timing_ms: None,
            },
        )
        .await;
    let _ = writer.flow_end(flow_id, now_millis()).await;
    Ok(())
}

/// Forward the raw query to the upstream resolver over UDP and return its reply.
async fn forward_upstream(query: &[u8], cfg: &DnsConfig) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if cfg.upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let up = UdpSocket::bind(bind).await?;
    up.connect(cfg.upstream).await?;
    up.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(cfg.timeout, up.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns upstream timeout"))??;
    buf.truncate(n);

    // Bind the reply to the query's transaction id. The socket is `connect`ed so
    // only the configured upstream can reach it (low risk), but a mismatched id
    // means the datagram is not the answer to THIS query — drop it rather than
    // relay a stray/spoofed response to the client. Best-effort: if either side
    // is undecodable we let the bytes through (decode is for logging only).
    if let (Some(qid), Some(rid)) = (message_id(query), message_id(&buf)) {
        if qid != rid {
            tracing::debug!(qid, rid, "dns reply id mismatch; dropping");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "dns upstream reply id mismatch",
            ));
        }
    }
    Ok(buf)
}

/// Decode just the 16-bit transaction id of a DNS message, best-effort.
fn message_id(bytes: &[u8]) -> Option<u16> {
    Message::from_vec(bytes).ok().map(|m| m.id())
}

/// Decode the (name, type) of the first question, best-effort.
fn describe_query(bytes: &[u8]) -> (String, String) {
    match Message::from_vec(bytes) {
        Ok(msg) => match msg.queries().first() {
            Some(q) => (q.name().to_string(), format!("{:?}", q.query_type())),
            None => ("?".into(), "?".into()),
        },
        Err(_) => ("?".into(), "?".into()),
    }
}

/// Render answer records as a human-readable, FTS-friendly block.
fn describe_answer(bytes: &[u8]) -> String {
    match Message::from_vec(bytes) {
        Ok(msg) => {
            let mut out = String::new();
            for q in msg.queries() {
                out.push_str(&format!("; question {} {:?}\n", q.name(), q.query_type()));
            }
            for a in msg.answers() {
                out.push_str(&format!("{a}\n"));
            }
            if msg.answers().is_empty() {
                out.push_str(&format!("; rcode {:?}\n", msg.response_code()));
            }
            out
        }
        Err(e) => format!("; undecodable answer: {e}"),
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    fn sample_query(name: &str) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        let mut q = Query::new();
        q.set_name(Name::from_str(name).unwrap())
            .set_query_type(RecordType::A);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    #[test]
    fn describes_query_name_and_type() {
        let bytes = sample_query("example.com.");
        let (name, ty) = describe_query(&bytes);
        assert!(name.starts_with("example.com"));
        assert_eq!(ty, "A");
    }

    #[test]
    fn describe_answer_handles_query_only_message() {
        let bytes = sample_query("test.local.");
        let rendered = describe_answer(&bytes);
        assert!(rendered.contains("test.local"));
    }

    #[test]
    fn undecodable_is_safe() {
        let (n, t) = describe_query(&[0xff, 0x00]);
        assert_eq!((n.as_str(), t.as_str()), ("?", "?"));
        assert!(describe_answer(&[0xff, 0x00]).contains("undecodable"));
    }

    #[tokio::test]
    async fn forwards_to_loopback_upstream_and_logs() {
        // Stand up a fake upstream resolver on loopback that echoes a canned
        // answer, then drive a query through `serve` and assert it round-trips.
        let upstream = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // The answer MUST echo the query's transaction id (0x1234, from
        // `sample_query`) or `forward_upstream` now drops it as a mismatch.
        let answer_bytes = {
            let mut msg = Message::new();
            msg.set_id(0x1234).set_message_type(MessageType::Response);
            msg.to_vec().unwrap()
        };
        let answer_for_task = answer_bytes.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((_, peer)) = upstream.recv_from(&mut buf).await {
                let _ = upstream.send_to(&answer_for_task, peer).await;
            }
        });

        let cfg = DnsConfig {
            upstream: upstream_addr,
            workspace_id: 1,
            exec_id: None,
            timeout: Duration::from_secs(2),
        };
        let query = sample_query("forward.test.");
        let got = forward_upstream(&query, &cfg).await.unwrap();
        assert_eq!(got, answer_bytes);
    }

    // Regression: an upstream reply whose transaction id does not match the query
    // must be dropped (returned as an error) rather than relayed to the client.
    #[tokio::test]
    async fn drops_reply_with_mismatched_id() {
        let upstream = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // Canned answer carries a DIFFERENT id than the query (0x1234).
        let answer_bytes = {
            let mut msg = Message::new();
            msg.set_id(0xBEEF).set_message_type(MessageType::Response);
            msg.to_vec().unwrap()
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((_, peer)) = upstream.recv_from(&mut buf).await {
                let _ = upstream.send_to(&answer_bytes, peer).await;
            }
        });

        let cfg = DnsConfig {
            upstream: upstream_addr,
            workspace_id: 1,
            exec_id: None,
            timeout: Duration::from_secs(2),
        };
        let query = sample_query("mismatch.test.");
        let err = forward_upstream(&query, &cfg).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
