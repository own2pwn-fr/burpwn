//! The daemon control protocol: newline-delimited JSON over a unix socket.
//!
//! This is the **contract the MCP server reuses**. The daemon (`daemon.rs`)
//! runs a [`serve`] loop over `control.sock`; the CLI's `intercept`/`status`
//! commands — and, later, the MCP server — drive it through [`ControlClient`].
//!
//! # Wire format
//!
//! One request per line (`serde_json` of [`ControlRequest`] + `\n`), one
//! response per line ([`ControlResponse`]). Requests and responses are tagged
//! enums (`{"type":"Status"}` etc.), so the protocol is self-describing and
//! forward-compatible (unknown fields are ignored on decode where possible).
//!
//! # Semantics
//!
//! - [`ControlRequest::Status`] → [`ControlResponse::Status`] (liveness + a
//!   snapshot of intercept state). Used to detect a live daemon.
//! - Intercept enable/disable/list map onto [`InterceptController`].
//! - [`ControlRequest::InterceptAwait`] is a **long-poll**: it maps to
//!   `InterceptController::take_next(timeout)` and returns the pending request
//!   (or `Pending(None)` on timeout). The returned `reply` sender is held by the
//!   daemon keyed by id, so a later `InterceptForward`/`InterceptDrop` resolves it.
//! - [`ControlRequest::Shutdown`] tears the daemon down.

use serde::{Deserialize, Serialize};

/// A single header edit (`name: value`) applied when forwarding an intercept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEdit {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Edits applied to a parked request/response on forward. An empty `Edits`
/// forwards the message unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edits {
    /// Headers to set/append (the raw header block is rebuilt by the daemon).
    #[serde(default)]
    pub set_headers: Vec<HeaderEdit>,
    /// Replacement body (UTF-8); `None` keeps the original body.
    #[serde(default)]
    pub body: Option<String>,
    /// Replacement method (requests only); `None` keeps the original.
    #[serde(default)]
    pub method: Option<String>,
    /// Replacement path (requests only); `None` keeps the original.
    #[serde(default)]
    pub path: Option<String>,
}

impl Edits {
    /// True when no edit is present (forward unchanged).
    pub fn is_empty(&self) -> bool {
        self.set_headers.is_empty()
            && self.body.is_none()
            && self.method.is_none()
            && self.path.is_none()
    }
}

/// A control request sent by the CLI / MCP to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlRequest {
    /// Liveness + intercept state snapshot.
    Status,
    /// Enable interception.
    InterceptEnable,
    /// Disable interception.
    InterceptDisable,
    /// List currently-parked intercepts.
    InterceptList,
    /// Long-poll for the next parked intercept (up to `timeout_secs`).
    InterceptAwait {
        /// How long to wait for a parked flow before returning `Pending(None)`.
        timeout_secs: u64,
    },
    /// Forward a parked intercept by id, optionally with edits.
    InterceptForward {
        /// The parked intercept id (from `InterceptList`/`InterceptAwait`).
        id: u64,
        /// Edits to apply before forwarding.
        #[serde(default)]
        edits: Edits,
    },
    /// Drop a parked intercept by id.
    InterceptDrop {
        /// The parked intercept id.
        id: u64,
    },
    /// Shut the daemon down.
    Shutdown,
}

/// A lightweight, serializable view of a parked intercept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptItem {
    /// Parked id.
    pub id: u64,
    /// `"request"` or `"response"`.
    pub kind: String,
    /// Host / `:authority`.
    pub host: String,
    /// Method.
    pub method: String,
    /// Path.
    pub path: String,
}

/// The daemon's reply to a [`ControlRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlResponse {
    /// Reply to `Status`.
    Status {
        /// Always true when answered (proves liveness).
        running: bool,
        /// Session name the daemon serves.
        session: String,
        /// Whether interception is currently enabled.
        intercept_enabled: bool,
        /// Count of currently-parked intercepts.
        pending: usize,
        /// DNS port the daemon bound.
        dns_port: u16,
    },
    /// Generic acknowledgement for a state change.
    Ack,
    /// Reply to `InterceptList`.
    Intercepts {
        /// The parked items.
        items: Vec<InterceptItem>,
    },
    /// Reply to `InterceptAwait`: `Some` item, or `None` on timeout.
    Pending {
        /// The next parked intercept, if one arrived in time.
        item: Option<InterceptItem>,
    },
    /// A `Forward`/`Drop` outcome: `true` if the id was found and resolved.
    Resolved {
        /// Whether the id matched a parked intercept.
        found: bool,
    },
    /// An error processing the request.
    Error {
        /// Human-readable message.
        message: String,
    },
}

/// Encode a request to a single newline-terminated JSON line.
pub fn encode_request(req: &ControlRequest) -> String {
    let mut s = serde_json::to_string(req).unwrap_or_else(|_| r#"{"type":"Status"}"#.to_string());
    s.push('\n');
    s
}

/// Encode a response to a single newline-terminated JSON line.
pub fn encode_response(resp: &ControlResponse) -> String {
    let mut s = serde_json::to_string(resp)
        .unwrap_or_else(|_| r#"{"type":"Error","message":"encode failed"}"#.to_string());
    s.push('\n');
    s
}

// --- async client ---------------------------------------------------------

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

/// A small async client for the control protocol. The MCP server should reuse
/// this type verbatim: `ControlClient::connect(paths.control_sock(session))`,
/// then call the typed methods.
///
/// The read half is wrapped in a persistent [`BufReader`] so any bytes buffered
/// past one response line survive across calls (the daemon writes one line per
/// request, but a persistent reader is the robust choice).
pub struct ControlClient {
    reader: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
}

impl ControlClient {
    /// Connect to a daemon's control socket.
    pub async fn connect(sock: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(sock.as_ref())
            .await
            .with_context(|| format!("connecting to control socket {}", sock.as_ref().display()))?;
        Ok(Self::from_stream(stream))
    }

    /// Connect, retrying for up to `timeout` while the socket may not yet exist
    /// (used by `exec` after spawning the daemon).
    pub async fn connect_retry(sock: impl AsRef<Path>, timeout: Duration) -> Result<Self> {
        let sock = sock.as_ref();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match UnixStream::connect(sock).await {
                Ok(stream) => return Ok(Self::from_stream(stream)),
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => {
                    return Err(anyhow!(
                        "control socket {} never became ready: {e}",
                        sock.display()
                    ))
                }
            }
        }
    }

    fn from_stream(stream: UnixStream) -> Self {
        let (read, write) = stream.into_split();
        Self {
            reader: BufReader::new(read),
            write,
        }
    }

    /// Send one request and read exactly one response line.
    pub async fn request(&mut self, req: ControlRequest) -> Result<ControlResponse> {
        let line = encode_request(&req);
        self.write.write_all(line.as_bytes()).await?;
        self.write.flush().await?;

        let mut buf = String::new();
        let n = self.reader.read_line(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("control connection closed before a response"));
        }
        let resp: ControlResponse = serde_json::from_str(buf.trim_end())
            .with_context(|| format!("decoding control response: {buf:?}"))?;
        Ok(resp)
    }

    /// `Status` convenience.
    pub async fn status(&mut self) -> Result<ControlResponse> {
        self.request(ControlRequest::Status).await
    }

    /// Enable interception.
    pub async fn intercept_enable(&mut self) -> Result<ControlResponse> {
        self.request(ControlRequest::InterceptEnable).await
    }

    /// Disable interception.
    pub async fn intercept_disable(&mut self) -> Result<ControlResponse> {
        self.request(ControlRequest::InterceptDisable).await
    }

    /// List parked intercepts.
    pub async fn intercept_list(&mut self) -> Result<ControlResponse> {
        self.request(ControlRequest::InterceptList).await
    }

    /// Long-poll for the next parked intercept.
    pub async fn intercept_await(&mut self, timeout_secs: u64) -> Result<ControlResponse> {
        self.request(ControlRequest::InterceptAwait { timeout_secs })
            .await
    }

    /// Forward a parked intercept by id with optional edits.
    pub async fn intercept_forward(&mut self, id: u64, edits: Edits) -> Result<ControlResponse> {
        self.request(ControlRequest::InterceptForward { id, edits })
            .await
    }

    /// Drop a parked intercept by id.
    pub async fn intercept_drop(&mut self, id: u64) -> Result<ControlResponse> {
        self.request(ControlRequest::InterceptDrop { id }).await
    }

    /// Ask the daemon to shut down.
    pub async fn shutdown(&mut self) -> Result<ControlResponse> {
        self.request(ControlRequest::Shutdown).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_through_serde() {
        let reqs = vec![
            ControlRequest::Status,
            ControlRequest::InterceptEnable,
            ControlRequest::InterceptAwait { timeout_secs: 30 },
            ControlRequest::InterceptForward {
                id: 5,
                edits: Edits {
                    set_headers: vec![HeaderEdit {
                        name: "X-Test".into(),
                        value: "1".into(),
                    }],
                    body: Some("hi".into()),
                    method: Some("POST".into()),
                    path: None,
                },
            },
            ControlRequest::InterceptDrop { id: 9 },
            ControlRequest::Shutdown,
        ];
        for r in reqs {
            let line = encode_request(&r);
            assert!(line.ends_with('\n'));
            let back: ControlRequest = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(back, r);
        }
    }

    #[test]
    fn response_roundtrips_through_serde() {
        let resps = vec![
            ControlResponse::Status {
                running: true,
                session: "default".into(),
                intercept_enabled: false,
                pending: 2,
                dns_port: 5353,
            },
            ControlResponse::Ack,
            ControlResponse::Intercepts {
                items: vec![InterceptItem {
                    id: 1,
                    kind: "request".into(),
                    host: "example.com".into(),
                    method: "GET".into(),
                    path: "/".into(),
                }],
            },
            ControlResponse::Pending { item: None },
            ControlResponse::Resolved { found: true },
            ControlResponse::Error {
                message: "nope".into(),
            },
        ];
        for r in resps {
            let line = encode_response(&r);
            let back: ControlResponse = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(back, r);
        }
    }

    #[test]
    fn edits_is_empty() {
        assert!(Edits::default().is_empty());
        assert!(!Edits {
            body: Some("x".into()),
            ..Default::default()
        }
        .is_empty());
    }
}
