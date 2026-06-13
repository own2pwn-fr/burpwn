//! The proxy daemon: a long-running process (the hidden `burpwn proxy`
//! subcommand) that opens a session store, builds a [`Proxy`], and concurrently
//! runs:
//!
//! - `serve_scm_unix(proxy.sock)` — the SCM_RIGHTS front-end the sandbox hands
//!   accepted client fds to,
//! - `dns_listener(127.0.0.1:<ephemeral>)` — the DNS shim (its chosen port is
//!   written to `ports.json`),
//! - a **control server** on `control.sock` speaking the newline-delimited JSON
//!   protocol in [`crate::control`].
//!
//! The control server is split out into [`serve_control`] / [`handle_request`]
//! so it can be exercised in-process against a real [`InterceptController`] over
//! a temp socket (see the tests) without standing up the whole proxy.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixListener, UnixStream};
use tokio::sync::Mutex;

use burpwn_proxy::intercept::{
    InterceptController, InterceptData, InterceptDecision, InterceptKind, PendingIntercept,
};
use burpwn_proxy::{Proxy, ProxyConfig};
use burpwn_store::Store;

use crate::control::{encode_response, ControlRequest, ControlResponse, Edits, InterceptItem};
use crate::paths::Paths;

/// Shared state the control server operates on. Holds the intercept controller
/// plus the table of intercepts pulled out of the controller by `InterceptAwait`
/// (which removes them from the controller's queue) so a later
/// `InterceptForward`/`InterceptDrop` can still resolve them.
#[derive(Clone)]
pub struct ControlState {
    /// The session name (echoed in `Status`).
    pub session: String,
    /// The DNS port the daemon bound (echoed in `Status`).
    pub dns_port: u16,
    /// The proxy's intercept primitive.
    pub intercept: InterceptController,
    /// Intercepts pulled by `InterceptAwait` and awaiting resolution, keyed by id.
    parked: Arc<Mutex<HashMap<u64, PendingIntercept>>>,
}

impl ControlState {
    /// Build a control state around an existing controller.
    pub fn new(session: impl Into<String>, dns_port: u16, intercept: InterceptController) -> Self {
        Self {
            session: session.into(),
            dns_port,
            intercept,
            parked: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn summary_item(id: u64, kind: InterceptKind, data: &InterceptData) -> InterceptItem {
        InterceptItem {
            id,
            kind: match kind {
                InterceptKind::Request => "request".into(),
                InterceptKind::Response => "response".into(),
            },
            host: data.host.clone(),
            method: data.method.clone(),
            path: data.path.clone(),
        }
    }
}

/// Apply control-protocol [`Edits`] to a parked intercept's data, producing the
/// `InterceptData` to forward. Header edits append `Name: value\r\n` lines to
/// the raw header block (origin servers tolerate duplicate headers; replacing
/// in-place would require a header parser we deliberately keep out of the v1
/// control path — documented limitation).
fn apply_edits(mut data: InterceptData, edits: &Edits) -> InterceptData {
    if let Some(m) = &edits.method {
        data.method = m.clone();
    }
    if let Some(p) = &edits.path {
        data.path = p.clone();
    }
    if let Some(b) = &edits.body {
        data.body = b.clone().into_bytes();
    }
    for h in &edits.set_headers {
        data.headers
            .extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }
    data
}

/// Handle a single decoded control request against `state`.
pub async fn handle_request(state: &ControlState, req: ControlRequest) -> ControlResponse {
    match req {
        ControlRequest::Status => ControlResponse::Status {
            running: true,
            session: state.session.clone(),
            intercept_enabled: state.intercept.is_enabled(),
            // pending count = still in the controller queue + already pulled.
            pending: state.intercept.pending().len() + state.parked.lock().await.len(),
            dns_port: state.dns_port,
        },
        ControlRequest::InterceptEnable => {
            state.intercept.set_enabled(true);
            ControlResponse::Ack
        }
        ControlRequest::InterceptDisable => {
            state.intercept.set_enabled(false);
            // Purge any already-parked intercepts so stale ids don't linger into
            // the next enable cycle. Resolve every queued flow (forward
            // unchanged) and drain the daemon-side parked table (those pulled by
            // `InterceptAwait`), unblocking their handlers. After this,
            // `intercept list` is empty and a later `forward <old-id>` honestly
            // reports "not found".
            for s in state.intercept.pending() {
                state
                    .intercept
                    .resolve(s.id, InterceptDecision::Forward(None));
            }
            let drained: Vec<PendingIntercept> =
                state.parked.lock().await.drain().map(|(_, p)| p).collect();
            for p in drained {
                let _ = p.reply.send(InterceptDecision::Forward(None));
            }
            ControlResponse::Ack
        }
        ControlRequest::InterceptList => {
            let mut items: Vec<InterceptItem> = state
                .intercept
                .pending()
                .into_iter()
                .map(|s| InterceptItem {
                    id: s.id,
                    kind: match s.kind {
                        InterceptKind::Request => "request".into(),
                        InterceptKind::Response => "response".into(),
                    },
                    host: s.host,
                    method: s.method,
                    path: s.path,
                })
                .collect();
            for (id, p) in state.parked.lock().await.iter() {
                items.push(ControlState::summary_item(*id, p.kind, &p.data));
            }
            items.sort_by_key(|i| i.id);
            ControlResponse::Intercepts { items }
        }
        ControlRequest::InterceptAwait { timeout_secs } => {
            match state
                .intercept
                .take_next(Duration::from_secs(timeout_secs))
                .await
            {
                Some(p) => {
                    let item = ControlState::summary_item(p.id, p.kind, &p.data);
                    // Park the pending (with its reply sender) for later resolve.
                    state.parked.lock().await.insert(p.id, p);
                    ControlResponse::Pending { item: Some(item) }
                }
                None => ControlResponse::Pending { item: None },
            }
        }
        ControlRequest::InterceptForward { id, edits } => {
            // First try a still-queued intercept (one not yet pulled by
            // `InterceptAwait`). Those carry no editable snapshot on this side,
            // so they can only be forwarded UNCHANGED — applying edits to an
            // empty base would blank the request. To edit, `InterceptAwait`
            // first (which parks a full snapshot), then `InterceptForward`.
            if state
                .intercept
                .resolve(id, InterceptDecision::Forward(None))
            {
                return ControlResponse::Resolved { found: true };
            }
            let pending = state.parked.lock().await.remove(&id);
            match pending {
                Some(p) => {
                    let decision = if edits.is_empty() {
                        InterceptDecision::Forward(None)
                    } else {
                        InterceptDecision::Forward(Some(apply_edits(p.data, &edits)))
                    };
                    let found = p.reply.send(decision).is_ok();
                    ControlResponse::Resolved { found }
                }
                None => ControlResponse::Resolved { found: false },
            }
        }
        ControlRequest::InterceptDrop { id } => {
            if state.intercept.resolve(id, InterceptDecision::Drop) {
                return ControlResponse::Resolved { found: true };
            }
            let pending = state.parked.lock().await.remove(&id);
            match pending {
                Some(p) => {
                    let found = p.reply.send(InterceptDecision::Drop).is_ok();
                    ControlResponse::Resolved { found }
                }
                None => ControlResponse::Resolved { found: false },
            }
        }
        // Shutdown is handled by the accept loop (it stops serving); here we
        // just acknowledge.
        ControlRequest::Shutdown => ControlResponse::Ack,
    }
}

/// Serve the control protocol on `sock` until a `Shutdown` request arrives (or
/// the listener errors). Returns when shutting down. Each connection is handled
/// inline (the protocol is request/response and low-volume).
pub async fn serve_control(state: ControlState, sock: impl AsRef<Path>) -> Result<()> {
    let sock = sock.as_ref();
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)
        .with_context(|| format!("binding control socket {}", sock.display()))?;
    tracing::info!(?sock, "control server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let stop = handle_connection(&state, stream).await?;
        if stop {
            tracing::info!("control server shutting down");
            return Ok(());
        }
    }
}

/// Handle one control connection: read newline-delimited requests until EOF,
/// replying to each. Returns `true` if a `Shutdown` was seen (after replying).
async fn handle_connection(state: &ControlState, stream: UnixStream) -> Result<bool> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(false);
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<ControlRequest>(trimmed) {
            Ok(req) => {
                let is_shutdown = matches!(req, ControlRequest::Shutdown);
                let resp = handle_request(state, req).await;
                write.write_all(encode_response(&resp).as_bytes()).await?;
                write.flush().await?;
                if is_shutdown {
                    return Ok(true);
                }
                continue;
            }
            Err(e) => ControlResponse::Error {
                message: format!("bad request: {e}"),
            },
        };
        write.write_all(encode_response(&resp).as_bytes()).await?;
        write.flush().await?;
    }
}

/// The fixed redirect port the in-netns acceptor binds and the nft ruleset
/// redirects all TCP to. It lives inside the sandbox's network namespace, so a
/// constant is safe (no host port conflict).
pub const NETNS_TCP_PORT: u16 = 8080;

/// The fixed redirect DNS port inside the netns.
pub const NETNS_DNS_PORT: u16 = 5353;

/// Run the full daemon for `session`: open the store, build the proxy, write
/// `ports.json`, and run the SCM front-end + DNS listener + control server
/// concurrently until a `Shutdown` (or fatal error). Blocks for the daemon's
/// lifetime.
pub async fn run_daemon(paths: &Paths, session: &str) -> Result<()> {
    paths.ensure_session_dir(session)?;
    let run_dir = paths.ensure_run_dir(session)?;

    let store = Store::open(paths.session_db(session)).context("opening session store")?;
    let cfg = ProxyConfig::new(paths.ca_dir());
    let proxy = Arc::new(Proxy::new(cfg, store.writer(), store.reader())?);

    // Bind the DNS UDP socket on an ephemeral port first, so we can publish the
    // chosen port before serving.
    let dns_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .context("binding DNS UDP socket")?;
    let dns_port = dns_sock.local_addr()?.port();
    drop(dns_sock); // release; dns_listener rebinds the same port below.
    write_ports(&paths.ports_file(session), dns_port)?;
    tracing::info!(%session, dns_port, run_dir = %run_dir.display(), "daemon starting");

    let intercept = proxy.intercept();
    let state = ControlState::new(session, dns_port, intercept);

    let proxy_sock = paths.proxy_sock(session);
    let control_sock = paths.control_sock(session);

    let scm_proxy = proxy.clone();
    let scm = tokio::spawn(async move { scm_proxy.serve_scm_unix(proxy_sock).await });

    let dns_proxy = proxy.clone();
    let dns = tokio::spawn(async move {
        dns_proxy
            .dns_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port)))
            .await
    });

    // The control server owns the shutdown trigger: when it returns Ok, abort
    // the front-ends and clean up the runtime files.
    let result = serve_control(state, &control_sock).await;

    scm.abort();
    dns.abort();
    let _ = std::fs::remove_file(paths.proxy_sock(session));
    let _ = std::fs::remove_file(&control_sock);
    result
}

/// Write `{ "dns_port": <port> }` to `ports.json`.
fn write_ports(path: &Path, dns_port: u16) -> Result<()> {
    let body = serde_json::json!({ "dns_port": dns_port });
    std::fs::write(path, serde_json::to_vec(&body)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read the DNS port from a session's `ports.json`, if present.
pub fn read_dns_port(path: &Path) -> Option<u16> {
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("dns_port").and_then(|p| p.as_u64()).map(|p| p as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlClient;

    fn ctrl_state() -> ControlState {
        ControlState::new("default", 5353, InterceptController::new())
    }

    #[tokio::test]
    async fn status_reports_liveness_and_intercept_state() {
        let state = ctrl_state();
        let resp = handle_request(&state, ControlRequest::Status).await;
        match resp {
            ControlResponse::Status {
                running,
                session,
                intercept_enabled,
                pending,
                dns_port,
            } => {
                assert!(running);
                assert_eq!(session, "default");
                assert!(!intercept_enabled);
                assert_eq!(pending, 0);
                assert_eq!(dns_port, 5353);
            }
            other => panic!("unexpected: {other:?}"),
        }

        handle_request(&state, ControlRequest::InterceptEnable).await;
        let resp = handle_request(&state, ControlRequest::Status).await;
        assert!(matches!(
            resp,
            ControlResponse::Status {
                intercept_enabled: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn await_then_forward_resolves_parked_intercept() {
        let state = ctrl_state();
        state.intercept.set_enabled(true);

        // Park an intercept in the background (the "proxy handler" side).
        let ctrl = state.intercept.clone();
        let handler = tokio::spawn(async move {
            ctrl.intercept(
                InterceptKind::Request,
                InterceptData {
                    host: "example.com".into(),
                    method: "GET".into(),
                    path: "/secret".into(),
                    headers: b"Host: example.com\r\n".to_vec(),
                    body: Vec::new(),
                },
            )
            .await
        });

        // Await pulls it.
        let resp = handle_request(&state, ControlRequest::InterceptAwait { timeout_secs: 5 }).await;
        let id = match resp {
            ControlResponse::Pending { item: Some(i) } => {
                assert_eq!(i.host, "example.com");
                assert_eq!(i.path, "/secret");
                i.id
            }
            other => panic!("expected a pending item, got {other:?}"),
        };

        // It is listed as still-pending until resolved.
        let listed = handle_request(&state, ControlRequest::InterceptList).await;
        assert!(matches!(listed, ControlResponse::Intercepts { items } if items.len() == 1));

        // Forward with a body edit.
        let resp = handle_request(
            &state,
            ControlRequest::InterceptForward {
                id,
                edits: Edits {
                    body: Some("edited".into()),
                    ..Default::default()
                },
            },
        )
        .await;
        assert!(matches!(resp, ControlResponse::Resolved { found: true }));

        let decision = handler.await.unwrap();
        match decision {
            InterceptDecision::Forward(Some(d)) => assert_eq!(d.body, b"edited"),
            other => panic!("expected forward-with-edit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disable_purges_parked_intercepts() {
        let state = ctrl_state();
        state.intercept.set_enabled(true);

        // Park an intercept and pull it via Await so it sits in the parked table.
        let ctrl = state.intercept.clone();
        let handler = tokio::spawn(async move {
            ctrl.intercept(
                InterceptKind::Request,
                InterceptData {
                    host: "example.com".into(),
                    method: "GET".into(),
                    path: "/x".into(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
            )
            .await
        });
        let resp = handle_request(&state, ControlRequest::InterceptAwait { timeout_secs: 5 }).await;
        let id = match resp {
            ControlResponse::Pending { item: Some(i) } => i.id,
            other => panic!("expected pending, got {other:?}"),
        };

        // Disable: should drain the parked table and unblock the handler.
        let ack = handle_request(&state, ControlRequest::InterceptDisable).await;
        assert!(matches!(ack, ControlResponse::Ack));

        // List is now empty.
        let listed = handle_request(&state, ControlRequest::InterceptList).await;
        assert!(matches!(listed, ControlResponse::Intercepts { items } if items.is_empty()));

        // Forwarding the old id is honestly "not found" (queue was cleared).
        let fwd = handle_request(
            &state,
            ControlRequest::InterceptForward {
                id,
                edits: Edits::default(),
            },
        )
        .await;
        assert!(matches!(fwd, ControlResponse::Resolved { found: false }));

        // The parked handler was resolved (forward unchanged), so it completes.
        let decision = handler.await.unwrap();
        assert!(matches!(decision, InterceptDecision::Forward(None)));
    }

    #[tokio::test]
    async fn await_times_out_to_none() {
        let state = ctrl_state();
        let resp = handle_request(&state, ControlRequest::InterceptAwait { timeout_secs: 0 }).await;
        assert!(matches!(resp, ControlResponse::Pending { item: None }));
    }

    #[tokio::test]
    async fn forward_unknown_id_is_not_found() {
        let state = ctrl_state();
        let resp = handle_request(&state, ControlRequest::InterceptDrop { id: 999 }).await;
        assert!(matches!(resp, ControlResponse::Resolved { found: false }));
    }

    #[tokio::test]
    async fn in_process_server_client_roundtrip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let state = ctrl_state();

        let server_sock = sock.clone();
        let server = tokio::spawn(async move { serve_control(state, &server_sock).await });

        // Give the listener a moment to bind.
        let mut client = ControlClient::connect_retry(&sock, Duration::from_secs(2))
            .await
            .unwrap();

        let status = client.status().await.unwrap();
        assert!(matches!(
            status,
            ControlResponse::Status { running: true, .. }
        ));

        let ack = client.intercept_enable().await.unwrap();
        assert!(matches!(ack, ControlResponse::Ack));
        let status = client.status().await.unwrap();
        assert!(matches!(
            status,
            ControlResponse::Status {
                intercept_enabled: true,
                ..
            }
        ));

        let shut = client.shutdown().await.unwrap();
        assert!(matches!(shut, ControlResponse::Ack));
        // The server returns Ok after a shutdown.
        server.await.unwrap().unwrap();
    }

    #[test]
    fn ports_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ports.json");
        write_ports(&p, 5353).unwrap();
        assert_eq!(read_dns_port(&p), Some(5353));
    }
}
