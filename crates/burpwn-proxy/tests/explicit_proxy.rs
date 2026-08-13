//! In-process integration tests driving the whole proxy pipeline through the
//! explicit forward-proxy front-end. Hermetic: loopback only, no privileges.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};

use burpwn_proxy::{Proxy, ProxyConfig};
use burpwn_store::model::{
    FlowFilter, Hook, HookAction, HookInject, HookInjectKind, HookPhase, HookScope,
};
use burpwn_store::Store;

/// Spin up a trivial loopback origin that echoes method + path and a fixed body.
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(sock);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let body = format!("origin saw {method} {path}");
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("x-origin", "yes")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

/// Start the explicit proxy and return its bound address.
async fn spawn_proxy() -> (SocketAddr, Store, TempDir) {
    let (bound, store, dir, _proxy) = spawn_proxy_handle().await;
    (bound, store, dir)
}

/// Same, keeping the [`Proxy`] itself — the hook engine hangs off it.
async fn spawn_proxy_handle() -> (SocketAddr, Store, TempDir, Arc<Proxy>) {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path().join("session.db")).unwrap();
    let cfg = ProxyConfig::new(dir.path().join("ca"));
    let proxy = Arc::new(Proxy::new(cfg, store.writer(), store.reader()).unwrap());
    let (bound, fut) = proxy
        .clone()
        .explicit_http_bound(([127, 0, 0, 1], 0).into())
        .await
        .unwrap();
    tokio::spawn(fut);
    (bound, store, dir, proxy)
}

/// Drive one absolute-form request through the proxy with a raw hyper client.
async fn request_through_proxy(
    proxy: SocketAddr,
    origin: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> (hyper::StatusCode, Vec<u8>) {
    let tcp = TcpStream::connect(proxy).await.unwrap();
    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    // Absolute-form URI so the proxy knows the origin.
    let uri = format!("http://{origin}{path}");
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", origin.to_string())
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

#[tokio::test]
async fn cleartext_request_flows_end_to_end_and_is_recorded() {
    let origin = spawn_origin().await;
    let (proxy, store, _dir) = spawn_proxy().await;

    let (status, body) = request_through_proxy(proxy, origin, "POST", "/login", "user=admin").await;
    assert_eq!(status, 200);
    assert_eq!(body.as_slice(), b"origin saw POST /login");

    // The store should have recorded the flow. Poll briefly since writes are
    // async (the response is returned before the final flow_end ack).
    let reader = store.reader();
    let mut rows = Vec::new();
    for _ in 0..50 {
        rows = reader.list_flows(&FlowFilter::default()).unwrap();
        if rows.iter().any(|r| r.status == Some(200)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let row = rows
        .iter()
        .find(|r| r.method.as_deref() == Some("POST"))
        .expect("POST flow recorded");
    assert_eq!(row.status, Some(200));
    assert_eq!(row.path.as_deref(), Some("/login"));

    // Decoded request body is searchable / stored.
    let detail = reader.get_flow(row.id).unwrap().unwrap();
    let req = detail.request.unwrap();
    assert_eq!(req.body.as_slice(), b"user=admin");
    let resp = detail.response.unwrap();
    assert_eq!(resp.body.as_slice(), b"origin saw POST /login");
}

#[tokio::test]
async fn multiple_methods_recorded() {
    let origin = spawn_origin().await;
    let (proxy, store, _dir) = spawn_proxy().await;

    let (s1, _) = request_through_proxy(proxy, origin, "GET", "/a", "").await;
    let (s2, _) = request_through_proxy(proxy, origin, "PUT", "/b", "payload").await;
    assert_eq!(s1, 200);
    assert_eq!(s2, 200);

    let reader = store.reader();
    let mut count = 0;
    for _ in 0..50 {
        let rows = reader.list_flows(&FlowFilter::default()).unwrap();
        count = rows.len();
        if count >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(count >= 2, "both flows recorded, got {count}");
}

/// An origin that streams a Server-Sent-Events response: it emits the first
/// chunk immediately, then sleeps 500ms before the second and closing. This lets
/// a test distinguish incremental forwarding (first chunk arrives fast) from
/// buffering (nothing until the whole body is done ~500ms later).
async fn spawn_sse_origin() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(sock);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let (mut tx, rx) = futures::channel::mpsc::channel::<Bytes>(4);
                    tokio::spawn(async move {
                        let _ = tx.send(Bytes::from_static(b"data: 1\n\n")).await;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let _ = tx.send(Bytes::from_static(b"data: 2\n\n")).await;
                        // Dropping `tx` ends the stream.
                    });
                    let body = StreamBody::new(rx.map(|b| Ok::<_, Infallible>(Frame::data(b))));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/event-stream")
                            .body(body)
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

// Streaming-bodies regression: an SSE / chunked response must be forwarded
// INCREMENTALLY (first chunk reaches the client before the origin finishes),
// not withheld until EOF. Before the hybrid streaming path, the proxy buffered
// the whole body, so SSE/long-poll stalled until the origin closed (or the 120s
// upstream timeout). Here the origin sleeps 500ms between chunks; the first
// chunk must arrive within a much shorter window.
#[tokio::test]
async fn sse_response_is_streamed_incrementally_not_withheld() {
    let origin = spawn_sse_origin().await;
    let (proxy, store, _dir) = spawn_proxy().await;

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let uri = format!("http://{origin}/sse");
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", origin.to_string())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();

    // The FIRST chunk must arrive well before the origin's 500ms inter-chunk
    // sleep — proof the body was streamed, not buffered to EOF.
    let first = tokio::time::timeout(Duration::from_millis(250), body.frame())
        .await
        .expect("first SSE chunk must arrive before the stream completes")
        .expect("body must yield a frame")
        .unwrap();
    assert_eq!(first.into_data().unwrap().as_ref(), b"data: 1\n\n");

    // Drain the remainder (the second chunk after the origin's sleep).
    let mut rest = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            rest.extend_from_slice(&data);
        }
    }
    assert_eq!(rest.as_slice(), b"data: 2\n\n");

    // The streamed flow is still recorded (response row written at stream end).
    let reader = store.reader();
    let mut recorded = false;
    for _ in 0..50 {
        if reader
            .list_flows(&FlowFilter::default())
            .unwrap()
            .iter()
            .any(|r| r.status == Some(200))
        {
            recorded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(recorded, "streamed flow recorded with status 200");
}

// --- hooks ------------------------------------------------------------------

/// Build a hook with the defaults the tests do not care about.
fn hook(id: i64, phase: HookPhase, scope: HookScope, action: HookAction) -> Hook {
    Hook {
        id,
        enabled: true,
        name: format!("hook{id}"),
        phase,
        scope,
        action,
        order: id,
        timeout_ms: 1_000,
        ttl_ms: 0,
        created_at: 0,
    }
}

/// An origin that echoes back the headers it received, so a test can see what
/// actually left the proxy rather than what the proxy said it sent.
async fn spawn_header_echo_origin() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(sock);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let mut seen = format!("{}\n", req.uri());
                    for (name, value) in req.headers() {
                        seen.push_str(&format!(
                            "{}: {}\n",
                            name,
                            value.to_str().unwrap_or_default()
                        ));
                    }
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from(seen)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

/// The headline case: a `User-Agent` on every request, synthesized by the proxy
/// for a client that never sent one. Match/replace cannot do this — it rewrites
/// what is there — and the origin's echo proves the header really went on the
/// wire, not just into the capture.
#[tokio::test]
async fn a_pre_request_hook_adds_a_header_the_client_never_sent() {
    let origin = spawn_header_echo_origin().await;
    let (proxy, _store, _dir, handle) = spawn_proxy_handle().await;
    handle.hooks().set_hooks(vec![hook(
        1,
        HookPhase::PreRequest,
        HookScope::default(),
        HookAction::AddHeader {
            name: "User-Agent".into(),
            value: "burpwn-hook/1".into(),
        },
    )]);

    let (status, body) = request_through_proxy(proxy, origin, "GET", "/echo", "").await;
    assert_eq!(status, 200);
    let seen = String::from_utf8(body).unwrap();
    assert!(seen.contains("user-agent: burpwn-hook/1"), "{seen}");

    // …and a `drop` hook refuses the flow outright, without reaching the origin.
    handle.hooks().set_hooks(vec![hook(
        2,
        HookPhase::PreRequest,
        HookScope {
            path: "/forbidden".into(),
            ..Default::default()
        },
        HookAction::Drop,
    )]);
    let (status, body) = request_through_proxy(proxy, origin, "GET", "/forbidden", "").await;
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&body).contains("dropped by hook"));
    // A path outside the hook's scope still goes through untouched.
    let (status, _) = request_through_proxy(proxy, origin, "GET", "/allowed", "").await;
    assert_eq!(status, 200);
}

/// A response hook must see a STREAMED body too. `should_stream` short-circuits
/// the whole response-rewrite path when nothing is in scope, so without the hook
/// clause a `post-response` hook on an SSE endpoint would simply never run —
/// silently, which is the worst way for a security tool to not work.
#[tokio::test]
async fn a_post_response_hook_takes_a_streaming_response_off_the_streaming_path() {
    let origin = spawn_sse_origin().await;
    let (proxy, _store, _dir, handle) = spawn_proxy_handle().await;
    handle.hooks().set_hooks(vec![hook(
        1,
        HookPhase::PostResponse,
        HookScope {
            status: Some(200),
            ..Default::default()
        },
        HookAction::SetHeader {
            name: "X-Burpwn-Hook".into(),
            value: "seen".into(),
        },
    )]);

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{origin}/sse"))
        .header("host", origin.to_string())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-burpwn-hook")
            .and_then(|v| v.to_str().ok()),
        Some("seen"),
        "the response hook must have run on a streamed body"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"data: 1\n\ndata: 2\n\n");
}

/// The cold-TTL burst, end to end: eight concurrent requests through the live
/// proxy on an empty cache. The command must run ONCE and all eight requests
/// must reach the origin carrying the token it minted — the seven that lose the
/// single-flight claim wait for the winner instead of being forwarded un-hooked
/// into a `401`, which is the whole reason an `exec` hook exists.
#[tokio::test]
async fn a_cold_ttl_burst_hooks_every_request_with_one_command() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A token mint: slow enough that the burst genuinely overlaps it.
    struct SlowMint(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl burpwn_proxy::HookRunner for SlowMint {
        async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(r#"{"token":"minted-once"}"#.to_string())
        }
    }

    let origin = spawn_header_echo_origin().await;
    let (proxy, _store, _dir, handle) = spawn_proxy_handle().await;
    let calls = Arc::new(AtomicUsize::new(0));
    handle.hooks().set_runner(Arc::new(SlowMint(calls.clone())));
    let mut h = hook(
        1,
        HookPhase::PreRequest,
        HookScope::default(),
        HookAction::Exec {
            cmd: "mint-a-token".into(),
            extract: r#""token":"([^"]+)""#.into(),
            inject: HookInject {
                kind: HookInjectKind::SetHeader,
                name: "Authorization".into(),
                value_template: "Bearer {}".into(),
            },
        },
    );
    h.ttl_ms = 60_000;
    handle.hooks().set_hooks(vec![h]);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        tasks.push(tokio::spawn(async move {
            request_through_proxy(proxy, origin, "GET", "/api", "").await
        }));
    }
    for t in tasks {
        let (status, body) = t.await.unwrap();
        assert_eq!(status, 200);
        let seen = String::from_utf8(body).unwrap();
        assert!(
            seen.contains("authorization: Bearer minted-once"),
            "every request in the burst must carry the token: {seen}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one command for the whole burst, not one per request"
    );
}

/// THE recursion test, end to end through a real proxy: an `exec` hook whose
/// command itself makes an HTTP request through that same proxy.
///
/// The explicit front-end has no exec id to stamp, so the `hook:` marker is
/// absent here BY CONSTRUCTION — this exercises the second guard, the one that
/// has to hold when the first is missing. The command must run exactly once, the
/// request it makes must come back normally, and the whole thing must finish in
/// well under the hook timeout: a recursion that "resolves at the timeout" is
/// still a proxy that hangs.
#[tokio::test]
async fn a_hook_command_that_talks_through_the_proxy_does_not_recurse() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A runner that does what a token-mint command does: an HTTP request
    /// through the proxy it is being run by.
    struct ProxiedRunner {
        proxy: SocketAddr,
        origin: SocketAddr,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl burpwn_proxy::HookRunner for ProxiedRunner {
        async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) =
                request_through_proxy(self.proxy, self.origin, "GET", "/token", "").await;
            assert_eq!(status, 200, "the hook's own request must be served");
            Ok(format!(
                "{{\"token\":\"{}\"}}",
                String::from_utf8_lossy(&body).len()
            ))
        }
    }

    let origin = spawn_header_echo_origin().await;
    let (proxy, _store, _dir, handle) = spawn_proxy_handle().await;
    let calls = Arc::new(AtomicUsize::new(0));
    handle.hooks().set_runner(Arc::new(ProxiedRunner {
        proxy,
        origin,
        calls: calls.clone(),
    }));
    handle.hooks().set_hooks(vec![hook(
        1,
        HookPhase::PreRequest,
        HookScope::default(),
        HookAction::Exec {
            cmd: "mint-a-token".into(),
            extract: r#""token":"([^"]+)""#.into(),
            inject: HookInject {
                kind: HookInjectKind::SetHeader,
                name: "Authorization".into(),
                value_template: "Bearer {}".into(),
            },
        },
    )]);

    let started = std::time::Instant::now();
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(10),
        request_through_proxy(proxy, origin, "GET", "/api", ""),
    )
    .await
    .expect("the proxy must not deadlock on a self-triggering hook");
    let elapsed = started.elapsed();

    assert_eq!(status, 200);
    let seen = String::from_utf8(body).unwrap();
    assert!(
        seen.contains("authorization: Bearer"),
        "the outer request still got its token: {seen}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the command ran once: the request it made must not have re-fired the hook"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "the guard must answer immediately, not resolve at the hook timeout \
         ({elapsed:?})"
    );
}

// --- websocket hooks --------------------------------------------------------

/// A WebSocket origin: completes the handshake with tungstenite, echoes every
/// data message back with an `echo:` prefix, and answers pings the way any
/// server does (tungstenite's own auto-pong), so the control-frame path is
/// exercised for real rather than mocked.
async fn spawn_ws_origin() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(sock).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    use tokio_tungstenite::tungstenite::Message as Wm;
                    let reply = match msg {
                        Wm::Text(t) => Wm::Text(format!("echo:{t}")),
                        Wm::Binary(b) => {
                            let mut out = b"echo:".to_vec();
                            out.extend_from_slice(&b);
                            Wm::Binary(out)
                        }
                        // Ping / close are tungstenite's own business.
                        _ => continue,
                    };
                    if ws.send(reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A raw WebSocket client speaking through the explicit proxy: the handshake is
/// written by hand (absolute-form, so the proxy knows the origin) and the frames
/// are built with the proxy's own encoder, which keeps the test honest about
/// what is on the wire — masking included.
struct RawWsClient {
    stream: TcpStream,
    framer: burpwn_proxy::ws::Framer,
    pending: Vec<burpwn_proxy::ws::Emit>,
}

impl RawWsClient {
    async fn connect(proxy: SocketAddr, origin: SocketAddr, path: &str) -> RawWsClient {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let req = format!(
            "GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        // Read exactly to the end of the response headers, so not one frame
        // byte is swallowed with them.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n == 1, "the proxy closed during the handshake");
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        RawWsClient {
            stream,
            framer: burpwn_proxy::ws::Framer::new(),
            pending: Vec::new(),
        }
    }

    /// Send one complete message, masked as a client must.
    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let wire =
            burpwn_proxy::ws::encode_frame(opcode, payload, Some(burpwn_proxy::ws::mask_key()));
        self.stream.write_all(&wire).await.unwrap();
    }

    /// Send one message split across three frames, to prove the hook path
    /// reassembles before it decides and does not corrupt what it forwards.
    async fn send_fragmented(&mut self, parts: [&[u8]; 3]) {
        use tokio::io::AsyncWriteExt;
        for (i, part) in parts.iter().enumerate() {
            let (opcode, fin) = match i {
                0 => (burpwn_proxy::ws::OP_TEXT, false),
                2 => (burpwn_proxy::ws::OP_CONTINUATION, true),
                _ => (burpwn_proxy::ws::OP_CONTINUATION, false),
            };
            let key = burpwn_proxy::ws::mask_key();
            let mut wire = Vec::new();
            wire.push((if fin { 0x80 } else { 0 }) | opcode);
            wire.push(0x80 | part.len() as u8);
            wire.extend_from_slice(&key);
            wire.extend(part.iter().enumerate().map(|(j, b)| b ^ key[j & 3]));
            self.stream.write_all(&wire).await.unwrap();
        }
    }

    /// The next thing off the socket, or `None` if nothing arrives in `within`.
    async fn recv(&mut self, within: Duration) -> Option<burpwn_proxy::ws::Emit> {
        use tokio::io::AsyncReadExt;
        loop {
            if !self.pending.is_empty() {
                return Some(self.pending.remove(0));
            }
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(within, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
                Ok(Ok(n)) => n,
            };
            self.pending.extend(self.framer.push(&buf[..n]));
        }
    }

    /// The next DATA payload (control frames skipped).
    async fn recv_data(&mut self, within: Duration) -> Option<Vec<u8>> {
        while let Some(emit) = self.recv(within).await {
            if let burpwn_proxy::ws::Emit::Data { payload, .. } = emit {
                return Some(payload);
            }
        }
        None
    }

    /// Whether a ping is still answered — i.e. whether the socket still works.
    async fn pings(&mut self) -> bool {
        self.send(burpwn_proxy::ws::OP_PING, b"alive").await;
        for _ in 0..4 {
            match self.recv(Duration::from_secs(5)).await {
                Some(burpwn_proxy::ws::Emit::Control { opcode, .. })
                    if opcode == burpwn_proxy::ws::OP_PONG =>
                {
                    return true
                }
                Some(_) => continue,
                None => return false,
            }
        }
        false
    }
}

/// The ws messages recorded against the (single) ws flow, once there are at
/// least `at_least` of them.
async fn recorded_ws(store: &Store, at_least: usize) -> Vec<burpwn_store::model::WsMessage> {
    let reader = store.reader();
    for _ in 0..100 {
        let flows = reader.list_flows(&FlowFilter::default()).unwrap();
        if let Some(flow) = flows
            .iter()
            .find(|f| f.protocol == burpwn_store::model::Protocol::Ws)
        {
            let msgs = reader.ws_messages_for_flow(flow.id).unwrap();
            if msgs.len() >= at_least {
                return msgs;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected at least {at_least} recorded websocket messages");
}

/// The baseline, and the regression guard for everything below: with NO ws hook
/// the splice is what it always was — the origin sees what the client sent,
/// control frames work, and both directions land in `ws_messages`.
#[tokio::test]
async fn a_websocket_without_hooks_is_spliced_and_captured_unchanged() {
    let origin = spawn_ws_origin().await;
    let (proxy, store, _dir, _handle) = spawn_proxy_handle().await;

    let mut client = RawWsClient::connect(proxy, origin, "/socket").await;
    client
        .send(burpwn_proxy::ws::OP_TEXT, br#"{"role":"user"}"#)
        .await;
    assert_eq!(
        client.recv_data(Duration::from_secs(5)).await.unwrap(),
        br#"echo:{"role":"user"}"#,
        "the origin must see exactly what the client sent"
    );
    assert!(client.pings().await, "a ping must still be answered");

    let msgs = recorded_ws(&store, 2).await;
    assert!(
        msgs.iter()
            .any(|m| m.direction == burpwn_store::model::WsDirection::C2s
                && m.payload == br#"{"role":"user"}"#),
        "the client message is captured: {msgs:?}"
    );
    assert!(
        msgs.iter()
            .any(|m| m.direction == burpwn_store::model::WsDirection::S2c
                && m.payload == br#"echo:{"role":"user"}"#),
        "and so is the server's answer: {msgs:?}"
    );
}

/// The headline WebSocket case: a hook rewrites a message BEFORE the origin
/// sees it, inside a socket that is already open. No replay can do that — the
/// message only exists inside a socket the page keeps open — and the origin's
/// echo is what proves the rewrite went on the wire and not into the capture.
#[tokio::test]
async fn a_ws_hook_rewrites_a_message_before_the_origin_sees_it() {
    let origin = spawn_ws_origin().await;
    let (proxy, store, _dir, handle) = spawn_proxy_handle().await;
    handle.hooks().set_hooks(vec![hook(
        1,
        HookPhase::WsC2s,
        HookScope {
            path: "/socket".into(),
            ..Default::default()
        },
        HookAction::ReplacePayload {
            find: "\"role\":\"user\"".into(),
            replace: "\"role\":\"admin\"".into(),
        },
    )]);

    let mut client = RawWsClient::connect(proxy, origin, "/socket").await;
    client
        .send(burpwn_proxy::ws::OP_TEXT, br#"{"role":"user","id":7}"#)
        .await;
    assert_eq!(
        client.recv_data(Duration::from_secs(5)).await.unwrap(),
        br#"echo:{"role":"admin","id":7}"#,
        "the origin must have received the REWRITTEN message"
    );

    // A binary message that does not match is forwarded untouched: a payload is
    // bytes, and a hook that does not match must cost it nothing.
    client
        .send(burpwn_proxy::ws::OP_BINARY, &[0x00, 0xff, 0x10])
        .await;
    assert_eq!(
        client.recv_data(Duration::from_secs(5)).await.unwrap(),
        vec![b'e', b'c', b'h', b'o', b':', 0x00, 0xff, 0x10]
    );

    // A FRAGMENTED message is reassembled before the hook sees it — the match
    // here straddles two frames — and comes out whole on the other side.
    client
        .send_fragmented([br#"{"role"#, br#"":"user""#, br#",-n-:2}"#])
        .await;
    assert_eq!(
        client.recv_data(Duration::from_secs(5)).await.unwrap(),
        br#"echo:{"role":"admin",-n-:2}"#,
        "a match straddling a fragment boundary must still be rewritten"
    );

    // A ping is never hooked and never re-framed: the socket still works.
    assert!(
        client.pings().await,
        "control frames must survive a hooked socket"
    );

    // The capture records what was actually relayed, not what was typed.
    let msgs = recorded_ws(&store, 2).await;
    assert!(
        msgs.iter()
            .any(|m| m.payload == br#"{"role":"admin","id":7}"#),
        "the stored c2s message is the one the origin saw: {msgs:?}"
    );
}

/// `drop` on a WebSocket phase: the message never reaches the origin, and the
/// socket keeps working. Scoped by path, so the same proxy relays another socket
/// untouched — a drop hook quietly taking down every socket on the host is
/// exactly the failure this guards against.
#[tokio::test]
async fn a_ws_drop_hook_refuses_a_message_and_leaves_the_socket_alive() {
    let origin = spawn_ws_origin().await;
    let (proxy, _store, _dir, handle) = spawn_proxy_handle().await;
    handle.hooks().set_hooks(vec![hook(
        1,
        HookPhase::WsC2s,
        HookScope {
            path: "/blocked".into(),
            ..Default::default()
        },
        HookAction::Drop,
    )]);

    let mut blocked = RawWsClient::connect(proxy, origin, "/blocked").await;
    blocked.send(burpwn_proxy::ws::OP_TEXT, b"secret").await;
    assert!(
        blocked
            .recv_data(Duration::from_millis(400))
            .await
            .is_none(),
        "a dropped message never reaches the origin, so no echo comes back"
    );
    assert!(
        blocked.pings().await,
        "dropping messages must not tear the socket down"
    );

    // …and a socket outside the hook's scope is relayed as usual.
    let mut allowed = RawWsClient::connect(proxy, origin, "/allowed").await;
    allowed.send(burpwn_proxy::ws::OP_TEXT, b"hello").await;
    assert_eq!(
        allowed.recv_data(Duration::from_secs(5)).await.unwrap(),
        b"echo:hello"
    );
}
