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
