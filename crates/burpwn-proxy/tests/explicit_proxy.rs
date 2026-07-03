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
use burpwn_store::model::FlowFilter;
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
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path().join("session.db")).unwrap();
    let cfg = ProxyConfig::new(dir.path().join("ca"));
    let proxy = Arc::new(Proxy::new(cfg, store.writer(), store.reader()).unwrap());
    let (bound, fut) = proxy
        .explicit_http_bound(([127, 0, 0, 1], 0).into())
        .await
        .unwrap();
    tokio::spawn(fut);
    (bound, store, dir)
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
