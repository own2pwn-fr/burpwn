//! HTTP/1.1 + HTTP/2 capture and forwarding, plus WebSocket splicing.
//!
//! The decrypted (MITM) or cleartext downstream connection is served with
//! hyper's server. For each request the service:
//! 1. buffers the request body (capped) and reconstructs an order-preserving
//!    raw header block for the store,
//! 2. applies request-side match/replace rules (cached per connection),
//! 3. consults the [`InterceptController`] (may park / drop / edit),
//! 4. forwards the (possibly modified) request upstream — plain TCP for the
//!    cleartext case, TLS via [`burpwn_tls::upstream_connector`] for MITM,
//! 5. captures the response, decompresses a *copy* for storage (forwarding the
//!    original bytes unchanged), applies response-side rules + intercept,
//! 6. writes the flow to the store and streams the response back downstream.
//!
//! WebSocket: an `Upgrade: websocket` request that the origin answers `101` is
//! detected; after the handshake we stop HTTP parsing and splice the two
//! upgraded byte streams, teeing frame bytes to the store as a `Protocol::Ws`
//! flow.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_TYPE, HOST};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use burpwn_store::model::{FlowStart, Protocol, RequestData, ResponseData, WsDirection};
use burpwn_store::{WriteHandle, WriteOp};

use crate::decode::decode_body;
use crate::intercept::{InterceptController, InterceptData, InterceptDecision, InterceptKind};
use crate::matchreplace::{apply_request, apply_response, host_in_scope, Message};
use crate::util::now_millis;
use crate::ws;

/// The boxed error type carried by [`ProxyBody`].
type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// The response body type the proxy hands hyper: either a fully-buffered body
/// (rewritten / intercepted responses) or a streaming tee of the upstream body
/// (SSE / chunked / long-poll passthrough). Boxing unifies both so `handle` has
/// a single return type.
pub type ProxyBody = BoxBody<Bytes, BoxErr>;

/// Wrap fully-buffered `bytes` as a [`ProxyBody`].
pub fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

/// Cap applied to the STORED copy of a body (via [`cap_for_store`]). Bodies are
/// always FORWARDED in full — only the copy persisted to the session DB is
/// bounded, so large uploads/downloads are captured-but-truncated rather than
/// corrupted on the wire.
const BODY_CAP: usize = 8 * 1024 * 1024;

/// Hard ceiling on a body buffered for FORWARDING. The match/replace and
/// intercept primitives need the full body in memory, so we cannot stream it
/// through — but we MUST bound the buffer or an adversarial client/origin can
/// stream gigabytes (chunked or via a huge Content-Length) and OOM the proxy
/// one connection at a time. 256 MiB is generous (well above the
/// [`BODY_CAP`] store cap, which only governs the persisted copy) yet finite;
/// bodies above it are refused (413 downstream / 502 upstream) rather than
/// buffered without limit.
const FORWARD_BODY_CAP: usize = 256 * 1024 * 1024;

/// Max time to read the inbound request headers before the connection is torn
/// down. Bounds slowloris-style header dribbling against the served side.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Max time to establish the upstream TCP (and, for MITM, TLS) connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall budget for the upstream request/response exchange (send the request,
/// receive the headers, and collect the full body). Bounds a slow/silent origin
/// from pinning a downstream connection and its buffers indefinitely.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);

/// How the proxy reaches the origin for a given served connection.
#[derive(Clone)]
pub enum Upstream {
    /// Cleartext HTTP over plain TCP to `addr`.
    Plain {
        /// Origin socket address.
        addr: SocketAddr,
    },
    /// TLS to `addr`, using `server_name` for SNI/validation, mirroring ALPN.
    Tls {
        /// Origin socket address.
        addr: SocketAddr,
        /// SNI / certificate validation name.
        server_name: String,
        /// Connector with the desired ALPN list.
        connector: TlsConnector,
    },
}

/// Shared per-connection context for the HTTP service.
#[derive(Clone)]
pub struct HttpContext {
    /// Store write handle.
    pub writer: WriteHandle,
    /// Intercept primitive.
    pub intercept: InterceptController,
    /// Session-auth auto-refresh trigger (inert unless the daemon armed it).
    pub auth: crate::auth::AuthWatcher,
    /// Match/replace rules, snapshotted for the life of the connection.
    pub rules: Arc<Vec<burpwn_store::model::MatchReplaceRule>>,
    /// Default workspace id.
    pub workspace_id: i64,
    /// Optional exec correlation id.
    pub exec_id: Option<String>,
    /// Client peer address string.
    pub client_addr: String,
    /// Destination IP (for the flow row).
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Observed SNI (MITM) if any.
    pub sni: Option<String>,
    /// `http` or `https`.
    pub scheme: String,
    /// How to reach the origin.
    pub upstream: Upstream,
    /// Negotiated (downstream MITM) TLS protocol version, e.g. `TLSv1.3`.
    pub tls_version: Option<String>,
    /// Negotiated (downstream MITM) cipher suite.
    pub tls_cipher: Option<String>,
    /// Negotiated (downstream MITM) ALPN protocol, e.g. `h2`.
    pub tls_alpn: Option<String>,
}

/// Serve a downstream connection that negotiated HTTP/1.1 (or cleartext H1).
/// Handles WebSocket upgrades via hyper's upgrade machinery.
pub async fn serve_h1<S>(stream: S, ctx: HttpContext) -> Result<(), hyper::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle(req, ctx).await) }
    });
    hyper::server::conn::http1::Builder::new()
        // Bound slowloris-style header dribbling on the served (downstream) side.
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(io, service)
        .with_upgrades()
        .await
}

/// Serve a downstream connection that negotiated HTTP/2.
pub async fn serve_h2<S>(stream: S, ctx: HttpContext) -> Result<(), hyper::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle(req, ctx).await) }
    });
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
}

/// Public entry for the explicit-proxy cleartext path: handle one request whose
/// upstream is already resolved in `ctx`. Mirrors the in-line service handler.
pub async fn handle_explicit(req: Request<Incoming>, ctx: HttpContext) -> Response<ProxyBody> {
    handle(req, ctx).await
}

/// The per-request handler shared by H1 and H2.
async fn handle(req: Request<Incoming>, ctx: HttpContext) -> Response<ProxyBody> {
    match handle_inner(req, ctx).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "proxy request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::from_static(b"burpwn: upstream error")))
                .unwrap()
        }
    }
}

async fn handle_inner(
    mut req: Request<Incoming>,
    ctx: HttpContext,
) -> anyhow::Result<Response<ProxyBody>> {
    let started = Instant::now();
    let version = req.version();
    let is_ws = is_websocket_upgrade(req.headers());

    // Capture the downstream upgrade future BEFORE consuming the request; this
    // resolves once we return a 101 and the server upgrades the connection.
    let downstream_upgrade = if is_ws {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    // Decompose the request.
    let (parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());
    let host = request_host(&parts);
    let raw_req_headers = serialize_headers(&parts.headers);
    let req_body = match collect_body(body).await? {
        BufferedBody::Full(b) => b,
        BufferedBody::TooLarge => {
            tracing::warn!(
                %host,
                cap = FORWARD_BODY_CAP,
                "request body exceeds forward cap; refusing"
            );
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(full_body(Bytes::from_static(
                    b"burpwn: request body too large",
                )))
                .unwrap());
        }
    };

    // --- request-side match/replace ---
    let mut msg = Message {
        host: host.clone(),
        url: path.clone(),
        headers: raw_req_headers.clone(),
        body: req_body.clone(),
    };
    let _ = apply_request(&ctx.rules, &mut msg);

    // --- intercept (request) ---
    let mut idata = InterceptData {
        host: msg.host.clone(),
        method: method.clone(),
        path: msg.url.clone(),
        headers: msg.headers.clone(),
        body: msg.body.clone(),
    };
    let intercepted = ctx.intercept.is_enabled();
    match ctx
        .intercept
        .intercept(InterceptKind::Request, idata.clone())
        .await
    {
        InterceptDecision::Forward(None) => {}
        InterceptDecision::Forward(Some(edited)) => {
            idata = edited;
            msg.host = idata.host.clone();
            msg.url = idata.path.clone();
            msg.headers = idata.headers.clone();
            msg.body = idata.body.clone();
        }
        InterceptDecision::Drop => {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full_body(Bytes::from_static(
                    b"burpwn: dropped by intercept",
                )))
                .unwrap());
        }
    }

    // --- record the flow + request ---
    let flow_id = ctx
        .writer
        .flow_start(FlowStart {
            workspace_id: ctx.workspace_id,
            ts_start: now_millis(),
            exec_id: ctx.exec_id.clone(),
            client_addr: ctx.client_addr.clone(),
            dst_ip: ctx.dst_ip.clone(),
            dst_port: ctx.dst_port,
            sni: ctx.sni.clone(),
            scheme: ctx.scheme.clone(),
            protocol: if is_ws {
                Protocol::Ws
            } else {
                version_to_protocol(version)
            },
            intercepted,
        })
        .await?;
    // gRPC request bodies are length-prefixed frames; deframe the STORED copy so
    // the capture isn't opaque (best-effort; non-gRPC bodies pass through).
    let req_content_type = header_str(&parts.headers, CONTENT_TYPE);
    let req_store_body = maybe_degrpc(req_content_type.as_deref(), &msg.body);
    let _ = ctx
        .writer
        .request(
            flow_id,
            RequestData {
                method: method.clone(),
                authority: msg.host.clone(),
                path: msg.url.clone(),
                http_version: version_str(version).into(),
                headers: msg.headers.clone(),
                body: cap_for_store(req_store_body.as_deref().unwrap_or(&msg.body)),
            },
        )
        .await;

    // --- build the upstream request from the (possibly edited) message ---
    // For a WebSocket upgrade we must NOT strip Connection/Upgrade/Sec-WebSocket-*:
    // RFC6455 requires the origin to see `Connection: Upgrade` + `Upgrade:
    // websocket` (and the Sec-WebSocket-Key/Version) or it never returns 101.
    let upstream_req = build_upstream_request(&parts, &method, &msg, version, is_ws)?;

    // WebSocket: hand off to the splice path after the handshake.
    if is_ws {
        return websocket_forward(upstream_req, ctx, flow_id, downstream_upgrade).await;
    }

    // --- forward: open upstream + read the response HEADERS (streaming body) ---
    // A connect/handshake/header timeout surfaces here as an `Err`, which `handle`
    // turns into a 502. The BODY is not collected yet — that is decided below.
    let (resp_parts, resp_body, up_guard, origin_cert_fp) =
        forward_streaming(&ctx.upstream, upstream_req).await?;

    // Best-effort session-auth AUTO-refresh hook: signal the (debounced) host on
    // a 401/403 so the daemon can re-mint an expired token. Inert (cheap no-op)
    // unless the daemon armed the watcher via `AuthWatcher::activate`. Covers
    // both the streaming and buffered response paths since the status is known
    // here, before either branch. See [`crate::auth`] for the recursion guard.
    ctx.auth.observe(&msg.host, resp_parts.status.as_u16());

    // --- TLS/connection metadata (best-effort) ---
    // Negotiated version/cipher/alpn come from the downstream MITM handshake
    // (carried on `ctx`); the origin leaf cert fingerprint from the upstream leg.
    if ctx.tls_version.is_some()
        || ctx.tls_cipher.is_some()
        || ctx.tls_alpn.is_some()
        || origin_cert_fp.is_some()
    {
        let _ = ctx
            .writer
            .set_flow_tls_meta(
                flow_id,
                ctx.tls_version.clone(),
                ctx.tls_cipher.clone(),
                ctx.tls_alpn.clone(),
                origin_cert_fp,
            )
            .await;
    }

    // --- HYBRID streaming decision ---
    // When NO match/replace rule targets this host AND intercept is disabled, we
    // never need the full body: stream it through chunk-by-chunk (fixing SSE /
    // chunked / long-poll, which otherwise stall until EOF or the upstream
    // timeout) while tee-ing a size-capped copy to the store. Otherwise we must
    // buffer the whole body to rewrite / hold it.
    if should_stream(&ctx, &msg.host) {
        return Ok(stream_response(
            resp_parts, resp_body, up_guard, &ctx, flow_id, started, version,
        ));
    }

    // --- buffer path: collect the full body (bounded) then rewrite/intercept ---
    let resp_body_bytes = with_timeout(
        UPSTREAM_TIMEOUT,
        "upstream body",
        collect_incoming(resp_body),
    )
    .await??;
    drop(up_guard);
    let raw_resp_headers = serialize_headers(&resp_parts.headers);

    // Decode a COPY for storage; never alter forwarded bytes.
    let content_encoding = resp_parts
        .headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let resp_content_type = header_str(&resp_parts.headers, CONTENT_TYPE);
    // gRPC bodies are length-prefixed frames; deframe the STORED copy so it isn't
    // opaque. Falls back to the decoded bytes when it isn't gRPC / can't deframe.
    let decoded_for_store = {
        let decoded = decode_body(content_encoding, &resp_body_bytes);
        maybe_degrpc(resp_content_type.as_deref(), &decoded).unwrap_or(decoded)
    };

    // --- response-side match/replace (operates on decoded body view) ---
    let mut resp_msg = Message {
        host: msg.host.clone(),
        url: msg.url.clone(),
        headers: raw_resp_headers.clone(),
        body: decoded_for_store.clone(),
    };
    let resp_changed = apply_response(&ctx.rules, &mut resp_msg);

    // --- intercept (response) ---
    let resp_idata = InterceptData {
        host: msg.host.clone(),
        method: method.clone(),
        path: msg.url.clone(),
        headers: resp_msg.headers.clone(),
        body: resp_msg.body.clone(),
    };
    let mut forward_headers = resp_parts.headers.clone();
    let mut forward_body = resp_body_bytes.clone();
    let mut store_headers = raw_resp_headers;
    let mut store_body = decoded_for_store;
    match ctx
        .intercept
        .intercept(InterceptKind::Response, resp_idata)
        .await
    {
        InterceptDecision::Forward(None) => {
            if resp_changed {
                // A rule changed the (decoded) body: forward the modified body,
                // strip Content-Encoding since we now emit plaintext.
                forward_headers = headers_from_bytes(&resp_msg.headers, &resp_parts.headers);
                forward_headers.remove(CONTENT_ENCODING);
                forward_body = Bytes::from(resp_msg.body.clone());
                store_headers = resp_msg.headers.clone();
                store_body = resp_msg.body.clone();
            }
        }
        InterceptDecision::Forward(Some(edited)) => {
            forward_headers = headers_from_bytes(&edited.headers, &resp_parts.headers);
            forward_headers.remove(CONTENT_ENCODING);
            forward_body = Bytes::from(edited.body.clone());
            store_headers = edited.headers.clone();
            store_body = edited.body.clone();
        }
        InterceptDecision::Drop => {
            let _ = ctx.writer.flow_end(flow_id, now_millis()).await;
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full_body(Bytes::from_static(b"burpwn: response dropped")))
                .unwrap());
        }
    }

    let status = resp_parts.status;
    let timing = started.elapsed().as_millis() as i64;
    let _ = ctx
        .writer
        .response(
            flow_id,
            ResponseData {
                status: status.as_u16(),
                http_version: version_str(version).into(),
                headers: store_headers,
                body: cap_for_store(&store_body),
                timing_ms: Some(timing),
            },
        )
        .await;
    let _ = ctx.writer.flow_end(flow_id, now_millis()).await;

    // --- return the buffered response downstream ---
    let mut builder = Response::builder().status(status);
    {
        let hdrs = builder.headers_mut().unwrap();
        *hdrs = forward_headers;
        sanitize_downstream_headers(hdrs);
    }
    Ok(builder.body(full_body(forward_body))?)
}

/// Strip framing + connection-specific + h3-advertising headers before relaying
/// a response downstream:
/// - `Content-Length` / `Transfer-Encoding`: hyper recomputes framing.
/// - `Connection` / `Upgrade` / `keep-alive` / `proxy-connection`: illegal when
///   the downstream is HTTP/2 (an h1 origin response relayed to an h2 client).
/// - `Alt-Svc`: advertises HTTP/3 over QUIC/UDP-443, which the sandbox
///   blackholes — clients that try h3 then hang. Removing it deterministically
///   keeps clients on h2/h1.
fn sanitize_downstream_headers(hdrs: &mut hyper::HeaderMap) {
    hdrs.remove(hyper::header::CONTENT_LENGTH);
    hdrs.remove(hyper::header::TRANSFER_ENCODING);
    hdrs.remove(hyper::header::CONNECTION);
    hdrs.remove(hyper::header::UPGRADE);
    hdrs.remove("keep-alive");
    hdrs.remove("proxy-connection");
    hdrs.remove("alt-svc");
}

/// Whether the response body for this flow can be streamed straight through
/// (tee-ing a capped copy) rather than buffered: true when interception is off
/// AND no enabled match/replace rule targets this host, so we never need the full
/// body to rewrite or hold it.
fn should_stream(ctx: &HttpContext, host: &str) -> bool {
    if ctx.intercept.is_enabled() {
        return false;
    }
    !ctx.rules
        .iter()
        .any(|r| r.enabled && host_in_scope(&r.scope, host))
}

/// gRPC message framing: `application/grpc*` bodies are a sequence of
/// `flag(1) | length(4, big-endian) | message` frames. Deframe them into the
/// concatenated message payloads (newline-separated) for the STORED/searchable
/// copy so the capture isn't opaque. Returns `None` when it isn't gRPC or the
/// framing doesn't parse cleanly (caller keeps the original bytes). Minimal by
/// design — no protobuf decoding.
fn maybe_degrpc(content_type: Option<&str>, body: &[u8]) -> Option<Vec<u8>> {
    let ct = content_type?;
    if !ct
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("application/grpc")
    {
        return None;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0usize;
    let mut frames = 0usize;
    while i + 5 <= body.len() {
        let len = u32::from_be_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]]) as usize;
        let start = i + 5;
        let end = start.checked_add(len)?;
        if end > body.len() {
            // Truncated final frame (or not really gRPC): bail cleanly.
            break;
        }
        if frames > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(&body[start..end]);
        i = end;
        frames += 1;
    }
    // Only claim success if we actually consumed at least one whole frame and the
    // stream ended on a frame boundary (garbage would leave a partial remainder).
    if frames == 0 || i != body.len() {
        return None;
    }
    Some(out)
}

/// Fetch a header value as an owned UTF-8 string, if present + valid.
fn header_str(headers: &hyper::HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Build a downstream response that STREAMS the upstream body through verbatim
/// while tee-ing a [`BODY_CAP`]-bounded copy to the store. The response row +
/// `flow_end` are written when the stream completes (or the body is dropped).
fn stream_response(
    parts: http::response::Parts,
    body: Incoming,
    guard: AbortOnDrop,
    ctx: &HttpContext,
    flow_id: i64,
    started: Instant,
    version: Version,
) -> Response<ProxyBody> {
    let status = parts.status;
    let stored_headers = serialize_headers(&parts.headers);
    let mut forward_headers = parts.headers.clone();
    sanitize_downstream_headers(&mut forward_headers);

    let tee = TeeBody {
        inner: body,
        _guard: guard,
        state: Some(TeeState {
            writer: ctx.writer.clone(),
            flow_id,
            status: status.as_u16(),
            http_version: version_str(version).into(),
            headers: stored_headers,
            captured: Vec::new(),
            started,
        }),
    };

    let mut builder = Response::builder().status(status);
    if let Some(hdrs) = builder.headers_mut() {
        *hdrs = forward_headers;
    }
    builder
        .body(tee.boxed())
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

/// Per-stream capture state persisted once the streamed body ends.
struct TeeState {
    writer: WriteHandle,
    flow_id: i64,
    status: u16,
    http_version: String,
    headers: Vec<u8>,
    captured: Vec<u8>,
    started: Instant,
}

/// A response body that forwards the upstream [`Incoming`] frames verbatim while
/// tee-ing a size-capped copy to the store. When the stream terminates (EOF,
/// error, or drop) it records the response row + `flow_end`. Holds the upstream
/// connection guard so the driver task lives exactly as long as the body.
struct TeeBody {
    inner: Incoming,
    _guard: AbortOnDrop,
    state: Option<TeeState>,
}

impl TeeBody {
    /// Persist the captured response exactly once (idempotent).
    ///
    /// This runs from `poll_frame` (stream end) OR `drop` (downstream disconnect /
    /// connection teardown). The drop can happen outside a Tokio runtime context —
    /// notably for H2, where hyper drops the response body as the connection winds
    /// down — so a detached `tokio::spawn` here would be cancelled (or panic for lack
    /// of a runtime) before its channel send lands, silently losing the response row
    /// (the request, DNS and buffered-HTTP writes all await inline and survive; only
    /// this streaming path spawned). Enqueue synchronously onto the persistent writer
    /// channel instead — `try_send` needs neither `.await` nor a runtime.
    fn finish(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        let timing = state.started.elapsed().as_millis() as i64;
        let ok = state.writer.response_sync(
            state.flow_id,
            ResponseData {
                status: state.status,
                http_version: state.http_version,
                headers: state.headers,
                body: state.captured,
                timing_ms: Some(timing),
            },
        );
        if !ok {
            tracing::warn!(
                flow_id = state.flow_id,
                "streaming response write dropped (writer channel full/closed)"
            );
        }
        let _ = state.writer.flow_end_sync(state.flow_id, now_millis());
    }
}

impl Body for TeeBody {
    type Data = Bytes;
    type Error = BoxErr;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxErr>>> {
        // TeeBody is Unpin (Incoming / Option / AbortOnDrop are all Unpin).
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(state) = this.state.as_mut() {
                        let remaining = BODY_CAP.saturating_sub(state.captured.len());
                        if remaining > 0 {
                            let take = data.len().min(remaining);
                            state.captured.extend_from_slice(&data[..take]);
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finish();
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for TeeBody {
    fn drop(&mut self) {
        // A downstream disconnect can drop the body without a terminal poll;
        // still persist whatever we captured so the flow isn't lost.
        self.finish();
    }
}

/// Open the upstream connection and read the response HEADERS, returning the
/// still-unread streaming body plus a guard that keeps the connection driver
/// alive while the body is consumed, and (for TLS) the origin leaf cert
/// fingerprint. The connect/handshake is bounded by [`CONNECT_TIMEOUT`] and
/// reading the response headers by [`UPSTREAM_TIMEOUT`]; the BODY read is
/// deliberately NOT time-bounded here so long-lived streams (SSE / long-poll)
/// are not killed at [`UPSTREAM_TIMEOUT`] — the buffered caller re-imposes a
/// body timeout when it collects.
async fn forward_streaming(
    upstream: &Upstream,
    req: Request<Full<Bytes>>,
) -> anyhow::Result<(http::response::Parts, Incoming, AbortOnDrop, Option<String>)> {
    match upstream {
        Upstream::Plain { addr } => {
            let tcp = with_timeout(
                CONNECT_TIMEOUT,
                "upstream connect",
                TcpStream::connect(*addr),
            )
            .await??;
            // No ALPN on a cleartext upstream: default to HTTP/1.1 (prior-knowledge
            // h2c is rare and not something we negotiated).
            let (parts, body, guard) = with_timeout(
                UPSTREAM_TIMEOUT,
                "upstream headers",
                send_over_streaming(tcp, req, false, "http"),
            )
            .await??;
            Ok((parts, body, guard, None))
        }
        Upstream::Tls {
            addr,
            server_name,
            connector,
        } => {
            let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
                .map_err(|_| anyhow::anyhow!("invalid upstream server name"))?;
            // TCP connect + TLS handshake share the connect budget.
            let tls = with_timeout(CONNECT_TIMEOUT, "upstream connect", async {
                let tcp = TcpStream::connect(*addr).await?;
                connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(anyhow::Error::from)
            })
            .await??;
            // Fingerprint the ORIGIN's leaf certificate (SHA-256, hex) before we
            // move the stream into the sender.
            let cert_fp = leaf_cert_fp(tls.get_ref().1.peer_certificates());
            // The UPSTREAM leg's protocol is whatever ALPN negotiated — independent
            // of the downstream version (a client may speak h2 to us while the
            // origin only speaks h1, or vice versa).
            let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            let (parts, body, guard) = with_timeout(
                UPSTREAM_TIMEOUT,
                "upstream headers",
                send_over_streaming(tls, req, is_h2, "https"),
            )
            .await??;
            Ok((parts, body, guard, cert_fp))
        }
    }
}

/// SHA-256 (hex) of the first (leaf) certificate in a peer chain, if present.
fn leaf_cert_fp(chain: Option<&[rustls::pki_types::CertificateDer<'static>]>) -> Option<String> {
    let leaf = chain?.first()?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(leaf.as_ref());
    Some(hex_lower(&hasher.finalize()))
}

/// Lowercase hex-encode bytes (no external hex crate).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Run `fut` under `dur`, mapping an elapsed timeout to a labelled error so the
/// flow fails cleanly (502 + log) instead of hanging. The inner future's own
/// result type is preserved.
async fn with_timeout<F, T>(dur: Duration, what: &'static str, fut: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(dur, fut)
        .await
        .map_err(|_| anyhow::anyhow!("{what} timed out after {dur:?}"))
}

/// Drive one request over an established (plain or TLS) byte stream using hyper's
/// client connection and collect the FULL response (bounded). `use_h2` is the
/// UPSTREAM-negotiated protocol (from ALPN), NOT the downstream version. Thin
/// wrapper over [`send_over_streaming`] used by the replay path and anywhere a
/// buffered response is wanted.
pub(crate) async fn send_over<S>(
    stream: S,
    req: Request<Full<Bytes>>,
    use_h2: bool,
    scheme: &str,
) -> anyhow::Result<(http::response::Parts, Bytes)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (parts, body, guard) = send_over_streaming(stream, req, use_h2, scheme).await?;
    let bytes = collect_incoming(body).await?;
    drop(guard);
    Ok((parts, bytes))
}

/// Drive one request and return the response HEADERS + the still-unread streaming
/// body + a guard keeping the connection driver alive. `use_h2` selects the
/// upstream protocol; `scheme` builds the absolute URI HTTP/2 requires.
pub(crate) async fn send_over_streaming<S>(
    stream: S,
    mut req: Request<Full<Bytes>>,
    use_h2: bool,
    scheme: &str,
) -> anyhow::Result<(http::response::Parts, Incoming, AbortOnDrop)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    if use_h2 {
        // HTTP/2 derives :scheme/:authority/:path from the URI, so it MUST be
        // absolute. The request comes in origin-form (path only) with the
        // authority in the Host header — promote it to an absolute URI and drop
        // Host (HTTP/2 forbids it; the authority travels as :authority).
        promote_to_absolute_uri(&mut req, scheme);
        req.headers_mut().remove(HOST);
        *req.version_mut() = Version::HTTP_2;
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        // Abort (not just detach) the conn driver when the guard is dropped — e.g.
        // an enclosing timeout fires, or the streaming body is dropped — so the
        // upstream task and its fd are not leaked.
        let guard = AbortOnDrop(tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "upstream h2 conn closed");
            }
        }));
        let resp = sender.send_request(req).await?;
        let (parts, body) = resp.into_parts();
        Ok((parts, body, guard))
    } else {
        // HTTP/1.1: origin-form path + Host header (already set). Pin the version
        // in case the downstream request arrived as h2.
        *req.version_mut() = Version::HTTP_11;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        let guard = AbortOnDrop(tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "upstream h1 conn closed");
            }
        }));
        let resp = sender.send_request(req).await?;
        let (parts, body) = resp.into_parts();
        Ok((parts, body, guard))
    }
}

/// Aborts the wrapped task when dropped, so an upstream connection driver spawned
/// for one request is not left running (leaking a task + fd) if the request
/// future is cancelled — e.g. by [`UPSTREAM_TIMEOUT`].
pub(crate) struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Rewrite an origin-form request URI (`/path`) into the absolute form
/// (`scheme://authority/path`) HTTP/2 needs, taking the authority from the
/// existing URI if present, else the `Host` header. No-op if already absolute.
fn promote_to_absolute_uri(req: &mut Request<Full<Bytes>>, scheme: &str) {
    if req.uri().authority().is_some() && req.uri().scheme().is_some() {
        return;
    }
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });
    let Some(authority) = authority else { return };
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    if let Ok(uri) = format!("{scheme}://{authority}{pq}").parse::<http::Uri>() {
        *req.uri_mut() = uri;
    }
}

/// Collect an upstream response body, bounding it at [`FORWARD_BODY_CAP`] so a
/// malicious origin cannot OOM the proxy. An over-cap body fails the flow (the
/// caller surfaces a 502) rather than buffering without limit.
async fn collect_incoming(body: Incoming) -> anyhow::Result<Bytes> {
    let limited = Limited::new(body, FORWARD_BODY_CAP);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        // `Limited` boxes a `LengthLimitError` on overflow; any other error is a
        // real read failure on the wire.
        Err(e)
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            Err(anyhow::anyhow!(
                "upstream response body exceeds forward cap ({FORWARD_BODY_CAP} bytes)"
            ))
        }
        Err(e) => Err(anyhow::anyhow!("read upstream body: {e}")),
    }
}

/// Build the request to send upstream from the original parts + the (possibly
/// rule/intercept-edited) [`Message`]. We rebuild the header map from the raw
/// header bytes so edits are honored, then re-target the URI to origin-form.
fn build_upstream_request(
    orig: &http::request::Parts,
    method: &str,
    msg: &Message,
    version: Version,
    is_ws: bool,
) -> anyhow::Result<Request<Full<Bytes>>> {
    let mut headers = headers_from_bytes(&msg.headers, &orig.headers);
    // Always carry the (possibly rewritten) authority in the Host header. The H1
    // sender uses it directly; the H2 sender promotes it to the :authority of an
    // absolute URI and then strips Host (HTTP/2 forbids it).
    if let Ok(hv) = HeaderValue::from_str(&msg.host) {
        headers.insert(HOST, hv);
    }
    // Drop hop-by-hop framing we will recompute.
    headers.remove(hyper::header::CONTENT_LENGTH);
    headers.remove(hyper::header::TRANSFER_ENCODING);
    // Strip connection-specific headers that are illegal on an HTTP/2 leg — but
    // NOT for a WebSocket upgrade, which goes out over HTTP/1.1 and MUST carry
    // `Connection: Upgrade` + `Upgrade: websocket` (and the Sec-WebSocket-* set,
    // which `headers_from_bytes` already preserved) verbatim, or the origin will
    // never answer 101 (RFC6455).
    if !is_ws {
        headers.remove(hyper::header::CONNECTION);
        headers.remove(hyper::header::UPGRADE);
        headers.remove("keep-alive");
        headers.remove("proxy-connection");
    }

    let uri: http::Uri = msg.url.parse().unwrap_or_else(|_| orig.uri.clone());
    // A WebSocket upgrade is always replayed upstream over HTTP/1.1 (see
    // `ws_handshake_upstream`), so pin the version even if the downstream request
    // arrived as h2 — an `Upgrade` over h2 is meaningless.
    let out_version = if is_ws { Version::HTTP_11 } else { version };
    let mut builder = Request::builder()
        .method(method.as_bytes())
        .uri(uri)
        .version(out_version);
    {
        let h = builder.headers_mut().unwrap();
        *h = headers;
    }
    Ok(builder.body(Full::new(Bytes::from(msg.body.clone())))?)
}

/// Outcome of buffering a forward-path body under the [`FORWARD_BODY_CAP`]
/// ceiling: either the full bytes, or a signal that the cap was exceeded so the
/// caller can refuse the flow instead of buffering without limit.
enum BufferedBody {
    /// The full body, under the cap.
    Full(Vec<u8>),
    /// The body exceeded [`FORWARD_BODY_CAP`]; refuse rather than OOM.
    TooLarge,
}

/// Collect a request body in FULL (so it can be forwarded upstream unchanged),
/// bounded by [`FORWARD_BODY_CAP`] so an adversarial client cannot OOM the proxy
/// by streaming an unbounded body. Truncation of the STORED copy is separate and
/// applies via [`cap_for_store`]. A genuine transport error still surfaces as an
/// `Err`; only an over-cap body maps to [`BufferedBody::TooLarge`].
async fn collect_body(body: Incoming) -> anyhow::Result<BufferedBody> {
    let limited = Limited::new(body, FORWARD_BODY_CAP);
    match limited.collect().await {
        Ok(collected) => Ok(BufferedBody::Full(collected.to_bytes().to_vec())),
        // `Limited` boxes a `LengthLimitError` on overflow; any other error is a
        // real read failure on the wire.
        Err(e)
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            Ok(BufferedBody::TooLarge)
        }
        Err(e) => Err(anyhow::anyhow!("read body: {e}")),
    }
}

/// A copy of a body bounded to [`BODY_CAP`] for STORAGE only (never for
/// forwarding). Bodies above the cap are truncated in the store but forwarded
/// in full, so large uploads/downloads are not corrupted.
fn cap_for_store(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(BODY_CAP)].to_vec()
}

/// Serialize a `HeaderMap` to order-preserving `Name: Value\r\n…` bytes.
pub fn serialize_headers(headers: &hyper::HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Reconstruct a `HeaderMap` from raw `Name: Value\r\n` bytes. On any malformed
/// line we fall back to the provided original map (so we never send garbage).
fn headers_from_bytes(bytes: &[u8], fallback: &hyper::HeaderMap) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return fallback.clone(),
    };
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return fallback.clone();
        };
        let name = name.trim();
        let value = value.trim_start();
        match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                map.append(n, v);
            }
            _ => return fallback.clone(),
        }
    }
    if map.is_empty() && !fallback.is_empty() {
        return fallback.clone();
    }
    map
}

/// Compute the request host from authority or the `Host` header.
fn request_host(parts: &http::request::Parts) -> String {
    if let Some(auth) = parts.uri.authority() {
        return auth.host().to_string();
    }
    parts
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default()
}

fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    let has_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    let is_ws = headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    has_upgrade && is_ws
}

fn version_to_protocol(v: Version) -> Protocol {
    if v == Version::HTTP_2 {
        Protocol::H2
    } else {
        Protocol::H1
    }
}

fn version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

/// WebSocket forwarding: open a plain/TLS upstream H1 connection, replay the
/// upgrade request, and on a `101` splice the two upgraded byte streams. The
/// bytes are forwarded verbatim on the wire; a COPY of each direction is parsed
/// into structured, complete WebSocket messages and persisted (see [`splice_ws`]).
async fn websocket_forward(
    req: Request<Full<Bytes>>,
    ctx: HttpContext,
    flow_id: i64,
    downstream_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> anyhow::Result<Response<ProxyBody>> {
    let (up_parts, up_upgrade) = match &ctx.upstream {
        Upstream::Plain { addr } => {
            let tcp = TcpStream::connect(*addr).await?;
            ws_handshake_upstream(tcp, req).await?
        }
        Upstream::Tls {
            addr,
            server_name,
            connector,
        } => {
            let tcp = TcpStream::connect(*addr).await?;
            let sn = rustls::pki_types::ServerName::try_from(server_name.clone())
                .map_err(|_| anyhow::anyhow!("invalid upstream server name"))?;
            let tls = connector.connect(sn, tcp).await?;
            ws_handshake_upstream(tls, req).await?
        }
    };

    if up_parts.status != StatusCode::SWITCHING_PROTOCOLS {
        // Not an upgrade after all — relay the (non-101) response as-is.
        let _ = ctx.writer.flow_end(flow_id, now_millis()).await;
        let mut builder = Response::builder().status(up_parts.status);
        *builder.headers_mut().unwrap() = up_parts.headers;
        return Ok(builder.body(full_body(Bytes::new()))?);
    }

    // Build the 101 we return downstream, mirroring the upstream's headers. The
    // server layer (`.with_upgrades()`) upgrades the downstream connection when
    // it writes this response, resolving `downstream_upgrade`.
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    *builder.headers_mut().unwrap() = up_parts.headers.clone();
    let downstream_resp = builder.body(full_body(Bytes::new()))?;

    // Splice both upgraded streams once they're ready.
    let writer = ctx.writer.clone();
    tokio::spawn(async move {
        let Some(down_fut) = downstream_upgrade else {
            return;
        };
        let (down, up) = match tokio::join!(down_fut, up_upgrade) {
            (Ok(d), Ok(u)) => (TokioIo::new(d), TokioIo::new(u)),
            _ => {
                let _ = writer.flow_end(flow_id, now_millis()).await;
                return;
            }
        };
        splice_ws(down, up, writer.clone(), flow_id).await;
        let _ = writer.flow_end(flow_id, now_millis()).await;
    });

    Ok(downstream_resp)
}

/// Splice two upgraded WebSocket streams. Each direction is forwarded verbatim
/// (the wire is never altered) while a COPY is fed to a [`ws::Scanner`] that
/// parses frames, unmasks client→server frames, reassembles continuation
/// fragments, and persists each COMPLETE message via [`WriteOp::InsertWsMessage`]
/// with the right direction + opcode/fin. Control frames (ping/pong/close) are
/// recorded with their opcode but never treated as data.
async fn splice_ws<D, U>(downstream: D, upstream: U, writer: WriteHandle, flow_id: i64)
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (dr, dw) = tokio::io::split(downstream);
    let (ur, uw) = tokio::io::split(upstream);

    let w1 = writer.clone();
    let c2s = tokio::spawn(pump_ws(dr, uw, w1, flow_id, WsDirection::C2s));
    let w2 = writer.clone();
    let s2c = tokio::spawn(pump_ws(ur, dw, w2, flow_id, WsDirection::S2c));
    join_half_open(c2s, s2c, SPLICE_DRAIN_GRACE).await;
}

/// Pump one WebSocket direction: forward every byte to `w` verbatim, and feed a
/// copy through a frame [`ws::Scanner`], persisting each completed message.
async fn pump_ws<R, W>(
    mut r: R,
    mut w: W,
    writer: WriteHandle,
    flow_id: i64,
    direction: WsDirection,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut scanner = ws::Scanner::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // Forward verbatim FIRST; capture must never delay or alter the wire.
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        for msg in scanner.push(&buf[..n]) {
            // Fire-and-forget: enqueue the write but don't block the pump on the
            // DB ack (the id reply is discarded via a dropped receiver).
            let (reply, _rx) = tokio::sync::oneshot::channel();
            let _ = writer
                .send(WriteOp::InsertWsMessage {
                    flow_id,
                    direction,
                    opcode: Some(msg.opcode as i64),
                    fin: Some(msg.fin),
                    payload: msg.payload,
                    ts: now_millis(),
                    reply,
                })
                .await;
        }
    }
    let _ = w.shutdown().await;
}

/// Grace period a still-open splice direction is given to drain after its
/// sibling has finished, before it is aborted. On a normal WebSocket/TCP close
/// both directions EOF within this window so no in-flight bytes are truncated; a
/// peer that half-closes one direction and holds the other open+silent is torn
/// down after the grace, preventing the sibling from blocking on `read` forever
/// (task + fd leak).
const SPLICE_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Join two splice-direction tasks without leaking on a half-open peer: wait for
/// the FIRST to finish, then give the sibling `grace` to drain its remaining
/// bytes; abort it only if it overruns that window. Returns once both are done
/// (or the survivor was aborted).
async fn join_half_open(
    mut c2s: tokio::task::JoinHandle<()>,
    mut s2c: tokio::task::JoinHandle<()>,
    grace: Duration,
) {
    let c2s_abort = c2s.abort_handle();
    let s2c_abort = s2c.abort_handle();
    // Wait for the FIRST direction to finish. The arms return a bool (no borrow
    // escapes the select), so both `&mut` future borrows are released before we
    // await the survivor below.
    let c2s_finished_first = tokio::select! {
        _ = &mut c2s => true,
        _ = &mut s2c => false,
    };
    let survivor = if c2s_finished_first {
        &mut s2c
    } else {
        &mut c2s
    };
    if tokio::time::timeout(grace, &mut *survivor).await.is_err() {
        // Whichever handle is still live: aborting the already-finished one is a
        // no-op, so abort both rather than thread the identity through.
        c2s_abort.abort();
        s2c_abort.abort();
        // Reap the aborted survivor so it is actually finished on return (abort
        // only schedules cancellation; awaiting drives it to completion).
        let _ = survivor.await;
    }
}

/// Perform the upstream side of a WebSocket handshake over `stream`, returning
/// the response parts and the upgrade future for the upgraded byte stream.
async fn ws_handshake_upstream<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> anyhow::Result<(http::response::Parts, hyper::upgrade::OnUpgrade)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let mut resp = sender.send_request(req).await?;
    let upgrade = hyper::upgrade::on(&mut resp);
    let (parts, _body) = resp.into_parts();
    Ok((parts, upgrade))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_headers_is_order_preserving() {
        let mut h = hyper::HeaderMap::new();
        h.append(HOST, HeaderValue::from_static("example.com"));
        h.append(
            hyper::header::USER_AGENT,
            HeaderValue::from_static("curl/8"),
        );
        let bytes = serialize_headers(&h);
        assert_eq!(bytes, b"host: example.com\r\nuser-agent: curl/8\r\n");
    }

    #[test]
    fn header_roundtrip_through_bytes() {
        let mut h = hyper::HeaderMap::new();
        h.append(HOST, HeaderValue::from_static("a.test"));
        h.append(
            hyper::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        let bytes = serialize_headers(&h);
        let back = headers_from_bytes(&bytes, &hyper::HeaderMap::new());
        assert_eq!(back.get(HOST).unwrap(), "a.test");
        assert_eq!(back.get(hyper::header::ACCEPT).unwrap(), "application/json");
    }

    // Regression: HTTP/2 upstream forwarding returned 502 because the request URI
    // stayed origin-form (`/`), so hyper's h2 client had no `:authority`. The
    // promotion must build an absolute URI from the Host header.
    #[test]
    fn promote_origin_form_to_absolute_for_h2() {
        let mut req = Request::builder()
            .method("GET")
            .uri("/path?q=1")
            .header(HOST, "example.com")
            .body(Full::new(Bytes::new()))
            .unwrap();
        promote_to_absolute_uri(&mut req, "https");
        assert_eq!(req.uri().scheme_str(), Some("https"));
        assert_eq!(
            req.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(
            req.uri().path_and_query().map(|p| p.as_str()),
            Some("/path?q=1")
        );
    }

    #[test]
    fn promote_is_noop_when_already_absolute() {
        let mut req = Request::builder()
            .method("GET")
            .uri("https://already.test/x")
            .body(Full::new(Bytes::new()))
            .unwrap();
        promote_to_absolute_uri(&mut req, "http");
        assert_eq!(req.uri().to_string(), "https://already.test/x");
    }

    #[test]
    fn malformed_header_bytes_fall_back() {
        let mut fallback = hyper::HeaderMap::new();
        fallback.append(HOST, HeaderValue::from_static("fallback.test"));
        let back = headers_from_bytes(b"this is not headers", &fallback);
        assert_eq!(back.get(HOST).unwrap(), "fallback.test");
    }

    // Build a `Message` whose raw header block carries a WebSocket upgrade, plus
    // the matching original `Parts`, to exercise `build_upstream_request`.
    fn ws_message_and_parts() -> (Message, http::request::Parts) {
        let req = Request::builder()
            .method("GET")
            .uri("/chat")
            .header(HOST, "example.com")
            .header(hyper::header::CONNECTION, "Upgrade")
            .header(hyper::header::UPGRADE, "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (parts, _) = req.into_parts();
        let raw = serialize_headers(&parts.headers);
        let msg = Message {
            host: "example.com".into(),
            url: "/chat".into(),
            headers: raw,
            body: Vec::new(),
        };
        (msg, parts)
    }

    // Bug 1 regression: a WebSocket upgrade request must carry Connection/Upgrade
    // (and the Sec-WebSocket-* set) verbatim to the origin, else it never 101s.
    #[test]
    fn build_upstream_keeps_upgrade_headers_for_ws() {
        let (msg, parts) = ws_message_and_parts();
        let out = build_upstream_request(&parts, "GET", &msg, Version::HTTP_11, true).unwrap();
        let h = out.headers();
        assert_eq!(
            h.get(hyper::header::CONNECTION)
                .map(|v| v.to_str().unwrap()),
            Some("Upgrade")
        );
        assert_eq!(
            h.get(hyper::header::UPGRADE).map(|v| v.to_str().unwrap()),
            Some("websocket")
        );
        assert!(h.contains_key("sec-websocket-key"));
        assert!(h.contains_key("sec-websocket-version"));
        // WS is replayed over HTTP/1.1 regardless of the downstream version.
        assert_eq!(out.version(), Version::HTTP_11);
    }

    // The non-WS path must still strip connection-specific headers (HTTP/2 leg
    // correctness).
    #[test]
    fn build_upstream_strips_upgrade_headers_for_non_ws() {
        let (msg, parts) = ws_message_and_parts();
        let out = build_upstream_request(&parts, "GET", &msg, Version::HTTP_2, false).unwrap();
        let h = out.headers();
        assert!(!h.contains_key(hyper::header::CONNECTION));
        assert!(!h.contains_key(hyper::header::UPGRADE));
    }

    // Bug (HIGH) regression: the forward-path body buffer is bounded by a
    // `Limited`, and an over-cap body must be detectable as a `LengthLimitError`
    // (so the request path can 413 / the response path can 502) rather than
    // buffering without limit. Exercise the exact `Limited` + downcast logic the
    // collectors rely on, with a tiny cap.
    #[tokio::test]
    async fn limited_body_overflow_is_detected() {
        let body = Full::new(Bytes::from_static(b"0123456789")); // 10 bytes
        let limited = Limited::new(body, 4); // cap below the body size
        let err = limited.collect().await.expect_err("over-cap must error");
        assert!(
            err.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some(),
            "overflow must surface as a LengthLimitError"
        );
    }

    #[tokio::test]
    async fn limited_body_under_cap_passes_through() {
        let body = Full::new(Bytes::from_static(b"0123456789"));
        let limited = Limited::new(body, FORWARD_BODY_CAP);
        let bytes = limited.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"0123456789");
    }

    // The forward cap must be finite and larger than the store cap (the store cap
    // only bounds the persisted copy, not the buffered-for-forwarding body).
    // Compile-time assertion so the invariant can never regress.
    const _: () = assert!(FORWARD_BODY_CAP > BODY_CAP);

    // Bug (MEDIUM) regression: when one splice direction finishes but the sibling
    // is parked forever on `read` (half-open peer), `join_half_open` must NOT block
    // indefinitely — it aborts the survivor after the grace and returns.
    #[tokio::test]
    async fn join_half_open_aborts_stuck_sibling() {
        let done = tokio::spawn(async {}); // finishes immediately
        let stuck = tokio::spawn(async {
            // Simulate a direction blocked forever on a silent half-open peer.
            std::future::pending::<()>().await;
        });
        let stuck_handle = stuck.abort_handle();
        // A short grace keeps the test fast; the real const is 10s.
        tokio::time::timeout(
            Duration::from_secs(5),
            join_half_open(done, stuck, Duration::from_millis(50)),
        )
        .await
        .expect("join_half_open must return, not hang on the stuck sibling");
        assert!(stuck_handle.is_finished(), "stuck sibling must be aborted");
    }

    // The normal path: both directions finish promptly, so the survivor drains
    // within the grace and is NOT aborted (no truncation).
    #[tokio::test]
    async fn join_half_open_lets_normal_close_drain() {
        let a = tokio::spawn(async {});
        let b = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        });
        join_half_open(a, b, Duration::from_secs(5)).await;
        // Reaching here without hanging is the assertion; a clean close drained.
    }

    // Bug (h3 downgrade) regression: Alt-Svc advertises HTTP/3 over QUIC/UDP-443,
    // which the sandbox blackholes; it MUST be stripped from relayed responses so
    // clients deterministically stay on h2/h1. Connection-specific + framing
    // headers must go too.
    #[test]
    fn sanitize_strips_alt_svc_and_hop_by_hop() {
        let mut h = hyper::HeaderMap::new();
        h.append("alt-svc", HeaderValue::from_static("h3=\":443\"; ma=86400"));
        h.append(
            hyper::header::CONTENT_LENGTH,
            HeaderValue::from_static("10"),
        );
        h.append(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        h.append(
            hyper::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        h.append(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );
        sanitize_downstream_headers(&mut h);
        assert!(!h.contains_key("alt-svc"), "alt-svc must be stripped");
        assert!(!h.contains_key(hyper::header::CONTENT_LENGTH));
        assert!(!h.contains_key(hyper::header::TRANSFER_ENCODING));
        assert!(!h.contains_key(hyper::header::CONNECTION));
        // Non-hop-by-hop headers are preserved.
        assert_eq!(h.get(hyper::header::CONTENT_TYPE).unwrap(), "text/html");
    }

    // gRPC framing: 1-byte flag + 4-byte big-endian length + message. Deframing
    // the STORED copy strips the framing so the capture isn't opaque.
    #[test]
    fn degrpc_deframes_length_prefixed_messages() {
        // Two frames: "abc" and "de".
        let mut body = Vec::new();
        body.push(0u8); // uncompressed flag
        body.extend_from_slice(&(3u32).to_be_bytes());
        body.extend_from_slice(b"abc");
        body.push(0u8);
        body.extend_from_slice(&(2u32).to_be_bytes());
        body.extend_from_slice(b"de");
        let out = maybe_degrpc(Some("application/grpc+proto"), &body).unwrap();
        assert_eq!(out, b"abc\nde");
    }

    #[test]
    fn degrpc_ignores_non_grpc_and_garbage() {
        // Not gRPC content-type → None (keep original).
        assert!(maybe_degrpc(Some("application/json"), b"{}").is_none());
        assert!(maybe_degrpc(None, b"anything").is_none());
        // gRPC content-type but the framing doesn't end on a boundary → None.
        let mut body = vec![0u8];
        body.extend_from_slice(&(10u32).to_be_bytes());
        body.extend_from_slice(b"short"); // declares 10, only 5 present
        assert!(maybe_degrpc(Some("application/grpc"), &body).is_none());
    }

    #[test]
    fn websocket_detection() {
        let mut h = hyper::HeaderMap::new();
        assert!(!is_websocket_upgrade(&h));
        h.append(
            hyper::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        h.append(
            hyper::header::UPGRADE,
            HeaderValue::from_static("websocket"),
        );
        assert!(is_websocket_upgrade(&h));
    }
}
