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
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, CONTENT_ENCODING, HOST};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use burpwn_store::model::{FlowStart, Protocol, RequestData, ResponseData};
use burpwn_store::{WriteHandle, WriteOp};

use crate::decode::decode_body;
use crate::intercept::{InterceptController, InterceptData, InterceptDecision, InterceptKind};
use crate::matchreplace::{apply_request, apply_response, Message};
use crate::util::now_millis;

/// Hard cap on a buffered body we will fully read for capture + rule application.
/// Larger bodies are still forwarded (streamed via `Full` after collection up to
/// this cap; bodies above it are truncated for storage only — see notes).
const BODY_CAP: usize = 8 * 1024 * 1024;

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
pub async fn handle_explicit(req: Request<Incoming>, ctx: HttpContext) -> Response<Full<Bytes>> {
    handle(req, ctx).await
}

/// The per-request handler shared by H1 and H2.
async fn handle(req: Request<Incoming>, ctx: HttpContext) -> Response<Full<Bytes>> {
    match handle_inner(req, ctx).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "proxy request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from_static(b"burpwn: upstream error")))
                .unwrap()
        }
    }
}

async fn handle_inner(
    mut req: Request<Incoming>,
    ctx: HttpContext,
) -> anyhow::Result<Response<Full<Bytes>>> {
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
    let req_body = collect_capped(body).await?;

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
                .body(Full::new(Bytes::from_static(
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
                body: msg.body.clone(),
            },
        )
        .await;

    // --- build the upstream request from the (possibly edited) message ---
    let upstream_req = build_upstream_request(&parts, &method, &msg, version)?;

    // WebSocket: hand off to the splice path after the handshake.
    if is_ws {
        return websocket_forward(upstream_req, ctx, flow_id, downstream_upgrade).await;
    }

    // --- forward + capture the response ---
    let (resp_parts, resp_body_bytes) = forward(&ctx.upstream, upstream_req, version).await?;
    let raw_resp_headers = serialize_headers(&resp_parts.headers);

    // Decode a COPY for storage; never alter forwarded bytes.
    let content_encoding = resp_parts
        .headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let decoded_for_store = decode_body(content_encoding, &resp_body_bytes);

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
                .body(Full::new(Bytes::from_static(b"burpwn: response dropped")))
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
                body: store_body,
                timing_ms: Some(timing),
            },
        )
        .await;
    let _ = ctx.writer.flow_end(flow_id, now_millis()).await;

    // --- stream the response back downstream ---
    let mut builder = Response::builder().status(status);
    {
        let hdrs = builder.headers_mut().unwrap();
        *hdrs = forward_headers;
        // Hyper sets the length from the Full body; drop a stale framing header.
        hdrs.remove(hyper::header::CONTENT_LENGTH);
        hdrs.remove(hyper::header::TRANSFER_ENCODING);
    }
    Ok(builder.body(Full::new(forward_body))?)
}

/// Open the upstream connection, send the request, and collect the response.
async fn forward(
    upstream: &Upstream,
    req: Request<Full<Bytes>>,
    downstream_version: Version,
) -> anyhow::Result<(http::response::Parts, Bytes)> {
    match upstream {
        Upstream::Plain { addr } => {
            let tcp = TcpStream::connect(*addr).await?;
            send_over(tcp, req, false, downstream_version).await
        }
        Upstream::Tls {
            addr,
            server_name,
            connector,
        } => {
            let tcp = TcpStream::connect(*addr).await?;
            let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
                .map_err(|_| anyhow::anyhow!("invalid upstream server name"))?;
            let tls = connector.connect(server_name, tcp).await?;
            let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            send_over(tls, req, is_h2, downstream_version).await
        }
    }
}

/// Drive one request/response over an established (plain or TLS) byte stream,
/// using hyper's client connection. `force_h2` follows the upstream's negotiated
/// ALPN; otherwise we mirror the downstream HTTP version.
async fn send_over<S>(
    stream: S,
    req: Request<Full<Bytes>>,
    force_h2: bool,
    downstream_version: Version,
) -> anyhow::Result<(http::response::Parts, Bytes)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let use_h2 = force_h2 || downstream_version == Version::HTTP_2;
    if use_h2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "upstream h2 conn closed");
            }
        });
        let resp = sender.send_request(req).await?;
        collect_response(resp).await
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "upstream h1 conn closed");
            }
        });
        let resp = sender.send_request(req).await?;
        collect_response(resp).await
    }
}

async fn collect_response(
    resp: Response<Incoming>,
) -> anyhow::Result<(http::response::Parts, Bytes)> {
    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read upstream body: {e}"))?
        .to_bytes();
    Ok((parts, bytes))
}

/// Build the request to send upstream from the original parts + the (possibly
/// rule/intercept-edited) [`Message`]. We rebuild the header map from the raw
/// header bytes so edits are honored, then re-target the URI to origin-form.
fn build_upstream_request(
    orig: &http::request::Parts,
    method: &str,
    msg: &Message,
    version: Version,
) -> anyhow::Result<Request<Full<Bytes>>> {
    let mut headers = headers_from_bytes(&msg.headers, &orig.headers);
    // Ensure Host matches the (possibly rewritten) authority for H1.
    if version != Version::HTTP_2 {
        if let Ok(hv) = HeaderValue::from_str(&msg.host) {
            headers.insert(HOST, hv);
        }
    }
    // Drop hop-by-hop framing we will recompute.
    headers.remove(hyper::header::CONTENT_LENGTH);
    headers.remove(hyper::header::TRANSFER_ENCODING);

    let uri: http::Uri = msg.url.parse().unwrap_or_else(|_| orig.uri.clone());
    let mut builder = Request::builder()
        .method(method.as_bytes())
        .uri(uri)
        .version(version);
    {
        let h = builder.headers_mut().unwrap();
        *h = headers;
    }
    Ok(builder.body(Full::new(Bytes::from(msg.body.clone())))?)
}

/// Collect a request/response body up to [`BODY_CAP`].
async fn collect_capped(body: Incoming) -> anyhow::Result<Vec<u8>> {
    let collected = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read body: {e}"))?
        .to_bytes();
    let mut v = collected.to_vec();
    v.truncate(BODY_CAP);
    Ok(v)
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
/// upgrade request, and on a `101` splice the two upgraded byte streams, teeing
/// frame bytes to the store. Minimal but functional: bytes are forwarded
/// verbatim and tee'd as raw chunks rather than parsing every WS frame.
async fn websocket_forward(
    req: Request<Full<Bytes>>,
    ctx: HttpContext,
    flow_id: i64,
    downstream_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> anyhow::Result<Response<Full<Bytes>>> {
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
        return Ok(builder.body(Full::new(Bytes::new()))?);
    }

    // Build the 101 we return downstream, mirroring the upstream's headers. The
    // server layer (`.with_upgrades()`) upgrades the downstream connection when
    // it writes this response, resolving `downstream_upgrade`.
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    *builder.headers_mut().unwrap() = up_parts.headers.clone();
    let downstream_resp = builder.body(Full::new(Bytes::new()))?;

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

/// Splice two upgraded WebSocket streams, teeing a capped copy of each direction
/// to the store as raw chunks (best-effort frame logging).
async fn splice_ws<D, U>(downstream: D, upstream: U, writer: WriteHandle, flow_id: i64)
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const WS_CAP: usize = 256 * 1024;

    let (mut dr, mut dw) = tokio::io::split(downstream);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let w1 = writer.clone();
    let c2s = tokio::spawn(async move {
        let mut cap = 0usize;
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = dr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            if uw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            if cap < WS_CAP {
                let take = n.min(WS_CAP - cap);
                cap += take;
                let mut bytes = b"ws-c2s:".to_vec();
                bytes.extend_from_slice(&buf[..take]);
                let _ = w1
                    .send(WriteOp::RawChunk {
                        flow_id,
                        bytes,
                        reply: None,
                    })
                    .await;
            }
        }
        let _ = uw.shutdown().await;
    });
    let w2 = writer.clone();
    let s2c = tokio::spawn(async move {
        let mut cap = 0usize;
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = ur.read(&mut buf).await {
            if n == 0 {
                break;
            }
            if dw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            if cap < WS_CAP {
                let take = n.min(WS_CAP - cap);
                cap += take;
                let mut bytes = b"ws-s2c:".to_vec();
                bytes.extend_from_slice(&buf[..take]);
                let _ = w2
                    .send(WriteOp::RawChunk {
                        flow_id,
                        bytes,
                        reply: None,
                    })
                    .await;
            }
        }
        let _ = dw.shutdown().await;
    });
    let _ = c2s.await;
    let _ = s2c.await;
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

    #[test]
    fn malformed_header_bytes_fall_back() {
        let mut fallback = hyper::HeaderMap::new();
        fallback.append(HOST, HeaderValue::from_static("fallback.test"));
        let back = headers_from_bytes(b"this is not headers", &fallback);
        assert_eq!(back.get(HOST).unwrap(), "fallback.test");
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
