//! burpwn-proxy — the proxy core.
//!
//! Receives connections (from the transparent sandbox via `SCM_RIGHTS`
//! fd-passing, or as an explicit HTTP proxy for testing), classifies them,
//! MITMs TLS, captures HTTP/1.1 + H2 + WebSocket + DNS + raw-TCP flows into the
//! [`burpwn_store`], applies match/replace rules, and forwards upstream.
//!
//! # Public surface
//!
//! - [`Proxy::new`] / [`ProxyConfig`] — construct the facade (loads the CA).
//! - [`Proxy::handle_redirected`] — the core entry both front-ends funnel into:
//!   classify a redirected TCP stream + known destination, then MITM / cleartext
//!   HTTP / raw-TCP dispatch.
//! - [`Proxy::serve_scm_unix`] — the real transparent path: receive passed
//!   client fds + the 26-byte metadata header over a unix socket.
//! - [`Proxy::serve_explicit_http`] / [`Proxy::explicit_http_bound`] — a normal
//!   forward HTTP/HTTPS proxy (`CONNECT` + absolute-form) for driving the whole
//!   pipeline in tests.
//! - [`Proxy::dns_listener`] — run the DNS decode/forward UDP server.
//! - [`InterceptController`] (re-exported) — the blocking-intercept primitive
//!   M6/M7 wire CLI + MCP onto.

pub mod classify;
pub mod decode;
pub mod dns;
pub mod http;
pub mod intercept;
pub mod matchreplace;
pub mod mitm;
pub mod passthrough;
pub mod rawtcp;
mod util;
pub mod wire;

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use burpwn_store::WriteHandle;
use burpwn_tls::{
    upstream_connector, upstream_connector_alpn, CertAuthority, LeafGenerator, PinnedHosts,
};

pub use crate::classify::{Class, PrefixedStream};
pub use crate::http::{HttpContext, Upstream};
pub use crate::intercept::{
    InterceptController, InterceptData, InterceptDecision, InterceptKind, InterceptScope,
    PendingIntercept, PendingSummary,
};
pub use crate::mitm::TlsInfo;
pub use crate::wire::{PassedConn, L4};

/// Configuration for constructing a [`Proxy`].
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Directory holding (or to generate) the burpwn root CA.
    pub ca_dir: PathBuf,
    /// Default workspace id for captured flows.
    pub workspace_id: i64,
    /// Optional sandbox/exec correlation id stamped on every flow.
    pub exec_id: Option<String>,
}

impl ProxyConfig {
    /// A config rooted at `ca_dir` with the default workspace (id 1) and no
    /// exec id.
    pub fn new(ca_dir: impl Into<PathBuf>) -> Self {
        Self {
            ca_dir: ca_dir.into(),
            workspace_id: 1,
            exec_id: None,
        }
    }
}

/// The proxy facade. Clone-cheap pieces inside; wrap in an `Arc` to share across
/// accept loops.
#[derive(Clone)]
pub struct Proxy {
    leaves: Arc<LeafGenerator>,
    writer: WriteHandle,
    reader: burpwn_store::Reader,
    pinned: PinnedHosts,
    intercept: InterceptController,
    workspace_id: i64,
    exec_id: Option<String>,
}

impl Proxy {
    /// Construct a proxy: load (or generate) the CA under `cfg.ca_dir`, wiring in
    /// the store handles and a fresh [`InterceptController`].
    pub fn new(
        cfg: ProxyConfig,
        writer: WriteHandle,
        reader: burpwn_store::Reader,
    ) -> anyhow::Result<Self> {
        let ca = CertAuthority::load_or_generate(&cfg.ca_dir)?;
        let leaves = Arc::new(LeafGenerator::new(ca));
        Ok(Self {
            leaves,
            writer,
            reader,
            pinned: PinnedHosts::new(),
            intercept: InterceptController::new(),
            workspace_id: cfg.workspace_id,
            exec_id: cfg.exec_id,
        })
    }

    /// The intercept primitive, for CLI/MCP wiring (M6/M7).
    pub fn intercept(&self) -> InterceptController {
        self.intercept.clone()
    }

    /// The set of hosts that rejected MITM (spliced through).
    pub fn pinned_hosts(&self) -> &PinnedHosts {
        &self.pinned
    }

    /// Snapshot the current match/replace rules from the store.
    fn rules(&self) -> Arc<Vec<burpwn_store::model::MatchReplaceRule>> {
        Arc::new(self.reader.list_match_replace().unwrap_or_default())
    }

    /// Core entry: handle one redirected TCP connection with a known original
    /// destination. Classifies the first bytes and dispatches to MITM / cleartext
    /// HTTP / raw-TCP. Both front-ends call this.
    pub async fn handle_redirected(
        self: Arc<Self>,
        mut stream: TcpStream,
        conn: PassedConn,
        client_addr: String,
    ) -> anyhow::Result<()> {
        let prefix = classify::peek(&mut stream).await?;
        match classify::classify(&prefix) {
            Class::Tls => {
                self.handle_tls_generic(stream, prefix, conn, client_addr)
                    .await
            }
            Class::CleartextHttp => {
                self.serve_cleartext(stream, prefix, conn, client_addr)
                    .await
            }
            Class::RawTcp => rawtcp::run(
                stream,
                prefix,
                conn.dst_ip,
                conn.dst_port,
                client_addr,
                &self.writer,
                self.workspace_id,
                self.exec_id.clone(),
            )
            .await
            .map_err(Into::into),
        }
    }

    /// Build an [`HttpContext`] for a plaintext origin.
    fn cleartext_ctx(&self, conn: &PassedConn, client_addr: String) -> HttpContext {
        HttpContext {
            writer: self.writer.clone(),
            intercept: self.intercept.clone(),
            rules: self.rules(),
            workspace_id: self.workspace_id,
            exec_id: self.exec_id.clone(),
            client_addr,
            dst_ip: conn.dst_ip.to_string(),
            dst_port: conn.dst_port,
            sni: None,
            scheme: "http".into(),
            upstream: Upstream::Plain {
                addr: SocketAddr::new(conn.dst_ip, conn.dst_port),
            },
        }
    }

    /// Serve a cleartext HTTP connection over any stream (H1 or H2 prior-knowledge).
    async fn serve_cleartext<S>(
        &self,
        stream: S,
        prefix: Vec<u8>,
        conn: PassedConn,
        client_addr: String,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let is_h2 = prefix.starts_with(b"PRI * HTTP/2.0");
        let replay = PrefixedStream::new(prefix, stream);
        let ctx = self.cleartext_ctx(&conn, client_addr);
        if is_h2 {
            http::serve_h2(replay, ctx).await?;
        } else {
            http::serve_h1(replay, ctx).await?;
        }
        Ok(())
    }

    /// MITM (or passthrough) a TLS connection over any stream, then serve HTTP
    /// over the decrypted stream.
    async fn handle_tls_generic<S>(
        &self,
        stream: S,
        prefix: Vec<u8>,
        conn: PassedConn,
        client_addr: String,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let outcome =
            match mitm::try_mitm(stream, prefix, conn.dst_ip, &self.leaves, &self.pinned).await {
                Ok(o) => o,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                    // Client rejected our leaf; host now pinned for the next
                    // attempt. Nothing more to do for this aborted connection.
                    tracing::debug!("tls mitm aborted (pinned for retry)");
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };

        match outcome {
            mitm::MitmOutcome::Mitm { stream, info } => {
                let sni = info.sni.clone();
                let server_name = sni.clone().unwrap_or_else(|| conn.dst_ip.to_string());
                let connector = if info.alpn_h2 {
                    upstream_connector()
                } else {
                    upstream_connector_alpn(&[b"http/1.1"])
                };
                let ctx = HttpContext {
                    writer: self.writer.clone(),
                    intercept: self.intercept.clone(),
                    rules: self.rules(),
                    workspace_id: self.workspace_id,
                    exec_id: self.exec_id.clone(),
                    client_addr,
                    dst_ip: conn.dst_ip.to_string(),
                    dst_port: conn.dst_port,
                    sni,
                    scheme: "https".into(),
                    upstream: Upstream::Tls {
                        addr: SocketAddr::new(conn.dst_ip, conn.dst_port),
                        server_name,
                        connector,
                    },
                };
                if info.alpn_h2 {
                    http::serve_h2(*stream, ctx).await?;
                } else {
                    http::serve_h1(*stream, ctx).await?;
                }
                Ok(())
            }
            mitm::MitmOutcome::Passthrough { stream, sni } => {
                let (prefix, inner) = stream.into_parts();
                passthrough::run(
                    inner,
                    prefix,
                    conn.dst_ip,
                    conn.dst_port,
                    sni,
                    client_addr,
                    &self.writer,
                    self.workspace_id,
                    self.exec_id.clone(),
                )
                .await
                .map_err(Into::into)
            }
        }
    }

    // ---- Front-end A: SCM_RIGHTS transparent path -------------------------

    /// Bind a unix socket at `path` and receive handed-off client connections
    /// from the in-netns acceptor (one `SCM_RIGHTS` fd + a 26-byte header per
    /// connection), routing each into [`Self::handle_redirected`].
    pub async fn serve_scm_unix(
        self: Arc<Self>,
        path: impl AsRef<std::path::Path>,
    ) -> anyhow::Result<()> {
        let path = path.as_ref();
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        tracing::info!(?path, "SCM_RIGHTS front-end listening");
        loop {
            let (sock, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.recv_loop(sock).await {
                    tracing::debug!(error = %e, "scm recv loop ended");
                }
            });
        }
    }

    /// Receive `SCM_RIGHTS` messages on one connected unix socket until it
    /// closes; each message yields a passed client fd + metadata header.
    async fn recv_loop(self: Arc<Self>, sock: UnixStream) -> anyhow::Result<()> {
        loop {
            sock.readable().await?;
            match recv_passed(&sock) {
                Ok(Some((fd, conn))) => {
                    let me = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = me.dispatch_passed(fd, conn).await {
                            tracing::debug!(error = %e, "passed-conn dispatch failed");
                        }
                    });
                }
                Ok(None) => return Ok(()), // peer closed
                Err(nix::errno::Errno::EWOULDBLOCK) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Turn a passed raw fd + metadata into a tokio stream and dispatch it.
    async fn dispatch_passed(self: Arc<Self>, fd: RawFd, conn: PassedConn) -> anyhow::Result<()> {
        // A passed UDP socket is the in-netns DNS socket (bound on the udp/53
        // redirect target inside the sandbox). Serve DNS over it from the host,
        // which has real upstream connectivity.
        if conn.l4 == L4::Udp {
            // SAFETY: `fd` is a freshly-received, owned UDP socket bound in the
            // sandbox netns; operations on it act in that netns by construction.
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            std_sock.set_nonblocking(true)?;
            let sock = tokio::net::UdpSocket::from_std(std_sock)?;
            let cfg = crate::dns::DnsConfig::from_host(self.workspace_id, self.exec_id.clone());
            return crate::dns::serve_socket(sock, cfg, self.writer.clone())
                .await
                .map_err(Into::into);
        }
        // SAFETY: `fd` is a freshly-received, owned accepted TCP socket.
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let client_addr = std_stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".into());
        let stream = TcpStream::from_std(std_stream)?;
        self.handle_redirected(stream, conn, client_addr).await
    }

    // ---- Front-end B: explicit forward proxy (for tests) ------------------

    /// Run a normal forward HTTP/HTTPS proxy on `addr`, serving until it errors.
    pub async fn serve_explicit_http(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(bound = %listener.local_addr()?, "explicit HTTP proxy listening");
        self.run_explicit(listener).await
    }

    /// Bind the explicit proxy and return its bound address before serving, so
    /// tests can target an ephemeral port. The returned future serves forever.
    pub async fn explicit_http_bound(
        self: Arc<Self>,
        addr: SocketAddr,
    ) -> anyhow::Result<(
        SocketAddr,
        impl std::future::Future<Output = anyhow::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        let me = self.clone();
        Ok((bound, async move { me.run_explicit(listener).await }))
    }

    async fn run_explicit(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
    ) -> anyhow::Result<()> {
        loop {
            let (sock, peer) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.serve_explicit_conn(sock, peer).await {
                    tracing::debug!(error = %e, "explicit proxy conn failed");
                }
            });
        }
    }

    async fn serve_explicit_conn(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        // Peek to distinguish CONNECT (TLS tunnel) from absolute-form cleartext.
        let mut s = stream;
        let prefix = classify::peek(&mut s).await?;
        if prefix.starts_with(b"CONNECT") {
            return self.serve_explicit_connect(s, prefix, peer).await;
        }
        // Absolute-form cleartext proxying via a hyper server whose service
        // resolves the upstream from the request URI / Host header.
        let me = self.clone();
        let client_addr = peer.to_string();
        let replay = PrefixedStream::new(prefix, s);
        let io = TokioIo::new(replay);
        let service = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let client_addr = client_addr.clone();
            async move {
                Ok::<_, std::convert::Infallible>(me.explicit_cleartext(req, client_addr).await)
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades()
            .await?;
        Ok(())
    }

    /// Handle one absolute-form cleartext request: extract the origin from the
    /// URI / Host, build an [`HttpContext`], and forward via the shared path.
    async fn explicit_cleartext(
        self: Arc<Self>,
        req: Request<Incoming>,
        client_addr: String,
    ) -> Response<Full<Bytes>> {
        let (host, port) = match req
            .uri()
            .authority()
            .map(|a| (a.host().to_string(), a.port_u16().unwrap_or(80)))
        {
            Some(hp) => hp,
            None => {
                let host = req
                    .headers()
                    .get(hyper::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(|h| {
                        let h = h.trim();
                        h.rsplit_once(':')
                            .map(|(host, _)| host.to_string())
                            .unwrap_or_else(|| h.to_string())
                    });
                match host {
                    Some(h) => (h, 80),
                    None => {
                        return bad_request("burpwn: no host");
                    }
                }
            }
        };
        let addr = match resolve_first(&host, port).await {
            Some(a) => a,
            None => return bad_gateway("burpwn: dns failure"),
        };
        let conn = PassedConn {
            dst_ip: addr.ip(),
            dst_port: addr.port(),
            l4: L4::Tcp,
        };
        let ctx = self.cleartext_ctx(&conn, client_addr);
        crate::http::handle_explicit(req, ctx).await
    }

    /// Handle a `CONNECT host:port` tunnel: answer `200`, then treat the tunneled
    /// bytes as a redirected connection to that origin (the shared path
    /// classifies + intercepts the TLS inside).
    async fn serve_explicit_connect(
        self: Arc<Self>,
        stream: TcpStream,
        prefix: Vec<u8>,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        let mut replay = PrefixedStream::new(prefix, stream);
        let target = read_connect_target(&mut replay).await?;
        replay
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        replay.flush().await?;

        let (host, port) =
            split_hostport(&target).ok_or_else(|| anyhow::anyhow!("malformed CONNECT target"))?;
        let addr = resolve_first(&host, port)
            .await
            .ok_or_else(|| anyhow::anyhow!("could not resolve {host}"))?;
        let conn = PassedConn {
            dst_ip: addr.ip(),
            dst_port: addr.port(),
            l4: L4::Tcp,
        };

        // Re-classify the tunneled stream (TLS ClientHello, cleartext, etc.).
        let (leftover, inner) = replay.into_parts();
        let mut combined = PrefixedStream::new(leftover, inner);
        let inner_prefix = classify::peek(&mut combined).await?;
        match classify::classify(&inner_prefix) {
            Class::Tls => {
                // Pin the connect host as the SNI hint via the leaf generator;
                // MITM works over any AsyncRead+Write, feed the wrapped stream.
                self.handle_tls_generic(combined, inner_prefix, conn, peer.to_string())
                    .await
            }
            Class::CleartextHttp => {
                self.serve_cleartext(combined, inner_prefix, conn, peer.to_string())
                    .await
            }
            Class::RawTcp => rawtcp::run(
                combined,
                inner_prefix,
                conn.dst_ip,
                conn.dst_port,
                peer.to_string(),
                &self.writer,
                self.workspace_id,
                self.exec_id.clone(),
            )
            .await
            .map_err(Into::into),
        }
    }

    // ---- DNS front-end ----------------------------------------------------

    /// Run the DNS decode/forward UDP server on `addr`, forwarding to the host's
    /// first resolver (or 1.1.1.1).
    pub async fn dns_listener(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let cfg = dns::DnsConfig::from_host(self.workspace_id, self.exec_id.clone());
        dns::serve(addr, cfg, self.writer.clone()).await?;
        Ok(())
    }
}

fn bad_request(msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Full::new(Bytes::from_static(msg.as_bytes())))
        .unwrap()
}

fn bad_gateway(msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::from_static(msg.as_bytes())))
        .unwrap()
}

/// Receive one `SCM_RIGHTS` message (the 26-byte header + a single fd) from a
/// connected unix socket. Returns `Ok(None)` on clean peer close, or
/// `Err(EWOULDBLOCK)` if the socket was not actually ready.
fn recv_passed(sock: &UnixStream) -> Result<Option<(RawFd, PassedConn)>, nix::errno::Errno> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, UnixAddr};
    use std::io::IoSliceMut;
    use std::os::fd::AsRawFd;

    let res = sock.try_io(tokio::io::Interest::READABLE, || {
        let raw = sock.as_raw_fd();
        let mut data = [0u8; wire::HEADER_LEN];
        let mut iov = [IoSliceMut::new(&mut data)];
        let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
        let msg: nix::sys::socket::RecvMsg<UnixAddr> =
            recvmsg(raw, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
                .map_err(std::io::Error::from)?;
        if msg.bytes == 0 {
            return Ok(None); // peer closed
        }
        let mut fd = None;
        for c in msg.cmsgs().map_err(std::io::Error::from)? {
            if let ControlMessageOwned::ScmRights(fds) = c {
                let mut it = fds.into_iter();
                fd = it.next();
                for extra in it {
                    // SAFETY: surplus received fds we don't use are owned by us.
                    unsafe {
                        libc::close(extra);
                    }
                }
            }
        }
        let fd = fd.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no SCM_RIGHTS fd")
        })?;
        let conn = PassedConn::decode(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Some((fd, conn)))
    });
    match res {
        Ok(v) => Ok(v),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(nix::errno::Errno::EWOULDBLOCK),
        Err(e) => Err(nix::errno::Errno::from_raw(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

/// Read the CONNECT request line + headers up to the blank line, returning the
/// `host:port` target.
async fn read_connect_target<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first = text.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let _method = parts.next();
    let target = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing CONNECT target"))?;
    Ok(target.to_string())
}

/// Split `host:port` (or bare `host`) into components, defaulting port 443
/// (CONNECT is almost always TLS).
fn split_hostport(s: &str) -> Option<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    Some((s.to_string(), 443))
}

/// Resolve `host:port` to its first socket address. A literal IP skips DNS.
async fn resolve_first(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await
        .ok()
        .and_then(|mut it| it.next())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_hostport_variants() {
        assert_eq!(
            split_hostport("example.com:8443"),
            Some(("example.com".into(), 8443))
        );
        assert_eq!(
            split_hostport("example.com"),
            Some(("example.com".into(), 443))
        );
    }

    #[tokio::test]
    async fn resolve_literal_ip() {
        let a = resolve_first("127.0.0.1", 8080).await.unwrap();
        assert_eq!(a, "127.0.0.1:8080".parse().unwrap());
    }
}
