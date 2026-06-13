//! First-bytes connection classification + a prefix-replaying stream wrapper.
//!
//! When a redirected TCP connection arrives we don't yet know what's on it: TLS,
//! cleartext HTTP, or some opaque protocol. We read a small prefix, classify it,
//! then hand the *whole* stream (prefix + the still-unread remainder) to the
//! right handler via [`PrefixedStream`], which replays the peeked bytes before
//! yielding live socket data. This is essential because hyper / rustls must
//! re-read the very bytes we sniffed.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Number of leading bytes we peek to classify a connection. Enough to see the
/// TLS record type + the longest HTTP method token / the H2 preface prefix.
pub const PEEK_LEN: usize = 24;

/// Coarse classification of a freshly-accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// TLS record (handshake `0x16`): MITM or passthrough.
    Tls,
    /// Cleartext HTTP/1.x or the HTTP/2 cleartext preface.
    CleartextHttp,
    /// Anything else: treat as opaque raw TCP.
    RawTcp,
}

/// Classify a connection from its first bytes. Never consumes more than it is
/// given; an empty slice classifies as [`Class::RawTcp`].
pub fn classify(prefix: &[u8]) -> Class {
    match prefix.first() {
        // TLS: handshake records start with content-type 0x16.
        Some(0x16) => Class::Tls,
        Some(_) if looks_like_http(prefix) => Class::CleartextHttp,
        _ => Class::RawTcp,
    }
}

/// HTTP/1 request line starts with a known method token followed by a space, or
/// it's the HTTP/2 cleartext connection preface (`PRI * HTTP/2.0\r\n`).
fn looks_like_http(prefix: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
    ];
    if prefix.starts_with(b"PRI * HTTP/2.0") {
        return true;
    }
    METHODS.iter().any(|m| prefix.starts_with(m))
}

/// Read up to [`PEEK_LEN`] bytes from `stream` for classification, returning the
/// peeked bytes (which may be shorter on a short read / EOF). The bytes are NOT
/// consumed from the logical stream — wrap the stream in [`PrefixedStream`] with
/// the returned prefix to replay them.
pub async fn peek<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; PEEK_LEN];
    let mut filled = 0;
    // One read is usually enough; loop to coalesce a fragmented first segment up
    // to a small bound so classification is reliable.
    while filled < PEEK_LEN {
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            break; // EOF: classify on what we have.
        }
        filled += n;
        // A TLS handshake record is unambiguous from its first byte.
        if buf[0] == 0x16 {
            break;
        }
        // Otherwise read enough to see the longest token we test: the H2
        // cleartext preface `PRI * HTTP/2.0` (14 bytes). This also covers every
        // HTTP/1 method token and the explicit-proxy `CONNECT ` check.
        if filled >= 14 {
            break;
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// A stream wrapper that yields a buffered prefix before delegating to the inner
/// stream. Reads drain the prefix first; writes always go straight through.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Wrap `inner`, replaying `prefix` on the next reads.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// Borrow the inner stream (e.g. to read negotiated TLS state).
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Consume the wrapper, returning any unreplayed prefix plus the inner
    /// stream.
    pub fn into_parts(self) -> (Vec<u8>, S) {
        (self.prefix[self.pos..].to_vec(), self.inner)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            // Return immediately with the replayed bytes; don't also touch the
            // socket in the same poll (keeps semantics simple and correct).
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn classifies_bytes() {
        assert_eq!(classify(&[0x16, 0x03, 0x01]), Class::Tls);
        assert_eq!(classify(b"GET / HTTP/1.1"), Class::CleartextHttp);
        assert_eq!(classify(b"POST /x"), Class::CleartextHttp);
        assert_eq!(classify(b"PRI * HTTP/2.0\r\n"), Class::CleartextHttp);
        assert_eq!(classify(b"\x00\x01\x02\x03"), Class::RawTcp);
        assert_eq!(classify(b""), Class::RawTcp);
        // A method-looking token without trailing space is not HTTP.
        assert_eq!(classify(b"GETX"), Class::RawTcp);
    }

    #[tokio::test]
    async fn peek_then_prefixed_replays_all_bytes() {
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let mut server = server;
        let prefix = peek(&mut server).await.unwrap();
        assert_eq!(classify(&prefix), Class::CleartextHttp);

        let mut wrapped = PrefixedStream::new(prefix, server);
        let mut all = Vec::new();
        wrapped.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[tokio::test]
    async fn prefixed_stream_write_passes_through() {
        let (mut client, server) = duplex(1024);
        let mut wrapped = PrefixedStream::new(b"AB".to_vec(), server);
        wrapped.write_all(b"hello").await.unwrap();
        wrapped.flush().await.unwrap();
        let mut buf = vec![0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
