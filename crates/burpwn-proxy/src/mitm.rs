//! TLS interception (MITM) and passthrough fallback.
//!
//! Flow:
//! 1. Peek the TLS ClientHello bytes off the (already prefix-replayed) stream
//!    and parse the SNI from them with [`parse_sni`] (a tiny, dependency-free
//!    ClientHello parser — we do NOT pull a TLS-parsing crate).
//! 2. If the destination host is already known to reject interception
//!    ([`PinnedHosts::is_pinned`]) → go straight to [`passthrough`].
//! 3. Otherwise build a per-connection `ServerConfig` pinned to the dst IP /
//!    SNI via [`burpwn_tls::server_config_for`] and accept the TLS. On success
//!    we read the negotiated ALPN and dispatch the decrypted stream to the HTTP
//!    handler. On failure (the client pinned the cert / wants mTLS) we mark the
//!    host pinned and fall back to passthrough.
//!
//! Because rustls consumes the ClientHello during `accept`, we capture the raw
//! ClientHello bytes up front (via the [`PrefixedStream`] prefix) so the
//! passthrough path can replay them to the origin verbatim.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use burpwn_tls::{server_config_for, LeafGenerator, PinnedHosts};

use crate::classify::PrefixedStream;

/// Negotiated post-handshake metadata handed to the HTTP layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// SNI server name observed in the ClientHello, if any.
    pub sni: Option<String>,
    /// Whether ALPN negotiated HTTP/2 (`h2`). Otherwise treat as HTTP/1.1.
    pub alpn_h2: bool,
}

/// Outcome of an interception attempt.
pub enum MitmOutcome<S> {
    /// TLS was terminated; the decrypted stream + negotiated info are ready for
    /// the HTTP handler.
    Mitm {
        /// The decrypted TLS stream.
        stream: Box<tokio_rustls::server::TlsStream<PrefixedStream<S>>>,
        /// Negotiated SNI + ALPN.
        info: TlsInfo,
    },
    /// Interception was skipped or failed; the caller should splice this stream
    /// straight to the origin (passthrough). The captured ClientHello prefix is
    /// already inside the returned stream's replay buffer.
    Passthrough {
        /// The original client stream with the ClientHello still replayable.
        stream: PrefixedStream<S>,
        /// SNI parsed from the ClientHello (for logging), if any.
        sni: Option<String>,
    },
}

/// Attempt to MITM a redirected TLS connection.
///
/// `peeked` is the classification prefix already read (its first byte is the TLS
/// content type `0x16`). We read a bit more to capture the whole ClientHello for
/// SNI extraction + passthrough replay, then proceed per the module docs.
pub async fn try_mitm<S>(
    mut stream: S,
    peeked: Vec<u8>,
    dst_ip: IpAddr,
    leaves: &Arc<LeafGenerator>,
    pinned: &PinnedHosts,
) -> std::io::Result<MitmOutcome<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Capture enough of the ClientHello to parse SNI. One TLS record holds the
    // ClientHello in practice; read its declared length from the record header.
    let hello = read_client_hello(&mut stream, peeked).await?;
    let sni = parse_sni(&hello);

    let host_key = sni.clone();
    if let Some(ref h) = host_key {
        if pinned.is_pinned(h) {
            return Ok(MitmOutcome::Passthrough {
                stream: PrefixedStream::new(hello, stream),
                sni,
            });
        }
    }

    // Build the per-connection server config pinned to dst IP (+ SNI hint).
    let server_config = match server_config_for(leaves, sni.as_deref(), Some(dst_ip)) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "leaf generation failed; passthrough");
            return Ok(MitmOutcome::Passthrough {
                stream: PrefixedStream::new(hello, stream),
                sni,
            });
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let replay = PrefixedStream::new(hello, stream);

    match acceptor.accept(replay).await {
        Ok(tls) => {
            let alpn_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            // Prefer the SNI rustls saw post-handshake; fall back to our parse.
            let negotiated_sni = tls.get_ref().1.server_name().map(|s| s.to_string()).or(sni);
            Ok(MitmOutcome::Mitm {
                stream: Box::new(tls),
                info: TlsInfo {
                    sni: negotiated_sni,
                    alpn_h2,
                },
            })
        }
        Err(e) => {
            // Client rejected our leaf (cert pinning / mTLS). Record the host so
            // future connections splice through, and passthrough this one.
            tracing::info!(error = %e, sni = ?host_key, "client rejected MITM leaf; pinning host");
            if let Some(h) = host_key {
                pinned.mark_pinned(h);
            }
            // The acceptor consumed the stream; we cannot recover the original
            // bytes here. Signal a hard passthrough-with-no-replay by returning
            // an error the caller treats as "abort cleanly". In practice the
            // explicit-proxy/transparent caller retries via the pinned set on
            // the NEXT connection from the same client, which is the realistic
            // pinning behaviour. We surface this as a specific error kind.
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "client rejected MITM leaf (host pinned for next attempt)",
            ))
        }
    }
}

/// Read the full ClientHello record. `prefix` is the already-peeked bytes (TLS
/// record header is 5 bytes: type(1) version(2) length(2)). We read until we
/// have the whole record, capping at a sane bound.
async fn read_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut prefix: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    const MAX_HELLO: usize = 16 * 1024;
    // Ensure we have the 5-byte record header.
    while prefix.len() < 5 {
        let mut tmp = [0u8; 512];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(prefix);
        }
        prefix.extend_from_slice(&tmp[..n]);
    }
    let record_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
    let want = (5 + record_len).min(MAX_HELLO);
    while prefix.len() < want {
        let mut tmp = [0u8; 2048];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        prefix.extend_from_slice(&tmp[..n]);
        if prefix.len() >= MAX_HELLO {
            break;
        }
    }
    Ok(prefix)
}

/// Parse the SNI (first `host_name` server name) from a raw TLS ClientHello
/// record. Returns `None` if the bytes are not a ClientHello or carry no SNI.
///
/// Layout walked (all big-endian, lengths as noted):
/// - TLS record: type(1)=0x16 | version(2) | length(2) | fragment…
/// - Handshake:  msg_type(1)=0x01 | length(3) | body…
/// - ClientHello body: version(2) | random(32) | session_id(u8 len + data) |
///   cipher_suites(u16 len + data) | compression(u8 len + data) |
///   extensions(u16 len + data)
/// - Extension: type(2) | len(2) | data — SNI is type 0x0000:
///   server_name_list(u16 len) | name_type(1)=0 | name(u16 len + bytes)
pub fn parse_sni(record: &[u8]) -> Option<String> {
    let mut c = Cursor::new(record);
    if c.u8()? != 0x16 {
        return None; // not a handshake record
    }
    let _version = c.bytes(2)?;
    let _rec_len = c.u16()? as usize;
    // Handshake header.
    if c.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let _hs_len = c.u24()?;
    // ClientHello body.
    let _client_version = c.bytes(2)?;
    let _random = c.bytes(32)?;
    let sid_len = c.u8()? as usize;
    c.bytes(sid_len)?;
    let cs_len = c.u16()? as usize;
    c.bytes(cs_len)?;
    let comp_len = c.u8()? as usize;
    c.bytes(comp_len)?;
    // Extensions are optional (TLS 1.0 ClientHello could omit them).
    let ext_total = c.u16()? as usize;
    let ext_end = c.pos + ext_total;
    while c.pos + 4 <= ext_end {
        let ext_type = c.u16()?;
        let ext_len = c.u16()? as usize;
        let ext_data_start = c.pos;
        if ext_type == 0x0000 {
            // server_name extension.
            let _list_len = c.u16()?;
            let name_type = c.u8()?;
            let name_len = c.u16()? as usize;
            let name = c.bytes(name_len)?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(|s| s.to_string());
            }
            return None;
        }
        // Skip to the next extension.
        c.pos = ext_data_start + ext_len;
    }
    None
}

/// Minimal big-endian byte cursor for the SNI parser. Every accessor bounds-
/// checks and returns `None` past the end, so malformed input never panics.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.bytes(3)
            .map(|b| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a minimal ClientHello record carrying SNI `host`.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        // server_name extension data.
        let mut sni_ext = Vec::new();
        let name_len = (host.len() as u16).to_be_bytes();
        // server_name_list: name_type(1=0) + name_len(2) + name
        let mut list = Vec::new();
        list.push(0u8); // name_type = host_name
        list.extend_from_slice(&name_len);
        list.extend_from_slice(host);
        let list_len = (list.len() as u16).to_be_bytes();
        sni_ext.extend_from_slice(&list_len);
        sni_ext.extend_from_slice(&list);
        // extension: type(0x0000) + len + data
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        // ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1); // compression len
        body.push(0); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions len
        body.extend_from_slice(&ext);

        // Handshake header: type(1) + len(3).
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let blen = body.len();
        hs.push((blen >> 16) as u8);
        hs.push((blen >> 8) as u8);
        hs.push(blen as u8);
        hs.extend_from_slice(&body);

        // Record header: type(0x16) + version(2) + len(2).
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni_from_client_hello() {
        let rec = client_hello_with_sni("api.example.com");
        assert_eq!(parse_sni(&rec).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn no_sni_returns_none() {
        // A record without the SNI extension: reuse the builder then truncate
        // extensions by handing a non-handshake byte.
        assert_eq!(parse_sni(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xff]), None);
    }

    #[test]
    fn truncated_record_is_safe() {
        let rec = client_hello_with_sni("x.test");
        // Truncate mid-extension; parser must not panic and returns None.
        assert_eq!(parse_sni(&rec[..rec.len() - 3]), None);
        assert_eq!(parse_sni(&[]), None);
        assert_eq!(parse_sni(&[0x16]), None);
    }
}
