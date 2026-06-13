//! rustls server-side certificate resolution for the MITM listener.
//!
//! There are two ways to plug the leaf generator into a rustls `ServerConfig`,
//! and the proxy should pick based on whether it knows the destination IP:
//!
//! - [`MitmResolver`] — a *shared* `ResolvesServerCert`. It only sees the SNI
//!   from the TLS ClientHello (rustls does not expose the destination socket to
//!   the resolver). Use this when the client always sends SNI (the common case
//!   for HTTPS in 2025). With no SNI it returns `None` and the handshake aborts.
//!   This config is built once and reused for every accepted connection.
//!
//! - [`server_config_for`] — a *per-connection* helper. When the proxy already
//!   knows the destination (e.g. from the transparent-redirect `SO_ORIGINAL_DST`
//!   or a CONNECT line) it can pin a leaf for that `(sni_hint, dst_ip)` up front,
//!   so even a no-SNI client gets a certificate carrying the dst IP's SAN. This
//!   builds a fresh `ServerConfig` per connection (cheap — the leaf itself is
//!   cached in the `LeafGenerator`).
//!
//! Recommendation: use [`server_config_for`] from the proxy's per-connection
//! accept path, since it always has the destination IP from the transparent
//! redirect and it covers the no-SNI case. Keep [`MitmResolver`] for an
//! SNI-only listener or for tests.

use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

use crate::error::Result;
use crate::leaf::LeafGenerator;

/// ALPN protocols offered to the *client*: HTTP/2 then HTTP/1.1.
const ALPN_H2_H1: &[&[u8]] = &[b"h2", b"http/1.1"];
/// ALPN offering only HTTP/1.1 (when the proxy will not speak h2 to the client).
const ALPN_H1: &[&[u8]] = &[b"http/1.1"];

/// A shared resolver that mints a leaf per SNI via a [`LeafGenerator`].
///
/// `resolve` returns `None` (aborting the handshake) when the client sent no
/// SNI — see the module docs for the no-SNI strategy.
#[derive(Debug)]
pub struct MitmResolver {
    leaves: Arc<LeafGenerator>,
}

impl MitmResolver {
    pub fn new(leaves: Arc<LeafGenerator>) -> Self {
        Self { leaves }
    }

    pub fn leaves(&self) -> &Arc<LeafGenerator> {
        &self.leaves
    }
}

impl ResolvesServerCert for MitmResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        match self.leaves.get_or_make(Some(sni), None) {
            Ok(ck) => Some(ck),
            Err(e) => {
                tracing::warn!(%sni, error = %e, "failed to mint leaf for SNI");
                None
            }
        }
    }
}

/// A per-connection resolver that *always* serves the same pre-pinned leaf,
/// regardless of (or in the absence of) SNI. Built by [`server_config_for`].
#[derive(Debug)]
struct PinnedResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for PinnedResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

/// Build a `ServerConfig` for a single accepted connection, pinning a leaf for
/// the known destination. Pass the client's SNI hint if you have it (from a
/// peeked ClientHello) and/or the destination IP (from the transparent
/// redirect). At least one must be `Some`.
///
/// ALPN offers `h2` + `http/1.1`. Use [`server_config_for_h1`] to offer only
/// HTTP/1.1.
pub fn server_config_for(
    leaves: &LeafGenerator,
    sni_hint: Option<&str>,
    dst_ip: Option<std::net::IpAddr>,
) -> Result<ServerConfig> {
    let key = leaves.get_or_make(sni_hint, dst_ip)?;
    Ok(build_config(Arc::new(PinnedResolver { key }), ALPN_H2_H1))
}

/// As [`server_config_for`] but offering only `http/1.1` to the client.
pub fn server_config_for_h1(
    leaves: &LeafGenerator,
    sni_hint: Option<&str>,
    dst_ip: Option<std::net::IpAddr>,
) -> Result<ServerConfig> {
    let key = leaves.get_or_make(sni_hint, dst_ip)?;
    Ok(build_config(Arc::new(PinnedResolver { key }), ALPN_H1))
}

/// Build a `ServerConfig` from any `ResolvesServerCert`, offering `h2` +
/// `http/1.1` to the client. Use with a shared [`MitmResolver`].
pub fn make_server_config(resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
    build_config(resolver, ALPN_H2_H1)
}

/// As [`make_server_config`] but offering only `http/1.1`.
pub fn make_server_config_h1(resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
    build_config(resolver, ALPN_H1)
}

fn build_config(resolver: Arc<dyn ResolvesServerCert>, alpn: &[&[u8]]) -> ServerConfig {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertAuthority;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    fn leaves() -> (TempDir, Arc<LeafGenerator>) {
        crate::test_support::ensure_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = CertAuthority::load_or_generate(dir.path()).unwrap();
        (dir, Arc::new(LeafGenerator::new(ca)))
    }

    #[test]
    fn make_server_config_offers_h2_and_h1() {
        let (_d, lv) = leaves();
        let resolver: Arc<dyn ResolvesServerCert> = Arc::new(MitmResolver::new(lv));
        let cfg = make_server_config(resolver);
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn h1_config_offers_only_http1() {
        let (_d, lv) = leaves();
        let resolver: Arc<dyn ResolvesServerCert> = Arc::new(MitmResolver::new(lv));
        let cfg = make_server_config_h1(resolver);
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn per_connection_config_builds_for_ip_only() {
        let (_d, lv) = leaves();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let cfg = server_config_for(&lv, None, Some(ip)).unwrap();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn per_connection_h1_config_for_sni() {
        let (_d, lv) = leaves();
        let cfg = server_config_for_h1(&lv, Some("host.example"), None).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn per_connection_requires_a_target() {
        let (_d, lv) = leaves();
        assert!(server_config_for(&lv, None, None).is_err());
    }
}
