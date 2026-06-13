//! Upstream (proxy → real server) TLS connector.
//!
//! The MITM sits between the client and the origin: it terminates the client's
//! TLS with a forged leaf, *and* opens its own TLS connection to the real
//! server. That upstream connection keeps **normal certificate validation**
//! against the Mozilla root store — burpwn tampers with HTTP framing and
//! content, never with the upstream's TLS trust. A failed upstream validation
//! is a real signal (the origin's cert is bad), not something to bypass.
//!
//! Roots come from `webpki-roots` (a tiny, pure-data crate) so we do not depend
//! on the host's platform trust store at runtime. ALPN offers `h2` + `http/1.1`
//! so the proxy can mirror whatever protocol the origin negotiates.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// ALPN offered to the upstream origin.
const ALPN_H2_H1: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Build the rustls `ClientConfig` for upstream connections: Mozilla roots,
/// normal validation, ALPN `h2` + `http/1.1`.
pub fn upstream_client_config() -> ClientConfig {
    upstream_client_config_alpn(ALPN_H2_H1)
}

/// As [`upstream_client_config`] but with a caller-chosen ALPN list (e.g. offer
/// only `http/1.1` when downgrading the upstream connection).
pub fn upstream_client_config_alpn(alpn: &[&[u8]]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

/// A ready-to-use `tokio_rustls::TlsConnector` for upstream connections, with
/// Mozilla-root validation and ALPN `h2` + `http/1.1`.
pub fn upstream_connector() -> TlsConnector {
    TlsConnector::from(Arc::new(upstream_client_config()))
}

/// As [`upstream_connector`] but with a caller-chosen ALPN list.
pub fn upstream_connector_alpn(alpn: &[&[u8]]) -> TlsConnector {
    TlsConnector::from(Arc::new(upstream_client_config_alpn(alpn)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_config_has_roots_and_alpn() {
        crate::test_support::ensure_crypto_provider();
        let cfg = upstream_client_config();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // Mozilla bundle is non-empty.
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
    }

    #[test]
    fn upstream_config_custom_alpn() {
        crate::test_support::ensure_crypto_provider();
        let cfg = upstream_client_config_alpn(&[b"http/1.1"]);
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn connector_builds() {
        // Smoke: construction must not panic (needs the default crypto provider,
        // which the test harness installs via the process default).
        crate::test_support::ensure_crypto_provider();
        let _ = upstream_connector();
    }
}
