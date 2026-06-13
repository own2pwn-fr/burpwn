//! burpwn-tls — transparent TLS-MITM support.
//!
//! Building blocks for a Burp-style intercepting proxy:
//!
//! - [`CertAuthority`] — a per-install root CA, generated once and persisted
//!   under the data dir; export its PEM for the user to trust (`burpwn ca
//!   export`).
//! - [`LeafGenerator`] — mints (and caches) a leaf certificate per SNI / dst-IP,
//!   signed by the CA, so the client sees a valid-looking cert for the site.
//! - [`MitmResolver`] / [`server_config_for`] — wire the leaf generator into a
//!   rustls `ServerConfig` for the client-facing side of the MITM (shared
//!   SNI-only resolver, or a per-connection config that pins the destination).
//! - [`upstream_connector`] — a `tokio_rustls::TlsConnector` for the proxy →
//!   origin side, keeping **normal** certificate validation (Mozilla roots). We
//!   tamper with HTTP, never with upstream TLS trust.
//! - [`PinnedHosts`] — fallback bookkeeping: hosts that reject interception are
//!   recorded so future connections splice straight through.
//!
//! ## Crypto provider
//!
//! This library uses rustls' *default* process-wide crypto provider; it does NOT
//! install one. The binary is responsible for calling
//! `rustls::crypto::ring::default_provider().install_default()` once at startup
//! (the test suite installs it itself).

mod ca;
mod error;
mod leaf;
mod passthrough;
mod resolver;
mod upstream;

pub use ca::{default_data_dir, CertAuthority};
pub use error::{Result, TlsError};
pub use leaf::{is_valid_server_name, LeafGenerator};
pub use passthrough::PinnedHosts;
pub use resolver::{
    make_server_config, make_server_config_h1, server_config_for, server_config_for_h1,
    MitmResolver,
};
pub use upstream::{
    upstream_client_config, upstream_client_config_alpn, upstream_connector,
    upstream_connector_alpn,
};

/// Current calendar year from the system clock, used for cert validity bounds.
/// Approximate (a year boundary is all `date_time_ymd` needs); never panics.
pub(crate) fn current_year() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 1970 + seconds / (average seconds per year, incl. leap years).
    1970 + (secs / 31_557_600) as i32
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Install the ring crypto provider as the process default exactly once, so
    /// tests that build rustls configs don't panic. No-op on the second call.
    pub fn ensure_crypto_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }
}
