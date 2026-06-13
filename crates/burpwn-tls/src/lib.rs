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

use time::OffsetDateTime;

/// A clock-skew-tolerant certificate validity window.
///
/// `not_before` is deliberately set a couple of days **in the past** and
/// `not_after` several years in the future, both computed from a real civil
/// timestamp ([`OffsetDateTime::now_utc`]). This is robust to:
///
/// - the old `1970 + secs / 31_557_600` year approximation, which drifts and,
///   near a New-Year boundary, could return a year off-by-one — landing
///   `not_before` in the *future* so freshly minted leaves were "not yet valid"
///   and every client rejected the handshake;
/// - small client/proxy clock skew, which would otherwise reject a cert minted
///   "just now".
pub(crate) struct Validity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

/// Slack subtracted from `now` for `not_before`, so a just-minted cert is never
/// in the future for a slightly-behind client clock.
const NOT_BEFORE_SLACK: time::Duration = time::Duration::days(2);

impl Validity {
    /// Build a window `[now - 2 days, now + `years` years]` from the real
    /// system clock. Never panics: the only fallible step (`replace_year`) is
    /// handled with a day-count approximation if it ever overflows the calendar.
    pub(crate) fn for_years(years: i32) -> Self {
        let now = OffsetDateTime::now_utc();
        let not_before = now - NOT_BEFORE_SLACK;
        // `replace_year` only fails for years outside ±9999; the small offsets
        // we use keep us well inside that range, but stay total just in case.
        let not_after = now
            .replace_year(now.year() + years)
            .unwrap_or_else(|_| now + time::Duration::days(365 * i64::from(years)));
        Self {
            not_before,
            not_after,
        }
    }
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
