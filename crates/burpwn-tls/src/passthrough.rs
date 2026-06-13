//! Pinning-fallback bookkeeping.
//!
//! Some origins pin their certificate (HPKP, native-app pinning, or a browser
//! that rejects our forged leaf). When a MITM accept fails for a host, the proxy
//! should *splice* future TLS for that host straight through (client ↔ origin,
//! no interception) instead of repeatedly failing the handshake.
//!
//! This module only owns the *decision state*: a concurrent set of hosts known
//! to reject interception. The actual byte-splice lives in `burpwn-proxy`; it
//! calls [`PinnedHosts::is_pinned`] before deciding to MITM and
//! [`PinnedHosts::mark_pinned`] when an accept fails.

use std::sync::Arc;

use dashmap::DashSet;

/// A thread-safe set of hosts that should bypass MITM (TLS pass-through).
///
/// Cheap to clone (`Arc` inside) so the proxy can hand a copy to every
/// connection task.
#[derive(Debug, Clone, Default)]
pub struct PinnedHosts {
    inner: Arc<DashSet<String>>,
}

impl PinnedHosts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `host` rejects interception; future connections splice
    /// through. Idempotent.
    pub fn mark_pinned(&self, host: impl AsRef<str>) {
        self.inner.insert(normalize(host.as_ref()));
    }

    /// True if `host` is known to reject interception (should be passed through).
    pub fn is_pinned(&self, host: impl AsRef<str>) -> bool {
        self.inner.contains(&normalize(host.as_ref()))
    }

    /// Remove a host from the pinned set (e.g. on manual override / retry).
    pub fn unmark(&self, host: impl AsRef<str>) -> bool {
        self.inner.remove(&normalize(host.as_ref())).is_some()
    }

    /// Number of pinned hosts (diagnostics).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Hosts compare case-insensitively (DNS is case-insensitive); a trailing dot is
/// stripped so `example.com` and `example.com.` collapse.
fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_query() {
        let p = PinnedHosts::new();
        assert!(!p.is_pinned("example.com"));
        p.mark_pinned("example.com");
        assert!(p.is_pinned("example.com"));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn case_and_trailing_dot_insensitive() {
        let p = PinnedHosts::new();
        p.mark_pinned("Example.COM.");
        assert!(p.is_pinned("example.com"));
        assert!(p.is_pinned("EXAMPLE.com."));
    }

    #[test]
    fn mark_is_idempotent() {
        let p = PinnedHosts::new();
        p.mark_pinned("a.test");
        p.mark_pinned("a.test");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn unmark_removes() {
        let p = PinnedHosts::new();
        p.mark_pinned("a.test");
        assert!(p.unmark("A.test"));
        assert!(!p.is_pinned("a.test"));
        assert!(!p.unmark("a.test"));
    }

    #[test]
    fn clone_shares_state() {
        let p = PinnedHosts::new();
        let q = p.clone();
        p.mark_pinned("shared.test");
        assert!(q.is_pinned("shared.test"));
    }
}
