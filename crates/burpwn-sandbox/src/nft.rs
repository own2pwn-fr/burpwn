//! nftables ruleset generation for the rootless sandbox netns.
//!
//! This is **pure string logic** — no privileges, no I/O — so it is fully
//! unit-tested in CI. Application (`nft -f -` inside the child netns) is done
//! by [`crate::rootless`] and requires the scoped `CAP_NET_ADMIN` granted by
//! the userns+netns unshare, which cannot run under the dev/CI harness.
//!
//! ## What the ruleset does
//!
//! The spike proved a `REDIRECT`-based (NOT `TPROXY`) `inet` NAT table in the
//! child netns. Every TCP connection the sandboxed command makes is redirected
//! to the in-netns acceptor on `tcp_port`, and every UDP/53 query is redirected
//! to the in-netns DNS shim on `dns_port`. The acceptor recovers the pre-NAT
//! destination via `SO_ORIGINAL_DST` and hands the connection to the host proxy.
//!
//! The two leading `accept` lines avoid an infinite redirect loop: traffic
//! *already aimed at* the acceptor / DNS shim ports must not be redirected again.
//!
//! The child netns has **no real egress** (only `lo` + a dummy `burp0`), so the
//! redirect is the ONLY path out — that is the security property ("rien ne sort
//! sauf via le proxy").
//!
//! ## QUIC / HTTP-3 fail-fast
//!
//! Only TCP (all ports) and `udp dport 53` are handled by the NAT chain; every
//! other UDP has nowhere to go (the netns has no real egress). Left to the
//! kernel that traffic is *silently blackholed*, so a wrapped client that tries
//! QUIC on UDP/443 (e.g. `curl --http3`, or any client honouring an `Alt-Svc`
//! HTTP-3 advert) HANGS until its own handshake timeout instead of falling back
//! to TCP/h2. To make the fallback deterministic, a second `filter hook output`
//! chain (`udpguard`, policy **accept**) explicitly **rejects** non-DNS UDP that
//! egresses the dummy `burp0` interface, so a QUIC attempt gets an immediate
//! ICMP/ICMPv6 port-unreachable and the client falls back at once. The guard is
//! scoped to `oifname "burp0"` on purpose: loopback traffic (the redirected DNS
//! query, the DNS shim's replies, and the redirected TCP acceptor) all stay on
//! `lo` and is therefore untouched — only real outbound UDP is rejected. On a
//! kernel that lacks `nf_reject` the guard can instead `drop` (see
//! [`UdpAction`]); the client then falls back only after its own timeout.

/// The fixed nftables table name used inside the sandbox netns.
pub const TABLE: &str = "burpwn";

/// How the `udpguard` chain handles non-DNS UDP egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAction {
    /// Emit an ICMP/ICMPv6 port-unreachable (the preferred behavior): a QUIC
    /// client fails fast and falls back to TCP/h2 immediately. Requires the
    /// kernel `nf_reject` module.
    Reject,
    /// Silently drop the packet. Fallback for kernels without `nf_reject`; a
    /// QUIC client then falls back only after its own handshake timeout.
    Drop,
}

impl UdpAction {
    /// The nft statement keyword for this action (`reject` / `drop`).
    fn keyword(self) -> &'static str {
        match self {
            UdpAction::Reject => "reject",
            UdpAction::Drop => "drop",
        }
    }
}

/// Build the `inet burpwn` REDIRECT ruleset for the sandbox netns.
///
/// `tcp_port` is where the in-netns TCP acceptor listens (`127.0.0.1:tcp_port`);
/// `dns_port` is where the in-netns DNS shim listens (`127.0.0.1:dns_port`).
/// All TCP is redirected to `tcp_port`, all UDP/53 to `dns_port`; the matching
/// destination ports are accepted first to break the redirect loop.
///
/// The output is suitable for `nft -f -` and is deterministic for a given pair
/// of ports (so the unit tests can assert it exactly).
///
/// Uses [`UdpAction::Reject`] for the QUIC/HTTP-3 fail-fast guard — the
/// preferred behavior. Use [`redirect_ruleset_with`] to select [`UdpAction::Drop`]
/// on kernels that lack `nf_reject`.
pub fn redirect_ruleset(tcp_port: u16, dns_port: u16) -> String {
    redirect_ruleset_with(tcp_port, dns_port, UdpAction::Reject)
}

/// Like [`redirect_ruleset`] but with an explicit [`UdpAction`] for the
/// non-DNS-UDP guard (`reject` vs `drop`). See the module docs for why the guard
/// exists (QUIC/HTTP-3 deterministic fail-fast) and why it is scoped to the
/// `burp0` egress interface (so loopback DNS/acceptor traffic is untouched).
pub fn redirect_ruleset_with(tcp_port: u16, dns_port: u16, udp_action: UdpAction) -> String {
    let mut s = String::new();
    // `add table` is idempotent (no-op if present); `flush table` afterwards
    // guarantees a clean slate on a reused netns name. `add` must precede
    // `flush` (flushing a non-existent table errors on old nft).
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!("flush table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));
    s.push_str("  chain output {\n");
    s.push_str("    type nat hook output priority -100; policy accept;\n");
    // Loop avoidance: don't re-redirect traffic already destined for the
    // acceptor / DNS shim (the proxy connection itself, and the shim's own dst).
    s.push_str(&format!("    tcp dport {tcp_port} accept\n"));
    s.push_str(&format!("    udp dport {dns_port} accept\n"));
    // Force every other TCP connection to the in-netns acceptor.
    s.push_str(&format!("    meta l4proto tcp redirect to :{tcp_port}\n"));
    // Force DNS to the in-netns DNS shim.
    s.push_str(&format!("    udp dport 53 redirect to :{dns_port}\n"));
    s.push_str("  }\n");
    // QUIC/HTTP-3 fail-fast guard. A SEPARATE `filter hook output` chain with a
    // `policy accept` (NOT drop — a drop policy blackholes the post-DNAT redirect
    // in this rootless setup; see the note below) that rejects non-DNS UDP which
    // egresses the dummy `burp0` interface. This targets exactly "a client trying
    // to send UDP to the outside world" — i.e. a QUIC attempt on UDP/443 — and
    // hands it an immediate ICMP port-unreachable so the client falls back to
    // TCP/h2 deterministically instead of hanging on a handshake timeout.
    //
    // Scoping to `oifname "burp0"` is load-bearing: the redirected DNS query, the
    // DNS shim's replies, and the redirected TCP acceptor connections all live on
    // `lo` (127.0.0.1 / [::1]) and are therefore NOT matched — only genuine
    // outbound UDP (routed via the default route out `burp0`) is rejected. The
    // `udp dport != 53` term is a belt-and-braces exclusion of DNS (already
    // redirected off `burp0` by the NAT chain, but never reject a DNS packet).
    s.push_str("  chain udpguard {\n");
    s.push_str("    type filter hook output priority 0; policy accept;\n");
    s.push_str(&format!(
        "    oifname \"burp0\" udp dport != 53 {}\n",
        udp_action.keyword()
    ));
    s.push_str("  }\n");
    s.push_str("}\n");
    // NOTE: a `filter hook output` chain with `policy drop` was evaluated as a
    // defense-in-depth egress guard but REJECTED: in this rootless REDIRECT setup
    // a drop *policy* blackholes the post-DNAT SYN (the packet does not present
    // `oif "lo"` to the filter hook as expected, so a loopback-only accept +
    // drop-policy blackholes the redirect itself). Egress is already structurally
    // blocked — the netns has only `lo` + the dummy `burp0` sink and NO real
    // interface, so nothing can leave except via the REDIRECT to the in-netns
    // acceptor. That is the security property; we do not rely on a fragile
    // drop-policy output filter for it. The `udpguard` chain above keeps
    // `policy accept` and only touches UDP, so it never affects the TCP redirect.
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_contains_table_and_nat_hook() {
        let rs = redirect_ruleset(8080, 5353);
        assert!(rs.contains("table inet burpwn {"));
        assert!(rs.contains("type nat hook output priority -100; policy accept;"));
    }

    #[test]
    fn ruleset_redirects_all_tcp_to_proxy_port() {
        let rs = redirect_ruleset(8080, 5353);
        assert!(rs.contains("meta l4proto tcp redirect to :8080"));
    }

    #[test]
    fn ruleset_redirects_dns_to_dns_port() {
        let rs = redirect_ruleset(8080, 5353);
        assert!(rs.contains("udp dport 53 redirect to :5353"));
    }

    #[test]
    fn ruleset_has_loop_avoidance_accepts_before_redirects() {
        let rs = redirect_ruleset(8080, 5353);
        // The accept lines must come before the redirect lines, otherwise the
        // proxy connection itself would be redirected into a loop.
        let tcp_accept = rs.find("tcp dport 8080 accept").unwrap();
        let udp_accept = rs.find("udp dport 5353 accept").unwrap();
        let tcp_redirect = rs.find("meta l4proto tcp redirect to :8080").unwrap();
        let udp_redirect = rs.find("udp dport 53 redirect to :5353").unwrap();
        assert!(
            tcp_accept < tcp_redirect,
            "tcp accept must precede redirect"
        );
        assert!(
            udp_accept < udp_redirect,
            "udp accept must precede redirect"
        );
    }

    #[test]
    fn ruleset_uses_distinct_ports_correctly() {
        // A different port pair must produce the matching lines (no hardcoding).
        let rs = redirect_ruleset(9999, 1053);
        assert!(rs.contains("tcp dport 9999 accept"));
        assert!(rs.contains("udp dport 1053 accept"));
        assert!(rs.contains("meta l4proto tcp redirect to :9999"));
        assert!(rs.contains("udp dport 53 redirect to :1053"));
        // The old ports must NOT appear.
        assert!(!rs.contains("8080"));
        assert!(!rs.contains("5353"));
    }

    #[test]
    fn add_table_precedes_flush() {
        let rs = redirect_ruleset(8080, 5353);
        let add = rs.find("add table inet burpwn").unwrap();
        let flush = rs.find("flush table inet burpwn").unwrap();
        assert!(add < flush, "add table must precede flush table");
    }

    #[test]
    fn ruleset_is_deterministic() {
        assert_eq!(redirect_ruleset(8080, 5353), redirect_ruleset(8080, 5353));
    }

    #[test]
    fn udp_guard_never_drops_or_rejects_tcp_or_uses_drop_policy() {
        // Regression guard: a `filter hook output` chain with a *drop policy*
        // blackholes the post-DNAT redirect in this rootless setup (proven via
        // the live e2e). The `udpguard` chain must therefore keep `policy accept`
        // and only ever act on UDP — never drop/reject TCP.
        let rs = redirect_ruleset(8080, 5353);
        assert!(!rs.contains("policy drop"));
        let low = rs.to_lowercase();
        assert!(!low.contains("l4proto tcp reject"));
        assert!(!low.contains("l4proto tcp drop"));
        assert!(!low.contains("tcp dport 443 reject"));
    }

    #[test]
    fn ruleset_rejects_nondns_udp_egress_via_dummy_iface() {
        // QUIC/HTTP-3 fail-fast: non-DNS UDP leaving the dummy egress interface
        // gets an ICMP port-unreachable so the client falls back to TCP/h2.
        let rs = redirect_ruleset(8080, 5353);
        assert!(rs.contains("chain udpguard {"));
        assert!(rs.contains("type filter hook output priority 0; policy accept;"));
        assert!(rs.contains("oifname \"burp0\" udp dport != 53 reject"));
    }

    #[test]
    fn udp_guard_spares_dns_and_loopback() {
        // The guard must NOT reject DNS (udp/53) and must be scoped to the burp0
        // egress iface so loopback (redirected DNS + DNS-shim replies + the
        // redirected TCP acceptor) is untouched.
        let rs = redirect_ruleset(8080, 5353);
        // The only reject line is scoped to burp0 AND excludes port 53.
        let reject_lines: Vec<&str> = rs.lines().filter(|l| l.contains("reject")).collect();
        assert_eq!(reject_lines.len(), 1, "exactly one reject rule expected");
        let line = reject_lines[0];
        assert!(line.contains("oifname \"burp0\""), "reject must be scoped to burp0: {line}");
        assert!(line.contains("!= 53"), "reject must exclude DNS: {line}");
    }

    #[test]
    fn drop_mode_uses_drop_action() {
        // On kernels lacking nf_reject the guard falls back to `drop`.
        let rs = redirect_ruleset_with(8080, 5353, UdpAction::Drop);
        assert!(rs.contains("oifname \"burp0\" udp dport != 53 drop"));
        assert!(!rs.contains("reject"));
        // Still never a drop *policy* (which would break the redirect).
        assert!(!rs.contains("policy drop"));
    }

    #[test]
    fn reject_is_the_default_action() {
        assert_eq!(
            redirect_ruleset(8080, 5353),
            redirect_ruleset_with(8080, 5353, UdpAction::Reject)
        );
    }
}
