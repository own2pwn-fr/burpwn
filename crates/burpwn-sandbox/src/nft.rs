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

/// The fixed nftables table name used inside the sandbox netns.
pub const TABLE: &str = "burpwn";

/// Build the `inet burpwn` REDIRECT ruleset for the sandbox netns.
///
/// `tcp_port` is where the in-netns TCP acceptor listens (`127.0.0.1:tcp_port`);
/// `dns_port` is where the in-netns DNS shim listens (`127.0.0.1:dns_port`).
/// All TCP is redirected to `tcp_port`, all UDP/53 to `dns_port`; the matching
/// destination ports are accepted first to break the redirect loop.
///
/// The output is suitable for `nft -f -` and is deterministic for a given pair
/// of ports (so the unit tests can assert it exactly).
pub fn redirect_ruleset(tcp_port: u16, dns_port: u16) -> String {
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
    s.push_str("}\n");
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
}
