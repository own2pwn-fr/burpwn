//! Live end-to-end check that a REDIRECTed packet actually reaches the in-netns
//! loopback shim — the one thing no string assertion on the generated nftables
//! script can prove.
//!
//! ## The bug this exists for
//!
//! In 0.3.1 the QUIC fail-fast `udpguard` chain sat at `filter hook output
//! priority 0`, i.e. AFTER the NAT chain's `dstnat` (-100). By the time the guard
//! saw the sandbox's own DNS query, the redirect had rewritten it to
//! `127.0.0.1:<dns_port>` while keeping the `burp0` output interface — so
//! `oifname "burp0" udp dport != 53 reject` matched and the kernel answered
//! `sendto` with `EPERM`. Every `burpwn exec` failed to resolve anything and
//! captured ZERO flows, on every host (the WSL-specific diagnosis in the doctor
//! output was a red herring: the same failure reproduced on Fedora 43). The
//! ruleset LOADED perfectly the whole time, which is exactly why the unit tests
//! stayed green.
//!
//! ## Why `harness = false`
//!
//! [`burpwn_sandbox::deep_probe`] re-execs `/proc/self/exe` with the
//! [`NETNS_PROBE_ARG`] marker to get a clean single-threaded image inside the
//! fresh namespaces. libtest's generated `main` would parse that marker as a test
//! filter and print no report, so this target owns its `main` and routes the
//! marker to [`netns_probe_main`] exactly like the real binary does.
//!
//! ## Running it
//!
//! It creates real user+network namespaces and execs `ip`/`nft`, so it is opt-in
//! (a plain `cargo test` prints `skipped` and exits 0):
//!
//! ```text
//! BURPWN_REAL_SANDBOX_TESTS=1 cargo test -p burpwn-sandbox --test redirect_delivery_real
//! ```

use burpwn_sandbox::{deep_probe, netns_probe_main, NETNS_PROBE_ARG};

const OPT_IN: &str = "BURPWN_REAL_SANDBOX_TESTS";

fn main() {
    // Re-exec'd probe helper: run the steps inside the namespaces and print the
    // JSON report the parent parses. Must be handled before anything else.
    if std::env::args().nth(1).as_deref() == Some(NETNS_PROBE_ARG) {
        std::process::exit(netns_probe_main());
    }

    if std::env::var_os(OPT_IN).is_none() {
        println!("test redirect_delivery_real ... skipped (set {OPT_IN}=1 to run)");
        return;
    }

    let report = deep_probe();
    let delivery = report
        .steps
        .iter()
        .find(|s| s.name == "redirect_delivery")
        .unwrap_or_else(|| {
            panic!(
                "the probe never reached the delivery step: {}",
                report.summary()
            )
        });
    assert!(
        delivery.ok,
        "the redirected UDP/53 datagram never reached the loopback shim: {}",
        delivery.detail
    );
    assert!(
        report.is_ok(),
        "sandbox not usable on this host: {}",
        report.summary()
    );
    println!("test redirect_delivery_real ... ok");
}
