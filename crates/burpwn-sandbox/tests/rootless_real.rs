//! Real-path integration test for the rootless runtime.
//!
//! This is `#[ignore]`d because it ACTUALLY creates user+network namespaces and
//! execs `bwrap`/`nft`/`ip`. It requires a real host with unprivileged user
//! namespaces enabled and the `bwrap`, `nft`, `ip` binaries present (e.g. the
//! validated Fedora 43 / kernel 6.17 box). CI has no such guarantee, so it does
//! not run by default. Run it explicitly with:
//!
//! ```text
//! cargo test -p burpwn-sandbox --test rootless_real -- --ignored --nocapture
//! ```
//!
//! It needs a host-side proxy listening on the `proxy_sock` to actually do the
//! egress; without one the in-netns acceptor's hand-off fails per connection but
//! the command itself still runs (and `curl` will simply get no response). The
//! point of the gated test is to prove the namespace + bwrap setup does not
//! error on a capable host, not to assert a full round-trip (that belongs in the
//! proxy crate's e2e suite).

use std::path::PathBuf;

use burpwn_sandbox::{doctor, ExecSpec, RootlessRuntime, SandboxRuntime};

#[tokio::test]
#[ignore = "creates real user+net namespaces; needs an unprivileged-userns host with bwrap/nft/ip"]
async fn runs_true_inside_a_real_sandbox() {
    let pf = doctor();
    assert!(
        pf.is_ok(),
        "host is not capable of the rootless sandbox: missing {}",
        pf.missing_summary()
    );

    let rt = RootlessRuntime::new();
    let spec = ExecSpec {
        argv: vec!["/usr/bin/true".into()],
        workdir: PathBuf::from("/tmp"),
        env: vec![],
        // No real proxy is required to exit cleanly when running `true`.
        proxy_sock: PathBuf::from("/run/burpwn/proxy.sock"),
        proxy_tcp_port: 18080,
        proxy_dns_port: 15353,
        ca_path: PathBuf::from("/etc/ssl/cert.pem"),
        timeout: None,
        inherit_stdio: false,
    };

    let outcome = rt.run(spec).await.expect("sandbox run should succeed");
    assert_eq!(
        outcome.exit_code, 0,
        "`true` should exit 0 inside the sandbox"
    );
}
