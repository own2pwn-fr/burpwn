//! burpwn — single binary entry point. Installs the rustls crypto provider, then
//! dispatches to the CLI (the CLI sets up tracing and, for the `mcp` path, the
//! MCP server — wired in M7).

fn main() {
    // Internal re-exec path: when launched as `burpwn __netns-agent` by the
    // sandbox runtime, run the in-namespace helper directly — no tokio runtime,
    // no clap parsing (this process was execve'd inside a fresh userns+netns and
    // must stay single-threaded so it can safely spawn ip/nft/bwrap).
    if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == burpwn_sandbox::NETNS_AGENT_ARG)
    {
        std::process::exit(burpwn_sandbox::netns_agent_main());
    }

    // Install the process-wide rustls crypto provider exactly once, before any
    // TLS work (leaf signing, MITM accept, upstream connect). `ring`, matching
    // the workspace's rustls feature selection.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // The CLI owns argv parsing, tracing setup, and dispatch; it returns a
    // process exit code.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("burpwn: failed to start the async runtime: {e}");
            std::process::exit(1);
        }
    };

    let code = match rt.block_on(burpwn_cli::run()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("burpwn: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
