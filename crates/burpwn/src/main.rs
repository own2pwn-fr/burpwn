//! burpwn — single binary entry point. Installs the rustls crypto provider, then
//! dispatches to the CLI, the MCP server (`burpwn mcp`), or the internal
//! `__netns-agent` re-exec helper.

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

    // The `mcp` subcommand is routed directly here (not through burpwn-cli's
    // clap tree) so burpwn-mcp can depend on burpwn-cli without a cycle.
    let result = if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("mcp")) {
        // Print help instead of starting the server when asked.
        if std::env::args().skip(2).any(|a| a == "--help" || a == "-h") {
            println!(
                "Run the burpwn MCP server over stdio (for AI agents).\n\n\
                 Usage: burpwn mcp [--session <name>]\n\n\
                 Options:\n  \
                 --session <name>  Session to operate on (default: the active session)\n  \
                 -h, --help        Print help\n\n\
                 The server speaks the Model Context Protocol on stdin/stdout; run it from\n\
                 your agent's MCP client configuration, not interactively."
            );
            std::process::exit(0);
        }
        rt.block_on(burpwn_mcp::run(parse_mcp_args()))
    } else {
        // The CLI owns argv parsing, tracing setup, and dispatch.
        rt.block_on(burpwn_cli::run())
    };

    let code = match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("burpwn: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

/// Minimal arg parsing for `burpwn mcp [--session <name>]` (the MCP server has
/// no other flags; it speaks MCP over stdio).
fn parse_mcp_args() -> burpwn_mcp::McpArgs {
    let mut args = std::env::args().skip(2); // skip exe + "mcp"
    let mut session = None;
    while let Some(a) = args.next() {
        if a == "--session" {
            session = args.next();
        }
    }
    burpwn_mcp::McpArgs { session }
}
