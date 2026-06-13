//! burpwn — single binary entry point. Installs the rustls crypto provider, sets up tracing, and
//! dispatches to the CLI or the MCP server.

fn main() -> anyhow::Result<()> {
    // Install the process-wide rustls crypto provider exactly once, before any TLS work.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("BURPWN_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Real dispatch lands in M5 (CLI) / M7 (MCP); placeholder keeps the binary runnable.
    println!("burpwn {} — scaffold", env!("CARGO_PKG_VERSION"));
    Ok(())
}
