//! burpwn-cli — the clap subcommand tree (doctor, init, ca, session, exec, req,
//! intercept, match-replace, workspace/tag/note, export) with a uniform JSON
//! envelope and the orchestration glue wiring the store, proxy, sandbox, TLS and
//! wrap layers together.
//!
//! # Command tree
//!
//! ```text
//! burpwn [--json] <command>
//!   doctor                               sandbox + CA preflight
//!   init [-g] [--agent A]                 install agent / shell hooks (burpwn-wrap)
//!   wrap-hook            (hidden)         stdin tool-input rewrite filter
//!   proxy [--session S]  (hidden)         the long-running daemon
//!   ca init | export
//!   session new|list|use|rm
//!   exec [--json] [--workspace W] [--timeout S] [--session S] -- <cmd>...
//!   req list <filters> | show <id> [--raw] | search <q> | replay <id> [edits]
//!   intercept enable|disable|list|await|forward|drop
//!   match-replace add|list|rm|enable|disable
//!   workspace new|list|use
//!   tag add <flow> <name> | note add <flow> <text>
//!   export har [--workspace] [-o file] | pcap
//! ```
//!
//! # Session / daemon / control contract (reused by the MCP crate)
//!
//! - [`paths`] defines the on-disk layout: `<data>/ca.pem`,
//!   `<data>/sessions/<name>/session.db`, `<data>/current`, and the per-session
//!   runtime dir `$XDG_RUNTIME_DIR/burpwn/<session>/{proxy.sock,control.sock,ports.json}`.
//! - [`daemon`] is the `burpwn proxy` process: it opens the session store, builds
//!   a [`burpwn_proxy::Proxy`], and concurrently serves the SCM_RIGHTS front-end,
//!   the DNS shim and the control server.
//! - [`control`] is the newline-delimited JSON control protocol
//!   ([`control::ControlRequest`] / [`control::ControlResponse`]) plus
//!   [`control::ControlClient`] — the MCP server connects a `ControlClient` to a
//!   session's `control.sock` and drives intercept/status with the typed methods.
//!
//! # Entry point
//!
//! The binary crate calls [`run`]; it parses argv, sets up tracing, dispatches,
//! and returns a process exit code.

pub mod cli;
pub mod commands;
pub mod control;
pub mod daemon;
pub mod envelope;
pub mod exec;
pub mod har;
pub mod paths;
pub mod replay;
pub mod wrap_hook;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;
use crate::paths::Paths;

/// Parse argv, set up tracing (env `BURPWN_LOG`, to stderr), dispatch, and
/// return a process exit code. The binary crate calls this.
///
/// Tracing is initialised best-effort: if a subscriber is already installed
/// (e.g. the binary crate set one up), this is a no-op.
pub async fn run() -> Result<i32> {
    init_tracing();
    let cli = Cli::parse();
    let paths = Paths::resolve()?;
    commands::dispatch(cli, &paths).await
}

/// Like [`run`] but against an explicit [`Paths`] (for tests / embedding).
pub async fn run_with(cli: Cli, paths: &Paths) -> Result<i32> {
    commands::dispatch(cli, paths).await
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("BURPWN_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Ignore the error when a global subscriber is already set.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_global_json_and_exec_trailing_args() {
        let cli = Cli::parse_from([
            "burpwn",
            "--json",
            "exec",
            "--timeout",
            "5",
            "--",
            "curl",
            "https://example.com",
        ]);
        assert!(cli.json);
        match cli.command {
            cli::Command::Exec(args) => {
                assert_eq!(args.timeout, Some(5));
                assert_eq!(args.cmd, vec!["curl", "https://example.com"]);
            }
            other => panic!("expected exec, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_req_list_filters() {
        let cli = Cli::parse_from([
            "burpwn", "req", "list", "--host", "example", "--status", "200", "--limit", "10",
        ]);
        match cli.command {
            cli::Command::Req {
                action: cli::ReqAction::List(args),
            } => {
                assert_eq!(args.host.as_deref(), Some("example"));
                assert_eq!(args.status, Some(200));
                assert_eq!(args.limit, Some(10));
            }
            other => panic!("expected req list, got {other:?}"),
        }
    }

    #[test]
    fn hidden_subcommands_parse() {
        let cli = Cli::parse_from(["burpwn", "proxy", "--session", "s"]);
        assert!(matches!(cli.command, cli::Command::Proxy(_)));
        let cli = Cli::parse_from(["burpwn", "wrap-hook"]);
        assert!(matches!(cli.command, cli::Command::WrapHook));
    }
}
