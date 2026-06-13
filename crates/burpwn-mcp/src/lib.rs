//! burpwn-mcp — an MCP server (rmcp 0.2) exposing burpwn's capabilities as tools so an AI agent
//! can drive the intercepting proxy + sandbox natively.
//!
//! # What it exposes
//!
//! Query (read the session SQLite via [`burpwn_store::Reader`], no daemon needed):
//! `session_list`, `session_current`, `req_list`, `req_show`, `req_search`,
//! `workspace_list`, `tag_list`, `match_replace_list`.
//!
//! Mutation (write via the store): `match_replace_add`, `tag_add`, `note_add`,
//! `workspace_new`.
//!
//! Daemon / intercept (drive the running `burpwn proxy` daemon via
//! [`burpwn_cli::control::ControlClient`]): `intercept_enable`,
//! `intercept_disable`, `intercept_list`, `await_intercept` (the long-poll that
//! surfaces blocking interception over stateless MCP calls), `intercept_forward`,
//! `intercept_drop`.
//!
//! Exec: `exec` — runs a command in the sandbox by shelling out to the burpwn
//! binary with fd 3 wired to a pipe (see [`handlers::run_exec`]).
//!
//! # Architecture
//!
//! - [`params`] — the typed, schemars-derived parameter structs.
//! - [`handlers`] — transport-free async functions doing the real work (unit-tested
//!   directly against a temp session db).
//! - [`server`] — the rmcp tool server ([`server::BurpwnServer`]); each `#[tool]`
//!   method is a thin shim over a [`handlers`] function.
//!
//! # Session resolution
//!
//! [`run`] resolves the active session from `McpArgs::session` (the `--session`
//! flag the binary passes through) or, when absent, [`Paths::active_session`]
//! (the `<data>/current` pointer, defaulting to `default`). The session dir is
//! created on demand so the query tools can open an (empty) store rather than
//! erroring. The control-socket path for the daemon tools is derived lazily per
//! call from the same [`Paths`].

pub mod handlers;
pub mod params;
pub mod server;

use anyhow::Result;

use burpwn_cli::paths::{validate_session_name, Paths};

/// Default server-side `await_intercept` timeout (seconds), kept well under the
/// typical MCP client request timeout so the long-poll returns `{pending:false}`
/// rather than the transport timing out.
pub const DEFAULT_AWAIT_SECS: u64 = 30;

/// Arguments for the MCP server, parsed by the binary's `mcp` subcommand.
#[derive(Debug, Clone, Default)]
pub struct McpArgs {
    /// Session to operate on; defaults to the active session when `None`.
    pub session: Option<String>,
}

/// Start the MCP server over stdio and run until the client disconnects.
///
/// Resolves the session, ensures its directory exists, builds a
/// [`server::BurpwnServer`], and serves it on stdin/stdout via rmcp's
/// `serve(stdio())`. Returns a process exit code (0 on clean shutdown).
///
/// The binary should wire its `mcp` subcommand to this:
/// `burpwn_mcp::run(burpwn_mcp::McpArgs { session }).await`.
pub async fn run(args: McpArgs) -> Result<i32> {
    use rmcp::transport::io::stdio;
    use rmcp::ServiceExt;

    let paths = Paths::resolve()?;
    let session = args.session.unwrap_or_else(|| paths.active_session());
    // Reject a traversing `--session` (e.g. `../../tmp/x`) BEFORE building any
    // filesystem path from it, so a caller can never escape the sessions dir.
    // `active_session()` is already self-validating (see paths.rs), so this only
    // ever rejects an explicitly-passed bad name.
    validate_session_name(&session)
        .map_err(|e| anyhow::anyhow!("invalid --session {session:?}: {e}"))?;
    // Ensure the session dir exists so query tools can open an (empty) store.
    paths.ensure_session_dir(&session)?;

    tracing::info!(session = %session, "starting burpwn MCP server on stdio");

    let svc = server::BurpwnServer::new(paths, session);
    let running = svc
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("starting MCP stdio server: {e}"))?;
    running
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server loop: {e}"))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_args_default_has_no_session() {
        let a = McpArgs::default();
        assert!(a.session.is_none());
    }

    /// A traversing `--session` must be rejected before any FS path is built
    /// from it, so `burpwn mcp --session ../../tmp/x` can't escape the sessions
    /// dir. This mirrors the guard `run()` applies (the same
    /// `validate_session_name` used by `cmd_exec`/`cmd_proxy`).
    #[test]
    fn traversing_session_is_rejected() {
        assert!(validate_session_name("../../tmp/x").is_err());
        assert!(validate_session_name("..").is_err());
        assert!(validate_session_name("a/b").is_err());
        assert!(validate_session_name("ok-1").is_ok());
    }

    #[tokio::test]
    async fn server_constructs_for_a_temp_session() {
        // Smoke test: building the server (and thus the tool router) does not panic.
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let _svc = server::BurpwnServer::new(paths, "default".to_string());
    }
}
