//! burpwn-wrap — agent integration (rtk-style). Installs per-agent command-rewrite hooks
//! (Claude Code / Copilot PreToolUse, Cursor hooks.json, Gemini BeforeTool, Cline/Roo .clinerules)
//! and a generic global shell hook so even a custom agent is covered. Each command the agent runs
//! is rewritten to flow through `burpwn exec -- sh -c '…'`, while the agent process itself stays out of the
//! sandbox (its LLM traffic is never captured).
//!
//! # Design (mirrors rtk)
//!
//! rtk installs, per AI tool, a hook that transparently rewrites each command
//! before execution, plus a generic global shell hook (`rtk init -g`) for
//! anything else, with an `exclude_commands` escape hatch. burpwn mirrors this;
//! our rewrite target is `burpwn exec -- sh -c '<original command line>'` — the
//! whole line is wrapped as one inner-shell argument so a compound command runs
//! entirely inside one sandbox (see [`rewrite_command`]).
//!
//! * [`agent`] — supported agents + best-effort presence detection.
//! * [`hooks`] — PURE per-agent hook-content generators (the testable core).
//! * [`shell`] — the generic global shell hook + the `burpwn-shell` wrapper.
//! * [`config`] — [`WrapConfig`] (the `[wrap]` table) + [`should_wrap`].
//! * [`install`] — merge-not-clobber install/uninstall orchestration.
//!
//! # The `burpwn wrap-hook` helper
//!
//! The installed JSON hooks all invoke `burpwn wrap-hook --agent <slug>`, a
//! stdin-filter the CLI implements: it reads the agent's tool-input JSON,
//! applies [`should_wrap`] + [`rewrite_command`], and emits the agent's hook
//! response JSON. This crate provides the rewrite *decision* and the rewrite
//! *string*; the CLI wires up the per-agent stdin/stdout dialects.

pub mod agent;
pub mod config;
pub mod hooks;
pub mod install;
pub mod shell;

pub use agent::{detect_present, Agent};
pub use config::{should_wrap, WrapConfig};
pub use hooks::{
    claude_code_pretooluse, cline_rules_block, copilot_pretooluse, cursor_hook_entry,
    cursor_hooks_json, gemini_beforetool, pretooluse_entry_for, wrap_hook_invocation,
};
pub use install::{
    install, install_with_bin, uninstall, InstallAction, InstallReport, DEFAULT_BURPWN_BIN,
};
pub use shell::{global_shell_snippet, install_global, shell_wrapper_script, uninstall_global};

/// Errors produced by burpwn-wrap install/config operations.
#[derive(Debug, thiserror::Error)]
pub enum WrapError {
    /// Filesystem I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON (de)serialization error on an agent config file.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// TOML parse error on `config.toml`.
    #[error("toml parse error: {0}")]
    TomlDe(#[from] toml::de::Error),
    /// TOML serialization error on `config.toml`.
    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    /// An existing agent config file parsed to valid JSON that is NOT an object,
    /// so merging burpwn's hook would have to clobber the user's content. We
    /// refuse rather than overwrite it.
    #[error("agent config root is not a JSON object (refusing to overwrite): {0}")]
    NonObjectRoot(String),
}

/// Rewrite a single command line into its `burpwn exec` form.
///
/// ```
/// # use burpwn_wrap::rewrite_command;
/// assert_eq!(
///     rewrite_command("curl https://x"),
///     "burpwn exec -- sh -c 'curl https://x'"
/// );
/// ```
///
/// # Why `sh -c '<cmd>'` and not a bare textual prefix
///
/// The command field we rewrite is a *single shell string* that the agent hands
/// to a shell to parse. A bare textual prefix (`burpwn exec -- <cmd>`) only puts
/// the FIRST top-level segment under the sandbox: for a compound line like
/// `curl https://a && curl https://evil` (also `;`, `|`, `||`, `$(…)`), the
/// agent's shell parses the operator at *its* top level, so `burpwn exec` sees
/// only `curl https://a` and everything after the operator runs OUTSIDE the
/// sandbox, uncaptured. That breaks the "capture every agent command" guarantee.
///
/// To wrap the WHOLE line we run it as one argument of an inner shell:
/// `burpwn exec -- sh -c '<cmd>'`. The entire compound then executes inside the
/// single sandboxed `sh`, so every segment's traffic is captured. `<cmd>` is
/// single-quoted with the standard `'\''` idiom (see [`shell::single_quote`]) so
/// any metacharacters in it are passed through verbatim to the inner shell
/// rather than being re-interpreted by `burpwn exec`'s own argv handling.
pub fn rewrite_command(cmd: &str) -> String {
    format!("burpwn exec -- sh -c {}", shell::single_quote(cmd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_command_shape() {
        assert_eq!(
            rewrite_command("nmap -sV target"),
            "burpwn exec -- sh -c 'nmap -sV target'"
        );
        assert_eq!(rewrite_command(""), "burpwn exec -- sh -c ''");
    }

    #[test]
    fn rewrite_command_wraps_whole_compound_line() {
        // The entire compound (both segments) must run inside the single
        // sandboxed `sh -c`, not just the first segment before `&&`.
        assert_eq!(
            rewrite_command("curl https://a && curl https://evil"),
            "burpwn exec -- sh -c 'curl https://a && curl https://evil'"
        );
        // Other top-level operators are likewise contained.
        assert_eq!(
            rewrite_command("a | b; c"),
            "burpwn exec -- sh -c 'a | b; c'"
        );
        assert_eq!(
            rewrite_command("echo $(id)"),
            "burpwn exec -- sh -c 'echo $(id)'"
        );
    }

    #[test]
    fn rewrite_command_escapes_embedded_single_quotes() {
        assert_eq!(
            rewrite_command("sh -c 'echo hi'"),
            "burpwn exec -- sh -c 'sh -c '\\''echo hi'\\'''"
        );
    }
}
