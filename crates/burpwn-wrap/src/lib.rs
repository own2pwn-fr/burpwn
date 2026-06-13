//! burpwn-wrap — agent integration (rtk-style). Installs per-agent command-rewrite hooks
//! (Claude Code / Copilot PreToolUse, Cursor hooks.json, Gemini BeforeTool, Cline/Roo .clinerules)
//! and a generic global shell hook so even a custom agent is covered. Each command the agent runs
//! is rewritten to flow through `burpwn exec`, while the agent process itself stays out of the
//! sandbox (its LLM traffic is never captured).
//!
//! # Design (mirrors rtk)
//!
//! rtk installs, per AI tool, a hook that transparently rewrites each command
//! before execution, plus a generic global shell hook (`rtk init -g`) for
//! anything else, with an `exclude_commands` escape hatch. burpwn mirrors this;
//! our rewrite target is `burpwn exec -- <original command>`.
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
}

/// Rewrite a single command line into its `burpwn exec` form.
///
/// ```
/// # use burpwn_wrap::rewrite_command;
/// assert_eq!(rewrite_command("curl https://x"), "burpwn exec -- curl https://x");
/// ```
///
/// # Quoting caveat
///
/// This is a textual prefix, NOT a shell re-quoter: it relies on `burpwn exec`
/// receiving the command tail verbatim and re-interpreting it the same way the
/// caller's shell would. When the rewrite is applied inside a structured tool
/// input (the Claude/Gemini/Cursor JSON `command` field, which is itself a
/// single shell string), this is correct — the agent passes the whole string to
/// a shell, so prepending `burpwn exec -- ` preserves the original word
/// splitting/quoting. burpwn's `exec` subcommand is expected to treat everything
/// after `--` as the command to run under the sandbox. Do not pre-split/re-quote
/// here; that would double-process metacharacters.
pub fn rewrite_command(cmd: &str) -> String {
    format!("burpwn exec -- {cmd}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_command_shape() {
        assert_eq!(
            rewrite_command("nmap -sV target"),
            "burpwn exec -- nmap -sV target"
        );
        assert_eq!(rewrite_command(""), "burpwn exec -- ");
    }
}
