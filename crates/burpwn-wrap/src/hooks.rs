//! PURE per-agent hook-content generation — the testable core.
//!
//! Every generator here is a pure function returning the structured value (JSON
//! for programmatic-hook agents, plain rule text for Cline) that, once merged
//! into the agent's config, makes the agent route shell commands through
//! `burpwn exec`. The actual file merge/IO lives in [`crate::install`]; this
//! module never touches the filesystem.
//!
//! ## The wrapper-invocation indirection
//!
//! Rather than baking command-rewriting logic into each agent's config (each
//! has a different stdin/stdout JSON contract), the installed hook simply calls
//! a single burpwn helper:
//!
//! ```text
//! burpwn wrap-hook --agent <slug>
//! ```
//!
//! `burpwn wrap-hook` reads the agent's PreToolUse/BeforeTool/beforeShellExecution
//! tool-input JSON on stdin, applies [`crate::should_wrap`] +
//! [`crate::rewrite_command`], and emits the response JSON in *that agent's*
//! dialect. This keeps the per-agent quirks in one Rust place (the CLI) instead
//! of scattered in shell. The generators below therefore only need to know each
//! agent's *config wiring* shape, not its stdin/stdout contract.
//!
//! ## Shape confidence
//!
//! * **Claude Code** — confident (documented `hooks.PreToolUse` matcher/command).
//! * **Gemini** — confident (documented `hooks.BeforeTool` matcher/command).
//! * **Cursor** — confident on `hooks.json` `beforeShellExecution`
//!   (`version`, `command`, `matcher`).
//! * **Copilot** — BEST-EFFORT: Copilot's hook config is not as stably
//!   documented; we emit the Claude-Code-compatible `PreToolUse` shape (Copilot
//!   tracks the Claude Code hook contract closely). See [`copilot_pretooluse`].
//! * **Cline/Roo** — rules-text, not a programmatic hook; we emit instruction
//!   text. Compliance is advisory (model-followed), unlike the enforced hooks.

use serde_json::{json, Value};

use crate::Agent;

/// The shell-token matcher Claude-Code-family hooks use to select shell tool
/// calls.
const BASH_MATCHER: &str = "Bash";

/// The wrapper invocation burpwn installs as the hook command for a given agent.
/// Calls the `burpwn wrap-hook` stdin-filter helper, telling it which agent's
/// JSON dialect to speak.
///
/// `burpwn_bin` is the path/name used to invoke burpwn (e.g. `"burpwn"` or an
/// absolute install path).
pub fn wrap_hook_invocation(burpwn_bin: &str, agent: Agent) -> String {
    format!("{burpwn_bin} wrap-hook --agent {}", agent.slug())
}

/// Claude Code `hooks.PreToolUse` array *element* for the `Bash` tool.
///
/// Shape (confident):
/// ```json
/// { "matcher": "Bash",
///   "hooks": [ { "type": "command", "command": "burpwn wrap-hook --agent claude-code" } ] }
/// ```
pub fn claude_code_pretooluse(burpwn_bin: &str) -> Value {
    pretooluse_entry(burpwn_bin, Agent::ClaudeCode)
}

/// GitHub Copilot PreToolUse array element.
///
/// BEST-EFFORT: emitted in the Claude-Code-compatible `PreToolUse` shape (see
/// module docs). If Copilot's hook schema diverges this entry may need
/// adjusting; the wiring is intentionally identical so the same merge logic and
/// `wrap-hook` helper apply.
pub fn copilot_pretooluse(burpwn_bin: &str) -> Value {
    pretooluse_entry(burpwn_bin, Agent::Copilot)
}

/// PreToolUse array element for a Claude-Code-family agent (`ClaudeCode` or
/// `Copilot`). Panics for non-PreToolUse agents — callers in [`crate::install`]
/// gate on the agent first.
pub fn pretooluse_entry_for(agent: Agent, burpwn_bin: &str) -> Value {
    debug_assert!(
        matches!(agent, Agent::ClaudeCode | Agent::Copilot),
        "pretooluse_entry_for only valid for Claude Code / Copilot"
    );
    pretooluse_entry(burpwn_bin, agent)
}

fn pretooluse_entry(burpwn_bin: &str, agent: Agent) -> Value {
    json!({
        "matcher": BASH_MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": wrap_hook_invocation(burpwn_bin, agent),
            }
        ]
    })
}

/// Cursor `hooks.json` document installing a `beforeShellExecution` hook.
///
/// Shape (confident):
/// ```json
/// { "version": 1,
///   "hooks": { "beforeShellExecution": [ { "command": "burpwn wrap-hook --agent cursor" } ] } }
/// ```
/// `failClosed` is left false (default) so a burpwn hiccup never blocks the
/// operator's shell.
pub fn cursor_hooks_json(burpwn_bin: &str) -> Value {
    json!({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [ cursor_hook_entry(burpwn_bin) ]
        }
    })
}

/// A single Cursor `beforeShellExecution` entry (used for merge into an
/// existing `hooks.json`).
pub fn cursor_hook_entry(burpwn_bin: &str) -> Value {
    json!({
        "command": wrap_hook_invocation(burpwn_bin, Agent::Cursor)
    })
}

/// Gemini CLI `hooks.BeforeTool` array element matching the shell tool.
///
/// Shape (confident):
/// ```json
/// { "matcher": "run_shell_command",
///   "hooks": [ { "type": "command", "name": "burpwn", "command": "burpwn wrap-hook --agent gemini" } ] }
/// ```
/// The Gemini built-in shell tool is `run_shell_command`; the matcher is a
/// regex, so this also tolerates close variants.
pub fn gemini_beforetool(burpwn_bin: &str) -> Value {
    json!({
        "matcher": "run_shell_command",
        "hooks": [
            {
                "type": "command",
                "name": "burpwn",
                "command": wrap_hook_invocation(burpwn_bin, Agent::Gemini),
            }
        ]
    })
}

/// Marker lines delimiting burpwn's block inside a `.clinerules` file, so it can
/// be appended/removed idempotently.
pub const CLINE_BEGIN: &str = "<!-- >>> burpwn >>> -->";
/// See [`CLINE_BEGIN`].
pub const CLINE_END: &str = "<!-- <<< burpwn <<< -->";

/// Cline/Roo `.clinerules` instruction block (rules-text, BEST-EFFORT
/// compliance — Cline is rules-driven, not hook-enforced).
///
/// If `exclude` is non-empty, the listed programs are called out as exceptions.
pub fn cline_rules_block(burpwn_bin: &str, exclude: &[String]) -> String {
    let mut s = String::new();
    s.push_str(CLINE_BEGIN);
    s.push('\n');
    s.push_str("# burpwn traffic capture\n\n");
    s.push_str(
        "Every shell/terminal command you run MUST be routed through burpwn so its \
network traffic is captured. Prefix the command exactly like:\n\n",
    );
    s.push_str(&format!("    {burpwn_bin} exec -- <your command>\n\n"));
    s.push_str(&format!(
        "Example: instead of `curl https://target`, run `{burpwn_bin} exec -- curl https://target`.\n",
    ));
    s.push_str(&format!(
        "Do not wrap a command that already begins with `{burpwn_bin} exec --`.\n",
    ));
    if !exclude.is_empty() {
        s.push_str("\nDo NOT wrap these commands (run them directly, unwrapped): ");
        s.push_str(&exclude.join(", "));
        s.push_str(".\n");
    }
    s.push_str(CLINE_END);
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIN: &str = "burpwn";

    #[test]
    fn invocation_shape() {
        assert_eq!(
            wrap_hook_invocation("burpwn", Agent::Cursor),
            "burpwn wrap-hook --agent cursor"
        );
        assert_eq!(
            wrap_hook_invocation("/opt/burpwn", Agent::Gemini),
            "/opt/burpwn wrap-hook --agent gemini"
        );
    }

    #[test]
    fn claude_pretooluse_has_matcher_and_rewrite() {
        let v = claude_code_pretooluse(BIN);
        assert_eq!(v["matcher"], "Bash");
        let cmd = v["hooks"][0]["command"].as_str().unwrap();
        assert!(cmd.contains("wrap-hook"));
        assert!(cmd.contains("--agent claude-code"));
        assert_eq!(v["hooks"][0]["type"], "command");
    }

    #[test]
    fn copilot_uses_claude_shape_with_own_slug() {
        let v = copilot_pretooluse(BIN);
        assert_eq!(v["matcher"], "Bash");
        assert!(v["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("--agent copilot"));
    }

    #[test]
    fn cursor_doc_and_entry() {
        let doc = cursor_hooks_json(BIN);
        assert_eq!(doc["version"], 1);
        let entry = &doc["hooks"]["beforeShellExecution"][0];
        assert!(entry["command"]
            .as_str()
            .unwrap()
            .contains("--agent cursor"));
        // standalone entry matches the one embedded in the doc
        assert_eq!(*entry, cursor_hook_entry(BIN));
    }

    #[test]
    fn gemini_beforetool_shape() {
        let v = gemini_beforetool(BIN);
        assert_eq!(v["matcher"], "run_shell_command");
        let h = &v["hooks"][0];
        assert_eq!(h["type"], "command");
        assert_eq!(h["name"], "burpwn");
        assert!(h["command"].as_str().unwrap().contains("--agent gemini"));
    }

    #[test]
    fn cline_rules_mentions_exec_and_markers() {
        let block = cline_rules_block(BIN, &[]);
        assert!(block.starts_with(CLINE_BEGIN));
        assert!(block.trim_end().ends_with(CLINE_END));
        assert!(block.contains("burpwn exec -- <your command>"));
        assert!(!block.contains("Do NOT wrap"));
    }

    #[test]
    fn cline_rules_lists_exclusions() {
        let block = cline_rules_block(BIN, &["git".into(), "ls".into()]);
        assert!(block.contains("Do NOT wrap"));
        assert!(block.contains("git, ls"));
    }
}
