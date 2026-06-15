//! `burpwn wrap-hook`: the stdin filter the installed agent hooks pipe their
//! tool-input JSON through. It reads a tool-input object on stdin, and if it is
//! a shell/Bash tool call whose command [`should_wrap`], rewrites the command to
//! `burpwn exec -- sh -c '<cmd>'` and emits the hook-response JSON **in that
//! agent's dialect** on stdout.
//!
//! ## Why the agent slug is load-bearing (not advisory)
//!
//! Each agent applies a hook's stdout differently. A hook that simply *echoes a
//! modified `tool_input` blob* does NOT rewrite the command for Claude Code: the
//! harness ignores a raw `{"tool_input":{…}}` on stdout and runs the ORIGINAL
//! command, so capture silently never happens. To actually rewrite, the hook
//! must emit the agent's documented response envelope:
//!
//! * **Claude Code / Copilot** (`PreToolUse`): a `hookSpecificOutput` object with
//!   `hookEventName: "PreToolUse"`, `permissionDecision: "allow"`, and
//!   `updatedInput` carrying the modified tool input (see [`claude_response`]).
//!   `updatedInput` is only honoured when `permissionDecision` is `allow`.
//! * **Gemini CLI** (`BeforeTool`): a `{"decision":"allow","hookSpecificOutput":
//!   {"tool_input":{…}}}` envelope — it likewise *can* rewrite (see
//!   [`gemini_response`]).
//! * **Cursor** (`beforeShellExecution`): CANNOT rewrite a command — only allow /
//!   deny / ask. So burpwn can't transparently wrap there; we emit a non-blocking
//!   allow + an `agentMessage` nudge instead (advisory capture, see
//!   [`cursor_response`]). Cline is rules-text only and uses the legacy echo.
//!
//! When no rewrite is warranted (command excluded, already wrapped, or no command
//! field present), we emit **nothing** and exit 0 — the documented "allow normal
//! flow unchanged" no-op. This module never blocks a command (it never exits 2).
//!
//! The rewrite *decision* ([`should_wrap`]) and the rewrite *string*
//! ([`rewrite_command`]) come from `burpwn-wrap`; this module only wires up the
//! per-agent stdin/stdout JSON dialects.

use serde_json::{json, Value};

use burpwn_wrap::{rewrite_command, should_wrap, Agent, WrapConfig};

/// Process one tool-input JSON document with no agent dialect — the legacy
/// shape-detecting echo path (used by the generic fallback and tests).
pub fn process(input: &str, cfg: &WrapConfig) -> String {
    process_for(None, input, cfg)
}

/// Process a tool-input document for a specific `agent` slug (as passed by the
/// installed hook via `burpwn wrap-hook --agent <slug>`), emitting that agent's
/// hook-response dialect on stdout.
///
/// * Claude Code / Copilot → the `PreToolUse` `hookSpecificOutput` envelope.
/// * Any other / unknown / no agent → the legacy shape-detecting in-place echo.
pub fn process_for(agent: Option<&str>, input: &str, cfg: &WrapConfig) -> String {
    let Ok(v) = serde_json::from_str::<Value>(input) else {
        // Not JSON we understand. For a known programmatic-hook agent the safe
        // no-op is empty stdout (allow normal flow); for the legacy path we keep
        // the verbatim pass-through.
        return match agent.and_then(Agent::from_slug) {
            Some(Agent::ClaudeCode | Agent::Copilot) => String::new(),
            _ => input.to_string(),
        };
    };

    match agent.and_then(Agent::from_slug) {
        Some(Agent::ClaudeCode | Agent::Copilot) => claude_response(&v, cfg),
        Some(Agent::Gemini) => gemini_response(&v, cfg),
        Some(Agent::Cursor) => cursor_response(&v, cfg),
        // Cline (rules-text, no programmatic hook) / unknown / none: legacy
        // in-place echo.
        _ => legacy_echo(v, cfg),
    }
}

/// Build the Claude-Code / Copilot `PreToolUse` response.
///
/// Emits, only when a rewrite is warranted:
/// ```json
/// { "hookSpecificOutput": {
///     "hookEventName": "PreToolUse",
///     "permissionDecision": "allow",
///     "updatedInput": { …original tool_input with `command` replaced… } } }
/// ```
/// `updatedInput` is the FULL original `tool_input` object with only `command`
/// swapped, so sibling fields (`description`, `timeout`, …) are preserved. When
/// no rewrite is warranted we return an empty string → no stdout → the tool runs
/// unmodified (the documented allow-normal-flow no-op).
fn claude_response(v: &Value, cfg: &WrapConfig) -> String {
    let Some(new_cmd) = rewritten_command_at(v, "/tool_input/command", cfg) else {
        return String::new();
    };
    let mut updated = v.get("tool_input").cloned().unwrap_or_else(|| json!({}));
    // `tool_input` is an object for the Bash tool; guard defensively.
    if let Some(obj) = updated.as_object_mut() {
        obj.insert("command".to_string(), Value::String(new_cmd));
    } else {
        updated = json!({ "command": new_cmd });
    }
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated,
        }
    })
    .to_string()
}

/// Build the Gemini CLI `BeforeTool` (`run_shell_command`) response.
///
/// Gemini *can* rewrite the command: it honours
/// ```json
/// { "decision": "allow",
///   "hookSpecificOutput": { "tool_input": { "command": "…" } } }
/// ```
/// where `tool_input` replaces the original. We send the full original
/// `tool_input` with `command` swapped (preserving sibling fields). No rewrite →
/// empty stdout → Gemini runs the command unmodified.
///
/// Confidence: based on the documented Gemini hook contract; if the exact shape
/// drifts, the failure mode is fail-SAFE — Gemini ignores an unrecognised body
/// and runs the original command (no capture), never a hard block.
fn gemini_response(v: &Value, cfg: &WrapConfig) -> String {
    let Some(new_cmd) = rewritten_command_at(v, "/tool_input/command", cfg) else {
        return String::new();
    };
    let mut updated = v.get("tool_input").cloned().unwrap_or_else(|| json!({}));
    if let Some(obj) = updated.as_object_mut() {
        obj.insert("command".to_string(), Value::String(new_cmd));
    } else {
        updated = json!({ "command": new_cmd });
    }
    json!({
        "decision": "allow",
        "hookSpecificOutput": { "tool_input": updated },
    })
    .to_string()
}

/// Build the Cursor `beforeShellExecution` response.
///
/// IMPORTANT: Cursor's `beforeShellExecution` hook CANNOT rewrite the command —
/// it only allows / denies / asks. So burpwn cannot transparently wrap commands
/// under Cursor the way it does for Claude Code / Gemini. We therefore emit a
/// non-blocking *allow* with an `agentMessage` nudge so the operator/agent re-runs
/// network commands through `burpwn exec` themselves (the standing SKILL.md rule).
/// We never deny: a hard block on every shell command would be far worse than an
/// un-captured one. Cursor capture is thus advisory (model-followed), like Cline.
///
/// The nudge is emitted only when a wrap WOULD have been warranted (network-ish
/// command, not excluded, not already wrapped); otherwise empty stdout (clean
/// allow, no message).
fn cursor_response(v: &Value, cfg: &WrapConfig) -> String {
    // Cursor sends the command at the top level (`.command`).
    if rewritten_command_at(v, "/command", cfg).is_none() {
        return String::new();
    }
    json!({
        "continue": true,
        "permission": "allow",
        "agentMessage": "burpwn: Cursor cannot auto-wrap commands. Re-run network \
    commands through `burpwn exec -- sh -c '<command>'` so their traffic is captured.",
    })
    .to_string()
}

/// Legacy shape-detecting echo: rewrite the first known command field in place
/// and echo the whole (possibly-rewritten) document. Used by the generic
/// fallback and by agents whose dedicated envelope is not yet wired.
fn legacy_echo(mut v: Value, cfg: &WrapConfig) -> String {
    rewrite_in_place(&mut v, cfg);
    serde_json::to_string(&v).unwrap_or_default()
}

/// Find a command string at JSON pointer `ptr`, and return its `burpwn exec`
/// rewrite iff one is warranted (parses as a string, not already wrapped, and
/// [`should_wrap`]). `None` means "leave it alone".
fn rewritten_command_at(v: &Value, ptr: &str, cfg: &WrapConfig) -> Option<String> {
    let cmd = v.pointer(ptr)?.as_str()?;
    if already_wrapped(cmd) {
        return None;
    }
    should_wrap(cmd, cfg).then(|| rewrite_command(cmd))
}

/// Locate a command field and rewrite it. Returns whether a rewrite happened.
fn rewrite_in_place(v: &mut Value, cfg: &WrapConfig) -> bool {
    for ptr in ["/tool_input/command", "/params/command", "/command"] {
        if let Some(slot) = v.pointer_mut(ptr) {
            if let Some(cmd) = slot.as_str() {
                // Never double-wrap a command already routed through burpwn (the
                // hook may fire on a command we ourselves produced, or the user
                // typed `burpwn exec` explicitly).
                if already_wrapped(cmd) {
                    return false;
                }
                if should_wrap(cmd, cfg) {
                    *slot = Value::String(rewrite_command(cmd));
                    return true;
                }
                return false;
            }
        }
    }
    false
}

/// True if `cmd` already invokes `burpwn exec` (so wrapping it again would give
/// `burpwn exec -- … burpwn exec -- …`).
///
/// The check is anchored to the PROGRAM position: we skip leading `VAR=val`
/// assignments and a benign wrapper prefix (`sudo`/`env`/`command`/`nice`/
/// `nohup`), then require the program token to be `burpwn` (or a path ending
/// `/burpwn`) immediately followed by `exec`. Scanning arbitrary token pairs
/// would false-positive on a command that merely MENTIONS "burpwn exec" as an
/// argument (`grep "burpwn exec" f`, `curl evil --data "burpwn exec"`) and
/// SILENTLY SKIP CAPTURE — far worse than the harmless double-wrap a false
/// negative produces (a nested `sh -c` still captures). A leading `bw ` (the
/// global-hook helper) is also recognised.
fn already_wrapped(cmd: &str) -> bool {
    let c = cmd.trim_start();
    if c == "bw" || c.starts_with("bw ") || c.starts_with("bw\t") {
        return true;
    }
    let mut it = c.split_whitespace().peekable();
    while let Some(&t) = it.peek() {
        if is_env_assignment(t) || matches!(t, "sudo" | "env" | "command" | "nice" | "nohup") {
            it.next();
        } else {
            break;
        }
    }
    matches!(it.next(), Some(p) if is_burpwn_token(p)) && it.next() == Some("exec")
}

/// A `VAR=value` shell assignment prefix (the key is a valid env-var name).
fn is_env_assignment(tok: &str) -> bool {
    match tok.split_once('=') {
        Some((k, _)) => !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        None => false,
    }
}

/// Is `tok` the `burpwn` program — either bare or as a path ending `/burpwn`?
fn is_burpwn_token(tok: &str) -> bool {
    tok == "burpwn" || tok.rsplit('/').next() == Some("burpwn")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rewrites_claude_bash_tool_input() {
        let cfg = WrapConfig::default();
        let input = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "curl https://example.com" }
        })
        .to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(
            out["tool_input"]["command"],
            "burpwn exec -- sh -c 'curl https://example.com'"
        );
    }

    #[test]
    fn rewrites_generic_command() {
        let cfg = WrapConfig::default();
        let input = json!({ "command": "nmap -sV target" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(out["command"], "burpwn exec -- sh -c 'nmap -sV target'");
    }

    #[test]
    fn rewrites_whole_compound_line() {
        // Both segments of the compound must end up inside one sandboxed `sh -c`.
        let cfg = WrapConfig::default();
        let input = json!({ "command": "curl https://a && curl https://evil" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(
            out["command"],
            "burpwn exec -- sh -c 'curl https://a && curl https://evil'"
        );
    }

    #[test]
    fn already_wrapped_command_is_not_double_wrapped() {
        let cfg = WrapConfig::default();
        // The hook already emits the `sh -c` form; firing on it must be a no-op.
        let input = json!({ "command": "burpwn exec -- sh -c 'curl https://x'" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(out["command"], "burpwn exec -- sh -c 'curl https://x'");
    }

    #[test]
    fn sudo_burpwn_exec_is_recognised_as_wrapped() {
        // `sudo burpwn exec -- …` (and a path-qualified burpwn) must not be
        // re-wrapped: the burpwn token is not the first token of the line.
        let cfg = WrapConfig::default();
        let input = json!({ "command": "sudo burpwn exec -- sh -c 'id'" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(out["command"], "sudo burpwn exec -- sh -c 'id'");

        let input =
            json!({ "command": "env FOO=1 /usr/local/bin/burpwn exec -- sh -c 'id'" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(
            out["command"],
            "env FOO=1 /usr/local/bin/burpwn exec -- sh -c 'id'"
        );
    }

    #[test]
    fn already_wrapped_unit() {
        assert!(already_wrapped("burpwn exec -- sh -c 'id'"));
        assert!(already_wrapped("  burpwn exec -- x"));
        assert!(already_wrapped("sudo burpwn exec -- x"));
        assert!(already_wrapped("/usr/local/bin/burpwn exec -- x"));
        assert!(already_wrapped("env A=1 /opt/burpwn exec -- x"));
        assert!(already_wrapped("bw curl https://x"));
        assert!(already_wrapped("bw"));
        // Not wrapped:
        assert!(!already_wrapped("curl https://x"));
        assert!(!already_wrapped("burpwn req list")); // burpwn but not `exec`
        assert!(!already_wrapped("burpwnexec foo")); // not the burpwn token
        assert!(!already_wrapped("bwrap --bind /"));
        // CRITICAL: a command that merely MENTIONS `burpwn exec` as an argument
        // must NOT be treated as wrapped — else it silently skips capture.
        assert!(!already_wrapped("grep \"burpwn exec\" notes.txt"));
        assert!(!already_wrapped("echo burpwn exec"));
        assert!(!already_wrapped("curl https://evil --data 'burpwn exec'"));
        assert!(!already_wrapped("git commit -m 'burpwn exec fix'"));
    }

    #[test]
    fn command_mentioning_burpwn_exec_is_still_captured() {
        let cfg = WrapConfig::default();
        let input = json!({ "command": "grep \"burpwn exec\" notes.txt" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        // It must be wrapped (captured), not passed through unchanged.
        assert_eq!(
            out["command"],
            "burpwn exec -- sh -c 'grep \"burpwn exec\" notes.txt'"
        );
    }

    // --- Claude Code / Copilot PreToolUse envelope ------------------------

    #[test]
    fn claude_code_emits_pretooluse_envelope_with_updated_input() {
        // The crux of the "PreTool install doesn't work" bug: Claude Code only
        // applies a rewrite if the hook emits the `hookSpecificOutput` envelope
        // with `permissionDecision: allow` + `updatedInput`. A raw echo is
        // ignored and the ORIGINAL command runs (no capture).
        let cfg = WrapConfig::default();
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "curl https://target", "description": "fetch" }
        })
        .to_string();
        let out: Value =
            serde_json::from_str(&process_for(Some("claude-code"), &input, &cfg)).unwrap();
        let hso = &out["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PreToolUse");
        assert_eq!(hso["permissionDecision"], "allow");
        assert_eq!(
            hso["updatedInput"]["command"],
            "burpwn exec -- sh -c 'curl https://target'"
        );
        // sibling fields of tool_input survive the rewrite
        assert_eq!(hso["updatedInput"]["description"], "fetch");
        // the raw tool_input must NOT be echoed at top level
        assert!(out.get("tool_input").is_none());
    }

    #[test]
    fn copilot_uses_same_pretooluse_envelope() {
        let cfg = WrapConfig::default();
        let input = json!({ "tool_input": { "command": "nmap t" } }).to_string();
        let out: Value = serde_json::from_str(&process_for(Some("copilot"), &input, &cfg)).unwrap();
        assert_eq!(
            out["hookSpecificOutput"]["updatedInput"]["command"],
            "burpwn exec -- sh -c 'nmap t'"
        );
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "allow");
    }

    #[test]
    fn claude_no_rewrite_emits_empty_noop() {
        let cfg = WrapConfig::default();
        // already wrapped → no-op (empty stdout = allow normal flow)
        let wrapped =
            json!({ "tool_input": { "command": "burpwn exec -- sh -c 'id'" } }).to_string();
        assert_eq!(process_for(Some("claude-code"), &wrapped, &cfg), "");
        // excluded command → no-op
        let cfg_excl = WrapConfig {
            exclude_commands: vec!["git".into()],
        };
        let git = json!({ "tool_input": { "command": "git push" } }).to_string();
        assert_eq!(process_for(Some("claude-code"), &git, &cfg_excl), "");
        // no command field → no-op
        let nocmd = json!({ "tool_input": { "description": "x" } }).to_string();
        assert_eq!(process_for(Some("claude-code"), &nocmd, &cfg), "");
        // unparseable stdin for a Claude hook → empty no-op (never block)
        assert_eq!(process_for(Some("claude-code"), "not json {", &cfg), "");
    }

    #[test]
    fn unknown_agent_falls_back_to_legacy_echo() {
        let cfg = WrapConfig::default();
        let input = json!({ "tool_input": { "command": "nmap t" } }).to_string();
        // Cline (rules-text) and unknown slugs keep the in-place echo behaviour.
        for slug in ["cline", "totally-unknown"] {
            let out: Value = serde_json::from_str(&process_for(Some(slug), &input, &cfg)).unwrap();
            assert_eq!(
                out["tool_input"]["command"], "burpwn exec -- sh -c 'nmap t'",
                "slug {slug}"
            );
        }
    }

    // --- Gemini BeforeTool envelope ---------------------------------------

    #[test]
    fn gemini_emits_decision_allow_with_modified_tool_input() {
        let cfg = WrapConfig::default();
        let input = json!({
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": { "command": "curl https://target", "description": "x" }
        })
        .to_string();
        let out: Value = serde_json::from_str(&process_for(Some("gemini"), &input, &cfg)).unwrap();
        assert_eq!(out["decision"], "allow");
        assert_eq!(
            out["hookSpecificOutput"]["tool_input"]["command"],
            "burpwn exec -- sh -c 'curl https://target'"
        );
        // sibling fields preserved
        assert_eq!(out["hookSpecificOutput"]["tool_input"]["description"], "x");
    }

    #[test]
    fn gemini_no_rewrite_is_empty_noop() {
        let cfg = WrapConfig::default();
        let wrapped =
            json!({ "tool_input": { "command": "burpwn exec -- sh -c 'id'" } }).to_string();
        assert_eq!(process_for(Some("gemini"), &wrapped, &cfg), "");
    }

    // --- Cursor beforeShellExecution (cannot rewrite) ---------------------

    #[test]
    fn cursor_emits_non_blocking_allow_with_nudge() {
        // Cursor can't rewrite, so we never deny — we allow + nudge. The command
        // lives at the top level `.command` in Cursor's stdin schema.
        let cfg = WrapConfig::default();
        let input = json!({
            "hook_event_name": "beforeShellExecution",
            "command": "curl https://target"
        })
        .to_string();
        let out: Value = serde_json::from_str(&process_for(Some("cursor"), &input, &cfg)).unwrap();
        assert_eq!(out["continue"], true);
        assert_eq!(out["permission"], "allow");
        assert!(out["agentMessage"]
            .as_str()
            .unwrap()
            .contains("burpwn exec"));
        // crucially: never a deny
        assert_ne!(out["permission"], "deny");
    }

    #[test]
    fn cursor_no_nudge_when_already_wrapped_or_excluded() {
        let cfg = WrapConfig::default();
        let wrapped = json!({ "command": "burpwn exec -- sh -c 'id'" }).to_string();
        assert_eq!(process_for(Some("cursor"), &wrapped, &cfg), "");
        let cfg_excl = WrapConfig {
            exclude_commands: vec!["git".into()],
        };
        let git = json!({ "command": "git status" }).to_string();
        assert_eq!(process_for(Some("cursor"), &git, &cfg_excl), "");
    }

    #[test]
    fn excluded_command_passes_through() {
        let cfg = WrapConfig {
            exclude_commands: vec!["git".into()],
        };
        let input = json!({ "command": "git push" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(out["command"], "git push");
    }

    #[test]
    fn non_json_passes_through_verbatim() {
        let cfg = WrapConfig::default();
        let raw = "this is not json {";
        assert_eq!(process(raw, &cfg), raw);
    }

    #[test]
    fn unknown_shape_is_echoed() {
        let cfg = WrapConfig::default();
        let input = json!({ "something": "else" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(out["something"], "else");
    }
}
