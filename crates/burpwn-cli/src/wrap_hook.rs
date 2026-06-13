//! `burpwn wrap-hook`: the stdin filter the installed agent hooks pipe their
//! tool-input JSON through. It reads a tool-input object on stdin, and if it is
//! a shell/Bash tool call whose command [`should_wrap`], rewrites the command to
//! `burpwn exec -- sh -c '<cmd>'` and emits the hook-response JSON on stdout.
//!
//! It is **robust to unknown shapes**: anything it can't parse, or any tool it
//! doesn't recognise, is passed through unchanged (echoed) so it never breaks an
//! agent. The exact agent hook envelope varies (Claude Code PreToolUse, Cursor,
//! Gemini…); we detect the common shapes generically.
//!
//! The rewrite *decision* ([`should_wrap`]) and the rewrite *string*
//! ([`rewrite_command`]) come from `burpwn-wrap`; this module only wires up the
//! per-agent stdin/stdout JSON dialects.

use serde_json::Value;

use burpwn_wrap::{rewrite_command, should_wrap, WrapConfig};

/// Process one tool-input JSON document, returning the JSON to emit on stdout.
///
/// Recognised command locations (first hit wins):
/// - `.tool_input.command` (Claude Code Bash PreToolUse)
/// - `.params.command` / `.command` (generic / shell)
///
/// When found and `should_wrap` is true, the command string is replaced in place
/// with `burpwn exec -- sh -c '<cmd>'`. Everything else is echoed unchanged.
pub fn process(input: &str, cfg: &WrapConfig) -> String {
    process_for(None, input, cfg)
}

/// Like [`process`] but with the originating `agent` slug (as passed by the
/// installed hook via `burpwn wrap-hook --agent <slug>`). The command field is
/// detected by shape, which covers every supported agent, so `agent` is
/// currently advisory — it is accepted so the installed hooks invoke this binary
/// successfully and stays available for future per-agent output dialects.
pub fn process_for(_agent: Option<&str>, input: &str, cfg: &WrapConfig) -> String {
    let Ok(mut v) = serde_json::from_str::<Value>(input) else {
        // Not JSON we understand — pass through verbatim.
        return input.to_string();
    };
    rewrite_in_place(&mut v, cfg);
    serde_json::to_string(&v).unwrap_or_else(|_| input.to_string())
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

    #[test]
    fn process_for_accepts_an_agent_slug() {
        let cfg = WrapConfig::default();
        let input = json!({ "tool_input": { "command": "nmap t" } }).to_string();
        let out: Value =
            serde_json::from_str(&process_for(Some("claude-code"), &input, &cfg)).unwrap();
        assert_eq!(
            out["tool_input"]["command"],
            "burpwn exec -- sh -c 'nmap t'"
        );
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
