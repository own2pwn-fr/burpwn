//! `burpwn wrap-hook`: the stdin filter the installed agent hooks pipe their
//! tool-input JSON through. It reads a tool-input object on stdin, and if it is
//! a shell/Bash tool call whose command [`should_wrap`], rewrites the command to
//! `burpwn exec -- <cmd>` and emits the hook-response JSON on stdout.
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
/// with `burpwn exec -- <cmd>`. Everything else is echoed unchanged.
pub fn process(input: &str, cfg: &WrapConfig) -> String {
    let Ok(mut v) = serde_json::from_str::<Value>(input) else {
        // Not JSON we understand — pass through verbatim.
        return input.to_string();
    };

    if rewrite_in_place(&mut v, cfg) {
        serde_json::to_string(&v).unwrap_or_else(|_| input.to_string())
    } else {
        // Re-serialize (normalises whitespace) but semantically unchanged.
        serde_json::to_string(&v).unwrap_or_else(|_| input.to_string())
    }
}

/// Locate a command field and rewrite it. Returns whether a rewrite happened.
fn rewrite_in_place(v: &mut Value, cfg: &WrapConfig) -> bool {
    for ptr in ["/tool_input/command", "/params/command", "/command"] {
        if let Some(slot) = v.pointer_mut(ptr) {
            if let Some(cmd) = slot.as_str() {
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
            "burpwn exec -- curl https://example.com"
        );
    }

    #[test]
    fn rewrites_generic_command() {
        let cfg = WrapConfig::default();
        let input = json!({ "command": "nmap -sV target" }).to_string();
        let out: Value = serde_json::from_str(&process(&input, &cfg)).unwrap();
        assert_eq!(out["command"], "burpwn exec -- nmap -sV target");
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
