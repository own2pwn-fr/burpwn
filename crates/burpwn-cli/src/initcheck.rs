//! `burpwn init --check` — hook self-verification.
//!
//! `burpwn`'s command capture FAILS OPEN: if an agent's real hook contract
//! differs from the envelope [`crate::wrap_hook`] assumes, the harness silently
//! runs the ORIGINAL command and nothing is captured — with no error. The
//! Copilot / Gemini / Cursor / Cline dialects are explicitly best-effort, so this
//! uncertainty is real.
//!
//! `--check` de-risks it by driving a SYNTHETIC network command through the very
//! same `wrap-hook` code path the installed hook uses, then asserting the emitted
//! envelope actually REWRITES the command to route through `burpwn exec` and has
//! the shape that agent requires to apply a rewrite. Per-agent verdict:
//!
//! * **PASS** — a rewrite-capable agent (Claude Code / Copilot / Gemini) emitted
//!   a well-formed envelope whose command routes through `burpwn exec`.
//! * **FAIL** — a rewrite-capable agent did NOT rewrite (capture would silently
//!   never happen). Any FAIL makes `init --check` exit non-zero.
//! * **ADVISORY** — Cursor / Cline can only *advise* (Cursor's hook cannot
//!   rewrite a command; Cline is rules-text). They are never a FAIL; we only
//!   confirm the advisory nudge is emitted.

use serde_json::Value;

use burpwn_wrap::{Agent, WrapConfig};

use crate::wrap_hook;

/// The synthetic, clearly network-facing command fed through each hook. It must
/// be something [`burpwn_wrap::should_wrap`] wraps by default (not excluded).
pub const SYNTHETIC_COMMAND: &str = "curl https://check.burpwn.test/health";

/// A single agent's verification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The agent rewrote the command through `burpwn exec` correctly.
    Pass,
    /// A rewrite-capable agent failed to rewrite (capture would silently fail).
    Fail,
    /// The agent can only advise (Cursor / Cline); not a failure.
    Advisory,
}

impl Verdict {
    /// Stable machine string.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Advisory => "ADVISORY",
        }
    }
}

/// The result of checking one agent.
#[derive(Debug, Clone)]
pub struct AgentCheck {
    /// Agent slug.
    pub agent: String,
    /// Verdict.
    pub verdict: Verdict,
    /// Human-readable explanation.
    pub detail: String,
    /// The rewritten command extracted from the envelope, if any.
    pub rewritten: Option<String>,
}

/// Whether this agent's hook is *expected* to rewrite the command (vs. only
/// advise). A FAIL is only meaningful for rewrite-capable agents.
pub fn is_rewrite_capable(agent: Agent) -> bool {
    matches!(agent, Agent::ClaudeCode | Agent::Copilot | Agent::Gemini)
}

/// Build the synthetic stdin tool-input document in `agent`'s dialect. Mirrors
/// what the real harness pipes into `burpwn wrap-hook --agent <slug>`.
pub fn synthetic_input(agent: Agent) -> String {
    match agent {
        // Cursor sends the command at the top level.
        Agent::Cursor => serde_json::json!({
            "hook_event_name": "beforeShellExecution",
            "command": SYNTHETIC_COMMAND,
        })
        .to_string(),
        // Everyone else uses the `tool_input.command` shape.
        _ => serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": SYNTHETIC_COMMAND, "description": "check" },
        })
        .to_string(),
    }
}

/// Where the rewritten command lands in each agent's response envelope. Returns
/// the command string if the envelope is well-formed for a rewrite.
fn rewritten_command(agent: Agent, out: &Value) -> Option<String> {
    match agent {
        Agent::ClaudeCode | Agent::Copilot => {
            let hso = out.get("hookSpecificOutput")?;
            // The rewrite is only honoured when the decision is `allow`.
            if hso.get("permissionDecision")?.as_str()? != "allow" {
                return None;
            }
            if hso.get("hookEventName")?.as_str()? != "PreToolUse" {
                return None;
            }
            hso.pointer("/updatedInput/command")?.as_str().map(Into::into)
        }
        Agent::Gemini => {
            if out.get("decision")?.as_str()? != "allow" {
                return None;
            }
            out.pointer("/hookSpecificOutput/tool_input/command")?
                .as_str()
                .map(Into::into)
        }
        // Legacy echo shape (Cline / generic): command rewritten in place.
        Agent::Cline => out.pointer("/tool_input/command")?.as_str().map(Into::into),
        // Cursor cannot rewrite; handled separately.
        Agent::Cursor => None,
    }
}

/// Verify one agent by driving the synthetic input through its `wrap-hook` path.
///
/// Uses a DEFAULT [`WrapConfig`] deliberately: the check validates the envelope
/// *mechanics*, not the operator's `exclude_commands` (an excluded `curl` would
/// otherwise read as a spurious FAIL).
pub fn check_agent(agent: Agent) -> AgentCheck {
    let cfg = WrapConfig::default();
    let input = synthetic_input(agent);
    let output = wrap_hook::process_for(Some(agent.slug()), &input, &cfg);

    // Cursor is advisory: it emits an allow + a nudge, never a rewrite.
    if let Agent::Cursor = agent {
        let advises = serde_json::from_str::<Value>(&output)
            .ok()
            .and_then(|v| {
                v.get("agentMessage")
                    .and_then(Value::as_str)
                    .map(|m| m.contains("burpwn exec"))
            })
            .unwrap_or(false);
        return AgentCheck {
            agent: agent.slug().to_string(),
            verdict: Verdict::Advisory,
            detail: if advises {
                "Cursor cannot rewrite commands; advisory nudge is emitted".into()
            } else {
                "Cursor cannot rewrite commands (advisory only)".into()
            },
            rewritten: None,
        };
    }

    let parsed: Option<Value> = serde_json::from_str(&output).ok();
    let rewritten = parsed.as_ref().and_then(|v| rewritten_command(agent, v));
    let routed = rewritten
        .as_deref()
        .map(|c| c.trim_start().starts_with("burpwn exec"))
        .unwrap_or(false);

    if is_rewrite_capable(agent) {
        if routed {
            AgentCheck {
                agent: agent.slug().to_string(),
                verdict: Verdict::Pass,
                detail: "command rewritten to route through `burpwn exec`".into(),
                rewritten,
            }
        } else {
            AgentCheck {
                agent: agent.slug().to_string(),
                verdict: Verdict::Fail,
                detail: format!(
                    "envelope did not rewrite the command through `burpwn exec` \
                     (capture would silently fail). Emitted: {}",
                    truncate(&output, 200)
                ),
                rewritten,
            }
        }
    } else {
        // Cline: rules-text, advisory. Report whether the echo rewrote (info).
        AgentCheck {
            agent: agent.slug().to_string(),
            verdict: Verdict::Advisory,
            detail: if routed {
                "Cline is rules-text (advisory); echo rewrite verified".into()
            } else {
                "Cline is rules-text (advisory)".into()
            },
            rewritten,
        }
    }
}

/// Check a set of agents.
pub fn check_agents(agents: &[Agent]) -> Vec<AgentCheck> {
    agents.iter().copied().map(check_agent).collect()
}

/// Whether any rewrite-capable agent FAILED (drives the non-zero exit).
pub fn any_failure(reports: &[AgentCheck]) -> bool {
    reports.iter().any(|r| r.verdict == Verdict::Fail)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_and_gemini_pass_the_rewrite_envelope() {
        for agent in [Agent::ClaudeCode, Agent::Copilot, Agent::Gemini] {
            let r = check_agent(agent);
            assert_eq!(r.verdict, Verdict::Pass, "{}: {}", r.agent, r.detail);
            let cmd = r.rewritten.expect("a rewritten command");
            assert!(
                cmd.starts_with("burpwn exec -- sh -c 'curl https://check.burpwn.test"),
                "{}: {cmd}",
                r.agent
            );
        }
    }

    #[test]
    fn cursor_and_cline_are_advisory_not_fail() {
        let cursor = check_agent(Agent::Cursor);
        assert_eq!(cursor.verdict, Verdict::Advisory);
        assert!(cursor.detail.contains("advisory") || cursor.detail.contains("nudge"));

        let cline = check_agent(Agent::Cline);
        assert_eq!(cline.verdict, Verdict::Advisory);
    }

    #[test]
    fn a_fail_drives_nonzero_exit() {
        // All-known-agents check on correct code has no FAIL.
        let reports = check_agents(&Agent::all());
        assert!(!any_failure(&reports), "correct code must not FAIL any agent");
        assert!(reports
            .iter()
            .any(|r| r.verdict == Verdict::Pass && r.agent == "claude-code"));
        assert!(reports
            .iter()
            .any(|r| r.verdict == Verdict::Advisory && r.agent == "cursor"));

        // A synthetic FAIL report flips the aggregate.
        let mut with_fail = reports;
        with_fail.push(AgentCheck {
            agent: "broken".into(),
            verdict: Verdict::Fail,
            detail: "x".into(),
            rewritten: None,
        });
        assert!(any_failure(&with_fail));
    }
}
