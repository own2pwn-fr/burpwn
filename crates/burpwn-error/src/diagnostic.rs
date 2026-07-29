//! [`Diagnostic`] — one failure, rendered so a human can act on it.
//!
//! The shape is fixed on purpose, because the value of an error message is in
//! its predictability: the reader always finds the same four things in the same
//! order.
//!
//! ```text
//! error [BW-SANDBOX-003] sandbox setup failed at `netns_setup`
//!   cause : ip link add burp0 type dummy failed: Error: Unknown device type.
//!   fix   : run `burpwn doctor`: it recreates the sandbox live and names the failing step
//!         : the usual cause is a kernel without the `dummy` / `nft_redir` modules
//!   debug : ~/.local/share/burpwn/debug/2026-07-29T17-42-11-BW-SANDBOX-003.json
//!   exit  : 70
//! ```
//!
//! * **code** — stable, searchable, and it determines the exit code.
//! * **cause** — the underlying chain, outermost first; the raw text from `ip`,
//!   `nft`, SQLite… is preserved verbatim rather than paraphrased.
//! * **fix** — what to DO. Static advice from the [`ErrorCode`] catalogue, plus
//!   anything the caller could work out at runtime.
//! * **debug** — where the full machine-readable report was written.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::code::ErrorCode;

/// A fully-formed, user-facing failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// The catalogue code (drives the exit code and the static remediation).
    pub code: ErrorCode,
    /// What happened, in this specific case.
    pub message: String,
    /// The underlying error chain, outermost first. Verbatim.
    pub causes: Vec<String>,
    /// What to do about it. Seeded from the code, extendable at runtime.
    pub remediation: Vec<String>,
    /// Structured context (session, command, path…) — shown in the debug report,
    /// not in the terminal, so the message stays readable.
    pub context: BTreeMap<String, String>,
    /// Where the full debug report was written, if one was.
    pub debug_report: Option<PathBuf>,
}

impl Diagnostic {
    /// A diagnostic for `code`, describing this specific failure.
    ///
    /// The remediation starts as the code's static advice; [`Self::advise`] adds
    /// runtime-specific lines on top.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            causes: Vec::new(),
            remediation: code.remediation().iter().map(|s| s.to_string()).collect(),
            context: BTreeMap::new(),
            debug_report: None,
        }
    }

    /// Append one underlying cause (call outermost-first).
    pub fn cause(mut self, cause: impl Into<String>) -> Self {
        let cause = cause.into();
        let cause = cause.trim();
        // A cause that merely repeats the message adds noise, not information.
        if !cause.is_empty() && cause != self.message {
            self.causes.push(cause.to_string());
        }
        self
    }

    /// Append every cause of an error chain, outermost first.
    pub fn causes<I, S>(mut self, causes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for c in causes {
            self = self.cause(c);
        }
        self
    }

    /// Add a runtime-specific remediation line (kept ahead of the static ones,
    /// because it is more precise than the generic advice).
    pub fn advise(mut self, line: impl Into<String>) -> Self {
        self.remediation.insert(0, line.into());
        self
    }

    /// Replace the remediation entirely (for a failure whose live diagnosis is
    /// strictly better than the catalogue's generic advice).
    pub fn advise_only<I, S>(mut self, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.remediation = lines.into_iter().map(Into::into).collect();
        self
    }

    /// Attach a structured context key (shown in the debug report).
    pub fn context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Record where the debug report was written.
    pub fn debug_report(mut self, path: impl Into<PathBuf>) -> Self {
        self.debug_report = Some(path.into());
        self
    }

    /// The process exit code for this failure.
    pub fn exit_code(&self) -> i32 {
        self.code.exit_code()
    }

    /// The terminal rendering (no ANSI, so it survives pipes and logs).
    pub fn render(&self) -> String {
        let mut out = format!("error [{}] {}\n", self.code.id(), self.message);
        let mut field = |label: &str, lines: &[String]| {
            for (i, line) in lines.iter().enumerate() {
                let label = if i == 0 { label } else { "" };
                out.push_str(&format!("  {label:<6}: {}\n", line.trim()));
            }
        };
        field("cause", &self.causes);
        field("fix", &self.remediation);
        if let Some(path) = &self.debug_report {
            field("debug", &[path.display().to_string()]);
        }
        field("exit", &[self.exit_code().to_string()]);
        out.trim_end().to_string()
    }

    /// The machine-readable shape embedded in the `--json` envelope, in MCP tool
    /// errors, and in the debug report.
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code.id(),
            "class": self.code.class().as_str(),
            "title": self.code.title(),
            "message": self.message,
            "causes": self.causes,
            "remediation": self.remediation,
            "context": self.context,
            "exit_code": self.exit_code(),
            "debug_report": self.debug_report.as_ref().map(|p| p.display().to_string()),
        })
    }

    /// The single-line form used where only one string fits (the legacy
    /// `error` field of the JSON envelope, MCP error text, log lines).
    pub fn one_line(&self) -> String {
        let mut s = format!("[{}] {}", self.code.id(), self.message);
        if let Some(first) = self.causes.first() {
            s.push_str(&format!(": {first}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> Diagnostic {
        Diagnostic::new(
            ErrorCode::SandboxNetnsSetup,
            "sandbox setup failed at `netns_setup`",
        )
        .cause("ip link add burp0 type dummy failed: Error: Unknown device type.")
        .context("session", "engagement-1")
    }

    #[test]
    fn render_has_the_documented_shape() {
        let d = sandbox().debug_report("/tmp/report.json");
        let text = d.render();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "error [BW-SANDBOX-003] sandbox setup failed at `netns_setup`"
        );
        assert!(lines[1].starts_with("  cause : ip link add burp0"));
        assert!(text.contains("  fix   : "));
        assert!(text.contains("  debug : /tmp/report.json"));
        assert!(text.trim_end().ends_with("  exit  : 70"));
    }

    // Multi-line fields must stay aligned under their label, otherwise a long
    // remediation list is unreadable.
    #[test]
    fn extra_lines_of_a_field_are_indented_without_repeating_the_label() {
        let d = Diagnostic::new(ErrorCode::SandboxNetnsSetup, "boom");
        let text = d.render();
        let fix_lines: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("  fix") || l.starts_with("        :"))
            .collect();
        assert!(fix_lines.len() >= 2, "{text}");
        assert_eq!(fix_lines.iter().filter(|l| l.contains("fix")).count(), 1);
    }

    #[test]
    fn context_is_not_in_the_terminal_output_but_is_in_the_json() {
        let d = sandbox();
        assert!(!d.render().contains("engagement-1"));
        assert_eq!(d.to_json()["context"]["session"], json!("engagement-1"));
    }

    #[test]
    fn a_cause_that_repeats_the_message_is_dropped() {
        let d = Diagnostic::new(ErrorCode::Internal, "same").cause("same");
        assert!(d.causes.is_empty());
    }

    #[test]
    fn empty_causes_are_dropped() {
        let d = Diagnostic::new(ErrorCode::Internal, "x").cause("   ");
        assert!(d.causes.is_empty());
    }

    #[test]
    fn causes_keep_their_order_outermost_first() {
        let d = Diagnostic::new(ErrorCode::Internal, "x").causes(["outer", "inner"]);
        assert_eq!(d.causes, vec!["outer", "inner"]);
    }

    // Runtime advice is more specific than the catalogue's, so it must be read
    // first.
    #[test]
    fn runtime_advice_comes_before_the_static_advice() {
        let d = Diagnostic::new(ErrorCode::SandboxNetnsSetup, "x").advise("live: dummy is missing");
        assert_eq!(d.remediation[0], "live: dummy is missing");
        assert!(d.remediation.len() > 1);
    }

    #[test]
    fn advise_only_replaces_the_catalogue_advice() {
        let d = Diagnostic::new(ErrorCode::SandboxNetnsSetup, "x").advise_only(["just this"]);
        assert_eq!(d.remediation, vec!["just this"]);
    }

    #[test]
    fn json_carries_the_full_contract() {
        let v = sandbox().debug_report("/tmp/r.json").to_json();
        assert_eq!(v["code"], json!("BW-SANDBOX-003"));
        assert_eq!(v["class"], json!("SANDBOX"));
        assert_eq!(v["exit_code"], json!(70));
        assert_eq!(v["debug_report"], json!("/tmp/r.json"));
        assert!(v["title"].as_str().unwrap().contains("network"));
        assert!(!v["remediation"].as_array().unwrap().is_empty());
    }

    #[test]
    fn one_line_carries_code_message_and_first_cause() {
        let s = sandbox().one_line();
        assert!(s.starts_with("[BW-SANDBOX-003] sandbox setup failed"));
        assert!(s.contains("Unknown device type"));
    }

    #[test]
    fn exit_code_comes_from_the_class() {
        assert_eq!(sandbox().exit_code(), 70);
        assert_eq!(
            Diagnostic::new(ErrorCode::InputNoSuchFlow, "x").exit_code(),
            75
        );
    }

    #[test]
    fn diagnostic_round_trips_through_serde() {
        let d = sandbox().debug_report("/tmp/r.json");
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Diagnostic>(&json).unwrap(), d);
    }
}
