//! Supported AI agents + best-effort presence detection.
//!
//! Each agent has a config location under the user's home where burpwn installs
//! its command-rewrite hook. Detection probes for that location so `burpwn init`
//! can default to the agents actually present, mirroring rtk's per-tool install.

use std::fmt;
use std::path::{Path, PathBuf};

/// An AI coding agent burpwn knows how to hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Agent {
    /// Anthropic Claude Code (`~/.claude/settings.json`, PreToolUse hooks).
    ClaudeCode,
    /// GitHub Copilot CLI / coding agent. Treated as Claude-Code-compatible
    /// PreToolUse JSON here (see [`crate::hooks`] doc on the assumption).
    Copilot,
    /// Cursor (`~/.cursor/hooks.json`, `beforeShellExecution`).
    Cursor,
    /// Google Gemini CLI (`~/.gemini/settings.json`, `BeforeTool`).
    Gemini,
    /// Cline / Roo (rules-text driven; `~/.clinerules`).
    Cline,
}

impl Agent {
    /// All known agents, in stable order.
    pub fn all() -> [Agent; 5] {
        [
            Agent::ClaudeCode,
            Agent::Copilot,
            Agent::Cursor,
            Agent::Gemini,
            Agent::Cline,
        ]
    }

    /// Human-readable display name.
    pub fn name(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Copilot => "GitHub Copilot",
            Agent::Cursor => "Cursor",
            Agent::Gemini => "Gemini CLI",
            Agent::Cline => "Cline",
        }
    }

    /// Lowercase machine slug (stable; used as a CLI value / map key).
    pub fn slug(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Copilot => "copilot",
            Agent::Cursor => "cursor",
            Agent::Gemini => "gemini",
            Agent::Cline => "cline",
        }
    }

    /// Parse an agent from its [`slug`](Agent::slug). Accepts a couple of
    /// common aliases.
    pub fn from_slug(s: &str) -> Option<Agent> {
        match s.trim().to_ascii_lowercase().as_str() {
            "claude-code" | "claude" | "claudecode" => Some(Agent::ClaudeCode),
            "copilot" | "github-copilot" => Some(Agent::Copilot),
            "cursor" => Some(Agent::Cursor),
            "gemini" | "gemini-cli" => Some(Agent::Gemini),
            "cline" | "roo" => Some(Agent::Cline),
            _ => None,
        }
    }

    /// Path to the config file burpwn writes this agent's hook into,
    /// relative to `home`.
    ///
    /// * ClaudeCode → `~/.claude/settings.json`
    /// * Copilot    → `~/.copilot/settings.json` (best-effort; see hooks.rs)
    /// * Cursor     → `~/.cursor/hooks.json`
    /// * Gemini     → `~/.gemini/settings.json`
    /// * Cline      → `~/.clinerules`
    pub fn config_path(self, home: &Path) -> PathBuf {
        match self {
            Agent::ClaudeCode => home.join(".claude").join("settings.json"),
            Agent::Copilot => home.join(".copilot").join("settings.json"),
            Agent::Cursor => home.join(".cursor").join("hooks.json"),
            Agent::Gemini => home.join(".gemini").join("settings.json"),
            Agent::Cline => home.join(".clinerules"),
        }
    }

    /// Paths whose existence indicates this agent is installed for the user.
    /// Any one existing counts as "present". (Cline uses bespoke logic in
    /// [`Agent::is_present`] and is not covered here.)
    fn presence_markers(self, home: &Path) -> Vec<PathBuf> {
        match self {
            Agent::ClaudeCode => vec![home.join(".claude")],
            Agent::Copilot => vec![
                home.join(".copilot"),
                home.join(".config").join("gh-copilot"),
            ],
            Agent::Cursor => vec![home.join(".cursor")],
            Agent::Gemini => vec![home.join(".gemini")],
            Agent::Cline => Vec::new(),
        }
    }

    /// Whether this agent appears installed under `home` (best-effort).
    pub fn is_present(self, home: &Path) -> bool {
        // For Cline the bare `.vscode/extensions` dir is too weak a signal, so
        // require either `.clinerules` or an extension dir matching the
        // Cline/Roo publisher prefix.
        if let Agent::Cline = self {
            if home.join(".clinerules").exists() {
                return true;
            }
            let ext_dir = home.join(".vscode").join("extensions");
            return vscode_has_cline_extension(&ext_dir);
        }
        self.presence_markers(home).iter().any(|p| p.exists())
    }

    /// Whether this agent's hook config is JSON (vs the `.clinerules` text form).
    pub fn is_json_config(self) -> bool {
        !matches!(self, Agent::Cline)
    }
}

/// Look for a Cline/Roo VS Code extension directory under `ext_dir`.
/// Extension folders are named `<publisher>.<name>-<version>`.
fn vscode_has_cline_extension(ext_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(ext_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().to_ascii_lowercase();
        if name.starts_with("saoudrizwan.claude-dev") || name.starts_with("rooveterinaryinc.") {
            return true;
        }
    }
    false
}

/// Best-effort detection of which agents are installed under `home`.
pub fn detect_present(home: &Path) -> Vec<Agent> {
    Agent::all()
        .into_iter()
        .filter(|a| a.is_present(home))
        .collect()
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_roundtrips() {
        for a in Agent::all() {
            assert_eq!(Agent::from_slug(a.slug()), Some(a));
        }
        assert_eq!(Agent::from_slug("claude"), Some(Agent::ClaudeCode));
        assert_eq!(Agent::from_slug("roo"), Some(Agent::Cline));
        assert_eq!(Agent::from_slug("nope"), None);
    }

    #[test]
    fn display_is_name() {
        assert_eq!(Agent::Cursor.to_string(), "Cursor");
    }

    #[test]
    fn config_paths() {
        let home = Path::new("/home/x");
        assert_eq!(
            Agent::ClaudeCode.config_path(home),
            Path::new("/home/x/.claude/settings.json")
        );
        assert_eq!(
            Agent::Cursor.config_path(home),
            Path::new("/home/x/.cursor/hooks.json")
        );
        assert_eq!(
            Agent::Gemini.config_path(home),
            Path::new("/home/x/.gemini/settings.json")
        );
        assert_eq!(
            Agent::Cline.config_path(home),
            Path::new("/home/x/.clinerules")
        );
    }

    #[test]
    fn detect_present_finds_marked_dirs() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        assert!(detect_present(h).is_empty());

        std::fs::create_dir_all(h.join(".claude")).unwrap();
        std::fs::create_dir_all(h.join(".gemini")).unwrap();
        std::fs::write(h.join(".clinerules"), "rules").unwrap();

        let found = detect_present(h);
        assert!(found.contains(&Agent::ClaudeCode));
        assert!(found.contains(&Agent::Gemini));
        assert!(found.contains(&Agent::Cline));
        assert!(!found.contains(&Agent::Cursor));
        assert!(!found.contains(&Agent::Copilot));
    }

    #[test]
    fn detect_cline_via_vscode_extension() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let ext = h
            .join(".vscode")
            .join("extensions")
            .join("saoudrizwan.claude-dev-3.0.0");
        std::fs::create_dir_all(&ext).unwrap();
        assert!(Agent::Cline.is_present(h));
        // A bare extensions dir with an unrelated extension is NOT Cline.
        let home2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(
            home2
                .path()
                .join(".vscode")
                .join("extensions")
                .join("ms-python.python-1.0.0"),
        )
        .unwrap();
        assert!(!Agent::Cline.is_present(home2.path()));
    }
}
