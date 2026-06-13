//! Wrap configuration model.
//!
//! The wrap layer is intentionally minimal: by construction the netns/sandbox
//! design keeps the agent's *own* LLM traffic out of capture (only the commands
//! the agent spawns are routed through `burpwn exec`), so the only knob we need
//! here is an escape hatch — [`WrapConfig::exclude_commands`] — mirroring rtk's
//! `exclude_commands`. Programs listed there are run untouched (never rewritten
//! to `burpwn exec -- …`).
//!
//! Persisted as the `[wrap]` table of `~/.config/burpwn/config.toml` (resolved
//! via [`directories`]). Tests pass an explicit override path so they never
//! touch the real home.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::WrapError;

/// Wrap-layer configuration (the `[wrap]` table of `config.toml`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapConfig {
    /// Programs whose invocations must NOT be rewritten through `burpwn exec`.
    ///
    /// Matched against the command's *program* (first shell token), e.g. an
    /// entry `"git"` excludes `git status` but not `mygit`. Defaults to empty:
    /// nothing is excluded, because the sandbox already isolates each command.
    #[serde(default)]
    pub exclude_commands: Vec<String>,
}

/// On-disk wrapper so the file is `[wrap] …` rather than top-level keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    wrap: WrapConfig,
}

impl WrapConfig {
    /// Default config path: `~/.config/burpwn/config.toml` (XDG via `directories`).
    ///
    /// Returns `None` if no valid home/config directory can be determined.
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("fr", "own2pwn", "burpwn")
            .map(|d| d.config_dir().join("config.toml"))
    }

    /// Load the `[wrap]` table from `path`. A missing file yields defaults.
    pub fn load(path: &Path) -> Result<Self, WrapError> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let cf: ConfigFile = toml::from_str(&s)?;
                Ok(cf.wrap)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(WrapError::Io(e)),
        }
    }

    /// Serialize `self` under the `[wrap]` table and write to `path`,
    /// creating parent directories as needed.
    ///
    /// NOTE: this rewrites the whole file with only the `[wrap]` table; the
    /// config file is owned by burpwn so that is acceptable here.
    pub fn save(&self, path: &Path) -> Result<(), WrapError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let cf = ConfigFile { wrap: self.clone() };
        let s = toml::to_string_pretty(&cf)?;
        std::fs::write(path, s)?;
        Ok(())
    }
}

/// Extract the *program* token from a command line: the first whitespace-
/// separated token, with any leading path components and `VAR=val` env
/// prefixes stripped. Best-effort (not a full shell parser).
///
/// ```text
/// "git status"              -> "git"
/// "/usr/bin/curl -sSL …"    -> "curl"
/// "FOO=1 BAR=2 npm install" -> "npm"
/// "FOO=\"a b\" curl …"      -> "curl"
/// ""                        -> ""
/// ```
fn program_of(cmd: &str) -> &str {
    let mut toks = cmd.split_whitespace().peekable();
    while let Some(tok) = toks.peek().copied() {
        // Skip leading `VAR=value` environment assignments.
        if tok.contains('=') && tok.split('=').next().is_some_and(is_env_name) {
            toks.next();
            // A quoted assignment value may contain whitespace and thus span
            // several whitespace-split tokens (`FOO="a b"`): consume tokens
            // until the opening quote is balanced, so we don't mistake the tail
            // of the value (e.g. `b"`) for the program. Without this the program
            // detection would be wrong and `should_wrap` could compare the wrong
            // program against `exclude_commands`, potentially skipping capture.
            if let Some((_, rest)) = tok.split_once('=') {
                if let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') {
                    // Closed within this same token? (>= 2 quote chars present.)
                    let closed = rest.matches(quote).count() >= 2;
                    if !closed {
                        // Consume following tokens until one ends the quote.
                        for next in toks.by_ref() {
                            if next.contains(quote) {
                                break;
                            }
                        }
                    }
                }
            }
            continue;
        }
        // Strip directory components: `/usr/bin/curl` -> `curl`.
        return tok.rsplit('/').next().unwrap_or(tok);
    }
    ""
}

/// Is `s` a plausible shell environment-variable name (`[A-Za-z_][A-Za-z0-9_]*`)?
fn is_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Decide whether `cmd` should be rewritten through `burpwn exec`.
///
/// Returns `false` (do not wrap) when the command's program is listed in
/// `cfg.exclude_commands`, or when the command is empty/blank. Pure.
pub fn should_wrap(cmd: &str, cfg: &WrapConfig) -> bool {
    let prog = program_of(cmd);
    if prog.is_empty() {
        return false;
    }
    !cfg.exclude_commands.iter().any(|e| e == prog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_of_strips_path_and_env() {
        assert_eq!(program_of("git status"), "git");
        assert_eq!(program_of("/usr/bin/curl -sSL x"), "curl");
        assert_eq!(program_of("FOO=1 BAR=2 npm install"), "npm");
        assert_eq!(program_of("   "), "");
        assert_eq!(program_of(""), "");
        assert_eq!(program_of("./run.sh"), "run.sh");
    }

    #[test]
    fn program_of_handles_quoted_assignment_values() {
        // Finding #4: a quoted assignment value containing whitespace spans
        // multiple whitespace-split tokens; we must consume through the closing
        // quote, not return the tail of the value as the program.
        assert_eq!(program_of(r#"FOO="a b" curl https://x"#), "curl");
        assert_eq!(program_of("A=1 ls"), "ls");
        assert_eq!(program_of("X='y' prog"), "prog");
        // single-quoted value with spaces
        assert_eq!(program_of("X='a b c' wget url"), "wget");
        // multiple assignments, one quoted with spaces
        assert_eq!(program_of(r#"A=1 B="x y" nmap -sV t"#), "nmap");
        // quoted value with a path-like program after it stays correctly stripped
        assert_eq!(program_of(r#"FOO="a b" /usr/bin/curl"#), "curl");
    }

    #[test]
    fn should_wrap_defaults_to_true() {
        let cfg = WrapConfig::default();
        assert!(should_wrap("curl https://example.com", &cfg));
        assert!(should_wrap("git status", &cfg));
    }

    #[test]
    fn should_wrap_honors_exclusions() {
        let cfg = WrapConfig {
            exclude_commands: vec!["git".into(), "ls".into()],
        };
        assert!(!should_wrap("git push", &cfg));
        assert!(!should_wrap("/usr/bin/git push", &cfg));
        assert!(!should_wrap("ls -la", &cfg));
        // not excluded:
        assert!(should_wrap("curl https://x", &cfg));
        // substring must not match (program is `gitk`, not `git`):
        assert!(should_wrap("gitk", &cfg));
    }

    #[test]
    fn should_wrap_blank_is_false() {
        let cfg = WrapConfig::default();
        assert!(!should_wrap("", &cfg));
        assert!(!should_wrap("   \t  ", &cfg));
    }

    #[test]
    fn load_missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.toml");
        let cfg = WrapConfig::load(&p).unwrap();
        assert_eq!(cfg, WrapConfig::default());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("config.toml");
        let cfg = WrapConfig {
            exclude_commands: vec!["aws".into(), "kubectl".into()],
        };
        cfg.save(&p).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("[wrap]"), "expected [wrap] table: {body}");
        assert_eq!(WrapConfig::load(&p).unwrap(), cfg);
    }

    #[test]
    fn load_ignores_unrelated_tables() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        std::fs::write(
            &p,
            "[proxy]\nport = 8080\n\n[wrap]\nexclude_commands = [\"git\"]\n",
        )
        .unwrap();
        let cfg = WrapConfig::load(&p).unwrap();
        assert_eq!(cfg.exclude_commands, vec!["git".to_string()]);
    }
}
