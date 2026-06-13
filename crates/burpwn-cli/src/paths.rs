//! Filesystem layout: data dir, runtime dir, session directories, the active
//! session pointer and the config file. This module is the single source of
//! truth for *where things live*, and is part of the contract the MCP server
//! reuses (it constructs the same paths to find a session's control socket).
//!
//! # Data dir (persistent)
//!
//! `base = directories::ProjectDirs::from("fr","own2pwn","burpwn").data_local_dir()`
//! with a fallback to `$XDG_DATA_HOME/burpwn` / `~/.local/share/burpwn`.
//!
//! - `<base>/ca.pem`, `<base>/ca.key` — the per-install root CA.
//! - `<base>/sessions/<name>/session.db` — one SQLite store per session.
//! - `<base>/current` — a one-line file naming the active session.
//!
//! # Runtime dir (ephemeral, per-session)
//!
//! `$XDG_RUNTIME_DIR/burpwn/<session>/` (fallback `<base>/run/<session>/`):
//!
//! - `proxy.sock`   — SCM_RIGHTS unix socket the sandbox hands fds to.
//! - `control.sock` — newline-delimited JSON control socket (see `control.rs`).
//! - `ports.json`   — `{ "dns_port": u16 }`, the ephemeral DNS port the daemon chose.
//!
//! # Config
//!
//! `<config_dir>/burpwn/config.toml` (XDG config), holding the `[wrap]` table
//! consumed by [`burpwn_wrap::WrapConfig`].

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// The default active-session name when `current` is absent.
pub const DEFAULT_SESSION: &str = "default";

/// Resolves and creates (on demand) the burpwn filesystem layout.
///
/// Construct via [`Paths::resolve`] for the real per-user layout, or
/// [`Paths::with_base`] in tests to root everything under a temp dir.
#[derive(Debug, Clone)]
pub struct Paths {
    base: PathBuf,
    runtime: PathBuf,
    config: PathBuf,
}

impl Paths {
    /// Resolve the real per-user layout from XDG / `directories`.
    pub fn resolve() -> Result<Self> {
        let base = data_base().ok_or_else(|| anyhow!("cannot determine a data directory"))?;
        let runtime = runtime_base().unwrap_or_else(|| base.join("run"));
        let config = config_base().ok_or_else(|| anyhow!("cannot determine a config directory"))?;
        Ok(Self {
            base,
            runtime,
            config,
        })
    }

    /// Root every directory under `base` (data + runtime + config). For tests.
    pub fn with_base(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        let runtime = base.join("run");
        let config = base.join("config");
        Self {
            base,
            runtime,
            config,
        }
    }

    /// The persistent data base dir.
    pub fn data_base(&self) -> &Path {
        &self.base
    }

    /// The CA certificate PEM path (`<base>/ca.pem`).
    pub fn ca_pem(&self) -> PathBuf {
        self.base.join("ca.pem")
    }

    /// The directory holding the CA (where `load_or_generate` writes ca.pem/ca.key).
    pub fn ca_dir(&self) -> PathBuf {
        self.base.clone()
    }

    /// The config file path (`<config>/burpwn/config.toml`).
    ///
    /// Note: `config_base()` already includes the `burpwn` segment when resolved
    /// via `directories`; for the test base we append `burpwn` for parity.
    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    /// The sessions root (`<base>/sessions`).
    pub fn sessions_dir(&self) -> PathBuf {
        self.base.join("sessions")
    }

    /// A specific session's directory (`<base>/sessions/<name>`).
    pub fn session_dir(&self, name: &str) -> PathBuf {
        self.sessions_dir().join(name)
    }

    /// A session's SQLite store path (`<base>/sessions/<name>/session.db`).
    pub fn session_db(&self, name: &str) -> PathBuf {
        self.session_dir(name).join("session.db")
    }

    /// The active-session pointer file (`<base>/current`).
    pub fn current_pointer(&self) -> PathBuf {
        self.base.join("current")
    }

    /// A session's runtime directory (`<runtime>/<name>`).
    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.runtime.join(name)
    }

    /// A session's SCM_RIGHTS proxy socket path.
    pub fn proxy_sock(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("proxy.sock")
    }

    /// A session's control socket path.
    pub fn control_sock(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("control.sock")
    }

    /// A session's `ports.json` path.
    pub fn ports_file(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("ports.json")
    }

    // --- mutation helpers -------------------------------------------------

    /// Ensure the data base exists.
    pub fn ensure_base(&self) -> Result<()> {
        std::fs::create_dir_all(&self.base)
            .with_context(|| format!("creating data dir {}", self.base.display()))
    }

    /// Ensure a session's persistent directory exists; returns it.
    pub fn ensure_session_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.session_dir(name);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating session dir {}", dir.display()))?;
        Ok(dir)
    }

    /// Ensure a session's runtime directory exists; returns it.
    pub fn ensure_run_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.run_dir(name);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating runtime dir {}", dir.display()))?;
        Ok(dir)
    }

    /// Read the active session name from the `current` pointer, defaulting to
    /// [`DEFAULT_SESSION`] when the pointer is absent or empty.
    pub fn active_session(&self) -> String {
        match std::fs::read_to_string(self.current_pointer()) {
            Ok(s) => {
                let t = s.trim();
                if t.is_empty() {
                    DEFAULT_SESSION.to_string()
                } else {
                    t.to_string()
                }
            }
            Err(_) => DEFAULT_SESSION.to_string(),
        }
    }

    /// Set the active session pointer to `name`. The session must already exist.
    pub fn set_active_session(&self, name: &str) -> Result<()> {
        self.ensure_base()?;
        std::fs::write(self.current_pointer(), format!("{name}\n"))
            .with_context(|| "writing current-session pointer")
    }

    /// List the names of all existing sessions (directories under `sessions/`).
    pub fn list_sessions(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.sessions_dir()) {
            for ent in rd.flatten() {
                if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = ent.file_name().to_str() {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Whether a session directory exists.
    pub fn session_exists(&self, name: &str) -> bool {
        self.session_dir(name).is_dir()
    }
}

/// A session name is valid if it is a single, non-empty, non-dotted path
/// component (no `/`, no `..`), keeping it inside the sessions dir.
pub fn validate_session_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(anyhow!("invalid session name: {name:?}"));
    }
    Ok(())
}

fn data_base() -> Option<PathBuf> {
    if let Some(d) = directories::ProjectDirs::from("fr", "own2pwn", "burpwn") {
        return Some(d.data_local_dir().to_path_buf());
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("burpwn"));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/burpwn"))
}

fn runtime_base() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(|v| PathBuf::from(v).join("burpwn"))
}

fn config_base() -> Option<PathBuf> {
    if let Some(d) = directories::ProjectDirs::from("fr", "own2pwn", "burpwn") {
        return Some(d.config_dir().to_path_buf());
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("burpwn"));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/burpwn"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_paths_are_under_base() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::with_base(dir.path());
        assert!(p.ca_pem().starts_with(dir.path()));
        assert!(p.session_db("s").ends_with("sessions/s/session.db"));
        assert!(p.proxy_sock("s").ends_with("s/proxy.sock"));
        assert!(p.control_sock("s").ends_with("s/control.sock"));
        assert!(p.ports_file("s").ends_with("s/ports.json"));
    }

    #[test]
    fn active_session_defaults_then_follows_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::with_base(dir.path());
        assert_eq!(p.active_session(), DEFAULT_SESSION);
        p.ensure_session_dir("work").unwrap();
        p.set_active_session("work").unwrap();
        assert_eq!(p.active_session(), "work");
    }

    #[test]
    fn list_sessions_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::with_base(dir.path());
        p.ensure_session_dir("b").unwrap();
        p.ensure_session_dir("a").unwrap();
        assert_eq!(p.list_sessions(), vec!["a".to_string(), "b".to_string()]);
        assert!(p.session_exists("a"));
        assert!(!p.session_exists("zzz"));
    }

    #[test]
    fn session_name_validation() {
        assert!(validate_session_name("ok-1").is_ok());
        assert!(validate_session_name("").is_err());
        assert!(validate_session_name("..").is_err());
        assert!(validate_session_name("a/b").is_err());
    }
}
