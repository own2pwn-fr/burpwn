//! `burpwn mcp register`: write the burpwn stdio MCP server
//! (`command="burpwn", args=["mcp"]`) into a framework's MCP host config,
//! idempotently and preserving existing entries. Complementary to `skill
//! install` — the skill teaches the workflow; this makes the MCP tools
//! actually reachable for MCP-driven frameworks.
//!
//! Supported hosts (all user-level configs under HOME):
//! * **Codex** → `~/.codex/config.toml`, TOML table `[mcp_servers.burpwn]`.
//! * **Copilot CLI** → `~/.copilot/mcp-config.json`, JSON
//!   `mcpServers.burpwn = {type:"local", command, args, tools:["*"]}`.
//! * **Antigravity** → `~/.gemini/config/mcp_config.json`, JSON
//!   `mcpServers.burpwn = {command, args}`.
//!
//! Frameworks without a stdio MCP host (Strix, Shannon) are reported as
//! unsupported rather than guessed at.
//!
//! NOTE (docs pass): Codex blocks outbound network in its default
//! `workspace-write` sandbox — running burpwn's MCP tools (which make network
//! calls on your behalf via `exec`) needs `network_access=true` in the Codex
//! sandbox config. The doc pass will surface this caveat prominently.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// The binary name baked into the generated MCP server entry.
const BURPWN_BIN: &str = "burpwn";

/// Config file encoding for an MCP host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpKind {
    /// TOML (`config.toml`, `[mcp_servers.<name>]`).
    Toml,
    /// JSON (`mcpServers.<name> = { … }`).
    Json,
}

/// One MCP host burpwn can register itself into.
#[derive(Debug, Clone, Copy)]
pub struct McpHost {
    /// Machine slug (CLI `--agent` value).
    pub slug: &'static str,
    /// Human display name.
    pub name: &'static str,
    /// Config file relative to HOME.
    pub config_rel: &'static str,
    /// Config encoding.
    pub kind: McpKind,
}

/// The MCP host registry.
pub fn hosts() -> &'static [McpHost] {
    const H: &[McpHost] = &[
        McpHost {
            slug: "codex",
            name: "Codex CLI",
            config_rel: ".codex/config.toml",
            kind: McpKind::Toml,
        },
        McpHost {
            slug: "copilot",
            name: "GitHub Copilot CLI",
            config_rel: ".copilot/mcp-config.json",
            kind: McpKind::Json,
        },
        McpHost {
            slug: "antigravity",
            name: "Antigravity",
            config_rel: ".gemini/config/mcp_config.json",
            kind: McpKind::Json,
        },
    ];
    H
}

/// Look up a host by slug.
pub fn host_by_slug(slug: &str) -> Option<&'static McpHost> {
    let s = slug.trim().to_ascii_lowercase();
    hosts().iter().find(|h| h.slug == s)
}

/// Frameworks that have no stdio MCP host (so `mcp register` can give a clear
/// "not supported" message rather than guessing a path).
pub fn unsupported_slug(slug: &str) -> Option<&'static str> {
    match slug.trim().to_ascii_lowercase().as_str() {
        "strix" => Some("Strix"),
        "shannon" => Some("Shannon"),
        _ => None,
    }
}

/// What a register call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAction {
    /// burpwn's MCP entry was added to a config that lacked it.
    Installed,
    /// The exact entry was already present; nothing changed.
    AlreadyPresent,
    /// A burpwn entry existed but differed and was updated in place.
    Updated,
    /// `--print` mode: nothing written.
    Printed,
    /// The host config file is malformed / not the expected shape; left intact.
    Refused,
}

impl McpAction {
    /// Stable label for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            McpAction::Installed => "Installed",
            McpAction::AlreadyPresent => "AlreadyPresent",
            McpAction::Updated => "Updated",
            McpAction::Printed => "Printed",
            McpAction::Refused => "Refused",
        }
    }
}

/// Outcome of registering into one host.
#[derive(Debug, Clone)]
pub struct McpReport {
    /// Host slug.
    pub slug: &'static str,
    /// Config file.
    pub path: PathBuf,
    /// What happened.
    pub action: McpAction,
    /// The content that would be written (for `--print`; empty otherwise).
    pub content: String,
}

/// Errors from MCP registration.
#[derive(Debug, thiserror::Error)]
pub enum McpRegError {
    /// Filesystem I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl burpwn_error::Coded for McpRegError {
    fn code(&self) -> burpwn_error::ErrorCode {
        match self {
            McpRegError::Io(_) => burpwn_error::ErrorCode::InputFileUnreadable,
        }
    }
}

/// The desired JSON server object for a JSON host.
fn json_server(slug: &str) -> Value {
    match slug {
        // Copilot's schema wants an explicit local transport + tool allowlist.
        "copilot" => json!({
            "type": "local",
            "command": BURPWN_BIN,
            "args": ["mcp"],
            "tools": ["*"],
        }),
        // Antigravity: minimal stdio command entry.
        _ => json!({
            "command": BURPWN_BIN,
            "args": ["mcp"],
        }),
    }
}

/// Register the burpwn MCP server into `host` under `home`. `print` writes
/// nothing and only fills [`McpReport::content`].
pub fn register(host: &McpHost, home: &Path, print: bool) -> Result<McpReport, McpRegError> {
    let path = home.join(host.config_rel);
    match host.kind {
        McpKind::Toml => register_toml(host, &path, print),
        McpKind::Json => register_json(host, &path, print),
    }
}

/// TOML host (Codex): parse → insert `[mcp_servers.burpwn]` → reserialize,
/// preserving all other tables. A malformed file is left intact (Refused).
fn register_toml(host: &McpHost, path: &Path, print: bool) -> Result<McpReport, McpRegError> {
    use toml::value::Table;
    use toml::Value as Toml;

    // Desired burpwn server table: command="burpwn", args=["mcp"].
    let mut desired = Table::new();
    desired.insert("command".into(), Toml::String(BURPWN_BIN.into()));
    desired.insert("args".into(), Toml::Array(vec![Toml::String("mcp".into())]));
    let desired = Toml::Table(desired);

    // Parse the existing file (empty/absent → empty root).
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(McpRegError::Io(e)),
    };
    let mut root: Table = match &existing {
        Some(s) if s.trim().is_empty() => Table::new(),
        Some(s) => match toml::from_str::<Table>(s) {
            Ok(t) => t,
            // Malformed TOML: refuse to clobber.
            Err(_) => {
                return Ok(McpReport {
                    slug: host.slug,
                    path: path.to_path_buf(),
                    action: McpAction::Refused,
                    content: String::new(),
                })
            }
        },
        None => Table::new(),
    };

    // Ensure `mcp_servers` is a table (refuse if a non-table sits there).
    let servers_entry = root
        .entry("mcp_servers".to_string())
        .or_insert_with(|| Toml::Table(Table::new()));
    let Some(servers) = servers_entry.as_table_mut() else {
        return Ok(McpReport {
            slug: host.slug,
            path: path.to_path_buf(),
            action: McpAction::Refused,
            content: String::new(),
        });
    };

    let action = match servers.get("burpwn") {
        Some(cur) if *cur == desired => McpAction::AlreadyPresent,
        Some(_) => McpAction::Updated,
        None => McpAction::Installed,
    };
    servers.insert("burpwn".to_string(), desired);

    let serialized = toml::to_string_pretty(&Toml::Table(root)).unwrap_or_default();

    finish(host, path, print, action, serialized, &existing)
}

/// JSON host (Copilot, Antigravity): parse → set `mcpServers.burpwn` →
/// reserialize, preserving other entries. A non-object root or malformed JSON is
/// left intact (Refused).
fn register_json(host: &McpHost, path: &Path, print: bool) -> Result<McpReport, McpRegError> {
    let desired = json_server(host.slug);

    let existing = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(McpRegError::Io(e)),
    };
    let mut root: Value = match &existing {
        Some(s) if s.trim().is_empty() => json!({}),
        Some(s) => match serde_json::from_str::<Value>(s) {
            Ok(v) if v.is_object() => v,
            // Malformed or non-object root: refuse to clobber.
            _ => {
                return Ok(McpReport {
                    slug: host.slug,
                    path: path.to_path_buf(),
                    action: McpAction::Refused,
                    content: String::new(),
                })
            }
        },
        None => json!({}),
    };

    let obj = root.as_object_mut().expect("root is an object");
    let servers = obj
        .entry("mcpServers".to_string())
        .or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        return Ok(McpReport {
            slug: host.slug,
            path: path.to_path_buf(),
            action: McpAction::Refused,
            content: String::new(),
        });
    };

    let action = match servers.get("burpwn") {
        Some(cur) if *cur == desired => McpAction::AlreadyPresent,
        Some(_) => McpAction::Updated,
        None => McpAction::Installed,
    };
    servers.insert("burpwn".to_string(), desired);

    let mut serialized = serde_json::to_string_pretty(&root).unwrap_or_default();
    serialized.push('\n');

    finish(host, path, print, action, serialized, &existing)
}

/// Shared tail: honor `--print`, then write iff the serialization changed.
fn finish(
    host: &McpHost,
    path: &Path,
    print: bool,
    action: McpAction,
    serialized: String,
    existing: &Option<String>,
) -> Result<McpReport, McpRegError> {
    if print {
        return Ok(McpReport {
            slug: host.slug,
            path: path.to_path_buf(),
            action: McpAction::Printed,
            content: serialized,
        });
    }
    // AlreadyPresent means the burpwn entry matched; only skip the write if the
    // serialized bytes are truly unchanged (formatting could still differ).
    let unchanged = existing.as_deref() == Some(serialized.as_str());
    if action != McpAction::AlreadyPresent || !unchanged {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &serialized)?;
    }
    Ok(McpReport {
        slug: host.slug,
        path: path.to_path_buf(),
        action,
        content: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn td() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn codex_toml_register_idempotent_and_preserves_other_tables() {
        let host = host_by_slug("codex").unwrap();
        let home = td();
        let path = home.path().join(host.config_rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Pre-seed an unrelated MCP server + a top-level key.
        std::fs::write(
            &path,
            "model = \"gpt-x\"\n\n[mcp_servers.other]\ncommand = \"foo\"\nargs = [\"bar\"]\n",
        )
        .unwrap();

        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::Installed);

        let parsed: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // burpwn entry present + correct.
        let burpwn = parsed["mcp_servers"]["burpwn"].as_table().unwrap();
        assert_eq!(burpwn["command"].as_str(), Some("burpwn"));
        assert_eq!(burpwn["args"][0].as_str(), Some("mcp"));
        // Unrelated entries preserved.
        assert_eq!(parsed["model"].as_str(), Some("gpt-x"));
        assert_eq!(
            parsed["mcp_servers"]["other"]["command"].as_str(),
            Some("foo")
        );

        // Second run: no change.
        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::AlreadyPresent);
    }

    #[test]
    fn codex_toml_malformed_is_refused() {
        let host = host_by_slug("codex").unwrap();
        let home = td();
        let path = home.path().join(host.config_rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bad = "this is = = not valid toml [[[\n";
        std::fs::write(&path, bad).unwrap();
        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::Refused);
        // File left intact.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
    }

    #[test]
    fn copilot_json_register_shape_and_preserve() {
        let host = host_by_slug("copilot").unwrap();
        let home = td();
        let path = home.path().join(host.config_rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{ "mcpServers": { "other": { "command": "x" } } }"#,
        )
        .unwrap();

        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::Installed);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["burpwn"]["type"], "local");
        assert_eq!(v["mcpServers"]["burpwn"]["command"], "burpwn");
        assert_eq!(v["mcpServers"]["burpwn"]["args"][0], "mcp");
        assert_eq!(v["mcpServers"]["burpwn"]["tools"][0], "*");
        // Unrelated server preserved.
        assert_eq!(v["mcpServers"]["other"]["command"], "x");

        // Idempotent.
        assert_eq!(
            register(host, home.path(), false).unwrap().action,
            McpAction::AlreadyPresent
        );
    }

    #[test]
    fn antigravity_json_minimal_shape() {
        let host = host_by_slug("antigravity").unwrap();
        let home = td();
        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::Installed);
        assert!(rep.path.ends_with(".gemini/config/mcp_config.json"));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&rep.path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["burpwn"]["command"], "burpwn");
        assert!(v["mcpServers"]["burpwn"].get("type").is_none());
    }

    #[test]
    fn json_non_object_root_is_refused() {
        let host = host_by_slug("copilot").unwrap();
        let home = td();
        let path = home.path().join(host.config_rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "[1, 2, 3]\n").unwrap();
        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::Refused);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[1, 2, 3]\n");
    }

    #[test]
    fn json_updates_when_entry_differs() {
        let host = host_by_slug("antigravity").unwrap();
        let home = td();
        let path = home.path().join(host.config_rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{ "mcpServers": { "burpwn": { "command": "old" } } }"#,
        )
        .unwrap();
        let rep = register(host, home.path(), false).unwrap();
        assert_eq!(rep.action, McpAction::Updated);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["burpwn"]["command"], "burpwn");
    }

    #[test]
    fn print_writes_nothing() {
        let host = host_by_slug("codex").unwrap();
        let home = td();
        let rep = register(host, home.path(), true).unwrap();
        assert_eq!(rep.action, McpAction::Printed);
        assert!(!rep.path.exists());
        assert!(rep.content.contains("[mcp_servers.burpwn]"));
    }

    #[test]
    fn unsupported_frameworks_named() {
        assert_eq!(unsupported_slug("strix"), Some("Strix"));
        assert_eq!(unsupported_slug("shannon"), Some("Shannon"));
        assert_eq!(unsupported_slug("codex"), None);
    }
}
