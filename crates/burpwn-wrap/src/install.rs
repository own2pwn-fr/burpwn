//! Per-agent install/uninstall orchestration.
//!
//! Reads the agent's existing config (if any), MERGES burpwn's hook entry in
//! without clobbering unrelated user config, and writes it back. JSON configs
//! are merged structurally; `.clinerules` is an idempotent text-block
//! append/replace. The merge is the load-bearing safety property: an operator's
//! pre-existing hooks must survive.

use std::path::PathBuf;

use serde_json::Value;

use crate::hooks;
use crate::{Agent, WrapError};

/// The default invocation name for the burpwn binary inside generated hooks.
pub const DEFAULT_BURPWN_BIN: &str = "burpwn";

/// What an install actually did to the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAction {
    /// burpwn's hook was added to a config that lacked it.
    Installed,
    /// The exact burpwn hook was already present; nothing changed.
    AlreadyPresent,
    /// A burpwn hook existed but differed and was updated in place.
    Updated,
}

/// Outcome of installing into one agent.
#[derive(Debug, Clone)]
pub struct InstallReport {
    /// Which agent was targeted.
    pub agent: Agent,
    /// Config file written.
    pub path: PathBuf,
    /// What happened.
    pub action: InstallAction,
}

/// Install burpwn's command-rewrite hook for `agent` under `home`.
///
/// `exclude` is only consumed by the `.clinerules` text (the JSON hooks defer
/// exclusion to the `burpwn wrap-hook` helper, which consults [`crate::WrapConfig`]
/// at runtime). Uses [`DEFAULT_BURPWN_BIN`] as the invocation name.
pub fn install(
    agent: Agent,
    home: &std::path::Path,
    exclude: &[String],
) -> Result<InstallReport, WrapError> {
    install_with_bin(agent, home, exclude, DEFAULT_BURPWN_BIN)
}

/// As [`install`], but with an explicit burpwn binary name/path (e.g. an
/// absolute install path baked into the hook command).
pub fn install_with_bin(
    agent: Agent,
    home: &std::path::Path,
    exclude: &[String],
    burpwn_bin: &str,
) -> Result<InstallReport, WrapError> {
    let path = agent.config_path(home);
    let action = match agent {
        Agent::Cline => install_cline(&path, burpwn_bin, exclude)?,
        Agent::ClaudeCode | Agent::Copilot => install_pretooluse(&path, agent, burpwn_bin)?,
        Agent::Cursor => install_cursor(&path, burpwn_bin)?,
        Agent::Gemini => install_gemini(&path, burpwn_bin)?,
    };
    Ok(InstallReport {
        agent,
        path,
        action,
    })
}

/// Uninstall burpwn's hook for `agent` (idempotent; missing config is a no-op).
pub fn uninstall(agent: Agent, home: &std::path::Path) -> Result<(), WrapError> {
    let path = agent.config_path(home);
    match agent {
        Agent::Cline => uninstall_cline(&path),
        Agent::ClaudeCode | Agent::Copilot => uninstall_pretooluse(&path),
        Agent::Cursor => uninstall_cursor(&path),
        Agent::Gemini => uninstall_gemini(&path),
    }
}

// ---------------------------------------------------------------------------
// JSON config helpers
// ---------------------------------------------------------------------------

/// Read a JSON config file, returning an empty object if absent.
///
/// A file that parses to valid JSON which is NOT an object (e.g. a top-level
/// array or scalar a user authored) is rejected with [`WrapError::NonObjectRoot`]
/// rather than silently clobbered — agent configs are objects, and merging would
/// otherwise have to discard the user's content.
fn read_json(path: &std::path::Path) -> Result<Value, WrapError> {
    let value = match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => return Ok(Value::Object(Default::default())),
        Ok(s) => serde_json::from_str::<Value>(&s)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Default::default()))
        }
        Err(e) => return Err(WrapError::Io(e)),
    };
    if !value.is_object() {
        return Err(WrapError::NonObjectRoot(path.display().to_string()));
    }
    Ok(value)
}

/// Pretty-print `value` to `path`, creating parent dirs.
fn write_json(path: &std::path::Path, value: &Value) -> Result<(), WrapError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut s = serde_json::to_string_pretty(value)?;
    s.push('\n');
    std::fs::write(path, s)?;
    Ok(())
}

/// Ensure `root[key]` is an array and return a mutable ref to it.
fn ensure_array<'a>(root: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let obj = root.as_object_mut().expect("root must be a JSON object");
    let entry = obj
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !entry.is_array() {
        *entry = Value::Array(Vec::new());
    }
    entry.as_array_mut().unwrap()
}

/// Navigate/create `root.hooks` as an object.
///
/// Callers obtain `root` from [`read_json`], which guarantees an object root
/// (non-object roots are rejected as [`WrapError::NonObjectRoot`]); the
/// coercion below is a belt-and-suspenders guard and is not expected to fire.
fn ensure_hooks_obj(root: &mut Value) -> &mut Value {
    if !root.is_object() {
        *root = Value::Object(Default::default());
    }
    let obj = root.as_object_mut().unwrap();
    let hooks = obj
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Default::default()));
    if !hooks.is_object() {
        *hooks = Value::Object(Default::default());
    }
    hooks
}

/// True if `cmd` is one of burpwn's OWN installed hook invocations.
///
/// Recognised by the exact structure [`hooks::wrap_hook_invocation`] generates:
/// `<burpwn-bin> wrap-hook --agent <slug>`. We anchor on the *token sequence*
/// `wrap-hook` (as the subcommand, i.e. the second token) immediately followed
/// by `--agent` — NOT on a bare `contains("wrap-hook")` substring. The substring
/// form misclassified unrelated user hooks whose command merely mentioned
/// `wrap-hook` (e.g. `~/bin/my-wrap-hook.sh`), clobbering/deleting them on
/// init/uninstall and violating the merge-not-clobber guarantee.
fn is_burpwn_command(cmd: &str) -> bool {
    let mut toks = cmd.split_whitespace();
    // First token is the burpwn binary path/name (we don't pin it: it is baked
    // at install time and may be `burpwn`, an absolute path, etc.).
    let Some(_bin) = toks.next() else {
        return false;
    };
    // Subcommand token must be exactly `wrap-hook`...
    if toks.next() != Some("wrap-hook") {
        return false;
    }
    // ...immediately followed by the `--agent` flag burpwn always emits.
    toks.next() == Some("--agent")
}

/// Does a Claude/Gemini-style matcher entry contain a burpwn hook command?
fn entry_is_burpwn(entry: &Value) -> bool {
    entry["hooks"]
        .as_array()
        .map(|hs| {
            hs.iter()
                .any(|h| h["command"].as_str().is_some_and(is_burpwn_command))
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Claude Code / Copilot — hooks.PreToolUse
// ---------------------------------------------------------------------------

fn install_pretooluse(
    path: &std::path::Path,
    agent: Agent,
    burpwn_bin: &str,
) -> Result<InstallAction, WrapError> {
    let mut root = read_json(path)?;
    let desired = hooks::pretooluse_entry_for(agent, burpwn_bin);

    let hooks_obj = ensure_hooks_obj(&mut root);
    let arr = ensure_array(hooks_obj, "PreToolUse");

    let action = upsert_matcher_entry(arr, desired);
    if action != InstallAction::AlreadyPresent {
        write_json(path, &root)?;
    }
    Ok(action)
}

fn uninstall_pretooluse(path: &std::path::Path) -> Result<(), WrapError> {
    remove_from_hooks_array(path, "PreToolUse")
}

// ---------------------------------------------------------------------------
// Gemini — hooks.BeforeTool
// ---------------------------------------------------------------------------

fn install_gemini(path: &std::path::Path, burpwn_bin: &str) -> Result<InstallAction, WrapError> {
    let mut root = read_json(path)?;
    let desired = hooks::gemini_beforetool(burpwn_bin);

    let hooks_obj = ensure_hooks_obj(&mut root);
    let arr = ensure_array(hooks_obj, "BeforeTool");

    let action = upsert_matcher_entry(arr, desired);
    if action != InstallAction::AlreadyPresent {
        write_json(path, &root)?;
    }
    Ok(action)
}

fn uninstall_gemini(path: &std::path::Path) -> Result<(), WrapError> {
    remove_from_hooks_array(path, "BeforeTool")
}

/// Insert/update burpwn's matcher entry in a `hooks.<Event>` array.
/// Replaces any existing burpwn entry (matched by command), preserving others.
fn upsert_matcher_entry(arr: &mut Vec<Value>, desired: Value) -> InstallAction {
    if let Some(pos) = arr.iter().position(entry_is_burpwn) {
        if arr[pos] == desired {
            InstallAction::AlreadyPresent
        } else {
            arr[pos] = desired;
            InstallAction::Updated
        }
    } else {
        arr.push(desired);
        InstallAction::Installed
    }
}

/// Remove burpwn entries from `root.hooks.<event>`, deleting now-empty
/// containers, and write back only if something changed.
fn remove_from_hooks_array(path: &std::path::Path, event: &str) -> Result<(), WrapError> {
    let mut root = match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => return Ok(()),
        Ok(s) => serde_json::from_str::<Value>(&s)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(WrapError::Io(e)),
    };

    let mut changed = false;
    if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(arr) = hooks.get_mut(event).and_then(|a| a.as_array_mut()) {
            let before = arr.len();
            arr.retain(|e| !entry_is_burpwn(e));
            if arr.len() != before {
                changed = true;
            }
            if arr.is_empty() {
                hooks.remove(event);
            }
        }
        if hooks.is_empty() {
            root.as_object_mut().unwrap().remove("hooks");
        }
    }

    if changed {
        write_json(path, &root)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cursor — hooks.json (beforeShellExecution)
// ---------------------------------------------------------------------------

fn install_cursor(path: &std::path::Path, burpwn_bin: &str) -> Result<InstallAction, WrapError> {
    let mut root = read_json(path)?;
    // Cursor expects a top-level `version`; set it if missing.
    if let Some(obj) = root.as_object_mut() {
        obj.entry("version".to_string())
            .or_insert_with(|| Value::from(1));
    }
    let desired = hooks::cursor_hook_entry(burpwn_bin);

    let hooks_obj = ensure_hooks_obj(&mut root);
    let arr = ensure_array(hooks_obj, "beforeShellExecution");

    // Cursor entries are flat `{command, …}` objects (no nested hooks array),
    // so match by the top-level command field.
    let action = if let Some(pos) = arr
        .iter()
        .position(|e| e["command"].as_str().is_some_and(is_burpwn_command))
    {
        if arr[pos] == desired {
            InstallAction::AlreadyPresent
        } else {
            arr[pos] = desired;
            InstallAction::Updated
        }
    } else {
        arr.push(desired);
        InstallAction::Installed
    };

    if action != InstallAction::AlreadyPresent {
        write_json(path, &root)?;
    }
    Ok(action)
}

fn uninstall_cursor(path: &std::path::Path) -> Result<(), WrapError> {
    let mut root = match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => return Ok(()),
        Ok(s) => serde_json::from_str::<Value>(&s)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(WrapError::Io(e)),
    };
    let mut changed = false;
    if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(arr) = hooks
            .get_mut("beforeShellExecution")
            .and_then(|a| a.as_array_mut())
        {
            let before = arr.len();
            arr.retain(|e| !e["command"].as_str().is_some_and(is_burpwn_command));
            if arr.len() != before {
                changed = true;
            }
            if arr.is_empty() {
                hooks.remove("beforeShellExecution");
            }
        }
    }
    if changed {
        write_json(path, &root)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cline — .clinerules text block
// ---------------------------------------------------------------------------

fn install_cline(
    path: &std::path::Path,
    burpwn_bin: &str,
    exclude: &[String],
) -> Result<InstallAction, WrapError> {
    let block = hooks::cline_rules_block(burpwn_bin, exclude);
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(WrapError::Io(e)),
    };

    let had_block = existing.contains(hooks::CLINE_BEGIN);
    let stripped = strip_cline_block(&existing);

    let mut next = stripped;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    if !next.is_empty() {
        next.push('\n');
    }
    next.push_str(&block);

    let action = if next == existing {
        InstallAction::AlreadyPresent
    } else if had_block {
        InstallAction::Updated
    } else {
        InstallAction::Installed
    };

    if action != InstallAction::AlreadyPresent {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, next)?;
    }
    Ok(action)
}

fn uninstall_cline(path: &std::path::Path) -> Result<(), WrapError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(WrapError::Io(e)),
    };
    let stripped = strip_cline_block(&existing);
    if stripped != existing {
        std::fs::write(path, stripped)?;
    }
    Ok(())
}

/// Remove the burpwn `.clinerules` block (inclusive of markers + one trailing
/// blank line). Pure.
fn strip_cline_block(text: &str) -> String {
    let Some(start) = text.find(hooks::CLINE_BEGIN) else {
        return text.to_string();
    };
    let Some(end_rel) = text[start..].find(hooks::CLINE_END) else {
        return text.to_string();
    };
    let end = start + end_rel + hooks::CLINE_END.len();
    let mut tail_start = end;
    if text[tail_start..].starts_with('\n') {
        tail_start += 1;
    }
    let mut head = text[..start].to_string();
    if head.ends_with("\n\n") {
        head.pop();
    }
    head.push_str(&text[tail_start..]);
    head
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read(path: &std::path::Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn install_claude_into_empty_home() {
        let home = tempfile::tempdir().unwrap();
        let rep = install(Agent::ClaudeCode, home.path(), &[]).unwrap();
        assert_eq!(rep.action, InstallAction::Installed);
        let v = read(&rep.path);
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Bash");
        assert!(arr[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("wrap-hook"));
    }

    #[test]
    fn install_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            install(Agent::ClaudeCode, home.path(), &[]).unwrap().action,
            InstallAction::Installed
        );
        assert_eq!(
            install(Agent::ClaudeCode, home.path(), &[]).unwrap().action,
            InstallAction::AlreadyPresent
        );
        // still exactly one entry
        let v = read(&Agent::ClaudeCode.config_path(home.path()));
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_preserves_existing_unrelated_hooks_and_settings() {
        let home = tempfile::tempdir().unwrap();
        let path = Agent::ClaudeCode.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // pre-existing user config: an unrelated PreToolUse hook + other keys
        let pre = json!({
            "model": "opus",
            "permissions": { "allow": ["Read"] },
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write",
                      "hooks": [ { "type": "command", "command": "/usr/local/bin/lint.sh" } ] }
                ],
                "PostToolUse": [
                    { "matcher": "Bash",
                      "hooks": [ { "type": "command", "command": "echo done" } ] }
                ]
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&pre).unwrap()).unwrap();

        let rep = install(Agent::ClaudeCode, home.path(), &[]).unwrap();
        assert_eq!(rep.action, InstallAction::Installed);

        let v = read(&path);
        // untouched keys survive
        assert_eq!(v["model"], "opus");
        assert_eq!(v["permissions"]["allow"][0], "Read");
        // unrelated PostToolUse survives
        assert_eq!(v["hooks"]["PostToolUse"][0]["matcher"], "Bash");
        // existing PreToolUse entry survives, burpwn appended (now 2)
        let pre_tool = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 2);
        assert!(pre_tool.iter().any(|e| e["matcher"] == "Write"));
        assert!(pre_tool.iter().any(entry_is_burpwn));
    }

    #[test]
    fn uninstall_removes_only_burpwn_entry() {
        let home = tempfile::tempdir().unwrap();
        let path = Agent::ClaudeCode.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let pre = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Write",
                  "hooks": [ { "type": "command", "command": "/usr/local/bin/lint.sh" } ] }
            ] }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&pre).unwrap()).unwrap();

        install(Agent::ClaudeCode, home.path(), &[]).unwrap();
        uninstall(Agent::ClaudeCode, home.path()).unwrap();

        let v = read(&path);
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Write");
    }

    #[test]
    fn update_in_place_when_command_changes() {
        let home = tempfile::tempdir().unwrap();
        // install with one bin name
        install_with_bin(Agent::ClaudeCode, home.path(), &[], "burpwn").unwrap();
        // re-install with a different bin path -> Updated, still one entry
        let rep = install_with_bin(Agent::ClaudeCode, home.path(), &[], "/opt/burpwn").unwrap();
        assert_eq!(rep.action, InstallAction::Updated);
        let v = read(&Agent::ClaudeCode.config_path(home.path()));
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("/opt/burpwn"));
    }

    #[test]
    fn cursor_install_sets_version_and_merges() {
        let home = tempfile::tempdir().unwrap();
        let path = Agent::Cursor.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // existing user hook
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "hooks": { "beforeShellExecution": [ { "command": "./mine.sh" } ] }
            }))
            .unwrap(),
        )
        .unwrap();

        let rep = install(Agent::Cursor, home.path(), &[]).unwrap();
        assert_eq!(rep.action, InstallAction::Installed);
        let v = read(&path);
        assert_eq!(v["version"], 1);
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().any(|e| e["command"] == "./mine.sh"));
        assert!(arr
            .iter()
            .any(|e| e["command"].as_str().unwrap().contains("wrap-hook")));

        uninstall(Agent::Cursor, home.path()).unwrap();
        let v = read(&path);
        assert_eq!(
            v["hooks"]["beforeShellExecution"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn gemini_install_uninstall() {
        let home = tempfile::tempdir().unwrap();
        let rep = install(Agent::Gemini, home.path(), &[]).unwrap();
        assert_eq!(rep.action, InstallAction::Installed);
        let v = read(&rep.path);
        assert_eq!(v["hooks"]["BeforeTool"][0]["matcher"], "run_shell_command");

        uninstall(Agent::Gemini, home.path()).unwrap();
        let v = read(&rep.path);
        // hooks object cleaned up entirely
        assert!(v.get("hooks").is_none());
    }

    #[test]
    fn cline_install_appends_block_and_preserves_user_rules() {
        let home = tempfile::tempdir().unwrap();
        let path = Agent::Cline.config_path(home.path());
        std::fs::write(&path, "# My project rules\nAlways write tests.\n").unwrap();

        let rep = install(Agent::Cline, home.path(), &["git".into()]).unwrap();
        assert_eq!(rep.action, InstallAction::Installed);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("My project rules"));
        assert!(body.contains("burpwn exec --"));
        assert!(body.contains("git"));

        // idempotent
        assert_eq!(
            install(Agent::Cline, home.path(), &["git".into()])
                .unwrap()
                .action,
            InstallAction::AlreadyPresent
        );
        // changing exclusions updates in place, single block
        let rep = install(Agent::Cline, home.path(), &[]).unwrap();
        assert_eq!(rep.action, InstallAction::Updated);
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.matches(hooks::CLINE_BEGIN).count(), 1);

        uninstall(Agent::Cline, home.path()).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("My project rules"));
        assert!(!body.contains(hooks::CLINE_BEGIN));
    }

    #[test]
    fn copilot_uses_pretooluse_path() {
        let home = tempfile::tempdir().unwrap();
        let rep = install(Agent::Copilot, home.path(), &[]).unwrap();
        let v = read(&rep.path);
        assert!(v["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("--agent copilot"));
    }

    #[test]
    fn is_burpwn_command_only_matches_anchored_invocation() {
        // Finding #2: burpwn's OWN entries are recognised...
        assert!(is_burpwn_command("burpwn wrap-hook --agent claude-code"));
        assert!(is_burpwn_command("/opt/burpwn wrap-hook --agent gemini"));
        // ...but unrelated user commands that merely CONTAIN the `wrap-hook`
        // substring are NOT misclassified (would clobber/delete them).
        assert!(!is_burpwn_command("~/bin/my-wrap-hook.sh"));
        assert!(!is_burpwn_command("/usr/local/bin/wrap-hook-runner --foo"));
        assert!(!is_burpwn_command("echo wrap-hook"));
        // `wrap-hook` must be the SUBCOMMAND token followed by `--agent`.
        assert!(!is_burpwn_command("burpwn other --wrap-hook"));
        assert!(!is_burpwn_command("burpwn wrap-hook"));
        assert!(!is_burpwn_command(""));
    }

    #[test]
    fn user_hook_containing_wrap_hook_substring_is_not_clobbered() {
        // Finding #2: a pre-existing user PreToolUse hook whose command merely
        // contains the literal `wrap-hook` must survive init AND uninstall.
        let home = tempfile::tempdir().unwrap();
        let path = Agent::ClaudeCode.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let pre = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash",
                  "hooks": [ { "type": "command", "command": "~/bin/my-wrap-hook.sh" } ] }
            ] }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&pre).unwrap()).unwrap();

        // init: user's hook preserved, burpwn appended (now 2 entries).
        let rep = install(Agent::ClaudeCode, home.path(), &[]).unwrap();
        assert_eq!(rep.action, InstallAction::Installed);
        let v = read(&path);
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr
            .iter()
            .any(|e| e["hooks"][0]["command"] == "~/bin/my-wrap-hook.sh"));

        // uninstall: only burpwn's entry removed, user's wrap-hook script kept.
        uninstall(Agent::ClaudeCode, home.path()).unwrap();
        let v = read(&path);
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0]["command"], "~/bin/my-wrap-hook.sh");
    }

    #[test]
    fn cursor_user_wrap_hook_substring_is_not_clobbered() {
        // Finding #2, Cursor flat-entry path: a user `beforeShellExecution` entry
        // whose command contains `wrap-hook` must not be overwritten or deleted.
        let home = tempfile::tempdir().unwrap();
        let path = Agent::Cursor.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "hooks": { "beforeShellExecution": [ { "command": "~/bin/my-wrap-hook.sh" } ] }
            }))
            .unwrap(),
        )
        .unwrap();

        install(Agent::Cursor, home.path(), &[]).unwrap();
        let v = read(&path);
        assert_eq!(
            v["hooks"]["beforeShellExecution"].as_array().unwrap().len(),
            2
        );

        uninstall(Agent::Cursor, home.path()).unwrap();
        let v = read(&path);
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "~/bin/my-wrap-hook.sh");
    }

    #[test]
    fn non_object_root_json_is_refused_not_clobbered() {
        // Finding #5: an existing config that is valid JSON but NOT an object
        // (e.g. a top-level array) must NOT be silently overwritten; we error.
        let home = tempfile::tempdir().unwrap();
        let path = Agent::ClaudeCode.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = "[1, 2, 3]\n";
        std::fs::write(&path, original).unwrap();

        let err = install(Agent::ClaudeCode, home.path(), &[]).unwrap_err();
        assert!(matches!(err, WrapError::NonObjectRoot(_)));
        // the user's file is untouched
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn non_object_root_scalar_is_refused() {
        // A top-level scalar/string is likewise refused (Gemini path).
        let home = tempfile::tempdir().unwrap();
        let path = Agent::Gemini.config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "\"just a string\"\n").unwrap();
        let err = install(Agent::Gemini, home.path(), &[]).unwrap_err();
        assert!(matches!(err, WrapError::NonObjectRoot(_)));
    }
}
