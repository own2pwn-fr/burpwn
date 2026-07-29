//! The debug report: everything someone needs to understand a failure without
//! asking the user a single follow-up question.
//!
//! One JSON file per failure, written automatically to
//! `<data-dir>/debug/<timestamp>-<code>.json`, its path printed in the error
//! message. `burpwn debug bundle` writes the same document on demand.
//!
//! ## What goes in
//!
//! The diagnostic itself, plus the state that turns "it failed" into "of course
//! it failed": burpwn's version, the (redacted) invocation, the host kernel and
//! distribution, whether this is WSL or a container, the sandbox prerequisites
//! and — for sandbox failures — a LIVE re-probe of the sandbox, the session's
//! on-disk state and whether its daemon is up.
//!
//! ## What does not
//!
//! Anything that could be a credential. burpwn holds the target's secrets by
//! design, so the report is filtered through [`burpwn_error::redact`]: env vars
//! outside a small allowlist keep their name and lose their value, and argv and
//! free text have token-shaped material stripped. Captured request/response
//! bodies are never touched at all — the report describes the store, it does not
//! read from it.
//!
//! ## Rotation
//!
//! The directory keeps the [`KEEP_REPORTS`] most recent files. A tool that
//! writes a file on every failure must not become a disk leak.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use burpwn_error::{redact_argv, redact_env, redact_text, Diagnostic};
use serde_json::{json, Value};

use crate::paths::Paths;

/// How many reports to keep in the debug directory.
pub const KEEP_REPORTS: usize = 20;

/// The report format version, so a future reader can tell what it is looking at.
pub const SCHEMA_VERSION: u32 = 1;

/// Build the full debug document.
///
/// `diag` is the failure being reported (`None` for an on-demand bundle).
/// `probe_sandbox` runs the live sandbox probe — it forks a namespace, so the
/// caller decides when it is worth it (sandbox failures and explicit bundles).
pub fn build(paths: &Paths, diag: Option<&Diagnostic>, probe_sandbox: bool) -> Value {
    json!({
        "schema": SCHEMA_VERSION,
        "generated_at": timestamp(),
        "burpwn": burpwn_facts(),
        "error": diag.map(|d| d.to_json()),
        "invocation": invocation(),
        "host": host_facts(),
        "prerequisites": prerequisite_facts(),
        "sandbox_probe": if probe_sandbox {
            let p = burpwn_sandbox::deep_probe();
            json!({
                "ok": p.is_ok(),
                "summary": p.summary(),
                "steps": p.steps,
                "remediation": p.remediation(),
            })
        } else {
            Value::Null
        },
        "sessions": session_facts(paths),
        "env": redact_env(std::env::vars()),
    })
}

/// Write a report for `diag` and return where it went.
///
/// Best-effort by design: a failure to write the report must never replace or
/// mask the failure being reported. Returns `None` if the file could not be
/// written, and the error message then simply has no `debug` line.
pub fn write(paths: &Paths, diag: &Diagnostic) -> Option<PathBuf> {
    // Re-probing the sandbox costs a fork; it is only informative for sandbox
    // failures, where it is the single most useful thing in the report.
    let probe = diag.code.class() == burpwn_error::ErrorClass::Sandbox;
    let doc = build(paths, Some(diag), probe);
    let dir = paths.debug_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{}-{}.json", file_timestamp(), diag.code.id()));
    let body = serde_json::to_string_pretty(&doc).ok()?;
    std::fs::write(&path, body).ok()?;
    rotate(&dir, KEEP_REPORTS);
    Some(path)
}

/// Keep only the `keep` most recent `*.json` reports in `dir`.
///
/// Ordering is by filename, which is exactly chronological because the names
/// start with a zero-padded RFC3339-ish timestamp — no filesystem mtime needed
/// (and no surprises when a directory is copied around).
pub fn rotate(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    if files.len() <= keep {
        return;
    }
    files.sort();
    let excess = files.len() - keep;
    for path in files.into_iter().take(excess) {
        let _ = std::fs::remove_file(path);
    }
}

/// The most recent reports on disk, newest first.
pub fn recent(dir: &Path, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files.reverse();
    files.truncate(limit);
    files
}

// ---------------------------------------------------------------------------
// Fact collection
// ---------------------------------------------------------------------------

fn burpwn_facts() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "binary": std::env::current_exe().ok().map(|p| p.display().to_string()),
    })
}

fn invocation() -> Value {
    json!({
        "argv": redact_argv(std::env::args()),
        "cwd": std::env::current_dir().ok().map(|p| p.display().to_string()),
        "uid": unsafe { libc::getuid() },
        "tty": unsafe { libc::isatty(libc::STDIN_FILENO) } == 1,
    })
}

fn host_facts() -> Value {
    json!({
        "kernel": read_trimmed("/proc/sys/kernel/osrelease"),
        "os_release": parse_os_release(&std::fs::read_to_string("/etc/os-release").unwrap_or_default()),
        "arch": std::env::consts::ARCH,
        "wsl": burpwn_sandbox::is_wsl(),
        "container": container_hint(),
    })
}

fn prerequisite_facts() -> Value {
    let pf = burpwn_sandbox::doctor();
    json!({
        "userns_enabled": pf.userns_enabled,
        "subuid_present": pf.subuid_present,
        "bwrap_present": pf.bwrap_present,
        "nft_present": pf.nft_present,
        "ip_present": pf.ip_present,
        "missing": pf.missing_summary(),
    })
}

/// On-disk state of every session: is the DB there, how big, is its daemon up.
///
/// Deliberately metadata only — the report never opens a capture database for
/// content, so no captured traffic can leak into it.
fn session_facts(paths: &Paths) -> Value {
    let active = paths.active_session();
    let mut sessions = Vec::new();
    if let Ok(entries) = std::fs::read_dir(paths.sessions_dir()) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let db = paths.session_db(&name);
            let run_dir = paths.proxy_sock(&name).parent().map(Path::to_path_buf);
            sessions.push(json!({
                "name": name,
                "active": name == active,
                "db_path": db.display().to_string(),
                "db_bytes": std::fs::metadata(&db).map(|m| m.len()).ok(),
                "runtime_dir": run_dir.as_ref().map(|p| p.display().to_string()),
                "control_socket": paths.control_sock(&name).exists(),
                "proxy_socket": paths.proxy_sock(&name).exists(),
            }));
        }
    }
    json!({
        "active": active,
        "data_dir": paths.data_base().display().to_string(),
        "ca_present": paths.ca_pem().exists(),
        "known": sessions,
    })
}

fn container_hint() -> Option<String> {
    if Path::new("/.dockerenv").exists() {
        return Some("docker".into());
    }
    if Path::new("/run/.containerenv").exists() {
        return Some("podman".into());
    }
    let cgroup = std::fs::read_to_string("/proc/1/cgroup").unwrap_or_default();
    for marker in ["docker", "podman", "containerd", "lxc", "kubepods"] {
        if cgroup.contains(marker) {
            return Some(marker.into());
        }
    }
    None
}

/// Parse the `KEY="value"` lines of `/etc/os-release` into a map.
///
/// Pure, so the parsing is unit-tested against the real quoting rules rather
/// than assumed.
pub fn parse_os_release(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (k, v) = line.split_once('=')?;
            let v = v.trim().trim_matches('"').trim_matches('\'');
            Some((k.trim().to_string(), redact_text(v)))
        })
        .collect()
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// An RFC3339 UTC timestamp, truncated to whole seconds.
///
/// Second precision is deliberate: the timestamp doubles as the report
/// FILENAME, and nanoseconds only make those unreadable. Two failures in the
/// same second is not a case worth a longer name — the second one simply
/// overwrites the first, and they describe the same incident anyway.
fn timestamp() -> String {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    now.format(&Rfc3339).unwrap_or_else(|_| "unknown".into())
}

/// A filename-safe, lexicographically-sortable timestamp (`2026-07-29T17-42-11Z`).
/// Sortability is what makes [`rotate`] and [`recent`] work on names alone.
fn file_timestamp() -> String {
    timestamp().replace(':', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_error::ErrorCode;

    fn paths_in(dir: &Path) -> Paths {
        Paths::with_base(dir)
    }

    #[test]
    fn os_release_is_parsed_and_unquoted() {
        let map =
            parse_os_release("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n# a comment\n\nID=ubuntu\n");
        assert_eq!(map["NAME"], "Ubuntu");
        assert_eq!(map["VERSION_ID"], "24.04");
        assert_eq!(map["ID"], "ubuntu");
        assert_eq!(map.len(), 3, "comments and blanks are skipped");
    }

    #[test]
    fn os_release_tolerates_garbage() {
        assert!(parse_os_release("").is_empty());
        assert!(parse_os_release("no-equals-sign\n").is_empty());
    }

    #[test]
    fn a_report_carries_the_diagnostic_and_the_host_facts() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(tmp.path());
        let diag = Diagnostic::new(ErrorCode::InputNoSuchFlow, "no such flow 7");
        let doc = build(&paths, Some(&diag), false);

        assert_eq!(doc["schema"], json!(SCHEMA_VERSION));
        assert_eq!(doc["error"]["code"], json!("BW-INPUT-002"));
        assert_eq!(doc["error"]["exit_code"], json!(75));
        assert!(doc["host"]["kernel"].is_string());
        assert!(doc["burpwn"]["version"].is_string());
        assert!(doc["prerequisites"]["missing"].is_string());
        // Not a sandbox failure => no fork, no probe.
        assert_eq!(doc["sandbox_probe"], Value::Null);
    }

    // A report is meant to be pasted into an issue. If an unknown env var's
    // value survives, a live credential goes with it.
    #[test]
    fn report_env_is_redacted() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(tmp.path());
        std::env::set_var("BURPWN_TEST_FAKE_SECRET", "super-secret-value");
        let doc = build(&paths, None, false);
        let env = &doc["env"];
        assert_eq!(
            env["BURPWN_TEST_FAKE_SECRET"],
            json!(burpwn_error::REDACTED),
            "an unknown env var must not keep its value"
        );
        assert!(!doc.to_string().contains("super-secret-value"));
        std::env::remove_var("BURPWN_TEST_FAKE_SECRET");
    }

    #[test]
    fn writing_a_report_returns_its_path_and_names_the_code() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(tmp.path());
        let diag = Diagnostic::new(ErrorCode::InputNoSuchFlow, "no such flow 7");
        let path = write(&paths, &diag).expect("report should be written");
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("BW-INPUT-002"));
        let back: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back["error"]["message"], json!("no such flow 7"));
    }

    // Writing a file on every failure must not grow without bound.
    #[test]
    fn rotation_keeps_only_the_most_recent_reports() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for i in 0..10 {
            std::fs::write(
                dir.join(format!("2026-07-29T00-00-{i:02}Z-BW-INPUT-001.json")),
                "{}",
            )
            .unwrap();
        }
        // A non-report file must survive rotation untouched.
        std::fs::write(dir.join("notes.txt"), "keep me").unwrap();

        rotate(dir, 3);

        let mut left: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".json"))
            .collect();
        left.sort();
        assert_eq!(left.len(), 3);
        assert!(left[0].contains("00-00-07"), "kept the newest: {left:?}");
        assert!(dir.join("notes.txt").exists());
    }

    #[test]
    fn rotation_is_a_noop_below_the_limit() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("2026-01-01T00-00-00Z-BW-INPUT-001.json"),
            "{}",
        )
        .unwrap();
        rotate(tmp.path(), 20);
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn recent_returns_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(
                tmp.path()
                    .join(format!("2026-07-29T00-00-{i:02}Z-BW-INPUT-001.json")),
                "{}",
            )
            .unwrap();
        }
        let recent = recent(tmp.path(), 2);
        assert_eq!(recent.len(), 2);
        assert!(recent[0].to_string_lossy().contains("00-00-04"));
        assert!(recent[1].to_string_lossy().contains("00-00-03"));
    }

    #[test]
    fn file_timestamps_are_sortable_and_path_safe() {
        let ts = file_timestamp();
        assert!(!ts.contains(':'), "colons break paths on some filesystems");
        assert!(ts.starts_with("20"), "{ts}");
        assert!(
            !ts.contains('.'),
            "sub-second precision bloats the name: {ts}"
        );
        // `YYYY-MM-DDTHH-MM-SSZ` — fixed width, so plain string sort is
        // chronological, which is what rotate()/recent() rely on.
        assert_eq!(ts.len(), 20, "{ts}");
    }
}
