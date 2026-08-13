//! Session bundles at the CLI layer: which file, which session, and what to say
//! about what is inside.
//!
//! The mechanics (`VACUUM INTO`, the manifest, the zstd container) live in
//! [`burpwn_store::bundle`]. What lives here is the policy: where the file goes
//! by default, refusing to clobber or to follow a symlink, resolving the import
//! name, refusing to overwrite an existing session, and the wording of the
//! warning that says a raw bundle is a credential store.
//!
//! Both the CLI (`burpwn export session`, `burpwn session import`) and the MCP
//! `session_export` tool go through these two functions, so an agent and an
//! operator get exactly the same guards.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use burpwn_error::ErrorCode;
use burpwn_store::bundle::{self, BundleCounts, BundleManifest};

use crate::paths::{validate_session_name, Paths};

/// Extension of a session bundle, and the default output name's suffix.
pub const BUNDLE_EXT: &str = "burpwn";

/// What a bundle exported WITHOUT `--redact` contains. Printed on stderr in
/// human mode and carried in the `--json` envelope, because "I sent my colleague
/// my session" and "I sent my colleague my session cookies" have to be the same
/// sentence in the operator's head.
pub const RAW_WARNING: &str = "this bundle holds the session exactly as captured: stored auth \
     tokens and login commands (credentials and all), plus every Authorization / Cookie / \
     Set-Cookie header recorded in the traffic. Anyone who opens it can replay them — move it the \
     way you would move the credentials themselves. `--redact` drops the stored auth profiles and \
     match/replace replacements.";

/// The honest small print of `--redact`: it covers what burpwn stored, not what
/// burpwn captured.
pub const REDACTED_WARNING: &str = "--redact dropped the stored auth tokens, login commands and \
     match/replace replacements. It does NOT scrub credentials captured inside recorded requests \
     and responses (Authorization / Cookie headers, login bodies) — those are still in this file.";

/// An `export session` request, from either the CLI or the MCP tool.
#[derive(Debug, Clone)]
pub struct ExportRequest {
    /// Session to export.
    pub session: String,
    /// Output file; defaults to `<session>.burpwn` in the current directory.
    pub output: Option<PathBuf>,
    /// Strip the stored credentials (see [`burpwn_store::bundle::redact`]).
    pub redact: bool,
    /// Overwrite an existing output file.
    pub force: bool,
}

/// What an export produced.
#[derive(Debug, Clone)]
pub struct ExportOutcome {
    /// Where the bundle was written.
    pub path: PathBuf,
    /// Size of the bundle on disk.
    pub bytes: u64,
    /// The manifest that travelled with it.
    pub manifest: BundleManifest,
}

impl ExportOutcome {
    /// The warning to show for this export — never nothing: a redacted bundle
    /// still carries whatever the target sent back.
    pub fn warning(&self) -> &'static str {
        if self.manifest.redacted {
            REDACTED_WARNING
        } else {
            RAW_WARNING
        }
    }
}

/// A `session import` request.
#[derive(Debug, Clone)]
pub struct ImportRequest {
    /// The bundle file.
    pub file: PathBuf,
    /// Name to import under; defaults to the bundle's own session name.
    pub as_name: Option<String>,
    /// Make the imported session the active one.
    pub use_session: bool,
}

/// What an import produced.
#[derive(Debug, Clone)]
pub struct ImportOutcome {
    /// Name the session was created under.
    pub session: String,
    /// The bundle's manifest.
    pub manifest: BundleManifest,
    /// Row counts of the imported session.
    pub counts: BundleCounts,
    /// `Some(v)` when the bundle carried an older schema, migrated on the way in.
    pub migrated_from: Option<i64>,
    /// Whether the `current` pointer now points at it.
    pub activated: bool,
}

/// Export a session to a single portable file.
pub fn export_session(paths: &Paths, req: &ExportRequest) -> Result<ExportOutcome> {
    validate_session_name(&req.session)?;
    let db = paths.session_db(&req.session);
    if !db.is_file() {
        crate::fail!(
            ErrorCode::SessionNotFound,
            "session '{}' has no capture database yet ({} does not exist)",
            req.session,
            db.display()
        );
    }

    let out = req
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.{BUNDLE_EXT}", req.session)));
    guard_output_path(&out, "bundle", req.force)?;
    // `--force`: remove first rather than truncate, so the new bundle is created
    // 0600 by the store instead of inheriting the old file's mode.
    if out.exists() {
        std::fs::remove_file(&out).with_context(|| format!("replacing {}", out.display()))?;
    }

    let ca_pem = paths.ca_pem();
    let manifest = bundle::export(
        &db,
        &out,
        &bundle::ExportOptions {
            session: &req.session,
            burpwn_version: env!("CARGO_PKG_VERSION"),
            exported_at: now_ms(),
            ca_pem: ca_pem.is_file().then_some(ca_pem.as_path()),
            redact: req.redact,
        },
    )
    .with_context(|| format!("exporting session '{}' to {}", req.session, out.display()))?;

    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    Ok(ExportOutcome {
        path: out,
        bytes,
        manifest,
    })
}

/// Import a bundle as a NEW session.
///
/// Never merges into an existing session and never overwrites one: the flow,
/// group, attack and blob ids inside a bundle are the bundle's own, and
/// re-numbering them to fit another session is a different (and much riskier)
/// feature. A name collision is therefore an error the user resolves with
/// `--as`, not something to paper over.
pub fn import_session(paths: &Paths, req: &ImportRequest) -> Result<ImportOutcome> {
    let file = &req.file;
    match std::fs::metadata(file) {
        Err(e) => crate::fail!(
            ErrorCode::InputFileUnreadable,
            "cannot read bundle {}: {}",
            file.display(),
            e.kind()
        ),
        // A FIFO or a device would block or stream forever; a directory is a
        // typo. Only a regular file can be a bundle.
        Ok(meta) if !meta.is_file() => crate::fail!(
            ErrorCode::InputUnsafePath,
            "refusing to read {}: not a regular file",
            file.display()
        ),
        Ok(_) => {}
    }

    // Stage inside the sessions dir: the staged database has to land on the same
    // filesystem as its final home for the install to be an atomic rename.
    let sessions = paths.sessions_dir();
    std::fs::create_dir_all(&sessions)
        .with_context(|| format!("creating {}", sessions.display()))?;
    let staged = bundle::stage(file, &sessions)
        .with_context(|| format!("reading bundle {}", file.display()))?;

    // The name may come from the bundle, i.e. from another machine — validate it
    // like any other untrusted input before it becomes a path.
    let name = req
        .as_name
        .clone()
        .unwrap_or_else(|| staged.manifest.session.clone());
    validate_session_name(&name).with_context(|| {
        format!(
            "the bundle was exported from session {:?}; import it under a name of your own with \
             `--as <name>`",
            staged.manifest.session
        )
    })?;
    if paths.session_exists(&name) {
        crate::fail!(
            ErrorCode::SessionExists,
            "session '{name}' already exists — import under another name with `--as <name>`"
        );
    }

    let dir = paths.ensure_session_dir(&name)?;
    let manifest = staged.manifest.clone();
    let counts = staged.counts;
    let migrated_from = staged.migrated_from;
    if let Err(e) = staged.install(&paths.session_db(&name)) {
        // Leave nothing half-created behind: the directory is one we just made.
        let _ = std::fs::remove_dir_all(&dir);
        return Err(anyhow::Error::new(e).context(format!(
            "installing the imported session into {}",
            dir.display()
        )));
    }

    if req.use_session {
        paths.set_active_session(&name)?;
    }

    Ok(ImportOutcome {
        session: name,
        manifest,
        counts,
        migrated_from,
        activated: req.use_session,
    })
}

/// Refuse to write through an existing symlink, and (unless `force`) to clobber
/// an existing file.
///
/// The symlink half is the security-relevant one: `std::fs::write` follows the
/// final component, so an attacker-seeded link at the output path would redirect
/// the write onto a victim file. `symlink_metadata` does not follow it, so the
/// link is caught. Shared with `export har`, which has always overwritten
/// silently (`force = true`) and keeps doing so.
pub fn guard_output_path(path: &Path, what: &str, force: bool) -> Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        crate::fail!(
            ErrorCode::InputUnsafePath,
            "refusing to write the {what} through an existing symlink: {}",
            path.display()
        );
    }
    if !force {
        crate::fail!(
            ErrorCode::InputFileExists,
            "{} already exists — pass --force to overwrite it",
            path.display()
        );
    }
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_store::model::{FlowStart, Protocol, RequestData, ResponseData};
    use burpwn_store::{schema, Store};

    async fn populate(paths: &Paths, session: &str) -> i64 {
        let store = Store::open(paths.session_db(session)).unwrap();
        let w = store.writer();
        let flow_id = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 1000,
                exec_id: Some("e1".into()),
                client_addr: "127.0.0.1:51000".into(),
                dst_ip: "93.184.216.34".into(),
                dst_port: 443,
                sni: Some("example.com".into()),
                scheme: "https".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            flow_id,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/search?q=needle".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Cookie: session=deadbeef\r\n".to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            flow_id,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"Content-Type: text/html\r\n".to_vec(),
                body: b"<html>needle</html>".to_vec(),
                timing_ms: Some(12),
            },
        )
        .await
        .unwrap();
        w.flow_end(flow_id, 1012).await.unwrap();
        w.tag_flow(flow_id, "interesting", None).await.unwrap();
        w.add_note(flow_id, "reflected", 1013).await.unwrap();
        let g = w
            .create_group(
                "auth-flow".to_string(),
                Some("login -> POST /login".to_string()),
                schema::DEFAULT_WORKSPACE_ID,
                1014,
            )
            .await
            .unwrap();
        w.add_flow_to_group(flow_id, g).await.unwrap();
        flow_id
    }

    fn code_of(err: &anyhow::Error) -> ErrorCode {
        crate::diag::diagnose(err).code
    }

    /// The user story, end to end: finish a session, hand the file over, open it
    /// on the other machine under a different name and find the work intact.
    #[tokio::test]
    async fn a_session_survives_the_trip_to_another_machine() {
        let mine = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(mine.path());
        paths.ensure_session_dir("acme").unwrap();
        let flow_id = populate(&paths, "acme").await;

        let out = mine.path().join("acme.burpwn");
        let exported = export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(out.clone()),
                redact: false,
                force: false,
            },
        )
        .unwrap();
        assert_eq!(exported.path, out);
        assert!(exported.bytes > 0);
        assert_eq!(exported.manifest.flow_count, 1);
        assert_eq!(exported.warning(), RAW_WARNING);

        // Another machine: a different data dir entirely.
        let theirs = tempfile::tempdir().unwrap();
        let their_paths = Paths::with_base(theirs.path());
        let imported = import_session(
            &their_paths,
            &ImportRequest {
                file: out.clone(),
                as_name: Some("from-colleague".into()),
                use_session: false,
            },
        )
        .unwrap();
        assert_eq!(imported.session, "from-colleague");
        assert_eq!(imported.manifest.session, "acme");
        assert_eq!(imported.counts.flows, 1);
        assert_eq!(imported.counts.groups, 1);
        assert_eq!(imported.counts.tags, 1);
        assert_eq!(imported.counts.notes, 1);
        assert!(imported.migrated_from.is_none());
        assert!(!imported.activated);
        // The import must not silently steal the active session.
        assert_eq!(their_paths.active_session(), crate::paths::DEFAULT_SESSION);

        let store = Store::open(their_paths.session_db("from-colleague")).unwrap();
        let detail = store.reader().get_flow(flow_id).unwrap().unwrap();
        assert_eq!(detail.request.as_ref().unwrap().path, "/search?q=needle");
        assert_eq!(detail.tags, vec!["interesting".to_string()]);
        assert_eq!(detail.notes, vec!["reflected".to_string()]);
        assert!(store
            .reader()
            .group_by_name("auth-flow", None)
            .unwrap()
            .is_some());
        assert!(their_paths
            .list_sessions()
            .contains(&"from-colleague".into()));
    }

    /// The default name comes from the bundle, and `--use` is the only thing
    /// that moves the `current` pointer.
    #[tokio::test]
    async fn the_bundle_names_the_session_and_use_switches_to_it() {
        let mine = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(mine.path());
        paths.ensure_session_dir("acme").unwrap();
        populate(&paths, "acme").await;
        let out = mine.path().join("acme.burpwn");
        export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(out.clone()),
                redact: false,
                force: false,
            },
        )
        .unwrap();

        let theirs = tempfile::tempdir().unwrap();
        let their_paths = Paths::with_base(theirs.path());
        let imported = import_session(
            &their_paths,
            &ImportRequest {
                file: out,
                as_name: None,
                use_session: true,
            },
        )
        .unwrap();
        assert_eq!(imported.session, "acme");
        assert!(imported.activated);
        assert_eq!(their_paths.active_session(), "acme");
    }

    /// Every refusal an operator can walk into, pinned to its catalogue code.
    #[tokio::test]
    async fn refusals_are_coded_and_leave_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("acme").unwrap();
        populate(&paths, "acme").await;

        // Exporting a session that was never captured into.
        let err = export_session(
            &paths,
            &ExportRequest {
                session: "ghost".into(),
                output: Some(dir.path().join("ghost.burpwn")),
                redact: false,
                force: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::SessionNotFound);

        // An invalid session name never becomes a path.
        let err = export_session(
            &paths,
            &ExportRequest {
                session: "../escape".into(),
                output: None,
                redact: false,
                force: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::SessionInvalidName);

        let out = dir.path().join("acme.burpwn");
        export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(out.clone()),
                redact: false,
                force: false,
            },
        )
        .unwrap();

        // Re-exporting over the same file needs --force…
        let err = export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(out.clone()),
                redact: false,
                force: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::InputFileExists);
        // …and with it, succeeds.
        export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(out.clone()),
                redact: true,
                force: true,
            },
        )
        .unwrap();

        // A symlink at the output path is refused even with --force.
        let link = dir.path().join("link.burpwn");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let err = export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(link),
                redact: false,
                force: true,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::InputUnsafePath);
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");

        // Importing something that is not a bundle.
        let junk = dir.path().join("notes.txt");
        std::fs::write(&junk, b"not a bundle").unwrap();
        let err = import_session(
            &paths,
            &ImportRequest {
                file: junk,
                as_name: None,
                use_session: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::SessionBundleInvalid);

        // Importing a file that is not there at all.
        let err = import_session(
            &paths,
            &ImportRequest {
                file: dir.path().join("nope.burpwn"),
                as_name: None,
                use_session: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::InputFileUnreadable);

        // Importing onto a name that is taken: refused, and the existing session
        // is untouched.
        let err = import_session(
            &paths,
            &ImportRequest {
                file: out.clone(),
                as_name: None,
                use_session: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::SessionExists);
        assert!(paths.session_db("acme").is_file());

        // An invalid `--as` name never becomes a path either.
        let err = import_session(
            &paths,
            &ImportRequest {
                file: out,
                as_name: Some("../evil".into()),
                use_session: false,
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ErrorCode::SessionInvalidName);

        // No failure left a staged file lying around in the sessions dir.
        let strays: Vec<_> = std::fs::read_dir(paths.sessions_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().map(|t| !t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        assert!(strays.is_empty(), "staged leftovers: {strays:?}");
        assert_eq!(paths.list_sessions(), vec!["acme".to_string()]);
    }

    /// `--redact` is opt-in and says so in the manifest, so the importing side
    /// can tell whether it was handed live credentials.
    #[tokio::test]
    async fn redaction_is_recorded_in_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("acme").unwrap();
        populate(&paths, "acme").await;

        let clean = export_session(
            &paths,
            &ExportRequest {
                session: "acme".into(),
                output: Some(dir.path().join("clean.burpwn")),
                redact: true,
                force: false,
            },
        )
        .unwrap();
        assert!(clean.manifest.redacted);
        assert_eq!(clean.warning(), REDACTED_WARNING);

        let theirs = tempfile::tempdir().unwrap();
        let their_paths = Paths::with_base(theirs.path());
        let imported = import_session(
            &their_paths,
            &ImportRequest {
                file: clean.path,
                as_name: None,
                use_session: false,
            },
        )
        .unwrap();
        assert!(imported.manifest.redacted);
    }

    /// A bundle can be exported while the daemon is still writing: the store is
    /// open, so the newest rows are in the WAL and nowhere else.
    #[tokio::test]
    async fn exporting_a_live_session_captures_the_wal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("live").unwrap();
        // Hold the store open for the duration, like a running daemon does.
        let store = Store::open(paths.session_db("live")).unwrap();
        populate(&paths, "live").await;

        let exported = export_session(
            &paths,
            &ExportRequest {
                session: "live".into(),
                output: Some(dir.path().join("live.burpwn")),
                redact: false,
                force: false,
            },
        )
        .unwrap();
        assert_eq!(exported.manifest.flow_count, 1);
        drop(store);
    }
}
