//! Session bundles: one portable file holding an entire session.
//!
//! A session is already self-contained — every request/response body lives in
//! the `blobs` table of `session.db`, there is no external payload directory —
//! so handing a session to someone else is "hand them the database". The catch
//! is that you cannot just `cp session.db`: the store runs in WAL mode, so a
//! session with a live daemon has committed rows sitting in `session.db-wal`
//! that a naive copy silently leaves behind.
//!
//! So a bundle is built with `VACUUM INTO`, which asks SQLite itself for a
//! transactionally consistent, fully checkpointed copy while the writer keeps
//! writing. The copy then gets a [`MANIFEST_TABLE`] describing where it came
//! from, and the whole thing is zstd-compressed behind a magic header:
//!
//! ```text
//! [ "BURPWNBUNDLE" ][ format:u8 ][ zstd frame: the SQLite database ]
//! ```
//!
//! The magic exists so that feeding burpwn a `.tar.gz`, a HAR or a truncated
//! download fails with "this is not a burpwn session bundle" instead of a
//! SQLite parse error 30 seconds later. zstd (rather than tar or a container
//! format) keeps the bundle to a single file with no new dependency — the store
//! already compresses blobs with it — and the payload stays an ordinary SQLite
//! database, so `zstd -d` plus `tail -c +14` is enough to open a bundle by hand.
//!
//! # Secrets
//!
//! A bundle is the session AS CAPTURED: `auth_profiles.token`, the
//! `auth_profiles.login_cmd` (which usually carries credentials in its argv),
//! and every `Authorization` / `Cookie` header recorded in the blobs. [`redact`]
//! covers the first two and the match/replace replacements; it deliberately does
//! NOT touch captured traffic (see its doc comment for why). Callers are
//! expected to say so out loud.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::StoreError;
use crate::schema::{self, SCHEMA_VERSION};

/// Magic prefix every bundle starts with.
pub const MAGIC: &[u8] = b"BURPWNBUNDLE";

/// Bundle container format. Bumped only if the framing itself changes; the
/// SQLite schema inside evolves on its own [`schema::SCHEMA_VERSION`] track.
pub const FORMAT_VERSION: u8 = 1;

/// [`MAGIC`] plus the one-byte format version.
const HEADER_LEN: usize = 13;

/// zstd level, matching [`crate::blob`]: the default ratio/speed balance.
const ZSTD_LEVEL: i32 = 3;

/// Ceiling on the database a bundle may unpack to. A bundle arrives from
/// somewhere else, so a hostile one could be a compression bomb; refusing at 4
/// GiB caps that at an error instead of a full disk, while staying far above
/// any real session (bodies are capped at 8 MiB each).
pub const MAX_BUNDLE_DB: u64 = 4 * 1024 * 1024 * 1024;

/// The key/value table carrying the bundle's provenance. Dropped on import: it
/// describes the transfer, not the session.
pub const MANIFEST_TABLE: &str = "bundle_manifest";

/// What [`redact`] leaves behind in place of a secret.
pub const REDACTED: &str = "(redacted by --redact)";

// Manifest keys. Stable: an older burpwn reading a newer bundle must still find
// what it knows.
const K_BURPWN_VERSION: &str = "burpwn_version";
const K_SCHEMA_VERSION: &str = "schema_version";
const K_SESSION: &str = "session";
const K_EXPORTED_AT: &str = "exported_at";
const K_FLOW_COUNT: &str = "flow_count";
const K_CA_SHA256: &str = "ca_sha256";
const K_REDACTED: &str = "redacted";

/// Bundle-specific failures. Everything else is a plain [`StoreError`].
#[derive(Debug, Error)]
pub enum BundleError {
    /// The file is not a bundle: wrong magic, truncated, corrupt, or written by
    /// a burpwn whose container format this build does not know.
    #[error("{0}")]
    NotABundle(String),

    /// The bundle unpacks to more than [`MAX_BUNDLE_DB`] bytes.
    #[error("the bundle unpacks to more than {limit} bytes — refusing to write it out")]
    TooLarge {
        /// The ceiling that was exceeded.
        limit: u64,
    },

    /// A storage-layer failure (SQLite, I/O, an incompatible schema).
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl burpwn_error::Coded for BundleError {
    fn code(&self) -> burpwn_error::ErrorCode {
        use burpwn_error::ErrorCode as C;
        match self {
            BundleError::NotABundle(_) | BundleError::TooLarge { .. } => C::SessionBundleInvalid,
            BundleError::Store(e) => e.code(),
        }
    }
}

impl From<rusqlite::Error> for BundleError {
    fn from(e: rusqlite::Error) -> Self {
        BundleError::Store(e.into())
    }
}

impl From<std::io::Error> for BundleError {
    fn from(e: std::io::Error) -> Self {
        BundleError::Store(e.into())
    }
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, BundleError>;

/// What a bundle says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleManifest {
    /// Container format version the file was written with.
    pub format: u8,
    /// burpwn version that produced it.
    pub burpwn_version: String,
    /// `PRAGMA user_version` of the database inside.
    pub schema_version: i64,
    /// Name of the session it was exported from (the default import name).
    pub session: String,
    /// Export time, milliseconds since the epoch.
    pub exported_at: i64,
    /// Flows in the bundle at export time.
    pub flow_count: i64,
    /// SHA-256 of the exporting install's CA certificate, hex. Informational:
    /// the private key is never bundled, so an imported session's captures were
    /// signed by a CA the importer does not have.
    pub ca_sha256: Option<String>,
    /// Whether [`redact`] was applied.
    pub redacted: bool,
}

/// Row counts of the things a user thinks of as "their session".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BundleCounts {
    /// Captured flows.
    pub flows: i64,
    /// Workspaces.
    pub workspaces: i64,
    /// Flow groups.
    pub groups: i64,
    /// Tags.
    pub tags: i64,
    /// Notes.
    pub notes: i64,
    /// Fuzzing attacks.
    pub attacks: i64,
}

/// Inputs to [`export`] that only the caller knows.
#[derive(Debug, Clone)]
pub struct ExportOptions<'a> {
    /// Name of the session being exported (recorded in the manifest).
    pub session: &'a str,
    /// Version string to stamp (`env!("CARGO_PKG_VERSION")` at the call site).
    pub burpwn_version: &'a str,
    /// Export timestamp, milliseconds since the epoch.
    pub exported_at: i64,
    /// The install's CA certificate, hashed into the manifest if it exists.
    pub ca_pem: Option<&'a Path>,
    /// Strip the stored credentials (see [`redact`] for the exact scope).
    pub redact: bool,
}

/// Write `db` out as a bundle at `out`, which must not already exist.
///
/// `out` is created `0600`: a raw bundle is a credential store.
pub fn export(db: &Path, out: &Path, opts: &ExportOptions<'_>) -> Result<BundleManifest> {
    let tmp = TempPath::beside(out, "export")?;
    snapshot(db, tmp.path())?;

    let conn = Connection::open(tmp.path())?;
    if opts.redact {
        redact(&conn)?;
    }
    let manifest = build_manifest(&conn, opts)?;
    write_manifest(&conn, &manifest)?;
    // Close explicitly so the rollback journal is gone before we compress the
    // file — otherwise the bundle could carry a half-applied transaction.
    conn.close().map_err(|(_, e)| BundleError::from(e))?;

    compress(tmp.path(), out)?;
    Ok(manifest)
}

/// A bundle unpacked next to its destination, validated and migrated, waiting
/// to be moved into place by [`StagedBundle::install`].
///
/// Staging exists because the import name is only known once the manifest has
/// been read, and because a bundle that fails validation must leave nothing
/// behind: dropping a `StagedBundle` that was never installed deletes the file.
#[derive(Debug)]
pub struct StagedBundle {
    path: PathBuf,
    /// What the bundle says about itself.
    pub manifest: BundleManifest,
    /// Row counts after any migration.
    pub counts: BundleCounts,
    /// `Some(v)` when the bundle carried an older schema that was migrated up
    /// to [`SCHEMA_VERSION`] during staging.
    pub migrated_from: Option<i64>,
    installed: bool,
}

impl StagedBundle {
    /// The staged database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Move the staged database to `dest` (same filesystem — that is why the
    /// caller chooses the staging directory).
    pub fn install(mut self, dest: &Path) -> Result<()> {
        std::fs::rename(&self.path, dest)?;
        self.installed = true;
        Ok(())
    }
}

impl Drop for StagedBundle {
    fn drop(&mut self) {
        if !self.installed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Unpack and validate `bundle` into a temporary file under `staging_dir`.
///
/// Validation order matters: magic and format first (so a wrong file type is
/// named as such), then the schema version — a bundle from a NEWER burpwn is
/// refused with [`StoreError::IncompatibleSchema`] rather than migrated
/// downwards, while an older one is migrated up here, before anything is moved
/// into place, so a failed migration cannot leave half a session on disk.
pub fn stage(bundle: &Path, staging_dir: &Path) -> Result<StagedBundle> {
    let staged = TempPath::in_dir(staging_dir, "import")?;
    let format = decompress(bundle, staged.path())?;

    let conn = Connection::open(staged.path())?;
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let mut manifest = read_manifest(&conn)?;
    manifest.format = format;

    if found > SCHEMA_VERSION {
        return Err(StoreError::IncompatibleSchema {
            found,
            supported: SCHEMA_VERSION,
        }
        .into());
    }

    conn.execute_batch(&format!("DROP TABLE IF EXISTS {MANIFEST_TABLE};"))?;
    // The ordinary migration path: an older bundle is brought up to date the
    // same way opening an older session.db would.
    schema::init(&conn)?;
    let counts = counts(&conn)?;
    conn.close().map_err(|(_, e)| BundleError::from(e))?;

    Ok(StagedBundle {
        path: staged.into_path(),
        manifest,
        counts,
        migrated_from: (found < SCHEMA_VERSION).then_some(found),
        installed: false,
    })
}

/// Drop the credentials burpwn itself stored: the auth profiles' tokens and
/// login commands (whose argv routinely carries a password), and every
/// match/replace replacement (which is where an injected `Authorization` value
/// lives).
///
/// ⚠️ It stops there. Credentials CAPTURED inside recorded traffic —
/// `Authorization` / `Cookie` / `Set-Cookie` headers, login request bodies —
/// stay in the bundle. Scrubbing those would mean rewriting content-addressed,
/// deduplicated, compressed blobs (changing their SHA-256, so every reference
/// and the dedup identity with it) and rebuilding the `flows_fts` rows that
/// index the same text — a lot of moving parts to end up with a file that still
/// leaks whatever a body happened to contain. The honest contract is the
/// narrow one, stated plainly, rather than a broad one that quietly holds only
/// some of the time.
pub fn redact(conn: &Connection) -> Result<()> {
    if table_exists(conn, "auth_profiles")? {
        conn.execute(
            "UPDATE auth_profiles SET token = NULL, login_cmd = ?1",
            [REDACTED],
        )?;
    }
    if table_exists(conn, "match_replace_rules")? {
        conn.execute(
            "UPDATE match_replace_rules SET replacement = ?1",
            [REDACTED],
        )?;
    }
    Ok(())
}

// --- internals --------------------------------------------------------------

/// `VACUUM INTO`: SQLite's own consistent-copy primitive. It reads through the
/// normal read path, so committed rows still living in the `-wal` file are in
/// the copy — which a `cp session.db` would drop on the floor. Deliberately
/// does NOT run [`schema::init`]: exporting must never migrate the session the
/// user is working in.
fn snapshot(db: &Path, dest: &Path) -> Result<()> {
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    conn.execute("VACUUM INTO ?1", [path_str(dest)?])?;
    conn.close().map_err(|(_, e)| BundleError::from(e))?;
    Ok(())
}

/// Magic + format byte + a zstd frame of the database.
fn compress(db: &Path, out: &Path) -> Result<()> {
    // `create_new` is both the "do not clobber" guard and the symlink guard:
    // O_EXCL|O_CREAT refuses to follow an existing link.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)?;
    file.write_all(MAGIC)?;
    file.write_all(&[FORMAT_VERSION])?;
    let mut src = File::open(db)?;
    zstd::stream::copy_encode(&mut src, &mut file, ZSTD_LEVEL)?;
    file.flush()?;
    Ok(())
}

/// Validate the header and unpack the database to `dest`. Returns the format
/// version the file declared.
fn decompress(bundle: &Path, dest: &Path) -> Result<u8> {
    let mut file = File::open(bundle)?;
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header).map_err(|_| {
        BundleError::NotABundle(format!(
            "{} is too short to be a burpwn session bundle",
            bundle.display()
        ))
    })?;
    if &header[..MAGIC.len()] != MAGIC {
        return Err(BundleError::NotABundle(format!(
            "{} is not a burpwn session bundle (no BURPWNBUNDLE header) — bundles are the files \
             written by `burpwn export session`",
            bundle.display()
        )));
    }
    let format = header[MAGIC.len()];
    if format > FORMAT_VERSION {
        return Err(BundleError::NotABundle(format!(
            "{} uses bundle format v{format}, newer than this burpwn understands (v{FORMAT_VERSION})",
            bundle.display()
        )));
    }

    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)?;
    let mut decoder = zstd::stream::read::Decoder::new(file)?;
    let mut limited = (&mut decoder).take(MAX_BUNDLE_DB + 1);
    let written = std::io::copy(&mut limited, &mut out).map_err(|e| {
        BundleError::NotABundle(format!(
            "{} could not be unpacked (truncated or corrupt): {e}",
            bundle.display()
        ))
    })?;
    out.flush()?;
    if written > MAX_BUNDLE_DB {
        return Err(BundleError::TooLarge {
            limit: MAX_BUNDLE_DB,
        });
    }
    Ok(format)
}

fn build_manifest(conn: &Connection, opts: &ExportOptions<'_>) -> Result<BundleManifest> {
    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(BundleManifest {
        format: FORMAT_VERSION,
        burpwn_version: opts.burpwn_version.to_string(),
        schema_version,
        session: opts.session.to_string(),
        exported_at: opts.exported_at,
        flow_count: count_of(conn, "flows")?,
        ca_sha256: opts.ca_pem.and_then(sha256_file),
        redacted: opts.redact,
    })
}

fn write_manifest(conn: &Connection, m: &BundleManifest) -> Result<()> {
    conn.execute_batch(&format!(
        "DROP TABLE IF EXISTS {MANIFEST_TABLE};
         CREATE TABLE {MANIFEST_TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
    ))?;
    let mut rows: Vec<(&str, String)> = vec![
        (K_BURPWN_VERSION, m.burpwn_version.clone()),
        (K_SCHEMA_VERSION, m.schema_version.to_string()),
        (K_SESSION, m.session.clone()),
        (K_EXPORTED_AT, m.exported_at.to_string()),
        (K_FLOW_COUNT, m.flow_count.to_string()),
        (K_REDACTED, u8::from(m.redacted).to_string()),
    ];
    if let Some(fp) = &m.ca_sha256 {
        rows.push((K_CA_SHA256, fp.clone()));
    }
    let mut stmt = conn.prepare(&format!(
        "INSERT INTO {MANIFEST_TABLE}(key, value) VALUES (?1, ?2)"
    ))?;
    for (k, v) in rows {
        stmt.execute(rusqlite::params![k, v])?;
    }
    Ok(())
}

fn read_manifest(conn: &Connection) -> Result<BundleManifest> {
    if !table_exists(conn, MANIFEST_TABLE)? {
        return Err(BundleError::NotABundle(
            "the file unpacks to a database with no bundle manifest — it may be a bare \
             session.db rather than a `burpwn export session` bundle"
                .into(),
        ));
    }
    let mut stmt = conn.prepare(&format!("SELECT key, value FROM {MANIFEST_TABLE}"))?;
    let mut kv: HashMap<String, String> = HashMap::new();
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for row in rows {
        let (k, v) = row?;
        kv.insert(k, v);
    }

    let need = |key: &str| -> Result<String> {
        kv.get(key).cloned().ok_or_else(|| {
            BundleError::NotABundle(format!("the bundle manifest is missing `{key}`"))
        })
    };
    let num = |key: &str, raw: String| -> Result<i64> {
        raw.parse::<i64>().map_err(|_| {
            BundleError::NotABundle(format!("the bundle manifest has a non-numeric `{key}`"))
        })
    };

    let schema_version = num(K_SCHEMA_VERSION, need(K_SCHEMA_VERSION)?)?;
    let exported_at = num(K_EXPORTED_AT, need(K_EXPORTED_AT)?)?;
    let flow_count = num(K_FLOW_COUNT, need(K_FLOW_COUNT)?)?;
    Ok(BundleManifest {
        format: FORMAT_VERSION,
        burpwn_version: need(K_BURPWN_VERSION)?,
        schema_version,
        session: need(K_SESSION)?,
        exported_at,
        flow_count,
        ca_sha256: kv.get(K_CA_SHA256).cloned(),
        redacted: kv.get(K_REDACTED).map(|v| v == "1").unwrap_or(false),
    })
}

fn counts(conn: &Connection) -> Result<BundleCounts> {
    Ok(BundleCounts {
        flows: count_of(conn, "flows")?,
        workspaces: count_of(conn, "workspaces")?,
        groups: count_of(conn, "groups")?,
        tags: count_of(conn, "tags")?,
        notes: count_of(conn, "notes")?,
        attacks: count_of(conn, "attacks")?,
    })
}

/// `COUNT(*)` of a table that may not exist yet (a pre-v4 bundle has no
/// `attacks`). `table` is always one of this module's own literals, never user
/// input, so interpolating it is safe.
fn count_of(conn: &Connection, table: &str) -> Result<i64> {
    if !table_exists(conn, table)? {
        return Ok(0);
    }
    Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn sha256_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        BundleError::Store(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path is not valid UTF-8: {}", path.display()),
        )))
    })
}

/// A path we intend to create and are responsible for cleaning up. Removed on
/// drop unless [`TempPath::into_path`] hands ownership on.
#[derive(Debug)]
struct TempPath {
    path: PathBuf,
    armed: bool,
}

impl TempPath {
    fn in_dir(dir: &Path, tag: &str) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let name = format!(".burpwn-{tag}-{}-{nanos}.tmp", std::process::id());
        Ok(Self {
            path: dir.join(name),
            armed: true,
        })
    }

    /// A temp path in the same directory as `file`, so a later rename stays on
    /// one filesystem and the temp copy never lands somewhere with different
    /// space or permissions than the destination.
    fn beside(file: &Path, tag: &str) -> Result<Self> {
        let dir = match file.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        Self::in_dir(dir, tag)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn into_path(mut self) -> PathBuf {
        self.armed = false;
        self.path.clone()
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FlowStart, MatchKind, NewAuthProfile, NewMatchReplaceRule, Protocol, RequestData,
        ResponseData,
    };
    use crate::Store;
    use tempfile::TempDir;

    fn opts<'a>(session: &'a str, redact: bool) -> ExportOptions<'a> {
        ExportOptions {
            session,
            burpwn_version: "0.0.0-test",
            exported_at: 1_700_000_000_000,
            ca_pem: None,
            redact,
        }
    }

    /// Populate a session with one of everything a user would be upset to lose.
    async fn populate(store: &Store) -> i64 {
        let w = store.writer();
        let flow_id = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 1000,
                exec_id: Some("exec-1".into()),
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
                headers: b"Authorization: Bearer s3cr3t\r\n".to_vec(),
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
        w.tag_flow(flow_id, "interesting", Some("red".to_string()))
            .await
            .unwrap();
        w.add_note(flow_id, "reflected in the title", 1013)
            .await
            .unwrap();
        let group = w
            .create_group(
                "auth-flow".to_string(),
                Some("login form -> POST /login".to_string()),
                schema::DEFAULT_WORKSPACE_ID,
                1014,
            )
            .await
            .unwrap();
        w.add_flow_to_group(flow_id, group).await.unwrap();
        w.create_workspace("staging", 1015).await.unwrap();
        flow_id
    }

    /// Flows in a database file, tolerating one so incomplete it has no `flows`
    /// table yet — which is exactly what a naive copy of a WAL database looks
    /// like.
    fn flow_count_of(db: &Path) -> i64 {
        let conn = Connection::open(db).unwrap();
        count_of(&conn, "flows").unwrap()
    }

    /// The whole point: export a session, unpack it somewhere else, and find
    /// every flow, group, tag and note where it was.
    #[tokio::test]
    async fn roundtrip_carries_the_whole_session() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        let flow_id = {
            let store = Store::open(&db).unwrap();
            populate(&store).await
        };

        let bundle = dir.path().join("work.burpwn");
        let manifest = export(&db, &bundle, &opts("work", false)).unwrap();
        assert_eq!(manifest.session, "work");
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.flow_count, 1);
        assert!(!manifest.redacted);

        // The file is a bundle, not a database: magic first, 0600.
        let head = std::fs::read(&bundle).unwrap();
        assert_eq!(&head[..MAGIC.len()], MAGIC);
        assert_eq!(head[MAGIC.len()], FORMAT_VERSION);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&bundle).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a raw bundle is a credential store");
        }

        let dest = TempDir::new().unwrap();
        let staged = stage(&bundle, dest.path()).unwrap();
        assert_eq!(staged.manifest.session, "work");
        assert_eq!(staged.counts.flows, 1);
        assert_eq!(staged.counts.groups, 1);
        assert_eq!(staged.counts.tags, 1);
        assert_eq!(staged.counts.notes, 1);
        assert_eq!(staged.counts.workspaces, 2);
        assert!(staged.migrated_from.is_none());

        let imported = dest.path().join("session.db");
        staged.install(&imported).unwrap();

        // The imported copy opens as an ordinary session, bodies and all.
        let store = Store::open(&imported).unwrap();
        let detail = store.reader().get_flow(flow_id).unwrap().unwrap();
        assert_eq!(detail.request.as_ref().unwrap().path, "/search?q=needle");
        assert_eq!(
            detail.response.as_ref().unwrap().body,
            b"<html>needle</html>".to_vec()
        );
        assert!(store
            .reader()
            .group_by_name("auth-flow", None)
            .unwrap()
            .is_some());
        // The manifest table is transfer metadata; it does not become part of
        // the session.
        let conn = Connection::open(&imported).unwrap();
        assert!(!table_exists(&conn, MANIFEST_TABLE).unwrap());
    }

    /// The reason a bundle is not `cp session.db`: with a live store the newest
    /// rows are still in the `-wal` file, and only `VACUUM INTO` sees them.
    #[tokio::test]
    async fn export_captures_uncheckpointed_wal_writes() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        // Keep the store OPEN for the whole test: no connection closes, so
        // nothing checkpoints the WAL back into the main database.
        let store = Store::open(&db).unwrap();
        populate(&store).await;
        assert!(
            db.with_extension("db-wal").exists(),
            "the test is meaningless without a WAL file"
        );

        // A naive copy of session.db alone loses the writes.
        let naive = dir.path().join("naive.db");
        std::fs::copy(&db, &naive).unwrap();
        assert_eq!(
            flow_count_of(&naive),
            0,
            "the writes should still live only in the WAL — that is the bug this guards against"
        );

        let bundle = dir.path().join("live.burpwn");
        let manifest = export(&db, &bundle, &opts("live", false)).unwrap();
        assert_eq!(manifest.flow_count, 1, "VACUUM INTO must see the WAL");

        let dest = TempDir::new().unwrap();
        let staged = stage(&bundle, dest.path()).unwrap();
        assert_eq!(staged.counts.flows, 1);
    }

    /// `--redact` purges exactly what it claims to purge — and nothing more, so
    /// the honest scope stays pinned by a test rather than by a doc comment.
    #[tokio::test]
    async fn redact_purges_stored_credentials_only() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        {
            let store = Store::open(&db).unwrap();
            let flow_id = populate(&store).await;
            let w = store.writer();
            let rule = w
                .add_match_replace(NewMatchReplaceRule {
                    enabled: true,
                    scope: "example.com".into(),
                    match_kind: MatchKind::Header,
                    pattern: "Authorization".into(),
                    replacement: "Authorization: Bearer s3cr3t".into(),
                    on_request: true,
                })
                .await
                .unwrap();
            w.upsert_auth_profile(NewAuthProfile {
                host: "example.com".into(),
                login_cmd: "curl -u admin:hunter2 https://example.com/login".into(),
                extract_regex: "\"token\":\"([^\"]+)\"".into(),
                header_template: "Authorization: Bearer {}".into(),
            })
            .await
            .unwrap();
            w.set_auth_token("example.com", Some("s3cr3t".into()), Some(rule), 1017)
                .await
                .unwrap();
            let _ = flow_id;
        }

        // Raw export: everything is there, on purpose.
        let raw = dir.path().join("raw.burpwn");
        export(&db, &raw, &opts("work", false)).unwrap();
        let raw_dir = TempDir::new().unwrap();
        let staged = stage(&raw, raw_dir.path()).unwrap();
        assert!(!staged.manifest.redacted);
        let raw_db = raw_dir.path().join("session.db");
        staged.install(&raw_db).unwrap();
        let store = Store::open(&raw_db).unwrap();
        let profile = store.reader().auth_profiles().unwrap().remove(0);
        assert_eq!(profile.token.as_deref(), Some("s3cr3t"));
        assert!(profile.login_cmd.contains("hunter2"));

        // Redacted export: the stored credentials are gone.
        let clean = dir.path().join("clean.burpwn");
        let manifest = export(&db, &clean, &opts("work", true)).unwrap();
        assert!(manifest.redacted);
        let clean_dir = TempDir::new().unwrap();
        let staged = stage(&clean, clean_dir.path()).unwrap();
        assert!(staged.manifest.redacted);
        let clean_db = clean_dir.path().join("session.db");
        staged.install(&clean_db).unwrap();
        let store = Store::open(&clean_db).unwrap();
        let profile = store.reader().auth_profiles().unwrap().remove(0);
        assert!(profile.token.is_none());
        assert_eq!(profile.login_cmd, REDACTED);
        let rules = store.reader().list_match_replace().unwrap();
        assert_eq!(rules[0].replacement, REDACTED);
        // …and the capture itself is untouched: the Authorization header the
        // proxy recorded is still in the blob. Documented, not accidental.
        let flows = store
            .reader()
            .list_flows(&crate::model::FlowFilter::default())
            .unwrap();
        let detail = store.reader().get_flow(flows[0].id).unwrap().unwrap();
        let headers = &detail.request.as_ref().unwrap().headers;
        assert!(
            String::from_utf8_lossy(headers).contains("s3cr3t"),
            "--redact does not scrub captured traffic; if that changes, say so"
        );

        // The source session is never modified by an export, redacted or not.
        let store = Store::open(&db).unwrap();
        assert_eq!(
            store.reader().auth_profiles().unwrap()[0].token.as_deref(),
            Some("s3cr3t")
        );
    }

    /// Anything that is not a bundle must be named as such, not blow up as a
    /// SQLite parse error.
    #[test]
    fn non_bundles_are_refused_by_the_magic() {
        let dir = TempDir::new().unwrap();
        let staging = dir.path().join("staging");

        let garbage = dir.path().join("notes.txt");
        std::fs::write(&garbage, b"this is not a bundle, it is a shopping list").unwrap();
        let err = stage(&garbage, &staging).unwrap_err();
        assert!(matches!(err, BundleError::NotABundle(_)), "{err}");

        // A file too short to even hold the header.
        let tiny = dir.path().join("tiny.burpwn");
        std::fs::write(&tiny, b"BUR").unwrap();
        assert!(matches!(
            stage(&tiny, &staging).unwrap_err(),
            BundleError::NotABundle(_)
        ));

        // Right magic, unknown container version.
        let future = dir.path().join("future.burpwn");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT_VERSION + 1);
        bytes.extend_from_slice(b"whatever");
        std::fs::write(&future, &bytes).unwrap();
        let err = stage(&future, &staging).unwrap_err();
        assert!(format!("{err}").contains("newer than this burpwn"), "{err}");

        // Right magic, corrupt zstd body.
        let corrupt = dir.path().join("corrupt.burpwn");
        let mut bytes = MAGIC.to_vec();
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&[0xff; 64]);
        std::fs::write(&corrupt, &bytes).unwrap();
        assert!(matches!(
            stage(&corrupt, &staging).unwrap_err(),
            BundleError::NotABundle(_)
        ));

        // Nothing was left behind in the staging directory by the failures.
        let leftovers: Vec<_> = std::fs::read_dir(&staging)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "staging leftovers: {leftovers:?}");
    }

    /// A bundle written by a newer burpwn is refused with the schema code, not
    /// migrated downwards into corruption.
    #[tokio::test]
    async fn a_bundle_from_a_newer_burpwn_is_refused() {
        use burpwn_error::Coded;

        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        {
            let store = Store::open(&db).unwrap();
            populate(&store).await;
        }
        // Stamp a schema version from the future.
        {
            let conn = Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 7)
                .unwrap();
        }

        let bundle = dir.path().join("future.burpwn");
        export(&db, &bundle, &opts("work", false)).unwrap();

        let dest = TempDir::new().unwrap();
        let err = stage(&bundle, dest.path()).unwrap_err();
        assert_eq!(err.code(), burpwn_error::ErrorCode::StoreSchemaTooNew);
        assert!(dest.path().read_dir().unwrap().next().is_none());
    }

    /// An older bundle migrates on the way in, exactly as opening an old
    /// session.db would.
    #[tokio::test]
    async fn an_older_bundle_migrates_on_import() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        {
            let store = Store::open(&db).unwrap();
            populate(&store).await;
        }
        {
            let conn = Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", 3).unwrap();
        }

        let bundle = dir.path().join("old.burpwn");
        let manifest = export(&db, &bundle, &opts("work", false)).unwrap();
        assert_eq!(manifest.schema_version, 3);

        let dest = TempDir::new().unwrap();
        let staged = stage(&bundle, dest.path()).unwrap();
        assert_eq!(staged.migrated_from, Some(3));
        assert_eq!(staged.counts.flows, 1);
        let imported = dest.path().join("session.db");
        staged.install(&imported).unwrap();
        let conn = Connection::open(&imported).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn export_refuses_to_clobber_an_existing_file() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        {
            let store = Store::open(&db).unwrap();
            populate(&store).await;
        }
        let bundle = dir.path().join("taken.burpwn");
        std::fs::write(&bundle, b"precious").unwrap();
        assert!(export(&db, &bundle, &opts("work", false)).is_err());
        assert_eq!(std::fs::read(&bundle).unwrap(), b"precious");
    }

    #[test]
    fn header_length_matches_the_magic() {
        assert_eq!(HEADER_LEN, MAGIC.len() + 1);
    }
}
