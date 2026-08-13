//! burpwn-store — per-session SQLite storage with a single-writer task, content-addressed
//! blob deduplication and FTS5 full-text search over message bodies.
//!
//! The proxy hot path never touches SQLite directly: it sends [`WriteOp`] messages over a
//! bounded channel to a dedicated writer task that owns the write connection. Reads go through
//! a separate read-only connection pool (WAL allows concurrent readers with the single writer).
//!
//! # Layout
//!
//! - ONE SQLite file per session (`session.db`), opened in WAL mode with
//!   `synchronous=NORMAL`.
//! - A single [`writer`] task owns the lone write [`rusqlite::Connection`] and
//!   consumes [`WriteOp`]s from a bounded `tokio::sync::mpsc` channel (see
//!   [`writer`] for the concurrency rationale).
//! - Reads go through an r2d2 pool of read-only connections ([`Reader`]).
//! - [`blob`] gives content-addressed, zstd-compressed, SHA-256-deduplicated
//!   payload storage.
//! - [`bundle`] packs a whole session into one portable file (`VACUUM INTO` +
//!   manifest + zstd) and unpacks one back, so a session can travel to another
//!   machine.
//!
//! # Example
//!
//! ```no_run
//! # use burpwn_store::{Store, model::{FlowStart, Protocol, RequestData}};
//! # async fn run() -> burpwn_store::Result<()> {
//! let store = Store::open("session.db")?;
//! let w = store.writer();
//! let flow_id = w.flow_start(FlowStart {
//!     workspace_id: 1,
//!     ts_start: 0,
//!     exec_id: None,
//!     client_addr: "127.0.0.1:5000".into(),
//!     dst_ip: "10.0.0.1".into(),
//!     dst_port: 443,
//!     sni: Some("example.com".into()),
//!     scheme: "https".into(),
//!     protocol: Protocol::H1,
//!     intercepted: false,
//! }).await?;
//! let detail = store.reader().get_flow(flow_id)?;
//! # Ok(()) }
//! ```

pub mod blob;
pub mod bundle;
pub mod error;
pub mod model;
pub mod reader;
pub mod schema;
pub mod writer;

use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OpenFlags};
use tokio::sync::mpsc;

pub use error::{Result, StoreError};
pub use reader::Reader;
pub use writer::{AckReply, IdReply, IdsReply};
pub use writer::{WriteHandle, WriteOp, DEFAULT_CHANNEL_CAP};

/// A per-session store: owns the writer task handle and the read pool.
///
/// Cheap to clone the pieces you need: call [`Store::writer`] for a write handle
/// and [`Store::reader`] for a read view. Dropping every [`WriteHandle`] closes
/// the writer channel and shuts the writer task down cleanly.
pub struct Store {
    write_handle: WriteHandle,
    reader: Reader,
}

impl Store {
    /// Open (creating if necessary) the session database at `path`, run
    /// migrations, seed the default workspace, and spawn the writer task.
    ///
    /// Must be called from within a Tokio runtime (it spawns a blocking writer
    /// task via [`tokio::task::spawn_blocking`]).
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        Self::open_with_capacity(path, DEFAULT_CHANNEL_CAP)
    }

    /// Like [`Store::open`] but with an explicit writer-channel capacity.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Result<Store> {
        let path = path.as_ref();

        // 1. Writer connection: read-write, applies schema + WAL.
        let write_conn = Connection::open(path)?;
        configure_connection(&write_conn, true)?;
        schema::init(&write_conn)?;

        // 2. Read pool. NOTE: we open these handles READ_WRITE rather than
        // SQLITE_OPEN_READ_ONLY and enforce read-only semantics with
        // `PRAGMA query_only = ON`. A pure READ_ONLY handle cannot create or
        // write the WAL `-shm` shared-memory file, so against a WAL database it
        // can fail to attach ("unable to open database file") when the shm does
        // not already exist. `query_only` gives us the same safety (any write
        // attempt errors) while staying fully WAL-compatible.
        let manager = SqliteConnectionManager::file(path)
            .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_init(|c| c.execute_batch("PRAGMA busy_timeout = 5000; PRAGMA query_only = ON;"));
        // `with_init` runs once per physical connection. Register a customizer
        // that re-asserts `query_only = ON` on every checkout, so a pooled
        // "reader" can never silently become a writer (e.g. if some code path
        // ever flipped the pragma off on a connection handed back to the pool).
        let pool = Pool::builder()
            .connection_customizer(Box::new(ReadOnlyCustomizer))
            .build(manager)?;

        // 3. Spawn the writer task, owning the write connection.
        let (tx, rx) = mpsc::channel::<WriteOp>(capacity);
        writer::spawn_writer(write_conn, rx);

        Ok(Store {
            write_handle: WriteHandle::new(tx),
            reader: Reader::new(pool),
        })
    }

    /// A cheaply-cloneable write handle for the proxy hot path.
    pub fn writer(&self) -> WriteHandle {
        self.write_handle.clone()
    }

    /// A read-only view backed by the connection pool.
    pub fn reader(&self) -> Reader {
        self.reader.clone()
    }
}

/// Apply the standard PRAGMA posture. For the writer connection we enable WAL +
/// `synchronous=NORMAL` (durable enough with WAL, far faster than FULL) and FK
/// enforcement; `busy_timeout` lets transient locks back off instead of erroring.
fn configure_connection(conn: &Connection, writer: bool) -> Result<()> {
    if writer {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;\
             PRAGMA synchronous = NORMAL;\
             PRAGMA foreign_keys = ON;\
             PRAGMA busy_timeout = 5000;",
        )?;
    } else {
        conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    }
    Ok(())
}

/// Re-asserts `PRAGMA query_only = ON` on every read-pool checkout.
///
/// `r2d2`'s `with_init` only runs once per physical connection, so on its own it
/// cannot guarantee a recycled connection is still read-only. This customizer's
/// `on_acquire` runs on every checkout, so a pooled reader can never silently
/// become a writer — any write attempt through it errors at the SQLite layer.
#[derive(Debug)]
struct ReadOnlyCustomizer;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for ReadOnlyCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> std::result::Result<(), rusqlite::Error> {
        conn.execute_batch("PRAGMA query_only = ON;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FlowFilter, FlowStart, InterceptState, MatchKind, NewAttack, NewAttackResult,
        NewMatchReplaceRule, Protocol, RequestData, ResponseData, WsDirection,
    };
    use tempfile::TempDir;

    fn sample_flow() -> FlowStart {
        FlowStart {
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
        }
    }

    #[tokio::test]
    async fn open_creates_schema_and_default_workspace_and_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("session.db");

        {
            let store = Store::open(&path).unwrap();
            let ws = store.reader().list_workspaces().unwrap();
            assert_eq!(ws.len(), 1);
            assert_eq!(ws[0].name, "default");
        }
        // Re-open the same file: still one workspace, no corruption.
        {
            let store = Store::open(&path).unwrap();
            let ws = store.reader().list_workspaces().unwrap();
            assert_eq!(ws.len(), 1);
        }
    }

    #[tokio::test]
    async fn full_flow_roundtrip_with_decoded_bodies() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.request(
            flow_id,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/secret".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Host: example.com\r\nAccept: */*\r\n".to_vec(),
                body: b"needle-in-the-request".to_vec(),
            },
        )
        .await
        .unwrap();
        w.response(
            flow_id,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"Content-Type: text/plain\r\n".to_vec(),
                body: b"hello haystack response".to_vec(),
                timing_ms: Some(42),
            },
        )
        .await
        .unwrap();
        w.flow_end(flow_id, 2000).await.unwrap();

        let detail = store.reader().get_flow(flow_id).unwrap().unwrap();
        assert_eq!(detail.flow.id, flow_id);
        assert_eq!(detail.flow.ts_end, Some(2000));
        assert_eq!(detail.exec_id.as_deref(), Some("exec-1"));
        let req = detail.request.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/secret");
        assert_eq!(req.body, b"needle-in-the-request");
        // Header bytes are preserved verbatim (order-preserving raw blob).
        assert_eq!(req.headers, b"Host: example.com\r\nAccept: */*\r\n");
        let resp = detail.response.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.timing_ms, Some(42));
        assert_eq!(resp.body, b"hello haystack response");

        // It shows up in list_flows with the joined request/response summary.
        let rows = store.reader().list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].method.as_deref(), Some("GET"));
        assert_eq!(rows[0].status, Some(200));
    }

    #[tokio::test]
    async fn fts_search_finds_flow_by_body_token() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.request(
            flow_id,
            RequestData {
                method: "POST".into(),
                authority: "example.com".into(),
                path: "/login".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: b"username=admin&token=supersecrettoken".to_vec(),
            },
        )
        .await
        .unwrap();

        let hits = store.reader().search("supersecrettoken").unwrap();
        assert!(hits.contains(&flow_id), "FTS should find the body token");

        let none = store.reader().search("absent_term_xyz").unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn re_recording_request_replaces_stale_fts_text() {
        // Bug 2 regression: re-recording a request must not leave the OLD body
        // text searchable, and must not produce duplicate hits for the flow.
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.request(
            flow_id,
            RequestData {
                method: "POST".into(),
                authority: "example.com".into(),
                path: "/login".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: b"oldbodytoken".to_vec(),
            },
        )
        .await
        .unwrap();

        // The old text is searchable for now.
        assert!(store
            .reader()
            .search("oldbodytoken")
            .unwrap()
            .contains(&flow_id));

        // Re-record the same flow's request with different body text.
        w.request(
            flow_id,
            RequestData {
                method: "POST".into(),
                authority: "example.com".into(),
                path: "/login".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: b"newbodytoken".to_vec(),
            },
        )
        .await
        .unwrap();

        // OLD text gone, NEW text present.
        assert!(
            store.reader().search("oldbodytoken").unwrap().is_empty(),
            "stale FTS text must be removed on re-record"
        );
        let hits = store.reader().search("newbodytoken").unwrap();
        assert_eq!(hits, vec![flow_id], "latest text wins, exactly one hit");
    }

    #[tokio::test]
    async fn response_status_and_headers_are_searchable() {
        // Bug 3 regression: response FTS must index status + headers, not just body.
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.response(
            flow_id,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"Set-Cookie: session=abrakadabra; HttpOnly\r\nLocation: /next\r\n"
                    .to_vec(),
                body: b"ok".to_vec(),
                timing_ms: None,
            },
        )
        .await
        .unwrap();

        let reader = store.reader();
        assert!(
            reader.search("abrakadabra").unwrap().contains(&flow_id),
            "Set-Cookie header value should be searchable"
        );
        assert!(
            reader.search("Location").unwrap().contains(&flow_id),
            "response header name should be searchable"
        );
    }

    #[tokio::test]
    async fn filters_narrow_flow_listing() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let f1 = w.flow_start(sample_flow()).await.unwrap();
        w.request(
            f1,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();

        let mut other = sample_flow();
        other.dst_ip = "1.2.3.4".into();
        other.sni = Some("other.test".into());
        let f2 = w.flow_start(other).await.unwrap();
        w.request(
            f2,
            RequestData {
                method: "POST".into(),
                authority: "other.test".into(),
                path: "/".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();

        let by_host = store
            .reader()
            .list_flows(&FlowFilter {
                host_contains: Some("other".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_host.len(), 1);
        assert_eq!(by_host[0].id, f2);

        let by_method = store
            .reader()
            .list_flows(&FlowFilter {
                method: Some("GET".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_method.len(), 1);
        assert_eq!(by_method[0].id, f1);
    }

    #[tokio::test]
    async fn match_replace_tag_note_crud_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();

        // Tag CRUD: create-or-attach, idempotent, listable per-flow.
        let tag_id = w
            .tag_flow(flow_id, "interesting", Some("#f00".into()))
            .await
            .unwrap();
        let tag_id2 = w.tag_flow(flow_id, "interesting", None).await.unwrap();
        assert_eq!(tag_id, tag_id2);
        let tags = reader.flow_tags(flow_id).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "interesting");
        assert_eq!(tags[0].color.as_deref(), Some("#f00"));

        // Note CRUD.
        let note_id = w.add_note(flow_id, "looks like IDOR", 123).await.unwrap();
        let notes = reader.flow_notes(flow_id).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, note_id);
        assert_eq!(notes[0].body, "looks like IDOR");

        // Match/replace CRUD.
        let rule_id = w
            .add_match_replace(NewMatchReplaceRule {
                enabled: true,
                scope: "*.example.com".into(),
                match_kind: MatchKind::Header,
                pattern: "User-Agent: .*".into(),
                replacement: "User-Agent: burpwn".into(),
                on_request: true,
            })
            .await
            .unwrap();
        let rules = reader.list_match_replace().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, rule_id);
        assert!(rules[0].enabled);
        assert_eq!(rules[0].match_kind, MatchKind::Header);

        // Group CRUD.
        let group_id = w
            .create_group(
                "auth-flows",
                Some("login form -> POST /login".into()),
                schema::DEFAULT_WORKSPACE_ID,
                42,
            )
            .await
            .unwrap();
        let groups = reader
            .list_groups(Some(schema::DEFAULT_WORKSPACE_ID))
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);
        assert_eq!(
            groups[0].description.as_deref(),
            Some("login form -> POST /login")
        );
        assert_eq!(groups[0].created_at, 42);

        // Intercept queue.
        let intercept_id = w.enqueue_intercept(flow_id, 500).await.unwrap();
        let pending = reader.pending_intercepts().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, intercept_id);
        w.resolve_intercept(intercept_id, InterceptState::Forwarded, 600)
            .await
            .unwrap();
        assert!(reader.pending_intercepts().unwrap().is_empty());
        let forwarded = reader
            .list_intercepts(Some(InterceptState::Forwarded))
            .unwrap();
        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0].resolved_at, Some(600));
    }

    /// Flow groups end to end: membership, the `group_id` filter, and the
    /// lifecycle guarantee that deleting a group never deletes captures.
    #[tokio::test]
    async fn group_membership_filters_flows_and_outlives_nothing() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        // Three flows; two of them make up the "auth" sequence.
        let mut ids = Vec::new();
        for (method, path) in [("GET", "/login"), ("GET", "/unrelated"), ("POST", "/login")] {
            let id = w.flow_start(sample_flow()).await.unwrap();
            w.request(
                id,
                RequestData {
                    method: method.into(),
                    authority: "example.com".into(),
                    path: path.into(),
                    http_version: "HTTP/1.1".into(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let (f_get, f_other, f_post) = (ids[0], ids[1], ids[2]);

        let gid = w
            .create_group(
                "auth-flow",
                Some("login form -> POST /login -> redirect + Set-Cookie".into()),
                schema::DEFAULT_WORKSPACE_ID,
                1000,
            )
            .await
            .unwrap();
        w.add_flow_to_group(f_get, gid).await.unwrap();
        w.add_flow_to_group(f_post, gid).await.unwrap();
        // Re-adding an existing member is a no-op, not a duplicate.
        w.add_flow_to_group(f_get, gid).await.unwrap();
        assert_eq!(reader.group_flow_count(gid).unwrap(), 2);

        // `flows_in_group` returns exactly the members, newest first.
        let members: Vec<i64> = reader
            .flows_in_group(gid)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(members, vec![f_post, f_get]);
        assert!(!members.contains(&f_other));

        // The group filter COMPOSES with the other filters rather than
        // replacing them (this is what `req list --group X --method POST` does).
        let post_only = reader
            .list_flows(&FlowFilter {
                group_id: Some(gid),
                method: Some("POST".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(post_only.len(), 1);
        assert_eq!(post_only[0].id, f_post);

        // An empty/unknown group filters everything out rather than erroring.
        assert!(reader
            .list_flows(&FlowFilter {
                group_id: Some(9999),
                ..Default::default()
            })
            .unwrap()
            .is_empty());

        // Name resolution.
        let by_name = reader
            .group_by_name("auth-flow", Some(schema::DEFAULT_WORKSPACE_ID))
            .unwrap()
            .expect("group by name");
        assert_eq!(by_name.id, gid);
        assert_eq!(by_name.created_at, 1000);
        assert!(reader
            .group_by_name("no-such-group", None)
            .unwrap()
            .is_none());
        // Right name, wrong workspace: not found.
        assert!(reader
            .group_by_name("auth-flow", Some(4242))
            .unwrap()
            .is_none());

        // Removing a member leaves the flow captured; removing a non-member is
        // a silent no-op.
        w.remove_flow_from_group(f_get, gid).await.unwrap();
        w.remove_flow_from_group(f_get, gid).await.unwrap();
        assert_eq!(reader.group_flow_count(gid).unwrap(), 1);
        assert!(reader.flow_exists(f_get).unwrap());

        // Deleting the group drops the grouping ONLY.
        w.delete_group(gid).await.unwrap();
        assert!(reader.group_by_name("auth-flow", None).unwrap().is_none());
        assert_eq!(reader.group_flow_count(gid).unwrap(), 0);
        assert_eq!(reader.list_flows(&FlowFilter::default()).unwrap().len(), 3);
    }

    /// `create_group` is a create-or-update keyed on (workspace, name), and a
    /// membership can only reference a flow that exists.
    #[tokio::test]
    async fn create_group_is_idempotent_and_membership_is_referential() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let first = w
            .create_group("xss-fuzz", Some("search param".into()), 1, 10)
            .await
            .unwrap();
        // Same name, same workspace → same group, description untouched by a
        // `None` and overwritten by a `Some`.
        let again = w.create_group("xss-fuzz", None, 1, 999).await.unwrap();
        assert_eq!(again, first);
        assert_eq!(
            reader
                .group_by_name("xss-fuzz", Some(1))
                .unwrap()
                .unwrap()
                .description
                .as_deref(),
            Some("search param")
        );
        let updated = w
            .create_group("xss-fuzz", Some("now the sort param".into()), 1, 999)
            .await
            .unwrap();
        assert_eq!(updated, first);
        let g = reader.group_by_name("xss-fuzz", Some(1)).unwrap().unwrap();
        assert_eq!(g.description.as_deref(), Some("now the sort param"));
        // The original creation timestamp survives the update.
        assert_eq!(g.created_at, 10);
        assert_eq!(reader.list_groups(None).unwrap().len(), 1);

        // The SAME name in another workspace is a DIFFERENT group.
        let other_ws = w.create_workspace("recon", 0).await.unwrap();
        let elsewhere = w
            .create_group("xss-fuzz", None, other_ws, 20)
            .await
            .unwrap();
        assert_ne!(elsewhere, first);
        assert_eq!(reader.list_groups(None).unwrap().len(), 1 + 1);
        assert_eq!(reader.list_groups(Some(other_ws)).unwrap().len(), 1);
        // Unscoped resolution picks the OLDEST match, so the original group
        // keeps answering to its name.
        assert_eq!(
            reader.group_by_name("xss-fuzz", None).unwrap().unwrap().id,
            first
        );

        // A membership for a flow that does not exist is refused (FK), and the
        // cheap existence check agrees.
        assert!(!reader.flow_exists(9999).unwrap());
        assert!(w.add_flow_to_group(9999, first).await.is_err());
        assert_eq!(reader.group_flow_count(first).unwrap(), 0);
    }

    #[tokio::test]
    async fn attribute_flows_stamps_only_in_window_null_exec_flows() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        // Helper that creates a flow with the given ts_start and exec_id.
        let mk = |ts: i64, exec: Option<&str>| FlowStart {
            workspace_id: schema::DEFAULT_WORKSPACE_ID,
            ts_start: ts,
            exec_id: exec.map(Into::into),
            client_addr: "127.0.0.1:1".into(),
            dst_ip: "10.0.0.1".into(),
            dst_port: 80,
            sni: None,
            scheme: "http".into(),
            protocol: Protocol::H1,
            intercepted: false,
        };

        // Pre-window, NULL exec: must NOT be stamped (ts < since).
        let pre = w.flow_start(mk(100, None)).await.unwrap();
        // In-window, NULL exec: must be stamped.
        let in1 = w.flow_start(mk(500, None)).await.unwrap();
        let in2 = w.flow_start(mk(600, None)).await.unwrap();
        // In-window but already attributed: must NOT be re-stamped.
        let already = w.flow_start(mk(700, Some("other-exec"))).await.unwrap();

        // The target workspace must exist (flows.workspace_id is a FK) — the CLI
        // resolves/creates it before attributing; do the same here.
        let ws = w.create_workspace("target", 0).await.unwrap();

        let stamped = w.attribute_flows(500, "exec-X", ws).await.unwrap();
        assert_eq!(stamped, vec![in1, in2], "only in-window NULL-exec flows");
        assert!(stamped.windows(2).all(|p| p[0] < p[1]), "ascending order");

        // Verify the DB state.
        let reader = store.reader();
        assert_eq!(reader.get_flow(pre).unwrap().unwrap().exec_id, None);
        let d1 = reader.get_flow(in1).unwrap().unwrap();
        assert_eq!(d1.exec_id.as_deref(), Some("exec-X"));
        assert_eq!(d1.flow.workspace_id, ws);
        assert_eq!(
            reader
                .get_flow(already)
                .unwrap()
                .unwrap()
                .exec_id
                .as_deref(),
            Some("other-exec"),
            "already-attributed flow is untouched"
        );

        // A second call stamps nothing (they're no longer NULL-exec).
        let again = w.attribute_flows(500, "exec-Y", 9).await.unwrap();
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn match_replace_enable_disable_delete_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let id = w
            .add_match_replace(NewMatchReplaceRule {
                enabled: true,
                scope: "".into(),
                match_kind: MatchKind::Body,
                pattern: "a".into(),
                replacement: "b".into(),
                on_request: true,
            })
            .await
            .unwrap();
        assert!(reader.list_match_replace().unwrap()[0].enabled);

        w.set_match_replace_enabled(id, false).await.unwrap();
        assert!(!reader.list_match_replace().unwrap()[0].enabled);

        w.set_match_replace_enabled(id, true).await.unwrap();
        assert!(reader.list_match_replace().unwrap()[0].enabled);

        w.delete_match_replace(id).await.unwrap();
        assert!(reader.list_match_replace().unwrap().is_empty());
    }

    #[tokio::test]
    async fn hook_crud_roundtrip_and_ordering() {
        use crate::model::{HookAction, HookPhase, HookScope, NewHook};

        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let second = w
            .add_hook(NewHook {
                enabled: true,
                name: "strip-cookie".into(),
                phase: HookPhase::PreRequest,
                scope: HookScope {
                    host: "api.test".into(),
                    method: "GET".into(),
                    path: "/v1".into(),
                    status: None,
                },
                action: HookAction::RemoveHeader {
                    name: "Cookie".into(),
                },
                order: 10,
                timeout_ms: 5_000,
                ttl_ms: 0,
            })
            .await
            .unwrap();
        let first = w
            .add_hook(NewHook {
                enabled: false,
                name: "ua".into(),
                phase: HookPhase::PreRequest,
                scope: HookScope::default(),
                action: HookAction::AddHeader {
                    name: "User-Agent".into(),
                    value: "burpwn".into(),
                },
                order: 1,
                timeout_ms: 10_000,
                ttl_ms: 0,
            })
            .await
            .unwrap();

        // Listed in APPLICATION order (`ord`), not insertion order.
        let hooks = reader.list_hooks().unwrap();
        assert_eq!(
            hooks.iter().map(|h| h.id).collect::<Vec<_>>(),
            vec![first, second]
        );
        assert!(!hooks[0].enabled);
        assert_eq!(hooks[1].scope.host, "api.test");
        assert_eq!(hooks[1].scope.method, "GET");
        assert_eq!(
            hooks[1].action,
            HookAction::RemoveHeader {
                name: "Cookie".into()
            }
        );
        assert!(hooks[1].created_at > 0, "the writer stamps created_at");

        w.set_hook_enabled(first, true).await.unwrap();
        assert!(reader.get_hook(first).unwrap().unwrap().enabled);

        w.delete_hook(first).await.unwrap();
        assert!(reader.get_hook(first).unwrap().is_none());
        assert_eq!(reader.list_hooks().unwrap().len(), 1);
    }

    /// A row this build cannot decode fails the whole read, so a caller never
    /// silently runs a PARTIAL hook set (see `Reader::list_hooks`).
    #[tokio::test]
    async fn a_hook_row_with_an_unknown_action_fails_the_read() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("session.db");
        {
            let _store = Store::open(&db).unwrap();
        }
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO hooks(phase, action, params) VALUES ('pre-request', 'launch-missiles', '{}')",
            [],
        )
        .unwrap();
        let store = Store::open(&db).unwrap();
        let err = store.reader().list_hooks().unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedRow { .. }), "{err}");
    }

    #[tokio::test]
    async fn get_flow_includes_tags_and_notes() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.tag_flow(flow_id, "vuln", None).await.unwrap();
        w.tag_flow(flow_id, "auth", None).await.unwrap();
        w.add_note(flow_id, "looks like IDOR", 1).await.unwrap();
        w.add_note(flow_id, "needs review", 2).await.unwrap();

        let detail = reader.get_flow(flow_id).unwrap().unwrap();
        // Tags are listed by name (flow_tags orders by t.name).
        assert_eq!(detail.tags, vec!["auth".to_string(), "vuln".to_string()]);
        // Notes are listed by ts (oldest first).
        assert_eq!(
            detail.notes,
            vec!["looks like IDOR".to_string(), "needs review".to_string()]
        );
    }

    #[tokio::test]
    async fn concurrency_smoke_all_flows_land() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        const N: usize = 200;
        let mut handles = Vec::new();
        for i in 0..N {
            let w = w.clone();
            handles.push(tokio::spawn(async move {
                let mut f = FlowStart {
                    workspace_id: schema::DEFAULT_WORKSPACE_ID,
                    ts_start: i as i64,
                    exec_id: None,
                    client_addr: format!("127.0.0.1:{}", 40000 + i),
                    dst_ip: "10.0.0.1".into(),
                    dst_port: 80,
                    sni: None,
                    scheme: "http".into(),
                    protocol: Protocol::H1,
                    intercepted: false,
                };
                f.ts_start = i as i64;
                w.flow_start(f).await.unwrap()
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let rows = store
            .reader()
            .list_flows(&FlowFilter {
                limit: Some(1000),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), N);
    }

    #[tokio::test]
    async fn read_pool_connection_is_read_only_on_checkout() {
        // Finding #2 regression: a pooled read connection must refuse writes,
        // and the customizer re-asserts this on every checkout (not just once).
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();

        // Exercise several checkouts: each must come back read-only.
        for _ in 0..3 {
            let reader = store.reader();
            let conn = reader.pool_conn_for_test();
            let err = conn
                .execute(
                    "INSERT INTO workspaces(name, created_at) VALUES ('x', 0)",
                    [],
                )
                .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("read") || msg.contains("readonly") || msg.contains("query_only"),
                "write through a read-pool connection must be refused, got: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn request_headers_are_full_text_searchable() {
        // v3 FTS fix: request headers (bearer token, custom X- headers) must be
        // indexed and searchable, not just method/path/authority/body.
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.request(
            flow_id,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Authorization: Bearer sekrit_bearer_jwt\r\nX-Custom: findme_hdr\r\n"
                    .to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();

        let reader = store.reader();
        assert!(
            reader
                .search("sekrit_bearer_jwt")
                .unwrap()
                .contains(&flow_id),
            "request bearer token must be searchable"
        );
        assert!(
            reader.search("findme_hdr").unwrap().contains(&flow_id),
            "custom request header value must be searchable"
        );
        // The raw-syntax variant supports FTS5 prefix queries.
        assert!(reader.search_raw("findme_*").unwrap().contains(&flow_id));
    }

    #[tokio::test]
    async fn ws_messages_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        let m1 = w
            .insert_ws_message(
                flow_id,
                WsDirection::C2s,
                Some(1),
                Some(true),
                b"hello ws".to_vec(),
                10,
            )
            .await
            .unwrap();
        let m2 = w
            .insert_ws_message(
                flow_id,
                WsDirection::S2c,
                Some(2),
                Some(false),
                Vec::new(),
                20,
            )
            .await
            .unwrap();
        assert_ne!(m1, m2);

        let msgs = store.reader().ws_messages_for_flow(flow_id).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].id, m1);
        assert_eq!(msgs[0].direction, WsDirection::C2s);
        assert_eq!(msgs[0].opcode, Some(1));
        assert_eq!(msgs[0].fin, Some(true));
        assert_eq!(msgs[0].payload, b"hello ws");
        assert_eq!(msgs[0].ts, Some(10));
        // Empty payload round-trips as an empty vec.
        assert_eq!(msgs[1].direction, WsDirection::S2c);
        assert_eq!(msgs[1].fin, Some(false));
        assert!(msgs[1].payload.is_empty());

        // A flow with no ws frames returns an empty list.
        let other = w.flow_start(sample_flow()).await.unwrap();
        assert!(store
            .reader()
            .ws_messages_for_flow(other)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn attack_and_results_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let base = w.flow_start(sample_flow()).await.unwrap();
        let attack_id = w
            .create_attack(NewAttack {
                workspace: "default".into(),
                name: "sniper-1".into(),
                base_flow_id: Some(base),
                positions: r#"[{"start":10,"end":20}]"#.into(),
                config: r#"{"mode":"sniper","concurrency":8}"#.into(),
                status: "pending".into(),
                created_ts: 100,
            })
            .await
            .unwrap();

        let got = reader.attack_get(attack_id).unwrap().unwrap();
        assert_eq!(got.id, attack_id);
        assert_eq!(got.name.as_deref(), Some("sniper-1"));
        assert_eq!(got.base_flow_id, Some(base));
        assert_eq!(got.status.as_deref(), Some("pending"));

        // Status update is reflected.
        w.update_attack_status(attack_id, "running").await.unwrap();
        assert_eq!(
            reader
                .attack_get(attack_id)
                .unwrap()
                .unwrap()
                .status
                .as_deref(),
            Some("running")
        );

        // Results round-trip, ordered by insertion.
        let r1 = w
            .insert_attack_result(NewAttackResult {
                attack_id,
                payload: r#"{"p":"admin"}"#.into(),
                flow_id: Some(base),
                status_code: Some(200),
                resp_len: Some(1234),
                latency_ms: Some(42),
                anomaly_score: Some(0.5),
                ts: 101,
            })
            .await
            .unwrap();
        let r2 = w
            .insert_attack_result(NewAttackResult {
                attack_id,
                payload: r#"{"p":"guest"}"#.into(),
                flow_id: None,
                status_code: Some(403),
                resp_len: Some(10),
                latency_ms: Some(5),
                anomaly_score: None,
                ts: 102,
            })
            .await
            .unwrap();
        assert_ne!(r1, r2);

        let results = reader.attack_results(attack_id).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id, r1);
        assert_eq!(results[0].status_code, Some(200));
        assert_eq!(results[0].resp_len, Some(1234));
        assert_eq!(results[0].anomaly_score, Some(0.5));
        assert_eq!(results[1].status_code, Some(403));
        assert_eq!(results[1].anomaly_score, None);

        // list_attacks by workspace and unfiltered.
        assert_eq!(reader.list_attacks(Some("default")).unwrap().len(), 1);
        assert!(reader.list_attacks(Some("nope")).unwrap().is_empty());
        assert_eq!(reader.list_attacks(None).unwrap().len(), 1);
        assert!(reader.attack_get(9999).unwrap().is_none());
    }

    #[tokio::test]
    async fn auth_profile_upsert_token_and_scope_lookup() {
        use crate::model::NewAuthProfile;
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        let id = w
            .upsert_auth_profile(NewAuthProfile {
                host: "api.example.com".into(),
                login_cmd: "printf tok123".into(),
                extract_regex: "(tok[0-9]+)".into(),
                header_template: "Authorization: Bearer {}".into(),
            })
            .await
            .unwrap();
        assert!(id > 0);

        // A re-upsert of the same host updates config in place (no duplicate).
        let id2 = w
            .upsert_auth_profile(NewAuthProfile {
                host: "api.example.com".into(),
                login_cmd: "printf tok999".into(),
                extract_regex: "(tok[0-9]+)".into(),
                header_template: "Authorization: Bearer {}".into(),
            })
            .await
            .unwrap();
        assert_eq!(id, id2);
        assert_eq!(reader.auth_profiles().unwrap().len(), 1);

        // Setting a token + rule id is reflected; a re-upsert does NOT clobber it.
        w.set_auth_token("api.example.com", Some("tok999".into()), Some(42), 7)
            .await
            .unwrap();
        let _ = w
            .upsert_auth_profile(NewAuthProfile {
                host: "api.example.com".into(),
                login_cmd: "printf again".into(),
                extract_regex: "(x)".into(),
                header_template: "Authorization: Bearer {}".into(),
            })
            .await
            .unwrap();
        let p = reader.auth_profiles().unwrap().pop().unwrap();
        assert_eq!(p.token.as_deref(), Some("tok999"));
        assert_eq!(p.rule_id, Some(42));
        assert_eq!(p.login_cmd, "printf again");

        // Scope lookup: substring match wins; a non-matching host resolves None.
        assert!(reader
            .auth_profile_for_host("api.example.com")
            .unwrap()
            .is_some());
        assert!(reader
            .auth_profile_for_host("other.test")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn exec_records_and_stats_aggregate_zero_flow_execs() {
        use crate::model::NewExecRecord;
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        // A network-facing exec that captured flows.
        w.insert_exec(NewExecRecord {
            exec_id: "e1".into(),
            cmd: "curl https://x".into(),
            network_facing: true,
            flow_count: 3,
            created_at: 1,
        })
        .await
        .unwrap();
        // A network-facing exec that captured NOTHING (traffic escaped).
        w.insert_exec(NewExecRecord {
            exec_id: "e2".into(),
            cmd: "curl https://y".into(),
            network_facing: true,
            flow_count: 0,
            created_at: 2,
        })
        .await
        .unwrap();
        // A non-network exec with zero flows must NOT count as escaped.
        w.insert_exec(NewExecRecord {
            exec_id: "e3".into(),
            cmd: "ls".into(),
            network_facing: false,
            flow_count: 0,
            created_at: 3,
        })
        .await
        .unwrap();

        assert_eq!(reader.exec_records().unwrap().len(), 3);
        let stats = reader.exec_stats().unwrap();
        assert_eq!(stats.total_execs, 3);
        assert_eq!(stats.total_flows, 3);
        assert_eq!(stats.network_execs, 2);
        assert_eq!(stats.network_zero_flow_execs, 1);
    }

    #[tokio::test]
    async fn set_flow_tls_meta_persists() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.set_flow_tls_meta(
            flow_id,
            Some("TLSv1.3".into()),
            Some("TLS_AES_128_GCM_SHA256".into()),
            Some("h2".into()),
            Some("aa:bb:cc".into()),
        )
        .await
        .unwrap();

        // Read the columns back directly through a pooled connection.
        let reader = store.reader();
        let conn = reader.pool_conn_for_test();
        let (v, c, a, fp): (String, String, String, String) = conn
            .query_row(
                "SELECT tls_version, tls_cipher, tls_alpn, origin_cert_fp FROM flows WHERE id = ?1",
                [flow_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(v, "TLSv1.3");
        assert_eq!(c, "TLS_AES_128_GCM_SHA256");
        assert_eq!(a, "h2");
        assert_eq!(fp, "aa:bb:cc");
    }

    #[tokio::test]
    async fn new_flow_filters_ts_size_and_header() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();
        let reader = store.reader();

        // Flow A: ts=1000, small response, request carries a custom header.
        let mut fa = sample_flow();
        fa.ts_start = 1000;
        let a = w.flow_start(fa).await.unwrap();
        w.request(
            a,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/a".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"X-Trace: alpha-marker\r\n".to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            a,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: vec![b'x'; 50],
                timing_ms: None,
            },
        )
        .await
        .unwrap();

        // Flow B: ts=5000, large response, response carries a header.
        let mut fb = sample_flow();
        fb.ts_start = 5000;
        let b = w.flow_start(fb).await.unwrap();
        w.request(
            b,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/b".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            b,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"X-Resp: beta-marker\r\n".to_vec(),
                body: vec![b'y'; 2000],
                timing_ms: None,
            },
        )
        .await
        .unwrap();

        // ts range: only A falls in [500, 2000].
        let by_ts = reader
            .list_flows(&FlowFilter {
                ts_from: Some(500),
                ts_to: Some(2000),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_ts.len(), 1);
        assert_eq!(by_ts[0].id, a);

        // response size: only B has a body >= 1000 bytes.
        let by_min = reader
            .list_flows(&FlowFilter {
                min_resp_len: Some(1000),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_min.len(), 1);
        assert_eq!(by_min[0].id, b);

        // max size: only A has a body <= 100 bytes.
        let by_max = reader
            .list_flows(&FlowFilter {
                max_resp_len: Some(100),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_max.len(), 1);
        assert_eq!(by_max[0].id, a);

        // header_contains matches the request header on A...
        let by_req_hdr = reader
            .list_flows(&FlowFilter {
                header_contains: Some("alpha-marker".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_req_hdr.len(), 1);
        assert_eq!(by_req_hdr[0].id, a);

        // ...and the response header on B.
        let by_resp_hdr = reader
            .list_flows(&FlowFilter {
                header_contains: Some("beta-marker".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_resp_hdr.len(), 1);
        assert_eq!(by_resp_hdr[0].id, b);
    }

    #[tokio::test]
    async fn large_body_compressed_and_decompressed_via_reader() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        let w = store.writer();

        let big = vec![b'Z'; 64 * 1024];
        let flow_id = w.flow_start(sample_flow()).await.unwrap();
        w.response(
            flow_id,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: big.clone(),
                timing_ms: None,
            },
        )
        .await
        .unwrap();

        let detail = store.reader().get_flow(flow_id).unwrap().unwrap();
        assert_eq!(detail.response.unwrap().body, big);
    }
}
