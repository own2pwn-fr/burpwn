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
        let pool = Pool::builder().build(manager)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FlowFilter, FlowStart, InterceptState, MatchKind, NewMatchReplaceRule, Protocol,
        RequestData, ResponseData,
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
            .create_group("auth-flows", schema::DEFAULT_WORKSPACE_ID)
            .await
            .unwrap();
        let groups = reader
            .list_groups(Some(schema::DEFAULT_WORKSPACE_ID))
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);

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
