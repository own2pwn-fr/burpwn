//! The single-writer task and its message protocol.
//!
//! # Concurrency model
//!
//! rusqlite's `Connection` is synchronous and `!Sync`. To keep the proxy hot
//! path off SQLite entirely we own the one write connection on a dedicated
//! blocking worker spawned via [`tokio::task::spawn_blocking`], and feed it
//! [`WriteOp`] messages over a *bounded* [`tokio::sync::mpsc`] channel. The
//! worker calls [`tokio::sync::mpsc::Receiver::blocking_recv`] in a loop, so it
//! parks on an OS thread (never starving the async runtime) and serializes every
//! write through a single connection — exactly what WAL wants (one writer, many
//! readers).
//!
//! Ops that mint an id (e.g. [`WriteOp::FlowStart`]) carry a
//! [`tokio::sync::oneshot`] reply channel so the caller can await the new id
//! without blocking.

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::blob::BlobStore;
use crate::error::{Result, StoreError};
use crate::model::{FlowStart, InterceptState, NewMatchReplaceRule, RequestData, ResponseData};

/// Default bound for the writer channel. Large enough to absorb bursts without
/// unbounded memory growth; senders `.await` when full (back-pressure).
pub const DEFAULT_CHANNEL_CAP: usize = 8192;

/// Per-body store cap (bytes). A stored request/response body — and the FTS text
/// derived from it — is truncated to this length before persisting, so a hostile
/// origin streaming large/incompressible bodies cannot grow `session.db`
/// unbounded (FTS roughly doubles each stored body).
///
/// This is a defensive *backstop*: the proxy already truncates the stored copy to
/// its own `http::BODY_CAP` (8 MiB) before it ever reaches the writer, so in the
/// normal path bodies are already well under this cap. We set it a notch higher
/// (16 MiB) so it only ever fires for callers that bypass the proxy's cap (e.g.
/// raw-chunk streamers, future direct writers).
pub const MAX_STORE_BODY: usize = 16 * 1024 * 1024;

/// Truncate `b` to at most [`MAX_STORE_BODY`] bytes for storage. Returns a
/// borrowed slice (no copy) so the common under-cap path is free.
fn cap_body(b: &[u8]) -> &[u8] {
    &b[..b.len().min(MAX_STORE_BODY)]
}

/// A reply channel for ops that produce a generated id.
pub type IdReply = oneshot::Sender<Result<i64>>;

/// A reply channel for ops whose only result is success/failure.
pub type AckReply = oneshot::Sender<Result<()>>;

/// A reply channel for ops that produce a list of generated/affected ids.
pub type IdsReply = oneshot::Sender<Result<Vec<i64>>>;

/// Messages consumed by the writer task. Every variant is processed in arrival
/// order on the single write connection.
pub enum WriteOp {
    /// Create a new flow row; replies with the new flow id.
    FlowStart {
        /// Flow parameters.
        flow: FlowStart,
        /// Reply with the generated flow id.
        reply: IdReply,
    },
    /// Attach the request to a flow (stores headers + body as dedup'd blobs and
    /// feeds the FTS index). Optional ack.
    Request {
        /// Target flow.
        flow_id: i64,
        /// Request payload.
        data: RequestData,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Attach the response to a flow. Optional ack.
    Response {
        /// Target flow.
        flow_id: i64,
        /// Response payload.
        data: ResponseData,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Mark a flow finished.
    FlowEnd {
        /// Target flow.
        flow_id: i64,
        /// End timestamp.
        ts_end: i64,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Append raw bytes for a rawtcp/ws flow as a note-like blob reference,
    /// recorded in the FTS index as decoded text (best-effort utf8).
    RawChunk {
        /// Target flow.
        flow_id: i64,
        /// Raw bytes.
        bytes: Vec<u8>,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Create (if absent) a tag and attach it to a flow; replies with tag id.
    TagFlow {
        /// Target flow.
        flow_id: i64,
        /// Tag name (unique).
        name: String,
        /// Optional color.
        color: Option<String>,
        /// Reply with the tag id.
        reply: IdReply,
    },
    /// Remove a tag from a flow.
    UntagFlow {
        /// Target flow.
        flow_id: i64,
        /// Tag id.
        tag_id: i64,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Add a note to a flow; replies with the note id.
    AddNote {
        /// Target flow.
        flow_id: i64,
        /// Note body.
        body: String,
        /// Timestamp.
        ts: i64,
        /// Reply with the note id.
        reply: IdReply,
    },
    /// Create a group; replies with the group id.
    CreateGroup {
        /// Group name.
        name: String,
        /// Owning workspace.
        workspace_id: i64,
        /// Reply with the group id.
        reply: IdReply,
    },
    /// Add a flow to a group.
    AddFlowToGroup {
        /// Target flow.
        flow_id: i64,
        /// Group id.
        group_id: i64,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Create a workspace; replies with the workspace id.
    CreateWorkspace {
        /// Workspace name (unique).
        name: String,
        /// Creation timestamp.
        created_at: i64,
        /// Reply with the workspace id.
        reply: IdReply,
    },
    /// Insert a match/replace rule; replies with its id.
    AddMatchReplace {
        /// Rule definition.
        rule: NewMatchReplaceRule,
        /// Reply with the rule id.
        reply: IdReply,
    },
    /// Enable/disable a match/replace rule.
    SetMatchReplaceEnabled {
        /// Rule id.
        id: i64,
        /// New enabled flag.
        enabled: bool,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Delete a match/replace rule.
    DeleteMatchReplace {
        /// Rule id.
        id: i64,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
    /// Enqueue a flow into the intercept queue (state=pending); replies with id.
    EnqueueIntercept {
        /// Target flow.
        flow_id: i64,
        /// Creation timestamp.
        created_at: i64,
        /// Reply with the intercept id.
        reply: IdReply,
    },
    /// Attribute every not-yet-attributed flow created at/after `since_ts` to an
    /// exec + workspace; replies with the ids it stamped (ascending).
    AttributeFlows {
        /// Lower-bound (inclusive) `ts_start` for the time window.
        since_ts: i64,
        /// Exec correlation id to stamp.
        exec_id: String,
        /// Workspace id to stamp.
        workspace_id: i64,
        /// Reply with the ids stamped.
        reply: IdsReply,
    },
    /// Resolve an intercept (set its terminal state + resolved_at).
    ResolveIntercept {
        /// Intercept id.
        id: i64,
        /// Terminal state.
        state: InterceptState,
        /// Resolution timestamp.
        resolved_at: i64,
        /// Optional completion ack.
        reply: Option<AckReply>,
    },
}

/// Cheaply-cloneable handle the proxy uses to enqueue writes.
#[derive(Clone)]
pub struct WriteHandle {
    tx: mpsc::Sender<WriteOp>,
}

impl WriteHandle {
    pub(crate) fn new(tx: mpsc::Sender<WriteOp>) -> Self {
        Self { tx }
    }

    /// Send a raw op (advanced use). Returns [`StoreError::WriterGone`] if the
    /// writer has shut down.
    pub async fn send(&self, op: WriteOp) -> Result<()> {
        self.tx.send(op).await.map_err(|_| StoreError::WriterGone)
    }

    /// Start a flow and await its generated id.
    pub async fn flow_start(&self, flow: FlowStart) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::FlowStart { flow, reply }).await?;
        recv_id(rx).await
    }

    /// Record a request for a flow, awaiting durability ack.
    pub async fn request(&self, flow_id: i64, data: RequestData) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::Request {
            flow_id,
            data,
            reply: Some(reply),
        })
        .await?;
        recv_ack(rx).await
    }

    /// Record a response for a flow, awaiting durability ack.
    pub async fn response(&self, flow_id: i64, data: ResponseData) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::Response {
            flow_id,
            data,
            reply: Some(reply),
        })
        .await?;
        recv_ack(rx).await
    }

    /// Mark a flow finished, awaiting ack.
    pub async fn flow_end(&self, flow_id: i64, ts_end: i64) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::FlowEnd {
            flow_id,
            ts_end,
            reply: Some(reply),
        })
        .await?;
        recv_ack(rx).await
    }

    /// Fire-and-forget request (no ack) — for the absolute hot path.
    pub async fn request_nowait(&self, flow_id: i64, data: RequestData) -> Result<()> {
        self.send(WriteOp::Request {
            flow_id,
            data,
            reply: None,
        })
        .await
    }

    /// Create-or-attach a tag to a flow, awaiting the tag id.
    pub async fn tag_flow(
        &self,
        flow_id: i64,
        name: impl Into<String>,
        color: Option<String>,
    ) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::TagFlow {
            flow_id,
            name: name.into(),
            color,
            reply,
        })
        .await?;
        recv_id(rx).await
    }

    /// Add a note to a flow, awaiting the note id.
    pub async fn add_note(&self, flow_id: i64, body: impl Into<String>, ts: i64) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::AddNote {
            flow_id,
            body: body.into(),
            ts,
            reply,
        })
        .await?;
        recv_id(rx).await
    }

    /// Create a workspace, awaiting its id.
    pub async fn create_workspace(&self, name: impl Into<String>, created_at: i64) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::CreateWorkspace {
            name: name.into(),
            created_at,
            reply,
        })
        .await?;
        recv_id(rx).await
    }

    /// Create a group, awaiting its id.
    pub async fn create_group(&self, name: impl Into<String>, workspace_id: i64) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::CreateGroup {
            name: name.into(),
            workspace_id,
            reply,
        })
        .await?;
        recv_id(rx).await
    }

    /// Insert a match/replace rule, awaiting its id.
    pub async fn add_match_replace(&self, rule: NewMatchReplaceRule) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::AddMatchReplace { rule, reply }).await?;
        recv_id(rx).await
    }

    /// Enqueue an intercept, awaiting its id.
    pub async fn enqueue_intercept(&self, flow_id: i64, created_at: i64) -> Result<i64> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::EnqueueIntercept {
            flow_id,
            created_at,
            reply,
        })
        .await?;
        recv_id(rx).await
    }

    /// Resolve an intercept, awaiting ack.
    pub async fn resolve_intercept(
        &self,
        id: i64,
        state: InterceptState,
        resolved_at: i64,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::ResolveIntercept {
            id,
            state,
            resolved_at,
            reply: Some(reply),
        })
        .await?;
        recv_ack(rx).await
    }

    /// Attribute every not-yet-attributed flow created at/after `since_ts` to the
    /// given exec + workspace. Returns the ids it stamped. Used by `burpwn exec`
    /// to scope a run's captures (the long-lived daemon records flows with a NULL
    /// exec_id / default workspace; this assigns them post-hoc by time window).
    pub async fn attribute_flows(
        &self,
        since_ts: i64,
        exec_id: &str,
        workspace_id: i64,
    ) -> Result<Vec<i64>> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::AttributeFlows {
            since_ts,
            exec_id: exec_id.to_string(),
            workspace_id,
            reply,
        })
        .await?;
        recv_ids(rx).await
    }

    /// Delete a match/replace rule, awaiting ack.
    pub async fn delete_match_replace(&self, id: i64) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::DeleteMatchReplace {
            id,
            reply: Some(reply),
        })
        .await?;
        recv_ack(rx).await
    }

    /// Enable/disable a match/replace rule, awaiting ack.
    pub async fn set_match_replace_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WriteOp::SetMatchReplaceEnabled {
            id,
            enabled,
            reply: Some(reply),
        })
        .await?;
        recv_ack(rx).await
    }
}

async fn recv_id(rx: oneshot::Receiver<Result<i64>>) -> Result<i64> {
    match rx.await {
        Ok(r) => r,
        Err(_) => Err(StoreError::NoReply("id op".into())),
    }
}

async fn recv_ack(rx: oneshot::Receiver<Result<()>>) -> Result<()> {
    match rx.await {
        Ok(r) => r,
        Err(_) => Err(StoreError::NoReply("ack op".into())),
    }
}

async fn recv_ids(rx: oneshot::Receiver<Result<Vec<i64>>>) -> Result<Vec<i64>> {
    match rx.await {
        Ok(r) => r,
        Err(_) => Err(StoreError::NoReply("ids op".into())),
    }
}

/// Spawn the blocking writer loop. Consumes `conn` (the keyed write connection).
/// Runs until the channel closes (all [`WriteHandle`]s dropped).
pub(crate) fn spawn_writer(conn: Connection, mut rx: mpsc::Receiver<WriteOp>) {
    tokio::task::spawn_blocking(move || {
        while let Some(op) = rx.blocking_recv() {
            handle_op(&conn, op);
        }
        tracing::debug!("burpwn-store writer task: channel closed, shutting down");
    });
}

/// Dispatch a single op. Errors are reported on the op's reply channel (if any)
/// and logged; one failing op never kills the writer.
fn handle_op(conn: &Connection, op: WriteOp) {
    match op {
        WriteOp::FlowStart { flow, reply } => {
            let _ = reply.send(do_flow_start(conn, &flow));
        }
        WriteOp::Request {
            flow_id,
            data,
            reply,
        } => ack(reply, do_request(conn, flow_id, &data)),
        WriteOp::Response {
            flow_id,
            data,
            reply,
        } => ack(reply, do_response(conn, flow_id, &data)),
        WriteOp::FlowEnd {
            flow_id,
            ts_end,
            reply,
        } => ack(reply, do_flow_end(conn, flow_id, ts_end)),
        WriteOp::RawChunk {
            flow_id,
            bytes,
            reply,
        } => ack(reply, do_raw_chunk(conn, flow_id, &bytes)),
        WriteOp::TagFlow {
            flow_id,
            name,
            color,
            reply,
        } => {
            let _ = reply.send(do_tag_flow(conn, flow_id, &name, color.as_deref()));
        }
        WriteOp::UntagFlow {
            flow_id,
            tag_id,
            reply,
        } => ack(
            reply,
            conn.execute(
                "DELETE FROM flow_tags WHERE flow_id = ?1 AND tag_id = ?2",
                rusqlite::params![flow_id, tag_id],
            )
            .map(|_| ())
            .map_err(Into::into),
        ),
        WriteOp::AddNote {
            flow_id,
            body,
            ts,
            reply,
        } => {
            let _ = reply.send(do_add_note(conn, flow_id, &body, ts));
        }
        WriteOp::CreateGroup {
            name,
            workspace_id,
            reply,
        } => {
            let _ = reply.send(do_create_group(conn, &name, workspace_id));
        }
        WriteOp::AddFlowToGroup {
            flow_id,
            group_id,
            reply,
        } => ack(
            reply,
            conn.execute(
                "INSERT INTO flow_groups(flow_id, group_id) VALUES (?1, ?2)
                 ON CONFLICT DO NOTHING",
                rusqlite::params![flow_id, group_id],
            )
            .map(|_| ())
            .map_err(Into::into),
        ),
        WriteOp::CreateWorkspace {
            name,
            created_at,
            reply,
        } => {
            let _ = reply.send(do_create_workspace(conn, &name, created_at));
        }
        WriteOp::AddMatchReplace { rule, reply } => {
            let _ = reply.send(do_add_match_replace(conn, &rule));
        }
        WriteOp::SetMatchReplaceEnabled { id, enabled, reply } => ack(
            reply,
            conn.execute(
                "UPDATE match_replace_rules SET enabled = ?1 WHERE id = ?2",
                rusqlite::params![enabled as i64, id],
            )
            .map(|_| ())
            .map_err(Into::into),
        ),
        WriteOp::DeleteMatchReplace { id, reply } => ack(
            reply,
            conn.execute("DELETE FROM match_replace_rules WHERE id = ?1", [id])
                .map(|_| ())
                .map_err(Into::into),
        ),
        WriteOp::EnqueueIntercept {
            flow_id,
            created_at,
            reply,
        } => {
            let _ = reply.send(do_enqueue_intercept(conn, flow_id, created_at));
        }
        WriteOp::AttributeFlows {
            since_ts,
            exec_id,
            workspace_id,
            reply,
        } => {
            let _ = reply.send(do_attribute_flows(conn, since_ts, &exec_id, workspace_id));
        }
        WriteOp::ResolveIntercept {
            id,
            state,
            resolved_at,
            reply,
        } => ack(
            reply,
            conn.execute(
                "UPDATE intercepts SET state = ?1, resolved_at = ?2 WHERE id = ?3",
                rusqlite::params![state.as_str(), resolved_at, id],
            )
            .map(|_| ())
            .map_err(Into::into),
        ),
    }
}

/// Send an ack on an optional reply channel, logging failures.
fn ack(reply: Option<AckReply>, result: Result<()>) {
    if let Err(ref e) = result {
        tracing::warn!(error = %e, "burpwn-store write op failed");
    }
    if let Some(tx) = reply {
        let _ = tx.send(result);
    }
}

fn do_flow_start(conn: &Connection, f: &FlowStart) -> Result<i64> {
    conn.execute(
        "INSERT INTO flows(workspace_id, ts_start, exec_id, client_addr, dst_ip, dst_port, sni, scheme, protocol, intercepted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            f.workspace_id,
            f.ts_start,
            f.exec_id,
            f.client_addr,
            f.dst_ip,
            f.dst_port as i64,
            f.sni,
            f.scheme,
            f.protocol.as_str(),
            f.intercepted as i64,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn do_request(conn: &Connection, flow_id: i64, d: &RequestData) -> Result<()> {
    // Cap the stored body (and the FTS text derived from it below) to
    // MAX_STORE_BODY so a hostile origin cannot grow session.db unbounded. The
    // proxy already caps to its own BODY_CAP; this is a defensive backstop.
    let body = cap_body(&d.body);
    let headers_id = BlobStore::put_opt(conn, blob_opt(&d.headers))?;
    let body_id = BlobStore::put_opt(conn, blob_opt(body))?;
    conn.execute(
        "INSERT INTO requests(flow_id, method, authority, path, http_version, headers_blob_id, body_blob_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(flow_id) DO UPDATE SET
            method=excluded.method, authority=excluded.authority, path=excluded.path,
            http_version=excluded.http_version, headers_blob_id=excluded.headers_blob_id,
            body_blob_id=excluded.body_blob_id",
        rusqlite::params![
            flow_id,
            d.method,
            d.authority,
            d.path,
            d.http_version,
            headers_id,
            body_id,
        ],
    )?;
    // Feed FTS with url + host + decoded (capped) body text.
    let mut text = format!("{} {}\n{}\n", d.method, d.path, d.authority);
    text.push_str(&String::from_utf8_lossy(body));
    index_fts(conn, flow_id, FtsKind::Request, &text)?;
    Ok(())
}

fn do_response(conn: &Connection, flow_id: i64, d: &ResponseData) -> Result<()> {
    // Cap the stored body (and its FTS text) to MAX_STORE_BODY — see do_request.
    let body = cap_body(&d.body);
    let headers_id = BlobStore::put_opt(conn, blob_opt(&d.headers))?;
    let body_id = BlobStore::put_opt(conn, blob_opt(body))?;
    conn.execute(
        "INSERT INTO responses(flow_id, status, http_version, headers_blob_id, body_blob_id, timing_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(flow_id) DO UPDATE SET
            status=excluded.status, http_version=excluded.http_version,
            headers_blob_id=excluded.headers_blob_id, body_blob_id=excluded.body_blob_id,
            timing_ms=excluded.timing_ms",
        rusqlite::params![
            flow_id,
            d.status as i64,
            d.http_version,
            headers_id,
            body_id,
            d.timing_ms,
        ],
    )?;
    // Feed FTS with status + decoded headers (so Set-Cookie / Location / status
    // are searchable) + decoded body text, mirroring the request side.
    let mut text = format!("{}\n", d.status);
    text.push_str(&String::from_utf8_lossy(&d.headers));
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(body));
    index_fts(conn, flow_id, FtsKind::Response, &text)?;
    Ok(())
}

fn do_flow_end(conn: &Connection, flow_id: i64, ts_end: i64) -> Result<()> {
    conn.execute(
        "UPDATE flows SET ts_end = ?1 WHERE id = ?2",
        rusqlite::params![ts_end, flow_id],
    )?;
    Ok(())
}

fn do_raw_chunk(conn: &Connection, flow_id: i64, bytes: &[u8]) -> Result<()> {
    // Raw chunks live as blobs referenced from notes-like FTS only; we keep the
    // bytes deduplicated and index their (best-effort) text. Cap the stored
    // chunk (and its FTS text) to MAX_STORE_BODY so a hostile peer streaming a
    // huge raw chunk cannot grow session.db unbounded.
    let bytes = cap_body(bytes);
    BlobStore::put(conn, bytes)?;
    index_fts(conn, flow_id, FtsKind::Raw, &String::from_utf8_lossy(bytes))?;
    Ok(())
}

fn do_tag_flow(conn: &Connection, flow_id: i64, name: &str, color: Option<&str>) -> Result<i64> {
    conn.execute(
        "INSERT INTO tags(name, color) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET color = COALESCE(excluded.color, tags.color)",
        rusqlite::params![name, color],
    )?;
    let tag_id: i64 =
        conn.query_row("SELECT id FROM tags WHERE name = ?1", [name], |r| r.get(0))?;
    conn.execute(
        "INSERT INTO flow_tags(flow_id, tag_id) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        rusqlite::params![flow_id, tag_id],
    )?;
    Ok(tag_id)
}

fn do_add_note(conn: &Connection, flow_id: i64, body: &str, ts: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO notes(flow_id, body, ts) VALUES (?1, ?2, ?3)",
        rusqlite::params![flow_id, body, ts],
    )?;
    Ok(conn.last_insert_rowid())
}

fn do_create_group(conn: &Connection, name: &str, workspace_id: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO groups(name, workspace_id) VALUES (?1, ?2)",
        rusqlite::params![name, workspace_id],
    )?;
    Ok(conn.last_insert_rowid())
}

fn do_create_workspace(conn: &Connection, name: &str, created_at: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO workspaces(name, created_at) VALUES (?1, ?2)",
        rusqlite::params![name, created_at],
    )?;
    Ok(conn.last_insert_rowid())
}

fn do_add_match_replace(conn: &Connection, r: &NewMatchReplaceRule) -> Result<i64> {
    conn.execute(
        "INSERT INTO match_replace_rules(enabled, scope, match_kind, pattern, replacement, on_request)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            r.enabled as i64,
            r.scope,
            r.match_kind.as_str(),
            r.pattern,
            r.replacement,
            r.on_request as i64,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn do_enqueue_intercept(conn: &Connection, flow_id: i64, created_at: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO intercepts(flow_id, state, created_at) VALUES (?1, 'pending', ?2)",
        rusqlite::params![flow_id, created_at],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Stamp `exec_id` + `workspace_id` onto every flow whose `ts_start >= since_ts`
/// that has not yet been attributed (NULL `exec_id`). Returns the affected flow
/// ids in ascending order. Uses SQLite's `RETURNING` clause.
fn do_attribute_flows(
    conn: &Connection,
    since_ts: i64,
    exec_id: &str,
    workspace_id: i64,
) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare(
        "UPDATE flows SET exec_id = ?1, workspace_id = ?2
         WHERE ts_start >= ?3 AND exec_id IS NULL
         RETURNING id",
    )?;
    let rows = stmt.query_map(rusqlite::params![exec_id, workspace_id, since_ts], |r| {
        r.get::<_, i64>(0)
    })?;
    let mut ids = Vec::new();
    for r in rows {
        ids.push(r?);
    }
    ids.sort_unstable();
    Ok(ids)
}

/// The kind of FTS row, stored in the unindexed `kind` column. `Request` and
/// `Response` are replaced in place on re-record (one row per flow per kind);
/// `Raw` rows accumulate (a flow streams many raw chunks).
#[derive(Clone, Copy)]
enum FtsKind {
    Request,
    Response,
    Raw,
}

impl FtsKind {
    fn as_str(self) -> &'static str {
        match self {
            FtsKind::Request => "req",
            FtsKind::Response => "resp",
            FtsKind::Raw => "raw",
        }
    }

    /// Whether re-indexing this kind replaces the flow's prior text for it.
    /// Request/response are singular per flow (replace on re-record); raw chunks
    /// are streamed and must accumulate.
    fn replaces_prior(self) -> bool {
        matches!(self, FtsKind::Request | FtsKind::Response)
    }
}

/// (Re)index a text fragment into the FTS index for a flow under `kind`.
///
/// For replace-style kinds (request/response) this first deletes the flow's prior
/// rows for that kind, so re-recording a request/response never leaves stale,
/// duplicated text searchable. Raw chunks accumulate.
fn index_fts(conn: &Connection, flow_id: i64, kind: FtsKind, text: &str) -> Result<()> {
    if kind.replaces_prior() {
        conn.execute(
            "DELETE FROM flows_fts WHERE flow_id = ?1 AND kind = ?2",
            rusqlite::params![flow_id, kind.as_str()],
        )?;
    }
    if text.trim().is_empty() {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO flows_fts(flow_id, kind, content) VALUES (?1, ?2, ?3)",
        rusqlite::params![flow_id, kind.as_str(), text],
    )?;
    Ok(())
}

/// `None` for an empty slice so we don't store/reference an empty blob.
fn blob_opt(b: &[u8]) -> Option<&[u8]> {
    if b.is_empty() {
        None
    } else {
        Some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_body_truncates_oversize_and_leaves_small_untouched() {
        // Under the cap: returned verbatim (no copy, same slice contents).
        let small = vec![0xAB_u8; 1024];
        assert_eq!(cap_body(&small).len(), small.len());

        // At the cap: kept whole.
        let exact = vec![0xCD_u8; MAX_STORE_BODY];
        assert_eq!(cap_body(&exact).len(), MAX_STORE_BODY);

        // Over the cap: truncated to exactly MAX_STORE_BODY.
        let huge = vec![0xEF_u8; MAX_STORE_BODY + 4096];
        let capped = cap_body(&huge);
        assert_eq!(capped.len(), MAX_STORE_BODY);
        assert_eq!(capped, &huge[..MAX_STORE_BODY]);
    }
}
