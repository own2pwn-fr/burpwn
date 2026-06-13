//! Read-only queries over the r2d2 connection pool.
//!
//! WAL lets these run concurrently with the single writer task. Every method
//! checks out a pooled read connection, runs its query, and returns
//! serde-serializable rows so the CLI can emit JSON directly.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::blob::get_blob;
use crate::error::Result;
use crate::model::{
    FlowDetail, FlowFilter, FlowRow, Group, Intercept, InterceptState, MatchKind, MatchReplaceRule,
    Note, Protocol, RequestData, ResponseData, Tag, Workspace,
};

/// Raw column tuple for a `requests` row: (method, authority, path, http_version,
/// headers_blob_id, body_blob_id). Aliased to satisfy `clippy::type_complexity`.
type RequestRow = (String, String, String, String, Option<i64>, Option<i64>);

/// Raw column tuple for a `responses` row: (status, http_version, headers_blob_id,
/// body_blob_id, timing_ms).
type ResponseRow = (i64, String, Option<i64>, Option<i64>, Option<i64>);

/// Read-only view over the session store.
#[derive(Clone)]
pub struct Reader {
    pool: Pool<SqliteConnectionManager>,
}

impl Reader {
    pub(crate) fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }

    fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        Ok(self.pool.get()?)
    }

    /// List flows matching `filter`, newest first.
    pub fn list_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowRow>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT f.id, f.workspace_id, f.ts_start, f.ts_end, f.protocol, f.scheme,
                    f.dst_ip, f.dst_port, f.sni, f.intercepted,
                    r.method, r.authority, r.path, resp.status
             FROM flows f
             LEFT JOIN requests r ON r.flow_id = f.id
             LEFT JOIN responses resp ON resp.flow_id = f.id
             WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(ws) = filter.workspace_id {
            sql.push_str(" AND f.workspace_id = ?");
            params.push(Box::new(ws));
        }
        if let Some(ref host) = filter.host_contains {
            // Three anonymous placeholders, bound positionally with the same value.
            sql.push_str(" AND (r.authority LIKE ? OR f.sni LIKE ? OR f.dst_ip LIKE ?)");
            let like = format!("%{host}%");
            params.push(Box::new(like.clone()));
            params.push(Box::new(like.clone()));
            params.push(Box::new(like));
        }
        if let Some(status) = filter.status {
            sql.push_str(" AND resp.status = ?");
            params.push(Box::new(status as i64));
        }
        if let Some(ref method) = filter.method {
            sql.push_str(" AND r.method = ?");
            params.push(Box::new(method.clone()));
        }
        if let Some(protocol) = filter.protocol {
            sql.push_str(" AND f.protocol = ?");
            params.push(Box::new(protocol.as_str().to_string()));
        }
        if let Some(port) = filter.port {
            sql.push_str(" AND f.dst_port = ?");
            params.push(Box::new(port as i64));
        }

        sql.push_str(" ORDER BY f.id DESC LIMIT ? OFFSET ?");
        params.push(Box::new(filter.limit.unwrap_or(100)));
        params.push(Box::new(filter.offset.unwrap_or(0)));

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), row_to_flow)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Fetch a fully-joined flow with decoded request + response, or `None`.
    pub fn get_flow(&self, id: i64) -> Result<Option<FlowDetail>> {
        let conn = self.conn()?;
        let base: Option<(FlowRow, Option<String>, String)> = conn
            .query_row(
                "SELECT f.id, f.workspace_id, f.ts_start, f.ts_end, f.protocol, f.scheme,
                        f.dst_ip, f.dst_port, f.sni, f.intercepted,
                        r.method, r.authority, r.path, resp.status,
                        f.exec_id, f.client_addr
                 FROM flows f
                 LEFT JOIN requests r ON r.flow_id = f.id
                 LEFT JOIN responses resp ON resp.flow_id = f.id
                 WHERE f.id = ?1",
                [id],
                |row| {
                    let flow = row_to_flow(row)?;
                    let exec_id: Option<String> = row.get(14)?;
                    let client_addr: String = row.get(15)?;
                    Ok((flow, exec_id, client_addr))
                },
            )
            .ok();

        let Some((flow, exec_id, client_addr)) = base else {
            return Ok(None);
        };

        // Reuse the connection we already checked out for tags + notes too, so a
        // single `get_flow` call only ever holds ONE pooled connection (avoids
        // exhausting/deadlocking the pool under concurrent readers).
        let request = self.load_request(&conn, id)?;
        let response = self.load_response(&conn, id)?;
        let tags = self
            .flow_tags_conn(&conn, id)?
            .into_iter()
            .map(|t| t.name)
            .collect();
        let notes = self
            .flow_notes_conn(&conn, id)?
            .into_iter()
            .map(|n| n.body)
            .collect();

        Ok(Some(FlowDetail {
            flow,
            exec_id,
            client_addr,
            request,
            response,
            tags,
            notes,
        }))
    }

    fn load_request(&self, conn: &Connection, flow_id: i64) -> Result<Option<RequestData>> {
        let row: Option<RequestRow> = conn
            .query_row(
                "SELECT method, authority, path, http_version, headers_blob_id, body_blob_id
                 FROM requests WHERE flow_id = ?1",
                [flow_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .ok();
        let Some((method, authority, path, http_version, hid, bid)) = row else {
            return Ok(None);
        };
        Ok(Some(RequestData {
            method,
            authority,
            path,
            http_version,
            headers: load_blob_or_empty(conn, hid)?,
            body: load_blob_or_empty(conn, bid)?,
        }))
    }

    fn load_response(&self, conn: &Connection, flow_id: i64) -> Result<Option<ResponseData>> {
        let row: Option<ResponseRow> = conn
            .query_row(
                "SELECT status, http_version, headers_blob_id, body_blob_id, timing_ms
                 FROM responses WHERE flow_id = ?1",
                [flow_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok();
        let Some((status, http_version, hid, bid, timing_ms)) = row else {
            return Ok(None);
        };
        Ok(Some(ResponseData {
            status: status as u16,
            http_version,
            headers: load_blob_or_empty(conn, hid)?,
            body: load_blob_or_empty(conn, bid)?,
            timing_ms,
        }))
    }

    /// Fetch a decoded blob by id.
    pub fn get_blob(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let conn = self.conn()?;
        get_blob(&conn, id)
    }

    /// Flow ids stamped with `exec_id`, ascending. The proxy attributes each
    /// captured flow to the originating `burpwn exec` at capture time (via the
    /// SCM wire header), so this returns exactly that run's captures.
    pub fn flow_ids_for_exec(&self, exec_id: &str) -> Result<Vec<i64>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id FROM flows WHERE exec_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map([exec_id], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Full-text search over indexed request/response/raw text; returns matching
    /// flow ids (deduplicated, newest first).
    pub fn search(&self, query: &str) -> Result<Vec<i64>> {
        let conn = self.conn()?;
        // Treat the user query as a LITERAL FTS5 phrase: wrap it in double quotes
        // (escaping any embedded ones) so characters that are FTS5 query syntax —
        // `-`, `:`, `*`, `^`, parentheses — don't get misinterpreted (e.g. a bare
        // `needle-token` otherwise parses `token` as a column filter). This keeps
        // `search` a plain substring/phrase search, which is what callers expect.
        let phrase = format!("\"{}\"", query.replace('"', "\"\""));
        let mut stmt = conn.prepare(
            "SELECT DISTINCT flow_id FROM flows_fts WHERE flows_fts MATCH ?1 ORDER BY flow_id DESC",
        )?;
        let rows = stmt.query_map([phrase], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ---- workspace / tag / group / note CRUD reads ----

    /// List all workspaces.
    pub fn list_workspaces(&self) -> Result<Vec<Workspace>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, created_at FROM workspaces ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Workspace {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
            })
        })?;
        collect(rows)
    }

    /// List all tags.
    pub fn list_tags(&self) -> Result<Vec<Tag>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, name, color FROM tags ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(Tag {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
            })
        })?;
        collect(rows)
    }

    /// List the tags attached to a flow.
    pub fn flow_tags(&self, flow_id: i64) -> Result<Vec<Tag>> {
        let conn = self.conn()?;
        self.flow_tags_conn(&conn, flow_id)
    }

    /// List the tags attached to a flow using an already-checked-out connection.
    fn flow_tags_conn(&self, conn: &Connection, flow_id: i64) -> Result<Vec<Tag>> {
        let mut stmt = conn.prepare(
            "SELECT t.id, t.name, t.color FROM tags t
             JOIN flow_tags ft ON ft.tag_id = t.id
             WHERE ft.flow_id = ?1 ORDER BY t.name",
        )?;
        let rows = stmt.query_map([flow_id], |r| {
            Ok(Tag {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
            })
        })?;
        collect(rows)
    }

    /// List groups, optionally filtered by workspace.
    pub fn list_groups(&self, workspace_id: Option<i64>) -> Result<Vec<Group>> {
        let conn = self.conn()?;
        let (sql, ws) = match workspace_id {
            Some(_) => (
                "SELECT id, name, workspace_id FROM groups WHERE workspace_id = ?1 ORDER BY name",
                workspace_id,
            ),
            None => (
                "SELECT id, name, workspace_id FROM groups ORDER BY name",
                None,
            ),
        };
        let mut stmt = conn.prepare(sql)?;
        let mapper = |r: &rusqlite::Row| {
            Ok(Group {
                id: r.get(0)?,
                name: r.get(1)?,
                workspace_id: r.get(2)?,
            })
        };
        let rows = match ws {
            Some(w) => stmt.query_map([w], mapper)?,
            None => stmt.query_map([], mapper)?,
        };
        collect(rows)
    }

    /// List notes on a flow, oldest first.
    pub fn flow_notes(&self, flow_id: i64) -> Result<Vec<Note>> {
        let conn = self.conn()?;
        self.flow_notes_conn(&conn, flow_id)
    }

    /// List notes on a flow using an already-checked-out connection, oldest first.
    fn flow_notes_conn(&self, conn: &Connection, flow_id: i64) -> Result<Vec<Note>> {
        let mut stmt =
            conn.prepare("SELECT id, flow_id, body, ts FROM notes WHERE flow_id = ?1 ORDER BY ts")?;
        let rows = stmt.query_map([flow_id], |r| {
            Ok(Note {
                id: r.get(0)?,
                flow_id: r.get(1)?,
                body: r.get(2)?,
                ts: r.get(3)?,
            })
        })?;
        collect(rows)
    }

    /// List all match/replace rules.
    pub fn list_match_replace(&self) -> Result<Vec<MatchReplaceRule>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, enabled, scope, match_kind, pattern, replacement, on_request
             FROM match_replace_rules ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            let kind: String = r.get(3)?;
            Ok(MatchReplaceRule {
                id: r.get(0)?,
                enabled: r.get::<_, i64>(1)? != 0,
                scope: r.get(2)?,
                match_kind: MatchKind::from_db(&kind),
                pattern: r.get(4)?,
                replacement: r.get(5)?,
                on_request: r.get::<_, i64>(6)? != 0,
            })
        })?;
        collect(rows)
    }

    /// List intercepts, optionally filtered by state. Newest first.
    pub fn list_intercepts(&self, state: Option<InterceptState>) -> Result<Vec<Intercept>> {
        let conn = self.conn()?;
        let mapper = |r: &rusqlite::Row| {
            let s: String = r.get(2)?;
            Ok(Intercept {
                id: r.get(0)?,
                flow_id: r.get(1)?,
                state: InterceptState::from_db(&s),
                created_at: r.get(3)?,
                resolved_at: r.get(4)?,
            })
        };
        match state {
            Some(st) => {
                let mut stmt = conn.prepare(
                    "SELECT id, flow_id, state, created_at, resolved_at FROM intercepts
                     WHERE state = ?1 ORDER BY id DESC",
                )?;
                let rows = stmt.query_map([st.as_str()], mapper)?;
                collect(rows)
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, flow_id, state, created_at, resolved_at FROM intercepts
                     ORDER BY id DESC",
                )?;
                let rows = stmt.query_map([], mapper)?;
                collect(rows)
            }
        }
    }

    /// Pending intercept queue (convenience over [`list_intercepts`]).
    pub fn pending_intercepts(&self) -> Result<Vec<Intercept>> {
        self.list_intercepts(Some(InterceptState::Pending))
    }
}

/// Map a flows-join row (15+ columns; first 14 are the [`FlowRow`] shape) into a
/// [`FlowRow`].
fn row_to_flow(row: &rusqlite::Row) -> rusqlite::Result<FlowRow> {
    let protocol: String = row.get(4)?;
    let status: Option<i64> = row.get(13)?;
    Ok(FlowRow {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        ts_start: row.get(2)?,
        ts_end: row.get(3)?,
        protocol: Protocol::from_db(&protocol),
        scheme: row.get(5)?,
        dst_ip: row.get(6)?,
        dst_port: row.get::<_, i64>(7)? as u16,
        sni: row.get(8)?,
        intercepted: row.get::<_, i64>(9)? != 0,
        method: row.get(10)?,
        authority: row.get(11)?,
        path: row.get(12)?,
        status: status.map(|s| s as u16),
    })
}

/// Load a blob by optional id, returning an empty vec when absent.
fn load_blob_or_empty(conn: &Connection, id: Option<i64>) -> Result<Vec<u8>> {
    match id {
        Some(i) => Ok(get_blob(conn, i)?.unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

/// Collect a `query_map` iterator into a `Vec`, propagating row errors.
fn collect<T>(rows: impl Iterator<Item = rusqlite::Result<T>>) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}
