//! Versioned schema bootstrap driven by `PRAGMA user_version`.
//!
//! A fresh `session.db` starts at `user_version = 0`; [`init`] applies every
//! migration step whose target version is greater than the file's current
//! version inside one transaction, stamps `user_version`, and seeds the default
//! workspace. Re-opening an already-current file is a no-op.
//!
//! Adding a migration: bump [`SCHEMA_VERSION`], append a `(version, step)` entry
//! to [`MIGRATIONS`] with `version == SCHEMA_VERSION`, keep the step idempotent.

use rusqlite::Connection;

use crate::error::{Result, StoreError};

/// Current schema version. Bump when adding a migration step.
pub const SCHEMA_VERSION: i64 = 1;

/// Id of the always-present default workspace.
pub const DEFAULT_WORKSPACE_ID: i64 = 1;

type MigrationStep = fn(&Connection) -> Result<()>;

const MIGRATIONS: &[(i64, MigrationStep)] = &[(1, migrate_v1)];

/// Apply pending migrations, stamp the version, and ensure the default
/// workspace exists. Refuses to open a file stamped with a newer schema.
pub fn init(conn: &Connection) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if current > SCHEMA_VERSION {
        return Err(StoreError::IncompatibleSchema {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    if current < SCHEMA_VERSION {
        conn.execute_batch("BEGIN")?;
        let apply = || -> Result<()> {
            for (version, step) in MIGRATIONS {
                if *version > current {
                    step(conn)?;
                }
            }
            Ok(())
        };
        if let Err(e) = apply() {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
        conn.execute_batch("COMMIT")?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }

    seed_default_workspace(conn)?;
    Ok(())
}

/// Insert the default workspace (id=1, "default") if it is not already present.
fn seed_default_workspace(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?1, 'default', 0)
         ON CONFLICT(id) DO NOTHING",
        rusqlite::params![DEFAULT_WORKSPACE_ID],
    )?;
    Ok(())
}

/// v1 baseline: the whole burpwn session schema + the FTS5 index.
fn migrate_v1(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS workspaces (
            id         INTEGER PRIMARY KEY,
            name       TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blobs (
            id         INTEGER PRIMARY KEY,
            sha256     BLOB NOT NULL UNIQUE,
            size       INTEGER NOT NULL,
            compressed INTEGER NOT NULL DEFAULT 0,
            data       BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS flows (
            id          INTEGER PRIMARY KEY,
            workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
            ts_start    INTEGER NOT NULL,
            ts_end      INTEGER,
            exec_id     TEXT,
            client_addr TEXT NOT NULL,
            dst_ip      TEXT NOT NULL,
            dst_port    INTEGER NOT NULL,
            sni         TEXT,
            scheme      TEXT NOT NULL,
            protocol    TEXT NOT NULL,
            intercepted INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_flows_workspace ON flows(workspace_id);
        CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts_start);

        CREATE TABLE IF NOT EXISTS requests (
            flow_id        INTEGER PRIMARY KEY REFERENCES flows(id) ON DELETE CASCADE,
            method         TEXT NOT NULL,
            authority      TEXT NOT NULL,
            path           TEXT NOT NULL,
            http_version   TEXT NOT NULL,
            headers_blob_id INTEGER REFERENCES blobs(id),
            body_blob_id    INTEGER REFERENCES blobs(id)
        );

        CREATE TABLE IF NOT EXISTS responses (
            flow_id         INTEGER PRIMARY KEY REFERENCES flows(id) ON DELETE CASCADE,
            status          INTEGER NOT NULL,
            http_version    TEXT NOT NULL,
            headers_blob_id INTEGER REFERENCES blobs(id),
            body_blob_id    INTEGER REFERENCES blobs(id),
            timing_ms       INTEGER
        );

        CREATE TABLE IF NOT EXISTS tags (
            id    INTEGER PRIMARY KEY,
            name  TEXT NOT NULL UNIQUE,
            color TEXT
        );

        CREATE TABLE IF NOT EXISTS flow_tags (
            flow_id INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
            tag_id  INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (flow_id, tag_id)
        );

        CREATE TABLE IF NOT EXISTS groups (
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            workspace_id INTEGER NOT NULL REFERENCES workspaces(id)
        );

        CREATE TABLE IF NOT EXISTS flow_groups (
            flow_id  INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (flow_id, group_id)
        );

        CREATE TABLE IF NOT EXISTS notes (
            id      INTEGER PRIMARY KEY,
            flow_id INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
            body    TEXT NOT NULL,
            ts      INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_notes_flow ON notes(flow_id);

        CREATE TABLE IF NOT EXISTS match_replace_rules (
            id          INTEGER PRIMARY KEY,
            enabled     INTEGER NOT NULL DEFAULT 1,
            scope       TEXT NOT NULL DEFAULT '',
            match_kind  TEXT NOT NULL,
            pattern     TEXT NOT NULL,
            replacement TEXT NOT NULL,
            on_request  INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS intercepts (
            id          INTEGER PRIMARY KEY,
            flow_id     INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
            state       TEXT NOT NULL DEFAULT 'pending',
            created_at  INTEGER NOT NULL,
            resolved_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_intercepts_state ON intercepts(state);

        -- Contentless FTS5 index. We feed it decoded text (url + host + bodies)
        -- keyed by the flow id stored in the unindexed `flow_id` column. Only the
        -- writer task ever touches it, so it can never block a hot read path.
        CREATE VIRTUAL TABLE IF NOT EXISTS flows_fts USING fts5(
            flow_id UNINDEXED,
            content,
            tokenize = 'unicode61'
        );
        "#,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_exists(conn: &Connection, name: &str) -> bool {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .unwrap();
        n > 0
    }

    #[test]
    fn init_creates_schema_and_default_workspace_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);

        for t in [
            "workspaces",
            "flows",
            "requests",
            "responses",
            "blobs",
            "tags",
            "flow_tags",
            "groups",
            "flow_groups",
            "notes",
            "match_replace_rules",
            "intercepts",
            "flows_fts",
        ] {
            assert!(table_exists(&conn, t), "missing table {t}");
        }

        let name: String = conn
            .query_row(
                "SELECT name FROM workspaces WHERE id = ?1",
                [DEFAULT_WORKSPACE_ID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(name, "default");

        // Idempotent second call, and still exactly one default workspace.
        init(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rejects_newer_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let err = init(&conn).unwrap_err();
        assert!(matches!(err, StoreError::IncompatibleSchema { .. }));
    }
}
