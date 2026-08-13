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
pub const SCHEMA_VERSION: i64 = 8;

/// Id of the always-present default workspace.
pub const DEFAULT_WORKSPACE_ID: i64 = 1;

type MigrationStep = fn(&Connection) -> Result<()>;

const MIGRATIONS: &[(i64, MigrationStep)] = &[
    (1, migrate_v1),
    (2, migrate_v2),
    (3, migrate_v3),
    (4, migrate_v4),
    (5, migrate_v5),
    (6, migrate_v6),
    (7, migrate_v7),
    (8, migrate_v8),
];

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
            // Stamp the schema version INSIDE the transaction (PRAGMA
            // user_version is transactional in SQLite). Doing it after COMMIT
            // as a separate autocommit write leaves a crash window where the
            // schema is migrated but user_version is stale, so the next open
            // re-runs every migration. Inside the txn, the version bump commits
            // atomically with the migration (or rolls back with it).
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            Ok(())
        };
        if let Err(e) = apply() {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
        conn.execute_batch("COMMIT")?;
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
            intercepted INTEGER NOT NULL DEFAULT 0,
            -- Negotiated TLS metadata (schema v3, nullable). On a fresh create
            -- these ship in the baseline DDL; migrate_v3 adds them to pre-v3 files
            -- via a guarded ALTER (skipped here because they already exist).
            tls_version    TEXT,
            tls_cipher     TEXT,
            tls_alpn       TEXT,
            origin_cert_fp TEXT
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
            workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
            -- Named-collection metadata (schema v5, nullable). On a fresh create
            -- these ship in the baseline DDL; migrate_v5 adds them to pre-v5
            -- files via a guarded ALTER (skipped here because they exist).
            description  TEXT,
            created_at   INTEGER NOT NULL DEFAULT 0
        );

        -- A group NAME is the handle the CLI/MCP resolve on, so it must identify
        -- at most one group per workspace (schema v5).
        CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_workspace_name
            ON groups(workspace_id, name);

        CREATE TABLE IF NOT EXISTS flow_groups (
            flow_id  INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (flow_id, group_id)
        );

        -- The PK is (flow_id, group_id), so "every flow in THIS group" — the
        -- read `group show` / `--group` filtering does — has no usable prefix.
        CREATE INDEX IF NOT EXISTS idx_flow_groups_group ON flow_groups(group_id);

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

        -- Hooks: an action applied to every message matching a scope, on one
        -- phase (schema v6). `ord` is spelled short because ORDER is a SQL
        -- keyword; `params` is the JSON payload of the action named by `action`.
        CREATE TABLE IF NOT EXISTS hooks (
            id         INTEGER PRIMARY KEY,
            enabled    INTEGER NOT NULL DEFAULT 1,
            name       TEXT NOT NULL DEFAULT '',
            phase      TEXT NOT NULL,
            host       TEXT NOT NULL DEFAULT '',
            method     TEXT NOT NULL DEFAULT '',
            path       TEXT NOT NULL DEFAULT '',
            status     INTEGER,
            action     TEXT NOT NULL,
            params     TEXT NOT NULL DEFAULT '{}',
            ord        INTEGER NOT NULL DEFAULT 0,
            timeout_ms INTEGER NOT NULL DEFAULT 10000,
            ttl_ms     INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        );

        -- The proxy reads hooks by phase, in application order.
        CREATE INDEX IF NOT EXISTS idx_hooks_phase ON hooks(phase, ord, id);

        -- (`intercepts` used to be created here; it was never written outside its
        -- own tests and is dropped by migrate_v7. Interception is a synchronous
        -- in-flight decision, so it has no persistent form.)

        -- FTS5 index over decoded message text. We feed it decoded text
        -- (url + host + bodies, status + headers + bodies) keyed by the flow id
        -- stored in the unindexed `flow_id` column. The unindexed `kind` column
        -- ('req' | 'resp' | 'raw') lets the writer replace a flow's prior text for
        -- that kind on re-record, so the index never accumulates stale duplicate
        -- rows. Only the writer task ever touches it, so it can never block a hot
        -- read path.
        CREATE VIRTUAL TABLE IF NOT EXISTS flows_fts USING fts5(
            flow_id UNINDEXED,
            kind UNINDEXED,
            content,
            tokenize = 'unicode61'
        );
        "#,
    )?;
    Ok(())
}

/// v2: add the unindexed `kind` column to `flows_fts` so FTS indexing is
/// idempotent per (flow_id, kind). FTS5 virtual tables can't be `ALTER`ed to add
/// columns, so we drop and recreate the index. The index is a derived, fully
/// rebuildable search cache (re-recording a request/response repopulates it), so
/// dropping its rows here is safe — no message data lives only in the FTS table.
fn migrate_v2(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        DROP TABLE IF EXISTS flows_fts;
        CREATE VIRTUAL TABLE flows_fts USING fts5(
            flow_id UNINDEXED,
            kind UNINDEXED,
            content,
            tokenize = 'unicode61'
        );
        "#,
    )?;
    Ok(())
}

/// v3: capture negotiated TLS metadata on flows, index `exec_id` (previously a
/// full scan for `flow_ids_for_exec` / `attribute_flows`), add STRUCTURED
/// websocket capture (`ws_messages`) and the fuzzer/Intruder tables (`attacks`,
/// `attack_results`). Every step is idempotent: the TLS columns are added via a
/// guarded ALTER (fresh DBs already carry them from the v1 baseline), and the
/// index/tables use `IF NOT EXISTS`. This step runs on BOTH the fresh-create path
/// (current=0 replays v1..v3) and the in-place v2→v3 upgrade.
fn migrate_v3(conn: &Connection) -> Result<()> {
    for (col, ty) in [
        ("tls_version", "TEXT"),
        ("tls_cipher", "TEXT"),
        ("tls_alpn", "TEXT"),
        ("origin_cert_fp", "TEXT"),
    ] {
        add_column_if_missing(conn, "flows", col, ty)?;
    }

    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS idx_flows_exec_id ON flows(exec_id);

        -- Structured websocket frame capture, replacing the in-band `ws-c2s:`
        -- marker hack. `payload_blob` holds a content-addressed blob reference
        -- (the blob row id, stored as text) into the shared `blobs` store.
        CREATE TABLE IF NOT EXISTS ws_messages (
            id           INTEGER PRIMARY KEY,
            flow_id      INTEGER REFERENCES flows(id) ON DELETE CASCADE,
            direction    TEXT CHECK(direction IN ('c2s','s2c')),
            opcode       INTEGER,
            fin          INTEGER,
            payload_blob TEXT,
            ts           INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_ws_messages_flow ON ws_messages(flow_id);

        -- Fuzzer / Intruder attack definitions and their per-payload results.
        CREATE TABLE IF NOT EXISTS attacks (
            id           INTEGER PRIMARY KEY,
            workspace    TEXT,
            name         TEXT,
            base_flow_id INTEGER,
            positions    TEXT,
            config       TEXT,
            status       TEXT,
            created_ts   INTEGER
        );

        CREATE TABLE IF NOT EXISTS attack_results (
            id            INTEGER PRIMARY KEY,
            attack_id     INTEGER REFERENCES attacks(id) ON DELETE CASCADE,
            payload       TEXT,
            flow_id       INTEGER,
            status_code   INTEGER,
            resp_len      INTEGER,
            latency_ms    INTEGER,
            anomaly_score REAL,
            ts            INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_attack_results_attack ON attack_results(attack_id);
        "#,
    )?;
    Ok(())
}

/// v4: session-robustness storage. Adds `auth_profiles` (persisted session-auth
/// login command + token-extraction regex + header-injection template, so
/// `session auth refresh` can re-mint a token and update ONE injection rule) and
/// `execs` (capture-completeness telemetry: one row per `burpwn exec` recording
/// whether it was network-facing and how many flows it captured). Both use
/// `IF NOT EXISTS`, so the step is idempotent on the fresh-create replay and the
/// in-place v3→v4 upgrade alike.
///
/// `auth_profiles` is dead as of v8: [`migrate_v8`] rewrites every row into a
/// `hooks` row and drops the table. The `CREATE` stays here so this step remains
/// exactly the one an existing v3 file went through — on a fresh create the
/// table is made here and dropped a few steps later, which costs nothing and
/// keeps the migration list readable as history.
fn migrate_v4(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS auth_profiles (
            id              INTEGER PRIMARY KEY,
            host            TEXT NOT NULL DEFAULT '' UNIQUE,
            login_cmd       TEXT NOT NULL,
            extract_regex   TEXT NOT NULL,
            header_template TEXT NOT NULL,
            token           TEXT,
            rule_id         INTEGER,
            updated_at      INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS execs (
            id             INTEGER PRIMARY KEY,
            exec_id        TEXT NOT NULL UNIQUE,
            cmd            TEXT NOT NULL DEFAULT '',
            network_facing INTEGER NOT NULL DEFAULT 0,
            flow_count     INTEGER NOT NULL DEFAULT 0,
            created_at     INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_execs_exec_id ON execs(exec_id);
        "#,
    )?;
    Ok(())
}

/// v5: flow groups become a real feature. `groups` gains the `description` an
/// agent uses to say what the collection MEANS ("login form → POST /login →
/// redirect + Set-Cookie") plus a `created_at`, the (workspace_id, name) pair
/// becomes unique (a name is the handle the CLI/MCP resolve on, so it may not
/// designate two groups in one workspace), and `flow_groups` gains the
/// group-side index the "flows in this group" read needs — its PK is
/// (flow_id, group_id), whose prefix is the wrong way round for that query.
///
/// Idempotent on both paths: the columns go in through a guarded ALTER (the v1
/// baseline already ships them on a fresh create) and the indexes use
/// `IF NOT EXISTS`. Pre-v5 files could in principle hold two same-named groups
/// in one workspace (nothing enforced it, and nothing but a unit test ever
/// created one), so duplicates are folded onto the lowest id — with their
/// memberships re-pointed — before the unique index goes on, rather than
/// letting the migration fail on someone's database.
fn migrate_v5(conn: &Connection) -> Result<()> {
    // Don't assume the tables are there: a step must be runnable on any older
    // file, including one whose `groups`/`flow_groups` never got created.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS groups (
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
            description  TEXT,
            created_at   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS flow_groups (
            flow_id  INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (flow_id, group_id)
        );
        "#,
    )?;

    add_column_if_missing(conn, "groups", "description", "TEXT")?;
    add_column_if_missing(conn, "groups", "created_at", "INTEGER NOT NULL DEFAULT 0")?;

    conn.execute_batch(
        r#"
        -- Re-point every membership of a duplicate group onto the surviving
        -- (lowest-id) row of the same (workspace_id, name). OR IGNORE: when the
        -- survivor already holds that flow the row stays on the duplicate and
        -- is removed by the cascade below.
        UPDATE OR IGNORE flow_groups SET group_id = (
            SELECT MIN(g2.id) FROM groups g2
            JOIN groups g1 ON g1.id = flow_groups.group_id
            WHERE g2.workspace_id = g1.workspace_id AND g2.name = g1.name
        );
        DELETE FROM groups WHERE id NOT IN (
            SELECT MIN(id) FROM groups GROUP BY workspace_id, name
        );
        -- Memberships the OR IGNORE above left on a now-deleted duplicate. The
        -- FK cascade normally takes care of these, but `PRAGMA foreign_keys` is
        -- a connection setting, so don't depend on it during a migration.
        DELETE FROM flow_groups WHERE group_id NOT IN (SELECT id FROM groups);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_workspace_name
            ON groups(workspace_id, name);
        CREATE INDEX IF NOT EXISTS idx_flow_groups_group ON flow_groups(group_id);
        "#,
    )?;
    Ok(())
}

/// v6: the `hooks` table — an action (declarative header/query edit, a drop, or
/// a sandboxed command whose output is injected) applied to every message
/// matching a scope on one phase. New table + one index, both `IF NOT EXISTS`,
/// so the step is a no-op on the fresh-create replay (the v1 baseline already
/// ships them) and adds the table in place on a v5→v6 upgrade. Nothing existing
/// is touched: match/replace rules keep working exactly as before.
fn migrate_v6(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS hooks (
            id         INTEGER PRIMARY KEY,
            enabled    INTEGER NOT NULL DEFAULT 1,
            name       TEXT NOT NULL DEFAULT '',
            phase      TEXT NOT NULL,
            host       TEXT NOT NULL DEFAULT '',
            method     TEXT NOT NULL DEFAULT '',
            path       TEXT NOT NULL DEFAULT '',
            status     INTEGER,
            action     TEXT NOT NULL,
            params     TEXT NOT NULL DEFAULT '{}',
            ord        INTEGER NOT NULL DEFAULT 0,
            timeout_ms INTEGER NOT NULL DEFAULT 10000,
            ttl_ms     INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_hooks_phase ON hooks(phase, ord, id);
        "#,
    )?;
    Ok(())
}

/// v7: drop `intercepts`. The table promised a persistent intercept history that
/// never existed — nothing outside the store's own tests ever inserted a row.
/// Interception is a SYNCHRONOUS decision: the proxy handler parks on a oneshot
/// inside `burpwn_proxy::InterceptController` and unblocks the instant an
/// operator forwards / edits / drops. There was no consumer for a persisted
/// queue (not the CLI, not MCP, not the export bundle), and an empty table in
/// the schema is an invitation to write a feature against a queue nobody fills.
///
/// The one durable trace of an intercept stays where it belongs: `flows.intercepted`.
///
/// Destructive but lossless in practice (only ever empty in the field), and
/// `IF NOT EXISTS`-guarded so the step is a no-op on the fresh-create replay —
/// where the v1 baseline no longer creates the table at all — and on a bundle
/// exported before v7, which is migrated here during staging like any old file.
fn migrate_v7(conn: &Connection) -> Result<()> {
    conn.execute_batch("DROP TABLE IF EXISTS intercepts;")?;
    Ok(())
}

/// v8: the login macro moves onto the hook engine — `auth_profiles` becomes
/// `hooks` rows and the table is dropped.
///
/// An auth profile was a login command + a one-capture-group extract regex + a
/// header template, and a refresh turned the minted token into a match/replace
/// rule. That rule could only ever REWRITE an `Authorization` header the request
/// already carried; a request that sent none went upstream bare, which is the
/// exact shape of "the first call after the token expires still 401s". A
/// `pre-request` hook with an `exec` action expresses the same profile and does
/// not have that hole: it runs the login command in the sandbox, extracts the
/// token, and `set-header` SYNTHESIZES the header when it is absent — on the
/// request that is waiting, before it is forwarded.
///
/// What each row becomes:
///
/// - one enabled `pre-request` / `exec` hook named `auth:<host>` (`auth:*` for a
///   profile with no host scope), carrying the command, the regex and the header
///   template as its injection;
/// - the profile's generated match/replace rule (`rule_id`) is DELETED — it is
///   what the hook now does, and leaving it behind would rewrite the header a
///   second time with a token frozen at migration time;
/// - the stored `token` is NOT carried over. It lived in the table because the
///   rule needed a literal to substitute; the hook mints its own on the first
///   in-scope request and keeps it in the daemon's memory for the hook TTL. A
///   session file therefore stops being a place where a bearer token is at rest.
///
/// A row whose header template cannot be expressed as an injection (no colon, no
/// `{}`, a name with CR/LF — only reachable by hand-editing the database, since
/// `session auth set` validates all of it) is migrated DISABLED rather than
/// dropped: the login command and the regex are the parts that took work, and a
/// disabled hook is visible in `hook list` instead of silently gone.
fn migrate_v8(conn: &Connection) -> Result<()> {
    if !table_exists(conn, "auth_profiles")? {
        return Ok(());
    }
    let profiles = {
        let mut stmt = conn.prepare(
            "SELECT host, login_cmd, extract_regex, header_template, updated_at
             FROM auth_profiles ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    for (host, login_cmd, extract, template, updated_at) in profiles {
        let (name, value_template) = inject_from_template(&template);
        let usable = header_template_is_usable(&template);
        let action = crate::model::HookAction::Exec {
            cmd: login_cmd,
            extract,
            inject: crate::model::HookInject {
                // `set-header` (add-or-replace), which covers BOTH what the old
                // match/replace rule did (replace a stale header) and what it
                // could not (put one on a request that has none).
                kind: crate::model::HookInjectKind::SetHeader,
                name,
                value_template,
            },
        };
        conn.execute(
            "INSERT INTO hooks(enabled, name, phase, host, method, path, status, action, params,
                               ord, timeout_ms, ttl_ms, created_at)
             VALUES (?1, ?2, 'pre-request', ?3, '', '', NULL, ?4, ?5, 0, ?6, ?7, ?8)",
            rusqlite::params![
                usable as i64,
                auth_hook_name(&host),
                host,
                action.kind(),
                action.params_json()?,
                // The CLI's `hook add` defaults (burpwn_cli::hooks::DEFAULT_*),
                // spelled out because the store cannot reach the CLI crate: a
                // 10 s command budget and a 5 min token cache.
                10_000_i64,
                300_000_i64,
                updated_at,
            ],
        )?;
    }

    // The generated injection rules (whose replacement holds the token as a
    // literal). Guarded: a step must survive being replayed on a file whose
    // `match_replace_rules` was never created.
    if table_exists(conn, "match_replace_rules")? {
        conn.execute_batch(
            "DELETE FROM match_replace_rules WHERE id IN
                (SELECT rule_id FROM auth_profiles WHERE rule_id IS NOT NULL);",
        )?;
    }
    conn.execute_batch("DROP TABLE auth_profiles;")?;
    Ok(())
}

/// The hook name a session-auth profile for `host` is stored under. Kept in sync
/// with `burpwn_cli::auth::auth_hook_name`, which is what `session auth status`
/// looks the hooks back up by (this module cannot reach the CLI crate).
fn auth_hook_name(host: &str) -> String {
    let scope = if host.trim().is_empty() { "*" } else { host };
    format!("auth:{scope}")
}

/// Whether a `Name: value {}` header template is directly expressible as a hook
/// injection.
fn header_template_is_usable(template: &str) -> bool {
    match template.split_once(':') {
        Some((name, value)) => {
            !name.trim().is_empty()
                && value.contains("{}")
                && !template.contains(['\r', '\n', '\0'])
        }
        None => false,
    }
}

/// Split a header template into an injection `(name, value_template)`, repairing
/// what can be repaired so the login command is never lost with it (the hook is
/// stored disabled when [`header_template_is_usable`] said no).
fn inject_from_template(template: &str) -> (String, String) {
    let (name, value) = match template.split_once(':') {
        Some((n, v)) => (n.trim(), v.trim()),
        None => (template.trim(), ""),
    };
    let name = match name.replace(['\r', '\n', '\0'], "") {
        n if n.is_empty() => "Authorization".to_string(),
        n => n,
    };
    let value = value.replace(['\r', '\n', '\0'], "");
    let value = if value.contains("{}") {
        value
    } else {
        format!("{value} {{}}").trim_start().to_string()
    };
    (name, value)
}

/// Whether a table by that name exists.
fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Whether `table` already has a column named `column`.
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut found = false;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for r in rows {
        if r? == column {
            found = true;
            break;
        }
    }
    Ok(found)
}

/// `ALTER TABLE ADD COLUMN` guarded by an existence check, since SQLite has no
/// `ADD COLUMN IF NOT EXISTS`. Keeps the v3 migration idempotent and safe on the
/// fresh-create path where the v1 baseline already ships the column.
fn add_column_if_missing(conn: &Connection, table: &str, column: &str, ty: &str) -> Result<()> {
    if !column_exists(conn, table, column)? {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {ty};"))?;
    }
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

    /// Whether an index by that name exists (indexes live in `sqlite_master`
    /// under `type = 'index'`, alongside tables).
    fn index_exists(conn: &Connection, name: &str) -> bool {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
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
            "hooks",
            "flows_fts",
            "ws_messages",
            "attacks",
            "attack_results",
            "execs",
        ] {
            assert!(table_exists(&conn, t), "missing table {t}");
        }

        // v7: a fresh file must NOT carry the dead intercept queue.
        assert!(!table_exists(&conn, "intercepts"));
        // v8: nor the auth profiles, which are hooks now.
        assert!(!table_exists(&conn, "auth_profiles"));

        // v3 TLS columns present on a fresh create.
        for c in ["tls_version", "tls_cipher", "tls_alpn", "origin_cert_fp"] {
            assert!(column_exists(&conn, "flows", c), "missing flows.{c}");
        }

        // v5 group metadata + indexes present on a fresh create.
        for c in ["description", "created_at"] {
            assert!(column_exists(&conn, "groups", c), "missing groups.{c}");
        }
        for i in ["idx_groups_workspace_name", "idx_flow_groups_group"] {
            assert!(index_exists(&conn, i), "missing index {i}");
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

    fn column_exists(conn: &Connection, table: &str, column: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        cols.iter().any(|c| c == column)
    }

    #[test]
    fn fresh_db_has_kind_column_on_flows_fts() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        assert!(
            column_exists(&conn, "flows_fts", "kind"),
            "flows_fts must carry the per-kind column"
        );
    }

    #[test]
    fn migrates_v1_fts_to_v2_kind_column() {
        // Simulate a file created at schema v1 (no `kind` column on flows_fts),
        // with a stray FTS row, then upgrade it via init().
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("BEGIN").unwrap();
        migrate_v1(&conn).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();

        // The v1 baseline now ships the `kind` column too, but emulate an OLD
        // 2-column index to exercise the v2 rebuild path.
        conn.execute_batch(
            "DROP TABLE flows_fts;
             CREATE VIRTUAL TABLE flows_fts USING fts5(flow_id UNINDEXED, content);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO flows_fts(flow_id, content) VALUES (1, 'legacytext')",
            [],
        )
        .unwrap();
        assert!(!column_exists(&conn, "flows_fts", "kind"));

        // Upgrade.
        init(&conn).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(column_exists(&conn, "flows_fts", "kind"));

        // The index is rebuildable, so the legacy row is dropped; new inserts work
        // with the per-kind shape and remain searchable.
        conn.execute(
            "INSERT INTO flows_fts(flow_id, kind, content) VALUES (2, 'req', 'freshtext')",
            [],
        )
        .unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM flows_fts WHERE flows_fts MATCH 'freshtext'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn migrates_v2_to_v3_adds_columns_tables_and_preserves_data() {
        // Emulate a file stamped at schema v2: the pre-v3 `flows` shape (no TLS
        // columns) with an existing row, and none of the v3 tables. The upgrade
        // must add the columns/tables in place without touching existing data.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE workspaces (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL
            );
            INSERT INTO workspaces(id, name, created_at) VALUES (1, 'default', 0);
            CREATE TABLE flows (
                id INTEGER PRIMARY KEY,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
                ts_start INTEGER NOT NULL, ts_end INTEGER, exec_id TEXT,
                client_addr TEXT NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL,
                sni TEXT, scheme TEXT NOT NULL, protocol TEXT NOT NULL,
                intercepted INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO flows(id, workspace_id, ts_start, client_addr, dst_ip, dst_port, scheme, protocol)
                VALUES (7, 1, 111, '127.0.0.1:1', '10.0.0.1', 443, 'https', 'h1');
            "#,
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();

        // Pre-conditions: none of the v3 additions exist yet.
        assert!(!column_exists(&conn, "flows", "tls_version"));
        assert!(!table_exists(&conn, "ws_messages"));
        assert!(!table_exists(&conn, "attacks"));

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        for c in ["tls_version", "tls_cipher", "tls_alpn", "origin_cert_fp"] {
            assert!(column_exists(&conn, "flows", c), "missing flows.{c}");
        }
        for t in ["ws_messages", "attacks", "attack_results"] {
            assert!(table_exists(&conn, t), "missing table {t}");
        }
        // Existing data preserved (row 7 still there, TLS columns default NULL).
        let (ts, tls): (i64, Option<String>) = conn
            .query_row(
                "SELECT ts_start, tls_version FROM flows WHERE id = 7",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(ts, 111);
        assert_eq!(tls, None);

        // Idempotent: a second init() is a no-op and does not double-add anything.
        init(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn migrates_v3_to_v4_adds_the_exec_telemetry_table() {
        // A file stamped at schema v3 (has flows + v3 tables but none of the v4
        // additions) must gain `execs` in place on upgrade. `auth_profiles` is
        // created by the same step and dropped again by v8, so it must NOT be
        // there once the whole chain has run.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("BEGIN").unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();

        assert!(!table_exists(&conn, "auth_profiles"));
        assert!(!table_exists(&conn, "execs"));

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(table_exists(&conn, "execs"));
        assert!(!table_exists(&conn, "auth_profiles"));

        // Idempotent second init is a no-op.
        init(&conn).unwrap();
    }

    /// Build a file in the pre-v5 shape of the tables v5 touches: `groups`
    /// without description/created_at, `flow_groups`, plus the `workspaces` and
    /// `flows` rows they reference. Stamped at `user_version = 4`.
    fn v4_db_with_groups() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE workspaces (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL
            );
            INSERT INTO workspaces(id, name, created_at) VALUES (1, 'default', 0);
            CREATE TABLE flows (
                id INTEGER PRIMARY KEY,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
                ts_start INTEGER NOT NULL
            );
            INSERT INTO flows(id, workspace_id, ts_start) VALUES (11, 1, 100), (12, 1, 200);
            CREATE TABLE groups (
                id           INTEGER PRIMARY KEY,
                name         TEXT NOT NULL,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id)
            );
            CREATE TABLE flow_groups (
                flow_id  INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
                group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                PRIMARY KEY (flow_id, group_id)
            );
            INSERT INTO groups(id, name, workspace_id) VALUES (1, 'auth-flow', 1);
            INSERT INTO flow_groups(flow_id, group_id) VALUES (11, 1);
            "#,
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 4).unwrap();
        conn
    }

    #[test]
    fn migrates_v4_to_v5_adds_group_metadata_and_preserves_memberships() {
        let conn = v4_db_with_groups();
        assert!(!column_exists(&conn, "groups", "description"));
        assert!(!index_exists(&conn, "idx_groups_workspace_name"));

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        for c in ["description", "created_at"] {
            assert!(column_exists(&conn, "groups", c), "missing groups.{c}");
        }
        for i in ["idx_groups_workspace_name", "idx_flow_groups_group"] {
            assert!(index_exists(&conn, i), "missing index {i}");
        }

        // Pre-existing data survives: the group keeps its id/name (description
        // defaults to NULL) and its membership row is untouched.
        let (name, desc): (String, Option<String>) = conn
            .query_row(
                "SELECT name, description FROM groups WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(name, "auth-flow");
        assert_eq!(desc, None);
        let members: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM flow_groups WHERE group_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(members, 1);

        // The new unique index is live: a second 'auth-flow' in workspace 1 is
        // refused, while the same name in another workspace is fine.
        assert!(conn
            .execute(
                "INSERT INTO groups(name, workspace_id) VALUES ('auth-flow', 1)",
                [],
            )
            .is_err());
        conn.execute(
            "INSERT INTO workspaces(id, name, created_at) VALUES (2, 'other', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO groups(name, workspace_id) VALUES ('auth-flow', 2)",
            [],
        )
        .unwrap();

        // Idempotent second init.
        init(&conn).unwrap();
    }

    #[test]
    fn migrating_to_v5_folds_duplicate_group_names_onto_the_lowest_id() {
        // Nothing before v5 stopped a workspace holding two same-named groups,
        // so the unique index cannot simply be created: the duplicates must
        // collapse (memberships and all) instead of failing the upgrade.
        let conn = v4_db_with_groups();
        conn.execute_batch(
            "INSERT INTO groups(id, name, workspace_id) VALUES (2, 'auth-flow', 1);
             INSERT INTO flow_groups(flow_id, group_id) VALUES (12, 2), (11, 2);",
        )
        .unwrap();

        init(&conn).unwrap();

        // One 'auth-flow' left, the lowest id, owning BOTH flows (11 was already
        // its member, 12 was re-pointed off the duplicate).
        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM groups WHERE name = 'auth-flow' AND workspace_id = 1")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ids, vec![1]);
        let mut members: Vec<i64> = conn
            .prepare("SELECT flow_id FROM flow_groups WHERE group_id = 1")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        members.sort_unstable();
        assert_eq!(members, vec![11, 12]);
    }

    /// A file in the real v5 shape: every table v5 shipped, stamped at
    /// `user_version = 5`, with a match/replace rule and a group in it. The v6
    /// upgrade must add `hooks` without disturbing any of that.
    fn v5_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("BEGIN").unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        // The v1 baseline already ships v6's table on a fresh create; drop it to
        // emulate a file that genuinely predates v6.
        conn.execute_batch("DROP TABLE IF EXISTS hooks;").unwrap();
        conn.execute_batch(
            "INSERT INTO workspaces(id, name, created_at) VALUES (1, 'default', 0);
             INSERT INTO groups(id, name, workspace_id, created_at)
                VALUES (1, 'auth-flow', 1, 7);
             INSERT INTO match_replace_rules(id, enabled, scope, match_kind, pattern, replacement, on_request)
                VALUES (1, 1, 'api.test', 'header', '^Authorization:.*', 'Authorization: Bearer x', 1);",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 5).unwrap();
        conn
    }

    #[test]
    fn migrates_v5_to_v6_adds_hooks_and_keeps_everything_else() {
        let conn = v5_db();
        assert!(!table_exists(&conn, "hooks"));

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(table_exists(&conn, "hooks"));
        assert!(index_exists(&conn, "idx_hooks_phase"));
        for c in [
            "enabled",
            "name",
            "phase",
            "host",
            "method",
            "path",
            "status",
            "action",
            "params",
            "ord",
            "timeout_ms",
            "ttl_ms",
            "created_at",
        ] {
            assert!(column_exists(&conn, "hooks", c), "missing hooks.{c}");
        }

        // The pre-existing match/replace rule and group are untouched: hooks are
        // an ADDITION, they do not migrate anything onto themselves.
        let pattern: String = conn
            .query_row(
                "SELECT pattern FROM match_replace_rules WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pattern, "^Authorization:.*");
        let group: String = conn
            .query_row("SELECT name FROM groups WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(group, "auth-flow");

        // The new table takes rows, and a second init() is a no-op.
        conn.execute(
            "INSERT INTO hooks(phase, action, params) VALUES ('pre-request', 'add-header', '{}')",
            [],
        )
        .unwrap();
        init(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM hooks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn migrates_v6_to_v7_drops_the_dead_intercept_queue() {
        // A file in the real v6 shape: everything v6 shipped, `intercepts`
        // included (with a row, as an old test-built file could have), stamped
        // at user_version = 6.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("BEGIN").unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        migrate_v6(&conn).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE intercepts (
                id          INTEGER PRIMARY KEY,
                flow_id     INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
                state       TEXT NOT NULL DEFAULT 'pending',
                created_at  INTEGER NOT NULL,
                resolved_at INTEGER
            );
            CREATE INDEX idx_intercepts_state ON intercepts(state);
            INSERT INTO workspaces(id, name, created_at) VALUES (1, 'default', 0);
            INSERT INTO flows(id, workspace_id, ts_start, client_addr, dst_ip, dst_port, scheme, protocol)
                VALUES (7, 1, 111, '127.0.0.1:1', '10.0.0.1', 443, 'https', 'h1');
            INSERT INTO intercepts(flow_id, state, created_at) VALUES (7, 'pending', 5);
            INSERT INTO match_replace_rules(id, enabled, scope, match_kind, pattern, replacement, on_request)
                VALUES (1, 1, 'api.test', 'header', '^Authorization:.*', 'Authorization: Bearer x', 1);
            "#,
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 6).unwrap();
        assert!(table_exists(&conn, "intercepts"));

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(!table_exists(&conn, "intercepts"), "v7 must drop the table");
        assert!(!index_exists(&conn, "idx_intercepts_state"));

        // Nothing else is disturbed: the flow and the rule are still there.
        let flows: i64 = conn
            .query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))
            .unwrap();
        assert_eq!(flows, 1);
        let pattern: String = conn
            .query_row(
                "SELECT pattern FROM match_replace_rules WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pattern, "^Authorization:.*");

        // Idempotent second init.
        init(&conn).unwrap();
    }

    /// A file in the real v7 shape, with `n` session-auth profiles and the
    /// match/replace rules a refresh generated for them. Stamped at
    /// `user_version = 7` — i.e. what a session that has been in use since
    /// before this migration actually looks like on disk.
    fn v7_db_with_auth_profiles() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("BEGIN").unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        migrate_v6(&conn).unwrap();
        migrate_v7(&conn).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO workspaces(id, name, created_at) VALUES (1, 'default', 0);
            -- The rule a refresh generated for the profile (id 1), plus an
            -- UNRELATED rule the operator wrote by hand (id 2).
            INSERT INTO match_replace_rules(id, enabled, scope, match_kind, pattern, replacement, on_request)
                VALUES (1, 1, 'api.test', 'header', '^Authorization:.*',
                        'Authorization: Bearer minted-token', 1),
                       (2, 1, '', 'body', 'foo', 'bar', 1);
            INSERT INTO auth_profiles(id, host, login_cmd, extract_regex, header_template,
                                      token, rule_id, updated_at)
                VALUES (1, 'api.test', 'curl -u admin:hunter2 https://api.test/login',
                        '"token":"([^"]+)"', 'Authorization: Bearer {}',
                        'minted-token', 1, 4242),
                       (2, '', 'get-key.sh', '(key-[a-z]+)', 'X-Api-Key: {}',
                        NULL, NULL, 7),
                       -- Hand-edited into a shape no `session auth set` would
                       -- have accepted: no placeholder to substitute into.
                       (3, 'broken.test', 'mint.sh', '(t)', 'Authorization', NULL, NULL, 9);
            -- A hook that was already there: the migration must not disturb it.
            INSERT INTO hooks(id, enabled, name, phase, host, method, path, status,
                              action, params, ord, timeout_ms, ttl_ms, created_at)
                VALUES (1, 1, 'ua', 'pre-request', '', '', '', NULL, 'add-header',
                        '{"name":"User-Agent","value":"burpwn"}', 0, 10000, 0, 5);
            "#,
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 7).unwrap();
        conn
    }

    /// THE migration a real session goes through: every auth profile comes out
    /// the other side as a hook that does strictly more (it can ADD the header,
    /// which the rule it replaces could not), and nothing is silently lost.
    #[test]
    fn migrates_v7_to_v8_rewriting_auth_profiles_as_hooks() {
        let conn = v7_db_with_auth_profiles();

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(!table_exists(&conn, "auth_profiles"), "v8 drops the table");

        // Three profiles in, three hooks out — beside the pre-existing one.
        let mut stmt = conn
            .prepare(
                "SELECT id, enabled, name, phase, host, action, params, timeout_ms, ttl_ms,
                        created_at
                 FROM hooks ORDER BY id",
            )
            .unwrap();
        type Row = (
            i64,
            i64,
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            i64,
        );
        let hooks: Vec<Row> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(hooks.len(), 4);
        assert_eq!(hooks[0].2, "ua", "the pre-existing hook is untouched");

        // The host-scoped profile.
        let (_, enabled, name, phase, host, action, params, timeout, ttl, created) = &hooks[1];
        assert_eq!(*enabled, 1);
        assert_eq!(name, "auth:api.test");
        assert_eq!(phase, "pre-request");
        assert_eq!(host, "api.test");
        assert_eq!(action, "exec");
        assert_eq!(*timeout, 10_000);
        assert_eq!(*ttl, 300_000);
        assert_eq!(*created, 4242, "the profile's own timestamp is kept");
        let p: serde_json::Value = serde_json::from_str(params).unwrap();
        assert_eq!(p["cmd"], "curl -u admin:hunter2 https://api.test/login");
        assert_eq!(p["extract"], r#""token":"([^"]+)""#);
        assert_eq!(
            p["inject_kind"], "set-header",
            "add-or-replace: it must also work on a request that sends NO \
             Authorization header — the hole the match/replace rule had"
        );
        assert_eq!(p["inject_name"], "Authorization");
        assert_eq!(p["inject_value"], "Bearer {}");

        // The un-scoped profile keeps its "every host" scope and gets the `*`
        // name the CLI façade looks it up by.
        assert_eq!(hooks[2].2, "auth:*");
        assert_eq!(hooks[2].4, "");
        assert_eq!(hooks[2].1, 1);

        // The hand-broken template: migrated DISABLED rather than dropped, with
        // the login command and regex preserved.
        assert_eq!(hooks[3].2, "auth:broken.test");
        assert_eq!(hooks[3].1, 0, "an unusable template lands disabled");
        let p: serde_json::Value = serde_json::from_str(&hooks[3].6).unwrap();
        assert_eq!(p["cmd"], "mint.sh");
        assert_eq!(p["inject_name"], "Authorization");

        // The generated injection rule is gone (the hook does that job now);
        // the operator's own rule is NOT.
        let rules: Vec<i64> = conn
            .prepare("SELECT id FROM match_replace_rules ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(rules, vec![2]);

        // Idempotent second init, and the hooks are not duplicated by it.
        init(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM hooks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 4);
    }

    /// The migrated hook must be readable by the ordinary hook path — a row the
    /// proxy refuses to decode would take the WHOLE hook set down with it (see
    /// `Reader::list_hooks`), so "it migrated" has to mean "it decodes".
    #[test]
    fn a_migrated_auth_hook_decodes_as_an_exec_hook() {
        use crate::model::{HookAction, HookInjectKind};
        let conn = v7_db_with_auth_profiles();
        init(&conn).unwrap();

        let (action, params): (String, String) = conn
            .query_row(
                "SELECT action, params FROM hooks WHERE name = 'auth:api.test'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        match HookAction::from_db(&action, &params).unwrap() {
            HookAction::Exec {
                cmd,
                extract,
                inject,
            } => {
                assert!(cmd.contains("api.test/login"));
                assert_eq!(extract, r#""token":"([^"]+)""#);
                assert_eq!(inject.kind, HookInjectKind::SetHeader);
                assert_eq!(inject.value_template, "Bearer {}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn user_version_is_stamped_atomically_with_migrations() {
        // The version stamp must commit together with the schema, never as a
        // separate post-COMMIT write. We assert the end state is consistent:
        // schema present AND user_version current, with a single init() call.
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(table_exists(&conn, "flows"));

        // A failing migration must leave BOTH the schema and the version
        // untouched (the version bump rolls back with the migration), so the
        // next open re-applies cleanly rather than seeing a half-stamped file.
        let fresh = Connection::open_in_memory().unwrap();
        fresh.execute_batch("BEGIN").unwrap();
        let migrated = (|| -> Result<()> {
            migrate_v1(&fresh)?;
            // simulate a crash/failure before the version stamp by erroring out
            Err(StoreError::IncompatibleSchema {
                found: 0,
                supported: SCHEMA_VERSION,
            })
        })();
        assert!(migrated.is_err());
        fresh.execute_batch("ROLLBACK").unwrap();
        let v2: i64 = fresh
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        // Rolled back: still at the initial version, schema gone too.
        assert_eq!(v2, 0);
        assert!(!table_exists(&fresh, "flows"));
        // A subsequent real init() then succeeds end-to-end.
        init(&fresh).unwrap();
        let v3: i64 = fresh
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v3, SCHEMA_VERSION);
        assert!(table_exists(&fresh, "flows"));
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
