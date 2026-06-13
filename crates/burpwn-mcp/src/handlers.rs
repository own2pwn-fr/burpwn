//! Transport-free tool logic.
//!
//! Every MCP tool maps onto one async function here that takes the resolved
//! [`Paths`] + session name (+ typed params) and returns a `serde_json::Value`.
//! Keeping the logic out of the rmcp `#[tool]` methods lets the unit tests drive
//! the tools directly against a temp session db with no MCP transport involved.
//!
//! - Query / mutation tools open the session store via [`Store::open`] and use
//!   the [`burpwn_store::Reader`] / [`burpwn_store::WriteHandle`].
//! - Daemon / intercept tools connect a [`ControlClient`] to the session's
//!   control socket; if the socket is absent/unanswering they return a clear
//!   error telling the agent to start the proxy daemon (`burpwn exec …`).
//! - `exec` shells out to the burpwn binary itself (see [`run_exec`]).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use burpwn_cli::control::{ControlClient, Edits, HeaderEdit};
use burpwn_cli::paths::Paths;
use burpwn_store::model::{FlowDetail, FlowFilter, MatchKind, NewMatchReplaceRule, Protocol};
use burpwn_store::Store;

/// Wall-clock unix-millis helper for timestamped writes.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Open the session store, with a context message naming the db path.
fn open_store(paths: &Paths, session: &str) -> Result<Store> {
    let db = paths.session_db(session);
    Store::open(&db).with_context(|| format!("opening session store {}", db.display()))
}

// --- session ---------------------------------------------------------------

/// `session_list` — names of all sessions + the active one.
pub fn session_list(paths: &Paths) -> Result<Value> {
    Ok(json!({
        "sessions": paths.list_sessions(),
        "active": paths.active_session(),
    }))
}

/// `session_current` — the active session name and whether its db exists.
pub fn session_current(paths: &Paths) -> Result<Value> {
    let active = paths.active_session();
    let exists = paths.session_db(&active).exists();
    Ok(json!({ "active": active, "db_exists": exists }))
}

// --- query -----------------------------------------------------------------

/// `req_list` — flow rows matching the filter, newest first.
pub fn req_list(
    paths: &Paths,
    session: &str,
    params: &crate::params::ReqListParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let filter = FlowFilter {
        workspace_id: params.workspace,
        host_contains: params.host.clone(),
        status: params.status,
        method: params.method.clone(),
        protocol: params.protocol.as_deref().map(Protocol::from_db),
        port: params.port,
        limit: params.limit,
        offset: params.offset,
    };
    let rows = store.reader().list_flows(&filter)?;
    Ok(json!({ "flows": rows, "count": rows.len() }))
}

/// JSON view of a flow detail, bodies decoded as lossy UTF-8 (mirrors the CLI's
/// `req show --json`). When `raw` is set, also include the verbatim head+body.
fn flow_detail_json(detail: &FlowDetail, raw: bool) -> Value {
    let req = detail.request.as_ref().map(|r| {
        json!({
            "method": r.method,
            "authority": r.authority,
            "path": r.path,
            "http_version": r.http_version,
            "headers": String::from_utf8_lossy(&r.headers),
            "body": String::from_utf8_lossy(&r.body),
        })
    });
    let resp = detail.response.as_ref().map(|r| {
        json!({
            "status": r.status,
            "http_version": r.http_version,
            "headers": String::from_utf8_lossy(&r.headers),
            "body": String::from_utf8_lossy(&r.body),
            "timing_ms": r.timing_ms,
        })
    });
    let mut v = json!({
        "id": detail.flow.id,
        "workspace_id": detail.flow.workspace_id,
        "protocol": detail.flow.protocol,
        "scheme": detail.flow.scheme,
        "dst_ip": detail.flow.dst_ip,
        "dst_port": detail.flow.dst_port,
        "sni": detail.flow.sni,
        "intercepted": detail.flow.intercepted,
        "exec_id": detail.exec_id,
        "client_addr": detail.client_addr,
        "request": req,
        "response": resp,
    });
    if raw {
        let obj = v.as_object_mut().expect("object");
        if let Some(r) = &detail.request {
            let mut s = format!("{} {} {}\r\n", r.method, r.path, r.http_version);
            s.push_str(&String::from_utf8_lossy(&r.headers));
            s.push_str("\r\n");
            s.push_str(&String::from_utf8_lossy(&r.body));
            obj.insert("raw_request".into(), Value::String(s));
        }
        if let Some(r) = &detail.response {
            let mut s = format!("{} {}\r\n", r.http_version, r.status);
            s.push_str(&String::from_utf8_lossy(&r.headers));
            s.push_str("\r\n");
            s.push_str(&String::from_utf8_lossy(&r.body));
            obj.insert("raw_response".into(), Value::String(s));
        }
    }
    v
}

/// `req_show` — full decoded flow detail, or an error if absent.
pub fn req_show(
    paths: &Paths,
    session: &str,
    params: &crate::params::ReqShowParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    match store.reader().get_flow(params.id)? {
        Some(detail) => Ok(flow_detail_json(&detail, params.raw)),
        None => Err(anyhow!("no such flow: {}", params.id)),
    }
}

/// `req_search` — matching flow ids (newest first).
pub fn req_search(
    paths: &Paths,
    session: &str,
    params: &crate::params::ReqSearchParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let ids = store.reader().search(&params.query)?;
    Ok(json!({ "flow_ids": ids }))
}

/// `workspace_list`.
pub fn workspace_list(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    Ok(json!({ "workspaces": store.reader().list_workspaces()? }))
}

/// `tag_list`.
pub fn tag_list(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    Ok(json!({ "tags": store.reader().list_tags()? }))
}

/// `match_replace_list`.
pub fn match_replace_list(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    Ok(json!({ "rules": store.reader().list_match_replace()? }))
}

// --- mutation --------------------------------------------------------------

/// `match_replace_add` — insert a rule (enabled by default).
pub async fn match_replace_add(
    paths: &Paths,
    session: &str,
    params: &crate::params::MatchReplaceAddParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let rule = NewMatchReplaceRule {
        enabled: true,
        scope: params.scope.clone(),
        match_kind: MatchKind::from_db(&params.kind),
        pattern: params.pattern.clone(),
        replacement: params.replacement.clone(),
        on_request: params.on_request,
    };
    let id = store.writer().add_match_replace(rule).await?;
    Ok(json!({ "id": id }))
}

/// `tag_add` — create/attach a tag to a flow.
pub async fn tag_add(
    paths: &Paths,
    session: &str,
    params: &crate::params::TagAddParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let id = store
        .writer()
        .tag_flow(params.flow_id, params.name.clone(), params.color.clone())
        .await?;
    Ok(json!({ "tag_id": id }))
}

/// `note_add` — attach a note to a flow.
pub async fn note_add(
    paths: &Paths,
    session: &str,
    params: &crate::params::NoteAddParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let id = store
        .writer()
        .add_note(params.flow_id, params.body.clone(), now_ms())
        .await?;
    Ok(json!({ "note_id": id }))
}

/// `workspace_new` — create a workspace.
pub async fn workspace_new(
    paths: &Paths,
    session: &str,
    params: &crate::params::WorkspaceNewParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let id = store
        .writer()
        .create_workspace(params.name.clone(), now_ms())
        .await?;
    Ok(json!({ "workspace_id": id }))
}

// --- daemon / intercept ----------------------------------------------------

/// Connect a [`ControlClient`] to the session's control socket, mapping a
/// connection failure to an actionable error for the agent.
async fn connect_control(paths: &Paths, session: &str) -> Result<ControlClient> {
    let sock = paths.control_sock(session);
    ControlClient::connect(&sock).await.map_err(|_| {
        anyhow!(
            "no burpwn proxy daemon answering on {} for session '{session}'. \
             Start it by running a command through the sandbox, e.g. the `exec` tool \
             or `burpwn exec -- <cmd>`, which spawns the daemon.",
            sock.display()
        )
    })
}

/// Turn a [`burpwn_cli::control::ControlResponse`] into a tool JSON value,
/// surfacing a daemon-side `Error` as an `anyhow` error.
fn control_value(resp: burpwn_cli::control::ControlResponse) -> Result<Value> {
    use burpwn_cli::control::ControlResponse as R;
    match resp {
        R::Status {
            running,
            session,
            intercept_enabled,
            pending,
            dns_port,
        } => Ok(json!({
            "running": running,
            "session": session,
            "intercept_enabled": intercept_enabled,
            "pending": pending,
            "dns_port": dns_port,
        })),
        R::Ack => Ok(json!({ "ok": true })),
        R::Intercepts { items } => Ok(json!({ "intercepts": items })),
        R::Pending { item } => match item {
            Some(it) => Ok(json!({ "pending": true, "intercept": it })),
            None => Ok(json!({ "pending": false })),
        },
        R::Resolved { found } => Ok(json!({ "found": found })),
        R::Error { message } => Err(anyhow!("daemon error: {message}")),
    }
}

/// `intercept_enable`.
pub async fn intercept_enable(paths: &Paths, session: &str) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    control_value(c.intercept_enable().await?)
}

/// `intercept_disable`.
pub async fn intercept_disable(paths: &Paths, session: &str) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    control_value(c.intercept_disable().await?)
}

/// `intercept_list`.
pub async fn intercept_list(paths: &Paths, session: &str) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    control_value(c.intercept_list().await?)
}

/// `await_intercept` — the long-poll. Blocks up to `timeout_secs` (default
/// [`crate::DEFAULT_AWAIT_SECS`]) for a parked request.
pub async fn await_intercept(
    paths: &Paths,
    session: &str,
    params: &crate::params::AwaitInterceptParams,
) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    let secs = params.timeout_secs.unwrap_or(crate::DEFAULT_AWAIT_SECS);
    control_value(c.intercept_await(secs).await?)
}

/// `intercept_forward` — release a parked intercept with optional edits.
pub async fn intercept_forward(
    paths: &Paths,
    session: &str,
    params: &crate::params::InterceptForwardParams,
) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    let edits = Edits {
        set_headers: params
            .set_headers
            .iter()
            .map(|h| HeaderEdit {
                name: h.name.clone(),
                value: h.value.clone(),
            })
            .collect(),
        body: params.set_body.clone(),
        method: None,
        path: None,
    };
    control_value(c.intercept_forward(params.id, edits).await?)
}

/// `intercept_drop`.
pub async fn intercept_drop(
    paths: &Paths,
    session: &str,
    params: &crate::params::InterceptDropParams,
) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    control_value(c.intercept_drop(params.id).await?)
}

// --- exec ------------------------------------------------------------------

/// `exec` — run a command in the sandbox by shelling out to the burpwn binary.
///
/// We re-invoke our own executable as
/// `<exe> --json exec --session S [--timeout T] [--workspace W] -- <argv…>`
/// with **fd 3** wired to a pipe. `--json` is the CLI's *global* flag; `--session`
/// / `--timeout` / `--workspace` are `exec`'s own args (so they must follow the
/// `exec` token). The CLI's exec path writes its
/// `{ok, data:{exit_code, exec_id, captured_request_ids}}` envelope to fd 3 when
/// it is open (see `burpwn_cli::exec::write_json_envelope`), keeping it cleanly
/// separated from the child's own stdout/stderr (which we let inherit so any
/// tool output is visible in the server's logs but never corrupts the envelope).
///
/// This deliberately reuses the whole CLI orchestration (daemon-ensure, sandbox
/// runtime, flow attribution) instead of reimplementing the sandbox here.
///
/// `params.workspace` is parsed as an i64 (the CLI's `--workspace` is a workspace
/// id); a non-numeric value is ignored with a warning rather than failing.
pub async fn run_exec(session: &str, params: &crate::params::ExecParams) -> Result<Value> {
    use std::os::fd::FromRawFd;
    use tokio::io::AsyncReadExt;

    if params.argv.is_empty() {
        return Err(anyhow!("exec: argv must not be empty"));
    }

    let exe = std::env::current_exe().context("locating the burpwn executable")?;

    // A pipe whose write end becomes the child's fd 3.
    let (read_fd, write_fd) = nix_pipe().context("creating fd-3 pipe for exec envelope")?;

    let mut cmd = tokio::process::Command::new(&exe);
    // `--json` is a global flag; `--session`/`--timeout`/`--workspace` belong to
    // the `exec` subcommand and must follow the `exec` token.
    cmd.arg("--json").arg("exec");
    cmd.arg("--session").arg(session);
    if let Some(t) = params.timeout_secs {
        cmd.arg("--timeout").arg(t.to_string());
    }
    if let Some(ws) = &params.workspace {
        match ws.parse::<i64>() {
            Ok(id) => {
                cmd.arg("--workspace").arg(id.to_string());
            }
            Err(_) => tracing::warn!(workspace = %ws, "ignoring non-numeric exec workspace"),
        }
    }
    cmd.arg("--");
    for a in &params.argv {
        cmd.arg(a);
    }
    // Child inherits stdio; the envelope goes to fd 3 only.
    cmd.stdin(std::process::Stdio::null());

    // SAFETY: in the forked child, before exec, dup the pipe write end onto fd 3.
    // We only call async-signal-safe libc calls (`dup2`). The parent's copy of
    // `write_fd` is closed after spawn below.
    let child_write_fd = write_fd;
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(child_write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("spawning burpwn exec")?;

    // Parent must drop its write end so the read end sees EOF when the child exits.
    // SAFETY: write_fd is a valid fd we own; wrapping + dropping closes it once.
    unsafe {
        drop(std::fs::File::from_raw_fd(write_fd));
    }

    // Read the envelope from the pipe read end.
    // SAFETY: read_fd is a valid owned fd; into a tokio File for async reads.
    let std_read = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut reader = tokio::fs::File::from_std(std_read);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .context("reading exec envelope from fd 3")?;

    let status = child.wait().await.context("waiting for burpwn exec")?;

    // Best-effort: parse the envelope. The CLI may have written nothing to fd 3
    // if it errored before producing one — fall back to the process status.
    let text = String::from_utf8_lossy(&buf);
    let envelope: Option<Value> = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str(l).ok());

    if let Some(env) = envelope {
        if env.get("ok").and_then(Value::as_bool) == Some(true) {
            let data = env.get("data").cloned().unwrap_or_else(|| json!({}));
            let exit_code = data
                .get("exit_code")
                .and_then(Value::as_i64)
                .unwrap_or_else(|| status.code().unwrap_or(-1) as i64);
            let captured = data
                .get("captured_request_ids")
                .cloned()
                .unwrap_or_else(|| json!([]));
            return Ok(json!({
                "exit_code": exit_code,
                "captured_request_ids": captured,
                "exec_id": data.get("exec_id").cloned().unwrap_or(Value::Null),
            }));
        }
        // The CLI reported a structured error.
        let msg = env
            .get("error")
            .and_then(Value::as_str)
            .or_else(|| env.get("message").and_then(Value::as_str))
            .unwrap_or("burpwn exec failed");
        return Err(anyhow!("exec failed: {msg}"));
    }

    Err(anyhow!(
        "burpwn exec produced no JSON envelope (exit status {:?}); stderr/stdout were inherited",
        status.code()
    ))
}

/// Create a `pipe(2)` returning `(read_fd, write_fd)` with `O_CLOEXEC` on both
/// (the write end's CLOEXEC is irrelevant — `pre_exec` `dup2`s it onto fd 3,
/// which is not CLOEXEC, so it survives the exec; the original CLOEXEC fd is
/// closed by exec).
fn nix_pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-element array; pipe2 fills it.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_store::model::{FlowStart, RequestData, ResponseData};

    /// Build a temp Paths with one populated session and return (paths, session).
    async fn temp_session() -> (tempfile::TempDir, Paths, String) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        (dir, paths, "default".to_string())
    }

    async fn seed_one_flow(paths: &Paths, session: &str) -> i64 {
        let store = open_store(paths, session).unwrap();
        let w = store.writer();
        let fid = w
            .flow_start(FlowStart {
                workspace_id: 1,
                ts_start: 0,
                exec_id: None,
                client_addr: "127.0.0.1:1".into(),
                dst_ip: "1.2.3.4".into(),
                dst_port: 443,
                sni: Some("example.com".into()),
                scheme: "https".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            fid,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/secret".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"host: example.com\r\n".to_vec(),
                body: b"needle-token".to_vec(),
            },
        )
        .await
        .unwrap();
        w.response(
            fid,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"content-type: text/plain\r\n".to_vec(),
                body: b"hello".to_vec(),
                timing_ms: Some(12),
            },
        )
        .await
        .unwrap();
        drop(w);
        drop(store);
        fid
    }

    #[tokio::test]
    async fn session_list_and_current() {
        let (_d, paths, _s) = temp_session().await;
        let v = session_list(&paths).unwrap();
        assert_eq!(v["sessions"], json!(["default"]));
        assert_eq!(v["active"], "default");
        let v = session_current(&paths).unwrap();
        assert_eq!(v["active"], "default");
    }

    #[tokio::test]
    async fn req_list_show_search_roundtrip() {
        let (_d, paths, s) = temp_session().await;
        let fid = seed_one_flow(&paths, &s).await;

        let v = req_list(&paths, &s, &crate::params::ReqListParams::default()).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["flows"][0]["id"], fid);
        assert_eq!(v["flows"][0]["status"], 200);

        // host filter hit + miss
        let hit = req_list(
            &paths,
            &s,
            &crate::params::ReqListParams {
                host: Some("example".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(hit["count"], 1);
        let miss = req_list(
            &paths,
            &s,
            &crate::params::ReqListParams {
                host: Some("nope".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(miss["count"], 0);

        let v = req_show(
            &paths,
            &s,
            &crate::params::ReqShowParams { id: fid, raw: true },
        )
        .unwrap();
        assert_eq!(v["request"]["path"], "/secret");
        assert_eq!(v["response"]["status"], 200);
        assert!(v["raw_request"].as_str().unwrap().contains("GET /secret"));

        let v = req_search(
            &paths,
            &s,
            &crate::params::ReqSearchParams {
                query: "needle-token".into(),
            },
        )
        .unwrap();
        assert_eq!(v["flow_ids"], json!([fid]));

        // missing flow → error
        assert!(req_show(
            &paths,
            &s,
            &crate::params::ReqShowParams {
                id: 9999,
                raw: false
            }
        )
        .is_err());
    }

    #[tokio::test]
    async fn mutations_persist() {
        let (_d, paths, s) = temp_session().await;
        let fid = seed_one_flow(&paths, &s).await;

        let v = tag_add(
            &paths,
            &s,
            &crate::params::TagAddParams {
                flow_id: fid,
                name: "vuln".into(),
                color: Some("red".into()),
            },
        )
        .await
        .unwrap();
        assert!(v["tag_id"].as_i64().unwrap() > 0);

        let v = note_add(
            &paths,
            &s,
            &crate::params::NoteAddParams {
                flow_id: fid,
                body: "looks injectable".into(),
            },
        )
        .await
        .unwrap();
        assert!(v["note_id"].as_i64().unwrap() > 0);

        let v = workspace_new(
            &paths,
            &s,
            &crate::params::WorkspaceNewParams {
                name: "scope-a".into(),
            },
        )
        .await
        .unwrap();
        assert!(v["workspace_id"].as_i64().unwrap() > 0);

        let v = match_replace_add(
            &paths,
            &s,
            &crate::params::MatchReplaceAddParams {
                scope: "*.example.com".into(),
                kind: "header".into(),
                pattern: "User-Agent: .*".into(),
                replacement: "User-Agent: burpwn".into(),
                on_request: true,
            },
        )
        .await
        .unwrap();
        assert!(v["id"].as_i64().unwrap() > 0);

        // reads reflect the writes
        let tags = tag_list(&paths, &s).unwrap();
        assert_eq!(tags["tags"][0]["name"], "vuln");
        let ws = workspace_list(&paths, &s).unwrap();
        assert!(ws["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["name"] == "scope-a"));
        let rules = match_replace_list(&paths, &s).unwrap();
        assert_eq!(rules["rules"][0]["match_kind"], "header");
    }

    #[tokio::test]
    async fn intercept_tools_error_without_daemon() {
        let (_d, paths, s) = temp_session().await;
        // No daemon → connect_control should produce an actionable error.
        let err = intercept_list(&paths, &s).await.unwrap_err().to_string();
        assert!(err.contains("no burpwn proxy daemon"), "got: {err}");
        let err = await_intercept(&paths, &s, &Default::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no burpwn proxy daemon"));
    }

    #[test]
    fn control_value_maps_responses() {
        use burpwn_cli::control::{ControlResponse as R, InterceptItem};
        let v = control_value(R::Pending { item: None }).unwrap();
        assert_eq!(v, json!({ "pending": false }));
        let v = control_value(R::Pending {
            item: Some(InterceptItem {
                id: 4,
                kind: "request".into(),
                host: "h".into(),
                method: "GET".into(),
                path: "/".into(),
            }),
        })
        .unwrap();
        assert_eq!(v["pending"], true);
        assert_eq!(v["intercept"]["id"], 4);
        assert!(control_value(R::Error {
            message: "boom".into()
        })
        .is_err());
    }
}
