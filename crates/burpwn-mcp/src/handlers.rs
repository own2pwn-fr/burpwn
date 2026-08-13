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

use anyhow::{Context, Result};
use serde_json::{json, Value};

use burpwn_cli::control::{ControlClient, Edits, HeaderEdit};
use burpwn_cli::paths::Paths;
use burpwn_error::ErrorCode;
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

/// Recursively drop `null` members from every object in `v`.
///
/// A tool result is not a screen, it is CONTEXT: whatever comes back is carried
/// by the agent for the rest of the conversation and paid for on every
/// subsequent turn. `"sni":null` costs a key, a colon, four letters and a comma
/// to say precisely what an absent key says, and a capture of DNS and raw-TCP
/// flows is mostly nulls — a listing of them shrinks by about a third. The
/// shape is otherwise untouched: a consumer reading `row.sni` gets `undefined`
/// instead of `null`, which every JSON consumer already treats the same way.
///
/// Only ever applied to LISTINGS, never to a single-value reply where a field
/// being explicitly null is the answer.
fn prune_nulls(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|_, val| !val.is_null());
            for val in map.values_mut() {
                prune_nulls(val);
            }
        }
        Value::Array(items) => {
            for item in items {
                prune_nulls(item);
            }
        }
        _ => {}
    }
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

/// `session_export` — pack the session into one portable file.
///
/// The reply is deliberately terse (path, size, counts): it is context the
/// agent pays for on every subsequent turn, and there is nothing to say about a
/// file beyond where it is and how big it is. The one exception is the warning
/// on a raw bundle — an agent that hands the file to someone must know it is
/// carrying live credentials.
pub fn session_export(
    paths: &Paths,
    session: &str,
    params: &crate::params::SessionExportParams,
) -> Result<Value> {
    let outcome = burpwn_cli::bundle::export_session(
        paths,
        &burpwn_cli::bundle::ExportRequest {
            session: session.to_string(),
            output: params.output.as_ref().map(std::path::PathBuf::from),
            redact: params.redact,
            force: params.force,
        },
    )?;
    let mut view = json!({
        "path": outcome.path.display().to_string(),
        "bytes": outcome.bytes,
        "flows": outcome.manifest.flow_count,
        "redacted": outcome.manifest.redacted,
    });
    if !outcome.manifest.redacted {
        view["warning"] = json!(
            "raw bundle: stored auth tokens/login commands and captured \
             Authorization/Cookie headers are inside"
        );
    }
    Ok(view)
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
        ..Default::default()
    };
    let rows = store.reader().list_flows(&filter)?;
    let mut flows = serde_json::to_value(&rows)?;
    prune_nulls(&mut flows);
    Ok(json!({ "flows": flows, "count": rows.len() }))
}

/// JSON view of a flow detail, bodies decoded as lossy UTF-8 (mirrors the CLI's
/// `req show --json`).
///
/// When `raw` is set, the verbatim head+body goes in `raw_request` /
/// `raw_response` and the decoded view drops its own `headers`/`body` copies:
/// the raw form already contains them byte for byte, and sending a 40 KB
/// response twice doubles what the agent pays to look at one flow. The decoded
/// METADATA (method, path, status, timings) stays either way — it is what the
/// agent branches on without reading the bytes.
fn flow_detail_json(detail: &FlowDetail, raw: bool) -> Value {
    let req = detail.request.as_ref().map(|r| {
        let mut v = json!({
            "method": r.method,
            "authority": r.authority,
            "path": r.path,
            "http_version": r.http_version,
        });
        if !raw {
            let obj = v.as_object_mut().expect("object");
            obj.insert("headers".into(), json!(String::from_utf8_lossy(&r.headers)));
            obj.insert("body".into(), json!(String::from_utf8_lossy(&r.body)));
        }
        v
    });
    let resp = detail.response.as_ref().map(|r| {
        let mut v = json!({
            "status": r.status,
            "http_version": r.http_version,
            "timing_ms": r.timing_ms,
        });
        if !raw {
            let obj = v.as_object_mut().expect("object");
            obj.insert("headers".into(), json!(String::from_utf8_lossy(&r.headers)));
            obj.insert("body".into(), json!(String::from_utf8_lossy(&r.body)));
        }
        v
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
        None => Err(burpwn_cli::coded!(
            ErrorCode::InputNoSuchFlow,
            "no such flow: {}",
            params.id
        )),
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
    let mut v = json!({ "workspaces": store.reader().list_workspaces()? });
    prune_nulls(&mut v);
    Ok(v)
}

/// `tag_list`.
pub fn tag_list(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    let mut v = json!({ "tags": store.reader().list_tags()? });
    prune_nulls(&mut v);
    Ok(v)
}

/// `match_replace_list`.
pub fn match_replace_list(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    let mut v = json!({ "rules": store.reader().list_match_replace()? });
    prune_nulls(&mut v);
    Ok(v)
}

// --- mutation --------------------------------------------------------------

/// `match_replace_add` — insert a rule (enabled by default).
pub async fn match_replace_add(
    paths: &Paths,
    session: &str,
    params: &crate::params::MatchReplaceAddParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let match_kind = MatchKind::parse(&params.kind).ok_or_else(|| {
        burpwn_cli::coded!(
            ErrorCode::InputInvalidValue,
            "kind must be {}, got {:?}",
            MatchKind::VALID.join("|"),
            params.kind
        )
    })?;
    let rule = NewMatchReplaceRule {
        enabled: true,
        scope: params.scope.clone(),
        match_kind,
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

// --- groups (named collections of flows) -----------------------------------

/// Resolve a group NAME to its row, or fail with the `GroupNotFound` code so the
/// agent can branch on it instead of parsing prose.
fn resolve_group(
    reader: &burpwn_store::Reader,
    name: &str,
    workspace_id: Option<i64>,
) -> Result<burpwn_store::model::Group> {
    match reader.group_by_name(name, workspace_id)? {
        Some(g) => Ok(g),
        None => Err(burpwn_cli::coded!(
            ErrorCode::GroupNotFound,
            "no such group: {name}"
        )),
    }
}

// --- hooks ------------------------------------------------------------------

/// `hook_add` — install a hook. Validated exactly like the CLI (same builder),
/// so an agent gets the same refusals for a hook that could never work.
pub async fn hook_add(
    paths: &Paths,
    session: &str,
    params: &crate::params::HookAddParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let spec = burpwn_cli::hooks::HookSpec {
        name: params.name.clone(),
        phase: params
            .phase
            .clone()
            .unwrap_or_else(|| "pre-request".to_string()),
        action: params.action.clone(),
        host: params.host.clone().unwrap_or_default(),
        method: params.method.clone().unwrap_or_default(),
        path: params.path.clone().unwrap_or_default(),
        status: params.status,
        header: params.header.clone(),
        param: params.param.clone(),
        cmd: params.cmd.clone(),
        extract: params.extract.clone(),
        inject_header: params.inject_header.clone(),
        inject_param: params.inject_param.clone(),
        inject_only_if_absent: false,
        order: params.order.unwrap_or(0),
        timeout_ms: params
            .timeout_ms
            .unwrap_or(burpwn_cli::hooks::DEFAULT_TIMEOUT_MS),
        ttl_ms: params.ttl_ms.unwrap_or(burpwn_cli::hooks::DEFAULT_TTL_MS),
        disabled: false,
    };
    let hook = burpwn_cli::hooks::build_hook(&spec)?;
    let id = store.writer().add_hook(hook).await?;
    Ok(json!({ "hook_id": id, "name": params.name }))
}

/// `hook_list` — every hook in application order.
pub fn hook_list(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    let hooks: Vec<Value> = store
        .reader()
        .list_hooks()?
        .iter()
        .map(burpwn_cli::hooks::to_json)
        .collect();
    let mut v = json!({ "hooks": hooks });
    prune_nulls(&mut v);
    Ok(v)
}

/// Resolve a hook id or fail with a code the agent can branch on.
fn resolve_hook(store: &Store, id: i64) -> Result<burpwn_store::model::Hook> {
    match store.reader().get_hook(id)? {
        Some(h) => Ok(h),
        None => Err(burpwn_cli::coded!(
            ErrorCode::InputNoSuchHook,
            "no such hook: {id}"
        )),
    }
}

/// `hook_set_enabled` — turn a hook on/off.
pub async fn hook_set_enabled(
    paths: &Paths,
    session: &str,
    params: &crate::params::HookSetEnabledParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    resolve_hook(&store, params.id)?;
    store
        .writer()
        .set_hook_enabled(params.id, params.enabled)
        .await?;
    Ok(json!({ "id": params.id, "enabled": params.enabled }))
}

/// `hook_rm` — delete a hook.
pub async fn hook_rm(
    paths: &Paths,
    session: &str,
    params: &crate::params::HookRmParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    resolve_hook(&store, params.id)?;
    store.writer().delete_hook(params.id).await?;
    Ok(json!({ "removed": params.id }))
}

/// `hook_test` — replay a hook against a captured flow.
///
/// Shelled out to the CLI rather than run in-process: an `exec` hook's command
/// needs the session daemon and the sandbox, which `burpwn hook test` already
/// knows how to bring up.
pub async fn hook_test(session: &str, params: &crate::params::HookTestParams) -> Result<Value> {
    run_burpwn_json(&[
        "--json".to_string(),
        "hook".to_string(),
        "test".to_string(),
        params.id.to_string(),
        "--flow".to_string(),
        params.flow_id.to_string(),
        "--session".to_string(),
        session.to_string(),
    ])
    .await
}

/// `group_new` — create (or re-describe) a named collection of flows.
pub async fn group_new(
    paths: &Paths,
    session: &str,
    params: &crate::params::GroupNewParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let workspace_id = params
        .workspace
        .unwrap_or(burpwn_store::schema::DEFAULT_WORKSPACE_ID);
    let existed = store
        .reader()
        .group_by_name(&params.name, Some(workspace_id))?
        .is_some();
    let id = store
        .writer()
        .create_group(
            params.name.clone(),
            params.description.clone(),
            workspace_id,
            now_ms(),
        )
        .await?;
    Ok(json!({
        "group_id": id,
        "name": params.name,
        "workspace_id": workspace_id,
        "created": !existed,
    }))
}

/// `group_add` — add flows to a group, refusing the whole call if any id is
/// unknown (a half-populated group is worse than a clear error).
pub async fn group_add(
    paths: &Paths,
    session: &str,
    params: &crate::params::GroupAddParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let group = resolve_group(&reader, &params.name, None)?;
    for id in &params.flow_ids {
        if !reader.flow_exists(*id)? {
            return Err(burpwn_cli::coded!(
                ErrorCode::InputNoSuchFlow,
                "no such flow: {id}"
            ));
        }
    }
    for id in &params.flow_ids {
        store.writer().add_flow_to_group(*id, group.id).await?;
    }
    Ok(json!({
        "group_id": group.id,
        "name": group.name,
        "added": params.flow_ids,
        "flow_count": reader.group_flow_count(group.id)?,
    }))
}

/// `group_list` — every group with its description and size.
pub fn group_list(
    paths: &Paths,
    session: &str,
    params: &crate::params::GroupListParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let groups = reader.list_groups(params.workspace)?;
    let mut view = Vec::with_capacity(groups.len());
    for g in &groups {
        view.push(json!({
            "id": g.id,
            "name": g.name,
            "description": g.description,
            "workspace_id": g.workspace_id,
            "created_at": g.created_at,
            "flow_count": reader.group_flow_count(g.id)?,
        }));
    }
    Ok(json!({ "groups": view, "count": groups.len() }))
}

/// `group_show` — the flows a group holds (same row shape as `req_list`).
pub fn group_show(
    paths: &Paths,
    session: &str,
    params: &crate::params::GroupShowParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let group = resolve_group(&reader, &params.name, None)?;
    let flows = reader.flows_in_group(group.id)?;
    let mut v = json!({
        "group": {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "workspace_id": group.workspace_id,
            "created_at": group.created_at,
        },
        "flows": flows,
        "count": flows.len(),
    });
    prune_nulls(&mut v);
    Ok(v)
}

/// `group_rm` — delete a group; the flows it held stay captured.
pub async fn group_rm(
    paths: &Paths,
    session: &str,
    params: &crate::params::GroupRmParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let group = resolve_group(&store.reader(), &params.name, None)?;
    store.writer().delete_group(group.id).await?;
    Ok(json!({ "group_id": group.id, "name": group.name, "deleted": true }))
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
        burpwn_cli::coded!(
            ErrorCode::DaemonUnreachable,
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
            version,
        } => Ok(json!({
            "running": running,
            "session": session,
            "intercept_enabled": intercept_enabled,
            "pending": pending,
            "dns_port": dns_port,
            // The DAEMON's build, which an in-place upgrade can leave behind the
            // CLI's — an agent debugging odd behaviour should see which one is
            // actually serving its traffic.
            "version": version,
        })),
        R::Ack => Ok(json!({ "ok": true })),
        R::Intercepts { items } => Ok(json!({ "intercepts": items })),
        // (a parked intercept has no optional fields to prune)
        R::Pending { item } => match item {
            Some(it) => Ok(json!({ "pending": true, "intercept": it })),
            None => Ok(json!({ "pending": false })),
        },
        // `found: false` means the forward/drop did NOT happen. Returning it as a
        // successful tool result invites an agent to move on believing the
        // intercept was released.
        R::Resolved { found: false } => Err(burpwn_cli::coded!(
            ErrorCode::InputNoSuchIntercept,
            "no parked intercept with that id (list them with intercept_list)"
        )),
        R::Resolved { found } => Ok(json!({ "found": found })),
        R::Error { message } => Err(burpwn_cli::coded!(
            ErrorCode::DaemonRejected,
            "daemon error: {message}"
        )),
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
        // MCP forward now reaches CLI parity: it can also change the method/path
        // of an `await_intercept`-parked request (previously CLI-only).
        method: params.method.clone(),
        path: params.path.clone(),
    };
    control_value(c.intercept_forward(params.id, edits).await?)
}

/// `intercept_scope` — narrow (or clear) blocking interception to a host/path/
/// method so not every flow parks. `clear` (or all-empty fields) widens back to
/// every flow.
pub async fn intercept_scope(
    paths: &Paths,
    session: &str,
    params: &crate::params::InterceptScopeParams,
) -> Result<Value> {
    let mut c = connect_control(paths, session).await?;
    let (host, path, method) = if params.clear {
        (String::new(), String::new(), String::new())
    } else {
        (
            params.host.clone().unwrap_or_default(),
            params.path.clone().unwrap_or_default(),
            params.method.clone().unwrap_or_default(),
        )
    };
    control_value(c.intercept_set_scope(host, path, method).await?)
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

// --- req_replay (Repeater) --------------------------------------------------

/// `req_replay` — replay a stored flow with optional edits, mirroring the CLI
/// `req replay`. Shares [`burpwn_cli::replay::replay_flow`] so both take exactly
/// the same transport path.
pub async fn req_replay(
    paths: &Paths,
    session: &str,
    params: &crate::params::ReqReplayParams,
) -> Result<Value> {
    use burpwn_cli::replay::{parse_header_spec, replay_flow};
    let store = open_store(paths, session)?;
    // Validate + normalise the header edits through the same CRLF-injection guard
    // the CLI uses (parse_header_spec on a `Name: value` string).
    let mut headers = Vec::new();
    for h in &params.set_headers {
        headers.push(parse_header_spec(&format!("{}: {}", h.name, h.value))?);
    }
    let body = params.set_body.clone().map(|b| b.into_bytes());
    let result = replay_flow(&store, params.id, params.method.as_deref(), &headers, body).await?;
    Ok(json!({
        "status": result.status,
        "response": String::from_utf8_lossy(&result.raw_response),
    }))
}

// --- fuzz (Intruder) --------------------------------------------------------

/// `fuzz` — run an Intruder attack against a stored flow and persist it.
pub async fn fuzz_run(
    paths: &Paths,
    session: &str,
    params: &crate::params::FuzzParams,
) -> Result<Value> {
    use burpwn_proxy::AttackMode;
    use tokio_util::sync::CancellationToken;

    let mode = AttackMode::from_str_opt(&params.mode).ok_or_else(|| {
        burpwn_cli::coded!(
            ErrorCode::InputInvalidValue,
            "mode must be sniper|battering-ram|pitchfork|cluster-bomb"
        )
    })?;
    let mut positions = Vec::new();
    for spec in &params.positions {
        positions.push(burpwn_cli::fuzz::parse_position(spec)?);
    }
    let payloads: Vec<Vec<u8>> = params
        .payloads
        .iter()
        .map(|p| p.clone().into_bytes())
        .collect();

    let spec = burpwn_cli::fuzz::FuzzSpec {
        flow_id: params.flow,
        request_bytes: None,
        positions,
        marker: params.marker.clone().map(|m| m.into_bytes()),
        payloads,
        mode,
        concurrency: params.concurrency,
        delay_ms: params.delay_ms,
        name: params.name.clone(),
    };
    burpwn_cli::fuzz::fuzz_run(paths, session, spec, CancellationToken::new()).await
}

/// `fuzz_list` — list stored attacks.
pub fn fuzz_list(
    paths: &Paths,
    session: &str,
    params: &crate::params::FuzzListParams,
) -> Result<Value> {
    let mut v = burpwn_cli::fuzz::fuzz_list(paths, session, params.workspace.as_deref())?;
    prune_nulls(&mut v);
    Ok(v)
}

/// `fuzz_results` — one attack's per-payload results.
pub fn fuzz_results(
    paths: &Paths,
    session: &str,
    params: &crate::params::FuzzResultsParams,
) -> Result<Value> {
    let sort = match &params.sort {
        Some(s) => burpwn_cli::fuzz::ResultSort::from_str_opt(s).ok_or_else(|| {
            burpwn_cli::coded!(
                ErrorCode::InputInvalidValue,
                "sort must be anomaly|status|len, got {s:?}"
            )
        })?,
        None => burpwn_cli::fuzz::ResultSort::Anomaly,
    };
    let mut v = burpwn_cli::fuzz::fuzz_show(paths, session, params.attack_id, sort, params.limit)?;
    // Every result row carries the `attack_id` that was the ARGUMENT of this
    // call — a few hundred rows repeating a number the caller just supplied.
    if let Some(rows) = v["results"].as_array_mut() {
        for row in rows {
            if let Some(obj) = row.as_object_mut() {
                obj.remove("attack_id");
            }
        }
    }
    prune_nulls(&mut v);
    Ok(v)
}

// --- compare ----------------------------------------------------------------

/// `compare` — structured diff of two flows.
///
/// The one reply in this surface whose size is set by the TARGET rather than by
/// the caller: two HTML pages that differ share almost no lines, so the raw
/// per-side line lists run to thousands. They are capped here (200 lines a side
/// by default, `max_lines` to change it, negative to lift it) and the cut is
/// declared in `body.truncated` — a diff that quietly stops at line 200 would
/// have the agent conclude things about a body it never saw.
pub fn compare(
    paths: &Paths,
    session: &str,
    params: &crate::params::CompareParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let a = reader.get_flow(params.flow_a)?.ok_or_else(|| {
        burpwn_cli::coded!(
            ErrorCode::InputNoSuchFlow,
            "no such flow: {}",
            params.flow_a
        )
    })?;
    let b = reader.get_flow(params.flow_b)?.ok_or_else(|| {
        burpwn_cli::coded!(
            ErrorCode::InputNoSuchFlow,
            "no such flow: {}",
            params.flow_b
        )
    })?;
    let what = match &params.what {
        Some(w) => burpwn_cli::compare::CompareWhat::from_str_opt(w).ok_or_else(|| {
            burpwn_cli::coded!(
                ErrorCode::InputInvalidValue,
                "what must be headers|body|all, got {w:?}"
            )
        })?,
        None => burpwn_cli::compare::CompareWhat::All,
    };
    let mut v = burpwn_cli::compare::diff_flows(&a, &b, what);
    burpwn_cli::compare::cap_body_lines(
        &mut v,
        burpwn_cli::compare::resolve_max_lines(params.max_lines),
    );
    Ok(v)
}

// --- encode / decode --------------------------------------------------------

/// `encode` — byte transform.
pub fn encode(params: &crate::params::EncodeParams) -> Result<Value> {
    burpwn_cli::encode::encode(&params.scheme, &params.value)
}

/// `decode` — reverse byte transform (plus `jwt`).
pub fn decode(params: &crate::params::EncodeParams) -> Result<Value> {
    burpwn_cli::encode::decode(&params.scheme, &params.value)
}

// --- session stats + auth --------------------------------------------------

/// `session_stats` — capture-completeness telemetry: execs vs captured flows,
/// and the network-facing execs that captured ZERO flows (traffic likely
/// escaped capture, e.g. an agent hook silently no-op'd).
pub fn session_stats(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    let reader = store.reader();
    let stats = reader.exec_stats()?;
    let escaped: Vec<Value> = reader
        .exec_records()?
        .into_iter()
        .filter(|e| e.network_facing && e.flow_count == 0)
        .map(|e| json!({ "exec_id": e.exec_id, "cmd": e.cmd }))
        .collect();
    Ok(json!({
        "session": session,
        "total_execs": stats.total_execs,
        "total_flows": stats.total_flows,
        "network_execs": stats.network_execs,
        "network_zero_flow_execs": stats.network_zero_flow_execs,
        "escaped_execs": escaped,
    }))
}

/// `session_auth_set` — persist (or update) a session-auth profile. Store-only
/// (no sandbox), so it runs in-process.
pub async fn session_auth_set(
    paths: &Paths,
    session: &str,
    params: &crate::params::SessionAuthSetParams,
) -> Result<Value> {
    let store = open_store(paths, session)?;
    let host = params.host.clone().unwrap_or_default();
    let id = burpwn_cli::auth::auth_set(
        &store,
        &host,
        &params.login,
        &params.extract,
        &params.header,
    )
    .await?;
    Ok(json!({ "id": id, "host": host }))
}

/// `session_auth_status` — the stored profiles with the token value MASKED.
pub fn session_auth_status(paths: &Paths, session: &str) -> Result<Value> {
    let store = open_store(paths, session)?;
    let profiles: Vec<Value> = store
        .reader()
        .auth_profiles()?
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "host": p.host,
                "login_cmd": p.login_cmd,
                "header_template": p.header_template,
                "token_set": p.token.is_some(),
                "token": p.token.as_deref().map(burpwn_cli::auth::mask_token),
                "rule_id": p.rule_id,
            })
        })
        .collect();
    let mut v = json!({ "profiles": profiles });
    prune_nulls(&mut v);
    Ok(v)
}

/// `session_auth_refresh` — re-mint the token(s) + update the injection rule(s).
/// This runs the login command in the sandbox, so it reuses the FULL CLI path
/// (daemon-ensure + sandbox) by shelling out to `burpwn session auth refresh`
/// (same rationale as [`run_exec`] shelling out for the sandbox).
pub async fn session_auth_refresh(
    session: &str,
    params: &crate::params::SessionAuthRefreshParams,
) -> Result<Value> {
    let mut args = vec![
        "--json".to_string(),
        "session".to_string(),
        "auth".to_string(),
        "refresh".to_string(),
        "--session".to_string(),
        session.to_string(),
    ];
    if let Some(h) = &params.host {
        args.push("--host".to_string());
        args.push(h.clone());
    }
    run_burpwn_json(&args).await
}

/// Run `burpwn <args>` (which include `--json`) capturing stdout, and return the
/// `data` of its `{ok,data,error}` envelope (or an error on `ok:false`). Used by
/// the auth-refresh tool to reuse the CLI's daemon-ensure + sandbox path.
async fn run_burpwn_json(args: &[String]) -> Result<Value> {
    let exe = std::env::current_exe().context("locating the burpwn executable")?;
    let output = tokio::process::Command::new(&exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .context("spawning burpwn")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let env: Option<Value> = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str(l).ok());
    match env {
        Some(v) if v.get("ok").and_then(Value::as_bool) == Some(true) => {
            Ok(v.get("data").cloned().unwrap_or_else(|| json!({})))
        }
        Some(v) => Err(burpwn_cli::coded!(
            ErrorCode::Internal,
            "burpwn command failed: {}",
            v.get("error").and_then(Value::as_str).unwrap_or("unknown")
        )),
        None => Err(burpwn_cli::coded!(
            ErrorCode::Internal,
            "burpwn produced no JSON envelope (exit {:?})",
            output.status.code()
        )),
    }
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
/// `params.workspace`, when present, is forwarded verbatim as the `--workspace`
/// value: the CLI's `--workspace` is a workspace NAME, which it resolves or
/// creates. (It used to be parsed as an i64 id, which silently dropped real
/// names and mis-attributed numeric-looking ones.)
pub async fn run_exec(session: &str, params: &crate::params::ExecParams) -> Result<Value> {
    use std::os::fd::FromRawFd;
    use tokio::io::AsyncReadExt;

    if params.argv.is_empty() {
        return Err(burpwn_cli::coded!(
            ErrorCode::InputNothingToDo,
            "exec: argv must not be empty"
        ));
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
        // `--workspace` is a NAME (the CLI resolves/creates it). Pass it through
        // verbatim — do NOT parse it as an id, which silently dropped real names
        // and mis-attributed numeric-looking ones.
        cmd.arg("--workspace").arg(ws);
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

    // Read the envelope from the pipe read end, concurrently with the child's
    // exit. SAFETY: read_fd is a valid owned fd; into a tokio File for async
    // reads.
    let std_read = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut reader = tokio::fs::File::from_std(std_read);
    let mut buf = Vec::new();

    // A grandchild that inherited fd 3 (and outlives the direct child) keeps the
    // pipe's write end open, so `read_to_end` would block on an EOF that never
    // comes — hanging the whole MCP tool call. Race the read against the child's
    // exit + a hard timeout grace: once the child is gone we only briefly wait
    // for any straggler envelope bytes, then stop reading regardless.
    let status = {
        // How long to keep draining fd 3 *after* the child exits before giving
        // up on a grandchild that's pinning the pipe open.
        const FD3_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);
        let mut wait = std::pin::pin!(child.wait());
        let mut read_all = std::pin::pin!(reader.read_to_end(&mut buf));
        tokio::select! {
            // Child exited first (the common case): briefly drain any remaining
            // envelope bytes, then proceed even if the pipe stays open (a
            // grandchild may still hold fd 3 — we must not block on it forever).
            status = &mut wait => {
                let _ = tokio::time::timeout(FD3_DRAIN_GRACE, &mut read_all).await;
                status.context("waiting for burpwn exec")?
            }
            // The envelope arrived and the writer closed (EOF) before the child
            // was reaped: now wait for the child normally.
            _ = &mut read_all => {
                wait.await.context("waiting for burpwn exec")?
            }
        }
    };

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
        return Err(burpwn_cli::coded!(
            ErrorCode::Internal,
            "exec failed: {msg}"
        ));
    }

    Err(burpwn_cli::coded!(
        ErrorCode::Internal,
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

    /// `compare` is the one reply whose size the target decides, so the MCP
    /// path must cap it BY DEFAULT — and say that it did.
    #[tokio::test]
    async fn compare_caps_the_body_diff_and_declares_it() {
        async fn seed_body(paths: &Paths, session: &str, body: Vec<u8>) -> i64 {
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
                    path: "/page".into(),
                    http_version: "HTTP/1.1".into(),
                    headers: b"host: example.com\r\n".to_vec(),
                    body: Vec::new(),
                },
            )
            .await
            .unwrap();
            w.response(
                fid,
                ResponseData {
                    status: 200,
                    http_version: "HTTP/1.1".into(),
                    headers: b"content-type: text/html\r\n".to_vec(),
                    body,
                    timing_ms: None,
                },
            )
            .await
            .unwrap();
            drop(w);
            drop(store);
            fid
        }

        let (_d, paths, s) = temp_session().await;
        let big: Vec<u8> = (0..1_000)
            .map(|i| format!("<div id=\"row-{i}\">a</div>\n"))
            .collect::<String>()
            .into_bytes();
        let a = seed_body(&paths, &s, big).await;
        let b = seed_body(&paths, &s, b"<div>denied</div>\n".to_vec()).await;

        let params = crate::params::CompareParams {
            flow_a: a,
            flow_b: b,
            what: None,
            max_lines: None,
        };
        let v = compare(&paths, &s, &params).unwrap();
        assert_eq!(v["body"]["only_in_a"].as_array().unwrap().len(), 200);
        assert_eq!(v["body"]["truncated"]["only_in_a"]["shown"], 200);
        assert_eq!(v["body"]["truncated"]["only_in_a"]["total"], 1_000);

        // …and an agent that read the marker can ask for the whole thing.
        let v = compare(
            &paths,
            &s,
            &crate::params::CompareParams {
                max_lines: Some(-1),
                ..params
            },
        )
        .unwrap();
        assert_eq!(v["body"]["only_in_a"].as_array().unwrap().len(), 1_000);
        assert!(v["body"].get("truncated").is_none());
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

    /// The agent-facing archive path: one compact result, an explicit warning
    /// when the bundle is raw, and no warning to pay for when it is not.
    #[tokio::test]
    async fn session_export_writes_a_bundle_and_flags_raw_secrets() {
        let (dir, paths, s) = temp_session().await;
        seed_one_flow(&paths, &s).await;

        let raw = dir.path().join("archive.burpwn");
        let v = session_export(
            &paths,
            &s,
            &crate::params::SessionExportParams {
                output: Some(raw.display().to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(v["path"], raw.display().to_string());
        assert_eq!(v["flows"], 1);
        assert_eq!(v["redacted"], false);
        assert!(v["bytes"].as_u64().unwrap() > 0);
        assert!(v["warning"].as_str().unwrap().contains("raw bundle"));
        assert!(raw.is_file());

        // Redacted: nothing to warn about beyond what the tool description says,
        // so the field is absent rather than empty.
        let clean = dir.path().join("clean.burpwn");
        let v = session_export(
            &paths,
            &s,
            &crate::params::SessionExportParams {
                output: Some(clean.display().to_string()),
                redact: true,
                force: false,
            },
        )
        .unwrap();
        assert_eq!(v["redacted"], true);
        assert!(v.get("warning").is_none());

        // Re-exporting over an existing file needs force.
        let err = session_export(
            &paths,
            &s,
            &crate::params::SessionExportParams {
                output: Some(clean.display().to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            burpwn_cli::diag::diagnose(&err).code,
            ErrorCode::InputFileExists
        );
    }

    /// A tool result is context the agent re-reads on every later turn, so the
    /// two cheapest wins are pinned here: no `null` members in a listing, and
    /// the raw bytes of a flow sent once rather than twice.
    #[tokio::test]
    async fn tool_replies_do_not_pay_for_nulls_or_duplicated_bodies() {
        let (_d, paths, s) = temp_session().await;
        let fid = seed_one_flow(&paths, &s).await;

        let v = req_list(&paths, &s, &crate::params::ReqListParams::default()).unwrap();
        let row = v["flows"][0].as_object().unwrap();
        assert!(
            row.values().all(|v| !v.is_null()),
            "a null field is a key an agent pays for to learn nothing: {row:?}"
        );
        // Pruning removes members, never renames or reshapes them.
        assert_eq!(row["id"], json!(fid));
        assert_eq!(row["status"], json!(200));

        let decoded = req_show(
            &paths,
            &s,
            &crate::params::ReqShowParams {
                id: fid,
                raw: false,
            },
        )
        .unwrap();
        let raw = req_show(
            &paths,
            &s,
            &crate::params::ReqShowParams { id: fid, raw: true },
        )
        .unwrap();
        // Decoded view: the bytes, once. Raw view: the bytes, once, verbatim.
        assert!(decoded["response"]["body"].is_string());
        assert!(raw.get("raw_response").is_some());
        assert!(
            raw["response"].get("body").is_none(),
            "the body came back twice: {raw}"
        );
        // …and the metadata an agent branches on is in both.
        assert_eq!(raw["response"]["status"], decoded["response"]["status"]);
        assert_eq!(raw["request"]["path"], decoded["request"]["path"]);
        assert!(raw.to_string().len() < decoded.to_string().len() * 2);
    }

    #[test]
    fn prune_nulls_only_removes_nulls() {
        let mut v = json!({
            "keep": 1,
            "gone": null,
            "nested": [{ "a": null, "b": "x" }],
        });
        prune_nulls(&mut v);
        assert_eq!(v, json!({ "keep": 1, "nested": [{ "b": "x" }] }));
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
    async fn group_tools_roundtrip_and_refuse_unknown_names() {
        let (_d, paths, s) = temp_session().await;
        let fid = seed_one_flow(&paths, &s).await;

        // Adding to a group that does not exist is a clean, coded failure.
        assert!(group_add(
            &paths,
            &s,
            &crate::params::GroupAddParams {
                name: "nope".into(),
                flow_ids: vec![fid],
            }
        )
        .await
        .is_err());

        let new = crate::params::GroupNewParams {
            name: "auth-flow".into(),
            description: Some("login form -> POST /login -> Set-Cookie".into()),
            workspace: None,
        };
        let v = group_new(&paths, &s, &new).await.unwrap();
        assert_eq!(v["created"], true);
        // Idempotent: the second create returns the SAME group, not an error.
        let again = group_new(&paths, &s, &new).await.unwrap();
        assert_eq!(again["created"], false);
        assert_eq!(again["group_id"], v["group_id"]);

        // One bogus id fails the whole call and adds nothing.
        assert!(group_add(
            &paths,
            &s,
            &crate::params::GroupAddParams {
                name: "auth-flow".into(),
                flow_ids: vec![fid, 9999],
            }
        )
        .await
        .is_err());
        let shown = group_show(
            &paths,
            &s,
            &crate::params::GroupShowParams {
                name: "auth-flow".into(),
            },
        )
        .unwrap();
        assert_eq!(shown["count"], 0);

        group_add(
            &paths,
            &s,
            &crate::params::GroupAddParams {
                name: "auth-flow".into(),
                flow_ids: vec![fid],
            },
        )
        .await
        .unwrap();
        let shown = group_show(
            &paths,
            &s,
            &crate::params::GroupShowParams {
                name: "auth-flow".into(),
            },
        )
        .unwrap();
        assert_eq!(shown["count"], 1);
        assert_eq!(shown["flows"][0]["id"], fid);
        assert_eq!(
            shown["group"]["description"],
            "login form -> POST /login -> Set-Cookie"
        );

        let listed = group_list(&paths, &s, &crate::params::GroupListParams::default()).unwrap();
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["groups"][0]["flow_count"], 1);

        // Deleting the group leaves the flow itself captured.
        group_rm(
            &paths,
            &s,
            &crate::params::GroupRmParams {
                name: "auth-flow".into(),
            },
        )
        .await
        .unwrap();
        assert!(group_show(
            &paths,
            &s,
            &crate::params::GroupShowParams {
                name: "auth-flow".into()
            }
        )
        .is_err());
        let flows = req_list(&paths, &s, &crate::params::ReqListParams::default()).unwrap();
        assert_eq!(flows["count"], 1);
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

    #[tokio::test]
    async fn hook_tools_round_trip_and_refuse_a_broken_hook() {
        let (_dir, paths, s) = temp_session().await;

        let added = hook_add(
            &paths,
            &s,
            &crate::params::HookAddParams {
                name: "ua".into(),
                action: "add-header".into(),
                phase: None,
                host: Some("example.com".into()),
                method: None,
                path: None,
                status: None,
                header: Some("User-Agent: burpwn".into()),
                param: None,
                cmd: None,
                extract: None,
                inject_header: None,
                inject_param: None,
                order: None,
                timeout_ms: None,
                ttl_ms: None,
            },
        )
        .await
        .unwrap();
        let id = added["hook_id"].as_i64().unwrap();

        let listed = hook_list(&paths, &s).unwrap();
        assert_eq!(listed["hooks"].as_array().unwrap().len(), 1);
        assert_eq!(listed["hooks"][0]["phase"], "pre-request");
        assert_eq!(listed["hooks"][0]["enabled"], true);

        hook_set_enabled(
            &paths,
            &s,
            &crate::params::HookSetEnabledParams { id, enabled: false },
        )
        .await
        .unwrap();
        let listed = hook_list(&paths, &s).unwrap();
        assert_eq!(listed["hooks"][0]["enabled"], false);

        // An unknown id comes back branchable, not as a silent no-op.
        let err = hook_rm(&paths, &s, &crate::params::HookRmParams { id: 999 })
            .await
            .unwrap_err();
        assert_eq!(
            burpwn_cli::diag::diagnose(&err).code.id(),
            ErrorCode::InputNoSuchHook.id()
        );

        hook_rm(&paths, &s, &crate::params::HookRmParams { id })
            .await
            .unwrap();
        assert!(hook_list(&paths, &s).unwrap()["hooks"]
            .as_array()
            .unwrap()
            .is_empty());

        // A hook that could never work is refused at add time, so it never
        // reaches the table the proxy reads on the hot path.
        let broken = hook_add(
            &paths,
            &s,
            &crate::params::HookAddParams {
                name: "tok".into(),
                action: "exec".into(),
                phase: None,
                host: None,
                method: None,
                path: None,
                status: None,
                header: None,
                param: None,
                cmd: Some("mint".into()),
                extract: Some(r#""token":"[^"]+""#.into()), // no capture group
                inject_header: Some("Authorization: Bearer {}".into()),
                inject_param: None,
                order: None,
                timeout_ms: None,
                ttl_ms: None,
            },
        )
        .await;
        assert!(broken.is_err());
        assert!(hook_list(&paths, &s).unwrap()["hooks"]
            .as_array()
            .unwrap()
            .is_empty());
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
