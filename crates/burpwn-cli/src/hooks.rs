//! `burpwn hook` — the policy half of the hook engine.
//!
//! The mechanism lives in [`burpwn_proxy::hooks`]: matching, ordering, the byte
//! edits, the TTL cache, the recursion guards. This module owns everything that
//! is a *decision* rather than a mechanism, and everything that needs the
//! sandbox (which the proxy crate cannot reach):
//!
//! - [`build_hook`] validates an operator's flags into a [`NewHook`], so a hook
//!   that could never work — a header template without its `{}`, an `--extract`
//!   regex with no capture group, a `--status` on the request side — is refused
//!   at `hook add` time rather than at 3am on the hot path;
//! - [`SandboxHookRunner`] runs an `exec` hook's command in the same rootless
//!   sandbox as `burpwn exec` and the login macro, so its traffic is captured
//!   like any other — and, crucially, is STAMPED with a `hook:`-prefixed exec id
//!   so the proxy knows not to hook it again (see [`burpwn_proxy::hooks`]);
//! - [`test_hook`] replays one hook against one captured flow, without any live
//!   traffic, which is what makes a hook debuggable at all.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Value};

use burpwn_error::ErrorCode;
use burpwn_proxy::hooks::{self, HookRunner, MatchCtx};
use burpwn_proxy::matchreplace::Message;
use burpwn_sandbox::{doctor, RootlessRuntime, SandboxRuntime};
use burpwn_store::model::{
    FlowDetail, Hook, HookAction, HookInject, HookInjectKind, HookPhase, HookScope, NewHook,
};

use crate::exec;
use crate::paths::Paths;

/// Default hard budget for an `exec` hook's command. Deliberately well under the
/// proxy's own `UPSTREAM_TIMEOUT` (120 s) and its 30 s connect/header budgets:
/// the hook's time is spent BEFORE any of those start, and the client is waiting
/// through all of it.
pub const DEFAULT_TIMEOUT_MS: i64 = 10_000;

/// Default TTL for an `exec` hook's extracted value: five minutes. A token
/// refresh that ran on every request would be a sandbox per request.
pub const DEFAULT_TTL_MS: i64 = 300_000;

/// The operator's raw flags, before validation. Mirrors the `hook add` args but
/// is plain data, so the whole validation surface is unit-testable without clap.
#[derive(Debug, Clone, Default)]
pub struct HookSpec {
    /// Operator-facing name.
    pub name: String,
    /// `pre-request` / `post-response` (aliases: `request`, `response`).
    pub phase: String,
    /// Action kind: `add-header`, `set-header`, `remove-header`,
    /// `set-query-param`, `drop`, `exec`.
    pub action: String,
    /// Host substring scope (empty = every host).
    pub host: String,
    /// Method scope (empty = every method).
    pub method: String,
    /// Path substring scope (empty = every path).
    pub path: String,
    /// Response status scope (`post-response` only).
    pub status: Option<u16>,
    /// `Name: value` for the header actions, or a bare `Name` for
    /// `remove-header`.
    pub header: Option<String>,
    /// `name=value` for `set-query-param`.
    pub param: Option<String>,
    /// The literal text to look for, for `replace-payload`.
    pub find: Option<String>,
    /// What replaces it, for `replace-payload`.
    pub replace: Option<String>,
    /// The address to answer with, for `set-answer`.
    pub answer: Option<String>,
    /// The command, for `exec`.
    pub cmd: Option<String>,
    /// The one-capture-group regex applied to the command's stdout.
    pub extract: Option<String>,
    /// `Name: template {}` — where the extracted value goes (header form).
    pub inject_header: Option<String>,
    /// `name=template{}` — where the extracted value goes (query form).
    pub inject_param: Option<String>,
    /// Whether a header injection ADDS only when absent (`false` = add-or-replace).
    pub inject_only_if_absent: bool,
    /// Application order within the phase.
    pub order: i64,
    /// Command budget in milliseconds.
    pub timeout_ms: i64,
    /// Extracted-value cache TTL in milliseconds.
    pub ttl_ms: i64,
    /// Create the hook disabled.
    pub disabled: bool,
}

/// Validate an operator's flags into a storable [`NewHook`].
///
/// Everything that can be checked up front is: a hook is applied to live traffic
/// with nobody watching, so the moment to refuse a broken one is now.
pub fn build_hook(spec: &HookSpec) -> Result<NewHook> {
    let phase = parse_phase(&spec.phase)?;
    if spec.status.is_some() && phase != HookPhase::PostResponse {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "--status only makes sense on a post-response hook (a request has no status yet)"
        );
    }
    // A WebSocket message and a DNS query have no method. A hook carrying one
    // could only ever fail to match, silently, which is the whole failure mode
    // `hook add` exists to prevent.
    if !spec.method.trim().is_empty() && !phase.is_http() {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "--method scopes an HTTP request; a {} hook has no method to match \
             (scope it with --host and --path instead)",
            phase.as_str()
        );
    }
    if spec.timeout_ms <= 0 {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "--timeout must be a positive number of milliseconds"
        );
    }
    if spec.ttl_ms < 0 {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "--ttl must be zero (never cache) or a positive number of milliseconds"
        );
    }

    let action = match spec.action.as_str() {
        "add-header" | "set-header" => {
            let h = header_spec(spec, &spec.action)?;
            if spec.action == "add-header" {
                HookAction::AddHeader {
                    name: h.name,
                    value: h.value,
                }
            } else {
                HookAction::SetHeader {
                    name: h.name,
                    value: h.value,
                }
            }
        }
        "remove-header" => {
            let raw = require(&spec.header, "--header <Name>", "remove-header")?;
            HookAction::RemoveHeader {
                name: header_name(raw)?,
            }
        }
        "set-query-param" => {
            let raw = require(&spec.param, "--param <name=value>", "set-query-param")?;
            let (name, value) = param_spec(raw)?;
            request_side_only(phase, "set-query-param")?;
            HookAction::SetQueryParam { name, value }
        }
        "drop" => HookAction::Drop,
        "replace-payload" => {
            let find = require(&spec.find, "--find <text>", "replace-payload")?;
            if find.is_empty() {
                crate::fail!(
                    ErrorCode::InputInvalidValue,
                    "--find must not be empty (an empty match would rewrite nothing, \
                     on every message)"
                );
            }
            HookAction::ReplacePayload {
                find: find.clone(),
                replace: spec.replace.clone().unwrap_or_default(),
            }
        }
        "set-answer" => {
            let raw = require(&spec.answer, "--answer <ip>", "set-answer")?;
            let ip = raw.trim().parse().map_err(|_| {
                crate::coded!(
                    ErrorCode::InputInvalidValue,
                    "--answer must be an IPv4 or IPv6 address, got {raw:?}"
                )
            })?;
            HookAction::SetAnswer { ip }
        }
        "exec" => {
            let cmd = require(&spec.cmd, "--cmd <command>", "exec")?
                .trim()
                .to_string();
            if cmd.is_empty() {
                crate::fail!(ErrorCode::InputInvalidValue, "--cmd must not be empty");
            }
            let extract = require(&spec.extract, "--extract <regex>", "exec")?;
            check_extract(extract)?;
            let inject = build_inject(spec, phase)?;
            HookAction::Exec {
                cmd,
                extract: extract.clone(),
                inject,
            }
        }
        other => crate::fail!(
            ErrorCode::InputInvalidValue,
            "unknown hook action {other:?} — one of: {}",
            HookAction::VALID.join(", ")
        ),
    };

    // The pairing. An action that means nothing on this phase — a header on a
    // WebSocket message, a command on a per-frame phase — is refused HERE, at
    // the only moment a human is looking: accepting it and discovering on the
    // hot path that there is nothing to add the header to is the silent
    // fallback this codebase keeps removing.
    if !action.allowed_on(phase) {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "the {} action does not apply to a {} hook — {}",
            action.kind(),
            phase.as_str(),
            why_not(&action, phase)
        );
    }

    Ok(NewHook {
        enabled: !spec.disabled,
        name: spec.name.clone(),
        phase,
        scope: HookScope {
            host: spec.host.clone(),
            method: spec.method.clone(),
            path: spec.path.clone(),
            status: spec.status,
        },
        action,
        order: spec.order,
        timeout_ms: spec.timeout_ms,
        ttl_ms: spec.ttl_ms,
    })
}

/// The phase, with the short aliases an operator will try.
///
/// The WebSocket phases are named after the DIRECTION, `ws-c2s` / `ws-s2c`,
/// because that is the word the capture already uses: `req show` on a WebSocket
/// flow prints `c2s`/`s2c` per message, so the operator who just read a frame
/// and wants to act on it writes down what they read. `ws-send`/`ws-recv` would
/// have been shorter and ambiguous — sent by whom? — so they are accepted as
/// aliases (from the CLIENT's point of view, the only one a browser-side
/// operator has) rather than as the name.
fn parse_phase(s: &str) -> Result<HookPhase> {
    match s {
        "pre-request" | "request" | "req" => Ok(HookPhase::PreRequest),
        "post-response" | "response" | "resp" => Ok(HookPhase::PostResponse),
        "ws-c2s" | "ws-send" | "ws-client" => Ok(HookPhase::WsC2s),
        "ws-s2c" | "ws-recv" | "ws-server" => Ok(HookPhase::WsS2c),
        "dns-query" | "dns" => Ok(HookPhase::DnsQuery),
        other => crate::fail!(
            ErrorCode::InputInvalidValue,
            "--phase must be one of {}, got {other:?}",
            HookPhase::ALL
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join("|")
        ),
    }
}

/// Why an action does not apply to a phase, in the operator's terms. The
/// refusal is worth nothing if it does not say what to do instead.
fn why_not(action: &HookAction, phase: HookPhase) -> String {
    match action {
        HookAction::Exec { .. } => format!(
            "an exec hook runs a command in a sandbox, and a {} hook fires on every \
             {} — one sandbox each would cost more than the traffic it watches. \
             Put the exec hook on pre-request: a socket inherits what its upgrade \
             request carried",
            phase.as_str(),
            if phase.is_ws() {
                "message the socket carries"
            } else {
                "name the workload resolves"
            }
        ),
        HookAction::ReplacePayload { .. } => {
            "it rewrites a websocket payload, so it needs --phase ws-c2s or ws-s2c".into()
        }
        HookAction::SetAnswer { .. } => {
            "it answers a name instead of resolving it, so it needs --phase dns-query".into()
        }
        _ => format!(
            "there are no headers and no request target on a {} message; what a hook \
             can do there is drop it{}",
            phase.as_str(),
            if phase.is_ws() {
                " or rewrite its payload (--action replace-payload)"
            } else {
                " or answer it (--action set-answer)"
            }
        ),
    }
}

fn require<'a>(value: &'a Option<String>, flag: &str, action: &str) -> Result<&'a String> {
    match value {
        Some(v) => Ok(v),
        None => crate::fail!(
            ErrorCode::InputMissingSelection,
            "the {action} action needs {flag}"
        ),
    }
}

fn request_side_only(phase: HookPhase, action: &str) -> Result<()> {
    if phase != HookPhase::PreRequest {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "{action} rewrites the request target, so it only applies to a \
             pre-request hook, not to a {} one",
            phase.as_str()
        );
    }
    Ok(())
}

/// Parse the `Name: value` a header action carries, reusing the repeater's
/// parser (which already rejects CR/LF/NUL — the header-injection guard).
fn header_spec(spec: &HookSpec, action: &str) -> Result<crate::replay::ReplayEdit> {
    let raw = require(&spec.header, "--header 'Name: value'", action)?;
    crate::replay::parse_header_spec(raw)
}

/// A bare header NAME (for `remove-header`).
fn header_name(raw: &str) -> Result<String> {
    let name = raw.split(':').next().unwrap_or(raw).trim().to_string();
    if name.is_empty() || name.contains(['\r', '\n', '\0']) {
        crate::fail!(
            ErrorCode::InputMalformedHeader,
            "--header must be a header name, got {raw:?}"
        );
    }
    Ok(name)
}

/// `name=value` for a query parameter.
fn param_spec(raw: &str) -> Result<(String, String)> {
    let (name, value) = raw.split_once('=').ok_or_else(|| {
        crate::coded!(
            ErrorCode::InputInvalidValue,
            "--param must be `name=value`, got {raw:?}"
        )
    })?;
    if name.trim().is_empty() {
        crate::fail!(ErrorCode::InputInvalidValue, "--param has an empty name");
    }
    Ok((name.trim().to_string(), value.to_string()))
}

/// The extraction regex must compile AND have exactly the one capture group that
/// says WHICH part of the output is the value. Same contract as
/// `session auth --extract`, and the same failure code.
fn check_extract(pattern: &str) -> Result<()> {
    let re = Regex::new(pattern)
        .with_context(|| format!("invalid --extract regex {pattern:?}"))
        .map_err(|e| crate::coded!(ErrorCode::InputBadRegex, "{e:#}"))?;
    if re.captures_len() < 2 {
        crate::fail!(
            ErrorCode::InputBadRegex,
            "--extract needs one capture group around the value to extract, \
             e.g. \"access_token\":\"([^\"]+)\""
        );
    }
    Ok(())
}

/// Where an `exec` hook's value goes. Exactly one of the two injection flags.
fn build_inject(spec: &HookSpec, phase: HookPhase) -> Result<HookInject> {
    match (&spec.inject_header, &spec.inject_param) {
        (Some(_), Some(_)) => crate::fail!(
            ErrorCode::InputInvalidValue,
            "pass either --inject-header or --inject-param, not both"
        ),
        (Some(raw), None) => {
            let edit = crate::replay::parse_header_spec(raw)?;
            check_template(&edit.value, "--inject-header")?;
            Ok(HookInject {
                kind: if spec.inject_only_if_absent {
                    HookInjectKind::AddHeader
                } else {
                    HookInjectKind::SetHeader
                },
                name: edit.name,
                value_template: edit.value,
            })
        }
        (None, Some(raw)) => {
            request_side_only(phase, "--inject-param")?;
            let (name, template) = param_spec(raw)?;
            check_template(&template, "--inject-param")?;
            Ok(HookInject {
                kind: HookInjectKind::SetQueryParam,
                name,
                value_template: template,
            })
        }
        (None, None) => crate::fail!(
            ErrorCode::InputMissingSelection,
            "the exec action needs --inject-header 'Name: prefix {{}}' (or \
             --inject-param name={{}}) to say where the extracted value goes"
        ),
    }
}

/// An injection template without the `{}` placeholder would inject a constant —
/// i.e. run a command for nothing. Refuse it.
fn check_template(template: &str, flag: &str) -> Result<()> {
    if !template.contains(hooks::VALUE_PLACEHOLDER) {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "{flag} must contain the {{}} placeholder the extracted value \
             replaces, e.g. 'Authorization: Bearer {{}}'"
        );
    }
    Ok(())
}

/// The hook's match scope as one field (`*` when it matches everything). One
/// half of the `hook list` / `hook show` row (the other is
/// [`action_summary`]); they are separate fields because the listing puts them
/// in separate columns.
pub fn scope_summary(hook: &Hook) -> String {
    let mut scope = Vec::new();
    if !hook.scope.host.is_empty() {
        scope.push(format!("host~{}", hook.scope.host));
    }
    if !hook.scope.method.is_empty() {
        scope.push(format!("method={}", hook.scope.method));
    }
    if !hook.scope.path.is_empty() {
        scope.push(format!("path~{}", hook.scope.path));
    }
    if let Some(s) = hook.scope.status {
        scope.push(format!("status={s}"));
    }
    if scope.is_empty() {
        "*".to_string()
    } else {
        scope.join(" ")
    }
}

/// What the hook DOES, as one field.
pub fn action_summary(hook: &Hook) -> String {
    match &hook.action {
        HookAction::AddHeader { name, value } => format!("add-header {name}: {value}"),
        HookAction::SetHeader { name, value } => format!("set-header {name}: {value}"),
        HookAction::RemoveHeader { name } => format!("remove-header {name}"),
        HookAction::SetQueryParam { name, value } => format!("set-query-param {name}={value}"),
        HookAction::Drop => "drop".to_string(),
        HookAction::ReplacePayload { find, replace } => {
            format!("replace-payload {find:?} -> {replace:?}")
        }
        HookAction::SetAnswer { ip } => format!("set-answer {ip}"),
        HookAction::Exec { cmd, inject, .. } => format!(
            "exec {cmd:?} -> {} {}: {}",
            inject.kind.as_str(),
            inject.name,
            inject.value_template
        ),
    }
}

/// The JSON view of a hook, shared by the CLI and the MCP tools.
pub fn to_json(hook: &Hook) -> Value {
    json!({
        "id": hook.id,
        "enabled": hook.enabled,
        "name": hook.name,
        "phase": hook.phase.as_str(),
        "scope": {
            "host": hook.scope.host,
            "method": hook.scope.method,
            "path": hook.scope.path,
            "status": hook.scope.status,
        },
        "action": hook.action,
        "order": hook.order,
        "timeout_ms": hook.timeout_ms,
        "ttl_ms": hook.ttl_ms,
        "created_at": hook.created_at,
    })
}

// --- running a hook's command ----------------------------------------------

/// Runs an `exec` hook's command in the rootless sandbox, exactly like
/// `burpwn exec` and the `session auth` login macro.
///
/// The command's traffic goes through this proxy — that is the point, it is how
/// a token mint is captured like everything else — which is precisely why the
/// run is stamped with a `hook:`-prefixed exec id: the proxy front-end carries
/// it in the wire header of every connection the command makes, and the hook
/// engine skips any flow that has it. Without that marker a hook that calls an
/// API would trigger itself.
pub struct SandboxHookRunner {
    paths: Paths,
    session: String,
    /// Test seam: a [`burpwn_sandbox::MockRuntime`] instead of the real one.
    runtime_override: Option<Arc<dyn SandboxRuntime>>,
}

impl SandboxHookRunner {
    /// A runner bound to one session's sandbox + proxy socket.
    pub fn new(paths: Paths, session: impl Into<String>) -> Self {
        Self {
            paths,
            session: session.into(),
            runtime_override: None,
        }
    }

    /// Inject a runtime (tests).
    pub fn with_runtime(mut self, runtime: Arc<dyn SandboxRuntime>) -> Self {
        self.runtime_override = Some(runtime);
        self
    }

    fn runtime(&self) -> Result<Arc<dyn SandboxRuntime>> {
        if let Some(rt) = &self.runtime_override {
            return Ok(rt.clone());
        }
        let pf = doctor();
        if !pf.is_ok() {
            crate::fail!(
                ErrorCode::SandboxPrerequisites,
                "sandbox preflight failed: {} — run `burpwn doctor`",
                pf.missing_summary()
            );
        }
        Ok(Arc::new(RootlessRuntime::new()))
    }
}

#[async_trait]
impl HookRunner for SandboxHookRunner {
    async fn run(&self, cmd: &str, budget: Duration) -> Result<String, anyhow::Error> {
        let runtime = self.runtime()?;
        let argv = vec!["sh".to_string(), "-c".to_string(), cmd.to_string()];
        // The marker. `run_exec_as` puts it in the wire header of every
        // connection this command opens.
        let exec_id = format!(
            "{}{}",
            burpwn_proxy::HOOK_EXEC_ID_PREFIX,
            exec::new_exec_id()
        );
        // The sandbox gets the budget too, so an over-running command is KILLED
        // rather than orphaned when the engine's own timeout cancels this future.
        let result = exec::run_exec_as(
            &self.paths,
            &self.session,
            exec::DEFAULT_WORKSPACE_ID,
            runtime,
            argv,
            Some(budget),
            false, // capture stdout
            exec_id,
        )
        .await
        .context("running the hook command in the sandbox")?;
        Ok(String::from_utf8_lossy(&result.outcome.stdout).into_owned())
    }
}

// --- `hook test` ------------------------------------------------------------

/// Replay one hook against one CAPTURED flow and report what it would do: no
/// live traffic, no target touched. For an `exec` hook the command DOES run
/// (that is the half an operator most needs to see), through `runner`.
pub async fn test_hook(
    hook: &Hook,
    detail: &FlowDetail,
    runner: Option<&dyn HookRunner>,
) -> Result<Value> {
    let Some(request) = detail.request.as_ref() else {
        crate::fail!(
            ErrorCode::InputNothingToDo,
            "flow {} has no recorded request to test a hook against",
            detail.flow.id
        );
    };
    let host = detail
        .flow
        .sni
        .clone()
        .or_else(|| (!request.authority.is_empty()).then(|| request.authority.clone()))
        .unwrap_or_default();

    // `hook test` replays a hook against a captured HTTP message. The
    // WebSocket and DNS phases have no such message on a `FlowDetail` — the
    // frames live in their own table and a DNS query is a name, not a request —
    // so testing them would mean inventing a message the hook never sees. Say
    // that, rather than report a confident "does not match" about a comparison
    // that was never made.
    if !hook.phase.is_http() {
        crate::fail!(
            ErrorCode::InputNothingToDo,
            "hook {} is a {} hook: `hook test` replays a hook against a captured \
             HTTP request or response, and neither exists for that phase. Watch it \
             on live traffic instead (`req list --protocol ws` / `--protocol dns`)",
            hook.id,
            hook.phase.as_str()
        );
    }

    // The message the hook would see, per phase: a request, or the response
    // headers/body carrying the request's host/path for scoping.
    let (mut msg, status) = match hook.phase {
        HookPhase::PreRequest => (
            Message {
                host: host.clone(),
                url: request.path.clone(),
                headers: request.headers.clone(),
                body: request.body.clone(),
            },
            None,
        ),
        HookPhase::PostResponse => {
            let Some(response) = detail.response.as_ref() else {
                crate::fail!(
                    ErrorCode::InputNothingToDo,
                    "flow {} has no recorded response to test a post-response hook against",
                    detail.flow.id
                );
            };
            (
                Message {
                    host: host.clone(),
                    url: request.path.clone(),
                    headers: response.headers.clone(),
                    body: response.body.clone(),
                },
                Some(response.status),
            )
        }
        // Refused above: `hook test` needs an HTTP message and these phases
        // have none. Unreachable, and deliberately not a fabricated default.
        other => crate::fail!(
            ErrorCode::InputNothingToDo,
            "hook test does not apply to the {} phase",
            other.as_str()
        ),
    };

    let (scope_host, scope_path) = (msg.host.clone(), request.path.clone());
    let ctx = MatchCtx {
        host: &scope_host,
        method: &request.method,
        path: &scope_path,
        status,
    };
    let matched = hooks::scope_matches(&hook.scope, &ctx);
    let before_headers = String::from_utf8_lossy(&msg.headers).into_owned();
    let before_url = msg.url.clone();

    let mut changed = false;
    let mut dropped = false;
    let mut ran: Option<Value> = None;
    if matched {
        match &hook.action {
            HookAction::Exec {
                cmd,
                extract,
                inject,
            } => {
                let Some(runner) = runner else {
                    crate::fail!(
                        ErrorCode::InputMissingSelection,
                        "this is an exec hook: testing it runs its command in the \
                         sandbox, which needs a session daemon"
                    );
                };
                let budget = Duration::from_millis(hook.timeout_ms.max(0) as u64);
                // Report the command's outcome rather than swallowing it the way
                // the proxy does: on the hot path a broken hook must fail open
                // and get out of the way; here, the failure IS the answer.
                match tokio::time::timeout(budget, runner.run(cmd, budget)).await {
                    Ok(Ok(stdout)) => match hooks::extract_value(extract, &stdout) {
                        Some(value) => {
                            changed = hooks::apply_inject(inject, &value, &mut msg);
                            ran = Some(json!({
                                "ok": true,
                                "stdout_bytes": stdout.len(),
                                "extracted": crate::auth::mask_token(&value),
                            }));
                        }
                        None => {
                            ran = Some(json!({
                                "ok": false,
                                "stdout_bytes": stdout.len(),
                                "error": "the --extract regex did not match the command output",
                            }));
                        }
                    },
                    Ok(Err(e)) => {
                        ran = Some(json!({ "ok": false, "error": format!("{e:#}") }));
                    }
                    Err(_) => {
                        ran = Some(json!({
                            "ok": false,
                            "error": format!("timed out after {}ms", hook.timeout_ms),
                        }));
                    }
                }
            }
            declarative => {
                let out = hooks::apply_declarative(
                    std::slice::from_ref(&Hook {
                        action: declarative.clone(),
                        ..hook.clone()
                    }),
                    hook.phase,
                    &ctx,
                    &mut msg,
                );
                changed = out.changed;
                dropped = out.dropped;
            }
        }
    }

    Ok(json!({
        "hook_id": hook.id,
        "flow_id": detail.flow.id,
        "phase": hook.phase.as_str(),
        "matched": matched,
        "changed": changed,
        "dropped": dropped,
        "exec": ran,
        "before": { "headers": before_headers, "url": before_url },
        "after": {
            "headers": String::from_utf8_lossy(&msg.headers),
            "url": msg.url,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(action: &str) -> HookSpec {
        HookSpec {
            name: "t".into(),
            phase: "pre-request".into(),
            action: action.into(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            ttl_ms: DEFAULT_TTL_MS,
            ..Default::default()
        }
    }

    #[test]
    fn builds_the_declarative_actions() {
        let mut s = spec("add-header");
        s.header = Some("User-Agent: burpwn".into());
        s.host = "example.com".into();
        let h = build_hook(&s).unwrap();
        assert_eq!(h.phase, HookPhase::PreRequest);
        assert_eq!(h.scope.host, "example.com");
        assert_eq!(
            h.action,
            HookAction::AddHeader {
                name: "User-Agent".into(),
                value: "burpwn".into()
            }
        );
        assert!(h.enabled);

        let mut s = spec("remove-header");
        s.header = Some("Cookie".into());
        assert_eq!(
            build_hook(&s).unwrap().action,
            HookAction::RemoveHeader {
                name: "Cookie".into()
            }
        );

        let mut s = spec("set-query-param");
        s.param = Some("debug=1".into());
        assert_eq!(
            build_hook(&s).unwrap().action,
            HookAction::SetQueryParam {
                name: "debug".into(),
                value: "1".into()
            }
        );

        assert_eq!(build_hook(&spec("drop")).unwrap().action, HookAction::Drop);
    }

    /// The WebSocket and DNS phases: what they accept, and — the part that
    /// matters — what they refuse. An action that means nothing on a phase must
    /// die here, with a message naming the phase, because the alternative is a
    /// hook sitting in the table doing nothing at all.
    #[test]
    fn the_websocket_and_dns_phases_accept_only_what_they_can_do() {
        let ws_spec = |action: &str| {
            let mut s = spec(action);
            s.phase = "ws-c2s".into();
            s
        };

        let mut s = ws_spec("replace-payload");
        s.find = Some("\"role\":\"user\"".into());
        s.replace = Some("\"role\":\"admin\"".into());
        let h = build_hook(&s).unwrap();
        assert_eq!(h.phase, HookPhase::WsC2s);
        assert_eq!(
            h.action,
            HookAction::ReplacePayload {
                find: "\"role\":\"user\"".into(),
                replace: "\"role\":\"admin\"".into()
            }
        );
        // An omitted --replace deletes the match rather than being a refusal:
        // "cut the heartbeat field out of every frame" is a real thing to want.
        let mut s = ws_spec("replace-payload");
        s.find = Some("secret".into());
        assert_eq!(
            build_hook(&s).unwrap().action,
            HookAction::ReplacePayload {
                find: "secret".into(),
                replace: String::new()
            }
        );
        // …but an empty --find would match nothing on every message.
        let mut s = ws_spec("replace-payload");
        s.find = Some(String::new());
        assert!(build_hook(&s).is_err());
        assert!(
            build_hook(&ws_spec("replace-payload")).is_err(),
            "no --find"
        );

        // `drop` is the one action every phase understands.
        assert_eq!(
            build_hook(&ws_spec("drop")).unwrap().action,
            HookAction::Drop
        );

        let mut s = spec("set-answer");
        s.phase = "dns-query".into();
        s.answer = Some("10.0.0.5".into());
        let h = build_hook(&s).unwrap();
        assert_eq!(h.phase, HookPhase::DnsQuery);
        assert_eq!(
            h.action,
            HookAction::SetAnswer {
                ip: "10.0.0.5".parse().unwrap()
            }
        );
        s.answer = Some("not-an-ip".into());
        assert!(build_hook(&s).is_err());

        // --- the refusals ---
        for (phase, action) in [
            // No header, no target, on a frame or a query.
            ("ws-c2s", "add-header"),
            ("ws-s2c", "set-header"),
            ("dns-query", "remove-header"),
            ("ws-c2s", "set-query-param"),
            // A command per message is the cost model these phases exist to
            // avoid.
            ("ws-s2c", "exec"),
            ("dns-query", "exec"),
            // …and the reverse: a payload rewrite is not an HTTP action, an
            // answer is not a WebSocket one.
            ("pre-request", "replace-payload"),
            ("ws-c2s", "set-answer"),
            ("dns-query", "replace-payload"),
        ] {
            let mut s = spec(action);
            s.phase = phase.into();
            // Give every action everything it could need, so the refusal is
            // about the PAIRING and not about a missing flag.
            s.header = Some("X-Test: 1".into());
            s.param = Some("a=1".into());
            s.find = Some("a".into());
            s.answer = Some("127.0.0.1".into());
            s.cmd = Some("mint".into());
            s.extract = Some(r#"tok=(\w+)"#.into());
            s.inject_header = Some("Authorization: Bearer {}".into());
            let err = build_hook(&s).unwrap_err().to_string();
            assert!(
                err.contains(phase) || err.contains("ws-c2s") || err.contains("dns-query"),
                "{phase}/{action} must be refused with a message that names the \
                 phase, got: {err}"
            );
        }

        // A method scope on a phase that has no method is equally a refusal:
        // silently never matching is the failure this whole check exists for.
        let mut s = ws_spec("drop");
        s.method = "GET".into();
        assert!(build_hook(&s).is_err());
    }

    /// The phase spellings an operator will actually type.
    #[test]
    fn phase_aliases_resolve_to_the_direction_the_capture_prints() {
        for (spelling, want) in [
            ("pre-request", HookPhase::PreRequest),
            ("req", HookPhase::PreRequest),
            ("post-response", HookPhase::PostResponse),
            ("resp", HookPhase::PostResponse),
            ("ws-c2s", HookPhase::WsC2s),
            ("ws-send", HookPhase::WsC2s),
            ("ws-client", HookPhase::WsC2s),
            ("ws-s2c", HookPhase::WsS2c),
            ("ws-recv", HookPhase::WsS2c),
            ("ws-server", HookPhase::WsS2c),
            ("dns-query", HookPhase::DnsQuery),
            ("dns", HookPhase::DnsQuery),
        ] {
            assert_eq!(parse_phase(spelling).unwrap(), want, "{spelling}");
        }
        // A near-miss is an error listing the real spellings, never a default.
        let err = parse_phase("ws").unwrap_err().to_string();
        assert!(err.contains("ws-c2s") && err.contains("dns-query"), "{err}");
    }

    #[test]
    fn builds_an_exec_hook_with_its_injection() {
        let mut s = spec("exec");
        s.cmd = Some("get-token.sh".into());
        s.extract = Some(r#""token":"([^"]+)""#.into());
        s.inject_header = Some("Authorization: Bearer {}".into());
        s.ttl_ms = 60_000;
        let h = build_hook(&s).unwrap();
        match h.action {
            HookAction::Exec {
                cmd,
                extract,
                inject,
            } => {
                assert_eq!(cmd, "get-token.sh");
                assert_eq!(extract, r#""token":"([^"]+)""#);
                assert_eq!(inject.kind, HookInjectKind::SetHeader);
                assert_eq!(inject.name, "Authorization");
                assert_eq!(inject.value_template, "Bearer {}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(h.ttl_ms, 60_000);
    }

    /// Everything that can only fail at 3am on live traffic is refused here.
    #[test]
    fn refuses_hooks_that_could_never_work() {
        // Unknown phase / action.
        let mut s = spec("add-header");
        s.header = Some("A: b".into());
        s.phase = "mid-flight".into();
        assert!(build_hook(&s).is_err());
        let mut s = spec("teleport");
        s.header = Some("A: b".into());
        assert!(build_hook(&s).is_err());

        // A header action with no header, and a header that would smuggle a
        // second line.
        assert!(build_hook(&spec("add-header")).is_err());
        let mut s = spec("set-header");
        s.header = Some("X: a\r\nX-Admin: 1".into());
        assert!(build_hook(&s).is_err());

        // `--status` on a request, which can never match.
        let mut s = spec("drop");
        s.status = Some(500);
        assert!(build_hook(&s).is_err());
        let mut s = spec("drop");
        s.status = Some(500);
        s.phase = "post-response".into();
        assert!(build_hook(&s).is_ok());

        // A query-param edit on the response side (there is no target to edit).
        let mut s = spec("set-query-param");
        s.param = Some("a=1".into());
        s.phase = "post-response".into();
        assert!(build_hook(&s).is_err());

        // exec: missing pieces, a regex with no capture group, a template with
        // no placeholder, and both injection flags at once.
        let mut s = spec("exec");
        assert!(build_hook(&s).is_err(), "no --cmd");
        s.cmd = Some("t.sh".into());
        assert!(build_hook(&s).is_err(), "no --extract");
        s.extract = Some(r#""token":"[^"]+""#.into());
        s.inject_header = Some("Authorization: Bearer {}".into());
        assert!(build_hook(&s).is_err(), "no capture group");
        s.extract = Some(r#""token":"([^"]+)""#.into());
        s.inject_header = Some("Authorization: Bearer".into());
        assert!(build_hook(&s).is_err(), "no {{}} placeholder");
        s.inject_header = Some("Authorization: Bearer {}".into());
        s.inject_param = Some("t={}".into());
        assert!(build_hook(&s).is_err(), "two injection flags");

        // Nonsensical budgets.
        let mut s = spec("drop");
        s.timeout_ms = 0;
        assert!(build_hook(&s).is_err());
        let mut s = spec("drop");
        s.ttl_ms = -1;
        assert!(build_hook(&s).is_err());
    }

    fn detail(status: Option<u16>) -> FlowDetail {
        use burpwn_store::model::{FlowRow, Protocol, RequestData, ResponseData};
        FlowDetail {
            flow: FlowRow {
                id: 7,
                workspace_id: 1,
                ts_start: 0,
                ts_end: None,
                protocol: Protocol::H1,
                scheme: "https".into(),
                dst_ip: "10.0.0.1".into(),
                dst_port: 443,
                sni: Some("api.example.com".into()),
                method: Some("GET".into()),
                authority: Some("api.example.com".into()),
                path: Some("/v1/users".into()),
                status,
                intercepted: false,
            },
            exec_id: None,
            client_addr: "127.0.0.1:1".into(),
            request: Some(RequestData {
                method: "GET".into(),
                authority: "api.example.com".into(),
                path: "/v1/users".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"host: api.example.com\r\n".to_vec(),
                body: Vec::new(),
            }),
            response: status.map(|s| ResponseData {
                status: s,
                http_version: "HTTP/1.1".into(),
                headers: b"content-type: application/json\r\n".to_vec(),
                body: b"{}".to_vec(),
                timing_ms: None,
            }),
            tags: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn stored(new: NewHook) -> Hook {
        Hook {
            id: 1,
            enabled: new.enabled,
            name: new.name,
            phase: new.phase,
            scope: new.scope,
            action: new.action,
            order: new.order,
            timeout_ms: new.timeout_ms,
            ttl_ms: new.ttl_ms,
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn test_hook_shows_the_edit_without_touching_the_network() {
        let mut s = spec("add-header");
        s.header = Some("X-Trace: 1".into());
        let hook = stored(build_hook(&s).unwrap());
        let out = test_hook(&hook, &detail(Some(200)), None).await.unwrap();
        assert_eq!(out["matched"], json!(true));
        assert_eq!(out["changed"], json!(true));
        assert!(out["after"]["headers"]
            .as_str()
            .unwrap()
            .contains("X-Trace: 1"));
        assert!(!out["before"]["headers"]
            .as_str()
            .unwrap()
            .contains("X-Trace"));

        // Out of scope: reported honestly rather than silently doing nothing.
        let mut s = spec("add-header");
        s.header = Some("X-Trace: 1".into());
        s.host = "other.test".into();
        let hook = stored(build_hook(&s).unwrap());
        let out = test_hook(&hook, &detail(Some(200)), None).await.unwrap();
        assert_eq!(out["matched"], json!(false));
        assert_eq!(out["changed"], json!(false));
    }

    #[tokio::test]
    async fn test_hook_runs_an_exec_hooks_command_and_reports_it() {
        struct Fake;
        #[async_trait]
        impl HookRunner for Fake {
            async fn run(&self, _cmd: &str, _budget: Duration) -> Result<String, anyhow::Error> {
                Ok(r#"{"token":"abcdefghijklmnop"}"#.to_string())
            }
        }
        let mut s = spec("exec");
        s.cmd = Some("mint".into());
        s.extract = Some(r#""token":"([^"]+)""#.into());
        s.inject_header = Some("Authorization: Bearer {}".into());
        let hook = stored(build_hook(&s).unwrap());
        let out = test_hook(&hook, &detail(Some(200)), Some(&Fake))
            .await
            .unwrap();
        assert_eq!(out["exec"]["ok"], json!(true));
        assert!(out["after"]["headers"]
            .as_str()
            .unwrap()
            .contains("Authorization: Bearer abcdefghijklmnop"));
        // The value is MASKED in the report: `hook test` output ends up in
        // terminals, logs and agent context.
        let extracted = out["exec"]["extracted"].as_str().unwrap();
        assert!(!extracted.contains("defghijklm"), "{extracted}");

        // A command that fails is reported, not swallowed.
        struct Boom;
        #[async_trait]
        impl HookRunner for Boom {
            async fn run(&self, _cmd: &str, _budget: Duration) -> Result<String, anyhow::Error> {
                Err(anyhow::anyhow!("command not found"))
            }
        }
        let out = test_hook(&hook, &detail(Some(200)), Some(&Boom))
            .await
            .unwrap();
        assert_eq!(out["exec"]["ok"], json!(false));
        assert!(out["exec"]["error"]
            .as_str()
            .unwrap()
            .contains("command not found"));
    }

    #[tokio::test]
    async fn a_post_response_hook_tests_against_the_recorded_response() {
        let mut s = spec("set-header");
        s.phase = "post-response".into();
        s.status = Some(200);
        s.header = Some("X-Checked: yes".into());
        let hook = stored(build_hook(&s).unwrap());
        let out = test_hook(&hook, &detail(Some(200)), None).await.unwrap();
        assert_eq!(out["changed"], json!(true));
        assert!(out["after"]["headers"]
            .as_str()
            .unwrap()
            .contains("X-Checked: yes"));
        // A flow with no response cannot exercise a response hook.
        assert!(test_hook(&hook, &detail(None), None).await.is_err());
    }
}
