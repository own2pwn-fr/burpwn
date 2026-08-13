//! The hook engine: an action applied to every message matching a scope, on one
//! phase of the proxy pipeline.
//!
//! Match/replace REWRITES text a message already carries; it cannot synthesize
//! what is not there, run anything, or refuse a flow. Hooks are the other half:
//! `add-header` puts in a header the client never sent, `drop` refuses the flow,
//! and `exec` parks the request behind a command (mint a token, read a signature
//! out of a helper) whose output is injected before the request goes upstream.
//! Both live side by side; neither replaces the other.
//!
//! # What this costs on the hot path
//!
//! Everything here is behind ONE relaxed atomic load. With no hook configured —
//! the case for every user who never ran `burpwn hook add` — [`HookEngine::any`]
//! is `false` and the proxy does not allocate, lock or await anything. The
//! declarative actions (header/query edits, drop) are pure byte work on the
//! message that is already in memory: no spawn, no I/O, no store access. Only
//! [`HookAction::Exec`] is expensive, and it pays for a whole sandbox (a network
//! namespace) per run — which is why its value is cached per hook and why the
//! declarative path never touches any of that machinery.
//!
//! # Recursion: the guarantee, in two layers
//!
//! An `exec` hook's command runs in the sandbox, so its own traffic comes back
//! through this proxy — and would hit the very hook that spawned it.
//!
//! 1. **The marker (hard, structural).** A hook's command runs under an
//!    `exec_id` prefixed with [`HOOK_EXEC_ID_PREFIX`], stamped into the wire
//!    header by the sandbox front-end for every connection it makes. Any flow
//!    carrying it bypasses the hook engine ENTIRELY ([`is_hook_traffic`]) — not
//!    "this hook", every hook, both phases. It is a property of the connection,
//!    not a timing window, so it cannot be raced.
//! 2. **The one-command invariant (bounded, defensive).** If the marker is ever
//!    missing — a hook command that reaches a *different* burpwn, a front-end
//!    that loses the exec id — **at most one hook command runs at a time, for
//!    the whole proxy**. A request that would need to start a second one is
//!    served fail-open immediately: it never waits on the running one (waiting
//!    is what turns a recursion into a stall) and never spawns beside it. A
//!    recursion therefore cannot amplify into N sandboxes; it degrades into one
//!    logged, un-hooked request.
//!
//! That invariant doubles as the **single-flight** the TTL cache needs: a burst
//! of concurrent requests on a cold cache mints ONE value, not one per request.
//! The price is explicit — the requests that lose the race are forwarded
//! un-hooked rather than parked behind the winner — and it is why an `exec` hook
//! wants a `ttl_ms`: with one, the race window is a single command per TTL and
//! every other request reads the cache.
//!
//! On top of both, every `exec` hook is bounded by its own `timeout_ms` and
//! FAILS OPEN on expiry or error: a broken hook never breaks traffic, it just
//! stops modifying it (and says so at `WARN`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use regex::Regex;

use burpwn_store::model::{Hook, HookAction, HookInject, HookInjectKind, HookPhase, HookScope};

use crate::matchreplace::Message;

/// Prefix that marks an `exec_id` as belonging to a hook's own command. Traffic
/// stamped with it bypasses every hook (see the module docs).
pub const HOOK_EXEC_ID_PREFIX: &str = "hook:";

/// The placeholder an injected value replaces in a template.
pub const VALUE_PLACEHOLDER: &str = "{}";

/// Whether this flow was produced by a hook's own command, and must therefore
/// not be hooked again.
pub fn is_hook_traffic(exec_id: Option<&str>) -> bool {
    exec_id.is_some_and(|id| id.starts_with(HOOK_EXEC_ID_PREFIX))
}

/// The dimensions a [`HookScope`] filters on for one message.
#[derive(Debug, Clone, Copy)]
pub struct MatchCtx<'a> {
    /// Request host / `:authority`.
    pub host: &'a str,
    /// Request method.
    pub method: &'a str,
    /// Request target (path + query).
    pub path: &'a str,
    /// Response status — `None` on the request side.
    pub status: Option<u16>,
}

/// What applying a phase's hooks did to the message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HookOutcome {
    /// Whether any hook actually modified the message.
    pub changed: bool,
    /// Whether a hook refused the message (the caller answers `403`).
    pub dropped: bool,
}

/// Runs a hook's command and returns its stdout.
///
/// The engine deliberately knows nothing about HOW (the sandbox, the session,
/// the timeout plumbing): the proxy crate cannot reach the CLI's exec layer, and
/// keeping the boundary here is what makes the engine unit-testable without
/// standing up a namespace. The daemon installs the real implementation with
/// [`HookEngine::set_runner`].
#[async_trait]
pub trait HookRunner: Send + Sync {
    /// Run `cmd` (as a shell command) under `budget` and return its captured
    /// stdout. The engine also enforces `budget` around this call, but the
    /// implementation gets it too so it can KILL the process rather than leave
    /// an orphan running past a cancelled future.
    async fn run(&self, cmd: &str, budget: Duration) -> anyhow::Result<String>;
}

/// A cached value extracted from a hook's command output.
struct CachedValue {
    value: String,
    expires_at: Instant,
}

struct Inner {
    /// The current snapshot, in application order.
    hooks: RwLock<Arc<Vec<Hook>>>,
    /// `true` when at least one ENABLED hook exists for that phase. The whole
    /// hot path is gated on these, so an unconfigured proxy pays one atomic load.
    any_pre: AtomicBool,
    any_post: AtomicBool,
    /// The command runner, installed by the daemon. Absent = `exec` hooks are
    /// skipped (fail-open), which is what the CLI-side `hook test` and the unit
    /// tests rely on.
    runner: RwLock<Option<Arc<dyn HookRunner>>>,
    /// Extracted values, per hook id, with their TTL deadline.
    cache: Mutex<HashMap<i64, CachedValue>>,
    /// Whether a hook command is running right now. Claimed with a
    /// compare-and-swap, so "at most one" is an invariant and not a race.
    running: AtomicBool,
}

/// The proxy-side hook engine. Clone-cheap (internally `Arc`-shared); one
/// instance per daemon, shared by every connection, so a hook added mid-session
/// reaches connections that are already open.
#[derive(Clone)]
pub struct HookEngine {
    inner: Arc<Inner>,
}

impl Default for HookEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HookEngine {
    /// An engine with no hooks and no runner: every entry point is a no-op.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                hooks: RwLock::new(Arc::new(Vec::new())),
                any_pre: AtomicBool::new(false),
                any_post: AtomicBool::new(false),
                runner: RwLock::new(None),
                cache: Mutex::new(HashMap::new()),
                running: AtomicBool::new(false),
            }),
        }
    }

    /// Replace the hook snapshot. Values cached for hooks that are gone (or
    /// whose definition changed) are dropped, so editing a hook never leaves a
    /// stale token being injected by the new one.
    pub fn set_hooks(&self, hooks: Vec<Hook>) {
        let any_pre = hooks
            .iter()
            .any(|h| h.enabled && h.phase == HookPhase::PreRequest);
        let any_post = hooks
            .iter()
            .any(|h| h.enabled && h.phase == HookPhase::PostResponse);
        let ids: Vec<i64> = hooks.iter().map(|h| h.id).collect();
        {
            let mut cache = self.inner.cache.lock();
            cache.retain(|id, _| ids.contains(id));
        }
        *self.inner.hooks.write() = Arc::new(hooks);
        self.inner.any_pre.store(any_pre, Ordering::Relaxed);
        self.inner.any_post.store(any_post, Ordering::Relaxed);
    }

    /// Install the command runner used by [`HookAction::Exec`].
    pub fn set_runner(&self, runner: Arc<dyn HookRunner>) {
        *self.inner.runner.write() = Some(runner);
    }

    /// The current snapshot (for `hook test`, listings and the replay/fuzz paths
    /// that apply the declarative subset out of band).
    pub fn snapshot(&self) -> Arc<Vec<Hook>> {
        self.inner.hooks.read().clone()
    }

    /// Whether ANY enabled hook exists, either phase. One relaxed atomic load.
    pub fn any(&self) -> bool {
        self.inner.any_pre.load(Ordering::Relaxed) || self.inner.any_post.load(Ordering::Relaxed)
    }

    /// Whether an enabled `post-response` hook could fire for this message.
    ///
    /// The proxy asks before deciding to STREAM a response body straight
    /// through: a streamed body is never buffered, so nothing could rewrite it.
    /// Answering `true` here is what makes a response hook work on SSE/chunked
    /// bodies instead of silently never running.
    pub fn has_post_response_for(&self, m: &MatchCtx) -> bool {
        if !self.inner.any_post.load(Ordering::Relaxed) {
            return false;
        }
        self.inner
            .hooks
            .read()
            .iter()
            .any(|h| h.enabled && h.phase == HookPhase::PostResponse && scope_matches(&h.scope, m))
    }

    /// Apply the `pre-request` hooks to a request message in place.
    ///
    /// `exec_id` is the connection's exec correlation id: hook-originated
    /// traffic ([`is_hook_traffic`]) returns immediately, which is the primary
    /// recursion guard.
    pub async fn pre_request(
        &self,
        exec_id: Option<&str>,
        method: &str,
        msg: &mut Message,
    ) -> HookOutcome {
        if !self.inner.any_pre.load(Ordering::Relaxed) {
            return HookOutcome::default();
        }
        // The scope is read from the message while the message is being
        // mutated, so the two dimensions a hook can itself rewrite are snapshot
        // first: every hook of a phase sees the SAME host/path, and hook N+1
        // cannot be steered into (or out of) scope by hook N.
        let (host, path) = (msg.host.clone(), msg.url.clone());
        let m = MatchCtx {
            host: &host,
            method,
            path: &path,
            status: None,
        };
        self.apply(HookPhase::PreRequest, exec_id, m, msg).await
    }

    /// Apply the `post-response` hooks to a response message in place. `msg`
    /// carries the REQUEST host/url (so scoping works) and the RESPONSE
    /// headers/body, exactly like the response-side match/replace call.
    pub async fn post_response(
        &self,
        exec_id: Option<&str>,
        method: &str,
        status: u16,
        msg: &mut Message,
    ) -> HookOutcome {
        if !self.inner.any_post.load(Ordering::Relaxed) {
            return HookOutcome::default();
        }
        let (host, path) = (msg.host.clone(), msg.url.clone());
        let m = MatchCtx {
            host: &host,
            method,
            path: &path,
            status: Some(status),
        };
        self.apply(HookPhase::PostResponse, exec_id, m, msg).await
    }

    async fn apply(
        &self,
        phase: HookPhase,
        exec_id: Option<&str>,
        m: MatchCtx<'_>,
        msg: &mut Message,
    ) -> HookOutcome {
        // Guard 1: this flow IS a hook's own command talking. Never hook it.
        if is_hook_traffic(exec_id) {
            return HookOutcome::default();
        }
        let hooks = self.snapshot();
        let mut out = HookOutcome::default();
        for hook in hooks.iter() {
            if !hook.enabled || hook.phase != phase || !scope_matches(&hook.scope, &m) {
                continue;
            }
            match &hook.action {
                HookAction::Exec {
                    cmd,
                    extract,
                    inject,
                } => {
                    let Some(value) = self.exec_value(hook, cmd, extract).await else {
                        continue; // fail open: already logged
                    };
                    out.changed |= apply_inject(inject, &value, msg);
                }
                declarative => {
                    let (changed, dropped) = apply_declarative_action(declarative, msg);
                    out.changed |= changed;
                    if dropped {
                        out.dropped = true;
                        return out;
                    }
                }
            }
        }
        out
    }

    /// The value for an `exec` hook: cached, single-flighted, timeout-bounded,
    /// fail-open. `None` means "leave the message alone".
    async fn exec_value(&self, hook: &Hook, cmd: &str, extract: &str) -> Option<String> {
        let budget = Duration::from_millis(hook.timeout_ms.max(0) as u64);
        // The whole acquisition — waiting on another task's run included — is
        // under ONE budget, so a hook can never hold a request longer than its
        // own timeout (which the operator sized against the client's patience).
        match tokio::time::timeout(budget, self.exec_value_inner(hook, cmd, extract, budget)).await
        {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    hook = hook.id,
                    name = %hook.name,
                    timeout_ms = hook.timeout_ms,
                    "hook exec timed out; forwarding un-hooked (fail open)"
                );
                None
            }
        }
    }

    async fn exec_value_inner(
        &self,
        hook: &Hook,
        cmd: &str,
        extract: &str,
        budget: Duration,
    ) -> Option<String> {
        if let Some(v) = self.cached(hook.id) {
            return Some(v);
        }
        // Guard 2 + single flight, in one claim: exactly one hook command runs
        // at a time. Losing the claim means forwarding un-hooked RIGHT NOW —
        // never waiting for the winner, because a request that waits may well be
        // the winner's own traffic (a missing marker), and then both are stuck
        // until the timeout.
        let Some(_running) = RunGuard::claim(&self.inner) else {
            tracing::warn!(
                hook = hook.id,
                name = %hook.name,
                "another hook command is already running; forwarding un-hooked \
                 (single-flight / recursion backstop)"
            );
            return None;
        };
        let runner = self.inner.runner.read().clone();
        let Some(runner) = runner else {
            tracing::warn!(
                hook = hook.id,
                "no hook command runner installed; forwarding un-hooked"
            );
            return None;
        };

        let stdout = match runner.run(cmd, budget).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    hook = hook.id,
                    name = %hook.name,
                    error = %e,
                    "hook command failed; forwarding un-hooked (fail open)"
                );
                return None;
            }
        };
        let value = match extract_value(extract, &stdout) {
            Some(v) => v,
            None => {
                tracing::warn!(
                    hook = hook.id,
                    name = %hook.name,
                    "hook extract regex did not match the command output; \
                     forwarding un-hooked (fail open)"
                );
                return None;
            }
        };
        if hook.ttl_ms > 0 {
            self.inner.cache.lock().insert(
                hook.id,
                CachedValue {
                    value: value.clone(),
                    expires_at: Instant::now() + Duration::from_millis(hook.ttl_ms as u64),
                },
            );
        }
        Some(value)
    }

    fn cached(&self, id: i64) -> Option<String> {
        let mut cache = self.inner.cache.lock();
        match cache.get(&id) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.value.clone()),
            Some(_) => {
                cache.remove(&id);
                None
            }
            None => None,
        }
    }
}

/// The exclusive right to run a hook command, released on drop — including when
/// the future is CANCELLED by the hook timeout, which is why this is a guard and
/// not a flag cleared at the end of the happy path.
struct RunGuard(Arc<Inner>);

impl RunGuard {
    /// Take the right, or `None` if another command holds it.
    fn claim(inner: &Arc<Inner>) -> Option<Self> {
        inner
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self(inner.clone()))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::SeqCst);
    }
}

/// Apply every DECLARATIVE hook of `phase` that matches, ignoring `exec` hooks.
///
/// This is the subset the out-of-band request paths — `req replay` (Repeater)
/// and `fuzz` (Intruder) — can run: they are not the proxy, they have no
/// sandbox, and an operator firing 500 fuzz requests must not fire 500 commands.
/// A stale `Authorization` on a replay is exactly what hooks exist to fix, so
/// the declarative half runs there too rather than not at all.
pub fn apply_declarative(
    hooks: &[Hook],
    phase: HookPhase,
    m: &MatchCtx,
    msg: &mut Message,
) -> HookOutcome {
    let mut out = HookOutcome::default();
    for hook in hooks {
        if !hook.enabled
            || hook.phase != phase
            || !hook.action.is_declarative()
            || !scope_matches(&hook.scope, m)
        {
            continue;
        }
        let (changed, dropped) = apply_declarative_action(&hook.action, msg);
        out.changed |= changed;
        if dropped {
            out.dropped = true;
            return out;
        }
    }
    out
}

/// Render `(name, value)` pairs as the raw `Name: value\r\n…` block the hook
/// edits operate on. The out-of-band request paths (replay, fuzz) carry their
/// headers as pairs; this and [`pairs_from_block`] are the adapters, so they can
/// run the very same edits the proxy runs instead of a lookalike.
pub fn block_from_pairs(pairs: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in pairs {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out
}

/// Parse a raw header block back into ordered `(name, value)` pairs. Lines
/// without a colon are dropped (nothing here produces one).
pub fn pairs_from_block(block: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(block)
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim_start().to_string()))
        .collect()
}

/// Whether every non-empty dimension of `scope` matches. Host and path are
/// case-insensitive substrings (a leading `*.` on the host is stripped, as in
/// match/replace scopes), the method is an exact case-insensitive match, and the
/// status must be equal — so a status-scoped hook can never match a request.
pub fn scope_matches(scope: &HookScope, m: &MatchCtx) -> bool {
    if !scope.host.trim().is_empty() && !crate::matchreplace::host_in_scope(&scope.host, m.host) {
        return false;
    }
    if !scope.method.trim().is_empty() && !m.method.eq_ignore_ascii_case(scope.method.trim()) {
        return false;
    }
    if !scope.path.is_empty()
        && !m
            .path
            .to_ascii_lowercase()
            .contains(&scope.path.to_ascii_lowercase())
    {
        return false;
    }
    match (scope.status, m.status) {
        (None, _) => true,
        (Some(want), Some(got)) => want == got,
        (Some(_), None) => false,
    }
}

/// Apply one declarative action, returning `(changed, dropped)`.
fn apply_declarative_action(action: &HookAction, msg: &mut Message) -> (bool, bool) {
    match action {
        HookAction::AddHeader { name, value } => (add_header(&mut msg.headers, name, value), false),
        HookAction::SetHeader { name, value } => (set_header(&mut msg.headers, name, value), false),
        HookAction::RemoveHeader { name } => (remove_header(&mut msg.headers, name), false),
        HookAction::SetQueryParam { name, value } => {
            (set_query_param(&mut msg.url, name, value), false)
        }
        HookAction::Drop => (false, true),
        // An `exec` hook has no declarative form; callers that cannot run
        // commands skip it (see `apply_declarative`).
        HookAction::Exec { .. } => (false, false),
    }
}

/// Substitute `{}` in the template and apply the injection. Public so the CLI's
/// `hook test` can drive one hook end to end (run the command, show the value it
/// extracted, inject it) through exactly the code the proxy uses.
pub fn apply_inject(inject: &HookInject, value: &str, msg: &mut Message) -> bool {
    let concrete = inject.value_template.replace(VALUE_PLACEHOLDER, value);
    match inject.kind {
        HookInjectKind::AddHeader => add_header(&mut msg.headers, &inject.name, &concrete),
        HookInjectKind::SetHeader => set_header(&mut msg.headers, &inject.name, &concrete),
        HookInjectKind::SetQueryParam => set_query_param(&mut msg.url, &inject.name, &concrete),
    }
}

/// Pull the first capture group out of `output`. A regex that does not compile,
/// does not match, or has no capture group yields `None` (the caller fails open
/// and logs) — never a panic, never a partial value. Public for `hook test`.
pub fn extract_value(pattern: &str, output: &str) -> Option<String> {
    let re = Regex::new(pattern).ok()?;
    let caps = re.captures(output)?;
    caps.get(1).map(|g| g.as_str().to_string())
}

// --- raw header-block primitives -------------------------------------------
//
// The header block is the order-preserving `Name: Value\r\n…` byte blob the rest
// of the proxy passes around. These edits keep it in exactly that shape:
// `http::headers_from_bytes` falls back to the ORIGINAL header map on the first
// malformed line, which would silently discard every mutation, so a value that
// could break the framing is refused here rather than written.

/// Whether a name/value could break out of its header line.
fn unsafe_header_text(s: &str) -> bool {
    s.contains('\r') || s.contains('\n') || s.contains('\0')
}

/// Whether the block already carries a header by this name (case-insensitive).
fn has_header(block: &[u8], name: &str) -> bool {
    String::from_utf8_lossy(block)
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .any(|(n, _)| n.trim().eq_ignore_ascii_case(name))
}

/// Append `Name: value\r\n`, normalizing a block that does not end on a line
/// break (nothing in the proxy produces one, but a rewritten block might).
fn push_header(block: &mut Vec<u8>, name: &str, value: &str) {
    if !block.is_empty() && !block.ends_with(b"\r\n") {
        block.extend_from_slice(b"\r\n");
    }
    block.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
}

/// Add the header only if absent. THE gap in match/replace: a rule can rewrite a
/// `User-Agent` that is there, but cannot put one on a request that never sent
/// one.
fn add_header(block: &mut Vec<u8>, name: &str, value: &str) -> bool {
    if unsafe_header_text(name) || unsafe_header_text(value) {
        tracing::warn!(%name, "hook header contains CR/LF/NUL; skipping the edit");
        return false;
    }
    if has_header(block, name) {
        return false;
    }
    push_header(block, name, value);
    true
}

/// Add-or-replace: drop every existing line with that name, then append.
fn set_header(block: &mut Vec<u8>, name: &str, value: &str) -> bool {
    if unsafe_header_text(name) || unsafe_header_text(value) {
        tracing::warn!(%name, "hook header contains CR/LF/NUL; skipping the edit");
        return false;
    }
    remove_header(block, name);
    push_header(block, name, value);
    true
}

/// Remove every header line with that name. Returns whether anything went.
fn remove_header(block: &mut Vec<u8>, name: &str) -> bool {
    let text = String::from_utf8_lossy(block).into_owned();
    let mut out = String::with_capacity(text.len());
    let mut removed = false;
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let is_target = line
            .split_once(':')
            .map(|(n, _)| n.trim().eq_ignore_ascii_case(name))
            .unwrap_or(false);
        if is_target {
            removed = true;
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if removed {
        *block = out.into_bytes();
    }
    removed
}

/// Set (or add) a query parameter on a request target, preserving the rest of
/// the query string and any fragment.
fn set_query_param(url: &mut String, name: &str, value: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let (path_and_query, fragment) = match url.split_once('#') {
        Some((pq, f)) => (pq.to_string(), Some(f.to_string())),
        None => (url.clone(), None),
    };
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_and_query, String::new()),
    };
    let encoded = format!("{}={}", percent_encode(name), percent_encode(value));
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let key = pair.split('=').next().unwrap_or(pair);
        if percent_decode_key_eq(key, name) {
            if !replaced {
                parts.push(encoded.clone());
                replaced = true;
            }
            continue;
        }
        parts.push(pair.to_string());
    }
    if !replaced {
        parts.push(encoded);
    }
    let mut out = path;
    if !parts.is_empty() {
        out.push('?');
        out.push_str(&parts.join("&"));
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(&f);
    }
    let changed = *url != out;
    *url = out;
    changed
}

/// Compare an existing (possibly percent-encoded) query key with a plain name.
fn percent_decode_key_eq(encoded_key: &str, name: &str) -> bool {
    encoded_key == name || encoded_key == percent_encode(name)
}

/// Minimal percent-encoding for a query component: everything outside the
/// unreserved set (RFC 3986) is escaped, so a value can never introduce a `&`,
/// a `=` or whitespace into the target.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn msg() -> Message {
        Message {
            host: "api.example.com".into(),
            url: "/v1/users?id=5".into(),
            headers: b"host: api.example.com\r\naccept: */*\r\n".to_vec(),
            body: Vec::new(),
        }
    }

    fn ctx<'a>(m: &'a Message, method: &'a str) -> MatchCtx<'a> {
        MatchCtx {
            host: &m.host,
            method,
            path: &m.url,
            status: None,
        }
    }

    fn hook(id: i64, phase: HookPhase, action: HookAction) -> Hook {
        Hook {
            id,
            enabled: true,
            name: format!("hook{id}"),
            phase,
            scope: HookScope::default(),
            action,
            order: id,
            timeout_ms: 1_000,
            ttl_ms: 0,
            created_at: 0,
        }
    }

    fn add_ua() -> HookAction {
        HookAction::AddHeader {
            name: "User-Agent".into(),
            value: "burpwn/1".into(),
        }
    }

    /// A counting runner: how many times a command was actually executed is the
    /// whole point of the recursion and single-flight tests.
    struct CountingRunner {
        calls: Arc<AtomicUsize>,
        output: String,
        delay: Duration,
    }

    #[async_trait]
    impl HookRunner for CountingRunner {
        async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(self.output.clone())
        }
    }

    fn token_hook(id: i64, ttl_ms: i64) -> Hook {
        let mut h = hook(
            id,
            HookPhase::PreRequest,
            HookAction::Exec {
                cmd: "mint-token".into(),
                extract: r#""token":"([^"]+)""#.into(),
                inject: HookInject {
                    kind: HookInjectKind::SetHeader,
                    name: "Authorization".into(),
                    value_template: "Bearer {}".into(),
                },
            },
        );
        h.ttl_ms = ttl_ms;
        h
    }

    // --- the hot path ------------------------------------------------------

    #[tokio::test]
    async fn an_empty_engine_touches_nothing() {
        let engine = HookEngine::new();
        assert!(!engine.any());
        let mut m = msg();
        let before = m.clone();
        assert_eq!(
            engine.pre_request(None, "GET", &mut m).await,
            HookOutcome::default()
        );
        assert_eq!(
            engine.post_response(None, "GET", 200, &mut m).await,
            HookOutcome::default()
        );
        assert_eq!(m, before);
        assert!(!engine.has_post_response_for(&ctx(&before, "GET")));
    }

    #[tokio::test]
    async fn add_header_synthesizes_a_header_that_is_not_there() {
        let engine = HookEngine::new();
        engine.set_hooks(vec![hook(1, HookPhase::PreRequest, add_ua())]);
        let mut m = msg();
        let out = engine.pre_request(None, "GET", &mut m).await;
        assert!(out.changed && !out.dropped);
        let headers = String::from_utf8(m.headers.clone()).unwrap();
        assert!(headers.ends_with("User-Agent: burpwn/1\r\n"), "{headers}");
        // The rest of the block is untouched and still parses line by line.
        assert!(headers.starts_with("host: api.example.com\r\n"));

        // Idempotent: a second pass sees the header and leaves it alone (that is
        // what makes it "add", not "append forever" on a keep-alive connection).
        let out = engine.pre_request(None, "GET", &mut m).await;
        assert!(!out.changed);
        assert_eq!(headers.matches("User-Agent").count(), 1);
    }

    #[tokio::test]
    async fn set_remove_and_query_param_actions() {
        let engine = HookEngine::new();
        engine.set_hooks(vec![
            hook(
                1,
                HookPhase::PreRequest,
                HookAction::SetHeader {
                    name: "Accept".into(),
                    value: "application/json".into(),
                },
            ),
            hook(
                2,
                HookPhase::PreRequest,
                HookAction::RemoveHeader {
                    name: "host".into(),
                },
            ),
            hook(
                3,
                HookPhase::PreRequest,
                HookAction::SetQueryParam {
                    name: "id".into(),
                    value: "1 &2".into(),
                },
            ),
        ]);
        let mut m = msg();
        assert!(engine.pre_request(None, "GET", &mut m).await.changed);
        let headers = String::from_utf8(m.headers).unwrap();
        assert!(!headers.contains("host:"), "{headers}");
        assert_eq!(headers.matches("Accept").count(), 1, "{headers}");
        assert!(headers.contains("Accept: application/json"), "{headers}");
        // The existing `id=5` is REPLACED (not duplicated) and percent-encoded.
        assert_eq!(m.url, "/v1/users?id=1%20%262");
    }

    #[tokio::test]
    async fn hooks_apply_in_order_and_a_disabled_hook_is_a_no_op() {
        let engine = HookEngine::new();
        let mut first = hook(
            1,
            HookPhase::PreRequest,
            HookAction::SetHeader {
                name: "X-Stage".into(),
                value: "one".into(),
            },
        );
        first.order = 1;
        let mut second = hook(
            2,
            HookPhase::PreRequest,
            HookAction::SetHeader {
                name: "X-Stage".into(),
                value: "two".into(),
            },
        );
        second.order = 2;
        let mut disabled = hook(
            3,
            HookPhase::PreRequest,
            HookAction::SetHeader {
                name: "X-Stage".into(),
                value: "three".into(),
            },
        );
        disabled.order = 3;
        disabled.enabled = false;
        // Deliberately handed over out of order: the engine applies the snapshot
        // as given, and the store hands it over sorted by `ord`.
        engine.set_hooks(vec![first, second, disabled]);

        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        let headers = String::from_utf8(m.headers).unwrap();
        assert!(headers.contains("X-Stage: two"), "{headers}");
        assert!(!headers.contains("three"), "disabled hook ran: {headers}");
        assert_eq!(headers.matches("X-Stage").count(), 1);
    }

    #[tokio::test]
    async fn scope_filters_on_host_method_path_and_status() {
        let engine = HookEngine::new();
        let mut h = hook(1, HookPhase::PreRequest, add_ua());
        h.scope = HookScope {
            host: "*.example.com".into(),
            method: "post".into(),
            path: "/v1/".into(),
            status: None,
        };
        engine.set_hooks(vec![h]);

        // Wrong method.
        let mut m = msg();
        assert!(!engine.pre_request(None, "GET", &mut m).await.changed);
        // Right method, right host, right path prefix.
        let mut m = msg();
        assert!(engine.pre_request(None, "POST", &mut m).await.changed);
        // Wrong host.
        let mut m = msg();
        m.host = "other.test".into();
        assert!(!engine.pre_request(None, "POST", &mut m).await.changed);
        // Wrong path.
        let mut m = msg();
        m.url = "/v2/users".into();
        assert!(!engine.pre_request(None, "POST", &mut m).await.changed);

        // A status-scoped response hook only fires on that status.
        let engine = HookEngine::new();
        let mut h = hook(
            1,
            HookPhase::PostResponse,
            HookAction::SetHeader {
                name: "X-Flag".into(),
                value: "seen".into(),
            },
        );
        h.scope.status = Some(500);
        engine.set_hooks(vec![h]);
        let mut m = msg();
        assert!(!engine.post_response(None, "GET", 200, &mut m).await.changed);
        assert!(engine.post_response(None, "GET", 500, &mut m).await.changed);
        // …and `should_stream` can see it coming, per status.
        assert!(engine.has_post_response_for(&MatchCtx {
            host: "api.example.com",
            method: "GET",
            path: "/v1/users",
            status: Some(500),
        }));
        assert!(!engine.has_post_response_for(&MatchCtx {
            host: "api.example.com",
            method: "GET",
            path: "/v1/users",
            status: Some(200),
        }));
    }

    #[tokio::test]
    async fn drop_stops_the_message_and_later_hooks() {
        let engine = HookEngine::new();
        engine.set_hooks(vec![
            hook(1, HookPhase::PreRequest, HookAction::Drop),
            hook(2, HookPhase::PreRequest, add_ua()),
        ]);
        let mut m = msg();
        let out = engine.pre_request(None, "GET", &mut m).await;
        assert!(out.dropped);
        assert!(
            !String::from_utf8_lossy(&m.headers).contains("User-Agent"),
            "hooks after a drop must not run"
        );
    }

    // --- exec: timeout, cache, single flight, recursion ---------------------

    #[tokio::test]
    async fn exec_injects_the_extracted_value() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"abc123"}"#.into(),
            delay: Duration::ZERO,
        }));
        engine.set_hooks(vec![token_hook(1, 0)]);

        let mut m = msg();
        assert!(engine.pre_request(None, "GET", &mut m).await.changed);
        let headers = String::from_utf8(m.headers).unwrap();
        assert!(
            headers.contains("Authorization: Bearer abc123"),
            "{headers}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A hook that hangs must cost the request its timeout and NOTHING else: the
    /// traffic still goes through, unmodified.
    #[tokio::test]
    async fn a_hanging_exec_hook_times_out_and_fails_open() {
        struct Hang;
        #[async_trait]
        impl HookRunner for Hang {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
        let engine = HookEngine::new();
        engine.set_runner(Arc::new(Hang));
        let mut h = token_hook(1, 0);
        h.timeout_ms = 40;
        engine.set_hooks(vec![h]);

        let mut m = msg();
        let started = Instant::now();
        let out = engine.pre_request(None, "GET", &mut m).await;
        assert!(!out.changed && !out.dropped, "fail OPEN, never drop");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!String::from_utf8_lossy(&m.headers).contains("Authorization"));

        // A command that ERRORS fails open the same way.
        struct Boom;
        #[async_trait]
        impl HookRunner for Boom {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("no such command"))
            }
        }
        engine.set_runner(Arc::new(Boom));
        let mut m = msg();
        assert!(!engine.pre_request(None, "GET", &mut m).await.changed);
    }

    #[tokio::test]
    async fn the_ttl_cache_reuses_a_value_and_expires_it() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"t1"}"#.into(),
            delay: Duration::ZERO,
        }));
        engine.set_hooks(vec![token_hook(1, 60)]);

        for _ in 0..3 {
            let mut m = msg();
            assert!(engine.pre_request(None, "GET", &mut m).await.changed);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "cached within the TTL");

        tokio::time::sleep(Duration::from_millis(80)).await;
        let mut m = msg();
        assert!(engine.pre_request(None, "GET", &mut m).await.changed);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "re-minted after the TTL");
    }

    /// Eight requests hitting a cold cache at once must mint ONE token, not
    /// eight sandboxes. The ones that lose the race are forwarded un-hooked
    /// (never parked behind the winner — see the module docs), and once the
    /// value is cached every later request gets it without running anything.
    #[tokio::test]
    async fn concurrent_cache_misses_run_the_command_once_single_flight() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"shared"}"#.into(),
            delay: Duration::from_millis(30),
        }));
        engine.set_hooks(vec![token_hook(1, 10_000)]);

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let e = engine.clone();
            tasks.push(tokio::spawn(async move {
                let mut m = msg();
                let out = e.pre_request(None, "GET", &mut m).await;
                assert!(!out.dropped, "a busy hook never drops traffic");
                out.changed
            }));
        }
        let injected = {
            let mut n = 0;
            for t in tasks {
                if t.await.unwrap() {
                    n += 1;
                }
            }
            n
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly ONE sandbox");
        assert!(injected >= 1, "the winner must still be hooked");

        // The value is now cached: no further command, and the header lands.
        let mut m = msg();
        assert!(engine.pre_request(None, "GET", &mut m).await.changed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(String::from_utf8_lossy(&m.headers).contains("Bearer shared"));
    }

    /// GUARD 1. A hook's command runs in the sandbox, so its traffic comes back
    /// through the proxy carrying the `hook:` exec id. That traffic must bypass
    /// every hook — proven here by having the runner itself re-enter the engine
    /// exactly as the proxy would for its own request.
    #[tokio::test]
    async fn hook_originated_traffic_never_re_enters_the_hooks() {
        struct ReEnter {
            engine: Mutex<Option<HookEngine>>,
            calls: Arc<AtomicUsize>,
            inner_changed: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl HookRunner for ReEnter {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let engine = self.engine.lock().clone().unwrap();
                // The command's OWN request, as the proxy would present it:
                // stamped with the hook exec-id marker.
                let mut m = msg();
                let out = engine.pre_request(Some("hook:abc123"), "GET", &mut m).await;
                if out.changed {
                    self.inner_changed.fetch_add(1, Ordering::SeqCst);
                }
                Ok(r#"{"token":"deep"}"#.to_string())
            }
        }

        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let inner_changed = Arc::new(AtomicUsize::new(0));
        let runner = Arc::new(ReEnter {
            engine: Mutex::new(Some(engine.clone())),
            calls: calls.clone(),
            inner_changed: inner_changed.clone(),
        });
        engine.set_runner(runner);
        // Two hooks, so the marker has to suppress the DECLARATIVE one too.
        engine.set_hooks(vec![
            token_hook(1, 0),
            hook(2, HookPhase::PreRequest, add_ua()),
        ]);

        let mut m = msg();
        let out = engine.pre_request(None, "GET", &mut m).await;
        assert!(out.changed);
        assert!(String::from_utf8_lossy(&m.headers).contains("Bearer deep"));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one command run");
        assert_eq!(
            inner_changed.load(Ordering::SeqCst),
            0,
            "the command's own request must come out completely un-hooked"
        );
    }

    /// GUARD 2. Same setup, but the marker is MISSING (a front-end that lost the
    /// exec id, another burpwn in the path). The one-command invariant must
    /// refuse the nested run outright: no chain of sandboxes, and — the part
    /// that matters — no stall either, because the nested request is answered
    /// immediately instead of waiting for the command it is itself blocking.
    #[tokio::test]
    async fn a_missing_marker_is_caught_by_the_one_command_backstop() {
        struct ReEnter {
            engine: Mutex<Option<HookEngine>>,
            calls: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl HookRunner for ReEnter {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let engine = self.engine.lock().clone().unwrap();
                let mut m = msg();
                // NO marker: this is the case the backstop exists for.
                let out = engine.pre_request(None, "GET", &mut m).await;
                assert!(!out.changed, "the nested request must not be hooked");
                Ok(r#"{"token":"outer"}"#.to_string())
            }
        }

        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(ReEnter {
            engine: Mutex::new(Some(engine.clone())),
            calls: calls.clone(),
        }));
        // A SECOND hook id, so the nested call cannot simply be absorbed by the
        // single-flight of the first one: it genuinely wants its own command.
        engine.set_hooks(vec![token_hook(1, 0), token_hook(2, 0)]);

        let mut m = msg();
        let started = Instant::now();
        let out = engine.pre_request(None, "GET", &mut m).await;
        assert!(out.changed, "the OUTER request still gets its token");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the backstop must answer the nested request at once, not stall it \
             until the hook timeout"
        );
        // Hook 1 ran, then hook 2 ran (the claim is released between them), but
        // neither NESTED request was allowed to start a command of its own —
        // that would be 4 runs, not 2.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a nested run was allowed to start"
        );
    }

    #[tokio::test]
    async fn changing_the_snapshot_drops_the_cached_value_of_a_removed_hook() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"t"}"#.into(),
            delay: Duration::ZERO,
        }));
        engine.set_hooks(vec![token_hook(1, 60_000)]);
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // The hook is deleted and re-created under a new id: the old cached
        // token must not be reused for it.
        engine.set_hooks(vec![token_hook(2, 60_000)]);
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // --- the declarative subset used by replay / fuzz ------------------------

    #[test]
    fn apply_declarative_skips_exec_hooks() {
        let hooks = vec![
            hook(1, HookPhase::PreRequest, add_ua()),
            token_hook(2, 0),
            hook(3, HookPhase::PostResponse, HookAction::Drop),
        ];
        let mut m = msg();
        let ctx = MatchCtx {
            host: "api.example.com",
            method: "GET",
            path: "/v1/users",
            status: None,
        };
        let out = apply_declarative(&hooks, HookPhase::PreRequest, &ctx, &mut m);
        assert!(out.changed && !out.dropped);
        let headers = String::from_utf8(m.headers).unwrap();
        assert!(headers.contains("User-Agent: burpwn/1"));
        assert!(
            !headers.contains("Authorization"),
            "an exec hook must never run off the proxy path: {headers}"
        );
    }

    // --- header/query primitives --------------------------------------------

    #[test]
    fn header_primitives_keep_the_block_parseable() {
        let mut block = b"host: a\r\nx-a: 1\r\n".to_vec();
        assert!(add_header(&mut block, "X-New", "v"));
        assert!(
            !add_header(&mut block, "x-new", "other"),
            "case-insensitive"
        );
        assert!(set_header(&mut block, "X-A", "2"));
        assert_eq!(
            String::from_utf8(block.clone()).unwrap(),
            "host: a\r\nX-New: v\r\nX-A: 2\r\n"
        );
        assert!(remove_header(&mut block, "HOST"));
        assert!(!remove_header(&mut block, "nope"));
        assert_eq!(
            String::from_utf8(block.clone()).unwrap(),
            "X-New: v\r\nX-A: 2\r\n"
        );

        // CRLF injection is refused, not written.
        assert!(!add_header(&mut block, "X-Evil", "a\r\nX-Admin: 1"));
        assert!(!set_header(&mut block, "X-E\nvil", "a"));
        assert!(!String::from_utf8_lossy(&block).contains("X-Admin"));

        // A block that lost its trailing CRLF is normalized rather than joined
        // onto the previous line.
        let mut ragged = b"host: a".to_vec();
        add_header(&mut ragged, "X-B", "1");
        assert_eq!(String::from_utf8(ragged).unwrap(), "host: a\r\nX-B: 1\r\n");
    }

    #[test]
    fn query_param_edits_preserve_the_rest_of_the_target() {
        let mut url = "/search?q=a&page=2".to_string();
        assert!(set_query_param(&mut url, "page", "3"));
        assert_eq!(url, "/search?q=a&page=3");
        assert!(set_query_param(&mut url, "debug", "1"));
        assert_eq!(url, "/search?q=a&page=3&debug=1");

        let mut url = "/search".to_string();
        assert!(set_query_param(&mut url, "q", "x y"));
        assert_eq!(url, "/search?q=x%20y");

        let mut url = "/p?a=1#frag".to_string();
        assert!(set_query_param(&mut url, "a", "2"));
        assert_eq!(url, "/p?a=2#frag");

        // Setting a parameter to the value it already has is not a change.
        let mut url = "/p?a=2".to_string();
        assert!(!set_query_param(&mut url, "a", "2"));
    }

    #[test]
    fn extract_value_needs_a_matching_capture_group() {
        assert_eq!(
            extract_value(r#""t":"([^"]+)""#, r#"{"t":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert_eq!(extract_value(r#""t":"[^"]+""#, r#"{"t":"abc"}"#), None);
        assert_eq!(extract_value("(unclosed", "abc"), None);
        assert_eq!(extract_value("nope", "abc"), None);
    }

    #[test]
    fn hook_traffic_is_recognised_by_its_exec_id() {
        assert!(is_hook_traffic(Some("hook:9f2c")));
        assert!(!is_hook_traffic(Some("9f2c")));
        assert!(!is_hook_traffic(None));
    }
}
