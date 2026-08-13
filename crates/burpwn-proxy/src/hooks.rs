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
//! # What is NOT hooked
//!
//! Hooks are an HTTP-message primitive: they act on a request before it is
//! forwarded and on a response before it is returned. Deliberately outside that:
//!
//! - **WebSocket frames** (`crate::ws`). After the `101` the proxy splices two
//!   byte streams; there is no request/response to act on, and a per-frame hook
//!   is a different feature with a different cost model. The `Upgrade` request
//!   ITSELF is a normal request and IS hooked — which is what matters for
//!   authenticating a socket.
//! - **Raw TCP** (`crate::rawtcp`) and **TLS passthrough** (`crate::passthrough`):
//!   nothing there is parsed, by design. There is no header to add.
//! - **DNS** (`crate::dns`): a different protocol entirely.
//! - `req replay` and `fuzz` run the DECLARATIVE subset only — see
//!   [`apply_declarative`].
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
//!    the whole proxy**. A request that would need to start a second one never
//!    spawns beside it: it either reads the running command's result or is
//!    forwarded un-hooked. A recursion therefore cannot amplify into N
//!    sandboxes; it degrades into a bounded stall and a logged, un-hooked
//!    request.
//!
//! That invariant doubles as the **single-flight** the TTL cache needs: a burst
//! of concurrent requests on a cold cache mints ONE value, not one per request.
//!
//! # Losing the claim: a BOUNDED wait, not a coin flip
//!
//! The requests that lose the claim used to be forwarded un-hooked on the spot,
//! which quietly defeated the feature exactly where it matters: on a cold TTL,
//! a burst of N concurrent calls saw ONE request get the fresh token and N-1
//! take a `401`. So a loser now waits for the winner and then re-reads the
//! cache — but only under conditions that make waiting both useful and safe:
//!
//! - **Only when the winner publishes something it can use.** The handoff
//!   happens through the TTL cache, so a hook with `ttl_ms == 0` (which caches
//!   nothing) and a command minting a *different* hook's value are both
//!   fail-open immediately, as before. Waiting there could only ever wake up to
//!   the same miss.
//! - **Only for [`MAX_SINGLE_FLIGHT_WAIT`], and never more than half the hook's
//!   own `timeout_ms`.** The waiter may BE the winner's own traffic — that is
//!   the missing-marker case, and the explicit front-end has no exec id to
//!   stamp — in which case the two block each other until the wait expires. An
//!   unbounded wait is a deadlock (a previous attempt at one was caught by the
//!   end-to-end test); a wait capped under the winner's own budget is a stall
//!   with a ceiling, after which the loser fails open and the winner still has
//!   half its timeout left to finish and cache.
//!
//! With the default `--timeout 10000` the ceiling is the full 5 s; with a
//! shorter timeout it is half of it. Either way it stays strictly under the
//! budget the operator gave the command, because a wait that can consume the
//! whole timeout bounds nothing useful.
//!
//! On top of both, every `exec` hook is bounded by its own `timeout_ms` and
//! FAILS OPEN on expiry or error: a broken hook never breaks traffic, it just
//! stops modifying it (and says so at `WARN`).
//!
//! # The `401` that arrives inside the TTL
//!
//! Minting on demand and caching for `--ttl` answers "the token expired between
//! two engagements" but not "the token expired mid-TTL": until the cache lapses,
//! every request keeps carrying a value the target has started refusing. So a
//! `401`/`403` on the response side drops the cached value of the `exec` hooks
//! in scope for that host ([`HookEngine::observe_status`]) and the NEXT request
//! re-mints on the spot. This is the whole of what the removed `AuthWatcher`
//! did, minus its machinery: no channel, no detached `session auth refresh`
//! child, and — since the marker already handles recursion structurally — no
//! debounce doing double duty as a recursion guard. What is left is a rate
//! question, answered by [`REMINT_COOLDOWN`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use tokio::sync::Notify;

use burpwn_store::model::{Hook, HookAction, HookInject, HookInjectKind, HookPhase, HookScope};

use crate::matchreplace::Message;

/// Prefix that marks an `exec_id` as belonging to a hook's own command. Traffic
/// stamped with it bypasses every hook (see the module docs).
pub const HOOK_EXEC_ID_PREFIX: &str = "hook:";

/// The placeholder an injected value replaces in a template.
pub const VALUE_PLACEHOLDER: &str = "{}";

/// Hard ceiling on how long a request may be parked on ANOTHER request's hook
/// command before it gives up and is forwarded un-hooked.
///
/// It exists because the request that waits might be the running command's own
/// traffic (the missing-marker case, see the module docs), and then the two
/// block each other. The effective wait is `min(this, timeout_ms / 2)`: it must
/// stay strictly under the winner's own budget, or the winner dies of its
/// timeout while being waited on and nobody gets a value. Five seconds is sized
/// on what it is waiting FOR — a token mint is a sandbox plus an HTTPS round
/// trip, hundreds of milliseconds — and on the default `--timeout 10000`, of
/// which it is exactly half.
pub const MAX_SINGLE_FLIGHT_WAIT: Duration = Duration::from_secs(5);

/// How young a cached value has to be for a `401`/`403` NOT to throw it away
/// (see [`HookEngine::observe_status`]).
///
/// It bounds the cost of a target that refuses everything: one command per hook
/// per this interval, not one per request. Thirty seconds is well above a login
/// round trip (so a value that has just been minted and is already being refused
/// is not re-minted on every following request) and far below any TTL an
/// operator would set on a token, so the case it exists for — a token that has
/// been working for a while and stops — is never delayed by it.
pub const REMINT_COOLDOWN: Duration = Duration::from_secs(30);

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
    minted_at: Instant,
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
    /// WHICH hook's command is running right now, if any. The claim is taken
    /// under this lock, so "at most one for the whole proxy" is an invariant
    /// and not a race — and a request that finds it taken can see whose value
    /// is being minted, which is what decides whether waiting could pay.
    running: Mutex<Option<i64>>,
    /// Signalled when a command releases the claim, so the requests parked on
    /// it wake on the value rather than on their timer.
    finished: Notify,
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
                running: Mutex::new(None),
                finished: Notify::new(),
            }),
        }
    }

    /// Replace the hook snapshot. Values cached for hooks that are gone — or
    /// whose definition CHANGED — are dropped, so editing a hook never leaves a
    /// stale token being injected by the new one.
    ///
    /// The comparison is on the whole hook, not on its id: a `session auth set`
    /// that replaces a profile deletes a row and inserts one, and SQLite hands
    /// the freed rowid straight back, so an id-only check would happily keep
    /// serving the token the PREVIOUS login command minted.
    pub fn set_hooks(&self, hooks: Vec<Hook>) {
        let any_pre = hooks
            .iter()
            .any(|h| h.enabled && h.phase == HookPhase::PreRequest);
        let any_post = hooks
            .iter()
            .any(|h| h.enabled && h.phase == HookPhase::PostResponse);
        {
            let previous = self.snapshot();
            let mut cache = self.inner.cache.lock();
            cache.retain(|id, _| {
                let before = previous.iter().find(|h| h.id == *id);
                let after = hooks.iter().find(|h| h.id == *id);
                match (before, after) {
                    (Some(b), Some(a)) => b == a,
                    // No previous entry to compare against (a cache written
                    // between two snapshots): keep it, its hook is still there.
                    (None, Some(_)) => true,
                    _ => false,
                }
            });
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
        // at a time. Losing the claim never spawns a second command — it waits
        // for the winner's value instead, briefly and only when that can work.
        let _running = match RunGuard::claim(&self.inner, hook.id) {
            Ok(guard) => guard,
            Err(holder) => return self.wait_for_running_command(hook, holder, budget).await,
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
            let now = Instant::now();
            self.inner.cache.lock().insert(
                hook.id,
                CachedValue {
                    value: value.clone(),
                    minted_at: now,
                    expires_at: now + Duration::from_millis(hook.ttl_ms as u64),
                },
            );
        }
        Some(value)
    }

    /// This request lost the one-command claim to `holder`. Park it on that
    /// command — bounded — and read the value it caches, or fail open.
    ///
    /// The whole point is the cold-TTL burst: N concurrent calls, one command,
    /// N hooked requests. Forwarding the losers un-hooked (what this used to do)
    /// hands them the `401` the hook exists to prevent.
    async fn wait_for_running_command(
        &self,
        hook: &Hook,
        holder: i64,
        budget: Duration,
    ) -> Option<String> {
        // Two cases where waiting is provably pointless, and therefore stays
        // immediate fail-open: nothing will be published for us to read.
        let pointless = if hook.ttl_ms <= 0 {
            Some("this hook caches nothing (ttl 0), so the running command publishes no value")
        } else if holder != hook.id {
            Some("the running command belongs to another hook, whose value this one cannot use")
        } else {
            None
        };
        let wait = single_flight_wait(budget);
        if let Some(reason) = pointless.or((wait.is_zero()).then_some("no time left to wait")) {
            tracing::warn!(
                hook = hook.id,
                name = %hook.name,
                running_hook = holder,
                reason,
                "another hook command is already running; forwarding un-hooked \
                 (single-flight / recursion backstop)"
            );
            return None;
        }

        let notified = self.inner.finished.notified();
        tokio::pin!(notified);
        // Register interest BEFORE the last cache read: a winner that finishes
        // in between then wakes us instead of leaving us on the timer.
        notified.as_mut().enable();
        if let Some(v) = self.cached(hook.id) {
            return Some(v);
        }
        let woken = tokio::time::timeout(wait, notified).await.is_ok();
        // The winner published through the cache, so that is where the answer
        // is — a loser never runs a command of its own.
        if let Some(v) = self.cached(hook.id) {
            return Some(v);
        }
        if woken {
            tracing::warn!(
                hook = hook.id,
                name = %hook.name,
                "the hook command that was already running cached no value \
                 (it failed, or its extract did not match); forwarding un-hooked"
            );
        } else {
            tracing::warn!(
                hook = hook.id,
                name = %hook.name,
                waited_ms = wait.as_millis(),
                "waited for the running hook command and it did not finish in time; \
                 forwarding un-hooked (fail open)"
            );
        }
        None
    }

    /// Drop the value cached for an `exec` hook because the target just refused
    /// a request that carried it.
    ///
    /// A token minted at `T` with `--ttl 5m` is served for five minutes whether
    /// or not it is still valid; a session the target revokes (or one that
    /// simply expires sooner than the TTL the operator guessed) turns into five
    /// minutes of `401`s that the hook is in a position to fix and does not.
    /// This is what makes the `401` fix it: the next in-scope request finds an
    /// empty cache and re-mints, SYNCHRONOUSLY, and goes out with the new token.
    ///
    /// This replaces the old `AuthWatcher`, which signalled a debounced host to
    /// the daemon so it could spawn a detached `session auth refresh`. The
    /// request that took the `401` was never the one that got the new token, and
    /// the debounce could not be a recursion guard against a login command that
    /// outlived it. Here, recursion is the marker's job ([`is_hook_traffic`],
    /// structural), concurrency is the one-command claim's, and this only has to
    /// answer "how often may a `401` cost a fresh mint".
    ///
    /// Its answer is [`REMINT_COOLDOWN`], and it is deliberately a property of
    /// the VALUE rather than a timer per host: a value younger than the cooldown
    /// is left alone, so a target that answers `401` to everything (a wrong
    /// extract regex, a revoked account) costs at most one command per hook per
    /// cooldown instead of one per request. A token that has been in use longer
    /// than that — the case this exists for — is dropped on the first `401`.
    ///
    /// Cheap when it does nothing: one relaxed atomic load before anything else,
    /// so a proxy with no hooks does not even look at the status.
    ///
    /// `m` is the REQUEST's own match context (host/method/path, `status: None`)
    /// — the one the pre-request phase matched on — so a hook narrowed to
    /// `--method POST` or a path prefix is invalidated by a refusal of the
    /// requests it actually injects into, and not by any other flow to that host.
    pub fn observe_status(&self, exec_id: Option<&str>, m: &MatchCtx, status: u16) {
        if status != 401 && status != 403 {
            return;
        }
        if !self.inner.any_pre.load(Ordering::Relaxed) {
            return;
        }
        // A hook command's own `401` says nothing about the token the client is
        // using — the login endpoint refusing the credentials is a different
        // failure, and letting it invalidate would make a broken login retry on
        // its own traffic.
        if is_hook_traffic(exec_id) {
            return;
        }
        let stale: Vec<i64> = self
            .snapshot()
            .iter()
            .filter(|h| {
                h.enabled
                    && h.phase == HookPhase::PreRequest
                    && !h.action.is_declarative()
                    && scope_matches(&h.scope, m)
            })
            .map(|h| h.id)
            .collect();
        if stale.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut cache = self.inner.cache.lock();
        for id in stale {
            let young = cache
                .get(&id)
                .is_some_and(|c| now.duration_since(c.minted_at) < REMINT_COOLDOWN);
            if young {
                continue;
            }
            if cache.remove(&id).is_some() {
                tracing::info!(
                    hook = id,
                    host = %m.host,
                    status,
                    "the target refused a request carrying this hook's value; \
                     dropping it so the next request re-mints"
                );
            }
        }
    }

    /// Drop cached values on request: `hook_ids` when non-empty, otherwise every
    /// one. Returns the ids that actually had a value.
    ///
    /// Unlike [`observe_status`](Self::observe_status) this ignores
    /// [`REMINT_COOLDOWN`]: an operator (or `session auth refresh`) asking for a
    /// fresh token is not a storm, and second-guessing an explicit request is
    /// how a command ends up appearing not to work.
    pub fn invalidate(&self, hook_ids: &[i64]) -> Vec<i64> {
        let mut cache = self.inner.cache.lock();
        let dropped: Vec<i64> = cache
            .keys()
            .copied()
            .filter(|id| hook_ids.is_empty() || hook_ids.contains(id))
            .collect();
        for id in &dropped {
            cache.remove(id);
        }
        dropped
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

/// How long a request may be parked on another request's hook command, given
/// that request's own budget.
///
/// Half the budget, capped at [`MAX_SINGLE_FLIGHT_WAIT`]. Halving is what keeps
/// the pathological case survivable: if the waiter turns out to be the winner's
/// own traffic, the winner is blocked for exactly this long and must still have
/// enough of its timeout left to run. A wait equal to the timeout would bound
/// the stall on paper and starve every winner in practice.
fn single_flight_wait(budget: Duration) -> Duration {
    MAX_SINGLE_FLIGHT_WAIT.min(budget / 2)
}

/// The exclusive right to run a hook command, released on drop — including when
/// the future is CANCELLED by the hook timeout, which is why this is a guard and
/// not a flag cleared at the end of the happy path.
struct RunGuard(Arc<Inner>);

impl RunGuard {
    /// Take the right for `hook_id`, or report WHICH hook already holds it (a
    /// loser needs to know: only the value it is itself waiting for is worth
    /// waiting for).
    fn claim(inner: &Arc<Inner>, hook_id: i64) -> Result<Self, i64> {
        let mut running = inner.running.lock();
        match *running {
            Some(holder) => Err(holder),
            None => {
                *running = Some(hook_id);
                Ok(Self(inner.clone()))
            }
        }
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        *self.0.running.lock() = None;
        // Wake everything parked on this command. Either it cached a value they
        // can read or it failed — both are answers, and neither is worth
        // sitting out the rest of the wait for.
        self.0.finished.notify_waiters();
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

    /// THE cold-cache burst. Eight requests hitting a cold TTL at once must
    /// mint ONE token, not eight sandboxes — and all EIGHT must go out carrying
    /// it. Forwarding the seven losers un-hooked (what this used to do) hands
    /// them exactly the `401` the hook exists to prevent.
    #[tokio::test]
    async fn concurrent_cache_misses_run_the_command_once_and_all_get_the_value() {
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
                (
                    out.changed,
                    String::from_utf8_lossy(&m.headers).into_owned(),
                )
            }));
        }
        for t in tasks {
            let (changed, headers) = t.await.unwrap();
            assert!(changed, "every request in the burst must be hooked");
            assert!(
                headers.contains("Authorization: Bearer shared"),
                "and with the SAME value the winner minted: {headers}"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly ONE sandbox");

        // The value is now cached: no further command, and the header lands.
        let mut m = msg();
        assert!(engine.pre_request(None, "GET", &mut m).await.changed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(String::from_utf8_lossy(&m.headers).contains("Bearer shared"));
    }

    /// The winner failing must not turn into a retry storm: the losers wake up
    /// on the released claim, find nothing in the cache and fail open — without
    /// each running a command of their own.
    #[tokio::test]
    async fn when_the_winner_fails_the_losers_fail_open_without_re_running_it() {
        struct SlowBoom(Arc<AtomicUsize>);
        #[async_trait]
        impl HookRunner for SlowBoom {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                Err(anyhow::anyhow!("the token endpoint is down"))
            }
        }
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(SlowBoom(calls.clone())));
        engine.set_hooks(vec![token_hook(1, 10_000)]);

        let started = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let e = engine.clone();
            tasks.push(tokio::spawn(async move {
                let mut m = msg();
                e.pre_request(None, "GET", &mut m).await
            }));
        }
        for t in tasks {
            let out = t.await.unwrap();
            assert!(!out.changed && !out.dropped, "fail OPEN, never drop");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a loser must never start a command of its own"
        );
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "the losers wake on the released claim, not on their timer"
        );
    }

    /// The wait must be BOUNDED, because the request doing the waiting can be
    /// the winner's own traffic: an `exec` command whose marker is missing (the
    /// explicit front-end has no exec id to stamp) re-enters the engine and
    /// wants the very value it is itself minting. Nobody can win that, so the
    /// waiter gives up at `min(MAX_SINGLE_FLIGHT_WAIT, timeout/2)` and the
    /// winner still has half its budget left to finish.
    #[tokio::test]
    async fn a_waiter_that_is_the_winners_own_traffic_stalls_at_most_the_bound() {
        struct ReEnter {
            engine: Mutex<Option<HookEngine>>,
            calls: Arc<AtomicUsize>,
            nested_ms: Arc<Mutex<u128>>,
        }
        #[async_trait]
        impl HookRunner for ReEnter {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let engine = self.engine.lock().clone().unwrap();
                let started = Instant::now();
                let mut m = msg();
                // No marker, and the SAME hook: this request is waiting for the
                // command that is waiting for it.
                let out = engine.pre_request(None, "GET", &mut m).await;
                *self.nested_ms.lock() = started.elapsed().as_millis();
                assert!(!out.changed, "the nested request cannot be hooked");
                Ok(r#"{"token":"outer"}"#.to_string())
            }
        }

        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let nested_ms = Arc::new(Mutex::new(0));
        engine.set_runner(Arc::new(ReEnter {
            engine: Mutex::new(Some(engine.clone())),
            calls: calls.clone(),
            nested_ms: nested_ms.clone(),
        }));
        // ttl > 0, so the waiting path is the one under test; timeout 300 ms, so
        // the bound is 150 ms and the whole thing fits well inside the budget.
        let mut h = token_hook(1, 10_000);
        h.timeout_ms = 300;
        engine.set_hooks(vec![h]);

        let mut m = msg();
        let started = Instant::now();
        let out = engine.pre_request(None, "GET", &mut m).await;
        let elapsed = started.elapsed();
        assert!(
            out.changed,
            "the outer request must still get its token ({elapsed:?})"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one command run");
        let nested = *nested_ms.lock();
        assert!(
            (100..250).contains(&nested),
            "the nested request must give up at the bound (~150 ms), got {nested} ms"
        );
        assert!(
            elapsed < Duration::from_millis(300),
            "and the winner must finish inside its own timeout ({elapsed:?})"
        );
    }

    #[test]
    fn the_single_flight_wait_stays_under_the_hooks_own_timeout() {
        // The default hook timeout (10 s) yields the full ceiling…
        assert_eq!(
            single_flight_wait(Duration::from_secs(10)),
            MAX_SINGLE_FLIGHT_WAIT
        );
        // …a longer one does not raise it…
        assert_eq!(
            single_flight_wait(Duration::from_secs(120)),
            MAX_SINGLE_FLIGHT_WAIT
        );
        // …and a short one is halved, never met.
        assert_eq!(
            single_flight_wait(Duration::from_millis(400)),
            Duration::from_millis(200)
        );
        assert!(single_flight_wait(Duration::ZERO).is_zero());
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
    /// that matters — no stall either.
    ///
    /// Both hooks here have `ttl 0`, which is what makes the answer IMMEDIATE
    /// rather than merely bounded: a hook that caches nothing publishes nothing
    /// a waiter could read, so waiting is skipped entirely. (The bounded wait
    /// that a `ttl > 0` hook gets in this same shape is covered by
    /// `a_waiter_that_is_the_winners_own_traffic_stalls_at_most_the_bound`.)
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

    // --- the 401 that arrives inside the TTL --------------------------------

    /// The case the removed `AuthWatcher` existed for, now handled where the
    /// value lives: the target starts refusing the cached token, and the NEXT
    /// request goes out with a freshly minted one.
    #[tokio::test]
    async fn a_401_drops_the_cached_value_so_the_next_request_re_mints() {
        struct Rotating(Arc<AtomicUsize>);
        #[async_trait]
        impl HookRunner for Rotating {
            async fn run(&self, _cmd: &str, _budget: Duration) -> anyhow::Result<String> {
                let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(format!(r#"{{"token":"t{n}"}}"#))
            }
        }
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(Rotating(calls.clone())));
        // A long TTL: without the 401 handling, the first token would be served
        // for an hour whatever the target thinks of it.
        engine.set_hooks(vec![token_hook(1, 3_600_000)]);

        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert!(String::from_utf8_lossy(&m.headers).contains("Bearer t1"));
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "cached, as it should be");

        // The response comes back 401. (`minted_at` is backdated past the
        // cooldown: a value that has been in use IS what this is for, and the
        // test must not depend on wall-clock sleeps.)
        backdate(&engine, 1, REMINT_COOLDOWN + Duration::from_secs(1));
        engine.observe_status(None, &ctx_for("api.example.com"), 401);

        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the 401 forced a re-mint");
        assert!(
            String::from_utf8_lossy(&m.headers).contains("Bearer t2"),
            "and the very next request carries the NEW token"
        );
    }

    /// The rate guard. A target that refuses everything must not cost one
    /// sandbox per request — which is what an unconditional invalidation would
    /// do, and the failure mode the old 30 s debounce was really about.
    #[tokio::test]
    async fn a_401_storm_costs_at_most_one_re_mint_per_cooldown() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"rejected"}"#.into(),
            delay: Duration::ZERO,
        }));
        engine.set_hooks(vec![token_hook(1, 3_600_000)]);

        for _ in 0..20 {
            let mut m = msg();
            engine.pre_request(None, "GET", &mut m).await;
            // Every single one of them comes back 401.
            engine.observe_status(None, &ctx_for("api.example.com"), 401);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a freshly minted value is not thrown away by the 401s it causes"
        );

        // Once the value is old enough, the next 401 does invalidate it.
        backdate(&engine, 1, REMINT_COOLDOWN + Duration::from_secs(1));
        engine.observe_status(None, &ctx_for("api.example.com"), 401);
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Scoping and the recursion guard, on the response side this time: a 401
    /// on a flow this hook does not inject into is none of its business, and a
    /// 401 the hook's OWN login command took says nothing about the client's
    /// token.
    #[tokio::test]
    async fn observe_status_ignores_out_of_scope_flows_other_statuses_and_hook_traffic() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"t"}"#.into(),
            delay: Duration::ZERO,
        }));
        let mut h = token_hook(1, 3_600_000);
        h.scope.host = "api.example.com".into();
        h.scope.path = "/v1/".into();
        engine.set_hooks(vec![h]);

        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        backdate(&engine, 1, REMINT_COOLDOWN + Duration::from_secs(1));

        engine.observe_status(None, &ctx_for("api.example.com"), 200);
        engine.observe_status(None, &ctx_for("api.example.com"), 500);
        engine.observe_status(None, &ctx_for("unrelated.test"), 401);
        engine.observe_status(Some("hook:abc"), &ctx_for("api.example.com"), 401);
        // A refusal of a request this hook does not inject into (it is scoped
        // to /v1/) says nothing about the value it holds.
        engine.observe_status(
            None,
            &MatchCtx {
                host: "api.example.com",
                method: "GET",
                path: "/public/health",
                status: None,
            },
            401,
        );
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "none of those may invalidate anything"
        );

        // …and the one that does apply, does.
        engine.observe_status(None, &ctx_for("api.example.com"), 403);
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The cost of the status hook on a proxy nobody configured: nothing. It
    /// must not even look at the hook list.
    #[tokio::test]
    async fn observe_status_on_an_empty_engine_is_a_no_op() {
        let engine = HookEngine::new();
        engine.observe_status(None, &ctx_for("api.example.com"), 401);
        assert!(engine.invalidate(&[]).is_empty());
    }

    /// `session auth refresh` / `hook cache clear`: an explicit request is NOT
    /// subject to the cooldown — an operator asking for a fresh token gets one.
    #[tokio::test]
    async fn invalidate_ignores_the_cooldown_and_reports_what_it_dropped() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"t"}"#.into(),
            delay: Duration::ZERO,
        }));
        engine.set_hooks(vec![token_hook(1, 3_600_000), token_hook(2, 3_600_000)]);

        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "both hooks minted");

        // Just minted — the cooldown would have refused, this must not.
        assert_eq!(engine.invalidate(&[1]), vec![1]);
        assert!(engine.invalidate(&[1]).is_empty(), "nothing left to drop");
        assert_eq!(engine.invalidate(&[]), vec![2], "empty = every hook");
    }

    /// The request context a response carries back to `observe_status`.
    fn ctx_for(host: &str) -> MatchCtx<'_> {
        MatchCtx {
            host,
            method: "GET",
            path: "/v1/users?id=5",
            status: None,
        }
    }

    /// Age a cached value by rewriting its `minted_at`, so the cooldown can be
    /// exercised without sleeping through it.
    fn backdate(engine: &HookEngine, id: i64, by: Duration) {
        let mut cache = engine.inner.cache.lock();
        if let Some(entry) = cache.get_mut(&id) {
            entry.minted_at -= by;
        }
    }

    /// Re-`set`ting a hook (`session auth set` on a host it already has) is a
    /// DELETE plus an INSERT, and SQLite hands the freed rowid straight back —
    /// so the id is no evidence at all. What must not survive it is the token
    /// the previous command minted.
    #[tokio::test]
    async fn a_hook_redefined_under_the_same_id_does_not_keep_its_cached_value() {
        let engine = HookEngine::new();
        let calls = Arc::new(AtomicUsize::new(0));
        engine.set_runner(Arc::new(CountingRunner {
            calls: calls.clone(),
            output: r#"{"token":"t"}"#.into(),
            delay: Duration::ZERO,
        }));
        engine.set_hooks(vec![token_hook(1, 3_600_000)]);
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Same id, same everything except the command: a different login.
        let mut redefined = token_hook(1, 3_600_000);
        if let HookAction::Exec { cmd, .. } = &mut redefined.action {
            *cmd = "mint-token --as other-user".into();
        }
        engine.set_hooks(vec![redefined]);
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the new definition must mint its own value"
        );

        // An UNCHANGED snapshot (the refresher re-reads every 2s) keeps it.
        engine.set_hooks(engine.snapshot().as_ref().clone());
        let mut m = msg();
        engine.pre_request(None, "GET", &mut m).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "re-reading is not editing");
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
