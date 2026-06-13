//! In-proxy blocking-intercept primitive (the hook M6/M7 wire CLI + MCP onto).
//!
//! The proxy HTTP handler calls [`InterceptController::intercept`] before
//! forwarding a request and before returning a response. When interception is
//! disabled or the flow is out of scope it returns [`InterceptDecision::Forward`]
//! `(None)` immediately. When enabled *and* in scope it **parks** the flow:
//! pushes a [`PendingIntercept`] onto a shared queue, signals a [`Notify`], and
//! awaits a [`oneshot`] decision with a hard timeout (default 5 min → auto
//! forward). An out-of-band consumer (CLI/MCP) inspects [`pending`], pulls work
//! with [`take_next`], and unblocks the handler with [`resolve`].
//!
//! This module deliberately knows nothing about MCP/CLI; it is only the
//! synchronization primitive + scope filtering + tests.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{oneshot, Notify};

/// Which side of a flow is being intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptKind {
    /// The request, before it is forwarded upstream.
    Request,
    /// The response, before it is returned downstream.
    Response,
}

/// The editable view of a message handed to the operator when parked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptData {
    /// Request host / `:authority`.
    pub host: String,
    /// Request method (for requests; echoed for responses).
    pub method: String,
    /// Request target / path.
    pub path: String,
    /// Raw header block bytes (order-preserving).
    pub headers: Vec<u8>,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// The operator's verdict for a parked flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptDecision {
    /// Release the message. `Some(data)` carries operator edits; `None` means
    /// forward unchanged.
    Forward(Option<InterceptData>),
    /// Drop the message without forwarding.
    Drop,
}

/// A parked flow awaiting a decision, pulled by the out-of-band consumer.
pub struct PendingIntercept {
    /// Unique id (monotonic within the controller).
    pub id: u64,
    /// Which side is held.
    pub kind: InterceptKind,
    /// The message snapshot, editable before [`InterceptController::resolve`].
    pub data: InterceptData,
    /// Channel the handler is awaiting; `resolve`/`take_next` sends on it.
    pub reply: oneshot::Sender<InterceptDecision>,
}

/// A lightweight summary of a parked flow (no `reply` sender) for listing.
#[derive(Debug, Clone)]
pub struct PendingSummary {
    /// Pending id.
    pub id: u64,
    /// Which side.
    pub kind: InterceptKind,
    /// Host.
    pub host: String,
    /// Method.
    pub method: String,
    /// Path.
    pub path: String,
}

/// Scope filter: simple case-insensitive substring matches. An empty field
/// matches everything on that dimension.
#[derive(Debug, Clone, Default)]
pub struct InterceptScope {
    /// Substring the host must contain (empty = any).
    pub host_contains: String,
    /// Substring the path must contain (empty = any).
    pub path_contains: String,
    /// Exact method (case-insensitive; empty = any).
    pub method: String,
}

impl InterceptScope {
    fn matches(&self, data: &InterceptData) -> bool {
        let host_ok = self.host_contains.is_empty()
            || data
                .host
                .to_ascii_lowercase()
                .contains(&self.host_contains.to_ascii_lowercase());
        let path_ok = self.path_contains.is_empty()
            || data
                .path
                .to_ascii_lowercase()
                .contains(&self.path_contains.to_ascii_lowercase());
        let method_ok =
            self.method.is_empty() || data.method.eq_ignore_ascii_case(self.method.trim());
        host_ok && path_ok && method_ok
    }
}

struct Inner {
    pending: Mutex<Vec<PendingIntercept>>,
    scope: Mutex<InterceptScope>,
    enabled: AtomicBool,
    next_id: AtomicU64,
    notify: Notify,
    timeout: Mutex<Duration>,
}

/// Clone-cheap handle to the intercept primitive (internally `Arc`-shared).
#[derive(Clone)]
pub struct InterceptController {
    inner: Arc<Inner>,
}

impl Default for InterceptController {
    fn default() -> Self {
        Self::new()
    }
}

impl InterceptController {
    /// Create a disabled controller with the default 5-minute park timeout.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                pending: Mutex::new(Vec::new()),
                scope: Mutex::new(InterceptScope::default()),
                enabled: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
                notify: Notify::new(),
                timeout: Mutex::new(Duration::from_secs(300)),
            }),
        }
    }

    /// Enable or disable interception globally.
    pub fn set_enabled(&self, on: bool) {
        self.inner.enabled.store(on, Ordering::SeqCst);
        // Wake any consumer waiting in `take_next` so it can re-check.
        self.inner.notify.notify_waiters();
    }

    /// Whether interception is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::SeqCst)
    }

    /// Replace the scope filter.
    pub fn set_scope(&self, scope: InterceptScope) {
        *self.inner.scope.lock() = scope;
    }

    /// Override the park timeout (after which a parked flow auto-forwards).
    pub fn set_timeout(&self, timeout: Duration) {
        *self.inner.timeout.lock() = timeout;
    }

    /// Snapshots of every parked flow.
    pub fn pending(&self) -> Vec<PendingSummary> {
        self.inner
            .pending
            .lock()
            .iter()
            .map(|p| PendingSummary {
                id: p.id,
                kind: p.kind,
                host: p.data.host.clone(),
                method: p.data.method.clone(),
                path: p.data.path.clone(),
            })
            .collect()
    }

    /// Resolve a specific parked flow by id. Returns `true` if it was found and
    /// the handler unblocked; `false` if the id was unknown (already resolved /
    /// timed out).
    pub fn resolve(&self, id: u64, decision: InterceptDecision) -> bool {
        let taken = {
            let mut q = self.inner.pending.lock();
            q.iter().position(|p| p.id == id).map(|idx| q.remove(idx))
        };
        match taken {
            Some(p) => p.reply.send(decision).is_ok(),
            None => false,
        }
    }

    /// Pull the oldest parked flow for an out-of-band consumer (e.g. the MCP
    /// long-poll). Waits up to `timeout` for one to appear. The caller owns the
    /// returned [`PendingIntercept`] and MUST send a decision on its `reply`
    /// sender to unblock the proxy handler.
    pub async fn take_next(&self, timeout: Duration) -> Option<PendingIntercept> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut q = self.inner.pending.lock();
                if !q.is_empty() {
                    // FIFO: oldest parked flow first.
                    return Some(q.remove(0));
                }
            }
            let notified = self.inner.notify.notified();
            tokio::select! {
                _ = notified => continue,
                _ = tokio::time::sleep_until(deadline) => return None,
            }
        }
    }

    /// The intercept entry point called by the proxy handler. Returns a decision
    /// the handler acts on. Disabled/out-of-scope ⇒ immediate `Forward(None)`.
    pub async fn intercept(&self, kind: InterceptKind, data: InterceptData) -> InterceptDecision {
        if !self.is_enabled() || !self.inner.scope.lock().matches(&data) {
            return InterceptDecision::Forward(None);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.inner.pending.lock().push(PendingIntercept {
            id,
            kind,
            data,
            reply: tx,
        });
        self.inner.notify.notify_waiters();

        let timeout = *self.inner.timeout.lock();
        match tokio::time::timeout(timeout, rx).await {
            // Resolved by an operator/consumer.
            Ok(Ok(decision)) => decision,
            // Sender dropped without a decision: fail open (forward unchanged).
            Ok(Err(_)) => InterceptDecision::Forward(None),
            // Timed out: drop the entry from the queue and auto-forward.
            Err(_) => {
                self.drop_pending(id);
                InterceptDecision::Forward(None)
            }
        }
    }

    fn drop_pending(&self, id: u64) {
        let mut q = self.inner.pending.lock();
        if let Some(idx) = q.iter().position(|p| p.id == id) {
            q.remove(idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(host: &str, method: &str, path: &str) -> InterceptData {
        InterceptData {
            host: host.into(),
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body: b"orig".to_vec(),
        }
    }

    #[tokio::test]
    async fn disabled_forwards_immediately() {
        let c = InterceptController::new();
        let d = c
            .intercept(InterceptKind::Request, data("example.com", "GET", "/"))
            .await;
        assert_eq!(d, InterceptDecision::Forward(None));
        assert!(c.pending().is_empty());
    }

    #[tokio::test]
    async fn out_of_scope_forwards_immediately() {
        let c = InterceptController::new();
        c.set_enabled(true);
        c.set_scope(InterceptScope {
            host_contains: "target.test".into(),
            ..Default::default()
        });
        let d = c
            .intercept(InterceptKind::Request, data("example.com", "GET", "/"))
            .await;
        assert_eq!(d, InterceptDecision::Forward(None));
    }

    #[tokio::test]
    async fn in_scope_parks_and_resolve_unblocks() {
        let c = InterceptController::new();
        c.set_enabled(true);
        let c2 = c.clone();
        let handle = tokio::spawn(async move {
            c2.intercept(
                InterceptKind::Request,
                data("example.com", "POST", "/login"),
            )
            .await
        });

        // Wait for it to park.
        loop {
            if !c.pending().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let summary = c.pending();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].kind, InterceptKind::Request);
        assert_eq!(summary[0].path, "/login");

        let edited = data("example.com", "POST", "/login");
        let mut edited = edited;
        edited.body = b"tampered".to_vec();
        assert!(c.resolve(
            summary[0].id,
            InterceptDecision::Forward(Some(edited.clone()))
        ));

        let decision = handle.await.unwrap();
        assert_eq!(decision, InterceptDecision::Forward(Some(edited)));
        assert!(c.pending().is_empty());
    }

    #[tokio::test]
    async fn drop_decision_propagates() {
        let c = InterceptController::new();
        c.set_enabled(true);
        let c2 = c.clone();
        let handle = tokio::spawn(async move {
            c2.intercept(InterceptKind::Response, data("h", "GET", "/"))
                .await
        });
        let id = loop {
            let p = c.pending();
            if let Some(s) = p.first() {
                break s.id;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        };
        assert!(c.resolve(id, InterceptDecision::Drop));
        assert_eq!(handle.await.unwrap(), InterceptDecision::Drop);
    }

    #[tokio::test]
    async fn timeout_auto_forwards() {
        let c = InterceptController::new();
        c.set_enabled(true);
        c.set_timeout(Duration::from_millis(20));
        let d = c
            .intercept(InterceptKind::Request, data("h", "GET", "/"))
            .await;
        assert_eq!(d, InterceptDecision::Forward(None));
        // Entry cleaned up after timeout.
        assert!(c.pending().is_empty());
    }

    #[tokio::test]
    async fn take_next_hands_off_work() {
        let c = InterceptController::new();
        c.set_enabled(true);
        let c2 = c.clone();
        let handle = tokio::spawn(async move {
            c2.intercept(InterceptKind::Request, data("h", "GET", "/x"))
                .await
        });

        let pending = c.take_next(Duration::from_secs(1)).await.unwrap();
        assert_eq!(pending.kind, InterceptKind::Request);
        pending.reply.send(InterceptDecision::Drop).unwrap();
        assert_eq!(handle.await.unwrap(), InterceptDecision::Drop);
    }

    #[tokio::test]
    async fn resolve_unknown_id_is_false() {
        let c = InterceptController::new();
        assert!(!c.resolve(999, InterceptDecision::Drop));
    }
}
