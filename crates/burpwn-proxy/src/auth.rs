//! Session-auth AUTO-refresh trigger primitive.
//!
//! Long engagements against authenticated targets silently start returning 401s
//! once a bearer/session token expires. `burpwn session auth` lets the operator
//! persist a login command + a match/replace rule that injects a fresh token;
//! this primitive is the *auto* half: it lets the proxy signal, best-effort, when
//! it observes a `401`/`403` for a host so a consumer (the daemon) can trigger
//! one refresh.
//!
//! # Design (mirrors [`crate::intercept::InterceptController`])
//!
//! [`AuthWatcher`] is a clone-cheap handle over shared state. It is **inert by
//! default** — [`AuthWatcher::observe`] is a cheap no-op until a consumer calls
//! [`AuthWatcher::activate`], which installs a bounded channel and returns its
//! receiver. The proxy calls `observe(host, status)` on every response; when the
//! status is `401`/`403`, the host has not been signalled within the debounce
//! window, and a consumer is attached, the host name is emitted on the channel
//! (non-blocking — a full channel drops the signal rather than stalling the hot
//! path).
//!
//! # Recursion + storm safety
//!
//! The debounce is the load-bearing guard. A single per-host timestamp is
//! compare-and-set inside `observe`: a host can be signalled **at most once per
//! [`AuthWatcher::interval`]**. Because the timestamp is stamped at *signal* time
//! (before the consumer runs the login command), the login command's own traffic
//! — which flows back through this same proxy and may itself 401 — is suppressed
//! for the whole window, so a refresh never recursively re-triggers itself. The
//! consumer is expected to keep a refresh well under the interval.
//!
//! The proxy layer knows nothing about *which* hosts have auth profiles: it
//! emits every debounced 401/403 host and lets the consumer decide (cheap store
//! read). Keeping the scope decision out of the hot path avoids a staleness
//! problem — a profile added by a separate `session auth set` process is picked
//! up on the next signal without the proxy needing to be told.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Default minimum spacing between auto-refresh signals for a given host. Chosen
/// well above a typical login-command round-trip so a refresh never re-triggers
/// on its own traffic, yet short enough that a genuinely expired token is
/// re-minted promptly.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_secs(30);

/// Bound on the pending-signal channel. Tiny: at most a handful of distinct
/// hosts refresh concurrently, and an over-full channel simply drops the signal
/// (the next 401 after the debounce re-signals).
const CHANNEL_CAP: usize = 16;

struct Inner {
    /// Present only after [`AuthWatcher::activate`]; `None` = inert.
    tx: Mutex<Option<mpsc::Sender<String>>>,
    /// Per-host last-signalled instant, for debounce.
    last: Mutex<HashMap<String, Instant>>,
    /// Minimum spacing between signals for one host.
    interval: Duration,
}

/// Clone-cheap handle to the auth auto-refresh trigger (internally `Arc`-shared).
#[derive(Clone)]
pub struct AuthWatcher {
    inner: Arc<Inner>,
}

impl Default for AuthWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthWatcher {
    /// Create an inert watcher with the [`DEFAULT_DEBOUNCE`] window.
    pub fn new() -> Self {
        Self::with_interval(DEFAULT_DEBOUNCE)
    }

    /// Create an inert watcher with a custom debounce window (tests use a short
    /// one).
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                tx: Mutex::new(None),
                last: Mutex::new(HashMap::new()),
                interval,
            }),
        }
    }

    /// Attach a consumer: install the signal channel and return its receiver.
    /// After this, [`observe`](Self::observe) starts emitting debounced host
    /// signals. Calling twice replaces the channel (the previous receiver stops
    /// receiving).
    pub fn activate(&self) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        *self.inner.tx.lock() = Some(tx);
        rx
    }

    /// Whether a consumer is attached (auto-refresh is armed).
    pub fn is_active(&self) -> bool {
        self.inner.tx.lock().is_some()
    }

    /// Observe one response's `(host, status)`. When inert this returns
    /// immediately. Emits `host` on the channel iff the status is `401`/`403`
    /// and the host has not been signalled within the debounce window. Returns
    /// whether a signal was emitted (used by tests).
    pub fn observe(&self, host: &str, status: u16) -> bool {
        if status != 401 && status != 403 {
            return false;
        }
        // Cheap early-out while inert (the common case for the explicit-proxy
        // test front-end, which never activates a watcher).
        let tx = {
            let guard = self.inner.tx.lock();
            match &*guard {
                Some(t) => t.clone(),
                None => return false,
            }
        };
        // Debounce: compare-and-set the per-host timestamp under the lock so two
        // concurrent 401s for the same host can't both signal.
        {
            let mut last = self.inner.last.lock();
            let now = Instant::now();
            if let Some(prev) = last.get(host) {
                if now.duration_since(*prev) < self.inner.interval {
                    return false;
                }
            }
            last.insert(host.to_string(), now);
        }
        // Non-blocking: a full channel drops the signal (the next post-debounce
        // 401 re-signals) rather than stalling the proxy response path.
        tx.try_send(host.to_string()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inert_watcher_never_signals() {
        let w = AuthWatcher::new();
        assert!(!w.is_active());
        // No consumer attached: even a 401 is a no-op.
        assert!(!w.observe("api.example.com", 401));
    }

    #[tokio::test]
    async fn only_401_403_signal() {
        let w = AuthWatcher::new();
        let mut rx = w.activate();
        assert!(!w.observe("h", 200));
        assert!(!w.observe("h", 500));
        assert!(w.observe("h", 401));
        assert_eq!(rx.recv().await.unwrap(), "h");
        // A different host still within its own (fresh) window signals.
        assert!(w.observe("h2", 403));
        assert_eq!(rx.recv().await.unwrap(), "h2");
    }

    #[tokio::test]
    async fn debounce_suppresses_repeat_within_window() {
        // A long window: the second 401 for the same host must be suppressed —
        // this is exactly what stops a refresh's own login traffic re-triggering.
        let w = AuthWatcher::with_interval(Duration::from_secs(3600));
        let mut rx = w.activate();
        assert!(w.observe("api", 401));
        assert!(!w.observe("api", 401), "second within window is suppressed");
        assert!(!w.observe("api", 403), "403 also suppressed within window");
        assert_eq!(rx.recv().await.unwrap(), "api");
        assert!(rx.try_recv().is_err(), "exactly one signal emitted");
    }

    #[tokio::test]
    async fn debounce_allows_after_window() {
        let w = AuthWatcher::with_interval(Duration::from_millis(20));
        let mut rx = w.activate();
        assert!(w.observe("api", 401));
        assert_eq!(rx.recv().await.unwrap(), "api");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(w.observe("api", 401), "re-signals after the window elapses");
        assert_eq!(rx.recv().await.unwrap(), "api");
    }
}
