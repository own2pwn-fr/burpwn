//! The [`SandboxRuntime`] trait, the [`ExecSpec`]/[`ExecOutcome`] data types,
//! the crate error type, and the privilege-free [`MockRuntime`].
//!
//! The shape mirrors `easm-sandbox`'s `container.rs` (a `#[async_trait]` runtime
//! trait, a RAII handle that tears down on `Drop` with a double-fire guard, and
//! a `MockRuntime` for tests) but adapted to OUR rootless mechanism: instead of
//! provisioning a long-lived podman container, [`SandboxRuntime::run`] executes
//! ONE command to completion inside a freshly-created userns+netns (with the
//! nftables REDIRECT ruleset and bubblewrap) and tears everything down. The RAII
//! lifetime is the duration of a single `run`, so the "handle on Drop" guarantee
//! is internal to the prod runtime ([`crate::rootless`]); the trait surface is a
//! single async `run`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Errors from the sandbox runtime layer.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// A required host capability/binary is missing (userns, bwrap, nft, ip…).
    /// Carries the human-readable preflight summary.
    #[error("sandbox preflight failed: {0}")]
    Preflight(String),
    /// A privileged setup/teardown step failed (clone, uid_map, netns, nft…).
    #[error("sandbox runtime error: {0}")]
    Runtime(String),
    /// The command was spawned but exceeded its timeout and was killed.
    #[error("sandbox command timed out after {0:?}")]
    Timeout(Duration),
    /// An I/O error talking to the child / pipes / sockets.
    #[error("sandbox io error: {0}")]
    Io(String),
}

/// Parameters used to run one command inside a fresh sandbox.
///
/// Serializable so the host runtime can hand it to the `__netns-agent` helper
/// process (the forked child `execve`s a clean single-threaded image before
/// spawning `ip`/`nft`/`bwrap`, avoiding the multithreaded-fork allocator hazard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecSpec {
    /// The command and its arguments (argv[0] is the program).
    pub argv: Vec<String>,
    /// Working directory the command runs in (bind-mounted rw into the sandbox).
    pub workdir: PathBuf,
    /// Extra environment variables for the command (on top of the CA injection).
    pub env: Vec<(String, String)>,
    /// Host unix socket the in-netns acceptor connects to, to hand off
    /// connections (SCM_RIGHTS) to the host proxy.
    pub proxy_sock: PathBuf,
    /// TCP port the in-netns acceptor binds (`127.0.0.1:proxy_tcp_port`) and the
    /// nftables ruleset redirects all TCP to.
    pub proxy_tcp_port: u16,
    /// UDP port the in-netns DNS shim binds and the ruleset redirects DNS to.
    pub proxy_dns_port: u16,
    /// Path to the CA PEM to bind into the sandbox and trust via the standard
    /// `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/… env vars (what makes MITM trusted).
    pub ca_path: PathBuf,
    /// Optional wall-clock timeout for the command.
    pub timeout: Option<Duration>,
    /// When true, inherit the parent's stdio (pass-through mode for the CLI);
    /// when false (default), capture stdout/stderr into the [`ExecOutcome`].
    pub inherit_stdio: bool,
}

impl ExecSpec {
    /// Construct a minimal capturing spec; chain the setters / struct-update for
    /// the rest. `argv` must be non-empty (argv[0] is the program).
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            workdir: PathBuf::from("/"),
            env: Vec::new(),
            proxy_sock: PathBuf::from("/run/burpwn/proxy.sock"),
            proxy_tcp_port: 8080,
            proxy_dns_port: 5353,
            ca_path: PathBuf::from("/etc/burpwn/ca.pem"),
            timeout: None,
            inherit_stdio: false,
        }
    }
}

/// The result of running one command inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// The command's exit code (or -1 if it was killed before exiting).
    pub exit_code: i32,
    /// Captured stdout (empty when `inherit_stdio` was set).
    pub stdout: Vec<u8>,
    /// Captured stderr (empty when `inherit_stdio` was set).
    pub stderr: Vec<u8>,
}

/// Abstraction over the privileged per-command isolation so the CLI and tests
/// can run without namespaces. Implemented by [`MockRuntime`] (tests) and
/// [`crate::rootless::RootlessRuntime`] (prod).
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Set up a fresh userns+netns (REDIRECT to the proxy) + bwrap, run the
    /// command described by `spec` to completion, tear everything down (RAII),
    /// and return its outcome.
    async fn run(&self, spec: ExecSpec) -> Result<ExecOutcome, SandboxError>;
}

// ---------------------------------------------------------------------------
// Mock runtime: records specs, returns canned outcomes. No privileges.
// ---------------------------------------------------------------------------

/// In-memory mock runtime for the CLI plumbing and unit tests. Records every
/// spec it is asked to run and returns a canned outcome — it never creates
/// namespaces, so it works unprivileged in CI.
#[derive(Default)]
pub struct MockRuntime {
    /// Every spec passed to [`SandboxRuntime::run`], in order.
    pub runs: Mutex<Vec<ExecSpec>>,
    /// When set, `run` returns this outcome; otherwise a default success.
    canned: Mutex<Option<ExecOutcome>>,
    /// When set, `run` returns this error instead (to test error paths).
    fail_with: Mutex<Option<String>>,
}

impl MockRuntime {
    /// A new mock wrapped in an `Arc` (the shape the CLI consumes).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Set the canned outcome returned by `run`.
    pub fn set_canned(&self, outcome: ExecOutcome) {
        *self.canned.lock().unwrap() = Some(outcome);
    }

    /// Force `run` to fail with a `Runtime` error carrying `msg`.
    pub fn set_failure(&self, msg: impl Into<String>) {
        *self.fail_with.lock().unwrap() = Some(msg.into());
    }

    /// Number of times `run` was invoked.
    pub fn run_count(&self) -> usize {
        self.runs.lock().unwrap().len()
    }

    /// The most-recently-recorded spec, if any.
    pub fn last_spec(&self) -> Option<ExecSpec> {
        self.runs.lock().unwrap().last().cloned()
    }
}

#[async_trait]
impl SandboxRuntime for MockRuntime {
    async fn run(&self, spec: ExecSpec) -> Result<ExecOutcome, SandboxError> {
        if let Some(msg) = self.fail_with.lock().unwrap().clone() {
            return Err(SandboxError::Runtime(msg));
        }
        self.runs.lock().unwrap().push(spec);
        Ok(self
            .canned
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| ExecOutcome {
                exit_code: 0,
                stdout: b"mock-output\n".to_vec(),
                stderr: Vec::new(),
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ExecSpec {
        ExecSpec::new(vec!["curl".into(), "https://example.com".into()])
    }

    #[tokio::test]
    async fn mock_records_spec_and_returns_default() {
        let rt = MockRuntime::new();
        let out = rt.run(spec()).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, b"mock-output\n");
        assert_eq!(rt.run_count(), 1);
        assert_eq!(
            rt.last_spec().unwrap().argv,
            vec!["curl", "https://example.com"]
        );
    }

    #[tokio::test]
    async fn mock_returns_canned_outcome() {
        let rt = MockRuntime::new();
        rt.set_canned(ExecOutcome {
            exit_code: 7,
            stdout: b"hi".to_vec(),
            stderr: b"warn".to_vec(),
        });
        let out = rt.run(spec()).await.unwrap();
        assert_eq!(out.exit_code, 7);
        assert_eq!(out.stdout, b"hi");
        assert_eq!(out.stderr, b"warn");
    }

    #[tokio::test]
    async fn mock_can_force_failure() {
        let rt = MockRuntime::new();
        rt.set_failure("boom");
        let err = rt.run(spec()).await.unwrap_err();
        assert!(matches!(err, SandboxError::Runtime(m) if m == "boom"));
        // A forced failure does not record the spec.
        assert_eq!(rt.run_count(), 0);
    }

    #[tokio::test]
    async fn mock_is_a_sandbox_runtime_object() {
        let rt: Arc<dyn SandboxRuntime> = MockRuntime::new();
        assert!(rt.run(spec()).await.is_ok());
    }

    #[test]
    fn exec_spec_new_defaults_to_capture() {
        let s = spec();
        assert!(!s.inherit_stdio);
        assert!(s.timeout.is_none());
    }
}
