//! `burpwn exec` orchestration: ensure a daemon is running for the session,
//! build the [`ExecSpec`], run it through an injectable [`SandboxRuntime`], and
//! report the captured flow ids.
//!
//! The runtime is injected so the whole path is testable against
//! [`burpwn_sandbox::MockRuntime`] without privileges. The daemon-ensure step is
//! also factored out ([`ensure_daemon`]) and skipped when a `proxy_sock` already
//! answers, so tests can pre-create the socket file (or a real daemon).
//!
//! # Output contract
//!
//! In normal mode the child inherits the real stdio. In `--json` mode, the JSON
//! envelope is written to **fd 3** when it is open, else to stderr — never
//! intermixed with the child's stdout (see [`write_json_envelope`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::json;

use burpwn_sandbox::{ExecOutcome, ExecSpec, SandboxRuntime};
use burpwn_store::model::FlowFilter;
use burpwn_store::Store;

use crate::daemon::{NETNS_DNS_PORT, NETNS_TCP_PORT};
use crate::envelope::Envelope;
use crate::paths::Paths;

/// Counter feeding the exec-id, so two execs in the same process+millisecond
/// still differ.
static EXEC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique-enough exec correlation id from pid + a monotonic counter +
/// wall-clock nanos. This is a real binary, not a deterministic workflow, so
/// wall-clock time is appropriate.
pub fn new_exec_id() -> String {
    let pid = std::process::id();
    let n = EXEC_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("exec-{pid}-{n}-{nanos}")
}

/// The outcome of an `exec`, before envelope rendering.
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// The exec correlation id stamped on captured flows.
    pub exec_id: String,
    /// The child's exit code.
    pub exit_code: i32,
    /// Flow ids captured during this exec.
    pub captured_request_ids: Vec<i64>,
    /// The sandbox outcome (stdout/stderr present only in capture mode).
    pub outcome: ExecOutcome,
}

/// Build the [`ExecSpec`] for one `exec` invocation.
///
/// `argv` is the command; `workdir` the cwd; `extra_env` the user-provided env
/// on top of the inherited process env (CA env is injected by the runtime).
pub fn build_spec(
    paths: &Paths,
    session: &str,
    argv: Vec<String>,
    timeout: Option<Duration>,
    inherit_stdio: bool,
) -> ExecSpec {
    let mut env: Vec<(String, String)> = std::env::vars().collect();
    // De-noise: the sandbox manages CA-trust env itself; we still forward the
    // rest of the inherited environment so the wrapped tool behaves normally.
    env.retain(|(k, _)| k != "SSL_CERT_FILE" && k != "SSL_CERT_DIR");

    ExecSpec {
        argv,
        workdir: std::env::current_dir().unwrap_or_else(|_| ".".into()),
        env,
        proxy_sock: paths.proxy_sock(session),
        proxy_tcp_port: NETNS_TCP_PORT,
        proxy_dns_port: NETNS_DNS_PORT,
        ca_path: paths.ca_pem(),
        timeout,
        inherit_stdio,
    }
}

/// Run one `exec` against the provided runtime. Pure orchestration: the caller
/// is responsible for ensuring the daemon is up (so tests can skip it).
///
/// After the command finishes, the session store is queried for flows stamped
/// with `exec_id` to populate `captured_request_ids`.
pub async fn run_exec(
    paths: &Paths,
    session: &str,
    runtime: Arc<dyn SandboxRuntime>,
    argv: Vec<String>,
    timeout: Option<Duration>,
    inherit_stdio: bool,
) -> Result<ExecResult> {
    let exec_id = new_exec_id();
    let mut spec = build_spec(paths, session, argv, timeout, inherit_stdio);
    // Stamp the exec id into the child's environment so the proxy (which reads
    // its exec_id from ProxyConfig per-daemon) is not the only correlator; the
    // daemon already attributes flows for this session, but exposing the id lets
    // tools and tests correlate too.
    spec.env.push(("BURPWN_EXEC_ID".into(), exec_id.clone()));

    let outcome = runtime
        .run(spec)
        .await
        .context("running command in sandbox")?;

    let captured_request_ids = collect_captured(paths, session, &exec_id).unwrap_or_default();

    Ok(ExecResult {
        exec_id,
        exit_code: outcome.exit_code,
        captured_request_ids,
        outcome,
    })
}

/// Query the session store for flows stamped with `exec_id`. Opening the store
/// read-only is cheap; we filter in-memory because `FlowFilter` has no exec
/// dimension.
fn collect_captured(paths: &Paths, session: &str, exec_id: &str) -> Result<Vec<i64>> {
    let db = paths.session_db(session);
    if !db.exists() {
        return Ok(Vec::new());
    }
    let store = Store::open(&db)?;
    let reader = store.reader();
    let rows = reader.list_flows(&FlowFilter {
        limit: Some(10_000),
        ..Default::default()
    })?;
    let mut ids = Vec::new();
    for row in rows {
        if let Some(detail) = reader.get_flow(row.id)? {
            if detail.exec_id.as_deref() == Some(exec_id) {
                ids.push(row.id);
            }
        }
    }
    Ok(ids)
}

/// Render an [`ExecResult`] to the JSON envelope value.
pub fn exec_envelope(result: &ExecResult) -> Envelope {
    Envelope::ok(json!({
        "exit_code": result.exit_code,
        "exec_id": result.exec_id,
        "captured_request_ids": result.captured_request_ids,
    }))
}

/// Write the JSON envelope to fd 3 if it is open, else to stderr. NEVER stdout:
/// the child's stdout passed through there in normal mode and machine consumers
/// read the envelope off a dedicated channel.
///
/// Uses `fcntl(3, F_GETFD)` to probe whether fd 3 is open without consuming it,
/// then writes via a borrowed `File` we explicitly `mem::forget` so we don't
/// close fd 3 on drop (the parent owns it).
pub fn write_json_envelope(env: &Envelope) {
    use std::io::Write;
    use std::os::fd::FromRawFd;

    let line = format!("{}\n", env.to_json_line());

    // SAFETY: F_GETFD only inspects the descriptor table; it does not transfer
    // ownership. A negative return means fd 3 is closed/invalid.
    let fd3_open = unsafe { libc::fcntl(3, libc::F_GETFD) } >= 0;

    if fd3_open {
        // SAFETY: fd 3 is open (checked above). We must not run its destructor
        // (which would close it), so we forget the File after writing.
        let mut file = unsafe { std::fs::File::from_raw_fd(3) };
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
        std::mem::forget(file);
    } else {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_sandbox::MockRuntime;
    use burpwn_store::model::{FlowStart, Protocol, RequestData};

    #[test]
    fn exec_ids_are_unique() {
        let a = new_exec_id();
        let b = new_exec_id();
        assert_ne!(a, b);
        assert!(a.starts_with("exec-"));
    }

    #[test]
    fn build_spec_uses_session_paths_and_fixed_netns_ports() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        let spec = build_spec(
            &paths,
            "default",
            vec!["curl".into(), "https://x".into()],
            Some(Duration::from_secs(9)),
            true,
        );
        assert_eq!(spec.argv, vec!["curl", "https://x"]);
        assert_eq!(spec.proxy_tcp_port, NETNS_TCP_PORT);
        assert_eq!(spec.proxy_dns_port, NETNS_DNS_PORT);
        assert!(spec.proxy_sock.ends_with("default/proxy.sock"));
        assert!(spec.ca_path.ends_with("ca.pem"));
        assert!(spec.inherit_stdio);
        assert_eq!(spec.timeout, Some(Duration::from_secs(9)));
    }

    #[tokio::test]
    async fn run_exec_builds_spec_and_returns_envelope_via_mock() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();

        let rt = MockRuntime::new();
        rt.set_canned(ExecOutcome {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
        });
        let dyn_rt: Arc<dyn SandboxRuntime> = rt.clone();

        let result = run_exec(
            &paths,
            "default",
            dyn_rt,
            vec!["curl".into(), "https://example.com".into()],
            None,
            false,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        // The mock recorded exactly the spec we built.
        let spec = rt.last_spec().unwrap();
        assert_eq!(spec.argv, vec!["curl", "https://example.com"]);
        assert!(spec
            .env
            .iter()
            .any(|(k, v)| k == "BURPWN_EXEC_ID" && v == &result.exec_id));

        let env = exec_envelope(&result);
        assert!(env.ok);
        assert_eq!(env.data["exit_code"], 0);
        assert_eq!(env.data["captured_request_ids"], json!([]));
    }

    #[tokio::test]
    async fn run_exec_collects_flows_stamped_with_exec_id() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();

        // Pre-populate the store: two flows, only one with a matching exec id.
        // We can't know the exec id ahead of run_exec, so instead we assert the
        // mechanism: run_exec generates an id, the daemon (absent here) would
        // stamp it; with no matching flows we get an empty list. The positive
        // path of `collect_captured` is exercised directly below.
        let store = Store::open(paths.session_db("default")).unwrap();
        let w = store.writer();
        let fid = w
            .flow_start(FlowStart {
                workspace_id: 1,
                ts_start: 0,
                exec_id: Some("known-exec".into()),
                client_addr: "127.0.0.1:1".into(),
                dst_ip: "1.2.3.4".into(),
                dst_port: 443,
                sni: Some("x".into()),
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
                authority: "x".into(),
                path: "/".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        drop(w);
        drop(store);

        let ids = collect_captured(&paths, "default", "known-exec").unwrap();
        assert_eq!(ids, vec![fid]);
        let none = collect_captured(&paths, "default", "absent").unwrap();
        assert!(none.is_empty());
    }
}
