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
use burpwn_store::Store;

use crate::daemon::{NETNS_DNS_PORT, NETNS_TCP_PORT};
use crate::envelope::Envelope;
use crate::paths::Paths;

/// The id of the implicit default workspace every session starts with.
pub const DEFAULT_WORKSPACE_ID: i64 = 1;

/// Wall-clock unix-millis helper. The daemon stamps flows in millis, so the
/// attribution window must be in the same unit.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Grace period before attributing flows, so the daemon's async writer has time
/// to flush the last in-flight flow rows it recorded for this exec.
const ATTRIBUTE_GRACE: Duration = Duration::from_millis(150);

/// Resolve a workspace NAME to its id, creating it if it does not yet exist.
/// `None` resolves to the default workspace ([`DEFAULT_WORKSPACE_ID`]).
///
/// Opening the store is cheap; we list existing workspaces and match by name
/// (case-sensitive, mirroring `workspace use`).
pub async fn resolve_workspace_id(paths: &Paths, session: &str, name: Option<&str>) -> Result<i64> {
    // Treat a missing or blank/whitespace-only name as "the default workspace"
    // (so e.g. an empty `--workspace ""` doesn't create a workspace named "").
    let name = match name {
        Some(n) if !n.trim().is_empty() => n,
        _ => return Ok(DEFAULT_WORKSPACE_ID),
    };
    let store = Store::open(paths.session_db(session))
        .with_context(|| format!("opening session store for workspace {name:?}"))?;
    if let Some(ws) = store
        .reader()
        .list_workspaces()?
        .into_iter()
        .find(|w| w.name == name)
    {
        return Ok(ws.id);
    }
    store
        .writer()
        .create_workspace(name.to_string(), now_millis())
        .await
        .with_context(|| format!("creating workspace {name:?}"))
}

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
    /// A capture-completeness warning: set when a clearly network-facing command
    /// completed but produced ZERO new flows (traffic likely escaped capture,
    /// e.g. the agent's hook silently no-op'd). `None` otherwise.
    pub capture_warning: Option<String>,
}

/// Programs that clearly speak the network (HTTP-y / scanning tools). Used by
/// [`is_network_facing`] to decide whether a ZERO-capture exec is worth warning
/// about. Deliberately CONSERVATIVE: only tools whose whole purpose is network
/// traffic, so an `ls`/`git`/`cat` that legitimately captures nothing never
/// warns. Matched against a command token's basename (whole word).
const NETWORK_TOOLS: &[&str] = &[
    "curl", "wget", "http", "https", "httpie", "httpx", "nc", "ncat", "netcat", "socat", "telnet",
    "nmap", "masscan", "ffuf", "gobuster", "feroxbuster", "dirb", "dirbuster", "nikto", "sqlmap",
    "wpscan", "whatweb", "wfuzz", "hydra", "nuclei", "katana", "amass", "subfinder", "arjun",
    "dalfox",
];

/// Whether `argv` is a CLEARLY network-facing command. Conservative: it only
/// considers tokens in **program position** (the start of the command or of a
/// segment after a shell separator), skipping `VAR=val` prefixes and benign
/// wrappers (`sudo`/`env`/…). So a network tool that appears merely as an
/// ARGUMENT (`grep curl notes`, `cat urls | wc -l`) never triggers a false
/// alarm, while `curl …`, `sudo wget …` and a wrapped `sh -c 'nmap …'` do.
pub fn is_network_facing(argv: &[String]) -> bool {
    // Direct form (argv[0] is the program): analyze the joined argv.
    if script_has_network_program(&argv.join(" ")) {
        return true;
    }
    // Wrapped `sh -c '<script>'` form: analyze the script argument on its own, so
    // a SINGLE inner command (no separator to re-mark program position in the
    // joined view) is still caught.
    argv.windows(2)
        .any(|w| w[0] == "-c" && script_has_network_program(&w[1]))
}

/// Whether a shell `script` invokes a [`NETWORK_TOOLS`] program in program
/// position (command start, or after a `;`/`|`/`&`/`(`/newline separator).
/// Leading `VAR=val` assignments and benign wrapper prefixes (`sudo`/`env`/
/// `command`/`nice`/`nohup`/`sh`/`bash`) are skipped so the program token is
/// found, not the wrapper.
fn script_has_network_program(script: &str) -> bool {
    let is_sep = |c: char| matches!(c, ';' | '|' | '&' | '(' | ')' | '\n' | '`' | '{' | '}');
    let mut at_start = true;
    let mut token = String::new();
    for c in script.chars() {
        if c.is_whitespace() || is_sep(c) {
            if program_token_is_network(&mut token, &mut at_start) {
                return true;
            }
            if is_sep(c) {
                at_start = true;
            }
        } else {
            token.push(c);
        }
    }
    program_token_is_network(&mut token, &mut at_start)
}

/// Classify one finished token in the program-position walk. Consumes `token`.
/// While `at_start`, an env-assignment or wrapper is skipped (stays at start);
/// the first real program token flips `at_start` off and is matched against
/// [`NETWORK_TOOLS`]. Returns whether it matched a network tool.
fn program_token_is_network(token: &mut String, at_start: &mut bool) -> bool {
    if token.is_empty() {
        return false;
    }
    let t = std::mem::take(token);
    if !*at_start {
        return false; // an argument, not a program: ignore.
    }
    // `VAR=val` prefix or a benign wrapper: consume, remain at program start.
    if is_env_assignment(&t) || is_wrapper(&t) {
        return false;
    }
    *at_start = false;
    let base = t.rsplit('/').next().unwrap_or(&t);
    NETWORK_TOOLS.contains(&base)
}

/// A `VAR=value` shell assignment prefix (a valid env-var name before `=`).
fn is_env_assignment(tok: &str) -> bool {
    match tok.split_once('=') {
        Some((k, _)) => !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        None => false,
    }
}

/// A benign wrapper prefix whose following token is the real program (also the
/// shells the wrap layer uses for `sh -c`, so their name isn't mistaken for the
/// program).
fn is_wrapper(tok: &str) -> bool {
    let base = tok.rsplit('/').next().unwrap_or(tok);
    matches!(
        base,
        "sudo" | "env" | "command" | "nice" | "nohup" | "sh" | "bash" | "dash" | "zsh" | "time"
    )
}

/// Environment variables forwarded verbatim into the sandbox.
///
/// # Threat model
///
/// The wrapped command is UNTRUSTED (it's an AI-driven tool or arbitrary binary)
/// and it has proxy egress, so any operator secret reaching its environment can
/// be exfiltrated over the wire. The host environment of the `burpwn` operator
/// routinely carries cloud/API credentials (`ANTHROPIC_API_KEY`, `AWS_*`,
/// `GITHUB_TOKEN`, `OPENAI_API_KEY`, …), `SSH_AUTH_SOCK`, etc. We therefore
/// forward an explicit ALLOWLIST of benign, behaviour-shaping variables and drop
/// everything else (deny-by-default). Variables matching [`ENV_ALLOWLIST_PREFIXES`]
/// (locale `LC_*` and proxy passthrough) are also forwarded.
///
/// Note: the CA-trust env (`SSL_CERT_FILE`/`SSL_CERT_DIR`) is injected by the
/// runtime itself, so it is deliberately NOT forwarded from the host here.
const ENV_ALLOWLIST: &[&str] = &[
    // Core shell/locale identity the wrapped tool expects to behave normally.
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "TZ",
    // Proxy configuration the tool may genuinely need (lower + upper forms).
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
];

/// Prefixes whose variables are also forwarded (locale `LC_*`). `BURPWN_*` is
/// intentionally NOT bulk-forwarded here: only `BURPWN_EXEC_ID`, added by
/// [`run_exec`] after building the spec, is exposed to the child.
const ENV_ALLOWLIST_PREFIXES: &[&str] = &["LC_"];

/// Filter a host environment down to the [`ENV_ALLOWLIST`] (+ prefixes),
/// dropping operator secrets so the untrusted wrapped tool never sees them.
/// Factored out as a pure helper so it can be unit-tested without touching the
/// real process environment.
fn filtered_env(vars: impl Iterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.filter(|(k, _)| {
        ENV_ALLOWLIST.contains(&k.as_str())
            || ENV_ALLOWLIST_PREFIXES.iter().any(|p| k.starts_with(p))
    })
    .collect()
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
    // ALLOWLIST: forward only a safe set of host env vars into the sandbox; the
    // untrusted wrapped tool (which has proxy egress) must never see operator
    // secrets. See [`ENV_ALLOWLIST`] for the threat model.
    let env = filtered_env(std::env::vars());

    ExecSpec {
        argv,
        workdir: std::env::current_dir().unwrap_or_else(|_| ".".into()),
        env,
        proxy_sock: paths.proxy_sock(session),
        proxy_tcp_port: NETNS_TCP_PORT,
        proxy_dns_port: NETNS_DNS_PORT,
        ca_path: paths.ca_pem(),
        // Defaults; `run_exec` overrides these per invocation so the proxy
        // attributes captures to the right exec/workspace at capture time.
        exec_id: String::new(),
        workspace_id: 1,
        timeout,
        inherit_stdio,
    }
}

/// Run one `exec` against the provided runtime. Pure orchestration: the caller
/// is responsible for ensuring the daemon is up (so tests can skip it).
///
/// Attribution is EXACT and per-connection: the `exec_id` + `workspace_id` are
/// carried in the SCM wire header for every connection this command makes, so
/// the proxy stamps each captured flow at capture time. After the command
/// finishes we simply query the flows stamped with this `exec_id` — concurrent
/// execs never cross-attribute (unlike a time-window guess).
pub async fn run_exec(
    paths: &Paths,
    session: &str,
    workspace_id: i64,
    runtime: Arc<dyn SandboxRuntime>,
    argv: Vec<String>,
    timeout: Option<Duration>,
    inherit_stdio: bool,
) -> Result<ExecResult> {
    let exec_id = new_exec_id();
    // Classify + record the command line BEFORE the argv is moved into the spec,
    // for capture-completeness telemetry (`session stats`).
    let network_facing = is_network_facing(&argv);
    let cmd_line = argv.join(" ");
    let mut spec = build_spec(paths, session, argv, timeout, inherit_stdio);
    // The proxy stamps flows from this run with these, via the wire header.
    spec.exec_id = exec_id.clone();
    spec.workspace_id = workspace_id;
    // Also expose the id in the child's env (harmless): tools may read it.
    spec.env.push(("BURPWN_EXEC_ID".into(), exec_id.clone()));

    let outcome = runtime
        .run(spec)
        .await
        .context("running command in sandbox")?;

    // Give the daemon's async writer a beat to flush the last flows it recorded.
    tokio::time::sleep(ATTRIBUTE_GRACE).await;

    let captured_request_ids = flows_for_exec(paths, session, &exec_id)
        .await
        .unwrap_or_default();

    // Capture-completeness telemetry: a clearly network-facing command that
    // produced ZERO new flows almost certainly had its traffic escape capture
    // (e.g. the agent's hook silently no-op'd, so the command never actually ran
    // through `burpwn exec`). Warn — conservatively, only for network tools — so
    // this failure mode is no longer silent. Record every exec regardless so
    // `session stats` can surface the exec-vs-capture ratio.
    let capture_warning = if network_facing && captured_request_ids.is_empty() {
        let msg = format!(
            "network-facing command captured ZERO flows; traffic likely escaped \
             capture (is the agent hook rewriting through `burpwn exec`? run \
             `burpwn init --check`): {cmd_line}"
        );
        tracing::warn!(exec_id = %exec_id, cmd = %cmd_line, "{msg}");
        Some(msg)
    } else {
        None
    };
    record_exec_telemetry(
        paths,
        session,
        &exec_id,
        &cmd_line,
        network_facing,
        captured_request_ids.len() as i64,
    )
    .await;

    Ok(ExecResult {
        exec_id,
        exit_code: outcome.exit_code,
        captured_request_ids,
        outcome,
        capture_warning,
    })
}

/// Record one capture-completeness telemetry row (best-effort; a telemetry write
/// failure must never fail the exec). Opens the session store the same way
/// [`flows_for_exec`] does.
async fn record_exec_telemetry(
    paths: &Paths,
    session: &str,
    exec_id: &str,
    cmd: &str,
    network_facing: bool,
    flow_count: i64,
) {
    use burpwn_store::model::NewExecRecord;
    let db = paths.session_db(session);
    if !db.exists() {
        return;
    }
    let Ok(store) = Store::open(&db) else {
        return;
    };
    let _ = store
        .writer()
        .insert_exec(NewExecRecord {
            exec_id: exec_id.to_string(),
            cmd: cmd.to_string(),
            network_facing,
            flow_count,
            created_at: now_millis(),
        })
        .await;
}

/// The flow ids stamped with `exec_id` (the proxy attributes at capture time).
/// Opening the store is cheap; an absent db means nothing was captured.
async fn flows_for_exec(paths: &Paths, session: &str, exec_id: &str) -> Result<Vec<i64>> {
    let db = paths.session_db(session);
    if !db.exists() {
        return Ok(Vec::new());
    }
    let store = Store::open(&db)?;
    let ids = store.reader().flow_ids_for_exec(exec_id)?;
    Ok(ids)
}

/// Render an [`ExecResult`] to the JSON envelope value. A capture-completeness
/// `warning` is included only when set (network-facing command, zero captures).
pub fn exec_envelope(result: &ExecResult) -> Envelope {
    let mut data = json!({
        "exit_code": result.exit_code,
        "exec_id": result.exec_id,
        "captured_request_ids": result.captured_request_ids,
    });
    if let Some(w) = &result.capture_warning {
        data["warning"] = json!(w);
    }
    Envelope::ok(data)
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
    use burpwn_store::model::{FlowStart, Protocol};

    /// The zero-flow heuristic classifier: network tools (curl/wget/…) flag as
    /// network-facing (→ warn on zero captures); benign commands (ls/git/…) do
    /// not (→ never a false alarm), including inside a wrapped `sh -c` script.
    #[test]
    fn network_facing_classifier_is_conservative() {
        // Bare network tools.
        assert!(is_network_facing(&["curl".into(), "https://x".into()]));
        assert!(is_network_facing(&["wget".into(), "https://x".into()]));
        // Wrapped `sh -c` compound — the actual exec shape hooks produce.
        assert!(is_network_facing(&[
            "sh".into(),
            "-c".into(),
            "curl https://a && echo done".into(),
        ]));
        assert!(is_network_facing(&[
            "sh".into(),
            "-c".into(),
            "nmap -sV target".into(),
        ]));
        // Path-qualified tool and a `sudo` wrapper prefix.
        assert!(is_network_facing(&["/usr/bin/curl".into(), "x".into()]));
        assert!(is_network_facing(&[
            "sh".into(),
            "-c".into(),
            "sudo wget https://x".into(),
        ]));

        // Benign commands must NOT flag (no false alarm on ls / git / cat).
        assert!(!is_network_facing(&["ls".into(), "-la".into()]));
        assert!(!is_network_facing(&["git".into(), "status".into()]));
        assert!(!is_network_facing(&["echo".into(), "hello world".into()]));
        assert!(!is_network_facing(&["python3".into(), "script.py".into()]));
        // A network tool as an ARGUMENT (not program position) must NOT flag —
        // this is the conservative property that avoids false alarms.
        assert!(!is_network_facing(&[
            "sh".into(),
            "-c".into(),
            "cat notes.txt | grep curl".into(),
        ]));
        assert!(!is_network_facing(&["grep".into(), "curl".into(), "f".into()]));
    }

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

    /// The env ALLOWLIST forwards benign vars (PATH, LC_*, proxy config) into
    /// the sandbox but DROPS operator secrets (AWS/cloud/API credentials), which
    /// the untrusted wrapped tool with proxy egress could otherwise exfiltrate.
    #[test]
    fn filtered_env_allowlists_safe_vars_and_drops_secrets() {
        let host = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/op".to_string()),
            ("LC_ALL".to_string(), "C".to_string()),
            (
                "https_proxy".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ),
            // Secrets that must NOT cross into the sandbox.
            ("AWS_SECRET_ACCESS_KEY".to_string(), "shh".to_string()),
            ("ANTHROPIC_API_KEY".to_string(), "sk-secret".to_string()),
            ("GITHUB_TOKEN".to_string(), "ghp_secret".to_string()),
            ("SSH_AUTH_SOCK".to_string(), "/run/agent".to_string()),
            // CA-trust env is injected by the runtime, not forwarded from host.
            ("SSL_CERT_FILE".to_string(), "/etc/ca.pem".to_string()),
        ];
        let out = filtered_env(host.into_iter());
        let has = |k: &str| out.iter().any(|(n, _)| n == k);

        assert!(has("PATH"));
        assert!(has("HOME"));
        assert!(has("LC_ALL"));
        assert!(has("https_proxy"));

        assert!(!has("AWS_SECRET_ACCESS_KEY"));
        assert!(!has("ANTHROPIC_API_KEY"));
        assert!(!has("GITHUB_TOKEN"));
        assert!(!has("SSH_AUTH_SOCK"));
        assert!(!has("SSL_CERT_FILE"));
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
            DEFAULT_WORKSPACE_ID,
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

    /// `--workspace foo` resolves to a freshly-created workspace id, and a second
    /// resolution of the same name returns that same id (no duplicate created).
    #[tokio::test]
    async fn resolve_workspace_creates_then_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        // Touch the store so the db file exists.
        drop(Store::open(paths.session_db("default")).unwrap());

        // Absent name resolves to the default id without creating anything.
        let def = resolve_workspace_id(&paths, "default", None).await.unwrap();
        assert_eq!(def, DEFAULT_WORKSPACE_ID);

        let id = resolve_workspace_id(&paths, "default", Some("recon"))
            .await
            .unwrap();
        assert!(id >= 1);
        let again = resolve_workspace_id(&paths, "default", Some("recon"))
            .await
            .unwrap();
        assert_eq!(id, again);

        let store = Store::open(paths.session_db("default")).unwrap();
        let names: Vec<String> = store
            .reader()
            .list_workspaces()
            .unwrap()
            .into_iter()
            .map(|w| w.name)
            .collect();
        assert_eq!(names.iter().filter(|n| *n == "recon").count(), 1);
    }

    /// `flows_for_exec` returns exactly the flows the proxy stamped with this
    /// exec_id (at capture time) — and ignores flows from other execs.
    #[tokio::test]
    async fn flows_for_exec_returns_only_matching_exec() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();

        let store = Store::open(paths.session_db("default")).unwrap();
        let w = store.writer();
        let mk = |exec: Option<&str>| FlowStart {
            workspace_id: 1,
            ts_start: now_millis(),
            exec_id: exec.map(Into::into),
            client_addr: "127.0.0.1:1".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: 443,
            sni: Some("x".into()),
            scheme: "https".into(),
            protocol: Protocol::H1,
            intercepted: false,
        };
        let mine1 = w.flow_start(mk(Some("exec-mine"))).await.unwrap();
        let _other = w.flow_start(mk(Some("exec-other"))).await.unwrap();
        let mine2 = w.flow_start(mk(Some("exec-mine"))).await.unwrap();
        let _unattributed = w.flow_start(mk(None)).await.unwrap();
        drop(w);
        drop(store);

        let ids = flows_for_exec(&paths, "default", "exec-mine")
            .await
            .unwrap();
        assert_eq!(ids, vec![mine1, mine2]);
    }
}
