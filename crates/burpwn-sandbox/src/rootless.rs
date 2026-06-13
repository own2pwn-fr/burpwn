//! The production rootless [`SandboxRuntime`].
//!
//! ## Mechanism (validated end-to-end on Fedora 43 / kernel 6.17, RUN AS THE
//! UNPRIVILEGED USER — do not redesign)
//!
//! 1. `fork()`. The CHILD calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)` (we need
//!    only the user namespace for scoped `CAP_NET_ADMIN` and the network
//!    namespace for isolation; bwrap handles mount/pid isolation for the
//!    command). It then signals the parent and blocks waiting for the maps.
//! 2. The PARENT writes `/proc/<child>/uid_map = "0 <hostuid> 1"`,
//!    `/proc/<child>/setgroups = "deny"`, `/proc/<child>/gid_map =
//!    "0 <hostgid> 1"` — mapping the caller's uid→0 inside the new userns. This
//!    grants `CAP_NET_ADMIN` SCOPED TO THE CHILD's netns, so `ip`/`nft` succeed
//!    rootless inside it. The write is permitted ONLY after the child's unshare
//!    lands, hence the handshake (writing earlier races → EPERM).
//! 3. The CHILD does NO heavy work in the forked image (it was forked from a
//!    multithreaded tokio process, so spawning subprocesses there fails — glibc
//!    locks held by other threads at fork time; observed as `ip: ENOMEM`).
//!    Instead it `execve`s itself as `burpwn __netns-agent`
//!    ([`netns_agent_main`]). That FRESH, single-threaded image sets up the
//!    netns with the EXACT sequence the spike proved (a dummy `burp0` + default
//!    route is essential for a sane source address), loads the [`crate::nft`]
//!    REDIRECT ruleset, binds the in-netns acceptor (`127.0.0.1:proxy_tcp_port`,
//!    recovers `SO_ORIGINAL_DST`, fd-passes each client to the host proxy over
//!    `proxy_sock`), then forks `bwrap` (NO `--unshare-net`: it inherits our
//!    netns) for the user command while the agent keeps the acceptor alive. CA
//!    env vars are injected so HTTPS MITM is trusted.
//! 4. Teardown is RAII: when the command exits the acceptor is stopped, the
//!    processes reaped, and the netns + nft ruleset are freed when the namespace
//!    fds drop.
//!
//! ## CONFIRMED CONSTRAINT
//!
//! The host (init userns, unprivileged) CANNOT `setns` into the child userns's
//! netns (EPERM). So the acceptor MUST live INSIDE the child userns and reach
//! the host proxy over a unix socket with SCM_RIGHTS fd-passing (see
//! [`crate::wire`] for the exact wire format).
//!
//! ## CI gating
//!
//! The privileged paths are GATED behind [`preflight`]: [`RootlessRuntime::run`]
//! returns [`SandboxError::Preflight`] when the host lacks unprivileged userns /
//! bwrap / nft / ip. The pure helpers ([`build_bwrap_argv`], [`uid_map_line`],
//! [`gid_map_line`]) ARE unit-tested in CI; the namespace creation is behind an
//! `#[ignore]`d integration test (needs a real unprivileged-userns host).

use std::path::Path;

use async_trait::async_trait;

use crate::nft::redirect_ruleset;
use crate::runtime::{ExecOutcome, ExecSpec, SandboxError, SandboxRuntime};

/// argv[1] value the rootless runtime re-execs itself with: the binary's
/// `main` must route this to [`netns_agent_main`] BEFORE clap parsing.
pub const NETNS_AGENT_ARG: &str = "__netns-agent";

/// Environment variable carrying the JSON-serialized [`ExecSpec`] to the
/// re-exec'd `__netns-agent` helper.
pub const SPEC_ENV: &str = "BURPWN_NETNS_SPEC";

/// Entry point for the re-exec'd `__netns-agent` helper process. The binary's
/// `main` calls this (and `std::process::exit`s with the returned code) when
/// invoked as `burpwn __netns-agent`. Runs in a clean single-threaded image
/// inside the userns+netns the parent created. See [`privileged::netns_agent_main`].
pub fn netns_agent_main() -> i32 {
    privileged::netns_agent_main()
}

/// Result of probing the host for the capabilities the rootless runtime needs.
/// Backs the `burpwn doctor` CLI command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    /// `/proc/sys/kernel/unprivileged_userns_clone` is enabled (or absent,
    /// which means always-on on this kernel).
    pub userns_enabled: bool,
    /// A `/etc/subuid` entry exists for the current user (informational — the
    /// scoped-CAP_NET_ADMIN design maps a single uid and does NOT require a
    /// subuid range, but `bwrap`/podman setups commonly want it).
    pub subuid_present: bool,
    /// `bwrap` is on `PATH`.
    pub bwrap_present: bool,
    /// `nft` is on `PATH`.
    pub nft_present: bool,
    /// `ip` is on `PATH`.
    pub ip_present: bool,
}

impl Preflight {
    /// True iff every MANDATORY capability is present (userns + the three
    /// binaries). `subuid_present` is informational and not required by the
    /// single-uid mapping design.
    pub fn is_ok(&self) -> bool {
        self.userns_enabled && self.bwrap_present && self.nft_present && self.ip_present
    }

    /// A human-readable summary of what is missing (empty string when ok).
    pub fn missing_summary(&self) -> String {
        let mut missing = Vec::new();
        if !self.userns_enabled {
            missing.push("unprivileged user namespaces (sysctl)");
        }
        if !self.bwrap_present {
            missing.push("bwrap binary");
        }
        if !self.nft_present {
            missing.push("nft binary");
        }
        if !self.ip_present {
            missing.push("ip binary");
        }
        missing.join(", ")
    }
}

/// Probe the host for the capabilities the rootless runtime needs. Pure I/O
/// (reads a sysctl + `which`-style PATH lookups); never creates a namespace, so
/// it is safe to call anywhere (including CI — it just reports `false`s).
pub fn doctor() -> Preflight {
    Preflight {
        userns_enabled: userns_clone_enabled(),
        subuid_present: subuid_entry_present(),
        bwrap_present: binary_on_path("bwrap"),
        nft_present: binary_on_path("nft"),
        ip_present: binary_on_path("ip"),
    }
}

/// On most modern kernels unprivileged userns is on by default and the sysctl
/// may not exist; treat a missing sysctl as "enabled".
fn userns_clone_enabled() -> bool {
    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(v) => v.trim() != "0",
        // Absent sysctl => kernel does not gate it => enabled.
        Err(_) => true,
    }
}

fn subuid_entry_present() -> bool {
    let user = std::env::var("USER").unwrap_or_default();
    let uid = unsafe { libc::getuid() }.to_string();
    match std::fs::read_to_string("/etc/subuid") {
        Ok(contents) => contents.lines().any(|line| {
            let key = line.split(':').next().unwrap_or("");
            (!user.is_empty() && key == user) || key == uid
        }),
        Err(_) => false,
    }
}

fn binary_on_path(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(name);
        candidate.is_file() && is_executable(&candidate)
    })
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The `/proc/<pid>/uid_map` line mapping the caller's host uid to 0 inside the
/// new userns (a single-uid map — this is the scoped-CAP_NET_ADMIN trick).
pub fn uid_map_line(host_uid: u32) -> String {
    format!("0 {host_uid} 1")
}

/// The `/proc/<pid>/gid_map` line mapping the caller's host gid to 0.
pub fn gid_map_line(host_gid: u32) -> String {
    format!("0 {host_gid} 1")
}

/// The CA-trust environment variables injected into the sandbox so that every
/// common TLS client trusts the burpwn MITM CA. Returned as `(KEY, VALUE)`
/// pairs given the in-sandbox CA path; `SSL_CERT_DIR` is deliberately emptied so
/// clients fall back to the single `SSL_CERT_FILE`.
pub fn ca_env_vars(ca_path: &str) -> Vec<(String, String)> {
    vec![
        ("SSL_CERT_FILE".into(), ca_path.into()),
        ("SSL_CERT_DIR".into(), String::new()),
        ("REQUESTS_CA_BUNDLE".into(), ca_path.into()),
        ("CURL_CA_BUNDLE".into(), ca_path.into()),
        ("NODE_EXTRA_CA_CERTS".into(), ca_path.into()),
        ("GIT_SSL_CAINFO".into(), ca_path.into()),
        ("AWS_CA_BUNDLE".into(), ca_path.into()),
    ]
}

/// Build the full `bwrap` argv for the user command. PURE (string-only) so it
/// is unit-tested. NOTE: `--unshare-net` is intentionally ABSENT — bwrap must
/// inherit the netns we created so the REDIRECT ruleset applies.
pub fn build_bwrap_argv(spec: &ExecSpec) -> Vec<String> {
    let workdir = spec.workdir.to_string_lossy().to_string();
    let ca = spec.ca_path.to_string_lossy().to_string();
    let mut args: Vec<String> = Vec::new();
    let push = |args: &mut Vec<String>, parts: &[&str]| {
        args.extend(parts.iter().map(|s| s.to_string()));
    };

    push(&mut args, &["bwrap"]);
    push(&mut args, &["--ro-bind", "/", "/"]);
    push(&mut args, &["--dev", "/dev"]);
    push(&mut args, &["--proc", "/proc"]);
    push(&mut args, &["--tmpfs", "/tmp"]);
    // The command's working directory is bind-mounted rw.
    args.extend([
        "--bind".to_string(),
        workdir.clone(),
        workdir.clone(),
        "--chdir".to_string(),
        workdir,
    ]);
    // The CA is bound read-only and trusted via the standard env vars.
    args.extend(["--ro-bind".to_string(), ca.clone(), ca.clone()]);
    for (k, v) in ca_env_vars(&ca) {
        args.extend(["--setenv".to_string(), k, v]);
    }
    // Caller-supplied extra env.
    for (k, v) in &spec.env {
        args.extend(["--setenv".to_string(), k.clone(), v.clone()]);
    }
    push(&mut args, &["--die-with-parent", "--unshare-pid"]);
    args.push("--".to_string());
    args.extend(spec.argv.iter().cloned());
    args
}

/// The exact in-netns network setup commands the spike proved, parameterised by
/// the nft ruleset. PURE (returns the argv lists + the ruleset script) so the
/// sequence is unit-testable; [`RootlessRuntime`] feeds these to `ip`/`nft`
/// inside the child. The dummy `burp0` + default route give a sane SOURCE
/// address (without it the reply path resolves to 0.0.0.0 and curl times out).
pub fn netns_setup_commands(tcp_port: u16, dns_port: u16) -> (Vec<Vec<String>>, String) {
    let ip = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let cmds = vec![
        ip(&["ip", "link", "set", "lo", "up"]),
        ip(&["ip", "link", "add", "burp0", "type", "dummy"]),
        ip(&["ip", "addr", "add", "10.99.0.1/32", "dev", "burp0"]),
        ip(&["ip", "link", "set", "burp0", "up"]),
        ip(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            "10.99.0.1",
            "dev",
            "burp0",
        ]),
    ];
    (cmds, redirect_ruleset(tcp_port, dns_port))
}

/// Production rootless runtime. Stateless: each [`SandboxRuntime::run`] creates
/// and tears down its own namespaces. Teardown is RAII at the kernel level — when
/// the forked child exits, the kernel reclaims its netns (and with it the nft
/// ruleset and the in-netns acceptor), so there is no per-runtime state to guard.
#[derive(Debug, Default)]
pub struct RootlessRuntime {
    _private: (),
}

impl RootlessRuntime {
    /// Build a new rootless runtime.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SandboxRuntime for RootlessRuntime {
    async fn run(&self, spec: ExecSpec) -> Result<ExecOutcome, SandboxError> {
        let pf = doctor();
        if !pf.is_ok() {
            return Err(SandboxError::Preflight(pf.missing_summary()));
        }
        // The actual privileged execution (fork + unshare + uid_map + netns +
        // bwrap) runs in a blocking task because it is heavily syscall-bound and
        // must not block the async reactor. It is implemented in
        // `privileged::run_command`, which only ever runs on a host that passed
        // preflight (so never in CI).
        tokio::task::spawn_blocking(move || privileged::run_command(spec))
            .await
            .map_err(|e| SandboxError::Runtime(format!("join error: {e}")))?
    }
}

/// The privileged implementation. Everything here needs the scoped
/// `CAP_NET_ADMIN` from the userns unshare + the `ip`/`nft`/`bwrap` binaries, so
/// it NEVER runs under CI (preflight gates it). It is plain syscall + process
/// glue; the testable logic lives in the pure helpers above and is unit-tested.
mod privileged {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    use nix::sched::{unshare, CloneFlags};
    use nix::sys::socket::sockopt::OriginalDst;
    use nix::sys::socket::{getsockopt, sendmsg, ControlMessage, MsgFlags};
    use nix::unistd::{fork, ForkResult};

    use crate::runtime::{ExecOutcome, ExecSpec, SandboxError};
    use crate::wire::{PassedConn, L4};

    use super::{gid_map_line, netns_setup_commands, uid_map_line};

    /// Run one command inside fresh namespaces and return its outcome. Blocking.
    ///
    /// Structure (the key to correctness): the forked child does ONLY
    /// async-signal-safe work (unshare, two pipe syscalls, execve). All of the
    /// heavy lifting — spawning `ip`/`nft`, binding the acceptor, forking bwrap —
    /// happens AFTER the child `execve`s the clean [`netns_agent_main`] image.
    /// Doing that work directly in the forked child of a multithreaded tokio
    /// process is unsound: glibc locks held by other threads at fork time make
    /// `std::process::Command` spawns fail (observed as `ip: ENOMEM`).
    pub fn run_command(spec: ExecSpec) -> Result<ExecOutcome, SandboxError> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        // Build the helper's argv + envp BEFORE forking (allocation in the
        // multithreaded parent is safe; in the forked child it is not).
        let spec_json = serde_json::to_string(&spec)
            .map_err(|e| SandboxError::Runtime(format!("serialize spec: {e}")))?;
        let exe = CString::new("/proc/self/exe").expect("no NUL");
        let argv: Vec<CString> = vec![
            CString::new("burpwn").expect("no NUL"),
            CString::new(super::NETNS_AGENT_ARG).expect("no NUL"),
        ];
        let mut envp: Vec<CString> = std::env::vars_os()
            .filter_map(|(k, v)| {
                if k.as_bytes() == super::SPEC_ENV.as_bytes() {
                    return None; // never inherit a stale spec var
                }
                let mut buf = k.as_bytes().to_vec();
                buf.push(b'=');
                buf.extend_from_slice(v.as_bytes());
                CString::new(buf).ok()
            })
            .collect();
        envp.push(
            CString::new(format!("{}={}", super::SPEC_ENV, spec_json))
                .map_err(|e| SandboxError::Runtime(format!("spec env: {e}")))?,
        );

        // Two pipes form a handshake. `ready`: child -> parent ("I have entered
        // the new userns"). `go`: parent -> child ("your uid/gid maps are
        // written, proceed"). The ordering is load-bearing: the kernel only
        // permits the unprivileged single-uid map write AFTER the child has
        // actually unshared CLONE_NEWUSER. Writing the map immediately after
        // fork (before the child's unshare lands) races and fails with EPERM.
        let (ready_r, ready_w) =
            nix::unistd::pipe().map_err(|e| SandboxError::Runtime(format!("pipe: {e}")))?;
        let (go_r, go_w) =
            nix::unistd::pipe().map_err(|e| SandboxError::Runtime(format!("pipe: {e}")))?;

        let host_uid = nix::unistd::getuid().as_raw();
        let host_gid = nix::unistd::getgid().as_raw();

        // SAFETY: between fork and execve the child only calls async-signal-safe
        // operations (unshare, write, read, execve); it does not allocate or
        // touch the tokio runtime.
        match unsafe { fork() }.map_err(|e| SandboxError::Runtime(format!("fork: {e}")))? {
            ForkResult::Child => {
                drop(ready_r);
                drop(go_w);
                // We need only NEWUSER (for scoped CAP_NET_ADMIN) + NEWNET (the
                // isolated network). bwrap handles mount/pid isolation for the
                // command itself.
                if unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).is_err() {
                    unsafe { libc::_exit(126) };
                }
                let _ = nix::unistd::write(&ready_w, &[1u8]);
                let mut b = [0u8; 1];
                let _ = nix::unistd::read(go_r.as_raw_fd(), &mut b);
                // Become the clean single-threaded helper image. uid/gid maps
                // are now in place, so we are uid 0 in the userns.
                let _ = nix::unistd::execve(&exe, &argv, &envp);
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child } => {
                drop(ready_w);
                drop(go_r);
                let res = parent_setup_maps(child, host_uid, host_gid, ready_r, go_w);
                if let Err(e) = res {
                    let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                    let _ = nix::sys::wait::waitpid(child, None);
                    return Err(e);
                }
                reap_child(child, &spec)
            }
        }
    }

    /// Entry point of the re-exec'd `__netns-agent` helper. Runs in a FRESH,
    /// single-threaded process image inside the userns+netns the parent set up,
    /// so spawning `ip`/`nft`/`bwrap` is safe. Reads the [`ExecSpec`] from the
    /// environment, configures the netns, binds the acceptor, forks the command
    /// under bwrap, and serves connection hand-offs until it exits. Returns the
    /// command's exit code (the binary calls `std::process::exit` with it).
    pub fn netns_agent_main() -> i32 {
        let spec: ExecSpec = match std::env::var(super::SPEC_ENV)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(s) => s,
            None => {
                eprintln!("burpwn __netns-agent: missing/invalid {}", super::SPEC_ENV);
                return 125;
            }
        };

        if let Err(e) = setup_netns(&spec) {
            eprintln!("burpwn __netns-agent: netns setup failed: {e}");
            return 124;
        }

        let tcp_port = spec.proxy_tcp_port;
        let listener = match TcpListener::bind(("127.0.0.1", tcp_port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("burpwn __netns-agent: bind 127.0.0.1:{tcp_port} failed: {e}");
                return 123;
            }
        };

        // Bind the in-netns DNS socket (the nftables `udp/53` redirect target)
        // and hand it to the host proxy ONCE — the host serves DNS over it (it
        // has real upstream connectivity; the netns has none). Keep our copy
        // open for the command's lifetime so the kernel socket stays alive.
        let dns_sock = std::net::UdpSocket::bind(("127.0.0.1", spec.proxy_dns_port)).ok();
        if let Some(ref udp) = dns_sock {
            let meta = PassedConn {
                dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                dst_port: 53,
                l4: L4::Udp,
            };
            if let Err(e) = send_fd(udp.as_raw_fd(), meta, &spec.proxy_sock) {
                eprintln!("burpwn __netns-agent: DNS socket hand-off failed: {e}");
            }
        }

        // Fork the command under bwrap as a separate process — the acceptor must
        // live in a process that does NOT exec (exec replaces the whole image,
        // killing the listener the instant the command starts).
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                drop(listener);
                exec_bwrap(&spec);
                unsafe { libc::_exit(127) };
            }
            Ok(ForkResult::Parent { child: cmd_pid }) => {
                let proxy_sock = spec.proxy_sock.clone();
                let stop = Arc::new(AtomicBool::new(false));
                let stop_thread = Arc::clone(&stop);
                let acceptor =
                    thread::spawn(move || run_acceptor(listener, &proxy_sock, &stop_thread));

                let code = match nix::sys::wait::waitpid(cmd_pid, None) {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, c)) => c,
                    Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                    _ => 127,
                };
                stop.store(true, Ordering::Relaxed);
                // Nudge the blocking accept() so the loop observes `stop`.
                let _ = std::net::TcpStream::connect(("127.0.0.1", tcp_port));
                let _ = acceptor.join();
                code
            }
            Err(e) => {
                eprintln!("burpwn __netns-agent: command fork failed: {e}");
                122
            }
        }
    }

    /// PARENT: wait until the child has entered its new userns, write the
    /// uid/gid maps, then signal the child to proceed (by closing `go_w`).
    fn parent_setup_maps(
        child: nix::unistd::Pid,
        host_uid: u32,
        host_gid: u32,
        ready_r: std::os::fd::OwnedFd,
        go_w: std::os::fd::OwnedFd,
    ) -> Result<(), SandboxError> {
        // Block until the child signals it has unshared CLONE_NEWUSER. A
        // zero-length read (EOF) means the child died before signalling.
        let mut ready = std::fs::File::from(ready_r);
        let mut buf = [0u8; 1];
        match ready.read(&mut buf) {
            Ok(0) => {
                return Err(SandboxError::Runtime(
                    "child exited before entering the user namespace (unshare failed)".into(),
                ))
            }
            Ok(_) => {}
            Err(e) => return Err(SandboxError::Runtime(format!("ready pipe: {e}"))),
        }

        let pid = child.as_raw();
        write_proc(pid, "uid_map", &uid_map_line(host_uid))?;
        // setgroups must be denied before writing gid_map in a single-uid userns.
        write_proc(pid, "setgroups", "deny")?;
        write_proc(pid, "gid_map", &gid_map_line(host_gid))?;
        // Closing `go_w` (drop) signals the child to proceed.
        drop(go_w);
        Ok(())
    }

    fn write_proc(pid: i32, file: &str, contents: &str) -> Result<(), SandboxError> {
        let path = format!("/proc/{pid}/{file}");
        std::fs::write(&path, contents)
            .map_err(|e| SandboxError::Runtime(format!("write {path}: {e}")))
    }

    /// Run the EXACT spike-proven `ip` sequence then load the nft ruleset.
    fn setup_netns(spec: &ExecSpec) -> Result<(), SandboxError> {
        let (cmds, ruleset) = netns_setup_commands(spec.proxy_tcp_port, spec.proxy_dns_port);
        for argv in &cmds {
            run_ok(argv)?;
        }
        // nft -f - <<< ruleset
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::Runtime(format!("nft spawn: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .map_err(|e| SandboxError::Runtime(format!("nft stdin: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| SandboxError::Runtime(format!("nft wait: {e}")))?;
        if !out.status.success() {
            return Err(SandboxError::Runtime(format!(
                "nft load failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    fn run_ok(argv: &[String]) -> Result<(), SandboxError> {
        let out = Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| SandboxError::Runtime(format!("{}: {e}", argv[0])))?;
        if !out.status.success() {
            return Err(SandboxError::Runtime(format!(
                "{} failed: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// The in-netns acceptor: bind `127.0.0.1:tcp_port`, accept clients, recover
    /// `SO_ORIGINAL_DST`, and hand each client fd to the host proxy over the
    /// unix socket using SCM_RIGHTS + the [`crate::wire`] header.
    fn run_acceptor(listener: TcpListener, proxy_sock: &std::path::Path, stop: &AtomicBool) {
        for client in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(client) = client else { continue };
            if let Err(e) = handoff(&client, proxy_sock) {
                tracing::warn!(error = %e, "burpwn sandbox: connection hand-off failed");
            }
            // The host proxy now owns a dup of the fd; drop our copy.
            drop(client);
        }
    }

    /// Recover the original destination and pass the client fd to the host proxy.
    fn handoff(
        client: &std::net::TcpStream,
        proxy_sock: &std::path::Path,
    ) -> Result<(), SandboxError> {
        let orig = getsockopt(client, OriginalDst)
            .map_err(|e| SandboxError::Runtime(format!("SO_ORIGINAL_DST: {e}")))?;
        // sockaddr_in fields are network byte order.
        let dst_port = u16::from_be(orig.sin_port);
        let dst_ip = std::net::Ipv4Addr::from(u32::from_be(orig.sin_addr.s_addr));
        let meta = PassedConn {
            dst_ip: std::net::IpAddr::V4(dst_ip),
            dst_port,
            l4: L4::Tcp,
        };
        send_fd(client.as_raw_fd(), meta, proxy_sock)
    }

    /// Pass one fd (TCP client socket, or the in-netns UDP/53 socket) to the
    /// host proxy over `proxy_sock` via SCM_RIGHTS + the [`crate::wire`] header.
    fn send_fd(
        fd: RawFd,
        meta: PassedConn,
        proxy_sock: &std::path::Path,
    ) -> Result<(), SandboxError> {
        let header = meta.encode();
        let proxy = UnixStream::connect(proxy_sock)
            .map_err(|e| SandboxError::Io(format!("connect proxy_sock: {e}")))?;
        let fds: [RawFd; 1] = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];
        let iov = [std::io::IoSlice::new(&header)];
        // No destination address (the unix socket is already connected); the
        // phantom `UnixAddr` only satisfies the `SockaddrLike` bound on `None`.
        sendmsg::<nix::sys::socket::UnixAddr>(
            proxy.as_raw_fd(),
            &iov,
            &cmsg,
            MsgFlags::empty(),
            None,
        )
        .map_err(|e| SandboxError::Io(format!("sendmsg SCM_RIGHTS: {e}")))?;
        Ok(())
    }

    /// Exec bwrap, replacing the child process image. Returns only on failure.
    fn exec_bwrap(spec: &ExecSpec) {
        let argv = super::build_bwrap_argv(spec);
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        if spec.inherit_stdio {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
        // exec replaces the image; if it returns, it errored.
        let err = {
            use std::os::unix::process::CommandExt;
            cmd.exec()
        };
        tracing::error!(error = %err, "burpwn sandbox: bwrap exec failed");
    }

    /// PARENT: wait for the child (bwrap) to exit and build the outcome.
    ///
    /// NOTE: in `inherit_stdio` mode we cannot capture output (it went to the
    /// real fds), so stdout/stderr are empty by design; otherwise the child's
    /// captured pipes would be wired here. For simplicity and because the spike
    /// validated the exec-and-wait shape, capture-mode plumbing of the grandchild
    /// pipes through bwrap is handled by redirecting bwrap's stdio to temp pipes
    /// in a follow-up; today we wait and report the exit code, with captured
    /// output left to the proxy-side transcript (the real value of this sandbox).
    fn reap_child(child: nix::unistd::Pid, _spec: &ExecSpec) -> Result<ExecOutcome, SandboxError> {
        use nix::sys::wait::{waitpid, WaitStatus};
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => Ok(ExecOutcome {
                exit_code: code,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            Ok(WaitStatus::Signaled(_, sig, _)) => Ok(ExecOutcome {
                exit_code: 128 + sig as i32,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            Ok(other) => Err(SandboxError::Runtime(format!(
                "unexpected wait status: {other:?}"
            ))),
            Err(e) => Err(SandboxError::Runtime(format!("waitpid: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> ExecSpec {
        ExecSpec {
            argv: vec!["curl".into(), "-s".into(), "https://example.com".into()],
            workdir: PathBuf::from("/work"),
            env: vec![("FOO".into(), "bar".into())],
            proxy_sock: PathBuf::from("/run/burpwn/proxy.sock"),
            proxy_tcp_port: 8080,
            proxy_dns_port: 5353,
            ca_path: PathBuf::from("/etc/burpwn/ca.pem"),
            timeout: None,
            inherit_stdio: false,
        }
    }

    #[test]
    fn uid_gid_map_lines_map_single_uid_to_root() {
        assert_eq!(uid_map_line(1000), "0 1000 1");
        assert_eq!(gid_map_line(1000), "0 1000 1");
    }

    #[test]
    fn ca_env_vars_cover_common_clients_and_empty_cert_dir() {
        let env = ca_env_vars("/etc/burpwn/ca.pem");
        let map: std::collections::HashMap<_, _> = env.into_iter().collect();
        assert_eq!(map["SSL_CERT_FILE"], "/etc/burpwn/ca.pem");
        assert_eq!(map["CURL_CA_BUNDLE"], "/etc/burpwn/ca.pem");
        assert_eq!(map["NODE_EXTRA_CA_CERTS"], "/etc/burpwn/ca.pem");
        assert_eq!(map["GIT_SSL_CAINFO"], "/etc/burpwn/ca.pem");
        assert_eq!(map["AWS_CA_BUNDLE"], "/etc/burpwn/ca.pem");
        assert_eq!(map["REQUESTS_CA_BUNDLE"], "/etc/burpwn/ca.pem");
        // SSL_CERT_DIR must be emptied so clients use the single file.
        assert_eq!(map["SSL_CERT_DIR"], "");
    }

    #[test]
    fn bwrap_argv_has_required_isolation_flags() {
        let argv = build_bwrap_argv(&spec());
        let joined = argv.join(" ");
        assert_eq!(argv[0], "bwrap");
        assert!(joined.contains("--ro-bind / /"));
        assert!(joined.contains("--dev /dev"));
        assert!(joined.contains("--proc /proc"));
        assert!(joined.contains("--tmpfs /tmp"));
        assert!(joined.contains("--bind /work /work"));
        assert!(joined.contains("--ro-bind /etc/burpwn/ca.pem /etc/burpwn/ca.pem"));
        assert!(joined.contains("--die-with-parent"));
        assert!(joined.contains("--unshare-pid"));
    }

    #[test]
    fn bwrap_argv_does_not_unshare_net() {
        // CRITICAL: bwrap must inherit the netns we created so the REDIRECT
        // ruleset applies; --unshare-net would give it a fresh empty netns.
        let argv = build_bwrap_argv(&spec());
        assert!(!argv.iter().any(|a| a == "--unshare-net"));
    }

    #[test]
    fn bwrap_argv_injects_ca_and_extra_env_then_command() {
        let argv = build_bwrap_argv(&spec());
        let joined = argv.join(" ");
        assert!(joined.contains("--setenv SSL_CERT_FILE /etc/burpwn/ca.pem"));
        assert!(joined.contains("--setenv FOO bar"));
        // The user command comes after the `--` separator, last.
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(&argv[sep + 1..], &["curl", "-s", "https://example.com"]);
    }

    #[test]
    fn netns_setup_uses_exact_spike_sequence() {
        let (cmds, ruleset) = netns_setup_commands(8080, 5353);
        let lines: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        assert_eq!(lines[0], "ip link set lo up");
        assert_eq!(lines[1], "ip link add burp0 type dummy");
        assert_eq!(lines[2], "ip addr add 10.99.0.1/32 dev burp0");
        assert_eq!(lines[3], "ip link set burp0 up");
        assert_eq!(lines[4], "ip route add default via 10.99.0.1 dev burp0");
        // The ruleset is the redirect ruleset for these ports.
        assert!(ruleset.contains("meta l4proto tcp redirect to :8080"));
    }

    #[test]
    fn doctor_returns_a_struct_without_panicking() {
        // In CI most of these will be false; we only assert it does not panic
        // and that the summary is consistent with is_ok.
        let pf = doctor();
        if pf.is_ok() {
            assert!(pf.missing_summary().is_empty());
        } else {
            assert!(!pf.missing_summary().is_empty());
        }
    }

    #[test]
    fn preflight_is_ok_requires_mandatory_caps() {
        let base = Preflight {
            userns_enabled: true,
            subuid_present: false, // informational, not required
            bwrap_present: true,
            nft_present: true,
            ip_present: true,
        };
        assert!(base.is_ok());
        assert!(base.missing_summary().is_empty());

        let missing_nft = Preflight {
            nft_present: false,
            ..base.clone()
        };
        assert!(!missing_nft.is_ok());
        assert!(missing_nft.missing_summary().contains("nft"));
    }

    #[tokio::test]
    async fn run_fails_with_preflight_error_when_unavailable() {
        // On a host without the binaries this returns Preflight; on a fully
        // capable host it would actually try to run. We only assert the error
        // VARIANT when preflight is not ok (the common CI case). If a CI host
        // happens to be fully capable, skip the assertion.
        let rt = RootlessRuntime::new();
        if !doctor().is_ok() {
            let err = rt
                .run(ExecSpec::new(vec!["true".into()]))
                .await
                .unwrap_err();
            assert!(matches!(err, SandboxError::Preflight(_)));
        }
    }
}
