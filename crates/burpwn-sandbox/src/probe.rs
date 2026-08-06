//! Deep (live) sandbox probe — what [`crate::rootless::doctor`] cannot tell you.
//!
//! [`crate::rootless::Preflight`] only answers "is the *binary* on PATH?". That
//! is not the question that matters: `ip` and `nft` can both be installed and
//! still be unable to do what the sandbox needs, because the kernel lacks the
//! module behind the feature. The canonical example is **WSL2**, whose kernel
//! ships `CONFIG_DUMMY=m`, `CONFIG_NFT_REDIR=m` and `CONFIG_NF_REJECT_IPV4=m`
//! but carries **no `/lib/modules` at all** — so `ip link add … type dummy` and
//! the `redirect` nft expression fail at runtime while `burpwn doctor` happily
//! prints `=> ready`. The user then sees every `burpwn exec` die with a vague
//! "captured ZERO flows" warning and an empty `req list`.
//!
//! This module closes that gap: it creates a REAL throwaway userns+netns and
//! executes the exact same setup sequence [`crate::rootless`] uses in
//! production ([`crate::rootless::netns_setup_commands`] +
//! [`crate::nft::redirect_ruleset_with`]), one step at a time, reporting which
//! step failed and why.
//!
//! ## Shape
//!
//! Same two-process dance as the production runtime, and for the same reason:
//! the caller may be a multithreaded tokio process, so the forked child does
//! ONLY async-signal-safe work before `execve`ing a clean single-threaded image
//! of ourselves ([`netns_probe_main`], reached via the [`NETNS_PROBE_ARG`]
//! argv[1] marker). That helper runs the steps and prints a JSON
//! [`ProbeReport`] on stdout, which the host parent parses.

use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::nft::{redirect_ruleset_with, UdpAction};
use crate::rootless::{gid_map_line, netns_setup_commands, uid_map_line};

/// argv[1] value the deep probe re-execs itself with; the binary's `main` must
/// route this to [`netns_probe_main`] BEFORE clap parsing (exactly like
/// [`crate::rootless::NETNS_AGENT_ARG`]).
pub const NETNS_PROBE_ARG: &str = "__netns-probe";

/// Ports used by the throwaway probe netns. They only have to be consistent
/// within the probe (nothing ever connects to them), so we reuse the production
/// defaults rather than inventing new ones.
const PROBE_TCP_PORT: u16 = 8080;
const PROBE_DNS_PORT: u16 = 5353;

/// One executed probe step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeStep {
    /// Stable machine-readable step id (e.g. `dummy_device`).
    pub name: String,
    /// Whether the step succeeded.
    pub ok: bool,
    /// `false` when a failure only DEGRADES the sandbox instead of breaking it
    /// (today: the `nf_reject`-based QUIC fail-fast guard, which falls back to
    /// `drop`). Only required steps make [`ProbeReport::is_ok`] false.
    pub required: bool,
    /// Raw error text on failure (empty when `ok`).
    pub detail: String,
}

impl ProbeStep {
    fn ok(name: &str, required: bool) -> Self {
        Self {
            name: name.into(),
            ok: true,
            required,
            detail: String::new(),
        }
    }

    fn failed(name: &str, required: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            required,
            detail: detail.into(),
        }
    }
}

/// The result of a deep probe: the steps that ran, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    /// Executed steps, in execution order. A required failure stops the run, so
    /// the last entry is the failing one.
    pub steps: Vec<ProbeStep>,
    /// True when the host kernel identifies as WSL (drives the remediation
    /// hint — WSL cannot be fixed by installing a package).
    pub wsl: bool,
}

impl ProbeReport {
    /// True when every REQUIRED step passed (an optional failure is a
    /// degradation, not a blocker).
    pub fn is_ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok || !s.required)
    }

    /// The first required step that failed, if any.
    pub fn blocking_failure(&self) -> Option<&ProbeStep> {
        self.steps.iter().find(|s| !s.ok && s.required)
    }

    /// A one-line summary suitable for an error message.
    pub fn summary(&self) -> String {
        match self.blocking_failure() {
            Some(s) => format!("{} failed: {}", s.name, s.detail.trim()),
            None if self.steps.iter().any(|s| !s.ok) => {
                "usable (degraded — see `burpwn doctor`)".into()
            }
            None => "usable".into(),
        }
    }

    /// Remediation lines for whatever failed (empty when everything passed).
    ///
    /// Pure string logic over the report, so it is fully unit-tested: the
    /// advice must differ on WSL, where the missing pieces are kernel modules
    /// the distro cannot supply.
    pub fn remediation(&self) -> Vec<String> {
        let Some(failed) = self.blocking_failure() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match failed.name.as_str() {
            "dummy_device" => out.push(
                "the `dummy` network driver is unavailable — the sandbox needs it \
                 for the netns egress sink (`ip link add burp0 type dummy`)"
                    .into(),
            ),
            "nft_redirect" => out.push(
                "nftables cannot load the REDIRECT ruleset — the kernel is missing \
                 nf_tables NAT/redirect support (nft_redir / nft_chain_nat)"
                    .into(),
            ),
            "redirect_delivery" => out.push(
                "the REDIRECT ruleset loads but a redirected packet never reaches the \
                 loopback shim — the kernel drops the DNAT-to-127.0.0.1 packet \
                 (missing nf_nat runtime, or route_localnet disabled). DNS resolution \
                 fails inside the sandbox and every exec captures ZERO flows."
                    .into(),
            ),
            "userns" | "netns" => {
                out.push("the host refuses to create an unprivileged user/network namespace".into())
            }
            "bwrap" => out.push("bubblewrap cannot start inside the sandbox namespaces".into()),
            _ => {}
        }
        // Only the steps below depend on a loadable kernel module. The WSL
        // "no modules" blurb is reserved for THEM: printing it under a failure
        // whose module-backed steps just passed (as `redirect_delivery` does —
        // it runs after `dummy_device`/`nft_redirect`/`nft_reject` were all
        // green) tells the user their kernel can never work when it demonstrably
        // can, and sends them off building a custom kernel for nothing.
        let module_backed = matches!(
            failed.name.as_str(),
            "dummy_device" | "nft_redirect" | "nft_reject"
        );
        if module_backed && self.wsl {
            out.push(
                "this host is WSL: the Microsoft kernel ships NO loadable modules, so \
                 the `=m` features above (dummy, nft_redir, nf_reject) can never load. \
                 burpwn cannot capture traffic on a stock WSL kernel."
                    .into(),
            );
            out.push(
                "options: (1) build a WSL2 kernel with CONFIG_DUMMY/CONFIG_NFT_REDIR \
                 built in (=y) and point .wslconfig `kernel=` at it, or (2) run burpwn \
                 in a real Linux VM / on a Linux host."
                    .into(),
            );
        } else if module_backed {
            out.push(
                "make sure the matching kernel modules are installed and loadable \
                 (Debian/Ubuntu: `linux-modules-$(uname -r)`; then `sudo modprobe dummy \
                 nft_redir`)."
                    .into(),
            );
        } else if failed.name == "userns" || failed.name == "netns" {
            out.push(
                "check `sysctl kernel.unprivileged_userns_clone` (Debian) and, on \
                 Ubuntu 24.04+, `sysctl kernel.apparmor_restrict_unprivileged_userns=0`."
                    .into(),
            );
        } else if failed.name == "redirect_delivery" {
            // The module-backed steps passed, so the kernel HAS dummy/nft_redir:
            // what is left is the delivery path itself.
            out.push(
                "check that the sandbox netns can enable `net.ipv4.conf.all.route_localnet` \
                 and that `nf_nat` is available at runtime; please report this with the \
                 full `burpwn doctor` output."
                    .into(),
            );
        }
        out
    }
}

/// True when the running kernel identifies as WSL.
pub fn is_wsl() -> bool {
    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let version = std::fs::read_to_string("/proc/version").unwrap_or_default();
    osrelease_is_wsl(&osrelease) || osrelease_is_wsl(&version)
}

/// Pure predicate behind [`is_wsl`] (so it is unit-testable): WSL kernels carry
/// `microsoft` / `WSL` in `/proc/sys/kernel/osrelease` and `/proc/version`.
pub fn osrelease_is_wsl(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("microsoft") || lower.contains("wsl")
}

/// Run the deep probe: fork into a throwaway userns+netns and execute the real
/// setup sequence there, step by step.
///
/// Never panics and never leaves state behind — the namespaces are reclaimed by
/// the kernel when the probe child exits. Returns a synthetic single-step report
/// when the probe process itself could not be started.
pub fn deep_probe() -> ProbeReport {
    let wsl = is_wsl();
    match spawn_probe_child() {
        Ok(mut report) => {
            report.wsl = wsl;
            report
        }
        Err(e) => ProbeReport {
            steps: vec![ProbeStep::failed("userns", true, e)],
            wsl,
        },
    }
}

/// Entry point of the re-exec'd `__netns-probe` helper: runs INSIDE the fresh
/// userns+netns, executes the steps, prints the JSON report on stdout.
pub fn netns_probe_main() -> i32 {
    let report = ProbeReport {
        steps: run_steps(),
        // Filled in by the host parent (which is the one asked about the host).
        wsl: false,
    };
    match serde_json::to_string(&report) {
        Ok(json) => {
            println!("{json}");
            0
        }
        Err(_) => 1,
    }
}

/// The step sequence, executed in the probe netns. Stops at the first REQUIRED
/// failure (later steps build on the earlier ones, so continuing would only
/// produce cascading noise).
fn run_steps() -> Vec<ProbeStep> {
    let mut steps = Vec::new();
    steps.push(ProbeStep::ok("userns", true));
    steps.push(ProbeStep::ok("netns", true));

    // The exact production `ip` sequence, one step at a time so the report says
    // WHICH of them the kernel refused.
    let (cmds, _) = netns_setup_commands(PROBE_TCP_PORT, PROBE_DNS_PORT);
    for argv in &cmds {
        let name = step_name_for(argv);
        match run_ok(argv) {
            Ok(()) => steps.push(ProbeStep::ok(name, true)),
            Err(e) => {
                steps.push(ProbeStep::failed(name, true, e));
                return steps;
            }
        }
    }

    // Mirror production: make the OUTPUT redirect deliverable to loopback before
    // we test delivery. Best-effort — if it does not take, the `redirect_delivery`
    // step below is what actually reports the consequence.
    for (path, val) in crate::rootless::route_localnet_writes() {
        let _ = std::fs::write(path, val);
    }

    // The `drop` variant is the MINIMUM viable ruleset (it still needs the
    // `redirect` expression, which is what actually matters); the `reject`
    // variant additionally needs nf_reject and is only a QUIC fail-fast nicety,
    // so it is reported as optional — matching the runtime's own fallback.
    let drop_rules = redirect_ruleset_with(PROBE_TCP_PORT, PROBE_DNS_PORT, UdpAction::Drop);
    match load_nft(&drop_rules) {
        Ok(()) => steps.push(ProbeStep::ok("nft_redirect", true)),
        Err(e) => {
            steps.push(ProbeStep::failed("nft_redirect", true, e));
            return steps;
        }
    }
    let reject_rules = redirect_ruleset_with(PROBE_TCP_PORT, PROBE_DNS_PORT, UdpAction::Reject);
    match load_nft(&reject_rules) {
        Ok(()) => steps.push(ProbeStep::ok("nft_reject", false)),
        Err(e) => steps.push(ProbeStep::failed("nft_reject", false, e)),
    }

    // The step the old probe was missing: prove a redirected packet actually
    // REACHES the loopback shim. The steps above only prove the ruleset LOADS;
    // on a kernel/netns where the DNAT-to-127.0.0.1 delivery is dropped (a fresh
    // netns' `route_localnet=0`, or a WSL kernel with no loadable nf_nat modules)
    // the load succeeds while every real `burpwn exec` resolves nothing and
    // captures ZERO flows. This end-to-end check turns that silent runtime
    // failure into a red `burpwn doctor`.
    match probe_redirect_delivery() {
        Ok(()) => steps.push(ProbeStep::ok("redirect_delivery", true)),
        Err(e) => {
            steps.push(ProbeStep::failed("redirect_delivery", true, e));
            return steps;
        }
    }

    // Finally, bubblewrap must be able to start inside these namespaces.
    match run_ok(&[
        "bwrap".to_string(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--unshare-pid".into(),
        "--".into(),
        "/bin/true".into(),
    ]) {
        Ok(()) => steps.push(ProbeStep::ok("bwrap", true)),
        Err(e) => steps.push(ProbeStep::failed("bwrap", true, e)),
    }
    steps
}

/// Machine-readable step id for one `ip …` argv from
/// [`netns_setup_commands`]. Pure — unit-tested against the real sequence.
fn step_name_for(argv: &[String]) -> &'static str {
    let joined = argv.join(" ");
    if joined.contains("type dummy") {
        "dummy_device"
    } else if joined.contains("addr add") {
        "netns_address"
    } else if joined.contains("route add") {
        "netns_route"
    } else if joined.contains(" lo ") {
        "netns_loopback"
    } else {
        "netns_link_up"
    }
}

/// End-to-end redirect delivery check (the crux of the "green doctor, ZERO
/// flows" gap). Binds a loopback UDP socket on the DNS redirect target, sends a
/// datagram to an off-netns address on port 53, and asserts the nft OUTPUT
/// `redirect` rule actually DNAT'd it onto the loopback listener. A timeout means
/// the ruleset loads but the DNAT-to-127.0.0.1 packet is being dropped (martian /
/// missing nf_nat runtime), which is the real cause of DNS failing inside the
/// sandbox.
fn probe_redirect_delivery() -> Result<(), String> {
    use std::net::UdpSocket;
    use std::time::Duration;

    let listener = UdpSocket::bind(("127.0.0.1", PROBE_DNS_PORT))
        .map_err(|e| format!("bind loopback DNS target 127.0.0.1:{PROBE_DNS_PORT}: {e}"))?;
    listener
        .set_read_timeout(Some(Duration::from_millis(750)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;

    let sender = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| format!("bind probe sender: {e}"))?;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): never a local address, so it routes out
    // the default route (the dummy `burp0`) and hits the OUTPUT nat hook. The
    // `dport 53` is what the `udp dport 53 redirect to :dns_port` rule matches.
    const PROBE_PAYLOAD: &[u8] = b"burpwn-redirect-probe";
    sender
        .send_to(PROBE_PAYLOAD, ("192.0.2.1", 53))
        .map_err(|e| format!("send probe datagram to 192.0.2.1:53: {e}"))?;

    let mut buf = [0u8; 64];
    match listener.recv_from(&mut buf) {
        Ok((n, _)) if &buf[..n] == PROBE_PAYLOAD => Ok(()),
        Ok((n, _)) => Err(format!(
            "redirect target received {n} unexpected bytes (not the probe datagram)"
        )),
        Err(e) => Err(format!(
            "nft redirect loaded but the UDP/53 datagram never reached the loopback \
             shim ({e}) — the DNAT-to-127.0.0.1 packet is being dropped; this is why \
             DNS fails and captures are empty inside the sandbox"
        )),
    }
}

fn run_ok(argv: &[String]) -> Result<(), String> {
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| format!("{}: {e}", argv[0]))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("{} exited with {}", argv.join(" "), out.status)
    } else {
        stderr
    })
}

fn load_nft(ruleset: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .map_err(|e| format!("nft stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft wait: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
}

/// Fork + `unshare(CLONE_NEWUSER|CLONE_NEWNET)` + uid/gid maps + re-exec
/// `/proc/self/exe __netns-probe`, capturing its stdout JSON.
///
/// Mirrors [`crate::rootless`]'s handshake exactly (and for the same reason: the
/// kernel only accepts the single-uid map write AFTER the child has unshared, and
/// the forked child of a multithreaded process must not allocate before
/// `execve`).
fn spawn_probe_child() -> Result<ProbeReport, String> {
    use nix::fcntl::OFlag;
    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let exe = CString::new("/proc/self/exe").expect("no NUL");
    let argv: Vec<CString> = vec![
        CString::new("burpwn").expect("no NUL"),
        CString::new(NETNS_PROBE_ARG).expect("no NUL"),
    ];
    let envp: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            use std::os::unix::ffi::OsStrExt;
            let mut buf = k.as_bytes().to_vec();
            buf.push(b'=');
            buf.extend_from_slice(v.as_bytes());
            CString::new(buf).ok()
        })
        .collect();

    let (ready_r, ready_w) =
        nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    let (go_r, go_w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    let (out_r, out_w) =
        nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("stdout pipe: {e}"))?;

    let host_uid = nix::unistd::getuid().as_raw();
    let host_gid = nix::unistd::getgid().as_raw();

    // SAFETY: between fork and execve the child only performs async-signal-safe
    // operations (unshare, dup2, write, read, execve) — no allocation.
    match unsafe { fork() }.map_err(|e| format!("fork: {e}"))? {
        ForkResult::Child => {
            drop(ready_r);
            drop(go_w);
            let _ = nix::unistd::dup2(out_w.as_raw_fd(), libc::STDOUT_FILENO);
            drop(out_w);
            drop(out_r);
            if unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).is_err() {
                unsafe { libc::_exit(126) };
            }
            let _ = nix::unistd::write(&ready_w, &[1u8]);
            let mut b = [0u8; 1];
            let _ = nix::unistd::read(go_r.as_raw_fd(), &mut b);
            let _ = nix::unistd::execve(&exe, &argv, &envp);
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            drop(ready_w);
            drop(go_r);
            drop(out_w);

            let mut ready = std::fs::File::from(ready_r);
            let mut buf = [0u8; 1];
            let unshared = matches!(ready.read(&mut buf), Ok(n) if n > 0);
            if !unshared {
                let _ = nix::sys::wait::waitpid(child, None);
                return Err("unshare(CLONE_NEWUSER|CLONE_NEWNET) was refused by the kernel".into());
            }
            let map_res = write_maps(child.as_raw(), host_uid, host_gid);
            drop(go_w); // signal the child to proceed (or to die on a broken map)
            if let Err(e) = map_res {
                let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(child, None);
                return Err(e);
            }

            let mut json = String::new();
            let _ = std::fs::File::from(out_r).read_to_string(&mut json);
            let _ = nix::sys::wait::waitpid(child, None);
            serde_json::from_str::<ProbeReport>(json.trim())
                .map_err(|e| format!("probe helper produced no usable report ({e}): {json:?}"))
        }
    }
}

fn write_maps(pid: i32, host_uid: u32, host_gid: u32) -> Result<(), String> {
    let write = |file: &str, contents: &str| {
        std::fs::write(format!("/proc/{pid}/{file}"), contents)
            .map_err(|e| format!("write /proc/{pid}/{file}: {e}"))
    };
    write("uid_map", &uid_map_line(host_uid))?;
    write("setgroups", "deny")?;
    write("gid_map", &gid_map_line(host_gid))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(steps: Vec<ProbeStep>, wsl: bool) -> ProbeReport {
        ProbeReport { steps, wsl }
    }

    #[test]
    fn all_steps_ok_is_ok() {
        let r = report(
            vec![ProbeStep::ok("userns", true), ProbeStep::ok("bwrap", true)],
            false,
        );
        assert!(r.is_ok());
        assert!(r.blocking_failure().is_none());
        assert_eq!(r.summary(), "usable");
        assert!(r.remediation().is_empty());
    }

    #[test]
    fn optional_failure_is_degraded_not_blocking() {
        let r = report(
            vec![
                ProbeStep::ok("nft_redirect", true),
                ProbeStep::failed("nft_reject", false, "no nf_reject"),
            ],
            false,
        );
        assert!(r.is_ok(), "an optional failure must not block the sandbox");
        assert!(r.summary().contains("degraded"));
        assert!(r.remediation().is_empty());
    }

    // Regression for the "green doctor, ZERO flows" gap: a redirect that LOADS
    // but does not DELIVER must be a blocking failure whose remediation names the
    // real cause (nf_nat runtime / route_localnet), not a green report.
    #[test]
    fn redirect_delivery_failure_blocks_and_explains_the_cause() {
        let r = report(
            vec![
                ProbeStep::ok("nft_redirect", true),
                ProbeStep::failed(
                    "redirect_delivery",
                    true,
                    "nft redirect loaded but the UDP/53 datagram never reached the loopback shim",
                ),
            ],
            false,
        );
        assert!(!r.is_ok(), "a redirect that never delivers must block");
        assert_eq!(r.blocking_failure().unwrap().name, "redirect_delivery");
        let advice = r.remediation().join("\n");
        assert!(advice.contains("route_localnet"));
        assert!(advice.contains("nf_nat"));
    }

    #[test]
    fn required_failure_blocks_and_is_summarised() {
        let r = report(
            vec![
                ProbeStep::ok("netns", true),
                ProbeStep::failed("dummy_device", true, "Error: Unknown device type."),
            ],
            false,
        );
        assert!(!r.is_ok());
        assert_eq!(r.blocking_failure().unwrap().name, "dummy_device");
        assert!(r.summary().starts_with("dummy_device failed:"));
    }

    // This is the exact WSL failure the deep probe exists for: `nft`/`ip` are
    // installed (so the shallow Preflight says "ready") yet the kernel cannot
    // create a dummy device, because WSL ships no loadable modules.
    #[test]
    fn wsl_remediation_says_the_kernel_cannot_be_fixed_by_a_package() {
        let r = report(
            vec![ProbeStep::failed(
                "dummy_device",
                true,
                "Error: Unknown device type.",
            )],
            true,
        );
        let advice = r.remediation().join("\n");
        assert!(advice.contains("dummy"));
        assert!(advice.contains("WSL"));
        assert!(advice.contains(".wslconfig"));
        assert!(
            !advice.contains("modprobe"),
            "modprobe advice is useless on WSL: {advice}"
        );
    }

    // The WSL "no loadable modules" verdict is only true of the steps that need
    // a module. When `dummy_device`/`nft_redirect`/`nft_reject` have just passed
    // and the *delivery* step is what failed, telling a WSL user to rebuild the
    // kernel is actively wrong — their kernel already loaded everything.
    #[test]
    fn wsl_remediation_stays_silent_when_the_module_steps_passed() {
        let r = report(
            vec![
                ProbeStep::ok("dummy_device", true),
                ProbeStep::ok("nft_redirect", true),
                ProbeStep::ok("nft_reject", false),
                ProbeStep::failed("redirect_delivery", true, "EPERM"),
            ],
            true,
        );
        let advice = r.remediation().join("\n");
        assert!(
            !advice.contains("can never load") && !advice.contains(".wslconfig"),
            "must not blame the WSL kernel for a non-module failure: {advice}"
        );
        assert!(advice.contains("route_localnet"));
    }

    #[test]
    fn non_wsl_remediation_points_at_the_modules_package() {
        let r = report(
            vec![ProbeStep::failed("nft_redirect", true, "not supported")],
            false,
        );
        let advice = r.remediation().join("\n");
        assert!(advice.contains("nft_redir"));
        assert!(advice.contains("modprobe"));
        assert!(!advice.contains("WSL"));
    }

    #[test]
    fn userns_failure_points_at_the_sysctls() {
        let r = report(vec![ProbeStep::failed("userns", true, "refused")], false);
        let advice = r.remediation().join("\n");
        assert!(advice.contains("unprivileged_userns_clone"));
        assert!(advice.contains("apparmor_restrict_unprivileged_userns"));
    }

    #[test]
    fn wsl_is_detected_from_osrelease_and_proc_version() {
        assert!(osrelease_is_wsl("5.15.153.1-microsoft-standard-WSL2"));
        assert!(osrelease_is_wsl(
            "Linux version 6.6.87.2-microsoft-standard-WSL2 (root@x) #1 SMP"
        ));
        assert!(!osrelease_is_wsl("6.17.11-300.fc43.x86_64"));
        assert!(!osrelease_is_wsl(""));
    }

    // The step ids must stay glued to the REAL production sequence: if
    // `netns_setup_commands` ever changes, this test fails rather than silently
    // reporting every `ip` step as the generic `netns_link`.
    #[test]
    fn step_names_cover_the_real_setup_sequence() {
        let (cmds, _) = netns_setup_commands(PROBE_TCP_PORT, PROBE_DNS_PORT);
        let names: Vec<&str> = cmds.iter().map(|c| step_name_for(c)).collect();
        assert!(names.contains(&"dummy_device"), "got {names:?}");
        assert!(names.contains(&"netns_address"), "got {names:?}");
        assert!(names.contains(&"netns_route"), "got {names:?}");
        assert!(names.contains(&"netns_loopback"), "got {names:?}");
        assert!(names.contains(&"netns_link_up"), "got {names:?}");
        // Every step must be distinguishable in the report, otherwise "which
        // step failed?" is ambiguous for the two `ip link set … up` calls.
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "duplicate step ids in {names:?}");
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = report(vec![ProbeStep::failed("dummy_device", true, "boom")], true);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ProbeReport>(&json).unwrap(), r);
    }
}
