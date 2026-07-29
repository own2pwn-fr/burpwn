//! burpwn-sandbox — rootless per-command isolation.
//!
//! Each executed command runs inside its OWN Linux user + network namespace
//! whose entire network is force-redirected (nftables `REDIRECT`, not `TPROXY`)
//! to the burpwn proxy, plus bubblewrap for filesystem/process isolation. The
//! design is ROOTLESS: `unshare(CLONE_NEWUSER|NEWNET|NEWNS|NEWPID)` + a
//! single-uid `uid_map`/`gid_map` (caller uid → 0) grants `CAP_NET_ADMIN`
//! SCOPED to the child netns, so `ip`/`nft` succeed without real root.
//!
//! Because the host (init userns, unprivileged) cannot `setns` into the child
//! userns's netns, the listener that recovers each connection's original
//! destination (`SO_ORIGINAL_DST`) lives INSIDE the child and hands the client
//! socket back to the host proxy over a unix socket using `SCM_RIGHTS`
//! fd-passing plus a fixed metadata header. The host proxy (real connectivity)
//! does the MITM/capture/egress — the child netns has NO real egress, which is
//! the security property ("rien ne sort sauf via le proxy").
//!
//! ## Module map
//!
//! * [`nft`] — pure nftables REDIRECT ruleset generation (CI-tested).
//! * [`wire`] — the SCM_RIGHTS hand-off wire format, the shared contract with
//!   the proxy ([`wire::PassedConn`], encode/decode; CI-tested).
//! * [`runtime`] — the [`SandboxRuntime`] trait, [`ExecSpec`]/[`ExecOutcome`],
//!   the [`SandboxError`] type, and the privilege-free [`MockRuntime`].
//! * [`rootless`] — the prod [`RootlessRuntime`] + [`doctor`]/[`Preflight`]
//!   (privileged paths gated behind preflight; pure helpers CI-tested).
//! * [`probe`] — the LIVE deep probe behind `burpwn doctor`: it really creates a
//!   throwaway userns+netns and runs the production setup sequence in it, so a
//!   kernel that has the binaries but not the features (WSL) is caught here
//!   instead of silently producing empty captures.

pub mod nft;
pub mod probe;
pub mod rootless;
pub mod runtime;
pub mod wire;

pub use nft::{redirect_ruleset, redirect_ruleset_with, UdpAction};
pub use probe::{deep_probe, is_wsl, netns_probe_main, ProbeReport, ProbeStep, NETNS_PROBE_ARG};
pub use rootless::{
    doctor, netns_agent_main, resolve_rlimits, Preflight, RootlessRuntime, SandboxRlimits,
    DEFAULT_RLIMIT_AS_BYTES, DEFAULT_RLIMIT_CPU_SECONDS, DEFAULT_RLIMIT_NPROC, NETNS_AGENT_ARG,
    SPEC_ENV,
};
pub use runtime::{ExecOutcome, ExecSpec, MockRuntime, SandboxError, SandboxRuntime};
pub use wire::{PassedConn, WireError, L4};
