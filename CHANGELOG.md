# Changelog

All notable changes to burpwn are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — flows can be grouped under a name and a description
A session is a flat river of flows. The one thing an agent works hardest to reconstruct — *how
this target authenticates* — had nowhere to live: it ended up as prose in the agent's context,
which the next session does not have, or as a tag, which is a label with no room to say what the
sequence means. The `groups` / `flow_groups` tables have been in the schema since v1, unreachable
from the CLI, the MCP server, or even a public writer method: dead weight nothing could use.
- **`burpwn group new|add|rm-flow|list|show|rm`** — a group is a named, described SUBSET of a
  session's flows, the equivalent of a Burp highlight. `burpwn group new auth-flow --description
  'login form → POST /login → redirect + Set-Cookie session'` then `burpwn group add auth-flow 3 5
  9` pins the reconstructed scenario to a handle; `group show` renders it exactly like `req list`,
  so it can be read back and replayed later. The same move isolates one campaign
  (`xss-fuzz-search-param`) from the thousands of flows around it. Every subcommand takes the
  NAME, supports `--json`, and `group new` is **idempotent** — re-running it returns the same
  group and updates its description, so it is safe to call before every `add` instead of
  branching on existence. Deleting a group deletes the grouping only; the flows stay captured.
- **The group is a first-class filter, not just a view** — `burpwn req list --group auth-flow
  --method POST` composes with every other filter, and `burpwn export har --group auth-flow`
  exports precisely one named scenario (exclusive with `--workspace`, which the group already
  belongs to). That is the point of naming a subset: it becomes the unit you hand to someone else.
- **Five MCP tools** (`group_new`, `group_add`, `group_list`, `group_show`, `group_rm`), bringing
  the server to **36 tools**. Their descriptions tell the model *when* to reach for them — after
  working out an auth sequence, or to fence off a fuzzing campaign — because a tool an agent never
  thinks to call is a tool that does not exist.
- **Schema v5** — `groups` gains `description` and `created_at`, `(workspace_id, name)` becomes
  unique (a name is the handle everything resolves on, so it may not designate two groups in one
  workspace), and `flow_groups` gains the group-side index the membership read needs (its primary
  key is `(flow_id, group_id)`, whose prefix is the wrong way round for "every flow in this
  group"). An existing v4 database migrates in place; because nothing ever enforced uniqueness
  before, same-named groups are folded onto the oldest id — memberships re-pointed — rather than
  failing someone's upgrade.
- **New error code `BW-SESSION-005`** (`no such flow group`), so an unknown group name comes back
  as a branchable code instead of an empty result. Adding a flow id that does not exist fails the
  whole `group add` rather than half-filling the group.

## [0.3.4] - 2026-08-10

### Fixed — an in-place upgrade kept serving traffic from the OLD daemon
`install.sh` replaces the binary on disk, but the `burpwn proxy` daemon started before the upgrade
keeps running from its now-deleted inode (`/proc/<pid>/exe -> … (deleted)`). It answers `Status`
perfectly well, and `ensure_daemon` only ever checked **liveness**, so `exec` adopted it forever:
every request kept being served by the previous build — with the previous build's bugs — under a
`burpwn -V` reporting the new version. Symptom that surfaced this: a freshly installed 0.3.3 still
returned the bare `burpwn: upstream error` that 0.3.3 had just fixed, and the only escape was to
find and kill the process by hand.
- `Status` now carries the **daemon's** version, and `exec` reuses a daemon only on an exact match.
  A mismatched daemon is shut down (under the existing `daemon.lock`, waiting for its control
  socket to stop answering) and respawned from the current binary, with a `WARN` naming both
  versions. A daemon predating the handshake sends no version and reads as stale, so the very
  daemons this bug leaves behind are the ones that get retired.
- The MCP `status` tool reports the daemon version too, so an agent debugging odd behaviour can see
  which build is actually serving its traffic.

## [0.3.3] - 2026-08-06

### Fixed — the proxy's 502 now says WHAT failed
An origin that never answered produced 30 s of silence followed by a bare
`burpwn: upstream error` — indistinguishable, for a human or an agent, from a burpwn bug. The
actual cause (a labelled connect/handshake/header timeout, a TLS error, a refused connection) only
ever reached the daemon's log.
- The synthetic 502 now carries the origin (`host:port`) and the full error chain, e.g.
  `burpwn: upstream error: ipconfig.me:443: upstream connect timed out after 30s`, in the body AND
  in a `burpwn-error` response header (for clients that discard bodies, like `curl -o /dev/null`).
  The header value is sanitised to single-line ASCII and length-bounded, so an origin certificate
  error carrying newlines/UTF-8 cannot break the response.

## [0.3.2] - 2026-08-06

### Fixed — the QUIC fail-fast guard was rejecting the sandbox's own DNS query
`burpwn doctor` went red on **every** host with
`redirect_delivery FAIL — send probe datagram to 192.0.2.1:53: Operation not permitted`, and any
sandbox whose `/etc/resolv.conf` names a **non-loopback** nameserver (WSL's `10.255.255.254`, a
LAN/router resolver, …) resolved nothing and captured ZERO flows. This was misdiagnosed as a WSL
kernel limitation in 0.3.1; it reproduced identically on Fedora 43 / kernel 6.17.
- **Root cause:** the `udpguard` chain (the QUIC/HTTP-3 fail-fast reject) sat at
  `filter hook output priority 0`, i.e. **after** the NAT chain's `dstnat` (-100). By then the
  redirect had rewritten the workload's DNS query to `127.0.0.1:<dns_port>` *while keeping the
  `burp0` output interface*, so `oifname "burp0" udp dport != 53 reject` matched burpwn's own DNS
  traffic and the kernel answered `sendto` with `EPERM`. The ruleset always **loaded** cleanly,
  which is why every string-level test stayed green.
- **Fix:** the guard now runs at `priority -150`, before the redirect, where the packet still
  carries its original `dport 53` — DNS passes, a genuine QUIC datagram to UDP/443 is still
  rejected immediately (verified live). A `udp dport <dns_port> accept` line guards the same
  invariant belt-and-braces.
- **Regression test:** new `--test redirect_delivery_real` (opt-in, `BURPWN_REAL_SANDBOX_TESTS=1`)
  drives the real userns+netns probe end to end. It fails on the 0.3.1 ruleset and passes on this
  one; unit tests additionally pin `udpguard`'s priority below the NAT chain's.

### Fixed — the WSL verdict was printed even when the WSL kernel was fine
`burpwn doctor` and `install.sh` claimed "the Microsoft kernel ships NO loadable modules, so the
`=m` features above can never load … burpwn cannot capture traffic on a stock WSL kernel" under a
report whose `dummy_device`, `nft_redirect` and `nft_reject` steps had all just **passed** — telling
users to rebuild their kernel for a bug that was in burpwn.
- The WSL blurb is now scoped to the steps that actually need a loadable module
  (`dummy_device` / `nft_redirect` / `nft_reject`); other failures get advice matching what broke.
- `install.sh` no longer prints its own blanket WSL verdict (the live doctor report is
  authoritative), and the README now says WSL support depends on the kernel and points at
  `burpwn doctor` instead of declaring WSL unsupported.

## [0.3.1] - 2026-08-05

### Fixed — DNS/redirect delivery inside the sandbox (the "green doctor, ZERO flows" gap)
On some hosts (notably WSL2) `burpwn exec -- curl …` failed with `Could not resolve host` or hung,
then warned `captured ZERO flows`, even though `burpwn doctor` reported everything ready. Root
cause: the sandbox's nftables OUTPUT `redirect` DNATs the workload's traffic to `127.0.0.1` (the
in-netns DNS shim / TCP acceptor), but a freshly-created network namespace defaults
`net.ipv4.conf.*.route_localnet=0` — under which the kernel drops the redirected-to-loopback packet
as *martian*. The ruleset **loaded** (all the diagnostics checked) while it **delivered** nothing.
- **`route_localnet` is now enabled** on the sandbox netns (`all` + `lo`) right after the interface
  setup, so the OUTPUT redirect can actually reach the loopback shim/acceptor. Best-effort with a
  warning on failure; shared with the deep probe so both exercise the identical path.
- **The DNS socket hand-off is no longer silently best-effort.** A failed bind or SCM_RIGHTS
  hand-off of the in-netns DNS socket now surfaces as an explicit `SandboxError::Setup`
  (`dns_bind` / `dns_handoff`) instead of a stderr line swallowed behind the downstream
  "captured ZERO flows" warning.
- **The deep probe now tests end-to-end DELIVERY, not just ruleset loading.** A new required
  `redirect_delivery` step sends a real UDP/53 datagram through the redirect and asserts it lands
  on a loopback listener; on failure `burpwn doctor` now goes red and names the cause
  (missing `nf_nat` runtime / `route_localnet` disabled) instead of printing `=> ready`.

### Notes
- IPv6 destinations inside the sandbox remain v4-only by design (the netns has no v6 route); this
  release does not add v6 egress. It is unrelated to the DNS failure fixed here.

## [0.3.0] - 2026-07-29

### Added — every error is coded, actionable, and leaves a debug report
- **New crate `burpwn-error`**: the error contract. A catalogue of 41 stable
  `BW-<CLASS>-<NNN>` codes, each with a plain-language title and remediation advice; a
  `Diagnostic` type that renders one failure as `code / cause / fix / debug / exit`; and the
  redaction policy for debug reports. All pure logic, unit-tested.
- **Process exit codes by failure class** — `70` sandbox, `71` daemon, `72` store, `73` TLS/CA,
  `74` session, `75` input, `76` agent integration, `77` network, `78` internal. Chosen above
  `0`/`1` and below the shell's reserved `126`/`127`/`128+n`. ⚠️ `burpwn exec` still passes the
  wrapped command's exit code through, so a value in that range from `exec` is disambiguated by
  the `--json` envelope, not by the number alone.
- **Automatic debug reports** (`<data>/debug/<ts>-<code>.json`, last 20 kept), written on every
  failure with the path printed in the message: burpwn version, redacted invocation, kernel /
  distribution / WSL / container detection, sandbox prerequisites, a LIVE sandbox re-probe for
  sandbox failures, and each session's on-disk state. Redacted before writing — env values
  outside an allowlist are dropped and token-shaped strings (JWTs, `Authorization` values, long
  opaque runs) are replaced; captured bodies are never included.
- **`burpwn debug bundle | list | show`** — an on-demand report for bug reports (`-o -` writes it
  to stdout), the reports from past failures, and a printer for one of them.
- **`--json` envelope gains `diagnostic`** — `{code, class, title, message, causes, remediation,
  context, exit_code, debug_report}`. The legacy `error` string is kept and now begins with the
  code, so an existing consumer that only reads that field still shows it.
- **MCP tool errors carry the same diagnostic**: the rendered block as the message and the
  structured object as the error `data`, so an agent branches on `diagnostic.code` instead of
  parsing prose. Previously they were `e.to_string()` — the outermost message only, with the
  cause chain discarded.

### Fixed — failures that were being reported as successes
An exhaustiveness audit of the new error contract found six paths that bypassed it entirely by
printing their own message and returning a success-shaped result:
- **`intercept forward|drop` on an id that names no parked intercept** exited **0** and printed
  "id not found"; in `--json` it came back as `ok: true`. An agent driving `await → forward` had
  no way to notice the forward never happened. Now `BW-INPUT-011` (new code), exit 75.
- **`intercept …` when the daemon answered with an error** exited **0** and printed to stderr;
  in `--json` the daemon's error was wrapped in an `ok: true` envelope. Now `BW-DAEMON-004`.
- **`mcp register` on a config file burpwn cannot edit** reported `action: "Refused"` and exited
  0, leaving the user believing the tools were registered. Now `BW-AGENT-002`.
- **`skill install --agent X` on a file burpwn does not own** likewise reported `Refused` and
  exited 0. Now `BW-AGENT-003` — but only for a single explicit `--agent`, since under `--all` a
  refusal is a legitimate per-target outcome.
- **`exec` when the sandbox preflight fails** and **`export pcap`** printed `error: …` and exited
  1 instead of their class exit code, with no catalogue code and no debug report.
- **A failure to start the async runtime** exited 1 with a bare sentence.

Two regression guards now hold the line: one asserts no command prints `error:` itself instead of
returning an `Err` (the pattern behind five of the six), and one asserts every catalogue code is
actually emitted somewhere — that is what exposed `BW-AGENT-003` as documentation for a failure
that was being reported as a success.

### Changed — no failure reaches the user as a bare sentence
- A single terminal handler in `burpwn-cli` classifies every error chain: an explicit code wins,
  then a typed error from a lower crate that knows its own code (`StoreError`, `TlsError`,
  `SandboxError`, `WrapError`, `SkillError`, `McpRegError` now implement `burpwn_error::Coded`),
  and otherwise `BW-INTERNAL-001`, which the catalogue documents as "this is a bug, report it".
  The fallback is the point: an error nobody annotated still arrives coded, with an exit code and
  a report, rather than degrading to a bare string.
- Every `bail!`/`anyhow!` site across `burpwn-cli` and `burpwn-mcp` (95 of them) now names its
  catalogue code. Sites that discarded a typed error with `map_err(|e| anyhow!("{e}"))` now
  propagate it, so it classifies itself.

### Fixed — a host that cannot sandbox no longer looks like a host that captured nothing
- **`burpwn doctor` now runs a LIVE sandbox probe** (`burpwn-sandbox/probe.rs`): it creates a real
  throwaway userns+netns and executes the production setup sequence inside it (`ip link set lo up`,
  `ip link add burp0 type dummy`, address/route, the nftables REDIRECT ruleset, then `bwrap`),
  reporting which step failed, why, and how to fix it. The previous preflight only checked that
  `ip`/`nft`/`bwrap` were **on PATH**, so it printed `=> ready` on hosts where the kernel cannot
  actually create the sandbox. `--quick` restores the old, binaries-only behaviour.
- **WSL is now diagnosed explicitly.** The WSL2 kernel ships no loadable modules while
  `CONFIG_DUMMY`, `CONFIG_NFT_REDIR` and `CONFIG_NF_REJECT_IPV4` are all `=m` there, so
  `ip link add … type dummy` and the nftables `redirect` expression fail at runtime. Every
  `burpwn exec` then died with an empty `req list` and a misleading "captured ZERO flows —
  is the agent hook rewriting through `burpwn exec`?" warning, which points at the wrong thing.
  `doctor` now detects the WSL kernel and says the sandbox cannot work there, with the two real
  options (custom `=y` kernel via `.wslconfig`, or a real Linux host).
- **`exec` reports sandbox-setup failures as failures** (`SandboxError::Setup`): the in-namespace
  agent now writes a JSON failure record to a host path carried in the `ExecSpec`, so the host
  side can tell "the sandbox never came up" apart from "the command exited non-zero" instead of
  relying on the agent's sentinel exit code. The CLI prints the failing stage, runs the live probe
  for remediation, and states that the command did **not** run captured.

## [0.2.0] - 2026-07-03

This release turns burpwn from a strong capture engine into an offensive
substrate for an AI agent: a native Intruder/fuzzer, Repeater over MCP, response
comparison, encode/decode, session auth handling — plus the engine fixes those
need (streaming bodies, structured WebSocket capture, TLS metadata) and the first
executable evaluation harness for the trained model.

### Added — one-command skill install
- **`burpwn skill install`** (`burpwn-cli`): installs the portable agent skill into each
  framework's **native** format — a skill directory (`SKILL.md`) for Claude Code / Strix, a
  rules file for Cursor (`.cursor/rules/burpwn.mdc`) / Cline (`.clinerules/burpwn.md`), or an
  append into an instructions file (`AGENTS.md` / `GEMINI.md` / `.github/copilot-instructions.md`)
  for Gemini CLI / Codex / Copilot / Antigravity / the generic `agents` fallback. Writes to the
  **project** by default, `--global` for the per-user path, plus `--all`, `--print` and `--force`.
  Idempotent and anti-clobber: re-runs are safe and it only ever rewrites the block it authored.
  `burpwn skill list` / `burpwn skill uninstall --agent <slug>` manage installs.
- **`burpwn mcp register`** (`burpwn-cli`): registers the stdio MCP server in the host's config
  (relative to `HOME`) for the agents that speak MCP — Codex (`~/.codex/config.toml`
  `[mcp_servers.burpwn]`), Copilot CLI (`~/.copilot/mcp-config.json`) and Antigravity
  (`~/.gemini/config/mcp_config.json`); `--global`, `--print`, and `--list` to enumerate hosts.
  Strix (Docker-sandbox shell, no stdio MCP) and HTTP-only cores use the skill + `burpwn exec`
  path instead. The enforced `PreToolUse` auto-capture hook (`burpwn init`) remains a **separate
  opt-in**, not stacked with the skill.

### Added — offensive loop
- **Intruder / `fuzz`** (`burpwn-cli` + `burpwn-mcp`): `fuzz run --flow <id>
  [--position start:end | § markers] [--payload <p> | --payloads <file>] --mode
  sniper|battering-ram|pitchfork|cluster-bomb [--concurrency N] [--delay MS]`
  builds a request template from a stored flow (or `--request <file>`), runs the
  `burpwn-proxy` attack engine through the same replay transport as `req replay`,
  and persists an `attacks` row plus one `attack_results` row per payload. Ctrl-C
  cancels the run. `fuzz list` / `fuzz show <id> [--sort anomaly|status|len]
  [--limit N]` inspect stored attacks. MCP tools `fuzz`, `fuzz_list`,
  `fuzz_results`.
- **Repeater over MCP** (`req_replay`): the CLI `req replay` capability is now an
  MCP tool sharing the same `replay_flow` path (closes the biggest MCP gap).
- **`compare` / diff** (CLI + MCP): structured JSON diff of two flows —
  status-line delta, header add/remove/change, line-based body diff, and a
  reflection check (tokens from flow A's request echoed in flow B's response).
  `--what headers|body|all`.
- **`encode` / `decode`** (CLI + MCP): pure byte transforms — `base64`,
  `base64url`, `url`, `hex`, and `jwt` (decode-only; splits header.payload.
  signature and decodes to JSON without verifying the signature).
- **MCP server** gains 7 offensive tools here — `req_replay`, `fuzz`,
  `fuzz_list`, `fuzz_results`, `compare`, `encode`, `decode` — and 5 more from
  the session-robustness work below, for **31 tools** total (was 19).

### Added — session robustness / integration hardening
- **Intercept scope** (CLI `intercept scope <pattern> [--path P] [--method M]` /
  `intercept scope --clear`; MCP `intercept_scope`): narrows blocking
  interception to a host/path/method so not every flow parks. Wires the proxy's
  previously-dead `InterceptController::set_scope` through a new
  `InterceptSetScope` control-plane message. MCP `intercept_forward` now also
  reaches CLI parity — it can change the parked request's `method`/`path`.
- **Session auth handling** (`session auth set|refresh|status`; MCP
  `session_auth_set`/`_refresh`/`_status`): persist a login command + a
  one-capture-group extraction regex + a `Header: … {} …` injection template
  (schema v4 `auth_profiles` table). `refresh` runs the login command in the
  sandbox, extracts the token, and installs/UPDATES a single match/replace rule
  that injects the fresh header into in-scope requests (idempotent). Best-effort
  AUTO-refresh: the proxy's new `AuthWatcher` signals 401/403 hosts (debounced,
  recursion-safe) and the daemon spawns a refresh.
- **`init --check`** (`init --check [--agent <slug>]`): drives a synthetic
  network command through each agent's `wrap-hook` path and asserts the command
  is actually rewritten to route through `burpwn exec`. Per-agent PASS / FAIL /
  ADVISORY (Cursor/Cline are advisory, never FAIL); exits non-zero if any
  rewrite-capable agent fails, de-risking the best-effort envelope dialects.
- **Capture-completeness telemetry** (schema v4 `execs` table; `session stats`,
  MCP `session_stats`): tracks per-session exec count vs captured-flow count and
  emits a `tracing::warn!` + a `warning` in the `exec` result when a clearly
  network-facing command (curl/wget/…) completes with ZERO new flows (traffic
  likely escaped capture). Conservative classifier (program-position only — no
  false alarms on `ls`/`git`/`grep curl`).
- **Store schema v4**: `auth_profiles` + `execs` tables (idempotent migration).

### Changed — capture engine (`burpwn-proxy`)
- **Streaming response bodies.** Bodies were buffered whole before forwarding,
  which stalled Server-Sent Events, chunked streaming and long-poll until EOF or
  the 120 s upstream timeout, and pinned up to 256 MiB per connection. Forwarding
  is now hybrid: when no intercept is active and no match/replace rule targets the
  host, upstream frames are relayed verbatim while a size-capped (8 MiB) copy is
  tee'd to the store; the full buffer path runs only when a rule actually needs
  the body. Streaming APIs now flow incrementally instead of hanging.
- **Structured WebSocket capture.** Replaced the marker-in-blob hack (which
  prepended `ws-c2s:` into the payload and capped at 256 KiB) with a real RFC 6455
  frame parser (FIN/opcode/mask, unmasking, continuation reassembly, control
  frames). Messages are stored structured via the new `ws_messages` table.
- **TLS/connection metadata.** Flows now record the negotiated TLS version,
  cipher and ALPN, plus a SHA-256 of the origin's leaf certificate.
- **HTTP/3 deterministic downgrade.** `Alt-Svc` is stripped from responses so
  clients don't attempt QUIC (blackholed in the sandbox) and stay on h2/h1
  instead of hanging on the h3 handshake.
- **gRPC visibility.** `application/grpc` length-prefixed framing is deframed for
  the stored/searchable copy.

### Changed — sandbox (`burpwn-sandbox`)
- **Fail-fast QUIC egress.** Non-DNS UDP out of the netns egress interface is now
  `reject`ed (was silently blackholed), so a wrapped `curl --http3` gets an
  immediate port-unreachable and falls back to TCP instead of hanging. DNS is
  spared; falls back to `drop` on kernels without `nf_reject`.
- **Resource limits on wrapped commands.** `RLIMIT_AS` (8 GiB), `RLIMIT_NPROC`
  (4096) and `RLIMIT_CPU` (3600 s) bound a fork bomb or memory hog beyond the
  wall-clock timeout. Generous defaults, all overridable via `BURPWN_RLIMIT_*`.

### Changed — storage (`burpwn-store`)
- **Schema v3**: TLS metadata columns, the `ws_messages` table, the `attacks`/
  `attack_results` tables for correlated fuzz runs, and `idx_flows_exec_id`
  (exec attribution was a full scan). Request headers are now indexed in FTS
  (searchable bearer tokens / `X-` headers), and flow queries gained
  time-range / response-size / header-substring filters plus a raw FTS5 variant.

### Added — tooling
- **Executable eval harness** (`training/eval/`): behavioural evaluation, which
  did not exist — the model was judged on validation loss and eyeballed prompts.
  `harness.py` scores predictions on a held-out split (valid command, correct
  tool, envelope shape, negative handling), with an optional `--live` grader that
  spawns real `burpwn`/`burpwn mcp`. `surface.py --check` derives the real
  CLI/MCP surface from the binary and fails on any drift from the dataset's
  hand-maintained sets.

## [0.1.2] - 2026-06-15

### Fixed
- **Claude Code / Copilot `PreToolUse` hook never actually wrapped commands**
  (`burpwn-cli`): `burpwn wrap-hook` rewrote `tool_input.command` and echoed the
  raw modified document back. Claude Code **ignores** a bare `{"tool_input":{…}}`
  on stdout, so it ran the *original* command — traffic was silently never
  captured. The hook now emits the documented envelope
  (`hookSpecificOutput` + `permissionDecision: "allow"` + `updatedInput`), so the
  rewrite is actually applied. The agent slug is now load-bearing (each agent has
  its own response dialect), not advisory.
- **Gemini CLI `BeforeTool` hook**: now emits its rewrite envelope
  (`{"decision":"allow","hookSpecificOutput":{"tool_input":{…}}}`) instead of the
  raw echo, so Gemini also wraps transparently.
- **Cursor `beforeShellExecution` hook**: Cursor's hook API can only allow/deny —
  it *cannot* rewrite a command. The raw echo was a silent no-op there. burpwn now
  emits a valid non-blocking allow with an `agentMessage` nudge to re-run network
  commands through `burpwn exec` (never a hard block). Cursor capture is advisory,
  like Cline.

### Added
- **Claude Code plugin** (`.claude-plugin/`): the repo is now a single-plugin
  marketplace, so the agent **skill** installs in one step —
  `/plugin marketplace add own2pwn-fr/burpwn` then `/plugin install burpwn@burpwn`
  (the `burpwn` binary must be on `PATH`). The plugin ships the **skill only**: the
  enforced `PreToolUse` auto-capture hook stays a separate opt-in via `burpwn init`,
  so the two integration layers are not stacked. The skill is session-aware and
  selective (it creates a session and wraps only target-facing commands); the hook
  is blunt (wraps every command, no session) — pick one.

## [0.1.1] - 2026-06-13

A fourth, exhaustive security pass (5 parallel audits across every crate) plus the
fixes it surfaced. Build, clippy and the full test suite are green; the live
end-to-end path (`burpwn exec -- curl https://…`, MITM capture, match-replace,
intercept, structured errors) was re-validated against a real rootless sandbox.

### Security
- **Sandbox control-plane isolation** (`burpwn-sandbox`): the per-session run dir
  (`proxy.sock` + `control.sock`) is now masked with a `tmpfs` inside bubblewrap.
  A unix-socket `connect()` is not IP traffic, so the nft egress rules never
  covered it — a wrapped command could previously reach `proxy.sock` to forge
  capture-attribution headers or `control.sock` to drive the daemon. Now neither
  is reachable from inside the sandbox (the in-netns acceptor lives in the agent
  process, outside bwrap, and still reaches `proxy.sock`).
- **Host-secret confinement** (`burpwn-cli`): `burpwn exec` no longer forwards the
  operator's full environment into the sandbox. It now ships only an allowlist
  (`PATH`, `HOME`, `TERM`, `LANG`, `LC_*`, proxy vars, `BURPWN_*`, …); secrets
  such as `AWS_*`, `*_TOKEN`, `*_API_KEY`, `SSH_AUTH_SOCK` are dropped so an
  untrusted wrapped tool with proxy egress cannot exfiltrate them.
- **Capture-bypass on bash** (`burpwn-wrap`): `BURPWN_AUTO=1` auto-capture is now
  zsh-only. On bash the DEBUG-trap could not cancel the typed line, so the command
  ran twice — once captured, once outside the sandbox; bash now stays tip-only.
- **Hook-config clobber** (`burpwn-wrap`): burpwn's own hook is matched by an
  anchored `<bin> wrap-hook --agent` signature instead of a bare `wrap-hook`
  substring, so a user hook merely mentioning that string is no longer
  overwritten/deleted on `init`/`uninstall`.
- **Path-traversal hardening** (`burpwn-cli`/`burpwn-mcp`): `burpwn mcp --session`
  and the `current`-pointer read path now validate the session name; control-plane
  header edits reject CR/LF/NUL (no request-line injection upstream).
- Sandbox: `--new-session` (TTY/TIOCSTI injection), size-capped `/tmp` tmpfs,
  `O_CLOEXEC` handshake/capture pipes, `RLIMIT_CORE=0` on the wrapped command.
- TLS: SNI length-capped before minting a leaf, IP-literal SNI now emits an
  `iPAddress` SAN, CA data dir tightened to `0700` and the key mode re-checked on
  load.

### Fixed
- **Proxy DoS bounds** (`burpwn-proxy`): forwarded request/response bodies are now
  capped (`http_body_util::Limited`, 413/502 on overflow) instead of buffered
  unbounded; added header-read / upstream connect+exchange timeouts; the upstream
  driver task is aborted on cancellation; half-open WebSocket/raw-TCP splices are
  torn down after a drain grace instead of leaking a task forever.
- **Store robustness** (`burpwn-store`): zstd blob decompression is bounded
  (decompression-bomb guard), per-body store size is capped, the read pool
  re-asserts `PRAGMA query_only` on every checkout, and status/port reads use
  checked conversions.
- **Structured errors** (`burpwn-cli`): in `--json` mode a top-level error is now
  emitted as the `{ok:false,data:null,error}` envelope on stdout (an agent always
  parses a structured result) instead of a plain-text `burpwn: …` line.
- DNS replies are dropped when their transaction id does not match the query.

## [0.1.0] - 2026-06-13

### Added
- **Rootless transparent sandbox** (`burpwn-sandbox`): each `burpwn exec` runs a command in its own
  user + network namespace; nftables `REDIRECT` forces all TCP (and UDP/53) to the proxy, bubblewrap
  isolates the filesystem. No root / setuid / host `CAP_NET_ADMIN`. The forked child only does
  signal-safe work then `execve`s a clean `__netns-agent` helper (avoids the multithreaded-fork
  allocator hazard); the in-netns acceptor hands connections to the host proxy via SCM_RIGHTS.
- **Proxy core** (`burpwn-proxy`): peek/classify (TLS / cleartext-HTTP / raw-TCP), HTTP/1.1 + H2 +
  WebSocket capture, transparent TLS-MITM, DNS decode/forward, raw-TCP splice, in-flight match/replace
  and a blocking-intercept primitive. Two front-ends: the transparent SCM_RIGHTS receiver and an
  explicit forward proxy (for tests).
- **TLS-MITM** (`burpwn-tls`): per-install root CA (rcgen), per-SNI leaf cache, rustls resolver,
  validating upstream connector, pinned-host passthrough fallback.
- **Per-session storage** (`burpwn-store`): SQLite (WAL + FTS5), single-writer task off the proxy hot
  path, content-addressed body dedup. FTS search treats the query as a literal phrase.
- **CLI** (`burpwn-cli`): `doctor`, `init`, `ca`, `session`, `exec`, `req list/show/search/replay`,
  `intercept`, `match-replace`, `workspace/tag/note`, `export har`; JSON envelope on fd 3; a per-session
  `burpwn proxy` daemon with a JSON control socket reused by the MCP server.
- **Agent integration** (`burpwn-wrap`): rtk-style command-rewrite hooks (Claude Code/Copilot, Cursor,
  Gemini, Cline) + a global shell hook, routing each command through `burpwn exec`.
- **MCP server** (`burpwn-mcp`): 19 tools over stdio (rmcp), including the `await_intercept` long-poll.
- Validated end-to-end: `burpwn exec -- curl https://example.com/` resolves via the proxy (DNS flows
  captured), the HTTPS request is MITM-decrypted and captured, and `burpwn req list/show` surfaces it.

### Known limitations
- `export pcap` is not yet implemented (errors clearly; use `export har`).
- `req replay` is implemented for cleartext HTTP/1.x; HTTPS/H2 replay is pending.
