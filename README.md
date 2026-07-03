# burpwn

[![CI](https://github.com/own2pwn-fr/burpwn/actions/workflows/ci.yml/badge.svg)](https://github.com/own2pwn-fr/burpwn/actions/workflows/ci.yml)

**A transparent intercepting proxy + execution sandbox + agent interface for AI-driven web pentesting.**

burpwn is to an AI agent what Burp Suite is to a human pentester. It runs every command an agent
executes inside a rootless Linux sandbox whose **entire** network (HTTP/HTTPS/DNS/TCP) is forced
through a built-in intercepting proxy. The agent can then go back through history, search and filter
the decrypted request/response flows, replay and edit them (Repeater), fuzz them with a native
Intruder, diff responses, encode/decode tokens, keep itself authenticated with a login macro, apply
match/replace rules, block and rewrite traffic in flight, and organize flows into workspaces — all
from a scriptable CLI or over MCP (31 tools). It is at once a Burp and a tshark, but driven by an
agent.

> **Status:** early development. See the milestones below.

## Why

Existing intercepting proxies are built for a human clicking in a GUI. An autonomous agent needs a
*programmatic* surface: create a session, run tooling, and query the captured traffic — without the
agent's own LLM traffic ever being captured. burpwn delivers exactly that: the agent process stays
**outside** the sandbox; only the commands it executes (its children) enter the captured network
namespace, so LLM traffic is excluded by construction.

## How it works

- **Rootless transparent sandbox.** Each executed command runs in its own Linux user + network
  namespace. An nftables `REDIRECT` ruleset inside that namespace forces all TCP (and UDP/53) to the
  burpwn proxy. bubblewrap isolates the filesystem and processes. No root, no setuid, no CAP_NET_ADMIN
  on the host — the kernel grants the needed capability *inside* the child namespace.
- **TLS-MITM.** A per-install root CA is generated once; leaf certs are minted on the fly per SNI and
  the CA is injected into the sandbox trust store so HTTPS is decrypted, capturing TLS metadata (SNI,
  negotiated HTTP version) alongside each flow. Cert-pinned targets fall back cleanly to TLS
  pass-through with metadata-only logging. QUIC/HTTP-3 (UDP/443) is fail-fast-rejected in the sandbox
  so clients gracefully downgrade to TCP and stay captured.
- **Full protocol coverage.** HTTP/1.1 and HTTP/2, streaming bodies (SSE / chunked / long-poll are
  tee'd to the store without buffering), and WebSocket upgrades captured as structured per-direction
  frames — plus DNS and raw-TCP metadata.
- **Capture & query.** Flows are stored in a per-session SQLite database (WAL, content-addressed body
  dedup, FTS5 full-text search) written by a single-writer task off the proxy hot path.
- **Offensive loop.** Beyond Repeater-style replay, burpwn has a native Intruder (`fuzz`, sniper /
  battering-ram / pitchfork / cluster-bomb, results ranked by anomaly), response `compare`,
  `encode`/`decode` (base64/url/hex/jwt), scoped blocking interception, and a session-auth login macro
  that auto-refreshes the token on 401/403 — so the tight probe loop never leaves the session.
- **Agent integration (rtk-style).** `burpwn init` installs the right command-rewrite hook for the
  detected agent (Claude Code / Copilot, Cursor, Gemini CLI, Cline/Roo), plus a generic global shell
  hook so even a custom agent is covered.

## Usage (target surface)

```sh
burpwn doctor                                  # check the rootless prerequisites
burpwn ca init && burpwn ca export             # generate / print the MITM CA
burpwn session new --name engagement-1
burpwn exec -- curl -s https://target.example/ # runs sandboxed; traffic captured + decrypted
burpwn req list                                # browse captured flows
burpwn req show 42 --raw                       # decrypted request + response
burpwn req replay 42 --set-header 'X: 1'       # Repeater (also `req_replay` over MCP)
burpwn fuzz run --flow 42 --position 40:47 \
  --payloads words.txt --mode sniper           # native Intruder, results ranked by anomaly
burpwn fuzz show <attack_id> --sort anomaly    # per-payload results
burpwn compare 42 43 --what all                # structured diff + reflection check
burpwn decode jwt <token>                      # encode/decode base64(url)/url/hex/jwt
burpwn session auth set --login 'curl -s https://target.example/login -d u=a' \
  --extract '"token":"([^"]+)"' --header 'Authorization: Bearer {}'  # login-macro refresh on 401/403
burpwn intercept scope target.example --path /admin  # narrow blocking intercept
burpwn intercept enable                        # blocking intercept (also via MCP await_intercept)
burpwn session stats                           # capture-completeness: flags execs that captured nothing
burpwn init --check                            # verify each agent hook really rewrites to `burpwn exec`
```

## Install

Linux-only (relies on user/network namespaces, nftables, bubblewrap). Install the prerequisites
first — Fedora/RHEL: `sudo dnf install bubblewrap nftables iproute`; Debian/Ubuntu:
`sudo apt install bubblewrap nftables iproute2`.

```sh
# one-liner: download the prebuilt binary, install to ~/.local/bin, generate the CA, run preflight
curl -fsSL https://raw.githubusercontent.com/own2pwn-fr/burpwn/main/install.sh | sh

# from a checkout (builds from source if no prebuilt binary fits your arch)
./install.sh                # ./install.sh --hooks also installs the global shell hook
./install.sh --from-source  # force a source build

# or via cargo / the Makefile
cargo install --git https://github.com/own2pwn-fr/burpwn burpwn
make install                # PREFIX=/usr/local make install  (may need sudo); `make help` lists tasks
```

The `curl | sh` path downloads the release binary for your architecture (x86_64 / aarch64 Linux) and
verifies its checksum; if none matches it falls back to a `cargo` source build.

## Build (from source)

```sh
cargo build --release    # produces a single `burpwn` binary at target/release/burpwn
cargo test               # the privileged rootless-sandbox test is #[ignore]d
```

## Agent integration

There are two integration layers. The **skill** is the recommended default; the **hook** is an
explicit opt-in. They are not meant to be stacked.

### Skill (recommended)

The bundled agent skill ([`skills/burpwn/`](./skills/burpwn)) teaches the agent the workflow:
create a named session first, then route **target-facing** network commands through
`burpwn exec`, and query/replay/intercept the captures. It is *selective* (only the commands that
touch the target are sandboxed) and *session-aware* — no surprise sandboxing of `ls`/`git`/builds,
and no captures landing in an unnamed default session.

On Claude Code this repo is a **plugin marketplace**, so the skill installs in one step (the
`burpwn` binary must already be on `PATH`):

```sh
# in Claude Code:
/plugin marketplace add own2pwn-fr/burpwn
/plugin install burpwn@burpwn
```

For other agents, copy the skill dir into your agent's skills folder, e.g.
`cp -r skills/burpwn ~/.claude/skills/`.

### Hook (opt-in: enforced auto-capture)

`burpwn init` installs an rtk-style command-rewrite hook so **every** shell command is auto-routed
through `burpwn exec`. This guarantees capture even if the model forgets to wrap a command — but it
sandboxes *all* commands (not just network ones) and does not create a session for you (captures go
to the active/default session). Use it only when you want enforced capture and accept that trade-off.

```sh
burpwn init --agent claude   # Claude Code / Copilot PreToolUse hook (also: cursor, gemini, cline)
burpwn init --global         # generic shell hook — works for any agent
burpwn mcp                   # MCP server over stdio (session/exec/req/intercept tools)
```

Hook support differs by what each agent's hook API allows:

| Agent | Mechanism | Auto-rewrites commands? |
|-------|-----------|-------------------------|
| Claude Code / Copilot | `PreToolUse` (`updatedInput`) | **Yes** — transparent |
| Gemini CLI | `BeforeTool` (`hookSpecificOutput.tool_input`) | **Yes** — transparent |
| Cursor | `beforeShellExecution` | No — its hook can only allow/deny, so burpwn emits a non-blocking nudge; rely on the skill rule to prefix `burpwn exec` |
| Cline / Roo | `.clinerules` text | No — advisory (model-followed) |

## License

[AGPL-3.0-only](./LICENSE).
