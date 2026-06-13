# burpwn

**A transparent intercepting proxy + execution sandbox + agent interface for AI-driven web pentesting.**

burpwn is to an AI agent what Burp Suite is to a human pentester. It runs every command an agent
executes inside a rootless Linux sandbox whose **entire** network (HTTP/HTTPS/DNS/TCP) is forced
through a built-in intercepting proxy. The agent can then go back through history, search and filter
the decrypted request/response flows, replay and edit them (Repeater), apply match/replace rules,
block and rewrite traffic in flight, and organize flows into workspaces — all from a scriptable CLI
or over MCP. It is at once a Burp and a tshark, but driven by an agent.

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
  the CA is injected into the sandbox trust store so HTTPS is decrypted. Cert-pinned targets fall back
  cleanly to TLS pass-through with metadata-only logging.
- **Capture & query.** Flows are stored in a per-session SQLite database (WAL, content-addressed body
  dedup, FTS5 full-text search) written by a single-writer task off the proxy hot path.
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
burpwn req replay 42 --set-header 'X: 1'       # Repeater
burpwn intercept enable                        # blocking intercept (also via MCP await_intercept)
```

## Build

```sh
cargo build --release    # produces a single `burpwn` binary
cargo test
```

Linux-only (relies on user/network namespaces, nftables, bubblewrap).

## License

[AGPL-3.0-only](./LICENSE).
