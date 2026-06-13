# Changelog

All notable changes to burpwn are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
