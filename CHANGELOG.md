# Changelog

All notable changes to burpwn are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
