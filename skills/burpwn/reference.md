# burpwn — full CLI reference

Verified against `burpwn <cmd> --help`. Global option on every command:
`--json` (emit the `{ok, data, error}` envelope instead of human text).

```
burpwn [--json] <command>
```

## doctor
`burpwn doctor [--json]` — probe the host for sandbox prerequisites and CA presence.

## init
`burpwn init [--global] [--agent <AGENT>] [--json]`
- `-g, --global` — install the generic global shell hook (covers any agent).
- `--agent <AGENT>` — install the hook for a specific agent (`claude`, `cursor`, `gemini`, `cline`).

## ca
- `burpwn ca init [--json]` — generate the CA if absent and report its location (idempotent).
- `burpwn ca export [--json]` — print the CA certificate PEM to stdout.

## session
- `burpwn session new [--name <NAME>] [--json]` — create a session (default name `default`).
- `burpwn session list [--json]`
- `burpwn session use <NAME> [--json]` — switch the active session.
- `burpwn session rm <NAME> [--json]` — remove a session (its DB and runtime files).

## exec
`burpwn exec [--workspace <WORKSPACE>] [--timeout <SECS>] [--session <SESSION>] [--json] -- <CMD>...`
- `<CMD>...` — everything after `--` is the command to run in the sandbox.
- `--workspace <id>` — attribute captured flows to a workspace.
- `--timeout <secs>` — wall-clock timeout for the command.
- `--session <n>` — session to run under (defaults to the active session).
- With `--json`, the `{exit_code, exec_id, captured_request_ids}` envelope is written to **fd 3**, keeping the command's own stdout clean.

## req
- `burpwn req list [OPTIONS] [--json]`
  - `--host <HOST>` — substring match against host / SNI / dst ip.
  - `--status <STATUS>` — exact response status.
  - `--method <METHOD>` — exact request method.
  - `--protocol <PROTOCOL>` — exact wire protocol: `h1`, `h2`, `ws`, `dns`, `rawtcp`, `tls-passthru`.
  - `--port <PORT>` — exact destination port.
  - `--workspace <WORKSPACE>` — restrict to a workspace id.
  - `--limit <LIMIT>` / `--offset <OFFSET>` — pagination.
- `burpwn req show <ID> [--raw] [--json]` — show one flow (`--raw` = verbatim bytes).
- `burpwn req search <QUERY> [--json]` — full-text search flow bodies.
- `burpwn req replay <ID> [OPTIONS] [--json]` — Repeater.
  - `--set-header <K=V>` — override/add a request header (`Name: value` or `Name=value`); repeatable.
  - `--set-body <STR|@file>` — replace the body with a literal string, or `@file` to read from a file.
  - `--method <METHOD>` — override the request method.

## intercept
- `burpwn intercept enable [--json]`
- `burpwn intercept disable [--json]`
- `burpwn intercept list [--json]` — list parked intercepts.
- `burpwn intercept await [--timeout <TIMEOUT>] [--json]` — long-poll for the next parked intercept (default 30s).
- `burpwn intercept forward <ID> [OPTIONS] [--json]`
  - `--set-header <K=V>` — set a header (`Name: value`); repeatable.
  - `--set-body <SET_BODY>` — replace the body.
  - `--method <METHOD>` — replace the method.
- `burpwn intercept drop <ID> [--json]`

## match-replace
- `burpwn match-replace add <SCOPE> <KIND> <PATTERN> <REPLACEMENT> [--on <ON>] [--json]`
  - `<SCOPE>` — scope expression (e.g. host glob; empty string = all).
  - `<KIND>` — what to match: `header`, `body`, `url`, `host`.
  - `<PATTERN>` / `<REPLACEMENT>` — match pattern and replacement string.
  - `--on <ON>` — apply to `request` (default) or `response`.
- `burpwn match-replace list [--json]`
- `burpwn match-replace rm <ID> [--json]`
- `burpwn match-replace enable <ID> [--json]`
- `burpwn match-replace disable <ID> [--json]`

## workspace
- `burpwn workspace new <NAME> [--json]`
- `burpwn workspace list [--json]`
- `burpwn workspace use <NAME> [--json]` — informational only: records the choice in config. To actually scope, pass `--workspace` on `exec`/`req`.

## tag / note
- `burpwn tag add <FLOW_ID> <NAME> [--json]`
- `burpwn note add <FLOW_ID> <TEXT> [--json]`

## export
- `burpwn export har [--workspace <WORKSPACE>] [-o <OUTPUT>] [--json]` — HAR 1.2 (stdout if no `-o`).
- `burpwn export pcap` — not yet implemented (errors clearly).

## mcp (stdio server)
`burpwn mcp [--session <n>]` — start the MCP server over stdio. It does not print
`--help`; running it starts the server (it exits when the stdio connection
closes). Exposes 19 tools: `session_list`, `session_current`, `req_list`,
`req_show`, `req_search`, `workspace_list`, `workspace_new`, `tag_list`,
`tag_add`, `note_add`, `match_replace_list`, `match_replace_add`,
`intercept_enable`, `intercept_disable`, `intercept_list`, `await_intercept`,
`intercept_forward`, `intercept_drop`, `exec`.
