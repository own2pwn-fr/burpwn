# burpwn — full CLI reference

Verified against `burpwn <cmd> --help`. Global option on every command:
`--json` (emit the `{ok, data, error}` envelope instead of human text).

```
burpwn [--json] <command>
```

## Errors

Every failure carries a stable code, a cause chain, remediation, and a debug report.

```text
error [BW-SANDBOX-003] the command did NOT run captured — no traffic was intercepted
  cause : sandbox setup failed at `netns_setup`: ip link add burp0 type dummy failed: …
  fix   : the `dummy` network driver is unavailable — the sandbox needs it …
        : run `burpwn doctor`: it recreates the sandbox live and names the failing step
  debug : ~/.local/share/burpwn/debug/2026-07-29T18-33-17Z-BW-SANDBOX-003.json
  exit  : 70
```

In `--json` mode the same information is in the envelope: `error` keeps the
one-line form (`[CODE] message: cause`) and `diagnostic` carries
`{code, class, title, message, causes, remediation, context, exit_code, debug_report}`.
MCP tool errors carry the rendered block as the message and the same object as
the error `data` — branch on `diagnostic.code`, not on the prose.

The process exit code is the failure's CLASS, so a script can react without
parsing anything. ⚠️ `burpwn exec` passes the wrapped command's exit code
through, so a 70–78 out of `exec` is only burpwn's if the command itself did not
produce it — the JSON envelope disambiguates.

**SANDBOX** — exit code `70`

| code | meaning |
|---|---|
| `BW-SANDBOX-001` | a sandbox prerequisite is not installed |
| `BW-SANDBOX-002` | the kernel refused to create the sandbox namespaces |
| `BW-SANDBOX-003` | the sandbox network could not be configured |
| `BW-SANDBOX-004` | the in-sandbox capture listener could not bind |
| `BW-SANDBOX-005` | the sandbox could not start the command |
| `BW-SANDBOX-006` | the command hit its timeout and was killed |
| `BW-SANDBOX-007` | the sandbox failed to run the command |

**DAEMON** — exit code `71`

| code | meaning |
|---|---|
| `BW-DAEMON-001` | the session proxy did not start in time |
| `BW-DAEMON-002` | the session proxy is not reachable |
| `BW-DAEMON-003` | the connection to the session proxy broke |
| `BW-DAEMON-004` | the session proxy refused the request |
| `BW-DAEMON-005` | the session runtime directory is unusable |

**STORE** — exit code `72`

| code | meaning |
|---|---|
| `BW-STORE-001` | the capture database could not be opened |
| `BW-STORE-002` | a database operation failed |
| `BW-STORE-003` | the capture database is from a newer burpwn |
| `BW-STORE-004` | a stored body is larger than the safety limit |
| `BW-STORE-005` | the capture writer has shut down |

**TLS** — exit code `73`

| code | meaning |
|---|---|
| `BW-TLS-001` | the MITM certificate authority could not be generated |
| `BW-TLS-002` | the MITM certificate authority could not be loaded |
| `BW-TLS-003` | the stored CA material is malformed |
| `BW-TLS-004` | a certificate could not be minted for the target |

**SESSION** — exit code `74`

| code | meaning |
|---|---|
| `BW-SESSION-001` | the session name is not allowed |
| `BW-SESSION-002` | no such session |
| `BW-SESSION-003` | no such workspace |
| `BW-SESSION-004` | burpwn cannot determine where to store its data |
| `BW-SESSION-005` | no such flow group |
| `BW-SESSION-006` | this file is not a burpwn session bundle |
| `BW-SESSION-007` | a session by that name already exists |

**INPUT** — exit code `75`

| code | meaning |
|---|---|
| `BW-INPUT-001` | a flag was given an unsupported value |
| `BW-INPUT-002` | no such flow |
| `BW-INPUT-003` | no such fuzz attack |
| `BW-INPUT-004` | a header specification is malformed |
| `BW-INPUT-005` | the input is malformed for that scheme |
| `BW-INPUT-006` | the command needs to know what to act on |
| `BW-INPUT-007` | an input file could not be read |
| `BW-INPUT-008` | refusing to write through an unsafe path |
| `BW-INPUT-009` | there is nothing to act on |
| `BW-INPUT-010` | the regex is invalid for this use |
| `BW-INPUT-011` | no such parked intercept |
| `BW-INPUT-012` | the output file already exists |

**AGENT** — exit code `76`

| code | meaning |
|---|---|
| `BW-AGENT-001` | unknown agent / framework / MCP host |
| `BW-AGENT-002` | the agent config file is not a shape burpwn can edit |
| `BW-AGENT-003` | refusing to overwrite a file burpwn does not own |

**NETWORK** — exit code `77`

| code | meaning |
|---|---|
| `BW-NETWORK-001` | the replay request failed |
| `BW-NETWORK-002` | the session-auth login macro failed |

**INTERNAL** — exit code `78`

| code | meaning |
|---|---|
| `BW-INTERNAL-001` | unexpected internal error |
## debug
`burpwn debug bundle [-o <path>|-] [--no-probe] [--json]` — write a full report (host,
prerequisites, live sandbox probe, sessions) for a bug report. `-o -` prints it to stdout.
`burpwn debug list` — the reports burpwn wrote automatically on past failures (last 20 kept).
`burpwn debug show [<path>]` — print one (the most recent by default).

Reports are redacted: env values outside a small allowlist are dropped, and
token-shaped strings (JWTs, `Authorization:` values, long opaque runs) are
replaced by `«redacted»`. Captured bodies are never included.

## doctor
`burpwn doctor [--quick] [--json]` — probe the host for sandbox prerequisites and CA presence,
then run a LIVE probe that really creates a throwaway userns+netns and executes the production
setup sequence in it (dummy device, nftables REDIRECT ruleset, bubblewrap). Reports the failing
step plus remediation — this is what catches a host where `ip`/`nft` are installed but the kernel
cannot use them (WSL). `--quick` skips the live probe.

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
- `burpwn session import <FILE> [--as <NAME>] [--use] [--json]` — open a bundle written by
  `burpwn export session` as a NEW session (never merges into, never overwrites an existing one;
  a name collision errors and is resolved with `--as`). An older bundle is migrated on the way in,
  one from a newer burpwn is refused (`BW-STORE-003`). `--use` also switches the active session.
  Prints what landed (flows / workspaces / groups / tags / notes / attacks) and warns when the
  bundle was exported without `--redact`.

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
  - `--group <GROUP>` — restrict to the flows in a group, by NAME (see `burpwn group list`).
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

## group
A named, described SUBSET of a session's flows (a Burp-style highlight): a
reconstructed auth scenario, one fuzzing campaign. Names are unique per
workspace and every subcommand takes the NAME, not an id.
- `burpwn group new <NAME> [--description <TEXT>] [--workspace <ID|NAME>] [--json]` — idempotent: an existing name is returned as is, with its description updated. Defaults to the default workspace.
- `burpwn group add <NAME> <FLOW_ID>... [--json]` — add flows; an unknown flow id fails the call without adding any.
- `burpwn group rm-flow <NAME> <FLOW_ID>... [--json]` — remove flows from the group (the flows stay captured).
- `burpwn group list [--workspace <ID|NAME>] [--json]` — name, description, flow count.
- `burpwn group show <NAME> [--json]` — the group's flows, rendered like `req list`.
- `burpwn group rm <NAME> [--json]` — delete the grouping only.

## export
- `burpwn export har [--workspace <WORKSPACE>] [--group <GROUP>] [-o <OUTPUT>] [--json]` — HAR 1.2 (stdout if no `-o`). `--group <NAME>` exports one named scenario; it is exclusive with `--workspace`.
- `burpwn export session [--session <NAME>] [-o <OUTPUT>] [--redact] [--force] [--json]` — the WHOLE
  session as one portable file (default `<session>.burpwn` in the current directory, created `0600`,
  never overwritten without `--force`): every flow with its bodies, plus workspaces, groups, tags,
  notes, attacks and rules. `burpwn session import` opens it on another machine.
  **The bundle is RAW by default**: it carries the stored auth tokens, the login commands (argv
  credentials included) and the Authorization / Cookie headers captured in the traffic, so that the
  session replays identically. `--redact` drops the stored auth tokens, login commands and
  match/replace replacements — it does **not** scrub credentials captured inside recorded requests
  and responses. Treat a bundle like the credentials it contains.
- `burpwn export pcap` — not yet implemented (errors clearly).

## mcp (stdio server)
`burpwn mcp [--session <n>]` — start the MCP server over stdio. It does not print
`--help`; running it starts the server (it exits when the stdio connection
closes). Exposes 37 tools: `session_list`, `session_current`, `session_stats`,
`session_export`, `session_auth_set`, `session_auth_refresh`,
`session_auth_status`, `req_list`,
`req_show`, `req_search`, `req_replay`, `workspace_list`, `workspace_new`,
`tag_list`, `tag_add`, `note_add`, `group_new`, `group_add`, `group_list`,
`group_show`, `group_rm`, `match_replace_list`, `match_replace_add`,
`intercept_enable`, `intercept_disable`, `intercept_list`, `intercept_scope`,
`await_intercept`, `intercept_forward`, `intercept_drop`, `exec`, `fuzz`,
`fuzz_list`, `fuzz_results`, `compare`, `encode`, `decode`.

There is deliberately no `session_import` tool: loading a session file that came
from somewhere else is an operator decision (`burpwn session import`), not
something an agent should do on its own say-so.
