# burpwn — AI-driven intercepting proxy

burpwn runs a command inside a user+network namespace whose entire network is
forced through burpwn's MITM proxy. HTTPS is decrypted with a per-install CA
injected into the sandbox trust store, and every request/response is captured to
a per-session SQLite store you can query, filter, replay, and live-edit. The
agent process stays OUTSIDE the sandbox, so its own LLM traffic is never
captured.

Linux only. Prefer `--json` on every command when you need to parse output.

## ALWAYS use burpwn for remote security work

In any security-audit / pentest session that performs **remote operations**
(HTTP/HTTPS/DNS/TCP against a target), this is a standing rule, not a suggestion:

- **Route every network command through `burpwn exec -- <cmd>`** (or install the
  hook once with `burpwn init` / `burpwn init --global` so it happens
  automatically). This applies to `curl`, `httpie`, `nmap`, `ffuf`/`gobuster`,
  `nuclei`, `sqlmap`, `wget`, custom scripts — anything that touches the target.
- **Do NOT issue raw network commands that bypass burpwn.** Traffic that doesn't
  go through `burpwn exec` is *invisible* to the audit: no capture, no decrypted
  HTTPS, no history to search/replay/intercept, no evidence trail. Treat an
  un-wrapped request as a mistake to redo under `burpwn exec`.
- **Create a session first** (`burpwn session new --name <engagement>`), and use
  one session (or per-target workspaces) so the whole engagement is one queryable
  capture set.
- The one thing you must NOT wrap is your own non-target traffic — burpwn already
  excludes the agent's LLM calls by construction (they stay outside the sandbox);
  only the target-facing tooling goes through `burpwn exec`.

If `burpwn doctor` fails (missing namespaces/`bwrap`/`nft`, or a kernel that cannot
create the sandbox — e.g. WSL), fix that before
starting remote work rather than silently falling back to un-captured commands.

**When a burpwn command fails**, do not retry blindly: the error carries a stable
code and remediation. In `--json` / MCP, read `diagnostic.code` and
`diagnostic.remediation`; a `BW-SANDBOX-*` code means the sandbox could not be
created, so nothing was captured (fix the host, do not fall back to un-wrapped
commands). Each failure also writes a debug report whose path is in the message —
attach it when reporting a problem, or read it with `burpwn debug show`.

**Confirm capture is actually working** (traffic silently escaping the sandbox is
the worst failure — you think you have evidence and you don't):

```sh
burpwn init --check            # verify each agent's hook really rewrites to `burpwn exec`
burpwn session stats           # execs vs captured flows; flags network execs that captured ZERO
```

Run `init --check` after installing a hook (it exits non-zero if an agent that
should rewrite doesn't), and glance at `session stats` during an engagement — a
network-facing exec with zero captured flows means the traffic bypassed burpwn.

## Setup (once)

```sh
burpwn doctor                      # preflight + LIVE sandbox probe (--quick skips the probe)
burpwn ca init                     # generate the CA if absent (idempotent)
burpwn session new --name pentest  # create a session (DB + runtime files)
burpwn session use pentest         # make it active
```

`burpwn session list` shows sessions; `burpwn session rm <name>` deletes one.
The proxy daemon is lazy: it starts automatically on the first `exec`.

## Core loop — capture then inspect

Run your tooling through the sandbox; everything it touches is captured:

```sh
burpwn exec -- curl -s https://target.example/api/login -d 'u=a&p=b'
burpwn exec --timeout 60 -- nmap -p 80,443 target.example
burpwn exec --json -- curl https://target.example/ >/dev/null
```

`exec --json` writes its `{exit_code, exec_id, captured_request_ids}` envelope to
**fd 3** (so it never mixes with the command's own stdout):

```sh
burpwn exec --json -- curl -s https://target.example/ 3>/tmp/env.json >/dev/null
```

If you ran `burpwn init` (see README), each shell command the agent runs is
auto-routed through `exec` — you can skip the explicit `burpwn exec --`.

Inspect what was captured:

```sh
burpwn req list                                  # recent flows
burpwn req list --host target.example --status 200 --method POST --limit 20
burpwn req list --protocol h2 --port 443 --json  # h1|h2|ws|dns|rawtcp|tls-passthru
burpwn req show <id>                              # summary of one flow
burpwn req show <id> --raw                        # verbatim request/response bytes
burpwn req search 'csrf_token'                    # full-text search bodies
```

## The offensive loop (prefer burpwn-native tools)

For the inner probe/exploit loop, prefer burpwn's built-ins over shelling out —
they operate on captured flows, keep everything in one session, and rank results.
Typical loop against a captured request:

1. **Capture** a real request through `exec` (see above).
2. **Probe** it: `req replay` for a single hand-edited request (Repeater), or
   `fuzz run` to sweep payloads across positions (Intruder).
3. **Compare** a suspicious response against a baseline with `compare` (structured
   header/body diff + reflection check).
4. **Decode/encode** any tokens you find with `decode`/`encode` (base64, url, hex,
   jwt) to understand or tamper with them.
5. **Stay authenticated** with `session auth` so 401/403s auto-refresh the token.
6. **Narrow interception** with `intercept scope` when you want to hand-edit only
   one host/path in flight instead of parking every flow.

Reach for external tools via `exec` (ffuf, sqlmap, nuclei) for heavy scanning, but
use the native `fuzz`/`compare`/`req replay`/`encode` for the tight iterate loop —
no leaving the session, and results come back ranked by anomaly.

## Repeater — replay with edits

```sh
burpwn req replay <id>
burpwn req replay <id> --method POST --set-header 'X-Forwarded-For: 127.0.0.1' \
  --set-header 'Authorization: Bearer NEW' --set-body 'role=admin'
burpwn req replay <id> --set-body @/tmp/payload.json
```

`--set-header` accepts `Name: value` or `Name=value` and is repeatable.
`--set-body` takes a literal string or `@file`. (Over MCP this is `req_replay`.)

## Fuzz — native Intruder

Sweep payloads across one or more injection positions in a captured request. The
flow supplies the destination + base request; positions are `start:end` byte
offsets (repeatable), or mark them inline with `§` (or a custom `--marker`).
Results are ranked by an anomaly score.

```sh
burpwn fuzz run --flow <id> --position 40:47 --payloads /usr/share/wordlists/x.txt \
  --mode sniper --concurrency 20 --delay 50 --name login-user
burpwn fuzz run --flow <id> --payload admin --payload root --mode battering-ram
burpwn fuzz run --flow <id> --request /tmp/base.raw --position 10:14 --payloads pl.txt
burpwn fuzz list                     # stored attacks (also --workspace W)
burpwn fuzz show <attack_id>         # per-payload results, --sort anomaly|status|len --limit N
```

Modes: `sniper` (one position at a time), `battering-ram` (same payload in all
positions), `pitchfork` (payload sets in lockstep), `cluster-bomb` (all
combinations).

## Compare — diff two responses

```sh
burpwn compare <flow_a> <flow_b>                 # structured diff + reflection check
burpwn compare <flow_a> <flow_b> --what headers  # or `body`, `all` (default)
```

Use it to spot what changed between a baseline and a payloaded response (length,
status, reflected input, added/removed headers).

## Encode / decode tokens

```sh
burpwn decode jwt <token>            # jwt is decode-only; header+claims
burpwn decode base64 <value>         # also base64url, url, hex
burpwn encode base64url <value>      # also base64, url, hex
```

Handy for reading/tampering cookies, JWTs, and encoded parameters mid-loop.

## Stay authenticated — session auth (login macro)

Persist a login command + a token-extraction regex + a header-injection template.
`refresh` runs the login, extracts the token, and installs a match/replace rule
that injects the header into in-scope requests; the token is auto-refreshed when
the target starts returning 401/403.

```sh
burpwn session auth set \
  --login 'curl -s https://target.example/login -d user=a -d pass=b' \
  --extract '"token":"([^"]+)"' \
  --header 'Authorization: Bearer {}' \
  --host target.example
burpwn session auth refresh          # mint the token now + install the injection rule
burpwn session auth status           # show profiles; token value is masked
```

`--extract` needs exactly one capture group; `--header` uses `{}` as the token
slot; `--host` scopes the injection (substring; omit for all hosts).

## Live interception

```sh
burpwn intercept enable
burpwn intercept await --timeout 60        # long-poll for the next parked flow; returns its id
burpwn intercept list                      # currently parked intercepts
burpwn intercept forward <id> --set-header 'X-Debug: 1' --method POST --set-body '...'
burpwn intercept drop <id>
burpwn intercept disable
```

Typical flow: `enable` → trigger traffic via `exec` → `await` to grab the parked
id → `forward` (optionally edited) or `drop`.

**Scope it** so not every flow parks — narrow to a host (and optionally a path /
method), then widen back with `--clear`:

```sh
burpwn intercept scope target.example --path /admin --method POST
burpwn intercept scope --clear
```

## Match/replace rules (auto-rewrite)

Positional args: `<scope> <kind> <pattern> <replacement>`. `kind` is
`header|body|url|host`; `scope` is a host glob (empty string = all).

```sh
burpwn match-replace add '*.example' header 'User-Agent: .*' 'User-Agent: burpwn'
burpwn match-replace add '' body 'secret' 'REDACTED' --on response
burpwn match-replace list
burpwn match-replace disable <id>          # also: enable <id>, rm <id>
```

## Hooks (act on every request / response)

A rule REWRITES what is already in a message. A hook can add what is not there,
take it out, refuse the flow, or run a command and inject what it prints.

```sh
# a User-Agent on every request, including the ones that never sent one
burpwn hook add ua --action add-header --header 'User-Agent: burpwn'

# keep a bearer token fresh: run the mint command in the sandbox before the
# request, inject what it prints, and reuse it for 5 minutes
burpwn hook add token --action exec --host api.target.com \
  --cmd './mint-token.sh' --extract '"access_token":"([^"]+)"' \
  --inject-header 'Authorization: Bearer {}' --ttl 300000

burpwn hook list
burpwn hook test <id> --flow <flow_id>     # does it match? what does it change?
burpwn hook disable <id>                   # also: enable <id>, rm <id>
```

Scope with `--host/--method/--path` (and `--status` on `--phase post-response`);
`--action` is `add-header|set-header|remove-header|set-query-param|drop|exec`. A
slow or failing `exec` hook FAILS OPEN — the traffic goes through un-hooked — and
only one hook command runs at a time, so a hook whose command talks to the target
cannot trigger itself. `req replay` and `fuzz` apply the declarative hooks only.

## Organize: workspaces, groups, tags, notes, export

```sh
burpwn workspace new recon                 # a workspace scopes a whole capture run
burpwn exec --workspace recon -- curl ...  # attribute captures to it
burpwn req list --workspace recon
burpwn tag add <flow_id> sqli-candidate
burpwn note add <flow_id> 'reflected param `q`'
burpwn export har -o /tmp/session.har      # HAR 1.2 (stdout if no -o); export pcap is not implemented
burpwn export session -o /tmp/acme.burpwn  # the WHOLE session in one portable file
```

A **session bundle** (`burpwn export session`) is the way to hand a session to
someone else, or to park it and come back to it on another machine: one file
holding every flow with its bodies, plus the workspaces, groups, tags, notes,
attacks and rules. `burpwn session import /tmp/acme.burpwn [--as name] [--use]`
opens it as a NEW session — it never merges into or overwrites an existing one,
so a name collision is an error you resolve with `--as`.

⚠️ **The bundle is raw by default**: it carries the stored auth tokens, the login
commands and the `Authorization` / `Cookie` headers captured in the traffic, so
the session replays identically. `--redact` drops the stored auth profiles and
match/replace replacements, but it does **not** scrub credentials captured inside
recorded requests and responses. Move a bundle the way you would move the
credentials it contains.

`burpwn workspace use <name>` only records the choice in config — you must still
pass `--workspace` on `exec`/`req` to actually scope.

**Groups** are named, described SUBSETS of a session's flows — the equivalent of
a Burp highlight, and the right place to record a scenario you had to work out.
Once you understand how the target authenticates, pin it:

```sh
burpwn group new auth-flow \
  --description 'login form -> POST /login -> redirect + Set-Cookie session'
burpwn group add auth-flow 3 5 9           # flow ids, from `req list` / `exec`
burpwn group list                          # name, description, flow count
burpwn group show auth-flow                # the flows, rendered like `req list`
burpwn req list --group auth-flow --method POST
burpwn export har --group auth-flow -o /tmp/auth.har
burpwn group rm-flow auth-flow 5           # and: burpwn group rm auth-flow
```

Do the same to isolate a campaign (`burpwn group new xss-fuzz-search-param
--description '...'`). Names are unique per workspace and `group new` is
idempotent — re-running it returns the same group and updates its description,
so it is safe to call before every `group add`. Deleting a group never deletes
flows.

## CLI vs MCP

- **CLI / hook (default):** use the commands above, or rely on the `init` hook.
- **MCP:** if the agent is already MCP-connected, `burpwn mcp` exposes 42 tools
  over stdio — the full loop is usable MCP-only, no shell needed. Session/query:
  `session_list`, `session_current`, `session_stats`, `req_list`, `req_show`,
  `req_search`, `workspace_list`, `workspace_new`, `tag_list`, `tag_add`,
  `note_add`, `match_replace_list`, `match_replace_add`, `exec`. Organize:
  `group_new`, `group_add`, `group_list`, `group_show`, `group_rm` (named
  collections of flows: a reconstructed auth scenario, one fuzzing campaign),
  and `session_export` to archive the whole session as one portable file (there
  is no import tool — opening a file from elsewhere is an operator decision).
  Repeater/Intruder:
  `req_replay` (Repeater parity — replay/edit stored flows), `fuzz`, `fuzz_list`,
  `fuzz_results`. Analysis: `compare`, `encode`, `decode`. Auth: `session_auth_set`,
  `session_auth_refresh`, `session_auth_status`. Interception: `intercept_enable`,
  `intercept_disable`, `intercept_list`, `await_intercept` (long-poll),
  `intercept_forward` (takes `method`/`path`), `intercept_scope`, `intercept_drop`.
  Use MCP when connected; otherwise use the CLI. Register it with
  `burpwn mcp register --agent <framework>`, then start it with
  `burpwn mcp [--session <n>]`.

## Gotchas

- **Linux only** (relies on rootless user+network namespaces).
- The **proxy daemon starts on the first `exec`** — `req`/`intercept` see flows
  only after something has been run through the sandbox.
- **Cert-pinned hosts** can't be MITM-decrypted; they fall back to passthrough
  (`tls-passthru`) so you get connection metadata only, not decrypted bodies.
- The **agent's own LLM/API traffic is never captured** — only what runs inside
  `exec`.
- Global `--json` emits `{ok, data, error}` — exactly one line on stdout; `exec --json` puts its
  envelope on **fd 3**, not stdout.
- **Output adapts to what stdout is.** Captured by a tool call (never a terminal), every listing
  comes back as TAB-separated records with no header, no footer, no padding and nothing truncated,
  and an empty listing prints **nothing**. Slice it with `cut -f`/`awk -F'\t'`, or pass `--json`
  when you want typed values. Do not expect the aligned columns and colours a human sees.

Full command reference: run `burpwn <command> --help`.
