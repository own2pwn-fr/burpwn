---
name: burpwn
description: Use burpwn (a Burp-like transparent intercepting proxy + rootless sandbox for Linux) to capture, inspect, search, replay, and live-intercept HTTP/HTTPS/DNS/TCP traffic when doing web pentesting, debugging API calls, or analyzing what a tool/command sends over the network.
---

# burpwn — AI-driven intercepting proxy

burpwn runs a command inside a user+network namespace whose entire network is
forced through burpwn's MITM proxy. HTTPS is decrypted with a per-install CA
injected into the sandbox trust store, and every request/response is captured to
a per-session SQLite store you can query, filter, replay, and live-edit. The
agent process stays OUTSIDE the sandbox, so its own LLM traffic is never
captured.

Linux only. Prefer `--json` on every command when you need to parse output.

## Setup (once)

```sh
burpwn doctor                      # preflight: rootless namespaces + CA presence
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

## Repeater — replay with edits

```sh
burpwn req replay <id>
burpwn req replay <id> --method POST --set-header 'X-Forwarded-For: 127.0.0.1' \
  --set-header 'Authorization: Bearer NEW' --set-body 'role=admin'
burpwn req replay <id> --set-body @/tmp/payload.json
```

`--set-header` accepts `Name: value` or `Name=value` and is repeatable.
`--set-body` takes a literal string or `@file`.

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

## Match/replace rules (auto-rewrite)

Positional args: `<scope> <kind> <pattern> <replacement>`. `kind` is
`header|body|url|host`; `scope` is a host glob (empty string = all).

```sh
burpwn match-replace add '*.example' header 'User-Agent: .*' 'User-Agent: burpwn'
burpwn match-replace add '' body 'secret' 'REDACTED' --on response
burpwn match-replace list
burpwn match-replace disable <id>          # also: enable <id>, rm <id>
```

## Organize: workspaces, tags, notes, export

```sh
burpwn workspace new recon                 # group flows
burpwn exec --workspace recon -- curl ...  # attribute captures to it
burpwn req list --workspace recon
burpwn tag add <flow_id> sqli-candidate
burpwn note add <flow_id> 'reflected param `q`'
burpwn export har -o /tmp/session.har      # HAR 1.2 (stdout if no -o); export pcap is not implemented
```

`burpwn workspace use <name>` only records the choice in config — you must still
pass `--workspace` on `exec`/`req` to actually scope.

## CLI vs MCP

- **CLI / hook (default):** use the commands above, or rely on the `init` hook.
- **MCP:** if the agent is already MCP-connected, `burpwn mcp` exposes 19 tools
  over stdio (`session_list`, `session_current`, `req_list`, `req_show`,
  `req_search`, `workspace_list`, `workspace_new`, `tag_list`, `tag_add`,
  `note_add`, `match_replace_list`, `match_replace_add`, `intercept_enable`,
  `intercept_disable`, `intercept_list`, `await_intercept` (long-poll),
  `intercept_forward`, `intercept_drop`, `exec`). Use MCP when connected;
  otherwise use the CLI. Start with `burpwn mcp [--session <n>]`.

## Gotchas

- **Linux only** (relies on rootless user+network namespaces).
- The **proxy daemon starts on the first `exec`** — `req`/`intercept` see flows
  only after something has been run through the sandbox.
- **Cert-pinned hosts** can't be MITM-decrypted; they fall back to passthrough
  (`tls-passthru`) so you get connection metadata only, not decrypted bodies.
- The **agent's own LLM/API traffic is never captured** — only what runs inside
  `exec`.
- Global `--json` emits `{ok, data, error}`; `exec --json` puts its envelope on
  **fd 3**, not stdout.

Full flag reference: see `reference.md` in this skill directory.
