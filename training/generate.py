#!/usr/bin/env python3
"""Deterministic generator for the burpwn LLM fine-tuning dataset.

This script is the *source of truth* for ``dataset.jsonl``. It emits one JSON
object per line. Every command name, flag, JSON envelope shape and MCP tool
name encoded here was verified against the real ``burpwn`` debug binary
(``target/debug/burpwn``) and the MCP server's typed parameter structs
(``crates/burpwn-mcp/src/params.rs``) on 2026-06-13.

Two example *styles* are produced, distinguished by the top-level ``"style"``
key on every record (and mirrored in the system prompt):

* ``"cli"``  — chat-format SFT examples. The user states a pentest goal in
  natural language; the assistant replies with the correct ``burpwn`` command(s),
  a short rationale, and (where useful) an interpretation of the JSON envelope.

* ``"mcp"``  — tool-calling examples. The assistant turn carries a ``tool_calls``
  array (OpenAI-compatible shape) naming a real burpwn MCP tool with correct
  JSON arguments; a following ``tool`` role message carries the tool result, and
  a final assistant turn interprets it.

Schema is documented in README.md. Usage::

    python generate.py > dataset.jsonl      # (re)generate
    python generate.py --validate           # validate ./dataset.jsonl
    python generate.py --validate -          # validate stdin

The generator is fully deterministic: no randomness, no network, stdlib only.
Examples are emitted in a stable order so the output diff is reviewable.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Shared constants — grounded against the real binary / source.
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = "1.0"

# System prompts. The model is taught it is an agent driving burpwn either via
# the shell (cli) or via MCP tools (mcp).
SYSTEM_CLI = (
    "You are a web-application penetration-testing assistant that drives "
    "burpwn, a transparent intercepting proxy and rootless sandbox for Linux. "
    "`burpwn exec -- <cmd>` runs a command inside a user+network namespace "
    "whose entire network egress is forced through burpwn's MITM proxy; every "
    "request/response is captured to a per-session SQLite store and can be "
    "listed, searched, inspected, replayed (Repeater), or intercepted live. "
    "Pass the global `--json` flag to get the machine-readable "
    "`{ok, data, error}` envelope. Respond with the exact burpwn command(s) to "
    "run and a brief rationale; interpret JSON output when shown."
)

SYSTEM_MCP = (
    "You are a web-application penetration-testing assistant connected to the "
    "burpwn MCP server (stdio). burpwn is a transparent intercepting proxy and "
    "rootless sandbox; `exec` runs a command in a namespace whose traffic is "
    "captured to a per-session store, and the other tools query, replay and "
    "intercept those flows. Call the appropriate burpwn MCP tool with correct "
    "JSON arguments to accomplish the user's goal, then interpret the result."
)


# --------------------------------------------------------------------------- #
# Record builders.
# --------------------------------------------------------------------------- #


def cli_example(
    *,
    tags: list[str],
    user: str,
    assistant: str,
    system: str = SYSTEM_CLI,
) -> dict[str, Any]:
    """Build a CLI-style chat record."""
    return {
        "schema_version": SCHEMA_VERSION,
        "style": "cli",
        "tags": tags,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
    }


def mcp_example(
    *,
    tags: list[str],
    user: str,
    tool_name: str,
    tool_args: dict[str, Any],
    tool_result: Any,
    assistant_final: str,
    call_id: str = "call_1",
    assistant_preamble: str = "",
) -> dict[str, Any]:
    """Build an MCP tool-calling record (OpenAI-compatible tool_calls shape).

    The assistant first emits a ``tool_calls`` turn (content may be empty), the
    ``tool`` role returns the JSON result keyed by ``tool_call_id``, and a final
    assistant turn interprets it in natural language.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "style": "mcp",
        "tags": tags,
        "messages": [
            {"role": "system", "content": SYSTEM_MCP},
            {"role": "user", "content": user},
            {
                "role": "assistant",
                "content": assistant_preamble,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": json.dumps(tool_args, sort_keys=True),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": tool_name,
                "content": json.dumps(tool_result, sort_keys=True),
            },
            {"role": "assistant", "content": assistant_final},
        ],
    }


# --------------------------------------------------------------------------- #
# CLI-style scenarios (grounded envelopes from the real binary).
# --------------------------------------------------------------------------- #


def cli_records() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # --- Prereqs / setup -------------------------------------------------- #
    out.append(
        cli_example(
            tags=["setup", "doctor"],
            user="Before I start, can you check my machine is ready to run burpwn?",
            assistant=(
                "Run the prerequisite probe:\n\n"
                "```\nburpwn --json doctor\n```\n\n"
                "This checks the unprivileged user namespace, the subuid entry, "
                "`bwrap`, `nft`, `ip`, and whether the CA exists. A ready host "
                "returns:\n\n"
                '```json\n{"ok":true,"data":{"bwrap_present":true,"ca_present":true,'
                '"ip_present":true,"missing":"","nft_present":true,"ready":true,'
                '"subuid_present":true,"userns_enabled":true},"error":null}\n```\n\n'
                "If `ready` is `false`, look at `ca_present` (fix with `burpwn ca "
                "init`) and any `*_present` field that is `false`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["setup", "doctor", "interpret"],
            user=(
                "I ran `burpwn --json doctor` and got "
                '`{"ok":true,"data":{"bwrap_present":true,"ca_present":false,'
                '"ip_present":true,"missing":"","nft_present":true,"ready":false,'
                '"subuid_present":true,"userns_enabled":true},"error":null}`. '
                "What do I do?"
            ),
            assistant=(
                "Everything is present except the CA: `ca_present` is `false`, "
                "which is why `ready` is `false`. Generate the root CA:\n\n"
                "```\nburpwn ca init\n```\n\n"
                "Then re-run `burpwn --json doctor`; `ca_present` and `ready` "
                "should both be `true`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["setup", "ca"],
            user="Generate the MITM root CA and tell me where it lives.",
            assistant=(
                "```\nburpwn ca init\n```\n\n"
                "It is idempotent (generates the CA only if absent) and reports the "
                "path:\n\n"
                '```json\n{"ok":true,"data":{"ca_pem":"/home/me/.local/share/burpwn/'
                'ca.pem"},"error":null}\n```'
            ),
        )
    )
    out.append(
        cli_example(
            tags=["setup", "ca", "export"],
            user="I need the CA certificate as PEM to install in a browser profile.",
            assistant=(
                "Print the CA certificate to stdout (redirect it to a file if you "
                "want):\n\n"
                "```\nburpwn ca export > burpwn-ca.pem\n```\n\n"
                "`ca export` writes the verbatim PEM (`-----BEGIN CERTIFICATE-----` …), "
                "not a JSON envelope, so it is safe to pipe directly into a trust store."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["setup", "init", "agent"],
            user="Hook burpwn into Claude Code so its shell commands run in the sandbox.",
            assistant=(
                "Install the agent hook (no argument defaults to the Claude Code "
                "hook):\n\n"
                "```\nburpwn init --agent claude\n```\n\n"
                "Result:\n\n"
                '```json\n{"ok":true,"data":{"installed":[{"action":"Installed",'
                '"agent":"claude-code","path":"/home/me/.claude/settings.json"}]},'
                '"error":null}\n```\n\n'
                "Use `burpwn init -g` instead to install a generic global shell hook "
                "(patches `~/.bashrc` and `~/.zshrc`) that covers any agent."
            ),
        )
    )

    # --- Sessions --------------------------------------------------------- #
    out.append(
        cli_example(
            tags=["session", "setup"],
            user="Start a fresh session for the acme.com engagement and make it active.",
            assistant=(
                "Create the session, then switch to it:\n\n"
                "```\nburpwn session new --name acme\nburpwn session use acme\n```\n\n"
                "`session new` returns `{\"ok\":true,\"data\":{\"name\":\"acme\"},"
                "\"error\":null}` and `session use` confirms with "
                "`{\"ok\":true,\"data\":{\"active\":\"acme\"},\"error\":null}`. All "
                "subsequent `exec`/`req` operate on the active session unless you pass "
                "`--session`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["session", "list"],
            user="Which burpwn sessions exist and which one am I on?",
            assistant=(
                "```\nburpwn --json session list\n```\n\n"
                "The active session is named in `data.active`:\n\n"
                '```json\n{"ok":true,"data":{"active":"acme","sessions":["default",'
                '"acme","probe"]},"error":null}\n```'
            ),
        )
    )
    out.append(
        cli_example(
            tags=["session", "rm"],
            user="Delete the old 'probe' session and its database.",
            assistant=(
                "```\nburpwn session rm probe\n```\n\n"
                "This removes the session's SQLite store and runtime files. Note you "
                "cannot remove the session you are currently `use`-ing without switching "
                "away first."
            ),
        )
    )

    # --- exec / recon ----------------------------------------------------- #
    out.append(
        cli_example(
            tags=["exec", "recon", "curl"],
            user="Fetch the acme.com homepage through the proxy so it gets captured.",
            assistant=(
                "```\nburpwn exec -- curl -s https://acme.com/\n```\n\n"
                "Everything after `--` is the command run inside the sandbox; its "
                "network is forced through burpwn's MITM proxy, so the request/response "
                "(plus the DNS lookups) land in the session store. The command's own "
                "stdout passes through untouched. Add `--json` to also get the exec "
                "envelope `{exit_code, exec_id, captured_request_ids}` on fd 3."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["exec", "recon", "envelope", "interpret"],
            user=(
                "I ran `burpwn --json exec -- curl -s -o /dev/null https://acme.com/` "
                "and fd 3 gave me "
                '`{"ok":true,"data":{"captured_request_ids":[12,13,14],'
                '"exec_id":"exec-3608212-0-1781363759621297073","exit_code":0},'
                '"error":null}`. What now?'
            ),
            assistant=(
                "The command exited cleanly (`exit_code: 0`) and burpwn captured three "
                "flows during this run: ids 12, 13 and 14 (typically the A/AAAA DNS "
                "queries plus the HTTP request). Inspect the HTTP one with "
                "`burpwn req show 14` (highest id is usually the request, the DNS ones "
                "are the QUERY flows). You can correlate everything from this run later "
                "via the `exec_id`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["exec", "recon", "tool", "ffuf"],
            user="Run ffuf content discovery against https://acme.com/FUZZ through burpwn.",
            assistant=(
                "Wrap the whole ffuf invocation after `--` and give it a generous "
                "timeout since fuzzing is long-running:\n\n"
                "```\nburpwn exec --timeout 600 -- ffuf -u https://acme.com/FUZZ "
                "-w wordlist.txt -mc 200,301,302,403\n```\n\n"
                "Every probe ffuf makes is captured, so afterwards you can "
                "`burpwn req list --host acme.com --status 200` to review the hits "
                "with their real responses."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["exec", "recon", "workspace"],
            user="Crawl acme.com with a spider but keep its flows in their own bucket.",
            assistant=(
                "Create a workspace and attribute the exec's flows to it by id:\n\n"
                "```\nburpwn workspace new crawl\nburpwn exec --workspace 2 -- "
                "katana -u https://acme.com -silent\n```\n\n"
                "`workspace new crawl` returns the new id (e.g. "
                "`{\"ok\":true,\"data\":{\"id\":2,\"name\":\"crawl\"},\"error\":null}`); "
                "pass that **id** to `--workspace`. Later filter with "
                "`burpwn req list --workspace 2`."
            ),
        )
    )

    # --- req list / filter ------------------------------------------------ #
    out.append(
        cli_example(
            tags=["req", "list", "interpret"],
            user="Show me the most recent captured flows.",
            assistant=(
                "```\nburpwn --json req list --limit 20\n```\n\n"
                "Flows come back newest-first as an array. Each row looks like:\n\n"
                '```json\n{"authority":"acme.com","dst_ip":"104.20.23.154",'
                '"dst_port":443,"id":14,"intercepted":false,"method":"GET","path":"/",'
                '"protocol":"h2","scheme":"https","sni":"acme.com","status":200,'
                '"ts_end":1781363726726,"ts_start":1781363726697,"workspace_id":1}\n```'
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "list", "filter"],
            user="List only the successful GET requests to api.acme.com.",
            assistant=(
                "Stack the exact-match filters:\n\n"
                "```\nburpwn req list --host api.acme.com --method GET --status 200\n```\n\n"
                "`--host` is a substring match against host/SNI/dst-ip; `--method` and "
                "`--status` are exact. Add `--json` for the array envelope, or "
                "`--limit`/`--offset` to page."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "list", "filter", "protocol"],
            user="Did the app open any websockets? Show me only WS flows.",
            assistant=(
                "Filter by wire protocol:\n\n"
                "```\nburpwn req list --protocol ws\n```\n\n"
                "Valid `--protocol` values are `h1`, `h2`, `ws`, `dns`, `rawtcp`, and "
                "`tls-passthru`. Use `--protocol dns` to review name resolution, or "
                "`--protocol tls-passthru` to see cert-pinned hosts that bypassed MITM."
            ),
        )
    )

    # --- req show / raw --------------------------------------------------- #
    out.append(
        cli_example(
            tags=["req", "show", "https", "interpret"],
            user="Show me the decrypted request and response for flow 14.",
            assistant=(
                "```\nburpwn --json req show 14\n```\n\n"
                "Because the traffic was MITM'd, the HTTPS body is decrypted. You get "
                "the decoded request/response with separate `headers` and `body`:\n\n"
                '```json\n{"ok":true,"data":{"id":14,"protocol":"h2","scheme":"https",'
                '"request":{"method":"GET","path":"/","headers":"...","body":""},'
                '"response":{"status":200,"headers":"...","body":"<!doctype html>..."}},'
                '"error":null}\n```'
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "show", "raw"],
            user="I need the byte-exact request and response for flow 14 to craft a PoC.",
            assistant=(
                "Use `--raw` to print the verbatim wire bytes instead of the parsed "
                "summary:\n\n"
                "```\nburpwn req show 14 --raw\n```\n\n"
                "This prints the literal request head + body, a blank line, then the "
                "literal response head + body — ideal for copy-pasting into a report or "
                "feeding to another tool."
            ),
        )
    )

    # --- search ----------------------------------------------------------- #
    out.append(
        cli_example(
            tags=["req", "search", "interpret"],
            user="Find any captured flow whose body mentions a password.",
            assistant=(
                "Full-text search runs over request/response bodies:\n\n"
                "```\nburpwn --json req search password\n```\n\n"
                "It returns matching flow ids, newest-first:\n\n"
                '```json\n{"ok":true,"data":{"flow_ids":[31,18,9]},"error":null}\n```\n\n'
                "Then `burpwn req show 31 --raw` on each id to read the match in context. "
                "The query is an FTS5 expression, so you can do `req search "
                '"authorization OR bearer"` too.'
            ),
        )
    )

    # --- replay / Repeater (IDOR/authz) ----------------------------------- #
    out.append(
        cli_example(
            tags=["req", "replay", "idor"],
            user=(
                "Flow 22 is `GET /api/users/1001/profile` with my own token. Test for "
                "IDOR by replaying it against user 1002."
            ),
            assistant=(
                "Replay (Repeater) the stored flow with the path edited. `req replay` "
                "doesn't have a `--set-path`, so override the resource via the method/"
                "headers you can change and re-target by editing the request — here the "
                "cleanest approach is to replay flow 22 then compare. To change just the "
                "id, replay and inspect:\n\n"
                "```\nburpwn --json req replay 22 --set-header "
                '"X-Original-User: 1002"\n```\n\n'
                "For path-level IDOR, the supported edits are headers, body and method; "
                "if the user id is in the URL path, copy the raw request "
                "(`burpwn req show 22 --raw`), change `1001`→`1002`, and re-issue it via "
                "`burpwn exec -- curl ...`. The replay envelope returns the new "
                "`{status, response}` so you can diff it against the original 200."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "replay", "authz"],
            user="Re-send flow 22 but strip the Authorization header to test for missing authz.",
            assistant=(
                "Override the header to empty (or to a junk value) and replay:\n\n"
                "```\nburpwn --json req replay 22 --set-header \"Authorization: \"\n```\n\n"
                "The envelope echoes the live response:\n\n"
                '```json\n{"ok":true,"data":{"status":200,"response":"HTTP/1.1 200 OK\\r\\n'
                '..."},"error":null}\n```\n\n'
                "If the endpoint still returns `200` with data, it is missing "
                "authentication. A `401`/`403` is the expected, secure behaviour. "
                "`--set-header` takes `Name: value` or `Name=value` and is repeatable."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "replay", "method", "body"],
            user="Replay flow 30 as a POST with a tampered JSON body from payload.json.",
            assistant=(
                "Override the method and read the body from a file with `@`:\n\n"
                "```\nburpwn req replay 30 --method POST --set-body @payload.json "
                '--set-header "Content-Type: application/json"\n```\n\n'
                "`--set-body` accepts a literal string or `@file`; `--method` overrides "
                "the verb. The original flow is untouched — replay always issues a fresh "
                "request and returns its response."
            ),
        )
    )

    # --- intercept (live tamper) ----------------------------------------- #
    out.append(
        cli_example(
            tags=["intercept", "workflow", "tamper"],
            user=(
                "I want to manually tamper the next request the app sends — add an admin "
                "header before it goes out."
            ),
            assistant=(
                "Enable interception, wait for the next request to park, then forward it "
                "with the header added:\n\n"
                "```\nburpwn intercept enable\nburpwn --json intercept await --timeout 60\n```\n\n"
                "`await` returns the parked item with its id, e.g. "
                '`{"ok":true,"data":{"type":"Pending","item":{"id":1,...}}}`. Forward '
                "that id with the edit:\n\n"
                "```\nburpwn intercept forward 1 --set-header \"X-Admin: true\"\n```\n\n"
                "If `await` times out with no traffic you get "
                '`{"ok":true,"data":{"type":"Pending","item":null},"error":null}` — just '
                "poll again. Run `burpwn intercept disable` when you're done."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "drop"],
            user="A telemetry beacon got parked as intercept id 3 — I don't want it sent. Kill it.",
            assistant=(
                "Drop the parked intercept so it is never forwarded:\n\n"
                "```\nburpwn intercept drop 3\n```\n\n"
                "A successful drop returns "
                '`{"ok":true,"data":{"type":"Resolved","found":true},"error":null}`. If '
                "`found` is `false`, that id was already forwarded/dropped or never "
                "existed."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "list"],
            user="What requests are currently held by the interceptor?",
            assistant=(
                "```\nburpwn --json intercept list\n```\n\n"
                "Returns the parked items:\n\n"
                '```json\n{"ok":true,"data":{"type":"Intercepts","items":[]},'
                '"error":null}\n```\n\n'
                "An empty `items` array means nothing is currently parked (or "
                "interception is disabled)."
            ),
        )
    )

    # --- match/replace ---------------------------------------------------- #
    out.append(
        cli_example(
            tags=["match-replace", "auth-inject"],
            user="Inject a fixed bearer token into every request to all hosts.",
            assistant=(
                "Add a request-side match/replace rule on the `header` kind with an "
                "empty scope (= all hosts):\n\n"
                "```\nburpwn match-replace add \"\" header Authorization "
                '"Bearer eyJhbGciOi..."\n```\n\n'
                "It returns the new rule id: `{\"ok\":true,\"data\":{\"id\":1},"
                "\"error\":null}`. Arguments are `<SCOPE> <KIND> <PATTERN> "
                "<REPLACEMENT>`; `--on request` is the default (use `--on response` to "
                "rewrite responses instead). Every subsequent `exec` request now carries "
                "the header."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["match-replace", "list", "interpret"],
            user="What match/replace rules are active?",
            assistant=(
                "```\nburpwn --json match-replace list\n```\n\n"
                "Each rule shows its id, scope, kind, pattern, replacement, direction and "
                "enabled flag:\n\n"
                '```json\n{"ok":true,"data":[{"enabled":true,"id":1,"match_kind":"header",'
                '"on_request":true,"pattern":"Authorization","replacement":"Bearer ...",'
                '"scope":""}],"error":null}\n```'
            ),
        )
    )
    out.append(
        cli_example(
            tags=["match-replace", "scope", "response"],
            user="On only *.acme.com responses, rewrite the string PRODUCTION to STAGING.",
            assistant=(
                "Scope it to the host glob, match on the `body` kind, and apply on "
                "responses:\n\n"
                "```\nburpwn match-replace add \"*.acme.com\" body PRODUCTION STAGING "
                "--on response\n```\n\n"
                "`<SCOPE>` is a host glob (empty = all hosts), `<KIND>` is one of "
                "`header|body|url|host`, and `--on response` flips it from the default "
                "request direction."
            ),
        )
    )

    # --- tag / note ------------------------------------------------------- #
    out.append(
        cli_example(
            tags=["tag", "triage"],
            user="Flag flow 14 as a candidate SQL injection so I can find it later.",
            assistant=(
                "```\nburpwn tag add 14 sqli\n```\n\n"
                "Arguments are `<FLOW_ID> <NAME>`; the tag is created if it doesn't "
                "exist. Returns `{\"ok\":true,\"data\":{\"flow_id\":14,\"name\":\"sqli\","
                "\"tag_id\":2},\"error\":null}`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["note", "triage"],
            user="Add a note to flow 14 reminding me the id param looked injectable.",
            assistant=(
                "```\nburpwn note add 14 \"id param reflects unescaped in SQL error\"\n```\n\n"
                "Arguments are `<FLOW_ID> <TEXT>`. Returns "
                '`{"ok":true,"data":{"flow_id":14,"note_id":1},"error":null}`.'
            ),
        )
    )

    # --- export ----------------------------------------------------------- #
    out.append(
        cli_example(
            tags=["export", "har"],
            user="Export all captured traffic to a HAR file for the report.",
            assistant=(
                "```\nburpwn export har -o acme-session.har\n```\n\n"
                "Writes an HAR 1.2 document; without `-o` it prints to stdout. Scope it "
                "with `--workspace <id>` to export just one bucket. The document is "
                "`{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"burpwn\",...},"
                "\"entries\":[...]}}`."
            ),
        )
    )

    # --- workspaces ------------------------------------------------------- #
    out.append(
        cli_example(
            tags=["workspace", "organise"],
            user="Group this target's flows under a workspace called 'login-flow'.",
            assistant=(
                "Create the workspace, then attribute traffic to it by passing its **id** "
                "to `exec`/`req` (the `workspace use` command is informational only):\n\n"
                "```\nburpwn workspace new login-flow\nburpwn exec --workspace 3 -- "
                "curl -s https://acme.com/login\nburpwn req list --workspace 3\n```\n\n"
                "`workspace new` returns the id to use; `workspace use <name>` merely "
                "records the choice in config and does not auto-scope, so always pass "
                "`--workspace <id>` explicitly."
            ),
        )
    )

    # --- choosing CLI vs MCP --------------------------------------------- #
    out.append(
        cli_example(
            tags=["meta", "mcp-vs-cli"],
            user="Should I drive burpwn via the shell or over MCP from my agent?",
            assistant=(
                "Both expose the same engine. Use the **CLI** (`burpwn <cmd> --json`) "
                "for ad-hoc shell work, scripting and piping. Use the **MCP server** "
                "(`burpwn mcp`, stdio) when an LLM agent should call burpwn as tools — it "
                "exposes 19 tools (`req_list`, `req_show`, `req_search`, `req_replay`-"
                "equivalent via `exec`, `intercept_*`, `match_replace_*`, `tag_add`, "
                "`note_add`, `exec`, …) with typed JSON arguments. The MCP `exec` returns "
                "`{exit_code, captured_request_ids, exec_id}` directly in the tool result."
            ),
        )
    )

    # --- NEGATIVE / disambiguation --------------------------------------- #
    out.append(
        cli_example(
            tags=["negative", "export", "pcap"],
            user="Export the session as a pcap so I can open it in Wireshark.",
            assistant=(
                "pcap export is **not implemented** — the command errors clearly:\n\n"
                '```json\n{"ok":false,"data":null,"error":"pcap export is not yet '
                'implemented (use `export har`)"}\n```\n\n'
                "Use HAR instead: `burpwn export har -o acme.har`. Most HTTP-analysis "
                "tooling imports HAR, and it preserves the decrypted bodies that a pcap "
                "of MITM'd TLS would not."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["negative", "match-replace", "rm"],
            user="Remove match/replace rule 1.",
            assistant=(
                "Heads up: `match-replace rm`, `enable` and `disable` are **not yet "
                "supported** in the current build — the store writer only exposes "
                "add + list for rules. Attempting it errors:\n\n"
                "```\nburpwn: match-replace rm/enable/disable are not yet supported: the "
                "store writer exposes only add + list for rules (no update/delete API)\n```\n\n"
                "Workaround: rules apply only while the proxy daemon is running for the "
                "session, so to clear a rule today you stop/restart the session's daemon "
                "(or start a fresh session). Re-add the rules you still want with "
                "`match-replace add`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["negative", "dns"],
            user=(
                "Does name resolution even work inside the sandbox, or do I have to use raw "
                "IPs?"
            ),
            assistant=(
                "DNS works — hostnames resolve normally. burpwn runs a DNS resolver inside "
                "the namespace and **captures the lookups too**: you'll see them as `dns` "
                "protocol flows with `method:\"QUERY\"` and paths like "
                "`acme.com./A` / `acme.com./AAAA`. So `burpwn exec -- curl https://acme.com` "
                "is fine; review the resolution with `burpwn req list --protocol dns`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["negative", "tls-passthru", "pinning"],
            user="One host's requests show up as 'tls-passthru' with no decrypted body. Why?",
            assistant=(
                "That host is **certificate-pinned** (or otherwise refused burpwn's CA), "
                "so burpwn could not MITM it and let the TLS pass through untouched — "
                "hence the `tls-passthru` protocol and no plaintext. You can still see the "
                "flow metadata (SNI, dst ip/port, timing) via "
                "`burpwn req list --protocol tls-passthru`, but not the decrypted body. "
                "To inspect it you'd need to defeat the pinning in the client itself; "
                "burpwn deliberately doesn't break pinned connections."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["negative", "llm-traffic"],
            user=(
                "If I run my AI agent under `burpwn exec`, won't burpwn capture the agent's "
                "own calls to the LLM API and pollute the flows?"
            ),
            assistant=(
                "No. burpwn is designed so the **agent's own LLM traffic stays outside the "
                "sandbox** and is never captured — only the commands you launch via "
                "`burpwn exec -- <cmd>` (the actual pentest tooling) have their network "
                "forced through the proxy. So `req list` shows the target's traffic, not "
                "your model API calls."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["negative", "req-show", "missing"],
            user="I ran `burpwn req show 999` and it said `burpwn: no such flow: 999`. Bug?",
            assistant=(
                "Not a bug — flow 999 doesn't exist in the active session's store. List "
                "what's actually captured first with `burpwn --json req list` and use a "
                "real id from the `id` field. Also confirm you're on the right session "
                "(`burpwn session list`); flows are per-session, so an id from another "
                "session won't resolve here."
            ),
        )
    )

    # --- extra coverage --------------------------------------------------- #
    out.append(
        cli_example(
            tags=["exec", "session-override"],
            user="Run a sqlmap probe but attribute it to my 'acme' session, not whatever's active.",
            assistant=(
                "Pin the session explicitly with `--session` (it must follow the `exec` "
                "token, before `--`):\n\n"
                "```\nburpwn exec --session acme --timeout 900 -- sqlmap -u "
                '"https://acme.com/item?id=1" --batch\n```\n\n'
                "Without `--session` it uses the active session from `session list`. All "
                "of sqlmap's payloads are captured under `acme` for later `req list`/"
                "`req search`."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "list", "port"],
            user="Show flows that went to a non-standard port, like 8443.",
            assistant=(
                "Filter by exact destination port:\n\n"
                "```\nburpwn req list --port 8443\n```\n\n"
                "`--port` is an exact match against `dst_port`. Combine with `--host` to "
                "narrow to one target's alternate port."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["workflow", "recon-triage", "multi-step"],
            user=(
                "Walk me through a quick flow: fetch the login page, find the form action in "
                "the capture, and flag it."
            ),
            assistant=(
                "1. Capture the page:\n"
                "```\nburpwn exec -- curl -s https://acme.com/login\n```\n"
                "2. Find which flow holds the form (full-text search the body):\n"
                "```\nburpwn --json req search \"<form\"\n```\n"
                "   → `{\"ok\":true,\"data\":{\"flow_ids\":[14]},\"error\":null}`\n"
                "3. Read it and tag it for follow-up:\n"
                "```\nburpwn req show 14 --raw\nburpwn tag add 14 login-form\n"
                "burpwn note add 14 \"POST action=/auth, has CSRF token field\"\n```"
            ),
        )
    )
    out.append(
        cli_example(
            tags=["req", "list", "pagination"],
            user="There are hundreds of flows — give me rows 50 to 100.",
            assistant=(
                "Page with `--limit` and `--offset`:\n\n"
                "```\nburpwn req list --limit 50 --offset 50\n```\n\n"
                "Results are newest-first, so `--offset 50` skips the 50 most recent and "
                "`--limit 50` returns the next 50."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "disable"],
            user="I'm done tampering — stop holding requests.",
            assistant=(
                "```\nburpwn intercept disable\n```\n\n"
                "Returns `{\"ok\":true,\"data\":{\"type\":\"Ack\"},\"error\":null}`. New "
                "requests now flow straight through (still captured, just not parked). "
                "Drop or forward any already-parked items first with `intercept list` if "
                "you don't want them stuck."
            ),
        )
    )
    out.append(
        cli_example(
            tags=["negative", "intercept", "await-timeout"],
            user=(
                "`burpwn --json intercept await --timeout 5` returned "
                '`{"ok":true,"data":{"type":"Pending","item":null},"error":null}`. Did it '
                "fail?"
            ),
            assistant=(
                "No — `item: null` just means nothing was parked within the 5-second "
                "window (the long-poll timed out). That's normal when the app is idle. "
                "Make sure interception is enabled (`burpwn intercept enable`), trigger "
                "some traffic, and `await` again — increase `--timeout` (default 30) to "
                "block longer."
            ),
        )
    )

    return out


# --------------------------------------------------------------------------- #
# MCP-style scenarios (tool args & results grounded in params.rs / handlers).
# --------------------------------------------------------------------------- #


def mcp_records() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    out.append(
        mcp_example(
            tags=["mcp", "session_list"],
            user="Which burpwn session is active?",
            tool_name="session_current",
            tool_args={},
            tool_result={"active": "acme", "db_exists": True},
            assistant_final=(
                "You're on the `acme` session and its capture database exists, so it's "
                "ready to query."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "req_list", "filter"],
            user="List successful GET requests to api.acme.com.",
            tool_name="req_list",
            tool_args={"host": "api.acme.com", "method": "GET", "status": 200},
            tool_result=[
                {
                    "id": 41,
                    "authority": "api.acme.com",
                    "method": "GET",
                    "path": "/v1/me",
                    "status": 200,
                    "protocol": "h2",
                    "scheme": "https",
                    "dst_port": 443,
                }
            ],
            assistant_final=(
                "One matching flow: id 41, `GET https://api.acme.com/v1/me` → 200 over "
                "HTTP/2. Want me to fetch its decoded request/response with `req_show`?"
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "req_show", "raw"],
            user="Show me the raw bytes of flow 41 so I can build a PoC.",
            tool_name="req_show",
            tool_args={"id": 41, "raw": True},
            tool_result={
                "id": 41,
                "protocol": "h2",
                "request": {"method": "GET", "path": "/v1/me", "headers": "authorization: Bearer ...\r\n", "body": ""},
                "response": {"status": 200, "headers": "content-type: application/json\r\n", "body": "{\"id\":1001,\"role\":\"user\"}"},
                "raw_request": "GET /v1/me HTTP/2\r\nauthorization: Bearer ...\r\n\r\n",
                "raw_response": "HTTP/2 200\r\ncontent-type: application/json\r\n\r\n{\"id\":1001,\"role\":\"user\"}",
            },
            assistant_final=(
                "Flow 41 is `GET /v1/me` with a bearer token; the JSON response exposes "
                "`{\"id\":1001,\"role\":\"user\"}`. The `raw_request`/`raw_response` fields "
                "give you the byte-exact messages. Since the response leaks the numeric "
                "user id, this is a good candidate to test for IDOR on `/v1/users/<id>`."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "req_search"],
            user="Search captured traffic for anything containing 'token'.",
            tool_name="req_search",
            tool_args={"query": "token"},
            tool_result={"flow_ids": [41, 37, 12]},
            assistant_final=(
                "Three flows mention 'token': ids 41, 37 and 12 (newest first). I can "
                "`req_show` any of them to read the match in context."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "exec", "recon"],
            user="Curl the acme.com homepage through the sandbox and tell me what got captured.",
            tool_name="exec",
            tool_args={"argv": ["curl", "-s", "-o", "/dev/null", "https://acme.com/"]},
            tool_result={
                "exit_code": 0,
                "captured_request_ids": [50, 51, 52],
                "exec_id": "exec-4101-0-1781400000000000000",
            },
            assistant_final=(
                "The fetch succeeded (`exit_code: 0`) and captured three flows: 50, 51 "
                "and 52 (the A/AAAA DNS queries plus the HTTPS GET). Use `req_show` on the "
                "highest id (52) to see the decoded homepage response."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "exec", "timeout"],
            user="Run a 5-minute nuclei scan against https://acme.com under the sandbox.",
            tool_name="exec",
            tool_args={
                "argv": ["nuclei", "-u", "https://acme.com", "-silent"],
                "timeout_secs": 300,
            },
            tool_result={
                "exit_code": 0,
                "captured_request_ids": [60, 61, 62, 63, 64],
                "exec_id": "exec-4140-1-1781400500000000000",
            },
            assistant_final=(
                "nuclei finished within the 5-minute budget and burpwn captured 5 flows "
                "(60–64). Review them with `req_list` to see exactly which requests nuclei "
                "sent and the live responses."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "match_replace_add", "auth-inject"],
            user="Inject a bearer token into every request to all hosts.",
            tool_name="match_replace_add",
            tool_args={
                "scope": "",
                "kind": "header",
                "pattern": "Authorization",
                "replacement": "Bearer eyJhbGciOi...",
                "on_request": True,
            },
            tool_result={"id": 1},
            assistant_final=(
                "Rule 1 is in place: on every request (empty scope = all hosts) the "
                "`Authorization` header is set to your bearer token. New flows captured "
                "via `exec` will carry it. Note `on_request: true` targets requests; set "
                "it to `false` to rewrite responses."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "workspace_new"],
            user="Create a workspace called login-flow.",
            tool_name="workspace_new",
            tool_args={"name": "login-flow"},
            tool_result={"id": 3, "name": "login-flow"},
            assistant_final=(
                "Created workspace `login-flow` with id 3. Pass `workspace: \"3\"` (or the "
                "id on the CLI) to `exec` to attribute captured flows to it."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "tag_add", "triage"],
            user="Tag flow 41 as idor.",
            tool_name="tag_add",
            tool_args={"flow_id": 41, "name": "idor"},
            tool_result={"flow_id": 41, "name": "idor", "tag_id": 2},
            assistant_final="Flow 41 is now tagged `idor` (tag id 2).",
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "note_add", "triage"],
            user="Note on flow 41 that /v1/me leaks the numeric user id.",
            tool_name="note_add",
            tool_args={"flow_id": 41, "body": "/v1/me response leaks numeric user id 1001 -> test IDOR"},
            tool_result={"flow_id": 41, "note_id": 1},
            assistant_final=(
                "Note saved on flow 41. (Heads up: the MCP `note_add` argument is `body`, "
                "whereas the CLI takes a positional `<TEXT>` — same effect.)"
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept", "enable"],
            user="Turn on live interception so I can tamper the next request.",
            tool_name="intercept_enable",
            tool_args={},
            tool_result={"type": "Ack"},
            assistant_final=(
                "Interception is enabled (`Ack`). Call `await_intercept` to block for the "
                "next parked request, then `intercept_forward` (with edits) or "
                "`intercept_drop` to resolve it."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "await_intercept", "workflow"],
            user="Wait up to 60s for the next request to be held, then I'll edit it.",
            tool_name="await_intercept",
            tool_args={"timeout_secs": 60},
            tool_result={
                "type": "Pending",
                "item": {
                    "id": 1,
                    "method": "POST",
                    "authority": "acme.com",
                    "path": "/cart/checkout",
                },
            },
            assistant_final=(
                "A request is parked: intercept id 1, `POST acme.com/cart/checkout`. Tell "
                "me what to change and I'll release it with `intercept_forward` (e.g. set "
                "headers or replace the body), or drop it with `intercept_drop`."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_forward", "tamper"],
            user="Forward the parked request (id 1) but bump the quantity and add an admin header.",
            tool_name="intercept_forward",
            tool_args={
                "id": 1,
                "set_headers": [{"name": "X-Admin", "value": "true"}],
                "set_body": "{\"item\":\"sku-9\",\"qty\":99}",
            },
            tool_result={"type": "Resolved", "found": True},
            assistant_final=(
                "Forwarded intercept 1 with the `X-Admin: true` header and the tampered "
                "body (`qty:99`). `found:true` confirms it was released. Note the MCP "
                "`intercept_forward` takes `set_headers` as `[{name,value}]` and a "
                "`set_body` string (no method override — use the CLI `--method` for that)."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_drop"],
            user="Actually, drop parked intercept 2 — it's a telemetry beacon.",
            tool_name="intercept_drop",
            tool_args={"id": 2},
            tool_result={"type": "Resolved", "found": True},
            assistant_final="Dropped intercept 2; it will not be forwarded (`found:true`).",
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "match_replace_list"],
            user="What rewrite rules are configured?",
            tool_name="match_replace_list",
            tool_args={},
            tool_result=[
                {
                    "id": 1,
                    "scope": "",
                    "match_kind": "header",
                    "pattern": "Authorization",
                    "replacement": "Bearer ...",
                    "on_request": True,
                    "enabled": True,
                }
            ],
            assistant_final=(
                "One enabled rule (id 1): on all-host requests, set the `Authorization` "
                "header. There's no MCP tool to delete/disable rules (the store only "
                "supports add + list), so to clear it you'd restart the session daemon."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "session_list"],
            user="What sessions are available?",
            tool_name="session_list",
            tool_args={},
            tool_result={"active": "acme", "sessions": ["default", "acme", "probe"]},
            assistant_final=(
                "Three sessions exist — `default`, `acme`, `probe` — and `acme` is "
                "active."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "workspace_list"],
            user="List the workspaces in this session.",
            tool_name="workspace_list",
            tool_args={},
            tool_result=[
                {"id": 1, "name": "default", "created_at": 0},
                {"id": 3, "name": "login-flow", "created_at": 1781363698970},
            ],
            assistant_final=(
                "Two workspaces: `default` (id 1) and `login-flow` (id 3). Use id 3 with "
                "`exec`'s workspace argument to scope new captures to the login flow."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "tag_list", "triage"],
            user="What tags have I applied so far?",
            tool_name="tag_list",
            tool_args={},
            tool_result=[{"id": 2, "name": "idor"}, {"id": 3, "name": "login-form"}],
            assistant_final="You've used two tags: `idor` (id 2) and `login-form` (id 3).",
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_list"],
            user="Is anything currently held by the interceptor?",
            tool_name="intercept_list",
            tool_args={},
            tool_result={"type": "Intercepts", "items": []},
            assistant_final=(
                "Nothing is parked right now (`items` is empty). Either interception is "
                "off or no matching request has arrived yet — enable it with "
                "`intercept_enable` and `await_intercept` for the next one."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_disable"],
            user="Disable interception, I'm done.",
            tool_name="intercept_disable",
            tool_args={},
            tool_result={"type": "Ack"},
            assistant_final=(
                "Interception is now off (`Ack`); traffic flows through normally and is "
                "still captured."
            ),
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "req_list", "pagination"],
            user="Give me the 25 newest flows.",
            tool_name="req_list",
            tool_args={"limit": 25},
            tool_result=[
                {"id": 64, "authority": "acme.com", "method": "GET", "path": "/", "status": 200, "protocol": "h2"},
                {"id": 63, "authority": "acme.com", "method": "POST", "path": "/auth", "status": 302, "protocol": "h2"},
            ],
            assistant_final=(
                "Newest flows (showing the top of 25): id 64 `GET /` → 200, and id 63 "
                "`POST /auth` → 302 (a redirect after login). The 302 on `/auth` is worth "
                "a `req_show` to see the Set-Cookie/session handling."
            ),
        )
    )

    return out


# --------------------------------------------------------------------------- #
# Assembly / validation.
# --------------------------------------------------------------------------- #


def all_records() -> list[dict[str, Any]]:
    return cli_records() + mcp_records()


def emit(records: Iterable[dict[str, Any]]) -> None:
    for rec in records:
        sys.stdout.write(json.dumps(rec, ensure_ascii=False, sort_keys=True))
        sys.stdout.write("\n")


VALID_ROLES = {"system", "user", "assistant", "tool"}


def validate_record(idx: int, rec: dict[str, Any]) -> list[str]:
    """Return a list of human-readable problems with one record (empty = ok)."""
    errs: list[str] = []

    def err(msg: str) -> None:
        errs.append(f"line {idx}: {msg}")

    if rec.get("schema_version") != SCHEMA_VERSION:
        err(f"schema_version must be {SCHEMA_VERSION!r}")
    style = rec.get("style")
    if style not in {"cli", "mcp"}:
        err(f"style must be 'cli' or 'mcp', got {style!r}")
    if not isinstance(rec.get("tags"), list) or not rec["tags"]:
        err("tags must be a non-empty list")
    msgs = rec.get("messages")
    if not isinstance(msgs, list) or len(msgs) < 3:
        err("messages must be a list of >=3 turns")
        return errs

    for i, m in enumerate(msgs):
        if not isinstance(m, dict):
            err(f"message {i} is not an object")
            continue
        role = m.get("role")
        if role not in VALID_ROLES:
            err(f"message {i} has invalid role {role!r}")
        if "content" not in m:
            err(f"message {i} missing 'content'")

    if msgs[0].get("role") != "system":
        err("first message must be role 'system'")
    if msgs[1].get("role") != "user":
        err("second message must be role 'user'")
    if msgs[-1].get("role") != "assistant":
        err("last message must be role 'assistant'")

    if style == "cli":
        if len(msgs) != 3:
            err("cli style must have exactly 3 messages (system,user,assistant)")
        if not msgs[-1].get("content", "").strip():
            err("cli assistant content must be non-empty")
    elif style == "mcp":
        # Expect: system, user, assistant(tool_calls), tool, assistant.
        if len(msgs) != 5:
            err("mcp style must have 5 messages (system,user,assistant,tool,assistant)")
            return errs
        tc_msg = msgs[2]
        if tc_msg.get("role") != "assistant" or "tool_calls" not in tc_msg:
            err("mcp message 2 must be an assistant turn with 'tool_calls'")
        else:
            tcs = tc_msg["tool_calls"]
            if not isinstance(tcs, list) or len(tcs) != 1:
                err("tool_calls must be a list with exactly one call")
            else:
                call = tcs[0]
                fn = call.get("function", {})
                if not call.get("id"):
                    err("tool_call missing id")
                if call.get("type") != "function":
                    err("tool_call type must be 'function'")
                if fn.get("name") not in MCP_TOOL_NAMES:
                    err(f"unknown MCP tool name {fn.get('name')!r}")
                args = fn.get("arguments")
                if not isinstance(args, str):
                    err("tool_call arguments must be a JSON string")
                else:
                    try:
                        json.loads(args)
                    except json.JSONDecodeError as e:
                        err(f"tool_call arguments is not valid JSON: {e}")
        tool_msg = msgs[3]
        if tool_msg.get("role") != "tool":
            err("mcp message 3 must be role 'tool'")
        else:
            if "tool_call_id" not in tool_msg:
                err("tool message missing tool_call_id")
            content = tool_msg.get("content")
            if not isinstance(content, str):
                err("tool message content must be a JSON string")
            else:
                try:
                    json.loads(content)
                except json.JSONDecodeError as e:
                    err(f"tool message content is not valid JSON: {e}")
            # cross-check ids/names line up
            if "tool_calls" in tc_msg and isinstance(tc_msg["tool_calls"], list) and tc_msg["tool_calls"]:
                call = tc_msg["tool_calls"][0]
                if tool_msg.get("tool_call_id") != call.get("id"):
                    err("tool_call_id does not match the assistant tool_call id")
                if tool_msg.get("name") != call.get("function", {}).get("name"):
                    err("tool message name does not match the called tool")
    return errs


# The 19 MCP tools exposed by `burpwn mcp` (verified against server.rs).
MCP_TOOL_NAMES = {
    "session_list",
    "session_current",
    "req_list",
    "req_show",
    "req_search",
    "workspace_list",
    "workspace_new",
    "tag_list",
    "tag_add",
    "note_add",
    "match_replace_list",
    "match_replace_add",
    "intercept_enable",
    "intercept_disable",
    "intercept_list",
    "await_intercept",
    "intercept_forward",
    "intercept_drop",
    "exec",
}


def run_validate(path: str) -> int:
    if path == "-":
        lines = sys.stdin.read().splitlines()
        src = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        src = path

    problems: list[str] = []
    n_cli = n_mcp = 0
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            problems.append(f"line {idx}: not valid JSON: {e}")
            continue
        errs = validate_record(idx, rec)
        problems.extend(errs)
        if not errs:
            if rec.get("style") == "cli":
                n_cli += 1
            elif rec.get("style") == "mcp":
                n_mcp += 1

    total = n_cli + n_mcp
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        print(
            f"FAIL: {len(problems)} problem(s) in {src} "
            f"({total} valid records: {n_cli} cli, {n_mcp} mcp)",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {src} — {total} valid records ({n_cli} cli, {n_mcp} mcp), "
        f"schema {SCHEMA_VERSION}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--validate",
        nargs="?",
        const="dataset.jsonl",
        metavar="PATH",
        help="validate the given JSONL file (default ./dataset.jsonl, '-' = stdin) "
        "instead of generating",
    )
    args = ap.parse_args(argv)

    if args.validate is not None:
        return run_validate(args.validate)

    emit(all_records())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
