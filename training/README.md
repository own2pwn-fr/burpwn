# burpwn fine-tuning dataset

An instruction-tuning dataset that teaches an LLM to operate
[`burpwn`](../) — a transparent intercepting proxy and rootless sandbox for
AI-driven web pentesting on Linux — both from the **shell CLI** and over the
**MCP** (Model Context Protocol) tool interface.

`burpwn exec -- <cmd>` runs a command inside a user+network namespace whose
entire network egress is forced through burpwn's MITM proxy; every
request/response is captured to a per-session SQLite store and can be listed,
searched, inspected (decrypted), replayed (Repeater), or intercepted live. The
agent's own LLM traffic stays outside the sandbox and is never captured.

## Files

| File | Purpose |
|------|---------|
| `generate.py` | Deterministic, stdlib-only generator. **Source of truth.** |
| `dataset.jsonl` | Generated output, one JSON record per line. Committed alongside the generator. |
| `README.md` | This document. |

## How accuracy was grounded

Every command name, flag, JSON envelope and MCP tool name was verified against
the **real binary** at `../target/debug/burpwn` and the MCP server source
(`../crates/burpwn-mcp/src/params.rs`, `server.rs`, `handlers.rs`) on
2026-06-13. The verified envelope shapes were captured by actually running:

```
burpwn --json doctor
burpwn ca init
burpwn --json session new --name demo
burpwn --json req list
burpwn --json req show <id>        # decoded + (with --raw) verbatim bytes
burpwn --json req replay <id> --set-header "...: ..."
burpwn --json exec -- curl ...     # envelope on fd 3: {exit_code, exec_id, captured_request_ids}
burpwn --json match-replace add "" header X-Demo 1
burpwn --json export har / export pcap
```

Notably, the dataset encodes real edge cases discovered this way:

* `exec --json` writes its `{exit_code, exec_id, captured_request_ids}` envelope
  to **fd 3**, not stdout (the child's stdout passes through cleanly). The MCP
  `exec` tool returns that object directly in its result.
* `export pcap` is **not implemented** and errors with a clear message →
  modelled as a negative example steering to `export har`.
* `match-replace rm/enable/disable` are **not yet supported** by the store
  writer → modelled as a negative example.
* DNS lookups inside the sandbox are captured as `protocol: "dns"`,
  `method: "QUERY"` flows; cert-pinned hosts appear as `protocol: "tls-passthru"`
  with no decrypted body.
* MCP argument names differ from CLI positionals in a few places
  (`note_add` uses `body`; `intercept_forward` uses `set_headers:[{name,value}]`
  with no method override; `match_replace_add` uses `on_request: bool`;
  `exec` uses `argv: [...]`; `await_intercept` uses `timeout_secs`).

## Record schema

One JSON object per line. Common keys:

```jsonc
{
  "schema_version": "1.0",
  "style": "cli" | "mcp",     // which interface the example teaches
  "tags": ["..."],            // non-empty list of topic labels (filtering/curation)
  "messages": [ ... ]         // chat turns (see below)
}
```

### `style: "cli"` — chat-format SFT

Exactly three turns. The user states a pentest goal (or pastes a JSON
envelope); the assistant replies with the exact `burpwn` command(s), a short
rationale, and an interpretation of the output where useful.

```json
{
  "schema_version": "1.0",
  "style": "cli",
  "tags": ["req", "replay", "authz"],
  "messages": [
    {"role": "system", "content": "You are a web-application penetration-testing assistant that drives burpwn ..."},
    {"role": "user", "content": "Re-send flow 22 but strip the Authorization header ..."},
    {"role": "assistant", "content": "```\nburpwn --json req replay 22 --set-header \"Authorization: \"\n```\n\n..."}
  ]
}
```

### `style: "mcp"` — tool-calling

Five turns using the **OpenAI-compatible tool-call shape**:
`system → user → assistant(with tool_calls) → tool(result) → assistant(final)`.

* The third turn is an `assistant` message whose `tool_calls` array contains
  exactly one call: `{"id", "type":"function", "function":{"name", "arguments"}}`
  where `arguments` is a **JSON-encoded string** of the tool's parameters.
* The fourth turn is a `tool` message with `tool_call_id` (matching the call
  `id`), `name`, and `content` (the tool's result as a JSON-encoded string).
* The fifth turn is the `assistant` interpreting the result in natural language.

```json
{
  "schema_version": "1.0",
  "style": "mcp",
  "tags": ["mcp", "req_list", "filter"],
  "messages": [
    {"role": "system", "content": "You are ... connected to the burpwn MCP server ..."},
    {"role": "user", "content": "List successful GET requests to api.acme.com."},
    {"role": "assistant", "content": "", "tool_calls": [
      {"id": "call_1", "type": "function",
       "function": {"name": "req_list",
                    "arguments": "{\"host\": \"api.acme.com\", \"method\": \"GET\", \"status\": 200}"}}]},
    {"role": "tool", "tool_call_id": "call_1", "name": "req_list",
     "content": "[{\"id\": 41, \"authority\": \"api.acme.com\", ...}]"},
    {"role": "assistant", "content": "One matching flow: id 41 ..."}
  ]
}
```

The 19 MCP tools used are: `session_list`, `session_current`, `req_list`,
`req_show`, `req_search`, `workspace_list`, `workspace_new`, `tag_list`,
`tag_add`, `note_add`, `match_replace_list`, `match_replace_add`,
`intercept_enable`, `intercept_disable`, `intercept_list`, `await_intercept`,
`intercept_forward`, `intercept_drop`, `exec`.

## Coverage

~65 deduplicated examples (≈44 CLI, ≈21 MCP) spanning: prerequisites/setup
(`doctor`, `ca init/export`, `init --agent`), sessions, recon under `exec`
(curl/ffuf/katana/nuclei/sqlmap), listing & filtering captured flows
(host/status/method/protocol/port, pagination), full-text search, inspecting
decrypted HTTPS (`req show`, `--raw`), Repeater (`req replay` editing
header/body/method for IDOR/authz), live interception
(enable → await → forward/drop, tampering), match/replace rules (auth-header
injection, scoped response rewrites), workspaces, tagging/notes, HAR export,
CLI-vs-MCP guidance, and several negative/disambiguation cases (pcap not
implemented, match-replace rm unsupported, DNS works, cert pinning →
tls-passthru, agent LLM traffic never captured, missing-flow errors,
await timeout).

## (Re)generate

```
cd training
python generate.py > dataset.jsonl
```

The generator is deterministic (no randomness, no network, stdlib only), so
regeneration is reproducible and the diff is reviewable. Add new scenarios by
appending records in `cli_records()` / `mcp_records()`.

## Validate

```
python generate.py --validate            # validates ./dataset.jsonl
python generate.py --validate path.jsonl # validate a specific file
python generate.py | python generate.py --validate -   # validate stdin
```

Validation checks: each line is valid JSON; `schema_version`/`style`/`tags`
present; role ordering; CLI records have exactly 3 turns with a non-empty
assistant reply; MCP records have the 5-turn tool-call shape with a single,
**known** tool name, JSON-parseable `arguments` and tool `content`, and matching
`tool_call_id`/tool `name`. Exit code is non-zero on any problem.

## Suggested use

Standard **SFT in chat format**. Most trainers ingest the `messages` array
directly:

* **TRL `SFTTrainer`** / **Axolotl** / **LLaMA-Factory**: map each record's
  `messages` to the chat template; train only on assistant turns
  (`train_on_responses_only` / completion-only masking) so the model learns to
  produce the commands and tool calls, not the prompts.
* **Tool-call–native finetuning**: the `mcp` records already use the
  OpenAI-compatible `tool_calls` / `tool` shape; feed them to a trainer that
  understands tool messages, or flatten `tool_calls` into your framework's
  tool-call template.
* Filter or weight by `style` and `tags` to balance CLI vs MCP, or to focus a
  run (e.g. only `intercept`/`replay` examples).

This is a small, high-signal seed set — combine with your own captured traces
for production-scale SFT.

## License

This dataset and generator are part of the burpwn repository and are released
under **AGPL-3.0** (see `../LICENSE`).
