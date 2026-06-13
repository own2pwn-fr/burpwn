---
license: agpl-3.0
language:
  - en
task_categories:
  - text-generation
tags:
  - security
  - pentest
  - web-security
  - tool-use
  - agents
  - burpwn
  - function-calling
pretty_name: burpwn Usage (CLI + MCP tool-use SFT)
size_categories:
  - 1K<n<10K
configs:
  - config_name: default
    data_files:
      - split: train
        path: dataset.train.jsonl
      - split: validation
        path: dataset.validation.jsonl
---

# burpwn Usage — fine-tuning dataset (CLI + MCP tool-use)

An instruction-tuning dataset that teaches an LLM to operate
[`burpwn`](https://github.com/own2pwn/burpwn) — a transparent intercepting
proxy and rootless sandbox for AI-driven web pentesting on Linux — both from the
**shell CLI** and over the **MCP** (Model Context Protocol) tool interface.

`burpwn exec -- <cmd>` runs a command inside a user+network namespace whose
entire network egress is forced through burpwn's MITM proxy; every
request/response is captured to a per-session SQLite store and can be listed,
searched, inspected (decrypted), replayed (Repeater), or intercepted live. The
agent's own LLM traffic stays outside the sandbox and is never captured.

> **Intended use:** supervised fine-tuning (SFT) of an LLM agent for *authorized*
> web-application security testing. See **Responsible use** below.

## Splits & size

| Split | Records |
|-------|---------|
| `train` | see `dataset.train.jsonl` |
| `validation` | see `dataset.validation.jsonl` |
| combined | `dataset.jsonl` (train + validation, same records) |

~2.6k deduplicated examples, roughly 62% `cli` / 38% `mcp`. The split is a
deterministic, **style-stratified** 95/5 split (both `cli` and `mcp` appear in
each split). Sizes are tunable — see *(Re)generate* — and the generator asserts
zero near-duplicates.

## Files

| File | Purpose |
|------|---------|
| `generate.py` | Deterministic, stdlib-only generator. **Source of truth.** |
| `dataset.jsonl` | Combined dataset, one JSON record per line. |
| `dataset.train.jsonl` | Training split. |
| `dataset.validation.jsonl` | Validation/hold-out split. |
| `README.md` | This dataset card. |
| `requirements.txt` | Deps for packaging/upload (the generator needs none). |
| `upload_to_hf.py` | Push the files + card to a HF dataset repo. |
| `finetune/` | Ready-to-run LLaMA-Factory recipes (4B LoRA, 70B QLoRA). |

## Record schema

One JSON object per line. Common keys:

```jsonc
{
  "schema_version": "2.0",
  "style": "cli" | "mcp",     // which interface the example teaches
  "tags": ["..."],            // non-empty list of topic labels (filtering/curation)
  "messages": [ ... ]         // OpenAI-style chat turns (see below)
}
```

### `style: "cli"` — chat-format SFT

`system`, then **alternating** `user`/`assistant` turns starting with `user`
and ending with `assistant` (single-shot *or* multi-turn, 2–8 turns). The user
states a pentest goal (or pastes a JSON envelope); the assistant replies with
the exact `burpwn` command(s), a short rationale, and an interpretation of the
output where useful.

```json
{
  "schema_version": "2.0",
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

`system → user`, then one or more **`assistant(tool_calls) → tool(result) →
assistant(final)`** triples (multi-step tool chains), using the
OpenAI-compatible tool-call shape.

* The `assistant` tool-call turn's `tool_calls` array contains exactly one call:
  `{"id", "type":"function", "function":{"name", "arguments"}}` where
  `arguments` is a **JSON-encoded string** of the tool's parameters.
* The `tool` turn carries `tool_call_id` (matching the call `id`), `name`, and
  `content` (the tool's result as a JSON-encoded string).
* The final `assistant` turn interprets the result.

```json
{
  "schema_version": "2.0",
  "style": "mcp",
  "tags": ["mcp", "req_list", "filter"],
  "messages": [
    {"role": "system", "content": "You are ... connected to the burpwn MCP server ..."},
    {"role": "user", "content": "List successful GET requests to api.shopwave.io."},
    {"role": "assistant", "content": "", "tool_calls": [
      {"id": "call_1", "type": "function",
       "function": {"name": "req_list",
                    "arguments": "{\"host\": \"api.shopwave.io\", \"method\": \"GET\", \"status\": 200}"}}]},
    {"role": "tool", "tool_call_id": "call_1", "name": "req_list",
     "content": "{\"flows\": [{\"id\": 41, ...}], \"count\": 1}"},
    {"role": "assistant", "content": "One matching flow: id 41 ..."}
  ]
}
```

The 19 MCP tools are: `session_list`, `session_current`, `req_list`,
`req_show`, `req_search`, `workspace_list`, `workspace_new`, `tag_list`,
`tag_add`, `note_add`, `match_replace_list`, `match_replace_add`,
`intercept_enable`, `intercept_disable`, `intercept_list`, `await_intercept`,
`intercept_forward`, `intercept_drop`, `exec`. All 19 appear as real tool calls.

## Grounding / accuracy

Every command name, flag, JSON envelope and MCP tool name was verified against
the **real binary** (`target/debug/burpwn`) and the MCP server source
(`crates/burpwn-mcp/src/{params,server,handlers}.rs`) on 2026-06-13 by *running
the binary* and capturing the actual envelopes. Notable grounded facts encoded:

* **CLI and MCP envelopes differ** (the dataset keeps them distinct):
  CLI `--json` wraps everything in `{ok,data,error}`; `req list`/`match-replace
  list`/`workspace list` return **bare arrays**; `req replay` returns
  `{response:"<raw HTTP string>"}` (no separate status); CLI intercept commands
  serialize the daemon enum as `{type:"Ack"|"Pending"|"Resolved"|"Intercepts", ...}`.
  MCP tool **results are not** `{ok,data,error}`-wrapped: `req_list` →
  `{flows,count}`, `tag_add` → `{tag_id}`, `note_add` → `{note_id}`,
  `workspace_new` → `{workspace_id}`, intercept tools → `{ok:true}` /
  `{pending:...}` / `{found:...}`.
* `exec --json` writes `{exit_code, exec_id, captured_request_ids}` to **fd 3**;
  the MCP `exec` tool returns that object directly.
* `export pcap` is **not implemented** → negative example steering to `export har`.
* `match-replace rm/enable/disable` parse but are **not yet supported at
  runtime** (the store writer exposes only add + list) → negative example.
* DNS lookups inside the sandbox are captured as `protocol:"dns"`,
  `method:"QUERY"`; cert-pinned hosts appear as `protocol:"tls-passthru"` with
  no decrypted body.
* `req show <missing>` → `burpwn: no such flow: <id>`; tagging/noting a
  non-existent flow → a sqlite FOREIGN KEY error.
* MCP arg names that differ from CLI positionals (`note_add.body`,
  `intercept_forward.set_headers:[{name,value}]`, `match_replace_add.on_request`,
  `exec.argv`, `await_intercept.timeout_secs`).

## Coverage

Scenario **families** (each parameterized over targets, tools, vuln classes,
flags and phrasings, then deduplicated):

* **Setup**: `doctor` (+ per-missing-prereq recovery), `ca init/export`,
  `init --agent`.
* **Sessions / workspaces**: new/list/use/rm; workspace scoping.
* **Recon under `exec`** (volume backbone): curl, httpie, wget, ffuf, gobuster,
  feroxbuster, dirb, nuclei, nikto, katana, httpx, wpscan, nmap, sqlmap, python
  scripts — across juice-shop, DVWA, a REST API, a GraphQL API, an SPA, internal
  hosts, a bare IP and non-standard ports, with realistic flag/wordlist variants.
* **Vuln testing**: IDOR/BOLA, authz, reflected/stored XSS, SQLi, SSRF,
  open-redirect, path-traversal, JWT (alg:none), CSRF, command injection, XXE,
  rate-limit — as single probes and as multi-turn workflows
  (probe → capture → inspect → confirm → tag/note → export).
* **Listing/filtering**: host/status/method/protocol/port/workspace, pagination.
* **Inspection**: `req show` (decoded + `--raw`), full-text `req search`.
* **Repeater**: `req replay` editing header/body/method (authz, JWT, SQLi, CSRF).
* **Live interception**: enable → await → forward/drop, body/header tamper.
* **Match/replace**: auth-header injection, scoped response rewrites, host/url.
* **Tag/note/export (HAR)**, CLI-vs-MCP guidance.
* **Negatives/recovery**: pcap unimplemented, match-replace rm unsupported, DNS
  works, cert pinning → tls-passthru, agent LLM traffic never captured,
  missing-flow / FK errors, await timeout, daemon-not-running guidance.

## (Re)generate

```
cd training
python generate.py                 # writes dataset.jsonl + train/validation splits
python generate.py --target 3000   # aim for ~N examples (style-balanced subsample)
python generate.py --seed 7        # change the deterministic RNG seed
python generate.py --stdout > out.jsonl
```

The generator is deterministic (no network, stdlib only, fixed default seed) so
regeneration is **byte-identical** and the diff is reviewable.

## Validate

```
python generate.py --validate                     # ./dataset.jsonl
python generate.py --validate dataset.train.jsonl
python generate.py --validate dataset.validation.jsonl
python generate.py --stdout | python generate.py --validate -
```

Checks: valid JSON per line; `schema_version`/`style`/`tags`; role ordering
(`cli` = alternating user/assistant ending assistant; `mcp` =
assistant(tool_calls)/tool/assistant triples); single, **known** MCP tool name
per call with JSON-parseable `arguments` and matching `tool_call_id`/`name`;
only known burpwn subcommands/flags appear in emitted commands; and **no
near-duplicates** (normalized-content hash). Exit code is non-zero on any
problem.

## Intended use (SFT for tool-use)

Standard chat-format SFT, **train-on-responses-only** (mask everything but the
assistant turns). Both `cli` and `mcp` records use the OpenAI `messages` shape,
which most trainers ingest directly:

* **LLaMA-Factory** (recommended; see `finetune/`): register with
  `formatting: sharegpt` + the OpenAI `tags` mapping; tool calls are handled
  natively.
* **TRL `SFTTrainer`** / **Axolotl**: map `messages` to the chat template and
  enable completion-only / response masking.

Filter or weight by `style` and `tags` to balance CLI vs MCP or focus a run.

## Upload to the Hugging Face Hub

```
pip install -r requirements.txt
huggingface-cli login            # or: export HF_TOKEN=hf_xxx
python upload_to_hf.py --dry-run
python upload_to_hf.py           # → own2pwn-fr/burpwn-usage (override with --repo)
```

`upload_to_hf.py` never hardcodes a token (reads `--token`/`$HF_TOKEN`/cached
login) and prints instructions if unauthenticated.

## Limitations

* Synthetic & deterministic: realistic but not captured from live engagements —
  combine with your own traces for production-scale SFT. Hostnames/IPs use
  documentation ranges (`example`, RFC 5737, RFC 1918) and `.local`/`.lan`.
* Grounded against one build (2026-06-13). If burpwn's surface changes,
  re-verify and regenerate. `match-replace rm/enable/disable` are intentionally
  modelled as unsupported per that build.
* English-only; web-app HTTP(S) focus (no deep WS/gRPC/binary-protocol coverage).

## Responsible use

burpwn is an offensive-security tool. This dataset is for building assistants
that operate it **only against systems you are explicitly authorized to test**.
Do not use it to facilitate unauthorized access. The system prompts in the data
include an authorized-testing reminder.

## License

Released under **AGPL-3.0**, matching the burpwn repository.
