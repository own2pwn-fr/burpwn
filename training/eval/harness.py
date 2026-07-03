#!/usr/bin/env python3
"""Behavioral eval harness for the burpwn fine-tuning dataset.

The generator (``generate.py``) *validates* records structurally, but nothing
scored whether a model trained on them actually produces correct burpwn behavior.
This harness closes that gap. It:

  1. Builds a **held-out TEST split** of task specs that does NOT overlap the
     committed ``dataset.train.jsonl`` / ``dataset.validation.jsonl`` content.
     It reuses ``generate.py``: the full corpus (``--multiturn-frac 0``) minus the
     exact normalized-content keys of the committed ``dataset.jsonl`` yields
     records that were generated but never shipped in the train/val splits — a
     clean, deterministic hold-out. Each spec is::

         {id, style, goal, tags,
          expected: {tool_or_subcommand, must_use_flags, envelope_shape,
                     negative, args_keys?}}

  2. Runs a **static grader** (no binary needed) over a predictions JSONL, scoring
     each prediction on:
       (a) valid-command  — parses & uses only real subcommands/flags/tools
                            (ground truth from ``surface.py``);
       (b) correct-tool   — the predicted subcommand / MCP tool matches expected;
       (c) envelope-shape — CLI ``{ok,data,error}`` vs raw MCP result vs Bash
                            tool-call, matching the spec's style;
       (d) negative-handling — for unsupported ops (e.g. ``export pcap``,
                            ``match-replace rm``) the answer must surface the
                            limitation instead of fabricating success.

  3. Optionally runs a **live grader** (``--live``): spawns the real ``burpwn``
     CLI / ``burpwn mcp`` stdio server in a throwaway ``$HOME`` and checks that
     read-only commands/tools execute and their output parses. It self-guards:
     if no binary is found or ``burpwn doctor`` is not ready, it no-ops with a
     clear message. Never required for the default run.

Usage::

    python harness.py --make-testset                 # write ./testset.jsonl
    python harness.py --testset testset.jsonl \
                      --predictions preds.jsonl       # static grade → summary+JSON
    python harness.py --testset testset.jsonl \
                      --predictions preds.jsonl --live # also live-check (best effort)

Predictions JSONL — one object per test ``id``. Accepted shapes (any subset)::

    {"id": "...", "content": "…assistant text with ```burpwn …``` fences…"}
    {"id": "...", "command": "burpwn req list --json"}
    {"id": "...", "tool_call": {"name": "req_list", "arguments": {"limit": 10}}}
    {"id": "...", "tool_call": {"name": "Bash",
                                "arguments": {"command": "burpwn req list"}}}

Stdlib only, deterministic.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any

import surface  # local module (same dir)

HERE = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(TRAINING_DIR)

TESTSET_PATH = os.path.join(HERE, "testset.jsonl")
COMMITTED_DATASET = os.path.join(TRAINING_DIR, "dataset.jsonl")

# Subcommand groups that take a second-level action token.
CLI_GROUPS = {
    "ca", "session", "req", "intercept", "match-replace",
    "workspace", "tag", "note", "export",
}

# Read-only CLI subpaths safe to actually execute in --live mode (no network,
# no daemon, no mutation of an external target).
LIVE_SAFE_CLI = {
    "doctor", "session list", "workspace list", "tag list", "note list",
    "req list", "req search", "req show", "match-replace list", "ca export",
    "export har",
}
# Read-only MCP tools safe to actually call in --live mode.
LIVE_SAFE_MCP = {
    "session_list", "session_current", "req_list", "req_show", "req_search",
    "workspace_list", "tag_list", "match_replace_list",
}

# Signals that an answer correctly surfaced an unsupported/negative outcome.
_NEGATIVE_SIGNALS = [
    "not yet implemented", "not implemented", "not supported",
    "not yet supported", "isn't supported", "aren't supported",
    "unsupported", "no such flow", "foreign key", "no burpwn proxy",
    "use `export har`", "use export har", "export har", "har instead",
    "not captured", "won't be captured", "will not be captured",
    "cannot", "can't", "is never captured", "never captured",
    "pending:false", '"pending": false', "timed out", "timeout",
    "pinning", "passthrough", "pass-through", "tls-passthru",
    "only add", "add + list", "add and list", '"ok":false', '"ok": false',
]


# --------------------------------------------------------------------------- #
# generate.py bridge.
# --------------------------------------------------------------------------- #

def _import_generate() -> Any:
    if TRAINING_DIR not in sys.path:
        sys.path.insert(0, TRAINING_DIR)
    import generate  # noqa: E402
    return generate


# --------------------------------------------------------------------------- #
# Command parsing helpers.
# --------------------------------------------------------------------------- #

def _burpwn_tokens(cmd: str) -> list[str]:
    """Tokens of a ``burpwn …`` command, dropping ``burpwn`` and stopping at the
    ``--`` sandbox boundary. Returns [] if it is not a burpwn command."""
    try:
        toks = shlex.split(cmd, comments=True)
    except ValueError:
        toks = cmd.split()
    if not toks or toks[0] != "burpwn":
        return []
    out: list[str] = []
    for t in toks[1:]:
        if t == "--":
            break
        out.append(t)
    return out


def subpath_of(cmd: str) -> str | None:
    """The subcommand path of a burpwn command, e.g. ``"req list"`` / ``"exec"``."""
    toks = _burpwn_tokens(cmd)
    bare = [t for t in toks if not t.startswith("-")]
    if not bare:
        return None
    sub = bare[0]
    if sub in CLI_GROUPS and len(bare) >= 2:
        return f"{sub} {bare[1]}"
    return sub


def flags_of(cmd: str) -> list[str]:
    """Normalized flag tokens of a burpwn command (``--flag`` / ``-f``)."""
    flags: list[str] = []
    for t in _burpwn_tokens(cmd):
        if t.startswith("--") and len(t) > 2 and t[2].isalpha():
            flags.append(t.split("=", 1)[0])
        elif t.startswith("-") and len(t) == 2 and t[1].isalpha():
            flags.append(t)
    return flags


_FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\n(.*?)```", re.S)


def burpwn_commands_in(text: str) -> list[str]:
    """Pull ``burpwn …`` command lines from text (fenced blocks + bare lines)."""
    cmds: list[str] = []
    bodies = _FENCE_RE.findall(text)
    bodies.append(text)  # also scan bare lines outside fences
    seen: set[str] = set()
    for body in bodies:
        for line in body.splitlines():
            s = line.strip().lstrip("$ ").strip()
            if s.startswith("burpwn ") and s not in seen:
                seen.add(s)
                cmds.append(s)
    return cmds


# --------------------------------------------------------------------------- #
# Test-spec construction (held-out slice).
# --------------------------------------------------------------------------- #

def _first_user(rec: dict[str, Any]) -> str:
    for m in rec["messages"]:
        if m.get("role") == "user":
            return m.get("content") or ""
    return ""


def _first_toolcall(rec: dict[str, Any]) -> dict[str, Any] | None:
    for m in rec["messages"]:
        if m.get("role") == "assistant" and m.get("tool_calls"):
            return m["tool_calls"][0]
    return None


def spec_from_record(gen: Any, rec: dict[str, Any]) -> dict[str, Any]:
    key = gen._normalized_key(rec)
    style = rec["style"]
    tags = rec.get("tags", [])
    negative = "negative" in tags
    goal = _first_user(rec)

    tool_or_sub: str | None = None
    must_flags: list[str] = []
    args_keys: list[str] = []

    if style == "cli":
        envelope = "cli"
        cmds = []
        for m in rec["messages"]:
            if m.get("role") == "assistant":
                cmds.extend(burpwn_commands_in(m.get("content", "")))
        if cmds:
            tool_or_sub = subpath_of(cmds[0])
            must_flags = flags_of(cmds[0])
    elif style == "shell":
        envelope = "bash_toolcall"
        tc = _first_toolcall(rec)
        if tc:
            try:
                a = json.loads(tc["function"]["arguments"])
                cmd = a.get("command", "")
            except (json.JSONDecodeError, KeyError, TypeError):
                cmd = ""
            if cmd.strip().startswith("burpwn "):
                tool_or_sub = subpath_of(cmd.strip())
                must_flags = flags_of(cmd.strip())
    else:  # mcp
        envelope = "mcp_raw"
        tc = _first_toolcall(rec)
        if tc:
            tool_or_sub = tc["function"]["name"]
            try:
                args_keys = sorted(json.loads(tc["function"]["arguments"]).keys())
            except (json.JSONDecodeError, KeyError, TypeError):
                args_keys = []

    return {
        "id": f"{style}-{key[:12]}",
        "style": style,
        "goal": goal,
        "tags": tags,
        "expected": {
            "tool_or_subcommand": tool_or_sub,
            "must_use_flags": must_flags,
            "envelope_shape": envelope,
            "negative": negative,
            "args_keys": args_keys,
        },
    }


def build_testset(seed: int | None = None, n: int = 300) -> list[dict[str, Any]]:
    """Deterministic held-out test specs, non-overlapping with train/val content.

    Selection: full corpus (multiturn-frac 0) minus the committed dataset's
    normalized keys, then a style-stratified deterministic slice of size ~n with
    ALL held-out negatives always included."""
    gen = _import_generate()
    seed = gen.DEFAULT_SEED if seed is None else seed
    full = gen.build_dataset(None, seed, 0)

    committed: set[str] = set()
    if os.path.isfile(COMMITTED_DATASET):
        with open(COMMITTED_DATASET, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    committed.add(gen._normalized_key(json.loads(line)))

    pool = [r for r in full if gen._normalized_key(r) not in committed]
    # Stable deterministic order by normalized key.
    pool.sort(key=gen._normalized_key)

    negatives = [r for r in pool if "negative" in r.get("tags", [])]
    rest = [r for r in pool if "negative" not in r.get("tags", [])]

    chosen: list[dict[str, Any]] = list(negatives)
    remaining = max(0, n - len(chosen))
    # Style-stratified proportional fill from the (non-negative) rest.
    by_style: dict[str, list[dict[str, Any]]] = {}
    for r in rest:
        by_style.setdefault(r["style"], []).append(r)
    total = len(rest) or 1
    styles = sorted(by_style)
    allocated = 0
    for i, st in enumerate(styles):
        grp = by_style[st]
        take = remaining - allocated if i == len(styles) - 1 else \
            round(remaining * len(grp) / total)
        take = max(0, min(take, len(grp)))
        chosen.extend(grp[:take])
        allocated += take

    specs = [spec_from_record(gen, r) for r in chosen]
    # Drop any spec we couldn't attach an expectation to (keep negatives even if
    # tool is None — they are graded on negative-handling).
    specs = [s for s in specs
             if s["expected"]["tool_or_subcommand"] is not None
             or s["expected"]["negative"]]
    specs.sort(key=lambda s: s["id"])
    return specs


# --------------------------------------------------------------------------- #
# Prediction normalization.
# --------------------------------------------------------------------------- #

def normalize_prediction(pred: dict[str, Any]) -> dict[str, Any]:
    """Extract a canonical view of a prediction for grading."""
    text = pred.get("content") or ""
    commands: list[str] = []
    tool_name: str | None = None
    tool_args: dict[str, Any] = {}
    shape: str | None = None

    if pred.get("command"):
        commands.append(str(pred["command"]).strip())

    tc = pred.get("tool_call")
    if isinstance(tc, dict):
        tool_name = tc.get("name")
        raw = tc.get("arguments", {})
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = {}
        if isinstance(raw, dict):
            tool_args = raw
        if tool_name == "Bash":
            shape = "bash_toolcall"
            cmd = tool_args.get("command", "")
            if isinstance(cmd, str) and cmd.strip():
                commands.append(cmd.strip())
        else:
            shape = "mcp_raw"

    if text:
        commands.extend(c for c in burpwn_commands_in(text) if c not in commands)

    if shape is None:
        # No tool_call → a CLI-style textual/command answer.
        shape = "cli"

    return {
        "text": text,
        "commands": commands,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "shape": shape,
    }


# --------------------------------------------------------------------------- #
# Static grader.
# --------------------------------------------------------------------------- #

class StaticGrader:
    def __init__(self, source: str = "auto") -> None:
        surf = surface.derive_surface(source)
        self.subcommands = set(surf["cli"]["subcommands"])
        self.flags = set(surf["cli"]["flags"])
        self.tools = set(surf["mcp"]["tools"])
        self.tool_params = {k: set(v) for k, v in surf["mcp"]["params"].items()}
        self.provenance = {
            "cli": surf["cli"]["provenance"],
            "mcp": surf["mcp"]["provenance"],
        }

    def _command_valid(self, cmd: str) -> bool:
        toks = _burpwn_tokens(cmd)
        if not toks:
            return False
        for t in toks:
            if t.startswith("--") and len(t) > 2 and t[2].isalpha():
                if t.split("=", 1)[0] not in self.flags:
                    return False
            elif t.startswith("-") and len(t) == 2 and t[1].isalpha():
                if t not in self.flags:
                    return False
            elif not t.startswith("-"):
                # A bare token is a subcommand only in leading position; we accept
                # any bare token that is a known subcommand, and ignore the rest
                # (positional values). We DO require the primary subcommand real.
                pass
        sub = subpath_of(cmd)
        if sub is None:
            return False
        primary = sub.split(" ")[0]
        if primary not in self.subcommands:
            return False
        parts = sub.split(" ")
        if len(parts) == 2 and parts[1] not in self.subcommands:
            return False
        return True

    def grade(self, spec: dict[str, Any], pred: dict[str, Any] | None) -> dict[str, Any]:
        exp = spec["expected"]
        result: dict[str, Any] = {
            "id": spec["id"], "style": spec["style"],
            "negative": exp["negative"], "missing": pred is None,
        }
        if pred is None:
            result.update({
                "valid_command": False, "correct_tool": False,
                "envelope_correct": False,
                "negative_handling": False if exp["negative"] else None,
                "notes": "no prediction",
            })
            return result

        npred = normalize_prediction(pred)

        # Negative specs (unsupported ops) are graded SOLELY on negative-handling:
        # a correct refusal legitimately emits no runnable command, so the other
        # criteria are not applicable (None) rather than failures.
        if exp["negative"]:
            hay = (npred["text"] + " " + " ".join(npred["commands"])).lower()
            result.update({
                "valid_command": None,
                "correct_tool": None,
                "envelope_correct": None,
                "negative_handling": any(sig in hay for sig in _NEGATIVE_SIGNALS),
                "shape": npred["shape"],
            })
            return result

        # (a) valid-command / valid-tool.
        if npred["shape"] == "mcp_raw":
            valid = npred["tool_name"] in self.tools
            if valid and npred["tool_args"]:
                allowed = self.tool_params.get(npred["tool_name"], set())
                if not set(npred["tool_args"]).issubset(allowed):
                    valid = False
        else:
            # CLI / Bash: every burpwn command must be valid; require >=1 command.
            cmds = npred["commands"]
            valid = bool(cmds) and all(self._command_valid(c) for c in cmds)

        # (b) correct-tool / subcommand.
        pred_tool = None
        if npred["shape"] == "mcp_raw":
            pred_tool = npred["tool_name"]
        elif npred["commands"]:
            pred_tool = subpath_of(npred["commands"][0])
        exp_tool = exp["tool_or_subcommand"]
        if exp_tool is None:
            correct_tool = None  # not applicable (pure negative w/o command)
        else:
            correct_tool = pred_tool == exp_tool

        # (c) envelope-shape.
        envelope_correct = npred["shape"] == exp["envelope_shape"]

        # (d) negative-handling.
        negative_handling: bool | None = None
        if exp["negative"]:
            hay = (npred["text"] + " " + " ".join(npred["commands"])).lower()
            negative_handling = any(sig in hay for sig in _NEGATIVE_SIGNALS)

        result.update({
            "valid_command": bool(valid),
            "correct_tool": correct_tool,
            "envelope_correct": bool(envelope_correct),
            "negative_handling": negative_handling,
            "pred_tool": pred_tool,
            "expected_tool": exp_tool,
            "shape": npred["shape"],
        })
        return result


def _rate(items: list[Any]) -> tuple[int, int]:
    """(#passed, #graded) over booleans, ignoring None (not-applicable)."""
    graded = [x for x in items if x is not None]
    return sum(1 for x in graded if x), len(graded)


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    def metric(name: str, subset: list[dict[str, Any]]) -> dict[str, Any]:
        p, g = _rate([r.get(name) for r in subset])
        return {"passed": p, "graded": g,
                "rate": round(p / g, 4) if g else None}

    styles = sorted({r["style"] for r in results})
    overall = {
        "count": len(results),
        "missing_predictions": sum(1 for r in results if r["missing"]),
        "valid_command": metric("valid_command", results),
        "correct_tool": metric("correct_tool", results),
        "envelope_correct": metric("envelope_correct", results),
        "negative_handling": metric(
            "negative_handling", [r for r in results if r["negative"]]),
    }
    per_style = {}
    for st in styles:
        sub = [r for r in results if r["style"] == st]
        per_style[st] = {
            "count": len(sub),
            "valid_command": metric("valid_command", sub),
            "correct_tool": metric("correct_tool", sub),
            "envelope_correct": metric("envelope_correct", sub),
        }
    return {"overall": overall, "per_style": per_style}


# --------------------------------------------------------------------------- #
# Live grader (optional, guarded).
# --------------------------------------------------------------------------- #

def _live_precheck() -> tuple[str | None, str]:
    binary = surface.find_binary()
    if not binary:
        return None, "no burpwn binary found (set $BURPWN_BIN or build target/release)"
    try:
        proc = subprocess.run([binary, "doctor"], capture_output=True,
                              text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"burpwn doctor failed to run: {e}"
    if proc.returncode != 0 or "ready" not in (proc.stdout + proc.stderr).lower():
        return None, ("sandbox prereqs not ready (burpwn doctor):\n"
                      + (proc.stdout or proc.stderr).strip())
    return binary, "ready"


def _live_env(tmp: str) -> dict[str, str]:
    env = dict(os.environ)
    for k in ("XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CONFIG_HOME",
              "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
        d = os.path.join(tmp, k.lower())
        os.makedirs(d, exist_ok=True)
        env[k] = d
    env["HOME"] = tmp
    return env


def _mcp_call(binary: str, env: dict[str, str], tool: str,
              args: dict[str, Any]) -> dict[str, Any]:
    """Minimal newline-delimited JSON-RPC client for one tools/call."""
    proc = subprocess.Popen(
        [binary, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, env=env, bufsize=1)
    try:
        def send(obj: dict[str, Any]) -> None:
            assert proc.stdin
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()

        def recv(match_id: int) -> dict[str, Any] | None:
            assert proc.stdout
            for _ in range(50):
                line = proc.stdout.readline()
                if not line:
                    return None
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if msg.get("id") == match_id:
                    return msg
            return None

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "harness", "version": "0"}}})
        if recv(1) is None:
            return {"ok": False, "reason": "no initialize response"}
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": tool, "arguments": args}})
        resp = recv(2)
        if resp is None:
            return {"ok": False, "reason": "no tools/call response"}
        if "error" in resp:
            return {"ok": False, "reason": f"tool error: {resp['error']}"}
        return {"ok": True, "reason": "tool call returned a result"}
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            proc.kill()


def live_grade(specs: list[dict[str, Any]], preds: dict[str, dict[str, Any]],
               max_checks: int = 40) -> dict[str, Any]:
    import tempfile
    binary, reason = _live_precheck()
    if binary is None:
        return {"status": "skipped", "reason": reason, "checks": []}

    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="burpwn-eval-") as tmp:
        env = _live_env(tmp)
        # A throwaway session so read-only queries have a DB to hit.
        try:
            subprocess.run([binary, "session", "new", "--name", "eval", "--json"],
                           capture_output=True, text=True, env=env, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass
        for spec in specs:
            if len(checks) >= max_checks:
                break
            pred = preds.get(spec["id"])
            if pred is None:
                continue
            npred = normalize_prediction(pred)
            if npred["shape"] == "mcp_raw":
                tool = npred["tool_name"]
                if tool not in LIVE_SAFE_MCP:
                    continue
                r = _mcp_call(binary, env, tool, npred["tool_args"])
                checks.append({"id": spec["id"], "kind": "mcp", "tool": tool, **r})
            else:
                cmds = npred["commands"]
                if not cmds:
                    continue
                sub = subpath_of(cmds[0])
                if sub not in LIVE_SAFE_CLI:
                    continue
                argv = [binary] + [t for t in _burpwn_tokens(cmds[0])] + ["--json"]
                try:
                    proc = subprocess.run(argv, capture_output=True, text=True,
                                          env=env, timeout=25)
                    parsed = True
                    try:
                        json.loads(proc.stdout or "{}")
                    except json.JSONDecodeError:
                        parsed = False
                    checks.append({
                        "id": spec["id"], "kind": "cli", "subpath": sub,
                        "ok": proc.returncode == 0 and parsed,
                        "reason": f"exit={proc.returncode} json_parsed={parsed}",
                    })
                except (OSError, subprocess.SubprocessError) as e:
                    checks.append({"id": spec["id"], "kind": "cli", "subpath": sub,
                                   "ok": False, "reason": str(e)})
    passed = sum(1 for c in checks if c.get("ok"))
    return {
        "status": "ran", "binary": binary,
        "executed": len(checks), "passed": passed,
        "rate": round(passed / len(checks), 4) if checks else None,
        "checks": checks,
    }


# --------------------------------------------------------------------------- #
# IO + reporting.
# --------------------------------------------------------------------------- #

def load_jsonl(path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def _fmt_metric(m: dict[str, Any]) -> str:
    if m["graded"] == 0:
        return "n/a (0 graded)"
    return f"{m['rate'] * 100:5.1f}%  ({m['passed']}/{m['graded']})"


def print_summary(agg: dict[str, Any], live: dict[str, Any] | None,
                  provenance: dict[str, str]) -> None:
    o = agg["overall"]
    print("burpwn behavioral eval — static grader", file=sys.stderr)
    print(f"  surface: cli={provenance['cli']} mcp={provenance['mcp']}",
          file=sys.stderr)
    print(f"  specs graded          : {o['count']} "
          f"(missing predictions: {o['missing_predictions']})", file=sys.stderr)
    print(f"  valid-command rate    : {_fmt_metric(o['valid_command'])}",
          file=sys.stderr)
    print(f"  correct-tool rate     : {_fmt_metric(o['correct_tool'])}",
          file=sys.stderr)
    print(f"  envelope-correctness  : {_fmt_metric(o['envelope_correct'])}",
          file=sys.stderr)
    print(f"  negative-handling     : {_fmt_metric(o['negative_handling'])}",
          file=sys.stderr)
    print("  per-style:", file=sys.stderr)
    for st, m in agg["per_style"].items():
        print(f"    {st:5s} n={m['count']:4d}  valid={_fmt_metric(m['valid_command'])}"
              f"  tool={_fmt_metric(m['correct_tool'])}"
              f"  env={_fmt_metric(m['envelope_correct'])}", file=sys.stderr)
    if live is not None:
        if live["status"] != "ran":
            print(f"  live grader           : SKIPPED — {live['reason']}",
                  file=sys.stderr)
        else:
            rate = "n/a" if live["rate"] is None else f"{live['rate'] * 100:.1f}%"
            print(f"  live grader           : {live['passed']}/{live['executed']} "
                  f"executed OK ({rate})", file=sys.stderr)


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="burpwn behavioral eval harness")
    ap.add_argument("--make-testset", action="store_true",
                    help="write the held-out test split to testset.jsonl and exit")
    ap.add_argument("--n", type=int, default=300,
                    help="target number of test specs (default 300)")
    ap.add_argument("--seed", type=int, default=None,
                    help="generator seed (default: generate.py DEFAULT_SEED)")
    ap.add_argument("--testset", default=TESTSET_PATH,
                    help="path to the test split (default ./testset.jsonl)")
    ap.add_argument("--predictions", help="predictions JSONL to grade")
    ap.add_argument("--report", help="write the full JSON report to this path")
    ap.add_argument("--source", choices=["auto", "binary", "static"], default="auto",
                    help="surface provenance for the grader (default auto)")
    ap.add_argument("--live", action="store_true",
                    help="also run the live grader (best-effort; auto-skips)")
    args = ap.parse_args(argv)

    if args.make_testset:
        specs = build_testset(args.seed, args.n)
        write_jsonl(args.testset, specs)
        from collections import Counter
        by_style = Counter(s["style"] for s in specs)
        negs = sum(1 for s in specs if s["expected"]["negative"])
        print(f"wrote {os.path.relpath(args.testset)} — {len(specs)} specs "
              f"({dict(by_style)}; {negs} negative)", file=sys.stderr)
        return 0

    if not args.predictions:
        ap.error("either --make-testset or --predictions is required")

    if not os.path.isfile(args.testset):
        specs = build_testset(args.seed, args.n)
        write_jsonl(args.testset, specs)
        print(f"(testset not found; generated {len(specs)} specs → "
              f"{os.path.relpath(args.testset)})", file=sys.stderr)
    else:
        specs = load_jsonl(args.testset)

    preds_list = load_jsonl(args.predictions)
    preds = {p["id"]: p for p in preds_list if "id" in p}

    grader = StaticGrader(args.source)
    results = [grader.grade(s, preds.get(s["id"])) for s in specs]
    agg = aggregate(results)

    live = live_grade(specs, preds) if args.live else None

    report = {
        "provenance": grader.provenance,
        "testset": os.path.relpath(args.testset),
        "predictions": os.path.relpath(args.predictions),
        "aggregate": agg,
        "live": live,
        "per_spec": results,
    }
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")

    print_summary(agg, live, grader.provenance)
    # Machine-readable aggregate to stdout.
    json.dump({"aggregate": agg, "live": live}, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
