#!/usr/bin/env python3
"""Derive burpwn's *ground-truth* command/tool surface from the real binary and
sources, instead of trusting the hand-maintained sets in ``generate.py``.

This is the **anti-drift guard** for the dataset generator. ``generate.py`` keeps
three hand-maintained collections it lints/validates records against:

    * ``KNOWN_CLI_SUBCOMMANDS`` — every CLI subcommand token (top-level + actions)
    * ``KNOWN_CLI_FLAGS``       — every CLI flag (long + short)
    * ``MCP_TOOL_NAMES``        — the MCP tools exposed by ``burpwn mcp``

If burpwn's real surface changes and those sets are not updated, the generator
will silently keep emitting stale examples (or reject valid ones). This module
recomputes the surface from authoritative sources and, in ``--check`` mode, fails
loudly on any drift.

Sources, in priority order:

  CLI subcommands + flags
    1. The real binary, if found (``$BURPWN_BIN`` / ``burpwn`` on PATH /
       ``target/release/burpwn`` / ``target/debug/burpwn``): recursively invoke
       ``burpwn [<path...>] --help`` and parse the ``Commands:`` / ``Options:``
       sections. Hidden commands (e.g. ``mcp``, ``proxy``) never appear in
       ``--help`` and so are correctly excluded from the user-facing surface.
    2. Fallback: static regex parse of ``crates/burpwn-cli/src/cli.rs`` (the clap
       derive structs/enums).

  MCP tool names + params
    Always parsed statically from ``crates/burpwn-mcp/src/{server,params}.rs``
    (the ``#[tool(...)] async fn <name>`` methods and the ``*Params`` structs).
    There is no cheap runtime introspection without speaking the MCP protocol.

Usage::

    python surface.py                 # derive + write ./surface.json, print summary
    python surface.py --json          # print the derived surface as JSON to stdout
    python surface.py --check         # diff derived vs generate.py's hand sets;
                                      #   exit non-zero on drift (CI anti-drift gate)
    python surface.py --source static # force the cli.rs static parse (ignore binary)

Stdlib only, deterministic. Public API: ``cli_surface()`` and ``mcp_tool_names()``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(TRAINING_DIR)

CLI_RS = os.path.join(REPO_ROOT, "crates", "burpwn-cli", "src", "cli.rs")
MCP_SERVER_RS = os.path.join(REPO_ROOT, "crates", "burpwn-mcp", "src", "server.rs")
MCP_PARAMS_RS = os.path.join(REPO_ROOT, "crates", "burpwn-mcp", "src", "params.rs")

SNAPSHOT_PATH = os.path.join(HERE, "surface.json")

# clap builtins present on every command; not declared in cli.rs but always real.
CLAP_BUILTIN_FLAGS = {"-h", "--help", "-V", "--version"}
# `help` is a clap-generated meta subcommand, not part of the authored surface.
META_SUBCOMMANDS = {"help"}


# --------------------------------------------------------------------------- #
# Binary discovery.
# --------------------------------------------------------------------------- #

def find_binary() -> str | None:
    """Locate a usable ``burpwn`` binary, or ``None``."""
    env = os.environ.get("BURPWN_BIN")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    onpath = shutil.which("burpwn")
    if onpath:
        return onpath
    for rel in ("target/release/burpwn", "target/debug/burpwn"):
        cand = os.path.join(REPO_ROOT, rel)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


# --------------------------------------------------------------------------- #
# --help parsing (binary source).
# --------------------------------------------------------------------------- #

_FLAG_RE = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")


def _parse_help(text: str) -> tuple[list[str], set[str]]:
    """Parse a clap ``--help`` page → (subcommand names, flag tokens).

    Sections are introduced by a column-0 header ending in ``:`` (``Commands:``,
    ``Options:``, ``Arguments:``); their members are indented lines beneath.
    """
    commands: list[str] = []
    flags: set[str] = set()
    section: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace() and raw.rstrip().endswith(":"):
            section = raw.strip().rstrip(":").lower()
            continue
        if not raw[0].isspace():
            section = None  # prose (Usage line, about, etc.)
            continue
        line = raw.strip()
        if section == "commands":
            m = re.match(r"([A-Za-z][\w-]*)", line)
            if m:
                name = m.group(1)
                if name not in META_SUBCOMMANDS:
                    commands.append(name)
        elif section == "options":
            # Only scan the flag/value column — the part before the 2+-space gap
            # that separates it from the description. Clap example text in a
            # description (e.g. `curl -s https://… -d user=…`) can otherwise be
            # mis-harvested as real `-s`/`-d` flags.
            column = re.split(r"\s{2,}", line, maxsplit=1)[0]
            for tok in _FLAG_RE.findall(column):
                flags.add(tok)
    return commands, flags


def _run_help(binary: str, path: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            [binary, *path, "--help"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # clap prints help to stdout; some builds use stderr for errors.
    return proc.stdout or proc.stderr or None


def cli_surface_from_binary(binary: str) -> dict[str, Any] | None:
    """Recursively walk ``burpwn --help`` to collect every subcommand + flag."""
    root_help = _run_help(binary, [])
    if not root_help:
        return None

    subcommands: set[str] = set()
    flags: set[str] = set()
    seen_paths: set[tuple[str, ...]] = set()

    def walk(path: list[str]) -> None:
        key = tuple(path)
        if key in seen_paths or len(path) > 6:
            return
        seen_paths.add(key)
        text = _run_help(binary, path) if path else root_help
        if not text:
            return
        cmds, fs = _parse_help(text)
        flags.update(fs)
        for c in cmds:
            subcommands.add(c)
            walk(path + [c])

    walk([])

    # `burpwn mcp` (with no subcommand) starts the stdio MCP server directly and
    # is routed in crates/burpwn/src/main.rs *before* burpwn-cli's clap tree, so
    # `burpwn mcp --help` prints the server usage and hides the real
    # `burpwn mcp register …` clap subcommand from the recursive walk. Probe it
    # explicitly so the derived surface stays complete (matches the cli.rs parse).
    if "mcp" in subcommands:
        reg_help = _run_help(binary, ["mcp", "register"])
        if reg_help:
            reg_cmds, reg_flags = _parse_help(reg_help)
            subcommands.add("register")
            subcommands.update(reg_cmds)
            flags.update(reg_flags)

    if not subcommands:
        return None
    flags.update(CLAP_BUILTIN_FLAGS)
    return {
        "provenance": f"binary:{binary}",
        "subcommands": sorted(subcommands),
        "flags": sorted(flags),
    }


# --------------------------------------------------------------------------- #
# cli.rs static parsing (fallback source).
# --------------------------------------------------------------------------- #

def _camel_to_kebab(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", s)
    return s.lower()


def _enum_variants(src: str, enum_name: str) -> list[tuple[str, bool]]:
    """Return [(VariantIdent, hidden)] for ``enum <enum_name> { ... }``."""
    m = re.search(r"enum\s+" + re.escape(enum_name) + r"\s*\{", src)
    if not m:
        return []
    i = m.end()
    depth = 1
    body_start = i
    while i < len(src) and depth:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    body = src[body_start:i - 1]
    variants: list[tuple[str, bool]] = []
    # A variant ident sits at brace-depth 0 within the enum body, preceded by
    # optional #[...] attribute lines. Track whether the nearest attrs hide it.
    depth = 0
    pending_hidden = False
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#["):
            if "hide = true" in s or "hide=true" in s:
                pending_hidden = True
            continue
        if s.startswith("//"):
            continue
        if depth == 0:
            vm = re.match(r"([A-Z][A-Za-z0-9]*)", s)
            if vm:
                variants.append((vm.group(1), pending_hidden))
                pending_hidden = False
        depth += s.count("{") - s.count("}")
        depth += s.count("(") - s.count(")")
    return variants


# Action enums whose kebab variants are subcommand tokens.
_ACTION_ENUMS = [
    "CaAction", "SessionAction", "SessionAuthAction", "FuzzAction",
    "ReqAction", "InterceptAction", "MatchReplaceAction", "WorkspaceAction",
    "TagAction", "NoteAction", "ExportAction",
    # 0.2.0 integration surface: `skill install/list/uninstall`, `mcp register`.
    "SkillAction", "McpAction",
]


def _parse_flags_from_cli_rs(src: str) -> set[str]:
    """Extract every long/short flag from ``#[arg(...)]`` attributes.

    Handles: ``long`` / ``long = "x"`` / ``short`` / ``short = 'c'`` / combos and
    trailing modifiers (``global``, ``default_value*``, ``value_name``). Positional
    args (no ``long``/``short``) are skipped.
    """
    flags: set[str] = set()
    lines = src.splitlines()
    for idx, line in enumerate(lines):
        s = line.strip()
        m = re.match(r"#\[arg\((.*)\)\]", s)
        if not m:
            continue
        attr = m.group(1)
        toks = [t.strip() for t in attr.split(",")]
        has_long = any(t == "long" or t.startswith("long ") or t.startswith("long=")
                       for t in toks)
        long_name = None
        lm = re.search(r"long\s*=\s*\"([^\"]+)\"", attr)
        if lm:
            long_name = lm.group(1)
        has_short = any(t == "short" or t.startswith("short ") or t.startswith("short=")
                        for t in toks)
        short_char = None
        sm = re.search(r"short\s*=\s*'([^'])'", attr)
        if sm:
            short_char = sm.group(1)
        if not (has_long or has_short):
            continue  # positional
        # Field name from the next non-attribute, non-comment declaration line.
        field = None
        for j in range(idx + 1, min(idx + 6, len(lines))):
            nxt = lines[j].strip()
            if not nxt or nxt.startswith("#[") or nxt.startswith("//"):
                continue
            fm = re.match(r"(?:pub\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", nxt)
            if fm:
                field = fm.group(1)
            break
        if has_long:
            if long_name is None and field is not None:
                long_name = field.replace("_", "-")
            if long_name:
                flags.add("--" + long_name)
        if has_short:
            if short_char is None and field is not None:
                short_char = field[0]
            if short_char:
                flags.add("-" + short_char)
    return flags


def cli_surface_from_source() -> dict[str, Any]:
    with open(CLI_RS, "r", encoding="utf-8") as fh:
        src = fh.read()
    subcommands: set[str] = set()
    for ident, hidden in _enum_variants(src, "Command"):
        if hidden:
            continue
        subcommands.add(_camel_to_kebab(ident))
    for enum in _ACTION_ENUMS:
        for ident, hidden in _enum_variants(src, enum):
            if hidden:
                continue
            subcommands.add(_camel_to_kebab(ident))
    flags = _parse_flags_from_cli_rs(src)
    flags.update(CLAP_BUILTIN_FLAGS)
    return {
        "provenance": f"source:{os.path.relpath(CLI_RS, REPO_ROOT)}",
        "subcommands": sorted(subcommands),
        "flags": sorted(flags),
    }


# --------------------------------------------------------------------------- #
# MCP parsing (server.rs + params.rs).
# --------------------------------------------------------------------------- #

def mcp_surface_from_source() -> dict[str, Any]:
    with open(MCP_SERVER_RS, "r", encoding="utf-8") as fh:
        server = fh.read()
    tools: list[str] = []
    # Each tool is a `#[tool(...)]` / `#[tool]` *attribute* (line starts with it,
    # excluding `#[tool_router]` / `#[tool_handler]` and doc-comment mentions),
    # followed — possibly after the attribute's own multi-line body — by the
    # method signature `async fn <name>(`.
    slines = server.splitlines()
    for i, raw in enumerate(slines):
        s = raw.strip()
        if not (s.startswith("#[tool(") or s == "#[tool]"):
            continue
        for j in range(i + 1, min(i + 12, len(slines))):
            fm = re.search(r"async\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                           slines[j])
            if fm:
                tools.append(fm.group(1))
                break
    # Params structs → field names (grounding for the harness).
    params: dict[str, list[str]] = {}
    with open(MCP_PARAMS_RS, "r", encoding="utf-8") as fh:
        psrc = fh.read()
    for sm in re.finditer(r"struct\s+([A-Za-z0-9_]+Params)\s*\{", psrc):
        name = sm.group(1)
        i = sm.end()
        depth = 1
        start = i
        while i < len(psrc) and depth:
            if psrc[i] == "{":
                depth += 1
            elif psrc[i] == "}":
                depth -= 1
            i += 1
        body = psrc[start:i - 1]
        fields = re.findall(r"^\s*(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:", body, re.M)
        # snake-case the struct name (drop trailing "Params") → tool-ish key.
        key = _camel_to_kebab(name[:-len("Params")]).replace("-", "_")
        params[key] = fields
    return {
        "provenance": f"source:{os.path.relpath(MCP_SERVER_RS, REPO_ROOT)}",
        "tools": tools,
        "params": params,
    }


# --------------------------------------------------------------------------- #
# Public API.
# --------------------------------------------------------------------------- #

def derive_surface(source: str = "auto") -> dict[str, Any]:
    """Derive the full surface snapshot.

    ``source`` selects the CLI provenance: ``"binary"`` (require the binary),
    ``"static"`` (force cli.rs), or ``"auto"`` (binary if available, else cli.rs).
    """
    cli: dict[str, Any] | None = None
    if source in ("auto", "binary"):
        binary = find_binary()
        if binary:
            cli = cli_surface_from_binary(binary)
        if source == "binary" and cli is None:
            raise RuntimeError("no usable burpwn binary found for --source binary")
    if cli is None:
        cli = cli_surface_from_source()
    mcp = mcp_surface_from_source()
    return {"cli": cli, "mcp": mcp}


def cli_surface(source: str = "auto") -> dict[str, set[str]]:
    """Return ``{"subcommands": set, "flags": set}`` for the CLI surface."""
    s = derive_surface(source)["cli"]
    return {"subcommands": set(s["subcommands"]), "flags": set(s["flags"])}


def mcp_tool_names(source: str = "auto") -> set[str]:
    """Return the set of real MCP tool names."""
    return set(derive_surface(source)["mcp"]["tools"])


def load_snapshot() -> dict[str, Any] | None:
    """Load the committed ``surface.json`` if present (offline consumers)."""
    if os.path.isfile(SNAPSHOT_PATH):
        with open(SNAPSHOT_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return None


# --------------------------------------------------------------------------- #
# Drift check.
# --------------------------------------------------------------------------- #

def _import_generate() -> Any:
    if TRAINING_DIR not in sys.path:
        sys.path.insert(0, TRAINING_DIR)
    import generate  # noqa: E402
    return generate


def check_drift(source: str = "auto") -> int:
    """Diff the derived surface against generate.py's hand-maintained sets.

    Returns 0 if consistent, 1 on any drift (printing a report to stderr)."""
    gen = _import_generate()
    surf = derive_surface(source)
    derived_sub = set(surf["cli"]["subcommands"])
    derived_flags = set(surf["cli"]["flags"])
    derived_tools = set(surf["mcp"]["tools"])

    hand_sub = set(gen.KNOWN_CLI_SUBCOMMANDS)
    hand_flags = set(gen.KNOWN_CLI_FLAGS)
    hand_tools = set(gen.MCP_TOOL_NAMES)

    drift = False

    def report(label: str, derived: set[str], hand: set[str]) -> None:
        nonlocal drift
        missing = derived - hand   # real, but generator does not know about it
        stale = hand - derived     # generator claims it, but not in real surface
        if missing or stale:
            drift = True
            print(f"DRIFT in {label}:", file=sys.stderr)
            if missing:
                print(f"  real but MISSING from hand set : {sorted(missing)}",
                      file=sys.stderr)
            if stale:
                print(f"  hand set but NOT in real surface: {sorted(stale)}",
                      file=sys.stderr)
        else:
            print(f"OK {label}: {len(derived)} tokens, consistent.", file=sys.stderr)

    print(f"surface provenance: cli={surf['cli']['provenance']} "
          f"mcp={surf['mcp']['provenance']}", file=sys.stderr)
    report("CLI subcommands", derived_sub, hand_sub)
    report("CLI flags", derived_flags, hand_flags)
    report("MCP tools", derived_tools, hand_tools)

    if drift:
        print("\nRESULT: surface drift detected — update generate.py's "
              "KNOWN_CLI_*/MCP_TOOL_NAMES (or the sources).", file=sys.stderr)
        return 1
    print("\nRESULT: no drift — hand-maintained sets match the real surface.",
          file=sys.stderr)
    return 0


def write_snapshot(source: str = "auto") -> dict[str, Any]:
    surf = derive_surface(source)
    with open(SNAPSHOT_PATH, "w", encoding="utf-8") as fh:
        json.dump(surf, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return surf


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="derive/verify burpwn's command surface")
    ap.add_argument("--check", action="store_true",
                    help="diff derived surface vs generate.py hand sets; exit 1 on drift")
    ap.add_argument("--json", action="store_true",
                    help="print the derived surface as JSON to stdout")
    ap.add_argument("--source", choices=["auto", "binary", "static"], default="auto",
                    help="CLI surface provenance (default: auto = binary else cli.rs)")
    ap.add_argument("--no-write", action="store_true",
                    help="do not (re)write surface.json in the default mode")
    args = ap.parse_args(argv)

    if args.check:
        return check_drift(args.source)

    surf = derive_surface(args.source)
    if args.json:
        json.dump(surf, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if not args.no_write:
        write_snapshot(args.source)
    print(f"cli provenance : {surf['cli']['provenance']}", file=sys.stderr)
    print(f"  subcommands  : {len(surf['cli']['subcommands'])}", file=sys.stderr)
    print(f"  flags        : {len(surf['cli']['flags'])}", file=sys.stderr)
    print(f"mcp provenance : {surf['mcp']['provenance']}", file=sys.stderr)
    print(f"  tools        : {len(surf['mcp']['tools'])}", file=sys.stderr)
    if not args.no_write:
        print(f"wrote {os.path.relpath(SNAPSHOT_PATH)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
