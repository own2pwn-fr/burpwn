# burpwn agent skill

Teaches an AI coding agent how to drive `burpwn` — a Burp-like transparent
intercepting proxy + rootless sandbox for AI-driven web pentesting on Linux.

## Files
- `SKILL.md` — the skill the agent loads: workflow + verified, copyable commands.
- `reference.md` — full flag reference for every subcommand.
- `README.md` — this file.

## Install

**Claude Code (one step):** the repo is a plugin marketplace, so

```sh
/plugin marketplace add own2pwn-fr/burpwn
/plugin install burpwn@burpwn
```

installs this skill (`burpwn` must be on `PATH`). The plugin ships the **skill only** — the
enforced `PreToolUse` auto-capture hook is a separate opt-in (see below), so the two aren't stacked.

**Manually / other agents:** copy the `burpwn/` skill directory into your agent's skills folder:

```sh
# Claude Code
cp -r skills/burpwn ~/.claude/skills/

# Other agents — equivalent skills dir, e.g.:
#   Cursor:  ~/.cursor/skills/
#   Cline:   ~/.cline/skills/
```

The agent matches the skill on web-pentest / intercept-traffic /
inspect-requests / replay tasks via the `description` in `SKILL.md`.

## Enforced auto-capture (opt-in, separate from the skill)

By default the skill drives capture itself: it creates a session and routes
target-facing commands through `burpwn exec`. If you instead want **every** shell
command auto-routed (enforced capture even when the model forgets), opt into the
hook with `burpwn init`:

```sh
burpwn init --agent claude     # or: cursor | gemini | cline
burpwn init --global           # generic global shell hook (any agent)
```

Trade-off: the hook sandboxes *all* commands (not just network ones) and does not
create a session for you — captures land in the active/default session. Pick the
skill *or* the hook; don't run both. Without the hook, route commands explicitly:
`burpwn exec -- <cmd>`.

## Prereqs the agent should check first
- `burpwn doctor` — rootless namespace support + CA presence (Linux only).
- `burpwn ca init` — generate the MITM CA once (idempotent).
