# burpwn agent skill

Teaches an AI coding agent how to drive `burpwn` — a Burp-like transparent
intercepting proxy + rootless sandbox for AI-driven web pentesting on Linux.

## Files
- `SKILL.md` — the skill the agent loads: workflow + verified, copyable commands.
- `reference.md` — full flag reference for every subcommand.
- `README.md` — this file.

## Install

Copy the `burpwn/` skill directory into your agent's skills folder:

```sh
# Claude Code
cp -r skills/burpwn ~/.claude/skills/

# Other agents — equivalent skills dir, e.g.:
#   Cursor:  ~/.cursor/skills/
#   Cline:   ~/.cline/skills/
```

The agent matches the skill on web-pentest / intercept-traffic /
inspect-requests / replay tasks via the `description` in `SKILL.md`.

## Wire up auto-capture (optional but recommended)

`burpwn init` installs a command-rewrite hook so each shell command the agent
runs is auto-routed through `burpwn exec` (so its traffic is captured without
prefixing every command):

```sh
burpwn init --agent claude     # or: cursor | gemini | cline
burpwn init --global           # generic global shell hook (any agent)
```

Without the hook, route commands explicitly: `burpwn exec -- <cmd>`.

## Prereqs the agent should check first
- `burpwn doctor` — rootless namespace support + CA presence (Linux only).
- `burpwn ca init` — generate the MITM CA once (idempotent).
