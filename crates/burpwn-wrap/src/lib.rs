//! burpwn-wrap — agent integration (rtk-style). Installs per-agent command-rewrite hooks
//! (Claude Code / Copilot PreToolUse, Cursor hooks.json, Gemini BeforeTool, Cline/Roo .clinerules)
//! and a generic global shell hook so even a custom agent is covered. Each command the agent runs
//! is rewritten to flow through `burpwn exec`, while the agent process itself stays out of the
//! sandbox (its LLM traffic is never captured).

// Implementation lands in M8.
