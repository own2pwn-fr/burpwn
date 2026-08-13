//! The clap derive command tree. Pure declaration: dispatch lives in
//! [`crate::commands`]. A global `--json` flag selects the machine envelope
//! output; `--session` overrides the active session for the relevant commands.

use clap::{Args, Parser, Subcommand};

/// burpwn — transparent intercepting proxy + sandbox + agent interface.
#[derive(Debug, Parser)]
#[command(name = "burpwn", version, about, long_about = None)]
pub struct Cli {
    /// Emit machine-readable JSON (the `{ok,data,error}` envelope) instead of
    /// human text.
    #[arg(long, global = true)]
    pub json: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Probe the host for sandbox prerequisites and the CA.
    Doctor(DoctorArgs),

    /// Inspect and collect debug reports.
    Debug {
        /// What to do.
        #[command(subcommand)]
        action: DebugAction,
    },

    /// Install agent / shell command-rewrite hooks.
    Init(InitArgs),

    /// (hidden) The stdin filter the installed hooks pipe tool-input through.
    #[command(hide = true)]
    WrapHook {
        /// The agent whose hook dialect produced the stdin (e.g. `claude-code`,
        /// `cursor`, `gemini`). The installed hooks pass this; it selects the
        /// stdin/stdout JSON shape. Accepted for all agents (unknown → generic).
        #[arg(long)]
        agent: Option<String>,
    },

    /// (hidden) Run the proxy daemon for a session (spawned by `exec`).
    #[command(hide = true)]
    Proxy(ProxyArgs),

    /// Root CA management.
    Ca {
        /// CA subcommand.
        #[command(subcommand)]
        action: CaAction,
    },

    /// Session management.
    Session {
        /// Session subcommand.
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Run a command inside the sandbox, routed through the proxy.
    Exec(ExecArgs),

    /// Inspect captured requests/flows.
    Req {
        /// Request subcommand.
        #[command(subcommand)]
        action: ReqAction,
    },

    /// Live interception control (drives the daemon).
    Intercept {
        /// Intercept subcommand.
        #[command(subcommand)]
        action: InterceptAction,
    },

    /// Match/replace rule management.
    MatchReplace {
        /// Match/replace subcommand.
        #[command(subcommand)]
        action: MatchReplaceAction,
    },

    /// Hooks: run an action before a request / after a response.
    Hook {
        /// Hook subcommand.
        #[command(subcommand)]
        action: HookAction,
    },

    /// Workspace management.
    Workspace {
        /// Workspace subcommand.
        #[command(subcommand)]
        action: WorkspaceAction,
    },

    /// Tag a flow.
    Tag {
        /// Tag subcommand.
        #[command(subcommand)]
        action: TagAction,
    },

    /// Attach a note to a flow.
    Note {
        /// Note subcommand.
        #[command(subcommand)]
        action: NoteAction,
    },

    /// Group flows under a name + description (a named collection / highlight).
    Group {
        /// Group subcommand.
        #[command(subcommand)]
        action: GroupAction,
    },

    /// Export captured flows.
    Export {
        /// Export subcommand.
        #[command(subcommand)]
        action: ExportAction,
    },

    /// Intruder: run/inspect payload fuzzing attacks against a flow.
    Fuzz {
        /// Fuzz subcommand.
        #[command(subcommand)]
        action: FuzzAction,
    },

    /// Structured diff of two captured flows.
    Compare(CompareArgs),

    /// Encode a value (`base64`, `base64url`, `url`, `hex`).
    Encode {
        /// Scheme: `base64`, `base64url`, `url`, or `hex`.
        scheme: String,
        /// The value to encode.
        value: String,
    },

    /// Decode a value (`base64`, `base64url`, `url`, `hex`, `jwt`).
    Decode {
        /// Scheme: `base64`, `base64url`, `url`, `hex`, or `jwt`.
        scheme: String,
        /// The value to decode.
        value: String,
    },

    /// Install the burpwn skill (agent-workflow instructions) into a framework's
    /// native format/location. Separate from the `init` command-rewrite hook.
    Skill {
        /// Skill subcommand.
        #[command(subcommand)]
        action: SkillAction,
    },

    /// Register the burpwn stdio MCP server into a framework's MCP config.
    ///
    /// Note: bare `burpwn mcp` (no subcommand) starts the MCP server itself and
    /// is routed before this clap tree; `burpwn mcp register …` lands here.
    Mcp {
        /// MCP subcommand.
        #[command(subcommand)]
        action: McpAction,
    },
}

/// `skill` subcommands.
#[derive(Debug, Subcommand)]
pub enum SkillAction {
    /// Install the skill into one framework (`--agent`) or all (`--all`).
    Install(SkillInstallArgs),
    /// List the supported frameworks, their destination path and format.
    List,
    /// Remove the burpwn skill from a framework (strips only our content).
    Uninstall(SkillUninstallArgs),
}

/// `skill install` arguments.
#[derive(Debug, Args)]
pub struct SkillInstallArgs {
    /// Framework slug to install into (e.g. `claude-code`, `cursor`, `codex`).
    #[arg(long, conflicts_with = "all")]
    pub agent: Option<String>,

    /// Install into every supported framework.
    #[arg(long)]
    pub all: bool,

    /// Install at project scope (cwd-relative). This is the default.
    #[arg(long, conflicts_with = "global")]
    pub project: bool,

    /// Install at global scope (HOME-relative), where the framework supports it.
    #[arg(long)]
    pub global: bool,

    /// Print the resolved destination path + content to stdout; write nothing.
    #[arg(long)]
    pub print: bool,

    /// Overwrite/replace even a file/section burpwn does not own.
    #[arg(long)]
    pub force: bool,
}

/// `skill uninstall` arguments.
#[derive(Debug, Args)]
pub struct SkillUninstallArgs {
    /// Framework slug to uninstall from.
    #[arg(long)]
    pub agent: String,

    /// Operate on the global (HOME-relative) install instead of the project one.
    #[arg(long)]
    pub global: bool,
}

/// `mcp` subcommands (only `register`; bare `mcp` starts the server upstream).
#[derive(Debug, Subcommand)]
pub enum McpAction {
    /// Register the burpwn MCP server into a framework's MCP config.
    Register(McpRegisterArgs),
}

/// `mcp register` arguments.
#[derive(Debug, Args)]
pub struct McpRegisterArgs {
    /// MCP host slug to register into (`codex`, `copilot`, `antigravity`).
    #[arg(long)]
    pub agent: Option<String>,

    /// Accepted for symmetry; MCP host configs are user-level (HOME) already.
    #[arg(long)]
    pub global: bool,

    /// Print the resolved config path + content to stdout; write nothing.
    #[arg(long)]
    pub print: bool,

    /// List the supported MCP hosts + their config path and format.
    #[arg(long)]
    pub list: bool,
}

/// `fuzz` subcommands.
#[derive(Debug, Subcommand)]
pub enum FuzzAction {
    /// Run an attack against a stored flow's request.
    Run(FuzzRunArgs),
    /// List stored attacks.
    List {
        /// Restrict to a workspace by NAME.
        #[arg(long)]
        workspace: Option<String>,
    },
    /// Show one attack's per-payload results.
    Show {
        /// Attack id.
        attack_id: i64,
        /// Sort key: `anomaly` (default), `status`, or `len`.
        #[arg(long, default_value = "anomaly")]
        sort: String,
        /// Max rows.
        #[arg(long)]
        limit: Option<usize>,
    },
}

/// `fuzz run` arguments.
#[derive(Debug, Args)]
pub struct FuzzRunArgs {
    /// Stored flow supplying the base request + transport target.
    #[arg(long)]
    pub flow: i64,
    /// Read the base request bytes from a file (overrides the flow's request as
    /// the template; the flow still supplies the destination).
    #[arg(long)]
    pub request: Option<String>,
    /// Injection position as `start:end` byte offsets into the request. Repeatable.
    #[arg(long = "position", value_name = "START:END")]
    pub position: Vec<String>,
    /// A single inline payload. Repeatable.
    #[arg(long = "payload")]
    pub payload: Vec<String>,
    /// Load payloads from a file (one per line).
    #[arg(long)]
    pub payloads: Option<String>,
    /// Attack mode: `sniper`, `battering-ram`, `pitchfork`, `cluster-bomb`.
    #[arg(long, default_value = "sniper")]
    pub mode: String,
    /// Max in-flight requests.
    #[arg(long)]
    pub concurrency: Option<usize>,
    /// Pacing delay between launches, in milliseconds.
    #[arg(long)]
    pub delay: Option<u64>,
    /// Custom position marker (defaults to `§`).
    #[arg(long)]
    pub marker: Option<String>,
    /// Attack name.
    #[arg(long)]
    pub name: Option<String>,
}

/// `compare` arguments.
#[derive(Debug, Args)]
pub struct CompareArgs {
    /// First flow id.
    pub flow_a: i64,
    /// Second flow id.
    pub flow_b: i64,
    /// What to diff: `headers`, `body`, or `all` (default).
    #[arg(long, default_value = "all")]
    pub what: String,
}

/// `init` arguments.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Install the generic global shell hook (covers any agent).
    #[arg(short, long)]
    pub global: bool,

    /// Install the hook for a specific agent (e.g. `claude`, `cursor`).
    #[arg(long)]
    pub agent: Option<String>,

    /// Verify (don't install): drive a synthetic network command through each
    /// agent's `wrap-hook` path and assert the command is actually rewritten to
    /// route through `burpwn exec`. Reports per-agent PASS/FAIL/ADVISORY and
    /// exits non-zero if any agent that should rewrite doesn't.
    #[arg(long)]
    pub check: bool,
}

/// `proxy` (hidden daemon) arguments.
#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Session to serve (defaults to the active session).
    #[arg(long)]
    pub session: Option<String>,
}

/// `ca` subcommands.
#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Generate the CA if absent and report its location.
    Init,
    /// Print the CA certificate PEM to stdout.
    Export,
}

/// `session` subcommands.
#[derive(Debug, Subcommand)]
pub enum SessionAction {
    /// Create a new session.
    New {
        /// Session name (defaults to `default`).
        #[arg(long)]
        name: Option<String>,
    },
    /// List sessions.
    List,
    /// Switch the active session.
    Use {
        /// Session name.
        name: String,
    },
    /// Remove a session (its database and runtime files).
    Rm {
        /// Session name.
        name: String,
    },
    /// Import a session bundle written by `burpwn export session`, as a NEW
    /// session. Never merges into and never overwrites an existing one.
    Import {
        /// The `.burpwn` bundle file.
        file: String,
        /// Name to import under (defaults to the name the bundle was exported
        /// from). Use it when that name is already taken here.
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
        /// Switch the active session to the imported one.
        #[arg(long = "use")]
        use_session: bool,
    },
    /// Capture-completeness stats for a session (execs vs captured flows; flags
    /// network-facing execs that captured ZERO flows — traffic likely escaped).
    Stats {
        /// Session to report on (defaults to the active session).
        #[arg(long)]
        session: Option<String>,
    },
    /// Session auth handling: persist a login command + token-injection rule and
    /// refresh the token when the target starts returning 401s.
    Auth {
        /// Auth subcommand.
        #[command(subcommand)]
        action: SessionAuthAction,
    },
}

/// `session auth` subcommands.
#[derive(Debug, Subcommand)]
pub enum SessionAuthAction {
    /// Persist (or update) an auth profile for the session.
    Set(SessionAuthSetArgs),
    /// Run the stored login command, extract the token, and (re)install the
    /// match/replace rule that injects the auth header into in-scope requests.
    Refresh {
        /// Restrict to the profile for this host scope (defaults to all profiles).
        #[arg(long)]
        host: Option<String>,
        /// Session to operate on (defaults to the active session).
        #[arg(long)]
        session: Option<String>,
    },
    /// Show the stored auth profile(s) and whether a token is currently set
    /// (the token value is masked).
    Status {
        /// Session to operate on (defaults to the active session).
        #[arg(long)]
        session: Option<String>,
    },
}

/// `session auth set` arguments.
#[derive(Debug, Args)]
pub struct SessionAuthSetArgs {
    /// The login command whose output carries a fresh token, e.g.
    /// `curl -s https://api/login -d user=…`.
    #[arg(long)]
    pub login: String,
    /// A regex with ONE capture group applied to the login command's output to
    /// pull the token, e.g. `"token":"([^"]+)"`.
    #[arg(long)]
    pub extract: String,
    /// The header to inject, with `{}` where the token goes, e.g.
    /// `Authorization: Bearer {}`.
    #[arg(long)]
    pub header: String,
    /// Host scope the injection applies to (case-insensitive substring; omit for
    /// all hosts).
    #[arg(long)]
    pub host: Option<String>,
    /// Session to operate on (defaults to the active session).
    #[arg(long)]
    pub session: Option<String>,
}

/// `debug` subcommands.
#[derive(Debug, Subcommand)]
pub enum DebugAction {
    /// Write a full debug report (host, prerequisites, live sandbox probe,
    /// sessions) for attaching to a bug report.
    Bundle(DebugBundleArgs),
    /// List the debug reports burpwn wrote automatically on past failures.
    List,
    /// Print one stored report (the most recent by default).
    Show {
        /// Path of a report to print. Defaults to the most recent one.
        path: Option<String>,
    },
}

/// `debug bundle` arguments.
#[derive(Debug, Args)]
pub struct DebugBundleArgs {
    /// Write the report here instead of the debug directory. `-` prints it to
    /// stdout.
    #[arg(long, short = 'o')]
    pub out: Option<String>,

    /// Skip the live sandbox probe (which forks a throwaway namespace). The
    /// probe is the most useful part of the report on a host where capture is
    /// not working, so it runs by default.
    #[arg(long)]
    pub no_probe: bool,
}

/// `doctor` arguments.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Skip the live sandbox probe and only check that the prerequisites are
    /// installed. Much faster, but it CANNOT tell you whether the kernel can
    /// actually create the sandbox (a host may have `ip`/`nft` installed and
    /// still lack the modules behind them — this is exactly what happens on
    /// WSL), so the deep probe is the default.
    #[arg(long)]
    pub quick: bool,
}

/// `exec` arguments.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Workspace NAME to attribute captured flows to (created on first use). When
    /// omitted, the default workspace (id 1) is used.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Wall-clock timeout for the command, in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Session to run under (defaults to the active session).
    #[arg(long)]
    pub session: Option<String>,

    /// The command to run (everything after `--`).
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}

/// `req` subcommands.
#[derive(Debug, Subcommand)]
pub enum ReqAction {
    /// List captured flows.
    List(ReqListArgs),
    /// Show one flow in detail.
    Show {
        /// Flow id.
        id: i64,
        /// Print the verbatim request/response bytes instead of a summary.
        #[arg(long)]
        raw: bool,
    },
    /// Full-text search flow bodies.
    Search {
        /// Query string.
        query: String,
    },
    /// Replay (Repeater) a stored flow, optionally edited.
    Replay(ReqReplayArgs),
}

/// `req list` filters.
#[derive(Debug, Args, Default)]
pub struct ReqListArgs {
    /// Substring match against host / SNI / dst ip.
    #[arg(long)]
    pub host: Option<String>,
    /// Exact response status.
    #[arg(long)]
    pub status: Option<u16>,
    /// Exact request method.
    #[arg(long)]
    pub method: Option<String>,
    /// Exact wire protocol (`h1`, `h2`, `ws`, `dns`, `rawtcp`, `tls-passthru`).
    #[arg(long)]
    pub protocol: Option<String>,
    /// Exact destination port.
    #[arg(long)]
    pub port: Option<u16>,
    /// Restrict to a workspace by NAME.
    #[arg(long)]
    pub workspace: Option<String>,
    /// Restrict to the flows in a group, by NAME (see `burpwn group list`).
    #[arg(long)]
    pub group: Option<String>,
    /// Max rows.
    #[arg(long)]
    pub limit: Option<i64>,
    /// Row offset.
    #[arg(long)]
    pub offset: Option<i64>,
}

/// `req replay` arguments.
#[derive(Debug, Args)]
pub struct ReqReplayArgs {
    /// Flow id to replay.
    pub id: i64,
    /// Override / add a request header (`Name: value` or `Name=value`). Repeatable.
    #[arg(long = "set-header", value_name = "K=V")]
    pub set_header: Vec<String>,
    /// Replace the body with a literal string, or `@file` to read from a file.
    #[arg(long = "set-body", value_name = "STR|@file")]
    pub set_body: Option<String>,
    /// Override the request method.
    #[arg(long)]
    pub method: Option<String>,
}

/// `intercept` subcommands.
#[derive(Debug, Subcommand)]
pub enum InterceptAction {
    /// Enable interception.
    Enable,
    /// Disable interception.
    Disable,
    /// List parked intercepts.
    List,
    /// Long-poll for the next parked intercept.
    Await {
        /// Seconds to wait.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Forward a parked intercept, optionally edited.
    Forward {
        /// Parked id.
        id: u64,
        /// Set a header (`Name: value`). Repeatable.
        #[arg(long = "set-header", value_name = "K=V")]
        set_header: Vec<String>,
        /// Replace the body.
        #[arg(long = "set-body")]
        set_body: Option<String>,
        /// Replace the method.
        #[arg(long)]
        method: Option<String>,
    },
    /// Drop a parked intercept.
    Drop {
        /// Parked id.
        id: u64,
    },
    /// Narrow blocking interception to a host/path (so not every flow parks), or
    /// clear the scope with `--clear`.
    Scope {
        /// Host substring the flow must contain to be intercepted. Omit with
        /// `--clear` to widen back to every flow.
        #[arg(required_unless_present = "clear")]
        pattern: Option<String>,
        /// Also require this path substring.
        #[arg(long)]
        path: Option<String>,
        /// Also require this exact request method (case-insensitive).
        #[arg(long)]
        method: Option<String>,
        /// Clear the scope (intercept every flow again).
        #[arg(long, conflicts_with_all = ["pattern", "path", "method"])]
        clear: bool,
    },
}

/// `match-replace` subcommands.
#[derive(Debug, Subcommand)]
pub enum MatchReplaceAction {
    /// Add a rule.
    Add {
        /// Scope expression (e.g. host glob; empty = all).
        scope: String,
        /// What to match (`header`, `body`, `url`, `host`).
        kind: String,
        /// Match pattern.
        pattern: String,
        /// Replacement string.
        replacement: String,
        /// Apply to `request` (default) or `response`.
        #[arg(long, default_value = "request")]
        on: String,
    },
    /// List rules.
    List,
    /// Remove a rule by id.
    Rm {
        /// Rule id.
        id: i64,
    },
    /// Enable a rule by id.
    Enable {
        /// Rule id.
        id: i64,
    },
    /// Disable a rule by id.
    Disable {
        /// Rule id.
        id: i64,
    },
}

/// `hook add` arguments.
#[derive(Debug, Args)]
pub struct HookAddArgs {
    /// Name for this hook (free text, for `hook list`).
    pub name: String,
    /// When it fires: `pre-request` (default) or `post-response`.
    #[arg(long, default_value = "pre-request")]
    pub phase: String,
    /// What it does: `add-header`, `set-header`, `remove-header`,
    /// `set-query-param`, `drop` or `exec`.
    #[arg(long)]
    pub action: String,
    /// Only for hosts containing this (empty = every host; `*.example.com`
    /// also accepted).
    #[arg(long, default_value = "")]
    pub host: String,
    /// Only for this request method (case-insensitive; empty = any).
    #[arg(long, default_value = "")]
    pub method: String,
    /// Only for request targets containing this (empty = any).
    #[arg(long, default_value = "")]
    pub path: String,
    /// Only for this response status (`post-response` hooks only).
    #[arg(long)]
    pub status: Option<u16>,
    /// `Name: value` for the header actions — or a bare `Name` for
    /// `remove-header`.
    #[arg(long)]
    pub header: Option<String>,
    /// `name=value`, for `set-query-param`.
    #[arg(long)]
    pub param: Option<String>,
    /// The command to run, for `exec` (run as `sh -c` IN THE SANDBOX, so
    /// its own traffic is captured — and never re-hooked).
    #[arg(long)]
    pub cmd: Option<String>,
    /// Regex with ONE capture group, applied to the command's stdout to
    /// pull out the value (e.g. `"access_token":"([^"]+)"`).
    #[arg(long)]
    pub extract: Option<String>,
    /// Where the extracted value goes: `Name: prefix {}` (the `{}` is
    /// replaced by the value).
    #[arg(long)]
    pub inject_header: Option<String>,
    /// Where the extracted value goes, as a query parameter: `name={}`.
    #[arg(long, conflicts_with = "inject_header")]
    pub inject_param: Option<String>,
    /// Inject the header only when the message does not already carry one
    /// (default: replace an existing one).
    #[arg(long)]
    pub inject_if_absent: bool,
    /// Application order within the phase (ascending).
    #[arg(long, default_value_t = 0)]
    pub order: i64,
    /// Hard budget for an `exec` command, in milliseconds. On expiry the
    /// hook FAILS OPEN: the request goes through un-hooked.
    #[arg(long = "timeout", default_value_t = crate::hooks::DEFAULT_TIMEOUT_MS)]
    pub timeout_ms: i64,
    /// How long an extracted value is reused before the command runs again,
    /// in milliseconds. `0` runs it on every matching request — one sandbox
    /// per request.
    #[arg(long = "ttl", default_value_t = crate::hooks::DEFAULT_TTL_MS)]
    pub ttl_ms: i64,
    /// Create it disabled.
    #[arg(long)]
    pub disabled: bool,
}

/// `hook` subcommands.
///
/// A hook applies ONE action to every message matching its scope, on one phase.
/// Where a match/replace rule rewrites text that is already in the message, a
/// hook can put in what is not there (`add-header`), take it out, refuse the
/// flow (`drop`), or park the request behind a command whose output it injects
/// (`exec` — a token mint, a request signer).
// `Add` carries every flag of the richest command in the tree; boxing it to
// even out the variants would cost an allocation on a one-shot CLI parse for
// nothing, and clap's derive wants the args by value.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Add a hook.
    Add(HookAddArgs),
    /// List hooks in application order.
    List,
    /// Show one hook in full.
    Show {
        /// Hook id.
        id: i64,
    },
    /// Remove a hook by id.
    Rm {
        /// Hook id.
        id: i64,
    },
    /// Enable a hook by id.
    Enable {
        /// Hook id.
        id: i64,
    },
    /// Disable a hook by id.
    Disable {
        /// Hook id.
        id: i64,
    },
    /// Replay a hook against a CAPTURED flow and show what it would do: does it
    /// match, what does it change. No live traffic is sent. For an `exec` hook
    /// the command DOES run (in the sandbox), so this is also how you check that
    /// the extraction regex still matches.
    Test {
        /// Hook id.
        id: i64,
        /// Flow to test it against.
        #[arg(long)]
        flow: i64,
        /// Session to operate on (defaults to the active session).
        #[arg(long)]
        session: Option<String>,
    },
}

/// `workspace` subcommands.
#[derive(Debug, Subcommand)]
pub enum WorkspaceAction {
    /// Create a workspace.
    New {
        /// Workspace name.
        name: String,
    },
    /// List workspaces.
    List,
    /// (informational) Print the workspace to attribute flows to. Pass `--workspace`
    /// on `exec`/`req` to actually scope; this records the choice in config.
    Use {
        /// Workspace name.
        name: String,
    },
}

/// `tag` subcommands.
#[derive(Debug, Subcommand)]
pub enum TagAction {
    /// Attach a tag to a flow.
    Add {
        /// Flow id.
        flow_id: i64,
        /// Tag name.
        name: String,
    },
    /// List all defined tags.
    List,
}

/// `note` subcommands.
#[derive(Debug, Subcommand)]
pub enum NoteAction {
    /// Attach a note to a flow.
    Add {
        /// Flow id.
        flow_id: i64,
        /// Note text.
        text: String,
    },
    /// List the notes attached to a flow.
    List {
        /// Flow id.
        flow_id: i64,
    },
}

/// `group` subcommands.
///
/// A group is a named, described subset of a session's flows: the handle for a
/// reconstructed scenario ("auth-flow": login form → POST /login → redirect +
/// Set-Cookie) or one campaign ("xss-fuzz-search-param"). Names are unique per
/// workspace; every subcommand takes the NAME, not an id.
#[derive(Debug, Subcommand)]
pub enum GroupAction {
    /// Create a group (or update the description of an existing one).
    New {
        /// Group name (unique within the workspace).
        name: String,
        /// What this collection of flows means, in prose.
        #[arg(long)]
        description: Option<String>,
        /// Workspace to create it in, by NAME or numeric id (defaults to the
        /// session's default workspace).
        #[arg(long)]
        workspace: Option<String>,
    },
    /// Add one or more flows to a group.
    Add {
        /// Group name.
        name: String,
        /// Flow ids to add.
        #[arg(required = true)]
        flow_id: Vec<i64>,
    },
    /// Remove one or more flows from a group (the flows themselves survive).
    RmFlow {
        /// Group name.
        name: String,
        /// Flow ids to remove.
        #[arg(required = true)]
        flow_id: Vec<i64>,
    },
    /// List groups with their description and flow count.
    List {
        /// Restrict to a workspace, by NAME or numeric id.
        #[arg(long)]
        workspace: Option<String>,
    },
    /// List the flows in a group (same rendering as `req list`).
    Show {
        /// Group name.
        name: String,
    },
    /// Delete a group. Only the grouping goes away; the flows stay captured.
    Rm {
        /// Group name.
        name: String,
    },
}

/// `export` subcommands.
#[derive(Debug, Subcommand)]
pub enum ExportAction {
    /// Export an HAR 1.2 document.
    Har {
        /// Restrict to a workspace id.
        #[arg(long)]
        workspace: Option<i64>,
        /// Restrict to the flows in a group, by NAME — the natural way to
        /// export one named scenario. Mutually exclusive with `--workspace`
        /// (the group already lives in a workspace).
        #[arg(long, conflicts_with = "workspace")]
        group: Option<String>,
        /// Output file (defaults to stdout).
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Export the WHOLE session as one portable file (`<name>.burpwn`): every
    /// flow with its bodies, plus the groups, tags, notes, attacks and rules.
    /// `burpwn session import <file>` opens it on another machine.
    ///
    /// By default the bundle is RAW — it carries the stored auth tokens, the
    /// login commands and the Authorization / Cookie headers captured in the
    /// traffic, so that the session replays identically. `--redact` drops the
    /// stored credentials; it does NOT scrub the ones captured inside recorded
    /// requests and responses.
    Session {
        /// Session to export (defaults to the active session).
        #[arg(long)]
        session: Option<String>,
        /// Output file (defaults to `<session>.burpwn` in the current directory).
        #[arg(short, long)]
        output: Option<String>,
        /// Drop the stored auth tokens, login commands and match/replace
        /// replacements. Credentials captured INSIDE recorded requests and
        /// responses (Authorization / Cookie headers, login bodies) stay in the
        /// bundle — see the command help.
        #[arg(long)]
        redact: bool,
        /// Overwrite the output file if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Export a pcap (not yet implemented — errors clearly).
    Pcap {
        /// Output file.
        #[arg(short, long)]
        output: Option<String>,
    },
}
