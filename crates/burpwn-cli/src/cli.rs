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
    Doctor,

    /// Install agent / shell command-rewrite hooks.
    Init(InitArgs),

    /// (hidden) The stdin filter the installed hooks pipe tool-input through.
    #[command(hide = true)]
    WrapHook,

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

    /// Export captured flows.
    Export {
        /// Export subcommand.
        #[command(subcommand)]
        action: ExportAction,
    },
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

/// `export` subcommands.
#[derive(Debug, Subcommand)]
pub enum ExportAction {
    /// Export an HAR 1.2 document.
    Har {
        /// Restrict to a workspace id.
        #[arg(long)]
        workspace: Option<i64>,
        /// Output file (defaults to stdout).
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Export a pcap (not yet implemented — errors clearly).
    Pcap {
        /// Output file.
        #[arg(short, long)]
        output: Option<String>,
    },
}
