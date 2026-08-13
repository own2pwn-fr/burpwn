//! The rmcp 0.2 tool server.
//!
//! Uses the declarative macro API confirmed against rmcp 0.2.1:
//! - the server struct carries a `tool_router: ToolRouter<Self>` field,
//!   initialised in `new()` via the macro-generated `Self::tool_router()`;
//! - `#[tool_router]` on the inherent `impl` collects every `#[tool]` method;
//! - each `#[tool]` async method takes `Parameters<T>` (for typed params) and
//!   returns `Result<CallToolResult, McpError>`;
//! - `#[tool_handler] impl ServerHandler` wires the router into the protocol;
//! - we serve over stdio with `server.serve(stdio()).await?.waiting().await`.
//!
//! Each tool is a thin shim: decode params → call the matching async function in
//! [`crate::handlers`] → wrap the returned `serde_json::Value` as JSON text
//! content, mapping `anyhow` errors to `McpError`.

use std::future::Future;
use std::sync::Arc;

use rmcp::handler::server::tool::{Parameters, ToolRouter};
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, Error as McpError, ServerHandler};

use burpwn_cli::paths::Paths;

use crate::handlers;
use crate::params::*;

/// The burpwn MCP server. Holds the resolved session context (paths + active
/// session name) and the generated tool router.
#[derive(Clone)]
pub struct BurpwnServer {
    inner: Arc<ServerState>,
    tool_router: ToolRouter<Self>,
}

/// Shared, immutable server context.
struct ServerState {
    paths: Paths,
    session: String,
}

/// Render a handler's JSON `Value` as a `CallToolResult` carrying a pretty-JSON
/// text block (rmcp 0.2.1 `CallToolResult` has no structured-content field).
fn ok_json(value: serde_json::Value) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

#[tool_router]
impl BurpwnServer {
    /// Map a handler failure into an MCP tool error the AGENT can act on.
    ///
    /// An agent cannot read a terminal, so everything a human would get from the
    /// rendered error block has to travel in the tool result: the message text
    /// IS that block, and the structured diagnostic (code, class, causes,
    /// remediation, exit code, debug-report path) rides along in the error's
    /// `data` so the agent can branch on the code instead of parsing prose. The
    /// debug report is filed here too — the agent's user will want it.
    fn err(&self, e: anyhow::Error) -> McpError {
        let mut diag = burpwn_cli::diag::diagnose(&e);
        if let Some(path) = burpwn_cli::debugreport::write(&self.inner.paths, &diag) {
            diag = diag.debug_report(path);
        }
        McpError::internal_error(diag.render(), Some(diag.to_json()))
    }

    /// Build the server for a resolved session.
    pub fn new(paths: Paths, session: String) -> Self {
        Self {
            inner: Arc::new(ServerState { paths, session }),
            tool_router: Self::tool_router(),
        }
    }

    fn paths(&self) -> &Paths {
        &self.inner.paths
    }
    fn session(&self) -> &str {
        &self.inner.session
    }

    // --- session ----------------------------------------------------------

    #[tool(description = "List all burpwn sessions and the active one.")]
    async fn session_list(&self) -> Result<CallToolResult, McpError> {
        handlers::session_list(self.paths())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Show the active session and whether its database exists.")]
    async fn session_current(&self) -> Result<CallToolResult, McpError> {
        handlers::session_current(self.paths())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Capture-completeness telemetry for the session: total execs vs captured flows, and network-facing execs that captured ZERO flows (traffic likely escaped capture — the agent hook may not be routing through `burpwn exec`)."
    )]
    async fn session_stats(&self) -> Result<CallToolResult, McpError> {
        handlers::session_stats(self.paths(), self.session())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Archive the WHOLE session into one portable file (a `.burpwn` bundle): every captured flow with its bodies, plus the workspaces, groups, tags, notes, attacks and match/replace rules. Reach for it when a piece of work is finished and worth keeping or handing over — the file opens on another machine with `burpwn session import <file>`, which is an operator action, not a tool. WARNING: by default the bundle is RAW, so it carries the stored auth tokens, the login commands and the Authorization/Cookie headers captured in the traffic; pass redact=true to drop the stored credentials (it does NOT scrub the ones captured inside recorded requests and responses). Refuses to overwrite an existing file unless force=true."
    )]
    async fn session_export(
        &self,
        Parameters(params): Parameters<SessionExportParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::session_export(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- session auth -----------------------------------------------------

    #[tool(
        description = "Persist a session-auth profile: a login command, a token-extraction regex (one capture group), and a header-injection template (e.g. 'Authorization: Bearer {}'), optionally scoped to a host. It becomes a pre-request hook that runs the login command on demand and ADDS the header (even to a request that carries none), so nothing has to be minted up front. Re-running it for the same host replaces that profile."
    )]
    async fn session_auth_set(
        &self,
        Parameters(params): Parameters<SessionAuthSetParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::session_auth_set(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Drop the token the daemon has cached for the profile(s), so the next request through the proxy runs the login command again and carries a fresh token. Rarely needed: a 401/403 already invalidates a cached token by itself."
    )]
    async fn session_auth_refresh(
        &self,
        Parameters(params): Parameters<SessionAuthRefreshParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::session_auth_refresh(self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Show the stored session-auth profile(s): hook id, host scope, login command, injected header and cache TTL. The token is never stored — it is minted on demand and held only in the running daemon."
    )]
    async fn session_auth_status(&self) -> Result<CallToolResult, McpError> {
        handlers::session_auth_status(self.paths(), self.session())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- query ------------------------------------------------------------

    #[tool(
        description = "List captured HTTP flows with optional filters (host, status, method, protocol, port, workspace, limit, offset). Newest first."
    )]
    async fn req_list(
        &self,
        Parameters(params): Parameters<ReqListParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::req_list(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Show one flow's decoded request and response by id. Set raw=true to also include verbatim head+body text."
    )]
    async fn req_show(
        &self,
        Parameters(params): Parameters<ReqShowParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::req_show(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Full-text search over captured request/response text; returns flow ids.")]
    async fn req_search(
        &self,
        Parameters(params): Parameters<ReqSearchParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::req_search(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "List workspaces in the active session.")]
    async fn workspace_list(&self) -> Result<CallToolResult, McpError> {
        handlers::workspace_list(self.paths(), self.session())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "List tags in the active session.")]
    async fn tag_list(&self) -> Result<CallToolResult, McpError> {
        handlers::tag_list(self.paths(), self.session())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "List match/replace rules in the active session.")]
    async fn match_replace_list(&self) -> Result<CallToolResult, McpError> {
        handlers::match_replace_list(self.paths(), self.session())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- mutation ---------------------------------------------------------

    #[tool(
        description = "Add a match/replace rule. kind is one of header|body|url|host; on_request true=requests, false=responses."
    )]
    async fn match_replace_add(
        &self,
        Parameters(params): Parameters<MatchReplaceAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::match_replace_add(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Create/attach a tag to a flow.")]
    async fn tag_add(
        &self,
        Parameters(params): Parameters<TagAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::tag_add(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Attach a note to a flow.")]
    async fn note_add(
        &self,
        Parameters(params): Parameters<NoteAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::note_add(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- groups (named collections of flows) ------------------------------

    // --- hooks ------------------------------------------------------------

    #[tool(
        description = "Install a HOOK: one action applied to every request (or response) matching a scope, by the proxy itself. Reach for it when something must be true of ALL traffic rather than of one request you are about to send. Two things match/replace cannot do: hook_add(name='ua', action='add-header', header='User-Agent: burpwn') puts in a header the client never sent (a rule can only rewrite one that is already there), and action='exec' runs a command in the sandbox before the request goes out and injects what it prints — the way to keep a bearer token fresh: hook_add(name='token', action='exec', host='api.target.com', cmd='./mint-token.sh', extract='\"access_token\":\"([^\"]+)\"', inject_header='Authorization: Bearer {}', ttl_ms=300000). Set ttl_ms or the command runs on every matching request (one sandbox each). A failing or slow exec hook FAILS OPEN — the traffic goes through un-hooked — so a hook never blocks an engagement. Other actions: set-header, remove-header, set-query-param, drop."
    )]
    async fn hook_add(
        &self,
        Parameters(params): Parameters<HookAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::hook_add(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "List the hooks installed on the proxy, in the order they are applied. Read it when traffic does not look like what you sent (a header you did not add, a request refused with 403 'dropped by hook'), and before adding a hook that may already exist."
    )]
    async fn hook_list(&self) -> Result<CallToolResult, McpError> {
        handlers::hook_list(self.paths(), self.session())
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Enable or disable a hook by id, keeping its definition. Use it to isolate a hook's effect on a target (disable, re-send, compare) instead of deleting and re-adding it."
    )]
    async fn hook_set_enabled(
        &self,
        Parameters(params): Parameters<HookSetEnabledParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::hook_set_enabled(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Delete a hook by id. Captured flows are untouched.")]
    async fn hook_rm(
        &self,
        Parameters(params): Parameters<HookRmParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::hook_rm(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Replay a hook against a CAPTURED flow and report what it would do — does it match, what does it change — without sending any live traffic. This is how you debug a hook that seems not to fire (usually a scope that does not match) instead of guessing from the captures. For an exec hook the command really runs, so it also tells you whether the extraction regex still matches the command's output."
    )]
    async fn hook_test(
        &self,
        Parameters(params): Parameters<HookTestParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::hook_test(self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Create a NAMED, described collection of flows (a 'group' — the equivalent of a Burp highlight). Use it the moment you understand something worth keeping: once you have worked out how the target authenticates, create group_new(name='auth-flow', description='login form -> POST /login -> redirect + Set-Cookie session') and add the flows that prove it; do the same to isolate one campaign (name='xss-fuzz-search-param'). The description is for your future self and for the report — say what the sequence MEANS, not that it exists. Idempotent: re-creating an existing name returns the same group and just updates its description."
    )]
    async fn group_new(
        &self,
        Parameters(params): Parameters<GroupNewParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::group_new(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Add captured flows to a group by its name, e.g. the three requests that make up a login sequence: group_add(name='auth-flow', flow_ids=[3,5,9]). Flow ids come from req_list/req_search/exec. Adding a flow twice is a no-op; an unknown flow id fails the whole call rather than half-filling the group."
    )]
    async fn group_add(
        &self,
        Parameters(params): Parameters<GroupAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::group_add(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "List the flow groups in the session with their description and flow count — the index of the scenarios recorded so far. Read it before re-deriving something (an auth sequence may already be captured under a name)."
    )]
    async fn group_list(
        &self,
        Parameters(params): Parameters<GroupListParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::group_list(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Show one group: its description plus every flow in it, in the same row shape as req_list. This is how you replay a documented scenario — read the group, then req_show/req_replay its flows in order."
    )]
    async fn group_show(
        &self,
        Parameters(params): Parameters<GroupShowParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::group_show(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Delete a flow group by name. Only the grouping is removed — the captured flows stay in the session and remain listable."
    )]
    async fn group_rm(
        &self,
        Parameters(params): Parameters<GroupRmParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::group_rm(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Create a new workspace.")]
    async fn workspace_new(
        &self,
        Parameters(params): Parameters<WorkspaceNewParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::workspace_new(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- daemon / intercept ----------------------------------------------

    #[tool(description = "Enable request interception on the running proxy daemon.")]
    async fn intercept_enable(&self) -> Result<CallToolResult, McpError> {
        handlers::intercept_enable(self.paths(), self.session())
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Disable request interception on the running proxy daemon.")]
    async fn intercept_disable(&self) -> Result<CallToolResult, McpError> {
        handlers::intercept_disable(self.paths(), self.session())
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "List currently parked (held) intercepts on the daemon.")]
    async fn intercept_list(&self) -> Result<CallToolResult, McpError> {
        handlers::intercept_list(self.paths(), self.session())
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Long-poll for the next parked intercept. Blocks up to timeout_secs (default ~30s) and returns the parked request or {pending:false} on timeout."
    )]
    async fn await_intercept(
        &self,
        Parameters(params): Parameters<AwaitInterceptParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::await_intercept(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Forward (release) a parked intercept by id, optionally setting headers, replacing the body, or (for an await_intercept-parked request) changing the method/path."
    )]
    async fn intercept_forward(
        &self,
        Parameters(params): Parameters<InterceptForwardParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::intercept_forward(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Narrow blocking interception to a host/path/method so not every flow parks (set clear=true to widen back to every flow). Wires the proxy's scope filter."
    )]
    async fn intercept_scope(
        &self,
        Parameters(params): Parameters<InterceptScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::intercept_scope(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Drop a parked intercept by id (do not forward it).")]
    async fn intercept_drop(
        &self,
        Parameters(params): Parameters<InterceptDropParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::intercept_drop(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- exec -------------------------------------------------------------

    #[tool(
        description = "Run a command inside the burpwn sandbox so its traffic is captured. Returns {exit_code, captured_request_ids, exec_id}."
    )]
    async fn exec(
        &self,
        Parameters(params): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::run_exec(self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- repeater ---------------------------------------------------------

    #[tool(
        description = "Replay (Repeater) a stored flow, optionally editing method/headers/body, and return the response. Same transport as the CLI `req replay`."
    )]
    async fn req_replay(
        &self,
        Parameters(params): Parameters<ReqReplayParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::req_replay(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- fuzz (Intruder) --------------------------------------------------

    #[tool(
        description = "Intruder: run a payload fuzzing attack against a stored flow's request. positions are start:end byte offsets (or § markers); mode is sniper|battering-ram|pitchfork|cluster-bomb. Persists an attack + per-payload results and returns the ranked table."
    )]
    async fn fuzz(
        &self,
        Parameters(params): Parameters<FuzzParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::fuzz_run(self.paths(), self.session(), &params)
            .await
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "List stored Intruder attacks (id, name, base flow, status, #results).")]
    async fn fuzz_list(
        &self,
        Parameters(params): Parameters<FuzzListParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::fuzz_list(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Fetch one attack's per-payload results, sorted by anomaly|status|len (default anomaly), optionally limited."
    )]
    async fn fuzz_results(
        &self,
        Parameters(params): Parameters<FuzzResultsParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::fuzz_results(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    // --- compare / encode -------------------------------------------------

    #[tool(
        description = "Structured diff of two flows: status-line delta, header add/remove/change, line-based body diff, and a reflection check (tokens from flow A's request echoed in flow B's response). what = headers|body|all. The body line lists are capped at 200 lines per side; when that cuts anything the reply carries body.truncated = {only_in_a|only_in_b: {shown, total}} — re-call with a larger max_lines (or a negative one for no cap) to get the rest."
    )]
    async fn compare(
        &self,
        Parameters(params): Parameters<CompareParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::compare(self.paths(), self.session(), &params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(description = "Encode a value. scheme = base64|base64url|url|hex. Pure (no network).")]
    async fn encode(
        &self,
        Parameters(params): Parameters<EncodeParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::encode(&params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }

    #[tool(
        description = "Decode a value. scheme = base64|base64url|url|hex|jwt (jwt splits header.payload.signature and decodes to JSON without verifying the signature)."
    )]
    async fn decode(
        &self,
        Parameters(params): Parameters<EncodeParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::decode(&params)
            .map_err(|e| self.err(e))
            .and_then(ok_json)
    }
}

#[tool_handler]
impl ServerHandler for BurpwnServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "burpwn MCP server: an intercepting web-pentest proxy + sandbox. \
                 Query captured flows (req_list/req_show/req_search), run commands \
                 through the sandbox (exec), and drive blocking interception \
                 (intercept_enable, await_intercept long-poll, intercept_forward/drop). \
                 Offensive tooling: req_replay (Repeater), fuzz/fuzz_list/fuzz_results \
                 (Intruder), compare (structured flow diff + reflection check), and \
                 encode/decode (base64/url/hex/jwt). Findings are kept as named \
                 collections (group_new/group_add/group_list/group_show/group_rm), \
                 tags and notes, and a finished session can be archived whole with \
                 session_export. Policy applied to ALL traffic goes in hooks \
                 (hook_add/hook_list/hook_test): adding a header the client never \
                 sent, or running a command before a request and injecting what it \
                 prints (a token refresh). Tools operate on the active session unless the \
                 server was started with --session."
                    .into(),
            ),
            ..Default::default()
        }
    }
}
