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

/// Map an `anyhow::Error` from a handler into an MCP tool error.
fn to_mcp_err(e: anyhow::Error) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

#[tool_router]
impl BurpwnServer {
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
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Show the active session and whether its database exists.")]
    async fn session_current(&self) -> Result<CallToolResult, McpError> {
        handlers::session_current(self.paths())
            .map_err(to_mcp_err)
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
            .map_err(to_mcp_err)
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
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Full-text search over captured request/response text; returns flow ids.")]
    async fn req_search(
        &self,
        Parameters(params): Parameters<ReqSearchParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::req_search(self.paths(), self.session(), &params)
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "List workspaces in the active session.")]
    async fn workspace_list(&self) -> Result<CallToolResult, McpError> {
        handlers::workspace_list(self.paths(), self.session())
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "List tags in the active session.")]
    async fn tag_list(&self) -> Result<CallToolResult, McpError> {
        handlers::tag_list(self.paths(), self.session())
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "List match/replace rules in the active session.")]
    async fn match_replace_list(&self) -> Result<CallToolResult, McpError> {
        handlers::match_replace_list(self.paths(), self.session())
            .map_err(to_mcp_err)
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
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Create/attach a tag to a flow.")]
    async fn tag_add(
        &self,
        Parameters(params): Parameters<TagAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::tag_add(self.paths(), self.session(), &params)
            .await
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Attach a note to a flow.")]
    async fn note_add(
        &self,
        Parameters(params): Parameters<NoteAddParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::note_add(self.paths(), self.session(), &params)
            .await
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Create a new workspace.")]
    async fn workspace_new(
        &self,
        Parameters(params): Parameters<WorkspaceNewParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::workspace_new(self.paths(), self.session(), &params)
            .await
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    // --- daemon / intercept ----------------------------------------------

    #[tool(description = "Enable request interception on the running proxy daemon.")]
    async fn intercept_enable(&self) -> Result<CallToolResult, McpError> {
        handlers::intercept_enable(self.paths(), self.session())
            .await
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Disable request interception on the running proxy daemon.")]
    async fn intercept_disable(&self) -> Result<CallToolResult, McpError> {
        handlers::intercept_disable(self.paths(), self.session())
            .await
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "List currently parked (held) intercepts on the daemon.")]
    async fn intercept_list(&self) -> Result<CallToolResult, McpError> {
        handlers::intercept_list(self.paths(), self.session())
            .await
            .map_err(to_mcp_err)
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
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(
        description = "Forward (release) a parked intercept by id, optionally setting headers and/or replacing the body."
    )]
    async fn intercept_forward(
        &self,
        Parameters(params): Parameters<InterceptForwardParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::intercept_forward(self.paths(), self.session(), &params)
            .await
            .map_err(to_mcp_err)
            .and_then(ok_json)
    }

    #[tool(description = "Drop a parked intercept by id (do not forward it).")]
    async fn intercept_drop(
        &self,
        Parameters(params): Parameters<InterceptDropParams>,
    ) -> Result<CallToolResult, McpError> {
        handlers::intercept_drop(self.paths(), self.session(), &params)
            .await
            .map_err(to_mcp_err)
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
            .map_err(to_mcp_err)
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
                 Tools operate on the active session unless the server was started \
                 with --session."
                    .into(),
            ),
            ..Default::default()
        }
    }
}
