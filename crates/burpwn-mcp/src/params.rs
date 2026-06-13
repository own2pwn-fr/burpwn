//! Typed parameter structs for every MCP tool.
//!
//! Each derives [`serde::Deserialize`] (so rmcp can decode the JSON arguments)
//! and [`schemars::JsonSchema`] (so rmcp can advertise the tool's input schema
//! to the client). They are deliberately plain data — all behaviour lives in
//! [`crate::handlers`], which keeps the tools unit-testable without a transport.

use schemars::JsonSchema;
use serde::Deserialize;

/// `req_list` — list captured flows with optional filters.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct ReqListParams {
    /// Substring match against request authority / SNI / destination IP.
    #[serde(default)]
    pub host: Option<String>,
    /// Exact HTTP response status code.
    #[serde(default)]
    pub status: Option<u16>,
    /// Exact HTTP request method (`GET`, `POST`, …).
    #[serde(default)]
    pub method: Option<String>,
    /// Wire protocol filter (`h1`, `h2`, `ws`, `dns`, `rawtcp`, `tls-passthru`).
    #[serde(default)]
    pub protocol: Option<String>,
    /// Exact destination port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Restrict to a workspace id.
    #[serde(default)]
    pub workspace: Option<i64>,
    /// Max rows to return (default 100).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Row offset for pagination.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// `req_show` — fetch one flow's decoded detail.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReqShowParams {
    /// Flow id to fetch.
    pub id: i64,
    /// When true, include the verbatim request/response head + body bytes as
    /// lossy UTF-8 `raw_request` / `raw_response` fields in addition to the
    /// decoded view.
    #[serde(default)]
    pub raw: bool,
}

/// `req_search` — full-text search over indexed request/response text.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReqSearchParams {
    /// FTS5 query string.
    pub query: String,
}

/// `match_replace_add` — create a match/replace rule.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MatchReplaceAddParams {
    /// Free-form scope expression (e.g. a host glob); empty = all.
    pub scope: String,
    /// What part of the message to match: `header`, `body`, `url`, or `host`.
    pub kind: String,
    /// Match pattern.
    pub pattern: String,
    /// Replacement string.
    pub replacement: String,
    /// `true` = rule applies to requests, `false` = responses.
    pub on_request: bool,
}

/// `tag_add` — create/attach a tag to a flow.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct TagAddParams {
    /// Flow id to tag.
    pub flow_id: i64,
    /// Tag name (created if absent).
    pub name: String,
    /// Optional display colour.
    #[serde(default)]
    pub color: Option<String>,
}

/// `note_add` — attach a note to a flow.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct NoteAddParams {
    /// Flow id to annotate.
    pub flow_id: i64,
    /// Note body.
    pub body: String,
}

/// `workspace_new` — create a workspace.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct WorkspaceNewParams {
    /// Unique workspace name.
    pub name: String,
}

/// `await_intercept` — long-poll for the next parked intercept.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct AwaitInterceptParams {
    /// How long to block waiting for a parked request before returning
    /// `{ "pending": false }`. Defaults to the server-side default
    /// ([`crate::DEFAULT_AWAIT_SECS`]) when omitted.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// A single header edit applied when forwarding an intercept.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct HeaderEditParam {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// `intercept_forward` — release a parked intercept, optionally edited.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct InterceptForwardParams {
    /// Parked intercept id (from `intercept_list` / `await_intercept`).
    pub id: u64,
    /// Headers to set/append before forwarding.
    #[serde(default)]
    pub set_headers: Vec<HeaderEditParam>,
    /// Replacement body (UTF-8); omit to keep the original.
    #[serde(default)]
    pub set_body: Option<String>,
}

/// `intercept_drop` — drop a parked intercept by id.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct InterceptDropParams {
    /// Parked intercept id.
    pub id: u64,
}

/// `exec` — run a command in the burpwn sandbox.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExecParams {
    /// The command + arguments, e.g. `["curl", "https://example.com"]`.
    pub argv: Vec<String>,
    /// Workspace NAME to attribute this exec's captured flows to. Forwarded to
    /// the CLI's `exec --workspace <name>`, which resolves the named workspace,
    /// creating it if it does not yet exist. Omit to use the session default.
    #[serde(default)]
    pub workspace: Option<String>,
    /// Wall-clock timeout in seconds for the child command.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_list_params_default_and_partial_decode() {
        let p: ReqListParams = serde_json::from_str("{}").unwrap();
        assert!(p.host.is_none() && p.limit.is_none());
        let p: ReqListParams =
            serde_json::from_str(r#"{"host":"example","status":200,"limit":10}"#).unwrap();
        assert_eq!(p.host.as_deref(), Some("example"));
        assert_eq!(p.status, Some(200));
        assert_eq!(p.limit, Some(10));
    }

    #[test]
    fn req_show_raw_defaults_false() {
        let p: ReqShowParams = serde_json::from_str(r#"{"id":7}"#).unwrap();
        assert_eq!(p.id, 7);
        assert!(!p.raw);
    }

    #[test]
    fn match_replace_add_decodes() {
        let p: MatchReplaceAddParams = serde_json::from_str(
            r#"{"scope":"*.example.com","kind":"header","pattern":"a","replacement":"b","on_request":true}"#,
        )
        .unwrap();
        assert_eq!(p.kind, "header");
        assert!(p.on_request);
    }

    #[test]
    fn intercept_forward_decodes_edits() {
        let p: InterceptForwardParams = serde_json::from_str(
            r#"{"id":3,"set_headers":[{"name":"X-A","value":"1"}],"set_body":"hi"}"#,
        )
        .unwrap();
        assert_eq!(p.id, 3);
        assert_eq!(p.set_headers.len(), 1);
        assert_eq!(p.set_body.as_deref(), Some("hi"));
    }

    #[test]
    fn await_intercept_optional_timeout() {
        let p: AwaitInterceptParams = serde_json::from_str("{}").unwrap();
        assert!(p.timeout_secs.is_none());
        let p: AwaitInterceptParams = serde_json::from_str(r#"{"timeout_secs":5}"#).unwrap();
        assert_eq!(p.timeout_secs, Some(5));
    }

    #[test]
    fn exec_params_decode() {
        let p: ExecParams =
            serde_json::from_str(r#"{"argv":["curl","https://x"],"timeout_secs":9}"#).unwrap();
        assert_eq!(p.argv, vec!["curl", "https://x"]);
        assert_eq!(p.timeout_secs, Some(9));
    }
}
