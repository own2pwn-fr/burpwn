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
    /// When true, return the verbatim request/response head + body bytes as
    /// lossy UTF-8 `raw_request` / `raw_response` INSTEAD of the decoded
    /// `headers`/`body` (which would be the same bytes a second time). The
    /// decoded metadata — method, path, status, timings — comes back either way.
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

/// `session_export` — write the whole session out as one portable file.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct SessionExportParams {
    /// Output path. Defaults to `<session>.burpwn` in the server's working
    /// directory.
    #[serde(default)]
    pub output: Option<String>,
    /// Drop the stored auth tokens, login commands and match/replace
    /// replacements. Credentials captured inside recorded requests/responses
    /// (Authorization / Cookie headers, login bodies) are NOT scrubbed.
    #[serde(default)]
    pub redact: bool,
    /// Overwrite the output file if it already exists.
    #[serde(default)]
    pub force: bool,
}

/// `hook_add` — install a hook on the proxy pipeline.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct HookAddParams {
    /// Name for the hook, for later listings (e.g. `refresh-api-token`).
    pub name: String,
    /// `add-header`, `set-header`, `remove-header`, `set-query-param`, `drop`
    /// or `exec`.
    pub action: String,
    /// `pre-request` (default) or `post-response`.
    #[serde(default)]
    pub phase: Option<String>,
    /// Only hosts containing this (omit for every host).
    #[serde(default)]
    pub host: Option<String>,
    /// Only this request method (omit for any).
    #[serde(default)]
    pub method: Option<String>,
    /// Only request targets containing this (omit for any).
    #[serde(default)]
    pub path: Option<String>,
    /// Only this response status (`post-response` hooks only).
    #[serde(default)]
    pub status: Option<u16>,
    /// `Name: value` for the header actions, or a bare `Name` for
    /// `remove-header`.
    #[serde(default)]
    pub header: Option<String>,
    /// `name=value`, for `set-query-param`.
    #[serde(default)]
    pub param: Option<String>,
    /// The command, for `exec`. Runs as `sh -c` in the sandbox.
    #[serde(default)]
    pub cmd: Option<String>,
    /// Regex with ONE capture group pulling the value out of the command's
    /// stdout, e.g. `"access_token":"([^"]+)"`.
    #[serde(default)]
    pub extract: Option<String>,
    /// Where the extracted value goes: `Name: prefix {}`.
    #[serde(default)]
    pub inject_header: Option<String>,
    /// Where the extracted value goes as a query parameter: `name={}`.
    #[serde(default)]
    pub inject_param: Option<String>,
    /// Application order within the phase (ascending; default 0).
    #[serde(default)]
    pub order: Option<i64>,
    /// Hard budget for an `exec` command in milliseconds (default 10000). On
    /// expiry the hook fails OPEN and the request goes through un-hooked.
    #[serde(default)]
    pub timeout_ms: Option<i64>,
    /// How long an extracted value is reused before the command runs again, in
    /// milliseconds (default 300000). `0` runs the command per request.
    #[serde(default)]
    pub ttl_ms: Option<i64>,
}

/// `hook_set_enabled` — turn a hook on or off without deleting it.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct HookSetEnabledParams {
    /// Hook id from `hook_list`.
    pub id: i64,
    /// `true` to enable, `false` to disable.
    pub enabled: bool,
}

/// `hook_rm` — delete a hook.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct HookRmParams {
    /// Hook id from `hook_list`.
    pub id: i64,
}

/// `hook_test` — replay a hook against a captured flow.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct HookTestParams {
    /// Hook id from `hook_list`.
    pub id: i64,
    /// Captured flow to replay it against.
    pub flow_id: i64,
}

/// `group_new` — create (or re-describe) a named collection of flows.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GroupNewParams {
    /// Group name, unique within the workspace — the handle every other group
    /// tool takes (e.g. `auth-flow`, `xss-fuzz-search-param`).
    pub name: String,
    /// What this collection means, in prose, e.g. "login form → POST /login →
    /// redirect + Set-Cookie session". Omit to keep an existing description.
    #[serde(default)]
    pub description: Option<String>,
    /// Workspace id to create it in (defaults to the session's default
    /// workspace, id 1).
    #[serde(default)]
    pub workspace: Option<i64>,
}

/// `group_add` — put flows into a group.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GroupAddParams {
    /// Name of an existing group.
    pub name: String,
    /// Flow ids to add. Adding a flow twice is a no-op.
    pub flow_ids: Vec<i64>,
}

/// `group_list` — list groups with their descriptions and sizes.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct GroupListParams {
    /// Restrict to a workspace id (omit for every workspace).
    #[serde(default)]
    pub workspace: Option<i64>,
}

/// `group_show` — the flows in one group.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GroupShowParams {
    /// Group name.
    pub name: String,
}

/// `group_rm` — delete a group (the flows survive).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GroupRmParams {
    /// Group name.
    pub name: String,
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
    /// Replacement request method (e.g. `POST`); omit to keep the original.
    /// (Requires an `await_intercept`-parked request — a still-queued intercept
    /// can only be forwarded unchanged.)
    #[serde(default)]
    pub method: Option<String>,
    /// Replacement request path/target; omit to keep the original.
    #[serde(default)]
    pub path: Option<String>,
}

/// `intercept_scope` — narrow (or clear) blocking interception.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct InterceptScopeParams {
    /// Host substring a flow must contain to be intercepted (omit = any).
    #[serde(default)]
    pub host: Option<String>,
    /// Path substring a flow must contain (omit = any).
    #[serde(default)]
    pub path: Option<String>,
    /// Exact request method, case-insensitive (omit = any).
    #[serde(default)]
    pub method: Option<String>,
    /// Clear the scope so every flow is intercepted again (ignores the other
    /// fields).
    #[serde(default)]
    pub clear: bool,
}

/// `session_auth_set` — persist a session-auth profile.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SessionAuthSetParams {
    /// Login command whose output carries a fresh token.
    pub login: String,
    /// Regex with ONE capture group applied to the login output to pull the token.
    pub extract: String,
    /// Header to inject with `{}` where the token goes, e.g. `Authorization: Bearer {}`.
    pub header: String,
    /// Host scope the injection applies to (case-insensitive substring; omit =
    /// all hosts).
    #[serde(default)]
    pub host: Option<String>,
}

/// `session_auth_refresh` — re-mint the token + update the injection rule.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct SessionAuthRefreshParams {
    /// Restrict to the profile for this exact host scope (omit = all profiles).
    #[serde(default)]
    pub host: Option<String>,
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

/// `req_replay` — replay (Repeater) a stored flow, optionally edited.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReqReplayParams {
    /// Flow id to replay.
    pub id: i64,
    /// Headers to set/append before sending (`Name`/`value` pairs).
    #[serde(default)]
    pub set_headers: Vec<HeaderEditParam>,
    /// Replacement request body (UTF-8); omit to keep the original.
    #[serde(default)]
    pub set_body: Option<String>,
    /// Override the request method (e.g. `POST`).
    #[serde(default)]
    pub method: Option<String>,
}

/// `fuzz` — run an Intruder attack against a stored flow.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FuzzParams {
    /// Stored flow supplying the base request + transport target.
    pub flow: i64,
    /// Injection positions as `start:end` byte offsets into the request. When
    /// empty, `§…§` markers in the request bytes delimit the positions.
    #[serde(default)]
    pub positions: Vec<String>,
    /// The payload set (shared across positions per the engine).
    #[serde(default)]
    pub payloads: Vec<String>,
    /// Attack mode: `sniper`, `battering-ram`, `pitchfork`, or `cluster-bomb`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Max in-flight requests (default 8).
    #[serde(default)]
    pub concurrency: Option<usize>,
    /// Pacing delay between launches, in milliseconds.
    #[serde(default)]
    pub delay_ms: Option<u64>,
    /// Custom position marker (defaults to `§`).
    #[serde(default)]
    pub marker: Option<String>,
    /// Attack name.
    #[serde(default)]
    pub name: Option<String>,
}

fn default_mode() -> String {
    "sniper".to_string()
}

/// `fuzz_results` — fetch one attack's per-payload results.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FuzzResultsParams {
    /// Attack id (from `fuzz` / `fuzz_list`).
    pub attack_id: i64,
    /// Sort key: `anomaly` (default), `status`, or `len`.
    #[serde(default)]
    pub sort: Option<String>,
    /// Max rows to return.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `fuzz_list` — list stored attacks.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct FuzzListParams {
    /// Restrict to a workspace by NAME.
    #[serde(default)]
    pub workspace: Option<String>,
}

/// `compare` — structured diff of two flows.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CompareParams {
    /// First flow id.
    pub flow_a: i64,
    /// Second flow id.
    pub flow_b: i64,
    /// What to diff: `headers`, `body`, or `all` (default).
    #[serde(default)]
    pub what: Option<String>,
    /// Max body-diff lines per side. Absent or `0` = 200; a negative value
    /// lifts the cap entirely. When lines are cut, the reply carries
    /// `body.truncated`.
    #[serde(default)]
    pub max_lines: Option<i64>,
}

/// `encode` / `decode` — byte transforms.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct EncodeParams {
    /// Scheme: `base64`, `base64url`, `url`, `hex` (encode+decode) or `jwt`
    /// (decode only).
    pub scheme: String,
    /// The value to transform.
    pub value: String,
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

    #[test]
    fn fuzz_params_defaults_mode() {
        let p: FuzzParams = serde_json::from_str(r#"{"flow":7}"#).unwrap();
        assert_eq!(p.flow, 7);
        assert_eq!(p.mode, "sniper");
        assert!(p.payloads.is_empty());
        let p: FuzzParams = serde_json::from_str(
            r#"{"flow":1,"positions":["3:4"],"payloads":["a","b"],"mode":"cluster-bomb"}"#,
        )
        .unwrap();
        assert_eq!(p.mode, "cluster-bomb");
        assert_eq!(p.positions, vec!["3:4"]);
    }

    #[test]
    fn session_export_params_default_to_a_raw_bundle_next_to_the_agent() {
        let p: SessionExportParams = serde_json::from_str("{}").unwrap();
        assert!(p.output.is_none());
        assert!(!p.redact, "raw by default: fidelity over convenience");
        assert!(!p.force);
        let p: SessionExportParams =
            serde_json::from_str(r#"{"output":"/tmp/x.burpwn","redact":true,"force":true}"#)
                .unwrap();
        assert_eq!(p.output.as_deref(), Some("/tmp/x.burpwn"));
        assert!(p.redact && p.force);
    }

    #[test]
    fn group_params_decode_with_and_without_optionals() {
        let p: GroupNewParams = serde_json::from_str(r#"{"name":"auth-flow"}"#).unwrap();
        assert_eq!(p.name, "auth-flow");
        assert!(p.description.is_none() && p.workspace.is_none());
        let p: GroupNewParams = serde_json::from_str(
            r#"{"name":"auth-flow","description":"login -> POST /login","workspace":2}"#,
        )
        .unwrap();
        assert_eq!(p.description.as_deref(), Some("login -> POST /login"));
        assert_eq!(p.workspace, Some(2));

        let p: GroupAddParams =
            serde_json::from_str(r#"{"name":"auth-flow","flow_ids":[3,5,9]}"#).unwrap();
        assert_eq!(p.flow_ids, vec![3, 5, 9]);

        let p: GroupListParams = serde_json::from_str("{}").unwrap();
        assert!(p.workspace.is_none());
        let p: GroupShowParams = serde_json::from_str(r#"{"name":"g"}"#).unwrap();
        assert_eq!(p.name, "g");
        let p: GroupRmParams = serde_json::from_str(r#"{"name":"g"}"#).unwrap();
        assert_eq!(p.name, "g");
    }

    #[test]
    fn req_replay_and_encode_params_decode() {
        let p: ReqReplayParams = serde_json::from_str(
            r#"{"id":3,"set_headers":[{"name":"X-A","value":"1"}],"method":"POST"}"#,
        )
        .unwrap();
        assert_eq!(p.id, 3);
        assert_eq!(p.method.as_deref(), Some("POST"));
        let p: EncodeParams = serde_json::from_str(r#"{"scheme":"base64","value":"hi"}"#).unwrap();
        assert_eq!(p.scheme, "base64");
        assert_eq!(p.value, "hi");
    }
}
