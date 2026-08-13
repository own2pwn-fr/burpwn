//! Serde-serializable row / detail structs and filter inputs shared across the
//! writer, the reader and (downstream) the CLI JSON output.

use serde::{Deserialize, Serialize};

/// Wire protocol classification for a flow. Matches the `protocol` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/1.x
    H1,
    /// HTTP/2
    H2,
    /// WebSocket
    Ws,
    /// DNS
    Dns,
    /// Raw TCP passthrough.
    RawTcp,
    /// TLS passthrough (not decrypted).
    TlsPassthru,
}

impl Protocol {
    /// String stored in the DB.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::H1 => "h1",
            Protocol::H2 => "h2",
            Protocol::Ws => "ws",
            Protocol::Dns => "dns",
            Protocol::RawTcp => "rawtcp",
            Protocol::TlsPassthru => "tls-passthru",
        }
    }

    /// The accepted spellings, in the order they are shown to a user.
    pub const VALID: [&'static str; 6] = ["h1", "h2", "ws", "dns", "tls-passthru", "rawtcp"];

    /// Parse a user-supplied protocol. `None` means "not one of [`Protocol::VALID`]".
    ///
    /// Callers taking a value from an operator — the `--protocol` filter on the
    /// CLI and over MCP — must surface that `None` as an error. `--protocol h3`
    /// used to fall through to `RawTcp`, so the listing silently answered a
    /// different question than the one that was asked.
    pub fn parse(s: &str) -> Option<Protocol> {
        match s {
            "h1" => Some(Protocol::H1),
            "h2" => Some(Protocol::H2),
            "ws" => Some(Protocol::Ws),
            "dns" => Some(Protocol::Dns),
            "tls-passthru" => Some(Protocol::TlsPassthru),
            "rawtcp" => Some(Protocol::RawTcp),
            _ => None,
        }
    }

    /// Parse a value the proxy itself wrote when it classified a connection.
    ///
    /// Unlike [`MatchKind::from_db`] the fallback here is deliberate and stays:
    /// this is not operator input but our own classification of observed
    /// traffic, and `RawTcp` — "bytes we did not recognise" — is precisely the
    /// right answer for a label a newer burpwn wrote and this one does not know.
    pub fn from_db(s: &str) -> Protocol {
        Protocol::parse(s).unwrap_or(Protocol::RawTcp)
    }
}

/// The mutable parameters for starting a flow row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStart {
    /// Owning workspace (default = 1).
    pub workspace_id: i64,
    /// Start timestamp (unix millis or whatever the proxy uses; opaque to store).
    pub ts_start: i64,
    /// Optional sandbox/exec correlation id.
    pub exec_id: Option<String>,
    /// Client peer address, e.g. `127.0.0.1:54321`.
    pub client_addr: String,
    /// Resolved destination IP.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// TLS SNI if observed.
    pub sni: Option<String>,
    /// URL scheme (`http`/`https`/…).
    pub scheme: String,
    /// Wire protocol.
    pub protocol: Protocol,
    /// Whether this flow was actually PARKED (held) by the proxy — interception
    /// enabled AND the scope filter matching, not the global toggle.
    ///
    /// ⚠️ Only ever `true` on a flow that was held and then RELEASED: a request
    /// the operator drops never reaches `flow_start` (the handler answers 403
    /// and returns), so a dropped intercept leaves no row at all.
    pub intercepted: bool,
}

/// Request payload for a flow. Headers are an order-preserving raw byte blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestData {
    /// HTTP method.
    pub method: String,
    /// `:authority` / Host.
    pub authority: String,
    /// Request target / path.
    pub path: String,
    /// HTTP version string (`HTTP/1.1`, `HTTP/2`, …).
    pub http_version: String,
    /// Raw, ORDER-PRESERVING header bytes (exactly as on the wire). May be empty.
    #[serde(with = "serde_bytes_vec")]
    pub headers: Vec<u8>,
    /// Decoded request body bytes (may be empty).
    #[serde(with = "serde_bytes_vec")]
    pub body: Vec<u8>,
}

/// Response payload for a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseData {
    /// HTTP status code.
    pub status: u16,
    /// HTTP version string.
    pub http_version: String,
    /// Raw, ORDER-PRESERVING header bytes.
    #[serde(with = "serde_bytes_vec")]
    pub headers: Vec<u8>,
    /// Decoded response body bytes.
    #[serde(with = "serde_bytes_vec")]
    pub body: Vec<u8>,
    /// End-to-end response timing in milliseconds, if measured.
    pub timing_ms: Option<i64>,
}

/// A summary row for flow listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRow {
    /// Flow id.
    pub id: i64,
    /// Owning workspace.
    pub workspace_id: i64,
    /// Start timestamp.
    pub ts_start: i64,
    /// End timestamp, if the flow finished.
    pub ts_end: Option<i64>,
    /// Wire protocol.
    pub protocol: Protocol,
    /// Scheme.
    pub scheme: String,
    /// Destination IP.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// SNI if seen.
    pub sni: Option<String>,
    /// Request method (if a request was recorded).
    pub method: Option<String>,
    /// Request authority/host.
    pub authority: Option<String>,
    /// Request path.
    pub path: Option<String>,
    /// Response status code (if a response was recorded).
    pub status: Option<u16>,
    /// Whether the flow was intercepted.
    pub intercepted: bool,
}

/// A fully-joined flow with decoded request + response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDetail {
    /// The summary row.
    pub flow: FlowRow,
    /// Exec correlation id.
    pub exec_id: Option<String>,
    /// Client address.
    pub client_addr: String,
    /// Decoded request, if recorded.
    pub request: Option<RequestData>,
    /// Decoded response, if recorded.
    pub response: Option<ResponseData>,
    /// Names of the tags attached to this flow.
    pub tags: Vec<String>,
    /// Bodies of the notes attached to this flow.
    pub notes: Vec<String>,
}

/// A note attached to a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    /// Note id.
    pub id: i64,
    /// Flow the note is attached to.
    pub flow_id: i64,
    /// Note body.
    pub body: String,
    /// Timestamp.
    pub ts: i64,
}

/// A tag definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    /// Tag id.
    pub id: i64,
    /// Unique tag name.
    pub name: String,
    /// Optional display color.
    pub color: Option<String>,
}

/// A group definition: a named, described collection of flows within a
/// workspace — the "highlight" an agent uses to pin a reconstructed scenario
/// (an auth sequence, one fuzzing campaign) to a handle it can come back to.
/// The name is unique per workspace (schema v5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group id.
    pub id: i64,
    /// Group name (unique within the workspace).
    pub name: String,
    /// What the collection means, in prose — e.g. "login form → POST /login →
    /// redirect + Set-Cookie session".
    pub description: Option<String>,
    /// Owning workspace.
    pub workspace_id: i64,
    /// Creation timestamp (unix millis; 0 for groups predating schema v5).
    pub created_at: i64,
}

/// A workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// Workspace id.
    pub id: i64,
    /// Unique name.
    pub name: String,
    /// Creation timestamp.
    pub created_at: i64,
}

/// A match/replace rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    /// Rule id.
    pub id: i64,
    /// Whether the rule is active.
    pub enabled: bool,
    /// Free-form scope expression (e.g. host glob).
    pub scope: String,
    /// What part of the message the rule matches.
    pub match_kind: MatchKind,
    /// Match pattern.
    pub pattern: String,
    /// Replacement string.
    pub replacement: String,
    /// `true` = applies to requests, `false` = responses.
    pub on_request: bool,
}

/// Parameters to create a match/replace rule (id is generated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMatchReplaceRule {
    /// Whether the rule is active.
    pub enabled: bool,
    /// Scope expression.
    pub scope: String,
    /// What part of the message the rule matches.
    pub match_kind: MatchKind,
    /// Match pattern.
    pub pattern: String,
    /// Replacement string.
    pub replacement: String,
    /// `true` = applies to requests, `false` = responses.
    pub on_request: bool,
}

/// The portion of a message a match/replace rule targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    /// Match against a header.
    Header,
    /// Match against the body.
    Body,
    /// Match against the URL/path.
    Url,
    /// Match against the host.
    Host,
}

impl MatchKind {
    /// DB string.
    pub fn as_str(self) -> &'static str {
        match self {
            MatchKind::Header => "header",
            MatchKind::Body => "body",
            MatchKind::Url => "url",
            MatchKind::Host => "host",
        }
    }

    /// The accepted spellings, in the order they are shown to a user.
    pub const VALID: [&'static str; 4] = ["header", "body", "url", "host"];

    /// Parse a user-supplied kind. `None` means "not one of [`MatchKind::VALID`]".
    ///
    /// Callers on the WRITE path (CLI / MCP) must surface that `None` as an
    /// error: a typo'd `heder` used to fall through to `Body`, so the rule went
    /// in silently rewriting bodies while the operator believed they had a
    /// header rule — the rewrite that never fires is the one you debug longest.
    pub fn parse(s: &str) -> Option<MatchKind> {
        match s {
            "header" => Some(MatchKind::Header),
            "body" => Some(MatchKind::Body),
            "url" => Some(MatchKind::Url),
            "host" => Some(MatchKind::Host),
            _ => None,
        }
    }

    /// Parse from the DB string. An unknown value is an ERROR, never a default —
    /// same contract as [`HookPhase::from_db`]. The reader turns this into a
    /// skipped row + a WARN naming the rule id rather than a failed listing, so
    /// one corrupt row cannot hide every other rule.
    pub fn from_db(s: &str) -> crate::Result<MatchKind> {
        MatchKind::parse(s).ok_or_else(|| crate::StoreError::UnsupportedRow {
            table: "match_replace_rules",
            detail: format!(
                "unknown match_kind {s:?} (expected {})",
                MatchKind::VALID.join("|")
            ),
        })
    }
}

/// Which point of the proxy pipeline a hook fires on.
///
/// Deliberately NOT a `from_db` that falls back on a default: a hook whose
/// stored phase is not understood must be an error, because guessing would run
/// an action on the wrong side of the wire. Same contract as
/// [`MatchKind::from_db`].
///
/// The four non-HTTP phases carry a message that is NOT an HTTP request: a
/// WebSocket frame has no headers and no target, a DNS query has neither. Which
/// actions each phase accepts is therefore not a matter of taste, and is
/// answered once by [`HookAction::allowed_on`] — the write paths (CLI, MCP)
/// refuse the combination up front rather than let it become a silent no-op on
/// the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookPhase {
    /// Before the request is forwarded upstream.
    PreRequest,
    /// After the response headers/body arrive, before they go downstream.
    PostResponse,
    /// On a complete WebSocket message travelling client→server, before it is
    /// relayed to the origin.
    WsC2s,
    /// On a complete WebSocket message travelling server→client, before it is
    /// relayed to the browser.
    WsS2c,
    /// On a DNS query received by the shim, before it is resolved upstream.
    DnsQuery,
}

impl HookPhase {
    /// DB string.
    pub fn as_str(self) -> &'static str {
        match self {
            HookPhase::PreRequest => "pre-request",
            HookPhase::PostResponse => "post-response",
            HookPhase::WsC2s => "ws-c2s",
            HookPhase::WsS2c => "ws-s2c",
            HookPhase::DnsQuery => "dns-query",
        }
    }

    /// Every phase, in the order the surfaces list them.
    pub const ALL: [HookPhase; 5] = [
        HookPhase::PreRequest,
        HookPhase::PostResponse,
        HookPhase::WsC2s,
        HookPhase::WsS2c,
        HookPhase::DnsQuery,
    ];

    /// Whether this phase carries an HTTP message (headers + a target).
    pub fn is_http(self) -> bool {
        matches!(self, HookPhase::PreRequest | HookPhase::PostResponse)
    }

    /// Whether this phase carries a WebSocket message.
    pub fn is_ws(self) -> bool {
        matches!(self, HookPhase::WsC2s | HookPhase::WsS2c)
    }

    /// Parse from the DB string. An unknown value is an ERROR, never a default.
    pub fn from_db(s: &str) -> crate::Result<HookPhase> {
        HookPhase::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| crate::StoreError::UnsupportedRow {
                table: "hooks",
                detail: format!(
                    "unknown phase {s:?} (expected {})",
                    HookPhase::ALL
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            })
    }
}

/// When a hook fires: every non-empty field must match, so an empty [`HookScope`]
/// matches every flow. `host`/`path` are case-insensitive substrings (with the
/// `*.example.com` form accepted for hosts, as in match/replace), `method` is an
/// exact case-insensitive match, `status` an exact response status (meaningful
/// only for [`HookPhase::PostResponse`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookScope {
    /// Host substring (empty = any).
    pub host: String,
    /// Exact request method, case-insensitive (empty = any).
    pub method: String,
    /// Path substring (empty = any).
    pub path: String,
    /// Exact response status (`None` = any).
    pub status: Option<u16>,
}

/// Where the value produced by a [`HookAction::Exec`] is injected. The
/// `value_template` carries the `{}` placeholder the extracted value replaces
/// (the convention `session auth set --header 'Authorization: Bearer {}'` uses,
/// which is the same thing: that façade builds one of these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookInject {
    /// Injection form.
    pub kind: HookInjectKind,
    /// Header or query-parameter name.
    pub name: String,
    /// Value template containing `{}`.
    pub value_template: String,
}

/// The declarative form a [`HookInject`] takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookInjectKind {
    /// Add the header only if the message does not already carry it.
    AddHeader,
    /// Add the header, replacing any existing one of that name.
    SetHeader,
    /// Set a query parameter on the request target.
    SetQueryParam,
}

impl HookInjectKind {
    /// DB / CLI string.
    pub fn as_str(self) -> &'static str {
        match self {
            HookInjectKind::AddHeader => "add-header",
            HookInjectKind::SetHeader => "set-header",
            HookInjectKind::SetQueryParam => "set-query-param",
        }
    }

    /// Parse from a string; unknown values are an error.
    pub fn from_db(s: &str) -> crate::Result<HookInjectKind> {
        match s {
            "add-header" => Ok(HookInjectKind::AddHeader),
            "set-header" => Ok(HookInjectKind::SetHeader),
            "set-query-param" => Ok(HookInjectKind::SetQueryParam),
            other => Err(crate::StoreError::UnsupportedRow {
                table: "hooks",
                detail: format!("unknown inject kind {other:?}"),
            }),
        }
    }
}

/// What a hook DOES to the message it matched.
///
/// All but the last are **declarative**: pure byte edits, no process, no I/O —
/// the only kind that may run on every message without a cost.
/// [`HookAction::Exec`] is the escape hatch: it runs a command in the sandbox,
/// pulls a value out of its stdout with a one-capture-group regex, and injects
/// it declaratively.
///
/// Not every action means something on every [`HookPhase`] — a WebSocket frame
/// has no headers — which [`HookAction::allowed_on`] answers once, for the
/// write paths to refuse on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum HookAction {
    /// Add a header ONLY if the message does not already carry one by that name.
    /// This is the gap match/replace cannot fill: it rewrites what is there, it
    /// cannot synthesize a header a message never sent.
    AddHeader {
        /// Header name.
        name: String,
        /// Header value.
        value: String,
    },
    /// Add the header, replacing any existing one of that name (add-or-replace).
    SetHeader {
        /// Header name.
        name: String,
        /// Header value.
        value: String,
    },
    /// Remove every header line with this name.
    RemoveHeader {
        /// Header name.
        name: String,
    },
    /// Set (or add) a query parameter on the request target. Request side only.
    SetQueryParam {
        /// Parameter name.
        name: String,
        /// Parameter value (percent-encoded on the way in).
        value: String,
    },
    /// Refuse the message: the request is never forwarded / the response never
    /// returned (the client gets a `403` from burpwn), the WebSocket frame is
    /// never relayed, the DNS query is answered `REFUSED` instead of resolved.
    Drop,
    /// Rewrite every occurrence of `find` in a WebSocket message payload.
    ///
    /// The WebSocket phases' equivalent of match/replace, and the only mutation
    /// that makes sense on a frame: there is no header to add and no target to
    /// edit. Deliberately a LITERAL, not a regex: a frame payload is bytes (a
    /// binary message is not text), and a literal search over the payload costs
    /// nothing when it does not match — which matters on a phase that fires per
    /// message on a chatty socket.
    ReplacePayload {
        /// The literal byte sequence to look for.
        find: String,
        /// What replaces it.
        replace: String,
    },
    /// Answer a DNS query with this address instead of resolving it upstream.
    SetAnswer {
        /// The address served for the queried name. Only a query whose type
        /// matches the family (`A` for v4, `AAAA` for v6) is answered; anything
        /// else is forwarded upstream untouched.
        ip: std::net::IpAddr,
    },
    /// Run `cmd` in the sandbox, extract a value from its stdout with `extract`
    /// (one capture group), and inject it per `inject`.
    Exec {
        /// Shell command (run as `sh -c`) in the sandbox, like a login macro.
        cmd: String,
        /// Regex with exactly one capture group, applied to the command stdout.
        extract: String,
        /// How the extracted value reaches the message.
        inject: HookInject,
    },
}

impl HookAction {
    /// The DB `action` column value.
    pub fn kind(&self) -> &'static str {
        match self {
            HookAction::AddHeader { .. } => "add-header",
            HookAction::SetHeader { .. } => "set-header",
            HookAction::RemoveHeader { .. } => "remove-header",
            HookAction::SetQueryParam { .. } => "set-query-param",
            HookAction::Drop => "drop",
            HookAction::ReplacePayload { .. } => "replace-payload",
            HookAction::SetAnswer { .. } => "set-answer",
            HookAction::Exec { .. } => "exec",
        }
    }

    /// Every action kind, for the surfaces that have to list them.
    pub const VALID: [&'static str; 8] = [
        "add-header",
        "set-header",
        "remove-header",
        "set-query-param",
        "drop",
        "replace-payload",
        "set-answer",
        "exec",
    ];

    /// Whether this action can run without spawning anything (see the type doc).
    pub fn is_declarative(&self) -> bool {
        !matches!(self, HookAction::Exec { .. })
    }

    /// Whether this action means anything on `phase`.
    ///
    /// The single source of truth behind `hook add`'s refusal, because the
    /// alternative — accepting the row and discovering on the hot path that
    /// there is no header to add to a WebSocket frame — is exactly the silent
    /// fallback [`MatchKind::from_db`] was fixed to stop doing. The rules:
    ///
    /// - the header/query edits need an HTTP message, and `set-query-param`
    ///   needs a REQUEST target (so it is request-side only);
    /// - `replace-payload` needs a WebSocket payload, `set-answer` a DNS query;
    /// - `exec` is barred from the WebSocket and DNS phases on COST, not on
    ///   meaning: those fire per message on a socket that may carry thousands,
    ///   and one hook command is one sandbox — see [`HookPhase`];
    /// - `drop` is the only action that means the same thing everywhere.
    pub fn allowed_on(&self, phase: HookPhase) -> bool {
        match self {
            HookAction::AddHeader { .. }
            | HookAction::SetHeader { .. }
            | HookAction::RemoveHeader { .. } => phase.is_http(),
            HookAction::SetQueryParam { .. } => phase == HookPhase::PreRequest,
            HookAction::Drop => true,
            HookAction::ReplacePayload { .. } => phase.is_ws(),
            HookAction::SetAnswer { .. } => phase == HookPhase::DnsQuery,
            HookAction::Exec { .. } => phase.is_http(),
        }
    }

    /// The DB `params` column: a JSON object holding the variant's fields (the
    /// variant itself is named by the `action` column).
    pub fn params_json(&self) -> crate::Result<String> {
        let v = match self {
            HookAction::AddHeader { name, value }
            | HookAction::SetHeader { name, value }
            | HookAction::SetQueryParam { name, value } => {
                serde_json::json!({ "name": name, "value": value })
            }
            HookAction::RemoveHeader { name } => serde_json::json!({ "name": name }),
            HookAction::Drop => serde_json::json!({}),
            HookAction::ReplacePayload { find, replace } => {
                serde_json::json!({ "find": find, "replace": replace })
            }
            HookAction::SetAnswer { ip } => serde_json::json!({ "ip": ip.to_string() }),
            HookAction::Exec {
                cmd,
                extract,
                inject,
            } => serde_json::json!({
                "cmd": cmd,
                "extract": extract,
                "inject_kind": inject.kind.as_str(),
                "inject_name": inject.name,
                "inject_value": inject.value_template,
            }),
        };
        Ok(serde_json::to_string(&v)?)
    }

    /// Rebuild an action from its stored `(action, params)` pair. An unknown
    /// kind — or a kind missing one of its parameters — is an ERROR: a hook that
    /// quietly degrades into a different action is a hook nobody configured.
    pub fn from_db(kind: &str, params: &str) -> crate::Result<HookAction> {
        let v: serde_json::Value = serde_json::from_str(params)?;
        let field = |key: &str| -> crate::Result<String> {
            v.get(key)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| crate::StoreError::UnsupportedRow {
                    table: "hooks",
                    detail: format!("action {kind:?} is missing its {key:?} parameter"),
                })
        };
        match kind {
            "add-header" => Ok(HookAction::AddHeader {
                name: field("name")?,
                value: field("value")?,
            }),
            "set-header" => Ok(HookAction::SetHeader {
                name: field("name")?,
                value: field("value")?,
            }),
            "remove-header" => Ok(HookAction::RemoveHeader {
                name: field("name")?,
            }),
            "set-query-param" => Ok(HookAction::SetQueryParam {
                name: field("name")?,
                value: field("value")?,
            }),
            "drop" => Ok(HookAction::Drop),
            "replace-payload" => Ok(HookAction::ReplacePayload {
                find: field("find")?,
                replace: field("replace")?,
            }),
            // A stored address that does not parse is a row this build cannot
            // act on: refusing it is the same contract as an unknown kind, and
            // far better than resolving a name to something arbitrary.
            "set-answer" => {
                let raw = field("ip")?;
                Ok(HookAction::SetAnswer {
                    ip: raw.parse().map_err(|_| crate::StoreError::UnsupportedRow {
                        table: "hooks",
                        detail: format!("action \"set-answer\" has an unparseable ip {raw:?}"),
                    })?,
                })
            }
            "exec" => Ok(HookAction::Exec {
                cmd: field("cmd")?,
                extract: field("extract")?,
                inject: HookInject {
                    kind: HookInjectKind::from_db(&field("inject_kind")?)?,
                    name: field("inject_name")?,
                    value_template: field("inject_value")?,
                },
            }),
            other => Err(crate::StoreError::UnsupportedRow {
                table: "hooks",
                detail: format!("unknown action {other:?}"),
            }),
        }
    }
}

/// A hook: an action applied to every message matching [`HookScope`] on one
/// [`HookPhase`] (schema v6).
///
/// Hooks and match/replace rules coexist and do different jobs: match/replace
/// REWRITES text that is already in the message; a hook can synthesize what is
/// not there (`add-header`), delete it, park the flow behind a command, or drop
/// it outright.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hook {
    /// Hook id.
    pub id: i64,
    /// Whether the hook is active.
    pub enabled: bool,
    /// Operator-facing name (free text; not unique).
    pub name: String,
    /// Which side of the flow it fires on.
    pub phase: HookPhase,
    /// When it fires.
    pub scope: HookScope,
    /// What it does.
    pub action: HookAction,
    /// Application order within a phase, ascending (ties broken by id).
    pub order: i64,
    /// Hard budget for an [`HookAction::Exec`] command, in milliseconds. On
    /// expiry the hook FAILS OPEN: the traffic goes through un-hooked.
    pub timeout_ms: i64,
    /// How long an extracted [`HookAction::Exec`] value is reused before the
    /// command runs again, in milliseconds. `0` = never cache.
    pub ttl_ms: i64,
    /// Creation timestamp (unix millis).
    pub created_at: i64,
}

/// Parameters to create a [`Hook`] (id is generated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewHook {
    /// Whether the hook starts enabled.
    pub enabled: bool,
    /// Operator-facing name.
    pub name: String,
    /// Phase.
    pub phase: HookPhase,
    /// Scope.
    pub scope: HookScope,
    /// Action.
    pub action: HookAction,
    /// Application order.
    pub order: i64,
    /// Exec timeout in milliseconds.
    pub timeout_ms: i64,
    /// Exec value cache TTL in milliseconds.
    pub ttl_ms: i64,
}

// An intercept is a SYNCHRONOUS, in-flight decision: the proxy handler parks on
// a oneshot inside `burpwn_proxy::InterceptController` and unblocks the moment an
// operator forwards, edits or drops. Nothing outlives the flow, so there is no
// `Intercept` row type here (and no `intercepts` table — dropped in schema v7).
// What DID survive is `flows.intercepted`, recorded at flow start.

/// Filter for [`crate::Reader::list_flows`]. All fields are optional; `None`
/// means "no constraint on this dimension".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowFilter {
    /// Restrict to a workspace.
    pub workspace_id: Option<i64>,
    /// Restrict to the flows that are members of this group (by id — resolve a
    /// group NAME through [`crate::Reader::group_by_name`] first).
    pub group_id: Option<i64>,
    /// Substring match against request authority / SNI / dst_ip.
    pub host_contains: Option<String>,
    /// Exact response status.
    pub status: Option<u16>,
    /// Exact request method.
    pub method: Option<String>,
    /// Exact wire protocol.
    pub protocol: Option<Protocol>,
    /// Exact destination port.
    pub port: Option<u16>,
    /// Lower bound (inclusive) on `ts_start`.
    pub ts_from: Option<i64>,
    /// Upper bound (inclusive) on `ts_start`.
    pub ts_to: Option<i64>,
    /// Minimum response body size in bytes (inclusive).
    pub min_resp_len: Option<i64>,
    /// Maximum response body size in bytes (inclusive).
    pub max_resp_len: Option<i64>,
    /// Substring match over the decoded request + response header bytes.
    ///
    /// Matched at the SQL layer against uncompressed header blobs (headers are
    /// almost always well under [`crate::blob::COMPRESS_THRESHOLD`], so they are
    /// stored uncompressed); a compressed header blob is not substring-searchable
    /// here and will not match.
    pub header_contains: Option<String>,
    /// Max rows to return (default 100 if `None`).
    pub limit: Option<i64>,
    /// Row offset for pagination.
    pub offset: Option<i64>,
}

/// Direction of a captured websocket frame relative to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WsDirection {
    /// Client → server.
    C2s,
    /// Server → client.
    S2c,
}

impl WsDirection {
    /// DB string (`c2s` / `s2c`).
    pub fn as_str(self) -> &'static str {
        match self {
            WsDirection::C2s => "c2s",
            WsDirection::S2c => "s2c",
        }
    }

    /// Parse from the DB string; unknown values map to `C2s`.
    pub fn from_db(s: &str) -> WsDirection {
        match s {
            "s2c" => WsDirection::S2c,
            _ => WsDirection::C2s,
        }
    }
}

/// A structured websocket frame captured for a flow. The payload is decoded from
/// the content-addressed blob store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    /// Message id.
    pub id: i64,
    /// Owning flow.
    pub flow_id: i64,
    /// Frame direction.
    pub direction: WsDirection,
    /// Websocket opcode (1=text, 2=binary, …), if recorded.
    pub opcode: Option<i64>,
    /// FIN bit, if recorded.
    pub fin: Option<bool>,
    /// Decoded frame payload bytes.
    #[serde(with = "serde_bytes_vec")]
    pub payload: Vec<u8>,
    /// Capture timestamp, if recorded.
    pub ts: Option<i64>,
}

/// An Intruder/fuzzer attack definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attack {
    /// Attack id.
    pub id: i64,
    /// Owning workspace name.
    pub workspace: Option<String>,
    /// Human-readable name.
    pub name: Option<String>,
    /// Base flow the attack is templated from.
    pub base_flow_id: Option<i64>,
    /// JSON-encoded payload positions.
    pub positions: Option<String>,
    /// JSON-encoded config (mode, payload sets, concurrency).
    pub config: Option<String>,
    /// Lifecycle status (e.g. `pending`, `running`, `done`).
    pub status: Option<String>,
    /// Creation timestamp.
    pub created_ts: Option<i64>,
}

/// Parameters to create an [`Attack`] (id is generated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAttack {
    /// Owning workspace name.
    pub workspace: String,
    /// Human-readable name.
    pub name: String,
    /// Base flow the attack is templated from.
    pub base_flow_id: Option<i64>,
    /// JSON-encoded payload positions.
    pub positions: String,
    /// JSON-encoded config.
    pub config: String,
    /// Initial lifecycle status.
    pub status: String,
    /// Creation timestamp.
    pub created_ts: i64,
}

/// A single per-payload result row for an attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Result id.
    pub id: i64,
    /// Owning attack.
    pub attack_id: i64,
    /// JSON-encoded payload that produced this result.
    pub payload: Option<String>,
    /// Captured flow for this request, if recorded.
    pub flow_id: Option<i64>,
    /// Response status code.
    pub status_code: Option<i64>,
    /// Response length in bytes.
    pub resp_len: Option<i64>,
    /// Request latency in milliseconds.
    pub latency_ms: Option<i64>,
    /// Heuristic anomaly score.
    pub anomaly_score: Option<f64>,
    /// Timestamp.
    pub ts: Option<i64>,
}

/// Parameters to insert an [`AttackResult`] (id is generated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAttackResult {
    /// Owning attack.
    pub attack_id: i64,
    /// JSON-encoded payload.
    pub payload: String,
    /// Captured flow for this request, if any.
    pub flow_id: Option<i64>,
    /// Response status code.
    pub status_code: Option<i64>,
    /// Response length in bytes.
    pub resp_len: Option<i64>,
    /// Request latency in milliseconds.
    pub latency_ms: Option<i64>,
    /// Heuristic anomaly score.
    pub anomaly_score: Option<f64>,
    /// Timestamp.
    pub ts: i64,
}

// A session-auth profile used to be a row type here (schema v4..v7): a login
// command, an extract regex, a header template, the last-minted token and the id
// of the match/replace rule injecting it. Schema v8 rewrote every one of them
// into a `pre-request` / `exec` [`Hook`], because that is the same thing minus
// the hole — a hook can ADD the header a request never sent — and dropped the
// table. `session auth` is now a façade that reads and writes those hooks, so
// there is one storage and one code path; the token is no longer persisted at
// all (the daemon caches it for the hook's TTL).

/// A capture-completeness telemetry row (schema v4): one per `burpwn exec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRecord {
    /// Row id.
    pub id: i64,
    /// The exec correlation id stamped on this run's captured flows.
    pub exec_id: String,
    /// The command line (best-effort, for display).
    pub cmd: String,
    /// Whether the command was classified as clearly network-facing.
    pub network_facing: bool,
    /// Number of flows captured during this exec.
    pub flow_count: i64,
    /// Creation timestamp (unix millis).
    pub created_at: i64,
}

/// Parameters to insert an [`ExecRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewExecRecord {
    /// Exec correlation id.
    pub exec_id: String,
    /// Command line.
    pub cmd: String,
    /// Network-facing classification.
    pub network_facing: bool,
    /// Captured flow count.
    pub flow_count: i64,
    /// Creation timestamp.
    pub created_at: i64,
}

/// Aggregate capture-completeness stats over a session's execs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecStats {
    /// Total recorded execs.
    pub total_execs: i64,
    /// Total flows captured across all execs.
    pub total_flows: i64,
    /// Execs classified as network-facing.
    pub network_execs: i64,
    /// Network-facing execs that captured ZERO flows (likely-escaped traffic).
    pub network_zero_flow_execs: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_action_round_trips_through_the_db_columns() {
        for action in [
            HookAction::AddHeader {
                name: "User-Agent".into(),
                value: "burpwn".into(),
            },
            HookAction::SetHeader {
                name: "X-Env".into(),
                value: "staging".into(),
            },
            HookAction::RemoveHeader {
                name: "Cookie".into(),
            },
            HookAction::SetQueryParam {
                name: "debug".into(),
                value: "1".into(),
            },
            HookAction::Drop,
            HookAction::ReplacePayload {
                find: "\"role\":\"user\"".into(),
                replace: "\"role\":\"admin\"".into(),
            },
            HookAction::SetAnswer {
                ip: "127.0.0.1".parse().unwrap(),
            },
            HookAction::SetAnswer {
                ip: "::1".parse().unwrap(),
            },
            HookAction::Exec {
                cmd: "get-token.sh".into(),
                extract: r#""token":"([^"]+)""#.into(),
                inject: HookInject {
                    kind: HookInjectKind::SetHeader,
                    name: "Authorization".into(),
                    value_template: "Bearer {}".into(),
                },
            },
        ] {
            let params = action.params_json().unwrap();
            let back = HookAction::from_db(action.kind(), &params).unwrap();
            assert_eq!(back, action);
        }
    }

    // A row this build cannot understand must be refused, not coerced onto some
    // default action.
    #[test]
    fn unknown_hook_action_or_phase_is_an_error_not_a_default() {
        let err = HookAction::from_db("teleport", "{}").unwrap_err();
        assert!(matches!(err, crate::StoreError::UnsupportedRow { .. }));
        // A known kind with a missing parameter is equally refused.
        assert!(HookAction::from_db("add-header", r#"{"name":"X"}"#).is_err());
        assert!(HookPhase::from_db("mid-flight").is_err());
        assert_eq!(
            HookPhase::from_db("post-response").unwrap(),
            HookPhase::PostResponse
        );
        // An address a newer burpwn could store but this one cannot parse is a
        // refusal too — resolving a name to "whatever parses" is not an option.
        assert!(HookAction::from_db("set-answer", r#"{"ip":"nowhere"}"#).is_err());
        assert!(HookAction::from_db("replace-payload", r#"{"find":"a"}"#).is_err());
    }

    /// Every phase round-trips through the DB string, and the string is the one
    /// the CLI/MCP surfaces spell.
    #[test]
    fn every_hook_phase_round_trips_through_its_db_string() {
        for phase in HookPhase::ALL {
            assert_eq!(HookPhase::from_db(phase.as_str()).unwrap(), phase);
        }
        assert_eq!(HookPhase::WsC2s.as_str(), "ws-c2s");
        assert_eq!(HookPhase::WsS2c.as_str(), "ws-s2c");
        assert_eq!(HookPhase::DnsQuery.as_str(), "dns-query");
        assert!(HookPhase::WsC2s.is_ws() && !HookPhase::WsC2s.is_http());
        assert!(!HookPhase::DnsQuery.is_ws() && !HookPhase::DnsQuery.is_http());
    }

    /// The pairing table. An action that means nothing on a phase must be a
    /// refusal at `hook add` time, so this is the fact the CLI and MCP both ask.
    #[test]
    fn an_action_is_only_allowed_on_the_phases_it_means_something_on() {
        let add_header = HookAction::AddHeader {
            name: "X".into(),
            value: "1".into(),
        };
        let replace = HookAction::ReplacePayload {
            find: "a".into(),
            replace: "b".into(),
        };
        let answer = HookAction::SetAnswer {
            ip: "127.0.0.1".parse().unwrap(),
        };
        let exec = HookAction::Exec {
            cmd: "x".into(),
            extract: "(.)".into(),
            inject: HookInject {
                kind: HookInjectKind::SetHeader,
                name: "A".into(),
                value_template: "{}".into(),
            },
        };
        let param = HookAction::SetQueryParam {
            name: "a".into(),
            value: "1".into(),
        };
        for phase in HookPhase::ALL {
            // There is no header on a frame or a query, and no sandbox command
            // on a per-message phase.
            assert_eq!(add_header.allowed_on(phase), phase.is_http());
            assert_eq!(exec.allowed_on(phase), phase.is_http());
            assert_eq!(replace.allowed_on(phase), phase.is_ws());
            assert_eq!(answer.allowed_on(phase), phase == HookPhase::DnsQuery);
            assert_eq!(param.allowed_on(phase), phase == HookPhase::PreRequest);
            // Refusing a message is the one thing every phase can do.
            assert!(HookAction::Drop.allowed_on(phase));
        }
    }

    // `heder` must not become a body rule. Every accepted spelling round-trips,
    // and anything else is an error on both the parse and the DB path.
    #[test]
    fn unknown_match_kind_is_an_error_not_body() {
        for kind in [
            MatchKind::Header,
            MatchKind::Body,
            MatchKind::Url,
            MatchKind::Host,
        ] {
            assert_eq!(MatchKind::parse(kind.as_str()), Some(kind));
            assert_eq!(MatchKind::from_db(kind.as_str()).unwrap(), kind);
            assert!(MatchKind::VALID.contains(&kind.as_str()));
        }
        assert_eq!(MatchKind::parse("heder"), None);
        assert_eq!(MatchKind::parse("HEADER"), None);
        assert_eq!(MatchKind::parse(""), None);
        let err = MatchKind::from_db("heder").unwrap_err();
        assert!(matches!(err, crate::StoreError::UnsupportedRow { .. }));
        // The message must name the accepted set: the operator has to know what
        // to type next.
        let msg = err.to_string();
        for v in MatchKind::VALID {
            assert!(msg.contains(v), "{msg} should list {v}");
        }
    }

    // `Protocol` carries the same fallback `MatchKind` just lost, but only one of
    // its two callers should have it: classifying a label the proxy wrote is not
    // the same act as accepting a value a human typed.
    #[test]
    fn unknown_protocol_is_rejected_on_the_input_path_and_absorbed_on_the_db_path() {
        for p in [
            Protocol::H1,
            Protocol::H2,
            Protocol::Ws,
            Protocol::Dns,
            Protocol::TlsPassthru,
            Protocol::RawTcp,
        ] {
            assert_eq!(Protocol::parse(p.as_str()), Some(p));
            assert_eq!(Protocol::from_db(p.as_str()), p);
            assert!(Protocol::VALID.contains(&p.as_str()));
        }
        // Operator input: a typo, a protocol we do not speak, and a spelling
        // that differs only in case must all be refusable by the caller.
        assert_eq!(Protocol::parse("h3"), None);
        assert_eq!(Protocol::parse("raw-tcp"), None);
        assert_eq!(Protocol::parse("H1"), None);
        assert_eq!(Protocol::parse(""), None);
        // Stored classification: a label written by a newer burpwn must not make
        // an older one fail to list the flow. "bytes we did not recognise" is
        // the honest reading of a protocol name we do not know.
        assert_eq!(Protocol::from_db("h3"), Protocol::RawTcp);
        assert_eq!(Protocol::from_db(""), Protocol::RawTcp);
    }
}

/// `serde_bytes`-style helper for `Vec<u8>` so JSON output is reasonable and
/// binary survives round-trips (encoded as an array of byte ints by serde_json,
/// but kept compact in bincode-like formats). Kept local to avoid a new dep.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        // Accept either a byte buf or a seq of u8 (serde_json emits the latter).
        let v: Vec<u8> = Deserialize::deserialize(d)?;
        Ok(v)
    }
}
