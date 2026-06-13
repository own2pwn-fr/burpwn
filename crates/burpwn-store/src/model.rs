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

    /// Parse from the DB string; unknown values map to `RawTcp` to stay lossy-safe.
    pub fn from_db(s: &str) -> Protocol {
        match s {
            "h1" => Protocol::H1,
            "h2" => Protocol::H2,
            "ws" => Protocol::Ws,
            "dns" => Protocol::Dns,
            "tls-passthru" => Protocol::TlsPassthru,
            _ => Protocol::RawTcp,
        }
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
    /// Whether this flow was intercepted (held) by the proxy.
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

/// A group definition (a named collection of flows within a workspace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group id.
    pub id: i64,
    /// Group name.
    pub name: String,
    /// Owning workspace.
    pub workspace_id: i64,
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

    /// Parse from DB string; defaults to `Body` on unknown input.
    pub fn from_db(s: &str) -> MatchKind {
        match s {
            "header" => MatchKind::Header,
            "url" => MatchKind::Url,
            "host" => MatchKind::Host,
            _ => MatchKind::Body,
        }
    }
}

/// State of an intercepted flow held in the intercept queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterceptState {
    /// Waiting for an operator/agent decision.
    Pending,
    /// Released unchanged.
    Forwarded,
    /// Dropped without forwarding.
    Dropped,
    /// Released after edits.
    Modified,
}

impl InterceptState {
    /// DB string.
    pub fn as_str(self) -> &'static str {
        match self {
            InterceptState::Pending => "pending",
            InterceptState::Forwarded => "forwarded",
            InterceptState::Dropped => "dropped",
            InterceptState::Modified => "modified",
        }
    }

    /// Parse from DB string; defaults to `Pending`.
    pub fn from_db(s: &str) -> InterceptState {
        match s {
            "forwarded" => InterceptState::Forwarded,
            "dropped" => InterceptState::Dropped,
            "modified" => InterceptState::Modified,
            _ => InterceptState::Pending,
        }
    }
}

/// A row in the intercept queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intercept {
    /// Intercept id.
    pub id: i64,
    /// Flow being intercepted.
    pub flow_id: i64,
    /// Current state.
    pub state: InterceptState,
    /// When the intercept was created.
    pub created_at: i64,
    /// When it was resolved, if it has been.
    pub resolved_at: Option<i64>,
}

/// Filter for [`crate::Reader::list_flows`]. All fields are optional; `None`
/// means "no constraint on this dimension".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowFilter {
    /// Restrict to a workspace.
    pub workspace_id: Option<i64>,
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
    /// Max rows to return (default 100 if `None`).
    pub limit: Option<i64>,
    /// Row offset for pagination.
    pub offset: Option<i64>,
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
