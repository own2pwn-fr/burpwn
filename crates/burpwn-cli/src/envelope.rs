//! The uniform JSON output envelope used by every command in `--json` mode.
//!
//! Shape: `{ "ok": bool, "data": <value>, "error": <string|null> }`. On success
//! `error` is `null` and `data` carries the command payload; on failure `ok` is
//! `false`, `data` is `null` and `error` carries a human-readable message. This
//! is the stable machine contract the MCP server and any scripting layer parse.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A serializable result envelope. Generic over the success payload only for
/// construction convenience; it always serializes to the three-field shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Whether the command succeeded.
    pub ok: bool,
    /// The success payload (`null` on error).
    pub data: Value,
    /// The error message (`null` on success).
    pub error: Option<String>,
}

impl Envelope {
    /// A success envelope carrying `data`.
    pub fn ok(data: Value) -> Self {
        Self {
            ok: true,
            data,
            error: None,
        }
    }

    /// A success envelope with `data: null` (for "did the thing" commands).
    pub fn ok_empty() -> Self {
        Self::ok(Value::Null)
    }

    /// An error envelope carrying `msg`.
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: Value::Null,
            error: Some(msg.into()),
        }
    }

    /// Serialize to a single-line JSON string (no trailing newline).
    pub fn to_json_line(&self) -> String {
        // Serialization of this fixed struct cannot fail.
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"ok":false,"data":null,"error":"envelope serialization failed"}"#.to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ok_envelope_shape() {
        let e = Envelope::ok(json!({"id": 7}));
        let v: Value = serde_json::from_str(&e.to_json_line()).unwrap();
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["data"]["id"], json!(7));
        assert_eq!(v["error"], Value::Null);
    }

    #[test]
    fn err_envelope_shape() {
        let e = Envelope::err("boom");
        let v: Value = serde_json::from_str(&e.to_json_line()).unwrap();
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["data"], Value::Null);
        assert_eq!(v["error"], json!("boom"));
    }

    #[test]
    fn empty_ok_has_null_data() {
        let e = Envelope::ok_empty();
        assert!(e.ok);
        assert_eq!(e.data, Value::Null);
        assert!(e.error.is_none());
    }

    #[test]
    fn roundtrips_through_serde() {
        let e = Envelope::ok(json!([1, 2, 3]));
        let s = e.to_json_line();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }
}
