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
    ///
    /// Kept as a plain string for backwards compatibility with everything that
    /// already parses this envelope; since codes were introduced it carries the
    /// [`Diagnostic::one_line`] form (`[BW-INPUT-002] no such flow 7: …`), so an
    /// old consumer that only prints this field still shows the code.
    pub error: Option<String>,
    /// The structured diagnostic: code, class, causes, remediation, exit code,
    /// and the path of the debug report. `null` on success and for errors
    /// raised before classification (there are none on the normal path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Value>,
}

impl Envelope {
    /// A success envelope carrying `data`.
    pub fn ok(data: Value) -> Self {
        Self {
            ok: true,
            data,
            error: None,
            diagnostic: None,
        }
    }

    /// A success envelope with `data: null` (for "did the thing" commands).
    pub fn ok_empty() -> Self {
        Self::ok(Value::Null)
    }

    /// An error envelope carrying `msg` and no structured diagnostic.
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: Value::Null,
            error: Some(msg.into()),
            diagnostic: None,
        }
    }

    /// An error envelope built from a classified failure: the legacy `error`
    /// string plus the full structured `diagnostic`.
    pub fn diagnostic(diag: &burpwn_error::Diagnostic) -> Self {
        Self {
            ok: false,
            data: Value::Null,
            error: Some(diag.one_line()),
            diagnostic: Some(diag.to_json()),
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

    // Old consumers only read `error`. They must still see the code, or the
    // whole point of having codes is lost for anything already integrated.
    #[test]
    fn diagnostic_envelope_keeps_the_legacy_error_string() {
        use burpwn_error::{Diagnostic, ErrorCode};
        let d = Diagnostic::new(ErrorCode::InputNoSuchFlow, "no such flow 7").cause("db said no");
        let e = Envelope::diagnostic(&d);
        let v: Value = serde_json::from_str(&e.to_json_line()).unwrap();
        assert_eq!(v["ok"], json!(false));
        let msg = v["error"].as_str().unwrap();
        assert!(msg.starts_with("[BW-INPUT-002] no such flow 7"), "{msg}");
        assert_eq!(v["diagnostic"]["code"], json!("BW-INPUT-002"));
        assert_eq!(v["diagnostic"]["exit_code"], json!(75));
        assert!(!v["diagnostic"]["remediation"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    // The new field must not appear on success, so existing golden outputs and
    // schema expectations for successful commands are untouched.
    #[test]
    fn success_envelopes_have_no_diagnostic_field() {
        let s = Envelope::ok(json!({"id": 1})).to_json_line();
        assert!(!s.contains("diagnostic"), "{s}");
    }

    #[test]
    fn roundtrips_through_serde() {
        let e = Envelope::ok(json!([1, 2, 3]));
        let s = e.to_json_line();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }
}
