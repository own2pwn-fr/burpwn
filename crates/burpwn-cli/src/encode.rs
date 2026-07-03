//! Pure encode/decode utilities for the `encode` / `decode` commands (and the
//! matching MCP tools). No network, no store — just byte transforms an agent
//! uses to manipulate tokens and parameters.
//!
//! Schemes:
//! - `base64` — standard alphabet (`+/`, `=` padding); decode also accepts the
//!   URL-safe alphabet (`-_`) and missing padding.
//! - `base64url` — URL-safe alphabet, no padding (encode); decode as base64.
//! - `url` — percent-encoding (encode escapes everything but the RFC-3986
//!   unreserved set; decode resolves `%XX`).
//! - `hex` — lowercase hex (decode accepts either case, ignores whitespace).
//! - `jwt` — DECODE ONLY: split `header.payload.signature`, base64url-decode the
//!   header + payload to pretty JSON, expose `alg` and the claims. The signature
//!   is NOT verified (this is a decoder, not a validator).

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

/// Encode `value` using `scheme`. Returns the encoded string.
pub fn encode(scheme: &str, value: &str) -> Result<Value> {
    let bytes = value.as_bytes();
    let encoded = match scheme.to_ascii_lowercase().as_str() {
        "base64" | "b64" => base64_encode(bytes, STD_ALPHABET, true),
        "base64url" | "b64url" | "base64-url" => base64_encode(bytes, URL_ALPHABET, false),
        "url" | "urlencode" | "percent" => url_encode(bytes),
        "hex" => hex_encode(bytes),
        "jwt" => bail!("jwt is decode-only (a JWT is signed; use decode jwt)"),
        other => bail!("unknown encode scheme {other:?} (base64|base64url|url|hex)"),
    };
    Ok(json!({ "scheme": scheme, "encoded": encoded }))
}

/// Decode `value` using `scheme`. Returns a JSON object with the decoded result;
/// for `jwt` it returns the structured header/claims.
pub fn decode(scheme: &str, value: &str) -> Result<Value> {
    match scheme.to_ascii_lowercase().as_str() {
        "base64" | "b64" | "base64url" | "b64url" | "base64-url" => {
            let bytes = base64_decode(value)?;
            Ok(json!({
                "scheme": scheme,
                "decoded": String::from_utf8_lossy(&bytes),
                "bytes": bytes.len(),
            }))
        }
        "url" | "urlencode" | "percent" => {
            let bytes = url_decode(value)?;
            Ok(json!({
                "scheme": scheme,
                "decoded": String::from_utf8_lossy(&bytes),
            }))
        }
        "hex" => {
            let bytes = hex_decode(value)?;
            Ok(json!({
                "scheme": scheme,
                "decoded": String::from_utf8_lossy(&bytes),
                "bytes": bytes.len(),
            }))
        }
        "jwt" => jwt_decode(value),
        other => bail!("unknown decode scheme {other:?} (base64|base64url|url|hex|jwt)"),
    }
}

// --- base64 ----------------------------------------------------------------

const STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64-encode `data` with `alphabet`, optionally appending `=` padding.
fn base64_encode(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(alphabet[((n >> 6) & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[(n & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// Base64-decode, accepting both the standard (`+/`) and URL-safe (`-_`)
/// alphabets, with or without `=` padding. Whitespace is ignored.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for c in input.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            c if c.is_whitespace() => continue,
            other => bail!("invalid base64 character {other:?}"),
        };
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

// --- hex -------------------------------------------------------------------

/// Lowercase hex encode.
fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// Hex decode, ignoring whitespace, accepting either case. Errors on odd length
/// or a non-hex character.
fn hex_decode(input: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() % 2 != 0 {
        bail!("hex input has an odd number of digits");
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for pair in clean.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex digit {:?}", pair[0] as char))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex digit {:?}", pair[1] as char))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

// --- url (percent) ---------------------------------------------------------

/// Percent-encode everything outside the RFC-3986 unreserved set
/// (`A-Za-z0-9-._~`).
fn url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Resolve `%XX` escapes (and `+` → space, the form-encoding convention).
fn url_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    bail!("truncated percent-escape at offset {i}");
                }
                let hi = (bytes[i + 1] as char)
                    .to_digit(16)
                    .ok_or_else(|| anyhow!("invalid percent-escape"))?;
                let lo = (bytes[i + 2] as char)
                    .to_digit(16)
                    .ok_or_else(|| anyhow!("invalid percent-escape"))?;
                out.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

// --- jwt -------------------------------------------------------------------

/// Decode a JWT `header.payload.signature` without verifying the signature.
fn jwt_decode(token: &str) -> Result<Value> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        bail!("not a JWT: expected 3 dot-separated segments, got {}", parts.len());
    }
    let header_bytes = base64_decode(parts[0])?;
    let payload_bytes = base64_decode(parts[1])?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| anyhow!("JWT header is not valid JSON: {e}"))?;
    let claims: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("JWT payload is not valid JSON: {e}"))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    Ok(json!({
        "scheme": "jwt",
        "alg": alg,
        "header": header,
        "claims": claims,
        "signature": parts[2],
        "verified": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_std_and_url() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "hi?>/=+&"] {
            let enc = encode("base64", s).unwrap();
            let e = enc["encoded"].as_str().unwrap();
            let dec = decode("base64", e).unwrap();
            assert_eq!(dec["decoded"], s, "std round-trip for {s:?}");
        }
        // URL-safe alphabet, no padding on encode, decodes back.
        let enc = encode("base64url", "<<<???>>>").unwrap();
        let e = enc["encoded"].as_str().unwrap();
        assert!(!e.contains('='), "base64url must not pad: {e}");
        let dec = decode("base64url", e).unwrap();
        assert_eq!(dec["decoded"], "<<<???>>>");
    }

    #[test]
    fn base64_known_vector() {
        assert_eq!(encode("base64", "foobar").unwrap()["encoded"], "Zm9vYmFy");
        assert_eq!(encode("base64", "foo").unwrap()["encoded"], "Zm9v");
        assert_eq!(encode("base64", "foo!").unwrap()["encoded"], "Zm9vIQ==");
    }

    #[test]
    fn hex_round_trip_and_vector() {
        assert_eq!(encode("hex", "AB").unwrap()["encoded"], "4142");
        let dec = decode("hex", "4142").unwrap();
        assert_eq!(dec["decoded"], "AB");
        // whitespace tolerated, case-insensitive
        assert_eq!(decode("hex", "de ad BE ef").unwrap()["bytes"], 4);
        assert!(decode("hex", "abc").is_err());
    }

    #[test]
    fn url_round_trip() {
        let enc = encode("url", "a b&c=d/e?f").unwrap();
        let e = enc["encoded"].as_str().unwrap();
        assert_eq!(e, "a%20b%26c%3Dd%2Fe%3Ff");
        let dec = decode("url", e).unwrap();
        assert_eq!(dec["decoded"], "a b&c=d/e?f");
        // `+` decodes to space (form convention).
        assert_eq!(decode("url", "a+b").unwrap()["decoded"], "a b");
    }

    #[test]
    fn jwt_decode_exposes_alg_and_claims() {
        // {"alg":"HS256","typ":"JWT"} . {"sub":"1234567890","name":"burpwn","admin":true} . sig
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImJ1cnB3biIsImFkbWluIjp0cnVlfQ.\
                     c2lnbmF0dXJl";
        let v = decode("jwt", token).unwrap();
        assert_eq!(v["alg"], "HS256");
        assert_eq!(v["claims"]["sub"], "1234567890");
        assert_eq!(v["claims"]["admin"], true);
        assert_eq!(v["verified"], false);
    }

    #[test]
    fn jwt_rejects_non_jwt() {
        assert!(decode("jwt", "not-a-jwt").is_err());
        assert!(decode("jwt", "a.b").is_err());
    }

    #[test]
    fn unknown_scheme_errors() {
        assert!(encode("rot13", "x").is_err());
        assert!(decode("rot13", "x").is_err());
        // jwt is decode-only.
        assert!(encode("jwt", "x").is_err());
    }
}
