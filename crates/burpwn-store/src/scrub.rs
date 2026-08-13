//! Masking credential-shaped values inside CAPTURED traffic.
//!
//! [`crate::bundle::redact`] uses this to scrub the text burpwn recorded off the
//! wire — request/response headers and bodies, raw chunks, websocket payloads,
//! request paths and the FTS index built from all of them — before a session
//! bundle leaves the machine.
//!
//! # What it looks for, and what it cannot
//!
//! This is a *shape* matcher, not a secret detector. It masks two shapes:
//!
//! 1. **Credential-bearing header lines** ([`SECRET_HEADERS`]): the whole value
//!    goes, because the whole value is the credential — `Authorization`,
//!    `Cookie`, `Set-Cookie`, `Proxy-Authorization` and the common `X-…-Token` /
//!    `X-Api-Key` spellings.
//! 2. **Credential-NAMED parameters**: `key=value` in a query string or a
//!    `application/x-www-form-urlencoded` body, and `"key": "value"` in JSON,
//!    where the key normalises to something like `password`, `access_token` or
//!    `api_key` (see [`is_secret_key`]).
//!
//! Everything else survives verbatim, and that is deliberate: a session capture
//! is evidence, and a scrubber aggressive enough to catch an unlabelled secret
//! (every long opaque run, say — which is what [`burpwn_error::redact_text`]
//! does for debug reports) would shred the HTML, JSON and base64 that make the
//! capture worth keeping. So a token echoed in a response body under a name
//! nobody would guess, a session id baked into a URL path segment, or a
//! credential in a custom header stays in the file. Callers must say so.
//!
//! # Why the marker has no delimiters
//!
//! Masked values are replaced by [`burpwn_error::REDACTED`] (`«redacted»`),
//! which contains no `&`, `;`, `"`, `,` or whitespace. That makes the transform
//! **idempotent**: re-scrubbing `password=«redacted»` finds the same value
//! extent and writes the same bytes back. [`crate::bundle`] leans on that
//! property when it re-deduplicates the blob store (see `scrub_blobs`), so it is
//! a load-bearing detail, not a cosmetic one.

use burpwn_error::REDACTED;

/// Headers whose ENTIRE value is a credential, lowercase. Matched on the full
/// header name, so `X-Api-Key` matches and `X-Api-Key-Hint` does not.
const SECRET_HEADERS: &[&str] = &[
    "api-key",
    "authentication",
    "authorization",
    "cookie",
    "cookie2",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "x-access-token",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-token",
    "x-xsrf-token",
];

/// Substrings that make a *normalised* parameter name a credential. These have
/// no innocent homograph in a parameter name, so matching them anywhere in the
/// key catches `oldPassword`, `user[password]`, `data.access_token` and
/// `X-Api-Key` alike without touching ordinary fields.
const SECRET_KEY_SUBSTRINGS: &[&str] = &[
    "apikey",
    "credential",
    "passphrase",
    "passwd",
    "password",
    "privatekey",
    "secret",
    "token",
];

/// Parameter names that ARE credentials but whose text appears inside ordinary
/// words (`auth` in `author`, `session` in `sessions_count`), so they are
/// matched whole rather than as substrings.
const SECRET_KEY_EXACT: &[&str] = &[
    "auth",
    "authorization",
    "jsessionid",
    "jwt",
    "otp",
    "pass",
    "phpsessid",
    "pwd",
    "session",
    "sessionid",
    "sid",
];

/// Scrub captured message text. Returns the text unchanged when nothing matched
/// (compare with the input to find out — that is cheaper and more honest than a
/// separate flag).
///
/// Works line by line so a multi-message raw chunk is handled the same way a
/// single header block is, and so line endings (`\r\n` or `\n`) survive intact.
pub fn scrub_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        scrub_line(line, &mut out);
    }
    out
}

/// Scrub captured bytes, or `None` if they are not UTF-8.
///
/// Binary payloads (images, gzip, protobuf) are left ALONE rather than mangled:
/// a text transform over arbitrary bytes would corrupt the capture, and a
/// credential inside a compressed body is not something a line scanner can see
/// anyway. Header blocks are always ASCII, so the headers are always covered.
pub fn scrub_bytes(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    Some(scrub_text(text).into_bytes())
}

/// True when a parameter name designates a credential. The name is normalised
/// first — lowercased, with everything that is not a letter or digit removed —
/// so `access_token`, `accessToken`, `ACCESS-TOKEN` and `access token` are one
/// and the same key.
pub fn is_secret_key(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if norm.is_empty() {
        return false;
    }
    SECRET_KEY_SUBSTRINGS.iter().any(|m| norm.contains(m))
        || SECRET_KEY_EXACT.iter().any(|m| norm == *m)
}

/// One line: a credential header loses its whole value, anything else gets the
/// parameter scan.
fn scrub_line(line: &str, out: &mut String) {
    if let Some(name_end) = header_name_end(line) {
        let name = &line[..name_end];
        if SECRET_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            out.push_str(name);
            out.push(':');
            // Keep the conventional space so the line still parses as a header.
            if line[name_end + 1..].starts_with(' ') {
                out.push(' ');
            }
            out.push_str(REDACTED);
            out.push_str(line_ending(line));
            return;
        }
    }
    scrub_params(line, out);
}

/// Index of the `:` ending a header name, if the line starts like a header
/// (`Token-Name:`). Rejects request lines, JSON (`"key":`) and prose, all of
/// which carry characters no header name may hold.
fn header_name_end(line: &str) -> Option<usize> {
    let colon = line.find(':')?;
    if colon == 0 {
        return None;
    }
    let name = &line[..colon];
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        .then_some(colon)
}

fn line_ending(line: &str) -> &'static str {
    if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else {
        ""
    }
}

/// Scan a line for `key=value` (query string / form body) and `"key": "value"`
/// (JSON) pairs whose key is a credential name, and mask the value.
fn scrub_params(line: &str, out: &mut String) {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut flushed = 0;
    while i < bytes.len() {
        let sep = bytes[i];
        if sep != b'=' && sep != b':' {
            i += 1;
            continue;
        }
        let Some((key, quoted)) = key_before(line, i) else {
            i += 1;
            continue;
        };
        // A bare `key: value` is either a header (handled above) or prose; only
        // the JSON spelling, where the key is quoted, is treated as a parameter.
        if sep == b':' && !quoted {
            i += 1;
            continue;
        }
        if !is_secret_key(key) {
            i += 1;
            continue;
        }
        let Some((start, end)) = value_span(line, i + 1) else {
            i += 1;
            continue;
        };
        out.push_str(&line[flushed..start]);
        out.push_str(REDACTED);
        flushed = end;
        i = end;
    }
    out.push_str(&line[flushed..]);
}

/// The parameter name ending just before `sep_idx`, and whether it was quoted.
///
/// Unquoted names stop at the first delimiter walking backwards (`&`, `?`, `{`,
/// `,`, whitespace…), which is what separates one query/form parameter from the
/// next.
fn key_before(line: &str, sep_idx: usize) -> Option<(&str, bool)> {
    let bytes = line.as_bytes();
    let mut end = sep_idx;
    // JSON tolerates `"key" : value`.
    while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let quote = bytes[end - 1];
    if quote == b'"' || quote == b'\'' {
        let inner_end = end - 1;
        let open = line[..inner_end].rfind(quote as char)?;
        return Some((&line[open + 1..inner_end], true));
    }
    let mut start = end;
    while start > 0 {
        let b = bytes[start - 1];
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']' | b'%') {
            start -= 1;
        } else {
            break;
        }
    }
    (start < end).then(|| (&line[start..end], false))
}

/// The half-open byte range of the value starting at `from`, or `None` when the
/// value is empty (`password=` on its own is not a secret worth masking, and
/// masking it would invent one).
fn value_span(line: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut start = from;
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    if start >= bytes.len() {
        return None;
    }
    let quote = bytes[start];
    if quote == b'"' || quote == b'\'' {
        // A JSON/quoted value: mask what is BETWEEN the quotes so the document
        // stays parseable.
        let mut j = start + 1;
        while j < bytes.len() {
            match bytes[j] {
                b'\\' => j += 2,
                b if b == quote => return (j > start + 1).then_some((start + 1, j)),
                _ => j += 1,
            }
        }
        return None;
    }
    let mut end = start;
    while end < bytes.len() {
        match bytes[end] {
            b'&' | b';' | b',' | b'}' | b'"' | b'\'' | b'#' | b' ' | b'\t' | b'\r' | b'\n' => break,
            _ => end += 1,
        }
    }
    (end > start).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_headers_lose_their_whole_value() {
        let raw = "Host: example.com\r\n\
                   Authorization: Bearer s3cr3t\r\n\
                   Cookie: session=abc; theme=dark\r\n\
                   Proxy-Authorization: Basic YWRtaW46aHVudGVyMg==\r\n\
                   Set-Cookie: sid=xyz; HttpOnly\r\n\
                   X-Api-Key: k-12345\r\n";
        let out = scrub_text(raw);
        for secret in ["s3cr3t", "abc", "YWRtaW46aHVudGVyMg==", "xyz", "k-12345"] {
            assert!(!out.contains(secret), "{secret} survived:\n{out}");
        }
        // The shape of the message survives: names, colons, CRLF, other headers.
        assert!(out.contains("Host: example.com\r\n"));
        assert_eq!(out.matches("\r\n").count(), 6);
        assert!(out.contains(&format!("Authorization: {REDACTED}\r\n")));
    }

    #[test]
    fn ordinary_headers_are_left_alone() {
        let raw = "Content-Type: application/json\r\nAuthor: Ada Lovelace\r\n";
        assert_eq!(scrub_text(raw), raw);
    }

    #[test]
    fn form_and_query_parameters_are_masked_by_name() {
        let out = scrub_text("user=admin&password=hunter2&remember=1");
        assert_eq!(
            out,
            format!("user=admin&password={REDACTED}&remember=1"),
            "the non-secret parameters must survive"
        );

        let out =
            scrub_text("GET /oauth?client_id=app&access_token=abc123&next=/home HTTP/1.1\r\n");
        assert!(!out.contains("abc123"));
        assert!(out.contains("client_id=app"), "{out}");
        assert!(out.contains("next=/home HTTP/1.1"), "{out}");
    }

    #[test]
    fn json_values_are_masked_and_stay_parseable() {
        let body = r#"{"user":"ada","password":"hunter2","accessToken":"ey.aa.bb","note":"ok"}"#;
        let out = scrub_text(body);
        assert!(
            !out.contains("hunter2") && !out.contains("ey.aa.bb"),
            "{out}"
        );
        assert!(
            out.contains(r#""user":"ada""#) && out.contains(r#""note":"ok""#),
            "{out}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("still valid JSON");
        assert_eq!(parsed["password"], REDACTED);
        assert_eq!(parsed["user"], "ada");
    }

    #[test]
    fn a_bare_colon_pair_is_not_a_parameter() {
        // `note: token` is prose, not a JSON field; masking it would shred
        // ordinary body text for nothing.
        let raw = "the token: is in the drawer\n";
        assert_eq!(scrub_text(raw), raw);
    }

    #[test]
    fn empty_values_are_left_as_they_are() {
        for raw in ["password=", "password=&next=1", r#"{"password":""}"#] {
            assert_eq!(scrub_text(raw), raw, "nothing to mask in {raw}");
        }
    }

    #[test]
    fn key_names_are_normalised_before_matching() {
        for key in [
            "password",
            "oldPassword",
            "user[password]",
            "access_token",
            "accessToken",
            "API-KEY",
            "client_secret",
            "refresh_token",
            "pwd",
            "sid",
            "JSESSIONID",
        ] {
            assert!(is_secret_key(key), "{key} should be secret");
        }
        for key in [
            "author",
            "session_count",
            "username",
            "email",
            "id",
            "next",
            "q",
            "page",
            "keyboard",
        ] {
            assert!(!is_secret_key(key), "{key} should NOT be secret");
        }
    }

    /// Load-bearing: [`crate::bundle`] re-deduplicates blobs by the SHA-256 of
    /// their SCRUBBED bytes, and the argument that no two surviving rows can
    /// collide relies on scrubbing twice being the same as scrubbing once.
    #[test]
    fn scrubbing_is_idempotent() {
        let raw = "Authorization: Bearer s3cr3t\r\n\
                   Cookie: a=b\r\n\
                   \r\n\
                   user=ada&password=hunter2&token=zz\n\
                   {\"api_key\":\"kk\",\"ok\":1}\n";
        let once = scrub_text(raw);
        assert_eq!(scrub_text(&once), once, "second pass must be a no-op");
        assert_ne!(once, raw);
    }

    #[test]
    fn non_utf8_payloads_are_refused_rather_than_mangled() {
        assert!(scrub_bytes(&[0xff, 0xfe, 0x00, 0x01]).is_none());
        assert_eq!(
            scrub_bytes(b"password=hunter2").unwrap(),
            format!("password={REDACTED}").into_bytes()
        );
    }

    /// The honest limit, pinned by a test so it cannot be discovered by
    /// surprise: a credential that is not SHAPED like one is not found.
    #[test]
    fn unlabelled_secrets_survive_on_purpose() {
        let raw = "X-Tenant-Blob: eyJhbGciOiJIUzI1NiJ9.payload.sig\n\
                   {\"result\":\"the door code is 4815162342\"}\n\
                   GET /reset/9f8a7b6c5d4e3f2a1b0c HTTP/1.1\n";
        assert_eq!(
            scrub_text(raw),
            raw,
            "--redact masks credential SHAPES; anything else is still in the bundle"
        );
    }
}
