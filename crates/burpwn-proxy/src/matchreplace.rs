//! Pure application of [`MatchReplaceRule`]s to an HTTP message.
//!
//! # Regex semantics
//!
//! Each rule's `pattern` is a **regular expression** (regex crate syntax) and
//! `replacement` supports capture references — `$1`, `$name`, `${name}` — exactly
//! as [`regex::Regex::replace_all`] interprets them. (A plain literal like
//! `User-Agent: burpwn` is itself a valid regex that matches verbatim, so
//! literal-style rules keep working.)
//!
//! - [`MatchKind::Header`]: the regex runs over the **whole header block**
//!   (`Name: Value\r\n…`, decoded lossily from bytes), so a pattern like
//!   `User-Agent: .*` matches and rewrites the entire UA line. The rewritten
//!   block is written back as bytes.
//! - [`MatchKind::Host`] / [`MatchKind::Url`]: the regex runs over the string.
//! - [`MatchKind::Body`]: the regex runs over the body decoded as lossy UTF-8,
//!   then re-encoded to bytes. If the body is **not valid UTF-8** the rule is a
//!   safe no-op (we won't risk mangling binary bodies through lossy decoding).
//!
//! An **invalid regex pattern** never panics and never aborts the request: the
//! offending rule is simply skipped (logged at `debug`). Every entry point stays
//! total and only reports whether anything changed.
//!
//! Scope: a rule's `scope` field is a simple substring filter against the
//! request host. An empty scope (or `"*"`) matches every host.
//!
//! These functions are pure (no I/O, no store access) so the proxy can call
//! them on the hot path and the test-suite can exercise every [`MatchKind`] ×
//! request/response combination without standing anything up.

use std::borrow::Cow;

use burpwn_store::model::{MatchKind, MatchReplaceRule};
use regex::{Regex, RegexBuilder};

/// The mutable parts of a message a rule set can rewrite. `headers` is the
/// order-preserving raw header block (`Name: Value\r\n…`); `host`/`url` are the
/// request-line components (responses ignore them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Request host / `:authority` (empty for responses).
    pub host: String,
    /// Request target / path (empty for responses).
    pub url: String,
    /// Raw header block bytes, order-preserving.
    pub headers: Vec<u8>,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// Whether at least one rule actually changed the message.
pub type Changed = bool;

/// Apply all enabled `on_request` rules to a request message in declaration
/// order. Returns whether anything changed.
pub fn apply_request(rules: &[MatchReplaceRule], msg: &mut Message) -> Changed {
    apply(rules, msg, true)
}

/// Apply all enabled `on_response` rules to a response message. The `host` of
/// `msg` should carry the originating request host so scope filtering works;
/// `url` is unused for responses.
pub fn apply_response(rules: &[MatchReplaceRule], msg: &mut Message) -> Changed {
    apply(rules, msg, false)
}

fn apply(rules: &[MatchReplaceRule], msg: &mut Message, on_request: bool) -> Changed {
    let mut changed = false;
    for rule in rules {
        if !rule.enabled || rule.on_request != on_request {
            continue;
        }
        if !scope_matches(&rule.scope, &msg.host) {
            continue;
        }
        changed |= apply_one(rule, msg);
    }
    changed
}

/// An empty scope or `"*"` matches everything; otherwise it's a case-insensitive
/// substring test against the host.
fn scope_matches(scope: &str, host: &str) -> bool {
    let scope = scope.trim();
    if scope.is_empty() || scope == "*" {
        return true;
    }
    // Support a leading wildcard like "*.example.com" by stripping the "*.".
    let needle = scope.strip_prefix("*.").unwrap_or(scope);
    host.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn apply_one(rule: &MatchReplaceRule, msg: &mut Message) -> Changed {
    // An empty pattern matches the empty string at every position; treat it as a
    // no-op so a blank rule never rewrites a message.
    if rule.pattern.is_empty() {
        return false;
    }
    // Compile the pattern as a regex. Header rules match case-INSENSITIVELY:
    // hyper normalizes header names to lowercase (HTTP/2 requires it on the
    // wire), so the captured block is `user-agent: …` while users naturally
    // write `User-Agent:` (as in Burp / our docs). An invalid pattern is a safe
    // no-op: skip the rule rather than panicking or aborting the request.
    let re = match RegexBuilder::new(&rule.pattern)
        .case_insensitive(matches!(rule.match_kind, MatchKind::Header))
        .build()
    {
        Ok(re) => re,
        Err(e) => {
            tracing::debug!(
                rule = rule.id,
                pattern = %rule.pattern,
                error = %e,
                "skipping match/replace rule with invalid regex"
            );
            return false;
        }
    };
    match rule.match_kind {
        MatchKind::Host => replace_str(&mut msg.host, &re, &rule.replacement),
        MatchKind::Url => replace_str(&mut msg.url, &re, &rule.replacement),
        // The header block is order-preserving raw bytes that are virtually
        // always UTF-8 (header names/values are ASCII). Apply the regex
        // PER LINE so a pattern like `User-Agent: .*` rewrites the value but
        // never consumes the `\r\n` terminator (regex `.` matches `\r`, so a
        // whole-block replace would eat it).
        MatchKind::Header => replace_header_block(&mut msg.headers, &re, &rule.replacement),
        MatchKind::Body => replace_body(&mut msg.body, &re, &rule.replacement),
    }
}

/// Regex replace-all on a `String`; `false` (no-op) when the pattern doesn't
/// match. `replacement` honors `$1`/`${name}` capture refs.
fn replace_str(haystack: &mut String, re: &Regex, replacement: &str) -> Changed {
    let rewritten = match re.replace_all(haystack, replacement) {
        Cow::Borrowed(_) => None, // no match → unchanged
        Cow::Owned(new) => Some(new),
    };
    match rewritten {
        Some(new) => {
            *haystack = new;
            true
        }
        None => false,
    }
}

/// Regex replace-all over the raw header block, applied PER LINE (split on
/// `\r\n`) so the `\r\n` terminators are preserved verbatim — `User-Agent: .*`
/// rewrites the value, not the line break. The block is decoded lossily (header
/// names/values are effectively ASCII) and written back as bytes.
fn replace_header_block(haystack: &mut Vec<u8>, re: &Regex, replacement: &str) -> Changed {
    let text = String::from_utf8_lossy(haystack);
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split("\r\n").enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        match re.replace_all(line, replacement) {
            Cow::Borrowed(_) => out.push_str(line),
            Cow::Owned(new) => {
                changed = true;
                out.push_str(&new);
            }
        }
    }
    if changed {
        *haystack = out.into_bytes();
    }
    changed
}

/// Regex replace-all over a body. The body may be binary, so we require valid
/// UTF-8: if it isn't, the rule is a documented no-op (we won't risk mangling
/// binary bodies by lossy-decoding non-UTF-8 bytes).
fn replace_body(haystack: &mut Vec<u8>, re: &Regex, replacement: &str) -> Changed {
    let text = match std::str::from_utf8(haystack) {
        Ok(t) => t,
        Err(_) => return false, // non-UTF-8 body: safe no-op
    };
    let rewritten = match re.replace_all(text, replacement) {
        Cow::Borrowed(_) => None,
        Cow::Owned(new) => Some(new.into_bytes()),
    };
    match rewritten {
        Some(bytes) => {
            *haystack = bytes;
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        kind: MatchKind,
        scope: &str,
        pat: &str,
        repl: &str,
        on_request: bool,
    ) -> MatchReplaceRule {
        MatchReplaceRule {
            id: 1,
            enabled: true,
            scope: scope.into(),
            match_kind: kind,
            pattern: pat.into(),
            replacement: repl.into(),
            on_request,
        }
    }

    fn msg() -> Message {
        Message {
            host: "api.example.com".into(),
            url: "/v1/users?id=5".into(),
            headers: b"Host: api.example.com\r\nUser-Agent: curl/8\r\n".to_vec(),
            body: b"{\"role\":\"user\"}".to_vec(),
        }
    }

    #[test]
    fn host_rule_on_request() {
        let mut m = msg();
        let changed = apply_request(
            &[rule(MatchKind::Host, "*", "example.com", "evil.test", true)],
            &mut m,
        );
        assert!(changed);
        assert_eq!(m.host, "api.evil.test");
    }

    #[test]
    fn url_rule_on_request() {
        let mut m = msg();
        apply_request(&[rule(MatchKind::Url, "", "id=5", "id=1", true)], &mut m);
        assert_eq!(m.url, "/v1/users?id=1");
    }

    #[test]
    fn header_rule_preserves_other_headers() {
        let mut m = msg();
        // A literal substring is a valid regex (no special chars), so a
        // value-only literal still works as before.
        let changed = apply_request(
            &[rule(MatchKind::Header, "", "curl/8", "burpwn/1", true)],
            &mut m,
        );
        assert!(changed);
        assert_eq!(
            m.headers,
            b"Host: api.example.com\r\nUser-Agent: burpwn/1\r\n"
        );
    }

    #[test]
    fn header_block_user_agent_dotstar_rewrites_whole_line() {
        // The documented example: `User-Agent: .*` over the header BLOCK rewrites
        // the whole UA line (regex `.*` does not cross `\r\n`).
        let mut m = msg();
        let changed = apply_request(
            &[rule(
                MatchKind::Header,
                "",
                "User-Agent: .*",
                "User-Agent: burpwn",
                true,
            )],
            &mut m,
        );
        assert!(changed);
        assert_eq!(
            m.headers,
            b"Host: api.example.com\r\nUser-Agent: burpwn\r\n"
        );
    }

    #[test]
    fn header_match_is_case_insensitive_for_lowercased_names() {
        // hyper lowercases header names (HTTP/2 wire requirement), so the captured
        // block is `user-agent: …`; the documented `User-Agent: .*` must still match.
        let mut m = Message {
            host: "api.example.com".into(),
            url: "/".into(),
            headers: b"host: api.example.com\r\nuser-agent: curl/8\r\n".to_vec(),
            body: Vec::new(),
        };
        let changed = apply_request(
            &[rule(
                MatchKind::Header,
                "",
                "User-Agent: .*",
                "user-agent: burpwn",
                true,
            )],
            &mut m,
        );
        assert!(changed);
        assert_eq!(
            m.headers,
            b"host: api.example.com\r\nuser-agent: burpwn\r\n"
        );
    }

    #[test]
    fn capture_group_replacement() {
        // Rewrite `id=5` to `id=500` using a capture reference.
        let mut m = msg();
        let changed = apply_request(
            &[rule(MatchKind::Url, "", r"id=(\d+)", "id=${1}00", true)],
            &mut m,
        );
        assert!(changed);
        assert_eq!(m.url, "/v1/users?id=500");
    }

    #[test]
    fn invalid_regex_is_safe_noop() {
        let mut m = msg();
        // An unclosed group is an invalid regex: must be skipped, not panic.
        let changed = apply_request(&[rule(MatchKind::Body, "", "(unclosed", "x", true)], &mut m);
        assert!(!changed);
        assert_eq!(m.body, b"{\"role\":\"user\"}");
    }

    #[test]
    fn non_utf8_body_is_noop() {
        let mut m = msg();
        m.body = vec![0xff, 0xfe, 0x00, 0x80]; // invalid UTF-8
        let before = m.body.clone();
        // `.+` would match any UTF-8 text, but the body isn't valid UTF-8 so the
        // body rule is a documented no-op.
        let changed = apply_request(&[rule(MatchKind::Body, "", ".+", "X", true)], &mut m);
        assert!(!changed);
        assert_eq!(m.body, before);
    }

    #[test]
    fn body_rule_on_response_only() {
        let mut m = msg();
        // An on_response rule must NOT fire during request application.
        let req_rules = [rule(MatchKind::Body, "", "user", "admin", false)];
        assert!(!apply_request(&req_rules, &mut m));
        assert_eq!(m.body, b"{\"role\":\"user\"}");
        // …but it fires on the response side.
        assert!(apply_response(&req_rules, &mut m));
        assert_eq!(m.body, b"{\"role\":\"admin\"}");
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let mut r = rule(MatchKind::Host, "*", "example.com", "x.test", true);
        r.enabled = false;
        let mut m = msg();
        assert!(!apply_request(&[r], &mut m));
        assert_eq!(m.host, "api.example.com");
    }

    #[test]
    fn scope_filters_by_host() {
        let mut m = msg();
        // Scope that does not match the host: no change.
        assert!(!apply_request(
            &[rule(MatchKind::Body, "other.test", "user", "admin", true)],
            &mut m
        ));
        // Wildcard scope matching the host: changes.
        assert!(apply_request(
            &[rule(
                MatchKind::Body,
                "*.example.com",
                "user",
                "admin",
                true
            )],
            &mut m
        ));
        assert_eq!(m.body, b"{\"role\":\"admin\"}");
    }

    #[test]
    fn multiple_rules_apply_in_order() {
        let mut m = msg();
        let rules = [
            rule(MatchKind::Body, "", "user", "ADMIN", true),
            rule(MatchKind::Body, "", "ADMIN", "root", true),
        ];
        assert!(apply_request(&rules, &mut m));
        assert_eq!(m.body, b"{\"role\":\"root\"}");
    }

    #[test]
    fn empty_pattern_is_noop() {
        // A blank pattern is treated as a no-op (it would otherwise match the
        // empty string at every position).
        let mut m = msg();
        assert!(!apply_request(
            &[rule(MatchKind::Body, "", "", "x", true)],
            &mut m
        ));
        assert_eq!(m.body, b"{\"role\":\"user\"}");
    }
}
