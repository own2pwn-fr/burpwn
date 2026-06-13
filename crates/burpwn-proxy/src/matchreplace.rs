//! Pure application of [`MatchReplaceRule`]s to an HTTP message.
//!
//! v1 semantics are deliberately regex-free: each rule does a literal substring
//! replacement of `pattern` with `replacement` on the targeted part of the
//! message (host / url / header block / body). This keeps the transform total,
//! cheap, and trivially unit-testable; regex support can layer on later behind
//! the same [`apply_request`] / [`apply_response`] entry points.
//!
//! Scope: a rule's `scope` field is a simple substring filter against the
//! request host. An empty scope (or `"*"`) matches every host.
//!
//! These functions are pure (no I/O, no store access) so the proxy can call
//! them on the hot path and the test-suite can exercise every [`MatchKind`] ×
//! request/response combination without standing anything up.

use burpwn_store::model::{MatchKind, MatchReplaceRule};

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
    match rule.match_kind {
        MatchKind::Host => replace_str(&mut msg.host, &rule.pattern, &rule.replacement),
        MatchKind::Url => replace_str(&mut msg.url, &rule.pattern, &rule.replacement),
        MatchKind::Header => replace_bytes(
            &mut msg.headers,
            rule.pattern.as_bytes(),
            rule.replacement.as_bytes(),
        ),
        MatchKind::Body => replace_bytes(
            &mut msg.body,
            rule.pattern.as_bytes(),
            rule.replacement.as_bytes(),
        ),
    }
}

/// Literal substring replace on a `String`; no-op (and `false`) if the pattern
/// is empty or absent.
fn replace_str(haystack: &mut String, pattern: &str, replacement: &str) -> Changed {
    if pattern.is_empty() || !haystack.contains(pattern) {
        return false;
    }
    *haystack = haystack.replace(pattern, replacement);
    true
}

/// Literal substring replace over raw bytes (headers/body may be non-UTF-8).
fn replace_bytes(haystack: &mut Vec<u8>, pattern: &[u8], replacement: &[u8]) -> Changed {
    if pattern.is_empty() {
        return false;
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    let mut hit = false;
    while i < haystack.len() {
        if haystack[i..].starts_with(pattern) {
            out.extend_from_slice(replacement);
            i += pattern.len();
            hit = true;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    if hit {
        *haystack = out;
    }
    hit
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
        let mut m = msg();
        assert!(!apply_request(
            &[rule(MatchKind::Body, "", "", "x", true)],
            &mut m
        ));
    }
}
