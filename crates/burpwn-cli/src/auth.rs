//! `session auth` — session-token handling for long engagements.
//!
//! Authenticated targets silently start returning 401s once a bearer/session
//! token expires; the only prior tool was a STATIC match/replace on the auth
//! header. This module persists an *auth profile* (a login command + a
//! token-extraction regex + a header-injection template) and can REFRESH it:
//! run the login command in the sandbox, pull a fresh token from its output, and
//! install/UPDATE a single match/replace rule that injects the header into
//! in-scope requests.
//!
//! # Injection semantics
//!
//! The injection is a [`MatchKind::Header`] rule. The pattern targets the header
//! LINE (`^Authorization:.*`, matched case-insensitively per line by the
//! match/replace engine) and the replacement re-emits the whole line with the
//! fresh token: `Authorization: Bearer <token>`. This REPLACES a stale token on
//! an in-scope request — the common cause of mid-engagement 401s, where the
//! request already carries a (now-expired) auth header. (match/replace rewrites
//! existing content; it cannot synthesize a header a request never sent.)
//!
//! # Idempotency
//!
//! Each profile stores the id of its injection rule. A refresh DELETES the prior
//! rule (if any) and installs a fresh one, then records the new rule id + token,
//! so repeated refreshes never stack duplicate rules.
//!
//! # Auto-refresh
//!
//! The proxy signals 401/403 hosts to the daemon (see `burpwn_proxy::auth` +
//! `daemon::auth_refresh_consumer`), which spawns `session auth refresh --host
//! <scope>`. The pure token/rule logic here is shared by the manual and auto
//! paths; only [`run_login`] touches the sandbox.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;

use burpwn_error::ErrorCode;
use burpwn_sandbox::{doctor, RootlessRuntime, SandboxRuntime};
use burpwn_store::model::{MatchKind, NewAuthProfile, NewMatchReplaceRule};
use burpwn_store::Store;

use crate::exec;
use crate::paths::Paths;

/// Placeholder in a header template that the token is substituted for.
const TOKEN_PLACEHOLDER: &str = "{}";

/// A header-injection template split into its name and value parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderTemplate {
    /// Header name, e.g. `Authorization`.
    pub name: String,
    /// Value template carrying the `{}` placeholder, e.g. `Bearer {}`.
    pub value_template: String,
}

impl HeaderTemplate {
    /// Parse a `Name: <prefix> {} <suffix>` template. The value part MUST contain
    /// the `{}` placeholder (else the token would never be injected).
    pub fn parse(header: &str) -> Result<Self> {
        let (name, value) = header.split_once(':').ok_or_else(|| {
            crate::coded!(
                ErrorCode::InputMalformedHeader,
                "--header must be `Name: value` with a {{}} placeholder"
            )
        })?;
        let name = name.trim();
        let value_template = value.trim();
        if name.is_empty() {
            crate::fail!(
                ErrorCode::InputMalformedHeader,
                "--header has an empty header name: {header:?}"
            );
        }
        if !value_template.contains(TOKEN_PLACEHOLDER) {
            crate::fail!(
                ErrorCode::InputMalformedHeader,
                "--header value must contain the {{}} token placeholder: {header:?}"
            );
        }
        // Reject CR/LF/NUL that would smuggle extra header lines when injected.
        if [name, value_template]
            .iter()
            .any(|s| s.contains('\r') || s.contains('\n') || s.contains('\0'))
        {
            crate::fail!(
                ErrorCode::InputMalformedHeader,
                "--header must not contain CR, LF or NUL"
            );
        }
        Ok(Self {
            name: name.to_string(),
            value_template: value_template.to_string(),
        })
    }

    /// The concrete header value with `{}` replaced by `token`.
    pub fn value_with(&self, token: &str) -> String {
        self.value_template.replace(TOKEN_PLACEHOLDER, token)
    }
}

/// Extract the token from a login command's output using `regex` (one capture
/// group). The FIRST match's group 1 is returned; a regex without a capture
/// group, or no match, is an error.
pub fn extract_token(regex: &str, output: &str) -> Result<String> {
    let re = Regex::new(regex).with_context(|| format!("invalid --extract regex {regex:?}"))?;
    let caps = re.captures(output).ok_or_else(|| {
        crate::coded!(
            ErrorCode::NetworkAuthRefreshFailed,
            "--extract regex did not match the login command output"
        )
    })?;
    let group = caps.get(1).ok_or_else(|| {
        crate::coded!(
            ErrorCode::InputBadRegex,
            "--extract regex must have one capture group (found none)"
        )
    })?;
    Ok(group.as_str().to_string())
}

/// Build the match/replace injection rule for `template` + `token` scoped to
/// `host`. The pattern rewrites the existing header LINE; the replacement carries
/// the fresh token with `$` neutralised (match/replace replacement honours `$1`
/// capture refs, so a literal `$` in a token must be escaped as `$$`).
pub fn injection_rule(template: &HeaderTemplate, token: &str, host: &str) -> NewMatchReplaceRule {
    let pattern = format!("^{}:.*", regex::escape(&template.name));
    let value = template.value_with(token);
    let replacement = format!("{}: {}", template.name, value).replace('$', "$$");
    NewMatchReplaceRule {
        enabled: true,
        scope: host.to_string(),
        match_kind: MatchKind::Header,
        pattern,
        replacement,
        on_request: true,
    }
}

/// Mask a token for display: keep a short prefix/suffix, redact the middle.
pub fn mask_token(token: &str) -> String {
    let n = token.chars().count();
    if n <= 8 {
        return "*".repeat(n.max(1));
    }
    let chars: Vec<char> = token.chars().collect();
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{head}…{tail} ({n} chars)")
}

/// Apply a freshly-minted token to a profile: DELETE the prior injection rule
/// (if any), install a new one, and record the new rule id + token. Idempotent —
/// repeated calls never stack rules. Pure w.r.t. the sandbox (store-only), so it
/// is unit-tested directly.
pub async fn apply_refresh(
    store: &Store,
    host: &str,
    template: &HeaderTemplate,
    token: &str,
    prior_rule_id: Option<i64>,
    now_ms: i64,
) -> Result<i64> {
    if let Some(old) = prior_rule_id {
        // Best-effort: the rule may already be gone (deleted by hand).
        let _ = store.writer().delete_match_replace(old).await;
    }
    let rule = injection_rule(template, token, host);
    let rule_id = store.writer().add_match_replace(rule).await?;
    store
        .writer()
        .set_auth_token(host, Some(token.to_string()), Some(rule_id), now_ms)
        .await?;
    Ok(rule_id)
}

/// Persist (or update) an auth profile. Validates the header template + extract
/// regex up front so a broken profile is rejected at `set` time, not refresh.
pub async fn auth_set(
    store: &Store,
    host: &str,
    login: &str,
    extract: &str,
    header: &str,
) -> Result<i64> {
    // Validate: the header template must carry `{}`, and the regex must compile.
    let _ = HeaderTemplate::parse(header)?;
    Regex::new(extract).with_context(|| format!("invalid --extract regex {extract:?}"))?;
    if login.trim().is_empty() {
        crate::fail!(ErrorCode::InputInvalidValue, "--login must not be empty");
    }
    store
        .writer()
        .upsert_auth_profile(NewAuthProfile {
            host: host.to_string(),
            login_cmd: login.to_string(),
            extract_regex: extract.to_string(),
            header_template: header.to_string(),
        })
        .await
        .map_err(Into::into)
}

/// Run a profile's login command in the sandbox (routed through the session's
/// proxy) and return its captured stdout. This is the only sandbox-touching part
/// of refresh; it is gated on the sandbox preflight like `burpwn exec`.
///
/// `runtime_override` lets tests inject a [`burpwn_sandbox::MockRuntime`]; in
/// production the real [`RootlessRuntime`] is used (after `doctor()`).
pub async fn run_login(
    paths: &Paths,
    session: &str,
    login_cmd: &str,
    runtime_override: Option<Arc<dyn SandboxRuntime>>,
) -> Result<String> {
    let runtime: Arc<dyn SandboxRuntime> = match runtime_override {
        Some(rt) => rt,
        None => {
            let pf = doctor();
            if !pf.is_ok() {
                crate::fail!(
                    ErrorCode::SandboxPrerequisites,
                    "sandbox preflight failed: {} — run `burpwn doctor`",
                    pf.missing_summary()
                );
            }
            Arc::new(RootlessRuntime::new())
        }
    };
    // Run the login as one sandboxed `sh -c` so a compound login works and its
    // traffic is captured/injected like any other exec.
    let argv = vec!["sh".to_string(), "-c".to_string(), login_cmd.to_string()];
    let result = exec::run_exec(
        paths,
        session,
        exec::DEFAULT_WORKSPACE_ID,
        runtime,
        argv,
        Some(Duration::from_secs(60)),
        false, // capture stdout instead of inheriting it
    )
    .await
    .context("running the auth login command in the sandbox")?;
    Ok(String::from_utf8_lossy(&result.outcome.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_template_parse_requires_placeholder() {
        let t = HeaderTemplate::parse("Authorization: Bearer {}").unwrap();
        assert_eq!(t.name, "Authorization");
        assert_eq!(t.value_template, "Bearer {}");
        assert_eq!(t.value_with("abc"), "Bearer abc");

        // Missing placeholder is rejected.
        assert!(HeaderTemplate::parse("Authorization: Bearer").is_err());
        // Missing colon is rejected.
        assert!(HeaderTemplate::parse("Authorization Bearer {}").is_err());
        // Empty name is rejected.
        assert!(HeaderTemplate::parse(": {}").is_err());
    }

    #[test]
    fn extract_token_pulls_capture_group() {
        let out = r#"{"access_token":"eyJabc.def","expires":3600}"#;
        let tok = extract_token(r#""access_token":"([^"]+)""#, out).unwrap();
        assert_eq!(tok, "eyJabc.def");

        // No match → error.
        assert!(extract_token(r#""nope":"([^"]+)""#, out).is_err());
        // No capture group → error.
        assert!(extract_token(r#""access_token":"[^"]+""#, out).is_err());
        // Invalid regex → error.
        assert!(extract_token("(unclosed", out).is_err());
    }

    #[test]
    fn injection_rule_replaces_stale_header_and_escapes_dollar() {
        let t = HeaderTemplate::parse("Authorization: Bearer {}").unwrap();
        let rule = injection_rule(&t, "tok123", "api.example.com");
        assert_eq!(rule.match_kind, MatchKind::Header);
        assert_eq!(rule.pattern, "^Authorization:.*");
        assert_eq!(rule.replacement, "Authorization: Bearer tok123");
        assert_eq!(rule.scope, "api.example.com");
        assert!(rule.on_request);

        // A `$` in the token is neutralised for the replacement engine.
        let rule = injection_rule(&t, "a$1b", "");
        assert_eq!(rule.replacement, "Authorization: Bearer a$$1b");
    }

    #[test]
    fn injection_rule_actually_rewrites_via_matchreplace_engine() {
        use burpwn_proxy::matchreplace::{apply_request, Message};
        use burpwn_store::model::MatchReplaceRule;

        let t = HeaderTemplate::parse("Authorization: Bearer {}").unwrap();
        let n = injection_rule(&t, "fresh-token", "example.com");
        let rule = MatchReplaceRule {
            id: 1,
            enabled: n.enabled,
            scope: n.scope,
            match_kind: n.match_kind,
            pattern: n.pattern,
            replacement: n.replacement,
            on_request: n.on_request,
        };
        // A request carrying a STALE token (hyper lowercases header names).
        let mut msg = Message {
            host: "api.example.com".into(),
            url: "/".into(),
            headers: b"host: api.example.com\r\nauthorization: Bearer stale-token\r\n".to_vec(),
            body: Vec::new(),
        };
        assert!(apply_request(&[rule], &mut msg));
        let hdrs = String::from_utf8(msg.headers).unwrap();
        assert!(hdrs.contains("Authorization: Bearer fresh-token"), "{hdrs}");
        assert!(
            !hdrs.contains("stale-token"),
            "stale token replaced: {hdrs}"
        );
    }

    #[test]
    fn mask_token_redacts() {
        assert_eq!(mask_token("short"), "*****");
        let m = mask_token("eyJhbGciOiJIUzI1NiIsInR5cCI");
        assert!(m.starts_with("eyJh"), "{m}");
        assert!(m.contains('…'));
        assert!(!m.contains("bGci"));
    }

    #[tokio::test]
    async fn apply_refresh_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let store = Store::open(paths.session_db("default")).unwrap();

        // Seed the profile.
        let host = "api.example.com";
        auth_set(
            &store,
            host,
            "printf tok1",
            r"(tok\d+)",
            "Authorization: Bearer {}",
        )
        .await
        .unwrap();
        let template = HeaderTemplate::parse("Authorization: Bearer {}").unwrap();

        // First refresh: installs one rule, sets the token.
        let rid1 = apply_refresh(&store, host, &template, "tok1", None, 10)
            .await
            .unwrap();
        assert_eq!(store.reader().list_match_replace().unwrap().len(), 1);

        // Second refresh (as auto-refresh would run) must UPDATE, not stack.
        let profile = store.reader().auth_profile_for_host(host).unwrap().unwrap();
        assert_eq!(profile.rule_id, Some(rid1));
        assert_eq!(profile.token.as_deref(), Some("tok1"));
        let rid2 = apply_refresh(&store, host, &template, "tok2", profile.rule_id, 20)
            .await
            .unwrap();
        let rules = store.reader().list_match_replace().unwrap();
        assert_eq!(
            rules.len(),
            1,
            "still exactly one injection rule (no stack)"
        );
        assert_eq!(rules[0].id, rid2, "the profile tracks the current rule");
        assert_eq!(rules[0].replacement, "Authorization: Bearer tok2");
        let _ = rid1;

        let profile = store.reader().auth_profile_for_host(host).unwrap().unwrap();
        assert_eq!(profile.token.as_deref(), Some("tok2"));
        assert_eq!(profile.rule_id, Some(rid2));
    }
}
