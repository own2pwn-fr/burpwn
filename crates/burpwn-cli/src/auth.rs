//! `session auth` — the login macro, as a façade over the hook engine.
//!
//! Authenticated targets silently start returning 401s once a bearer/session
//! token expires. This used to be its own machine: an `auth_profiles` row, a
//! `session auth refresh` that ran the login command and rewrote ONE generated
//! match/replace rule with the token it minted, and a proxy-side watcher that
//! spawned that refresh in the background when it saw a 401.
//!
//! It is now one `pre-request` hook with an `exec` action, because that is the
//! same description of the same thing — run a command, pull a value out of its
//! stdout with a one-capture-group regex, put the value in a header — with the
//! two properties the old shape could not have:
//!
//! - **it can ADD the header.** A match/replace rule rewrites text the message
//!   already carries: `^Authorization:.*` matches nothing on a request that
//!   never sent one, so the very first call of a fresh session went upstream
//!   bare. A hook injection is `set-header`, i.e. add-or-replace.
//! - **it happens to the request that is waiting.** The refresh no longer runs
//!   beside the traffic; the request is parked on the mint and forwarded with
//!   the token. Nobody has to take a 401 to make the next call work.
//!
//! # What this module is
//!
//! Only the naming and the translation. A profile is a hook stored under the
//! name `auth:<host>` ([`auth_hook_name`]) — [`build_auth_hook`] turns the
//! `session auth set` flags into the very [`crate::hooks::HookSpec`] that `hook
//! add --action exec` builds, so there is one validator and one storage. Which
//! is also why the façade is worth keeping: `session auth set --login … --header
//! 'Authorization: Bearer {}'` says what an operator (or an agent) means, and
//! `hook list` still shows exactly what it built.
//!
//! # Idempotency
//!
//! [`auth_set`] upserts BY NAME (`Writer::upsert_hook_by_name`), so re-running
//! it for a host replaces that profile instead of stacking a second login
//! command onto every request. The proxy drops the value cached for a hook whose
//! definition changed, so a re-`set` never keeps serving the previous command's
//! token either.
//!
//! # Where the token lives
//!
//! Nowhere on disk. It used to be a column (`auth_profiles.token`) because the
//! generated rule needed a literal to substitute; the hook mints its own and the
//! daemon holds it in memory for the hook's TTL. A session file is no longer a
//! place where a bearer token is at rest, which is also why `--redact` has less
//! to erase.

use burpwn_store::model::{Hook, HookAction, NewHook};
use burpwn_store::Store;

use anyhow::Result;
use burpwn_error::ErrorCode;

use crate::hooks::{self, HookSpec};

/// Placeholder in a header template that the token is substituted for.
const TOKEN_PLACEHOLDER: &str = "{}";

/// Prefix of the hook name a session-auth profile is stored under. Also the
/// filter `session auth status` / `session auth refresh` select on, so a hook
/// named this way by hand is a profile as far as they are concerned — which is
/// the honest answer, since it IS one.
pub const AUTH_HOOK_PREFIX: &str = "auth:";

/// The hook name a profile for `host` lives under (`auth:*` when unscoped).
///
/// ⚠️ Kept in sync with `burpwn_store::schema`'s v8 migration, which names the
/// hooks it rewrites out of `auth_profiles` the same way.
pub fn auth_hook_name(host: &str) -> String {
    let scope = if host.trim().is_empty() { "*" } else { host };
    format!("{AUTH_HOOK_PREFIX}{scope}")
}

/// Whether this hook is a session-auth profile: an `exec` hook stored under the
/// [`AUTH_HOOK_PREFIX`].
pub fn is_auth_hook(hook: &Hook) -> bool {
    hook.name.starts_with(AUTH_HOOK_PREFIX) && matches!(hook.action, HookAction::Exec { .. })
}

/// Every session-auth profile in the session, in hook application order.
pub fn auth_hooks(store: &Store) -> Result<Vec<Hook>> {
    Ok(store
        .reader()
        .list_hooks()?
        .into_iter()
        .filter(is_auth_hook)
        .collect())
}

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

/// Translate the `session auth set` flags into the hook they describe.
///
/// The header template is parsed here FIRST, so a bad one is reported in terms
/// of the flag the caller actually passed (`--header`) rather than the
/// `--inject-header` it becomes; everything after that is `hook add`'s own
/// validation, deliberately, so the façade can never build a hook the direct
/// command would have refused.
pub fn build_auth_hook(host: &str, login: &str, extract: &str, header: &str) -> Result<NewHook> {
    let _ = HeaderTemplate::parse(header)?;
    if login.trim().is_empty() {
        crate::fail!(ErrorCode::InputInvalidValue, "--login must not be empty");
    }
    hooks::build_hook(&HookSpec {
        name: auth_hook_name(host),
        phase: "pre-request".into(),
        action: "exec".into(),
        host: host.to_string(),
        cmd: Some(login.to_string()),
        extract: Some(extract.to_string()),
        inject_header: Some(header.to_string()),
        // Add-OR-REPLACE. Both halves matter: a stale header must be overwritten
        // (all the old match/replace rule could do) and an absent one must be
        // synthesized (what it could not).
        inject_only_if_absent: false,
        timeout_ms: hooks::DEFAULT_TIMEOUT_MS,
        ttl_ms: hooks::DEFAULT_TTL_MS,
        ..Default::default()
    })
}

/// Persist (or update) a session-auth profile; returns the hook id.
pub async fn auth_set(
    store: &Store,
    host: &str,
    login: &str,
    extract: &str,
    header: &str,
) -> Result<i64> {
    let hook = build_auth_hook(host, login, extract, header)?;
    store
        .writer()
        .upsert_hook_by_name(hook)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use burpwn_store::model::{HookInjectKind, HookPhase};

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
    fn a_profile_is_a_pre_request_exec_hook() {
        let h = build_auth_hook(
            "api.example.com",
            "curl -s https://api.example.com/login",
            r#""token":"([^"]+)""#,
            "Authorization: Bearer {}",
        )
        .unwrap();
        assert_eq!(h.name, "auth:api.example.com");
        assert_eq!(h.phase, HookPhase::PreRequest);
        assert_eq!(h.scope.host, "api.example.com");
        assert_eq!(h.ttl_ms, hooks::DEFAULT_TTL_MS);
        match h.action {
            HookAction::Exec {
                cmd,
                extract,
                inject,
            } => {
                assert_eq!(cmd, "curl -s https://api.example.com/login");
                assert_eq!(extract, r#""token":"([^"]+)""#);
                assert_eq!(
                    inject.kind,
                    HookInjectKind::SetHeader,
                    "add-or-replace, so a request with NO auth header gets one"
                );
                assert_eq!(inject.name, "Authorization");
                assert_eq!(inject.value_template, "Bearer {}");
            }
            other => panic!("{other:?}"),
        }

        // Un-scoped profiles are named `auth:*` and match every host.
        let h = build_auth_hook("", "login.sh", "(t)", "X-Token: {}").unwrap();
        assert_eq!(h.name, "auth:*");
        assert!(h.scope.host.is_empty());

        // The validation is `hook add`'s, so nothing that could never work gets
        // in: no capture group, no placeholder, an empty login.
        assert!(build_auth_hook("h", "login.sh", r#""t":"[^"]+""#, "A: {}").is_err());
        assert!(build_auth_hook("h", "login.sh", "(t)", "A: bare").is_err());
        assert!(build_auth_hook("h", "   ", "(t)", "A: {}").is_err());
    }

    /// THE gain over the match/replace rule this replaces, end to end through
    /// the real engine: a request that sends no `Authorization` at all comes out
    /// carrying one.
    #[tokio::test]
    async fn the_injected_header_is_added_when_the_request_has_none() {
        use burpwn_proxy::hooks::{HookEngine, HookRunner};
        use burpwn_proxy::matchreplace::Message;
        use std::sync::Arc;
        use std::time::Duration;

        struct Login;
        #[async_trait::async_trait]
        impl HookRunner for Login {
            async fn run(&self, _cmd: &str, _budget: Duration) -> Result<String> {
                Ok(r#"{"token":"fresh-token"}"#.to_string())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let store = Store::open(paths.session_db("default")).unwrap();
        auth_set(
            &store,
            "api.example.com",
            "login.sh",
            r#""token":"([^"]+)""#,
            "Authorization: Bearer {}",
        )
        .await
        .unwrap();

        let engine = HookEngine::new();
        engine.set_runner(Arc::new(Login));
        engine.set_hooks(store.reader().list_hooks().unwrap());

        // A request with NO auth header — what the old `^Authorization:.*` rule
        // could not touch, which is why the first call of a session 401'd.
        let mut msg = Message {
            host: "api.example.com".into(),
            url: "/v1/me".into(),
            headers: b"host: api.example.com\r\n".to_vec(),
            body: Vec::new(),
        };
        assert!(engine.pre_request(None, "GET", &mut msg).await.changed);
        let headers = String::from_utf8(msg.headers).unwrap();
        assert!(
            headers.contains("Authorization: Bearer fresh-token"),
            "the header must be ADDED, not merely replaced: {headers}"
        );

        // And a STALE header is still overwritten (the half that did work).
        let mut msg = Message {
            host: "api.example.com".into(),
            url: "/v1/me".into(),
            headers: b"host: api.example.com\r\nauthorization: Bearer stale\r\n".to_vec(),
            body: Vec::new(),
        };
        assert!(engine.pre_request(None, "GET", &mut msg).await.changed);
        let headers = String::from_utf8(msg.headers).unwrap();
        assert!(
            headers.contains("Authorization: Bearer fresh-token"),
            "{headers}"
        );
        assert!(!headers.contains("stale"), "{headers}");

        // Out of scope: another host is left alone.
        let mut msg = Message {
            host: "other.test".into(),
            url: "/".into(),
            headers: b"host: other.test\r\n".to_vec(),
            body: Vec::new(),
        };
        assert!(!engine.pre_request(None, "GET", &mut msg).await.changed);
    }

    /// Re-`set`ting a host must UPDATE its profile, never stack a second login
    /// command onto every request.
    #[tokio::test]
    async fn auth_set_is_idempotent_per_host() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let store = Store::open(paths.session_db("default")).unwrap();

        for cmd in ["login-v1.sh", "login-v2.sh", "login-v3.sh"] {
            auth_set(
                &store,
                "api.example.com",
                cmd,
                r#""token":"([^"]+)""#,
                "Authorization: Bearer {}",
            )
            .await
            .unwrap();
        }
        // A profile for ANOTHER host is a different name, so it coexists.
        auth_set(&store, "other.test", "other.sh", "(t)", "X-Token: {}")
            .await
            .unwrap();

        let profiles = auth_hooks(&store).unwrap();
        assert_eq!(profiles.len(), 2, "one hook per host, not one per set");
        let api = profiles
            .iter()
            .find(|h| h.name == "auth:api.example.com")
            .unwrap();
        assert!(
            matches!(&api.action, HookAction::Exec { cmd, .. } if cmd == "login-v3.sh"),
            "the last set wins: {:?}",
            api.action
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
}
