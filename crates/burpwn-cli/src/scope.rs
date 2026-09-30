//! `burpwn scope`: the network scope (allowlist / denylist of destinations),
//! shared by the CLI and the MCP tools so both validate, store and answer the
//! same way.
//!
//! Rules live in the session store (`scope_rules`); the proxy daemon re-reads
//! them every two seconds and enforces them before any upstream contact (see
//! `burpwn_proxy::scope` for the matching and evaluation semantics). The same
//! rules hold `req replay` and `fuzz` through [`check_replay`].
//!
//! Not to be confused with `intercept scope`, which only selects the flows the
//! interceptor parks and never blocks anything.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};

use burpwn_error::ErrorCode;
use burpwn_proxy::scope::{
    ConnCheck, HostPattern, Identity, Pattern, ReplayScope, RuleRef, RuleSet, Target, Verdict,
};
use burpwn_store::model::{NewScopeRule, ScopeClearTarget, ScopeKind, ScopeRule, Workspace};
use burpwn_store::schema::DEFAULT_WORKSPACE_ID;
use burpwn_store::Store;

/// Validate and normalize one pattern, as an operator-facing error.
pub fn normalize_pattern(raw: &str) -> Result<Pattern> {
    Pattern::parse(raw).map_err(|e| {
        crate::coded!(
            ErrorCode::InputBadScopePattern,
            "invalid scope pattern: {e}"
        )
    })
}

/// Parse `allow` / `deny`.
pub fn parse_kind(raw: &str) -> Result<ScopeKind> {
    ScopeKind::parse(&raw.trim().to_ascii_lowercase()).ok_or_else(|| {
        crate::coded!(
            ErrorCode::InputInvalidValue,
            "scope kind must be allow|deny, got {raw:?}"
        )
    })
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Find a workspace by NAME (exact, case-sensitive, like `workspace use`).
fn find_workspace(store: &Store, name: &str) -> Result<Option<Workspace>> {
    Ok(store
        .reader()
        .list_workspaces()?
        .into_iter()
        .find(|w| w.name == name))
}

/// Resolve an existing workspace NAME, or fail with `WorkspaceNotFound`.
fn existing_workspace(store: &Store, name: &str) -> Result<Workspace> {
    match find_workspace(store, name)? {
        Some(w) => Ok(w),
        None => crate::fail!(ErrorCode::WorkspaceNotFound, "no such workspace: {name}"),
    }
}

/// Resolve a workspace NAME, creating it when missing (the `exec --workspace`
/// semantics: rules can be staged for a workspace before its first capture).
async fn workspace_or_create(store: &Store, name: &str) -> Result<i64> {
    if name.trim().is_empty() {
        crate::fail!(
            ErrorCode::InputInvalidValue,
            "--workspace needs a name (omit it for a global rule)"
        );
    }
    if let Some(w) = find_workspace(store, name)? {
        return Ok(w.id);
    }
    Ok(store
        .writer()
        .create_workspace(name.to_string(), now_millis())
        .await?)
}

/// `global` or the workspace name, as a rule's scope label.
fn scope_label(rule: &ScopeRule) -> String {
    match (&rule.workspace, rule.workspace_id) {
        (Some(name), _) => name.clone(),
        (None, Some(id)) => format!("workspace #{id}"),
        (None, None) => "global".into(),
    }
}

/// JSON view of one stored rule.
pub fn rule_json(rule: &ScopeRule) -> Value {
    json!({
        "id": rule.id,
        "kind": rule.kind,
        "pattern": rule.pattern,
        "scope": scope_label(rule),
        "workspace_id": rule.workspace_id,
        "created_at": rule.created_at,
    })
}

/// `scope allow|deny`: validate EVERY pattern first (one bad pattern stores
/// nothing), then add each idempotently. Returns
/// `{"rules": [{id, kind, pattern, scope, workspace_id, created}]}`.
pub async fn add(
    store: &Store,
    kind: ScopeKind,
    patterns: &[String],
    workspace: Option<&str>,
) -> Result<Value> {
    if patterns.is_empty() {
        crate::fail!(
            ErrorCode::InputMissingSelection,
            "give at least one pattern (host, *.host, IP or CIDR, optional :port)"
        );
    }
    let normalized: Vec<String> = patterns
        .iter()
        .map(|p| normalize_pattern(p).map(|p| p.to_string()))
        .collect::<Result<_>>()?;
    let workspace_id = match workspace {
        Some(name) => Some(workspace_or_create(store, name).await?),
        None => None,
    };
    let scope = workspace
        .map(str::to_string)
        .unwrap_or_else(|| "global".into());
    let mut rules = Vec::new();
    for pattern in normalized {
        let (id, created) = store
            .writer()
            .add_scope_rule(NewScopeRule {
                workspace_id,
                kind,
                pattern: pattern.clone(),
            })
            .await?;
        rules.push(json!({
            "id": id,
            "kind": kind,
            "pattern": pattern,
            "scope": scope,
            "workspace_id": workspace_id,
            "created": created,
        }));
    }
    Ok(json!({ "rules": rules }))
}

/// `scope list`: every rule, or — with a workspace — its EFFECTIVE set (the
/// global rules plus its own). Returns `{"workspace": name|null, "rules": [...]}`.
pub fn list(store: &Store, workspace: Option<&str>) -> Result<Value> {
    let rows = store.reader().list_scope_rules()?;
    let rows: Vec<&ScopeRule> = match workspace {
        None => rows.iter().collect(),
        Some(name) => {
            let ws = existing_workspace(store, name)?;
            rows.iter()
                .filter(|r| r.workspace_id.is_none() || r.workspace_id == Some(ws.id))
                .collect()
        }
    };
    let rules: Vec<Value> = rows.into_iter().map(rule_json).collect();
    Ok(json!({ "workspace": workspace, "rules": rules }))
}

/// `scope rm`: every id must exist (checked first, so a typo removes nothing).
/// Returns `{"removed": [ids]}`.
pub async fn rm(store: &Store, ids: &[i64]) -> Result<Value> {
    if ids.is_empty() {
        crate::fail!(
            ErrorCode::InputMissingSelection,
            "give at least one rule id"
        );
    }
    let existing = store.reader().list_scope_rules()?;
    for id in ids {
        if !existing.iter().any(|r| r.id == *id) {
            crate::fail!(ErrorCode::InputNoSuchScopeRule, "no such scope rule: {id}");
        }
    }
    let mut removed = Vec::new();
    for id in ids {
        if store.writer().delete_scope_rule(*id).await? && !removed.contains(id) {
            removed.push(*id);
        }
    }
    Ok(json!({ "removed": removed }))
}

/// `scope clear`: the global rules (default), one workspace's OWN rules, or
/// every rule; optionally one kind only. Returns
/// `{"removed": n, "target": "global"|"workspace"|"all", "workspace": name|null, "kind": kind|null}`.
pub async fn clear(
    store: &Store,
    workspace: Option<&str>,
    all: bool,
    kind: Option<ScopeKind>,
) -> Result<Value> {
    let (target, label) = match (workspace, all) {
        (Some(_), true) => crate::fail!(
            ErrorCode::InputInvalidValue,
            "--workspace and --all are mutually exclusive"
        ),
        (Some(name), false) => (
            ScopeClearTarget::Workspace(existing_workspace(store, name)?.id),
            "workspace",
        ),
        (None, true) => (ScopeClearTarget::All, "all"),
        (None, false) => (ScopeClearTarget::Global, "global"),
    };
    let removed = store.writer().clear_scope_rules(target, kind).await?;
    Ok(json!({
        "removed": removed,
        "target": label,
        "workspace": workspace,
        "kind": kind,
    }))
}

/// A `scope test` target: one host or one IP, with an optional port.
fn parse_target(raw: &str) -> Result<(Identity, Option<u16>)> {
    let p = normalize_pattern(raw)?;
    let id = match &p.target {
        Target::Host(HostPattern::Exact(h)) => Identity::Name(h.clone()),
        Target::Net(net) => match net.address() {
            Some(ip) => Identity::Ip(ip),
            None => crate::fail!(
                ErrorCode::InputBadScopePattern,
                "a test target is one host or IP (with an optional :port), not a network: {raw:?}"
            ),
        },
        Target::Host(HostPattern::Subtree(_)) => crate::fail!(
            ErrorCode::InputBadScopePattern,
            "a test target is one host or IP (with an optional :port), not a wildcard: {raw:?}"
        ),
    };
    Ok((id, p.port))
}

fn verdict_json(v: &Verdict) -> Value {
    json!({
        "verdict": if v.allowed { "allowed" } else { "blocked" },
        "allowed": v.allowed,
        "reason": v.reason,
        "rule": v.rule.as_ref().map(rule_ref_json),
    })
}

fn rule_ref_json(r: &RuleRef) -> Value {
    json!({ "id": r.id, "kind": r.kind, "pattern": r.pattern, "scope": r.scope })
}

/// Load and parse the session's rules.
fn load_rules(store: &Store) -> Result<RuleSet> {
    let rows = store.reader().list_scope_rules()?;
    RuleSet::from_store(&rows).map_err(|e| {
        crate::coded!(
            ErrorCode::InputBadScopePattern,
            "the session's network scope cannot be loaded ({e}); fix it with `burpwn scope rm <id>`"
        )
    })
}

/// `scope test`: pure evaluation, nothing is resolved or sent.
///
/// A HOST target is evaluated as a connection burpwn itself resolved that name
/// for (explicit proxy / replay): the name both declares and justifies the
/// destination. Its IP is unknown here, so IP/CIDR rules cannot justify it
/// (`note` says so when such rules exist; test the address instead). Live, a
/// named connection IS accepted by an IP/CIDR allow rule when the name is bound
/// to the destination (the sandbox's DNS resolved it there, or burpwn resolved
/// it itself) — which `scope test` cannot observe, hence the note. A host
/// target also gets the verdict of a DNS query for it (`dns`). An IP target is
/// a connection to that address declaring no name. Without a port, only the
/// rules without a port constraint apply.
///
/// Returns `{"target", "workspace", "kind": "host"|"ip", "port", "verdict",
/// "allowed", "reason", "rule", "dns", "note"}`.
pub fn test(store: &Store, target: &str, workspace: Option<&str>) -> Result<Value> {
    let (identity, port) = parse_target(target)?;
    let (ws_id, ws_name) = match workspace {
        Some(name) => {
            let w = existing_workspace(store, name)?;
            (w.id, w.name)
        }
        None => (DEFAULT_WORKSPACE_ID, "default".to_string()),
    };
    let rules = load_rules(store)?;
    let (conn, dns, note, kind) = match &identity {
        Identity::Name(name) => {
            let declared = [identity.clone()];
            let conn = rules.check_conn(
                ws_id,
                &ConnCheck {
                    dst_ip: None,
                    dst_port: port,
                    declared: &declared,
                    resolved_name: Some(name),
                    cache_names: &[],
                },
            );
            let dns = rules.check_dns(ws_id, name);
            let has_ip_allow = rules
                .for_workspace(ws_id)
                .any(|r| r.kind == ScopeKind::Allow && !r.pattern.is_host());
            // Only relevant when the allowlist (not a deny rule) decided.
            let note = (!conn.allowed && conn.rule.is_none() && has_ip_allow).then(|| {
                "IP/CIDR allow rules were not evaluated: a host target is not resolved by \
                 `scope test`. Live, this name is allowed when the address it resolves to (via \
                 the sandbox's DNS, or burpwn's own lookup) matches an IP/CIDR allow rule; test \
                 that address to check it"
                    .to_string()
            });
            (conn, Some(dns), note, "host")
        }
        Identity::Ip(ip) => {
            let conn = rules.check_conn(
                ws_id,
                &ConnCheck {
                    dst_ip: Some(*ip),
                    dst_port: port,
                    declared: &[],
                    resolved_name: None,
                    cache_names: &[],
                },
            );
            (conn, None, None, "ip")
        }
    };
    let mut out = verdict_json(&conn);
    let obj = out.as_object_mut().expect("verdict_json builds an object");
    obj.insert("target".into(), json!(target.trim()));
    obj.insert("workspace".into(), json!(ws_name));
    obj.insert("kind".into(), json!(kind));
    obj.insert("port".into(), json!(port));
    obj.insert(
        "dns".into(),
        dns.as_ref().map(verdict_json).unwrap_or(Value::Null),
    );
    obj.insert("note".into(), json!(note));
    Ok(out)
}

/// Hold a request burpwn is about to send itself (`req replay`, `fuzz`) to the
/// scope of the flow's workspace: `host` is what it declares (SNI / `Host`),
/// `dst` the address it will dial. Nothing is sent when this fails.
///
/// The recorded destination is justified by an allow host rule only if `host`
/// really resolves to it: that lookup happens only when needed, and only for a
/// name the scope would let resolve (a refused name is never looked up).
///
/// Returns the [`ReplayScope`] a per-request sender re-checks with (`None`
/// when the session has no rule at all).
pub async fn check_replay(
    store: &Store,
    workspace_id: i64,
    flow_id: i64,
    host: &str,
    dst: SocketAddr,
) -> Result<Option<ReplayScope>> {
    let rules = load_rules(store)?;
    if rules.is_empty() {
        return Ok(None);
    }
    let mut scope = ReplayScope {
        rules: Arc::new(rules),
        workspace_id,
        dst_ip: dst.ip(),
        dst_port: dst.port(),
        resolved_name: None,
    };
    let mut verdict = scope.check(&[host]);
    if !verdict.allowed {
        if let Some(Identity::Name(name)) = Identity::from_authority(host) {
            let denied = verdict
                .rule
                .as_ref()
                .is_some_and(|r| r.kind == ScopeKind::Deny);
            if !denied && scope.rules.check_dns(workspace_id, &name).allowed {
                let resolves_there = tokio::net::lookup_host((name.as_str(), dst.port()))
                    .await
                    .map(|mut addrs| addrs.any(|a| same_ip(a.ip(), dst.ip())))
                    .unwrap_or(false);
                if resolves_there {
                    scope.resolved_name = Some(name);
                    verdict = scope.check(&[host]);
                }
            }
        }
    }
    if let Some(reason) = verdict.blocked_reason() {
        crate::fail!(
            ErrorCode::NetworkBlockedByScope,
            "flow {flow_id}: {host} ({dst}) is outside the network scope ({reason}); nothing was sent"
        );
    }
    Ok(Some(scope))
}

/// Address equality that treats an IPv4-mapped IPv6 address as its IPv4 form.
fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    canon(a) == canon(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path().join("session.db")).unwrap();
        (dir, store)
    }

    fn code_of(e: &anyhow::Error) -> ErrorCode {
        crate::diag::diagnose(e).code
    }

    #[tokio::test]
    async fn add_normalizes_dedupes_and_creates_the_workspace() {
        let (_d, s) = store();
        let v = add(&s, ScopeKind::Allow, &["*.TOTO.fr.".into()], None)
            .await
            .unwrap();
        assert_eq!(v["rules"][0]["pattern"], "*.toto.fr");
        assert_eq!(v["rules"][0]["scope"], "global");
        assert_eq!(v["rules"][0]["created"], true);
        let again = add(&s, ScopeKind::Allow, &["*.toto.fr".into()], None)
            .await
            .unwrap();
        assert_eq!(again["rules"][0]["id"], v["rules"][0]["id"]);
        assert_eq!(again["rules"][0]["created"], false);

        let w = add(&s, ScopeKind::Deny, &["10.0.0.0/8".into()], Some("target"))
            .await
            .unwrap();
        assert_eq!(w["rules"][0]["scope"], "target");
        assert!(find_workspace(&s, "target").unwrap().is_some());

        // One bad pattern stores nothing.
        let e = add(&s, ScopeKind::Allow, &["ok.fr".into(), "*".into()], None)
            .await
            .unwrap_err();
        assert_eq!(code_of(&e), ErrorCode::InputBadScopePattern);
        assert_eq!(s.reader().list_scope_rules().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_effective_rm_and_clear() {
        let (_d, s) = store();
        add(&s, ScopeKind::Allow, &["toto.fr".into()], None)
            .await
            .unwrap();
        add(&s, ScopeKind::Allow, &["a.fr".into()], Some("w1"))
            .await
            .unwrap();
        add(&s, ScopeKind::Deny, &["b.fr".into()], Some("w2"))
            .await
            .unwrap();

        let all = list(&s, None).unwrap();
        assert_eq!(all["rules"].as_array().unwrap().len(), 3);
        let eff = list(&s, Some("w1")).unwrap();
        let pats: Vec<&str> = eff["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["pattern"].as_str().unwrap())
            .collect();
        assert_eq!(pats, vec!["toto.fr", "a.fr"]);
        assert_eq!(
            code_of(&list(&s, Some("nope")).unwrap_err()),
            ErrorCode::WorkspaceNotFound
        );

        let e = rm(&s, &[1, 999]).await.unwrap_err();
        assert_eq!(code_of(&e), ErrorCode::InputNoSuchScopeRule);
        assert_eq!(
            s.reader().list_scope_rules().unwrap().len(),
            3,
            "nothing removed"
        );
        assert_eq!(rm(&s, &[1]).await.unwrap()["removed"], json!([1]));

        let c = clear(&s, None, false, None).await.unwrap();
        assert_eq!(c["removed"], 0, "no global rule left");
        let c = clear(&s, Some("w1"), false, None).await.unwrap();
        assert_eq!(c["removed"], 1);
        let c = clear(&s, None, true, Some(ScopeKind::Allow)).await.unwrap();
        assert_eq!(c["removed"], 0);
        let c = clear(&s, None, true, None).await.unwrap();
        assert_eq!(c["removed"], 1);
    }

    #[tokio::test]
    async fn test_reports_verdicts_and_rules() {
        let (_d, s) = store();
        add(&s, ScopeKind::Allow, &["*.toto.fr".into()], None)
            .await
            .unwrap();
        add(&s, ScopeKind::Deny, &["admin.toto.fr".into()], None)
            .await
            .unwrap();

        let v = test(&s, "api.toto.fr:443", None).unwrap();
        assert_eq!(v["verdict"], "allowed");
        assert_eq!(v["rule"]["pattern"], "*.toto.fr");
        assert_eq!(v["dns"]["verdict"], "allowed");
        assert_eq!(v["workspace"], "default");
        assert_eq!(v["port"], 443);

        let v = test(&s, "admin.toto.fr", None).unwrap();
        assert_eq!(v["verdict"], "blocked");
        assert_eq!(v["rule"]["kind"], "deny");

        let v = test(&s, "nottoto.fr", None).unwrap();
        assert_eq!(v["verdict"], "blocked");
        assert!(v["reason"]
            .as_str()
            .unwrap()
            .starts_with("not in allowlist"));
        assert_eq!(v["dns"]["verdict"], "blocked");

        let v = test(&s, "[2001:db8::1]:443", None).unwrap();
        assert_eq!(v["kind"], "ip");
        assert_eq!(v["verdict"], "blocked");
        assert!(v["dns"].is_null());

        for bad in ["*.toto.fr", "10.0.0.0/8", "*"] {
            let e = test(&s, bad, None).unwrap_err();
            assert_eq!(code_of(&e), ErrorCode::InputBadScopePattern, "{bad}");
        }

        // IP-only allowlist: a host target cannot be judged without its
        // address; the note explains the live rule, DNS lets it resolve.
        clear(&s, None, true, None).await.unwrap();
        add(&s, ScopeKind::Allow, &["10.0.0.0/8".into()], None)
            .await
            .unwrap();
        let v = test(&s, "intranet.corp", None).unwrap();
        assert_eq!(v["verdict"], "blocked");
        assert_eq!(v["dns"]["verdict"], "allowed");
        let note = v["note"].as_str().unwrap();
        assert!(note.contains("IP/CIDR allow rule"), "{note}");
        assert!(note.contains("resolves to"), "{note}");
        assert_eq!(
            test(&s, "10.1.2.3:443", None).unwrap()["verdict"],
            "allowed"
        );
    }

    #[tokio::test]
    async fn replay_check_blocks_before_sending() {
        let (_d, s) = store();
        // No rules: nothing to hold.
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(check_replay(&s, 1, 1, "evil.test", dst)
            .await
            .unwrap()
            .is_none());

        add(&s, ScopeKind::Deny, &["evil.test".into()], None)
            .await
            .unwrap();
        let e = check_replay(&s, 1, 7, "evil.test", dst).await.unwrap_err();
        assert_eq!(code_of(&e), ErrorCode::NetworkBlockedByScope);
        assert!(e.to_string().contains("flow 7"), "{e}");

        // Allowlist on the IP: an undeclared-name replay to it passes, a
        // spoofed Host does not.
        clear(&s, None, true, None).await.unwrap();
        add(&s, ScopeKind::Allow, &["127.0.0.0/8".into()], None)
            .await
            .unwrap();
        assert!(check_replay(&s, 1, 1, "127.0.0.1", dst)
            .await
            .unwrap()
            .is_some());
        let e = check_replay(&s, 1, 1, "evil.test", dst).await.unwrap_err();
        assert_eq!(code_of(&e), ErrorCode::NetworkBlockedByScope);
        // …but a name that really resolves to the allowed address is bound to
        // it (replay's own lookup), so an IP-only allowlist lets it through.
        let scope = check_replay(&s, 1, 1, "localhost:9", dst)
            .await
            .unwrap()
            .expect("rules exist");
        assert_eq!(scope.resolved_name.as_deref(), Some("localhost"));
        // The per-request re-check (fuzz) keeps refusing a Host that never
        // resolved there.
        assert!(scope.check(&["localhost", "localhost:9"]).allowed);
        assert!(!scope.check(&["localhost", "evil.test"]).allowed);
        // `localhost` resolves to the recorded loopback destination, which the
        // allow host rule then justifies.
        clear(&s, None, true, None).await.unwrap();
        add(&s, ScopeKind::Allow, &["localhost".into()], None)
            .await
            .unwrap();
        assert!(check_replay(&s, 1, 1, "localhost", dst)
            .await
            .unwrap()
            .is_some());
    }
}
