//! Network scope: allow/deny destination patterns enforced BEFORE any upstream
//! contact.
//!
//! A pattern names a destination: an exact host (`toto.fr`), a host and every
//! subdomain (`*.toto.fr`, which also matches the apex), an IP (`10.0.0.5`,
//! `2001:db8::1`) or a CIDR (`10.0.0.0/8`), each with an optional port suffix
//! (`toto.fr:8443`, `[2001:db8::1]:443`). Patterns are validated and normalized
//! by [`Pattern::parse`] when they are added, so the store only ever holds the
//! canonical spelling and two spellings of one destination are one rule.
//!
//! # Evaluation
//!
//! The rules considered for a flow in workspace `W` are the global rules plus
//! `W`'s own ([`RuleSet::for_workspace`]). Then:
//!
//! 1. any DENY rule matching any identity of the flow blocks it;
//! 2. else, if at least one ALLOW rule is considered, the flow must pass the
//!    allow check, or it is blocked ("not in allowlist");
//! 3. else it is allowed.
//!
//! The identities of a CONNECTION are the names it declares (HTTP `Host` /
//! `:authority`, TLS SNI), the name burpwn itself resolved to reach it (explicit
//! proxy, replay), the names the DNS shim saw resolve to its destination IP
//! ([`DnsCache`]) and the destination IP + port.
//!
//! Deny rules on names see the declared names and the name burpwn resolved;
//! the DNS-cache names of the destination are consulted by deny rules ONLY for
//! a connection that declares no name at all (raw TCP, SNI-less TLS). A shared
//! CDN address that once answered for a denied tracker must not take down
//! every allowed site that lives on the same address.
//!
//! The allow check trusts the destination, not the declarations: the upstream
//! socket goes to `dst_ip:dst_port` whatever the `Host` header says. So the
//! destination must be JUSTIFIED (its IP matches an allow IP/CIDR rule, or a
//! name that resolved to it matches an allow host rule) AND every declared name
//! must be acceptable. A declared name is acceptable when it matches an allow
//! host rule, OR when the destination is justified by an allow IP/CIDR rule and
//! the name is BOUND to that address: the DNS cache saw it resolve there, or it
//! is the name burpwn itself resolved to reach it. So an IP-only allowlist
//! (`allow 10.0.0.0/8`) lets `https://intranet.corp` through when
//! `intranet.corp` really resolved into `10/8`, and `Host: evil.com` sent to an
//! allowed (shared-CDN) IP that `evil.com` never resolved to is still refused.
//!
//! A DNS QUERY is checked against host rules only. Deny rules carrying a port
//! (`deny evil.com:8443`) are skipped there — they restrict one port, and the
//! connection check enforces them — while an allow rule's port is ignored: a
//! matching deny rule, or an allowlist of host rules that none matches, makes
//! the shim answer `REFUSED` without forwarding the query. An allowlist with no
//! host rule at all (IP-only) lets names resolve: the connection check then
//! decides on the IP.
//!
//! # Whose traffic
//!
//! Every connection is evaluated for the workspace stamped in its wire header
//! (`PassedConn::workspace_id`); the explicit-proxy front-end uses the proxy's
//! configured workspace (1, `default`). A hook `exec` command runs in the
//! sandbox under the workspace of the flow that TRIGGERED it, so its own
//! traffic is held to the global rules plus that workspace's — it is NOT
//! exempt, and a hook fired from `audit` cannot reach what `audit` refuses.
//!
//! # Matching is strict
//!
//! `*.toto.fr` matches `toto.fr` and `a.b.toto.fr`, and NOT `nottoto.fr` nor
//! `toto.fr.evil.com`: it is a label-suffix test, never a substring test (which
//! is what the match/replace host glob does, and why it is not reused here).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use burpwn_store::model::{ScopeKind, ScopeRule};

/// The host part of a host pattern, normalized (lowercase, no trailing dot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Matches exactly this name.
    Exact(String),
    /// `*.suffix`: matches `suffix` itself and every name under it.
    Subtree(String),
}

/// An IP network with its host bits cleared. A single address is a network of
/// full length (`/32`, `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Build a network, clearing the host bits of `addr`. `None` when the
    /// prefix is longer than the address family allows.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Cidr> {
        // An IPv4-mapped IPv6 network is an IPv4 network: store it as one so a
        // v4 destination matches it.
        let (addr, prefix) = match addr {
            IpAddr::V6(v6) if prefix >= 96 => match v6.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), prefix - 96),
                None => (addr, prefix),
            },
            _ => (addr, prefix),
        };
        let net = match addr {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return None;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                IpAddr::V4((u32::from(v4) & mask).into())
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return None;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6((u128::from(v6) & mask).into())
            }
        };
        Some(Cidr { net, prefix })
    }

    /// Whether `ip` is inside this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match Cidr::new(canonical_ip(ip), self.prefix) {
            Some(c) => c.net == self.net,
            None => false,
        }
    }

    /// The address, when this network is one single address.
    pub fn address(&self) -> Option<IpAddr> {
        self.is_single().then_some(self.net)
    }

    /// Whether this network is one single address.
    fn is_single(&self) -> bool {
        match self.net {
            IpAddr::V4(_) => self.prefix == 32,
            IpAddr::V6(_) => self.prefix == 128,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.net)
        } else {
            write!(f, "{}/{}", self.net, self.prefix)
        }
    }
}

/// What a pattern designates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A host name (exact or subtree).
    Host(HostPattern),
    /// An IP address or network.
    Net(Cidr),
}

/// A validated, normalized scope pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// The destination.
    pub target: Target,
    /// `None` = any port.
    pub port: Option<u16>,
}

/// Why a pattern (or a `scope test` target) was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PatternError(String);

fn perr(msg: impl Into<String>) -> PatternError {
    PatternError(msg.into())
}

impl Pattern {
    /// Parse and normalize a pattern: `host`, `*.host`, IP, CIDR, each with an
    /// optional `:port` (`[v6]:port` / `[v6/len]:port` for IPv6).
    pub fn parse(input: &str) -> Result<Pattern, PatternError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(perr("empty scope pattern"));
        }
        let (body, port, bracketed) = split_port(s)?;
        if body == "*" {
            return Err(perr(
                "a bare `*` would match everything: to lift the allowlist, remove its rules \
                 with `burpwn scope clear` instead",
            ));
        }
        if let Some((addr, len)) = body.split_once('/') {
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| perr(format!("{input:?}: {addr:?} is not an IP address")))?;
            let len: u8 = len
                .parse()
                .map_err(|_| perr(format!("{input:?}: {len:?} is not a prefix length")))?;
            // Brackets are checked on the address AS WRITTEN: `[::ffff:10.0.0.0/104]`
            // is a legitimate IPv6 spelling even though it is stored as IPv4.
            check_brackets(input, bracketed, ip)?;
            let net = Cidr::new(ip, len)
                .ok_or_else(|| perr(format!("{input:?}: prefix /{len} is too long")))?;
            return Ok(Pattern {
                target: Target::Net(net),
                port,
            });
        }
        if let Ok(ip) = body.parse::<IpAddr>() {
            check_brackets(input, bracketed, ip)?;
            let full = if ip.is_ipv4() { 32 } else { 128 };
            let net = Cidr::new(ip, full).expect("full-length prefix is valid");
            return Ok(Pattern {
                target: Target::Net(net),
                port,
            });
        }
        if bracketed {
            return Err(perr(format!(
                "{input:?}: brackets are only for IPv6 addresses (`[2001:db8::1]:443`)"
            )));
        }
        let name = normalize_name(body);
        let host = match name.strip_prefix("*.") {
            Some(rest) => {
                validate_host(input, rest)?;
                HostPattern::Subtree(rest.to_string())
            }
            None => {
                validate_host(input, &name)?;
                HostPattern::Exact(name)
            }
        };
        Ok(Pattern {
            target: Target::Host(host),
            port,
        })
    }

    /// Whether this is a host (name) pattern rather than an IP/CIDR one.
    pub fn is_host(&self) -> bool {
        matches!(self.target, Target::Host(_))
    }

    /// Whether the rule's port constraint admits `port`. An unknown port
    /// (`None`) only satisfies a rule without a port constraint.
    fn port_ok(&self, port: Option<u16>) -> bool {
        match self.port {
            None => true,
            Some(p) => port == Some(p),
        }
    }

    /// Whether this (host) pattern matches a normalized name.
    fn matches_name(&self, name: &str) -> bool {
        match &self.target {
            Target::Host(HostPattern::Exact(h)) => name == h,
            Target::Host(HostPattern::Subtree(s)) => {
                name == s
                    || (name.len() > s.len()
                        && name.ends_with(s.as_str())
                        && name.as_bytes()[name.len() - s.len() - 1] == b'.')
            }
            Target::Net(_) => false,
        }
    }

    /// Whether this (IP/CIDR) pattern matches an address.
    fn matches_ip(&self, ip: IpAddr) -> bool {
        match &self.target {
            Target::Net(net) => net.contains(ip),
            Target::Host(_) => false,
        }
    }

    /// Whether this pattern matches an identity (name vs host rules, IP vs
    /// IP rules).
    fn matches_identity(&self, id: &Identity) -> bool {
        match id {
            Identity::Name(n) => self.matches_name(n),
            Identity::Ip(ip) => self.matches_ip(*ip),
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = match &self.target {
            Target::Host(HostPattern::Exact(h)) => h.clone(),
            Target::Host(HostPattern::Subtree(s)) => format!("*.{s}"),
            Target::Net(net) => net.to_string(),
        };
        match self.port {
            None => f.write_str(&body),
            Some(p) => match &self.target {
                Target::Net(Cidr {
                    net: IpAddr::V6(_), ..
                }) => write!(f, "[{body}]:{p}"),
                _ => write!(f, "{body}:{p}"),
            },
        }
    }
}

/// Split an optional port off a pattern: `(body, port, bracketed)`.
fn split_port(s: &str) -> Result<(&str, Option<u16>, bool), PatternError> {
    if let Some(rest) = s.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return Err(perr(format!("{s:?}: unbalanced `[`")));
        };
        let port = match after {
            "" => None,
            p => match p.strip_prefix(':') {
                Some(p) => Some(parse_port(s, p)?),
                None => return Err(perr(format!("{s:?}: expected `:port` after `]`"))),
            },
        };
        return Ok((inner, port, true));
    }
    match s.matches(':').count() {
        0 => Ok((s, None, false)),
        1 => {
            let (body, p) = s.split_once(':').expect("one colon");
            Ok((body, Some(parse_port(s, p)?), false))
        }
        // Two or more colons: a bare IPv6 address (a port on one needs brackets).
        _ => Ok((s, None, false)),
    }
}

fn parse_port(input: &str, p: &str) -> Result<u16, PatternError> {
    match p.parse::<u16>() {
        Ok(port) if port != 0 && p.bytes().all(|b| b.is_ascii_digit()) => Ok(port),
        _ => Err(perr(format!(
            "{input:?}: {p:?} is not a port (1-65535; IPv6 with a port needs brackets: \
             `[2001:db8::1]:443`)"
        ))),
    }
}

/// Brackets go with IPv6 and nothing else. `ip` is the address as written,
/// before an IPv4-mapped IPv6 address is folded to IPv4.
fn check_brackets(input: &str, bracketed: bool, ip: IpAddr) -> Result<(), PatternError> {
    if bracketed && ip.is_ipv4() {
        return Err(perr(format!(
            "{input:?}: brackets are only for IPv6 addresses (`[2001:db8::1]:443`)"
        )));
    }
    Ok(())
}

/// Validate a normalized host name (no wildcard left in it).
fn validate_host(input: &str, name: &str) -> Result<(), PatternError> {
    if name.contains('*') {
        return Err(perr(format!(
            "{input:?}: `*` is only allowed as the whole leftmost label (`*.example.com`)"
        )));
    }
    if name.is_empty() || name.len() > 253 {
        return Err(perr(format!("{input:?}: not a valid host name")));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(perr(format!(
                "{input:?}: not a valid host name (empty or over-long label)"
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(perr(format!(
                "{input:?}: not a valid host name (use letters, digits, `-`, `_`; punycode \
                 for internationalized names)"
            )));
        }
    }
    let last = name.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(perr(format!(
            "{input:?}: looks like an IP address but is not a valid one"
        )));
    }
    Ok(())
}

/// Normalize a DNS name for comparison: lowercase, one trailing dot removed
/// (DNS question names are fully qualified).
pub fn normalize_name(name: &str) -> String {
    let n = name.trim();
    let n = n.strip_suffix('.').unwrap_or(n);
    n.to_ascii_lowercase()
}

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, what a dual-stack socket
/// reports for a v4 peer) are compared as the IPv4 address they carry.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// One identity a flow presents: a name or an address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity {
    /// A (normalized) host name.
    Name(String),
    /// An IP literal.
    Ip(IpAddr),
}

impl Identity {
    /// Parse a declared authority (`host`, `host:port`, `[v6]:port`, `[v6]`, a
    /// bare IPv6, an IP) into an identity, dropping any userinfo and port.
    /// `None` for an empty value.
    ///
    /// Userinfo is everything up to the LAST `@` (`allowed.com:443@evil.com`
    /// names `evil.com`, which is the host an URL parser dials).
    pub fn from_authority(raw: &str) -> Option<Identity> {
        let s = raw.trim();
        let s = match s.rfind('@') {
            Some(at) => &s[at + 1..],
            None => s,
        };
        if s.is_empty() {
            return None;
        }
        let host = if let Some(rest) = s.strip_prefix('[') {
            rest.split_once(']').map(|(h, _)| h).unwrap_or(rest)
        } else if s.matches(':').count() == 1 {
            s.split_once(':').map(|(h, _)| h).unwrap_or(s)
        } else {
            s
        };
        if host.is_empty() {
            return None;
        }
        Some(match host.parse::<IpAddr>() {
            Ok(ip) => Identity::Ip(canonical_ip(ip)),
            Err(_) => Identity::Name(normalize_name(host)),
        })
    }

    fn describe(&self) -> String {
        match self {
            Identity::Name(n) => n.clone(),
            Identity::Ip(ip) => ip.to_string(),
        }
    }
}

/// One rule as the evaluator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Store id.
    pub id: i64,
    /// Owning workspace (`None` = global).
    pub workspace_id: Option<i64>,
    /// Owning workspace's name (`None` = global).
    pub workspace: Option<String>,
    /// Allow or deny.
    pub kind: ScopeKind,
    /// Parsed pattern.
    pub pattern: Pattern,
}

/// Which rule decided a verdict, for operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleRef {
    /// Rule id.
    pub id: i64,
    /// `allow` / `deny`.
    pub kind: ScopeKind,
    /// Normalized pattern.
    pub pattern: String,
    /// `global` or the workspace name.
    pub scope: String,
}

impl RuleRef {
    fn of(rule: &Rule) -> RuleRef {
        RuleRef {
            id: rule.id,
            kind: rule.kind,
            pattern: rule.pattern.to_string(),
            scope: rule
                .workspace
                .clone()
                .unwrap_or_else(|| match rule.workspace_id {
                    Some(id) => format!("workspace #{id}"),
                    None => "global".into(),
                }),
        }
    }
}

/// The outcome of a scope evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// Whether the flow may go.
    pub allowed: bool,
    /// Human-readable reason (the deciding rule, or why nothing allowed it).
    pub reason: String,
    /// The deciding rule, when one rule decided.
    pub rule: Option<RuleRef>,
}

impl Verdict {
    fn allow(reason: impl Into<String>, rule: Option<&Rule>) -> Verdict {
        Verdict {
            allowed: true,
            reason: reason.into(),
            rule: rule.map(RuleRef::of),
        }
    }

    fn block(reason: impl Into<String>, rule: Option<&Rule>) -> Verdict {
        Verdict {
            allowed: false,
            reason: reason.into(),
            rule: rule.map(RuleRef::of),
        }
    }

    fn deny_rule(rule: &Rule) -> Verdict {
        Verdict::block(
            format!("deny rule #{} {}", rule.id, rule.pattern),
            Some(rule),
        )
    }

    /// The blocking reason, or `None` when allowed.
    pub fn blocked_reason(&self) -> Option<&str> {
        (!self.allowed).then_some(self.reason.as_str())
    }
}

/// Everything known about a connection at check time.
#[derive(Debug, Clone, Default)]
pub struct ConnCheck<'a> {
    /// Where the upstream socket goes (`None`: not resolved, nothing will connect).
    pub dst_ip: Option<IpAddr>,
    /// Destination port (`None`: unknown — only port-less rules apply).
    pub dst_port: Option<u16>,
    /// Names the client declared (HTTP `Host` / `:authority`, TLS SNI).
    pub declared: &'a [Identity],
    /// The name burpwn itself resolved to obtain `dst_ip` (explicit proxy,
    /// replay).
    pub resolved_name: Option<&'a str>,
    /// Names the DNS shim saw resolve to `dst_ip` in this workspace.
    pub cache_names: &'a [String],
}

/// An immutable snapshot of every scope rule of a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// A rule set from already-parsed rules.
    pub fn new(rules: Vec<Rule>) -> RuleSet {
        RuleSet { rules }
    }

    /// Parse the store's rows. One unparsable pattern fails the whole set (the
    /// caller keeps its previous snapshot rather than enforce a partial policy).
    pub fn from_store(rows: &[ScopeRule]) -> Result<RuleSet, PatternError> {
        let mut rules = Vec::with_capacity(rows.len());
        for r in rows {
            let pattern = Pattern::parse(&r.pattern)
                .map_err(|e| perr(format!("scope rule #{}: {e}", r.id)))?;
            rules.push(Rule {
                id: r.id,
                workspace_id: r.workspace_id,
                workspace: r.workspace.clone(),
                kind: r.kind,
                pattern,
            });
        }
        Ok(RuleSet { rules })
    }

    /// Whether the session has no rule at all.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every rule.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The rules considered for workspace `ws`: the global ones plus `ws`'s own.
    pub fn for_workspace(&self, ws: i64) -> impl Iterator<Item = &Rule> {
        self.rules
            .iter()
            .filter(move |r| r.workspace_id.is_none() || r.workspace_id == Some(ws))
    }

    /// Whether any host rule is considered for `ws`.
    pub fn has_host_rules(&self, ws: i64) -> bool {
        self.for_workspace(ws).any(|r| r.pattern.is_host())
    }

    /// Evaluate a connection (see the module docs).
    pub fn check_conn(&self, ws: i64, c: &ConnCheck<'_>) -> Verdict {
        let considered: Vec<&Rule> = self.for_workspace(ws).collect();
        if considered.is_empty() {
            return Verdict::allow("no scope rules", None);
        }
        let dst_ip = c.dst_ip.map(canonical_ip);
        let declared_names = || {
            c.declared
                .iter()
                .filter_map(|i| match i {
                    Identity::Name(n) => Some(n.as_str()),
                    Identity::Ip(_) => None,
                })
                .chain(c.resolved_name)
        };
        // The DNS-cache names of the destination stand in for a name only when
        // the connection has none of its own: once a name is declared, THAT is
        // what the origin serves, and an unrelated name that shares the address
        // (a shared CDN IP) must not get it denied.
        let nameless = declared_names().next().is_none();
        let cache_for_deny: &[String] = if nameless { c.cache_names } else { &[] };
        let names = || declared_names().chain(cache_for_deny.iter().map(String::as_str));

        // 1. Deny wins, on any identity.
        for rule in considered.iter().filter(|r| r.kind == ScopeKind::Deny) {
            if !rule.pattern.port_ok(c.dst_port) {
                continue;
            }
            let hit = match &rule.pattern.target {
                Target::Host(_) => names().any(|n| rule.pattern.matches_name(n)),
                Target::Net(_) => {
                    dst_ip.is_some_and(|ip| rule.pattern.matches_ip(ip))
                        || c.declared.iter().any(|i| match i {
                            Identity::Ip(ip) => rule.pattern.matches_ip(*ip),
                            Identity::Name(_) => false,
                        })
                }
            };
            if hit {
                return Verdict::deny_rule(rule);
            }
        }

        // 2. An allowlist applies: the destination must be justified and every
        //    declared name allowed.
        let allows: Vec<&Rule> = considered
            .iter()
            .copied()
            .filter(|r| r.kind == ScopeKind::Allow)
            .collect();
        if allows.is_empty() {
            return Verdict::allow("no deny rule matches and no allowlist applies", None);
        }
        let justified = allows.iter().copied().find(|r| {
            r.pattern.port_ok(c.dst_port)
                && match &r.pattern.target {
                    Target::Net(_) => dst_ip.is_some_and(|ip| r.pattern.matches_ip(ip)),
                    Target::Host(_) => c
                        .resolved_name
                        .into_iter()
                        .chain(c.cache_names.iter().map(String::as_str))
                        .any(|n| r.pattern.matches_name(n)),
                }
        });
        let Some(justified) = justified else {
            let dst = match (dst_ip, c.dst_port) {
                (Some(ip), Some(p)) => format!("{}:{p}", bracket_ip(ip)),
                (Some(ip), None) => ip.to_string(),
                (None, _) => c.resolved_name.unwrap_or("unresolved destination").into(),
            };
            return Verdict::block(
                format!("not in allowlist: destination {dst} is not justified by an allow rule"),
                None,
            );
        };
        // A destination justified by an IP/CIDR rule accepts the names BOUND to
        // that address (seen resolving to it, or resolved to it by burpwn), so
        // an IP-only allowlist does not block every named flow — and still
        // refuses a name that never pointed there.
        let ip_justified = dst_ip.is_some_and(|ip| {
            allows.iter().any(|r| {
                r.pattern.port_ok(c.dst_port)
                    && matches!(r.pattern.target, Target::Net(_))
                    && r.pattern.matches_ip(ip)
            })
        });
        let bound_to_dst = |n: &str| {
            c.resolved_name.is_some_and(|r| normalize_name(r) == n)
                || c.cache_names.iter().any(|x| normalize_name(x) == n)
        };
        for id in c.declared {
            let ok = allows
                .iter()
                .any(|r| r.pattern.port_ok(c.dst_port) && r.pattern.matches_identity(id))
                || (ip_justified && matches!(id, Identity::Name(n) if bound_to_dst(n)));
            if !ok {
                return Verdict::block(
                    format!("not in allowlist: declared name {}", id.describe()),
                    None,
                );
            }
        }
        Verdict::allow(
            format!("allow rule #{} {}", justified.id, justified.pattern),
            Some(justified),
        )
    }

    /// Evaluate a DNS question name (host rules only). A deny rule with a port
    /// does not refuse the name — it forbids one port, which only the
    /// connection check can see — and an allow rule's port is ignored.
    pub fn check_dns(&self, ws: i64, qname: &str) -> Verdict {
        let name = normalize_name(qname);
        let host_rules: Vec<&Rule> = self
            .for_workspace(ws)
            .filter(|r| r.pattern.is_host())
            .collect();
        if let Some(rule) = host_rules.iter().find(|r| {
            r.kind == ScopeKind::Deny && r.pattern.port.is_none() && r.pattern.matches_name(&name)
        }) {
            return Verdict::deny_rule(rule);
        }
        let mut allows = host_rules
            .iter()
            .filter(|r| r.kind == ScopeKind::Allow)
            .peekable();
        if allows.peek().is_none() {
            return Verdict::allow(
                "no host allow rule: the name resolves, the connection check decides on the IP",
                None,
            );
        }
        match allows.find(|r| r.pattern.matches_name(&name)) {
            Some(rule) => Verdict::allow(
                format!("allow rule #{} {}", rule.id, rule.pattern),
                Some(rule),
            ),
            None => Verdict::block(format!("not in allowlist: name {name}"), None),
        }
    }
}

fn bracket_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    }
}

/// Default bound on the DNS cache (distinct `(workspace, IP)` entries).
pub const DNS_CACHE_CAP: usize = 65_536;

/// Names kept per IP (a shared CDN address can front thousands of names).
const NAMES_PER_IP: usize = 32;

/// The shortest life a name -> IP binding gets, whatever TTL the answer carried:
/// a binding expires at `now + max(TTL, DNS_BINDING_FLOOR)`.
///
/// The record TTL alone is too short to trust for a check that runs at CONNECT
/// time: clients keep using an address well past it — JVMs cache lookups by
/// policy (often for the process lifetime), browsers and HTTP clients pin a
/// resolved address to a connection pool, and a CDN answer routinely carries a
/// 20-60 s TTL. A binding that lapsed at the TTL would refuse those
/// still-legitimate connections as "not justified". An hour covers that
/// reuse while still letting a recycled cloud address (released, then handed
/// to someone else) stop being justified by a name that no longer points at it
/// — which is what keeping bindings for the daemon's whole lifetime got wrong.
pub const DNS_BINDING_FLOOR: Duration = Duration::from_secs(3_600);

/// `(workspace, IP) -> names` learned from DNS answers the shim relayed, each
/// binding with its own expiry.
///
/// Policy: in-memory, bounded to [`DNS_CACHE_CAP`] entries with the
/// least-recently-UPDATED entry evicted first, and at most [`NAMES_PER_IP`]
/// names per entry. Every `(workspace, IP, name)` binding expires at
/// `now + max(answer TTL, DNS_BINDING_FLOOR)` (see [`DNS_BINDING_FLOOR`] for
/// why the TTL is floored); a new answer for the same binding refreshes it, and
/// never shortens it — an earlier answer's longer TTL was a promise clients may
/// still be acting on. An expired binding justifies nothing: lookups ignore it
/// and prune it lazily (as does the next update of its entry), so there is no
/// background sweeper.
///
/// Within that life, a name keeps justifying an IP it resolved to, which can
/// only widen an ALLOW to an address that name really pointed at — never an
/// unrelated one.
///
/// Every method has an `_at` twin taking `now` explicitly, so expiry is tested
/// deterministically; the plain methods use [`Instant::now`].
#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<CacheInner>,
    cap: usize,
}

/// One entry: the tick of its last update (for LRU eviction) and its bindings,
/// least recently refreshed first.
type CacheEntry = (u64, Vec<(String, Instant)>);

#[derive(Debug, Default)]
struct CacheInner {
    map: HashMap<(i64, IpAddr), CacheEntry>,
    order: VecDeque<((i64, IpAddr), u64)>,
    tick: u64,
}

impl Default for DnsCache {
    fn default() -> Self {
        DnsCache::with_capacity(DNS_CACHE_CAP)
    }
}

impl DnsCache {
    /// A cache bounded to `cap` entries.
    pub fn with_capacity(cap: usize) -> DnsCache {
        DnsCache {
            inner: Mutex::new(CacheInner::default()),
            cap: cap.max(1),
        }
    }

    /// Record that every name in `names` resolved to `ip` in workspace `ws`,
    /// in an answer valid for `ttl_secs` (for a CNAME chain, the minimum TTL
    /// along it).
    pub fn record(&self, ws: i64, ip: IpAddr, names: &[String], ttl_secs: u32) {
        self.record_at(ws, ip, names, ttl_secs, Instant::now());
    }

    /// [`record`](Self::record) at an explicit `now`.
    pub fn record_at(&self, ws: i64, ip: IpAddr, names: &[String], ttl_secs: u32, now: Instant) {
        if names.is_empty() {
            return;
        }
        let expires = now + DNS_BINDING_FLOOR.max(Duration::from_secs(u64::from(ttl_secs)));
        let key = (ws, canonical_ip(ip));
        let mut g = self.inner.lock();
        g.tick += 1;
        let tick = g.tick;
        let entry = g.map.entry(key).or_insert_with(|| (tick, Vec::new()));
        entry.0 = tick;
        entry.1.retain(|(_, exp)| *exp > now);
        for n in names {
            let n = normalize_name(n);
            if n.is_empty() {
                continue;
            }
            let mut exp = expires;
            if let Some(pos) = entry.1.iter().position(|(x, _)| *x == n) {
                exp = exp.max(entry.1.remove(pos).1);
            }
            entry.1.push((n, exp));
        }
        if entry.1.len() > NAMES_PER_IP {
            let excess = entry.1.len() - NAMES_PER_IP;
            entry.1.drain(..excess);
        }
        g.order.push_back((key, tick));
        // Evict least-recently-updated entries. Stale order slots (an entry
        // updated since) are skipped.
        while g.map.len() > self.cap {
            let Some((k, t)) = g.order.pop_front() else {
                break;
            };
            if g.map.get(&k).is_some_and(|(cur, _)| *cur == t) {
                g.map.remove(&k);
            }
        }
        // Keep the order queue from growing without bound under repeated updates.
        if g.order.len() > self.cap.saturating_mul(4) {
            let CacheInner { map, order, .. } = &mut *g;
            order.retain(|(k, t)| map.get(k).is_some_and(|(cur, _)| cur == t));
        }
    }

    /// Names whose binding to `ip` in workspace `ws` has not expired.
    pub fn names(&self, ws: i64, ip: IpAddr) -> Vec<String> {
        self.names_at(ws, ip, Instant::now())
    }

    /// [`names`](Self::names) at an explicit `now`. Expired bindings are pruned
    /// on the way (and an entry left with none is dropped).
    pub fn names_at(&self, ws: i64, ip: IpAddr, now: Instant) -> Vec<String> {
        let key = (ws, canonical_ip(ip));
        let mut g = self.inner.lock();
        let Some(entry) = g.map.get_mut(&key) else {
            return Vec::new();
        };
        entry.1.retain(|(_, exp)| *exp > now);
        if entry.1.is_empty() {
            g.map.remove(&key);
            return Vec::new();
        }
        entry.1.iter().map(|(n, _)| n.clone()).collect()
    }

    /// Number of `(workspace, IP)` entries (expired ones included until they
    /// are pruned).
    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The proxy's scope: the current rule snapshot plus the DNS cache. ONE per
/// proxy, shared by every connection and refreshed in place by the daemon.
#[derive(Clone, Default)]
pub struct ScopeEngine {
    rules: Arc<RwLock<Arc<RuleSet>>>,
    active: Arc<AtomicBool>,
    cache: Arc<DnsCache>,
}

impl ScopeEngine {
    /// An engine with no rules (everything allowed).
    pub fn new() -> ScopeEngine {
        ScopeEngine::default()
    }

    /// Replace the rule snapshot.
    pub fn set_rules(&self, rules: RuleSet) {
        self.active.store(!rules.is_empty(), Ordering::Release);
        *self.rules.write() = Arc::new(rules);
    }

    /// The current rule snapshot.
    pub fn snapshot(&self) -> Arc<RuleSet> {
        self.rules.read().clone()
    }

    /// Whether any rule exists (one relaxed load; the fast path).
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// The DNS name cache.
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /// Evaluate a connection to `dst_ip:dst_port` from workspace `ws`, pulling
    /// the DNS-cache names for the destination itself.
    pub fn check_conn(
        &self,
        ws: i64,
        dst_ip: Option<IpAddr>,
        dst_port: u16,
        declared: &[Identity],
        resolved_name: Option<&str>,
    ) -> Verdict {
        if !self.is_active() {
            return Verdict::allow("no scope rules", None);
        }
        let cache_names = dst_ip
            .map(|ip| self.cache.names(ws, ip))
            .unwrap_or_default();
        self.snapshot().check_conn(
            ws,
            &ConnCheck {
                dst_ip,
                dst_port: Some(dst_port),
                declared,
                resolved_name,
                cache_names: &cache_names,
            },
        )
    }

    /// Evaluate a DNS question from workspace `ws`.
    pub fn check_dns(&self, ws: i64, qname: &str) -> Verdict {
        if !self.is_active() {
            return Verdict::allow("no scope rules", None);
        }
        self.snapshot().check_dns(ws, qname)
    }
}

/// The scope a request sent by burpwn itself (`req replay`, `fuzz`) is held to:
/// the rules of the replayed flow's workspace, and the one destination the
/// sender dials. Checked on every rendered request, since a fuzz payload can
/// sit in the `Host` header.
#[derive(Debug, Clone)]
pub struct ReplayScope {
    /// Rule snapshot.
    pub rules: Arc<RuleSet>,
    /// Workspace of the replayed flow.
    pub workspace_id: i64,
    /// The address the sender connects to.
    pub dst_ip: IpAddr,
    /// The port it connects to.
    pub dst_port: u16,
    /// The name that was resolved to `dst_ip`, when the caller verified one.
    pub resolved_name: Option<String>,
}

impl ReplayScope {
    /// Evaluate a request declaring `names` (SNI, `Host`; ports allowed).
    pub fn check(&self, names: &[&str]) -> Verdict {
        let mut declared: Vec<Identity> = Vec::new();
        for n in names {
            if let Some(id) = Identity::from_authority(n) {
                if !declared.contains(&id) {
                    declared.push(id);
                }
            }
        }
        self.rules.check_conn(
            self.workspace_id,
            &ConnCheck {
                dst_ip: Some(self.dst_ip),
                dst_port: Some(self.dst_port),
                declared: &declared,
                resolved_name: self.resolved_name.as_deref(),
                cache_names: &[],
            },
        )
    }
}

/// Body of the synthetic response to a scope-blocked HTTP request.
pub fn blocked_body(reason: &str) -> String {
    format!("burpwn: blocked by scope ({reason})\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pattern {
        Pattern::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    fn norm(s: &str) -> String {
        p(s).to_string()
    }

    #[test]
    fn patterns_normalize() {
        for (input, want) in [
            ("toto.fr", "toto.fr"),
            ("TOTO.Fr.", "toto.fr"),
            ("  *.Toto.FR  ", "*.toto.fr"),
            ("toto.fr:8443", "toto.fr:8443"),
            ("*.toto.fr:443", "*.toto.fr:443"),
            ("10.0.0.5", "10.0.0.5"),
            ("10.0.0.5/32", "10.0.0.5"),
            ("10.1.2.3/8", "10.0.0.0/8"),
            ("10.0.0.0/8:22", "10.0.0.0/8:22"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:DB8::ffff/32", "2001:db8::/32"),
            ("[2001:db8::1]:443", "[2001:db8::1]:443"),
            ("[2001:db8::/32]:443", "[2001:db8::/32]:443"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("::ffff:10.0.0.1", "10.0.0.1"),
            // A v4-mapped address IS IPv6 as written: brackets are legitimate.
            ("[::ffff:10.0.0.1]:443", "10.0.0.1:443"),
            ("[::ffff:10.0.0.0/104]:22", "10.0.0.0/8:22"),
            ("0.0.0.0/0", "0.0.0.0/0"),
            ("_dmarc.toto.fr", "_dmarc.toto.fr"),
        ] {
            assert_eq!(norm(input), want, "{input}");
        }
    }

    #[test]
    fn patterns_reject() {
        for bad in [
            "",
            "*",
            "*:443",
            "a.*.toto.fr",
            "*toto.fr",
            "*.*.toto.fr",
            "toto.fr:0",
            "toto.fr:65536",
            "toto.fr:http",
            "toto.fr:",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/x",
            "[10.0.0.1]:443",
            "[toto.fr]:443",
            "[2001:db8::1",
            "[2001:db8::1]443",
            "10.0.0",
            "1.2.3.256",
            "to to.fr",
            "toto..fr",
            "héhé.fr",
            "http://toto.fr",
        ] {
            assert!(Pattern::parse(bad).is_err(), "{bad:?} must be rejected");
        }
        let e = Pattern::parse("*").unwrap_err().to_string();
        assert!(e.contains("scope clear"), "{e}");
    }

    #[test]
    fn subtree_is_strict_label_suffix() {
        let w = p("*.toto.fr");
        assert!(w.matches_name("toto.fr"), "apex");
        assert!(w.matches_name("api.toto.fr"));
        assert!(w.matches_name("a.b.c.toto.fr"), "depth");
        assert!(!w.matches_name("nottoto.fr"));
        assert!(!w.matches_name("toto.fr.evil.com"));
        assert!(!w.matches_name("fr"));
        let e = p("toto.fr");
        assert!(e.matches_name("toto.fr"));
        assert!(!e.matches_name("api.toto.fr"));
        assert!(!e.matches_name("nottoto.fr"));
    }

    #[test]
    fn identities_parse_and_normalize() {
        assert_eq!(
            Identity::from_authority("API.Toto.fr.:8443"),
            Some(Identity::Name("api.toto.fr".into()))
        );
        assert_eq!(
            Identity::from_authority("[2001:db8::1]:443"),
            Some(Identity::Ip("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            Identity::from_authority("2001:db8::1"),
            Some(Identity::Ip("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            Identity::from_authority("10.0.0.1:80"),
            Some(Identity::Ip("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(Identity::from_authority(""), None);
        assert_eq!(Identity::from_authority(":80"), None);
    }

    /// Userinfo is not the host: `allowed.com:443@evil.com` names `evil.com`
    /// (everything up to the LAST `@` goes), brackets included.
    #[test]
    fn identities_strip_userinfo() {
        for (raw, want) in [
            ("allowed.com:443@evil.com", name("evil.com")),
            ("allowed.com@evil.com:8080", name("evil.com")),
            ("a@b@Evil.com.", name("evil.com")),
            ("user:pw@[2001:db8::1]:443", Identity::Ip(ip("2001:db8::1"))),
            ("allowed.com@10.0.0.1", Identity::Ip(ip("10.0.0.1"))),
        ] {
            assert_eq!(Identity::from_authority(raw), Some(want), "{raw}");
        }
        assert_eq!(Identity::from_authority("allowed.com@"), None);
        // The evaluator therefore judges the real host.
        let rs = RuleSet::new(vec![deny(1, None, "evil.com")]);
        let decl = [Identity::from_authority("allowed.com:443@evil.com").unwrap()];
        assert!(!rs.check_conn(WS, &conn("1.1.1.1", 443, &decl, &[])).allowed);
    }

    #[test]
    fn cidr_contains() {
        let c = Cidr::new("10.0.0.0".parse().unwrap(), 8).unwrap();
        assert!(c.contains("10.255.0.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
        // A v4-mapped v6 destination is the v4 address.
        assert!(c.contains("::ffff:10.1.1.1".parse().unwrap()));
        let v6 = Cidr::new("2001:db8::".parse().unwrap(), 32).unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("2001:db9::5".parse().unwrap()));
        let all = Cidr::new("0.0.0.0".parse().unwrap(), 0).unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
    }

    // --- evaluation ------------------------------------------------------

    const WS: i64 = 2;
    const OTHER: i64 = 3;

    fn rule(id: i64, ws: Option<i64>, kind: ScopeKind, pat: &str) -> Rule {
        Rule {
            id,
            workspace_id: ws,
            workspace: ws.map(|w| format!("ws{w}")),
            kind,
            pattern: p(pat),
        }
    }

    fn allow(id: i64, ws: Option<i64>, pat: &str) -> Rule {
        rule(id, ws, ScopeKind::Allow, pat)
    }

    fn deny(id: i64, ws: Option<i64>, pat: &str) -> Rule {
        rule(id, ws, ScopeKind::Deny, pat)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn name(s: &str) -> Identity {
        Identity::Name(s.into())
    }

    fn conn<'a>(
        dst: &str,
        port: u16,
        declared: &'a [Identity],
        cache: &'a [String],
    ) -> ConnCheck<'a> {
        ConnCheck {
            dst_ip: Some(ip(dst)),
            dst_port: Some(port),
            declared,
            resolved_name: None,
            cache_names: cache,
        }
    }

    #[test]
    fn no_rules_allows_everything() {
        let rs = RuleSet::default();
        assert!(rs.check_conn(WS, &conn("1.2.3.4", 443, &[], &[])).allowed);
        assert!(rs.check_dns(WS, "evil.com.").allowed);
    }

    #[test]
    fn deny_wins_over_allow() {
        let rs = RuleSet::new(vec![
            allow(1, None, "*.toto.fr"),
            deny(2, None, "admin.toto.fr"),
        ]);
        let cache = vec!["admin.toto.fr".to_string()];
        let v = rs.check_conn(WS, &conn("1.2.3.4", 443, &[name("admin.toto.fr")], &cache));
        assert!(!v.allowed);
        assert_eq!(v.reason, "deny rule #2 admin.toto.fr");
        assert_eq!(v.rule.as_ref().unwrap().id, 2);
        assert!(!rs.check_dns(WS, "admin.toto.fr.").allowed);
        assert!(rs.check_dns(WS, "api.toto.fr.").allowed);
    }

    #[test]
    fn deny_on_ip_and_cidr() {
        let rs = RuleSet::new(vec![deny(1, None, "169.254.0.0/16")]);
        assert!(
            !rs.check_conn(WS, &conn("169.254.169.254", 80, &[], &[]))
                .allowed
        );
        assert!(rs.check_conn(WS, &conn("1.1.1.1", 80, &[], &[])).allowed);
        // An IP literal in the Host header is an identity too.
        let decl = [Identity::Ip(ip("169.254.169.254"))];
        assert!(!rs.check_conn(WS, &conn("1.1.1.1", 80, &decl, &[])).allowed);
        // IP rules never refuse a DNS name.
        assert!(rs.check_dns(WS, "metadata.google.internal").allowed);
    }

    #[test]
    fn global_and_workspace_rules_union_other_workspace_ignored() {
        let rs = RuleSet::new(vec![
            allow(1, None, "toto.fr"),
            allow(2, Some(WS), "titi.fr"),
            allow(3, Some(OTHER), "tata.fr"),
            deny(4, Some(OTHER), "toto.fr"),
        ]);
        let c1 = vec!["toto.fr".to_string()];
        let c2 = vec!["titi.fr".to_string()];
        let c3 = vec!["tata.fr".to_string()];
        assert!(rs.check_conn(WS, &conn("1.1.1.1", 443, &[], &c1)).allowed);
        assert!(rs.check_conn(WS, &conn("1.1.1.2", 443, &[], &c2)).allowed);
        // OTHER's allow does not help WS, OTHER's deny does not hurt it.
        assert!(!rs.check_conn(WS, &conn("1.1.1.3", 443, &[], &c3)).allowed);
        assert!(
            !rs.check_conn(OTHER, &conn("1.1.1.1", 443, &[], &c1))
                .allowed
        );
        // A workspace with no own rules still gets the global ones.
        assert!(rs.check_conn(99, &conn("1.1.1.1", 443, &[], &c1)).allowed);
        assert!(!rs.check_conn(99, &conn("1.1.1.2", 443, &[], &c2)).allowed);
    }

    #[test]
    fn empty_allowlist_means_allowed_unless_denied() {
        let rs = RuleSet::new(vec![
            deny(1, None, "evil.com"),
            allow(2, Some(OTHER), "x.fr"),
        ]);
        assert!(
            rs.check_conn(WS, &conn("1.2.3.4", 443, &[name("good.com")], &[]))
                .allowed
        );
        assert!(rs.check_dns(WS, "good.com").allowed);
        assert!(
            !rs.check_conn(WS, &conn("1.2.3.4", 443, &[name("evil.com")], &[]))
                .allowed
        );
    }

    #[test]
    fn host_spoof_on_allowed_ip_is_blocked() {
        // The shared CDN IP is justified (allowed.com resolved to it) but the
        // request claims another host: the upstream would serve evil.com.
        let rs = RuleSet::new(vec![allow(1, None, "allowed.com")]);
        let cache = vec!["allowed.com".to_string()];
        let v = rs.check_conn(WS, &conn("5.5.5.5", 443, &[name("evil.com")], &cache));
        assert!(!v.allowed);
        assert!(v.reason.contains("evil.com"), "{}", v.reason);
        // Same with an IP allow rule.
        let rs = RuleSet::new(vec![allow(1, None, "5.5.5.0/24")]);
        assert!(
            !rs.check_conn(WS, &conn("5.5.5.5", 443, &[name("evil.com")], &[]))
                .allowed
        );
        // …and allowed with no declared name at all (raw TCP to the IP).
        assert!(rs.check_conn(WS, &conn("5.5.5.5", 443, &[], &[])).allowed);
        // A name bound to the address (it really resolved there) is not a
        // spoof: the IP rule accepts it.
        let bound = vec!["evil.com".to_string()];
        assert!(
            rs.check_conn(WS, &conn("5.5.5.5", 443, &[name("evil.com")], &bound))
                .allowed
        );
        // Bound to ANOTHER address does not count.
        let elsewhere = vec!["other.com".to_string()];
        assert!(
            !rs.check_conn(WS, &conn("5.5.5.5", 443, &[name("evil.com")], &elsewhere))
                .allowed
        );
        // A host-rule justification does not extend to cache-bound names: on
        // a shared CDN address, `allowed.com` justifying the IP must not let
        // `evil.com` (also seen on it) through.
        let rs = RuleSet::new(vec![allow(1, None, "allowed.com")]);
        let shared = vec!["allowed.com".to_string(), "evil.com".to_string()];
        assert!(
            !rs.check_conn(WS, &conn("5.5.5.5", 443, &[name("evil.com")], &shared))
                .allowed
        );
    }

    /// An IP-only allowlist lets named HTTP/TLS flows through when the name is
    /// bound to the destination (DNS cache or burpwn's own resolution), and
    /// refuses an unrelated name on the same address.
    #[test]
    fn ip_only_allowlist_accepts_names_bound_to_the_destination() {
        let rs = RuleSet::new(vec![allow(1, None, "10.0.0.0/8")]);
        let cache = vec!["intranet.corp".to_string()];
        let decl = [name("intranet.corp")];
        let v = rs.check_conn(WS, &conn("10.1.2.3", 443, &decl, &cache));
        assert!(v.allowed, "{}", v.reason);
        assert_eq!(v.rule.unwrap().id, 1);
        // Unrelated Host on the same (allowed) IP: blocked.
        let v = rs.check_conn(WS, &conn("10.1.2.3", 443, &[name("evil.com")], &cache));
        assert!(!v.allowed);
        assert!(v.reason.contains("declared name evil.com"), "{}", v.reason);
        // Replay / explicit proxy: the name burpwn resolved itself.
        let c = ConnCheck {
            resolved_name: Some("Intranet.Corp."),
            ..conn("10.1.2.3", 443, &decl, &[])
        };
        assert!(rs.check_conn(WS, &c).allowed);
        // The binding does not help an address outside the rule.
        assert!(
            !rs.check_conn(WS, &conn("11.1.2.3", 443, &decl, &cache))
                .allowed
        );
        // Nor a port the IP rule excludes.
        let rs = RuleSet::new(vec![allow(1, None, "10.0.0.0/8:443")]);
        assert!(
            rs.check_conn(WS, &conn("10.1.2.3", 443, &decl, &cache))
                .allowed
        );
        assert!(
            !rs.check_conn(WS, &conn("10.1.2.3", 80, &decl, &cache))
                .allowed
        );
    }

    #[test]
    fn destination_must_be_justified() {
        let rs = RuleSet::new(vec![allow(1, None, "*.toto.fr")]);
        // SNI claims an allowed name but nothing ties the IP to it.
        let decl = [name("api.toto.fr")];
        let v = rs.check_conn(WS, &conn("6.6.6.6", 443, &decl, &[]));
        assert!(!v.allowed);
        assert!(v.reason.starts_with("not in allowlist"), "{}", v.reason);
        // The DNS cache justifies it.
        let cache = vec!["api.toto.fr".to_string()];
        let v = rs.check_conn(WS, &conn("6.6.6.6", 443, &decl, &cache));
        assert!(v.allowed, "{}", v.reason);
        assert_eq!(v.rule.unwrap().id, 1);
        // So does the name burpwn resolved itself (explicit proxy / replay).
        let c = ConnCheck {
            resolved_name: Some("api.toto.fr"),
            ..conn("6.6.6.6", 443, &decl, &[])
        };
        assert!(rs.check_conn(WS, &c).allowed);
        // A CNAME-chain name in the cache justifies too.
        let cache = vec!["cdn.provider.net".to_string(), "www.toto.fr".to_string()];
        assert!(
            rs.check_conn(WS, &conn("6.6.6.7", 443, &[name("www.toto.fr")], &cache))
                .allowed
        );
        // Unresolved destination (explicit proxy pre-check failed): blocked.
        let c = ConnCheck {
            dst_ip: None,
            ..conn("6.6.6.6", 443, &decl, &[])
        };
        assert!(!rs.check_conn(WS, &c).allowed);
    }

    #[test]
    fn ip_only_allowlist_lets_dns_resolve() {
        let rs = RuleSet::new(vec![allow(1, None, "10.0.0.0/8")]);
        assert!(rs.check_dns(WS, "anything.example.").allowed);
        assert!(rs.check_conn(WS, &conn("10.1.2.3", 80, &[], &[])).allowed);
        assert!(!rs.check_conn(WS, &conn("11.1.2.3", 80, &[], &[])).allowed);
        // With a host allow rule next to it, unknown names are refused.
        let rs = RuleSet::new(vec![
            allow(1, None, "10.0.0.0/8"),
            allow(2, None, "toto.fr"),
        ]);
        assert!(!rs.check_dns(WS, "anything.example.").allowed);
        assert!(rs.check_dns(WS, "TOTO.fr.").allowed);
    }

    #[test]
    fn port_constraints() {
        let rs = RuleSet::new(vec![allow(1, None, "toto.fr:443")]);
        let cache = vec!["toto.fr".to_string()];
        let decl = [name("toto.fr")];
        assert!(
            rs.check_conn(WS, &conn("1.1.1.1", 443, &decl, &cache))
                .allowed
        );
        assert!(
            !rs.check_conn(WS, &conn("1.1.1.1", 8443, &decl, &cache))
                .allowed
        );
        // DNS ignores the port suffix.
        assert!(rs.check_dns(WS, "toto.fr").allowed);
        // Unknown port: a port-constrained rule does not apply.
        let c = ConnCheck {
            dst_port: None,
            ..conn("1.1.1.1", 0, &decl, &cache)
        };
        assert!(!rs.check_conn(WS, &c).allowed);

        let rs = RuleSet::new(vec![deny(1, None, "10.0.0.0/8:22")]);
        assert!(!rs.check_conn(WS, &conn("10.0.0.1", 22, &[], &[])).allowed);
        assert!(rs.check_conn(WS, &conn("10.0.0.1", 80, &[], &[])).allowed);
        let rs = RuleSet::new(vec![deny(1, None, "[2001:db8::/32]:443")]);
        assert!(
            !rs.check_conn(WS, &conn("2001:db8::5", 443, &[], &[]))
                .allowed
        );
        assert!(
            rs.check_conn(WS, &conn("2001:db8::5", 80, &[], &[]))
                .allowed
        );
    }

    #[test]
    fn deny_via_dns_cache_name() {
        let rs = RuleSet::new(vec![deny(1, None, "*.evil.com")]);
        let cache = vec!["x.evil.com".to_string()];
        assert!(
            !rs.check_conn(WS, &conn("7.7.7.7", 443, &[], &cache))
                .allowed
        );
    }

    /// Deny-by-cache-name applies only to a connection declaring no name: a
    /// shared CDN address once seen for a denied tracker must not block an
    /// allowed site that declares its own name. Declared names and the IP are
    /// still denied.
    #[test]
    fn deny_by_cache_name_only_for_nameless_connections() {
        let rs = RuleSet::new(vec![deny(1, None, "*.tracker.com")]);
        let cache = vec!["cdn.tracker.com".to_string(), "site.org".to_string()];
        // Declared name: the cache is not held against it.
        assert!(
            rs.check_conn(WS, &conn("8.8.4.4", 443, &[name("site.org")], &cache))
                .allowed
        );
        let c = ConnCheck {
            resolved_name: Some("site.org"),
            ..conn("8.8.4.4", 443, &[], &cache)
        };
        assert!(rs.check_conn(WS, &c).allowed, "a resolved name counts too");
        // No name (raw TCP / SNI-less TLS): the cache speaks for it.
        assert!(
            !rs.check_conn(WS, &conn("8.8.4.4", 443, &[], &cache))
                .allowed
        );
        // An IP literal is not a name either.
        let lit = [Identity::Ip(ip("8.8.4.4"))];
        assert!(
            !rs.check_conn(WS, &conn("8.8.4.4", 443, &lit, &cache))
                .allowed
        );
        // A declared denied name is still denied.
        assert!(
            !rs.check_conn(WS, &conn("8.8.4.4", 443, &[name("x.tracker.com")], &cache))
                .allowed
        );
    }

    /// A port-qualified deny forbids one port: the name still resolves, and
    /// the connection check enforces the port.
    #[test]
    fn a_port_qualified_deny_does_not_refuse_dns() {
        let rs = RuleSet::new(vec![deny(1, None, "evil.com:8443")]);
        assert!(rs.check_dns(WS, "evil.com.").allowed);
        let decl = [name("evil.com")];
        assert!(
            !rs.check_conn(WS, &conn("1.2.3.4", 8443, &decl, &[]))
                .allowed
        );
        assert!(rs.check_conn(WS, &conn("1.2.3.4", 443, &decl, &[])).allowed);
        // A port-less deny still refuses the name.
        let rs = RuleSet::new(vec![deny(1, None, "evil.com")]);
        assert!(!rs.check_dns(WS, "evil.com.").allowed);
    }

    #[test]
    fn from_store_rejects_bad_rows() {
        let row = |id, pattern: &str| ScopeRule {
            id,
            workspace_id: None,
            workspace: None,
            kind: ScopeKind::Allow,
            pattern: pattern.into(),
            created_at: 0,
        };
        assert!(RuleSet::from_store(&[row(1, "toto.fr"), row(2, "10.0.0.0/8")]).is_ok());
        let e = RuleSet::from_store(&[row(1, "toto.fr"), row(7, "*")]).unwrap_err();
        assert!(e.to_string().contains("#7"), "{e}");
    }

    #[test]
    fn dns_cache_is_per_workspace_bounded_and_normalized() {
        let c = DnsCache::with_capacity(2);
        c.record(
            1,
            ip("1.1.1.1"),
            &["A.example.".into(), "b.example".into()],
            60,
        );
        assert_eq!(c.names(1, ip("1.1.1.1")), vec!["a.example", "b.example"]);
        assert!(c.names(2, ip("1.1.1.1")).is_empty(), "per workspace");
        c.record(1, ip("2.2.2.2"), &["c.example".into()], 60);
        // Touch 1.1.1.1 so 2.2.2.2 is now the least recently updated.
        c.record(1, ip("1.1.1.1"), &["a.example".into()], 60);
        c.record(1, ip("3.3.3.3"), &["d.example".into()], 60);
        assert_eq!(c.len(), 2);
        assert!(c.names(1, ip("2.2.2.2")).is_empty(), "evicted");
        assert_eq!(c.names(1, ip("1.1.1.1")), vec!["b.example", "a.example"]);
        // v4-mapped lookups hit the v4 entry.
        assert!(!c.names(1, ip("::ffff:3.3.3.3")).is_empty());
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A binding from a short-TTL answer lives for the floor, and not a second
    /// more: after that the name justifies nothing, and the entry is pruned.
    #[test]
    fn dns_binding_is_valid_until_the_floor_then_ignored_and_pruned() {
        let c = DnsCache::default();
        let t0 = Instant::now();
        c.record_at(1, ip("1.1.1.1"), &["a.example".into()], 60, t0);
        let floor = DNS_BINDING_FLOOR;
        assert_eq!(
            c.names_at(1, ip("1.1.1.1"), t0 + secs(61)),
            vec!["a.example"]
        );
        assert_eq!(
            c.names_at(1, ip("1.1.1.1"), t0 + floor - secs(1)),
            vec!["a.example"],
            "the TTL is floored"
        );
        assert!(
            c.names_at(1, ip("1.1.1.1"), t0 + floor).is_empty(),
            "expired"
        );
        assert!(
            c.is_empty(),
            "an entry with no live binding is pruned on lookup"
        );
    }

    /// A TTL longer than the floor is honored as is.
    #[test]
    fn dns_binding_ttl_above_the_floor_is_honored() {
        let c = DnsCache::default();
        let t0 = Instant::now();
        let ttl = DNS_BINDING_FLOOR.as_secs() * 3;
        c.record_at(1, ip("1.1.1.1"), &["a.example".into()], ttl as u32, t0);
        assert_eq!(
            c.names_at(1, ip("1.1.1.1"), t0 + secs(ttl - 1)),
            vec!["a.example"]
        );
        assert!(c.names_at(1, ip("1.1.1.1"), t0 + secs(ttl)).is_empty());
    }

    /// Each new answer refreshes its binding (and only its own); a later answer
    /// with a shorter TTL never cuts an earlier, longer promise short. An update
    /// of the entry prunes its expired bindings.
    #[test]
    fn dns_binding_refresh_extends_and_never_shortens() {
        let c = DnsCache::default();
        let t0 = Instant::now();
        let floor = DNS_BINDING_FLOOR;
        c.record_at(
            1,
            ip("1.1.1.1"),
            &["a.example".into(), "b.example".into()],
            60,
            t0,
        );
        // Refresh `a` only, half-way through its life.
        c.record_at(1, ip("1.1.1.1"), &["a.example".into()], 60, t0 + floor / 2);
        assert_eq!(
            c.names_at(1, ip("1.1.1.1"), t0 + floor + secs(1)),
            vec!["a.example"],
            "a refreshed, b expired"
        );

        let long = floor.as_secs() * 4;
        c.record_at(2, ip("2.2.2.2"), &["c.example".into()], long as u32, t0);
        c.record_at(2, ip("2.2.2.2"), &["c.example".into()], 60, t0 + secs(10));
        assert_eq!(
            c.names_at(2, ip("2.2.2.2"), t0 + secs(long - 1)),
            vec!["c.example"],
            "the shorter later answer did not shorten the binding"
        );

        // An update after `a` expired drops it rather than keep dead weight.
        c.record_at(1, ip("1.1.1.1"), &["d.example".into()], 60, t0 + floor * 3);
        let g = c.inner.lock();
        let names: Vec<&str> = g.map[&(1, ip("1.1.1.1"))]
            .1
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names, vec!["d.example"]);
    }

    #[test]
    fn engine_fast_path_and_snapshot() {
        let e = ScopeEngine::new();
        assert!(!e.is_active());
        assert!(e.check_conn(WS, Some(ip("1.1.1.1")), 80, &[], None).allowed);
        e.set_rules(RuleSet::new(vec![allow(1, None, "toto.fr")]));
        assert!(e.is_active());
        assert!(!e.check_conn(WS, Some(ip("1.1.1.1")), 80, &[], None).allowed);
        e.cache().record(WS, ip("1.1.1.1"), &["toto.fr".into()], 60);
        assert!(
            e.check_conn(WS, Some(ip("1.1.1.1")), 80, &[name("toto.fr")], None)
                .allowed
        );
        e.set_rules(RuleSet::default());
        assert!(!e.is_active());
    }
}
