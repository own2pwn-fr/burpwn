//! DNS decode-and-forward UDP front-end.
//!
//! The sandbox redirects the workload's UDP/53 traffic to this listener. For
//! each datagram we:
//! 1. decode the query with `hickory-proto`,
//! 2. forward the raw query bytes to a real upstream resolver (the host's first
//!    `/etc/resolv.conf` nameserver, falling back to `1.1.1.1:53`),
//! 3. decode the answer for logging,
//! 4. record a `Protocol::Dns` flow (query name/type as request, answer records
//!    as the response body),
//! 5. return the upstream answer bytes verbatim to the client.
//!
//! # Network scope
//!
//! Checked FIRST, before any hook and before step 2: a question name the scope
//! refuses (see [`crate::scope`]) is answered `REFUSED` here and never
//! forwarded. Every A/AAAA answer the shim relays (resolved upstream or
//! synthesized by a hook) feeds the scope's name cache, which is what lets a
//! later connection to that IP be justified by an allow host rule.
//!
//! # Hooks
//!
//! A `dns-query` hook can short-circuit step 2, and only step 2: it decides
//! whether the name is resolved at all, and — for an `A`/`AAAA` query — what it
//! resolves to. Everything burpwn answers itself is SYNTHESIZED here rather than
//! edited, because that is the only form it can get right: a response built from
//! the query echoes the id and the question, carries one record and nothing
//! else. Rewriting an upstream answer would mean re-encoding records burpwn did
//! not make — CNAME chains, EDNS(0), DNSSEC material — so there is deliberately
//! no `dns-response` phase.
//!
//! What a synthetic answer is NOT: authoritative about anything else. It carries
//! no EDNS OPT record even when the query had one (a resolver reads that as "no
//! EDNS support", which is a defined answer), and it is unsigned — a client that
//! set `DO` and validates will refuse it, correctly. Both are properties of
//! answering rather than resolving, and neither can be fixed by trying harder.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

use burpwn_store::model::{FlowStart, Protocol, RequestData, ResponseData};
use burpwn_store::WriteHandle;

use crate::hooks::{DnsDecision, HookEngine};
use crate::scope::ScopeEngine;
use crate::util::now_millis;

/// TTL put on a synthesized answer, in seconds.
///
/// Short on purpose: the point of a `set-answer` hook is to steer a target
/// during an engagement, and a long TTL would keep steering it from the client's
/// own cache after the hook is gone — a stale finding that looks like a live one.
const SYNTHETIC_TTL: u32 = 60;

/// Configuration for the DNS front-end.
#[derive(Clone)]
pub struct DnsConfig {
    /// Upstream resolver to forward to.
    pub upstream: SocketAddr,
    /// Default workspace id for logged flows.
    pub workspace_id: i64,
    /// Optional exec correlation id.
    pub exec_id: Option<String>,
    /// Per-query upstream timeout.
    pub timeout: Duration,
    /// The hook engine, shared with the daemon: a `dns-query` hook added
    /// mid-session reaches the shim that is already serving.
    pub hooks: HookEngine,
    /// The network scope, shared with the daemon (rules + the name cache).
    pub scope: ScopeEngine,
}

impl std::fmt::Debug for DnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsConfig")
            .field("upstream", &self.upstream)
            .field("workspace_id", &self.workspace_id)
            .field("exec_id", &self.exec_id)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl DnsConfig {
    /// Build a config using the host's first configured nameserver, or
    /// `1.1.1.1:53` if `/etc/resolv.conf` has none.
    pub fn from_host(
        workspace_id: i64,
        exec_id: Option<String>,
        hooks: HookEngine,
        scope: ScopeEngine,
    ) -> Self {
        Self {
            upstream: host_upstream(),
            workspace_id,
            exec_id,
            timeout: Duration::from_secs(5),
            hooks,
            scope,
        }
    }
}

/// Read the first `nameserver` line from `/etc/resolv.conf`; fallback 1.1.1.1.
fn host_upstream() -> SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    return SocketAddr::new(ip, 53);
                }
            }
        }
    }
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
}

/// Bind a UDP DNS server on `addr` and serve until the socket errors.
pub async fn serve(addr: SocketAddr, cfg: DnsConfig, writer: WriteHandle) -> std::io::Result<()> {
    let sock = UdpSocket::bind(addr).await?;
    tracing::info!(%addr, upstream = %cfg.upstream, "DNS front-end listening");
    serve_socket(sock, cfg, writer).await
}

/// Serve DNS over an ALREADY-BOUND socket — used for the transparent sandbox
/// path, where the in-netns agent binds `127.0.0.1:dns_port` (the nftables
/// `udp/53` redirect target) and passes the fd to the host proxy via SCM_RIGHTS.
/// Stops after [`IDLE_TIMEOUT`] with no query, which bounds the per-exec task
/// leak once the sandbox netns is gone (the passed fd then never sees traffic).
pub async fn serve_socket(
    sock: UdpSocket,
    cfg: DnsConfig,
    writer: WriteHandle,
) -> std::io::Result<()> {
    let sock = Arc::new(sock);
    let cfg = Arc::new(cfg);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match tokio::time::timeout(IDLE_TIMEOUT, sock.recv_from(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()), // idle → stop serving this socket
        };
        let query = buf[..n].to_vec();
        let sock = sock.clone();
        let cfg = cfg.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_query(&sock, peer, query, &cfg, &writer).await {
                tracing::debug!(error = %e, "dns query handling failed");
            }
        });
    }
}

/// Stop serving a (passed) DNS socket after this long with no query.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

async fn handle_query(
    sock: &UdpSocket,
    peer: SocketAddr,
    query: Vec<u8>,
    cfg: &DnsConfig,
    writer: &WriteHandle,
) -> std::io::Result<()> {
    // The hooks are consulted behind one relaxed atomic load, and the query is
    // decoded for them only if one exists — a shim with no `dns-query` hook
    // resolves exactly as it did, and decodes the query once, for the log.
    let mut described: Option<(String, String)> = None;

    // The network scope comes first: a refused name is never forwarded, and no
    // hook gets to answer it either. Decoding is gated on the scope having
    // rules at all (one atomic load), exactly like the hooks below.
    let mut blocked: Option<String> = None;
    if cfg.scope.is_active() {
        blocked = scope_block_reason(&cfg.scope, cfg.workspace_id, &query);
        described = Some(describe_query(&query));
    }

    let answer = if let Some(reason) = &blocked {
        tracing::info!(qname = ?described.as_ref().map(|d| &d.0), %reason, "dns query blocked by scope");
        // `None` only for a query that cannot be decoded: then there is nothing
        // to answer, and it is still not forwarded.
        synthesize(&query, ResponseCode::Refused, None)
    } else {
        let decision = if cfg.hooks.any_dns() {
            let (qname, qtype) = described.clone().unwrap_or_else(|| describe_query(&query));
            let d = cfg
                .hooks
                .dns_query(cfg.exec_id.as_deref(), &qname, &format!("/{qtype}"));
            described = Some((qname, qtype));
            d
        } else {
            DnsDecision::Resolve
        };
        Some(match hooked_answer(&query, decision) {
            Some(bytes) => bytes,
            None => forward_upstream(&query, cfg).await?,
        })
    };
    // Reply to the client first (latency), then log.
    if let Some(answer) = &answer {
        sock.send_to(answer, peer).await?;
        // Every relayed address answer teaches the scope which names point at
        // which IPs (cheap; filled whether or not rules exist yet, so a rule
        // added mid-session can already justify connections).
        learn_names(&cfg.scope, cfg.workspace_id, answer);
    }

    let (qname, qtype) = described.unwrap_or_else(|| describe_query(&query));
    let answer_text = match &answer {
        Some(a) => describe_answer(a),
        None => "; not answered: blocked by scope\n".to_string(),
    };

    let flow_id = writer
        .flow_start(FlowStart {
            workspace_id: cfg.workspace_id,
            ts_start: now_millis(),
            exec_id: cfg.exec_id.clone(),
            client_addr: peer.to_string(),
            dst_ip: cfg.upstream.ip().to_string(),
            dst_port: cfg.upstream.port(),
            sni: None,
            scheme: "dns".into(),
            protocol: Protocol::Dns,
            intercepted: false,
            blocked,
        })
        .await
        .map_err(to_io)?;
    let _ = writer
        .request(
            flow_id,
            RequestData {
                method: "QUERY".into(),
                authority: qname.clone(),
                // Path is the record type only — the authority already carries the
                // qname, so `req list` renders `dns://example.com./A` (not a
                // doubled `dns://example.com.example.com./A`).
                path: format!("/{qtype}"),
                http_version: "DNS".into(),
                headers: Vec::new(),
                body: query,
            },
        )
        .await;
    let _ = writer
        .response(
            flow_id,
            ResponseData {
                status: 0,
                http_version: "DNS".into(),
                headers: Vec::new(),
                body: answer_text.into_bytes(),
                timing_ms: None,
            },
        )
        .await;
    let _ = writer.flow_end(flow_id, now_millis()).await;
    Ok(())
}

/// The scope's reason to refuse a query, or `None` to let it through.
///
/// With host rules in force, anything the scope cannot judge exactly is
/// refused rather than smuggled upstream: an undecodable message, a message
/// whose question count is not exactly one (only one name would be checked,
/// the resolver may answer them all), and a question name with a label that is
/// not a plain host label (`[A-Za-z0-9-_]`) — a `.` byte inside a wire label
/// would otherwise print as a label separator and impersonate an allowed
/// subtree. Names are compared in their ASCII (punycode) form, never the
/// Unicode rendering, so `deny xn--bcher-kva.example` holds `bücher.example`.
/// Without host rules none of this can matter: IP rules never refuse a name.
fn scope_block_reason(scope: &ScopeEngine, ws: i64, query: &[u8]) -> Option<String> {
    let rules = scope.snapshot();
    let strict = rules.has_host_rules(ws);
    let Ok(msg) = Message::from_vec(query) else {
        return strict.then(|| "undecodable DNS query".to_string());
    };
    let questions = msg.queries();
    if questions.len() != 1 {
        return strict.then(|| {
            format!(
                "DNS query with {} questions (exactly one is accepted)",
                questions.len()
            )
        });
    }
    let name = questions[0].name();
    match scope_name(name) {
        Some(qname) => rules
            .check_dns(ws, &qname)
            .blocked_reason()
            .map(str::to_string),
        None => strict.then(|| {
            format!(
                "DNS name {} has a label outside [A-Za-z0-9-_]",
                name.to_ascii()
            )
        }),
    }
}

/// A DNS name as the scope compares it: its wire labels joined with `.`, no
/// trailing dot, or `None` when a label holds anything but `[A-Za-z0-9-_]`
/// (a `.` byte, a space, raw UTF-8...). IDN labels stay in their `xn--` form.
fn scope_name(name: &Name) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    for label in name.iter() {
        if label.is_empty()
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(label).ok()?);
    }
    Some(out)
}

/// Feed the scope's name cache from a DNS response: every A/AAAA address in
/// the answer section maps to the question name AND every name of the answer's
/// CNAME chain (the owner names and CNAME targets).
fn learn_names(scope: &ScopeEngine, workspace_id: i64, answer: &[u8]) {
    let Ok(msg) = Message::from_vec(answer) else {
        return;
    };
    if msg.response_code() != ResponseCode::NoError {
        return;
    }
    // ASCII (punycode) form, like the scope checks; a name that is not a plain
    // host name can never match a rule and is not learned.
    let mut names: Vec<String> = msg
        .queries()
        .iter()
        .filter_map(|q| scope_name(q.name()))
        .collect();
    let mut ips: Vec<IpAddr> = Vec::new();
    for rec in msg.answers() {
        names.extend(scope_name(rec.name()));
        match rec.data() {
            RData::A(a) => ips.push(IpAddr::V4(a.0)),
            RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
            RData::CNAME(c) => names.extend(scope_name(&c.0)),
            _ => {}
        }
    }
    if ips.is_empty() {
        return;
    }
    names.sort();
    names.dedup();
    for ip in ips {
        scope.cache().record(workspace_id, ip, &names);
    }
}

/// The answer a `dns-query` hook decided on, or `None` to resolve upstream.
///
/// Every failure here FAILS OPEN — an undecodable query, a `set-answer` whose
/// family does not match the question, a message that will not re-encode — and
/// falls back to resolving. A hook that cannot be honoured must never turn into
/// a name that stops resolving.
fn hooked_answer(query: &[u8], decision: DnsDecision) -> Option<Vec<u8>> {
    let (rcode, ip) = match decision {
        DnsDecision::Resolve => return None,
        DnsDecision::Refuse => (ResponseCode::Refused, None),
        DnsDecision::Answer(ip) => (ResponseCode::NoError, Some(ip)),
    };
    match synthesize(query, rcode, ip) {
        Some(bytes) => {
            tracing::info!(
                refused = rcode == ResponseCode::Refused,
                answered = ?ip,
                "dns query answered by a hook instead of being resolved"
            );
            Some(bytes)
        }
        None => {
            tracing::warn!(
                answered = ?ip,
                "a dns hook could not be applied to this query (undecodable, or a \
                 record type the address does not fit); resolving upstream instead"
            );
            None
        }
    }
}

/// Build a response to `query` carrying `rcode` and, optionally, one address
/// record. `None` when the query cannot be decoded, has no question, or asks for
/// a record type `ip` cannot answer (an `A` hook has nothing to say about an
/// `MX` lookup, and saying it anyway would be a lie the client caches).
fn synthesize(query: &[u8], rcode: ResponseCode, ip: Option<IpAddr>) -> Option<Vec<u8>> {
    let request = Message::from_vec(query).ok()?;
    let question = request.queries().first()?.clone();
    if let Some(addr) = ip {
        let wanted = match addr {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::AAAA,
        };
        if question.query_type() != wanted {
            return None;
        }
    }

    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_op_code(request.op_code())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(rcode)
        .add_query(question.clone());
    if let Some(addr) = ip {
        let rdata = match addr {
            IpAddr::V4(v4) => RData::A(v4.into()),
            IpAddr::V6(v6) => RData::AAAA(v6.into()),
        };
        response.set_authoritative(true);
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            SYNTHETIC_TTL,
            rdata,
        ));
    }
    response.to_vec().ok()
}

/// Forward the raw query to the upstream resolver over UDP and return its reply.
async fn forward_upstream(query: &[u8], cfg: &DnsConfig) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if cfg.upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let up = UdpSocket::bind(bind).await?;
    up.connect(cfg.upstream).await?;
    up.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(cfg.timeout, up.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns upstream timeout"))??;
    buf.truncate(n);

    // Bind the reply to the query's transaction id. The socket is `connect`ed so
    // only the configured upstream can reach it (low risk), but a mismatched id
    // means the datagram is not the answer to THIS query — drop it rather than
    // relay a stray/spoofed response to the client. Best-effort: if either side
    // is undecodable we let the bytes through (decode is for logging only).
    if let (Some(qid), Some(rid)) = (message_id(query), message_id(&buf)) {
        if qid != rid {
            tracing::debug!(qid, rid, "dns reply id mismatch; dropping");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "dns upstream reply id mismatch",
            ));
        }
    }
    Ok(buf)
}

/// Decode just the 16-bit transaction id of a DNS message, best-effort.
fn message_id(bytes: &[u8]) -> Option<u16> {
    Message::from_vec(bytes).ok().map(|m| m.id())
}

/// Decode the (name, type) of the first question, best-effort. The name is in
/// its escaped ASCII form (`xn--` labels kept, a `.` inside a label written
/// `\.`): the Unicode rendering would make two different names look alike.
fn describe_query(bytes: &[u8]) -> (String, String) {
    match Message::from_vec(bytes) {
        Ok(msg) => match msg.queries().first() {
            Some(q) => (q.name().to_ascii(), format!("{:?}", q.query_type())),
            None => ("?".into(), "?".into()),
        },
        Err(_) => ("?".into(), "?".into()),
    }
}

/// Render answer records as a human-readable, FTS-friendly block.
fn describe_answer(bytes: &[u8]) -> String {
    match Message::from_vec(bytes) {
        Ok(msg) => {
            let mut out = String::new();
            for q in msg.queries() {
                out.push_str(&format!(
                    "; question {} {:?}\n",
                    q.name().to_ascii(),
                    q.query_type()
                ));
            }
            for a in msg.answers() {
                out.push_str(&format!("{a}\n"));
            }
            if msg.answers().is_empty() {
                out.push_str(&format!("; rcode {:?}\n", msg.response_code()));
            }
            out
        }
        Err(e) => format!("; undecodable answer: {e}"),
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    fn sample_query(name: &str) -> Vec<u8> {
        typed_query(name, RecordType::A)
    }

    fn typed_query(name: &str, rtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        let mut q = Query::new();
        q.set_name(Name::from_str(name).unwrap())
            .set_query_type(rtype);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    #[test]
    fn describes_query_name_and_type() {
        let bytes = sample_query("example.com.");
        let (name, ty) = describe_query(&bytes);
        assert!(name.starts_with("example.com"));
        assert_eq!(ty, "A");
    }

    #[test]
    fn describe_answer_handles_query_only_message() {
        let bytes = sample_query("test.local.");
        let rendered = describe_answer(&bytes);
        assert!(rendered.contains("test.local"));
    }

    /// A synthesized answer has to be an answer to THIS query: same id, same
    /// question, one record of the type that was asked for. A resolver that
    /// gets any of those wrong is a resolver whose reply is thrown away.
    #[test]
    fn a_synthesized_answer_echoes_the_query_and_carries_the_record() {
        let query = sample_query("internal.example.com.");
        let bytes = synthesize(
            &query,
            ResponseCode::NoError,
            Some("10.0.0.5".parse().unwrap()),
        )
        .expect("an A query is answerable with an A record");
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.id(), 0x1234, "the transaction id must be echoed");
        assert_eq!(msg.message_type(), MessageType::Response);
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.queries().len(), 1);
        assert!(msg.queries()[0].name().to_string().starts_with("internal"));
        assert_eq!(msg.answers().len(), 1);
        assert_eq!(msg.answers()[0].ttl(), SYNTHETIC_TTL);
        assert_eq!(
            msg.answers()[0].data().ip_addr(),
            Some("10.0.0.5".parse().unwrap())
        );
        assert!(msg.recursion_available());

        // AAAA, the same way.
        let v6 = typed_query("internal.example.com.", RecordType::AAAA);
        let bytes = synthesize(&v6, ResponseCode::NoError, Some("::1".parse().unwrap())).unwrap();
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(
            msg.answers()[0].data().ip_addr(),
            Some("::1".parse().unwrap())
        );
    }

    /// The honest boundary of `set-answer`: an address answers an address
    /// question and nothing else. Anything it cannot answer must fall back to
    /// resolving rather than invent a record — including a query it cannot even
    /// decode.
    #[test]
    fn an_address_hook_does_not_answer_a_question_it_cannot_answer() {
        // An A hook has nothing to say about an MX (or AAAA) lookup…
        for rtype in [RecordType::MX, RecordType::AAAA, RecordType::TXT] {
            let q = typed_query("internal.example.com.", rtype);
            assert!(
                synthesize(&q, ResponseCode::NoError, Some("10.0.0.5".parse().unwrap())).is_none(),
                "{rtype:?}"
            );
        }
        // …nor a v6 hook about an A lookup.
        let q = sample_query("internal.example.com.");
        assert!(synthesize(&q, ResponseCode::NoError, Some("::1".parse().unwrap())).is_none());
        // An undecodable datagram is forwarded, not answered.
        assert!(hooked_answer(&[0xff, 0x00], DnsDecision::Refuse).is_none());
        assert!(hooked_answer(&q, DnsDecision::Resolve).is_none());
    }

    /// A `drop` on DNS is a REFUSED answer, not silence: a client that gets no
    /// datagram retries for seconds and then blames the network.
    #[test]
    fn a_dropped_query_is_answered_refused() {
        let query = sample_query("telemetry.example.com.");
        let bytes = hooked_answer(&query, DnsDecision::Refuse).expect("an rcode, not silence");
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::Refused);
        assert_eq!(msg.id(), 0x1234);
        assert!(msg.answers().is_empty());
    }

    /// End to end through the shim: a `set-answer` hook must answer WITHOUT
    /// asking upstream. The upstream here is a socket nobody is listening on,
    /// so a reply proves the query never left.
    #[tokio::test]
    async fn a_set_answer_hook_answers_without_touching_the_upstream() {
        use burpwn_store::model::{Hook, HookAction, HookPhase, HookScope};

        let dead_upstream: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let hooks = HookEngine::new();
        hooks.set_hooks(vec![Hook {
            id: 1,
            enabled: true,
            name: "force".into(),
            phase: HookPhase::DnsQuery,
            scope: HookScope {
                host: "internal.example.com".into(),
                ..Default::default()
            },
            action: HookAction::SetAnswer {
                ip: "10.0.0.5".parse().unwrap(),
            },
            order: 0,
            timeout_ms: 1_000,
            ttl_ms: 0,
            created_at: 0,
        }]);

        let dir = tempfile::tempdir().unwrap();
        let store = burpwn_store::Store::open(dir.path().join("session.db")).unwrap();
        let shim = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let shim_addr = shim.local_addr().unwrap();
        let cfg = DnsConfig {
            upstream: dead_upstream,
            workspace_id: 1,
            exec_id: None,
            timeout: Duration::from_millis(200),
            hooks,
            scope: ScopeEngine::new(),
        };
        tokio::spawn(serve_socket(shim, cfg, store.writer()));

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client
            .send_to(&sample_query("internal.example.com."), shim_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("the shim must answer from the hook, not wait on the upstream")
            .unwrap();
        let msg = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(
            msg.answers()[0].data().ip_addr(),
            Some("10.0.0.5".parse().unwrap())
        );
    }

    /// A name the scope refuses is answered REFUSED by the shim and never
    /// reaches the upstream resolver (a live socket that must see nothing), and
    /// the query is recorded as a blocked flow.
    #[tokio::test]
    async fn a_scope_refused_name_is_refused_without_touching_the_upstream() {
        use crate::scope::{Pattern, Rule, RuleSet};
        use burpwn_store::model::{FlowFilter, ScopeKind};

        let upstream = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let scope = ScopeEngine::new();
        scope.set_rules(RuleSet::new(vec![Rule {
            id: 1,
            workspace_id: None,
            workspace: None,
            kind: ScopeKind::Allow,
            pattern: Pattern::parse("*.toto.fr").unwrap(),
        }]));

        let dir = tempfile::tempdir().unwrap();
        let store = burpwn_store::Store::open(dir.path().join("session.db")).unwrap();
        let shim = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let shim_addr = shim.local_addr().unwrap();
        let cfg = DnsConfig {
            upstream: upstream_addr,
            workspace_id: 1,
            exec_id: None,
            timeout: Duration::from_millis(500),
            hooks: HookEngine::new(),
            scope,
        };
        tokio::spawn(serve_socket(shim, cfg, store.writer()));

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client
            .send_to(&sample_query("evil.example.com."), shim_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("the shim answers a refused name itself")
            .unwrap();
        let msg = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::Refused);
        let mut up = [0u8; 512];
        let leaked = tokio::time::timeout(Duration::from_millis(300), upstream.recv(&mut up)).await;
        assert!(
            leaked.is_err(),
            "the refused query must never reach the upstream"
        );

        // Recorded, with the reason.
        let mut rows = Vec::new();
        for _ in 0..50 {
            rows = store
                .reader()
                .list_flows(&FlowFilter {
                    blocked_only: true,
                    ..Default::default()
                })
                .unwrap();
            if !rows.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(rows.len(), 1);
        assert!(rows[0]
            .blocked
            .as_deref()
            .unwrap()
            .starts_with("not in allowlist"));
    }

    /// Relayed address answers feed the scope cache with the question name and
    /// the whole CNAME chain.
    #[test]
    fn answers_feed_the_name_cache_with_the_cname_chain() {
        use hickory_proto::rr::rdata::CNAME;
        let mut msg = Message::new();
        msg.set_id(1)
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NoError);
        let mut q = Query::new();
        q.set_name(Name::from_str("www.toto.fr.").unwrap())
            .set_query_type(RecordType::A);
        msg.add_query(q);
        msg.add_answer(Record::from_rdata(
            Name::from_str("www.toto.fr.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_str("edge.cdn.net.").unwrap())),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_str("edge.cdn.net.").unwrap(),
            60,
            RData::A("9.9.9.9".parse::<Ipv4Addr>().unwrap().into()),
        ));
        let scope = ScopeEngine::new();
        learn_names(&scope, 4, &msg.to_vec().unwrap());
        let names = scope.cache().names(4, "9.9.9.9".parse().unwrap());
        assert!(names.contains(&"www.toto.fr".to_string()), "{names:?}");
        assert!(names.contains(&"edge.cdn.net".to_string()), "{names:?}");
        assert!(scope
            .cache()
            .names(1, "9.9.9.9".parse().unwrap())
            .is_empty());
        // A hook's synthesized answer is learned too.
        let synth = synthesize(
            &sample_query("forced.toto.fr."),
            ResponseCode::NoError,
            Some("10.0.0.9".parse().unwrap()),
        )
        .unwrap();
        learn_names(&scope, 4, &synth);
        assert_eq!(
            scope.cache().names(4, "10.0.0.9".parse().unwrap()),
            vec!["forced.toto.fr".to_string()]
        );
    }

    fn scope_with(pats: &[(crate::scope::Pattern, burpwn_store::model::ScopeKind)]) -> ScopeEngine {
        use crate::scope::{Rule, RuleSet};
        let scope = ScopeEngine::new();
        scope.set_rules(RuleSet::new(
            pats.iter()
                .enumerate()
                .map(|(i, (p, k))| Rule {
                    id: i as i64 + 1,
                    workspace_id: None,
                    workspace: None,
                    kind: *k,
                    pattern: p.clone(),
                })
                .collect(),
        ));
        scope
    }

    fn query_with_names(names: Vec<Name>) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(7)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query);
        for n in names {
            let mut q = Query::new();
            q.set_name(n).set_query_type(RecordType::A);
            msg.add_query(q);
        }
        msg.to_vec().unwrap()
    }

    /// IDN names are judged in their punycode form: the Unicode rendering of
    /// `xn--bcher-kva.example` is `bücher.example`, which no ASCII rule could
    /// ever match. The cache learns the punycode form too.
    #[test]
    fn scope_compares_idn_names_in_punycode() {
        use crate::scope::Pattern;
        use burpwn_store::model::ScopeKind;
        let scope = scope_with(&[(
            Pattern::parse("xn--bcher-kva.example").unwrap(),
            ScopeKind::Deny,
        )]);
        let q = query_with_names(vec![Name::from_utf8("bücher.example.").unwrap()]);
        let reason = scope_block_reason(&scope, 1, &q).expect("the IDN name is denied");
        assert!(reason.starts_with("deny rule #1"), "{reason}");
        assert_eq!(describe_query(&q).0, "xn--bcher-kva.example.");

        let synth =
            synthesize(&q, ResponseCode::NoError, Some("10.0.0.7".parse().unwrap())).unwrap();
        learn_names(&scope, 1, &synth);
        assert_eq!(
            scope.cache().names(1, "10.0.0.7".parse().unwrap()),
            vec!["xn--bcher-kva.example".to_string()]
        );
    }

    /// A wire label holding a `.` byte (`[evil][xn--bcher-kva.toto][fr]`) must
    /// not be read as extra labels: printed, it looks like a name under
    /// `toto.fr`. With host rules in force it is refused outright, and never
    /// learned by the cache.
    #[test]
    fn scope_refuses_labels_that_are_not_host_labels() {
        use crate::scope::Pattern;
        use burpwn_store::model::ScopeKind;
        use hickory_proto::rr::domain::Label;
        let tricky = Name::from_labels(vec![
            Label::from_raw_bytes(b"evil").unwrap(),
            Label::from_raw_bytes(b"xn--bcher-kva.toto").unwrap(),
            Label::from_raw_bytes(b"fr").unwrap(),
        ])
        .unwrap();
        let q = query_with_names(vec![tricky.clone()]);
        // It survives the wire as one label with a dot in it.
        let decoded = Message::from_vec(&q).unwrap();
        assert_eq!(decoded.queries()[0].name().num_labels(), 3);

        let allow = scope_with(&[(Pattern::parse("*.toto.fr").unwrap(), ScopeKind::Allow)]);
        let reason = scope_block_reason(&allow, 1, &q).expect("refused");
        assert!(reason.contains("label outside"), "{reason}");
        // A deny-only host scope refuses it too (it cannot be judged).
        let deny = scope_with(&[(Pattern::parse("other.test").unwrap(), ScopeKind::Deny)]);
        assert!(scope_block_reason(&deny, 1, &q).is_some());
        // Raw UTF-8 / spaces / `*` in a label: same.
        for bad in [&b"b\xc3\xbccher"[..], b"a b", b"*"] {
            let n = Name::from_labels(vec![
                Label::from_raw_bytes(bad).unwrap(),
                Label::from_raw_bytes(b"toto").unwrap(),
                Label::from_raw_bytes(b"fr").unwrap(),
            ])
            .unwrap();
            assert!(scope_block_reason(&allow, 1, &query_with_names(vec![n])).is_some());
        }
        // IP-only rules never refuse a name.
        let ip_only = scope_with(&[(Pattern::parse("10.0.0.0/8").unwrap(), ScopeKind::Allow)]);
        assert!(scope_block_reason(&ip_only, 1, &q).is_none());
        // Legit names still pass.
        let ok = query_with_names(vec![Name::from_str("_srv.api.toto.fr.").unwrap()]);
        assert!(scope_block_reason(&allow, 1, &ok).is_none());

        // The cache does not learn the tricky name.
        let synth =
            synthesize(&q, ResponseCode::NoError, Some("10.0.0.8".parse().unwrap())).unwrap();
        learn_names(&allow, 1, &synth);
        assert!(allow
            .cache()
            .names(1, "10.0.0.8".parse().unwrap())
            .is_empty());
    }

    /// Only the first question used to be checked: a second one rode along
    /// unchecked. With host rules, anything but exactly one question is
    /// refused.
    #[test]
    fn scope_refuses_queries_without_exactly_one_question() {
        use crate::scope::Pattern;
        use burpwn_store::model::ScopeKind;
        let allow = scope_with(&[(Pattern::parse("*.toto.fr").unwrap(), ScopeKind::Allow)]);
        let two = query_with_names(vec![
            Name::from_str("api.toto.fr.").unwrap(),
            Name::from_str("evil.com.").unwrap(),
        ]);
        let reason = scope_block_reason(&allow, 1, &two).expect("refused");
        assert!(reason.contains("2 questions"), "{reason}");
        assert!(scope_block_reason(&allow, 1, &query_with_names(vec![])).is_some());
        let one = query_with_names(vec![Name::from_str("api.toto.fr.").unwrap()]);
        assert!(scope_block_reason(&allow, 1, &one).is_none());
        assert!(scope_block_reason(&allow, 1, &[0xff, 0x00]).is_some());
    }

    #[test]
    fn undecodable_is_safe() {
        let (n, t) = describe_query(&[0xff, 0x00]);
        assert_eq!((n.as_str(), t.as_str()), ("?", "?"));
        assert!(describe_answer(&[0xff, 0x00]).contains("undecodable"));
    }

    #[tokio::test]
    async fn forwards_to_loopback_upstream_and_logs() {
        // Stand up a fake upstream resolver on loopback that echoes a canned
        // answer, then drive a query through `serve` and assert it round-trips.
        let upstream = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // The answer MUST echo the query's transaction id (0x1234, from
        // `sample_query`) or `forward_upstream` now drops it as a mismatch.
        let answer_bytes = {
            let mut msg = Message::new();
            msg.set_id(0x1234).set_message_type(MessageType::Response);
            msg.to_vec().unwrap()
        };
        let answer_for_task = answer_bytes.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((_, peer)) = upstream.recv_from(&mut buf).await {
                let _ = upstream.send_to(&answer_for_task, peer).await;
            }
        });

        let cfg = DnsConfig {
            upstream: upstream_addr,
            workspace_id: 1,
            exec_id: None,
            timeout: Duration::from_secs(2),
            hooks: HookEngine::new(),
            scope: ScopeEngine::new(),
        };
        let query = sample_query("forward.test.");
        let got = forward_upstream(&query, &cfg).await.unwrap();
        assert_eq!(got, answer_bytes);
    }

    // Regression: an upstream reply whose transaction id does not match the query
    // must be dropped (returned as an error) rather than relayed to the client.
    #[tokio::test]
    async fn drops_reply_with_mismatched_id() {
        let upstream = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // Canned answer carries a DIFFERENT id than the query (0x1234).
        let answer_bytes = {
            let mut msg = Message::new();
            msg.set_id(0xBEEF).set_message_type(MessageType::Response);
            msg.to_vec().unwrap()
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((_, peer)) = upstream.recv_from(&mut buf).await {
                let _ = upstream.send_to(&answer_bytes, peer).await;
            }
        });

        let cfg = DnsConfig {
            upstream: upstream_addr,
            workspace_id: 1,
            exec_id: None,
            timeout: Duration::from_secs(2),
            hooks: HookEngine::new(),
            scope: ScopeEngine::new(),
        };
        let query = sample_query("mismatch.test.");
        let err = forward_upstream(&query, &cfg).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
