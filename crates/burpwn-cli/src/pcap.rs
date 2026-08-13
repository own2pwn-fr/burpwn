//! pcapng export: synthesize a packet capture from stored application data.
//!
//! # What this is, and what it is not
//!
//! burpwn never captured a packet. The proxy terminates TLS, reassembles the
//! HTTP layer and stores *messages* — a method, a header block, a decoded body.
//! A pcap is the opposite: a list of frames with sequence numbers, an MTU and a
//! per-packet clock. So this module does not *convert* anything, it **fabricates
//! a plausible wire trace that carries the bytes we really have**. That is worth
//! doing — `Follow HTTP stream`, the HTTP dissector, `tshark -z`, an IDS replay
//! all become available — but the file must never be mistaken for a capture.
//!
//! ## Why pcapng and not classic pcap
//!
//! Both formats can hold the same synthetic frames, and Wireshark follows a TCP
//! stream out of either. pcapng wins on the one axis that matters here: a
//! classic pcap has **nowhere to say the file is synthetic**. Its 24-byte header
//! holds a magic, a version, a link type and a snaplen; the file therefore
//! claims to be a capture and there is no honest place to contradict it. pcapng
//! has options, so this writer stamps:
//!
//! - an `opt_comment` on the Section Header Block spelling out that every frame
//!   was generated from reassembled application data,
//! - `shb_userappl` = `burpwn <version>`,
//! - an `if_description` on the (fake) interface saying the same,
//! - an `opt_comment` on each synthetic `SYN` and on every frame whose bytes
//!   were re-encoded, so the provenance is visible **in the packet list**, not
//!   only in a README nobody ships with the file.
//!
//! The second win is the clock. The store keeps **milliseconds**; pcap's packet
//! header is microseconds, so a pcap export would have to pad three zero digits
//! onto every timestamp and imply a precision that does not exist. pcapng's
//! `if_tsresol` lets the file declare millisecond resolution, which is exactly
//! what we know.
//!
//! Cost: a hand-written writer (~200 lines) instead of ~60. No new dependency
//! either way — both formats are trivial enough that pulling a crate in would
//! buy nothing but a supply-chain edge.
//!
//! ## Reconstructed vs invented
//!
//! **Real, straight out of the store**: the request method / target / headers /
//! body, the response status / headers / body, the websocket frame payloads and
//! opcodes, the client and server addresses and ports, and the millisecond
//! timestamps of the request and the response.
//!
//! **Invented, because the store has no such thing**:
//! - the TCP handshake and teardown (`SYN`, `SYN/ACK`, `ACK`, `FIN`) — marked
//!   with a packet comment,
//! - all sequence / acknowledgement numbers, window sizes, IP ids and TTLs,
//! - the segmentation: payloads are cut at a conventional 1460-byte MSS (1440
//!   over IPv6) because the real segmentation was never recorded,
//! - the ordering of packets *within* one millisecond,
//! - `Content-Length`. Stored bodies are **decoded** (gunzipped, de-chunked), so
//!   the captured `Content-Length` / `Transfer-Encoding` / `Content-Encoding`
//!   headers describe bytes that are not in the file. Emitting them would make
//!   the stream undissectable, so they are dropped and a correct
//!   `Content-Length` is written instead. This is the one place where the header
//!   block on the wire differs from the header block in the store.
//! - an addresses fallback: a flow whose endpoint the store could not record is
//!   given an address from the RFC 5737 documentation ranges (`192.0.2.0/24` for
//!   a server, `198.51.100.0/24` for a client) — deliberately un-routable, so a
//!   reader who checks cannot mistake it for a real host.
//!
//! ## What is excluded, and why
//!
//! A flow whose *bytes* were never stored cannot be rendered without making them
//! up, so it is left out and **counted**, never faked:
//!
//! - `dns` — the store keeps the resolution, not the query/answer wire bytes.
//! - `rawtcp` — passthrough; the payload is not retained.
//! - `tls-passthru` — not decrypted; there is nothing to write but ciphertext we
//!   do not have.
//! - any HTTP/websocket flow with no request recorded (still in flight, or
//!   dropped at intercept).
//!
//! HTTP/2 flows *are* exported, but re-encoded as HTTP/1.1 on the wire: writing
//! real HPACK-compressed HTTP/2 framing would mean inventing a dynamic-table
//! history the store never had. Those flows are counted separately and each
//! carries a packet comment saying so.
//!
//! ## Why there is no `export_pcap` MCP tool
//!
//! For the same reason `export har` has none: the artefact is a binary file
//! whose only consumer is a human with Wireshark. A tool would hand an agent a
//! path and a set of counters and nothing it could act on, while costing a tool
//! description in every turn's context. `session_export` stays the archival
//! action an agent can actually use.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::Serialize;

use burpwn_store::model::{
    FlowDetail, Protocol, RequestData, ResponseData, WsDirection, WsMessage,
};
use burpwn_store::Reader;

/// `LINKTYPE_RAW`: the frame starts at the IP header. Chosen over
/// `LINKTYPE_ETHERNET` on purpose — an Ethernet frame would force us to invent
/// two MAC addresses for a hop that never existed. There was no link layer, so
/// the file does not pretend there was one.
const LINKTYPE_RAW: u16 = 101;

/// Snapshot length advertised in the interface block. Nothing is truncated;
/// this is the ceiling, and it is above any single synthetic frame.
const SNAPLEN: u32 = 262_144;

/// Conventional MSS for a 1500-byte MTU over IPv4 (1500 − 20 IP − 20 TCP) and
/// over IPv6 (1500 − 40 − 20). The real segmentation was never recorded; this
/// is the value a reader would expect to see on an ordinary path.
const MSS_V4: usize = 1460;
const MSS_V6: usize = 1440;

/// Fixed TCP receive window and IP TTL. Both are invented; constants keep the
/// output byte-for-byte reproducible for the same input.
const TCP_WINDOW: u16 = 65_535;
const IP_TTL: u8 = 64;

/// First port handed out when two synthetic connections would otherwise collide
/// on the same 4-tuple (the ephemeral range, per IANA).
const FIRST_SYNTHETIC_PORT: u16 = 49_152;

// TCP flag bits.
const F_FIN: u8 = 0x01;
const F_SYN: u8 = 0x02;
const F_PSH: u8 = 0x08;
const F_ACK: u8 = 0x10;

/// The comment stamped on the section header — the first thing a reader of the
/// file sees in Wireshark's `Statistics ▸ Capture File Properties`.
const SECTION_COMMENT: &str = concat!(
    "SYNTHETIC CAPTURE — not a packet capture.\n",
    "Generated by burpwn ",
    env!("CARGO_PKG_VERSION"),
    " from application data reassembled by its MITM proxy.\n",
    "Real: request/response bytes, websocket payloads, endpoints, millisecond timestamps.\n",
    "Invented: TCP handshakes and teardowns, all sequence/ack numbers, segmentation at a \
     conventional 1460-byte MSS, sub-millisecond ordering.\n",
    "Content-Length is rewritten to match the DECODED body (stored bodies are gunzipped and \
     de-chunked), and Content-Encoding / Transfer-Encoding are dropped.\n",
    "DNS, raw-TCP and TLS-passthrough flows are absent: burpwn stores their metadata, not their \
     bytes."
);

/// Comment carried by every fabricated handshake / teardown packet.
const HANDSHAKE_COMMENT: &str =
    "Synthetic TCP control packet: burpwn stores reassembled messages, never packets. \
     No handshake was observed; sequence numbers are generated.";

/// What an export actually produced. Every number here is reported to the user:
/// an export that silently dropped half a session would be worse than no export.
#[derive(Debug, Default, Clone, Serialize)]
pub struct PcapStats {
    /// Frames written.
    pub packets: usize,
    /// Synthetic TCP connections in the file.
    pub connections: usize,
    /// Flows that contributed bytes.
    pub flows_rendered: usize,
    /// Request/response exchanges written.
    pub exchanges: usize,
    /// Requests written with no response recorded.
    pub requests_without_response: usize,
    /// Websocket frames re-encoded onto the stream.
    pub ws_frames: usize,
    /// HTTP/2 flows re-encoded as HTTP/1.1 (see the module docs).
    pub h2_as_http1: usize,
    /// Connections that had to be given an invented client port to avoid two
    /// distinct conversations colliding on one 4-tuple.
    pub synthetic_client_ports: usize,
    /// Endpoints the store could not supply, filled from the RFC 5737 ranges.
    pub synthetic_addresses: usize,
    /// Flows left out, by reason. Keys are stable: `dns`, `raw_tcp`,
    /// `tls_passthru`, `no_request`, `not_found`.
    pub skipped: BTreeMap<String, usize>,
    /// Sum of [`Self::skipped`], so a caller does not have to add it up.
    pub skipped_total: usize,
}

impl PcapStats {
    fn skip(&mut self, reason: &str) {
        *self.skipped.entry(reason.to_string()).or_insert(0) += 1;
        self.skipped_total += 1;
    }

    /// A one-line, human-readable account of what was left out, or `None` when
    /// nothing was. Never say "some flows were skipped" when none were.
    pub fn skipped_summary(&self) -> Option<String> {
        if self.skipped.is_empty() {
            return None;
        }
        let parts: Vec<String> = self
            .skipped
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect();
        Some(parts.join(", "))
    }
}

/// A finished export: the pcapng bytes and what went into them.
#[derive(Debug)]
pub struct PcapExport {
    /// The complete pcapng file.
    pub bytes: Vec<u8>,
    /// Counters, including the exclusions.
    pub stats: PcapStats,
}

/// Build a pcapng file from the given flows (ids in any order — they are sorted
/// by start time here, because a capture file is chronological).
pub fn build_pcapng(reader: &Reader, flow_ids: &[i64]) -> anyhow::Result<PcapExport> {
    let mut stats = PcapStats::default();

    // 1. Load, and drop what cannot be rendered without inventing bytes.
    let mut details: Vec<FlowDetail> = Vec::new();
    for &id in flow_ids {
        let Some(detail) = reader.get_flow(id)? else {
            stats.skip("not_found");
            continue;
        };
        match detail.flow.protocol {
            Protocol::Dns => {
                stats.skip("dns");
                continue;
            }
            Protocol::RawTcp => {
                stats.skip("raw_tcp");
                continue;
            }
            Protocol::TlsPassthru => {
                stats.skip("tls_passthru");
                continue;
            }
            Protocol::H1 | Protocol::H2 | Protocol::Ws => {}
        }
        if detail.request.is_none() {
            stats.skip("no_request");
            continue;
        }
        details.push(detail);
    }
    // Chronological, id as the tiebreak so the output is deterministic.
    details.sort_by_key(|d| (d.flow.ts_start, d.flow.id));

    // 2. Lay the flows out on synthetic TCP connections.
    let mut conns: Vec<Conn> = Vec::new();
    let mut by_key: HashMap<String, usize> = HashMap::new();
    let mut taken: HashSet<(IpAddr, u16, IpAddr, u16)> = HashSet::new();
    let mut next_port = FIRST_SYNTHETIC_PORT;

    for detail in &details {
        let ws_msgs = if detail.flow.protocol == Protocol::Ws {
            reader.ws_messages_for_flow(detail.flow.id)?
        } else {
            Vec::new()
        };

        // An HTTP/1 client connection is keep-alive by nature, and `client_addr`
        // IS the real client socket — two flows sharing it really did share a
        // TCP connection, so they share one synthetic stream and its sequence
        // space. HTTP/2 is multiplexed and websockets are long-lived: laying
        // several of those on one stream would produce interleaved nonsense, so
        // they each get their own.
        let key = match detail.flow.protocol {
            Protocol::H1 => format!(
                "h1|{}|{}|{}",
                detail.client_addr, detail.flow.dst_ip, detail.flow.dst_port
            ),
            _ => format!("flow{}", detail.flow.id),
        };

        let idx = match by_key.get(&key) {
            Some(&i) => i,
            None => {
                let (client, server, synth_addrs) = endpoints(detail);
                let mut client = client;
                // Two different conversations must never share a 4-tuple, or
                // Wireshark merges them into one broken stream.
                while !taken.insert((client.0, client.1, server.0, server.1)) {
                    client.1 = next_port;
                    next_port = next_port.checked_add(1).unwrap_or(FIRST_SYNTHETIC_PORT);
                    stats.synthetic_client_ports += 1;
                }
                stats.synthetic_addresses += synth_addrs;
                conns.push(Conn::new(&key, client, server));
                by_key.insert(key.clone(), conns.len() - 1);
                conns.len() - 1
            }
        };

        let conn = &mut conns[idx];
        stats.flows_rendered += 1;
        if detail.flow.protocol == Protocol::H2 {
            stats.h2_as_http1 += 1;
        }
        render_flow(conn, detail, &ws_msgs, &mut stats);
    }

    // 3. Close every connection and flatten. A stable sort by timestamp keeps
    //    each connection's own packets in order (they are already monotonic),
    //    while interleaving connections the way a real capture would.
    let mut packets: Vec<Pkt> = Vec::new();
    for conn in &mut conns {
        conn.close();
        packets.append(&mut conn.pkts);
    }
    packets.sort_by_key(|p| p.ts_ms);

    stats.packets = packets.len();
    stats.connections = conns.len();

    Ok(PcapExport {
        bytes: write_pcapng(&packets),
        stats,
    })
}

/// Write one flow (handshake if needed, request, response, websocket frames)
/// onto its connection.
fn render_flow(conn: &mut Conn, detail: &FlowDetail, ws: &[WsMessage], stats: &mut PcapStats) {
    let Some(req) = detail.request.as_ref() else {
        return;
    };
    let ts_req = detail.flow.ts_start;
    conn.open(ts_req);

    let downgraded = detail.flow.protocol == Protocol::H2;
    let comment = downgraded.then(|| {
        "This exchange was HTTP/2 on the wire. burpwn stores the decoded messages, not the \
         HPACK-compressed frames, so it is re-encoded here as HTTP/1.1."
            .to_string()
    });
    conn.data(Dir::C2s, &request_bytes(req), ts_req, comment.clone());

    let timed = detail
        .response
        .as_ref()
        .and_then(|r| r.timing_ms)
        .map(|t| ts_req + t);
    // On an ordinary exchange `ts_end` IS when the response finished. On a
    // websocket flow it is when the CONNECTION closed, long after the 101 — use
    // the measured timing there, or every frame exchanged in between would pile
    // up behind a handshake dated at the end of the conversation.
    let ts_resp = if ws.is_empty() {
        detail.flow.ts_end.or(timed)
    } else {
        timed.or(detail.flow.ts_end)
    }
    .unwrap_or(ts_req)
    .max(ts_req);

    match detail.response.as_ref() {
        Some(resp) => {
            stats.exchanges += 1;
            conn.data(Dir::S2c, &response_bytes(resp), ts_resp, comment);
        }
        None => stats.requests_without_response += 1,
    }

    // Websocket frames ride the same stream after the 101, exactly as they do
    // on a real connection — which is what makes Wireshark's websocket
    // dissector light up.
    if ws.is_empty() {
        return;
    }
    let span_end = detail.flow.ts_end.unwrap_or(ts_resp).max(ts_resp);
    for (i, msg) in ws.iter().enumerate() {
        // Frames without a recorded timestamp are spread evenly over the flow's
        // own span rather than piled onto one instant.
        let ts = msg.ts.unwrap_or_else(|| {
            let n = ws.len().max(1) as i64;
            ts_resp + (span_end - ts_resp) * (i as i64 + 1) / n
        });
        let dir = match msg.direction {
            WsDirection::C2s => Dir::C2s,
            WsDirection::S2c => Dir::S2c,
        };
        conn.data(dir, &ws_frame(msg), ts.max(ts_resp), None);
        stats.ws_frames += 1;
    }
}

// --- endpoints ---------------------------------------------------------------

/// Resolve a flow's two endpoints, returning `(client, server, invented_count)`.
///
/// Anything the store could not supply is filled from RFC 5737's documentation
/// ranges — addresses that are guaranteed not to route, so a reader who looks
/// one up cannot mistake it for a host that was really contacted.
fn endpoints(detail: &FlowDetail) -> ((IpAddr, u16), (IpAddr, u16), usize) {
    let mut invented = 0usize;

    let server_ip = match detail.flow.dst_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            invented += 1;
            // TEST-NET-1, keyed on the authority so the same host keeps the
            // same placeholder across the file.
            let h = fnv1a(detail.flow.authority.as_deref().unwrap_or("unknown"));
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, (h % 254) as u8 + 1))
        }
    };
    let server_port = if detail.flow.dst_port == 0 {
        if detail.flow.scheme == "https" {
            443
        } else {
            80
        }
    } else {
        detail.flow.dst_port
    };

    let parsed_client = detail.client_addr.parse::<SocketAddr>().ok();
    let client_port = parsed_client.map(|a| a.port()).unwrap_or_else(|| {
        // Deterministic ephemeral port from the flow id.
        FIRST_SYNTHETIC_PORT.wrapping_add((detail.flow.id % 10_000) as u16)
    });
    let client_ip = match parsed_client.map(|a| a.ip()) {
        // Same family as the server, or the IP header cannot be built at all.
        Some(ip) if ip.is_ipv4() == server_ip.is_ipv4() => ip,
        _ => {
            invented += 1;
            if server_ip.is_ipv4() {
                // TEST-NET-2.
                let h = fnv1a(&detail.client_addr);
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, (h % 254) as u8 + 1))
            } else {
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            }
        }
    };

    ((client_ip, client_port), (server_ip, server_port), invented)
}

// --- HTTP reconstruction -----------------------------------------------------

/// Header names whose stored value describes bytes that are NOT what we write.
/// Stored bodies are decoded, so keeping these would frame the stream wrong and
/// make the whole capture undissectable — the one lossy rewrite in this module.
const FRAMING_HEADERS: [&str; 3] = ["content-length", "transfer-encoding", "content-encoding"];

fn request_bytes(req: &RequestData) -> Vec<u8> {
    let target = if req.path.is_empty() { "/" } else { &req.path };
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, target).into_bytes();
    let mut headers = kept_headers(&req.headers);
    // HTTP/2 carries the authority in `:authority`, which has no place in a
    // header block; HTTP/1.1 needs a Host line or the dissector has no host.
    if !headers
        .iter()
        .any(|(n, _)| n == "host" || n == ":authority")
        && !req.authority.is_empty()
    {
        headers.insert(0, ("host".into(), format!("Host: {}", req.authority)));
    }
    for (_, line) in &headers {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !req.body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

fn response_bytes(resp: &ResponseData) -> Vec<u8> {
    let reason = reason_phrase(resp.status);
    let mut out = if reason.is_empty() {
        format!("HTTP/1.1 {}\r\n", resp.status).into_bytes()
    } else {
        format!("HTTP/1.1 {} {reason}\r\n", resp.status).into_bytes()
    };
    for (_, line) in kept_headers(&resp.headers) {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // 101 hands the connection to another protocol: a Content-Length there
    // would contradict the upgrade. Every other status gets one, so a
    // keep-alive stream stays parseable without waiting for a close.
    if resp.status != 101 {
        out.extend_from_slice(format!("Content-Length: {}\r\n", resp.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&resp.body);
    out
}

/// Split a stored header block into `(lowercased name, original line)`, dropping
/// the framing headers and any pseudo-header (`:method`, `:authority`, …) which
/// is HTTP/2 syntax and not writable on an HTTP/1 wire.
fn kept_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, _)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || line.starts_with(':') {
            continue;
        }
        if FRAMING_HEADERS.contains(&name.as_str()) {
            continue;
        }
        out.push((name, line.to_string()));
    }
    out
}

/// The reason phrases a reader expects to see. Unknown codes get none — an
/// invented phrase would be a lie about a field we simply never stored.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Encode one stored websocket message as an RFC 6455 frame.
///
/// Client frames must be masked, so they are — with an all-zero key. Masking
/// with zero is legal (XOR is the identity), the dissector unmasks it, and the
/// payload stays readable in `Follow TCP stream` instead of turning into noise
/// nobody can grep.
fn ws_frame(msg: &WsMessage) -> Vec<u8> {
    let fin = msg.fin.unwrap_or(true);
    let opcode = (msg.opcode.unwrap_or(1) & 0x0f) as u8;
    let masked = msg.direction == WsDirection::C2s;
    let len = msg.payload.len();

    let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
    let mask_bit = if masked { 0x80u8 } else { 0 };
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if masked {
        out.extend_from_slice(&[0, 0, 0, 0]);
    }
    out.extend_from_slice(&msg.payload);
    out
}

// --- synthetic TCP -----------------------------------------------------------

/// Which way a segment travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    C2s,
    S2c,
}

/// One synthesized frame, with the timestamp it will carry.
struct Pkt {
    ts_ms: i64,
    data: Vec<u8>,
    comment: Option<String>,
}

/// A synthetic TCP connection: two endpoints, a sequence space, and the frames
/// generated so far.
struct Conn {
    client: (IpAddr, u16),
    server: (IpAddr, u16),
    seq_c: u32,
    seq_s: u32,
    ip_id: u16,
    opened: bool,
    last_ts: i64,
    pkts: Vec<Pkt>,
}

impl Conn {
    fn new(key: &str, client: (IpAddr, u16), server: (IpAddr, u16)) -> Self {
        // Initial sequence numbers derived from the connection key: invented,
        // but deterministic, so the same session exports byte-for-byte the same
        // file twice (which is what makes the tests meaningful).
        Self {
            client,
            server,
            seq_c: fnv1a(&format!("{key}|c")) | 1,
            seq_s: fnv1a(&format!("{key}|s")) | 1,
            ip_id: 1,
            opened: false,
            last_ts: 0,
            pkts: Vec::new(),
        }
    }

    fn mss(&self) -> usize {
        if self.server.0.is_ipv4() {
            MSS_V4
        } else {
            MSS_V6
        }
    }

    /// Timestamps never go backwards inside a connection: a flow recorded out of
    /// order would otherwise produce a capture Wireshark flags as corrupt.
    fn stamp(&mut self, ts: i64) -> i64 {
        let ts = ts.max(self.last_ts);
        self.last_ts = ts;
        ts
    }

    /// Emit the three-way handshake, once, at the first exchange.
    fn open(&mut self, ts: i64) {
        if self.opened {
            return;
        }
        self.opened = true;
        let ts = self.stamp(ts);
        let (isn_c, isn_s) = (self.seq_c, self.seq_s);
        self.emit(
            Dir::C2s,
            F_SYN,
            isn_c,
            0,
            &[],
            ts,
            Some(HANDSHAKE_COMMENT.into()),
        );
        self.emit(
            Dir::S2c,
            F_SYN | F_ACK,
            isn_s,
            isn_c.wrapping_add(1),
            &[],
            ts,
            None,
        );
        self.seq_c = isn_c.wrapping_add(1);
        self.seq_s = isn_s.wrapping_add(1);
        let (c, s) = (self.seq_c, self.seq_s);
        self.emit(Dir::C2s, F_ACK, c, s, &[], ts, None);
    }

    /// Segment `payload` at the MSS and acknowledge it from the far side.
    fn data(&mut self, dir: Dir, payload: &[u8], ts: i64, comment: Option<String>) {
        if payload.is_empty() {
            return;
        }
        let ts = self.stamp(ts);
        let mss = self.mss();
        let chunks: Vec<&[u8]> = payload.chunks(mss).collect();
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let (seq, ack) = match dir {
                Dir::C2s => (self.seq_c, self.seq_s),
                Dir::S2c => (self.seq_s, self.seq_c),
            };
            let flags = if i == last { F_ACK | F_PSH } else { F_ACK };
            let c = if i == 0 { comment.clone() } else { None };
            self.emit(dir, flags, seq, ack, chunk, ts, c);
            match dir {
                Dir::C2s => self.seq_c = self.seq_c.wrapping_add(chunk.len() as u32),
                Dir::S2c => self.seq_s = self.seq_s.wrapping_add(chunk.len() as u32),
            }
        }
        // The bare ACK the peer would have sent back.
        let (rdir, seq, ack) = match dir {
            Dir::C2s => (Dir::S2c, self.seq_s, self.seq_c),
            Dir::S2c => (Dir::C2s, self.seq_c, self.seq_s),
        };
        self.emit(rdir, F_ACK, seq, ack, &[], ts, None);
    }

    /// Emit the FIN exchange. A connection that never carried a byte is left
    /// empty rather than given a handshake it never had.
    fn close(&mut self) {
        if !self.opened {
            return;
        }
        let ts = self.last_ts;
        let (c, s) = (self.seq_c, self.seq_s);
        self.emit(
            Dir::C2s,
            F_FIN | F_ACK,
            c,
            s,
            &[],
            ts,
            Some(HANDSHAKE_COMMENT.into()),
        );
        self.seq_c = c.wrapping_add(1);
        let (c, s) = (self.seq_c, self.seq_s);
        self.emit(Dir::S2c, F_ACK, s, c, &[], ts, None);
        self.emit(Dir::S2c, F_FIN | F_ACK, s, c, &[], ts, None);
        self.seq_s = s.wrapping_add(1);
        let (c, s) = (self.seq_c, self.seq_s);
        self.emit(Dir::C2s, F_ACK, c, s, &[], ts, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        dir: Dir,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
        ts: i64,
        comment: Option<String>,
    ) {
        let (src, dst) = match dir {
            Dir::C2s => (self.client, self.server),
            Dir::S2c => (self.server, self.client),
        };
        let tcp = tcp_segment(src.0, dst.0, src.1, dst.1, seq, ack, flags, payload);
        let data = match (src.0, dst.0) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let id = self.ip_id;
                self.ip_id = self.ip_id.wrapping_add(1);
                ipv4_packet(s, d, id, &tcp)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => ipv6_packet(s, d, &tcp),
            // Families are coerced to match in `endpoints`; unreachable in
            // practice, and dropping the frame beats writing a malformed one.
            _ => return,
        };
        self.pkts.push(Pkt {
            ts_ms: ts,
            data,
            comment,
        });
    }
}

/// Build a TCP segment, checksum included. Wireshark does not verify TCP
/// checksums by default, but a wrong one shows up red in the detail pane and
/// would make every frame look broken — cheap to get right, expensive to skip.
#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(5 << 4); // data offset = 5 words, no options
    seg.push(flags);
    seg.extend_from_slice(&TCP_WINDOW.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(payload);

    let mut sum = Checksum::default();
    match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum.feed(&s.octets());
            sum.feed(&d.octets());
            sum.feed(&[0, 6]);
            sum.feed(&(seg.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum.feed(&s.octets());
            sum.feed(&d.octets());
            sum.feed(&(seg.len() as u32).to_be_bytes());
            sum.feed(&[0, 0, 0, 6]);
        }
        _ => {}
    }
    sum.feed(&seg);
    let ck = sum.finish();
    seg[16..18].copy_from_slice(&ck.to_be_bytes());
    seg
}

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, id: u16, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut ip = Vec::with_capacity(total as usize);
    ip.push(0x45); // IPv4, 5-word header
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    ip.push(IP_TTL);
    ip.push(6); // TCP
    ip.extend_from_slice(&[0, 0]); // checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let mut sum = Checksum::default();
    sum.feed(&ip);
    let ck = sum.finish();
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    ip.extend_from_slice(payload);
    ip
}

fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut ip = Vec::with_capacity(40 + payload.len());
    ip.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6, no TC/flow
    ip.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ip.push(6); // next header: TCP
    ip.push(IP_TTL); // hop limit
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(payload);
    ip
}

/// The internet checksum (RFC 1071), fed in arbitrary-sized slices.
#[derive(Default)]
struct Checksum {
    sum: u32,
    odd: Option<u8>,
}

impl Checksum {
    fn feed(&mut self, mut bytes: &[u8]) {
        if let Some(hi) = self.odd.take() {
            if let Some((&lo, rest)) = bytes.split_first() {
                self.sum += u16::from_be_bytes([hi, lo]) as u32;
                bytes = rest;
            } else {
                self.odd = Some(hi);
                return;
            }
        }
        let mut chunks = bytes.chunks_exact(2);
        for c in &mut chunks {
            self.sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let [last] = chunks.remainder() {
            self.odd = Some(*last);
        }
    }

    fn finish(mut self) -> u16 {
        if let Some(hi) = self.odd.take() {
            self.sum += u16::from_be_bytes([hi, 0]) as u32;
        }
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        !(self.sum as u16)
    }
}

/// FNV-1a, 32-bit. Not a security primitive — it exists so that invented values
/// (ISNs, placeholder addresses) are stable for a given input.
fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

// --- pcapng container --------------------------------------------------------

const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;

const OPT_ENDOFOPT: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_DESCRIPTION: u16 = 3;
const IF_TSRESOL: u16 = 9;

/// Serialize the frames as a little-endian pcapng section.
fn write_pcapng(packets: &[Pkt]) -> Vec<u8> {
    let mut out = Vec::new();

    // Section Header Block.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // byte-order magic
    shb.extend_from_slice(&1u16.to_le_bytes()); // major
    shb.extend_from_slice(&0u16.to_le_bytes()); // minor
    shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
    push_option(&mut shb, OPT_COMMENT, SECTION_COMMENT.as_bytes());
    push_option(
        &mut shb,
        SHB_USERAPPL,
        format!("burpwn {}", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    end_options(&mut shb);
    push_block(&mut out, BT_SHB, &shb);

    // Interface Description Block: one fake interface, described as fake.
    let mut idb = Vec::new();
    idb.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
    idb.extend_from_slice(&SNAPLEN.to_le_bytes());
    push_option(&mut idb, IF_NAME, b"burpwn-synthetic");
    push_option(
        &mut idb,
        IF_DESCRIPTION,
        b"Synthetic interface: frames generated by burpwn from reassembled \
          application data. No interface was ever captured from.",
    );
    // Timestamps are in MILLISECONDS — the resolution the store actually has.
    push_option(&mut idb, IF_TSRESOL, &[3u8]);
    end_options(&mut idb);
    push_block(&mut out, BT_IDB, &idb);

    for p in packets {
        let ts = p.ts_ms.max(0) as u64;
        let mut epb = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes()); // interface id
        epb.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&((ts & 0xffff_ffff) as u32).to_le_bytes());
        epb.extend_from_slice(&(p.data.len() as u32).to_le_bytes()); // captured
        epb.extend_from_slice(&(p.data.len() as u32).to_le_bytes()); // original
        epb.extend_from_slice(&p.data);
        pad4(&mut epb);
        if let Some(c) = &p.comment {
            push_option(&mut epb, OPT_COMMENT, c.as_bytes());
            end_options(&mut epb);
        }
        push_block(&mut out, BT_EPB, &epb);
    }
    out
}

/// Frame a block body: type, total length, body, total length again.
fn push_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let total = (12 + body.len()) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    pad4(buf);
}

fn end_options(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&OPT_ENDOFOPT.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
}

fn pad4(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_store::model::FlowStart;
    use burpwn_store::{schema, Store};

    // --- A minimal pcapng READER, so the tests validate the file rather than
    // --- the writer's own idea of it. tshark cannot be assumed present on a
    // --- build box, so structural correctness is asserted here and the
    // --- external check below runs only when the machine can do it.

    #[derive(Debug)]
    struct ParsedPkt {
        ts_ms: u64,
        comment: Option<String>,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        payload: Vec<u8>,
    }

    #[derive(Debug, Default)]
    struct ParsedFile {
        section_comment: Option<String>,
        userappl: Option<String>,
        if_description: Option<String>,
        linktype: u16,
        tsresol: u8,
        packets: Vec<ParsedPkt>,
    }

    fn le16(b: &[u8]) -> u16 {
        u16::from_le_bytes([b[0], b[1]])
    }

    fn le32(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Walk the option list at the end of a block body.
    fn parse_options(mut b: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        while b.len() >= 4 {
            let code = le16(&b[0..2]);
            let len = le16(&b[2..4]) as usize;
            if code == OPT_ENDOFOPT {
                break;
            }
            assert!(b.len() >= 4 + len, "option runs past the block");
            out.push((code, b[4..4 + len].to_vec()));
            b = &b[4 + len.div_ceil(4) * 4..];
        }
        out
    }

    fn parse_pcapng(bytes: &[u8]) -> ParsedFile {
        let mut f = ParsedFile::default();
        let mut off = 0usize;
        let mut seen_shb = false;
        while off < bytes.len() {
            assert!(bytes.len() - off >= 12, "truncated block header");
            let btype = le32(&bytes[off..]);
            let total = le32(&bytes[off + 4..]) as usize;
            assert_eq!(total % 4, 0, "block length is not 32-bit aligned");
            assert!(
                total >= 12 && off + total <= bytes.len(),
                "bad block length"
            );
            // The trailing length MUST repeat the leading one — that redundancy
            // is what lets a reader walk a pcapng backwards, and getting it
            // wrong is the classic hand-written-writer bug.
            assert_eq!(
                le32(&bytes[off + total - 4..]),
                total as u32,
                "trailing block length mismatch"
            );
            let body = &bytes[off + 8..off + total - 4];
            match btype {
                BT_SHB => {
                    assert!(!seen_shb, "only one section expected");
                    seen_shb = true;
                    assert_eq!(le32(&body[0..4]), 0x1A2B_3C4D, "byte-order magic");
                    assert_eq!(le16(&body[4..6]), 1, "major version");
                    for (code, v) in parse_options(&body[16..]) {
                        let s = String::from_utf8_lossy(&v).into_owned();
                        match code {
                            OPT_COMMENT => f.section_comment = Some(s),
                            SHB_USERAPPL => f.userappl = Some(s),
                            _ => {}
                        }
                    }
                }
                BT_IDB => {
                    f.linktype = le16(&body[0..2]);
                    for (code, v) in parse_options(&body[8..]) {
                        match code {
                            IF_TSRESOL => f.tsresol = v[0],
                            IF_DESCRIPTION => {
                                f.if_description = Some(String::from_utf8_lossy(&v).into_owned());
                            }
                            _ => {}
                        }
                    }
                }
                BT_EPB => {
                    let ts = ((le32(&body[4..8]) as u64) << 32) | le32(&body[8..12]) as u64;
                    let cap = le32(&body[12..16]) as usize;
                    let orig = le32(&body[16..20]) as usize;
                    assert_eq!(cap, orig, "nothing is truncated");
                    let data = &body[20..20 + cap];
                    let padded = (20 + cap.div_ceil(4) * 4).min(body.len());
                    let comment = parse_options(&body[padded..])
                        .into_iter()
                        .find(|(c, _)| *c == OPT_COMMENT)
                        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned());
                    f.packets.push(parse_frame(data, ts, comment));
                }
                other => panic!("unexpected block type {other:#x}"),
            }
            off += total;
        }
        assert!(seen_shb, "no section header block");
        f
    }

    /// Decode a raw-IP frame, verifying both checksums on the way through.
    fn parse_frame(data: &[u8], ts_ms: u64, comment: Option<String>) -> ParsedPkt {
        let (src, dst, tcp): (IpAddr, IpAddr, &[u8]) = match data[0] >> 4 {
            4 => {
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                assert_eq!(ihl, 20);
                let mut ck = Checksum::default();
                ck.feed(&data[..ihl]);
                assert_eq!(ck.finish(), 0, "IPv4 header checksum");
                assert_eq!(data[9], 6, "protocol is TCP");
                assert_eq!(
                    u16::from_be_bytes([data[2], data[3]]) as usize,
                    data.len(),
                    "IPv4 total length"
                );
                let s = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                let d = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                (IpAddr::V4(s), IpAddr::V4(d), &data[ihl..])
            }
            6 => {
                assert_eq!(data[6], 6, "next header is TCP");
                assert_eq!(
                    u16::from_be_bytes([data[4], data[5]]) as usize,
                    data.len() - 40,
                    "IPv6 payload length"
                );
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s.copy_from_slice(&data[8..24]);
                d.copy_from_slice(&data[24..40]);
                (
                    IpAddr::V6(Ipv6Addr::from(s)),
                    IpAddr::V6(Ipv6Addr::from(d)),
                    &data[40..],
                )
            }
            v => panic!("unexpected IP version {v}"),
        };

        // The TCP checksum over the pseudo-header + segment must fold to zero.
        let mut ck = Checksum::default();
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ck.feed(&s.octets());
                ck.feed(&d.octets());
                ck.feed(&[0, 6]);
                ck.feed(&(tcp.len() as u16).to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ck.feed(&s.octets());
                ck.feed(&d.octets());
                ck.feed(&(tcp.len() as u32).to_be_bytes());
                ck.feed(&[0, 0, 0, 6]);
            }
            _ => unreachable!("families are coerced to match"),
        }
        ck.feed(tcp);
        assert_eq!(ck.finish(), 0, "TCP checksum");

        let data_off = ((tcp[12] >> 4) as usize) * 4;
        ParsedPkt {
            ts_ms,
            comment,
            src,
            dst,
            sport: u16::from_be_bytes([tcp[0], tcp[1]]),
            dport: u16::from_be_bytes([tcp[2], tcp[3]]),
            seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            flags: tcp[13],
            payload: tcp[data_off..].to_vec(),
        }
    }

    /// Reassemble one direction of one conversation, asserting the sequence
    /// space is contiguous — the property `Follow HTTP stream` depends on.
    fn follow(f: &ParsedFile, sport: u16, dport: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let mut expect: Option<u32> = None;
        for p in &f.packets {
            if p.sport != sport || p.dport != dport {
                continue;
            }
            if p.flags & F_SYN != 0 {
                expect = Some(p.seq.wrapping_add(1));
                continue;
            }
            if p.payload.is_empty() {
                continue;
            }
            if let Some(e) = expect {
                assert_eq!(p.seq, e, "sequence gap in the reassembled stream");
            }
            expect = Some(p.seq.wrapping_add(p.payload.len() as u32));
            out.extend_from_slice(&p.payload);
        }
        out
    }

    // --- fixtures ----------------------------------------------------------

    async fn store_with_flows(path: &std::path::Path) -> Store {
        let store = Store::open(path).unwrap();
        let w = store.writer();

        // 1. A plain HTTP/1.1 GET.
        let f1 = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 1_700_000_000_000,
                exec_id: Some("e1".into()),
                client_addr: "127.0.0.1:51000".into(),
                dst_ip: "93.184.216.34".into(),
                dst_port: 80,
                sni: None,
                scheme: "http".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            f1,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/search?q=needle".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Host: example.com\r\nAccept: */*\r\n".to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            f1,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                // The stored body is DECODED, so these two headers describe
                // bytes that are not in the store — exactly the case the writer
                // has to rewrite or the stream becomes undissectable.
                headers:
                    b"Content-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\n"
                        .to_vec(),
                body: b"<html>needle</html>".to_vec(),
                timing_ms: Some(12),
            },
        )
        .await
        .unwrap();
        w.flow_end(f1, 1_700_000_000_012).await.unwrap();

        // 2. A second exchange on the SAME client socket: keep-alive, so it
        //    must land on the same synthetic stream.
        let f2 = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 1_700_000_000_100,
                exec_id: None,
                client_addr: "127.0.0.1:51000".into(),
                dst_ip: "93.184.216.34".into(),
                dst_port: 80,
                sni: None,
                scheme: "http".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            f2,
            RequestData {
                method: "POST".into(),
                authority: "example.com".into(),
                path: "/login".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Host: example.com\r\nTransfer-Encoding: chunked\r\n".to_vec(),
                body: b"user=admin".to_vec(),
            },
        )
        .await
        .unwrap();
        w.response(
            f2,
            ResponseData {
                status: 302,
                http_version: "HTTP/1.1".into(),
                headers: b"Location: /home\r\n".to_vec(),
                body: Vec::new(),
                timing_ms: Some(5),
            },
        )
        .await
        .unwrap();
        w.flow_end(f2, 1_700_000_000_105).await.unwrap();

        // 3. Three flows whose bytes the store never had: excluded, counted.
        for (proto, port) in [
            (Protocol::Dns, 53u16),
            (Protocol::RawTcp, 9000),
            (Protocol::TlsPassthru, 443),
        ] {
            let id = w
                .flow_start(FlowStart {
                    workspace_id: schema::DEFAULT_WORKSPACE_ID,
                    ts_start: 1_700_000_000_200,
                    exec_id: None,
                    client_addr: "127.0.0.1:51100".into(),
                    dst_ip: "1.1.1.1".into(),
                    dst_port: port,
                    sni: None,
                    scheme: String::new(),
                    protocol: proto,
                    intercepted: false,
                })
                .await
                .unwrap();
            w.flow_end(id, 1_700_000_000_201).await.unwrap();
        }

        // 4. An HTTP flow still in flight: no request recorded.
        w.flow_start(FlowStart {
            workspace_id: schema::DEFAULT_WORKSPACE_ID,
            ts_start: 1_700_000_000_300,
            exec_id: None,
            client_addr: "127.0.0.1:51200".into(),
            dst_ip: "93.184.216.34".into(),
            dst_port: 80,
            sni: None,
            scheme: "http".into(),
            protocol: Protocol::H1,
            intercepted: false,
        })
        .await
        .unwrap();

        store
    }

    fn all_ids(store: &Store) -> Vec<i64> {
        store
            .reader()
            .list_flows(&burpwn_store::model::FlowFilter {
                limit: Some(1000),
                ..Default::default()
            })
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect()
    }

    // --- tests -------------------------------------------------------------

    #[tokio::test]
    async fn export_is_a_wellformed_pcapng_whose_http_stream_can_be_followed() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_flows(&dir.path().join("s.db")).await;
        let export = build_pcapng(&store.reader(), &all_ids(&store)).unwrap();
        let f = parse_pcapng(&export.bytes);

        assert_eq!(f.linktype, LINKTYPE_RAW);
        // Millisecond resolution: the store has no finer, and the file says so
        // instead of padding three zeroes onto every timestamp.
        assert_eq!(f.tsresol, 3);
        assert!(f
            .section_comment
            .as_deref()
            .unwrap()
            .starts_with("SYNTHETIC CAPTURE"));
        assert!(f.userappl.as_deref().unwrap().starts_with("burpwn "));
        assert!(f.if_description.as_deref().unwrap().contains("Synthetic"));
        assert_eq!(f.packets.first().unwrap().ts_ms, 1_700_000_000_000);

        // Timestamps never go backwards: a capture file is chronological.
        assert!(f.packets.windows(2).all(|w| w[0].ts_ms <= w[1].ts_ms));

        // The fabricated handshake says so, in the packet list itself.
        let syn = f.packets.iter().find(|p| p.flags & F_SYN != 0).unwrap();
        assert!(syn.comment.as_deref().unwrap().contains("Synthetic TCP"));

        // Both exchanges rode ONE stream (same client socket = keep-alive), and
        // it reassembles into contiguous, dissectable HTTP.
        let c2s = String::from_utf8(follow(&f, 51000, 80)).unwrap();
        let s2c = String::from_utf8(follow(&f, 80, 51000)).unwrap();
        assert!(c2s.starts_with("GET /search?q=needle HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(c2s.contains("POST /login HTTP/1.1\r\n"));
        // Transfer-Encoding described bytes we do not have; it is gone, and the
        // body is framed by a Content-Length that is actually true.
        assert!(!c2s.contains("Transfer-Encoding"));
        assert!(c2s.contains("Content-Length: 10\r\n\r\nuser=admin"));
        assert!(s2c.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!s2c.contains("Content-Encoding"));
        assert!(s2c.contains("Content-Length: 19\r\n\r\n<html>needle</html>"));
        assert!(s2c.contains("HTTP/1.1 302 Found\r\nLocation: /home\r\n"));

        // The connection is opened once and closed once, from both sides.
        assert_eq!(
            f.packets.iter().filter(|p| p.flags == F_SYN).count(),
            export.stats.connections
        );
        assert_eq!(
            f.packets.iter().filter(|p| p.flags & F_FIN != 0).count(),
            export.stats.connections * 2
        );

        assert_eq!(export.stats.connections, 1);
        assert_eq!(export.stats.flows_rendered, 2);
        assert_eq!(export.stats.exchanges, 2);
        assert_eq!(export.stats.packets, f.packets.len());
    }

    #[tokio::test]
    async fn flows_whose_bytes_were_never_stored_are_counted_not_faked() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_flows(&dir.path().join("s.db")).await;
        let export = build_pcapng(&store.reader(), &all_ids(&store)).unwrap();
        let s = &export.stats;

        assert_eq!(s.skipped.get("dns"), Some(&1));
        assert_eq!(s.skipped.get("raw_tcp"), Some(&1));
        assert_eq!(s.skipped.get("tls_passthru"), Some(&1));
        assert_eq!(s.skipped.get("no_request"), Some(&1));
        assert_eq!(s.skipped_total, 4);
        let summary = s.skipped_summary().unwrap();
        assert!(summary.contains("1 dns") && summary.contains("1 tls_passthru"));

        // A flow id that no longer exists is a counted skip, not a panic and
        // not silence…
        let export = build_pcapng(&store.reader(), &[999_999]).unwrap();
        assert_eq!(export.stats.skipped.get("not_found"), Some(&1));
        assert_eq!(export.stats.packets, 0);
        // …and an export with nothing in it is still a valid, openable file.
        let f = parse_pcapng(&export.bytes);
        assert!(f.packets.is_empty());
    }

    #[tokio::test]
    async fn nothing_skipped_says_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.db")).unwrap();
        let export = build_pcapng(&store.reader(), &[]).unwrap();
        assert!(export.stats.skipped_summary().is_none());
        assert_eq!(export.stats.packets, 0);
        parse_pcapng(&export.bytes);
    }

    #[tokio::test]
    async fn websocket_frames_ride_the_upgraded_stream() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.db")).unwrap();
        let w = store.writer();
        let id = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 2_000,
                exec_id: None,
                client_addr: "127.0.0.1:52000".into(),
                dst_ip: "10.0.0.9".into(),
                dst_port: 8080,
                sni: None,
                scheme: "http".into(),
                protocol: Protocol::Ws,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            id,
            RequestData {
                method: "GET".into(),
                authority: "ws.local".into(),
                path: "/socket".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Host: ws.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    .to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            id,
            ResponseData {
                status: 101,
                http_version: "HTTP/1.1".into(),
                headers: b"Upgrade: websocket\r\nConnection: Upgrade\r\n".to_vec(),
                body: Vec::new(),
                timing_ms: Some(3),
            },
        )
        .await
        .unwrap();
        w.insert_ws_message(
            id,
            WsDirection::C2s,
            Some(1),
            Some(true),
            b"ping".to_vec(),
            2_010,
        )
        .await
        .unwrap();
        w.insert_ws_message(
            id,
            WsDirection::S2c,
            Some(1),
            Some(true),
            b"pong".to_vec(),
            2_020,
        )
        .await
        .unwrap();
        w.flow_end(id, 2_030).await.unwrap();

        let export = build_pcapng(&store.reader(), &[id]).unwrap();
        assert_eq!(export.stats.ws_frames, 2);
        let f = parse_pcapng(&export.bytes);
        // The 101 is dated by its measured timing, not by `ts_end` (which is
        // when the whole conversation closed), so the frames that followed it
        // keep their own timestamps instead of collapsing onto the close.
        let ts: Vec<u64> = f
            .packets
            .iter()
            .filter(|p| !p.payload.is_empty())
            .map(|p| p.ts_ms)
            .collect();
        assert_eq!(ts, vec![2_000, 2_003, 2_010, 2_020]);
        let c2s = follow(&f, 52000, 8080);
        let s2c = follow(&f, 8080, 52000);

        // A 101 hands the connection to another protocol: no Content-Length is
        // invented on it, or the upgrade would contradict itself.
        let head = String::from_utf8_lossy(&s2c).into_owned();
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(!head.contains("Content-Length"));

        // Client frame: FIN + text, masked as RFC 6455 requires — with a zero
        // key, so the payload stays greppable instead of turning into noise.
        let frame = &c2s[c2s.len() - 10..];
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 0x80 | 4);
        assert_eq!(&frame[2..6], &[0, 0, 0, 0]);
        assert_eq!(&frame[6..], b"ping");
        // Server frame: same, unmasked.
        assert_eq!(&s2c[s2c.len() - 6..], b"\x81\x04pong");
    }

    #[tokio::test]
    async fn http2_is_re_encoded_as_http1_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.db")).unwrap();
        let w = store.writer();
        let id = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 5_000,
                exec_id: None,
                client_addr: "[::1]:53000".into(),
                dst_ip: "2606:2800:220:1:248:1893:25c8:1946".into(),
                dst_port: 443,
                sni: Some("h2.example".into()),
                scheme: "https".into(),
                protocol: Protocol::H2,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            id,
            RequestData {
                method: "GET".into(),
                authority: "h2.example".into(),
                path: "/".into(),
                http_version: "HTTP/2".into(),
                // HTTP/2 pseudo-headers have no HTTP/1 spelling and must not
                // reach the wire.
                headers: b":method: GET\r\n:authority: h2.example\r\naccept: */*\r\n".to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            id,
            ResponseData {
                status: 200,
                http_version: "HTTP/2".into(),
                headers: b"content-type: text/plain\r\n".to_vec(),
                // Larger than one MSS, so the segmentation path is exercised.
                body: vec![b'x'; 3_500],
                timing_ms: Some(9),
            },
        )
        .await
        .unwrap();
        w.flow_end(id, 5_009).await.unwrap();

        let export = build_pcapng(&store.reader(), &[id]).unwrap();
        assert_eq!(export.stats.h2_as_http1, 1);
        let f = parse_pcapng(&export.bytes);
        assert!(f.packets.iter().all(|p| p.src.is_ipv6() && p.dst.is_ipv6()));

        let c2s = String::from_utf8(follow(&f, 53000, 443)).unwrap();
        assert!(c2s.starts_with("GET / HTTP/1.1\r\nHost: h2.example\r\n"));
        assert!(!c2s.contains(":method"));
        assert!(c2s.contains("accept: */*"));
        // The downgrade is stated on the frames themselves, not only in docs.
        let commented = f
            .packets
            .iter()
            .filter(|p| p.comment.as_deref().is_some_and(|c| c.contains("HTTP/2")))
            .count();
        assert_eq!(commented, 2);

        // 3500 bytes of body cannot fit one IPv6 MSS: it was segmented, and no
        // frame exceeds the MSS.
        let s2c = follow(&f, 443, 53000);
        assert!(s2c.ends_with(&vec![b'x'; 3_500]));
        assert!(
            f.packets
                .iter()
                .filter(|p| p.sport == 443 && !p.payload.is_empty())
                .count()
                >= 3
        );
        assert!(f.packets.iter().all(|p| p.payload.len() <= MSS_V6));
    }

    #[tokio::test]
    async fn two_conversations_never_share_a_four_tuple() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.db")).unwrap();
        let w = store.writer();
        // Two websocket flows from the same client socket. Each needs its own
        // stream, so one must be given a synthetic client port — otherwise
        // Wireshark splices them into one broken conversation.
        for ts in [1_000i64, 2_000] {
            let id = w
                .flow_start(FlowStart {
                    workspace_id: schema::DEFAULT_WORKSPACE_ID,
                    ts_start: ts,
                    exec_id: None,
                    client_addr: "127.0.0.1:54000".into(),
                    dst_ip: "10.0.0.5".into(),
                    dst_port: 80,
                    sni: None,
                    scheme: "http".into(),
                    protocol: Protocol::Ws,
                    intercepted: false,
                })
                .await
                .unwrap();
            w.request(
                id,
                RequestData {
                    method: "GET".into(),
                    authority: "a.local".into(),
                    path: "/s".into(),
                    http_version: "HTTP/1.1".into(),
                    headers: b"Host: a.local\r\n".to_vec(),
                    body: Vec::new(),
                },
            )
            .await
            .unwrap();
            w.flow_end(id, ts + 1).await.unwrap();
        }
        let export = build_pcapng(&store.reader(), &all_ids(&store)).unwrap();
        assert_eq!(export.stats.connections, 2);
        assert_eq!(export.stats.synthetic_client_ports, 1);
        assert_eq!(export.stats.requests_without_response, 2);

        let f = parse_pcapng(&export.bytes);
        let mut tuples: Vec<(u16, u16)> = f
            .packets
            .iter()
            .filter(|p| p.flags == F_SYN)
            .map(|p| (p.sport, p.dport))
            .collect();
        tuples.sort_unstable();
        assert_eq!(tuples, vec![(FIRST_SYNTHETIC_PORT, 80), (54000, 80)]);
    }

    #[tokio::test]
    async fn an_endpoint_the_store_never_had_falls_back_to_rfc5737() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.db")).unwrap();
        let w = store.writer();
        let id = w
            .flow_start(FlowStart {
                workspace_id: schema::DEFAULT_WORKSPACE_ID,
                ts_start: 10,
                exec_id: None,
                client_addr: String::new(),
                dst_ip: String::new(),
                dst_port: 0,
                sni: None,
                scheme: "https".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            id,
            RequestData {
                method: "GET".into(),
                authority: "ghost.example".into(),
                path: "/".into(),
                http_version: "HTTP/1.1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.flow_end(id, 11).await.unwrap();

        let export = build_pcapng(&store.reader(), &[id]).unwrap();
        assert_eq!(export.stats.synthetic_addresses, 2);
        let f = parse_pcapng(&export.bytes);
        let syn = f.packets.iter().find(|p| p.flags == F_SYN).unwrap();
        // Documentation ranges, so nobody mistakes a placeholder for a host
        // that was really contacted. The port is defaulted from the scheme.
        assert!(matches!(syn.src, IpAddr::V4(a) if a.octets()[..3] == [198, 51, 100]));
        assert!(matches!(syn.dst, IpAddr::V4(a) if a.octets()[..3] == [192, 0, 2]));
        assert_eq!(syn.dport, 443);
        // A missing Host is reconstructed from the stored authority.
        let c2s = String::from_utf8(follow(&f, syn.sport, 443)).unwrap();
        assert_eq!(c2s, "GET / HTTP/1.1\r\nHost: ghost.example\r\n\r\n");
    }

    #[tokio::test]
    async fn the_same_session_exports_byte_for_byte_the_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_flows(&dir.path().join("s.db")).await;
        let a = build_pcapng(&store.reader(), &all_ids(&store)).unwrap();
        let b = build_pcapng(&store.reader(), &all_ids(&store)).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn internet_checksum_folds_a_known_header() {
        // A UDP/IPv4 header with its checksum field zeroed; 0xb861 is the
        // documented answer for it.
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let mut ck = Checksum::default();
        ck.feed(&hdr);
        assert_eq!(ck.finish(), 0xb861);
        // Fed in odd-sized pieces it must fold identically — the boundary case
        // a naive `chunks(2)` per call gets wrong, and the reason the pseudo
        // header can be streamed in before the segment.
        let mut ck = Checksum::default();
        ck.feed(&hdr[..3]);
        ck.feed(&hdr[3..7]);
        ck.feed(&hdr[7..]);
        assert_eq!(ck.finish(), 0xb861);
    }

    #[test]
    fn extended_websocket_lengths_are_encoded() {
        let msg = |len: usize, direction| WsMessage {
            id: 1,
            flow_id: 1,
            direction,
            opcode: Some(2),
            fin: Some(false),
            payload: vec![7u8; len],
            ts: None,
        };
        let f = ws_frame(&msg(200, WsDirection::S2c));
        assert_eq!(f[0], 0x02, "no FIN, binary opcode");
        assert_eq!(f[1], 126);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]), 200);
        assert_eq!(f.len(), 4 + 200);

        let f = ws_frame(&msg(70_000, WsDirection::C2s));
        assert_eq!(f[1], 0x80 | 127);
        assert_eq!(u64::from_be_bytes(f[2..10].try_into().unwrap()), 70_000);
        assert_eq!(f.len(), 10 + 4 + 70_000);
    }

    /// Ground truth, when the machine has it: libpcap itself must be able to
    /// read what we wrote. Skipped — not failed — where tcpdump is absent, so
    /// the suite stays runnable on a bare build box.
    #[tokio::test]
    async fn tcpdump_reads_the_synthetic_capture() {
        let Ok(probe) = std::process::Command::new("tcpdump")
            .arg("--version")
            .output()
        else {
            return;
        };
        if !probe.status.success() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_flows(&dir.path().join("s.db")).await;
        let export = build_pcapng(&store.reader(), &all_ids(&store)).unwrap();
        let file = dir.path().join("out.pcapng");
        std::fs::write(&file, &export.bytes).unwrap();

        // `-nn`: no name resolution at all, so the assertions below match on
        // the addresses and ports we actually wrote.
        let out = std::process::Command::new("tcpdump")
            .args(["-nn", "-r"])
            .arg(&file)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "tcpdump refused the file: {stderr}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            text.lines().filter(|l| l.contains(" IP ")).count(),
            export.stats.packets,
            "tcpdump saw a different number of frames:\n{text}\n{stderr}"
        );
        assert!(
            text.contains("127.0.0.1.51000 > 93.184.216.34.80"),
            "{text}"
        );
        // libpcap honoured `if_tsresol = 3` rather than reading the value as
        // microseconds — the timestamps come back as the real wall clock.
        assert!(text.contains(".012000 IP"), "{text}");
        // And the payload dissects as HTTP, which is the whole point of the
        // synthetic framing.
        assert!(
            text.contains("HTTP: GET /search?q=needle HTTP/1.1"),
            "{text}"
        );
        assert!(text.contains("HTTP: HTTP/1.1 200 OK"), "{text}");
    }
}
