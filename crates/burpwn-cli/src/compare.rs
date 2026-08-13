//! Structured diff of two captured flows for the `compare` command and MCP tool.
//!
//! Produces a machine-readable diff (not a unified-diff blob): a status-line
//! delta, a header add/remove/change breakdown, and a line-based body diff. It
//! also runs a reflection check — tokens drawn from flow A's *request* that
//! appear verbatim in flow B's *response* body — a cheap signal for reflection /
//! IDOR / auth-bypass reasoning (e.g. A's id reflected in B's response).
//!
//! [`diff_flows`] itself is complete and uncapped — it is what the `compare`
//! CLI command shows a human, who asked for the diff and wants all of it.
//! Capping is a separate, explicit step ([`cap_body_lines`]) applied by the MCP
//! tool, whose reader pays per line for the rest of the conversation.

use burpwn_store::model::FlowDetail;
use serde_json::{json, Value};

/// Default ceiling on `body.only_in_a` / `only_in_b` lines per side, for the
/// callers that cap at all (the MCP tool — see [`cap_body_lines`]).
///
/// Two HTML pages that differ share almost no lines, so a diff of them is
/// naturally thousands of lines long. Two hundred is enough to see WHAT changed
/// and to reason about it; past that an agent is paying for a page it will not
/// read, on every turn it keeps the reply in context.
pub const DEFAULT_MAX_BODY_LINES: usize = 200;

/// Which parts of the flows to diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareWhat {
    /// Only status line + headers.
    Headers,
    /// Only the body diff + reflection.
    Body,
    /// Everything (default).
    All,
}

impl CompareWhat {
    /// Parse from the `--what` argument; unknown → error string.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "headers" | "header" => Some(Self::Headers),
            "body" => Some(Self::Body),
            "all" | "" => Some(Self::All),
            _ => None,
        }
    }

    fn wants_headers(self) -> bool {
        matches!(self, Self::Headers | Self::All)
    }
    fn wants_body(self) -> bool {
        matches!(self, Self::Body | Self::All)
    }
}

/// Diff two flows (comparing their *responses*, with the reflection check
/// keying flow A's request against flow B's response) and return structured JSON.
pub fn diff_flows(a: &FlowDetail, b: &FlowDetail, what: CompareWhat) -> Value {
    let mut out = json!({
        "flow_a": a.flow.id,
        "flow_b": b.flow.id,
    });
    let obj = out.as_object_mut().expect("object");

    // Status-line delta (always useful, cheap).
    let sa = a.response.as_ref().map(|r| r.status);
    let sb = b.response.as_ref().map(|r| r.status);
    obj.insert(
        "status".into(),
        json!({ "a": sa, "b": sb, "changed": sa != sb }),
    );

    if what.wants_headers() {
        let ha = a
            .response
            .as_ref()
            .map(|r| r.headers.as_slice())
            .unwrap_or(&[]);
        let hb = b
            .response
            .as_ref()
            .map(|r| r.headers.as_slice())
            .unwrap_or(&[]);
        obj.insert("headers".into(), diff_headers(ha, hb));
    }

    if what.wants_body() {
        let ba = a
            .response
            .as_ref()
            .map(|r| r.body.as_slice())
            .unwrap_or(&[]);
        let bb = b
            .response
            .as_ref()
            .map(|r| r.body.as_slice())
            .unwrap_or(&[]);
        let mut body = diff_body(ba, bb);
        // Reflection: tokens from A's request reflected in B's response body.
        let reflected = a
            .request
            .as_ref()
            .map(|req| reflected_tokens(req, bb))
            .unwrap_or_default();
        body.as_object_mut()
            .expect("object")
            .insert("reflected".into(), json!(reflected));
        obj.insert("body".into(), body);
    }

    out
}

/// Resolve a caller-supplied line cap into the one [`cap_body_lines`] takes.
///
/// Absent or `0` is the default cap: the caller said nothing, so it gets the
/// budget rather than the firehose. A NEGATIVE value is the explicit "give me
/// everything" — deliberately not spelled `0`, so that "I did not think about
/// it" and "I want the whole diff" can never be the same request.
pub fn resolve_max_lines(requested: Option<i64>) -> usize {
    match requested {
        None | Some(0) => DEFAULT_MAX_BODY_LINES,
        Some(n) if n < 0 => 0,
        Some(n) => n as usize,
    }
}

/// Truncate the per-side body line lists of a [`diff_flows`] result to
/// `max_lines` each (`0` = no cap), marking what was cut.
///
/// Truncation is never silent: a side that lost lines is reported under
/// `body.truncated.<side> = { shown, total }`, and the `truncated` object only
/// exists when something was actually cut — a reader that does not see it knows
/// it is holding the whole diff, and one that does knows exactly how much it is
/// missing and can ask again with a bigger `max_lines`.
pub fn cap_body_lines(v: &mut Value, max_lines: usize) {
    if max_lines == 0 {
        return;
    }
    let Some(body) = v.get_mut("body").and_then(Value::as_object_mut) else {
        return;
    };
    let mut marks = serde_json::Map::new();
    for side in ["only_in_a", "only_in_b"] {
        let Some(lines) = body.get_mut(side).and_then(Value::as_array_mut) else {
            continue;
        };
        let total = lines.len();
        if total <= max_lines {
            continue;
        }
        lines.truncate(max_lines);
        marks.insert(side.into(), json!({ "shown": max_lines, "total": total }));
    }
    if !marks.is_empty() {
        body.insert("truncated".into(), Value::Object(marks));
    }
}

/// Parse a raw `Name: value\r\n` header block into ordered pairs.
fn parse_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        if line.is_empty() {
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            out.push((n.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Header add/remove/change between two raw header blocks (case-insensitive
/// names). A name present in both with a different value is a `changed` entry.
fn diff_headers(a: &[u8], b: &[u8]) -> Value {
    let ha = parse_headers(a);
    let hb = parse_headers(b);
    let find = |set: &[(String, String)], name: &str| -> Option<String> {
        set.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (n, v) in &hb {
        match find(&ha, n) {
            None => added.push(json!({ "name": n, "value": v })),
            Some(av) if &av != v => changed.push(json!({ "name": n, "a": av, "b": v })),
            Some(_) => {}
        }
    }
    for (n, v) in &ha {
        if find(&hb, n).is_none() {
            removed.push(json!({ "name": n, "value": v }));
        }
    }
    json!({ "added": added, "removed": removed, "changed": changed })
}

/// Line-based body diff: lines only in A, lines only in B, and whether the
/// bodies are byte-identical.
fn diff_body(a: &[u8], b: &[u8]) -> Value {
    let ta = String::from_utf8_lossy(a);
    let tb = String::from_utf8_lossy(b);
    let la: Vec<&str> = ta.lines().collect();
    let lb: Vec<&str> = tb.lines().collect();
    let sa: std::collections::HashSet<&str> = la.iter().copied().collect();
    let sb: std::collections::HashSet<&str> = lb.iter().copied().collect();
    let only_a: Vec<&str> = la.iter().copied().filter(|l| !sb.contains(l)).collect();
    let only_b: Vec<&str> = lb.iter().copied().filter(|l| !sa.contains(l)).collect();
    json!({
        "identical": a == b,
        "len_a": a.len(),
        "len_b": b.len(),
        "only_in_a": only_a,
        "only_in_b": only_b,
    })
}

/// Extract candidate tokens from a request (path query values + body) and return
/// those (length ≥ 4) that appear verbatim in `response_body`. A cheap
/// reflection detector for XSS / IDOR / auth-bypass reasoning.
fn reflected_tokens(req: &burpwn_store::model::RequestData, response_body: &[u8]) -> Vec<String> {
    let resp = String::from_utf8_lossy(response_body);
    let mut candidates: Vec<String> = Vec::new();

    // Query-string values from the path.
    if let Some(q) = req.path.split_once('?').map(|(_, q)| q) {
        for pair in q.split('&') {
            let val = pair.split_once('=').map(|(_, v)| v).unwrap_or(pair);
            candidates.push(val.to_string());
        }
    }
    // Body tokens (split on non-token bytes).
    let body = String::from_utf8_lossy(&req.body);
    candidates.extend(
        body.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
            .map(|s| s.to_string()),
    );

    let mut hits: Vec<String> = Vec::new();
    for c in candidates {
        let c = c.trim();
        if c.len() >= 4 && resp.contains(c) && !hits.iter().any(|h| h == c) {
            hits.push(c.to_string());
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_store::model::{FlowRow, Protocol, RequestData, ResponseData};

    fn flow(
        id: i64,
        req_path: &str,
        req_body: &[u8],
        status: u16,
        resp_headers: &[u8],
        resp_body: &[u8],
    ) -> FlowDetail {
        FlowDetail {
            flow: FlowRow {
                id,
                workspace_id: 1,
                ts_start: 0,
                ts_end: None,
                protocol: Protocol::H1,
                scheme: "https".into(),
                dst_ip: "1.2.3.4".into(),
                dst_port: 443,
                sni: Some("example.com".into()),
                method: Some("GET".into()),
                authority: Some("example.com".into()),
                path: Some(req_path.into()),
                status: Some(status),
                intercepted: false,
            },
            exec_id: None,
            client_addr: "127.0.0.1:1".into(),
            request: Some(RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: req_path.into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Host: example.com\r\n".to_vec(),
                body: req_body.to_vec(),
            }),
            response: Some(ResponseData {
                status,
                http_version: "HTTP/1.1".into(),
                headers: resp_headers.to_vec(),
                body: resp_body.to_vec(),
                timing_ms: None,
            }),
            tags: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn headers_add_remove_change() {
        let a = flow(
            1,
            "/",
            b"",
            200,
            b"Content-Type: text/html\r\nX-Old: 1\r\nServer: nginx\r\n",
            b"",
        );
        let b = flow(
            2,
            "/",
            b"",
            200,
            b"Content-Type: application/json\r\nX-New: 2\r\nServer: nginx\r\n",
            b"",
        );
        let d = diff_headers(
            a.response.as_ref().unwrap().headers.as_slice(),
            b.response.as_ref().unwrap().headers.as_slice(),
        );
        // X-New added, X-Old removed, Content-Type changed, Server unchanged.
        assert_eq!(d["added"][0]["name"], "X-New");
        assert_eq!(d["removed"][0]["name"], "X-Old");
        assert_eq!(d["changed"][0]["name"], "Content-Type");
        assert_eq!(d["changed"][0]["a"], "text/html");
        assert_eq!(d["changed"][0]["b"], "application/json");
    }

    #[test]
    fn status_delta_flagged() {
        let a = flow(1, "/", b"", 200, b"", b"");
        let b = flow(2, "/", b"", 403, b"", b"");
        let v = diff_flows(&a, &b, CompareWhat::All);
        assert_eq!(v["status"]["a"], 200);
        assert_eq!(v["status"]["b"], 403);
        assert_eq!(v["status"]["changed"], true);
    }

    #[test]
    fn reflection_hit_detected() {
        // A's request carries a token in the query that B's response echoes back.
        let a = flow(1, "/p?name=injecthere", b"", 200, b"", b"");
        let b = flow(2, "/p", b"", 200, b"", b"<div>hello injecthere world</div>");
        let v = diff_flows(&a, &b, CompareWhat::All);
        let reflected = v["body"]["reflected"].as_array().unwrap();
        assert!(
            reflected.iter().any(|t| t == "injecthere"),
            "expected reflected token, got {reflected:?}"
        );
    }

    #[test]
    fn body_line_diff() {
        let a = flow(1, "/", b"", 200, b"", b"same\nonlyA\n");
        let b = flow(2, "/", b"", 200, b"", b"same\nonlyB\n");
        let v = diff_flows(&a, &b, CompareWhat::Body);
        assert_eq!(v["body"]["only_in_a"], json!(["onlyA"]));
        assert_eq!(v["body"]["only_in_b"], json!(["onlyB"]));
        assert_eq!(v["body"]["identical"], false);
        // Headers omitted when what=body.
        assert!(v.get("headers").is_none());
    }

    /// A body diff of two HTML pages is thousands of lines; the capped reply
    /// must say so instead of quietly handing back a prefix.
    #[test]
    fn body_lines_are_capped_with_an_explicit_marker() {
        let big_a: Vec<u8> = (0..500)
            .map(|i| format!("a-line-{i}\n"))
            .collect::<String>()
            .into_bytes();
        let big_b: Vec<u8> = (0..10)
            .map(|i| format!("b-line-{i}\n"))
            .collect::<String>()
            .into_bytes();
        let a = flow(1, "/", b"", 200, b"", &big_a);
        let b = flow(2, "/", b"", 200, b"", &big_b);

        let mut v = diff_flows(&a, &b, CompareWhat::Body);
        cap_body_lines(&mut v, DEFAULT_MAX_BODY_LINES);
        assert_eq!(v["body"]["only_in_a"].as_array().unwrap().len(), 200);
        assert_eq!(v["body"]["truncated"]["only_in_a"]["shown"], 200);
        assert_eq!(v["body"]["truncated"]["only_in_a"]["total"], 500);
        // The side that fits is untouched AND unmarked: the marker means "there
        // is more", so it must never appear where there is not.
        assert_eq!(v["body"]["only_in_b"].as_array().unwrap().len(), 10);
        assert!(v["body"]["truncated"].get("only_in_b").is_none());
        // The lines that survive are the FIRST ones, in order.
        assert_eq!(v["body"]["only_in_a"][0], "a-line-0");

        // Under the cap, nothing is marked at all.
        let small = flow(3, "/", b"", 200, b"", b"one\ntwo\n");
        let mut v = diff_flows(&small, &b, CompareWhat::Body);
        cap_body_lines(&mut v, DEFAULT_MAX_BODY_LINES);
        assert!(
            v["body"].get("truncated").is_none(),
            "no marker when there is nothing to say: {v}"
        );

        // And the cap can be lifted, or raised.
        let mut v = diff_flows(&a, &b, CompareWhat::Body);
        cap_body_lines(&mut v, 0);
        assert_eq!(v["body"]["only_in_a"].as_array().unwrap().len(), 500);
        assert!(v["body"].get("truncated").is_none());
        let mut v = diff_flows(&a, &b, CompareWhat::Body);
        cap_body_lines(&mut v, 300);
        assert_eq!(v["body"]["only_in_a"].as_array().unwrap().len(), 300);
        assert_eq!(v["body"]["truncated"]["only_in_a"]["total"], 500);

        // `what=headers` has no body at all: capping it is a no-op, not a panic.
        let mut v = diff_flows(&a, &b, CompareWhat::Headers);
        cap_body_lines(&mut v, DEFAULT_MAX_BODY_LINES);
        assert!(v.get("body").is_none());
    }

    #[test]
    fn max_lines_resolves_absent_zero_and_negative() {
        assert_eq!(resolve_max_lines(None), DEFAULT_MAX_BODY_LINES);
        assert_eq!(resolve_max_lines(Some(0)), DEFAULT_MAX_BODY_LINES);
        assert_eq!(resolve_max_lines(Some(50)), 50);
        // Negative is the explicit "no cap", which `cap_body_lines` reads as 0.
        assert_eq!(resolve_max_lines(Some(-1)), 0);
    }

    #[test]
    fn what_parses() {
        assert_eq!(
            CompareWhat::from_str_opt("headers"),
            Some(CompareWhat::Headers)
        );
        assert_eq!(CompareWhat::from_str_opt("body"), Some(CompareWhat::Body));
        assert_eq!(CompareWhat::from_str_opt("all"), Some(CompareWhat::All));
        assert_eq!(CompareWhat::from_str_opt("nope"), None);
    }
}
