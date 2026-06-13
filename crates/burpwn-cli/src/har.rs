//! HAR 1.2 export: turn stored flows into an HTTP Archive JSON document that
//! browsers and Burp can import.
//!
//! We build the document with `serde_json` directly (no schema crate) but follow
//! the HAR 1.2 structure faithfully: `log.creator`, and one `log.entries[*]`
//! per HTTP flow with `request`/`response`, decoded headers, query string,
//! `postData`/`content`, sizes and a synthetic `time`. Non-HTTP flows (DNS, raw
//! TCP, TLS passthrough) are skipped — HAR only models HTTP exchanges.

use serde_json::{json, Value};

use burpwn_store::model::{FlowDetail, Protocol, RequestData, ResponseData};
use burpwn_store::Reader;

/// Build a HAR 1.2 document (as a `serde_json::Value`) from the flows matching
/// the given workspace (or all workspaces when `None`). Reads each flow's full
/// detail via the reader.
pub fn build_har(reader: &Reader, flow_ids: &[i64]) -> anyhow::Result<Value> {
    let mut entries = Vec::new();
    for &id in flow_ids {
        let Some(detail) = reader.get_flow(id)? else {
            continue;
        };
        if !is_http(detail.flow.protocol) {
            continue;
        }
        if let Some(entry) = entry_for(&detail) {
            entries.push(entry);
        }
    }
    Ok(json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "burpwn", "version": env!("CARGO_PKG_VERSION") },
            "entries": entries,
        }
    }))
}

fn is_http(p: Protocol) -> bool {
    matches!(p, Protocol::H1 | Protocol::H2 | Protocol::Ws)
}

fn entry_for(detail: &FlowDetail) -> Option<Value> {
    let req = detail.request.as_ref()?;
    let scheme = &detail.flow.scheme;
    let authority = req.authority.as_str();
    let url = build_url(scheme, authority, &req.path);

    let started = iso8601_millis(detail.flow.ts_start);
    let time_ms = detail
        .flow
        .ts_end
        .map(|e| (e - detail.flow.ts_start).max(0))
        .or_else(|| detail.response.as_ref().and_then(|r| r.timing_ms))
        .unwrap_or(0);

    let request = har_request(req, &url);
    let response = detail
        .response
        .as_ref()
        .map(har_response)
        .unwrap_or_else(empty_response);

    Some(json!({
        "startedDateTime": started,
        "time": time_ms,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {
            "send": 0,
            "wait": time_ms,
            "receive": 0,
        },
        "serverIPAddress": detail.flow.dst_ip,
    }))
}

fn har_request(req: &RequestData, url: &str) -> Value {
    let headers = parse_headers(&req.headers);
    let query = parse_query(&req.path);
    let body_str = String::from_utf8_lossy(&req.body).into_owned();
    let post_data = if req.body.is_empty() {
        Value::Null
    } else {
        json!({
            "mimeType": header_value(&headers, "content-type").unwrap_or_default(),
            "text": body_str,
        })
    };
    let mut obj = json!({
        "method": req.method,
        "url": url,
        "httpVersion": req.http_version,
        "headers": headers,
        "queryString": query,
        "cookies": [],
        "headersSize": req.headers.len() as i64,
        "bodySize": req.body.len() as i64,
    });
    if !post_data.is_null() {
        obj["postData"] = post_data;
    }
    obj
}

fn har_response(resp: &ResponseData) -> Value {
    let headers = parse_headers(&resp.headers);
    let mime = header_value(&headers, "content-type").unwrap_or_default();
    json!({
        "status": resp.status,
        "statusText": "",
        "httpVersion": resp.http_version,
        "headers": headers,
        "cookies": [],
        "content": {
            "size": resp.body.len() as i64,
            "mimeType": mime,
            "text": String::from_utf8_lossy(&resp.body),
        },
        "redirectURL": "",
        "headersSize": resp.headers.len() as i64,
        "bodySize": resp.body.len() as i64,
    })
}

fn empty_response() -> Value {
    json!({
        "status": 0,
        "statusText": "",
        "httpVersion": "",
        "headers": [],
        "cookies": [],
        "content": { "size": 0, "mimeType": "", "text": "" },
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": -1,
    })
}

fn build_url(scheme: &str, authority: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let scheme = if scheme.is_empty() { "http" } else { scheme };
    format!("{scheme}://{authority}{path}")
}

/// Parse a raw header block (`Name: value\r\n` lines) into HAR header objects.
fn parse_headers(raw: &[u8]) -> Value {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push(json!({ "name": name.trim(), "value": value.trim() }));
        }
    }
    Value::Array(out)
}

fn header_value(headers: &Value, name: &str) -> Option<String> {
    headers.as_array()?.iter().find_map(|h| {
        let n = h.get("name")?.as_str()?;
        if n.eq_ignore_ascii_case(name) {
            Some(h.get("value")?.as_str()?.to_string())
        } else {
            None
        }
    })
}

fn parse_query(path: &str) -> Value {
    let Some((_, qs)) = path.split_once('?') else {
        return Value::Array(Vec::new());
    };
    let mut out = Vec::new();
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.push(json!({ "name": name, "value": value }));
    }
    Value::Array(out)
}

/// Render unix-millis as a (best-effort) ISO-8601 UTC timestamp. We avoid a
/// date crate: compute the civil date from the epoch-day with the standard
/// days-from-civil algorithm. Good enough for HAR `startedDateTime`.
fn iso8601_millis(ts_millis: i64) -> String {
    let secs = ts_millis.div_euclid(1000);
    let millis = ts_millis.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`: convert a count of days since the unix
/// epoch (1970-01-01) into a `(year, month, day)` proleptic-Gregorian triple.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_epoch_and_known_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2021-01-01 is 18628 days after the epoch.
        assert_eq!(civil_from_days(18628), (2021, 1, 1));
    }

    #[test]
    fn iso8601_formats_epoch() {
        assert_eq!(iso8601_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_millis(1_000), "1970-01-01T00:00:01.000Z");
    }

    #[test]
    fn parse_headers_and_query() {
        let h = parse_headers(b"Host: example.com\r\nAccept: */*\r\n");
        assert_eq!(h.as_array().unwrap().len(), 2);
        assert_eq!(header_value(&h, "host").as_deref(), Some("example.com"));

        let q = parse_query("/search?q=hello&n=3");
        let arr = q.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["name"], "q");
        assert_eq!(arr[0]["value"], "hello");
    }

    #[test]
    fn build_url_joins_or_passes_through() {
        assert_eq!(
            build_url("https", "example.com", "/a?b=1"),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            build_url("https", "x", "http://abs/path"),
            "http://abs/path"
        );
    }
}
