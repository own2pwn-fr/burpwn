//! Reusable single-shot request replay over the proxy's own upstream path.
//!
//! The CLI's "send to repeater"/replay feature needs to fire one request at a
//! target and read back the response — over the **same** upstream machinery the
//! proxy uses for live traffic, so HTTPS (real cert validation, ALPN-negotiated
//! `h2`/`http/1.1`) and the HTTP/2 absolute-URI promotion all behave identically.
//!
//! [`replay_once`] builds a [`hyper::Request`] in origin-form (path + `Host`
//! header) and hands it to [`crate::http::send_over`] — exactly the helper the
//! proxy's [`crate::http::forward`] uses. For HTTP/2 upstreams `send_over`
//! promotes the URI to absolute form and moves the authority to `:authority`
//! (the recent h2 fix), so we don't duplicate any of that logic here.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::{Request, Version};

use burpwn_tls::upstream_connector;

/// The response from a single replayed request.
#[derive(Debug, Clone)]
pub struct ReplayResponse {
    /// HTTP status code.
    pub status: u16,
    /// HTTP version of the response (e.g. `HTTP/1.1`, `HTTP/2.0`).
    pub http_version: String,
    /// Response headers, in arrival order.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Send ONE request to `addr` and return the response. `scheme` is "http"|"https";
/// for https it uses burpwn_tls::upstream_connector (real cert validation, ALPN
/// h2/http1.1) with `sni` for the server name; the request is sent h1 or h2 per
/// the negotiated ALPN, with the absolute-URI promotion HTTP/2 needs.
#[allow(clippy::too_many_arguments)] // a replay target is genuinely this many fields
pub async fn replay_once(
    scheme: &str,
    sni: &str,
    addr: SocketAddr,
    method: &str,
    authority: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> anyhow::Result<ReplayResponse> {
    let req = build_request(method, authority, path, headers, body)?;

    let (parts, bytes) = if scheme.eq_ignore_ascii_case("https") {
        use tokio::net::TcpStream;
        let tcp = TcpStream::connect(addr).await?;
        let connector = upstream_connector();
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
            .map_err(|_| anyhow::anyhow!("invalid sni / server name: {sni}"))?;
        let tls = connector.connect(server_name, tcp).await?;
        // Mirror the proxy: the upstream leg's protocol is whatever ALPN chose.
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        crate::http::send_over(tls, req, is_h2, "https").await?
    } else {
        use tokio::net::TcpStream;
        let tcp = TcpStream::connect(addr).await?;
        // Cleartext: no ALPN, default to HTTP/1.1 (same as the proxy's Plain leg).
        crate::http::send_over(tcp, req, false, "http").await?
    };

    let http_version = version_str(parts.version).to_string();
    let mut out_headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in parts.headers.iter() {
        out_headers.push((
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        ));
    }
    Ok(ReplayResponse {
        status: parts.status.as_u16(),
        http_version,
        headers: out_headers,
        body: bytes.to_vec(),
    })
}

/// Build an origin-form request (path + `Host` header) ready for
/// [`crate::http::send_over`]. The `Host` header carries `authority` so the h2
/// path can promote it to an absolute URI + `:authority` exactly like the proxy.
fn build_request(
    method: &str,
    authority: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> anyhow::Result<Request<Full<Bytes>>> {
    let mut map = hyper::HeaderMap::new();
    for (name, value) in headers {
        // Skip headers the upstream sender recomputes / forbids; tolerate bad
        // names/values by skipping rather than failing the whole replay.
        let lname = name.to_ascii_lowercase();
        if matches!(
            lname.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "upgrade"
                | "keep-alive"
                | "proxy-connection"
        ) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            map.append(n, v);
        }
    }
    // Always set Host from the authority (the h1 sender uses it directly; the h2
    // sender promotes it to :authority of an absolute URI and strips Host).
    if let Ok(hv) = HeaderValue::from_str(authority) {
        map.insert(HOST, hv);
    }

    // Origin-form URI (path only); send_over promotes to absolute for h2.
    let uri: http::Uri = path
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid request path: {path}"))?;

    let mut builder = Request::builder()
        .method(method.as_bytes())
        .uri(uri)
        .version(Version::HTTP_11);
    {
        let h = builder
            .headers_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid request method/uri"))?;
        *h = map;
    }
    Ok(builder.body(Full::new(Bytes::from(body)))?)
}

fn version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_sets_host_and_origin_form_path() {
        let req = build_request(
            "GET",
            "example.com",
            "/v1/users?id=5",
            vec![("User-Agent".into(), "burpwn".into())],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(req.method(), "GET");
        // Origin-form path is preserved verbatim.
        assert_eq!(
            req.uri().path_and_query().map(|p| p.as_str()),
            Some("/v1/users?id=5")
        );
        assert_eq!(req.headers().get(HOST).unwrap(), "example.com");
        assert_eq!(req.headers().get("user-agent").unwrap(), "burpwn");
    }

    #[test]
    fn build_request_drops_framing_and_host_headers() {
        // Caller-supplied Host / framing headers must be dropped (Host is
        // recomputed from `authority`; framing is recomputed by the sender).
        let req = build_request(
            "POST",
            "api.test",
            "/x",
            vec![
                ("Host".into(), "wrong.test".into()),
                ("Content-Length".into(), "999".into()),
                ("Connection".into(), "keep-alive".into()),
                ("X-Keep".into(), "yes".into()),
            ],
            b"hello".to_vec(),
        )
        .unwrap();
        assert_eq!(req.headers().get(HOST).unwrap(), "api.test");
        assert!(req.headers().get("content-length").is_none());
        assert!(req.headers().get("connection").is_none());
        assert_eq!(req.headers().get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn build_request_h2_promotion_compatible() {
        // The request is origin-form with a Host header, so the h2 absolute-URI
        // promotion in send_over (exercised in http.rs tests) can derive the
        // authority. We assert the shape here.
        let req = build_request("GET", "example.com", "/path?q=1", Vec::new(), Vec::new()).unwrap();
        assert!(req.uri().authority().is_none(), "starts origin-form");
        assert_eq!(req.headers().get(HOST).unwrap(), "example.com");
    }

    // A real-network replay can't run in CI; gated behind --ignored.
    #[tokio::test]
    #[ignore = "requires live network"]
    async fn live_replay_https_example() {
        use std::net::ToSocketAddrs;
        let addr = ("example.com", 443u16)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let resp = replay_once(
            "https",
            "example.com",
            addr,
            "GET",
            "example.com",
            "/",
            vec![("User-Agent".into(), "burpwn-replay".into())],
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(resp.status >= 200 && resp.status < 600);
    }
}
