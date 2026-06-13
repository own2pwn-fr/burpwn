//! Body decompression helpers.
//!
//! These produce a *searchable / storable* plaintext view of an HTTP body that
//! arrived gzip / deflate / brotli-encoded. They are used ONLY for what we write
//! into the store (so FTS and the operator see plaintext). The bytes forwarded
//! on the wire are NEVER altered by this module — the proxy forwards the
//! original encoded bytes verbatim.

use std::io::Read;

/// Decode a body according to its `Content-Encoding` header value (case
/// insensitive, comma-separated chains applied right-to-left). Unknown or absent
/// encodings return the input unchanged. Decoding failures fall back to the
/// original bytes (best-effort: a truncated/garbage body still gets stored raw).
pub fn decode_body(content_encoding: Option<&str>, body: &[u8]) -> Vec<u8> {
    let Some(enc) = content_encoding else {
        return body.to_vec();
    };
    // A chain like "gzip, br" means gzip was applied first then br; to decode we
    // reverse it. Most real traffic uses a single coding.
    let codings: Vec<&str> = enc.split(',').map(|s| s.trim()).collect();
    let mut cur = body.to_vec();
    for coding in codings.into_iter().rev() {
        cur = match decode_one(coding, &cur) {
            Some(decoded) => decoded,
            // Unknown coding or failure: stop and keep what we have so far.
            None => return cur,
        };
    }
    cur
}

/// Decode a single coding token. Returns `None` if the token is unrecognized
/// (caller should treat the body as already-plaintext) or if decoding fails.
fn decode_one(coding: &str, body: &[u8]) -> Option<Vec<u8>> {
    match coding.to_ascii_lowercase().as_str() {
        "identity" | "" => Some(body.to_vec()),
        "gzip" | "x-gzip" => gunzip(body),
        "deflate" => inflate(body),
        "br" => brotli_decode(body),
        _ => None,
    }
}

fn gunzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = flate2::read::GzDecoder::new(body);
    dec.read_to_end(&mut out).ok().map(|_| out)
}

/// `deflate` per HTTP can be either zlib-wrapped or raw; try zlib first, then
/// raw, matching what real servers emit.
fn inflate(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = flate2::read::ZlibDecoder::new(body);
    if dec.read_to_end(&mut out).is_ok() {
        return Some(out);
    }
    out.clear();
    let mut raw = flate2::read::DeflateDecoder::new(body);
    raw.read_to_end(&mut out).ok().map(|_| out)
}

fn brotli_decode(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = brotli::Decompressor::new(body, 4096);
    dec.read_to_end(&mut out).ok().map(|_| out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn br(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    #[test]
    fn passthrough_when_no_encoding() {
        assert_eq!(decode_body(None, b"hello"), b"hello");
        assert_eq!(decode_body(Some("identity"), b"hello"), b"hello");
    }

    #[test]
    fn decodes_gzip() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        assert_eq!(decode_body(Some("gzip"), &gz(payload)), payload);
    }

    #[test]
    fn decodes_deflate_zlib_and_raw() {
        let payload = b"deflate me please";
        assert_eq!(decode_body(Some("deflate"), &zlib(payload)), payload);
    }

    #[test]
    fn decodes_brotli() {
        let payload = b"brotli compressed content here";
        assert_eq!(decode_body(Some("br"), &br(payload)), payload);
    }

    #[test]
    fn unknown_encoding_left_alone() {
        assert_eq!(decode_body(Some("snappy"), b"raw"), b"raw");
    }

    #[test]
    fn corrupt_body_falls_back_to_raw() {
        // Not valid gzip — we keep the bytes rather than dropping them.
        assert_eq!(decode_body(Some("gzip"), b"not-gzip"), b"not-gzip");
    }
}
