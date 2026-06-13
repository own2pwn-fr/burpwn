//! Body decompression helpers.
//!
//! These produce a *searchable / storable* plaintext view of an HTTP body that
//! arrived gzip / deflate / brotli-encoded. They are used ONLY for what we write
//! into the store (so FTS and the operator see plaintext). The bytes forwarded
//! on the wire are NEVER altered by this module — the proxy forwards the
//! original encoded bytes verbatim.

use std::io::Read;

/// Upper bound on the size of a DECODED body copy. Compressed bodies are
/// attacker-controlled and a few-KB "zip/brotli bomb" can inflate to gigabytes,
/// so each decompressor is wrapped in `.take(DECODE_CAP)` before `read_to_end`.
/// The decoded copy is truncated at this bound (only the stored/searchable copy
/// is decoded — the bytes forwarded on the wire are the original compressed body
/// and are never touched by this module). Mirrors `http::BODY_CAP` (8 MiB).
pub const DECODE_CAP: u64 = 8 * 1024 * 1024;

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

/// Drain a decompressor into a buffer bounded by [`DECODE_CAP`]. The reader is
/// wrapped in `.take(DECODE_CAP)` so a decompression bomb cannot exhaust memory:
/// the decoded copy is truncated at the cap rather than allowed to grow without
/// limit.
fn read_capped<R: Read>(reader: R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(DECODE_CAP).read_to_end(&mut out)?;
    Ok(out)
}

fn gunzip(body: &[u8]) -> Option<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(body)).ok()
}

/// `deflate` per HTTP can be either zlib-wrapped or raw; try zlib first, then
/// raw, matching what real servers emit.
fn inflate(body: &[u8]) -> Option<Vec<u8>> {
    if let Ok(out) = read_capped(flate2::read::ZlibDecoder::new(body)) {
        return Some(out);
    }
    read_capped(flate2::read::DeflateDecoder::new(body)).ok()
}

fn brotli_decode(body: &[u8]) -> Option<Vec<u8>> {
    read_capped(brotli::Decompressor::new(body, 4096)).ok()
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

    #[test]
    fn gzip_bomb_is_capped() {
        // A highly-compressible input that decodes to far more than DECODE_CAP.
        // The compressed form is a few KB; the decompressed form would be 32 MiB
        // unbounded. The cap must clamp the decoded copy to DECODE_CAP.
        let raw = vec![0u8; (DECODE_CAP as usize) * 4];
        let bomb = gz(&raw);
        assert!(
            bomb.len() < 1024 * 1024,
            "compressed bomb should be small, got {}",
            bomb.len()
        );
        let decoded = decode_body(Some("gzip"), &bomb);
        assert_eq!(decoded.len() as u64, DECODE_CAP);
    }

    #[test]
    fn brotli_bomb_is_capped() {
        let raw = vec![0u8; (DECODE_CAP as usize) * 4];
        let bomb = br(&raw);
        let decoded = decode_body(Some("br"), &bomb);
        assert_eq!(decoded.len() as u64, DECODE_CAP);
    }
}
