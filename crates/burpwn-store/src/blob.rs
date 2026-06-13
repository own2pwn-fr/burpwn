//! Content-addressed blob storage with transparent zstd compression and
//! SHA-256 deduplication.
//!
//! [`BlobStore::put`] hashes the *raw* bytes, compresses if they exceed
//! [`COMPRESS_THRESHOLD`], and inserts with `ON CONFLICT(sha256) DO NOTHING`,
//! returning the id of the existing-or-just-inserted row. [`BlobStore::get`]
//! transparently decompresses.
//!
//! `put` takes a `&Connection` because it is only ever called from the writer
//! task (which owns the single write connection); `get` is a free function so
//! the read pool can call it without an owning struct.

use std::io::Read;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};

/// Raw payloads larger than this (bytes) are zstd-compressed before storage.
pub const COMPRESS_THRESHOLD: usize = 4096;

/// Hard ceiling on the bytes a single compressed blob may decode to. A tampered
/// or maliciously-fed `blobs` row could record a huge `size` and pack a
/// high-ratio frame that expands to GBs; bounding the decoder at this ceiling
/// (regardless of the recorded `size`) caps the blast radius to an error rather
/// than an OOM. Aligned with the proxy's `http::BODY_CAP` (8 MiB), which is the
/// largest body the proxy ever persists, with headroom for the upgrade path.
pub const MAX_DECOMPRESSED: u64 = 64 * 1024 * 1024;

/// zstd compression level. 3 is the zstd default: a good ratio/speed balance and
/// well within budget for off-hot-path writer work.
const ZSTD_LEVEL: i32 = 3;

/// Writer-side blob helper. Borrows the write connection per call.
pub struct BlobStore;

impl BlobStore {
    /// Store `raw` bytes, deduplicating by SHA-256 of the *uncompressed* bytes.
    /// Returns the row id (existing or newly inserted).
    pub fn put(conn: &Connection, raw: &[u8]) -> Result<i64> {
        let mut hasher = Sha256::new();
        hasher.update(raw);
        let digest = hasher.finalize();
        let sha: [u8; 32] = digest.into();

        // Fast path: already present.
        if let Some(id) = lookup_id(conn, &sha)? {
            return Ok(id);
        }

        let (compressed, stored): (i64, Vec<u8>) = if raw.len() > COMPRESS_THRESHOLD {
            (1, zstd::stream::encode_all(raw, ZSTD_LEVEL)?)
        } else {
            (0, raw.to_vec())
        };

        conn.execute(
            "INSERT INTO blobs(sha256, size, compressed, data) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(sha256) DO NOTHING",
            rusqlite::params![&sha[..], raw.len() as i64, compressed, stored],
        )?;

        // Whether we inserted or lost the race, the row now exists; fetch its id.
        match lookup_id(conn, &sha)? {
            Some(id) => Ok(id),
            None => Ok(conn.last_insert_rowid()),
        }
    }

    /// Convenience: store an optional payload, returning `None` for `None`.
    pub fn put_opt(conn: &Connection, raw: Option<&[u8]>) -> Result<Option<i64>> {
        match raw {
            Some(b) => Ok(Some(Self::put(conn, b)?)),
            None => Ok(None),
        }
    }
}

/// Look up an existing blob id by hash.
fn lookup_id(conn: &Connection, sha: &[u8; 32]) -> Result<Option<i64>> {
    let id: Option<i64> = conn
        .query_row(
            "SELECT id FROM blobs WHERE sha256 = ?1",
            rusqlite::params![&sha[..]],
            |r| r.get(0),
        )
        .ok();
    Ok(id)
}

/// Fetch and transparently decompress a blob by id. Works against any
/// connection (read pool or writer).
pub fn get_blob(conn: &Connection, id: i64) -> Result<Option<Vec<u8>>> {
    let row: Option<(i64, i64, Vec<u8>)> = conn
        .query_row(
            "SELECT compressed, size, data FROM blobs WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();

    let Some((compressed, size, data)) = row else {
        return Ok(None);
    };

    if compressed == 1 {
        // Bound the decompressed output. The recorded `size` is the original
        // uncompressed length (a sanity bound for a well-formed row), capped by
        // the hard ceiling so even a tampered `size` cannot ask us to buffer GBs.
        // We read up to `limit + 1` bytes: if the frame yields more than `limit`,
        // it disagrees with `size` (or blows the ceiling) and we refuse it rather
        // than OOMing.
        let recorded = u64::try_from(size).unwrap_or(0);
        let limit = recorded.min(MAX_DECOMPRESSED);
        Ok(Some(decode_bounded(id, &data, limit)?))
    } else {
        Ok(Some(data))
    }
}

/// Decode a zstd frame, refusing to buffer more than `limit` bytes. The decoder
/// is wrapped in `.take(limit + 1)` so a decompression bomb cannot exhaust
/// memory: if the decoded length exceeds `limit` we return [`StoreError::BlobTooLarge`].
fn decode_bounded(id: i64, data: &[u8], limit: u64) -> Result<Vec<u8>> {
    let decoder = zstd::stream::Decoder::new(data)?;
    let mut out = Vec::new();
    // `limit + 1`: reading one extra byte lets us distinguish "exactly `limit`"
    // (fine) from "more than `limit`" (reject) without an unbounded read.
    let read_cap = limit.saturating_add(1);
    decoder.take(read_cap).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        return Err(StoreError::BlobTooLarge { id, limit });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::init(&conn).unwrap();
        conn
    }

    #[test]
    fn dedup_same_bytes_one_row_same_id() {
        let conn = db();
        let id1 = BlobStore::put(&conn, b"hello world").unwrap();
        let id2 = BlobStore::put(&conn, b"hello world").unwrap();
        assert_eq!(id1, id2);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn distinct_bytes_distinct_ids() {
        let conn = db();
        let a = BlobStore::put(&conn, b"alpha").unwrap();
        let b = BlobStore::put(&conn, b"beta").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn small_blob_uncompressed_roundtrip() {
        let conn = db();
        let raw = b"short";
        let id = BlobStore::put(&conn, raw).unwrap();
        let compressed: i64 = conn
            .query_row("SELECT compressed FROM blobs WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(compressed, 0);
        assert_eq!(get_blob(&conn, id).unwrap().unwrap(), raw);
    }

    #[test]
    fn large_blob_compressed_roundtrip() {
        let conn = db();
        // Highly compressible payload well over the threshold.
        let raw = vec![b'A'; COMPRESS_THRESHOLD * 4];
        let id = BlobStore::put(&conn, &raw).unwrap();
        let (compressed, stored_size): (i64, i64) = conn
            .query_row(
                "SELECT compressed, length(data) FROM blobs WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(compressed, 1);
        assert!(
            (stored_size as usize) < raw.len(),
            "compressed data should be smaller"
        );
        assert_eq!(get_blob(&conn, id).unwrap().unwrap(), raw);
    }

    #[test]
    fn get_missing_blob_is_none() {
        let conn = db();
        assert!(get_blob(&conn, 999).unwrap().is_none());
    }

    #[test]
    fn tampered_size_smaller_than_real_is_rejected() {
        // A row whose `data` is a valid zstd frame that decodes to more bytes
        // than its recorded `size` must be refused (BlobTooLarge), not silently
        // returned — a tampered `size` cannot be trusted to bound the output.
        let conn = db();
        let raw = vec![b'A'; COMPRESS_THRESHOLD * 4];
        let id = BlobStore::put(&conn, &raw).unwrap();
        // Lie about the size: claim the blob is tiny.
        conn.execute("UPDATE blobs SET size = 8 WHERE id = ?1", [id])
            .unwrap();
        let err = get_blob(&conn, id).unwrap_err();
        assert!(
            matches!(err, StoreError::BlobTooLarge { id: bad, limit: 8 } if bad == id),
            "expected BlobTooLarge, got {err:?}"
        );
    }

    #[test]
    fn honest_size_decodes_within_limit() {
        // The happy path: a correctly-recorded `size` decodes fully (the bound
        // is `size`, decoded length equals `size`, so it passes).
        let conn = db();
        let raw = vec![b'B'; COMPRESS_THRESHOLD * 4];
        let id = BlobStore::put(&conn, &raw).unwrap();
        assert_eq!(get_blob(&conn, id).unwrap().unwrap(), raw);
    }

    #[test]
    fn ceiling_caps_even_a_huge_recorded_size() {
        // Even if a tampered row records an absurd `size` above MAX_DECOMPRESSED,
        // the hard ceiling clamps the limit; a frame decoding past it is refused.
        let conn = db();
        let raw = vec![b'C'; COMPRESS_THRESHOLD * 4];
        let id = BlobStore::put(&conn, &raw).unwrap();
        // Claim a size far above the ceiling: limit collapses to MAX_DECOMPRESSED.
        conn.execute(
            "UPDATE blobs SET size = ?1 WHERE id = ?2",
            rusqlite::params![(MAX_DECOMPRESSED as i64) * 1000, id],
        )
        .unwrap();
        // This particular blob is small, so it still decodes fine under the
        // ceiling; the point is the limit is the ceiling, not the bogus size.
        assert_eq!(get_blob(&conn, id).unwrap().unwrap(), raw);
    }
}
