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

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::error::Result;

/// Raw payloads larger than this (bytes) are zstd-compressed before storage.
pub const COMPRESS_THRESHOLD: usize = 4096;

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
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT compressed, data FROM blobs WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();

    let Some((compressed, data)) = row else {
        return Ok(None);
    };

    if compressed == 1 {
        Ok(Some(zstd::stream::decode_all(&data[..])?))
    } else {
        Ok(Some(data))
    }
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
}
