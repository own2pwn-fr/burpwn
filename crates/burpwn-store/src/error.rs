//! Error type for the store crate.

use thiserror::Error;

/// Errors surfaced by the store layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A `rusqlite` operation failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The r2d2 connection pool could not hand out a read connection.
    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    /// A zstd (de)compression operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization of a row payload failed.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// The writer task has shut down, so a [`crate::WriteOp`] could not be sent.
    #[error("writer task is gone: the store has been shut down")]
    WriterGone,

    /// A write op that expected a reply never received one (writer dropped the
    /// reply channel, typically because the op failed on its side).
    #[error("writer did not reply: {0}")]
    NoReply(String),

    /// The on-disk schema version is newer than this build understands.
    #[error("schema version {found} is newer than supported ({supported})")]
    IncompatibleSchema {
        /// Version stamped in the file.
        found: i64,
        /// Highest version this build can apply.
        supported: i64,
    },

    /// A stored row carries a value this build does not understand — an unknown
    /// hook phase or action kind. Refused loudly instead of being coerced onto a
    /// default: a hook that silently becomes some OTHER hook would mutate live
    /// traffic in a way nobody asked for.
    #[error("unsupported value in a stored {table} row: {detail}")]
    UnsupportedRow {
        /// The table the row came from.
        table: &'static str,
        /// What could not be understood.
        detail: String,
    },

    /// A compressed blob decoded to more bytes than its recorded `size` (or the
    /// hard ceiling) allows — refused rather than risking an OOM from a tampered
    /// or maliciously-fed high-ratio frame.
    #[error("blob {id} decoded to an oversized payload (limit {limit} bytes)")]
    BlobTooLarge {
        /// The offending blob row id.
        id: i64,
        /// The byte limit that was exceeded.
        limit: u64,
    },
}

impl burpwn_error::Coded for StoreError {
    fn code(&self) -> burpwn_error::ErrorCode {
        use burpwn_error::ErrorCode as C;
        match self {
            // An I/O error on the store is almost always "the file could not be
            // opened/created" (permissions, missing dir, full disk) — which is
            // the actionable framing, unlike a bare "io error".
            StoreError::Io(_) => C::StoreOpen,
            StoreError::Sqlite(_) | StoreError::Pool(_) | StoreError::Serde(_) => C::StoreSqlite,
            // Today the only rows with a closed variant set are hooks, and the
            // remediation is hook-specific (find it, delete it) — a generic
            // "a database operation failed" would leave the user nowhere.
            StoreError::UnsupportedRow { .. } => C::StoreHookUnreadable,
            StoreError::WriterGone | StoreError::NoReply(_) => C::StoreWriterGone,
            StoreError::IncompatibleSchema { .. } => C::StoreSchemaTooNew,
            StoreError::BlobTooLarge { .. } => C::StoreBlobTooLarge,
        }
    }
}

/// Convenience result alias for the store crate.
pub type Result<T> = std::result::Result<T, StoreError>;

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_error::{Coded, ErrorCode};

    #[test]
    fn variants_map_onto_the_documented_codes() {
        assert_eq!(StoreError::WriterGone.code(), ErrorCode::StoreWriterGone);
        assert_eq!(
            StoreError::IncompatibleSchema {
                found: 9,
                supported: 3
            }
            .code(),
            ErrorCode::StoreSchemaTooNew
        );
        assert_eq!(
            StoreError::BlobTooLarge { id: 1, limit: 10 }.code(),
            ErrorCode::StoreBlobTooLarge
        );
        assert_eq!(
            StoreError::UnsupportedRow {
                table: "hooks",
                detail: "unknown action".into()
            }
            .code(),
            ErrorCode::StoreHookUnreadable
        );
        assert_eq!(
            StoreError::NoReply("x".into()).code(),
            ErrorCode::StoreWriterGone
        );
    }

    // Every store failure must land in the STORE class, or the exit code lies.
    #[test]
    fn every_variant_is_in_the_store_class() {
        let errors: Vec<StoreError> = vec![
            StoreError::WriterGone,
            StoreError::NoReply("x".into()),
            StoreError::IncompatibleSchema {
                found: 9,
                supported: 3,
            },
            StoreError::BlobTooLarge { id: 1, limit: 10 },
            StoreError::UnsupportedRow {
                table: "hooks",
                detail: "unknown action".into(),
            },
            StoreError::Io(std::io::Error::other("x")),
        ];
        for e in errors {
            assert_eq!(e.code().class(), burpwn_error::ErrorClass::Store, "{e}");
        }
    }
}
