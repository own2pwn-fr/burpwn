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
}

/// Convenience result alias for the store crate.
pub type Result<T> = std::result::Result<T, StoreError>;
