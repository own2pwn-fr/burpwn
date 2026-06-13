//! Error type for the TLS-MITM machinery.

use std::path::PathBuf;

/// Errors raised by CA management, leaf minting and config construction.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// An I/O error touching the CA files on disk.
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A certificate / key generation or parsing failure from rcgen.
    #[error("certificate generation/parse error: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// A rustls error building a config or a signing key.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// The stored CA files were present but malformed / unreadable as PEM.
    #[error("malformed CA material in {path}: {detail}")]
    MalformedCa { path: PathBuf, detail: String },

    /// The provided SNI / IP could not be turned into a valid SAN.
    #[error("invalid subject-alternative-name {0:?}: {1}")]
    InvalidSan(String, String),
}

impl TlsError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        TlsError::Io {
            path: path.into(),
            source,
        }
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, TlsError>;
