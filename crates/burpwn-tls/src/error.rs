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

impl burpwn_error::Coded for TlsError {
    fn code(&self) -> burpwn_error::ErrorCode {
        use burpwn_error::ErrorCode as C;
        match self {
            // Touching the CA files on disk failed: the actionable framing is
            // "the CA could not be loaded", which points at `burpwn ca init`.
            TlsError::Io { .. } => C::TlsCaLoad,
            TlsError::MalformedCa { .. } => C::TlsCaMalformed,
            // rcgen/rustls failures happen either while generating the CA or
            // while minting a leaf; the SAN case is unambiguously a leaf.
            TlsError::InvalidSan(..) => C::TlsLeafMint,
            TlsError::Rcgen(_) | TlsError::Rustls(_) => C::TlsCaInit,
        }
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, TlsError>;

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_error::{Coded, ErrorClass, ErrorCode};

    #[test]
    fn variants_map_onto_the_documented_codes() {
        let io = TlsError::io("/tmp/ca.pem", std::io::Error::other("x"));
        assert_eq!(io.code(), ErrorCode::TlsCaLoad);
        assert_eq!(
            TlsError::MalformedCa {
                path: "/tmp/ca.pem".into(),
                detail: "not pem".into()
            }
            .code(),
            ErrorCode::TlsCaMalformed
        );
        assert_eq!(
            TlsError::InvalidSan("..".into(), "bad".into()).code(),
            ErrorCode::TlsLeafMint
        );
    }

    #[test]
    fn every_variant_is_in_the_tls_class() {
        for e in [
            TlsError::io("/tmp/ca.pem", std::io::Error::other("x")),
            TlsError::MalformedCa {
                path: "/tmp/ca.pem".into(),
                detail: "x".into(),
            },
            TlsError::InvalidSan("x".into(), "y".into()),
        ] {
            assert_eq!(e.code().class(), ErrorClass::Tls, "{e}");
        }
    }
}
