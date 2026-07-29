//! burpwn-error — the error contract every other crate reports through.
//!
//! Three pieces, all pure (no I/O, no deps beyond serde) so they are fully
//! unit-tested and usable from any layer including the sandbox helper:
//!
//! * [`code`] — the CATALOGUE. Every failure mode has a stable `BW-CLASS-NNN`
//!   id, a plain-language title, remediation advice, and a class that maps to a
//!   process exit code.
//! * [`diagnostic`] — [`Diagnostic`], one rendered failure: code, message, the
//!   verbatim cause chain, what to do, and where the debug report went.
//! * [`redact`] — the redaction policy for anything written into a debug
//!   report. burpwn holds credentials for the target by design, so a report
//!   must never carry them.
//!
//! The crate deliberately does NOT know about `anyhow`, the filesystem, or the
//! CLI: the layer that owns those (burpwn-cli) turns an error chain into a
//! [`Diagnostic`] and writes the report.

pub mod code;
pub mod diagnostic;
pub mod redact;

pub use code::{ErrorClass, ErrorCode};
pub use diagnostic::Diagnostic;
pub use redact::{redact_argv, redact_env, redact_text, REDACTED};

/// Anything that can name its own failure mode.
///
/// Implemented by the typed error enums of the lower crates (store, TLS,
/// sandbox, wrap) so the CLI's central handler classifies them exactly instead
/// of pattern-matching on message text.
pub trait Coded {
    /// The catalogue code for this error.
    fn code(&self) -> ErrorCode;
}
