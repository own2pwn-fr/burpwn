//! Turning an `anyhow` error chain into a coded, actionable [`Diagnostic`].
//!
//! Two halves:
//!
//! * **Annotation** — [`CodedError`] plus the [`WithCode`] extension trait and
//!   the [`fail!`](crate::fail) macro, used at the ~110 error sites across the
//!   CLI, MCP and proxy layers to say which catalogue code a failure is.
//! * **Classification** — [`diagnose`], the terminal handler's view: it walks
//!   the chain looking for an explicit code, then for a typed error from a lower
//!   crate that knows its own code ([`burpwn_error::Coded`]), and only then
//!   falls back to [`ErrorCode::Internal`].
//!
//! The fallback matters as much as the annotation: it guarantees that EVERY
//! failure — including ones nobody annotated, including future ones — still
//! reaches the user with a code, an exit code, and a debug report. Annotating a
//! site upgrades the quality of the message; forgetting to annotate one degrades
//! it, but never back to a bare string.

use burpwn_error::{Coded, Diagnostic, ErrorCode};
use burpwn_sandbox::SandboxError;
use burpwn_store::error::StoreError;
use burpwn_tls::TlsError;
use burpwn_wrap::WrapError;

/// An error that knows its catalogue code.
///
/// Used two ways: as the error itself (via [`fail!`](crate::fail)), or as
/// `anyhow` context wrapped around someone else's error (via [`WithCode`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedError {
    /// The catalogue code.
    pub code: ErrorCode,
    /// The specific message. When absent, the code's title is used, which is
    /// the right thing for `.with_code()` on an error that already explains
    /// itself.
    pub message: Option<String>,
}

impl CodedError {
    /// A coded error with its own message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }

    /// A bare code, displaying as the catalogue title.
    pub fn bare(code: ErrorCode) -> Self {
        Self {
            code,
            message: None,
        }
    }

    /// The text this error displays as.
    pub fn text(&self) -> String {
        self.message
            .clone()
            .unwrap_or_else(|| self.code.title().to_string())
    }
}

impl std::fmt::Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

impl std::error::Error for CodedError {}

/// Attach a catalogue code to any `Result`.
///
/// ```ignore
/// let body = std::fs::read(&path).with_code(ErrorCode::InputFileUnreadable)?;
/// ```
pub trait WithCode<T> {
    /// Tag the error with `code`, keeping its own message as the cause.
    fn with_code(self, code: ErrorCode) -> anyhow::Result<T>;

    /// Tag the error with `code` AND replace the headline message.
    fn with_code_msg(self, code: ErrorCode, message: impl Into<String>) -> anyhow::Result<T>;
}

impl<T, E> WithCode<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_code(self, code: ErrorCode) -> anyhow::Result<T> {
        self.map_err(|e| anyhow::Error::new(e).context(CodedError::bare(code)))
    }

    fn with_code_msg(self, code: ErrorCode, message: impl Into<String>) -> anyhow::Result<T> {
        self.map_err(|e| anyhow::Error::new(e).context(CodedError::new(code, message)))
    }
}

/// The same, for a `Result` that is already `anyhow`'s.
pub trait WithCodeAnyhow<T> {
    /// Tag the error with `code`, keeping its own message as the cause.
    fn with_code(self, code: ErrorCode) -> anyhow::Result<T>;
    /// Tag the error with `code` AND replace the headline message.
    fn with_code_msg(self, code: ErrorCode, message: impl Into<String>) -> anyhow::Result<T>;
}

impl<T> WithCodeAnyhow<T> for anyhow::Result<T> {
    fn with_code(self, code: ErrorCode) -> anyhow::Result<T> {
        self.map_err(|e| e.context(CodedError::bare(code)))
    }

    fn with_code_msg(self, code: ErrorCode, message: impl Into<String>) -> anyhow::Result<T> {
        self.map_err(|e| e.context(CodedError::new(code, message)))
    }
}

/// `bail!` with a catalogue code: `fail!(ErrorCode::InputNoSuchFlow, "no such flow {id}")`.
#[macro_export]
macro_rules! fail {
    ($code:expr, $($arg:tt)*) => {
        return Err(::anyhow::Error::new($crate::diag::CodedError::new(
            $code,
            format!($($arg)*),
        )))
    };
}

/// `anyhow!` with a catalogue code, for use in `.ok_or_else(…)` and friends.
#[macro_export]
macro_rules! coded {
    ($code:expr, $($arg:tt)*) => {
        ::anyhow::Error::new($crate::diag::CodedError::new($code, format!($($arg)*)))
    };
}

/// Classify an error chain into a [`Diagnostic`].
///
/// Precedence, most to least specific:
/// 1. an explicit [`CodedError`] anywhere in the chain (the outermost wins —
///    the layer closest to the user has the most context about what the user
///    was trying to do),
/// 2. a typed error from a lower crate that implements [`Coded`],
/// 3. [`ErrorCode::Internal`] — an unclassified failure, which the catalogue
///    documents as "this is a bug, please report it".
pub fn diagnose(err: &anyhow::Error) -> Diagnostic {
    let code = classify(err).unwrap_or(ErrorCode::Internal);

    // The headline is the outermost link (what the user was doing); the rest of
    // the chain becomes the verbatim causes, so the raw `ip`/`nft`/SQLite text
    // is never paraphrased away.
    let mut links = err.chain().map(|c| c.to_string());
    let message = links.next().unwrap_or_else(|| code.title().to_string());
    let mut diag = Diagnostic::new(code, message);
    for link in links {
        diag = diag.cause(link);
    }
    // A bare `.with_code()` context displays as the catalogue title, which the
    // renderer already shows via the code — drop it from the causes so the
    // message does not say the same thing twice.
    diag.causes.retain(|c| c != code.title());
    diag
}

/// Find the most specific code in the chain, if any.
fn classify(err: &anyhow::Error) -> Option<ErrorCode> {
    // A code attached with `.with_code()` lives in anyhow's CONTEXT slot, not as
    // a chain link: `err.chain()` yields the opaque `ContextError` wrapper, which
    // does not downcast to `CodedError`. `Error::downcast_ref` is the accessor
    // that inspects contexts, and it walks outermost-first — which is exactly
    // the precedence we want.
    if let Some(c) = err.downcast_ref::<CodedError>() {
        return Some(c.code);
    }
    for link in err.chain() {
        if let Some(e) = link.downcast_ref::<SandboxError>() {
            return Some(e.code());
        }
        if let Some(e) = link.downcast_ref::<StoreError>() {
            return Some(e.code());
        }
        if let Some(e) = link.downcast_ref::<burpwn_store::bundle::BundleError>() {
            return Some(e.code());
        }
        if let Some(e) = link.downcast_ref::<TlsError>() {
            return Some(e.code());
        }
        if let Some(e) = link.downcast_ref::<WrapError>() {
            return Some(e.code());
        }
        if let Some(e) = link.downcast_ref::<crate::skill::SkillError>() {
            return Some(e.code());
        }
        if let Some(e) = link.downcast_ref::<crate::mcpreg::McpRegError>() {
            return Some(e.code());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    fn code_of(e: &anyhow::Error) -> ErrorCode {
        diagnose(e).code
    }

    #[test]
    fn an_explicit_code_wins() {
        let e = anyhow::Error::new(CodedError::new(
            ErrorCode::InputNoSuchFlow,
            "no such flow 7",
        ));
        let d = diagnose(&e);
        assert_eq!(d.code, ErrorCode::InputNoSuchFlow);
        assert_eq!(d.message, "no such flow 7");
        assert_eq!(d.exit_code(), 75);
    }

    // The layer closest to the user knows best what the user was attempting, so
    // its code must not be shadowed by a lower layer's.
    #[test]
    fn the_outermost_code_wins_over_an_inner_one() {
        let inner = anyhow::Error::new(CodedError::new(ErrorCode::StoreSqlite, "inner"));
        let outer = inner.context(CodedError::new(ErrorCode::InputNoSuchFlow, "outer"));
        assert_eq!(code_of(&outer), ErrorCode::InputNoSuchFlow);
    }

    #[test]
    fn a_typed_lower_crate_error_is_classified_without_annotation() {
        let e = anyhow::Error::new(SandboxError::Setup {
            stage: "netns_setup".into(),
            detail: "dummy missing".into(),
        });
        assert_eq!(code_of(&e), ErrorCode::SandboxNetnsSetup);

        let e = anyhow::Error::new(StoreError::WriterGone);
        assert_eq!(code_of(&e), ErrorCode::StoreWriterGone);
    }

    #[test]
    fn a_typed_error_is_still_found_under_context() {
        let e = anyhow::Error::new(SandboxError::Timeout(std::time::Duration::from_secs(3)))
            .context("running command in sandbox");
        assert_eq!(code_of(&e), ErrorCode::SandboxTimeout);
    }

    // The safety net: an error nobody annotated must still be coded, exit
    // non-zero with a documented code, and tell the user it is a bug.
    #[test]
    fn an_unclassified_error_falls_back_to_internal() {
        let e = anyhow!("something nobody anticipated");
        let d = diagnose(&e);
        assert_eq!(d.code, ErrorCode::Internal);
        assert_eq!(d.exit_code(), 78);
        assert_eq!(d.message, "something nobody anticipated");
        assert!(!d.remediation.is_empty());
    }

    #[test]
    fn the_chain_becomes_the_causes_outermost_first() {
        let e = anyhow!("root cause")
            .context("middle")
            .context(CodedError::new(
                ErrorCode::StoreOpen,
                "could not open the store",
            ));
        let d = diagnose(&e);
        assert_eq!(d.message, "could not open the store");
        assert_eq!(d.causes, vec!["middle", "root cause"]);
    }

    // `.with_code()` on an error that already explains itself must not make the
    // renderer print the catalogue title twice.
    #[test]
    fn a_bare_code_context_is_not_repeated_as_a_cause() {
        let e: anyhow::Result<()> = Err(anyhow!("permission denied"));
        let e = e.with_code(ErrorCode::InputFileUnreadable).unwrap_err();
        let d = diagnose(&e);
        assert_eq!(d.code, ErrorCode::InputFileUnreadable);
        assert_eq!(d.message, ErrorCode::InputFileUnreadable.title());
        assert_eq!(d.causes, vec!["permission denied"]);
    }

    #[test]
    fn with_code_msg_replaces_the_headline_and_keeps_the_cause() {
        let e: Result<(), std::io::Error> = Err(std::io::Error::other("disk on fire"));
        let e = e
            .with_code_msg(ErrorCode::InputFileUnreadable, "reading --payloads failed")
            .unwrap_err();
        let d = diagnose(&e);
        assert_eq!(d.message, "reading --payloads failed");
        assert_eq!(d.causes, vec!["disk on fire"]);
    }

    #[test]
    fn fail_macro_produces_a_coded_error() {
        fn boom() -> anyhow::Result<()> {
            fail!(ErrorCode::InputNoSuchAttack, "no such attack {}", "abc");
        }
        let d = diagnose(&boom().unwrap_err());
        assert_eq!(d.code, ErrorCode::InputNoSuchAttack);
        assert_eq!(d.message, "no such attack abc");
    }

    #[test]
    fn coded_macro_builds_an_error_for_ok_or_else() {
        let e: anyhow::Result<u8> =
            None.ok_or_else(|| coded!(ErrorCode::AgentUnknown, "unknown agent {}", "x"));
        let d = diagnose(&e.unwrap_err());
        assert_eq!(d.code, ErrorCode::AgentUnknown);
        assert_eq!(d.message, "unknown agent x");
    }

    #[test]
    fn coded_error_displays_as_its_message_or_the_title() {
        assert_eq!(
            CodedError::new(ErrorCode::StoreOpen, "custom").to_string(),
            "custom"
        );
        assert_eq!(
            CodedError::bare(ErrorCode::StoreOpen).to_string(),
            ErrorCode::StoreOpen.title()
        );
    }
}
