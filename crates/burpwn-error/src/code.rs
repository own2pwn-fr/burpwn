//! The error catalogue: every failure burpwn can report has a stable id here.
//!
//! ## Why a catalogue and not one code per `bail!`
//!
//! Codes are a CONTRACT: they go in error messages, in the `--json` envelope, in
//! MCP tool errors and in debug reports, and users search the web for them. A
//! code per call site would be unmaintainable and would churn on every refactor.
//! So codes name *failure modes*, not code locations — several call sites map
//! onto one code, and the free-text message carries the specifics.
//!
//! ## Anatomy
//!
//! `BW-SANDBOX-003` = the `BW` prefix, the [`ErrorClass`], and a number that is
//! **never reused or renumbered** once released (a removed code stays retired).
//! The class determines the process [exit code](ErrorClass::exit_code), so a
//! script can branch on the family without parsing the string.

use serde::{Deserialize, Serialize};

/// The family a failure belongs to. Determines the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The rootless sandbox could not be created or run.
    Sandbox,
    /// The per-session proxy daemon or its control socket.
    Daemon,
    /// The SQLite capture store.
    Store,
    /// The MITM certificate authority / TLS material.
    Tls,
    /// Session and workspace lifecycle.
    Session,
    /// The user's input: a flag value, an id that does not exist, a bad file.
    Input,
    /// Agent integration: hooks, skills, MCP registration.
    Agent,
    /// Talking to the target / upstream (replay, login macro).
    Network,
    /// A burpwn bug: a failure we did not anticipate and cannot advise on.
    Internal,
}

impl ErrorClass {
    /// The process exit code for this class.
    ///
    /// The 70–78 range is deliberate: it sits above the conventional `0`/`1`
    /// and below the shell's reserved 126/127/128+n, so it never collides with
    /// "command not found" or "killed by signal".
    ///
    /// ⚠️ `burpwn exec` PASSES THROUGH the wrapped command's exit code, so a
    /// value in this range coming out of `exec` is ambiguous on its own — the
    /// command may simply have exited 70. Use the `exit_source` field of the
    /// `--json` envelope (or the debug report) to disambiguate: it says whether
    /// the code came from burpwn or from the wrapped command.
    pub const fn exit_code(self) -> i32 {
        match self {
            ErrorClass::Sandbox => 70,
            ErrorClass::Daemon => 71,
            ErrorClass::Store => 72,
            ErrorClass::Tls => 73,
            ErrorClass::Session => 74,
            ErrorClass::Input => 75,
            ErrorClass::Agent => 76,
            ErrorClass::Network => 77,
            ErrorClass::Internal => 78,
        }
    }

    /// The token used in code ids (`BW-<CLASS>-NNN`).
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Sandbox => "SANDBOX",
            ErrorClass::Daemon => "DAEMON",
            ErrorClass::Store => "STORE",
            ErrorClass::Tls => "TLS",
            ErrorClass::Session => "SESSION",
            ErrorClass::Input => "INPUT",
            ErrorClass::Agent => "AGENT",
            ErrorClass::Network => "NETWORK",
            ErrorClass::Internal => "INTERNAL",
        }
    }

    /// Every class, for exhaustive tests and documentation generation.
    pub const ALL: &'static [ErrorClass] = &[
        ErrorClass::Sandbox,
        ErrorClass::Daemon,
        ErrorClass::Store,
        ErrorClass::Tls,
        ErrorClass::Session,
        ErrorClass::Input,
        ErrorClass::Agent,
        ErrorClass::Network,
        ErrorClass::Internal,
    ];
}

/// A stable, documented failure mode.
///
/// Adding a variant is additive; RENUMBERING or REUSING an id is a breaking
/// change to the contract (a test enforces uniqueness, and the docs table is
/// generated from this enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // --- sandbox (exit 70) -------------------------------------------------
    /// A prerequisite for the rootless sandbox is not installed.
    SandboxPrerequisites,
    /// The kernel refused to create the unprivileged user/network namespace.
    SandboxNamespaceRefused,
    /// The namespace came up but its network could not be configured.
    SandboxNetnsSetup,
    /// The in-namespace acceptor could not bind its port.
    SandboxAcceptorBind,
    /// The sandbox could not fork the wrapped command.
    SandboxCommandFork,
    /// The wrapped command exceeded its wall-clock timeout and was killed.
    SandboxTimeout,
    /// Any other failure from the sandbox runtime.
    SandboxRuntime,

    // --- daemon (exit 71) --------------------------------------------------
    /// The session's proxy daemon did not become ready in time.
    DaemonNotReady,
    /// The daemon's control socket could not be reached.
    DaemonUnreachable,
    /// The control connection broke or spoke an unexpected dialect.
    DaemonProtocol,
    /// The daemon answered, but with an error.
    DaemonRejected,
    /// The session runtime directory is unusable.
    DaemonRuntimeDir,

    // --- store (exit 72) ---------------------------------------------------
    /// The capture database could not be opened or created.
    StoreOpen,
    /// A SQLite operation failed.
    StoreSqlite,
    /// The database was written by a newer burpwn than this one.
    StoreSchemaTooNew,
    /// A stored body decoded to more bytes than allowed (refused, not OOM'd).
    StoreBlobTooLarge,
    /// The store's writer task is gone, so nothing more can be persisted.
    StoreWriterGone,

    // --- tls / CA (exit 73) ------------------------------------------------
    /// The MITM CA could not be generated.
    TlsCaInit,
    /// The MITM CA could not be loaded.
    TlsCaLoad,
    /// The CA files exist but are malformed or half-present.
    TlsCaMalformed,
    /// A certificate could not be minted for a target.
    TlsLeafMint,

    // --- session / workspace (exit 74) -------------------------------------
    /// The session name is not a safe single path segment.
    SessionInvalidName,
    /// No session by that name exists.
    SessionNotFound,
    /// No workspace by that name exists.
    WorkspaceNotFound,
    /// burpwn cannot determine where to put its data or config.
    SessionNoDataDir,
    /// No flow group by that name exists.
    GroupNotFound,
    /// The file is not a burpwn session bundle (wrong magic, truncated, or a
    /// container format this build does not know).
    SessionBundleInvalid,
    /// A session by that name already exists, and burpwn will not overwrite it.
    SessionExists,

    // --- input (exit 75) ---------------------------------------------------
    /// A flag was given a value outside its allowed set.
    InputInvalidValue,
    /// The referenced flow id does not exist.
    InputNoSuchFlow,
    /// The referenced fuzz attack id does not exist.
    InputNoSuchAttack,
    /// A `Name: value` header specification is malformed.
    InputMalformedHeader,
    /// The payload to encode/decode is malformed for the chosen scheme.
    InputMalformedPayload,
    /// A required choice was not made (e.g. neither `--agent` nor `--all`).
    InputMissingSelection,
    /// An input file could not be read.
    InputFileUnreadable,
    /// Writing there would follow a symlink or escape the intended path.
    InputUnsafePath,
    /// The command has nothing to act on (no payloads, no positions, no body).
    InputNothingToDo,
    /// A user-supplied regex is invalid or lacks its capture group.
    InputBadRegex,
    /// The referenced parked intercept does not exist (already forwarded,
    /// dropped, or never parked).
    InputNoSuchIntercept,
    /// The output file already exists and `--force` was not given.
    InputFileExists,

    // --- agent integration (exit 76) ---------------------------------------
    /// The named agent / framework / MCP host is not one burpwn knows.
    AgentUnknown,
    /// An agent config file exists but is not the shape burpwn can edit.
    AgentConfigShape,
    /// A target file exists and is not owned by burpwn; refusing to overwrite.
    AgentRefusedOverwrite,

    // --- network (exit 77) -------------------------------------------------
    /// Replaying a flow against the target failed.
    NetworkReplayFailed,
    /// The session-auth login macro failed or its regex did not match.
    NetworkAuthRefreshFailed,

    // --- internal (exit 78) ------------------------------------------------
    /// A failure burpwn did not classify — always a bug worth reporting.
    Internal,
}

impl ErrorCode {
    /// The class this code belongs to.
    pub const fn class(self) -> ErrorClass {
        use ErrorCode::*;
        match self {
            SandboxPrerequisites
            | SandboxNamespaceRefused
            | SandboxNetnsSetup
            | SandboxAcceptorBind
            | SandboxCommandFork
            | SandboxTimeout
            | SandboxRuntime => ErrorClass::Sandbox,
            DaemonNotReady | DaemonUnreachable | DaemonProtocol | DaemonRejected
            | DaemonRuntimeDir => ErrorClass::Daemon,
            StoreOpen | StoreSqlite | StoreSchemaTooNew | StoreBlobTooLarge | StoreWriterGone => {
                ErrorClass::Store
            }
            TlsCaInit | TlsCaLoad | TlsCaMalformed | TlsLeafMint => ErrorClass::Tls,
            SessionInvalidName | SessionNotFound | WorkspaceNotFound | SessionNoDataDir
            | GroupNotFound | SessionBundleInvalid | SessionExists => ErrorClass::Session,
            InputInvalidValue
            | InputNoSuchFlow
            | InputNoSuchAttack
            | InputMalformedHeader
            | InputMalformedPayload
            | InputMissingSelection
            | InputFileUnreadable
            | InputUnsafePath
            | InputNothingToDo
            | InputBadRegex
            | InputNoSuchIntercept
            | InputFileExists => ErrorClass::Input,
            AgentUnknown | AgentConfigShape | AgentRefusedOverwrite => ErrorClass::Agent,
            NetworkReplayFailed | NetworkAuthRefreshFailed => ErrorClass::Network,
            Internal => ErrorClass::Internal,
        }
    }

    /// The number within the class. Stable forever once released.
    pub const fn number(self) -> u16 {
        use ErrorCode::*;
        match self {
            SandboxPrerequisites => 1,
            SandboxNamespaceRefused => 2,
            SandboxNetnsSetup => 3,
            SandboxAcceptorBind => 4,
            SandboxCommandFork => 5,
            SandboxTimeout => 6,
            SandboxRuntime => 7,

            DaemonNotReady => 1,
            DaemonUnreachable => 2,
            DaemonProtocol => 3,
            DaemonRejected => 4,
            DaemonRuntimeDir => 5,

            StoreOpen => 1,
            StoreSqlite => 2,
            StoreSchemaTooNew => 3,
            StoreBlobTooLarge => 4,
            StoreWriterGone => 5,

            TlsCaInit => 1,
            TlsCaLoad => 2,
            TlsCaMalformed => 3,
            TlsLeafMint => 4,

            SessionInvalidName => 1,
            SessionNotFound => 2,
            WorkspaceNotFound => 3,
            SessionNoDataDir => 4,
            GroupNotFound => 5,
            SessionBundleInvalid => 6,
            SessionExists => 7,

            InputInvalidValue => 1,
            InputNoSuchFlow => 2,
            InputNoSuchAttack => 3,
            InputMalformedHeader => 4,
            InputMalformedPayload => 5,
            InputMissingSelection => 6,
            InputFileUnreadable => 7,
            InputUnsafePath => 8,
            InputNothingToDo => 9,
            InputBadRegex => 10,
            InputNoSuchIntercept => 11,
            InputFileExists => 12,

            AgentUnknown => 1,
            AgentConfigShape => 2,
            AgentRefusedOverwrite => 3,

            NetworkReplayFailed => 1,
            NetworkAuthRefreshFailed => 2,

            Internal => 1,
        }
    }

    /// The stable public id, e.g. `BW-SANDBOX-003`.
    pub fn id(self) -> String {
        format!("BW-{}-{:03}", self.class().as_str(), self.number())
    }

    /// The process exit code (from the class).
    pub const fn exit_code(self) -> i32 {
        self.class().exit_code()
    }

    /// A short noun phrase naming the failure — the headline of the message.
    pub const fn title(self) -> &'static str {
        use ErrorCode::*;
        match self {
            SandboxPrerequisites => "a sandbox prerequisite is not installed",
            SandboxNamespaceRefused => "the kernel refused to create the sandbox namespaces",
            SandboxNetnsSetup => "the sandbox network could not be configured",
            SandboxAcceptorBind => "the in-sandbox capture listener could not bind",
            SandboxCommandFork => "the sandbox could not start the command",
            SandboxTimeout => "the command hit its timeout and was killed",
            SandboxRuntime => "the sandbox failed to run the command",

            DaemonNotReady => "the session proxy did not start in time",
            DaemonUnreachable => "the session proxy is not reachable",
            DaemonProtocol => "the connection to the session proxy broke",
            DaemonRejected => "the session proxy refused the request",
            DaemonRuntimeDir => "the session runtime directory is unusable",

            StoreOpen => "the capture database could not be opened",
            StoreSqlite => "a database operation failed",
            StoreSchemaTooNew => "the capture database is from a newer burpwn",
            StoreBlobTooLarge => "a stored body is larger than the safety limit",
            StoreWriterGone => "the capture writer has shut down",

            TlsCaInit => "the MITM certificate authority could not be generated",
            TlsCaLoad => "the MITM certificate authority could not be loaded",
            TlsCaMalformed => "the stored CA material is malformed",
            TlsLeafMint => "a certificate could not be minted for the target",

            SessionInvalidName => "the session name is not allowed",
            SessionNotFound => "no such session",
            WorkspaceNotFound => "no such workspace",
            SessionNoDataDir => "burpwn cannot determine where to store its data",
            GroupNotFound => "no such flow group",
            SessionBundleInvalid => "this file is not a burpwn session bundle",
            SessionExists => "a session by that name already exists",

            InputInvalidValue => "a flag was given an unsupported value",
            InputNoSuchFlow => "no such flow",
            InputNoSuchAttack => "no such fuzz attack",
            InputMalformedHeader => "a header specification is malformed",
            InputMalformedPayload => "the input is malformed for that scheme",
            InputMissingSelection => "the command needs to know what to act on",
            InputFileUnreadable => "an input file could not be read",
            InputUnsafePath => "refusing to write through an unsafe path",
            InputNothingToDo => "there is nothing to act on",
            InputBadRegex => "the regex is invalid for this use",
            InputNoSuchIntercept => "no such parked intercept",
            InputFileExists => "the output file already exists",

            AgentUnknown => "unknown agent / framework / MCP host",
            AgentConfigShape => "the agent config file is not a shape burpwn can edit",
            AgentRefusedOverwrite => "refusing to overwrite a file burpwn does not own",

            NetworkReplayFailed => "the replay request failed",
            NetworkAuthRefreshFailed => "the session-auth login macro failed",

            Internal => "unexpected internal error",
        }
    }

    /// What the user can actually DO about it. One line per suggestion; empty
    /// only for codes whose message is already fully actionable on its own.
    ///
    /// These are static. Failures that can say something sharper at runtime
    /// (the sandbox, which can re-probe the host) append dynamic lines on top.
    pub fn remediation(self) -> Vec<&'static str> {
        use ErrorCode::*;
        match self {
            SandboxPrerequisites => vec![
                "install them — Fedora/RHEL: `sudo dnf install bubblewrap nftables iproute`; \
                 Debian/Ubuntu: `sudo apt install bubblewrap nftables iproute2`",
                "then re-run `burpwn doctor`",
            ],
            SandboxNamespaceRefused => vec![
                "check `sysctl kernel.unprivileged_userns_clone` (Debian) and, on Ubuntu 24.04+, \
                 `sysctl kernel.apparmor_restrict_unprivileged_userns`",
                "containers often disable user namespaces — run burpwn on the host instead",
            ],
            SandboxNetnsSetup => vec![
                "run `burpwn doctor`: it recreates the sandbox live and names the failing step",
                "the usual cause is a kernel without the `dummy` / `nft_redir` modules (WSL \
                 ships none at all)",
            ],
            SandboxAcceptorBind => vec![
                "another process may hold the port inside the namespace — retry, and report it \
                 if it persists",
            ],
            SandboxCommandFork => vec![
                "check the process/memory limits (`BURPWN_RLIMIT_NPROC`, `BURPWN_RLIMIT_AS`)",
            ],
            SandboxTimeout => vec![
                "raise it with `--timeout <seconds>`, or narrow the command's scope",
            ],
            SandboxRuntime => vec!["run `burpwn doctor` for a live diagnosis of the sandbox"],

            DaemonNotReady => vec![
                "look at the daemon log in the session runtime directory (path in the debug report)",
                "a stale socket from a killed daemon clears with `burpwn session stop` or by \
                 removing the runtime directory",
            ],
            DaemonUnreachable => vec![
                "the daemon starts on demand — re-run the command; if it keeps failing, check \
                 that the runtime directory is writable",
            ],
            DaemonProtocol => vec![
                "this usually means a burpwn version mismatch between the CLI and a daemon that \
                 is still running: stop the daemon and retry",
            ],
            DaemonRejected => vec!["the daemon's own message above says what it refused and why"],
            DaemonRuntimeDir => vec![
                "check `$XDG_RUNTIME_DIR` — burpwn needs a writable, private runtime directory",
            ],

            StoreOpen => vec![
                "check the permissions and free space on the session directory (path in the \
                 debug report)",
            ],
            StoreSqlite => vec![
                "if the database is corrupt, the session can be recreated: `burpwn session new \
                 --name <other>` (captures in the old session stay on disk)",
            ],
            StoreSchemaTooNew => vec![
                "upgrade burpwn, or open that session with the version that wrote it",
            ],
            StoreBlobTooLarge => vec![
                "this is a safety limit against decompression bombs; the flow's metadata is \
                 intact, only that body is refused",
            ],
            StoreWriterGone => vec!["the session daemon shut down mid-write — re-run the command"],

            TlsCaInit => vec![
                "check that the CA directory is writable, then `burpwn ca init`",
            ],
            TlsCaLoad => vec!["regenerate it with `burpwn ca init`"],
            TlsCaMalformed => vec![
                "burpwn refuses to guess with half a CA: remove the CA directory and re-run \
                 `burpwn ca init` (targets must then re-trust the new CA)",
            ],
            TlsLeafMint => vec![
                "an unusual SNI can be unrepresentable as a certificate name; the flow still \
                 gets metadata-only capture",
            ],

            SessionInvalidName => vec![
                "use a single path segment: letters, digits, `-`, `_` and `.` (no `/`, no `..`)",
            ],
            SessionNotFound => vec!["list them with `burpwn session list`"],
            WorkspaceNotFound => vec!["list them with `burpwn workspace list`"],
            SessionNoDataDir => vec![
                "set `$XDG_DATA_HOME` or `$HOME` to a writable directory",
            ],
            GroupNotFound => vec![
                "list them with `burpwn group list`, or create it with `burpwn group new <name>`",
            ],
            SessionBundleInvalid => vec![
                "a bundle is what `burpwn export session` writes: a `BURPWNBUNDLE` header \
                 followed by a zstd-compressed session database",
                "if the file came over the network or a chat client, check it was not truncated \
                 or re-encoded in transit",
            ],
            SessionExists => vec![
                "import it under another name with `--as <name>`; burpwn never merges into or \
                 overwrites an existing session",
            ],

            InputInvalidValue => vec!["the accepted values are listed in the message above"],
            InputNoSuchFlow => vec!["list captured flows with `burpwn req list`"],
            InputNoSuchAttack => vec!["list attacks with `burpwn fuzz list`"],
            InputMalformedHeader => vec!["the form is `Name: value`, with no CR, LF or NUL"],
            InputMalformedPayload => vec![
                "check the scheme matches the data (`burpwn decode --help` lists them)",
            ],
            InputMissingSelection => vec!["the message above lists the flags that select a target"],
            InputFileUnreadable => vec!["check the path, permissions, and that the file exists"],
            InputUnsafePath => vec![
                "burpwn will not write through an existing symlink; pass a plain file path",
            ],
            InputNothingToDo => vec![],
            InputBadRegex => vec![
                "`--extract` needs exactly one capture group: the token to extract",
            ],
            InputNoSuchIntercept => vec![
                "list what is currently parked with `burpwn intercept list` — an intercept \
                 disappears once it has been forwarded or dropped",
            ],
            InputFileExists => vec![
                "pass `--force` to overwrite it deliberately, or choose another `-o <file>`",
            ],

            AgentUnknown => vec!["the supported names are listed in the message above"],
            AgentConfigShape => vec![
                "burpwn only edits a JSON object config; fix or move the file, then retry",
            ],
            AgentRefusedOverwrite => vec![
                "pass `--force` to overwrite it deliberately, or move the existing file aside",
            ],

            NetworkReplayFailed => vec![
                "the target may be down, or the flow's host may no longer resolve — check with \
                 `burpwn req show <id>`",
            ],
            NetworkAuthRefreshFailed => vec![
                "check the login command and the extraction regex with `burpwn session auth show`",
            ],

            Internal => vec![
                "this is a burpwn bug: please report it with the debug report referenced below",
            ],
        }
    }

    /// Every code, for exhaustive tests and doc generation.
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::SandboxPrerequisites,
        ErrorCode::SandboxNamespaceRefused,
        ErrorCode::SandboxNetnsSetup,
        ErrorCode::SandboxAcceptorBind,
        ErrorCode::SandboxCommandFork,
        ErrorCode::SandboxTimeout,
        ErrorCode::SandboxRuntime,
        ErrorCode::DaemonNotReady,
        ErrorCode::DaemonUnreachable,
        ErrorCode::DaemonProtocol,
        ErrorCode::DaemonRejected,
        ErrorCode::DaemonRuntimeDir,
        ErrorCode::StoreOpen,
        ErrorCode::StoreSqlite,
        ErrorCode::StoreSchemaTooNew,
        ErrorCode::StoreBlobTooLarge,
        ErrorCode::StoreWriterGone,
        ErrorCode::TlsCaInit,
        ErrorCode::TlsCaLoad,
        ErrorCode::TlsCaMalformed,
        ErrorCode::TlsLeafMint,
        ErrorCode::SessionInvalidName,
        ErrorCode::SessionNotFound,
        ErrorCode::WorkspaceNotFound,
        ErrorCode::SessionNoDataDir,
        ErrorCode::GroupNotFound,
        ErrorCode::SessionBundleInvalid,
        ErrorCode::SessionExists,
        ErrorCode::InputInvalidValue,
        ErrorCode::InputNoSuchFlow,
        ErrorCode::InputNoSuchAttack,
        ErrorCode::InputMalformedHeader,
        ErrorCode::InputMalformedPayload,
        ErrorCode::InputMissingSelection,
        ErrorCode::InputFileUnreadable,
        ErrorCode::InputUnsafePath,
        ErrorCode::InputNothingToDo,
        ErrorCode::InputBadRegex,
        ErrorCode::InputNoSuchIntercept,
        ErrorCode::InputFileExists,
        ErrorCode::AgentUnknown,
        ErrorCode::AgentConfigShape,
        ErrorCode::AgentRefusedOverwrite,
        ErrorCode::NetworkReplayFailed,
        ErrorCode::NetworkAuthRefreshFailed,
        ErrorCode::Internal,
    ];

    /// Parse a public id (`BW-INPUT-002`) back into a code. Used by tooling and
    /// by the debug-report reader; unknown ids return `None` rather than
    /// guessing.
    pub fn from_id(id: &str) -> Option<ErrorCode> {
        ErrorCode::ALL.iter().copied().find(|c| c.id() == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // The whole point of a code is that it is unique and stable. If this fails,
    // two failure modes are reporting the same id to users.
    #[test]
    fn every_code_has_a_unique_id() {
        let ids: HashSet<String> = ErrorCode::ALL.iter().map(|c| c.id()).collect();
        assert_eq!(ids.len(), ErrorCode::ALL.len());
    }

    #[test]
    fn all_lists_every_variant() {
        // Serde gives us the variant count for free: every variant must round
        // trip through ALL, so a newly added code that is not registered here
        // is caught immediately.
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(code).unwrap();
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*code, back);
        }
        assert_eq!(ErrorCode::ALL.len(), 46, "register new codes in ALL");
    }

    #[test]
    fn ids_are_well_formed_and_round_trip() {
        for code in ErrorCode::ALL {
            let id = code.id();
            assert!(id.starts_with("BW-"), "{id}");
            assert!(id.contains(code.class().as_str()), "{id}");
            assert_eq!(ErrorCode::from_id(&id), Some(*code));
        }
        assert_eq!(ErrorCode::SandboxNetnsSetup.id(), "BW-SANDBOX-003");
        assert_eq!(ErrorCode::InputNoSuchFlow.id(), "BW-INPUT-002");
        assert_eq!(ErrorCode::from_id("BW-NOPE-999"), None);
    }

    // Numbers are per-class, so the same number in two classes is fine, but a
    // duplicate WITHIN a class would silently collide.
    #[test]
    fn numbers_are_unique_within_a_class() {
        for class in ErrorClass::ALL {
            let numbers: Vec<u16> = ErrorCode::ALL
                .iter()
                .filter(|c| c.class() == *class)
                .map(|c| c.number())
                .collect();
            let unique: HashSet<u16> = numbers.iter().copied().collect();
            assert_eq!(unique.len(), numbers.len(), "{class:?} has duplicates");
        }
    }

    #[test]
    fn every_code_has_a_usable_title() {
        for code in ErrorCode::ALL {
            let t = code.title();
            assert!(!t.is_empty(), "{code:?}");
            assert!(!t.ends_with('.'), "titles are phrases, not sentences: {t}");
        }
    }

    // A code without remediation is a code that leaves the user stuck. Only
    // InputNothingToDo is exempt (its message IS the remediation).
    #[test]
    fn every_code_tells_the_user_what_to_do() {
        for code in ErrorCode::ALL {
            if *code == ErrorCode::InputNothingToDo {
                continue;
            }
            assert!(
                !code.remediation().is_empty(),
                "{} has no remediation",
                code.id()
            );
        }
    }

    #[test]
    fn exit_codes_are_distinct_and_shell_safe() {
        let codes: HashSet<i32> = ErrorClass::ALL.iter().map(|c| c.exit_code()).collect();
        assert_eq!(codes.len(), ErrorClass::ALL.len());
        for class in ErrorClass::ALL {
            let c = class.exit_code();
            // Above 0/1, below the shell's reserved 126/127/128+n.
            assert!((2..126).contains(&c), "{class:?} -> {c}");
        }
    }

    // A code nobody can ever emit is worse than no code: it is documentation
    // for a failure that does not exist, and it hides the fact that the real
    // failure is being reported some other (uncoded) way. This caught
    // `AgentRefusedOverwrite`, which was documented while the refusal it names
    // was being reported as a SUCCESS.
    #[test]
    fn every_code_is_actually_emitted_somewhere() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let Ok(crates) = std::fs::read_dir(root.join("crates")) else {
            return; // not a workspace checkout
        };
        let mut sources = String::new();
        let mut stack: Vec<std::path::PathBuf> =
            crates.flatten().map(|e| e.path().join("src")).collect();
        while let Some(dir) = stack.pop() {
            // The catalogue's own file defines every variant; it proves nothing
            // about whether anyone emits them.
            if dir.ends_with("burpwn-error/src") {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    sources.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
                }
            }
        }
        if sources.is_empty() {
            return;
        }
        let unemitted: Vec<String> = ErrorCode::ALL
            .iter()
            .filter(|c| {
                let name = format!("{c:?}");
                // Emitted as `ErrorCode::X` at a call site, or as `C::X` inside a
                // `Coded` impl that aliases the enum.
                !sources.contains(&format!("ErrorCode::{name}"))
                    && !sources.contains(&format!("C::{name}"))
            })
            .map(|c| c.id())
            .collect();
        assert!(
            unemitted.is_empty(),
            "codes in the catalogue that nothing can ever emit: {unemitted:?}"
        );
    }

    // The published catalogue is a contract, so the docs must not drift from
    // the enum: a code added here without a row in the reference table would
    // reach a user with nowhere to look it up.
    #[test]
    fn every_code_is_documented_in_the_skill_reference() {
        let doc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../skills/burpwn/reference.md");
        let Ok(text) = std::fs::read_to_string(&doc) else {
            // The crate must stay buildable outside the workspace checkout.
            return;
        };
        let missing: Vec<String> = ErrorCode::ALL
            .iter()
            .map(|c| c.id())
            .filter(|id| !text.contains(id.as_str()))
            .collect();
        assert!(missing.is_empty(), "undocumented codes: {missing:?}");
    }

    #[test]
    fn class_exit_codes_are_the_documented_ones() {
        assert_eq!(ErrorClass::Sandbox.exit_code(), 70);
        assert_eq!(ErrorCode::SandboxNetnsSetup.exit_code(), 70);
        assert_eq!(ErrorCode::InputNoSuchFlow.exit_code(), 75);
        assert_eq!(ErrorCode::Internal.exit_code(), 78);
    }
}
