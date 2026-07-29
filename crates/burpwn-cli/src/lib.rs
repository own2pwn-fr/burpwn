//! burpwn-cli — the clap subcommand tree (doctor, init, ca, session, exec, req,
//! intercept, match-replace, workspace/tag/note, export, fuzz, compare,
//! encode/decode) with a uniform JSON envelope and the orchestration glue wiring
//! the store, proxy, sandbox, TLS and wrap layers together.
//!
//! # Command tree
//!
//! ```text
//! burpwn [--json] <command>
//!   doctor                               sandbox + CA preflight
//!   init [-g] [--agent A]                 install agent / shell hooks (burpwn-wrap)
//!   wrap-hook            (hidden)         stdin tool-input rewrite filter
//!   proxy [--session S]  (hidden)         the long-running daemon
//!   ca init | export
//!   session new|list|use|rm
//!   exec [--json] [--workspace W] [--timeout S] [--session S] -- <cmd>...
//!   req list <filters> | show <id> [--raw] | search <q> | replay <id> [edits]
//!   intercept enable|disable|list|await|forward|drop
//!   match-replace add|list|rm|enable|disable
//!   workspace new|list|use
//!   tag add <flow> <name> | note add <flow> <text>
//!   export har [--workspace] [-o file] | pcap
//!   fuzz run --flow <id> … | list | show <attack_id>   Intruder
//!   compare <flow_a> <flow_b> [--what headers|body|all]
//!   encode <scheme> <value> | decode <scheme> <value>
//! ```
//!
//! # Session / daemon / control contract (reused by the MCP crate)
//!
//! - [`paths`] defines the on-disk layout: `<data>/ca.pem`,
//!   `<data>/sessions/<name>/session.db`, `<data>/current`, and the per-session
//!   runtime dir `$XDG_RUNTIME_DIR/burpwn/<session>/{proxy.sock,control.sock,ports.json}`.
//! - [`daemon`] is the `burpwn proxy` process: it opens the session store, builds
//!   a [`burpwn_proxy::Proxy`], and concurrently serves the SCM_RIGHTS front-end,
//!   the DNS shim and the control server.
//! - [`control`] is the newline-delimited JSON control protocol
//!   ([`control::ControlRequest`] / [`control::ControlResponse`]) plus
//!   [`control::ControlClient`] — the MCP server connects a `ControlClient` to a
//!   session's `control.sock` and drives intercept/status with the typed methods.
//!
//! # Entry point
//!
//! The binary crate calls [`run`]; it parses argv, sets up tracing, dispatches,
//! and returns a process exit code.

pub mod auth;
pub mod cli;
pub mod commands;
pub mod compare;
pub mod control;
pub mod daemon;
pub mod debugreport;
pub mod diag;
pub mod encode;
pub mod envelope;
pub mod exec;
pub mod fuzz;
pub mod har;
pub mod initcheck;
pub mod mcpreg;
pub mod paths;
pub mod replay;
pub mod skill;
pub mod wrap_hook;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;
use crate::paths::Paths;

/// Parse argv, set up tracing (env `BURPWN_LOG`, to stderr), dispatch, and
/// return a process exit code. The binary crate calls this.
///
/// Tracing is initialised best-effort: if a subscriber is already installed
/// (e.g. the binary crate set one up), this is a no-op.
pub async fn run() -> Result<i32> {
    init_tracing();
    let cli = Cli::parse();
    // A failure to even resolve the data directory has to be reported the same
    // way as everything else — but there is nowhere to write a report yet, so it
    // is rendered without one.
    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => return Ok(report_without_paths(cli.json, &e)),
    };
    let json = cli.json;
    Ok(terminate(
        json,
        &paths,
        commands::dispatch(cli, &paths).await,
    ))
}

/// Like [`run`] but against an explicit [`Paths`] (for tests / embedding).
pub async fn run_with(cli: Cli, paths: &Paths) -> Result<i32> {
    let json = cli.json;
    Ok(terminate(json, paths, commands::dispatch(cli, paths).await))
}

/// The single place a burpwn failure becomes user-visible.
///
/// Everything a command can fail with converges here, and here it always gets
/// the same four things: a catalogue code, the verbatim cause chain, what to do
/// about it, and a debug report on disk. That uniformity is the point — there is
/// no path by which a failure reaches the user as a bare sentence.
///
/// * human mode → the rendered block on stderr,
/// * `--json` mode → the error envelope (legacy `error` string + structured
///   `diagnostic`) on stdout, because an agent parses stdout,
/// * exit code → the failure's [class](burpwn_error::ErrorClass::exit_code).
///
/// Success passes straight through, including `exec`'s pass-through of the
/// wrapped command's own exit code.
fn terminate(json: bool, paths: &Paths, result: Result<i32>) -> i32 {
    let err = match result {
        Ok(code) => return code,
        Err(e) => e,
    };
    let mut diag = diag::diagnose(&err);
    // Sandbox failures can say something far sharper than the catalogue's static
    // advice, by re-creating the sandbox and reporting the step that breaks. It
    // costs a fork, and only on a failure that is already fatal.
    if diag.code.class() == burpwn_error::ErrorClass::Sandbox {
        let probe = burpwn_sandbox::deep_probe();
        if !probe.is_ok() {
            for line in probe.remediation().into_iter().rev() {
                diag = diag.advise(line);
            }
        }
    }
    if let Some(path) = debugreport::write(paths, &diag) {
        diag = diag.debug_report(path);
    }
    if json {
        println!("{}", envelope::Envelope::diagnostic(&diag).to_json_line());
    } else {
        eprintln!("{}", diag.render());
    }
    diag.exit_code()
}

/// Render a failure that happened before [`Paths`] existed, so no report can be
/// written. Same shape, minus the `debug` line.
fn report_without_paths(json: bool, err: &anyhow::Error) -> i32 {
    let diag = diag::diagnose(err);
    if json {
        println!("{}", envelope::Envelope::diagnostic(&diag).to_json_line());
    } else {
        eprintln!("{}", diag.render());
    }
    diag.exit_code()
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("BURPWN_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Ignore the error when a global subscriber is already set.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_global_json_and_exec_trailing_args() {
        let cli = Cli::parse_from([
            "burpwn",
            "--json",
            "exec",
            "--timeout",
            "5",
            "--",
            "curl",
            "https://example.com",
        ]);
        assert!(cli.json);
        match cli.command {
            cli::Command::Exec(args) => {
                assert_eq!(args.timeout, Some(5));
                assert_eq!(args.cmd, vec!["curl", "https://example.com"]);
            }
            other => panic!("expected exec, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_req_list_filters() {
        let cli = Cli::parse_from([
            "burpwn", "req", "list", "--host", "example", "--status", "200", "--limit", "10",
        ]);
        match cli.command {
            cli::Command::Req {
                action: cli::ReqAction::List(args),
            } => {
                assert_eq!(args.host.as_deref(), Some("example"));
                assert_eq!(args.status, Some(200));
                assert_eq!(args.limit, Some(10));
            }
            other => panic!("expected req list, got {other:?}"),
        }
    }

    // The terminal handler is the contract: no failure escapes it uncoded, and
    // the exit code always names the failure's family.
    #[test]
    fn terminate_returns_the_class_exit_code_and_writes_a_report() {
        use burpwn_error::ErrorCode;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(tmp.path());

        let err = Err(coded!(ErrorCode::InputNoSuchFlow, "no such flow 7"));
        assert_eq!(terminate(false, &paths, err), 75);

        let reports = debugreport::recent(&paths.debug_dir(), 10);
        assert_eq!(reports.len(), 1, "a failure must leave a debug report");
        assert!(reports[0].to_string_lossy().contains("BW-INPUT-002"));
    }

    // An error nobody annotated still has to come out coded and non-zero.
    #[test]
    fn terminate_codes_an_unannotated_error_as_internal() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(tmp.path());
        let err = Err(anyhow::anyhow!("something nobody anticipated"));
        assert_eq!(terminate(false, &paths, err), 78);
    }

    #[test]
    fn terminate_passes_success_through_including_exec_exit_codes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(tmp.path());
        assert_eq!(terminate(true, &paths, Ok(0)), 0);
        // `exec` returns the wrapped command's code; it must survive untouched.
        assert_eq!(terminate(false, &paths, Ok(42)), 42);
    }

    // The bypass this guards against is easy to reintroduce and invisible in
    // review: print `error: …` yourself and `return Ok(1)`. The command then
    // exits 1 instead of its class code, with no catalogue code and no debug
    // report — and in `--json` mode it can even come back as `ok: true`.
    // Failures must travel as `Err`, so the terminal handler sees them.
    #[test]
    fn no_command_prints_its_own_error_instead_of_returning_one() {
        let src = include_str!("commands.rs");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            // `contains`, not `starts_with`: the worst instance of this bug was
            // an inline match arm (`Response::Error { .. } => eprintln!("error: …")`),
            // which a line-prefix check walks straight past.
            .filter(|(_, l)| {
                l.contains("eprintln!(\"error:") || l.contains("eprintln!(\"burpwn: error")
            })
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "these print an error instead of returning one: {offenders:?}"
        );
    }

    #[test]
    fn a_failure_before_paths_exist_is_still_coded() {
        let err = anyhow::anyhow!("cannot determine a data directory");
        assert_eq!(report_without_paths(false, &err), 78);
    }

    #[test]
    fn hidden_subcommands_parse() {
        let cli = Cli::parse_from(["burpwn", "proxy", "--session", "s"]);
        assert!(matches!(cli.command, cli::Command::Proxy(_)));
        let cli = Cli::parse_from(["burpwn", "wrap-hook"]);
        assert!(matches!(cli.command, cli::Command::WrapHook { .. }));
    }

    #[test]
    fn skill_install_flags_parse() {
        let cli = Cli::try_parse_from([
            "burpwn", "skill", "install", "--agent", "cursor", "--global", "--force",
        ])
        .unwrap();
        match cli.command {
            cli::Command::Skill {
                action: cli::SkillAction::Install(args),
            } => {
                assert_eq!(args.agent.as_deref(), Some("cursor"));
                assert!(args.global);
                assert!(args.force);
                assert!(!args.print);
                assert!(!args.all);
            }
            other => panic!("expected skill install, got {other:?}"),
        }

        // --all + --print, project default.
        let cli = Cli::try_parse_from(["burpwn", "skill", "install", "--all", "--print"]).unwrap();
        match cli.command {
            cli::Command::Skill {
                action: cli::SkillAction::Install(args),
            } => {
                assert!(args.all);
                assert!(args.print);
            }
            other => panic!("expected skill install, got {other:?}"),
        }
    }

    #[test]
    fn skill_list_and_uninstall_parse() {
        let cli = Cli::try_parse_from(["burpwn", "skill", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            cli::Command::Skill {
                action: cli::SkillAction::List
            }
        ));

        let cli = Cli::try_parse_from([
            "burpwn",
            "skill",
            "uninstall",
            "--agent",
            "codex",
            "--global",
        ])
        .unwrap();
        match cli.command {
            cli::Command::Skill {
                action: cli::SkillAction::Uninstall(args),
            } => {
                assert_eq!(args.agent, "codex");
                assert!(args.global);
            }
            other => panic!("expected skill uninstall, got {other:?}"),
        }
    }

    #[test]
    fn skill_install_bad_combos_rejected() {
        // --project + --global conflict.
        assert!(Cli::try_parse_from([
            "burpwn",
            "skill",
            "install",
            "--agent",
            "cursor",
            "--project",
            "--global",
        ])
        .is_err());
        // --agent + --all conflict.
        assert!(
            Cli::try_parse_from(["burpwn", "skill", "install", "--agent", "cursor", "--all",])
                .is_err()
        );
        // uninstall requires --agent.
        assert!(Cli::try_parse_from(["burpwn", "skill", "uninstall"]).is_err());
    }

    #[test]
    fn mcp_register_flags_parse() {
        let cli = Cli::try_parse_from(["burpwn", "mcp", "register", "--agent", "codex", "--print"])
            .unwrap();
        match cli.command {
            cli::Command::Mcp {
                action: cli::McpAction::Register(args),
            } => {
                assert_eq!(args.agent.as_deref(), Some("codex"));
                assert!(args.print);
                assert!(!args.list);
            }
            other => panic!("expected mcp register, got {other:?}"),
        }

        // --list without --agent parses.
        let cli = Cli::try_parse_from(["burpwn", "mcp", "register", "--list"]).unwrap();
        match cli.command {
            cli::Command::Mcp {
                action: cli::McpAction::Register(args),
            } => assert!(args.list),
            other => panic!("expected mcp register, got {other:?}"),
        }
    }
}
