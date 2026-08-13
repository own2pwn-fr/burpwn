//! The output contract, driven through the real binary.
//!
//! The unit tests in `burpwn-cli` pin the formatters; this pins what a PROCESS
//! actually writes, which is where the two rules that matter can break without
//! any formatter changing:
//!
//! 1. `--json` puts the envelope on stdout and nothing else — the MCP server
//!    parses the last non-empty stdout line, so one stray line of prose there is
//!    a protocol break rather than a cosmetic problem.
//! 2. Piped (as every one of these runs is, and as an agent's capture buffer is),
//!    the human mode emits data only: no column headers, no summary footers, no
//!    escape codes.

use std::path::Path;
use std::process::{Command, Output};

/// Run the burpwn binary against a throwaway HOME/XDG tree so nothing touches
/// the developer's real sessions.
fn burpwn(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_burpwn"))
        .args(args)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .output()
        .expect("running the burpwn binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn json_mode_emits_exactly_one_envelope_line() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    for args in [
        vec!["--json", "doctor", "--quick"],
        vec!["--json", "session", "list"],
        vec!["--json", "session", "new", "--name", "render-test"],
        vec!["--json", "req", "list"],
        vec!["--json", "tag", "list"],
        vec!["--json", "group", "list"],
        vec!["--json", "hook", "list"],
        vec!["--json", "decode", "base64", "aGk="],
    ] {
        let out = burpwn(home, &args);
        let text = stdout(&out);
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            1,
            "{args:?} wrote more than the envelope: {text}"
        );
        let v: serde_json::Value =
            serde_json::from_str(lines[0]).unwrap_or_else(|e| panic!("{args:?}: {e} in {text}"));
        assert_eq!(v["ok"], serde_json::json!(true), "{args:?}: {text}");
        assert!(!text.contains('\u{1b}'), "{args:?} coloured the envelope");
    }
}

/// A failure in `--json` mode is still one line, and still on stdout — an agent
/// parses stdout, and a diagnostic that landed on stderr would be invisible.
#[test]
fn a_json_failure_is_one_envelope_line_on_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    // The session has to exist, or the failure is about the store rather than
    // the flow — a different code and a different test.
    assert!(burpwn(tmp.path(), &["session", "new"]).status.success());
    let out = burpwn(tmp.path(), &["--json", "req", "show", "4242"]);
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "{text}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["ok"], serde_json::json!(false));
    assert_eq!(v["diagnostic"]["code"], serde_json::json!("BW-INPUT-002"));
}

#[test]
fn piped_output_is_data_only() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    assert!(burpwn(home, &["session", "new", "--name", "alpha"])
        .status
        .success());
    assert!(burpwn(home, &["session", "new", "--name", "beta"])
        .status
        .success());

    let text = stdout(&burpwn(home, &["session", "list"]));
    // No header row, no colour, no indent — and one record per line, with the
    // fields TAB-separated so `cut -f1` gives the session names.
    assert!(!text.contains("SESSION"), "header leaked: {text}");
    assert!(!text.contains('\u{1b}'), "colour leaked: {text}");
    let names: Vec<&str> = text
        .lines()
        .map(|l| l.split('\t').next().unwrap())
        .collect();
    assert_eq!(names, vec!["alpha", "beta"], "{text}");
    assert!(text.lines().all(|l| !l.starts_with(' ')), "{text}");

    // An empty listing is empty: `(no flows)` would be a line a parser has to
    // know about.
    let text = stdout(&burpwn(home, &["req", "list"]));
    assert_eq!(text, "", "an empty listing must print nothing: {text:?}");

    // The doctor's checks are data (a piped `doctor` is still greppable); its
    // verdict line is decoration.
    let text = stdout(&burpwn(home, &["doctor", "--quick"]));
    assert!(text.contains("nftables\t"), "{text}");
    assert!(!text.contains("NOT ready"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
}

/// The error block on stderr is documented in the README and asserted verbatim
/// by `burpwn-error`; without a terminal it must stay exactly that text.
#[test]
fn a_piped_error_block_is_unstyled() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(burpwn(tmp.path(), &["session", "new"]).status.success());
    let out = burpwn(tmp.path(), &["req", "show", "4242"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("error [BW-INPUT-002] "), "{err}");
    assert!(!err.contains('\u{1b}'), "{err}");
    assert!(err.trim_end().ends_with("exit  : 75"), "{err}");
    assert!(stdout(&out).is_empty(), "a failure wrote to stdout");
}
