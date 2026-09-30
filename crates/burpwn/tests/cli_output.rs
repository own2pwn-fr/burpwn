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
        vec!["--json", "scope", "list"],
        vec!["--json", "scope", "test", "example.com"],
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

/// `scope allow` / `list` / `test` / `rm` round trip through the real binary:
/// normalized patterns, idempotence, the effective set of a workspace, the
/// verdict, and the codes of the two scope-specific failures.
#[test]
fn scope_round_trip_through_the_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    assert!(burpwn(home, &["session", "new"]).status.success());
    let json = |args: &[&str]| -> serde_json::Value {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        let text = stdout(&burpwn(home, &full));
        let line = text.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("");
        serde_json::from_str(line).unwrap_or_else(|e| panic!("{args:?}: {e} in {text}"))
    };

    let v = json(&["scope", "allow", "*.Toto.FR.", "10.0.0.0/8:22"]);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["data"]["rules"][0]["pattern"], "*.toto.fr");
    assert_eq!(v["data"]["rules"][1]["pattern"], "10.0.0.0/8:22");
    let id = v["data"]["rules"][0]["id"].as_i64().unwrap();
    let again = json(&["scope", "allow", "*.toto.fr"]);
    assert_eq!(again["data"]["rules"][0]["id"], id);
    assert_eq!(again["data"]["rules"][0]["created"], false);
    let v = json(&["scope", "deny", "admin.toto.fr", "--workspace", "target"]);
    assert_eq!(v["data"]["rules"][0]["scope"], "target");

    let all = json(&["scope", "list"]);
    assert_eq!(all["data"]["rules"].as_array().unwrap().len(), 3);
    let eff = json(&["scope", "list", "--workspace", "target"]);
    assert_eq!(eff["data"]["workspace"], "target");
    assert_eq!(eff["data"]["rules"].as_array().unwrap().len(), 3);

    let t = json(&[
        "scope",
        "test",
        "admin.toto.fr:443",
        "--workspace",
        "target",
    ]);
    assert_eq!(t["data"]["verdict"], "blocked");
    assert_eq!(t["data"]["rule"]["kind"], "deny");
    let t = json(&["scope", "test", "api.toto.fr:443"]);
    assert_eq!(t["data"]["verdict"], "allowed");
    let t = json(&["scope", "test", "nottoto.fr"]);
    assert_eq!(t["data"]["verdict"], "blocked");

    let bad = json(&["scope", "allow", "*"]);
    assert_eq!(bad["ok"], false);
    assert_eq!(bad["diagnostic"]["code"], "BW-INPUT-015");
    let missing = json(&["scope", "rm", "4242"]);
    assert_eq!(missing["diagnostic"]["code"], "BW-INPUT-014");
    let rm = json(&["scope", "rm", &id.to_string()]);
    assert_eq!(rm["data"]["removed"], serde_json::json!([id]));
    let cleared = json(&["scope", "clear", "--all"]);
    assert_eq!(cleared["data"]["removed"], 2);
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

/// `export pcap` writes a BINARY file, so unlike `export har` it can never fall
/// back to stdout — the envelope has to stay alone on it. This is the case that
/// would break the MCP layer loudest if the pcapng ever leaked onto fd 1.
#[test]
fn export_pcap_keeps_stdout_clean_and_puts_the_capture_in_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    assert!(burpwn(home, &["session", "new"]).status.success());
    let out_path = home.join("cap.pcapng");
    let out = burpwn(
        home,
        &["--json", "export", "pcap", "-o", out_path.to_str().unwrap()],
    );
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "the pcapng leaked onto stdout: {text:?}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["data"]["format"], serde_json::json!("pcapng"));
    // The reply says outright that the capture is manufactured.
    assert_eq!(v["data"]["synthetic"], serde_json::json!(true));
    assert_eq!(v["data"]["packets"], serde_json::json!(0));

    // Under --json even the "this is synthetic" caveat stays off both streams as
    // prose: it is a field of the envelope, not a line an agent has to parse.
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The file really is a pcapng section header, and it is on disk rather than
    // on the wire to the caller.
    let bytes = std::fs::read(&out_path).unwrap();
    assert_eq!(&bytes[0..4], &[0x0a, 0x0d, 0x0d, 0x0a], "pcapng block type");
    assert_eq!(&bytes[8..12], &[0x4d, 0x3c, 0x2b, 0x1a], "byte-order magic");

    // Without --json the caveat IS shown — on stderr, so stdout keeps the one
    // "wrote …" line a pipe can read, exactly like `export session`.
    let human = burpwn(
        home,
        &[
            "export",
            "pcap",
            "--force",
            "-o",
            out_path.to_str().unwrap(),
        ],
    );
    assert_eq!(stdout(&human).lines().count(), 1, "{}", stdout(&human));
    assert!(stdout(&human).starts_with("wrote "), "{}", stdout(&human));
    let err = String::from_utf8_lossy(&human.stderr);
    assert!(err.contains("synthetic capture"), "{err}");

    // A second run must not clobber it silently.
    let out = burpwn(
        home,
        &["--json", "export", "pcap", "-o", out_path.to_str().unwrap()],
    );
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "{text}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["ok"], serde_json::json!(false));
    assert_eq!(v["diagnostic"]["code"], serde_json::json!("BW-INPUT-012"));
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
