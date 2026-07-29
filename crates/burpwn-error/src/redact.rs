//! Redaction for anything that goes into a debug report.
//!
//! A debug report is meant to be pasted into an issue, so it must not carry the
//! operator's secrets. burpwn is a pentest tool: the strings floating around it
//! (argv, env, error text) routinely contain session tokens, `Authorization`
//! headers and API keys, and the whole point of the tool is that it holds
//! credentials for the target.
//!
//! The policy is deliberately **conservative** — over-redacting a debug report
//! costs a follow-up question, under-redacting one leaks a live credential:
//!
//! * env: an **allowlist** of variables is kept with values; everything else is
//!   reported by NAME only (the name alone is often the signal — "they have
//!   `HTTPS_PROXY` set" — while the value never is),
//! * argv and free text: token-shaped substrings are replaced by `«redacted»`,
//!   and the value following a secret-ish flag is dropped whole.
//!
//! All of it is pure string work, so it is exhaustively unit-tested.

use std::collections::BTreeMap;

/// What replaces a redacted value. Deliberately distinctive so a reader knows
/// something was removed rather than mistaking it for the real value.
pub const REDACTED: &str = "«redacted»";

/// Environment variables kept WITH their value in a debug report: they are
/// diagnostic and cannot carry a credential.
const ENV_ALLOWLIST: &[&str] = &[
    "BURPWN_LOG",
    "BURPWN_RLIMIT_AS",
    "BURPWN_RLIMIT_CPU",
    "BURPWN_RLIMIT_NPROC",
    "BURPWN_SESSION",
    "COLORTERM",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "PWD",
    "SHELL",
    "TERM",
    "USER",
    "WSL_DISTRO_NAME",
    "WSL_INTEROP",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
];

/// Flag names whose FOLLOWING argument is a secret and must never be recorded.
const SECRET_FLAGS: &[&str] = &[
    "--header",
    "--password",
    "--secret",
    "--token",
    "-H",
    "-p",
    "-u",
];

/// Substrings that mark a `KEY=VALUE` / `Key: value` pair as sensitive.
const SECRET_KEY_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "auth",
    "cookie",
    "credential",
    "passwd",
    "password",
    "secret",
    "session",
    "token",
];

/// Redact the process environment for a debug report: allowlisted variables
/// keep their value, every other variable is recorded as present-but-hidden.
pub fn redact_env<I, K, V>(vars: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    vars.into_iter()
        .map(|(k, v)| {
            let k = k.into();
            let allowed = ENV_ALLOWLIST.contains(&k.as_str());
            let value = if allowed {
                redact_text(&v.into())
            } else {
                REDACTED.to_string()
            };
            (k, value)
        })
        .collect()
}

/// Redact a command line: the value after a secret flag is dropped whole, and
/// every remaining argument still goes through [`redact_text`].
pub fn redact_argv<I, S>(argv: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut out = Vec::new();
    let mut drop_next = false;
    for arg in argv {
        let arg = arg.into();
        if drop_next {
            out.push(REDACTED.to_string());
            drop_next = false;
            continue;
        }
        // `--header=value` carries the secret inline; `--header value` in the
        // next argv slot.
        if let Some((flag, _)) = arg.split_once('=') {
            if SECRET_FLAGS.contains(&flag) {
                out.push(format!("{flag}={REDACTED}"));
                continue;
            }
        }
        if SECRET_FLAGS.contains(&arg.as_str()) {
            drop_next = true;
        }
        out.push(redact_text(&arg));
    }
    out
}

/// Redact token-shaped material inside arbitrary text (error messages, command
/// lines, log excerpts).
///
/// Catches, in order: JWTs, `Bearer <token>`, `Key: value` / `key=value` pairs
/// whose key looks sensitive, and long opaque hex/base64 runs.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let _ = i;
        out.push_str(&redact_line(line));
    }
    out
}

fn redact_line(line: &str) -> String {
    // A `key: value` / `key=value` pair with a sensitive key: drop the value
    // whole, keeping the separator so the shape stays readable.
    for sep in [": ", ":", "="] {
        if let Some((key, value)) = line.split_once(sep) {
            let k = key
                .trim()
                .trim_start_matches(['-', '"', '\''])
                .to_ascii_lowercase();
            if !value.trim().is_empty() && SECRET_KEY_MARKERS.iter().any(|m| k.contains(m)) {
                let trailing_newline = if line.ends_with('\n') { "\n" } else { "" };
                return format!("{key}{sep}{REDACTED}{trailing_newline}");
            }
        }
    }
    // Otherwise redact token-shaped words in place.
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while !rest.is_empty() {
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let (word, tail) = rest.split_at(end);
        out.push_str(&redact_word(word));
        let ws_end = tail
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(tail.len());
        out.push_str(&tail[..ws_end]);
        rest = &tail[ws_end..];
    }
    out
}

fn redact_word(word: &str) -> String {
    let core =
        word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-');
    if core.is_empty() {
        return word.to_string();
    }
    if looks_like_secret(core) {
        return word.replace(core, REDACTED);
    }
    word.to_string()
}

/// True for strings that are almost certainly credentials rather than prose.
fn looks_like_secret(s: &str) -> bool {
    // A JWT: three base64url segments separated by dots, starting with a header.
    let dot_parts: Vec<&str> = s.split('.').collect();
    if dot_parts.len() == 3
        && dot_parts.iter().all(|p| p.len() >= 8 && is_b64url(p))
        && s.starts_with("ey")
    {
        return true;
    }
    // A long opaque run with no vowel-ish structure: hex or base64 material.
    // 24 is above any realistic English word or path segment, and above the
    // hostnames/flag names that legitimately appear in these strings.
    if s.len() >= 24 && is_b64url(s) && !s.contains('/') && !s.contains('.') {
        return true;
    }
    if s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

fn is_b64url(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlisted_env_keeps_its_value() {
        let env = redact_env([("PATH", "/usr/bin"), ("TERM", "xterm")]);
        assert_eq!(env["PATH"], "/usr/bin");
        assert_eq!(env["TERM"], "xterm");
    }

    // The variable NAME is diagnostic; the value never is. An unknown variable
    // is exactly where an operator's secrets live.
    #[test]
    fn unknown_env_keeps_the_name_and_drops_the_value() {
        let env = redact_env([
            ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG"),
            ("GITHUB_TOKEN", "ghp_abcdefghijklmnop"),
        ]);
        assert!(env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(env["AWS_SECRET_ACCESS_KEY"], REDACTED);
        assert_eq!(env["GITHUB_TOKEN"], REDACTED);
    }

    #[test]
    fn secret_flag_values_are_dropped_from_argv() {
        let argv = redact_argv([
            "burpwn",
            "exec",
            "--",
            "curl",
            "-H",
            "Authorization: Bearer sk-live-1234567890",
            "https://target.example/",
        ]);
        assert_eq!(argv[5], REDACTED);
        assert!(!argv.join(" ").contains("sk-live-1234567890"));
        // Everything non-secret survives, or the report is useless.
        assert_eq!(argv[3], "curl");
        assert_eq!(argv[6], "https://target.example/");
    }

    #[test]
    fn inline_secret_flag_values_are_dropped_too() {
        let argv = redact_argv(["burpwn", "--token=abcdefghijklmnopqrstuvwxyz"]);
        assert_eq!(argv[1], format!("--token={REDACTED}"));
    }

    #[test]
    fn jwts_are_redacted_anywhere_in_a_string() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let out = redact_text(&format!("token was {jwt} and it expired"));
        assert!(!out.contains(jwt), "{out}");
        assert!(out.contains(REDACTED));
        assert!(out.contains("and it expired"));
    }

    #[test]
    fn sensitive_key_value_pairs_drop_the_value() {
        assert_eq!(
            redact_text("Authorization: Bearer abc123"),
            format!("Authorization: {REDACTED}")
        );
        assert_eq!(
            redact_text("password=hunter2"),
            format!("password={REDACTED}")
        );
        assert!(redact_text("Cookie: session=abc").contains(REDACTED));
    }

    #[test]
    fn long_opaque_runs_are_redacted() {
        let out = redact_text("key AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7 done");
        assert!(out.contains(REDACTED), "{out}");
        assert!(out.contains("done"));
    }

    // Over-redaction makes reports useless, so the ordinary diagnostic text a
    // report exists to carry must survive untouched.
    #[test]
    fn ordinary_diagnostic_text_survives() {
        for text in [
            "ip link add burp0 type dummy failed: Error: Unknown device type.",
            "nft load failed: Could not process rule: Operation not supported",
            "/home/me/.local/share/burpwn/sessions/engagement-1/capture.db",
            "https://target.example/admin?page=2",
            "6.17.11-300.fc43.x86_64",
        ] {
            assert_eq!(redact_text(text), text, "over-redacted: {text}");
        }
    }

    #[test]
    fn multiline_text_is_redacted_line_by_line() {
        let out = redact_text("host: target\nAuthorization: Bearer abc\nport: 443\n");
        assert!(out.contains("host: target"));
        assert!(out.contains(&format!("Authorization: {REDACTED}")));
        assert!(out.contains("port: 443"));
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn empty_values_are_not_treated_as_secrets() {
        assert_eq!(redact_text("token: "), "token: ");
    }
}
