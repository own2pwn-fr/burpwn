//! Generic global shell hook — the catch-all that works for ANY agent.
//!
//! Per-agent hooks ([`crate::hooks`]) only cover agents we explicitly support.
//! For an arbitrary/custom agent that just spawns `$SHELL -c "cmd"`, we install
//! a generic interactive-shell hook (rtk's `init -g` equivalent).
//!
//! ## Mechanism (and why)
//!
//! A `command_not_found_handler` is useless here (the command *is* found). The
//! robust, shell-portable approach we generate is a **`preexec` rewrite**:
//!
//! * In zsh: a `preexec` function fires with the about-to-run command line.
//! * In bash: we emulate the same via a `DEBUG` trap guarded by
//!   `$BASH_COMMAND`, gated on an interactive shell.
//!
//! The snippet does NOT try to silently re-exec the typed command (that fights
//! the shell and is fragile). Instead it follows rtk's pragmatic model:
//!
//!   1. Define a `burpwn` passthrough so the snippet is self-contained.
//!   2. On each command, if the program is not excluded and not already a
//!      `burpwn exec` invocation, PRINT a one-line hint that the operator (or a
//!      scripted agent reading the TTY) should run it via `burpwn exec --`.
//!   3. Provide a `bw` helper function: `bw <cmd…>` ⇒ `burpwn exec -- <cmd…>`
//!      (argv passed through verbatim — no shell re-parse), and a
//!      `BURPWN_AUTO=1` opt-in that makes the preexec actively re-run the whole
//!      command line through `burpwn exec -- sh -c "$cmd"` (off by default to
//!      avoid surprising an interactive operator). The `sh -c` form ensures a
//!      compound line (`&&`, `;`, `|`, `$(…)`) runs entirely inside one sandbox
//!      rather than only its first top-level segment.
//!
//! The accompanying [`shell_wrapper_script`] is a tiny executable an operator
//! can set as a custom agent's shell (`SHELL=/…/burpwn-shell`) for fully
//! transparent wrapping when an agent honors `$SHELL`.
//!
//! Exclusions ([`crate::WrapConfig::exclude_commands`]) are honored inline.

use std::path::Path;

use crate::WrapError;

/// Marker lines bracketing the burpwn block in an rc file (idempotent install).
pub const BEGIN_MARKER: &str = "# >>> burpwn >>>";
/// See [`BEGIN_MARKER`].
pub const END_MARKER: &str = "# <<< burpwn <<<";

/// Render a shell array literal of the excluded program names, quoted safely
/// for both bash and zsh (single-quoted, with embedded `'` escaped).
fn exclude_array(exclude: &[String]) -> String {
    let mut s = String::from("(");
    for (i, e) in exclude.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&single_quote(e));
    }
    s.push(')');
    s
}

/// Single-quote a string for POSIX-ish shells: wrap in `'…'`, turning any
/// embedded `'` into the `'\''` idiom.
pub(crate) fn single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Generate the global shell hook snippet (pure).
///
/// The returned text is bracketed by the begin/end markers and is valid in both
/// bash and zsh. `exclude` lists program names that must never be rewritten.
pub fn global_shell_snippet(exclude: &[String]) -> String {
    let excl = exclude_array(exclude);
    // NOTE: this is a heredoc-free literal; `{excl}` is the only interpolation.
    format!(
        r#"{BEGIN_MARKER}
# burpwn generic shell hook (rtk-style `init -g`). Routes interactive commands
# through `burpwn exec` so their network traffic is captured. Safe to re-source.
# Honors exclude_commands; opt into auto-rewrite with `export BURPWN_AUTO=1`.

# Programs that must NOT be wrapped (run unchanged).
__burpwn_exclude={excl}

# True if $1 (a full command line) should be wrapped.
__burpwn_should_wrap() {{
  local line="$1" prog="" next="" tok seen_prog=0
  # Extract the PROGRAM token: skip leading VAR=val assignments and a benign
  # wrapper prefix (sudo/env/command/nice/nohup), strip any path, and remember
  # the token right after it. Anchoring to the program (rather than scanning the
  # whole line) avoids a false "already wrapped" on a command that merely
  # mentions `burpwn exec` as an argument — which would silently skip capture.
  for tok in $line; do
    if [ "$seen_prog" = "1" ]; then next="$tok"; break; fi
    case "$tok" in
      [A-Za-z_]*=*) continue ;;
      sudo|env|command|nice|nohup) continue ;;
      *) prog="${{tok##*/}}"; seen_prog=1 ;;
    esac
  done
  [ -z "$prog" ] && return 1
  # Already wrapped? (program is `burpwn` followed by `exec`, or the `bw` helper.)
  if {{ [ "$prog" = "burpwn" ] && [ "$next" = "exec" ]; }} || [ "$prog" = "bw" ]; then
    return 1
  fi
  local e
  for e in "${{__burpwn_exclude[@]}}"; do
    [ "$e" = "$prog" ] && return 1
  done
  return 0
}}

# `bw <cmd...>` — explicit helper to run a command through burpwn.
bw() {{ command burpwn exec -- "$@"; }}

# preexec-style rewrite. With BURPWN_AUTO=1 it re-runs the typed command via
# `burpwn exec`; otherwise it just prints a reminder (non-invasive default).
__burpwn_preexec() {{
  local cmd="$1"
  __burpwn_should_wrap "$cmd" || return 0
  if [ "${{BURPWN_AUTO:-0}}" = "1" ]; then
    print -r -- "[burpwn] wrapping: $cmd" 2>/dev/null || echo "[burpwn] wrapping: $cmd"
    # Run the WHOLE line inside one sandboxed shell so compound commands
    # (&&, ;, |, $(…)) are captured in full, not just the first segment.
    command burpwn exec -- sh -c "$cmd"
    return 130   # signal the original line was already handled (zsh)
  else
    echo "[burpwn] tip: export BURPWN_AUTO=1 to auto-capture, or run: burpwn exec -- sh -c '$cmd'" >&2
  fi
}}

if [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null
  if typeset -f add-zsh-hook >/dev/null 2>&1; then
    add-zsh-hook preexec __burpwn_preexec
  fi
elif [ -n "$BASH_VERSION" ]; then
  case $- in
    *i*)
      __burpwn_debug_trap() {{
        [ -n "$COMP_LINE" ] && return            # skip completion
        [ "$BASH_COMMAND" = "$PROMPT_COMMAND" ] && return
        __burpwn_preexec "$BASH_COMMAND"
      }}
      trap '__burpwn_debug_trap' DEBUG
      ;;
  esac
fi
{END_MARKER}
"#
    )
}

/// Content of a standalone `burpwn-shell` wrapper executable.
///
/// Set as a custom agent's `$SHELL` (`SHELL=/usr/local/bin/burpwn-shell`) so any
/// `$SHELL -c "<cmd>"` it spawns is transparently routed through `burpwn exec`.
/// Honors `-c`; an interactive launch falls back to the user's real shell.
pub fn shell_wrapper_script() -> String {
    String::from(
        r#"#!/usr/bin/env sh
# burpwn-shell — drop-in $SHELL wrapper. Routes `-c <cmd>` through burpwn so its
# traffic is captured. Any other invocation defers to the user's real shell.
set -eu
__real_shell="${BURPWN_REAL_SHELL:-/bin/sh}"
if [ "${1:-}" = "-c" ] && [ "$#" -ge 2 ]; then
  shift
  exec burpwn exec -- "$__real_shell" -c "$@"
fi
exec "$__real_shell" "$@"
"#,
    )
}

/// Idempotently install the global snippet into rc file `rc_path` between the
/// burpwn markers. If a burpwn block already exists it is replaced (so re-runs
/// update in place); the rest of the file is preserved. Creates the file (and
/// parents) if absent. Returns `true` if the file content changed.
pub fn install_global(rc_path: &Path, exclude: &[String]) -> Result<bool, WrapError> {
    let snippet = global_shell_snippet(exclude);
    let existing = match std::fs::read_to_string(rc_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(WrapError::Io(e)),
    };

    let stripped = strip_block(&existing);
    // Ensure separation: trailing newline before the block.
    let mut next = stripped;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    if !next.is_empty() {
        next.push('\n');
    }
    next.push_str(&snippet);

    if next == existing {
        return Ok(false);
    }
    if let Some(parent) = rc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(rc_path, next)?;
    Ok(true)
}

/// Remove the burpwn block from `rc_path` (idempotent). Returns `true` if a
/// block was present and removed. A missing file is a no-op.
pub fn uninstall_global(rc_path: &Path) -> Result<bool, WrapError> {
    let existing = match std::fs::read_to_string(rc_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(WrapError::Io(e)),
    };
    let stripped = strip_block(&existing);
    if stripped == existing {
        return Ok(false);
    }
    std::fs::write(rc_path, stripped)?;
    Ok(true)
}

/// Remove any `# >>> burpwn >>> … # <<< burpwn <<<` block (inclusive) from
/// `text`, along with one trailing blank line if it leaves one. Pure.
fn strip_block(text: &str) -> String {
    let Some(start) = text.find(BEGIN_MARKER) else {
        return text.to_string();
    };
    let Some(end_rel) = text[start..].find(END_MARKER) else {
        return text.to_string();
    };
    let end = start + end_rel + END_MARKER.len();
    // Consume the newline right after the end marker, if present.
    let mut tail_start = end;
    if text[tail_start..].starts_with('\n') {
        tail_start += 1;
    }
    let mut head = text[..start].to_string();
    // Drop a blank separator line we may have inserted before the block.
    if head.ends_with("\n\n") {
        head.pop();
    }
    let tail = &text[tail_start..];
    head.push_str(tail);
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_has_markers_and_rewrite() {
        let s = global_shell_snippet(&[]);
        assert!(s.starts_with(BEGIN_MARKER));
        assert!(s.trim_end().ends_with(END_MARKER));
        assert!(s.contains("burpwn exec --"));
        assert!(s.contains("preexec"));
        assert!(s.contains("DEBUG")); // bash path present
        assert!(s.contains("__burpwn_exclude=()"));
    }

    #[test]
    fn snippet_embeds_exclusions_quoted() {
        let s = global_shell_snippet(&["git".into(), "weird name".into()]);
        assert!(s.contains("__burpwn_exclude=('git' 'weird name')"));
    }

    #[test]
    fn single_quote_escapes() {
        assert_eq!(single_quote("git"), "'git'");
        assert_eq!(single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn wrapper_script_execs_burpwn() {
        let w = shell_wrapper_script();
        assert!(w.starts_with("#!/usr/bin/env sh"));
        assert!(w.contains("exec burpwn exec --"));
    }

    #[test]
    fn install_global_creates_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("sub").join(".zshrc");

        // first install creates the file + block
        assert!(install_global(&rc, &[]).unwrap());
        let body1 = std::fs::read_to_string(&rc).unwrap();
        assert!(body1.contains(BEGIN_MARKER));

        // second install with same args: no change
        assert!(!install_global(&rc, &[]).unwrap());
        let body2 = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(body1, body2);

        // exactly one block (no duplication)
        assert_eq!(body2.matches(BEGIN_MARKER).count(), 1);
    }

    #[test]
    fn install_global_preserves_existing_rc_content() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        std::fs::write(&rc, "export FOO=bar\nalias ll='ls -la'\n").unwrap();

        install_global(&rc, &[]).unwrap();
        let body = std::fs::read_to_string(&rc).unwrap();
        assert!(body.contains("export FOO=bar"));
        assert!(body.contains("alias ll='ls -la'"));
        assert!(body.contains(BEGIN_MARKER));
    }

    #[test]
    fn install_global_updates_block_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        std::fs::write(&rc, "keep me\n").unwrap();

        install_global(&rc, &[]).unwrap();
        // change exclusions -> block replaced, still single block, user line kept
        assert!(install_global(&rc, &["git".into()]).unwrap());
        let body = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(body.matches(BEGIN_MARKER).count(), 1);
        assert!(body.contains("keep me"));
        assert!(body.contains("'git'"));
    }

    #[test]
    fn uninstall_global_removes_block_only() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        std::fs::write(&rc, "export FOO=bar\n").unwrap();
        install_global(&rc, &[]).unwrap();

        assert!(uninstall_global(&rc).unwrap());
        let body = std::fs::read_to_string(&rc).unwrap();
        assert!(body.contains("export FOO=bar"));
        assert!(!body.contains(BEGIN_MARKER));
        assert!(!body.contains(END_MARKER));

        // idempotent: removing again is a no-op
        assert!(!uninstall_global(&rc).unwrap());
    }

    #[test]
    fn uninstall_missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("nope");
        assert!(!uninstall_global(&rc).unwrap());
    }

    #[test]
    fn strip_block_roundtrips_install() {
        // installing then stripping yields back (modulo separator) the original
        let original = "line A\nline B\n";
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("rc");
        std::fs::write(&rc, original).unwrap();
        install_global(&rc, &[]).unwrap();
        uninstall_global(&rc).unwrap();
        let body = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(body, original);
    }
}
