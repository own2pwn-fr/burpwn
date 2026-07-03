//! Portable "skill" installer: drop the burpwn agent-workflow instructions into
//! ANY supported framework's native location + format, in one command.
//!
//! This is separate from the `init` command-rewrite hook (`burpwn wrap-hook`):
//! the *skill* is a markdown instruction file teaching an agent the burpwn
//! workflow (create a session, route target-facing network commands through
//! `burpwn exec`, then query/replay/`fuzz`/`compare`/`encode`/intercept/`session
//! auth`, and use the MCP tools when available). `init` rewrites shell commands;
//! this teaches the agent what to do. They are complementary.
//!
//! # Design
//!
//! A single framework-neutral skill body is embedded via [`include_str!`]
//! ([`SKILL_CORE`]) so the installer works with no repo checkout. A data-driven
//! [`SkillTarget`] registry ([`targets`]) declares, per framework, the install
//! [`Format`] and the project/global destination paths. Three formats:
//!
//! * [`Format::SkillDir`] — a `skills/burpwn/SKILL.md` directory file with YAML
//!   frontmatter (`name: burpwn`, `description: <one-line>`). Claude Code, Strix.
//! * [`Format::RulesFile`] — a rules file with the framework's frontmatter.
//!   Cursor (`.cursor/rules/burpwn.mdc`), Cline (`.clinerules/burpwn.md`).
//! * [`Format::InstructionsAppend`] — a managed, marker-delimited section
//!   appended to an existing instructions file (`GEMINI.md`, `AGENTS.md`,
//!   `.github/copilot-instructions.md`, …), created if absent.
//!
//! # Idempotency + anti-clobber (mirrors [`burpwn_wrap::install`])
//!
//! Whole-file formats (SkillDir/RulesFile) carry an HTML-comment ownership marker
//! ([`MANAGED_MARKER`]); re-running rewrites *our* managed file in place, but a
//! pre-existing file we do NOT own is refused (returned [`SkillAction::Refused`],
//! never overwritten) unless `force`. InstructionsAppend replaces only the
//! marker-delimited block, leaving unrelated file content intact.

use std::path::{Path, PathBuf};

/// The framework-neutral skill body, embedded at compile time so `skill install`
/// works without the repo checkout. Frontmatter/markers are added per format.
pub const SKILL_CORE: &str = include_str!("../../../skills/burpwn/skill-core.md");

/// The one-line description used in SkillDir / Cursor frontmatter.
pub const ONE_LINE_DESC: &str = "Route every target-facing network command \
    through `burpwn exec` during a web/API/network security audit so all traffic \
    is captured, MITM-decrypted, searchable, replayable, fuzzable and \
    live-interceptable; use the burpwn CLI or its MCP tools.";

/// Ownership marker embedded in whole-file (SkillDir/RulesFile) skill files. Its
/// presence means "burpwn owns this file"; we refuse to overwrite a same-named
/// file that lacks it (unless `force`).
pub const MANAGED_MARKER: &str = "<!-- burpwn-skill: managed";

/// The full managed-marker line written into whole-file skill content.
const MANAGED_MARKER_LINE: &str =
    "<!-- burpwn-skill: managed — do not edit; regenerate with `burpwn skill install` -->";

/// Marker delimiting the burpwn block inside an InstructionsAppend target file.
pub const APPEND_BEGIN: &str = "<!-- >>> burpwn >>> -->";
/// Closing marker for the InstructionsAppend block.
pub const APPEND_END: &str = "<!-- <<< burpwn <<< -->";

/// Which on-disk shape a framework's skill takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A `skills/burpwn/SKILL.md` file with `name`/`description` YAML frontmatter.
    SkillDir,
    /// A rules file. `cursor` selects the Cursor `.mdc` frontmatter
    /// (`description:` + `alwaysApply: true`); otherwise a plain-markdown rules
    /// file (Cline).
    RulesFile { cursor: bool },
    /// A managed, marker-delimited block appended to an instructions file.
    InstructionsAppend,
}

impl Format {
    /// Stable label for `skill list` output.
    pub fn label(self) -> &'static str {
        match self {
            Format::SkillDir => "SkillDir",
            Format::RulesFile { .. } => "RulesFile",
            Format::InstructionsAppend => "InstructionsAppend",
        }
    }

    /// True if the whole destination file is burpwn-managed (SkillDir/RulesFile);
    /// false for the append-a-section format.
    fn is_whole_file(self) -> bool {
        !matches!(self, Format::InstructionsAppend)
    }
}

/// Project (cwd-relative) vs global (HOME-relative) install scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// cwd-relative — the recommended default.
    Project,
    /// HOME-relative — only some frameworks define a global location.
    Global,
}

/// One framework's skill target: how + where to install.
#[derive(Debug, Clone, Copy)]
pub struct SkillTarget {
    /// Machine slug (CLI `--agent` value).
    pub slug: &'static str,
    /// Human display name.
    pub name: &'static str,
    /// Install format.
    pub format: Format,
    /// Destination relative to the cwd for project scope.
    pub project_rel: &'static str,
    /// Destination relative to HOME for global scope, or `None` if this
    /// framework has no well-defined global location.
    pub global_rel: Option<&'static str>,
    /// A note surfaced by `skill list` / docs when a path is best-effort /
    /// uncertain (empty when the path is authoritative).
    pub note: &'static str,
}

impl SkillTarget {
    /// The destination relative path for `scope`, or `None` when unsupported.
    pub fn rel_for(&self, scope: Scope) -> Option<&'static str> {
        match scope {
            Scope::Project => Some(self.project_rel),
            Scope::Global => self.global_rel,
        }
    }

    /// The absolute destination path under `root` (cwd for project, HOME for
    /// global) for `scope`, or `None` when the scope is unsupported.
    pub fn dest(&self, root: &Path, scope: Scope) -> Option<PathBuf> {
        self.rel_for(scope).map(|rel| root.join(rel))
    }
}

/// The framework target registry — one entry per supported framework.
///
/// Path notes (surfaced for the docs pass):
/// * Claude Code SkillDir paths are authoritative (`.claude/skills/<name>/SKILL.md`).
/// * Strix: skill files use the same SkillDir frontmatter; the exact directory
///   (`.strix/skills/…`) is best-effort — flagged via `note`.
/// * Cursor project rules (`.cursor/rules/*.mdc`) are authoritative; Cursor has
///   no file-based *global* rules location, so `--global` is unsupported.
/// * Cline `.clinerules/<file>.md` is authoritative for project; no global file.
/// * Gemini `GEMINI.md` (project) + `~/.gemini/GEMINI.md` (global) authoritative.
/// * Codex `AGENTS.md` (project) + `~/.codex/AGENTS.md` (global) authoritative.
/// * Copilot `.github/copilot-instructions.md` authoritative for project; no
///   well-defined global instructions file, so `--global` is unsupported.
/// * Antigravity uses `AGENTS.md`; no documented global instructions path.
/// * `agents` is the generic `AGENTS.md` fallback (project only).
pub fn targets() -> &'static [SkillTarget] {
    const T: &[SkillTarget] = &[
        SkillTarget {
            slug: "claude-code",
            name: "Claude Code",
            format: Format::SkillDir,
            project_rel: ".claude/skills/burpwn/SKILL.md",
            global_rel: Some(".claude/skills/burpwn/SKILL.md"),
            note: "",
        },
        SkillTarget {
            slug: "strix",
            name: "Strix",
            format: Format::SkillDir,
            project_rel: ".strix/skills/burpwn/SKILL.md",
            global_rel: None,
            note: "skill directory best-effort; confirm Strix's skills path",
        },
        SkillTarget {
            slug: "cursor",
            name: "Cursor",
            format: Format::RulesFile { cursor: true },
            project_rel: ".cursor/rules/burpwn.mdc",
            global_rel: None,
            note: "Cursor has no file-based global rules; use --project",
        },
        SkillTarget {
            slug: "cline",
            name: "Cline",
            format: Format::RulesFile { cursor: false },
            project_rel: ".clinerules/burpwn.md",
            global_rel: None,
            note: "",
        },
        SkillTarget {
            slug: "gemini",
            name: "Gemini CLI",
            format: Format::InstructionsAppend,
            project_rel: "GEMINI.md",
            global_rel: Some(".gemini/GEMINI.md"),
            note: "",
        },
        SkillTarget {
            slug: "codex",
            name: "Codex CLI",
            format: Format::InstructionsAppend,
            project_rel: "AGENTS.md",
            global_rel: Some(".codex/AGENTS.md"),
            note: "",
        },
        SkillTarget {
            slug: "copilot",
            name: "GitHub Copilot CLI",
            format: Format::InstructionsAppend,
            project_rel: ".github/copilot-instructions.md",
            global_rel: None,
            note: "no well-defined global instructions file; use --project",
        },
        SkillTarget {
            slug: "antigravity",
            name: "Antigravity",
            format: Format::InstructionsAppend,
            project_rel: "AGENTS.md",
            global_rel: None,
            note: "no documented global instructions path; use --project",
        },
        SkillTarget {
            slug: "agents",
            name: "Generic AGENTS.md",
            format: Format::InstructionsAppend,
            project_rel: "AGENTS.md",
            global_rel: None,
            note: "generic AGENTS.md fallback (project only)",
        },
    ];
    T
}

/// Look up a target by slug.
pub fn target_by_slug(slug: &str) -> Option<&'static SkillTarget> {
    let s = slug.trim().to_ascii_lowercase();
    targets().iter().find(|t| t.slug == s)
}

/// What an install actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillAction {
    /// Skill written into a location that lacked it.
    Installed,
    /// The exact skill content was already present; nothing changed.
    AlreadyPresent,
    /// A burpwn-managed skill existed but differed and was updated in place.
    Updated,
    /// A non-burpwn file/section already occupies the destination; refused to
    /// clobber it (pass `force` to replace).
    Refused,
    /// `--print` mode: nothing was written.
    Printed,
    /// Uninstall removed our file / stripped our block.
    Removed,
    /// Uninstall found nothing of ours to remove.
    Absent,
}

impl SkillAction {
    /// Lowercase stable label for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            SkillAction::Installed => "Installed",
            SkillAction::AlreadyPresent => "AlreadyPresent",
            SkillAction::Updated => "Updated",
            SkillAction::Refused => "Refused",
            SkillAction::Printed => "Printed",
            SkillAction::Removed => "Removed",
            SkillAction::Absent => "Absent",
        }
    }
}

/// Outcome of installing/uninstalling one target.
#[derive(Debug, Clone)]
pub struct SkillReport {
    /// Target slug.
    pub slug: &'static str,
    /// Destination file.
    pub path: PathBuf,
    /// What happened.
    pub action: SkillAction,
    /// The rendered content (for `--print`; empty otherwise).
    pub content: String,
}

/// Errors from skill install/uninstall.
#[derive(Debug, thiserror::Error)]
pub enum SkillError {
    /// Filesystem I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested scope has no destination for this framework.
    #[error("{scope} scope not supported for {slug}; use --project")]
    ScopeUnsupported {
        /// Framework slug.
        slug: &'static str,
        /// The unsupported scope ("global").
        scope: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Content rendering (pure)
// ---------------------------------------------------------------------------

/// Render the full file content for a whole-file (SkillDir/RulesFile) target.
fn render_whole_file(format: Format) -> String {
    match format {
        Format::SkillDir => format!(
            "---\nname: burpwn\ndescription: {desc}\n---\n\n{marker}\n\n{body}",
            desc = ONE_LINE_DESC,
            marker = MANAGED_MARKER_LINE,
            body = SKILL_CORE,
        ),
        Format::RulesFile { cursor: true } => format!(
            "---\ndescription: {desc}\nalwaysApply: true\n---\n\n{marker}\n\n{body}",
            desc = ONE_LINE_DESC,
            marker = MANAGED_MARKER_LINE,
            body = SKILL_CORE,
        ),
        Format::RulesFile { cursor: false } => {
            format!(
                "{marker}\n\n{body}",
                marker = MANAGED_MARKER_LINE,
                body = SKILL_CORE
            )
        }
        // Not a whole-file format; callers must not reach here.
        Format::InstructionsAppend => String::new(),
    }
}

/// Render the marker-delimited block for an InstructionsAppend target.
fn render_block() -> String {
    format!(
        "{APPEND_BEGIN}\n{body}\n{APPEND_END}",
        body = SKILL_CORE.trim_end()
    )
}

/// The content that `install` would produce for a target (for `--print`). For
/// InstructionsAppend this is just the managed block, not the whole file.
pub fn render_content(target: &SkillTarget) -> String {
    if target.format.is_whole_file() {
        render_whole_file(target.format)
    } else {
        render_block()
    }
}

/// Replace the marker-delimited burpwn block in `existing`, or append it if
/// absent. Returns the new file text. Pure. `block` must NOT carry a trailing
/// newline (one is added between existing content and the block).
fn upsert_block(existing: &str, block: &str) -> String {
    if let (Some(start), Some(end_rel)) = (
        existing.find(APPEND_BEGIN),
        existing.find(APPEND_END).map(|e| e + APPEND_END.len()),
    ) {
        // Replace in place (guard against a malformed file where END precedes
        // BEGIN by falling through to append).
        if end_rel > start {
            let mut out = String::with_capacity(existing.len() + block.len());
            out.push_str(&existing[..start]);
            out.push_str(block);
            out.push_str(&existing[end_rel..]);
            return out;
        }
    }
    // Append: keep the user's content, ensure a blank line before our block.
    let mut out = existing.to_string();
    if !out.is_empty() {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(block);
    out.push('\n');
    out
}

/// Strip the marker-delimited burpwn block (inclusive of markers + one trailing
/// blank line). Pure.
fn strip_block(text: &str) -> String {
    let Some(start) = text.find(APPEND_BEGIN) else {
        return text.to_string();
    };
    let Some(end_rel) = text[start..].find(APPEND_END) else {
        return text.to_string();
    };
    let end = start + end_rel + APPEND_END.len();
    let mut tail_start = end;
    if text[tail_start..].starts_with('\n') {
        tail_start += 1;
    }
    let mut head = text[..start].to_string();
    if head.ends_with("\n\n") {
        head.pop();
    }
    head.push_str(&text[tail_start..]);
    head
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

/// Install the skill for `target` under `root` (cwd for project, HOME for
/// global). `print` writes nothing and only fills [`SkillReport::content`].
/// `force` overwrites a non-burpwn file/section.
pub fn install(
    target: &SkillTarget,
    root: &Path,
    scope: Scope,
    print: bool,
    force: bool,
) -> Result<SkillReport, SkillError> {
    let Some(path) = target.dest(root, scope) else {
        return Err(SkillError::ScopeUnsupported {
            slug: target.slug,
            scope: "global",
        });
    };

    let content = render_content(target);
    if print {
        return Ok(SkillReport {
            slug: target.slug,
            path,
            action: SkillAction::Printed,
            content,
        });
    }

    let action = if target.format.is_whole_file() {
        install_whole_file(&path, &render_whole_file(target.format), force)?
    } else {
        install_append(&path, &render_block())?
    };

    Ok(SkillReport {
        slug: target.slug,
        path,
        action,
        content: String::new(),
    })
}

/// Whole-file install: write our managed file, refusing to clobber a file we
/// don't own unless `force`.
fn install_whole_file(path: &Path, desired: &str, force: bool) -> Result<SkillAction, SkillError> {
    match std::fs::read_to_string(path) {
        Ok(existing) => {
            if existing == desired {
                return Ok(SkillAction::AlreadyPresent);
            }
            let ours = existing.contains(MANAGED_MARKER);
            if !ours && !force {
                return Ok(SkillAction::Refused);
            }
            write_file(path, desired)?;
            Ok(SkillAction::Updated)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_file(path, desired)?;
            Ok(SkillAction::Installed)
        }
        Err(e) => Err(SkillError::Io(e)),
    }
}

/// InstructionsAppend install: replace our marker block, or append it. We never
/// touch content outside our markers, so this never clobbers user content.
fn install_append(path: &Path, block: &str) -> Result<SkillAction, SkillError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(SkillError::Io(e)),
    };
    let had_block = existing.contains(APPEND_BEGIN);
    let next = upsert_block(&existing, block);
    if next == existing {
        return Ok(SkillAction::AlreadyPresent);
    }
    write_file(path, &next)?;
    // Either a fresh file or our section appended to a pre-existing (non-burpwn)
    // file counts as Installed; only replacing an existing burpwn block is Updated.
    Ok(if had_block {
        SkillAction::Updated
    } else {
        SkillAction::Installed
    })
}

/// Uninstall the skill for `target` under `root`: remove our managed file /
/// strip our block. Leaves unrelated content intact; never deletes a file we
/// don't own.
pub fn uninstall(
    target: &SkillTarget,
    root: &Path,
    scope: Scope,
) -> Result<SkillReport, SkillError> {
    let Some(path) = target.dest(root, scope) else {
        return Err(SkillError::ScopeUnsupported {
            slug: target.slug,
            scope: "global",
        });
    };

    let action = if target.format.is_whole_file() {
        uninstall_whole_file(&path)?
    } else {
        uninstall_append(&path)?
    };

    Ok(SkillReport {
        slug: target.slug,
        path,
        action,
        content: String::new(),
    })
}

/// Remove our whole-file skill iff we own it (has [`MANAGED_MARKER`]).
fn uninstall_whole_file(path: &Path) -> Result<SkillAction, SkillError> {
    match std::fs::read_to_string(path) {
        Ok(existing) if existing.contains(MANAGED_MARKER) => {
            std::fs::remove_file(path)?;
            // Best-effort: prune now-empty `skills/burpwn` parent dirs so a
            // SkillDir uninstall doesn't leave empty scaffolding. Ignore errors
            // (a non-empty dir stays put).
            prune_empty_parents(path);
            Ok(SkillAction::Removed)
        }
        Ok(_) => Ok(SkillAction::Absent), // present but not ours: leave it
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SkillAction::Absent),
        Err(e) => Err(SkillError::Io(e)),
    }
}

/// Strip our marker block from an InstructionsAppend target, leaving the rest.
fn uninstall_append(path: &Path) -> Result<SkillAction, SkillError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SkillAction::Absent),
        Err(e) => return Err(SkillError::Io(e)),
    };
    if !existing.contains(APPEND_BEGIN) {
        return Ok(SkillAction::Absent);
    }
    let stripped = strip_block(&existing);
    if stripped == existing {
        return Ok(SkillAction::Absent);
    }
    // If stripping left only whitespace and the file didn't exist before us in a
    // meaningful way, still keep the (now near-empty) file: it may have been the
    // user's. Simplest + safest: write the stripped content back.
    write_file(path, &stripped)?;
    Ok(SkillAction::Removed)
}

/// Write `content` to `path`, creating parent dirs.
fn write_file(path: &Path, content: &str) -> Result<(), SkillError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

/// Remove `path`'s parent directories while they are empty, stopping at the
/// first non-empty one. Best-effort (errors ignored).
fn prune_empty_parents(path: &Path) {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        // Stop before we'd try to remove the cwd/home root.
        if std::fs::remove_dir(dir).is_err() {
            break;
        }
        cur = dir.parent();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn td() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn every_target_installs_into_project_tempdir() {
        for t in targets() {
            let root = td();
            let rep = install(t, root.path(), Scope::Project, false, false).unwrap();
            assert_eq!(rep.action, SkillAction::Installed, "target {}", t.slug);
            assert!(rep.path.exists(), "dest missing for {}", t.slug);
            let body = read(&rep.path);
            // The skill body is present in every format.
            assert!(
                body.contains("burpwn exec"),
                "skill body missing for {}",
                t.slug
            );
            // Whole-file formats carry the ownership marker + right frontmatter.
            match t.format {
                Format::SkillDir => {
                    assert!(body.starts_with("---\nname: burpwn\n"), "{}", t.slug);
                    assert!(body.contains(MANAGED_MARKER), "{}", t.slug);
                }
                Format::RulesFile { cursor: true } => {
                    assert!(body.contains("alwaysApply: true"), "{}", t.slug);
                    assert!(body.contains("description:"), "{}", t.slug);
                    assert!(body.contains(MANAGED_MARKER), "{}", t.slug);
                }
                Format::RulesFile { cursor: false } => {
                    assert!(body.contains(MANAGED_MARKER), "{}", t.slug);
                }
                Format::InstructionsAppend => {
                    assert!(body.contains(APPEND_BEGIN), "{}", t.slug);
                    assert!(body.contains(APPEND_END), "{}", t.slug);
                }
            }
        }
    }

    #[test]
    fn second_run_is_idempotent_no_duplication() {
        for t in targets() {
            let root = td();
            install(t, root.path(), Scope::Project, false, false).unwrap();
            let rep2 = install(t, root.path(), Scope::Project, false, false).unwrap();
            assert_eq!(
                rep2.action,
                SkillAction::AlreadyPresent,
                "second run not idempotent for {}",
                t.slug
            );
            let body = read(&rep2.path);
            if !t.format.is_whole_file() {
                assert_eq!(
                    body.matches(APPEND_BEGIN).count(),
                    1,
                    "duplicated block for {}",
                    t.slug
                );
            }
        }
    }

    #[test]
    fn uninstall_removes_only_our_content() {
        // SkillDir: file removed.
        let t = target_by_slug("claude-code").unwrap();
        let root = td();
        let rep = install(t, root.path(), Scope::Project, false, false).unwrap();
        assert!(rep.path.exists());
        let un = uninstall(t, root.path(), Scope::Project).unwrap();
        assert_eq!(un.action, SkillAction::Removed);
        assert!(!rep.path.exists());

        // InstructionsAppend: user content survives, our block stripped.
        let t = target_by_slug("codex").unwrap();
        let root = td();
        let path = t.dest(root.path(), Scope::Project).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# My project\nBe nice.\n").unwrap();
        install(t, root.path(), Scope::Project, false, false).unwrap();
        let un = uninstall(t, root.path(), Scope::Project).unwrap();
        assert_eq!(un.action, SkillAction::Removed);
        let body = read(&path);
        assert!(body.contains("Be nice."));
        assert!(!body.contains(APPEND_BEGIN));
    }

    #[test]
    fn append_preserves_existing_file_content() {
        let t = target_by_slug("gemini").unwrap();
        let root = td();
        let path = t.dest(root.path(), Scope::Project).unwrap();
        std::fs::write(&path, "# Gemini rules\nExisting stuff.\n").unwrap();
        let rep = install(t, root.path(), Scope::Project, false, false).unwrap();
        assert_eq!(rep.action, SkillAction::Installed);
        let body = read(&path);
        assert!(body.contains("Existing stuff."));
        assert!(body.contains(APPEND_BEGIN));
    }

    #[test]
    fn whole_file_refuses_foreign_file_without_force() {
        let t = target_by_slug("cursor").unwrap();
        let root = td();
        let path = t.dest(root.path(), Scope::Project).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = "# my own cursor rule\n";
        std::fs::write(&path, original).unwrap();

        // Refused, file untouched.
        let rep = install(t, root.path(), Scope::Project, false, false).unwrap();
        assert_eq!(rep.action, SkillAction::Refused);
        assert_eq!(read(&path), original);

        // With force, replaced.
        let rep = install(t, root.path(), Scope::Project, false, true).unwrap();
        assert_eq!(rep.action, SkillAction::Updated);
        assert!(read(&path).contains(MANAGED_MARKER));
    }

    #[test]
    fn whole_file_updates_our_own_file_in_place() {
        let t = target_by_slug("claude-code").unwrap();
        let root = td();
        let path = t.dest(root.path(), Scope::Project).unwrap();
        install(t, root.path(), Scope::Project, false, false).unwrap();
        // Tamper with our managed file, keeping the marker: re-install updates it.
        let mut body = read(&path);
        body.push_str("\nstale line\n");
        std::fs::write(&path, &body).unwrap();
        let rep = install(t, root.path(), Scope::Project, false, false).unwrap();
        assert_eq!(rep.action, SkillAction::Updated);
        assert!(!read(&path).contains("stale line"));
    }

    #[test]
    fn print_writes_nothing() {
        let t = target_by_slug("claude-code").unwrap();
        let root = td();
        let rep = install(t, root.path(), Scope::Project, true, false).unwrap();
        assert_eq!(rep.action, SkillAction::Printed);
        assert!(!rep.path.exists());
        assert!(rep.content.contains("name: burpwn"));
    }

    #[test]
    fn global_scope_supported_and_unsupported() {
        // Claude Code supports global.
        let t = target_by_slug("claude-code").unwrap();
        let root = td();
        let rep = install(t, root.path(), Scope::Global, false, false).unwrap();
        assert_eq!(rep.action, SkillAction::Installed);
        assert!(rep.path.starts_with(root.path()));
        assert!(rep.path.ends_with(".claude/skills/burpwn/SKILL.md"));

        // Cursor does not: a clear error.
        let t = target_by_slug("cursor").unwrap();
        let err = install(t, root.path(), Scope::Global, false, false).unwrap_err();
        assert!(matches!(
            err,
            SkillError::ScopeUnsupported { slug: "cursor", .. }
        ));
    }

    #[test]
    fn gemini_global_goes_under_home_dotdir() {
        let t = target_by_slug("gemini").unwrap();
        let home = td();
        let rep = install(t, home.path(), Scope::Global, false, false).unwrap();
        assert!(rep.path.ends_with(".gemini/GEMINI.md"));
        assert_eq!(rep.action, SkillAction::Installed);
    }

    #[test]
    fn uninstall_leaves_foreign_whole_file_untouched() {
        let t = target_by_slug("cursor").unwrap();
        let root = td();
        let path = t.dest(root.path(), Scope::Project).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# not ours\n").unwrap();
        let un = uninstall(t, root.path(), Scope::Project).unwrap();
        assert_eq!(un.action, SkillAction::Absent);
        assert_eq!(read(&path), "# not ours\n");
    }
}
