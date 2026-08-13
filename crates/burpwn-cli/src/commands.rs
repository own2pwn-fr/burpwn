//! Command dispatch: maps the parsed [`crate::cli::Command`] tree onto the store,
//! proxy, sandbox, TLS and wrap layers, rendering either human text or the JSON
//! envelope per the global `--json` flag.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use burpwn_error::ErrorCode;
use burpwn_sandbox::{deep_probe, doctor, RootlessRuntime, SandboxRuntime};
use burpwn_store::model::{FlowFilter, Group, MatchKind, NewMatchReplaceRule, Protocol};
use burpwn_store::Store;
use burpwn_tls::CertAuthority;
use burpwn_wrap::{install, install_global, Agent, WrapConfig};

use crate::cli::*;
use crate::control::{ControlClient, ControlResponse, Edits, HeaderEdit};
use crate::debugreport;
use crate::diag::WithCode;
use crate::envelope::Envelope;
use crate::exec;
use crate::paths::{validate_session_name, Paths, DEFAULT_SESSION};
use crate::render::{palette, Cell, Column, Render, Table};
use crate::{har, replay, wrap_hook};

/// How long `exec` waits for a freshly-spawned daemon's control socket.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The single output path of every command.
///
/// There used to be two: [`Output::ok`] for "one line or one blob", and an
/// open-coded `if json { println!(envelope) } else { … }` in every command that
/// prints more than a line — thirty-one of them, each free to drift from the
/// envelope it was supposed to mirror. Everything now goes through
/// [`Output::emit`]: the JSON branch is written once, and the human branch is
/// handed the [`Render`] decided at startup, so what a terminal gets and what a
/// pipe gets are two renderings of the same values rather than two code paths.
pub struct Output {
    render: Render,
}

impl Output {
    fn new(json: bool) -> Self {
        Self {
            render: Render::detect(json),
        }
    }

    /// An output bound to an explicit renderer (tests, embedding).
    pub fn with_render(render: Render) -> Self {
        Self { render }
    }

    /// The rendering decision, for callers that build their own text.
    fn render(&self) -> &Render {
        &self.render
    }

    /// Whether stdout is reserved for the JSON envelope.
    fn is_json(&self) -> bool {
        self.render.is_json()
    }

    /// Emit a success: the envelope carrying `data` under `--json`, otherwise
    /// the text `human` builds for the active mode. An empty string prints
    /// nothing at all — that is how a listing says "no rows" to a pipe, where
    /// `(no flows)` would be a line a parser has to know about.
    fn emit(&self, data: Value, human: impl FnOnce(&Render) -> String) {
        if self.render.is_json() {
            println!("{}", Envelope::ok(data).to_json_line());
            return;
        }
        let text = human(&self.render);
        if !text.is_empty() {
            // `anstream` strips any escape that reached here without a terminal
            // behind it; the modes above are what decides the STRUCTURE.
            anstream::println!("{text}");
        }
    }

    /// Emit a success whose human form is one fixed line.
    fn ok(&self, human: impl AsRef<str>, data: Value) {
        self.emit(data, |_| human.as_ref().to_string());
    }
}

/// Render a listing, or — for a human only — the note that says it is empty.
/// A pipe gets nothing, which is what "no rows" looks like to `wc -l`.
fn listing(r: &Render, table: &Table, empty: &str) -> String {
    if table.is_empty() {
        return r.aside(empty).unwrap_or_default();
    }
    table.render(r)
}

/// Dispatch entry point. Returns the process exit code.
pub async fn dispatch(cli: Cli, paths: &Paths) -> Result<i32> {
    let out = Output::new(cli.json);
    match cli.command {
        Command::Doctor(args) => cmd_doctor(&out, paths, args),
        Command::Debug { action } => cmd_debug(&out, paths, action),
        Command::Init(args) => cmd_init(&out, args),
        Command::WrapHook { agent } => cmd_wrap_hook(paths, agent),
        Command::Proxy(args) => cmd_proxy(paths, args).await,
        Command::Ca { action } => cmd_ca(&out, paths, action),
        Command::Session { action } => cmd_session(&out, paths, action).await,
        Command::Exec(args) => cmd_exec(cli.json, paths, args, None).await,
        Command::Req { action } => cmd_req(&out, paths, action).await,
        Command::Intercept { action } => cmd_intercept(&out, paths, action).await,
        Command::MatchReplace { action } => cmd_match_replace(&out, paths, action).await,
        Command::Hook { action } => cmd_hook(&out, paths, action).await,
        Command::Workspace { action } => cmd_workspace(&out, paths, action).await,
        Command::Tag { action } => cmd_tag(&out, paths, action).await,
        Command::Note { action } => cmd_note(&out, paths, action).await,
        Command::Group { action } => cmd_group(&out, paths, action).await,
        Command::Export { action } => cmd_export(&out, paths, action),
        Command::Fuzz { action } => cmd_fuzz(&out, paths, action).await,
        Command::Compare(args) => cmd_compare(&out, paths, args),
        Command::Encode { scheme, value } => cmd_encode(&out, &scheme, &value),
        Command::Decode { scheme, value } => cmd_decode(&out, &scheme, &value),
        Command::Skill { action } => cmd_skill(&out, action),
        Command::Mcp { action } => cmd_mcp(&out, action),
    }
}

// --- skill (portable skill installer) --------------------------------------

fn cmd_skill(out: &Output, action: SkillAction) -> Result<i32> {
    use crate::skill::{self, Scope};
    match action {
        SkillAction::List => {
            let rows: Vec<Value> = skill::targets()
                .iter()
                .map(|t| {
                    json!({
                        "agent": t.slug,
                        "name": t.name,
                        "format": t.format.label(),
                        "project_path": t.project_rel,
                        "global_path": t.global_rel,
                        "note": t.note,
                    })
                })
                .collect();
            out.emit(json!({ "targets": rows }), |r| {
                let mut t = Table::new(vec![
                    Column::left("agent"),
                    Column::left("format"),
                    Column::left("project"),
                    Column::left("global"),
                    Column::left("note").truncatable(),
                ]);
                for target in skill::targets() {
                    t.row(vec![
                        Cell::styled(target.slug, palette::IDENT),
                        Cell::new(target.format.label()),
                        Cell::new(target.project_rel),
                        Cell::new(target.global_rel.unwrap_or("")),
                        Cell::new(target.note),
                    ]);
                }
                t.render(r)
            });
            Ok(0)
        }
        SkillAction::Install(args) => cmd_skill_install(out, args),
        SkillAction::Uninstall(args) => {
            let scope = if args.global {
                Scope::Global
            } else {
                Scope::Project
            };
            let root = scope_root(scope)?;
            let target = skill::target_by_slug(&args.agent).ok_or_else(|| {
                crate::coded!(
                    ErrorCode::AgentUnknown,
                    "unknown framework: {:?} (try `burpwn skill list`)",
                    args.agent
                )
            })?;
            let rep = skill::uninstall(target, &root, scope).map_err(anyhow::Error::new)?;
            out.ok(
                format!(
                    "{}: {} ({})",
                    rep.slug,
                    rep.action.as_str(),
                    rep.path.display()
                ),
                json!({ "removed": [{
                    "agent": rep.slug,
                    "path": rep.path,
                    "action": rep.action.as_str(),
                }] }),
            );
            Ok(0)
        }
    }
}

fn cmd_skill_install(out: &Output, args: SkillInstallArgs) -> Result<i32> {
    use crate::skill::{self, Scope};

    let scope = if args.global {
        Scope::Global
    } else {
        Scope::Project
    };

    // Resolve the set of targets: --all, or a single --agent.
    let selected: Vec<&'static skill::SkillTarget> = if args.all {
        skill::targets().iter().collect()
    } else {
        let slug = args.agent.as_deref().ok_or_else(|| {
            crate::coded!(
                ErrorCode::InputMissingSelection,
                "pass --agent <slug> or --all (see `burpwn skill list`)"
            )
        })?;
        let t = skill::target_by_slug(slug).ok_or_else(|| {
            crate::coded!(
                ErrorCode::AgentUnknown,
                "unknown framework: {slug:?} (try `burpwn skill list`)"
            )
        })?;
        vec![t]
    };

    let root = scope_root(scope)?;
    let mut reports = Vec::new();
    for target in selected {
        // With --all + --global, skip frameworks that don't support global
        // rather than erroring the whole run; a single explicit --agent surfaces
        // the error.
        match skill::install(target, &root, scope, args.print, args.force) {
            Ok(rep) => {
                if args.print {
                    // Print the resolved path + content; write nothing.
                    println!("# {} -> {}", rep.slug, rep.path.display());
                    println!("{}", rep.content);
                }
                reports.push(json!({
                    "agent": rep.slug,
                    "path": rep.path,
                    "action": rep.action.as_str(),
                }));
            }
            Err(e @ skill::SkillError::ScopeUnsupported { .. }) if args.all => {
                reports.push(json!({
                    "agent": target.slug,
                    "path": Value::Null,
                    "action": "Skipped",
                    "reason": e.to_string(),
                }));
            }
            Err(e) => return Err(anyhow::Error::new(e)),
        }
    }

    // A refusal is a legitimate per-target OUTCOME under `--all` (some targets
    // install, some are already owned by someone else). But when the user named
    // exactly one target, "refused" means the thing they asked for did not
    // happen — reporting that as success, with exit 0, hides it.
    if !args.all {
        if let Some(rep) = reports.first() {
            if rep["action"] == json!(skill::SkillAction::Refused.as_str()) {
                crate::fail!(
                    ErrorCode::AgentRefusedOverwrite,
                    "{} already exists and was not written by burpwn",
                    rep["path"].as_str().unwrap_or("the target file")
                );
            }
        }
    }

    let human = format!("processed {} skill target(s)", reports.len());
    out.ok(human, json!({ "installed": reports }));
    Ok(0)
}

/// The root directory a scope resolves against: cwd for project, HOME for global.
fn scope_root(scope: crate::skill::Scope) -> Result<std::path::PathBuf> {
    match scope {
        crate::skill::Scope::Project => {
            std::env::current_dir().context("resolving current directory")
        }
        crate::skill::Scope::Global => dirs_home(),
    }
}

// --- mcp register (complementary MCP host registration) --------------------

fn cmd_mcp(out: &Output, action: McpAction) -> Result<i32> {
    match action {
        McpAction::Register(args) => cmd_mcp_register(out, args),
    }
}

fn cmd_mcp_register(out: &Output, args: McpRegisterArgs) -> Result<i32> {
    use crate::mcpreg;

    if args.list {
        let rows: Vec<Value> = mcpreg::hosts()
            .iter()
            .map(|h| {
                json!({
                    "agent": h.slug,
                    "name": h.name,
                    "config": h.config_rel,
                    "format": match h.kind {
                        mcpreg::McpKind::Toml => "toml",
                        mcpreg::McpKind::Json => "json",
                    },
                })
            })
            .collect();
        out.emit(json!({ "hosts": rows }), |r| {
            let mut t = Table::new(vec![
                Column::left("agent"),
                Column::left("format"),
                Column::left("config").truncatable(),
            ]);
            for h in mcpreg::hosts() {
                t.row(vec![
                    Cell::styled(h.slug, palette::IDENT),
                    Cell::new(match h.kind {
                        mcpreg::McpKind::Toml => "toml",
                        mcpreg::McpKind::Json => "json",
                    }),
                    Cell::new(h.config_rel),
                ]);
            }
            let mut text = t.render(r);
            if let Some(l) = r.aside("paths are relative to HOME") {
                text.push('\n');
                text.push('\n');
                text.push_str(&l);
            }
            text
        });
        return Ok(0);
    }

    let slug = args.agent.as_deref().ok_or_else(|| {
        crate::coded!(
            ErrorCode::InputMissingSelection,
            "pass --agent <host> or --list (see `mcp register --list`)"
        )
    })?;

    // Frameworks with no stdio MCP host: clear message, not a guessed path.
    if let Some(name) = mcpreg::unsupported_slug(slug) {
        crate::fail!(
            ErrorCode::AgentUnknown,
            "{name} has no stdio MCP host to register into; see its docs"
        );
    }

    let host = mcpreg::host_by_slug(slug).ok_or_else(|| {
        crate::coded!(
            ErrorCode::AgentUnknown,
            "unknown MCP host: {slug:?} (try `mcp register --list`)"
        )
    })?;

    // MCP host configs are user-level; `--global` is accepted for symmetry.
    let _ = args.global;
    let home = dirs_home()?;
    let rep = mcpreg::register(host, &home, args.print).map_err(anyhow::Error::new)?;

    if args.print {
        println!("# {} -> {}", rep.slug, rep.path.display());
        print!("{}", rep.content);
        return Ok(0);
    }

    // `mcp register` always targets exactly one host, so a refusal — the config
    // file is not the shape burpwn can edit — is a failure, not an outcome.
    // Reporting it as success left the user believing the tools were registered.
    if rep.action == mcpreg::McpAction::Refused {
        crate::fail!(
            ErrorCode::AgentConfigShape,
            "{} is not a config burpwn can edit; it was left intact",
            rep.path.display()
        );
    }

    out.ok(
        format!(
            "{}: {} ({})",
            rep.slug,
            rep.action.as_str(),
            rep.path.display()
        ),
        json!({ "registered": [{
            "agent": rep.slug,
            "path": rep.path,
            "action": rep.action.as_str(),
        }] }),
    );
    Ok(0)
}

// --- doctor ---------------------------------------------------------------

fn cmd_doctor(out: &Output, paths: &Paths, args: DoctorArgs) -> Result<i32> {
    let pf = doctor();
    let ca_present = paths.ca_pem().exists();
    let installed_ok = pf.is_ok() && ca_present;

    // The LIVE probe is what actually answers "can this host capture traffic?".
    // It needs the prerequisites to exist first, so it is skipped when the
    // shallow checks already failed (there would be nothing to probe with).
    let probe = if args.quick || !pf.is_ok() {
        None
    } else {
        Some(deep_probe())
    };
    let ok = installed_ok && probe.as_ref().is_none_or(|p| p.is_ok());

    let data = json!({
        "userns_enabled": pf.userns_enabled,
        "subuid_present": pf.subuid_present,
        "bwrap_present": pf.bwrap_present,
        "nft_present": pf.nft_present,
        "ip_present": pf.ip_present,
        "ca_present": ca_present,
        "ready": ok,
        "missing": pf.missing_summary(),
        "wsl": probe.as_ref().map(|p| p.wsl),
        "sandbox_probe": probe.as_ref().map(|p| json!({
            "ok": p.is_ok(),
            "summary": p.summary(),
            "steps": p.steps,
            "remediation": p.remediation(),
        })),
    });

    out.emit(data, |r| {
        doctor_report(r, &pf, ca_present, probe.as_ref(), args.quick, ok)
    });
    Ok(if ok { 0 } else { 1 })
}

/// The doctor report as text: one `check  verdict  detail` row per
/// prerequisite, and — for a human only — the verdict and what to do about it.
///
/// Pure, so both renderings are testable without a terminal: piped, this is a
/// grep-able `nftables\tNO\tnot on PATH`; on a TTY it is the aligned block with
/// the yes/NO coloured.
fn doctor_report(
    r: &Render,
    pf: &burpwn_sandbox::Preflight,
    ca_present: bool,
    probe: Option<&burpwn_sandbox::ProbeReport>,
    quick: bool,
    ready: bool,
) -> String {
    let mut t = crate::render::kv_table();
    let mut check = |name: &str, ok: bool, detail: &str| {
        t.row(vec![
            Cell::new(name),
            Cell::styled(if ok { "yes" } else { "NO" }, palette::yes_no(ok)),
            Cell::new(detail),
        ]);
    };
    check("unprivileged userns", pf.userns_enabled, "");
    check("subuid entry", pf.subuid_present, "informational");
    check("bubblewrap", pf.bwrap_present, "bwrap");
    check("nftables", pf.nft_present, "nft");
    check("iproute2", pf.ip_present, "ip");
    check(
        "CA",
        ca_present,
        if ca_present {
            ""
        } else {
            "run `burpwn ca init`"
        },
    );
    match probe {
        Some(p) => {
            for step in &p.steps {
                let (mark, style) = if step.ok {
                    ("ok", palette::GOOD)
                } else if step.required {
                    ("FAIL", palette::BAD)
                } else {
                    ("degraded", palette::WARN)
                };
                t.row(vec![
                    Cell::new(format!("probe {}", step.name)),
                    Cell::styled(mark, style),
                    Cell::new(step.detail.trim().replace('\n', " ")),
                ]);
            }
            if p.wsl {
                t.row(vec![
                    Cell::new("host"),
                    Cell::styled("WSL", palette::WARN),
                    Cell::new(""),
                ]);
            }
        }
        None if quick => {
            t.row(vec![
                Cell::new("live sandbox probe"),
                Cell::styled("skipped", palette::MUTED),
                Cell::new("--quick"),
            ]);
        }
        None => {}
    }

    let mut text = t.render(r);
    // The verdict repeats what the rows already say and what the exit code
    // already carries, so it is a courtesy to a human, not output.
    if ready {
        if let Some(l) = r.aside(r.paint("ready", palette::GOOD)) {
            text.push_str("\n\n");
            text.push_str(&l);
        }
        return text;
    }
    let mut missing = pf.missing_summary();
    if !ca_present {
        if !missing.is_empty() {
            missing.push_str(", ");
        }
        missing.push_str("CA");
    }
    if let Some(p) = probe {
        if !p.is_ok() {
            if !missing.is_empty() {
                missing.push_str(", ");
            }
            missing.push_str(&p.summary());
        }
    }
    if let Some(l) = r.aside(r.paint(&format!("NOT ready — {missing}"), palette::BAD)) {
        text.push_str("\n\n");
        text.push_str(&l);
        for line in probe.map(|p| p.remediation()).unwrap_or_default() {
            text.push_str("\n    \u{2192} ");
            text.push_str(&line);
        }
    }
    text
}

// --- debug reports ---------------------------------------------------------

fn cmd_debug(out: &Output, paths: &Paths, action: DebugAction) -> Result<i32> {
    match action {
        DebugAction::Bundle(args) => cmd_debug_bundle(out, paths, args),
        DebugAction::List => cmd_debug_list(out, paths),
        DebugAction::Show { path } => cmd_debug_show(out, paths, path),
    }
}

fn cmd_debug_bundle(out: &Output, paths: &Paths, args: DebugBundleArgs) -> Result<i32> {
    let doc = debugreport::build(paths, None, !args.no_probe);
    let body = serde_json::to_string_pretty(&doc)?;

    // `-o -` is the "give it to me on stdout so I can pipe it" form; it must not
    // also print a human line, or the JSON is no longer pipeable.
    if args.out.as_deref() == Some("-") {
        println!("{body}");
        return Ok(0);
    }

    let path = match args.out {
        Some(p) => PathBuf::from(p),
        None => {
            let dir = paths.debug_dir();
            std::fs::create_dir_all(&dir).with_code_msg(
                ErrorCode::InputUnsafePath,
                format!("creating {}", dir.display()),
            )?;
            dir.join(format!("{}-bundle.json", now_millis()))
        }
    };
    std::fs::write(&path, &body).with_code_msg(
        ErrorCode::InputUnsafePath,
        format!("writing {}", path.display()),
    )?;

    out.emit(
        json!({"path": path.display().to_string(), "bytes": body.len()}),
        |r| {
            // A pipe gets the path and nothing else: it is what the next
            // command in the chain needs, and the reassurance about redaction
            // is for the person deciding whether to attach the file.
            let Some(l) = r.aside(format!("debug report written to {}", path.display())) else {
                return path.display().to_string();
            };
            format!(
                "{l}\n{}",
                r.aside(
                    "it contains no credentials (env values and token-shaped strings are redacted)"
                )
                .unwrap_or_default()
            )
        },
    );
    Ok(0)
}

fn cmd_debug_list(out: &Output, paths: &Paths) -> Result<i32> {
    let dir = paths.debug_dir();
    let reports = debugreport::recent(&dir, 100);
    let items: Vec<Value> = reports
        .iter()
        .map(|p| json!({"path": p.display().to_string()}))
        .collect();
    out.emit(json!({"reports": items}), |r| {
        let mut t = Table::new(vec![Column::left("report").truncatable()]);
        for path in &reports {
            t.row(vec![Cell::new(path.display().to_string())]);
        }
        if !t.is_empty() {
            t.footer(format!(
                "{} report(s) in {}, newest first",
                t.len(),
                dir.display()
            ));
        }
        listing(
            r,
            &t,
            &format!(
                "no debug reports in {} (nothing has failed yet)",
                dir.display()
            ),
        )
    });
    Ok(0)
}

fn cmd_debug_show(out: &Output, paths: &Paths, path: Option<String>) -> Result<i32> {
    let path = match path {
        Some(p) => PathBuf::from(p),
        None => match debugreport::recent(&paths.debug_dir(), 1)
            .into_iter()
            .next()
        {
            Some(p) => p,
            None => crate::fail!(
                ErrorCode::InputNothingToDo,
                "no debug report to show — nothing has failed yet, or run `burpwn debug bundle`"
            ),
        },
    };
    let body = std::fs::read_to_string(&path).with_code_msg(
        ErrorCode::InputFileUnreadable,
        format!("reading {}", path.display()),
    )?;
    // Re-emit as data so `--json` stays one envelope per invocation; the
    // human form is the file itself, verbatim, in every other mode.
    let doc: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    out.emit(doc, |_| body.clone());
    Ok(0)
}

// --- init / wrap-hook ------------------------------------------------------

fn cmd_init(out: &Output, args: InitArgs) -> Result<i32> {
    let home = dirs_home()?;

    // `--check` verifies rather than installs: drive a synthetic network command
    // through each agent's wrap-hook path and report PASS/FAIL/ADVISORY.
    if args.check {
        return cmd_init_check(out, &home, args.agent.as_deref());
    }

    let cfg = WrapConfig::load(&WrapConfig::default_path().unwrap_or_default()).unwrap_or_default();
    let mut reports = Vec::new();

    if let Some(slug) = &args.agent {
        let agent = Agent::from_slug(slug).ok_or_else(|| {
            crate::coded!(
                ErrorCode::AgentUnknown,
                "unknown agent: {slug:?} (try claude, cursor, gemini, …)"
            )
        })?;
        let r = install(agent, &home, &cfg.exclude_commands).map_err(anyhow::Error::new)?;
        reports.push(
            json!({ "agent": agent.slug(), "path": r.path, "action": format!("{:?}", r.action) }),
        );
    } else if !args.global {
        // No agent and not global: install for every detected agent.
        let detected = burpwn_wrap::detect_present(&home);
        if detected.is_empty() {
            // Nothing detected: fall back to the global shell hook.
            install_global_hook(&home, &cfg, &mut reports)?;
        }
        for agent in detected {
            let r = install(agent, &home, &cfg.exclude_commands).map_err(anyhow::Error::new)?;
            reports.push(json!({ "agent": agent.slug(), "path": r.path, "action": format!("{:?}", r.action) }));
        }
    }

    if args.global {
        install_global_hook(&home, &cfg, &mut reports)?;
    }

    let human = format!("installed {} hook(s)", reports.len());
    out.ok(human, json!({ "installed": reports }));
    Ok(0)
}

/// `init --check`: verify each target agent's hook actually rewrites a synthetic
/// network command through `burpwn exec`. Exits non-zero if any rewrite-capable
/// agent FAILs.
fn cmd_init_check(out: &Output, home: &std::path::Path, agent: Option<&str>) -> Result<i32> {
    use crate::initcheck::{any_failure, check_agents, Verdict};

    // Target agents: an explicit --agent, else the detected/installed ones, else
    // ALL known agents (so the check is still informative on a clean box).
    let agents = match agent {
        Some(slug) => vec![Agent::from_slug(slug).ok_or_else(|| {
            crate::coded!(
                ErrorCode::AgentUnknown,
                "unknown agent: {slug:?} (try claude, cursor, gemini, …)"
            )
        })?],
        None => {
            let detected = burpwn_wrap::detect_present(home);
            if detected.is_empty() {
                Agent::all().to_vec()
            } else {
                detected
            }
        }
    };

    let reports = check_agents(&agents);
    let failed = any_failure(&reports);

    let data: Vec<Value> = reports
        .iter()
        .map(|r| {
            json!({
                "agent": r.agent,
                "verdict": r.verdict.as_str(),
                "detail": r.detail,
                "rewritten": r.rewritten,
            })
        })
        .collect();

    out.emit(json!({ "checks": data, "ok": !failed }), |r| {
        let mut t = Table::new(vec![
            Column::left("verdict"),
            Column::left("agent"),
            Column::left("detail").truncatable(),
        ]);
        for rep in &reports {
            let (mark, style) = match rep.verdict {
                Verdict::Pass => ("PASS", palette::GOOD),
                Verdict::Fail => ("FAIL", palette::BAD),
                Verdict::Advisory => ("ADVISORY", palette::WARN),
            };
            t.row(vec![
                Cell::styled(mark, style),
                Cell::styled(rep.agent.clone(), palette::IDENT),
                Cell::new(rep.detail.clone()),
            ]);
        }
        let mut text = t.render(r);
        let verdict = if failed {
            r.paint(
                "FAIL: at least one agent does not rewrite commands through `burpwn exec`",
                palette::BAD,
            )
        } else {
            r.paint("ok", palette::GOOD)
        };
        if let Some(l) = r.aside(verdict) {
            text.push_str("\n\n");
            text.push_str(&l);
        }
        text
    });
    Ok(if failed { 1 } else { 0 })
}

fn install_global_hook(
    home: &std::path::Path,
    cfg: &WrapConfig,
    reports: &mut Vec<Value>,
) -> Result<()> {
    // Install into the user's interactive shell rc (best-effort: bash + zsh).
    let mut any = false;
    for rc in [".bashrc", ".zshrc"] {
        let rc_path = home.join(rc);
        // Only touch an rc that already exists (don't create shells the user lacks).
        if rc_path.exists() {
            let changed =
                install_global(&rc_path, &cfg.exclude_commands).map_err(anyhow::Error::new)?;
            reports.push(json!({ "agent": "global-shell", "path": rc_path, "action": if changed { "Installed" } else { "AlreadyPresent" } }));
            any = true;
        }
    }
    if !any {
        // No rc present: install into ~/.bashrc so the hook exists somewhere.
        let rc_path = home.join(".bashrc");
        let changed =
            install_global(&rc_path, &cfg.exclude_commands).map_err(anyhow::Error::new)?;
        reports.push(json!({ "agent": "global-shell", "path": rc_path, "action": if changed { "Installed" } else { "AlreadyPresent" } }));
    }
    Ok(())
}

/// The hidden stdin filter. Reads tool-input JSON on stdin, rewrites, emits the
/// (possibly-rewritten) JSON on stdout. Always exits 0 (never breaks the agent).
fn cmd_wrap_hook(_paths: &Paths, agent: Option<String>) -> Result<i32> {
    let cfg = WrapConfig::default_path()
        .and_then(|p| WrapConfig::load(&p).ok())
        .unwrap_or_default();
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        // Can't read stdin: emit nothing, succeed (pass-through semantics).
        return Ok(0);
    }
    let output = wrap_hook::process_for(agent.as_deref(), &input, &cfg);
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(output.as_bytes());
    let _ = stdout.flush();
    Ok(0)
}

// --- proxy (daemon) --------------------------------------------------------

async fn cmd_proxy(paths: &Paths, args: ProxyArgs) -> Result<i32> {
    let session = args.session.unwrap_or_else(|| paths.active_session());
    // Reject traversal / absolute session names before any path is built from
    // them (Bug #6): otherwise `--session ../../foo` would open dirs+DB outside
    // `…/sessions/`.
    validate_session_name(&session)?;
    crate::daemon::run_daemon(paths, &session).await?;
    Ok(0)
}

// --- ca --------------------------------------------------------------------

fn cmd_ca(out: &Output, paths: &Paths, action: CaAction) -> Result<i32> {
    paths.ensure_base()?;
    match action {
        CaAction::Init => {
            let ca = CertAuthority::load_or_generate(paths.ca_dir())
                .map_err(|e| crate::coded!(ErrorCode::TlsCaInit, "CA init failed: {e}"))?;
            let _ = ca; // generated/loaded as a side effect.
            out.ok(
                format!("CA ready at {}", paths.ca_pem().display()),
                json!({ "ca_pem": paths.ca_pem() }),
            );
            Ok(0)
        }
        CaAction::Export => {
            let ca = CertAuthority::load_or_generate(paths.ca_dir())
                .map_err(|e| crate::coded!(ErrorCode::TlsCaLoad, "CA load failed: {e}"))?;
            let pem = ca.cert_pem();
            // The PEM is the payload, not a rendering of it: no decoration in
            // any mode, and no trailing newline added to a file format.
            if out.is_json() {
                println!("{}", Envelope::ok(json!({ "pem": pem })).to_json_line());
            } else {
                print!("{pem}");
            }
            Ok(0)
        }
    }
}

// --- session ---------------------------------------------------------------

async fn cmd_session(out: &Output, paths: &Paths, action: SessionAction) -> Result<i32> {
    match action {
        SessionAction::New { name } => {
            let name = name.unwrap_or_else(|| DEFAULT_SESSION.to_string());
            validate_session_name(&name)?;
            paths.ensure_session_dir(&name)?;
            // Make it the active session if there is no current pointer yet.
            if !paths.current_pointer().exists() {
                paths.set_active_session(&name)?;
            }
            out.ok(format!("created session {name}"), json!({ "name": name }));
            Ok(0)
        }
        SessionAction::List => {
            let active = paths.active_session();
            let names = paths.list_sessions();
            out.emit(json!({ "active": active, "sessions": names }), |r| {
                let mut t = Table::new(vec![Column::left("session"), Column::left("state")]);
                for n in &names {
                    let is_active = *n == active;
                    t.row(vec![
                        Cell::styled(n.clone(), palette::IDENT),
                        Cell::styled(if is_active { "active" } else { "" }, palette::GOOD),
                    ]);
                }
                listing(r, &t, "(no sessions)")
            });
            Ok(0)
        }
        SessionAction::Use { name } => {
            validate_session_name(&name)?;
            if !paths.session_exists(&name) {
                crate::fail!(ErrorCode::SessionNotFound, "no such session: {name}");
            }
            paths.set_active_session(&name)?;
            out.ok(
                format!("active session is now {name}"),
                json!({ "active": name }),
            );
            Ok(0)
        }
        SessionAction::Rm { name } => {
            validate_session_name(&name)?;
            if !paths.session_exists(&name) {
                crate::fail!(ErrorCode::SessionNotFound, "no such session: {name}");
            }
            std::fs::remove_dir_all(paths.session_dir(&name))
                .with_context(|| "removing session dir")?;
            let _ = std::fs::remove_dir_all(paths.run_dir(&name));
            // If it was active, reset the pointer to default.
            if paths.active_session() == name {
                let _ = std::fs::remove_file(paths.current_pointer());
            }
            out.ok(
                format!("removed session {name}"),
                json!({ "removed": name }),
            );
            Ok(0)
        }
        SessionAction::Import {
            file,
            as_name,
            use_session,
        } => cmd_session_import(out, paths, file, as_name, use_session),
        SessionAction::Stats { session } => cmd_session_stats(out, paths, session),
        SessionAction::Auth { action } => cmd_session_auth(out, paths, action).await,
    }
}

/// `session import <file>`: unpack a bundle into a brand-new session.
///
/// The summary is not decoration: the receiving side needs to know what landed
/// (so an empty or truncated hand-off is obvious immediately) and whether the
/// file it was just sent is carrying live credentials.
fn cmd_session_import(
    out: &Output,
    paths: &Paths,
    file: String,
    as_name: Option<String>,
    use_session: bool,
) -> Result<i32> {
    let outcome = crate::bundle::import_session(
        paths,
        &crate::bundle::ImportRequest {
            file: PathBuf::from(&file),
            as_name,
            use_session,
        },
    )?;
    let c = &outcome.counts;
    let m = &outcome.manifest;

    let data = json!({
                "session": outcome.session,
                "from": {
                    "session": m.session,
                    "burpwn_version": m.burpwn_version,
                    "schema_version": m.schema_version,
                    "exported_at": m.exported_at,
                    "ca_sha256": m.ca_sha256,
                },
                "redacted": m.redacted,
                "migrated_from": outcome.migrated_from,
                "active": outcome.activated,
                "flows": c.flows,
                "workspaces": c.workspaces,
                "groups": c.groups,
                "tags": c.tags,
                "notes": c.notes,
                "attacks": c.attacks,
                "warning": (!m.redacted).then_some(crate::bundle::RAW_WARNING),
    });

    out.emit(data, |r| {
        let mut text = format!(
            "imported session {} from {file} ({} flows, {} workspaces, {} groups, \
             {} tags, {} notes, {} attacks)",
            outcome.session, c.flows, c.workspaces, c.groups, c.tags, c.notes, c.attacks
        );
        if let Some(l) = r.aside(format!(
            "exported from '{}' by burpwn {}",
            m.session, m.burpwn_version
        )) {
            text.push('\n');
            text.push_str(&l);
        }
        if let Some(from) = outcome.migrated_from {
            if let Some(l) = r.aside(format!(
                "schema v{from} migrated up to v{}",
                burpwn_store::schema::SCHEMA_VERSION
            )) {
                text.push('\n');
                text.push_str(&l);
            }
        }
        let next = if outcome.activated {
            "it is now the active session".to_string()
        } else {
            format!("`burpwn session use {}` to switch to it", outcome.session)
        };
        if let Some(l) = r.aside(next) {
            text.push('\n');
            text.push_str(&l);
        }
        text
    });
    // The credential warning belongs on stderr in every non-JSON mode: it is
    // not part of the result and must never reach a parser reading stdout.
    if !m.redacted && !out.is_json() {
        eprintln!("⚠ {}", crate::bundle::RAW_WARNING);
    }
    Ok(0)
}

// --- session stats (capture-completeness telemetry) ------------------------

fn cmd_session_stats(out: &Output, paths: &Paths, session: Option<String>) -> Result<i32> {
    let session = session.unwrap_or_else(|| paths.active_session());
    validate_session_name(&session)?;
    let store = open_store(paths, &session)?;
    let reader = store.reader();
    let stats = reader.exec_stats()?;
    // The execs that escaped capture (network-facing, zero flows) — the actionable
    // list an operator wants to see.
    let escaped: Vec<Value> = reader
        .exec_records()?
        .into_iter()
        .filter(|e| e.network_facing && e.flow_count == 0)
        .map(|e| json!({ "exec_id": e.exec_id, "cmd": e.cmd }))
        .collect();

    out.emit(
        json!({
            "session": session,
            "total_execs": stats.total_execs,
            "total_flows": stats.total_flows,
            "network_execs": stats.network_execs,
            "network_zero_flow_execs": stats.network_zero_flow_execs,
            "escaped_execs": escaped,
        }),
        |r| {
            let zero = stats.network_zero_flow_execs;
            let mut t = crate::render::kv_pair();
            let mut row = |k: &str, v: String, style| {
                t.row(vec![Cell::new(k), Cell::styled(v, style)]);
            };
            row(
                "execs recorded",
                stats.total_execs.to_string(),
                palette::LABEL,
            );
            row(
                "flows captured",
                stats.total_flows.to_string(),
                palette::LABEL,
            );
            row(
                "network-facing execs",
                stats.network_execs.to_string(),
                palette::LABEL,
            );
            // The one number that means something is wrong, aligned like the
            // rest of them: it used to be the one line that was NOT.
            row(
                "network execs, zero captures",
                zero.to_string(),
                if zero > 0 {
                    palette::BAD
                } else {
                    palette::GOOD
                },
            );
            for e in &escaped {
                t.row(vec![
                    Cell::styled("escaped capture", palette::WARN),
                    Cell::new(e["cmd"].as_str().unwrap_or("")),
                ]);
            }
            let mut text = t.render(r);
            if !escaped.is_empty() {
                if let Some(l) = r.aside("run `burpwn init --check` to verify the agent hook") {
                    text.push_str("\n\n");
                    text.push_str(&l);
                }
            }
            text
        },
    );
    Ok(0)
}

// --- session auth ----------------------------------------------------------

async fn cmd_session_auth(out: &Output, paths: &Paths, action: SessionAuthAction) -> Result<i32> {
    match action {
        SessionAuthAction::Set(args) => {
            let session = args.session.unwrap_or_else(|| paths.active_session());
            validate_session_name(&session)?;
            paths.ensure_session_dir(&session)?;
            let store = open_store(paths, &session)?;
            let host = args.host.clone().unwrap_or_default();
            let id = crate::auth::auth_set(&store, &host, &args.login, &args.extract, &args.header)
                .await?;
            out.ok(
                format!(
                    "auth profile {id} set for {}",
                    if host.is_empty() { "all hosts" } else { &host }
                ),
                json!({ "id": id, "host": host }),
            );
            Ok(0)
        }
        SessionAuthAction::Status { session } => {
            let session = session.unwrap_or_else(|| paths.active_session());
            validate_session_name(&session)?;
            let store = open_store(paths, &session)?;
            let profiles = store.reader().auth_profiles()?;
            let view: Vec<Value> = profiles
                .iter()
                .map(|p| {
                    json!({
                        "id": p.id,
                        "host": p.host,
                        "login_cmd": p.login_cmd,
                        "header_template": p.header_template,
                        "token_set": p.token.is_some(),
                        "token": p.token.as_deref().map(crate::auth::mask_token),
                        "rule_id": p.rule_id,
                    })
                })
                .collect();
            out.emit(json!({ "profiles": view }), |r| {
                let mut t = Table::new(vec![
                    Column::right("id"),
                    Column::left("host"),
                    Column::left("header").truncatable(),
                    Column::left("token"),
                ]);
                for p in &profiles {
                    let scope = if p.host.is_empty() { "*" } else { &p.host };
                    let (tok, style) = match &p.token {
                        Some(t) => (crate::auth::mask_token(t), palette::GOOD),
                        None => ("none".to_string(), palette::MUTED),
                    };
                    t.row(vec![
                        Cell::new(p.id.to_string()),
                        Cell::new(scope),
                        Cell::new(p.header_template.clone()),
                        Cell::styled(tok, style),
                    ]);
                }
                listing(r, &t, "(no auth profiles)")
            });
            Ok(0)
        }
        SessionAuthAction::Refresh { host, session } => {
            cmd_session_auth_refresh(out, paths, host, session).await
        }
    }
}

/// `session auth refresh`: for each matching profile, run its login command in
/// the sandbox, extract a fresh token, and (re)install its injection rule.
async fn cmd_session_auth_refresh(
    out: &Output,
    paths: &Paths,
    host: Option<String>,
    session: Option<String>,
) -> Result<i32> {
    use crate::auth::{apply_refresh, extract_token, run_login, HeaderTemplate};

    let session = session.unwrap_or_else(|| paths.active_session());
    validate_session_name(&session)?;
    paths.ensure_session_dir(&session)?;
    let store = open_store(paths, &session)?;

    // Select the profiles to refresh: an exact-host match, or all profiles.
    let all = store.reader().auth_profiles()?;
    let targets: Vec<_> = match &host {
        Some(h) => all.into_iter().filter(|p| &p.host == h).collect(),
        None => all,
    };
    if targets.is_empty() {
        crate::fail!(
            ErrorCode::InputNothingToDo,
            "no matching auth profile (set one with `session auth set`)"
        );
    }

    // The login command routes through the session's proxy, so ensure it is up.
    ensure_daemon(paths, &session).await?;

    let mut results = Vec::new();
    for profile in &targets {
        let template = HeaderTemplate::parse(&profile.header_template)?;
        let output = run_login(paths, &session, &profile.login_cmd, None).await?;
        let token = extract_token(&profile.extract_regex, &output)?;
        let rule_id = apply_refresh(
            &store,
            &profile.host,
            &template,
            &token,
            profile.rule_id,
            now_millis(),
        )
        .await?;
        results.push(json!({
            "host": profile.host,
            "rule_id": rule_id,
            "token": crate::auth::mask_token(&token),
        }));
    }

    out.emit(json!({ "refreshed": results }), |r| {
        let mut t = Table::new(vec![
            Column::left("host"),
            Column::right("rule"),
            Column::left("token"),
        ]);
        for res in &results {
            let host = res["host"].as_str().unwrap_or("");
            t.row(vec![
                Cell::new(if host.is_empty() { "*" } else { host }),
                Cell::new(res["rule_id"].as_i64().unwrap_or(0).to_string()),
                Cell::styled(res["token"].as_str().unwrap_or(""), palette::GOOD),
            ]);
        }
        if !t.is_empty() {
            t.footer(format!("refreshed {} profile(s)", t.len()));
        }
        listing(r, &t, "(nothing to refresh)")
    });
    Ok(0)
}

// --- exec ------------------------------------------------------------------

/// Run `exec`. `runtime_override` lets tests inject a runtime; production uses
/// the real [`RootlessRuntime`] gated on `doctor()`.
pub async fn cmd_exec(
    json: bool,
    paths: &Paths,
    args: ExecArgs,
    runtime_override: Option<Arc<dyn SandboxRuntime>>,
) -> Result<i32> {
    let session = args.session.unwrap_or_else(|| paths.active_session());
    // Reject traversal / absolute session names before any path is built from
    // them (Bug #6): otherwise `--session ../../foo` would create/open dirs+DB
    // (and runtime dirs) outside `…/sessions/`.
    validate_session_name(&session)?;
    paths.ensure_base()?;
    paths.ensure_session_dir(&session)?;

    // Ensure the CA exists (the sandbox needs to bind it in).
    CertAuthority::load_or_generate(paths.ca_dir())
        .map_err(|e| crate::coded!(ErrorCode::TlsCaLoad, "CA: {e}"))?;

    // Resolve the --workspace NAME to an id (creating it if absent); omitted ⇒
    // the default workspace. Done before the run so attribution can target it.
    let workspace_id =
        exec::resolve_workspace_id(paths, &session, args.workspace.as_deref()).await?;

    let runtime: Arc<dyn SandboxRuntime> = match runtime_override {
        Some(rt) => rt,
        None => {
            let pf = doctor();
            if !pf.is_ok() {
                crate::fail!(
                    ErrorCode::SandboxPrerequisites,
                    "sandbox preflight failed: {}",
                    pf.missing_summary()
                );
            }
            // Ensure a daemon is running for this session.
            ensure_daemon(paths, &session).await?;
            Arc::new(RootlessRuntime::new())
        }
    };

    let timeout = args.timeout.map(Duration::from_secs);
    let inherit_stdio = !json;
    let result = match exec::run_exec(
        paths,
        &session,
        workspace_id,
        runtime,
        args.cmd,
        timeout,
        inherit_stdio,
    )
    .await
    {
        Ok(result) => result,
        // The command never ran captured, which is the fact that matters here —
        // an `exec` that silently produced no traffic is worse than one that
        // failed loudly. The terminal handler codes it and, for a sandbox
        // failure, appends a live diagnosis of why the sandbox would not come up.
        Err(e) => {
            return Err(e.context("the command did NOT run captured — no traffic was intercepted"))
        }
    };

    if json {
        exec::write_json_envelope(&exec::exec_envelope(&result));
    }
    Ok(result.exit_code)
}

/// Ensure a daemon of OUR version answers `Status` on the session's control
/// socket; spawn the hidden `burpwn proxy --session S` detached child and poll
/// until ready.
///
/// The whole check-then-spawn is serialized under an exclusive `flock` on
/// `<run_dir>/daemon.lock` (Bug #3b): without it, two execs racing on a cold
/// session would each spawn a daemon, and the second daemon's `serve_control`
/// would unlink the first's live control socket. Holding the lock until the
/// daemon answers `Status` guarantees a single winner per session.
async fn ensure_daemon(paths: &Paths, session: &str) -> Result<()> {
    let control = paths.control_sock(session);
    // Fast path: a daemon of our own version is already answering — no need to
    // take the lock. A daemon of a DIFFERENT version falls through to the
    // locked path, which retires it.
    if matches!(probe_daemon(&control).await, DaemonProbe::Current) {
        return Ok(());
    }
    let run_dir = paths.ensure_run_dir(session)?;

    // Serialize the check-and-spawn critical section with an exclusive lock.
    let lock_path = run_dir.join("daemon.lock");
    let lock = DaemonLock::acquire(&lock_path)
        .with_context(|| format!("locking {}", lock_path.display()))?;

    // Re-check under the lock: another exec may have won the race and already
    // brought a daemon up while we were blocked on the flock.
    match probe_daemon(&control).await {
        DaemonProbe::Current => return Ok(()),
        DaemonProbe::Absent => {}
        DaemonProbe::Stale { version } => {
            tracing::warn!(
                daemon_version = %version,
                our_version = %CURRENT_VERSION,
                "retiring a daemon left over from a previous burpwn version"
            );
            retire_daemon(&control)
                .await
                .context("retiring the previous version's daemon")?;
        }
    }

    // Spawn ourselves as the daemon, fully detached: a new session leader
    // (setsid) so it's reparented to init immediately and decoupled from the
    // exec's process group — Ctrl-C in the user's shell no longer kills the
    // daemon, and it can't become a zombie nobody reaps (Bug #3). stdio is
    // redirected to /dev/null so it never holds the terminal. The long-lived
    // daemon must also NOT inherit fd 3 (the exec envelope pipe the MCP `run_exec`
    // reads): if it did, the read end would never see EOF and the MCP tool call
    // would hang. `spawn_detached_daemon` explicitly closes fd 3 in the child.
    let exe = std::env::current_exe().context("locating own executable")?;
    spawn_detached_daemon(&exe, session).context("spawning proxy daemon")?;

    // Poll until proxy.sock exists and control answers Status.
    let proxy_sock = paths.proxy_sock(session);
    let mut client = ControlClient::connect_retry(&control, DAEMON_READY_TIMEOUT)
        .await
        .context("daemon control socket never became ready")?;
    client
        .status()
        .await
        .context("daemon did not answer Status")?;
    if !proxy_sock.exists() {
        // Control answered but the SCM socket isn't up yet; give it a beat.
        for _ in 0..40 {
            if proxy_sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    // Release the lock only after the daemon answers, so a racing exec that
    // wakes next sees a live daemon on its own re-check.
    drop(lock);
    Ok(())
}

/// The version this binary was built as, compared against a live daemon's.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long to wait for a retired daemon's control socket to stop answering.
const DAEMON_RETIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// What probing a session's control socket found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonProbe {
    /// Nothing answered: a cold session, or a dead daemon's leftover socket.
    Absent,
    /// A daemon running our version answered — reuse it.
    Current,
    /// A daemon answered, but it is running a different build.
    Stale {
        /// Version it reported (`""` for a daemon predating the handshake).
        version: String,
    },
}

/// Probe the session's control socket for a reusable daemon.
///
/// Liveness alone is NOT enough to reuse one. `install.sh` upgrades burpwn by
/// replacing the binary in place, which leaves any running daemon executing the
/// PREVIOUS build from a now-deleted inode (`/proc/<pid>/exe → … (deleted)`).
/// That daemon answers `Status` perfectly, so a liveness-only check adopted it
/// forever: every request kept being served by the old build — with the old
/// build's bugs — under a `burpwn -V` reporting the new version, and the only
/// way out was for the user to find and kill the process by hand.
async fn probe_daemon(control: &std::path::Path) -> DaemonProbe {
    let Ok(mut client) = ControlClient::connect(control).await else {
        return DaemonProbe::Absent;
    };
    let Ok(resp) = client.status().await else {
        return DaemonProbe::Absent;
    };
    if crate::control::daemon_is_current(&resp, CURRENT_VERSION) {
        return DaemonProbe::Current;
    }
    DaemonProbe::Stale {
        version: crate::control::status_version(&resp)
            .unwrap_or_default()
            .to_string(),
    }
}

/// Shut a stale daemon down and wait until its control socket stops answering.
///
/// The wait matters: the old daemon unlinks the control socket and drops its
/// listeners as it exits, so spawning the replacement first would race it into
/// having ITS socket unlinked by the corpse of the one it replaced — the same
/// failure the `daemon.lock` guards against for concurrent spawns.
///
/// This is called only under the lock, and only when the versions actually
/// differ (once per upgrade). An `exec` running concurrently against the old
/// daemon does lose its in-flight connections; serving the previous build
/// silently and indefinitely is the worse of the two.
async fn retire_daemon(control: &std::path::Path) -> Result<()> {
    if let Ok(mut client) = ControlClient::connect(control).await {
        // The daemon closes the connection as it tears down, so an unanswered
        // `Shutdown` is a success signal, not an error: the check below is what
        // decides whether it is really gone.
        let _ = client.shutdown().await;
    }
    let deadline = Instant::now() + DAEMON_RETIRE_TIMEOUT;
    while Instant::now() < deadline {
        if probe_daemon(control).await == DaemonProbe::Absent {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(crate::coded!(
        ErrorCode::DaemonProtocol,
        "the previous version's daemon is still answering on {} after \
         {DAEMON_RETIRE_TIMEOUT:?}; kill it and retry",
        control.display()
    ))
}

/// Spawn `burpwn proxy --session <session>` as a detached daemon: a new session
/// leader (via `setsid` in a `pre_exec` hook) with stdio routed to `/dev/null`.
fn spawn_detached_daemon(exe: &std::path::Path, session: &str) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("proxy")
        .arg("--session")
        .arg(session)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: `setsid` and `close` are async-signal-safe and the only things we
    // call between fork and exec. Detaching the child into its own session makes
    // it a session leader reparented to init, decoupled from our signal group.
    // We also close fd 3 so the long-lived daemon never inherits (and pins open)
    // the exec envelope pipe: otherwise the MCP `run_exec` reading the parent's
    // fd-3 read end would block forever waiting for an EOF the daemon withholds.
    // `close` returning EBADF (fd 3 already closed) is fine and ignored.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(3);
            Ok(())
        });
    }
    // Drop the returned Child handle: the daemon outlives us (it's its own
    // session leader; init reaps it), so there's no zombie to wait on here.
    cmd.spawn().map(|_child| ())
}

/// An exclusive advisory lock held on `<run_dir>/daemon.lock` for the duration
/// of `ensure_daemon`'s critical section. Uses raw `flock(LOCK_EX)` (no extra
/// deps); the lock is released when the file is closed (on drop).
struct DaemonLock {
    _file: std::fs::File,
}

impl DaemonLock {
    /// Open (creating if needed) the lock file and block until an exclusive
    /// `flock` is held.
    fn acquire(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        // SAFETY: `file` owns the fd for the duration of the call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

// --- req -------------------------------------------------------------------

async fn cmd_req(out: &Output, paths: &Paths, action: ReqAction) -> Result<i32> {
    let session = paths.active_session();
    match action {
        ReqAction::List(args) => req_list(out, paths, &session, args),
        ReqAction::Show { id, raw } => req_show(out, paths, &session, id, raw),
        ReqAction::Search { query } => req_search(out, paths, &session, &query),
        ReqAction::Replay(args) => req_replay(out, paths, &session, args).await,
    }
}

fn open_store(paths: &Paths, session: &str) -> Result<Store> {
    let db = paths.session_db(session);
    Store::open(&db).with_context(|| format!("opening session store {}", db.display()))
}

fn req_list(out: &Output, paths: &Paths, session: &str, args: ReqListArgs) -> Result<i32> {
    let store = open_store(paths, session)?;
    // Resolve the --workspace NAME (if any) to an id. An unknown name is an
    // error (listing a workspace that does not exist is a user mistake, not an
    // empty result), mirroring `workspace use`.
    let workspace_id = match &args.workspace {
        None => None,
        Some(name) => {
            let ws = store.reader().list_workspaces()?;
            let found = ws.iter().find(|w| &w.name == name);
            match found {
                Some(w) => Some(w.id),
                None => crate::fail!(ErrorCode::WorkspaceNotFound, "no such workspace: {name}"),
            }
        }
    };
    // Same posture for `--group`: an unknown NAME is a mistake, not an empty
    // listing. Scoped to `--workspace` when both are given.
    let group_id = match &args.group {
        None => None,
        Some(name) => Some(resolve_group(&store, name, workspace_id)?.id),
    };
    let filter = FlowFilter {
        workspace_id,
        group_id,
        host_contains: args.host,
        status: args.status,
        method: args.method,
        protocol: args.protocol.as_deref().map(Protocol::from_db),
        port: args.port,
        limit: args.limit,
        offset: args.offset,
        ..Default::default()
    };
    let rows = store.reader().list_flows(&filter)?;
    out.emit(serde_json::to_value(&rows)?, |r| {
        let mut t = flow_table(&rows);
        let mut scope = vec![format!("{} flows", rows.len())];
        if let Some(w) = &args.workspace {
            scope.push(format!("workspace {w}"));
        }
        if let Some(g) = &args.group {
            scope.push(format!("group {g}"));
        }
        t.footer(scope.join("  ·  "));
        listing(r, &t, "(no flows)")
    });
    Ok(0)
}

fn req_show(out: &Output, paths: &Paths, session: &str, id: i64, raw: bool) -> Result<i32> {
    let store = open_store(paths, session)?;
    let Some(detail) = store.reader().get_flow(id)? else {
        crate::fail!(ErrorCode::InputNoSuchFlow, "no such flow: {id}");
    };
    if raw {
        // Print the verbatim request/response bytes (head + body).
        let mut stdout = std::io::stdout();
        if let Some(req) = &detail.request {
            let _ = writeln!(stdout, "{} {} {}", req.method, req.path, req.http_version);
            let _ = stdout.write_all(&req.headers);
            let _ = stdout.write_all(b"\r\n");
            let _ = stdout.write_all(&req.body);
            let _ = writeln!(stdout, "\n");
        }
        if let Some(resp) = &detail.response {
            let _ = writeln!(stdout, "{} {}", resp.http_version, resp.status);
            let _ = stdout.write_all(&resp.headers);
            let _ = stdout.write_all(b"\r\n");
            let _ = stdout.write_all(&resp.body);
            let _ = writeln!(stdout);
        }
        return Ok(0);
    }

    out.emit(flow_detail_json(&detail), |r| {
        let mut t = crate::render::kv_table();
        t.row(vec![
            Cell::new("flow"),
            Cell::styled(id.to_string(), palette::IDENT),
            Cell::new(format!("{} -> {}", detail.client_addr, detail.flow.dst_ip)),
        ]);
        if let Some(req) = &detail.request {
            t.row(vec![
                Cell::new("request"),
                Cell::new(req.method.clone()),
                Cell::new(format!("{} ({} bytes body)", req.path, req.body.len())),
            ]);
        }
        if let Some(resp) = &detail.response {
            t.row(vec![
                Cell::new("response"),
                Cell::styled(resp.status.to_string(), palette::status(resp.status)),
                Cell::new(format!("{} bytes body", resp.body.len())),
            ]);
        }
        if !detail.tags.is_empty() {
            t.row(vec![
                Cell::new("tags"),
                Cell::new(detail.tags.join(",")),
                Cell::new(""),
            ]);
        }
        for note in &detail.notes {
            t.row(vec![
                Cell::new("note"),
                Cell::new(note.clone()),
                Cell::new(""),
            ]);
        }
        t.render(r)
    });
    Ok(0)
}

/// JSON view of a flow detail with bodies as lossy UTF-8 strings (decoded for
/// readability; use `--raw` for verbatim bytes).
fn flow_detail_json(detail: &burpwn_store::model::FlowDetail) -> Value {
    let req = detail.request.as_ref().map(|r| {
        json!({
            "method": r.method,
            "authority": r.authority,
            "path": r.path,
            "http_version": r.http_version,
            "headers": String::from_utf8_lossy(&r.headers),
            "body": String::from_utf8_lossy(&r.body),
        })
    });
    let resp = detail.response.as_ref().map(|r| {
        json!({
            "status": r.status,
            "http_version": r.http_version,
            "headers": String::from_utf8_lossy(&r.headers),
            "body": String::from_utf8_lossy(&r.body),
            "timing_ms": r.timing_ms,
        })
    });
    json!({
        "id": detail.flow.id,
        "workspace_id": detail.flow.workspace_id,
        "protocol": detail.flow.protocol,
        "scheme": detail.flow.scheme,
        "dst_ip": detail.flow.dst_ip,
        "dst_port": detail.flow.dst_port,
        "sni": detail.flow.sni,
        "exec_id": detail.exec_id,
        "client_addr": detail.client_addr,
        "request": req,
        "response": resp,
        "tags": detail.tags,
        "notes": detail.notes,
    })
}

fn req_search(out: &Output, paths: &Paths, session: &str, query: &str) -> Result<i32> {
    let store = open_store(paths, session)?;
    let ids = store.reader().search(query)?;
    out.emit(json!({ "flow_ids": ids }), |r| {
        // Bare ids, one per line: the shape `burpwn req show $(…)` wants, and
        // the one an agent can feed straight back into another call.
        let mut t = Table::new(vec![Column::right("id")]);
        for id in &ids {
            t.row(vec![Cell::styled(id.to_string(), palette::IDENT)]);
        }
        if !t.is_empty() {
            t.footer(format!("{} match(es)", ids.len()));
        }
        listing(r, &t, "(no matches)")
    });
    Ok(0)
}

async fn req_replay(
    out: &Output,
    paths: &Paths,
    session: &str,
    args: ReqReplayArgs,
) -> Result<i32> {
    let store = open_store(paths, session)?;

    let mut headers = Vec::new();
    for spec in &args.set_header {
        headers.push(replay::parse_header_spec(spec)?);
    }
    let body = match &args.set_body {
        Some(spec) if spec.starts_with('@') => {
            // `@file` reads the body from a file. On failure, do NOT echo the
            // (possibly resolved/absolute) path back: an error message that
            // varies by path existence/permission is a path-probing oracle for
            // agent-driven automation. Report only the io error kind.
            let data = std::fs::read(&spec[1..]).map_err(|e| {
                crate::coded!(
                    ErrorCode::InputFileUnreadable,
                    "reading --set-body @file failed: {}",
                    e.kind()
                )
            })?;
            Some(data)
        }
        Some(spec) => Some(spec.clone().into_bytes()),
        None => None,
    };

    let result =
        replay::replay_flow(&store, args.id, args.method.as_deref(), &headers, body).await?;

    if out.is_json() {
        println!(
            "{}",
            Envelope::ok(json!({
                "status": result.status,
                "response": String::from_utf8_lossy(&result.raw_response),
            }))
            .to_json_line()
        );
    } else {
        // The response bytes ARE the result; the "replayed flow N -> 200" line
        // above them is a courtesy to a human and noise in a capture buffer.
        if let Some(l) = out
            .render()
            .aside(format!("replayed flow {} -> {}", args.id, result.status))
        {
            anstream::println!("{l}");
        }
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(&result.raw_response);
        let _ = writeln!(stdout);
    }
    Ok(0)
}

// --- intercept (via daemon) ------------------------------------------------

async fn cmd_intercept(out: &Output, paths: &Paths, action: InterceptAction) -> Result<i32> {
    let session = paths.active_session();
    ensure_daemon(paths, &session).await?;
    let mut client = ControlClient::connect(paths.control_sock(&session)).await?;

    let resp = match action {
        InterceptAction::Enable => client.intercept_enable().await?,
        InterceptAction::Disable => client.intercept_disable().await?,
        InterceptAction::List => client.intercept_list().await?,
        InterceptAction::Await { timeout } => client.intercept_await(timeout).await?,
        InterceptAction::Forward {
            id,
            set_header,
            set_body,
            method,
        } => {
            let edits = build_edits(&set_header, set_body, method)?;
            client.intercept_forward(id, edits).await?
        }
        InterceptAction::Drop { id } => client.intercept_drop(id).await?,
        InterceptAction::Scope {
            pattern,
            path,
            method,
            clear,
        } => {
            let (host, path, method) = if clear {
                (String::new(), String::new(), String::new())
            } else {
                (
                    pattern.unwrap_or_default(),
                    path.unwrap_or_default(),
                    method.unwrap_or_default(),
                )
            };
            client.intercept_set_scope(host, path, method).await?
        }
    };

    render_control(out, resp)?;
    Ok(0)
}

fn build_edits(
    set_header: &[String],
    body: Option<String>,
    method: Option<String>,
) -> Result<Edits> {
    let mut headers = Vec::new();
    for spec in set_header {
        let e = replay::parse_header_spec(spec)?;
        headers.push(HeaderEdit {
            name: e.name,
            value: e.value,
        });
    }
    Ok(Edits {
        set_headers: headers,
        body,
        method,
        path: None,
    })
}

/// Render one control response.
///
/// Returns `Err` for [`ControlResponse::Error`] so a refusal by the daemon is a
/// FAILURE, not a success that happens to print the word "error": it used to
/// print to stderr and still exit 0 — and in `--json` mode it was wrapped in an
/// `ok: true` envelope, which is actively misleading to a script or an agent.
fn render_control(out: &Output, resp: ControlResponse) -> Result<()> {
    if let ControlResponse::Error { message } = &resp {
        crate::fail!(ErrorCode::DaemonRejected, "{message}");
    }
    // `forward`/`drop` answer `Resolved { found: false }` when the id names no
    // parked intercept. That is the request NOT being carried out, so it cannot
    // be a success: it used to print "id not found" and exit 0, which reads to a
    // script — or an agent driving await→forward — as if the request went through.
    if let ControlResponse::Resolved { found: false } = &resp {
        crate::fail!(
            ErrorCode::InputNoSuchIntercept,
            "no parked intercept with that id"
        );
    }
    let data = serde_json::to_value(&resp).unwrap_or(Value::Null);
    out.emit(data, |r| match resp {
        ControlResponse::Status {
            session,
            intercept_enabled,
            pending,
            dns_port,
            ..
        } => {
            let mut t = crate::render::kv_table();
            t.row(vec![
                Cell::new("session"),
                Cell::styled(session, palette::IDENT),
                Cell::new(""),
            ]);
            t.row(vec![
                Cell::new("intercept"),
                Cell::styled(
                    if intercept_enabled { "ON" } else { "off" },
                    if intercept_enabled {
                        palette::WARN
                    } else {
                        palette::MUTED
                    },
                ),
                Cell::new(format!("{pending} pending")),
            ]);
            t.row(vec![
                Cell::new("dns port"),
                Cell::new(dns_port.to_string()),
                Cell::new(""),
            ]);
            t.render(r)
        }
        ControlResponse::Ack => "ok".to_string(),
        ControlResponse::Intercepts { items } => {
            let mut t = intercept_table();
            for i in &items {
                t.row(intercept_row(i));
            }
            listing(r, &t, "(no parked intercepts)")
        }
        ControlResponse::Pending { item } => match item {
            Some(i) => {
                let mut t = intercept_table();
                t.row(intercept_row(&i));
                t.render(r)
            }
            None => r.aside("(timed out, none parked)").unwrap_or_default(),
        },
        ControlResponse::Resolved { .. } => "resolved".to_string(),
        // Already turned into a coded failure above.
        ControlResponse::Error { .. } => unreachable!("handled before rendering"),
    });
    Ok(())
}

/// The parked-intercept listing: `intercept list` and `intercept await` show
/// the same row, because the id in it is what `forward`/`drop` takes next.
fn intercept_table() -> Table {
    Table::new(vec![
        Column::right("id"),
        Column::left("phase"),
        Column::left("method"),
        Column::left("host"),
        Column::left("path").truncatable(),
    ])
}

fn intercept_row(i: &crate::control::InterceptItem) -> Vec<Cell> {
    vec![
        Cell::styled(i.id.to_string(), palette::IDENT),
        Cell::new(i.kind.clone()),
        Cell::new(i.method.clone()),
        Cell::new(i.host.clone()),
        Cell::new(i.path.clone()),
    ]
}

// --- match-replace ---------------------------------------------------------

async fn cmd_match_replace(out: &Output, paths: &Paths, action: MatchReplaceAction) -> Result<i32> {
    let session = paths.active_session();
    let store = open_store(paths, &session)?;
    match action {
        MatchReplaceAction::Add {
            scope,
            kind,
            pattern,
            replacement,
            on,
        } => {
            let on_request = match on.as_str() {
                "request" | "req" => true,
                "response" | "resp" => false,
                other => crate::fail!(
                    ErrorCode::InputInvalidValue,
                    "--on must be request|response, got {other:?}"
                ),
            };
            let Some(match_kind) = MatchKind::parse(&kind) else {
                crate::fail!(
                    ErrorCode::InputInvalidValue,
                    "kind must be {}, got {kind:?}",
                    MatchKind::VALID.join("|")
                )
            };
            let id = store
                .writer()
                .add_match_replace(NewMatchReplaceRule {
                    enabled: true,
                    scope,
                    match_kind,
                    pattern,
                    replacement,
                    on_request,
                })
                .await?;
            out.ok(format!("added rule {id}"), json!({ "id": id }));
        }
        MatchReplaceAction::List => {
            let rules = store.reader().list_match_replace()?;
            out.emit(serde_json::to_value(&rules)?, |r| {
                let mut t = Table::new(vec![
                    Column::right("id"),
                    Column::left("state"),
                    Column::left("on"),
                    Column::left("scope"),
                    Column::left("kind"),
                    Column::left("pattern").truncatable(),
                    Column::left("replacement").truncatable(),
                ]);
                for rule in &rules {
                    t.row(vec![
                        Cell::styled(rule.id.to_string(), palette::IDENT),
                        Cell::styled(
                            if rule.enabled { "on" } else { "off" },
                            if rule.enabled {
                                palette::GOOD
                            } else {
                                palette::MUTED
                            },
                        ),
                        Cell::new(if rule.on_request {
                            "request"
                        } else {
                            "response"
                        }),
                        Cell::new(rule.scope.clone()),
                        Cell::new(format!("{:?}", rule.match_kind).to_lowercase()),
                        Cell::new(rule.pattern.clone()),
                        Cell::new(rule.replacement.clone()),
                    ]);
                }
                listing(r, &t, "(no rules)")
            });
        }
        MatchReplaceAction::Rm { id } => {
            store.writer().delete_match_replace(id).await?;
            out.ok(format!("removed rule {id}"), json!({ "removed": id }));
        }
        MatchReplaceAction::Enable { id } => {
            store.writer().set_match_replace_enabled(id, true).await?;
            out.ok(
                format!("enabled rule {id}"),
                json!({ "id": id, "enabled": true }),
            );
        }
        MatchReplaceAction::Disable { id } => {
            store.writer().set_match_replace_enabled(id, false).await?;
            out.ok(
                format!("disabled rule {id}"),
                json!({ "id": id, "enabled": false }),
            );
        }
    }
    Ok(0)
}

// --- hooks -----------------------------------------------------------------

/// Resolve a hook id or fail with a branchable code.
fn resolve_hook(store: &Store, id: i64) -> Result<burpwn_store::model::Hook> {
    match store.reader().get_hook(id)? {
        Some(h) => Ok(h),
        None => crate::fail!(ErrorCode::InputNoSuchHook, "no such hook: {id}"),
    }
}

/// The hook listing: id, state, phase, scope, action, order — the same row for
/// `hook list` and `hook show`, since the second is the first plus its knobs.
fn hook_table() -> Table {
    Table::new(vec![
        Column::right("id"),
        Column::left("state"),
        Column::left("phase"),
        Column::left("scope").truncatable(),
        Column::left("action").truncatable(),
        Column::right("order"),
    ])
}

fn hook_row(h: &burpwn_store::model::Hook) -> Vec<Cell> {
    vec![
        Cell::styled(h.id.to_string(), palette::IDENT),
        Cell::styled(
            if h.enabled { "on" } else { "off" },
            if h.enabled {
                palette::GOOD
            } else {
                palette::MUTED
            },
        ),
        Cell::new(h.phase.as_str()),
        Cell::new(crate::hooks::scope_summary(h)),
        Cell::new(crate::hooks::action_summary(h)),
        Cell::new(h.order.to_string()),
    ]
}

async fn cmd_hook(out: &Output, paths: &Paths, action: HookAction) -> Result<i32> {
    // Only `hook test` takes an explicit session (it is the one the MCP server
    // shells out to); everything else edits the active session, like `match-replace`.
    let session = match &action {
        HookAction::Test {
            session: Some(s), ..
        } => s.clone(),
        _ => paths.active_session(),
    };
    let store = open_store(paths, &session)?;
    match action {
        HookAction::Add(args) => {
            // Validate BEFORE writing: a hook is applied to live traffic with
            // nobody watching, so a broken one must never reach the table.
            let spec = crate::hooks::HookSpec {
                name: args.name.clone(),
                phase: args.phase,
                action: args.action,
                host: args.host,
                method: args.method,
                path: args.path,
                status: args.status,
                header: args.header,
                param: args.param,
                cmd: args.cmd,
                extract: args.extract,
                inject_header: args.inject_header,
                inject_param: args.inject_param,
                inject_only_if_absent: args.inject_if_absent,
                order: args.order,
                timeout_ms: args.timeout_ms,
                ttl_ms: args.ttl_ms,
                disabled: args.disabled,
            };
            let hook = crate::hooks::build_hook(&spec)?;
            let id = store.writer().add_hook(hook).await?;
            out.ok(
                format!("added hook {id} ({})", args.name),
                json!({ "hook_id": id, "name": args.name }),
            );
        }
        HookAction::List => {
            let hooks = store.reader().list_hooks()?;
            let rows: Vec<Value> = hooks.iter().map(crate::hooks::to_json).collect();
            out.emit(json!({ "hooks": rows }), |r| {
                let mut t = hook_table();
                for h in &hooks {
                    t.row(hook_row(h));
                }
                listing(r, &t, "(no hooks)")
            });
        }
        HookAction::Show { id } => {
            let hook = resolve_hook(&store, id)?;
            out.emit(crate::hooks::to_json(&hook), |r| {
                let mut t = hook_table();
                t.row(hook_row(&hook));
                let mut text = t.render(r);
                let mut kv = crate::render::kv_pair();
                kv.row(vec![
                    Cell::new("name"),
                    Cell::styled(hook.name.clone(), palette::IDENT),
                ]);
                kv.row(vec![
                    Cell::new("timeout_ms"),
                    Cell::new(hook.timeout_ms.to_string()),
                ]);
                kv.row(vec![
                    Cell::new("ttl_ms"),
                    Cell::new(hook.ttl_ms.to_string()),
                ]);
                text.push('\n');
                text.push_str(&kv.render(r));
                text
            });
        }
        HookAction::Rm { id } => {
            resolve_hook(&store, id)?;
            store.writer().delete_hook(id).await?;
            out.ok(format!("removed hook {id}"), json!({ "removed": id }));
        }
        HookAction::Enable { id } => {
            resolve_hook(&store, id)?;
            store.writer().set_hook_enabled(id, true).await?;
            out.ok(
                format!("enabled hook {id}"),
                json!({ "id": id, "enabled": true }),
            );
        }
        HookAction::Disable { id } => {
            resolve_hook(&store, id)?;
            store.writer().set_hook_enabled(id, false).await?;
            out.ok(
                format!("disabled hook {id}"),
                json!({ "id": id, "enabled": false }),
            );
        }
        HookAction::Test { id, flow, .. } => {
            let hook = resolve_hook(&store, id)?;
            let Some(detail) = store.reader().get_flow(flow)? else {
                crate::fail!(ErrorCode::InputNoSuchFlow, "no such flow: {flow}");
            };
            // An `exec` hook's command runs in the sandbox, which needs the
            // session daemon (it is what owns the proxy socket the sandbox hands
            // connections to). Declarative hooks need none of that.
            let runner = if hook.action.is_declarative() {
                None
            } else {
                ensure_daemon(paths, &session).await?;
                Some(crate::hooks::SandboxHookRunner::new(
                    paths.clone(),
                    session.clone(),
                ))
            };
            let report = crate::hooks::test_hook(
                &hook,
                &detail,
                runner.as_ref().map(|r| r as &dyn burpwn_proxy::HookRunner),
            )
            .await?;
            out.emit(report.clone(), |r| {
                let flag = |k: &str| report[k].as_bool().unwrap_or(false);
                let yes_no =
                    |b: bool| Cell::styled(if b { "yes" } else { "no" }, palette::yes_no(b));
                let mut t = crate::render::kv_table();
                t.row(vec![
                    Cell::new("hook"),
                    Cell::styled(id.to_string(), palette::IDENT),
                    Cell::new(format!("on flow {flow}")),
                ]);
                t.row(vec![
                    Cell::new("matched"),
                    yes_no(flag("matched")),
                    Cell::new(""),
                ]);
                t.row(vec![
                    Cell::new("changed"),
                    yes_no(flag("changed")),
                    Cell::new(""),
                ]);
                t.row(vec![
                    Cell::new("dropped"),
                    yes_no(flag("dropped")),
                    Cell::new(""),
                ]);
                if let Some(exec) = report["exec"].as_object() {
                    t.row(vec![
                        Cell::new("exec"),
                        Cell::new(Value::Object(exec.clone()).to_string()),
                        Cell::new(""),
                    ]);
                }
                t.row(vec![
                    Cell::new("before"),
                    Cell::new(report["before"]["url"].as_str().unwrap_or("").to_string()),
                    Cell::new(""),
                ]);
                t.row(vec![
                    Cell::new("after"),
                    Cell::new(report["after"]["url"].as_str().unwrap_or("").to_string()),
                    Cell::new(""),
                ]);
                let mut text = t.render(r);
                // The rewritten header block is the thing being debugged, so it
                // is printed verbatim rather than squeezed into a column.
                let headers = report["after"]["headers"].as_str().unwrap_or_default();
                if !headers.is_empty() {
                    text.push('\n');
                    text.push_str(headers.trim_end());
                }
                text
            });
        }
    }
    Ok(0)
}

// --- workspace / tag / note ------------------------------------------------

async fn cmd_workspace(out: &Output, paths: &Paths, action: WorkspaceAction) -> Result<i32> {
    let session = paths.active_session();
    let store = open_store(paths, &session)?;
    match action {
        WorkspaceAction::New { name } => {
            let id = store
                .writer()
                .create_workspace(name.clone(), now_millis())
                .await?;
            out.ok(
                format!("created workspace {name} ({id})"),
                json!({ "id": id, "name": name }),
            );
        }
        WorkspaceAction::List => {
            let ws = store.reader().list_workspaces()?;
            out.emit(serde_json::to_value(&ws)?, |r| {
                let mut t = Table::new(vec![Column::right("id"), Column::left("workspace")]);
                for w in &ws {
                    t.row(vec![
                        Cell::styled(w.id.to_string(), palette::IDENT),
                        Cell::new(w.name.clone()),
                    ]);
                }
                listing(r, &t, "(no workspaces)")
            });
        }
        WorkspaceAction::Use { name } => {
            // Resolve to an id for the caller's convenience; persistence of the
            // "active workspace" is the caller's job (pass --workspace).
            let ws = store.reader().list_workspaces()?;
            let found = ws.iter().find(|w| w.name == name);
            match found {
                Some(w) => out.ok(
                    format!("workspace {name} is id {}", w.id),
                    json!({ "id": w.id, "name": name }),
                ),
                None => crate::fail!(ErrorCode::WorkspaceNotFound, "no such workspace: {name}"),
            }
        }
    }
    Ok(0)
}

async fn cmd_tag(out: &Output, paths: &Paths, action: TagAction) -> Result<i32> {
    let session = paths.active_session();
    let store = open_store(paths, &session)?;
    match action {
        TagAction::Add { flow_id, name } => {
            let id = store.writer().tag_flow(flow_id, name.clone(), None).await?;
            out.ok(
                format!("tagged flow {flow_id} with {name}"),
                json!({ "tag_id": id, "flow_id": flow_id, "name": name }),
            );
        }
        TagAction::List => {
            let tags = store.reader().list_tags()?;
            out.emit(serde_json::to_value(&tags)?, |r| {
                let mut t = Table::new(vec![
                    Column::right("id"),
                    Column::left("tag"),
                    Column::left("color"),
                ]);
                for tag in &tags {
                    // The colour has been in the table since v1 and coloured
                    // nothing until now: on a terminal the tag wears it.
                    t.row(vec![
                        Cell::styled(tag.id.to_string(), palette::IDENT),
                        Cell::styled(tag.name.clone(), palette::tag(tag.color.as_deref())),
                        Cell::new(tag.color.clone().unwrap_or_default()),
                    ]);
                }
                listing(r, &t, "(no tags)")
            });
        }
    }
    Ok(0)
}

async fn cmd_note(out: &Output, paths: &Paths, action: NoteAction) -> Result<i32> {
    let session = paths.active_session();
    let store = open_store(paths, &session)?;
    match action {
        NoteAction::Add { flow_id, text } => {
            let id = store
                .writer()
                .add_note(flow_id, text.clone(), now_millis())
                .await?;
            out.ok(
                format!("added note {id} to flow {flow_id}"),
                json!({ "note_id": id, "flow_id": flow_id }),
            );
        }
        NoteAction::List { flow_id } => {
            let notes = store.reader().flow_notes(flow_id)?;
            out.emit(serde_json::to_value(&notes)?, |r| {
                let mut t = Table::new(vec![
                    Column::right("id"),
                    Column::left("note").truncatable(),
                ]);
                for n in &notes {
                    t.row(vec![
                        Cell::styled(n.id.to_string(), palette::IDENT),
                        Cell::new(n.body.clone()),
                    ]);
                }
                listing(r, &t, "(no notes)")
            });
        }
    }
    Ok(0)
}

// --- group (named collections of flows) ------------------------------------

/// Resolve a `--workspace` value that may be a NAME or a numeric id. An unknown
/// value is an error rather than a silent fallback to the default workspace:
/// putting a group somewhere the user did not ask for is worse than refusing.
fn resolve_workspace_ref(store: &Store, value: &str) -> Result<i64> {
    let workspaces = store.reader().list_workspaces()?;
    if let Some(w) = workspaces.iter().find(|w| w.name == value) {
        return Ok(w.id);
    }
    if let Ok(id) = value.parse::<i64>() {
        if let Some(w) = workspaces.iter().find(|w| w.id == id) {
            return Ok(w.id);
        }
    }
    crate::fail!(ErrorCode::WorkspaceNotFound, "no such workspace: {value}");
}

/// Resolve a group NAME (optionally scoped to a workspace) to its row, failing
/// with `GroupNotFound` when there is none.
fn resolve_group(store: &Store, name: &str, workspace_id: Option<i64>) -> Result<Group> {
    match store.reader().group_by_name(name, workspace_id)? {
        Some(g) => Ok(g),
        None => crate::fail!(ErrorCode::GroupNotFound, "no such group: {name}"),
    }
}

/// The flow listing, shared by `req list` and `group show` so a group reads
/// exactly like the listing it came from.
///
/// Widths are measured on the rows, not hard-coded: one long URL used to push
/// every later column out of line for the whole listing. The URL is also the
/// only column allowed to give ground when the terminal is too narrow — the id,
/// the method and the status are what the NEXT command takes as arguments, so
/// losing a character of them would be losing the point.
fn flow_table(rows: &[burpwn_store::model::FlowRow]) -> Table {
    let mut t = Table::new(vec![
        Column::right("id"),
        Column::left("proto"),
        Column::left("method"),
        Column::left("url").truncatable(),
        Column::right("status"),
    ]);
    for r in rows {
        let host = r
            .authority
            .as_deref()
            .or(r.sni.as_deref())
            .unwrap_or(&r.dst_ip);
        let (status, style) = match r.status {
            Some(s) => (s.to_string(), palette::status(s)),
            None => ("-".to_string(), palette::MUTED),
        };
        t.row(vec![
            Cell::styled(r.id.to_string(), palette::IDENT),
            Cell::new(r.protocol.as_str()),
            Cell::new(r.method.clone().unwrap_or_default()),
            Cell::new(format!(
                "{}://{host}{}",
                r.scheme,
                r.path.as_deref().unwrap_or("")
            )),
            Cell::styled(status, style),
        ]);
    }
    t
}

async fn cmd_group(out: &Output, paths: &Paths, action: GroupAction) -> Result<i32> {
    let session = paths.active_session();
    let store = open_store(paths, &session)?;
    match action {
        GroupAction::New {
            name,
            description,
            workspace,
        } => {
            let workspace_id = match &workspace {
                Some(v) => resolve_workspace_ref(&store, v)?,
                None => burpwn_store::schema::DEFAULT_WORKSPACE_ID,
            };
            // `create_group` is a create-or-update (see the store docs), so look
            // first purely to tell the user WHICH of the two happened.
            let existed = store
                .reader()
                .group_by_name(&name, Some(workspace_id))?
                .is_some();
            let id = store
                .writer()
                .create_group(
                    name.clone(),
                    description.clone(),
                    workspace_id,
                    now_millis(),
                )
                .await?;
            let human = if existed {
                format!("group {name} ({id}) already existed — description updated")
            } else {
                format!("created group {name} ({id})")
            };
            out.ok(
                human,
                json!({
                    "group_id": id,
                    "name": name,
                    "description": description,
                    "workspace_id": workspace_id,
                    "created": !existed,
                }),
            );
        }
        GroupAction::Add { name, flow_id } => {
            let group = resolve_group(&store, &name, None)?;
            // Validate every id BEFORE writing any membership, so a typo in the
            // third id doesn't leave the group half-populated.
            for id in &flow_id {
                if !store.reader().flow_exists(*id)? {
                    crate::fail!(ErrorCode::InputNoSuchFlow, "no such flow: {id}");
                }
            }
            for id in &flow_id {
                store.writer().add_flow_to_group(*id, group.id).await?;
            }
            out.ok(
                format!("added {} flow(s) to group {name}", flow_id.len()),
                json!({ "group_id": group.id, "name": name, "flow_ids": flow_id }),
            );
        }
        GroupAction::RmFlow { name, flow_id } => {
            let group = resolve_group(&store, &name, None)?;
            for id in &flow_id {
                store.writer().remove_flow_from_group(*id, group.id).await?;
            }
            out.ok(
                format!("removed {} flow(s) from group {name}", flow_id.len()),
                json!({ "group_id": group.id, "name": name, "flow_ids": flow_id }),
            );
        }
        GroupAction::List { workspace } => {
            let workspace_id = match &workspace {
                Some(v) => Some(resolve_workspace_ref(&store, v)?),
                None => None,
            };
            let reader = store.reader();
            let groups = reader.list_groups(workspace_id)?;
            let mut view = Vec::with_capacity(groups.len());
            for g in &groups {
                let count = reader.group_flow_count(g.id)?;
                view.push(json!({
                    "id": g.id,
                    "name": g.name,
                    "description": g.description,
                    "workspace_id": g.workspace_id,
                    "created_at": g.created_at,
                    "flow_count": count,
                }));
            }
            out.emit(json!({ "groups": view }), |r| {
                let mut t = Table::new(vec![
                    Column::right("id"),
                    Column::left("group"),
                    Column::right("flows"),
                    Column::left("description").truncatable(),
                ]);
                for (g, v) in groups.iter().zip(&view) {
                    t.row(vec![
                        Cell::styled(g.id.to_string(), palette::IDENT),
                        Cell::new(g.name.clone()),
                        Cell::new(v["flow_count"].as_i64().unwrap_or(0).to_string()),
                        Cell::new(g.description.clone().unwrap_or_default()),
                    ]);
                }
                listing(r, &t, "(no groups)")
            });
        }
        GroupAction::Show { name } => {
            let group = resolve_group(&store, &name, None)?;
            let rows = store.reader().flows_in_group(group.id)?;
            out.emit(
                json!({
                    "group": {
                        "id": group.id,
                        "name": group.name,
                        "description": group.description,
                        "workspace_id": group.workspace_id,
                        "created_at": group.created_at,
                    },
                    "flows": rows,
                    "count": rows.len(),
                }),
                |r| {
                    let mut t = flow_table(&rows);
                    let mut foot = format!("{} flows  ·  group {}", rows.len(), group.name);
                    if let Some(d) = &group.description {
                        foot.push_str("  ·  ");
                        foot.push_str(d);
                    }
                    t.footer(foot);
                    listing(r, &t, &format!("(no flows in group {name})"))
                },
            );
        }
        GroupAction::Rm { name } => {
            let group = resolve_group(&store, &name, None)?;
            store.writer().delete_group(group.id).await?;
            out.ok(
                format!("deleted group {name} ({})", group.id),
                json!({ "group_id": group.id, "name": name }),
            );
        }
    }
    Ok(0)
}

// --- export ----------------------------------------------------------------

fn cmd_export(out: &Output, paths: &Paths, action: ExportAction) -> Result<i32> {
    let session = paths.active_session();
    match action {
        ExportAction::Har {
            workspace,
            group,
            output,
        } => {
            let store = open_store(paths, &session)?;
            // `--group NAME` exports exactly one named scenario. It is exclusive
            // with `--workspace` (clap enforces that), so the group's own
            // workspace scopes the export.
            let group_id = match &group {
                None => None,
                Some(name) => Some(resolve_group(&store, name, None)?.id),
            };
            let reader = store.reader();
            let rows = reader.list_flows(&FlowFilter {
                workspace_id: workspace,
                group_id,
                limit: Some(100_000),
                ..Default::default()
            })?;
            let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
            let har = har::build_har(&reader, &ids)?;
            // Report the number of HTTP entries actually written, not the total
            // flow count (which includes DNS / raw-TCP / TLS-passthru flows the
            // HAR omits).
            let entry_count = har["log"]["entries"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            let text = serde_json::to_string_pretty(&har)?;
            match output {
                Some(path) => {
                    // Refuse to follow an existing symlink at the target: writing
                    // through it would let an attacker-seeded link redirect the
                    // HAR onto a victim file (this is operator-facing but also
                    // reachable from agent-driven automation). `force = true`:
                    // a HAR export has always overwritten silently.
                    crate::bundle::guard_output_path(Path::new(&path), "HAR", true)?;
                    std::fs::write(&path, &text).with_context(|| format!("writing {path}"))?;
                    out.ok(
                        format!("wrote {entry_count} entries to {path}"),
                        json!({ "path": path, "entries": entry_count }),
                    );
                }
                None => {
                    // A HAR on stdout is a file, not a listing: it goes out
                    // whole. Indented for a human, compact for a pipe — the
                    // indentation of a 5 MB export is pure padding to a parser.
                    out.emit(har.clone(), |r| {
                        if r.is_pretty() {
                            text.clone()
                        } else {
                            har.to_string()
                        }
                    });
                }
            }
            Ok(0)
        }
        ExportAction::Session {
            session: name,
            output,
            redact,
            force,
        } => {
            let name = name.unwrap_or(session);
            let outcome = crate::bundle::export_session(
                paths,
                &crate::bundle::ExportRequest {
                    session: name,
                    output: output.map(PathBuf::from),
                    redact,
                    force,
                },
            )?;
            let m = &outcome.manifest;
            // The warning goes in the envelope (never on stdout as prose: the
            // MCP layer parses the last stdout line as the envelope) and on
            // stderr everywhere else.
            out.emit(
                json!({
                    "path": outcome.path.display().to_string(),
                    "bytes": outcome.bytes,
                    "session": m.session,
                    "flows": m.flow_count,
                    "schema_version": m.schema_version,
                    "redacted": m.redacted,
                    "warning": outcome.warning(),
                }),
                |_| {
                    format!(
                        "wrote {} ({} flows, {} bytes)",
                        outcome.path.display(),
                        m.flow_count,
                        outcome.bytes
                    )
                },
            );
            if !out.is_json() {
                eprintln!("⚠ {}", outcome.warning());
            }
            Ok(0)
        }
        ExportAction::Pcap { output } => {
            let _ = output;
            crate::fail!(
                ErrorCode::InputInvalidValue,
                "pcap export is not yet implemented (use `export har`)"
            );
        }
    }
}

// --- fuzz (Intruder) --------------------------------------------------------

/// A `serde_json` scalar rendered as the value it holds.
///
/// This is the fix for a real bug in both Intruder tables: the numbers came
/// straight out of a [`Value`] and were interpolated as one, so `{:>6}` padded
/// nothing at all (`Display for Value` ignores the formatter's width) and a
/// string payload arrived with its JSON quotes still attached. Pulling the
/// scalar out first is what makes the column line up AND the payload readable.
fn num(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The payload cell: `fuzz run` reports a LIST of payloads (one per position),
/// `fuzz show` the single stored string.
fn payload_text(v: &Value) -> String {
    match v {
        Value::Array(items) => items.iter().map(num).collect::<Vec<_>>().join(" "),
        other => num(other),
    }
}

/// The ranked Intruder results table. `first` names the leading column because
/// `fuzz show` lists stored result ids and `fuzz run` the payload index.
fn fuzz_result_table(first: &'static str) -> Table {
    Table::new(vec![
        Column::right(first),
        Column::right("status"),
        Column::right("len"),
        Column::right("ms"),
        Column::right("anomaly"),
        Column::left("payload").truncatable(),
    ])
}

/// One result row. The anomaly score carries the gradient: this is the one
/// listing whose whole purpose is that the outlier is seen before it is read.
fn fuzz_result_row(
    id: &Value,
    status: &Value,
    len: &Value,
    ms: &Value,
    anomaly: &Value,
    payload: &Value,
) -> Vec<Cell> {
    let score = anomaly.as_f64().unwrap_or(0.0);
    let status_cell = match status.as_i64().and_then(|c| u16::try_from(c).ok()) {
        Some(code) => Cell::styled(code.to_string(), palette::status(code)),
        None => Cell::styled("", palette::MUTED),
    };
    vec![
        Cell::styled(num(id), palette::IDENT),
        status_cell,
        Cell::new(num(len)),
        Cell::new(num(ms)),
        Cell::styled(format!("{score:.3}"), palette::anomaly(score)),
        Cell::new(payload_text(payload)),
    ]
}

async fn cmd_fuzz(out: &Output, paths: &Paths, action: FuzzAction) -> Result<i32> {
    let session = paths.active_session();
    match action {
        FuzzAction::Run(args) => cmd_fuzz_run(out, paths, &session, args).await,
        FuzzAction::List { workspace } => {
            let v = crate::fuzz::fuzz_list(paths, &session, workspace.as_deref())?;
            out.emit(v.clone(), |r| {
                let empty = Vec::new();
                let rows = v["attacks"].as_array().unwrap_or(&empty);
                let mut t = Table::new(vec![
                    Column::right("id"),
                    Column::left("status"),
                    Column::left("name").truncatable(),
                    Column::right("flow"),
                    Column::right("results"),
                ]);
                for a in rows {
                    let status = a["status"].as_str().unwrap_or("");
                    t.row(vec![
                        Cell::styled(a["id"].as_i64().unwrap_or(0).to_string(), palette::IDENT),
                        Cell::styled(
                            status,
                            match status {
                                "done" => palette::GOOD,
                                "running" | "pending" => palette::WARN,
                                _ => palette::MUTED,
                            },
                        ),
                        Cell::new(a["name"].as_str().unwrap_or("")),
                        Cell::new(num(&a["base_flow_id"])),
                        Cell::new(a["results"].as_i64().unwrap_or(0).to_string()),
                    ]);
                }
                listing(r, &t, "(no attacks)")
            });
            Ok(0)
        }
        FuzzAction::Show {
            attack_id,
            sort,
            limit,
        } => {
            let sort = crate::fuzz::ResultSort::from_str_opt(&sort).ok_or_else(|| {
                crate::coded!(
                    ErrorCode::InputInvalidValue,
                    "--sort must be anomaly|status|len, got {sort:?}"
                )
            })?;
            let v = crate::fuzz::fuzz_show(paths, &session, attack_id, sort, limit)?;
            out.emit(v.clone(), |r| {
                let empty = Vec::new();
                let rows = v["results"].as_array().unwrap_or(&empty);
                let mut t = fuzz_result_table("id");
                for res in rows {
                    t.row(fuzz_result_row(
                        &res["id"],
                        &res["status_code"],
                        &res["resp_len"],
                        &res["latency_ms"],
                        &res["anomaly_score"],
                        &res["payload"],
                    ));
                }
                if !t.is_empty() {
                    t.footer(format!(
                        "{} results  ·  attack {attack_id}  ·  most anomalous first",
                        t.len()
                    ));
                }
                listing(r, &t, "(no results)")
            });
            Ok(0)
        }
    }
}

async fn cmd_fuzz_run(
    out: &Output,
    paths: &Paths,
    session: &str,
    args: FuzzRunArgs,
) -> Result<i32> {
    use burpwn_proxy::AttackMode;
    use tokio_util::sync::CancellationToken;

    let mode = AttackMode::from_str_opt(&args.mode).ok_or_else(|| {
        crate::coded!(
            ErrorCode::InputInvalidValue,
            "--mode must be sniper|battering-ram|pitchfork|cluster-bomb"
        )
    })?;

    // Positions.
    let mut positions = Vec::new();
    for spec in &args.position {
        positions.push(crate::fuzz::parse_position(spec)?);
    }

    // Payloads: inline --payload plus --payloads file (one per line).
    let mut payloads: Vec<Vec<u8>> = args
        .payload
        .iter()
        .map(|p| p.clone().into_bytes())
        .collect();
    if let Some(file) = &args.payloads {
        let data = std::fs::read_to_string(file).map_err(|e| {
            crate::coded!(
                ErrorCode::InputFileUnreadable,
                "reading --payloads file failed: {}",
                e.kind()
            )
        })?;
        for line in data.lines() {
            payloads.push(line.as_bytes().to_vec());
        }
    }

    let request_bytes = match &args.request {
        Some(file) => Some(std::fs::read(file).map_err(|e| {
            crate::coded!(
                ErrorCode::InputFileUnreadable,
                "reading --request file failed: {}",
                e.kind()
            )
        })?),
        None => None,
    };

    let spec = crate::fuzz::FuzzSpec {
        flow_id: args.flow,
        request_bytes,
        positions,
        marker: args.marker.map(|m| m.into_bytes()),
        payloads,
        mode,
        concurrency: args.concurrency,
        delay_ms: args.delay,
        name: args.name,
    };

    // Cancel the run on Ctrl-C.
    let cancel = CancellationToken::new();
    let cancel_bg = cancel.clone();
    let sig = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_bg.cancel();
        }
    });

    let result = crate::fuzz::fuzz_run(paths, session, spec, cancel).await;
    sig.abort();
    let v = result?;

    out.emit(v.clone(), |r| {
        let empty = Vec::new();
        let mut t = fuzz_result_table("#");
        for res in v["results"].as_array().unwrap_or(&empty) {
            t.row(fuzz_result_row(
                &res["index"],
                &res["status"],
                &res["resp_len"],
                &res["latency_ms"],
                &res["anomaly"],
                &res["payloads"],
            ));
        }
        let mut foot = format!(
            "{} results  ·  attack {} ({})  ·  {}",
            t.len(),
            v["attack_id"].as_i64().unwrap_or(0),
            v["mode"].as_str().unwrap_or("-"),
            v["status"].as_str().unwrap_or("-"),
        );
        if let Some(b) = v["baseline"].as_object() {
            foot.push_str(&format!(
                "  ·  baseline {} / {} bytes",
                num(b.get("status").unwrap_or(&Value::Null)),
                num(b.get("resp_len").unwrap_or(&Value::Null)),
            ));
        }
        t.footer(foot);
        listing(r, &t, "(no results)")
    });
    Ok(0)
}

// --- compare ----------------------------------------------------------------

fn cmd_compare(out: &Output, paths: &Paths, args: CompareArgs) -> Result<i32> {
    let session = paths.active_session();
    let store = open_store(paths, &session)?;
    let reader = store.reader();
    let Some(a) = reader.get_flow(args.flow_a)? else {
        crate::fail!(ErrorCode::InputNoSuchFlow, "no such flow: {}", args.flow_a);
    };
    let Some(b) = reader.get_flow(args.flow_b)? else {
        crate::fail!(ErrorCode::InputNoSuchFlow, "no such flow: {}", args.flow_b);
    };
    let what = crate::compare::CompareWhat::from_str_opt(&args.what).ok_or_else(|| {
        crate::coded!(
            ErrorCode::InputInvalidValue,
            "--what must be headers|body|all, got {:?}",
            args.what
        )
    })?;
    let v = crate::compare::diff_flows(&a, &b, what);
    out.emit(v.clone(), |r| compare_report(r, &v));
    Ok(0)
}

/// The diff as rows instead of the pretty-printed JSON blob it used to be:
/// `serde_json::to_string_pretty` is a machine format shown to a human, and it
/// costs a piped consumer three lines and a pile of punctuation per header.
fn compare_report(r: &Render, v: &Value) -> String {
    let mut t = crate::render::kv_table();
    let changed = v["status"]["changed"].as_bool().unwrap_or(false);
    t.row(vec![
        Cell::new("status"),
        Cell::styled(
            format!("{} -> {}", num(&v["status"]["a"]), num(&v["status"]["b"])),
            if changed {
                palette::WARN
            } else {
                palette::MUTED
            },
        ),
        Cell::new(""),
    ]);
    for (mark, key, style) in [
        ("header +", "added", palette::GOOD),
        ("header -", "removed", palette::BAD),
        ("header ~", "changed", palette::WARN),
    ] {
        for item in v["headers"][key].as_array().into_iter().flatten() {
            let detail = if key == "changed" {
                format!("{} -> {}", num(&item["a"]), num(&item["b"]))
            } else {
                num(&item["value"])
            };
            t.row(vec![
                Cell::styled(mark, style),
                Cell::new(num(&item["name"])),
                Cell::new(detail),
            ]);
        }
    }
    if let Some(body) = v["body"].as_object() {
        let identical = body["identical"].as_bool().unwrap_or(false);
        t.row(vec![
            Cell::new("body"),
            Cell::styled(
                if identical { "identical" } else { "differs" },
                if identical {
                    palette::MUTED
                } else {
                    palette::WARN
                },
            ),
            Cell::new(format!(
                "{} -> {} bytes",
                num(&body["len_a"]),
                num(&body["len_b"])
            )),
        ]);
        for (mark, key) in [("body -", "only_in_a"), ("body +", "only_in_b")] {
            for line in body[key].as_array().into_iter().flatten() {
                t.row(vec![Cell::new(mark), Cell::new(num(line)), Cell::new("")]);
            }
        }
        // A request token echoed back in the response is the finding this
        // command exists to surface, so it is coloured like one.
        for tok in body["reflected"].as_array().into_iter().flatten() {
            t.row(vec![
                Cell::styled("reflected", palette::BAD),
                Cell::new(num(tok)),
                Cell::new(""),
            ]);
        }
    }
    t.render(r)
}

// --- encode / decode --------------------------------------------------------

fn cmd_encode(out: &Output, scheme: &str, value: &str) -> Result<i32> {
    let v = crate::encode::encode(scheme, value)?;
    out.emit(v.clone(), |_| {
        v["encoded"].as_str().unwrap_or("").to_string()
    });
    Ok(0)
}

fn cmd_decode(out: &Output, scheme: &str, value: &str) -> Result<i32> {
    let v = crate::encode::decode(scheme, value)?;
    let jwt = scheme.eq_ignore_ascii_case("jwt");
    out.emit(v.clone(), |r| {
        if !jwt {
            return v["decoded"].as_str().unwrap_or("").to_string();
        }
        // A JWT is a claim set, not a document: one `claim  value` row each,
        // instead of the re-indented JSON this used to print.
        let mut t = crate::render::kv_pair();
        t.row(vec![
            Cell::new("alg"),
            Cell::styled(num(&v["alg"]), palette::IDENT),
        ]);
        if let Some(claims) = v["claims"].as_object() {
            for (k, val) in claims {
                t.row(vec![Cell::new(format!("claim {k}")), Cell::new(num(val))]);
            }
        }
        t.row(vec![
            Cell::new("signature"),
            Cell::styled("not verified", palette::WARN),
        ]);
        t.render(r)
    });
    Ok(0)
}

// --- helpers ---------------------------------------------------------------

fn dirs_home() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| crate::coded!(ErrorCode::SessionNoDataDir, "HOME is not set"))
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpwn_sandbox::{ExecOutcome, MockRuntime};
    use burpwn_store::model::{FlowStart, RequestData, ResponseData};

    /// Serve `Status` replies on `sock` exactly like a daemon from `version`,
    /// stopping when a `Shutdown` arrives (and unlinking the socket, as the real
    /// `serve_control` does). `version: None` impersonates a daemon predating
    /// the version handshake, which sends no `version` field at all.
    ///
    /// Hand-rolled rather than driven through `serve_control`, which can only
    /// ever answer with the version this test binary was built as — and the
    /// case that matters here is precisely a daemon of a DIFFERENT build.
    fn fake_daemon(
        sock: std::path::PathBuf,
        version: Option<&'static str>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&sock).unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let (r, mut w) = tokio::io::split(stream);
                let mut lines = tokio::io::BufReader::new(r);
                let mut line = String::new();
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                while lines.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let shutdown = line.contains("Shutdown");
                    let reply = if shutdown {
                        r#"{"type":"Ack"}"#.to_string()
                    } else {
                        let v = match version {
                            Some(v) => format!(r#","version":"{v}""#),
                            None => String::new(),
                        };
                        format!(
                            r#"{{"type":"Status","running":true,"session":"t",
                             "intercept_enabled":false,"pending":0,"dns_port":5353{v}}}"#
                        )
                        .replace('\n', "")
                    };
                    let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    let _ = w.flush().await;
                    if shutdown {
                        let _ = std::fs::remove_file(&sock);
                        return;
                    }
                    line.clear();
                }
            }
        })
    }

    #[tokio::test]
    async fn no_socket_probes_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            probe_daemon(&dir.path().join("control.sock")).await,
            DaemonProbe::Absent
        );
    }

    /// Regression for the upgrade that changed nothing: after `install.sh`
    /// replaced the binary, the daemon started by the PREVIOUS version kept
    /// answering `Status`, so `ensure_daemon`'s liveness-only check adopted it
    /// and every request was still served by the old build — the user saw the
    /// old build's bugs under the new `burpwn -V` with no way to tell.
    #[tokio::test]
    async fn a_daemon_from_another_version_is_stale_not_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = fake_daemon(sock.clone(), Some("0.0.1-old"));
        // Give the listener a moment to bind before probing.
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert_eq!(
            probe_daemon(&sock).await,
            DaemonProbe::Stale {
                version: "0.0.1-old".into()
            }
        );
        // …and retiring it leaves the socket free for the current build.
        retire_daemon(&sock).await.unwrap();
        assert_eq!(probe_daemon(&sock).await, DaemonProbe::Absent);
        server.abort();
    }

    /// A daemon old enough to predate the handshake sends no `version`; it must
    /// be treated as stale rather than crashing the probe on a decode error.
    #[tokio::test]
    async fn a_pre_handshake_daemon_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = fake_daemon(sock.clone(), None);
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            probe_daemon(&sock).await,
            DaemonProbe::Stale {
                version: String::new()
            }
        );
        server.abort();
    }

    /// The other half of the contract: a daemon running OUR build is reused, so
    /// the version check cannot degenerate into respawning on every `exec`.
    #[tokio::test]
    async fn a_daemon_of_our_own_version_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = fake_daemon(sock.clone(), Some(CURRENT_VERSION));
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(probe_daemon(&sock).await, DaemonProbe::Current);
        server.abort();
    }

    fn rustls_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    async fn populate(paths: &Paths, session: &str) -> i64 {
        let store = open_store(paths, session).unwrap();
        let w = store.writer();
        let fid = w
            .flow_start(FlowStart {
                workspace_id: 1,
                ts_start: 1000,
                exec_id: Some("e1".into()),
                client_addr: "127.0.0.1:5000".into(),
                dst_ip: "93.184.216.34".into(),
                dst_port: 80,
                sni: Some("example.com".into()),
                scheme: "http".into(),
                protocol: Protocol::H1,
                intercepted: false,
            })
            .await
            .unwrap();
        w.request(
            fid,
            RequestData {
                method: "GET".into(),
                authority: "example.com".into(),
                path: "/search?q=needle".into(),
                http_version: "HTTP/1.1".into(),
                headers: b"Host: example.com\r\nAccept: */*\r\n".to_vec(),
                body: Vec::new(),
            },
        )
        .await
        .unwrap();
        w.response(
            fid,
            ResponseData {
                status: 200,
                http_version: "HTTP/1.1".into(),
                headers: b"Content-Type: text/html\r\n".to_vec(),
                body: b"<html>needle</html>".to_vec(),
                timing_ms: Some(12),
            },
        )
        .await
        .unwrap();
        w.flow_end(fid, 1012).await.unwrap();
        fid
    }

    #[tokio::test]
    async fn req_list_json_shape() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = populate(&paths, "default").await;

        let store = open_store(&paths, "default").unwrap();
        let rows = store.reader().list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, fid);
        let v = serde_json::to_value(&rows).unwrap();
        assert_eq!(v[0]["method"], "GET");
        assert_eq!(v[0]["status"], 200);
    }

    #[tokio::test]
    async fn req_show_detail_json_decodes_bodies() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = populate(&paths, "default").await;

        let store = open_store(&paths, "default").unwrap();
        let detail = store.reader().get_flow(fid).unwrap().unwrap();
        let v = flow_detail_json(&detail);
        assert_eq!(v["request"]["path"], "/search?q=needle");
        assert_eq!(v["response"]["body"], "<html>needle</html>");
        assert_eq!(v["exec_id"], "e1");
    }

    /// The `group` command tree end to end: create (idempotent), populate,
    /// filter `req list` through it, export it, and delete it without losing a
    /// single capture. Also pins the two failure modes an agent will hit —
    /// unknown group NAME and unknown flow id — to their catalogue codes.
    #[tokio::test]
    async fn group_command_tree_roundtrip_and_coded_failures() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = populate(&paths, "default").await;
        let out = Output::new(false);

        // Unknown group name → BW-SESSION-005, not an empty listing.
        let err = cmd_group(
            &out,
            &paths,
            GroupAction::Show {
                name: "auth-flow".into(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(crate::diag::diagnose(&err).code, ErrorCode::GroupNotFound);

        cmd_group(
            &out,
            &paths,
            GroupAction::New {
                name: "auth-flow".into(),
                description: Some("login form -> POST /login".into()),
                workspace: None,
            },
        )
        .await
        .unwrap();
        // Re-creating the same name succeeds (idempotent) instead of erroring.
        cmd_group(
            &out,
            &paths,
            GroupAction::New {
                name: "auth-flow".into(),
                description: None,
                workspace: None,
            },
        )
        .await
        .unwrap();

        // An unknown --workspace is refused rather than silently defaulting.
        let err = cmd_group(
            &out,
            &paths,
            GroupAction::New {
                name: "elsewhere".into(),
                description: None,
                workspace: Some("no-such-workspace".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            crate::diag::diagnose(&err).code,
            ErrorCode::WorkspaceNotFound
        );

        // A bogus flow id fails the whole add.
        let err = cmd_group(
            &out,
            &paths,
            GroupAction::Add {
                name: "auth-flow".into(),
                flow_id: vec![fid, 4242],
            },
        )
        .await
        .unwrap_err();
        assert_eq!(crate::diag::diagnose(&err).code, ErrorCode::InputNoSuchFlow);

        cmd_group(
            &out,
            &paths,
            GroupAction::Add {
                name: "auth-flow".into(),
                flow_id: vec![fid],
            },
        )
        .await
        .unwrap();

        // The group now filters `req list` and scopes a HAR export.
        let store = open_store(&paths, "default").unwrap();
        let group = resolve_group(&store, "auth-flow", None).unwrap();
        assert_eq!(store.reader().group_flow_count(group.id).unwrap(), 1);
        let listed = store
            .reader()
            .list_flows(&FlowFilter {
                group_id: Some(group.id),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, fid);
        let har_out = dir.path().join("group.har");
        let code = cmd_export(
            &out,
            &paths,
            ExportAction::Har {
                workspace: None,
                group: Some("auth-flow".into()),
                output: Some(har_out.to_string_lossy().into_owned()),
            },
        )
        .unwrap();
        assert_eq!(code, 0);
        let har: Value = serde_json::from_slice(&std::fs::read(&har_out).unwrap()).unwrap();
        assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);

        // Removing the flow, then the group, leaves the capture untouched.
        cmd_group(
            &out,
            &paths,
            GroupAction::RmFlow {
                name: "auth-flow".into(),
                flow_id: vec![fid],
            },
        )
        .await
        .unwrap();
        assert_eq!(store.reader().group_flow_count(group.id).unwrap(), 0);
        cmd_group(
            &out,
            &paths,
            GroupAction::Rm {
                name: "auth-flow".into(),
            },
        )
        .await
        .unwrap();
        assert!(store
            .reader()
            .group_by_name("auth-flow", None)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .reader()
                .list_flows(&FlowFilter::default())
                .unwrap()
                .len(),
            1
        );
    }

    /// `export session` → `session import` through the command tree itself: the
    /// hand-over an operator actually types, including the two things that must
    /// not happen quietly (clobbering a session, moving the active pointer).
    #[tokio::test]
    async fn session_bundle_roundtrip_through_the_command_tree() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = populate(&paths, "default").await;
        let out = Output::new(false);

        let bundle = dir.path().join("hand-over.burpwn");
        let code = cmd_export(
            &out,
            &paths,
            ExportAction::Session {
                session: None,
                output: Some(bundle.to_string_lossy().into_owned()),
                redact: false,
                force: false,
            },
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(bundle.is_file());

        let code = cmd_session(
            &out,
            &paths,
            SessionAction::Import {
                file: bundle.to_string_lossy().into_owned(),
                as_name: Some("hand-over".into()),
                use_session: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        assert!(paths.session_exists("hand-over"));
        // Importing does not hijack the active session.
        assert_eq!(paths.active_session(), DEFAULT_SESSION);

        let store = open_store(&paths, "hand-over").unwrap();
        let rows = store.reader().list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, fid);

        // The same bundle a second time: refused, with the code that tells the
        // user how to proceed.
        let err = cmd_session(
            &out,
            &paths,
            SessionAction::Import {
                file: bundle.to_string_lossy().into_owned(),
                as_name: Some("hand-over".into()),
                use_session: false,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(crate::diag::diagnose(&err).code, ErrorCode::SessionExists);

        // Re-exporting onto the same path needs --force.
        let err = cmd_export(
            &out,
            &paths,
            ExportAction::Session {
                session: None,
                output: Some(bundle.to_string_lossy().into_owned()),
                redact: false,
                force: false,
            },
        )
        .unwrap_err();
        assert_eq!(crate::diag::diagnose(&err).code, ErrorCode::InputFileExists);
    }

    #[tokio::test]
    async fn har_export_has_entries() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        populate(&paths, "default").await;

        let store = open_store(&paths, "default").unwrap();
        let reader = store.reader();
        let rows = reader.list_flows(&FlowFilter::default()).unwrap();
        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        let har = har::build_har(&reader, &ids).unwrap();
        assert_eq!(har["log"]["version"], "1.2");
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["request"]["method"], "GET");
        assert_eq!(
            entries[0]["request"]["url"],
            "http://example.com/search?q=needle"
        );
        assert_eq!(entries[0]["response"]["status"], 200);
        // queryString parsed.
        assert_eq!(entries[0]["request"]["queryString"][0]["name"], "q");
    }

    #[tokio::test]
    async fn exec_via_mock_runtime_returns_envelope() {
        rustls_provider();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_base().unwrap();
        paths.ensure_session_dir("default").unwrap();

        let rt = MockRuntime::new();
        rt.set_canned(ExecOutcome {
            exit_code: 3,
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
        let dyn_rt: Arc<dyn SandboxRuntime> = rt.clone();

        let code = cmd_exec(
            true,
            &paths,
            ExecArgs {
                workspace: None,
                timeout: Some(5),
                session: Some("default".into()),
                cmd: vec!["curl".into(), "http://example.com".into()],
            },
            Some(dyn_rt),
        )
        .await
        .unwrap();
        assert_eq!(code, 3);
        // The CA was generated as part of exec.
        assert!(paths.ca_pem().exists());
        // The mock saw our argv.
        assert_eq!(
            rt.last_spec().unwrap().argv,
            vec!["curl", "http://example.com"]
        );
    }

    #[tokio::test]
    async fn exec_rejects_traversal_session_name() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_base().unwrap();

        // A traversal session name must be rejected before any path is built,
        // and crucially before a session dir/DB is created outside sessions/.
        let rt = MockRuntime::new();
        let dyn_rt: Arc<dyn SandboxRuntime> = rt.clone();
        let err = cmd_exec(
            true,
            &paths,
            ExecArgs {
                workspace: None,
                timeout: Some(5),
                session: Some("../../foo".into()),
                cmd: vec!["true".into()],
            },
            Some(dyn_rt),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid session name"),
            "unexpected error: {err}"
        );
        // No escape: nothing was created above the sessions dir.
        assert!(!dir.path().join("foo").exists());
        // An absolute path is rejected too.
        let rt2 = MockRuntime::new();
        let dyn_rt2: Arc<dyn SandboxRuntime> = rt2.clone();
        let err = cmd_exec(
            true,
            &paths,
            ExecArgs {
                workspace: None,
                timeout: Some(5),
                session: Some("/tmp/abs".into()),
                cmd: vec!["true".into()],
            },
            Some(dyn_rt2),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid session name"));
    }

    #[tokio::test]
    async fn proxy_rejects_traversal_session_name() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_base().unwrap();

        let err = cmd_proxy(
            &paths,
            ProxyArgs {
                session: Some("../../escape".into()),
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid session name"),
            "unexpected error: {err}"
        );
        // The daemon never ran, so no runtime dir leaked outside the base.
        assert!(!dir.path().join("escape").exists());
    }

    /// `export har -o <path>` must refuse to write *through* an existing symlink
    /// at the target, so an attacker-seeded link can't redirect the HAR onto a
    /// victim file. A regular (non-symlink) target still writes fine.
    #[tokio::test]
    async fn export_har_refuses_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        let session = "default";
        paths.ensure_session_dir(session).unwrap();
        populate(&paths, session).await;
        let out = Output::new(false);

        // Seed a symlink at the output path pointing at a "victim" file.
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"do not clobber").unwrap();
        let link = dir.path().join("out.har");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = cmd_export(
            &out,
            &paths,
            ExportAction::Har {
                workspace: None,
                group: None,
                output: Some(link.to_string_lossy().into_owned()),
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
        // The victim file was not overwritten.
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not clobber");

        // A plain target writes normally.
        let plain = dir.path().join("plain.har");
        let code = cmd_export(
            &out,
            &paths,
            ExportAction::Har {
                workspace: None,
                group: None,
                output: Some(plain.to_string_lossy().into_owned()),
            },
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(plain.exists());
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        let out = Output::new(false);

        cmd_session(
            &out,
            &paths,
            SessionAction::New {
                name: Some("work".into()),
            },
        )
        .await
        .unwrap();
        assert!(paths.session_exists("work"));
        assert_eq!(paths.active_session(), "work");

        cmd_session(
            &out,
            &paths,
            SessionAction::New {
                name: Some("scratch".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(paths.list_sessions(), vec!["scratch", "work"]);

        cmd_session(
            &out,
            &paths,
            SessionAction::Use {
                name: "scratch".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(paths.active_session(), "scratch");

        cmd_session(
            &out,
            &paths,
            SessionAction::Rm {
                name: "scratch".into(),
            },
        )
        .await
        .unwrap();
        assert!(!paths.session_exists("scratch"));
        // active pointer reset to default after removing the active session.
        assert_eq!(paths.active_session(), DEFAULT_SESSION);
    }

    #[test]
    fn daemon_lock_is_mutually_exclusive() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("daemon.lock");

        // Hold the lock on this thread.
        let held = DaemonLock::acquire(&lock_path).unwrap();

        // A second thread must block on acquire until we drop ours.
        let inside = Arc::new(AtomicUsize::new(0));
        let inside2 = inside.clone();
        let lp = lock_path.clone();
        let t = std::thread::spawn(move || {
            let _l = DaemonLock::acquire(&lp).unwrap();
            inside2.store(1, Ordering::SeqCst);
        });

        // Give the thread a chance to (fail to) acquire.
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            inside.load(Ordering::SeqCst),
            0,
            "second acquire must block while the first lock is held"
        );

        drop(held);
        t.join().unwrap();
        assert_eq!(inside.load(Ordering::SeqCst), 1);
    }

    // --- rendering ---------------------------------------------------------
    //
    // The formatters are pure `(data, mode) -> String`, so both renderings are
    // pinned here without a terminal, a subprocess or a snapshot file. What is
    // being defended is the RULE: a pipe gets the data and nothing else.

    #[tokio::test]
    async fn flow_listing_renders_data_only_to_a_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let fid = populate(&paths, "default").await;
        let store = open_store(&paths, "default").unwrap();
        let rows = store.reader().list_flows(&FlowFilter::default()).unwrap();

        let mut t = flow_table(&rows);
        t.footer("1 flows  ·  workspace default");

        let terse = t.render(&Render::terse());
        assert_eq!(
            terse,
            format!("{fid}\th1\tGET\thttp://example.com/search?q=needle\t200")
        );
        assert!(!terse.contains("METHOD"), "header leaked into a pipe");
        assert!(!terse.contains('·'), "footer leaked into a pipe");

        let pretty = t.render(&Render::pretty(100).without_color());
        let lines: Vec<&str> = pretty.lines().collect();
        assert!(lines[0].contains("METHOD") && lines[0].contains("STATUS"));
        assert!(lines[1].contains("http://example.com/search?q=needle"));
        assert_eq!(
            lines.last().unwrap().trim(),
            "1 flows  ·  workspace default"
        );
    }

    #[tokio::test]
    async fn an_empty_listing_says_nothing_to_a_pipe() {
        let t = flow_table(&[]);
        assert_eq!(listing(&Render::terse(), &t, "(no flows)"), "");
        assert_eq!(
            listing(&Render::pretty(80).without_color(), &t, "(no flows)"),
            "  (no flows)"
        );
    }

    /// A long URL used to break the alignment of the whole listing, because the
    /// widths were literals (`{:>6}`) rather than measurements. On a terminal it
    /// is now the URL that gives ground; in a pipe nothing is lost at all.
    #[test]
    fn a_long_url_truncates_on_a_terminal_and_never_in_a_pipe() {
        let long = format!("/v2/users/4711/permissions/{}", "e".repeat(120));
        let rows = vec![burpwn_store::model::FlowRow {
            id: 15,
            workspace_id: 1,
            ts_start: 0,
            ts_end: None,
            protocol: Protocol::H1,
            scheme: "https".into(),
            dst_ip: "10.0.0.1".into(),
            dst_port: 443,
            sni: None,
            method: Some("GET".into()),
            authority: Some("api.example.com".into()),
            path: Some(long.clone()),
            status: Some(403),
            intercepted: false,
        }];
        let t = flow_table(&rows);
        let pretty = t.render(&Render::pretty(80).without_color());
        assert!(pretty.contains('…'));
        for line in pretty.lines() {
            assert!(line.chars().count() <= 80, "{line:?}");
        }
        // The id and the status — what the next command takes as arguments —
        // survive the squeeze intact.
        assert!(pretty.contains("15"));
        assert!(pretty.contains("403"));
        let terse = t.render(&Render::terse());
        assert!(terse.ends_with(&format!("{long}\t403")));
    }

    #[test]
    fn doctor_report_renders_both_modes() {
        let pf = burpwn_sandbox::Preflight {
            userns_enabled: true,
            subuid_present: true,
            bwrap_present: true,
            nft_present: false,
            ip_present: true,
        };
        let terse = doctor_report(&Render::terse(), &pf, false, None, true, false);
        assert!(terse.contains("nftables\tNO\tnft"), "{terse}");
        assert!(terse.contains("CA\tNO\t"), "{terse}");
        // The verdict and the remediation are for a human: the exit code and
        // the `--json` payload already carry them for everyone else.
        assert!(!terse.contains("NOT ready"), "{terse}");

        let pretty = doctor_report(
            &Render::pretty(90).without_color(),
            &pf,
            false,
            None,
            true,
            false,
        );
        assert!(pretty.contains("NOT ready — "), "{pretty}");
        assert!(pretty.starts_with("  unprivileged userns  yes"), "{pretty}");
    }

    /// Regression: these values arrive as `serde_json::Value`s, and formatting
    /// one directly means `{:>6}` pads nothing and a string payload prints with
    /// its JSON quotes on.
    #[test]
    fn fuzz_rows_format_scalars_not_json_values() {
        let row = fuzz_result_row(
            &json!(3),
            &json!(500),
            &json!(1234),
            &json!(42),
            &json!(0.8712),
            &json!(["' OR 1=1--"]),
        );
        let texts: Vec<&str> = row.iter().map(Cell::text).collect();
        assert_eq!(texts, vec!["3", "500", "1234", "42", "0.871", "' OR 1=1--"]);

        // A request that never got a response has no status and no length.
        let row = fuzz_result_row(
            &json!(4),
            &Value::Null,
            &Value::Null,
            &json!(9),
            &Value::Null,
            &json!("x"),
        );
        let texts: Vec<&str> = row.iter().map(Cell::text).collect();
        assert_eq!(texts, vec!["4", "", "", "9", "0.000", "x"]);

        // …and the columns line up, which is the point of measuring them.
        let mut t = fuzz_result_table("id");
        t.row(fuzz_result_row(
            &json!(1),
            &json!(200),
            &json!(9),
            &json!(3),
            &json!(0.1),
            &json!("a"),
        ));
        t.row(fuzz_result_row(
            &json!(2),
            &json!(500),
            &json!(123456),
            &json!(1200),
            &json!(0.99),
            &json!("bb"),
        ));
        let pretty = t.render(&Render::pretty(100).without_color());
        let cols: Vec<usize> = pretty
            .lines()
            .skip(1)
            .map(|l| l.find("0.").expect("an anomaly score on every data row"))
            .collect();
        assert_eq!(cols[0], cols[1], "anomaly column is not aligned: {pretty}");
    }

    #[test]
    fn compare_report_is_rows_not_pretty_printed_json() {
        let v = json!({
            "status": { "a": 200, "b": 403, "changed": true },
            "headers": {
                "added": [{ "name": "X-Trace", "value": "abc" }],
                "removed": [],
                "changed": [{ "name": "Content-Length", "a": "12", "b": "40" }],
            },
            "body": {
                "identical": false,
                "len_a": 12,
                "len_b": 40,
                "only_in_a": [],
                "only_in_b": ["denied"],
                "reflected": ["needle"],
            },
        });
        let terse = compare_report(&Render::terse(), &v);
        assert!(terse.contains("status\t200 -> 403"), "{terse}");
        assert!(terse.contains("header +\tX-Trace\tabc"), "{terse}");
        assert!(
            terse.contains("header ~\tContent-Length\t12 -> 40"),
            "{terse}"
        );
        assert!(terse.contains("reflected\tneedle"), "{terse}");
        // No JSON punctuation survives into the human/pipe rendering.
        assert!(!terse.contains('{'), "{terse}");
    }

    #[tokio::test]
    async fn match_replace_add_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let out = Output::new(false);

        cmd_match_replace(
            &out,
            &paths,
            MatchReplaceAction::Add {
                scope: "*.example.com".into(),
                kind: "header".into(),
                pattern: "User-Agent: .*".into(),
                replacement: "User-Agent: burpwn".into(),
                on: "request".into(),
            },
        )
        .await
        .unwrap();

        let store = open_store(&paths, "default").unwrap();
        let rules = store.reader().list_match_replace().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].match_kind, MatchKind::Header);
        assert!(rules[0].on_request);
    }

    /// A typo'd kind used to sail through as a BODY rule. It must be refused at
    /// the point of entry, with the accepted spellings in the message, and leave
    /// nothing behind in the store.
    #[tokio::test]
    async fn match_replace_add_rejects_an_unknown_kind() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_base(dir.path());
        paths.ensure_session_dir("default").unwrap();
        let out = Output::new(false);

        let err = cmd_match_replace(
            &out,
            &paths,
            MatchReplaceAction::Add {
                scope: "*.example.com".into(),
                kind: "heder".into(),
                pattern: "^X:.*".into(),
                replacement: "X: y".into(),
                on: "request".into(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(
            crate::diag::diagnose(&err).code,
            ErrorCode::InputInvalidValue
        );
        let msg = err.to_string();
        for v in MatchKind::VALID {
            assert!(msg.contains(v), "{msg} should list {v}");
        }
        assert!(msg.contains("heder"), "{msg}");

        let store = open_store(&paths, "default").unwrap();
        assert!(
            store.reader().list_match_replace().unwrap().is_empty(),
            "a refused kind must not leave a rule behind"
        );
    }
}
