//! Command dispatch: maps the parsed [`crate::cli::Command`] tree onto the store,
//! proxy, sandbox, TLS and wrap layers, rendering either human text or the JSON
//! envelope per the global `--json` flag.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use burpwn_error::ErrorCode;
use burpwn_sandbox::{deep_probe, doctor, RootlessRuntime, SandboxRuntime};
use burpwn_store::model::{FlowFilter, MatchKind, NewMatchReplaceRule, Protocol};
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
use crate::{har, replay, wrap_hook};

/// How long `exec` waits for a freshly-spawned daemon's control socket.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// A renderer that prints either human text or a JSON envelope, tracking whether
/// any output has been emitted to stdout (so `exec` knows whether to use fd 3).
pub struct Output {
    json: bool,
}

impl Output {
    fn new(json: bool) -> Self {
        Self { json }
    }

    /// Emit a success result: `human` text in normal mode, the envelope in JSON.
    fn ok(&self, human: impl AsRef<str>, data: Value) {
        if self.json {
            println!("{}", Envelope::ok(data).to_json_line());
        } else {
            let h = human.as_ref();
            if !h.is_empty() {
                println!("{h}");
            }
        }
    }
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
        Command::Workspace { action } => cmd_workspace(&out, paths, action).await,
        Command::Tag { action } => cmd_tag(&out, paths, action).await,
        Command::Note { action } => cmd_note(&out, paths, action).await,
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
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(json!({ "targets": rows })).to_json_line()
                );
            } else {
                println!("Supported skill targets:");
                for t in skill::targets() {
                    let global = t.global_rel.unwrap_or("(project only)");
                    println!(
                        "  {:<12} {:<18} project={}  global={}",
                        t.slug,
                        t.format.label(),
                        t.project_rel,
                        global
                    );
                    if !t.note.is_empty() {
                        println!("               note: {}", t.note);
                    }
                }
            }
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
        if out.json {
            println!("{}", Envelope::ok(json!({ "hosts": rows })).to_json_line());
        } else {
            println!("Supported MCP hosts (config relative to HOME):");
            for h in mcpreg::hosts() {
                println!(
                    "  {:<12} {:<5} {}",
                    h.slug,
                    match h.kind {
                        mcpreg::McpKind::Toml => "toml",
                        mcpreg::McpKind::Json => "json",
                    },
                    h.config_rel
                );
            }
        }
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

    if out.json {
        println!("{}", Envelope::ok(data).to_json_line());
        return Ok(if ok { 0 } else { 1 });
    }

    let yn = |b: bool| if b { "yes" } else { "NO" };
    println!("burpwn doctor:");
    println!("  unprivileged userns : {}", yn(pf.userns_enabled));
    println!("  subuid entry        : {}", yn(pf.subuid_present));
    println!("  bwrap               : {}", yn(pf.bwrap_present));
    println!("  nft                 : {}", yn(pf.nft_present));
    println!("  ip                  : {}", yn(pf.ip_present));
    println!("  CA present          : {}", yn(ca_present));
    if let Some(p) = &probe {
        println!("  live sandbox probe  :");
        for step in &p.steps {
            let mark = if step.ok {
                "ok"
            } else if step.required {
                "FAIL"
            } else {
                "degraded"
            };
            print!("    {:<14} {mark}", step.name);
            if step.ok {
                println!();
            } else {
                println!(" — {}", step.detail.trim().replace('\n', " "));
            }
        }
        if p.wsl {
            println!("  host                : WSL");
        }
    } else if args.quick {
        println!("  live sandbox probe  : skipped (--quick)");
    }

    if ok {
        println!("=> ready");
    } else {
        let mut missing = pf.missing_summary();
        if !ca_present {
            if !missing.is_empty() {
                missing.push_str(", ");
            }
            missing.push_str("CA (run `burpwn ca init`)");
        }
        if let Some(p) = &probe {
            if !p.is_ok() {
                if !missing.is_empty() {
                    missing.push_str(", ");
                }
                missing.push_str(&p.summary());
            }
        }
        println!("=> NOT ready: {missing}");
        for line in probe.as_ref().map(|p| p.remediation()).unwrap_or_default() {
            println!("   - {line}");
        }
    }
    Ok(if ok { 0 } else { 1 })
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

    if out.json {
        println!(
            "{}",
            Envelope::ok(json!({"path": path.display().to_string(), "bytes": body.len()}))
                .to_json_line()
        );
    } else {
        println!("debug report written to {}", path.display());
        println!("it contains no credentials (env values and token-shaped strings are redacted)");
    }
    Ok(0)
}

fn cmd_debug_list(out: &Output, paths: &Paths) -> Result<i32> {
    let dir = paths.debug_dir();
    let reports = debugreport::recent(&dir, 100);
    if out.json {
        let items: Vec<Value> = reports
            .iter()
            .map(|p| json!({"path": p.display().to_string()}))
            .collect();
        println!("{}", Envelope::ok(json!({"reports": items})).to_json_line());
        return Ok(0);
    }
    if reports.is_empty() {
        println!(
            "no debug reports in {} (nothing has failed yet)",
            dir.display()
        );
        return Ok(0);
    }
    println!("debug reports in {} (newest first):", dir.display());
    for path in &reports {
        println!("  {}", path.display());
    }
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
    if out.json {
        // Re-emit as data so `--json` stays one envelope per invocation.
        let doc: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        println!("{}", Envelope::ok(doc).to_json_line());
    } else {
        println!("{body}");
    }
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

    if out.json {
        println!(
            "{}",
            Envelope::ok(json!({ "checks": data, "ok": !failed })).to_json_line()
        );
    } else {
        for r in &reports {
            let mark = match r.verdict {
                Verdict::Pass => "PASS",
                Verdict::Fail => "FAIL",
                Verdict::Advisory => "ADVISORY",
            };
            println!("  {mark:<8} {:<12} {}", r.agent, r.detail);
        }
        if failed {
            println!("=> FAIL: at least one agent does not rewrite commands through `burpwn exec`");
        } else {
            println!("=> ok");
        }
    }
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
            if out.json {
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
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(json!({ "active": active, "sessions": names })).to_json_line()
                );
            } else if names.is_empty() {
                println!("(no sessions)");
            } else {
                for n in &names {
                    let marker = if *n == active { "*" } else { " " };
                    println!("{marker} {n}");
                }
            }
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
        SessionAction::Stats { session } => cmd_session_stats(out, paths, session),
        SessionAction::Auth { action } => cmd_session_auth(out, paths, action).await,
    }
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

    if out.json {
        println!(
            "{}",
            Envelope::ok(json!({
                "session": session,
                "total_execs": stats.total_execs,
                "total_flows": stats.total_flows,
                "network_execs": stats.network_execs,
                "network_zero_flow_execs": stats.network_zero_flow_execs,
                "escaped_execs": escaped,
            }))
            .to_json_line()
        );
    } else {
        println!("session {session}:");
        println!("  execs recorded        : {}", stats.total_execs);
        println!("  flows captured        : {}", stats.total_flows);
        println!("  network-facing execs  : {}", stats.network_execs);
        println!(
            "  network execs w/ ZERO captures : {}",
            stats.network_zero_flow_execs
        );
        if !escaped.is_empty() {
            println!("  ⚠ traffic likely escaped capture for:");
            for e in &escaped {
                println!("      {}", e["cmd"].as_str().unwrap_or("-"));
            }
            println!("    (run `burpwn init --check` to verify the agent hook)");
        }
    }
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
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(json!({ "profiles": view })).to_json_line()
                );
            } else if profiles.is_empty() {
                println!("(no auth profiles)");
            } else {
                for p in &profiles {
                    let scope = if p.host.is_empty() { "*" } else { &p.host };
                    let tok = match &p.token {
                        Some(t) => crate::auth::mask_token(t),
                        None => "(none)".into(),
                    };
                    println!(
                        "  {:>3} {:<24} header={:?} token={tok}",
                        p.id, scope, p.header_template
                    );
                }
            }
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

    if out.json {
        println!(
            "{}",
            Envelope::ok(json!({ "refreshed": results })).to_json_line()
        );
    } else {
        for r in &results {
            println!(
                "refreshed auth for {} (rule {}, token {})",
                r["host"].as_str().unwrap_or("*"),
                r["rule_id"],
                r["token"].as_str().unwrap_or("")
            );
        }
    }
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
    let filter = FlowFilter {
        workspace_id,
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
    if out.json {
        println!(
            "{}",
            Envelope::ok(serde_json::to_value(&rows)?).to_json_line()
        );
    } else if rows.is_empty() {
        println!("(no flows)");
    } else {
        for r in &rows {
            println!(
                "{:>6}  {:<5} {:<4} {}://{}{}  -> {}",
                r.id,
                r.protocol.as_str(),
                r.method.as_deref().unwrap_or("-"),
                r.scheme,
                r.authority
                    .as_deref()
                    .or(r.sni.as_deref())
                    .unwrap_or(&r.dst_ip),
                r.path.as_deref().unwrap_or(""),
                r.status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into()),
            );
        }
    }
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

    if out.json {
        println!("{}", Envelope::ok(flow_detail_json(&detail)).to_json_line());
    } else {
        println!(
            "flow {id}: {} -> {}",
            detail.client_addr, detail.flow.dst_ip
        );
        if let Some(req) = &detail.request {
            println!(
                "  request: {} {} ({} bytes body)",
                req.method,
                req.path,
                req.body.len()
            );
        }
        if let Some(resp) = &detail.response {
            println!(
                "  response: {} ({} bytes body)",
                resp.status,
                resp.body.len()
            );
        }
        if !detail.tags.is_empty() {
            println!("  tags: {}", detail.tags.join(", "));
        }
        for note in &detail.notes {
            println!("  note: {note}");
        }
    }
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
    if out.json {
        println!(
            "{}",
            Envelope::ok(json!({ "flow_ids": ids })).to_json_line()
        );
    } else if ids.is_empty() {
        println!("(no matches)");
    } else {
        for id in &ids {
            println!("{id}");
        }
    }
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

    if out.json {
        println!(
            "{}",
            Envelope::ok(json!({
                "status": result.status,
                "response": String::from_utf8_lossy(&result.raw_response),
            }))
            .to_json_line()
        );
    } else {
        println!("replayed flow {} -> {}", args.id, result.status);
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
    if out.json {
        println!("{}", Envelope::ok(data).to_json_line());
        return Ok(());
    }
    match resp {
        ControlResponse::Status {
            session,
            intercept_enabled,
            pending,
            dns_port,
            ..
        } => {
            println!(
                "session {session}: intercept {}, {pending} pending, dns_port {dns_port}",
                if intercept_enabled { "ON" } else { "off" }
            );
        }
        ControlResponse::Ack => println!("ok"),
        ControlResponse::Intercepts { items } => {
            if items.is_empty() {
                println!("(no parked intercepts)");
            }
            for i in items {
                println!(
                    "{:>4} {:<8} {} {} {}",
                    i.id, i.kind, i.method, i.host, i.path
                );
            }
        }
        ControlResponse::Pending { item } => match item {
            Some(i) => println!("{} {} {} {} {}", i.id, i.kind, i.method, i.host, i.path),
            None => println!("(timed out, none parked)"),
        },
        ControlResponse::Resolved { found } => {
            println!("resolved");
            let _ = found; // `found: false` is rejected before we get here.
        }
        // Already turned into a coded failure above.
        ControlResponse::Error { .. } => unreachable!("handled before rendering"),
    }
    Ok(())
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
            let id = store
                .writer()
                .add_match_replace(NewMatchReplaceRule {
                    enabled: true,
                    scope,
                    match_kind: MatchKind::from_db(&kind),
                    pattern,
                    replacement,
                    on_request,
                })
                .await?;
            out.ok(format!("added rule {id}"), json!({ "id": id }));
        }
        MatchReplaceAction::List => {
            let rules = store.reader().list_match_replace()?;
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(serde_json::to_value(&rules)?).to_json_line()
                );
            } else if rules.is_empty() {
                println!("(no rules)");
            } else {
                for r in &rules {
                    println!(
                        "{:>4} [{}] {} {:?} {:?} -> {:?} ({})",
                        r.id,
                        if r.enabled { "on" } else { "off" },
                        r.scope,
                        r.match_kind,
                        r.pattern,
                        r.replacement,
                        if r.on_request { "request" } else { "response" }
                    );
                }
            }
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
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(serde_json::to_value(&ws)?).to_json_line()
                );
            } else {
                for w in &ws {
                    println!("{:>4} {}", w.id, w.name);
                }
            }
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
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(serde_json::to_value(&tags)?).to_json_line()
                );
            } else if tags.is_empty() {
                println!("(no tags)");
            } else {
                for t in &tags {
                    match &t.color {
                        Some(c) => println!("{:>4} {} ({c})", t.id, t.name),
                        None => println!("{:>4} {}", t.id, t.name),
                    }
                }
            }
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
            if out.json {
                println!(
                    "{}",
                    Envelope::ok(serde_json::to_value(&notes)?).to_json_line()
                );
            } else if notes.is_empty() {
                println!("(no notes)");
            } else {
                for n in &notes {
                    println!("{:>4} {}", n.id, n.body);
                }
            }
        }
    }
    Ok(0)
}

// --- export ----------------------------------------------------------------

fn cmd_export(out: &Output, paths: &Paths, action: ExportAction) -> Result<i32> {
    let session = paths.active_session();
    match action {
        ExportAction::Har { workspace, output } => {
            let store = open_store(paths, &session)?;
            let reader = store.reader();
            let rows = reader.list_flows(&FlowFilter {
                workspace_id: workspace,
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
                    // reachable from agent-driven automation). `symlink_metadata`
                    // does not follow the final component, so a symlink is caught.
                    if let Ok(meta) = std::fs::symlink_metadata(&path) {
                        if meta.file_type().is_symlink() {
                            crate::fail!(
                                ErrorCode::InputUnsafePath,
                                "refusing to write HAR through an existing symlink: {path}"
                            );
                        }
                    }
                    std::fs::write(&path, &text).with_context(|| format!("writing {path}"))?;
                    out.ok(
                        format!("wrote {entry_count} entries to {path}"),
                        json!({ "path": path, "entries": entry_count }),
                    );
                }
                None => {
                    if out.json {
                        println!("{}", Envelope::ok(har).to_json_line());
                    } else {
                        println!("{text}");
                    }
                }
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

async fn cmd_fuzz(out: &Output, paths: &Paths, action: FuzzAction) -> Result<i32> {
    let session = paths.active_session();
    match action {
        FuzzAction::Run(args) => cmd_fuzz_run(out, paths, &session, args).await,
        FuzzAction::List { workspace } => {
            let v = crate::fuzz::fuzz_list(paths, &session, workspace.as_deref())?;
            if out.json {
                println!("{}", Envelope::ok(v).to_json_line());
            } else {
                let empty = Vec::new();
                let rows = v["attacks"].as_array().unwrap_or(&empty);
                if rows.is_empty() {
                    println!("(no attacks)");
                }
                for a in rows {
                    println!(
                        "{:>4} [{}] {} (flow {}, {} results)",
                        a["id"].as_i64().unwrap_or(0),
                        a["status"].as_str().unwrap_or("-"),
                        a["name"].as_str().unwrap_or("-"),
                        a["base_flow_id"],
                        a["results"].as_i64().unwrap_or(0),
                    );
                }
            }
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
            if out.json {
                println!("{}", Envelope::ok(v).to_json_line());
            } else {
                let empty = Vec::new();
                let rows = v["results"].as_array().unwrap_or(&empty);
                if rows.is_empty() {
                    println!("(no results)");
                }
                for r in rows {
                    println!(
                        "{:>4}  {:>3}  len {:>6}  {:>5}ms  anomaly {:.3}  {}",
                        r["id"].as_i64().unwrap_or(0),
                        r["status_code"],
                        r["resp_len"],
                        r["latency_ms"],
                        r["anomaly_score"].as_f64().unwrap_or(0.0),
                        r["payload"].as_str().unwrap_or(""),
                    );
                }
            }
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

    if out.json {
        println!("{}", Envelope::ok(v).to_json_line());
    } else {
        println!(
            "attack {} ({}): {} results, status {}",
            v["attack_id"].as_i64().unwrap_or(0),
            v["mode"].as_str().unwrap_or("-"),
            v["results"].as_array().map(|a| a.len()).unwrap_or(0),
            v["status"].as_str().unwrap_or("-"),
        );
        if let Some(b) = v["baseline"].as_object() {
            println!("  baseline: status {} len {}", b["status"], b["resp_len"]);
        }
        let empty = Vec::new();
        for r in v["results"].as_array().unwrap_or(&empty) {
            println!(
                "  {:>4}  {:>3}  len {:>6}  {:>5}ms  anomaly {:.3}  {}",
                r["index"].as_i64().unwrap_or(0),
                r["status"],
                r["resp_len"],
                r["latency_ms"],
                r["anomaly"].as_f64().unwrap_or(0.0),
                r["payloads"],
            );
        }
    }
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
    if out.json {
        println!("{}", Envelope::ok(v).to_json_line());
    } else {
        println!("{}", serde_json::to_string_pretty(&v)?);
    }
    Ok(0)
}

// --- encode / decode --------------------------------------------------------

fn cmd_encode(out: &Output, scheme: &str, value: &str) -> Result<i32> {
    let v = crate::encode::encode(scheme, value)?;
    if out.json {
        println!("{}", Envelope::ok(v).to_json_line());
    } else {
        println!("{}", v["encoded"].as_str().unwrap_or(""));
    }
    Ok(0)
}

fn cmd_decode(out: &Output, scheme: &str, value: &str) -> Result<i32> {
    let v = crate::encode::decode(scheme, value)?;
    if out.json {
        println!("{}", Envelope::ok(v).to_json_line());
    } else if scheme.eq_ignore_ascii_case("jwt") {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{}", v["decoded"].as_str().unwrap_or(""));
    }
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
}
