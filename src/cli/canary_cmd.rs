//! `tallow canary cycle` — the L4 detection-ops cycle (P1 W4-D1/D2).
//!
//! One cycle, all steps recorded to the run-evidence JSONL
//! (`TALLOW_RUN_EVIDENCE_DIR`, defaulted to `<out>/evidence`):
//!
//! 1. **quiet gate** — consult `quiet_window::ingest_allowed` for this instant
//!    and record the decision (a deferred ingest exits 3 unless `--force`).
//! 2. **render + verify** — build a canary page (`canary_page::render_page`)
//!    carrying `--count` fresh tokens, verify every token round-trips
//!    (`verify_embed`), and write `canary_page.html` into the out dir.
//! 3. **observe** — scan each `--observe FILE` (real fetched content, e.g. the
//!    scrape-demo fetch output) for this cycle's canaries: a hit in observed
//!    content is a **leak** (recorded per origin); zero hits is a clean
//!    observation (also recorded).
//! 4. **leak control** — a held-out synthetic observation carrying one canary
//!    MUST alert; a sweep that cannot fire is not evidence.
//! 5. **sweep + report** — `canary_monitor::sweep` + `alert_report`; the
//!    report lands in `<out>/canary_report.txt`, per-step records in the
//!    run-evidence JSONL, and a machine summary in
//!    `<out>/canary_cycle_summary.json`.
//!
//! Subcommand `burn-cycle` (P1 W5-P2) instead runs the persona burn-cycle
//! drill on an in-memory registry: create → use → canary-trigger → burn →
//! refuse (re-use, re-registration, hard-fail, double-burn). Refusals are
//! asserted, not assumed: any step that fails to refuse is a cycle FAILURE.
//! Writes `<out>/burn_cycle.json`. Exit: 0 valid, 2 failed check, 64 usage.
//!
//! Exit codes: `0` = valid cycle (verified, no real leaks, control fired);
//! `2` = cycle FAILED a check (fail loud — never a quiet pass); `3` = deferred
//! by the quiet window; `64` = usage error.

use std::path::PathBuf;

use crate::canary_monitor::Observation;
use crate::canary_page::CanaryPageConfig;
use crate::quiet_window::QuietConfig;
use crate::run_evidence;

struct CycleArgs {
    out: PathBuf,
    count: usize,
    site: String,
    title: String,
    observe: Vec<PathBuf>,
    json: bool,
    force: bool,
}

const USAGE: &str = "tallow canary cycle [--out DIR] [--count N] [--site NAME] [--title T]\n\
                         [--observe FILE]... [--json] [--force]\n\
\n\
  Runs one detection-ops canary cycle: quiet-gate consult, canary-page\n\
  render+verify, observation scan (leaks), held-out leak control, sweep +\n\
  report. Evidence records go to $TALLOW_RUN_EVIDENCE_DIR (default:\n\
  <out>/evidence). Exit: 0 valid, 2 failed check, 3 quiet-window deferred,\n\
  64 usage.";

fn print_help() {
    eprintln!("Usage: {USAGE}");
}

fn parse_args(argv: &[String]) -> Result<CycleArgs, String> {
    let mut out: Option<PathBuf> = None;
    let mut count: usize = 5;
    let mut site = "canary.local".to_string();
    let mut title = "Tallow canary page".to_string();
    let mut observe: Vec<PathBuf> = Vec::new();
    let mut json = false;
    let mut force = false;

    let mut it = argv.iter();
    // argv[0] must be the subcommand (main dispatches `canary` with trailing args).
    match it.next() {
        Some(s) if s == "cycle" => {}
        Some(other) => return Err(format!("unknown canary subcommand {other:?}")),
        None => return Err("missing subcommand (expected `cycle`)".to_string()),
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(it.next().ok_or("--out needs a path")?)),
            "--count" => {
                count = it
                    .next()
                    .ok_or("--count needs a number")?
                    .parse()
                    .map_err(|_| "--count must be a number".to_string())?
            }
            "--site" => site = it.next().ok_or("--site needs a value")?.clone(),
            "--title" => title = it.next().ok_or("--title needs a value")?.clone(),
            "--observe" => observe.push(PathBuf::from(it.next().ok_or("--observe needs a path")?)),
            "--json" => json = true,
            "--force" => force = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    let out = out.unwrap_or_else(|| {
        PathBuf::from(format!(
            "canary-cycle-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ))
    });
    Ok(CycleArgs {
        out,
        count,
        site,
        title,
        observe,
        json,
        force,
    })
}

/// Origin label for an observation: the file name (never the full temp path).
fn origin_label(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

pub fn run_canary_args(argv: &[String]) -> i32 {
    if argv.first().map(String::as_str) == Some("burn-cycle") {
        return match parse_burn_cycle_args(argv) {
            Ok(a) => run_burn_cycle(&a),
            Err(e) => {
                eprintln!("canary: {e}");
                eprintln!("Usage: {BURN_CYCLE_USAGE}");
                64
            }
        };
    }
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("canary: {e}");
            print_help();
            return 64;
        }
    };
    run_cycle(&args)
}

fn run_cycle(args: &CycleArgs) -> i32 {
    // Evidence sink: default to <out>/evidence so a cycle always carries its
    // own records (the run-evidence sink is otherwise opt-in).
    let env_set = std::env::var(run_evidence::RUN_EVIDENCE_DIR_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if !env_set {
        let ev = args.out.join("evidence");
        // Single-threaded at this point in the CLI; the sink is process-global
        // by design (same pattern as the runtime's env-lock users).
        unsafe { std::env::set_var(run_evidence::RUN_EVIDENCE_DIR_ENV, &ev) };
    }
    if std::fs::create_dir_all(&args.out).is_err() {
        eprintln!("canary cycle: cannot create out dir {}", args.out.display());
        return 2;
    }

    // Step 1: quiet-window gate (consulted + recorded; a future config with
    // windows can defer the cycle).
    let now = run_evidence::now_ms();
    let quiet = QuietConfig {
        windows: vec![],
        consolidation_ms: 0,
        digest_size: 5,
        interrupt_severity: 2,
    };
    let allowed = run_evidence::quiet_gate(&quiet, None, now);
    if !allowed && !args.force {
        println!("canary cycle: deferred by quiet window (use --force to override)");
        return 3;
    }

    // Step 2: render + verify the canary page.
    let page_cfg = CanaryPageConfig {
        site: args.site.clone(),
        title: args.title.clone(),
        count: args.count,
    };
    let (page, verified) = match run_evidence::canary_page_check(&page_cfg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("canary cycle: canary page error: {e:?}");
            return 2;
        }
    };
    let page_path = args.out.join("canary_page.html");
    if let Err(e) = std::fs::write(&page_path, &page) {
        eprintln!("canary cycle: cannot write {}: {e}", page_path.display());
        return 2;
    }
    let canaries = crate::canary_page::tokens_in(&page);
    let mut failures: Vec<String> = Vec::new();
    if verified != args.count {
        failures.push(format!(
            "verify_embed returned {verified} tokens, configured {}",
            args.count
        ));
    }
    if canaries.len() != args.count {
        failures.push(format!(
            "tokens_in(page) = {} tokens, configured {}",
            canaries.len(),
            args.count
        ));
    }
    // Digest batching over the cycle's token set (exercises the quiet-window
    // digest path with real inputs; recorded).
    let _ = run_evidence::digest_pending(&quiet, &canaries);

    // Step 3: observations (live fetched content fed by the runner).
    let mut observations: Vec<Observation> = Vec::new();
    let mut observed: Vec<serde_json::Value> = Vec::new();
    for path in &args.observe {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let origin = origin_label(path);
                let hits = run_evidence::scan_observation(&canaries, &origin, &text);
                observed.push(serde_json::json!({
                    "origin": origin,
                    "bytes": text.len(),
                    "hits": hits.len(),
                }));
                if !hits.is_empty() {
                    failures.push(format!(
                        "LEAK: {} canary hit(s) in observed {}",
                        hits.len(),
                        path.display()
                    ));
                }
                observations.push(Observation { origin, text });
            }
            Err(e) => failures.push(format!("cannot read observation {}: {e}", path.display())),
        }
    }

    // Step 4: held-out leak control — MUST alert.
    let control_origin = "leak-control(held-out)".to_string();
    let control_text = match canaries.first() {
        Some(c) => format!("held-out control carrying {c} (synthetic)"),
        None => "held-out control without a token (no canaries configured)".to_string(),
    };
    observations.push(Observation {
        origin: control_origin.clone(),
        text: control_text,
    });

    // Step 5: sweep + report.
    let (alerts, report) = run_evidence::sweep_observations(&observations, &canaries);
    let report_path = args.out.join("canary_report.txt");
    let _ = std::fs::write(&report_path, &report);
    let control_fired = alerts.iter().any(|a| a.origin == control_origin);
    if !control_fired {
        failures.push("leak control did NOT alert — the sweep is not live".to_string());
    }
    let real_leaks = alerts.iter().filter(|a| a.origin != control_origin).count();

    let summary = serde_json::json!({
        "cycle": "canary",
        "site": args.site,
        "count": args.count,
        "verified_tokens": verified,
        "page": page_path.display().to_string(),
        "observed": observed,
        "alerts": alerts.len(),
        "real_leaks": real_leaks,
        "control_fired": control_fired,
        "failures": failures,
        "evidence_dir": run_evidence::evidence_dir().map(|d| d.display().to_string()),
        "ts_ms": now,
    });
    let summary_path = args.out.join("canary_cycle_summary.json");
    let _ = std::fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).unwrap_or_default(),
    );

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );
    } else {
        println!("── canary cycle ──");
        println!("site:          {}", args.site);
        println!("tokens:        {verified}/{} verified", args.count);
        println!("page:          {}", page_path.display());
        println!("observations:  {}", observations.len());
        println!(
            "alerts:        {} (control fired: {control_fired})",
            alerts.len()
        );
        println!("real leaks:    {real_leaks}");
        println!("report:        {}", report_path.display());
        for f in &failures {
            println!("FAILURE: {f}");
        }
        if failures.is_empty() {
            println!("cycle verdict: VALID");
        } else {
            println!("cycle verdict: FAILED ({} failure(s))", failures.len());
        }
    }

    if failures.is_empty() { 0 } else { 2 }
}

// ---------------------------------------------------------------------------
// W5-P2: persona burn-cycle demonstration (`tallow canary burn-cycle`)
// ---------------------------------------------------------------------------

struct BurnCycleArgs {
    out: PathBuf,
    json: bool,
}

const BURN_CYCLE_USAGE: &str = "tallow canary burn-cycle [--out DIR] [--json]\n\
\n\
  Runs the persona burn-cycle drill (P1 W5-P2) on a fresh in-memory registry:\n\
  create -> use -> canary-alert trigger -> burn -> refuse (re-use,\n\
  re-registration, assert_reusable hard-fail, double burn). Every refusal is\n\
  asserted; a persona that stays usable after a burn is a FAILURE. Writes\n\
  <out>/burn_cycle.json and records steps to the run-evidence JSONL.\n\
  Exit: 0 valid, 2 failed check, 64 usage.";

fn parse_burn_cycle_args(argv: &[String]) -> Result<BurnCycleArgs, String> {
    let mut out: Option<PathBuf> = None;
    let mut json = false;

    let mut it = argv.iter();
    match it.next() {
        Some(s) if s == "burn-cycle" => {}
        Some(other) => return Err(format!("unknown canary subcommand {other:?}")),
        None => return Err("missing subcommand (expected `burn-cycle`)".to_string()),
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(it.next().ok_or("--out needs a path")?)),
            "--json" => json = true,
            "-h" | "--help" => {
                eprintln!("Usage: {BURN_CYCLE_USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    let out = out.unwrap_or_else(|| {
        PathBuf::from(format!(
            "canary-burn-cycle-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ))
    });
    Ok(BurnCycleArgs { out, json })
}

fn run_burn_cycle(args: &BurnCycleArgs) -> i32 {
    use crate::persona::{
        BurnMethod, BurnTrigger, CoverClass, Legend, Persona, PersonaError, PersonaRegistry,
        QuarantineMode,
    };

    // Evidence sink: default to <out>/evidence (same rule as `cycle`).
    let env_set = std::env::var(run_evidence::RUN_EVIDENCE_DIR_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if !env_set {
        let ev = args.out.join("evidence");
        unsafe { std::env::set_var(run_evidence::RUN_EVIDENCE_DIR_ENV, &ev) };
    }
    if std::fs::create_dir_all(&args.out).is_err() {
        eprintln!(
            "canary burn-cycle: cannot create out dir {}",
            args.out.display()
        );
        return 2;
    }

    let now = run_evidence::now_ms();
    let id = format!("burn-cycle-demo-{now}");
    let mut steps: Vec<serde_json::Value> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    // Step 1 — create: register a fresh persona on an in-memory registry.
    let mut registry = PersonaRegistry::new();
    let persona = Persona::new(
        &id,
        CoverClass::new("researcher"),
        "burn-cycle-demo",
        Legend::new(
            "demo cover story (burn-cycle drill)",
            "demo@example.invalid",
            "burn-cycle",
        ),
        format!("seed-{now}"),
        u64::try_from(now).unwrap_or(0),
    );
    match registry.register(persona) {
        Ok(()) => steps.push(serde_json::json!({
            "step": "create", "ok": true, "id": id,
        })),
        Err(e) => failures.push(format!("create: register failed: {e}")),
    }

    // Step 2 — use: open the working bundle (the A5.1.2 open-bundle flow).
    match registry.open_bundle(&id) {
        Ok(bundle) => steps.push(serde_json::json!({
            "step": "use", "ok": true,
            "cover_class": bundle.cover_class.as_str(),
            "compartment": bundle.compartment,
        })),
        Err(e) => failures.push(format!("use: open_bundle refused before burn: {e}")),
    }

    // Step 3 — trigger: a canary/leak alert fires the burn (detection-ops).
    let trigger = BurnTrigger::CanaryAlert {
        origin: "burn-cycle-demo(held-out)".to_string(),
        canary: format!("canary-demo-{now}"),
    };
    steps.push(serde_json::json!({
        "step": "trigger", "trigger_kind": trigger.as_str(),
    }));

    // Step 4 — burn: terminal disposition, audit record to run evidence.
    let burn_record = match registry.burn_on_trigger(
        &id,
        u64::try_from(now).unwrap_or(0),
        BurnMethod::RevokeAndQuarantine,
        QuarantineMode::Quarantine,
        trigger,
    ) {
        Ok(rec) => {
            let _ = run_evidence::record("persona_burn", rec.to_json());
            steps.push(serde_json::json!({
                "step": "burn", "ok": true, "record": rec.to_json(),
            }));
            Some(rec)
        }
        Err(e) => {
            failures.push(format!("burn: burn_on_trigger failed: {e}"));
            None
        }
    };

    // Step 5 — refusals: every re-use gate must hard-fail (never-reuse).
    let assert_refusal =
        |step: &str, r: Result<(), PersonaError>, out: &mut Vec<serde_json::Value>| match r {
            Err(PersonaError::BurnedReuse { .. }) => out.push(serde_json::json!({
                "step": step, "refused": true, "error": "burned_reuse",
            })),
            Err(other) => out.push(serde_json::json!({
                "step": step, "refused": true, "error": other.to_string(),
            })),
            Ok(()) => out.push(serde_json::json!({
                "step": step, "refused": false,
            })),
        };
    assert_refusal(
        "refuse_hard_fail",
        registry.assert_reusable(&id),
        &mut steps,
    );
    if !steps
        .last()
        .and_then(|s| s["refused"].as_bool())
        .unwrap_or(false)
    {
        failures.push("refuse_hard_fail: burned id passed assert_reusable".to_string());
    }
    match registry.open_bundle(&id) {
        Err(PersonaError::BurnedReuse { .. }) => steps.push(serde_json::json!({
            "step": "refuse_reuse", "refused": true, "error": "burned_reuse",
        })),
        Err(e) => failures.push(format!("refuse_reuse: unexpected error {e}")),
        Ok(_) => {
            steps.push(serde_json::json!({
                "step": "refuse_reuse", "refused": false,
            }));
            failures.push("refuse_reuse: burned persona was handed a bundle".to_string());
        }
    }
    let rereg = registry.register(Persona::new(
        &id,
        CoverClass::new("researcher"),
        "burn-cycle-demo",
        Legend::new(
            "re-register attempt (must fail)",
            "demo@example.invalid",
            "burn-cycle",
        ),
        format!("seed-rereg-{now}"),
        u64::try_from(now).unwrap_or(0),
    ));
    match rereg {
        Err(PersonaError::BurnedReuse { .. }) => steps.push(serde_json::json!({
            "step": "refuse_reregister", "refused": true, "error": "burned_reuse",
        })),
        Err(e) => failures.push(format!("refuse_reregister: unexpected error {e}")),
        Ok(()) => {
            steps.push(serde_json::json!({
                "step": "refuse_reregister", "refused": false,
            }));
            failures.push("refuse_reregister: burned id was re-registered".to_string());
        }
    }
    // Double burn surfaces (terminal state), it must not be silently idempotent.
    match registry.burn(
        &id,
        u64::try_from(now).unwrap_or(0),
        BurnMethod::RevokeOnly,
        QuarantineMode::None,
    ) {
        Err(PersonaError::AlreadyBurned { .. }) => steps.push(serde_json::json!({
            "step": "double_burn", "refused": true, "error": "already_burned",
        })),
        Err(e) => failures.push(format!("double_burn: unexpected error {e}")),
        Ok(_) => {
            steps.push(serde_json::json!({
                "step": "double_burn", "refused": false,
            }));
            failures.push("double_burn: second burn was silently accepted".to_string());
        }
    }

    let tainted: Vec<&String> = registry.burned_ids().iter().collect();
    let summary = serde_json::json!({
        "cycle": "burn-cycle",
        "persona_id": id,
        "steps": steps,
        "burned_ids": tainted,
        "burn_record": burn_record.map(|r| r.to_json()),
        "failures": failures,
        "evidence_dir": run_evidence::evidence_dir().map(|d| d.display().to_string()),
        "ts_ms": now,
    });
    let summary_path = args.out.join("burn_cycle.json");
    if let Err(e) = std::fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).unwrap_or_default(),
    ) {
        eprintln!(
            "canary burn-cycle: cannot write {}: {e}",
            summary_path.display()
        );
        return 2;
    }
    let _ = run_evidence::record("persona_burn_cycle", summary.clone());

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );
    } else {
        println!("── burn-cycle (W5-P2) ──");
        println!("persona:   {}", summary["persona_id"]);
        for s in summary["steps"].as_array().into_iter().flatten() {
            let step = s["step"].as_str().unwrap_or("?");
            if let Some(r) = s["refused"].as_bool() {
                println!("  {step:<20} refused={r}");
            } else if let Some(k) = s["trigger_kind"].as_str() {
                println!("  {step:<20} fired: {k}");
            } else {
                println!("  {step:<20} ok={}", s["ok"].as_bool().unwrap_or(false));
            }
        }
        println!("tainted:   {:?}", summary["burned_ids"]);
        println!("evidence:  {}", summary["evidence_dir"]);
        for f in summary["failures"].as_array().into_iter().flatten() {
            println!("FAILURE: {f}");
        }
        if summary["failures"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false)
        {
            println!("cycle verdict: VALID (burned → never reusable)");
        } else {
            println!("cycle verdict: FAILED");
        }
    }

    if summary["failures"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(false)
    {
        0
    } else {
        2
    }
}
