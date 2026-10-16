//! `tallow-jobs` — local jobs v1 CLI (recipes · scheduler · receipts).
//!
//! ```text
//! Usage: tallow-jobs --ledger <L> [--state <S>] [--dead-letter <DL>]
//!                    [--runs-log <RL>] [--out-dir <O>] [--key <K>] [--actor <A>]
//!                    <verb> [args]
//!
//!   list [--dir D] [--json]           parse recipes in D (default ./recipes)
//!   run --recipe FILE                 run one recipe now; emit receipt
//!   run --dir D --id ID               same, resolved by recipe id
//!   scheduler --dir D [--once] [--max-ticks N] [--tick-ms N] [--retry-delay-ms N]
//!                                     run the scheduler (default: forever)
//!   verify-ledger [--json]            verify chain + signatures (exit 3 if broken)
//!   dead-letter [--json]              print the dead-letter file
//!
//!   --key <K>   JSON {"seed_hex": "<64 hex>"} Ed25519 actor key; default = DEV key
//!               (deterministic test material — loud warning)
//! ```
//!
//! Exit codes: 0 ok · 1 runtime (failed run / parse errors) · 2 usage ·
//! 3 ledger broken (`verify-ledger`).

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sha2::Digest;

use tallow_jobs::budget::{self, BudgetState};
use tallow_jobs::exec::run_recipe;
use tallow_jobs::recipe::Recipe;
use tallow_jobs::scheduler::{load_recipes, run_scheduler, SchedulerCfg};
use tallow_registry::ledger::{Ledger, Query};
use tallow_registry::receipt::dev_actor_key;

fn die(msg: &str) -> ! {
    eprintln!("tallow-jobs: {msg}");
    std::process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "tallow-jobs {}\n\
         Usage: tallow-jobs --ledger <L> [--state <S>] [--dead-letter <DL>] [--runs-log <RL>]\n\
         \x20                  [--out-dir <O>] [--key <K>] [--actor <A>] <verb> [args]\n\
         Verbs: list [--dir D] [--json] | run (--recipe FILE | --dir D --id ID)\n\
         \x20      scheduler --dir D [--once] [--max-ticks N] [--tick-ms N] [--retry-delay-ms N] [--budget <F>]\n\
         \x20      budget [--budget <F>] [--json] | verify-ledger [--json] | dead-letter [--json]\n",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}

struct Args {
    flags: std::collections::HashMap<String, String>,
    verbs: Vec<String>,
}

fn parse_args(argv: Vec<String>) -> Args {
    let mut flags = std::collections::HashMap::new();
    let mut verbs = Vec::new();
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            let name = name.to_string();
            if name == "once" || name == "json" {
                flags.insert(name, "true".to_string());
            } else {
                let val = it
                    .next()
                    .unwrap_or_else(|| usage_and("missing value after flag"));
                flags.insert(name, val);
            }
        } else {
            verbs.push(a);
        }
    }
    Args { flags, verbs }
}

fn usage_and(msg: &str) -> ! {
    eprintln!("tallow-jobs: {msg}");
    std::process::exit(2);
}

fn flag<'a>(args: &'a Args, name: &str) -> Option<&'a str> {
    args.flags.get(name).map(|s| s.as_str())
}

fn flag_or(args: &Args, name: &str, default: &str) -> String {
    flag(args, name).unwrap_or(default).to_string()
}

/// Build the budget state from `--budget` (strict; parse errors = fail closed).
fn budget_state(args: &Args) -> BudgetState {
    match flag(args, "budget") {
        Some(p) => match budget::Budget::load(std::path::Path::new(p)) {
            Ok(b) => BudgetState::Active(b),
            Err(e) => {
                eprintln!("tallow-jobs: budget: {e}");
                BudgetState::Invalid(e)
            }
        },
        None => BudgetState::Disabled,
    }
}

/// `TALLOW_JOBS_HALT` — kill-switch file path (exists ⇒ stop). Always honored.
fn halt_override() -> Option<std::path::PathBuf> {
    std::env::var("TALLOW_JOBS_HALT")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
}

fn load_key(path: Option<&str>) -> SigningKey {
    match path {
        None => {
            eprintln!("tallow-jobs: WARNING — using deterministic DEV actor key (TEST ONLY)");
            dev_actor_key()
        }
        Some(p) => {
            #[derive(serde::Deserialize)]
            struct KeyFile {
                seed_hex: String,
            }
            let data =
                std::fs::read_to_string(p).unwrap_or_else(|e| die(&format!("key: read {p}: {e}")));
            let f: KeyFile =
                serde_json::from_str(&data).unwrap_or_else(|e| die(&format!("key: bad JSON: {e}")));
            let raw =
                hex::decode(&f.seed_hex).unwrap_or_else(|e| die(&format!("key: bad hex: {e}")));
            let arr: [u8; 32] = raw.try_into().unwrap_or_else(|v: Vec<u8>| {
                die(&format!("key: expected 32 bytes, got {}", v.len()))
            });
            SigningKey::from_bytes(&arr)
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(argv);
    let verb = args.verbs.first().cloned().unwrap_or_else(|| usage());

    let ledger_path = flag_or(&args, "ledger", "jobs-state/ledger.jsonl");
    let state_path = flag_or(&args, "state", "jobs-state/state.json");
    let dead_letter_path = flag_or(&args, "dead-letter", "jobs-state/dead-letter.jsonl");
    let runs_log_path = flag_or(&args, "runs-log", "jobs-state/runs.jsonl");
    let out_dir = flag_or(&args, "out-dir", "jobs-state/out");
    let actor = flag_or(&args, "actor", "tallow-jobs");
    let key = load_key(flag(&args, "key"));

    match verb.as_str() {
        "list" => {
            let dir = flag_or(&args, "dir", "recipes");
            let (recipes, errors) = load_recipes(std::path::Path::new(&dir));
            if flag(&args, "json").is_some() {
                let items: Vec<_> = recipes
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id, "path": r.path.display().to_string(),
                            "schedule_s": r.schedule_s, "priority": r.priority,
                            "retries": r.retries, "timeout_s": r.timeout_s, "enabled": r.enabled,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items).expect("json"));
            } else {
                println!(
                    "{:<20} {:>8} {:>8} {:>7} {:>8} {:>7}  PATH",
                    "ID", "SCHED_S", "PRIORITY", "RETRIES", "TIMEOUT", "ENABLED"
                );
                let mut sorted = recipes.clone();
                sorted.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
                for r in &sorted {
                    println!(
                        "{:<20} {:>8} {:>8} {:>7} {:>8} {:>7}  {}",
                        r.id,
                        r.schedule_s,
                        r.priority,
                        r.retries,
                        r.timeout_s,
                        r.enabled,
                        r.path.display()
                    );
                }
            }
            for e in &errors {
                eprintln!("parse error: {e}");
            }
            if !errors.is_empty() {
                std::process::exit(1);
            }
        }

        "run" => {
            let recipe = if let Some(file) = flag(&args, "recipe") {
                Recipe::from_file(file).unwrap_or_else(|e| die(&format!("recipe {file}: {e}")))
            } else if let Some(dir) = flag(&args, "dir") {
                let id = flag(&args, "id").unwrap_or_else(|| usage());
                let (recipes, errors) = load_recipes(std::path::Path::new(dir));
                for e in &errors {
                    eprintln!("parse error: {e}");
                }
                recipes
                    .into_iter()
                    .find(|r| r.id == id)
                    .unwrap_or_else(|| die(&format!("no recipe with id `{id}` in {dir}")))
            } else {
                usage();
            };

            let out = PathBuf::from(&out_dir).join(&recipe.id);
            std::fs::create_dir_all(&out).unwrap_or_else(|e| die(&format!("out dir: {e}")));
            let envs = vec![
                ("TALLOW_JOB_ID".to_string(), recipe.id.clone()),
                ("TALLOW_JOB_OUT".to_string(), out.display().to_string()),
            ];
            let resolved_cwd = recipe.cwd.as_ref().map(|c| {
                recipe
                    .path
                    .parent()
                    .map(|p| p.join(c))
                    .unwrap_or_else(|| c.clone())
            });
            let outcome = run_recipe(
                &recipe.path,
                &recipe.args,
                resolved_cwd.as_deref(),
                Duration::from_secs(recipe.timeout_s),
                &envs,
                recipe.egress,
            )
            .unwrap_or_else(|e| die(&format!("exec: {e}")));

            // Receipt for this run.
            let ledger = Ledger::new(&ledger_path);
            let seq = ledger
                .next_seq()
                .unwrap_or_else(|e| die(&format!("ledger: {e}")));
            let prev = ledger
                .next_prev()
                .unwrap_or_else(|e| die(&format!("ledger: {e}")));
            let receipt = tallow_registry::receipt::Receipt::sign_new(
                seq,
                "job.run",
                &actor,
                Some(&recipe.id),
                serde_json::json!({
                    "recipe": recipe.id,
                    "file": recipe.path.display().to_string(),
                    "attempt": 1,
                    "max_attempts": 1,
                    "ok": outcome.ok(),
                    "exit_code": outcome.exit_code,
                    "timed_out": outcome.timed_out,
                    "duration_ms": outcome.duration_ms,
                    "stdout_sha256": hex::encode(sha2::Sha256::digest(outcome.stdout.as_bytes())),
                    "stdout_bytes": outcome.stdout.len(),
                    "slot_runs_total": 1,
                    "egress": recipe.egress.as_str(),
                    "via": "cli-run",
                }),
                prev,
                &key,
            );
            ledger
                .append(&receipt)
                .unwrap_or_else(|e| die(&format!("ledger append: {e}")));

            println!(
                "run {}: {} (exit={:?}, {} ms{})",
                recipe.id,
                if outcome.ok() { "ok" } else { "FAILED" },
                outcome.exit_code,
                outcome.duration_ms,
                if outcome.timed_out { ", timed out" } else { "" }
            );
            if !outcome.stdout.trim().is_empty() {
                println!("--- stdout ---\n{}", outcome.stdout.trim_end());
            }
            if !outcome.stderr.trim().is_empty() {
                eprintln!("--- stderr ---\n{}", outcome.stderr.trim_end());
            }
            println!(
                "receipt seq={seq} kind=job.run digest={}",
                receipt.digest_hex()
            );
            if !outcome.ok() {
                std::process::exit(1);
            }
        }

        "scheduler" => {
            let dir = flag_or(&args, "dir", "recipes");
            let cfg = SchedulerCfg {
                dir: PathBuf::from(dir),
                single_recipe: flag(&args, "recipe").map(PathBuf::from),
                ledger_path: PathBuf::from(&ledger_path),
                state_path: PathBuf::from(&state_path),
                dead_letter_path: PathBuf::from(&dead_letter_path),
                runs_log_path: PathBuf::from(&runs_log_path),
                out_dir: PathBuf::from(&out_dir),
                tick_ms: flag_or(&args, "tick-ms", "1000")
                    .parse()
                    .unwrap_or_else(|_| usage_and("bad --tick-ms")),
                retry_delay_ms: flag_or(&args, "retry-delay-ms", "1000")
                    .parse()
                    .unwrap_or_else(|_| usage_and("bad --retry-delay-ms")),
                actor,
                key,
                once: flag(&args, "once").is_some(),
                max_ticks: flag(&args, "max-ticks").map(|v| {
                    v.parse::<u64>()
                        .unwrap_or_else(|_| usage_and("bad --max-ticks"))
                }),
                budget: budget_state(&args),
                halt_override: halt_override(),
            };
            let report = run_scheduler(&cfg).unwrap_or_else(|e| die(&format!("scheduler: {e}")));
            println!(
                "scheduler done: ticks={} recipes={} disabled={} runs={} attempts={} failures={} dead_letters={} receipts={} refused={} halted={} parse_errors={}",
                report.ticks,
                report.recipes,
                report.disabled,
                report.runs,
                report.attempts,
                report.failures,
                report.dead_letters,
                report.receipts,
                report.refused,
                report.halted,
                report.parse_errors.len()
            );
            for e in &report.parse_errors {
                eprintln!("parse error: {e}");
            }
            if report.halted || report.refused > 0 {
                std::process::exit(3); // budget stop: kill switch / caps / fail-closed
            }
            if !report.parse_errors.is_empty() || report.failures > 0 {
                std::process::exit(1);
            }
        }

        "budget" => {
            let ledger = Ledger::new(&ledger_path);
            let state = budget_state(&args);
            let now = tallow_registry::now_ms();
            let lines = tallow_jobs::budget::status_lines(&state, &ledger, now as i64);
            if flag(&args, "json").is_some() {
                let s = match &state {
                    BudgetState::Disabled => "disabled",
                    BudgetState::Active(_) => "active",
                    BudgetState::Invalid(_) => "invalid",
                };
                println!(
                    "{}",
                    serde_json::json!({
                        "state": s,
                        "halt_env": std::env::var("TALLOW_JOBS_HALT").ok(),
                        "lines": lines,
                    })
                );
            } else {
                for l in &lines {
                    println!("{l}");
                }
                if let Some(h) = halt_override() {
                    println!(
                        "env kill switch TALLOW_JOBS_HALT={} — {}",
                        h.display(),
                        if h.exists() { "ENGAGED" } else { "clear" }
                    );
                }
            }
            if matches!(state, BudgetState::Invalid(_)) {
                std::process::exit(1);
            }
        }

        "verify-ledger" => {
            let ledger = Ledger::new(&ledger_path);
            let vk = key.verifying_key();
            let verdict = ledger.verify(&vk);
            if flag(&args, "json").is_some() {
                println!(
                    "{}",
                    serde_json::json!({
                        "rows": verdict.rows,
                        "ok": verdict.ok(),
                        "errors": verdict.errors,
                        "ledger": ledger_path,
                    })
                );
            } else {
                println!(
                    "ledger {}: rows={} {}",
                    ledger_path,
                    verdict.rows,
                    if verdict.ok() { "OK" } else { "BROKEN" }
                );
                for e in &verdict.errors {
                    println!("  {e}");
                }
            }
            if !verdict.ok() {
                std::process::exit(3);
            }
        }

        "dead-letter" => {
            let text = std::fs::read_to_string(&dead_letter_path).unwrap_or_default();
            if flag(&args, "json").is_some() {
                let lines: Vec<serde_json::Value> = text
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect();
                println!("{}", serde_json::to_string_pretty(&lines).expect("json"));
            } else if text.trim().is_empty() {
                println!("dead-letter {}: empty", dead_letter_path);
            } else {
                print!("{text}");
            }
        }

        "receipts" => {
            // Convenience passthrough query (mirrors tallow-registry).
            let ledger = Ledger::new(&ledger_path);
            let q = Query {
                kind: flag(&args, "kind").map(str::to_string),
                actor: flag(&args, "actor").map(str::to_string).or(Some(actor)),
                subject: flag(&args, "subject").map(str::to_string),
                limit: flag(&args, "limit").and_then(|v| v.parse().ok()),
            };
            let rows = ledger
                .query(&q)
                .unwrap_or_else(|e| die(&format!("ledger: {e}")));
            for r in &rows {
                println!(
                    "seq={} kind={} subject={} sig_fp={}",
                    r.seq,
                    r.kind,
                    r.subject.as_deref().unwrap_or("-"),
                    r.sig.as_ref().map(|s| s.key_fp.as_str()).unwrap_or("-")
                );
            }
        }

        _ => usage(),
    }
}
