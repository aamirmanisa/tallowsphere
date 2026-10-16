//! The tick loop: due-scan → priority queue → execute → in-tick bounded
//! retries → dead-letter; one signed receipt per attempt.

use std::collections::BinaryHeap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};

use tallow_registry::ledger::{Ledger, LedgerError};
use tallow_registry::now_ms;
use tallow_registry::receipt::Receipt;

use crate::budget::Refusal;
use crate::exec::{run_recipe, RunOutcome};
use crate::queue::{push, QueuedRun};
use crate::recipe::Recipe;
use crate::state::{append_jsonl, State};
use crate::SchedulerReport;

/// Scheduler errors.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
}

/// Static scheduler configuration for one pass/daemon run.
#[derive(Debug, Clone)]
pub struct SchedulerCfg {
    /// Directory scanned for `*.tl` recipes (ignored when `single_recipe` is set).
    pub dir: PathBuf,
    /// Run exactly this recipe file instead of scanning `dir`.
    pub single_recipe: Option<PathBuf>,
    pub ledger_path: PathBuf,
    pub state_path: PathBuf,
    pub dead_letter_path: PathBuf,
    pub runs_log_path: PathBuf,
    /// Per-run output dir exposed to recipes as `TALLOW_JOB_OUT`.
    pub out_dir: PathBuf,
    pub tick_ms: u64,
    /// Delay between retry attempts within a slot.
    pub retry_delay_ms: u64,
    pub actor: String,
    pub key: SigningKey,
    /// Run a single pass over due jobs, then exit.
    pub once: bool,
    /// Stop after N ticks (bounded runs; `None` = forever).
    pub max_ticks: Option<u64>,
    /// Budget state (3.7): caps + fail-closed; `Disabled` = env kill switch only.
    pub budget: crate::budget::BudgetState,
    /// Kill-switch path override (`TALLOW_JOBS_HALT` env, resolved by the CLI).
    pub halt_override: Option<PathBuf>,
}

/// Load all recipes from `dir` (`*.tl`). Returns `(recipes, errors)`.
pub fn load_recipes(dir: &Path) -> (Vec<Recipe>, Vec<String>) {
    let mut recipes = Vec::new();
    let mut errors = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            errors.push(format!("dir {}: {e}", dir.display()));
            return (recipes, errors);
        }
    };
    let mut paths: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "tl"))
        .collect();
    paths.sort();
    for p in paths {
        match Recipe::from_file(&p) {
            Ok(r) => recipes.push(r),
            Err(e) => errors.push(format!("{}: {e}", p.display())),
        }
    }
    (recipes, errors)
}

/// Execute one due run slot: attempt(s) with bounded in-tick retries; emits
/// one receipt per attempt and, when attempts are exhausted, a dead letter.
#[allow(clippy::too_many_arguments)]
fn execute_slot(
    recipe: &Recipe,
    cfg: &SchedulerCfg,
    ledger: &Ledger,
    report: &mut SchedulerReport,
    slot_runs_total: u64,
) -> Result<bool, SchedulerError> {
    let max_attempts = recipe.retries.saturating_add(1);
    let mut attempt = 1u32;
    loop {
        // Per-run env: job identity + output dir.
        let out = cfg.out_dir.join(&recipe.id);
        std::fs::create_dir_all(&out)?;
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
        let outcome: RunOutcome = match run_recipe(
            &recipe.path,
            &recipe.args,
            resolved_cwd.as_deref(),
            Duration::from_secs(recipe.timeout_s),
            &envs,
            recipe.egress,
        ) {
            Ok(o) => o,
            Err(e) => RunOutcome {
                exit_code: None,
                timed_out: false,
                duration_ms: 0,
                stdout: String::new(),
                stderr: format!("spawn failed: {e}"),
            },
        };

        report.attempts += 1;
        let ok = outcome.ok();
        let stdout_sha256 = hex::encode(Sha256::digest(outcome.stdout.as_bytes()));

        // Signed receipt: one per attempt.
        let seq = ledger.next_seq()?;
        let prev = ledger.next_prev()?;
        let receipt = Receipt::sign_new(
            seq,
            "job.run",
            &cfg.actor,
            Some(&recipe.id),
            json!({
                "recipe": recipe.id,
                "file": recipe.path.display().to_string(),
                "attempt": attempt,
                "max_attempts": max_attempts,
                "ok": ok,
                "exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "duration_ms": outcome.duration_ms,
                "stdout_sha256": stdout_sha256,
                "stdout_bytes": outcome.stdout.len(),
                "slot_runs_total": slot_runs_total,
                "egress": recipe.egress.as_str(),
            }),
            prev,
            &cfg.key,
        );
        ledger.append(&receipt)?;
        report.receipts += 1;

        // Human log line.
        append_jsonl(
            &cfg.runs_log_path,
            &json!({
                "ts_ms": now_ms(),
                "recipe": recipe.id,
                "attempt": attempt,
                "ok": ok,
                "exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "duration_ms": outcome.duration_ms,
                "stdout_sha256": stdout_sha256,
                "stdout_bytes": outcome.stdout.len(),
                "stderr_tail": tail(&outcome.stderr, 400),
                "receipt_seq": seq,
            }),
        )?;

        if ok {
            return Ok(true);
        }

        if attempt < max_attempts {
            attempt += 1;
            if cfg.retry_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(cfg.retry_delay_ms));
            }
            continue;
        }

        // Exhausted → dead letter.
        append_jsonl(
            &cfg.dead_letter_path,
            &json!({
                "ts_ms": now_ms(),
                "recipe": recipe.id,
                "file": recipe.path.display().to_string(),
                "attempts": attempt,
                "last_exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "stderr_tail": tail(&outcome.stderr, 400),
            }),
        )?;
        report.dead_letters += 1;
        return Ok(false);
    }
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut idx = s.len() - n;
    while !s.is_char_boundary(idx) {
        idx += 1;
    }
    s[idx..].to_string()
}

/// Run the scheduler. `once` = single due-pass; otherwise ticks until
/// `max_ticks` (if set) or forever.
pub fn run_scheduler(cfg: &SchedulerCfg) -> Result<SchedulerReport, SchedulerError> {
    let ledger = Ledger::new(&cfg.ledger_path);
    let mut state = State::load(&cfg.state_path)?;
    let mut report = SchedulerReport::default();
    let mut seq_counter: u64 = 0;

    let mut ticks: u64 = 0;
    loop {
        ticks += 1;
        report.ticks = ticks;

        let (recipes, errors) = match &cfg.single_recipe {
            Some(p) => match Recipe::from_file(p) {
                Ok(r) => (vec![r], Vec::new()),
                Err(e) => (Vec::new(), vec![format!("{}: {e}", p.display())]),
            },
            None => load_recipes(&cfg.dir),
        };
        report.recipes = recipes.iter().filter(|r| r.enabled).count();
        report.disabled = recipes.iter().filter(|r| !r.enabled).count();
        report.parse_errors = errors;

        let now = now_ms();
        let mut heap: BinaryHeap<QueuedRun> = BinaryHeap::new();
        for r in recipes.iter().filter(|r| r.enabled) {
            let due = match state.recipes.get(&r.id) {
                Some(st) => {
                    st.last_run_ms
                        .saturating_add(r.schedule_s.saturating_mul(1000))
                        <= now
                }
                None => true,
            };
            if due {
                seq_counter += 1;
                push(
                    &mut heap,
                    QueuedRun {
                        recipe_id: r.id.clone(),
                        path: r.path.clone(),
                        priority: r.priority,
                        due_ms: now,
                        seq: seq_counter,
                        attempt: 1,
                    },
                );
            }
        }

        while let Some(run) = heap.pop() {
            let Some(recipe) = recipes.iter().find(|r| r.id == run.recipe_id) else {
                continue;
            };
            // Budget gate (3.7): kill switch → fail-closed state → caps.
            // Refused slots do not execute, do not touch state, and do not
            // consume the schedule — but are recorded (run log + report).
            if let Err(r) = crate::budget::gate(
                &cfg.budget,
                cfg.halt_override.as_ref(),
                &ledger,
                &recipe.id,
                now as i64,
            ) {
                report.refused += 1;
                let halted = matches!(r, Refusal::Halt { .. });
                if halted {
                    report.halted = true;
                }
                append_jsonl(
                    &cfg.runs_log_path,
                    &json!({
                        "ts_ms": now_ms(),
                        "event": "refused",
                        "recipe": recipe.id,
                        "code": r.code(),
                        "reason": r.reason(),
                    }),
                )?;
                if halted {
                    break; // fleet stop: nothing else dispatches this pass
                }
                continue;
            }
            report.runs += 1;
            let slot_total = {
                let st = state.recipes.entry(recipe.id.clone()).or_default();
                st.runs += 1;
                st.runs
            };
            let ok = execute_slot(recipe, cfg, &ledger, &mut report, slot_total)?;
            let st = state.recipes.entry(recipe.id.clone()).or_default();
            st.last_run_ms = now_ms();
            if ok {
                st.failures = 0;
            } else {
                st.failures = st.failures.saturating_add(1);
                report.failures += 1;
            }
        }

        state.save(&cfg.state_path)?;

        if cfg.once {
            break;
        }
        if let Some(max) = cfg.max_ticks {
            if ticks >= max {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(cfg.tick_ms));
    }

    Ok(report)
}
