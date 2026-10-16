//! End-to-end budget stops (3.7): kill switch (fleet stop) + daily caps
//! through the real scheduler loop. Needs a `tallow` binary (PATH or
//! `TALLOW_JOBS_TALLOW_BIN`); skips with a notice when absent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;
use tallow_jobs::budget::{Budget, BudgetState};
use tallow_jobs::scheduler::{run_scheduler, SchedulerCfg};
use tallow_registry::ledger::Ledger;
use tallow_registry::receipt::dev_actor_key;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "tallow-budget-it-{}-{}-{}",
        std::process::id(),
        tag,
        n
    ));
    std::fs::create_dir_all(&p).expect("tmpdir");
    p
}

fn write(path: &Path, s: &str) {
    std::fs::write(path, s).expect("write");
}

fn have_tallow() -> bool {
    if std::env::var("TALLOW_JOBS_TALLOW_BIN").is_ok() {
        return true;
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join("tallow").is_file()))
}

fn recipes_dir(base: &Path) -> PathBuf {
    let recipes = base.join("recipes");
    std::fs::create_dir_all(&recipes).expect("recipes dir");
    write(
        &recipes.join("a.tl"),
        "// @job(id: \"stop-a\", schedule: 1, priority: 2)\nfn main() { print(\"a\") }\n",
    );
    write(
        &recipes.join("b.tl"),
        "// @job(id: \"stop-b\", schedule: 1, priority: 1)\nfn main() { print(\"b\") }\n",
    );
    recipes
}

fn mk_cfg(
    base: &Path,
    recipes: PathBuf,
    budget: BudgetState,
    halt: Option<PathBuf>,
) -> SchedulerCfg {
    SchedulerCfg {
        dir: recipes,
        single_recipe: None,
        ledger_path: base.join("ledger.jsonl"),
        state_path: base.join("state.json"),
        dead_letter_path: base.join("dead-letter.jsonl"),
        runs_log_path: base.join("runs.jsonl"),
        out_dir: base.join("out"),
        tick_ms: 50,
        retry_delay_ms: 50,
        actor: "tallow-jobs-test".into(),
        key: dev_actor_key(),
        once: true,
        max_ticks: None,
        budget,
        halt_override: halt,
    }
}

fn refused_lines(base: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(base.join("runs.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"] == json!("refused"))
        .collect()
}

#[test]
fn kill_switch_stops_the_fleet_then_resumes() {
    if !have_tallow() {
        eprintln!("skipping kill_switch_stops_the_fleet_then_resumes: no tallow binary");
        return;
    }
    let base = tmpdir("halt");
    let recipes = recipes_dir(&base);
    let halt = base.join("HALT");
    write(&halt, "stop");

    let cfg = mk_cfg(
        &base,
        recipes.clone(),
        BudgetState::Disabled,
        Some(halt.clone()),
    );
    let report = run_scheduler(&cfg).expect("scheduler");
    assert!(report.halted, "halt must be flagged");
    assert_eq!(report.runs, 0, "nothing executes while halted");
    assert_eq!(report.receipts, 0, "no receipts while halted");
    assert!(report.refused >= 1);

    let ledger = Ledger::new(base.join("ledger.jsonl"));
    assert_eq!(ledger.iter().expect("rows").len(), 0, "ledger untouched");
    let refs = refused_lines(&base);
    assert!(!refs.is_empty());
    assert_eq!(refs[0]["code"], json!("halt"));
    assert_eq!(refs[0]["recipe"], json!("stop-a"), "priority order");
    assert!(
        refs[0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("kill switch"),
        "reason names the kill switch"
    );

    // Lift the halt → the fleet resumes and the same slots run.
    std::fs::remove_file(&halt).expect("unhalt");
    let cfg2 = mk_cfg(&base, recipes, BudgetState::Disabled, Some(halt));
    let report2 = run_scheduler(&cfg2).expect("scheduler");
    assert!(!report2.halted);
    assert_eq!(report2.runs, 2, "both recipes run after resume");
    assert_eq!(report2.receipts, 2);
    let verdict = ledger.verify(&dev_actor_key().verifying_key());
    assert!(verdict.ok(), "ledger broken: {:?}", verdict.errors);
}

#[test]
fn daily_run_cap_refuses_after_limit() {
    if !have_tallow() {
        eprintln!("skipping daily_run_cap_refuses_after_limit: no tallow binary");
        return;
    }
    let base = tmpdir("cap");
    let recipes = recipes_dir(&base);
    let bpath = base.join("budget.json");
    write(
        &bpath,
        &serde_json::to_string_pretty(&json!({
            "schema": "tallow-budget/v1",
            "global": {"max_runs_per_day": 1}
        }))
        .unwrap(),
    );
    let state = BudgetState::Active(Budget::load(&bpath).expect("budget"));

    // Pass 1: one slot runs (a, priority 2), the next is refused by the cap.
    let cfg = mk_cfg(&base, recipes.clone(), state.clone(), None);
    let report = run_scheduler(&cfg).expect("scheduler");
    assert_eq!(report.runs, 1, "one run fits the cap");
    assert_eq!(report.receipts, 1);
    assert_eq!(report.refused, 1, "second slot refused");
    assert!(!report.halted, "caps are not a halt");
    let refs = refused_lines(&base);
    assert_eq!(refs[0]["code"], json!("cap-runs-global"));

    // Pass 2 (1s cadence ⇒ due again after a short wait): the cap counts
    // today's receipt and refuses both slots; the ledger does not grow.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let cfg2 = mk_cfg(&base, recipes, state, None);
    let report2 = run_scheduler(&cfg2).expect("scheduler");
    assert_eq!(report2.runs, 0);
    assert!(report2.refused >= 1);
    let ledger = Ledger::new(base.join("ledger.jsonl"));
    assert_eq!(ledger.iter().expect("rows").len(), 1, "still one receipt");
}

#[test]
fn invalid_budget_fails_closed() {
    if !have_tallow() {
        eprintln!("skipping invalid_budget_fails_closed: no tallow binary");
        return;
    }
    let base = tmpdir("invalid");
    let recipes = recipes_dir(&base);
    let bpath = base.join("budget.json");
    write(&bpath, "{ not valid json ");
    let err = Budget::load(&bpath).expect_err("must fail to load");
    let state = BudgetState::Invalid(err);

    let cfg = mk_cfg(&base, recipes, state, None);
    let report = run_scheduler(&cfg).expect("scheduler");
    assert_eq!(report.runs, 0, "fail closed: nothing runs");
    assert!(!report.halted, "not a halt — an invalid config");
    assert!(report.refused >= 1);
    let refs = refused_lines(&base);
    assert_eq!(refs[0]["code"], json!("budget-invalid"));
    let ledger = Ledger::new(base.join("ledger.jsonl"));
    assert_eq!(ledger.iter().expect("rows").len(), 0);
}
