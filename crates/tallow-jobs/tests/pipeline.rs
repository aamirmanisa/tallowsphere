//! End-to-end pipeline tests: recipes in a temp dir → scheduler `--once` →
//! ledger receipts, dead-letter, state, runs log.
//!
//! These need a `tallow` binary (PATH or `TALLOW_JOBS_TALLOW_BIN`); they
//! skip with a notice when absent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tallow_jobs::exec::run_with_bin;
use tallow_jobs::scheduler::{run_scheduler, SchedulerCfg};
use tallow_registry::ledger::Ledger;
use tallow_registry::receipt::dev_actor_key;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "tallow-jobs-it-{}-{}-{}",
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

#[test]
fn scheduler_once_end_to_end() {
    if !have_tallow() {
        eprintln!("skipping scheduler_once_end_to_end: no tallow binary");
        return;
    }
    let base = tmpdir("sched");
    let recipes = base.join("recipes");
    std::fs::create_dir_all(&recipes).expect("recipes dir");
    write(
        &recipes.join("ok.tl"),
        "// @job(id: \"ok-recipe\", schedule: 60, priority: 1)\nfn main() { print(\"ok!\") }\n",
    );
    write(
        &recipes.join("fail.tl"),
        "// @job(id: \"fail-recipe\", schedule: 60, retries: 1)\nfn main() { let x = 1 / 0 }\n",
    );
    write(
        &recipes.join("off.tl"),
        "// @job(id: \"off-recipe\", schedule: 60, enabled: false)\nfn main() { print(\"never\") }\n",
    );

    let cfg = SchedulerCfg {
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
        budget: tallow_jobs::budget::BudgetState::Disabled,
        halt_override: None,
    };

    let report = run_scheduler(&cfg).expect("scheduler");
    assert_eq!(report.recipes, 2, "two enabled recipes");
    assert_eq!(report.disabled, 1, "one disabled recipe");
    assert!(
        report.parse_errors.is_empty(),
        "parse errors: {:?}",
        report.parse_errors
    );
    assert_eq!(report.runs, 2);
    assert_eq!(report.attempts, 3, "ok: 1 attempt + fail: 2 attempts");
    assert_eq!(report.failures, 1);
    assert_eq!(report.dead_letters, 1);
    assert_eq!(report.receipts, 3);

    // Ledger: chain + signatures verify under the dev actor key.
    let ledger = Ledger::new(base.join("ledger.jsonl"));
    let verdict = ledger.verify(&dev_actor_key().verifying_key());
    assert!(verdict.ok(), "ledger broken: {:?}", verdict.errors);
    assert_eq!(verdict.rows, 3);
    let rows = ledger.iter().expect("rows");
    assert!(rows.iter().all(|r| r.kind == "job.run"));
    assert_eq!(rows[0].subject.as_deref(), Some("ok-recipe"));
    assert_eq!(rows[0].data["ok"], serde_json::json!(true));
    let last = rows.last().expect("last row");
    assert_eq!(last.data["ok"], serde_json::json!(false));
    assert_eq!(last.data["attempt"], serde_json::json!(2));

    // Dead letter, runs log, and state exist with expected content.
    let dl = std::fs::read_to_string(base.join("dead-letter.jsonl")).expect("dead letter");
    assert!(dl.contains("fail-recipe"), "dead letter: {dl}");
    let runs = std::fs::read_to_string(base.join("runs.jsonl")).expect("runs log");
    assert_eq!(runs.lines().count(), 3);
    let state = std::fs::read_to_string(base.join("state.json")).expect("state");
    assert!(state.contains("ok-recipe") && state.contains("fail-recipe"));

    // A second --once pass: schedules are 60 s, nothing due → no new runs.
    let report2 = run_scheduler(&cfg).expect("scheduler pass 2");
    assert_eq!(report2.runs, 0, "nothing due on the second pass");
    assert_eq!(report2.receipts, 0);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn args_and_cwd_end_to_end() {
    if !have_tallow() {
        eprintln!("skipping args_and_cwd_end_to_end: no tallow binary");
        return;
    }
    let base = tmpdir("argcwd");
    let work = base.join("work");
    std::fs::create_dir_all(&work).expect("work dir");
    let script = base.join("fx.tl");
    write(
        &script,
        "// @job(id: \"fx\", schedule: 60, args: [\"hello\", \"world\"], cwd: \"work\")\n\
         fn main() {\n\
         \x20   let a = cli.args()\n\
         \x20   var s = \"\"\n\
         \x20   var i = 0\n\
         \x20   while i < a.len() {\n\
         \x20       s = s + \"|\" + a[i]\n\
         \x20       i = i + 1\n\
         \x20   }\n\
         \x20   fs.write_file(\"args.txt\", s)\n\
         \x20   fs.write_file(\"marker.txt\", \"here\")\n\
         }\n",
    );

    let cfg = SchedulerCfg {
        dir: base.clone(),
        single_recipe: Some(script),
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
        budget: tallow_jobs::budget::BudgetState::Disabled,
        halt_override: None,
    };
    let report = run_scheduler(&cfg).expect("scheduler");
    assert_eq!(report.runs, 1);
    assert_eq!(report.failures, 0, "runs log: {:?}", report.parse_errors);
    assert!(report.parse_errors.is_empty(), "{:?}", report.parse_errors);

    // cwd applied: outputs landed in work/, not the base dir.
    assert!(
        work.join("marker.txt").is_file(),
        "marker must be created under the recipe cwd"
    );
    assert!(!base.join("marker.txt").exists());

    // args applied: cli.args() saw the declared args after `--`.
    let got = std::fs::read_to_string(work.join("args.txt")).expect("args.txt");
    assert!(
        got.ends_with("|hello|world"),
        "args must reach the script (got: {got:?})"
    );

    let ledger = Ledger::new(base.join("ledger.jsonl"));
    let verdict = ledger.verify(&dev_actor_key().verifying_key());
    assert!(verdict.ok(), "{:?}", verdict.errors);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn timeout_kill_path() {
    let base = tmpdir("timeout");
    let stub = base.join("stub.sh");
    write(&stub, "#!/bin/sh\nsleep 30\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&stub).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&stub, perms).expect("chmod");
    }
    let script = base.join("x.tl");
    write(&script, "fn main() {}\n");

    let out = run_with_bin(
        stub.to_str().expect("path"),
        &script,
        Duration::from_millis(300),
        &[],
    )
    .expect("run");
    assert!(out.timed_out, "stub should have been killed");
    assert!(!out.ok());
    assert!(out.duration_ms >= 250, "at least the timeout wait");

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn recipe_id_resolution_and_strictness() {
    use tallow_jobs::recipe::Recipe;

    let base = tmpdir("recipe");
    let good = base.join("good.tl");
    write(&good, "// @job(id: \"good\", schedule: 30)\nfn main() {}\n");
    let r = Recipe::from_file(&good).expect("parse good");
    assert_eq!(r.id, "good");

    let bad = base.join("bad.tl");
    write(
        &bad,
        "// @job(id: \"bad\", schedule: 30, mystery: 1)\nfn main() {}\n",
    );
    assert!(Recipe::from_file(&bad).is_err(), "unknown key must fail");

    let _ = std::fs::remove_dir_all(&base);
}
