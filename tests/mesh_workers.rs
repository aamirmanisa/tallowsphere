//! Integration acceptance for the mesh execution plane.
//!
//! These are real runs: a plan of tasks goes through the coordinator, workers
//! execute it, and the assertions are on the journal's checkpoint hashes — the
//! artifact a replay compares against.

use std::sync::Arc;

use tallow::mesh::coordinator::{Coordinator, RetryPolicy};
use tallow::mesh::worker::TaskFn;
use tallow::mesh::{plan, Task, TaskClass};

struct Deterministic;
impl TaskFn for Deterministic {
    fn call(&self, task: &Task, seed: u64) -> Result<String, String> {
        // Deliberately a pure function of (id, seed): any dependence on the
        // worker index would make the hash comparison fail, which is the point.
        Ok(format!("{}:{}", task.id, seed % 97))
    }
}

fn wave_of(n: usize) -> Vec<Task> {
    (0..n)
        .map(|i| Task::new(&format!("t{i:03}"), "det", vec![], TaskClass::Pure, None))
        .collect()
}

fn tmp(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "tallow-mesh-it-{}-{}-{name}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    p.to_string_lossy().to_string()
}

fn run_with(workers: usize, tasks: Vec<Task>, name: &str) -> Vec<String> {
    let path = tmp(name);
    let mut c = Coordinator::new(workers, Arc::new(Deterministic), &path, 0xA11CE)
        .expect("coordinator")
        .with_retry_policy(RetryPolicy { base_ms: 1, cap_ms: 4 });
    let waves = plan(&tasks).expect("plan");
    let out = c.run(name, &waves).expect("run");
    c.finish();
    assert_eq!(out.failed, 0, "no task may fail in the acceptance run");
    let _ = std::fs::remove_file(&path);
    out.checkpoints
}

/// The M1 gate: the same plan on 1 and 8 workers must produce identical
/// checkpoint hashes, and a replay of each journal must agree with its run.
#[test]
fn same_hashes_at_one_and_eight_workers() {
    let tasks = wave_of(200);
    let one = run_with(1, tasks.clone(), "w1");
    let eight = run_with(8, tasks, "w8");
    assert_eq!(one.len(), eight.len());
    assert_eq!(
        one, eight,
        "checkpoint hashes must not depend on worker count"
    );
    assert_eq!(one.len(), 1, "200 independent tasks form one wave");
}

/// A wave with a dependency chain splits into waves, and the hashes still match
/// across worker counts — this is the case where scheduling order could leak in.
#[test]
fn chained_waves_match_across_worker_counts() {
    let mut tasks = vec![Task::new("root", "det", vec![], TaskClass::Pure, None)];
    for i in 0..20 {
        tasks.push(Task::new(
            &format!("n{i:02}"),
            "det",
            vec![if i == 0 { "root" } else { "nPREV" }],
            TaskClass::Pure,
            None,
        ));
        if i > 0 {
            let id = format!("n{i:02}");
            let prev = format!("n{:02}", i - 1);
            let t = tasks.last_mut().unwrap();
            assert_eq!(t.id, id);
            t.deps = vec![prev];
        }
    }
    let one = run_with(1, tasks.clone(), "chain1");
    let four = run_with(4, tasks, "chain4");
    assert_eq!(one, four);
    assert_eq!(one.len(), 21, "one wave per link");
}

/// NOTE: the test binary takes the full stall duration to exit even though the
/// RUN finishes in milliseconds — `finish()` joins a worker that is still inside
/// a `sleep`, and std threads cannot be interrupted mid-call. The bounded part is
/// the run; the leftover thread is reaped at process exit. That limitation is
/// deliberate and documented rather than papered over with a detached join.
///
/// A worker that stalls must not hold the wave hostage: the duplicate is
/// dispatched under a new epoch, commits first, and the stalled result is fenced
/// out. Without epoch fencing both results would commit and the checkpoint would
/// depend on timing.
#[test]
fn a_stalled_worker_does_not_extend_the_wave() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tallow::mesh::scheduler::SpeculationPolicy;

    struct StallOnce {
        stalled: AtomicBool,
    }
    impl TaskFn for StallOnce {
        fn call(&self, task: &Task, seed: u64) -> Result<String, String> {
            if task.id == "stuck" && !self.stalled.swap(true, Ordering::SeqCst) {
                // simulate a stalled worker on the first attempt only
                std::thread::sleep(std::time::Duration::from_millis(5_000));
            } else if task.id != "stuck" {
                // give the ordinary tasks a measurable duration so the wave's
                // median is non-zero; a zero baseline must never trigger
                // speculation (guarded in scheduler::is_straggler)
                std::thread::sleep(std::time::Duration::from_millis(3));
            }
            Ok(format!("{}:{}", task.id, seed % 97))
        }
    }

    let path = tmp("speculate");
    let policy = SpeculationPolicy {
        enabled: true,
        threshold_multiplier: 1.5,
        budget_fraction: 0.5,
    };
    let mut c = Coordinator::new(
        4,
        Arc::new(StallOnce {
            stalled: AtomicBool::new(false),
        }),
        &path,
        0xA11CE,
    )
    .expect("coordinator")
    .with_retry_policy(RetryPolicy { base_ms: 1, cap_ms: 4 })
    .with_speculation(policy);

    let mut tasks = wave_of(9);
    tasks.push(Task::new("stuck", "det", vec![], TaskClass::Pure, None));

    let waves = plan(&tasks).expect("plan");
    let start = std::time::Instant::now();
    let out = c.run("speculate", &waves).expect("run");
    let elapsed = start.elapsed();
    c.finish();

    assert_eq!(out.committed, 10, "every task commits exactly once");
    assert_eq!(out.failed, 0);
    assert!(out.speculated >= 1, "a duplicate must have been issued");
    assert!(
        elapsed < std::time::Duration::from_millis(2_500),
        "wave took {elapsed:?}; the stalled worker was not fenced out"
    );

    // exactly one commit per task in the journal
    let journal = std::fs::read_to_string(&path).expect("journal");
    let mut counts = std::collections::HashMap::new();
    for line in journal.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        if v["kind"] == "task_committed" {
            *counts.entry(v["task"].as_str().unwrap().to_string()).or_insert(0) += 1;
        }
    }
    assert_eq!(counts.len(), 10);
    assert!(counts.values().all(|c| *c == 1), "double commit: {counts:?}");
    let _ = std::fs::remove_file(&path);
}

/// The M3 gate, first half: a bounded memory plane on a real run. Ten slots,
/// fifty activities — forty drops, all counted, and the ten survivors written.
#[test]
fn memory_drops_are_counted_on_a_real_run() {
    use tallow::mesh::memory::{Activity, ActivitySink, MemoryConfig, MemoryPlane};

    struct Counting(std::sync::atomic::AtomicUsize);
    impl ActivitySink for Counting {
        fn write_batch(&self, b: &[Activity]) -> Result<(), String> {
            self.0.fetch_add(b.len(), std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    let out = {
        let path = tmp("memory");
        let mut c = Coordinator::new(2, Arc::new(Deterministic), &path, 5).expect("coordinator");
        let waves = plan(&wave_of(50)).expect("plan");
        let o = c.run("memory", &waves).expect("run");
        c.finish();
        let _ = std::fs::remove_file(&path);
        o
    };
    assert_eq!(out.committed, 50);

    let plane = MemoryPlane::new(MemoryConfig {
        capacity: 10,
        batch_size: 4,
    });
    for i in 0..out.committed {
        plane.record(Activity {
            run_id: "memory".into(),
            wave: 0,
            task: format!("t{i:03}"),
            detail: "committed".into(),
        });
    }
    assert_eq!(plane.dropped_total(), 40, "drops must be counted exactly");
    let sink = Counting(std::sync::atomic::AtomicUsize::new(0));
    let report = plane.flush(&sink, 0);
    assert_eq!(report.written, 10);
    assert_eq!(report.dropped, 40);
}

/// The M3 gate, second half: an injection is invisible before its wave, visible
/// from it onward, and recorded in the journal so a replay can reproduce it.
#[test]
fn inject_applies_from_its_wave_only() {
    use tallow::mesh::control::RunControl;

    let mut tasks = vec![Task::new("w0", "det", vec![], TaskClass::Pure, None)];
    tasks.push(Task::new("w1", "det", vec!["w0"], TaskClass::Pure, None));
    tasks.push(Task::new("w2", "det", vec!["w1"], TaskClass::Pure, None));

    let control = Arc::new(RunControl::new());
    control.inject("rate", "9", 2);

    let path = tmp("inject");
    let mut c = Coordinator::new(1, Arc::new(Deterministic), &path, 5)
        .expect("coordinator")
        .with_control(Arc::clone(&control));
    let waves = plan(&tasks).expect("plan");
    let out = c.run("inject", &waves).expect("run");
    c.finish();

    assert_eq!(out.waves, 3);
    assert_eq!(
        out.injections,
        vec![(2usize, "rate".to_string(), "9".to_string())],
        "the injection must appear at wave 2 and nowhere earlier"
    );

    let journal = std::fs::read_to_string(&path).expect("journal");
    let injected: Vec<&str> = journal
        .lines()
        .filter(|l| l.contains("\"inject_applied\""))
        .collect();
    assert_eq!(injected.len(), 1, "one recorded injection");
    assert!(injected[0].contains("\"wave\":2"), "{}", injected[0]);
    let _ = std::fs::remove_file(&path);
}
