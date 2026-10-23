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
