//! Mesh execution plane: task graph → waves → leases → checkpoints.
//!
//! Topology (membership, gossip, DHT) lives in `src/stdlib/mesh.rs` and is
//! deliberately separate: that module models a mesh, this one runs work on it.
//! See `docs/architecture/tallow-mesh-execution-plane-2026-10-23.md`.
//!
//! Determinism is the contract: every seed is derived from `mesh_seed` plus the
//! wave index and the task id, so the same plan on a different worker produces
//! the same result hash. Nothing here reads the clock to decide a value.

pub mod control;
pub mod coordinator;
pub mod journal;
pub mod memory;
pub mod lease;
pub mod scheduler;
pub mod worker;

use std::collections::{HashMap, HashSet};

/// How a task may be retried and replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskClass {
    /// Replayable: re-executing must produce a byte-identical result hash.
    Pure,
    /// Side effects; retryable only with an idempotency key.
    Io,
    /// Non-deterministic by nature; the journal stores the response instead.
    Llm,
}

impl TaskClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskClass::Pure => "pure",
            TaskClass::Io => "io",
            TaskClass::Llm => "llm",
        }
    }

    /// Attempts allowed for this class. `Llm` gets one: a retry would produce a
    /// different answer, which is the divergence the journal exists to prevent.
    pub fn max_attempts(&self) -> u32 {
        match self {
            TaskClass::Pure => 3,
            TaskClass::Io => 2,
            TaskClass::Llm => 1,
        }
    }
}

/// One unit of work.
#[derive(Clone, Debug)]
pub struct Task {
    pub id: String,
    pub func: String,
    pub deps: Vec<String>,
    pub class: TaskClass,
    pub idempotency_key: Option<String>,
}

impl Task {
    pub fn new(
        id: &str,
        func: &str,
        deps: Vec<&str>,
        class: TaskClass,
        idempotency_key: Option<&str>,
    ) -> Self {
        Task {
            id: id.to_string(),
            func: func.to_string(),
            deps: deps.into_iter().map(|d| d.to_string()).collect(),
            class,
            idempotency_key: idempotency_key.map(|k| k.to_string()),
        }
    }

    /// Refuse a task whose class makes replay unsafe. Visible refusal, never a
    /// silent re-run.
    pub fn validate(&self) -> Result<(), String> {
        if self.id == "" {
            return Err("task: empty id".to_string());
        }
        if self.class == TaskClass::Io && self.idempotency_key.is_none() {
            return Err(format!(
                "task '{}': io class requires an idempotency key (a retry would repeat the side effect)",
                self.id
            ));
        }
        Ok(())
    }
}

/// A set of tasks with no dependencies among them.
#[derive(Clone, Debug)]
pub struct Wave {
    pub index: usize,
    pub tasks: Vec<Task>,
}

impl Wave {
    pub fn seed(&self, mesh_seed: u64) -> u64 {
        wave_seed(mesh_seed, self.index)
    }
}

/// Topologically sort tasks into waves. Order inside a wave follows input order
/// so that plan output is itself deterministic.
pub fn plan(tasks: &[Task]) -> Result<Vec<Wave>, String> {
    let mut by_id: HashMap<&str, &Task> = HashMap::new();
    for t in tasks {
        t.validate()?;
        if by_id.insert(t.id.as_str(), t).is_some() {
            return Err(format!("task '{}' declared twice", t.id));
        }
    }
    for t in tasks {
        for d in &t.deps {
            if !by_id.contains_key(d.as_str()) {
                return Err(format!("task '{}': dependency '{}' does not exist", t.id, d));
            }
        }
    }

    let mut remaining: HashSet<&str> = tasks.iter().map(|t| t.id.as_str()).collect();
    let mut done: HashSet<&str> = HashSet::new();
    let mut waves: Vec<Wave> = Vec::new();

    while !remaining.is_empty() {
        let mut ready: Vec<&Task> = Vec::new();
        for t in tasks {
            if !remaining.contains(t.id.as_str()) {
                continue;
            }
            if t.deps.iter().all(|d| done.contains(d.as_str())) {
                ready.push(t);
            }
        }
        if ready.is_empty() {
            return Err(format!("dependency cycle: {}", cycle_path(tasks, &remaining)));
        }
        for t in &ready {
            remaining.remove(t.id.as_str());
            done.insert(t.id.as_str());
        }
        waves.push(Wave {
            index: waves.len(),
            tasks: ready.into_iter().cloned().collect(),
        });
    }

    Ok(waves)
}

/// Recover one cycle path for the error message instead of saying "cycle".
fn cycle_path(tasks: &[Task], remaining: &HashSet<&str>) -> String {
    let mut stack: Vec<&str> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut node = tasks
        .iter()
        .find(|t| remaining.contains(t.id.as_str()))
        .map(|t| t.id.as_str());

    while let Some(id) = node {
        if let Some(pos) = stack.iter().position(|s| *s == id) {
            let mut path: Vec<&str> = stack[pos..].to_vec();
            path.push(id);
            return path.join(" -> ");
        }
        if !seen.insert(id) {
            break;
        }
        stack.push(id);
        node = tasks
            .iter()
            .find(|t| t.id == id)
            .and_then(|t| t.deps.first())
            .map(|d| by_id_lookup(tasks, d));
    }
    "unresolved".to_string()
}

fn by_id_lookup<'a>(tasks: &'a [Task], id: &str) -> &'a str {
    tasks
        .iter()
        .find(|t| t.id == id)
        .map(|t| t.id.as_str())
        .unwrap_or("?")
}

// ── Derived seeds ───────────────────────────────────────────────────────────

fn digest(parts: &[&[u8]]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    for p in parts {
        hasher.update(p);
        hasher.update(&[0u8]);
    }
    let out = hasher.finalize();
    let b = out.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub fn wave_seed(mesh_seed: u64, wave: usize) -> u64 {
    digest(&[&mesh_seed.to_le_bytes(), &(wave as u64).to_le_bytes()])
}

pub fn task_seed(mesh_seed: u64, wave: usize, task_id: &str, attempt: u32) -> u64 {
    digest(&[
        &mesh_seed.to_le_bytes(),
        &(wave as u64).to_le_bytes(),
        task_id.as_bytes(),
        &attempt.to_le_bytes(),
    ])
}

pub fn shard_seed(mesh_seed: u64, wave: usize, shard: usize) -> u64 {
    digest(&[
        &mesh_seed.to_le_bytes(),
        &(wave as u64).to_le_bytes(),
        &[0x5a],
        &(shard as u64).to_le_bytes(),
    ])
}

pub fn sample_seed(task_seed: u64, i: usize) -> u64 {
    digest(&[&task_seed.to_le_bytes(), &[0x51], &(i as u64).to_le_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pure(id: &str, deps: Vec<&str>) -> Task {
        Task::new(id, "noop", deps, TaskClass::Pure, None)
    }

    #[test]
    fn io_task_without_idempotency_key_is_rejected() {
        let t = Task::new("a", "fn_a", vec![], TaskClass::Io, None);
        let err = t.validate().expect_err("io without key must be refused");
        assert!(err.contains("idempotency key"), "{err}");
    }

    #[test]
    fn io_task_with_idempotency_key_is_accepted() {
        let t = Task::new("a", "fn_a", vec![], TaskClass::Io, Some("k1"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn diamond_graph_is_three_waves() {
        let tasks = vec![
            pure("a", vec![]),
            pure("b", vec!["a"]),
            pure("c", vec!["a"]),
            pure("d", vec!["b", "c"]),
        ];
        let waves = plan(&tasks).expect("plan");
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].tasks.len(), 1);
        assert_eq!(waves[1].tasks.len(), 2);
        assert_eq!(waves[2].tasks.len(), 1);
        // insertion order inside the wave, so plan output is deterministic
        assert_eq!(waves[1].tasks[0].id, "b");
        assert_eq!(waves[1].tasks[1].id, "c");
    }

    #[test]
    fn cycle_is_rejected_with_the_path() {
        let tasks = vec![pure("a", vec!["b"]), pure("b", vec!["a"])];
        let err = plan(&tasks).expect_err("cycle must be refused");
        assert!(err.contains(" -> "), "message must show the path: {err}");
        assert!(err.contains('a') && err.contains('b'), "{err}");
    }

    #[test]
    fn missing_dependency_is_named() {
        let tasks = vec![pure("a", vec!["ghost"])];
        let err = plan(&tasks).expect_err("must refuse");
        assert!(err.contains("ghost"), "{err}");
    }

    #[test]
    fn duplicate_id_is_refused() {
        let tasks = vec![pure("a", vec![]), pure("a", vec![])];
        let err = plan(&tasks).expect_err("must refuse");
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn seeds_are_stable_and_distinct() {
        let s = 0xDEAD_BEEF_u64;
        assert_eq!(task_seed(s, 1, "t", 0), task_seed(s, 1, "t", 0));
        assert_ne!(task_seed(s, 1, "t", 0), task_seed(s, 1, "t", 1));
        assert_ne!(task_seed(s, 1, "t", 0), task_seed(s, 2, "t", 0));
        assert_ne!(task_seed(s, 1, "t", 0), task_seed(s, 1, "u", 0));
    }

    #[test]
    fn ten_thousand_task_ids_do_not_collide() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..10_000 {
            assert!(
                seen.insert(task_seed(7, 0, &format!("task-{i}"), 0)),
                "seed collision at {i}"
            );
        }
    }

    #[test]
    fn shard_and_sample_seeds_are_separated_from_task_seeds() {
        let s = 11;
        assert_ne!(shard_seed(s, 0, 0), wave_seed(s, 0));
        assert_ne!(sample_seed(task_seed(s, 0, "t", 0), 0), task_seed(s, 0, "t", 0));
        assert_ne!(sample_seed(5, 0), sample_seed(5, 1));
    }
}
