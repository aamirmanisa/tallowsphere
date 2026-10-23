//! Coordinator: waves → leases → workers → checkpoints.
//!
//! One wave at a time is dispatched (the graph's dependencies decide the order),
//! every task runs under a lease with an epoch, and each wave ends with a
//! checkpoint hash written to the journal. A failed task is retried within its
//! class's budget; the run continues and reports the failures rather than
//! pretending the wave succeeded.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::journal::{checkpoint_hash, Event, Journal};
use super::lease::LeaseTable;
use super::control::RunControl;
use super::scheduler::{is_straggler, SpeculationPolicy};
use super::worker::{Job, Outcome, Pool, TaskFn};
use super::{task_seed, TaskClass, Wave};

pub struct RetryPolicy {
    pub base_ms: u64,
    pub cap_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy { base_ms: 50, cap_ms: 2_000 }
    }
}

impl RetryPolicy {
    fn delay(&self, attempt: u32) -> Duration {
        let exp = self.base_ms.saturating_mul(1u64 << attempt.min(6));
        Duration::from_millis(exp.min(self.cap_ms))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RunOutcome {
    pub waves: usize,
    pub committed: usize,
    pub failed: usize,
    pub retried: usize,
    pub speculated: usize,
    pub checkpoints: Vec<String>,
    pub stopped: bool,
    pub drained: bool,
    pub injections: Vec<(usize, String, String)>,
}

pub struct Coordinator {
    pool: Pool,
    rx: Receiver<Outcome>,
    leases: LeaseTable,
    journal: Journal,
    mesh_seed: u64,
    retry: RetryPolicy,
    stop_flag: Arc<AtomicBool>,
    drain_ms: u64,
    speculation: SpeculationPolicy,
    control: Arc<RunControl>,
}

impl Coordinator {
    pub fn new(
        workers: usize,
        task_fn: Arc<dyn TaskFn>,
        journal_path: &str,
        mesh_seed: u64,
    ) -> Result<Self, String> {
        let (pool, rx) = Pool::new(workers, task_fn);
        let journal = Journal::open(journal_path).map_err(|e| format!("mesh: journal: {e}"))?;
        Ok(Coordinator {
            pool,
            rx,
            leases: LeaseTable::new(),
            journal,
            mesh_seed,
            retry: RetryPolicy::default(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            drain_ms: 5_000,
            speculation: SpeculationPolicy::default(),
            control: Arc::new(RunControl::new()),
        })
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    pub fn with_drain_ms(mut self, ms: u64) -> Self {
        self.drain_ms = ms;
        self
    }

    pub fn with_control(mut self, control: Arc<RunControl>) -> Self {
        self.control = control;
        self
    }

    pub fn with_speculation(mut self, policy: SpeculationPolicy) -> Self {
        self.speculation = policy;
        self
    }

    /// Stop taking new work. In-flight results are still collected for up to
    /// `drain_ms`, then the run returns with `drained: false`.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    pub fn run(&mut self, run_id: &str, waves: &[Wave]) -> Result<RunOutcome, String> {
        let started = Instant::now();
        let total_tasks: usize = waves.iter().map(|w| w.tasks.len()).sum();
        self.journal
            .append(&Event::RunStarted {
                run_id: run_id.to_string(),
                mesh_seed: self.mesh_seed,
                tasks: total_tasks,
            })
            .map_err(|e| format!("mesh: journal: {e}"))?;

        let mut out = RunOutcome::default();
        let mut slot = 0usize;

        for wave in waves {
            if self.stop_flag.load(Ordering::Relaxed) {
                out.stopped = true;
                break;
            }
            // Honour pause between waves: in-flight work finishes, no new wave
            // starts until resumed.
            while self.control.is_paused()
                && !self.control.is_stopped()
                && !self.stop_flag.load(Ordering::Relaxed)
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.control.is_stopped() {
                out.stopped = true;
                self.stop_flag.store(true, Ordering::Relaxed);
                break;
            }

            self.journal
                .append(&Event::WaveStarted {
                    wave: wave.index,
                    seed: wave.seed(self.mesh_seed),
                })
                .map_err(|e| format!("mesh: journal: {e}"))?;

            for (k, v) in self.control.injections_for(wave.index) {
                self.journal
                    .append(&Event::InjectApplied {
                        wave: wave.index,
                        key: k.clone(),
                        value: v.clone(),
                    })
                    .ok();
                out.injections.push((wave.index, k, v));
            }

            // tasks still to settle: id -> (task, attempt)
            let mut pending: HashMap<String, (super::Task, u32)> = wave
                .tasks
                .iter()
                .map(|t| (t.id.clone(), (t.clone(), 0u32)))
                .collect();
            let mut committed: Vec<(String, String)> = Vec::new();
            let mut in_flight: HashSet<String> = HashSet::new();
            let mut lease_of: HashMap<String, (usize, u64)> = HashMap::new();
            let mut wave_failed: usize = 0;
            let mut started_at: HashMap<String, Instant> = HashMap::new();
            let mut completed_ms: Vec<u64> = Vec::new();
            let mut duplicated: HashSet<String> = HashSet::new();
            let mut speculated: usize = 0;
            let mut drain_started: Option<Instant> = None;
            let budget = self.speculation.budget_for(wave.tasks.len());

            while !pending.is_empty() || !in_flight.is_empty() {
                // dispatch everything not in flight
                let ready: Vec<(String, super::Task, u32)> = pending
                    .iter()
                    .filter(|(id, _)| !in_flight.contains(*id))
                    .map(|(id, (t, a))| (id.clone(), t.clone(), *a))
                    .collect();

                if !ready.is_empty() {
                    // Shard the wave across the pool. One job carrying the whole
                    // wave would run every task on one worker — measured: a
                    // 10-task wave with one 3 s task took 3.0 s because the
                    // stalled task blocked the only worker that had the batch.
                    let workers = self.pool.workers().max(1);
                    let chunk = ready.len().div_ceil(workers);
                    for group in ready.chunks(chunk) {
                        let slot_id = slot % workers;
                        slot = slot.wrapping_add(1);
                        let mut items = Vec::with_capacity(group.len());
                        for (id, task, attempt) in group {
                            let now = started.elapsed().as_millis() as u64;
                            let ttl = (self.retry.cap_ms * 4).max(1_000);
                            let lease = self.leases.grant(id, slot_id, ttl, now);
                            lease_of.insert(id.clone(), (slot_id, lease.epoch));
                            let seed = task_seed(self.mesh_seed, wave.index, id, *attempt);
                            items.push((task.clone(), seed));
                            in_flight.insert(id.clone());
                            started_at.entry(id.clone()).or_insert_with(Instant::now);
                        }
                        self.pool.dispatch(slot_id, Job { wave: wave.index, items })?;
                    }
                }

                // Straggler check: duplicate a slow task under a NEW epoch so
                // its eventual result is fenced out. Bounded per wave.
                if self.speculation.enabled
                    && speculated < budget
                    && completed_ms.len() >= 3
                    && !in_flight.is_empty()
                {
                    // Pick the SLOWEST eligible task, not an arbitrary one:
                    // HashSet iteration order is unrelated to elapsed time, so
                    // `find` could spend the whole budget duplicating fast
                    // tasks while the real straggler never got a duplicate
                    // (measured: a 5 s stall survived because of it).
                    let candidate = in_flight
                        .iter()
                        .filter(|id| !duplicated.contains(*id))
                        .filter_map(|id| {
                            let t0 = started_at.get(id)?;
                            let elapsed = t0.elapsed();
                            if is_straggler(elapsed, &completed_ms, self.speculation.threshold_multiplier) {
                                Some((elapsed, (*id).clone()))
                            } else {
                                None
                            }
                        })
                        .max_by_key(|(elapsed, _)| *elapsed)
                        .map(|(_, id)| id);
                    if let Some(id) = candidate {
                        if let Some((task, attempt)) = pending.get(&id).cloned() {
                            let now = started.elapsed().as_millis() as u64;
                            let ttl = (self.retry.cap_ms * 4).max(1_000);
                            let lease = self.leases.grant(&id, slot, ttl, now);
                            lease_of.insert(id.clone(), (slot, lease.epoch));
                            slot = slot.wrapping_add(1);
                            let seed = task_seed(self.mesh_seed, wave.index, &id, attempt + 1);
                            self.pool.dispatch(
                                slot,
                                Job { wave: wave.index, items: vec![(task, seed)] },
                            )?;
                            duplicated.insert(id);
                            speculated += 1;
                        }
                    }
                }

                // Poll briefly rather than blocking: the straggler check needs
                // to run while a task is still in flight. A blocking recv here
                // made speculation unreachable — the loop slept exactly as long
                // as the stall it was supposed to detect (measured: 5.0 s).
                if self.stop_flag.load(Ordering::Relaxed) && in_flight.is_empty() {
                    break;
                }
                if let Some(t0) = drain_started {
                    if t0.elapsed() >= Duration::from_millis(self.drain_ms.max(1)) {
                        out.stopped = true;
                        out.drained = false;
                        self.journal.append(&Event::RunStopped { drained: false }).ok();
                        out.waves = wave.index + 1;
                        out.committed = committed.len();
                        out.failed = wave_failed;
                        return Ok(out);
                    }
                }
                let outcome = match self.rx.recv_timeout(Duration::from_millis(5)) {
                    Ok(o) => o,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if self.stop_flag.load(Ordering::Relaxed) && drain_started.is_none() {
                            drain_started = Some(Instant::now());
                        }
                        // fall through to the speculation check on the next
                        // iteration; nothing to process this pass
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err("mesh: worker channel closed mid-wave".to_string());
                    }
                };
                let id = outcome.task().to_string();
                in_flight.remove(&id);

                match outcome {
                    Outcome::Done { value, seed, .. } => {
                        if !pending.contains_key(&id) {
                            continue;
                        }
                        let now = started.elapsed().as_millis() as u64;
                        let (worker, epoch) = match lease_of.get(&id).cloned() {
                            Some(v) => v,
                            None => continue,
                        };
                        if !self.leases.accept(&id, worker, epoch, now) {
                            // stale result: the epoch moved on or the lease
                            // expired — drop it rather than commit a lie
                            continue;
                        }
                        let hash = blake3::hash(format!("{seed}:{value}").as_bytes())
                            .to_hex()
                            .to_string();
                        self.journal
                            .append(&Event::TaskCommitted {
                                wave: wave.index,
                                task: id.clone(),
                                result_hash: hash.clone(),
                            })
                            .map_err(|e| format!("mesh: journal: {e}"))?;
                        if let Some(t0) = started_at.remove(&id) {
                            completed_ms.push(t0.elapsed().as_millis() as u64);
                        }
                        committed.push((id.clone(), hash));
                        pending.remove(&id);
                        lease_of.remove(&id);
                        out.committed += 1;
                    }
                    Outcome::Failed { error, .. } => {
                        let (task, attempt) = match pending.get(&id).cloned() {
                            Some(v) => v,
                            None => continue,
                        };
                        let next = attempt + 1;
                        if next < task.class.max_attempts() {
                            self.journal
                                .append(&Event::TaskRetried {
                                    wave: wave.index,
                                    task: id.clone(),
                                    attempt: next,
                                    reason: error,
                                })
                                .ok();
                            out.retried += 1;
                            lease_of.remove(&id);
                            std::thread::sleep(self.retry.delay(attempt));
                            pending.insert(id.clone(), (task, next));
                        } else {
                            self.journal
                                .append(&Event::TaskFailed {
                                    wave: wave.index,
                                    task: id.clone(),
                                    reason: error,
                                })
                                .ok();
                            pending.remove(&id);
                            wave_failed += 1;
                            out.failed += 1;
                        }
                    }
                }

                if self.stop_flag.load(Ordering::Relaxed) && in_flight.is_empty() {
                    break;
                }
            }

            let cp = checkpoint_hash(&committed);
            self.journal
                .append(&Event::WaveEnded {
                    wave: wave.index,
                    checkpoint: cp.clone(),
                })
                .map_err(|e| format!("mesh: journal: {e}"))?;
            out.checkpoints.push(cp);
            out.waves += 1;
            out.speculated += speculated;

            if self.stop_flag.load(Ordering::Relaxed) {
                out.stopped = true;
                out.drained = true;
                self.journal.append(&Event::RunStopped { drained: true }).ok();
                break;
            }
        }

        Ok(out)
    }

    /// Consume the coordinator, shutting the pool down.
    pub fn finish(self) {
        self.pool.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{Task, TaskClass};
    use std::sync::atomic::{AtomicU32, Ordering as AOrdering};

    struct Deterministic;
    impl TaskFn for Deterministic {
        fn call(&self, task: &Task, seed: u64) -> Result<String, String> {
            // pure function of (seed, id): the same on every worker
            Ok(format!("{}:{}", task.id, seed % 97))
        }
    }

    struct Flaky {
        failures: AtomicU32,
        fail_times: u32,
    }
    impl TaskFn for Flaky {
        fn call(&self, _task: &Task, _seed: u64) -> Result<String, String> {
            let n = self.failures.fetch_add(1, AOrdering::SeqCst);
            if n < self.fail_times {
                Err(format!("transient {n}"))
            } else {
                Ok("ok".to_string())
            }
        }
    }

    struct Slow(Duration);
    impl TaskFn for Slow {
        fn call(&self, _task: &Task, _seed: u64) -> Result<String, String> {
            std::thread::sleep(self.0);
            Ok("slow".to_string())
        }
    }

    fn tmp_journal(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tallow-mesh-coord-{}-{}-{name}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p.to_string_lossy().to_string()
    }

    fn task(id: &str) -> Task {
        Task::new(id, "det", vec![], TaskClass::Pure, None)
    }

    #[test]
    fn a_wave_runs_and_produces_a_checkpoint() {
        let path = tmp_journal("wave");
        let mut c = Coordinator::new(2, Arc::new(Deterministic), &path, 7).unwrap();
        let waves = crate::mesh::plan(&[task("a"), task("b")]).unwrap();
        let out = c.run("r1", &waves).unwrap();
        assert_eq!(out.waves, 1);
        assert_eq!(out.committed, 2);
        assert_eq!(out.checkpoints.len(), 1);
        c.finish();

        let replayed = crate::mesh::journal::replay(&path).expect("replay");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].checkpoint, out.checkpoints[0]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_task_failing_twice_then_succeeding_reports_two_retries() {
        let path = tmp_journal("retry");
        let flaky = Arc::new(Flaky {
            failures: AtomicU32::new(0),
            fail_times: 2,
        });
        let mut c = Coordinator::new(1, flaky, &path, 1)
            .unwrap()
            .with_retry_policy(RetryPolicy { base_ms: 1, cap_ms: 5 });
        let waves = crate::mesh::plan(&[task("a")]).unwrap();
        let out = c.run("r2", &waves).unwrap();
        assert_eq!(out.committed, 1, "third attempt succeeds");
        assert_eq!(out.retried, 2);
        assert_eq!(out.failed, 0);
        c.finish();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn exhausted_retries_are_reported_not_hidden() {
        let path = tmp_journal("exhaust");
        let flaky = Arc::new(Flaky {
            failures: AtomicU32::new(0),
            fail_times: 99,
        });
        let mut c = Coordinator::new(1, flaky, &path, 1)
            .unwrap()
            .with_retry_policy(RetryPolicy { base_ms: 1, cap_ms: 5 });
        let waves = crate::mesh::plan(&[task("a")]).unwrap();
        let out = c.run("r3", &waves).unwrap();
        assert_eq!(out.failed, 1);
        assert_eq!(out.committed, 0);
        c.finish();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stop_drains_within_the_bound() {
        let path = tmp_journal("stop");
        let mut c = Coordinator::new(1, Arc::new(Slow(Duration::from_millis(150))), &path, 1)
            .unwrap()
            .with_drain_ms(100);
        let flags = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flags);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            f.store(true, Ordering::Relaxed);
        });
        let waves = crate::mesh::plan(&[task("a"), task("b"), task("c")]).unwrap();
        let start = Instant::now();
        let out = c.run("r4", &waves).unwrap();
        let elapsed = start.elapsed();
        assert!(out.stopped, "run must report the stop");
        assert!(
            elapsed < Duration::from_millis(1_000),
            "stop must be bounded, took {elapsed:?}"
        );
        c.finish();
        let _ = std::fs::remove_file(&path);
    }
}
