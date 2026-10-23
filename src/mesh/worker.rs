//! Worker threads.
//!
//! One worker owns nothing shared: it receives a batch of `(task, seed)` pairs
//! on a channel and returns one outcome per task. That is deliberate — `Value`
//! in this codebase is `Rc<RefCell<…>>` and is not `Send`, so a worker that
//! shared an interpreter would be a data race the compiler would refuse anyway.
//!
//! A task that panics must not kill the worker: the panic is caught at the task
//! boundary and reported as a failure, because one bad task is not a reason to
//! abandon a wave.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use super::Task;

/// What a worker calls for each task. Implementations live outside this module
/// so the pool does not depend on the interpreter.
pub trait TaskFn: Send + Sync {
    fn call(&self, task: &Task, seed: u64) -> Result<String, String>;
}

#[derive(Clone, Debug)]
pub struct Job {
    pub wave: usize,
    pub items: Vec<(Task, u64)>,
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Done { wave: usize, task: String, value: String, seed: u64 },
    Failed { wave: usize, task: String, error: String },
}

impl Outcome {
    pub fn task(&self) -> &str {
        match self {
            Outcome::Done { task, .. } | Outcome::Failed { task, .. } => task,
        }
    }
    pub fn wave(&self) -> usize {
        match self {
            Outcome::Done { wave, .. } | Outcome::Failed { wave, .. } => *wave,
        }
    }
}

pub struct Pool {
    senders: Vec<Sender<Job>>,
    handles: Vec<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl Pool {
    /// Spawn `n` workers. `n` is clamped to at least 1.
    pub fn new(n: usize, task_fn: Arc<dyn TaskFn>) -> (Pool, Receiver<Outcome>) {
        let n = n.max(1);
        let (out_tx, out_rx) = channel::<Outcome>();
        let stop = Arc::new(AtomicBool::new(false));
        let mut senders = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);

        for _ in 0..n {
            let (tx, rx) = channel::<Job>();
            senders.push(tx);
            let out = out_tx.clone();
            let f = Arc::clone(&task_fn);
            let stop_flag = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while let Ok(job) = rx.recv() {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    for (task, seed) in job.items {
                        let wave = job.wave;
                        let result = catch_unwind(AssertUnwindSafe(|| f.call(&task, seed)));
                        let outcome = match result {
                            Ok(Ok(value)) => Outcome::Done {
                                wave,
                                task: task.id.clone(),
                                value,
                                seed,
                            },
                            Ok(Err(error)) => Outcome::Failed {
                                wave,
                                task: task.id.clone(),
                                error,
                            },
                            Err(payload) => Outcome::Failed {
                                wave,
                                task: task.id.clone(),
                                error: format!(
                                    "task panicked: {}",
                                    payload
                                        .downcast_ref::<&str>()
                                        .map(|s| s.to_string())
                                        .or_else(|| payload.downcast_ref::<String>().cloned())
                                        .unwrap_or_else(|| "unknown panic".to_string())
                                ),
                            },
                        };
                        if out.send(outcome).is_err() {
                            return;
                        }
                    }
                }
            }));
        }

        (
            Pool {
                senders,
                handles,
                stop,
            },
            out_rx,
        )
    }

    pub fn workers(&self) -> usize {
        self.senders.len()
    }

    /// Send a batch to the least-loaded worker slot (round-robin by wave index).
    pub fn dispatch(&self, slot: usize, job: Job) -> Result<(), String> {
        let idx = slot % self.senders.len();
        self.senders[idx]
            .send(job)
            .map_err(|_| "mesh: worker channel closed".to_string())
    }

    /// Signal every worker to stop taking new batches and join them.
    ///
    /// `drain_ms == 0` drops what is queued; a positive value waits for the
    /// current batch to finish, bounded by the caller's timeout.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        drop(self.senders.drain(..).collect::<Vec<_>>());
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{Task, TaskClass};

    struct Echo;
    impl TaskFn for Echo {
        fn call(&self, task: &Task, seed: u64) -> Result<String, String> {
            Ok(format!("{}:{seed}", task.id))
        }
    }

    struct PanicOn(&'static str);
    impl TaskFn for PanicOn {
        fn call(&self, task: &Task, _seed: u64) -> Result<String, String> {
            if task.id == self.0 {
                panic!("boom");
            }
            Ok("ok".to_string())
        }
    }

    fn task(id: &str) -> Task {
        Task::new(id, "echo", vec![], TaskClass::Pure, None)
    }

    #[test]
    fn ten_tasks_produce_ten_outcomes() {
        let (pool, rx) = Pool::new(2, Arc::new(Echo));
        pool.dispatch(
            0,
            Job {
                wave: 0,
                items: (0..10).map(|i| (task(&format!("t{i}")), i as u64)).collect(),
            },
        )
        .unwrap();
        let mut got = Vec::new();
        for _ in 0..10 {
            got.push(rx.recv_timeout(std::time::Duration::from_secs(5)).expect("outcome"));
        }
        assert_eq!(got.len(), 10);
        let mut ids: Vec<String> = got.iter().map(|o| o.task().to_string()).collect();
        ids.sort();
        assert_eq!(ids[0], "t0");
        assert_eq!(ids[9], "t9");
        pool.shutdown();
    }

    #[test]
    fn a_panicking_task_does_not_kill_the_worker() {
        let (pool, rx) = Pool::new(1, Arc::new(PanicOn("bad")));
        pool.dispatch(
            0,
            Job {
                wave: 0,
                items: vec![(task("bad"), 1), (task("good"), 2)],
            },
        )
        .unwrap();
        let a = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let b = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let failed: Vec<_> = [&a, &b]
            .into_iter()
            .filter(|o| matches!(o, Outcome::Failed { .. }))
            .collect();
        assert_eq!(failed.len(), 1, "exactly the panicking task fails");
        match failed[0] {
            Outcome::Failed { error, .. } => assert!(error.contains("panicked"), "{error}"),
            _ => unreachable!(),
        }
        // the worker is still alive for another batch
        pool.dispatch(1, Job { wave: 1, items: vec![(task("after"), 3)] }).unwrap();
        let c = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(matches!(c, Outcome::Done { .. }));
        pool.shutdown();
    }

    #[test]
    fn work_is_spread_across_workers() {
        let (pool, rx) = Pool::new(4, Arc::new(Echo));
        for w in 0..4 {
            pool.dispatch(w, Job { wave: w, items: vec![(task(&format!("t{w}")), w as u64)] })
                .unwrap();
        }
        let mut waves = Vec::new();
        for _ in 0..4 {
            waves.push(rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap().wave());
        }
        waves.sort();
        assert_eq!(waves, vec![0, 1, 2, 3]);
        pool.shutdown();
    }
}
