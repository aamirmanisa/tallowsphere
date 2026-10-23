//! Memory plane: a bounded activity queue, a batcher, and a dead-letter list.
//!
//! Activity writes are off the run's critical path, but "off the path" is not
//! "allowed to vanish". The queue has a hard bound, dropping the oldest entry and
//! counting it (MiroFish's ingest queue with a visible failure mode); a batch that
//! fails to write is retried, then parked in a dead-letter list that can be read
//! and replayed.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activity {
    pub run_id: String,
    pub wave: usize,
    pub task: String,
    pub detail: String,
}

/// Where a batch goes. A failure must be an `Err`, never a silent `Ok`.
pub trait ActivitySink: Send + Sync {
    fn write_batch(&self, batch: &[Activity]) -> Result<(), String>;
}

pub struct MemoryConfig {
    pub capacity: usize,
    pub batch_size: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            capacity: 1024,
            batch_size: 64,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub written: usize,
    pub dropped: u64,
    pub dead_lettered: usize,
    pub batches: usize,
}

pub struct MemoryPlane {
    cfg: MemoryConfig,
    queue: Mutex<VecDeque<Activity>>,
    dead: Mutex<Vec<Activity>>,
    dropped: AtomicU64,
}

impl MemoryPlane {
    pub fn new(cfg: MemoryConfig) -> Self {
        MemoryPlane {
            cfg,
            queue: Mutex::new(VecDeque::new()),
            dead: Mutex::new(Vec::new()),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.cfg.capacity
    }

    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Record one activity. Returns `false` when the queue was full and the
    /// OLDEST entry was dropped to make room — the caller can see the loss.
    pub fn record(&self, activity: Activity) -> bool {
        let mut q = self.queue.lock().unwrap();
        let mut kept = true;
        while q.len() >= self.cfg.capacity.max(1) {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
            kept = false;
        }
        q.push_back(activity);
        kept
    }

    pub fn dead_letters(&self) -> Vec<Activity> {
        self.dead.lock().unwrap().clone()
    }

    /// Drain the queue in batches, retrying each failed batch up to `retries`
    /// times before dead-lettering it.
    pub fn flush(&self, sink: &dyn ActivitySink, retries: u32) -> FlushReport {
        let mut report = FlushReport {
            dropped: self.dropped_total(),
            ..Default::default()
        };
        loop {
            let batch: Vec<Activity> = {
                let mut q = self.queue.lock().unwrap();
                let n = q.len().min(self.cfg.batch_size.max(1));
                q.drain(..n).collect()
            };
            if batch.is_empty() {
                break;
            }
            report.batches += 1;
            let mut attempt = 0;
            loop {
                match sink.write_batch(&batch) {
                    Ok(()) => {
                        report.written += batch.len();
                        break;
                    }
                    Err(_) if attempt < retries => {
                        attempt += 1;
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(_) => {
                        report.dead_lettered += batch.len();
                        self.dead.lock().unwrap().extend(batch);
                        break;
                    }
                }
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn act(i: usize) -> Activity {
        Activity {
            run_id: "r".into(),
            wave: i / 10,
            task: format!("t{i}"),
            detail: "d".into(),
        }
    }

    struct Ok_();
    impl ActivitySink for Ok_ {
        fn write_batch(&self, _b: &[Activity]) -> Result<(), String> {
            Ok(())
        }
    }

    struct FailAlways;
    impl ActivitySink for FailAlways {
        fn write_batch(&self, _b: &[Activity]) -> Result<(), String> {
            Err("writer down".into())
        }
    }

    struct FailOnce {
        failed: AtomicBool,
    }
    impl ActivitySink for FailOnce {
        fn write_batch(&self, _b: &[Activity]) -> Result<(), String> {
            if !self.failed.swap(true, Ordering::SeqCst) {
                Err("first write fails".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn the_queue_drops_oldest_and_counts_it() {
        let p = MemoryPlane::new(MemoryConfig {
            capacity: 3,
            batch_size: 2,
        });
        assert!(p.record(act(0)));
        assert!(p.record(act(1)));
        assert!(p.record(act(2)));
        assert!(!p.record(act(3)), "fourth record must report a drop");
        assert_eq!(p.len(), 3);
        assert_eq!(p.dropped_total(), 1);
        let report = p.flush(&Ok_(), 0);
        assert_eq!(report.written, 3);
        assert_eq!(report.dropped, 1, "drops are reported, not hidden");
    }

    #[test]
    fn batches_respect_batch_size() {
        let p = MemoryPlane::new(MemoryConfig {
            capacity: 100,
            batch_size: 4,
        });
        for i in 0..10 {
            p.record(act(i));
        }
        let report = p.flush(&Ok_(), 0);
        assert_eq!(report.written, 10);
        assert_eq!(report.batches, 3, "4 + 4 + 2");
        assert!(p.is_empty());
    }

    #[test]
    fn a_failing_writer_retries_then_dead_letters() {
        let p = MemoryPlane::new(MemoryConfig {
            capacity: 10,
            batch_size: 3,
        });
        for i in 0..6 {
            p.record(act(i));
        }
        let report = p.flush(&FailAlways, 2);
        assert_eq!(report.written, 0);
        assert_eq!(report.dead_lettered, 6);
        assert_eq!(p.dead_letters().len(), 6);
    }

    #[test]
    fn a_transient_failure_is_not_dead_lettered() {
        let p = MemoryPlane::new(MemoryConfig {
            capacity: 10,
            batch_size: 3,
        });
        for i in 0..3 {
            p.record(act(i));
        }
        let sink = FailOnce {
            failed: AtomicBool::new(false),
        };
        let report = p.flush(&sink, 2);
        assert_eq!(report.written, 3, "a retry must recover the batch");
        assert!(p.dead_letters().is_empty());
    }

    #[test]
    fn concurrent_records_stay_within_the_bound() {
        let p = std::sync::Arc::new(MemoryPlane::new(MemoryConfig {
            capacity: 16,
            batch_size: 8,
        }));
        let written = std::sync::Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for t in 0..4 {
            let p = std::sync::Arc::clone(&p);
            let w = std::sync::Arc::clone(&written);
            handles.push(std::thread::spawn(move || {
                for i in 0..100 {
                    if p.record(act(t * 100 + i)) {
                        w.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(p.len() <= 16, "bound must hold under concurrency");
        assert_eq!(p.dropped_total() + written.load(Ordering::Relaxed) as u64, 400);
    }
}
