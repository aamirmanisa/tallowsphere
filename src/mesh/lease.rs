//! Lease table with epoch fencing.
//!
//! A worker may commit a result only while it holds the *current* epoch for that
//! task. Reassignment increments the epoch, so a stalled worker that wakes up
//! after its lease expired cannot commit a stale answer — it is fenced out.
//! Time is passed in, never read: the same sequence of `(now_ms)` values must
//! produce the same decisions, which is what makes the tests meaningful.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub task: String,
    pub worker: usize,
    pub epoch: u64,
    pub expires_at_ms: u64,
}

#[derive(Default)]
pub struct LeaseTable {
    inner: Mutex<HashMap<String, Lease>>,
    epochs: Mutex<HashMap<String, u64>>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant (or re-grant) a task to a worker. Always bumps the epoch.
    pub fn grant(&self, task: &str, worker: usize, ttl_ms: u64, now_ms: u64) -> Lease {
        let mut epochs = self.epochs.lock().unwrap();
        let epoch = epochs.entry(task.to_string()).or_insert(0);
        *epoch += 1;
        let lease = Lease {
            task: task.to_string(),
            worker,
            epoch: *epoch,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        };
        self.inner
            .lock()
            .unwrap()
            .insert(task.to_string(), lease.clone());
        lease
    }

    /// May `worker` at `epoch` commit this task right now?
    ///
    /// False when the epoch is stale (someone else owns it now) or the lease has
    /// expired. Both are the same refusal to the caller, and the caller must
    /// treat a false as "drop this result", not "retry immediately".
    pub fn accept(&self, task: &str, worker: usize, epoch: u64, now_ms: u64) -> bool {
        let map = self.inner.lock().unwrap();
        match map.get(task) {
            Some(l) => l.epoch == epoch && l.worker == worker && now_ms < l.expires_at_ms,
            None => false,
        }
    }

    /// Tasks whose lease expired at or before `now_ms`.
    pub fn expire_due(&self, now_ms: u64) -> Vec<String> {
        let mut map = self.inner.lock().unwrap();
        let mut due: Vec<String> = map
            .iter()
            .filter(|(_, l)| l.expires_at_ms <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        due.sort();
        for t in &due {
            map.remove(t);
        }
        due
    }

    /// Current epoch for a task, for diagnostics and journaling.
    pub fn epoch_of(&self, task: &str) -> Option<u64> {
        self.epochs.lock().unwrap().get(task).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_epoch_cannot_commit() {
        let t = LeaseTable::new();
        let first = t.grant("a", 0, 1000, 0);
        let _second = t.grant("a", 1, 1000, 0); // reassigned on expiry
        assert!(
            !t.accept("a", 0, first.epoch, 10),
            "the first owner's result must be fenced out"
        );
        assert!(t.accept("a", 1, _second.epoch, 10));
    }

    #[test]
    fn grant_increments_the_epoch() {
        let t = LeaseTable::new();
        let a = t.grant("x", 0, 100, 0);
        let b = t.grant("x", 0, 100, 0);
        assert_eq!(b.epoch, a.epoch + 1);
    }

    #[test]
    fn expired_lease_is_not_accepted_and_is_returned_once() {
        let t = LeaseTable::new();
        let l = t.grant("y", 2, 50, 0);
        assert!(!t.accept("y", 2, l.epoch, 60), "expired at 60");
        let due = t.expire_due(60);
        assert_eq!(due, vec!["y".to_string()]);
        assert!(t.expire_due(60).is_empty(), "reported exactly once");
    }

    #[test]
    fn wrong_worker_is_refused_even_with_the_right_epoch() {
        let t = LeaseTable::new();
        let l = t.grant("z", 0, 1000, 0);
        assert!(!t.accept("z", 1, l.epoch, 1));
    }

    #[test]
    fn expired_leases_are_sorted() {
        let t = LeaseTable::new();
        t.grant("b", 0, 10, 0);
        t.grant("a", 0, 10, 0);
        assert_eq!(t.expire_due(10), vec!["a".to_string(), "b".to_string()]);
    }
}
