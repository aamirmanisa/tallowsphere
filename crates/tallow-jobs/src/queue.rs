//! Priority queue for due runs: higher `priority` first, then earlier due
//! time, then lower enqueue sequence (deterministic FIFO within a class).

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::path::PathBuf;

/// One queued execution of a recipe.
#[derive(Debug, Clone)]
pub struct QueuedRun {
    pub recipe_id: String,
    pub path: PathBuf,
    pub priority: i64,
    /// When the run became due (ms since epoch).
    pub due_ms: u64,
    /// Enqueue sequence (tiebreaker; lower = first).
    pub seq: u64,
    /// 1-based attempt number this run represents.
    pub attempt: u32,
}

impl PartialEq for QueuedRun {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for QueuedRun {}

impl PartialOrd for QueuedRun {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedRun {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority) // higher priority = Greater = popped first
            .then_with(|| other.due_ms.cmp(&self.due_ms)) // earlier due = Greater
            .then_with(|| other.seq.cmp(&self.seq)) // lower seq = Greater
    }
}

/// Push helper (keeps call sites tidy).
pub fn push(heap: &mut BinaryHeap<QueuedRun>, run: QueuedRun) {
    heap.push(run);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BinaryHeap;

    fn q(id: &str, priority: i64, due_ms: u64, seq: u64) -> QueuedRun {
        QueuedRun {
            recipe_id: id.to_string(),
            path: PathBuf::from(format!("{id}.tl")),
            priority,
            due_ms,
            seq,
            attempt: 1,
        }
    }

    #[test]
    fn order_priority_then_due_then_seq() {
        let mut h = BinaryHeap::new();
        h.push(q("low", 0, 100, 1));
        h.push(q("high-late", 9, 200, 2));
        h.push(q("high-early", 9, 100, 3));
        h.push(q("high-early-first", 9, 100, 0));

        let mut order = Vec::new();
        while let Some(r) = h.pop() {
            order.push(r.recipe_id);
        }
        assert_eq!(
            order,
            vec!["high-early-first", "high-early", "high-late", "low"]
        );
    }
}
