use tokio::sync::Semaphore;

use crate::db;

/// Priority-driven job queue backed by SQLite.
///
/// The queue SHAPE is the database itself — jobs are stored in the `jobs` table.
/// `PriorityQueue` is a concurrency coordinator that:
///   - Controls how many jobs can run concurrently via a semaphore
///   - Dequeues the next highest-priority job from SQLite
///
/// This design avoids the "queue lost on crash" problem since all state is durable.
pub struct PriorityQueue {
    semaphore: Semaphore,
}

impl PriorityQueue {
    /// Create a new priority queue with a maximum of `max_concurrent` jobs running
    /// simultaneously.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Semaphore::new(max_concurrent.max(1)),
        }
    }

    /// Acquire a concurrency permit. Blocks until a slot is available.
    /// The returned `SemaphorePermit` auto-releases on drop.
    pub async fn acquire_permit(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.semaphore
            .acquire()
            .await
            .expect("semaphore should not be closed")
    }

    /// Return the number of available permits (for diagnostics).
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Dequeue the next highest-priority 'created' job from the database.
    /// The caller should hold a semaphore permit before calling this.
    pub async fn dequeue_next(
        &self,
        db: &tokio::sync::Mutex<rusqlite::Connection>,
    ) -> Option<db::Job> {
        let conn = db.lock().await;
        db::dequeue_by_priority(&conn).unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn in_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE jobs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                config_json TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .unwrap();
        // Add Phase 4 columns
        conn.execute("ALTER TABLE jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 0", [])
            .unwrap();
        conn.execute(
            "ALTER TABLE jobs ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .unwrap();
        conn.execute(
            "ALTER TABLE jobs ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 3",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                event TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    /// Insert a test job into the database with a given priority.
    fn insert_job(conn: &rusqlite::Connection, name: &str, priority: u32) -> String {
        let id = format!("{}-{}", name, uuid::Uuid::new_v4());
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO jobs (id, name, status, config_json, priority, retry_count, max_retries, created_at, updated_at)
             VALUES (?1, ?2, 'created', '{}', ?3, 0, 3, ?4, ?4)",
            rusqlite::params![id, name, priority, now],
        )
        .unwrap();
        id
    }

    #[tokio::test]
    async fn test_semaphore_limits_concurrency() {
        let queue = Arc::new(PriorityQueue::new(2));

        // Acquire 2 permits — should succeed
        let p1 = queue.acquire_permit().await;
        let p2 = queue.acquire_permit().await;
        assert_eq!(queue.available_permits(), 0);

        // Drop p1 — one permit frees
        drop(p1);
        assert_eq!(queue.available_permits(), 1);

        drop(p2);
        assert_eq!(queue.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_dequeue_returns_highest_priority_first() {
        let conn = in_memory_db();
        // Create job_history table for dequeue_by_priority
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                event TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL
            );",
        )
        .unwrap();

        let db = Mutex::new(conn);

        // Insert jobs with different priorities
        {
            let c = db.lock().await;
            insert_job(&c, "low", 0);
            insert_job(&c, "high", 10);
            insert_job(&c, "mid", 5);
        }

        let queue = PriorityQueue::new(4);

        // First dequeue should be the highest priority job
        let job1 = queue.dequeue_next(&db).await.expect("should dequeue job");
        assert_eq!(
            job1.name, "high",
            "highest priority (10) should dequeue first"
        );

        // Second should be mid (priority 5)
        let job2 = queue.dequeue_next(&db).await.expect("should dequeue job");
        assert_eq!(job2.name, "mid", "priority 5 should dequeue second");

        // Third should be low (priority 0)
        let job3 = queue.dequeue_next(&db).await.expect("should dequeue job");
        assert_eq!(job3.name, "low", "priority 0 should dequeue last");

        // Fourth should be None (no more created jobs)
        let job4 = queue.dequeue_next(&db).await;
        assert!(job4.is_none(), "empty queue should return None");
    }
}
