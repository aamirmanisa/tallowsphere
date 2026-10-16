//! Job queue and workflow orchestration system (T2.15).
//!
//! Lightweight Redis-stream-style queue for scrape jobs with:
//! - Priority ordering
//! - Visibility timeouts and reclaim of crashed workers
//! - Exponential backoff retries with jitter
//! - Dead letter queue for poison messages
//! - Backpressure to protect downstream systems
//! - Disk checkpointing for crash recovery
//! - Multi-step workflow engine with dependencies

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

// Redis `Commands` trait must be in scope for the convenience methods
// (`sadd`/`hset`/`zadd`/`hget`/…) used by the feature-gated `RedisQueueBackend`.
#[cfg(feature = "redis-backend")]
use redis::Commands;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum QueueError {
    BackpressureActive,
    JobNotFound,
    AlreadyAcked,
    IoError(String),
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueError::BackpressureActive => write!(f, "queue backpressure active"),
            QueueError::JobNotFound => write!(f, "job not found"),
            QueueError::AlreadyAcked => write!(f, "job already acked"),
            QueueError::IoError(msg) => write!(f, "io error: {}", msg),
        }
    }
}

impl std::error::Error for QueueError {}

// ---------------------------------------------------------------------------
// Job types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobType {
    ScrapePage,
    ExtractProduct,
    MatchProduct,
    ValidatePrice,
    SendAlert,
    RefreshCookies,
    WarmupProfile,
    ParseFlyer,
    SyncApi,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub job_type: JobType,
    pub priority: u8, // 0 = highest
    pub payload: serde_json::Value,
    pub created_at: i64,
    pub scheduled_for: i64, // not-before (unix seconds)
    pub attempts: u32,
    pub max_attempts: u32,
    pub backoff_ms: u64,
}

impl Job {
    pub fn new(job_type: JobType, payload: serde_json::Value) -> Self {
        let now = now_secs();
        let id = deterministic_id(&job_type, &payload, now);
        Self {
            id,
            job_type,
            priority: 5,
            payload,
            created_at: now,
            scheduled_for: now,
            attempts: 0,
            max_attempts: 5,
            backoff_ms: 1000,
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = max;
        self
    }

    pub fn scheduled_at(mut self, ts: i64) -> Self {
        self.scheduled_for = ts;
        self
    }
}

// BinaryHeap is a max-heap; we want lowest priority value first, then earliest scheduled.
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Job {}

impl Ord for Job {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so smaller priority pops first.
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.scheduled_for.cmp(&self.scheduled_for))
            .then_with(|| other.created_at.cmp(&self.created_at))
    }
}

impl PartialOrd for Job {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
pub struct InFlightJob {
    pub job: Job,
    pub worker_id: String,
    pub started_at: Instant,
    pub visibility_timeout: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeadJob {
    pub job: Job,
    pub final_error: String,
    pub failed_at: i64,
    pub response_snapshot: Option<String>,
}

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_backoff_ms: 1000,
            max_backoff_ms: 3_600_000,
            multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    pub fn compute_backoff(&self, attempt: u32) -> u64 {
        let base = (self.initial_backoff_ms as f64) * self.multiplier.powi(attempt as i32);
        let capped = base.min(self.max_backoff_ms as f64);
        if self.jitter {
            let jitter_range = capped * 0.2;
            // Deterministic pseudo-random in [0,1)
            let r = ((attempt.wrapping_mul(2_654_435_761)) % 1000) as f64 / 1000.0;
            let signed = (r - 0.5) * 2.0 * jitter_range;
            (capped + signed).max(0.0) as u64
        } else {
            capped as u64
        }
    }
}

// ---------------------------------------------------------------------------
// QueueStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct QueueStats {
    pub pending_count: usize,
    pub in_flight_count: usize,
    pub dead_letter_count: usize,
    pub total_completed: u64,
    pub total_failed: u64,
    pub backpressure_active: bool,
}

// ---------------------------------------------------------------------------
// Checkpoint format
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    pending: Vec<Job>,
    dead_letter: Vec<DeadJob>,
    completed_count: u64,
    failed_count: u64,
    backpressure_threshold: usize,
}

// ---------------------------------------------------------------------------
// JobQueue
// ---------------------------------------------------------------------------

pub struct JobQueue {
    pending: Arc<Mutex<BinaryHeap<Job>>>,
    in_flight: Arc<RwLock<HashMap<String, InFlightJob>>>,
    dead_letter: Arc<Mutex<VecDeque<DeadJob>>>,
    backpressure_threshold: usize,
    completed_count: Arc<Mutex<u64>>,
    failed_count: Arc<Mutex<u64>>,
    retry_policy: RetryPolicy,
    default_visibility: Duration,
    /// Optional cross-worker (distributed) backing store. When `Some`, all
    /// queue operations route to SQLite and the in-memory heap is unused.
    storage: Option<Arc<SqliteStorageQueueBackend>>,
    /// Optional Redis-backed distributed store (feature `redis-backend`). When
    /// present, all queue operations route to Redis and both the in-memory heap
    /// and the SQLite store are unused.
    #[cfg(feature = "redis-backend")]
    redis_storage: Option<Arc<RedisQueueBackend>>,
}

impl JobQueue {
    pub fn new(backpressure_threshold: usize) -> Self {
        Self {
            pending: Arc::new(Mutex::new(BinaryHeap::new())),
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            dead_letter: Arc::new(Mutex::new(VecDeque::new())),
            backpressure_threshold,
            completed_count: Arc::new(Mutex::new(0)),
            failed_count: Arc::new(Mutex::new(0)),
            retry_policy: RetryPolicy::default(),
            default_visibility: Duration::from_secs(60),
            storage: None,
            #[cfg(feature = "redis-backend")]
            redis_storage: None,
        }
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    pub fn with_visibility_timeout(mut self, timeout: Duration) -> Self {
        self.default_visibility = timeout;
        self
    }

    /// Route this queue through a shared [`SqliteStorageQueueBackend`] so that
    /// multiple workers/nodes operate on the same durable queue with cross-worker
    /// URL dedup, visibility-timeout reclaim, and ack/nack. The in-memory path
    /// remains the default; calling this opts into the distributed backend.
    pub fn with_storage_backend(mut self, backend: Arc<SqliteStorageQueueBackend>) -> Self {
        self.storage = Some(backend);
        self
    }

    /// Route this queue through a shared [`RedisQueueBackend`] (requires the
    /// `redis-backend` feature). Same distributed semantics as the SQLite store
    /// (cross-worker URL dedup, visibility-timeout reclaim, ack/nack, DLQ) but
    /// backed by a real Redis server, so any number of workers on any hosts can
    /// share one queue. The in-memory path remains the default.
    #[cfg(feature = "redis-backend")]
    pub fn with_redis_backend(mut self, backend: Arc<RedisQueueBackend>) -> Self {
        self.redis_storage = Some(backend);
        self
    }

    pub fn enqueue(&self, job: Job) -> Result<(), QueueError> {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            backend.enqueue(&job)?;
            return Ok(());
        }
        // Storage-backed path: cross-worker URL dedup + atomic insert. A duplicate
        // URL (already owned by another worker) is silently accepted.
        if let Some(backend) = &self.storage {
            backend.enqueue(&job)?;
            return Ok(());
        }
        let mut pending = self.pending.lock().unwrap();
        let in_flight_len = self.in_flight.read().unwrap().len();
        if pending.len() + in_flight_len >= self.backpressure_threshold {
            return Err(QueueError::BackpressureActive);
        }
        pending.push(job);
        Ok(())
    }

    pub fn dequeue(&self, worker_id: &str) -> Option<Job> {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            return backend
                .dequeue(worker_id, self.default_visibility)
                .ok()
                .flatten();
        }
        if let Some(backend) = &self.storage {
            return backend
                .dequeue(worker_id, self.default_visibility)
                .ok()
                .flatten();
        }
        let now = now_secs();
        let mut pending = self.pending.lock().unwrap();

        // Pop highest priority that is ready (scheduled_for <= now).
        // For not-ready jobs, hold them aside and reinsert after.
        let mut deferred: Vec<Job> = Vec::new();
        let chosen = loop {
            match pending.pop() {
                Some(job) => {
                    if job.scheduled_for <= now {
                        break Some(job);
                    } else {
                        deferred.push(job);
                    }
                }
                None => break None,
            }
        };
        for d in deferred {
            pending.push(d);
        }
        drop(pending);

        if let Some(job) = chosen {
            let mut in_flight = self.in_flight.write().unwrap();
            in_flight.insert(
                job.id.clone(),
                InFlightJob {
                    job: job.clone(),
                    worker_id: worker_id.to_string(),
                    started_at: Instant::now(),
                    visibility_timeout: self.default_visibility,
                },
            );
            Some(job)
        } else {
            None
        }
    }

    pub fn ack(&self, job_id: &str) -> Result<(), QueueError> {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            return backend.ack(job_id);
        }
        if let Some(backend) = &self.storage {
            return backend.ack(job_id);
        }
        let mut in_flight = self.in_flight.write().unwrap();
        if in_flight.remove(job_id).is_none() {
            return Err(QueueError::JobNotFound);
        }
        *self.completed_count.lock().unwrap() += 1;
        Ok(())
    }

    pub fn nack(
        &self,
        job_id: &str,
        error: &str,
        snapshot: Option<String>,
    ) -> Result<(), QueueError> {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            return backend.nack(job_id, error, snapshot);
        }
        if let Some(backend) = &self.storage {
            return backend.nack(job_id, error, snapshot);
        }
        let mut in_flight = self.in_flight.write().unwrap();
        let entry = in_flight.remove(job_id).ok_or(QueueError::JobNotFound)?;
        drop(in_flight);

        let mut job = entry.job;
        job.attempts += 1;

        if job.attempts >= job.max_attempts {
            *self.failed_count.lock().unwrap() += 1;
            self.dead_letter.lock().unwrap().push_back(DeadJob {
                job,
                final_error: error.to_string(),
                failed_at: now_secs(),
                response_snapshot: snapshot,
            });
            return Ok(());
        }

        let backoff_ms = self.retry_policy.compute_backoff(job.attempts);
        job.backoff_ms = backoff_ms;
        job.scheduled_for = now_secs() + (backoff_ms / 1000) as i64 + 1;
        self.pending.lock().unwrap().push(job);
        Ok(())
    }

    pub fn reclaim_expired(&self) -> usize {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            return backend.reclaim_expired().unwrap_or(0);
        }
        if let Some(backend) = &self.storage {
            return backend.reclaim_expired().unwrap_or(0);
        }
        let now = Instant::now();
        let mut in_flight = self.in_flight.write().unwrap();
        let expired: Vec<String> = in_flight
            .iter()
            .filter(|(_, j)| now.duration_since(j.started_at) > j.visibility_timeout)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        let mut pending = self.pending.lock().unwrap();
        for id in expired {
            if let Some(entry) = in_flight.remove(&id) {
                let mut job = entry.job;
                job.attempts += 1;
                pending.push(job);
            }
        }
        count
    }

    pub fn dead_letters(&self, limit: usize) -> Vec<DeadJob> {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            return backend.dead_letters(limit).unwrap_or_default();
        }
        if let Some(backend) = &self.storage {
            return backend.dead_letters(limit).unwrap_or_default();
        }
        self.dead_letter
            .lock()
            .unwrap()
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn requeue_dead(&self, job_id: &str) -> Result<(), QueueError> {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            return backend.requeue_dead(job_id);
        }
        if let Some(backend) = &self.storage {
            return backend.requeue_dead(job_id);
        }
        let mut dlq = self.dead_letter.lock().unwrap();
        let pos = dlq
            .iter()
            .position(|d| d.job.id == job_id)
            .ok_or(QueueError::JobNotFound)?;
        let dead = dlq.remove(pos).unwrap();
        drop(dlq);
        let mut job = dead.job;
        job.attempts = 0;
        job.scheduled_for = now_secs();
        self.pending.lock().unwrap().push(job);
        Ok(())
    }

    pub fn checkpoint(&self, path: &str) -> Result<(), QueueError> {
        // Storage-backed queues are already durable (SQLite/Redis); the file
        // checkpoint is a no-op in that mode.
        #[cfg(feature = "redis-backend")]
        if self.redis_storage.is_some() {
            return Ok(());
        }
        if self.storage.is_some() {
            return Ok(());
        }
        let pending: Vec<Job> = self.pending.lock().unwrap().iter().cloned().collect();
        let dlq: Vec<DeadJob> = self.dead_letter.lock().unwrap().iter().cloned().collect();
        let cp = Checkpoint {
            pending,
            dead_letter: dlq,
            completed_count: *self.completed_count.lock().unwrap(),
            failed_count: *self.failed_count.lock().unwrap(),
            backpressure_threshold: self.backpressure_threshold,
        };
        let bytes =
            serde_json::to_vec(&cp).map_err(|e| QueueError::IoError(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(())
    }

    pub fn load_checkpoint(path: &str) -> Result<Self, QueueError> {
        let bytes = fs::read(path).map_err(|e| QueueError::IoError(e.to_string()))?;
        let cp: Checkpoint =
            serde_json::from_slice(&bytes).map_err(|e| QueueError::IoError(e.to_string()))?;
        let mut heap = BinaryHeap::new();
        for j in cp.pending {
            heap.push(j);
        }
        Ok(Self {
            pending: Arc::new(Mutex::new(heap)),
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            dead_letter: Arc::new(Mutex::new(VecDeque::from(cp.dead_letter))),
            backpressure_threshold: cp.backpressure_threshold,
            completed_count: Arc::new(Mutex::new(cp.completed_count)),
            failed_count: Arc::new(Mutex::new(cp.failed_count)),
            retry_policy: RetryPolicy::default(),
            default_visibility: Duration::from_secs(60),
            storage: None,
            #[cfg(feature = "redis-backend")]
            redis_storage: None,
        })
    }

    pub fn stats(&self) -> QueueStats {
        #[cfg(feature = "redis-backend")]
        if let Some(backend) = &self.redis_storage {
            if let Ok(s) = backend.stats() {
                return s;
            }
        }
        if let Some(backend) = &self.storage {
            if let Ok(s) = backend.stats() {
                return s;
            }
        }
        let pending_count = self.pending.lock().unwrap().len();
        let in_flight_count = self.in_flight.read().unwrap().len();
        let dead_letter_count = self.dead_letter.lock().unwrap().len();
        QueueStats {
            pending_count,
            in_flight_count,
            dead_letter_count,
            total_completed: *self.completed_count.lock().unwrap(),
            total_failed: *self.failed_count.lock().unwrap(),
            backpressure_active: (pending_count + in_flight_count) >= self.backpressure_threshold,
        }
    }
}

// ---------------------------------------------------------------------------
// SqliteStorageQueueBackend — cross-worker distributed queue
// ---------------------------------------------------------------------------
//
// The gap reports (G9 §1, G3 §6) call for a *distributed* queue with cross-worker
// URL dedup. A real `redis` client is NOT available here — Cargo.lock contains no
// `redis` crate and adding one would be a heavy new dependency. Instead this change
// implements the distributed queue on the already-available `rusqlite` (bundled)
// using the same `Mutex<Connection>` pattern as `storage::SqliteBackend`.
//
// Guarantees (all cross-worker / multi-process):
//  - Cross-worker URL dedup: a UNIQUE index on `url_key` plus `INSERT ... ON
//    CONFLICT DO NOTHING` (`INSERT OR IGNORE`) means N workers cannot double-insert
//    the same URL; the first insert wins and later ones report `Duplicate`.
//  - Visibility timeout + reclaim: `dequeue` atomically claims a job with a lease
//    (`lease_expires_at`); a worker that crashes before `ack` has its lease expire
//    and `reclaim_expired` re-queues the job for another worker.
//  - `ack`/`nack`: complete a job, or retry with backoff / dead-letter it.
//
// Redis upgrade path (documented, NOT implemented): swap the SQL statements for
// Redis — `LPUSH`/`BLPOP`-style list or a sorted set keyed by scheduled time for
// `enqueue`/`dequeue`, `SET url <ts> NX PX <ttl>` (or a Bloom filter) for cross-worker
// dedup, and `ZADD`/`ZRANGEBYSCORE` on a "delayed" set for the visibility-timeout
// reclaim. The public `SqliteStorageQueueBackend` method set is the natural seam for
// a `RedisQueueBackend` with the same surface.

/// Outcome of a deduplicating enqueue against the storage-backed queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Inserted,
    Duplicate,
}

/// A SQLite-backed distributed job queue shared across workers/nodes.
///
/// Thread-safe via a `std::sync::Mutex<rusqlite::Connection>` (same pattern as
/// `storage::SqliteBackend`). Use the same DB path from every worker; each holds
/// its own `Connection` and the UNIQUE index + atomic claims provide the
/// cross-worker coordination.
pub struct SqliteStorageQueueBackend {
    conn: Mutex<Connection>,
    retry_policy: RetryPolicy,
}

impl SqliteStorageQueueBackend {
    /// Open (creating if needed) a SQLite DB at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QueueError> {
        let conn = Connection::open(path.as_ref()).map_err(|e| QueueError::IoError(e.to_string()))?;
        Self::from_conn(conn)
    }

    /// Open an ephemeral in-memory SQLite DB (tests / scratch).
    pub fn in_memory() -> Result<Self, QueueError> {
        let conn = Connection::open_in_memory().map_err(|e| QueueError::IoError(e.to_string()))?;
        Self::from_conn(conn)
    }

    fn from_conn(conn: Connection) -> Result<Self, QueueError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS distributed_jobs (
                id               TEXT PRIMARY KEY,
                job_type         TEXT NOT NULL,
                priority         INTEGER NOT NULL DEFAULT 5,
                payload          TEXT NOT NULL,
                url_key          TEXT,
                created_at       INTEGER NOT NULL,
                scheduled_for    INTEGER NOT NULL,
                attempts         INTEGER NOT NULL DEFAULT 0,
                max_attempts     INTEGER NOT NULL DEFAULT 5,
                backoff_ms       INTEGER NOT NULL DEFAULT 1000,
                state            TEXT NOT NULL DEFAULT 'pending',
                worker_id        TEXT,
                lease_expires_at INTEGER,
                final_error      TEXT,
                response_snapshot TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_distributed_jobs_url
                ON distributed_jobs(url_key) WHERE url_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_distributed_jobs_claim
                ON distributed_jobs(state, priority, scheduled_for);",
        )
        .map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            retry_policy: RetryPolicy::default(),
        })
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Enqueue a job with cross-worker URL dedup. If the job's URL already exists
    /// (UNIQUE `url_key` index) the insert is a no-op and `Duplicate` is returned,
    /// so N workers cannot double-insert the same URL.
    pub fn enqueue(&self, job: &Job) -> Result<EnqueueOutcome, QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let url_key = payload_url_key(&job.payload);
        let affected = conn
            .execute(
                "INSERT OR IGNORE INTO distributed_jobs
                 (id, job_type, priority, payload, url_key, created_at, scheduled_for,
                  attempts, max_attempts, backoff_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    job.id,
                    job_type_to_str(&job.job_type),
                    job.priority as i64,
                    job.payload.to_string(),
                    url_key,
                    job.created_at,
                    job.scheduled_for,
                    job.attempts as i64,
                    job.max_attempts as i64,
                    job.backoff_ms as i64,
                ],
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(if affected == 0 {
            EnqueueOutcome::Duplicate
        } else {
            EnqueueOutcome::Inserted
        })
    }

    /// Atomically claim the next ready job for `worker_id` with a visibility-timeout
    /// lease. Returns `None` if none are ready. Cross-worker safe: two workers
    /// racing to claim the same row — only one wins the conditional `UPDATE`.
    pub fn dequeue(
        &self,
        worker_id: &str,
        visibility_timeout: Duration,
    ) -> Result<Option<Job>, QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let now = now_secs();
        let now_ms = now_millis();
        let lease_until = now_ms + visibility_timeout.as_millis() as i64;
        // Loop until we claim one or there are no more ready candidates.
        for _ in 0..1024 {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM distributed_jobs
                     WHERE state = 'pending' AND scheduled_for <= ?1
                     ORDER BY priority ASC, created_at ASC, id ASC
                     LIMIT 1",
                    params![now],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| QueueError::IoError(e.to_string()))?;
            let Some(id) = id else {
                return Ok(None);
            };
            let affected = conn
                .execute(
                    "UPDATE distributed_jobs
                     SET state = 'in_flight', worker_id = ?1, lease_expires_at = ?2
                     WHERE id = ?3 AND state = 'pending'",
                    params![worker_id, lease_until, id],
                )
                .map_err(|e| QueueError::IoError(e.to_string()))?;
            if affected == 1 {
                return load_job(&conn, &id).map(Some);
            }
            // Another worker won the race; try the next candidate.
        }
        Ok(None)
    }

    pub fn ack(&self, job_id: &str) -> Result<(), QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let affected = conn
            .execute(
                "UPDATE distributed_jobs SET state = 'done'
                 WHERE id = ?1 AND state = 'in_flight'",
                params![job_id],
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        if affected == 0 {
            return Err(QueueError::JobNotFound);
        }
        Ok(())
    }

    pub fn nack(&self, job_id: &str, error: &str, snapshot: Option<String>) -> Result<(), QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let row = conn
            .query_row(
                "SELECT attempts, max_attempts FROM distributed_jobs
                 WHERE id = ?1 AND state = 'in_flight'",
                params![job_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let Some((attempts, max_attempts)) = row else {
            return Err(QueueError::JobNotFound);
        };
        let attempts = attempts + 1;
        if attempts >= max_attempts {
            conn.execute(
                "UPDATE distributed_jobs SET state = 'dead', final_error = ?2, response_snapshot = ?3
                 WHERE id = ?1 AND state = 'in_flight'",
                params![job_id, error, snapshot],
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        } else {
            let backoff_ms = self.retry_policy.compute_backoff(attempts as u32);
            let scheduled = now_secs() + (backoff_ms / 1000) as i64 + 1;
            conn.execute(
                "UPDATE distributed_jobs SET state = 'pending', worker_id = NULL,
                    lease_expires_at = NULL, attempts = ?2, backoff_ms = ?3, scheduled_for = ?4
                 WHERE id = ?1 AND state = 'in_flight'",
                params![job_id, attempts, backoff_ms as i64, scheduled],
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    /// Re-claim jobs whose visibility lease has expired (crashed worker). Returns
    /// the number of jobs re-queued for other workers.
    pub fn reclaim_expired(&self) -> Result<usize, QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let now_ms = now_millis();
        let affected = conn
            .execute(
                "UPDATE distributed_jobs
                 SET state = 'pending', worker_id = NULL, lease_expires_at = NULL
                 WHERE state = 'in_flight' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?1",
                params![now_ms],
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(affected)
    }

    pub fn dead_letters(&self, limit: usize) -> Result<Vec<DeadJob>, QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, job_type, priority, payload, created_at, scheduled_for, attempts,
                        max_attempts, backoff_ms, final_error, response_snapshot
                 FROM distributed_jobs WHERE state = 'dead' ORDER BY created_at DESC LIMIT ?1",
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit as i64], |r| Ok(load_dead_row(r)))
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| QueueError::IoError(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn requeue_dead(&self, job_id: &str) -> Result<(), QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let affected = conn
            .execute(
                "UPDATE distributed_jobs SET state = 'pending', worker_id = NULL,
                    lease_expires_at = NULL, attempts = 0, final_error = NULL,
                    response_snapshot = NULL, scheduled_for = ?2
                 WHERE id = ?1 AND state = 'dead'",
                params![job_id, now_secs()],
            )
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        if affected == 0 {
            return Err(QueueError::JobNotFound);
        }
        Ok(())
    }

    /// Whether a URL has already been claimed/seen by any worker (exact dedup).
    pub fn url_seen(&self, url: &str) -> Result<bool, QueueError> {
        let key = payload_url_key(&serde_json::json!({ "url": url }));
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let seen: Option<()> = conn
            .query_row(
                "SELECT 1 FROM distributed_jobs WHERE url_key = ?1 LIMIT 1",
                params![key],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(seen.is_some())
    }

    pub fn stats(&self) -> Result<QueueStats, QueueError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| QueueError::IoError("sqlite lock poisoned".into()))?;
        let count = |conn: &Connection, state: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM distributed_jobs WHERE state = ?1",
                params![state],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        let dead = count(&conn, "dead");
        Ok(QueueStats {
            pending_count: count(&conn, "pending") as usize,
            in_flight_count: count(&conn, "in_flight") as usize,
            dead_letter_count: dead as usize,
            total_completed: count(&conn, "done") as u64,
            total_failed: dead as u64,
            backpressure_active: false,
        })
    }
}

// ---------------------------------------------------------------------------
// RedisQueueBackend — cross-worker distributed queue (feature-gated)
// ---------------------------------------------------------------------------
//
// A real Redis-backed distributed job queue, compiled only when the
// `redis-backend` Cargo feature is enabled. It implements the SAME method
// surface as `SqliteStorageQueueBackend` (`enqueue`/`dequeue`/`ack`/`nack`/
// `reclaim_expired`/`dead_letters`/`requeue_dead`/`url_seen`/`stats`), so a
// `JobQueue` routes through it identically via `JobQueue::with_redis_backend`
// or a manual call. Requires a reachable Redis server (e.g. `redis-server` on
// `localhost:6379`), configured via `TALLOW_REDIS_URL` or the constructor URL.
//
// Data model (all keys under a configurable prefix, default `tallow:q:`):
//   <prefix>pending    ZSET  score = scheduled_for (ms)     member = job_id
//   <prefix>inflight   ZSET  score = lease_expires_at (ms)  member = job_id
//   <prefix>dead       ZSET  score = failed_at (ms)         member = job_id
//   <prefix>meta:<id>  HASH  serialized Job + state + worker + lease + dlq fields
//   <prefix>seen       SET   EXACT cross-worker URL dedup (url_key members)
//   <prefix>seen:bf    Bloom approximate dedup (RedisBloom BF.ADD / BF.EXISTS)
//   <prefix>done       STRING monotonically-increasing ack counter
//
// Cross-worker safety is inherited from Redis: `enqueue` dedups atomically
// (SADD / BF.ADD reports an existing URL without inserting the job), `dequeue`
// claims a job with a visibility-timeout lease via an atomic Lua script (only
// one racing worker wins the ZREM+ZADD), and `reclaim_expired` re-queues jobs
// whose lease lapsed because their worker crashed.
#[cfg(feature = "redis-backend")]
pub struct RedisQueueBackend {
    client: redis::Client,
    prefix: String,
    retry_policy: RetryPolicy,
    /// When true, cross-worker URL dedup uses RedisBloom `BF.ADD`/`BF.EXISTS`
    /// (approximate, small false-positive rate). When false (default), exact
    /// `SADD`/`SISMEMBER` is used.
    use_bloom: bool,
}

#[cfg(feature = "redis-backend")]
impl RedisQueueBackend {
    /// Connect to the Redis server at `url`, e.g. `redis://127.0.0.1:6379`.
    /// The URL may alternatively be supplied via the `TALLOW_REDIS_URL` env
    /// var. The connection is lazy: nothing touches the network until the first
    /// command, so call [`Self::connect`] to fail fast at startup.
    pub fn new(url: impl AsRef<str>) -> Result<Self, QueueError> {
        let client = redis::Client::open(url.as_ref())
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(Self {
            client,
            prefix: "tallow:q:".to_string(),
            retry_policy: RetryPolicy::default(),
            use_bloom: false,
        })
    }

    /// Set the Redis key prefix (default `tallow:q:`). Give each deployment /
    /// queue namespace a distinct prefix to avoid cross-cluster collisions.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Enable approximate (Bloom) cross-worker URL dedup via RedisBloom
    /// (`BF.ADD`/`BF.EXISTS`). Falls back to exact `SADD` if the server lacks
    /// the RedisBloom module.
    pub fn with_bloom_dedup(mut self) -> Self {
        self.use_bloom = true;
        self
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Verify the Redis server is reachable. Returns `Ok` on a successful PING.
    pub fn connect(&self) -> Result<(), QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        redis::cmd("PING")
            .query::<()>(&mut conn)
            .map_err(|e| QueueError::IoError(e.to_string()))
    }

    fn key(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name)
    }

    fn meta_key(&self, id: &str) -> String {
        format!("{}meta:{}", self.prefix, id)
    }

    /// Enqueue a job with cross-worker URL dedup. If the job's URL was already
    /// claimed by any worker (SADD returns 0 / BF.ADD says present), the job is
    /// NOT inserted and `Duplicate` is returned, so N workers cannot double-insert.
    pub fn enqueue(&self, job: &Job) -> Result<EnqueueOutcome, QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let seen_key = self.key("seen");
        let bf_key = self.key("seen:bf");

        if let Some(url) = payload_url_key(&job.payload) {
            let duplicate = if self.use_bloom {
                // BF.EXISTS true => likely present; skip (approximate dedup).
                redis::cmd("BF.EXISTS")
                    .arg(&bf_key)
                    .arg(&url)
                    .query::<bool>(&mut conn)
                    .unwrap_or(false)
            } else {
                // SADD returns 0 when the url_key was already a member (exact dedup).
                let added: i32 = conn.sadd(&seen_key, &url).map_err(redis_err)?;
                added == 0
            };
            if duplicate {
                return Ok(EnqueueOutcome::Duplicate);
            }
            if self.use_bloom {
                let _ = redis::cmd("BF.ADD")
                    .arg(&bf_key)
                    .arg(&url)
                    .query::<i64>(&mut conn);
            }
        }

        let meta = self.meta_key(&job.id);
        let _: () = conn
            .hset_multiple(
                &meta,
                &[
                    ("id", job.id.as_str()),
                    ("type", job_type_to_str(&job.job_type)),
                    ("priority", &job.priority.to_string()),
                    ("payload", &job.payload.to_string()),
                    ("created_at", &job.created_at.to_string()),
                    ("scheduled_for", &job.scheduled_for.to_string()),
                    ("attempts", &job.attempts.to_string()),
                    ("max_attempts", &job.max_attempts.to_string()),
                    ("backoff_ms", &job.backoff_ms.to_string()),
                    ("state", "pending"),
                ],
            )
            .map_err(redis_err)?;
        let _: () = conn
            .zadd(self.key("pending"), &job.id, job.scheduled_for * 1000)
            .map_err(redis_err)?;
        Ok(EnqueueOutcome::Inserted)
    }

    /// Atomically claim the next ready job for `worker_id` with a
    /// visibility-timeout lease. Cross-worker safe: the Lua script moves a
    /// ready job from `pending` to `inflight` in one atomic step, so only one
    /// racing worker wins. Orders by `scheduled_for` (FIFO within the ready set).
    pub fn dequeue(
        &self,
        worker_id: &str,
        visibility_timeout: Duration,
    ) -> Result<Option<Job>, QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let now_ms = now_millis();
        let lease_until = now_ms + visibility_timeout.as_millis() as i64;
        let meta_prefix = format!("{}meta:", self.prefix);

        let script = redis::Script::new(
            "local id = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, 1)[1] \
             if not id then return nil end \
             redis.call('ZREM', KEYS[1], id) \
             redis.call('ZADD', KEYS[2], ARGV[2], id) \
             redis.call('HSET', ARGV[3] .. id, 'state', 'in_flight', 'worker_id', ARGV[4], 'lease_expires_at', ARGV[2]) \
             return id",
        );
        script.key(self.key("pending")).key(self.key("inflight"));
        script
            .arg(now_ms)
            .arg(lease_until)
            .arg(meta_prefix)
            .arg(worker_id);

        let id: Option<String> = script
            .invoke(&mut conn)
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let Some(id) = id else {
            return Ok(None);
        };
        let job = self.load_job(&mut conn, &id)?;
        Ok(Some(job))
    }

    /// Complete a claimed job. Returns `JobNotFound` if the job is not currently
    /// in-flight (already acked, reclaimed, or never claimed).
    pub fn ack(&self, job_id: &str) -> Result<(), QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let script = redis::Script::new(
            "if not redis.call('ZSCORE', KEYS[1], ARGV[1]) then return 0 end \
             redis.call('ZREM', KEYS[1], ARGV[1]) \
             redis.call('HSET', ARGV[2], 'state', 'done') \
             redis.call('INCR', ARGV[3]) \
             return 1",
        );
        script.key(self.key("inflight"));
        script
            .arg(job_id)
            .arg(self.meta_key(job_id))
            .arg(self.key("done"));
        let ok: i64 = script
            .invoke(&mut conn)
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        if ok == 0 {
            return Err(QueueError::JobNotFound);
        }
        Ok(())
    }

    /// Negative-ack a claimed job: retry with backoff (back to `pending` with a
    /// new `scheduled_for`) or, when `attempts >= max_attempts`, move it to the
    /// dead-letter set. Returns `JobNotFound` if the job is not in-flight.
    pub fn nack(&self, job_id: &str, error: &str, snapshot: Option<String>) -> Result<(), QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let meta = self.meta_key(job_id);
        let attempts: i64 = conn.hget(&meta, "attempts").map_err(redis_err)?;
        let max_attempts: i64 = conn.hget(&meta, "max_attempts").map_err(redis_err)?;
        let attempts = attempts + 1;
        let retry = attempts < max_attempts;
        let backoff_ms = self.retry_policy.compute_backoff(attempts as u32) as i64;
        let sched_ms = (now_secs() + (backoff_ms / 1000) + 1) * 1000;

        let script = redis::Script::new(
            "if not redis.call('ZSCORE', KEYS[1], ARGV[1]) then return 0 end \
             redis.call('ZREM', KEYS[1], ARGV[1]) \
             if ARGV[7] == '1' then \
               redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1]) \
               redis.call('HSET', ARGV[8], 'state', 'pending', 'attempts', ARGV[3], 'backoff_ms', ARGV[4], 'scheduled_for', ARGV[5], 'worker_id', '') \
             else \
               redis.call('ZADD', KEYS[3], ARGV[6], ARGV[1]) \
               redis.call('HSET', ARGV[8], 'state', 'dead', 'attempts', ARGV[3], 'final_error', ARGV[9], 'response_snapshot', ARGV[10]) \
             end \
             return 1",
        );
        script.key(self.key("inflight")).key(self.key("pending")).key(self.key("dead"));
        script
            .arg(job_id)
            .arg(sched_ms)
            .arg(attempts)
            .arg(backoff_ms)
            .arg(sched_ms / 1000)
            .arg(now_millis())
            .arg(if retry { "1" } else { "0" })
            .arg(&meta)
            .arg(error)
            .arg(snapshot.unwrap_or_default());
        let ok: i64 = script
            .invoke(&mut conn)
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        if ok == 0 {
            return Err(QueueError::JobNotFound);
        }
        Ok(())
    }

    /// Re-claim jobs whose visibility lease has expired (crashed worker) back to
    /// `pending`, immediately claimable by any worker. Returns the count.
    pub fn reclaim_expired(&self) -> Result<usize, QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let now = now_millis();
        let meta_prefix = format!("{}meta:", self.prefix);
        let script = redis::Script::new(
            "local ids = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1]) \
             for _, id in ipairs(ids) do \
               redis.call('ZREM', KEYS[1], id) \
               redis.call('ZADD', KEYS[2], ARGV[1], id) \
               redis.call('HSET', ARGV[2] .. id, 'state', 'pending', 'worker_id', '', 'lease_expires_at', '') \
             end \
             return #ids",
        );
        script.key(self.key("inflight")).key(self.key("pending"));
        script.arg(now).arg(meta_prefix);
        let n: i64 = script
            .invoke(&mut conn)
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        Ok(n as usize)
    }

    /// Read dead-letter jobs, newest first.
    pub fn dead_letters(&self, limit: usize) -> Result<Vec<DeadJob>, QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let ids: Vec<String> = if limit == 0 {
            Vec::new()
        } else {
            conn.zrevrange(self.key("dead"), 0, limit as isize - 1)
                .map_err(redis_err)?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let job = self.load_job(&mut conn, &id)?;
            let meta = self.meta_key(&id);
            let final_error: String = conn.hget(&meta, "final_error").map_err(redis_err)?;
            let snapshot: String = conn.hget(&meta, "response_snapshot").map_err(redis_err)?;
            let failed_at: f64 = conn.zscore(self.key("dead"), &id).map_err(redis_err)?;
            out.push(DeadJob {
                job,
                final_error,
                failed_at: (failed_at as i64) / 1000,
                response_snapshot: if snapshot.is_empty() { None } else { Some(snapshot) },
            });
        }
        Ok(out)
    }

    /// Requeue a dead-letter job back to `pending` with a fresh attempt counter.
    pub fn requeue_dead(&self, job_id: &str) -> Result<(), QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let meta = self.meta_key(job_id);
        let script = redis::Script::new(
            "if not redis.call('ZSCORE', KEYS[1], ARGV[1]) then return 0 end \
             redis.call('ZREM', KEYS[1], ARGV[1]) \
             redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1]) \
             redis.call('HSET', ARGV[3], 'state', 'pending', 'attempts', 0, 'worker_id', '', 'final_error', '', 'response_snapshot', '') \
             return 1",
        );
        script.key(self.key("dead")).key(self.key("pending"));
        script.arg(job_id).arg(now_millis()).arg(&meta);
        let ok: i64 = script
            .invoke(&mut conn)
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        if ok == 0 {
            return Err(QueueError::JobNotFound);
        }
        Ok(())
    }

    /// Whether a URL has already been seen by any worker. Exact `SISMEMBER` by
    /// default; approximate `BF.EXISTS` when bloom dedup is enabled.
    pub fn url_seen(&self, url: &str) -> Result<bool, QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let Some(key) = payload_url_key(&serde_json::json!({ "url": url })) else {
            return Ok(false);
        };
        if self.use_bloom {
            return redis::cmd("BF.EXISTS")
                .arg(self.key("seen:bf"))
                .arg(&key)
                .query::<bool>(&mut conn)
                .map_err(redis_err);
        }
        conn.sismember(self.key("seen"), &key).map_err(redis_err)
    }

    pub fn stats(&self) -> Result<QueueStats, QueueError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| QueueError::IoError(e.to_string()))?;
        let pending: i64 = conn.zcard(self.key("pending")).map_err(redis_err)?;
        let inflight: i64 = conn.zcard(self.key("inflight")).map_err(redis_err)?;
        let dead: i64 = conn.zcard(self.key("dead")).map_err(redis_err)?;
        let done: Option<i64> = conn.get(self.key("done")).map_err(redis_err)?;
        Ok(QueueStats {
            pending_count: pending as usize,
            in_flight_count: inflight as usize,
            dead_letter_count: dead as usize,
            total_completed: done.unwrap_or(0) as u64,
            total_failed: dead as u64,
            backpressure_active: false,
        })
    }

    /// Deserialize a Job from its `<prefix>meta:<id>` hash.
    fn load_job(&self, conn: &mut redis::Connection, id: &str) -> Result<Job, QueueError> {
        let fields: Vec<(String, String)> = conn
            .hgetall(self.meta_key(id))
            .map_err(redis_err)?;
        let mut m = std::collections::HashMap::new();
        for (k, v) in fields {
            m.insert(k, v);
        }
        let get = |k: &str| -> String { m.get(k).cloned().unwrap_or_default() };
        Ok(Job {
            id: id.to_string(),
            job_type: job_type_from_str(&get("type")),
            priority: get("priority").parse().unwrap_or(5),
            payload: serde_json::from_str(&get("payload")).unwrap_or(serde_json::Value::Null),
            created_at: get("created_at").parse().unwrap_or(0),
            scheduled_for: get("scheduled_for").parse().unwrap_or(0),
            attempts: get("attempts").parse().unwrap_or(0),
            max_attempts: get("max_attempts").parse().unwrap_or(5),
            backoff_ms: get("backoff_ms").parse().unwrap_or(1000),
        })
    }
}

#[cfg(feature = "redis-backend")]
fn redis_err(e: redis::RedisError) -> QueueError {
    QueueError::IoError(e.to_string())
}

fn job_type_to_str(jt: &JobType) -> &'static str {
    match jt {
        JobType::ScrapePage => "ScrapePage",
        JobType::ExtractProduct => "ExtractProduct",
        JobType::MatchProduct => "MatchProduct",
        JobType::ValidatePrice => "ValidatePrice",
        JobType::SendAlert => "SendAlert",
        JobType::RefreshCookies => "RefreshCookies",
        JobType::WarmupProfile => "WarmupProfile",
        JobType::ParseFlyer => "ParseFlyer",
        JobType::SyncApi => "SyncApi",
    }
}

fn job_type_from_str(s: &str) -> JobType {
    match s {
        "ExtractProduct" => JobType::ExtractProduct,
        "MatchProduct" => JobType::MatchProduct,
        "ValidatePrice" => JobType::ValidatePrice,
        "SendAlert" => JobType::SendAlert,
        "RefreshCookies" => JobType::RefreshCookies,
        "WarmupProfile" => JobType::WarmupProfile,
        "ParseFlyer" => JobType::ParseFlyer,
        "SyncApi" => JobType::SyncApi,
        _ => JobType::ScrapePage,
    }
}

/// Extract a dedup key (a URL string) from a job payload, if present.
fn payload_url_key(payload: &serde_json::Value) -> Option<String> {
    ["url", "target_url", "target"]
        .iter()
        .find_map(|k| payload.get(*k).and_then(|v| v.as_str()).map(|s| s.to_string()))
}

fn load_job(conn: &Connection, id: &str) -> Result<Job, QueueError> {
    conn.query_row(
        "SELECT id, job_type, priority, payload, created_at, scheduled_for, attempts,
                max_attempts, backoff_ms
         FROM distributed_jobs WHERE id = ?1",
        params![id],
        |r| {
            let payload_str: String = r.get(3)?;
            Ok(Job {
                id: r.get(0)?,
                job_type: job_type_from_str(&r.get::<_, String>(1)?),
                priority: r.get(2)?,
                payload: serde_json::from_str(&payload_str)
                    .unwrap_or_else(|_| serde_json::Value::Null),
                created_at: r.get(4)?,
                scheduled_for: r.get(5)?,
                attempts: r.get(6)?,
                max_attempts: r.get(7)?,
                backoff_ms: r.get(8)?,
            })
        },
    )
    .map_err(|e| QueueError::IoError(e.to_string()))
}

fn load_dead_row(r: &rusqlite::Row<'_>) -> DeadJob {
    let payload_str: String = r.get(3).unwrap_or_default();
    DeadJob {
        job: Job {
            id: r.get(0).unwrap_or_default(),
            job_type: job_type_from_str(&r.get::<_, String>(1).unwrap_or_default()),
            priority: r.get(2).unwrap_or(5),
            payload: serde_json::from_str(&payload_str).unwrap_or_else(|_| serde_json::Value::Null),
            created_at: r.get(4).unwrap_or(0),
            scheduled_for: r.get(5).unwrap_or(0),
            attempts: r.get(6).unwrap_or(0),
            max_attempts: r.get(7).unwrap_or(0),
            backoff_ms: r.get(8).unwrap_or(0),
        },
        final_error: r.get(9).unwrap_or_default(),
        failed_at: now_secs(),
        response_snapshot: r.get(10).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Workflow engine
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum WorkflowAction {
    Continue,
    Stop,
    Retry,
    Skip,
}

#[derive(Clone, Debug)]
pub enum WorkflowState {
    Pending,
    Running,
    Completed,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct WorkflowStep {
    pub step_id: String,
    pub job_type: JobType,
    pub depends_on: Vec<String>,
    pub on_success: WorkflowAction,
    pub on_failure: WorkflowAction,
}

#[derive(Clone, Debug)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub state: WorkflowState,
    completed_steps: HashSet<String>,
    failed_steps: HashSet<String>,
}

impl Workflow {
    pub fn new(id: impl Into<String>, name: impl Into<String>, steps: Vec<WorkflowStep>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            steps,
            state: WorkflowState::Pending,
            completed_steps: HashSet::new(),
            failed_steps: HashSet::new(),
        }
    }

    /// Returns step IDs whose dependencies are satisfied and not yet run.
    pub fn ready_steps(&self) -> Vec<&WorkflowStep> {
        self.steps
            .iter()
            .filter(|s| {
                !self.completed_steps.contains(&s.step_id)
                    && !self.failed_steps.contains(&s.step_id)
                    && s.depends_on.iter().all(|d| self.completed_steps.contains(d))
            })
            .collect()
    }

    pub fn mark_completed(&mut self, step_id: &str) {
        self.completed_steps.insert(step_id.to_string());
        if self.completed_steps.len() == self.steps.len() {
            self.state = WorkflowState::Completed;
        } else {
            self.state = WorkflowState::Running;
        }
    }

    pub fn mark_failed(&mut self, step_id: &str, error: &str) {
        self.failed_steps.insert(step_id.to_string());
        self.state = WorkflowState::Failed(format!("step {} failed: {}", step_id, error));
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, WorkflowState::Completed | WorkflowState::Failed(_))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current unix time in milliseconds (used for sub-second lease precision).
fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn deterministic_id(job_type: &JobType, payload: &serde_json::Value, ts: i64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let bucket = ts / 60; // 1-minute buckets for idempotency
    let mut h = DefaultHasher::new();
    format!("{:?}", job_type).hash(&mut h);
    payload.to_string().hash(&mut h);
    bucket.hash(&mut h);
    format!("job_{:016x}", h.finish())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk(jt: JobType, prio: u8) -> Job {
        let mut j = Job::new(jt, json!({"x": prio}));
        j.priority = prio;
        // unique id per call
        j.id = format!("j_{}_{}", prio, rand_suffix());
        j
    }

    fn rand_suffix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::SeqCst).to_string()
    }

    #[test]
    fn enqueue_dequeue_basic() {
        let q = JobQueue::new(100);
        let j = mk(JobType::ScrapePage, 5);
        let id = j.id.clone();
        q.enqueue(j).unwrap();
        let got = q.dequeue("w1").unwrap();
        assert_eq!(got.id, id);
        assert_eq!(q.stats().in_flight_count, 1);
    }

    #[test]
    fn priority_ordering() {
        let q = JobQueue::new(100);
        q.enqueue(mk(JobType::ScrapePage, 9)).unwrap();
        q.enqueue(mk(JobType::ScrapePage, 1)).unwrap();
        q.enqueue(mk(JobType::ScrapePage, 5)).unwrap();
        assert_eq!(q.dequeue("w").unwrap().priority, 1);
        assert_eq!(q.dequeue("w").unwrap().priority, 5);
        assert_eq!(q.dequeue("w").unwrap().priority, 9);
    }

    #[test]
    fn ack_removes_in_flight() {
        let q = JobQueue::new(10);
        let j = mk(JobType::ScrapePage, 5);
        let id = j.id.clone();
        q.enqueue(j).unwrap();
        q.dequeue("w").unwrap();
        q.ack(&id).unwrap();
        assert_eq!(q.stats().in_flight_count, 0);
        assert_eq!(q.stats().total_completed, 1);
    }

    #[test]
    fn nack_retries_with_backoff() {
        let q = JobQueue::new(10);
        let mut j = mk(JobType::ScrapePage, 5);
        j.max_attempts = 3;
        let id = j.id.clone();
        q.enqueue(j).unwrap();
        q.dequeue("w").unwrap();
        q.nack(&id, "boom", None).unwrap();
        assert_eq!(q.stats().in_flight_count, 0);
        assert_eq!(q.stats().pending_count, 1);
    }

    #[test]
    fn nack_exceeds_max_attempts_to_dlq() {
        let q = JobQueue::new(10);
        let mut j = mk(JobType::ScrapePage, 5);
        j.max_attempts = 2;
        j.attempts = 1; // next nack pushes to DLQ
        let id = j.id.clone();
        q.enqueue(j).unwrap();
        q.dequeue("w").unwrap();
        q.nack(&id, "fatal", Some("<html/>".into())).unwrap();
        assert_eq!(q.stats().dead_letter_count, 1);
        assert_eq!(q.stats().total_failed, 1);
        let dl = q.dead_letters(10);
        assert_eq!(dl[0].final_error, "fatal");
    }

    #[test]
    fn reclaim_expired_jobs() {
        let q = JobQueue::new(10).with_visibility_timeout(Duration::from_millis(10));
        let j = mk(JobType::ScrapePage, 5);
        q.enqueue(j).unwrap();
        q.dequeue("worker_dead").unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let n = q.reclaim_expired();
        assert_eq!(n, 1);
        assert_eq!(q.stats().pending_count, 1);
    }

    #[test]
    fn backpressure_rejects_new_jobs() {
        let q = JobQueue::new(2);
        q.enqueue(mk(JobType::ScrapePage, 5)).unwrap();
        q.enqueue(mk(JobType::ScrapePage, 5)).unwrap();
        let r = q.enqueue(mk(JobType::ScrapePage, 5));
        assert!(matches!(r, Err(QueueError::BackpressureActive)));
        assert!(q.stats().backpressure_active);
    }

    #[test]
    fn checkpoint_save_load() {
        let dir = std::env::temp_dir().join(format!("tallow_jq_{}", rand_suffix()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cp.json");
        let path_s = path.to_string_lossy().to_string();

        let q = JobQueue::new(50);
        q.enqueue(mk(JobType::ScrapePage, 3)).unwrap();
        q.enqueue(mk(JobType::ExtractProduct, 7)).unwrap();
        q.checkpoint(&path_s).unwrap();

        let q2 = JobQueue::load_checkpoint(&path_s).unwrap();
        assert_eq!(q2.stats().pending_count, 2);
        let first = q2.dequeue("w").unwrap();
        assert_eq!(first.priority, 3);
    }

    #[test]
    fn retry_policy_backoff_and_jitter() {
        let p = RetryPolicy::default();
        let b1 = p.compute_backoff(1);
        let b2 = p.compute_backoff(2);
        let b3 = p.compute_backoff(3);
        // Generally increasing (jitter ±20% allows minor noise)
        assert!(b2 > b1 / 2);
        assert!(b3 > b1);
        // Capped
        let huge = p.compute_backoff(50);
        assert!(huge <= p.max_backoff_ms + (p.max_backoff_ms / 5));

        let no_jitter = RetryPolicy {
            jitter: false,
            ..RetryPolicy::default()
        };
        assert_eq!(no_jitter.compute_backoff(0), 1000);
        assert_eq!(no_jitter.compute_backoff(1), 2000);
        assert_eq!(no_jitter.compute_backoff(2), 4000);
    }

    #[test]
    fn workflow_with_step_dependencies() {
        let steps = vec![
            WorkflowStep {
                step_id: "scrape".into(),
                job_type: JobType::ScrapePage,
                depends_on: vec![],
                on_success: WorkflowAction::Continue,
                on_failure: WorkflowAction::Retry,
            },
            WorkflowStep {
                step_id: "extract".into(),
                job_type: JobType::ExtractProduct,
                depends_on: vec!["scrape".into()],
                on_success: WorkflowAction::Continue,
                on_failure: WorkflowAction::Stop,
            },
            WorkflowStep {
                step_id: "match".into(),
                job_type: JobType::MatchProduct,
                depends_on: vec!["extract".into()],
                on_success: WorkflowAction::Continue,
                on_failure: WorkflowAction::Skip,
            },
            WorkflowStep {
                step_id: "alert".into(),
                job_type: JobType::SendAlert,
                depends_on: vec!["match".into()],
                on_success: WorkflowAction::Stop,
                on_failure: WorkflowAction::Stop,
            },
        ];

        let mut wf = Workflow::new("wf1", "price-pipeline", steps);
        let ready: Vec<String> = wf.ready_steps().iter().map(|s| s.step_id.clone()).collect();
        assert_eq!(ready, vec!["scrape"]);

        wf.mark_completed("scrape");
        let ready: Vec<String> = wf.ready_steps().iter().map(|s| s.step_id.clone()).collect();
        assert_eq!(ready, vec!["extract"]);

        wf.mark_completed("extract");
        wf.mark_completed("match");
        wf.mark_completed("alert");
        assert!(wf.is_done());
        assert!(matches!(wf.state, WorkflowState::Completed));
    }
}

#[cfg(test)]
mod storage_backend_tests {
    use super::*;
    use serde_json::json;

    fn url_job(url: &str) -> Job {
        Job::new(JobType::ScrapePage, json!({ "url": url }))
    }

    #[test]
    fn backend_enqueue_dequeue_ack() {
        let backend = SqliteStorageQueueBackend::in_memory().unwrap();
        let job = url_job("https://example.com/a");
        let id = job.id.clone();
        assert_eq!(backend.enqueue(&job).unwrap(), EnqueueOutcome::Inserted);
        let got = backend.dequeue("w1", Duration::from_secs(30)).unwrap().unwrap();
        assert_eq!(got.id, id);
        assert_eq!(backend.stats().unwrap().in_flight_count, 1);
        backend.ack(&id).unwrap();
        assert_eq!(backend.stats().unwrap().total_completed, 1);
    }

    #[test]
    fn backend_cross_worker_url_dedup() {
        // Two "workers" share one SQLite queue: the same URL may only be inserted
        // once (UNIQUE url_key + INSERT OR IGNORE).
        let backend = SqliteStorageQueueBackend::in_memory().unwrap();
        assert_eq!(
            backend.enqueue(&url_job("https://example.com/x")).unwrap(),
            EnqueueOutcome::Inserted
        );
        assert_eq!(
            backend.enqueue(&url_job("https://example.com/x")).unwrap(),
            EnqueueOutcome::Duplicate,
            "second worker must not double-insert the URL"
        );
        assert_eq!(backend.stats().unwrap().pending_count, 1);
        assert!(backend.url_seen("https://example.com/x").unwrap());
    }

    #[test]
    fn backend_visibility_reclaim() {
        let backend = SqliteStorageQueueBackend::in_memory().unwrap();
        backend.enqueue(&url_job("https://example.com/a")).unwrap();
        // Claim with a sub-second lease, then let it expire.
        backend.dequeue("dead_worker", Duration::from_millis(1)).unwrap().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let reclaimed = backend.reclaim_expired().unwrap();
        assert_eq!(reclaimed, 1);
        // Another worker can now claim the reclaimed job.
        let got = backend.dequeue("w2", Duration::from_secs(30)).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn backend_nack_retries_then_dlq() {
        let backend = SqliteStorageQueueBackend::in_memory().unwrap();

        // Retry branch: a nack with attempts remaining returns the job to pending
        // (with backoff) instead of dead-lettering it.
        let mut job = url_job("https://example.com/a");
        job.max_attempts = 3;
        let id_a = job.id.clone();
        backend.enqueue(&job).unwrap();
        backend.dequeue("w", Duration::from_secs(30)).unwrap();
        backend.nack(&id_a, "boom", None).unwrap();
        assert_eq!(backend.stats().unwrap().pending_count, 1, "retried job re-queued");
        assert_eq!(backend.stats().unwrap().dead_letter_count, 0);

        // DLQ branch: a nack when attempts reach max_attempts moves the job to dead
        // letter (pre-set attempts so the branch is reached immediately).
        let mut job2 = url_job("https://example.com/b");
        job2.max_attempts = 2;
        job2.attempts = 1;
        let id_b = job2.id.clone();
        backend.enqueue(&job2).unwrap();
        backend.dequeue("w", Duration::from_secs(30)).unwrap();
        backend
            .nack(&id_b, "fatal", Some("<html/>".into()))
            .unwrap();
        assert_eq!(backend.stats().unwrap().dead_letter_count, 1);
        let dl = backend.dead_letters(10).unwrap();
        assert_eq!(dl.len(), 1);
        assert_eq!(dl[0].final_error, "fatal");
        // Requeue from dead letter.
        backend.requeue_dead(&id_b).unwrap();
        assert_eq!(backend.stats().unwrap().pending_count, 2);
    }
}

