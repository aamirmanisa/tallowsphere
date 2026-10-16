use rusqlite::Connection;
use tokio::sync::{broadcast, Mutex};

/// Recover jobs that were running when the daemon last stopped/crashed.
///
/// Scans the jobs table for rows with status='running', reads their transfer_resume
/// state (byte offset checkpoint), resets them to 'created' so the executor picks
/// them up, and logs/emits resume events.
///
/// Returns the number of jobs recovered.
pub async fn recover_crashed_jobs(
    db: &Mutex<Connection>,
    progress_tx: &broadcast::Sender<crate::sse::ProgressEvent>,
) -> usize {
    let conn = db.lock().await;

    // Find all jobs that were running at shutdown/crash time
    let running_jobs = match crate::db::list_jobs(&conn, Some("running")) {
        Ok(jobs) => jobs,
        Err(e) => {
            tracing::error!("Failed to query running jobs for crash recovery: {}", e);
            return 0;
        }
    };

    if running_jobs.is_empty() {
        tracing::info!("No crashed jobs to recover");
        return 0;
    }

    tracing::info!(
        "Found {} crashed job(s), recovering...",
        running_jobs.len()
    );
    let mut recovered = 0usize;

    for job in &running_jobs {
        // Read the transfer_resume checkpoint
        let (byte_offset, file_path) = match crate::db::get_transfer_state(&conn, &job.id) {
            Ok(Some(state)) => state,
            Ok(None) => {
                tracing::warn!(
                    "Job {} was running but has no transfer_resume row — starting from offset 0",
                    job.id
                );
                (0u64, String::new())
            }
            Err(e) => {
                tracing::error!(
                    "Failed to read transfer_resume for job {}: {}",
                    job.id,
                    e
                );
                continue;
            }
        };

        // Reset the job to 'created' so it re-enters the queue
        let detail = if byte_offset > 0 {
            format!(
                "resumed after crash at offset {} (file: {})",
                byte_offset, file_path
            )
        } else {
            "resumed after crash".to_string()
        };

        if let Err(e) = crate::db::update_job_status(&conn, &job.id, "created", Some(&detail)) {
            tracing::error!(
                "Failed to reset job {} status for recovery: {}",
                job.id,
                e
            );
            continue;
        }

        // Emit SSE event so connected clients see the recovery
        let timestamp = chrono::Utc::now().to_rfc3339();
        let _ = progress_tx.send(crate::sse::ProgressEvent::JobUpdate {
            job_id: job.id.clone(),
            status: "created".to_string(),
            detail: Some(detail.clone()),
            timestamp,
        });

        tracing::info!("Recovered job {} ({}) — {}", job.id, job.name, detail);
        recovered += 1;
    }

    recovered
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::sync::Arc;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().expect("failed to create in-memory DB");

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                config_json TEXT NOT NULL,
                error_message TEXT,
                priority INTEGER NOT NULL DEFAULT 0,
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 3,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                event TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transfer_resume (
                job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
                byte_offset INTEGER NOT NULL DEFAULT 0,
                file_path TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_job_history_job_id ON job_history(job_id);
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);",
        )
        .expect("failed to create test schema");

        conn
    }

    fn insert_test_job(conn: &Connection, id: &str, name: &str, status: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO jobs (id, name, status, config_json, priority, retry_count, max_retries, created_at, updated_at)
             VALUES (?1, ?2, ?3, '{}', 5, 0, 3, ?4, ?4)",
            rusqlite::params![id, name, status, now],
        )
        .unwrap();
    }

    fn insert_transfer_state(conn: &Connection, job_id: &str, byte_offset: i64, file_path: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO transfer_resume (job_id, byte_offset, file_path, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![job_id, byte_offset, file_path, now],
        )
        .unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 1: recover_crashed_jobs finds all jobs with status='running'
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_finds_all_running_jobs() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-1", "alpha", "running");
        insert_test_job(&conn, "job-2", "beta", "running");
        insert_test_job(&conn, "job-3", "gamma", "created"); // not running — should be ignored
        insert_test_job(&conn, "job-4", "delta", "completed"); // not running

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;

        assert_eq!(recovered, 2, "should recover exactly 2 running jobs");
    }

    // -----------------------------------------------------------------------
    // Test 2: Each running job gets its transfer_resume row read
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_reads_transfer_resume_state() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-1", "alpha", "running");
        insert_transfer_state(&conn, "job-1", 4096, "/mnt/data/file.bin");

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 1, "should recover 1 job");

        // Verify the transfer_resume data was read by checking history
        let conn = db.lock().await;
        let history = crate::db::get_job_history(&conn, "job-1").unwrap();
        let has_resume_event = history.iter().any(|h| {
            h.event == "created"
                && h.detail
                    .as_ref()
                    .map_or(false, |d| d.contains("offset 4096"))
        });
        assert!(
            has_resume_event,
            "history should contain resume detail with byte_offset 4096"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Each recovered job is reset to status='created'
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_resets_jobs_to_created() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-1", "alpha", "running");
        insert_test_job(&conn, "job-2", "beta", "running");

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 2, "should recover 2 jobs");

        let conn = db.lock().await;
        let job1 = crate::db::get_job(&conn, "job-1").unwrap().unwrap();
        let job2 = crate::db::get_job(&conn, "job-2").unwrap().unwrap();

        assert_eq!(job1.status, "created", "job-1 should be reset to 'created'");
        assert_eq!(job2.status, "created", "job-2 should be reset to 'created'");
    }

    // -----------------------------------------------------------------------
    // Test 4: A job_history entry appended with event='resumed'
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_appends_resume_history_entry() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-1", "alpha", "running");
        insert_transfer_state(&conn, "job-1", 8192, "/tmp/resume.bin");

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 1);

        let conn = db.lock().await;
        let history = crate::db::get_job_history(&conn, "job-1").unwrap();

        let resume_entry = history
            .iter()
            .find(|h| h.event == "created"
                  && h.detail
                      .as_ref()
                      .map_or(false, |d| d.contains("resumed after crash")));
        assert!(
            resume_entry.is_some(),
            "history should contain a 'created' event with resume detail. History: {:?}",
            history.iter().map(|h| format!("({}: {})", h.event, h.detail.as_deref().unwrap_or("none"))).collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: SSE ProgressEvent::JobUpdate emitted for each resumed job
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_emits_sse_events() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-a", "first", "running");
        insert_test_job(&conn, "job-b", "second", "running");

        let db = Arc::new(Mutex::new(conn));
        let (tx, mut rx) = broadcast::channel::<crate::sse::ProgressEvent>(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 2);

        // Collect received events
        let mut received = Vec::new();
        while let Ok(event) = rx.try_recv() {
            received.push(event);
        }

        assert!(
            received.len() >= 2,
            "should receive at least 2 SSE events, got {}",
            received.len()
        );

        // Verify events are JobUpdate variants with status 'created' and resume detail
        let mut job_updates = 0u32;
        for event in &received {
            match event {
                crate::sse::ProgressEvent::JobUpdate { job_id, status, detail, .. } => {
                    if status == "created" && detail.as_ref().map_or(false, |d| d.contains("resumed")) {
                        assert!(
                            job_id == "job-a" || job_id == "job-b",
                            "unexpected job_id: {}",
                            job_id
                        );
                        job_updates += 1;
                    }
                }
                _ => {}
            }
        }

        assert_eq!(job_updates, 2, "should have 2 resume JobUpdate events, got {}", job_updates);
    }

    // -----------------------------------------------------------------------
    // Test 6: recover_crashed_jobs() returns the count of recovered jobs
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_returns_recovered_count() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-1", "alpha", "running");
        insert_test_job(&conn, "job-2", "beta", "running");
        insert_test_job(&conn, "job-3", "gamma", "running");

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 3, "should return count of 3 recovered jobs");
    }

    // -----------------------------------------------------------------------
    // Test 7: Returns 0 when no running jobs exist
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_returns_zero_when_no_running_jobs() {
        let conn = setup_test_db();
        insert_test_job(&conn, "job-1", "alpha", "created");
        insert_test_job(&conn, "job-2", "beta", "completed");
        insert_test_job(&conn, "job-3", "gamma", "failed");

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 0, "should return 0 when no running jobs exist");
    }

    // -----------------------------------------------------------------------
    // Test 8: On empty database does not panic
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_empty_database_does_not_panic() {
        let conn = setup_test_db();
        // No jobs inserted at all — completely empty

        let db = Arc::new(Mutex::new(conn));
        let (tx, _) = broadcast::channel(16);

        let recovered = recover_crashed_jobs(&db, &tx).await;
        assert_eq!(recovered, 0, "empty database should return 0 without panicking");
    }
}
