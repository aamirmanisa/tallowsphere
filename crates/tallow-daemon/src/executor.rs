use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::sync::watch;

use crate::config;
use crate::db;
use crate::queue::PriorityQueue;
use crate::sse::ProgressEvent;
use crate::throttle;

// ---------------------------------------------------------------------------
// Script-job Landlock write-jail (T-109 — audit-04 F-1)
// ---------------------------------------------------------------------------
//
// Every `tallow_script` job runs inside a Landlock **write-jail**: the child
// may create/write/remove files only beneath its per-job workspace (plus any
// operator-declared roots); reads and execution keep today's behavior. The
// jail is applied by the child itself in a pre-exec hook right before
// `execve`, so the script cannot escape it. Default **on**; an unenforceable
// kernel fails the job loudly instead of silently degrading (audit-04 F-1:
// "fail-closed or explicit opt-out") and the documented kill-switch below is
// the only way to run unconfined.
//
// This mirrors `tallow::sandbox_runtime::install_landlock` (same `landlock`
// crate, same ABI/status discipline); the daemon cannot import the compiler
// crate without pulling its whole dependency tree into the service, so the
// write half is implemented here in the same shape.

/// Kill-switch env var for the script-job write-jail. Default **on**; set to
/// `off` / `0` / `false` / `no` to explicitly run script jobs unconfined.
pub const SCRIPT_SANDBOX_ENV: &str = "TALLOW_DAEMON_SCRIPT_SANDBOX";

/// Colon-separated operator-declared extra write roots for script jobs. Roots
/// are declared by the daemon operator (environment), never by job config, so
/// a submitted job cannot widen its own jail.
pub const SCRIPT_WRITE_ROOTS_ENV: &str = "TALLOW_DAEMON_SCRIPT_WRITE_ROOTS";

/// Env var exported to the script child naming its writable workspace.
pub const JOB_WORKSPACE_ENV: &str = "TALLOW_DAEMON_JOB_WORKSPACE";

/// Pure parser for the kill-switch (unit-tested; no env access here).
fn script_sandbox_disabled(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        Some(v) => {
            v.eq_ignore_ascii_case("off")
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("no")
                || v == "0"
        }
        None => false,
    }
}

/// Write roots for one script job: its workspace plus operator-declared roots.
fn script_job_write_roots(workspace: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut roots = vec![workspace.to_path_buf()];
    if let Ok(raw) = std::env::var(SCRIPT_WRITE_ROOTS_ENV) {
        roots.extend(std::env::split_paths(&raw).filter(|p| !p.as_os_str().is_empty()));
    }
    roots
}

/// Parent-side preflight: can this kernel create the same ruleset the child
/// will enforce? A pre-exec hook can only pass an OS error code back, so the
/// preflight is what makes a refusal carry a first-class message. Creating a
/// ruleset has no effect until `restrict_self` (never called here).
fn landlock_write_jail_supported() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{ABI, AccessFs, Ruleset, RulesetAttr};

        Ruleset::default()
            .handle_access(AccessFs::from_write(ABI::V1))
            .and_then(|ruleset| ruleset.create())
            .map(|_| ()) // drops the unused ruleset fd (no restriction applied)
            .map_err(|e| {
                format!(
                    "landlock write-jail cannot be enforced on this kernel ({e}); refusing to \
                     run unconfined — set {SCRIPT_SANDBOX_ENV}=off to opt out explicitly"
                )
            })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(format!(
            "landlock is Linux-only; refusing to run unconfined — set \
             {SCRIPT_SANDBOX_ENV}=off to opt out explicitly"
        ))
    }
}

/// Install a Landlock write-jail into the CURRENT (child, pre-exec) process:
/// writes are allowed only beneath `write_roots`; read and execute access is
/// deliberately NOT handled, i.e. reads keep current behavior (the child must
/// still read the tallow binary, its shared libraries and the `.tl` source).
///
/// Must be called after `fork` and before `exec` — Landlock is per-thread and
/// irreversible. `PartiallyEnforced` is accepted (best available on the
/// kernel), `NotEnforced` is an error so nothing ever degrades silently.
fn install_landlock_write_jail(write_roots: &[std::path::PathBuf]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, path_beneath_rules,
        };

        // ABI v1 (kernel 5.13) is the compatibility baseline: WriteFile,
        // RemoveFile/Dir and all Make* rights — i.e. file creation, writes
        // and deletion are all jailed; everything else is left untouched.
        let abi = ABI::V1;
        let access_write = AccessFs::from_write(abi);

        let paths: Vec<std::path::PathBuf> = write_roots
            .iter()
            .filter(|p| p.exists())
            .cloned()
            .collect();

        let status = Ruleset::default()
            .handle_access(access_write)
            .map_err(|e| format!("landlock handle_access failed: {e}"))?
            .create()
            .map_err(|e| format!("landlock create failed: {e}"))?
            .add_rules(path_beneath_rules(&paths, access_write))
            .map_err(|e| format!("landlock add_rules failed: {e}"))?
            .restrict_self()
            .map_err(|e| format!("landlock restrict_self failed: {e}"))?;

        match status.ruleset {
            landlock::RulesetStatus::FullyEnforced | landlock::RulesetStatus::PartiallyEnforced => {
                Ok(())
            }
            landlock::RulesetStatus::NotEnforced => Err(format!(
                "landlock write-jail not enforced (kernel too old); refusing to run unconfined \
                 — set {SCRIPT_SANDBOX_ENV}=off to opt out explicitly"
            )),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = write_roots;
        Err(format!(
            "landlock is Linux-only; refusing to run unconfined — set {SCRIPT_SANDBOX_ENV}=off \
             to opt out explicitly"
        ))
    }
}

// ---------------------------------------------------------------------------
// Exponential backoff with jitter
// ---------------------------------------------------------------------------

/// Calculate retry delay in milliseconds: min(base_ms * 2^attempt, max_ms) + random(0..jitter_ms)
///
/// Attempt numbering: attempt 0 = first retry delay, attempt 1 = second, etc.
/// Formula: capped(base_ms * 2^attempt, max_ms) + random(0, jitter_ms)
pub fn backoff_delay(attempt: u32, cfg: &config::Config) -> u64 {
    use rand::Rng;
    let raw = cfg
        .retry_base_ms
        .saturating_mul(2u64.saturating_pow(attempt));
    let capped = raw.min(cfg.retry_max_ms);
    let jitter = if cfg.retry_jitter_ms > 0 {
        rand::rng().random_range(0..cfg.retry_jitter_ms)
    } else {
        0
    };
    capped.saturating_add(jitter)
}

// ---------------------------------------------------------------------------
// Job Executor
// ---------------------------------------------------------------------------

/// Executes jobs dequeued from the priority queue with retry logic,
/// bandwidth throttling, and graceful shutdown support.
pub struct JobExecutor {
    queue: Arc<PriorityQueue>,
    db: Arc<Mutex<rusqlite::Connection>>,
    progress_tx: broadcast::Sender<ProgressEvent>,
    shutdown_rx: watch::Receiver<bool>,
    config: config::Config,
    throttle: Option<Arc<throttle::ScheduledThrottle>>,
}

impl JobExecutor {
    /// Spawn the executor loop as a background tokio task (fire-and-forget).
    pub fn spawn_executor(
        queue: Arc<PriorityQueue>,
        db: Arc<Mutex<rusqlite::Connection>>,
        progress_tx: broadcast::Sender<ProgressEvent>,
        shutdown_rx: watch::Receiver<bool>,
        cfg: config::Config,
        throttle: Option<Arc<throttle::ScheduledThrottle>>,
    ) {
        let executor = Self {
            queue,
            db,
            progress_tx,
            shutdown_rx,
            config: cfg,
            throttle,
        };
        tokio::spawn(async move {
            executor.run_loop().await;
        });
    }

    /// The main executor loop: acquire permit, poll for shutdown, dequeue, spawn job task.
    async fn run_loop(self) {
        loop {
            // Acquire a concurrency slot
            let _permit = self.queue.acquire_permit().await;

            // Check for shutdown before dequeuing
            if self.shutdown_rx.has_changed().unwrap_or(false) {
                self.save_in_progress_jobs().await;
                tracing::info!("Executor shutting down after saving in-progress jobs");
                break;
            }

            // Dequeue next job
            let job = match self.queue.dequeue_next(&self.db).await {
                Some(j) => j,
                None => {
                    // No jobs ready — sleep briefly to avoid busy-looping
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };

            // Clone Arcs for the spawned task
            let db = self.db.clone();
            let progress_tx = self.progress_tx.clone();
            let cfg = self.config.clone();
            let throttle = self.throttle.clone();
            let mut shutdown_rx = self.shutdown_rx.clone();

            tokio::spawn(async move {
                Self::execute_job_task(&db, &progress_tx, &cfg, throttle, job, &mut shutdown_rx)
                    .await;
                // Permit auto-releases when this async block drops
                drop(shutdown_rx);
            });
        }
    }

    /// Execute a single job: mark running, execute, handle result.
    async fn execute_job_task(
        db: &Mutex<rusqlite::Connection>,
        progress_tx: &broadcast::Sender<ProgressEvent>,
        cfg: &config::Config,
        throttle: Option<Arc<throttle::ScheduledThrottle>>,
        job: db::Job,
        _shutdown_rx: &mut watch::Receiver<bool>,
    ) {
        // SSE: job started
        Self::emit_job_update(progress_tx, &job.id, "running", None);

        // Attempt to execute
        match Self::execute_job(cfg, throttle.as_deref(), &job).await {
            Ok(()) => {
                // Success
                let conn = db.lock().await;
                let _ = db::update_job_status(&conn, &job.id, "completed", None);
                // Clear transfer state
                let _ = db::save_transfer_state(&conn, &job.id, 0, "");
                Self::emit_job_update(progress_tx, &job.id, "completed", None);
            }
            Err(e) => {
                // Failure — check if we should retry
                let conn = db.lock().await;
                let retry_count = db::increment_retry_count(&conn, &job.id).unwrap_or(999);
                let max_retries = 3u32; // default; could be read from Job row in future

                if retry_count < max_retries {
                    // Transient: re-queue for retry
                    let delay = backoff_delay(retry_count, cfg);
                    let _ =
                        db::update_job_status(&conn, &job.id, "created", Some(&format!("retry {}/{} — waiting {}ms", retry_count, max_retries, delay)));
                    drop(conn);

                    Self::emit_job_update(
                        progress_tx,
                        &job.id,
                        "retrying",
                        Some(&format!("attempt {}/{}, delay {}ms", retry_count, max_retries, delay)),
                    );

                    tokio::time::sleep(Duration::from_millis(delay)).await;
                } else {
                    // Permanent failure
                    let _ = db::update_job_status(
                        &conn,
                        &job.id,
                        "failed",
                        Some(&format!("{}", e)),
                    );
                    Self::emit_job_update(
                        progress_tx,
                        &job.id,
                        "failed",
                        Some(&format!("{}", e)),
                    );
                }
            }
        }
    }

    /// Execute a job for real.
    ///
    /// The daemon knows exactly two job shapes (see [`crate::job_kind`]):
    ///   * **copy** — `config` is `{"source": "<path>", "dest": "<path>"}`;
    ///     a throttled real-I/O file copy.
    ///   * **tallow_script** — `config` is
    ///     `{"type": "tallow_script", "script": "<.tl source>", ...}`;
    ///     the source is materialized and executed by the real `tallow`
    ///     binary as a subprocess (same runner the CLI schedule path uses).
    ///
    /// Anything else returns an honest `Err` with the supported shapes so a
    /// job that slipped past submit-time validation (e.g. inserted directly
    /// into the DB) still fails loudly — never accept-then-fail, never a
    /// fabricated success.
    async fn execute_job(
        cfg: &config::Config,
        throttle: Option<&throttle::ScheduledThrottle>,
        job: &db::Job,
    ) -> Result<(), String> {
        // Parse config — validate it's well-formed JSON
        let config: serde_json::Value =
            serde_json::from_str(&job.config_json).map_err(|e| format!("invalid config: {e}"))?;

        match crate::job_kind::classify(&config) {
            Ok(crate::job_kind::JobKind::Copy { source, dest }) => {
                Self::copy_file(throttle, &source, &dest).await
            }
            Ok(crate::job_kind::JobKind::TallowScript { name, script }) => {
                Self::run_tallow_script(cfg, &job.id, &name, &script).await
            }
            Err(reason) => Err(format!(
                "daemon executor: unsupported job '{}': {reason}",
                job.name
            )),
        }
    }

    /// Resolve the `tallow` binary used to run `.tl` script jobs. Honest
    /// discovery order: config override (`TALLOW_DAEMON_TALLOW_BIN`), a
    /// `tallow` binary next to the daemon binary, then `tallow` on PATH.
    fn resolve_tallow_bin(cfg: &config::Config) -> Result<std::path::PathBuf, String> {
        if let Some(b) = &cfg.tallow_bin {
            if b.is_file() {
                return Ok(b.clone());
            }
            return Err(format!(
                "configured tallow binary not found at {}",
                b.display()
            ));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sibling = dir.join("tallow");
                if sibling.is_file() {
                    return Ok(sibling);
                }
            }
        }
        if let Ok(path) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path) {
                let candidate = dir.join("tallow");
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
        Err(
            "cannot execute tallow_script job: tallow binary not found — install tallow on \
             PATH, place it next to the tallow-daemon binary, or set \
             TALLOW_DAEMON_TALLOW_BIN"
                .to_string(),
        )
    }

    /// Execute a `tallow_script` job by materializing its source and running
    /// the real `tallow` binary (`tallow run <file>`) as a subprocess — the
    /// same runner the CLI schedule path uses. Script runs are bounded by
    /// `TALLOW_DAEMON_SCRIPT_TIMEOUT_SECS` (default 300s) so a hung script
    /// cannot stall the executor; a timed-out or non-zero run is an honest
    /// `Err` carrying the exit status and captured output tail.
    ///
    /// T-109 (audit-04 F-1): the run is confined by a Landlock write-jail by
    /// default — writes only beneath the per-job workspace (exported to the
    /// child as `TALLOW_DAEMON_JOB_WORKSPACE`) plus operator-declared roots
    /// (`TALLOW_DAEMON_SCRIPT_WRITE_ROOTS`); reads/exec keep current behavior.
    /// `TALLOW_DAEMON_SCRIPT_SANDBOX=off` is the explicit opt-out; an
    /// unenforceable kernel refuses the job instead of running unconfined.
    async fn run_tallow_script(
        cfg: &config::Config,
        job_id: &str,
        script_name: &str,
        script: &str,
    ) -> Result<(), String> {
        let bin = Self::resolve_tallow_bin(cfg)?;

        // Materialize the script under the daemon data dir (or the system
        // temp dir when no data dir is configured, e.g. in tests).
        let scripts_dir = if cfg.data_dir.as_os_str().is_empty() {
            std::env::temp_dir().join("tallow-daemon-scripts")
        } else {
            cfg.data_dir.join("scripts")
        };
        std::fs::create_dir_all(&scripts_dir)
            .map_err(|e| format!("cannot create scripts dir {}: {e}", scripts_dir.display()))?;
        let safe_id: String = job_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let script_path = scripts_dir.join(format!("{safe_id}.tl"));
        std::fs::write(&script_path, script).map_err(|e| {
            format!(
                "cannot materialize script for job '{}': {e}",
                script_name
            )
        })?;

        let timeout_secs: u64 = std::env::var("TALLOW_DAEMON_SCRIPT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(300);

        // T-109 (audit-04 F-1): confine the script job before its first
        // instruction. The child gets a per-job workspace it may write to;
        // writes anywhere else are denied by the kernel (reads and exec keep
        // today's behavior).
        let workspace_dir = scripts_dir.join(format!("{safe_id}.work"));
        std::fs::create_dir_all(&workspace_dir).map_err(|e| {
            format!(
                "cannot create job workspace {}: {e}",
                workspace_dir.display()
            )
        })?;
        let sandbox_enabled = !script_sandbox_disabled(std::env::var(SCRIPT_SANDBOX_ENV).ok().as_deref());

        let mut cmd = tokio::process::Command::new(&bin);
        cmd.arg("run")
            .arg(&script_path)
            .env(JOB_WORKSPACE_ENV, &workspace_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        if sandbox_enabled {
            landlock_write_jail_supported()
                .map_err(|e| format!("script job '{script_name}' refused: {e}"))?;
            let write_roots = script_job_write_roots(&workspace_dir);
            let logged_roots = write_roots.clone();
            // SAFETY: the hook runs in the child after fork, before exec; it
            // only issues Landlock syscalls against its own captured paths,
            // and kernel support was preflighted above. A failure aborts the
            // spawn (fail-closed) instead of running the script unconfined.
            unsafe {
                cmd.pre_exec(move || {
                    install_landlock_write_jail(&write_roots)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
                });
            }
            tracing::info!(
                "executor: script job '{script_name}' confined by landlock write-jail \
                 (roots: {logged_roots:?})"
            );
        } else {
            tracing::warn!(
                "executor: script job '{script_name}' running UNCONFINED \
                 ({SCRIPT_SANDBOX_ENV} opt-out)"
            );
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn tallow binary '{}': {e}", bin.display()))?;

        let start = std::time::Instant::now();
        let status = match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            child.wait(),
        )
        .await
        {
            Ok(res) => res.map_err(|e| format!("failed to wait for tallow run: {e}"))?,
            Err(_elapsed) => {
                let _ = child.kill().await;
                return Err(format!(
                    "tallow_script job '{script_name}' timed out after {timeout_secs}s \
                     (TALLOW_DAEMON_SCRIPT_TIMEOUT_SECS) — killed"
                ));
            }
        };

        // Collect captured output (best-effort; the child has exited so these
        // reads cannot block).
        use tokio::io::AsyncReadExt;
        let mut stdout_tail = String::new();
        let mut stderr_tail = String::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut stdout_tail).await;
        }
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_string(&mut stderr_tail).await;
        }
        tracing::info!(
            "executor: tallow run finished in {:.1}s for job '{script_name}' (exit {:?})",
            start.elapsed().as_secs_f64(),
            status.code()
        );

        if status.success() {
            if !stdout_tail.trim().is_empty() {
                tracing::debug!("tallow_script job '{script_name}' stdout: {stdout_tail}");
            }
            Ok(())
        } else {
            let tail = format!("{}\n{}", stdout_tail.trim(), stderr_tail.trim());
            let tail: String = tail.chars().take(4000).collect();
            Err(format!(
                "tallow_script job '{script_name}' failed: tallow run exited with {}:\n{tail}",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string())
            ))
        }
    }

    /// Throttled whole-file copy (the daemon's real "copy engine" for jobs).
    ///
    /// Streams `source` to `dest` in 64 KiB chunks, calling
    /// `throttle.consume()` before each write so the configured bandwidth
    /// limit is honored. Creates parent directories as needed. Returns a
    /// descriptive `Err` on any I/O failure — the copy either completes or
    /// fails loudly; it never fabricates success.
    async fn copy_file(
        throttle: Option<&throttle::ScheduledThrottle>,
        source: &str,
        dest: &str,
    ) -> Result<(), String> {
        use std::io::{Read, Write};

        let src_path = std::path::Path::new(source);
        let dest_path = std::path::Path::new(dest);

        let mut src = std::fs::File::open(src_path).map_err(|e| {
            format!(
                "daemon executor: cannot open source '{}': {e}",
                src_path.display()
            )
        })?;

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "daemon executor: cannot create destination directory '{}': {e}",
                    parent.display()
                )
            })?;
        }
        let mut dst = std::fs::File::create(dest_path).map_err(|e| {
            format!(
                "daemon executor: cannot create destination '{}': {e}",
                dest_path.display()
            )
        })?;

        const CHUNK: usize = 64 * 1024;
        let mut buf = vec![0u8; CHUNK];
        let mut total: u64 = 0;
        loop {
            let n = src.read(&mut buf).map_err(|e| {
                format!(
                    "daemon executor: read error on '{}': {e}",
                    src_path.display()
                )
            })?;
            if n == 0 {
                break;
            }
            if let Some(t) = throttle {
                t.consume(n as u64).await;
            }
            dst.write_all(&buf[..n]).map_err(|e| {
                format!(
                    "daemon executor: write error on '{}': {e}",
                    dest_path.display()
                )
            })?;
            total += n as u64;
        }

        tracing::info!(
            "executor: copied {total} bytes '{}' -> '{}'",
            src_path.display(),
            dest_path.display()
        );
        Ok(())
    }

    /// Emit a ProgressEvent::JobUpdate via the broadcast channel.
    fn emit_job_update(
        tx: &broadcast::Sender<ProgressEvent>,
        job_id: &str,
        status: &str,
        detail: Option<&str>,
    ) {
        let event = ProgressEvent::JobUpdate {
            job_id: job_id.to_string(),
            status: status.to_string(),
            detail: detail.map(|s| s.to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let _ = tx.send(event);
    }

    /// Save all currently 'running' jobs to transfer_resume and reset them to 'created'.
    async fn save_in_progress_jobs(&self) {
        let conn = self.db.lock().await;
        let running_jobs = db::list_jobs(&conn, Some("running")).unwrap_or_default();
        for job in &running_jobs {
            let _ = db::save_transfer_state(&conn, &job.id, 0, "");
            let _ = db::update_job_status(&conn, &job.id, "created", Some("daemon shutdown"));
        }
        tracing::info!(
            "Saved {} in-progress jobs before shutdown",
            running_jobs.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> config::Config {
        config::Config {
            bind_addr: String::new(),
            port: 0,
            token: String::new(),
            data_dir: std::path::PathBuf::new(),
            token_path: std::path::PathBuf::new(),
            port_file: std::path::PathBuf::new(),
            db_path: std::path::PathBuf::new(),
            tallow_bin: None,
            concurrency_limit: 4,
            retry_base_ms: 1000,
            retry_max_ms: 60000,
            retry_jitter_ms: 500,
            bandwidth_limit_bytes_per_sec: 0,
            bandwidth_schedule: Vec::new(),
            watch_dirs: Vec::new(),
            debounce_delay_ms: 2000,
            debounce_large_file_ms: 10000,
            large_file_threshold_bytes: 10485760,
        }
    }

    #[test]
    fn test_backoff_delay_attempt_0() {
        let cfg = test_config();
        let delay = backoff_delay(0, &cfg);
        // 1000 * 2^0 = 1000, capped at 60000, jitter 0..500
        // So delay is in [1000, 1500)
        assert!(
            delay >= 1000 && delay < 1500,
            "attempt 0 delay should be in [1000, 1500), got {}",
            delay
        );
    }

    #[test]
    fn test_backoff_delay_attempt_1() {
        let cfg = test_config();
        let delay = backoff_delay(1, &cfg);
        // 1000 * 2^1 = 2000, jitter 0..500 -> [2000, 2500)
        assert!(
            delay >= 2000 && delay < 2500,
            "attempt 1 delay should be in [2000, 2500), got {}",
            delay
        );
    }

    #[test]
    fn test_backoff_delay_attempt_2() {
        let cfg = test_config();
        let delay = backoff_delay(2, &cfg);
        // 1000 * 2^2 = 4000, jitter 0..500 -> [4000, 4500)
        assert!(
            delay >= 4000 && delay < 4500,
            "attempt 2 delay should be in [4000, 4500), got {}",
            delay
        );
    }

    #[test]
    fn test_backoff_delay_capped_at_max() {
        let mut cfg = test_config();
        cfg.retry_base_ms = 1000;
        cfg.retry_max_ms = 3000; // low cap for testing
        cfg.retry_jitter_ms = 0; // no jitter for deterministic test

        let delay = backoff_delay(10, &cfg);
        // 1000 * 2^10 = 1,024,000, capped at 3000, no jitter
        assert_eq!(delay, 3000, "should be capped at max_ms");
    }

    #[test]
    fn test_backoff_delay_with_jitter_range() {
        let cfg = test_config();
        // Run many times to ensure jitter varies (probabilistic)
        let mut values = Vec::new();
        for _ in 0..50 {
            values.push(backoff_delay(0, &cfg));
        }
        // Should see at least 2 different values with 50 samples (extremely likely)
        let unique: std::collections::HashSet<u64> = values.into_iter().collect();
        assert!(
            unique.len() > 1,
            "jitter should produce varied delays, got only {} unique values",
            unique.len()
        );
    }

    #[tokio::test]
    async fn test_execute_job_copies_file_for_real() {
        let cfg = test_config();
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("src.bin");
        let dst = tmp.path().join("nested").join("dst.bin");
        std::fs::write(&src, b"real executor payload").expect("write src");

        let job = db::Job {
            id: "test-1".to_string(),
            name: "test-copy".to_string(),
            status: "running".to_string(),
            config_json: serde_json::json!({
                "source": src.to_string_lossy(),
                "dest": dst.to_string_lossy(),
            })
            .to_string(),
            error_message: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        assert!(
            result.is_ok(),
            "valid copy job should execute successfully, got: {:?}",
            result
        );
        let copied = std::fs::read(&dst).expect("dest should exist after real copy");
        assert_eq!(copied, b"real executor payload");
    }

    #[tokio::test]
    async fn test_execute_job_invalid_config() {
        let cfg = test_config();
        let job = db::Job {
            id: "test-2".to_string(),
            name: "bad-copy".to_string(),
            status: "running".to_string(),
            config_json: "not valid json".to_string(),
            error_message: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        assert!(
            result.is_err(),
            "invalid config should return error, got: {:?}",
            result
        );
        assert!(
            result.unwrap_err().contains("invalid config"),
            "error should mention invalid config"
        );
    }

    #[tokio::test]
    async fn test_execute_job_unsupported_shape_is_honest_error() {
        let cfg = test_config();
        // No "source"/"dest" fields — the executor must refuse rather than
        // pretend the job ran.
        let job = db::Job {
            id: "test-3".to_string(),
            name: "mystery-job".to_string(),
            status: "running".to_string(),
            config_json: r#"{"operation": "reindex"}"#.to_string(),
            error_message: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        let err = result.expect_err("unsupported job shape must fail honestly");
        assert!(
            err.contains("unsupported job") && err.contains("mystery-job"),
            "error should name the job and the missing field, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_execute_job_missing_source_file_errors() {
        let cfg = test_config();
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("does-not-exist.bin");
        let dst = tmp.path().join("dst.bin");

        let job = db::Job {
            id: "test-4".to_string(),
            name: "copy-missing".to_string(),
            status: "running".to_string(),
            config_json: serde_json::json!({
                "source": missing.to_string_lossy(),
                "dest": dst.to_string_lossy(),
            })
            .to_string(),
            error_message: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        let err = result.expect_err("copying a nonexistent source must fail");
        assert!(
            err.contains("cannot open source"),
            "error should report the open failure, got: {err}"
        );
        assert!(
            !dst.exists(),
            "destination must not be created when source is unreadable"
        );
    }

    #[test]
    fn test_backoff_delay_formula_exponential() {
        let cfg = test_config();
        // Without jitter, delay = min(base * 2^attempt, max)
        let d0 = backoff_delay(0, &cfg); // ~1000-1499
        let d1 = backoff_delay(1, &cfg); // ~2000-2499
        let d2 = backoff_delay(2, &cfg); // ~4000-4499

        // d1 should be roughly 2x d0 (allowing for jitter overlap)
        assert!(d1 > d0, "d1 ({}) should be > d0 ({})", d1, d0);
        assert!(d2 > d1, "d2 ({}) should be > d1 ({})", d2, d1);
    }

    fn script_job(id: &str, name: &str, config_json: &str) -> db::Job {
        db::Job {
            id: id.to_string(),
            name: name.to_string(),
            status: "running".to_string(),
            config_json: config_json.to_string(),
            error_message: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    /// B8: a `tallow_script` job with no tallow binary available must fail
    /// with an honest discovery error — the executor never fabricates success.
    #[tokio::test]
    async fn test_execute_tallow_script_job_without_binary_is_honest_error() {
        let mut cfg = test_config();
        // Point at a binary that does not exist so discovery fails
        // deterministically regardless of what is on PATH.
        cfg.tallow_bin = Some(std::path::PathBuf::from(
            "/nonexistent/tallow-does-not-exist",
        ));
        let job = script_job(
            "script-1",
            "hello.tl",
            &serde_json::json!({
                "type": "tallow_script",
                "script": "fn main() { print(\"hi\") }",
                "name": "hello.tl",
            })
            .to_string(),
        );
        let err = JobExecutor::execute_job(&cfg, None, &job)
            .await
            .expect_err("script job without binary must fail honestly");
        assert!(
            err.contains("configured tallow binary not found"),
            "error should name the missing configured binary, got: {err}"
        );
    }

    /// B8: a supported `tallow_script` job executes through the real runner —
    /// here a fake `tallow` binary (a shell script) that records the args it
    /// was invoked with. The executor must materialize the .tl source and run
    /// `tallow run <file>` exactly like the CLI schedule path.
    #[tokio::test]
    async fn test_execute_tallow_script_job_runs_subprocess_runner() {
        let mut cfg = test_config();
        cfg.data_dir = tempfile::tempdir()
            .expect("tempdir")
            .path()
            .to_path_buf();
        let tmp = tempfile::tempdir().expect("tempdir");
        // T-109: the jailed child may only write inside its workspace, so the
        // fake runner records its argv there (the workspace path is derived
        // from the data dir exactly like `run_tallow_script` does).
        let marker = cfg
            .data_dir
            .join("scripts")
            .join("script-ok.work")
            .join("marker.txt");

        let fake_bin = tmp.path().join("tallow");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(
                &fake_bin,
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TALLOW_DAEMON_JOB_WORKSPACE/marker.txt\"\nexit 0\n",
            )
            .expect("write fake tallow");
            std::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake tallow");
        }
        cfg.tallow_bin = Some(fake_bin.clone());

        let job = script_job(
            "script-ok",
            "hello.tl",
            &serde_json::json!({
                "type": "tallow_script",
                "script": "fn main() { print(\"hi\") }",
                "name": "hello.tl",
            })
            .to_string(),
        );

        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        assert!(result.is_ok(), "script job should run, got: {:?}", result);

        let recorded = std::fs::read_to_string(&marker).expect("marker written by fake runner");
        let parts: Vec<&str> = recorded.split_whitespace().collect();
        assert_eq!(parts.first().copied(), Some("run"), "runner invoked with `run`");
        assert!(
            parts.get(1).is_some_and(|p| p.ends_with(".tl")),
            "runner invoked with a materialized .tl path, got: {recorded}"
        );
        assert!(
            std::path::Path::new(parts[1]).exists(),
            "materialized script file must exist on disk: {recorded}"
        );
    }

    /// B8: a failing script run (non-zero exit) surfaces the exit code and
    /// output tail in the error — never a fabricated success.
    #[tokio::test]
    async fn test_execute_tallow_script_job_nonzero_exit_is_honest_error() {
        let mut cfg = test_config();
        cfg.data_dir = tempfile::tempdir()
            .expect("tempdir")
            .path()
            .to_path_buf();
        let tmp = tempfile::tempdir().expect("tempdir");
        let fake_bin = tmp.path().join("tallow");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(
                &fake_bin,
                "#!/bin/sh\necho 'boom from script' >&2\nexit 3\n",
            )
            .expect("write fake tallow");
            std::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake tallow");
        }
        cfg.tallow_bin = Some(fake_bin);

        let job = script_job(
            "script-fail",
            "boom.tl",
            &serde_json::json!({
                "type": "tallow_script",
                "script": "fn main() { panic }",
                "name": "boom.tl",
            })
            .to_string(),
        );
        let err = JobExecutor::execute_job(&cfg, None, &job)
            .await
            .expect_err("failing script must error");
        assert!(
            err.contains("exited with 3") && err.contains("boom from script"),
            "error should carry exit code and output tail, got: {err}"
        );
    }

    /// T-109: the kill-switch parser is pure and total.
    #[test]
    fn test_script_sandbox_kill_switch_parsing() {
        assert!(!script_sandbox_disabled(None), "unset ⇒ default on");
        assert!(!script_sandbox_disabled(Some("")));
        assert!(!script_sandbox_disabled(Some("on")));
        assert!(!script_sandbox_disabled(Some("1")));
        assert!(script_sandbox_disabled(Some("off")));
        assert!(script_sandbox_disabled(Some("OFF")));
        assert!(script_sandbox_disabled(Some(" 0 ")));
        assert!(script_sandbox_disabled(Some("False")));
        assert!(script_sandbox_disabled(Some("no")));
    }

    /// T-109 (audit-04 F-1): the script-job spawn path applies a real Landlock
    /// write-jail by default — proven from inside the child: the workspace and
    /// an operator-declared root are writable, an undeclared sibling path is
    /// denied by the kernel (no file appears), and the documented opt-out
    /// (`TALLOW_DAEMON_SCRIPT_SANDBOX=off`) is shown to lift the jail.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_script_job_spawn_applies_landlock_write_jail() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("data");
        let declared = tmp.path().join("declared-root");
        let undeclared = tmp.path().join("undeclared");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        std::fs::create_dir_all(&declared).expect("declared root");
        std::fs::create_dir_all(&undeclared).expect("undeclared dir");

        let fake_bin = tmp.path().join("tallow");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(
                &fake_bin,
                format!(
                    "#!/bin/sh\n\
                     ws=\"$TALLOW_DAEMON_JOB_WORKSPACE\"\n\
                     [ -n \"$ws\" ] || exit 10\n\
                     echo ok > \"$ws/inside.txt\" || exit 11\n\
                     echo ok > \"{declared}/declared.txt\" || exit 12\n\
                     case \"${{TALLOW_DAEMON_SCRIPT_SANDBOX:-on}}\" in\n\
                     off|0|false|False|FALSE) expected=off ;;\n\
                     *) expected=on ;;\n\
                     esac\n\
                     if echo leak > \"{undeclared}/leak.txt\" 2>/dev/null; then\n\
                     [ \"$expected\" = \"on\" ] && exit 13\n\
                     else\n\
                     [ \"$expected\" = \"off\" ] && exit 14\n\
                     fi\n\
                     exit 0\n",
                    declared = declared.display(),
                    undeclared = undeclared.display(),
                ),
            )
            .expect("write fake tallow");
            std::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake tallow");
        }

        let mut cfg = test_config();
        cfg.data_dir = data_dir.clone();
        cfg.tallow_bin = Some(fake_bin);

        // --- default (kill-switch unset): confinement is live -------------
        // SAFETY (edition 2024: env mutation is unsafe): only this test sets
        // these two vars; other tests read them only through the executor and
        // their fixtures never write outside their workspace.
        unsafe {
            std::env::remove_var(SCRIPT_SANDBOX_ENV);
            std::env::set_var(SCRIPT_WRITE_ROOTS_ENV, declared.display().to_string());
        }

        let job = script_job(
            "jail-on",
            "jail-on.tl",
            &serde_json::json!({
                "type": "tallow_script",
                "script": "fn main() { print(\"hi\") }",
                "name": "jail-on.tl",
            })
            .to_string(),
        );
        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        assert!(
            result.is_ok(),
            "confined script job must succeed, got: {result:?}"
        );
        assert!(
            data_dir
                .join("scripts")
                .join("jail-on.work")
                .join("inside.txt")
                .exists(),
            "workspace write must succeed under the jail"
        );
        assert!(
            declared.join("declared.txt").exists(),
            "operator-declared root write must succeed under the jail"
        );
        assert!(
            !undeclared.join("leak.txt").exists(),
            "write outside workspace + declared roots must be denied by the kernel"
        );

        // --- documented opt-out: the jail is lifted ------------------------
        unsafe { std::env::set_var(SCRIPT_SANDBOX_ENV, "off") };
        let job = script_job(
            "jail-off",
            "jail-off.tl",
            &serde_json::json!({
                "type": "tallow_script",
                "script": "fn main() { print(\"hi\") }",
                "name": "jail-off.tl",
            })
            .to_string(),
        );
        let result = JobExecutor::execute_job(&cfg, None, &job).await;
        assert!(
            result.is_ok(),
            "opt-out run must succeed (fake runner expects the lifted jail), got: {result:?}"
        );
        assert!(
            undeclared.join("leak.txt").exists(),
            "with TALLOW_DAEMON_SCRIPT_SANDBOX=off the undeclared write must land"
        );

        unsafe {
            std::env::remove_var(SCRIPT_SANDBOX_ENV);
            std::env::remove_var(SCRIPT_WRITE_ROOTS_ENV);
        }
    }
}
