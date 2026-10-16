//! Browser automation scheduler — run .tl scripts on cron or interval.
//!
//! Features:
//! - Cron syntax: `"0 8 * * *"` (every day at 8am)
//! - Cron shorthands: @yearly, @monthly, @weekly, @daily, @hourly
//! - Intervals: `30m`, `1h`, `6h`, `1d`
//! - Named schedules with pause/resume/cancel
//! - Persistent storage (`.tallow-schedules.json`)
//! - History tracking (last run, next run, run count, duration)
//! - Retry on failure with exponential backoff
//! - Overlap prevention (skip if previous run still active)
//! - Run output logging to disk
//! - Timezone offset support
//! - Missed-run catch-up policy
//! - Atomic file writes (prevents corruption)
//! - Graceful shutdown with interruptible sleep

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::browser::crawl_queue::CrawlQueue;

// ── Schedule Types ──────────────────────────────────────────────────

/// How often a schedule fires.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Frequency {
    /// Cron expression (min hour dom month dow)
    Cron(String),
    /// Fixed interval in seconds
    Interval(u64),
    /// Once at a specific epoch timestamp
    Once(u64),
    /// Daily at HH:MM
    Daily(String),
}

/// What to do when a scheduled run was missed (daemon was down).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MissedPolicy {
    /// Skip missed runs, schedule next future occurrence
    Skip,
    /// Run once immediately to catch up, then resume normal schedule
    RunOnce,
    /// Run all missed occurrences (dangerous for short intervals)
    RunAll,
}

impl Default for MissedPolicy {
    fn default() -> Self {
        Self::RunOnce
    }
}

/// A single scheduled job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScheduledJob {
    pub name: String,
    pub script: String,
    pub frequency: Frequency,
    pub enabled: bool,
    pub headless: bool,
    pub plugins: String,
    pub device: Option<String>,
    pub tor: bool,
    pub proxy: Option<String>,
    pub created_at: u64,
    pub last_run: Option<u64>,
    pub next_run: Option<u64>,
    pub run_count: u64,
    pub last_status: Option<String>,
    pub last_duration_secs: Option<u64>,
    pub max_runs: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub args: Vec<String>,
    // Retry config
    pub retry_count: u32,
    pub retry_delay_secs: u64,
    pub retry_backoff: bool,
    // Overlap prevention
    pub allow_overlap: bool,
    #[serde(default)]
    pub running: bool,
    // Missed-run policy
    #[serde(default)]
    pub missed_policy: MissedPolicy,
    // Timezone offset in seconds from UTC (e.g. -18000 for EST, 3600 for CET)
    #[serde(default)]
    pub tz_offset_secs: i64,
    // Working directory for the script
    pub work_dir: Option<String>,
    // Environment variables
    #[serde(default)]
    pub env_vars: Vec<(String, String)>,
    /// Whether this schedule runs as a delta / incremental crawl. When true,
    /// the run only re-fetches URLs whose stored content-hash / ETag indicates
    /// a change (using `If-None-Match` / `If-Modified-Since`), skipping
    /// unchanged URLs. Default `false` = full crawl (backward compatible).
    #[serde(default)]
    pub delta: bool,
    /// Per-job cap on concurrent `jobs.run_now` subprocess instances of this
    /// job (stdlib `jobs` API, roadmap #3 stage 1). `None` = no per-job limit
    /// beyond the store-wide cap. The daemon's own overlap prevention uses
    /// `running`/`allow_overlap`; this field is read by the jobs module only.
    #[serde(default)]
    pub max_parallel: Option<u32>,
}

impl ScheduledJob {
    pub fn new(name: &str, script: &str, frequency: Frequency) -> Self {
        let now = epoch_secs();
        let mut job = Self {
            name: name.to_string(),
            script: script.to_string(),
            frequency,
            enabled: true,
            headless: true,
            plugins: "balanced".to_string(),
            device: None,
            tor: false,
            proxy: None,
            created_at: now,
            last_run: None,
            next_run: None,
            run_count: 0,
            last_status: None,
            last_duration_secs: None,
            max_runs: None,
            timeout_secs: None,
            args: Vec::new(),
            retry_count: 0,
            retry_delay_secs: 30,
            retry_backoff: true,
            allow_overlap: false,
            running: false,
            missed_policy: MissedPolicy::default(),
            tz_offset_secs: 0,
            work_dir: None,
            env_vars: Vec::new(),
            delta: false,
            max_parallel: None,
        };
        job.next_run = Some(job.calculate_next_run(now));
        job
    }

    /// Calculate the next run timestamp from a reference point.
    pub fn calculate_next_run(&self, from: u64) -> u64 {
        match &self.frequency {
            Frequency::Interval(secs) => from + secs,
            Frequency::Once(at) => *at,
            Frequency::Daily(time_str) => next_daily(from, time_str, self.tz_offset_secs),
            Frequency::Cron(expr) => next_cron(from, expr, self.tz_offset_secs),
        }
    }

    /// Check if this job should run now.
    pub fn is_due(&self, now: u64) -> bool {
        if !self.enabled {
            return false;
        }
        if self.running && !self.allow_overlap {
            return false; // overlap prevention
        }
        if let Some(max) = self.max_runs {
            if self.run_count >= max {
                return false;
            }
        }
        if let Some(next) = self.next_run {
            now >= next
        } else {
            false
        }
    }

    /// Whether this schedule runs as a delta / incremental crawl.
    pub fn is_delta(&self) -> bool {
        self.delta
    }

    /// Mark as just ran, compute next run.
    pub fn mark_ran(&mut self, status: &str, duration_secs: u64) {
        let now = epoch_secs();
        self.last_run = Some(now);
        self.run_count += 1;
        self.last_status = Some(status.to_string());
        self.last_duration_secs = Some(duration_secs);
        self.running = false;

        if matches!(self.frequency, Frequency::Once(_)) {
            self.enabled = false;
            self.next_run = None;
        } else {
            self.next_run = Some(self.calculate_next_run(now));
        }
    }

    /// Human-readable frequency description.
    pub fn frequency_display(&self) -> String {
        match &self.frequency {
            Frequency::Cron(expr) => format!("cron({})", expr),
            Frequency::Interval(secs) => format_interval(*secs),
            Frequency::Once(at) => format!("once at {}", format_epoch(*at)),
            Frequency::Daily(time) => {
                if self.tz_offset_secs != 0 {
                    let h = self.tz_offset_secs / 3600;
                    format!("daily at {} (UTC{:+})", time, h)
                } else {
                    format!("daily at {} UTC", time)
                }
            }
        }
    }

    /// Human-readable next run.
    pub fn next_run_display(&self) -> String {
        match self.next_run {
            Some(ts) => format_epoch(ts),
            None => "none".to_string(),
        }
    }

    /// Human-readable last run.
    pub fn last_run_display(&self) -> String {
        match self.last_run {
            Some(ts) => format_epoch(ts),
            None => "never".to_string(),
        }
    }

    /// Preview the next N run times.
    pub fn next_runs(&self, count: usize) -> Vec<u64> {
        let mut runs = Vec::with_capacity(count);
        let mut from = epoch_secs();
        for _ in 0..count {
            let next = self.calculate_next_run(from);
            runs.push(next);
            from = next;
        }
        runs
    }
}

// ── Delta / Incremental Crawl Planning ─────────────────────────────

/// Cached HTTP metadata for a single URL — the input to delta-crawl planning.
///
/// Mirrors `crawl_queue::UrlCacheEntry` (etag / last_modified / content_hash /
/// fetched_at). Constructed from a `CrawlQueue`'s public cache accessors (see
/// [`CachedUrl::from_queue`]) or supplied directly by callers that keep their
/// own HTTP cache. This is a plain library type so the scheduler can plan
/// delta crawls without depending on a concrete cache implementation.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CachedUrl {
    pub url: String,
    /// ETag from the last response (for `If-None-Match`).
    pub etag: Option<String>,
    /// Last-Modified from the last response (for `If-Modified-Since`).
    pub last_modified: Option<String>,
    /// `sha256(body)` of the last fetched body (for change detection).
    pub content_hash: Option<String>,
    /// Unix timestamp of the last successful fetch.
    pub fetched_at_epoch: Option<i64>,
}

impl CachedUrl {
    /// Build a `CachedUrl` from a `CrawlQueue`'s recorded cache metadata for
    /// `url`, using the queue's public accessors (`etag`, `last_modified`,
    /// `last_content_hash`).
    pub fn from_queue(queue: &CrawlQueue, url: &str) -> Self {
        Self {
            url: url.to_string(),
            etag: queue.etag(url).map(|s| s.to_string()),
            last_modified: queue.last_modified(url).map(|s| s.to_string()),
            content_hash: queue.last_content_hash(url).map(|s| s.to_string()),
            fetched_at_epoch: None,
        }
    }

    /// Conditional-GET headers (`If-None-Match` / `If-Modified-Since`) derived
    /// from this entry's cache metadata. Empty if none available.
    pub fn conditional_headers(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(etag) = self.etag.as_deref().filter(|s| !s.is_empty()) {
            out.push(("If-None-Match".to_string(), etag.to_string()));
        }
        if let Some(lm) = self.last_modified.as_deref().filter(|s| !s.is_empty()) {
            out.push(("If-Modified-Since".to_string(), lm.to_string()));
        }
        out
    }

    /// Whether this URL has enough cached metadata to attempt a conditional
    /// re-fetch (a prior content hash) rather than a forced full fetch.
    pub fn has_cache(&self) -> bool {
        self.content_hash.is_some()
    }
}

/// Re-crawl need for a single URL, derived purely from its cached metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaNeed {
    /// No prior content hash — must fetch the full body (first crawl / unknown).
    Full,
    /// Has prior cache metadata — send a conditional GET and confirm whether
    /// content actually changed via `304` or a matching body hash.
    Conditional,
    /// Has prior cache metadata *and* the origin advertises revalidation
    /// validators (ETag / Last-Modified). The delta scheduler trusts the
    /// cached copy and skips re-crawling this URL entirely.
    Skip,
}

impl DeltaNeed {
    /// Classify a URL's re-crawl need from its cached metadata.
    ///
    /// Consult the cache the way `plan_incremental_crawl` does:
    /// * [`CachedUrl::has_cache`] — does the crawl-queue content cache hold a
    ///   stored `content_hash` for this URL (i.e. have we crawled it before)?
    /// * [`CachedUrl::conditional_headers`] — do we have a revalidation
    ///   validator (`If-None-Match` / `If-Modified-Since`)?
    ///
    /// Rules:
    /// * `Full` — no stored content hash: first crawl / unknown content, must
    ///   fetch the whole body.
    /// * `Skip` — stored hash **and** a validator: the origin revalidates the
    ///   resource, so the delta crawler trusts its cached copy and skips the
    ///   URL (no re-fetch this pass).
    /// * `Conditional` — stored hash but no validator: we must re-fetch and
    ///   confirm via a matching body hash (`is_unchanged_after_fetch`).
    pub fn classify(entry: &CachedUrl) -> DeltaNeed {
        if !entry.has_cache() {
            return DeltaNeed::Full;
        }
        if !entry.conditional_headers().is_empty() {
            DeltaNeed::Skip
        } else {
            DeltaNeed::Conditional
        }
    }
}

/// The result of incremental-crawl planning over a URL set.
#[derive(Debug, Clone, Default)]
pub struct IncrementalPlan {
    /// URLs that must be re-fetched (either `Full` or `Conditional`). A
    /// conditional entry is placed here because a pure planner cannot know the
    /// server state without asking; after the conditional GET, use
    /// [`is_unchanged_after_fetch`] to move it to [`IncrementalPlan::unchanged`].
    pub re_crawl: Vec<CachedUrl>,
    /// URLs already known-unchanged and skipped (no re-fetch needed). Filled
    /// by callers that have verified content via `304`/hash match; empty from a
    /// pure metadata-only plan.
    pub unchanged: Vec<CachedUrl>,
}

impl IncrementalPlan {
    /// Number of URLs to re-crawl.
    pub fn re_crawl_count(&self) -> usize {
        self.re_crawl.len()
    }

    /// Number of URLs skipped as unchanged.
    pub fn unchanged_count(&self) -> usize {
        self.unchanged.len()
    }

    /// Fraction of the full set (re-crawl + unchanged) that is unchanged.
    /// Returns `0.0` when there is nothing to compare.
    pub fn skip_ratio(&self) -> f64 {
        let total = self.re_crawl.len() + self.unchanged.len();
        if total == 0 {
            0.0
        } else {
            self.unchanged.len() as f64 / total as f64
        }
    }
}

/// Compute an incremental crawl plan for a URL set given each URL's stored
/// content-hash / ETag metadata.
///
/// Returns the subset that must be re-fetched (`IncrementalPlan::re_crawl`),
/// classifying each as either `Full` (no cache → fetch everything) or
/// `Conditional` (has cache but no validator → re-fetch and confirm via
/// [`is_unchanged_after_fetch`]). URLs whose cached copy is trusted — a stored
/// content hash plus a revalidation validator (ETag / Last-Modified) — are
/// classified `DeltaNeed::Skip` and placed in `IncrementalPlan::unchanged`, so
/// they are **not** re-crawled.
///
/// The classification consults the crawl-queue content cache via
/// [`CachedUrl::has_cache`] and [`CachedUrl::conditional_headers`], exactly the
/// signals a real delta scheduler uses to decide whether a URL changed.
///
/// *Backward compatible:* a caller that ignores this function and simply
/// re-crawls everything behaves exactly as before; this only *adds* the
/// ability to skip unchanged URLs.
pub fn plan_incremental_crawl(urls_with_cache: &[CachedUrl]) -> IncrementalPlan {
    let mut plan = IncrementalPlan::default();
    for entry in urls_with_cache {
        match DeltaNeed::classify(entry) {
            // Trusted cache (hash + validator): skip, do not re-crawl.
            DeltaNeed::Skip => plan.unchanged.push(entry.clone()),
            // Full and Conditional entries both require a (possibly cheap) fetch.
            DeltaNeed::Full | DeltaNeed::Conditional => plan.re_crawl.push(entry.clone()),
        }
    }
    plan
}

/// SHA-256 hex digest of `body` — used to compare stored vs freshly-fetched
/// content. Matches `crawl_queue::record_response`'s hash so the two agree.
pub fn content_hash_of(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Decide, after issuing a conditional GET for `entry`, whether the response
/// proves the URL's content is unchanged.
///
/// - `304 Not Modified` ⇒ unchanged.
/// - Server ignored the conditional headers (200 with a body) ⇒ unchanged only
///   when `new_body_hash` equals the entry's stored `content_hash`.
pub fn is_unchanged_after_fetch(
    entry: &CachedUrl,
    status_is_304: bool,
    new_body_hash: Option<&str>,
) -> bool {
    if status_is_304 {
        return true;
    }
    match (entry.content_hash.as_deref(), new_body_hash) {
        (Some(stored), Some(fresh)) => stored == fresh,
        _ => false,
    }
}

/// Human-readable summary of an [`IncrementalPlan`].
pub fn describe_plan(plan: &IncrementalPlan) -> String {
    format!(
        "delta plan: {} to re-crawl, {} unchanged ({:.1}% skip)",
        plan.re_crawl_count(),
        plan.unchanged_count(),
        plan.skip_ratio() * 100.0
    )
}

// ── Schedule Store ──────────────────────────────────────────────────

/// Persistent schedule database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScheduleStore {
    pub jobs: Vec<ScheduledJob>,
    /// Persisted store-wide cap on concurrent subprocess runs (stdlib `jobs`
    /// module's `set_max_concurrent`, roadmap #3 stage 1). `None` falls back
    /// to the `TALLOW_MAX_CONCURRENT` env var, then the daemon default (40).
    /// Honored by `jobs.run_now`'s in-process run registry; the daemon
    /// applies its own construction-time cap (`SchedulerDaemon::new`).
    #[serde(default)]
    pub max_concurrent: Option<usize>,
}

impl ScheduleStore {
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            max_concurrent: None,
        }
    }

    /// Load from disk (or create empty if missing).
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(data) => {
                match serde_json::from_str(&data) {
                    Ok(store) => store,
                    Err(e) => {
                        eprintln!("Warning: corrupt schedule store, backing up: {}", e);
                        // Back up corrupt file
                        let backup = path.with_extension("json.bak");
                        let _ = fs::copy(path, &backup);
                        Self::new()
                    }
                }
            }
            Err(_) => Self::new(),
        }
    }

    /// Save to disk atomically (write to .tmp then rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize error: {}", e))?;
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &json)
            .map_err(|e| format!("write error: {}", e))?;
        fs::rename(&tmp_path, path)
            .map_err(|e| {
                // On Windows, rename can fail if target exists — fallback to overwrite
                let _ = fs::write(path, &json);
                format!("rename error (fallback used): {}", e)
            })
    }

    /// Default store path.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".tallow-schedules.json")
    }

    /// Log directory for run outputs.
    pub fn log_dir() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".tallow-schedule-logs")
    }

    /// Add a job (rejects duplicates by name).
    pub fn add(&mut self, job: ScheduledJob) -> Result<(), String> {
        if self.jobs.iter().any(|j| j.name == job.name) {
            return Err(format!("schedule '{}' already exists", job.name));
        }
        self.jobs.push(job);
        Ok(())
    }

    /// Remove by name.
    pub fn remove(&mut self, name: &str) -> Result<ScheduledJob, String> {
        let idx = self.jobs.iter().position(|j| j.name == name)
            .ok_or_else(|| format!("schedule '{}' not found", name))?;
        Ok(self.jobs.remove(idx))
    }

    /// Get by name (mutable).
    pub fn get_mut(&mut self, name: &str) -> Option<&mut ScheduledJob> {
        self.jobs.iter_mut().find(|j| j.name == name)
    }

    /// Get by name.
    pub fn get(&self, name: &str) -> Option<&ScheduledJob> {
        self.jobs.iter().find(|j| j.name == name)
    }

    /// Pause a job.
    pub fn pause(&mut self, name: &str) -> Result<(), String> {
        let job = self.get_mut(name)
            .ok_or_else(|| format!("schedule '{}' not found", name))?;
        job.enabled = false;
        Ok(())
    }

    /// Resume a job.
    pub fn resume(&mut self, name: &str) -> Result<(), String> {
        let job = self.get_mut(name)
            .ok_or_else(|| format!("schedule '{}' not found", name))?;
        job.enabled = true;
        let now = epoch_secs();
        job.next_run = Some(job.calculate_next_run(now));
        Ok(())
    }

    /// Get all jobs that are due to run.
    pub fn due_jobs(&self, now: u64) -> Vec<&ScheduledJob> {
        self.jobs.iter().filter(|j| j.is_due(now)).collect()
    }

    /// Number of active jobs.
    pub fn active_count(&self) -> usize {
        self.jobs.iter().filter(|j| j.enabled).count()
    }

    /// Handle missed-run catch-up for all jobs.
    pub fn catch_up_missed(&mut self, now: u64) {
        let mut names_to_run: Vec<String> = Vec::new();
        for job in &mut self.jobs {
            if !job.enabled { continue; }
            if let Some(next) = job.next_run {
                if now > next + 60 {
                    // Missed by more than 1 minute
                    match job.missed_policy {
                        MissedPolicy::Skip => {
                            // Fast-forward to next future occurrence
                            job.next_run = Some(job.calculate_next_run(now));
                            println!("  [catch-up] '{}' — skipped missed run, next: {}",
                                job.name, job.next_run_display());
                        }
                        MissedPolicy::RunOnce => {
                            names_to_run.push(job.name.clone());
                        }
                        MissedPolicy::RunAll => {
                            // Only mark one for now — daemon loop will pick up more
                            names_to_run.push(job.name.clone());
                        }
                    }
                }
            }
        }
        if !names_to_run.is_empty() {
            println!("  [catch-up] {} missed jobs will run now", names_to_run.len());
        }
    }

    /// Crash recovery sweep, run once at daemon startup.
    ///
    /// Any job persisted with `running = true` was mid-run when the previous
    /// daemon died (the flag is written before the worker thread finishes, and
    /// is only cleared by `mark_ran` in the completion path). With no startup
    /// sweep those jobs would stay `running` forever and `is_due` would skip
    /// them — the "stuck job after crash" bug. This resets the flag, records
    /// the interruption, and requeues the job so it becomes due again
    /// immediately. Returns the number of recovered jobs.
    pub fn recover_stale_running(&mut self, now: u64) -> usize {
        let mut recovered = 0;
        for job in &mut self.jobs {
            if job.running {
                job.running = false;
                job.last_status = Some("interrupted".to_string());
                // Requeue: due immediately so the job re-runs after restart.
                job.next_run = Some(now);
                recovered += 1;
                println!(
                    "  [recover] '{}' was running at shutdown — marked interrupted, requeued",
                    job.name
                );
            }
        }
        recovered
    }
}

// ── Scheduler Daemon ────────────────────────────────────────────────

/// Runs as a background loop, checking and executing due jobs.
pub struct SchedulerDaemon {
    store_path: PathBuf,
    poll_interval: Duration,
    running: Arc<AtomicBool>,
    max_concurrent: usize,
}

impl SchedulerDaemon {
    pub fn new(store_path: PathBuf, poll_interval: Duration) -> Self {
        // Parallelism lever for the 1000x upgrade: default 40 concurrent jobs
        // (was a hardcoded 4). Override with TALLOW_MAX_CONCURRENT (clamped
        // 1..256) or `with_max_concurrent`.
        let max_concurrent = std::env::var("TALLOW_MAX_CONCURRENT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(40)
            .clamp(1, 256);
        Self {
            store_path,
            poll_interval,
            running: Arc::new(AtomicBool::new(false)),
            max_concurrent,
        }
    }

    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Start the scheduler loop (blocking). Press Ctrl+C to stop.
    pub fn run(&self) {
        self.running.store(true, Ordering::SeqCst);

        let store_path = self.store_path.clone();
        let poll = self.poll_interval;
        let running = Arc::clone(&self.running);

        // Create log directory
        let log_dir = ScheduleStore::log_dir();
        let _ = fs::create_dir_all(&log_dir);

        println!("Tallow scheduler started");
        println!("  Store:    {}", store_path.display());
        println!("  Logs:     {}", log_dir.display());
        println!("  Polling:  every {}s", poll.as_secs());
        println!("  Max jobs: {}", self.max_concurrent);
        println!();

        // Install ctrl+c handler
        let running_clone = Arc::clone(&running);
        let _ = ctrlc::set_handler(move || {
            running_clone.store(false, Ordering::SeqCst);
            eprintln!("\nScheduler stopping (waiting for running jobs)...");
        });

        // Catch-up missed runs on start
        {
            let mut store = ScheduleStore::load(&store_path);
            let now = epoch_secs();
            store.catch_up_missed(now);
            let _ = store.save(&store_path);
        }

        // Crash recovery: reset stale running=true jobs (the previous daemon
        // died mid-run). Without this sweep, `is_due` would skip them forever.
        {
            let mut store = ScheduleStore::load(&store_path);
            let now = epoch_secs();
            let recovered = store.recover_stale_running(now);
            if recovered > 0 {
                println!("  [recover] reset {recovered} stale running job(s)");
                let _ = store.save(&store_path);
            }
        }

        let mut active_jobs: Vec<std::thread::JoinHandle<(String, String, u64)>> = Vec::new();

        loop {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            // Clean up finished jobs
            let mut finished = Vec::new();
            let mut still_running = Vec::new();
            for handle in active_jobs.drain(..) {
                if handle.is_finished() {
                    finished.push(handle);
                } else {
                    still_running.push(handle);
                }
            }
            active_jobs = still_running;

            // Process finished jobs
            if !finished.is_empty() {
                let mut store = ScheduleStore::load(&store_path);
                for handle in finished {
                    if let Ok((name, status, duration)) = handle.join() {
                        if let Some(job) = store.get_mut(&name) {
                            job.mark_ran(&status, duration);
                            if status == "ok" {
                                println!("  {} completed ({}s)", name, duration);
                            } else {
                                println!("  {} failed: {} ({}s)", name, status, duration);
                            }
                        }
                    }
                }
                let _ = store.save(&store_path);
            }

            // Check for due jobs
            let mut store = ScheduleStore::load(&store_path);
            let now = epoch_secs();
            let due_names: Vec<String> = store
                .due_jobs(now)
                .iter()
                .map(|j| j.name.clone())
                .collect();

            let available_slots = self.max_concurrent.saturating_sub(active_jobs.len());

            for name in due_names.iter().take(available_slots) {
                if let Some(job) = store.get_mut(name) {
                    job.running = true;

                    let job_clone = job.clone();
                    let log_dir_clone = log_dir.clone();

                    println!(
                        "[{}] Starting: {} ({})",
                        format_epoch(now),
                        name,
                        job.frequency_display()
                    );

                    // `running` is only persisted (store.save below) for jobs
                    // whose worker thread actually spawned. If the OS refuses
                    // the spawn, reset the flag so the job is not stuck
                    // `running=true` on disk with no live worker.
                    let spawned = std::thread::Builder::new()
                        .name(format!("tallow-job-{name}"))
                        .spawn(move || run_job_with_retry(&job_clone, &log_dir_clone));
                    match spawned {
                        Ok(handle) => active_jobs.push(handle),
                        Err(e) => {
                            job.running = false;
                            eprintln!("  [warn] failed to spawn job '{}': {e}", name);
                        }
                    }
                }
            }

            if !due_names.is_empty() {
                let _ = store.save(&store_path);
            }

            // Interruptible sleep — check running flag every second
            let sleep_secs = poll.as_secs().max(1);
            for _ in 0..sleep_secs {
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        // Graceful shutdown: wait for running jobs (max 60s)
        if !active_jobs.is_empty() {
            println!("Waiting for {} running job(s) to finish...", active_jobs.len());
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            for handle in active_jobs {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    println!("  Timeout waiting — some jobs may still be running");
                    break;
                }
                let _ = handle.join();
            }
        }

        println!("Scheduler stopped.");
    }

    /// Stop the scheduler loop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

// ── Job Execution with Retry ────────────────────────────────────────

/// Run a job with retry logic. Returns (name, status, duration_secs).
fn run_job_with_retry(job: &ScheduledJob, log_dir: &Path) -> (String, String, u64) {
    let max_attempts = (job.retry_count + 1) as usize; // 0 retries = 1 attempt
    let mut delay = job.retry_delay_secs;
    let start = std::time::Instant::now();

    for attempt in 0..max_attempts {
        if attempt > 0 {
            println!("  [retry] '{}' attempt {}/{} (waiting {}s)",
                job.name, attempt + 1, max_attempts, delay);
            std::thread::sleep(Duration::from_secs(delay));
            if job.retry_backoff {
                delay = (delay * 2).min(600); // cap at 10 min
            }
        }

        match execute_scheduled_script(job, log_dir) {
            Ok(()) => {
                return (job.name.clone(), "ok".to_string(), start.elapsed().as_secs());
            }
            Err(e) => {
                if attempt + 1 < max_attempts {
                    println!("  [retry] '{}' failed: {}", job.name, e);
                } else {
                    return (job.name.clone(), format!("error: {}", e), start.elapsed().as_secs());
                }
            }
        }
    }

    (job.name.clone(), "error: max retries exceeded".to_string(), start.elapsed().as_secs())
}

/// Execute a .tl script file as a scheduled job with full option support.
fn execute_scheduled_script(
    job: &ScheduledJob,
    log_dir: &Path,
) -> Result<(), String> {
    let script_path = Path::new(&job.script);
    if !script_path.exists() {
        return Err(format!("script not found: {}", job.script));
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot find tallow binary: {}", e))?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("run").arg(&job.script);

    // Pass extra args
    for arg in &job.args {
        cmd.arg(arg);
    }

    // Set environment variables
    for (key, val) in &job.env_vars {
        cmd.env(key, val);
    }

    // Pass browser-relevant options as env vars so the script can use them
    // (The interpreter reads these when creating Browser instances)
    if job.headless {
        cmd.env("TALLOW_HEADLESS", "1");
    }
    cmd.env("TALLOW_PLUGINS", &job.plugins);
    if let Some(ref device) = job.device {
        cmd.env("TALLOW_DEVICE", device);
    }
    if job.tor {
        cmd.env("TALLOW_TOR", "1");
    }
    if let Some(ref proxy) = job.proxy {
        cmd.env("TALLOW_PROXY", proxy);
    }

    // Per-job run-log directory (also hosts the delta crawl cache below).
    let job_log_dir = log_dir.join(&job.name);

    // Delta / incremental crawl: signal the runtime so the crawl path only
    // re-fetches URLs whose stored content-hash / ETag changed. The per-job
    // crawl-queue checkpoint (`TALLOW_DELTA_QUEUE`) and per-run delta stats
    // file (`TALLOW_DELTA_STATS`) are handed to the subprocess so
    // `CrawlPipeline`'s HTTP-cache middleware persists content hashes across
    // scheduled runs (hash compare on the next run skips unchanged URLs) and
    // the run log below records this run's delta stats.
    if job.delta {
        cmd.env("TALLOW_DELTA_CRAWL", "1");
        let _ = fs::create_dir_all(&job_log_dir);
        cmd.env("TALLOW_DELTA_QUEUE", job_log_dir.join("delta-cache.json"));
        cmd.env("TALLOW_DELTA_STATS", job_log_dir.join("delta-run-stats.json"));
    }

    // Set working directory
    if let Some(ref wd) = job.work_dir {
        cmd.current_dir(wd);
    }

    // Create log file for this run
    let _ = fs::create_dir_all(&job_log_dir);
    let timestamp = epoch_secs();
    let log_file = job_log_dir.join(format!("run_{}.log", timestamp));

    cmd.stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn failed: {}", e))?;

    // Enforce timeout
    let timeout_dur = Duration::from_secs(job.timeout_secs.unwrap_or(300));
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished — collect output
                let mut stdout_buf = String::new();
                let mut stderr_buf = String::new();
                if let Some(ref mut out) = child.stdout {
                    use std::io::Read;
                    let _ = out.read_to_string(&mut stdout_buf);
                }
                if let Some(ref mut err) = child.stderr {
                    use std::io::Read;
                    let _ = err.read_to_string(&mut stderr_buf);
                }

                // Write log file
                let status_str = if status.success() {
                    "ok".to_string()
                } else {
                    format!("exit {}", status.code().unwrap_or(-1))
                };
                let log_content = format!(
                    "=== Tallow Schedule Run ===\nJob:      {}\nScript:   {}\nTime:     {}\nDuration: {}s\nStatus:   {}\n\n--- STDOUT ---\n{}\n--- STDERR ---\n{}\n",
                    job.name,
                    job.script,
                    format_epoch(timestamp),
                    start.elapsed().as_secs(),
                    status_str,
                    stdout_buf,
                    stderr_buf,
                );

                // Delta runs: append the crawl path's per-run delta stats
                // (written by CrawlPipeline's HTTP-cache middleware to
                // TALLOW_DELTA_STATS) so the run log records how many URLs
                // were skipped as unchanged vs re-fetched.
                let log_content = if job.delta {
                    let stats_path = job_log_dir.join("delta-run-stats.json");
                    match fs::read_to_string(&stats_path) {
                        Ok(stats_json) => format!(
                            "{log_content}--- DELTA STATS ---\n{}\n",
                            stats_json.trim()
                        ),
                        Err(_) => format!("{log_content}--- DELTA STATS ---\n(unavailable)\n"),
                    }
                } else {
                    log_content
                };
                let _ = fs::write(&log_file, &log_content);

                // Print stdout lines
                if !stdout_buf.is_empty() {
                    for line in stdout_buf.lines() {
                        println!("  | {}", line);
                    }
                }

                if !status.success() {
                    return Err(format!("exit code {}: {}",
                        status.code().unwrap_or(-1),
                        stderr_buf.lines().next().unwrap_or("unknown error")));
                }
                return Ok(());
            }
            Ok(None) => {
                // Still running — check timeout
                if start.elapsed() > timeout_dur {
                    let _ = child.kill();
                    let _ = child.wait(); // reap
                    let _ = fs::write(&log_file, format!(
                        "=== Tallow Schedule Run ===\nJob: {}\nStatus: TIMEOUT after {}s\n",
                        job.name, timeout_dur.as_secs()
                    ));
                    return Err(format!("timeout after {}s", timeout_dur.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => {
                return Err(format!("wait error: {}", e));
            }
        }
    }
}

// ── Cron Parser ─────────────────────────────────────────────────────

/// Expand cron shorthand aliases.
fn expand_cron_shorthand(expr: &str) -> Result<String, String> {
    match expr.trim() {
        "@yearly" | "@annually" => Ok("0 0 1 1 *".to_string()),
        "@monthly" => Ok("0 0 1 * *".to_string()),
        "@weekly" => Ok("0 0 * * 0".to_string()),
        "@daily" | "@midnight" => Ok("0 0 * * *".to_string()),
        "@hourly" => Ok("0 * * * *".to_string()),
        other => {
            if other.starts_with('@') {
                Err(format!("unknown cron shorthand '{}' (use @yearly @monthly @weekly @daily @hourly)", other))
            } else {
                Ok(other.to_string())
            }
        }
    }
}

/// Parse a cron field value against a range.
/// Supports: `*`, `N`, `N-M`, `*/N`, `N,M,O`
fn parse_cron_field(field: &str, min: u32, max: u32) -> Vec<u32> {
    let mut values = Vec::new();

    for part in field.split(',') {
        let part = part.trim();
        if part == "*" {
            values.extend(min..=max);
        } else if let Some(step_str) = part.strip_prefix("*/") {
            if let Ok(step) = step_str.parse::<u32>() {
                if step > 0 {
                    let mut v = min;
                    while v <= max {
                        values.push(v);
                        v += step;
                    }
                }
            }
        } else if part.contains('-') {
            // Handle range with optional step: N-M/S
            let range_parts: Vec<&str> = part.split('/').collect();
            let range_str = range_parts[0];
            let step: u32 = range_parts.get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            let bounds: Vec<&str> = range_str.split('-').collect();
            if bounds.len() == 2 {
                if let (Ok(a), Ok(b)) = (bounds[0].parse::<u32>(), bounds[1].parse::<u32>()) {
                    let mut v = a;
                    while v <= b {
                        values.push(v);
                        v += step;
                    }
                }
            }
        } else if let Ok(v) = part.parse::<u32>() {
            values.push(v);
        }
    }

    values.sort();
    values.dedup();
    values
}

/// Parse full cron expression: `min hour dom month dow`
pub struct CronExpr {
    pub minutes: Vec<u32>,
    pub hours: Vec<u32>,
    pub days_of_month: Vec<u32>,
    pub months: Vec<u32>,
    pub days_of_week: Vec<u32>,
}

impl CronExpr {
    pub fn parse(expr: &str) -> Result<Self, String> {
        let expanded = expand_cron_shorthand(expr)?;
        let fields: Vec<&str> = expanded.trim().split_whitespace().collect();
        if fields.len() != 5 {
            return Err(format!(
                "cron expression must have 5 fields (min hour dom month dow), got {}",
                fields.len()
            ));
        }

        Ok(Self {
            minutes: parse_cron_field(fields[0], 0, 59),
            hours: parse_cron_field(fields[1], 0, 23),
            days_of_month: parse_cron_field(fields[2], 1, 31),
            months: parse_cron_field(fields[3], 1, 12),
            days_of_week: parse_cron_field(fields[4], 0, 6),
        })
    }

    /// Check if a given time matches this cron expression.
    pub fn matches(&self, min: u32, hour: u32, dom: u32, month: u32, dow: u32) -> bool {
        self.minutes.contains(&min)
            && self.hours.contains(&hour)
            && self.days_of_month.contains(&dom)
            && self.months.contains(&month)
            && self.days_of_week.contains(&dow)
    }
}

/// Find next cron match after `from` (epoch seconds), with timezone offset.
fn next_cron(from: u64, expr: &str, tz_offset: i64) -> u64 {
    let expanded = expand_cron_shorthand(expr).unwrap_or_else(|_| expr.to_string());
    let cron = match CronExpr::parse(&expanded) {
        Ok(c) => c,
        Err(_) => return from + 3600,
    };

    let max_check: u64 = 366 * 24 * 60;
    let start = from - (from % 60) + 60;

    for i in 0..max_check {
        let ts = start + (i * 60);
        let local_ts = (ts as i64 + tz_offset) as u64;
        let (min, hour, dom, month, dow) = epoch_to_parts(local_ts);
        if cron.matches(min, hour, dom, month, dow) {
            return ts; // return UTC timestamp
        }
    }

    from + 86400
}

/// Find next daily occurrence of HH:MM after `from`, with timezone offset.
fn next_daily(from: u64, time_str: &str, tz_offset: i64) -> u64 {
    let parts: Vec<&str> = time_str.split(':').collect();
    let (target_h, target_m) = if parts.len() == 2 {
        (
            parts[0].parse::<u64>().unwrap_or(8),
            parts[1].parse::<u64>().unwrap_or(0),
        )
    } else {
        (8, 0)
    };

    // Validate
    let target_h = target_h.min(23);
    let target_m = target_m.min(59);

    // Convert "local time" target to UTC
    let local_from = (from as i64 + tz_offset) as u64;
    let day_start = local_from - (local_from % 86400);
    let target_local = day_start + target_h * 3600 + target_m * 60;
    let target_utc = (target_local as i64 - tz_offset) as u64;

    if target_utc > from {
        target_utc
    } else {
        target_utc + 86400
    }
}

/// Validate a daily time string.
pub fn validate_daily_time(s: &str) -> Result<(), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("expected HH:MM format, got '{}'", s));
    }
    let h: u32 = parts[0].parse().map_err(|_| format!("invalid hour: '{}'", parts[0]))?;
    let m: u32 = parts[1].parse().map_err(|_| format!("invalid minute: '{}'", parts[1]))?;
    if h > 23 {
        return Err(format!("hour must be 0-23, got {}", h));
    }
    if m > 59 {
        return Err(format!("minute must be 0-59, got {}", m));
    }
    Ok(())
}

// ── Interval Parser ─────────────────────────────────────────────────

/// Parse interval string: `30s`, `5m`, `1h`, `2d`, `1w`
pub fn parse_interval(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return Err("empty interval".to_string());
    }

    let (num_str, unit) = if s.ends_with("ms") {
        (&s[..s.len() - 2], "ms")
    } else {
        let split = s.len() - 1;
        if split == 0 {
            return Err(format!("invalid interval: '{}'", s));
        }
        (&s[..split], &s[split..])
    };

    let num: f64 = num_str.parse().map_err(|_| format!("invalid number: '{}'", num_str))?;

    let secs = match unit {
        "ms" => num / 1000.0,
        "s" => num,
        "m" => num * 60.0,
        "h" => num * 3600.0,
        "d" => num * 86400.0,
        "w" => num * 604800.0,
        _ => return Err(format!("unknown unit '{}' (use s/m/h/d/w)", unit)),
    };

    if secs < 10.0 {
        return Err("minimum interval is 10 seconds".to_string());
    }

    Ok(secs as u64)
}

// ── Time Helpers ────────────────────────────────────────────────────

pub fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format epoch as human-readable UTC time.
pub fn format_epoch(ts: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = ts / secs_per_day;
    let time_of_day = ts % secs_per_day;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let secs = time_of_day % 60;

    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, mins, secs
    )
}

/// Convert days since epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert epoch seconds to (minute, hour, day_of_month, month, day_of_week).
fn epoch_to_parts(ts: u64) -> (u32, u32, u32, u32, u32) {
    let secs_per_day: u64 = 86400;
    let days = ts / secs_per_day;
    let time_of_day = ts % secs_per_day;

    let hour = (time_of_day / 3600) as u32;
    let minute = ((time_of_day % 3600) / 60) as u32;

    let (_, month, day) = days_to_date(days);
    let dow = ((days + 4) % 7) as u32; // 0=Sun

    (minute, hour, day as u32, month as u32, dow)
}

/// Format seconds as human-readable interval.
fn format_interval(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 { format!("{}h{}m", h, m) } else { format!("{}h", h) }
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        if h > 0 { format!("{}d{}h", d, h) } else { format!("{}d", d) }
    }
}

// ── Pretty Print ────────────────────────────────────────────────────

/// Print schedule table to stdout.
pub fn print_schedule_table(store: &ScheduleStore) {
    if store.jobs.is_empty() {
        println!("No scheduled jobs.");
        println!("  Add one: tallow browser schedule add --name my-job --script scraper.tl --every 1h");
        return;
    }

    println!(
        "{:<20} {:<8} {:<22} {:<24} {:<24} {:<6} {:<10}",
        "NAME", "STATUS", "FREQUENCY", "NEXT RUN", "LAST RUN", "RUNS", "LAST"
    );
    println!("{}", "-".repeat(114));

    for job in &store.jobs {
        let status = if job.running {
            "running"
        } else if job.enabled {
            "active"
        } else {
            "paused"
        };
        let last_status = job.last_status.as_deref().unwrap_or("-");
        let last_short = truncate_safe(last_status, 9);

        println!(
            "{:<20} {:<8} {:<22} {:<24} {:<24} {:<6} {:<10}",
            truncate_safe(&job.name, 19),
            status,
            truncate_safe(&job.frequency_display(), 21),
            truncate_safe(&job.next_run_display(), 23),
            truncate_safe(&job.last_run_display(), 23),
            job.run_count,
            last_short,
        );
    }

    println!();
    println!(
        "{} jobs ({} active, {} running)",
        store.jobs.len(),
        store.active_count(),
        store.jobs.iter().filter(|j| j.running).count(),
    );
}

/// Safely truncate a string to max chars (not bytes), avoiding UTF-8 boundary panics.
fn truncate_safe(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}~", truncated)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interval() {
        assert_eq!(parse_interval("30s").unwrap(), 30);
        assert_eq!(parse_interval("5m").unwrap(), 300);
        assert_eq!(parse_interval("1h").unwrap(), 3600);
        assert_eq!(parse_interval("2d").unwrap(), 172800);
        assert_eq!(parse_interval("1w").unwrap(), 604800);
        assert!(parse_interval("5s").is_err()); // below 10s minimum
        assert!(parse_interval("").is_err());
        assert!(parse_interval("abc").is_err());
    }

    #[test]
    fn test_cron_parse() {
        let c = CronExpr::parse("0 8 * * *").unwrap();
        assert_eq!(c.minutes, vec![0]);
        assert_eq!(c.hours, vec![8]);
        assert_eq!(c.days_of_month.len(), 31);
        assert_eq!(c.months.len(), 12);
        assert_eq!(c.days_of_week.len(), 7);
    }

    #[test]
    fn test_cron_step() {
        let c = CronExpr::parse("*/15 * * * *").unwrap();
        assert_eq!(c.minutes, vec![0, 15, 30, 45]);
    }

    #[test]
    fn test_cron_range() {
        let c = CronExpr::parse("0 9-17 * * 1-5").unwrap();
        assert_eq!(c.hours, vec![9, 10, 11, 12, 13, 14, 15, 16, 17]);
        assert_eq!(c.days_of_week, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_cron_range_with_step() {
        let c = CronExpr::parse("0 0-23/2 * * *").unwrap();
        assert_eq!(c.hours, vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]);
    }

    #[test]
    fn test_cron_list() {
        let c = CronExpr::parse("0,30 8,12,18 * * *").unwrap();
        assert_eq!(c.minutes, vec![0, 30]);
        assert_eq!(c.hours, vec![8, 12, 18]);
    }

    #[test]
    fn test_cron_matches() {
        let c = CronExpr::parse("0 8 * * *").unwrap();
        assert!(c.matches(0, 8, 15, 3, 1));
        assert!(!c.matches(0, 9, 15, 3, 1));
        assert!(!c.matches(5, 8, 15, 3, 1));
    }

    #[test]
    fn test_cron_bad_fields() {
        assert!(CronExpr::parse("0 8 * *").is_err());
        assert!(CronExpr::parse("").is_err());
    }

    #[test]
    fn test_cron_shorthands() {
        // @daily = 0 0 * * *
        let c = CronExpr::parse("@daily").unwrap();
        assert_eq!(c.minutes, vec![0]);
        assert_eq!(c.hours, vec![0]);

        // @hourly = 0 * * * *
        let c2 = CronExpr::parse("@hourly").unwrap();
        assert_eq!(c2.minutes, vec![0]);
        assert_eq!(c2.hours.len(), 24);

        // @weekly = 0 0 * * 0
        let c3 = CronExpr::parse("@weekly").unwrap();
        assert_eq!(c3.days_of_week, vec![0]); // Sunday

        // @monthly = 0 0 1 * *
        let c4 = CronExpr::parse("@monthly").unwrap();
        assert_eq!(c4.days_of_month, vec![1]);

        // @yearly = 0 0 1 1 *
        let c5 = CronExpr::parse("@yearly").unwrap();
        assert_eq!(c5.months, vec![1]);
        assert_eq!(c5.days_of_month, vec![1]);

        // @annually same as @yearly
        let c6 = CronExpr::parse("@annually").unwrap();
        assert_eq!(c6.months, vec![1]);

        // Unknown shorthand
        assert!(CronExpr::parse("@biweekly").is_err());
    }

    #[test]
    fn test_scheduled_job_is_due() {
        let job = ScheduledJob::new("test", "test.tl", Frequency::Interval(60));
        let now = epoch_secs();
        assert!(!job.is_due(now));
        assert!(job.is_due(now + 61));
    }

    #[test]
    fn test_overlap_prevention() {
        let mut job = ScheduledJob::new("test", "test.tl", Frequency::Interval(60));
        job.running = true;
        job.allow_overlap = false;
        // Even if past next_run, should not be due because running
        assert!(!job.is_due(epoch_secs() + 100));

        // With allow_overlap, should be due
        job.allow_overlap = true;
        assert!(job.is_due(epoch_secs() + 100));
    }

    #[test]
    fn test_scheduled_job_mark_ran() {
        let mut job = ScheduledJob::new("test", "test.tl", Frequency::Interval(300));
        job.running = true;
        job.mark_ran("ok", 5);
        assert_eq!(job.run_count, 1);
        assert_eq!(job.last_status.as_deref(), Some("ok"));
        assert_eq!(job.last_duration_secs, Some(5));
        assert!(!job.running);
        assert!(job.next_run.is_some());
    }

    #[test]
    fn test_scheduled_job_once() {
        let future = epoch_secs() + 100;
        let mut job = ScheduledJob::new("once-job", "task.tl", Frequency::Once(future));
        assert!(job.is_due(future));
        job.mark_ran("ok", 2);
        assert!(!job.enabled);
        assert!(!job.is_due(future + 100));
    }

    #[test]
    fn test_scheduled_job_max_runs() {
        let mut job = ScheduledJob::new("limited", "test.tl", Frequency::Interval(10));
        job.max_runs = Some(3);
        job.run_count = 3;
        assert!(!job.is_due(epoch_secs() + 100));
    }

    #[test]
    fn test_store_add_remove() {
        let mut store = ScheduleStore::new();
        let job = ScheduledJob::new("j1", "a.tl", Frequency::Interval(60));
        store.add(job.clone()).unwrap();
        assert_eq!(store.jobs.len(), 1);
        assert!(store.add(job).is_err()); // duplicate
        let removed = store.remove("j1").unwrap();
        assert_eq!(removed.name, "j1");
        assert_eq!(store.jobs.len(), 0);
    }

    #[test]
    fn test_store_pause_resume() {
        let mut store = ScheduleStore::new();
        store.add(ScheduledJob::new("p1", "b.tl", Frequency::Interval(300))).unwrap();
        store.pause("p1").unwrap();
        assert!(!store.get("p1").unwrap().enabled);
        store.resume("p1").unwrap();
        assert!(store.get("p1").unwrap().enabled);
    }

    #[test]
    fn test_recover_stale_running_resets_and_requeues() {
        // Simulate a crash: a job persisted with running=true, next_run in the
        // past → is_due() would skip it (stuck job). The startup sweep must
        // reset it, mark it interrupted, and make it due again.
        let mut store = ScheduleStore::new();
        let mut job = ScheduledJob::new("crashy", "b.tl", Frequency::Interval(300));
        job.running = true; // daemon died mid-run
        job.next_run = Some(1_000_000); // long past due
        store.add(job).unwrap();

        let now = 2_000_000u64;
        assert!(!store.get("crashy").unwrap().is_due(now), "stuck: running job never due");

        let recovered = store.recover_stale_running(now);
        assert_eq!(recovered, 1);
        let job = store.get("crashy").unwrap();
        assert!(!job.running, "flag must be reset");
        assert_eq!(job.last_status.as_deref(), Some("interrupted"));
        assert_eq!(job.next_run, Some(now));
        assert!(store.get("crashy").unwrap().is_due(now), "requeued job is due again");

        // Idempotent: a second sweep recovers nothing.
        assert_eq!(store.recover_stale_running(now), 0);
    }

    #[test]
    fn test_daily_next() {
        let now = 1711022400;
        let next = next_daily(now, "08:00", 0);
        assert!(next >= now);
        assert!(next - now <= 86400);
    }

    #[test]
    fn test_daily_validation() {
        assert!(validate_daily_time("08:00").is_ok());
        assert!(validate_daily_time("23:59").is_ok());
        assert!(validate_daily_time("00:00").is_ok());
        assert!(validate_daily_time("25:00").is_err());
        assert!(validate_daily_time("12:60").is_err());
        assert!(validate_daily_time("abc").is_err());
        assert!(validate_daily_time("12").is_err());
        assert!(validate_daily_time("").is_err());
    }

    #[test]
    fn test_next_cron() {
        let now = epoch_secs();
        let next = next_cron(now, "0 8 * * *", 0);
        assert!(next > now);
        assert!(next - now <= 90000);
    }

    #[test]
    fn test_format_interval_display() {
        assert_eq!(format_interval(30), "30s");
        assert_eq!(format_interval(300), "5m");
        assert_eq!(format_interval(3600), "1h");
        assert_eq!(format_interval(7200), "2h");
        assert_eq!(format_interval(86400), "1d");
        assert_eq!(format_interval(90000), "1d1h");
    }

    #[test]
    fn test_frequency_display() {
        let j1 = ScheduledJob::new("a", "a.tl", Frequency::Interval(3600));
        assert_eq!(j1.frequency_display(), "1h");

        let j2 = ScheduledJob::new("b", "b.tl", Frequency::Daily("08:30".into()));
        assert_eq!(j2.frequency_display(), "daily at 08:30 UTC");

        let j3 = ScheduledJob::new("c", "c.tl", Frequency::Cron("0 8 * * *".into()));
        assert_eq!(j3.frequency_display(), "cron(0 8 * * *)");
    }

    #[test]
    fn test_days_to_date() {
        assert_eq!(days_to_date(0), (1970, 1, 1));
        let (y, m, d) = days_to_date(19723);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_store_serialization() {
        let mut store = ScheduleStore::new();
        store.add(ScheduledJob::new("s1", "x.tl", Frequency::Interval(600))).unwrap();
        store.add(ScheduledJob::new("s2", "y.tl", Frequency::Daily("14:00".into()))).unwrap();
        let json = serde_json::to_string(&store).unwrap();
        let loaded: ScheduleStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.jobs.len(), 2);
        assert_eq!(loaded.jobs[0].name, "s1");
        assert_eq!(loaded.jobs[1].name, "s2");
    }

    #[test]
    fn test_truncate_safe() {
        assert_eq!(truncate_safe("hello", 10), "hello");
        assert_eq!(truncate_safe("hello world!", 5), "hell~");
        // UTF-8 safety — should NOT panic
        assert_eq!(truncate_safe("cafe\u{0301}", 3), "ca~");
    }

    #[test]
    fn test_next_runs_preview() {
        let job = ScheduledJob::new("preview", "a.tl", Frequency::Interval(3600));
        let runs = job.next_runs(5);
        assert_eq!(runs.len(), 5);
        for i in 1..5 {
            assert!(runs[i] > runs[i - 1]);
            // Each run should be ~3600s apart
            let diff = runs[i] - runs[i - 1];
            assert!(diff >= 3590 && diff <= 3610);
        }
    }

    #[test]
    fn test_timezone_offset() {
        let mut job = ScheduledJob::new("tz", "a.tl", Frequency::Daily("08:00".into()));
        // EST = UTC-5 = -18000 seconds
        job.tz_offset_secs = -18000;
        assert_eq!(job.frequency_display(), "daily at 08:00 (UTC-5)");
    }

    #[test]
    fn test_missed_policy_default() {
        let job = ScheduledJob::new("m", "a.tl", Frequency::Interval(60));
        assert!(matches!(job.missed_policy, MissedPolicy::RunOnce));
    }

    #[test]
    fn test_catch_up_missed() {
        let mut store = ScheduleStore::new();
        let mut job = ScheduledJob::new("old", "a.tl", Frequency::Interval(60));
        job.next_run = Some(epoch_secs() - 3600); // missed 1 hour ago
        job.missed_policy = MissedPolicy::Skip;
        store.jobs.push(job);

        let now = epoch_secs();
        store.catch_up_missed(now);

        // next_run should be fast-forwarded to future
        let updated = store.get("old").unwrap();
        assert!(updated.next_run.unwrap() > now);
    }

    #[test]
    fn test_env_vars_and_work_dir() {
        let mut job = ScheduledJob::new("env", "a.tl", Frequency::Interval(60));
        job.env_vars.push(("API_KEY".to_string(), "secret".to_string()));
        job.work_dir = Some("/tmp".to_string());
        assert_eq!(job.env_vars.len(), 1);
        assert_eq!(job.work_dir.as_deref(), Some("/tmp"));
    }

    #[test]
    fn test_expand_cron_shorthand() {
        assert_eq!(expand_cron_shorthand("@daily").unwrap(), "0 0 * * *");
        assert_eq!(expand_cron_shorthand("@hourly").unwrap(), "0 * * * *");
        assert_eq!(expand_cron_shorthand("@weekly").unwrap(), "0 0 * * 0");
        assert_eq!(expand_cron_shorthand("@monthly").unwrap(), "0 0 1 * *");
        assert_eq!(expand_cron_shorthand("@yearly").unwrap(), "0 0 1 1 *");
        assert_eq!(expand_cron_shorthand("@annually").unwrap(), "0 0 1 1 *");
        assert_eq!(expand_cron_shorthand("@midnight").unwrap(), "0 0 * * *");
        assert!(expand_cron_shorthand("@biweekly").is_err());
        // Non-shorthand passes through
        assert_eq!(expand_cron_shorthand("0 8 * * *").unwrap(), "0 8 * * *");
    }

    #[test]
    fn test_validate_daily_time_edge_cases() {
        assert!(validate_daily_time("0:0").is_ok());
        assert!(validate_daily_time("24:00").is_err());
        assert!(validate_daily_time("12:60").is_err());
        assert!(validate_daily_time("hello").is_err());
    }

    #[test]
    fn test_delta_flag_defaults_to_false() {
        let job = ScheduledJob::new("d", "a.tl", Frequency::Interval(60));
        assert!(!job.is_delta());
        assert!(!job.delta);
        // Backward compatible: JSON without a `delta` field still loads.
        let json = serde_json::to_string(&job).unwrap();
        let loaded: ScheduledJob = serde_json::from_str(&json).unwrap();
        assert!(!loaded.delta);
    }

    #[test]
    fn test_delta_flag_roundtrips() {
        let mut job = ScheduledJob::new("d2", "a.tl", Frequency::Interval(60));
        job.delta = true;
        assert!(job.is_delta());
        let json = serde_json::to_string(&job).unwrap();
        let loaded: ScheduledJob = serde_json::from_str(&json).unwrap();
        assert!(loaded.is_delta());
    }

    #[test]
    fn test_content_hash_of_is_sha256() {
        // Empty string SHA-256 is well-known.
        assert_eq!(
            content_hash_of(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(content_hash_of("a"), content_hash_of("b"));
        assert_eq!(content_hash_of("a"), content_hash_of("a"));
    }

    #[test]
    fn test_plan_incremental_crawl_classifies_by_cache() {
        let urls = vec![
            // No cache → Full.
            CachedUrl { url: "https://a".into(), ..Default::default() },
            // Cache + ETag validator → Skip.
            CachedUrl {
                url: "https://b".into(),
                content_hash: Some("abc".into()),
                etag: Some("\"xyz\"".into()),
                ..Default::default()
            },
            // Cache + Last-Modified validator → Skip.
            CachedUrl {
                url: "https://c".into(),
                content_hash: Some("def".into()),
                last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
                ..Default::default()
            },
            // Cache, no validator → Conditional.
            CachedUrl {
                url: "https://d".into(),
                content_hash: Some("ghi".into()),
                ..Default::default()
            },
        ];
        assert_eq!(DeltaNeed::classify(&urls[0]), DeltaNeed::Full);
        assert_eq!(DeltaNeed::classify(&urls[1]), DeltaNeed::Skip);
        assert_eq!(DeltaNeed::classify(&urls[2]), DeltaNeed::Skip);
        assert_eq!(DeltaNeed::classify(&urls[3]), DeltaNeed::Conditional);

        assert!(urls[0].conditional_headers().is_empty());
        assert_eq!(
            urls[1].conditional_headers(),
            vec![("If-None-Match".to_string(), "\"xyz\"".to_string())]
        );
        assert_eq!(urls[3].conditional_headers().len(), 0);
    }

    #[test]
    fn test_plan_incremental_crawl_skips_unchanged_urls() {
        // Three URLs: one never-crawled (Full), one cached-with-validator
        // (Skip → unchanged), one cached-without-validator (Conditional).
        let urls = vec![
            CachedUrl { url: "https://fresh".into(), ..Default::default() },
            CachedUrl {
                url: "https://unchanged-etag".into(),
                content_hash: Some("stored-hash".into()),
                etag: Some("\"v1\"".into()),
                ..Default::default()
            },
            CachedUrl {
                url: "https://recheck".into(),
                content_hash: Some("stored-hash".into()),
                ..Default::default()
            },
        ];

        let plan = plan_incremental_crawl(&urls);

        // The unchanged (Skip) URL is NOT re-crawled.
        let re_crawled: Vec<&str> = plan.re_crawl.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(re_crawled, vec!["https://fresh", "https://recheck"]);
        assert_eq!(plan.re_crawl_count(), 2);

        let unchanged: Vec<&str> = plan.unchanged.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(unchanged, vec!["https://unchanged-etag"]);
        assert_eq!(plan.unchanged_count(), 1);

        // 1 of 3 URLs skipped → skip ratio 1/3.
        assert!((plan.skip_ratio() - 1.0 / 3.0).abs() < 1e-9);
        assert!(describe_plan(&plan).contains("1 unchanged"));
    }

    #[test]
    fn test_plan_incremental_crawl_skips_nothing_when_no_validators() {
        // Entries with only a content hash (no etag/last_modified) must still
        // be re-crawled (Conditional) — nothing may be silently dropped.
        let urls = vec![
            CachedUrl {
                url: "https://x".into(),
                content_hash: Some("h1".into()),
                ..Default::default()
            },
            CachedUrl { url: "https://y".into(), ..Default::default() },
        ];
        let plan = plan_incremental_crawl(&urls);
        assert_eq!(plan.re_crawl_count(), 2);
        assert_eq!(plan.unchanged_count(), 0);
        assert_eq!(DeltaNeed::classify(&urls[0]), DeltaNeed::Conditional);
    }

    #[test]
    fn test_is_unchanged_after_fetch() {
        let cached = CachedUrl {
            url: "https://b".into(),
            content_hash: Some("stored".into()),
            ..Default::default()
        };
        // 304 always means unchanged.
        assert!(is_unchanged_after_fetch(&cached, true, None));
        assert!(is_unchanged_after_fetch(&cached, true, Some("stored")));
        // 200 with matching hash → unchanged.
        assert!(is_unchanged_after_fetch(&cached, false, Some("stored")));
        // 200 with different hash → changed.
        assert!(!is_unchanged_after_fetch(&cached, false, Some("fresh")));
        // 200 with no body hash → cannot prove unchanged.
        assert!(!is_unchanged_after_fetch(&cached, false, None));
        // No prior cache → changed by default.
        let fresh = CachedUrl { url: "https://x".into(), ..Default::default() };
        assert!(!is_unchanged_after_fetch(&fresh, false, Some("anything")));
    }

    #[test]
    fn test_describe_plan_and_skip_ratio() {
        let mut plan = IncrementalPlan::default();
        plan.re_crawl = vec![CachedUrl { url: "a".into(), ..Default::default() }];
        plan.unchanged = vec![CachedUrl { url: "b".into(), ..Default::default() }];
        assert!((plan.skip_ratio() - 0.5).abs() < 1e-9);
        let desc = describe_plan(&plan);
        assert!(desc.contains("1 to re-crawl"));
        assert!(desc.contains("1 unchanged"));
    }

    #[test]
    fn test_cached_url_from_queue() {
        // CrawlQueue is concrete; build one, record a body, then read it back.
        let mut q = CrawlQueue::new();
        let url = "https://example.com/page";
        q.record_response(url, Some("etag-1"), None, "hello world");
        let cached = CachedUrl::from_queue(&q, url);
        assert_eq!(cached.url, url);
        assert_eq!(cached.etag.as_deref(), Some("etag-1"));
        // Hash of "hello world".
        assert_eq!(
            cached.content_hash.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
        assert!(cached.has_cache());
    }

}
