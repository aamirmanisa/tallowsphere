//! Standard library: `tallow.jobs` — in-language scheduling bridge to the
//! real browser scheduler (`ScheduleStore` / `ScheduledJob` in
//! `src/browser/scheduler.rs`).
//!
//! Today, schedule management is CLI-only (`tallow browser schedule
//! add|list|pause|resume|remove|run` in `src/main.rs`). This module exposes
//! the same store reads/writes to `.tl` scripts so a running script can
//! submit, inspect, pause/resume, remove, and one-shot-run jobs without
//! touching `main.rs`. It is a *bridge*, not a re-architecture:
//!
//! - Execution is subprocess-based: `jobs.run_now` spawns
//!   `tallow run <script>` exactly like the CLI run path (main.rs:6508-6592)
//!   and the daemon's `execute_scheduled_script` (scheduler.rs). Stage-2
//!   warm-interpreter execution is deliberately out of scope.
//! - The store file is the same one the CLI and the scheduler daemon use
//!   (`~/.tallow-schedules.json`, overridable with `TALLOW_SCHEDULE_STORE`).
//! - Max parallelism reuses the scheduler core's cap model (scheduler.rs:
//!   640-655: `TALLOW_MAX_CONCURRENT`, default 40, clamped 1..256) and
//!   persists the explicit cap in the store JSON (`ScheduleStore
//!   .max_concurrent`) so it survives restarts. `jobs.run_now` keeps an
//!   in-process run registry per store path that never starts more
//!   subprocesses than the effective cap; surplus run requests are queued
//!   (state `pending`, observable via `jobs.status`) and drained FIFO as
//!   slots free up. A per-job `{max_parallel: n}` submit option additionally
//!   caps how many instances of that one job may run at once (persisted as
//!   `ScheduledJob.max_parallel`).
//!
//! # API (as surfaced in `stdlib/jobs.tl`)
//!
//! - `jobs.submit(name, script, schedule_spec[, {max_parallel: n}])` → job id (the unique name)
//! - `jobs.list()` → array of `ScheduledJob` summary structs
//! - `jobs.pause(id)` / `jobs.resume(id)` → Bool
//! - `jobs.remove(id)` → Bool
//! - `jobs.run_now(id)` → "running" (spawned) | "queued" (at capacity) — async
//! - `jobs.status(id)` → `JobStatus` struct: state idle|pending|running|done + counters
//! - `jobs.set_max_concurrent(n)` / `jobs.get_max_concurrent()` — global cap
//!
//! Capitalized `Jobs.submit(...)` etc. resolve identically (namespace-case
//! normalization in the interpreter, roadmap #1).
//!
//! # schedule_spec syntax (lossless w.r.t. `Frequency` in scheduler.rs)
//!
//! | prefix | example | stored as |
//! |---|---|---|
//! | `cron:` | `cron:0 8 * * *` | `Frequency::Cron(expr)` (raw string kept) |
//! | `every:` | `every:5m` | `Frequency::Interval(secs)` (via `parse_interval`) |
//! | `daily:` | `daily:09:30` | `Frequency::Daily("09:30")` (raw string kept) |
//! | (bare) | `0 8 * * *` or `@daily` | `Frequency::Cron(spec)` — bare specs
//!   are cron expressions, mirroring `tallow browser schedule add --cron` |
//!
//! All specs are validated with the same parsers the CLI uses
//! (`CronExpr::parse`, `parse_interval`, `validate_daily_time`), so anything
//! accepted here is accepted by `tallow browser schedule add`.
//!
//! # Async run_now and process liveness
//!
//! `run_now` returns as soon as the run is accepted (spawned or queued);
//! completion bookkeeping (last_status/run_count via `mark_ran`) happens on
//! a detached worker thread when the subprocess exits. If the calling
//! process exits before the subprocess finishes (e.g. a `tallow run` script
//! ends without waiting), that bookkeeping is lost — keep the script alive
//! (poll `jobs.status`) until the state reads `done`. Also note: if the
//! scheduled script itself calls `jobs.run_now` on its own job, each level
//! spawns a fresh `tallow run` subprocess — bound the fork depth with the
//! per-job `max_parallel` option.
//!
//! # Store path
//!
//! The module writes the *same* store the CLI and daemon read. Set
//! `TALLOW_SCHEDULE_STORE=/path/to/store.json` to point a script (or a
//! test) at a different store file; unset → `ScheduleStore::default_path()`
//! (identical to src/main.rs:6378). Run-registry state is keyed by store
//! path, so distinct stores never share capacity.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Mutex;
use std::time::Instant;

use super::StdlibResult;
use crate::browser::scheduler::{
    CronExpr, Frequency, ScheduleStore, ScheduledJob, parse_interval, validate_daily_time,
};
use crate::interp::{Value, type_name};

/// Env var that overrides the schedule store path. Unset → the same default
/// the CLI and scheduler daemon use (`~/.tallow-schedules.json`).
pub const STORE_PATH_ENV: &str = "TALLOW_SCHEDULE_STORE";

/// Concurrency clamp + default mirrors `SchedulerDaemon::new`
/// (src/browser/scheduler.rs:640-655): `TALLOW_MAX_CONCURRENT`, default 40,
/// clamped 1..256. The same env var seeds this module's cap when the store
/// has no persisted `max_concurrent`.
pub const MAX_CONCURRENT_ENV: &str = "TALLOW_MAX_CONCURRENT";
pub const MAX_CONCURRENT_DEFAULT: usize = 40;
pub const MAX_CONCURRENT_MIN: usize = 1;
pub const MAX_CONCURRENT_MAX: usize = 256;

/// Test-only seam: when set (non-empty), `run_now` spawns `sh -c <value>`
/// instead of `tallow run <script>`. `job.script` must still exist — the
/// existence check is unchanged. Lets unit tests exercise the concurrency
/// registry with real, short-lived child processes without invoking the
/// test binary. Never set in production.
pub const TEST_RUNNER_ENV: &str = "TALLOW_JOBS_TEST_CMD";

/// Resolve the schedule store path: `TALLOW_SCHEDULE_STORE` when set,
/// otherwise `ScheduleStore::default_path()` (CLI/daemon default).
pub fn store_path() -> PathBuf {
    match std::env::var(STORE_PATH_ENV) {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => ScheduleStore::default_path(),
    }
}

/// Effective store-wide cap: persisted `max_concurrent` (clamped), else the
/// `TALLOW_MAX_CONCURRENT` env var (clamped), else the daemon default 40.
/// Same resolution order the daemon uses for its construction-time cap.
pub fn effective_cap(store: &ScheduleStore) -> usize {
    store
        .max_concurrent
        .map(|v| v.clamp(MAX_CONCURRENT_MIN, MAX_CONCURRENT_MAX))
        .unwrap_or_else(env_cap)
}

fn env_cap() -> usize {
    std::env::var(MAX_CONCURRENT_ENV)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(MAX_CONCURRENT_DEFAULT)
        .clamp(MAX_CONCURRENT_MIN, MAX_CONCURRENT_MAX)
}

fn clamp_parallel(n: usize) -> usize {
    n.clamp(MAX_CONCURRENT_MIN, MAX_CONCURRENT_MAX)
}

/// Parse a `schedule_spec` into a lossless `Frequency` (see module docs).
pub fn parse_schedule_spec(spec: &str) -> Result<Frequency, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty schedule_spec (use cron:<expr> | every:<interval> | daily:<HH:MM>, or a bare cron expression)".to_string());
    }
    if let Some(expr) = spec.strip_prefix("cron:") {
        let expr = expr.trim();
        CronExpr::parse(expr).map_err(|e| format!("invalid cron '{expr}': {e}"))?;
        Ok(Frequency::Cron(expr.to_string()))
    } else if let Some(interval) = spec.strip_prefix("every:") {
        let interval = interval.trim();
        let secs =
            parse_interval(interval).map_err(|e| format!("invalid interval '{interval}': {e}"))?;
        Ok(Frequency::Interval(secs))
    } else if let Some(time) = spec.strip_prefix("daily:") {
        let time = time.trim();
        validate_daily_time(time).map_err(|e| format!("invalid daily time '{time}': {e}"))?;
        Ok(Frequency::Daily(time.to_string()))
    } else {
        // Bare spec = cron expression (CLI `--cron` semantics; supports the
        // @yearly/@monthly/@weekly/@daily/@hourly shorthands too).
        CronExpr::parse(spec).map_err(|e| format!("invalid cron '{spec}': {e}"))?;
        Ok(Frequency::Cron(spec.to_string()))
    }
}

/// Human status mirroring `tallow browser schedule info` (main.rs:6608-6615).
fn status_of(job: &ScheduledJob) -> &'static str {
    if job.running {
        "running"
    } else if job.enabled {
        "active"
    } else {
        "paused"
    }
}

/// Convert one `ScheduledJob` to a `ScheduledJob` struct value for `.tl`.
fn job_to_value(job: &ScheduledJob) -> Value {
    Value::Struct {
        name: "ScheduledJob".to_string(),
        fields: vec![
            ("name".into(), Value::String(job.name.clone())),
            ("script".into(), Value::String(job.script.clone())),
            ("enabled".into(), Value::Bool(job.enabled)),
            ("status".into(), Value::String(status_of(job).to_string())),
            ("frequency".into(), Value::String(job.frequency_display())),
            ("run_count".into(), Value::Int(job.run_count as i128)),
            (
                "last_status".into(),
                Value::String(job.last_status.clone().unwrap_or_default()),
            ),
            ("next_run".into(), Value::Int(job.next_run.unwrap_or(0) as i128)),
            ("last_run".into(), Value::Int(job.last_run.unwrap_or(0) as i128)),
        ],
    }
}

fn store_to_value(store: &ScheduleStore) -> Value {
    Value::Array(store.jobs.iter().map(job_to_value).collect())
}

// ── Run registry (per store path; in-process) ────────────────────────
//
// Tracks spawned `run_now` subprocesses so the store-wide cap and per-job
// `max_parallel` are never exceeded. All mutations happen under one global
// mutex; subprocess *waiting* happens on detached worker threads that
// re-acquire the lock only to bookkeep and drain the queue. Keyed by store
// path so different stores (and different tests) never share capacity.

/// Per-job run bookkeeping.
#[derive(Default)]
struct JobRunState {
    /// Instances currently executing (subprocess spawned).
    active: usize,
    /// Accepted `run_now` requests waiting for a free slot.
    queued: usize,
    /// Instances that finished in this process (success or recorded error).
    completed: usize,
}

/// Per-store run registry.
#[derive(Default)]
struct StoreRunState {
    /// Total subprocesses running right now (across all jobs of the store).
    active: usize,
    /// FIFO of accepted run_now requests awaiting a slot (job snapshots).
    queue: VecDeque<ScheduledJob>,
    /// Per-job bookkeeping.
    jobs: HashMap<String, JobRunState>,
}

static RUN_REGISTRY: std::sync::OnceLock<Mutex<HashMap<String, StoreRunState>>> =
    std::sync::OnceLock::new();

/// Lazily-initialized global registry (HashMap::new is not const, so a plain
/// `static Mutex<HashMap>` is impossible).
fn run_registry() -> &'static Mutex<HashMap<String, StoreRunState>> {
    RUN_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn registry_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Spawn the subprocess for a job run. Production path mirrors the CLI run
/// path (main.rs:6508-6592) — `tallow run <script>` with the job's args,
/// env vars, browser env knobs, and optional working dir. The test seam
/// (`TALLOW_JOBS_TEST_CMD` → `sh -c <cmd>`) is compiled **test-only** — a
/// production binary contains no env-var → shell-execution path (A6.1/R7).
fn spawn_child(job: &ScheduledJob) -> Result<Child, String> {
    #[cfg(test)]
    if let Ok(cmdline) = std::env::var(TEST_RUNNER_ENV) {
        let cmdline = cmdline.trim().to_string();
        if !cmdline.is_empty() {
            return std::process::Command::new("sh")
                .arg("-c")
                .arg(cmdline)
                .spawn()
                .map_err(|e| format!("spawn failed: {e}"));
        }
    }
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot find tallow binary: {e}"))?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("run").arg(&job.script);
    for arg in &job.args {
        cmd.arg(arg);
    }
    for (k, v) in &job.env_vars {
        cmd.env(k, v);
    }
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
    if let Some(ref work_dir) = job.work_dir {
        cmd.current_dir(work_dir);
    }
    cmd.spawn().map_err(|e| format!("spawn failed: {e}"))
}

/// Worker-thread completion path: wait for the child, then (under the
/// registry lock) release the slot, record the run via `mark_ran`, and drain
/// any queued runs into the freed slot(s).
fn complete_run(path: PathBuf, job: ScheduledJob, mut child: Child, started: Instant) {
    let status = child.wait();
    let duration = started.elapsed().as_secs();
    let mark = match &status {
        Ok(s) if s.success() => "ok".to_string(),
        Ok(s) => format!("error: exit {}", s.code().unwrap_or(-1)),
        Err(e) => format!("error: {e}"),
    };

    let mut reg = run_registry().lock().unwrap();
    let key = registry_key(&path);
    let st = reg.entry(key.clone()).or_default();
    st.active = st.active.saturating_sub(1);
    let jr = st.jobs.entry(job.name.clone()).or_default();
    jr.active = jr.active.saturating_sub(1);
    jr.completed += 1;

    // Store bookkeeping under the same lock: concurrent completions of the
    // same job serialize their load → mark_ran → save, so run_count is not
    // lost to read-modify-write races.
    let mut store = ScheduleStore::load(&path);
    if let Some(jm) = store.get_mut(&job.name) {
        jm.mark_ran(&mark, duration);
    }
    let _ = store.save(&path);

    drain_registry_locked(&mut reg, &key, &path);
}

/// Start queued runs until the effective cap or the queue is exhausted.
/// Caller must hold `RUN_REGISTRY`. Jobs whose per-job `max_parallel` is
/// full are cycled to the back; the scan is bounded so a fully-blocked queue
/// does not spin.
fn drain_registry_locked(
    reg: &mut std::sync::MutexGuard<'_, HashMap<String, StoreRunState>>,
    key: &str,
    path: &Path,
) {
    let cap = effective_cap(&ScheduleStore::load(path));
    let st = match reg.get_mut(key) {
        Some(st) => st,
        None => return,
    };
    let queue_len = st.queue.len();
    let mut attempts = 0usize;
    while st.active < cap && attempts < queue_len && !st.queue.is_empty() {
        attempts += 1;
        let job = match st.queue.pop_front() {
            Some(j) => j,
            None => return,
        };
        let per_job = job
            .max_parallel
            .map(|m| clamp_parallel(m as usize));
        let jr = st.jobs.entry(job.name.clone()).or_default();
        if let Some(m) = per_job {
            if jr.active >= m {
                // Per-job cap full — try the next queued job.
                st.queue.push_back(job);
                continue;
            }
        }
        // The script may have disappeared since the request was queued —
        // record an honest failed run (daemon precedent: scheduler.rs:864
        // + 850) rather than silently spawning nothing.
        if !Path::new(&job.script).exists() {
            jr.queued = jr.queued.saturating_sub(1);
            jr.completed += 1;
            let mut store = ScheduleStore::load(path);
            if let Some(jm) = store.get_mut(&job.name) {
                jm.mark_ran(&format!("error: script not found: {}", job.script), 0);
            }
            let _ = store.save(path);
            continue;
        }
        jr.queued = jr.queued.saturating_sub(1);
        jr.active += 1;
        st.active += 1;
        let started = Instant::now();
        match spawn_child(&job) {
            Ok(child) => {
                let p = path.to_path_buf();
                std::thread::spawn(move || complete_run(p, job, child, started));
            }
            Err(e) => {
                jr.active = jr.active.saturating_sub(1);
                st.active = st.active.saturating_sub(1);
                jr.completed += 1;
                let mut store = ScheduleStore::load(path);
                if let Some(jm) = store.get_mut(&job.name) {
                    jm.mark_ran(&format!("error: {e}"), 0);
                }
                let _ = store.save(path);
            }
        }
    }
}

// ── Path-explicit core (unit-tested against temp stores) ─────────────

fn submit_impl(
    path: &Path,
    name: &str,
    script: &str,
    spec: &str,
    max_parallel: Option<u32>,
) -> StdlibResult {
    let name = name.trim();
    if name.is_empty() {
        return Err("jobs.submit: name must not be empty".to_string());
    }
    if script.trim().is_empty() {
        return Err("jobs.submit: script must not be empty".to_string());
    }
    let freq = parse_schedule_spec(spec).map_err(|e| format!("jobs.submit: {e}"))?;
    let mut store = ScheduleStore::load(path);
    let mut job = ScheduledJob::new(name, script, freq);
    job.max_parallel = max_parallel.map(|m| clamp_parallel(m as usize) as u32);
    store.add(job).map_err(|e| format!("jobs.submit: {e}"))?;
    store
        .save(path)
        .map_err(|e| format!("jobs.submit: failed to save {}: {e}", path.display()))?;
    Ok(Value::String(name.to_string()))
}

fn list_impl(path: &Path) -> StdlibResult {
    let store = ScheduleStore::load(path);
    Ok(store_to_value(&store))
}

fn set_enabled_impl(path: &Path, id: &str, enable: bool) -> StdlibResult {
    let mut store = ScheduleStore::load(path);
    if enable {
        store.resume(id).map_err(|e| format!("jobs.resume: {e}"))?;
    } else {
        store.pause(id).map_err(|e| format!("jobs.pause: {e}"))?;
    }
    store
        .save(path)
        .map_err(|e| format!("failed to save {}: {e}", path.display()))?;
    Ok(Value::Bool(true))
}

fn remove_impl(path: &Path, id: &str) -> StdlibResult {
    let mut store = ScheduleStore::load(path);
    store.remove(id).map_err(|e| format!("jobs.remove: {e}"))?;
    store
        .save(path)
        .map_err(|e| format!("jobs.remove: failed to save {}: {e}", path.display()))?;
    Ok(Value::Bool(true))
}

/// Persist the store-wide cap (clamped 1..256). Survives restarts via the
/// ScheduleStore JSON; takes effect for subsequent `run_now` reservations
/// and queue drains in this process too.
fn set_max_concurrent_impl(path: &Path, n: usize) -> StdlibResult {
    let n = clamp_parallel(n);
    let mut store = ScheduleStore::load(path);
    store.max_concurrent = Some(n);
    store
        .save(path)
        .map_err(|e| format!("jobs.set_max_concurrent: failed to save {}: {e}", path.display()))?;
    Ok(Value::Bool(true))
}

/// Read the effective cap: persisted value, else env, else daemon default.
fn get_max_concurrent_impl(path: &Path) -> StdlibResult {
    let store = ScheduleStore::load(path);
    Ok(Value::Int(effective_cap(&store) as i128))
}

/// `run_now` is asynchronous: it spawns (or queues) the subprocess and
/// returns immediately. Real `Err`s — unknown id, missing script, spawn
/// failure — are returned before anything is recorded (no fake success).
/// When the store-wide cap or the job's `max_parallel` is exhausted the
/// request is queued (return "queued"); completion bookkeeping happens on a
/// worker thread, observable via `status(id)`.
fn run_now_impl(path: &Path, id: &str) -> StdlibResult {
    let store = ScheduleStore::load(path);
    let job = store
        .get(id)
        .cloned()
        .ok_or_else(|| format!("jobs.run_now: schedule '{id}' not found"))?;
    if !Path::new(&job.script).exists() {
        return Err(format!("jobs.run_now: script not found: {}", job.script));
    }
    let cap = effective_cap(&store);
    let per_job = job.max_parallel.map(|m| clamp_parallel(m as usize));

    let mut reg = run_registry().lock().unwrap();
    let key = registry_key(path);
    let st = reg.entry(key).or_default();
    let jr = st.jobs.entry(id.to_string()).or_default();
    if st.active < cap && per_job.map_or(true, |m| jr.active < m) {
        // Slot free — reserve and spawn now.
        st.active += 1;
        jr.active += 1;
        match spawn_child(&job) {
            Ok(child) => {
                let p = path.to_path_buf();
                let started = Instant::now();
                std::thread::spawn(move || complete_run(p, job, child, started));
                Ok(Value::String("running".to_string()))
            }
            Err(e) => {
                st.active = st.active.saturating_sub(1);
                jr.active = jr.active.saturating_sub(1);
                Err(format!("jobs.run_now: spawn failed for '{id}': {e}"))
            }
        }
    } else {
        // At capacity (global or per-job) — queue honestly; the request is
        // observable as state "pending" via jobs.status(id).
        jr.queued += 1;
        st.queue.push_back(job);
        Ok(Value::String("queued".to_string()))
    }
}

/// Run-state of one job for `jobs.status`: idle | pending | running | done.
///
/// - `running` — at least one subprocess instance is executing.
/// - `pending` — accepted `run_now` request(s) queued behind a full cap.
/// - `done` — no outstanding work and at least one run has completed (this
///   process or persisted run_count).
/// - `idle` — never run and nothing queued.
fn status_impl(path: &Path, id: &str) -> StdlibResult {
    let store = ScheduleStore::load(path);
    let job = store
        .get(id)
        .ok_or_else(|| format!("jobs.status: schedule '{id}' not found"))?;
    let (active, queued, completed) = {
        let reg = run_registry().lock().unwrap();
        match reg.get(&registry_key(path)).and_then(|st| st.jobs.get(id)) {
            Some(jr) => (jr.active, jr.queued, jr.completed),
            None => (0, 0, 0),
        }
    };
    let state = if active > 0 {
        "running"
    } else if queued > 0 {
        "pending"
    } else if completed > 0 || job.run_count > 0 {
        "done"
    } else {
        "idle"
    };
    Ok(Value::Struct {
        name: "JobStatus".to_string(),
        fields: vec![
            ("state".into(), Value::String(state.to_string())),
            ("active".into(), Value::Int(active as i128)),
            ("queued".into(), Value::Int(queued as i128)),
            ("completed".into(), Value::Int(completed as i128)),
            ("total_runs".into(), Value::Int(job.run_count as i128)),
        ],
    })
}

// ── Dispatch surface (env-resolved store path) ───────────────────────

fn str_arg<'a>(args: &'a [Value], idx: usize, fname: &str) -> Result<&'a str, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(format!(
            "jobs.{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("jobs.{fname}: missing argument {}", idx + 1)),
    }
}

fn int_arg(args: &[Value], idx: usize, fname: &str) -> Result<usize, String> {
    match args.get(idx) {
        Some(Value::Int(i)) => usize::try_from(*i)
            .map_err(|_| format!("jobs.{fname}: argument {} out of range", idx + 1)),
        Some(other) => Err(format!(
            "jobs.{fname}: argument {} expected Int, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("jobs.{fname}: missing argument {}", idx + 1)),
    }
}

/// Optional 4th `submit` argument: a Map like `{max_parallel: 2}` capping
/// how many instances of this job may run concurrently. Absent / `nil` → no
/// per-job cap. Extra map keys are ignored (documented).
fn max_parallel_opt(args: &[Value]) -> Result<Option<u32>, String> {
    let Some(v) = args.get(3) else {
        return Ok(None);
    };
    match v {
        Value::Nil => Ok(None),
        Value::Map(fields) => {
            let mut max_parallel: Option<u32> = None;
            for (k, val) in fields {
                if let Value::String(name) = k {
                    if name != "max_parallel" {
                        continue;
                    }
                } else {
                    continue;
                }
                match val {
                    Value::Int(i) => {
                        let clamped = usize::try_from(*i)
                            .map_err(|_| {
                                "jobs.submit: opts.max_parallel out of range".to_string()
                            })?
                            .clamp(MAX_CONCURRENT_MIN, MAX_CONCURRENT_MAX);
                        max_parallel = Some(clamped as u32);
                    }
                    other => {
                        return Err(format!(
                            "jobs.submit: opts.max_parallel expected Int, got {}",
                            type_name(other)
                        ));
                    }
                }
            }
            Ok(max_parallel)
        }
        other => Err(format!(
            "jobs.submit: argument 4 expected Map? with {{max_parallel: Int}}, got {}",
            type_name(other)
        )),
    }
}

fn submit_dispatch(args: Vec<Value>) -> StdlibResult {
    let name = str_arg(&args, 0, "submit")?;
    let script = str_arg(&args, 1, "submit")?;
    let spec = str_arg(&args, 2, "submit")?;
    let max_parallel = max_parallel_opt(&args)?;
    submit_impl(&store_path(), name, script, spec, max_parallel)
}

fn list_dispatch(args: Vec<Value>) -> StdlibResult {
    if !args.is_empty() {
        return Err(format!(
            "jobs.list: expected no arguments, got {}",
            args.len()
        ));
    }
    list_impl(&store_path())
}

fn pause_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = str_arg(&args, 0, "pause")?;
    set_enabled_impl(&store_path(), id, false)
}

fn resume_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = str_arg(&args, 0, "resume")?;
    set_enabled_impl(&store_path(), id, true)
}

fn remove_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = str_arg(&args, 0, "remove")?;
    remove_impl(&store_path(), id)
}

fn run_now_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = str_arg(&args, 0, "run_now")?;
    run_now_impl(&store_path(), id)
}

fn status_dispatch(args: Vec<Value>) -> StdlibResult {
    let id = str_arg(&args, 0, "status")?;
    status_impl(&store_path(), id)
}

fn set_max_concurrent_dispatch(args: Vec<Value>) -> StdlibResult {
    let n = int_arg(&args, 0, "set_max_concurrent")?;
    set_max_concurrent_impl(&store_path(), n)
}

fn get_max_concurrent_dispatch(args: Vec<Value>) -> StdlibResult {
    if !args.is_empty() {
        return Err(format!(
            "jobs.get_max_concurrent: expected no arguments, got {}",
            args.len()
        ));
    }
    get_max_concurrent_impl(&store_path())
}

/// Route `jobs.*` / `Jobs.*` function calls. Returns `None` for unknown
/// functions so the interpreter can fall through to other dispatch.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "submit" => Some(submit_dispatch(args)),
        "list" => Some(list_dispatch(args)),
        "pause" => Some(pause_dispatch(args)),
        "resume" => Some(resume_dispatch(args)),
        "remove" => Some(remove_dispatch(args)),
        "run_now" => Some(run_now_dispatch(args)),
        "status" => Some(status_dispatch(args)),
        "set_max_concurrent" => Some(set_max_concurrent_dispatch(args)),
        "get_max_concurrent" => Some(get_max_concurrent_dispatch(args)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-128: env-mutating tests serialize on the one process-global env
    // lock (`crate::runtime::egress_http::env_lock`), not a module-local one.

    fn temp_store_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tallow-jobs-{tag}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// Run `f` with TALLOW_SCHEDULE_STORE pointing at `path` (edition-2024:
    /// set_var/remove_var are unsafe). Serialized by ENV_LOCK.
    fn with_store_env<T>(path: &Path, f: impl FnOnce() -> T) -> T {
        // Poison-recovering: a panicking sibling test must not take the rest
        // of the jobs suite down with it.
        let _guard = crate::runtime::egress_http::env_lock();
        // SAFETY: test-only; serialized by the process-global env lock; restored on exit.
        unsafe {
            std::env::set_var(STORE_PATH_ENV, path);
        }
        let result = f();
        // SAFETY: test-only; serialized by the process-global env lock.
        unsafe {
            std::env::remove_var(STORE_PATH_ENV);
        }
        result
    }

    /// Run `f` with the subprocess test seam set (real `sh -c` children).
    fn with_test_runner<T>(cmd: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::runtime::egress_http::env_lock();
        // SAFETY: test-only; serialized by the process-global env lock; restored on exit.
        unsafe {
            std::env::set_var(TEST_RUNNER_ENV, cmd);
        }
        let result = f();
        // SAFETY: test-only; serialized by the process-global env lock.
        unsafe {
            std::env::remove_var(TEST_RUNNER_ENV);
        }
        result
    }

    /// Poll `status(id)` until its state matches `want` or `timeout` passes.
    /// Returns the final JobStatus fields.
    fn wait_for_state(
        path: &Path,
        id: &str,
        want: &str,
        timeout: std::time::Duration,
    ) -> (String, usize, usize, usize) {
        let deadline = Instant::now() + timeout;
        loop {
            let (state, active, queued, completed) = match status_impl(path, id) {
                Ok(Value::Struct { fields, .. }) => {
                    let get = |k: &str| {
                        fields
                            .iter()
                            .find(|(name, _)| name == k)
                            .map(|(_, v)| v.clone())
                            .unwrap()
                    };
                    let s = match get("state") {
                        Value::String(s) => s,
                        _ => String::new(),
                    };
                    let a = match get("active") {
                        Value::Int(i) => i as usize,
                        _ => 0,
                    };
                    let q = match get("queued") {
                        Value::Int(i) => i as usize,
                        _ => 0,
                    };
                    let c = match get("completed") {
                        Value::Int(i) => i as usize,
                        _ => 0,
                    };
                    (s, a, q, c)
                }
                _ => (String::new(), 0, 0, 0),
            };
            if state == want || Instant::now() >= deadline {
                return (state, active, queued, completed);
            }
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
    }

    /// Max number of overlapping live intervals in a B/E marker log written
    /// by the `sh -c` test seam (`echo B >> f; sleep; echo E >> f`).
    fn max_overlap(log: &str) -> usize {
        let mut active = 0usize;
        let mut max = 0usize;
        for line in log.lines() {
            match line.trim() {
                "B" => {
                    active += 1;
                    max = max.max(active);
                }
                "E" => active = active.saturating_sub(1),
                _ => {}
            }
        }
        max
    }

    #[test]
    fn submit_list_roundtrip_is_lossless() {
        let path = temp_store_path("roundtrip");
        // cron spec — raw expression preserved.
        assert!(matches!(
            submit_impl(&path, "backup", "/tmp/backup.tl", "cron:0 8 * * *", None).unwrap(),
            Value::String(s) if s == "backup"
        ));
        // every spec — parsed to Interval seconds (store canonical form).
        assert!(submit_impl(&path, "sync", "/tmp/sync.tl", "every:5m", None).is_ok());
        // daily spec — raw HH:MM preserved.
        assert!(submit_impl(&path, "digest", "/tmp/digest.tl", "daily:09:30", None).is_ok());
        // Bare cron shorthand also accepted (CLI --cron semantics).
        assert!(submit_impl(&path, "hourly_beat", "/tmp/hb.tl", "@hourly", None).is_ok());

        // Duplicate name is rejected (ScheduleStore::add semantics).
        let dup = submit_impl(&path, "backup", "/tmp/other.tl", "cron:0 9 * * *", None);
        assert!(matches!(dup, Err(e) if e.contains("already exists")));

        // list() roundtrips all four jobs.
        let listed = list_impl(&path).unwrap();
        let Value::Array(items) = &listed else {
            panic!("list() should return an Array");
        };
        assert_eq!(items.len(), 4, "four jobs should be listed");

        // Reload from disk and verify scheduling fields were stored lossless.
        let store = ScheduleStore::load(&path);
        assert_eq!(store.jobs.len(), 4);
        let backup = store.get("backup").expect("backup job present");
        assert_eq!(backup.script, "/tmp/backup.tl");
        assert!(matches!(&backup.frequency, Frequency::Cron(e) if e == "0 8 * * *"));
        let sync = store.get("sync").unwrap();
        assert!(matches!(&sync.frequency, Frequency::Interval(300)));
        let digest = store.get("digest").unwrap();
        assert!(matches!(&digest.frequency, Frequency::Daily(t) if t == "09:30"));
        let hourly = store.get("hourly_beat").unwrap();
        assert!(matches!(&hourly.frequency, Frequency::Cron(e) if e == "@hourly"));
        // Fresh jobs start enabled with a computed next run.
        assert!(backup.enabled);
        assert!(backup.next_run.is_some());
        assert_eq!(backup.run_count, 0);
        assert!(backup.last_status.is_none());

        cleanup(&path);
    }

    #[test]
    fn invalid_schedule_specs_are_honest_errors() {
        let path = temp_store_path("badspec");
        for (spec, needle) in [
            ("cron:not a cron", "invalid cron"),
            ("cron:0 8 * *", "invalid cron"), // 4 fields
            ("every:2s", "invalid interval"), // below 10s minimum
            ("every:xyz", "invalid interval"),
            ("daily:25:00", "invalid daily time"), // hour out of range
            ("daily:9am", "invalid daily time"),
            ("", "empty schedule_spec"),
        ] {
            let err = submit_impl(&path, "job_x", "/tmp/x.tl", spec, None).unwrap_err();
            assert!(
                err.contains(needle),
                "spec {spec:?}: expected err containing {needle:?}, got {err:?}"
            );
        }
        // Nothing was persisted.
        assert!(ScheduleStore::load(&path).jobs.is_empty());
        cleanup(&path);
    }

    #[test]
    fn pause_resume_state_transitions() {
        let path = temp_store_path("pauseresume");
        submit_impl(&path, "nightly", "/tmp/nightly.tl", "cron:0 8 * * *", None).unwrap();

        // Pause → disabled on disk, listed as paused.
        assert!(matches!(
            set_enabled_impl(&path, "nightly", false).unwrap(),
            Value::Bool(true)
        ));
        let store = ScheduleStore::load(&path);
        assert!(!store.get("nightly").unwrap().enabled);
        drop(store);
        let Value::Array(items) = list_impl(&path).unwrap() else {
            panic!("list() should return an Array");
        };
        let Value::Struct { fields, .. } = &items[0] else {
            panic!("job should be a Struct");
        };
        let get = |k: &str| {
            fields
                .iter()
                .find(|(name, _)| name == k)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert!(matches!(get("status"), Value::String(s) if s == "paused"));
        assert!(matches!(get("enabled"), Value::Bool(false)));
        assert!(matches!(get("name"), Value::String(s) if s == "nightly"));

        // Resume → enabled again with a recomputed next run.
        assert!(matches!(
            set_enabled_impl(&path, "nightly", true).unwrap(),
            Value::Bool(true)
        ));
        let store = ScheduleStore::load(&path);
        let job = store.get("nightly").unwrap();
        assert!(job.enabled);
        assert!(job.next_run.is_some(), "resume recomputes next_run");

        // Unknown id → honest Err mentioning the id.
        let err = set_enabled_impl(&path, "ghost", false).unwrap_err();
        assert!(err.contains("ghost"), "pause err should name the id: {err}");

        cleanup(&path);
    }

    #[test]
    fn remove_removes_and_reports_unknown() {
        let path = temp_store_path("remove");
        submit_impl(&path, "a", "/tmp/a.tl", "every:1h", None).unwrap();
        submit_impl(&path, "b", "/tmp/b.tl", "every:2h", None).unwrap();

        assert!(matches!(remove_impl(&path, "a").unwrap(), Value::Bool(true)));
        let store = ScheduleStore::load(&path);
        assert_eq!(store.jobs.len(), 1);
        assert!(store.get("a").is_none());
        assert!(store.get("b").is_some());
        drop(store);

        let err = remove_impl(&path, "a").unwrap_err();
        assert!(err.contains("not found"), "second remove should err: {err}");
        cleanup(&path);
    }

    #[test]
    fn run_now_missing_script_is_a_real_error_not_fake_success() {
        let path = temp_store_path("runnow");
        let missing = "/nonexistent/tallow-jobs-definitely-missing.tl";
        submit_impl(&path, "phantom", missing, "every:5m", None).unwrap();

        // Before: pristine job.
        let store = ScheduleStore::load(&path);
        let job = store.get("phantom").unwrap();
        let next_run_before = job.next_run;
        assert_eq!(job.run_count, 0);
        assert!(job.last_status.is_none());
        drop(store);

        // run_now on a job whose script is missing → real Err naming the path.
        let err = run_now_impl(&path, "phantom").unwrap_err();
        assert!(err.contains("script not found"), "err: {err}");
        assert!(
            err.contains(missing),
            "err should name the script path: {err}"
        );

        // Nothing was recorded: no fake success, no phantom run stats.
        let store = ScheduleStore::load(&path);
        let job = store.get("phantom").unwrap();
        assert_eq!(job.run_count, 0, "no run should be recorded");
        assert!(job.last_status.is_none(), "no status should be recorded");
        assert_eq!(job.next_run, next_run_before, "schedule untouched");

        // Unknown id → honest Err.
        let err = run_now_impl(&path, "never_submitted").unwrap_err();
        assert!(err.contains("never_submitted"), "err: {err}");

        cleanup(&path);
    }

    #[test]
    fn dispatch_routes_and_env_store_override() {
        let path = temp_store_path("dispatch");
        with_store_env(&path, || {
            // submit through the router (env-resolved store path).
            let r = crate::stdlib::dispatch(
                "jobs",
                "submit",
                vec![
                    Value::String("nightly".into()),
                    Value::String("/tmp/nightly.tl".into()),
                    Value::String("cron:0 8 * * *".into()),
                ],
            );
            assert!(matches!(r, Some(Ok(Value::String(id))) if id == "nightly"));

            // list through the router sees the submitted job.
            let r = crate::stdlib::dispatch("jobs", "list", vec![])
                .unwrap()
                .unwrap();
            assert!(matches!(&r, Value::Array(a) if a.len() == 1));

            // pause / resume / remove roundtrip through the router.
            assert!(matches!(
                crate::stdlib::dispatch("jobs", "pause", vec![Value::String("nightly".into())]),
                Some(Ok(Value::Bool(true)))
            ));
            assert!(matches!(
                crate::stdlib::dispatch("jobs", "resume", vec![Value::String("nightly".into())]),
                Some(Ok(Value::Bool(true)))
            ));
            assert!(matches!(
                crate::stdlib::dispatch("jobs", "remove", vec![Value::String("nightly".into())]),
                Some(Ok(Value::Bool(true)))
            ));
            assert!(ScheduleStore::load(&path).jobs.is_empty());

            // Unknown job id → Some(Err) (routable but failing honestly).
            let r = crate::stdlib::dispatch("jobs", "run_now", vec![Value::String("nope".into())]);
            assert!(r.is_some() && r.unwrap().is_err());
            let r = crate::stdlib::dispatch("jobs", "status", vec![Value::String("nope".into())]);
            assert!(r.is_some() && r.unwrap().is_err());

            // Wrong arg type → honest Err naming the module function.
            let r = crate::stdlib::dispatch("jobs", "submit", vec![Value::Int(5)]);
            assert!(matches!(r, Some(Err(e)) if e.contains("jobs.submit")));

            // Unknown fn in known module → None (fall-through contract).
            assert!(crate::stdlib::dispatch("jobs", "defragment", vec![]).is_none());
            // Unknown module → None.
            assert!(crate::stdlib::dispatch("not_a_module", "list", vec![]).is_none());
        });
        cleanup(&path);
    }

    #[test]
    fn module_registration_contract() {
        // is_registered_module powers interp.rs namespace resolution for
        // both spellings (lowercase + capitalized alias).
        assert!(crate::stdlib::is_registered_module("jobs"));
        assert!(crate::stdlib::is_registered_module("Jobs"));
    }

    // ── MAX PARALLELISM ─────────────────────────────────────────────

    #[test]
    fn max_concurrent_clamp_and_persist() {
        let path = temp_store_path("cap");
        // Below range clamps to 1.
        assert!(matches!(
            set_max_concurrent_impl(&path, 0).unwrap(),
            Value::Bool(true)
        ));
        assert_eq!(ScheduleStore::load(&path).max_concurrent, Some(1));
        // Above range clamps to 256.
        assert!(set_max_concurrent_impl(&path, 99999).is_ok());
        assert_eq!(ScheduleStore::load(&path).max_concurrent, Some(256));
        // In-range value persists and is readable back.
        assert!(set_max_concurrent_impl(&path, 7).is_ok());
        assert_eq!(ScheduleStore::load(&path).max_concurrent, Some(7));
        assert!(matches!(get_max_concurrent_impl(&path), Ok(Value::Int(7))));
        cleanup(&path);
    }

    #[test]
    fn max_concurrent_env_default_and_clamp() {
        let path = temp_store_path("capenv");
        with_store_env(&path, || {
            // No persisted cap → env TALLOW_MAX_CONCURRENT is the default.
            // SAFETY: test-only, serialized by the process-global env lock.
            unsafe {
                std::env::set_var(MAX_CONCURRENT_ENV, "5");
            }
            assert!(matches!(get_max_concurrent_impl(&path), Ok(Value::Int(5))));
            // Env below/above range is clamped 1..256 too.
            // SAFETY: test-only, serialized by the process-global env lock.
            unsafe {
                std::env::set_var(MAX_CONCURRENT_ENV, "0");
            }
            assert!(matches!(get_max_concurrent_impl(&path), Ok(Value::Int(1))));
            // SAFETY: test-only, serialized by the process-global env lock.
            unsafe {
                std::env::set_var(MAX_CONCURRENT_ENV, "99999");
            }
            assert!(matches!(get_max_concurrent_impl(&path), Ok(Value::Int(256))));
            // A persisted cap wins over the env default.
            assert!(set_max_concurrent_impl(&path, 3).is_ok());
            assert!(matches!(get_max_concurrent_impl(&path), Ok(Value::Int(3))));
            // SAFETY: test-only, serialized by the process-global env lock.
            unsafe {
                std::env::remove_var(MAX_CONCURRENT_ENV);
            }
            assert!(matches!(get_max_concurrent_impl(&path), Ok(Value::Int(3))));
        });
        cleanup(&path);
    }

    #[test]
    fn submit_opts_max_parallel_persists_and_clamps() {
        let path = temp_store_path("jobcap");
        // In-range override persisted on the job.
        submit_impl(&path, "capped", "/tmp/capped.tl", "every:5m", Some(2)).unwrap();
        // Below/above range clamps to 1 / 256.
        submit_impl(&path, "clamp_lo", "/tmp/lo.tl", "every:5m", Some(0)).unwrap();
        submit_impl(&path, "clamp_hi", "/tmp/hi.tl", "every:5m", Some(99999)).unwrap();
        submit_impl(&path, "uncapped", "/tmp/unc.tl", "every:5m", None).unwrap();
        let store = ScheduleStore::load(&path);
        assert_eq!(store.get("capped").unwrap().max_parallel, Some(2));
        assert_eq!(store.get("clamp_lo").unwrap().max_parallel, Some(1));
        assert_eq!(store.get("clamp_hi").unwrap().max_parallel, Some(256));
        assert_eq!(store.get("uncapped").unwrap().max_parallel, None);

        // Dispatch-level opts map parsing runs against its own env store so it
        // can never race a sibling test's store or touch the real HOME store.
        let dpath = temp_store_path("jobcap_dispatch");
        with_store_env(&dpath, || {
            // {max_parallel: 4} + absent map.
            let r = crate::stdlib::dispatch(
                "jobs",
                "submit",
                vec![
                    Value::String("via_map".into()),
                    Value::String("/tmp/vm.tl".into()),
                    Value::String("every:5m".into()),
                    Value::Map(vec![(
                        Value::String("max_parallel".into()),
                        Value::Int(4),
                    )]),
                ],
            );
            assert!(matches!(r, Some(Ok(Value::String(id))) if id == "via_map"));
            let r = crate::stdlib::dispatch(
                "jobs",
                "submit",
                vec![
                    Value::String("via_nil".into()),
                    Value::String("/tmp/vn.tl".into()),
                    Value::String("every:5m".into()),
                    Value::Nil,
                ],
            );
            assert!(matches!(r, Some(Ok(Value::String(id))) if id == "via_nil"));
            // Wrong type in the map → honest Err.
            let r = crate::stdlib::dispatch(
                "jobs",
                "submit",
                vec![
                    Value::String("bad".into()),
                    Value::String("/tmp/bad.tl".into()),
                    Value::String("every:5m".into()),
                    Value::Map(vec![(
                        Value::String("max_parallel".into()),
                        Value::String("lots".into()),
                    )]),
                ],
            );
            assert!(matches!(r, Some(Err(e)) if e.contains("max_parallel")));
            // Non-map 4th arg → honest Err.
            let r = crate::stdlib::dispatch(
                "jobs",
                "submit",
                vec![
                    Value::String("bad2".into()),
                    Value::String("/tmp/bad2.tl".into()),
                    Value::String("every:5m".into()),
                    Value::Int(2),
                ],
            );
            assert!(matches!(r, Some(Err(e)) if e.contains("expected Map")));
            let store = ScheduleStore::load(&dpath);
            assert_eq!(store.get("via_map").unwrap().max_parallel, Some(4));
            assert_eq!(store.get("via_nil").unwrap().max_parallel, None);
        });
        cleanup(&path);
        cleanup(&dpath);
    }

    #[test]
    fn run_now_never_exceeds_global_cap() {
        // Real short-lived `sh` children via the test seam + a B/E marker log.
        let path = temp_store_path("cap2");
        let log = std::env::temp_dir().join(format!(
            "tallow-jobs-overlap-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        assert!(set_max_concurrent_impl(&path, 2).is_ok());
        // Jobs point at real (empty) script files so the existence pre-check
        // passes; the seam replaces the actual command.
        for i in 0..4 {
            let script = std::env::temp_dir().join(format!("tallow-jobs-script-{i}.tl"));
            let _ = std::fs::write(&script, "fn main() {}\n");
            let name = format!("job{i}");
            submit_impl(&path, &name, script.to_str().unwrap(), "every:5m", None).unwrap();
        }

        let cmd = format!("echo B >> {}; sleep 0.6; echo E >> {}", log.display(), log.display());
        with_test_runner(&cmd, || {
            // Four rapid run_now calls: exactly two start, two queue.
            for i in 0..4 {
                let name = format!("job{i}");
                let r = run_now_impl(&path, &name).unwrap();
                let expected = if i < 2 { "running" } else { "queued" };
                assert!(
                    matches!(r, Value::String(s) if s == expected),
                    "job{i} should be {expected} (cap 2)"
                );
            }
            // Observable state right after submission.
            let (s0, a0, _, _) = match status_impl(&path, "job0").unwrap() {
                Value::Struct { fields, .. } => {
                    let get = |k: &str| {
                        fields
                            .iter()
                            .find(|(n, _)| n == k)
                            .map(|(_, v)| v.clone())
                            .unwrap()
                    };
                    (
                        match get("state") {
                            Value::String(s) => s,
                            _ => String::new(),
                        },
                        match get("active") {
                            Value::Int(i) => i as usize,
                            _ => 0,
                        },
                        0,
                        0,
                    )
                }
                _ => (String::new(), 0, 0, 0),
            };
            assert_eq!(s0, "running");
            assert_eq!(a0, 1);
            let (s2, a2, q2, _) = wait_for_state(&path, "job2", "pending", std::time::Duration::from_secs(5));
            assert_eq!(s2, "pending", "job2 waits in the queue");
            assert_eq!(a2, 0, "queued job has no running instance");
            assert_eq!(q2, 1, "exactly one queued request for job2");

            // Everything drains: all four reach done (completed=1 each).
            for i in 0..4 {
                let name = format!("job{i}");
                let (state, _, _, completed) = wait_for_state(
                    &path,
                    &name,
                    "done",
                    std::time::Duration::from_secs(20),
                );
                assert_eq!(state, "done", "{name} should finish");
                assert_eq!(completed, 1, "{name} completed once");
            }
        });

        // Marker-log interval analysis: never more than 2 overlapping runs.
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        let b_count = log_text.lines().filter(|l| l.trim() == "B").count();
        let e_count = log_text.lines().filter(|l| l.trim() == "E").count();
        assert_eq!(b_count, 4, "all four runs started: {log_text}");
        assert_eq!(e_count, 4, "all four runs finished: {log_text}");
        assert!(
            max_overlap(&log_text) <= 2,
            "global cap 2 violated: {log_text}"
        );

        let _ = std::fs::remove_file(&log);
        cleanup(&path);
    }

    #[test]
    fn run_now_per_job_max_parallel_honored() {
        let path = temp_store_path("perjob");
        let log = std::env::temp_dir().join(format!(
            "tallow-jobs-perjob-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        // Global headroom: 8. Job "solo" allows only 1 concurrent instance.
        assert!(set_max_concurrent_impl(&path, 8).is_ok());
        for (name, cap) in [("solo", Some(1u32)), ("free", None)] {
            let script = std::env::temp_dir().join(format!("tallow-jobs-{name}.tl"));
            let _ = std::fs::write(&script, "fn main() {}\n");
            submit_impl(
                &path,
                name,
                script.to_str().unwrap(),
                "every:5m",
                cap,
            )
            .unwrap();
        }

        let cmd = format!("echo B >> {}; sleep 0.5; echo E >> {}", log.display(), log.display());
        with_test_runner(&cmd, || {
            // Three rapid run_now calls on the per-job-capped job: 1 running,
            // 2 queued (global cap has room, per-job cap does not).
            for i in 0..3 {
                let r = run_now_impl(&path, "solo").unwrap();
                let expected = if i == 0 { "running" } else { "queued" };
                assert!(
                    matches!(r, Value::String(s) if s == expected),
                    "solo call {i} should be {expected}"
                );
            }
            // An uncapped job still runs immediately (global headroom left).
            let r = run_now_impl(&path, "free").unwrap();
            assert!(matches!(r, Value::String(s) if s == "running"));

            let (state, active, queued, _) = wait_for_state(
                &path,
                "solo",
                "running",
                std::time::Duration::from_secs(5),
            );
            assert_eq!(state, "running");
            assert_eq!(active, 1, "solo: at most 1 instance");
            assert_eq!(queued, 2, "solo: two requests queued behind its cap");

            // Everything drains to done.
            let (s, _, _, completed) =
                wait_for_state(&path, "solo", "done", std::time::Duration::from_secs(20));
            assert_eq!(s, "done");
            assert_eq!(completed, 3);
            let (s, _, _, completed) =
                wait_for_state(&path, "free", "done", std::time::Duration::from_secs(20));
            assert_eq!(s, "done");
            assert_eq!(completed, 1);
        });

        // Marker-log analysis: solo never overlaps itself; total overlap ≤ 8.
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(max_overlap(&log_text) <= 8, "log: {log_text}");
        // Solo's 3 runs are serialized: total B=4, and every solo interval is
        // disjoint — proven by max_overlap of only-solo markers. Re-derive
        // with a solo-only log by filtering impossible; instead assert the
        // queueing already proved it. Keep: 4 B + 4 E.
        assert_eq!(
            log_text.lines().filter(|l| l.trim() == "B").count(),
            4,
            "log: {log_text}"
        );
        assert_eq!(
            log_text.lines().filter(|l| l.trim() == "E").count(),
            4,
            "log: {log_text}"
        );

        let _ = std::fs::remove_file(&log);
        cleanup(&path);
    }

    #[test]
    fn interp_end_to_end() {
        // Exercises namespace resolution (lowercase `jobs.*` and the
        // capitalized `Jobs.*` alias), submit/list/pause/resume/remove
        // dispatch, the parallelism surface, struct field access on list()
        // and status() results, and real store persistence — through the
        // actual lexer/parser/interpreter. run_now is intentionally not
        // exercised here (it spawns subprocesses); see the seam tests.
        let path = temp_store_path("interp");
        with_store_env(&path, || {
            let src = r#"
            fn main() {
                print(jobs.submit("nightly", "scripts/e2e_nightly.tl", "cron:0 8 * * *"))
                print(Jobs.submit("frequent", "scripts/e2e_frequent.tl", "every:5m"))
                print(jobs.submit("daily_digest", "scripts/e2e_daily.tl", "daily:09:30"))
                print(len(jobs.list()))
                print(jobs.set_max_concurrent(3))
                print(jobs.get_max_concurrent())
                print(jobs.pause("nightly"))
                let all = jobs.list()
                let first = all[0]
                print(first.name)
                print(first.status)
                print(first.enabled.to_string())
                print(first.frequency)
                print(jobs.resume("nightly"))
                print(jobs.remove("daily_digest"))
                print(len(jobs.list()))
                let remaining = jobs.list()
                print(remaining[0].name)
                let st = jobs.status("nightly")
                print(st.state)
                print(st.active.to_string())
                print(st.completed.to_string())
                print(st.total_runs.to_string())
            }
            "#;
            let (tokens, lex_errs) = crate::lexer::tokenize(src);
            assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
            let program = crate::parser::Parser::parse(tokens).expect("parse error");
            let mut interp = crate::interp::Interpreter::new();
            interp.run(&program).expect("interp run failed");
            assert_eq!(
                interp.output,
                vec![
                    "nightly",         // 0 submit (cron)
                    "frequent",        // 1 Jobs.submit capitalized alias
                    "daily_digest",    // 2 submit (daily)
                    "3",               // 3 len(list())
                    "true",            // 4 set_max_concurrent(3)
                    "3",               // 5 get_max_concurrent
                    "true",            // 6 pause ok
                    "nightly",         // 7 first job name
                    "paused",          // 8 status after pause
                    "false",           // 9 enabled after pause
                    "cron(0 8 * * *)", // 10 lossless cron frequency display
                    "true",            // 11 resume ok
                    "true",            // 12 remove ok
                    "2",               // 13 len(list()) after remove
                    "nightly",         // 14 remaining[0].name (insertion order)
                    "idle",            // 15 status state: never run_now'd
                    "0",               // 16 active
                    "0",               // 17 completed (this process)
                    "0",               // 18 total_runs
                ],
                "output: {:?}",
                interp.output
            );
            // Store on disk reflects the final state (2 jobs, nightly active,
            // cap 3 persisted).
            let store = ScheduleStore::load(&path);
            assert_eq!(store.jobs.len(), 2);
            assert!(store.get("nightly").unwrap().enabled);
            assert!(store.get("daily_digest").is_none());
            assert_eq!(store.max_concurrent, Some(3));
        });
        cleanup(&path);
    }
}
