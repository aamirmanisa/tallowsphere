// tallow.jobs — in-language scheduling bridge to the real browser scheduler.
//
// Bridges the CLI-only scheduler (`tallow browser schedule add|list|pause|
// resume|remove|run` in src/main.rs) to .tl scripts. Jobs are stored in and
// read from the same ScheduleStore the CLI and daemon use
// (~/.tallow-schedules.json). Execution is subprocess-based for now
// (`tallow run <script>`, mirroring the CLI run path); stage-2
// warm-interpreter execution is out of scope.
//
// Capitalized namespace:  Jobs.submit(...)  /  Jobs.list(...)  /  ...
// Lowercase alias:        jobs.submit(...)  /  jobs.list(...)  /  ...
// (both resolve to the same module; the interpreter normalizes the case)
//
// Store override: set the TALLOW_SCHEDULE_STORE env var to point a script at
// a different store file (unset → ~/.tallow-schedules.json, same as CLI).
//
// schedule_spec is one string, validated with the CLI's own parsers:
//   cron:0 8 * * *     cron expression (5 fields; @yearly @monthly @weekly
//                      @daily @hourly shorthands accepted) — raw string kept
//   every:5m           fixed interval (10s.. : s/m/h/d/w units) — stored as
//                      Interval seconds, the store's canonical form
//   daily:09:30        once per day at HH:MM (UTC unless tz_offset_secs set)
//   bare "0 8 * * *"   bare specs are cron (CLI --cron semantics)
//
// Max parallelism (reuses the scheduler core's cap model, scheduler.rs):
// the store-wide cap defaults to the TALLOW_MAX_CONCURRENT env var (40 if
// unset), clamped 1..256. jobs.set_max_concurrent(n) persists an explicit
// cap into the store JSON so it survives restarts. jobs.run_now never spawns
// more subprocesses than the effective cap: at capacity, extra run requests
// are queued (state "pending") and start FIFO as slots free up. A per-job
// {max_parallel: n} submit option additionally caps concurrent instances of
// that one job. jobs.status(id) reports idle | pending | running | done with
// active/queued/completed counters.
//
// run_now is ASYNC: it returns "running" (spawned) or "queued" (waiting for
// a slot) and completion bookkeeping (last_status/run_count) happens on a
// worker thread when the subprocess exits. Keep the calling script alive —
// e.g. poll jobs.status until "done" — otherwise that bookkeeping is lost
// when the process exits. If a scheduled script calls jobs.run_now on its
// own job, each level forks a fresh `tallow run` subprocess: bound the depth
// with the per-job max_parallel option.
//
// Errors are honest: a failed call (duplicate name, unknown id, invalid
// schedule_spec, run_now/status on a missing job, run_now on a job whose
// script file is missing) aborts the script with a descriptive message;
// nothing is recorded for runs that never started.

/// Summary of one scheduled job, as returned by jobs.list().
struct ScheduledJob {
    name: String,
    script: String,
    enabled: Bool,
    status: String,      // "active" | "paused" | "running"
    frequency: String,   // human display, e.g. "cron(0 8 * * *)", "5m"
    run_count: Int,
    last_status: String, // "" when never run
    next_run: Int,       // unix epoch seconds; 0 when none
    last_run: Int,       // unix epoch seconds; 0 when never run
}

/// Run-state of one job, as returned by jobs.status(id).
struct JobStatus {
    state: String,      // "idle" | "pending" | "running" | "done"
    active: Int,        // instances executing right now
    queued: Int,        // accepted run_now requests waiting for a slot
    completed: Int,     // run_now instances finished in this process
    total_runs: Int,    // persisted run_count (incl. daemon runs)
}

/// Submit a new job. The job id is its unique name (duplicates are
/// rejected). Returns the job id.
///
/// Optional 4th arg (a Map): {max_parallel: n} caps how many instances of
/// this job may run concurrently (clamped 1..256, persisted on the job).
/// Extra map keys are ignored.
native fn submit(name: String, script: String, schedule_spec: String, opts: Map?) -> String

/// List all jobs in the store as ScheduledJob structs.
native fn list() -> []ScheduledJob

/// Pause a job by id (it will not fire until resumed). Errors on unknown id.
native fn pause(id: String) -> Bool

/// Resume a paused job by id; recomputes next_run. Errors on unknown id.
native fn resume(id: String) -> Bool

/// Remove a job by id. Errors on unknown id.
native fn remove(id: String) -> Bool

/// Run a job's script once right now, as a subprocess (`tallow run`), and
/// record the outcome (last_status/last_run/run_count) when it finishes.
/// Async: returns "running" when spawned, "queued" when the concurrency cap
/// is full (the request is queued FIFO and starts as slots free up).
/// Real errors (no fake success) when the job or its script file does not
/// exist. Poll jobs.status(id) until "done" to observe completion.
native fn run_now(id: String) -> String

/// Run-state of one job: idle | pending | running | done plus counters.
/// Errors on unknown id.
native fn status(id: String) -> JobStatus

/// Persist the store-wide concurrency cap (clamped 1..256). Survives
/// restarts via the ScheduleStore JSON. Initial default: TALLOW_MAX_CONCURRENT
/// env var, else 40 (same as the scheduler daemon).
native fn set_max_concurrent(n: Int) -> Bool

/// Effective store-wide concurrency cap (persisted value, else the
/// TALLOW_MAX_CONCURRENT env var, else 40).
native fn get_max_concurrent() -> Int
