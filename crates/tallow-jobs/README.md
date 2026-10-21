<div align="center">

# tallow-jobs

**Cron, but the run leaves a signed receipt you can verify afterwards.**

![receipts](https://img.shields.io/badge/receipts-kind%20job.run-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

Cron runs your job whether or not you can prove it ran. A failed job leaves nothing behind but an exit code nobody reads, and "did the nightly run happen?" becomes a question answered by memory. This crate schedules `.tl` recipes and writes a signed, chained receipt for **every attempt**.

## What it is

| Module | Responsibility |
|---|---|
| `recipe` | The `.tl` recipe format v1 — a `// @job(...)` comment block at the top of a script |
| `queue` | Priority ordering: priority desc → due asc → sequence asc |
| `exec` | Runs `tallow run <script>` as a subprocess with a hard timeout, output capture and injected `TALLOW_JOB_ID` / `TALLOW_JOB_OUT` |
| `state` | Per-recipe state (`state.json`), append-only `runs.jsonl` and `dead-letter.jsonl` |
| `budget` | Per-recipe daily caps and a fleet kill switch; refusals are recorded, not silent |
| `scheduler` | The tick loop: due scan → priority queue → run → in-tick bounded retries → dead-letter |

A recipe is an ordinary Tallow script; the comment block is the only addition, so the same file still runs by hand:

```tallow
// @job(
//   id: "price-monitor",
//   schedule: 300,        // seconds between runs (fixed interval in v1)
//   priority: 5,          // higher runs first when several are due
//   retries: 2,           // attempts after a failed run
//   timeout_s: 60,        // hard kill
//   enabled: true,
//   args: ["--once"],     // optional: passed after `--` to `tallow run`
//   cwd: "subdir"         // optional: relative to the recipe file
// )
fn main() {
    // …
}
```

Parsing is strict and fail-closed: an unknown key, a duplicate key or a bad value is an error. A typo in `retries` must not silently mean "no retries".

## What it is not

- **Not cron.** Fixed intervals only — no cron expressions, no calendars, no time zones.
- **Not a distributed scheduler.** One process, one worker, sequential runs.
- **Not retry-with-backoff across ticks.** Retries are bounded and happen inside the tick; a failure that needs a long backoff goes to the dead-letter file instead.
- **Not a sandbox.** It runs the `tallow` binary; isolation is the caller's (or the daemon's) job.

## Quick start

```console
$ cargo build -p tallow-jobs

# what would run, in order?
$ ./target/debug/tallow-jobs --ledger receipts.jsonl --dir ./recipes list

# run everything due, once
$ ./target/debug/tallow-jobs --ledger receipts.jsonl --dir ./recipes scheduler --once

# keep ticking
$ ./target/debug/tallow-jobs --ledger receipts.jsonl --dir ./recipes scheduler --tick-ms 1000

# what happened (the run log is append-only JSONL)
$ tail -n 5 runs.jsonl
$ ./target/debug/tallow-jobs --ledger receipts.jsonl dead-letter --json
$ ./target/debug/tallow-jobs --ledger receipts.jsonl verify-ledger
```

```
Usage: tallow-jobs --ledger <L> [--state <S>] [--dead-letter <DL>] [--runs-log <RL>]
                   [--out-dir <O>] [--key <K>] [--actor <A>] <verb> [args]
Verbs: list [--dir D] [--json] | run (--recipe FILE | --dir D --id ID)
       scheduler --dir D [--once] [--max-ticks N] [--tick-ms N] [--retry-delay-ms N] [--budget <F>]
       budget [--budget <F>] [--json] | verify-ledger [--json] | dead-letter [--json]
```

Exit codes: `0` ok · `1` runtime (a failed run or recipe parse errors) · `2` usage.

## Configuration

| Flag | Meaning | Default |
|---|---|---|
| `--ledger` | Receipt ledger shared with `tallow-registry` | required |
| `--state` | Per-recipe state file | `<ledger dir>/state.json` |
| `--dead-letter` | Where exhausted jobs go | `<ledger dir>/dead-letter.jsonl` |
| `--runs-log` | Append-only run log | `<ledger dir>/runs.jsonl` |
| `--out-dir` | Captured stdout/stderr per run | `<ledger dir>/out` |
| `--key` | Actor signing key `{"seed_hex": …}` | deterministic DEV key + warning |
| `--budget` | Budget file for daily caps | none (uncapped) |

The `--budget` file caps runs per recipe per day and holds the fleet kill switch. A refusal is counted (`refused`) and recorded — it does not look like a run that happened.

## Deploying it

The scheduler is a supervised foreground process; systemd owns restart and logging:

```ini
# /etc/systemd/system/tallow-jobs.service
[Unit]
Description=Tallow job scheduler
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tallow-jobs \
  --ledger /var/lib/tallow/receipts.jsonl \
  --dir /srv/tallow/recipes \
  --budget /etc/tallow/budget.json \
  --key /etc/tallow/scheduler-actor.json \
  scheduler --tick-ms 1000
User=tallow
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/tallow /srv/tallow

[Install]
WantedBy=multi-user.target
```

Operational rules:

- **Load a real `--key`.** The dev key is published in this repository; receipts signed with it prove nothing.
- **Watch `dead-letter.jsonl`, not the exit code.** A job that exhausts retries stops being retried, and the dead-letter file is the only place that says so.
- **Budget before you scale.** Without a budget file there is no cap on how often a fast recipe can run.
- **Keep the ledger backed up.** It is the record of what ran; the state file is only an optimisation.

## Design notes

**One receipt per attempt, not per job.** A retry is a real event. Collapsing attempts into one row hides the failure that caused them.

**In-tick retries with a bound.** A retry that waits across ticks needs a persistent backoff queue; v1 chooses the simpler, inspectable behaviour and sends the long-tail cases to the dead-letter file instead of pretending.

**Strict recipe parsing.** A scheduler that guesses at a malformed recipe will eventually guess "run it every second".

## Verification

```console
$ cargo test -p tallow-jobs
$ cargo test -p tallow-jobs recipe -- --nocapture
$ cargo test -p tallow-jobs scheduler -- --nocapture
```

24 test functions in the crate source [measured 2026-10-21]: recipe parse accept/reject cases, queue ordering, retry and dead-letter behaviour, budget refusals, receipt emission.

## Limits

| Limit | Detail |
|---|---|
| Fixed-interval schedules | No cron syntax; `schedule` is seconds |
| Single worker | Runs are sequential; a slow job delays the next |
| Recipes reloaded each tick | Editing a recipe takes effect without a restart — and also means a broken edit fails at the next tick |
| One actor key per ledger | Shared with the registry |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
