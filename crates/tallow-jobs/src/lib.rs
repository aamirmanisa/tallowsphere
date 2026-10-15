//! # tallow-jobs — jobs v1 (`.tl` recipes, scheduler, receipts)
//!
//! Local v1 of the spine's *jobs* element (SPEC-v2 §10): a file-backed
//! scheduler that runs `.tl` recipes and emits **signed run receipts**
//! (`kind: "job.run"`) into the registry's append-only ledger.
//!
//! - [`recipe`] — the `.tl` recipe format v1: a `// @job(...)` comment block
//!   at the top of any Tallow script (schedule · priority · retries ·
//!   timeout · enabled). Strict parsing, fail-closed on unknown keys.
//! - [`queue`] — priority queue ordering (priority desc → due asc → seq asc).
//! - [`exec`] — subprocess runner for `tallow run <script>` with hard
//!   timeout, output capture, and env injection (`TALLOW_JOB_ID`,
//!   `TALLOW_JOB_OUT`).
//! - [`state`] — per-recipe state (`state.json`) + append-only
//!   `dead-letter.jsonl` and `runs.jsonl`.
//! - [`scheduler`] — the tick loop: due-scan → priority queue → run →
//!   in-tick bounded retries → dead-letter; one receipt per attempt.
//!
//! Everything is local by design: the CLI (`tallow-jobs`) is the v1
//! "scheduler service" shape. It runs on deterministic DEV key material by
//! default with a loud warning; `--key` loads real material.
//!
//! v1 limits (documented, not bugs): fixed-interval schedules only (no
//! cron), in-tick retries (no cross-tick backoff queue), single worker
//! (sequential runs), recipes reloaded each tick, one actor key per ledger
//! (shared with the registry).

#![forbid(unsafe_code)]

pub mod budget;
pub mod exec;
pub mod queue;
pub mod recipe;
pub mod scheduler;
pub mod state;

/// Summary of a scheduler pass (once-mode or bounded run).
#[derive(Debug, Default, Clone)]
pub struct SchedulerReport {
    pub ticks: u64,
    pub recipes: usize,
    pub disabled: usize,
    pub parse_errors: Vec<String>,
    pub runs: u64,
    pub attempts: u64,
    pub failures: u64,
    pub dead_letters: u64,
    pub receipts: u64,
    /// Dispatch slots refused by the budget gate (caps / fail-closed state).
    pub refused: u64,
    /// Kill switch was engaged during this pass (fleet stop).
    pub halted: bool,
}

/// Test-only helpers (shared by unit tests in this crate).
#[cfg(test)]
pub(crate) mod test_support {
    use ed25519_dalek::Signer;
    use serde_json::json;
    use tallow_registry::ledger::Ledger;
    use tallow_registry::receipt::{Receipt, Signed, RECEIPT_V};

    /// Append a `job.run` receipt with an exact `ts_ms` (test fixture; the
    /// public `sign_new` always stamps "now", which tests cannot control).
    pub fn append_run_at(ledger: &Ledger, recipe: &str, ts_ms: i64, ok: bool, attempt: u64) {
        let key = tallow_registry::receipt::dev_actor_key();
        let seq = ledger.next_seq().unwrap();
        let prev = ledger.next_prev().unwrap();
        let mut r = Receipt {
            v: RECEIPT_V,
            seq,
            kind: "job.run".into(),
            ts_ms: ts_ms as u64,
            actor: "tallow-jobs-test".into(),
            subject: Some(recipe.into()),
            data: json!({
                "recipe": recipe,
                "ok": ok,
                "exit_code": if ok { 0 } else { 1 },
                "attempt": attempt,
                "duration_ms": 1000,
                "timed_out": false,
            }),
            prev,
            sig: None,
        };
        let digest = r.digest_hex();
        let sig = key.sign(digest.as_bytes());
        r.sig = Some(Signed {
            alg: "ed25519".into(),
            key_fp: tallow_registry::receipt::key_fp16(&key.verifying_key()),
            sig_hex: hex::encode(sig.to_bytes()),
        });
        ledger.append(&r).unwrap();
    }
}
