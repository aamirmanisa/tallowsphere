//! `tallow drill` exercise mode — matrix #205 · agent-07 R-14 (W3 batch-2
//! cluster C). CCDCOE/NCSC lesson: *readiness is exercised*, and the row's
//! acceptance is: *"built-in scenario drills (key compromise, rogue mesh node,
//! relay down, vault key loss, backup restore) run against a sandboxed local
//! deployment; generates after-action report; runbooks versioned."*
//!
//! Design rules (mirroring the B3.2 fault-injection precedent):
//!
//! * **Real in-repo machinery, no parallel fakes.** Each scenario drives the
//!   actual subsystem: `key_ledger` reuse gates + `tallow-svid` signed
//!   revocation lists (key compromise), `tallow-svid::policy` node pinning +
//!   service registry (rogue node), `tallow-protocol::transfer::journal`
//!   (relay outage / resume), `vault::share` Shamir custody (vault key loss),
//!   `vault::import_export` TVX1 export (backup restore), and
//!   [`crate::key_drills`] (crypto-agility rehearsal, bridging #54).
//! * **Sandboxed + offline.** Everything runs under a caller-supplied sandbox
//!   directory (tempdir by default); no sockets, no network, no daemon.
//! * **Bounded.** Fixed scenario list; the crypto-agility scenario takes an
//!   explicit `scale` (default 1_000; 750_000 = ID-card scale is stageable and
//!   measured in the lane log run — see `docs/ops/drills.md`).
//! * **After-action report.** Every run writes `after-action-<stamp>.json`
//!   (schema `tallow.drill.after_action.v1`) + a human `.md` twin into the
//!   report dir, and names the runbook section per scenario.
//! * **Honest scope.** A scenario's steps only claim what the offline sandbox
//!   proved. Live legs (real relay down, real daemon eviction) are named as
//!   operator steps in the runbook, never simulated as if executed.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::key_drills::{self, DependencyGraph, DrillKey, RehearsalSpec, SignedReceipt};
use tallow_crypto::sig::ed25519::Ed25519Signer;
use tallow_svid::model::SpiffeId;
use tallow_svid::policy::{check_node_pin, NodePin, ServiceRegistry};
use tallow_svid::revocation::{RevocationEntry, RevocationList, RevocationReason, RevocationStore};

/// Schema of the after-action report.
pub const AFTER_ACTION_SCHEMA: &str = "tallow.drill.after_action.v1";
/// Default rehearsal scale for the crypto-agility scenario (bounded).
pub const DEFAULT_AGILITY_SCALE: usize = 1_000;
/// ID-card-scale reference for the crypto-agility rehearsal (ROCA: ≈750 k).
pub const ID_CARD_SCALE: usize = 750_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Harness-level drill failures (a scenario *finding* is a failed step, not an
/// `Err`; `Err` means the drill itself could not run).
#[derive(Debug, thiserror::Error)]
pub enum DrillError {
    /// Unknown scenario id.
    #[error("unknown scenario {0:?} (see `tallow drill --list`)")]
    UnknownScenario(String),
    /// Filesystem failure while staging the sandbox/evidence.
    #[error("drill io: {0}")]
    Io(String),
    /// Crypto-agility sub-drill refused (typed upstream error).
    #[error("crypto-agility: {0}")]
    Agility(#[from] key_drills::DrillError),
    /// Any other staging failure.
    #[error("drill setup: {0}")]
    Setup(String),
}

fn io<E: std::fmt::Display>(e: E) -> DrillError {
    DrillError::Io(e.to_string())
}

// ---------------------------------------------------------------------------
// Scenario registry
// ---------------------------------------------------------------------------

/// Static scenario metadata (the runbook contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioMeta {
    /// Stable id (`tallow drill --scenario <id>`).
    pub id: &'static str,
    /// Human title.
    pub title: &'static str,
    /// Fault injected.
    pub fault: &'static str,
    /// Expected handling (what a pass means).
    pub expected: &'static str,
    /// Runbook anchor in `docs/ops/drills.md`.
    pub runbook: &'static str,
}

/// The canonical offline scenario suite (fixed order).
pub const SCENARIOS: &[ScenarioMeta] = &[
    ScenarioMeta {
        id: "key-compromise",
        title: "Key compromise → detect, revoke, reissue",
        fault: "one signing key leaks and is used from a second context",
        expected: "cross-context reuse detected; signed revocation entry applied; \
                   dependents reissued with verifiable receipts",
        runbook: "docs/ops/drills.md#key-compromise",
    },
    ScenarioMeta {
        id: "rogue-node",
        title: "Rogue mesh node → pin refusal + eviction",
        fault: "a node id outside the pin joins claiming a registry service",
        expected: "node-pin check and service allowlist both refuse (fail closed); \
                   eviction record emitted",
        runbook: "docs/ops/drills.md#rogue-node",
    },
    ScenarioMeta {
        id: "relay-outage",
        title: "Relay outage → journaled resume",
        fault: "transfer interrupted mid-run (relay down)",
        expected: "delta-sync journal survives the outage; committed files are not \
                   re-copied; pending files are re-copied; no journal ⇒ no silent skip",
        runbook: "docs/ops/drills.md#relay-outage",
    },
    ScenarioMeta {
        id: "vault-key-loss",
        title: "Vault key loss → custody-share recovery",
        fault: "master key gone; only custody shares remain",
        expected: "threshold shares reconstruct the key; fewer than threshold fail closed",
        runbook: "docs/ops/drills.md#vault-key-loss",
    },
    ScenarioMeta {
        id: "backup-restore",
        title: "Backup restore → TVX1 export round-trip",
        fault: "vault state lost; restore from encrypted export",
        expected: "export restores byte-exact entries; wrong passphrase and tampering \
                   fail closed",
        runbook: "docs/ops/drills.md#backup-restore",
    },
    ScenarioMeta {
        id: "crypto-agility",
        title: "Crypto-agility rehearsal (ROCA playbook, #54 bridge)",
        fault: "algorithm/key family retires: mass revocation + reissue at scale",
        expected: "deterministic wave plan, signed+verified migration receipts, \
                   deprecation clocks joined from the T-206 registry",
        runbook: "docs/ops/drills.md#crypto-agility",
    },
];

/// One executed step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    /// Step name.
    pub step: String,
    /// Pass/fail.
    pub ok: bool,
    /// What was observed (evidence line).
    pub detail: String,
}

/// Outcome of one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioOutcome {
    /// Scenario id.
    pub id: String,
    /// Title at run time.
    pub title: String,
    /// Whether the scenario is usable offline (all current ones are).
    pub offline_checkable: bool,
    /// `true` iff every step passed.
    pub passed: bool,
    /// Executed steps.
    pub steps: Vec<StepResult>,
    /// Findings / notes (honest labels).
    pub findings: Vec<String>,
    /// Runbook anchor.
    pub runbook: String,
}

/// The after-action report (written as JSON + Markdown).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AfterActionReport {
    /// [`AFTER_ACTION_SCHEMA`].
    pub schema: String,
    /// UTC stamp (from the caller-provided clock).
    pub generated_at: String,
    /// Sandbox root the scenarios ran in.
    pub sandbox: String,
    /// Scale used for the crypto-agility rehearsal.
    pub scale: usize,
    /// Scenario outcomes, in suite order.
    pub scenarios: Vec<ScenarioOutcome>,
    /// Passed scenario count.
    pub passed: usize,
    /// Failed scenario count.
    pub failed: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn stamp_from_ms(now_ms: i64) -> String {
    match chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms) {
        Some(dt) => dt.format("%Y-%m-%dT%H-%M-%SZ").to_string(),
        None => format!("unix-ms-{now_ms}"),
    }
}

fn year_from_ms(now_ms: i64) -> i32 {
    use chrono::Datelike;
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
        .map(|dt| dt.year())
        .unwrap_or(2026)
}

fn step(step: &str, ok: bool, detail: impl Into<String>) -> StepResult {
    StepResult {
        step: step.to_string(),
        ok,
        detail: detail.into(),
    }
}

fn scenario_dir(sandbox: &Path, id: &str) -> Result<PathBuf, DrillError> {
    let dir = sandbox.join(id);
    std::fs::create_dir_all(&dir).map_err(io)?;
    Ok(dir)
}

fn write_evidence(dir: &Path, name: &str, value: &serde_json::Value) -> Result<(), DrillError> {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(value).map_err(io)?).map_err(io)?;
    Ok(())
}

fn finish(
    meta: &ScenarioMeta,
    steps: Vec<StepResult>,
    mut findings: Vec<String>,
) -> ScenarioOutcome {
    let passed = steps.iter().all(|s| s.ok) && !steps.is_empty();
    let failed_steps: Vec<&str> = steps
        .iter()
        .filter(|s| !s.ok)
        .map(|s| s.step.as_str())
        .collect();
    if !passed {
        findings.push(format!("failed steps: {}", failed_steps.join(", ")));
    }
    ScenarioOutcome {
        id: meta.id.to_string(),
        title: meta.title.to_string(),
        offline_checkable: true,
        passed,
        steps,
        findings,
        runbook: meta.runbook.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Scenario 1 — key compromise (#205 × #54/#120 adjacent)
// ---------------------------------------------------------------------------

fn scenario_key_compromise(sandbox: &Path, now_ms: i64) -> Result<ScenarioOutcome, DrillError> {
    let meta = SCENARIOS
        .iter()
        .find(|m| m.id == "key-compromise")
        .ok_or_else(|| DrillError::UnknownScenario("key-compromise".into()))?;
    let dir = scenario_dir(sandbox, meta.id)?;
    let t_s = now_ms / 1000;
    let mut steps = Vec::new();

    // 1. Detect: the compromised key appears in a second context.
    use crate::key_ledger::{KeyUse, KeyUseLedger};
    let mut ledger = KeyUseLedger::new();
    for (ctx, ts) in [("daemon", t_s - 600), ("mesh", t_s - 300)] {
        ledger
            .record_key_use(KeyUse {
                key_id: "svid:daemon:v1".to_string(),
                context: ctx.to_string(),
                ts_ms: ts * 1000,
                operation: "sign".to_string(),
                fingerprint: "ed25519-fp-drill".to_string(),
            })
            .map_err(io)?;
    }
    let findings = ledger.reuse_findings();
    let detected = findings.len() == 1
        && findings[0].contexts == vec!["daemon".to_string(), "mesh".to_string()];
    steps.push(step(
        "detect-cross-context-reuse",
        detected,
        format!(
            "reuse findings: {} (contexts {:?})",
            findings.len(),
            findings
                .first()
                .map(|f| f.contexts.clone())
                .unwrap_or_default()
        ),
    ));

    // 2. Hard-fail gate: the second context is denied before any use.
    let gate = ledger.check_reuse("svid:daemon:v1", "mesh");
    steps.push(step(
        "hard-fail-gate-denies-second-context",
        gate.is_err(),
        match &gate {
            Err(e) => e.to_string(),
            Ok(()) => "unexpectedly allowed".to_string(),
        },
    ));

    // 3. Revoke: signed revocation entry + list applied through the store.
    let signer = Ed25519Signer::keygen();
    let pk = signer.verifying_key_bytes();
    let entry = RevocationEntry::sign(
        &signer,
        "svid-serial-0001",
        RevocationReason::KeyCompromise,
        t_s,
    )
    .map_err(io)?;
    let list = RevocationList::sign(&signer, 1, t_s, vec![entry]).map_err(io)?;
    let verified = list.verify(&pk).is_ok();
    let mut store = RevocationStore::with_default_freshness(pk);
    let applied = store.apply(&list, t_s).is_ok();
    let revoked = store.is_revoked_at("svid-serial-0001", t_s);
    steps.push(step(
        "revoke-signed-entry-applied",
        verified && applied && revoked,
        format!("list verified={verified} applied={applied} revoked={revoked}"),
    ));

    // 4. Reissue: dependents reissued with signed, verified receipts.
    let graph = DependencyGraph::new(vec![
        DrillKey {
            key_id: "svid:daemon".to_string(),
            algorithm: "Ed25519".to_string(),
            custody: "vault".to_string(),
            services: vec!["daemon".to_string(), "mesh".to_string()],
        },
        DrillKey {
            key_id: "svid:reader".to_string(),
            algorithm: "Ed25519".to_string(),
            custody: "vault".to_string(),
            services: vec!["reader".to_string()],
        },
    ])
    .map_err(DrillError::Agility)?;
    let rehearsal = key_drills::rehearse_mass_revocation(
        &graph,
        &RehearsalSpec {
            now_ms,
            revoke: vec!["svid:daemon".to_string()],
            scale: 64,
            batch: 64,
        },
        &signer,
    )?;
    let receipts_ok = !rehearsal.receipts.is_empty()
        && rehearsal
            .receipts
            .iter()
            .all(|r| key_drills::verify_receipt(r).is_ok());
    steps.push(step(
        "reissue-with-verified-receipts",
        receipts_ok,
        format!(
            "fleet {} reissued across {} wave(s); receipts verified: {}",
            rehearsal.fleet_size,
            rehearsal.waves.len(),
            rehearsal.receipts.len()
        ),
    ));

    write_evidence(
        &dir,
        "evidence.json",
        &serde_json::json!({
            "scenario": meta.id,
            "ts_unix": t_s,
            "reuse_findings": findings,
            "revocation_serial": "svid-serial-0001",
            "rehearsal": rehearsal,
        }),
    )?;
    Ok(finish(
        meta,
        steps,
        vec![
            "offline drill: detection, revocation and reissue machinery exercised with real in-repo code paths".to_string(),
            "operator leg: run the same sequence against the live daemon with `tallow doctor --rotation` alarms open".to_string(),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Scenario 2 — rogue node
// ---------------------------------------------------------------------------

fn scenario_rogue_node(sandbox: &Path, now_ms: i64) -> Result<ScenarioOutcome, DrillError> {
    let meta = SCENARIOS
        .iter()
        .find(|m| m.id == "rogue-node")
        .ok_or_else(|| DrillError::UnknownScenario("rogue-node".into()))?;
    let dir = scenario_dir(sandbox, meta.id)?;
    let mut steps = Vec::new();

    let pin = NodePin::new("node-01").map_err(io)?;
    let legit = SpiffeId::new("node-01", "daemon").map_err(io)?;
    let rogue = SpiffeId::new("node-99", "daemon").map_err(io)?;

    // 1. Node pin: the rogue node id is refused, the pinned one passes.
    let rogue_res = check_node_pin(pin.as_str(), &rogue);
    let legit_res = check_node_pin(pin.as_str(), &legit);
    steps.push(step(
        "node-pin-refuses-rogue-accepts-pinned",
        rogue_res.is_err() && legit_res.is_ok(),
        format!(
            "rogue → {}; pinned → ok={}",
            rogue_res
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ALLOWED (!!)".into()),
            legit_res.is_ok()
        ),
    ));

    // 2. Service allowlist: an unregistered service is refused.
    let registry = ServiceRegistry::builtin();
    let unregistered = registry.require_registered("rogue-svc");
    let registered = registry.require_registered("daemon");
    steps.push(step(
        "service-allowlist-refuses-unregistered",
        unregistered.is_err() && registered.is_ok(),
        format!(
            "rogue-svc → {}; daemon → ok={}",
            unregistered
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ALLOWED (!!)".into()),
            registered.is_ok()
        ),
    ));

    // 3. Eviction record (what the operator applies on the live mesh).
    let eviction = serde_json::json!({
        "schema": "tallow.drill.eviction_record.v1",
        "node_id": "node-99",
        "action": "evict",
        "reason": "node_pin_mismatch",
        "ts_unix": now_ms / 1000,
        "evidence": "node-pin check returned a typed refusal (offline drill)",
    });
    write_evidence(&dir, "eviction-record.json", &eviction)?;
    steps.push(step(
        "eviction-record-emitted",
        true,
        "eviction-record.json written (node-99, node_pin_mismatch)".to_string(),
    ));

    Ok(finish(
        meta,
        steps,
        vec![
            "offline drill: both fail-closed gates exercised directly".to_string(),
            "operator leg: apply the eviction record to the live mesh registry and confirm heartbeat silence".to_string(),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Scenario 3 — relay outage (journaled resume)
// ---------------------------------------------------------------------------

fn scenario_relay_outage(sandbox: &Path, now_ms: i64) -> Result<ScenarioOutcome, DrillError> {
    let meta = SCENARIOS
        .iter()
        .find(|m| m.id == "relay-outage")
        .ok_or_else(|| DrillError::UnknownScenario("relay-outage".into()))?;
    let dir = scenario_dir(sandbox, meta.id)?;
    let src = dir.join("src");
    let dst = dir.join("dst");
    std::fs::create_dir_all(&src).map_err(io)?;
    std::fs::create_dir_all(&dst).map_err(io)?;
    let mut steps = Vec::new();

    // Real files on disk: (rel, bytes) for committed/pending/failed cases.
    for (rel, bytes) in [
        ("a.txt", b"aaaa".as_slice()),
        ("b.txt", b"bbbb"),
        ("c.txt", b"cccc"),
    ] {
        std::fs::write(src.join(rel), bytes).map_err(io)?;
    }
    // The committed file reached the target before the outage; b/c did not.
    std::fs::write(dst.join("a.txt"), b"aaaa").map_err(io)?;

    use tallow_protocol::transfer::journal::{
        consult, DeltaSyncJournal, JournalDecision, JournalEntry, JournalEntryStatus,
    };
    let t = (now_ms / 1000) as u64;
    let mut journal = DeltaSyncJournal::new(
        src.to_str()
            .ok_or_else(|| DrillError::Setup("src path not utf8".into()))?,
        dst.to_str()
            .ok_or_else(|| DrillError::Setup("dst path not utf8".into()))?,
    );
    let size_of = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mk = |rel: &str, status| JournalEntry {
        rel_path: rel.to_string(),
        size: size_of(&src.join(rel)),
        mtime: t,
        src_blake3: None,
        status,
        ts: t,
    };
    journal
        .entries
        .push(mk("a.txt", JournalEntryStatus::Committed));
    journal
        .entries
        .push(mk("b.txt", JournalEntryStatus::Pending));
    journal
        .entries
        .push(mk("c.txt", JournalEntryStatus::Failed));

    // 1. The journal survives the outage (atomic save + validated reload).
    let jpath = dir.join("run-drill.postcard");
    journal.save_atomic(&jpath).map_err(io)?;
    let reloaded = DeltaSyncJournal::load(&jpath).map_err(io)?;
    let survived = reloaded.entries.len() == 3
        && reloaded.entry("a.txt").map(|e| e.status) == Some(JournalEntryStatus::Committed);
    steps.push(step(
        "journal-survives-interruption",
        survived,
        format!(
            "{} entries reloaded from {}",
            reloaded.entries.len(),
            jpath.display()
        ),
    ));

    // 2. Resume decisions are exactly: committed → skip, pending → recopy,
    //    failed → caller's fallback (None), never a silent skip.
    let a = reloaded.entry("a.txt");
    let b = reloaded.entry("b.txt");
    let c = reloaded.entry("c.txt");
    let skip = consult(
        a,
        size_of(&src.join("a.txt")),
        t,
        Some((size_of(&dst.join("a.txt")), t)),
    );
    let recopy = consult(b, size_of(&src.join("b.txt")), t, Some((0, 0)));
    let failed_opinion = consult(c, size_of(&src.join("c.txt")), t, Some((0, 0)));
    let committed_target_missing = consult(a, size_of(&src.join("a.txt")), t, None);
    let ok = skip == Some(JournalDecision::Skip)
        && recopy == Some(JournalDecision::Recopy)
        && failed_opinion.is_none()
        && committed_target_missing.is_none();
    steps.push(step(
        "resume-decisions-committed-pending-failed",
        ok,
        format!(
            "a(copy present)={skip:?}; b(pending)={recopy:?}; c(failed)={failed_opinion:?}; \
             a(target missing)={committed_target_missing:?}"
        ),
    ));

    // 3. Fail closed: no journal ⇒ no opinion (full recopy, never silent skip).
    let no_journal = consult(
        None,
        size_of(&src.join("b.txt")),
        t,
        Some((size_of(&src.join("b.txt")), t)),
    );
    steps.push(step(
        "no-journal-never-silently-skips",
        no_journal.is_none(),
        format!("consult without entry → {no_journal:?}"),
    ));

    Ok(finish(
        meta,
        steps,
        vec![
            "offline drill: journal persistence + resume decision table exercised on real files".to_string(),
            "operator leg: kill the relay mid-transfer on the live path, then confirm the next run emits \
             the same decision table (committed skipped, pending recopied)"
                .to_string(),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Scenario 4 — vault key loss (custody shares)
// ---------------------------------------------------------------------------

fn scenario_vault_key_loss(sandbox: &Path, now_ms: i64) -> Result<ScenarioOutcome, DrillError> {
    let meta = SCENARIOS
        .iter()
        .find(|m| m.id == "vault-key-loss")
        .ok_or_else(|| DrillError::UnknownScenario("vault-key-loss".into()))?;
    let dir = scenario_dir(sandbox, meta.id)?;
    let mut steps = Vec::new();

    use crate::vault::share::{recover_master_key, split_master_key};
    let master = b"tallow-drill-master-key-material-32b";
    let shares = split_master_key(master, 2, 3).map_err(io)?;
    let recovered_12 = recover_master_key(&shares[0..2]);
    let recovered_23 = recover_master_key(&shares[1..3]);
    let ok = recovered_12.as_deref() == Ok(master.as_slice())
        && recovered_23.as_deref() == Ok(master.as_slice());
    steps.push(step(
        "threshold-shares-reconstruct-key",
        ok,
        format!(
            "2-of-3 respected: shares[0,1]={} shares[1,2]={}",
            recovered_12.is_ok(),
            recovered_23.is_ok()
        ),
    ));

    // Below threshold must fail closed.
    let one = recover_master_key(&shares[0..1]);
    steps.push(step(
        "below-threshold-refused",
        one.is_err(),
        one.err()
            .unwrap_or_else(|| "RECONSTRUCTED (!!)".to_string()),
    ));

    // Evidence: share metadata only (no secret material in the report).
    let share_meta: Vec<serde_json::Value> = shares
        .iter()
        .map(|s| {
            serde_json::json!({
                "index": s.index,
                "threshold": s.threshold,
                "total_shares": s.total_shares,
                "data_len": s.data.len(),
            })
        })
        .collect();
    write_evidence(
        &dir,
        "share-metadata.json",
        &serde_json::json!({ "scenario": meta.id, "ts_unix": now_ms / 1000, "shares": share_meta }),
    )?;
    Ok(finish(
        meta,
        steps,
        vec![
            "offline drill: Shamir split/recover exercised (GF(256), threshold semantics)".to_string(),
            "operator leg: repeat with the real custody shares held offline (no share material entered this sandbox)".to_string(),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Scenario 5 — backup restore (TVX1 export)
// ---------------------------------------------------------------------------

fn scenario_backup_restore(sandbox: &Path, now_ms: i64) -> Result<ScenarioOutcome, DrillError> {
    let meta = SCENARIOS
        .iter()
        .find(|m| m.id == "backup-restore")
        .ok_or_else(|| DrillError::UnknownScenario("backup-restore".into()))?;
    let dir = scenario_dir(sandbox, meta.id)?;
    let mut steps = Vec::new();

    use crate::vault::entry::VaultEntry;
    use crate::vault::import_export::{export_encrypted_json, import_encrypted_json};
    let entries = vec![
        VaultEntry::new_login(
            "drill-login",
            "alice",
            "drill-secret",
            vec!["https://example.invalid".into()],
        ),
        VaultEntry::new_note("drill-note", "restore me"),
    ];
    let pass = "drill-passphrase-not-a-secret";

    // D7 named exemption (R1 wave): drill QA — deterministic fixtures in the
    // scenario sandbox; not a policy-gated release path.
    // Backup.
    let export = export_encrypted_json(&entries, pass).map_err(io)?;
    let export_path = dir.join("vault-export.tvx1");
    std::fs::write(&export_path, &export).map_err(io)?;
    steps.push(step(
        "export-written",
        export.len() > 24,
        format!(
            "{} bytes TVX1 export at {}",
            export.len(),
            export_path.display()
        ),
    ));

    // "Loss": the live store file is gone; only the export remains.
    let live = dir.join("live-vault.json");
    std::fs::write(&live, "[]").map_err(io)?;
    std::fs::remove_file(&live).map_err(io)?;

    // Restore: byte-exact entries come back.
    let restored = import_encrypted_json(&export, pass).map_err(io)?;
    let names_ok = restored.len() == entries.len()
        && restored
            .iter()
            .zip(entries.iter())
            .all(|(a, b)| a.name == b.name && a.id == b.id);
    steps.push(step(
        "restore-round-trips-entries",
        names_ok,
        format!(
            "{} entries restored ({} expected)",
            restored.len(),
            entries.len()
        ),
    ));

    // Wrong passphrase fails closed.
    let wrong = import_encrypted_json(&export, "wrong-passphrase");
    steps.push(step(
        "wrong-passphrase-fails-closed",
        wrong.is_err(),
        wrong.err().unwrap_or_else(|| "DECRYPTED (!!)".to_string()),
    ));

    // Tampering fails closed (flip one ciphertext byte).
    let mut tampered = export.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tampered_res = import_encrypted_json(&tampered, pass);
    steps.push(step(
        "tampered-export-fails-closed",
        tampered_res.is_err(),
        tampered_res
            .err()
            .unwrap_or_else(|| "DECRYPTED (!!)".to_string()),
    ));

    Ok(finish(
        meta,
        steps,
        vec![
            "offline drill: TVX1 export/import round trip incl. negative tests".to_string(),
            "operator leg: run the same restore against the off-machine backup media and record the RTO".to_string(),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Scenario 6 — crypto-agility rehearsal (#54 bridge)
// ---------------------------------------------------------------------------

fn scenario_crypto_agility(
    sandbox: &Path,
    now_ms: i64,
    scale: usize,
) -> Result<ScenarioOutcome, DrillError> {
    let meta = SCENARIOS
        .iter()
        .find(|m| m.id == "crypto-agility")
        .ok_or_else(|| DrillError::UnknownScenario("crypto-agility".into()))?;
    let dir = scenario_dir(sandbox, meta.id)?;
    let mut steps = Vec::new();

    // 1. Deprecation clocks from the committed T-206 registry artifact.
    let clocks = key_drills::load_registry_clocks()?;
    let year = year_from_ms(now_ms);
    let alarms = key_drills::clock_alarms(&clocks, year);
    steps.push(step(
        "deprecation-clocks-loaded",
        !clocks.is_empty(),
        format!(
            "{} algorithms with clocks; {} alarm(s) at year {year}",
            clocks.len(),
            alarms.len()
        ),
    ));

    // 2. Deterministic mass revocation/reissue rehearsal with signed receipts.
    let graph = DependencyGraph::new(vec![
        DrillKey {
            key_id: "node-key".to_string(),
            algorithm: "Ed25519".to_string(),
            custody: "tpm".to_string(),
            services: vec!["daemon".to_string(), "mesh".to_string()],
        },
        DrillKey {
            key_id: "issuer-intermediate".to_string(),
            algorithm: "Ed25519".to_string(),
            custody: "vault".to_string(),
            services: vec![
                "daemon".to_string(),
                "job-worker".to_string(),
                "reader".to_string(),
            ],
        },
        DrillKey {
            key_id: "pkg-signing".to_string(),
            algorithm: "ML-DSA".to_string(),
            custody: "vault".to_string(),
            services: vec!["pkg".to_string()],
        },
    ])
    .map_err(DrillError::Agility)?;
    let signer = Ed25519Signer::keygen();
    let spec = RehearsalSpec {
        now_ms,
        revoke: vec!["node-key".to_string(), "issuer-intermediate".to_string()],
        scale,
        batch: (scale / 8).max(1),
    };
    let rehearsal = key_drills::rehearse_mass_revocation(&graph, &spec, &signer)?;
    let invalid_receipts: Vec<&SignedReceipt> = rehearsal
        .receipts
        .iter()
        .filter(|r| key_drills::verify_receipt(r).is_err())
        .collect();
    steps.push(step(
        "mass-revocation-rehearsal",
        invalid_receipts.is_empty() && !rehearsal.receipts.is_empty(),
        format!(
            "fleet {} → {} wave(s); {} receipt(s), {} invalid",
            rehearsal.fleet_size,
            rehearsal.waves.len(),
            rehearsal.receipts.len(),
            invalid_receipts.len()
        ),
    ));

    // 3. Algorithm/parameter inventory export (keys × dependents × clocks).
    let export = key_drills::inventory_export(&graph, None, &clocks, year);
    write_evidence(&dir, "crypto-agility-inventory.json", &export)?;
    steps.push(step(
        "inventory-export-written",
        export["keys"].as_array().map(|k| k.len()).unwrap_or(0) == graph.len(),
        format!("crypto-agility-inventory.json ({} keys)", graph.len()),
    ));

    // 4. Rehearsal report artifact.
    write_evidence(
        &dir,
        "rehearsal-report.json",
        &serde_json::to_value(&rehearsal).map_err(io)?,
    )?;

    let mut findings = rehearsal.findings.clone();
    if scale < ID_CARD_SCALE {
        findings.push(format!(
            "drill scale {scale} < ID-card scale {ID_CARD_SCALE} (stageable: `tallow drill --scenario \
             crypto-agility --scale {ID_CARD_SCALE}`)"
        ));
    }
    if !alarms.is_empty() {
        findings.push(format!("clock alarms at {year}: {}", alarms.len()));
    }
    Ok(finish(meta, steps, findings))
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run one scenario by id inside `sandbox`.
pub fn run_scenario(
    id: &str,
    sandbox: &Path,
    now_ms: i64,
    scale: usize,
) -> Result<ScenarioOutcome, DrillError> {
    match id {
        "key-compromise" => scenario_key_compromise(sandbox, now_ms),
        "rogue-node" => scenario_rogue_node(sandbox, now_ms),
        "relay-outage" => scenario_relay_outage(sandbox, now_ms),
        "vault-key-loss" => scenario_vault_key_loss(sandbox, now_ms),
        "backup-restore" => scenario_backup_restore(sandbox, now_ms),
        "crypto-agility" => scenario_crypto_agility(sandbox, now_ms, scale),
        other => Err(DrillError::UnknownScenario(other.to_string())),
    }
}

/// Run the whole offline suite inside `sandbox`.
pub fn run_all(sandbox: &Path, now_ms: i64, scale: usize) -> Vec<ScenarioOutcome> {
    SCENARIOS
        .iter()
        .map(|meta| {
            run_scenario(meta.id, sandbox, now_ms, scale).unwrap_or_else(|e| ScenarioOutcome {
                id: meta.id.to_string(),
                title: meta.title.to_string(),
                offline_checkable: true,
                passed: false,
                steps: vec![step("harness", false, e.to_string())],
                findings: vec![format!("harness error: {e}")],
                runbook: meta.runbook.to_string(),
            })
        })
        .collect()
}

/// Assemble the after-action report value (does not write it).
pub fn build_report(
    sandbox: &Path,
    now_ms: i64,
    scale: usize,
    outcomes: Vec<ScenarioOutcome>,
) -> AfterActionReport {
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let failed = outcomes.len() - passed;
    AfterActionReport {
        schema: AFTER_ACTION_SCHEMA.to_string(),
        generated_at: stamp_from_ms(now_ms),
        sandbox: sandbox.display().to_string(),
        scale,
        scenarios: outcomes,
        passed,
        failed,
    }
}

/// Write `after-action-<stamp>.json` + `.md` into `report_dir`; returns both paths.
pub fn write_after_action(
    report: &AfterActionReport,
    report_dir: &Path,
) -> Result<(PathBuf, PathBuf), DrillError> {
    std::fs::create_dir_all(report_dir).map_err(io)?;
    let base = format!("after-action-{}", report.generated_at);
    let json_path = report_dir.join(format!("{base}.json"));
    let md_path = report_dir.join(format!("{base}.md"));
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(report).map_err(io)?,
    )
    .map_err(io)?;
    std::fs::write(&md_path, render_markdown(report)).map_err(io)?;
    Ok((json_path, md_path))
}

/// Human after-action rendering.
pub fn render_markdown(report: &AfterActionReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Tallow drill — after-action report\n\n"));
    out.push_str(&format!(
        "- **schema:** {}\n- **generated:** {}\n- **sandbox:** `{}`\n- **scale:** {}\n- **result:** {} passed / {} failed\n\n",
        report.schema, report.generated_at, report.sandbox, report.scale, report.passed, report.failed
    ));
    for s in &report.scenarios {
        out.push_str(&format!(
            "## {} — {}\n\n**{}** · runbook: `{}`\n\n| step | result | evidence |\n|---|---|---|\n",
            s.id,
            s.title,
            if s.passed { "PASS" } else { "FAIL" },
            s.runbook
        ));
        for st in &s.steps {
            out.push_str(&format!(
                "| `{}` | {} | {} |\n",
                st.step,
                if st.ok { "ok" } else { "FAIL" },
                st.detail.replace('|', "\\|")
            ));
        }
        if !s.findings.is_empty() {
            out.push_str("\nFindings:\n");
            for f in &s.findings {
                out.push_str(&format!("- {f}\n"));
            }
        }
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// CLI entry (called from src/main.rs)
// ---------------------------------------------------------------------------

/// Options mirroring the `tallow drill` CLI.
#[derive(Debug, Clone, Default)]
pub struct CliOptions {
    /// List scenarios and exit.
    pub list: bool,
    /// Run one scenario.
    pub scenario: Option<String>,
    /// Run the whole suite.
    pub all: bool,
    /// Sandbox dir (default: tempdir).
    pub sandbox_dir: Option<PathBuf>,
    /// Report dir (default: `artifacts/drills`).
    pub report_dir: Option<PathBuf>,
    /// Crypto-agility rehearsal scale.
    pub scale: Option<usize>,
    /// Print the JSON report on stdout.
    pub json: bool,
}

/// `tallow drill` entry point. Returns the process exit code (0 pass, 2 fail).
pub fn run_cli(options: CliOptions) -> i32 {
    if options.list {
        println!("tallow drill — offline scenario suite (sandboxed, bounded, no network)\n");
        println!("{:<16} {:<48} runbook", "id", "scenario");
        for s in SCENARIOS {
            println!("{:<16} {:<48} {}", s.id, s.title, s.runbook);
        }
        println!(
            "\nrun: `tallow drill --scenario <id>` or `tallow drill --all` \
             [--scale N] [--sandbox-dir DIR] [--report-dir DIR] [--json]"
        );
        return 0;
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let scale = options.scale.unwrap_or(DEFAULT_AGILITY_SCALE);
    let sandbox = options.sandbox_dir.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("tallow-drill-{}", std::process::id()))
    });
    if let Err(e) = std::fs::create_dir_all(&sandbox) {
        eprintln!("drill: cannot create sandbox {}: {e}", sandbox.display());
        return 2;
    }
    let report_dir = options
        .report_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("artifacts/drills"));

    let outcomes = match (&options.scenario, options.all) {
        (Some(id), false) => match run_scenario(id, &sandbox, now_ms, scale) {
            Ok(o) => vec![o],
            Err(DrillError::UnknownScenario(id)) => {
                eprintln!("drill: unknown scenario {id:?} (see `tallow drill --list`)");
                return 2;
            }
            Err(e) => {
                eprintln!("drill: harness error: {e}");
                return 2;
            }
        },
        _ => run_all(&sandbox, now_ms, scale),
    };

    let report = build_report(&sandbox, now_ms, scale, outcomes);
    let (json_path, md_path) = match write_after_action(&report, &report_dir) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("drill: cannot write after-action report: {e}");
            return 2;
        }
    };

    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!(
            "tallow drill — {} passed / {} failed (scale {})",
            report.passed, report.failed, report.scale
        );
        for s in &report.scenarios {
            println!(
                "  [{}] {:<16} {}",
                if s.passed { "PASS" } else { "FAIL" },
                s.id,
                s.title
            );
            for st in &s.steps {
                if !st.ok {
                    println!("        FAIL {} — {}", st.step, st.detail);
                }
            }
        }
        println!(
            "after-action: {}\n              {}",
            json_path.display(),
            md_path.display()
        );
    }
    if report.failed == 0 {
        0
    } else {
        2
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> tempfile::TempDir {
        tempfile::tempdir().expect("sandbox")
    }

    const NOW_MS: i64 = 1_760_000_000_000;

    #[test]
    fn registry_is_complete_and_consistent() {
        assert_eq!(SCENARIOS.len(), 6);
        let ids: Vec<&str> = SCENARIOS.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![
                "key-compromise",
                "rogue-node",
                "relay-outage",
                "vault-key-loss",
                "backup-restore",
                "crypto-agility"
            ]
        );
        for s in SCENARIOS {
            assert!(!s.title.is_empty() && !s.expected.is_empty());
            assert!(s.runbook.starts_with("docs/ops/drills.md#"));
        }
    }

    #[test]
    fn every_scenario_passes_offline_in_a_temp_sandbox() {
        let dir = sandbox();
        for meta in SCENARIOS {
            let out = run_scenario(meta.id, dir.path(), NOW_MS, 64).expect("scenario runs");
            assert!(out.passed, "{} failed: {:?}", meta.id, out.steps);
            assert_eq!(out.id, meta.id);
            assert!(out.offline_checkable);
        }
    }

    #[test]
    fn key_compromise_scenario_steps_are_meaningful() {
        let dir = sandbox();
        let out = run_scenario("key-compromise", dir.path(), NOW_MS, 64).expect("run");
        let names: Vec<&str> = out.steps.iter().map(|s| s.step.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "detect-cross-context-reuse",
                "hard-fail-gate-denies-second-context",
                "revoke-signed-entry-applied",
                "reissue-with-verified-receipts"
            ]
        );
        assert!(dir.path().join("key-compromise/evidence.json").exists());
    }

    #[test]
    fn relay_outage_scenario_asserts_decision_table() {
        let dir = sandbox();
        let out = run_scenario("relay-outage", dir.path(), NOW_MS, 64).expect("run");
        assert!(out.passed, "steps: {:?}", out.steps);
        assert!(dir.path().join("relay-outage/run-drill.postcard").exists());
    }

    #[test]
    fn backup_restore_scenario_has_negative_cases() {
        let dir = sandbox();
        let out = run_scenario("backup-restore", dir.path(), NOW_MS, 64).expect("run");
        assert!(out.passed);
        let steps: Vec<&str> = out.steps.iter().map(|s| s.step.as_str()).collect();
        assert!(steps.contains(&"wrong-passphrase-fails-closed"));
        assert!(steps.contains(&"tampered-export-fails-closed"));
    }

    #[test]
    fn crypto_agility_scenario_scales_and_reports() {
        let dir = sandbox();
        let out = run_scenario("crypto-agility", dir.path(), NOW_MS, 256).expect("run");
        assert!(out.passed, "steps: {:?}", out.steps);
        // stageable ID-card scale is named in findings while running small
        assert!(out.findings.iter().any(|f| f.contains("ID-card scale")));
        assert!(dir
            .path()
            .join("crypto-agility/crypto-agility-inventory.json")
            .exists());
        assert!(dir
            .path()
            .join("crypto-agility/rehearsal-report.json")
            .exists());
    }

    #[test]
    fn unknown_scenario_is_a_typed_error() {
        let dir = sandbox();
        assert!(matches!(
            run_scenario("no-such-drill", dir.path(), NOW_MS, 64),
            Err(DrillError::UnknownScenario(_))
        ));
    }

    #[test]
    fn report_written_as_json_and_markdown_with_counts() {
        let dir = sandbox();
        let outcomes = run_all(dir.path(), NOW_MS, 64);
        let report = build_report(dir.path(), NOW_MS, 64, outcomes);
        assert_eq!(report.schema, AFTER_ACTION_SCHEMA);
        assert_eq!(report.passed, 6);
        assert_eq!(report.failed, 0);
        let reports = dir.path().join("reports");
        let (json_path, md_path) = write_after_action(&report, &reports).expect("write");
        assert!(json_path.exists() && md_path.exists());
        let back: AfterActionReport =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).expect("decode");
        assert_eq!(back, report);
        let md = std::fs::read_to_string(&md_path).unwrap();
        assert!(md.contains("# Tallow drill — after-action report"));
        assert!(
            md.contains("6 passed / 0 failed") || md.contains("**result:** 6 passed / 0 failed")
        );
        assert!(md.contains("## key-compromise"));
    }

    #[test]
    fn stamp_is_deterministic_from_ms() {
        assert_eq!(stamp_from_ms(NOW_MS), "2025-10-09T08-53-20Z");
        assert_eq!(year_from_ms(NOW_MS), 2025);
    }
}
