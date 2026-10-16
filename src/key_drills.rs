//! Crypto-agility drills (matrix #54 · agent-09 R-9 · ROCA playbook) — the
//! key-ledger drill leg (W3 batch-2 cluster C).
//!
//! Row acceptance: *"Crypto-agility drills in key_ledger: dependency queries,
//! mass revocation/reissue rehearsal, algorithm deprecation clocks (ROCA
//! playbook)"*; concept text adds *"algorithm/parameter inventory export,
//! 'what depends on this key' queries, rehearsal workflow for mass
//! revocation/reissue (ID-card-scale), signed migration receipts; deprecation
//! clock per algorithm (deadline from R-2)"*.
//!
//! This module consumes (never forks):
//! * [`crate::key_ledger`] — the live key-use source for dependency answers and
//!   the reuse/rotation gates (the "in key_ledger" home: drills operate on the
//!   ledger's recorded key uses rather than a parallel key store);
//! * `scripts/crypto-inventory.json` (T-206 registry, NIST IR 8547 dates) — the
//!   single deprecation-clock source ("deadline from R-2");
//! * `tallow_crypto::sig::ed25519` — the same signer/verifier family the SVID
//!   revocation lists use, so migration receipts verify with established code.
//!
//! Everything is deterministic and clock-free: callers pass `now_ms` / `year`.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * **Dependency graph** is declared, not inferred: keys carry the services
//!   that depend on them. `what_depends_on` answers from that declaration;
//!   the ledger join adds *observed* contexts. An unknown key is a typed
//!   error, never an empty answer.
//! * **Rehearsal fleet is synthetic and labeled as such.** `scale` expands the
//!   template graph into `scale` credential ids deterministically
//!   (`<key>#<seq>`); the report records `synthtic_fleet` facts rather than
//!   pretending the drill owned ID-card-scale real keys. Cap:
//!   [`MAX_REHEARSAL_SCALE`] (2 M) — beyond that the drill refuses.
//! * **Wave ordering** is deterministic: credentials are distributed
//!   round-robin over the sorted revoked-key list, then chunked into
//!   `batch`-sized waves in order. Identical specs ⇒ identical plans
//!   (digest-equal), which is what makes the receipts comparable run to run.
//! * **Receipts** sign the canonical JSON of the receipt (fixed field order);
//!   verification is on the exact bytes, so any mutating edit fails. A
//!   receipt is *evidence of a rehearsal*, not an authorization.
//! * **Clocks**: a `pqTransition` with `deprecate`/`disallow` years yields
//!   `Deprecated` at `year >= deprecate`, `Disallowed` at `year >= disallow`,
//!   and a one-year `DeprecationWarning` before `deprecate`. Algorithms
//!   without a transition (symmetric/hash primitives) are `NotApplicable` —
//!   absence of a date is not a date of today.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::key_ledger::KeyUseLedger;
use tallow_crypto::sig::ed25519::{self as ed25519_sig, Ed25519Signer};

/// Schema of a signed migration receipt.
pub const RECEIPT_SCHEMA: &str = "tallow.migration_receipt.v1";
/// Schema of the crypto-agility inventory export.
pub const INVENTORY_SCHEMA: &str = "tallow.crypto_agility_inventory/1";
/// Repo-relative path of the T-206 registry artifact (deprecation-clock source).
pub const INVENTORY_ARTIFACT: &str = "scripts/crypto-inventory.json";
/// Refusal ceiling for a rehearsal fleet (bounded memory; 2 M ids ≈ 100 MB).
pub const MAX_REHEARSAL_SCALE: usize = 2_000_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed drill failures — every refusal is explicit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DrillError {
    /// Two keys shared a `key_id`.
    #[error("duplicate key id {0:?} in dependency graph")]
    DuplicateKey(String),
    /// A key id was empty/blank.
    #[error("key id must be non-empty")]
    EmptyKeyId,
    /// The queried/revoked key is not in the graph.
    #[error("unknown key id {0:?}")]
    UnknownKey(String),
    /// A rehearsal spec named no keys to revoke.
    #[error("mass-revocation rehearsal needs at least one revoked key")]
    EmptyRevocations,
    /// `scale` outside `1..=`[`MAX_REHEARSAL_SCALE`].
    #[error("rehearsal scale {requested} out of range (1..={cap})")]
    BadScale {
        /// Requested fleet size.
        requested: usize,
        /// The cap ([`MAX_REHEARSAL_SCALE`]).
        cap: usize,
    },
    /// Batch size 0.
    #[error("rehearsal batch size must be >= 1")]
    BadBatch,
    /// The registry artifact was unreadable/unparseable/incomplete.
    #[error("crypto inventory: {0}")]
    Registry(String),
    /// Receipt encode/decode failure.
    #[error("receipt: {0}")]
    Receipt(String),
    /// Receipt signature failed verification (tampered or wrong signer).
    #[error("receipt signature invalid")]
    ReceiptSignatureInvalid,
}

// ---------------------------------------------------------------------------
// Dependency graph ("what depends on this key")
// ---------------------------------------------------------------------------

/// One declarable key: identity, algorithm, custody location, and the services
/// that depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillKey {
    /// Stable key id (as recorded in the key ledger).
    pub key_id: String,
    /// Registry algorithm name (joined against the deprecation clocks).
    pub algorithm: String,
    /// Custody location (`vault`, `tpm`, `file`, …) — free-form, recorded.
    pub custody: String,
    /// Services depending on this key.
    pub services: Vec<String>,
}

/// Declared dependency graph over keys and services.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyGraph {
    keys: BTreeMap<String, DrillKey>,
    by_service: BTreeMap<String, Vec<String>>,
}

impl DependencyGraph {
    /// Build a graph from declared keys (unique, non-empty ids; services
    /// de-duplicated and sorted per key).
    pub fn new(mut keys: Vec<DrillKey>) -> Result<Self, DrillError> {
        let mut map = BTreeMap::new();
        let mut by_service: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for k in &mut keys {
            if k.key_id.trim().is_empty() {
                return Err(DrillError::EmptyKeyId);
            }
            if map.contains_key(&k.key_id) {
                return Err(DrillError::DuplicateKey(k.key_id.clone()));
            }
            k.services.sort();
            k.services.dedup();
            for svc in &k.services {
                by_service
                    .entry(svc.clone())
                    .or_default()
                    .push(k.key_id.clone());
            }
            map.insert(k.key_id.clone(), k.clone());
        }
        for ids in by_service.values_mut() {
            ids.sort();
            ids.dedup();
        }
        Ok(Self {
            keys: map,
            by_service,
        })
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// One key by id.
    pub fn get(&self, key_id: &str) -> Option<&DrillKey> {
        self.keys.get(key_id)
    }

    /// Keys, ascending by id.
    pub fn keys(&self) -> impl Iterator<Item = &DrillKey> {
        self.keys.values()
    }

    /// Services, ascending.
    pub fn services(&self) -> impl Iterator<Item = &str> {
        self.by_service.keys().map(String::as_str)
    }

    /// **"What depends on this key"** — the services that declared a
    /// dependency on `key_id` (ascending). Unknown key ⇒ typed error.
    pub fn what_depends_on(&self, key_id: &str) -> Result<Vec<String>, DrillError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| DrillError::UnknownKey(key_id.to_string()))?;
        Ok(key.services.clone())
    }

    /// Which keys does `service` depend on (ascending; empty for unknown).
    pub fn service_dependencies(&self, service: &str) -> Vec<String> {
        self.by_service.get(service).cloned().unwrap_or_default()
    }

    /// Consistency findings: keys with no dependents; ledger-recorded keys the
    /// graph does not declare (a drill on an undeclared key is a blind spot).
    pub fn findings(&self, ledger: Option<&KeyUseLedger>) -> Vec<String> {
        let mut out = Vec::new();
        for k in self.keys.values() {
            if k.services.is_empty() {
                out.push(format!("key {:?} has no registered dependents", k.key_id));
            }
            if k.algorithm.trim().is_empty() {
                out.push(format!("key {:?} declares no algorithm", k.key_id));
            }
        }
        if let Some(ledger) = ledger {
            for key_id in self.keys.keys() {
                if ledger.uses_for(key_id).is_empty() {
                    out.push(format!(
                        "declared key {key_id:?} has no recorded uses in the ledger"
                    ));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Deprecation clocks (deadline from R-2 / T-206 registry)
// ---------------------------------------------------------------------------

/// One algorithm's deprecation clock, straight from the registry artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecationClock {
    /// Registry algorithm name.
    pub algorithm: String,
    /// Role (`kem`, `sig`, `aead`, …).
    pub role: String,
    /// Registry lifecycle state (`active`, …) — recorded, not interpreted.
    pub state: String,
    /// Quantum-resistance class.
    pub quantum_resistance: String,
    /// Year the algorithm is deprecated (NIST IR 8547 classes), when dated.
    pub deprecate_year: Option<i32>,
    /// Year the algorithm is disallowed, when dated.
    pub disallow_year: Option<i32>,
    /// Source string of the transition dates.
    pub source: Option<String>,
}

/// Clock status for one algorithm at one year.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockStatus {
    /// No transition dates (symmetric/hash primitives).
    NotApplicable,
    /// Beyond any near-term transition.
    Active,
    /// One year before `deprecate`.
    DeprecationWarning,
    /// At/after `deprecate`, before `disallow`.
    Deprecated,
    /// At/after `disallow`.
    Disallowed,
}

/// Resolution of the registry artifact path (repo root = crate manifest dir).
pub fn inventory_artifact_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(INVENTORY_ARTIFACT)
}

/// Load the deprecation clocks from the committed registry artifact.
pub fn load_registry_clocks() -> Result<Vec<DeprecationClock>, DrillError> {
    let path = inventory_artifact_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|e| DrillError::Registry(format!("cannot read {}: {e}", path.display())))?;
    parse_registry_clocks(&text)
}

/// Parse clocks from registry JSON text (tolerant of extra fields; strict on
/// the shape this module consumes).
pub fn parse_registry_clocks(json: &str) -> Result<Vec<DeprecationClock>, DrillError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| DrillError::Registry(format!("bad JSON: {e}")))?;
    let algorithms = value
        .get("algorithms")
        .and_then(|v| v.as_array())
        .ok_or_else(|| DrillError::Registry("missing `algorithms` array".to_string()))?;
    let mut out = Vec::with_capacity(algorithms.len());
    for a in algorithms {
        let name = a
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DrillError::Registry("algorithm without `name`".to_string()))?;
        let year_of = |field: &str| -> Option<i32> {
            a.get("pqTransition")
                .and_then(|t| t.get(field))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i32>().ok())
        };
        out.push(DeprecationClock {
            algorithm: name.to_string(),
            role: a
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            state: a
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            quantum_resistance: a
                .get("quantumResistance")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            deprecate_year: year_of("deprecate"),
            disallow_year: year_of("disallow"),
            source: a
                .get("pqTransition")
                .and_then(|t| t.get("source"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }
    out.sort_by(|a, b| a.algorithm.cmp(&b.algorithm));
    Ok(out)
}

/// Status of a clock at `year` (see module edge rules).
pub fn clock_status(clock: &DeprecationClock, year: i32) -> ClockStatus {
    match (clock.deprecate_year, clock.disallow_year) {
        (None, None) => ClockStatus::NotApplicable,
        (deprecate, disallow) => {
            if let Some(d) = disallow {
                if year >= d {
                    return ClockStatus::Disallowed;
                }
                if year == d.saturating_sub(1) && deprecate.is_none() {
                    return ClockStatus::DeprecationWarning;
                }
            }
            if let Some(p) = deprecate {
                if year >= p {
                    return ClockStatus::Deprecated;
                }
                if year == p.saturating_sub(1) {
                    return ClockStatus::DeprecationWarning;
                }
            }
            ClockStatus::Active
        }
    }
}

/// One clock alarm (status ≠ Active/NotApplicable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockAlarm {
    /// Algorithm name.
    pub algorithm: String,
    /// Status at `year`.
    pub status: ClockStatus,
    /// Evaluation year.
    pub year: i32,
    /// Deprecation year, when dated.
    pub deprecate_year: Option<i32>,
    /// Disallow year, when dated.
    pub disallow_year: Option<i32>,
    /// Message.
    pub message: String,
}

/// Alarms for all dated algorithms whose clock has started or rings.
pub fn clock_alarms(clocks: &[DeprecationClock], year: i32) -> Vec<ClockAlarm> {
    let mut out = Vec::new();
    for c in clocks {
        let status = clock_status(c, year);
        if matches!(status, ClockStatus::Active | ClockStatus::NotApplicable) {
            continue;
        }
        out.push(ClockAlarm {
            algorithm: c.algorithm.clone(),
            status,
            year,
            deprecate_year: c.deprecate_year,
            disallow_year: c.disallow_year,
            message: match status {
                ClockStatus::DeprecationWarning => format!(
                    "{} is one year from deprecation (deprecate {}, disallow {})",
                    c.algorithm,
                    c.deprecate_year.map_or("-".into(), |y| y.to_string()),
                    c.disallow_year.map_or("-".into(), |y| y.to_string()),
                ),
                ClockStatus::Deprecated => format!(
                    "{} is DEPRECATED as of {} (disallow {})",
                    c.algorithm,
                    c.deprecate_year.map_or("-".into(), |y| y.to_string()),
                    c.disallow_year.map_or("-".into(), |y| y.to_string()),
                ),
                ClockStatus::Disallowed => format!(
                    "{} is DISALLOWED as of {}",
                    c.algorithm,
                    c.disallow_year.map_or("-".into(), |y| y.to_string()),
                ),
                ClockStatus::Active | ClockStatus::NotApplicable => unreachable!(),
            },
        });
    }
    out.sort_by(|a, b| b.status.cmp(&a.status).then(a.algorithm.cmp(&b.algorithm)));
    out
}

// ---------------------------------------------------------------------------
// Migration receipts (signed)
// ---------------------------------------------------------------------------

/// One rehearsal/Migration wave receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    /// [`RECEIPT_SCHEMA`].
    pub schema: String,
    /// Batch identifier (deterministic from the plan).
    pub batch_id: String,
    /// When the rehearsal ran (caller-supplied ms).
    pub ts_ms: i64,
    /// Wave number (1-based).
    pub wave: u32,
    /// Credentials revoked in this wave.
    pub revoked_count: u64,
    /// Credentials reissued in this wave.
    pub reissued_count: u64,
    /// BLAKE3 (hex) of the wave's canonical plan text.
    pub plan_digest: String,
}

/// A signed receipt: canonical receipt bytes + Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// The receipt.
    pub receipt: MigrationReceipt,
    /// Signer public key (hex, 32 bytes).
    pub signer: String,
    /// Ed25519 signature over the canonical receipt bytes (hex, 64 bytes).
    pub sig: String,
}

/// Canonical bytes a receipt signature covers (fixed field order via serde).
pub fn canonical_receipt_bytes(receipt: &MigrationReceipt) -> Result<Vec<u8>, DrillError> {
    serde_json::to_vec(receipt).map_err(|e| DrillError::Receipt(e.to_string()))
}

/// Sign a receipt with a caller-owned Ed25519 signer.
pub fn sign_receipt(
    receipt: MigrationReceipt,
    signer: &Ed25519Signer,
) -> Result<SignedReceipt, DrillError> {
    let bytes = canonical_receipt_bytes(&receipt)?;
    let sig = signer.sign(&bytes);
    Ok(SignedReceipt {
        receipt,
        signer: hex_encode(&signer.verifying_key_bytes()),
        sig: hex_encode(&sig),
    })
}

/// Verify a signed receipt (signature over the exact receipt bytes).
pub fn verify_receipt(sr: &SignedReceipt) -> Result<(), DrillError> {
    let pk: [u8; 32] = hex_decode32(&sr.signer)
        .ok_or_else(|| DrillError::Receipt("signer key is not 32 hex bytes".to_string()))?;
    let sig_bytes = hex_decode(&sr.sig)
        .ok_or_else(|| DrillError::Receipt("signature is not hex".to_string()))?;
    let sig: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DrillError::Receipt(format!("signature is {} bytes, want 64", sig_bytes.len())))?;
    let bytes = canonical_receipt_bytes(&sr.receipt)?;
    ed25519_sig::verify(&pk, &bytes, &sig).map_err(|_| DrillError::ReceiptSignatureInvalid)
}

// ---------------------------------------------------------------------------
// Mass revocation / reissue rehearsal (ROCA playbook)
// ---------------------------------------------------------------------------

/// Rehearsal spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehearsalSpec {
    /// Caller-supplied clock (ms) stamped on receipts.
    pub now_ms: i64,
    /// Template keys being revoked (must exist in the graph).
    pub revoke: Vec<String>,
    /// Synthetic fleet size (credential population rehearsed).
    pub scale: usize,
    /// Wave batch size.
    pub batch: usize,
}

/// One wave of the rehearsal plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehearsalWave {
    /// 1-based wave number.
    pub wave: u32,
    /// Credentials revoked in this wave (count).
    pub revoked_count: u64,
    /// Credentials reissued in this wave (count).
    pub reissued_count: u64,
    /// Sample ids (first ≤3) for human inspection.
    pub sample: Vec<String>,
}

/// Rehearsal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehearsalReport {
    /// Schema tag.
    pub schema: String,
    /// Fleet size rehearsed.
    pub fleet_size: u64,
    /// Wave plan.
    pub waves: Vec<RehearsalWave>,
    /// Distinct dependents (services) touched, ascending.
    pub dependents_touched: Vec<String>,
    /// Findings (honest labels: synthetic fleet facts, empty-dependency keys).
    pub findings: Vec<String>,
    /// Signed per-wave receipts.
    pub receipts: Vec<SignedReceipt>,
}

/// Run a deterministic mass revocation/reissue rehearsal over a synthetic
/// fleet of `spec.scale` credentials derived from the revoked template keys.
pub fn rehearse_mass_revocation(
    graph: &DependencyGraph,
    spec: &RehearsalSpec,
    signer: &Ed25519Signer,
) -> Result<RehearsalReport, DrillError> {
    if spec.scale == 0 || spec.scale > MAX_REHEARSAL_SCALE {
        return Err(DrillError::BadScale {
            requested: spec.scale,
            cap: MAX_REHEARSAL_SCALE,
        });
    }
    if spec.batch == 0 {
        return Err(DrillError::BadBatch);
    }
    if spec.revoke.is_empty() {
        return Err(DrillError::EmptyRevocations);
    }
    let mut revoke = spec.revoke.clone();
    revoke.sort();
    revoke.dedup();
    for key_id in &revoke {
        if graph.get(key_id).is_none() {
            return Err(DrillError::UnknownKey(key_id.clone()));
        }
    }

    // Deterministic synthetic fleet: round-robin over revoked keys.
    let mut fleet: Vec<String> = Vec::with_capacity(spec.scale);
    for i in 0..spec.scale {
        let key = &revoke[i % revoke.len()];
        fleet.push(format!("{key}#{i:07}"));
    }

    let mut waves = Vec::new();
    let mut receipts = Vec::new();
    for (idx, chunk) in fleet.chunks(spec.batch).enumerate() {
        let wave_no = (idx + 1) as u32;
        let plan_text = chunk.join("\n");
        let digest = blake3::hash(plan_text.as_bytes()).to_hex().to_string();
        let sample: Vec<String> = chunk.iter().take(3).cloned().collect();
        waves.push(RehearsalWave {
            wave: wave_no,
            revoked_count: chunk.len() as u64,
            reissued_count: chunk.len() as u64,
            sample,
        });
        let receipt = MigrationReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            batch_id: format!("roca-drill-w{wave_no}-{}", &digest[..12]),
            ts_ms: spec.now_ms,
            wave: wave_no,
            revoked_count: chunk.len() as u64,
            reissued_count: chunk.len() as u64,
            plan_digest: digest,
        };
        receipts.push(sign_receipt(receipt, signer)?);
    }

    let mut dependents_touched: Vec<String> = revoke
        .iter()
        .flat_map(|k| graph.what_depends_on(k).unwrap_or_default())
        .collect();
    dependents_touched.sort();
    dependents_touched.dedup();

    let mut findings = vec![format!(
        "fleet is synthetic: {} credentials expanded from {} template key(s) (scale={})",
        spec.scale,
        revoke.len(),
        spec.scale
    )];
    for key_id in &revoke {
        let deps = graph.what_depends_on(key_id).unwrap_or_default();
        if deps.is_empty() {
            findings.push(format!("revoked key {key_id:?} has no registered dependents"));
        }
    }

    Ok(RehearsalReport {
        schema: "tallow.rehearsal_report.v1".to_string(),
        fleet_size: spec.scale as u64,
        waves,
        dependents_touched,
        findings,
        receipts,
    })
}

// ---------------------------------------------------------------------------
// Inventory export
// ---------------------------------------------------------------------------

/// Algorithm/parameter inventory export with dependency and clock joins.
pub fn inventory_export(
    graph: &DependencyGraph,
    ledger: Option<&KeyUseLedger>,
    clocks: &[DeprecationClock],
    year: i32,
) -> serde_json::Value {
    let keys: Vec<serde_json::Value> = graph
        .keys()
        .map(|k| {
            let contexts: Vec<String> = ledger
                .map(|l| {
                    let mut ctx: Vec<String> = l
                        .uses_for(&k.key_id)
                        .iter()
                        .map(|u| u.context.clone())
                        .collect();
                    ctx.sort();
                    ctx.dedup();
                    ctx
                })
                .unwrap_or_default();
            serde_json::json!({
                "key_id": k.key_id,
                "algorithm": k.algorithm,
                "custody": k.custody,
                "dependents": k.services,
                "dependent_count": k.services.len(),
                "ledger_contexts": contexts,
            })
        })
        .collect();
    let algorithms: Vec<serde_json::Value> = clocks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.algorithm,
                "role": c.role,
                "state": c.state,
                "quantum_resistance": c.quantum_resistance,
                "deprecate_year": c.deprecate_year,
                "disallow_year": c.disallow_year,
                "clock_status": clock_status(c, year),
            })
        })
        .collect();
    let mut warning = 0usize;
    let mut deprecated = 0usize;
    let mut disallowed = 0usize;
    for c in clocks {
        match clock_status(c, year) {
            ClockStatus::DeprecationWarning => warning += 1,
            ClockStatus::Deprecated => deprecated += 1,
            ClockStatus::Disallowed => disallowed += 1,
            ClockStatus::Active | ClockStatus::NotApplicable => {}
        }
    }
    serde_json::json!({
        "schema": INVENTORY_SCHEMA,
        "generated_for_year": year,
        "keys": keys,
        "algorithms": algorithms,
        "clock_counts": { "deprecation_warning": warning, "deprecated": deprecated, "disallowed": disallowed },
        "dependency_findings": graph.findings(ledger),
        "note": "deprecation clocks are read from the committed T-206 registry artifact \
                 (scripts/crypto-inventory.json); the registry is the single source of truth.",
    })
}

// ---------------------------------------------------------------------------
// Small hex helpers (no new deps)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_decode32(s: &str) -> Option<[u8; 32]> {
    let v = hex_decode(s)?;
    v.as_slice().try_into().ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, algo: &str, services: &[&str]) -> DrillKey {
        DrillKey {
            key_id: id.to_string(),
            algorithm: algo.to_string(),
            custody: "vault".to_string(),
            services: services.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn graph() -> DependencyGraph {
        DependencyGraph::new(vec![
            key("node-key", "Ed25519", &["daemon", "mesh"]),
            key("svc-key", "ML-DSA", &["pkg"]),
            key("lone-key", "RSA-2048", &[]),
        ])
        .expect("graph")
    }

    // --- dependency queries ------------------------------------------------

    #[test]
    fn dependency_queries_answer_and_refuse() {
        let g = graph();
        assert_eq!(g.len(), 3);
        assert_eq!(
            g.what_depends_on("node-key").unwrap(),
            vec!["daemon".to_string(), "mesh".to_string()]
        );
        assert!(g.what_depends_on("lone-key").unwrap().is_empty());
        assert_eq!(
            g.what_depends_on("missing"),
            Err(DrillError::UnknownKey("missing".to_string()))
        );
        // reverse query
        assert_eq!(g.service_dependencies("mesh"), vec!["node-key".to_string()]);
        assert!(g.service_dependencies("nobody").is_empty());
        // findings call out the undeclared-dependency key
        let findings = g.findings(None);
        assert!(findings.iter().any(|f| f.contains("lone-key")));
    }

    #[test]
    fn graph_rejects_bad_declarations() {
        assert_eq!(
            DependencyGraph::new(vec![key("k", "Ed25519", &[]), key("k", "ML-DSA", &[])]),
            Err(DrillError::DuplicateKey("k".to_string()))
        );
        assert_eq!(
            DependencyGraph::new(vec![key("  ", "Ed25519", &[])]),
            Err(DrillError::EmptyKeyId)
        );
    }

    // --- rehearsal ---------------------------------------------------------

    #[test]
    fn rehearsal_plans_deterministically_and_signs_verifiable_receipts() {
        let g = graph();
        let signer = Ed25519Signer::keygen();
        let spec = RehearsalSpec {
            now_ms: 1_760_000_000_000,
            revoke: vec!["node-key".to_string()],
            scale: 1000,
            batch: 256,
        };
        let r1 = rehearse_mass_revocation(&g, &spec, &signer).expect("rehearsal");
        let r2 = rehearse_mass_revocation(&g, &spec, &signer).expect("rehearsal");
        assert_eq!(r1.waves, r2.waves, "same spec ⇒ same plan");
        assert_eq!(r1.receipts, r2.receipts, "same spec ⇒ same receipts");
        assert_eq!(r1.fleet_size, 1000);
        assert_eq!(r1.waves.len(), 4, "1000 / 256 ⇒ 4 waves");
        assert!(r1.waves.iter().map(|w| w.revoked_count).sum::<u64>() == 1000);
        assert!(r1.waves.iter().map(|w| w.reissued_count).sum::<u64>() == 1000);
        assert_eq!(r1.dependents_touched, vec!["daemon", "mesh"]);
        assert!(r1.findings.iter().any(|f| f.contains("synthetic")));
        // every receipt verifies; wave-1 receipt is bound to its plan digest
        assert_eq!(r1.receipts.len(), 4);
        for sr in &r1.receipts {
            verify_receipt(sr).expect("receipt verifies");
            assert_eq!(sr.receipt.schema, RECEIPT_SCHEMA);
        }
        assert_eq!(r1.receipts[0].receipt.wave, 1);
        assert!(!r1.receipts[0].receipt.plan_digest.is_empty());
    }

    #[test]
    fn receipt_tampering_and_wrong_signers_are_refused() {
        let g = graph();
        let signer = Ed25519Signer::keygen();
        let spec = RehearsalSpec {
            now_ms: 1,
            revoke: vec!["svc-key".to_string()],
            scale: 4,
            batch: 2,
        };
        let report = rehearse_mass_revocation(&g, &spec, &signer).expect("rehearsal");
        let mut sr = report.receipts[0].clone();
        verify_receipt(&sr).expect("pristine verifies");
        // mutate the payload → signature must fail
        sr.receipt.revoked_count += 1;
        assert_eq!(verify_receipt(&sr), Err(DrillError::ReceiptSignatureInvalid));
        // right shape, wrong signer → must fail
        let other = Ed25519Signer::keygen();
        let mut sr2 = report.receipts[0].clone();
        sr2.signer = hex_encode(&other.verifying_key_bytes());
        assert_eq!(verify_receipt(&sr2), Err(DrillError::ReceiptSignatureInvalid));
        // malformed signer hex → typed receipt error, not a pass
        let mut sr3 = report.receipts[0].clone();
        sr3.signer = "zz".to_string();
        assert!(matches!(verify_receipt(&sr3), Err(DrillError::Receipt(_))));
    }

    #[test]
    fn rehearsal_refuses_bad_specs() {
        let g = graph();
        let signer = Ed25519Signer::keygen();
        let base = RehearsalSpec {
            now_ms: 0,
            revoke: vec!["node-key".to_string()],
            scale: 10,
            batch: 4,
        };
        assert_eq!(
            rehearse_mass_revocation(&g, &RehearsalSpec { scale: 0, ..base.clone() }, &signer),
            Err(DrillError::BadScale { requested: 0, cap: MAX_REHEARSAL_SCALE })
        );
        assert_eq!(
            rehearse_mass_revocation(
                &g,
                &RehearsalSpec { scale: MAX_REHEARSAL_SCALE + 1, ..base.clone() },
                &signer
            ),
            Err(DrillError::BadScale { requested: MAX_REHEARSAL_SCALE + 1, cap: MAX_REHEARSAL_SCALE })
        );
        assert_eq!(
            rehearse_mass_revocation(&g, &RehearsalSpec { batch: 0, ..base.clone() }, &signer),
            Err(DrillError::BadBatch)
        );
        assert_eq!(
            rehearse_mass_revocation(&g, &RehearsalSpec { revoke: vec![], ..base.clone() }, &signer),
            Err(DrillError::EmptyRevocations)
        );
        assert_eq!(
            rehearse_mass_revocation(
                &g,
                &RehearsalSpec { revoke: vec!["ghost".to_string()], ..base },
                &signer
            ),
            Err(DrillError::UnknownKey("ghost".to_string()))
        );
    }

    // --- deprecation clocks ------------------------------------------------

    #[test]
    fn clocks_load_from_the_committed_registry_artifact() {
        let clocks = load_registry_clocks().expect("registry artifact readable");
        assert!(clocks.len() >= 40, "T-206 registry has 44 entries, got {}", clocks.len());
        let ed = clocks.iter().find(|c| c.algorithm == "Ed25519").expect("Ed25519 registered");
        assert_eq!(ed.deprecate_year, Some(2030));
        assert_eq!(ed.disallow_year, Some(2035));
        assert_eq!(ed.source.as_deref(), Some("NIST IR 8547"));
        // symmetric primitives carry no transition dates
        let c = clocks.iter().find(|c| c.algorithm == "BLAKE3").expect("BLAKE3 registered");
        assert_eq!(clock_status(c, 2040), ClockStatus::NotApplicable);
    }

    #[test]
    fn clock_status_boundaries_and_alarms() {
        let c = DeprecationClock {
            algorithm: "Ed25519".to_string(),
            role: "sig".to_string(),
            state: "active".to_string(),
            quantum_resistance: "classical-vulnerable".to_string(),
            deprecate_year: Some(2030),
            disallow_year: Some(2035),
            source: Some("NIST IR 8547".to_string()),
        };
        assert_eq!(clock_status(&c, 2028), ClockStatus::Active);
        assert_eq!(clock_status(&c, 2029), ClockStatus::DeprecationWarning);
        assert_eq!(clock_status(&c, 2030), ClockStatus::Deprecated);
        assert_eq!(clock_status(&c, 2034), ClockStatus::Deprecated);
        assert_eq!(clock_status(&c, 2035), ClockStatus::Disallowed);
        assert_eq!(clock_status(&c, 2099), ClockStatus::Disallowed);
        // alarms only for ringing clocks, most severe first
        let clocks = vec![
            c.clone(),
            DeprecationClock {
                algorithm: "RSA-2048".to_string(),
                deprecate_year: Some(2030),
                disallow_year: Some(2035),
                ..c.clone()
            },
            DeprecationClock {
                algorithm: "BLAKE3".to_string(),
                deprecate_year: None,
                disallow_year: None,
                ..c
            },
        ];
        let alarms = clock_alarms(&clocks, 2035);
        assert_eq!(alarms.len(), 2);
        assert!(alarms.iter().all(|a| a.status == ClockStatus::Disallowed));
        assert!(clock_alarms(&clocks, 2028).is_empty());
        let warn = clock_alarms(&clocks, 2029);
        assert_eq!(warn.len(), 2);
        assert!(warn[0].message.contains("one year from deprecation"));
    }

    // --- inventory ---------------------------------------------------------

    #[test]
    fn inventory_export_joins_keys_ledger_and_clocks() {
        use crate::key_ledger::{KeyUse, KeyUseLedger};
        let g = graph();
        let mut ledger = KeyUseLedger::new();
        ledger
            .record_key_use(KeyUse {
                key_id: "node-key".to_string(),
                context: "svc-daemon".to_string(),
                ts_ms: 1_000,
                operation: "sign".to_string(),
                fingerprint: "fp".to_string(),
            })
            .unwrap();
        let clocks = parse_registry_clocks(
            r#"{"algorithms":[
                 {"name":"Ed25519","role":"sig","state":"active","quantumResistance":"classical-vulnerable",
                  "pqTransition":{"deprecate":"2030","disallow":"2035","source":"NIST IR 8547"}},
                 {"name":"BLAKE3","role":"hash","state":"active","quantumResistance":"symmetric-grover-halved","pqTransition":null}]}"#,
        )
        .expect("parse");
        let export = inventory_export(&g, Some(&ledger), &clocks, 2030);
        assert_eq!(export["schema"], INVENTORY_SCHEMA);
        let keys = export["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3);
        let node = keys.iter().find(|k| k["key_id"] == "node-key").unwrap();
        assert_eq!(node["dependent_count"], 2);
        assert_eq!(node["ledger_contexts"][0], "svc-daemon");
        let algos = export["algorithms"].as_array().unwrap();
        let ed = algos.iter().find(|a| a["name"] == "Ed25519").unwrap();
        assert_eq!(ed["clock_status"], "deprecated");
        assert_eq!(export["clock_counts"]["deprecated"], 1);
        assert_eq!(export["clock_counts"]["deprecation_warning"], 0);
        // findings surface the undeclared key + the unused declared keys
        let findings = export["dependency_findings"].as_array().unwrap();
        assert!(findings.iter().any(|f| f.as_str().unwrap().contains("lone-key")));
        assert!(findings
            .iter()
            .any(|f| f.as_str().unwrap().contains("no recorded uses")));
    }
}
