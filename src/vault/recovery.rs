//! Recovery architecture (row #114 · spec R-5.12) — dual-control custody
//! recovery + root-rotation ceremony, KT-logged, honest-unrecoverable.
//!
//! Design source: `phase5-identity/05-identity-architecture-draft.md` §5.7.6
//! ("recover access, never silently restore trust") and `impl/U-201.md` G-17
//! / `T-recovery`. The Shamir primitive itself lives in [`super::share`]
//! (GF(256), real polynomial sharing); **this** module is the custody policy
//! and ceremony layer the spec's anti-abuse rules require:
//!
//! * **(a) dual-control recovery.** A custody kit is a Shamir split with
//!   `threshold >= 2` and a [`CustodyPolicy`] that can never be weakened
//!   below **2 distinct custody shares from 2 distinct custodians**
//!   ([`MIN_DUAL_CONTROL_SHARES`]). Single-share recovery is refused for all
//!   inputs — a duplicate of one custodian's share is still one custodian; a
//!   share whose metadata was hand-edited does not change the quorum.
//! * **(b) root-rotation ceremony.** [`RootRotationCeremony`] is a four-step
//!   state machine (propose → approve ≥2 distinct operator keys → execute;
//!   abort anywhere before execute). The requester can never self-approve
//!   ("second factor, not person", U-201 G-17) and a retired root can never
//!   be re-anchored ([`RecoveryError::RestoreRefused`]) — the honest-
//!   unrecoverable rule: you re-enroll new material, you do not resurrect
//!   old trust.
//! * **(c) KT-logged.** Every recovery attempt (recovered **and** refused)
//!   and every ceremony step is appended to a [`KtLog`] (`src/kt_log.rs`)
//!   *before* the operation returns; if the append fails on the success path
//!   the recovered material is dropped and the call fails closed. Payloads
//!   carry digests only — never share material, never the recovered secret,
//!   never custodian names (only [`custodian_digest`] values). When an
//!   in-memory [`AuditLog`] (`merkle_audit`) is supplied, the same events are
//!   appended there.
//! * **(d) honest-unrecoverable.** [`assess`] answers "can this share set open
//!   the kit?" as a value ([`Recoverability`]) and [`recover_root`] returns a
//!   [`RecoveryDecision`] — `Recovered` or `Refused { reason }` — instead of
//!   pretending. Below quorum, a foreign split, a corrupted share, or a
//!   metadata edit are *refusals with named reasons*; there is no fallback
//!   path, no shadow key, no partial recovery, and no "best effort" mode.
//!
//! # What this module is NOT (honest limits — [target-only] where noted)
//!
//! * **SLIP-39 is not implemented** (row #114's third leg is blocked on an
//!   offline crate + wordlist dependency; recorded in the lane log, nothing
//!   fetched). This module is the Shamir custody path only.
//! * The KT log is **local audit-only** (`KT_LOG_ROLE`, `src/kt_log.rs`) — it
//!   is evidence, not a transparency service; the `merkle_audit` leg is
//!   in-memory unless the caller persists it.
//! * The 24 h post-recovery freeze is **recorded and KT-logged here**
//!   ([`POST_RECOVERY_FREEZE_SECS`], `freeze_until_ms` in
//!   [`RecoveryReport`]); enforcing it on identity-mutating operations is
//!   daemon-side work (gated on G-12) — [partial].
//! * Offline custody ("shares never on the node") is an operational rule:
//!   this module hands out [`CustodyShare`] values and keeps no copy of a
//!   split's shares in the manifest ([`CustodyManifest`] holds commitments
//!   only), but it cannot stop a caller from writing them to disk.
//!
//! # Trust shape
//!
//! The manifest's `root_commitment` is `BLAKE3` over the custody secret. It
//! lets a recovery *verify* that the reconstruction is the original secret
//! (wrong-split garbage and single-share "recovery" fail this check rather
//! than silently producing a different key). For a low-entropy custody secret
//! it also doubles as an offline verifier — the CLI path's secret is derived
//! from the vault password with a plain BLAKE3 (`src/main.rs`), which is
//! weaker than the vault's own Argon2id envelope; hardening that derivation
//! is a named §OPEN item in the lane log, out of the buildable legs.

use std::collections::HashSet;
use std::fmt;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::share::{self, KeyShare};
use crate::kt_log::{KtEntry, KtError, KtLog};
use crate::merkle_audit::AuditLog;

// ── Constants ──────────────────────────────────────────────────────────────

/// Custody scheme tag recorded in manifests and KT payloads.
pub const RECOVERY_SCHEME: &str = "shamir-gf256";
/// Manifest format version.
pub const CUSTODY_MANIFEST_VERSION: u32 = 1;
/// Hard floor for dual control: a custody kit below 2 shares / 2 distinct
/// custodians is refused at construction, and every manifest is re-checked
/// against this floor before use.
pub const MIN_DUAL_CONTROL_SHARES: u8 = 2;
/// Post-recovery freeze window (U-201 G-17: "24 h post-recovery freeze").
pub const POST_RECOVERY_FREEZE_SECS: u64 = 24 * 60 * 60;
/// KT payload `kind` for recovery events.
pub const RECOVERY_EVENT_KIND: &str = "tallow.recovery.v1";
/// KT payload `kind` for root-rotation events.
pub const ROOT_ROTATION_EVENT_KIND: &str = "tallow.root-rotation.v1";
/// Domain label for per-share commitments.
pub const CUSTODY_SHARE_DOMAIN: &str = "tallow-custody-share-v1";
/// Domain label for the root commitment.
pub const CUSTODY_ROOT_DOMAIN: &str = "tallow-custody-root-v1";
/// Domain label for custodian digests (names never leave the manifest).
pub const CUSTODIAN_DIGEST_DOMAIN: &str = "tallow-custodian-v1";
/// Domain label for the rotation approval transcript.
pub const ROOT_ROTATION_TRANSCRIPT_DOMAIN: &str = "tallow-root-rotation-v1|approve|";
/// Maximum accepted custodian label length.
pub const MAX_CUSTODIAN_LEN: usize = 128;
/// Maximum accepted rotation rationale length.
pub const MAX_REASON_LEN: usize = 512;

/// The honest-unrecoverable statement, verbatim, for operator-facing output.
pub const UNRECOVERABLE_DOCTRINE: &str = "Honest-unrecoverable: recovery restores access, never trust. \
Below quorum, foreign, or corrupted shares are refused as unrecoverable — there is no fallback path, \
no shadow key, no partial recovery, and no silent trust restoration. A lost quorum is a lost quorum: \
fresh material is issued (re-enroll), destroyed material is never resurrected, and a retired root is \
never re-anchored.";

// ── Hex helpers ────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, RecoveryError> {
    if s.len() % 2 != 0 {
        return Err(RecoveryError::InvalidInput(
            "hex string must have even length".into(),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| {
                RecoveryError::InvalidInput(format!("invalid hex at position {i}"))
            })
        })
        .collect()
}

fn digest_hex(domain: &str, bytes: &[u8]) -> String {
    let mut buf = Vec::with_capacity(domain.len() + bytes.len() + 1);
    buf.extend_from_slice(domain.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(bytes);
    blake3::hash(&buf).to_hex().to_string()
}

/// Digest of a custodian label — the only form of the label that leaves this
/// module (KT payloads, audit metadata). Stable across runs.
pub fn custodian_digest(custodian: &CustodianId) -> String {
    digest_hex(CUSTODIAN_DIGEST_DOMAIN, custodian.as_str().as_bytes())
}

fn random_hex(bytes: usize) -> String {
    let raw: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    hex_encode(&raw)
}

// ── Custodian + policy ─────────────────────────────────────────────────────

/// One custody holder's label (person, role, or offline device). Validated,
/// refused-not-normalized: surrounding whitespace is an error, not a trim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CustodianId(String);

impl CustodianId {
    /// Validate and wrap a custodian label.
    pub fn new(label: &str) -> Result<Self, RecoveryError> {
        if label.is_empty() {
            return Err(RecoveryError::InvalidInput(
                "custodian label must not be empty".into(),
            ));
        }
        if label.len() > MAX_CUSTODIAN_LEN {
            return Err(RecoveryError::InvalidInput(format!(
                "custodian label exceeds {MAX_CUSTODIAN_LEN} bytes"
            )));
        }
        if label.trim() != label {
            return Err(RecoveryError::InvalidInput(format!(
                "custodian label {label:?} has surrounding whitespace (refused, not normalized)"
            )));
        }
        if label.chars().any(|c| c.is_control()) {
            return Err(RecoveryError::InvalidInput(format!(
                "custodian label {label:?} contains control characters"
            )));
        }
        Ok(Self(label.to_string()))
    }

    /// The label as validated.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CustodianId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Dual-control policy for a custody kit. The constructor refuses anything
/// weaker than [`MIN_DUAL_CONTROL_SHARES`] on both axes — there is no way to
/// build a policy that permits single-share recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyPolicy {
    /// Minimum custody shares that must be presented (≥ 2).
    pub min_shares: u8,
    /// Minimum *distinct* custodians those shares must come from (≥ 2).
    pub min_distinct_custodians: u8,
}

impl CustodyPolicy {
    /// The default dual-control policy: 2 shares from 2 distinct custodians.
    pub fn dual_control() -> Self {
        Self {
            min_shares: MIN_DUAL_CONTROL_SHARES,
            min_distinct_custodians: MIN_DUAL_CONTROL_SHARES,
        }
    }

    /// Construct a policy; refuses any value below the dual-control floor.
    pub fn new(min_shares: u8, min_distinct_custodians: u8) -> Result<Self, RecoveryError> {
        let policy = Self {
            min_shares,
            min_distinct_custodians,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Re-check the floor (used again on deserialized manifests — a hand-
    /// edited JSON policy must not weaken a kit).
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.min_shares < MIN_DUAL_CONTROL_SHARES {
            return Err(RecoveryError::SingleShareRefused {
                detail: format!(
                    "policy min_shares={} is below the dual-control floor {MIN_DUAL_CONTROL_SHARES}",
                    self.min_shares
                ),
            });
        }
        if self.min_distinct_custodians < MIN_DUAL_CONTROL_SHARES {
            return Err(RecoveryError::SingleShareRefused {
                detail: format!(
                    "policy min_distinct_custodians={} is below the dual-control floor {MIN_DUAL_CONTROL_SHARES}",
                    self.min_distinct_custodians
                ),
            });
        }
        Ok(())
    }
}

impl Default for CustodyPolicy {
    fn default() -> Self {
        Self::dual_control()
    }
}

// ── Shares + manifest ──────────────────────────────────────────────────────

/// One custodian's custody share: the Shamir material plus the custody
/// metadata that binds it to a kit, a custodian, and an index. Integrity is
/// checked against [`CustodyShare::commitment`] before any reconstruction.
#[derive(Clone, Serialize, Deserialize)]
pub struct CustodyShare {
    /// Holder of this share.
    pub custodian: CustodianId,
    /// Kit this share belongs to (hex, random per split).
    pub split_id: String,
    /// `BLAKE3` commitment over (split_id, custodian, share fields) — the
    /// share is validated against this before use, so a corrupted or
    /// relabeled share is refused rather than merged into a reconstruction.
    pub commitment: String,
    /// The Shamir share itself (zeroize-on-drop, redacted `Debug`).
    pub share: KeyShare,
}

impl CustodyShare {
    /// Canonical commitment bytes for this share.
    fn commitment_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(CUSTODY_SHARE_DOMAIN.as_bytes());
        buf.push(b'|');
        for field in [
            self.split_id.as_str(),
            self.custodian.as_str(),
            self.share.data.as_str(),
        ] {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field.as_bytes());
        }
        buf.extend_from_slice(&[
            self.share.index,
            self.share.threshold,
            self.share.total_shares,
        ]);
        buf
    }

    /// Recompute the commitment and compare (constant-shape comparison; the
    /// values are hashes, not secrets).
    pub fn commitment_matches(&self) -> bool {
        digest_hex_raw(&self.commitment_bytes()) == self.commitment
    }

    /// Read-only access to the share index.
    pub fn index(&self) -> u8 {
        self.share.index
    }

    /// Digest of this share's custodian (the only label form that is logged).
    pub fn custodian_digest(&self) -> String {
        custodian_digest(&self.custodian)
    }
}

impl fmt::Debug for CustodyShare {
    /// Share material is redacted; [`KeyShare`]'s own `Debug` is applied.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodyShare")
            .field("custodian", &self.custodian)
            .field("split_id", &self.split_id)
            .field("commitment", &self.commitment)
            .field("share", &self.share)
            .finish()
    }
}

fn digest_hex_raw(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The custody manifest: everything an operator stores **on disk** about a
/// kit. It contains commitments only — no share material, no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyManifest {
    /// Format version ([`CUSTODY_MANIFEST_VERSION`]).
    pub version: u32,
    /// Scheme tag ([`RECOVERY_SCHEME`]).
    pub scheme: String,
    /// Random id tying shares to this kit.
    pub split_id: String,
    /// Reconstruction threshold (≥ 2).
    pub threshold: u8,
    /// Total shares issued.
    pub total: u8,
    /// Dual-control policy of record.
    pub policy: CustodyPolicy,
    /// `BLAKE3` commitment over the custody secret; recovery verifies the
    /// reconstruction against it and refuses on mismatch (no silent wrong key).
    pub root_commitment: String,
    /// Creation time (Unix ms).
    pub created_at_ms: u64,
    /// Custodian labels, one per share index (position `i` ⇔ share index `i+1`).
    pub custodians: Vec<CustodianId>,
    /// `BLAKE3` commitment per share, same order as [`Self::custodians`].
    pub share_commitments: Vec<String>,
}

impl CustodyManifest {
    /// Re-validate a manifest (also used on deserialized JSON): scheme,
    /// version, dual-control floor, threshold/roster agreement, distinct
    /// custodians, commitment arity.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.version != CUSTODY_MANIFEST_VERSION {
            return Err(RecoveryError::ManifestInvalid {
                detail: format!("unsupported manifest version {}", self.version),
            });
        }
        if self.scheme != RECOVERY_SCHEME {
            return Err(RecoveryError::ManifestInvalid {
                detail: format!("unsupported custody scheme {:?}", self.scheme),
            });
        }
        self.policy.validate()?;
        if self.threshold < MIN_DUAL_CONTROL_SHARES {
            return Err(RecoveryError::SingleShareRefused {
                detail: format!(
                    "manifest threshold {} is below the dual-control floor {MIN_DUAL_CONTROL_SHARES}",
                    self.threshold
                ),
            });
        }
        if self.threshold > self.total {
            return Err(RecoveryError::ManifestInvalid {
                detail: format!(
                    "manifest threshold {} exceeds total {}",
                    self.threshold, self.total
                ),
            });
        }
        if self.total < 2 {
            return Err(RecoveryError::ManifestInvalid {
                detail: format!("manifest total {} is below 2", self.total),
            });
        }
        if self.custodians.len() != self.total as usize {
            return Err(RecoveryError::ManifestInvalid {
                detail: format!(
                    "manifest lists {} custodians for {} shares",
                    self.custodians.len(),
                    self.total
                ),
            });
        }
        if self.share_commitments.len() != self.custodians.len() {
            return Err(RecoveryError::ManifestInvalid {
                detail: "manifest share commitment count does not match the custodian roster"
                    .into(),
            });
        }
        if self.split_id.is_empty() || self.root_commitment.is_empty() {
            return Err(RecoveryError::ManifestInvalid {
                detail: "manifest split_id/root_commitment must not be empty".into(),
            });
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for c in &self.custodians {
            if !seen.insert(c.as_str()) {
                return Err(RecoveryError::DuplicateCustodian {
                    custodian: c.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Effective share count needed: the split threshold, floored by policy.
    pub fn shares_required(&self) -> u8 {
        self.threshold.max(self.policy.min_shares)
    }

    /// Effective distinct-custodian count needed.
    pub fn distinct_custodians_required(&self) -> u8 {
        self.policy
            .min_distinct_custodians
            .max(MIN_DUAL_CONTROL_SHARES)
    }

    /// Commitment recorded for a given share index (1-based).
    pub fn commitment_for(&self, index: u8) -> Option<&str> {
        if index == 0 || index > self.total {
            return None;
        }
        self.share_commitments.get(index as usize - 1).map(|s| s.as_str())
    }

    /// Custodian recorded for a given share index (1-based).
    pub fn custodian_for(&self, index: u8) -> Option<&CustodianId> {
        if index == 0 || index > self.total {
            return None;
        }
        self.custodians.get(index as usize - 1)
    }
}

/// Split a custody secret into a dual-control kit.
///
/// Returns the [`CustodyManifest`] (commitments only — safe to store) and one
/// [`CustodyShare`] per custodian, in roster order. Refuses, before any
/// splitting: an empty secret, fewer than 2 custodians, duplicate custodians,
/// `threshold < max(2, policy.min_shares)`, `threshold > total`, and any
/// policy below the dual-control floor. There is **no** code path that
/// produces a 1-of-n kit.
pub fn create_custody_kit(
    secret: &[u8],
    policy: CustodyPolicy,
    threshold: u8,
    custodians: &[CustodianId],
    created_at_ms: u64,
) -> Result<(CustodyManifest, Vec<CustodyShare>), RecoveryError> {
    policy.validate()?;
    if secret.is_empty() {
        return Err(RecoveryError::InvalidInput(
            "custody secret must not be empty".into(),
        ));
    }
    let total = u8::try_from(custodians.len()).map_err(|_| RecoveryError::InvalidInput(
        "too many custodians (max 255)".into(),
    ))?;
    if total < MIN_DUAL_CONTROL_SHARES {
        return Err(RecoveryError::SingleShareRefused {
            detail: format!("custody requires at least {MIN_DUAL_CONTROL_SHARES} custodians, got {total}"),
        });
    }
    if threshold < MIN_DUAL_CONTROL_SHARES {
        return Err(RecoveryError::SingleShareRefused {
            detail: format!(
                "threshold {threshold} is below the dual-control floor {MIN_DUAL_CONTROL_SHARES}"
            ),
        });
    }
    if threshold < policy.min_shares {
        return Err(RecoveryError::PolicyViolation {
            detail: format!(
                "threshold {threshold} is below policy min_shares {}",
                policy.min_shares
            ),
        });
    }
    if threshold > total {
        return Err(RecoveryError::InvalidInput(format!(
            "threshold {threshold} exceeds total shares {total}"
        )));
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for c in custodians {
        if !seen.insert(c.as_str()) {
            return Err(RecoveryError::DuplicateCustodian {
                custodian: c.to_string(),
            });
        }
    }

    let split_id = random_hex(16);
    let key_shares = share::split_master_key(secret, threshold, total)
        .map_err(RecoveryError::Primitive)?;

    let mut shares = Vec::with_capacity(key_shares.len());
    for (i, ks) in key_shares.into_iter().enumerate() {
        if i >= custodians.len() {
            // Defensive: split_master_key returns exactly `total` shares.
            return Err(RecoveryError::Primitive(
                "split produced more shares than custodians".into(),
            ));
        }
        let mut share = CustodyShare {
            custodian: custodians[i].clone(),
            split_id: split_id.clone(),
            commitment: String::new(),
            share: ks,
        };
        share.commitment = digest_hex_raw(&share.commitment_bytes());
        shares.push(share);
    }

    let manifest = CustodyManifest {
        version: CUSTODY_MANIFEST_VERSION,
        scheme: RECOVERY_SCHEME.to_string(),
        split_id,
        threshold,
        total,
        policy,
        root_commitment: digest_hex(CUSTODY_ROOT_DOMAIN, secret),
        created_at_ms,
        custodians: custodians.to_vec(),
        share_commitments: shares.iter().map(|s| s.commitment.clone()).collect(),
    };
    manifest.validate()?;
    Ok((manifest, shares))
}

// ── Honest recoverability assessment ───────────────────────────────────────

/// Payload for a `custody-kit-created` event. Shared by [`log_kit_created`]
/// and tests so the KT `payload_hash` can be re-bound externally: the KT log
/// persists **chain entries only** — the payload is caller-held evidence.
pub fn kit_created_payload(manifest: &CustodyManifest, now_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "kind": RECOVERY_EVENT_KIND,
        "action": "custody-kit-created",
        "scheme": manifest.scheme,
        "split_id": manifest.split_id,
        "threshold": manifest.threshold,
        "total": manifest.total,
        "policy": {
            "min_shares": manifest.policy.min_shares,
            "min_distinct_custodians": manifest.policy.min_distinct_custodians,
        },
        "custodians": manifest
            .custodians
            .iter()
            .enumerate()
            .map(|(i, c)| serde_json::json!({
                "custodian_digest": custodian_digest(c),
                "index": (i + 1) as u8,
            }))
            .collect::<Vec<_>>(),
        "share_commitments": manifest.share_commitments,
        "root_commitment": manifest.root_commitment,
        "at_ms": now_ms,
    })
}

/// KT-log the creation of a custody kit: the manifest's commitments (never
/// share material, never custodian names — digests only). Returns the
/// [`KtEvent`] receipt — the caller-held evidence the log commits to. Callers
/// should log creation so the audit trail starts before any recovery attempt
/// exists.
pub fn log_kit_created(
    manifest: &CustodyManifest,
    kt: &mut KtLog,
    now_ms: u64,
) -> Result<KtEvent, RecoveryError> {
    manifest.validate()?;
    let payload = kit_created_payload(manifest, now_ms);
    let entry = kt.append_json(&payload)?;
    Ok(kt_event(entry, payload))
}

/// Why a share set cannot open a kit. Every variant is a refusal with a
/// named reason — there is no "try anyway" mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnrecoverableReason {
    /// Nothing presented.
    NoShares,
    /// Fewer shares than the effective threshold.
    InsufficientShares {
        /// Shares actually presented.
        have: usize,
        /// Shares required (`max(threshold, policy.min_shares)`).
        need: u8,
    },
    /// Threshold met in count, but not from enough distinct custodians
    /// (the same custodian's share, however duplicated, is one custodian).
    InsufficientDistinctCustodians {
        /// Distinct custodians actually represented.
        have: usize,
        /// Distinct custodians required.
        need: u8,
    },
    /// The same share index was presented more than once.
    DuplicateShareIndex {
        /// The repeated index.
        index: u8,
    },
    /// A share's custodian label disagrees with the manifest roster for its
    /// index, or a custodian appears twice under different indices.
    RosterMismatch {
        /// Presentation position (0-based).
        at: usize,
    },
    /// A share's `threshold`/`total_shares` fields disagree with the manifest.
    ShareMetadataMismatch {
        /// Presentation position (0-based).
        at: usize,
    },
    /// A share belongs to a different kit.
    SplitMismatch {
        /// Presentation position (0-based).
        at: usize,
    },
    /// The share failed its commitment check (corrupted or tampered).
    ShareIntegrityFailure {
        /// Presentation position (0-based).
        at: usize,
    },
}

impl fmt::Display for UnrecoverableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoShares => write!(f, "no shares presented"),
            Self::InsufficientShares { have, need } => {
                write!(f, "insufficient shares: {have} of {need}")
            }
            Self::InsufficientDistinctCustodians { have, need } => write!(
                f,
                "insufficient distinct custodians: {have} of {need} (dual control)"
            ),
            Self::DuplicateShareIndex { index } => {
                write!(f, "duplicate share index {index}")
            }
            Self::RosterMismatch { at } => {
                write!(f, "custodian roster mismatch at position {at}")
            }
            Self::ShareMetadataMismatch { at } => {
                write!(f, "share metadata mismatch at position {at}")
            }
            Self::SplitMismatch { at } => {
                write!(f, "share from a different kit at position {at}")
            }
            Self::ShareIntegrityFailure { at } => {
                write!(f, "share commitment failed at position {at}")
            }
        }
    }
}

/// The honest verdict for a presented share set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recoverability {
    /// The set satisfies every dual-control rule (subject to reconstruction
    /// verifying against the manifest's root commitment).
    Recoverable {
        /// Shares presented.
        shares_present: usize,
        /// Effective threshold they must meet.
        threshold: u8,
    },
    /// The set cannot open the kit; the reason is the honest answer.
    Unrecoverable {
        /// Why.
        reason: UnrecoverableReason,
    },
}

impl Recoverability {
    /// True only for [`Self::Recoverable`].
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::Recoverable { .. })
    }
}

/// Assessment core shared by [`assess`] and [`recover_root`]. Returns the
/// number of usable shares when the set is admissible.
fn evaluate_set(
    manifest: &CustodyManifest,
    provided: &[CustodyShare],
) -> (Result<usize, UnrecoverableReason>, Vec<(String, u8)>) {
    let mut index_seen: HashSet<u8> = HashSet::new();
    let mut custodian_seen: HashSet<&str> = HashSet::new();
    let mut described: Vec<(String, u8)> = Vec::new();

    if provided.is_empty() {
        return (Err(UnrecoverableReason::NoShares), described);
    }

    for (at, s) in provided.iter().enumerate() {
        // Kit binding first: a share from another split is not part of this set.
        if s.split_id != manifest.split_id {
            return (Err(UnrecoverableReason::SplitMismatch { at }), described);
        }
        // Metadata must agree with the manifest (no hand-edited thresholds).
        if s.share.threshold != manifest.threshold || s.share.total_shares != manifest.total {
            return (
                Err(UnrecoverableReason::ShareMetadataMismatch { at }),
                described,
            );
        }
        // The custodian must match the roster entry for this index.
        match manifest.custodian_for(s.share.index) {
            Some(expected) if expected == &s.custodian => {}
            _ => return (Err(UnrecoverableReason::RosterMismatch { at }), described),
        }
        if !index_seen.insert(s.share.index) {
            return (
                Err(UnrecoverableReason::DuplicateShareIndex { index: s.share.index }),
                described,
            );
        }
        if !custodian_seen.insert(s.custodian.as_str()) {
            return (Err(UnrecoverableReason::RosterMismatch { at }), described);
        }
        // Integrity last: it is the only check that needs the commitment.
        if !s.commitment_matches() {
            return (
                Err(UnrecoverableReason::ShareIntegrityFailure { at }),
                described,
            );
        }
        described.push((s.custodian_digest(), s.share.index));
    }

    let need = manifest.shares_required();
    if (provided.len() as u8) < need {
        return (
            Err(UnrecoverableReason::InsufficientShares {
                have: provided.len(),
                need,
            }),
            described,
        );
    }
    let distinct = custodian_seen.len() as u8;
    let need_distinct = manifest.distinct_custodians_required();
    if distinct < need_distinct {
        return (
            Err(UnrecoverableReason::InsufficientDistinctCustodians {
                have: distinct as usize,
                need: need_distinct,
            }),
            described,
        );
    }
    (Ok(provided.len()), described)
}

/// Answer "can this share set open the kit?" without touching secrets.
///
/// Fails closed: the whole presented set is judged as one attempt — a single
/// bad share refuses the attempt (quarantine it and retry deliberately; there
/// is no partial-credit path).
pub fn assess(
    manifest: &CustodyManifest,
    provided: &[CustodyShare],
) -> Result<Recoverability, RecoveryError> {
    manifest.validate()?;
    match evaluate_set(manifest, provided) {
        (Ok(n), _) => Ok(Recoverability::Recoverable {
            shares_present: n,
            threshold: manifest.shares_required(),
        }),
        (Err(reason), _) => Ok(Recoverability::Unrecoverable { reason }),
    }
}

// ── Recovery ───────────────────────────────────────────────────────────────

/// The recovered custody secret. Redacted `Debug`, zeroize-on-drop; read it
/// via [`Self::expose`] and nothing else.
pub struct RecoveredRoot {
    secret: Zeroizing<Vec<u8>>,
    report: RecoveryReport,
}

impl RecoveredRoot {
    /// The recovered secret bytes (the only read path).
    pub fn expose(&self) -> &[u8] {
        &self.secret
    }

    /// Metadata of the recovery (no secret).
    pub fn report(&self) -> &RecoveryReport {
        &self.report
    }
}

impl fmt::Debug for RecoveredRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredRoot")
            .field("secret", &"[redacted]")
            .field("report", &self.report)
            .finish()
    }
}

/// Metadata of a completed recovery. Contains digests, never material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Kit that was opened.
    pub split_id: String,
    /// Scheme tag.
    pub scheme: String,
    /// Effective share count used.
    pub shares_used: usize,
    /// Effective threshold at the time of recovery.
    pub threshold: u8,
    /// Distinct custodians represented (digest, index) — sorted by index.
    pub custodians: Vec<CustodianDigestIndex>,
    /// Manifest root commitment (re-verified).
    pub root_commitment: String,
    /// Recovery time (Unix ms).
    pub recovered_at_ms: u64,
    /// Freeze window end ([`POST_RECOVERY_FREEZE_SECS`]) — enforcement is
    /// daemon-side (U-201 G-17); recorded and KT-logged here.
    pub freeze_until_ms: u64,
    /// KT entry sequence of the `recovered` event.
    pub kt: KtEvent,
}

/// A custodian digest paired with the share index it presented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodianDigestIndex {
    /// [`custodian_digest`] of the holder.
    pub custodian_digest: String,
    /// Share index presented.
    pub index: u8,
}

/// A logged KT event as the caller should retain it.
///
/// [`KtLog`] stores the chain record and commits to the event payload by
/// hash; the payload itself is **caller-held evidence** (module docs,
/// `src/kt_log.rs`). This receipt carries both, so the caller keeps the
/// evidence the log commits to, and [`KtEvent::verify_against`] proves the
/// payload is exactly what the chain entry binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtEvent {
    /// KT entry sequence.
    pub seq: u64,
    /// `payload_hash` of the chain entry (binds [`Self::payload`]).
    pub payload_hash: String,
    /// The event payload (digests only — never material, never labels).
    pub payload: serde_json::Value,
}

impl KtEvent {
    /// Verify this receipt against the log entry it claims to be: the
    /// sequence and payload hash must match, and the payload must re-hash to
    /// the committed `payload_hash`.
    pub fn verify_against(&self, entry: &KtEntry) -> bool {
        entry.seq == self.seq
            && entry.payload_hash == self.payload_hash
            && crate::kt_log::payload_hash(&serde_json::to_vec(&self.payload).unwrap_or_default())
                == self.payload_hash
    }
}

/// Build a [`KtEvent`] receipt from a just-appended log entry and its payload.
fn kt_event(entry: &KtEntry, payload: serde_json::Value) -> KtEvent {
    KtEvent {
        seq: entry.seq,
        payload_hash: entry.payload_hash.clone(),
        payload,
    }
}

/// Outcome of a recovery attempt — a decision, not an error.
#[derive(Debug)]
pub enum RecoveryDecision {
    /// The kit was opened; the decision's payload carries the material.
    Recovered(RecoveredRoot),
    /// The attempt was refused; the reason is honest and KT-logged.
    Refused {
        /// Why the attempt could not proceed.
        reason: UnrecoverableReason,
        /// The logged `refused` event (caller-held evidence).
        kt: KtEvent,
    },
}

/// Payload for a **refused** recovery attempt. Shared by [`recover_root`] and
/// tests so the committed `payload_hash` can be re-bound externally (the KT
/// log stores chain entries only; the payload is caller-held evidence).
pub fn recovery_refusal_payload(
    manifest: &CustodyManifest,
    described: &[(String, u8)],
    reason: &str,
    now_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "kind": RECOVERY_EVENT_KIND,
        "action": "share-set-recovery",
        "scheme": RECOVERY_SCHEME,
        "split_id": manifest.split_id,
        "threshold": manifest.shares_required(),
        "total": manifest.total,
        "policy": {
            "min_shares": manifest.policy.min_shares,
            "min_distinct_custodians": manifest.policy.min_distinct_custodians,
        },
        "presented": described
            .iter()
            .map(|(digest, index)| serde_json::json!({
                "custodian_digest": digest,
                "index": index,
            }))
            .collect::<Vec<_>>(),
        "outcome": "refused",
        "reason": reason,
        "at_ms": now_ms,
    })
}

/// Payload for a **recovered** event (digests only, never material).
pub fn recovery_recovered_payload(
    manifest: &CustodyManifest,
    custodians: &[CustodianDigestIndex],
    now_ms: u64,
    freeze_until_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "kind": RECOVERY_EVENT_KIND,
        "action": "share-set-recovery",
        "scheme": RECOVERY_SCHEME,
        "split_id": manifest.split_id,
        "threshold": manifest.shares_required(),
        "total": manifest.total,
        "policy": {
            "min_shares": manifest.policy.min_shares,
            "min_distinct_custodians": manifest.policy.min_distinct_custodians,
        },
        "presented": custodians,
        "outcome": "recovered",
        "at_ms": now_ms,
        "freeze_until_ms": freeze_until_ms,
    })
}

/// Attempt a dual-control custody recovery.
///
/// Order of operations: assess (fail closed) → reconstruct → verify against
/// the manifest's root commitment → **append the KT event** → only then
/// return the material. If the KT append fails on the success path, the
/// reconstructed secret is dropped and the call returns
/// [`RecoveryError::Kt`] — an unrecorded recovery did not happen.
/// Refusals are KT-logged too (best-effort ordering: the refusal is returned
/// only after its log append; a failing log turns the refusal into
/// [`RecoveryError::Kt`], because an unrecordable refusal breaks the audit
/// trail this architecture exists to provide).
pub fn recover_root(
    manifest: &CustodyManifest,
    provided: &[CustodyShare],
    kt: &mut KtLog,
    mut audit: Option<&mut AuditLog>,
    now_ms: u64,
) -> Result<RecoveryDecision, RecoveryError> {
    manifest.validate()?;
    let (verdict, described) = evaluate_set(manifest, provided);

    let reason = match verdict {
        Ok(_) => None,
        Err(reason) => Some(reason),
    };

    // Refusal path: log the refusal, then answer with it.
    if let Some(reason) = reason {
        let payload = recovery_refusal_payload(manifest, &described, &reason.to_string(), now_ms);
        let entry = kt.append_json(&payload)?;
        push_audit(audit.as_deref_mut(), "share-set-recovery", &payload);
        return Ok(RecoveryDecision::Refused {
            reason,
            kt: kt_event(entry, payload),
        });
    }

    // Admissible set: reconstruct the secret.
    let mut usable: Vec<&CustodyShare> = provided.iter().collect();
    usable.sort_by_key(|s| s.share.index);
    let key_shares: Vec<KeyShare> = usable.iter().map(|s| s.share.clone()).collect();
    let recovered = share::recover_master_key(&key_shares).map_err(RecoveryError::Primitive)?;

    // Verify the reconstruction against the manifest before anything else.
    if digest_hex(CUSTODY_ROOT_DOMAIN, &recovered) != manifest.root_commitment {
        let payload =
            recovery_refusal_payload(manifest, &described, "root-commitment-mismatch", now_ms);
        let entry = kt.append_json(&payload)?;
        push_audit(audit.as_deref_mut(), "share-set-recovery", &payload);
        return Err(RecoveryError::RootCommitmentMismatch {
            kt: kt_event(entry, payload),
        });
    }

    let custodians: Vec<CustodianDigestIndex> = usable
        .iter()
        .map(|s| CustodianDigestIndex {
            custodian_digest: s.custodian_digest(),
            index: s.share.index,
        })
        .collect();
    let freeze_until_ms = now_ms.saturating_add(POST_RECOVERY_FREEZE_SECS.saturating_mul(1000));

    let payload = recovery_recovered_payload(manifest, &custodians, now_ms, freeze_until_ms);
    let entry = kt.append_json(&payload)?; // fail closed: no log ⇒ no material
    push_audit(audit.as_deref_mut(), "share-set-recovery", &payload);
    let receipt = kt_event(entry, payload);

    let report = RecoveryReport {
        split_id: manifest.split_id.clone(),
        scheme: RECOVERY_SCHEME.to_string(),
        shares_used: usable.len(),
        threshold: manifest.shares_required(),
        custodians,
        root_commitment: manifest.root_commitment.clone(),
        recovered_at_ms: now_ms,
        freeze_until_ms,
        kt: receipt,
    };
    Ok(RecoveryDecision::Recovered(RecoveredRoot {
        secret: Zeroizing::new(recovered),
        report,
    }))
}

fn push_audit(audit: Option<&mut AuditLog>, action: &str, payload: &serde_json::Value) {
    if let Some(log) = audit {
        log.append("vault::recovery", action, payload.clone());
    }
}

// ── Root-rotation ceremony ─────────────────────────────────────────────────

/// Approval policy for a root rotation. The constructor refuses anything
/// below 2 distinct approval keys — dual control is enforced at construction,
/// exactly like [`CustodyPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRotationPolicy {
    /// Number of distinct operator keys that must approve (≥ 2).
    pub min_approvals: u8,
}

impl RootRotationPolicy {
    /// The dual-control default: 2 approvals.
    pub fn dual_control() -> Self {
        Self {
            min_approvals: MIN_DUAL_CONTROL_SHARES,
        }
    }

    /// Construct; refuses a weak policy.
    pub fn new(min_approvals: u8) -> Result<Self, RecoveryError> {
        let p = Self { min_approvals };
        p.validate()?;
        Ok(p)
    }

    /// Re-check the floor (also used on deserialized proposals).
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.min_approvals < MIN_DUAL_CONTROL_SHARES {
            return Err(RecoveryError::SingleShareRefused {
                detail: format!(
                    "rotation min_approvals={} is below the dual-control floor {MIN_DUAL_CONTROL_SHARES}",
                    self.min_approvals
                ),
            });
        }
        Ok(())
    }
}

impl Default for RootRotationPolicy {
    fn default() -> Self {
        Self::dual_control()
    }
}

/// A root-rotation proposal: retire `old_root`, re-anchor members on
/// `new_root` for epoch `[epoch_from, epoch_to)`. Identity fields are hex
/// Ed25519 public keys (serializable without an ed25519 serde feature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRotationProposal {
    /// Random ceremony id (hex); approvals are bound to it.
    pub proposal_id: String,
    /// Root being retired (hex Ed25519 public key).
    pub old_root: String,
    /// Root being anchored (hex Ed25519 public key).
    pub new_root: String,
    /// First epoch under the new root.
    pub epoch_from: u64,
    /// First epoch *after* the new root's validity (exclusive).
    pub epoch_to: u64,
    /// Operator key requesting the rotation (hex). Can never approve its own
    /// proposal.
    pub requested_by: String,
    /// Approval policy of record.
    pub policy: RootRotationPolicy,
    /// Operator-visible re-anchoring rationale (required, non-empty).
    pub reason: String,
    /// Proposal time (Unix ms).
    pub created_at_ms: u64,
}

impl RootRotationProposal {
    /// Build a proposal; refuses weak policy, an inverted/empty epoch range,
    /// a no-op rotation (new == old), and a missing rationale.
    pub fn new(
        old_root: &VerifyingKey,
        new_root: &VerifyingKey,
        requested_by: &VerifyingKey,
        epoch_from: u64,
        epoch_to: u64,
        reason: &str,
        policy: RootRotationPolicy,
        now_ms: u64,
    ) -> Result<Self, RecoveryError> {
        policy.validate()?;
        if epoch_to <= epoch_from {
            return Err(RecoveryError::InvalidInput(format!(
                "epoch range [{epoch_from}, {epoch_to}) is empty or inverted"
            )));
        }
        if new_root == old_root {
            return Err(RecoveryError::NoOpRotation);
        }
        if reason.is_empty() {
            return Err(RecoveryError::InvalidInput(
                "rotation rationale must not be empty".into(),
            ));
        }
        if reason.len() > MAX_REASON_LEN {
            return Err(RecoveryError::InvalidInput(format!(
                "rotation rationale exceeds {MAX_REASON_LEN} bytes"
            )));
        }
        Ok(Self {
            proposal_id: random_hex(16),
            old_root: hex_encode(old_root.as_bytes()),
            new_root: hex_encode(new_root.as_bytes()),
            epoch_from,
            epoch_to,
            requested_by: hex_encode(requested_by.as_bytes()),
            policy,
            reason: reason.to_string(),
            created_at_ms: now_ms,
        })
    }

    /// Proposal digest (hex) — the ceremony-step binding written to the KT log.
    pub fn digest(&self) -> String {
        digest_hex_raw(&rotation_transcript(self))
    }
}

/// Canonical bytes an approval signature covers. Domain-separated and
/// length-prefixed so no field boundary is ambiguous.
pub fn rotation_transcript(p: &RootRotationProposal) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(ROOT_ROTATION_TRANSCRIPT_DOMAIN.as_bytes());
    for field in [
        p.proposal_id.as_str(),
        p.old_root.as_str(),
        p.new_root.as_str(),
        p.requested_by.as_str(),
    ] {
        buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
        buf.extend_from_slice(field.as_bytes());
    }
    buf.extend_from_slice(&p.epoch_from.to_be_bytes());
    buf.extend_from_slice(&p.epoch_to.to_be_bytes());
    buf.push(p.policy.min_approvals);
    buf.extend_from_slice(&(p.reason.len() as u32).to_be_bytes());
    buf.extend_from_slice(p.reason.as_bytes());
    buf
}

/// One operator approval: the approver key and its Ed25519 signature (hex)
/// over [`rotation_transcript`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootApproval {
    /// Approver Ed25519 public key (hex).
    pub approver: String,
    /// Signature over the proposal transcript (hex, 64 bytes).
    pub signature: String,
}

impl RootApproval {
    /// Verify the signature against the recorded approver key.
    pub fn verify(&self, proposal: &RootRotationProposal) -> Result<bool, RecoveryError> {
        let bytes = hex_decode(&self.approver)?;
        if bytes.len() != 32 {
            return Err(RecoveryError::ApprovalInvalid(
                "approver key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| RecoveryError::ApprovalInvalid(format!("approver key invalid: {e}")))?;
        let sig = hex_decode(&self.signature)?;
        let transcript = rotation_transcript(proposal);
        crate::signing::verify_artifact(&transcript, &sig, &vk)
            .map_err(RecoveryError::ApprovalInvalid)
    }
}

/// Ceremony state machine position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyState {
    /// Proposed and open for approvals / abort.
    Proposed,
    /// Executed: the new root is anchored; terminal.
    Executed,
    /// Aborted by an operator; terminal (execute refuses in this state).
    Aborted,
}

/// The executed rotation — the record that is KT-logged and returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRotationRecord {
    /// Ceremony id.
    pub proposal_id: String,
    /// Retired root (hex).
    pub old_root: String,
    /// Anchored root (hex).
    pub new_root: String,
    /// First epoch under the new root.
    pub epoch_from: u64,
    /// Exclusive end of the new root's validity.
    pub epoch_to: u64,
    /// Approver keys (hex), in approval order.
    pub approvals: Vec<String>,
    /// Proposal digest.
    pub proposal_digest: String,
    /// Execution time (Unix ms).
    pub executed_at_ms: u64,
    /// Members must be re-issued under the new root (always true: a rotation
    /// re-anchors, it never restores).
    pub reissue_required: bool,
    /// KT entry sequence of the `execute` event.
    pub kt_seq: u64,
}

/// The root-rotation ceremony (U-201 `T-recovery`).
///
/// Steps, each KT-logged: [`Self::begin`] (propose) → [`Self::approve`] (per
/// operator, ≥ [`RootRotationPolicy::min_approvals`] distinct keys) →
/// [`Self::execute`]. [`Self::abort`] is terminal. Fields are public so a
/// persisted ceremony can be reconstructed and re-validated; `execute`
/// re-verifies every signature rather than trusting stored state.
pub struct RootRotationCeremony {
    /// The proposal under ceremony.
    pub proposal: RootRotationProposal,
    /// Approvals gathered so far (order = arrival).
    pub approvals: Vec<RootApproval>,
    /// Current state.
    pub state: CeremonyState,
    /// Present once executed.
    pub record: Option<RootRotationRecord>,
    /// Abort rationale, when aborted.
    pub abort_reason: Option<String>,
    /// KT receipts of this ceremony's events, in order (caller-held evidence).
    pub kt_events: Vec<KtEvent>,
}

/// One root-rotation ceremony step, for [`rotation_event_payload`].
pub enum RotationAction<'a> {
    /// Proposal opened.
    Propose,
    /// One approval recorded.
    Approve {
        /// Approver key (hex).
        approver: &'a str,
        /// Approvals gathered after this one.
        approvals_now: usize,
    },
    /// Rotation executed.
    Execute {
        /// Approver keys (hex), in order.
        approvals: &'a [String],
    },
    /// Ceremony aborted.
    Abort {
        /// Abort rationale.
        reason: &'a str,
    },
}

/// Payload for one rotation ceremony step. Single source of truth for the
/// ceremony and for tests rebinding the committed `payload_hash` (the KT log
/// stores chain entries only; payloads are caller-held evidence).
pub fn rotation_event_payload(
    action: RotationAction<'_>,
    p: &RootRotationProposal,
    now_ms: u64,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "kind": ROOT_ROTATION_EVENT_KIND,
        "proposal_id": p.proposal_id,
        "proposal_digest": p.digest(),
        "at_ms": now_ms,
    });
    let obj = value.as_object_mut().expect("json object");
    match action {
        RotationAction::Propose => {
            obj.insert("action".into(), serde_json::json!("propose"));
            obj.insert("old_root".into(), serde_json::json!(p.old_root));
            obj.insert("new_root".into(), serde_json::json!(p.new_root));
            obj.insert("epoch_from".into(), serde_json::json!(p.epoch_from));
            obj.insert("epoch_to".into(), serde_json::json!(p.epoch_to));
            obj.insert("requested_by".into(), serde_json::json!(p.requested_by));
            obj.insert(
                "min_approvals".into(),
                serde_json::json!(p.policy.min_approvals),
            );
            obj.insert("reason".into(), serde_json::json!(p.reason));
        }
        RotationAction::Approve {
            approver,
            approvals_now,
        } => {
            obj.insert("action".into(), serde_json::json!("approve"));
            obj.insert("approver".into(), serde_json::json!(approver));
            obj.insert("approvals_now".into(), serde_json::json!(approvals_now));
            obj.insert(
                "min_approvals".into(),
                serde_json::json!(p.policy.min_approvals),
            );
        }
        RotationAction::Execute { approvals } => {
            obj.insert("action".into(), serde_json::json!("execute"));
            obj.insert("old_root".into(), serde_json::json!(p.old_root));
            obj.insert("new_root".into(), serde_json::json!(p.new_root));
            obj.insert("epoch_from".into(), serde_json::json!(p.epoch_from));
            obj.insert("epoch_to".into(), serde_json::json!(p.epoch_to));
            obj.insert("approvals".into(), serde_json::json!(approvals));
            obj.insert("outcome".into(), serde_json::json!("rotated"));
            obj.insert("reissue_required".into(), serde_json::json!(true));
        }
        RotationAction::Abort { reason } => {
            obj.insert("action".into(), serde_json::json!("abort"));
            obj.insert("reason".into(), serde_json::json!(reason));
        }
    }
    value
}

impl RootRotationCeremony {
    /// Start a ceremony: persist the proposal to the KT log, then return the
    /// open ceremony.
    pub fn begin(
        proposal: RootRotationProposal,
        kt: &mut KtLog,
        mut audit: Option<&mut AuditLog>,
    ) -> Result<Self, RecoveryError> {
        proposal.policy.validate()?;
        let payload = rotation_event_payload(
            RotationAction::Propose,
            &proposal,
            proposal.created_at_ms,
        );
        let entry = kt.append_json(&payload)?;
        push_audit(audit.as_deref_mut(), "root-rotation-propose", &payload);
        Ok(Self {
            proposal,
            approvals: Vec::new(),
            state: CeremonyState::Proposed,
            record: None,
            abort_reason: None,
            kt_events: vec![kt_event(entry, payload)],
        })
    }

    /// Record one operator approval. Refuses: a terminal ceremony, the
    /// requester approving its own proposal ([`RecoveryError::SelfApprovalRefused`]),
    /// a second approval from the same key, and any signature that does not
    /// verify over this proposal's transcript.
    pub fn approve(
        &mut self,
        approver: &VerifyingKey,
        signature_hex: &str,
        kt: &mut KtLog,
        mut audit: Option<&mut AuditLog>,
        now_ms: u64,
    ) -> Result<KtEvent, RecoveryError> {
        self.ensure_open()?;
        let approver_hex = hex_encode(approver.as_bytes());
        if approver_hex == self.proposal.requested_by {
            return Err(RecoveryError::SelfApprovalRefused);
        }
        if self.approvals.iter().any(|a| a.approver == approver_hex) {
            return Err(RecoveryError::DuplicateApproval);
        }
        let approval = RootApproval {
            approver: approver_hex.clone(),
            signature: signature_hex.to_string(),
        };
        if !approval.verify(&self.proposal)? {
            return Err(RecoveryError::ApprovalInvalid(
                "signature did not verify over the proposal transcript".into(),
            ));
        }
        self.approvals.push(approval);
        let payload = rotation_event_payload(
            RotationAction::Approve {
                approver: &approver_hex,
                approvals_now: self.approvals.len(),
            },
            &self.proposal,
            now_ms,
        );
        let entry = kt.append_json(&payload)?;
        push_audit(audit.as_deref_mut(), "root-rotation-approve", &payload);
        let event = kt_event(entry, payload);
        self.kt_events.push(event.clone());
        Ok(event)
    }

    /// Execute the rotation: quorum-check → re-verify **every** approval
    /// signature → refuse no-op/restore rotations → KT-log → terminal state.
    ///
    /// `retired_roots` is the caller's set of previously retired root keys
    /// (hex). Re-anchoring a retired root is refused
    /// ([`RecoveryError::RestoreRefused`]) — the honest rule that recovery
    /// issues new material and never silently restores trust.
    pub fn execute(
        &mut self,
        retired_roots: &[String],
        kt: &mut KtLog,
        mut audit: Option<&mut AuditLog>,
        now_ms: u64,
    ) -> Result<RootRotationRecord, RecoveryError> {
        self.ensure_open()?;
        let need = self.proposal.policy.min_approvals;
        if (self.approvals.len() as u8) < need {
            return Err(RecoveryError::NotApproved {
                have: self.approvals.len(),
                need,
            });
        }
        // Defense in depth: re-verify every stored signature.
        for approval in &self.approvals {
            if !approval.verify(&self.proposal)? {
                return Err(RecoveryError::ApprovalInvalid(format!(
                    "stored approval by {} did not verify",
                    approval.approver
                )));
            }
        }
        if self.proposal.new_root == self.proposal.old_root {
            return Err(RecoveryError::NoOpRotation);
        }
        if retired_roots.iter().any(|r| r == &self.proposal.new_root) {
            return Err(RecoveryError::RestoreRefused {
                root: self.proposal.new_root.clone(),
            });
        }

        let approvals: Vec<String> = self
            .approvals
            .iter()
            .map(|a| a.approver.clone())
            .collect();
        let payload = rotation_event_payload(
            RotationAction::Execute {
                approvals: &approvals,
            },
            &self.proposal,
            now_ms,
        );
        let entry = kt.append_json(&payload)?;
        let kt_seq = entry.seq;
        push_audit(audit.as_deref_mut(), "root-rotation-execute", &payload);
        self.kt_events.push(kt_event(entry, payload));

        let record = RootRotationRecord {
            proposal_id: self.proposal.proposal_id.clone(),
            old_root: self.proposal.old_root.clone(),
            new_root: self.proposal.new_root.clone(),
            epoch_from: self.proposal.epoch_from,
            epoch_to: self.proposal.epoch_to,
            approvals: self.approvals.iter().map(|a| a.approver.clone()).collect(),
            proposal_digest: self.proposal.digest(),
            executed_at_ms: now_ms,
            reissue_required: true,
            kt_seq,
        };
        self.state = CeremonyState::Executed;
        self.record = Some(record.clone());
        Ok(record)
    }

    /// Abort the ceremony. Terminal; KT-logged.
    pub fn abort(
        &mut self,
        reason: &str,
        kt: &mut KtLog,
        mut audit: Option<&mut AuditLog>,
        now_ms: u64,
    ) -> Result<KtEvent, RecoveryError> {
        self.ensure_open()?;
        if reason.is_empty() {
            return Err(RecoveryError::InvalidInput(
                "abort reason must not be empty".into(),
            ));
        }
        let payload =
            rotation_event_payload(RotationAction::Abort { reason }, &self.proposal, now_ms);
        let entry = kt.append_json(&payload)?;
        push_audit(audit.as_deref_mut(), "root-rotation-abort", &payload);
        let event = kt_event(entry, payload);
        self.kt_events.push(event.clone());
        self.state = CeremonyState::Aborted;
        self.abort_reason = Some(reason.to_string());
        Ok(event)
    }

    /// Number of approvals gathered.
    pub fn approvals_gathered(&self) -> usize {
        self.approvals.len()
    }

    /// Whether the quorum is met (does not imply execution).
    pub fn quorum_met(&self) -> bool {
        (self.approvals.len() as u8) >= self.proposal.policy.min_approvals
    }

    fn ensure_open(&self) -> Result<(), RecoveryError> {
        match self.state {
            CeremonyState::Proposed => Ok(()),
            CeremonyState::Executed => Err(RecoveryError::AlreadyExecuted),
            CeremonyState::Aborted => Err(RecoveryError::WrongState {
                detail: "ceremony was aborted".into(),
            }),
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// Typed refusals and failures. Every variant is fail-closed.
#[derive(Debug)]
pub enum RecoveryError {
    /// Input/format error (hex, lengths, epoch range, rationale).
    InvalidInput(String),
    /// A custody policy or manifest below the dual-control floor.
    SingleShareRefused {
        /// Human-readable detail.
        detail: String,
    },
    /// A kit violates its own policy (e.g. threshold below `min_shares`).
    PolicyViolation {
        /// Human-readable detail.
        detail: String,
    },
    /// Two custodians (or two approvals) share a label/key.
    DuplicateCustodian {
        /// The repeated label.
        custodian: String,
    },
    /// A deserialized manifest failed re-validation.
    ManifestInvalid {
        /// Human-readable detail.
        detail: String,
    },
    /// The reconstruct check failed: the shares did not reproduce the
    /// committed secret. Recovery refuses rather than returning wrong
    /// material; the refusal's KT event travels with the error.
    RootCommitmentMismatch {
        /// The logged `refused` event (caller-held evidence).
        kt: KtEvent,
    },
    /// The Shamir primitive refused (insufficient/degenerate shares).
    Primitive(String),
    /// The requester attempted to approve its own rotation.
    SelfApprovalRefused,
    /// The same approver key appeared twice.
    DuplicateApproval,
    /// An approval signature was missing, malformed, or did not verify.
    ApprovalInvalid(String),
    /// Execution attempted without the dual-control quorum.
    NotApproved {
        /// Approvals gathered.
        have: usize,
        /// Approvals required.
        need: u8,
    },
    /// Execution attempted twice.
    AlreadyExecuted,
    /// Step attempted in a terminal state.
    WrongState {
        /// Human-readable detail.
        detail: String,
    },
    /// Rotation to the same key is refused (nothing would change).
    NoOpRotation,
    /// Re-anchoring a retired root is refused (no silent trust restoration).
    RestoreRefused {
        /// The retired root that was offered.
        root: String,
    },
    /// KT log failure: on the success path this means no material is returned.
    Kt(KtError),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(d) => write!(f, "invalid input: {d}"),
            Self::SingleShareRefused { detail } => {
                write!(f, "single-share recovery refused: {detail}")
            }
            Self::PolicyViolation { detail } => write!(f, "custody policy violation: {detail}"),
            Self::DuplicateCustodian { custodian } => {
                write!(f, "duplicate custodian: {custodian}")
            }
            Self::ManifestInvalid { detail } => write!(f, "invalid custody manifest: {detail}"),
            Self::RootCommitmentMismatch { kt } => write!(
                f,
                "reconstruction did not match the manifest root commitment (refused; KT entry {})",
                kt.seq
            ),
            Self::Primitive(d) => write!(f, "shamir primitive refused: {d}"),
            Self::SelfApprovalRefused => {
                write!(f, "the requester cannot approve its own rotation (dual control)")
            }
            Self::DuplicateApproval => write!(f, "duplicate approval from the same key"),
            Self::ApprovalInvalid(d) => write!(f, "approval invalid: {d}"),
            Self::NotApproved { have, need } => {
                write!(f, "rotation not approved: {have} of {need} approvals")
            }
            Self::AlreadyExecuted => write!(f, "ceremony already executed"),
            Self::WrongState { detail } => write!(f, "ceremony state refusal: {detail}"),
            Self::NoOpRotation => write!(f, "rotation to the same root is refused"),
            Self::RestoreRefused { root } => write!(
                f,
                "refused: root {root} is retired — recovery issues new material, it never restores old trust"
            ),
            Self::Kt(e) => write!(f, "KT log failure: {e}"),
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<KtError> for RecoveryError {
    fn from(e: KtError) -> Self {
        Self::Kt(e)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{generate_keypair, sign_artifact};
    use tempfile::tempdir;

    const T0: u64 = 1_700_000_000_000;
    const SECRET: &[u8] = b"tallow-custody-secret-32-bytes!!!";

    fn custodian(label: &str) -> CustodianId {
        CustodianId::new(label).expect("valid custodian")
    }

    fn kit(
        threshold: u8,
        n: u8,
    ) -> (CustodyManifest, Vec<CustodyShare>) {
        let custodians: Vec<CustodianId> = (1..=n)
            .map(|i| custodian(&format!("custodian-{i}")))
            .collect();
        create_custody_kit(
            SECRET,
            CustodyPolicy::dual_control(),
            threshold,
            &custodians,
            T0,
        )
        .expect("kit")
    }

    fn tmp_kt() -> (tempfile::TempDir, KtLog) {
        let dir = tempdir().unwrap();
        let log = KtLog::open(dir.path().join("recovery-kt.jsonl")).unwrap();
        (dir, log)
    }

    fn take(manifest: &CustodyManifest, shares: &[CustodyShare], indexes: &[u8]) -> Vec<CustodyShare> {
        indexes
            .iter()
            .map(|i| {
                let s = shares
                    .iter()
                    .find(|s| s.share.index == *i)
                    .unwrap_or_else(|| panic!("share {i} missing"));
                assert_eq!(
                    manifest.commitment_for(*i),
                    Some(s.commitment.as_str()),
                    "manifest commitment agrees"
                );
                s.clone()
            })
            .collect()
    }

    // ── policy floors ──────────────────────────────────────────────────────

    #[test]
    fn policy_refuses_anything_below_dual_control() {
        assert!(CustodyPolicy::new(1, 2).is_err());
        assert!(CustodyPolicy::new(2, 1).is_err());
        assert!(CustodyPolicy::new(0, 0).is_err());
        let ok = CustodyPolicy::new(2, 2).expect("2/2 is the floor");
        assert_eq!(ok, CustodyPolicy::dual_control());
        let stronger = CustodyPolicy::new(3, 3).expect("3/3 allowed");
        assert_eq!(stronger.min_shares, 3);
    }

    #[test]
    fn kit_creation_refuses_single_share_splits() {
        let c = vec![custodian("a"), custodian("b"), custodian("c")];
        // threshold 1 (a classic 1-of-n recovery) is refused outright.
        let err = create_custody_kit(
            SECRET,
            CustodyPolicy::dual_control(),
            1,
            &c,
            T0,
        )
        .unwrap_err();
        assert!(matches!(err, RecoveryError::SingleShareRefused { .. }), "{err}");
        // threshold above policy.min_shares is honoured: 3-of-3 needs 3.
        let (m, s) = create_custody_kit(SECRET, CustodyPolicy::dual_control(), 3, &c, T0).unwrap();
        assert_eq!(m.threshold, 3);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn kit_creation_refuses_bad_rosters_and_secret() {
        let dup = vec![custodian("a"), custodian("a")];
        assert!(matches!(
            create_custody_kit(SECRET, CustodyPolicy::dual_control(), 2, &dup, T0),
            Err(RecoveryError::DuplicateCustodian { .. })
        ));
        let one = vec![custodian("solo")];
        assert!(matches!(
            create_custody_kit(SECRET, CustodyPolicy::dual_control(), 2, &one, T0),
            Err(RecoveryError::SingleShareRefused { .. })
        ));
        let two = vec![custodian("a"), custodian("b")];
        assert!(matches!(
            create_custody_kit(b"", CustodyPolicy::dual_control(), 2, &two, T0),
            Err(RecoveryError::InvalidInput(_))
        ));
    }

    // ── dual-control recovery ──────────────────────────────────────────────

    #[test]
    fn dual_control_roundtrip_recovers_the_secret() {
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let presented = take(&m, &shares, &[1, 3]);
        let decision = recover_root(&m, &presented, &mut kt, None, T0 + 5).unwrap();
        match decision {
            RecoveryDecision::Recovered(root) => {
                assert_eq!(root.expose(), SECRET);
                assert_eq!(root.report().shares_used, 2);
                assert_eq!(root.report().custodians.len(), 2);
                assert_eq!(root.report().split_id, m.split_id);
                assert_eq!(
                    root.report().freeze_until_ms,
                    T0 + 5 + POST_RECOVERY_FREEZE_SECS * 1000,
                    "24 h freeze recorded"
                );
                assert_eq!(root.report().kt.seq, 0, "first KT entry");
                assert!(root.report().kt.verify_against(&kt.entries()[0]));
                assert!(
                    root.report().kt.verify_against(&kt.entries()[0]),
                    "the receipt re-hashes to the logged entry"
                );
            }
            other => panic!("expected recovery, got {other:?}"),
        }
        kt.verify_chain().expect("chain");
        assert_eq!(kt.len(), 1);
    }

    #[test]
    fn recovery_is_order_independent() {
        let (m, shares) = kit(2, 4);
        let (_dir, mut kt) = tmp_kt();
        let a = take(&m, &shares, &[4, 2]);
        let b = take(&m, &shares, &[2, 4]);
        let ra = recover_root(&m, &a, &mut kt, None, T0).unwrap();
        let rb = recover_root(&m, &b, &mut kt, None, T0).unwrap();
        match (ra, rb) {
            (RecoveryDecision::Recovered(x), RecoveryDecision::Recovered(y)) => {
                assert_eq!(x.expose(), y.expose());
                assert_eq!(x.report().custodians, y.report().custodians);
            }
            other => panic!("expected two recoveries, got {other:?}"),
        }
    }

    #[test]
    fn single_share_is_always_refused() {
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let one = take(&m, &shares, &[2]);
        let verdict = assess(&m, &one).unwrap();
        assert_eq!(
            verdict,
            Recoverability::Unrecoverable {
                reason: UnrecoverableReason::InsufficientShares { have: 1, need: 2 }
            }
        );
        let decision = recover_root(&m, &one, &mut kt, None, T0).unwrap();
        match decision {
            RecoveryDecision::Refused { reason, kt: event } => {
                assert_eq!(
                    reason,
                    UnrecoverableReason::InsufficientShares { have: 1, need: 2 }
                );
                assert_eq!(event.seq, 0, "the refusal itself is KT-logged");
                assert!(event.verify_against(&kt.entries()[0]));
            }
            other => panic!("single share must never recover, got {other:?}"),
        }
        kt.verify_chain().unwrap();
        assert_eq!(kt.len(), 1);
    }

    #[test]
    fn threshold_dominates_the_policy_count() {
        // Policy 2/2, split 3-of-4: two shares are still not enough.
        let (m, shares) = kit(3, 4);
        let (_dir, mut kt) = tmp_kt();
        let two = take(&m, &shares, &[1, 2]);
        match recover_root(&m, &two, &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => assert_eq!(
                reason,
                UnrecoverableReason::InsufficientShares { have: 2, need: 3 }
            ),
            other => panic!("expected refusal, got {other:?}"),
        }
        let three = take(&m, &shares, &[1, 2, 3]);
        assert!(matches!(
            recover_root(&m, &three, &mut kt, None, T0).unwrap(),
            RecoveryDecision::Recovered(_)
        ));
    }

    #[test]
    fn duplicate_of_one_custodian_is_one_custodian() {
        // Same share presented twice: one index twice, one custodian.
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let s1 = take(&m, &shares, &[1]);
        let presented = vec![s1[0].clone(), s1[0].clone()];
        match recover_root(&m, &presented, &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::DuplicateShareIndex { index: 1 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_shares_with_one_custodian_name_refused() {
        // Different indices, but the second share was relabeled to the first
        // custodian's name → still one custodian (dual control refuses).
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let mut s2 = shares[1].clone();
        s2.custodian = custodian("custodian-1"); // now claims to be custodian-1
        let presented = vec![shares[0].clone(), s2];
        match recover_root(&m, &presented, &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::RosterMismatch { at: 1 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_share_refuses_the_whole_attempt() {
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let mut s3 = shares[2].clone();
        // Flip one hex digit of the share material; the commitment catches it.
        let mut data = s3.share.data.clone().into_bytes();
        let last = data.len() - 1;
        data[last] = if data[last] == b'0' { b'1' } else { b'0' };
        s3.share.data = String::from_utf8(data).unwrap();
        let verdict = assess(&m, &[shares[0].clone(), s3.clone()]).unwrap();
        assert_eq!(
            verdict,
            Recoverability::Unrecoverable {
                reason: UnrecoverableReason::ShareIntegrityFailure { at: 1 }
            }
        );
        match recover_root(&m, &[shares[0].clone(), s3], &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::ShareIntegrityFailure { at: 1 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn relabeled_custodian_fails_the_commitment() {
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let mut s2 = shares[1].clone();
        s2.custodian = custodian("mallory");
        match recover_root(&m, &[shares[0].clone(), s2], &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::RosterMismatch { at: 1 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        // Same index, a *roster* custodian, but tampered data → commitment.
        let mut s3 = shares[2].clone();
        s3.share.data = "00".repeat(s3.share.data.len() / 2);
        match recover_root(&m, &[shares[0].clone(), s3], &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::ShareIntegrityFailure { at: 1 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn foreign_split_share_refused() {
        let (m, _a) = kit(2, 3);
        let (_m2, b) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let presented = vec![b[0].clone(), b[1].clone()];
        assert_eq!(
            assess(&m, &presented).unwrap(),
            Recoverability::Unrecoverable {
                reason: UnrecoverableReason::SplitMismatch { at: 0 }
            }
        );
        match recover_root(&m, &presented, &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::SplitMismatch { at: 0 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn hand_edited_share_metadata_refused() {
        let (m, shares) = kit(3, 4);
        let (_dir, mut kt) = tmp_kt();
        // Attacker downgrades the stored share to "threshold 1" and presents
        // it alone: the manifest says 3; the metadata check catches it first.
        let mut s1 = shares[0].clone();
        s1.share.threshold = 1;
        match recover_root(&m, &[s1], &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, .. } => {
                assert_eq!(reason, UnrecoverableReason::ShareMetadataMismatch { at: 0 });
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn hand_edited_manifest_threshold_refused() {
        let (mut m, shares) = kit(3, 4);
        let (_dir, mut kt) = tmp_kt();
        m.threshold = 1; // doctor the manifest itself
        let presented = take(&m, &shares, &[1]);
        let err = recover_root(&m, &presented, &mut kt, None, T0).unwrap_err();
        assert!(matches!(err, RecoveryError::SingleShareRefused { .. }), "{err}");
        assert_eq!(kt.len(), 0, "invalid manifest never reaches the log");
    }

    #[test]
    fn tampered_root_commitment_refuses_after_reconstruction() {
        let (mut m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        m.root_commitment = "00".repeat(32);
        let presented = take(&m, &shares, &[1, 2]);
        let err = recover_root(&m, &presented, &mut kt, None, T0).unwrap_err();
        // The failure is evidence too: one KT entry, outcome refused — and the
        // error carries the receipt that binds it.
        match err {
            RecoveryError::RootCommitmentMismatch { kt: event } => {
                assert_eq!(event.seq, 0);
                assert!(event.verify_against(&kt.entries()[0]));
                assert!(
                    event.payload.to_string().contains("root-commitment-mismatch"),
                    "{}",
                    event.payload
                );
            }
            other => panic!("expected a root-commitment refusal, got {other:?}"),
        }
        assert_eq!(kt.len(), 1);
    }

    #[test]
    fn empty_presentation_refused() {
        let (m, _shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        assert_eq!(
            assess(&m, &[]).unwrap(),
            Recoverability::Unrecoverable {
                reason: UnrecoverableReason::NoShares
            }
        );
        match recover_root(&m, &[], &mut kt, None, T0).unwrap() {
            RecoveryDecision::Refused { reason, kt: event } => {
                assert_eq!(reason, UnrecoverableReason::NoShares);
                assert_eq!(event.seq, 0);
                assert!(event.verify_against(&kt.entries()[0]));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn recovered_root_is_redacted_and_exposes_exactly() {
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let presented = take(&m, &shares, &[1, 2]);
        let root = match recover_root(&m, &presented, &mut kt, None, T0).unwrap() {
            RecoveryDecision::Recovered(r) => r,
            other => panic!("expected recovery, got {other:?}"),
        };
        let dbg = format!("{root:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains(&hex_encode(SECRET)), "{dbg}");
        assert_eq!(root.expose(), SECRET);
    }

    // ── KT log + audit surface ─────────────────────────────────────────────

    #[test]
    fn kt_log_records_events_with_digests_not_names() {
        let (m, shares) = kit(2, 3);
        let (dir, mut kt) = tmp_kt();
        let presented = take(&m, &shares, &[1, 2]);
        let decision = recover_root(&m, &presented, &mut kt, None, T0).unwrap();
        let receipt = match &decision {
            RecoveryDecision::Recovered(r) => r.report().kt.clone(),
            other => panic!("expected recovery, got {other:?}"),
        };
        assert_eq!(receipt.seq, 0);
        // The receipt re-hashes to the committed payload_hash: the log entry
        // binds exactly this payload (caller-held evidence).
        assert!(receipt.verify_against(&kt.entries()[0]));
        let payload_text = receipt.payload.to_string();
        assert!(payload_text.contains("tallow.recovery.v1"), "{payload_text}");
        assert!(payload_text.contains("\"outcome\":\"recovered\""), "{payload_text}");
        assert!(
            payload_text.contains(&custodian_digest(&custodian("custodian-1"))),
            "{payload_text}"
        );
        assert!(!payload_text.contains("custodian-1"), "custodian names never leave the manifest");
        assert!(!payload_text.contains(&hex_encode(SECRET)), "no material in the payload");
        kt.verify_chain().unwrap();
        // Inclusion proof of the event verifies against the tree head.
        let proof = kt.prove_inclusion(0).unwrap();
        let head = kt.tree_head();
        proof.verify(&head.root_hash).unwrap();
        assert_eq!(head.chain_len, 1);

        // Persistence: reopening re-verifies the whole chain.
        drop(kt);
        let reopened = KtLog::open(dir.path().join("recovery-kt.jsonl")).unwrap();
        reopened.verify_chain().unwrap();
        assert_eq!(reopened.len(), 1);

        // The log file itself is chain entries only: the payload (with the
        // event kind and digests) stays caller-held, committed by hash.
        let raw = std::fs::read_to_string(reopened.path()).unwrap();
        assert!(raw.contains("\"payload_hash\""), "{raw}");
        assert!(!raw.contains("tallow.recovery.v1"), "no payload text in the log file");
        assert!(!raw.contains("custodian-1"), "no labels in the log file");
        assert!(!raw.contains(&hex_encode(SECRET)), "no material in the log");
        assert_eq!(raw.lines().count(), 1);
    }

    #[test]
    fn kit_creation_can_be_kt_logged() {
        let (m, _shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let receipt = log_kit_created(&m, &mut kt, T0).unwrap();
        assert_eq!(receipt.seq, 0);
        assert!(receipt.verify_against(&kt.entries()[0]));
        kt.verify_chain().unwrap();
        let payload = receipt.payload.to_string();
        assert!(payload.contains("custody-kit-created"), "{payload}");
        assert!(payload.contains(&custodian_digest(&custodian("custodian-2"))), "{payload}");
        assert!(!payload.contains("custodian-2"), "custodian names never logged");
        let raw = std::fs::read_to_string(kt.path()).unwrap();
        assert!(!raw.contains("custodian-2"), "labels never leave the manifest");
        assert!(!raw.contains("custody-kit-created"), "payload stays caller-held");
    }

    #[test]
    fn merkle_audit_receives_events_when_supplied() {
        let (m, shares) = kit(2, 3);
        let (_dir, mut kt) = tmp_kt();
        let mut audit = AuditLog::new();
        let presented = take(&m, &shares, &[2, 3]);
        let _ = recover_root(&m, &presented, &mut kt, Some(&mut audit), T0).unwrap();
        assert!(audit.verify_chain());
        assert_eq!(audit.len(), 1);
        let proof = audit.prove_inclusion(0).expect("proof");
        assert!(AuditLog::verify_proof(
            &proof.leaf_hash,
            &proof,
            &audit.merkle_root().expect("root")
        ));
        let json = audit.to_json();
        assert_eq!(json["count"], 1);
        assert_eq!(json["entries"][0]["function"], "vault::recovery");
        assert_eq!(json["entries"][0]["event_type"], "share-set-recovery");
        assert_eq!(json["entries"][0]["metadata"]["outcome"], "recovered");
    }

    // ── root-rotation ceremony ─────────────────────────────────────────────

    fn ceremony_setup(
        kt: &mut KtLog,
    ) -> (
        ed25519_dalek::SigningKey,
        ed25519_dalek::VerifyingKey,
        ed25519_dalek::SigningKey,
        ed25519_dalek::VerifyingKey,
        RootRotationCeremony,
    ) {
        let (requester_sk, requester_vk) = generate_keypair();
        let (approver_sk, approver_vk) = generate_keypair();
        let (old_sk, old_vk) = generate_keypair();
        let (new_sk, new_vk) = generate_keypair();
        let _ = (old_sk, new_sk);
        let proposal = RootRotationProposal::new(
            &old_vk,
            &new_vk,
            &requester_vk,
            1,
            2,
            "quorum lost; re-anchor fleet root",
            RootRotationPolicy::dual_control(),
            T0,
        )
        .unwrap();
        let ceremony = RootRotationCeremony::begin(proposal, kt, None).unwrap();
        (requester_sk, requester_vk, approver_sk, approver_vk, ceremony)
    }

    #[test]
    fn rotation_ceremony_full_flow() {
        let (_dir, mut kt) = tmp_kt();
        let (_rsk, rvk, ask, avk, mut ceremony) = ceremony_setup(&mut kt);
        let (bsk, bvk) = generate_keypair();
        let transcript = rotation_transcript(&ceremony.proposal);

        // Requester cannot self-approve.
        let self_sig = hex_encode(&sign_artifact(&transcript, &_rsk));
        let err = ceremony
            .approve(&rvk, &self_sig, &mut kt, None, T0 + 1)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::SelfApprovalRefused), "{err}");

        // One approval is not dual control.
        let sig_a = hex_encode(&sign_artifact(&transcript, &ask));
        ceremony.approve(&avk, &sig_a, &mut kt, None, T0 + 2).unwrap();
        assert!(!ceremony.quorum_met());
        let err = ceremony
            .execute(&[], &mut kt, None, T0 + 3)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::NotApproved { have: 1, need: 2 }), "{err}");

        // Duplicate approval from the same key is refused.
        let err = ceremony
            .approve(&avk, &sig_a, &mut kt, None, T0 + 4)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::DuplicateApproval), "{err}");

        // Second distinct key completes the quorum.
        let sig_b = hex_encode(&sign_artifact(&transcript, &bsk));
        ceremony.approve(&bvk, &sig_b, &mut kt, None, T0 + 5).unwrap();
        assert!(ceremony.quorum_met());

        let record = ceremony.execute(&[], &mut kt, None, T0 + 6).unwrap();
        assert_eq!(record.proposal_digest, ceremony.proposal.digest());
        assert_eq!(record.approvals.len(), 2);
        assert!(record.reissue_required);
        assert_eq!(ceremony.state, CeremonyState::Executed);
        assert_eq!(ceremony.record.as_ref().unwrap(), &record);
        // propose + approve + approve + execute = 4 KT entries.
        assert_eq!(kt.len(), 4);
        kt.verify_chain().unwrap();
        let proof = kt.prove_inclusion(3).unwrap();
        proof.verify(&kt.tree_head().root_hash).unwrap();
        // The receipts bind the chain entries; the payloads are caller-held.
        assert!(ceremony.kt_events[3].verify_against(&kt.entries()[3]));
        let execute_payload = ceremony.kt_events[3].payload.to_string();
        assert!(execute_payload.contains("\"outcome\":\"rotated\""), "{execute_payload}");
        assert!(execute_payload.contains("\"action\":\"execute\""), "{execute_payload}");
        let propose_payload = ceremony.kt_events[0].payload.to_string();
        assert!(propose_payload.contains("\"action\":\"propose\""), "{propose_payload}");
        let raw = std::fs::read_to_string(kt.path()).unwrap();
        assert!(!raw.contains("tallow.root-rotation.v1"), "payload stays caller-held");
        assert_eq!(raw.lines().count(), 4);
    }

    #[test]
    fn rotation_execution_is_single_use_and_terminal() {
        let (_dir, mut kt) = tmp_kt();
        let (_rsk, _rvk, ask, avk, mut ceremony) = ceremony_setup(&mut kt);
        let (bsk, bvk) = generate_keypair();
        let transcript = rotation_transcript(&ceremony.proposal);
        ceremony
            .approve(&avk, &hex_encode(&sign_artifact(&transcript, &ask)), &mut kt, None, T0 + 1)
            .unwrap();
        ceremony
            .approve(&bvk, &hex_encode(&sign_artifact(&transcript, &bsk)), &mut kt, None, T0 + 2)
            .unwrap();
        ceremony.execute(&[], &mut kt, None, T0 + 3).unwrap();
        let err = ceremony.execute(&[], &mut kt, None, T0 + 4).unwrap_err();
        assert!(matches!(err, RecoveryError::AlreadyExecuted), "{err}");
        let err = ceremony
            .approve(&avk, "00".to_string().repeat(64).as_str(), &mut kt, None, T0 + 5)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::AlreadyExecuted), "{err}");
    }

    #[test]
    fn rotation_abort_is_terminal_and_logged() {
        let (_dir, mut kt) = tmp_kt();
        let (_rsk, _rvk, ask, avk, mut ceremony) = ceremony_setup(&mut kt);
        let transcript = rotation_transcript(&ceremony.proposal);
        ceremony
            .approve(&avk, &hex_encode(&sign_artifact(&transcript, &ask)), &mut kt, None, T0 + 1)
            .unwrap();
        ceremony.abort("root compromise suspected", &mut kt, None, T0 + 2).unwrap();
        assert_eq!(ceremony.state, CeremonyState::Aborted);
        assert_eq!(ceremony.abort_reason.as_deref(), Some("root compromise suspected"));
        let err = ceremony.execute(&[], &mut kt, None, T0 + 3).unwrap_err();
        assert!(matches!(err, RecoveryError::WrongState { .. }), "{err}");
        let err = ceremony
            .abort("again", &mut kt, None, T0 + 4)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::WrongState { .. }), "{err}");
        assert_eq!(kt.len(), 3); // propose + approve + abort
        assert!(ceremony.kt_events[2].verify_against(&kt.entries()[2]));
        kt.verify_chain().unwrap();
    }

    #[test]
    fn rotation_tampered_stored_approval_caught_at_execute() {
        let (_dir, mut kt) = tmp_kt();
        let (_rsk, _rvk, ask, avk, mut ceremony) = ceremony_setup(&mut kt);
        let (bsk, bvk) = generate_keypair();
        let transcript = rotation_transcript(&ceremony.proposal);
        ceremony
            .approve(&avk, &hex_encode(&sign_artifact(&transcript, &ask)), &mut kt, None, T0 + 1)
            .unwrap();
        ceremony
            .approve(&bvk, &hex_encode(&sign_artifact(&transcript, &bsk)), &mut kt, None, T0 + 2)
            .unwrap();
        // An attacker with write access to persisted ceremony state flips one
        // digit of the second signature; execute re-verifies and refuses.
        let sig = ceremony.approvals[1].signature.clone();
        let mut bytes = sig.into_bytes();
        let i = bytes.len() - 1;
        bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
        ceremony.approvals[1].signature = String::from_utf8(bytes).unwrap();
        let err = ceremony.execute(&[], &mut kt, None, T0 + 3).unwrap_err();
        assert!(matches!(err, RecoveryError::ApprovalInvalid(_)), "{err}");
        assert_eq!(ceremony.state, CeremonyState::Proposed, "not executed");
        // And the ceremony can still be completed once the bad sig is fixed.
        ceremony.approvals[1].signature =
            hex_encode(&sign_artifact(&transcript, &bsk));
        ceremony.execute(&[], &mut kt, None, T0 + 4).unwrap();
        assert_eq!(ceremony.state, CeremonyState::Executed);
    }

    #[test]
    fn rotation_signature_bound_to_this_proposal() {
        let (_dir, mut kt) = tmp_kt();
        let (_rsk, _rvk, ask, avk, mut ceremony) = ceremony_setup(&mut kt);
        // Sign a *different* proposal's transcript (same keys, different id).
        let (old2_sk, old2_vk) = generate_keypair();
        let (new2_sk, new2_vk) = generate_keypair();
        let (r2_sk, r2_vk) = generate_keypair();
        let _ = (old2_sk, new2_sk, r2_sk);
        let other = RootRotationProposal::new(
            &old2_vk,
            &new2_vk,
            &r2_vk,
            1,
            2,
            "another ceremony",
            RootRotationPolicy::dual_control(),
            T0,
        )
        .unwrap();
        let foreign_sig = hex_encode(&sign_artifact(&rotation_transcript(&other), &ask));
        let err = ceremony
            .approve(&avk, &foreign_sig, &mut kt, None, T0 + 1)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::ApprovalInvalid(_)), "{err}");
        assert_eq!(ceremony.approvals_gathered(), 0);
    }

    #[test]
    fn rotation_refuses_restoring_a_retired_root() {
        let (_dir, mut kt) = tmp_kt();
        let (_rsk, _rvk, ask, avk, mut ceremony) = ceremony_setup(&mut kt);
        let (bsk, bvk) = generate_keypair();
        let transcript = rotation_transcript(&ceremony.proposal);
        ceremony
            .approve(&avk, &hex_encode(&sign_artifact(&transcript, &ask)), &mut kt, None, T0 + 1)
            .unwrap();
        ceremony
            .approve(&bvk, &hex_encode(&sign_artifact(&transcript, &bsk)), &mut kt, None, T0 + 2)
            .unwrap();
        let retired = vec![ceremony.proposal.new_root.clone()];
        let err = ceremony.execute(&retired, &mut kt, None, T0 + 3).unwrap_err();
        assert!(matches!(err, RecoveryError::RestoreRefused { .. }), "{err}");
        assert_eq!(ceremony.state, CeremonyState::Proposed);
        // Not restored, but a fresh (non-retired) root is fine.
        assert!(ceremony.execute(&[], &mut kt, None, T0 + 4).is_ok());
    }

    #[test]
    fn rotation_policy_and_proposal_refuse_weak_or_noop_inputs() {
        assert!(RootRotationPolicy::new(1).is_err());
        assert!(RootRotationPolicy::new(0).is_err());
        assert_eq!(RootRotationPolicy::new(2).unwrap(), RootRotationPolicy::dual_control());

        let (old_sk, old_vk) = generate_keypair();
        let (new_sk, new_vk) = generate_keypair();
        let (r_sk, r_vk) = generate_keypair();
        let _ = (old_sk, new_sk, r_sk);
        assert!(matches!(
            RootRotationProposal::new(&old_vk, &old_vk, &r_vk, 1, 2, "noop", RootRotationPolicy::dual_control(), T0),
            Err(RecoveryError::NoOpRotation)
        ));
        assert!(matches!(
            RootRotationProposal::new(&old_vk, &new_vk, &r_vk, 5, 5, "empty", RootRotationPolicy::dual_control(), T0),
            Err(RecoveryError::InvalidInput(_))
        ));
        assert!(matches!(
            RootRotationProposal::new(&old_vk, &new_vk, &r_vk, 1, 2, "", RootRotationPolicy::dual_control(), T0),
            Err(RecoveryError::InvalidInput(_))
        ));
    }

    #[test]
    fn manifest_serde_roundtrip_and_validation() {
        let (m, shares) = kit(2, 3);
        let json = serde_json::to_string(&m).unwrap();
        let back: CustodyManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        back.validate().unwrap();
        // A doctored JSON policy is refused on re-validation.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["policy"]["min_distinct_custodians"] = serde_json::json!(1);
        let doctored: CustodyManifest = serde_json::from_value(value).unwrap();
        assert!(matches!(
            doctored.validate(),
            Err(RecoveryError::SingleShareRefused { .. })
        ));

        // CustodyShare keeps fidelity and redacts Debug.
        let js = serde_json::to_string(&shares[0]).unwrap();
        let bs: CustodyShare = serde_json::from_str(&js).unwrap();
        assert_eq!(bs.custodian, shares[0].custodian);
        assert!(bs.commitment_matches());
        let dbg = format!("{:?}", shares[0]);
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains(&shares[0].share.data), "share data redacted");
    }

    #[test]
    fn custodian_labels_are_refused_not_normalized() {
        assert!(CustodianId::new("").is_err());
        assert!(CustodianId::new(" padded ").is_err());
        assert!(CustodianId::new("tab\tname").is_err());
        assert!(CustodianId::new(&"x".repeat(MAX_CUSTODIAN_LEN + 1)).is_err());
        let ok = CustodianId::new("Custodian One").unwrap();
        assert_eq!(ok.as_str(), "Custodian One");
        assert_eq!(ok.to_string(), "Custodian One");
        // The digest is stable and domain-separated from the label itself.
        assert_eq!(
            custodian_digest(&ok),
            custodian_digest(&CustodianId::new("Custodian One").unwrap())
        );
        assert_ne!(custodian_digest(&ok), "Custodian One");
    }

    #[test]
    fn doctrine_text_states_the_honest_rules() {
        for needle in ["no fallback path", "never trust", "re-enroll"] {
            assert!(
                UNRECOVERABLE_DOCTRINE.contains(needle),
                "doctrine must state {needle:?}"
            );
        }
    }
}
