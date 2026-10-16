//! Signed SVID revocation lists — module owner: U-213 (W3 revocation, R-5.11 / ATK-2.3).
//!
//! Design constraints (U-201 blueprint + governance D-1):
//!
//! * **No external CT/OCSP.** Revocation travels as *local, signed* lists only. rcgen's
//!   CRL support exists but is explicitly **not** the chosen mechanism (U-201 D-1: "signed
//!   revocation lists, not CRL/OCSP"). Nothing in this module performs I/O or network calls.
//! * **Every entry is signed** with Ed25519 over a canonical, domain-separated byte encoding
//!   (`tallow-svid-revocation-entry-v1`). The signer key is *passed in* at construction; the
//!   verifier holds a pinned trusted key.
//! * **The list head is signed too**, so `seq` / `issued_at` / the entry set cannot be
//!   tampered with or spliced by an attacker who only replays signed entries. The head
//!   signature covers the SHA-256 digest of every `(entry canonical bytes || entry
//!   signature)`, which binds the entry set in order.
//! * **Freshness gate**: a list older than `max_age` is refused with a typed error
//!   (ATK-2.3 mitigation 1 → fail-closed for *new* sessions; the caller decides what to do
//!   about already-established ones). `freshness_bound(ttl)` returns `min(ttl/2, 6 h)`.
//! * **Monotonic high-water sequence** (ATK-2.8 / M50 rollback compensation): lists are
//!   applied in non-decreasing `seq` order; a regression is refused. Re-applying the same
//!   `seq` with *different* content is refused as equivocation.
//!
//! Entry fields: `{ serial, reason, not_before, signature }`. `serial` is the SVID serial
//! (or identity id, e.g. a node id or SPIFFE id string) — an opaque, non-empty identifier.
//! `not_before` is the **effective-from** unix-seconds timestamp: an entry is honoured from
//! `not_before` onwards (`is_revoked_at`). [`is_revoked`] / [`RevocationList::is_revoked`]
//! ignore `not_before` and are deliberately fail-closed: any listed serial counts as revoked.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tallow_crypto::sig::ed25519::{self, Ed25519Signer};

/// Canonical-bytes domain tag for a single revocation entry (v1).
pub const ENTRY_DOMAIN: &[u8] = b"tallow-svid-revocation-entry-v1";
/// Canonical-bytes domain tag for a revocation list head (v1).
pub const LIST_DOMAIN: &[u8] = b"tallow-svid-revocation-list-v1";
/// Wire version of [`RevocationList`] understood by this module.
pub const LIST_VERSION: u8 = 1;
/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Absolute freshness ceiling for revocation lists (`min(ttl/2, 6 h)`, report §5.4 + ATK-2.3).
pub const REVOCATION_MAX_AGE_SECS: i64 = 6 * 3600;
/// Tolerated clock skew when a list claims to be issued in the future (ATK-2.8 rollback alarm).
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Why a serial is revoked. Mirrors the RFC 5280 `CRLReason` spirit without pulling in X.509 CRLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The SVID key is known or suspected compromised.
    KeyCompromise,
    /// The issuing key is compromised — every SVID under it is suspect.
    CaCompromise,
    /// The workload/identity moved or was re-assigned.
    AffiliationChanged,
    /// Replaced by a newer SVID (rotation hygiene / rolled-back rotation).
    Superseded,
    /// The workload no longer runs.
    CessationOfOperation,
    /// Temporarily held (recoverable, still fail-closed).
    CertificateHold,
    /// Privileges withdrawn by operator action.
    PrivilegeWithdrawn,
    /// No specific reason recorded.
    Unspecified,
}

impl RevocationReason {
    /// Stable textual encoding used inside the canonical byte string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyCompromise => "key_compromise",
            Self::CaCompromise => "ca_compromise",
            Self::AffiliationChanged => "affiliation_changed",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessation_of_operation",
            Self::CertificateHold => "certificate_hold",
            Self::PrivilegeWithdrawn => "privilege_withdrawn",
            Self::Unspecified => "unspecified",
        }
    }
}

/// Typed failures for revocation handling. Every refusal path is explicit; there is no
/// "assume revoked / assume not revoked" fallback.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationError {
    /// The list is older than the freshness bound; callers must fail closed for new sessions.
    #[error("revocation list stale: age {age_secs}s exceeds max_age {max_age_secs}s")]
    Stale {
        /// Observed age in seconds (`now - issued_at`).
        age_secs: i64,
        /// Configured maximum age in seconds.
        max_age_secs: i64,
    },
    /// The list claims an `issued_at` beyond tolerated clock skew (rollback / forgery signal).
    #[error(
        "revocation list from the future: issued_at {issued_at} > now {now} + skew {skew_secs}s"
    )]
    ListFromFuture {
        /// Claimed issuance time.
        issued_at: i64,
        /// Local time at evaluation.
        now: i64,
        /// Tolerated skew (see [`MAX_CLOCK_SKEW_SECS`]).
        skew_secs: i64,
    },
    /// Sequence regression: incoming list is older than the applied high-water mark.
    #[error("revocation seq regression refused: incoming {incoming} < high-water {high_water}")]
    SeqRegression {
        /// Applied high-water sequence.
        high_water: u64,
        /// Incoming (lower) sequence.
        incoming: u64,
    },
    /// Same sequence number, different content — equivocation attack or split-brain feed.
    #[error(
        "revocation seq equivocation refused: seq {seq} already applied with different content"
    )]
    SeqEquivocation {
        /// The conflicting sequence number.
        seq: u64,
    },
    /// An entry's Ed25519 signature did not verify under the trusted signer key.
    #[error("revocation entry signature invalid for serial {serial:?}")]
    EntrySignatureInvalid {
        /// Serial whose entry failed verification.
        serial: String,
    },
    /// The list head signature did not verify under the trusted signer key.
    #[error("revocation list head signature invalid")]
    ListSignatureInvalid,
    /// The entry serial/id was empty.
    #[error("revocation entry serial id must be non-empty")]
    EmptySerial,
    /// A signature field had the wrong length.
    #[error("malformed signature: expected {expected} bytes, got {got}")]
    SignatureLength {
        /// Expected byte length (64 for Ed25519).
        expected: usize,
        /// Observed byte length.
        got: usize,
    },
    /// The list declared a wire version this build does not understand.
    #[error("unsupported revocation list version {0}")]
    UnsupportedVersion(u8),
    /// No list has ever been applied, so a freshness verdict is impossible.
    /// Callers enforcing the check-at-use gate must treat this as fail-closed.
    #[error("no revocation list applied: refusing (fail-closed)")]
    NoListApplied,
}

/// One signed revocation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// SVID serial (or identity id) being revoked — opaque, non-empty.
    pub serial: String,
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Effective-from unix seconds (entry honoured at `now >= not_before`).
    pub not_before: i64,
    /// Ed25519 signature (64 bytes) over [`Self::canonical_bytes`].
    pub signature: Vec<u8>,
}

impl RevocationEntry {
    /// Build an entry with an empty (invalid) signature placeholder.
    pub fn unsigned(
        serial: impl Into<String>,
        reason: RevocationReason,
        not_before: i64,
    ) -> Result<Self, RevocationError> {
        let serial = serial.into();
        if serial.trim().is_empty() {
            return Err(RevocationError::EmptySerial);
        }
        Ok(Self {
            serial,
            reason,
            not_before,
            signature: Vec::new(),
        })
    }

    /// Build and sign an entry with the caller-supplied Ed25519 signer key.
    pub fn sign(
        signer: &Ed25519Signer,
        serial: impl Into<String>,
        reason: RevocationReason,
        not_before: i64,
    ) -> Result<Self, RevocationError> {
        let mut entry = Self::unsigned(serial, reason, not_before)?;
        entry.signature = signer.sign(&entry.canonical_bytes()).to_vec();
        Ok(entry)
    }

    /// Canonical, domain-separated, length-prefixed encoding — the exact bytes that are signed.
    ///
    /// Length-prefixing every field removes any ambiguity between (e.g.) a serial that
    /// contains the reason string and a differently-split pair of fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        push_field(&mut out, ENTRY_DOMAIN);
        push_field(&mut out, self.serial.as_bytes());
        push_field(&mut out, self.reason.as_str().as_bytes());
        push_field(&mut out, &self.not_before.to_be_bytes());
        out
    }

    /// The 64-byte signature, or a typed length error.
    pub fn signature_bytes(&self) -> Result<[u8; SIGNATURE_LEN], RevocationError> {
        self.signature
            .as_slice()
            .try_into()
            .map_err(|_| RevocationError::SignatureLength {
                expected: SIGNATURE_LEN,
                got: self.signature.len(),
            })
    }

    /// Verify this entry's signature against a trusted Ed25519 public key.
    pub fn verify(&self, signer_pubkey: &[u8; 32]) -> Result<(), RevocationError> {
        let signature = self.signature_bytes()?;
        ed25519::verify(signer_pubkey, &self.canonical_bytes(), &signature).map_err(|_| {
            RevocationError::EntrySignatureInvalid {
                serial: self.serial.clone(),
            }
        })
    }

    /// Whether the revocation is effective at `now` (unix seconds).
    pub fn is_effective_at(&self, now: i64) -> bool {
        now >= self.not_before
    }
}

/// A signed revocation list: monotonic `seq`, `issued_at`, entries, and a signed head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    /// Wire version ([`LIST_VERSION`]).
    pub version: u8,
    /// Monotonic revision sequence — drives the rollback high-water gate.
    pub seq: u64,
    /// Unix seconds when this list was produced — drives the freshness gate.
    pub issued_at: i64,
    /// The signed revocation entries (sorted by serial for canonical head bytes).
    pub entries: Vec<RevocationEntry>,
    /// Ed25519 signature (64 bytes) over [`Self::head_bytes`].
    pub signature: Vec<u8>,
}

impl RevocationList {
    /// Seal a new list: sorts entries, requires each entry to carry a 64-byte signature, then
    /// signs the canonical head with the caller-supplied Ed25519 signer key.
    pub fn sign(
        signer: &Ed25519Signer,
        seq: u64,
        issued_at: i64,
        mut entries: Vec<RevocationEntry>,
    ) -> Result<Self, RevocationError> {
        entries.sort_by(|a, b| {
            a.serial
                .cmp(&b.serial)
                .then(a.not_before.cmp(&b.not_before))
        });
        let mut list = Self {
            version: LIST_VERSION,
            seq,
            issued_at,
            entries,
            signature: Vec::new(),
        };
        for entry in &list.entries {
            entry.signature_bytes()?;
        }
        list.signature = signer.sign(&list.head_bytes()).to_vec();
        Ok(list)
    }

    /// Canonical bytes for the list head: version, seq, issued_at, entry-count, and the
    /// SHA-256 digest of each `(entry canonical bytes || entry signature)` in order.
    pub fn head_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.entries.len() * 40);
        push_field(&mut out, LIST_DOMAIN);
        push_field(&mut out, &[self.version]);
        push_field(&mut out, &self.seq.to_be_bytes());
        push_field(&mut out, &self.issued_at.to_be_bytes());
        push_field(&mut out, &(self.entries.len() as u64).to_be_bytes());
        for entry in &self.entries {
            let mut digest = Sha256::new();
            digest.update(entry.canonical_bytes());
            digest.update(&entry.signature);
            push_field(&mut out, digest.finalize().as_slice());
        }
        out
    }

    /// Verify the head signature and every entry signature under the trusted signer key.
    ///
    /// This is the *authenticity* gate — call it **before** applying any content.
    pub fn verify(&self, signer_pubkey: &[u8; 32]) -> Result<(), RevocationError> {
        if self.version != LIST_VERSION {
            return Err(RevocationError::UnsupportedVersion(self.version));
        }
        let signature: [u8; SIGNATURE_LEN] =
            self.signature
                .as_slice()
                .try_into()
                .map_err(|_| RevocationError::SignatureLength {
                    expected: SIGNATURE_LEN,
                    got: self.signature.len(),
                })?;
        ed25519::verify(signer_pubkey, &self.head_bytes(), &signature)
            .map_err(|_| RevocationError::ListSignatureInvalid)?;
        for entry in &self.entries {
            entry.verify(signer_pubkey)?;
        }
        Ok(())
    }

    /// Freshness gate. Returns the observed age in seconds, or a typed refusal.
    ///
    /// `now` must come from the caller's monotonic-guarded clock (daemon owns that, see
    /// U-209/U-210 wiring); this module deliberately has no clock of its own.
    pub fn check_freshness(&self, now: i64, max_age_secs: i64) -> Result<i64, RevocationError> {
        if self.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(RevocationError::ListFromFuture {
                issued_at: self.issued_at,
                now,
                skew_secs: MAX_CLOCK_SKEW_SECS,
            });
        }
        let age_secs = now.saturating_sub(self.issued_at);
        if age_secs > max_age_secs {
            return Err(RevocationError::Stale {
                age_secs,
                max_age_secs,
            });
        }
        Ok(age_secs)
    }

    /// Fail-closed membership check: any listed serial counts as revoked, regardless of
    /// `not_before` (early revocation is the safe direction).
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|entry| entry.serial == serial)
    }

    /// Membership check honouring each entry's effective-from time.
    pub fn is_revoked_at(&self, serial: &str, now: i64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.serial == serial && entry.is_effective_at(now))
    }

    /// Look up the first matching entry.
    pub fn find(&self, serial: &str) -> Option<&RevocationEntry> {
        self.entries.iter().find(|entry| entry.serial == serial)
    }

    /// Number of entries in the list.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Freshness bound for a given SVID TTL: `min(ttl/2, 6 h)`, floored at 1 s
/// (report §5.4 + ATK-2.3 mitigation 1).
pub fn freshness_bound(ttl_secs: i64) -> i64 {
    (ttl_secs / 2).clamp(1, REVOCATION_MAX_AGE_SECS)
}

/// Fail-closed membership helper: `is_revoked(list, serial)`.
pub fn is_revoked(list: &RevocationList, serial: &str) -> bool {
    list.is_revoked(serial)
}

/// Outcome of observing a list sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighWaterOutcome {
    /// The sequence advanced past the previous high-water mark.
    Advanced,
    /// The same sequence was re-applied (idempotent; content must match).
    Duplicate,
}

/// Monotonic high-water mark over list sequence numbers (skip-list / rollback gate).
///
/// Semantics: `seq` must never go backwards. Equal is a no-op replay; smaller is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RevocationHighWater {
    seq: Option<u64>,
}

impl RevocationHighWater {
    /// Empty mark — the first observed sequence always advances.
    pub const fn new() -> Self {
        Self { seq: None }
    }

    /// Start from a known high-water (e.g. reloaded from persisted state).
    pub const fn from_seq(seq: u64) -> Self {
        Self { seq: Some(seq) }
    }

    /// Current high-water sequence, if any list has been observed.
    pub const fn seq(&self) -> Option<u64> {
        self.seq
    }

    /// Whether `incoming` would be refused as a regression.
    pub fn refuses(&self, incoming: u64) -> bool {
        matches!(self.seq, Some(current) if incoming < current)
    }

    /// Observe a sequence number: advance, accept a duplicate, or refuse a regression.
    pub fn observe(&mut self, incoming: u64) -> Result<HighWaterOutcome, RevocationError> {
        match self.seq {
            Some(current) if incoming < current => Err(RevocationError::SeqRegression {
                high_water: current,
                incoming,
            }),
            Some(current) if incoming == current => Ok(HighWaterOutcome::Duplicate),
            _ => {
                self.seq = Some(incoming);
                Ok(HighWaterOutcome::Advanced)
            }
        }
    }
}

/// In-memory applied view of verified, fresh revocation lists.
///
/// The store enforces, in order: **signature** (authenticity) → **freshness** → **sequence
/// high-water** → merge. Entries are merged additively for the lifetime of the store, so a
/// later list cannot silently un-revoke a serial that an earlier (still valid) list revoked.
/// Persistence is deliberately out of scope here (daemon-side wiring owns durability).
#[derive(Debug)]
pub struct RevocationStore {
    trusted_signer: [u8; 32],
    max_age_secs: i64,
    high_water: RevocationHighWater,
    applied_head: Option<[u8; 32]>,
    /// `issued_at` of the most recently applied list — the anchor for the
    /// *check-at-use* freshness verdict ([`Self::check_admission_freshness`]).
    applied_issued_at: Option<i64>,
    revoked: BTreeMap<String, RevocationEntry>,
}

impl RevocationStore {
    /// New store pinned to one trusted Ed25519 signer key and one freshness bound.
    pub fn new(trusted_signer: [u8; 32], max_age_secs: i64) -> Self {
        Self {
            trusted_signer,
            max_age_secs,
            high_water: RevocationHighWater::new(),
            applied_head: None,
            applied_issued_at: None,
            revoked: BTreeMap::new(),
        }
    }

    /// New store using the [`REVOCATION_MAX_AGE_SECS`] default (`min(TTL/2, 6 h)` ceiling).
    pub fn with_default_freshness(trusted_signer: [u8; 32]) -> Self {
        Self::new(trusted_signer, REVOCATION_MAX_AGE_SECS)
    }

    /// Verify, freshness-check, and apply a list.
    pub fn apply(
        &mut self,
        list: &RevocationList,
        now: i64,
    ) -> Result<HighWaterOutcome, RevocationError> {
        list.verify(&self.trusted_signer)?;
        list.check_freshness(now, self.max_age_secs)?;
        let head = sha256(&list.head_bytes());
        let outcome = self.high_water.observe(list.seq)?;
        if outcome == HighWaterOutcome::Duplicate && self.applied_head != Some(head) {
            return Err(RevocationError::SeqEquivocation { seq: list.seq });
        }
        for entry in &list.entries {
            self.revoked.insert(entry.serial.clone(), entry.clone());
        }
        self.applied_head = Some(head);
        self.applied_issued_at = Some(list.issued_at);
        Ok(outcome)
    }

    /// `issued_at` of the most recently applied list, if any.
    pub fn applied_issued_at(&self) -> Option<i64> {
        self.applied_issued_at
    }

    /// Freshness of the *applied* list at `now`, evaluated **at use time**.
    ///
    /// This is the check-at-use half of the freshness gate (row #127 R-5.11):
    /// a list can be fresh when it is applied and stale by the time a new
    /// session asks for admission, so the daemon seam must re-check here and
    /// fail closed. Refusals: [`RevocationError::NoListApplied`] (nothing was
    /// ever applied), [`RevocationError::ListFromFuture`] (clock rollback
    /// signal), [`RevocationError::Stale`] (`now - issued_at > max_age`).
    pub fn check_admission_freshness(&self, now: i64) -> Result<i64, RevocationError> {
        let Some(issued_at) = self.applied_issued_at else {
            return Err(RevocationError::NoListApplied);
        };
        if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(RevocationError::ListFromFuture {
                issued_at,
                now,
                skew_secs: MAX_CLOCK_SKEW_SECS,
            });
        }
        let age_secs = now.saturating_sub(issued_at);
        if age_secs > self.max_age_secs {
            return Err(RevocationError::Stale {
                age_secs,
                max_age_secs: self.max_age_secs,
            });
        }
        Ok(age_secs)
    }

    /// Fail-closed membership check across every applied list.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked.contains_key(serial)
    }

    /// The applied entry for a revoked serial, if any.
    pub fn find_entry(&self, serial: &str) -> Option<&RevocationEntry> {
        self.revoked.get(serial)
    }

    /// Membership check honouring effective-from times.
    pub fn is_revoked_at(&self, serial: &str, now: i64) -> bool {
        self.revoked
            .get(serial)
            .is_some_and(|entry| entry.is_effective_at(now))
    }

    /// Number of distinct revoked serials held.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether no serials are held.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Applied high-water sequence.
    pub fn high_water(&self) -> Option<u64> {
        self.high_water.seq()
    }

    /// Digest of the most recently applied list head.
    pub fn applied_head(&self) -> Option<&[u8; 32]> {
        self.applied_head.as_ref()
    }

    /// The pinned trusted signer key.
    pub fn trusted_signer(&self) -> &[u8; 32] {
        &self.trusted_signer
    }

    /// Configured freshness bound in seconds.
    pub fn max_age_secs(&self) -> i64 {
        self.max_age_secs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KT event payloads + check-at-use admission gate — row #127 (R-5.11 +
// freshness): "…KT-logged, checked at every use".
//
// The two halves this section lands, both without adding machinery:
//
// * **KT-logged**: every decision the gate makes is expressed as a
//   [`RevocationEventV1`] payload. The payload is *appended through the
//   existing key-transparency log* (`tallow::kt_log::KtLog::append_json` in
//   the root crate — no new log format, no new file type; the entry's
//   `payload_hash` binds this JSON exactly like every other KT event).
// * **Check at use**: [`RevocationGate::admit_new_session`] re-evaluates the
//   freshness bound at the moment a *new* session asks for admission, on the
//   caller's clock, and fails closed (`NoList` / `ListFromFuture` / `Stale` /
//   `Revoked`). Established sessions are out of scope here by design
//   (U-201 D-4 / ATK-2.3 mitigation 1: stale lists refuse *new* sessions).
// ─────────────────────────────────────────────────────────────────────────────

/// Schema version of the KT payload produced by [`RevocationEventV1`].
pub const KT_EVENT_VERSION: u8 = 1;
/// KT payload `kind`: a signed list verified, passed freshness, and applied.
pub const KT_KIND_LIST_APPLIED: &str = "revocation_list_applied";
/// KT payload `kind`: a list was refused (signature / freshness / sequence).
pub const KT_KIND_LIST_REFUSED: &str = "revocation_list_refused";
/// KT payload `kind`: a new-session admission passed the gate.
pub const KT_KIND_ADMISSION_ALLOWED: &str = "revocation_admission_allowed";
/// KT payload `kind`: a new-session admission was refused fail-closed.
pub const KT_KIND_ADMISSION_REFUSED: &str = "revocation_admission_refused";

/// Closed set of revocation event kinds (the KT payload `kind` field).
///
/// The serde representation is the pinned `KT_KIND_*` string — the payload a
/// KT consumer parses carries exactly those constants, not a derived name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationEventKind {
    /// `KT_KIND_LIST_APPLIED`.
    #[serde(rename = "revocation_list_applied")]
    ListApplied,
    /// `KT_KIND_LIST_REFUSED`.
    #[serde(rename = "revocation_list_refused")]
    ListRefused,
    /// `KT_KIND_ADMISSION_ALLOWED`.
    #[serde(rename = "revocation_admission_allowed")]
    AdmissionAllowed,
    /// `KT_KIND_ADMISSION_REFUSED`.
    #[serde(rename = "revocation_admission_refused")]
    AdmissionRefused,
}

impl RevocationEventKind {
    /// The stable wire string written into the KT payload (`kind` field).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListApplied => KT_KIND_LIST_APPLIED,
            Self::ListRefused => KT_KIND_LIST_REFUSED,
            Self::AdmissionAllowed => KT_KIND_ADMISSION_ALLOWED,
            Self::AdmissionRefused => KT_KIND_ADMISSION_REFUSED,
        }
    }
}

/// One revocation event, in the exact shape appended to the KT log.
///
/// Serialization is the KT payload; [`Self::to_kt_payload`] hands it to
/// `KtLog::append_json`. Optional fields are omitted (not nulled) so a
/// payload's bytes are deterministic and minimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEventV1 {
    /// Schema version ([`KT_EVENT_VERSION`]).
    pub v: u8,
    /// Event kind ([`RevocationEventKind`]).
    pub kind: RevocationEventKind,
    /// Unix seconds the event was observed (caller's monotonic-guarded clock).
    pub at: i64,
    /// Hex Ed25519 verifying key of the trusted revocation signer.
    pub signer: String,
    /// List sequence number, when a list is involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// List `issued_at`, when a list is involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    /// Hex SHA-256 of the list head, when one was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha256: Option<String>,
    /// Number of entries in the list, when one is involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<usize>,
    /// The identity serial under admission (or the revoked serial).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Machine-readable refusal reason (`no_list`, `stale`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Age of the applied list at decision time, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<i64>,
}

impl RevocationEventV1 {
    /// Event for a successfully applied list. `age_secs` is the list age the
    /// apply-time freshness gate observed; `head` is [`RevocationStore::applied_head`].
    pub fn list_applied(
        signer: &[u8; 32],
        list: &RevocationList,
        head: &[u8; 32],
        age_secs: i64,
        at: i64,
    ) -> Self {
        Self {
            v: KT_EVENT_VERSION,
            kind: RevocationEventKind::ListApplied,
            at,
            signer: hex::encode(signer),
            seq: Some(list.seq),
            issued_at: Some(list.issued_at),
            head_sha256: Some(hex::encode(head)),
            entry_count: Some(list.entries.len()),
            serial: None,
            reason: None,
            age_secs: Some(age_secs),
        }
    }

    /// Event for a refused list (signature / freshness / sequence). `reason`
    /// is the machine-readable error kind (see [`refusal_kind`]).
    pub fn list_refused(signer: &[u8; 32], list: &RevocationList, reason: &str, at: i64) -> Self {
        Self {
            v: KT_EVENT_VERSION,
            kind: RevocationEventKind::ListRefused,
            at,
            signer: hex::encode(signer),
            seq: Some(list.seq),
            issued_at: Some(list.issued_at),
            head_sha256: None,
            entry_count: Some(list.entries.len()),
            serial: None,
            reason: Some(reason.to_string()),
            age_secs: None,
        }
    }

    /// Event for an admission decision (allowed or refused), from a permit /
    /// refusal and the emitting gate's store.
    pub fn admission(
        signer: &[u8; 32],
        verdict: Result<&AdmissionPermit, &AdmissionRefusal>,
        store: &RevocationStore,
        at: i64,
    ) -> Self {
        let head_sha256 = store.applied_head().map(hex::encode);
        match verdict {
            Ok(permit) => Self {
                v: KT_EVENT_VERSION,
                kind: RevocationEventKind::AdmissionAllowed,
                at,
                signer: hex::encode(signer),
                seq: store.high_water(),
                issued_at: store.applied_issued_at(),
                head_sha256,
                entry_count: None,
                serial: permit.serial.clone(),
                reason: None,
                age_secs: Some(permit.age_secs),
            },
            Err(refusal) => Self {
                v: KT_EVENT_VERSION,
                kind: RevocationEventKind::AdmissionRefused,
                at,
                signer: hex::encode(signer),
                seq: store.high_water(),
                issued_at: store.applied_issued_at(),
                head_sha256,
                entry_count: None,
                serial: refusal.serial().map(str::to_string),
                reason: Some(refusal.as_str().to_string()),
                age_secs: refusal.age_secs(),
            },
        }
    }

    /// The KT payload — append with `KtLog::append_json` (root crate). The KT
    /// entry's `payload_hash` binds exactly these bytes.
    pub fn to_kt_payload(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("revocation event is plain JSON data")
    }
}

/// Machine-readable kind of a [`RevocationError`] — the `reason` string in
/// [`RevocationEventV1::list_refused`] and daemon-side diagnostics. Exhaustive
/// by construction: a new error variant must be classified here.
pub fn refusal_kind(err: &RevocationError) -> &'static str {
    match err {
        RevocationError::Stale { .. } => "stale",
        RevocationError::ListFromFuture { .. } => "list_from_future",
        RevocationError::SeqRegression { .. } => "seq_regression",
        RevocationError::SeqEquivocation { .. } => "seq_equivocation",
        RevocationError::EntrySignatureInvalid { .. } => "entry_signature_invalid",
        RevocationError::ListSignatureInvalid => "list_signature_invalid",
        RevocationError::EmptySerial => "empty_serial",
        RevocationError::SignatureLength { .. } => "signature_length",
        RevocationError::UnsupportedVersion(_) => "unsupported_version",
        RevocationError::NoListApplied => "no_list_applied",
    }
}

/// Why a *new session* was refused admission by [`RevocationGate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// Nothing has been applied — fail-closed (the gate has no policy evidence).
    NoList,
    /// The applied list's `issued_at` is ahead of the local clock beyond skew.
    ListFromFuture {
        /// Claimed issuance time.
        issued_at: i64,
    },
    /// The applied list has aged past the freshness bound at the moment of use.
    Stale {
        /// Observed age (`now - issued_at`).
        age_secs: i64,
        /// The configured bound (`min(ttl/2, 6 h)` when derived from a TTL).
        max_age_secs: i64,
        /// The list's `issued_at`.
        issued_at: i64,
    },
    /// The presented identity is on the applied list, effective at `now`.
    Revoked {
        /// The revoked identity serial.
        serial: String,
        /// Why it was revoked.
        reason: RevocationReason,
        /// Effective-from unix seconds of the entry.
        not_before: i64,
    },
}

impl AdmissionRefusal {
    /// Machine-readable code (`revocation_*` codes are derived by callers).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoList => "no_list",
            Self::ListFromFuture { .. } => "list_from_future",
            Self::Stale { .. } => "stale",
            Self::Revoked { .. } => "revoked",
        }
    }

    /// The serial involved, when the refusal is identity-specific.
    pub fn serial(&self) -> Option<&str> {
        match self {
            Self::Revoked { serial, .. } => Some(serial),
            _ => None,
        }
    }

    /// The list age observed at refusal, when the refusal is freshness-specific.
    pub fn age_secs(&self) -> Option<i64> {
        match self {
            Self::Stale { age_secs, .. } => Some(*age_secs),
            _ => None,
        }
    }
}

/// A granted admission: which applied list and age admitted the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPermit {
    /// Age of the applied list at admission.
    pub age_secs: i64,
    /// Applied high-water sequence (always set after a successful admission).
    pub list_seq: u64,
    /// The checked identity serial, when one was presented.
    pub serial: Option<String>,
}

/// Check-at-use admission gate — the daemon's new-session seam calls
/// [`Self::admit_new_session`] before minting; it re-evaluates the freshness
/// bound *at use* and fails closed on every refusal path.
///
/// The gate wraps one [`RevocationStore`]; `apply_list` is the only way lists
/// enter, so authenticity → freshness → high-water ordering is the store's,
/// unchanged. `for_ttl` derives the bound the report pins: `min(ttl/2, 6 h)`.
#[derive(Debug)]
pub struct RevocationGate {
    store: RevocationStore,
}

impl RevocationGate {
    /// New gate with an explicit freshness bound in seconds.
    pub fn new(trusted_signer: [u8; 32], max_age_secs: i64) -> Self {
        Self {
            store: RevocationStore::new(trusted_signer, max_age_secs),
        }
    }

    /// New gate with the [`REVOCATION_MAX_AGE_SECS`] ceiling (6 h).
    pub fn with_default_freshness(trusted_signer: [u8; 32]) -> Self {
        Self::new(trusted_signer, REVOCATION_MAX_AGE_SECS)
    }

    /// New gate whose bound follows the SVID TTL: `freshness_bound(ttl)` =
    /// `min(ttl/2, 6 h)`, floored at 1 s (report §5.4 + ATK-2.3).
    pub fn for_ttl(trusted_signer: [u8; 32], ttl_secs: i64) -> Self {
        Self::new(trusted_signer, freshness_bound(ttl_secs))
    }

    /// The wrapped store (read-only).
    pub fn store(&self) -> &RevocationStore {
        &self.store
    }

    /// The pinned trusted signer key.
    pub fn trusted_signer(&self) -> &[u8; 32] {
        self.store.trusted_signer()
    }

    /// Configured freshness bound in seconds.
    pub fn max_age_secs(&self) -> i64 {
        self.store.max_age_secs()
    }

    /// Fail-closed membership check across every applied list.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.store.is_revoked(serial)
    }

    /// Apply a signed list, returning the outcome **and** the KT event for the
    /// decision (applied or refused — both are audit-worthy). The event is
    /// built whether or not the apply succeeded; the caller appends it.
    #[allow(clippy::type_complexity)]
    pub fn apply_list(
        &mut self,
        list: &RevocationList,
        now: i64,
    ) -> (Result<HighWaterOutcome, RevocationError>, RevocationEventV1) {
        match self.store.apply(list, now) {
            Ok(outcome) => {
                // Age the store itself computed during the apply-time freshness gate.
                let age = now.saturating_sub(list.issued_at).max(0);
                let head = *self
                    .store
                    .applied_head()
                    .expect("apply sets the head on success");
                let event = RevocationEventV1::list_applied(
                    self.store.trusted_signer(),
                    list,
                    &head,
                    age,
                    now,
                );
                (Ok(outcome), event)
            }
            Err(err) => {
                let event = RevocationEventV1::list_refused(
                    self.store.trusted_signer(),
                    list,
                    refusal_kind(&err),
                    now,
                );
                (Err(err), event)
            }
        }
    }

    /// Check **at use**: may a *new* session for `serial` (when presented) be
    /// admitted at `now`? Returns the permit/refusal **and** the KT event.
    ///
    /// Order: presence of an applied list → clock-rollback → freshness bound →
    /// membership (effective at `now`). Every refusal is fail-closed; the
    /// caller keeps established sessions untouched (U-201 D-4).
    #[allow(clippy::type_complexity)]
    pub fn admit_new_session(
        &self,
        now: i64,
        serial: Option<&str>,
    ) -> (Result<AdmissionPermit, AdmissionRefusal>, RevocationEventV1) {
        let verdict: Result<AdmissionPermit, AdmissionRefusal> =
            match self.store.check_admission_freshness(now) {
                Err(RevocationError::NoListApplied) => Err(AdmissionRefusal::NoList),
                Err(RevocationError::ListFromFuture { issued_at, .. }) => {
                    Err(AdmissionRefusal::ListFromFuture { issued_at })
                }
                Err(RevocationError::Stale {
                    age_secs,
                    max_age_secs,
                }) => {
                    let issued_at = self.store.applied_issued_at().unwrap_or(now);
                    Err(AdmissionRefusal::Stale {
                        age_secs,
                        max_age_secs,
                        issued_at,
                    })
                }
                // `check_admission_freshness` has exactly the three failure
                // shapes above; anything else would be a programming error and
                // must still fail closed.
                Err(_) => Err(AdmissionRefusal::NoList),
                Ok(age_secs) => match serial {
                    Some(serial) if self.store.is_revoked_at(serial, now) => {
                        let entry = self
                            .store
                            .find_entry(serial)
                            .expect("is_revoked_at implies an entry");
                        Err(AdmissionRefusal::Revoked {
                            serial: serial.to_string(),
                            reason: entry.reason,
                            not_before: entry.not_before,
                        })
                    }
                    other => Ok(AdmissionPermit {
                        age_secs,
                        list_seq: self
                            .store
                            .high_water()
                            .expect("fresh applied list implies a sequence"),
                        serial: other.map(str::to_string),
                    }),
                },
            };
        let event = RevocationEventV1::admission(
            self.store.trusted_signer(),
            verdict.as_ref(),
            &self.store,
            now,
        );
        (verdict, event)
    }
}

/// Length-prefixed field append (`u32` big-endian length + bytes) — unambiguous canonical form.
fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// SHA-256 digest helper.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Ed25519Signer {
        Ed25519Signer::keygen()
    }

    fn list_of(signer: &Ed25519Signer, seq: u64, issued_at: i64, serial: &str) -> RevocationList {
        let entry =
            RevocationEntry::sign(signer, serial, RevocationReason::KeyCompromise, issued_at)
                .expect("entry builds");
        RevocationList::sign(signer, seq, issued_at, vec![entry]).expect("list signs")
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn entry_sign_and_verify_roundtrip() {
        let key = signer();
        let entry =
            RevocationEntry::sign(&key, "svid-0x0001", RevocationReason::KeyCompromise, NOW)
                .unwrap();
        entry.verify(&key.verifying_key_bytes()).unwrap();
        assert_eq!(entry.signature.len(), SIGNATURE_LEN);
    }

    #[test]
    fn entry_signature_tamper_rejected() {
        let key = signer();
        let mut entry =
            RevocationEntry::sign(&key, "svid-0x0002", RevocationReason::Superseded, NOW).unwrap();
        entry.signature[0] ^= 0x01;
        assert_eq!(
            entry.verify(&key.verifying_key_bytes()),
            Err(RevocationError::EntrySignatureInvalid {
                serial: "svid-0x0002".into()
            })
        );
    }

    #[test]
    fn entry_field_tamper_rejected() {
        let key = signer();
        let mut entry =
            RevocationEntry::sign(&key, "svid-0x0003", RevocationReason::Superseded, NOW).unwrap();
        entry.reason = RevocationReason::AffiliationChanged;
        assert!(entry.verify(&key.verifying_key_bytes()).is_err());

        let mut entry2 =
            RevocationEntry::sign(&key, "svid-0x0003", RevocationReason::Superseded, NOW).unwrap();
        entry2.not_before += 1;
        assert!(entry2.verify(&key.verifying_key_bytes()).is_err());
    }

    #[test]
    fn entry_verify_under_other_key_rejected() {
        let key = signer();
        let other = signer();
        let entry =
            RevocationEntry::sign(&key, "svid-0x0004", RevocationReason::Unspecified, NOW).unwrap();
        assert!(entry.verify(&other.verifying_key_bytes()).is_err());
    }

    #[test]
    fn list_head_tamper_rejected() {
        let key = signer();
        let mut list = list_of(&key, 7, NOW, "svid-0x0005");
        list.verify(&key.verifying_key_bytes()).unwrap();
        list.seq = 99_999; // attacker tries to jam the high-water mark
        assert_eq!(
            list.verify(&key.verifying_key_bytes()),
            Err(RevocationError::ListSignatureInvalid)
        );
    }

    #[test]
    fn list_verify_rejects_tampered_entry_before_apply() {
        let key = signer();
        let mut list = list_of(&key, 8, NOW, "svid-0x0006");
        list.entries[0].serial = "svid-attacker".into();
        // Head digest binds the entry set, so the head check fires first.
        assert!(list.verify(&key.verifying_key_bytes()).is_err());
    }

    #[test]
    fn stale_list_refused() {
        let key = signer();
        let list = list_of(&key, 1, NOW - 7 * 3600, "svid-0x0007");
        assert_eq!(
            list.check_freshness(NOW, REVOCATION_MAX_AGE_SECS),
            Err(RevocationError::Stale {
                age_secs: 7 * 3600,
                max_age_secs: REVOCATION_MAX_AGE_SECS
            })
        );
        // Fresh inside the bound.
        let fresh = list_of(&key, 1, NOW - 60, "svid-0x0007");
        assert_eq!(
            fresh.check_freshness(NOW, REVOCATION_MAX_AGE_SECS).unwrap(),
            60
        );
    }

    #[test]
    fn freshness_bound_is_min_half_ttl_and_6h() {
        assert_eq!(freshness_bound(4 * 3600), 2 * 3600);
        assert_eq!(freshness_bound(48 * 3600), REVOCATION_MAX_AGE_SECS);
        assert_eq!(freshness_bound(0), 1);
    }

    #[test]
    fn future_dated_list_refused() {
        let key = signer();
        let list = list_of(&key, 2, NOW + MAX_CLOCK_SKEW_SECS + 1, "svid-0x0008");
        assert_eq!(
            list.check_freshness(NOW, REVOCATION_MAX_AGE_SECS),
            Err(RevocationError::ListFromFuture {
                issued_at: NOW + MAX_CLOCK_SKEW_SECS + 1,
                now: NOW,
                skew_secs: MAX_CLOCK_SKEW_SECS
            })
        );
    }

    #[test]
    fn high_water_regression_refused() {
        let mut mark = RevocationHighWater::new();
        assert_eq!(mark.observe(5).unwrap(), HighWaterOutcome::Advanced);
        assert_eq!(mark.observe(5).unwrap(), HighWaterOutcome::Duplicate);
        assert!(mark.refuses(4));
        assert_eq!(
            mark.observe(4),
            Err(RevocationError::SeqRegression {
                high_water: 5,
                incoming: 4
            })
        );
        // Refusal must not move the mark.
        assert_eq!(mark.seq(), Some(5));
        assert_eq!(mark.observe(6).unwrap(), HighWaterOutcome::Advanced);
    }

    #[test]
    fn is_revoked_matches_serial_and_effective_time() {
        let key = signer();
        let entry =
            RevocationEntry::sign(&key, "svid-a", RevocationReason::CertificateHold, NOW + 100)
                .unwrap();
        let list = RevocationList::sign(&key, 1, NOW, vec![entry]).unwrap();
        assert!(is_revoked(&list, "svid-a"));
        assert!(!is_revoked(&list, "svid-b"));
        assert!(list.is_revoked_at("svid-a", NOW + 100));
        assert!(!list.is_revoked_at("svid-a", NOW + 99));
        assert_eq!(list.entry_count(), 1);
        assert_eq!(
            list.find("svid-a").unwrap().reason,
            RevocationReason::CertificateHold
        );
    }

    #[test]
    fn store_applies_merges_and_refuses_regression_and_equivocation() {
        let key = signer();
        let mut store = RevocationStore::with_default_freshness(key.verifying_key_bytes());

        let first = list_of(&key, 10, NOW, "svid-x");
        assert_eq!(
            store.apply(&first, NOW).unwrap(),
            HighWaterOutcome::Advanced
        );
        assert!(store.is_revoked("svid-x"));
        assert_eq!(store.high_water(), Some(10));
        assert_eq!(store.len(), 1);

        // Idempotent re-apply of the *same* list (same seq, same head).
        assert_eq!(
            store.apply(&first, NOW).unwrap(),
            HighWaterOutcome::Duplicate
        );

        // Same seq, different content -> equivocation refused, store unchanged.
        let fork = list_of(&key, 10, NOW, "svid-y");
        assert_eq!(
            store.apply(&fork, NOW),
            Err(RevocationError::SeqEquivocation { seq: 10 })
        );
        assert!(!store.is_revoked("svid-y"));

        // Regression refused.
        let older = list_of(&key, 9, NOW, "svid-x");
        assert_eq!(
            store.apply(&older, NOW),
            Err(RevocationError::SeqRegression {
                high_water: 10,
                incoming: 9
            })
        );

        // Stale refused even at the newest seq.
        let stale = list_of(&key, 11, NOW - 7 * 3600, "svid-z");
        assert!(matches!(
            store.apply(&stale, NOW),
            Err(RevocationError::Stale { .. })
        ));
        assert_eq!(store.high_water(), Some(10));

        // Advance with a second serial; merge is additive.
        let next = list_of(&key, 12, NOW, "svid-y");
        assert_eq!(store.apply(&next, NOW).unwrap(), HighWaterOutcome::Advanced);
        assert!(store.is_revoked("svid-x") && store.is_revoked("svid-y"));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_rejects_wrong_signer_and_unsigned_entries() {
        let key = signer();
        let rogue = signer();
        let mut store = RevocationStore::with_default_freshness(key.verifying_key_bytes());
        let forged = list_of(&rogue, 1, NOW, "svid-f");
        assert_eq!(
            store.apply(&forged, NOW),
            Err(RevocationError::ListSignatureInvalid)
        );
        assert!(store.is_empty());

        // An entry that never got signed cannot be sealed into a list.
        let unsigned =
            RevocationEntry::unsigned("svid-u", RevocationReason::Unspecified, NOW).unwrap();
        assert_eq!(
            RevocationList::sign(&key, 1, NOW, vec![unsigned]),
            Err(RevocationError::SignatureLength {
                expected: SIGNATURE_LEN,
                got: 0
            })
        );
    }

    #[test]
    fn empty_serial_and_bad_version_rejected() {
        assert_eq!(
            RevocationEntry::unsigned("   ", RevocationReason::Unspecified, NOW),
            Err(RevocationError::EmptySerial)
        );
        let key = signer();
        let mut list = list_of(&key, 1, NOW, "svid-v");
        list.version = 9;
        assert_eq!(
            list.verify(&key.verifying_key_bytes()),
            Err(RevocationError::UnsupportedVersion(9))
        );
    }

    // ── Row #127: check-at-use gate + KT event payloads ─────────────────────

    /// Multi-entry list helper: `(serial, reason, not_before)` triples.
    fn list_with(
        signer: &Ed25519Signer,
        seq: u64,
        issued_at: i64,
        entries: &[(&str, RevocationReason, i64)],
    ) -> RevocationList {
        let entries = entries
            .iter()
            .map(|(serial, reason, not_before)| {
                RevocationEntry::sign(signer, *serial, *reason, *not_before).expect("entry builds")
            })
            .collect();
        RevocationList::sign(signer, seq, issued_at, entries).expect("list signs")
    }

    #[test]
    fn store_freshness_at_use_shapes() {
        let key = signer();
        let mut store = RevocationStore::new(key.verifying_key_bytes(), 3600);
        // Nothing applied → fail-closed verdict.
        assert_eq!(
            store.check_admission_freshness(NOW),
            Err(RevocationError::NoListApplied)
        );
        assert_eq!(store.applied_issued_at(), None);

        let list = list_of(&key, 1, NOW - 60, "svid-a");
        store.apply(&list, NOW).unwrap();
        assert_eq!(store.applied_issued_at(), Some(NOW - 60));
        assert_eq!(store.check_admission_freshness(NOW).unwrap(), 60);
        assert_eq!(
            store.check_admission_freshness(NOW + 3600 + 1),
            Err(RevocationError::Stale {
                age_secs: 3661,
                max_age_secs: 3600
            })
        );
    }

    #[test]
    fn gate_for_ttl_derives_min_half_ttl_and_ceiling() {
        let key = signer();
        let gate = RevocationGate::for_ttl(key.verifying_key_bytes(), 4 * 3600);
        assert_eq!(gate.max_age_secs(), 2 * 3600);
        let gate = RevocationGate::for_ttl(key.verifying_key_bytes(), 48 * 3600);
        assert_eq!(gate.max_age_secs(), REVOCATION_MAX_AGE_SECS);
        let gate = RevocationGate::with_default_freshness(key.verifying_key_bytes());
        assert_eq!(gate.max_age_secs(), REVOCATION_MAX_AGE_SECS);
    }

    #[test]
    fn gate_refuses_admission_with_no_list_applied_fail_closed() {
        let key = signer();
        let gate = RevocationGate::with_default_freshness(key.verifying_key_bytes());
        let (verdict, event) = gate.admit_new_session(NOW, Some("svid-new"));
        assert_eq!(verdict, Err(AdmissionRefusal::NoList));
        assert_eq!(event.kind, RevocationEventKind::AdmissionRefused);
        assert_eq!(event.reason.as_deref(), Some("no_list"));
        assert_eq!(event.serial, None); // no list → no identity evidence
        assert_eq!(event.seq, None);
        assert_eq!(event.v, KT_EVENT_VERSION);
    }

    #[test]
    fn gate_admits_clean_identity_on_fresh_list() {
        let key = signer();
        let mut gate = RevocationGate::for_ttl(key.verifying_key_bytes(), 8 * 3600);
        let list = list_of(&key, 1, NOW - 90, "svid-revoked");
        let (outcome, applied) = gate.apply_list(&list, NOW);
        assert_eq!(outcome.unwrap(), HighWaterOutcome::Advanced);

        let (verdict, event) = gate.admit_new_session(NOW, Some("svid-clean"));
        let permit = verdict.expect("fresh list admits a clean identity");
        assert_eq!(permit.age_secs, 90);
        assert_eq!(permit.list_seq, 1);
        assert_eq!(permit.serial.as_deref(), Some("svid-clean"));
        assert_eq!(event.kind, RevocationEventKind::AdmissionAllowed);
        assert_eq!(event.age_secs, Some(90));
        assert_eq!(event.serial.as_deref(), Some("svid-clean"));
        assert!(event.head_sha256.is_some());

        // No serial presented: freshness still enforced, membership moot.
        let (verdict, _) = gate.admit_new_session(NOW, None);
        assert!(verdict.is_ok());

        // Applied-event cross-check: the event head is the store's head.
        assert_eq!(
            applied.head_sha256.as_deref(),
            gate.store()
                .applied_head()
                .map(|h| hex::encode(h))
                .as_deref()
        );
    }

    #[test]
    fn gate_refuses_stale_list_at_use_even_when_fresh_at_apply() {
        let key = signer();
        let mut gate = RevocationGate::for_ttl(key.verifying_key_bytes(), 4 * 3600); // bound 2 h
                                                                                     // Fresh at apply time…
        let list = list_of(&key, 1, NOW, "svid-a");
        assert!(gate.apply_list(&list, NOW).0.is_ok());
        assert!(gate.admit_new_session(NOW + 2 * 3600, None).0.is_ok());

        // …stale one second past the bound at the moment of use.
        let (verdict, event) = gate.admit_new_session(NOW + 2 * 3600 + 1, None);
        assert_eq!(
            verdict,
            Err(AdmissionRefusal::Stale {
                age_secs: 2 * 3600 + 1,
                max_age_secs: 2 * 3600,
                issued_at: NOW,
            })
        );
        assert_eq!(event.kind, RevocationEventKind::AdmissionRefused);
        assert_eq!(event.reason.as_deref(), Some("stale"));
        assert_eq!(event.age_secs, Some(2 * 3600 + 1));
        // The applied revoked set stays queryable (established-session checks
        // are not the admission gate's business).
        assert!(gate.is_revoked("svid-a"));
    }

    #[test]
    fn gate_refuses_revoked_identity_and_honours_not_before() {
        let key = signer();
        let mut gate = RevocationGate::with_default_freshness(key.verifying_key_bytes());
        let list = list_with(
            &key,
            7,
            NOW - 10,
            &[("svid-bad", RevocationReason::KeyCompromise, NOW + 100)],
        );
        gate.apply_list(&list, NOW).0.unwrap();

        // Before the entry's effective-from: not yet revoked.
        let (verdict, _) = gate.admit_new_session(NOW + 99, Some("svid-bad"));
        assert!(verdict.is_ok());

        // Effective: refused with the applied entry's reason.
        let (verdict, event) = gate.admit_new_session(NOW + 100, Some("svid-bad"));
        assert_eq!(
            verdict,
            Err(AdmissionRefusal::Revoked {
                serial: "svid-bad".to_string(),
                reason: RevocationReason::KeyCompromise,
                not_before: NOW + 100,
            })
        );
        assert_eq!(event.reason.as_deref(), Some("revoked"));
        assert_eq!(event.serial.as_deref(), Some("svid-bad"));

        // A different identity on the same list is admitted.
        let (verdict, _) = gate.admit_new_session(NOW + 100, Some("svid-good"));
        assert!(verdict.is_ok());
    }

    #[test]
    fn gate_refuses_clock_rollback_at_use() {
        let key = signer();
        let mut gate = RevocationGate::with_default_freshness(key.verifying_key_bytes());
        let list = list_of(&key, 1, NOW, "svid-a");
        assert!(gate.apply_list(&list, NOW).0.is_ok());

        // Local clock jumps back a day: the applied list is now "from the
        // future" beyond skew → fail closed (ATK-2.8 rollback signal).
        let (verdict, event) = gate.admit_new_session(NOW - 24 * 3600, None);
        assert_eq!(
            verdict,
            Err(AdmissionRefusal::ListFromFuture { issued_at: NOW })
        );
        assert_eq!(event.reason.as_deref(), Some("list_from_future"));
    }

    #[test]
    fn gate_apply_list_refusals_emit_refused_events() {
        let key = signer();
        let rogue = signer();
        let mut gate = RevocationGate::with_default_freshness(key.verifying_key_bytes());

        // Stale at apply.
        let stale = list_of(&key, 1, NOW - 7 * 3600, "svid-s");
        let (outcome, event) = gate.apply_list(&stale, NOW);
        assert!(matches!(outcome, Err(RevocationError::Stale { .. })));
        assert_eq!(event.kind, RevocationEventKind::ListRefused);
        assert_eq!(event.reason.as_deref(), Some("stale"));
        assert_eq!(event.seq, Some(1));

        // Wrong signer.
        let forged = list_of(&rogue, 2, NOW, "svid-f");
        let (outcome, event) = gate.apply_list(&forged, NOW);
        assert_eq!(outcome, Err(RevocationError::ListSignatureInvalid));
        assert_eq!(event.reason.as_deref(), Some("list_signature_invalid"));

        // Fresh + authentic applies; then regression and equivocation refuse.
        let ok = list_of(&key, 10, NOW, "svid-a");
        assert!(gate.apply_list(&ok, NOW).0.is_ok());
        let older = list_of(&key, 9, NOW, "svid-b");
        let (outcome, event) = gate.apply_list(&older, NOW);
        assert!(matches!(
            outcome,
            Err(RevocationError::SeqRegression { .. })
        ));
        assert_eq!(event.reason.as_deref(), Some("seq_regression"));
        let fork = list_of(&key, 10, NOW, "svid-c");
        let (outcome, event) = gate.apply_list(&fork, NOW);
        assert_eq!(outcome, Err(RevocationError::SeqEquivocation { seq: 10 }));
        assert_eq!(event.reason.as_deref(), Some("seq_equivocation"));
        // Refusals did not disturb the applied state.
        assert!(
            gate.is_revoked("svid-a") && !gate.is_revoked("svid-b") && !gate.is_revoked("svid-c")
        );
        assert_eq!(gate.store().high_water(), Some(10));
    }

    #[test]
    fn event_payloads_are_stable_deterministic_json() {
        let key = signer();
        let list = list_of(&key, 3, NOW - 5, "svid-a");
        let applied =
            RevocationEventV1::list_applied(&key.verifying_key_bytes(), &list, &[7u8; 32], 5, NOW);
        let payload = applied.to_kt_payload();
        assert_eq!(payload["v"], KT_EVENT_VERSION);
        assert_eq!(payload["kind"], KT_KIND_LIST_APPLIED);
        assert_eq!(payload["seq"], 3);
        assert_eq!(payload["entry_count"], 1);
        assert_eq!(payload["head_sha256"], hex::encode([7u8; 32]));
        assert!(
            payload.get("serial").is_none(),
            "absent optionals are omitted"
        );

        // Deterministic bytes (what the KT `payload_hash` binds) + round trip.
        let bytes_a = serde_json::to_vec(&applied.to_kt_payload()).unwrap();
        let bytes_b = serde_json::to_vec(&applied.to_kt_payload()).unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded: RevocationEventV1 = serde_json::from_slice(&bytes_a).unwrap();
        assert_eq!(decoded, applied);

        // The other three kinds serialize with their pinned strings.
        let refused = RevocationEventV1::list_refused(
            &key.verifying_key_bytes(),
            &list,
            refusal_kind(&RevocationError::NoListApplied),
            NOW,
        );
        assert_eq!(refused.to_kt_payload()["kind"], KT_KIND_LIST_REFUSED);
        assert_eq!(refused.to_kt_payload()["reason"], "no_list_applied");
    }

    #[test]
    fn refusal_kind_covers_every_error_variant() {
        // Spot-pin the stable strings the daemon and KT payloads depend on.
        assert_eq!(
            refusal_kind(&RevocationError::NoListApplied),
            "no_list_applied"
        );
        assert_eq!(
            refusal_kind(&RevocationError::Stale {
                age_secs: 1,
                max_age_secs: 2
            }),
            "stale"
        );
        assert_eq!(
            refusal_kind(&RevocationError::SeqEquivocation { seq: 1 }),
            "seq_equivocation"
        );
        assert_eq!(
            refusal_kind(&RevocationError::ListSignatureInvalid),
            "list_signature_invalid"
        );
    }
}
