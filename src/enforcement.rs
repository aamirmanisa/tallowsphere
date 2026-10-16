//! Read + export enforcement composition — A2.2.1 gates under an A2.2.2
//! redaction-receipt requirement (frozen interface §3, task AGT-93).
//!
//! [`crate::access_class`] is the pure policy core (*may* this audience read
//! or export this class?). [`crate::redaction`] is the release pipeline
//! (*what exactly* leaves, pinned by sha256 on both sides). This module is
//! the composition point where a release path passes through both, with one
//! call and one error shape per operation:
//!
//! - [`enforce_read`] — pass-through over
//!   [`check_read`](crate::access_class::check_read); a denial becomes
//!   [`EnforceError::ReadDenied`] carrying the stable
//!   [`code`](crate::access_class::DenyReason::code) (e.g. `"deny.sealed"`).
//! - [`enforce_export`] — the composed export gate. A release leaves only
//!   when **all three** hold, in this order:
//!   1. **Receipt present** — `receipt_hash` non-empty, else
//!      [`EnforceError::MissingReceipt`] (checked before anything else).
//!   2. **Receipt intact and binding** — the receipt must pass
//!      [`verify_release`](crate::redaction::verify_release) (tamper-evident
//!      recompute of the released side), and must certify *this* release:
//!      `receipt.released_hash == receipt_hash`. Failures are
//!      [`EnforceError::Redaction`] with a stable code
//!      (`"redaction.receipt-unverified"` / `"redaction.receipt-hash-mismatch"`).
//!   3. **Policy admits** — the A2.2.1 row for
//!      `(class, audience, embargo_active)` must allow the export, else
//!      [`EnforceError::ExportDenied`] with the deny code (e.g.
//!      `"deny.embargo-active"`).
//!
//!   Only then is a [`ReleasedExport`] produced: the derivative bytes passed
//!   through unchanged, the receipt hash, the sealed original's hash, the
//!   requested caveats (sorted, deduplicated), and the caller-supplied
//!   timestamp.
//!
//! # Deny-by-default, composed
//! Both underlying gates are allowlists (see `access_class` docs); this
//! layer adds the receipt requirement *on top*, so an export admits only
//! when a present receipt, an intact receipt, **and** a policy admission all
//! agree. Refusals never return a bare `false`: they carry a stable machine
//! code for the audit ledger ([`DenyReason::code`](crate::access_class::DenyReason::code)
//! or one of the two `redaction.receipt-*` codes), matching the house
//! convention that every refusal is auditable with *why*.
//!
//! # `original_sha256` choice (frozen §3 offered two adaptations)
//! [`ReleasedExport::original_sha256`] is pinned to `receipt.original_hash` —
//! the sha256 hex of the **sealed original** under redaction.rs's canonical
//! compact `serde_json::to_vec` convention ("hash the original per
//! redaction.rs semantics"). The alternative (sha256-hex of the input
//! derivative bytes) was rejected: the derivative is released unchanged, so
//! re-hashing it would duplicate the released-side pin that `receipt_hash`
//! already carries via the receipt (`receipt.released_hash`). Pinning the
//! sealed original instead is what the field name says, and it is the
//! A2.2.2 audit story: original hash + released hash + receipt, chained.
//! Cross-checked in tests: `sha256_hex(canonical original bytes) ==
//! receipt.original_hash == ReleasedExport.original_sha256`.
//!
//! # Gate call choice
//! The frozen text names "`may_export(...)` gate". `may_export` is
//! bool-only; this layer needs the denial *code* for its error payload, so
//! it calls [`check_export`](crate::access_class::check_export) — the exact
//! `Result` form `may_export` wraps, same rule table. (`redaction::export_gate`
//! is the redaction-side mirror of the same call with identical codes; this
//! layer owns the [`EnforceError`] shape, so it maps the `DenyReason`
//! directly.)
//!
//! # Scope / integration
//! Pure functions: no I/O, no clock (`now_ms` is supplied by the caller so
//! exports are reproducible and replayable), no global state. sha256 uses
//! the crate's existing `sha2` dependency — same convention as
//! `crate::redaction` / `crate::raw_store` content addresses (lowercase hex,
//! 64 chars). Consumed by the CLI vault path through [`crate::vault::access`]
//! (R1 wiring: read paths wired 2026-09-28; the export/release wiring lands in
//! the same wave).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::access_class::{AccessClass, Audience, check_export, check_read};
use crate::caveats::release_check;
use crate::redaction::{ReleaseBundle, verify_release};

/// Stable code: a receipt was supplied but fails
/// `crate::redaction::verify_release` (tampered or internally inconsistent).
const CODE_RECEIPT_UNVERIFIED: &str = "redaction.receipt-unverified";

/// Stable code: the receipt verifies, but it does not certify the
/// caller-supplied `receipt_hash` (`receipt.released_hash != receipt_hash`).
const CODE_RECEIPT_HASH_MISMATCH: &str = "redaction.receipt-hash-mismatch";

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the composed enforcement layer.
///
/// `ReadDenied`/`ExportDenied` carry the stable deny machine code from
/// [`DenyReason::code`](crate::access_class::DenyReason::code); the
/// `Redaction` variant carries one of the `redaction.receipt-*` codes.
/// Serde-round-trippable for ledger records; `Display` renders a human
/// audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforceError {
    /// A read was refused; carries the stable deny code (e.g. `"deny.sealed"`).
    ReadDenied(String),
    /// An export was refused by the A2.2.1 gate; carries the stable deny
    /// code (e.g. `"deny.embargo-active"`, `"deny.no-export-path"`).
    ExportDenied(String),
    /// No redaction receipt was supplied for an export (empty/whitespace
    /// `receipt_hash`) — no receipt, no release.
    MissingReceipt,
    /// The supplied redaction receipt failed validation; carries a stable
    /// receipt-failure code (`"redaction.receipt-unverified"` or
    /// `"redaction.receipt-hash-mismatch"`).
    Redaction(String),
}

impl fmt::Display for EnforceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnforceError::ReadDenied(code) => write!(f, "read denied: {code}"),
            EnforceError::ExportDenied(code) => write!(f, "export denied: {code}"),
            EnforceError::MissingReceipt => {
                write!(f, "export denied: redaction receipt required")
            }
            EnforceError::Redaction(code) => {
                write!(f, "redaction receipt invalid: {code}")
            }
        }
    }
}

impl std::error::Error for EnforceError {}

// ── Hashing helper ───────────────────────────────────────────────────────────

/// sha256 of `bytes`, lowercase hex (64 chars) — the same convention as
/// [`crate::redaction`] and `crate::raw_store` content addresses.
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for &b in digest.iter() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ── Read enforcement ─────────────────────────────────────────────────────────

/// Enforce a vault read of `class` material for `audience`.
///
/// Pass-through over [`check_read`](crate::access_class::check_read): `Ok(())`
/// iff the A2.2.1 matrix admits the read; a denial is mapped to
/// [`EnforceError::ReadDenied`] with the stable `DenyReason::code()` string
/// (`"deny.sealed"`, `"deny.audience-not-admitted"`).
///
/// Sealed material is denied to every audience and `Open` is admitted to
/// everyone, per the frozen A2.2.1 starter policy (pinned by test).
pub fn enforce_read(class: AccessClass, audience: Audience) -> Result<(), EnforceError> {
    check_read(class, audience)
        .map_err(|reason| EnforceError::ReadDenied(reason.code().to_string()))
}

// ── Export enforcement ───────────────────────────────────────────────────────

/// One pending export/release request.
///
/// - `derivative` — the bytes that would leave the vault (already produced
///   by the redaction pipeline; passed through unchanged on release).
/// - `required_caveats` — caveats the caller wants attached to the release;
///   they are sorted and deduplicated into the [`ReleasedExport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRequest {
    /// Classification of the material being exported.
    pub class: AccessClass,
    /// Audience the export is being performed for.
    pub audience: Audience,
    /// Whether an embargo window is currently active.
    pub embargo_active: bool,
    /// The released derivative bytes (input to this gate; released unchanged).
    pub derivative: Vec<u8>,
    /// Caveats the caller requests on the release (sorted + deduped on release).
    pub required_caveats: Vec<String>,
}

/// A released export, chained to its redaction receipt.
///
/// Produced only by [`enforce_export`]; serde-round-trippable for audit
/// ledger records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedExport {
    /// The released derivative bytes — byte-identical to the request's input.
    pub derivative: Vec<u8>,
    /// Hash the release is certified by (the receipt's released-side sha256,
    /// lowercase hex, 64 chars).
    pub receipt_hash: String,
    /// sha256 hex of the *sealed original* (`receipt.original_hash` under
    /// redaction.rs semantics) — see module docs for the adaptation argument.
    pub original_sha256: String,
    /// Requested caveats, ascending (ASCII), deduplicated.
    pub caveats: Vec<String>,
    /// Caller-supplied release time (unix ms).
    pub released_ms: i64,
}

/// Whether the composed export gate **evaluates** a release's dissemination
/// caveats or merely renders them.
///
/// This exists because of a real, verified gap: `crate::caveats::release_check`
/// was written and documented as "checked by `release_check` just before
/// anything leaves", and had **no production call site** — step 5 below sorted
/// and deduplicated `required_caveats` onto the release without evaluating them,
/// so a release marked `NO-THIRD-PARTY` reached [`Audience::ThirdParty`].
///
/// [`CaveatGate::RenderOnly`] is that historical behaviour and remains the
/// default, so nothing changes until an operator asks for it. See
/// `caveat_gate_enforce_refuses_the_laundering_case_render_only_admits`, which
/// pins **both** sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaveatGate {
    /// Historical behaviour: render the markings, never evaluate them.
    #[default]
    RenderOnly,
    /// Evaluate them with [`release_check`](crate::caveats::release_check)
    /// before any release is produced.
    Enforce,
}

impl CaveatGate {
    /// Opt in with `TALLOW_CAVEAT_GATE=enforce` (case-insensitive; any other
    /// value, including unset, is [`CaveatGate::RenderOnly`]). Reading the
    /// environment is the *caller's* job — [`ReleaseAuthority::from_env`] is the
    /// boundary that does it — so the decision path itself stays pure.
    pub fn from_env() -> Self {
        match std::env::var("TALLOW_CAVEAT_GATE") {
            Ok(v) if v.trim().eq_ignore_ascii_case("enforce") => CaveatGate::Enforce,
            _ => CaveatGate::RenderOnly,
        }
    }

    /// Stable token for audit lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            CaveatGate::RenderOnly => "render-only",
            CaveatGate::Enforce => "enforce",
        }
    }
}

/// Who authorises a release, and under which caveat policy.
///
/// Kept separate from [`ExportRequest`] because these are *authorisation*
/// inputs, not properties of the material: a request describes what would
/// leave, an authority says who says it may. `Default` is exactly today's
/// behaviour — render-only, no role, no approval — so a caller that has not
/// been taught about caveats is unaffected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReleaseAuthority {
    /// Whether caveats are evaluated or only rendered.
    pub gate: CaveatGate,
    /// The role the release is made *for*, unlocking `REL-<role>`.
    pub role: Option<String>,
    /// The originator's explicit approval, unlocking `ORCON`.
    pub originator_approved: bool,
}

impl ReleaseAuthority {
    /// The operator's switch, read at the boundary. `role` and
    /// `originator_approved` stay unset here: with the gate on, a release
    /// carrying `ORCON` or `REL-*` is therefore **refused** rather than
    /// released, until the call site can express them. That is fail-closed by
    /// design, and the reason this defaults to render-only.
    pub fn from_env() -> Self {
        ReleaseAuthority {
            gate: CaveatGate::from_env(),
            role: None,
            originator_approved: false,
        }
    }
}

impl From<CaveatGate> for ReleaseAuthority {
    fn from(gate: CaveatGate) -> Self {
        ReleaseAuthority {
            gate,
            role: None,
            originator_approved: false,
        }
    }
}

/// Enforce an export/release of `req` under a redaction receipt.
///
/// `receipt_hash` is the caller's claimed released-side hash — it must equal
/// the receipt's `released_hash` (pass `receipt.released_hash` when the
/// receipt was just produced; *not* a re-hash of the derivative bytes, which
/// use a different encoding unless the derivative is exactly the canonical
/// compact JSON of the released value). `receipt` is the
/// [`ReleaseBundle`](crate::redaction::ReleaseBundle) produced by the
/// redaction pipeline; `now_ms` comes from the caller (pure function).
///
/// Order of checks (first failure wins):
/// 1. empty/whitespace `receipt_hash` → [`EnforceError::MissingReceipt`];
/// 2. `verify_release(receipt)` false → [`EnforceError::Redaction`] with
///    `"redaction.receipt-unverified"`;
/// 3. `receipt.released_hash != receipt_hash` → [`EnforceError::Redaction`]
///    with `"redaction.receipt-hash-mismatch"`;
/// 4. A2.2.1 gate denial → [`EnforceError::ExportDenied`] with the
///    `DenyReason::code()` value.
/// 5. *Only when* [`ReleaseAuthority::gate`] is [`CaveatGate::Enforce`]: an
///    unparseable caveat (`"deny.caveat-unparseable"`) or a
///    [`release_check`](crate::caveats::release_check) refusal (its own
///    `deny.caveat*` code) → [`EnforceError::ExportDenied`].
///
/// On success the derivative is released byte-identical, `original_sha256`
/// chains to the sealed original, and `caveats` is the request's caveat list
/// sorted ascending and deduplicated.
pub fn enforce_export(
    req: &ExportRequest,
    receipt_hash: &str,
    now_ms: i64,
    receipt: &ReleaseBundle,
) -> Result<ReleasedExport, EnforceError> {
    enforce_export_with(
        req,
        receipt_hash,
        now_ms,
        receipt,
        ReleaseAuthority::default(),
    )
}

/// [`enforce_export`] with an explicit [`ReleaseAuthority`].
///
/// [`ReleaseAuthority::default`] is byte-for-byte the historical behaviour and
/// is exactly what the four-argument wrapper passes, so every existing caller is
/// unchanged. With `gate == CaveatGate::Enforce` the request's caveats are
/// parsed with the **same** parser `sluice` uses
/// ([`crate::sluice::parse_caveat_marking`]) and evaluated with
/// [`release_check`](crate::caveats::release_check) before anything is released,
/// so the two gates cannot disagree about what a marking means.
pub fn enforce_export_with(
    req: &ExportRequest,
    receipt_hash: &str,
    now_ms: i64,
    receipt: &ReleaseBundle,
    authority: ReleaseAuthority,
) -> Result<ReleasedExport, EnforceError> {
    // 1. No receipt, no release. Presence is checked before verification so
    //    a missing receipt can never be masked by a second failure.
    if receipt_hash.trim().is_empty() {
        return Err(EnforceError::MissingReceipt);
    }

    // 2. The receipt must be tamper-evident-intact per the redaction surface.
    if !verify_release(receipt) {
        return Err(EnforceError::Redaction(CODE_RECEIPT_UNVERIFIED.to_string()));
    }

    // 3. …and must certify *this* release: the claimed hash must be the
    //    receipt's released-side hash.
    if receipt.released_hash != receipt_hash {
        return Err(EnforceError::Redaction(
            CODE_RECEIPT_HASH_MISMATCH.to_string(),
        ));
    }

    // 4. The A2.2.1 export gate. `check_export` is the Result form `may_export`
    //    wraps; the deny code is preserved for the audit payload.
    check_export(req.class, req.audience, req.embargo_active)
        .map_err(|reason| EnforceError::ExportDenied(reason.code().to_string()))?;

    // 4b. Dissemination caveats — only when the operator has asked for it.
    //
    //     RenderOnly reproduces the historical behaviour exactly: the markings
    //     are carried on the release and never evaluated. That is the gap this
    //     flag exists to close, asserted rather than hidden — see the
    //     laundering test below, which requires BOTH behaviours.
    if authority.gate == CaveatGate::Enforce {
        let mut parsed = Vec::with_capacity(req.required_caveats.len());
        for raw in &req.required_caveats {
            match crate::sluice::parse_caveat_marking(raw) {
                Some(c) => parsed.push(c),
                // An unrecognised marking is a refusal, never a drop: the whole
                // failure mode being fixed is a restriction that survives as
                // text but stops binding.
                None => {
                    return Err(EnforceError::ExportDenied(
                        "deny.caveat-unparseable".to_string(),
                    ));
                }
            }
        }
        release_check(
            &parsed,
            req.audience,
            authority.role.as_deref(),
            authority.originator_approved,
        )
        .map_err(|e| EnforceError::ExportDenied(e.code().to_string()))?;
    }

    // 5. Release: derivative bytes unchanged; caveats ascending, deduplicated.
    let mut caveats = req.required_caveats.clone();
    caveats.sort();
    caveats.dedup();

    Ok(ReleasedExport {
        derivative: req.derivative.clone(),
        receipt_hash: receipt_hash.to_string(),
        original_sha256: receipt.original_hash.clone(),
        caveats,
        released_ms: now_ms,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::{RedactMode, RedactionRule, produce_release};
    use serde_json::json;

    // Externally computed constants (printf … | sha256sum) so the hashing
    // convention is grounded outside this module's own code path.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_1234: &str = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";

    fn rule(field: &str, mode: RedactMode) -> RedactionRule {
        RedactionRule {
            field: field.to_string(),
            mode,
        }
    }

    /// A valid receipt: redact `ssn` out of a small object.
    fn receipt_for(original: &serde_json::Value) -> ReleaseBundle {
        produce_release(original, &[rule("ssn", RedactMode::Remove)], 42).unwrap()
    }

    fn req_for(class: AccessClass, audience: Audience, embargo: bool) -> ExportRequest {
        ExportRequest {
            class,
            audience,
            embargo_active: embargo,
            derivative: br#"{"id":7}"#.to_vec(),
            required_caveats: Vec::new(),
        }
    }

    fn is_sha256_hex(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    // ── sha256_hex ───────────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_matches_external_constants() {
        assert_eq!(sha256_hex(b""), SHA256_EMPTY);
        assert_eq!(sha256_hex(b"abc"), SHA256_ABC);
        assert_eq!(sha256_hex(b"1234"), SHA256_1234);
        // Property: 64 lowercase hex chars, deterministic, UTF-8 safe.
        for input in [b"tallow".as_slice(), "αβγ".as_bytes(), &[0u8, 255, 7]] {
            let h = sha256_hex(input);
            assert!(is_sha256_hex(&h), "bad hash {h} for {input:?}");
            assert_eq!(h, sha256_hex(input), "nondeterministic");
        }
    }

    #[test]
    fn sha256_hex_matches_redaction_hashing_convention() {
        // Grounded against redaction.rs's own original-side pin: the sealed
        // original is hashed over its canonical compact JSON bytes.
        let original = json!({"a": 1, "ssn": "123-45-6789"});
        let bundle = produce_release(&original, &[rule("ssn", RedactMode::Remove)], 7).unwrap();
        assert_eq!(
            sha256_hex(&serde_json::to_vec(&original).unwrap()),
            bundle.original_hash
        );
    }

    // ── enforce_read ─────────────────────────────────────────────────────────

    #[test]
    fn enforce_read_sealed_denies_every_audience_open_allows_everyone() {
        for audience in Audience::ALL {
            assert_eq!(
                enforce_read(AccessClass::Sealed, audience),
                Err(EnforceError::ReadDenied("deny.sealed".to_string())),
                "sealed / {audience:?}"
            );
        }
        for audience in Audience::ALL {
            assert_eq!(
                enforce_read(AccessClass::Open, audience),
                Ok(()),
                "open / {audience:?}"
            );
        }
    }

    #[test]
    fn enforce_read_matches_check_read_with_codes() {
        for class in AccessClass::ALL {
            for audience in Audience::ALL {
                let enforced = enforce_read(class, audience);
                let checked = check_read(class, audience);
                assert_eq!(enforced.is_ok(), checked.is_ok(), "{class:?}/{audience:?}");
                match enforced {
                    Ok(()) => assert!(checked.is_ok()),
                    Err(EnforceError::ReadDenied(code)) => {
                        assert_eq!(code, checked.unwrap_err().code())
                    }
                    other => panic!("unexpected error shape {other:?}"),
                }
            }
        }
    }

    #[test]
    fn enforce_read_research_and_restricted_rows_pinned() {
        use AccessClass::*;
        use Audience::*;
        assert_eq!(enforce_read(Research, Teammate), Ok(()));
        assert_eq!(enforce_read(Research, Operator), Ok(()));
        assert_eq!(
            enforce_read(Research, Public),
            Err(EnforceError::ReadDenied(
                "deny.audience-not-admitted".to_string()
            ))
        );
        assert_eq!(enforce_read(Restricted, Operator), Ok(()));
        assert_eq!(
            enforce_read(Restricted, Teammate),
            Err(EnforceError::ReadDenied(
                "deny.audience-not-admitted".to_string()
            ))
        );
    }

    // ── enforce_export: receipt requirement ──────────────────────────────────

    #[test]
    fn export_requires_a_receipt() {
        let bundle = receipt_for(&json!({"ssn": "123-45-6789", "id": 7}));
        let req = req_for(AccessClass::Open, Audience::Public, false);

        // Empty and whitespace-only hash → MissingReceipt, even for a valid
        // receipt and an otherwise-admissible row.
        assert_eq!(
            enforce_export(&req, "", 1, &bundle),
            Err(EnforceError::MissingReceipt)
        );
        assert_eq!(
            enforce_export(&req, "   \t\n", 1, &bundle),
            Err(EnforceError::MissingReceipt)
        );

        // Presence is checked before verification: a missing receipt never
        // reaches receipt validation even if the bundle is tampered.
        let mut tampered = bundle.clone();
        tampered.released["id"] = json!(999);
        assert_eq!(
            enforce_export(&req, "", 1, &tampered),
            Err(EnforceError::MissingReceipt)
        );
    }

    #[test]
    fn tampered_receipt_is_rejected() {
        let original = json!({"ssn": "123-45-6789", "id": 7});
        let req = req_for(AccessClass::Open, Audience::Public, false);

        // Tampered released side.
        let mut bundle = receipt_for(&original);
        let hash = bundle.released_hash.clone();
        bundle.released["id"] = json!(999);
        assert_eq!(
            enforce_export(&req, &hash, 1, &bundle),
            Err(EnforceError::Redaction(
                "redaction.receipt-unverified".to_string()
            ))
        );

        // Tampered recorded hash.
        let mut bundle = receipt_for(&original);
        bundle.released_hash = "deadbeef".to_string();
        assert_eq!(
            enforce_export(&req, &bundle.released_hash.clone(), 1, &bundle),
            Err(EnforceError::Redaction(
                "redaction.receipt-unverified".to_string()
            ))
        );

        // Tampered audit mirror.
        let mut bundle = receipt_for(&original);
        let hash = bundle.released_hash.clone();
        bundle.audit.released_hash = "0".repeat(64);
        assert_eq!(
            enforce_export(&req, &hash, 1, &bundle),
            Err(EnforceError::Redaction(
                "redaction.receipt-unverified".to_string()
            ))
        );
    }

    #[test]
    fn receipt_hash_mismatch_is_rejected() {
        let bundle = receipt_for(&json!({"ssn": "x", "id": 1}));
        let req = req_for(AccessClass::Open, Audience::Public, false);
        let other = sha256_hex(b"not-this-release");
        assert_ne!(other, bundle.released_hash, "test fixture collision");
        assert_eq!(
            enforce_export(&req, &other, 1, &bundle),
            Err(EnforceError::Redaction(
                "redaction.receipt-hash-mismatch".to_string()
            ))
        );
    }

    // ── enforce_export: gate rows ────────────────────────────────────────────

    #[test]
    fn export_denied_rows_carry_stable_codes() {
        use AccessClass::*;
        use Audience::*;
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();

        let sealed = req_for(Sealed, Operator, false);
        assert_eq!(
            enforce_export(&sealed, &hash, 0, &bundle),
            Err(EnforceError::ExportDenied("deny.sealed".to_string()))
        );

        let restricted = req_for(Restricted, Operator, false);
        assert_eq!(
            enforce_export(&restricted, &hash, 0, &bundle),
            Err(EnforceError::ExportDenied(
                "deny.no-export-path".to_string()
            ))
        );

        let research_public = req_for(Research, Public, false);
        assert_eq!(
            enforce_export(&research_public, &hash, 0, &bundle),
            Err(EnforceError::ExportDenied(
                "deny.audience-not-admitted".to_string()
            ))
        );

        let embargoed = req_for(Open, Public, true);
        assert_eq!(
            enforce_export(&embargoed, &hash, 0, &bundle),
            Err(EnforceError::ExportDenied(
                "deny.embargo-active".to_string()
            ))
        );
    }

    #[test]
    fn embargo_blocks_every_class_and_audience_even_with_valid_receipt() {
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();
        for class in AccessClass::ALL {
            for audience in Audience::ALL {
                let req = req_for(class, audience, true);
                assert_eq!(
                    enforce_export(&req, &hash, 0, &bundle),
                    Err(EnforceError::ExportDenied(
                        "deny.embargo-active".to_string()
                    )),
                    "{class:?} / {audience:?}"
                );
            }
        }
    }

    #[test]
    fn export_allowed_rows_pass_with_valid_receipt() {
        use AccessClass::*;
        use Audience::*;
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();
        // The frozen allow rows: Open → everyone; Research → Teammate+.
        for audience in Audience::ALL {
            assert!(
                enforce_export(&req_for(Open, audience, false), &hash, 0, &bundle).is_ok(),
                "open / {audience:?}"
            );
        }
        for audience in [Teammate, Operator] {
            assert!(
                enforce_export(&req_for(Research, audience, false), &hash, 0, &bundle).is_ok(),
                "research / {audience:?}"
            );
        }
    }

    #[test]
    fn export_never_exceeds_read_admission_composed() {
        // Mirrors the access_class invariant at the composition layer,
        // including the receipt+gate interaction: what an export admits,
        // a read must admit, for every row and embargo state.
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();
        for class in AccessClass::ALL {
            for audience in Audience::ALL {
                for embargo in [false, true] {
                    let req = req_for(class, audience, embargo);
                    if enforce_export(&req, &hash, 0, &bundle).is_ok() {
                        assert!(
                            enforce_read(class, audience).is_ok(),
                            "export of {class:?} to {audience:?} allowed but read denied"
                        );
                    }
                }
            }
        }
    }

    // ── enforce_export: happy path fields ────────────────────────────────────

    #[test]
    fn happy_export_fields_are_pinned() {
        let original = json!({"ssn": "123-45-6789", "id": 7});
        let bundle = produce_release(&original, &[rule("ssn", RedactMode::Remove)], 42).unwrap();
        let req = ExportRequest {
            class: AccessClass::Research,
            audience: Audience::Teammate,
            embargo_active: false,
            derivative: vec![0u8, 255, 7, 1], // arbitrary non-UTF-8 bytes pass through
            required_caveats: vec!["b".to_string(), "a".to_string(), "a".to_string()],
        };
        let rel = enforce_export(&req, &bundle.released_hash, 1_700_000_000_000, &bundle).unwrap();

        assert_eq!(
            rel.derivative, req.derivative,
            "derivative must be byte-identical"
        );
        assert_eq!(rel.receipt_hash, bundle.released_hash);
        assert_eq!(rel.original_sha256, bundle.original_hash);
        assert_eq!(rel.caveats, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(rel.released_ms, 1_700_000_000_000);
        assert!(
            is_sha256_hex(&rel.receipt_hash),
            "receipt_hash: {}",
            rel.receipt_hash
        );
        assert!(
            is_sha256_hex(&rel.original_sha256),
            "original_sha256: {}",
            rel.original_sha256
        );
        // The original-side pin chains to the sealed original (redaction
        // semantics), not to the derivative bytes.
        assert_eq!(
            rel.original_sha256,
            sha256_hex(&serde_json::to_vec(&original).unwrap())
        );
    }

    #[test]
    fn caveats_are_sorted_and_deduped() {
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let req = ExportRequest {
            class: AccessClass::Open,
            audience: Audience::Public,
            embargo_active: false,
            derivative: Vec::new(),
            required_caveats: vec![
                "z".to_string(),
                "M".to_string(),
                "a".to_string(),
                "z".to_string(),
                "M".to_string(),
            ],
        };
        let rel = enforce_export(&req, &bundle.released_hash, 0, &bundle).unwrap();
        // String ordering is ASCII ascending: 'M' < 'a' < 'z'.
        assert_eq!(
            rel.caveats,
            vec!["M".to_string(), "a".to_string(), "z".to_string()]
        );
        // Empty caveat list stays empty.
        let req2 = req_for(AccessClass::Open, Audience::Public, false);
        let rel2 = enforce_export(&req2, &bundle.released_hash, 0, &bundle).unwrap();
        assert!(rel2.caveats.is_empty());
    }

    // ── enforce_export: the caveat gate (S3) ─────────────────────────────────

    /// **S3's acceptance criterion.** The caveat-laundering case: `Open`
    /// material marked `NO-THIRD-PARTY` released to a third party.
    /// `RenderOnly` admits it — that *is* the defect, pinned here so that any
    /// change to the default becomes visible — and `Enforce` refuses the
    /// identical request. Both halves are required: a test that only asserted
    /// the refusal would pass just as well if the default had silently flipped.
    #[test]
    fn caveat_gate_enforce_refuses_the_laundering_case_render_only_admits() {
        let bundle = receipt_for(&json!({"ssn": "x", "id": 7}));
        let hash = bundle.released_hash.clone();
        let mut req = req_for(AccessClass::Open, Audience::ThirdParty, false);
        req.required_caveats = vec!["NO-THIRD-PARTY".to_string()];

        let rendered = enforce_export(&req, &hash, 0, &bundle)
            .expect("RenderOnly admits the laundering case — that is the defect");
        assert_eq!(rendered.caveats, vec!["NO-THIRD-PARTY".to_string()]);

        match enforce_export_with(&req, &hash, 0, &bundle, CaveatGate::Enforce.into()) {
            Err(EnforceError::ExportDenied(code)) => assert_eq!(code, "deny.caveat"),
            other => panic!("Enforce must refuse NO-THIRD-PARTY to a third party, got {other:?}"),
        }
    }

    #[test]
    fn caveat_gate_enforce_admits_an_unconstrained_release() {
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();
        let req = req_for(AccessClass::Open, Audience::Operator, false);
        assert!(
            enforce_export_with(&req, &hash, 0, &bundle, CaveatGate::Enforce.into()).is_ok(),
            "the flag must not break the ordinary unconstrained release"
        );
    }

    #[test]
    fn caveat_gate_enforce_refuses_an_unparseable_marking() {
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();
        let mut req = req_for(AccessClass::Open, Audience::Operator, false);
        req.required_caveats = vec!["need-to-know".to_string()];
        match enforce_export_with(&req, &hash, 0, &bundle, CaveatGate::Enforce.into()) {
            Err(EnforceError::ExportDenied(code)) => assert_eq!(code, "deny.caveat-unparseable"),
            other => panic!("expected deny.caveat-unparseable, got {other:?}"),
        }
    }

    #[test]
    fn caveat_gate_enforce_refuses_orcon_without_approval_and_admits_it_with() {
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let hash = bundle.released_hash.clone();
        let mut req = req_for(AccessClass::Open, Audience::Operator, false);
        req.required_caveats = vec!["ORCON".to_string()];

        assert!(
            enforce_export_with(&req, &hash, 0, &bundle, CaveatGate::Enforce.into()).is_err(),
            "ORCON without the originator's approval must refuse"
        );
        let authority = ReleaseAuthority {
            gate: CaveatGate::Enforce,
            role: None,
            originator_approved: true,
        };
        assert!(
            enforce_export_with(&req, &hash, 0, &bundle, authority).is_ok(),
            "ORCON with approval must still release"
        );
    }

    #[test]
    fn caveat_gate_defaults_are_render_only_everywhere() {
        assert_eq!(CaveatGate::default(), CaveatGate::RenderOnly);
        assert_eq!(CaveatGate::RenderOnly.as_str(), "render-only");
        assert_eq!(CaveatGate::Enforce.as_str(), "enforce");
        assert_eq!(
            ReleaseAuthority::default().gate,
            CaveatGate::RenderOnly,
            "a caller that has not opted in must be unchanged"
        );
        assert_eq!(
            ReleaseAuthority::from(CaveatGate::Enforce).gate,
            CaveatGate::Enforce
        );
        // And the four-argument wrapper is that default.
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let mut req = req_for(AccessClass::Open, Audience::ThirdParty, false);
        req.required_caveats = vec!["NO-THIRD-PARTY".to_string()];
        assert!(enforce_export(&req, &bundle.released_hash.clone(), 0, &bundle).is_ok());
    }

    // ── Determinism, serde, display ──────────────────────────────────────────

    #[test]
    fn determinism_and_serde_stability() {
        let bundle = receipt_for(&json!({"ssn": "x", "id": 3}));
        let req = ExportRequest {
            class: AccessClass::Open,
            audience: Audience::ThirdParty,
            embargo_active: false,
            derivative: b"payload".to_vec(),
            required_caveats: vec!["c".to_string(), "c".to_string()],
        };
        let a = enforce_export(&req, &bundle.released_hash, 99, &bundle).unwrap();
        let b = enforce_export(&req, &bundle.released_hash, 99, &bundle).unwrap();
        assert_eq!(a, b, "same inputs must yield identical releases");
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "serialization must be stable"
        );
    }

    #[test]
    fn serde_roundtrips_and_wire_shapes_pinned() {
        let bundle = receipt_for(&json!({"ssn": "x"}));
        let req = ExportRequest {
            class: AccessClass::Restricted,
            audience: Audience::Operator,
            embargo_active: true,
            derivative: vec![1, 2, 3],
            required_caveats: vec!["NO-FOR".to_string()],
        };
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<ExportRequest>(&s).unwrap(), req);

        let rel = ReleasedExport {
            derivative: vec![9],
            receipt_hash: sha256_hex(b"r"),
            original_sha256: sha256_hex(b"o"),
            caveats: vec!["NO-FOR".to_string()],
            released_ms: 5,
        };
        let s = serde_json::to_string(&rel).unwrap();
        assert_eq!(serde_json::from_str::<ReleasedExport>(&s).unwrap(), rel);

        // Error wire shapes: variant names, stable for ledger records.
        let errors = [
            EnforceError::ReadDenied("deny.sealed".to_string()),
            EnforceError::ExportDenied("deny.embargo-active".to_string()),
            EnforceError::MissingReceipt,
            EnforceError::Redaction("redaction.receipt-unverified".to_string()),
        ];
        for e in &errors {
            let s = serde_json::to_string(e).unwrap();
            assert_eq!(&serde_json::from_str::<EnforceError>(&s).unwrap(), e);
        }
        assert_eq!(
            serde_json::to_string(&EnforceError::MissingReceipt).unwrap(),
            "\"MissingReceipt\""
        );
        assert_eq!(
            serde_json::to_string(&EnforceError::ReadDenied("deny.sealed".to_string())).unwrap(),
            "{\"ReadDenied\":\"deny.sealed\"}"
        );
        // Deny codes carried by export errors are the access_class codes.
        let denied_req = req_for(AccessClass::Sealed, Audience::Operator, false);
        let denial = enforce_export(&denied_req, &bundle.released_hash, 0, &bundle).unwrap_err();
        assert_eq!(
            denial,
            EnforceError::ExportDenied(
                check_export(AccessClass::Sealed, Audience::Operator, false)
                    .unwrap_err()
                    .code()
                    .to_string()
            )
        );
        assert!(matches!(denial, EnforceError::ExportDenied(c) if c.starts_with("deny.")));
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            EnforceError::ReadDenied("deny.sealed".to_string()).to_string(),
            "read denied: deny.sealed"
        );
        assert_eq!(
            EnforceError::ExportDenied("deny.embargo-active".to_string()).to_string(),
            "export denied: deny.embargo-active"
        );
        assert_eq!(
            EnforceError::MissingReceipt.to_string(),
            "export denied: redaction receipt required"
        );
        assert_eq!(
            EnforceError::Redaction("redaction.receipt-hash-mismatch".to_string()).to_string(),
            "redaction receipt invalid: redaction.receipt-hash-mismatch"
        );
        let _: &dyn std::error::Error = &EnforceError::MissingReceipt;
    }
}
