//! Cryptographic enrollment ceremony — R-5.5 (tracker row #57).
//!
//! "CPace (in-crate) over untrusted channels → SAS/word comparison on both screens →
//! CSR + optional TPM quote + single-use join token → issuance; all enrollments
//! KT-logged" (`research/tallow-security-2026-09-12/phase5-identity/05-identity-architecture-draft.md:321`).
//!
//! Composition exercised here (no new crypto primitives — every piece is an in-tree
//! construction):
//!
//! * **CPace** ([`tallow_crypto::pake::CpaceInitiator`] / [`CpaceResponder`], T-201
//!   verified) establishes the session key over an untrusted channel.
//! * **SAS word comparison** ([`tallow_crypto::pake::SasCode`]) — both endpoints derive
//!   the same six words from the session key + transcript; the operator compares screens.
//! * **Key confirmation** — the issuer's acknowledgement and the enrollee's submission are
//!   sealed with `XChaCha20-Poly1305` under direction-separated session keys derived via
//!   BLAKE3 `derive_key`. A peer that cannot open the seal does not hold the same PAKE
//!   transcript: the ceremony fails closed before any credential is presented.
//! * **Single-use join tokens** ([`tallow_svid::join`], U-213) — the enrollee presents the
//!   token secret *inside* the sealed submission; the token is bound to `SHA-256(SPKI)` and
//!   consumed atomically, so a replay or a mis-bound token is refused.
//! * **Attestation "where available"** ([`Attestation`]) — the row text is literally
//!   "TPM quote attestation where available": when no TPM 2.0 device node exists the
//!   ceremony records `assurance=software` and says so; it never fabricates a quote.
//! * **KT log** — the issuance record is appended through [`EnrollmentAudit`], implemented
//!   for the existing [`crate::kt_log::KtLog`] (this lane appends enrollments only; the
//!   inclusion/consistency-proof leg is tracker row #80 and is *not* claimed here).
//!
//! Out of scope for this module (recorded in the lane log §OPEN, not silently dropped):
//! re-enrollment / operator-approval re-bind (row text is operator-gated, ⚠️OA), the
//! daemon-side durable token store (the trait seam is [`JoinTokenStore`]), and the actual
//! SVID certificate issuance call (the ceremony emits the verifiable issuance binding; the
//! daemon hands it to `tallow-svid`'s issuer).

use std::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde_json::{json, Value};
use tallow_crypto::pake::{CpaceInitiator, CpaceResponder, SasCode};
use tallow_svid::join::{
    InMemoryJoinTokenStore, JoinError, JoinToken, JoinTokenStore, JOIN_TOKEN_MAX_TTL_SECS,
};

/// Protocol label carried in every ceremony message and in the SAS transcript.
pub const ENROLLMENT_PROTOCOL: &str = "tallow-enroll-v1";
/// Default join-token TTL for the local ceremony (seconds).
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 300;
/// Domain separator for the enrollee → issuer sealing key.
const C2S_DOMAIN: &str = "tallow-enroll-c2s-v1";
/// Domain separator for the issuer → enrollee sealing key.
const S2C_DOMAIN: &str = "tallow-enroll-s2c-v1";
/// Domain separator for the SAS transcript label/separator.
const SAS_CONTEXT_LABEL: &[u8] = b"tallow-enroll-v1/sas-transcript";

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4, OID 1.3.101.112).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Every ceremony failure is typed and explicit — nothing "assumes valid".
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// The peer does not hold the same PAKE transcript (seal refused to open, or the
    /// peer echoed a different SAS fingerprint). This is the MITM screen.
    #[error("enrollment key confirmation failed — peer does not share the PAKE transcript (possible MITM)")]
    KeyConfirmationFailed,
    /// The operator rejected the SAS words on the enrollee screen.
    #[error("SAS words were not confirmed — ceremony aborted before presenting the join token")]
    SasNotConfirmed,
    /// The issuer refused the enrollment (join-token replay/expiry/mis-binding, policy…).
    #[error("issuer refused the enrollment: {code} — {detail}")]
    Refused {
        /// Machine-readable refusal code (e.g. `join_replay`).
        code: String,
        /// Human-readable detail.
        detail: String,
    },
    /// A ceremony step ran out of order.
    #[error("ceremony step out of order: expected {expected}, got {got}")]
    StepOutOfOrder {
        /// Expected previous step.
        expected: &'static str,
        /// Attempted step.
        got: &'static str,
    },
    /// A message field is malformed or missing.
    #[error("ceremony message is malformed: {0}")]
    Malformed(String),
    /// PAKE-level failure (invalid peer point, wrong length…).
    #[error("PAKE failure: {0}")]
    Pake(#[from] tallow_crypto::CryptoError),
    /// Join-token store failure that is not a policy refusal.
    #[error("join token store error: {0}")]
    Join(#[from] JoinError),
    /// The enrollment record could not be KT-logged.
    #[error("enrollment record could not be KT-logged: {0}")]
    KtLog(String),
    /// Sealing failed (entropy/JSON).
    #[error("enrollment seal failed: {0}")]
    Seal(String),
}

/// Convenience result alias for the ceremony.
pub type Result<T> = std::result::Result<T, EnrollmentError>;

// ─────────────────────────────────────────────────────────────────────────────
// Attestation ("where available")
// ─────────────────────────────────────────────────────────────────────────────

/// Device attestation state. The row text is "TPM quote attestation **where available**";
/// this enum is how the ceremony stays honest about which of those applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// No TPM 2.0 device node on this host → the ceremony proceeds at `assurance=software`.
    Unavailable {
        /// Why the quote path is unavailable.
        reason: String,
    },
    /// A TPM 2.0 device node exists, but no quote implementation is wired in this build.
    /// (Honest gap: the ceremony does **not** pretend a quote happened.)
    DevicePresentNoQuote {
        /// The device node that was found.
        device: String,
    },
    /// A quote over the enrollment transcript, supplied by the enrolling platform.
    Quote {
        /// Hex digest of the quoted PCR selection.
        pcr_digest_hex: String,
        /// Hex signature over the quote structure.
        signature_hex: String,
        /// Whether a verifier accepted the quote for this transcript.
        verified: bool,
    },
}

impl Attestation {
    /// Machine-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Attestation::Unavailable { .. } => "unavailable",
            Attestation::DevicePresentNoQuote { .. } => "device-present-no-quote",
            Attestation::Quote { .. } => "quote",
        }
    }

    /// Assurance level recorded for the enrollment.
    pub fn assurance(&self) -> &'static str {
        match self {
            Attestation::Unavailable { .. } | Attestation::DevicePresentNoQuote { .. } => "software",
            Attestation::Quote { verified, .. } => {
                if *verified {
                    "tpm-quote"
                } else {
                    "tpm-quote-unverified"
                }
            }
        }
    }

    /// Whether a *usable* attestation is present (a verified quote).
    pub fn available(&self) -> bool {
        matches!(self, Attestation::Quote { verified: true, .. })
    }

    /// Human-facing detail line.
    pub fn detail(&self) -> String {
        match self {
            Attestation::Unavailable { reason } => reason.clone(),
            Attestation::DevicePresentNoQuote { device } => format!(
                "{device} present, but TPM quote support is not wired in this build"
            ),
            Attestation::Quote { pcr_digest_hex, .. } => {
                format!("TPM quote over transcript (PCR digest {pcr_digest_hex})")
            }
        }
    }
}

/// Detect the attestation state of this host (no external crate: device-node presence).
pub fn detect_attestation() -> Attestation {
    for candidate in ["/dev/tpmrm0", "/dev/tpm0"] {
        if std::path::Path::new(candidate).exists() {
            return Attestation::DevicePresentNoQuote {
                device: candidate.to_string(),
            };
        }
    }
    Attestation::Unavailable {
        reason: "no TPM 2.0 device node (/dev/tpmrm0 or /dev/tpm0) on this host".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Messages / wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Enrollee → issuer: protocol, session id and the CPace public message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Protocol label ([`ENROLLMENT_PROTOCOL`]).
    pub protocol: String,
    /// Ceremony session id (also binds the CPace generator).
    pub session_id: [u8; 32],
    /// CPace public message (32 bytes).
    pub cpace_public: [u8; 32],
}

/// Issuer → enrollee: CPace public message + the sealed acknowledgement (key confirmation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAck {
    /// CPace public message (32 bytes).
    pub cpace_public: [u8; 32],
    /// `nonce ‖ XChaCha20-Poly1305 ciphertext` under the s2c session key.
    pub sealed: Vec<u8>,
}

/// Enrollee → issuer: the sealed submission (device name, SPKI, join-token secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubmission {
    /// `nonce ‖ XChaCha20-Poly1305 ciphertext` under the c2s session key.
    pub sealed: Vec<u8>,
}

/// Issuer → enrollee: the sealed issuance binding (or an authenticated refusal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGrant {
    /// `nonce ‖ XChaCha20-Poly1305 ciphertext` under the s2c session key.
    pub sealed: Vec<u8>,
}

/// The verifiable issuance binding returned to the enrollee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentGrant {
    /// Device name presented by the enrollee.
    pub device_name: String,
    /// `SHA-256(SPKI)` the enrollment is bound to.
    pub spki_sha256: [u8; 32],
    /// Non-secret id of the consumed join token.
    pub token_id: [u8; 32],
    /// Redemption time (unix seconds).
    pub redeemed_at: i64,
    /// Assurance level (`software` until a verified quote exists).
    pub assurance: String,
    /// Attestation label ([`Attestation::label`]).
    pub attestation_label: String,
    /// SAS fingerprint both screens showed.
    pub sas_fingerprint_hex: String,
    /// KT-log entry hash for this enrollment, when a KT log was attached.
    pub kt_entry: Option<String>,
}

/// An authenticated refusal (the issuer says *why*, inside the seal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Machine-readable code (`join_replay`, `join_expired`, `sas_not_confirmed`, …).
    pub code: String,
    /// Human-readable detail.
    pub detail: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} — {}", self.code, self.detail)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KT-log seam
// ─────────────────────────────────────────────────────────────────────────────

/// Append-only sink for enrollment records ("all enrollments KT-logged").
pub trait EnrollmentAudit {
    /// Append one enrollment record; returns the log entry hash.
    fn record_enrollment(&mut self, payload: &Value) -> Result<String>;
}

/// The existing key-transparency log, wired as an enrollment audit sink.
impl EnrollmentAudit for crate::kt_log::KtLog {
    fn record_enrollment(&mut self, payload: &Value) -> Result<String> {
        let entry = self
            .append_json(payload)
            .map_err(|err| EnrollmentError::KtLog(err.to_string()))?;
        Ok(entry.entry_hash.clone())
    }
}

/// In-memory audit sink: records the payloads and returns a BLAKE3 hash per record.
/// Used by tests and the local CLI ceremony (a real deployment attaches [`crate::kt_log::KtLog`]).
#[derive(Debug, Default)]
pub struct RecordingAudit {
    /// Every appended record, in order.
    pub records: Vec<Value>,
    /// Entry hashes, in the same order.
    pub entry_hashes: Vec<String>,
}

impl EnrollmentAudit for RecordingAudit {
    fn record_enrollment(&mut self, payload: &Value) -> Result<String> {
        let bytes = serde_json::to_vec(payload).map_err(|e| EnrollmentError::Seal(e.to_string()))?;
        let hash = blake3::hash(&bytes).to_hex().to_string();
        self.records.push(payload.clone());
        self.entry_hashes.push(hash.clone());
        Ok(hash)
    }
}

/// Shared tally of an audit sink, for callers that need the count after the ceremony
/// (the sink itself is moved into the issuer).
#[derive(Debug, Default, Clone)]
pub struct CountingAudit {
    tally: std::rc::Rc<std::cell::RefCell<AuditTally>>,
}

#[derive(Debug, Default)]
struct AuditTally {
    records: usize,
    entry_hashes: Vec<String>,
}

impl CountingAudit {
    /// (records appended, entry hashes in order).
    pub fn tally(&self) -> (usize, Vec<String>) {
        let tally = self.tally.borrow();
        (tally.records, tally.entry_hashes.clone())
    }
}

impl EnrollmentAudit for CountingAudit {
    fn record_enrollment(&mut self, payload: &Value) -> Result<String> {
        let bytes = serde_json::to_vec(payload).map_err(|e| EnrollmentError::Seal(e.to_string()))?;
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let mut tally = self.tally.borrow_mut();
        tally.records += 1;
        tally.entry_hashes.push(hash.clone());
        Ok(hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn from_hex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(EnrollmentError::Malformed(format!(
            "hex field has odd length ({})",
            text.len()
        )));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| EnrollmentError::Malformed("hex field is not hex".to_string()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| EnrollmentError::Malformed("hex field is not hex".to_string()))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Fresh 32-byte ceremony session id (OS entropy).
pub fn new_session_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Build the SAS/transcript context both sides derive identically.
fn sas_context(session_id: &[u8; 32], client_public: &[u8; 32], server_public: &[u8; 32]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(SAS_CONTEXT_LABEL.len() + 1 + 96);
    ctx.extend_from_slice(SAS_CONTEXT_LABEL);
    ctx.push(0);
    ctx.extend_from_slice(session_id);
    ctx.extend_from_slice(client_public);
    ctx.extend_from_slice(server_public);
    ctx
}

fn derive_key(domain: &str, session_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(domain, session_key)
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| EnrollmentError::Seal(e.to_string()))?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() <= 24 {
        return Err(EnrollmentError::Malformed(format!(
            "sealed payload too short ({} bytes)",
            sealed.len()
        )));
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| EnrollmentError::KeyConfirmationFailed)
}

/// RFC 8410 §4 Ed25519 `SubjectPublicKeyInfo` DER for a raw 32-byte public key.
///
/// Production enrollees pass the SPKI parsed from their CSR; the local ceremony uses this
/// so the token binding is over real DER, not a private convention.
pub fn spki_from_ed25519(public_key: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(public_key);
    der
}

const fn refusal_code(err: &JoinError) -> &'static str {
    match err {
        JoinError::Replayed { .. } => "join_replay",
        JoinError::Expired { .. } => "join_expired",
        JoinError::UnknownToken => "join_unknown",
        JoinError::SpkiMismatch => "join_spki_mismatch",
        JoinError::TokenLength { .. } => "join_malformed",
        JoinError::TtlTooLong { .. } | JoinError::TtlNonPositive { .. } => "join_ttl_refused",
        JoinError::Entropy => "join_entropy",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enrollee side
// ─────────────────────────────────────────────────────────────────────────────

/// The enrolling device: runs CPace as initiator, derives/confirms the SAS, then submits
/// its SPKI + join-token secret inside the sealed channel.
pub struct Enrollee {
    session_id: [u8; 32],
    device_name: String,
    spki_der: Vec<u8>,
    initiator: CpaceInitiator,
    session_key: Option<[u8; 32]>,
    transcript: Option<Vec<u8>>,
    sas: Option<SasCode>,
}

impl Enrollee {
    /// Start a ceremony. `code_phrase` is the out-of-band phrase both endpoints type;
    /// `spki_der` is the `SubjectPublicKeyInfo` of the key that will be certified.
    pub fn new(code_phrase: &str, session_id: [u8; 32], device_name: &str, spki_der: Vec<u8>) -> Self {
        Self {
            session_id,
            device_name: device_name.to_string(),
            spki_der,
            initiator: CpaceInitiator::new(code_phrase, &session_id),
            session_key: None,
            transcript: None,
            sas: None,
        }
    }

    /// Step 1 — the hello to send to the issuer.
    pub fn hello(&self) -> ClientHello {
        ClientHello {
            protocol: ENROLLMENT_PROTOCOL.to_string(),
            session_id: self.session_id,
            cpace_public: self.initiator.public_message(),
        }
    }

    /// Step 2 — consume the issuer's acknowledgement: derive the session key, **open the
    /// seal** (key confirmation) and derive the SAS that the operator will read out.
    pub fn on_ack(&mut self, ack: &ServerAck) -> Result<SasCode> {
        let client_public = self.initiator.public_message();
        let session_key = self.initiator.finish(&ack.cpace_public)?;
        let transcript = sas_context(&self.session_id, &client_public, &ack.cpace_public);
        let plaintext = open(&derive_key(S2C_DOMAIN, &session_key), &transcript, &ack.sealed)?;
        let value: Value = serde_json::from_slice(&plaintext)
            .map_err(|e| EnrollmentError::Malformed(format!("sealed ack is not JSON: {e}")))?;
        let sas = SasCode::derive(&session_key, &transcript);
        let echoed = value
            .get("sas_fingerprint")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if echoed != sas.fingerprint_hex() {
            return Err(EnrollmentError::KeyConfirmationFailed);
        }
        self.session_key = Some(session_key);
        self.transcript = Some(transcript);
        self.sas = Some(sas);
        Ok(sas)
    }

    /// The SAS this endpoint displays, once step 2 has run.
    pub fn sas(&self) -> Option<SasCode> {
        self.sas
    }

    /// Step 3 — build the sealed submission. `sas_confirmed` is the operator's answer to
    /// "do both screens show the same words?"; a refusal aborts **before** the join token
    /// is presented, so a mistyped phrase cannot burn a token.
    pub fn submission(&self, token_secret: &[u8], sas_confirmed: bool) -> Result<ClientSubmission> {
        if !sas_confirmed {
            return Err(EnrollmentError::SasNotConfirmed);
        }
        let session_key = self.session_key.ok_or(EnrollmentError::StepOutOfOrder {
            expected: "on_ack",
            got: "submission",
        })?;
        let transcript = self.transcript.as_ref().ok_or(EnrollmentError::StepOutOfOrder {
            expected: "on_ack",
            got: "submission",
        })?;
        let payload = json!({
            "protocol": ENROLLMENT_PROTOCOL,
            "device_name": self.device_name,
            "spki": to_hex(&self.spki_der),
            "token_secret": to_hex(token_secret),
            "sas_fingerprint": self.sas.map(|s| s.fingerprint_hex()).unwrap_or_default(),
        });
        let bytes = serde_json::to_vec(&payload).map_err(|e| EnrollmentError::Seal(e.to_string()))?;
        let sealed = seal(&derive_key(C2S_DOMAIN, &session_key), transcript, &bytes)?;
        Ok(ClientSubmission { sealed })
    }

    /// Step 4 — consume the issuer's sealed grant.
    pub fn on_grant(&mut self, grant: &ServerGrant) -> Result<EnrollmentGrant> {
        let session_key = self.session_key.ok_or(EnrollmentError::StepOutOfOrder {
            expected: "on_ack",
            got: "on_grant",
        })?;
        let transcript = self.transcript.as_ref().ok_or(EnrollmentError::StepOutOfOrder {
            expected: "on_ack",
            got: "on_grant",
        })?;
        let plaintext = open(&derive_key(S2C_DOMAIN, &session_key), transcript, &grant.sealed)?;
        let value: Value = serde_json::from_slice(&plaintext)
            .map_err(|e| EnrollmentError::Malformed(format!("sealed grant is not JSON: {e}")))?;
        let status = value.get("status").and_then(Value::as_str).unwrap_or_default();
        if status != "issued" {
            return Err(EnrollmentError::Refused {
                code: value
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("refused")
                    .to_string(),
                detail: value
                    .get("detail")
                    .and_then(Value::as_str)
                    .unwrap_or("issuer refused without detail")
                    .to_string(),
            });
        }
        let spki_sha256: [u8; 32] = from_hex(
            value
                .get("spki_sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| EnrollmentError::Malformed("grant is missing spki_sha256".into()))?,
        )?
        .try_into()
        .map_err(|_| EnrollmentError::Malformed("grant spki_sha256 is not 32 bytes".into()))?;
        let token_id: [u8; 32] = from_hex(
            value
                .get("token_id")
                .and_then(Value::as_str)
                .ok_or_else(|| EnrollmentError::Malformed("grant is missing token_id".into()))?,
        )?
        .try_into()
        .map_err(|_| EnrollmentError::Malformed("grant token_id is not 32 bytes".into()))?;
        Ok(EnrollmentGrant {
            device_name: value
                .get("device_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            spki_sha256,
            token_id,
            redeemed_at: value.get("redeemed_at").and_then(Value::as_i64).unwrap_or(0),
            assurance: value
                .get("assurance")
                .and_then(Value::as_str)
                .unwrap_or("software")
                .to_string(),
            attestation_label: value
                .get("attestation")
                .and_then(Value::as_str)
                .unwrap_or("unavailable")
                .to_string(),
            sas_fingerprint_hex: value
                .get("sas_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            kt_entry: value
                .get("kt_entry")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Issuer side
// ─────────────────────────────────────────────────────────────────────────────

/// The issuing endpoint: runs CPace as responder, displays the same SAS, redeems the
/// single-use join token and returns the sealed issuance binding.
pub struct EnrollmentIssuer<S: JoinTokenStore = InMemoryJoinTokenStore> {
    session_id: [u8; 32],
    responder: CpaceResponder,
    store: S,
    attestation: Attestation,
    audit: Option<Box<dyn EnrollmentAudit>>,
    session_key: Option<[u8; 32]>,
    transcript: Option<Vec<u8>>,
    sas: Option<SasCode>,
}

impl<S: JoinTokenStore> EnrollmentIssuer<S> {
    /// Start the issuer side. `store` owns token durability/serialisation (the daemon
    /// supplies the durable implementation; the in-memory store is the local default).
    pub fn new(code_phrase: &str, session_id: [u8; 32], store: S) -> Self {
        Self {
            session_id,
            responder: CpaceResponder::new(code_phrase, &session_id),
            store,
            attestation: detect_attestation(),
            audit: None,
            session_key: None,
            transcript: None,
            sas: None,
        }
    }

    /// Attach a KT-log sink (enrollment records are appended on issuance).
    pub fn set_audit(&mut self, audit: Box<dyn EnrollmentAudit>) {
        self.audit = Some(audit);
    }

    /// Override the attestation state (tests / platforms that supply a quote out of band).
    pub fn set_attestation(&mut self, attestation: Attestation) {
        self.attestation = attestation;
    }

    /// The attestation state this issuer will record.
    pub fn attestation(&self) -> &Attestation {
        &self.attestation
    }

    /// The SAS this endpoint displays, once a hello has been processed.
    pub fn sas(&self) -> Option<SasCode> {
        self.sas
    }

    /// Access to the token store (tests inspect outstanding/tracked counts).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mint a join token bound to the SPKI of the device that will enroll.
    pub fn mint_token(
        &self,
        spki_der: &[u8],
        ttl_secs: i64,
        now: i64,
    ) -> std::result::Result<JoinToken, JoinError> {
        let digest = JoinToken::spki_binding(spki_der);
        self.store.mint(&digest, ttl_secs, now)
    }

    /// Step 1 — process the hello and produce the sealed acknowledgement.
    pub fn on_hello(&mut self, hello: &ClientHello) -> Result<ServerAck> {
        if hello.protocol != ENROLLMENT_PROTOCOL {
            return Err(EnrollmentError::Malformed(format!(
                "unexpected protocol {:?} (expected {ENROLLMENT_PROTOCOL})",
                hello.protocol
            )));
        }
        if hello.session_id != self.session_id {
            return Err(EnrollmentError::Malformed(
                "session id does not match this ceremony".to_string(),
            ));
        }
        let server_public = self.responder.public_message();
        let session_key = self.responder.finish(&hello.cpace_public)?;
        let transcript = sas_context(&self.session_id, &hello.cpace_public, &server_public);
        let sas = SasCode::derive(&session_key, &transcript);
        let payload = json!({
            "protocol": ENROLLMENT_PROTOCOL,
            "sas_words": sas.words(),
            "sas_fingerprint": sas.fingerprint_hex(),
            "attestation": {
                "label": self.attestation.label(),
                "assurance": self.attestation.assurance(),
                "detail": self.attestation.detail(),
            },
        });
        let bytes = serde_json::to_vec(&payload).map_err(|e| EnrollmentError::Seal(e.to_string()))?;
        let sealed = seal(&derive_key(S2C_DOMAIN, &session_key), &transcript, &bytes)?;
        self.session_key = Some(session_key);
        self.transcript = Some(transcript);
        self.sas = Some(sas);
        Ok(ServerAck {
            cpace_public: server_public,
            sealed,
        })
    }

    /// Step 2 — open the submission (key confirmation), redeem the single-use join token
    /// and return the sealed grant (issuance binding, or an authenticated refusal).
    pub fn on_submission(&mut self, submission: &ClientSubmission, now: i64) -> Result<ServerGrant> {
        let session_key = self.session_key.ok_or(EnrollmentError::StepOutOfOrder {
            expected: "on_hello",
            got: "on_submission",
        })?;
        let transcript = self.transcript.clone().ok_or(EnrollmentError::StepOutOfOrder {
            expected: "on_hello",
            got: "on_submission",
        })?;
        let plaintext = open(&derive_key(C2S_DOMAIN, &session_key), &transcript, &submission.sealed)?;
        let value: Value = serde_json::from_slice(&plaintext)
            .map_err(|e| EnrollmentError::Malformed(format!("sealed submission is not JSON: {e}")))?;
        if value.get("protocol").and_then(Value::as_str) != Some(ENROLLMENT_PROTOCOL) {
            return Err(EnrollmentError::Malformed(
                "submission protocol label does not match".to_string(),
            ));
        }
        let device_name = value
            .get("device_name")
            .and_then(Value::as_str)
            .ok_or_else(|| EnrollmentError::Malformed("submission is missing device_name".into()))?
            .to_string();
        let spki_der = from_hex(
            value
                .get("spki")
                .and_then(Value::as_str)
                .ok_or_else(|| EnrollmentError::Malformed("submission is missing spki".into()))?,
        )?;
        let token_secret = from_hex(
            value
                .get("token_secret")
                .and_then(Value::as_str)
                .ok_or_else(|| EnrollmentError::Malformed("submission is missing token_secret".into()))?,
        )?;
        let spki_sha256 = JoinToken::spki_binding(&spki_der);

        let payload = match self.store.redeem(&token_secret, &spki_sha256, now) {
            Ok(grant) => {
                let sas_fingerprint_hex = self
                    .sas
                    .map(|sas| sas.fingerprint_hex())
                    .unwrap_or_default();
                // The enrollment record appended to the KT log — identity binding, token id,
                // timestamps, SAS fingerprint and the *honest* attestation state.
                let record = json!({
                    "kind": "enrollment",
                    "protocol": ENROLLMENT_PROTOCOL,
                    "device_name": device_name.clone(),
                    "spki_sha256": to_hex(&spki_sha256),
                    "token_id": to_hex(&grant.token_id),
                    "token_issued_at": grant.token_issued_at,
                    "redeemed_at": grant.redeemed_at,
                    "sas_fingerprint": sas_fingerprint_hex.clone(),
                    "assurance": self.attestation.assurance(),
                    "attestation": self.attestation.label(),
                    "attestation_detail": self.attestation.detail(),
                });
                let kt_entry = match self.audit.as_mut() {
                    Some(audit) => Some(audit.record_enrollment(&record)?),
                    None => None,
                };
                json!({
                    "status": "issued",
                    "device_name": device_name,
                    "spki_sha256": to_hex(&spki_sha256),
                    "token_id": to_hex(&grant.token_id),
                    "redeemed_at": grant.redeemed_at,
                    "assurance": record["assurance"].clone(),
                    "attestation": record["attestation"].clone(),
                    "sas_fingerprint": sas_fingerprint_hex,
                    "kt_entry": kt_entry,
                })
            }
            Err(err) => json!({
                "status": "refused",
                "code": refusal_code(&err),
                "detail": err.to_string(),
            }),
        };

        let bytes = serde_json::to_vec(&payload).map_err(|e| EnrollmentError::Seal(e.to_string()))?;
        let sealed = seal(&derive_key(S2C_DOMAIN, &session_key), &transcript, &bytes)?;
        Ok(ServerGrant { sealed })
    }
}

impl EnrollmentIssuer<InMemoryJoinTokenStore> {
    /// Convenience constructor for the local ceremony (in-memory token store).
    pub fn local(code_phrase: &str, session_id: [u8; 32]) -> Self {
        Self::new(code_phrase, session_id, InMemoryJoinTokenStore::new())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Local two-endpoint ceremony (tests + `tallow enroll`)
// ─────────────────────────────────────────────────────────────────────────────

/// The code phrase used by the local loopback ceremony (documented demo value; a real
/// ceremony gets the phrase from the operator at both endpoints).
pub const LOOPBACK_CODE_PHRASE: &str = "tallow-loopback-demo-phrase";

/// Which local demonstration to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackScenario {
    /// Honest ceremony: identical words on both screens, token consumed, grant issued.
    Happy,
    /// The operator rejects the SAS on the enrollee screen (must abort before the token is presented).
    SasRejected,
    /// The two endpoints used *different* code phrases (relay/MITM simulation).
    MismatchedPhrase,
    /// The join token was already consumed by a previous ceremony (replay).
    Replay,
}

impl LoopbackScenario {
    /// Parse a CLI scenario name.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "happy" => Some(LoopbackScenario::Happy),
            "sas-rejected" => Some(LoopbackScenario::SasRejected),
            "mismatched-phrase" => Some(LoopbackScenario::MismatchedPhrase),
            "replay" => Some(LoopbackScenario::Replay),
            other => {
                let _ = other;
                None
            }
        }
    }

    /// Stable name (CLI/JSON).
    pub fn name(&self) -> &'static str {
        match self {
            LoopbackScenario::Happy => "happy",
            LoopbackScenario::SasRejected => "sas-rejected",
            LoopbackScenario::MismatchedPhrase => "mismatched-phrase",
            LoopbackScenario::Replay => "replay",
        }
    }

    /// All scenarios, for CLI help/tests.
    pub fn all() -> [LoopbackScenario; 4] {
        [
            LoopbackScenario::Happy,
            LoopbackScenario::SasRejected,
            LoopbackScenario::MismatchedPhrase,
            LoopbackScenario::Replay,
        ]
    }
}

/// Everything the local ceremony observed — the evidence a test or CLI prints.
#[derive(Debug, Clone)]
pub struct LoopbackOutcome {
    /// Scenario that ran.
    pub scenario: LoopbackScenario,
    /// Ceremony session id.
    pub session_id: [u8; 32],
    /// Device name presented.
    pub device_name: String,
    /// `SHA-256(SPKI)` of the presented key.
    pub spki_sha256: [u8; 32],
    /// SAS shown on the enrollee screen (when the exchange reached key derivation).
    pub enrollee_sas: Option<SasCode>,
    /// SAS shown on the issuer screen.
    pub issuer_sas: Option<SasCode>,
    /// Whether the two screens showed the same words.
    pub sas_match: bool,
    /// Whether the enrollee aborted on key confirmation (relay/MITM screen).
    pub mitm_detected: bool,
    /// Whether the join token was consumed by this run.
    pub token_consumed: bool,
    /// Join tokens still outstanding afterwards.
    pub tokens_outstanding: usize,
    /// Issuance binding, when the ceremony completed.
    pub grant: Option<EnrollmentGrant>,
    /// Refusal (operator abort, replay, key-confirmation failure…), when it did not.
    pub refusal: Option<Refusal>,
    /// Attestation state recorded by the issuer.
    pub attestation: Attestation,
    /// Enrollment records appended to the audit sink.
    pub audit_records: usize,
}

/// Run the local (in-process, single-threaded, no network) two-endpoint ceremony.
///
/// This is the shipped orchestration: the same steps a daemon would drive over a socket,
/// executed against local structures so the ceremony is testable and demonstrable offline.
pub fn run_loopback(scenario: LoopbackScenario, device_name: &str, now: i64) -> Result<LoopbackOutcome> {
    let session_id = new_session_id();
    let (enrollee_phrase, issuer_phrase) = match scenario {
        LoopbackScenario::MismatchedPhrase => (
            format!("{LOOPBACK_CODE_PHRASE}-left"),
            format!("{LOOPBACK_CODE_PHRASE}-right"),
        ),
        _ => (
            LOOPBACK_CODE_PHRASE.to_string(),
            LOOPBACK_CODE_PHRASE.to_string(),
        ),
    };

    // Device key + real SPKI DER; the join token is bound to SHA-256(SPKI).
    let (_, verifying_key) = crate::signing::generate_keypair();
    let spki_der = spki_from_ed25519(&verifying_key.to_bytes());
    let spki_sha256 = JoinToken::spki_binding(&spki_der);

    let mut enrollee = Enrollee::new(&enrollee_phrase, session_id, device_name, spki_der.clone());
    let mut issuer = EnrollmentIssuer::local(&issuer_phrase, session_id);
    let audit = CountingAudit::default();
    issuer.set_audit(Box::new(audit.clone()));

    let token = issuer
        .mint_token(&spki_der, DEFAULT_TOKEN_TTL_SECS, now)
        .map_err(EnrollmentError::Join)?;

    // Replay scenario: a previous ceremony already consumed this token.
    if scenario == LoopbackScenario::Replay {
        issuer
            .store()
            .redeem(token.secret(), &spki_sha256, now)
            .map_err(EnrollmentError::Join)?;
    }

    let mut outcome = LoopbackOutcome {
        scenario,
        session_id,
        device_name: device_name.to_string(),
        spki_sha256,
        enrollee_sas: None,
        issuer_sas: None,
        sas_match: false,
        mitm_detected: false,
        token_consumed: false,
        tokens_outstanding: 0,
        grant: None,
        refusal: None,
        attestation: issuer.attestation().clone(),
        audit_records: 0,
    };

    let hello = enrollee.hello();

    if scenario == LoopbackScenario::MismatchedPhrase {
        // A relaying attacker: leg 1 completes between the enrollee (phrase A) and the
        // attacker *playing issuer*; leg 2 completes between the attacker *playing enrollee*
        // (phrase B) and the real issuer. Both legs succeed cryptographically — only the SAS
        // word comparison on the two screens exposes the relay.
        let mut attacker_issuer = EnrollmentIssuer::local(&enrollee_phrase, session_id);
        let attacker_ack = attacker_issuer.on_hello(&hello)?;
        let client_sas = enrollee.on_ack(&attacker_ack)?;

        let mut conduit = Enrollee::new(&issuer_phrase, session_id, device_name, spki_der.clone());
        let server_ack = issuer.on_hello(&conduit.hello())?;
        let server_sas = conduit.on_ack(&server_ack)?;

        outcome.enrollee_sas = Some(client_sas);
        outcome.issuer_sas = Some(server_sas);
        outcome.sas_match = client_sas.compare(&server_sas);

        // The attacker forwards the enrollee's sealed submission across the legs; the real
        // issuer's key came from the *other* leg, so the seal refuses to open.
        let submission = enrollee.submission(token.secret(), true)?;
        match issuer.on_submission(&submission, now) {
            Err(EnrollmentError::KeyConfirmationFailed) => {
                outcome.mitm_detected = true;
                outcome.refusal = Some(Refusal {
                    code: "key_confirmation_failed".to_string(),
                    detail: "the relayed submission does not open under this leg's key — the \
                             attacker cannot bridge the two PAKE legs"
                        .to_string(),
                });
            }
            Err(other) => return Err(other),
            Ok(_) => {
                return Err(EnrollmentError::Refused {
                    code: "mitm_not_detected".to_string(),
                    detail: "a relaying attacker completed the ceremony — invariant violated"
                        .to_string(),
                })
            }
        }
        outcome.tokens_outstanding = issuer.store().outstanding();
        return Ok(outcome);
    }

    let ack = issuer.on_hello(&hello)?;
    if let Some(sas) = issuer.sas() {
        outcome.issuer_sas = Some(sas);
    }

    let enrollee_sas = enrollee.on_ack(&ack)?;
    outcome.enrollee_sas = Some(enrollee_sas);
    outcome.sas_match = match outcome.issuer_sas {
        Some(issuer_sas) => enrollee_sas.compare(&issuer_sas),
        None => false,
    };

    let confirmation = match scenario {
        // The operator reads both screens; here the harness answers for the enrollee.
        LoopbackScenario::SasRejected => false,
        _ => outcome.sas_match,
    };

    let submission = match enrollee.submission(token.secret(), confirmation) {
        Ok(submission) => submission,
        Err(EnrollmentError::SasNotConfirmed) => {
            outcome.refusal = Some(Refusal {
                code: "sas_not_confirmed".to_string(),
                detail: "SAS words were not confirmed on both screens — the join token was \
                         never presented"
                    .to_string(),
            });
            outcome.tokens_outstanding = issuer.store().outstanding();
            return Ok(outcome);
        }
        Err(other) => return Err(other),
    };

    let grant_message = issuer.on_submission(&submission, now)?;
    match enrollee.on_grant(&grant_message) {
        Ok(grant) => outcome.grant = Some(grant),
        Err(EnrollmentError::Refused { code, detail }) => {
            outcome.refusal = Some(Refusal { code, detail });
        }
        Err(other) => return Err(other),
    }

    outcome.token_consumed = issuer.store().outstanding() == 0 && outcome.grant.is_some();
    outcome.tokens_outstanding = issuer.store().outstanding();
    outcome.audit_records = audit.tally().0;
    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI entry points (`tallow enroll …`)
// ─────────────────────────────────────────────────────────────────────────────

/// `tallow enroll` implementation surface (the clap types live in `src/main.rs`).
pub mod cli {
    use super::*;

    /// Exit code for a completed ceremony (issued).
    pub const EXIT_ISSUED: i32 = 0;
    /// Exit code for a checked refusal / detection.
    pub const EXIT_REFUSED: i32 = 1;
    /// Exit code for "could not run".
    pub const EXIT_UNAVAILABLE: i32 = 2;

    fn outcome_json(outcome: &LoopbackOutcome) -> Value {
        json!({
            "protocol": ENROLLMENT_PROTOCOL,
            "scenario": outcome.scenario.name(),
            "session_id": to_hex(&outcome.session_id),
            "device_name": outcome.device_name,
            "spki_sha256": to_hex(&outcome.spki_sha256),
            "enrollee_sas": outcome.enrollee_sas.map(|s| s.words().to_vec()),
            "issuer_sas": outcome.issuer_sas.map(|s| s.words().to_vec()),
            "sas_fingerprint": outcome.enrollee_sas.map(|s| s.fingerprint_hex()),
            "sas_match": outcome.sas_match,
            "mitm_detected": outcome.mitm_detected,
            "token_consumed": outcome.token_consumed,
            "tokens_outstanding": outcome.tokens_outstanding,
            "assurance": outcome.attestation.assurance(),
            "attestation": outcome.attestation.label(),
            "attestation_detail": outcome.attestation.detail(),
            "grant": outcome.grant.as_ref().map(|grant| json!({
                "device_name": grant.device_name,
                "spki_sha256": to_hex(&grant.spki_sha256),
                "token_id": to_hex(&grant.token_id),
                "redeemed_at": grant.redeemed_at,
                "assurance": grant.assurance,
                "kt_entry": grant.kt_entry,
            })),
            "refusal": outcome.refusal.as_ref().map(|r| json!({
                "code": r.code,
                "detail": r.detail,
            })),
        })
    }

    fn words_line(label: &str, sas: Option<SasCode>) -> String {
        match sas {
            Some(sas) => format!(
                "{label}: {} (fingerprint {})",
                sas.words().join("-"),
                sas.fingerprint_hex()
            ),
            None => format!("{label}: (not derived)"),
        }
    }

    /// Run `tallow enroll ceremony`.
    pub fn run_enroll_ceremony(scenario_name: &str, device_name: &str, format: &str) -> i32 {
        let Some(scenario) = LoopbackScenario::parse(scenario_name) else {
            eprintln!(
                "tallow enroll ceremony: unknown scenario {scenario_name:?} (expected one of: {})",
                LoopbackScenario::all()
                    .iter()
                    .map(LoopbackScenario::name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return EXIT_UNAVAILABLE;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let outcome = match run_loopback(scenario, device_name, now) {
            Ok(outcome) => outcome,
            Err(err) => {
                eprintln!("tallow enroll ceremony: ceremony could not run: {err}");
                return EXIT_UNAVAILABLE;
            }
        };

        if format == "json" {
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome_json(&outcome)).unwrap_or_else(|_| "{}".into())
            );
        } else {
            println!("enrollment ceremony — scenario={}", outcome.scenario.name());
            println!("session:        {}", to_hex(&outcome.session_id));
            println!("device:         {}", outcome.device_name);
            println!("spki sha256:    {}", to_hex(&outcome.spki_sha256));
            println!("{}", words_line("enrollee screen", outcome.enrollee_sas));
            println!("{}", words_line("issuer screen  ", outcome.issuer_sas));
            println!(
                "screens match:  {}",
                if outcome.sas_match { "yes" } else { "no" }
            );
            println!(
                "attestation:    {} (assurance={}) — {}",
                outcome.attestation.label(),
                outcome.attestation.assurance(),
                outcome.attestation.detail()
            );
            println!(
                "join token:     {}",
                if outcome.token_consumed {
                    "consumed (single use)".to_string()
                } else {
                    format!("not consumed ({} outstanding)", outcome.tokens_outstanding)
                }
            );
            if let Some(grant) = outcome.grant.as_ref() {
                println!(
                    "KT log:         {} (entry {})",
                    outcome.audit_records,
                    grant.kt_entry.clone().unwrap_or_else(|| "n/a".to_string())
                );
                println!(
                    "result:         ISSUED (token_id {}, assurance={})",
                    to_hex(&grant.token_id),
                    grant.assurance
                );
            }
            if let Some(refusal) = outcome.refusal.as_ref() {
                println!("result:         REFUSED ({refusal})");
            }
            if outcome.mitm_detected {
                println!(
                    "NOTE:            key confirmation failed and the two screens show different \
                     words — this is the relay/MITM screen, not a transient error."
                );
            }
        }

        if outcome.grant.is_some() {
            EXIT_ISSUED
        } else {
            EXIT_REFUSED
        }
    }

    /// Run `tallow enroll token` — mint a single-use join token for a fresh demo device key.
    pub fn run_enroll_token(ttl_secs: i64, format: &str) -> i32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (_, verifying_key) = crate::signing::generate_keypair();
        let spki_der = spki_from_ed25519(&verifying_key.to_bytes());
        let digest = JoinToken::spki_binding(&spki_der);
        let store = InMemoryJoinTokenStore::new();
        let token = match store.mint(&digest, ttl_secs, now) {
            Ok(token) => token,
            Err(err) => {
                eprintln!("tallow enroll token: refused: {err}");
                return EXIT_REFUSED;
            }
        };
        if format == "json" {
            let payload = json!({
                "protocol": ENROLLMENT_PROTOCOL,
                "token_id": to_hex(&token.token_id()),
                "token_secret": token.secret_hex(),
                "spki_sha256": to_hex(&digest),
                "issued_at": token.issued_at(),
                "expires_at": token.expires_at(),
                "ttl_secs": token.ttl_secs(),
                "max_ttl_secs": JOIN_TOKEN_MAX_TTL_SECS,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
            );
        } else {
            println!("enrollment join token (single use, SPKI-bound)");
            println!("token id:     {}", to_hex(&token.token_id()));
            println!("token secret: {}", token.secret_hex());
            println!("spki sha256:  {}", to_hex(&digest));
            println!("issued:       {} (ttl {}s, max {JOIN_TOKEN_MAX_TTL_SECS}s)", token.issued_at(), token.ttl_secs());
            println!("expires:      {}", token.expires_at());
        }
        EXIT_ISSUED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        1_800_000_000
    }

    #[test]
    fn happy_path_issues_and_consumes_the_token_once() {
        let outcome = run_loopback(LoopbackScenario::Happy, "test-device", now()).unwrap();
        assert!(outcome.sas_match, "both screens must show the same words");
        assert!(!outcome.mitm_detected);
        let grant = outcome.grant.expect("happy path issues");
        assert_eq!(grant.device_name, "test-device");
        assert_eq!(grant.spki_sha256, outcome.spki_sha256);
        assert_eq!(grant.sas_fingerprint_hex, outcome.enrollee_sas.unwrap().fingerprint_hex());
        assert!(outcome.token_consumed, "the token must be consumed exactly once");
        assert_eq!(outcome.tokens_outstanding, 0);
        assert_eq!(outcome.audit_records, 1, "the enrollment must be KT-logged");
        assert!(grant.kt_entry.is_some(), "the grant carries the log entry hash");
        assert_eq!(
            grant.attestation_label,
            outcome.attestation.label(),
            "the recorded attestation must match this host's honest state"
        );
        // This host has no TPM device node (measured) ⇒ software assurance, no fake quote.
        assert!(!outcome.attestation.available());
        assert_eq!(outcome.attestation.assurance(), "software");
    }

    #[test]
    fn replayed_join_token_is_refused() {
        let outcome = run_loopback(LoopbackScenario::Replay, "test-device", now()).unwrap();
        let refusal = outcome.refusal.expect("replay must be refused");
        assert_eq!(refusal.code, "join_replay");
        assert!(outcome.grant.is_none());
        assert!(!outcome.token_consumed);
        assert_eq!(outcome.tokens_outstanding, 0, "the (replayed) token is not outstanding");
    }

    #[test]
    fn sas_rejection_aborts_before_the_token_is_consumed() {
        let outcome = run_loopback(LoopbackScenario::SasRejected, "test-device", now()).unwrap();
        assert!(outcome.sas_match, "the words did match; the operator declined anyway");
        let refusal = outcome.refusal.expect("a declined SAS must abort");
        assert_eq!(refusal.code, "sas_not_confirmed");
        assert!(outcome.grant.is_none());
        assert!(!outcome.token_consumed);
        assert_eq!(
            outcome.tokens_outstanding, 1,
            "an aborted ceremony must not burn the join token"
        );
    }

    #[test]
    fn mismatched_code_phrases_are_detected() {
        let outcome =
            run_loopback(LoopbackScenario::MismatchedPhrase, "test-device", now()).unwrap();
        assert!(outcome.mitm_detected, "different phrases must fail key confirmation");
        let refusal = outcome.refusal.expect("key confirmation failure is a refusal");
        assert_eq!(refusal.code, "key_confirmation_failed");
        assert!(outcome.grant.is_none());
        assert!(!outcome.token_consumed);
        // Both sides derived a SAS, but the two screens disagree — the human-visible screen.
        let left = outcome.enrollee_sas.expect("enrollee derived its own SAS");
        let right = outcome.issuer_sas.expect("issuer derived its own SAS");
        assert!(!left.compare(&right), "the two screens must show different words");
        assert_ne!(left.display(), right.display());
    }

    #[test]
    fn tampered_submission_cannot_complete_the_ceremony() {
        let session_id = new_session_id();
        let (_, verifying_key) = crate::signing::generate_keypair();
        let spki_der = spki_from_ed25519(&verifying_key.to_bytes());
        let mut enrollee = Enrollee::new(LOOPBACK_CODE_PHRASE, session_id, "tamper-device", spki_der.clone());
        let mut issuer = EnrollmentIssuer::local(LOOPBACK_CODE_PHRASE, session_id);
        let token = issuer.mint_token(&spki_der, DEFAULT_TOKEN_TTL_SECS, now()).unwrap();

        let hello = enrollee.hello();
        let ack = issuer.on_hello(&hello).unwrap();
        enrollee.on_ack(&ack).unwrap();
        let mut submission = enrollee.submission(token.secret(), true).unwrap();
        // Flip one ciphertext byte: the AEAD tag must refuse to open.
        let last = submission.sealed.len() - 1;
        submission.sealed[last] ^= 0x01;
        let err = issuer.on_submission(&submission, now()).unwrap_err();
        assert!(matches!(err, EnrollmentError::KeyConfirmationFailed));
        assert_eq!(issuer.store().outstanding(), 1, "no token was consumed");
    }

    #[test]
    fn tampered_grant_is_refused_by_the_enrollee() {
        let session_id = new_session_id();
        let (_, verifying_key) = crate::signing::generate_keypair();
        let spki_der = spki_from_ed25519(&verifying_key.to_bytes());
        let mut enrollee = Enrollee::new(LOOPBACK_CODE_PHRASE, session_id, "tamper-device", spki_der.clone());
        let mut issuer = EnrollmentIssuer::local(LOOPBACK_CODE_PHRASE, session_id);
        let token = issuer.mint_token(&spki_der, DEFAULT_TOKEN_TTL_SECS, now()).unwrap();

        let ack = issuer.on_hello(&enrollee.hello()).unwrap();
        enrollee.on_ack(&ack).unwrap();
        let submission = enrollee.submission(token.secret(), true).unwrap();
        let mut grant = issuer.on_submission(&submission, now()).unwrap();
        let last = grant.sealed.len() - 1;
        grant.sealed[last] ^= 0x01;
        let err = enrollee.on_grant(&grant).unwrap_err();
        assert!(matches!(err, EnrollmentError::KeyConfirmationFailed));
    }

    #[test]
    fn join_token_is_bound_to_the_presented_spki() {
        let session_id = new_session_id();
        let (_, enrollee_key) = crate::signing::generate_keypair();
        let enrollee_spki = spki_from_ed25519(&enrollee_key.to_bytes());
        let (_, other_key) = crate::signing::generate_keypair();
        let other_spki = spki_from_ed25519(&other_key.to_bytes());

        let mut enrollee = Enrollee::new(LOOPBACK_CODE_PHRASE, session_id, "bound-device", enrollee_spki);
        let mut issuer = EnrollmentIssuer::local(LOOPBACK_CODE_PHRASE, session_id);
        // Token bound to a *different* SPKI than the one presented.
        let token = issuer.mint_token(&other_spki, DEFAULT_TOKEN_TTL_SECS, now()).unwrap();

        let ack = issuer.on_hello(&enrollee.hello()).unwrap();
        enrollee.on_ack(&ack).unwrap();
        let submission = enrollee.submission(token.secret(), true).unwrap();
        let grant_message = issuer.on_submission(&submission, now()).unwrap();
        let err = enrollee.on_grant(&grant_message).unwrap_err();
        match err {
            EnrollmentError::Refused { code, .. } => assert_eq!(code, "join_spki_mismatch"),
            other => panic!("expected an SPKI mis-binding refusal, got {other:?}"),
        }
        assert_eq!(issuer.store().outstanding(), 1);
    }

    #[test]
    fn expired_join_token_is_refused() {
        let session_id = new_session_id();
        let (_, verifying_key) = crate::signing::generate_keypair();
        let spki_der = spki_from_ed25519(&verifying_key.to_bytes());
        let mut enrollee = Enrollee::new(LOOPBACK_CODE_PHRASE, session_id, "stale-device", spki_der.clone());
        let mut issuer = EnrollmentIssuer::local(LOOPBACK_CODE_PHRASE, session_id);
        let token = issuer.mint_token(&spki_der, 60, now()).unwrap();

        let ack = issuer.on_hello(&enrollee.hello()).unwrap();
        enrollee.on_ack(&ack).unwrap();
        let submission = enrollee.submission(token.secret(), true).unwrap();
        // Redeem well after the TTL.
        let grant_message = issuer.on_submission(&submission, now() + 3600).unwrap();
        let err = enrollee.on_grant(&grant_message).unwrap_err();
        match err {
            EnrollmentError::Refused { code, .. } => assert_eq!(code, "join_expired"),
            other => panic!("expected an expiry refusal, got {other:?}"),
        }
    }

    #[test]
    fn enrollment_is_appended_to_a_real_kt_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enrollment-kt.jsonl");
        let kt = crate::kt_log::KtLog::open(&path).unwrap();

        let session_id = new_session_id();
        let (_, verifying_key) = crate::signing::generate_keypair();
        let spki_der = spki_from_ed25519(&verifying_key.to_bytes());
        let mut enrollee = Enrollee::new(LOOPBACK_CODE_PHRASE, session_id, "kt-device", spki_der.clone());
        let mut issuer = EnrollmentIssuer::local(LOOPBACK_CODE_PHRASE, session_id);
        issuer.set_audit(Box::new(kt));
        let token = issuer.mint_token(&spki_der, DEFAULT_TOKEN_TTL_SECS, now()).unwrap();

        let ack = issuer.on_hello(&enrollee.hello()).unwrap();
        enrollee.on_ack(&ack).unwrap();
        let submission = enrollee.submission(token.secret(), true).unwrap();
        let grant_message = issuer.on_submission(&submission, now()).unwrap();
        let grant = enrollee.on_grant(&grant_message).unwrap();

        let entry_hash = grant.kt_entry.expect("grant carries the KT entry hash");
        let reopened = crate::kt_log::KtLog::open(&path).unwrap();
        assert_eq!(reopened.len(), 1, "exactly one enrollment record must be appended");
        reopened.verify_chain().expect("the chain must verify");
        assert_eq!(reopened.entries()[0].entry_hash, entry_hash);
        assert!(reopened.tree_root().len() >= 32);
    }

    #[test]
    fn attestation_detection_matches_this_host() {
        let attestation = detect_attestation();
        let tpm_present = std::path::Path::new("/dev/tpm0").exists()
            || std::path::Path::new("/dev/tpmrm0").exists();
        if tpm_present {
            assert!(matches!(attestation, Attestation::DevicePresentNoQuote { .. }));
        } else {
            assert!(matches!(attestation, Attestation::Unavailable { .. }));
        }
        assert!(!attestation.available(), "no verified quote is fabricated");
        assert_eq!(attestation.assurance(), "software");
        assert!(attestation.label() == "unavailable" || attestation.label() == "device-present-no-quote");
    }

    #[test]
    fn session_ids_and_sas_differ_between_runs() {
        let first = run_loopback(LoopbackScenario::Happy, "device-a", now()).unwrap();
        let second = run_loopback(LoopbackScenario::Happy, "device-b", now()).unwrap();
        assert_ne!(first.session_id, second.session_id);
        let left = first.enrollee_sas.unwrap();
        let right = second.enrollee_sas.unwrap();
        assert!(
            !left.compare(&right),
            "independent ceremonies must not share a SAS (fresh session id + fresh key)"
        );
    }

    #[test]
    fn spki_helper_builds_rfc8410_ed25519_der() {
        let der = spki_from_ed25519(&[7u8; 32]);
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..12], &ED25519_SPKI_PREFIX[..]);
        assert_eq!(&der[12..], &[7u8; 32]);
        assert_eq!(der[0], 0x30);
    }
}
