//! Authenticated inter-component session handshake model (B7.1.1–B7.1.3).
//!
//! Frozen interface §1 (batch 13). This module is the **pure handshake model**
//! for authenticating an IPC session between two Tallow components (e.g. the
//! daemon and a browser-bridge worker) that share a pre-shared key (PSK):
//!
//! 1. **B7.1.1 — hello + transcript + proof** ([`hello`], [`transcript`],
//!    [`proof`]): the initiator announces itself with a [`Hello`] carrying a
//!    caller-supplied 32-byte nonce (encoded as exactly 64 lowercase hex
//!    characters). Both sides derive the same [`transcript`] string
//!    (`tallow-ipc-auth-v1|<initiator>|<responder>|<nonce>`) and each returns
//!    an HMAC-SHA256 **proof** over `transcript + "|" + role-label`
//!    (`"initiator"` / `"responder"`), rendered as 64 lowercase hex characters.
//!    [`verify`] re-derives the proof and compares in constant time via
//!    `hmac`'s [`Mac::verify_slice`].
//! 2. **B7.1.2 — replay guard** ([`SeenNonces`]): a monotone record of every
//!    nonce consumed by a completed handshake. [`SeenNonces::accept`] returns
//!    `false` (and records nothing new) when the nonce was already consumed;
//!    [`Session::establish`] refuses a replayed nonce with
//!    [`IpcAuthError::Replayed`] **before** doing any crypto work.
//! 3. **B7.1.3 — session establishment** ([`Session::establish`]): validates
//!    the full transcript evidence (both role proofs), checks the replay guard,
//!    checks the TTL, then mints a [`Session`] (id derived from the transcript
//!    + both proofs — both parties compute the same value) with a
//!    saturating `expires_ms = now_ms + ttl_ms`. [`Session::valid`] uses the
//!    strict `<` expiry rule: a session is valid while `now_ms < expires_ms`.
//!
//! # Pinned checks (do not reorder)
//!
//! [`Session::establish`] evaluates in this exact order: psk / hello / proof
//! *field* validation → nonce replay → initiator proof → responder proof →
//! `ttl_ms > 0` → session id. A **failed** handshake records nothing in the
//! [`SeenNonces`] guard (a nonce is only burned by success), so a transient
//! failure never forces the caller to invent a fresh nonce.
//!
//! # Invariants
//!
//! - **Pure & deterministic**: functions of their arguments only — no clock, no
//!   randomness, no I/O, no globals. Same inputs ⇒ byte-identical outputs
//!   (pinned). Time is always passed in as `now_ms`; nonce generation is the
//!   *caller's* job (`rand` + lowercase hex of 32 bytes).
//! - **Transcript label is the constant**: [`transcript`] formats
//!   [`PROTOCOL_LABEL`] itself, not the (untrusted) `Hello::protocol` field, so
//!   a hand-built `Hello` cannot move the transcript off-protocol.
//! - **Wire names are verbatim variant / field names** (`"Initiator"`,
//!   `"BadProof"`, `"protocol"`, …); serde derives are reused unchanged.
//! - **Scope**: pure in-memory model. Not wired into `lib.rs` yet (the parent
//!   does that: `pub mod ipc_auth;`). This is a protocol **model**, not an
//!   audited Noise/SPAKE2 implementation — see `docs/ops/ipc_auth.md`.
//!   No `crate::` dependencies; only `serde`, `sha2`, `hmac` (+ `serde_json`
//!   in tests).

use std::collections::HashSet;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Protocol label bound into every transcript (pinned; never change in place —
/// a new label means a new protocol version).
pub const PROTOCOL_LABEL: &str = "tallow-ipc-auth-v1";

/// A nonce is exactly 64 lowercase hex characters = 32 bytes.
const NONCE_HEX_LEN: usize = 64;

/// Upper/lower hex alphabet for encoding (encoding emits lowercase only).
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

type HmacSha256 = Hmac<Sha256>;

// ── Role ────────────────────────────────────────────────────────────────────

/// Which side of the handshake a proof belongs to.
///
/// The role is bound into the proof payload as a lowercase label
/// ([`Role::label`]), so an initiator proof can never be replayed as a
/// responder proof within the same transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// The side that sends the first `Hello`.
    Initiator,
    /// The side that answers.
    Responder,
}

impl Role {
    /// Lowercase wire label bound into the proof payload (`"initiator"` /
    /// `"responder"`).
    pub fn label(self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

// ── Hello ───────────────────────────────────────────────────────────────────

/// The handshake opening message. `protocol` is always set to
/// [`PROTOCOL_LABEL`] by [`hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol label (`"tallow-ipc-auth-v1"`). Carried for wire clarity; the
    /// transcript always binds [`PROTOCOL_LABEL`] regardless of this field.
    pub protocol: String,
    /// Initiator component id (non-empty).
    pub initiator: String,
    /// Responder component id (non-empty).
    pub responder: String,
    /// 32-byte nonce, exactly 64 lowercase hex characters.
    pub nonce: String,
}

/// Build a [`Hello`] for a fresh handshake.
///
/// Refusals (checked in this order): empty `initiator` →
/// [`IpcAuthError::BadInput`]`("initiator")`; empty `responder` →
/// `BadInput("responder")`; `nonce` that is not exactly 64 lowercase hex
/// characters → `BadInput("nonce")`.
pub fn hello(initiator: &str, responder: &str, nonce: &str) -> Result<Hello, IpcAuthError> {
    if initiator.is_empty() {
        return Err(IpcAuthError::BadInput("initiator"));
    }
    if responder.is_empty() {
        return Err(IpcAuthError::BadInput("responder"));
    }
    if !is_canonical_nonce(nonce) {
        return Err(IpcAuthError::BadInput("nonce"));
    }
    Ok(Hello {
        protocol: PROTOCOL_LABEL.to_string(),
        initiator: initiator.to_string(),
        responder: responder.to_string(),
        nonce: nonce.to_string(),
    })
}

/// Re-check the field invariants of an externally constructed [`Hello`]
/// (same rules and order as [`hello`]).
fn validate_hello(h: &Hello) -> Result<(), IpcAuthError> {
    if h.initiator.is_empty() {
        return Err(IpcAuthError::BadInput("initiator"));
    }
    if h.responder.is_empty() {
        return Err(IpcAuthError::BadInput("responder"));
    }
    if !is_canonical_nonce(&h.nonce) {
        return Err(IpcAuthError::BadInput("nonce"));
    }
    Ok(())
}

// ── Transcript + proofs ─────────────────────────────────────────────────────

/// The transcript both sides sign: `tallow-ipc-auth-v1|<initiator>|<responder>|<nonce>`
/// (verbatim pin). Uses the canonical [`PROTOCOL_LABEL`], not `h.protocol`.
pub fn transcript(h: &Hello) -> String {
    format!(
        "{}|{}|{}|{}",
        PROTOCOL_LABEL, h.initiator, h.responder, h.nonce
    )
}

/// Session id, shared by both parties: `sess-` + the first 12 hex chars of
/// SHA-256 over the transcript and **both** proofs (domain-separated).
///
/// Both sides compute it for the same exchange — a local counter could never
/// be validated by the peer — so a responder can register the id it minted
/// and later validate a presented `X-Tallow-Session` value.
pub fn session_id(h: &Hello, initiator_proof: &str, responder_proof: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tallow-ipc-sess-v1|");
    hasher.update(transcript(h).as_bytes());
    hasher.update(b"|");
    hasher.update(initiator_proof.as_bytes());
    hasher.update(b"|");
    hasher.update(responder_proof.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("sess-{}", &hex[..12])
}

/// The exact byte payload a proof signs: `transcript + "|" + role-label`.
fn proof_payload(h: &Hello, role: Role) -> String {
    format!("{}|{}", transcript(h), role.label())
}

/// Fresh HMAC-SHA256 instance keyed by `psk` over the role's proof payload.
fn proof_mac(psk: &[u8], h: &Hello, role: Role) -> Result<HmacSha256, IpcAuthError> {
    if psk.is_empty() {
        return Err(IpcAuthError::BadInput("psk"));
    }
    let mut mac =
        HmacSha256::new_from_slice(psk).map_err(|_| IpcAuthError::BadInput("psk"))?;
    mac.update(proof_payload(h, role).as_bytes());
    Ok(mac)
}

/// Compute this side's proof: lowercase hex HMAC-SHA256 over
/// `transcript + "|" + role-label`.
///
/// Empty `psk` → [`IpcAuthError::BadInput`]`("psk")`. Deterministic: equal
/// inputs (incl. role) always yield the same 64-hex-character string.
pub fn proof(psk: &[u8], h: &Hello, role: Role) -> Result<String, IpcAuthError> {
    let mac = proof_mac(psk, h, role)?;
    Ok(to_hex(mac.finalize().into_bytes().as_slice()))
}

/// Verify a peer's proof against the local PSK.
///
/// psk is validated first (empty → `BadInput("psk")`), then the hex *format* of
/// `proof_hex` (not hex-decodable — odd length or a non-hex character →
/// `BadInput("proof")`). Any well-formed hex that simply does not match yields
/// `Ok(false)`; the comparison itself is constant-time
/// ([`Mac::verify_slice`]). Hex decoding follows standard semantics and
/// accepts either case (uppercase hex of the same bytes still verifies).
pub fn verify(
    psk: &[u8],
    h: &Hello,
    role: Role,
    proof_hex: &str,
) -> Result<bool, IpcAuthError> {
    if psk.is_empty() {
        return Err(IpcAuthError::BadInput("psk"));
    }
    let raw = from_hex(proof_hex).ok_or(IpcAuthError::BadInput("proof"))?;
    let mac = proof_mac(psk, h, role)?;
    Ok(mac.verify_slice(&raw).is_ok())
}

// ── Replay guard (B7.1.2) ───────────────────────────────────────────────────

/// Monotone replay guard: records every nonce consumed by a **successful**
/// handshake and refuses repeats.
///
/// A nonce is recorded exactly once; [`accept`](SeenNonces::accept) returns
/// `false` for a repeat and records nothing new. Failed handshakes (bad proof,
/// bad TTL, …) must not call `accept`, so they do not burn the nonce.
#[derive(Debug, Clone, Default)]
pub struct SeenNonces {
    seen: HashSet<String>,
}

impl SeenNonces {
    /// Empty guard.
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Record `nonce`. Returns `true` when it was not seen before; `false`
    /// (without recording anything) when it is a replay.
    pub fn accept(&mut self, nonce: &str) -> bool {
        self.seen.insert(nonce.to_string())
    }

    /// Number of distinct nonces consumed so far.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no nonce has been consumed yet.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Read-only membership check (does not record).
    fn contains(&self, nonce: &str) -> bool {
        self.seen.contains(nonce)
    }
}

// ── Session (B7.1.3) ────────────────────────────────────────────────────────

/// An established IPC session between two authenticated components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Session id, `sess-<12 hex>`: derived from the transcript and both
    /// proofs, so both parties of the same handshake compute the same id
    /// (see [`session_id`]).
    pub id: String,
    /// Authenticated initiator id.
    pub initiator: String,
    /// Authenticated responder id.
    pub responder: String,
    /// Wall-clock establishment time (ms, caller-supplied).
    pub established_ms: i64,
    /// Expiry: `established_ms + ttl_ms`, saturating at `i64::MAX`.
    pub expires_ms: i64,
}

impl Session {
    /// Complete a handshake over `h` with both role proofs.
    ///
    /// Pinned check order (first failure wins):
    /// 1. field validation: empty `psk` → `BadInput("psk")`; hello field
    ///    invariants (see [`hello`]); empty **or** non-hex
    ///    `initiator_proof`/`responder_proof` → `BadInput("proof")`;
    /// 2. replay: nonce already in `seen` → [`IpcAuthError::Replayed`];
    /// 3. initiator proof mismatch → [`IpcAuthError::BadProof`];
    /// 4. responder proof mismatch → [`IpcAuthError::BadProof`];
    /// 5. `ttl_ms <= 0` → `BadInput("ttl_ms")`;
    /// 6. success: `seen.accept(nonce)` records the nonce and the session id is
    ///    minted (`sess-<12 hex>`, transcript-derived — see [`session_id`]).
    ///
    /// A **failed** handshake records nothing in `seen`.
    pub fn establish(
        psk: &[u8],
        h: &Hello,
        initiator_proof: &str,
        responder_proof: &str,
        now_ms: i64,
        ttl_ms: i64,
        seen: &mut SeenNonces,
    ) -> Result<Session, IpcAuthError> {
        // 1. Field validation (no crypto, no state touched).
        if psk.is_empty() {
            return Err(IpcAuthError::BadInput("psk"));
        }
        validate_hello(h)?;
        if initiator_proof.is_empty() || from_hex(initiator_proof).is_none() {
            return Err(IpcAuthError::BadInput("proof"));
        }
        if responder_proof.is_empty() || from_hex(responder_proof).is_none() {
            return Err(IpcAuthError::BadInput("proof"));
        }

        // 2. Replay guard (read-only: a refusal must not consume the nonce).
        if seen.contains(&h.nonce) {
            return Err(IpcAuthError::Replayed);
        }

        // 3./4. Constant-time proof verification, initiator then responder.
        if !verify(psk, h, Role::Initiator, initiator_proof)? {
            return Err(IpcAuthError::BadProof);
        }
        if !verify(psk, h, Role::Responder, responder_proof)? {
            return Err(IpcAuthError::BadProof);
        }

        // 5. TTL must be a positive number of milliseconds.
        if ttl_ms <= 0 {
            return Err(IpcAuthError::BadInput("ttl_ms"));
        }

        // 6. Success: burn the nonce, then mint the session id — derived from
        // the transcript and BOTH proofs, so both parties compute the SAME id
        // (a local counter could never be validated by the peer).
        let recorded = seen.accept(&h.nonce);
        debug_assert!(recorded, "seen.contains() was checked above");
        Ok(Session {
            id: session_id(h, initiator_proof, responder_proof),
            initiator: h.initiator.clone(),
            responder: h.responder.clone(),
            established_ms: now_ms,
            expires_ms: now_ms.saturating_add(ttl_ms),
        })
    }

    /// Strict expiry rule: valid while `now_ms < expires_ms` (the expiry
    /// millisecond itself is already invalid). A clock moving backwards keeps
    /// a session valid — the rule only compares against `expires_ms`.
    pub fn valid(&self, now_ms: i64) -> bool {
        now_ms < self.expires_ms
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Handshake refusal. Serialize-only (the `&'static str` payload follows the
/// house precedent for field-name-carrying errors).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IpcAuthError {
    /// A required input field was empty/invalid; payload is the field name
    /// (`"psk"`, `"proof"`, `"nonce"`, `"initiator"`, `"responder"`,
    /// `"ttl_ms"`).
    BadInput(&'static str),
    /// A role proof did not verify against the transcript.
    BadProof,
    /// The handshake nonce was already consumed (replay refused).
    Replayed,
}

impl std::fmt::Display for IpcAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcAuthError::BadInput(field) => {
                write!(f, "invalid ipc-auth input: `{field}` must not be empty or malformed")
            }
            IpcAuthError::BadProof => {
                write!(f, "ipc-auth proof verification failed for the claimed role")
            }
            IpcAuthError::Replayed => {
                write!(f, "ipc-auth nonce replay: handshake refused")
            }
        }
    }
}

impl std::error::Error for IpcAuthError {}

// ── Hex helpers (private) ───────────────────────────────────────────────────

/// Exactly 64 characters, all in `[0-9a-f]` (uppercase is *not* canonical
/// here — a nonce must be lowercase).
fn is_canonical_nonce(s: &str) -> bool {
    s.len() == NONCE_HEX_LEN
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Lowercase hex encoding.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_ALPHABET[(b >> 4) as usize] as char);
        out.push(HEX_ALPHABET[(b & 0x0f) as usize] as char);
    }
    out
}

/// Strict hex decoding (standard semantics: either case accepted). `None` for
/// odd length or any non-hex character — including for the empty-vs-invalid
/// distinction the callers need (empty decodes to an empty vector).
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((nibble(bytes[i])? << 4) | nibble(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const PSK: &[u8] = b"tallow-ipc-test-psk";

    fn hs(initiator: &str, responder: &str, nonce: &str) -> Hello {
        hello(initiator, responder, nonce).expect("valid hello")
    }

    fn handshake(seen: &mut SeenNonces, nonce: &str, now: i64, ttl: i64) -> Result<Session, IpcAuthError> {
        let h = hs("daemon", "browser-bridge", nonce);
        let ip = proof(PSK, &h, Role::Initiator).unwrap();
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        Session::establish(PSK, &h, &ip, &rp, now, ttl, seen)
    }

    // ---------- B7.1.1 · hello ----------

    #[test]
    fn hello_pins_protocol_and_fields() {
        assert_eq!(PROTOCOL_LABEL, "tallow-ipc-auth-v1");
        let h = hs("daemon", "browser-bridge", NONCE_A);
        assert_eq!(h.protocol, PROTOCOL_LABEL);
        assert_eq!(h.initiator, "daemon");
        assert_eq!(h.responder, "browser-bridge");
        assert_eq!(h.nonce, NONCE_A);
    }

    #[test]
    fn hello_refuses_empty_ids() {
        assert_eq!(hello("", "b", NONCE_A), Err(IpcAuthError::BadInput("initiator")));
        assert_eq!(hello("a", "", NONCE_A), Err(IpcAuthError::BadInput("responder")));
        // Field order pin: both empty reports the initiator first.
        assert_eq!(hello("", "", NONCE_A), Err(IpcAuthError::BadInput("initiator")));
    }

    #[test]
    fn hello_refuses_bad_nonces() {
        // Empty, wrong length, uppercase, non-hex — all BadInput("nonce").
        for bad in [
            "",
            "abcd",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", // 63
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65
            "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", // uppercase
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeZ", // mixed
        ] {
            assert_eq!(hello("a", "b", bad), Err(IpcAuthError::BadInput("nonce")), "nonce={bad}");
        }
    }

    #[test]
    fn transcript_pin() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        assert_eq!(
            transcript(&h),
            format!("tallow-ipc-auth-v1|daemon|browser-bridge|{NONCE_A}")
        );
    }

    #[test]
    fn transcript_binds_canonical_label_not_hello_field() {
        // A hand-built Hello cannot move the transcript off-protocol: the
        // `protocol` field is decorative, PROTOCOL_LABEL is what is signed.
        let mut h = hs("daemon", "browser-bridge", NONCE_A);
        h.protocol = "evil-ipc-v0".to_string();
        assert_eq!(
            transcript(&h),
            format!("tallow-ipc-auth-v1|daemon|browser-bridge|{NONCE_A}")
        );
    }

    // ---------- B7.1.1 · proofs ----------

    #[test]
    fn proof_roundtrip_both_roles() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let ip = proof(PSK, &h, Role::Initiator).unwrap();
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        assert_eq!(verify(PSK, &h, Role::Initiator, &ip), Ok(true));
        assert_eq!(verify(PSK, &h, Role::Responder, &rp), Ok(true));
        // Roles are labelled distinctly.
        assert_ne!(ip, rp);
    }

    #[test]
    fn proof_is_64_lowercase_hex() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let p = proof(PSK, &h, Role::Initiator).unwrap();
        assert_eq!(p.len(), 64);
        assert!(p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn proof_deterministic() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        assert_eq!(
            proof(PSK, &h, Role::Initiator),
            proof(PSK, &h, Role::Initiator)
        );
        assert_ne!(
            proof(PSK, &h, Role::Initiator),
            proof(b"other-psk", &h, Role::Initiator)
        );
    }

    #[test]
    fn proof_empty_psk_refused() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        assert_eq!(proof(&[], &h, Role::Initiator), Err(IpcAuthError::BadInput("psk")));
        // psk is validated before the proof hex in verify, too.
        assert_eq!(verify(&[], &h, Role::Initiator, "zz"), Err(IpcAuthError::BadInput("psk")));
    }

    #[test]
    fn verify_wrong_psk_is_false() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let p = proof(PSK, &h, Role::Initiator).unwrap();
        assert_eq!(verify(b"wrong-psk", &h, Role::Initiator, &p), Ok(false));
    }

    #[test]
    fn verify_tampered_nonce_fails() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let p = proof(PSK, &h, Role::Initiator).unwrap();
        let h2 = hs("daemon", "browser-bridge", NONCE_B);
        assert_eq!(verify(PSK, &h2, Role::Initiator, &p), Ok(false));
    }

    #[test]
    fn verify_tampered_ids_fail() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let p = proof(PSK, &h, Role::Responder).unwrap();
        let h2 = hs("daemon", "another-bridge", NONCE_A);
        assert_eq!(verify(PSK, &h2, Role::Responder, &p), Ok(false));
        let h3 = hs("evil-daemon", "browser-bridge", NONCE_A);
        assert_eq!(verify(PSK, &h3, Role::Responder, &p), Ok(false));
    }

    #[test]
    fn verify_role_mislabel_fails() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let ip = proof(PSK, &h, Role::Initiator).unwrap();
        assert_eq!(verify(PSK, &h, Role::Responder, &ip), Ok(false));
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        assert_eq!(verify(PSK, &h, Role::Initiator, &rp), Ok(false));
    }

    #[test]
    fn verify_malformed_hex_refused() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        for bad in ["zz", "abc", "gggg", "0123-4567", "éé"] {
            assert_eq!(
                verify(PSK, &h, Role::Initiator, bad),
                Err(IpcAuthError::BadInput("proof")),
                "proof={bad}"
            );
        }
        // Valid hex of the wrong byte length is not *malformed*, it is simply
        // not this proof → Ok(false).
        assert_eq!(verify(PSK, &h, Role::Initiator, "abcd"), Ok(false));
    }

    #[test]
    fn verify_accepts_uppercase_hex_of_correct_bytes() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let p = proof(PSK, &h, Role::Initiator).unwrap();
        assert_eq!(verify(PSK, &h, Role::Initiator, &p.to_uppercase()), Ok(true));
    }

    // ---------- B7.1.2 · replay guard ----------

    #[test]
    fn seen_accept_and_len() {
        let mut seen = SeenNonces::new();
        assert_eq!(seen.len(), 0);
        assert!(seen.is_empty());
        assert!(seen.accept(NONCE_A));
        assert!(!seen.accept(NONCE_A)); // replay
        assert_eq!(seen.len(), 1);
        assert!(seen.accept(NONCE_B));
        assert_eq!(seen.len(), 2);
        assert!(!seen.is_empty());
    }

    #[test]
    fn replay_refused_after_successful_handshake() {
        let mut seen = SeenNonces::new();
        let s1 = handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        assert!(s1.id.starts_with("sess-"));
        assert_eq!(s1.id.len(), 17);
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let ip = proof(PSK, &h, Role::Initiator).unwrap();
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        assert_eq!(
            Session::establish(PSK, &h, &ip, &rp, 2_000, 500, &mut seen),
            Err(IpcAuthError::Replayed)
        );
        assert_eq!(seen.len(), 1); // refusal recorded nothing
    }

    #[test]
    fn failed_proof_does_not_burn_nonce() {
        let mut seen = SeenNonces::new();
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        let bogus = proof(b"wrong-psk", &h, Role::Initiator).unwrap();
        assert_eq!(
            Session::establish(PSK, &h, &bogus, &rp, 1_000, 500, &mut seen),
            Err(IpcAuthError::BadProof)
        );
        assert_eq!(seen.len(), 0);
        // Retry on the same nonce succeeds (id is transcript-derived).
        let s = handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        assert!(s.id.starts_with("sess-"));
        assert_eq!(s.id.len(), 17);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn failed_ttl_does_not_burn_nonce() {
        let mut seen = SeenNonces::new();
        assert_eq!(
            handshake(&mut seen, NONCE_A, 1_000, 0),
            Err(IpcAuthError::BadInput("ttl_ms"))
        );
        assert_eq!(seen.len(), 0);
        // Negative TTL refuses too, still without burning the nonce.
        assert_eq!(
            handshake(&mut seen, NONCE_A, 1_000, -5),
            Err(IpcAuthError::BadInput("ttl_ms"))
        );
        assert_eq!(seen.len(), 0);
        let s = handshake(&mut seen, NONCE_A, 1_000, 250).unwrap();
        assert!(s.id.starts_with("sess-"));
        assert_eq!(s.id.len(), 17);
    }

    // ---------- B7.1.3 · sessions ----------

    #[test]
    fn session_id_is_transcript_derived_and_shared() {
        let mut seen = SeenNonces::new();
        let s1 = handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        let s2 = handshake(&mut seen, NONCE_B, 1_100, 500).unwrap();
        // Same transcript + proofs ⇒ the same id on both sides (the property
        // the daemon relies on when it validates a presented session id).
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let ip = proof(PSK, &h, Role::Initiator).unwrap();
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        assert_eq!(s1.id, session_id(&h, &ip, &rp));
        // Different nonce ⇒ different id; the id is not a local counter.
        assert_ne!(s1.id, s2.id);
        assert!(s1.id.starts_with("sess-"));
        assert_eq!(s1.id.len(), 17);
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn session_fields_and_strict_expiry() {
        let mut seen = SeenNonces::new();
        let s = handshake(&mut seen, NONCE_A, 10_000, 1_500).unwrap();
        assert_eq!(s.initiator, "daemon");
        assert_eq!(s.responder, "browser-bridge");
        assert_eq!(s.established_ms, 10_000);
        assert_eq!(s.expires_ms, 11_500);
        assert!(s.valid(10_000));
        assert!(s.valid(11_499)); // one ms before expiry: valid
        assert!(!s.valid(11_500)); // expiry ms itself: NOT valid (strict <)
        assert!(!s.valid(11_501));
        // Strict comparison only — a clock stepping backwards keeps validity.
        assert!(s.valid(-1));
    }

    #[test]
    fn expiry_saturates_at_i64_max() {
        let mut seen = SeenNonces::new();
        let s = handshake(&mut seen, NONCE_A, i64::MAX - 10, 1_000).unwrap();
        assert_eq!(s.expires_ms, i64::MAX);
        assert!(s.valid(i64::MAX - 1));
        assert!(!s.valid(i64::MAX));
    }

    #[test]
    fn establish_order_replay_before_proofs() {
        let mut seen = SeenNonces::new();
        // Burn NONCE_A by a successful handshake.
        handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let bogus = proof(b"wrong-psk", &h, Role::Initiator).unwrap();
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        // Bad proofs on a replayed nonce: Replayed, not BadProof.
        assert_eq!(
            Session::establish(PSK, &h, &bogus, &rp, 2_000, 500, &mut seen),
            Err(IpcAuthError::Replayed)
        );
    }

    #[test]
    fn establish_order_fields_before_replay() {
        let mut seen = SeenNonces::new();
        handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let rp = proof(PSK, &h, Role::Responder).unwrap();
        // Field validation precedes the replay check: empty/malformed proof
        // fields refuse as BadInput("proof") even on a replayed nonce.
        assert_eq!(
            Session::establish(PSK, &h, "", &rp, 2_000, 500, &mut seen),
            Err(IpcAuthError::BadInput("proof"))
        );
        assert_eq!(
            Session::establish(PSK, &h, "not-hex", &rp, 2_000, 500, &mut seen),
            Err(IpcAuthError::BadInput("proof"))
        );
    }

    #[test]
    fn establish_field_validation() {
        let mut seen = SeenNonces::new();
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let ip = proof(PSK, &h, Role::Initiator).unwrap();
        let rp = proof(PSK, &h, Role::Responder).unwrap();

        assert_eq!(
            Session::establish(&[], &h, &ip, &rp, 0, 500, &mut seen),
            Err(IpcAuthError::BadInput("psk"))
        );

        let mut bad = h.clone();
        bad.initiator.clear();
        assert_eq!(
            Session::establish(PSK, &bad, &ip, &rp, 0, 500, &mut seen),
            Err(IpcAuthError::BadInput("initiator"))
        );
        let mut bad = h.clone();
        bad.responder.clear();
        assert_eq!(
            Session::establish(PSK, &bad, &ip, &rp, 0, 500, &mut seen),
            Err(IpcAuthError::BadInput("responder"))
        );
        let mut bad = h.clone();
        bad.nonce = "short".to_string();
        assert_eq!(
            Session::establish(PSK, &bad, &ip, &rp, 0, 500, &mut seen),
            Err(IpcAuthError::BadInput("nonce"))
        );

        assert_eq!(
            Session::establish(PSK, &h, &rp, &rp, 0, 500, &mut seen),
            Err(IpcAuthError::BadProof)
        );
        assert_eq!(
            Session::establish(PSK, &h, &ip, &ip, 0, 500, &mut seen),
            Err(IpcAuthError::BadProof)
        );
        assert_eq!(seen.len(), 0, "no attempt above recorded anything");
    }

    #[test]
    fn handshake_determinism() {
        let mut s1 = SeenNonces::new();
        let mut s2 = SeenNonces::new();
        let a = handshake(&mut s1, NONCE_A, 7_000, 900).unwrap();
        let b = handshake(&mut s2, NONCE_A, 7_000, 900).unwrap();
        assert_eq!(a, b);
        assert_eq!(s1.len(), s2.len());
    }

    // ---------- wire pins ----------

    #[test]
    fn serde_wire_pins() {
        assert_eq!(serde_json::to_string(&Role::Initiator).unwrap(), "\"Initiator\"");
        assert_eq!(serde_json::to_string(&Role::Responder).unwrap(), "\"Responder\"");

        let h = hs("daemon", "browser-bridge", NONCE_A);
        assert_eq!(
            serde_json::to_string(&h).unwrap(),
            format!(
                "{{\"protocol\":\"tallow-ipc-auth-v1\",\"initiator\":\"daemon\",\
                 \"responder\":\"browser-bridge\",\"nonce\":\"{NONCE_A}\"}}"
            )
        );

        let mut seen = SeenNonces::new();
        let s = handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            format!(
                "{{\"id\":\"{}\",\"initiator\":\"daemon\",\
                 \"responder\":\"browser-bridge\",\"established_ms\":1000,\
                 \"expires_ms\":1500}}",
                s.id
            )
        );

        assert_eq!(
            serde_json::to_string(&IpcAuthError::BadInput("psk")).unwrap(),
            "{\"BadInput\":\"psk\"}"
        );
        assert_eq!(serde_json::to_string(&IpcAuthError::BadProof).unwrap(), "\"BadProof\"");
        assert_eq!(serde_json::to_string(&IpcAuthError::Replayed).unwrap(), "\"Replayed\"");
    }

    #[test]
    fn serde_roundtrip() {
        let h = hs("daemon", "browser-bridge", NONCE_A);
        let back: Hello = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(back, h);

        let role: Role = serde_json::from_str("\"Responder\"").unwrap();
        assert_eq!(role, Role::Responder);

        let mut seen = SeenNonces::new();
        let s = handshake(&mut seen, NONCE_A, 1_000, 500).unwrap();
        let back: Session = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn display_texts_are_distinct_and_actionable() {
        let texts = [
            IpcAuthError::BadInput("psk").to_string(),
            IpcAuthError::BadProof.to_string(),
            IpcAuthError::Replayed.to_string(),
        ];
        assert!(texts[0].contains("psk"));
        assert_ne!(texts[0], texts[1]);
        assert_ne!(texts[1], texts[2]);
        for t in &texts {
            assert!(!t.is_empty());
        }
    }
}
