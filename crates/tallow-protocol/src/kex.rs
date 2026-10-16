//! Key exchange orchestration
//!
//! Combines hybrid KEM (ML-KEM-1024 + X25519), HKDF-SHA256,
//! and CPace PAKE to establish a session key between two peers.
//!
//! ## Protocol Flow (v2)
//!
//! 1. Sender -> Receiver: `HandshakeInit` (CPace public, KEM capabilities, nonce)
//! 2. Receiver -> Sender: `HandshakeResponse` (CPace public, KEM public key, nonce)
//! 3. Sender -> Receiver: `HandshakeKem` (KEM ciphertext, sender confirmation)
//! 4. Receiver -> Sender: `HandshakeComplete` (receiver confirmation)
//!
//! After step 4, both sides hold an identical 256-bit session key derived from
//! both the CPace PAKE output and the hybrid KEM shared secret.
//!
//! ## v5+ PQ authentication (implemented; rollout-gated)
//!
//! In a v5+ negotiation the receiver additionally ACKs `PQ_AUTH_FLAG` and both
//! sides exchange `HandshakeSigned` frames: hybrid identity signatures
//! (ML-DSA-87 + Ed25519, both must verify) over
//! `DOMAIN_HANDSHAKE_SIGNED || role || transcript_hash`. Signing and
//! verification are state-machine methods; the CLI/TUI/wasm drivers now
//! exchange and verify these frames before any transfer data (see
//! `crate::pq_handshake`), so `KEX_PROTOCOL_VERSION` is 5 and capable peers
//! gate the signed exchange on `PQ_AUTH_FLAG`. Rollout downgrade policy:
//! Alarm (peers that predate v5 proceed unsigned but loudly — see
//! `crate::pq_handshake::PqAuthAlarm`).

use crate::wire::capabilities::{capability_record, CapabilityLatch, CAPABILITY_BINDING_VERSION};
use crate::wire::Message;
use crate::{ProtocolError, Result};
use subtle::ConstantTimeEq;
use tallow_crypto::hash::domain;

/// Highest handshake protocol version this build implements.
///
/// Must track `wire::version::PROTOCOL_VERSION` (that module is feature-gated
/// behind `full`, so the constant is mirrored here — keep both in lockstep).
///
/// History: v6 = wire flow credits (A9); v7 = version+mode transcript binding
/// (security review 2026-09-23, crypto hack report Attack 1); v8 = the declared
/// suite code joins the binding (checklist 5.2).
pub const KEX_PROTOCOL_VERSION: u32 = 9;

/// Lowest protocol version whose canonical handshake binds `protocol_version`
/// into the transcript (security review 2026-09-23, crypto hack report
/// Attack 1). Both sides append the declared version + a mode byte right
/// after the initiator's nonce, so any wire rewrite of `protocol_version`
/// makes the session keys / key confirmations diverge and the handshake fails
/// loudly instead of silently downgrading to the legacy path.
pub const TRANSCRIPT_BINDING_VERSION: u32 = 7;

/// Lowest protocol version whose canonical handshake also binds the declared
/// **suite code** (checklist 5.2).
///
/// Where v7 made a rewrite of the version diverge, v8 covers the companion
/// question — *which construction* is being run. The initiator's declared code
/// is absorbed right after the version + mode, and a receiver refuses a code
/// outside [`tallow_crypto::is_known_suite_code`] instead of defaulting to a
/// suite the initiator did not declare. There is deliberately no fallback path:
/// an unknown suite is a refusal, never a negotiation.
pub const TRANSCRIPT_SUITE_BINDING_VERSION: u32 = 8;

/// Lowest `HandshakeInit.protocol_version` a receiver accepts (R1, security
/// review 2026-09-23, crypto hack report Attack 1).
///
/// v4 is the canonical CPace+KEM handshake. Anything below it would run the
/// unauthenticated legacy (dummy-PAKE) path, which is exactly what a wire
/// version-rewrite attack steers peers onto — so receivers refuse it and tell
/// both users to update. Kept here (not in the wasm bridge) so the gate is
/// host-testable; the wasm receiver returns the JsValue error.
///
/// Derived from `wire::version::MIN_PROTOCOL_VERSION` (2026-10-07, V2-U10):
/// `wire` is compiled unconditionally and `kex` is feature-gated, so `wire`
/// owns the number. Before this the two floors disagreed — the negotiator
/// advertised `[2, 7]` while this gate refused 2 and 3, so such a peer
/// negotiated successfully and then died mid-handshake.
pub const MIN_ACCEPTED_INIT_VERSION: u32 = crate::wire::MIN_PROTOCOL_VERSION;

/// Fail-closed version gate for incoming `HandshakeInit`s (R1).
pub fn is_init_version_accepted(protocol_version: u32) -> bool {
    protocol_version >= MIN_ACCEPTED_INIT_VERSION
}

/// Mode byte appended to the transcript under [`TRANSCRIPT_BINDING_VERSION`].
/// The handshake only runs for Full (end-to-end) mode; Simple/transport-only
/// has no handshake. Reserved for future mode-bound sessions.
pub const TRANSCRIPT_BINDING_MODE_FULL: u8 = 0x01;

/// High bit of `HandshakeResponse.selected_kem`.
///
/// Set by a v3 receiver when the initiator declared `protocol_version >= 3`.
/// When the sender reads it, both sides switch chunk crypto to the scoped
/// (per-transfer subkey) mode — see
/// `transfer::SendPipeline::set_scoped_transfer_keys`.
/// KEM discriminants are 0..=2 and v2 senders ignore `selected_kem`, so the
/// high bit is free to carry this signal.
pub const SCOPED_TRANSFER_FLAG: u8 = 0x80;

/// Bit 6 of `HandshakeResponse.selected_kem`.
///
/// Set by a v4 receiver to ACK that it completed the canonical CPace+KEM
/// handshake (this implementation). A v4 initiator that does NOT see this bit
/// knows the peer is a legacy implementation that only speaks the same message
/// *shape* (the browser's early JS handshake), and can fall back accordingly.
/// KEM discriminants are 0..=2, so bits 6/7 are free to carry these signals.
pub const CANONICAL_KEX_FLAG: u8 = 0x40;

/// Bit 5 of `HandshakeResponse.selected_kem`.
///
/// Set by a v5 receiver when the initiator declared `protocol_version >= 5`:
/// ACKs that both sides must exchange `HandshakeSigned` frames carrying
/// long-term hybrid identity signatures over the completed transcript.
/// KEM discriminants are 0..=2, so bits 5-7 are free to carry these signals.
pub const PQ_AUTH_FLAG: u8 = 0x20;

/// Bit 4 of `HandshakeResponse.selected_kem`.
///
/// Set by a receiver that understands the browser's per-chunk
/// `[flag][deflate-raw]` chunk dialect (the wasm receiver sets this).
/// Initiators that do NOT see this bit must send uncompressed chunk frames
/// (`compression = "none"`) — the CLI receiver cannot decode the JS dialect,
/// so JS senders fall back to plain chunks for CLI peers.
pub const DEFLATE_CHUNK_FLAG: u8 = 0x10;

/// Bit 3 of `HandshakeResponse.selected_kem`.
///
/// Set by a receiver that cannot decode zstd-compressed chunks (the browser
/// has no zstd decoder). Initiators must use `compression = "none"` chunk
/// frames when this bit is set — otherwise the receiver cannot decode the
/// transfer. The CLI receiver can decode zstd and leaves this clear.
pub const NO_ZSTD_CHUNK_FLAG: u8 = 0x08;

/// Bit 2 of `HandshakeResponse.selected_kem`.
///
/// Set by a v6 receiver when the initiator declared `protocol_version >= 6`:
/// ACKs that both sides may replace per-chunk `Ack`s with batched `Credit`
/// frames (wire v6 flow control, A9) — the receiver then owns the send window
/// (see `wire::messages::Message::Credit`). Initiators that do NOT see this bit
/// must keep today's per-chunk acks and fixed window. KEM discriminants are
/// 0..=2, so bits 2–7 are free to carry these signals.
///
/// Inert until the version constants bump: no shipped peer declares 6, so the
/// flag stays clear and the credit path never engages (the CLI is built from
/// this crate and must not declare 6 before it handles `Credit` frames).
pub const FLOW_CREDIT_FLAG: u8 = 0x04;

/// **NOT YET IMPLEMENTED — nothing sets this today, and the value below is a
/// fail-closed placeholder.** See the UNASSIGNED note at the constant.
///
/// Intended meaning once a carrier exists: set by a v9 receiver when the initiator
/// declared `protocol_version >= 9`, signalling the receiver can drive browser chat
/// on the **ratcheting** session (`RatchetSession::encryptChat`/`decryptChat`)
/// rather than the static-key `ChatSession`.
///
/// The initiator reads this echo and engages the ratcheting chat path **only**
/// when it is set. When it is clear, chat runs on the static-key path as it does
/// today — a **disclosed downgrade, never a silent one**: chat keeps working, and
/// nothing may claim post-quantum forward secrecy for it (`isPqActive()` stays
/// false, and the site's copy already states the browser chat limitation).
///
/// Deliberately NOT a refusal. An earlier draft of this flag required the
/// initiator to refuse ratchet chat when the echo was absent; that is wrong, and
/// the v6 precedent says so — `FLOW_CREDIT_FLAG`'s peer negotiation *"negotiate
/// down and stay on the legacy per-chunk-ack path"* for mixed sessions. Refusing
/// would break chat outright between a v9 and a v8 peer for no security gain,
/// because the downgrade is disclosed either way. The defect this flag guards
/// against is a downgrade that still *implies* PQ, not a downgrade as such.
///
/// The declared `protocol_version` **cannot** serve as this gate, which is the
/// whole reason a flag is needed: `MIN_ACCEPTED_INIT_VERSION` is 4, so an older
/// receiver accepts a v9 handshake without complaint and would happily run chat
/// on the old framing.
///
/// No new downgrade surface: `protocol_version` and the suite code are already
/// bound into the transcript (v7+/v8+), so a MITM that rewrites v9 down to
/// suppress this echo fails the handshake rather than forcing the AES path.
/// A peer that suppresses the echo can only cost itself PQ chat, and that is
/// disclosed by the status flag rather than hidden.
/// **UNASSIGNED — the value is a deliberate fail-closed placeholder, not a bit.**
///
/// `selected_kem` is a FULL carrier and cannot hold this flag:
///   - bits 0–1 carry the KEM discriminant (values 0..=2, so discriminant 2 already
///     sets bit 1 = `0x02` — the low bits were never free);
///   - bits 2–7 are taken by SCOPED_TRANSFER (`0x80`), CANONICAL_KEX (`0x40`),
///     PQ_AUTH (`0x20`), DEFLATE_CHUNK (`0x10`), NO_ZSTD_CHUNK (`0x08`) and
///     FLOW_CREDIT (`0x04`).
///
/// So the v9 chat capability needs a DIFFERENT carrier — an open decision, listed
/// here rather than guessed at.
///
/// This constant previously read `0x02` and that was a real defect, not a
/// placeholder: `0x02` is the discriminant's bit 1, so `selected_kem & 0x02` is set
/// for essentially every v4+ peer (canonical KEX selects discriminant 2). Anything
/// reading it would have engaged the ratchet against receivers that do not support
/// it while claiming post-quantum forward secrecy. A cross-version echo test that
/// asserted the ACK follows the DECLARED version is what caught it — the test failed
/// at `declared v4` with the bit already set.
///
/// `0x00` fails closed: OR-ing it is a no-op and reading it is always clear, so no
/// peer can be mistaken for a v9 chat peer and nothing may claim PQ forward secrecy
/// on this flag's strength. Replace it only together with the carrier decision.
pub const PQ_CHAT_FLAG: u8 = 0x00;

/// Role byte signed by the handshake initiator in `HandshakeSigned`.
pub const PQ_AUTH_ROLE_SENDER: u8 = 1;

/// Role byte signed by the handshake responder in `HandshakeSigned`.
pub const PQ_AUTH_ROLE_RECEIVER: u8 = 2;

/// Build the signed input for `HandshakeSigned`:
/// `DOMAIN_HANDSHAKE_SIGNED || role || transcript_hash`.
///
/// The role byte prevents reflecting a peer's own signed frame back at it.
fn pq_auth_signed_input(role: u8, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut data =
        Vec::with_capacity(domain::DOMAIN_HANDSHAKE_SIGNED.len() + 1 + transcript_hash.len());
    data.extend_from_slice(domain::DOMAIN_HANDSHAKE_SIGNED.as_bytes());
    data.push(role);
    data.extend_from_slice(transcript_hash);
    data
}

/// Shared verification path for a peer's `HandshakeSigned` frame.
///
/// All failure modes (role mismatch, decode failure, signature mismatch, pin
/// mismatch) collapse to one generic error — MUST NOT distinguish them.
fn verify_pq_auth_frame(
    pq_auth: bool,
    expected_role: u8,
    role: u8,
    identity_public_key: &[u8],
    signature: &[u8],
    transcript_hash: Option<&[u8; 32]>,
    expected_identity: Option<&[u8; 32]>,
) -> Result<[u8; 32]> {
    if !pq_auth {
        return Err(ProtocolError::InvalidStateTransition {
            from: "v4-or-lower (no PQ auth)".to_string(),
            to: "verify_signed_frame".to_string(),
        });
    }
    let transcript_hash = transcript_hash.ok_or_else(|| ProtocolError::InvalidStateTransition {
        from: "no transcript hash".to_string(),
        to: "verify_signed_frame".to_string(),
    })?;

    let generic = || ProtocolError::HandshakeFailed("handshake authentication failed".to_string());
    if role != expected_role {
        return Err(generic());
    }

    let pk: tallow_crypto::sig::HybridPublicKey =
        postcard::from_bytes(identity_public_key).map_err(|_e| generic())?;
    let signature: tallow_crypto::sig::HybridSignature =
        postcard::from_bytes(signature).map_err(|_e| generic())?;

    let signed_input = pq_auth_signed_input(expected_role, transcript_hash);
    tallow_crypto::sig::hybrid::verify(&pk, &signed_input, &signature).map_err(|_e| generic())?;

    let peer_id = tallow_crypto::keys::id_for_public_key(&pk)
        .map_err(|_e| ProtocolError::EncodingError("identity id derivation failed".to_string()))?;

    if let Some(expected) = expected_identity {
        if !bool::from(peer_id.ct_eq(expected)) {
            return Err(generic());
        }
    }

    Ok(peer_id)
}

/// Session key derived from key exchange
pub struct SessionKey {
    /// 32-byte key for AES-256-GCM encryption
    key: [u8; 32],
}

impl SessionKey {
    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Consume and return the raw key
    pub fn into_bytes(self) -> [u8; 32] {
        self.key
    }

    /// Create a session key from raw bytes
    ///
    /// # Security
    ///
    /// The caller is responsible for ensuring the bytes come from a
    /// cryptographically secure key derivation process.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

/// Derive a session key from a code phrase using HKDF
///
/// This is the simplest key exchange: both sides know the code phrase,
/// derive the same key. For v1, this provides the baseline.
///
/// # Arguments
///
/// * `code_phrase` - Shared code phrase
/// * `room_id` - BLAKE3 hash of the code phrase (domain separation)
#[cfg(test)]
pub fn derive_session_key_from_phrase(code_phrase: &str, room_id: &[u8; 32]) -> SessionKey {
    // Use BLAKE3 KDF with domain separation
    let mut input = Vec::with_capacity(code_phrase.len() + 32);
    input.extend_from_slice(code_phrase.as_bytes());
    input.extend_from_slice(room_id);

    let key = tallow_crypto::hash::blake3::derive_key("tallow-session-key-v1", &input);
    SessionKey { key }
}

/// Derive a unique session key using a per-transfer random salt
///
/// Unlike [`derive_session_key_from_phrase`], this includes the random
/// `transfer_id` in the derivation input, ensuring that reusing the same
/// code phrase produces a **different** session key each time. This
/// prevents catastrophic AES-GCM nonce reuse.
///
/// # Arguments
///
/// * `code_phrase` - Shared code phrase
/// * `room_id` - BLAKE3 hash of the code phrase (domain separation)
/// * `transfer_id` - Random 16-byte per-transfer salt (sent in FileOffer)
#[deprecated(
    since = "2.0.0",
    note = "Use SenderHandshake/ReceiverHandshake for KEM-based key exchange"
)]
pub fn derive_session_key_with_salt(
    code_phrase: &str,
    room_id: &[u8; 32],
    transfer_id: &[u8; 16],
) -> SessionKey {
    let mut input = Vec::with_capacity(code_phrase.len() + 32 + 16);
    input.extend_from_slice(code_phrase.as_bytes());
    input.extend_from_slice(room_id);
    input.extend_from_slice(transfer_id);

    let key = tallow_crypto::hash::blake3::derive_key("tallow-session-key-v2", &input);
    SessionKey { key }
}

/// Perform CPace-based key exchange
///
/// Both peers use the code phrase to derive a shared secret
/// via CPace (password-authenticated key exchange).
///
/// # Arguments
///
/// * `code_phrase` - Shared code phrase
/// * `session_id` - Unique session identifier (e.g., room_id + nonces)
///
/// # Returns
///
/// (public_message, CpaceState) -- send public_message to peer,
/// then call `complete_cpace` with their public_message.
#[cfg(test)]
pub(crate) fn start_cpace_initiator(code_phrase: &str, session_id: &[u8]) -> (Vec<u8>, CpaceState) {
    let initiator = tallow_crypto::pake::CpaceInitiator::new(code_phrase, session_id);
    let public_bytes = initiator.public_message();

    (public_bytes.to_vec(), CpaceState::Initiator(initiator))
}

/// Start CPace as responder
#[cfg(test)]
pub(crate) fn start_cpace_responder(code_phrase: &str, session_id: &[u8]) -> (Vec<u8>, CpaceState) {
    let responder = tallow_crypto::pake::CpaceResponder::new(code_phrase, session_id);
    let public_bytes = responder.public_message();

    (public_bytes.to_vec(), CpaceState::Responder(responder))
}

/// Complete CPace key exchange with the peer's public message
///
/// # Arguments
///
/// * `state` - The CPace state from start_cpace_*
/// * `their_public` - The peer's public message (32 bytes)
///
/// # Returns
///
/// The derived session key
#[cfg(test)]
pub(crate) fn complete_cpace(state: CpaceState, their_public: &[u8; 32]) -> Result<SessionKey> {
    let shared_secret = match state {
        CpaceState::Initiator(initiator) => initiator.finish(their_public).map_err(|e| {
            ProtocolError::TransferFailed(format!("CPace initiator finish failed: {}", e))
        })?,
        CpaceState::Responder(responder) => responder.finish(their_public).map_err(|e| {
            ProtocolError::TransferFailed(format!("CPace responder finish failed: {}", e))
        })?,
    };

    // Derive session key from CPace shared secret using BLAKE3 KDF
    let key = tallow_crypto::hash::blake3::derive_key("tallow-cpace-session-v1", &shared_secret);
    Ok(SessionKey { key })
}

/// CPace exchange state (opaque to callers)
pub(crate) enum CpaceState {
    /// Initiator state
    Initiator(tallow_crypto::pake::CpaceInitiator),
    /// Responder state (constructed in tests; matched in production error paths)
    #[allow(dead_code)]
    Responder(tallow_crypto::pake::CpaceResponder),
}

// ---------------------------------------------------------------------------
// Handshake Transcript
// ---------------------------------------------------------------------------

/// Append-only transcript of all handshake messages for key binding.
///
/// Both sides must append data in identical order.
struct HandshakeTranscript {
    buffer: Vec<u8>,
}

impl HandshakeTranscript {
    fn new() -> Self {
        let mut buffer = Vec::with_capacity(4096);
        // Start with domain separator
        buffer.extend_from_slice(domain::DOMAIN_HANDSHAKE_TRANSCRIPT.as_bytes());
        Self { buffer }
    }

    fn append(&mut self, data: &[u8]) {
        // Length-prefix each field to prevent ambiguity
        self.buffer
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(data);
    }

    fn hash(&self) -> [u8; 32] {
        tallow_crypto::hash::blake3::hash(&self.buffer)
    }
}

impl Drop for HandshakeTranscript {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buffer.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Key Confirmation Helpers
// ---------------------------------------------------------------------------

/// Compute a key confirmation tag using BLAKE3 keyed MAC.
///
/// `tag = BLAKE3_keyed(session_key, domain_label || transcript_hash)`
fn compute_confirmation(
    session_key: &[u8; 32],
    domain_label: &str,
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(domain_label.len() + 32);
    data.extend_from_slice(domain_label.as_bytes());
    data.extend_from_slice(transcript_hash);
    tallow_crypto::hash::blake3::keyed_hash(session_key, &data)
}

/// Derive a session key from KEM + PAKE secrets via HKDF-SHA256.
///
/// R6 (crypto report #5, 2026-09-23): the combiner explicitly binds the
/// transmitted hybrid KEM material — IKM = `kem_ss ‖ pake ‖ BLAKE3(kem_ct) ‖
/// x25519_eph_pub ‖ transcript_hash`. The transcript (which already carries
/// the ciphertext, declared version, and mode) still salts the HKDF; this
/// makes the binding explicit in the combine itself so no transcript-ordering
/// or collision gap can decouple the derived key from the KEM material.
fn derive_handshake_session_key(
    kem_shared_secret: &[u8; 32],
    pake_secret: &[u8; 32],
    kem_ciphertext: &[u8],
    x25519_eph_pub: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    use zeroize::Zeroize;

    // IKM = kem_ss || pake || BLAKE3(kem_ct) || x25519_pub || transcript_hash
    // (160 bytes; the transcript hash is bound both in IKM and as HKDF salt).
    let ct_binding = tallow_crypto::hash::blake3::hash(kem_ciphertext);
    let mut ikm = [0u8; 160];
    ikm[..32].copy_from_slice(kem_shared_secret);
    ikm[32..64].copy_from_slice(pake_secret);
    ikm[64..96].copy_from_slice(&ct_binding);
    ikm[96..128].copy_from_slice(x25519_eph_pub);
    ikm[128..160].copy_from_slice(transcript_hash);

    let derived = tallow_crypto::kdf::hkdf::derive(
        transcript_hash,
        &ikm,
        domain::DOMAIN_SESSION_KEY_KEM_PAKE.as_bytes(),
        32,
    )
    .map_err(|e| ProtocolError::HandshakeFailed(format!("HKDF derivation failed: {}", e)))?;

    ikm.zeroize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    Ok(key)
}

/// The capability bits a v9 responder advertises in `HandshakeResponseV9`.
///
/// **Single source of truth for the v9 chat gate.** Three things read it, and all three
/// must move together or the peers disagree about whether to ratchet:
///
///   1. the responder's emit (`process_init`) — what the initiator is TOLD;
///   2. `WasmReceiverHandshake::advertisedCapabilityBits()` — what the responder itself
///      reads back, so its own gate cannot drift from what it advertised;
///   3. the initiator's gate, via the bits it received.
///
/// **SET — this IS the swap, engaged 2026-10-14.** It was `0` while the ratcheting chat
/// session existed on the site but could not be constructed. It can now, and the ordering
/// constraint was honoured rather than assumed: a relay that carries `ChatTextV9`
/// (ordinal 78) was deployed FIRST, because on the single-room path the inner frame goes
/// out top-level and a relay built from mainline drops it silently.
///
/// Flipping it is ONE line by design, and that one line is the whole engagement: it opens
/// the gate here (the advertisement), at `advertisedCapabilityBits()` (what the responder
/// reads back about itself), and therefore on the site's responder path — plus the
/// initiator's gate via the bits it received. There is no second place for the value to
/// live and drift from this one.
///
/// Still guarded on the client side beyond this bit: a multi-peer broadcast room stays on
/// the static-key envelope, because the ratchet is pairwise and one frame cannot serve a
/// room. See docs/security/blackbox/09-V9-SWAP-PLAN.md.
pub const RESPONDER_CAPABILITY_BITS: u8 = crate::wire::messages::CAP_PQ_CHAT;

/// Derive the browser-chat **ratchet seed** from the same handshake secrets.
///
/// v9: browser chat moves onto a bidirectional `RatchetSession` instead of the two
/// unidirectional static-key `ChatSession`s. That session needs ONE shared secret,
/// and the existing per-direction subkeys cannot serve — they are direction-bound,
/// so the two peers do not hold the same value.
///
/// This is derived from the IDENTICAL IKM as the session key (see
/// [`derive_handshake_session_key`]) under a DIFFERENT domain label. Two properties
/// follow, and both are load-bearing:
///
///   1. **Identical on both peers.** The IKM is built from material both sides hold
///      (KEM secret, PAKE secret, the ciphertext, the ephemeral public key and the
///      transcript), so no new round trip and no new agreement is needed.
///   2. **Domain-separated from the session key.** Distinct labels mean the ratchet
///      seed is not recoverable from the session key or vice versa, so putting chat
///      on the ratchet cannot weaken the AEAD key that still protects everything
///      else on the connection.
///
/// Label choice is a NEW v1 (`tallow.chat.ratchet_seed.v1`), not a reuse of the
/// existing `DOMAIN_RATCHET*` labels: those domain-separate the ratchet's OWN send
/// and receive chains, one layer down. Using them here would collapse two distinct
/// separations into one.
///
/// Note this does NOT move any existing vector: the session-key derivation is
/// untouched, and a new label produces a new value without changing old ones.
pub fn derive_handshake_ratchet_seed(
    kem_shared_secret: &[u8; 32],
    pake_secret: &[u8; 32],
    kem_ciphertext: &[u8],
    x25519_eph_pub: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    use zeroize::Zeroize;

    // Deliberately the same IKM construction as the session key so both peers agree
    // without any additional exchange; only the label differs.
    let ct_binding = tallow_crypto::hash::blake3::hash(kem_ciphertext);
    let mut ikm = [0u8; 160];
    ikm[..32].copy_from_slice(kem_shared_secret);
    ikm[32..64].copy_from_slice(pake_secret);
    ikm[64..96].copy_from_slice(&ct_binding);
    ikm[96..128].copy_from_slice(x25519_eph_pub);
    ikm[128..160].copy_from_slice(transcript_hash);

    let derived = tallow_crypto::kdf::hkdf::derive(
        transcript_hash,
        &ikm,
        domain::DOMAIN_CHAT_RATCHET_SEED.as_bytes(),
        32,
    )
    .map_err(|e| ProtocolError::HandshakeFailed(format!("HKDF derivation failed: {}", e)))?;

    ikm.zeroize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&derived);
    Ok(seed)
}

// ---------------------------------------------------------------------------
// SenderHandshake
// ---------------------------------------------------------------------------

/// Handshake state machine for the sender (CPace initiator, KEM encapsulator).
///
/// All secret fields are zeroized on drop.
pub struct SenderHandshake {
    code_phrase: String,
    room_id: [u8; 32],
    nonce: [u8; 16],
    cpace_state: Option<CpaceState>,
    transcript: HandshakeTranscript,
    /// Cached session key for receiver confirmation verification
    session_key_bytes: Option<[u8; 32]>,
    /// v9: the shared browser-chat ratchet seed, derived during the handshake from
    /// the same IKM as the session key under a distinct domain label. `None` until
    /// `process_response`. Both peers compute the same value, which is what lets
    /// chat move onto a bidirectional ratchet with no extra round trip.
    ratchet_seed: Option<[u8; 32]>,
    /// Cached transcript hash for confirmation verification
    transcript_hash: Option<[u8; 32]>,
    /// Whether the receiver signalled scoped transfer keys (v3+)
    scoped_transfer_keys: bool,
    /// Whether the receiver ACKed PQ auth (v5+; `PQ_AUTH_FLAG`)
    pq_auth: bool,
    /// Whether the receiver understands the browser's `[flag][deflate]` chunk
    /// dialect (`DEFLATE_CHUNK_FLAG`; wasm receivers set it). When false the
    /// initiator must send plain, uncompressed chunk frames.
    peer_deflate_chunks: bool,
    /// Whether the receiver cannot decode zstd chunks (`NO_ZSTD_CHUNK_FLAG`;
    /// browsers set it). When true the initiator must use `compression = none`.
    peer_no_zstd_chunks: bool,
    /// Whether the receiver ACKed wire-v6 flow credits (`FLOW_CREDIT_FLAG`).
    /// When true the sender expects batched `Credit` frames and a
    /// receiver-owned window; when false (all shipped peers today) it keeps
    /// per-chunk `Ack`s and the legacy fixed window.
    peer_flow_credit: bool,
    /// Verified peer identity id, set by `verify_signed_frame`
    peer_identity: Option<[u8; 32]>,
    /// The protocol version THIS side declared in `HandshakeInit`.
    ///
    /// Needed by `process_response`: the capability record is bound into the
    /// transcript once the declared version reaches
    /// [`CAPABILITY_BINDING_VERSION`], and the gate must read the DECLARED
    /// version (what the responder saw) rather than the local constant, or the
    /// two sides could bind different transcripts.
    declared_version: u32,
    /// The peer's PQ capability byte, latched from the FIRST handshake response
    /// and fixed for the session ([`CapabilityLatch`]). A later statement that
    /// disagrees is refused rather than absorbed.
    peer_capabilities: CapabilityLatch,
}

impl SenderHandshake {
    /// Create a new sender handshake state machine.
    ///
    /// # Arguments
    ///
    /// * `code_phrase` - Shared code phrase for PAKE authentication
    /// * `room_id` - BLAKE3 hash of the code phrase
    pub fn new(code_phrase: &str, room_id: &[u8; 32]) -> Self {
        let nonce: [u8; 16] = rand::random();
        Self {
            code_phrase: code_phrase.to_string(),
            room_id: *room_id,
            nonce,
            cpace_state: None,
            transcript: HandshakeTranscript::new(),
            session_key_bytes: None,
            ratchet_seed: None,
            transcript_hash: None,
            scoped_transfer_keys: false,
            pq_auth: false,
            peer_deflate_chunks: false,
            peer_no_zstd_chunks: false,
            peer_flow_credit: false,
            peer_identity: None,
            declared_version: 0,
            peer_capabilities: CapabilityLatch::new(),
        }
    }

    /// Generate the HandshakeInit message (step 1).
    ///
    /// Initializes CPace as initiator and returns the init message to send.
    ///
    /// Declares [`KEX_PROTOCOL_VERSION`]; see [`Self::init_with_version`].
    pub fn init(&mut self) -> Result<Message> {
        self.init_with_version(KEX_PROTOCOL_VERSION)
    }

    /// Like [`Self::init`], but declares `protocol_version` in the
    /// `HandshakeInit` instead of [`KEX_PROTOCOL_VERSION`].
    ///
    /// Wire-v6 flow credits (A9 / tracker issue 09): a receiver ACKs
    /// `FLOW_CREDIT_FLAG` only when the initiator declared `>= 6`, and the
    /// credit path engages only on that ACK - so the web (wasm) initiator
    /// declares 6 when the rollout flag is on, while the CLI keeps calling
    /// [`Self::init`] (declares 5) until it speaks credits. Mixed sessions
    /// negotiate down and stay on the legacy per-chunk-ack path.
    pub fn init_with_version(&mut self, protocol_version: u32) -> Result<Message> {
        if self.cpace_state.is_some() {
            return Err(ProtocolError::InvalidStateTransition {
                from: "initialized".to_string(),
                to: "init".to_string(),
            });
        }

        // Build partial session_id = room_id || sender_nonce
        let mut session_id = Vec::with_capacity(48);
        session_id.extend_from_slice(&self.room_id);
        session_id.extend_from_slice(&self.nonce);

        // Create CPace initiator
        let initiator = tallow_crypto::pake::CpaceInitiator::new(&self.code_phrase, &session_id);
        let cpace_public = initiator.public_message();

        // Serialize KEM capabilities
        let kem_capabilities = postcard::to_stdvec(&tallow_crypto::kem::KemCapabilities::all())
            .map_err(|e| {
                ProtocolError::EncodingError(format!("KEM capabilities encoding: {}", e))
            })?;

        // Append to transcript (same order as receiver will)
        self.transcript.append(&cpace_public);
        self.transcript.append(&self.nonce);

        // Remember what we declared: `process_response` needs it to decide
        // whether the PQ capability record joins the transcript.
        self.declared_version = protocol_version;

        // v7+ (security review 2026-09-23, Attack 1): bind the declared
        // version + mode into the transcript so a wire rewrite diverges the
        // session keys/confirmations instead of silently downgrading.
        if protocol_version >= TRANSCRIPT_BINDING_VERSION {
            self.transcript.append(&protocol_version.to_le_bytes());
            self.transcript.append(&[TRANSCRIPT_BINDING_MODE_FULL]);
        }

        // v8+ (checklist 5.2): the declared suite code is bound beside them. The
        // sender declares the suite this build implements; the receiver checks
        // whatever was declared against the suites it knows, so a peer running a
        // different construction is refused rather than negotiated down.
        let suite_code = tallow_crypto::suite_code();
        if protocol_version >= TRANSCRIPT_SUITE_BINDING_VERSION {
            self.transcript.append(&[suite_code]);
        }

        self.cpace_state = Some(CpaceState::Initiator(initiator));

        Ok(Message::HandshakeInit {
            protocol_version,
            suite_code,
            kem_capabilities,
            cpace_public,
            nonce: self.nonce,
        })
    }

    /// Process the HandshakeResponse and generate HandshakeKem (steps 2-3).
    ///
    /// Completes CPace, encapsulates to the receiver's KEM public key,
    /// derives the session key, and computes the sender confirmation tag.
    ///
    /// **Capability-blind.** This entry point is not handed the peer's PQ
    /// capability byte, so it cannot bind it into the transcript. It is correct
    /// for every peer that declared a version below
    /// [`CAPABILITY_BINDING_VERSION`] — and it REFUSES one that declared at or
    /// above it, because there the transcript must carry the capability record
    /// and proceeding without it would silently derive unbound keys. Use
    /// [`Self::process_response_with_capabilities`] for those peers; the
    /// capability byte travels in `HandshakeResponseV9::capability_bits` and
    /// `Message::handshake_response_parts` already returns it beside the fields
    /// this call needs.
    ///
    /// # Arguments
    ///
    /// * `selected_kem` - KEM discriminant; high bit = receiver's scoped-transfer flag (v3+)
    /// * `cpace_public` - The receiver's CPace public message
    /// * `kem_public_key` - Serialized hybrid KEM public key
    /// * `nonce` - The receiver's random nonce
    pub fn process_response(
        &mut self,
        selected_kem: u8,
        cpace_public: &[u8; 32],
        kem_public_key: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(Message, SessionKey)> {
        self.process_response_inner(selected_kem, cpace_public, kem_public_key, nonce, None)
    }

    /// Like [`Self::process_response`], but WITH the peer's PQ capability byte.
    ///
    /// Phase 5 item 2: once the peer declared [`CAPABILITY_BINDING_VERSION`] or
    /// above, that byte joins the handshake transcript, so clearing or altering
    /// it in flight diverges the transcript hash and therefore the session key,
    /// the ratchet seed and both key confirmation tags — the handshake fails
    /// instead of downgrading silently. The value passed here must be the one
    /// that actually ARRIVED (`HandshakeResponseV9::capability_bits`, or `0` for
    /// the older shape that carries no capability byte at all), never a local
    /// constant: binding our own value would prove nothing about the peer.
    ///
    /// The value is also LATCHED ([`CapabilityLatch`]): the first response fixes
    /// the session's capability state, and a later statement that disagrees is
    /// refused.
    pub fn process_response_with_capabilities(
        &mut self,
        selected_kem: u8,
        cpace_public: &[u8; 32],
        kem_public_key: &[u8],
        nonce: &[u8; 16],
        capability_bits: u8,
    ) -> Result<(Message, SessionKey)> {
        self.process_response_inner(
            selected_kem,
            cpace_public,
            kem_public_key,
            nonce,
            Some(capability_bits),
        )
    }

    /// The peer's latched PQ capability bits, once a response has been processed.
    ///
    /// `Some(0)` means the peer disclosed "no PQ capabilities" (either it sent the
    /// older response shape, or it cleared the byte); `None` means no response has
    /// been processed, or it was processed through the capability-blind entry
    /// point, which is not handed the byte at all.
    pub fn peer_capability_bits(&self) -> Option<u8> {
        self.peer_capabilities.bits()
    }

    fn process_response_inner(
        &mut self,
        selected_kem: u8,
        cpace_public: &[u8; 32],
        kem_public_key: &[u8],
        nonce: &[u8; 16],
        capability_bits: Option<u8>,
    ) -> Result<(Message, SessionKey)> {
        // Take CPace state (consumes it -- can't call again)
        let cpace_state =
            self.cpace_state
                .take()
                .ok_or_else(|| ProtocolError::InvalidStateTransition {
                    from: "no cpace state".to_string(),
                    to: "process_response".to_string(),
                })?;

        // Complete CPace with responder's public message -> pake_secret
        let mut pake_secret = match cpace_state {
            CpaceState::Initiator(initiator) => initiator.finish(cpace_public).map_err(|_e| {
                // Generic error -- MUST NOT reveal whether PAKE or KEM caused failure
                ProtocolError::HandshakeFailed("handshake authentication failed".to_string())
            })?,
            CpaceState::Responder(_) => {
                return Err(ProtocolError::InvalidStateTransition {
                    from: "responder".to_string(),
                    to: "process_response (sender)".to_string(),
                });
            }
        };

        // Append receiver's data to transcript (same order as receiver)
        self.transcript.append(cpace_public);
        self.transcript.append(nonce);
        self.transcript.append(kem_public_key);

        // Phase 5 item 2 — bind the PQ capability record, in the SAME position the
        // responder wrote it (immediately after its serialized KEM public key,
        // before the KEM ciphertext). From `CAPABILITY_BINDING_VERSION` on, the
        // value must be the one that ARRIVED: clearing or altering the byte in
        // flight then diverges this transcript hash from the responder's, so the
        // session key, the ratchet seed and both confirmation tags diverge and the
        // handshake fails — a DISCLOSED downgrade (the older response shape, which
        // carries no byte) stays completable, a stripped one does not.
        if self.declared_version >= CAPABILITY_BINDING_VERSION {
            let bits = capability_bits.ok_or_else(|| {
                ProtocolError::InvalidMessage(format!(
                    "declared protocol_version {} binds the PQ capability record, but this \
                     process_response call was not given the peer's capability byte; use \
                     SenderHandshake::process_response_with_capabilities",
                    self.declared_version
                ))
            })?;
            self.transcript.append(&capability_record(bits));
        }

        // Latch the peer's capability on the FIRST message: the value is fixed for
        // the session, and a later statement that disagrees is refused rather than
        // absorbed. (Absent byte = a disclosed "no capabilities", never a refusal.)
        if let Some(bits) = capability_bits {
            self.peer_capabilities.observe_first(bits);
        }

        // Deserialize the receiver's KEM public key
        let pk: tallow_crypto::kem::hybrid::PublicKey = postcard::from_bytes(kem_public_key)
            .map_err(|e| {
                ProtocolError::HandshakeFailed(format!("handshake authentication failed: {}", e))
            })?;

        // Encapsulate to receiver's KEM public key
        let (ciphertext, kem_shared_secret) = tallow_crypto::kem::HybridKem::encapsulate(&pk)
            .map_err(|_e| {
                ProtocolError::HandshakeFailed("handshake authentication failed".to_string())
            })?;

        // Serialize ciphertext
        let kem_ciphertext = postcard::to_stdvec(&ciphertext)
            .map_err(|e| ProtocolError::EncodingError(format!("KEM ciphertext encoding: {}", e)))?;

        // Append ciphertext to transcript
        self.transcript.append(&kem_ciphertext);

        // Compute transcript hash
        let transcript_hash = self.transcript.hash();

        // R6: bind the transmitted KEM material into the combiner (the X25519
        // ephemeral public rides inside the hybrid ciphertext we just sent).
        let x25519_eph_pub = *ciphertext.x25519_public.as_bytes();

        // Derive session key from KEM + PAKE
        let session_key_bytes = derive_handshake_session_key(
            kem_shared_secret.expose_secret(),
            &pake_secret,
            &kem_ciphertext,
            &x25519_eph_pub,
            &transcript_hash,
        )?;

        // v9: the shared chat ratchet seed, from the SAME IKM under a distinct
        // domain label — so both peers compute it with no extra round trip, and it
        // cannot be derived from the session key (or vice versa).
        //
        // Derived HERE — immediately after the session key — and deliberately NOT
        // further down: this function zeroizes `pake_secret` a few lines below, so a
        // seed derived after that point would be computed from an all-zero PAKE
        // secret ON THIS SIDE ONLY. The two peers would then hold silently different
        // seeds while every key-confirmation and session-key assertion still passed.
        // That is exactly what happened first time; the both-peers test caught it.
        self.ratchet_seed = Some(derive_handshake_ratchet_seed(
            kem_shared_secret.expose_secret(),
            &pake_secret,
            &kem_ciphertext,
            &x25519_eph_pub,
            &transcript_hash,
        )?);

        // Compute sender confirmation tag
        let confirmation = compute_confirmation(
            &session_key_bytes,
            domain::DOMAIN_KEY_CONFIRM_SENDER,
            &transcript_hash,
        );

        // Zeroize intermediate secrets
        use zeroize::Zeroize;
        pake_secret.zeroize();

        // Record the receiver's scoped-transfer signal (v3 peers set the
        // high bit of selected_kem; legacy peers leave it clear).
        self.scoped_transfer_keys = selected_kem & SCOPED_TRANSFER_FLAG != 0;
        // Record the receiver's PQ-auth ACK (v5 peers set bit 5; earlier
        // peers leave it clear).
        self.pq_auth = selected_kem & PQ_AUTH_FLAG != 0;
        // Record the receiver's chunk-format capabilities (wasm receivers
        // advertise bits 3/4; the CLI and legacy peers leave them clear).
        self.peer_deflate_chunks = selected_kem & DEFLATE_CHUNK_FLAG != 0;
        self.peer_no_zstd_chunks = selected_kem & NO_ZSTD_CHUNK_FLAG != 0;
        // Record the receiver's flow-credit ACK (v6 peers set bit 2; earlier
        // peers leave it clear, and the flag is inert until the version
        // constants bump).
        self.peer_flow_credit = selected_kem & FLOW_CREDIT_FLAG != 0;

        // Cache for receiver confirmation verification
        self.session_key_bytes = Some(session_key_bytes);
        self.transcript_hash = Some(transcript_hash);

        Ok((
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            },
            SessionKey::from_bytes(session_key_bytes),
        ))
    }

    /// Verify the receiver's key confirmation tag (step 4).
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_receiver_confirmation(&self, their_confirmation: &[u8; 32]) -> Result<()> {
        let session_key_bytes = self.session_key_bytes.as_ref().ok_or_else(|| {
            ProtocolError::InvalidStateTransition {
                from: "no session key".to_string(),
                to: "verify_receiver_confirmation".to_string(),
            }
        })?;

        let transcript_hash =
            self.transcript_hash
                .as_ref()
                .ok_or_else(|| ProtocolError::InvalidStateTransition {
                    from: "no transcript hash".to_string(),
                    to: "verify_receiver_confirmation".to_string(),
                })?;

        let expected = compute_confirmation(
            session_key_bytes,
            domain::DOMAIN_KEY_CONFIRM_RECEIVER,
            transcript_hash,
        );

        if their_confirmation.ct_eq(&expected).into() {
            Ok(())
        } else {
            Err(ProtocolError::KeyConfirmationFailed)
        }
    }

    /// Whether the peer ACKed PQ authentication (`PQ_AUTH_FLAG`; v5+).
    pub fn pq_auth(&self) -> bool {
        self.pq_auth
    }

    /// Whether the peer ACKed wire-v6 flow credits (`FLOW_CREDIT_FLAG`; v6+).
    ///
    /// False against every shipped peer today (nobody declares protocol
    /// version 6 yet), which is exactly the fallback: per-chunk `Ack`s and the
    /// legacy fixed window.
    pub fn flow_credit(&self) -> bool {
        self.peer_flow_credit
    }

    /// The shared browser-chat ratchet seed (v9).
    ///
    /// `None` before [`Self::process_response`]. Both peers derive the SAME value
    /// from material they already hold, which is what lets chat move onto a
    /// bidirectional `RatchetSession` with no additional round trip. It is
    /// domain-separated from the session key, so using it for chat cannot weaken the
    /// AEAD key that protects everything else on the connection.
    pub fn ratchet_seed(&self) -> Option<&[u8; 32]> {
        self.ratchet_seed.as_ref()
    }

    /// Whether the peer's `HandshakeSigned` frame has been verified.
    pub fn pq_verified(&self) -> bool {
        self.peer_identity.is_some()
    }

    /// The verified peer identity id (BLAKE3 of the peer's hybrid public key;
    /// see `tallow_crypto::keys::id_for_public_key`).
    pub fn peer_identity(&self) -> Option<[u8; 32]> {
        self.peer_identity
    }

    /// Create this side's `HandshakeSigned` frame (v5+).
    ///
    /// Signs `DOMAIN_HANDSHAKE_SIGNED || role || transcript_hash` with the
    /// local hybrid identity signer. Requires a v5 negotiation and a
    /// completed transcript (after [`Self::process_response`]).
    pub fn create_signed_frame(
        &self,
        signer: &tallow_crypto::sig::HybridSigner,
    ) -> Result<Message> {
        if !self.pq_auth {
            return Err(ProtocolError::InvalidStateTransition {
                from: "v4-or-lower (no PQ auth)".to_string(),
                to: "create_signed_frame".to_string(),
            });
        }
        let transcript_hash =
            self.transcript_hash
                .as_ref()
                .ok_or_else(|| ProtocolError::InvalidStateTransition {
                    from: "no transcript hash".to_string(),
                    to: "create_signed_frame".to_string(),
                })?;

        let signed_input = pq_auth_signed_input(PQ_AUTH_ROLE_SENDER, transcript_hash);
        let signature = signer.sign(&signed_input).map_err(|_e| {
            ProtocolError::HandshakeFailed("handshake signature failed".to_string())
        })?;
        let identity_public_key = postcard::to_stdvec(&signer.public_key())
            .map_err(|e| ProtocolError::EncodingError(format!("identity key encoding: {}", e)))?;
        let signature_bytes = postcard::to_stdvec(&signature)
            .map_err(|e| ProtocolError::EncodingError(format!("signature encoding: {}", e)))?;

        Ok(Message::HandshakeSigned {
            role: PQ_AUTH_ROLE_SENDER,
            identity_public_key,
            signature: signature_bytes,
        })
    }

    /// Verify the peer's `HandshakeSigned` frame (expects the responder role).
    ///
    /// `expected_identity` pins the peer (`None` = first-contact/TOFU: accept
    /// and record whatever identity was presented). On success caches the
    /// verified peer id.
    pub fn verify_signed_frame(
        &mut self,
        msg: &Message,
        expected_identity: Option<&[u8; 32]>,
    ) -> Result<[u8; 32]> {
        let (role, identity_public_key, signature) = match msg {
            Message::HandshakeSigned {
                role,
                identity_public_key,
                signature,
            } => (*role, identity_public_key, signature),
            _ => {
                return Err(ProtocolError::InvalidMessage(
                    "verify_signed_frame: expected HandshakeSigned".to_string(),
                ))
            }
        };
        let peer_id = verify_pq_auth_frame(
            self.pq_auth,
            PQ_AUTH_ROLE_RECEIVER,
            role,
            identity_public_key,
            signature,
            self.transcript_hash.as_ref(),
            expected_identity,
        )?;
        self.peer_identity = Some(peer_id);
        Ok(peer_id)
    }

    /// Whether the negotiated session enables scoped (per-transfer subkey)
    /// chunk crypto.
    ///
    /// `true` only when the receiver signalled `SCOPED_TRANSFER_FLAG` in its
    /// `HandshakeResponse` (v3+ peers). Legacy peers → `false`: chunk crypto
    /// keeps the legacy raw-session-key semantics.
    pub fn scoped_transfer_keys(&self) -> bool {
        self.scoped_transfer_keys
    }

    /// Whether the receiver understands the browser's `[flag][deflate]` chunk
    /// dialect (`DEFLATE_CHUNK_FLAG`). When false the peer cannot decode that
    /// dialect and the initiator must send plain chunk frames.
    pub fn peer_supports_deflate_chunks(&self) -> bool {
        self.peer_deflate_chunks
    }

    /// Whether the receiver cannot decode zstd chunk frames
    /// (`NO_ZSTD_CHUNK_FLAG`; browsers set it). When true the initiator must
    /// send plain (`compression = none`) chunks.
    pub fn peer_needs_plain_chunks(&self) -> bool {
        self.peer_no_zstd_chunks
    }
}

impl Drop for SenderHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroize secret material
        self.code_phrase.zeroize();
        self.nonce.zeroize();
        if let Some(ref mut key) = self.session_key_bytes {
            key.zeroize();
        }
        if let Some(ref mut hash) = self.transcript_hash {
            hash.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// ReceiverHandshake
// ---------------------------------------------------------------------------

/// Handshake state machine for the receiver (CPace responder, KEM decapsulator).
///
/// All secret fields are zeroized on drop.
pub struct ReceiverHandshake {
    code_phrase: String,
    room_id: [u8; 32],
    nonce: [u8; 16],
    kem_secret_key: Option<tallow_crypto::kem::hybrid::SecretKey>,
    pake_secret: Option<[u8; 32]>,
    transcript: HandshakeTranscript,
    /// Cached transcript hash for v5+ PQ-auth frame signing/verification
    transcript_hash: Option<[u8; 32]>,
    /// Whether the initiator declared v3+ (scoped transfer keys)
    scoped_transfer_keys: bool,
    /// Whether PQ auth was negotiated (v5+; initiator declared >= 5)
    pq_auth: bool,
    /// Extra capability bits ORed into every `HandshakeResponse::selected_kem`
    /// this receiver emits (0 for the CLI; the browser sets its chunk-dialect
    /// bits — see `DEFLATE_CHUNK_FLAG` / `NO_ZSTD_CHUNK_FLAG`).
    response_caps: u8,
    /// v9: the shared browser-chat ratchet seed, derived during `process_kem`
    /// from the same IKM as the session key under a distinct domain label. `None`
    /// until then. Both peers compute the SAME value, which is what lets chat
    /// move onto a bidirectional ratchet with no extra round trip.
    ratchet_seed: Option<[u8; 32]>,
    /// Verified peer identity id, set by `verify_signed_frame`
    peer_identity: Option<[u8; 32]>,
}

impl ReceiverHandshake {
    /// Create a new receiver handshake state machine.
    ///
    /// # Arguments
    ///
    /// * `code_phrase` - Shared code phrase for PAKE authentication
    /// * `room_id` - BLAKE3 hash of the code phrase
    pub fn new(code_phrase: &str, room_id: &[u8; 32]) -> Self {
        let nonce: [u8; 16] = rand::random();
        Self {
            code_phrase: code_phrase.to_string(),
            room_id: *room_id,
            nonce,
            kem_secret_key: None,
            pake_secret: None,
            transcript: HandshakeTranscript::new(),
            transcript_hash: None,
            scoped_transfer_keys: false,
            pq_auth: false,
            response_caps: 0,
            ratchet_seed: None,
            peer_identity: None,
        }
    }

    /// Same as [`Self::new`] but with extra capability bits ORed into every
    /// `HandshakeResponse::selected_kem` this receiver emits.
    ///
    /// Used by the browser (`WasmReceiverHandshake`) to advertise its chunk
    /// codecs so senders can pick a chunk format both sides can decode.
    pub fn new_with_response_caps(
        code_phrase: &str,
        room_id: &[u8; 32],
        response_caps: u8,
    ) -> Self {
        let mut hs = Self::new(code_phrase, room_id);
        hs.response_caps = response_caps & (DEFLATE_CHUNK_FLAG | NO_ZSTD_CHUNK_FLAG);
        hs
    }

    /// Process the HandshakeInit and generate HandshakeResponse (steps 1-2).
    ///
    /// Validates the protocol version, completes CPace as responder,
    /// generates an ephemeral KEM keypair, and returns the response message.
    ///
    /// # Arguments
    ///
    /// * `protocol_version` - The handshake protocol version (must be >= 2)
    /// * `suite_code` - The suite code the initiator declared (v8+; an unknown
    ///   code is refused, never defaulted)
    /// * `kem_capabilities` - Serialized KEM capabilities from sender
    /// * `cpace_public` - The sender's CPace public message
    /// * `sender_nonce` - The sender's random nonce
    pub fn process_init(
        &mut self,
        protocol_version: u32,
        suite_code: u8,
        kem_capabilities: &[u8],
        cpace_public: &[u8; 32],
        sender_nonce: &[u8; 16],
    ) -> Result<Message> {
        if protocol_version < 2 {
            return Err(ProtocolError::VersionMismatch {
                local: 2,
                remote: protocol_version,
            });
        }

        // v8+ (checklist 5.2): the initiator declared which suite it is running.
        // An unknown code is refused outright — never defaulted onto ours —
        // because two sides running different constructions would derive
        // different keys and only discover it later, as a confusing failure
        // rather than an explicit refusal. Checked before anything is absorbed
        // into the transcript, so a refused handshake leaves no state behind.
        if protocol_version >= TRANSCRIPT_SUITE_BINDING_VERSION
            && !tallow_crypto::is_known_suite_code(suite_code)
        {
            return Err(ProtocolError::HandshakeFailed(format!(
                "unsupported suite code 0x{suite_code:02x}: this build implements {} only",
                tallow_crypto::SUITE_ID
            )));
        }

        // v3+: the initiator claims scoped-transfer-key support. The receiver
        // opts in by echoing the high bit in `selected_kem`; v2 initiators
        // never see or send the flag, so legacy behavior is preserved.
        self.scoped_transfer_keys = protocol_version >= 3;

        // v5+: the initiator expects PQ-auth signing; ACK with the flag so
        // both sides exchange `HandshakeSigned` frames.
        self.pq_auth = protocol_version >= 5;

        // Build session_id matching what initiator used: room_id || sender_nonce
        let mut session_id = Vec::with_capacity(48);
        session_id.extend_from_slice(&self.room_id);
        session_id.extend_from_slice(sender_nonce);

        // Create CPace responder and complete immediately
        let responder = tallow_crypto::pake::CpaceResponder::new(&self.code_phrase, &session_id);
        let resp_cpace_public = responder.public_message();
        let pake_secret = responder.finish(cpace_public).map_err(|_e| {
            ProtocolError::HandshakeFailed("handshake authentication failed".to_string())
        })?;
        self.pake_secret = Some(pake_secret);

        // Append to transcript (same order as sender)
        self.transcript.append(cpace_public);
        self.transcript.append(sender_nonce);

        // v7+ (security review 2026-09-23, Attack 1): mirror the sender's
        // version+mode binding — a rewritten version diverges the keys.
        if protocol_version >= TRANSCRIPT_BINDING_VERSION {
            self.transcript.append(&protocol_version.to_le_bytes());
            self.transcript.append(&[TRANSCRIPT_BINDING_MODE_FULL]);
        }

        // v8+ (checklist 5.2): bind the declared suite code in the same position
        // the initiator wrote it — right after the version + mode — so a rewrite
        // of the declared code diverges the keys exactly the way a version
        // rewrite does. The value bound here is the one that arrived on the wire
        // (validated above), not the local constant: binding our own would prove
        // nothing about the peer.
        if protocol_version >= TRANSCRIPT_SUITE_BINDING_VERSION {
            self.transcript.append(&[suite_code]);
        }

        self.transcript.append(&resp_cpace_public);
        self.transcript.append(&self.nonce);

        // Negotiate KEM algorithm
        let their_caps: tallow_crypto::kem::KemCapabilities =
            postcard::from_bytes(kem_capabilities).map_err(|e| {
                ProtocolError::HandshakeFailed(format!("KEM capabilities decode failed: {}", e))
            })?;
        let ours = tallow_crypto::kem::KemCapabilities::all();
        let selected = tallow_crypto::kem::negotiate(&ours, &their_caps).ok_or_else(|| {
            ProtocolError::HandshakeFailed("no compatible KEM algorithm".to_string())
        })?;
        let selected_kem = selected as u8;

        // Generate ephemeral KEM keypair
        let (pk, sk) = tallow_crypto::kem::HybridKem::keygen().map_err(|_e| {
            ProtocolError::HandshakeFailed("KEM key generation failed".to_string())
        })?;
        self.kem_secret_key = Some(sk);

        // Serialize public key
        let kem_public_key = postcard::to_stdvec(&pk)
            .map_err(|e| ProtocolError::EncodingError(format!("KEM public key encoding: {}", e)))?;

        // Append serialized pk to transcript
        self.transcript.append(&kem_public_key);

        // Phase 5 item 2 — the PQ capability record joins the transcript here, on
        // the responder side, in the position the initiator mirrors: right after
        // this responder's serialized KEM public key and before the KEM
        // ciphertext. From `CAPABILITY_BINDING_VERSION` on, the value bound is the
        // one this responder is about to ADVERTISE, so a middleman that clears or
        // alters it in flight makes the two transcript hashes disagree and the
        // handshake fails instead of downgrading silently. Gated on the DECLARED
        // version (the same value the initiator gated on), so a pre-binding peer
        // keeps the transcript it already speaks, byte for byte.
        if protocol_version >= CAPABILITY_BINDING_VERSION {
            self.transcript
                .append(&capability_record(RESPONDER_CAPABILITY_BITS));
        }

        // A peer that declared >= 9 gets the v9 response shape, which carries a
        // whole capability byte. The `selected_kem` flag budget is fully spoken for
        // (bits 0-1 = KEM discriminant, bits 2-7 = six flags), so a new capability
        // has nowhere to go in that byte — see doc 08.
        let selected_kem = selected_kem
            | if self.scoped_transfer_keys {
                SCOPED_TRANSFER_FLAG
            } else {
                0
            }
            | if protocol_version >= 4 {
                CANONICAL_KEX_FLAG
            } else {
                0
            }
            | if self.pq_auth { PQ_AUTH_FLAG } else { 0 }
            | if protocol_version >= 6 {
                FLOW_CREDIT_FLAG
            } else {
                0
            }
            | self.response_caps;

        if protocol_version >= 9 {
            Ok(Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public: resp_cpace_public,
                kem_public_key,
                nonce: self.nonce,
                // Single-sourced from `RESPONDER_CAPABILITY_BITS`, which the responder
                // itself reads back via `advertisedCapabilityBits()`. Flipping that ONE
                // constant opens the gate here and on the site together — see its doc.
                capability_bits: RESPONDER_CAPABILITY_BITS,
            })
        } else {
            Ok(Message::HandshakeResponse {
                selected_kem,
                cpace_public: resp_cpace_public,
                kem_public_key,
                nonce: self.nonce,
            })
        }
    }

    /// Process the HandshakeKem and generate HandshakeComplete (step 3-4).
    ///
    /// Decapsulates the KEM ciphertext, derives the session key,
    /// verifies the sender's confirmation tag, and returns the
    /// receiver confirmation and session key.
    ///
    /// # Arguments
    ///
    /// * `kem_ciphertext` - Serialized KEM ciphertext from sender
    /// * `sender_confirmation` - Sender's key confirmation tag
    pub fn process_kem(
        &mut self,
        kem_ciphertext: &[u8],
        sender_confirmation: &[u8; 32],
    ) -> Result<(Message, SessionKey)> {
        // Take KEM secret key (consumes it)
        let sk =
            self.kem_secret_key
                .take()
                .ok_or_else(|| ProtocolError::InvalidStateTransition {
                    from: "no KEM secret key".to_string(),
                    to: "process_kem".to_string(),
                })?;

        // Deserialize ciphertext
        let ct: tallow_crypto::kem::hybrid::Ciphertext = postcard::from_bytes(kem_ciphertext)
            .map_err(|e| {
                ProtocolError::HandshakeFailed(format!("handshake authentication failed: {}", e))
            })?;

        // Decapsulate
        let kem_shared_secret =
            tallow_crypto::kem::HybridKem::decapsulate(&sk, &ct).map_err(|_e| {
                ProtocolError::HandshakeFailed("handshake authentication failed".to_string())
            })?;

        // Append ciphertext to transcript (raw bytes, same as sender serialized them)
        self.transcript.append(kem_ciphertext);

        // Compute transcript hash
        let transcript_hash = self.transcript.hash();
        // Cache for v5+ PQ-auth frame signing/verification.
        self.transcript_hash = Some(transcript_hash);

        // Take PAKE secret
        let mut pake_secret =
            self.pake_secret
                .take()
                .ok_or_else(|| ProtocolError::InvalidStateTransition {
                    from: "no PAKE secret".to_string(),
                    to: "process_kem".to_string(),
                })?;

        // R6: bind the transmitted KEM material into the combiner (the X25519
        // ephemeral public rides inside the received hybrid ciphertext).
        let x25519_eph_pub = *ct.x25519_public.as_bytes();

        // Derive session key
        let session_key_bytes = derive_handshake_session_key(
            kem_shared_secret.expose_secret(),
            &pake_secret,
            kem_ciphertext,
            &x25519_eph_pub,
            &transcript_hash,
        )?;

        // v9: the same shared chat ratchet seed the initiator computes — same
        // IKM, same distinct label — so both peers agree on it with no
        // additional exchange. Stored so the caller can reach it via
        // `ratchet_seed()`; the session swap is what will consume it.
        self.ratchet_seed = Some(derive_handshake_ratchet_seed(
            kem_shared_secret.expose_secret(),
            &pake_secret,
            kem_ciphertext,
            &x25519_eph_pub,
            &transcript_hash,
        )?);

        // Verify sender's confirmation tag (constant-time)
        let expected_sender_confirmation = compute_confirmation(
            &session_key_bytes,
            domain::DOMAIN_KEY_CONFIRM_SENDER,
            &transcript_hash,
        );

        if !bool::from(sender_confirmation.ct_eq(&expected_sender_confirmation)) {
            return Err(ProtocolError::KeyConfirmationFailed);
        }

        // Compute receiver confirmation tag
        let receiver_confirmation = compute_confirmation(
            &session_key_bytes,
            domain::DOMAIN_KEY_CONFIRM_RECEIVER,
            &transcript_hash,
        );

        // Zeroize intermediate secrets
        use zeroize::Zeroize;
        pake_secret.zeroize();

        Ok((
            Message::HandshakeComplete {
                confirmation: receiver_confirmation,
            },
            SessionKey::from_bytes(session_key_bytes),
        ))
    }

    /// Whether PQ authentication was negotiated (`PQ_AUTH_FLAG`; v5+).
    pub fn pq_auth(&self) -> bool {
        self.pq_auth
    }

    /// The shared browser-chat ratchet seed (v9).
    ///
    /// `None` before [`Self::process_kem`]. Both peers derive the SAME value from
    /// material they already hold, so chat can move onto a bidirectional
    /// `RatchetSession` with no additional round trip, and the seed is
    /// domain-separated from the session key.
    pub fn ratchet_seed(&self) -> Option<&[u8; 32]> {
        self.ratchet_seed.as_ref()
    }

    /// Whether the peer's `HandshakeSigned` frame has been verified.
    pub fn pq_verified(&self) -> bool {
        self.peer_identity.is_some()
    }

    /// The verified peer identity id (BLAKE3 of the peer's hybrid public key;
    /// see `tallow_crypto::keys::id_for_public_key`).
    pub fn peer_identity(&self) -> Option<[u8; 32]> {
        self.peer_identity
    }

    /// Create this side's `HandshakeSigned` frame (v5+).
    ///
    /// Signs `DOMAIN_HANDSHAKE_SIGNED || role || transcript_hash` with the
    /// local hybrid identity signer. Requires a v5 negotiation and a
    /// completed transcript (after [`Self::process_kem`]).
    pub fn create_signed_frame(
        &self,
        signer: &tallow_crypto::sig::HybridSigner,
    ) -> Result<Message> {
        if !self.pq_auth {
            return Err(ProtocolError::InvalidStateTransition {
                from: "v4-or-lower (no PQ auth)".to_string(),
                to: "create_signed_frame".to_string(),
            });
        }
        let transcript_hash =
            self.transcript_hash
                .as_ref()
                .ok_or_else(|| ProtocolError::InvalidStateTransition {
                    from: "no transcript hash".to_string(),
                    to: "create_signed_frame".to_string(),
                })?;

        let signed_input = pq_auth_signed_input(PQ_AUTH_ROLE_RECEIVER, transcript_hash);
        let signature = signer.sign(&signed_input).map_err(|_e| {
            ProtocolError::HandshakeFailed("handshake signature failed".to_string())
        })?;
        let identity_public_key = postcard::to_stdvec(&signer.public_key())
            .map_err(|e| ProtocolError::EncodingError(format!("identity key encoding: {}", e)))?;
        let signature_bytes = postcard::to_stdvec(&signature)
            .map_err(|e| ProtocolError::EncodingError(format!("signature encoding: {}", e)))?;

        Ok(Message::HandshakeSigned {
            role: PQ_AUTH_ROLE_RECEIVER,
            identity_public_key,
            signature: signature_bytes,
        })
    }

    /// Verify the peer's `HandshakeSigned` frame (expects the initiator role).
    ///
    /// `expected_identity` pins the peer (`None` = first-contact/TOFU: accept
    /// and record whatever identity was presented). On success caches the
    /// verified peer id.
    pub fn verify_signed_frame(
        &mut self,
        msg: &Message,
        expected_identity: Option<&[u8; 32]>,
    ) -> Result<[u8; 32]> {
        let (role, identity_public_key, signature) = match msg {
            Message::HandshakeSigned {
                role,
                identity_public_key,
                signature,
            } => (*role, identity_public_key, signature),
            _ => {
                return Err(ProtocolError::InvalidMessage(
                    "verify_signed_frame: expected HandshakeSigned".to_string(),
                ))
            }
        };
        let peer_id = verify_pq_auth_frame(
            self.pq_auth,
            PQ_AUTH_ROLE_SENDER,
            role,
            identity_public_key,
            signature,
            self.transcript_hash.as_ref(),
            expected_identity,
        )?;
        self.peer_identity = Some(peer_id);
        Ok(peer_id)
    }

    /// Whether the negotiated session enables scoped (per-transfer subkey)
    /// chunk crypto.
    ///
    /// `true` only when the initiator declared `protocol_version >= 3`; the
    /// same value was echoed to the initiator via `SCOPED_TRANSFER_FLAG`.
    pub fn scoped_transfer_keys(&self) -> bool {
        self.scoped_transfer_keys
    }
}

impl Drop for ReceiverHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.code_phrase.zeroize();
        self.nonce.zeroize();
        if let Some(ref mut secret) = self.pake_secret {
            secret.zeroize();
        }
        if let Some(ref mut hash) = self.transcript_hash {
            hash.zeroize();
        }
        if let Some(ref mut seed) = self.ratchet_seed {
            seed.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_derive_session_key_deterministic() {
        let room_id = crate::room::code::derive_room_id("test-phrase");
        let key1 = derive_session_key_from_phrase("test-phrase", &room_id);
        let key2 = derive_session_key_from_phrase("test-phrase", &room_id);
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    #[allow(deprecated)]
    fn test_derive_session_key_different_phrases() {
        let room1 = crate::room::code::derive_room_id("phrase-one");
        let room2 = crate::room::code::derive_room_id("phrase-two");
        let key1 = derive_session_key_from_phrase("phrase-one", &room1);
        let key2 = derive_session_key_from_phrase("phrase-two", &room2);
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_cpace_key_exchange() {
        let code = "test-code";
        let session_id = b"session-123";

        let (init_pub, init_state) = start_cpace_initiator(code, session_id);
        let (resp_pub, resp_state) = start_cpace_responder(code, session_id);

        let init_pub_arr: [u8; 32] = init_pub.try_into().unwrap();
        let resp_pub_arr: [u8; 32] = resp_pub.try_into().unwrap();

        let key1 = complete_cpace(init_state, &resp_pub_arr).unwrap();
        let key2 = complete_cpace(resp_state, &init_pub_arr).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    /// Full v3 flight: both sides negotiate scoped transfer keys.
    #[test]
    fn test_scoped_transfer_keys_v4_flight() {
        let code = "scoped-flight-code";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        let init = sender.init().unwrap();
        let (caps, cpace_pub, init_nonce) = match &init {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities.clone(), *cpace_public, *nonce),
            _ => panic!("expected HandshakeInit"),
        };

        let resp = receiver
            .process_init(KEX_PROTOCOL_VERSION, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce) = match &resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (*selected_kem, *cpace_public, kem_public_key.clone(), *nonce),
            _ => panic!("expected HandshakeResponse"),
        };
        assert_eq!(selected_kem & SCOPED_TRANSFER_FLAG, SCOPED_TRANSFER_FLAG);
        assert_eq!(selected_kem & CANONICAL_KEX_FLAG, CANONICAL_KEX_FLAG);
        assert!(receiver.scoped_transfer_keys());

        let (kem_msg, sender_key) = sender
            .process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce)
            .unwrap();
        assert!(sender.scoped_transfer_keys());

        let (ct, confirmation) = match &kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext.clone(), *confirmation),
            _ => panic!("expected HandshakeKem"),
        };

        let (complete, receiver_key) = receiver.process_kem(&ct, &confirmation).unwrap();
        let receiver_confirmation = match &complete {
            Message::HandshakeComplete { confirmation } => *confirmation,
            _ => panic!("expected HandshakeComplete"),
        };
        sender
            .verify_receiver_confirmation(&receiver_confirmation)
            .unwrap();
        assert_eq!(sender_key.as_bytes(), receiver_key.as_bytes());
    }

    /// Chunk-capability bits (0x10 DEFLATE_CHUNK_FLAG / 0x08 NO_ZSTD_CHUNK_FLAG)
    /// round-trip through selected_kem: a cap-setting receiver (browser) is
    /// visible to the sender; a default CLI receiver sets neither.
    #[test]
    fn test_chunk_capability_flags_roundtrip() {
        let code = "caps-flight-code";
        let room_id = crate::room::code::derive_room_id(code);

        // Case 1: browser-style receiver advertises both caps.
        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new_with_response_caps(
            code,
            &room_id,
            DEFLATE_CHUNK_FLAG | NO_ZSTD_CHUNK_FLAG,
        );

        let (caps, cpace_pub, init_nonce) = match sender.init().unwrap() {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities, cpace_public, nonce),
            _ => panic!("expected HandshakeInit"),
        };
        let resp = receiver
            .process_init(KEX_PROTOCOL_VERSION, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce) = match &resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (*selected_kem, *cpace_public, kem_public_key.clone(), *nonce),
            _ => panic!("expected HandshakeResponse"),
        };
        assert_eq!(selected_kem & DEFLATE_CHUNK_FLAG, DEFLATE_CHUNK_FLAG);
        assert_eq!(selected_kem & NO_ZSTD_CHUNK_FLAG, NO_ZSTD_CHUNK_FLAG);
        // The pre-existing signals are unaffected.
        assert_eq!(selected_kem & SCOPED_TRANSFER_FLAG, SCOPED_TRANSFER_FLAG);
        assert_eq!(selected_kem & CANONICAL_KEX_FLAG, CANONICAL_KEX_FLAG);

        let _ = sender
            .process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce)
            .unwrap();
        assert!(sender.peer_supports_deflate_chunks());
        assert!(sender.peer_needs_plain_chunks());

        // Case 2: default CLI receiver — no caps advertised, sender sees none.
        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);
        let (caps, cpace_pub, init_nonce) = match sender.init().unwrap() {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities, cpace_public, nonce),
            _ => panic!("expected HandshakeInit"),
        };
        let resp = receiver
            .process_init(KEX_PROTOCOL_VERSION, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce) = match &resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (*selected_kem, *cpace_public, kem_public_key.clone(), *nonce),
            _ => panic!("expected HandshakeResponse"),
        };
        assert_eq!(selected_kem & DEFLATE_CHUNK_FLAG, 0);
        assert_eq!(selected_kem & NO_ZSTD_CHUNK_FLAG, 0);
        let _ = sender
            .process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce)
            .unwrap();
        assert!(!sender.peer_supports_deflate_chunks());
        assert!(!sender.peer_needs_plain_chunks());
    }

    /// A v3 initiator (scoped transfers, pre-canonical-kex) gets the scoped
    /// flag but NO canonical ACK — a v4 initiator uses the missing ACK to fall
    /// back to its legacy path.
    #[test]
    fn test_scoped_transfer_keys_v3_no_canonical_ack() {
        let code = "v3-legacy-flight-code";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        let (caps, cpace_pub, init_nonce) = match sender.init().unwrap() {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities, cpace_public, nonce),
            _ => panic!("expected HandshakeInit"),
        };

        let resp = receiver
            .process_init(3, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let selected_kem = match resp {
            Message::HandshakeResponse { selected_kem, .. }
            | Message::HandshakeResponseV9 { selected_kem, .. } => selected_kem,
            _ => panic!("expected HandshakeResponse"),
        };
        assert_eq!(selected_kem & SCOPED_TRANSFER_FLAG, SCOPED_TRANSFER_FLAG);
        assert_eq!(selected_kem & CANONICAL_KEX_FLAG, 0);
        assert!(receiver.scoped_transfer_keys());
    }

    /// 04-P1 negative case: a peer that does NOT ACK the canonical / PQ flags is
    /// never treated as an equal hybrid session.
    ///
    /// What is actually enforced on disk: [`SenderHandshake::process_response`]
    /// *records* these ACK bits (`self.pq_auth = selected_kem & PQ_AUTH_FLAG != 0`)
    /// and does NOT reject on them — a downgraded response still completes the
    /// flight, which is why [`test_scoped_transfer_keys_v3_no_canonical_ack`]
    /// can assert an unflagged response is accepted. The refusal is caller-side.
    ///
    /// So the load-bearing invariant this pins is that the downgrade is never
    /// *masked*: `pq_auth()` / `scoped_transfer_keys()` read false on exactly
    /// the bytes a legacy peer sends, and the browser gates its canonical branch
    /// on those accessors rather than on the raw flag byte.
    #[test]
    fn test_pq_downgrade_peer_is_not_authenticated() {
        let code = "pq-downgrade-negative";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        // v5 ⇒ scoped (>=3) + canonical (>=4) + PQ auth (>=5).
        let (caps, cpace_pub, init_nonce) = match sender.init_with_version(5).unwrap() {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities, cpace_public, nonce),
            _ => panic!("expected HandshakeInit"),
        };

        let (baseline_kem, resp_cpace, resp_kem_pk, resp_nonce) = match receiver
            .process_init(5, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap()
        {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (selected_kem, cpace_public, kem_public_key, nonce),
            _ => panic!("expected HandshakeResponse"),
        };

        // Baseline: a v5 negotiation ACKs all three.
        assert_eq!(baseline_kem & SCOPED_TRANSFER_FLAG, SCOPED_TRANSFER_FLAG);
        assert_eq!(baseline_kem & CANONICAL_KEX_FLAG, CANONICAL_KEX_FLAG);
        assert_eq!(baseline_kem & PQ_AUTH_FLAG, PQ_AUTH_FLAG);

        // The downgrade a legacy / JS-only peer presents: identical CPace + KEM
        // material, ACK bits cleared. The flags are not part of the transcript,
        // so the flight still completes — only the caller-visible signals move.
        let downgraded = baseline_kem & !(SCOPED_TRANSFER_FLAG | CANONICAL_KEX_FLAG | PQ_AUTH_FLAG);

        let (_kem_frame, _session_key) = sender
            .process_response(downgraded, &resp_cpace, &resp_kem_pk, &resp_nonce)
            .expect(
                "a downgraded response still completes the flight (the ACK bits are caller-side)",
            );

        assert!(
            !sender.pq_auth(),
            "a peer that never ACKed PQ_AUTH_FLAG (0x20) must not read as PQ-authenticated"
        );
        assert!(
            !sender.scoped_transfer_keys(),
            "a peer that never ACKed SCOPED_TRANSFER_FLAG (0x80) must not read as scoped"
        );
    }

    /// v2 compat: a v2 initiator negotiation never opts in; both sides stay
    /// on legacy chunk-crypto semantics and the flight still completes.
    #[test]
    fn test_scoped_transfer_keys_v2_compat_flight() {
        let code = "legacy-flight-code";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        // Security review 2026-09-23: declare v2 via `init_with_version` —
        // a real v2 initiator declares its version on the wire (the old
        // rewrite-after-init trick is itself a downgrade attack now).
        let init = sender.init_with_version(2).unwrap();
        let (caps, cpace_pub, init_nonce) = match &init {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities.clone(), *cpace_public, *nonce),
            _ => panic!("expected HandshakeInit"),
        };

        let resp = receiver
            .process_init(2, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce) = match &resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (*selected_kem, *cpace_public, kem_public_key.clone(), *nonce),
            _ => panic!("expected HandshakeResponse"),
        };
        assert_eq!(selected_kem & SCOPED_TRANSFER_FLAG, 0);
        assert_eq!(selected_kem & CANONICAL_KEX_FLAG, 0);
        assert!(!receiver.scoped_transfer_keys());

        let (kem_msg, sender_key) = sender
            .process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce)
            .unwrap();
        assert!(!sender.scoped_transfer_keys());

        let (ct, confirmation) = match &kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext.clone(), *confirmation),
            _ => panic!("expected HandshakeKem"),
        };

        let (_complete, receiver_key) = receiver.process_kem(&ct, &confirmation).unwrap();
        assert_eq!(sender_key.as_bytes(), receiver_key.as_bytes());
    }

    #[test]
    #[allow(deprecated)]
    fn test_derive_session_key_with_salt_unique() {
        let room_id = crate::room::code::derive_room_id("test-phrase");
        let salt1: [u8; 16] = [1u8; 16];
        let salt2: [u8; 16] = [2u8; 16];
        let key1 = derive_session_key_with_salt("test-phrase", &room_id, &salt1);
        let key2 = derive_session_key_with_salt("test-phrase", &room_id, &salt2);
        // Same phrase but different salts must produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    #[allow(deprecated)]
    fn test_derive_session_key_with_salt_deterministic() {
        let room_id = crate::room::code::derive_room_id("test-phrase");
        let salt: [u8; 16] = [42u8; 16];
        let key1 = derive_session_key_with_salt("test-phrase", &room_id, &salt);
        let key2 = derive_session_key_with_salt("test-phrase", &room_id, &salt);
        // Same inputs must produce the same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    #[allow(deprecated)]
    fn test_derive_session_key_with_salt_differs_from_unsalted() {
        let room_id = crate::room::code::derive_room_id("test-phrase");
        let salt: [u8; 16] = [0u8; 16];
        let unsalted = derive_session_key_from_phrase("test-phrase", &room_id);
        let salted = derive_session_key_with_salt("test-phrase", &room_id, &salt);
        // v1 (unsalted) and v2 (salted) use different domain strings
        assert_ne!(unsalted.as_bytes(), salted.as_bytes());
    }

    #[test]
    fn test_cpace_wrong_password() {
        let session_id = b"session-123";

        let (_init_pub, init_state) = start_cpace_initiator("correct", session_id);
        let (resp_pub, _resp_state) = start_cpace_responder("wrong", session_id);

        let resp_pub_arr: [u8; 32] = resp_pub.try_into().unwrap();
        let key1 = complete_cpace(init_state, &resp_pub_arr).unwrap();

        let (_init_pub2, init_state2) = start_cpace_initiator("correct", session_id);
        let (resp_pub2, _) = start_cpace_responder("correct", session_id);
        let resp_pub_arr2: [u8; 32] = resp_pub2.try_into().unwrap();
        let key2 = complete_cpace(init_state2, &resp_pub_arr2).unwrap();

        // Keys should differ with wrong password
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    // -----------------------------------------------------------------------
    // KEM Handshake Tests
    // -----------------------------------------------------------------------

    /// Cross-generation interop: a v9 build must still complete a handshake with a
    /// peer that declares an OLDER version.
    ///
    /// This is the property that makes the v9 bump deployable without a
    /// simultaneous upgrade. The transcript binds the DECLARED version
    /// (`TRANSCRIPT_BINDING_VERSION`), not each side's own local constant, so a v8
    /// peer and a v9 peer agree on one transcript and derive the same keys. It is
    /// also why `init_with_version` exists: a build declares the version it is
    /// willing to be bound to, and mixed generations negotiate down — the same
    /// mechanism the v6 flow-credit rollout used.
    ///
    /// Backwards compatibility is NOT legacy debt here, and this test is the
    /// reason: `MIN_ACCEPTED_INIT_VERSION` is 4 by design, and the ladder is pinned
    /// against the published page by `scripts/wire-version-claim-check.py`. The loop
    /// is derived from the constants rather than hardcoded, so a future version bump
    /// extends the proof instead of breaking it.
    ///
    /// (The paragraph above belongs to `test_cross_generation_handshake_derives_identical_keys`,
    /// which follows this test; the two doc blocks sit adjacent because this test was inserted
    /// between that doc and its function. Left labelled rather than silently merged.)
    ///
    /// The property the entire v9 chat ratchet rests on: after a REAL handshake, both
    /// peers hold the SAME ratchet seed — and it is not the session key.
    ///
    /// The derivation test above proves the function is deterministic. This one proves
    /// the handshake actually CALLS it, on both sides, and that the two sides agree.
    /// Without it the derivation could be perfectly correct and still never exercised
    /// in a way that matters — the failure mode that let the `0x02` collision through,
    /// where a green build was not evidence of a correct wire.
    ///
    /// Asserts three things:
    ///   1. both sides derive a seed at all (neither accessor is None);
    ///   2. the two seeds are EQUAL — the whole point, since one bidirectional ratchet
    ///      needs one shared secret;
    ///   3. the seed is NOT the session key — domain separation, so moving chat onto
    ///      the ratchet cannot hand anyone the AEAD key.
    #[test]
    fn test_both_peers_derive_the_same_ratchet_seed() {
        let code = "shared-ratchet-seed";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        let init_msg = sender.init().unwrap();
        let (pv, suite_code, caps, cpace_pub, snonce) = match init_msg {
            Message::HandshakeInit {
                protocol_version,
                suite_code,
                kem_capabilities,
                cpace_public,
                nonce,
            } => (
                protocol_version,
                suite_code,
                kem_capabilities,
                cpace_public,
                nonce,
            ),
            _ => panic!("Expected HandshakeInit"),
        };

        let resp_msg = receiver
            .process_init(pv, suite_code, &caps, &cpace_pub, &snonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_kem_pk, resp_nonce) = match resp_msg {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (selected_kem, cpace_public, kem_public_key, nonce),
            _ => panic!("Expected HandshakeResponse"),
        };

        let (kem_msg, sender_key) = sender
            .process_response(selected_kem, &resp_cpace, &resp_kem_pk, &resp_nonce)
            .unwrap();

        let (kem_ciphertext, sender_confirmation) = match kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext, confirmation),
            _ => panic!("Expected HandshakeKem"),
        };

        let (complete_msg, receiver_key) = receiver
            .process_kem(&kem_ciphertext, &sender_confirmation)
            .unwrap();
        let receiver_confirmation = match complete_msg {
            Message::HandshakeComplete { confirmation } => confirmation,
            _ => panic!("Expected HandshakeComplete"),
        };
        sender
            .verify_receiver_confirmation(&receiver_confirmation)
            .unwrap();

        // (1) Both sides computed a seed — the accessors must actually be populated.
        let sender_seed = sender
            .ratchet_seed()
            .expect("the initiator must derive a seed during process_response");
        let receiver_seed = receiver
            .ratchet_seed()
            .expect("the responder must derive a seed during process_kem");

        // The session keys must still agree — the seed work changed no existing path.
        // Asserted FIRST so a failure is unambiguous about which value diverged:
        // agreeing keys with differing seeds isolates the cause to the seed's own
        // inputs, not to the handshake.
        assert_eq!(&sender_key.as_bytes()[..], &receiver_key.as_bytes()[..]);

        // (2) They AGREE. This is what one bidirectional ratchet needs, and it is
        // what makes the capability worth advertising at all.
        assert_eq!(
            sender_seed, receiver_seed,
            "both peers must derive the SAME ratchet seed\n  initiator: {:02x?}\n  responder: {:02x?}",
            sender_seed, receiver_seed
        );

        // (3) The seed is NOT the session key. If the two derivations ever collapsed
        // onto one label this fails — and chat would be ratcheting on the key that
        // protects everything else on the connection.
        assert_ne!(
            &sender_seed[..],
            &sender_key.as_bytes()[..],
            "the ratchet seed must be domain-separated from the session key"
        );
    }

    #[test]
    fn test_cross_generation_handshake_derives_identical_keys() {
        for declared in MIN_ACCEPTED_INIT_VERSION..=crate::wire::PROTOCOL_VERSION {
            let code = format!("cross-generation-{declared}");
            let room_id = crate::room::code::derive_room_id(&code);

            let mut sender = SenderHandshake::new(&code, &room_id);
            let mut receiver = ReceiverHandshake::new(&code, &room_id);

            // The "older build" declares the version it speaks.
            let init_msg = sender.init_with_version(declared).unwrap();
            let (pv, suite_code, caps, cpace_pub, snonce) = match init_msg {
                Message::HandshakeInit {
                    protocol_version,
                    suite_code,
                    kem_capabilities,
                    cpace_public,
                    nonce,
                } => (
                    protocol_version,
                    suite_code,
                    kem_capabilities,
                    cpace_public,
                    nonce,
                ),
                _ => panic!("Expected HandshakeInit"),
            };
            assert_eq!(pv, declared, "the initiator declares what it was told to");

            // The current build must ACCEPT it — that is the floor's whole job.
            let resp_msg = receiver
                .process_init(pv, suite_code, &caps, &cpace_pub, &snonce)
                .unwrap_or_else(|e| {
                    panic!("a peer declaring v{declared} must be accepted, got: {e}")
                });

            let (selected_kem, resp_cpace, resp_kem_pk, resp_nonce) = match resp_msg {
                Message::HandshakeResponse {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                }
                | Message::HandshakeResponseV9 {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                    ..
                } => (selected_kem, cpace_public, kem_public_key, nonce),
                _ => panic!("Expected HandshakeResponse"),
            };

            let (kem_msg, sender_key) = sender
                .process_response(selected_kem, &resp_cpace, &resp_kem_pk, &resp_nonce)
                .unwrap();

            let (kem_ciphertext, sender_confirmation) = match kem_msg {
                Message::HandshakeKem {
                    kem_ciphertext,
                    confirmation,
                } => (kem_ciphertext, confirmation),
                _ => panic!("Expected HandshakeKem"),
            };

            let (complete_msg, receiver_key) = receiver
                .process_kem(&kem_ciphertext, &sender_confirmation)
                .unwrap();

            let receiver_confirmation = match complete_msg {
                Message::HandshakeComplete { confirmation } => confirmation,
                _ => panic!("Expected HandshakeComplete"),
            };
            sender
                .verify_receiver_confirmation(&receiver_confirmation)
                .unwrap();

            assert_eq!(
                sender_key.as_bytes(),
                receiver_key.as_bytes(),
                "a peer declaring v{} must still derive identical session keys",
                declared
            );
        }
    }

    /// The v9 emit: a receiver answers a peer that declared >= 9 with
    /// `HandshakeResponseV9`, and an older peer with the original shape.
    ///
    /// Pins the two properties the carrier decision rests on:
    ///   1. the SHAPE follows the DECLARED version, so a v8 peer never receives a
    ///      variant it cannot decode;
    ///   2. `capability_bits` is CLEAR, because the ratcheting chat session is not
    ///      wired yet. Setting `CAP_PQ_CHAT` here would advertise a capability the
    ///      build does not exercise — the defect class doc 08 exists to prevent.
    ///
    /// This is the tripwire for (2): when the session swap lands, flipping the bit
    /// must be a deliberate edit that updates this test too, rather than a silent
    /// capability claim.
    #[test]
    fn test_v9_response_shape_follows_declared_version() {
        use crate::wire::messages::CAP_PQ_CHAT;

        for declared in MIN_ACCEPTED_INIT_VERSION..=crate::wire::PROTOCOL_VERSION {
            let code = format!("v9-shape-{declared}");
            let room_id = crate::room::code::derive_room_id(&code);
            let mut sender = SenderHandshake::new(&code, &room_id);
            let mut receiver = ReceiverHandshake::new(&code, &room_id);

            let init_msg = sender.init_with_version(declared).unwrap();
            let (pv, suite_code, caps, cpace_pub, snonce) = match init_msg {
                Message::HandshakeInit {
                    protocol_version,
                    suite_code,
                    kem_capabilities,
                    cpace_public,
                    nonce,
                } => (
                    protocol_version,
                    suite_code,
                    kem_capabilities,
                    cpace_public,
                    nonce,
                ),
                _ => panic!("Expected HandshakeInit"),
            };

            let resp = receiver
                .process_init(pv, suite_code, &caps, &cpace_pub, &snonce)
                .unwrap();

            let is_v9_shape = matches!(resp, Message::HandshakeResponseV9 { .. });
            assert_eq!(
                is_v9_shape,
                declared >= 9,
                "a peer declaring v{declared} got the wrong response shape"
            );

            // POST-FLIP: a v9 peer must now be TOLD the capability. The site builds a
            // ratcheting session whenever this bit is set, so a CLEAR bit would be the
            // dishonest direction — withholding a capability the build has and exercises.
            //
            // An older peer receives the other shape, which carries no capability byte at
            // all. That is the disclosed downgrade and it is correct: a v8 receiver cannot
            // read ChatTextV9, so it must never be told to expect one.
            if let Message::HandshakeResponseV9 { capability_bits, .. } = &resp {
                assert_eq!(
                    capability_bits & CAP_PQ_CHAT,
                    CAP_PQ_CHAT,
                    "a v9 peer must be told PQ chat is available now that the session is wired"
                );
            }
        }
    }

    /// The v9 ratchet seed: both peers derive the SAME seed, and it is NOT the
    /// session key.
    ///
    /// Two properties, both load-bearing for the session swap:
    ///   1. identical on both sides — the seed comes from handshake material both
    ///      peers already hold, so chat can move onto the ratchet with no extra
    ///      round trip and no new agreement;
    ///   2. distinct from the session key — domain separation means putting chat on
    ///      the ratchet cannot weaken the AEAD key that protects everything else.
    ///
    /// (2) is asserted directly rather than described: if the two derivations ever
    /// collapsed onto one label, the seed would equal the session key and this test
    /// would catch it.
    #[test]
    fn test_ratchet_seed_matches_both_peers_and_differs_from_session_key() {
        let kem_ss = [7u8; 32];
        let pake = [9u8; 32];
        let eph = [11u8; 32];
        let th = [13u8; 32];
        let ct = b"ratchet-seed-ct";

        let seed_a = derive_handshake_ratchet_seed(&kem_ss, &pake, ct, &eph, &th).unwrap();
        let seed_b = derive_handshake_ratchet_seed(&kem_ss, &pake, ct, &eph, &th).unwrap();
        assert_eq!(
            seed_a, seed_b,
            "peers holding the same handshake material must derive the same seed"
        );

        let sk = derive_handshake_session_key(&kem_ss, &pake, ct, &eph, &th).unwrap();
        assert_ne!(
            seed_a, sk,
            "the ratchet seed must be domain-separated from the session key"
        );

        // A different transcript must move the seed, so one session's seed cannot be
        // reused by another.
        let seed_other =
            derive_handshake_ratchet_seed(&kem_ss, &pake, ct, &eph, &[14u8; 32]).unwrap();
        assert_ne!(seed_a, seed_other, "the transcript must bind the seed");
    }

    #[test]
    fn test_kem_handshake_roundtrip() {
        let code = "test-kem-handshake";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        // Step 1: Sender init
        let init_msg = sender.init().unwrap();
        let (protocol_version, suite_code, kem_capabilities, cpace_public, sender_nonce) =
            match init_msg {
            Message::HandshakeInit {
                protocol_version,
                suite_code,
                kem_capabilities,
                cpace_public,
                nonce,
            } => (protocol_version, suite_code, kem_capabilities, cpace_public, nonce),
            _ => panic!("Expected HandshakeInit"),
        };

        // Step 2: Receiver process init -> HandshakeResponse
        let resp_msg = receiver
            .process_init(
                protocol_version,
                suite_code,
                &kem_capabilities,
                &cpace_public,
                &sender_nonce,
            )
            .unwrap();

        let (selected_kem, resp_cpace, resp_kem_pk, resp_nonce) = match resp_msg {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (selected_kem, cpace_public, kem_public_key, nonce),
            _ => panic!("Expected HandshakeResponse"),
        };

        // Step 3: Sender process response -> HandshakeKem + session key
        let (kem_msg, sender_key) = sender
            .process_response(selected_kem, &resp_cpace, &resp_kem_pk, &resp_nonce)
            .unwrap();

        let (kem_ciphertext, sender_confirmation) = match kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext, confirmation),
            _ => panic!("Expected HandshakeKem"),
        };

        // Step 4: Receiver process KEM -> HandshakeComplete + session key
        let (complete_msg, receiver_key) = receiver
            .process_kem(&kem_ciphertext, &sender_confirmation)
            .unwrap();

        let receiver_confirmation = match complete_msg {
            Message::HandshakeComplete { confirmation } => confirmation,
            _ => panic!("Expected HandshakeComplete"),
        };

        // Sender verifies receiver's confirmation
        sender
            .verify_receiver_confirmation(&receiver_confirmation)
            .unwrap();

        // Both sides must derive the same session key
        assert_eq!(
            sender_key.as_bytes(),
            receiver_key.as_bytes(),
            "Sender and receiver must derive identical session keys"
        );
    }

    #[test]
    fn test_kem_handshake_wrong_password() {
        let room_id = crate::room::code::derive_room_id("code-a");

        let mut sender = SenderHandshake::new("code-a", &room_id);
        let mut receiver = ReceiverHandshake::new("code-b", &room_id);

        // Step 1
        let init_msg = sender.init().unwrap();
        let (pv, caps, cpub, snonce) = match init_msg {
            Message::HandshakeInit {
                suite_code: _,
                protocol_version,
                kem_capabilities,
                cpace_public,
                nonce,
            } => (protocol_version, kem_capabilities, cpace_public, nonce),
            _ => panic!("Expected HandshakeInit"),
        };

        // Step 2
        let resp_msg = receiver.process_init(pv, tallow_crypto::suite_code(), &caps, &cpub, &snonce).unwrap();
        let (sk, rc, rpk, rn) = match resp_msg {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (selected_kem, cpace_public, kem_public_key, nonce),
            _ => panic!("Expected HandshakeResponse"),
        };

        // Step 3
        let (kem_msg, _sender_key) = sender.process_response(sk, &rc, &rpk, &rn).unwrap();
        let (ct, conf) = match kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext, confirmation),
            _ => panic!("Expected HandshakeKem"),
        };

        // Step 4: Receiver should fail key confirmation because passwords differ
        let result = receiver.process_kem(&ct, &conf);
        assert!(
            result.is_err(),
            "Wrong password should cause key confirmation failure"
        );
        match result {
            Err(ProtocolError::KeyConfirmationFailed) => {} // expected
            Err(e) => panic!("Expected KeyConfirmationFailed, got: {}", e),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_kem_handshake_ephemeral_keys() {
        let code = "same-code-phrase";
        let room_id = crate::room::code::derive_room_id(code);

        // First handshake
        let key1 = {
            let mut sender = SenderHandshake::new(code, &room_id);
            let mut receiver = ReceiverHandshake::new(code, &room_id);

            let init = sender.init().unwrap();
            let (pv, caps, cpub, sn) = match init {
                Message::HandshakeInit {
                    suite_code: _,
                    protocol_version,
                    kem_capabilities,
                    cpace_public,
                    nonce,
                } => (protocol_version, kem_capabilities, cpace_public, nonce),
                _ => panic!("Expected HandshakeInit"),
            };

            let resp = receiver.process_init(pv, tallow_crypto::suite_code(), &caps, &cpub, &sn).unwrap();
            let (sk, rc, rpk, rn) = match resp {
                Message::HandshakeResponse {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                }
                | Message::HandshakeResponseV9 {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                    ..
                } => (selected_kem, cpace_public, kem_public_key, nonce),
                _ => panic!("Expected HandshakeResponse"),
            };

            let (_kem_msg, sender_key) = sender.process_response(sk, &rc, &rpk, &rn).unwrap();
            *sender_key.as_bytes()
        };

        // Second handshake with same code phrase
        let key2 = {
            let mut sender = SenderHandshake::new(code, &room_id);
            let mut receiver = ReceiverHandshake::new(code, &room_id);

            let init = sender.init().unwrap();
            let (pv, caps, cpub, sn) = match init {
                Message::HandshakeInit {
                    suite_code: _,
                    protocol_version,
                    kem_capabilities,
                    cpace_public,
                    nonce,
                } => (protocol_version, kem_capabilities, cpace_public, nonce),
                _ => panic!("Expected HandshakeInit"),
            };

            let resp = receiver.process_init(pv, tallow_crypto::suite_code(), &caps, &cpub, &sn).unwrap();
            let (sk, rc, rpk, rn) = match resp {
                Message::HandshakeResponse {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                }
                | Message::HandshakeResponseV9 {
                    selected_kem,
                    cpace_public,
                    kem_public_key,
                    nonce,
                    ..
                } => (selected_kem, cpace_public, kem_public_key, nonce),
                _ => panic!("Expected HandshakeResponse"),
            };

            let (_kem_msg, sender_key) = sender.process_response(sk, &rc, &rpk, &rn).unwrap();
            *sender_key.as_bytes()
        };

        // Ephemeral KEM keys ensure different session keys each time
        assert_ne!(
            key1, key2,
            "Two handshakes with the same code phrase must produce different session keys"
        );
    }

    /// Checklist 5.2: the declared suite code rides the wire, is validated before
    /// anything is absorbed, and is bound into the transcript by v8 — so an
    /// unknown suite is an explicit refusal rather than a negotiation down to
    /// whatever the receiver happens to implement.
    #[test]
    fn v8_declared_suite_is_validated_not_defaulted() {
        let code = "suite-binding-test";
        let room_id = crate::room::code::derive_room_id(code);
        let mut sender = SenderHandshake::new(code, &room_id);
        let init = sender.init().unwrap();

        let (pv, declared, caps, cpub, sn) = match init {
            Message::HandshakeInit {
                protocol_version,
                suite_code,
                kem_capabilities,
                cpace_public,
                nonce,
            } => (protocol_version, suite_code, kem_capabilities, cpace_public, nonce),
            _ => panic!("Expected HandshakeInit"),
        };

        // The initiator declares the suite this build runs, at the version that
        // binds it.
        assert_eq!(pv, KEX_PROTOCOL_VERSION);
        assert!(pv >= TRANSCRIPT_SUITE_BINDING_VERSION, "v8 is the binding version");
        assert_eq!(declared, tallow_crypto::suite_code());

        // An unknown code is refused outright — never defaulted onto ours, since
        // the two sides would derive different keys and only find out later.
        let mut receiver = ReceiverHandshake::new(code, &room_id);
        match receiver.process_init(pv, 0x7F, &caps, &cpub, &sn) {
            Err(ProtocolError::HandshakeFailed(msg)) => assert!(
                msg.contains("unsupported suite code"),
                "refusal should name the problem, got: {msg}"
            ),
            Err(other) => panic!(
                "expected HandshakeFailed for an unknown suite, got another error: {other:?}"
            ),
            Ok(_) => panic!("an unknown suite code must not be accepted"),
        }

        // The same init with the declared code proceeds past the gate, so the
        // refusal above is about the code and not about the handshake.
        let mut receiver = ReceiverHandshake::new(code, &room_id);
        assert!(
            receiver.process_init(pv, declared, &caps, &cpub, &sn).is_ok(),
            "the declared suite must be accepted"
        );
    }

    #[test]
    fn test_kem_handshake_transcript_binding() {
        let code = "transcript-test";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        // Step 1
        let init = sender.init().unwrap();
        let (pv, caps, cpub, sn) = match init {
            Message::HandshakeInit {
                suite_code: _,
                protocol_version,
                kem_capabilities,
                cpace_public,
                nonce,
            } => (protocol_version, kem_capabilities, cpace_public, nonce),
            _ => panic!("Expected HandshakeInit"),
        };

        // Step 2
        let resp = receiver.process_init(pv, tallow_crypto::suite_code(), &caps, &cpub, &sn).unwrap();
        let (sk, rc, mut rpk, rn) = match resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (selected_kem, cpace_public, kem_public_key, nonce),
            _ => panic!("Expected HandshakeResponse"),
        };

        // Tamper with the KEM public key (flip a byte)
        if !rpk.is_empty() {
            rpk[0] ^= 0xFF;
        }

        // Step 3: Sender processes tampered response
        // This should fail because the deserialized public key is invalid
        // or the KEM encapsulation will produce a different shared secret
        let result = sender.process_response(sk, &rc, &rpk, &rn);

        // The tampered key should cause a failure somewhere in the handshake
        // Either deserialization fails, or (if it doesn't) the receiver's
        // decapsulation will produce a different shared secret, causing
        // key confirmation to fail
        if let Ok((kem_msg, _sender_key)) = result {
            // Sender succeeded (tampered key happened to deserialize),
            // but receiver must fail because it decapsulates with a different key
            let (ct, conf) = match kem_msg {
                Message::HandshakeKem {
                    kem_ciphertext,
                    confirmation,
                } => (kem_ciphertext, confirmation),
                _ => panic!("Expected HandshakeKem"),
            };

            // Receiver should fail because transcript hashes won't match
            let recv_result = receiver.process_kem(&ct, &conf);
            assert!(
                recv_result.is_err(),
                "Tampered transcript should cause verification failure"
            );
        }
        // If sender failed, the tamper was caught early -- also acceptable
    }

    #[test]
    fn test_sender_handshake_double_init_fails() {
        let code = "double-init";
        let room_id = crate::room::code::derive_room_id(code);
        let mut sender = SenderHandshake::new(code, &room_id);

        // First init should succeed
        let _ = sender.init().unwrap();

        // Second init should fail (state machine already consumed)
        let result = sender.init();
        assert!(result.is_err(), "Double init should fail");
    }

    #[test]
    fn test_receiver_handshake_out_of_order() {
        let code = "out-of-order";
        let room_id = crate::room::code::derive_room_id(code);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        // Calling process_kem before process_init should fail
        let result = receiver.process_kem(&[0u8; 64], &[0u8; 32]);
        assert!(result.is_err(), "Out-of-order call should fail");
    }

    #[test]
    fn test_kem_handshake_message_serialization() {
        // Verify each handshake message roundtrips through postcard
        let init = Message::HandshakeInit {
            protocol_version: 2,
            suite_code: tallow_crypto::suite_code(),
            kem_capabilities: vec![0, 1, 2],
            cpace_public: [0xAA; 32],
            nonce: [0xBB; 16],
        };
        let bytes = postcard::to_stdvec(&init).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(init, decoded);

        let resp = Message::HandshakeResponse {
            selected_kem: 2,
            cpace_public: [0xCC; 32],
            kem_public_key: vec![0xDD; 128],
            nonce: [0xEE; 16],
        };
        let bytes = postcard::to_stdvec(&resp).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(resp, decoded);

        let kem = Message::HandshakeKem {
            kem_ciphertext: vec![0xFF; 256],
            confirmation: [0x11; 32],
        };
        let bytes = postcard::to_stdvec(&kem).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(kem, decoded);

        let complete = Message::HandshakeComplete {
            confirmation: [0x22; 32],
        };
        let bytes = postcard::to_stdvec(&complete).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(complete, decoded);

        let failed = Message::HandshakeFailed {
            reason: "test failure".to_string(),
        };
        let bytes = postcard::to_stdvec(&failed).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(failed, decoded);
    }

    #[test]
    fn test_version_negotiation_reject_v1_only() {
        let room_id = crate::room::code::derive_room_id("v1-test");
        let mut receiver = ReceiverHandshake::new("v1-test", &room_id);

        // A peer advertising version 1 should be rejected
        let result = receiver.process_init(1, tallow_crypto::suite_code(), &[], &[0u8; 32], &[0u8; 16]);
        assert!(result.is_err(), "Version 1 should be rejected");
        match result {
            Err(ProtocolError::VersionMismatch {
                local: 2,
                remote: 1,
            }) => {}
            Err(e) => panic!("Expected VersionMismatch, got: {}", e),
            Ok(_) => panic!("Expected error"),
        }
    }

    // -----------------------------------------------------------------
    // v5 PQ authentication (HandshakeSigned)
    // -----------------------------------------------------------------

    use tallow_crypto::keys::IdentityKeyPair;

    /// Drive a full flight with `version` as the initiator's declared
    /// protocol version (tests exercise v5 without bumping the constant).
    fn drive_flight(code: &str, version: u32) -> (SenderHandshake, ReceiverHandshake) {
        let room_id = crate::room::code::derive_room_id(code);
        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        // Security review 2026-09-23: declare via `init_with_version` so the
        // sender's transcript matches what the receiver is told (v7+ binds
        // the declared version — a wire rewrite is now an attack to detect,
        // not a test convenience).
        let init = sender.init_with_version(version).unwrap();
        let (caps, cpace_pub, init_nonce) = match &init {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities.clone(), *cpace_public, *nonce),
            _ => panic!("expected HandshakeInit"),
        };

        let resp = receiver
            .process_init(version, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce) = match &resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (*selected_kem, *cpace_public, kem_public_key.clone(), *nonce),
            _ => panic!("expected HandshakeResponse"),
        };

        let (kem_msg, sender_key) = sender
            .process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce)
            .unwrap();
        let (ct, confirmation) = match &kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext.clone(), *confirmation),
            _ => panic!("expected HandshakeKem"),
        };

        let (complete, receiver_key) = receiver.process_kem(&ct, &confirmation).unwrap();
        let receiver_confirmation = match &complete {
            Message::HandshakeComplete { confirmation } => *confirmation,
            _ => panic!("expected HandshakeComplete"),
        };
        sender
            .verify_receiver_confirmation(&receiver_confirmation)
            .unwrap();

        assert_eq!(sender_key.as_bytes(), receiver_key.as_bytes());
        (sender, receiver)
    }

    #[test]
    fn test_pq_auth_v5_flight_signed_and_verified() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let (mut sender, mut receiver) = drive_flight("pq-auth-v5-flight", 5);

        // Both sides opted in via the ACK flag.
        assert!(sender.pq_auth());
        assert!(receiver.pq_auth());
        assert!(!sender.pq_verified());
        assert!(!receiver.pq_verified());

        let sender_frame = sender.create_signed_frame(alice.signer()).unwrap();
        let receiver_frame = receiver.create_signed_frame(bob.signer()).unwrap();

        // Roles are signed correctly.
        match &sender_frame {
            Message::HandshakeSigned { role, .. } => assert_eq!(*role, PQ_AUTH_ROLE_SENDER),
            _ => panic!("expected HandshakeSigned"),
        }
        match &receiver_frame {
            Message::HandshakeSigned { role, .. } => assert_eq!(*role, PQ_AUTH_ROLE_RECEIVER),
            _ => panic!("expected HandshakeSigned"),
        }

        // Sender verifies the responder's frame (pinned to bob)...
        let seen = sender
            .verify_signed_frame(&receiver_frame, Some(bob.id()))
            .unwrap();
        assert_eq!(&seen, bob.id());
        // ...and the receiver verifies the initiator's frame (pinned to alice).
        let seen = receiver
            .verify_signed_frame(&sender_frame, Some(alice.id()))
            .unwrap();
        assert_eq!(&seen, alice.id());

        assert!(sender.pq_verified());
        assert!(receiver.pq_verified());
        assert_eq!(sender.peer_identity(), Some(*bob.id()));
        assert_eq!(receiver.peer_identity(), Some(*alice.id()));
    }

    #[test]
    fn test_pq_auth_v4_flight_is_dormant() {
        // A v4 flight never engages the v5 machinery.
        let (mut sender, receiver) = drive_flight("pq-auth-v4-dormant", 4);
        assert!(!sender.pq_auth());
        assert!(!receiver.pq_auth());

        let identity = IdentityKeyPair::generate().unwrap();
        assert!(sender.create_signed_frame(identity.signer()).is_err());
        assert!(receiver.create_signed_frame(identity.signer()).is_err());

        let bogus = Message::HandshakeSigned {
            role: PQ_AUTH_ROLE_RECEIVER,
            identity_public_key: vec![],
            signature: vec![],
        };
        assert!(sender.verify_signed_frame(&bogus, None).is_err());
    }

    #[test]
    fn test_pq_auth_tampered_signature_rejected() {
        let bob = IdentityKeyPair::generate().unwrap();
        let (mut sender, receiver) = drive_flight("pq-auth-tamper", 5);

        // Well-formed frame, flipped ML-DSA signature byte.
        let mut frame = receiver.create_signed_frame(bob.signer()).unwrap();
        if let Message::HandshakeSigned { signature, .. } = &mut frame {
            let mut sig: tallow_crypto::sig::HybridSignature =
                postcard::from_bytes(signature).unwrap();
            sig.mldsa[0] ^= 0xFF;
            *signature = postcard::to_stdvec(&sig).unwrap();
        }
        assert!(sender.verify_signed_frame(&frame, None).is_err());
        assert!(!sender.pq_verified());

        // The un-tampered frame still verifies.
        let good = receiver.create_signed_frame(bob.signer()).unwrap();
        assert!(sender.verify_signed_frame(&good, None).is_ok());
    }

    #[test]
    fn test_pq_auth_reflection_rejected() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let (mut sender, mut receiver) = drive_flight("pq-auth-reflection", 5);

        // Each side's own frame must not verify at its own verifier.
        let sender_own = sender.create_signed_frame(alice.signer()).unwrap();
        assert!(sender.verify_signed_frame(&sender_own, None).is_err());
        let receiver_own = receiver.create_signed_frame(bob.signer()).unwrap();
        assert!(receiver.verify_signed_frame(&receiver_own, None).is_err());
    }

    #[test]
    fn test_pq_auth_pin_mismatch_rejected() {
        let bob = IdentityKeyPair::generate().unwrap();
        let mallory = IdentityKeyPair::generate().unwrap();
        let (mut sender, receiver) = drive_flight("pq-auth-pin", 5);

        let frame = receiver.create_signed_frame(bob.signer()).unwrap();

        // Wrong pin is rejected and records nothing...
        assert!(sender
            .verify_signed_frame(&frame, Some(mallory.id()))
            .is_err());
        assert!(!sender.pq_verified());
        // ...while TOFU (no pin) accepts and records bob.
        let seen = sender.verify_signed_frame(&frame, None).unwrap();
        assert_eq!(&seen, bob.id());
        assert_eq!(sender.peer_identity(), Some(*bob.id()));
    }

    #[test]
    fn test_pq_auth_frame_does_not_cross_flights() {
        let bob = IdentityKeyPair::generate().unwrap();
        let (mut sender_one, _receiver_one) = drive_flight("pq-auth-flight-one", 5);
        let (_sender_two, receiver_two) = drive_flight("pq-auth-flight-two", 5);

        // A signed frame from another flight's transcript must not verify.
        let foreign = receiver_two.create_signed_frame(bob.signer()).unwrap();
        assert!(sender_one.verify_signed_frame(&foreign, None).is_err());
        assert!(!sender_one.pq_verified());
    }

    #[test]
    fn test_flow_credit_flag_gates_on_v6() {
        // v5 (every shipped peer today): the credit flag stays clear — inert.
        let (sender_v5, _) = drive_flight("flow-credit-v5", 5);
        assert!(!sender_v5.flow_credit());

        // v6: the receiver ACKs the flag and the initiator records it.
        let (sender_v6, _) = drive_flight("flow-credit-v6", 6);
        assert!(sender_v6.flow_credit());
    }

    /// `init_with_version` (A9 rollout, issue 09): the wasm sender declares 6
    /// when the rollout flag is on; `init()` keeps the v5 constant.
    #[test]
    fn test_init_with_version_declares_requested_version() {
        let code = "init-version-code";
        let room_id = crate::room::code::derive_room_id(code);

        let mut sender6 = SenderHandshake::new(code, &room_id);
        match sender6.init_with_version(6).unwrap() {
            Message::HandshakeInit {
                protocol_version, ..
            } => assert_eq!(protocol_version, 6),
            _ => panic!("expected HandshakeInit"),
        }

        let mut sender5 = SenderHandshake::new(code, &room_id);
        match sender5.init().unwrap() {
            Message::HandshakeInit {
                protocol_version, ..
            } => assert_eq!(protocol_version, KEX_PROTOCOL_VERSION),
            _ => panic!("expected HandshakeInit"),
        }
    }

    /// R1 (security review 2026-09-23): the receiver-side version gate is
    /// fail-closed below the canonical handshake (v4) — a wire rewrite of
    /// `protocol_version` down to the legacy band can no longer be accepted.
    #[test]
    fn init_version_gate_fails_closed_below_canonical() {
        assert_eq!(MIN_ACCEPTED_INIT_VERSION, 4);
        for v in [0u32, 1, 2, 3] {
            assert!(
                !is_init_version_accepted(v),
                "version {} must be refused (legacy dummy-PAKE band)",
                v
            );
        }
        for v in [4u32, 5, 6, 7, 8] {
            assert!(
                is_init_version_accepted(v),
                "version {} must be accepted",
                v
            );
        }
    }

    #[test]
    fn test_combiner_binds_kem_material() {
        // R6 (crypto #5): identical KEM + PAKE secrets and transcript, but
        // tampered/different transmitted KEM material ⇒ different session keys.
        // (This is the property the combiner lacked before 2026-09-23: it
        // derived from kem_ss||pake only, with the transcript as salt.)
        let kem_ss = [3u8; 32];
        let pake = [4u8; 32];
        let th = [5u8; 32];
        let eph_a = [6u8; 32];
        let eph_b = [7u8; 32];

        let k1 = derive_handshake_session_key(&kem_ss, &pake, b"ct-one", &eph_a, &th).unwrap();
        let k2 = derive_handshake_session_key(&kem_ss, &pake, b"ct-one", &eph_a, &th).unwrap();
        assert_eq!(k1, k2, "deterministic for identical inputs");

        let k3 = derive_handshake_session_key(&kem_ss, &pake, b"ct-two", &eph_a, &th).unwrap();
        assert_ne!(k1, k3, "kem_ciphertext must be bound into the combine");
        let k4 = derive_handshake_session_key(&kem_ss, &pake, b"ct-one", &eph_b, &th).unwrap();
        assert_ne!(
            k1, k4,
            "x25519 ephemeral public must be bound into the combine"
        );
        let k5 =
            derive_handshake_session_key(&kem_ss, &pake, b"ct-one", &eph_a, &[9u8; 32]).unwrap();
        assert_ne!(k1, k5, "transcript hash must stay bound");
    }

    /// Security review 2026-09-23 (crypto hack report, Attack 1) — RED probe:
    /// a MITM that rewrites the declared `protocol_version` down on the wire
    /// must NOT produce a silently working session. With transcript binding
    /// (v7+) the sender bound the version it truly declared; a receiver fed a
    /// rewritten version derives different keys/confirmations and the
    /// exchange must fail.
    #[test]
    fn test_version_rewrite_fails_confirmations() {
        let code = "rewrite-probe-code";
        let room_id = crate::room::code::derive_room_id(code);

        // Sender binds TRANSCRIPT_BINDING_VERSION — the version it declares.
        let mut sender = SenderHandshake::new(code, &room_id);
        let init = sender
            .init_with_version(TRANSCRIPT_BINDING_VERSION)
            .unwrap();
        let (caps, cpace_pub, init_nonce) = match &init {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities.clone(), *cpace_public, *nonce),
            _ => panic!("expected HandshakeInit"),
        };

        // MITM rewrites the version on the wire down to v5 before delivery.
        let mut receiver = ReceiverHandshake::new(code, &room_id);
        let resp = receiver
            .process_init(5, tallow_crypto::suite_code(), &caps, &cpace_pub, &init_nonce)
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce) = match &resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            }
            | Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                ..
            } => (*selected_kem, *cpace_public, kem_public_key.clone(), *nonce),
            _ => panic!("expected HandshakeResponse"),
        };

        // The session must not silently succeed: either the sender rejects the
        // response or the receiver rejects the sender's confirmation.
        let detected =
            match sender.process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce) {
                Err(_) => true,
                Ok((kem_msg, _key)) => {
                    let (ct, confirmation) = match &kem_msg {
                        Message::HandshakeKem {
                            kem_ciphertext,
                            confirmation,
                        } => (kem_ciphertext.clone(), *confirmation),
                        _ => panic!("expected HandshakeKem"),
                    };
                    receiver.process_kem(&ct, &confirmation).is_err()
                }
            };
        assert!(
            detected,
            "version rewrite was accepted silently — transcript binding missing"
        );

        // Control: the un-rewritten flight still succeeds end to end
        // (drive_flight asserts both sides derive the same session key).
        let _ = drive_flight(code, TRANSCRIPT_BINDING_VERSION);
    }

    // -------------------------------------------------------------------
    // Phase 5 item 2 — the PQ capability record's transcript binding
    // -------------------------------------------------------------------

    /// One full flight at `version`, with the initiator TOLD `told` capability
    /// bits (what a middleman let through) while the responder advertises
    /// [`RESPONDER_CAPABILITY_BITS`].
    ///
    /// Returns `(completed, advertised, told)`. `completed` means the whole
    /// four-frame handshake finished AND both sides derived the same session key —
    /// deliberately the same pass condition the hostile-relay matrix's strip arm
    /// asserts, so the two instruments cannot disagree about what "detected" means.
    fn capability_flight(code: &str, version: u32, told: Option<u8>) -> (bool, u8, u8) {
        let room_id = crate::room::code::derive_room_id(code);
        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        let init = sender.init_with_version(version).unwrap();
        let (caps, cpace_pub, init_nonce) = match &init {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities.clone(), *cpace_public, *nonce),
            _ => panic!("expected HandshakeInit"),
        };
        let resp = receiver
            .process_init(
                version,
                tallow_crypto::suite_code(),
                &caps,
                &cpace_pub,
                &init_nonce,
            )
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce, advertised) = resp
            .handshake_response_parts()
            .expect("a handshake response");
        let told = told.unwrap_or(advertised);

        let (kem_msg, sender_key) = match sender.process_response_with_capabilities(
            selected_kem,
            &resp_cpace,
            &resp_pk,
            &resp_nonce,
            told,
        ) {
            Ok(v) => v,
            Err(_) => return (false, advertised, told),
        };
        let (ct, confirmation) = match &kem_msg {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext.clone(), *confirmation),
            _ => panic!("expected HandshakeKem"),
        };
        let (complete, receiver_key) = match receiver.process_kem(&ct, &confirmation) {
            Ok(v) => v,
            Err(_) => return (false, advertised, told),
        };
        let receiver_confirmation = match &complete {
            Message::HandshakeComplete { confirmation } => *confirmation,
            _ => panic!("expected HandshakeComplete"),
        };
        let confirmed = sender
            .verify_receiver_confirmation(&receiver_confirmation)
            .is_ok();
        (
            confirmed && sender_key.as_bytes() == receiver_key.as_bytes(),
            advertised,
            told,
        )
    }

    /// Below the binding version NOTHING changes: the transcript is byte-for-byte
    /// what the deployed pair already speaks, both entry points complete a
    /// handshake, and the capability byte stays a plain field.
    ///
    /// This is the interop control for the gate. If it ever fails, the binding has
    /// been activated at (or below) a version a shipped peer declares — which is
    /// the flag day `CAPABILITY_BINDING_VERSION`'s docs describe, and it must be a
    /// deliberate move, with the pair-compat reference re-cut, not a side effect.
    #[test]
    fn test_capability_binding_is_inert_below_its_version() {
        assert!(
            CAPABILITY_BINDING_VERSION > KEX_PROTOCOL_VERSION,
            "the binding must sit above the version this build declares"
        );

        let (completed, advertised, told) =
            capability_flight("phase5-cap-inert", KEX_PROTOCOL_VERSION, None);
        assert_eq!(advertised, RESPONDER_CAPABILITY_BITS);
        assert_eq!(told, advertised);
        assert!(
            completed,
            "an honest v{} flight must complete with the binding gate closed",
            KEX_PROTOCOL_VERSION
        );

        // The capability-blind entry point is still CORRECT here — only the binding
        // version requires the byte — so the deployed call sites keep working
        // unchanged. (drive_flight asserts both sides derive the same session key.)
        let _ = drive_flight("phase5-cap-inert-legacy", KEX_PROTOCOL_VERSION);
    }

    /// At the binding version the capability record IS bound, so a middleman that
    /// clears it (or changes it) no longer decides what the initiator believes:
    /// the two transcript hashes diverge, and with them the session key, the
    /// ratchet seed and both confirmation tags.
    ///
    /// The assertion is the phase's own pass condition: the handshake must NOT
    /// complete under the strip. Note what is NOT asserted — a low capability value
    /// is not refused. The record is a pure function of the value, so a peer that
    /// honestly advertises `0` binds `record(0)` on both sides and completes: the
    /// binding refuses DISAGREEMENT, never a disclosed "no capabilities".
    #[test]
    fn test_stripped_capability_record_is_detected_at_the_binding_version() {
        let version = CAPABILITY_BINDING_VERSION;

        // Control — honest flight: completes, and the initiator latched what it was told.
        let (completed, advertised, told) = capability_flight("phase5-cap-bound", version, None);
        assert_eq!(advertised, RESPONDER_CAPABILITY_BITS);
        assert_eq!(told, advertised);
        assert!(completed, "the honest control flight must complete");

        // ARM — the middleman clears the byte in flight.
        let (completed, advertised, told) =
            capability_flight("phase5-cap-stripped", version, Some(0));
        assert_eq!(
            advertised, RESPONDER_CAPABILITY_BITS,
            "the responder still advertised"
        );
        assert_eq!(told, 0, "the middleman's view reached the initiator");
        assert!(
            !completed,
            "STRIP NOT DETECTED at the binding version: the responder advertised \
             0x{advertised:02x} and the initiator was told 0x{told:02x}, yet the handshake \
             completed with matching keys — the capability record is not bound into the \
             transcript"
        );

        // ARM — a rewritten (not cleared) byte is caught by the same divergence, so
        // the protection is not "the zero case" only.
        let (rewritten_completed, _, _) =
            capability_flight("phase5-cap-rewritten", version, Some(0x02));
        assert!(
            !rewritten_completed,
            "a rewritten capability byte must be detected as well as a cleared one"
        );
    }

    /// The capability-blind entry point REFUSES a peer that declared the binding
    /// version instead of silently deriving keys from an unbound transcript.
    ///
    /// This is what makes the version bump a mechanical, compiler-adjacent change:
    /// a call site left behind fails loudly at handshake time with the rule in the
    /// message.
    #[test]
    fn test_capability_blind_entry_point_refuses_a_binding_version_peer() {
        let code = "phase5-cap-refuse";
        let room_id = crate::room::code::derive_room_id(code);
        let mut sender = SenderHandshake::new(code, &room_id);
        let mut receiver = ReceiverHandshake::new(code, &room_id);

        let init = sender
            .init_with_version(CAPABILITY_BINDING_VERSION)
            .unwrap();
        let (caps, cpace_pub, init_nonce) = match &init {
            Message::HandshakeInit {
                kem_capabilities,
                cpace_public,
                nonce,
                ..
            } => (kem_capabilities.clone(), *cpace_public, *nonce),
            _ => panic!("expected HandshakeInit"),
        };
        let resp = receiver
            .process_init(
                CAPABILITY_BINDING_VERSION,
                tallow_crypto::suite_code(),
                &caps,
                &cpace_pub,
                &init_nonce,
            )
            .unwrap();
        let (selected_kem, resp_cpace, resp_pk, resp_nonce, _advertised) = resp
            .handshake_response_parts()
            .expect("a handshake response");

        let err = match sender.process_response(selected_kem, &resp_cpace, &resp_pk, &resp_nonce) {
            Ok(_) => panic!("the capability-blind entry point must refuse a binding-version peer"),
            Err(err) => err,
        };
        assert!(
            format!("{err}").contains("binds the PQ capability record"),
            "the refusal must name the rule: {err}"
        );
    }
}
