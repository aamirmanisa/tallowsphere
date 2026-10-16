//! PQ capability records — the carrier, its transcript binding, and the latch.
//!
//! ## What the record is
//!
//! A receiver that can drive chat on the **ratcheting** session says so in
//! `HandshakeResponseV9::capability_bits` (bit 0 = [`CAP_PQ_CHAT`]); a clear byte
//! means the static-key chat path — a disclosed downgrade, never a refusal, so
//! chat keeps working between generations.[`CAP_PQ_CHAT`]: crate::wire::messages::CAP_PQ_CHAT
//!
//! Until the binding below was added, that byte was the one part of the handshake
//! response no key depended on: `kex` appends the responder's CPace public
//! message, its nonce and its KEM public key to the handshake transcript, and the
//! transcript hash then feeds the session key, the ratchet seed, both key
//! confirmations and (v5+) the `HandshakeSigned` long-term signature — but never
//! the capability byte. A middleman could therefore clear it in flight and the
//! initiator would see an ordinary "no capabilities" peer: a SILENT downgrade off
//! the PQ chat ratchet. Reproduced by the Phase 5 hostile-relay matrix's strip
//! arm (`crates/tallow-relay/tests/hostile_relay_matrix.rs`,
//! `strip_pq_control_records_must_be_detected`), which was RED at the pre-fix head
//! with "the initiator was told capability_bits=0x00 while the responder
//! advertised 0x01".
//!
//! ## The binding
//!
//! [`capability_record`] is the canonical byte pair appended to the handshake
//! transcript by BOTH peers — the responder for the value it advertises, the
//! initiator for the value it received — in the same position (immediately after
//! the responder's serialized KEM public key, before the KEM ciphertext). The
//! record therefore rides the existing handshake MAC: altering or clearing the
//! byte diverges the transcript hash, which diverges the session key, the ratchet
//! seed and both key confirmation tags — the handshake FAILS instead of
//! downgrading. No new field, no new round trip, no key material of its own.
//!
//! [`CAPABILITY_BINDING_VERSION`] gates it. That is deliberate and load-bearing:
//! binding the record at the version the deployed pair speaks would change the
//! transcript of a shipped peer, so a patched build could no longer complete a
//! handshake with an unpatched one — a hard failure, which is the right direction,
//! but not something a single card may impose on the wire. See the constant's own
//! docs for what a version bump requires.
//!
//! ## The latch
//!
//! [`CapabilityLatch`] is the "downgrade only on the FIRST message, locked in
//! afterwards" rule in one place: the first capability statement a peer makes
//! fixes the value for the session, and any later statement that tries to change
//! it is refused rather than absorbed. Without the latch, "the peer has no PQ
//! chat" is a property of the most recent frame rather than of the session, and a
//! late frame — or a replayed handshake response — can move it.

use crate::error::ProtocolError;

/// The protocol version at which the PQ capability record becomes transcript-bound.
///
/// **This build does not declare it**: [`PROTOCOL_VERSION`] stays 9, so the gate
/// is inert and the deployed pair keeps the transcript it already speaks. The
/// constant exists so the change is version-gated BY CONSTRUCTION rather than by
/// discipline.
///
/// ## What a version bump would require (recorded, not executed — Phase 5 item 2)
///
/// 1. `PROTOCOL_VERSION` / `KEX_PROTOCOL_VERSION` move to this value, and the
///    initiator's `process_response` call sites must pass the received capability
///    byte (`SenderHandshake::process_response_with_capabilities`). The 4-argument
///    `process_response` **refuses** once the declared version reaches this
///    constant, so a call site left behind fails loudly at handshake time instead
///    of deriving unbound keys.
/// 2. What stays compatible: every declared version below this constant keeps the
///    old transcript byte-for-byte, so a v9 peer (including the Phase 0
///    pair-compat reference) still completes a handshake with either shape of the
///    response, and `capability_bits` stays a plain field there.
/// 3. What breaks, by design: a peer that declares >= this constant and a peer
///    that does not cannot complete a handshake with each other. That is the
///    point — an unbound capability byte is exactly the silent downgrade this
///    record removes — but it means the raise is a flag day for mixed builds, and
///    it needs the ordering lesson from `c-2026-10-14-1`: the relay path carried
///    the new chat variant BEFORE any client claimed it, because a relay built
///    from mainline drops an unknown frame silently. The same rule applies here —
///    the binding must be carried by every hop and every shipped peer that
///    declares the new version before any client declares it.
///
/// [`PROTOCOL_VERSION`]: crate::wire::version::PROTOCOL_VERSION
pub const CAPABILITY_BINDING_VERSION: u32 = 10;

/// Domain tag of the capability record inside the handshake transcript.
///
/// A single tagged byte keeps the record distinguishable from the other
/// transcript appends (which are length-prefixed blobs) and pins it to one
/// meaning: "the PQ capability byte that followed".
pub const CAPABILITY_RECORD_TAG: u8 = 0x50;

/// The canonical transcript record for a peer's PQ capability byte.
///
/// Fixed 2 bytes — tag then value — so the record length cannot vary with the
/// value and the append position is the same on both peers.
pub fn capability_record(capability_bits: u8) -> [u8; 2] {
    [CAPABILITY_RECORD_TAG, capability_bits]
}

/// The peer capability a session has locked in from the peer's first message.
///
/// One value per session: the first statement wins ([`Self::observe_first`]) and
/// any later statement that disagrees is refused ([`Self::observe`]). Both entry
/// points return the value now in force, so a caller can record and read it in
/// one step and cannot accidentally hold a private copy that drifts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLatch {
    observed: Option<u8>,
}

impl CapabilityLatch {
    /// A latch that has seen nothing yet.
    pub const fn new() -> Self {
        Self { observed: None }
    }

    /// Record the capability the peer declared on its FIRST message.
    ///
    /// Idempotent: repeating the same first value is a no-op (a retransmitted or
    /// re-decoded handshake response cannot move it), and a *different* value is
    /// NOT absorbed here — see [`Self::observe`], which is what a later message
    /// must go through.
    pub fn observe_first(&mut self, capability_bits: u8) -> u8 {
        *self.observed.get_or_insert(capability_bits)
    }

    /// Record a capability statement from a LATER message.
    ///
    /// Returns the latched value when the statement agrees with the first one,
    /// and refuses a change: a peer that says "no PQ chat" in its handshake and
    /// "PQ chat" later (or the reverse) is not being honest about the session, and
    /// the difference must not be absorbed silently.
    pub fn observe(&mut self, capability_bits: u8) -> Result<u8, ProtocolError> {
        match self.observed {
            None => {
                self.observed = Some(capability_bits);
                Ok(capability_bits)
            }
            Some(current) if current == capability_bits => Ok(current),
            Some(current) => Err(ProtocolError::InvalidMessage(format!(
                "peer capability bits changed after the first message: latched 0x{current:02x}, \
                 later message declares 0x{capability_bits:02x}"
            ))),
        }
    }

    /// The capability in force, or `None` if the peer has not spoken yet.
    pub fn bits(&self) -> Option<u8> {
        self.observed
    }

    /// Whether the session's capability state is fixed.
    pub fn is_locked(&self) -> bool {
        self.observed.is_some()
    }

    /// Forget the latched value (session teardown).
    pub fn clear(&mut self) {
        self.observed = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record is fixed-width and injective in the value: two different
    /// capability bytes can never produce the same transcript append, and the
    /// append cannot change length — which is what makes "same position on both
    /// peers" meaningful.
    #[test]
    fn test_record_is_fixed_width_and_value_distinct() {
        let set = capability_record(0x01);
        let cleared = capability_record(0x00);
        assert_eq!(set.len(), 2);
        assert_eq!(cleared.len(), 2);
        assert_eq!(set[0], CAPABILITY_RECORD_TAG);
        assert_eq!(cleared[0], CAPABILITY_RECORD_TAG);
        assert_ne!(set, cleared);
        assert_ne!(capability_record(0x02), set);
    }

    /// First statement wins; the same value repeated is a no-op.
    #[test]
    fn test_latch_first_statement_wins() {
        let mut latch = CapabilityLatch::new();
        assert!(!latch.is_locked());
        assert_eq!(latch.bits(), None);
        assert_eq!(latch.observe_first(0x01), 0x01);
        assert_eq!(latch.bits(), Some(0x01));
        assert!(latch.is_locked());
        // A repeat cannot move it.
        assert_eq!(latch.observe_first(0x00), 0x01);
        assert_eq!(latch.observe(0x01).expect("the latch is unchanged"), 0x01);
    }

    /// A later message may not change the latched capability — in either
    /// direction, so "no capabilities" cannot be quietly upgraded to a PQ peer
    /// either.
    #[test]
    fn test_latch_refuses_a_change_after_the_first_message() {
        let mut latch = CapabilityLatch::new();
        latch.observe_first(0x01);
        let err = latch
            .observe(0x00)
            .expect_err("a downgrade after the first message must be refused");
        assert!(
            format!("{err}").contains("changed after the first message"),
            "the refusal must name the rule: {err}"
        );
        assert_eq!(latch.bits(), Some(0x01), "the latched value is unchanged");

        // The mirrored direction is refused by the same rule.
        let mut other = CapabilityLatch::new();
        other.observe_first(0x00);
        assert!(other.observe(0x01).is_err());
        assert_eq!(other.bits(), Some(0x00));
    }

    /// A latch with nothing latched accepts the first statement it is given
    /// through `observe` too, so a caller may route either frame through it.
    #[test]
    fn test_latch_accepts_the_first_statement_through_observe() {
        let mut latch = CapabilityLatch::new();
        assert_eq!(
            latch
                .observe(0x00)
                .expect("first statement through observe"),
            0x00
        );
        assert_eq!(latch.bits(), Some(0x00));
        // `clear` releases the session's value (teardown).
        latch.clear();
        assert!(!latch.is_locked());
        assert_eq!(latch.observe_first(0x01), 0x01);
    }

    /// The binding is gated on a version this build does NOT declare: if this
    /// ever fails, the gate has been activated and the interop consequences in
    /// `CAPABILITY_BINDING_VERSION`'s docs stop being hypothetical.
    #[test]
    fn test_binding_version_is_not_the_declared_version_yet() {
        assert_eq!(crate::wire::version::PROTOCOL_VERSION, 9);
        assert_eq!(
            CAPABILITY_BINDING_VERSION,
            crate::wire::version::PROTOCOL_VERSION + 1,
            "the binding must sit one version above the deployed one"
        );
    }
}
