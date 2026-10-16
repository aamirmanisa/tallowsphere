//! Sparse PQ ratchet for periodic ML-KEM re-keying
//!
//! ATK-4-4 repair (T-202): this module previously held a chain secret that
//! never advanced on `step()` — the "ratchet" was a no-op, and the only PQ
//! contribution (`TripleRatchet` re-mixing the original shared secret at
//! rekey boundaries) added no entropy. The repaired construction is a real
//! chain:
//!
//! * every `step()` derives a new chain secret with a domain-separated KDF
//!   (`next = KDF(prev, step_index)`), so consecutive steps yield distinct
//!   key material and a skipped step desynchronizes against a peer;
//! * at `rekey_interval` boundaries a fresh ML-KEM keypair is generated and
//!   its public key returned for transmission to the peer, and that keypair is
//!   RETAINED (bounded, oldest first) until the peer's ciphertext for it comes
//!   back — a rekey is a round trip, so the next boundary must not overwrite a
//!   keypair whose answer is still in flight (see `MAX_RETAINED_KEYPAIRS`);
//! * a *completed* KEM exchange mixes the decapsulated secret into the chain:
//!   the keypair owner via `process_ciphertext`, the peer via
//!   `encapsulate_to`. Only then does fresh PQ entropy enter the chain.
//!
//! Honesty note: until a caller completes that exchange (transmit the
//! `step()` public key, feed the returned ciphertext back), the PQ leg is
//! inert. `pq_established()` reports whether a PQ secret has actually been
//! mixed, and `TripleRatchet::is_pq_active()` forwards that, so no PQ
//! FS/PCS is claimed for an exchange that never ran.

use crate::error::{CryptoError, Result};
use crate::hash::blake3;
use crate::kem::mlkem::{Ciphertext, MlKem, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use zeroize::Zeroize;

/// Domain separation for the per-step chain advance.
const STEP_DOMAIN: &str = "tallow.sparse_pq.ratchet.step";
/// Domain separation for mixing a KEM shared secret into the chain.
const KEM_MIX_DOMAIN: &str = "tallow.sparse_pq.ratchet.kem_mix";

/// How many completed-exchange secrets may wait for drainage.
///
/// The queue exists so a completed ML-KEM secret is NEVER silently overwritten
/// by the next completed exchange — see [`PendingMix`]. It is bounded so a peer
/// that stops draining cannot grow session state without limit; a secret dropped
/// by the bound is COUNTED ([`SparsePqRatchet::dropped_pending_mixes`]), never
/// silent, because a dropped secret means the two root keys no longer carry the
/// same mix sequence.
const MAX_PENDING_MIXES: usize = 4;

/// How many superseded rekey keypairs are retained for their ciphertext.
///
/// A rekey boundary emits a public key and the peer's ciphertext for it comes
/// back some messages later, so at any moment the owner can hold more than one
/// keypair whose exchange is still open — and which one a ciphertext belongs to
/// is not on the wire (FIPS 203 decapsulation *cannot* say: a ciphertext for
/// another keypair implicit-rejects to a junk secret with `Ok`, see
/// [`Self::process_ciphertext`]). Retention is what keeps the pairing: the
/// oldest outstanding keypair is the oldest outstanding public key, and
/// ciphertexts come back in the order their public keys went out.
///
/// Bounded, like the mix queue, so a peer that never answers cannot grow session
/// state without limit; a keypair discarded by the bound is COUNTED
/// ([`Self::dropped_keypairs`]) and the count matters, because it means the
/// owner can no longer complete an exchange the peer may still be answering.
const MAX_RETAINED_KEYPAIRS: usize = 8;

/// A completed ML-KEM exchange secret, tagged with the chain epoch it belongs to.
///
/// SPQR parity (Phase 5 item 3): SPQR selects a chain **from the message's
/// epoch** rather than from a boundary counter both peers must advance in step.
/// The analogous property here is that the root-key mix slot is derived from the
/// secret's own epoch tag and the queue is drained in ASCENDING epoch order, so
/// *when* a caller drains cannot reorder the mixes — which is what a
/// one-message drain skew used to do to a single-slot `Option`.
#[derive(Clone)]
struct PendingMix {
    /// Chain epoch (`step_count`) at which this secret was mixed into the
    /// sparse chain. Monotone: appended in production order.
    epoch: u64,
    /// The decapsulated / encapsulated ML-KEM shared secret itself.
    secret: [u8; 32],
}

impl Zeroize for PendingMix {
    fn zeroize(&mut self) {
        self.epoch.zeroize();
        self.secret.zeroize();
    }
}

/// Sparse PQ Ratchet state
///
/// Not Clone — ratchet state must never be duplicated.
#[derive(Serialize, Deserialize)]
pub struct SparsePqRatchet {
    current_secret: [u8; 32],
    /// ML-KEM keypairs whose public key went out and whose ciphertext has not
    /// come back yet, OLDEST FIRST. Intentionally skipped on serialize (secret
    /// key material must not be persisted). After deserialization this is empty
    /// and rekeying resumes at the next boundary.
    ///
    /// Was a single `Option<(PublicKey, SecretKey)>`, overwritten
    /// UNCONDITIONALLY at every rekey boundary — so a ciphertext that came back
    /// after the next boundary was decapsulated against the *replacement* key,
    /// implicit-rejected to a junk secret, mixed into the chain, and the two
    /// peers desynced permanently with no error anywhere (measured: 11th message
    /// at interval 3, zero packet loss). A keypair is now retained until its
    /// ciphertext arrives or the bound retires it, and the OLDEST outstanding
    /// keypair is the one the oldest outstanding public key belongs to.
    #[serde(skip)]
    keypairs: VecDeque<(PublicKey, SecretKey)>,
    step_count: u64,
    rekey_interval: u64,
    /// Whether an ML-KEM exchange secret has actually been mixed into this
    /// chain (i.e. the PQ leg has run at least once).
    #[serde(default)]
    pq_established: bool,
    /// Fresh PQ secrets awaiting drainage into the root key by the owner
    /// (`TripleRatchet`), held in ASCENDING chain-epoch order. Transient session
    /// state — not serialized.
    ///
    /// Was a single `Option<[u8; 32]>`, which silently DROPPED a completed
    /// secret when the next exchange completed before the caller drained: the
    /// two peers then applied different mix sequences and their root keys never
    /// converged again, with no error anywhere. The queue makes the drain order
    /// the production order, so a caller that is a boundary late still applies
    /// the same sequence (Phase 5 item 3).
    #[serde(skip)]
    pending_mixes: Vec<PendingMix>,
    /// Completed-exchange secrets discarded because the queue was at capacity.
    /// A non-zero value means the peers' root keys no longer carry the same mix
    /// sequence — the honest, greppable form of the failure the queue prevents.
    #[serde(skip)]
    dropped_pending_mixes: u64,
    /// Rekey keypairs retired because their public key never reached the peer
    /// (`abandon_rekey_key`). Distinct from the bound drop above: this one is
    /// the caller's accounting of a rekey record it could not transmit.
    #[serde(skip)]
    abandoned_rekeys: u64,
    /// Rekey keypairs discarded because the retention bound was reached.
    #[serde(skip)]
    dropped_keypairs: u64,
}

impl SparsePqRatchet {
    /// How many rekey keypairs are still waiting for their ciphertext.
    pub fn retained_keypair_count(&self) -> usize {
        self.keypairs.len()
    }

    /// The public key of the OLDEST outstanding rekey keypair — the one a
    /// returning ciphertext is expected to belong to — if any.
    pub fn oldest_outstanding_rekey_key(&self) -> Option<&PublicKey> {
        self.keypairs.front().map(|(pk, _)| pk)
    }

    /// Rekey keypairs discarded because the retention bound was reached.
    ///
    /// Non-zero means an exchange this ratchet opened can no longer be
    /// completed: the mix sequence that follows cannot be symmetric with the
    /// peer's, so PQ forward secrecy for the session must not be claimed.
    pub fn dropped_keypairs(&self) -> u64 {
        self.dropped_keypairs
    }

    /// Retire the keypair for a rekey public key that was never transmitted.
    ///
    /// The owner generates a keypair and hands its public key to the caller for
    /// transmission. A caller that cannot transmit it (its outgoing record was
    /// itself superseded) must call this: no ciphertext can ever arrive for a
    /// public key that never went on the wire, so leaving the keypair in the
    /// retention queue would shift every later ciphertext onto the wrong keypair
    /// — the same desync this queue exists to prevent, one rekey later.
    ///
    /// Returns whether a keypair was actually retired.
    pub fn abandon_rekey_key(&mut self, pk: &PublicKey) -> bool {
        if let Some(pos) = self
            .keypairs
            .iter()
            .position(|(held, _)| held.as_bytes() == pk.as_bytes())
        {
            let mut retired = self.keypairs.remove(pos).expect("position checked");
            retired.1.zeroize();
            self.abandoned_rekeys = self.abandoned_rekeys.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Rekey keypairs retired because their public key never reached the peer.
    pub fn abandoned_rekeys(&self) -> u64 {
        self.abandoned_rekeys
    }
}

impl Zeroize for SparsePqRatchet {
    fn zeroize(&mut self) {
        self.current_secret.zeroize();
        // Clear the retained keypairs (secret key material).
        for (_, mut sk) in self.keypairs.drain(..) {
            sk.zeroize();
        }
        self.step_count.zeroize();
        for mix in self.pending_mixes.iter_mut() {
            mix.zeroize();
        }
        self.pending_mixes.clear();
        self.dropped_pending_mixes = 0;
        self.pq_established = false;
    }
}

impl Drop for SparsePqRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SparsePqRatchet {
    /// Create a new sparse PQ ratchet that rekeys every `rekey_interval` steps.
    ///
    /// # Panics
    ///
    /// Panics if `rekey_interval` is 0.
    ///
    /// Zero used to be silently clamped to `u64::MAX`, which disabled PQ rekeying with no signal
    /// anywhere: a caller passing a zero from an unset config, a default, or a computed value lost
    /// post-quantum forward secrecy, with no error, no log, and nothing visible at the call site.
    /// That is the exact property this ratchet exists to provide, failing open on a zero.
    ///
    /// Disabling rekeying is a legitimate choice, so it is a *named* one — call
    /// [`SparsePqRatchet::new_disabled`]. This panics only on a programming error, not on user
    /// input: `tallow-web` maps a caller-supplied 0 to the default before construction, so no
    /// untrusted value reaches here as 0.
    pub fn new(initial_secret: [u8; 32], rekey_interval: u64) -> Self {
        assert!(
            rekey_interval != 0,
            "rekey_interval must be non-zero: PQ rekeying is disabled by choice via \
             SparsePqRatchet::new_disabled, never by silently passing 0"
        );
        Self {
            current_secret: initial_secret,
            keypairs: VecDeque::new(),
            step_count: 0,
            rekey_interval,
            pq_established: false,
            pending_mixes: Vec::new(),
            dropped_pending_mixes: 0,
            abandoned_rekeys: 0,
            dropped_keypairs: 0,
        }
    }

    /// Create a sparse PQ ratchet with ML-KEM rekeying deliberately disabled.
    ///
    /// This is the explicit, greppable form of "no rekeying", and it is honest about the cost: the
    /// chain secret still advances on every step (so the ratchet is not a no-op), but no fresh
    /// ML-KEM keypair is ever generated, so the session gets no post-quantum forward secrecy.
    /// Prefer [`SparsePqRatchet::new`] unless a caller genuinely needs this.
    pub fn new_disabled(initial_secret: [u8; 32]) -> Self {
        Self {
            current_secret: initial_secret,
            keypairs: VecDeque::new(),
            step_count: 0,
            rekey_interval: u64::MAX,
            pq_established: false,
            pending_mixes: Vec::new(),
            dropped_pending_mixes: 0,
            abandoned_rekeys: 0,
            dropped_keypairs: 0,
        }
    }

    /// Perform a ratchet step
    ///
    /// Always advances the chain secret with a domain-separated KDF step
    /// (ATK-4-4: previously the chain did not advance at all). When the step
    /// count reaches `rekey_interval`, a fresh ML-KEM keypair is generated and
    /// its public key returned for transmission to the peer; the peer
    /// encapsulates to it and the ciphertext is consumed by
    /// `process_ciphertext`, which retires the keypair it belongs to.
    ///
    /// Emitting at every boundary is deliberate and unchanged: the rekey cadence
    /// is a protocol property, so a keypair is retained ALONGSIDE the newer one
    /// rather than replacing it.
    pub fn step(&mut self) -> Result<Option<PublicKey>> {
        self.step_count = self.step_count.saturating_add(1);

        // Chain step: next = KDF(prev || step_index). Every step moves the
        // chain, so a skipped step desynchronizes against a peer in lockstep.
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(&self.current_secret);
        input.extend_from_slice(&self.step_count.to_le_bytes());
        let next = blake3::derive_key(STEP_DOMAIN, &input);
        input.zeroize();
        self.current_secret.zeroize();
        self.current_secret = next;

        if self.step_count.is_multiple_of(self.rekey_interval) {
            // Time to rekey: fresh ML-KEM keypair; public key is emitted for
            // transmission, ciphertext comes back via `process_ciphertext`.
            let (pk, sk) = MlKem::keygen()?;
            self.keypairs.push_back((pk.clone(), sk));
            while self.keypairs.len() > MAX_RETAINED_KEYPAIRS {
                // Retire the OLDEST: the peer has had the most time to answer
                // for it, so it is the least likely to still be in flight.
                if let Some((_, mut sk)) = self.keypairs.pop_front() {
                    sk.zeroize();
                }
                self.dropped_keypairs = self.dropped_keypairs.saturating_add(1);
            }
            Ok(Some(pk))
        } else {
            Ok(None)
        }
    }

    /// Process received ML-KEM ciphertext and update secret
    ///
    /// Decapsulates against the OLDEST outstanding rekey keypair — the one whose
    /// public key went out earliest and whose answer is therefore the one that
    /// can arrive now — mixes the shared secret into the chain with a
    /// domain-separated KDF, records the secret for the owner (`TripleRatchet`)
    /// to drain via `take_pending_mix`, and retires that keypair.
    ///
    /// Why the oldest and not the newest: `MlKem::decapsulate` cannot tell you
    /// which keypair a ciphertext belongs to. FIPS 203 decapsulation
    /// implicit-rejects (`K̄ ← J(z‖c)`) rather than failing, so decapsulating a
    /// stale ciphertext against a replacement key returns `Ok` with a *junk*
    /// secret; that secret used to be mixed in silently and the two peers' root
    /// keys parted for good. Selection therefore has to come from ORDER, which
    /// is the one thing the wire still gives us: public keys go out in order and
    /// their ciphertexts come back in the same order.
    ///
    /// Returns an error if no keypair is retained (ciphertext received without a
    /// prior rekey step).
    pub fn process_ciphertext(&mut self, ct: &Ciphertext) -> Result<()> {
        let (_, sk) = self.keypairs.front().ok_or_else(|| {
            CryptoError::InvalidKey("no PQ keypair available to decapsulate ciphertext".into())
        })?;
        let shared_secret = MlKem::decapsulate(sk, ct)?;

        // Mix the decapsulated secret into the chain, then record it for the
        // root-key mix and retire the keypair it belonged to.
        self.mix_kem_secret(&shared_secret.0);
        self.record_pending_mix(shared_secret.0);
        self.pq_established = true;
        if let Some((_, mut used)) = self.keypairs.pop_front() {
            used.zeroize();
        }

        Ok(())
    }

    /// Peer side of the exchange: encapsulate against the public key received
    /// from the rekey owner, mix the shared secret into this chain, and return
    /// the ciphertext to send back to the owner.
    pub fn encapsulate_to(&mut self, pk: &PublicKey) -> Result<Ciphertext> {
        let (ct, shared_secret) = MlKem::encapsulate(pk)?;

        self.mix_kem_secret(&shared_secret.0);
        self.record_pending_mix(shared_secret.0);
        self.pq_established = true;

        Ok(ct)
    }

    /// Queue a completed-exchange secret for the root-key mix, tagged with the
    /// chain epoch it was mixed into.
    ///
    /// Appends in production order (epochs are monotone), so the queue is sorted
    /// by epoch and the drain order is the production order. At capacity the
    /// OLDEST pending secret is dropped and counted — a dropped mix means the two
    /// root keys diverge, so it must be observable rather than silent.
    fn record_pending_mix(&mut self, secret: [u8; 32]) {
        if self.pending_mixes.len() >= MAX_PENDING_MIXES {
            let mut dropped = self.pending_mixes.remove(0);
            dropped.zeroize();
            self.dropped_pending_mixes = self.dropped_pending_mixes.saturating_add(1);
        }
        self.pending_mixes.push(PendingMix {
            epoch: self.step_count,
            secret,
        });
    }

    /// Take the oldest pending PQ secret (set by `process_ciphertext` /
    /// `encapsulate_to`) so the owner can mix it into the root key.
    /// Cleared on read, oldest epoch first.
    ///
    /// Contract (weakened on purpose — Phase 5 item 3): the completed secrets are
    /// held in chain-epoch order and handed out in that order, so a caller that
    /// drains a boundary late still applies the SAME sequence of mixes as its
    /// peer. Correctness therefore no longer rests on both peers calling this at
    /// the same message boundary: a skew delays the mixes, it cannot reorder them
    /// and it cannot silently drop one (the capacity bound is counted — see
    /// [`Self::dropped_pending_mixes`]).
    pub fn take_pending_mix(&mut self) -> Option<[u8; 32]> {
        if self.pending_mixes.is_empty() {
            return None;
        }
        let front = self.pending_mixes.remove(0);
        Some(front.secret)
    }

    /// The chain epoch of the OLDEST pending mix, if one is waiting.
    ///
    /// The epoch tag is what makes the mix slot data-derived rather than
    /// call-derived: a consumer can state which boundary the pending secret
    /// belongs to instead of assuming the peer advanced in step.
    pub fn pending_mix_epoch(&self) -> Option<u64> {
        self.pending_mixes.first().map(|m| m.epoch)
    }

    /// How many completed-exchange secrets are waiting for drainage.
    pub fn pending_mix_count(&self) -> usize {
        self.pending_mixes.len()
    }

    /// Completed-exchange secrets dropped because the queue hit its capacity.
    ///
    /// Non-zero means the peers' root keys no longer carry the same mix sequence:
    /// PQ forward secrecy is broken for this session and it must not be claimed.
    pub fn dropped_pending_mixes(&self) -> u64 {
        self.dropped_pending_mixes
    }

    /// Whether an ML-KEM exchange secret has actually been mixed into the
    /// chain. `false` means the PQ leg has never run (no ciphertext was ever
    /// processed, no peer key encapsulated against), so callers must not
    /// claim PQ forward secrecy for this ratchet.
    pub fn pq_established(&self) -> bool {
        self.pq_established
    }

    /// Get current secret
    pub fn current_secret(&self) -> &[u8; 32] {
        &self.current_secret
    }

    /// Mix a KEM shared secret into the chain with domain separation.
    fn mix_kem_secret(&mut self, shared_secret: &[u8; 32]) {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&self.current_secret);
        input.extend_from_slice(shared_secret);
        let next = blake3::derive_key(KEM_MIX_DOMAIN, &input);
        input.zeroize();
        self.current_secret.zeroize();
        self.current_secret = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ratchet(interval: u64) -> SparsePqRatchet {
        SparsePqRatchet::new([7u8; 32], interval)
    }

    /// Step 4.3 defect A: a zero interval must be REFUSED, not silently turned into "PQ rekeying
    /// disabled". Before this, `new(_, 0)` clamped to `u64::MAX`, so a caller passing a zero from
    /// an unset config, a default, or a computed value lost post-quantum forward secrecy with no
    /// error and nothing visible at the call site.
    #[test]
    #[should_panic(expected = "rekey_interval must be non-zero")]
    fn test_zero_rekey_interval_is_refused() {
        let _ = SparsePqRatchet::new([7u8; 32], 0);
    }

    /// Disabling PQ rekeying is still possible, but only as a NAMED choice — so a diff that
    /// removes post-quantum forward secrecy shows up as `new_disabled`, not as a `0`.
    #[test]
    fn test_new_disabled_is_the_named_opt_out() {
        let _ = SparsePqRatchet::new_disabled([7u8; 32]);
    }

    #[test]
    fn test_step_advances_chain_secret() {
        // ATK-4-4: consecutive steps must derive different chain secrets
        // (previously `step()` did not advance the chain at all and the
        // secret stayed constant until an unrelated mix).
        let mut r = ratchet(100);
        let s0 = *r.current_secret();
        r.step().unwrap();
        let s1 = *r.current_secret();
        r.step().unwrap();
        let s2 = *r.current_secret();

        assert_ne!(s0, s1, "first step must advance the chain");
        assert_ne!(s1, s2, "consecutive steps must derive different secrets");
        assert_ne!(s0, s2);

        // Two ratchets stepped the same number of times stay in lockstep.
        let mut a = ratchet(100);
        let mut b = ratchet(100);
        a.step().unwrap();
        a.step().unwrap();
        b.step().unwrap();
        b.step().unwrap();
        assert_eq!(a.current_secret(), b.current_secret());
    }

    #[test]
    fn test_rekey_boundary_emits_fresh_public_keys() {
        let mut r = ratchet(2);
        assert!(r.step().unwrap().is_none());
        let pk1 = r.step().unwrap().expect("rekey at interval");
        assert!(r.step().unwrap().is_none());
        let pk2 = r.step().unwrap().expect("second rekey");

        // Fresh keypairs per rekey: serialized public keys must differ.
        assert_ne!(
            bincode::serialize(&pk1).unwrap(),
            bincode::serialize(&pk2).unwrap()
        );
    }

    #[test]
    fn test_pq_exchange_converges() {
        // Lockstep owners completing one ML-KEM exchange: the chain secrets
        // must converge after both sides mix the same shared secret.
        let mut owner = ratchet(1);
        let mut peer = ratchet(1);

        let pk = owner.step().unwrap().expect("rekey at interval 1");
        peer.step().unwrap(); // peer advances in lockstep

        let ct = peer.encapsulate_to(&pk).unwrap();
        owner.process_ciphertext(&ct).unwrap();

        assert_eq!(owner.current_secret(), peer.current_secret());
        assert!(owner.pq_established());
        assert!(peer.pq_established());

        // Both sides expose the same PQ secret for the root-key mix, once.
        let so = owner.take_pending_mix().unwrap();
        let sp = peer.take_pending_mix().unwrap();
        assert_eq!(so, sp);
        assert!(owner.take_pending_mix().is_none());
    }

    #[test]
    fn test_skipped_step_desynchronizes() {
        // Forward-secrecy smoke: if the peer skips a chain step, the mix
        // lands on a different chain state, the shared secrets diverge, and
        // key material from an old step cannot produce the new chain value.
        let mut owner = ratchet(1);
        let mut peer = ratchet(1);

        let pk = owner.step().unwrap().expect("rekey");
        let old_owner_secret = *owner.current_secret();

        // Peer does NOT step: it mixes into the initial chain state.
        let ct = peer.encapsulate_to(&pk).unwrap();
        owner.process_ciphertext(&ct).unwrap();

        assert_ne!(
            owner.current_secret(),
            peer.current_secret(),
            "skipping a chain step must desynchronize the ratchets"
        );

        // The pre-exchange (old-step) key material is not the new chain key.
        assert_ne!(&old_owner_secret, owner.current_secret());
        assert_ne!(&old_owner_secret, peer.current_secret());
    }

    /// Phase 5 item 3 — undrained secrets are carried, in chain-epoch order.
    ///
    /// Two exchanges complete on the peer before it drains. Both secrets must be
    /// handed out, oldest first, and they must be the SAME two values in the SAME
    /// order the owner applied — that is what makes the root-key mix sequence
    /// independent of the caller's drain timing. The single-slot `Option` this
    /// replaced returned only the second one and dropped the first with no error.
    #[test]
    fn test_undrained_mixes_are_carried_in_epoch_order() {
        let mut owner = ratchet(1);
        let mut peer = ratchet(1);

        // Exchange 1.
        let pk1 = owner.step().unwrap().expect("rekey 1"); // owner epoch 1
        let ct1 = peer.encapsulate_to(&pk1).unwrap(); // peer pending #1 @ epoch 0
        peer.step().unwrap(); // peer epoch 1 (no drain — the skew)
        owner.process_ciphertext(&ct1).unwrap(); // owner pending #1 @ epoch 1

        // Exchange 2, still undrained on the peer.
        let pk2 = owner.step().unwrap().expect("rekey 2"); // owner epoch 2
        let ct2 = peer.encapsulate_to(&pk2).unwrap(); // peer pending #2 @ epoch 1
        owner.process_ciphertext(&ct2).unwrap(); // owner pending #2 @ epoch 2

        assert_eq!(peer.pending_mix_count(), 2, "both secrets must be held");
        assert_eq!(
            peer.pending_mix_epoch(),
            Some(0),
            "the queue drains oldest epoch first"
        );
        assert_eq!(peer.dropped_pending_mixes(), 0);

        // Owner order: #1 then #2 (the same sequence the peer must produce).
        let so1 = owner.take_pending_mix().expect("owner #1");
        let so2 = owner.take_pending_mix().expect("owner #2");
        let sp1 = peer.take_pending_mix().expect("peer #1");
        let sp2 = peer.take_pending_mix().expect("peer #2");

        assert_eq!(sp1, so1, "the oldest secret must be drained first");
        assert_eq!(sp2, so2, "the second secret must survive the first");
        assert_ne!(so1, so2, "the two exchanges have distinct secrets");
        assert!(peer.take_pending_mix().is_none());
    }

    /// Phase 5 item 3 — the queue is bounded, and a drop is COUNTED, never silent.
    ///
    /// A drop means the two root keys no longer carry the same mix sequence, so
    /// it must be observable: the counter is the honest signal, and the value
    /// dropped is the OLDEST (so the surviving sequence stays a suffix of the
    /// produced one and preserves order).
    #[test]
    fn test_pending_queue_is_bounded_and_drops_are_counted() {
        let mut owner = ratchet(1);
        let mut peer = ratchet(1);
        let mut owner_secrets = Vec::new();

        for _ in 0..(MAX_PENDING_MIXES + 1) {
            let pk = owner.step().unwrap().expect("rekey");
            let ct = peer.encapsulate_to(&pk).unwrap(); // peer queues, never drains
            owner.process_ciphertext(&ct).unwrap();
            // The owner drains promptly, so only the peer's queue can overflow.
            owner_secrets.push(owner.take_pending_mix().expect("owner secret"));
        }

        assert_eq!(
            peer.pending_mix_count(),
            MAX_PENDING_MIXES,
            "the queue must stay bounded"
        );
        assert_eq!(
            peer.dropped_pending_mixes(),
            1,
            "an overflow must be counted, not silent"
        );
        assert_eq!(
            peer.take_pending_mix().unwrap(),
            owner_secrets[1],
            "the OLDEST pending secret is the one dropped"
        );
        assert_eq!(peer.dropped_pending_mixes(), 1);
    }

    #[test]
    fn test_process_ciphertext_requires_pending_keypair() {
        let mut r = ratchet(100);
        // Ciphertext generated against an unrelated keypair must be rejected
        // when no rekey keypair is pending.
        let (pk, _sk) = MlKem::keygen().unwrap();
        let (ct, _ss) = MlKem::encapsulate(&pk).unwrap();
        assert!(r.process_ciphertext(&ct).is_err());
    }

    /// THE defect this retention queue exists for: a ciphertext that comes back
    /// AFTER a later rekey boundary must be decapsulated against the keypair it
    /// was encapsulated to, not against the replacement.
    ///
    /// Before retention, `step` overwrote the only keypair slot, so the late
    /// ciphertext was decapsulated against the newer key — FIPS 203 implicit
    /// rejection returns a junk secret as `Ok`, the two chains parted, and the
    /// next message failed to decrypt. Measured on the chat wiring: 11th message
    /// at interval 3, zero packet loss.
    #[test]
    fn test_late_ciphertext_pairs_with_the_keypair_it_belongs_to() {
        let mut owner = ratchet(1);
        let mut peer = ratchet(1);

        // Two boundaries pass before the first answer arrives: the keypair for
        // pk1 is superseded by pk2's and must NOT be discarded with it.
        let pk1 = owner.step().unwrap().expect("rekey 1");
        peer.step().unwrap();
        let pk2 = owner.step().unwrap().expect("rekey 2");
        peer.step().unwrap();

        assert_eq!(
            owner.retained_keypair_count(),
            2,
            "both outstanding keypairs must be retained"
        );
        assert_eq!(
            owner.oldest_outstanding_rekey_key().map(|pk| pk.as_bytes()),
            Some(pk1.as_bytes()),
            "the oldest outstanding key is the one a returning ciphertext is for"
        );
        assert_eq!(owner.dropped_keypairs(), 0);

        // The answer to pk1 arrives while pk2 is the newest keypair.
        let ct1 = peer.encapsulate_to(&pk1).unwrap();
        owner.process_ciphertext(&ct1).unwrap();
        assert_eq!(
            owner.current_secret(),
            peer.current_secret(),
            "a ciphertext must be paired with the keypair it was made for, not the newest one"
        );
        assert_eq!(
            owner.retained_keypair_count(),
            1,
            "the pairing retires exactly the keypair it consumed"
        );

        // The next answer pairs with the keypair that follows it.
        let ct2 = peer.encapsulate_to(&pk2).unwrap();
        owner.process_ciphertext(&ct2).unwrap();
        assert_eq!(owner.current_secret(), peer.current_secret());
        assert_eq!(owner.retained_keypair_count(), 0);
        assert!(owner.pq_established());
    }

    /// Retention is bounded, and a keypair retired by the bound is COUNTED: it
    /// means an exchange this ratchet opened can no longer be completed, so the
    /// mix sequence is no longer symmetric with the peer's.
    #[test]
    fn test_keypair_retention_is_bounded_and_drops_are_counted() {
        let mut owner = ratchet(1);
        for i in 0..(MAX_RETAINED_KEYPAIRS + 1) {
            assert!(owner.step().unwrap().is_some(), "every step rekeys at 1");
            assert!(owner.retained_keypair_count() <= MAX_RETAINED_KEYPAIRS);
            assert_eq!(owner.dropped_keypairs(), u64::from(i >= MAX_RETAINED_KEYPAIRS));
        }
        assert_eq!(owner.retained_keypair_count(), MAX_RETAINED_KEYPAIRS);
        assert_eq!(owner.dropped_keypairs(), 1);
    }

    /// A rekey key that never reached the peer must be retired at the owner: no
    /// ciphertext can ever arrive for it, and leaving its keypair in the queue
    /// would shift every later ciphertext onto the wrong key.
    #[test]
    fn test_abandoned_rekey_key_is_retired_so_later_ciphertexts_still_pair() {
        let mut owner = ratchet(1);
        let mut peer = ratchet(1);

        let pk1 = owner.step().unwrap().expect("rekey 1");
        peer.step().unwrap();
        assert!(owner.abandon_rekey_key(&pk1), "the keypair must be retired");
        assert_eq!(owner.retained_keypair_count(), 0);
        assert_eq!(owner.abandoned_rekeys(), 1);
        assert!(
            !owner.abandon_rekey_key(&pk1),
            "retiring the same key twice must report nothing to do"
        );

        // The next exchange is unaffected: its ciphertext pairs with its key.
        let pk2 = owner.step().unwrap().expect("rekey 2");
        peer.step().expect("peer advances in lockstep");
        let ct2 = peer.encapsulate_to(&pk2).unwrap();
        owner.process_ciphertext(&ct2).unwrap();
        assert_eq!(owner.current_secret(), peer.current_secret());
    }
}
