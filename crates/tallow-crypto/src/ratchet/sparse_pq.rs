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
//!   its public key returned for transmission to the peer;
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
use zeroize::Zeroize;

/// Domain separation for the per-step chain advance.
const STEP_DOMAIN: &str = "tallow.sparse_pq.ratchet.step";
/// Domain separation for mixing a KEM shared secret into the chain.
const KEM_MIX_DOMAIN: &str = "tallow.sparse_pq.ratchet.kem_mix";

/// Sparse PQ Ratchet state
///
/// Not Clone — ratchet state must never be duplicated.
#[derive(Serialize, Deserialize)]
pub struct SparsePqRatchet {
    current_secret: [u8; 32],
    /// ML-KEM keypair — intentionally skipped on serialize to avoid persisting
    /// secret key material. After deserialization, this is None and will be
    /// regenerated on the next `step()` call that triggers re-keying.
    #[serde(skip)]
    keypair: Option<(PublicKey, SecretKey)>,
    step_count: u64,
    rekey_interval: u64,
    /// Whether an ML-KEM exchange secret has actually been mixed into this
    /// chain (i.e. the PQ leg has run at least once).
    #[serde(default)]
    pq_established: bool,
    /// Fresh PQ secret awaiting drainage into the root key by the owner
    /// (`TripleRatchet`). Transient session state — not serialized.
    #[serde(skip)]
    pending_mix: Option<[u8; 32]>,
}

impl Zeroize for SparsePqRatchet {
    fn zeroize(&mut self) {
        self.current_secret.zeroize();
        self.keypair = None; // Clear the keypair
        self.step_count.zeroize();
        if let Some(ref mut mix) = self.pending_mix {
            mix.zeroize();
        }
        self.pending_mix = None;
        self.pq_established = false;
    }
}

impl Drop for SparsePqRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SparsePqRatchet {
    /// Create a new sparse PQ ratchet
    ///
    /// # Panics
    ///
    /// Never panics. A `rekey_interval` of 0 disables PQ rekeying.
    pub fn new(initial_secret: [u8; 32], rekey_interval: u64) -> Self {
        Self {
            current_secret: initial_secret,
            keypair: None,
            step_count: 0,
            // Clamp to prevent div-by-zero in is_multiple_of
            rekey_interval: if rekey_interval == 0 {
                u64::MAX
            } else {
                rekey_interval
            },
            pq_established: false,
            pending_mix: None,
        }
    }

    /// Perform a ratchet step
    ///
    /// Always advances the chain secret with a domain-separated KDF step
    /// (ATK-4-4: previously the chain did not advance at all). When the step
    /// count reaches `rekey_interval`, a fresh ML-KEM keypair is generated
    /// and its public key returned for transmission to the peer; the peer
    /// encapsulates to it and the ciphertext is consumed by
    /// `process_ciphertext`.
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
            self.keypair = Some((pk.clone(), sk));
            Ok(Some(pk))
        } else {
            Ok(None)
        }
    }

    /// Process received ML-KEM ciphertext and update secret
    ///
    /// Decapsulates against the pending rekey keypair, mixes the shared
    /// secret into the chain with a domain-separated KDF, and records the
    /// secret for the owner (`TripleRatchet`) to drain via `take_pending_mix`.
    ///
    /// Returns an error if no keypair is available (ciphertext received
    /// without a prior rekey step).
    pub fn process_ciphertext(&mut self, ct: &Ciphertext) -> Result<()> {
        let (_, sk) = self.keypair.as_ref().ok_or_else(|| {
            CryptoError::InvalidKey("no PQ keypair available to decapsulate ciphertext".into())
        })?;
        let shared_secret = MlKem::decapsulate(sk, ct)?;

        // Mix the decapsulated secret into the chain, then record it for the
        // root-key mix and clear the used keypair.
        self.mix_kem_secret(&shared_secret.0);
        self.pending_mix = Some(shared_secret.0);
        self.pq_established = true;
        self.keypair = None;

        Ok(())
    }

    /// Peer side of the exchange: encapsulate against the public key received
    /// from the rekey owner, mix the shared secret into this chain, and return
    /// the ciphertext to send back to the owner.
    pub fn encapsulate_to(&mut self, pk: &PublicKey) -> Result<Ciphertext> {
        let (ct, shared_secret) = MlKem::encapsulate(pk)?;

        self.mix_kem_secret(&shared_secret.0);
        self.pending_mix = Some(shared_secret.0);
        self.pq_established = true;

        Ok(ct)
    }

    /// Take the pending PQ secret (set by `process_ciphertext` /
    /// `encapsulate_to`) so the owner can mix it into the root key.
    /// Cleared on read.
    ///
    /// Contract: callers must drain this at the same message boundary on both
    /// sides — the root-key mix is only symmetric if both peers apply it to
    /// the same root-key state.
    pub fn take_pending_mix(&mut self) -> Option<[u8; 32]> {
        self.pending_mix.take()
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

    #[test]
    fn test_process_ciphertext_requires_pending_keypair() {
        let mut r = ratchet(100);
        // Ciphertext generated against an unrelated keypair must be rejected
        // when no rekey keypair is pending.
        let (pk, _sk) = MlKem::keygen().unwrap();
        let (ct, _ss) = MlKem::encapsulate(&pk).unwrap();
        assert!(r.process_ciphertext(&ct).is_err());
    }
}
