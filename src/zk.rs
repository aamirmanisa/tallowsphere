//! Zero-knowledge range proofs (P6, `--features zk`).
//!
//! Bulletproofs (Bünz–Bootle–Boneh–Poelstra–Wuille, 2018) over the ristretto255
//! group: prove that a value committed under a Pedersen commitment lies in
//! `[0, 2^bits)` without revealing the value. No trusted setup — the generators
//! are derived deterministically from the group, which is why this is the right
//! first ZK primitive for an engine that must stay auditable.
//!
//! Feature-gated: the default build does not link curve25519 arithmetic it
//! never uses, and the language surface refuses by name when the feature is off.
//!
//! **Not constant-time-guaranteed by this wrapper.** The underlying arithmetic
//! is dalek's, whose variable-time operations are documented as such; do not
//! present these proofs as side-channel hardened.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// Domain separation for every transcript this module creates. Changing it
/// invalidates proofs made by an earlier build, which is the intent: a proof
/// must not be replayable into a different protocol.
const DOMAIN: &[u8] = b"tallow.zk.range.v1";

/// Result of a proof: the proof bytes and the commitment it is about, both hex.
#[derive(Debug)]
pub struct ProofOut {
    pub proof: String,
    pub commitment: String,
}

fn transcript() -> Transcript {
    Transcript::new(DOMAIN)
}

fn scalar_from_hex(hex: &str) -> Result<Scalar, String> {
    let bytes = crate::age::hex_decode(hex)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("blinding must be 32 bytes (64 hex chars), got {}", bytes.len()))?;
    Ok(Scalar::from_bytes_mod_order(arr))
}

/// Prove `value ∈ [0, 2^bits)` under a Pedersen commitment with the given blinding.
///
/// `blinding_hex` must be 64 hex characters. It is the caller's secret: reusing
/// it across proofs links them, so generate a fresh one per proof.
pub fn range_prove(value: u64, bits: u32, blinding_hex: &str) -> Result<ProofOut, String> {
    if !(1..=64).contains(&bits) {
        return Err(format!("bits must be 1..=64, got {bits}"));
    }
    if bits < 64 && value >= (1u64 << bits) {
        return Err(format!("value {value} does not fit in {bits} bits; a proof of a false statement is not a proof"));
    }
    let blinding = scalar_from_hex(blinding_hex)?;
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(bits as usize, 1);
    let (proof, commitment) = RangeProof::prove_single(&bp, &pc, &mut transcript(), value, &blinding, bits as usize)
        .map_err(|e| format!("proof generation failed: {e}"))?;
    Ok(ProofOut {
        proof: crate::age::hex_encode(&proof.to_bytes()),
        commitment: crate::age::hex_encode(commitment.as_bytes()),
    })
}

/// Verify a proof against its commitment. Returns `Ok(false)` for a well-formed
/// but wrong proof; `Err` only when the inputs cannot be parsed at all.
pub fn range_verify(proof_hex: &str, commitment_hex: &str, bits: u32) -> Result<bool, String> {
    if !(1..=64).contains(&bits) {
        return Err(format!("bits must be 1..=64, got {bits}"));
    }
    let proof_bytes = crate::age::hex_decode(proof_hex)?;
    let commitment_bytes = crate::age::hex_decode(commitment_hex)?;
    if commitment_bytes.len() != 32 {
        return Err(format!("commitment must be 32 bytes, got {}", commitment_bytes.len()));
    }
    let proof = RangeProof::from_bytes(&proof_bytes)
        .map_err(|e| format!("proof is not a valid bulletproof: {e}"))?;
    let commitment = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&commitment_bytes)
        .map_err(|_| "commitment is not 32 bytes".to_string())?;
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(bits as usize, 1);
    Ok(proof
        .verify_single(&bp, &pc, &mut transcript(), &commitment, bits as usize)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLIND: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    #[test]
    fn proves_and_verifies_a_true_statement() {
        let out = range_prove(1234, 32, BLIND).expect("prove");
        assert_eq!(out.proof.len() % 2, 0);
        assert!(range_verify(&out.proof, &out.commitment, 32).expect("verify"));
    }

    #[test]
    fn refuses_to_prove_a_false_statement() {
        let e = range_prove(70_000, 16, BLIND).unwrap_err();
        assert!(e.contains("does not fit"), "{e}");
    }

    #[test]
    fn wrong_bit_length_fails_verification() {
        let out = range_prove(1234, 32, BLIND).expect("prove");
        assert!(!range_verify(&out.proof, &out.commitment, 16).expect("verify"));
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let out = range_prove(1234, 32, BLIND).expect("prove");
        let mut bytes = crate::age::hex_decode(&out.proof).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let bad = crate::age::hex_encode(&bytes);
        match range_verify(&bad, &out.commitment, 32) {
            Ok(ok) => assert!(!ok, "a tampered proof must not verify"),
            Err(_) => {}, // also acceptable: it fails to parse
        }
    }

    #[test]
    fn a_different_commitment_does_not_verify() {
        let a = range_prove(1234, 32, BLIND).expect("prove a");
        let b = range_prove(4321, 32, BLIND).expect("prove b");
        assert!(!range_verify(&a.proof, &b.commitment, 32).expect("verify"));
    }
}
