//! P6 — zero-knowledge range proofs through the public crate API.
//!
//! Compiles to zero tests in a default build; run with `--features zk`.
#![cfg(feature = "zk")]

const BLIND: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

#[test]
fn proof_round_trips_and_is_short() {
    let out = tallow::zk::range_prove(424242, 32, BLIND).expect("prove");
    assert!(
        out.proof.len() <= 1400,
        "a 32-bit range proof should be compact, got {} hex chars",
        out.proof.len()
    );
    assert!(tallow::zk::range_verify(&out.proof, &out.commitment, 32).expect("verify"));
}

#[test]
fn a_value_outside_the_range_cannot_be_proven() {
    // 2^16 = 65536; proving 65536 fits in 16 bits would be proving a false
    // statement, so the prover must refuse rather than emit a bad proof.
    assert!(tallow::zk::range_prove(65_536, 16, BLIND).is_err());
    assert!(tallow::zk::range_prove(65_535, 16, BLIND).is_ok());
}

#[test]
fn proofs_are_binding_to_their_commitment() {
    let a = tallow::zk::range_prove(10, 16, BLIND).expect("a");
    let b = tallow::zk::range_prove(11, 16, BLIND).expect("b");
    assert!(tallow::zk::range_verify(&a.proof, &a.commitment, 16).unwrap());
    assert!(!tallow::zk::range_verify(&a.proof, &b.commitment, 16).unwrap());
}

#[test]
fn malformed_inputs_are_errors_not_panics() {
    assert!(tallow::zk::range_verify("zz", "00", 16).is_err());
    assert!(tallow::zk::range_verify("00", "00", 16).is_err());
    assert!(tallow::zk::range_prove(1, 0, BLIND).is_err());
    assert!(tallow::zk::range_prove(1, 65, BLIND).is_err());
    assert!(tallow::zk::range_prove(1, 16, "00").is_err());
}
