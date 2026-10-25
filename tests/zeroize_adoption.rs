//! Regression guard for the zeroization adoption in the new crypto modules.
//!
//! This is a **source-level** check, and it is labelled as such: it cannot prove
//! that memory was wiped (a dropped buffer cannot be inspected safely), only
//! that the wiping code is still there. The behavioural proof that these modules
//! still work lives in `age_container`, `opaque_flow` and the opaque unit tests.

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn age_wipes_the_plaintext_and_ciphertext_buffers() {
    let src = read("src/age.rs");
    assert!(
        src.contains("Zeroizing"),
        "src/age.rs must keep its secret buffers in Zeroizing — removing it \
         silently drops the wipe"
    );
    // The plaintext appears in both directions: encrypt input and decrypt output.
    let pt_uses = src.matches("Zeroizing").count();
    assert!(
        pt_uses >= 3,
        "expected plaintext, ciphertext and decrypt output to be wrapped, found {pt_uses}"
    );
}

#[test]
fn opaque_wipes_its_serialized_state_buffers() {
    let src = read("src/opaque.rs");
    assert!(
        src.contains("zeroize::Zeroize::zeroize"),
        "the state serialization path must wipe its buffer after hex-encoding"
    );
    assert!(
        src.contains("Zeroizing"),
        "the decoded state bytes must be held in a wiping container"
    );
}

#[test]
fn the_secret_field_table_is_not_empty() {
    let src = read("src/secret_fields.rs");
    for required in ["AgeKeypair", "KeyPair", "OpaqueLoginResult"] {
        assert!(
            src.contains(required),
            "secret_fields must still redact {required}"
        );
    }
}
