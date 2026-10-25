//! Known-answer tests (P7): every published vector below is compared byte for
//! byte against what the language actually returns.
//!
//! Sources: FIPS 180-4 (SHA-2), RFC 6234 (SHA-2 test vectors), the BLAKE3
//! specification, RFC 5869 (HKDF-SHA256 test case 1), RFC 8032 §7.1 (Ed25519
//! test 1, the empty-message vector).
//!
//! These run through `tallow run --interpret` so the vector is checked against
//! the surface a program calls, not against a library in isolation.

use std::process::Command;

fn eval(expr: &str) -> String {
    let dir = std::env::temp_dir().join(format!("tallow-kat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    // Unique per call: the tests run in parallel and a shared path let one
    // test's program answer another's assertion (all five "passed" the same
    // wrong value until this was fixed).
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = dir.join(format!("kat-{n}-{:?}.tl", std::thread::current().id()));
    let src = format!("fn main() {{\n    print({expr})\n}}\n");
    std::fs::write(&p, src).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--interpret"])
        .arg(&p)
        .output()
        .expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "`{expr}` failed\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .last()
        .unwrap_or("")
        .to_string()
}

#[test]
fn sha256_matches_fips_180_4() {
    // "abc" — the canonical short vector.
    assert_eq!(
        eval(r#"crypto.hash("abc", "sha256")"#),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    assert_eq!(
        eval(r#"crypto.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "sha256")"#),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha384_and_sha512_match_fips_180_4() {
    assert_eq!(
        eval(r#"crypto.hash("abc", "sha384")"#),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7"
            .replace(' ', "")
    );
    assert_eq!(
        eval(r#"crypto.hash("abc", "sha512")"#),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            .replace(' ', "")
    );
}

#[test]
fn blake3_matches_the_specification() {
    // Empty input.
    assert_eq!(
        eval(r#"crypto.hash("", "blake3")"#),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    // "abc" — BLAKE3 of the three-byte message.
    assert_eq!(
        eval(r#"crypto.hash("abc", "blake3")"#),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
}

#[test]
fn hkdf_sha256_matches_rfc_5869_case_3() {
    // IKM 0b×22, empty salt, empty info, L = 42 (RFC 5869 A.3).
    //
    // Case 3, not case 1, because this API takes `info` as a UTF-8 label rather
    // than hex (salt and IKM are hex). That is a defensible design — info is
    // usually a context string — but it means a binary info field cannot be
    // expressed, so the vector that exercises one is not reproducible here.
    let ikm = "0b".repeat(22);
    let got = eval(&format!(r#"crypto.hkdf_derive("{ikm}", "", "", 42)"#));
    assert_eq!(
        got,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8"
            .replace(' ', "")
    );
}

#[test]
fn ed25519_matches_rfc_8032_test_1() {
    // The empty-message vector: deterministic signature from a fixed seed.
    let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let expected_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                        5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        .replace(' ', "");

    let sig = eval(&format!(r#"crypto.sign("", "{seed}")"#));
    assert_eq!(sig, expected_sig, "RFC 8032 test 1 signature");

    // Argument order is (data, signature, public key) — the error message and
    // the implementation agree; my first draft had them swapped.
    let ok = eval(&format!(
        r#"crypto.verify("", "{expected_sig}", "{expected_pk}")"#
    ));
    assert_eq!(ok, "true", "the RFC's own signature must verify");

    let bad = eval(&format!(
        r#"crypto.verify("x", "{expected_sig}", "{expected_pk}")"#
    ));
    assert_eq!(bad, "false", "a different message must not verify");
}
