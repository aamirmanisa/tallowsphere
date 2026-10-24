//! HPKE (RFC 9180) end-to-end through the language surface, plus the native
//! plane's documented refusal.
//!
//! The cryptographic proof lives in `src/hpke.rs` (the RFC Appendix A.1 vector,
//! asserted byte for byte). What these tests prove is the other half: that the
//! Tallow surface marshals into that implementation without changing a byte, and
//! that the compiled plane refuses by name instead of emitting a stub that
//! always "succeeds".

use std::process::Command;

fn tallow() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
}

const SUITE: &str = "DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM (RFC 9180 A.1)";
const PT_HEX: &str = "4265617574792069732074727574682c20747275746820626561757479";

fn rfc_program() -> String {
    format!(
        r#"fn main() {{
    print(crypto.hpke_suite())
    let pt = crypto.hpke_open(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        "4f6465206f6e2061204772656369616e2055726e",
        "436f756e742d30",
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
    )
    print(pt)
}}
"#
    )
}

fn write_prog(name: &str, src: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-hpke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let p = dir.join(name);
    std::fs::write(&p, src).expect("write program");
    p
}

fn run(path: &std::path::Path, extra: &[&str]) -> (bool, String, String) {
    let out = tallow()
        .arg("run")
        .args(extra)
        .arg(path)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn the_interpreter_opens_the_rfc_9180_vector_through_the_language() {
    let p = write_prog("rfc.tl", &rfc_program());
    let (ok, stdout, stderr) = run(&p, &["--interpret"]);
    assert!(ok, "run failed\n{stdout}\n{stderr}");
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .collect();
    assert_eq!(
        lines,
        vec![SUITE, PT_HEX],
        "the surface must produce the RFC plaintext unchanged"
    );
}

#[test]
fn seal_and_open_round_trip_through_the_language() {
    let src = r#"fn main() {
    let kp = crypto.hpke_generate_keypair()
    let sealed = crypto.hpke_seal(
        kp.public_key,
        "696e666f",      // "info"
        "616164",        // "aad"
        "736563726574"   // "secret"
    )
    let opened = crypto.hpke_open(
        kp.secret_key,
        sealed.enc,
        "696e666f",
        "616164",
        sealed.ciphertext
    )
    print(opened)
    print(sealed.enc.len)
    print(sealed.ciphertext.len)
}
"#;
    let p = write_prog("roundtrip.tl", src);
    let (ok, stdout, stderr) = run(&p, &["--interpret"]);
    assert!(ok, "run failed\n{stdout}\n{stderr}");
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .collect();
    assert_eq!(lines[0], "736563726574", "plaintext round-trips");
    assert_eq!(lines[1], "64", "enc is a 32-byte key in hex");
    assert_eq!(lines[2], "44", "(6-byte plaintext + 16-byte tag) x 2 hex chars");
}

#[test]
fn a_tampered_ciphertext_is_refused_not_silently_accepted() {
    let src = r#"fn main() {
    let kp = crypto.hpke_generate_keypair()
    let sealed = crypto.hpke_seal(kp.public_key, "", "", "00")
    let opened = crypto.hpke_open(kp.secret_key, sealed.enc, "", "", "ff")
    print(opened)
}
"#;
    let p = write_prog("tamper.tl", src);
    let (ok, stdout, stderr) = run(&p, &["--interpret"]);
    assert!(!ok, "a forged ciphertext must not open; stdout={stdout}");
    assert!(
        stderr.contains("hpke") && stderr.contains("authentication failed"),
        "the refusal must name the failure, got: {stderr}"
    );
}

#[test]
fn the_compiled_plane_refuses_by_name_instead_of_stubbing() {
    let p = write_prog("native.tl", &rfc_program());
    let out = tallow()
        .arg("run")
        .arg("--require-native")
        .arg(&p)
        .output()
        .expect("run tallow");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "--require-native must not fall back silently"
    );
    assert!(
        stderr.contains("crypto.hpke_suite") && stderr.contains("no native lowering"),
        "the refusal must name the function, got: {stderr}"
    );
}
