//! age on both planes: the native lowering must exist and must interoperate
//! with the interpreter, not merely with itself.
//!
//! Note on ciphertext length: two containers for the same plaintext and the same
//! recipient legitimately differ in size, because the age crate inserts a random
//! GREASE stanza. This test therefore compares *behaviour* (decryptability and
//! cross-plane interop), never byte lengths — comparing lengths would produce a
//! flaky test and a false "parity defect".

use std::process::Command;

fn tallow() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
}

fn write(src: &str, name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-agenat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let p = dir.join(name);
    std::fs::write(&p, src).expect("write program");
    p
}

/// Run a program; returns (ok, last non-log line of stdout, stderr).
fn run(src: &str, name: &str, interpret: bool) -> (bool, String, String) {
    let p = write(src, name);
    let mut c = tallow();
    c.arg("run");
    if interpret {
        c.arg("--interpret");
    } else {
        c.arg("--require-native");
    }
    let out = c.arg(&p).output().expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let last = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .last()
        .unwrap_or("")
        .to_string();
    (
        out.status.success(),
        last,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn keypair() -> (String, String) {
    let dir = std::env::temp_dir().join(format!("tallow-agenat-k-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let id_path = dir.join(format!(
        "id-{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let kg = Command::new("age-keygen")
        .arg("-o")
        .arg(&id_path)
        .output()
        .expect("age-keygen (install age to run this test)");
    assert!(kg.status.success(), "age-keygen failed");
    let text = std::fs::read_to_string(&id_path).expect("identity file");
    let recipient = text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("public key")
        .trim()
        .to_string();
    let identity = text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .expect("secret key")
        .trim()
        .to_string();
    (recipient, identity)
}

#[test]
fn the_native_plane_really_lowers_age() {
    let (recipient, _identity) = keypair();
    let src = format!(
        "fn main() {{\n    let ct = crypto.age_encrypt(\"{recipient}\", \"68656c6c6f\")\n    print(ct.len)\n}}\n"
    );
    let (ok, out, err) = run(&src, "native_only.tl", false);
    assert!(
        ok,
        "--require-native must succeed for crypto.age_encrypt: {out}\n{err}"
    );
    assert!(
        !err.contains("no native lowering"),
        "the lowering must exist, not fall back: {err}"
    );
    let n: usize = out.trim().parse().expect("a length");
    assert!(n > 100, "a real container is at least 100 hex chars, got {n}");
}

#[test]
fn containers_cross_the_planes_both_ways() {
    let (recipient, identity) = keypair();

    let enc = format!(
        "fn main() {{\n    print(crypto.age_encrypt(\"{recipient}\", \"68656c6c6f\"))\n}}\n"
    );
    let dec = |ct: &str| {
        format!("fn main() {{\n    print(crypto.age_decrypt(\"{identity}\", \"{ct}\"))\n}}\n")
    };

    let (ok, ct_from_interp, err) = run(&enc, "enc_i.tl", true);
    assert!(ok, "{ct_from_interp}\n{err}");

    let (ok, ct_from_native, err) = run(&enc, "enc_n.tl", false);
    assert!(ok, "{ct_from_native}\n{err}");

    // Native container decrypted by the interpreter.
    let (ok, pt, err) = run(&dec(&ct_from_native), "dec_i.tl", true);
    assert!(ok, "interpreter could not open the native container: {err}");
    assert_eq!(pt, "68656c6c6f");

    // Interpreter container decrypted natively.
    let (ok, pt, err) = run(&dec(&ct_from_interp), "dec_n.tl", false);
    assert!(ok, "native could not open the interpreter container: {err}");
    assert_eq!(pt, "68656c6c6f");
}
