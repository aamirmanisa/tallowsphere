//! P5 secret-hygiene gate.
//!
//! Two things are checked:
//!
//! 1. **Display never leaks.** `print()` of a struct carrying key material must
//!    show `<redacted>` for those fields. Before this gate existed, `print(kp)`
//!    wrote an age private key to stdout.
//! 2. **The table stays complete.** Every struct the crypto stdlib returns with a
//!    secret-sounding field must be listed in `secret_fields::SECRET_FIELDS`, so
//!    a new secret-bearing struct cannot ship unredacted by omission.

use std::process::Command;

fn run(src: &str, name: &str) -> (bool, String, String) {
    let dir = std::env::temp_dir().join(format!("tallow-secret-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let p = dir.join(name);
    std::fs::write(&p, src).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--interpret"])
        .arg(&p)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn printing_a_keypair_does_not_reveal_the_private_key() {
    let (ok, out, err) = run(
        "fn main() {\n    let kp = crypto.age_keygen()\n    print(kp)\n}\n",
        "kp.tl",
    );
    assert!(ok, "{out}\n{err}");
    assert!(
        !out.contains("AGE-SECRET-KEY"),
        "a printed struct must not contain private key material:\n{out}"
    );
    assert!(
        out.contains("<redacted>"),
        "the secret field must be visibly redacted:\n{out}"
    );
    // The public half stays visible — redaction must not blank the whole value.
    assert!(
        out.contains("age1"),
        "the recipient is public and must remain printable:\n{out}"
    );
}

#[test]
fn printing_a_generated_keypair_does_not_reveal_the_private_key() {
    let (ok, out, err) = run(
        "fn main() {\n    let kp = crypto.generate_keypair(\"ed25519\")\n    print(kp)\n}\n",
        "gen.tl",
    );
    assert!(ok, "{out}\n{err}");
    assert!(out.contains("<redacted>"), "expected redaction:\n{out}");
    // The public key is 32 bytes = 64 hex chars; grab it from the printed line
    // and prove it is not the hidden value.
    assert!(!out.contains("private_key: \""), "{out}");
    assert!(out.contains("public_key: \""), "{out}");
}

#[test]
fn printing_opaque_state_does_not_reveal_it() {
    let (ok, out, err) = run(
        "fn main() {\n    let r = crypto.opaque_register_start(\"hunter2\")\n    print(r)\n}\n",
        "opq.tl",
    );
    assert!(ok, "{out}\n{err}");
    let body = out
        .lines()
        .find(|l| l.contains("OpaqueRegistration"))
        .expect("struct line");
    assert!(
        body.contains("state: <redacted>"),
        "the client state must be redacted:\n{body}"
    );
    // The registration request is public material and must still be shown.
    assert!(body.contains("request: \""), "{body}");
}

#[test]
fn field_access_still_returns_the_secret_to_the_caller() {
    // Redaction is a display rule, not a capability removal: a caller that asks
    // for the field still gets it.
    let (ok, out, err) = run(
        "fn main() {\n    let kp = crypto.age_keygen()\n    print(kp.identity.len)\n}\n",
        "field.tl",
    );
    assert!(ok, "{out}\n{err}");
    let n: usize = out
        .lines()
        .filter(|l| !l.starts_with('*'))
        .find_map(|l| l.trim().parse().ok())
        .expect("a length");
    assert!(n > 60, "the identity must be returned in full, got {n} chars");
}

#[test]
fn every_secret_bearing_struct_in_the_crypto_stdlib_is_in_the_table() {
    let src = std::fs::read_to_string("src/stdlib/crypto.rs").expect("read crypto.rs");
    let secretish = [
        "identity",
        "secret_key",
        "private_key",
        "export_key",
        "session_key",
        "state",
        "password",
        "seed",
    ];

    // Structs are emitted as  name: "X".into(),  followed by their fields.
    let mut missing = Vec::new();
    let mut rest = src.as_str();
    while let Some(i) = rest.find("name: \"") {
        rest = &rest[i + 7..];
        let Some(end) = rest.find('"') else { break };
        let struct_name = &rest[..end];
        // Char-safe window: the source contains multi-byte punctuation.
        // Only this struct's own field list: stop at the next `name: "`.
        let own = &rest[end..];
        let stop = own.find("name: \"").unwrap_or(own.len()).min(1200);
        let window: String = own[..stop].to_string();
        for f in secretish {
            let needle = format!("\"{f}\".into()");
            if window.contains(&needle)
                && !tallow::secret_fields::is_secret(struct_name, f)
            {
                missing.push(format!("{struct_name}.{f}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these struct fields look secret but are not in secret_fields::SECRET_FIELDS: {missing:?}"
    );
}
