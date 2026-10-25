//! age container: the Tallow surface must be a real age implementation, not a
//! lookalike. Round-trip and tamper behaviour always run; the interoperability
//! check against the reference `age(1)` binary runs when it is installed.

use std::process::Command;

fn tallow() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tallow"))
}

fn dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("tallow-age-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("tempdir");
    d
}

fn run_program(src: &str, name: &str) -> (bool, String, String) {
    let p = dir().join(name);
    std::fs::write(&p, src).expect("write program");
    let out = tallow()
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

fn lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

#[test]
fn encrypt_then_decrypt_round_trips_through_the_language() {
    let src = r#"fn main() {
    let kp = crypto.age_keygen()
    let ct = crypto.age_encrypt(kp.recipient, "68656c6c6f")
    let pt = crypto.age_decrypt(kp.identity, ct)
    print(kp.recipient)
    print(kp.identity)
    print(pt)
}
"#;
    let (ok, stdout, stderr) = run_program(src, "roundtrip.tl");
    assert!(ok, "run failed\n{stdout}\n{stderr}");
    let l = lines(&stdout);
    assert!(l[0].starts_with("age1"), "recipient must be age1…, got {}", l[0]);
    assert!(
        l[1].starts_with("AGE-SECRET-KEY-1"),
        "identity must be AGE-SECRET-KEY-1…, got {}",
        l[1]
    );
    assert_eq!(l[2], "68656c6c6f", "plaintext must round-trip");
}

#[test]
fn a_tampered_container_is_refused() {
    // Two steps on purpose. The earlier version did the tamper inside the .tl
    // program by replacing the last nibble with "0" — which is a no-op whenever
    // that nibble already IS "0" (1 in 16 runs), so the "tampered" container
    // was sometimes the original and the test asserted on something it had not
    // changed. The mutation now happens in Rust and is guaranteed to differ.
    let producer = r#"fn main() {
    let kp = crypto.age_keygen()
    let ct = crypto.age_encrypt(kp.recipient, "01")
    print(kp.identity)
    print(ct)
}
"#;
    let (ok, stdout, _) = run_program(producer, "tamper_produce.tl");
    assert!(ok, "producing the container must succeed");
    let l = lines(&stdout);
    let (identity, ct) = (l[0].clone(), l[1].clone());

    // Tamper the LAST nibble, not the middle. The container is a binary age
    // file hex-encoded, and the header's stanza body is base64 INSIDE it: a
    // character in the middle can land on the final character of a base64
    // quantum, whose low two bits the decoder discards. Flipping there changes
    // the text and not the decoded bytes, so the "tampered" container decrypts
    // perfectly and this test fails on a coin flip (~1 in 43). The last nibble
    // is the low half of the final Poly1305 tag byte — raw binary, no encoding
    // to absorb it — so the AEAD always rejects.
    let mut chars: Vec<char> = ct.chars().collect();
    let last = chars.len() - 1;
    let original = chars[last];
    chars[last] = if original == '0' { '1' } else { '0' };
    let tampered: String = chars.into_iter().collect();
    assert_ne!(tampered, ct, "the tamper must change the container");

    let consumer = format!(
        "fn main() {{\n    print(crypto.age_decrypt(\"{identity}\", \"{tampered}\"))\n}}\n"
    );
    let (ok, stdout, stderr) = run_program(&consumer, "tamper_decrypt.tl");
    assert!(!ok, "a tampered container must not decrypt; stdout={stdout}");
    assert!(
        stderr.contains("age_decrypt"),
        "the refusal must name the operation, got {stderr}"
    );
}

#[test]
fn the_reference_age_binary_decrypts_what_we_produce() {
    let age_bin = match Command::new("age").arg("--version").output() {
        Ok(o) if o.status.success() => "age",
        _ => {
            eprintln!("skipping: age(1) is not installed");
            return;
        }
    };

    // age-keygen writes the identity file age(1) expects.
    let id_path = dir().join("id.txt");
    let kg = Command::new("age-keygen")
        .arg("-o")
        .arg(&id_path)
        .output()
        .expect("age-keygen");
    assert!(kg.status.success(), "age-keygen failed: {kg:?}");

    let id_text = std::fs::read_to_string(&id_path).expect("identity file");
    let recipient = id_text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("public key line")
        .trim()
        .to_string();

    let pt_hex = "68656c6c6f2066726f6d2074616c6c6f77"; // "hello from tallow"
    let src = format!(
        "fn main() {{\n    print(crypto.age_encrypt(\"{recipient}\", \"{pt_hex}\"))\n}}\n"
    );
    let (ok, stdout, stderr) = run_program(&src, "interop.tl");
    assert!(ok, "encrypt failed\n{stdout}\n{stderr}");
    let ct_hex = lines(&stdout)[0].clone();

    let ct_bytes = hex_decode(&ct_hex);
    let ct_path = dir().join("ours.age");
    std::fs::write(&ct_path, &ct_bytes).expect("write ciphertext");

    let out = Command::new(age_bin)
        .arg("-d")
        .arg("-i")
        .arg(&id_path)
        .arg(&ct_path)
        .output()
        .expect("run age -d");
    assert!(
        out.status.success(),
        "age(1) could not decrypt our container: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hello from tallow",
        "the reference implementation must recover our plaintext"
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
