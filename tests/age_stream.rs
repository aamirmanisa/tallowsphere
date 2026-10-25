//! Resumable chunked transfer: a directory of ordinary age containers.
//!
//! What is proven here, in order of what could break:
//! * a multi-part transfer round-trips byte for byte;
//! * deleting a part and re-running encrypts only the missing parts (resume);
//! * a tampered part fails the transfer instead of yielding corrupt output;
//! * each part is a real age container — `age(1)` decrypts one on its own.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tallow-agestream-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).expect("tempdir");
    d
}

fn tallow_run(dir: &Path, body: &str, name: &str) -> (bool, Vec<String>, String) {
    let p = dir.join(name);
    let src = format!("fn main() {{\n{body}}}\n");
    std::fs::write(&p, src).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--interpret"])
        .arg(&p)
        .output()
        .expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    (
        out.status.success(),
        stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(str::to_string)
            .collect(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn keypair(dir: &Path) -> (String, String) {
    let id = dir.join("id.txt");
    let out = Command::new("age-keygen")
        .arg("-o")
        .arg(&id)
        .output()
        .expect("age-keygen (install age to run this test)");
    assert!(out.status.success(), "age-keygen failed");
    let text = std::fs::read_to_string(&id).expect("identity");
    let pk = text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("public key")
        .trim()
        .to_string();
    let sk = text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .expect("secret key")
        .trim()
        .to_string();
    (pk, sk)
}

fn source_file(dir: &Path, len: usize) -> PathBuf {
    let p = dir.join("src.bin");
    // Deterministic bytes: a repeating pattern catches ordering errors that
    // random data would hide behind "it differs anyway".
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    std::fs::write(&p, data).expect("write source");
    p
}

#[test]
fn a_multi_part_transfer_round_trips_and_resumes() {
    let dir = workdir();
    let (pk, sk) = keypair(&dir);
    let src = source_file(&dir, 2_500_000);
    let out_dir = dir.join("out");
    let dst = dir.join("dst.bin");

    let (ok, out, err) = tallow_run(
        &dir,
        &format!(
            "    let r = crypto.age_encrypt_dir(\"{pk}\", \"{}\", \"{}\", 1048576)\n    print(r.parts)\n    print(r.resumed_from)\n",
            src.display(),
            out_dir.display()
        ),
        "enc.tl",
    );
    assert!(ok, "{out:?}\n{err}");
    assert_eq!(out, vec!["3", "0"], "2.5 MiB at 1 MiB parts is 3 parts, none resumed");

    // Delete the last part: a resumed run must redo exactly that one.
    std::fs::remove_file(out_dir.join("part-00002.age")).expect("remove part");
    let (ok, out, err) = tallow_run(
        &dir,
        &format!(
            "    let r = crypto.age_encrypt_dir(\"{pk}\", \"{}\", \"{}\", 1048576)\n    print(r.resumed_from)\n    print(r.parts)\n",
            src.display(),
            out_dir.display()
        ),
        "resume.tl",
    );
    assert!(ok, "{out:?}\n{err}");
    assert_eq!(out, vec!["2", "3"], "resume must start at the first missing part");

    let (ok, out, err) = tallow_run(
        &dir,
        &format!(
            "    let d = crypto.age_decrypt_dir(\"{sk}\", \"{}\", \"{}\")\n    print(d.parts)\n    print(d.total_len)\n",
            out_dir.display(),
            dst.display()
        ),
        "dec.tl",
    );
    assert!(ok, "{out:?}\n{err}");
    assert_eq!(out, vec!["3", "2500000"]);

    let a = std::fs::read(&src).expect("src");
    let b = std::fs::read(&dst).expect("dst");
    assert_eq!(a, b, "the reassembled file must be byte-identical");
}

#[test]
fn a_tampered_part_fails_the_transfer() {
    let dir = workdir();
    let (pk, sk) = keypair(&dir);
    let src = source_file(&dir, 2_400_000);
    let out_dir = dir.join("out");
    let dst = dir.join("dst.bin");

    let (ok, _, err) = tallow_run(
        &dir,
        &format!(
            "    let r = crypto.age_encrypt_dir(\"{pk}\", \"{}\", \"{}\", 1048576)\n    print(r.parts)\n",
            src.display(),
            out_dir.display()
        ),
        "enc.tl",
    );
    assert!(ok, "{err}");

    let part = out_dir.join("part-00001.age");
    let mut bytes = std::fs::read(&part).expect("part");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&part, &bytes).expect("tamper");

    let (ok, out, err) = tallow_run(
        &dir,
        &format!(
            "    let d = crypto.age_decrypt_dir(\"{sk}\", \"{}\", \"{}\")\n    print(d.total_len)\n",
            out_dir.display(),
            dst.display()
        ),
        "dec.tl",
    );
    assert!(!ok, "a tampered part must fail the transfer; stdout={out:?}");
    assert!(
        err.contains("age_decrypt"),
        "the failure must name the decryption: {err}"
    );
}

#[test]
fn each_part_is_a_real_age_container() {
    let dir = workdir();
    let (pk, sk) = keypair(&dir);
    let src = source_file(&dir, 1_500_000);
    let out_dir = dir.join("out");
    let id_path = dir.join("id.txt");

    let (ok, _, err) = tallow_run(
        &dir,
        &format!(
            "    let r = crypto.age_encrypt_dir(\"{pk}\", \"{}\", \"{}\", 1048576)\n    print(r.parts)\n",
            src.display(),
            out_dir.display()
        ),
        "enc.tl",
    );
    assert!(ok, "{err}");

    // The reference implementation opens part 0 by itself and returns exactly
    // the first MiB of the source.
    let out = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(&id_path)
        .arg(out_dir.join("part-00000.age"))
        .output()
        .expect("run age");
    assert!(
        out.status.success(),
        "age(1) could not open part 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let whole = std::fs::read(&src).expect("src");
    assert_eq!(&out.stdout[..], &whole[..1_048_576]);
    let _ = sk;
}
