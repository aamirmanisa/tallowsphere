//! `crypto.generate_keypair` on the native plane.
//!
//! Two behaviours are asserted: the lowering exists (so `tallow build` can use
//! it), and printing a whole struct is refused with a message rather than
//! reading the record as a string — which is what it did before, emitting binary
//! garbage.

use std::process::Command;

fn write(src: &str, name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-kpnat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let p = dir.join(name);
    std::fs::write(&p, src).expect("write program");
    p
}

fn run(src: &str, name: &str, interpret: bool) -> (bool, Vec<String>, String) {
    let p = write(src, name);
    let mut c = Command::new(env!("CARGO_BIN_EXE_tallow"));
    c.arg("run");
    if interpret {
        c.arg("--interpret");
    } else {
        c.arg("--require-native");
    }
    let out = c.arg(&p).output().expect("run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lines = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*') && !l.starts_with("runtime archive"))
        .map(str::to_string)
        .collect();
    (
        out.status.success(),
        lines,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn the_native_plane_generates_a_usable_keypair() {
    let src = r#"fn main() {
    let kp = crypto.generate_keypair("ed25519")
    print(kp.algorithm)
    print(kp.public_key.len)
    print(kp.private_key.len)
}
"#;
    let (ok, out, err) = run(src, "kp.tl", false);
    assert!(ok, "--require-native must succeed: {out:?}\n{err}");
    assert!(
        !err.contains("no native lowering"),
        "the lowering must exist, not fall back: {err}"
    );
    assert_eq!(
        out,
        vec!["ed25519", "64", "64"],
        "32-byte keys, hex encoded"
    );
}

#[test]
fn the_two_planes_agree_on_the_shape() {
    let src = r#"fn main() {
    let kp = crypto.generate_keypair("x25519")
    print(kp.algorithm)
    print(kp.public_key.len)
}
"#;
    let (n_ok, n_out, n_err) = run(src, "kx_n.tl", false);
    let (i_ok, i_out, i_err) = run(src, "kx_i.tl", true);
    assert!(n_ok, "{n_err}");
    assert!(i_ok, "{i_err}");
    assert_eq!(n_out, i_out, "both planes must report the same shape");
    assert_eq!(n_out, vec!["x25519", "64"]);
}

#[test]
fn printing_a_whole_struct_is_refused_not_garbled() {
    let src = "fn main() {\n    let kp = crypto.generate_keypair(\"ed25519\")\n    print(kp)\n}\n";
    let (ok, out, err) = run(src, "kp_print.tl", false);
    assert!(
        !ok,
        "--require-native must not accept a whole-struct print; stdout={out:?}"
    );
    assert!(
        err.contains("print() of a struct"),
        "the refusal must name the construct: {err}"
    );
    assert!(
        err.contains("Print its fields"),
        "the refusal must name the fix: {err}"
    );
}

#[test]
fn the_interpreter_still_renders_the_struct_with_redaction() {
    let src = "fn main() {\n    let kp = crypto.generate_keypair(\"ed25519\")\n    print(kp)\n}\n";
    let (ok, out, err) = run(src, "kp_interp.tl", true);
    assert!(ok, "{out:?}\n{err}");
    let line = out.join("\n");
    assert!(line.contains("private_key: <redacted>"), "{line}");
    assert!(line.contains("public_key: \""), "{line}");
}
