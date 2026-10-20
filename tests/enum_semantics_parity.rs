//! Enums are integer-backed, and both planes must say so.
//!
//! The interpreter used to carry enums as tagged values: `Color.Red` printed
//! `Red`, `c == 0` raised "cannot apply Eq to Enum and int", and an integer match
//! arm silently fell through to `_`. The shipped `examples/enums.tl` therefore
//! printed `unknown unknown unknown ???` on the interpreter and `red green blue go`
//! natively. The discriminant is now part of the runtime value, and these tests
//! pin the agreement.

const PROGRAM: &str = r#"
enum Color { Red, Green, Blue }

fn name_of(c: Color) -> String {
    match c {
        0 -> "red"
        1 -> "green"
        2 -> "blue"
        _ -> "unknown"
    }
}

fn main() {
    print(Color.Red)
    print(Color.Green == 1)
    print(Color.Blue != 2)
    print(name_of(Color.Blue))
    print(name_of(Color.Red))
}
"#;

fn run(program: &std::path::Path, extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(extra)
        .arg(program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}

fn both_planes(program: &str, name: &str) -> (String, String) {
    let path = std::env::temp_dir().join(format!("tallow-{name}-{}.tl", std::process::id()));
    std::fs::write(&path, program).expect("write program");
    let interpreted = run(&path, &["--interpret"]);
    let native = run(&path, &["--require-native"]);
    let _ = std::fs::remove_file(&path);

    let interp_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let native_out = String::from_utf8_lossy(&native.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();

    assert!(
        interpreted.status.success(),
        "interpreter leg failed:\n{interp_out}\n{}",
        String::from_utf8_lossy(&interpreted.stderr)
    );
    assert!(
        native.status.success(),
        "native leg failed:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );
    (interp_out, native_out)
}

#[test]
fn enum_discriminant_is_the_same_value_on_both_planes() {
    let (interp_out, native_out) = both_planes(PROGRAM, "enum-parity");
    assert_eq!(interp_out, "0\ntrue\nfalse\nblue\nred\n", "interpreter output moved");
    assert_eq!(native_out, interp_out, "the planes disagree about enums");
}

#[test]
fn the_shipped_enum_example_runs_on_both_planes() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/enums.tl");
    let source = std::fs::read_to_string(&path).expect("read examples/enums.tl");
    let (interp_out, native_out) = both_planes(&source, "enum-example");
    assert_eq!(
        interp_out, "red\ngreen\nblue\ngo\n",
        "examples/enums.tl must print its variants, not `unknown`"
    );
    assert_eq!(native_out, interp_out);
}
