//! G07 — destructuring is a real pattern, on both planes.
//!
//! `let` and `for` lower a `Pattern` (src/ast.rs): `Ident`, `Wildcard`,
//! `Tuple(..)` and `Array { elems, rest }`. The native backend lowers a tuple
//! to one slot extract per element and an array pattern to index loads plus a
//! copy of the remainder; the interpreter binds the same shape out of the same
//! value.
//!
//! Every case asserts **byte-identical stdout** between `--interpret` and
//! `--require-native`. The mismatch case asserts that BOTH planes refuse the
//! program with the same named error (`E0152`) and produce no stdout, so a
//! shape the pattern cannot have never becomes data.
//!
//! Run: `cargo test --test pattern_destructure`

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The binary cargo built for this test run. `CARGO_BIN_EXE_tallow` is the debug
/// build of *this* tree, so a stale on-disk binary cannot testify here.
fn tallow_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn run(program: &Path, plane: &str) -> Out {
    let out = Command::new(tallow_bin())
        .arg("run")
        .arg(plane)
        .arg(program)
        .current_dir(repo_root())
        .output()
        .expect("spawn tallow");
    Out {
        rc: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn write_program(tag: &str, source: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tallow-g07-{tag}-{}.tl",
        std::process::id()
    ));
    std::fs::write(&path, source).expect("write program");
    path
}

/// Run both planes, require the same stdout, and return it.
fn parity(tag: &str, source: &str) -> String {
    let path = write_program(tag, source);
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);

    assert!(
        interp.rc == 0,
        "[{tag}] interpreter leg failed (rc {}):\n{}\n{}",
        interp.rc,
        interp.stdout,
        interp.stderr
    );
    assert!(
        native.rc == 0,
        "[{tag}] native leg failed (rc {}):\n{}\n{}",
        native.rc,
        native.stdout,
        native.stderr
    );
    assert!(
        !native.stderr.contains("native build unavailable"),
        "[{tag}] the native leg fell back to the interpreter:\n{}",
        native.stderr
    );
    assert_eq!(
        interp.stdout, native.stdout,
        "[{tag}] the planes disagree — interpreter {:?}, native {:?}",
        interp.stdout, native.stdout
    );
    interp.stdout
}

/// Both planes must REJECT the program with the same named error and no stdout.
fn refuses(tag: &str, source: &str, must_name: &str) -> String {
    let path = write_program(tag, source);
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);

    for (plane, out) in [("interpreter", &interp), ("native", &native)] {
        assert_ne!(out.rc, 0, "[{tag}] {plane} leg ran the program anyway");
        assert!(
            out.stdout.is_empty(),
            "[{tag}] {plane} leg produced stdout before refusing: {:?}",
            out.stdout
        );
        assert!(
            out.stderr.contains(must_name),
            "[{tag}] {plane} leg did not name {must_name}:\n{}",
            out.stderr
        );
    }
    assert!(
        !native.stderr.contains("native build unavailable"),
        "[{tag}] the native leg fell back to the interpreter:\n{}",
        native.stderr
    );
    interp.stderr
}

#[test]
fn nested_tuple_pattern_binds_each_position() {
    let out = parity(
        "nested-tuple",
        r#"
fn main() {
    let ((a, b), (c, d)) = [[1, 2], [3, 4]]
    print(a)
    print(b + c)
    print(d)
}
"#,
    );
    assert_eq!(out, "1\n5\n4\n");
}

#[test]
fn array_pattern_with_rest_binds_the_remainder() {
    let out = parity(
        "array-rest",
        r#"
fn main() {
    let [first, second, ..tail] = [10, 20, 30, 40]
    print(first)
    print(second)
    for n in tail {
        print(n)
    }
}
"#,
    );
    assert_eq!(out, "10\n20\n30\n40\n");
}

#[test]
fn array_pattern_rest_may_be_empty() {
    let out = parity(
        "array-rest-empty",
        r#"
fn main() {
    let [a, ..rest] = [7]
    print(a)
    for n in rest {
        print(n)
    }
    print("done")
}
"#,
    );
    assert_eq!(out, "7\ndone\n");
}

#[test]
fn wildcard_binds_nothing_and_discards_the_tail() {
    let out = parity(
        "wildcard",
        r#"
fn main() {
    let (_, second) = [11, 22]
    print(second)
    let [head, ..] = [5, 6, 7]
    print(head)
    for _ in [1, 2, 3] {
        print("tick")
    }
}
"#,
    );
    assert_eq!(out, "22\n5\ntick\ntick\ntick\n");
}

#[test]
fn for_loop_binds_an_array_pattern() {
    let out = parity(
        "for-array",
        r#"
fn main() {
    for [a, b] in [[1, 2], [3, 4]] {
        print(a + b)
    }
    for [head, ..tail] in [[9, 8, 7], [6, 5]] {
        print(head)
        for rest in tail {
            print(rest)
        }
    }
}
"#,
    );
    assert_eq!(out, "3\n7\n9\n8\n7\n6\n5\n");
}

#[test]
fn tuple_pattern_against_a_scalar_is_refused() {
    let stderr = refuses(
        "mismatch-scalar",
        r#"
fn main() {
    let (a, b) = 42
    print(a)
}
"#,
        "E0152",
    );
    assert!(
        stderr.contains("destructuring mismatch"),
        "the refusal did not name the rule:\n{stderr}"
    );
}

#[test]
fn tuple_arity_against_a_literal_sequence_is_refused() {
    let stderr = refuses(
        "mismatch-arity",
        r#"
fn main() {
    let (a, b) = [1, 2, 3]
    print(a)
}
"#,
        "E0152",
    );
    assert!(
        stderr.contains("tuple pattern cannot bind a 3-element sequence"),
        "the refusal did not name both arities:\n{stderr}"
    );
}
