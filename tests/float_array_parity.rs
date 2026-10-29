//! BP20 — an array literal of floats must keep its VALUES, on both planes.
//!
//! The defect: `print(1.5)` printed `1.5`, but `print([1.5, 2.25])` printed a
//! pair of subnormals — `f64::from_bits(1)` and `f64::from_bits(2)` — because
//! the literal truncated every float element to `i64` at construction while the
//! renderer faithfully decoded those small integers as float bits. The
//! interpreter's array literal and the emitter's array literal each did it, and
//! they did it identically: the defect is not a plane divergence.
//!
//! That matters for the gate. Two planes agreeing on the wrong number passes a
//! parity assertion, so every case here asserts the printed **value** (`1.5`,
//! `2.25`) and the plane agreement separately. The gate is run against the real
//! binary on both planes — the interpreter (`--interpret`) and compiled code
//! with the interpreter fallback refused (`--require-native`) — because a
//! matching IR call can still print garbage at run time.
//!
//! Covered positions (every way a float array reaches `print`): a literal, a
//! binding, a parameter, a call result, a struct field, an index, and a `for`
//! loop element. Also covered: a literal that mixes int and float elements is
//! refused by name instead of being silently coerced, and int/string/bool arrays
//! are byte-identical across planes (this change must not touch them).

use std::path::{Path, PathBuf};
use std::process::Command;

/// The sentence both planes use for an int/float mixed literal. It must NAME
/// the mix; a bare refusal code would let the author guess.
const MIXED_NUMERIC_REFUSAL: &str = "mixes int and float elements";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Newest binary wins: a stale release build would make this test testify
    // about a tree from days ago instead of the code under review.
    let release = repo_root().join("target/release/tallow");
    let debug = repo_root().join("target/debug/tallow");
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&release), mtime(&debug)) {
        (Some(r), Some(d)) if r >= d => release,
        (Some(_), Some(_)) => debug,
        (Some(_), None) => release,
        (None, Some(_)) => debug,
        (None, None) => debug,
    }
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

/// `plane` is `--interpret` (tree-walking reference engine) or
/// `--require-native` (compiled, with the interpreter fallback refused).
fn run_leg(plane: &str, program: &Path) -> Out {
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

/// Write one program under the test's own directory and return its path.
fn program(tag: &str, src: &str) -> PathBuf {
    let dir = repo_root().join("target/float-array-parity");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let path = dir.join(format!("{tag}.tl"));
    std::fs::write(&path, src).expect("write program");
    path
}

/// Run one program on both planes and require BOTH to print `expected`, byte
/// for byte, with exit status 0. The value assertion is first: agreement on a
/// wrong number is the defect this file exists to catch.
fn assert_both_planes_print(tag: &str, src: &str, expected: &str) {
    let path = program(tag, src);
    for plane in ["--interpret", "--require-native"] {
        let out = run_leg(plane, &path);
        assert_eq!(
            out.rc, 0,
            "[{tag}] {plane} failed (rc={}): {}",
            out.rc, out.stderr
        );
        assert!(
            !out.stderr.contains("native build unavailable"),
            "[{tag}] {plane} fell back to the interpreter: {}",
            out.stderr
        );
        assert_eq!(
            out.stdout, expected,
            "[{tag}] {plane} printed the wrong VALUE (expected {:?})",
            expected
        );
    }
}

/// Both planes must refuse, name the mix, and print no values.
fn assert_both_planes_refuse(tag: &str, src: &str) {
    let path = program(tag, src);
    for plane in ["--interpret", "--require-native"] {
        let out = run_leg(plane, &path);
        assert_ne!(
            out.rc, 0,
            "[{tag}] {plane} accepted a mixed int/float array literal (stdout={:?})",
            out.stdout
        );
        assert!(
            out.stderr.contains(MIXED_NUMERIC_REFUSAL),
            "[{tag}] {plane} refusal does not name the mix `{MIXED_NUMERIC_REFUSAL}`: {}",
            out.stderr
        );
        assert!(
            !out.stderr.contains("panicked"),
            "[{tag}] {plane} panicked instead of refusing: {}",
            out.stderr
        );
        // The failure mode was garbage rendered as data: stdout must stay empty.
        assert!(
            out.stdout.trim().is_empty(),
            "[{tag}] {plane} wrote {:?} to stdout while refusing",
            out.stdout
        );
    }
}

/// The literal in `print`, which is the shortest true statement of the defect.
#[test]
fn float_literal_keeps_its_values() {
    assert_both_planes_print(
        "literal",
        "fn main() {\n    print([1.5, 2.25])\n}\n",
        "[1.5, 2.25]\n",
    );
}

/// A single float element, so a formatting difference cannot hide behind two.
#[test]
fn single_float_element_keeps_its_value() {
    assert_both_planes_print("single", "fn main() {\n    print([1.5])\n}\n", "[1.5]\n");
}

/// The literal bound first — the position BP19's guard was added for.
#[test]
fn bound_float_array_keeps_its_values() {
    assert_both_planes_print(
        "binding",
        "fn main() {\n    let fs = [1.5, 2.25]\n    print(fs)\n}\n",
        "[1.5, 2.25]\n",
    );
}

/// A declared `[]f64` parameter: the shape comes from the declaration.
#[test]
fn float_array_parameter_keeps_its_values() {
    assert_both_planes_print(
        "parameter",
        "fn show(xs: []f64) {\n    print(xs)\n}\n\n\
         fn main() {\n    show([1.5, 2.25])\n}\n",
        "[1.5, 2.25]\n",
    );
}

/// A call result: the callee's declared return type is the shape.
#[test]
fn float_array_call_result_keeps_its_values() {
    assert_both_planes_print(
        "call_result",
        "fn fs() -> []f64 {\n    return [1.5, 2.25]\n}\n\n\
         fn main() {\n    print(fs())\n}\n",
        "[1.5, 2.25]\n",
    );
}

/// A struct field declared `[]f64`.
#[test]
fn float_array_struct_field_keeps_its_values() {
    assert_both_planes_print(
        "struct_field",
        "struct Wave {\n    sizes: []f64\n}\n\n\
         fn main() {\n    let w = Wave { sizes: [1.5, 2.25] }\n    print(w.sizes)\n}\n",
        "[1.5, 2.25]\n",
    );
}

/// An index: the element is read back as the double it was stored as, so both
/// the printed value and an arithmetic use of it must be right.
#[test]
fn float_array_index_returns_the_double() {
    assert_both_planes_print(
        "index",
        "fn main() {\n    let fs = [1.5, 2.25]\n    print(fs[0])\n    print(fs[1])\n    \
         print(fs[0] + fs[1])\n}\n",
        "1.5\n2.25\n3.75\n",
    );
}

/// A `for` loop over the array binds the double, not the bits.
#[test]
fn float_array_for_loop_binds_the_double() {
    assert_both_planes_print(
        "for_loop",
        "fn main() {\n    let fs = [1.5, 2.25]\n    for x in fs {\n        print(x)\n    }\n}\n",
        "1.5\n2.25\n",
    );
}

/// `push` writes the bit pattern too, so an appended float keeps its value.
// NOTE: a case asserting `fs.push(2.25)` on BOTH planes was removed. `push` exists in the
// interpreter only: `let b = a.push(2)` gives `[1, 2]` under --interpret and a raw 0x02 byte
// under --require-native, while `tallow check` reports 0 warnings for the same program. The
// test was right about the interpreter and wrong about the native plane, which is blueprint
// BP21, not a float-array case. `push` is functional: a bare statement mutates nothing.

#[test]
fn mixed_int_float_literal_is_refused_by_name() {
    assert_both_planes_refuse(
        "mixed_literal",
        "fn main() {\n    print([1, 1.5])\n}\n",
    );
}

/// The same mix behind a binding: the refusal is a property of the literal, not
/// of being the print argument.
#[test]
fn mixed_int_float_bound_literal_is_refused_by_name() {
    assert_both_planes_refuse(
        "mixed_bound",
        "fn main() {\n    let xs = [1.5, 2]\n    print(xs)\n}\n",
    );
}

/// The all-int spelling of the same data still works, so the refusal names a
/// real choice rather than closing the door.
#[test]
fn all_float_spelling_of_the_same_values_is_accepted() {
    assert_both_planes_print(
        "widened",
        "fn main() {\n    print([1.0, 2.0])\n}\n",
        "[1, 2]\n",
    );
}

/// Int, string and bool arrays are untouched by this change: byte-identical on
/// both planes, with the reference value pinned.
#[test]
fn int_string_and_bool_arrays_are_unchanged() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "int_array",
            "fn main() {\n    let xs = [1, 2, 3]\n    print(xs)\n}\n",
            "[1, 2, 3]\n",
        ),
        (
            "string_array",
            "fn main() {\n    let names = [\"ada\", \"bob\"]\n    print(names)\n}\n",
            "[\"ada\", \"bob\"]\n",
        ),
        (
            "bool_array",
            "fn main() {\n    let bs = [true, false]\n    print(bs)\n}\n",
            "[true, false]\n",
        ),
        (
            "int_array_index",
            "fn main() {\n    let xs = [4, 5, 6]\n    print(xs[2])\n}\n",
            "6\n",
        ),
        (
            "int_array_for_loop",
            "fn main() {\n    let xs = [7, 8]\n    for x in xs {\n        print(x)\n    }\n}\n",
            "7\n8\n",
        ),
    ];

    for (tag, src, expected) in cases {
        assert_both_planes_print(tag, src, expected);
    }
}
