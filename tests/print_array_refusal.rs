//! B4 — `print(<array>)` refuses by the VALUE's element shape, on both planes.
//!
//! The defect this pins (measured 2026-10-29, `native-print-divergence.md`): the
//! native `print` guard used to test the *syntax* of the print argument, not the
//! value's element kind. `print([[1,2],[3,4]])` was refused, but
//! `let xs = [[1,2],[3,4]]; print(xs)` compiled a call that rendered the inner
//! arrays' heap addresses through the integer element slot — exit 0, stdout
//! `[222585374741200, 222585374741232]`, which a reader parses as data. Same for
//! a mixed `let m = [1, "two"]`.
//!
//! The native array layout carries no per-element tags, so the element kind is a
//! property of the *value*, and every way an array reaches `print` — a binding, a
//! parameter, a struct field, a call result, an index — holds the same layout.
//! The guard now resolves the shape from the declared type (annotation,
//! parameter, callee signature, struct field declaration, container kind) or from
//! the shape recorded where the binding was created, and every non-scalar,
//! mixed or unknown-kind array takes the documented refusal path: the native
//! build is refused, `--require-native` exits non-zero, and stdout carries no
//! address.
//!
//! What must NOT change: a scalar-element array still renders identically on both
//! planes, byte for byte. That is asserted here by running the binary, not by
//! reading the emitted IR — a matching IR call can still print garbage at run
//! time, which is exactly how this bug survived its unit test.
//!
//! Two measured limits, recorded rather than silently excluded:
//!
//! * `float`-element arrays are NOT in the identical-planes list. They are
//!   scalar by the `ELEM_*` table but do not agree today: `let fs = [1.5, 2.25]`
//!   prints `[1.5, 2.25]` interpreted and a subnormal pair natively, because the
//!   array literal coerces each element to `i64` (the double's bits are lost)
//!   while the renderer decodes `ELEM_FLOAT` with `f64::from_bits`. That is a
//!   storage-layout defect of its own, not this guard's, and it predates this
//!   change; it is reported, not papered over.
//! * `print(<map>)` routing is untouched by this change and is not asserted here.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The refusal sentence the native backend uses for an array whose element kind
/// is not a scalar the renderer can decode.
const NON_SCALAR_REFUSAL: &str = "print() of an array with non-scalar or unknown-kind elements";
/// The refusal sentence for an array whose elements disagree on their kind.
const MIXED_REFUSAL: &str = "print() of a mixed-type array";

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
    let dir = repo_root().join("target/print-array-refusal");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let path = dir.join(format!("{tag}.tl"));
    std::fs::write(&path, src).expect("write program");
    path
}

/// The longest run of decimal digits in `text` — an address rendered as an
/// integer shows up as a run of 10+ digits, while every value these programs
/// print legitimately is one digit.
fn longest_digit_run(text: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for c in text.chars() {
        if c.is_ascii_digit() {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// A refusal assertion: the interpreter runs the program and produces the
/// reference output, the native plane refuses it with `needle` in stderr, and
/// neither plane's stdout carries a heap address.
fn assert_native_refuses(tag: &str, src: &str, needle: &str, interp_stdout: &str) {
    let path = program(tag, src);

    let interp = run_leg("--interpret", &path);
    assert_eq!(
        interp.rc, 0,
        "[{tag}] interpreter leg failed (rc={}): {}",
        interp.rc, interp.stderr
    );
    assert_eq!(
        interp.stdout, interp_stdout,
        "[{tag}] interpreter output drifted from the reference"
    );

    let native = run_leg("--require-native", &path);
    assert_ne!(
        native.rc, 0,
        "[{tag}] native plane accepted a print the native array layout cannot \
         render (rc={}, stdout={:?}, stderr={:?})",
        native.rc, native.stdout, native.stderr
    );
    assert!(
        native.stderr.contains(needle),
        "[{tag}] native refusal does not name the cause `{needle}`: {}",
        native.stderr
    );
    assert!(
        !native.stderr.contains("panicked"),
        "[{tag}] native leg panicked instead of refusing: {}",
        native.stderr
    );
    // The whole defect was addresses rendered as data: stdout must not carry one.
    for (plane, out) in [("interpreter", &interp), ("native", &native)] {
        let run = longest_digit_run(&out.stdout);
        assert!(
            run < 10,
            "[{tag}] {plane} stdout carries what looks like a heap address \
             (a {run}-digit run): {:?}",
            out.stdout
        );
    }
}

/// A `let`-bound array of arrays. Before the fix this printed the inner arrays'
/// heap addresses through the integer element slot, with exit 0.
#[test]
fn bound_nested_array_refuses_on_native() {
    assert_native_refuses(
        "bound_nested",
        "fn main() {\n    let xs = [[1, 2], [3, 4]]\n    print(xs)\n}\n",
        NON_SCALAR_REFUSAL,
        "[[1, 2], [3, 4]]\n",
    );
}

/// A `let`-bound array whose element kinds disagree.
#[test]
fn bound_mixed_array_refuses_on_native() {
    assert_native_refuses(
        "bound_mixed",
        "fn main() {\n    let m = [1, \"two\"]\n    print(m)\n}\n",
        MIXED_REFUSAL,
        "[1, \"two\"]\n",
    );
}

/// The array-literal case the guard already covered: kept so the value-based
/// path cannot regress the syntactic one.
#[test]
fn literal_array_of_arrays_still_refuses() {
    assert_native_refuses(
        "literal_nested",
        "fn main() {\n    print([[1, 2], [3, 4]])\n}\n",
        NON_SCALAR_REFUSAL,
        "[[1, 2], [3, 4]]\n",
    );
}

/// The same value reached through a parameter: the shape comes from the declared
/// `[][]int` annotation, not from the print argument.
#[test]
fn parameter_array_of_arrays_refuses_on_native() {
    assert_native_refuses(
        "param_nested",
        "fn show(xs: [][]int) {\n    print(xs)\n}\n\n\
         fn main() {\n    show([[1, 2], [3, 4]])\n}\n",
        NON_SCALAR_REFUSAL,
        "[[1, 2], [3, 4]]\n",
    );
}

/// An array of arrays bound from a call result — the callee's declared return
/// type is the value's shape.
#[test]
fn call_result_array_of_arrays_refuses_on_native() {
    assert_native_refuses(
        "call_result_nested",
        "fn rows() -> [][]int {\n    return [[1, 2], [3, 4]]\n}\n\n\
         fn main() {\n    print(rows())\n}\n",
        NON_SCALAR_REFUSAL,
        "[[1, 2], [3, 4]]\n",
    );
}

/// A struct field holding an array of arrays: the shape comes from the field's
/// declared type in the struct declaration.
#[test]
fn struct_field_array_of_arrays_refuses_on_native() {
    assert_native_refuses(
        "field_nested",
        "struct Grid {\n    rows: [][]int\n}\n\n\
         fn main() {\n    let g = Grid { rows: [[1, 2], [3, 4]] }\n    print(g.rows)\n}\n",
        NON_SCALAR_REFUSAL,
        "[[1, 2], [3, 4]]\n",
    );
}

/// An element of an array of arrays is itself an array: the slot holds a pointer
/// to an untagged inner array, so it is the same value class the literal guard
/// refuses.
#[test]
fn index_into_array_of_arrays_refuses_on_native() {
    assert_native_refuses(
        "index_nested",
        "fn main() {\n    let xs = [[1, 2], [3, 4]]\n    print(xs[0])\n}\n",
        NON_SCALAR_REFUSAL,
        "[1, 2]\n",
    );
}

/// A scalar-element array must print identically on both planes — the property
/// the guard exists to protect, verified by running the binary in every position
/// an array can reach `print` from.
#[test]
fn scalar_arrays_print_identically_on_both_planes() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "scalar_int",
            "fn main() {\n    let xs = [1, 2, 3]\n    print(xs)\n}\n",
            "[1, 2, 3]\n",
        ),
        (
            "scalar_str",
            "fn main() {\n    let names = [\"ada\", \"bob\"]\n    print(names)\n}\n",
            "[\"ada\", \"bob\"]\n",
        ),
        (
            "scalar_bool",
            "fn main() {\n    let bs = [true, false]\n    print(bs)\n}\n",
            "[true, false]\n",
        ),
        (
            "scalar_param_and_call_result",
            "fn names() -> []String {\n    return [\"ada\", \"bob\"]\n}\n\n\
             fn show(xs: []String) {\n    print(xs)\n}\n\n\
             fn main() {\n    show(names())\n}\n",
            "[\"ada\", \"bob\"]\n",
        ),
        (
            "scalar_field_int",
            "struct Wave {\n    sizes: []int\n}\n\n\
             fn main() {\n    let w = Wave { sizes: [1, 2, 3] }\n    print(w.sizes)\n}\n",
            "[1, 2, 3]\n",
        ),
        (
            "scalar_field_str",
            "struct Wave {\n    names: []String\n}\n\n\
             fn main() {\n    let w = Wave { names: [\"ada\", \"bob\"] }\n    print(w.names)\n}\n",
            "[\"ada\", \"bob\"]\n",
        ),
        (
            "scalar_index",
            "fn main() {\n    let xs = [1, 2, 3]\n    print(xs[1])\n}\n",
            "2\n",
        ),
    ];

    for (tag, src, expected) in cases {
        let path = program(tag, src);
        let interp = run_leg("--interpret", &path);
        assert_eq!(
            interp.rc, 0,
            "[{tag}] interpreter leg failed (rc={}): {}",
            interp.rc, interp.stderr
        );
        let native = run_leg("--require-native", &path);
        assert_eq!(
            native.rc, 0,
            "[{tag}] native plane refused a scalar-element array print, which the \
             renderer supports (rc={}, stderr={})",
            native.rc, native.stderr
        );
        assert!(
            !native.stderr.contains("native build unavailable"),
            "[{tag}] native leg fell back to the interpreter: {}",
            native.stderr
        );
        assert_eq!(
            native.stdout, interp.stdout,
            "[{tag}] the planes disagree on stdout"
        );
        assert_eq!(interp.stdout, *expected, "[{tag}] reference block drifted");
    }
}
