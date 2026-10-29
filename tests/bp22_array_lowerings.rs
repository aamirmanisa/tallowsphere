//! BP22 — the six array lowerings that computed the wrong value, measured on
//! both planes with VALUE assertions.
//!
//! The defect this file pins (measured at `5103ae6`): `zip`, `take`, `chunk`,
//! `enumerate`, `flat_map` and `unique` each had a native lowering that
//! returned a ONE-element array where the interpreter returned the full set,
//! because `infer_kind`/`expr_is_native_array` did not know those results were
//! arrays: `.len()` fell through to `strlen` over the count word.
//!
//! ```text
//! let n = [1, 2].zip([3, 4]).len()
//! --interpret        2
//! --require-native   1      <- strlen of the length prefix
//! ```
//!
//! The six were refused by name (BP21) rather than fixed. This target is the
//! gate for the fix: each method is run through the real binary on the
//! interpreter and on the native plane, and the assertion is on the VALUES
//! (the length and the elements), never on IR shape — IR-shape assertions are
//! exactly how the broken lowerings passed unit tests before BP21.

use std::path::PathBuf;
use std::process::Command;

use tallow::array_methods::lookup;

/// The binary cargo built for THIS test run: a stale on-disk binary cannot
/// testify about this tree.
fn tallow_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn exec(args: &[&str]) -> Out {
    let out = Command::new(tallow_bin())
        .args(args)
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
    let path = std::env::temp_dir().join(format!("tallow-bp22-{tag}-{}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
    path
}

fn run(program: &PathBuf, plane: &str) -> Out {
    exec(&["run", plane, program.to_str().expect("utf-8 path")])
}

/// One probe per fixed method: `expect` is the interpreter's answer, which the
/// native plane must reproduce byte for byte. Every probe prints the LENGTH of
/// the result and then elements read out of it — a lowering that produces the
/// right buffer but the wrong count fails, and so does one that produces the
/// right count with the wrong elements.
struct Probe {
    method: &'static str,
    src: &'static str,
    expect: &'static str,
}

static PROBES: &[Probe] = &[
    Probe {
        method: "zip",
        src: "fn main() {\n    let z = [10, 20].zip([30, 40])\n    print(z.len())\n    print(z[0][0])\n    print(z[0][1])\n    print(z[1][0])\n}\n",
        expect: "2\n10\n30\n20\n",
    },
    Probe {
        method: "take",
        src: "fn main() {\n    let t = [10, 20, 30].take(2)\n    print(t.len())\n    print(t[0])\n    print(t[1])\n}\n",
        expect: "2\n10\n20\n",
    },
    Probe {
        method: "chunk",
        src: "fn main() {\n    let c = [10, 20, 30].chunk(2)\n    print(c.len())\n    print(c[0][0])\n    print(c[0][1])\n    print(c[1][0])\n}\n",
        expect: "2\n10\n20\n30\n",
    },
    Probe {
        method: "enumerate",
        src: "fn main() {\n    let e = [10, 20].enumerate()\n    print(e.len())\n    print(e[0][0])\n    print(e[0][1])\n    print(e[1][0])\n}\n",
        expect: "2\n0\n10\n1\n",
    },
    Probe {
        method: "flat_map",
        src: "fn main() {\n    let f = [10, 20].flat_map({ x -> [x, x + 1] })\n    print(f.len())\n    print(f[0])\n    print(f[1])\n    print(f[3])\n}\n",
        expect: "4\n10\n11\n21\n",
    },
    Probe {
        method: "unique",
        src: "fn main() {\n    let u = [5, 5, 6].unique()\n    print(u.len())\n    print(u[0])\n    print(u[1])\n}\n",
        expect: "2\n5\n6\n",
    },
];

/// The gate: every one of the six plans the same values on both planes.
#[test]
fn six_lowerings_agree_on_both_planes() {
    for probe in PROBES {
        let path = write_program(probe.method, probe.src);
        let interp = run(&path, "--interpret");
        let native = run(&path, "--require-native");
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            interp.rc, 0,
            "[{}] interpreter failed:\n{}",
            probe.method, interp.stderr
        );
        assert_eq!(
            interp.stdout, probe.expect,
            "[{}] interpreter printed something other than the recorded answer",
            probe.method
        );
        assert_eq!(
            native.rc, 0,
            "[{}] native plane failed (it must not refuse a method the registry lowers):\n{}",
            probe.method, native.stderr
        );
        assert!(
            !native.stderr.contains("no lowering"),
            "[{}] native plane refused by name:\n{}",
            probe.method,
            native.stderr
        );
        assert!(
            !native.stderr.contains("native build unavailable"),
            "[{}] the native leg fell back to the interpreter:\n{}",
            probe.method,
            native.stderr
        );
        assert_eq!(
            native.stdout, probe.expect,
            "[{}] the planes disagree — the native lowering computes the wrong value",
            probe.method
        );
        assert_eq!(
            interp.stdout, native.stdout,
            "[{}] planes are not byte-identical",
            probe.method
        );
    }
}

/// A `.len()`-only chained call is the defect's original shape: the result of
/// one of the six must be recognised as an array by the call that follows it.
#[test]
fn chained_len_on_a_lowered_result_reads_the_count_slot() {
    let path = write_program(
        "chain",
        "fn main() {\n    print([1, 2].zip([3, 4]).len())\n    print([1, 2, 3].take(2).len())\n    print([1, 2, 3].chunk(2).len())\n    print([\"a\", \"b\"].enumerate().len())\n    print([[1], [2, 3]].flat_map({ x -> x }).len())\n    print([1, 1, 2].unique().len())\n}\n",
    );
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);
    let expect = "2\n2\n2\n2\n3\n2\n";
    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(interp.stdout, expect, "interpreter");
    assert_eq!(native.rc, 0, "{}", native.stderr);
    assert_eq!(native.stdout, expect, "native");
}

/// A lowered result can feed the next array method: the second call sees an
/// array receiver, so its registry gate applies and its count is right.
#[test]
fn lowered_results_compose() {
    let path = write_program(
        "compose",
        "fn main() {\n    let u = [1, 2, 3, 2].take(4).unique()\n    print(u.len())\n    print(u[2])\n}\n",
    );
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);
    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(interp.stdout, "3\n3\n", "interpreter");
    assert_eq!(native.rc, 0, "{}", native.stderr);
    assert_eq!(native.stdout, "3\n3\n", "native");
}

/// `unique` on strings: the interpreter compares VALUES, so two equal strings
/// interned at different addresses collapse. A slot-pointer comparison does
/// not, and would silently keep both.
#[test]
fn unique_compares_string_values_not_slots() {
    let path = write_program(
        "unique-strings",
        "fn main() {\n    let s = [\"a\", \"b\", \"a\"].unique()\n    print(s.len())\n    print(s[0])\n    print(s[1])\n}\n",
    );
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);
    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(interp.stdout, "2\na\nb\n", "interpreter");
    assert_eq!(native.rc, 0, "{}", native.stderr);
    assert_eq!(native.stdout, "2\na\nb\n", "native");
}

/// The registry rows the fix flips must say `native: true`; a row left false
/// is a capability the interpreter has and the native plane refuses.
#[test]
fn registry_marks_the_six_as_native() {
    for method in ["zip", "take", "chunk", "enumerate", "flat_map", "unique"] {
        let row = lookup(method).unwrap_or_else(|| panic!("{method} is a registry row"));
        assert!(
            row.native,
            "{method}: measured correct on both planes, so the registry must lower it"
        );
    }
}

/// `take(0)` and `take(n > len)` keep the interpreter's answers: an empty
/// array and the whole array. The select that chooses `min(n, len)` used to
/// write a negative count for a negative argument.
#[test]
fn take_clamps_to_the_interpreters_answers() {
    let path = write_program(
        "take-edges",
        "fn main() {\n    let z = [1, 2, 3].take(0)\n    print(z.len())\n    let a = [1, 2, 3].take(9)\n    print(a.len())\n    let n = [1, 2, 3].take(-1)\n    print(n.len())\n}\n",
    );
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);
    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(interp.stdout, "0\n3\n3\n", "interpreter");
    assert_eq!(native.rc, 0, "{}", native.stderr);
    assert_eq!(native.stdout, "0\n3\n3\n", "native");
}

/// `chunk(0)` is an error on the interpreter (`chunk size must be > 0`); the
/// native plane must fail loudly instead of dividing by zero.
#[test]
fn chunk_zero_is_a_named_error_on_both_planes() {
    let path = write_program(
        "chunk-zero",
        "fn main() {\n    let c = [1, 2].chunk(0)\n    print(c.len())\n}\n",
    );
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);
    assert_ne!(interp.rc, 0, "interpreter accepted chunk(0)");
    assert_ne!(native.rc, 0, "native plane accepted chunk(0)");
    assert!(
        native.stderr.contains("chunk size must be > 0"),
        "the native refusal must name the reason:\n{}",
        native.stderr
    );
}
