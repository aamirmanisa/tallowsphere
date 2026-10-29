//! BP21 — array method resolution, measured on both planes.
//!
//! The defect this file pins (measured at `8dafa20`):
//!
//! ```text
//! let a = [1]; let b = a.push(2)
//! --interpret        print(b) = [1, 2]        print(a) = [1]
//! --require-native   print(b) = raw 0x02      print(a) = [1]
//! tallow check       check passed: 1 items, 0 warning(s)
//! ```
//!
//! Three components disagreed about whether `push` exists, and `tallow check`
//! — the command a user runs before shipping — said the program was fine.
//!
//! This target drives the real binary (`CARGO_BIN_EXE_tallow`) on both planes
//! and asserts the contract in `docs/spec/ARRAY-METHODS.md`:
//!
//!   * every method the registry (`src/array_methods.rs`) declares runs on the
//!     interpreter — the registry is the interpreter's set, not a wish list;
//!   * a row the native plane lowers produces byte-identical stdout, and a row
//!     it does not lower is a NAMED refusal (never a byte, never a silent
//!     wrong answer);
//!   * an unknown method name on an `Array` is `E0625` from `tallow check` and
//!     from both planes, naming `Array` and the method;
//!   * a wrong argument count is a named error (`E0626`);
//!   * a method on an `Unknown` receiver is left alone.

use std::path::{Path, PathBuf};
use std::process::Command;

use tallow::array_methods::{ARRAY_METHODS, lookup, native_refusal};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The binary cargo built for this test run: a stale on-disk binary cannot
/// testify about this tree.
fn tallow_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
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
    let path = std::env::temp_dir().join(format!(
        "tallow-bp21-{tag}-{}.tl",
        std::process::id()
    ));
    std::fs::write(&path, source).expect("write program");
    path
}

fn run(program: &Path, plane: &str) -> Out {
    exec(&["run", plane, program.to_str().expect("utf-8 path")])
}

fn check(program: &Path) -> Out {
    exec(&["check", program.to_str().expect("utf-8 path")])
}

/// One probe per registry row: a program whose stdout is the observable answer
/// of exactly one array method. `expect` is what the interpreter must print.
struct Probe {
    method: &'static str,
    src: &'static str,
    expect: &'static str,
}

/// Every row of the registry is probed here, and every probe names a row
/// (`probes_and_registry_agree_on_the_method_set`).
static PROBES: &[Probe] = &[
    Probe {
        method: "push",
        src: "fn main() {\n    let a = [1]\n    let b = a.push(2)\n    print(b)\n    print(a)\n}\n",
        expect: "[1, 2]\n[1]\n",
    },
    Probe {
        method: "len",
        src: "fn main() {\n    let a = [10, 20, 30]\n    print(a.len())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "first",
        src: "fn main() {\n    let a = [10, 20, 30]\n    print(a.first())\n}\n",
        expect: "10\n",
    },
    Probe {
        method: "last",
        src: "fn main() {\n    let a = [10, 20, 30]\n    print(a.last())\n}\n",
        expect: "30\n",
    },
    Probe {
        method: "sum",
        src: "fn main() {\n    let a = [1, 2, 3]\n    print(a.sum())\n}\n",
        expect: "6\n",
    },
    Probe {
        method: "reverse",
        src: "fn main() {\n    let r = [1, 2, 3].reverse()\n    print(r.first())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "join",
        src: "fn main() {\n    let a = [1, 2, 3]\n    print(a.join(\"-\"))\n}\n",
        expect: "1-2-3\n",
    },
    Probe {
        method: "is_empty",
        src: "fn main() {\n    let a = [1]\n    print(a.is_empty())\n}\n",
        expect: "false\n",
    },
    Probe {
        method: "contains",
        src: "fn main() {\n    let a = [1, 2, 3]\n    print(a.contains(2))\n}\n",
        expect: "true\n",
    },
    Probe {
        method: "index_of",
        src: "fn main() {\n    let a = [1, 2, 3]\n    print(a.index_of(3))\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "count",
        src: "fn main() {\n    let a = [1, 2, 3]\n    print(a.count())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "to_array",
        src: "fn main() {\n    print([1, 2].to_array().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "to_string",
        src: "fn main() {\n    let a = [1, 2]\n    print(a.to_string())\n}\n",
        expect: "[1, 2]\n",
    },
    Probe {
        method: "to_json",
        src: "fn main() {\n    let a = [1, 2]\n    print(a.to_json())\n}\n",
        expect: "[1,2]\n",
    },
    Probe {
        method: "map",
        src: "fn main() {\n    let m = [1, 2, 3].map({ x -> x * 2 })\n    print(m.len())\n    print(m.last())\n}\n",
        expect: "3\n6\n",
    },
    Probe {
        method: "filter",
        src: "fn main() {\n    let f = [1, 2, 3].filter({ x -> x > 1 })\n    print(f.len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "each",
        src: "fn main() {\n    [1, 2].each({ x -> print(x) })\n}\n",
        expect: "1\n2\n",
    },
    Probe {
        method: "each_ok",
        src: "fn main() {\n    [Ok(1), Err(\"x\")].each_ok({ x -> print(x) })\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "flat_map",
        src: "fn main() {\n    let f = [[1], [2, 3]].flat_map({ x -> x })\n    print(f.len())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "flatten",
        src: "fn main() {\n    let f = [[1], [2, 3]].flatten()\n    print(f.len())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "unique",
        src: "fn main() {\n    print([1, 1, 2].unique().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "to_set",
        src: "fn main() {\n    print([1, 1, 2].to_set().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "distinct",
        src: "fn main() {\n    print([1, 1, 2].distinct().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "union",
        src: "fn main() {\n    print([1, 2].union([2, 3]).len())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "intersection",
        src: "fn main() {\n    print([1, 2].intersection([2, 3]).len())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "difference",
        src: "fn main() {\n    print([1, 2].difference([2, 3]).len())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "symmetric_difference",
        src: "fn main() {\n    print([1, 2].symmetric_difference([2, 3]).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "is_subset",
        src: "fn main() {\n    print([1, 2].is_subset([1, 2, 3]))\n}\n",
        expect: "true\n",
    },
    Probe {
        method: "concat",
        src: "fn main() {\n    print([1, 2].concat([3]).len())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "zip",
        src: "fn main() {\n    print([1, 2].zip([3, 4]).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "enumerate",
        src: "fn main() {\n    print([\"a\", \"b\"].enumerate().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "take",
        src: "fn main() {\n    print([1, 2, 3].take(2).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "skip",
        src: "fn main() {\n    print([1, 2, 3].skip(2).len())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "slice",
        src: "fn main() {\n    print([1, 2, 3].slice(1, 2).len())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "sort",
        src: "fn main() {\n    print([3, 1, 2].sort().first())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "sort_by",
        // The interpreter's `sort_by` takes a KEY EXTRACTOR, not a comparator:
        // the native arm calls the closure with two arguments, which is a
        // different contract for the same name, so the row refuses natively.
        src: "fn main() {\n    print([3, 1].sort_by({ x -> x }).first())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "min",
        src: "fn main() {\n    print([3, 1, 2].min())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "max",
        src: "fn main() {\n    print([3, 1, 2].max())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "min_by",
        src: "fn main() {\n    print([3, 1, 2].min_by({ x -> x }))\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "max_by",
        src: "fn main() {\n    print([3, 1, 2].max_by({ x -> x }))\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "group_by",
        src: "fn main() {\n    print([1, 2].group_by({ x -> x }).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "find",
        src: "fn main() {\n    print([1, 2, 3].find({ x -> x > 1 }))\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "find_index",
        src: "fn main() {\n    print([1, 2, 3].find_index({ x -> x > 1 }))\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "any",
        src: "fn main() {\n    print([1, 2, 3].any({ x -> x > 2 }))\n}\n",
        expect: "true\n",
    },
    Probe {
        method: "all",
        src: "fn main() {\n    print([1, 2, 3].all({ x -> x > 0 }))\n}\n",
        expect: "true\n",
    },
    Probe {
        method: "reduce",
        src: "fn main() {\n    print([1, 2, 3].reduce(0, { acc, x -> acc + x }))\n}\n",
        expect: "6\n",
    },
    Probe {
        method: "chunk",
        src: "fn main() {\n    print([1, 2, 3].chunk(2).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "chunks",
        src: "fn main() {\n    print([1, 2, 3].chunks(2).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "window",
        src: "fn main() {\n    print([1, 2, 3].window(2).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "windows",
        src: "fn main() {\n    print([1, 2, 3].windows(2).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "pop",
        src: "fn main() {\n    print([1, 2, 3].pop())\n}\n",
        expect: "3\n",
    },
    Probe {
        method: "collect_ok",
        src: "fn main() {\n    let a = [1, 2]\n    print(a.collect_ok().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "filter_ok",
        src: "fn main() {\n    print([Ok(1), Err(\"x\")].filter_ok().len())\n}\n",
        expect: "1\n",
    },
    Probe {
        method: "partition_result",
        src: "fn main() {\n    print([Ok(1), Err(\"x\")].partition_result().len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "parallel_map",
        src: "fn main() {\n    print([1, 2].parallel_map({ x -> x * 2 }).len())\n}\n",
        expect: "2\n",
    },
    Probe {
        method: "anonymize",
        src: "struct Rec {\n    a: i64\n}\n\nfn main() {\n    let rows = [Rec { a: 1 }, Rec { a: 2 }, Rec { a: 3 }]\n    print(rows.anonymize(2).len())\n}\n",
        expect: "3\n",
    },
];

#[test]
fn probes_and_registry_agree_on_the_method_set() {
    for probe in PROBES {
        assert!(
            lookup(probe.method).is_some(),
            "probe `{}` names no registry row",
            probe.method
        );
    }
    for row in ARRAY_METHODS {
        assert!(
            PROBES.iter().any(|p| p.method == row.name),
            "registry row `{}` has no probe — an unmeasured row is a wish",
            row.name
        );
    }
}

/// The registry is the interpreter's set: every declared row must execute.
#[test]
fn every_registry_method_runs_on_the_interpreter() {
    for probe in PROBES {
        let path = write_program(&format!("interp-{}", probe.method), probe.src);
        let out = run(&path, "--interpret");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            out.rc, 0,
            "[{}] the interpreter refused a method the registry declares:\n{}\n{}",
            probe.method, out.stdout, out.stderr
        );
        assert_eq!(
            out.stdout, probe.expect,
            "[{}] the interpreter printed something other than the recorded answer",
            probe.method
        );
        assert!(
            !out.stderr.contains("unknown method"),
            "[{}] the interpreter has no such method — the registry row is a defect:\n{}",
            probe.method,
            out.stderr
        );
    }
}

/// Both directions of rule 5, measured: a lowered row matches byte for byte, a
/// row with no lowering refuses **by name** and produces no output at all.
#[test]
fn registry_native_flags_match_the_native_plane() {
    for probe in PROBES {
        let row = lookup(probe.method).expect("probe names a registry row");
        let path = write_program(&format!("native-{}", probe.method), probe.src);
        let native = run(&path, "--require-native");
        let _ = std::fs::remove_file(&path);
        if row.native {
            assert_eq!(
                native.rc, 0,
                "[{}] the native plane refused a row the registry says it lowers:\n{}",
                probe.method, native.stderr
            );
            assert!(
                !native.stderr.contains("native build unavailable"),
                "[{}] the native leg fell back to the interpreter:\n{}",
                probe.method, native.stderr
            );
            assert_eq!(
                native.stdout, probe.expect,
                "[{}] the planes disagree — the registry's `native` flag is wrong",
                probe.method
            );
        } else {
            assert_ne!(
                native.rc, 0,
                "[{}] the native plane ran a row the registry says it cannot lower:\n{}",
                probe.method, native.stdout
            );
            assert!(
                native.stdout.is_empty(),
                "[{}] the native plane produced output before refusing: {:?}",
                probe.method,
                native.stdout
            );
            assert!(
                native.stderr.contains(&native_refusal(probe.method)),
                "[{}] the refusal must name the method and the way out:\n{}",
                probe.method,
                native.stderr
            );
        }
    }
}

/// The measured defect: `let b = a.push(2)`.
#[test]
fn push_returns_a_new_array_on_the_interpreter() {
    let path = write_program(
        "push-bound",
        "fn main() {\n    let a = [1]\n    let b = a.push(2)\n    print(b)\n    print(a)\n}\n",
    );
    let interp = run(&path, "--interpret");
    let _ = std::fs::remove_file(&path);
    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(
        interp.stdout, "[1, 2]\n[1]\n",
        "push is FUNCTIONAL: it returns a new array and leaves the receiver alone"
    );
}

/// `a.push(2)` bare: the result is discarded, so nothing changes — on both
/// planes, and the native plane says so instead of running something.
#[test]
fn bare_push_mutates_nothing() {
    let path = write_program(
        "push-bare",
        "fn main() {\n    let a = [1]\n    a.push(2)\n    print(a.len())\n    print(a.first())\n}\n",
    );
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);

    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(
        interp.stdout, "1\n1\n",
        "a bare `a.push(2)` must mutate nothing on the interpreter"
    );

    assert_ne!(native.rc, 0, "the native plane must refuse Array.push");
    assert!(
        native.stdout.is_empty(),
        "a refused build cannot mutate anything, and must not print: {:?}",
        native.stdout
    );
    assert!(
        native.stderr.contains(&native_refusal("push")),
        "{}",
        native.stderr
    );
}

/// No `--interpret` fallback hides the refusal: `--require-native` is fatal.
#[test]
fn native_refusal_is_fatal_under_require_native() {
    let path = write_program(
        "push-require-native",
        "fn main() {\n    let b = [1].push(2)\n    print(b.first())\n}\n",
    );
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);
    assert_ne!(native.rc, 0);
    assert!(native.stdout.is_empty(), "{:?}", native.stdout);
    assert!(
        native.stderr.contains(
            "the native backend has no lowering for Array.push; run with --interpret"
        ),
        "the refusal must be the documented sentence:\n{}",
        native.stderr
    );
    assert!(
        native.stderr.contains("--require-native refuses the interpreter fallback"),
        "a refused build under --require-native must not silently fall back:\n{}",
        native.stderr
    );
}

/// The lowered methods the contract names, on both planes.
#[test]
fn lowered_methods_agree_on_both_planes() {
    for (tag, src, expect) in [
        (
            "len",
            "fn main() {\n    let a = [10, 20, 30]\n    print(a.len())\n}\n",
            "3\n",
        ),
        (
            "first",
            "fn main() {\n    let a = [10, 20, 30]\n    print(a.first())\n}\n",
            "10\n",
        ),
        (
            "last",
            "fn main() {\n    let a = [10, 20, 30]\n    print(a.last())\n}\n",
            "30\n",
        ),
    ] {
        let path = write_program(&format!("lowered-{tag}"), src);
        let interp = run(&path, "--interpret");
        let native = run(&path, "--require-native");
        let _ = std::fs::remove_file(&path);
        assert_eq!(interp.rc, 0, "[{tag}] {}", interp.stderr);
        assert_eq!(native.rc, 0, "[{tag}] {}", native.stderr);
        assert_eq!(interp.stdout, expect, "[{tag}] interpreter");
        assert_eq!(native.stdout, expect, "[{tag}] native");
        assert_eq!(
            interp.stdout, native.stdout,
            "[{tag}] the planes disagree"
        );
    }
}

/// Rule 4: an unknown method name on a known receiver is `E0625` at check time,
/// on both planes, naming the type and the method.
#[test]
fn unknown_array_method_is_e0625_everywhere() {
    let path = write_program(
        "unknown",
        "fn main() {\n    let a = [1, 2]\n    a.frobnicate()\n}\n",
    );
    let checked = check(&path);
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);

    for (label, out) in [
        ("tallow check", &checked),
        ("--interpret", &interp),
        ("--require-native", &native),
    ] {
        assert_ne!(out.rc, 0, "[{label}] the program was accepted");
        assert!(
            out.stdout.is_empty(),
            "[{label}] produced stdout before refusing: {:?}",
            out.stdout
        );
        assert!(
            out.stderr.contains("E0625"),
            "[{label}] must name E0625:\n{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("Array"),
            "[{label}] must name the receiver type:\n{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("frobnicate"),
            "[{label}] must name the method:\n{}",
            out.stderr
        );
    }
}

/// Rule 3: a wrong argument count is a named error, not a runtime surprise.
#[test]
fn wrong_array_method_arity_is_a_named_error() {
    let path = write_program(
        "arity",
        "fn main() {\n    let a = [1]\n    let b = a.push(1, 2)\n    print(b)\n}\n",
    );
    let checked = check(&path);
    let interp = run(&path, "--interpret");
    let native = run(&path, "--require-native");
    let _ = std::fs::remove_file(&path);

    for (label, out) in [
        ("tallow check", &checked),
        ("--interpret", &interp),
        ("--require-native", &native),
    ] {
        assert_ne!(out.rc, 0, "[{label}] `a.push(1, 2)` was accepted");
        assert!(
            out.stderr.contains("E0626"),
            "[{label}] must name the arity error:\n{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("push") && out.stderr.contains("Array"),
            "[{label}] must name the method and the receiver:\n{}",
            out.stderr
        );
    }
}

/// Rule 6: a method on an `Unknown` receiver is left alone. The checker cannot
/// see the receiver's type, so no rule is invented — and the interpreter stays
/// the fallback plane for the program.
///
/// `let u = f([1, 2, 3])` through a closure value infers `Unknown` (the callee
/// is not a declared function, so there is no signature to read), while the
/// value at run time is a real array. The same method name on a *known* array
/// receiver is `E0625` (the contrast case below), which is what makes this a
/// statement about the receiver's type rather than about the method name.
#[test]
fn method_on_unknown_receiver_is_left_alone() {
    let path = write_program(
        "unknown-receiver",
        "fn main() {\n    let f = { x -> x }\n    let u = f([1, 2, 3])\n    print(u.len())\n}\n",
    );
    let checked = check(&path);
    let interp = run(&path, "--interpret");
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        checked.rc, 0,
        "an Unknown receiver must not be judged:\n{}",
        checked.stderr
    );
    assert!(
        !checked.stderr.contains("E0625"),
        "no E0625 may be invented for a receiver the checker cannot see:\n{}",
        checked.stderr
    );
    assert_eq!(interp.rc, 0, "{}", interp.stderr);
    assert_eq!(interp.stdout, "3\n");

    // Contrast: the identical call on a receiver the checker CAN see.
    let path = write_program(
        "unknown-receiver-contrast",
        "fn main() {\n    let a = [1, 2, 3]\n    print(a.frobnicate())\n}\n",
    );
    let checked = check(&path);
    let _ = std::fs::remove_file(&path);
    assert_ne!(checked.rc, 0, "a known Array receiver must be judged");
    assert!(checked.stderr.contains("E0625"), "{}", checked.stderr);
}

/// Names the native backend has an arm for but the interpreter does not are
/// **not** array methods: the registry is the interpreter's set (rule 1), so
/// `tallow check` now says so instead of letting the program die at run time —
/// or, worse, run on one plane and produce a wrong answer on the other.
///
/// `insert`/`remove` exist in codegen's pointer branch (map methods that share
/// the name); `for_each` and `fold` are native aliases of `each` and `reduce`
/// that `Interpreter::call_method` never dispatches. Measured at this revision:
///
/// ```text
/// $ tallow run --interpret  # a.for_each({ x -> print(x) })
/// runtime error: type error: unknown method: .for_each() on Array
/// $ tallow run --interpret  # [1,2,3].fold(0, { acc, x -> acc + x })
/// runtime error: type error: unknown method: .fold() on Array
/// ```
#[test]
fn methods_no_plane_implements_are_e0625() {
    for (tag, call) in [
        ("insert", "a.insert(0, 9)"),
        ("remove", "a.remove(0)"),
        ("for_each", "a.for_each({ x -> print(x) })"),
        ("fold", "a.fold(0, { acc, x -> acc + x })"),
    ] {
        let src = format!("fn main() {{\n    let a = [1, 2]\n    {call}\n}}\n");
        let path = write_program(&format!("absent-{tag}"), &src);
        let checked = check(&path);
        let _ = std::fs::remove_file(&path);
        assert_ne!(
            checked.rc, 0,
            "[{tag}] the checker accepted a method no plane runs"
        );
        assert!(
            checked.stderr.contains("E0625") && checked.stderr.contains(tag),
            "[{tag}] must be E0625 naming the method:\n{}",
            checked.stderr
        );
    }
}
