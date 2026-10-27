//! Engine parity for the *values* the generic stdlib bridge returns.
//!
//! # The defect this pins shut
//!
//! `c979aa7` made a compiled program able to call any of the 59 stdlib modules
//! that have no hand-written emitter, by having the bridge call the
//! interpreter's own `stdlib::dispatch`. It returned a pointer to a marshalled
//! value, and codegen had no declared return type for a stdlib module call
//! (`resolve_imports` skips `import tallow.*`), so the result was a bare `ptr`:
//!
//! * a `String` result printed correctly (a C string is a C string);
//! * a struct result round-tripped correctly (the `__type` tag — pinned by
//!   `tests/api_parity_native.rs`);
//! * an `Int`/`Float` result printed its **marshalled form** — `\x1fJ1` where
//!   the interpreter printed `1`;
//! * a `Bool` result was **truthy whenever it was non-null**, so
//!   `if geocode.is_zip5("7870")` printed `short-is-valid`. Measured on
//!   `ad3dc9e` before the fix; that line is the reason this file exists.
//!
//! # What is asserted
//!
//! One program per class, each run on both planes:
//!
//! | class  | call | why this one |
//! |--------|------|--------------|
//! | Int    | `decimal.decimal_cmp("1.10","1.09",2)` | deterministic sign, used in `n * 2` and `n * 2 + 1` |
//! | Float  | `finance.roa(100.0, 400.0)` | `0.25` exactly; `* 2.0` and `* 3.0` are exact binary fractions |
//! | Bool   | `geocode.is_zip5(...)` | true **and** false, because a pointer is truthy in both cases |
//! | String | `geocode.state_from_name("Texas")` | the control: it worked before and must keep working |
//! | struct | `api.openapi_load` → `api.endpoints_json` | the control: struct out, struct back in |
//!
//! For each: **byte-identical stdout** across the two planes, the native leg
//! under `--require-native`, and no `native build unavailable` in its stderr —
//! a fallback would make "parity" a tautology. Each program also asserts the
//! *computed* answer is present, so "both printed nothing" cannot pass.
//!
//! A sixth test proves the other half of the contract: a result kind this pass
//! does not decode (`[][]String`) is refused **by name** instead of being
//! returned as a pointer that prints for a demo and breaks in a loop.
//!
//! Float values are chosen so `%g` (the native format) and the interpreter's
//! `Display` cannot disagree: `0.25`, `0.5`, `0.75` are exact binary fractions
//! with at most three significant digits, so no tolerance and no formatting
//! guess is involved.

use std::process::{Command, Output};

const INT_PROGRAM: &str = r#"import tallow.decimal

fn main() {
    let n = decimal.decimal_cmp("1.10", "1.09", 2)
    print(n)
    print(n * 2)
    print(n * 2 + 1)
    if n > 0 {
        print("positive")
    }
}
"#;

const FLOAT_PROGRAM: &str = r#"import tallow.finance

fn main() {
    let r = finance.roa(100.0, 400.0)
    print(r)
    print(r * 2.0)
    print(r * 3.0)
}
"#;

const BOOL_PROGRAM: &str = r#"import tallow.geocode

fn main() {
    let ok = geocode.is_zip5("78701")
    if ok {
        print("zip-ok")
    } else {
        print("zip-bad")
    }
    let short = geocode.is_zip5("7870")
    if short {
        print("short-is-valid")
    } else {
        print("short-is-invalid")
    }
    print(ok)
}
"#;

const STRING_PROGRAM: &str = r#"import tallow.geocode

fn main() {
    print(geocode.state_from_name("Texas"))
    print(geocode.state_from_abbrev("TX"))
}
"#;

const STRUCT_PROGRAM: &str = r#"import tallow.api

fn main() {
    let doc = '{"openapi":"3.0.0","info":{"title":"probe","version":"1"},"paths":{"/users":{"get":{"responses":{"200":{"description":"ok"}}}},"/orders":{"post":{"responses":{"201":{"description":"made"}}}}}}'
    let inventory = api.openapi_load(doc, "https://example.test/openapi.json")
    print(api.endpoints_json(inventory))
}
"#;

/// `csv.read` declares `-> [][]String`. That is not decodable in this pass, so
/// the call must be refused *at the use* — printing it would render the
/// marshalled form, and indexing it would read a JSON array as a Tallow one.
const OPAQUE_PROGRAM: &str = r#"import tallow.csv

fn main() {
    let rows = csv.read("rows.csv")
    print(rows)
}
"#;

/// One `tallow` child at a time.
///
/// `cargo test` runs these tests on parallel threads, and each leg is a full
/// native build (clang link against the debug runtime archive, ~2 GB RSS peak).
/// Four of those at once drove this box into zram thrash during the bridge
/// spike, so the legs are serialized here rather than left to the harness:
/// correctness does not need the parallelism and the box does not survive it.
static BUILD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run(tag: &str, plane: &str, source: &str) -> Output {
    let _serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // `tag` keeps concurrent tests off each other's file: two tests sharing a
    // source+plane pair would compute the same path, and one test's cleanup
    // would delete the file the other's child had not read yet.
    tag.hash(&mut hasher);
    source.hash(&mut hasher);
    plane.hash(&mut hasher);
    let path =
        std::env::temp_dir().join(format!("tallow-bridge-returns-{:016x}.tl", hasher.finish()));
    std::fs::write(&path, source).expect("write program");

    let mut command = Command::new(env!("CARGO_BIN_EXE_tallow"));
    command
        .args(["run", plane, path.to_str().expect("utf-8 path")])
        // The run path gates direct egress; these programs touch no socket and
        // no file (csv.read is never executed), but the gate is on the command.
        .env("TALLOW_ALLOW_DIRECT", "1");
    let output = command.output().expect("run tallow");
    let _ = std::fs::remove_file(&path);
    output
}

/// Run both planes and return `(interpreter stdout, native stdout)`, asserting
/// the invariants every class shares.
fn parity(tag: &str, source: &str) -> (String, String) {
    let interpreted = run(tag, "--interpret", source);
    assert!(
        interpreted.status.success(),
        "[{tag}] interpreter leg failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&interpreted.stdout),
        String::from_utf8_lossy(&interpreted.stderr)
    );

    let native = run(tag, "--require-native", source);
    let native_stdout = String::from_utf8_lossy(&native.stdout).into_owned();
    let native_stderr = String::from_utf8_lossy(&native.stderr).into_owned();
    assert!(
        native.status.success(),
        "[{tag}] --require-native failed (the bridge did not lower this call):\n\
         stdout:\n{native_stdout}\nstderr:\n{native_stderr}"
    );
    assert!(
        !native_stderr.contains("native build unavailable"),
        "[{tag}] the native leg fell back to the interpreter, so this is not parity:\n\
         {native_stderr}"
    );

    let interpreted_stdout = String::from_utf8_lossy(&interpreted.stdout).into_owned();
    assert_eq!(
        native.stdout, interpreted.stdout,
        "[{tag}] stdout differs between the interpreter and the native bridge\n\
         interpreter:\n{interpreted_stdout}\nnative:\n{native_stdout}"
    );
    (interpreted_stdout, native_stdout)
}

#[test]
fn int_result_is_a_real_integer_in_arithmetic_and_print() {
    let (interp, native) = parity("int", INT_PROGRAM);
    // The marshalled form must be gone, not merely "close": the old output was
    // `\x1fJ1`, and `n * 2` on that pointer was a string concatenation.
    assert!(
        !native.contains('\u{1f}'),
        "the native leg printed the marshalled form:\n{native}"
    );
    assert_eq!(
        native, "1\n2\n3\npositive\n",
        "the computed integers are wrong (interpreter said:\n{interp})"
    );
}

#[test]
fn float_result_is_a_real_float_in_arithmetic_and_print() {
    let (interp, native) = parity("float", FLOAT_PROGRAM);
    assert!(
        !native.contains('\u{1f}'),
        "the native leg printed the marshalled form:\n{native}"
    );
    assert_eq!(
        native, "0.25\n0.5\n0.75\n",
        "the computed floats are wrong (interpreter said:\n{interp})"
    );
}

#[test]
fn bool_result_drives_the_branch_it_says_it_does() {
    let (interp, native) = parity("bool", BOOL_PROGRAM);
    // The pre-fix failure, exactly: a marshalled `false` is a non-null pointer,
    // so `if short` took the true branch and printed `short-is-valid`.
    assert!(
        native.contains("short-is-invalid"),
        "a marshalled `false` was read as truthy:\n{native}"
    );
    assert_eq!(
        native, "zip-ok\nshort-is-invalid\ntrue\n",
        "the boolean results are wrong (interpreter said:\n{interp})"
    );
}

#[test]
fn string_result_is_still_a_plain_string() {
    let (interp, native) = parity("string", STRING_PROGRAM);
    assert_eq!(
        native, "TX\nTexas\n",
        "the String control regressed (interpreter said:\n{interp})"
    );
}

#[test]
fn struct_result_still_round_trips_through_the_bridge() {
    let (interp, native) = parity("struct", STRUCT_PROGRAM);
    assert!(
        native.contains("\"schema_version\":\"tallow.api.inventory.v1\""),
        "the payload is not the inventory document:\n{native}"
    );
    assert!(
        native.contains("\"count\":2"),
        "the inventory did not parse both endpoints:\n{native}"
    );
    assert!(interp.contains("\"count\":2"), "interpreter leg diverged");
}

#[test]
fn an_undecodable_result_kind_is_refused_by_name() {
    let output = run("opaque", "--require-native", OPAQUE_PROGRAM);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "printing a `[][]String` bridged result must be refused, not rendered:\n\
         stdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("[][]String"),
        "the refusal must name the declared type that could not be decoded:\n{stderr}"
    );
    assert!(
        stderr.contains("does not decode that kind yet"),
        "the refusal must say the kind is not decoded yet:\n{stderr}"
    );
    // `tallow run --require-native` wraps a codegen refusal as
    // `* native build unavailable (<reason>); --require-native refuses the
    // interpreter fallback`, so the *presence* of that prefix is the wrapper, not
    // a fallback: what must not appear is a runtime abort or interpreter output.
    assert!(
        !stderr.contains("runtime error:"),
        "the refusal must be a build-time refusal, not a runtime abort:\n{stderr}"
    );
    assert!(
        !stderr.contains("running in the interpreter"),
        "the program must not have been handled by the interpreter:\n{stderr}"
    );
}
