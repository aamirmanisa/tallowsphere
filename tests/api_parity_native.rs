//! Engine parity for a module that has no hand-written native emitter — `api`.
//!
//! # What this pins
//!
//! `emit_stdlib_module_call` (src/codegen.rs) used to match module names and
//! call a hand-written emitter; an unlisted module returned `Ok(None)` and the
//! build refused with `native backend has no lowering for method …`. `api` is
//! one of the 69 modules in that gap.
//!
//! The generic bridge (`src/runtime/stdlib_bridge_ffi.rs`) closes it by calling
//! the interpreter's *own* `stdlib::dispatch` from a C entry point, so the
//! module semantics are the interpreter's by construction. That claim is worth
//! nothing without a measurement, which is what this file is:
//!
//! * the same program is run through both planes;
//! * stdout must be **byte-identical** (`Vec<u8>`, not a trimmed string);
//! * the native leg must not have fallen back to the interpreter;
//! * the output must contain the module's real payload, so "both printed
//!   nothing" cannot pass as parity;
//! * with `TALLOW_GENERIC_STDLIB_BRIDGE=0` the native leg must refuse again —
//!   proof that the parity above came from the bridge and that the fallback can
//!   be turned off for a bisect.
//!
//! `api` is deliberately a struct-carrying module: `api.openapi_load` returns
//! `ApiInventory` (a struct) and `api.endpoints_json` consumes it, so this also
//! exercises the bridge's value round trip (struct out, struct back in) and not
//! just string-in/string-out.

use std::process::{Command, Output};

/// Two endpoints, both carrying their document URL as evidence.
///
/// The document is a raw (single-quoted) string: a double-quoted `.tl` string
/// treats `{…}` as interpolation, so JSON in one needs escaping and a stray
/// escape is exactly the kind of thing that would make this test measure the
/// parser instead of the bridge.
const PROGRAM: &str = r#"import tallow.api

fn main() {
    let doc = '{"openapi":"3.0.0","info":{"title":"probe","version":"1"},"paths":{"/users":{"get":{"responses":{"200":{"description":"ok"}}}},"/orders":{"post":{"responses":{"201":{"description":"made"}}}}}}'
    let inventory = api.openapi_load(doc, "https://example.test/openapi.json")
    print(api.endpoints_json(inventory))
}
"#;

/// `math.sqrt` has a hand-written emitter. It must keep working with the bridge
/// switched off — otherwise the fallback arm has started stealing modules that
/// already have a lowering, which the spike explicitly forbids.
const EMITTED_MODULE_PROGRAM: &str = r#"import tallow.math

fn main() {
    print(math.sqrt(2.0))
}
"#;

fn run(tag: &str, plane: &str, source: &str, extra_env: &[(&str, &str)]) -> Output {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // `tag` keeps concurrent tests off each other's file: two tests sharing a
    // source+plane pair would otherwise compute the same path, and one test's
    // cleanup would delete the file the other's child had not read yet.
    tag.hash(&mut hasher);
    source.hash(&mut hasher);
    plane.hash(&mut hasher);
    let path = std::env::temp_dir().join(format!(
        "tallow-api-parity-{:016x}.tl",
        hasher.finish()
    ));
    std::fs::write(&path, source).expect("write program");

    let mut command = Command::new(env!("CARGO_BIN_EXE_tallow"));
    command
        .args(["run", plane, path.to_str().expect("utf-8 path")])
        // The run path gates direct egress; these probes read nothing and write
        // nothing, but the gate is on the command, not on the program.
        .env("TALLOW_ALLOW_DIRECT", "1");
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command.output().expect("run tallow");
    let _ = std::fs::remove_file(&path);
    output
}

#[test]
fn api_bridge_stdout_is_byte_identical_across_planes() {
    let interpreted = run("parity-interpret", "--interpret", PROGRAM, &[]);
    assert!(
        interpreted.status.success(),
        "interpreter leg failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&interpreted.stdout),
        String::from_utf8_lossy(&interpreted.stderr)
    );

    let native = run("parity-native", "--require-native", PROGRAM, &[]);
    let native_stdout = String::from_utf8_lossy(&native.stdout).into_owned();
    let native_stderr = String::from_utf8_lossy(&native.stderr).into_owned();
    assert!(
        native.status.success(),
        "--require-native failed (the bridge did not lower api):\nstdout:\n{native_stdout}\nstderr:\n{native_stderr}"
    );
    assert!(
        !native_stderr.contains("native build unavailable"),
        "the native leg fell back to the interpreter, so this is not parity:\n{native_stderr}"
    );

    // "Both printed nothing" is not parity. Require the module's real payload,
    // including the count it computed from the document.
    assert!(
        native_stdout.contains("\"schema_version\":\"tallow.api.inventory.v1\""),
        "the payload is not the inventory document:\n{native_stdout}"
    );
    assert!(
        native_stdout.contains("\"count\":2"),
        "the inventory did not parse both endpoints:\n{native_stdout}"
    );
    assert!(
        native_stdout.contains("https://example.test/openapi.json"),
        "the document URL (the evidence on every row) is missing:\n{native_stdout}"
    );

    assert_eq!(
        native.stdout, interpreted.stdout,
        "stdout differs between the interpreter and the native bridge\n\
         interpreter:\n{}\nnative:\n{}",
        String::from_utf8_lossy(&interpreted.stdout),
        String::from_utf8_lossy(&native.stdout)
    );
}

#[test]
fn bridge_is_gated_off_by_env_and_then_api_refuses() {
    let output = run(
        "gated",
        "--require-native",
        PROGRAM,
        &[("TALLOW_GENERIC_STDLIB_BRIDGE", "0")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "with the bridge disabled the native leg must refuse api, not answer:\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("no lowering for method 'openapi_load'")
            || stderr.contains("native build unavailable"),
        "the refusal must name the missing lowering:\n{stderr}"
    );
}

#[test]
fn hand_written_emitters_keep_their_code_path_when_the_bridge_is_off() {
    let output = run(
        "emitted",
        "--require-native",
        EMITTED_MODULE_PROGRAM,
        &[("TALLOW_GENERIC_STDLIB_BRIDGE", "0")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "math.sqrt has a real emitter and must not depend on the bridge:\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("native build unavailable"),
        "math.sqrt fell back to the interpreter with the bridge off:\n{stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "1.41421",
        "math.sqrt's native answer changed"
    );
}
