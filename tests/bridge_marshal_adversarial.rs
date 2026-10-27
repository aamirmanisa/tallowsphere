//! Adversarial coverage for the **generic stdlib bridge** (`c979aa7` + `2d1c512`):
//! the boundary in `src/runtime/stdlib_bridge_ffi.rs` and its codegen call site
//! (`CodeGen::emit_stdlib_bridge_call` / `emit_stdlib_bridge_arg`), not the
//! modules behind it.
//!
//! # What is being attacked
//!
//! A compiled Tallow program hands a bridged call a `char *const *argv` whose
//! elements are either raw UTF-8 (a `String`) or `\x1fJ`-prefixed JSON (every
//! other marshalled value); the result comes back the same way. Every test here
//! asks the boundary one question: *does the value that arrives mean the same
//! thing the program wrote?*
//!
//! # Choosing a vehicle
//!
//! A bridged call is only bridged if `emit_stdlib_module_call` has **no** arm
//! for its module. This matters for test design: `math.*`, `crypto.*`,
//! `provenance.*` and `url.*` are hand-written lowerings, so a test written
//! against `crypto.hash` or `provenance.hash_body` would measure those
//! lowerings and say nothing about this boundary. The vehicles below —
//! `api.*`, `geocode.*`, `finance.*`, `recordlink.*` — have no arm and were
//! measured running through `tallow_stdlib_call` (the native leg succeeds with no
//! `native build unavailable` fallback).
//!
//! # Planes — what is end-to-end and what is Rust-boundary
//!
//! | # | case | plane | declared expectation |
//! |---|------|-------|----------------------|
//! | 1 | String arg: quote + backslash + multibyte text | end-to-end | local |
//! | 1 | String arg: 1 MiB | end-to-end | local |
//! | 1 | String arg containing a NUL byte | end-to-end | local |
//! | 1 | String arg: invalid UTF-8 | **Rust-boundary** | local |
//! | 2 | result whose bytes need JSON escaping (sha256) | end-to-end | local |
//! | 3 | Int arg at `i64::MIN`, `i64::MAX`, `-1` | end-to-end | local |
//! | 3 | the same values through the raw ABI | **Rust-boundary** | local |
//! | 4 | Float arg: NaN, +inf, -inf | end-to-end | local |
//! | 4 | Float arg: `0.1` (not decimal-exact) | end-to-end | local |
//! | 5 | 600 bridged String results: RSS growth | end-to-end | local |
//! | 6 | registered module, unknown method | end-to-end | local |
//! | 6 | module the dispatcher does not know | **Rust-boundary** | local |
//!
//! Two cases cannot be expressed in `.tl`:
//!
//! * **invalid UTF-8** — a Tallow `String` is a Rust `String`; the lexer cannot
//!   produce a byte sequence that is not UTF-8, so the only way to reach
//!   `decode_argument`'s UTF-8 refusal is to call `tallow_stdlib_call` with raw
//!   bytes.
//! * **a module the router does not know** — an `import tallow.<unknown>` never
//!   becomes a bridged module call (the build refuses it earlier, by name), so
//!   the dispatcher's `None` arm is only reachable through the ABI. The
//!   *reachable* half of the same question — a registered module with a method
//!   its dispatch does not know — **is** end-to-end and is tested that way.
//!
//! Everything else runs on the compiled plane under `--require-native`, with the
//! interpreter leg as the control. A test that only ran the interpreter would
//! say nothing about the bridge: the bridge *is* the interpreter's own
//! `stdlib::dispatch`, so the interpreter leg cannot fail these cases by
//! construction.
//!
//! # Note on literal escaping
//!
//! In this language a **double-quoted** literal processes `\\ \" \n \t \r \0`
//! and starts an *interpolation* at `{`, while a **single-quoted** literal is
//! raw. Every payload below is therefore embedded with [`tl_escape`], which
//! escapes braces as well; `"{...}"` written naively is a lex error, measured.
//!
//! # Defects this file keeps red
//!
//! Three assertions fail on the tree they were written against. They are the
//! *correct* expectation, not the observed behaviour — they are meant to start
//! passing when the boundary is fixed, and must not be relaxed:
//!
//! * `string_arg_with_an_embedded_nul_must_not_truncate` — argument bytes are
//!   read with `CStr::from_ptr`, so a `String` containing `\0` reaches the callee
//!   cut at the NUL. Measured: `recordlink.soundex("a\0b")` answers `A000` on the
//!   compiled plane (soundex of `"a"`) where the rule and the interpreter answer
//!   `A100` (soundex of `a\0b`).
//! * `nan_and_infinite_float_arguments_must_reach_the_module` — `tallow_json_f64`
//!   marshals a non-finite float as JSON `null`, the callee receives `nil`, and
//!   the dispatch aborts with `Expected number, got nil`; the interpreter answers
//!   `nan` / `inf`.
//! * `bridged_string_results_do_not_grow_rss_without_bound` — the result pointer
//!   of a bridged call is never released (`tallow_free_string` is emitted only
//!   for the marshalled scalar *arguments*, `src/codegen.rs:23101`), so every
//!   bridged `String` result is leaked: measured 32 KiB per call, 2000 calls
//!   cost +64 MB of RSS.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tallow::runtime::stdlib_bridge_ffi::{tallow_json_as_i64, tallow_json_i64, tallow_stdlib_call};
use tallow::runtime::{tallow_free_string, tallow_last_error};

/// Native legs are full builds (clang link against the debug runtime archive,
/// ~2 GB peak RSS). `cargo test` would otherwise run several at once and drive
/// this box into zram thrash — the same reason `tests/stdlib_bridge_returns.rs`
/// serializes its legs.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

const BIN: &str = env!("CARGO_BIN_EXE_tallow");

// ── Running a program on a plane ────────────────────────────────────────────

struct Leg {
    ok: bool,
    stdout: Vec<u8>,
    stderr: String,
}

impl Leg {
    fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    fn describe(&self, tag: &str, plane: &str) -> String {
        format!(
            "[{tag} {plane}] ok={}\nstdout:\n{}\nstderr:\n{}",
            self.ok,
            self.stdout_text(),
            self.stderr
        )
    }
}

/// A private directory for one test's program and its built binary.
fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-bridge-marshal-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create work dir");
    dir
}

fn write_program(dir: &Path, source: &str) -> PathBuf {
    let path = dir.join("prog.tl");
    std::fs::write(&path, source).expect("write program");
    path
}

/// Run one plane. Holds the build lock for the whole child, so two tests never
/// link at once.
fn run_plane(tag: &str, plane: &str, source: &str) -> Leg {
    let _serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = workdir(tag);
    let path = write_program(&dir, source);
    let output = Command::new(BIN)
        .args(["run", plane])
        .arg(&path)
        // These programs touch no socket and read no file, but the run path
        // gates direct egress on the command anyway.
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_dir_all(&dir);
    Leg {
        ok: output.status.success(),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run both planes and return `(interpreter stdout, native stdout)` after
/// asserting the shared invariants: both succeeded, and the native leg really
/// was the native leg (a fallback would make "parity" a tautology).
fn both_planes(tag: &str, source: &str) -> (Vec<u8>, Vec<u8>) {
    let interpreted = run_plane(tag, "--interpret", source);
    assert!(
        interpreted.ok,
        "the interpreter control leg failed, so this test cannot say anything \
         about the bridge:\n{}",
        interpreted.describe(tag, "--interpret")
    );

    let native = run_plane(tag, "--require-native", source);
    assert!(
        !native.stderr.contains("native build unavailable"),
        "the --require-native leg fell back to the interpreter, so it tested \
         nothing:\n{}",
        native.describe(tag, "--require-native")
    );
    assert!(
        native.ok,
        "the compiled leg failed.\n{}\nthe interpreter answered:\n{}",
        native.describe(tag, "--require-native"),
        interpreted.describe(tag, "--interpret")
    );
    (interpreted.stdout, native.stdout)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Escape a Rust string so that embedding it in a Tallow **double-quoted**
/// literal yields exactly these bytes.
///
/// Double-quoted literals process `\\ \" \n \t \r \0`, and `{` opens an
/// interpolation (`src/lexer.rs`, measured: `"{\"a\":1}"` is a lex error), so
/// braces are escaped too. Everything else is written raw; source is UTF-8.
fn tl_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            other => out.push(other),
        }
    }
    out
}

/// A `fn main` that loads `doc` through `api.openapi_load` and prints the
/// inventory JSON. `api` has no hand-written lowering, so both calls are the
/// bridge: a `String` in, a struct back, the struct in again, a `String` out.
fn api_echo_program(doc: &str) -> String {
    format!(
        "import tallow.api\n\nfn main() {{\n    let doc = \"{}\"\n    \
         let inv = api.openapi_load(doc, \"https://example.test/openapi.json\")\n    \
         let out = api.endpoints_json(inv)\n    print(out)\n}}\n",
        tl_escape(doc)
    )
}

/// One-endpoint OpenAPI document whose only path key is `path`.
fn openapi_doc_with_path(path: &str) -> String {
    serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "probe", "version": "1"},
        "paths": {path: {"get": {"responses": {"200": {"description": "ok"}}}}},
    })
    .to_string()
}

/// The path key as `api.endpoints_json` must render it, computed independently
/// of the module: `serde_json`'s escaping of the same string.
fn escaped_path(path: &str) -> String {
    serde_json::to_string(path).expect("serialise path")
}

// ── 1. String arguments ────────────────────────────────────────────────────

/// Characters a naive marshaller is tempted to mangle — a quote, a backslash,
/// multi-byte UTF-8 — must reach the callee unchanged. The check is on the
/// *escaped rendering of the value as JSON*, computed here with `serde_json`, so
/// "both planes agree" is not enough: both could agree on the wrong bytes.
#[test]
fn string_arg_with_quoting_and_multibyte_text_arrives_intact() {
    let path = "/a\"b\\c/x-y_é日本";
    let source = api_echo_program(&openapi_doc_with_path(path));
    let (interp, native) = both_planes("quoted-arg", &source);
    assert_eq!(
        sha256_hex(&native),
        sha256_hex(&interp),
        "the compiled leg and the interpreter disagree:\ninterpreter:\n{}\n\
         native:\n{}",
        String::from_utf8_lossy(&interp),
        String::from_utf8_lossy(&native)
    );
    let native = String::from_utf8_lossy(&native).into_owned();
    assert!(
        native.contains(&escaped_path(path)),
        "the path did not survive the argument marshalling; expected {} in:\n{}",
        escaped_path(path),
        native
    );
}

/// 1 MiB is past every small-buffer assumption a marshaller might make. The
/// answer must be byte-identical to the interpreter's, and it must be *large* —
/// a silent truncation of the argument would cut the result too, so the length
/// assertion makes "both printed the same short prefix" impossible.
#[test]
fn one_mib_string_arg_arrives_intact() {
    let mut payload = String::with_capacity(1 << 20);
    let mut index = 0usize;
    while payload.len() < (1 << 20) {
        payload.push_str(&format!("1 main st {index:06} "));
        index += 1;
    }
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let payload = \"{}\"\n    \
         let out = geocode.normalize_address(payload)\n    print(out.len())\n    print(out)\n}}\n",
        tl_escape(&payload)
    );
    let (interp, native) = both_planes("one-mib", &source);
    assert_eq!(
        sha256_hex(&native),
        sha256_hex(&interp),
        "a 1 MiB String argument did not produce the interpreter's answer \
         (native {} bytes, interpreter {} bytes)",
        native.len(),
        interp.len()
    );
    // The normalized text is slightly longer than the input (token expansion),
    // so anything appreciably shorter than 1 MiB means the argument was cut.
    assert!(
        native.len() > (1 << 20),
        "the compiled leg's output is only {} bytes for a 1 MiB argument",
        native.len()
    );
}

/// **Kept red: real defect.** A Tallow `String` may contain `\0`
/// (`src/lexer.rs` decodes the escape), but `decode_argument` reads every
/// argument with `CStr::from_ptr`, which stops at the first NUL. The callee
/// therefore sees `"a"` where the program wrote `"a\0b"`.
///
/// The expectation is the soundex rule itself: `A` + code('b')='1' + padding =
/// `A100`, and `A000` for `"a"` alone. It is not relaxed to "the native leg
/// printed the soundex of a truncated string"; that would record the defect as
/// the contract.
#[test]
fn string_arg_with_an_embedded_nul_must_not_truncate() {
    let source = "import tallow.recordlink\n\nfn main() {\n    \
                  print(recordlink.soundex(\"a\\0b\"))\n    \
                  print(recordlink.soundex(\"a\"))\n}\n";
    let (interp, native) = both_planes("nul-arg", source);
    assert_eq!(
        String::from_utf8_lossy(&interp),
        "A100\nA000\n",
        "the interpreter control is not passing the NUL through"
    );
    assert_eq!(
        String::from_utf8_lossy(&native),
        "A100\nA000\n",
        "the bridge truncated the argument at the embedded NUL: the callee saw \
         \"a\" instead of \"a\\0b\""
    );
}

/// **Rust boundary: not expressible in `.tl`.** A Tallow `String` is UTF-8 by
/// construction, so the only way to hand `decode_argument` invalid UTF-8 is the
/// C ABI. It must be refused with a message that names the problem — silently
/// lossy-converting it would put different bytes in front of the callee.
#[test]
fn invalid_utf8_string_arg_is_refused_at_the_abi() {
    let module = CString::new("recordlink").unwrap();
    let method = CString::new("soundex").unwrap();
    // 0xff 0xfe is not valid UTF-8; no interior NUL, so it is a legal C string.
    let bad = CString::new(vec![b'x', 0xff, 0xfe]).unwrap();
    let argv = [bad.as_ptr()];

    let result = tallow_stdlib_call(
        module.as_ptr(),
        method.as_ptr(),
        1,
        argv.as_ptr() as *const *const c_char,
    );
    let error = last_error();
    assert!(
        result.is_null(),
        "an invalid-UTF-8 argument must be refused, not decoded lossily"
    );
    assert!(
        error.contains("not valid UTF-8"),
        "the refusal must name the encoding problem, got: {error:?}"
    );
    assert!(
        error.contains("recordlink.soundex"),
        "the refusal must name the call, got: {error:?}"
    );
}

// ── 2. Result bytes that need escaping ─────────────────────────────────────

/// The one place a result's bytes pass through a JSON encoder is a *non-String*
/// result: `encode_result` serialises it as `\x1fJ` + JSON. A path containing a
/// quote, a backslash, a real newline, a tab and multi-byte text must come back
/// through that encoder byte-for-byte: the test re-parses the compiled leg's
/// output with `serde_json` and compares the recovered path to what the program
/// put in, and compares sha256 of the whole output against the interpreter's.
///
/// A plain `String` result takes the other branch (`encode_result` returns its
/// raw UTF-8, there is no escaping layer), so this is the strongest form the
/// question takes.
#[test]
fn result_with_characters_that_need_escaping_round_trips_byte_identically() {
    let path = "/a\"b\\c\nd\te/é/😀";
    let source = api_echo_program(&openapi_doc_with_path(path));
    let (interp, native) = both_planes("escapes", &source);
    assert_eq!(
        sha256_hex(&native),
        sha256_hex(&interp),
        "the escaped result is not byte-identical between the planes\n\
         interpreter:\n{}\nnative:\n{}",
        String::from_utf8_lossy(&interp),
        String::from_utf8_lossy(&native)
    );
    let native_text = String::from_utf8(native.clone()).expect("stdout is valid UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(native_text.trim()).expect("the result is not JSON");
    assert_eq!(
        json["endpoints"][0]["path"].as_str(),
        Some(path),
        "the escaping round trip changed the path"
    );
    assert!(
        native_text.contains(&escaped_path(path)),
        "the escaped form is not the encoder's; expected {} in:\n{}",
        escaped_path(path),
        native_text
    );
}

// ── 3. Int arguments ───────────────────────────────────────────────────────

/// `finance.eps(earnings, shares: Int)` is bridged. The answer is read as a
/// *sign*, not as text, because the two planes' float renderings legitimately
/// differ (`%g` vs `Display`). A width truncation is visible: `i64::MIN` cut to
/// 32 bits is `0` (division by zero → `+inf`, not negative) and `i64::MAX` cut
/// to 32 bits is `-1` (negative, not positive).
#[test]
fn int_extremes_survive_the_bridge() {
    let source = "import tallow.finance\n\nfn main() {\n    \
                  let min = -9223372036854775807 - 1\n    \
                  let max = 9223372036854775807\n    \
                  if finance.eps(1.0, min) < 0.0 {\n        print(\"min-neg\")\n    } else {\n        \
                  print(\"min-not-neg\")\n    }\n    \
                  if finance.eps(1.0, max) > 0.0 {\n        print(\"max-pos\")\n    } else {\n        \
                  print(\"max-not-pos\")\n    }\n    \
                  if finance.eps(1.0, -1) < 0.0 {\n        print(\"one-neg\")\n    } else {\n        \
                  print(\"one-not-neg\")\n    }\n}\n";
    let (interp, native) = both_planes("int-extremes", source);
    assert_eq!(
        String::from_utf8_lossy(&native),
        "min-neg\nmax-pos\none-neg\n",
        "an i64 extreme changed value or sign through the bridge \
         (interpreter said: {})",
        String::from_utf8_lossy(&interp)
    );
}

/// **Rust boundary.** The same values without the compiler in the way: marshal
/// with `tallow_json_i64`, call the ABI, decode with `tallow_json_as_i64`. This
/// pins the ABI itself — `-1` turns into `u64::MAX` under a sign-extension bug,
/// and `i64::MIN` overflows a `neg`-based reading of the JSON number.
#[test]
fn int_extremes_survive_the_abi() {
    let module = CString::new("math").unwrap();
    let method = CString::new("min_i").unwrap();
    let what = CString::new("math.min_i").unwrap();

    for value in [i64::MIN, i64::MAX, -1, 0, 1] {
        let arg = tallow_json_i64(value);
        assert!(!arg.is_null(), "tallow_json_i64 returned NULL for {value}");
        let argv = [arg as *const c_char, arg as *const c_char];
        let result = tallow_stdlib_call(
            module.as_ptr(),
            method.as_ptr(),
            2,
            argv.as_ptr() as *const *const c_char,
        );
        assert!(
            !result.is_null(),
            "math.min_i({value}, {value}) failed at the ABI: {}",
            last_error()
        );
        let back = tallow_json_as_i64(result, what.as_ptr());
        tallow_free_string(arg);
        assert_eq!(back, value, "an i64 did not survive the ABI round trip");
    }
}

// ── 4. Float arguments ─────────────────────────────────────────────────────

/// **Kept red: real defect.** `tallow_json_f64` maps NaN and ±inf to JSON
/// `null` (JSON has no spelling for them), `decode_argument` turns that into
/// `nil`, and the module's own argument check refuses: the compiled plane aborts
/// with `Expected number, got nil` while the interpreter computes with NaN/inf.
/// The assertion is parity, because a bridged call must mean what the
/// interpreter's call means.
#[test]
fn nan_and_infinite_float_arguments_must_reach_the_module() {
    let source = "import tallow.finance\nimport tallow.math\n\nfn main() {\n    \
                  let nan = math.sqrt(-1.0)\n    \
                  print(finance.roa(nan, 1.0))\n    \
                  let inf = math.pow(2.0, 1024.0)\n    \
                  print(finance.roa(inf, 1.0))\n    \
                  print(finance.roa(-inf, 1.0))\n}\n";
    let (interp, native) = both_planes("float-nonfinite", source);
    assert_eq!(
        String::from_utf8_lossy(&native),
        String::from_utf8_lossy(&interp),
        "NaN/±inf arguments do not survive the bridge"
    );
    let native = String::from_utf8_lossy(&native).into_owned();
    assert!(native.contains("nan"), "expected NaN in: {native}");
    assert!(native.contains("inf"), "expected ±inf in: {native}");
}

/// A value that is not exactly representable in decimal (`0.1`, and `1/3`) must
/// come back as the same `f64` bits. The comparison happens in-language
/// (`r == 0.1`), so it is a bit comparison of values, not of the `%g`/`Display`
/// renderings — those formatters legitimately differ and are not what this test
/// is about.
#[test]
fn a_float_that_is_not_decimal_exact_round_trips_bit_identically() {
    let source = "import tallow.finance\n\nfn main() {\n    \
                  let r = finance.roa(0.1, 1.0)\n    \
                  if r == 0.1 {\n        print(\"exact\")\n    } else {\n        \
                  print(\"drifted\")\n    }\n    \
                  let q = finance.roa(1.0, 3.0)\n    \
                  if q == 1.0 / 3.0 {\n        print(\"third-exact\")\n    } else {\n        \
                  print(\"third-drifted\")\n    }\n}\n";
    let (interp, native) = both_planes("float-decimal", source);
    assert_eq!(
        String::from_utf8_lossy(&native),
        "exact\nthird-exact\n",
        "a non-decimal-exact float drifted through the bridge \
         (interpreter said: {})",
        String::from_utf8_lossy(&interp)
    );
}

// ── 5. Repeated calls: RSS ─────────────────────────────────────────────────

fn resident_kb(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    let page_kb = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64 / 1024;
    Some(resident_pages * page_kb)
}

/// **Kept red: real defect.** 600 bridged calls that each return a ~32 KiB
/// `String`. If the result pointer were released, RSS would plateau a few MiB
/// above the start; because `emit_stdlib_bridge_call` frees only the marshalled
/// scalar *arguments* and never the result, every call leaks its result and RSS
/// climbs by ~19 MiB.
///
/// Measured on `/proc/<pid>/statm` of the compiled binary (not of the `tallow`
/// driver, whose compiler footprint would swamp the signal), sampled every
/// millisecond. The ceiling is deliberately generous — 8 MiB for 600 calls — so
/// allocator noise cannot fail it; the leak is 19 MiB, and 2000 calls measured
/// +64 MiB.
#[test]
fn bridged_string_results_do_not_grow_rss_without_bound() {
    const CALLS: usize = 600;
    const PAYLOAD_BYTES: usize = 32 * 1024;
    const CEILING_KB: u64 = 8 * 1024;

    let unit = "1 main st, austin tx 78701 ";
    let payload = unit.repeat(PAYLOAD_BYTES / unit.len());
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let payload = \"{}\"\n    \
         var total = 0\n    var i = 0\n    while i < {CALLS} {{\n        \
         let k = geocode.normalize_address(payload)\n        total = total + k.len()\n        \
         i = i + 1\n    }}\n    print(total)\n}}\n",
        tl_escape(&payload)
    );

    let _serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = workdir("rss");
    let path = write_program(&dir, &source);
    // Build, so the program under measurement is the compiled binary alone. The
    // `tallow run` driver loads and runs the whole compiler; measuring it would
    // report the compiler's RSS, not the bridge's.
    let build = Command::new(BIN)
        .args(["build", "-q"])
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("build tallow program");
    assert!(
        build.status.success(),
        "the program did not build: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let binary = path.with_extension("");
    assert!(binary.exists(), "no binary at {}", binary.display());

    let mut child = Command::new(&binary)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn built program");
    let pid = child.id();
    let mut samples: Vec<u64> = Vec::new();
    loop {
        if let Some(kb) = resident_kb(pid) {
            samples.push(kb);
        }
        match child.try_wait().expect("wait on child") {
            Some(_) => break,
            None => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
    let output = child.wait_with_output().expect("collect output");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "the measured program failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        samples.len() >= 40,
        "too few RSS samples ({}) to make a claim about growth",
        samples.len()
    );

    let tenth = (samples.len() / 10).max(1);
    // Startup (mapping the debug binary) settles inside the first tenth; the
    // loop runs for seconds after it.
    let baseline = *samples[..tenth].iter().max().expect("samples");
    let final_high = *samples[samples.len() - tenth..]
        .iter()
        .max()
        .expect("samples");
    let growth = final_high.saturating_sub(baseline);
    // Every 500th sample: enough to see the climb without turning the failure
    // message into 19k numbers.
    let series: Vec<u64> = samples.iter().copied().step_by(500).collect();
    assert!(
        growth < CEILING_KB,
        "RSS grew {growth} KiB over {CALLS} bridged calls that return a \
         {PAYLOAD_BYTES}-byte String (baseline {baseline} KiB, peak {final_high} KiB, \
         ceiling {CEILING_KB} KiB, {} samples); a bridged String result is never \
         `tallow_free_string`-ed, so each call leaks its result. Sampled series \
         (every 500th, KiB): {series:?}",
        samples.len()
    );
}

// ── 6. Unknown module / unknown method ─────────────────────────────────────

/// The reachable half of "a module argument the dispatcher does not know": a
/// registered module with a method its `dispatch` does not answer. Both planes
/// must refuse, and both refusals must name the call — an abort with no
/// information is the failure mode this asks about.
#[test]
fn an_unknown_method_is_refused_by_name_on_both_planes() {
    let source = "import tallow.geocode\n\nfn main() {\n    \
                  print(geocode.no_such_method(\"x\"))\n}\n";
    let interpreted = run_plane("unknown-method-interp", "--interpret", source);
    let native = run_plane("unknown-method-native", "--require-native", source);

    assert!(
        !interpreted.ok,
        "the interpreter answered an unknown method instead of raising:\n{}",
        interpreted.describe("unknown-method", "--interpret")
    );
    assert!(
        interpreted.stderr.contains("geocode.no_such_method"),
        "the interpreter refusal does not name the call:\n{}",
        interpreted.describe("unknown-method", "--interpret")
    );
    assert!(
        !native.ok,
        "the compiled plane answered an unknown method instead of refusing:\n{}",
        native.describe("unknown-method", "--require-native")
    );
    assert!(
        native.stderr.contains("geocode.no_such_method"),
        "the compiled-plane refusal must name the module and method:\n{}",
        native.describe("unknown-method", "--require-native")
    );
    assert!(
        !native.stdout.iter().any(|b| !b.is_ascii_whitespace()),
        "the compiled plane printed a value for an unknown method:\n{}",
        native.describe("unknown-method", "--require-native")
    );
}

/// **Rust boundary: not expressible in `.tl`.** `import tallow.<unknown>` is
/// refused before it ever becomes a bridged call, so the router's `None` arm has
/// no `.tl` spelling. Called directly, it must return NULL with a message naming
/// the module — not a NULL with an empty or generic error, and never a value.
#[test]
fn an_unknown_module_is_refused_by_name_at_the_abi() {
    let module = CString::new("definitely_not_a_module").unwrap();
    let method = CString::new("anything").unwrap();
    let result = tallow_stdlib_call(module.as_ptr(), method.as_ptr(), 0, std::ptr::null());
    let error = last_error();

    assert!(
        result.is_null(),
        "an unknown module must not produce a value"
    );
    assert!(
        error.contains("definitely_not_a_module"),
        "the refusal must name the module the caller asked for, got: {error:?}"
    );
    assert!(
        error.contains("anything"),
        "the refusal must name the method too, got: {error:?}"
    );
    assert!(
        !error.trim().is_empty(),
        "the refusal carried no message at all"
    );
}

// ── ABI helpers ────────────────────────────────────────────────────────────

fn last_error() -> String {
    let pointer = tallow_last_error();
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: a non-null `tallow_last_error` pointer is a NUL-terminated string
    // owned by the runtime and valid for the life of the thread-local.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}
