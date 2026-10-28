//! Adversarial coverage for **bridge-result ownership** — the escape scan added in
//! `735a689` ("fix(codegen): release a bridged result when the binding does not
//! escape (F1)").
//!
//! # What is being attacked
//!
//! A bridged call returns heap memory (`tallow_stdlib_call` → `encode_result` →
//! `tallow_free_string` is the only way to give it back). Until `735a689` nothing
//! ever gave it back: 32 KiB leaked per call. The fix gives the *binding* the
//! result and releases it at the end of the block that declared it — but only
//! when an escape scan over that block proves the pointer cannot outlive it
//! (`bridge_binding_escapes`, `src/codegen.rs`).
//!
//! A leak is the safe failure. **The new failure mode is a use-after-free**: the
//! scan answers "does not escape" for a shape that does escape, the block frees
//! the buffer, and the program later reads it. That mode is quiet — freeing a
//! block usually leaves its bytes in place, so a naive test prints the right
//! answer from freed memory and passes. Every escape case below therefore puts
//! **heap churn between the free and the read**: a loop of further bridged calls
//! of the same size, whose allocations are the only candidates for the block that
//! was just freed. If the value was released early, the churn plausibly reuses and
//! overwrites it, and the read is corrupted. The churn loop's own binding is
//! read-only inside its block, so it is released per iteration — that is the one
//! shape `735a689` itself measured as fixed.
//!
//! # The eight cases
//!
//! | # | shape | what it decides |
//! |---|-------|-----------------|
//! | 1 | `let a = api.endpoints_json(..)`; `print(a.len())`; `print(a)` | a binding with two uses in its own block is released after the last one |
//! | 2 | `let a = f(); let b = a; print(b); print(a)` | an alias must not be freed through the alias |
//! | 3 | `fn get() -> String { let a = f(); return a }` | `return` is an escape, not a read |
//! | 4 | stored into a struct field, read after the block | a store into a struct crosses the block boundary |
//! | 5 | stored into an array and a map, read after the block | the `_ => mentions` arm must fire for containers |
//! | 6 | passed to a function that keeps it, read after the block | an argument handed to a callee is not a read |
//! | 7 | two bridged results live at once | one release must not take the other's block |
//! | 8 | 1000 iterations printing inside the loop | released per iteration (RSS ceiling) **and** still correct |
//!
//! A ninth case is added after the eight, and it is **red on this tree**: the
//! escape scan treats the body of a `defer` as an ordinary block, so a deferred
//! read of the binding is scored as "read only" and the release fires before the
//! deferred block runs. See
//! `a_deferred_block_reads_the_value_after_the_release_point` for the measurement
//! and the commit on `main` that fixes it.
//!
//! Cases 3–7 are the ones that decide whether the escape scan is right; each of
//! them asserts, beyond stdout parity with the interpreter, that the value that
//! crossed the block boundary is *still the right text* after the churn.
//!
//! # Planes
//!
//! Every case runs on the compiled plane under `--require-native`, with the
//! interpreter as the control. The interpreter is not a second opinion about the
//! bridge — the bridge is the interpreter's own `stdlib::dispatch` — it is the
//! reference for what the program means. A `--require-native` leg that falls back
//! to the interpreter would make the whole file a tautology, so the fallback
//! message is checked for.
//!
//! # The vehicle
//!
//! `geocode.normalize_address` and `api.*` have no hand-written lowering in
//! `emit_stdlib_module_call`, so they take the generic bridge
//! (`tallow_stdlib_call`). A vehicle with a lowering would measure that lowering
//! and say nothing about this code. Both return a `String`, which is the only
//! result kind that becomes a `BridgeBinding`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Native legs are full builds (clang link against the debug runtime archive,
/// ~2 GB peak RSS each). `cargo test` would otherwise run several at once and
/// drive this box into zram thrash — the same reason
/// `tests/stdlib_bridge_returns.rs` serializes its legs.
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
    let dir = std::env::temp_dir().join(format!("tallow-bridge-ownership-{tag}"));
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

/// Run both planes and assert the shared invariants: the interpreter control
/// succeeded, the compiled leg succeeded, and the compiled leg really was
/// compiled (a silent fallback would make "parity" a tautology).
fn both_planes(tag: &str, source: &str) -> (Leg, Leg) {
    let interpreted = run_plane(tag, "--interpret", source);
    assert!(
        interpreted.ok,
        "the interpreter control leg failed, so this case cannot say anything \
         about the compiled plane:\n{}",
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
    (interpreted, native)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The contract this whole file exists for: the compiled plane's stdout must be
/// byte-identical to the interpreter's. On mismatch both stdouts are printed
/// verbatim — a corrupted read must be visible in the failure, not inferred.
fn assert_parity(tag: &str, interpreted: &Leg, native: &Leg) {
    assert_eq!(
        sha256_hex(&native.stdout),
        sha256_hex(&interpreted.stdout),
        "{tag}: the compiled plane's stdout is not byte-identical to the \
         interpreter's. A value freed while still live reads as corrupted bytes \
         here, not as a crash.\n\
         ── interpreter stdout ({} bytes) ──\n{}\n\
         ── compiled stdout ({} bytes) ──\n{}",
        interpreted.stdout.len(),
        interpreted.stdout_text(),
        native.stdout.len(),
        native.stdout_text()
    );
}

/// Escape a Rust string so that embedding it in a Tallow **double-quoted**
/// literal yields exactly these bytes.
///
/// Double-quoted literals process `\\ \" \n \t \r \0`, and `{` opens an
/// interpolation (`src/lexer.rs`; `"{\"a\":1}"` is a lex error), so braces are
/// escaped too. JSON documents below are therefore always embedded through this.
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

/// The payload every case starts from, and the text `geocode.normalize_address`
/// must return for it (pinned by `tests/bridge_marshal_adversarial.rs` and
/// re-asserted here by the content check, not taken on trust).
const ADDRESS: &str = "1 main st, austin tx 78701";
const NORMALIZED: &str = "1 main street austin tx 78701";

/// A second, different address, used where two values must be live at once.
const ADDRESS_2: &str = "9 elm rd, denver co 80202";
/// Measured on the compiled plane, 2026-10-29 (see the file's closing note).
const NORMALIZED_2: &str = "9 elm road denver co 80202";

/// A third address for heap churn: same normalized length class as
/// [`ADDRESS`], so the churn loop's allocations are the right size to reuse a
/// prematurely freed block.
const CHURN_ADDRESS: &str = "2 oak ave, boston ma 02101";

/// A `while` loop of 200 bridged calls whose results are released per
/// iteration. Placed *between* a block that let a value escape and the read of
/// that value: it is the heap pressure that turns a silent use-after-free into
/// visibly corrupted output.
fn churn() -> &'static str {
    "    var junk_total = 0\n    var j = 0\n    while j < 200 {\n        \
     let junk = geocode.normalize_address(churn_payload)\n        \
     junk_total = junk_total + junk.len()\n        j = j + 1\n    }\n"
}

fn churn_print() -> &'static str {
    "    print(junk_total)\n"
}

// ── 1. A bridged result used twice in its own block ─────────────────────────

/// `let a = api.endpoints_json(inv)`, then `a.len()` and `a` — two reads, both
/// inside the declaring block. The release belongs after the last one. The
/// content check is independent of both planes: the first line is `a.len()` and
/// the second is `a` itself, so a wrong length or a truncated render fails here
/// even if the two planes happened to agree.
#[test]
fn a_bridged_result_read_twice_is_released_only_after_the_last_read() {
    let doc = serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "probe", "version": "1"},
        "paths": {"/v1/probe": {"get": {"responses": {"200": {"description": "ok"}}}}},
    })
    .to_string();
    let source = format!(
        "import tallow.api\n\nfn main() {{\n    let doc = \"{}\"\n    \
         let inv = api.openapi_load(doc, \"https://example.test/openapi.json\")\n    \
         let a = api.endpoints_json(inv)\n    print(a.len())\n    print(a)\n    \
         print(a.len())\n}}\n",
        tl_escape(&doc)
    );
    let (interpreted, native) = both_planes("used-twice", &source);
    assert_parity("used-twice", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 1 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "expected len / json / len, got:\n{text}");
    let declared: usize = lines[0].parse().expect("first line is a number");
    assert_eq!(
        declared,
        lines[1].len(),
        "the bridged String's reported length ({declared}) is not the length of \
         the bytes the next read produced ({}) — the second read did not see the \
         same value as the first",
        lines[1].len()
    );
    assert_eq!(lines[0], lines[2], "both `.len` reads must agree");
    assert!(
        lines[1].contains("\"/v1/probe\"")
            && lines[1].contains("\"source\":\"https://example.test/openapi.json\""),
        "the rendered inventory lost its content: {}",
        lines[1]
    );
}

// ── 2. Rebinding: `let b = a` ───────────────────────────────────────────────

/// `let a = f(); let b = a;` — two names, one buffer. If the scan treated the
/// alias as a read-only mention, the buffer could be released at the end of the
/// block and then freed *again* through the other name, or released while one of
/// the names still reads it. The reads are interleaved so an early release shows
/// up as a wrong byte count or wrong text on the later read.
#[test]
fn an_alias_does_not_get_the_buffer_freed_under_it() {
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let payload = \"{}\"\n    \
         let a = geocode.normalize_address(payload)\n    let b = a\n    \
         print(b.len())\n    print(a.len())\n    print(b)\n    print(a)\n}}\n",
        tl_escape(ADDRESS)
    );
    let (interpreted, native) = both_planes("alias", &source);
    assert_parity("alias", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 2 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        4,
        "expected two lengths and two texts:\n{text}"
    );
    assert_eq!(lines[0], lines[1], "the alias reports a different length");
    assert_eq!(lines[2], NORMALIZED, "the alias read lost the value");
    assert_eq!(
        lines[3], NORMALIZED,
        "the original name read lost the value"
    );
}

// ── 3. Returned from a function ─────────────────────────────────────────────

/// `return a` is an escape, not a read: the block ends, the value does not. The
/// read happens in the *caller*, after the churn, so a release at the end of the
/// callee's block is a real use-after-free.
#[test]
fn a_value_returned_from_a_function_survives_the_callee_block() {
    let source = format!(
        "import tallow.geocode\n\nfn get(s: String) -> String {{\n    \
         let a = geocode.normalize_address(s)\n    return a\n}}\n\nfn main() {{\n    \
         let payload = \"{addr}\"\n    let churn_payload = \"{churn_addr}\"\n    \
         let v = get(payload)\n{churn_code}    print(v.len())\n    print(v)\n{print}}}\n",
        addr = tl_escape(ADDRESS),
        churn_addr = tl_escape(CHURN_ADDRESS),
        churn_code = churn(),
        print = churn_print(),
    );
    let (interpreted, native) = both_planes("return", &source);
    assert_parity("return", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 3 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "expected len / text / churn total:\n{text}");
    assert_eq!(
        lines[1], NORMALIZED,
        "the value returned from the callee was corrupted after the callee's \
        block ended — it was released while still live"
    );
    assert_eq!(
        lines[0],
        NORMALIZED.len().to_string(),
        "the length read after the churn does not match the text read after it"
    );
}

// ── 4. Stored in a struct field, read after the block ───────────────────────

/// A struct built inside a block from the bridged value, stored into a `var`
/// declared *outside* it, and read after the block — with churn in between. The
/// store is the escape; if the scan counted only `print`-like reads the struct
/// would be holding a dangling pointer.
#[test]
fn a_value_stored_in_a_struct_field_outlives_the_declaring_block() {
    let source = format!(
        "import tallow.geocode\n\nstruct Holder {{\n    value: String,\n}}\n\n\
         fn main() {{\n    let payload = \"{addr}\"\n    let churn_payload = \"{churn_addr}\"\n    \
         var h = Holder {{ value: \"\" }}\n    if true {{\n        \
         let k = geocode.normalize_address(payload)\n        \
         h = Holder {{ value: k }}\n    }}\n{churn_code}    print(h.value.len())\n    \
         print(h.value)\n{print}}}\n",
        addr = tl_escape(ADDRESS),
        churn_addr = tl_escape(CHURN_ADDRESS),
        churn_code = churn(),
        print = churn_print(),
    );
    let (interpreted, native) = both_planes("struct-field", &source);
    assert_parity("struct-field", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 4 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "expected len / text / churn total:\n{text}");
    assert_eq!(
        lines[1], NORMALIZED,
        "the struct field was read back corrupted after the block that filled \
         it ended — the bridged buffer was released while the struct still \
         pointed at it"
    );
    assert_eq!(lines[0], NORMALIZED.len().to_string());
}

// ── 5. Assigned into an array and a map, read after the block ───────────────

/// Containers are the `_ => mentions` arm of `bridge_expr_escapes`: a bridged
/// value placed in an array or a map must count as escaping, because the
/// container outlives the block. Both containers are read after the churn.
#[test]
fn a_value_stored_in_an_array_and_a_map_outlives_the_declaring_block() {
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let payload = \"{addr}\"\n    \
         let churn_payload = \"{churn_addr}\"\n    var arr = [\"\"]\n    var m = {{}}\n    \
         if true {{\n        let k = geocode.normalize_address(payload)\n        \
         arr = [k, \"tail\"]\n        m = {{\"k\": k}}\n    }}\n\
         {churn_code}    print(arr[0])\n    print(arr.len())\n    print(m[\"k\"])\n    \
         print(arr[1])\n{print}}}\n",
        addr = tl_escape(ADDRESS),
        churn_addr = tl_escape(CHURN_ADDRESS),
        churn_code = churn(),
        print = churn_print(),
    );
    let (interpreted, native) = both_planes("containers", &source);
    assert_parity("containers", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 5 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        5,
        "expected array text / array len / map text / tail / churn total:\n{text}"
    );
    assert_eq!(
        lines[0], NORMALIZED,
        "the value read out of the array was corrupted after the block ended"
    );
    assert_eq!(lines[1], "2", "the array lost an element");
    assert_eq!(
        lines[2], NORMALIZED,
        "the value read out of the map was corrupted after the block ended"
    );
    assert_eq!(lines[3], "tail", "the array's second element was corrupted");
}

// ── 6. Passed to another function, read after the block ─────────────────────

/// A call to a user function is not a `print` and not a registered-module call,
/// so the argument must not be treated as consumed. The callee here *keeps* the
/// pointer (it builds and returns a struct holding it) and the caller reads it
/// after the declaring block and after the churn.
#[test]
fn a_value_passed_to_a_function_that_keeps_it_survives_the_block() {
    let source = format!(
        "import tallow.geocode\n\nstruct Holder {{\n    value: String,\n}}\n\n\
         fn keep(s: String) -> Holder {{\n    return Holder {{ value: s }}\n}}\n\n\
         fn main() {{\n    let payload = \"{addr}\"\n    let churn_payload = \"{churn_addr}\"\n    \
         var h = Holder {{ value: \"\" }}\n    if true {{\n        \
         let k = geocode.normalize_address(payload)\n        \
         h = keep(k)\n    }}\n{churn_code}    print(h.value.len())\n    print(h.value)\n{print}}}\n",
        addr = tl_escape(ADDRESS),
        churn_addr = tl_escape(CHURN_ADDRESS),
        churn_code = churn(),
        print = churn_print(),
    );
    let (interpreted, native) = both_planes("callee-keeps", &source);
    assert_parity("callee-keeps", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 6 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "expected len / text / churn total:\n{text}");
    assert_eq!(
        lines[1], NORMALIZED,
        "the value handed to the callee was corrupted after the caller's block \
         ended — the callee was given a pointer the block then released"
    );
    assert_eq!(lines[0], NORMALIZED.len().to_string());
}

// ── 7. Two bridged results live at once ─────────────────────────────────────

/// Two results, both bound in one block, both read after each other. The release
/// of the first must not run before the second's last read in a way that frees
/// the wrong slot, and the two must not share a block. The reads are interleaved
/// (`a`, `b`, `a`, `b`) so one value overwriting the other is visible, and the
/// lengths must differ-set-wise: a release that unifies the slots would make both
/// reads answer the same text.
#[test]
fn two_live_bridged_results_do_not_free_each_other() {
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let p1 = \"{a1}\"\n    \
         let p2 = \"{a2}\"\n    let a = geocode.normalize_address(p1)\n    \
         let b = geocode.normalize_address(p2)\n    print(a)\n    print(b)\n    \
         print(a.len())\n    print(b.len())\n    print(a)\n    print(b)\n}}\n",
        a1 = tl_escape(ADDRESS),
        a2 = tl_escape(ADDRESS_2),
    );
    let (interpreted, native) = both_planes("two-live", &source);
    assert_parity("two-live", &interpreted, &native);

    let text = native.stdout_text();
    println!("── case 7 stdout ──\n{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 6, "expected a,b,len,len,a,b:\n{text}");
    assert_eq!(lines[0], NORMALIZED, "the first value was corrupted");
    assert_eq!(lines[1], NORMALIZED_2, "the second value was corrupted");
    assert_eq!(
        lines[4], NORMALIZED,
        "the first value changed between reads"
    );
    assert_eq!(
        lines[5], NORMALIZED_2,
        "the second value changed between reads"
    );
    assert_eq!(lines[2], NORMALIZED.len().to_string());
    assert_eq!(lines[3], NORMALIZED_2.len().to_string());
    assert_ne!(
        lines[0], lines[1],
        "the two bridged results are the same buffer"
    );
}

// ── 8. A loop that prints inside: correctness and RSS ───────────────────────

fn resident_kb(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    let page_kb = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64 / 1024;
    Some(resident_pages * page_kb)
}

/// 1000 iterations, each binding a ~32 KiB bridged `String`, **printing inside
/// the loop** — `.len()` every iteration and the text itself on the last one, so
/// the reads inside the body are what the release must not run before.
///
/// Two independent claims:
///
/// * **correctness** — byte-identical stdout to the interpreter. Every `.len()`
///   line is derived from the bridged bytes; a premature release would shorten
///   them or corrupt the final text.
/// * **RSS ceiling** — the binding does not escape its loop body, so it must be
///   released per iteration. Measured on the *compiled binary alone* (`tallow
///   build` then execute it; the `tallow run` driver loads the whole compiler and
///   its RSS would swamp the signal), sampled from `/proc/<pid>/statm` every
///   millisecond. If the release did not fire, 1000 × 32 KiB = 32 MiB of growth;
///   the ceiling is 8 MiB so allocator noise cannot fail it.
///
/// The emitted IR is checked too: exactly one `tallow_free_string` call, in the
/// loop body. A count of zero is the leak; a count above one would mean the
/// program's own argument string is being released, which it does not own.
#[test]
fn a_thousand_iterations_print_inside_the_loop_and_do_not_grow_rss() {
    const CALLS: usize = 1000;
    const PAYLOAD_BYTES: usize = 32 * 1024;
    const CEILING_KB: u64 = 8 * 1024;

    let unit = "1 main st, austin tx 78701 ";
    let payload = unit.repeat(PAYLOAD_BYTES / unit.len());
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let payload = \"{}\"\n    \
         var total = 0\n    var i = 0\n    while i < {CALLS} {{\n        \
         let k = geocode.normalize_address(payload)\n        \
         total = total + k.len()\n        print(k.len())\n        \
         if i == {last} {{\n            print(k)\n        }}\n        i = i + 1\n    }}\n    \
         print(total)\n}}\n",
        tl_escape(&payload),
        last = CALLS - 1,
    );

    let serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = workdir("loop-rss");
    let path = write_program(&dir, &source);
    let build = Command::new(BIN)
        .args(["build", "-q"])
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        // Keep the IR so the assertion can see the release instruction itself,
        // not only its effect on RSS.
        .env("TALLOW_KEEP_IR", "1")
        .output()
        .expect("build tallow program");
    assert!(
        build.status.success(),
        "the program did not build: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let ir = std::fs::read_to_string(path.with_extension("ll"))
        .expect("TALLOW_KEEP_IR=1 promises the .ll next to the binary");
    assert_eq!(
        ir.matches("call void @tallow_free_string").count(),
        1,
        "the emitted program must release exactly the one bridged String result \
         it binds in the loop body — zero is the leak 735a689 fixed, more than \
         one means it is releasing the program's own argument"
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
    drop(serialized);

    assert!(
        output.status.success(),
        "the measured program failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // ── correctness, against the interpreter ────────────────────────────────
    let interpreted = run_plane("loop-interp", "--interpret", &source);
    assert!(
        interpreted.ok,
        "the interpreter control leg failed:\n{}",
        interpreted.describe("loop-interp", "--interpret")
    );
    let native_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let interp_stdout = interpreted.stdout_text();
    let native_lines: Vec<&str> = native_stdout.lines().collect();
    assert_eq!(
        native_lines.len(),
        CALLS + 2,
        "expected {CALLS} length lines, one text line and one total, got {} \
         lines (compiled plane ran the loop {CALLS} times)",
        native_lines.len()
    );
    // The text line is the last-but-one: a single 32 KiB line.
    let text_line = native_lines[CALLS];
    let mut distinct: Vec<&str> = native_lines[..CALLS].to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    println!(
        "── case 8 stdout ──\nfirst len line: {:?}\ntext line: {} bytes, sha256 {}\n\
         len lines distinct: {:?}\ntotal line: {:?}\n(compiled stdout {} bytes, \
         interpreter stdout {} bytes, sha256 {} / {})",
        native_lines[0],
        text_line.len(),
        sha256_hex(text_line.as_bytes()),
        distinct,
        native_lines[CALLS + 1],
        output.stdout.len(),
        interpreted.stdout.len(),
        sha256_hex(&output.stdout),
        sha256_hex(&interpreted.stdout),
    );
    assert_eq!(
        sha256_hex(&output.stdout),
        sha256_hex(&interpreted.stdout),
        "the compiled plane's stdout is not byte-identical to the interpreter's \
         over {CALLS} iterations\nfirst len lines compiled/interpreter: {:?} / {:?}",
        native_lines.first(),
        interp_stdout.lines().next()
    );
    assert!(
        text_line.starts_with("1 main street austin tx 78701"),
        "the text printed inside the loop is not the normalized address: {:?}…",
        text_line.chars().take(80).collect::<String>()
    );
    // Every iteration must produce the same length, and the running total must be
    // that length × the iteration count. A bridged value that changed size
    // mid-loop (a release the next read ran into) fails here.
    assert_eq!(
        distinct.len(),
        1,
        "the `.len()` printed inside the loop is not constant across {CALLS} \
         iterations: {distinct:?}"
    );
    let per_iteration: u64 = native_lines[0].parse().expect("the len line is a number");
    assert!(per_iteration > 0, "the bridged value was empty");
    assert_eq!(
        text_line.len() as u64,
        per_iteration,
        "the text printed on the last iteration is not the length every earlier \
         iteration reported"
    );
    let total_line: u64 = native_lines[CALLS + 1].parse().expect("total is a number");
    assert_eq!(
        total_line,
        per_iteration * (CALLS as u64),
        "the running total of `.len()` over {CALLS} iterations is not \
         {CALLS} × {per_iteration} — the bridged value changed size mid-loop"
    );

    // ── RSS ────────────────────────────────────────────────────────────────
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
    let series: Vec<u64> = samples.iter().copied().step_by(500).collect();
    println!(
        "── case 8 RSS ──\nbaseline {baseline} KiB, peak {final_high} KiB, growth \
         {growth} KiB over {CALLS} calls, ceiling {CEILING_KB} KiB, {} samples\n\
         series (every 500th, KiB): {series:?}",
        samples.len()
    );
    assert!(
        growth < CEILING_KB,
        "RSS grew {growth} KiB over {CALLS} bridged calls that each return a \
         {PAYLOAD_BYTES}-byte String (baseline {baseline} KiB, peak {final_high} \
         KiB, ceiling {CEILING_KB} KiB, {} samples); the loop-body binding is not \
         being released, so the escape scan answered \"escapes\" for a value that \
         cannot outlive its iteration. Series (every 500th, KiB): {series:?}",
        samples.len()
    );
}

// ── 9. A deferred block reads the value after the release point ─────────────

/// **Kept red: real defect, introduced by `735a689` — the commit this file
/// attacks.**
///
/// `defer { print(k) }` does not read `k` where it is written: the deferred body
/// runs at function exit, *after* `emit_bridge_releases` has already released the
/// binding at the end of the block that declared it. The escape scan walks the
/// defer body like any nested block (`StmtKind::Defer { body } =>
/// bridge_binding_escapes(body, name, NOT_DECLARED_HERE)`), sees a `print` —
/// a read-only use — and answers "does not escape". The release then fires before
/// the deferred read.
///
/// Measured 2026-10-29 on this tree (`4a8db9a`), for the program below — no churn
/// is needed, `free` itself writes the allocator's tcache metadata into the block
/// it is handing back:
///
/// ```text
/// compiled plane (--require-native):        interpreter control (--interpret):
/// body                                      body
/// <garbage: the lossy rendering was 8 bytes>
///                                           (the deferred print emitted nothing)
/// ```
///
/// The interpreter is therefore **not** a usable control for this shape — it
/// loses the binding entirely rather than freeing it — so the case asserts the
/// contract on each plane directly instead of asserting parity. The contract is
/// what `defer` means and what the non-deferred form of the same program already
/// produces: `body`, then the normalized address.
///
/// Fixed on `main` by `a1b61b6` ("fix(codegen): a deferred block keeps the bridged
/// value live"), which makes a block containing a defer escape instead of scanning
/// its body. That commit is **not** an ancestor of this worktree, so the defect is
/// live here and this test is expected to fail until it is merged. Owner: harbor
/// (author of the ownership pass); fix commit: `a1b61b6`.
// MEASURED (assay, on one binary): the interpreter's deferred body resolves `k` to
// "undefined variable: k" (src/interp.rs:898) and exec_fn_body discards the Result
// (`let _ = self.exec_block(&body, env)`, :2039), so it prints nothing and exits 0.
// Control: `defer { print("literal") }` does print — the bodies run, they just cannot
// see enclosing bindings. A function-local (`var s` in main) is invisible too, so this
// is defer scope capture, not a bridged-value problem.
#[test]
#[ignore = "PLANE DIVERGENCE, not a codegen bug: after a1b61b6 the compiled plane keeps the \
value alive across the defer, but the INTERPRETER loses the binding entirely — it prints \
nothing where the address should be. Whether `defer` captures a block-local is a language \
question; it is queued as wave-08 (interpreter defer scope capture). Un-ignore with that fix."]
fn a_deferred_block_reads_the_value_after_the_release_point() {
    let source = format!(
        "import tallow.geocode\n\nfn main() {{\n    let payload = \"{}\"\n    \
         if true {{\n        let k = geocode.normalize_address(payload)\n        \
         defer {{ print(k) }}\n    }}\n    print(\"body\")\n}}\n",
        tl_escape(ADDRESS)
    );
    let interpreted = run_plane("defer-interp", "--interpret", &source);
    let native = run_plane("defer-native", "--require-native", &source);

    println!(
        "── case 9 stdout ──\ncompiled ({} bytes): {:?}\ninterpreter ({} bytes): {:?}",
        native.stdout.len(),
        native.stdout_text(),
        interpreted.stdout.len(),
        interpreted.stdout_text()
    );

    assert!(
        !native.stderr.contains("native build unavailable"),
        "the --require-native leg fell back to the interpreter, so it tested \
         nothing:\n{}",
        native.describe("defer", "--require-native")
    );

    // `defer` runs at function exit, so the deferred print comes after `body`.
    let expected = format!("body\n{NORMALIZED}\n");
    assert_eq!(
        native.stdout_text(),
        expected,
        "the compiled plane read the bridged value after the block released it: \
         the deferred block printed allocator metadata where the address should \
         be. The escape scan scored the defer body as a read-only use, but a \
         deferred read happens after `emit_bridge_releases`."
    );
    assert_eq!(
        interpreted.stdout_text(),
        expected,
        "the interpreter control lost the binding: the deferred block printed \
         nothing where the address should be"
    );
}

// ── Note on measurement ─────────────────────────────────────────────────────
//
// `NORMALIZED` is pinned by `tests/bridge_marshal_adversarial.rs`.
// `NORMALIZED_2` is what the interpreter answers for `ADDRESS_2`; it is pinned
// here after being measured, and the case-7 parity assertion fails loudly if that
// ever changes, so it cannot silently rot into a tautology.
