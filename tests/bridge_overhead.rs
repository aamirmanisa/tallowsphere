//! The generic stdlib bridge's **pure marshalling cost**, measured and bounded.
//!
//! # The number this file exists to produce
//!
//! `c979aa7` added the bridge and reported 89.4 µs/call bridged against
//! 105.2 µs/call interpreted for `api.endpoints_json` — and said plainly that
//! this was *not* overhead: serializing two endpoints dominates it. `2d1c512`
//! made the results typed and re-ran the same kind of comparison. Neither
//! answered the question a bridge inherits from every FFI boundary: what does
//! the marshalling itself cost, with the module doing nothing?
//!
//! So this test drives the cheapest module function there is — one `String`
//! in, one `String` out, constant work — and differences two call counts in the
//! same program.
//!
//! # Method
//!
//! One program, two counts, both planes:
//!
//! ```text
//! while i < CALLS { let s = geocode.state_from_name("Texas"); … }
//! ```
//!
//! `CALLS` is the only difference between the two programs, and it is a loop
//! bound, so the emitted IR, the parse, the typecheck and the link have the
//! same size, and the constant cost of process start — and of the native build,
//! which is hoisted out of the timed path entirely — cancels in the
//! subtraction:
//!
//! ```text
//! delta(plane) = min_over_runs(time(N + 2000)) - min_over_runs(time(N))
//! per_call     = delta / 2000
//! ```
//!
//! ## Why the compiled leg is timed as a built artifact, not as `tallow run`
//!
//! The obvious harness — time `tallow run --require-native prog.tl`, exactly as
//! `tests/stdlib_bridge_returns.rs` runs its legs — is **unusable for this
//! measurement**, and that is a measurement, not a preference. `tallow run`
//! codegens and links before executing, and on this box that is ~21 s per
//! invocation with a multi-second spread (measured, same two programs, 5 runs
//! each, min of each side subtracted):
//!
//! ```text
//! tallow run --require-native    19808 ms -> 20204 ms   =>  198.1 µs/call
//! same programs, built artifacts      9.3 ms ->  17.4 ms =>    3.80 µs/call
//! ```
//!
//! The 198 µs figure is 52× the real cost: it is mostly the difference between
//! two 21 s builds, not between two call counts. `tallow build` once per
//! program and timing the resulting executable removes the compiler from the
//! measurement, which is the only thing being asked about here. The brief's
//! "process startup and JIT/loading cancels" holds for a ~10 ms process; it
//! does not hold for a ~21 s build whose variance is seconds.
//!
//! `min` of [`RUNS`] runs, not a mean: this box runs other lanes' builds
//! concurrently (`/run/nixe-heavy-build.lock` is a real queue), so the
//! distribution is one-sided — a run can only be slowed, never sped up.
//!
//! # What the three numbers mean
//!
//! * **bridged** — the compiled plane: `tallow_stdlib_call`, which decodes the
//!   argument into a `Value`, calls the interpreter's *own* `stdlib::dispatch`,
//!   and re-encodes the result as a C string.
//! * **interpreted** — the tree-walking plane, which reaches the *same*
//!   `stdlib::dispatch` and clones the positional argument vector on the way
//!   (`interp.rs:4772`).
//! * **delta** — the difference. It is a difference between two *call
//!   mechanisms*, and both of them pay the module's own work, so it is neither
//!   "the bridge's overhead" nor "the bridge's saving": see
//!   `the_module_work_floor_under_both_planes` and
//!   `docs/perf/bridge-overhead.md` for the arithmetic that splits it.
//!
//! # The bound, and why it is loose
//!
//! `bridged_per_call < 5 × interpreted_per_call`. The measured ratio is ~0.1
//! (the bridge is the cheaper call mechanism for this function), so the
//! assertion tolerates a **~50× regression** in the bridge before it fires.
//! A tighter bound would be defensible only on an idle machine; this one has to
//! survive a box where another lane is linking. `BRIDGED_CEILING_US` is the
//! second fence: 20 µs/call is ~5× the measured value and still far below the
//! spike's 89.4 µs/call (which included real serialization work), so a
//! regression that keeps the *ratio* but inflates the cost still fails.
//!
//! # The ownership case, added after F1
//!
//! `735a689` (F1) made a bridged `String` result releasable: when the binding
//! does not escape its block, codegen frees the runtime's buffer at the end of
//! that block. `bridged_string_ownership_path_is_bounded_and_released` times
//! the case where that release fires — a result consumed immediately by
//! `print` — subtracts a print-only control, times `tallow_free_string`
//! directly (one deallocation is below what the two-count subtraction can
//! resolve), and checks RSS flatness at 2000 calls with a 32 KiB result. The
//! numbers and the bound rationale are in `docs/perf/bridge-overhead.md` §7.

use std::ffi::CString;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use tallow::runtime::stdlib_bridge_ffi::tallow_stdlib_call;
use tallow::runtime::tallow_free_string;

/// Baseline call count. The loop — not unrolled straight-line calls — is what
/// keeps the emitted IR the same size between the two programs.
const BASE_CALLS: usize = 200;

/// Added calls. The measurement is the difference, so this is the signal:
/// ~4 ms of work against a ~10 ms process, which is what makes the subtraction
/// survive a shared box.
const EXTRA_CALLS: usize = 2000;

/// Runs per configuration; the reported time for each is the minimum.
const RUNS: usize = 5;

/// `geocode.state_from_name` — the cheapest routed function found. See
/// `docs/perf/bridge-overhead.md` for the search and for what it also does.
const MODULE: &str = "geocode";
const METHOD: &str = "state_from_name";

/// The result the probe's declaration promises; asserted, so this test cannot
/// silently start measuring a function that no longer returns a `String`.
const EXPECTED_RESULT: &str = "TX";

/// Ceiling on the bridged per-call cost, in microseconds. Generous: ~5× the
/// measured value, and still under the spike's 89.4 µs/call for a call that did
/// real work.
const BRIDGED_CEILING_US: f64 = 20.0;

/// The ratio bound. Measured ratio is ~0.1; 5.0 leaves a ~50× regression free.
const MAX_RATIO_TO_INTERPRETER: f64 = 5.0;

/// Ceiling on the ownership case's per-call cost (µs): a bridged `String`
/// result consumed immediately and released at the end of the loop body, as
/// F1's escape scan allows. `2 ×` the measured 3.72 µs/call; see
/// `docs/perf/bridge-overhead.md` §7.
const OWNERSHIP_CEILING_US: f64 = 8.0;

/// RSS leg: F1's own shape at four times the call count F1's test used.
const RSS_CALLS: usize = 2000;
const RSS_PAYLOAD_BYTES: usize = 32 * 1024;
const RSS_METHOD: &str = "normalize_address";

/// Ceiling on RSS growth over [`RSS_CALLS`] bridged calls returning a
/// 32 KiB result: measured +300 and +408 KiB on two runs, so this is ~5× the
/// larger reading rather than 2×. The reason is stated rather than hidden: a
/// 1 ms sampler's *peak* moves with the allocator's arena, and 2× a
/// noise-level peak would flake, which is worse than a slightly looser bound.
/// It is still 32× below the 64 MiB that one un-released result per call would
/// produce, and 13× tighter per call than F1's own 8 MiB ceiling for 600 calls
/// (1.0 KiB/call allowed here against 13.7 KiB/call there).
/// See `docs/perf/bridge-overhead.md` §7.3.
const OWNERSHIP_RSS_CEILING_KB: u64 = 2048;

/// Sanity fence on `tallow_free_string` itself, in nanoseconds. Deliberately
/// not a performance bound: it is ~15× the measured 67 ns and exists only to
/// catch the release turning into something other than one deallocation (a
/// scan, a copy, a lock).
const FREE_CEILING_NS: f64 = 1_000.0;

/// Serializes this test's legs. Each fixture is a full codegen + clang link
/// against a 1.1 GB archive, and this box has been driven into zram thrash by
/// four of those at once (see `tests/stdlib_bridge_returns.rs`). The builds are
/// outside the timed region, but they are not outside the box's memory budget.
static BUILD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The program both planes run. `acc` is printed so nothing above it can be
/// eliminated, and it is derived from the *content* of the bridged result, so a
/// bridge that returned garbage fails the assertion below instead of measuring
/// fast garbage.
fn program(calls: usize) -> String {
    format!(
        r#"import tallow.{MODULE}

fn main() {{
    var i = 0
    var acc = 0
    while i < {calls} {{
        let s = {MODULE}.{METHOD}("Texas")
        if s == "{EXPECTED_RESULT}" {{
            acc = acc + 1
        }}
        i = i + 1
    }}
    print(acc)
}}
"#
    )
}

/// One program of `calls` calls, built natively, in a directory of its own.
struct Fixture {
    dir: PathBuf,
    source: PathBuf,
    artifact: PathBuf,
}

impl Fixture {
    /// Writes the source and runs `tallow build` on it.
    ///
    /// The build is the proof that the call was lowered by the *bridge*: with
    /// no lowering the native backend refuses by name and `build` exits
    /// non-zero (there is no interpreter fallback on this path, unlike
    /// `tallow run`), so a silent fallback cannot make "bridged" a second
    /// interpretation of the same program.
    fn prepare(tag: &str, calls: usize) -> Fixture {
        Fixture::prepare_source(tag, calls, program(calls), false)
    }

    /// The same, for any source text. `keep_ir` asks `tallow build` to leave
    /// the emitted IR next to the artifact, so a caller can assert on the
    /// instruction a case depends on instead of only on its effect.
    fn prepare_source(tag: &str, calls: usize, text: String, keep_ir: bool) -> Fixture {
        let dir = unique_dir(tag, calls);
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        let source = dir.join("prog.tl");
        std::fs::write(&source, text).expect("write program");
        // `tallow build` writes the executable next to the source, replacing
        // the `.tl` extension (src/main.rs:10740).
        let artifact = dir.join("prog");
        let mut build = Command::new(env!("CARGO_BIN_EXE_tallow"));
        build
            .args(["build", source.to_str().expect("utf-8 path")])
            .env("TALLOW_ALLOW_DIRECT", "1");
        if keep_ir {
            build.env("TALLOW_KEEP_IR", "1");
        }
        let output = build.output().expect("run tallow build");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "[bridge-overhead] the native build of the '{tag}' program ({calls} calls) failed, so \
             the call was not lowered to the bridge:\n{stderr}"
        );
        assert!(
            artifact.exists(),
            "[bridge-overhead] `tallow build` reported success but produced no executable at \
             {}\nstderr:\n{stderr}",
            artifact.display()
        );
        Fixture {
            dir,
            source,
            artifact,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Proves the compiled leg really goes through the generic bridge.
///
/// `geocode` is not one of the modules with a hand-written emitter, but that is
/// an argument about the source tree, not an assertion about the program that
/// was timed. With the bridge gated off (`TALLOW_GENERIC_STDLIB_BRIDGE=0`) the
/// same source must be refused by name — the pre-bridge verdict. If it ever
/// compiles with the gate off, a hand-written emitter has appeared and the
/// numbers are no longer about the bridge.
///
/// The gate-off build writes to its own source file so it can never clobber the
/// artifact being timed.
fn assert_bridge_is_what_lowers_the_call(fixture: &Fixture) {
    let source = fixture.dir.join("gate-off.tl");
    std::fs::copy(&fixture.source, &source).expect("copy program for the gate-off build");
    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["build", source.to_str().expect("utf-8 path")])
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env("TALLOW_GENERIC_STDLIB_BRIDGE", "0")
        .output()
        .expect("run tallow build with the bridge gated off");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "with TALLOW_GENERIC_STDLIB_BRIDGE=0 the {MODULE}.{METHOD} call still compiled, so \
         something other than the generic bridge lowers it and this file is not measuring the \
         bridge\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains(METHOD),
        "the gate-off refusal must name the method that lost its lowering:\n{stderr}"
    );
}

/// A per-run directory that no concurrent test can share.
fn unique_dir(tag: &str, calls: usize) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut hasher);
    calls.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    std::env::temp_dir().join(format!("tallow-bridge-overhead-{:016x}", hasher.finish()))
}

/// Minimum of [`RUNS`] executions of `command`, with the program's own output
/// checked on every run.
///
/// The check is here rather than in the caller because a duration from a child
/// that did not run the program it claims is not a measurement: a failure to
/// make `calls` calls would show up as a fast run and a small delta.
fn min_of_runs(command: &mut Command, calls: usize, what: &str) -> Duration {
    let mut best: Option<Duration> = None;
    for attempt in 0..RUNS {
        let started = Instant::now();
        let output: Output = command.output().expect(what);
        let elapsed = started.elapsed();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "[{what}] run {attempt} failed\nstdout:\n{}\nstderr:\n{stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            calls.to_string(),
            "[{what}] the program did not report {calls} completed calls, so this is not a \
             timing of {calls} calls\nstderr:\n{stderr}"
        );
        best = Some(match best {
            Some(previous) if previous <= elapsed => previous,
            _ => elapsed,
        });
    }
    best.expect("at least one run")
}

/// Per-call cost the compiled plane pays for one bridged call.
fn bridged_per_call(fixture: &Fixture, calls: usize) -> Duration {
    min_of_runs(
        &mut Command::new(&fixture.artifact),
        calls,
        &format!("bridged #{calls}"),
    )
}

/// Per-call cost the interpreter pays for the same call, from the same source
/// file. `tallow run --interpret` parses and typechecks (~constant, and it
/// cancels) but never compiles or links.
fn interpreted_per_call(fixture: &Fixture, calls: usize) -> Duration {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tallow"));
    command
        .args([
            "run",
            "--interpret",
            fixture.source.to_str().expect("utf-8 path"),
        ])
        .env("TALLOW_ALLOW_DIRECT", "1");
    min_of_runs(&mut command, calls, &format!("interpreted #{calls}"))
}

#[test]
fn bridged_call_is_not_an_order_of_magnitude_above_the_interpreter() {
    let _serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let short = Fixture::prepare("bridge-overhead", BASE_CALLS);
    let long = Fixture::prepare("bridge-overhead", BASE_CALLS + EXTRA_CALLS);

    // Before timing anything: prove the compiled leg is the *bridge* and not
    // some hand-written emitter that happens to lower this module. With the
    // bridge gated off the same source must fail to compile, naming the method.
    // `tallow build` has no interpreter fallback, so this is the same refusal
    // the pre-bridge tree gave, and it costs a codegen pass (it never reaches
    // the linker).
    assert_bridge_is_what_lowers_the_call(&short);

    let bridged_base = bridged_per_call(&short, BASE_CALLS);
    let bridged_long = bridged_per_call(&long, BASE_CALLS + EXTRA_CALLS);
    let interpreted_base = interpreted_per_call(&short, BASE_CALLS);
    let interpreted_long = interpreted_per_call(&long, BASE_CALLS + EXTRA_CALLS);

    assert!(
        bridged_long >= bridged_base,
        "adding {EXTRA_CALLS} calls made the compiled program faster \
         ({bridged_long:?} < {bridged_base:?}); the subtraction is not measuring the loop"
    );
    assert!(
        interpreted_long >= interpreted_base,
        "adding {EXTRA_CALLS} calls made the interpreted program faster \
         ({interpreted_long:?} < {interpreted_base:?}); the subtraction is not measuring the loop"
    );

    let bridged_us = (bridged_long - bridged_base).as_secs_f64() * 1e6 / EXTRA_CALLS as f64;
    let interpreted_us =
        (interpreted_long - interpreted_base).as_secs_f64() * 1e6 / EXTRA_CALLS as f64;
    let delta_us = bridged_us - interpreted_us;

    eprintln!(
        "\n── bridge pure-overhead measurement ──\n\
         binary      {}\n\
         corpus      {MODULE}.{METHOD}(\"Texas\") -> \"{EXPECTED_RESULT}\"\n\
         counts      {BASE_CALLS} vs {} calls, min of {RUNS} runs each, difference / {EXTRA_CALLS}\n\
         bridged     {bridged_us:.3} µs/call   ({bridged_base:?} -> {bridged_long:?})\n\
         interpreted {interpreted_us:.3} µs/call   ({interpreted_base:?} -> {interpreted_long:?})\n\
         delta       {delta_us:+.3} µs/call  ({:.2}x)",
        binary_fingerprint(),
        BASE_CALLS + EXTRA_CALLS,
        bridged_us / interpreted_us,
    );

    // A delta of exactly zero means the two legs are the same program, which is
    // what a silent fallback looks like. The fixtures assert the builds
    // succeeded; this asserts the *numbers* are not identical.
    assert!(
        bridged_us > 0.0 && interpreted_us > 0.0,
        "both planes measured a non-positive per-call cost (bridged {bridged_us:.3} µs, \
         interpreted {interpreted_us:.3} µs); this measurement did not resolve"
    );
    assert!(
        bridged_us < MAX_RATIO_TO_INTERPRETER * interpreted_us,
        "the bridge costs {:.2}x the interpreter per call ({bridged_us:.3} µs vs \
         {interpreted_us:.3} µs); the bound is {MAX_RATIO_TO_INTERPRETER}x",
        bridged_us / interpreted_us,
    );
    assert!(
        bridged_us < BRIDGED_CEILING_US,
        "the bridge costs {bridged_us:.3} µs/call for a call that does no work worth measuring; \
         the ceiling is {BRIDGED_CEILING_US} µs",
    );
}

/// The floor under both numbers: the module's own work, with no plane in the
/// way.
///
/// `stdlib::dispatch` is what *both* the bridge and the interpreter reach. This
/// test times it directly — same function, same argument text, in-process — so
/// `docs/perf/bridge-overhead.md` can split each plane's per-call cost into
/// "the module doing its job" and "the call mechanism around it" instead of
/// attributing the whole delta to marshalling.
///
/// What it includes: the `String` argument allocation (which the bridge also
/// makes, in `decode_argument`), the module and function dispatch, the
/// `trim().to_lowercase()` inside `state_abbrev_of_name`, the scan of the state
/// table, and the two-byte result `String`. What it does not: the bridge's
/// result re-encode (`Vec` + `CString`), the `extern "C"` boundary and the
/// ownership handoff back to codegen — which is exactly the difference this
/// floor exists to let a reader name.
///
/// Debug profile, like both legs it is compared against; a debug/release
/// mismatch would swamp every number here.
#[test]
fn the_module_work_floor_under_both_planes() {
    const CALLS: usize = 20_000;

    let call = || {
        let args = vec![tallow::interp::Value::String("Texas".to_string())];
        match tallow::stdlib::dispatch(MODULE, METHOD, args) {
            Some(Ok(tallow::interp::Value::String(text))) => text.len(),
            other => panic!("[{MODULE}.{METHOD}] dispatch did not answer a String: {other:?}"),
        }
    };

    // Warm the table, the heap and the code paths before timing anything.
    for _ in 0..256 {
        assert_eq!(call(), EXPECTED_RESULT.len());
    }

    let started = Instant::now();
    let mut total = 0usize;
    for _ in 0..CALLS {
        total += call();
    }
    let elapsed = started.elapsed();
    assert_eq!(
        total,
        EXPECTED_RESULT.len() * CALLS,
        "the loop did not do what the timing assumes"
    );

    let per_call_us = elapsed.as_secs_f64() * 1e6 / CALLS as f64;
    eprintln!(
        "\n── module work floor ({CALLS} in-process dispatch calls) ──\n\
         dispatch    {per_call_us:.3} µs/call  ({MODULE}.{METHOD})"
    );
    assert!(
        per_call_us < BRIDGED_CEILING_US,
        "one dispatch of a function that only lowercases one word costs {per_call_us:.3} µs; if \
         that is not cheap, the bridged number above is not measuring the bridge"
    );
}

// ── The ownership path (F1), timed ─────────────────────────────────────────
//
// F1 (`735a689`) gave a bridged `String` result an owner: when the binding
// does not escape its block, codegen releases the runtime's buffer at the end
// of that block. Two things are new and both can cost something — a *compile
// time* escape scan over the declaring block, and one *run time* release per
// call. The escape scan cannot be seen in a µs/call figure (it is the same
// scan whether the program loops 200 times or 2200), so what this case
// measures at run time is the release, on the case where it fires.

/// `calls` iterations of the ownership path: a bridged `String` result that is
/// consumed immediately (printed) and released when the loop body ends.
///
/// `print(s)` is a *read* — the escape scan's `Call` arm treats `print`'s
/// arguments as consumed — so the binding does not escape and F1's release
/// fires. That is asserted against the emitted IR below, not assumed from the
/// source: a case that silently stopped releasing would measure the leak path
/// and report it as the fix.
fn ownership_program(calls: usize) -> String {
    format!(
        r#"import tallow.{MODULE}

fn main() {{
    var i = 0
    while i < {calls} {{
        let s = {MODULE}.{METHOD}("Texas")
        print(s)
        i = i + 1
    }}
}}
"#
    )
}

/// The control: the same loop with the same number of writes and no bridged
/// call. Subtracting it is what makes "the ownership path is what is timed" a
/// measurement rather than a claim — what is left is the bridged call (module
/// work + marshalling + the release), with the loop and the write removed.
fn print_control_program(calls: usize) -> String {
    format!(
        r#"fn main() {{
    var i = 0
    while i < {calls} {{
        print("{EXPECTED_RESULT}")
        i = i + 1
    }}
}}
"#
    )
}

/// F1's RSS shape at [`RSS_CALLS`] calls. The payload is what makes RSS a
/// signal: `state_from_name` returns two bytes, so a leak in the timed case
/// would be invisible in RSS no matter how long the loop ran.
fn ownership_rss_program(calls: usize, payload: &str) -> String {
    format!(
        r#"import tallow.{MODULE}

fn main() {{
    let payload = "{payload}"
    var total = 0
    var i = 0
    while i < {calls} {{
        let k = {MODULE}.{RSS_METHOD}(payload)
        total = total + k.len()
        i = i + 1
    }}
    print(total)
}}
"#
    )
}

/// Minimum of [`RUNS`] executions, checking that the program printed `calls`
/// lines of `line`.
///
/// These programs have no accumulator to print, so the output is the proof the
/// loop ran: a run that printed fewer results, or a result that is not what
/// the module answers, fails instead of reporting a small delta.
fn min_of_line_runs(command: &mut Command, calls: usize, line: &str, what: &str) -> Duration {
    let mut best: Option<Duration> = None;
    for attempt in 0..RUNS {
        let started = Instant::now();
        let output: Output = command.output().expect(what);
        let elapsed = started.elapsed();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "[{what}] run {attempt} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let printed: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            printed.len(),
            calls,
            "[{what}] the program printed {} line(s) for {calls} iterations, so this is not a \
             timing of {calls} consumed results\nstderr:\n{stderr}",
            printed.len()
        );
        assert!(
            printed.iter().all(|got| got.trim() == line),
            "[{what}] a consumed result printed something other than {line:?} (first five: {:?})",
            &printed[..printed.len().min(5)]
        );
        best = Some(match best {
            Some(previous) if previous <= elapsed => previous,
            _ => elapsed,
        });
    }
    best.expect("at least one run")
}

/// Resident set of `pid`, in KiB.
fn resident_kb(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    let page_kb = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64 / 1024;
    Some(resident_pages * page_kb)
}

/// What one `tallow_free_string` — the instruction F1 emits — costs.
///
/// The end-to-end planes cannot resolve this: the release is one deallocation
/// against a ~4 µs call, well inside the run-to-run spread of the two-count
/// subtraction. So it is timed directly: allocate the results first, then time
/// the frees alone, so neither the bridge call nor the module's work is inside
/// the timed region.
fn free_cost_per_call_ns() -> f64 {
    const CALLS: usize = 200_000;

    let module = CString::new(MODULE).expect("module name");
    let method = CString::new(METHOD).expect("method name");
    let argument = CString::new("Texas").expect("argument");
    let argv = [argument.as_ptr()];

    let mut results: Vec<*mut c_char> = Vec::with_capacity(CALLS);
    for _ in 0..CALLS {
        let pointer = tallow_stdlib_call(
            module.as_ptr(),
            method.as_ptr(),
            1,
            argv.as_ptr() as *const *const c_char,
        );
        assert!(
            !pointer.is_null(),
            "the bridge refused the free probe's call to {MODULE}.{METHOD}"
        );
        results.push(pointer);
    }

    let started = Instant::now();
    for pointer in results.drain(..) {
        tallow_free_string(pointer);
    }
    started.elapsed().as_secs_f64() * 1e9 / CALLS as f64
}

/// **The cost of F1's ownership rule, and that it holds at 2000 calls.**
///
/// Three numbers, all on the compiled plane of one binary:
///
/// 1. **the ownership loop** — a bridged `String` result consumed immediately
///    (printed) and released at the end of every iteration, differenced over
///    2000 calls exactly as the planes above are;
/// 2. **its control** — the same writes with no bridged call, so the print and
///    the loop can be removed rather than hand-waved;
/// 3. **the release itself** — `tallow_free_string`, timed directly, because
///    the two-count subtraction cannot resolve a deallocation.
///
/// The RSS leg is F1's own shape at 2000 calls instead of 600 (2000 × 32 KiB =
/// 64 MiB if anything is un-released).
#[test]
fn bridged_string_ownership_path_is_bounded_and_released() {
    let _serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let owned_base =
        Fixture::prepare_source("ownership", BASE_CALLS, ownership_program(BASE_CALLS), true);
    let owned_long = Fixture::prepare_source(
        "ownership",
        BASE_CALLS + EXTRA_CALLS,
        ownership_program(BASE_CALLS + EXTRA_CALLS),
        false,
    );
    let control_base = Fixture::prepare_source(
        "print-control",
        BASE_CALLS,
        print_control_program(BASE_CALLS),
        false,
    );
    let control_long = Fixture::prepare_source(
        "print-control",
        BASE_CALLS + EXTRA_CALLS,
        print_control_program(BASE_CALLS + EXTRA_CALLS),
        false,
    );

    // The case is about the ownership path only if the release is in the
    // program. `TALLOW_KEEP_IR=1` leaves the IR beside the artifact; exactly
    // one release means the bridged result — and not the program's own string
    // argument — is what gets freed, once, per iteration.
    let ir = std::fs::read_to_string(owned_base.dir.join("prog.ll"))
        .expect("TALLOW_KEEP_IR=1 promises prog.ll next to the artifact");
    assert_eq!(
        ir.matches("call void @tallow_free_string").count(),
        1,
        "the ownership program must release exactly one value — the bridged String result it \
         binds in the loop body; a different count means F1's rule moved and this case no longer \
         measures the release"
    );

    let owned_base_time = min_of_line_runs(
        &mut Command::new(&owned_base.artifact),
        BASE_CALLS,
        EXPECTED_RESULT,
        "ownership #200",
    );
    let owned_long_time = min_of_line_runs(
        &mut Command::new(&owned_long.artifact),
        BASE_CALLS + EXTRA_CALLS,
        EXPECTED_RESULT,
        "ownership #2200",
    );
    let control_base_time = min_of_line_runs(
        &mut Command::new(&control_base.artifact),
        BASE_CALLS,
        EXPECTED_RESULT,
        "print-control #200",
    );
    let control_long_time = min_of_line_runs(
        &mut Command::new(&control_long.artifact),
        BASE_CALLS + EXTRA_CALLS,
        EXPECTED_RESULT,
        "print-control #2200",
    );

    assert!(
        owned_long_time >= owned_base_time,
        "adding {EXTRA_CALLS} calls made the compiled program faster \
         ({owned_long_time:?} < {owned_base_time:?}); the subtraction is not measuring the loop"
    );
    // The control has no such guard, and that is the measurement: 2000 buffered
    // writes cost less than the ±0.2 ms of start-up jitter between two runs of a
    // ~4 ms process, so its difference can come out *negative*. That is the
    // control saying "printing and looping are below this method's resolution",
    // not the control failing — clamping it at zero is the honest reading, and
    // a control that ever became expensive would arrive as a positive number and
    // be subtracted.
    let per_call = |long: Duration, base: Duration| -> f64 {
        let delta = long.as_secs_f64() - base.as_secs_f64();
        delta * 1e6 / EXTRA_CALLS as f64
    };
    let owned_us = per_call(owned_long_time, owned_base_time);
    let control_us = per_call(control_long_time, control_base_time);
    let ownership_us = owned_us - control_us.max(0.0);

    let free_ns = free_cost_per_call_ns();

    // ── RSS: the same ownership shape, 2000 calls, 32 KiB results ───────────
    let unit = "1 main st, austin tx 78701 ";
    let payload = unit.repeat(RSS_PAYLOAD_BYTES / unit.len());
    let rss_fixture = Fixture::prepare_source(
        "ownership-rss",
        RSS_CALLS,
        ownership_rss_program(RSS_CALLS, &payload),
        false,
    );

    let mut child = Command::new(&rss_fixture.artifact)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the RSS program");
    let pid = child.id();
    let mut samples: Vec<u64> = Vec::new();
    loop {
        if let Some(kb) = resident_kb(pid) {
            samples.push(kb);
        }
        match child.try_wait().expect("wait on the RSS program") {
            Some(_) => break,
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    let output = child.wait_with_output().expect("collect the RSS program");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the RSS program failed:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let total: u64 = stdout.trim().parse().unwrap_or_else(|_| {
        panic!("the RSS program must print the summed result length, printed {stdout:?}")
    });
    assert!(
        total >= (RSS_CALLS * (payload.len() / 2)) as u64
            && total <= (RSS_CALLS * (payload.len() * 2)) as u64,
        "the RSS program summed {total} bytes over {RSS_CALLS} calls on a {}-byte payload; an \
         empty or corrupted result is what a premature release looks like, and it would also \
         make the RSS series meaningless",
        payload.len()
    );
    assert!(
        samples.len() >= 20,
        "too few RSS samples ({}) to make a claim about growth",
        samples.len()
    );

    let tenth = (samples.len() / 10).max(1);
    let baseline = *samples[..tenth].iter().max().expect("samples");
    let final_high = *samples[samples.len() - tenth..]
        .iter()
        .max()
        .expect("samples");
    let growth = final_high.saturating_sub(baseline);
    let series: Vec<u64> = samples.iter().copied().step_by(500).collect();

    eprintln!(
        "\n── bridged String ownership path (F1) ──\n\
         binary      {}\n\
         corpus      {MODULE}.{METHOD}(\"Texas\") -> \"{EXPECTED_RESULT}\", consumed by print\n\
         counts      {BASE_CALLS} vs {} iterations, min of {RUNS} runs each, difference / {EXTRA_CALLS}\n\
         loop        {owned_us:.3} µs/call   ({owned_base_time:?} -> {owned_long_time:?})\n\
         control     {control_us:.3} µs/call   (same loop, print only; {control_base_time:?} -> {control_long_time:?})\n\
         ownership   {ownership_us:.3} µs/call  (loop - control: bridge + marshalling + release)\n\
         release     {free_ns:.1} ns/call      (tallow_free_string, timed directly)\n\
         rss         +{growth} KiB over {RSS_CALLS} calls returning {} bytes (baseline {baseline} KiB, peak {final_high} KiB, {} samples)\n\
         rss series  {series:?}",
        binary_fingerprint(),
        BASE_CALLS + EXTRA_CALLS,
        payload.len(),
        samples.len(),
    );

    assert!(
        ownership_us > 0.0,
        "the ownership loop cost no more than printing a literal ({ownership_us:.3} µs), so the \
         bridged call is not what is being timed"
    );
    assert!(
        owned_us < OWNERSHIP_CEILING_US,
        "a bridged String result consumed immediately costs {owned_us:.3} µs/call, over the \
         {OWNERSHIP_CEILING_US} µs ceiling (2x the measured value)"
    );
    assert!(
        free_ns < FREE_CEILING_NS,
        "one tallow_free_string took {free_ns:.1} ns against a {FREE_CEILING_NS} ns fence; the \
         release is supposed to be one deallocation, not a scan"
    );
    assert!(
        growth < OWNERSHIP_RSS_CEILING_KB,
        "RSS grew {growth} KiB over {RSS_CALLS} bridged calls returning a {}-byte String \
         (baseline {baseline} KiB, peak {final_high} KiB, ceiling {OWNERSHIP_RSS_CEILING_KB} KiB, \
         {} samples); the result buffer is not being released. Sampled series (every 500th, KiB): \
         {series:?}",
        payload.len(),
        samples.len()
    );
}

/// `sha256` of the binary under test, so a number in a report can be tied to
/// the artifact that produced it.
fn binary_fingerprint() -> String {
    use sha2::{Digest, Sha256};
    let path = Path::new(env!("CARGO_BIN_EXE_tallow"));
    match std::fs::read(path) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("{} sha256:{hex}", path.display())
        }
        Err(error) => format!("{} (unreadable: {error})", path.display()),
    }
}
