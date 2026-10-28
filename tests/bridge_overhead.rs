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

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

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
        let dir = unique_dir(tag, calls);
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        let source = dir.join("prog.tl");
        std::fs::write(&source, program(calls)).expect("write program");
        // `tallow build` writes the executable next to the source, replacing
        // the `.tl` extension (src/main.rs:10740).
        let artifact = dir.join("prog");
        let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
            .args(["build", source.to_str().expect("utf-8 path")])
            .env("TALLOW_ALLOW_DIRECT", "1")
            .output()
            .expect("run tallow build");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "[bridge-overhead] the native build of the {calls}-call program failed, so the \
             bridge did not lower {MODULE}.{METHOD}:\n{stderr}"
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
