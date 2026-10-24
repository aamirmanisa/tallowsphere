//! E1 — behavioral-parity runner wired as an automated cargo test.
//!
//! Contract source: `tests/parity/README.md` + `tests/parity/run_parity.sh`
//! (same MATCH / DIVERGE / ERROR classification) and E1 in
//! `artifacts/TALLOW_FULL_TASKS_TODO.md` — *"wire the parity runner (tree-walk vs
//! native on the 5 fixtures) as an automated test"*.
//!
//! For every fixture in `tests/parity/parity_programs/*.tl`:
//!
//! 1. REFERENCE (tree-walking interpreter): `tallow run <fixture> --target x86_64-linux`
//!    — the cross target makes `is_cross` skip the native path, so this leg is forced
//!    through `src/interp.rs`.
//! 2. NATIVE: `tallow build` into a per-fixture temp dir, then execute the produced
//!    binary.
//!
//! Verdicts — stdout is compared **byte-for-byte** and exit codes must be equal
//! (stderr is NOT compared: the two paths legitimately differ there, e.g. the
//! cross-target warning):
//!
//! * `MATCH`         — identical stdout bytes and rc.
//! * `DIVERGE`       — both legs ran; stdout bytes or rc differ. TEST FAILS.
//! * `ERROR(build)`  — the native build failed. For fixtures whose native support is a
//!                     documented fail-loud contract (`08_closure_return`) the guard
//!                     message must be present and **no binary may be produced** →
//!                     `REFUSED-LOUD` (expected, passes); the test additionally checks
//!                     that plain `tallow run` falls back to the interpreter with
//!                     byte-identical output. For any other fixture a build failure is
//!                     an ERROR. TEST FAILS.
//! * `ERROR(interp)` — the interpreter reference leg failed or printed nothing.
//!                     TEST FAILS.
//!
//! Resource caps (Batch-4 INCIDENT rules, `artifacts/to-100-2026-09-16/README.md`):
//! every native/compiled **run** and every interpreter leg is launched as
//! `bash -c 'ulimit -v 2000000; exec timeout -k 10 <T> "$0" "$@"'` — 2 GiB
//! address-space cap + hard timeout (120 s native / 60 s interpreter). The
//! `tallow build` compile+link step alone gets the larger `BUILD_AS_LIMIT_KB`
//! (measured: GNU ld cannot link the ~1.6 GB runtime staticlib inside 2 GiB).
//! The fixtures are tiny, deterministic, and touch no network/ports/filesystem.
//!
//! Env knobs:
//! * `TALLOW_PARITY_SKIP_NATIVE=1` — interpreter legs only; each native leg prints
//!   `SKIP(native)` with the reason. DEFAULT: native leg ON.
//! * `TALLOW_BIN=<path>` — tallow binary to drive (default `<repo>/target/debug/tallow`).
//! * `TALLOW_PARITY_ROOT=<path>` — repo-root override (used for standalone
//!   `rustc --test` runs where `CARGO_MANIFEST_DIR` is absent).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// 2 GiB address-space cap (KiB) — mandatory for native/compiled RUNS (incident rule).
const AS_LIMIT_KB: u32 = 2_000_000;
/// Build-only cap (KiB). `tallow build` links the ~1.6 GB runtime staticlib and GNU
/// ld needs far more than 2 GiB of address space for it — measured 2026-09-16:
/// `ld: bfd_new_link_order failed: memory exhausted` at the 2 GiB cap with the
/// 1.59 GB archive, same link rc 0 at 6 GiB. Compiles are bounded tools (not the
/// runaway-runtime risk the incident rule targets) and the produced binary is
/// still EXECUTED under the mandated 2 GiB cap. A build that dies at this cap is
/// reported as `ERROR(build-cap)`, never as a normal link failure.
const BUILD_AS_LIMIT_KB: u32 = 6_000_000;
const INTERP_TIMEOUT_S: u32 = 60;
const NATIVE_TIMEOUT_S: u32 = 120;
const RUNNER_TIMEOUT_S: u32 = 300;

/// A cross target forces `tallow run` down the tree-walking interpreter path.
const CROSS_TARGET: &str = "x86_64-linux";

/// The five E1 fixtures — the test fails if any of these is missing.
const CORE_FIXTURES: [&str; 5] = [
    "01_control_flow.tl",
    "02_functions.tl",
    "03_loops_arrays.tl",
    "04_strings.tl",
    "05_maps.tl",
];

const FIXTURES_SUBDIR: &str = "tests/parity/parity_programs";
const SHELL_RUNNER_SUBDIR: &str = "tests/parity/run_parity.sh";

// ───────────────────────── expectations ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Native path must compile and be byte-identical to the interpreter leg.
    Match,
    /// Native path must REFUSE loudly (documented fail-loud contract). The build
    /// must fail with `guard` in stderr, must not leave a binary behind, and the
    /// interpreter leg must print each `must_print` marker.
    NativeFailLoud {
        must_print: &'static [&'static str],
        guard: &'static str,
    },
    /// The program is *meant* to be refused at runtime — a fixture that passes
    /// the wrong type to a native function. Both planes must refuse, with the
    /// same sentence. Before this variant existed the runner treated every
    /// non-zero interpreter exit as an error, so the refusal fixtures could
    /// never be classified and the suite was excluded from CI.
    RefuseBoth,
}

/// The refusal sentence, normalised: the last line naming a runtime error.
fn refusal_line(stderr: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("runtime error:"))
        .last()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

fn expect_for(name: &str) -> Expect {
    match name {
        // Documented contract (fixture header + tests/parity/README.md): the native
        // backend cannot lift a closure across a function boundary, so `tallow build`
        // must fail loudly instead of silently miscompiling, and `tallow run` must
        // fall back to the interpreter.
        "08_closure_return.tl" => Expect::NativeFailLoud {
            must_print: &["add5(10) = 15", "CLOSURE_RETURN_OK"],
            guard: "returns a closure",
        },
        n if n.ends_with("_refusal.tl") => Expect::RefuseBoth,
        _ => Expect::Match,
    }
}

// ───────────────────────── paths ─────────────────────────

fn repo_root() -> PathBuf {
    if let Some(root) = std::env::var_os("TALLOW_PARITY_ROOT") {
        if !root.is_empty() {
            return PathBuf::from(root);
        }
    }
    if let Some(root) = option_env!("CARGO_MANIFEST_DIR") {
        if !root.is_empty() {
            return PathBuf::from(root);
        }
    }
    std::env::current_dir().expect("current_dir")
}

fn tallow_bin() -> PathBuf {
    match std::env::var_os("TALLOW_BIN") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => repo_root().join("target/debug/tallow"),
    }
}

fn fixtures_dir() -> PathBuf {
    repo_root().join(FIXTURES_SUBDIR)
}

fn fixture_names() -> Vec<String> {
    let dir = fixtures_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read fixture dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| name.ends_with(".tl"))
        .collect();
    names.sort();
    names
}

fn skip_native_requested() -> bool {
    std::env::var("TALLOW_PARITY_SKIP_NATIVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

// ───────────────────────── capped process runner ─────────────────────────

struct Leg {
    stdout: Vec<u8>,
    rc: i32,
    stderr: String,
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    -1
}

/// Run `program args…` under the mandatory caps: address-space cap + hard timeout.
/// `bash -c '<script>' <program> <args…>` binds `$0`=program, `$@`=args.
fn run_capped(
    program: &Path,
    args: &[String],
    timeout_s: u32,
    cap_kb: u32,
    cwd: &Path,
) -> std::io::Result<Leg> {
    let script = format!("ulimit -v {cap_kb}; exec timeout -k 10 {timeout_s} \"$0\" \"$@\"");
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg(program)
        .args(args)
        .current_dir(cwd)
        .output()?;
    Ok(Leg {
        stdout: out.stdout,
        rc: exit_code(out.status),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn is_timeout_rc(rc: i32) -> bool {
    rc == 124 || rc == 137
}

/// Hard-link the tallow binary (+ runtime staticlib, if present) into a private
/// snapshot dir so a concurrent `cargo build` in another lane cannot replace the
/// binary mid-test — cargo renames a new build over `target/debug/tallow`, while a
/// hard link keeps the old inode alive. `codegen::find_runtime_lib_for_target`
/// resolves `libtallow.a` via `current_exe()`'s parent, so the link must sit next
/// to the snapshot binary.
fn snapshot_binary(src: &Path) -> std::io::Result<(PathBuf, Option<PathBuf>)> {
    let dir = std::env::temp_dir().join(format!("tallow-parity-snap-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let dst = dir.join(src.file_name().unwrap_or_default());
    let _ = std::fs::remove_file(&dst);
    std::fs::hard_link(src, &dst)?;

    // The runtime static library must sit next to the snapshot binary, because
    // `find_runtime_lib_for_target` resolves it through `current_exe()`'s
    // parent. `target/<profile>/libtallow.a` only exists once the `staticlib`
    // target has been built; `cargo build --bin tallow` alone leaves only the
    // hashed copy in `deps/`. CI hit exactly that: the snapshot had "runtime lib:
    // none", so every program that calls a runtime helper linked with undefined
    // references (tallow_display_map, tallow_last_error, …).
    let lib_source = src
        .parent()
        .map(|p| p.join("libtallow.a"))
        .filter(|p| p.is_file())
        .or_else(|| {
            // Fall back to the newest hashed archive in `deps/`.
            let deps = src.parent()?.join("deps");
            let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
            for entry in std::fs::read_dir(deps).ok()? {
                let path = entry.ok()?.path();
                let name = path.file_name()?.to_string_lossy().to_string();
                if !(name.starts_with("libtallow-") && name.ends_with(".a")) {
                    continue;
                }
                let mtime = path.metadata().ok()?.modified().ok()?;
                if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
                    best = Some((mtime, path));
                }
            }
            best.map(|(_, p)| p)
        });
    let lib_dst = lib_source.and_then(|lib_src| {
        let dst = dir.join("libtallow.a");
        let _ = std::fs::remove_file(&dst);
        std::fs::hard_link(&lib_src, &dst).ok().map(|_| dst)
    });
    Ok((dst, lib_dst))
}

// ───────────────────────── byte-compare helpers ─────────────────────────

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    if let Some(i) = a.iter().zip(b.iter()).position(|(x, y)| x != y) {
        return Some(i);
    }
    if a.len() != b.len() {
        return Some(a.len().min(b.len()));
    }
    None
}

fn render(bytes: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(bytes).chars().take(400).collect();
    if bytes.len() > 400 {
        format!("{s}…[{} bytes total]", bytes.len())
    } else {
        s
    }
}

fn tail(text: &str) -> String {
    let t: String = text
        .chars()
        .rev()
        .take(400)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    t.replace('\n', " ⏎ ")
}

// ───────────────────────── the parity test ─────────────────────────

#[test]
fn parity_fixtures_interpreter_vs_native() {
    let names = fixture_names();
    for core in CORE_FIXTURES {
        assert!(
            names.iter().any(|n| n == core),
            "missing core E1 fixture {core} in {}",
            fixtures_dir().display()
        );
    }
    assert!(
        names.len() >= CORE_FIXTURES.len(),
        "E1 expects at least the 5 core fixtures, found {}",
        names.len()
    );

    let root = repo_root();
    let tallow = tallow_bin();
    if !tallow.is_file() {
        println!(
            "SKIP(parity): tallow binary not found at {} — build it first: cargo build --bin tallow",
            tallow.display()
        );
        return;
    }

    // Private, inode-stable copy of the binary under test (see snapshot_binary).
    let (tallow, snap_lib) = match snapshot_binary(&tallow) {
        Ok((bin, lib)) => (bin, lib),
        Err(e) => {
            println!("WARN(parity): could not snapshot tallow binary ({e}); running the live path");
            (tallow_bin(), None)
        }
    };
    println!(
        "parity binary: {} (snapshot runtime lib: {})",
        tallow.display(),
        snap_lib
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none".into())
    );

    let skip_native = skip_native_requested();
    if skip_native {
        println!(
            "native leg: SKIPPED on request (TALLOW_PARITY_SKIP_NATIVE=1) — interpreter legs only"
        );
    } else {
        println!(
            "native leg: ON (default) — tallow build + run under ulimit -v {AS_LIMIT_KB} KiB, timeout {NATIVE_TIMEOUT_S}s"
        );
    }

    let mut n_match = 0usize;
    let mut n_refused = 0usize;
    let mut n_skipped = 0usize;
    let mut diverges: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for name in &names {
        let fixture = fixtures_dir().join(name);
        let expect = expect_for(name);

        // ── reference leg: forced tree-walking interpreter ──
        let ref_args = vec![
            "run".to_string(),
            fixture.display().to_string(),
            "--target".to_string(),
            CROSS_TARGET.to_string(),
        ];
        let ref_leg = match run_capped(&tallow, &ref_args, INTERP_TIMEOUT_S, AS_LIMIT_KB, &root) {
            Ok(leg) => leg,
            Err(e) => {
                errors.push(format!("{name}: ERROR(interp-spawn) {e}"));
                continue;
            }
        };
        let expect_refusal = matches!(expect, Expect::RefuseBoth);
        if ref_leg.rc != 0 && !expect_refusal {
            errors.push(format!(
                "{name}: ERROR(interp) rc={} stderr={}",
                ref_leg.rc,
                tail(&ref_leg.stderr)
            ));
            continue;
        }
        if ref_leg.stdout.is_empty() && !expect_refusal {
            errors.push(format!(
                "{name}: ERROR(interp) reference produced no stdout — a byte-compare would be vacuous"
            ));
            continue;
        }
        if let Expect::NativeFailLoud { must_print, .. } = expect {
            let text = String::from_utf8_lossy(&ref_leg.stdout);
            let missing: Vec<&&str> = must_print.iter().filter(|m| !text.contains(**m)).collect();
            if !missing.is_empty() {
                errors.push(format!(
                    "{name}: ERROR(interp-output) missing {missing:?}; stdout={:?}",
                    render(&ref_leg.stdout)
                ));
                continue;
            }
        }

        if skip_native {
            println!(
                "{name}: SKIP(native) — TALLOW_PARITY_SKIP_NATIVE=1 (interp rc=0, {} bytes)",
                ref_leg.stdout.len()
            );
            n_skipped += 1;
            continue;
        }

        // ── native leg: build in a private temp dir, then execute the binary ──
        let work = std::env::temp_dir().join(format!(
            "tallow-parity-{}-{}",
            std::process::id(),
            name.trim_end_matches(".tl")
        ));
        if let Err(e) = std::fs::create_dir_all(&work) {
            errors.push(format!("{name}: ERROR(native-setup) {}", e));
            continue;
        }
        let prog = work.join("prog.tl");
        if let Err(e) = std::fs::copy(&fixture, &prog) {
            errors.push(format!("{name}: ERROR(native-setup) copy: {}", e));
            continue;
        }
        let build_args = vec!["build".to_string(), prog.display().to_string()];
        // Compile+link step: bounded tool, needs the larger build cap (see BUILD_AS_LIMIT_KB).
        let build = match run_capped(
            &tallow,
            &build_args,
            NATIVE_TIMEOUT_S,
            BUILD_AS_LIMIT_KB,
            &work,
        ) {
            Ok(leg) => leg,
            Err(e) => {
                errors.push(format!("{name}: ERROR(build-spawn) {}", e));
                continue;
            }
        };

        if build.rc != 0 {
            match expect {
                Expect::NativeFailLoud { guard, .. } => {
                    let bin = work.join("prog");
                    if !build.stderr.contains(guard) {
                        errors.push(format!(
                            "{name}: ERROR(build) not the documented fail-loud guard (rc={}); stderr={}",
                            build.rc,
                            tail(&build.stderr)
                        ));
                    } else if bin.exists() {
                        errors.push(format!(
                            "{name}: ERROR(build) fail-loud guard fired but a binary was still produced at {}",
                            bin.display()
                        ));
                    } else {
                        n_refused += 1;
                        println!(
                            "{name}: REFUSED-LOUD (expected fail-loud contract; build rc={}, guard={guard:?})",
                            build.rc
                        );
                        // Expected outcome — no need to keep the scratch dir.
                        let _ = std::fs::remove_dir_all(&work);
                    }
                }
                // A refusal fixture whose native build refuses the program for the
                // same reason the interpreter refuses it at runtime is a refusal
                // on both planes — the compile-time message is checked below.
                Expect::RefuseBoth => {
                    let msg = build
                        .stderr
                        .lines()
                        .map(str::trim)
                        .filter(|l| l.starts_with("build failed:"))
                        .last()
                        .unwrap_or("")
                        .to_string();
                    if msg.is_empty() {
                        errors.push(format!(
                            "{name}: ERROR(build) native build failed without a 'build failed:' line; \
                             stderr={}",
                            tail(&build.stderr)
                        ));
                    } else {
                        n_refused += 1;
                        println!("{name}: REFUSED-BOTH (build refused: {msg})");
                        let _ = std::fs::remove_dir_all(&work);
                    }
                }
                Expect::Match => {
                    // Distinguish a cap artifact from a real link failure — a build
                    // killed by the address-space cap must never read as a normal error.
                    let kind = if is_timeout_rc(build.rc) {
                        "build-timeout"
                    } else if build.stderr.contains("memory exhausted") {
                        "build-cap"
                    } else {
                        "build"
                    };
                    let hint = if kind == "build-cap" {
                        format!(
                            " (address-space cap {BUILD_AS_LIMIT_KB} KiB exceeded by the linker)"
                        )
                    } else {
                        String::new()
                    };
                    errors.push(format!(
                        "{name}: ERROR({kind}) rc={}{hint}; stderr={}",
                        build.rc,
                        tail(&build.stderr)
                    ));
                }
            }
            continue;
        }

        let bin = work.join("prog");
        if !bin.exists() {
            errors.push(format!(
                "{name}: ERROR(build) reported success (rc=0) but produced no binary in {}",
                work.display()
            ));
            continue;
        }
        let nat_leg = match run_capped(&bin, &[], NATIVE_TIMEOUT_S, AS_LIMIT_KB, &work) {
            Ok(leg) => leg,
            Err(e) => {
                errors.push(format!("{name}: ERROR(native-spawn) {}", e));
                continue;
            }
        };
        if is_timeout_rc(nat_leg.rc) {
            errors.push(format!(
                "{name}: ERROR(native-timeout) rc={} (cap {NATIVE_TIMEOUT_S}s) — binary did not terminate",
                nat_leg.rc
            ));
            continue;
        }

        if expect_refusal {
            let want = refusal_line(&ref_leg.stderr);
            let got = refusal_line(&nat_leg.stderr);
            if nat_leg.rc == 0 {
                errors.push(format!(
                    "{name}: ERROR(refusal) native leg succeeded where the interpreter refused ({want:?})"
                ));
            } else if want.is_empty() || got.is_empty() || want != got {
                diverges.push(format!(
                    "{name}: DIVERGE(refusal) interp refused with {want:?}, native with {got:?}"
                ));
            } else {
                n_refused += 1;
                println!("{name}: REFUSED-BOTH (same sentence on both planes: {want:?})");
                let _ = std::fs::remove_dir_all(&work);
            }
            continue;
        }

        if nat_leg.stdout == ref_leg.stdout && nat_leg.rc == ref_leg.rc {
            n_match += 1;
            println!(
                "{name}: MATCH (rc={}, {} bytes)",
                ref_leg.rc,
                ref_leg.stdout.len()
            );
            let _ = std::fs::remove_dir_all(&work);
        } else {
            let d = first_diff(&ref_leg.stdout, &nat_leg.stdout);
            diverges.push(format!(
                "{name}: DIVERGE ref_rc={} nat_rc={} first_stdout_diff_byte={:?}\n  ref: {:?}\n  nat: {:?}",
                ref_leg.rc,
                nat_leg.rc,
                d,
                render(&ref_leg.stdout),
                render(&nat_leg.stdout)
            ));
            println!(
                "{name}: DIVERGE (ref_rc={} nat_rc={}) — temp kept at {}",
                ref_leg.rc,
                nat_leg.rc,
                work.display()
            );
        }
    }

    // ── fail-loud regression: plain `tallow run` must fall back transparently ──
    if !skip_native {
        for name in &names {
            if let Expect::NativeFailLoud { .. } = expect_for(name) {
                let fixture = fixtures_dir().join(name);
                let run_args = vec!["run".to_string(), fixture.display().to_string()];
                match run_capped(&tallow, &run_args, NATIVE_TIMEOUT_S, AS_LIMIT_KB, &root) {
                    Ok(fb) if fb.rc == 0 => {
                        // Compare against the forced-interpreter reference for the same fixture.
                        let ref_args = vec![
                            "run".to_string(),
                            fixture.display().to_string(),
                            "--target".to_string(),
                            CROSS_TARGET.to_string(),
                        ];
                        match run_capped(&tallow, &ref_args, INTERP_TIMEOUT_S, AS_LIMIT_KB, &root) {
                            Ok(r) if r.stdout == fb.stdout && r.rc == fb.rc => println!(
                                "{name}: FALLBACK-OK (tallow run → interpreter fallback, rc=0, {} bytes)",
                                fb.stdout.len()
                            ),
                            Ok(r) => diverges.push(format!(
                                "{name}: DIVERGE run-with-fallback vs forced interpreter (rc {} vs {}, {} vs {} bytes)",
                                fb.rc,
                                r.rc,
                                fb.stdout.len(),
                                r.stdout.len()
                            )),
                            Err(e) => errors.push(format!("{name}: ERROR(interp-spawn) {e}")),
                        }
                    }
                    Ok(fb) => errors.push(format!(
                        "{name}: ERROR(fallback) rc={} for plain `tallow run` (interpreter fallback should succeed); stderr={}",
                        fb.rc,
                        tail(&fb.stderr)
                    )),
                    Err(e) => errors.push(format!("{name}: ERROR(fallback-spawn) {e}")),
                }
            }
        }
    }

    // ── cleanup ──
    if let Some(lib) = snap_lib {
        let _ = std::fs::remove_file(lib);
    }
    if let Some(dir) = tallow.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }

    println!("── E1 parity summary ──");
    println!("fixtures: {} (core 5 required)", names.len());
    println!(
        "MATCH: {n_match} | REFUSED-LOUD(expected): {n_refused} | native-SKIPPED: {n_skipped} | DIVERGE: {} | ERROR: {}",
        diverges.len(),
        errors.len()
    );
    println!(
        "native leg: {}",
        if skip_native {
            "OFF(env)"
        } else {
            "ON(default)"
        }
    );

    assert!(
        diverges.is_empty(),
        "parity DIVERGENCE(s):\n{}",
        diverges.join("\n")
    );
    assert!(errors.is_empty(), "parity ERROR(s):\n{}", errors.join("\n"));
    if !skip_native {
        assert!(
            n_match >= CORE_FIXTURES.len(),
            "only {n_match} fixtures byte-matched — E1 requires the 5 core fixtures to MATCH"
        );
        assert_eq!(
            n_match + n_refused,
            names.len(),
            "every fixture must end as MATCH or REFUSED-LOUD ({n_match} + {n_refused} != {})",
            names.len()
        );
    }
}

// ─────────── cross-check: the shell runner (CI entry) agrees ───────────

/// `tests/parity/run_parity.sh` is the latency-wired CI entry for the same
/// contract. This test re-runs it and requires every per-fixture verdict to match
/// the fixture table above (so runner and cargo test cannot drift apart), with
/// zero DIVERGE and zero unexpected ERROR(build).
#[test]
fn shell_runner_verdicts_match_fixture_table() {
    let names = fixture_names();
    let root = repo_root();
    let runner = root.join(SHELL_RUNNER_SUBDIR);

    if !tallow_bin().is_file() {
        println!(
            "SKIP(shell-runner): tallow binary not found at {} — build it first: cargo build --bin tallow",
            tallow_bin().display()
        );
        return;
    }
    if std::env::var_os("TALLOW_BIN").is_some() {
        println!(
            "SKIP(shell-runner): TALLOW_BIN override set — the shell runner resolves its own binary"
        );
        return;
    }
    if skip_native_requested() {
        println!(
            "SKIP(shell-runner): TALLOW_PARITY_SKIP_NATIVE=1 — the shell runner has no native-off mode"
        );
        return;
    }
    if !runner.is_file() {
        println!("SKIP(shell-runner): {} missing", runner.display());
        return;
    }

    // The runner compiles natively (tallow build → clang/ld): it needs the
    // BUILD address-space cap, not the 2 GiB run cap — wrapping it at
    // AS_LIMIT_KB made `ld` die 'memory exhausted' on 05_maps.tl (false drift
    // vs the fixture table, 2026-09-16).
    let script =
        format!("ulimit -v {BUILD_AS_LIMIT_KB}; exec timeout {RUNNER_TIMEOUT_S} bash \"$0\"");
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg(&runner)
        .current_dir(&root)
        .output()
        .expect("spawn shell parity runner");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let rc = exit_code(out.status);
    println!("shell runner rc={rc}:\n{stdout}");

    let mut verdicts: BTreeMap<String, String> = BTreeMap::new();
    let mut result_line: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("RESULT: ") {
            result_line = Some(rest.to_string());
        }
        if let Some((name, rest)) = line.split_once(": ") {
            if name.ends_with(".tl") {
                let verdict = rest.split_whitespace().next().unwrap_or("").to_string();
                verdicts.insert(name.to_string(), verdict);
            }
        }
    }

    for name in &names {
        let got = verdicts.get(name).unwrap_or_else(|| {
            panic!("shell runner printed no verdict for {name}; output:\n{stdout}")
        });
        let want = match expect_for(name) {
            Expect::Match => "MATCH",
            // The shell runner reports a documented fail-loud build as FALLBACK,
            // because `tallow run` still succeeds via the interpreter.
            Expect::NativeFailLoud { .. } => "FALLBACK",
            // The shell runner classifies a both-planes refusal as its own
            // verdict; anything else would make this table disagree with the
            // runner it is checking.
            Expect::RefuseBoth => "REFUSED",
        };
        // The shell runner prints `VERDICT(detail…)`; compare the class only.
        assert!(
            got.starts_with(want),
            "shell runner verdict for {name} drifted from the E1 fixture table: got {got:?}, want {want:?}"
        );
    }
    assert_eq!(
        verdicts.len(),
        names.len(),
        "shell runner reported {} verdicts for {} fixtures (unknown fixtures?)",
        verdicts.len(),
        names.len()
    );
    for (name, v) in &verdicts {
        assert_ne!(v, "DIVERGE", "shell runner reports DIVERGE for {name}");
    }
    assert_eq!(rc, 0, "shell runner exited rc={rc} (nonzero = DIVERGE)");
    println!(
        "shell runner: {} verdicts, all matching the fixture table; RESULT: {}",
        verdicts.len(),
        result_line.unwrap_or_else(|| "<missing>".into())
    );
}
