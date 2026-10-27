//! A census gate for native lowering of `stdlib/*.tl` modules.
//!
//! Two lanes (topology, ip) shipped acceptance evidence from the interpreter
//! alone because the native backend has no lowering for their calls: the
//! compiled build refuses and `tallow run` silently falls back. That gap was
//! found three times, late, by hand. This test makes it a checked-in number.
//!
//! ## What it measures
//!
//! For every `stdlib/*.tl` file that declares at least one module-level
//! `native fn`, the census picks the first declaration whose arguments it can
//! synthesize, generates a program that *calls* it inside a function `main`
//! never calls, and compiles that program:
//!
//! ```text
//! import tallow.<file-stem>
//!
//! fn probe_unused(...) {
//!     let _probe = <module>.<fn>(<synthesized args>)
//! }
//!
//! fn main() {
//! }
//! ```
//!
//! Nothing is executed. `main` is empty and the call sits in a function no
//! path reaches, so no socket is opened and no process is spawned — the call
//! exists only to be *compiled*.
//!
//! ## The command that requires native codegen
//!
//! `tallow build <file>` has no `--require-native` flag; `build` **is** the
//! native plane. Its only outcome is `built: <path>` (exit 0) or
//! `build failed: <reason>` (non-zero) — there is no interpreter to fall back
//! to, which is why the census drives `build` and not `run`.
//!
//! `--require-native` exists only on `tallow run`; there it means "do not
//! substitute the interpreter when the native build is unavailable". The two
//! reach the same codegen: `cargo run -- run --require-native probe.tl` on a
//! module with no lowering exits non-zero with
//! `* native build unavailable (<reason>); --require-native refuses the
//! interpreter fallback`, where `<reason>` is the same string `build` prints
//! after `build failed: `. The census uses `build` because it stops before the
//! produced binary is launched at all.
//!
//! ## Statuses
//!
//! - `lowers`          — the probe compiled; a native lowering exists for that call.
//! - `refuses`         — codegen refused the call by name (the interpreter-only gap).
//! - `not_expressible` — no declared free function takes arguments the census can
//!   synthesize (a `fn()` value, a struct array, a `Grant`, a live handle), or the
//!   program is stopped by a front-end gate before codegen runs. The reason is
//!   recorded; it is *not* counted as passing.
//!
//! ## Rules the test enforces (read-only unless blessed)
//!
//! - a module recorded `lowers` that now refuses **fails** the test (regression);
//! - a module with natives and no baseline entry **fails** the test (a new lane
//!   cannot ship an interpreter-only module silently);
//! - refusals are **reported**, never fatal, so the debt is a number in the log;
//! - `refuses` → `lowers` is fine: re-bless in the commit that lands the lowering.
//!
//! Regenerate the baseline with:
//!
//! ```text
//! BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering
//! ```
//!
//! The baseline is `tests/fixtures/stdlib_native_lowering/baseline.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const BASELINE_REL: &str = "tests/fixtures/stdlib_native_lowering/baseline.json";

// ───────────────────────────── declarations ─────────────────────────────

/// One module-level `native fn` declaration, with its call already rendered.
#[derive(Clone, Debug)]
struct Decl {
    /// `module.fn` as written at the call site (the `native fn` name, qualified
    /// by the module alias when the declaration is bare).
    label: String,
    /// `module.fn(arg, arg, …)` — the call this census compiles.
    call: String,
}

#[derive(Clone, Debug)]
struct Module {
    /// File stem, e.g. `topology`. This is the baseline key.
    stem: String,
    /// Declarations in source order whose arguments the census can synthesize;
    /// the first one is probed.
    decls: Vec<Decl>,
    /// How many module-level `native fn` lines the file declares, expressible
    /// or not — the denominator behind a `not_expressible` verdict.
    declared: usize,
    /// Why the first non-expressible declaration was rejected.
    reason: Option<String>,
}

/// Scalar-only argument values. Anything richer (structs, maps, `fn()` values,
/// arrays of structs) is outside what this census can synthesize honestly, and
/// the module is then recorded `not_expressible` rather than dropped.
fn synth_scalar(ty: &str) -> Option<String> {
    let v = match ty {
        "String" | "str" => "\"probe\"",
        "Int" | "i64" | "u64" | "u32" | "i32" | "usize" | "u8" | "i8" | "u16" | "i16" => "1",
        "Float" | "f64" | "f32" => "1.0",
        "bool" | "Bool" => "true",
        "Bytes" => "\"probe\".to_bytes()",
        _ => return None,
    };
    Some(v.to_string())
}

fn synth_arg(ty: &str) -> Option<String> {
    if let Some(inner) = ty.strip_suffix('?') {
        // An optional argument is always satisfiable with `nil`.
        let _ = inner;
        return Some("nil".to_string());
    }
    if let Some(inner) = ty.strip_prefix("[]") {
        let elem = synth_scalar(inner).or_else(|| {
            inner
                .strip_prefix("[]")
                .and_then(synth_scalar)
                .map(|v| format!("[{v}]"))
        })?;
        return Some(format!("[{elem}]"));
    }
    synth_scalar(ty)
}

/// Split a parameter list on commas that are not inside `<>`, `[]`, `()`, `{}`.
fn split_params(params: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut cur = String::new();
    for ch in params.chars() {
        match ch {
            '<' | '[' | '(' | '{' => depth += 1,
            '>' | ']' | ')' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Parse the module-level `native fn` lines of one stdlib source file.
///
/// Only column-0 declarations are module-level; `native fn` inside an `impl`
/// block is a method, is reached through a receiver, and is not this census's
/// subject. A declaration whose arguments cannot be synthesized is remembered
/// as the module's reason, so "no expressible call" is a fact about the file
/// with a named argument type behind it, not a parser blind spot.
fn parse_file(path: &Path, stem: &str) -> Option<Module> {
    let src = std::fs::read_to_string(path).ok()?;
    let mut decls = Vec::new();
    let mut declared = 0usize;
    let mut reason: Option<String> = None;
    for line in src.lines() {
        let Some(rest) = line.strip_prefix("native fn ") else {
            continue;
        };
        declared += 1;
        let Some(open) = rest.find('(') else {
            continue;
        };
        // A generic native (`parse_toml<T>`) is called the same way at the call
        // site; the type parameter is the compiler's to infer, not this
        // census's to guess, so it is stripped from the name and the call is
        // made exactly as a program would make it.
        let head = rest[..open].trim();
        let head = head.split('<').next().unwrap_or(head).trim();
        if head.is_empty() {
            continue;
        }
        let Some(close) = rest.rfind(')') else {
            continue;
        };
        if close < open {
            continue;
        }
        let params = &rest[open + 1..close];

        let mut args = Vec::new();
        let mut rejection: Option<String> = None;
        for p in split_params(params) {
            let Some((pname, pty)) = p.split_once(':') else {
                rejection = Some(format!("parameter `{p}` has no type annotation"));
                break;
            };
            if pname.trim() == "self" {
                rejection = Some("takes a receiver (`self`) — a method, not a module call".into());
                break;
            }
            // Drop a default value: `chunk_size: i64 = 262144`.
            let pty = pty.split('=').next().unwrap_or(pty).trim();
            match synth_arg(pty) {
                Some(a) => args.push(a),
                None => {
                    rejection = Some(format!(
                        "argument `{}: {pty}` is not a scalar the census can synthesize",
                        pname.trim()
                    ));
                    break;
                }
            }
        }
        if let Some(why) = rejection {
            if reason.is_none() {
                reason = Some(format!("`{head}` {why}"));
            }
            continue;
        }

        // A bare declaration is called as `<file stem>.<name>`; a dotted one
        // (`ip.load`, `Transfer.hash`, `intel.export`) carries its own alias.
        let label = if head.contains('.') {
            head.to_string()
        } else {
            format!("{stem}.{head}")
        };
        decls.push(Decl {
            call: format!("{label}({})", args.join(", ")),
            label,
        });
    }
    if declared == 0 {
        return None;
    }
    Some(Module {
        stem: stem.to_string(),
        decls,
        declared,
        reason,
    })
}

fn discover(stdlib: &Path) -> Vec<Module> {
    let mut modules = Vec::new();
    let Ok(entries) = std::fs::read_dir(stdlib) else {
        return modules;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "tl"))
        .collect();
    paths.sort();
    for path in paths {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(module) = parse_file(&path, stem) {
            modules.push(module);
        }
    }
    modules
}

// ───────────────────────────── the probe build ─────────────────────────────

#[derive(Clone, Debug, Default)]
struct Opts {
    grant: bool,
    effect: Option<String>,
    legal: bool,
    fingerprint_policy: bool,
    opsec_waiver: bool,
}

/// Render the probe program.
///
/// The annotations are not decoration: the front end refuses a call that
/// declares a `Net` effect without the row, a `Grant` in scope, or a program
/// scope for a network/fingerprint feature. Those gates are unrelated to
/// lowering, so the probe satisfies them the way any compiled program must —
/// and only when the compiler asks (see `census_module`).
fn render(stem: &str, call: &str, opts: &Opts) -> String {
    let mut out = String::new();
    out.push_str(&format!("import tallow.{stem}\n\n"));
    if opts.opsec_waiver {
        out.push_str(
            "@opsec_waiver(rule: \"E5102\", reason: \"native-lowering census probe: \
             the call is compiled and never executed\", reviewer: \"harbor\")\n",
        );
    }
    if opts.legal {
        out.push_str(
            "@legal(basis: .research, purpose: \"native-lowering census probe \
             (compiled, never executed)\", personal_data: false)\n",
        );
    }
    out.push_str("fn probe_unused(");
    if opts.grant {
        out.push_str("g: Grant<Net>");
    }
    out.push(')');
    if let Some(effect) = &opts.effect {
        out.push_str(&format!(" with Net({effect})"));
    }
    out.push_str(&format!(" {{\n    let _probe = {call}\n}}\n\n"));
    if opts.fingerprint_policy {
        out.push_str(
            "@fingerprint_policy(policy: .cohort_uniform, \
             bot_identity: \"TallowCensus/1.0 (+https://tallow.invalid/bot)\")\n",
        );
    }
    out.push_str("fn main() {\n}\n");
    out
}

/// Compile one probe program. Returns `(success, stdout+stderr)`.
///
/// Output goes to files rather than pipes so a chatty build cannot fill a pipe
/// buffer and block, and a wall-clock cap keeps one wedged linker (this box has
/// swapped under concurrent multi-GB links against the debug runtime archive)
/// from hanging the gate forever.
fn build_probe(tag: &str, source: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("tallow-census-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("probe.tl");
    let log = dir.join("build.log");
    std::fs::write(&path, source).expect("write probe program");

    let log_file = std::fs::File::create(&log).expect("create build log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("build")
        .arg(&path)
        .stdout(std::process::Stdio::from(
            log_file.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log_file))
        .spawn()
        .expect("run tallow build");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut timed_out = false;
    let success = loop {
        match child.try_wait().expect("wait for tallow build") {
            Some(status) => break status.success(),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break false;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };

    let mut text = std::fs::read_to_string(&log).unwrap_or_default();
    if timed_out {
        text.push_str("\nbuild timed out after 180 s\n");
    }
    let _ = std::fs::remove_dir_all(&dir);
    (success, text)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Lowers,
    Refuses,
    NotExpressible,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Lowers => "lowers",
            Status::Refuses => "refuses",
            Status::NotExpressible => "not_expressible",
        }
    }

    fn parse(s: &str) -> Option<Status> {
        match s {
            "lowers" => Some(Status::Lowers),
            "refuses" => Some(Status::Refuses),
            "not_expressible" => Some(Status::NotExpressible),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct Outcome {
    status: Status,
    /// The call that was compiled, when one exists.
    function: Option<String>,
    /// The refusal line, or the reason the module is not expressible.
    evidence: String,
}

/// The first line that is a refusal or an error, not a warning.
fn refusal_line(text: &str) -> String {
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("build failed:") || t.starts_with("error[") || t.contains(": error:") {
            // A clang diagnostic is prefixed with the generated `.ll` path and
            // offsets; keep the diagnostic itself so the baseline is stable.
            if let Some(idx) = t.find("error:") {
                if !t.starts_with("error") && t.contains(": error:") {
                    return t[idx..].to_string();
                }
            }
            return t.to_string();
        }
    }
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

fn census_module(module: &Module) -> Outcome {
    let Some(decl) = module.decls.first() else {
        return Outcome {
            status: Status::NotExpressible,
            function: None,
            evidence: format!(
                "{} of {} declared native fn(s) can be called by this census: {}",
                module.decls.len(),
                module.declared,
                module
                    .reason
                    .clone()
                    .unwrap_or_else(|| "no module-level declaration was parseable".to_string())
            ),
        };
    };

    let mut opts = Opts::default();
    let mut ok = false;
    let mut text = String::new();
    // Each pass answers exactly one front-end gate. Bounded so a probe that
    // cycles between two refusals cannot loop.
    for _ in 0..6 {
        let source = render(&module.stem, &decl.call, &opts);
        let (success, out) = build_probe(&module.stem, &source);
        text = out;
        if success {
            ok = true;
            break;
        }
        let mut progressed = false;
        if text.contains("E0141") && opts.effect.is_none() {
            let effect = text
                .split("help: add: with Net(")
                .nth(1)
                .and_then(|s| s.split(')').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| {
                    decl.label
                        .rsplit('.')
                        .next()
                        .unwrap_or("connect")
                        .to_string()
                });
            opts.effect = Some(effect);
            progressed = true;
        } else if text.contains("E0142") && !opts.grant {
            opts.grant = true;
            progressed = true;
        } else if text.contains("E0100") && !opts.legal {
            opts.legal = true;
            progressed = true;
        } else if text.contains("E5100") && !opts.fingerprint_policy {
            opts.fingerprint_policy = true;
            progressed = true;
        } else if text.contains("E5102") && !opts.opsec_waiver {
            opts.opsec_waiver = true;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    if ok {
        return Outcome {
            status: Status::Lowers,
            function: Some(decl.call.clone()),
            evidence: String::new(),
        };
    }

    let evidence = refusal_line(&text);
    if text.contains("build timed out after") {
        return Outcome {
            status: Status::NotExpressible,
            function: Some(decl.call.clone()),
            evidence: "probe build exceeded the 180 s cap; no verdict was measured".to_string(),
        };
    }
    // A diagnostic with a Tallow error code is a front-end gate, not a codegen
    // answer: the probe never reached lowering, so the module is not measured
    // rather than measured and refused.
    let front_end = text.contains("error[E") && !text.contains("has no native lowering");
    Outcome {
        status: if front_end {
            Status::NotExpressible
        } else {
            Status::Refuses
        },
        function: Some(decl.call.clone()),
        evidence,
    }
}

fn run_census(modules: &[Module]) -> Vec<(String, Outcome)> {
    // Two workers, not one per core: each `tallow build` that gets as far as
    // linking peaks near 2 GB of RSS against the debug runtime archive, and
    // four concurrent links drove this box into zram thrash (linkers parked in
    // D state for minutes). Two keeps the wall clock reasonable without it.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().min(2))
        .unwrap_or(1);
    let chunk = modules.len().div_ceil(workers.max(1));
    let mut results = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for slice in modules.chunks(chunk.max(1)) {
            handles.push(scope.spawn(move || {
                slice
                    .iter()
                    .map(|m| (m.stem.clone(), census_module(m)))
                    .collect::<Vec<_>>()
            }));
        }
        for h in handles {
            results.extend(h.join().expect("census worker panicked"));
        }
    });
    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

// ───────────────────────────── baseline ─────────────────────────────

struct Baseline {
    /// module -> status
    statuses: BTreeMap<String, Status>,
}

fn load_baseline(path: &Path) -> Option<Baseline> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let mut statuses = BTreeMap::new();
    for entry in value.as_array()? {
        let module = entry.get("module")?.as_str()?.to_string();
        let status = Status::parse(entry.get("status")?.as_str()?)?;
        statuses.insert(module, status);
    }
    Some(Baseline { statuses })
}

fn git_head() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_baseline(path: &Path, results: &[(String, Outcome)]) {
    let head = git_head();
    let entries: Vec<serde_json::Value> = results
        .iter()
        .map(|(module, outcome)| {
            serde_json::json!({
                "module": module,
                "status": outcome.status.as_str(),
                "function": outcome.function,
                "evidence": outcome.evidence,
                "checked_at": head,
            })
        })
        .collect();
    let body = serde_json::to_string_pretty(&serde_json::Value::Array(entries))
        .expect("serialize baseline");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("create baseline dir");
    }
    std::fs::write(path, format!("{body}\n")).expect("write baseline");
}

// ───────────────────────────── comparison ─────────────────────────────

#[derive(Debug, Default, PartialEq, Eq)]
struct Comparison {
    /// recorded `lowers`, now refuses — the regression the gate exists for.
    regressions: Vec<String>,
    /// modules with natives and no baseline entry at all.
    new_modules: Vec<String>,
    /// status moved in an allowed direction (e.g. refuses -> lowers).
    changes: Vec<String>,
    /// baseline entries whose module no longer declares natives.
    stale: Vec<String>,
    lowers: usize,
    refuses: usize,
    not_expressible: usize,
}

fn compare(results: &[(String, Status)], baseline: &BTreeMap<String, Status>) -> Comparison {
    let mut c = Comparison::default();
    for (module, status) in results {
        match *status {
            Status::Lowers => c.lowers += 1,
            Status::Refuses => c.refuses += 1,
            Status::NotExpressible => c.not_expressible += 1,
        }
        let Some(recorded) = baseline.get(module).copied() else {
            c.new_modules.push(module.clone());
            continue;
        };
        match (recorded, *status) {
            (Status::Lowers, Status::Refuses) => c.regressions.push(module.clone()),
            (Status::Refuses, Status::Lowers) => {
                c.changes.push(format!("{module}: refuses -> lowers"))
            }
            (Status::NotExpressible, s) if s != Status::NotExpressible => {
                c.changes
                    .push(format!("{module}: not_expressible -> {}", s.as_str()));
            }
            (Status::Refuses, Status::NotExpressible) => c.changes.push(format!(
                "{module}: refuses -> not_expressible (probe no longer reaches codegen)"
            )),
            _ => {}
        }
    }
    for module in baseline.keys() {
        if !results.iter().any(|(m, _)| m == module) {
            c.stale.push(module.clone());
        }
    }
    c
}

// ───────────────────────────── test ─────────────────────────────

#[test]
fn stdlib_native_lowering_census() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let modules = discover(&root.join("stdlib"));
    assert!(
        modules.len() > 20,
        "stdlib discovery found only {} modules — the census would be vacuous",
        modules.len()
    );

    let results = run_census(&modules);
    let statuses: Vec<(String, Status)> =
        results.iter().map(|(m, o)| (m.clone(), o.status)).collect();

    let baseline_path = root.join(BASELINE_REL);
    let bless = std::env::var("BLESS_STDLIB_LOWERING").is_ok_and(|v| v == "1");

    if bless {
        write_baseline(&baseline_path, &results);
        let lowers = results
            .iter()
            .filter(|(_, o)| o.status == Status::Lowers)
            .count();
        let refuses = results
            .iter()
            .filter(|(_, o)| o.status == Status::Refuses)
            .count();
        let nexpr = results.len() - lowers - refuses;
        println!(
            "stdlib native-lowering census blessed: {} modules — lowers {lowers}, \
             refuses {refuses}, not_expressible {nexpr}",
            results.len()
        );
        for (module, o) in &results {
            if o.status != Status::Lowers {
                println!("  {:16} {:16} {}", module, o.status.as_str(), o.evidence);
            }
        }
        return;
    }

    let baseline = load_baseline(&baseline_path).unwrap_or_else(|| {
        panic!(
            "no readable baseline at {} — run \
             `BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering` once, \
             review the diff, and commit it with the census",
            baseline_path.display()
        )
    });

    let c = compare(&statuses, &baseline.statuses);

    // The debt, as a number, on every run.
    println!(
        "stdlib native-lowering census: {} modules — lowers {}, refuses {}, not_expressible {}",
        results.len(),
        c.lowers,
        c.refuses,
        c.not_expressible
    );
    for (module, o) in &results {
        if o.status == Status::Refuses {
            println!("  refuses         {module:16} {}", o.evidence);
        }
    }
    for (module, o) in &results {
        if o.status == Status::NotExpressible {
            println!("  not_expressible {module:16} {}", o.evidence);
        }
    }
    for change in &c.changes {
        println!("  note: {change} (re-bless to record)");
    }
    for stale in &c.stale {
        println!("  note: {stale} is in the baseline but declares no native fn now");
    }

    assert!(
        c.new_modules.is_empty(),
        "new stdlib module(s) with native declarations and no baseline entry: {:?}\n\
         A lane must not ship an interpreter-only module silently. Add the module by \
         running BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering and \
         commit the baseline with the change.",
        c.new_modules
    );

    assert!(
        c.regressions.is_empty(),
        "native-lowering regression(s) — recorded as `lowers`, now refused: {:?}\n\
         The baseline is the contract: a call that compiled before must compile now. \
         If the removal is deliberate, re-bless in the same commit and say so.",
        c.regressions
    );
}

// ───────────────────────────── gate self-tests ─────────────────────────────

fn map(pairs: &[(&str, Status)]) -> BTreeMap<String, Status> {
    pairs.iter().map(|(m, s)| (m.to_string(), *s)).collect()
}

#[test]
fn gate_fails_a_recorded_lowering_that_now_refuses() {
    let baseline = map(&[("topology", Status::Lowers)]);
    let results = vec![("topology".to_string(), Status::Refuses)];
    let c = compare(&results, &baseline);
    assert_eq!(c.regressions, vec!["topology".to_string()]);
}

#[test]
fn gate_fails_a_new_module_with_no_baseline_entry() {
    let baseline = map(&[("math", Status::Lowers)]);
    let results = vec![
        ("math".to_string(), Status::Lowers),
        ("shiny".to_string(), Status::Refuses),
    ];
    let c = compare(&results, &baseline);
    assert_eq!(c.new_modules, vec!["shiny".to_string()]);
    assert!(c.regressions.is_empty());
}

#[test]
fn gate_allows_a_refusal_that_starts_lowering() {
    let baseline = map(&[("ip", Status::Refuses)]);
    let results = vec![("ip".to_string(), Status::Lowers)];
    let c = compare(&results, &baseline);
    assert!(c.regressions.is_empty() && c.new_modules.is_empty());
    assert_eq!(c.changes, vec!["ip: refuses -> lowers".to_string()]);
}

#[test]
fn gate_counts_not_expressible_separately_from_lowers() {
    let baseline = map(&[("http", Status::NotExpressible)]);
    let results = vec![("http".to_string(), Status::NotExpressible)];
    let c = compare(&results, &baseline);
    assert_eq!(
        (c.lowers, c.refuses, c.not_expressible),
        (0, 0, 1),
        "not_expressible must never be counted as passing"
    );
    assert!(c.regressions.is_empty() && c.new_modules.is_empty());
}
