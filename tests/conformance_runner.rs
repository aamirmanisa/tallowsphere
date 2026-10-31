//! Conformance suite, Rust runner.
//!
//! Replaces `conformance/run.py`. The suite's rule is unchanged: every case is a
//! `.tl` program plus a `.json` expectation, and a case passes only when BOTH
//! planes (interpreter and native) agree with the expectation. A plane that
//! silently diverges fails the suite instead of shipping.
//!
//!     cargo test --test conformance_runner
//!     TALLOW_BIN=target/debug/tallow cargo test --test conformance_runner
//!     TALLOW_REFRESH=1 cargo test --test conformance_runner -- --ignored
//!
//! The binary under test is `$TALLOW_BIN` when set, else `target/debug/tallow`
//! relative to the workspace root. There is deliberately no PATH fallback: a
//! `tallow` picked up from PATH is a different compiler than the one this tree
//! built, and proving the packaged binary (the suite's stated purpose) against
//! the wrong compiler proves nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One disagreement between an expectation and what a plane produced.
#[derive(Debug)]
struct Failure {
    case: String,
    plane: &'static str,
    why: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn cases_dir() -> PathBuf {
    workspace_root().join("conformance/cases")
}

/// The compiler under test. Explicit override, else the debug build this tree
/// produces — never a `tallow` from PATH.
fn tallow_bin() -> PathBuf {
    match std::env::var_os("TALLOW_BIN") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => workspace_root().join("target/debug/tallow"),
    }
}

#[derive(Debug, Clone)]
struct PlaneResult {
    stdout: String,
    stderr: String,
    exit: i32,
}

fn run_plane(tallow: &Path, program: &Path, plane_args: &[&str]) -> PlaneResult {
    let out = Command::new(tallow)
        .arg("run")
        .args(plane_args)
        .arg(program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", tallow.display()));
    PlaneResult {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        exit: out.status.code().unwrap_or(-1),
    }
}

const PLANES: [(&str, &[&str]); 2] = [
    ("interpret", &["--interpret"]),
    ("native", &["--require-native"]),
];

/// A `.json` expectation. `kind` is the only required field.
#[derive(Debug, Clone, PartialEq)]
enum Expect {
    Accept { stdout: String },
    Reject { code: Option<String> },
    Runtime { message: Option<String> },
}

impl Expect {
    fn parse(text: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let kind = v
            .get("kind")
            .and_then(|k| k.as_str())
            .ok_or("missing `kind`")?;
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        match kind {
            "accept" => Ok(Expect::Accept {
                stdout: s("stdout").ok_or("accept needs `stdout`")?,
            }),
            "reject" => Ok(Expect::Reject { code: s("code") }),
            "runtime" => Ok(Expect::Runtime { message: s("message") }),
            other => Err(format!("unknown kind {other:?}")),
        }
    }

    fn to_json(&self) -> String {
        let v = match self {
            Expect::Accept { stdout } => {
                serde_json::json!({ "kind": "accept", "stdout": stdout })
            }
            Expect::Reject { code } => serde_json::json!({
                "kind": "reject",
                "code": code.clone().unwrap_or_default(),
            }),
            Expect::Runtime { message } => match message {
                Some(m) => serde_json::json!({ "kind": "runtime", "message": m }),
                None => serde_json::json!({ "kind": "runtime" }),
            },
        };
        format!("{}\n", serde_json::to_string_pretty(&v).unwrap_or_default())
    }

    /// Does `got` satisfy this expectation? The error names the first mismatch.
    fn check(&self, got: &PlaneResult) -> Result<(), String> {
        match self {
            Expect::Accept { stdout } => {
                if got.exit != 0 {
                    return Err(format!(
                        "exit {}: {}",
                        got.exit,
                        first_line(&got.stderr)
                    ));
                }
                if &got.stdout != stdout {
                    return Err(format!(
                        "stdout {:?} != {:?}",
                        got.stdout, stdout
                    ));
                }
                Ok(())
            }
            Expect::Reject { code } => {
                if got.exit == 0 {
                    return Err("accepted, but the suite expects a diagnostic".to_string());
                }
                if let Some(c) = code {
                    if !c.is_empty() && !got.stderr.contains(c.as_str()) {
                        return Err(format!("missing {c} in diagnostics"));
                    }
                }
                Ok(())
            }
            Expect::Runtime { message } => {
                if got.exit == 0 {
                    return Err("ran, but the suite expects a runtime error".to_string());
                }
                if let Some(m) = message {
                    if !got.stderr.contains(m.as_str()) {
                        return Err(format!("missing {m:?} in stderr"));
                    }
                }
                Ok(())
            }
        }
    }

    /// Derive an expectation from what both planes produced. Fails when the
    /// planes disagree, because a diverging program cannot pin anything.
    fn refresh(interp: &PlaneResult, native: &PlaneResult) -> Result<Self, String> {
        if interp.exit != native.exit || interp.stdout != native.stdout {
            return Err(format!(
                "planes disagree (interp exit {}, native exit {})",
                interp.exit, native.exit
            ));
        }
        if interp.exit == 0 {
            return Ok(Expect::Accept {
                stdout: interp.stdout.clone(),
            });
        }
        if interp.stderr.contains("non-exhaustive match") {
            return Ok(Expect::Runtime {
                message: Some("non-exhaustive match".to_string()),
            });
        }
        Ok(Expect::Reject {
            code: find_error_code(&interp.stderr),
        })
    }
}

fn first_line(s: &str) -> String {
    s.trim().lines().next().unwrap_or("").chars().take(200).collect()
}

/// The first `Exxxx` diagnostic code in a stderr, if any.
fn find_error_code(stderr: &str) -> Option<String> {
    let bytes: Vec<char> = stderr.chars().collect();
    for i in 0..bytes.len().saturating_sub(4) {
        if bytes[i] == 'E' && bytes[i + 1..i + 5].iter().all(|c| c.is_ascii_digit()) {
            return Some(bytes[i..i + 5].iter().collect());
        }
    }
    None
}

fn run_suite() -> Vec<Failure> {
    let tallow = tallow_bin();
    assert!(
        tallow.is_file(),
        "no compiler under test at {} — build it (`cargo build --bin tallow --lib`) \
         or set TALLOW_BIN",
        tallow.display()
    );
    let mut entries: Vec<PathBuf> = std::fs::read_dir(cases_dir())
        .expect("conformance/cases is unreadable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "tl"))
        .collect();
    // The suite's order is the filename order; sorted() on PathBuf is by bytes,
    // which matches the Python runner's `sorted(CASES.glob("*.tl"))`.
    entries.sort();

    let mut failures = Vec::new();
    let mut checked = 0usize;
    for program in entries {
        let name = program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let meta_path = program.with_extension("json");
        let results: BTreeMap<&str, PlaneResult> = PLANES
            .iter()
            .map(|(plane, args)| (*plane, run_plane(&tallow, &program, args)))
            .collect();

        let expect = match std::fs::read_to_string(&meta_path) {
            Ok(text) => match Expect::parse(&text) {
                Ok(e) => e,
                Err(why) => {
                    failures.push(Failure {
                        case: name,
                        plane: "expectation",
                        why: format!("{}: {why}", meta_path.display()),
                    });
                    continue;
                }
            },
            Err(_) => {
                failures.push(Failure {
                    case: name,
                    plane: "expectation",
                    why: "no expectation (run with TALLOW_REFRESH=1)".to_string(),
                });
                continue;
            }
        };

        checked += 1;
        for (plane, got) in &results {
            if let Err(why) = expect.check(got) {
                failures.push(Failure {
                    case: name.clone(),
                    plane,
                    why,
                });
                break;
            }
        }
    }
    eprintln!("conformance: {checked} case(s) checked against {}", tallow.display());
    failures
}

/// `--refresh`: rewrite every expectation from the reference engine. A case
/// whose planes disagree is REFUSED, not pinned.
#[allow(dead_code)]
fn refresh_suite() -> Vec<Failure> {
    let tallow = tallow_bin();
    let mut failures = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(cases_dir())
        .expect("conformance/cases is unreadable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "tl"))
        .collect();
    entries.sort();
    for program in entries {
        let name = program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let results: BTreeMap<&str, PlaneResult> = PLANES
            .iter()
            .map(|(plane, args)| (*plane, run_plane(&tallow, &program, args)))
            .collect();
        match Expect::refresh(&results["interpret"], &results["native"]) {
            Ok(expect) => {
                let path = program.with_extension("json");
                std::fs::write(&path, expect.to_json())
                    .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
                eprintln!("refreshed {name}: {expect:?}");
            }
            Err(why) => failures.push(Failure {
                case: name,
                plane: "refresh",
                why,
            }),
        }
    }
    failures
}

#[test]
fn conformance_cases_agree_on_both_planes() {
    if std::env::var_os("TALLOW_REFRESH").is_some() {
        eprintln!("TALLOW_REFRESH is set; run the refresh test instead");
        return;
    }
    let failures = run_suite();
    if !failures.is_empty() {
        let mut report = String::new();
        for f in &failures {
            report.push_str(&format!(
                "FAIL     {} [{}] {}\n",
                f.case, f.plane, f.why
            ));
        }
        report.push_str(&format!("\n{} failure(s)", failures.len()));
        panic!("{report}");
    }
}

/// Rewrites expectations; ignored so a normal `cargo test` never mutates the
/// corpus.
#[test]
#[ignore = "mutates conformance/cases/*.json; run explicitly with TALLOW_REFRESH=1"]
fn conformance_refresh() {
    let failures = refresh_suite();
    assert!(
        failures.is_empty(),
        "{} case(s) refused (planes disagree)",
        failures.len()
    );
}
