//! `tallow test --doc <path>` — G14 doctests.
//!
//! A fenced ```tallow / ```tl block inside a `///` doc comment is a claim, and
//! this module runs it. The fence grammar is **exactly** the one
//! `scripts/docs_examples.py` enforces (G59), so the repository has one
//! vocabulary rather than two:
//!
//! ```text
//!   ```tallow run                  execute; must exit 0
//!   ```tallow run:fail:E0125       execute; must exit non-zero AND print every listed code
//!   ```tallow skip:<reason>        not executed; the reason is required
//!   ```tallow                      (no marker) — an error: silence is how an example rots
//! ```
//!
//! Every executed block runs on **both planes** — `run --interpret` and
//! `run --require-native` — and the two must agree on exit status and stdout.
//! A block the native backend cannot lower makes `--require-native` refuse,
//! which is a disagreement: the doctest fails and the refusal text is printed.
//! The one thing that never happens is a silent fallback to the interpreter.
//!
//! Blocks are standalone (docs/spec/DOCTESTS.md §Isolation): no imports from
//! the enclosing file, no access to the item under test. Each block is written
//! to its own temporary file, so the enclosing file's items are not in scope.
//!
//! The child runner is this binary (`current_exe`), or `TALLOW_BIN` when set to
//! an existing path — the same override `scripts/docs_examples.py` honours.
//!
//! Exit codes: `0` every doctest honoured its marker, `1` at least one failed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long one plane may run before the doctest is a failure. Same cap as
/// `scripts/docs_examples.py`, so an example cannot hang CI on one checker and
/// time out on the other.
const TIMEOUT: Duration = Duration::from_secs(120);

/// The marker on a fence, parsed exactly like `scripts/docs_examples.py`'s
/// `parse_marker` (including its leniency: `run:E0125` is a `run:fail`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Marker {
    /// A fence with no marker — a failure, never a skip.
    Unmarked,
    /// Must exit 0.
    Run,
    /// Must exit non-zero and print every listed code.
    RunFail(Vec<String>),
    /// Not executed; the reason is required and printed.
    Skip(String),
}

/// One fenced block lifted out of a doc comment.
#[derive(Debug, Clone)]
pub struct DocBlock {
    pub file: PathBuf,
    /// 1-based line of the opening fence, in the source file.
    pub line: usize,
    pub marker: Marker,
    pub body: String,
}

impl DocBlock {
    fn where_(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

/// Fence grammar, byte-identical to `FENCE` in `scripts/docs_examples.py`:
/// open at column 0, a `tallow`/`tl` language tag, an info string, a body, and
/// a closing fence alone on its line.
fn fence() -> &'static regex::Regex {
    static FENCE: OnceLock<regex::Regex> = OnceLock::new();
    FENCE.get_or_init(|| {
        regex::Regex::new(r"(?ms)^```(tallow|tl)([^\n]*)\n(.*?)^```[ \t]*$")
            .expect("doctest fence grammar compiles")
    })
}

/// Port of `parse_marker` from `scripts/docs_examples.py`. Keeping the two in
/// lockstep is the point: a marker the docs gate accepts must mean the same
/// thing here.
pub fn parse_marker(info: &str) -> Marker {
    let info = info.trim();
    if info.is_empty() {
        return Marker::Unmarked;
    }
    let (head, rest) = match info.split_once(':') {
        Some((h, r)) => (h.trim(), r.trim()),
        None => (info, ""),
    };
    match head {
        "run" => {
            let codes: Vec<String> = if let Some(tail) = rest.strip_prefix("fail:") {
                split_codes(tail)
            } else {
                split_codes(rest)
            };
            if codes.is_empty() {
                Marker::Run
            } else {
                Marker::RunFail(codes)
            }
        }
        "skip" => Marker::Skip(rest.to_string()),
        _ => Marker::Unmarked,
    }
}

fn split_codes(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

/// The content of a `///` line, or `None` when the line is not a doc comment.
/// Indentation before `///` is dropped so the fence still opens at column 0 of
/// the joined group; one space after `///` is conventional and dropped with it.
fn doc_comment_content(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("///")?;
    Some(rest.strip_prefix(' ').unwrap_or(rest))
}

/// Extract every doc-comment fence in `text`, recording `file:line` for each.
///
/// Consecutive `///` lines form one group (a gap of any non-doc line ends it —
/// a fence cannot span two doc comments), and the group text is searched with
/// the shared grammar. Line numbers are the source file's, not the group's.
pub fn extract_blocks(file: &Path, text: &str) -> Vec<DocBlock> {
    let mut blocks = Vec::new();
    let mut group: Vec<&str> = Vec::new();
    let mut group_start = 0usize;

    let flush = |group: &mut Vec<&str>, group_start: usize, blocks: &mut Vec<DocBlock>| {
        if group.is_empty() {
            return;
        }
        let joined = group.join("\n");
        for caps in fence().captures_iter(&joined) {
            let Some(open) = caps.get(0) else { continue };
            let line = group_start + joined[..open.start()].matches('\n').count();
            let marker = parse_marker(caps.get(2).map(|m| m.as_str()).unwrap_or(""));
            let body = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
            blocks.push(DocBlock {
                file: file.to_path_buf(),
                line,
                marker,
                body,
            });
        }
        group.clear();
    };

    for (idx, line) in text.split('\n').enumerate() {
        match doc_comment_content(line) {
            Some(content) => {
                if group.is_empty() {
                    group_start = idx + 1;
                }
                group.push(content.trim_end());
            }
            None => flush(&mut group, group_start, &mut blocks),
        }
    }
    flush(&mut group, group_start, &mut blocks);

    blocks
}

/// One plane's result: exit status plus the two streams, captured to files so a
/// chatty block cannot deadlock on a full pipe.
struct Leg {
    rc: i32,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn run_leg(bin: &Path, plane: &str, program: &Path, tag: &str, dir: &Path) -> anyhow::Result<Leg> {
    let out_path = dir.join(format!("{tag}.{plane}.stdout"));
    let err_path = dir.join(format!("{tag}.{plane}.stderr"));
    let out_file = std::fs::File::create(&out_path)?;
    let err_file = std::fs::File::create(&err_path)?;

    let mut child = Command::new(bin)
        .arg("run")
        .arg(plane)
        .arg(program)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()?;

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() >= TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            timed_out = true;
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let stdout = std::fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
    Ok(Leg {
        rc: status.and_then(|s| s.code()).unwrap_or(-1),
        stdout,
        stderr,
        timed_out,
    })
}

/// How many doctests ran, were skipped, and failed. Failure text already carries
/// `file:line`; the caller prints it and returns the exit code.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tally {
    pub executed: usize,
    pub skipped: usize,
    pub failed: usize,
}

impl Tally {
    pub fn ok(&self) -> bool {
        self.failed == 0
    }
}

fn first_line(text: &str) -> &str {
    text.lines().find(|l| !l.trim().is_empty()).unwrap_or("")
}

fn collect_tl_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let p = entry.path();
        if p.is_dir() {
            collect_tl_files(&p, out);
        } else if p.extension().map_or(false, |e| e == "tl") {
            out.push(p);
        }
    }
}

/// The child runner: `TALLOW_BIN` when it names a real file (the override
/// `scripts/docs_examples.py` honours too), otherwise this binary.
fn runner_binary() -> anyhow::Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("TALLOW_BIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Ok(p);
        }
    }
    Ok(std::env::current_exe()?)
}

/// `tallow test --doc <path>`: scan every `.tl` file under `path`, execute each
/// marked block on both planes, print one line per doctest and a summary.
///
/// Returns the process exit code: `0` when every block honoured its marker,
/// `1` when any failed (unmarked, missing skip reason, wrong exit status,
/// missing error code, or a two-plane disagreement).
pub fn run_doc_tests(path: &Path) -> anyhow::Result<i32> {
    let mut files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_tl_files(path, &mut files);
    } else {
        anyhow::bail!("no doctest path found at '{}'", path.display());
    }
    files.sort();

    let bin = runner_binary()?;
    let tmp = tempfile::Builder::new()
        .prefix("tallow-doctest-")
        .tempdir()?;

    let mut tally = Tally::default();
    let mut failures: Vec<String> = Vec::new();

    for file in &files {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                tally.failed += 1;
                let msg = format!("{}: cannot read — {e}", file.display());
                println!("FAIL    {msg}");
                failures.push(msg);
                continue;
            }
        };

        for (idx, block) in extract_blocks(file, &text).into_iter().enumerate() {
            let where_ = block.where_();
            match &block.marker {
                Marker::Unmarked => {
                    tally.failed += 1;
                    let msg = format!(
                        "{where_}: unmarked fence — add `run`, `run:fail:<CODE>` or `skip:<reason>`"
                    );
                    println!("FAIL    {msg}");
                    failures.push(msg);
                }
                Marker::Skip(reason) => {
                    if reason.is_empty() {
                        tally.failed += 1;
                        let msg = format!("{where_}: `skip` without a reason");
                        println!("FAIL    {msg}");
                        failures.push(msg);
                    } else {
                        tally.skipped += 1;
                        println!("skip    {where_}  ({reason})");
                    }
                }
                Marker::Run | Marker::RunFail(_) => {
                    tally.executed += 1;
                    let tag = format!("block_{idx}");
                    let program = tmp.path().join(format!("{tag}.tl"));
                    std::fs::write(&program, &block.body)?;

                    let interp = run_leg(&bin, "--interpret", &program, &tag, tmp.path())?;
                    let native = run_leg(&bin, "--require-native", &program, &tag, tmp.path())?;

                    if let Some(failure) = judge(&block.marker, &interp, &native) {
                        tally.failed += 1;
                        println!("FAIL    {where_}  {failure}");
                        failures.push(format!("{where_}: {failure}"));
                    } else {
                        let label = match &block.marker {
                            Marker::Run => "run".to_string(),
                            Marker::RunFail(codes) => format!("run:fail:{}", codes.join(",")),
                            _ => unreachable!(),
                        };
                        println!("ok      {where_}  {label}");
                    }
                }
            }
        }
    }

    println!();
    if !failures.is_empty() {
        println!("failures:");
        for f in &failures {
            println!("  {f}");
        }
        println!();
    }
    println!(
        "doctest: {} executed, {} skipped, {} failed",
        tally.executed, tally.skipped, tally.failed
    );
    Ok(if tally.ok() { 0 } else { 1 })
}

/// Judge one block across both planes. Returns the failure text, or `None` when
/// the planes agreed and the block honoured its marker.
fn judge(marker: &Marker, interp: &Leg, native: &Leg) -> Option<String> {
    if interp.timed_out || native.timed_out {
        let plane = if interp.timed_out {
            "interpreter"
        } else {
            "native"
        };
        return Some(format!(
            "timed out after {}s on the {plane} plane",
            TIMEOUT.as_secs()
        ));
    }

    // The two-plane rule first: a doctest that passes on one plane lies about
    // the other. This is also how a native refusal surfaces — `--require-native`
    // exits non-zero with the refusal text instead of falling back, so the
    // statuses disagree and the refusal is printed.
    if interp.rc != native.rc {
        let mut msg = format!(
            "the planes disagree — interpreter exited {}, native exited {}",
            interp.rc, native.rc
        );
        let native_note = first_line(&native.stderr);
        if !native_note.is_empty() {
            msg.push_str(&format!("; native refused: {native_note}"));
        }
        return Some(msg);
    }
    if interp.stdout != native.stdout {
        return Some(format!(
            "the planes disagree on stdout — interpreter {:?}, native {:?}",
            interp.stdout, native.stdout
        ));
    }

    match marker {
        Marker::Run => {
            if interp.rc != 0 {
                let why = first_line(&interp.stderr);
                let why = if why.is_empty() {
                    first_line(&interp.stdout)
                } else {
                    why
                };
                return Some(format!("exited {} — {}", interp.rc, truncate(why, 160)));
            }
            None
        }
        Marker::RunFail(codes) => {
            // `docs_examples.py` matches codes against stdout+stderr combined.
            // Both planes are checked: the exit statuses already agree, so a
            // code that only one plane prints is an asymmetry the doctest is
            // meant to catch, not to average away.
            for (plane, leg) in [("interpreter", interp), ("native", native)] {
                let combined = format!("{}{}", leg.stdout, leg.stderr);
                let missing: Vec<&str> = codes
                    .iter()
                    .filter(|c| !combined.contains(c.as_str()))
                    .map(String::as_str)
                    .collect();
                if leg.rc == 0 {
                    return Some(format!("expected failure {codes:?}, but {plane} exited 0"));
                }
                if !missing.is_empty() {
                    return Some(format!(
                        "expected failure {codes:?}, but {plane} did not print {missing:?}"
                    ));
                }
            }
            None
        }
        Marker::Unmarked | Marker::Skip(_) => None,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_grammar_matches_the_docs_gate() {
        assert_eq!(parse_marker(""), Marker::Unmarked);
        assert_eq!(parse_marker("   "), Marker::Unmarked);
        assert_eq!(parse_marker(" run "), Marker::Run);
        assert_eq!(
            parse_marker("run:fail:E0125"),
            Marker::RunFail(vec!["E0125".into()])
        );
        assert_eq!(
            parse_marker("run:fail:E0125,E0153"),
            Marker::RunFail(vec!["E0125".into(), "E0153".into()])
        );
        // `run:E0125` is a run:fail, exactly as the docs gate treats it.
        assert_eq!(
            parse_marker("run:E0125"),
            Marker::RunFail(vec!["E0125".into()])
        );
        assert_eq!(
            parse_marker("skip:illustrative"),
            Marker::Skip("illustrative".into())
        );
        assert_eq!(parse_marker("skip:"), Marker::Skip(String::new()));
        assert_eq!(parse_marker("ignore"), Marker::Unmarked);
    }

    #[test]
    fn extraction_records_source_lines_and_skips_non_fences() {
        let src = "/// Doubles.\n///\n/// ```tallow run\n/// print(2)\n/// ```\npub fn double(x: Int) -> Int { x * 2 }\n";
        let blocks = extract_blocks(Path::new("demo.tl"), src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].line, 3);
        assert_eq!(blocks[0].marker, Marker::Run);
        assert_eq!(blocks[0].body, "print(2)\n");
    }

    #[test]
    fn a_gap_ends_a_group_so_a_fence_cannot_span_two_comments() {
        let src = "/// ```tallow run\nfn a() {}\n/// print(1)\n/// ```\n";
        let blocks = extract_blocks(Path::new("demo.tl"), src);
        assert!(
            blocks.is_empty(),
            "an unterminated fence is not a block: {blocks:?}"
        );
    }

    #[test]
    fn both_language_tags_are_doctests() {
        let src = "/// ```tl run\n/// print(1)\n/// ```\n";
        let blocks = extract_blocks(Path::new("demo.tl"), src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].marker, Marker::Run);
    }

    fn leg(rc: i32, stdout: &str, stderr: &str) -> Leg {
        Leg {
            rc,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            timed_out: false,
        }
    }

    #[test]
    fn a_native_refusal_is_a_disagreement_that_carries_the_text() {
        let interp = leg(0, "1\n", "");
        let native = leg(
            1,
            "",
            "* native build unavailable (no lowering for method 'x'); \
             --require-native refuses the interpreter fallback\n",
        );
        let msg =
            judge(&Marker::Run, &interp, &native).expect("a native refusal must fail the block");
        assert!(msg.contains("the planes disagree"), "{msg}");
        assert!(
            msg.contains("native refused: * native build unavailable"),
            "the refusal text was dropped: {msg}"
        );
    }

    #[test]
    fn run_fail_requires_its_codes_on_both_planes() {
        let interp = leg(1, "", "error[2:5]: E0152 destructuring mismatch\n");
        let native_silent = leg(1, "", "error[2:5]: something else\n");
        let msg = judge(
            &Marker::RunFail(vec!["E0152".into()]),
            &interp,
            &native_silent,
        )
        .expect("a code printed on one plane only must fail the block");
        assert!(msg.contains("native did not print"), "{msg}");

        let native_named = leg(1, "", "error[2:5]: E0152 destructuring mismatch\n");
        assert!(
            judge(
                &Marker::RunFail(vec!["E0152".into()]),
                &interp,
                &native_named
            )
            .is_none(),
            "both planes named the code, so the marker is honoured"
        );
    }
}
