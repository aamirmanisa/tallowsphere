//! G59 — docs that run.
//!
//! Rust port of `scripts/docs_examples.py`. Every ```tallow / ```tl fenced block
//! in `docs/` and `README.md` must carry an explicit marker, and every `run`
//! marker is executed. A stale example therefore fails CI instead of quietly
//! lying in the docs.
//!
//! Markers (after the language, in the fence info string):
//!
//! ```text
//! ```tallow run                  execute; must exit 0
//! ```tallow run:fail:E0125       execute; must exit non-zero AND print every code
//! ```tallow skip:<reason>        not executed; the reason is required
//! ```
//!
//! An unmarked block is an error: silence is how examples rot.
//!
//! Two behaviours carried over deliberately:
//!
//! * **No PATH fallback.** A `tallow` on PATH is a different build, and testing
//!   docs against it reports the repo's examples as wrong when the only wrong
//!   thing is the binary. Resolution order is explicit `--bin`, `$TALLOW_BIN`,
//!   `target/debug/tallow`, `target/release/tallow`, then a hard error.
//! * `--only` is applied *after* marker validation, so a block with a bad marker
//!   still fails even when the caller narrowed to another file. That is the
//!   Python's order and it is the safer one.
//!
//! Exit codes: 0 = every block honoured its marker, 1 = at least one failure.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const LANGS: [&str; 2] = ["tallow", "tl"];
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Kind {
    Unmarked,
    Run,
    RunFail(Vec<String>),
    Skip(String),
}

#[derive(Debug)]
pub struct Block {
    /// 1-based line of the opening fence.
    pub line: usize,
    pub kind: Kind,
    pub body: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub ran: usize,
    pub skipped: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

impl Report {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "docs_examples: {} executed, {} skipped, {} failed",
            self.ran, self.skipped, self.failed
        )];
        for f in &self.failures {
            out.push(format!("  FAIL {f}"));
        }
        out
    }
}

/// `(kind, reason_or_empty, required_error_codes)` from a fence info string.
pub fn parse_marker(info: &str) -> Kind {
    let info = info.trim();
    if info.is_empty() {
        return Kind::Unmarked;
    }
    let (head, rest) = match info.split_once(':') {
        Some((h, r)) => (h.trim(), r.trim()),
        None => (info, ""),
    };
    match head {
        "run" => {
            let codes_src = if let Some(tail) = rest.strip_prefix("fail:") {
                tail
            } else {
                rest
            };
            let codes: Vec<String> = codes_src
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect();
            if rest.starts_with("fail:") || !codes.is_empty() {
                Kind::RunFail(codes)
            } else {
                Kind::Run
            }
        }
        "skip" => Kind::Skip(rest.to_string()),
        _ => Kind::Unmarked,
    }
}

/// Find every fenced block in `text` whose language is in LANGS.
///
/// The Python's regex is `^```(tallow|tl)([^\n]*)\n(.*?)^```[ \t]*$` with
/// DOTALL/MULTILINE: it matches at line starts, takes the remainder of the info
/// line unanchored, and ends at the first line that is ``` optionally followed
/// by spaces/tabs. Reproduced with an explicit line scan.
pub fn find_blocks(text: &str) -> Vec<Block> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut blocks = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let lang_match = LANGS.iter().find_map(|l| {
            line.strip_prefix("```")
                .filter(|rest| rest.starts_with(l))
                .map(|rest| (l.len(), rest[l.len()..].to_string()))
        });
        let Some((_lang_len, info)) = lang_match else {
            i += 1;
            continue;
        };
        // Opening fence at 1-based line i+1; body runs until a closing fence.
        let open_line = i + 1;
        let mut body = String::new();
        let mut j = i + 1;
        let mut closed = false;
        while j < lines.len() {
            let t = lines[j];
            if let Some(after) = t.strip_prefix("```") {
                if after.chars().all(|c| c == ' ' || c == '\t') {
                    closed = true;
                    break;
                }
            }
            body.push_str(t);
            body.push('\n');
            j += 1;
        }
        if closed {
            blocks.push(Block {
                line: open_line,
                kind: parse_marker(&info),
                body,
            });
            i = j + 1;
        } else {
            i += 1;
        }
    }
    blocks
}

fn docs_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let readme = root.join("README.md");
    if readme.exists() {
        files.push(readme);
    }
    let docs = root.join("docs");
    let mut found = Vec::new();
    walk_md(&docs, &mut found);
    found.sort();
    files.extend(found);
    files
}

fn walk_md(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_md(&p, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
}

/// Resolve the binary. Deliberately NO PATH fallback — see the module docs.
pub fn find_binary(explicit: Option<&str>, root: &Path) -> Option<PathBuf> {
    if let Some(c) = explicit {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(env) = std::env::var_os("TALLOW_BIN") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    for rel in ["target/debug/tallow", "target/release/tallow"] {
        let p = root.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Run `binary run <src>` with a deadline. `None` means it exceeded `timeout`
/// (the child is killed), matching the Python's `subprocess.TimeoutExpired`
/// branch. `Some(None)`-style ambiguity is avoided by using `Option<Output>`:
/// spawn failure also yields `None`, and both are failures.
fn run_with_timeout(binary: &Path, src: &Path, timeout: Duration) -> Option<std::process::Output> {
    use std::io::Read;
    use std::process::Stdio;

    let mut child = Command::new(binary)
        .arg("run")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut stderr);
    }
    let status = child.wait().ok()?;
    Some(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

pub fn run(root: &Path, binary: &Path, only: Option<&str>) -> Report {
    let mut report = Report::default();
    let tmp = std::env::temp_dir().join(format!("tallow-docs-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    for path in docs_files(root) {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for block in find_blocks(&text) {
            let where_ = format!("{rel}:{}", block.line);
            match &block.kind {
                Kind::Unmarked => {
                    report.failed += 1;
                    report.failures.push(format!(
                        "{where_}: unmarked fence — add `run`, `run:fail:<CODE>` or `skip:<reason>`"
                    ));
                    continue;
                }
                Kind::Skip(reason) => {
                    if reason.is_empty() {
                        report.failed += 1;
                        report
                            .failures
                            .push(format!("{where_}: `skip` without a reason"));
                        continue;
                    }
                    report.skipped += 1;
                    continue;
                }
                _ => {}
            }

            if let Some(needle) = only {
                if !rel.contains(needle) {
                    continue;
                }
            }
            report.ran += 1;

            let src = tmp.join(format!("block_{}_{}.tl", block.line, report.ran));
            if std::fs::write(&src, &block.body).is_err() {
                report.failed += 1;
                report
                    .failures
                    .push(format!("{where_}: could not write temp source"));
                continue;
            }

            let out = run_with_timeout(binary, &src, TIMEOUT);
            let code = match &out {
                Some(o) => o.status.code().unwrap_or(-1),
                None => {
                    report.failed += 1;
                    report.failures.push(format!(
                        "{where_}: timed out after {}s",
                        TIMEOUT.as_secs()
                    ));
                    continue;
                }
            };
            let o = out.expect("checked above");
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );

            match &block.kind {
                Kind::Run => {
                    if code != 0 {
                        report.failed += 1;
                        let first = output.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                        let snippet: String = first.chars().take(160).collect();
                        report
                            .failures
                            .push(format!("{where_}: exited {code} — {snippet}"));
                    }
                }
                Kind::RunFail(codes) => {
                    let missing: Vec<&String> =
                        codes.iter().filter(|c| !output.contains(c.as_str())).collect();
                    if code == 0 || !missing.is_empty() {
                        report.failed += 1;
                        let why = if code == 0 {
                            "exited 0".to_string()
                        } else {
                            format!("did not print {missing:?}")
                        };
                        report
                            .failures
                            .push(format!("{where_}: expected failure {codes:?}, but {why}"));
                    }
                }
                _ => {}
            }
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_parsing() {
        assert_eq!(parse_marker(""), Kind::Unmarked);
        assert_eq!(parse_marker("  "), Kind::Unmarked);
        assert_eq!(parse_marker(" run"), Kind::Run);
        assert_eq!(
            parse_marker(" run:fail:E0125"),
            Kind::RunFail(vec!["E0125".into()])
        );
        assert_eq!(
            parse_marker(" run:E0125,E0100"),
            Kind::RunFail(vec!["E0125".into(), "E0100".into()])
        );
        assert_eq!(parse_marker(" skip: needs network"), Kind::Skip("needs network".into()));
        assert_eq!(parse_marker(" skip"), Kind::Skip(String::new()));
        assert_eq!(parse_marker("whatever"), Kind::Unmarked);
    }

    #[test]
    fn finds_fenced_blocks_with_line_numbers() {
        let text = "# T\n\n```tallow run\nlet x = 1\nprint(x)\n```\n\ntext\n";
        let blocks = find_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].line, 3);
        assert_eq!(blocks[0].kind, Kind::Run);
        assert_eq!(blocks[0].body, "let x = 1\nprint(x)\n");
    }

    #[test]
    fn closing_fence_may_have_trailing_spaces() {
        let text = "```tl run\nlet x = 1\n```   \n";
        let blocks = find_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].body, "let x = 1\n");
    }

    #[test]
    fn unclosed_fence_is_not_a_block() {
        let text = "```tallow run\nlet x = 1\n";
        assert!(find_blocks(text).is_empty());
    }

    #[test]
    fn rust_fences_are_ignored() {
        let text = "```rust run\nlet x = 1;\n```\n";
        assert!(find_blocks(text).is_empty());
    }
}
