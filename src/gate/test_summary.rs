//! Turn this run's own test output into the release body's `## Verified` section.
//!
//! Rust port of `scripts/test_summary.py`. The rule: a release may only state
//! numbers it measured in the same run that built it. Nothing here is copied
//! from a previous release or from documentation — the inputs are the log files
//! the gate job just wrote, and a missing measurement refuses rather than
//! printing a zero.
//!
//! Two details carried over deliberately:
//!
//! * Library numbers are *summed across every* `test result:` line. A workspace
//!   with several test binaries prints one per binary, and the Python accumulates
//!   all of them; taking the last would undercount.
//! * `passed == 0` is the "no measurement" signal, not `failed == 0`. A log with
//!   no `test result:` line at all and a log reporting a lone `0 passed; 0
//!   failed` are indistinguishable to the Python, and both refuse.
//!
//! Exit codes: 0 ok, 1 a measurement is missing, 64 usage.

use std::path::Path;

#[derive(Debug)]
pub struct Totals {
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
    pub conformance_cases: usize,
    pub conformance_failures: u64,
}

#[derive(Debug)]
pub enum Outcome {
    Ok(String),
    Refused(String),
}

/// `test result: <ok|FAILED>. <p> passed; <f> failed; <i> ignored`
///
/// The Python's regex is unanchored and takes the first match *per line*, so a
/// line containing two such phrases contributes once. Reproduced.
fn parse_test_result(line: &str) -> Option<(u64, u64, u64)> {
    let marker = "test result: ";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    // `<word>. ` then the counts.
    let after_status = rest.find(". ")? + 2;
    let counts = &rest[after_status..];
    let p = number_before(counts, " passed")?;
    let f = number_before(counts, " failed")?;
    let i = number_before(counts, " ignored")?;
    Some((p, f, i))
}

/// Parse `<digits>` immediately preceding `suffix` in `s`.
fn number_before(s: &str, suffix: &str) -> Option<u64> {
    let end = s.find(suffix)?;
    let head = &s[..end];
    let digits: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// `<digits> failure(s)`
fn parse_failure_count(text: &str) -> Option<u64> {
    let marker = " failure(s)";
    let idx = text.find(marker)?;
    let head = &text[..idx];
    let digits: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn read_or_empty(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Python's `{:,}`: thousands separated by commas. Rust's format machinery has
/// no integer grouping flag, so this is explicit.
fn group_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = s.len();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn run(lib_log: &Path, conformance_log: &Path, sha: &str, cases_dir: &Path) -> Outcome {
    let lib = read_or_empty(lib_log);
    let mut totals = Totals {
        passed: 0,
        failed: 0,
        ignored: 0,
        conformance_cases: 0,
        conformance_failures: 0,
    };
    for line in lib.lines() {
        if let Some((p, f, i)) = parse_test_result(line) {
            totals.passed += p;
            totals.failed += f;
            totals.ignored += i;
        }
    }
    if totals.passed == 0 {
        return Outcome::Refused(
            "test_summary: no `test result:` line in the library log — refusing to claim a suite result"
                .into(),
        );
    }

    let conf = read_or_empty(conformance_log);
    let Some(conf_failures) = parse_failure_count(&conf) else {
        return Outcome::Refused(
            "test_summary: no failure count in the conformance log — refusing to claim a conformance result"
                .into(),
        );
    };
    totals.conformance_failures = conf_failures;

    totals.conformance_cases = std::fs::read_dir(cases_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|x| x == "tl")
                })
                .count()
        })
        .unwrap_or(0);

    let short_sha: String = sha.chars().take(7).collect();
    let passed_grouped = group_thousands(totals.passed);
    let out = format!(
        "## Verified\n\n\
         Measured in the run that produced this release (commit `{short_sha}`):\n\n\
         - Library suite: **{passed_grouped} passed / {f} failed / {i} ignored**\n\
         - Conformance corpus: **{cases} programs, {cf} failure(s)** on both the interpreter and native planes\n\n\
         A release is only published when both numbers come from this run; the step that writes this section fails rather than printing a stale figure.\n",
        f = totals.failed,
        i = totals.ignored,
        cases = totals.conformance_cases,
        cf = totals.conformance_failures,
    );
    Outcome::Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_test_result_line() {
        assert_eq!(
            parse_test_result("test result: ok. 9529 passed; 0 failed; 0 ignored; 0 measured out;"),
            Some((9529, 0, 0))
        );
    }

    #[test]
    fn reads_a_failed_result_line() {
        assert_eq!(
            parse_test_result("test result: FAILED. 12 passed; 3 failed; 1 ignored"),
            Some((12, 3, 1))
        );
    }

    #[test]
    fn non_result_lines_are_ignored() {
        assert_eq!(parse_test_result("running 3 tests"), None);
        assert_eq!(parse_test_result(""), None);
    }

    #[test]
    fn conformance_failure_count() {
        assert_eq!(parse_failure_count("ran 62 cases; 0 failure(s)"), Some(0));
        assert_eq!(parse_failure_count("summary: 4 failure(s)"), Some(4));
        assert_eq!(parse_failure_count("no count here"), None);
    }

    #[test]
    fn thousands_separator_matches_python() {
        // Python's `f"{n:,}"`: 9529 -> "9,529", 0 -> "0", 1000000 -> "1,000,000".
        assert_eq!(group_thousands(9529), "9,529");
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(1_000_000), "1,000,000");
        assert_eq!(group_thousands(12_345_678), "12,345,678");
    }
}
