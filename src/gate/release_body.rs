//! Build a GitHub release body from CHANGELOG.md, or fail loudly.
//!
//! Rust port of `scripts/release_body.py`. The rule it enforces: every release
//! states WHAT WAS ADDED and WHAT WAS FIXED. A release without both headings
//! does not get a body, so the workflow fails before anything is published — a
//! missing explanation is a release blocker, not a formatting preference.
//!
//! The heading test is a plain case-insensitive *substring* search over the
//! section body, not a heading parse: the Python checks `"added" in body.lower()`,
//! so a section whose prose merely mentions "added" satisfies it. That weakness
//! is preserved rather than silently tightened — tightening it would change which
//! releases pass, which is not a port's decision to make. CI compensates
//! downstream by grepping the emitted markdown for real `## Added` headings.
//!
//! Exit codes: 0 ok, 1 rule unmet, 64 usage.

use std::path::{Path, PathBuf};

const REQUIRED: [&str; 2] = ["added", "fixed"];

const VERIFY_BLOCK: &str = "\n---\n\nFive targets, each with a `.sha256` sidecar and a Sigstore keyless signature:\n\n```\ncosign verify-blob --signature <archive>.sig <archive>\nsha256sum -c <archive>.sha256\n```\n";

#[derive(Debug)]
pub enum Outcome {
    /// The body to print, or the `--check` success line.
    Ok(String),
    /// A rule was unmet: message for stderr.
    Rejected(String),
    /// Usage error (exit 64).
    Usage(String),
}

/// Return the changelog section for `version`, without the next heading.
///
/// Matches `^## \[<version>\]` at line start, then takes everything up to the
/// next line starting with `## [`. A version that is a prefix of another
/// (e.g. `v1.2` vs `v1.2.1`) cannot match the wrong section, because the
/// closing `]` is part of the pattern.
pub fn section(text: &str, version: &str) -> Option<String> {
    let opener = format!("## [{version}]");
    let mut rest: Option<&str> = None;
    let mut offset = 0usize;

    for line in text.split_inclusive('\n') {
        let at_line_start = offset == 0 || text.as_bytes()[offset - 1] == b'\n';
        let starts_with_open =
            at_line_start && line.starts_with(&opener);
        if rest.is_none() && starts_with_open {
            // Skip the rest of the heading line.
            let consumed = line.len();
            rest = Some(&text[offset + consumed..]);
            break;
        }
        offset += line.len();
    }
    let rest = rest?;

    // The next `## [` heading ends the section.
    let mut end = rest.len();
    let mut pos = 0usize;
    for line in rest.split_inclusive('\n') {
        let at_start = pos == 0 || rest.as_bytes()[pos - 1] == b'\n';
        if at_start && pos > 0 && line.starts_with("## [") {
            end = pos;
            break;
        }
        pos += line.len();
    }
    Some(rest[..end].trim_matches('\n').to_string())
}

pub struct Request<'a> {
    pub version: &'a str,
    pub check: bool,
    pub verified: Option<PathBuf>,
}

pub fn run(changelog_path: &Path, req: &Request<'_>) -> Outcome {
    // `--verified` must carry this run's measured numbers.
    let verified_text = match &req.verified {
        None => None,
        Some(p) => {
            let text = std::fs::read_to_string(p).unwrap_or_default();
            if text.trim().is_empty() {
                return Outcome::Rejected(format!(
                    "release_body: {} is missing or empty — a Verified section must carry this run's measured numbers",
                    p.display()
                ));
            }
            Some(text.trim().to_string())
        }
    };

    let changelog = match std::fs::read_to_string(changelog_path) {
        Ok(t) => t,
        Err(e) => {
            return Outcome::Rejected(format!(
                "release_body: cannot read {}: {e}",
                changelog_path.display()
            ))
        }
    };

    let Some(body) = section(&changelog, req.version) else {
        return Outcome::Rejected(format!(
            "release_body: no CHANGELOG section for {}; every release must record what was added and what was fixed",
            req.version
        ));
    };

    let lowered = body.to_lowercase();
    let missing: Vec<&str> = REQUIRED
        .iter()
        .copied()
        .filter(|h| !lowered.contains(h))
        .collect();
    if !missing.is_empty() {
        return Outcome::Rejected(format!(
            "release_body: {} is missing required heading(s): {} — the body must state what was added and what was fixed",
            req.version,
            missing.join(", ")
        ));
    }

    if req.check {
        return Outcome::Ok(format!(
            "release_body: {} OK ({} chars)",
            req.version,
            body.chars().count()
        ));
    }

    let mut out = String::new();
    out.push_str(&format!("# Tallow {}\n\n", req.version));
    // Known defect preserved from the Python original, deliberately:
    // `section()` starts AFTER the `## [version]` heading line, so `title_line`
    // is never the "— tagline" line the code appears to be testing for — it is
    // the first body line, usually `### Added`. When that line happens to
    // contain an em-dash the tagline branch fires and prints the heading text
    // as if it were the release tagline. Zero of the 21 current CHANGELOG
    // sections reach it, so it is dormant, and "fixing" it here would change
    // release bodies relative to the oracle. Recorded as a follow-up instead.
    let title_line = body.lines().next().unwrap_or(req.version);
    if let Some((_, after)) = title_line.split_once('—') {
        out.push_str(&format!("*{}*\n\n", after.trim()));
    }
    out.push_str(&body);
    // print(body) -> body + "\n"
    out.push('\n');
    if let Some(v) = verified_text {
        // print(); print("---"); print(); print(verified.strip())
        out.push_str("\n---\n\n");
        out.push_str(&v);
        out.push('\n');
    }
    // `print(VERIFY_BLOCK)` emits the block plus its own newline. VERIFY_BLOCK
    // already ends in "\n", so the Python's output ends with a blank line —
    // "\n\n" at EOF. Reproduced exactly, since the emitted body is compared
    // byte-for-byte downstream.
    out.push_str(VERIFY_BLOCK);
    out.push('\n');
    Outcome::Ok(out)
}

/// Parse argv (excluding the program name) into a request. Mirrors the Python's
/// positional-then-flags handling, including that `--verified` scans the whole
/// tail of argv rather than stopping at the first non-flag.
pub fn parse(argv: &[String]) -> Result<Request<'_>, Outcome> {
    if argv.is_empty() {
        return Err(Outcome::Usage(
            "usage: release_body.py <vX.Y.Z> [--check] [--verified PATH]".into(),
        ));
    }
    let version = &argv[0];
    let tail = &argv[1..];
    let check = tail.iter().any(|a| a == "--check");
    let verified = match tail.iter().position(|a| a == "--verified") {
        None => None,
        Some(idx) => match tail.get(idx + 1) {
            Some(p) => Some(PathBuf::from(p)),
            None => {
                return Err(Outcome::Usage(
                    "release_body: --verified needs a path".into(),
                ))
            }
        },
    };
    Ok(Request {
        version,
        check,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGELOG: &str = "# Changelog\n\n## [v1.2.1] — Gate hardening\n\n### Added\n- a gate\n\n### Fixed\n- a bug\n\n## [v1.2.0] — Before\n\n### Added\n- old\n";

    #[test]
    fn extracts_the_right_section() {
        let s = section(CHANGELOG, "v1.2.1").unwrap();
        // The section begins AFTER the `## [version]` heading line — the
        // tagline lives on that heading, not in the body. This is the fact that
        // makes the Python's `"—" in title_line` branch unreachable for its
        // intended purpose, so the assertion is on observed behaviour.
        assert_eq!(s.lines().next(), Some("### Added"));
        assert!(s.contains("### Fixed"));
        assert!(!s.contains("Before"), "section ran past the next heading");
    }

    #[test]
    fn version_prefix_does_not_match_a_longer_version() {
        // v1.2 must not silently take v1.2.1's section.
        assert!(section(CHANGELOG, "v1.2").is_none());
    }

    #[test]
    fn missing_version_is_none() {
        assert!(section(CHANGELOG, "v9.9.9").is_none());
    }

    #[test]
    fn body_prose_satisfies_the_heading_rule() {
        // Preserved weakness: the check is a substring search, so this section
        // passes without real headings. Documented, not "fixed".
        let text = "## [v0.1.0] — x\n\nSomething was added and fixed.\n";
        let s = section(text, "v0.1.0").unwrap();
        let lowered = s.to_lowercase();
        assert!(lowered.contains("added") && lowered.contains("fixed"));
    }
}
