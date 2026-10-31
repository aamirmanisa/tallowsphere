//! Capability-registry check: the machine-readable `surface_entry` claims must
//! match the code.
//!
//! Rust port of `scripts/check_capability_registry.py`. `surface_entry` in
//! `src/stdlib/browser.rs` asserts, per method, which planes implement it. Those
//! assertions were wrong twice: `Page.goto_antibot` claimed
//! `implemented_interp_routed` with zero arms, and `Page.resolve_antibot` had no
//! entry at all. Both were found by hand, weeks late.
//!
//! The claim is derived from the registry and the fact from the arms:
//!
//! ```text
//! status contains "native"  -> src/codegen.rs must contain ("Page", "X")
//! status contains "interp"  -> src/interp.rs  must contain ("Page", "X")
//! status is declared_*      -> neither file may contain it
//! ```
//!
//! Reverse assertions are deliberately omitted: statuses such as
//! `implemented_mock_contract_tested` describe a plane this gate cannot
//! enumerate, so "no arm expected" would produce false failures.
//!
//! Output is byte-identical to the Python original so the two can be diffed
//! during adoption; `tests/gate_capability_registry_parity.rs` pins that.

use std::path::{Path, PathBuf};

/// One `surface_entry(label, area, status, ..)` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub label: String,
    pub area: String,
    pub status: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub entries: Vec<Entry>,
    pub checked: usize,
    pub problems: Vec<String>,
}

impl Report {
    pub fn summary_line(&self) -> String {
        format!(
            "checked {} Page entries, {} mismatches",
            self.checked,
            self.problems.len()
        )
    }

    pub fn problem_lines(&self) -> Vec<String> {
        self.problems
            .iter()
            .map(|p| format!("MISMATCH {p}"))
            .collect()
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Read the first three string literals of a `surface_entry` block.
///
/// The original matches `"label"\s*,\s*"area"\s*,\s*"status"` where status is
/// `[a-z_]+`. Comment lines are stripped from the block first: the
/// `goto_antibot` entry documents its own status inline, and a flat scan over
/// the raw text silently skipped it — a checker that undercounts its population
/// is the defect it exists to catch.
fn parse_block(block: &str) -> Option<(String, String, String)> {
    let kept: String = block
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let bytes = kept.as_bytes();
    let mut i = 0usize;
    // Literals in order: label, area, status.
    let mut lits: Vec<String> = Vec::new();
    while i < bytes.len() && lits.len() < 3 {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        // Only a literal that starts an argument counts: it must be the first
        // non-space, non-comma character here. The original's regex anchored the
        // whole triple, so require this literal to be followed by `,` then by
        // the next literal — checked implicitly by collecting in order.
        let start = i + 1;
        let mut j = start;
        let mut closed = false;
        while j < bytes.len() {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            if bytes[j] == b'"' {
                closed = true;
                break;
            }
            j += 1;
        }
        if !closed {
            break;
        }
        lits.push(kept[start..j].to_string());
        i = j + 1;
    }
    if lits.len() < 3 {
        return None;
    }
    // The status must be `[a-z_]+` in the original; anything else means this
    // was not the triple the regex would have matched.
    let status = lits.pop().unwrap();
    if status.is_empty() || !status.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
        return None;
    }
    let area = lits.pop().unwrap();
    let label = lits.pop().unwrap();
    Some((label, area, status))
}

/// Every `surface_entry(..)` claim in the registry text.
pub fn entries(text: &str) -> Vec<Entry> {
    const NEEDLE: &str = "surface_entry(";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find(NEEDLE) {
        let after = &rest[pos + NEEDLE.len()..];
        if let Some((label, area, status)) = parse_block(after) {
            out.push(Entry {
                label,
                area,
                status,
            });
        }
        rest = after;
    }
    out
}

/// Count `("Page", "<method>"` arms in a plane's source.
pub fn arms(path: &Path, method: &str) -> usize {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    let bytes = text.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        // `(` then optional whitespace, `"Page"`, optional whitespace, `,`,
        // optional whitespace, `"<method>"`
        if bytes[i] == b'(' {
            let mut j = i + 1;
            let skip_ws = |k: &mut usize| {
                while *k < bytes.len() && bytes[*k].is_ascii_whitespace() {
                    *k += 1;
                }
            };
            skip_ws(&mut j);
            if text[j..].starts_with("\"Page\"") {
                j += 6;
                skip_ws(&mut j);
                if bytes.get(j) == Some(&b',') {
                    j += 1;
                    skip_ws(&mut j);
                    let needle = format!("\"{method}\"");
                    if text[j..].starts_with(&needle) {
                        count += 1;
                    }
                }
            }
        }
        i += 1;
    }
    count
}

/// `Page.<method>` from a label, if it is one.
///
/// The original matches `Page\.([A-Za-z0-9_]+)` with `re.match`, so the method
/// is the ident PREFIX and anything after it is ignored: the registry spells
/// `Page.goto_antibot (egress map)` and `Page.resolve_antibot (opts map)`, and
/// requiring the ident to be the whole remainder silently dropped both — the
/// exact undercount this gate exists to catch.
fn page_method(label: &str) -> Option<&str> {
    let rest = label.strip_prefix("Page.")?;
    let end = rest
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

/// Run the check against `root`.
pub fn check(root: &Path) -> Report {
    let registry = root.join("src/stdlib/browser.rs");
    let native = root.join("src/codegen.rs");
    let interp = root.join("src/interp.rs");

    let Ok(text) = std::fs::read_to_string(&registry) else {
        return Report::default();
    };
    let found = entries(&text);
    let mut report = Report {
        entries: found.clone(),
        ..Default::default()
    };

    for e in &found {
        let Some(method) = page_method(&e.label) else {
            continue;
        };
        report.checked += 1;
        let n = arms(&native, method);
        let i = arms(&interp, method);

        if e.status.starts_with("declared_") {
            if n > 0 || i > 0 {
                report.problems.push(format!(
                    "{method}: registry says {}, but arms exist (codegen={n}, interp={i})",
                    e.status
                ));
            }
            continue;
        }
        if e.status.contains("native") && n == 0 {
            report
                .problems
                .push(format!("{method}: registry says {}, codegen has no arm", e.status));
        }
        if e.status.contains("interp") && i == 0 {
            report
                .problems
                .push(format!("{method}: registry says {}, interp has no arm", e.status));
        }
    }
    report
}

pub fn check_here() -> Report {
    check(&repo_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(status: &str) -> String {
        format!(
            "surface_entry(\n    \"Page.demo\",\n    \"runtime_entrypoint\",\n    \"{status}\",\n    \"cdp\",\n    true,\n),\n"
        )
    }

    fn fixture(tag: &str, registry: &str, codegen: &str, interp: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("caplist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src/stdlib")).unwrap();
        std::fs::write(dir.join("src/stdlib/browser.rs"), registry).unwrap();
        std::fs::write(dir.join("src/codegen.rs"), codegen).unwrap();
        std::fs::write(dir.join("src/interp.rs"), interp).unwrap();
        dir
    }

    #[test]
    fn parses_label_area_status() {
        let got = entries(&entry("implemented_both_planes"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].label, "Page.demo");
        assert_eq!(got[0].area, "runtime_entrypoint");
        assert_eq!(got[0].status, "implemented_both_planes");
    }

    /// The defect the comment-stripping exists for: an inline status comment
    /// must not hide the entry.
    #[test]
    fn comment_between_arguments_does_not_hide_the_entry() {
        let text = "surface_entry(\n    \"Page.demo\",\n    // status is declared below\n    \"runtime_entrypoint\",\n    \"declared_absent\",\n);\n";
        let got = entries(text);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].status, "declared_absent");
    }

    #[test]
    fn a_missing_native_arm_is_a_mismatch() {
        let dir = fixture(
            "no-native",
            &entry("implemented_native_mock_contract_tested"),
            "// no arms\n",
            "(\"Page\", \"demo\") => {}\n",
        );
        let r = check(&dir);
        assert_eq!(r.checked, 1);
        assert_eq!(r.problems.len(), 1);
        assert!(r.problems[0].contains("codegen has no arm"), "{:?}", r.problems);
        assert_eq!(r.summary_line(), "checked 1 Page entries, 1 mismatches");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_interp_arm_is_a_mismatch() {
        let dir = fixture(
            "no-interp",
            &entry("implemented_interp_routed"),
            "(\"Page\", \"demo\") => {}\n",
            "// nothing\n",
        );
        let r = check(&dir);
        assert_eq!(r.problems.len(), 1);
        assert!(r.problems[0].contains("interp has no arm"), "{:?}", r.problems);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `declared_*` claims must have NO arms; one is a mismatch.
    #[test]
    fn declared_status_with_an_arm_is_a_mismatch() {
        let dir = fixture(
            "declared",
            &entry("declared_absent"),
            "(\"Page\", \"demo\") => {}\n",
            "// nothing\n",
        );
        let r = check(&dir);
        assert_eq!(r.problems.len(), 1);
        assert!(r.problems[0].contains("but arms exist"), "{:?}", r.problems);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_matching_registry_reports_nothing() {
        let dir = fixture(
            "clean",
            &entry("implemented_native_mock_contract_tested"),
            "(\"Page\", \"demo\") => {}\n",
            "(\"Page\", \"demo\") => {}\n",
        );
        let r = check(&dir);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert_eq!(r.summary_line(), "checked 1 Page entries, 0 mismatches");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A label with a trailing parenthetical is a Page entry: the registry says
    /// `Page.resolve_antibot (opts map)` and the method is `resolve_antibot`.
    #[test]
    fn parenthetical_label_still_resolves_the_method() {
        assert_eq!(page_method("Page.resolve_antibot (opts map)"), Some("resolve_antibot"));
        assert_eq!(page_method("Page.goto_antibot (egress map)"), Some("goto_antibot"));
        assert_eq!(page_method("Page.goto"), Some("goto"));
        assert_eq!(page_method("Browser.launch"), None);
    }

    /// A non-Page label (Browser.launch, cdp.pipe, ...) is not counted: the arms
    /// this gate can enumerate are the Page ones.
    #[test]
    fn non_page_entries_are_not_checked() {
        let text = "surface_entry(\n    \"Browser.launch\",\n    \"runtime_entrypoint\",\n    \"implemented_non_live_contract_tested\",\n);\n";
        let dir = fixture("nonpage", text, "", "");
        let r = check(&dir);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.checked, 0);
        assert!(r.problems.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
