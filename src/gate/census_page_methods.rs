//! Census every method in `impl Page` against the codegen and interpreter arms.
//!
//! Rust port of `scripts/census_page_methods.py`. Why it exists: the three-entry
//! registry in `src/stdlib/browser.rs` does not cover the rest of the surface,
//! and two "unlowered method" claims were once invented from a grep that matched
//! only the exact tuple form `("Page", "name")`. The callbacks are dispatched
//! through or-patterns (`("Page", m @ ("on_console" | ...))`), so an exact-tuple
//! grep reports them as missing when they are implemented. This matches by
//! quoted name instead, which is the property that actually matters.
//!
//! Exit codes: 0 = every method is mentioned on both planes (or allowlisted),
//! 1 = at least one method is missing a plane, 2 = the parse found nothing (the
//! parse broke, not the surface).

use std::path::{Path, PathBuf};

/// Methods deliberately refused on both planes, with the reason. An entry here
/// is a decision, not a gap: the refusal itself is pinned by
/// `tests/browser_unlowered_gaps.rs`.
fn refused(method: &str) -> Option<&'static str> {
    match method {
        "goto_antibot" => Some(
            "egress is process-level (BrowserConfig.proxy); honest home is BrowserPool.create",
        ),
        _ => None,
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub methods: Vec<String>,
    pub lines: Vec<String>,
    pub problems: usize,
    /// Methods with no quoted name in codegen.rs / interp.rs respectively.
    pub missing_native: Vec<String>,
    pub missing_interp: Vec<String>,
    /// The parse found no methods: the scan broke, not the surface.
    pub parse_failed: bool,
}

impl Report {
    pub fn summary_line(&self) -> String {
        let missing_native = &self.missing_native;
        let missing_interp = &self.missing_interp;
        let mut union: Vec<&String> = missing_native.iter().collect();
        for m in missing_interp {
            if !union.contains(&m) {
                union.push(m);
            }
        }
        let implemented = self.methods.len() - union.len();
        format!(
            "checked {} Page methods, {} on both planes, {} mismatch(es)",
            self.methods.len(),
            implemented,
            self.problems
        )
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Parse `impl Page { ... }` method names from the manifest.
///
/// The surface is written `native fn …`; a plain `fn` pattern matched nothing
/// once and the script reported a clean-looking result from a scan that found
/// almost nothing. `native` is therefore optional here but the parse result is
/// checked by the caller: zero methods is a FAIL, not a pass.
pub fn page_methods(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let Some(start) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("impl Page"))
    else {
        return Vec::new();
    };
    let mut depth: i64 = 0;
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(start) {
        depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
        if let Some(name) = fn_name(line) {
            if depth >= 1 {
                found.push(name);
            }
        }
        if i > start && depth <= 0 {
            break;
        }
    }
    found
}

/// `\s*(?:native\s+)?fn\s+([a-z_0-9]+)\s*\(` — the name, if this line declares one.
fn fn_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("native ")
        .map(|r| r.trim_start())
        .unwrap_or(trimmed);
    let rest = rest.strip_prefix("fn ")?;
    let rest = rest.trim_start();
    let end = rest
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_'))
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    // Must be followed (after optional spaces) by `(`.
    let mut k = end;
    let bytes = rest.as_bytes();
    while k < bytes.len() && bytes[k] == b' ' {
        k += 1;
    }
    if bytes.get(k) != Some(&b'(') {
        return None;
    }
    Some(rest[..end].to_string())
}

fn contains_quoted(haystack: &str, name: &str) -> bool {
    haystack.contains(&format!("\"{name}\""))
}

/// Run the census against `root`.
pub fn check(root: &Path) -> Report {
    let Ok(manifest) = std::fs::read_to_string(root.join("stdlib/browser.tl")) else {
        return Report {
            parse_failed: true,
            ..Default::default()
        };
    };
    let methods = page_methods(&manifest);
    let mut report = Report {
        methods: methods.clone(),
        ..Default::default()
    };
    if methods.is_empty() {
        report.parse_failed = true;
        return report;
    }

    let codegen = std::fs::read_to_string(root.join("src/codegen.rs")).unwrap_or_default();
    let interp = std::fs::read_to_string(root.join("src/interp.rs")).unwrap_or_default();

    let mut missing_native = Vec::new();
    let mut missing_interp = Vec::new();
    for m in &methods {
        if !contains_quoted(&codegen, m) {
            missing_native.push(m.clone());
        }
        if !contains_quoted(&interp, m) {
            missing_interp.push(m.clone());
        }
    }
    report.missing_native = missing_native.clone();
    report.missing_interp = missing_interp.clone();

    for name in &missing_native {
        if let Some(reason) = refused(name) {
            report.lines.push(format!("refused-on-purpose  Page.{name}: {reason}"));
        } else {
            report.problems += 1;
            report
                .lines
                .push(format!("MISMATCH  Page.{name} has no codegen arm"));
        }
    }
    for name in &missing_interp {
        if refused(name).is_some() {
            continue;
        }
        report.problems += 1;
        report
            .lines
            .push(format!("MISMATCH  Page.{name} has no interpreter arm"));
    }
    report
}

pub fn check_here() -> Report {
    check(&repo_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_native_and_plain_fns_inside_the_impl() {
        let text = "impl Page {\n    native fn goto(url: String) -> Result\n    fn plain() {}\n}\nfn outside() {}\n";
        assert_eq!(page_methods(text), vec!["goto", "plain"]);
    }

    #[test]
    fn stops_at_the_end_of_the_impl_block() {
        let text = "impl Page {\n    native fn a()\n}\nimpl Other {\n    native fn b()\n}\n";
        assert_eq!(page_methods(text), vec!["a"]);
    }

    #[test]
    fn zero_methods_is_a_parse_failure_not_a_pass() {
        let dir = std::env::temp_dir().join(format!("pagemeth-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("stdlib")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("stdlib/browser.tl"), "impl Page {\n}\n").unwrap();
        std::fs::write(dir.join("src/codegen.rs"), "").unwrap();
        std::fs::write(dir.join("src/interp.rs"), "").unwrap();
        let r = check(&dir);
        assert!(r.parse_failed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_plane_is_a_mismatch() {
        let dir = std::env::temp_dir().join(format!("pagemeth-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("stdlib")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("stdlib/browser.tl"), "impl Page {\n    native fn goto()\n}\n").unwrap();
        std::fs::write(dir.join("src/codegen.rs"), "\"goto\"").unwrap();
        std::fs::write(dir.join("src/interp.rs"), "").unwrap();
        let r = check(&dir);
        assert_eq!(r.problems, 1);
        assert!(r.lines[0].contains("no interpreter arm"), "{:?}", r.lines);
        assert_eq!(r.summary_line(), "checked 1 Page methods, 0 on both planes, 1 mismatch(es)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_allowlisted_method_is_reported_but_not_a_problem() {
        let dir = std::env::temp_dir().join(format!("pagemeth-refused-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("stdlib")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("stdlib/browser.tl"),
            "impl Page {\n    native fn goto_antibot()\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("src/codegen.rs"), "").unwrap();
        std::fs::write(dir.join("src/interp.rs"), "").unwrap();
        let r = check(&dir);
        assert_eq!(r.problems, 0);
        assert!(r.lines[0].starts_with("refused-on-purpose  Page.goto_antibot: "));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
