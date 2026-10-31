//! Panic-policy drift gate: recompute what `docs/PANIC-POLICY.md` claims.
//!
//! Rust port of `scripts/panic_policy_check.py`. The document states two facts
//! about the tree — the shipped profiles set `panic = "abort"`, and a
//! `| file | sites | lines |` table lists every `catch_unwind` call site. This
//! parses that table as the declared census and recomputes both facts from the
//! tree so the document cannot silently go stale. There is no second copy of
//! the counts in this file.
//!
//! Two properties the Python relied on and this preserves deliberately:
//!
//! * Only *calls* count. `\bcatch_unwind\s*\(` requires a word boundary before
//!   the name, so the test function named
//!   `spawn_agent_crash_isolation_via_catch_unwind(` is a definition, not a
//!   call: the preceding `_` is a word character, so no boundary exists there.
//! * Comment lines are skipped, but only `//` and `*` prefixes. A trailing
//!   comment on a code line does not stop that line counting, because the match
//!   is anchored on the stripped line's *prefix*.
//!
//! Exit codes: 0 = policy matches the tree, 1 = drift, 2 = could not evaluate.

use std::fs;
use std::path::{Path, PathBuf};

/// Declared by `docs/PANIC-POLICY.md`. `[profile.max]` must *inherit* release
/// rather than restate `panic`.
const EXPECT_PROFILE_PANIC: &[(&str, &str)] = &[("release", "abort")];

/// Files that mention `catch_unwind` but are not shipped code.
const EXCLUDED: &[&str] = &["tests/fuzz_safety.rs"];

#[derive(Debug, Default)]
pub struct Report {
    /// `(check, status, message)` rows, in emission order.
    rows: Vec<(&'static str, &'static str, String)>,
    pub drift: bool,
    /// The manifest could not be read or parsed: not a drift verdict.
    pub unevaluable: bool,
}

impl Report {
    fn pass(&mut self, check: &'static str, msg: String) {
        self.rows.push((check, "pass", msg));
    }

    fn drift(&mut self, check: &'static str, msg: String) {
        self.rows.push((check, "DRIFT", msg));
        self.drift = true;
    }

    pub fn problems(&self) -> usize {
        self.rows.iter().filter(|r| r.1 == "DRIFT").count()
    }

    /// Rows render as `  <check ljust width>  <status:5>  <msg>`, then a blank
    /// line and the verdict. The padding is part of the output the differential
    /// test compares, so it is reproduced rather than tidied.
    pub fn lines(&self) -> Vec<String> {
        let width = self.rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
        let mut out: Vec<String> = self
            .rows
            .iter()
            .map(|(check, status, msg)| {
                format!("  {:<width$}  {:<5}  {}", check, status, msg, width = width)
            })
            .collect();
        out.push(String::new());
        out.push(format!(
            "PANIC-POLICY GATE: {}",
            if self.drift { "FAIL" } else { "PASS" }
        ));
        out
    }
}

/// Count `catch_unwind(` call sites in a file: non-comment lines only, with a
/// word boundary before the name so a longer identifier ending in it does not
/// count.
fn count_calls(path: &Path) -> usize {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => match fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => return 0,
        },
    };
    let mut n = 0;
    for line in text.lines() {
        let s = line.trim();
        if s.starts_with("//") || s.starts_with('*') {
            continue;
        }
        if contains_catch_unwind_call(s) {
            n += 1;
        }
    }
    n
}

/// `\bcatch_unwind\s*\(` — word boundary, the identifier, optional whitespace,
/// then an open paren.
fn contains_catch_unwind_call(s: &str) -> bool {
    const NEEDLE: &str = "catch_unwind";
    let bytes = s.as_bytes();
    let mut from = 0;
    while let Some(idx) = s[from..].find(NEEDLE) {
        let at = from + idx;
        // Word boundary before: start of string, or a non-word character.
        let boundary = at == 0 || !is_word_byte(bytes[at - 1]);
        if boundary {
            let mut rest = at + NEEDLE.len();
            while rest < bytes.len() && bytes[rest].is_ascii_whitespace() {
                rest += 1;
            }
            if rest < bytes.len() && bytes[rest] == b'(' {
                return true;
            }
        }
        from = at + NEEDLE.len();
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Walk `*.rs` under `root_dir`, returning relative paths (forward-slashed).
fn walk_rs(root_dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root_dir) else {
        return;
    };
    let mut items: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    items.sort();
    for p in items {
        if p.is_dir() {
            walk_rs(&p, base, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            if let Ok(rel) = p.strip_prefix(base) {
                out.push(rel.to_path_buf());
            }
        }
    }
}

fn rel_string(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    s.strip_prefix("./").map(str::to_owned).unwrap_or(s)
}

/// Parse the `| file | sites | lines |` table. `None` if the table is absent.
fn parse_declared_sites(text: &str) -> Option<Vec<(String, usize)>> {
    let mut declared: Vec<(String, usize)> = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let s = line.trim();
        if !in_table {
            if is_file_sites_header(s) {
                in_table = true;
            }
            continue;
        }
        if !s.starts_with('|') {
            break;
        }
        if is_table_separator(s) {
            continue;
        }
        if let Some((file, n)) = parse_file_sites_row(s) {
            declared.push((file, n));
        }
    }
    if declared.is_empty() {
        None
    } else {
        Some(declared)
    }
}

fn is_file_sites_header(s: &str) -> bool {
    let cells: Vec<&str> = s
        .split('|')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect();
    cells.len() >= 3
        && cells[0].eq_ignore_ascii_case("file")
        && cells[1].eq_ignore_ascii_case("sites")
        && cells[2].eq_ignore_ascii_case("lines")
}

fn is_table_separator(s: &str) -> bool {
    s.chars()
        .all(|c| c == '|' || c == '-' || c == ':' || c.is_whitespace())
}

fn parse_file_sites_row(s: &str) -> Option<(String, usize)> {
    let cells: Vec<&str> = s.split('|').map(str::trim).collect();
    // Leading '|' yields an empty first cell.
    if cells.len() < 3 {
        return None;
    }
    let file = cells[1].trim_matches('`');
    if file.is_empty() {
        return None;
    }
    let n = cells[2].parse::<usize>().ok()?;
    Some((file.to_string(), n))
}

/// Minimal TOML reader for the two facts that matter: `[profile.<name>]`'s
/// `panic` and `inherits` keys. Avoids pulling a TOML dependency into the gate
/// path; anything it cannot see reads as absent, which is what the policy check
/// treats as drift.
fn profile_keys(manifest: &str, profile: &str) -> (Option<String>, Option<String>) {
    let want = format!("[profile.{profile}]");
    let mut in_section = false;
    let mut panic = None;
    let mut inherits = None;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_section = line.trim_end() == want;
            continue;
        }
        if !in_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().trim_matches('"');
        let val = v.trim().trim_matches('"').to_string();
        match key {
            "panic" => panic = Some(val),
            "inherits" => inherits = Some(val),
            _ => {}
        }
    }
    (panic, inherits)
}

pub fn check(root: &Path) -> Report {
    let mut r = Report::default();

    let manifest_path = root.join("Cargo.toml");
    let Ok(manifest) = fs::read_to_string(&manifest_path) else {
        eprintln!("  could not parse {}: unreadable", manifest_path.display());
        r.unevaluable = true;
        return r;
    };

    let policy_path = root.join("docs/PANIC-POLICY.md");
    let Ok(policy) = fs::read_to_string(&policy_path) else {
        eprintln!("  could not parse {}: unreadable", policy_path.display());
        r.unevaluable = true;
        return r;
    };
    let Some(mut declared) = parse_declared_sites(&policy) else {
        eprintln!(
            "  could not parse {}: no `| file | sites | lines |` table",
            policy_path.display()
        );
        r.unevaluable = true;
        return r;
    };

    for (name, want) in EXPECT_PROFILE_PANIC {
        let (got, _) = profile_keys(&manifest, name);
        match got.as_deref() {
            Some(v) if v == *want => {
                r.pass("profile", format!("[profile.{name}] panic = {v}"));
            }
            Some(v) => r.drift(
                "profile",
                format!("[profile.{name}] panic = {v}, policy says {want}"),
            ),
            None => r.drift(
                "profile",
                format!("[profile.{name}] panic = <unset>, policy says {want}"),
            ),
        }
    }

    let (max_panic, max_inherits) = profile_keys(&manifest, "max");
    if max_panic.is_none() && max_inherits.as_deref() == Some("release") {
        r.pass("profile", "[profile.max] inherits release -> abort".into());
    } else {
        r.drift(
            "profile",
            format!(
                "[profile.max] panic={} inherits={} -- policy assumes it inherits release",
                max_panic.as_deref().unwrap_or("<unset>"),
                max_inherits.as_deref().unwrap_or("<none>")
            ),
        );
    }

    // Any file in shipped code that mentions catch_unwind and is not declared.
    let mut found: Vec<(String, usize)> = Vec::new();
    for base in ["src", "crates", "tests"] {
        let dir = root.join(base);
        if !dir.is_dir() {
            continue;
        }
        let mut rels = Vec::new();
        walk_rs(&dir, root, &mut rels);
        for rel in rels {
            let rel_s = rel_string(&rel);
            if EXCLUDED.contains(&rel_s.as_str()) {
                continue;
            }
            let n = count_calls(&root.join(&rel));
            if n > 0 {
                found.push((rel_s, n));
            }
        }
    }
    found.sort();

    declared.sort();
    for (rel, want) in &declared {
        let got = found
            .iter()
            .find(|(f, _)| f == rel)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        if got == *want {
            r.pass("call-sites", format!("{rel}: {got}"));
        } else {
            r.drift(
                "call-sites",
                format!("{rel}: {got} call site(s), policy says {want}"),
            );
        }
    }

    for (rel, got) in &found {
        if !declared.iter().any(|(d, _)| d == rel) {
            r.drift(
                "call-sites",
                format!("{rel}: {got} undocumented call site(s)"),
            );
        }
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn word_boundary_excludes_longer_identifiers() {
        assert!(!contains_catch_unwind_call(&longer_ident_call()));
        assert!(contains_catch_unwind_call(&qualified_call()));
        assert!(contains_catch_unwind_call(&spaced_call()));
    }

    // Fixtures are built at runtime rather than written into a literal: a
    // literal `catch_unwind(` in any file under `src/` is, by this gate's own
    // rule, an undocumented call site — and the gate would (correctly) fail on
    // its own test strings. Keeping the source text free of the token keeps the
    // census honest instead of declaring phantom shipping calls.
    fn longer_ident_call() -> String {
        format!("fn spawn_agent_crash_isolation_via_{}() {{", "catch_unwind")
    }

    fn qualified_call() -> String {
        format!("std::panic::{}{}", "catch_unwind", "(")
    }

    fn spaced_call() -> String {
        format!("{} (|| {{", "catch_unwind")
    }

    #[test]
    fn comment_prefixes_are_skipped() {
        let text = format!(
            "// {0}(x)\n* {0}(y)\n{0}(z)",
            "catch_unwind"
        );
        assert_eq!(count_calls_text(&text), 1);
    }

    fn count_calls_text(text: &str) -> usize {
        let mut n = 0;
        for line in text.lines() {
            let s = line.trim();
            if s.starts_with("//") || s.starts_with('*') {
                continue;
            }
            if contains_catch_unwind_call(s) {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn profile_section_reader_sees_panic_and_inherits() {
        let manifest = "[profile.release]\npanic = \"abort\"\n\n[profile.max]\ninherits = \"release\"\n";
        assert_eq!(
            profile_keys(manifest, "release"),
            (Some("abort".into()), None)
        );
        assert_eq!(
            profile_keys(manifest, "max"),
            (None, Some("release".into()))
        );
    }

    #[test]
    fn parse_reads_file_sites_table_not_the_profile_table() {
        let text = "\
| profile | `panic` | who |\n\
|---|---|---|\n\
| `[profile.release]` | `abort` | everything |\n\
\n\
| file | sites | lines |\n\
|---|---|---|\n\
| `src/main.rs` | 2 | 1, 2 |\n\
| `src/interp.rs` | 4 | 3 |\n\
| `src/supply_chain.rs` | 2 | 4 |\n\
| `src/mesh/worker.rs` | 1 | 5 |\n\
";
        let got = parse_declared_sites(text).expect("table");
        assert_eq!(
            got,
            vec![
                ("src/main.rs".into(), 2),
                ("src/interp.rs".into(), 4),
                ("src/supply_chain.rs".into(), 2),
                ("src/mesh/worker.rs".into(), 1),
            ]
        );
    }

    #[test]
    fn parse_returns_none_without_the_table() {
        assert!(parse_declared_sites("# no table here\n").is_none());
    }

    fn fixture_manifest() -> &'static str {
        "[profile.release]\npanic = \"abort\"\n\n[profile.max]\ninherits = \"release\"\n"
    }

    fn write_policy(root: &Path, rows: &str) {
        fs::create_dir_all(root.join("docs")).unwrap();
        let text = format!(
            "| profile | panic | who |\n|---|---|---|\n| `[profile.release]` | `abort` | all |\n\n| file | sites | lines |\n|---|---|---|\n{rows}"
        );
        fs::write(root.join("docs/PANIC-POLICY.md"), text).unwrap();
    }

    fn write_call(root: &Path, rel: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        // Built at runtime: a literal token in this file would be an
        // undocumented call site under src/.
        let body = format!("fn f() {{ let _ = {}{}|| {{}}); }}\n", "catch_unwind", "(");
        fs::write(path, body).unwrap();
    }

    #[test]
    fn extra_file_in_document_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("Cargo.toml"), fixture_manifest()).unwrap();
        write_policy(root, "| `src/ghost.rs` | 1 | missing |\n");
        let report = check(root);
        assert!(report.drift, "{:?}", report.lines());
        let text = report.lines().join("\n");
        assert!(
            text.contains("src/ghost.rs"),
            "document-only file must be named\n{text}"
        );
    }

    #[test]
    fn extra_file_in_tree_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("Cargo.toml"), fixture_manifest()).unwrap();
        write_policy(root, "| `src/ok.rs` | 1 | declared |\n");
        write_call(root, "src/ok.rs");
        write_call(root, "src/probe.rs");
        let report = check(root);
        assert!(report.drift, "{:?}", report.lines());
        let text = report.lines().join("\n");
        assert!(
            text.contains("src/probe.rs") && text.contains("undocumented"),
            "tree-only file must be named\n{text}"
        );
    }

    #[test]
    fn mutated_count_is_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("Cargo.toml"), fixture_manifest()).unwrap();
        write_policy(root, "| `src/ok.rs` | 2 | mutated |\n");
        write_call(root, "src/ok.rs");
        let report = check(root);
        assert!(report.drift, "{:?}", report.lines());
        let text = report.lines().join("\n");
        assert!(
            text.contains("src/ok.rs") && text.contains("policy says 2"),
            "count drift must name the file\n{text}"
        );
    }
}
