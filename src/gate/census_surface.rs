//! Census empty-bodied `.tl` declarations against the two execution planes.
//!
//! Rust port of `scripts/census_surface.py`. A method declared as
//! `fn name(...) -> T { }` in `stdlib/` is a *declaration*: it has no Tallow
//! body, so the compiler/runtime must supply the behaviour. If neither
//! `src/codegen.rs` nor `src/interp.rs` mentions the name, the method is
//! implemented in appearance only — exactly the defect class this repository
//! keeps finding by hand (three unmangled FFIs, two handlers that could never
//! fire). Methods with a real body are skipped: their behaviour lives in Tallow
//! source.
//!
//! Exit codes: 0 clean, 1 an unmentioned declaration, 2 the scan is broken (a
//! zero-declaration parse over real impl blocks is an instrument failure, not a
//! clean surface — the manifest writes `native fn … { // native: … }`, and once
//! that comment is stripped the body is not empty).

use std::path::{Path, PathBuf};

/// Declarations deliberately refused on both planes rather than lowered. Each
/// entry names the refusal so it stays a decision, not a hiding place.
fn refused(ty: &str, name: &str) -> Option<&'static str> {
    match (ty, name) {
        ("Page", "goto_antibot") => Some(
            "egress is process-level (BrowserConfig.proxy); honest home is BrowserPool.create",
        ),
        _ => None,
    }
}

/// Declared in `stdlib/time.tl`'s `impl i64`, with no arm in either plane. Kept
/// as dated debt rather than an exclusion the checker cannot see: the
/// interpreter's duration methods return Int milliseconds while the manifest
/// declares `-> Duration`, so implementing these two is a semantics decision,
/// not a patch.
fn known_unimplemented(key: &str) -> Option<&'static str> {
    match key {
        "i64.nanoseconds" | "i64.microseconds" => Some("2027-03-31"),
        _ => None,
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub declarations: usize,
    pub unmentioned: usize,
    pub refusals: usize,
    pub debt: usize,
    /// Zero declarations over real impl blocks: the body rule does not match
    /// the manifest's current form.
    pub parse_failed: bool,
    pub impl_blocks: usize,
}

impl Report {
    pub fn summary_line(&self) -> String {
        format!(
            "checked {} empty-bodied declarations, {} unmentioned on both planes, {} declared refusals, {} dated debt",
            self.declarations, self.unmentioned, self.refusals, self.debt
        )
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Remove `//`-to-end-of-line comments. The original is line-based: the first
/// `//` on a line truncates it, whatever the quoting context.
fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Find `impl <Type> {` blocks and, for each, the `fn` declarations inside.
///
/// The manifest form is a bare signature — `native fn goto(self, url: String)
/// -> Void` with no braces at all. So "empty body" means "no brace follows the
/// signature", not "{ }". Two earlier versions of the Python function assumed
/// braces: the first matched a brace inside a nested block and reported bodies
/// belonging to other methods; the second matched none and printed a clean zero
/// over 94 impl blocks. This mirrors the fixed version.
pub fn parse_impls(text: &str) -> Vec<(String, String, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0usize;

    while let Some(rel) = find_impl_start(&text[pos..]) {
        let abs = pos + rel;
        let m_end = abs + impl_prefix_len(&text[abs..]);
        let ty = impl_type_name(&text[abs..]);

        // Walk to the matching close brace of the impl block.
        let mut depth = 1i64;
        let mut i = m_end;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        let block_end = i.saturating_sub(1);
        let block = &text[m_end..block_end.min(text.len())];
        scan_fns(block, &ty, &mut out);
        pos = i;
    }
    out
}

/// Byte offset of the next `impl \w+ {` at `s`, if any.
fn find_impl_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if s[i..].starts_with("impl") {
            let before_ok = i == 0
                || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let after = bytes.get(i + 4).copied();
            if before_ok && after.is_some_and(|c| c.is_ascii_whitespace()) {
                let rest = &s[i + 4..];
                let trimmed = rest.trim_start();
                let name_len = trimmed
                    .char_indices()
                    .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
                    .map(|(j, _)| j)
                    .unwrap_or(trimmed.len());
                if name_len > 0 && trimmed[name_len..].trim_start().starts_with('{') {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Length from `impl` through the opening `{` (inclusive) plus its trailing
/// content offset: `impl Type {` -> index just past `{`.
fn impl_prefix_len(s: &str) -> usize {
    let rest = &s[4..];
    let lead = rest.len() - rest.trim_start().len();
    let trimmed = rest.trim_start();
    let name_len = trimmed
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(j, _)| j)
        .unwrap_or(trimmed.len());
    let after_name = &trimmed[name_len..];
    let ws = after_name.len() - after_name.trim_start().len();
    4 + lead + name_len + ws + 1 // past `{`
}

fn impl_type_name(s: &str) -> String {
    let rest = s[4..].trim_start();
    let name_len = rest
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(j, _)| j)
        .unwrap_or(rest.len());
    rest[..name_len].to_string()
}

/// Every `(?:native\s+)?fn\s+(\w+)\s*\(` inside an impl block, with its body.
fn scan_fns(block: &str, ty: &str, out: &mut Vec<(String, String, String)>) {
    let bytes = block.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // `fn ` at a word boundary, optionally preceded by `native `.
        let is_native = block[i..].starts_with("native");
        let fn_at = if is_native {
            let after = i + 6;
            if block[after..].starts_with(|c: char| c.is_whitespace()) {
                let mut k = after;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if block[k..].starts_with("fn") { Some(k) } else { None }
            } else {
                None
            }
        } else if block[i..].starts_with("fn") {
            Some(i)
        } else {
            None
        };
        let Some(fn_pos) = fn_at else {
            i += 1;
            continue;
        };
        // Word boundary before `fn` / `native`.
        if fn_pos > 0 {
            let prev = bytes[fn_pos - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                i = fn_pos + 2;
                continue;
            }
        }
        let after_fn = fn_pos + 2;
        if block[after_fn..].starts_with(|c: char| c.is_alphanumeric() || c == '_') {
            i = after_fn;
            continue;
        }
        let mut j = after_fn;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let name_start = j;
        let name_end = block[name_start..]
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
            .map(|(k, _)| name_start + k)
            .unwrap_or(block.len());
        if name_end == name_start {
            i = after_fn;
            continue;
        }
        let name = block[name_start..name_end].to_string();
        let mut k = name_end;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if bytes.get(k) != Some(&b'(') {
            i = after_fn;
            continue;
        }
        // Walk the parameter list.
        let mut paren = 1i64;
        k += 1;
        while k < bytes.len() && paren > 0 {
            match bytes[k] {
                b'(' => paren += 1,
                b')' => paren -= 1,
                _ => {}
            }
            k += 1;
        }
        let eol = block[k..].find('\n').map(|p| k + p).unwrap_or(block.len());
        let line_rest = &block[k..eol];
        if !line_rest.contains('{') {
            // Declared, no body — the manifest form.
            out.push((ty.to_string(), name, String::new()));
            i = k;
            continue;
        }
        let body_open = k + line_rest.find('{').unwrap();
        let mut d = 1i64;
        let mut n = body_open + 1;
        while n < bytes.len() && d > 0 {
            match bytes[n] {
                b'{' => d += 1,
                b'}' => d -= 1,
                _ => {}
            }
            n += 1;
        }
        let body = &block[body_open + 1..n.saturating_sub(1).min(block.len())];
        out.push((ty.to_string(), name, body.to_string()));
        i = n;
    }
}

fn collect_tl(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_tl(&p, out);
        } else if p.extension().is_some_and(|x| x == "tl") {
            out.push(p);
        }
    }
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn read_stripped(p: &Path) -> String {
    strip_comments(&std::fs::read_to_string(p).unwrap_or_default())
}

/// Run the census against `root`.
pub fn check(root: &Path) -> Report {
    let codegen = read_stripped(&root.join("src/codegen.rs"));
    let interp = read_stripped(&root.join("src/interp.rs"));

    let mut runtime_paths = Vec::new();
    collect_rs(&root.join("src/runtime"), &mut runtime_paths);
    let runtime = runtime_paths
        .iter()
        .map(|p| read_stripped(p))
        .collect::<Vec<_>>()
        .join("\n");

    // The interpreter reaches many stdlib methods through
    // src/stdlib/<module>.rs::dispatch_method, not through a literal in
    // interp.rs. That plane counts.
    let mut stdlib_paths = Vec::new();
    collect_rs(&root.join("src/stdlib"), &mut stdlib_paths);
    let stdlib_rs = stdlib_paths
        .iter()
        .map(|p| read_stripped(p))
        .collect::<Vec<_>>()
        .join("\n");

    let haystack = format!("{codegen}\n{interp}\n{runtime}\n{stdlib_rs}");

    let mut tl_paths = Vec::new();
    collect_tl(&root.join("stdlib"), &mut tl_paths);
    tl_paths.sort();

    let mut report = Report::default();
    let mut unmentioned: Vec<String> = Vec::new();
    for tl in &tl_paths {
        let text = read_stripped(tl);
        for (ty, name, body) in parse_impls(&text) {
            if !body.trim().is_empty() {
                continue; // real Tallow body
            }
            report.declarations += 1;
            if refused(&ty, &name).is_some() {
                continue;
            }
            let quoted = format!("\"{name}\"");
            if !haystack.contains(&quoted) && !haystack.contains(&name) {
                let rel = tl.strip_prefix(root).unwrap_or(tl).display().to_string();
                unmentioned.push(format!("{rel}: {ty}.{name}"));
            }
        }
    }

    let mut impl_blocks = 0usize;
    for tl in &tl_paths {
        let text = read_stripped(tl);
        impl_blocks += count_impls(&text);
    }
    report.impl_blocks = impl_blocks;
    if report.declarations == 0 && impl_blocks > 0 {
        report.parse_failed = true;
        return report;
    }

    report.refusals = 1; // the REFUSED table, as the original prints its length
    let mut debt = Vec::new();
    let mut rest = Vec::new();
    for u in &unmentioned {
        // `path: Type.name` — the key is everything after the last ": "
        if let Some(key) = u.rsplit(": ").next() {
            if let Some(expires) = known_unimplemented(key) {
                debt.push(format!(
                    "DEBT  {u} declared with no arm on either plane (expires {expires})"
                ));
                continue;
            }
        }
        rest.push(u.clone());
    }
    report.debt = debt.len();
    report.lines = debt;
    for line in &rest {
        report.lines.push(format!("UNMENTIONED  {line}"));
    }
    report.unmentioned = rest.len();
    report
}

fn count_impls(text: &str) -> usize {
    let mut count = 0usize;
    let mut pos = 0usize;
    while let Some(rel) = find_impl_start(&text[pos..]) {
        count += 1;
        pos += rel + 4;
    }
    count
}

pub fn check_here() -> Report {
    check(&repo_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_signature_has_no_body() {
        let text = "impl Page {\n    native fn goto(self, url: String) -> Void\n}\n";
        let got = parse_impls(text);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "Page");
        assert_eq!(got[0].1, "goto");
        assert_eq!(got[0].2, "");
    }

    #[test]
    fn a_real_body_is_captured_and_skipped() {
        let text = "impl Foo {\n    fn bar(self) -> Int {\n        1\n    }\n    native fn baz(self)\n}\n";
        let got = parse_impls(text);
        let bar = got.iter().find(|(_, n, _)| n == "bar").unwrap();
        assert!(bar.2.contains('1'), "body: {:?}", bar.2);
        let baz = got.iter().find(|(_, n, _)| n == "baz").unwrap();
        assert_eq!(baz.2, "");
    }

    #[test]
    fn nested_blocks_do_not_close_the_impl_early() {
        let text = "impl A {\n    fn f(self) -> Int {\n        if true {\n            1\n        } else {\n            2\n        }\n    }\n    native fn g(self)\n}\n";
        let got = parse_impls(text);
        let names: Vec<&str> = got.iter().map(|(_, n, _)| n.as_str()).collect();
        assert!(names.contains(&"g"), "{names:?}");
    }

    #[test]
    fn comments_are_stripped_before_parsing() {
        let text = "impl X {\n    // a comment with { a brace\n    native fn h(self)\n}\n";
        let got = parse_impls(&strip_comments(text));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "h");
    }
}
