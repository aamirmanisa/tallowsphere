//! FFI boundary check between generated code and the runtime archive.
//!
//! Rust port of `scripts/check_ffi_symbols.py`. Two failure modes, both silent
//! until link time:
//!
//! 1. A `pub extern "C" fn tallow_*` without `#[unsafe(no_mangle)]` gets a
//!    mangled Rust symbol, so generated C-style calls cannot resolve it. This
//!    happened to `tallow_page_fill`, `tallow_page_select` and
//!    `tallow_page_handle_cookie_consent_str`: the codegen arm existed and
//!    compiled, and only `--require-native` (a real link) exposed it.
//! 2. Codegen emitting `@tallow_<name>` for a name the runtime never defines.
//!    The 2026-10-30 release binary referenced `tallow_str_index`, which no
//!    source file defined — this is the check that names that class.
//!
//! Exit 0 when both hold, 1 otherwise.
//!
//! The output line is byte-identical to the Python original
//! (`checked N runtime FFI fns, M emitted symbols, P problem(s)`) so the two can
//! be diffed during the port. `tools/tests/ffi_symbols_gate.rs` pins that.

use std::path::{Path, PathBuf};

/// One `pub extern "C" fn` found in a runtime file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFn {
    pub name: String,
    /// `path:line` (1-based) in the repository
    pub where_: String,
    /// True when no `no_mangle` appears in the 6 lines above the signature.
    pub unmangled: bool,
}

/// The result of a scan: everything found, plus the problems to report.
#[derive(Debug, Default)]
pub struct Report {
    pub defined: Vec<RuntimeFn>,
    pub emitted: Vec<String>,
    pub from_ir: Vec<String>,
    pub unmangled: Vec<(String, String)>,
    pub missing: Vec<String>,
}

impl Report {
    pub fn problems(&self) -> usize {
        self.unmangled.len() + self.missing.len()
    }

    /// The whole summary line. Identical in shape to the Python original.
    pub fn summary_line(&self) -> String {
        // `defined` is the UNION of the archive set and the IR/shim set, as in
        // the original's `defined |= defined_in_ir()`. Summing the two lengths
        // double-counts a symbol defined in both — `tallow_response_status` and
        // `tallow_response_url` are — which printed 331 where the original
        // printed 329.
        let mut all: Vec<&str> = self.defined.iter().map(|f| f.name.as_str()).collect();
        all.extend(self.from_ir.iter().map(String::as_str));
        all.sort();
        all.dedup();
        format!(
            "checked {} runtime FFI fns, {} emitted symbols, {} problem(s)",
            all.len(),
            self.emitted.len(),
            self.problems()
        )
    }

    /// Lines printed before the summary, in the original order.
    pub fn problem_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (where_, name) in &self.unmangled {
            out.push(format!(
                "UNMANGLED  {where_}: {name} lacks #[unsafe(no_mangle)]"
            ));
        }
        for name in &self.missing {
            out.push(format!(
                "UNDEFINED  codegen emits @{name} but no runtime fn defines it"
            ));
        }
        out
    }
}

/// Repository root: two levels up from this file (`src/gate/ffi_symbols.rs`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every `.rs` file under `src/runtime`, recursively, sorted by path.
fn runtime_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs(&root.join("src/runtime"), &mut out);
    out.sort();
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `tallow_[a-z0-9_]+` starting at `bytes[start]`, if it does.
fn take_ident(bytes: &[u8], start: usize) -> Option<String> {
    if !bytes[start..].starts_with(b"tallow_") {
        return None;
    }
    let mut end = start + b"tallow_".len();
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' {
            end += 1;
        } else {
            break;
        }
    }
    if end == start + b"tallow_".len() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[start..end]).into_owned())
}

/// Scan the runtime tree for `pub extern "C" fn tallow_*` definitions.
pub fn runtime_fns(root: &Path) -> Vec<RuntimeFn> {
    const NEEDLE: &str = "pub extern \"C\" fn ";
    let mut found = Vec::new();
    for path in runtime_files(root) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            // The original matched `\s*pub extern "C" fn (tallow_...)`: leading
            // whitespace only, so search for the needle and require the name.
            let Some(pos) = line.find(NEEDLE) else {
                continue;
            };
            let after = pos + NEEDLE.len();
            let Some(name) = take_ident(line.as_bytes(), after) else {
                continue;
            };
            // `no_mangle` must appear within the 6 lines above (the attribute
            // block). The original joined lines[i-6..i]; here the same window.
            let lo = i.saturating_sub(6);
            let unmangled = !lines[lo..i].iter().any(|l| l.contains("no_mangle"));
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            found.push(RuntimeFn {
                name,
                where_: format!("{rel}:{}", i + 1),
                unmangled,
            });
        }
    }
    found
}

/// Symbols codegen emits as `@tallow_*(`.
pub fn emitted(root: &Path) -> Vec<String> {
    let Ok(codegen) = std::fs::read_to_string(root.join("src/codegen.rs")) else {
        return Vec::new();
    };
    let bytes = codegen.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            if let Some(name) = take_ident(bytes, i + 1) {
                let after = i + 1 + name.len();
                if after < bytes.len() && bytes[after] == b'(' {
                    out.push(name);
                }
            }
        }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

/// Symbols satisfied by LLVM IR `define`s or embedded C source in codegen itself
/// rather than by the runtime archive (the async shim, redact_private,
/// replace_all).
pub fn defined_in_ir(root: &Path) -> Vec<String> {
    let Ok(codegen) = std::fs::read_to_string(root.join("src/codegen.rs")) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();

    // `define ... @tallow_name(`
    for line in codegen.lines() {
        let Some(dpos) = line.find("define ") else {
            continue;
        };
        let rest = &line[dpos..];
        if let Some(at) = rest.find('@') {
            if let Some(name) = take_ident(rest.as_bytes(), at + 1) {
                let after = at + 1 + name.len();
                if rest.as_bytes().get(after) == Some(&b'(') {
                    out.push(name);
                }
            }
        }
    }

    // Embedded C: `void tallow_x(`, `int *tallow_x(` etc.
    const C_TYPES: [&str; 8] = ["void", "int", "long", "char", "size_t", "bool", "double", "float"];
    let bytes = codegen.as_bytes();
    for (idx, line) in codegen.lines().enumerate() {
        let _ = idx;
        for ty in C_TYPES {
            let mut search = 0usize;
            while let Some(pos) = line[search..].find(ty) {
                let abs = search + pos;
                // Require a word boundary before the type.
                let boundary = abs == 0
                    || !line.as_bytes()[abs - 1].is_ascii_alphanumeric()
                        && line.as_bytes()[abs - 1] != b'_';
                let mut j = abs + ty.len();
                if !boundary {
                    search = abs + ty.len();
                    continue;
                }
                // Optional `*` / whitespace, then the identifier, then `(`.
                while j < line.len() && (line.as_bytes()[j] == b' ' || line.as_bytes()[j] == b'*')
                {
                    j += 1;
                }
                if let Some(name) = take_ident(line.as_bytes(), j) {
                    let mut k = j + name.len();
                    while k < line.len() && line.as_bytes()[k] == b' ' {
                        k += 1;
                    }
                    if line.as_bytes().get(k) == Some(&b'(') {
                        out.push(name);
                    }
                }
                search = abs + ty.len();
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Run the whole check against `root`.
pub fn check(root: &Path) -> Report {
    let fns = runtime_fns(root);
    let mut report = Report {
        unmangled: fns
            .iter()
            .filter(|f| f.unmangled)
            .map(|f| (f.where_.clone(), f.name.clone()))
            .collect(),
        defined: fns,
        ..Default::default()
    };
    report.emitted = emitted(root);
    // `defined_in_ir` returns the UNION of the LLVM defines and the embedded C
    // shim, deduped across both — the original unions the two sets before
    // counting. Two names (`tallow_response_status`, `tallow_response_url`)
    // appear in both, so a dedupe within each set alone double-counts them.
    report.from_ir = defined_in_ir(root);

    let mut known: Vec<String> = report.defined.iter().map(|f| f.name.clone()).collect();
    known.extend(report.from_ir.iter().cloned());
    known.sort();
    known.dedup();

    report.missing = report
        .emitted
        .iter()
        .filter(|e| !known.binary_search(e).is_ok())
        .cloned()
        .collect();
    report
}

/// The check with the repository root inferred from the crate layout.
pub fn check_here() -> Report {
    check(&repo_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a throwaway repo tree: `src/runtime/<files>` plus `src/codegen.rs`.
    fn fixture(tag: &str, runtime_files: &[(&str, &str)], codegen: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ffi-gate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src/runtime")).unwrap();
        for (name, body) in runtime_files {
            std::fs::write(dir.join("src/runtime").join(name), body).unwrap();
        }
        std::fs::write(dir.join("src/codegen.rs"), codegen).unwrap();
        dir
    }

    #[test]
    fn finds_a_mangled_definition() {
        // Real files put each attribute directly above its own fn, separated
        // from the previous fn by a doc comment and a blank line. The fixture
        // must look like that: in the original, `no_mangle` is searched in the
        // 6 lines ABOVE the signature, so two fns stacked with no gap would let
        // the first attribute cover the second.
        let dir = fixture(
            "mangled",
            &[(
                "a.rs",
                "/// first\n#[unsafe(no_mangle)]\npub extern \"C\" fn tallow_ok() {}\n\n\n\n\n\n/// second, attribute omitted\npub extern \"C\" fn tallow_bad() {}\n",
            )],
            "call @tallow_missing()\n",
        );
        let r = check(&dir);
        assert_eq!(r.defined.len(), 2);
        assert_eq!(r.unmangled.len(), 1, "{:?}", r.unmangled);
        assert_eq!(r.unmangled[0].1, "tallow_bad");
        assert_eq!(r.missing, vec!["tallow_missing".to_string()]);
        assert_eq!(r.problems(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_clean_pair_reports_nothing() {
        let dir = fixture(
            "clean",
            &[(
                "b.rs",
                "/// one\n#[unsafe(no_mangle)]\npub extern \"C\" fn tallow_one() {}\n\n/// two\n#[unsafe(no_mangle)]\npub extern \"C\" fn tallow_two() {}\n",
            )],
            "call @tallow_one()\ncall @tallow_two()\n",
        );
        let r = check(&dir);
        assert!(r.problem_lines().is_empty(), "{:?}", r.problem_lines());
        assert_eq!(
            r.summary_line(),
            "checked 2 runtime FFI fns, 2 emitted symbols, 0 problem(s)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ir_define_satisfies_an_emitted_symbol() {
        let dir = fixture(
            "ir",
            &[],
            "define i64 @tallow_redact_private(ptr) {\ncall @tallow_redact_private()\n",
        );
        let r = check(&dir);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The summary counts the UNION of the archive set and the IR/shim set.
    /// `tallow_response_status` and `tallow_response_url` are defined in both,
    /// and summing the two lengths printed 331 where the original printed 329.
    #[test]
    fn symbol_defined_in_both_sets_is_counted_once() {
        let dir = fixture(
            "overlap",
            &[(
                "c.rs",
                "#[unsafe(no_mangle)]\npub extern \"C\" fn tallow_response_url() {}\n",
            )],
            "define i32 @tallow_response_url(ptr) {\n",
        );
        let r = check(&dir);
        assert!(
            r.summary_line().starts_with("checked 1 runtime FFI fns"),
            "{}",
            r.summary_line()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symbol codegen emits with no definition anywhere is the failure this
    /// gate exists for — the `tallow_str_index` shape.
    #[test]
    fn undefined_emitted_symbol_is_a_problem() {
        let dir = fixture("undef", &[], "call @tallow_str_index(ptr, i64)\n");
        let r = check(&dir);
        assert_eq!(r.missing, vec!["tallow_str_index".to_string()]);
        assert_eq!(r.problems(), 1);
        assert!(r.problem_lines()[0].contains("UNDEFINED"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
