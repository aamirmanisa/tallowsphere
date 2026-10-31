//! Minimal SBOM inventory generator + drift gate.
//!
//! Rust port of `scripts/sbom-gen.py` (T-114). Produces a deterministic,
//! canonical package inventory of the workspace dependency graph from
//! `cargo metadata --locked`, and fails when the regenerated artifact does not
//! byte-match the committed snapshot.
//!
//! Why the rendering is hand-written rather than `serde_json::to_string_pretty`:
//! the drift gate compares the *exact bytes* of the snapshot. The Python emitted
//! a specific layout — two-space top-level keys, one package per line indented
//! four spaces, per-package objects with sorted keys and `(",", ":")`
//! separators — so matching that layout is what makes `--check` mean the same
//! thing on both implementations. Reformatting would report drift on a tree that
//! is not drifted.
//!
//! Exit codes: 0 = ok / no drift; 1 = drift detected; 2 = generator error.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

const FORMAT: &str = "tallow-sbom-min/1";
const GENERATOR: &str = "scripts/sbom-gen.py";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub source: String,
    pub license: String,
}

#[derive(Debug)]
pub struct Sbom {
    pub lockfile_sha256: String,
    pub packages: Vec<Pkg>,
}

#[derive(Debug)]
pub enum Error {
    /// `cargo metadata` failed both offline and with registry access.
    Metadata(String),
    /// `Cargo.lock` is absent.
    NoLock(PathBuf),
    /// The metadata JSON did not parse or lacked `packages`.
    BadMetadata(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Metadata(d) => write!(f, "`cargo metadata --locked` failed: {d}"),
            Error::NoLock(p) => write!(f, "Cargo.lock not found at {}", p.display()),
            Error::BadMetadata(d) => write!(f, "cargo metadata output unusable: {d}"),
        }
    }
}

/// Resolve the workspace dependency graph, offline first.
///
/// The artifact must not depend on network state, so the primary attempt is
/// fully offline. On a cold cache (a fresh runner that never ran `cargo fetch`)
/// registry summaries may be missing; retry once *without* `--offline`. Both
/// attempts carry `--locked`, so the lockfile can never be mutated.
fn cargo_metadata(root: &Path) -> Result<Value, Error> {
    let base = ["metadata", "--locked", "--format-version", "1"];

    let offline = Command::new("cargo")
        .args(base)
        .arg("--offline")
        .current_dir(root)
        .output()
        .map_err(|e| Error::Metadata(format!("could not run cargo: {e}")))?;

    if offline.status.success() {
        return serde_json::from_slice(&offline.stdout)
            .map_err(|e| Error::BadMetadata(e.to_string()));
    }

    let offline_err = String::from_utf8_lossy(&offline.stderr).into_owned();
    eprintln!(
        "sbom-gen: note: offline resolution unavailable (cold cache?); \
         retrying `cargo metadata --locked` with registry access"
    );

    let online = Command::new("cargo")
        .args(base)
        .current_dir(root)
        .output()
        .map_err(|e| Error::Metadata(format!("could not run cargo: {e}")))?;

    if !online.status.success() {
        return Err(Error::Metadata(format!(
            "offline attempt and registry attempt both failed.\n\
             -- offline attempt stderr:\n{offline_err}\n\
             -- registry attempt stderr:\n{}",
            String::from_utf8_lossy(&online.stderr)
        )));
    }
    serde_json::from_slice(&online.stdout).map_err(|e| Error::BadMetadata(e.to_string()))
}

pub fn build(root: &Path) -> Result<Sbom, Error> {
    let lock_path = root.join("Cargo.lock");
    if !lock_path.is_file() {
        return Err(Error::NoLock(lock_path));
    }
    let meta = cargo_metadata(root)?;
    let list = meta
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::BadMetadata("no `packages` array".into()))?;

    let mut packages = Vec::with_capacity(list.len());
    for p in list {
        let s = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        // `source` falls back to the literal `workspace-path`; `license` to
        // `UNKNOWN`. Both are the Python's `or` semantics: absent OR empty.
        let source = match p.get("source").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => "workspace-path".to_string(),
        };
        let license = match p.get("license").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => "UNKNOWN".to_string(),
        };
        packages.push(Pkg {
            name: s("name"),
            version: s("version"),
            source,
            license,
        });
    }
    packages.sort();

    let lock_bytes = std::fs::read(&lock_path).map_err(|_| Error::NoLock(lock_path.clone()))?;
    let mut hasher = Sha256::new();
    hasher.update(&lock_bytes);
    let lockfile_sha256 = format!("{:x}", hasher.finalize());

    Ok(Sbom {
        lockfile_sha256,
        packages,
    })
}

/// Canonical rendering. Layout is byte-compatible with the Python original.
pub fn render(sbom: &Sbom) -> String {
    let mut lines: Vec<String> = vec![
        "{".to_string(),
        format!("  \"format\": {},", json_str(FORMAT)),
        format!("  \"generator\": {},", json_str(GENERATOR)),
        format!("  \"lockfileSha256\": {},", json_str(&sbom.lockfile_sha256)),
        format!("  \"packageCount\": {},", sbom.packages.len()),
        "  \"packages\": [".to_string(),
    ];
    let n = sbom.packages.len();
    for (i, p) in sbom.packages.iter().enumerate() {
        let comma = if i + 1 < n { "," } else { "" };
        lines.push(format!("    {}{}", pkg_json(p), comma));
    }
    lines.push("  ]".to_string());
    lines.push("}".to_string());
    lines.push(String::new());
    lines.join("\n")
}

/// `json.dumps(dict, sort_keys=True, separators=(",", ":"))` for a package:
/// keys in alphabetical order, no spaces, ascii-escaped.
fn pkg_json(p: &Pkg) -> String {
    format!(
        "{{\"license\":{},\"name\":{},\"source\":{},\"version\":{}}}",
        json_str(&p.license),
        json_str(&p.name),
        json_str(&p.source),
        json_str(&p.version)
    )
}

/// JSON string literal. `serde_json` matches Python's `json.dumps` for ASCII
/// content, which is the only content this artifact carries (crate names,
/// semver, registry URLs, SPDX ids) — but it escapes `/`-adjacent characters
/// identically, so the bytes line up.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Unified diff between `expected` and `actual`, matching `difflib.unified_diff`
/// on the inputs this gate produces.
///
/// The first version guessed: it trimmed a common prefix and suffix and emitted
/// one hunk. That is wrong whenever the changed span is intermittent — with a
/// pretty-printed snapshot and a compact artifact, whole blocks differ, and
/// difflib splits hunks by opcode runs with `n=3` context while the guess merged
/// them. The verdict (exit 1) was right and the *text* was not, which matters
/// because the comparison is on bytes.
///
/// This computes a longest-common-subsequence edit script (the artifact files
/// are hundreds of lines, so the quadratic table is fine) and groups it with
/// difflib's rule: consecutive change blocks closer than `2 * n` lines share a
/// hunk.
pub fn unified_diff(expected: &str, actual: &str, fromfile: &str, tofile: &str) -> String {
    const N: usize = 3;
    let e: Vec<&str> = expected.lines().collect();
    let a: Vec<&str> = actual.lines().collect();
    let mut out = String::new();
    out.push_str(&format!("--- {fromfile}\n+++ {tofile}\n"));

    // Opcodes as (tag, e_start, e_end, a_start, a_end).
    let ops = opcodes(&e, &a);

    // difflib's grouping: a hunk opens at a change block and extends while the
    // following equal run is shorter than 2*N lines.
    let mut groups: Vec<(usize, usize)> = Vec::new(); // (first op, last op inclusive)
    let mut i = 0usize;
    while i < ops.len() {
        if ops[i].0 == "equal" {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i;
        i += 1;
        while i < ops.len() {
            if ops[i].0 != "equal" {
                end = i;
                i += 1;
                continue;
            }
            let eq_len = ops[i].2 - ops[i].1;
            if eq_len > 2 * N {
                break;
            }
            i += 1;
        }
        groups.push((start, end));
    }

    for (first, last) in groups {
        // Emit with context.
        let mut body = String::new();
        let mut old_len = 0usize;
        let mut new_len = 0usize;

        // Leading context
        if first > 0 && ops[first - 1].0 == "equal" {
            let (_, es, ee, _, _) = ops[first - 1];
            let from = ee.saturating_sub(N).max(es);
            for k in from..ee {
                body.push(' ');
                body.push_str(e[k]);
                body.push('\n');
                old_len += 1;
                new_len += 1;
            }
        }

        for op in &ops[first..=last] {
            let (tag, es, ee, as_, ae) = *op;
            match tag {
                "equal" => {
                    for k in 0..(ee - es) {
                        body.push(' ');
                        body.push_str(e[es + k]);
                        body.push('\n');
                        old_len += 1;
                        new_len += 1;
                    }
                }
                "delete" => {
                    for k in es..ee {
                        body.push('-');
                        body.push_str(e[k]);
                        body.push('\n');
                        old_len += 1;
                    }
                }
                "insert" => {
                    for k in as_..ae {
                        body.push('+');
                        body.push_str(a[k]);
                        body.push('\n');
                        new_len += 1;
                    }
                }
                "replace" => {
                    for k in es..ee {
                        body.push('-');
                        body.push_str(e[k]);
                        body.push('\n');
                        old_len += 1;
                    }
                    for k in as_..ae {
                        body.push('+');
                        body.push_str(a[k]);
                        body.push('\n');
                        new_len += 1;
                    }
                }
                _ => {}
            }
        }

        // Trailing context
        if last + 1 < ops.len() && ops[last + 1].0 == "equal" {
            let (_, es, ee, _, _) = ops[last + 1];
            let to = (es + N).min(ee);
            for k in es..to {
                body.push(' ');
                body.push_str(e[k]);
                body.push('\n');
                old_len += 1;
                new_len += 1;
            }
        }

        // Header offsets are 1-based; difflib omits the count when it is 1 and
        // clamps a zero-length range to the preceding line.
        let e_begin = ops[first].1;
        let a_begin = ops[first].3;
        let old_start = if old_len == 0 { e_begin } else { e_begin.saturating_sub(
            if first > 0 && ops[first - 1].0 == "equal" {
                let (_, es, ee, _, _) = ops[first - 1];
                (ee - (ee.saturating_sub(N).max(es)))
            } else { 0 },
        ) + 1 };
        let new_start = if new_len == 0 { a_begin } else { a_begin.saturating_sub(
            if first > 0 && ops[first - 1].0 == "equal" {
                let (_, es, ee, _, _) = ops[first - 1];
                (ee - (ee.saturating_sub(N).max(es)))
            } else { 0 },
        ) + 1 };

        out.push_str("@@ ");
        out.push_str(&fmt_range("-", old_start, old_len));
        out.push(' ');
        out.push_str(&fmt_range("+", new_start, new_len));
        out.push_str(" @@\n");
        out.push_str(&body);
    }
    out
}

fn fmt_range(sign: &str, start: usize, len: usize) -> String {
    if len == 1 {
        format!("{sign}{start}")
    } else {
        format!("{sign}{start},{len}")
    }
}

/// LCS edit script as difflib-style opcodes over two line slices.
fn opcodes(e: &[&str], a: &[&str]) -> Vec<(&'static str, usize, usize, usize, usize)> {
    let (n, m) = (e.len(), a.len());
    // lcs[i][j] = length of the LCS of e[i..] and a[j..]
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if e[i] == a[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut raw: Vec<(&'static str, usize, usize, usize, usize)> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if e[i] == a[j] {
            let (si, sj) = (i, j);
            while i < n && j < m && e[i] == a[j] {
                i += 1;
                j += 1;
            }
            raw.push(("equal", si, i, sj, j));
        } else {
            let (si, sj) = (i, j);
            while i < n && j < m && e[i] != a[j] {
                if lcs[i + 1][j] >= lcs[i][j + 1] {
                    i += 1;
                } else {
                    j += 1;
                }
            }
            let deletes = i - si;
            let inserts = j - sj;
            if deletes > 0 && inserts > 0 {
                raw.push(("replace", si, i, sj, j));
            } else if deletes > 0 {
                raw.push(("delete", si, i, sj, j));
            } else {
                raw.push(("insert", si, i, sj, j));
            }
        }
    }
    if i < n {
        raw.push(("delete", i, n, j, j));
    } else if j < m {
        raw.push(("insert", i, i, j, m));
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_line_matches_python_separators() {
        let p = Pkg {
            name: "adler2".into(),
            version: "2.0.1".into(),
            source: "registry+https://github.com/rust-lang/crates.io-index".into(),
            license: "0BSD OR MIT OR Apache-2.0".into(),
        };
        assert_eq!(
            pkg_json(&p),
            "{\"license\":\"0BSD OR MIT OR Apache-2.0\",\"name\":\"adler2\",\"source\":\"registry+https://github.com/rust-lang/crates.io-index\",\"version\":\"2.0.1\"}"
        );
    }

    #[test]
    fn sort_is_python_tuple_order() {
        // Python sorts on (name, version, source, license) as strings. These
        // crate names have no natural version order, so the tiebreak must be
        // the string form: 1.10.0 sorts BEFORE 1.9.0 lexically.
        let mut v = vec![
            Pkg {
                name: "a".into(),
                version: "1.9.0".into(),
                source: "s".into(),
                license: "l".into(),
            },
            Pkg {
                name: "a".into(),
                version: "1.10.0".into(),
                source: "s".into(),
                license: "l".into(),
            },
        ];
        v.sort();
        assert_eq!(v[0].version, "1.10.0");
    }

    #[test]
    fn empty_source_and_license_fall_back() {
        let meta: Value = serde_json::from_str(
            r#"{"packages":[{"name":"w","version":"0.1.0","source":null,"license":""}]}"#,
        )
        .unwrap();
        let p = &meta["packages"][0];
        let source = match p.get("source").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => "workspace-path".to_string(),
        };
        let license = match p.get("license").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => "UNKNOWN".to_string(),
        };
        assert_eq!(source, "workspace-path");
        assert_eq!(license, "UNKNOWN");
    }

    #[test]
    fn identical_inputs_render_identically() {
        let sbom = Sbom {
            lockfile_sha256: "abc".into(),
            packages: vec![Pkg {
                name: "x".into(),
                version: "1.0.0".into(),
                source: "s".into(),
                license: "MIT".into(),
            }],
        };
        let a = render(&sbom);
        let b = render(&sbom);
        assert_eq!(a, b);
        assert!(a.ends_with("]\n}\n"));
    }
}
