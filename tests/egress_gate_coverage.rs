//! Coverage gate: every `src/stdlib/*.rs` that builds a request on the shared
//! egress client outside `#[cfg(test)]` must also name `scope::require`.
//!
//! A safety property that lives in a document is a wish. This test is the
//! durable replacement for a prose census of which stdlib modules consult the
//! authorization register before they talk to the network. A module that calls
//! `egress_http::get`/`post`/`agent`/… without `scope::require` cannot land:
//! the test fails and prints the file name.
//!
//! A mere mention is not a site: `egress_http::env_lock()` is a `MutexGuard`,
//! and four modules touch it only from their test harness. See `REQUEST_VERBS`.
//!
//! Negative control (the exact one-line edit that must turn this test red):
//!
//! ```text
//! printf '%s\n' 'fn _probe() { let _ = crate::runtime::egress_http::get("http://example.invalid"); }' > src/stdlib/_ungated_probe.rs
//! ```
//!
//! Then `cargo test --test egress_gate_coverage -- --nocapture` must fail
//! naming `_ungated_probe.rs`. Delete the file to restore. A coverage test
//! nobody has seen fail is a claim, not a gate.
//!
//! Exempt modules are those that mention the type without sending bytes, or
//! that exist only as a test harness. Each entry carries a reason. An exempt
//! file that no longer contains `egress_http::`, or that now contains
//! `scope::require`, is stale and fails. More than three exemptions means
//! this file is an allowlist, not a gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const EGRESS_NEEDLE: &str = "egress_http::";

/// Raw-client needle. A module that builds its own `ureq` request is on the
/// network just as much as one that uses the shared shims — `intel_api`'s
/// method matrix does exactly that — so the same rule applies to both.
const UREQ_NEEDLE: &str = "ureq::";
const REQUIRE_NEEDLE: &str = "scope::require";

/// Request-shaped constructors on the shared client.
///
/// The predicate is deliberately narrower than "mentions `egress_http::`": four
/// modules (advisory, jobs, legal, rmdb_store) name the module only through
/// `egress_http::env_lock()`, a `MutexGuard` used to serialise tests that mutate
/// environment variables. Treating that as an egress site demands a gate in a
/// module that cannot send bytes — the decorative-gate defect this file exists
/// to prevent, arrived at from the other side.
const REQUEST_VERBS: &[&str] = &[
    "get(",
    "post(",
    "put(",
    "delete(",
    "head(",
    "patch(",
    "request(",
    "agent(",
    "agent_with_timeouts(",
    "Agent::config_builder(",
];

/// Line numbers (1-based) of request-shaped `egress_http::` calls outside any
/// `#[cfg(test)]` module. A test harness may name the client freely; production
/// code may not reach it without the register.
fn request_sites(text: &str) -> Vec<usize> {
    let mut sites = Vec::new();
    let mut in_test_mod = false;
    let mut depth: i32 = 0;
    let mut pending_cfg_test = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if !in_test_mod {
            if line.starts_with("#[cfg(test)]") {
                pending_cfg_test = true;
                continue;
            }
            if pending_cfg_test {
                if line.starts_with("mod ") || line.starts_with("pub mod ") {
                    in_test_mod = true;
                    depth = 0;
                    pending_cfg_test = false;
                } else if !line.is_empty() && !line.starts_with("//") {
                    pending_cfg_test = false;
                }
            }
        }
        if in_test_mod {
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if depth <= 0 && line.contains('}') {
                in_test_mod = false;
            }
            continue;
        }
        for needle in [EGRESS_NEEDLE, UREQ_NEEDLE] {
            let Some(pos) = raw.find(needle) else { continue };
            let rest = &raw[pos + needle.len()..];
            if rest.starts_with("env_lock") {
                continue;
            }
            if REQUEST_VERBS.iter().any(|verb| rest.starts_with(verb)) {
                sites.push(i + 1);
                break;
            }
        }
    }
    sites
}

/// `(file name in src/stdlib/, reason)`.
///
/// Empty on purpose: no current module both mentions `egress_http::` and is
/// justified in skipping the register. A type-only re-export, or a
/// `#[cfg(test)]`-only harness that names the type without calling it, would
/// go here with a one-line reason. Putting every currently-ungated file on
/// this list is how the gate rots.
const EXEMPT: &[(&str, &str)] = &[
    // No entries. Cap is three; a fourth is a failing assertion, not a review
    // comment. See `exempt_list_is_not_stale`.
];

fn stdlib_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/stdlib")
}

fn stdlib_rs_files() -> Vec<PathBuf> {
    let dir = stdlib_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|ent| {
            let ent = ent.ok()?;
            let path = ent.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "src/stdlib/*.rs was empty — the glob drifted"
    );
    files
}

#[test]
fn every_egress_http_site_consults_scope_require() {
    let exempt: BTreeSet<&str> = EXEMPT.iter().map(|(name, _)| *name).collect();
    let mut gated = Vec::new();
    let mut ungated = Vec::new();
    let mut scanned = 0usize;

    for path in stdlib_rs_files() {
        scanned += 1;
        let name = path
            .file_name()
            .expect("stdlib file name")
            .to_string_lossy()
            .into_owned();
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let sites = request_sites(&text);
        if sites.is_empty() {
            continue;
        }
        if exempt.contains(name.as_str()) {
            continue;
        }
        if text.contains(REQUIRE_NEEDLE) {
            gated.push(name);
        } else {
            ungated.push(name);
        }
    }

    eprintln!("scanned {scanned} src/stdlib/*.rs");
    eprintln!("gated ({}): {}", gated.len(), gated.join(", "));
    eprintln!(
        "ungated ({}): {}",
        ungated.len(),
        if ungated.is_empty() {
            "(none)".to_string()
        } else {
            ungated.join(", ")
        }
    );

    assert!(
        !gated.is_empty(),
        "scan found no gated module — the needles {EGRESS_NEEDLE:?} / {REQUIRE_NEEDLE:?} may have drifted"
    );
    assert!(
        ungated.is_empty(),
        "ungated stdlib modules mention {EGRESS_NEEDLE} without {REQUIRE_NEEDLE}: {}",
        ungated.join(", ")
    );
}

#[test]
fn exempt_list_is_not_stale() {
    assert!(
        EXEMPT.len() <= 3,
        "EXEMPT has {} entries; more than 3 means this gate is an allowlist",
        EXEMPT.len()
    );

    let files: BTreeMap<String, String> = stdlib_rs_files()
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .expect("stdlib file name")
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            (name, text)
        })
        .collect();

    let mut seen = BTreeSet::new();
    let mut stale = Vec::new();
    for (name, reason) in EXEMPT {
        if !seen.insert(*name) {
            stale.push(format!("{name}: duplicate EXEMPT entry"));
            continue;
        }
        match files.get(*name) {
            None => stale.push(format!(
                "{name}: listed but src/stdlib/{name} does not exist"
            )),
            Some(text) => {
                if !text.contains(EGRESS_NEEDLE) {
                    stale.push(format!(
                        "{name}: exempted ({reason}) but has no {EGRESS_NEEDLE} site"
                    ));
                }
                if text.contains(REQUIRE_NEEDLE) {
                    stale.push(format!(
                        "{name}: exempted ({reason}) but is gated ({REQUIRE_NEEDLE} present)"
                    ));
                }
            }
        }
    }

    eprintln!("EXEMPT entries: {}", EXEMPT.len());
    assert!(
        stale.is_empty(),
        "stale EXEMPT entries:\n  {}",
        stale.join("\n  ")
    );
}
