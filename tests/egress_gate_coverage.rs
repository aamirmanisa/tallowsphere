//! Coverage gate: every production region under `src/` that builds an HTTP
//! request or a raw connect must also name `scope::require`, unless the file
//! is on `DEBT`.
//!
//! Wave 3's predicate was `src/stdlib/*.rs` × `egress_http::<verb>(`. That is
//! why 68 ungated sites survived four waves — `ureq`, `reqwest`,
//! `TcpStream::connect`, and everything outside `src/stdlib/` were invisible.
//! `reports/egress-surface-inventory.md` is the measurement; this file is the
//! widened meter. It does not gate any file.
//!
//! A file is gated if its production region (cut at the first `#[cfg(test)]`)
//! contains `scope::require`. Comment lines are not sites.
//!
//! Negative control (the exact one-line edit that must turn this test red):
//!
//! ```text
//! printf '%s\n' 'fn _probe() { let _ = std::net::TcpStream::connect("203.0.113.1:80"); }' > src/_ungated_probe.rs
//! ```
//!
//! Then `cargo test --test egress_gate_coverage -- --nocapture` must fail
//! naming `src/_ungated_probe.rs`. Delete the file to restore. A coverage
//! test nobody has seen fail is a claim, not a gate. This edit is a raw
//! connect outside `src/stdlib/` — the hole the old predicate could not see.
//!
//! `DEBT` is the measured ungated set that is legitimately so (loopback
//! control sockets, the sendtallow boundary, plane-assertion probes, and
//! the handful of other sites justified in one line). Cap is the measured
//! size. A thirteenth entry means this file is an allowlist. A listed file
//! that is now gated, or that no longer has an egress site, is stale and
//! fails.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const REQUIRE_NEEDLE: &str = "scope::require";

/// Request verbs. Applied after `egress_http::`, `ureq::`, and `reqwest::`.
///
/// `env_lock()` is a `MutexGuard` — not a site. `agent` / `agent_with_timeouts`
/// / `Agent::config_builder` are the shared-client factories and apply only to
/// `egress_http::` (the inventory counts `agent_with_timeouts(` as HTTP egress
/// because the module issues on that agent a few lines later). They must not
/// apply to `ureq::`: `ureq::Agent::config_builder()` is a type constructor
/// that would flag `crawl_pipeline.rs` without a `ureq::<verb>(` site.
const REQUEST_VERBS: &[&str] = &[
    "get(", "post(", "put(", "delete(", "head(", "patch(", "request(",
];

const EGRESS_HTTP_EXTRA: &[&str] = &["agent(", "agent_with_timeouts(", "Agent::config_builder("];

/// HTTP client constructors. `reqwest::blocking::Client` is the same primitive
/// as `reqwest::Client` (inventory method, `reports/probes/inventory_scan.py`).
const REQWEST_CLIENTS: &[&str] = &[
    "reqwest::Client::new",
    "reqwest::Client::builder",
    "reqwest::blocking::Client::new",
    "reqwest::blocking::Client::builder",
];

const HTTP_PREFIXES: &[&str] = &["egress_http::", "ureq::", "reqwest::"];

const RAW_NEEDLES: &[&str] = &[
    "TcpStream::connect(",
    "UdpSocket::connect(",
    "connect_timeout(",
];

/// `(path relative to crate root, one-line reason)`.
///
/// Cap is the measured union at `ee9cf9f`: 3 HTTP + 7 raw, no overlap — the
/// 12-entry list at `595334a` minus `src/browser/typesense.rs` and
/// `src/request_plan.rs`, both gated in wave 11.
/// Putting a newly-ungated file here instead of gating it is how the gate
/// rots; the cap makes that a failing assertion, not a review comment.
/// `src/stdlib/relay_room.rs` is the other sendtallow-boundary file but has
/// no matching site on this revision — listing it would be stale on day one.
const DEBT: &[(&str, &str)] = &[
    (
        "src/browser/process.rs",
        "Chrome CDP control socket (/json/version on the launched debug port)",
    ),
    (
        "src/browser/socks_shim.rs",
        "loopback SOCKS upstream; destination is dialed by the proxy, never this process",
    ),
    (
        "src/cli/daemon.rs",
        "loopback-only daemon health check (http://127.0.0.1:{port}/health)",
    ),
    (
        "src/cli/fingerprint_audit_cmd.rs",
        "TCP liveness probe of local Tor SOCKS; no payload sent",
    ),
    (
        "src/cli/request_plan_cmd.rs",
        "loopback_get refuses any non-loopback URL before connect",
    ),
    (
        "src/cli/veil_cmd.rs",
        "plane-assertion probes (tor SOCKS / mesh hub / loopback bridge); the verb's job is reachability",
    ),
    (
        "src/signing.rs",
        "Sigstore keyless signing (GitHub OIDC + fulcio.sigstore.dev); CI identity, not program egress",
    ),
    (
        "src/stdlib/mesh.rs",
        "mesh bootstrap handshake to operator-supplied overlay addrs (named plane: mesh)",
    ),
    (
        "src/stdlib/sync.rs",
        "loopback-only tallow-daemon HTTP (http://127.0.0.1:{port})",
    ),
    (
        "src/stdlib/transfer_net.rs",
        "sendtallow boundary; operator 2026-10-26, out of fleet scope",
    ),
];

const DEBT_CAP: usize = 10;

/// Production region: everything before the first `#[cfg(test)]`.
/// Matches `reports/egress-surface-inventory.md` / `inventory_scan.py`.
fn production_region(text: &str) -> &str {
    match text.find("#[cfg(test)]") {
        Some(i) => &text[..i],
        None => text,
    }
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn prefixed_verb(line: &str, prefix: &str) -> bool {
    let Some(pos) = line.find(prefix) else {
        return false;
    };
    let rest = &line[pos + prefix.len()..];
    if prefix == "egress_http::" && rest.starts_with("env_lock") {
        return false;
    }
    if REQUEST_VERBS.iter().any(|verb| rest.starts_with(verb)) {
        return true;
    }
    prefix == "egress_http::" && EGRESS_HTTP_EXTRA.iter().any(|verb| rest.starts_with(verb))
}

fn has_http_site(line: &str) -> bool {
    if REQWEST_CLIENTS.iter().any(|n| line.contains(n)) {
        return true;
    }
    HTTP_PREFIXES.iter().any(|p| prefixed_verb(line, p))
}

fn has_raw_site(line: &str) -> bool {
    RAW_NEEDLES.iter().any(|n| line.contains(n))
}

/// 1-based line numbers of HTTP or raw-connect sites in the production region.
fn egress_sites(text: &str) -> Vec<usize> {
    production_region(text)
        .lines()
        .enumerate()
        .filter(|(_, line)| !is_comment(line) && (has_http_site(line) || has_raw_site(line)))
        .map(|(i, _)| i + 1)
        .collect()
}

fn is_gated(text: &str) -> bool {
    production_region(text).contains(REQUIRE_NEEDLE)
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn src_dir() -> PathBuf {
    crate_root().join("src")
}

fn rel_src(path: &Path) -> String {
    path.strip_prefix(crate_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn src_rs_files() -> Vec<PathBuf> {
    let dir = src_dir();
    let mut files = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let rd = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for ent in rd {
            let ent = ent.unwrap_or_else(|e| panic!("read_dir entry: {e}"));
            let path = ent.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    walk(&dir, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "src/**/*.rs was empty — the walk drifted"
    );
    files
}

fn load_src() -> BTreeMap<String, String> {
    src_rs_files()
        .into_iter()
        .map(|path| {
            let rel = rel_src(&path);
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            (rel, text)
        })
        .collect()
}

#[test]
fn every_egress_site_consults_scope_require() {
    let debt: BTreeSet<&str> = DEBT.iter().map(|(name, _)| *name).collect();
    let files = load_src();
    let mut gated = Vec::new();
    let mut ungated = Vec::new();

    for (rel, text) in &files {
        let sites = egress_sites(text);
        if sites.is_empty() {
            continue;
        }
        if debt.contains(rel.as_str()) {
            continue;
        }
        if is_gated(text) {
            gated.push(rel.clone());
        } else {
            ungated.push(rel.clone());
        }
    }

    eprintln!("scanned {} src/**/*.rs", files.len());
    eprintln!("gated ({}): {}", gated.len(), gated.join(", "));
    eprintln!(
        "debt ({}): {}",
        DEBT.len(),
        DEBT.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
    );
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
        "scan found no gated module — the HTTP/raw needles or {REQUIRE_NEEDLE:?} may have drifted"
    );
    assert!(
        ungated.is_empty(),
        "ungated src/ files have an HTTP or raw-connect site without {REQUIRE_NEEDLE}: {}",
        ungated.join(", ")
    );
}

#[test]
fn debt_list_is_not_stale() {
    assert!(
        DEBT.len() <= DEBT_CAP,
        "DEBT has {} entries; more than {DEBT_CAP} means this gate is an allowlist",
        DEBT.len()
    );

    let files = load_src();
    let mut seen = BTreeSet::new();
    let mut stale = Vec::new();
    for (name, reason) in DEBT {
        if !seen.insert(*name) {
            stale.push(format!("{name}: duplicate DEBT entry"));
            continue;
        }
        match files.get(*name) {
            None => stale.push(format!("{name}: listed but {name} does not exist")),
            Some(text) => {
                if egress_sites(text).is_empty() {
                    stale.push(format!(
                        "{name}: listed ({reason}) but has no HTTP or raw-connect site"
                    ));
                }
                if is_gated(text) {
                    stale.push(format!(
                        "{name}: listed ({reason}) but is gated ({REQUIRE_NEEDLE} present)"
                    ));
                }
            }
        }
    }

    eprintln!("DEBT entries: {} (cap {DEBT_CAP})", DEBT.len());
    assert!(
        stale.is_empty(),
        "stale DEBT entries:\n  {}",
        stale.join("\n  ")
    );
}
