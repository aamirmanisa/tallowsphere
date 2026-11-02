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
//! A file is gated if its production region (cut at the first test-only
//! `#[cfg(...)]` — `#[cfg(test)]`, `#[cfg(all(test, unix))]`, or any cfg whose
//! expression mentions the `test` token) contains `scope::require`. Comment
//! lines are not sites.
//!
//! The gate is line-text, so it has no cfg *awareness*: it cannot tell a site
//! compiled on every platform from one compiled only on Unix. `CFG_EGRESS`
//! below closes that blind spot. It is the measured census of every
//! egress-capable site inside a `#[cfg(...)]` span (inline or inherited from a
//! `#[cfg(...)] mod`), each with a Windows verdict. The scanner is bidirectional
//! and stale-checked, so a new cfg-gated egress path fails this test until it
//! is enumerated and its other-platform behavior is stated. Measurement:
//! `reports/egress-surface-inventory.md` ("CFG-gated egress census") and
//! `reports/probes/cfg_unix_egress_census.py`.
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
        "src/stdlib/transfer_net.rs",
        "sendtallow boundary; operator 2026-10-26, out of fleet scope",
    ),
];

const DEBT_CAP: usize = 10;

/// Production region: everything before the first test-only `#[cfg(...)]`.
///
/// The old cut looked for the literal `#[cfg(test)]` only. That misses
/// `#[cfg(all(test, unix))]` (cdp.rs:187, runtime/hardening.rs:110), so a
/// test-only socket would be counted as production egress and a
/// `scope::require` inside such a test module would mark the whole file gated.
/// Both are false readings; the cut is now expression-based.
fn production_region(text: &str) -> &str {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if let Some(expr) = cfg_attr_expr(line) {
            if cfg_expr_mentions_test(expr) {
                return &text[..offset];
            }
        }
        offset += line.len();
    }
    text
}

/// `#[cfg(<expr>)]` on its own line → `<expr>`. `#[cfg_attr(...)]` and
/// `cfg!(...)` do not match.
fn cfg_attr_expr(line: &str) -> Option<&str> {
    let t = line.trim();
    let rest = t.strip_prefix("#[cfg(")?;
    let inner = rest.strip_suffix(")]")?;
    Some(inner.trim())
}

/// True when a cfg expression names the bare `test` predicate.
fn cfg_expr_mentions_test(expr: &str) -> bool {
    expr.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|tok| tok == "test")
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
// ── CFG-gated egress census ────────────────────────────────────────────────
//
// The gate above is line-text: it cannot tell a site compiled everywhere from
// one a Windows build never sees. `CFG_EGRESS` is the measured set of every
// egress-capable site inside a `#[cfg(...)]` span, either inline (`#[cfg(unix)]
// fn launch`) or inherited from a `#[cfg(...)] mod` (`#[cfg(unix)] pub mod
// sandbox_runtime;`). Each row states what the *other* platform does.
//
// Measured 2026-11-02 at 7f744ac with `reports/probes/cfg_unix_egress_census.py`
// (read-only; 595 files, 271 egress-capable production sites: 14 absent on
// Windows, 10 only on Windows, 0 under `cfg_both`). The table is a pin, not an
// allowlist: a cfg-gated site with no row fails, a row that no longer matches a
// site fails, and a row whose guard expression drifted fails. Adding a
// cfg-gated egress path means adding a row that says what the other platform
// does — that is the whole point.

/// Egress primitives the cfg census must see. Wider than `REQUEST_VERBS`
/// because platform-gated code is dominated by the classes the gate cannot
/// model: child processes, raw sockets, UDP binds, DNS. Same order and
/// first-class-wins rule as `reports/probes/cfg_unix_egress_census.py`.
const CFG_EGRESS_CLASSES: &[(&str, &str)] = &[
    ("tls", "ClientConnection::new("),
    ("tls", "TlsConnector::new("),
    ("tls", "TlsConnector::builder("),
    ("quic", "quinn::Endpoint::"),
    ("quic", ".connect(addr"),
    ("tcp", "TcpStream::connect("),
    ("tcp", "TcpStream::connect_timeout("),
    ("tcp", "TcpListener::bind("),
    ("udp", "UdpSocket::bind("),
    ("udp", ".send_to("),
    ("ws", "tokio_tungstenite::connect_async"),
    ("ws", "tungstenite::connect"),
    ("raw", "libc::socket("),
    ("dns", "lookup_host("),
    ("dns", "to_socket_addrs("),
    ("dns", ".lookup_ip("),
    ("proc", "Command::new("),
];

/// Verdict vocabulary. A row must open with one of these so the test can
/// refuse a hand-wavy "n/a".
const V_UNREACHABLE: &str = "unreachable:";
const V_EQUIVALENT: &str = "equivalent:";
const V_ONLY_WINDOWS: &str = "only-on-windows:";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PlatformView {
    /// The site is compiled out on Windows (`cfg(unix)`, `cfg(target_os = ...)`).
    AbsentOnWindows,
    /// The site is compiled only on Windows; no Unix counterpart exists.
    OnlyOnWindows,
}

struct CfgSite {
    file: &'static str,
    line: usize,
    /// The cfg expression exactly as written inside `#[cfg( ... )]`.
    guard: &'static str,
    /// Census class (`proc`, `raw`, `udp`, `tcp`, `dns`, ...).
    class: &'static str,
    view: PlatformView,
    /// What the other platform does — one verdict, machine-checked prefix.
    other_platform: &'static str,
    /// Open defect or reachability note, or "".
    note: &'static str,
}

const CFG_EGRESS: &[CfgSite] = &[
    // ── absent on Windows ──────────────────────────────────────────────────
    CfgSite {
        file: "src/browser/juggler.rs",
        line: 91,
        guard: "unix",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: juggler.rs:223 #[cfg(not(unix))] launch returns ConnectionFailed and spawns nothing",
        note: "open: juggler.rs has no scope::require; the Unix browser launch is ungated child-process egress",
    },
    CfgSite {
        file: "src/browser/trace.rs",
        line: 455,
        guard: "target_os = \"macos\"",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: trace.rs:449 #[cfg(target_os = \"windows\")] Command::new(\"cmd\")",
        note: "local trace-viewer open; not network egress",
    },
    CfgSite {
        file: "src/browser/trace.rs",
        line: 461,
        guard: "target_os = \"linux\"",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: trace.rs:449 #[cfg(target_os = \"windows\")] Command::new(\"cmd\")",
        note: "local trace-viewer open; not network egress",
    },
    CfgSite {
        file: "src/main.rs",
        line: 2203,
        guard: "target_os = \"macos\"",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: main.rs:2167 winget / main.rs:2183 choco #[cfg(target_os = \"windows\")]",
        note: "ffmpeg package-manager install; local OS maintenance",
    },
    CfgSite {
        file: "src/main.rs",
        line: 2220,
        guard: "not(any(target_os = \"windows\", target_os = \"macos\"))",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: main.rs:2167 winget / main.rs:2183 choco #[cfg(target_os = \"windows\")]",
        note: "ffmpeg package-manager install (apt); local OS maintenance",
    },
    CfgSite {
        file: "src/main.rs",
        line: 2230,
        guard: "not(any(target_os = \"windows\", target_os = \"macos\"))",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: main.rs:2167 winget / main.rs:2183 choco #[cfg(target_os = \"windows\")]",
        note: "ffmpeg package-manager install (dnf); local OS maintenance",
    },
    CfgSite {
        file: "src/main.rs",
        line: 2240,
        guard: "not(any(target_os = \"windows\", target_os = \"macos\"))",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: main.rs:2167 winget / main.rs:2183 choco #[cfg(target_os = \"windows\")]",
        note: "ffmpeg package-manager install (pacman); local OS maintenance",
    },
    CfgSite {
        file: "src/main.rs",
        line: 4813,
        guard: "unix",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "equivalent: main.rs:4973/:4984/:4992 #[cfg(windows)] icacls save/restore",
        note: "local file metadata preservation; not network egress",
    },
    CfgSite {
        file: "src/runtime/io_uring_runtime.rs",
        line: 123,
        guard: "all(target_os = \"linux\", feature = \"io-uring-backend\")",
        class: "proc",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: fn is cfg'd out and is_available() returns false off Linux",
        note: "local `uname -r` probe; not network egress",
    },
    CfgSite {
        file: "src/stdlib/topology.rs",
        line: 593,
        guard: "target_os = \"linux\"",
        class: "raw",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: topology.rs:1001 #[cfg(not(target_os = \"linux\"))] mod raw returns Unsupported",
        note: "open: raw ICMPv6 socket; icmpv6_echo has no scope::require",
    },
    CfgSite {
        file: "src/stdlib/topology.rs",
        line: 701,
        guard: "target_os = \"linux\"",
        class: "udp",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: topology.rs:1001 #[cfg(not(target_os = \"linux\"))] mod raw returns Unsupported",
        note: "udp_source_v6 routes a connect() to select a source address; sends no packet",
    },
    CfgSite {
        file: "src/stdlib/topology.rs",
        line: 714,
        guard: "target_os = \"linux\"",
        class: "raw",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: topology.rs:1001 #[cfg(not(target_os = \"linux\"))] mod raw returns Unsupported",
        note: "open: raw TCP SYN socket; RawSyn::open has no scope::require",
    },
    CfgSite {
        file: "src/stdlib/topology.rs",
        line: 743,
        guard: "target_os = \"linux\"",
        class: "udp",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: topology.rs:1001 #[cfg(not(target_os = \"linux\"))] mod raw returns Unsupported",
        note: "RawSyn::source_for routes a connect() to select a source address; sends no packet",
    },
    CfgSite {
        file: "src/stdlib/topology.rs",
        line: 832,
        guard: "target_os = \"linux\"",
        class: "raw",
        view: PlatformView::AbsentOnWindows,
        other_platform: "unreachable: topology.rs:1001 #[cfg(not(target_os = \"linux\"))] mod raw returns Unsupported",
        note: "open: raw ICMP socket; icmp_echo has no scope::require",
    },
    // ── only on Windows (the counterparts, so the pair is auditable) ───────
    CfgSite {
        file: "src/browser/process.rs",
        line: 1397,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: tasklist liveness probe; Unix uses libc::kill at :1381",
        note: "local process liveness; not network egress",
    },
    CfgSite {
        file: "src/browser/trace.rs",
        line: 449,
        guard: "target_os = \"windows\"",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: opens the trace viewer via cmd",
        note: "local viewer open; not network egress",
    },
    CfgSite {
        file: "src/main.rs",
        line: 2167,
        guard: "target_os = \"windows\"",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: winget install",
        note: "ffmpeg package-manager install; local OS maintenance",
    },
    CfgSite {
        file: "src/main.rs",
        line: 2183,
        guard: "target_os = \"windows\"",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: choco install",
        note: "ffmpeg package-manager install; local OS maintenance",
    },
    CfgSite {
        file: "src/main.rs",
        line: 4973,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: icacls availability probe",
        note: "local file metadata preservation; not network egress",
    },
    CfgSite {
        file: "src/main.rs",
        line: 4984,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: icacls /save",
        note: "local file metadata preservation; not network egress",
    },
    CfgSite {
        file: "src/main.rs",
        line: 4992,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: icacls /restore",
        note: "local file metadata preservation; not network egress",
    },
    CfgSite {
        file: "src/pkg/cache.rs",
        line: 575,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: cmd to create a directory junction",
        note: "local package-cache link; not network egress",
    },
    CfgSite {
        file: "src/pkg/cache.rs",
        line: 618,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: cmd to create a directory link",
        note: "local package-cache link; not network egress",
    },
    CfgSite {
        file: "src/stdlib/transfer.rs",
        line: 718,
        guard: "windows",
        class: "proc",
        view: PlatformView::OnlyOnWindows,
        other_platform: "only-on-windows: powershell VSS copy",
        note: "local file copy; not network egress",
    },
];

const CFG_EGRESS_CAP: usize = 24;

#[derive(Clone, Debug)]
struct FoundCfgSite {
    line: usize,
    class: &'static str,
    guard: String,
}

#[derive(Clone, Debug)]
struct ModGuard {
    name: String,
    path: Option<String>,
    guard: String,
}

fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// 0-based last line of the item starting at `start`, by brace / `;` matching.
/// Returns `(line, ended_with_semicolon)`.
fn item_end(lines: &[&str], start: usize) -> (usize, bool) {
    let mut depth: i32 = 0;
    let mut seen_open = false;
    let mut in_block = false;
    let mut i = start;
    while i < lines.len() {
        let raw = lines[i];
        if in_block {
            if raw.contains("*/") {
                in_block = false;
            }
            i += 1;
            continue;
        }
        if raw.contains("/*") && !raw.contains("*/") {
            in_block = true;
            i += 1;
            continue;
        }
        let code = strip_line_comment(raw);
        if !seen_open && depth == 0 && code.trim_end().ends_with(';') {
            return (i, true);
        }
        for ch in code.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    seen_open = true;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 && seen_open {
                        return (i, false);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    (lines.len().saturating_sub(1), false)
}

fn path_attr(line: &str) -> Option<&str> {
    let t = line.trim();
    let rest = t.strip_prefix("#[path")?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    rest.split('"').next()
}

fn mod_decl(line: &str) -> Option<&str> {
    let t = line.trim();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub(super) "))
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let rest = t.strip_prefix("mod ")?;
    let name = rest.strip_suffix(';')?.trim();
    if name.is_empty() || name.contains('{') || name.contains(' ') {
        return None;
    }
    Some(name)
}

/// HTTP egress, matching the probe's `(blocking::)?` handling.
fn has_cfg_http(line: &str) -> bool {
    const VERBS: &[&str] = &[
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
        "Client::new",
        "Client::builder",
    ];
    for prefix in ["egress_http::", "ureq::", "reqwest::"] {
        let mut hay = line;
        while let Some(pos) = hay.find(prefix) {
            let mut rest = &hay[pos + prefix.len()..];
            if prefix == "reqwest::" {
                if let Some(r) = rest.strip_prefix("blocking::") {
                    rest = r;
                }
            }
            if VERBS.iter().any(|v| rest.starts_with(v)) {
                return true;
            }
            hay = &hay[pos + prefix.len()..];
        }
    }
    false
}

fn classify_cfg_line(line: &str) -> Option<&'static str> {
    if has_cfg_http(line) {
        return Some("http");
    }
    for (class, needle) in CFG_EGRESS_CLASSES {
        if line.contains(needle) {
            return Some(class);
        }
    }
    None
}

/// Inline cfg spans: every line that invokes an egress primitive inside an
/// attribute's item span, plus any `#[cfg(...)] mod X;` declarations.
fn scan_cfg_spans(text: &str) -> (Vec<FoundCfgSite>, Vec<ModGuard>) {
    let lines: Vec<&str> = text.lines().collect();
    let n_prod = production_region(text).lines().count();
    // line -> (span length, guard, class); the innermost (shortest) span wins.
    let mut sites: BTreeMap<usize, (usize, String, &'static str)> = BTreeMap::new();
    let mut mods = Vec::new();

    for i in 0..lines.len() {
        let Some(expr) = cfg_attr_expr(lines[i]) else {
            continue;
        };
        if cfg_expr_mentions_test(expr) {
            continue;
        }
        let mut j = i + 1;
        let mut pattr: Option<String> = None;
        while j < lines.len() {
            let t = lines[j].trim();
            if t.is_empty() || t.starts_with("//") {
                j += 1;
                continue;
            }
            if t.starts_with("#[") {
                if let Some(p) = path_attr(lines[j]) {
                    pattr = Some(p.to_string());
                }
                j += 1;
                continue;
            }
            break;
        }
        if j >= lines.len() {
            break;
        }
        let (end, semi) = item_end(&lines, j);
        for k in i..=end {
            if k + 1 > n_prod {
                continue;
            }
            let code = strip_line_comment(lines[k]);
            let t = code.trim();
            if t.is_empty() || t.starts_with("//") || cfg_attr_expr(code).is_some() {
                continue;
            }
            let Some(class) = classify_cfg_line(code) else {
                continue;
            };
            let span = end - i;
            sites
                .entry(k + 1)
                .and_modify(|e| {
                    if span < e.0 {
                        *e = (span, expr.to_string(), class);
                    }
                })
                .or_insert((span, expr.to_string(), class));
        }
        if semi {
            if let Some(name) = mod_decl(lines[j]) {
                mods.push(ModGuard {
                    name: name.to_string(),
                    path: pattr,
                    guard: expr.to_string(),
                });
            }
        }
    }

    (
        sites
            .into_iter()
            .map(|(line, (_, guard, class))| FoundCfgSite { line, class, guard })
            .collect(),
        mods,
    )
}

fn path_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn normalize_rel(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

fn resolve_mod(decl_rel: &str, name: &str, pattr: Option<&str>) -> Vec<String> {
    let dir = decl_rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let mut out = Vec::new();
    if let Some(p) = pattr {
        out.push(normalize_rel(&path_join(dir, p)));
    }
    out.push(normalize_rel(&path_join(dir, &format!("{name}.rs"))));
    out.push(normalize_rel(&path_join(dir, &format!("{name}/mod.rs"))));
    out
}

/// Every `mod X;` in a file (cfg-attributed or not), for guard inheritance.
fn all_mod_decls(text: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut pending_path: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if t.starts_with("#[") {
            if let Some(p) = path_attr(line) {
                pending_path = Some(p.to_string());
            }
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if let Some(name) = mod_decl(line) {
            out.push((name.to_string(), pending_path.take()));
        } else if !t.starts_with("#![") {
            pending_path = None;
        }
    }
    out
}

/// File-level guards: `#[cfg(...)] mod X;` resolves to the module file, and a
/// module declared inside a guarded file inherits that file's guard.
fn file_guards(files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut guards: BTreeMap<String, String> = BTreeMap::new();
    let mut direct: Vec<(String, String, Option<String>, String)> = Vec::new();
    for (rel, text) in files {
        let (_, mods) = scan_cfg_spans(text);
        for m in mods {
            direct.push((rel.clone(), m.name, m.path, m.guard));
        }
    }
    // Seed from direct cfg-mod declarations.
    for (decl_rel, name, pattr, guard) in &direct {
        for cand in resolve_mod(decl_rel, name, pattr.as_deref()) {
            if files.contains_key(&cand) {
                guards.entry(cand).or_insert_with(|| guard.clone());
                break;
            }
        }
    }
    // Propagate through unguarded children of a guarded file.
    loop {
        let mut changed = false;
        for (rel, guard) in guards.clone() {
            let Some(text) = files.get(&rel) else {
                continue;
            };
            for (name, pattr) in all_mod_decls(text) {
                for cand in resolve_mod(&rel, &name, pattr.as_deref()) {
                    if files.contains_key(&cand) && !guards.contains_key(&cand) {
                        guards.insert(cand, guard.clone());
                        changed = true;
                        break;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    guards
}

/// Every cfg-gated egress site in the tree, with its effective guard.
fn cfg_egress_sites(files: &BTreeMap<String, String>) -> Vec<(&str, FoundCfgSite)> {
    let guards = file_guards(files);
    let mut out = Vec::new();
    for (rel, text) in files {
        let (inline, _) = scan_cfg_spans(text);
        let inline_lines: BTreeSet<usize> = inline.iter().map(|s| s.line).collect();
        for site in inline {
            out.push((rel.as_str(), site));
        }
        let Some(guard) = guards.get(rel) else {
            continue;
        };
        let n_prod = production_region(text).lines().count();
        for (idx, line) in text.lines().enumerate() {
            let lineno = idx + 1;
            if lineno > n_prod {
                break;
            }
            if inline_lines.contains(&lineno) || is_comment(line) {
                continue;
            }
            if let Some(class) = classify_cfg_line(line) {
                out.push((
                    rel.as_str(),
                    FoundCfgSite {
                        line: lineno,
                        class,
                        guard: guard.clone(),
                    },
                ));
            }
        }
    }
    out
}

#[test]
fn cfg_gated_egress_sites_are_enumerated() {
    assert!(
        CFG_EGRESS.len() <= CFG_EGRESS_CAP,
        "CFG_EGRESS has {} entries; more than {CFG_EGRESS_CAP} means the census is growing faster than it is audited",
        CFG_EGRESS.len()
    );

    let files = load_src();
    let found = cfg_egress_sites(&files);

    let mut problems = Vec::new();
    let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();

    for (file, site) in &found {
        let key = (file.to_string(), site.line);
        if !seen.insert(key) {
            problems.push(format!(
                "{file}:{}: classified twice — the scanner or the census has a duplicate",
                site.line
            ));
            continue;
        }
        let row = CFG_EGRESS
            .iter()
            .find(|r| r.file == *file && r.line == site.line);
        match row {
            None => problems.push(format!(
                "{file}:{}: new cfg-gated egress site [{}] under `{}` has no CFG_EGRESS row — \
                 state what the other platform does before it can land",
                site.line, site.class, site.guard
            )),
            Some(r) => {
                if r.guard != site.guard {
                    problems.push(format!(
                        "{file}:{}: guard drifted — census `{}`, source `{}`",
                        site.line, r.guard, site.guard
                    ));
                }
                if r.class != site.class {
                    problems.push(format!(
                        "{file}:{}: class drifted — census `{}`, source `{}`",
                        site.line, r.class, site.class
                    ));
                }
            }
        }
    }

    for row in CFG_EGRESS {
        if !seen.contains(&(row.file.to_string(), row.line)) {
            problems.push(format!(
                "{}:{}: stale CFG_EGRESS row — no cfg-gated egress site at that line",
                row.file, row.line
            ));
        }
        let ok_prefix = row.other_platform.starts_with(V_UNREACHABLE)
            || row.other_platform.starts_with(V_EQUIVALENT)
            || row.other_platform.starts_with(V_ONLY_WINDOWS);
        if !ok_prefix {
            problems.push(format!(
                "{}:{}: other-platform verdict must start with {V_UNREACHABLE:?}, \
                 {V_EQUIVALENT:?} or {V_ONLY_WINDOWS:?}: {:?}",
                row.file, row.line, row.other_platform
            ));
        }
        if row.note.is_empty() {
            problems.push(format!(
                "{}:{}: every cfg row carries a one-line note — say why it is safe or name the open defect",
                row.file, row.line
            ));
        }
        let expected_view = if row.view == PlatformView::OnlyOnWindows {
            V_ONLY_WINDOWS
        } else {
            ""
        };
        if !expected_view.is_empty() && !row.other_platform.starts_with(expected_view) {
            problems.push(format!(
                "{}:{}: OnlyOnWindows row must carry an only-on-windows verdict",
                row.file, row.line
            ));
        }
    }

    eprintln!(
        "cfg census: {} sites scanned, {} rows ({} absent, {} windows-only, cap {})",
        found.len(),
        CFG_EGRESS.len(),
        CFG_EGRESS
            .iter()
            .filter(|r| r.view == PlatformView::AbsentOnWindows)
            .count(),
        CFG_EGRESS
            .iter()
            .filter(|r| r.view == PlatformView::OnlyOnWindows)
            .count(),
        CFG_EGRESS_CAP
    );

    assert!(
        problems.is_empty(),
        "cfg-gated egress census is out of date:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn production_region_cuts_every_test_only_cfg() {
    // The forms that appear in this tree, plus the two a future author might use.
    for marker in [
        "#[cfg(test)]",
        "#[cfg(all(test, unix))]",
        "#[cfg(any(test, feature = \"harness\"))]",
    ] {
        let text = format!("fn prod() {{}}\n{marker}\nmod tests {{}}");
        assert_eq!(
            production_region(&text),
            "fn prod() {}\n",
            "production_region must cut at {marker}"
        );
    }
    // A platform cfg is not a test cut.
    let text = "fn prod() {}\n#[cfg(unix)]\nfn f() {}\n";
    assert_eq!(production_region(text), text);
}

#[test]
fn cfg_scanner_sees_a_planted_unix_site() {
    // Negative control for the scanner itself: if this stops finding the
    // planted site, the census above is green by blindness, not by coverage.
    let text =
        "fn a() {}\n#[cfg(unix)]\nfn launch() {\n    let _ = Command::new(\"browser\");\n}\n";
    let (sites, _) = scan_cfg_spans(text);
    assert_eq!(sites.len(), 1, "scanner missed the planted site: {sites:?}");
    assert_eq!(sites[0].line, 4);
    assert_eq!(sites[0].class, "proc");
    assert_eq!(sites[0].guard, "unix");
}
