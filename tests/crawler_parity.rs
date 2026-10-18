//! Crawler natives: value parity where it is offline-testable, refusal parity everywhere.
//!
//! Two natives, deliberately treated differently, because they are not the same kind of
//! thing:
//!
//! * **`Crawler.from_links`** plans without any network (`crawler_from_links_plan` is pure),
//!   so it gets the full three-assertion parity treatment: both legs exit 0, stdout is
//!   byte-identical, and stdout matches a **pinned reference** — the third assertion is what
//!   catches two engines agreeing on the wrong answer.
//! * **`Crawler.from_sitemap`** FETCHES: the facade drives `SitemapParser` over
//!   `runtime::egress_http` (Tor by default, refusing rather than falling back to the box IP).
//!   Its happy path therefore cannot be exercised offline — a local fixture can never be
//!   fetched, which the facade's own doc records. What IS deterministic offline is the
//!   **refusal**: a non-string argument is rejected before any egress. That is what is
//!   pinned here, and the gap is stated rather than papered over.
//!
//! The refusal tests also pin a defect this suite found in the same class as
//! `StructuredData.extract(42)`: both crawler arms used `v.as_string()`, which coerced an int
//! argument into a URL string and proceeded. The arms now refuse, naming the same cause as the
//! compiled legs (`interp.rs`, `codegen.rs`).
//!
//! Harness shape (engine forcing, binary resolution, caps) follows
//! `tests/regex_engine_parity.rs` and `tests/structured_data_parity.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

const LINKS_FIXTURE: &str = "tests/parity/parity_programs/19_crawler_from_links.tl";
const LINKS_REFUSAL: &str = "tests/parity/parity_programs/20_crawler_from_links_refusal.tl";
const SITEMAP_REFUSAL: &str = "tests/parity/parity_programs/21_crawler_from_sitemap_refusal.tl";

/// The interpreter's answer for the `from_links` fixture, pinned and not derived.
/// A supplied depth of 5; B the omitted depth, whose shared default is 3.
const EXPECTED: &str = "\
A_seed
https://example.com
A_strategy
link_follow
A_maxdepth
5
A_maxpages
1
A_crawled
0
A_rate
0
B_maxdepth
3
";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Prefer the NEWEST binary. A stale release build silently makes a parity
    // test testify about a tree from days ago: measured 2026-10-17, the release
    // binary was 2026-10-16 18:46 while the debug binary carrying the fix was
    // 2026-10-18 00:45, so the "regression" was the harness, not the code.
    let release = repo_root().join("target/release/tallow");
    let debug = repo_root().join("target/debug/tallow");
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&release), mtime(&debug)) {
        (Some(r), Some(d)) if r >= d => release,
        (Some(_), Some(_)) => debug,
        (Some(_), None) => release,
        (None, Some(_)) => debug,
        (None, None) => debug,
    }
}

struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[String], cwd: &Path) -> Out {
    let out = Command::new(tallow_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn tallow");
    Out {
        rc: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Cross target ⇒ `is_cross` ⇒ the tree-walking interpreter path.
fn run_interp(file: &Path) -> Out {
    let args: Vec<String> = vec![
        "run".into(),
        file.display().to_string(),
        "--target".into(),
        "x86_64-linux".into(),
    ];
    run(&args, &repo_root())
}

/// `--require-native` refuses the interpreter fallback, so a pass here is a real
/// compiled-path pass.
fn run_native(file: &Path) -> Out {
    let args: Vec<String> = vec![
        "run".into(),
        "--require-native".into(),
        file.display().to_string(),
    ];
    run(&args, &repo_root())
}

#[test]
fn crawler_from_links_engines_agree_byte_for_byte() {
    let fixture = repo_root().join(LINKS_FIXTURE);
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let interp = run_interp(&fixture);
    assert_eq!(
        interp.rc, 0,
        "interpreter leg failed (rc={}): {}",
        interp.rc, interp.stderr
    );
    let native = run_native(&fixture);
    assert_eq!(
        native.rc, 0,
        "native leg failed (rc={}); stderr={}",
        native.rc, native.stderr
    );
    assert!(
        !native.stderr.contains("native build unavailable")
            && !native.stderr.contains("interpreter fallback"),
        "native leg fell back to the interpreter: {}",
        native.stderr
    );
    assert_eq!(
        native.stdout, interp.stdout,
        "interp↔native stdout divergence\n--- interp ---\n{}\n--- native ---\n{}",
        interp.stdout, native.stdout
    );
    assert_eq!(
        interp.stdout, EXPECTED,
        "reference block drifted (interpreter is the reference engine)"
    );
    assert_eq!(
        native.stdout, EXPECTED,
        "native output is not the reference block"
    );
}

/// The same helper for both refusal tests: both engines must refuse, name the same cause,
/// and the compiled leg must not have emitted output first.
fn assert_refusal_parity(fixture_rel: &str, cause: &str) {
    let fixture = repo_root().join(fixture_rel);
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let interp = run_interp(&fixture);
    let native = run_native(&fixture);

    assert_ne!(interp.rc, 0, "the interpreter must refuse: {}", interp.stdout);
    assert_ne!(native.rc, 0, "the native path must refuse: {}", native.stdout);
    assert!(
        interp.stderr.contains(cause),
        "interpreter refusal does not name the cause ({cause}): {}",
        interp.stderr
    );
    assert!(
        native.stderr.contains(cause),
        "native refusal does not name the cause ({cause}): {}",
        native.stderr
    );
    assert!(
        native.stdout.trim().is_empty(),
        "the native path emitted output before refusing: {:?}",
        native.stdout
    );
}

#[test]
fn a_non_string_seed_url_is_refused_by_both_engines() {
    assert_refusal_parity(
        LINKS_REFUSAL,
        "expected a seed URL string argument",
    );
}

#[test]
fn a_non_string_sitemap_url_is_refused_by_both_engines() {
    assert_refusal_parity(
        SITEMAP_REFUSAL,
        "expected a sitemap URL string argument",
    );
}
