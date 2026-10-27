//! `tallow.ip` fixtures, run through the real binary.
//!
//! These three programs existed under `tests/fixtures/intel_ip/` with nothing
//! executing them: they were committed as evidence and were only ever evidence
//! if a human remembered to run them by hand. This file is the driver that makes
//! the claim "the refusal path works end to end" checkable on every `cargo test`.
//!
//! What each fixture pins, and why it is not already covered by the unit tests:
//!
//! * `smoke.tl` — the declared surface is *reachable from a `.tl` program*. The
//!   module's own tests call Rust functions directly, so they cannot notice a
//!   manifest/declaration that no program can name (that defect happened once in
//!   this module: a struct literal the typechecker would not accept).
//! * `refusal_no_match.tl` — an uncovered address exits non-zero with
//!   `ip:not-in-table`, not `asn=0`. ASN 0 is a plausible-looking answer for a
//!   host nobody knows, which is exactly why it must not be returned.
//! * `refusal_no_table.tl` — a missing table names the path it looked for and
//!   refuses; an empty table that loads cleanly would make "no data" and "no
//!   such table" indistinguishable.
//!
//! Paths inside the fixtures are repo-root relative, so the child runs with the
//! manifest directory as its working directory.

use std::process::Command;

fn run(name: &str) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(format!("tests/fixtures/intel_ip/{name}"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn smoke_program_reaches_the_declared_surface_and_picks_the_longest_prefix() {
    let (ok, stdout, stderr) = run("smoke.tl");
    assert!(ok, "smoke.tl failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("longest-prefix: asn=64501 prefix_len=24"),
        "the /24 row must beat the earlier /8 row; got:\n{stdout}"
    );
    assert!(
        stdout.contains("get-stale-flag: true"),
        "a read past TTL must report staleness rather than a miss; got:\n{stdout}"
    );
}

#[test]
fn uncovered_address_is_a_coded_refusal_not_asn_zero() {
    let (ok, stdout, stderr) = run("refusal_no_match.tl");
    assert!(!ok, "an uncovered address must exhaust: {stdout}");
    assert!(
        stderr.contains("ip:not-in-table"),
        "refusal must carry its code; stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("unreachable"),
        "the fixture must fail before printing an answer; stdout:\n{stdout}"
    );
}

#[test]
fn missing_table_names_the_path_instead_of_loading_empty() {
    let (ok, stdout, stderr) = run("refusal_no_table.tl");
    assert!(!ok, "a missing table must refuse: {stdout}");
    assert!(
        stderr.contains("ip:table-missing"),
        "refusal must carry its code; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("/nonexistent/intel-ip/ip2asn-v4.tsv"),
        "the refusal must name the path it looked for; stderr:\n{stderr}"
    );
}
