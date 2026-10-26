//! Adversarial coverage for the topology plane.
//!
//! `tests/topology_scan.rs` proves the plane works when it is supposed to. This
//! file attacks the two properties that make it safe to ship:
//!
//! 1. **The scope register is the only door.** Every dispatched entry point must
//!    refuse an unlisted target with the register's own code (`scope:not-listed`)
//!    and must not build a probe. `203.0.113.7` is TEST-NET-3: assigned to
//!    documentation, absent from `configs/tallow/scope/authorized-hosts.toml`.
//!    No fixture here reaches the network for a real target.
//! 2. **Bad input is a refusal, not a panic or an empty success.** A malformed
//!    port spec must exit 1 with a message, never crash and never report a scan
//!    that did not happen.
//!
//! Plus the two structural properties the rest of the capability work depends
//! on: a scope decision must not be reachable through an alternate spelling of
//! the same address, and a module namespace must not be reachable through a
//! string (`"__module_topology__".syn_scan(..)`, lattice N-1).
//!
//! A test that documents a defect is left failing on purpose. Each such test
//! says so in its own comment and names the defect it measures; the run summary
//! lists them. Deleting one to make the suite green would hide the defect.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/topology_adversarial")
        .join(name)
}

struct Run {
    fixture: String,
    code: i32,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Run {
    fn dump(&self) -> String {
        format!(
            "fixture {} exit={} elapsed={:?}\n--- stdout ---\n{}--- stderr ---\n{}",
            self.fixture, self.code, self.elapsed, self.stdout, self.stderr
        )
    }

    fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Run a fixture through the tree-walking interpreter (`--target x86_64-linux`
/// is the documented way to force it, and the plane must behave identically on
/// that path).
fn run(fixture_name: &str) -> Run {
    let path = fixture(fixture_name);
    assert!(path.is_file(), "missing fixture: {}", path.display());
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("could not run tallow on {}: {e}", path.display()));
    Run {
        fixture: fixture_name.to_string(),
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        elapsed: started.elapsed(),
    }
}

/// Markers that mean the runtime crashed rather than refused. A crash on
/// attacker-controlled input is a defect even when the exit code is non-zero.
const PANIC_MARKERS: [&str; 5] = [
    "panicked",
    "index out of bounds",
    "RUST_BACKTRACE",
    "called `Option::unwrap`",
    "called `Result::unwrap`",
];

fn assert_no_panic(r: &Run) {
    let combined = r.combined();
    for marker in PANIC_MARKERS {
        assert!(
            !combined.contains(marker),
            "panic marker {marker:?} present — a refusal must not be a crash:\n{}",
            r.dump()
        );
    }
}

/// The documented refusal: exit 1, the register's own code, and the fixture's
/// canary never printed (the call did not return, so no probe was built).
fn assert_refused_by_scope(r: &Run, what: &str) {
    assert_eq!(
        r.code,
        1,
        "{what} must be refused with exit 1:\n{}",
        r.dump()
    );
    assert!(
        r.stderr.contains("not authorized"),
        "{what} must be refused by the scope register:\n{}",
        r.dump()
    );
    assert!(
        r.stderr.contains("scope:not-listed"),
        "{what} must carry the register's own refusal code:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY"),
        "{what} returned a result to the program — the call was not refused:\n{}",
        r.dump()
    );
    assert_no_panic(r);
}

// ═══════════════════════════════════════════════════════════════════
// 1. Refusal is enforced by EVERY dispatched entry point
// ═══════════════════════════════════════════════════════════════════

macro_rules! refusal_test {
    ($name:ident, $fixture:expr, $func:expr) => {
        #[test]
        fn $name() {
            let r = run($fixture);
            assert_refused_by_scope(&r, concat!("topology.", $func));
        }
    };
}

refusal_test!(
    refusal_is_enforced_by_syn_scan,
    "refusal_syn_scan.tl",
    "syn_scan"
);
refusal_test!(
    refusal_is_enforced_by_connect_scan,
    "refusal_connect_scan.tl",
    "connect_scan"
);
refusal_test!(
    refusal_is_enforced_by_fin_scan,
    "refusal_fin_scan.tl",
    "fin_scan"
);
refusal_test!(
    refusal_is_enforced_by_null_scan,
    "refusal_null_scan.tl",
    "null_scan"
);
refusal_test!(
    refusal_is_enforced_by_xmas_scan,
    "refusal_xmas_scan.tl",
    "xmas_scan"
);
refusal_test!(
    refusal_is_enforced_by_udp_scan,
    "refusal_udp_scan.tl",
    "udp_scan"
);
refusal_test!(
    refusal_is_enforced_by_discover,
    "refusal_discover.tl",
    "discover"
);
refusal_test!(refusal_is_enforced_by_banner, "refusal_banner.tl", "banner");
refusal_test!(
    refusal_is_enforced_by_tls_posture,
    "refusal_tls_posture.tl",
    "tls_posture"
);
refusal_test!(refusal_is_enforced_by_ja4, "refusal_ja4.tl", "ja4");
refusal_test!(
    refusal_is_enforced_by_traceroute,
    "refusal_traceroute.tl",
    "traceroute"
);
refusal_test!(
    refusal_is_enforced_by_reconcile,
    "refusal_reconcile.tl",
    "reconcile"
);

/// The planner is not a listed entry point in the directive, but it is
/// dispatched and it resolves the target, so it gets the same gate.
#[test]
fn refusal_is_enforced_by_plan() {
    let r = run("refusal_plan.tl");
    assert_refused_by_scope(&r, "topology.plan");
}

// ═══════════════════════════════════════════════════════════════════
// 2. Malformed port specifications
// ═══════════════════════════════════════════════════════════════════
//
// The target is loopback (authorized), so the only thing under test is
// `parse_ports`. The documented contract: "an empty spec is an error, not an
// empty scan". Every one of these must exit 1 with a clear message.

macro_rules! malformed_ports_test {
    ($name:ident, $fixture:expr, $spec:expr) => {
        #[test]
        fn $name() {
            let r = run($fixture);
            assert_eq!(
                r.code,
                1,
                "port spec {:?} must be an error, not a scan:\n{}",
                $spec,
                r.dump()
            );
            assert!(
                r.stderr.contains("topology:"),
                "port spec {:?} must name the defect on stderr:\n{}",
                $spec,
                r.dump()
            );
            assert!(
                !r.stdout.contains("CANARY_SCAN_COMPLETED"),
                "port spec {:?} produced a completed scan instead of a refusal:\n{}",
                $spec,
                r.dump()
            );
            assert_no_panic(&r);
        }
    };
}

malformed_ports_test!(empty_port_spec_is_refused, "ports_empty.tl", "");
malformed_ports_test!(port_zero_is_refused, "ports_zero.tl", "0");
malformed_ports_test!(negative_port_is_refused, "ports_negative.tl", "-1");
malformed_ports_test!(port_above_u16_is_refused, "ports_above_max.tl", "70000");
malformed_ports_test!(open_ended_range_is_refused, "ports_open_range.tl", "1-");
malformed_ports_test!(alphabetic_port_is_refused, "ports_alpha.tl", "abc");

/// A spec with an empty element (`1,,2`) is the one shape `parse_ports` is
/// tempted to forgive: `split(',')` yields an empty string, and the loop
/// `continue`s past it. The documented contract is that a malformed spec is an
/// error; silently reinterpreting `1,,2` as `1,2` means the operator's typo is
/// turned into a scan of ports they did not ask for.
#[test]
fn empty_element_in_port_list_is_refused() {
    let r = run("ports_double_comma.tl");
    assert_eq!(
        r.code,
        1,
        "'1,,2' is a malformed spec and must be refused, not silently read as '1,2':\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY_SCAN_COMPLETED"),
        "'1,,2' produced a completed scan instead of a refusal:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

// ═══════════════════════════════════════════════════════════════════
// 3. Boundary values
// ═══════════════════════════════════════════════════════════════════

/// 65535 is the top of the u16 range; it must parse and scan.
#[test]
fn top_of_the_port_range_scans() {
    let r = run("boundary_port_65535.tl");
    assert_eq!(r.code, 0, "port 65535 must be scannable:\n{}", r.dump());
    assert!(
        r.stdout.contains("BOUNDARY_65535"),
        "the scan must return a result:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// Three ports at the very top of the range, as a range expression.
#[test]
fn three_port_spec_at_the_top_of_the_range_scans() {
    let r = run("boundary_top3.tl");
    assert_eq!(r.code, 0, "'65533-65535' must be scannable:\n{}", r.dump());
    assert!(
        r.stdout.contains("BOUNDARY_TOP3"),
        "the scan must return a result:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// A zero timeout must terminate immediately, not hang and not divide by zero.
#[test]
fn zero_timeout_does_not_hang_or_panic() {
    let r = run("boundary_timeout_zero.tl");
    assert_eq!(
        r.code,
        0,
        "a zero timeout is a degenerate but legal request:\n{}",
        r.dump()
    );
    assert!(
        r.elapsed < Duration::from_secs(10),
        "a zero timeout must not hang (took {:?}):\n{}",
        r.elapsed,
        r.dump()
    );
    assert_no_panic(&r);
}

/// `rps 0` must be clamped: used as a divisor it is an infinity, and as a token
/// refill rate it is a deadlock. Both are silent failures, so the plan must
/// report a non-zero rate and the scan must still finish.
#[test]
fn zero_rps_is_clamped_not_divided_by() {
    let r = run("boundary_rps_zero.tl");
    assert_eq!(
        r.code,
        0,
        "rps 0 must be clamped, not rejected and not fatal:\n{}",
        r.dump()
    );
    assert!(
        r.stdout.contains("BOUNDARY_RPS0"),
        "the plan must return a result:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("rps=0"),
        "a zero rate must be clamped before it reaches the planner:\n{}",
        r.dump()
    );
    assert!(
        r.stdout.contains("BOUNDARY_RPS0_SCAN"),
        "a zero rate must not deadlock the token bucket:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// The `port` argument of `banner` / `tls_posture` / `ja4` is an `Int`, and the
/// implementation casts it with `as u16`. 70000 is not a port: it wraps to 4464,
/// which is a *different* port than the operator named. The documented contract
/// for a bad port is a clear error, so the failure must name the port it was
/// given, not the port it silently became.
#[test]
fn out_of_range_int_port_must_not_wrap() {
    let r = run("boundary_port_int_wrap.tl");
    assert_eq!(
        r.code,
        1,
        "port 70000 is out of range and must be refused:\n{}",
        r.dump()
    );
    assert!(
        r.stderr.contains("70000"),
        "the error must name the port that was requested; a 16-bit wrap to 4464 \
         means the probe was aimed at a port nobody asked for:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY_BANNER_WRAPPED"),
        "the wrapped port returned a result:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

// ═══════════════════════════════════════════════════════════════════
// 4. Scope-bypass attempts
// ═══════════════════════════════════════════════════════════════════
//
// The gate compares the *target string* against the register. Each fixture
// below spells 127.0.0.1 in a form the register does not contain. None of them
// may reach a scan; if one does, that is a finding, not a test to relax.

macro_rules! bypass_test {
    ($name:ident, $fixture:expr, $spelling:expr) => {
        #[test]
        fn $name() {
            let r = run($fixture);
            assert!(
                !r.stdout.contains("CANARY_BYPASS_SCANNED"),
                "the spelling {} bypassed the scope gate:\n{}",
                $spelling,
                r.dump()
            );
            assert_eq!(
                r.code,
                1,
                "the spelling {} must be refused or unresolvable, not scanned:\n{}",
                $spelling,
                r.dump()
            );
            assert_no_panic(&r);
        }
    };
}

bypass_test!(
    trailing_dot_spelling_does_not_bypass_scope,
    "bypass_trailing_dot.tl",
    "'127.0.0.1.'"
);
bypass_test!(
    hex_spelling_does_not_bypass_scope,
    "bypass_hex.tl",
    "'0x7f000001'"
);
bypass_test!(
    integer_spelling_does_not_bypass_scope,
    "bypass_decimal.tl",
    "'2130706433'"
);
bypass_test!(
    short_form_spelling_does_not_bypass_scope,
    "bypass_short_form.tl",
    "'127.1'"
);

/// `127.0.0.1:46520` is the allowlisted host with a port suffix. `split_host_path`
/// strips the port before matching, so the decision is made on the host — which
/// is correct only because the resolved address is the same host. The scan must
/// reach 127.0.0.1 and nothing else.
#[test]
fn port_suffix_reaches_only_the_allowlisted_host() {
    let r = run("bypass_port_suffix.tl");
    assert_eq!(
        r.code,
        0,
        "the allowlisted host with a port suffix must scan:\n{}",
        r.dump()
    );
    assert!(
        r.stdout.contains("closed=[46520]"),
        "the scan must have run against the allowlisted host on the named port:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// A hostname that IS in the register must scan — the control that proves the
/// three refusals above are about the spelling, not about every name failing.
#[test]
fn registered_hostname_scans() {
    let r = run("bypass_hostname_listed.tl");
    assert_eq!(
        r.code,
        0,
        "'localhost' is in the register and must be scannable:\n{}",
        r.dump()
    );
    assert!(
        r.stdout.contains("CANARY_HOST_LISTED"),
        "the registered hostname must return a result:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// A hostname that resolves (via /etc/hosts) to 127.0.1.1 — a loopback address,
/// but not the registered 127.0.0.1 — must be refused.
#[test]
fn unregistered_hostname_is_refused() {
    let r = run("bypass_hostname_unlisted.tl");
    assert_eq!(
        r.code,
        1,
        "an unregistered hostname must be refused:\n{}",
        r.dump()
    );
    assert!(
        r.stderr.contains("not authorized") && r.stderr.contains("scope:not-listed"),
        "the refusal must come from the register:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY_HOST_UNLISTED"),
        "the unregistered hostname returned a result:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// A hostname that does not resolve at all.
///
/// DOCUMENTED BEHAVIOUR (topology.rs module doc, and the task brief): "The scope
/// register is consulted before a packet is built." A DNS query is a packet. If
/// the register ran first, an unauthorized name would be refused as
/// `scope:not-listed` without the resolver ever being asked, and the refusal
/// would not depend on whether the name exists.
///
/// MEASURED BEHAVIOUR: every entry point calls `resolve_v4(&target)` *before*
/// `require_authorized(&target)`, so the failure for an unlisted, unresolvable
/// name is the resolver's error. That means a DNS query was emitted for a target
/// nobody authorized. This test documents the defect and stays failing.
#[test]
fn unresolvable_unlisted_target_is_refused_by_the_register_not_the_resolver() {
    let r = run("bypass_hostname_unresolvable.tl");
    assert_eq!(
        r.code,
        1,
        "an unresolvable target must still fail:\n{}",
        r.dump()
    );
    assert!(
        r.stderr.contains("scope:not-listed"),
        "the target is not in the register, so the register must be what refuses \
         it — before the resolver is consulted and a DNS query leaves the box. \
         The observed failure came from resolution instead:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY_UNRESOLVABLE_SCANNED"),
        "the unresolvable target returned a result:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

// ═══════════════════════════════════════════════════════════════════
// 5. Module-value dispatch — the P0 property
// ═══════════════════════════════════════════════════════════════════
//
// A module namespace is `Value::Module`, not a string. A hand-written tag must
// reach `call_method` on a `String` and refuse. If either of these dispatch, a
// program can reach the topology plane with no namespace in the source.

/// `"__module_topology__".connect_scan(..)` must not dispatch.
#[test]
fn literal_module_tag_does_not_dispatch() {
    let r = run("dispatch_literal_tag.tl");
    assert_ne!(
        r.code,
        0,
        "a hand-written module tag must not dispatch:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY_DISPATCH_LITERAL"),
        "the string tag dispatched into topology.connect_scan:\n{}",
        r.dump()
    );
    assert!(
        r.stderr.contains("unknown method") && r.stderr.contains("on String"),
        "the refusal must name the receiver as a String:\n{}",
        r.dump()
    );
}

/// The same tag carried through an explicitly `string`-typed binding and a
/// parameter must not dispatch either.
#[test]
fn typed_module_tag_does_not_dispatch() {
    let r = run("dispatch_typed_tag.tl");
    assert_ne!(
        r.code,
        0,
        "a string-typed module tag must not dispatch:\n{}",
        r.dump()
    );
    assert!(
        !r.stdout.contains("CANARY_DISPATCH_TYPED"),
        "the typed string tag dispatched into topology.connect_scan:\n{}",
        r.dump()
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. The declared surface must match the dispatch table
// ═══════════════════════════════════════════════════════════════════

/// `stdlib/topology.tl` declares `native fn parse_ports` as part of the public
/// surface. A declaration with no dispatch arm is a surface a caller can only
/// discover is missing at run time. This test asserts the declaration is real.
#[test]
fn declared_parse_ports_is_dispatched() {
    let r = run("surface_parse_ports.tl");
    assert_eq!(
        r.code,
        0,
        "stdlib/topology.tl declares `native fn parse_ports`, so the call must \
         dispatch:\n{}",
        r.dump()
    );
    assert!(
        r.stdout.contains("CANARY_PARSE_PORTS"),
        "declared parse_ports did not return:\n{}",
        r.dump()
    );
    assert_no_panic(&r);
}

/// Every function in the dispatch table must be declared in the manifest, and
/// every declaration must have a dispatch arm. The two lists are maintained by
/// hand, so the only way to keep them honest is to compare them.
#[test]
fn manifest_and_dispatch_table_agree() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        std::fs::read_to_string(root.join("stdlib/topology.tl")).expect("read stdlib/topology.tl");
    let dispatch_src = std::fs::read_to_string(root.join("src/stdlib/topology.rs"))
        .expect("read src/stdlib/topology.rs");

    let declared: Vec<String> = manifest
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("native fn ")?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() { None } else { Some(name) }
        })
        .collect();

    // The arms of `pub fn dispatch(..)`, between its signature and its end.
    let dispatch_body = dispatch_src
        .split("pub fn dispatch(function: &str")
        .nth(1)
        .expect("dispatch fn present")
        .split("\n}\n")
        .next()
        .expect("dispatch body");
    let dispatched: Vec<String> = dispatch_body
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix('"')?;
            let (name, _) = rest.split_once('"')?;
            if rest
                .split_once('"')
                .map(|r| r.1.trim_start().starts_with("=>"))
                .unwrap_or(false)
            {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect();

    let undeclared: Vec<&String> = dispatched
        .iter()
        .filter(|d| !declared.iter().any(|m| m == *d))
        .collect();
    let unimplemented: Vec<&String> = declared
        .iter()
        .filter(|m| !dispatched.iter().any(|d| d == *m))
        .collect();

    assert!(
        undeclared.is_empty(),
        "dispatched but not declared in stdlib/topology.tl: {undeclared:?}\n\
         declared: {declared:?}\ndispatched: {dispatched:?}"
    );
    assert!(
        unimplemented.is_empty(),
        "declared in stdlib/topology.tl but not dispatched: {unimplemented:?}\n\
         declared: {declared:?}\ndispatched: {dispatched:?}"
    );
}
