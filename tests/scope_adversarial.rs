//! Adversarial coverage for the scope gate itself: every test runs the real
//! `tallow` binary and asserts on exit status, stdout/stderr, or a bound TCP
//! listener — never on an internal function. (`scope_gate.rs` and
//! `topology_adversarial.rs` prove acceptance and scanner compliance; neither
//! attacks the gate.)
//!
//! Pinned contract: exit 0 = allowed, exit 2 = refused, refusals carry a
//! `scope:*` code on stderr; `--today` fixes the expiry clock. Tests that
//! measure a defect assert the doctrine's requirement and are left failing on
//! purpose, naming the measured deviation.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

const TODAY: &str = "2026-10-27";
const REGISTER_REL: &str = "configs/tallow/scope/authorized-hosts.toml";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scope_adversarial")
}

fn register(name: &str) -> String {
    fixtures()
        .join("registers")
        .join(name)
        .display()
        .to_string()
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn dump(&self) -> String {
        format!(
            "exit={}\n--- stdout ---\n{}--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Run `tallow scope <args>` from `cwd`; the cwd decides the default register.
fn scope_in(cwd: &PathBuf, args: &[&str]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("scope")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("could not run tallow scope {args:?}: {e}"));
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn check(reg: &str, target: &str) -> Out {
    let args = ["check", target, "--register", reg, "--today", TODAY];
    scope_in(&fixtures(), &args)
}

fn assert_allowed(o: &Out, what: &str) {
    assert_eq!(o.code, 0, "{what} must be allowed:\n{}", o.dump());
    assert!(
        o.stdout.contains("allowed:"),
        "{what}: no verdict:\n{}",
        o.dump()
    );
}

fn assert_refused(o: &Out, code: &str, what: &str) {
    assert_eq!(o.code, 2, "{what} must be refused (exit 2):\n{}", o.dump());
    assert!(
        o.stderr.contains(code),
        "{what} must carry {code}:\n{}",
        o.dump()
    );
    assert!(
        o.stdout.contains("refused:")
            && o.stderr.contains("refused:")
            && !o.stderr.contains("panicked"),
        "{what} must be a reasoned refusal, not a crash:\n{}",
        o.dump()
    );
}

/// Bind loopback before the child runs, non-blocking, so a connection attempt
/// is visible as a queued accept after the child exits.
fn watch(port: u16) -> TcpListener {
    let l = TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port} (port busy?): {e}"));
    l.set_nonblocking(true).expect("non-blocking listener");
    l
}

/// No register at all: every host refused, and the refusal names the register.
#[test]
fn absent_register_refuses_every_host_and_names_the_register() {
    let cwd = fixtures().join("no_register");
    for t in [
        "https://example.com/",
        "https://127.0.0.1/",
        "https://[::1]/",
    ] {
        let o = scope_in(&cwd, &["check", t, "--today", TODAY]);
        assert_refused(&o, "scope:register-unreadable", t);
        assert!(o.stderr.contains(REGISTER_REL), "{t}: unnamed register");
    }
}

/// The refusal precedes any socket. A listener is bound first: a queued accept
/// would prove a connection was attempted. Measured on the real egress path
/// (`topology.connect_scan`), not on `scope check`, which touches no network.
#[test]
fn absent_register_opens_no_socket() {
    let listener = watch(47101);
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--target", "x86_64-linux"])
        .arg(fixtures().join("connect_scan.tl"))
        .current_dir(fixtures().join("no_register"))
        .output()
        .expect("run tallow");
    let o = Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    assert_eq!(o.code, 1, "a refused scan must exit 1:\n{}", o.dump());
    assert!(
        o.stderr.contains("scope:register-unreadable") && o.stderr.contains(REGISTER_REL),
        "the scan must be refused by the register, naming it:\n{}",
        o.dump()
    );
    assert!(!o.stdout.contains("CANARY_SCAN_RETURNED"), "call returned");
    assert!(
        matches!(listener.accept(), Err(ref e) if e.kind() == ErrorKind::WouldBlock),
        "a refused scan must not have opened a connection to the listener"
    );
}

/// Table over the three shapes a loader must reject outright.
#[test]
fn unparseable_registers_refuse_everything() {
    let cases = [
        ("invalid_toml.toml", "https://example.com/", "malformed"),
        (
            "missing_field.toml",
            "https://unattributed.example/",
            "granted_by",
        ),
        ("unknown_basis.toml", "https://vibes.example/", "vibes"),
    ];
    for (file, target, needle) in cases {
        let o = check(&register(file), target);
        assert_refused(&o, "scope:register-malformed", file);
        assert!(o.stderr.contains(needle), "{file}: must name {needle}");
    }
}

/// Doctrine: an unparseable `expires_at` makes the file not-a-register.
/// MEASURED: `expires_at` is `Option<String>` compared lexicographically, so
/// "soon" loads, never compares greater than a real date, and the grant never
/// lapses; `scope verify` even calls the register sound. Defect — fails on
/// purpose.
#[test]
fn unparseable_expiry_does_not_load_the_register() {
    let reg = register("unparseable_expiry.toml");
    let bad = check(&reg, "https://unparseable-expiry.example/");
    assert_refused(&bad, "scope:register-malformed", "unparseable expires_at");
    let sibling = check(&reg, "https://neighbour.example/");
    assert_refused(
        &sibling,
        "scope:register-malformed",
        "sibling (partial load)",
    );
}

/// An evidence-less written-consent entry must not authorise its host, and the
/// register it sits in is a defective artifact.
/// MEASURED before the fix: the host was refused `scope:evidence-missing` (the
/// security half held) but the file still loaded and its honoured neighbours
/// were authorised around it, so `check` and `verify` disagreed about the same
/// file. After the fix the defective entry invalidates the register: both the
/// assertion and its sound neighbour are refused `scope:register-malformed`,
/// and the message names the entry and the missing pointer.
#[test]
fn written_consent_without_evidence_does_not_load_the_register() {
    let reg = register("written_consent_no_evidence.toml");
    let asserted = check(&reg, "https://asserted.example/");
    assert_refused(
        &asserted,
        "scope:register-malformed",
        "evidence-less consent (register refused whole)",
    );
    assert!(
        asserted.stderr.contains("carries no evidence pointer"),
        "the refusal must name the missing pointer, not just say malformed:\n{}",
        asserted.dump()
    );
    let sibling = check(&reg, "https://neighbour.example/");
    assert_refused(
        &sibling,
        "scope:register-malformed",
        "sibling (partial load)",
    );
}

/// Documented rule: valid on the expiry date, lapsed the day after.
/// Measured: the code agrees exactly at every boundary.
#[test]
fn expiry_lapses_the_day_after_the_expiry_date() {
    let reg = register("expiry.toml");
    let yesterday = check(&reg, "https://expired-yesterday.example/");
    assert_refused(&yesterday, "scope:expired", "grant expiring yesterday");
    assert_allowed(
        &check(&reg, "https://expires-today.example/"),
        "expiring today",
    );
    assert_allowed(
        &check(&reg, "https://expires-tomorrow.example/"),
        "expiring tomorrow",
    );
    // The same entry one day later is refused: the boundary is the day.
    let later = scope_in(
        &fixtures(),
        &[
            "check",
            "https://expires-today.example/",
            "--register",
            reg.as_str(),
            "--today",
            "2026-10-28",
        ],
    );
    assert_refused(&later, "scope:expired", "grant one day past expiry");
    assert!(later.stderr.contains("2026-10-27"), "lapsed date unnamed");
}

#[test]
fn wildcard_covers_subdomains_but_not_apex_or_lookalikes() {
    let reg = register("main.toml");
    assert_allowed(&check(&reg, "https://a.wild.example/"), "subdomain");
    let refused = [
        "https://wild.example/",
        "https://badexample.com/",
        "https://a.example.com.evil.test/",
    ];
    for t in refused {
        let o = check(&reg, t);
        assert_refused(&o, "scope:not-listed", t);
    }
}

/// A well-formed port suffix is stripped; the decision is made on the host key.
#[test]
fn port_suffix_resolves_to_the_host_key() {
    let reg = register("main.toml");
    for t in [
        "https://example.com:443/",
        "http://[::1]:443/",
        "example.com:443",
    ] {
        assert_allowed(&check(&reg, t), t);
    }
}

/// A port that is not a port must be refused as malformed.
/// MEASURED: `host_key` cuts at the first `:`, so `example.com:notaport` and
/// `example.com:99999` both become `example.com` and are ALLOWED — the gate
/// reports an allow for a target the operator never spelled. Defect — fails on
/// purpose.
#[test]
fn malformed_port_suffix_is_refused_not_silently_stripped() {
    let reg = register("main.toml");
    for t in [
        "https://example.com:notaport/",
        "https://example.com:99999/",
    ] {
        let o = check(&reg, t);
        assert_refused(&o, "scope:host-malformed", t);
    }
}

/// DNS: names are case-insensitive and `example.com.` is the same FQDN, so both
/// spellings must reach the same decision.
/// MEASURED: `Example.COM` is allowed (both sides lowercased), `example.com.`
/// is refused as `not-listed`. Fail-closed, so no bypass, but one name gets two
/// answers and no register can express the dotted form without a second entry.
/// Defect — fails on purpose.
#[test]
fn case_and_trailing_dot_reach_the_same_decision() {
    let reg = register("main.toml");
    let upper = check(&reg, "https://Example.COM/");
    let dotted = check(&reg, "https://example.com./");
    assert_allowed(&upper, "upper-case spelling of a granted host");
    assert_eq!(
        dotted.code,
        upper.code,
        "Example.COM (exit {}) and example.com. (exit {}) are one host:\n{}",
        upper.code,
        dotted.code,
        dotted.dump()
    );
}

#[test]
fn ipv6_lookalike_addresses_are_not_authorised() {
    let reg = register("main.toml");
    assert_allowed(&check(&reg, "https://2001:db8::1/"), "granted literal");
    let look = check(&reg, "https://2001:db8::10/");
    assert_refused(&look, "scope:not-listed", "2001:db8::10 lookalike");
}

/// RFC 3986: `[::1]` in a grant and bare `::1` in a target name the same host.
/// MEASURED: the register key is the literal entry text, so `[::1]` is stored
/// with brackets and never equals a host key — a bracketed grant authorises
/// nothing, not even the bracketed spelling. Defect — fails on purpose.
#[test]
fn bracketed_grant_authorises_the_bare_literal() {
    let reg = register("bracketed_v6_only.toml");
    assert_allowed(&check(&reg, "https://[::1]/"), "bracketed target");
    assert_allowed(&check(&reg, "https://::1/"), "bare target");
}

/// `evidence` is checked for presence, never dereferenced: a traversal value
/// must not read a file or leak its contents, and a FIFO used as evidence must
/// not block the decision.
#[test]
fn evidence_pointer_is_never_dereferenced() {
    let root = std::env::temp_dir().join(format!("tallow-scope-ev-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cwd = root.join("a/b");
    let scope_dir = cwd.join("configs/tallow/scope");
    std::fs::create_dir_all(&scope_dir).expect("mkdir register");
    std::fs::create_dir_all(root.join("secret")).expect("mkdir secret");
    let canary = root.join("secret/canary.txt");
    std::fs::write(canary, "CANARY_EVIDENCE_BODY_9f3a\n").expect("canary");
    let fifo = root.join("secret/fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo")
            .success(),
        "could not create the FIFO evidence target"
    );
    let write_register = |evidence: &str| {
        let body = format!(
            "[[authorized]]\nhost = \"consented.example\"\nbasis = \"written-consent\"\n\
             granted_by = \"owner\"\ngranted_at = \"2026-01-01\"\n\
             expires_at = \"2027-01-01\"\nevidence = \"{evidence}\"\n"
        );
        std::fs::write(scope_dir.join("authorized-hosts.toml"), body).expect("write register");
    };
    let ask = |label: &str| {
        let o = scope_in(
            &cwd,
            &["check", "https://consented.example/", "--today", TODAY],
        );
        assert!(matches!(o.code, 0 | 2), "{label}: crashed:\n{}", o.dump());
        let all = format!("{}\n{}", o.stdout, o.stderr);
        assert!(
            !all.contains("CANARY_EVIDENCE_BODY_9f3a") && !all.contains("root:x:0:0"),
            "{label}: evidence contents leaked into the output:\n{}",
            o.dump()
        );
    };

    write_register("../../etc/passwd");
    ask("the brief's literal traversal");
    write_register("../../secret/canary.txt");
    ask("a traversal reaching a real file");

    // Opening this FIFO for read with no writer blocks forever; a gate that
    // treats evidence as a string returns immediately. `timeout` exits 124 if
    // the child is still blocked after 5s.
    write_register("../../secret/fifo");
    let blocked = Command::new("timeout")
        .arg("5")
        .arg(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "scope",
            "check",
            "https://consented.example/",
            "--today",
            TODAY,
        ])
        .current_dir(&cwd)
        .output()
        .expect("run timeout");
    assert_eq!(
        blocked.status.code(),
        Some(0),
        "exit 124 means the gate opened an unread FIFO and blocked on it"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Two grants for one host have no defensible winner, so the register is
/// refused whole. Measured: neither wins (deliberate — `load` documents
/// "Duplicate hosts are a register defect, not a merge."), the sound sibling is
/// refused too, and case-insensitive duplicates are caught.
#[test]
fn duplicate_host_refuses_the_whole_register() {
    let reg = register("duplicate_host.toml");
    let o = check(&reg, "https://neighbour.example/");
    assert_refused(&o, "scope:register-malformed", "duplicate-host register");
    assert!(
        o.stderr.contains("appears more than once"),
        "defect unnamed"
    );
    let dup = check(&reg, "https://twice.example/");
    assert_refused(&dup, "scope:register-malformed", "duplicated host");
}

/// The doctrine clause is enforced in code, not by the register, so it holds on
/// every basis. Each host is authorised on its own basis by `bases.toml` (the
/// control), so a refusal below cannot be "the host was never listed".
#[test]
fn authentication_paths_are_refused_on_every_basis() {
    let reg = register("bases.toml");
    for host in [
        "own.example",
        "consent.example",
        "self.example",
        "public.example",
    ] {
        assert_allowed(&check(&reg, &format!("https://{host}/")), host);
        for path in ["/login", "/account", "/admin", "/api/keys"] {
            let t = format!("https://{host}{path}");
            let o = check(&reg, &t);
            assert_refused(&o, "scope:authentication-surface", &t);
        }
    }
}
