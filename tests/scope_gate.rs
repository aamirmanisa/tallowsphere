//! Scope-gate acceptance tests.
//!
//! Why this file exists: the gate's whole value is that it says *no* by default
//! and says why. A unit test can pin the decision function; only a test against
//! a real register file pins the loader, the fail-closed paths, and the shipped
//! artifact that the engine actually reads at runtime.
//!
//! The last test is the one that matters most: it asserts the doctrine's hard
//! clause — no basis authorizes an authentication surface — against every basis
//! the type system can express. If someone later adds a `Basis` variant that
//! should have this property, the exhaustive match in that test fails to
//! compile, which is the intended alarm.

use std::fs;
use std::path::PathBuf;
use tallow::scope::{Basis, Decision, Refusal, ScopeRegister, DEFAULT_REGISTER_PATH};

fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tallow-scope-acceptance-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).expect("create temp dir");
    d
}

const FIXTURE: &str = r#"
[[authorized]]
host = "owned.example"
basis = "ownership"
granted_by = "operator"
granted_at = "2026-01-01"
expires_at = "2027-01-01"
methods = ["GET", "HEAD"]
notes = "the operator's own domain"

[[authorized]]
host = "lapsed.example"
basis = "ownership"
granted_by = "operator"
granted_at = "2025-01-01"
expires_at = "2026-01-01"

[[authorized]]
host = "asserted.example"
basis = "written-consent"
granted_by = "operator"
granted_at = "2026-01-01"
expires_at = "2027-01-01"

[[authorized]]
host = "*.wild.example"
basis = "ownership"
granted_by = "operator"
granted_at = "2026-01-01"
expires_at = "2027-01-01"

[[authorized]]
host = "public.example"
basis = "public-read-only"
granted_by = "published for machine retrieval"
granted_at = "2026-01-01"
expires_at = "2027-01-01"
evidence = "https://public.example/robots.txt"
"#;

const T: &str = "2026-10-16";

#[test]
fn a_listed_host_is_allowed_and_carries_its_basis() {
    let d = tmp_dir("listed");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);
    assert_eq!(r.load_failure(), None, "fixture must load cleanly");

    let decision = r.authorize("https://owned.example/pricing", "GET", T);
    assert!(decision.is_allowed(), "{}", decision.render());
    match decision {
        Decision::Allowed(e) => {
            assert_eq!(e.basis, Basis::Ownership);
            assert_eq!(e.granted_by, "operator");
        }
        Decision::Refused(r) => panic!("expected allowed, got {}", r.explain()),
    }
}

#[test]
fn an_unlisted_host_is_refused() {
    let d = tmp_dir("unlisted");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);
    let decision = r.authorize("https://stranger.example/", "GET", T);
    assert_eq!(
        decision.refusal(),
        Some(&Refusal::NotListed {
            host: "stranger.example".to_string()
        })
    );
}

#[test]
fn a_lapsed_grant_is_refused_and_the_reason_names_the_date() {
    let d = tmp_dir("lapsed");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);
    let decision = r.authorize("https://lapsed.example/", "GET", T);
    match decision.refusal() {
        Some(Refusal::Expired {
            expires_at, today, ..
        }) => {
            assert_eq!(expires_at, "2026-01-01");
            assert_eq!(today, T);
        }
        other => panic!("expected an expiry refusal, got {other:?}"),
    }
}

#[test]
fn written_consent_without_evidence_is_refused() {
    let d = tmp_dir("evidence");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);
    let decision = r.authorize("https://asserted.example/", "GET", T);
    assert!(
        matches!(decision.refusal(), Some(Refusal::EvidenceMissing { .. })),
        "an assertion without an evidence pointer is not a grant: {}",
        decision.render()
    );
}

#[test]
fn a_wildcard_covers_subdomains_and_not_the_apex() {
    let d = tmp_dir("wildcard");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);

    assert!(r.authorize("https://a.wild.example/", "GET", T).is_allowed());
    assert!(r
        .authorize("https://deep.a.wild.example/", "GET", T)
        .is_allowed());
    // The apex is a different owner until proven otherwise.
    assert!(matches!(
        r.authorize("https://wild.example/", "GET", T).refusal(),
        Some(Refusal::NotListed { .. })
    ));
    // And a lookalike suffix is not a match.
    assert!(matches!(
        r.authorize("https://notwild.example/", "GET", T).refusal(),
        Some(Refusal::NotListed { .. })
    ));
}

#[test]
fn the_doctrine_clause_holds_for_every_basis() {
    // Exhaustive over the variants the type system can express: adding a new
    // Basis forces this match to be updated, which is the point.
    let all_bases = [
        Basis::Ownership,
        Basis::WrittenConsent,
        Basis::SelfHosted,
        Basis::PublicReadOnly,
    ];
    let d = tmp_dir("doctrine");
    for (i, basis) in all_bases.into_iter().enumerate() {
        let name = basis.as_str();
        let register = format!(
            r#"
[[authorized]]
host = "basis{i}.example"
basis = "{name}"
granted_by = "operator"
granted_at = "2026-01-01"
expires_at = "2027-01-01"
evidence = "docs/consent/{name}.txt"
"#
        );
        let p = d.join(format!("register-{i}.toml"));
        fs::write(&p, register).expect("write register");
        let r = ScopeRegister::load(&p);
        assert_eq!(r.load_failure(), None, "basis {name} register must load");

        for path in [
            "/login",
            "/account/orders",
            "/api/v1/tokens",
            "/admin/settings",
            "/password/reset",
        ] {
            let url = format!("https://basis{i}.example{path}");
            let decision = r.authorize(&url, "GET", T);
            assert!(
                matches!(
                    decision.refusal(),
                    Some(Refusal::AuthenticationSurface { .. })
                ),
                "basis {name} must not authorize {path}: {}",
                decision.render()
            );
        }
    }
}

#[test]
fn credentials_embedded_in_a_url_are_refused() {
    let d = tmp_dir("credurl");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);
    let decision = r.authorize("https://user:secret@owned.example/", "GET", T);
    assert!(
        matches!(decision.refusal(), Some(Refusal::AuthenticationSurface { .. })),
        "a credential in the target URL is refused on sight: {}",
        decision.render()
    );
}

#[test]
fn a_write_method_is_outside_a_read_only_grant() {
    let d = tmp_dir("methods");
    let p = d.join("register.toml");
    fs::write(&p, FIXTURE).expect("write register");
    let r = ScopeRegister::load(&p);
    assert!(r.authorize("https://owned.example/", "GET", T).is_allowed());
    assert!(r.authorize("https://owned.example/", "HEAD", T).is_allowed());
    assert!(matches!(
        r.authorize("https://owned.example/", "POST", T).refusal(),
        Some(Refusal::MethodNotAllowed { .. })
    ));
}

#[test]
fn a_missing_register_refuses_everything() {
    let missing = tmp_dir("missing").join("does-not-exist.toml");
    let r = ScopeRegister::load(&missing);
    assert!(matches!(
        r.load_failure(),
        Some(Refusal::RegisterUnreadable { .. })
    ));
    assert!(!r.authorize("https://owned.example/", "GET", T).is_allowed());
}

#[test]
fn a_malformed_register_refuses_everything() {
    let d = tmp_dir("malformed");
    let p = d.join("register.toml");
    fs::write(&p, "authorized = [ this is not toml").expect("write register");
    let r = ScopeRegister::load(&p);
    assert!(matches!(
        r.load_failure(),
        Some(Refusal::RegisterMalformed { .. })
    ));
    assert!(!r.authorize("https://owned.example/", "GET", T).is_allowed());
}

#[test]
fn a_duplicate_host_is_a_register_defect_not_a_merge() {
    let d = tmp_dir("duplicate");
    let p = d.join("register.toml");
    fs::write(
        &p,
        r#"
[[authorized]]
host = "twice.example"
basis = "ownership"
granted_by = "operator"
granted_at = "2026-01-01"

[[authorized]]
host = "TWICE.example"
basis = "public-read-only"
granted_by = "someone else"
granted_at = "2026-01-01"
"#,
    )
    .expect("write register");
    let r = ScopeRegister::load(&p);
    assert!(
        matches!(r.load_failure(), Some(Refusal::RegisterMalformed { .. })),
        "two grants for one host is ambiguous; the register must refuse rather than pick"
    );
}

#[test]
fn an_empty_register_is_valid_and_authorizes_nothing() {
    let d = tmp_dir("empty");
    let p = d.join("register.toml");
    fs::write(&p, "# no entries yet\n").expect("write register");
    let r = ScopeRegister::load(&p);
    assert_eq!(
        r.load_failure(),
        None,
        "an empty register is a valid register with zero grants"
    );
    assert_eq!(r.len(), 0);
    assert!(matches!(
        r.authorize("https://owned.example/", "GET", T).refusal(),
        Some(Refusal::NotListed { .. })
    ));
}

#[test]
fn the_shipped_register_parses_and_is_deny_by_default() {
    // Pins the artifact the engine reads at runtime, not just a fixture.
    let r = ScopeRegister::load(DEFAULT_REGISTER_PATH);
    assert_eq!(
        r.load_failure(),
        None,
        "the shipped register at {DEFAULT_REGISTER_PATH} must parse"
    );
    assert!(
        !r.is_empty(),
        "the shipped register should seed at least loopback and the test host"
    );
    // Seeded targets work...
    assert!(r.authorize("http://127.0.0.1:8080/health", "GET", T).is_allowed());
    assert!(r.authorize("https://example.com/", "GET", T).is_allowed());
    // ...and everything else is refused by default.
    assert!(matches!(
        r.authorize("https://random-store.example/product/1", "GET", T).refusal(),
        Some(Refusal::NotListed { .. })
    ));
    // Including an authentication surface on a seeded host.
    assert!(matches!(
        r.authorize("https://example.com/login", "GET", T).refusal(),
        Some(Refusal::AuthenticationSurface { .. })
    ));
}
