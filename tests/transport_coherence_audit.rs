//! Runtime fingerprint-audit harness — non-browser TLS/QUIC client stacks
//! (matrix row #5 / ag03 R-2 / U-102).
//!
//! Feeds the *real* client configurations tallow-net builds — captured offline
//! as rustls ClientHellos via `transport::tls_cohort::ja4_cohort_v1` (no
//! network, no sockets) — through `ClientStackValidator`, and pins both sides
//! of the audit:
//!
//! * coherent detection — the live TCP and QUIC cohorts match the declared
//!   `JA4_COHORT_V1` relay-client profiles with zero warnings;
//! * incoherent detection — injected drift (TLS version, cipher suite, curve,
//!   sigalg, ALPN, cohort id, QUIC transport parameters, transport mislabel)
//!   is caught with the right warning vectors.
//!
//! The declared profiles themselves are cross-checked against the pinned
//! snapshot constants (`JA4_COHORT_V1_TCP` / `JA4_COHORT_V1_QUIC`) so a
//! re-pin cannot silently diverge from this declaration.

use tallow::browser::fingerprint_coherence::{
    ClientStackValidator, ClientTransport, CoherenceReport, CoherenceValidator,
    DeclaredClientProfile, QuicTransportParams, TlsClientObservation,
};
use tallow_net::transport::tls_cohort::{self, Ja4Transport};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tcp_observation() -> TlsClientObservation {
    let cohort = tls_cohort::ja4_cohort_v1(Ja4Transport::Tcp).expect("TCP cohort capture");
    TlsClientObservation::from_cohort(&cohort, ClientTransport::TcpTls)
}

fn quic_observation() -> TlsClientObservation {
    let cohort = tls_cohort::ja4_cohort_v1(Ja4Transport::Quic).expect("QUIC cohort capture");
    TlsClientObservation::from_cohort(&cohort, ClientTransport::Quic)
}

fn has_vector(report: &CoherenceReport, vector: &str) -> bool {
    report.warnings.iter().any(|w| w.vectors.contains(&vector))
}

/// Extract one `key=value` line from a pinned cohort render.
fn pinned_line(render: &str, key: &str) -> String {
    render
        .lines()
        .find_map(|l| l.strip_prefix(&(key.to_string() + "=")))
        .unwrap_or_else(|| panic!("pinned render has no '{}' line", key))
        .to_string()
}

/// Parse a `0x…,0x…` hex u16 list (empty / `(none)` → empty vec).
fn parse_hex_u16s(s: &str) -> Vec<u16> {
    if s.is_empty() || s == "(none)" {
        return Vec::new();
    }
    s.split(',')
        .map(|p| {
            u16::from_str_radix(p.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("bad hex u16 '{}'", p))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Coherent detection — real client configs vs the declared profile
// ---------------------------------------------------------------------------

/// The live capture is exactly what the pinned constants claim.
#[test]
fn live_capture_matches_pinned_cohort_snapshot_constants() {
    let tcp = tls_cohort::ja4_cohort_v1(Ja4Transport::Tcp).expect("TCP capture");
    assert_eq!(
        tcp.render(),
        tls_cohort::JA4_COHORT_V1_TCP,
        "TCP client config drifted from the pinned JA4_COHORT_V1 snapshot"
    );
    let quic = tls_cohort::ja4_cohort_v1(Ja4Transport::Quic).expect("QUIC capture");
    assert_eq!(
        quic.render(),
        tls_cohort::JA4_COHORT_V1_QUIC,
        "QUIC client config drifted from the pinned JA4_COHORT_V1 snapshot"
    );
}

/// Declared profiles track the pinned constants (extension set + curves), so
/// the audit cannot silently diverge from `JA4_COHORT_V1`.
#[test]
fn declared_profiles_track_pinned_cohort_constants() {
    let tcp_exts = parse_hex_u16s(&pinned_line(tls_cohort::JA4_COHORT_V1_TCP, "extensions"));
    assert_eq!(
        DeclaredClientProfile::tallow_relay_tcp().expected_extensions,
        tcp_exts,
        "TCP declared extension set must track JA4_COHORT_V1_TCP"
    );

    let quic_exts = parse_hex_u16s(&pinned_line(tls_cohort::JA4_COHORT_V1_QUIC, "extensions"));
    assert_eq!(
        DeclaredClientProfile::tallow_relay_quic().expected_extensions,
        quic_exts,
        "QUIC declared extension set must track JA4_COHORT_V1_QUIC"
    );

    for (render, declared) in [
        (
            tls_cohort::JA4_COHORT_V1_TCP,
            DeclaredClientProfile::tallow_relay_tcp(),
        ),
        (
            tls_cohort::JA4_COHORT_V1_QUIC,
            DeclaredClientProfile::tallow_relay_quic(),
        ),
    ] {
        let groups = parse_hex_u16s(&pinned_line(render, "groups"));
        for g in &declared.required_groups {
            assert!(
                groups.contains(g),
                "declared required group 0x{:04x} is not in the pinned cohort groups {:?}",
                g,
                groups
            );
        }
        assert_eq!(
            parse_hex_u16s(&pinned_line(render, "ciphers"))
                .iter()
                .filter(|c| (0x1301..=0x1305).contains(*c))
                .count(),
            declared.min_tls13_ciphers,
            "declared TLS 1.3 cipher minimum must match the pinned cohort"
        );
    }
}

/// Real TCP+TLS client config → declared relay profile: fully coherent.
#[test]
fn real_tcp_client_config_is_coherent_with_declared_profile() {
    let declared = DeclaredClientProfile::tallow_relay_tcp();
    let report =
        CoherenceValidator::audit_tallow_client(&declared, None).expect("TCP cohort capture");

    assert_eq!(report.critical_count, 0, "{:?}", report.warnings);
    assert_eq!(report.warning_count, 0, "{:?}", report.warnings);
    assert_eq!(report.info_count, 0, "{:?}", report.warnings);
    assert_eq!(report.score, 1.0);

    // The same observation passes through the sibling validator directly.
    let report = ClientStackValidator::validate(&declared, &tcp_observation());
    assert!(report.is_safe());
    assert_eq!(report.score, 1.0);
}

/// Real QUIC client config + its declared transport parameters: coherent.
#[test]
fn real_quic_client_config_is_coherent_with_declared_profile() {
    let declared = DeclaredClientProfile::tallow_relay_quic();
    let params = QuicTransportParams::tallow_relay_client(); // idle 300 s / keep-alive 15 s
    let report = CoherenceValidator::audit_tallow_client(&declared, Some(params))
        .expect("QUIC cohort capture");

    assert_eq!(report.critical_count, 0, "{:?}", report.warnings);
    assert_eq!(report.warning_count, 0, "{:?}", report.warnings);
    assert_eq!(report.info_count, 0, "{:?}", report.warnings);
    assert_eq!(report.score, 1.0);

    // QUIC carries the transport_parameters extension; TCP must not.
    let quic = quic_observation();
    assert!(quic.extensions.contains(&0x0039));
    assert!(!tcp_observation().extensions.contains(&0x0039));
}

// ---------------------------------------------------------------------------
// Incoherent detection — drift injected into the *real* captures
// ---------------------------------------------------------------------------

#[test]
fn quic_capture_with_tls12_suite_is_critical() {
    let declared = DeclaredClientProfile::tallow_relay_quic();
    let mut obs = quic_observation().with_quic_params(QuicTransportParams::tallow_relay_client());
    obs.ciphers.push(0xc02c); // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 — TCP-only

    let report = ClientStackValidator::validate(&declared, &obs);
    assert!(report.critical_count >= 1, "{:?}", report.warnings);
    assert!(has_vector(&report, "tls_cipher_suites"));
    assert!(has_vector(&report, "quic"));
    assert!(!report.is_safe());
    assert!(report.score < 1.0);
}

#[test]
fn dropped_tls13_offer_is_critical() {
    let declared = DeclaredClientProfile::tallow_relay_quic();
    let mut obs = quic_observation().with_quic_params(QuicTransportParams::tallow_relay_client());
    obs.tls13_offered = false;

    let report = ClientStackValidator::validate(&declared, &obs);
    assert!(report.critical_count >= 1, "{:?}", report.warnings);
    assert!(has_vector(&report, "tls_version"));
}

#[test]
fn curve_and_sigalg_drift_in_real_capture_are_warnings() {
    let declared = DeclaredClientProfile::tallow_relay_tcp();

    let mut obs = tcp_observation();
    obs.groups.retain(|g| *g != 0x001d); // drop x25519
    obs.key_share_groups.clear();
    let report = ClientStackValidator::validate(&declared, &obs);
    assert_eq!(report.critical_count, 0, "{:?}", report.warnings);
    assert!(has_vector(&report, "tls_groups"));
    assert!(has_vector(&report, "declared_profile"));

    let mut obs = tcp_observation();
    obs.sigalgs.push(0x0201); // rsa_pkcs1_sha1
    let report = ClientStackValidator::validate(&declared, &obs);
    assert!(has_vector(&report, "legacy_sigalg"), "{:?}", report.warnings);
}

#[test]
fn alpn_and_cohort_drift_in_real_capture_are_warnings() {
    let declared = DeclaredClientProfile::tallow_relay_tcp();

    let mut obs = tcp_observation();
    obs.alpn.push("h2".to_string()); // declared: no ALPN offered
    let report = ClientStackValidator::validate(&declared, &obs);
    assert!(has_vector(&report, "alpn"), "{:?}", report.warnings);

    let mut obs = tcp_observation();
    obs.cohort = "JA4_COHORT_V0".to_string();
    let report = ClientStackValidator::validate(&declared, &obs);
    assert!(has_vector(&report, "tls_cohort"), "{:?}", report.warnings);
}

#[test]
fn quic_transport_param_drift_is_detected_against_declared() {
    let declared = DeclaredClientProfile::tallow_relay_quic();

    // quinn's own defaults (30 s idle, no keep-alive) instead of 300 s / 15 s.
    let mut obs = quic_observation().with_quic_params(QuicTransportParams {
        max_idle_timeout_secs: Some(30),
        keep_alive_interval_secs: None,
    });
    let report = ClientStackValidator::validate(&declared, &obs);
    assert_eq!(report.critical_count, 0, "{:?}", report.warnings);
    assert_eq!(
        report
            .warnings
            .iter()
            .filter(|w| w.vectors.contains(&"quic_transport_params"))
            .count(),
        2,
        "{:?}",
        report.warnings
    );

    // Keep-alive that would never fire before the idle timeout.
    obs.quic_params = Some(QuicTransportParams {
        max_idle_timeout_secs: Some(300),
        keep_alive_interval_secs: Some(600),
    });
    let report = ClientStackValidator::validate(&declared, &obs);
    assert!(has_vector(&report, "quic_transport_params"));

    // Not captured (e.g. quic feature not compiled in the caller) → Info, so
    // the audit reports "unverified" instead of silently passing.
    obs.quic_params = None;
    let report = ClientStackValidator::validate(&declared, &obs);
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.warning_count, 0, "{:?}", report.warnings);
    assert_eq!(report.info_count, 1, "{:?}", report.warnings);
    assert!(has_vector(&report, "quic_transport_params"));
}

#[test]
fn transport_label_mismatch_is_critical() {
    let declared = DeclaredClientProfile::tallow_relay_quic();
    let tcp = tcp_observation(); // captured from the TCP stack, declared QUIC

    let report = ClientStackValidator::validate(&declared, &tcp);
    assert!(report.critical_count >= 1, "{:?}", report.warnings);
    assert!(has_vector(&report, "transport"));
}

/// Full-stack runtime audit: the browser identity and the non-browser client
/// stack are audited separately and merged into one report.
#[test]
fn full_stack_audit_merges_browser_and_client_stack() {
    let geo = tallow::browser::fingerprint_coherence::GeoContext::us_residential(
        "Houston",
        "Texas",
        "America/Chicago",
    );
    let profile = CoherenceValidator::generate_coherent_profile(&geo);

    // Coherent browser + drifted client stack.
    let mut obs = quic_observation().with_quic_params(QuicTransportParams::tallow_relay_client());
    obs.cohort = "JA4_COHORT_V0".to_string();
    let report = CoherenceValidator::validate_with_client_stack(
        &profile,
        &geo,
        Some(tallow::browser::fingerprint_coherence::TlsBrowser::Chrome),
        &DeclaredClientProfile::tallow_relay_quic(),
        &obs,
    );
    assert!(report.is_safe(), "browser side stays coherent: {:?}", report.warnings);
    assert!(has_vector(&report, "tls_cohort"));

    // Incoherent browser (Firefox TLS vs Chrome profile) + drifted stack.
    let report = CoherenceValidator::validate_with_client_stack(
        &profile,
        &geo,
        Some(tallow::browser::fingerprint_coherence::TlsBrowser::Firefox),
        &DeclaredClientProfile::tallow_relay_quic(),
        &obs,
    );
    assert!(!report.is_safe());
    assert!(has_vector(&report, "tls_fingerprint"));
    assert!(has_vector(&report, "tls_cohort"));
}
