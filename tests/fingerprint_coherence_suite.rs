//! Fingerprint-coherence integration suite (G9 §6 verification / §7 observability).
//!
//! End-to-end assertion of the full Tallow identity stack for representative
//! network contexts: `generate_coherent_profile(geo)` → `CoherenceValidator::validate`
//! must produce a `CoherenceReport` whose 8 coherence pairs are all consistent,
//! with `is_safe()` true and a Panopticlick/BrowserScan-style `score` pinned to
//! exactly 1.0 (stable 0..1 baseline).

use tallow::browser::fingerprint_coherence::{CoherenceValidator, GeoContext, TlsBrowser};

// ---------------------------------------------------------------------------
// Representative GeoContexts (residential / coherent)
// ---------------------------------------------------------------------------

fn us_houston_geo() -> GeoContext {
    GeoContext::us_residential("Houston", "Texas", "America/Chicago")
}

fn gb_london_geo() -> GeoContext {
    GeoContext {
        ip: "51.36.10.1".to_string(),
        country_code: "GB".to_string(),
        region: "England".to_string(),
        city: "London".to_string(),
        timezone: "Europe/London".to_string(),
        latitude: 51.5074,
        longitude: -0.1278,
        asn: 12576,
        asn_org: "EE Limited".to_string(),
        is_datacenter: false,
        is_residential: true,
        is_mobile: false,
    }
}

fn de_munich_geo() -> GeoContext {
    GeoContext {
        ip: "85.212.10.1".to_string(),
        country_code: "DE".to_string(),
        region: "Bavaria".to_string(),
        city: "Munich".to_string(),
        timezone: "Europe/Berlin".to_string(),
        latitude: 48.1351,
        longitude: 11.5820,
        asn: 3209,
        asn_org: "Vodafone Germany".to_string(),
        is_datacenter: false,
        is_residential: true,
        is_mobile: false,
    }
}

fn jp_tokyo_geo() -> GeoContext {
    GeoContext {
        ip: "126.100.50.1".to_string(),
        country_code: "JP".to_string(),
        region: "Tokyo".to_string(),
        city: "Tokyo".to_string(),
        timezone: "Asia/Tokyo".to_string(),
        latitude: 35.6762,
        longitude: 139.6503,
        asn: 4713,
        asn_org: "NTT Communications".to_string(),
        is_datacenter: false,
        is_residential: true,
        is_mobile: false,
    }
}

fn br_saopaulo_geo() -> GeoContext {
    GeoContext {
        ip: "177.55.10.1".to_string(),
        country_code: "BR".to_string(),
        region: "Sao Paulo".to_string(),
        city: "Sao Paulo".to_string(),
        timezone: "America/Sao_Paulo".to_string(),
        latitude: -23.5505,
        longitude: -46.6333,
        asn: 27699,
        asn_org: "Telefonica Brasil S.A.".to_string(),
        is_datacenter: false,
        is_residential: true,
        is_mobile: false,
    }
}

fn au_sydney_geo() -> GeoContext {
    GeoContext {
        ip: "139.130.10.1".to_string(),
        country_code: "AU".to_string(),
        region: "New South Wales".to_string(),
        city: "Sydney".to_string(),
        timezone: "Australia/Sydney".to_string(),
        latitude: -33.8688,
        longitude: 151.2093,
        asn: 1221,
        asn_org: "Telstra".to_string(),
        is_datacenter: false,
        is_residential: true,
        is_mobile: false,
    }
}

fn us_mobile_geo() -> GeoContext {
    GeoContext {
        ip: "100.200.50.1".to_string(),
        country_code: "US".to_string(),
        region: "Texas".to_string(),
        city: "Houston".to_string(),
        timezone: "America/Chicago".to_string(),
        latitude: 29.76,
        longitude: -95.37,
        asn: 21928,
        asn_org: "T-Mobile USA".to_string(),
        is_datacenter: false,
        is_residential: false,
        is_mobile: true,
    }
}

/// The 8 coherence pairs validated by `CoherenceValidator::validate`, expressed
/// as the `FingerprintWarning.vectors` tags each check emits on violation.
/// (A 9th TLS-vs-Client-Hints check runs when a `TlsBrowser` is supplied.)
const EIGHT_PAIR_VECTORS: &[&[&str]] = &[
    // timezone ↔ IP geolocation
    &["timezone", "ip_geolocation"],
    // Accept-Language ↔ IP country
    &["accept_language", "ip_geolocation"],
    // Accept-Language ↔ timezone
    &["accept_language", "timezone"],
    // screen dimensions ↔ device type
    &["viewport", "user_agent"],
    // touch support ↔ device type
    &["max_touch_points", "user_agent"],
    // GPU vendor ↔ platform
    &["webgl_renderer", "user_agent"],
    // ASN type ↔ browsing pattern
    &["ip_asn", "browsing_pattern"],
    // Client-Hints platform ↔ User-Agent platform
    &["user_agent", "navigator.platform", "client_hints"],
];

fn coherent_contexts() -> Vec<GeoContext> {
    vec![
        us_houston_geo(),
        gb_london_geo(),
        de_munich_geo(),
        jp_tokyo_geo(),
        br_saopaulo_geo(),
        au_sydney_geo(),
        us_mobile_geo(),
    ]
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

/// Full identity stack is consistent end-to-end: generate → validate → safe,
/// with no critical/warning/info issues, for every representative context.
#[test]
fn full_identity_stack_is_consistent_for_representative_geos() {
    for geo in coherent_contexts() {
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        // Generated profiles are Chrome; validate against a Chrome JA4/TLS fingerprint.
        let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));

        assert!(
            report.is_safe(),
            "{}: report not safe: {:?}",
            geo.city, report.warnings
        );
        assert_eq!(report.critical_count, 0, "{}: critical issues", geo.city);
        assert_eq!(
            report.warning_count, 0,
            "{}: warning issues {:?}",
            geo.city, report.warnings
        );
        assert_eq!(report.info_count, 0, "{}: info issues", geo.city);
    }
}

/// Each of the 8 coherence pairs reports zero violations for coherent profiles.
#[test]
fn all_eight_coherence_pairs_have_no_violations() {
    for geo in coherent_contexts() {
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));

        for pair in EIGHT_PAIR_VECTORS {
            for w in &report.warnings {
                assert!(
                    !w.vectors.iter().any(|v| pair.contains(v)),
                    "{}: pair {:?} violated: {:?}",
                    geo.city, pair, w
                );
            }
        }
    }
}

/// TLS ↔ Client-Hints / UA pair is consistent for generated Chrome profiles.
#[test]
fn tls_and_client_hints_pair_is_consistent() {
    let geo = us_houston_geo();
    let profile = CoherenceValidator::generate_coherent_profile(&geo);
    let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));
    assert!(
        !report.warnings.iter().any(|w| w.vectors.contains(&"tls_fingerprint")),
        "Chrome profile + Chrome TLS must not be flagged: {:?}",
        report.warnings
    );
}

/// Panopticlick/BrowserScan-style coherence score is a stable 0..1 baseline:
/// clean profiles pin to exactly 1.0; incoherent profiles stay in-bounds and
/// strictly below the baseline.
#[test]
fn coherence_score_is_a_stable_unit_baseline() {
    for geo in coherent_contexts() {
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));

        assert!(
            (0.0..=1.0).contains(&report.score),
            "{}: score {} out of [0,1]",
            geo.city, report.score
        );
        assert!(
            (report.score - 1.0).abs() < 1e-9,
            "{}: clean profile must score 1.0, got {}",
            geo.city, report.score
        );

        // Deterministic: revalidating the same profile yields the same score.
        let again = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));
        assert_eq!(report.score, again.score, "{}: score must be stable", geo.city);
    }

    // A deliberately incoherent profile lands within [0,1] but strictly below 1.0.
    let mut broken = CoherenceValidator::generate_coherent_profile(&us_houston_geo());
    broken.timezone = "Asia/Tokyo".to_string();
    broken.languages = vec!["pt-BR".to_string()];
    broken.max_touch_points = 5;
    let report = CoherenceValidator::validate(&broken, &us_houston_geo(), Some(TlsBrowser::Firefox));
    assert!(
        (0.0..=1.0).contains(&report.score),
        "broken profile score {} out of [0,1]",
        report.score
    );
    assert!(
        report.score < 1.0,
        "incoherent profile must score below the clean baseline, got {}",
        report.score
    );
    assert!(report.critical_count > 0, "broken profile should surface critical issues");
}
