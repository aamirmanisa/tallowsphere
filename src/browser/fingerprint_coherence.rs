//! Network-context coherence validation for Tallow stealth profiles.
//!
//! Modern anti-bot systems (DataDome, Cloudflare, PerimeterX) cross-reference
//! the browser fingerprint with the network context: IP geolocation, timezone,
//! locale, ASN type, and TLS fingerprint. A Chrome profile claiming
//! "America/Chicago" but connecting from a Hetzner IP in Germany is an instant
//! flag. This module validates — and auto-fixes — coherence between the
//! `StealthProfile` fingerprint vectors and the actual `GeoContext` of the
//! connection.
//!
//! Checks performed:
//! - Timezone ↔ IP geolocation (country + region → valid IANA timezones)
//! - Locale / Accept-Language ↔ IP country
//! - Client Hints ↔ TLS fingerprint (JA4 browser vs Sec-CH-UA)
//! - Client Hints ↔ User-Agent platform consistency
//! - Screen dimensions ↔ device type (mobile vs desktop)
//! - Touch support ↔ device type
//! - GPU vendor ↔ platform plausibility
//! - ASN type ↔ browsing pattern (datacenter vs residential)
//! - Language ↔ timezone plausibility
//!
//! Non-browser client stacks (the `tallow-net` TLS/QUIC relay transports) are
//! audited by [`ClientStackValidator`] against a [`DeclaredClientProfile`]:
//! TLS versions, cipher suites, curves, signature algorithms, ALPN and QUIC
//! transport parameters are read from the real `tallow-net`
//! `transport/tls_config` + `transport/tls_cohort` APIs and compared with what
//! the stack is declared to look like on the wire (ag03 R-2 / matrix row #5).

use super::fingerprint_validator::{FingerprintWarning, Severity};
use super::stealth::StealthProfile;
use tallow_net::transport::tls_cohort::{self, is_grease, Ja4CohortV1, Ja4Transport};

// Local helper constructors since FingerprintWarning's methods are private.
fn warn_critical(vectors: Vec<&'static str>, message: impl Into<String>) -> FingerprintWarning {
    FingerprintWarning {
        severity: Severity::Critical,
        vectors,
        message: message.into(),
    }
}
fn warn_warning(vectors: Vec<&'static str>, message: impl Into<String>) -> FingerprintWarning {
    FingerprintWarning {
        severity: Severity::Warning,
        vectors,
        message: message.into(),
    }
}
fn warn_info(vectors: Vec<&'static str>, message: impl Into<String>) -> FingerprintWarning {
    FingerprintWarning {
        severity: Severity::Info,
        vectors,
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// GeoContext — network-level identity of the connection
// ---------------------------------------------------------------------------

/// Geolocation and network metadata for the current connection.
///
/// Populated from GeoIP databases (MaxMind GeoLite2, ip-api.com, ipinfo.io)
/// or from proxy provider metadata.
#[derive(Debug, Clone)]
pub struct GeoContext {
    /// The IP address in use (IPv4 or IPv6).
    pub ip: String,
    /// ISO 3166-1 alpha-2 country code (e.g. "US", "DE", "JP").
    pub country_code: String,
    /// Region / state name (e.g. "Texas", "Bavaria").
    pub region: String,
    /// City name (e.g. "Houston", "Berlin").
    pub city: String,
    /// IANA timezone (e.g. "America/Chicago").
    pub timezone: String,
    /// Latitude of the IP geolocation.
    pub latitude: f64,
    /// Longitude of the IP geolocation.
    pub longitude: f64,
    /// Autonomous System Number.
    pub asn: u32,
    /// ASN organization name (e.g. "Comcast", "Hetzner Online GmbH").
    pub asn_org: String,
    /// Whether the IP belongs to a known datacenter / hosting provider.
    pub is_datacenter: bool,
    /// Whether the IP is classified as residential.
    pub is_residential: bool,
    /// Whether the IP is classified as mobile / cellular.
    pub is_mobile: bool,
}

impl GeoContext {
    /// Convenience constructor for a US residential IP.
    pub fn us_residential(city: &str, region: &str, timezone: &str) -> Self {
        Self {
            ip: "73.162.100.1".to_string(),
            country_code: "US".to_string(),
            region: region.to_string(),
            city: city.to_string(),
            timezone: timezone.to_string(),
            latitude: 29.7604,
            longitude: -95.3698,
            asn: 7922,
            asn_org: "Comcast Cable Communications".to_string(),
            is_datacenter: false,
            is_residential: true,
            is_mobile: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CoherenceFix — describes a single auto-correction
// ---------------------------------------------------------------------------

/// A single field correction applied by the auto-fixer.
#[derive(Debug, Clone)]
pub struct CoherenceFix {
    /// Which field was changed.
    pub field: &'static str,
    /// Previous value.
    pub old_value: String,
    /// New value after fix.
    pub new_value: String,
    /// Why the fix was applied.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// CoherenceReport — aggregated validation result
// ---------------------------------------------------------------------------

/// Full coherence report combining fingerprint warnings with network context.
#[derive(Debug, Clone)]
pub struct CoherenceReport {
    /// All detected issues, ordered by severity (Critical first).
    pub warnings: Vec<FingerprintWarning>,
    /// Number of critical issues (likely bot detection).
    pub critical_count: usize,
    /// Number of warnings (contributes to bot score).
    pub warning_count: usize,
    /// Number of informational notes.
    pub info_count: usize,
    /// Overall coherence score: 0.0 (completely incoherent) to 1.0 (perfect).
    pub score: f64,
}

impl CoherenceReport {
    /// Build a report from a list of warnings.
    pub fn from_warnings(mut warnings: Vec<FingerprintWarning>) -> Self {
        warnings.sort_by_key(|w| match w.severity {
            Severity::Critical => 0,
            Severity::Warning => 1,
            Severity::Info => 2,
        });
        let critical_count = warnings
            .iter()
            .filter(|w| w.severity == Severity::Critical)
            .count();
        let warning_count = warnings
            .iter()
            .filter(|w| w.severity == Severity::Warning)
            .count();
        let info_count = warnings
            .iter()
            .filter(|w| w.severity == Severity::Info)
            .count();

        // Score: start at 1.0, subtract 0.25 per critical, 0.10 per warning, 0.02 per info.
        let deductions =
            critical_count as f64 * 0.25 + warning_count as f64 * 0.10 + info_count as f64 * 0.02;
        let score = (1.0 - deductions).max(0.0);

        Self {
            warnings,
            critical_count,
            warning_count,
            info_count,
            score,
        }
    }

    /// Whether the profile is safe to use without fixes.
    pub fn is_safe(&self) -> bool {
        self.critical_count == 0
    }
}

// ---------------------------------------------------------------------------
// TLS browser hint (for Client Hints ↔ TLS check)
// ---------------------------------------------------------------------------

/// Browser family detected from TLS/JA4 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsBrowser {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Unknown,
}

// ---------------------------------------------------------------------------
// Country → Timezone mapping (50+ countries)
// ---------------------------------------------------------------------------

/// Returns valid IANA timezones for a given ISO 3166-1 alpha-2 country code.
pub fn timezones_for_country(country: &str) -> &'static [&'static str] {
    match country {
        // North America
        "US" => &[
            "America/New_York",
            "America/Chicago",
            "America/Denver",
            "America/Los_Angeles",
            "America/Phoenix",
            "America/Anchorage",
            "Pacific/Honolulu",
            "America/Detroit",
            "America/Indiana/Indianapolis",
            "America/Kentucky/Louisville",
            "America/Boise",
            "America/Juneau",
            "America/Adak",
            "America/Nome",
        ],
        "CA" => &[
            "America/Toronto",
            "America/Vancouver",
            "America/Edmonton",
            "America/Winnipeg",
            "America/Halifax",
            "America/St_Johns",
            "America/Regina",
            "America/Yellowknife",
            "America/Iqaluit",
        ],
        "MX" => &[
            "America/Mexico_City",
            "America/Cancun",
            "America/Monterrey",
            "America/Tijuana",
            "America/Chihuahua",
            "America/Hermosillo",
        ],

        // South America
        "BR" => &[
            "America/Sao_Paulo",
            "America/Manaus",
            "America/Fortaleza",
            "America/Recife",
            "America/Belem",
            "America/Cuiaba",
            "America/Porto_Velho",
            "America/Rio_Branco",
        ],
        "AR" => &[
            "America/Argentina/Buenos_Aires",
            "America/Argentina/Cordoba",
        ],
        "CL" => &["America/Santiago", "Pacific/Easter"],
        "CO" => &["America/Bogota"],
        "PE" => &["America/Lima"],
        "VE" => &["America/Caracas"],
        "EC" => &["America/Guayaquil", "Pacific/Galapagos"],
        "UY" => &["America/Montevideo"],
        "PY" => &["America/Asuncion"],
        "BO" => &["America/La_Paz"],

        // Europe
        "GB" | "UK" => &["Europe/London"],
        "DE" => &["Europe/Berlin"],
        "FR" => &["Europe/Paris"],
        "ES" => &["Europe/Madrid", "Atlantic/Canary"],
        "IT" => &["Europe/Rome"],
        "NL" => &["Europe/Amsterdam"],
        "BE" => &["Europe/Brussels"],
        "PT" => &["Europe/Lisbon", "Atlantic/Azores"],
        "CH" => &["Europe/Zurich"],
        "AT" => &["Europe/Vienna"],
        "SE" => &["Europe/Stockholm"],
        "NO" => &["Europe/Oslo"],
        "DK" => &["Europe/Copenhagen"],
        "FI" => &["Europe/Helsinki"],
        "PL" => &["Europe/Warsaw"],
        "CZ" => &["Europe/Prague"],
        "IE" => &["Europe/Dublin"],
        "RO" => &["Europe/Bucharest"],
        "HU" => &["Europe/Budapest"],
        "GR" => &["Europe/Athens"],
        "BG" => &["Europe/Sofia"],
        "HR" => &["Europe/Zagreb"],
        "SK" => &["Europe/Bratislava"],
        "UA" => &["Europe/Kiev"],
        "BY" => &["Europe/Minsk"],
        "RS" => &["Europe/Belgrade"],
        "LT" => &["Europe/Vilnius"],
        "LV" => &["Europe/Riga"],
        "EE" => &["Europe/Tallinn"],
        "IS" => &["Atlantic/Reykjavik"],
        "LU" => &["Europe/Luxembourg"],

        // Russia spans many zones
        "RU" => &[
            "Europe/Moscow",
            "Europe/Kaliningrad",
            "Europe/Samara",
            "Asia/Yekaterinburg",
            "Asia/Novosibirsk",
            "Asia/Krasnoyarsk",
            "Asia/Irkutsk",
            "Asia/Yakutsk",
            "Asia/Vladivostok",
            "Asia/Kamchatka",
        ],

        // Middle East
        "TR" => &["Europe/Istanbul"],
        "IL" => &["Asia/Jerusalem"],
        "AE" => &["Asia/Dubai"],
        "SA" => &["Asia/Riyadh"],
        "QA" => &["Asia/Qatar"],
        "KW" => &["Asia/Kuwait"],
        "BH" => &["Asia/Bahrain"],
        "OM" => &["Asia/Muscat"],
        "JO" => &["Asia/Amman"],
        "LB" => &["Asia/Beirut"],
        "IQ" => &["Asia/Baghdad"],
        "IR" => &["Asia/Tehran"],
        "EG" => &["Africa/Cairo"],

        // Asia-Pacific
        "JP" => &["Asia/Tokyo"],
        "KR" => &["Asia/Seoul"],
        "CN" => &["Asia/Shanghai"],
        "TW" => &["Asia/Taipei"],
        "HK" => &["Asia/Hong_Kong"],
        "SG" => &["Asia/Singapore"],
        "IN" => &["Asia/Kolkata"],
        "PK" => &["Asia/Karachi"],
        "BD" => &["Asia/Dhaka"],
        "TH" => &["Asia/Bangkok"],
        "VN" => &["Asia/Ho_Chi_Minh"],
        "MY" => &["Asia/Kuala_Lumpur"],
        "PH" => &["Asia/Manila"],
        "ID" => &["Asia/Jakarta", "Asia/Makassar", "Asia/Jayapura"],
        "NP" => &["Asia/Kathmandu"],
        "LK" => &["Asia/Colombo"],
        "MM" => &["Asia/Yangon"],
        "KH" => &["Asia/Phnom_Penh"],
        "LA" => &["Asia/Vientiane"],
        "KZ" => &["Asia/Almaty", "Asia/Aqtobe"],

        // Oceania
        "AU" => &[
            "Australia/Sydney",
            "Australia/Melbourne",
            "Australia/Brisbane",
            "Australia/Perth",
            "Australia/Adelaide",
            "Australia/Hobart",
            "Australia/Darwin",
        ],
        "NZ" => &["Pacific/Auckland", "Pacific/Chatham"],

        // Africa
        "ZA" => &["Africa/Johannesburg"],
        "NG" => &["Africa/Lagos"],
        "KE" => &["Africa/Nairobi"],
        "GH" => &["Africa/Accra"],
        "MA" => &["Africa/Casablanca"],
        "TN" => &["Africa/Tunis"],
        "ET" => &["Africa/Addis_Ababa"],
        "TZ" => &["Africa/Dar_es_Salaam"],
        "SN" => &["Africa/Dakar"],
        "CI" => &["Africa/Abidjan"],

        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Country → Primary languages mapping
// ---------------------------------------------------------------------------

/// Returns primary Accept-Language tags for a given country code.
///
/// The first element is the dominant language. A real browser from that
/// country would typically send these (possibly with quality weights).
pub fn languages_for_country(country: &str) -> &'static [&'static str] {
    match country {
        // English-speaking
        "US" => &["en-US", "en"],
        "GB" | "UK" => &["en-GB", "en"],
        "CA" => &["en-CA", "en", "fr-CA", "fr"],
        "AU" => &["en-AU", "en"],
        "NZ" => &["en-NZ", "en"],
        "IE" => &["en-IE", "en", "ga"],
        "SG" => &["en-SG", "en", "zh", "ms", "ta"],
        "ZA" => &["en-ZA", "en", "af", "zu"],
        "IN" => &["en-IN", "en", "hi"],
        "PH" => &["en-PH", "en", "fil"],
        "NG" => &["en-NG", "en"],
        "GH" => &["en-GH", "en"],
        "KE" => &["en", "sw"],

        // Spanish-speaking
        "MX" => &["es-MX", "es", "en"],
        "ES" => &["es-ES", "es", "ca", "gl"],
        "AR" => &["es-AR", "es"],
        "CO" => &["es-CO", "es"],
        "CL" => &["es-CL", "es"],
        "PE" => &["es-PE", "es"],
        "VE" => &["es-VE", "es"],
        "EC" => &["es-EC", "es"],
        "UY" => &["es-UY", "es"],
        "PY" => &["es-PY", "es"],
        "BO" => &["es-BO", "es"],

        // Portuguese-speaking
        "BR" => &["pt-BR", "pt", "en"],
        "PT" => &["pt-PT", "pt", "en"],

        // French-speaking
        "FR" => &["fr-FR", "fr", "en"],
        "BE" => &["fr-BE", "fr", "nl-BE", "nl", "de"],
        "CH" => &["de-CH", "de", "fr-CH", "fr", "it-CH", "it"],
        "SN" => &["fr", "wo"],
        "CI" => &["fr"],
        "LU" => &["fr-LU", "fr", "de-LU", "de", "lb"],

        // German-speaking
        "DE" => &["de-DE", "de", "en"],
        "AT" => &["de-AT", "de", "en"],

        // Nordic
        "SE" => &["sv-SE", "sv", "en"],
        "NO" => &["nb-NO", "no", "nn", "en"],
        "DK" => &["da-DK", "da", "en"],
        "FI" => &["fi-FI", "fi", "sv", "en"],
        "IS" => &["is-IS", "is", "en"],

        // Eastern Europe
        "PL" => &["pl-PL", "pl", "en"],
        "CZ" => &["cs-CZ", "cs", "en"],
        "SK" => &["sk-SK", "sk", "en"],
        "HU" => &["hu-HU", "hu", "en"],
        "RO" => &["ro-RO", "ro", "en"],
        "BG" => &["bg-BG", "bg", "en"],
        "HR" => &["hr-HR", "hr", "en"],
        "RS" => &["sr-RS", "sr", "en"],
        "UA" => &["uk-UA", "uk", "ru", "en"],
        "BY" => &["be-BY", "be", "ru"],
        "LT" => &["lt-LT", "lt", "en"],
        "LV" => &["lv-LV", "lv", "en"],
        "EE" => &["et-EE", "et", "en"],

        // Southern Europe
        "IT" => &["it-IT", "it", "en"],
        "GR" => &["el-GR", "el", "en"],

        // Netherlands
        "NL" => &["nl-NL", "nl", "en"],

        // Russia
        "RU" => &["ru-RU", "ru", "en"],

        // Middle East
        "TR" => &["tr-TR", "tr", "en"],
        "IL" => &["he-IL", "he", "ar", "en"],
        "AE" | "SA" | "QA" | "KW" | "BH" | "OM" | "JO" | "IQ" => &["ar", "en"],
        "LB" => &["ar", "fr", "en"],
        "IR" => &["fa-IR", "fa", "en"],
        "EG" => &["ar-EG", "ar", "en"],
        "MA" => &["ar-MA", "ar", "fr", "en"],
        "TN" => &["ar-TN", "ar", "fr", "en"],

        // East Asia
        "JP" => &["ja-JP", "ja", "en"],
        "KR" => &["ko-KR", "ko", "en"],
        "CN" => &["zh-CN", "zh", "en"],
        "TW" => &["zh-TW", "zh", "en"],
        "HK" => &["zh-HK", "zh", "en"],

        // Southeast Asia
        "TH" => &["th-TH", "th", "en"],
        "VN" => &["vi-VN", "vi", "en"],
        "MY" => &["ms-MY", "ms", "en", "zh"],
        "ID" => &["id-ID", "id", "en"],
        "KH" => &["km-KH", "km", "en"],
        "LA" => &["lo-LA", "lo", "en"],
        "MM" => &["my", "en"],

        // South Asia
        "PK" => &["ur-PK", "ur", "en"],
        "BD" => &["bn-BD", "bn", "en"],
        "NP" => &["ne-NP", "ne", "en"],
        "LK" => &["si-LK", "si", "ta", "en"],
        "KZ" => &["kk-KZ", "kk", "ru", "en"],

        // Africa
        "ET" => &["am-ET", "am", "en"],
        "TZ" => &["sw-TZ", "sw", "en"],

        _ => &["en"],
    }
}

// ---------------------------------------------------------------------------
// Timezone → plausible language tags
// ---------------------------------------------------------------------------

/// Given an IANA timezone, returns language tags that are plausible.
/// Used for the Language ↔ Timezone cross-check.
fn plausible_languages_for_timezone(tz: &str) -> Vec<&'static str> {
    // English is plausible almost everywhere (browser default / expat)
    let mut langs: Vec<&'static str> = vec!["en", "en-US", "en-GB"];

    if tz.starts_with("America/") {
        // Americas: English + Spanish + Portuguese + French (CA)
        langs.extend_from_slice(&["es", "pt", "fr"]);
        if tz.contains("Sao_Paulo")
            || tz.contains("Fortaleza")
            || tz.contains("Manaus")
            || tz.contains("Recife")
            || tz.contains("Belem")
            || tz.contains("Rio_Branco")
        {
            langs.extend_from_slice(&["pt-BR"]);
        }
        if tz.contains("Mexico")
            || tz.contains("Cancun")
            || tz.contains("Monterrey")
            || tz.contains("Buenos_Aires")
            || tz.contains("Bogota")
            || tz.contains("Santiago")
            || tz.contains("Lima")
            || tz.contains("Caracas")
        {
            langs.extend_from_slice(&["es-MX", "es-AR", "es-CO"]);
        }
    } else if tz.starts_with("Europe/") {
        langs.extend_from_slice(&[
            "de", "fr", "es", "it", "nl", "pl", "pt", "ru", "sv", "da", "no", "fi", "cs", "hu",
            "ro", "bg", "hr", "sk", "uk", "el", "tr", "sr", "lt", "lv", "et",
        ]);
    } else if tz.starts_with("Asia/Tokyo") {
        langs.extend_from_slice(&["ja", "ja-JP"]);
    } else if tz.starts_with("Asia/Seoul") {
        langs.extend_from_slice(&["ko", "ko-KR"]);
    } else if tz.starts_with("Asia/Shanghai")
        || tz.starts_with("Asia/Hong_Kong")
        || tz.starts_with("Asia/Taipei")
    {
        langs.extend_from_slice(&["zh", "zh-CN", "zh-TW", "zh-HK"]);
    } else if tz.starts_with("Asia/") {
        // Generic Asia: many languages plausible
        langs.extend_from_slice(&[
            "zh", "ja", "ko", "th", "vi", "id", "ms", "hi", "ar", "fa", "tr", "he", "ru", "ur",
            "bn",
        ]);
    } else if tz.starts_with("Australia/") || tz.starts_with("Pacific/Auckland") {
        // English-dominant, all good
    } else if tz.starts_with("Africa/") {
        langs.extend_from_slice(&["fr", "ar", "sw", "pt", "am", "zu", "af"]);
    }

    langs
}

// ---------------------------------------------------------------------------
// English-speaking countries (Accept-Language "en-*" is fine from these)
// ---------------------------------------------------------------------------

const ENGLISH_SPEAKING_COUNTRIES: &[&str] = &[
    "US", "GB", "UK", "CA", "AU", "NZ", "IE", "SG", "ZA", "IN", "PH", "NG", "GH", "KE", "HK", "MY",
    "PK", "BD", "TZ",
];

// ---------------------------------------------------------------------------
// Known datacenter ASN organizations
// ---------------------------------------------------------------------------

const DATACENTER_ASN_KEYWORDS: &[&str] = &[
    "hetzner",
    "ovh",
    "digitalocean",
    "amazon",
    "aws",
    "google cloud",
    "microsoft azure",
    "linode",
    "akamai",
    "vultr",
    "oracle cloud",
    "cloudflare",
    "scaleway",
    "contabo",
    "ionos",
    "rackspace",
    "softlayer",
    "ibm cloud",
    "alibaba cloud",
    "tencent cloud",
    "leaseweb",
    "choopa",
    "m247",
    "psychz",
    "cogent",
    "quadranet",
    "datacamp",
    "hostwinds",
    "kamatera",
];

// ---------------------------------------------------------------------------
// CoherenceValidator
// ---------------------------------------------------------------------------

/// Validates coherence between a `StealthProfile` and the network `GeoContext`.
///
/// While `FingerprintValidator` checks internal consistency of browser vectors
/// (UA vs platform, WebGL vendor vs renderer), this validator checks that the
/// profile is plausible *for the actual network connection*. Anti-bot systems
/// cross-reference these signals to detect proxy/VPN usage with mismatched
/// browser profiles.
pub struct CoherenceValidator;

impl CoherenceValidator {
    /// Run all coherence checks between a profile and its network context.
    pub fn validate(
        profile: &StealthProfile,
        geo: &GeoContext,
        tls_browser: Option<TlsBrowser>,
    ) -> CoherenceReport {
        let mut warnings = Vec::new();

        Self::check_timezone_ip(profile, geo, &mut warnings);
        Self::check_locale_ip(profile, geo, &mut warnings);
        Self::check_language_timezone(profile, geo, &mut warnings);
        Self::check_screen_device(profile, &mut warnings);
        Self::check_touch_device(profile, &mut warnings);
        Self::check_gpu_platform(profile, &mut warnings);
        Self::check_asn_behavior(profile, geo, &mut warnings);

        if let Some(browser) = tls_browser {
            Self::check_client_hints_tls(profile, browser, &mut warnings);
        }
        Self::check_client_hints_ua(profile, &mut warnings);

        CoherenceReport::from_warnings(warnings)
    }

    // -----------------------------------------------------------------------
    // Individual checks
    // -----------------------------------------------------------------------

    /// Timezone claimed by profile must be valid for the IP's country.
    fn check_timezone_ip(
        profile: &StealthProfile,
        geo: &GeoContext,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if geo.country_code.is_empty() || profile.timezone.is_empty() {
            return;
        }

        let valid_tzs = timezones_for_country(&geo.country_code);

        // If we have no mapping for this country, skip (don't false-positive).
        if valid_tzs.is_empty() {
            return;
        }

        if !valid_tzs.contains(&profile.timezone.as_str()) {
            warnings.push(warn_critical(
                vec!["timezone", "ip_geolocation"],
                format!(
                    "Profile timezone '{}' is not valid for IP country '{}' ({}). \
                     Valid timezones: {}",
                    profile.timezone,
                    geo.country_code,
                    geo.city,
                    valid_tzs
                        .iter()
                        .take(5)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            ));
        }
    }

    /// Accept-Language should be plausible for the IP's country.
    fn check_locale_ip(
        profile: &StealthProfile,
        geo: &GeoContext,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if profile.languages.is_empty() || geo.country_code.is_empty() {
            return;
        }

        let primary_lang = &profile.languages[0];
        let country_langs = languages_for_country(&geo.country_code);

        // If the primary language tag's base matches any of the country's languages, it's fine.
        let base_lang = primary_lang.split('-').next().unwrap_or(primary_lang);

        // English is acceptable from English-speaking countries regardless of tag variant.
        if base_lang == "en" && ENGLISH_SPEAKING_COUNTRIES.contains(&geo.country_code.as_str()) {
            return;
        }

        // Check if the base language matches any country language base.
        let matches = country_langs.iter().any(|cl| {
            let cl_base = cl.split('-').next().unwrap_or(cl);
            cl_base == base_lang
        });

        // Also accept English from any country (expats, English-literate users).
        // But flag it if it's a language that makes no sense (e.g. "ja-JP" from Brazil).
        if !matches && base_lang != "en" {
            warnings.push(warn_warning(
                vec!["accept_language", "ip_geolocation"],
                format!(
                    "Primary language '{}' is unusual for IP country '{}'. \
                     Expected one of: {}",
                    primary_lang,
                    geo.country_code,
                    country_langs
                        .iter()
                        .take(4)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            ));
        }
    }

    /// Language tags should be plausible for the claimed timezone.
    fn check_language_timezone(
        profile: &StealthProfile,
        _geo: &GeoContext,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if profile.languages.is_empty() || profile.timezone.is_empty() {
            return;
        }

        let plausible = plausible_languages_for_timezone(&profile.timezone);
        if plausible.is_empty() {
            return;
        }

        let primary_lang = &profile.languages[0];
        let base_lang = primary_lang.split('-').next().unwrap_or(primary_lang);

        let lang_ok = plausible.iter().any(|pl| {
            let pl_base = pl.split('-').next().unwrap_or(pl);
            pl_base == base_lang
        });

        if !lang_ok {
            warnings.push(warn_warning(
                vec!["accept_language", "timezone"],
                format!(
                    "Language '{}' is unusual for timezone '{}' — \
                     anti-bot systems cross-reference these signals",
                    primary_lang, profile.timezone,
                ),
            ));
        }
    }

    /// Sec-CH-UA must match the TLS fingerprint's browser family.
    fn check_client_hints_tls(
        profile: &StealthProfile,
        tls_browser: TlsBrowser,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        let ua = &profile.user_agent;

        let ua_browser = if ua.contains("Chrome/") && !ua.contains("Edg/") {
            TlsBrowser::Chrome
        } else if ua.contains("Firefox/") {
            TlsBrowser::Firefox
        } else if ua.contains("Safari/") && !ua.contains("Chrome/") {
            TlsBrowser::Safari
        } else if ua.contains("Edg/") {
            TlsBrowser::Edge
        } else {
            TlsBrowser::Unknown
        };

        if tls_browser != TlsBrowser::Unknown
            && ua_browser != TlsBrowser::Unknown
            && tls_browser != ua_browser
        {
            // Edge and Chrome share similar TLS fingerprints, allow that.
            let compatible = matches!(
                (tls_browser, ua_browser),
                (TlsBrowser::Chrome, TlsBrowser::Edge) | (TlsBrowser::Edge, TlsBrowser::Chrome)
            );

            if !compatible {
                warnings.push(warn_critical(
                    vec!["tls_fingerprint", "user_agent", "client_hints"],
                    format!(
                        "TLS fingerprint indicates {:?} but UA claims {:?} — \
                         Sec-CH-UA and JA4 hash will be inconsistent",
                        tls_browser, ua_browser,
                    ),
                ));
            }
        }
    }

    /// Sec-CH-UA-Platform must match User-Agent platform.
    fn check_client_hints_ua(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let ua = &profile.user_agent;

        // Derive expected CH-Platform from UA.
        let ch_platform = if ua.contains("iPhone") || ua.contains("iPad") {
            "iOS"
        } else if ua.contains("Android") {
            "Android"
        } else if ua.contains("Windows") {
            "Windows"
        } else if ua.contains("Macintosh") || ua.contains("Mac OS") {
            "macOS"
        } else if ua.contains("Linux") {
            "Linux"
        } else {
            return; // Can't determine, skip.
        };

        let platform_ok = match ch_platform {
            "Windows" => profile.platform == "Win32",
            "macOS" => profile.platform == "MacIntel",
            "Linux" => profile.platform.starts_with("Linux"),
            "Android" => profile.platform.starts_with("Linux"),
            "iOS" => profile.platform == "iPhone" || profile.platform == "iPad",
            _ => true,
        };

        if !platform_ok {
            warnings.push(warn_critical(
                vec!["user_agent", "navigator.platform", "client_hints"],
                format!(
                    "UA implies Sec-CH-UA-Platform '{}' but navigator.platform is '{}' — \
                     cross-API mismatch detected by DataDome/Cloudflare",
                    ch_platform, profile.platform,
                ),
            ));
        }
    }

    /// Mobile UA should have mobile screen dimensions; desktop should have desktop.
    fn check_screen_device(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let is_mobile = ua_is_mobile(&profile.user_agent);
        let (w, _h) = profile.viewport;

        if is_mobile && w > 500 {
            // Allow tablets up to ~1024px wide.
            let is_tablet = profile.user_agent.contains("iPad") || (w >= 768 && w <= 1024);
            if !is_tablet {
                warnings.push(warn_warning(
                    vec!["viewport", "user_agent"],
                    format!(
                        "Mobile UA but viewport width is {}px — \
                         most phones are under 500px CSS width",
                        w,
                    ),
                ));
            }
        }

        if !is_mobile && w < 800 {
            warnings.push(warn_warning(
                vec!["viewport", "user_agent"],
                format!(
                    "Desktop UA but viewport width is only {}px — \
                     desktop browsers are typically 800px+ wide",
                    w,
                ),
            ));
        }
    }

    /// maxTouchPoints > 0 only for mobile/tablet.
    fn check_touch_device(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let is_mobile = ua_is_mobile(&profile.user_agent);

        if !is_mobile && profile.max_touch_points > 0 {
            warnings.push(warn_warning(
                vec!["max_touch_points", "user_agent"],
                format!(
                    "Desktop UA but maxTouchPoints={} — most desktop Chrome reports 0",
                    profile.max_touch_points,
                ),
            ));
        }

        if is_mobile && profile.max_touch_points == 0 {
            warnings.push(warn_critical(
                vec!["max_touch_points", "user_agent"],
                "Mobile UA but maxTouchPoints=0 — all mobile devices support touch".to_string(),
            ));
        }
    }

    /// GPU vendor must be plausible for the claimed platform.
    fn check_gpu_platform(profile: &StealthProfile, warnings: &mut Vec<FingerprintWarning>) {
        let ua = &profile.user_agent;
        let renderer_upper = profile.webgl_renderer.to_uppercase();

        // macOS (Apple Silicon era): NVIDIA/AMD GPUs are suspicious.
        if ua.contains("Macintosh") || ua.contains("Mac OS") {
            if renderer_upper.contains("NVIDIA")
                || renderer_upper.contains("GEFORCE")
                || renderer_upper.contains("RTX")
                || renderer_upper.contains("GTX")
            {
                warnings.push(warn_critical(
                    vec!["webgl_renderer", "user_agent"],
                    format!(
                        "macOS UA but WebGL renderer claims NVIDIA GPU — \
                         Apple Silicon Macs (2020+) use Apple GPU only; \
                         renderer: '{}'",
                        profile.webgl_renderer,
                    ),
                ));
            }
            if renderer_upper.contains("AMD RADEON") || renderer_upper.contains("ATI RADEON") {
                warnings.push(warn_warning(
                    vec!["webgl_renderer", "user_agent"],
                    format!(
                        "macOS UA with AMD GPU — last AMD-equipped Mac was 2019; \
                         modern macOS traffic is predominantly Apple Silicon. \
                         Renderer: '{}'",
                        profile.webgl_renderer,
                    ),
                ));
            }
        }

        // Intel iGPU with very high resolution is suspicious (gaming monitors).
        if renderer_upper.contains("INTEL") && renderer_upper.contains("UHD") {
            let (w, h) = profile.viewport;
            if w >= 3440 || h >= 2160 {
                warnings.push(warn_info(
                    vec!["webgl_renderer", "viewport"],
                    format!(
                        "Intel iGPU with {}x{} resolution — unusual for integrated graphics; \
                         gaming-class displays typically paired with discrete GPUs",
                        w, h,
                    ),
                ));
            }
        }

        // Windows or Linux claiming Apple GPU is impossible.
        if (ua.contains("Windows") || ua.contains("Linux"))
            && !ua.contains("Android")
            && (renderer_upper.contains("APPLE") && renderer_upper.contains("M1")
                || renderer_upper.contains("M2")
                || renderer_upper.contains("M3")
                || renderer_upper.contains("M4"))
        {
            warnings.push(warn_critical(
                vec!["webgl_renderer", "user_agent"],
                format!(
                    "Non-macOS UA but WebGL renderer claims Apple Silicon GPU — \
                     Apple GPUs only exist on macOS/iOS devices. Renderer: '{}'",
                    profile.webgl_renderer,
                ),
            ));
        }

        // Mobile UA with desktop-class discrete GPU is suspicious.
        let is_mobile = ua_is_mobile(ua);
        if is_mobile {
            if renderer_upper.contains("GEFORCE")
                || renderer_upper.contains("RTX")
                || renderer_upper.contains("GTX")
                || renderer_upper.contains("RADEON RX")
            {
                warnings.push(warn_critical(
                    vec!["webgl_renderer", "user_agent"],
                    format!(
                        "Mobile UA but WebGL renderer claims desktop discrete GPU — \
                         mobile devices use mobile GPUs (Adreno, Mali, Apple GPU). \
                         Renderer: '{}'",
                        profile.webgl_renderer,
                    ),
                ));
            }
        }
    }

    /// Datacenter ASN with residential browsing pattern is suspicious.
    fn check_asn_behavior(
        profile: &StealthProfile,
        geo: &GeoContext,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        // Explicit datacenter flag takes priority.
        if geo.is_datacenter {
            warnings.push(warn_warning(
                vec!["ip_asn", "browsing_pattern"],
                format!(
                    "IP {} (ASN {} / {}) is classified as datacenter — \
                     residential browsing profile from datacenter IP is a strong bot signal",
                    geo.ip, geo.asn, geo.asn_org,
                ),
            ));
            return;
        }

        // Also check ASN org name against known datacenter providers.
        let org_lower = geo.asn_org.to_lowercase();
        for &keyword in DATACENTER_ASN_KEYWORDS {
            if org_lower.contains(keyword) {
                warnings.push(warn_warning(
                    vec!["ip_asn", "browsing_pattern"],
                    format!(
                        "ASN org '{}' matches known datacenter provider '{}' — \
                         but is_datacenter=false. Verify IP classification.",
                        geo.asn_org, keyword,
                    ),
                ));
                break;
            }
        }

        // Mobile IP with desktop UA (or vice versa) is suspicious.
        let is_mobile_ua = ua_is_mobile(&profile.user_agent);
        if geo.is_mobile && !is_mobile_ua {
            warnings.push(warn_info(
                vec!["ip_asn", "user_agent"],
                format!(
                    "Mobile/cellular IP (ASN {} / {}) but desktop User-Agent — \
                     mobile tethering exists but anti-bot systems weight this signal",
                    geo.asn, geo.asn_org,
                ),
            ));
        }
        if !geo.is_mobile && !geo.is_datacenter && geo.is_residential && is_mobile_ua {
            warnings.push(warn_info(
                vec!["ip_asn", "user_agent"],
                format!(
                    "Residential non-mobile IP (ASN {} / {}) with mobile User-Agent — \
                     WiFi browsing is common, but some systems flag this combination",
                    geo.asn, geo.asn_org,
                ),
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Auto-fix: adjust profile to match GeoContext
    // -----------------------------------------------------------------------

    /// Automatically fix coherence violations by adjusting the profile to match
    /// the network context. Returns a list of all corrections applied.
    pub fn auto_fix_profile(profile: &mut StealthProfile, geo: &GeoContext) -> Vec<CoherenceFix> {
        let mut fixes = Vec::new();

        // Fix timezone to match IP country.
        Self::fix_timezone(profile, geo, &mut fixes);

        // Fix locale to match IP country.
        Self::fix_locale(profile, geo, &mut fixes);

        // Fix languages to match IP country.
        Self::fix_languages(profile, geo, &mut fixes);

        // Fix touch for mobile/desktop consistency.
        Self::fix_touch(profile, &mut fixes);

        // Fix screen dimensions for device type.
        Self::fix_screen(profile, &mut fixes);

        // Fix GPU to match platform.
        Self::fix_gpu(profile, &mut fixes);

        fixes
    }

    fn fix_timezone(profile: &mut StealthProfile, geo: &GeoContext, fixes: &mut Vec<CoherenceFix>) {
        let valid_tzs = timezones_for_country(&geo.country_code);
        if valid_tzs.is_empty() {
            return;
        }

        if !valid_tzs.contains(&profile.timezone.as_str()) {
            let old = profile.timezone.clone();
            // Pick the timezone that matches the geo's reported timezone if valid,
            // otherwise use the first (most populous) timezone for the country.
            let new_tz = if valid_tzs.contains(&geo.timezone.as_str()) {
                geo.timezone.clone()
            } else {
                valid_tzs[0].to_string()
            };
            profile.timezone = new_tz.clone();
            fixes.push(CoherenceFix {
                field: "timezone",
                old_value: old,
                new_value: new_tz,
                reason: format!("Timezone not valid for IP country '{}'", geo.country_code),
            });
        }
    }

    fn fix_locale(profile: &mut StealthProfile, geo: &GeoContext, fixes: &mut Vec<CoherenceFix>) {
        let country_langs = languages_for_country(&geo.country_code);
        if country_langs.is_empty() {
            return;
        }

        let locale_base = profile.locale.split('-').next().unwrap_or(&profile.locale);
        let locale_ok = country_langs.iter().any(|cl| {
            let cl_base = cl.split('-').next().unwrap_or(cl);
            cl_base == locale_base
        }) || locale_base == "en"; // English is always acceptable.

        if !locale_ok {
            let old = profile.locale.clone();
            // Use the first country language that has a region subtag.
            let new_locale = country_langs
                .iter()
                .find(|l| l.contains('-'))
                .or(country_langs.first())
                .unwrap_or(&"en-US");
            profile.locale = new_locale.to_string();
            fixes.push(CoherenceFix {
                field: "locale",
                old_value: old,
                new_value: new_locale.to_string(),
                reason: format!("Locale not plausible for IP country '{}'", geo.country_code),
            });
        }
    }

    fn fix_languages(
        profile: &mut StealthProfile,
        geo: &GeoContext,
        fixes: &mut Vec<CoherenceFix>,
    ) {
        if profile.languages.is_empty() {
            return;
        }

        let country_langs = languages_for_country(&geo.country_code);
        if country_langs.is_empty() {
            return;
        }

        let primary = &profile.languages[0];
        let base = primary.split('-').next().unwrap_or(primary);

        let ok = country_langs.iter().any(|cl| {
            let cl_base = cl.split('-').next().unwrap_or(cl);
            cl_base == base
        }) || base == "en";

        if !ok {
            let old = profile.languages.join(", ");
            // Build a natural Accept-Language list for the country.
            let mut new_langs: Vec<String> = country_langs
                .iter()
                .take(3)
                .map(|s| s.to_string())
                .collect();
            // Ensure "en" is present (common in many browsers).
            if !new_langs.iter().any(|l| l.starts_with("en")) {
                new_langs.push("en".to_string());
            }
            let new_str = new_langs.join(", ");
            profile.languages = new_langs;
            fixes.push(CoherenceFix {
                field: "languages",
                old_value: old,
                new_value: new_str,
                reason: format!(
                    "Accept-Language not plausible for IP country '{}'",
                    geo.country_code
                ),
            });
        }
    }

    fn fix_touch(profile: &mut StealthProfile, fixes: &mut Vec<CoherenceFix>) {
        let is_mobile = ua_is_mobile(&profile.user_agent);

        if !is_mobile && profile.max_touch_points > 0 {
            let old = profile.max_touch_points.to_string();
            profile.max_touch_points = 0;
            fixes.push(CoherenceFix {
                field: "max_touch_points",
                old_value: old,
                new_value: "0".to_string(),
                reason: "Desktop UA should not report touch support".to_string(),
            });
        }

        if is_mobile && profile.max_touch_points == 0 {
            let old = "0".to_string();
            profile.max_touch_points = 5;
            fixes.push(CoherenceFix {
                field: "max_touch_points",
                old_value: old,
                new_value: "5".to_string(),
                reason: "Mobile UA must report touch support".to_string(),
            });
        }
    }

    fn fix_screen(profile: &mut StealthProfile, fixes: &mut Vec<CoherenceFix>) {
        let is_mobile = ua_is_mobile(&profile.user_agent);
        let (w, _h) = profile.viewport;

        if !is_mobile && w < 800 {
            let old = format!("{}x{}", profile.viewport.0, profile.viewport.1);
            profile.viewport = (1920, 1080);
            fixes.push(CoherenceFix {
                field: "viewport",
                old_value: old,
                new_value: "1920x1080".to_string(),
                reason: "Desktop UA had mobile-sized viewport".to_string(),
            });
        }

        if is_mobile && w > 500 {
            let is_tablet = profile.user_agent.contains("iPad") || (w >= 768 && w <= 1024);
            if !is_tablet {
                let old = format!("{}x{}", profile.viewport.0, profile.viewport.1);
                profile.viewport = (393, 852);
                fixes.push(CoherenceFix {
                    field: "viewport",
                    old_value: old,
                    new_value: "393x852".to_string(),
                    reason: "Mobile UA had desktop-sized viewport".to_string(),
                });
            }
        }
    }

    fn fix_gpu(profile: &mut StealthProfile, fixes: &mut Vec<CoherenceFix>) {
        let ua = &profile.user_agent;
        let renderer_upper = profile.webgl_renderer.to_uppercase();
        let is_mobile = ua_is_mobile(ua);

        // macOS with NVIDIA/AMD discrete GPU → replace with Apple GPU.
        if (ua.contains("Macintosh") || ua.contains("Mac OS"))
            && (renderer_upper.contains("NVIDIA")
                || renderer_upper.contains("GEFORCE")
                || renderer_upper.contains("RTX")
                || renderer_upper.contains("GTX")
                || renderer_upper.contains("AMD RADEON")
                || renderer_upper.contains("ATI RADEON"))
        {
            let old_vendor = profile.webgl_vendor.clone();
            let old_renderer = profile.webgl_renderer.clone();
            profile.webgl_vendor = "Google Inc. (Apple)".to_string();
            profile.webgl_renderer = "ANGLE (Apple, Apple M2, OpenGL 4.1)".to_string();
            fixes.push(CoherenceFix {
                field: "webgl_vendor",
                old_value: old_vendor,
                new_value: profile.webgl_vendor.clone(),
                reason: "macOS UA requires Apple GPU (no NVIDIA/AMD since Apple Silicon)"
                    .to_string(),
            });
            fixes.push(CoherenceFix {
                field: "webgl_renderer",
                old_value: old_renderer,
                new_value: profile.webgl_renderer.clone(),
                reason: "macOS UA requires Apple GPU renderer".to_string(),
            });
        }

        // Mobile UA with desktop discrete GPU → replace with mobile GPU.
        if is_mobile
            && (renderer_upper.contains("GEFORCE")
                || renderer_upper.contains("RTX")
                || renderer_upper.contains("GTX")
                || renderer_upper.contains("RADEON RX"))
        {
            let old_vendor = profile.webgl_vendor.clone();
            let old_renderer = profile.webgl_renderer.clone();
            if ua.contains("iPhone") || ua.contains("iPad") {
                profile.webgl_vendor = "Apple Inc.".to_string();
                profile.webgl_renderer = "Apple GPU".to_string();
            } else {
                profile.webgl_vendor = "Qualcomm".to_string();
                profile.webgl_renderer = "Adreno (TM) 740".to_string();
            }
            fixes.push(CoherenceFix {
                field: "webgl_vendor",
                old_value: old_vendor,
                new_value: profile.webgl_vendor.clone(),
                reason: "Mobile UA requires mobile GPU vendor".to_string(),
            });
            fixes.push(CoherenceFix {
                field: "webgl_renderer",
                old_value: old_renderer,
                new_value: profile.webgl_renderer.clone(),
                reason: "Mobile UA requires mobile GPU renderer".to_string(),
            });
        }
    }

    // -----------------------------------------------------------------------
    // Generate a fully coherent profile from GeoContext
    // -----------------------------------------------------------------------

    /// Generate a complete `StealthProfile` that is guaranteed to be internally
    /// consistent with the given network context.
    ///
    /// The generated profile is a Chrome desktop profile by default, matching
    /// the IP's country, timezone, and language expectations.
    pub fn generate_coherent_profile(geo: &GeoContext) -> StealthProfile {
        // Select timezone: prefer the geo-reported timezone if it's valid for
        // the country; otherwise pick the first mapped timezone.
        let valid_tzs = timezones_for_country(&geo.country_code);
        let timezone = if !geo.timezone.is_empty() && valid_tzs.contains(&geo.timezone.as_str()) {
            geo.timezone.clone()
        } else if !valid_tzs.is_empty() {
            valid_tzs[0].to_string()
        } else {
            // Fallback: use the geo-reported timezone or UTC.
            if geo.timezone.is_empty() {
                "Etc/UTC".to_string()
            } else {
                geo.timezone.clone()
            }
        };

        // Select languages.
        let country_langs = languages_for_country(&geo.country_code);
        let languages: Vec<String> = if country_langs.is_empty() {
            vec!["en-US".to_string(), "en".to_string()]
        } else {
            let mut langs: Vec<String> = country_langs
                .iter()
                .take(3)
                .map(|s| s.to_string())
                .collect();
            if !langs.iter().any(|l| l.starts_with("en")) {
                langs.push("en".to_string());
            }
            langs
        };

        // Select locale (first language with region subtag, or "en-US").
        let locale = languages
            .iter()
            .find(|l| l.contains('-'))
            .cloned()
            .unwrap_or_else(|| "en-US".to_string());

        // For mobile IPs, generate a mobile profile.
        if geo.is_mobile {
            return StealthProfile {
                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
                             (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36"
                    .to_string(),
                platform: "Linux armv81".to_string(),
                vendor: "Google Inc.".to_string(),
                languages,
                hardware_concurrency: 8,
                device_memory: 8.0,
                max_touch_points: 5,
                viewport: (412, 915),
                device_scale_factor: 2.625,
                webgl_vendor: "Qualcomm".to_string(),
                webgl_renderer: "Adreno (TM) 740".to_string(),
                timezone,
                locale,
                canvas_noise_seed: hash_seed(&geo.ip),
                is_firefox_profile: false,
            };
        }

        // Desktop Chrome on Windows (most common desktop fingerprint globally).
        StealthProfile {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
                .to_string(),
            platform: "Win32".to_string(),
            vendor: "Google Inc.".to_string(),
            languages,
            hardware_concurrency: 8,
            device_memory: 8.0,
            max_touch_points: 0,
            viewport: (1920, 1080),
            device_scale_factor: 1.0,
            webgl_vendor: "Google Inc. (NVIDIA)".to_string(),
            webgl_renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 \
                             ps_5_0, D3D11)"
                .to_string(),
            timezone,
            locale,
            canvas_noise_seed: hash_seed(&geo.ip),
            is_firefox_profile: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Whether the UA indicates a mobile device.
fn ua_is_mobile(ua: &str) -> bool {
    ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone") || ua.contains("iPad")
}

/// Simple hash of a string into a u64 seed (for canvas noise uniqueness per IP).
fn hash_seed(s: &str) -> u64 {
    // FNV-1a 64-bit
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ---------------------------------------------------------------------------
// Client-stack coherence — non-browser TLS/QUIC clients (ag03 R-2 / U-102)
// ---------------------------------------------------------------------------
//
// The checks above audit a *browser* fingerprint. Tallow's own non-browser
// clients — the TCP+TLS and QUIC relay transports in `tallow-net` — have no
// browser fingerprint, but they do have a declared *wire* fingerprint: the
// pinned JA4 client cohort (`crates/tallow-net/src/transport/tls_cohort.rs`,
// `JA4_COHORT_V1`) and the frozen QUIC transport parameters built by
// `crates/tallow-net/src/transport/tls_config.rs`. The checks below validate
// the configuration a tallow-net client actually builds against that
// declaration, so cohort drift (rustls/provider upgrade, cipher / curve /
// sigalg / ALPN edits) and QUIC transport-parameter drift surface at audit
// time instead of silently changing what peers observe.

/// Transport of a non-browser client stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTransport {
    /// TCP + TLS (tokio-rustls path; `tallow-net` `transport/tcp_tls.rs`).
    TcpTls,
    /// QUIC over UDP (quinn path; requires the `quic` feature in tallow-net).
    Quic,
}

/// QUIC transport parameters as configured by tallow-net's client
/// (`transport/tls_config.rs::quinn_client_config`) or observed on the wire.
///
/// Plain data, so the audit compiles with or without the tallow-net `quic`
/// feature. Where that feature is compiled, live values come from the
/// recorded accessor patch (see U-102 evidence §Recorded patch) — quinn's
/// `TransportConfig` exposes no public getters for these fields in 0.11.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicTransportParams {
    /// `max_idle_timeout` in whole seconds; `None` = not configured.
    pub max_idle_timeout_secs: Option<u64>,
    /// `keep_alive_interval` in whole seconds; `None` = keep-alive disabled.
    pub keep_alive_interval_secs: Option<u64>,
}

impl QuicTransportParams {
    /// The parameters tallow-net's relay client is declared to use.
    ///
    /// Mirrors `crates/tallow-net/src/transport/tls_config.rs`
    /// (`quinn_client_config`, compiled into the real `quinn::ClientConfig`
    /// under the `quic` feature): 300 s idle timeout, 15 s keep-alive — sized
    /// so connections survive while peers wait for each other in relay rooms.
    pub fn tallow_relay_client() -> Self {
        Self {
            max_idle_timeout_secs: Some(300),
            keep_alive_interval_secs: Some(15),
        }
    }
}

/// Legacy (pre-1.3 era) key-exchange groups; presence indicates config decay.
const LEGACY_GROUPS: &[u16] = &[
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c,
    0x000d, 0x000e, // binary/sect curves
    0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, // secp160k1 … secp256k1
];

/// Declared (intended) wire configuration of a non-browser client stack.
///
/// This is the machine-checkable form of "what our client is supposed to look
/// like on the wire"; it is compared against a [`TlsClientObservation`]
/// captured from the config the code actually builds.
#[derive(Debug, Clone)]
pub struct DeclaredClientProfile {
    /// Human-readable name used in warning messages.
    pub name: &'static str,
    /// Transport the client is declared to use.
    pub transport: ClientTransport,
    /// Declared JA4 cohort id (`tallow-net`: `tls_cohort::JA4_COHORT_ID`).
    pub cohort: &'static str,
    /// Declared TLS provider (`tallow-net`: `tls_cohort::COHORT_PROVIDER`).
    pub provider: &'static str,
    /// Posture: TLS 1.3 must be offered.
    pub require_tls13: bool,
    /// Whether TLS 1.2 cipher suites may be offered (TCP only; QUIC never).
    pub allow_tls12: bool,
    /// Minimum number of TLS 1.3 cipher suites that must be offered.
    pub min_tls13_ciphers: usize,
    /// Key-exchange groups that must be offered.
    pub required_groups: Vec<u16>,
    /// Legacy groups whose presence indicates config decay.
    pub forbidden_groups: Vec<u16>,
    /// Whether MD5/SHA-1-based signature algorithms are rejected.
    pub forbid_sha1_sigalgs: bool,
    /// Require a key_share so TLS 1.3 completes without a HelloRetryRequest
    /// round trip (a round trip is itself observable and adds a fingerprint).
    pub require_key_share: bool,
    /// ALPN protocols the client is declared to offer (empty = none offered).
    pub alpn: Vec<String>,
    /// Whether RFC 8701 GREASE values are acceptable in the hello.
    pub allow_grease: bool,
    /// Extension-ID set expected in the hello; empty = no drift check.
    pub expected_extensions: Vec<u16>,
    /// Declared QUIC transport parameters (QUIC transport only).
    pub quic_params: Option<QuicTransportParams>,
}

impl DeclaredClientProfile {
    /// Declared profile of the tallow-net relay client over TCP+TLS.
    ///
    /// Tracks the pinned `JA4_COHORT_V1` TCP render
    /// (`tls_cohort::JA4_COHORT_V1_TCP`); the audit harness cross-checks the
    /// extension set against that constant so a re-pin cannot silently diverge
    /// from this declaration.
    pub fn tallow_relay_tcp() -> Self {
        Self {
            name: "tallow-relay-client/tcp",
            transport: ClientTransport::TcpTls,
            cohort: tls_cohort::JA4_COHORT_ID,
            provider: tls_cohort::COHORT_PROVIDER,
            require_tls13: true,
            allow_tls12: true,
            min_tls13_ciphers: 3,
            required_groups: vec![0x001d],
            forbidden_groups: LEGACY_GROUPS.to_vec(),
            forbid_sha1_sigalgs: true,
            require_key_share: true,
            alpn: Vec::new(),
            allow_grease: false,
            expected_extensions: vec![
                0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0017, 0x0023, 0x002b, 0x002d, 0x0033,
            ],
            quic_params: None,
        }
    }

    /// Declared profile of the tallow-net relay client over QUIC.
    ///
    /// Tracks the pinned `JA4_COHORT_V1` QUIC render
    /// (`tls_cohort::JA4_COHORT_V1_QUIC`); QUIC additionally carries the
    /// transport_parameters extension (0x0039), may never offer pre-TLS-1.3
    /// cipher suites, and — as of the 2026-09-16 re-pin (rustls ≥0.23.45 /
    /// quinn ≥0.11.12) — no longer offers session_ticket (0x0023).
    pub fn tallow_relay_quic() -> Self {
        Self {
            name: "tallow-relay-client/quic",
            transport: ClientTransport::Quic,
            cohort: tls_cohort::JA4_COHORT_ID,
            provider: tls_cohort::COHORT_PROVIDER,
            require_tls13: true,
            allow_tls12: false,
            min_tls13_ciphers: 3,
            required_groups: vec![0x001d],
            forbidden_groups: LEGACY_GROUPS.to_vec(),
            forbid_sha1_sigalgs: true,
            require_key_share: true,
            alpn: Vec::new(),
            allow_grease: false,
            expected_extensions: vec![
                0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0017, 0x002b, 0x002d, 0x0033, 0x0039,
            ],
            quic_params: Some(QuicTransportParams::tallow_relay_client()),
        }
    }
}

/// Wire-level observation of a non-browser client stack.
///
/// Captured from the configuration the code actually builds — for tallow-net
/// via [`TlsClientObservation::from_cohort`] over a `tls_cohort::ja4_cohort_v1`
/// capture (offline: rustls writes its ClientHello to a buffer, no network).
#[derive(Debug, Clone)]
pub struct TlsClientObservation {
    /// Transport the observation was captured from.
    pub transport: ClientTransport,
    /// Cohort tag the capture reports (`tls_cohort::JA4_COHORT_ID`).
    pub cohort: String,
    /// TLS provider tag the capture reports.
    pub provider: String,
    /// ClientHello `legacy_version`.
    pub legacy_version: u16,
    /// Whether TLS 1.3 is offered in supported_versions.
    pub tls13_offered: bool,
    /// Offered cipher suites (wire values, GREASE included).
    pub ciphers: Vec<u16>,
    /// Offered extension IDs.
    pub extensions: Vec<u16>,
    /// supported_groups (curves).
    pub groups: Vec<u16>,
    /// signature_algorithms.
    pub sigalgs: Vec<u16>,
    /// Offered ALPN protocols (empty = none).
    pub alpn: Vec<String>,
    /// key_share group IDs.
    pub key_share_groups: Vec<u16>,
    /// True if GREASE values appear anywhere in the hello.
    pub grease_present: bool,
    /// Full `a_b_c` fingerprint of the captured hello.
    pub ja4: String,
    /// Observed QUIC transport parameters, when captured (QUIC only).
    pub quic_params: Option<QuicTransportParams>,
}

impl TlsClientObservation {
    /// Build an observation from a captured tallow-net JA4 cohort.
    pub fn from_cohort(cohort: &Ja4CohortV1, transport: ClientTransport) -> Self {
        Self {
            transport,
            cohort: cohort.cohort.to_string(),
            provider: cohort.provider.to_string(),
            legacy_version: cohort.legacy_version,
            tls13_offered: cohort.tls13_offered,
            ciphers: cohort.ciphers.clone(),
            extensions: cohort.extensions.clone(),
            groups: cohort.groups.clone(),
            sigalgs: cohort.sigalgs.clone(),
            alpn: cohort.alpn.clone(),
            key_share_groups: cohort.key_share_groups.clone(),
            grease_present: cohort.grease_present,
            ja4: cohort.ja4(),
            quic_params: None,
        }
    }

    /// Attach observed QUIC transport parameters (read from a built
    /// `quinn::ClientConfig` where the tallow-net `quic` feature is compiled —
    /// see U-102 evidence §Recorded patch).
    pub fn with_quic_params(mut self, params: QuicTransportParams) -> Self {
        self.quic_params = Some(params);
        self
    }
}

/// Validates coherence between a declared non-browser client profile and the
/// wire configuration the client actually builds (ag03 R-2 / matrix row #5).
///
/// Sibling of [`CoherenceValidator`] (browser side), invoked from it via
/// [`CoherenceValidator::validate_client_stack`]. Warning vectors used:
/// `declared_profile`, `transport`, `tls_cohort`, `tls_version`,
/// `tls_cipher_suites`, `legacy_cipher`, `tls_groups`, `legacy_group`,
/// `key_share`, `tls_sigalgs`, `legacy_sigalg`, `alpn`, `grease`,
/// `extension_set`, `quic_transport_params`.
pub struct ClientStackValidator;

impl ClientStackValidator {
    /// Run all client-stack coherence checks.
    pub fn validate(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
    ) -> CoherenceReport {
        let mut warnings = Vec::new();

        Self::check_transport(declared, observed, &mut warnings);
        Self::check_cohort_identity(declared, observed, &mut warnings);
        Self::check_versions(declared, observed, &mut warnings);
        Self::check_ciphers(declared, observed, &mut warnings);
        Self::check_groups(declared, observed, &mut warnings);
        Self::check_sigalgs(declared, observed, &mut warnings);
        Self::check_alpn(declared, observed, &mut warnings);
        Self::check_grease(declared, observed, &mut warnings);
        Self::check_extension_set(declared, observed, &mut warnings);
        Self::check_quic(declared, observed, &mut warnings);

        CoherenceReport::from_warnings(warnings)
    }

    fn check_transport(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if declared.transport != observed.transport {
            warnings.push(warn_critical(
                vec!["declared_profile", "transport"],
                format!(
                    "Client stack '{}' is declared as {:?} but the observation was captured \
                     from {:?} — the audit would compare two different stacks",
                    declared.name, declared.transport, observed.transport
                ),
            ));
        }
    }

    fn check_cohort_identity(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if observed.cohort != declared.cohort {
            warnings.push(warn_warning(
                vec!["tls_cohort", "declared_profile"],
                format!(
                    "Client stack '{}' declares cohort '{}' but the built client reports '{}' \
                     (JA4 {}) — cohort drift changes what peers observe and must be a \
                     deliberate re-pin",
                    declared.name, declared.cohort, observed.cohort, observed.ja4
                ),
            ));
        }
        if observed.provider != declared.provider {
            warnings.push(warn_warning(
                vec!["tls_cohort", "declared_profile"],
                format!(
                    "Client stack '{}' declares provider '{}' but the built client uses '{}'",
                    declared.name, declared.provider, observed.provider
                ),
            ));
        }
    }

    fn check_versions(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if declared.require_tls13 && !observed.tls13_offered {
            warnings.push(warn_critical(
                vec!["tls_version", "declared_profile"],
                format!(
                    "Client stack '{}' requires TLS 1.3 but the ClientHello (JA4 {}) does not \
                     offer it — version drift downgrades the whole cohort",
                    declared.name, observed.ja4
                ),
            ));
        }
        if observed.tls13_offered && observed.legacy_version != 0x0303 {
            warnings.push(warn_warning(
                vec!["tls_version", "tls_cohort"],
                format!(
                    "Client stack '{}' offers TLS 1.3 with legacy_version 0x{:04x} \
                     (expected 0x0303) — middlebox/ossification checks may flag this",
                    declared.name, observed.legacy_version
                ),
            ));
        }
    }

    fn check_ciphers(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        let ciphers: Vec<u16> = observed
            .ciphers
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();

        if ciphers.is_empty() {
            warnings.push(warn_critical(
                vec!["tls_cipher_suites"],
                format!(
                    "Client stack '{}' offers no cipher suites — malformed ClientHello",
                    declared.name
                ),
            ));
            return;
        }

        let tls13_count = ciphers
            .iter()
            .filter(|c| (0x1301..=0x1305).contains(*c))
            .count();
        if tls13_count < declared.min_tls13_ciphers {
            warnings.push(warn_critical(
                vec!["tls_cipher_suites", "declared_profile"],
                format!(
                    "Client stack '{}' offers {} TLS 1.3 cipher suite(s), declared minimum is \
                     {} — the JA4_b cipher digest shifted",
                    declared.name, tls13_count, declared.min_tls13_ciphers
                ),
            ));
        }

        // 0x00ff is the TLS 1.2 renegotiation SCSV pseudo-suite, not a real offer.
        let legacy: Vec<u16> = ciphers
            .iter()
            .copied()
            .filter(|c| !(0x1301..=0x1305).contains(c) && *c != 0x00ff)
            .collect();

        if observed.transport == ClientTransport::Quic && !legacy.is_empty() {
            warnings.push(warn_critical(
                vec!["tls_cipher_suites", "quic"],
                format!(
                    "QUIC ClientHello for '{}' offers pre-TLS-1.3 suite(s) {} — QUIC must only \
                     offer TLS 1.3 suites; wire-incoherent with the declared QUIC profile",
                    declared.name,
                    hex_list(&legacy)
                ),
            ));
        } else if !declared.allow_tls12 && !legacy.is_empty() {
            warnings.push(warn_warning(
                vec!["tls_cipher_suites", "legacy_cipher"],
                format!(
                    "Client stack '{}' declares no TLS 1.2 suites but offers {}",
                    declared.name,
                    hex_list(&legacy)
                ),
            ));
        }
    }

    fn check_groups(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        let groups: Vec<u16> = observed
            .groups
            .iter()
            .copied()
            .filter(|g| !is_grease(*g))
            .collect();

        for &g in &declared.required_groups {
            if !groups.contains(&g) {
                warnings.push(warn_warning(
                    vec!["tls_groups", "declared_profile"],
                    format!(
                        "Client stack '{}' must offer key-exchange group 0x{:04x} but the hello \
                         offers {} — forward secrecy / handshake posture drifted",
                        declared.name,
                        g,
                        hex_list(&groups)
                    ),
                ));
            }
        }

        let legacy: Vec<u16> = groups
            .iter()
            .copied()
            .filter(|g| declared.forbidden_groups.contains(g))
            .collect();
        if !legacy.is_empty() {
            warnings.push(warn_warning(
                vec!["tls_groups", "legacy_group"],
                format!(
                    "Client stack '{}' offers legacy curve(s) {} — config decay, re-verify the \
                     provider defaults",
                    declared.name,
                    hex_list(&legacy)
                ),
            ));
        }

        if declared.require_key_share {
            if observed.key_share_groups.is_empty() {
                warnings.push(warn_warning(
                    vec!["tls_groups", "key_share"],
                    format!(
                        "Client stack '{}' sends no key_share — the TLS 1.3 handshake would \
                         need a HelloRetryRequest round trip (observable extra flight)",
                        declared.name
                    ),
                ));
            }
            for &ks in &observed.key_share_groups {
                if !groups.contains(&ks) {
                    warnings.push(warn_warning(
                        vec!["tls_groups", "key_share"],
                        format!(
                            "Client stack '{}' shares a key for group 0x{:04x} that is not in \
                             supported_groups {} — malformed hello",
                            declared.name,
                            ks,
                            hex_list(&groups)
                        ),
                    ));
                }
            }
        }
    }

    fn check_sigalgs(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        let sigalgs: Vec<u16> = observed
            .sigalgs
            .iter()
            .copied()
            .filter(|s| !is_grease(*s))
            .collect();

        if sigalgs.is_empty() {
            warnings.push(warn_warning(
                vec!["tls_sigalgs"],
                format!(
                    "Client stack '{}' offers no signature algorithms — TLS 1.3 certificate \
                     verification would fail; malformed hello",
                    declared.name
                ),
            ));
            return;
        }

        if declared.forbid_sha1_sigalgs {
            // MD5 (0x010x) and SHA-1 (0x020x) family signature algorithms.
            const WEAK: &[u16] = &[0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202, 0x0203];
            let weak: Vec<u16> = sigalgs
                .iter()
                .copied()
                .filter(|s| WEAK.contains(s))
                .collect();
            if !weak.is_empty() {
                warnings.push(warn_warning(
                    vec!["tls_sigalgs", "legacy_sigalg"],
                    format!(
                        "Client stack '{}' offers MD5/SHA-1 signature algorithm(s) {} — declared \
                         profile rejects them",
                        declared.name,
                        hex_list(&weak)
                    ),
                ));
            }
        }
    }

    fn check_alpn(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        let offered: Vec<&str> = observed.alpn.iter().map(|s| s.as_str()).collect();
        let declared_alpn: Vec<&str> = declared.alpn.iter().map(|s| s.as_str()).collect();
        let missing = declared_alpn
            .iter()
            .any(|p| !offered.contains(p));
        let extra = offered.iter().any(|p| !declared_alpn.contains(p));

        if missing || extra {
            warnings.push(warn_warning(
                vec!["alpn", "declared_profile"],
                format!(
                    "Client stack '{}' declares ALPN {:?} but the hello offers {:?} — ALPN is \
                     visible in the JA4_a segment and to every peer",
                    declared.name, declared.alpn, observed.alpn
                ),
            ));
        }
    }

    fn check_grease(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if observed.grease_present && !declared.allow_grease {
            warnings.push(warn_info(
                vec!["tls_cohort", "grease"],
                format!(
                    "Client stack '{}' hello contains RFC 8701 GREASE values though the \
                     profile is declared GREASE-free — JA4_b / JA4_c change; re-pin the \
                     cohort deliberately",
                    declared.name
                ),
            ));
        }
    }

    fn check_extension_set(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        if declared.expected_extensions.is_empty() {
            return;
        }
        use std::collections::BTreeSet;

        let expected: BTreeSet<u16> = declared
            .expected_extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect();
        let actual: BTreeSet<u16> = observed
            .extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect();

        if expected != actual {
            let missing: Vec<u16> = expected.difference(&actual).copied().collect();
            let added: Vec<u16> = actual.difference(&expected).copied().collect();
            warnings.push(warn_info(
                vec!["tls_cohort", "extension_set"],
                format!(
                    "Client stack '{}' extension set drifted from the declared cohort: missing \
                     {}, added {} — re-pin JA4_COHORT_V1 deliberately if intended",
                    declared.name,
                    hex_list(&missing),
                    hex_list(&added)
                ),
            ));
        }
    }

    fn check_quic(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
        warnings: &mut Vec<FingerprintWarning>,
    ) {
        let has_transport_params_ext = observed.extensions.contains(&0x0039);
        match observed.transport {
            ClientTransport::Quic => {
                if !has_transport_params_ext {
                    warnings.push(warn_warning(
                        vec!["quic_transport_params", "tls_cohort"],
                        format!(
                            "QUIC hello for '{}' does not carry the QUIC transport_parameters \
                             extension (0x0039) — a live quinn handshake always sends it",
                            declared.name
                        ),
                    ));
                }
            }
            ClientTransport::TcpTls => {
                if has_transport_params_ext {
                    warnings.push(warn_warning(
                        vec!["quic_transport_params", "tls_cohort"],
                        format!(
                            "TCP+TLS hello for '{}' carries the QUIC transport_parameters \
                             extension (0x0039) — incoherent transport configuration",
                            declared.name
                        ),
                    ));
                }
            }
        }

        if observed.transport != ClientTransport::Quic {
            return;
        }
        let Some(declared_params) = declared.quic_params else {
            return;
        };
        let Some(observed_params) = observed.quic_params else {
            warnings.push(warn_info(
                vec!["quic_transport_params", "declared_profile"],
                format!(
                    "QUIC transport parameters for '{}' were not captured (declared: idle {:?} s, \
                     keep-alive {:?} s) — live values unverified",
                    declared.name,
                    declared_params.max_idle_timeout_secs,
                    declared_params.keep_alive_interval_secs
                ),
            ));
            return;
        };

        if observed_params.max_idle_timeout_secs != declared_params.max_idle_timeout_secs {
            warnings.push(warn_warning(
                vec!["quic_transport_params", "declared_profile"],
                format!(
                    "QUIC max_idle_timeout is {:?} s but declared {:?} s — relay peers waiting \
                     for each other may outlive the connection",
                    observed_params.max_idle_timeout_secs, declared_params.max_idle_timeout_secs
                ),
            ));
        }
        if observed_params.keep_alive_interval_secs != declared_params.keep_alive_interval_secs {
            warnings.push(warn_warning(
                vec!["quic_transport_params", "declared_profile"],
                format!(
                    "QUIC keep_alive_interval is {:?} s but declared {:?} s",
                    observed_params.keep_alive_interval_secs,
                    declared_params.keep_alive_interval_secs
                ),
            ));
        }
        if let (Some(ka), Some(idle)) = (
            observed_params.keep_alive_interval_secs,
            observed_params.max_idle_timeout_secs,
        ) {
            if ka >= idle {
                warnings.push(warn_warning(
                    vec!["quic_transport_params"],
                    format!(
                        "QUIC keep_alive_interval ({} s) must fire before max_idle_timeout \
                         ({} s) — keep-alive would never run",
                        ka, idle
                    ),
                ));
            }
        }
    }
}

/// Render a slice of TLS u16 wire values as `0x…` hex.
fn hex_list(values: &[u16]) -> String {
    if values.is_empty() {
        return "(none)".to_string();
    }
    values
        .iter()
        .map(|v| format!("0x{:04x}", v))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// CoherenceValidator — client-stack integration (ag03 R-2 / U-102)
// ---------------------------------------------------------------------------

impl CoherenceValidator {
    /// Audit a non-browser client stack's wire configuration against its
    /// declared profile. Delegates to [`ClientStackValidator`].
    pub fn validate_client_stack(
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
    ) -> CoherenceReport {
        ClientStackValidator::validate(declared, observed)
    }

    /// Capture the real tallow-net client cohort for `declared.transport` and
    /// audit it against `declared` — the runtime half of the fingerprint audit.
    ///
    /// `observed_quic_params` carries QUIC transport parameters read from the
    /// built client config where the tallow-net `quic` feature is compiled
    /// (ignored for TCP). No network I/O: rustls emits its ClientHello offline.
    pub fn audit_tallow_client(
        declared: &DeclaredClientProfile,
        observed_quic_params: Option<QuicTransportParams>,
    ) -> Result<CoherenceReport, String> {
        let transport = match declared.transport {
            ClientTransport::TcpTls => Ja4Transport::Tcp,
            ClientTransport::Quic => Ja4Transport::Quic,
        };
        let cohort = tls_cohort::ja4_cohort_v1(transport)?;
        let mut observed = TlsClientObservation::from_cohort(&cohort, declared.transport);
        if declared.transport == ClientTransport::Quic {
            observed.quic_params = observed_quic_params;
        }
        Ok(ClientStackValidator::validate(declared, &observed))
    }

    /// Full-stack audit: browser-profile coherence ([`Self::validate`]) merged
    /// with the non-browser client-stack audit ([`Self::validate_client_stack`]).
    pub fn validate_with_client_stack(
        profile: &StealthProfile,
        geo: &GeoContext,
        tls_browser: Option<TlsBrowser>,
        declared: &DeclaredClientProfile,
        observed: &TlsClientObservation,
    ) -> CoherenceReport {
        let mut report = Self::validate(profile, geo, tls_browser);
        report
            .warnings
            .extend(ClientStackValidator::validate(declared, observed).warnings);
        CoherenceReport::from_warnings(report.warnings)
    }
}

// ---------------------------------------------------------------------------
// Effective-config coherence (P1 C2) — cross-config fail-loud checker
// ---------------------------------------------------------------------------

/// The effective browser-config values a coherence check runs over.
///
/// Assembled by the caller: the `tallow fingerprint-audit --coherence` CLI
/// loads the live `~/.tallow/browser/config/*.toml` set; tests construct it
/// directly. Every field is what the *run path* would actually use — the
/// check is about the effective configuration, not the file bytes.
#[derive(Debug, Clone)]
pub struct EffectiveConfigSnapshot {
    /// The stealth profile the run path resolves (preset, `[custom]`, or
    /// declared-bot).
    pub profile: StealthProfile,
    /// `tor.toml [tor] isolate_by_domain` — `None` when the artifact is absent.
    pub tor_isolate_by_domain: Option<bool>,
    /// `session.toml [cookies] block_third_party` — `None` when absent.
    pub block_third_party: Option<bool>,
    /// Tor-cohort timezone policy: the deployment default is UTC (mirrors the
    /// Camoufox reader pin). Set `false` only for a geo-aligned persona.
    pub expect_utc: bool,
}

/// Cross-config coherence check for the effective browser configuration
/// (P1 C2). Fail-loud: every returned warning is an actionable finding; the
/// CLI maps any non-empty report to exit code 2.
///
/// Checks (all on the effective config, see [`EffectiveConfigSnapshot`]):
/// - internal cross-vector consistency (UA ↔ platform ↔ WebGL ↔ fonts) via
///   [`crate::browser::fingerprint_validator::FingerprintValidator::validate`];
/// - canvas noise seed is nonzero (a literal `0` is a fleet-uniform seed);
/// - timezone/locale/languages nonempty, locale consistent with languages,
///   the UTC cohort default honored (or explicitly geo-justified);
/// - Tor per-domain circuit isolation and first-party cookie isolation are on
///   when the artifact expresses them.
pub fn check_effective_config(snapshot: &EffectiveConfigSnapshot) -> CoherenceReport {
    let profile = &snapshot.profile;
    let mut warnings: Vec<FingerprintWarning> =
        crate::browser::fingerprint_validator::FingerprintValidator::validate(profile);

    if profile.canvas_noise_seed == 0 {
        warnings.push(FingerprintWarning {
            severity: Severity::Critical,
            vectors: vec!["canvas_noise_seed", "fleet_uniformity"],
            message: "canvas noise seed is 0 — a fleet-uniform seed produces identical \
                      deterministic noise on every instance (cluster signal). Give the \
                      persona a unique nonzero seed (P1 C1)."
                .to_string(),
        });
    }
    if profile.timezone.trim().is_empty() {
        warnings.push(FingerprintWarning {
            severity: Severity::Critical,
            vectors: vec!["timezone"],
            message: "timezone is empty — the host timezone would leak; pin UTC for \
                      the Tor cohort (P1 C1)."
                .to_string(),
        });
    } else if snapshot.expect_utc && profile.timezone != "UTC" {
        warnings.push(FingerprintWarning {
            severity: Severity::Warning,
            vectors: vec!["timezone", "tor_cohort"],
            message: format!(
                "timezone '{}' is not UTC — allowed only for a fully geo-consistent \
                 persona (per-exit alignment); the Tor cohort default is UTC.",
                profile.timezone
            ),
        });
    }
    if profile.locale.trim().is_empty() {
        warnings.push(FingerprintWarning {
            severity: Severity::Critical,
            vectors: vec!["locale"],
            message: "locale is empty — an empty Accept-Language diverges from any \
                      real browser (P1 C1)."
                .to_string(),
        });
    }
    if profile.languages.is_empty() {
        warnings.push(FingerprintWarning {
            severity: Severity::Critical,
            vectors: vec!["languages"],
            message: "navigator.languages is empty (P1 C1).".to_string(),
        });
    } else if !profile.locale.trim().is_empty() {
        let base = profile.locale.split('-').next().unwrap_or_default();
        let consistent = profile
            .languages
            .iter()
            .any(|l| l == &profile.locale || l.split('-').next() == Some(base));
        if !consistent {
            warnings.push(FingerprintWarning {
                severity: Severity::Warning,
                vectors: vec!["locale", "languages"],
                message: format!(
                    "locale '{}' is not present in languages {:?} — the \
                     Accept-Language header and navigator.languages disagree.",
                    profile.locale, profile.languages
                ),
            });
        }
    }
    if snapshot.tor_isolate_by_domain == Some(false) {
        warnings.push(FingerprintWarning {
            severity: Severity::Warning,
            vectors: vec!["tor", "isolate_by_domain"],
            message: "tor.toml isolate_by_domain=false — every target shares one \
                      circuit; per-domain isolation is the box default (one target \
                      = one circuit, P1 E4)."
                .to_string(),
        });
    }
    if snapshot.block_third_party == Some(false) {
        warnings.push(FingerprintWarning {
            severity: Severity::Warning,
            vectors: vec!["session", "block_third_party"],
            message: "session.toml block_third_party=false — third-party cookies \
                      re-enable cross-site state (P0-2 set this true; do not \
                      regress)."
                .to_string(),
        });
    }

    CoherenceReport::from_warnings(warnings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn us_houston_geo() -> GeoContext {
        GeoContext::us_residential("Houston", "Texas", "America/Chicago")
    }

    fn de_berlin_geo() -> GeoContext {
        GeoContext {
            ip: "94.130.100.1".to_string(),
            country_code: "DE".to_string(),
            region: "Berlin".to_string(),
            city: "Berlin".to_string(),
            timezone: "Europe/Berlin".to_string(),
            latitude: 52.52,
            longitude: 13.405,
            asn: 24940,
            asn_org: "Hetzner Online GmbH".to_string(),
            is_datacenter: true,
            is_residential: false,
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

    // -- Timezone checks --

    #[test]
    fn valid_us_timezone_passes() {
        let profile = StealthProfile::chrome_windows();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"timezone") && w.severity == Severity::Critical),
            "America/New_York should be valid for US: {:?}",
            report.warnings,
        );
    }

    #[test]
    fn german_timezone_from_us_ip_flagged() {
        let mut profile = StealthProfile::chrome_windows();
        profile.timezone = "Europe/Berlin".to_string();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"timezone") && w.severity == Severity::Critical),
            "Europe/Berlin from US IP should be critical"
        );
    }

    #[test]
    fn us_timezone_from_german_ip_flagged() {
        let profile = StealthProfile::chrome_windows(); // America/New_York
        let geo = de_berlin_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"timezone") && w.severity == Severity::Critical),
            "America/New_York from DE IP should be critical"
        );
    }

    // -- Locale / Language checks --

    #[test]
    fn english_from_us_ip_is_fine() {
        let profile = StealthProfile::chrome_windows();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"accept_language")),
            "en-US from US IP should be fine"
        );
    }

    #[test]
    fn japanese_from_us_ip_flagged() {
        let mut profile = StealthProfile::chrome_windows();
        profile.languages = vec!["ja-JP".to_string(), "ja".to_string()];
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"accept_language")),
            "ja-JP from US IP should trigger a warning"
        );
    }

    #[test]
    fn english_from_japan_ip_is_fine() {
        // English is acceptable from any country (expats).
        let profile = StealthProfile::chrome_windows();
        let geo = jp_tokyo_geo();
        // Timezone will be flagged but language should be fine.
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"accept_language")
                    && w.vectors.contains(&"ip_geolocation")),
            "English from JP IP is acceptable"
        );
    }

    // -- TLS fingerprint checks --

    #[test]
    fn chrome_ua_with_firefox_tls_flagged() {
        let profile = StealthProfile::chrome_windows();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Firefox));
        assert!(
            report.warnings.iter().any(|w|
                w.vectors.contains(&"tls_fingerprint") && w.severity == Severity::Critical
            ),
            "Chrome UA with Firefox TLS fingerprint should be critical"
        );
    }

    #[test]
    fn chrome_ua_with_chrome_tls_passes() {
        let profile = StealthProfile::chrome_windows();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"tls_fingerprint")),
            "Chrome UA with Chrome TLS should pass"
        );
    }

    // -- GPU + platform checks --

    #[test]
    fn nvidia_on_macos_flagged() {
        let mut profile = StealthProfile::chrome_macos();
        profile.webgl_vendor = "Google Inc. (NVIDIA)".to_string();
        profile.webgl_renderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.1)".to_string();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"webgl_renderer") && w.severity == Severity::Critical),
            "NVIDIA GPU on macOS should be critical"
        );
    }

    // -- ASN checks --

    #[test]
    fn datacenter_ip_flagged() {
        let profile = StealthProfile::chrome_windows();
        let geo = de_berlin_geo(); // Hetzner, is_datacenter: true
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"ip_asn")),
            "Datacenter IP should trigger ASN warning"
        );
    }

    #[test]
    fn residential_ip_no_asn_warning() {
        let mut profile = StealthProfile::chrome_windows();
        profile.timezone = "America/Chicago".to_string();
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"ip_asn")),
            "Residential IP should not trigger ASN warning"
        );
    }

    // -- Touch + Screen checks --

    #[test]
    fn touch_on_desktop_flagged() {
        let mut profile = StealthProfile::chrome_windows();
        profile.max_touch_points = 5;
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"max_touch_points")),
        );
    }

    #[test]
    fn no_touch_on_mobile_critical() {
        let mut profile = StealthProfile::mobile_android();
        profile.max_touch_points = 0;
        let geo = us_houston_geo();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report.warnings.iter().any(
                |w| w.vectors.contains(&"max_touch_points") && w.severity == Severity::Critical
            ),
        );
    }

    // -- Auto-fix tests --

    #[test]
    fn auto_fix_timezone_for_country() {
        let mut profile = StealthProfile::chrome_windows();
        profile.timezone = "Asia/Tokyo".to_string();
        let geo = us_houston_geo();
        let fixes = CoherenceValidator::auto_fix_profile(&mut profile, &geo);
        assert!(fixes.iter().any(|f| f.field == "timezone"));
        assert!(timezones_for_country("US").contains(&profile.timezone.as_str()));
    }

    #[test]
    fn auto_fix_languages_for_country() {
        let mut profile = StealthProfile::chrome_windows();
        profile.languages = vec!["pt-BR".to_string(), "pt".to_string()];
        let geo = jp_tokyo_geo();
        let fixes = CoherenceValidator::auto_fix_profile(&mut profile, &geo);
        assert!(fixes.iter().any(|f| f.field == "languages"));
        let base = profile.languages[0].split('-').next().unwrap_or("");
        let jp_langs = languages_for_country("JP");
        let ok = jp_langs
            .iter()
            .any(|l| l.split('-').next().unwrap_or("") == base)
            || base == "en";
        assert!(
            ok,
            "Languages should match JP after fix: {:?}",
            profile.languages
        );
    }

    #[test]
    fn auto_fix_touch_on_desktop() {
        let mut profile = StealthProfile::chrome_windows();
        profile.max_touch_points = 5;
        let geo = us_houston_geo();
        let fixes = CoherenceValidator::auto_fix_profile(&mut profile, &geo);
        assert!(fixes.iter().any(|f| f.field == "max_touch_points"));
        assert_eq!(profile.max_touch_points, 0);
    }

    // -- Generate coherent profile tests --

    #[test]
    fn generated_profile_is_coherent_us() {
        let geo = us_houston_geo();
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report.is_safe(),
            "Generated US profile should have no critical issues: {:?}",
            report.warnings,
        );
    }

    #[test]
    fn generated_profile_is_coherent_jp() {
        let geo = jp_tokyo_geo();
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report.is_safe(),
            "Generated JP profile should have no critical issues: {:?}",
            report.warnings,
        );
    }

    #[test]
    fn generated_profile_is_coherent_de() {
        let geo = de_berlin_geo();
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        // ASN warning is expected (datacenter), but no critical issues from profile itself.
        let report = CoherenceValidator::validate(&profile, &geo, None);
        let non_asn_critical: Vec<_> = report
            .warnings
            .iter()
            .filter(|w| w.severity == Severity::Critical && !w.vectors.contains(&"ip_asn"))
            .collect();
        assert!(
            non_asn_critical.is_empty(),
            "Generated DE profile should have no non-ASN critical issues: {:?}",
            non_asn_critical,
        );
    }

    #[test]
    fn generated_mobile_profile_for_mobile_ip() {
        let geo = GeoContext {
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
        };
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        assert!(
            profile.user_agent.contains("Mobile"),
            "Mobile IP should generate mobile profile"
        );
        assert!(
            profile.max_touch_points > 0,
            "Mobile profile must have touch"
        );
    }

    // -- CoherenceReport tests --

    #[test]
    fn score_is_1_for_clean_profile() {
        let geo = us_houston_geo();
        let mut profile = CoherenceValidator::generate_coherent_profile(&geo);
        profile.timezone = "America/Chicago".to_string();
        let report = CoherenceValidator::validate(&profile, &geo, None);
        assert!(
            report.score >= 0.9,
            "Clean profile should score high, got {}",
            report.score
        );
    }

    #[test]
    fn score_drops_for_violations() {
        let mut profile = StealthProfile::chrome_windows();
        profile.timezone = "Asia/Tokyo".to_string();
        profile.languages = vec!["pt-BR".to_string()];
        profile.max_touch_points = 5;
        let geo = de_berlin_geo();
        let report = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Firefox));
        assert!(
            report.score < 0.5,
            "Many violations should reduce score, got {}",
            report.score
        );
        assert!(report.critical_count > 0);
    }

    // -- Mapping coverage tests --

    #[test]
    fn all_major_countries_have_timezones() {
        let major = [
            "US", "CA", "MX", "BR", "AR", "GB", "DE", "FR", "ES", "IT", "NL", "SE", "NO", "DK",
            "FI", "PL", "RU", "JP", "KR", "CN", "IN", "AU", "NZ", "ZA", "NG", "EG", "TR", "IL",
            "AE", "SA", "TH", "VN", "ID", "PH", "MY", "SG", "TW", "HK", "PK", "BD", "CH", "AT",
            "BE", "PT", "IE", "CZ", "HU", "RO", "BG", "HR",
        ];
        for code in &major {
            let tzs = timezones_for_country(code);
            assert!(
                !tzs.is_empty(),
                "Country '{}' should have timezone mapping",
                code
            );
        }
    }

    #[test]
    fn all_major_countries_have_languages() {
        let major = [
            "US", "CA", "MX", "BR", "GB", "DE", "FR", "ES", "IT", "JP", "KR", "CN", "IN", "AU",
            "RU", "TR", "NL", "SE", "PL",
        ];
        for code in &major {
            let langs = languages_for_country(code);
            assert!(
                !langs.is_empty(),
                "Country '{}' should have language mapping",
                code
            );
        }
    }

    /// Tracking baseline: the Panopticlick/BrowserScan-style coherence score is
    /// always a stable 0..1 value — 1.0 for a coherent profile, strictly lower
    /// (but still in-bounds) for an incoherent one.
    #[test]
    fn coherence_score_is_a_stable_unit_baseline() {
        let geo = us_houston_geo();

        // Coherent generated profile pins to exactly 1.0.
        let profile = CoherenceValidator::generate_coherent_profile(&geo);
        let clean = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));
        assert_eq!(clean.score, 1.0, "clean profile must score exactly 1.0");
        assert!((0.0..=1.0).contains(&clean.score));

        // Deterministic: same inputs, same score.
        let again = CoherenceValidator::validate(&profile, &geo, Some(TlsBrowser::Chrome));
        assert_eq!(clean.score, again.score, "score must be stable");

        // Incoherent profile stays within [0,1] but drops below the baseline.
        let mut broken = StealthProfile::chrome_windows();
        broken.timezone = "Asia/Tokyo".to_string();
        broken.languages = vec!["pt-BR".to_string()];
        broken.max_touch_points = 5;
        let bad = CoherenceValidator::validate(&broken, &geo, Some(TlsBrowser::Firefox));
        assert!((0.0..=1.0).contains(&bad.score));
        assert!(bad.score < clean.score, "violations must lower the score");
        assert!(bad.score >= 0.0);
    }

    // -- Non-browser client-stack coherence (ag03 R-2 / U-102) --

    /// Synthetic observation mirroring the pinned `JA4_COHORT_V1` TCP render.
    fn tallow_tcp_observation() -> TlsClientObservation {
        TlsClientObservation {
            transport: ClientTransport::TcpTls,
            cohort: tls_cohort::JA4_COHORT_ID.to_string(),
            provider: tls_cohort::COHORT_PROVIDER.to_string(),
            legacy_version: 0x0303,
            tls13_offered: true,
            ciphers: vec![
                0x1302, 0x1301, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0x00ff,
            ],
            extensions: vec![
                0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0017, 0x0023, 0x002b, 0x002d, 0x0033,
            ],
            groups: vec![0x11ec, 0x001d, 0x0017, 0x0018],
            sigalgs: vec![
                0x0503, 0x0403, 0x0603, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401,
            ],
            alpn: Vec::new(),
            key_share_groups: vec![0x11ec, 0x001d],
            grease_present: false,
            ja4: "t13d101000_b9b30c653583_2df05b0555f9".to_string(),
            quic_params: None,
        }
    }

    /// Synthetic observation mirroring the pinned `JA4_COHORT_V1` QUIC render.
    fn tallow_quic_observation() -> TlsClientObservation {
        let mut obs = tallow_tcp_observation();
        obs.transport = ClientTransport::Quic;
        obs.ciphers = vec![0x1302, 0x1301, 0x1303];
        // QUIC render: transport_parameters (0x0039) in, session_ticket (0x0023)
        // out (2026-09-16 re-pin: rustls ≥0.23.45 / quinn ≥0.11.12).
        obs.extensions = vec![
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0017, 0x002b, 0x002d, 0x0033, 0x0039,
        ];
        obs.ja4 = "q13d031000_24b2f16fafab_4479bb40581a".to_string();
        obs.quic_params = Some(QuicTransportParams::tallow_relay_client());
        obs
    }

    #[test]
    fn client_stack_coherent_observations_pass() {
        let report = ClientStackValidator::validate(
            &DeclaredClientProfile::tallow_relay_tcp(),
            &tallow_tcp_observation(),
        );
        assert!(
            report.is_safe(),
            "coherent TCP stack must have no critical issues: {:?}",
            report.warnings
        );
        assert_eq!(report.warning_count, 0, "{:?}", report.warnings);
        assert_eq!(report.info_count, 0, "{:?}", report.warnings);

        let report = ClientStackValidator::validate(
            &DeclaredClientProfile::tallow_relay_quic(),
            &tallow_quic_observation(),
        );
        assert!(
            report.is_safe(),
            "coherent QUIC stack must have no critical issues: {:?}",
            report.warnings
        );
        assert_eq!(report.warning_count, 0, "{:?}", report.warnings);
        assert_eq!(report.info_count, 0, "{:?}", report.warnings);
        assert_eq!(report.score, 1.0);
    }

    #[test]
    fn client_stack_detects_quic_tls12_suite() {
        let declared = DeclaredClientProfile::tallow_relay_quic();
        let mut obs = tallow_quic_observation();
        // A TLS 1.2 suite must never appear in a QUIC ClientHello.
        obs.ciphers.push(0xc02c);
        let report = ClientStackValidator::validate(&declared, &obs);
        assert!(report.critical_count > 0, "{:?}", report.warnings);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"quic")),
            "{:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"tls_cipher_suites")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn client_stack_detects_version_and_group_drift() {
        let declared = DeclaredClientProfile::tallow_relay_quic();

        let mut obs = tallow_quic_observation();
        obs.tls13_offered = false;
        let report = ClientStackValidator::validate(&declared, &obs);
        assert!(report.critical_count > 0, "{:?}", report.warnings);
        assert!(report.warnings.iter().any(|w| w.vectors.contains(&"tls_version")));

        let mut obs = tallow_quic_observation();
        obs.groups.retain(|g| *g != 0x001d);
        obs.key_share_groups.clear();
        let report = ClientStackValidator::validate(&declared, &obs);
        assert!(report.warning_count >= 1, "{:?}", report.warnings);
        assert!(report.warnings.iter().any(|w| w.vectors.contains(&"tls_groups")));

        // A legacy curve sneaking into supported_groups is config decay.
        let mut obs = tallow_quic_observation();
        obs.groups.push(0x0013); // secp192r1
        let report = ClientStackValidator::validate(&declared, &obs);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"legacy_group")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn client_stack_detects_sigalg_alpn_and_cohort_drift() {
        let declared = DeclaredClientProfile::tallow_relay_tcp();

        let mut obs = tallow_tcp_observation();
        obs.sigalgs.push(0x0201); // rsa_pkcs1_sha1
        obs.alpn.push("h2".to_string());
        obs.cohort = "JA4_COHORT_V0".to_string();
        let report = ClientStackValidator::validate(&declared, &obs);
        assert_eq!(report.critical_count, 0, "{:?}", report.warnings);
        for vector in ["legacy_sigalg", "alpn", "tls_cohort"] {
            assert!(
                report.warnings.iter().any(|w| w.vectors.contains(&vector)),
                "missing {} in {:?}",
                vector,
                report.warnings
            );
        }
        assert!(report.score < 1.0);
    }

    #[test]
    fn client_stack_detects_quic_param_drift_and_uncaptured_params() {
        let declared = DeclaredClientProfile::tallow_relay_quic();

        // Mismatched live params (quinn defaults instead of the declared 300/15).
        let mut obs = tallow_quic_observation();
        obs.quic_params = Some(QuicTransportParams {
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

        // Captured but internally incoherent: keep-alive after the idle timeout.
        let mut obs = tallow_quic_observation();
        obs.quic_params = Some(QuicTransportParams {
            max_idle_timeout_secs: Some(300),
            keep_alive_interval_secs: Some(600),
        });
        let report = ClientStackValidator::validate(&declared, &obs);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"quic_transport_params")),
            "{:?}",
            report.warnings
        );

        // Not captured at all → informational, not a false clean pass.
        let mut obs = tallow_quic_observation();
        obs.quic_params = None;
        let report = ClientStackValidator::validate(&declared, &obs);
        assert_eq!(report.critical_count, 0);
        assert_eq!(report.warning_count, 0, "{:?}", report.warnings);
        assert_eq!(report.info_count, 1, "{:?}", report.warnings);
    }

    #[test]
    fn validate_with_client_stack_merges_browser_and_stack_findings() {
        let geo = us_houston_geo();
        let profile = CoherenceValidator::generate_coherent_profile(&geo);

        let mut obs = tallow_quic_observation();
        obs.cohort = "JA4_COHORT_V0".to_string();

        let report = CoherenceValidator::validate_with_client_stack(
            &profile,
            &geo,
            Some(TlsBrowser::Chrome),
            &DeclaredClientProfile::tallow_relay_quic(),
            &obs,
        );
        assert!(report.is_safe(), "browser side is coherent: {:?}", report.warnings);
        assert!(
            report.warnings.iter().any(|w| w.vectors.contains(&"tls_cohort")),
            "client-stack cohort drift must be merged in: {:?}",
            report.warnings
        );

        // And the browser-side mismatch still surfaces when both are broken.
        let report = CoherenceValidator::validate_with_client_stack(
            &profile,
            &geo,
            Some(TlsBrowser::Firefox),
            &DeclaredClientProfile::tallow_relay_quic(),
            &obs,
        );
        assert!(!report.is_safe());
        assert!(report.warnings.iter().any(|w| w.vectors.contains(&"tls_fingerprint")));
        assert!(report.warnings.iter().any(|w| w.vectors.contains(&"tls_cohort")));
    }

    // ── P1 C2: effective-config coherence ───────────────────────────────────

    fn coherent_snapshot() -> EffectiveConfigSnapshot {
        let mut profile = StealthProfile::chrome_windows();
        profile.timezone = "UTC".to_string();
        EffectiveConfigSnapshot {
            profile,
            tor_isolate_by_domain: Some(true),
            block_third_party: Some(true),
            expect_utc: true,
        }
    }

    #[test]
    fn effective_config_check_passes_a_coherent_config() {
        let report = check_effective_config(&coherent_snapshot());
        assert!(
            report.is_safe(),
            "a coherent config must have no critical findings: {:?}",
            report.warnings
        );
    }

    #[test]
    fn effective_config_check_fails_loud_on_each_incoherence() {
        // Fleet-uniform canvas seed.
        let mut snap = coherent_snapshot();
        snap.profile.canvas_noise_seed = 0;
        let report = check_effective_config(&snap);
        assert!(!report.is_safe());
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"canvas_noise_seed")),
            "seed 0 must be a critical finding: {:?}",
            report.warnings
        );

        // Non-UTC timezone under the Tor-cohort policy.
        let mut snap = coherent_snapshot();
        snap.profile.timezone = "America/New_York".to_string();
        let report = check_effective_config(&snap);
        assert!(
            report.warnings.iter().any(|w| w.vectors.contains(&"tor_cohort")),
            "non-UTC must warn: {:?}",
            report.warnings
        );

        // Locale vs languages disagreement.
        let mut snap = coherent_snapshot();
        snap.profile.locale = "fr-FR".to_string();
        let report = check_effective_config(&snap);
        assert!(
            report.warnings.iter().any(|w| w.vectors.contains(&"locale")),
            "locale/languages mismatch must warn: {:?}",
            report.warnings
        );

        // Isolation switches off.
        let mut snap = coherent_snapshot();
        snap.tor_isolate_by_domain = Some(false);
        snap.block_third_party = Some(false);
        let report = check_effective_config(&snap);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"isolate_by_domain")),
            "isolation off must warn: {:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.vectors.contains(&"block_third_party")),
            "third-party cookies must warn: {:?}",
            report.warnings
        );
    }
}
