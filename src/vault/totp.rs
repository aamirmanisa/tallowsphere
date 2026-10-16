//! TOTP (Time-based One-Time Password) generator — RFC 6238.
//!
//! Supports SHA-1 (default), SHA-256, SHA-512 hash algorithms,
//! 6/7/8 digit codes, configurable period, and Steam Guard.

use hmac::{Hmac, Mac};

/// TOTP configuration parsed from (or serializable to) an `otpauth://` URI.
#[derive(Debug, Clone)]
pub struct TOTPConfig {
    pub secret: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub digits: u8,
    pub period: u32,
    pub algorithm: String,
}

impl Default for TOTPConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: None,
            account: None,
            digits: 6,
            period: 30,
            algorithm: "SHA1".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Base32 decoding (RFC 4648)
// ---------------------------------------------------------------------------

/// Decode a base32-encoded string (A-Z = 0..25, 2-7 = 26..31).
/// Ignores padding ('=') and spaces. Case-insensitive.
fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut output = Vec::with_capacity(input.len() * 5 / 8);

    for ch in input.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            'a'..='z' => ch as u64 - 'a' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            '=' | ' ' | '\n' | '\r' | '\t' => continue,
            _ => return Err(format!("totp: invalid base32 character '{ch}'")),
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// HOTP core (RFC 4226)
// ---------------------------------------------------------------------------

/// Compute HOTP(key, counter) with the specified algorithm and digit count.
fn hotp(key: &[u8], counter: u64, digits: u8, algorithm: &str) -> Result<u32, String> {
    let counter_bytes = counter.to_be_bytes();

    let hmac_result = match algorithm.to_uppercase().as_str() {
        "SHA1" | "SHA-1" => {
            type HmacSha1 = Hmac<sha1::Sha1>;
            let mut mac = HmacSha1::new_from_slice(key)
                .map_err(|e| format!("totp: HMAC-SHA1 init failed: {e}"))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA256" | "SHA-256" => {
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|e| format!("totp: HMAC-SHA256 init failed: {e}"))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" | "SHA-512" => {
            type HmacSha512 = Hmac<sha2::Sha512>;
            let mut mac = HmacSha512::new_from_slice(key)
                .map_err(|e| format!("totp: HMAC-SHA512 init failed: {e}"))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        other => return Err(format!("totp: unsupported algorithm '{other}' (use SHA1, SHA256, or SHA512)")),
    };

    // Dynamic truncation (RFC 4226 section 5.4).
    let offset = (hmac_result[hmac_result.len() - 1] & 0x0F) as usize;
    let code = ((hmac_result[offset] as u32 & 0x7F) << 24)
        | ((hmac_result[offset + 1] as u32) << 16)
        | ((hmac_result[offset + 2] as u32) << 8)
        | (hmac_result[offset + 3] as u32);

    let modulus = 10u32.pow(digits as u32);
    Ok(code % modulus)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a TOTP code for the current time.
///
/// - `secret_base32`: base32-encoded shared secret
/// - `digits`: number of output digits (typically 6, 7, or 8)
/// - `period`: time step in seconds (typically 30)
/// - `algorithm`: `"SHA1"`, `"SHA256"`, or `"SHA512"`
pub fn generate_totp(
    secret_base32: &str,
    digits: u8,
    period: u32,
    algorithm: &str,
) -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("totp: system time error: {e}"))?
        .as_secs();
    generate_totp_at(secret_base32, digits, period, algorithm, now)
}

/// Generate a TOTP code for a specific UNIX timestamp.
pub fn generate_totp_at(
    secret_base32: &str,
    digits: u8,
    period: u32,
    algorithm: &str,
    timestamp: u64,
) -> Result<String, String> {
    if secret_base32.is_empty() {
        return Err("totp: secret must not be empty".into());
    }
    if period == 0 {
        return Err("totp: period must be > 0".into());
    }
    if !(4..=10).contains(&digits) {
        return Err(format!("totp: digits must be 4-10, got {digits}"));
    }

    let key = base32_decode(secret_base32)?;
    let counter = timestamp / period as u64;
    let code = hotp(&key, counter, digits, algorithm)?;

    // Zero-pad to the requested digit count.
    Ok(format!("{:0>width$}", code, width = digits as usize))
}

/// Generate a Steam Guard code (5 alphanumeric characters).
///
/// Steam Guard uses HMAC-SHA1 with a 30-second period, but instead of
/// decimal digits it maps the truncated value to a custom 26-character
/// alphabet: `23456789BCDFGHJKMNPQRTVWXY`.
pub fn generate_steam_guard(secret_base32: &str) -> Result<String, String> {
    if secret_base32.is_empty() {
        return Err("totp: secret must not be empty".into());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("totp: system time error: {e}"))?
        .as_secs();

    generate_steam_guard_at(secret_base32, now)
}

/// Generate a Steam Guard code for a specific UNIX timestamp.
fn generate_steam_guard_at(secret_base32: &str, timestamp: u64) -> Result<String, String> {
    const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
    const STEAM_LEN: usize = 5;

    let key = base32_decode(secret_base32)?;
    let counter = timestamp / 30;
    let counter_bytes = counter.to_be_bytes();

    type HmacSha1 = Hmac<sha1::Sha1>;
    let mut mac = HmacSha1::new_from_slice(&key)
        .map_err(|e| format!("totp: HMAC-SHA1 init failed: {e}"))?;
    mac.update(&counter_bytes);
    let hmac_result = mac.finalize().into_bytes();

    let offset = (hmac_result[hmac_result.len() - 1] & 0x0F) as usize;
    let mut code = ((hmac_result[offset] as u32 & 0x7F) << 24)
        | ((hmac_result[offset + 1] as u32) << 16)
        | ((hmac_result[offset + 2] as u32) << 8)
        | (hmac_result[offset + 3] as u32);

    let mut result = String::with_capacity(STEAM_LEN);
    for _ in 0..STEAM_LEN {
        result.push(STEAM_CHARS[(code as usize) % STEAM_CHARS.len()] as char);
        code /= STEAM_CHARS.len() as u32;
    }

    Ok(result)
}

/// Seconds remaining until the current TOTP code expires.
pub fn time_remaining(period: u32) -> u32 {
    if period == 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let elapsed = (now % period as u64) as u32;
    period - elapsed
}

/// Parse an `otpauth://totp/...` URI into a [`TOTPConfig`].
///
/// Format: `otpauth://totp/ISSUER:ACCOUNT?secret=BASE32&issuer=ISSUER&digits=6&period=30&algorithm=SHA1`
pub fn parse_otpauth_uri(uri: &str) -> Result<TOTPConfig, String> {
    if !uri.starts_with("otpauth://totp/") {
        return Err("totp: URI must start with 'otpauth://totp/'".into());
    }

    let rest = &uri["otpauth://totp/".len()..];

    // Split path from query string.
    let (label, query) = match rest.find('?') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };

    // Parse label — may be "Issuer:Account" or just "Account".
    let label_decoded = percent_decode(label);
    let (label_issuer, account) = match label_decoded.find(':') {
        Some(pos) => (
            Some(label_decoded[..pos].to_string()),
            label_decoded[pos + 1..].to_string(),
        ),
        None => (None, label_decoded),
    };

    // Parse query parameters.
    let mut secret = String::new();
    let mut issuer: Option<String> = label_issuer;
    let mut digits: u8 = 6;
    let mut period: u32 = 30;
    let mut algorithm = "SHA1".to_string();

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let (key, value) = match param.find('=') {
            Some(pos) => (&param[..pos], percent_decode(&param[pos + 1..])),
            None => continue,
        };
        match key.to_lowercase().as_str() {
            "secret" => secret = value,
            "issuer" => issuer = Some(value),
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| format!("totp: invalid digits '{value}'"))?;
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| format!("totp: invalid period '{value}'"))?;
            }
            "algorithm" => algorithm = value.to_uppercase(),
            _ => {} // ignore unknown params
        }
    }

    if secret.is_empty() {
        return Err("totp: URI missing 'secret' parameter".into());
    }

    Ok(TOTPConfig {
        secret,
        issuer,
        account: if account.is_empty() { None } else { Some(account) },
        digits,
        period,
        algorithm,
    })
}

/// Build an `otpauth://totp/...` URI from a [`TOTPConfig`].
pub fn build_otpauth_uri(config: &TOTPConfig) -> String {
    let mut uri = String::from("otpauth://totp/");

    // Label.
    match (&config.issuer, &config.account) {
        (Some(issuer), Some(account)) => {
            uri.push_str(&percent_encode(issuer));
            uri.push(':');
            uri.push_str(&percent_encode(account));
        }
        (None, Some(account)) => {
            uri.push_str(&percent_encode(account));
        }
        (Some(issuer), None) => {
            uri.push_str(&percent_encode(issuer));
        }
        (None, None) => {
            uri.push_str("Unknown");
        }
    }

    // Query parameters.
    uri.push_str("?secret=");
    uri.push_str(&config.secret);

    if let Some(ref issuer) = config.issuer {
        uri.push_str("&issuer=");
        uri.push_str(&percent_encode(issuer));
    }

    if config.digits != 6 {
        uri.push_str(&format!("&digits={}", config.digits));
    }

    if config.period != 30 {
        uri.push_str(&format!("&period={}", config.period));
    }

    if config.algorithm != "SHA1" {
        uri.push_str("&algorithm=");
        uri.push_str(&config.algorithm);
    }

    uri
}

// ---------------------------------------------------------------------------
// Percent-encoding helpers
// ---------------------------------------------------------------------------

/// Minimal percent-decode for otpauth URI parsing.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Minimal percent-encode for otpauth URI building.
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vectors (SHA-1, 8 digits, period 30).
    // Secret: "12345678901234567890" → base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    const TEST_SECRET_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn base32_decode_known() {
        // Base32("Hello!") = "JBSWY3DPEE"
        let decoded = base32_decode("JBSWY3DPEE").unwrap();
        assert_eq!(&decoded, b"Hello!");
        // Also verify a 16-char base32 string decodes to 10 bytes without error.
        let decoded2 = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decoded2.len(), 10);
    }

    #[test]
    fn base32_decode_rfc_secret() {
        let decoded = base32_decode(TEST_SECRET_SHA1).unwrap();
        assert_eq!(&decoded, b"12345678901234567890");
    }

    #[test]
    fn base32_decode_case_insensitive() {
        let upper = base32_decode("JBSWY3DPEE").unwrap();
        let lower = base32_decode("jbswy3dpee").unwrap();
        assert_eq!(upper, lower);
    }

    #[test]
    fn base32_decode_with_padding() {
        let with_pad = base32_decode("JBSWY3DPEE======").unwrap();
        let without = base32_decode("JBSWY3DPEE").unwrap();
        assert_eq!(with_pad, without);
    }

    #[test]
    fn rfc6238_sha1_test_vectors() {
        // RFC 6238 Appendix B test values (using 8-digit codes).
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for &(time, expected) in cases {
            let code = generate_totp_at(TEST_SECRET_SHA1, 8, 30, "SHA1", time).unwrap();
            assert_eq!(
                code, expected,
                "SHA1 TOTP at t={time}: expected {expected}, got {code}"
            );
        }
    }

    #[test]
    fn rfc6238_sha256_test_vectors() {
        // SHA-256 secret: "12345678901234567890123456789012" (32 bytes)
        // base32 of that:
        let secret256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        let cases: &[(u64, &str)] = &[
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];
        for &(time, expected) in cases {
            let code = generate_totp_at(secret256, 8, 30, "SHA256", time).unwrap();
            assert_eq!(
                code, expected,
                "SHA256 TOTP at t={time}: expected {expected}, got {code}"
            );
        }
    }

    #[test]
    fn rfc6238_sha512_test_vectors() {
        // SHA-512 secret: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
        let secret512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
        let cases: &[(u64, &str)] = &[
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];
        for &(time, expected) in cases {
            let code = generate_totp_at(secret512, 8, 30, "SHA512", time).unwrap();
            assert_eq!(
                code, expected,
                "SHA512 TOTP at t={time}: expected {expected}, got {code}"
            );
        }
    }

    #[test]
    fn six_digit_code() {
        let code = generate_totp_at(TEST_SECRET_SHA1, 6, 30, "SHA1", 59).unwrap();
        assert_eq!(code.len(), 6);
        // Last 6 digits of 94287082 = 287082
        assert_eq!(code, "287082");
    }

    #[test]
    fn generate_totp_current_time() {
        // Just verify it doesn't error — we can't predict the exact code.
        let code = generate_totp(TEST_SECRET_SHA1, 6, 30, "SHA1").unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn empty_secret_errors() {
        assert!(generate_totp_at("", 6, 30, "SHA1", 0).is_err());
    }

    #[test]
    fn zero_period_errors() {
        assert!(generate_totp_at(TEST_SECRET_SHA1, 6, 0, "SHA1", 0).is_err());
    }

    #[test]
    fn bad_algorithm_errors() {
        assert!(generate_totp_at(TEST_SECRET_SHA1, 6, 30, "MD5", 0).is_err());
    }

    #[test]
    fn steam_guard_format() {
        let code = generate_steam_guard_at(TEST_SECRET_SHA1, 59).unwrap();
        assert_eq!(code.len(), 5);
        const VALID: &str = "23456789BCDFGHJKMNPQRTVWXY";
        assert!(
            code.chars().all(|c| VALID.contains(c)),
            "Steam Guard code '{}' contains invalid character",
            code
        );
    }

    #[test]
    fn time_remaining_range() {
        let rem = time_remaining(30);
        assert!(rem >= 1 && rem <= 30, "time_remaining={rem}");
    }

    #[test]
    fn parse_otpauth_full() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60&algorithm=SHA256";
        let cfg = parse_otpauth_uri(uri).unwrap();
        assert_eq!(cfg.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(cfg.issuer.as_deref(), Some("Example"));
        assert_eq!(cfg.account.as_deref(), Some("alice@example.com"));
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period, 60);
        assert_eq!(cfg.algorithm, "SHA256");
    }

    #[test]
    fn parse_otpauth_minimal() {
        let uri = "otpauth://totp/MyService?secret=JBSWY3DPEHPK3PXP";
        let cfg = parse_otpauth_uri(uri).unwrap();
        assert_eq!(cfg.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(cfg.account.as_deref(), Some("MyService"));
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.algorithm, "SHA1");
    }

    #[test]
    fn parse_otpauth_missing_secret_errors() {
        let uri = "otpauth://totp/Test?issuer=Foo";
        assert!(parse_otpauth_uri(uri).is_err());
    }

    #[test]
    fn parse_otpauth_bad_scheme_errors() {
        assert!(parse_otpauth_uri("http://example.com").is_err());
    }

    #[test]
    fn build_otpauth_roundtrip() {
        let cfg = TOTPConfig {
            secret: "JBSWY3DPEHPK3PXP".into(),
            issuer: Some("Example".into()),
            account: Some("alice@example.com".into()),
            digits: 8,
            period: 60,
            algorithm: "SHA256".into(),
        };
        let uri = build_otpauth_uri(&cfg);
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=Example"));
        assert!(uri.contains("digits=8"));
        assert!(uri.contains("period=60"));
        assert!(uri.contains("algorithm=SHA256"));

        // Roundtrip: parse the built URI.
        let parsed = parse_otpauth_uri(&uri).unwrap();
        assert_eq!(parsed.secret, cfg.secret);
        assert_eq!(parsed.digits, cfg.digits);
        assert_eq!(parsed.period, cfg.period);
        assert_eq!(parsed.algorithm, cfg.algorithm);
    }

    #[test]
    fn build_otpauth_defaults_omits_standard_values() {
        let cfg = TOTPConfig {
            secret: "AAAA".into(),
            issuer: None,
            account: Some("test".into()),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
        };
        let uri = build_otpauth_uri(&cfg);
        // Should NOT contain digits= or period= or algorithm= since they're defaults.
        assert!(!uri.contains("digits="));
        assert!(!uri.contains("period="));
        assert!(!uri.contains("algorithm="));
    }
}
