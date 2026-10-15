//! Authentication helpers for Tallow browser automation.
//!
//! Provides login session persistence (wrapping session module),
//! TOTP 2FA code generation (RFC 6238), and OAuth redirect flow capture.

use std::collections::HashMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::session;

// ── Login session persistence (BRAT-01) ─────────────────────────────

/// Save browser session state after a successful login.
///
/// Wraps `session::capture_session` + `session::save_session`. Captures
/// cookies + localStorage/sessionStorage for all provided origins, encrypts
/// with the shared secret, and persists to SQLite.
pub async fn save_login_session(
    client: &CdpClient,
    session_id_cdp: &str,
    db: &rusqlite::Connection,
    session_name: &str,
    origins: &[&str],
    shared_secret: &[u8],
) -> Result<(), BrowserError> {
    let browser_session =
        session::capture_session(client, session_id_cdp, session_name, origins).await?;
    session::save_session(db, &browser_session, shared_secret)?;
    Ok(())
}

/// Restore a previously saved login session.
///
/// Wraps `session::load_session` + `session::restore_session`. Loads the
/// encrypted session from SQLite, decrypts it, and restores cookies +
/// storage into the browser.
pub async fn restore_login_session(
    client: &CdpClient,
    session_id_cdp: &str,
    db: &rusqlite::Connection,
    session_name: &str,
    shared_secret: &[u8],
) -> Result<(), BrowserError> {
    let browser_session = session::load_session(db, session_name, shared_secret)?;
    session::restore_session(client, session_id_cdp, &browser_session).await?;
    Ok(())
}

/// Check if the user appears to be logged in by looking for a DOM element.
///
/// Evaluates `document.querySelector(selector) !== null` in the current page.
/// Returns `true` if the element exists (indicating a logged-in state).
pub async fn is_logged_in(
    client: &CdpClient,
    session_id_cdp: &str,
    check_selector: &str,
) -> Result<bool, BrowserError> {
    let js = format!(
        "document.querySelector({}) !== null",
        serde_json::to_string(check_selector)
            .unwrap_or_else(|_| format!("\"{}\"", check_selector))
    );
    let params = serde_json::json!({
        "expression": js,
        "returnByValue": true,
    });
    let result = client
        .send_command_with_session("Runtime.evaluate", Some(params), session_id_cdp)
        .await?;

    let logged_in = result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(logged_in)
}

// ── TOTP generation (BRAT-02) ───────────────────────────────────────

type HmacSha1 = Hmac<Sha1>;

/// Generate a TOTP code per RFC 6238 using HMAC-SHA1.
///
/// Uses HMAC-SHA1 for maximum compatibility with Google Authenticator,
/// Authy, and other standard TOTP apps (RFC 6238 default algorithm).
///
/// # Arguments
/// - `secret`: raw TOTP secret bytes (decode base32 first if needed)
/// - `time_step`: time step in seconds (typically 30)
/// - `digits`: number of output digits (typically 6)
///
/// # Returns
/// Zero-padded decimal string of `digits` length.
pub fn generate_totp(secret: &[u8], time_step: u64, digits: u32) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    generate_totp_at(secret, time_step, digits, now)
}

/// Generate a TOTP code at a specific Unix timestamp.
///
/// Useful for testing with known timestamps.
pub fn generate_totp_at(secret: &[u8], time_step: u64, digits: u32, unix_seconds: u64) -> String {
    let counter = unix_seconds / time_step;
    hotp(secret, counter, digits)
}

/// Generate a HOTP code per RFC 4226.
///
/// Core algorithm shared by TOTP (which feeds in time-based counter).
fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    // Step 1: HMAC-SHA1(secret, counter)
    let mut mac =
        HmacSha1::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Step 2: Dynamic truncation (RFC 4226 section 5.4)
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    // Step 3: Reduce to `digits` decimal digits
    let modulus = 10u32.pow(digits);
    let otp = code % modulus;

    // Zero-pad to requested length
    format!("{:0>width$}", otp, width = digits as usize)
}

/// Convenience: generate a standard 6-digit TOTP with 30-second step.
pub fn generate_totp_default(secret: &[u8]) -> String {
    generate_totp(secret, 30, 6)
}

/// Decode a base32-encoded TOTP secret (RFC 4648).
///
/// Handles uppercase/lowercase, padding ('='), and whitespace.
/// This is the standard encoding used by Google Authenticator QR codes.
pub fn decode_totp_secret(base32_secret: &str) -> Result<Vec<u8>, BrowserError> {
    // Strip whitespace and padding
    let cleaned: String = base32_secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect::<String>()
        .to_uppercase();

    if cleaned.is_empty() {
        return Err(BrowserError::AuthError(
            "empty base32 secret".to_string(),
        ));
    }

    let mut bits = Vec::with_capacity(cleaned.len() * 5);

    for ch in cleaned.chars() {
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            _ => {
                return Err(BrowserError::AuthError(format!(
                    "invalid base32 character: '{}'",
                    ch
                )))
            }
        };
        // Push 5 bits
        for i in (0..5).rev() {
            bits.push((val >> i) & 1);
        }
    }

    // Convert bits to bytes (groups of 8)
    let mut bytes = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 {
            break; // discard trailing bits that don't form a full byte
        }
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | bit;
        }
        bytes.push(byte);
    }

    Ok(bytes)
}

// ── OAuth flow helpers (BRAT-03) ────────────────────────────────────

/// Result of an OAuth redirect capture.
///
/// A6.1.1 zeroization sweep: no derived `Debug` (it would print tokens into
/// logs and panic messages — hand-written redacted form below); fields are
/// wiped on drop on a best-effort basis (`zeroize`). `Clone` is kept for
/// existing callers; cloned copies are independent and must be dropped for
/// their own wipes.
#[derive(Clone)]
pub struct OAuthTokenResult {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub code: Option<String>,
    pub state: Option<String>,
    pub token_type: Option<String>,
    pub raw_params: HashMap<String, String>,
}

impl std::fmt::Debug for OAuthTokenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokenResult")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("code", &self.code.as_ref().map(|_| "[redacted]"))
            .field("state", &self.state)
            .field("token_type", &self.token_type)
            .field("raw_params", &format!("{} entries", self.raw_params.len()))
            .finish()
    }
}

impl Drop for OAuthTokenResult {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(s) = self.access_token.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.refresh_token.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.code.as_mut() {
            s.zeroize();
        }
        for value in self.raw_params.values_mut() {
            value.zeroize();
        }
        self.raw_params.clear();
    }
}

/// Capture an OAuth redirect by polling the current page URL.
///
/// Polls every 200ms until the current URL starts with `redirect_uri_prefix`,
/// then parses query/fragment parameters to extract tokens.
///
/// Works with both authorization code flow (params in query string)
/// and implicit flow (tokens in URL fragment).
pub async fn capture_oauth_redirect(
    client: &CdpClient,
    session_id_cdp: &str,
    redirect_uri_prefix: &str,
    timeout: Duration,
) -> Result<OAuthTokenResult, BrowserError> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(200);

    loop {
        // Get current page URL via Runtime.evaluate
        let params = serde_json::json!({
            "expression": "window.location.href",
            "returnByValue": true,
        });
        let result = client
            .send_command_with_session("Runtime.evaluate", Some(params), session_id_cdp)
            .await?;

        let current_url = result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if current_url.starts_with(redirect_uri_prefix) {
            return Ok(parse_oauth_params(current_url));
        }

        if start.elapsed() >= timeout {
            return Err(BrowserError::AuthError(format!(
                "OAuth redirect timeout after {}s waiting for URL prefix '{}'",
                timeout.as_secs(),
                redirect_uri_prefix
            )));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Parse OAuth parameters from both query string and URL fragment.
///
/// Checks fragment first (implicit flow puts tokens in `#fragment`),
/// then query string (authorization code flow puts code in `?query`).
pub fn parse_oauth_params(url: &str) -> OAuthTokenResult {
    let mut all_params = HashMap::new();

    // Parse fragment parameters (after #)
    if let Some(fragment_pos) = url.find('#') {
        let fragment = &url[fragment_pos + 1..];
        parse_url_params(fragment, &mut all_params);
    }

    // Parse query parameters (after ? but before #)
    let url_without_fragment = if let Some(hash_pos) = url.find('#') {
        &url[..hash_pos]
    } else {
        url
    };

    if let Some(query_pos) = url_without_fragment.find('?') {
        let query = &url_without_fragment[query_pos + 1..];
        // Don't overwrite fragment params (fragment takes precedence for implicit flow)
        let mut query_params = HashMap::new();
        parse_url_params(query, &mut query_params);
        for (k, v) in query_params {
            all_params.entry(k).or_insert(v);
        }
    }

    OAuthTokenResult {
        access_token: all_params.get("access_token").cloned(),
        refresh_token: all_params.get("refresh_token").cloned(),
        code: all_params.get("code").cloned(),
        state: all_params.get("state").cloned(),
        token_type: all_params.get("token_type").cloned(),
        raw_params: all_params,
    }
}

/// Parse URL-encoded key=value pairs separated by '&'.
fn parse_url_params(params_str: &str, out: &mut HashMap<String, String>) {
    for pair in params_str.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        if let Some(key) = parts.next() {
            let value = parts.next().unwrap_or("");
            // Simple percent-decode for common cases
            let key_decoded = percent_decode(key);
            let value_decoded = percent_decode(value);
            out.insert(key_decoded, value_decoded);
        }
    }
}

/// Simple percent-decoding for URL parameters.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TOTP tests ──────────────────────────────────────────────────

    #[test]
    fn test_generate_totp_rfc6238_sha1_vector() {
        // RFC 6238 test vector for SHA-1:
        // Secret: "12345678901234567890" (ASCII bytes)
        // Time = 59s -> counter = 59/30 = 1
        // Expected: 287082
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 59);
        assert_eq!(code, "94287082");
    }

    #[test]
    fn test_generate_totp_rfc6238_vector_t1111111109() {
        // RFC 6238: T = 1111111109 -> counter = 1111111109/30 = 37037036
        // Expected: 07081804
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 1111111109);
        assert_eq!(code, "07081804");
    }

    #[test]
    fn test_generate_totp_rfc6238_vector_t1111111111() {
        // RFC 6238: T = 1111111111 -> counter = 1111111111/30 = 37037037
        // Expected: 14050471
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 1111111111);
        assert_eq!(code, "14050471");
    }

    #[test]
    fn test_generate_totp_rfc6238_vector_t1234567890() {
        // RFC 6238: T = 1234567890 -> counter = 1234567890/30 = 41152263
        // Expected: 89005924
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 1234567890);
        assert_eq!(code, "89005924");
    }

    #[test]
    fn test_generate_totp_rfc6238_vector_t2000000000() {
        // RFC 6238: T = 2000000000 -> counter = 2000000000/30 = 66666666
        // Expected: 69279037
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 2000000000);
        assert_eq!(code, "69279037");
    }

    #[test]
    fn test_generate_totp_rfc6238_vector_t20000000000() {
        // RFC 6238: T = 20000000000 -> counter = 20000000000/30 = 666666666
        // Expected: 65353130
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 20000000000);
        assert_eq!(code, "65353130");
    }

    #[test]
    fn test_generate_totp_default_returns_6_digits() {
        let secret = b"12345678901234567890";
        let code = generate_totp_default(secret);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_totp_6_digit_at_known_time() {
        // 6-digit version at T=59
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 6, 59);
        // Counter=1, 6 digits => last 6 digits of the 8-digit code "94287082" -> "287082"
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_generate_totp_zero_padding() {
        // When OTP has leading zeros, they should be preserved
        // T=1111111109, 8 digits => "07081804" (starts with 0)
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 30, 8, 1111111109);
        assert_eq!(code.len(), 8);
        assert!(code.starts_with('0'));
    }

    // ── Base32 decoding tests ───────────────────────────────────────

    #[test]
    fn test_decode_totp_secret_known_value() {
        // "JBSWY3DPEHPK3PXP" decodes to bytes for "Hello!" + 0xDE 0xAD 0xBE 0xEF
        let bytes = decode_totp_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(
            bytes,
            &[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_decode_totp_secret_lowercase() {
        let bytes = decode_totp_secret("jbswy3dpehpk3pxp").unwrap();
        assert_eq!(
            bytes,
            &[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_decode_totp_secret_with_padding() {
        // "MY======" is base32 for "f"
        // M=12 Y=24 -> binary: 01100 11000 -> 01100110 00 -> 0x66 = 'f'
        let bytes = decode_totp_secret("MY======").unwrap();
        assert_eq!(bytes, b"f");
    }

    #[test]
    fn test_decode_totp_secret_with_whitespace() {
        let bytes = decode_totp_secret("JBSW Y3DP EHPK 3PXP").unwrap();
        assert_eq!(
            bytes,
            &[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_decode_totp_secret_empty() {
        let result = decode_totp_secret("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_decode_totp_secret_invalid_char() {
        let result = decode_totp_secret("JBSWY3DP!!");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid base32"), "got: {}", err);
    }

    #[test]
    fn test_decode_totp_secret_only_padding() {
        let result = decode_totp_secret("====");
        assert!(result.is_err()); // All padding, no data
    }

    // ── OAuth parsing tests ─────────────────────────────────────────

    #[test]
    fn test_parse_oauth_params_query_string() {
        let result =
            parse_oauth_params("https://redirect.com/callback?code=abc123&state=xyz");
        assert_eq!(result.code, Some("abc123".to_string()));
        assert_eq!(result.state, Some("xyz".to_string()));
        assert_eq!(result.access_token, None);
        assert_eq!(result.refresh_token, None);
    }

    #[test]
    fn test_parse_oauth_params_fragment() {
        let result = parse_oauth_params(
            "https://redirect.com/callback#access_token=tok123&token_type=bearer",
        );
        assert_eq!(result.access_token, Some("tok123".to_string()));
        assert_eq!(result.token_type, Some("bearer".to_string()));
        assert_eq!(result.code, None);
    }

    #[test]
    fn test_parse_oauth_params_both_query_and_fragment() {
        let result = parse_oauth_params(
            "https://redirect.com/callback?state=s1#access_token=tok&token_type=bearer",
        );
        assert_eq!(result.access_token, Some("tok".to_string()));
        assert_eq!(result.token_type, Some("bearer".to_string()));
        assert_eq!(result.state, Some("s1".to_string()));
    }

    #[test]
    fn test_parse_oauth_params_with_refresh_token() {
        let result = parse_oauth_params(
            "https://redirect.com/callback?code=auth_code&state=st&refresh_token=rt123",
        );
        assert_eq!(result.code, Some("auth_code".to_string()));
        assert_eq!(result.state, Some("st".to_string()));
        assert_eq!(result.refresh_token, Some("rt123".to_string()));
    }

    #[test]
    fn test_parse_oauth_params_no_params() {
        let result = parse_oauth_params("https://redirect.com/callback");
        assert_eq!(result.access_token, None);
        assert_eq!(result.code, None);
        assert_eq!(result.state, None);
        assert!(result.raw_params.is_empty());
    }

    #[test]
    fn test_parse_oauth_params_percent_encoded() {
        let result =
            parse_oauth_params("https://redirect.com/callback?code=abc%20123&state=x%26y");
        assert_eq!(result.code, Some("abc 123".to_string()));
        assert_eq!(result.state, Some("x&y".to_string()));
    }

    #[test]
    fn test_parse_oauth_params_raw_params_populated() {
        let result = parse_oauth_params(
            "https://redirect.com/callback?code=c1&state=s1&extra=data",
        );
        assert_eq!(result.raw_params.get("extra"), Some(&"data".to_string()));
        assert_eq!(result.raw_params.len(), 3);
    }

    // ── Percent decode tests ────────────────────────────────────────

    #[test]
    fn test_percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a%26b"), "a&b");
        assert_eq!(percent_decode("no+encoding"), "no encoding");
    }

    #[test]
    fn test_percent_decode_passthrough() {
        assert_eq!(percent_decode("simple"), "simple");
        assert_eq!(percent_decode(""), "");
    }

    // ── A6.1.1 zeroization sweep: redacted Debug ────────────────────

    #[test]
    fn test_oauth_token_result_debug_redacts_secrets() {
        let r = OAuthTokenResult {
            access_token: Some("sekrit-access".to_string()),
            refresh_token: Some("sekrit-refresh".to_string()),
            code: Some("sekrit-code".to_string()),
            state: Some("st-1".to_string()),
            token_type: Some("bearer".to_string()),
            raw_params: HashMap::from([(
                "access_token".to_string(),
                "sekrit-access".to_string(),
            )]),
        };
        let dbg = format!("{:?}", r);
        assert!(!dbg.contains("sekrit"), "debug leaked a secret: {dbg}");
        assert!(dbg.contains("[redacted]"), "debug missing redaction: {dbg}");
        assert!(
            dbg.contains("st-1"),
            "non-secret state should remain visible: {dbg}"
        );
    }

    #[test]
    fn test_parse_oauth_params_debug_is_redacted() {
        let r = parse_oauth_params("https://x/cb#access_token=tok123&token_type=bearer");
        let dbg = format!("{:?}", r);
        assert!(!dbg.contains("tok123"), "debug leaked token: {dbg}");
        assert!(dbg.contains("[redacted]"), "debug missing redaction: {dbg}");
    }
}
