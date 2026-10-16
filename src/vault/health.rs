//! Vault health analysis — weak passwords, reused credentials, breach detection.

use std::collections::HashMap;

use super::entry::{EntryData, VaultEntry};

// ── Hex Utilities ───────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Result Structs ──────────────────────────────────────────────────────────

/// A password that fails the minimum entropy threshold.
#[derive(Debug, Clone)]
pub struct WeakPassword {
    pub entry_id: String,
    pub entry_name: String,
    pub entropy_bits: f64,
    pub rating: String,
}

/// A group of entries sharing the same password (BLAKE3 hash).
#[derive(Debug, Clone)]
pub struct ReusedPassword {
    pub password_hash: String,
    pub entry_ids: Vec<String>,
    pub entry_names: Vec<String>,
}

/// A login entry whose URL uses HTTP instead of HTTPS.
#[derive(Debug, Clone)]
pub struct UnsecuredUrl {
    pub entry_id: String,
    pub entry_name: String,
    pub url: String,
}

/// A login entry that has no TOTP secret configured.
#[derive(Debug, Clone)]
pub struct MissingTOTP {
    pub entry_id: String,
    pub entry_name: String,
}

/// An entry whose `expires_at` timestamp is in the past.
#[derive(Debug, Clone)]
pub struct ExpiredEntry {
    pub entry_id: String,
    pub entry_name: String,
    pub expired_at: String,
}

/// Result of a Have I Been Pwned password check.
#[derive(Debug, Clone)]
pub struct BreachResult {
    pub found: bool,
    pub count: u64,
}

/// Full vault health report.
#[derive(Debug, Clone)]
pub struct HealthReport {
    pub total_entries: usize,
    pub login_entries: usize,
    pub weak_passwords: Vec<WeakPassword>,
    pub reused_passwords: Vec<ReusedPassword>,
    pub unsecured_urls: Vec<UnsecuredUrl>,
    pub missing_totp: Vec<MissingTOTP>,
    pub expired_entries: Vec<ExpiredEntry>,
    pub score: u32,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Run every health check and return a comprehensive report.
pub fn analyze(entries: &[VaultEntry]) -> HealthReport {
    let login_entries = entries
        .iter()
        .filter(|e| matches!(e.data, EntryData::Login(_)))
        .count();

    let weak_passwords = check_weak_passwords(entries);
    let reused_passwords = check_reused_passwords(entries);
    let unsecured_urls = check_unsecured_urls(entries);
    let missing_totp = check_missing_totp(entries);
    let expired_entries = check_expired(entries);

    let mut report = HealthReport {
        total_entries: entries.len(),
        login_entries,
        weak_passwords,
        reused_passwords,
        unsecured_urls,
        missing_totp,
        expired_entries,
        score: 0,
    };

    report.score = calculate_score(&report);
    report
}

/// Check a single password against the HIBP k-anonymity API.
///
/// SHA-1 hashes the password, sends the first 5 hex characters to
/// `https://api.pwnedpasswords.com/range/{prefix}`, then checks whether
/// the remaining suffix appears in the response.
pub fn check_breach_password(password: &str) -> Result<BreachResult, String> {
    use sha1::Digest;

    let hash = sha1::Sha1::digest(password.as_bytes());
    let hash_hex = hex_encode(&hash).to_uppercase();

    // k-anonymity range check via the shared helper: never sends more than the
    // first 5 hex chars, adds a local prefix->suffix cache + optional padding,
    // and paces the outbound call (backoff/retry on 429/5xx).
    let count = crate::stdlib::http::hibp_range_check(&hash_hex)
        .map_err(|e| format!("HIBP request failed: {e}"))?;

    Ok(BreachResult {
        found: count > 0,
        count,
    })
}

/// Check an email address against the Have I Been Pwned breachedaccount API v3.
///
/// Requires a `HIBP_API_KEY` environment variable containing a valid HIBP
/// subscription key (see <https://haveibeenpwned.com/API/Key>).
///
/// Returns the list of breach names the email appears in, or an error message
/// explaining how to obtain an API key when none is configured.
///
/// # Endpoint
/// `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}`
/// Header: `hibp-api-key: {key}`
///
/// A 404 response means the email was not found in any breach.
pub fn check_breach_email(email: &str) -> Result<Vec<String>, String> {
    let api_key = match std::env::var("HIBP_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return Err(
                "HIBP email breach check requires a paid API key. \
                 Set the HIBP_API_KEY environment variable with your key from \
                 https://haveibeenpwned.com/API/Key".to_string()
            );
        }
    };

    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
        url_encode(email)
    );

    let headers = vec![
        ("hibp-api-key".to_string(), api_key),
        ("user-agent".to_string(), "nixe-vault/0.4".to_string()),
    ];
    let (status, body, _retries, rate_limited) = crate::stdlib::http::governed_get(
        &url,
        &headers,
        &crate::stdlib::http::GOV_HIBP,
        3,
    )
    .map_err(|e| format!("HIBP request failed: {e}"))?;

    if rate_limited {
        return Err(format!("HIBP rate limited (429)"));
    }
    if status == 404 {
        // 404 = email not found in any breach
        return Ok(Vec::new());
    }
    if status != 200 {
        return Err(format!("HIBP request failed: HTTP {status}"));
    }

    // Response is a JSON array of breach objects with a "Name" field.
    // Example: [{"Name":"Adobe"},{"Name":"LinkedIn"}]
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("failed to parse HIBP response: {e}"))?;

    let names = parsed
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|v| v.get("Name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    Ok(names)
}

/// Percent-encode characters that are not safe in a URL path segment.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Internal Checks ─────────────────────────────────────────────────────────

/// Calculate password entropy in bits.
///
/// `pool_size` = sum of character-class sizes actually used:
///   lowercase (26), uppercase (26), digits (10), special (33).
/// `entropy = length * log2(pool_size)`.
fn password_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }

    let mut pool_size: u32 = 0;
    if has_lower {
        pool_size += 26;
    }
    if has_upper {
        pool_size += 26;
    }
    if has_digit {
        pool_size += 10;
    }
    if has_special {
        pool_size += 33;
    }
    if pool_size == 0 {
        pool_size = 1;
    }

    password.len() as f64 * (pool_size as f64).log2()
}

fn entropy_rating(bits: f64) -> String {
    if bits < 20.0 {
        "very weak".into()
    } else if bits < 40.0 {
        "weak".into()
    } else if bits < 60.0 {
        "fair".into()
    } else if bits < 80.0 {
        "strong".into()
    } else {
        "very strong".into()
    }
}

fn check_weak_passwords(entries: &[VaultEntry]) -> Vec<WeakPassword> {
    let mut results = Vec::new();

    for entry in entries {
        let password = match &entry.data {
            EntryData::Login(d) => &d.password,
            _ => continue,
        };

        let bits = password_entropy(password);
        if bits < 40.0 {
            results.push(WeakPassword {
                entry_id: entry.id.clone(),
                entry_name: entry.name.clone(),
                entropy_bits: bits,
                rating: entropy_rating(bits),
            });
        }
    }

    results
}

fn check_reused_passwords(entries: &[VaultEntry]) -> Vec<ReusedPassword> {
    let mut map: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for entry in entries {
        let password = match &entry.data {
            EntryData::Login(d) => &d.password,
            _ => continue,
        };

        let hash = blake3::hash(password.as_bytes());
        let hash_hex = hex_encode(hash.as_bytes());
        map.entry(hash_hex)
            .or_default()
            .push((entry.id.clone(), entry.name.clone()));
    }

    map.into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(hash, entries_vec)| {
            let (ids, names): (Vec<_>, Vec<_>) = entries_vec.into_iter().unzip();
            ReusedPassword {
                password_hash: hash,
                entry_ids: ids,
                entry_names: names,
            }
        })
        .collect()
}

fn check_unsecured_urls(entries: &[VaultEntry]) -> Vec<UnsecuredUrl> {
    let mut results = Vec::new();

    for entry in entries {
        let urls = match &entry.data {
            EntryData::Login(d) => &d.urls,
            _ => continue,
        };

        for url in urls {
            let lower = url.to_lowercase();
            if lower.starts_with("http://") {
                results.push(UnsecuredUrl {
                    entry_id: entry.id.clone(),
                    entry_name: entry.name.clone(),
                    url: url.clone(),
                });
            }
        }
    }

    results
}

fn check_missing_totp(entries: &[VaultEntry]) -> Vec<MissingTOTP> {
    let mut results = Vec::new();

    for entry in entries {
        if let EntryData::Login(d) = &entry.data {
            if d.totp_secret.is_none() {
                results.push(MissingTOTP {
                    entry_id: entry.id.clone(),
                    entry_name: entry.name.clone(),
                });
            }
        }
    }

    results
}

fn check_expired(entries: &[VaultEntry]) -> Vec<ExpiredEntry> {
    let now = chrono::Utc::now();
    let mut results = Vec::new();

    for entry in entries {
        if let Some(ref exp) = entry.expires_at {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                if dt < now {
                    results.push(ExpiredEntry {
                        entry_id: entry.id.clone(),
                        entry_name: entry.name.clone(),
                        expired_at: exp.clone(),
                    });
                }
            }
        }
    }

    results
}

/// Compute a weighted health score in [0, 100].
///
/// Deductions (clamped so the score never goes negative):
/// - 10 pts per weak password
/// - 15 pts per reused-password group
/// - 5 pts per unsecured URL
/// - 3 pts per login missing TOTP
/// - 5 pts per expired entry
fn calculate_score(report: &HealthReport) -> u32 {
    if report.login_entries == 0 {
        return 100;
    }

    let mut deductions: i32 = 0;
    deductions += report.weak_passwords.len() as i32 * 10;
    deductions += report.reused_passwords.len() as i32 * 15;
    deductions += report.unsecured_urls.len() as i32 * 5;
    deductions += report.missing_totp.len() as i32 * 3;
    deductions += report.expired_entries.len() as i32 * 5;

    let raw = 100i32 - deductions;
    raw.max(0) as u32
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    fn make_login(name: &str, password: &str, urls: Vec<String>) -> VaultEntry {
        VaultEntry::new_login(name, "user", password, urls)
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(password_entropy(""), 0.0);
    }

    #[test]
    fn entropy_lowercase_only() {
        // 8 lowercase chars => 8 * log2(26) ≈ 37.6 bits
        let bits = password_entropy("abcdefgh");
        assert!(bits > 37.0 && bits < 38.0, "got {bits}");
    }

    #[test]
    fn entropy_mixed() {
        // "Aa1!" uses all 4 classes => pool = 95, 4 * log2(95) ≈ 26.3
        let bits = password_entropy("Aa1!");
        assert!(bits > 26.0 && bits < 27.0, "got {bits}");
    }

    #[test]
    fn weak_password_detected() {
        let entries = vec![make_login("bad", "123", vec![])];
        let weak = check_weak_passwords(&entries);
        assert_eq!(weak.len(), 1);
        assert!(weak[0].entropy_bits < 40.0);
    }

    #[test]
    fn strong_password_not_flagged() {
        let entries = vec![make_login("good", "Tr0ub4dor&3xPl!cit99", vec![])];
        let weak = check_weak_passwords(&entries);
        assert!(weak.is_empty());
    }

    #[test]
    fn reused_passwords_grouped() {
        let entries = vec![
            make_login("site-a", "same_password", vec![]),
            make_login("site-b", "same_password", vec![]),
            make_login("site-c", "different", vec![]),
        ];
        let reused = check_reused_passwords(&entries);
        assert_eq!(reused.len(), 1);
        assert_eq!(reused[0].entry_ids.len(), 2);
    }

    #[test]
    fn unsecured_url_detected() {
        let entries = vec![
            make_login("http-site", "pw", vec!["http://example.com".into()]),
            make_login("https-site", "pw", vec!["https://example.com".into()]),
        ];
        let unsec = check_unsecured_urls(&entries);
        assert_eq!(unsec.len(), 1);
        assert_eq!(unsec[0].entry_name, "http-site");
    }

    #[test]
    fn missing_totp_detected() {
        let entries = vec![make_login("no-2fa", "pw123", vec![])];
        let missing = check_missing_totp(&entries);
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn expired_entry_detected() {
        let mut entry = make_login("old", "pw", vec![]);
        entry.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        let expired = check_expired(&[entry]);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn score_perfect_vault() {
        let mut entry = make_login("good", "Tr0ub4dor&3xPl!cit99", vec!["https://site-35.example".into()]);
        if let EntryData::Login(ref mut d) = entry.data {
            d.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        }
        let report = analyze(&[entry]);
        assert_eq!(report.score, 100);
    }

    #[test]
    fn score_degrades_with_issues() {
        let entries = vec![
            make_login("bad1", "123", vec!["http://site-35.example".into()]),
            make_login("bad2", "123", vec![]),
        ];
        let report = analyze(&entries);
        assert!(report.score < 100);
        assert!(!report.weak_passwords.is_empty());
        assert!(!report.reused_passwords.is_empty());
    }

    #[test]
    fn analyze_handles_empty() {
        let report = analyze(&[]);
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.score, 100);
    }
}
