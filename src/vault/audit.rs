//! Compliance Audit -- GDPR Art.32, NIST 800-63B, PCI-DSS Req.8, ISO 27001 A.9,
//! and post-quantum readiness assessment for vault contents.

use super::db::VaultDatabase;
use super::entry::{EntryData, VaultEntry};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Complete audit report for a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAuditReport {
    pub generated_at: String,
    pub vault_name: String,
    pub overall_grade: char,
    pub sections: Vec<AuditSection>,
    pub recommendations: Vec<String>,
    pub compliance: ComplianceStatus,
}

/// A scored audit section with findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSection {
    pub name: String,
    pub score: u32,
    pub findings: Vec<AuditFinding>,
}

/// A single audit finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub affected_entries: Vec<String>,
    pub remediation: String,
}

/// Finding severity levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Compliance framework status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    /// GDPR Article 32: Security of processing.
    pub gdpr_article_32: bool,
    /// NIST SP 800-63B: Digital identity guidelines.
    pub nist_800_63b: bool,
    /// PCI-DSS Requirement 8: Identify and authenticate access.
    pub pci_dss_req8: bool,
    /// ISO 27001 Annex A.9: Access control.
    pub iso_27001_a9: bool,
    /// Post-quantum cryptography readiness.
    pub pqc_ready: bool,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum acceptable password length (NIST 800-63B).
const MIN_PASSWORD_LENGTH: usize = 8;
/// Passwords shorter than this are considered critically weak.
const CRITICAL_PASSWORD_LENGTH: usize = 4;
/// Entries not updated in this many days trigger a warning.
const STALE_ENTRY_DAYS: i64 = 90;
/// Entries not updated in this many days are considered very old.
const OLD_ENTRY_DAYS: i64 = 365;

// ---------------------------------------------------------------------------
// Password entropy estimation
// ---------------------------------------------------------------------------

/// Estimate the Shannon entropy of a password in bits.
fn estimate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut charset_size: u32 = 0;
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if has_lower {
        charset_size += 26;
    }
    if has_upper {
        charset_size += 26;
    }
    if has_digit {
        charset_size += 10;
    }
    if has_special {
        charset_size += 32;
    }
    if charset_size == 0 {
        charset_size = 26; // fallback for non-ASCII
    }

    password.len() as f64 * (charset_size as f64).log2()
}

/// Well-known weak passwords to check against.
const WEAK_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "1234567",
    "letmein",
    "trustno1",
    "dragon",
    "baseball",
    "iloveyou",
    "master",
    "sunshine",
    "ashley",
    "bailey",
    "passw0rd",
    "shadow",
    "123123",
    "654321",
    "superman",
    "qazwsx",
    "michael",
    "football",
    "password1",
    "password123",
    "admin",
    "welcome",
    "hello",
    "charlie",
];

fn is_weak_password(password: &str) -> bool {
    let lower = password.to_lowercase();
    WEAK_PASSWORDS.contains(&lower.as_str())
        || password.len() < CRITICAL_PASSWORD_LENGTH
        || password.chars().collect::<std::collections::HashSet<_>>().len() <= 2
}

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

fn days_since(timestamp: &str) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let now = chrono::Utc::now();
    Some((now - parsed.with_timezone(&chrono::Utc)).num_days())
}

// ---------------------------------------------------------------------------
// Audit sections
// ---------------------------------------------------------------------------

/// Audit encryption configuration.
fn audit_encryption(db: &VaultDatabase) -> AuditSection {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    // Check PQC setting
    if !db.settings.pqc_enabled {
        findings.push(AuditFinding {
            severity: Severity::Medium,
            category: "Encryption".into(),
            description: "Post-quantum encryption (PQC) is not enabled at the vault level."
                .into(),
            affected_entries: vec![],
            remediation:
                "Enable pqc_enabled in vault settings to protect against quantum threats."
                    .into(),
        });
        score = score.saturating_sub(15);
    }

    // Check auto-lock setting
    if db.settings.auto_lock_seconds > 600 {
        findings.push(AuditFinding {
            severity: Severity::Low,
            category: "Encryption".into(),
            description: format!(
                "Auto-lock timeout is {}s (>600s). Consider reducing for better security.",
                db.settings.auto_lock_seconds
            ),
            affected_entries: vec![],
            remediation: "Set auto_lock_seconds to 300 or less.".into(),
        });
        score = score.saturating_sub(5);
    }

    // Check clipboard clear setting
    if db.settings.clipboard_clear_seconds > 60 {
        findings.push(AuditFinding {
            severity: Severity::Low,
            category: "Encryption".into(),
            description: format!(
                "Clipboard clear timeout is {}s (>60s). Sensitive data may linger on clipboard.",
                db.settings.clipboard_clear_seconds
            ),
            affected_entries: vec![],
            remediation: "Set clipboard_clear_seconds to 30 or less.".into(),
        });
        score = score.saturating_sub(5);
    }

    // AES-256-GCM is always used (enforced by db.rs), so that's always compliant
    if findings.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Info,
            category: "Encryption".into(),
            description: "Vault uses AES-256-GCM with Argon2id key derivation. All settings optimal.".into(),
            affected_entries: vec![],
            remediation: String::new(),
        });
    }

    AuditSection {
        name: "Encryption".into(),
        score,
        findings,
    }
}

/// Audit password hygiene across all login entries.
fn audit_passwords(db: &VaultDatabase) -> AuditSection {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    let logins: Vec<&VaultEntry> = db
        .entries
        .iter()
        .filter(|e| matches!(e.data, EntryData::Login(_)))
        .collect();

    if logins.is_empty() {
        return AuditSection {
            name: "Password Hygiene".into(),
            score: 100,
            findings: vec![AuditFinding {
                severity: Severity::Info,
                category: "Passwords".into(),
                description: "No login entries to audit.".into(),
                affected_entries: vec![],
                remediation: String::new(),
            }],
        };
    }

    // Collect passwords for reuse detection
    let mut password_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut weak_entries = Vec::new();
    let mut short_entries = Vec::new();
    let mut low_entropy_entries = Vec::new();

    for entry in &logins {
        if let EntryData::Login(ref data) = entry.data {
            // Track password reuse
            password_map
                .entry(data.password.clone())
                .or_default()
                .push(entry.name.clone());

            // Check for weak passwords
            if is_weak_password(&data.password) {
                weak_entries.push(entry.name.clone());
            }

            // Check minimum length
            if data.password.len() < MIN_PASSWORD_LENGTH {
                short_entries.push(entry.name.clone());
            }

            // Check entropy
            let entropy = estimate_entropy(&data.password);
            if entropy < 28.0 {
                low_entropy_entries.push(entry.name.clone());
            }
        }
    }

    // Report weak passwords
    if !weak_entries.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Critical,
            category: "Passwords".into(),
            description: format!(
                "{} entries use commonly-known weak passwords.",
                weak_entries.len()
            ),
            affected_entries: weak_entries,
            remediation: "Replace with strong, randomly-generated passwords (20+ characters)."
                .into(),
        });
        score = score.saturating_sub(30);
    }

    // Report short passwords
    if !short_entries.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::High,
            category: "Passwords".into(),
            description: format!(
                "{} entries have passwords shorter than {} characters (NIST 800-63B minimum).",
                short_entries.len(),
                MIN_PASSWORD_LENGTH
            ),
            affected_entries: short_entries,
            remediation: "Use passwords of at least 8 characters, preferably 16+.".into(),
        });
        score = score.saturating_sub(20);
    }

    // Report low entropy
    if !low_entropy_entries.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::High,
            category: "Passwords".into(),
            description: format!(
                "{} entries have passwords with low entropy (<28 bits).",
                low_entropy_entries.len()
            ),
            affected_entries: low_entropy_entries,
            remediation:
                "Use passwords with mixed case, digits, and symbols for higher entropy."
                    .into(),
        });
        score = score.saturating_sub(15);
    }

    // Report reused passwords
    let reused: Vec<_> = password_map
        .values()
        .filter(|names| names.len() > 1)
        .collect();
    if !reused.is_empty() {
        let total_reused: usize = reused.iter().map(|v| v.len()).sum();
        let affected: Vec<String> = reused.iter().flat_map(|v| v.iter().cloned()).collect();
        findings.push(AuditFinding {
            severity: Severity::High,
            category: "Passwords".into(),
            description: format!(
                "{} entries share passwords across {} groups. Password reuse is a major risk.",
                total_reused,
                reused.len()
            ),
            affected_entries: affected,
            remediation: "Use unique passwords for every account.".into(),
        });
        score = score.saturating_sub(20);
    }

    // Check for stale passwords
    let mut stale_entries = Vec::new();
    for entry in &logins {
        if let Some(days) = days_since(&entry.updated_at) {
            if days > STALE_ENTRY_DAYS {
                stale_entries.push(entry.name.clone());
            }
        }
    }
    if !stale_entries.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Medium,
            category: "Passwords".into(),
            description: format!(
                "{} entries have not been updated in over {} days.",
                stale_entries.len(),
                STALE_ENTRY_DAYS
            ),
            affected_entries: stale_entries,
            remediation: "Rotate passwords periodically, especially for critical accounts."
                .into(),
        });
        score = score.saturating_sub(10);
    }

    AuditSection {
        name: "Password Hygiene".into(),
        score,
        findings,
    }
}

/// Audit access control and organization.
fn audit_access_control(db: &VaultDatabase) -> AuditSection {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    // Check for entries with raw secrets in notes
    let mut secrets_in_notes = Vec::new();
    let secret_patterns = [
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "private_key",
        "access_key",
        "client_secret",
    ];
    for entry in &db.entries {
        if let Some(ref notes) = entry.notes {
            let lower = notes.to_lowercase();
            for pattern in &secret_patterns {
                if lower.contains(pattern) {
                    secrets_in_notes.push(entry.name.clone());
                    break;
                }
            }
        }
    }
    if !secrets_in_notes.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Medium,
            category: "Access Control".into(),
            description: format!(
                "{} entries may contain raw secrets in their notes fields.",
                secrets_in_notes.len()
            ),
            affected_entries: secrets_in_notes,
            remediation:
                "Move secrets to dedicated fields (password, API key) instead of freeform notes."
                    .into(),
        });
        score = score.saturating_sub(15);
    }

    // Check for unorganized entries (no folder)
    let no_folder: Vec<String> = db
        .entries
        .iter()
        .filter(|e| e.folder.is_none())
        .map(|e| e.name.clone())
        .collect();
    if !no_folder.is_empty() && db.entries.len() > 5 {
        let pct = (no_folder.len() * 100) / db.entries.len().max(1);
        if pct > 50 {
            findings.push(AuditFinding {
                severity: Severity::Low,
                category: "Access Control".into(),
                description: format!(
                    "{}% of entries ({}/{}) have no folder assigned.",
                    pct,
                    no_folder.len(),
                    db.entries.len()
                ),
                affected_entries: no_folder,
                remediation: "Organize entries into folders for better access management.".into(),
            });
            score = score.saturating_sub(10);
        }
    }

    // Check favorites ratio (are critical entries bookmarked for quick access?)
    let fav_count = db.entries.iter().filter(|e| e.favorite).count();
    if db.entries.len() > 10 && fav_count == 0 {
        findings.push(AuditFinding {
            severity: Severity::Info,
            category: "Access Control".into(),
            description: "No entries are marked as favorites.".into(),
            affected_entries: vec![],
            remediation:
                "Mark frequently-used entries as favorites for faster access.".into(),
        });
        score = score.saturating_sub(5);
    }

    if findings.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Info,
            category: "Access Control".into(),
            description: "Access control and organization look good.".into(),
            affected_entries: vec![],
            remediation: String::new(),
        });
    }

    AuditSection {
        name: "Access Control".into(),
        score,
        findings,
    }
}

/// Audit data retention policies.
fn audit_data_retention(db: &VaultDatabase) -> AuditSection {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    // Check for expired entries
    let now = chrono::Utc::now();
    let mut expired = Vec::new();
    let mut no_expiry = Vec::new();
    let mut very_old = Vec::new();

    for entry in &db.entries {
        // Check expiry
        if let Some(ref exp) = entry.expires_at {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                if dt.with_timezone(&chrono::Utc) < now {
                    expired.push(entry.name.clone());
                }
            }
        } else {
            no_expiry.push(entry.name.clone());
        }

        // Check age
        if let Some(days) = days_since(&entry.updated_at) {
            if days > OLD_ENTRY_DAYS {
                very_old.push(entry.name.clone());
            }
        }
    }

    if !expired.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::High,
            category: "Retention".into(),
            description: format!("{} entries are past their expiration date.", expired.len()),
            affected_entries: expired,
            remediation: "Remove or update expired entries. Expired credentials may be revoked."
                .into(),
        });
        score = score.saturating_sub(20);
    }

    if !very_old.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Medium,
            category: "Retention".into(),
            description: format!(
                "{} entries have not been updated in over {} days.",
                very_old.len(),
                OLD_ENTRY_DAYS
            ),
            affected_entries: very_old,
            remediation:
                "Review old entries: update credentials or remove entries no longer needed."
                    .into(),
        });
        score = score.saturating_sub(10);
    }

    // Entries without expiry set
    if !no_expiry.is_empty() && db.entries.len() > 3 {
        let pct = (no_expiry.len() * 100) / db.entries.len().max(1);
        if pct > 80 {
            findings.push(AuditFinding {
                severity: Severity::Low,
                category: "Retention".into(),
                description: format!(
                    "{}% of entries have no expiration date set.",
                    pct
                ),
                affected_entries: vec![],
                remediation:
                    "Set expiration dates on entries, especially for temporary credentials."
                        .into(),
            });
            score = score.saturating_sub(5);
        }
    }

    if findings.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Info,
            category: "Retention".into(),
            description: "Data retention looks good.".into(),
            affected_entries: vec![],
            remediation: String::new(),
        });
    }

    AuditSection {
        name: "Data Retention".into(),
        score,
        findings,
    }
}

/// Audit MFA (TOTP / passkey) coverage across login entries.
fn audit_mfa_coverage(db: &VaultDatabase) -> AuditSection {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    let logins: Vec<&VaultEntry> = db
        .entries
        .iter()
        .filter(|e| matches!(e.data, EntryData::Login(_)))
        .collect();

    if logins.is_empty() {
        return AuditSection {
            name: "MFA Coverage".into(),
            score: 100,
            findings: vec![AuditFinding {
                severity: Severity::Info,
                category: "MFA".into(),
                description: "No login entries to audit for MFA.".into(),
                affected_entries: vec![],
                remediation: String::new(),
            }],
        };
    }

    let mut no_totp = Vec::new();
    let mut no_passkey = Vec::new();
    let mut has_totp = 0u32;
    let mut has_passkey = 0u32;

    for entry in &logins {
        if let EntryData::Login(ref data) = entry.data {
            if data.totp_secret.is_some() {
                has_totp += 1;
            } else {
                no_totp.push(entry.name.clone());
            }
            if data.passkey.is_some() {
                has_passkey += 1;
            } else {
                no_passkey.push(entry.name.clone());
            }
        }
    }

    let total = logins.len() as u32;
    let totp_pct = (has_totp * 100) / total.max(1);
    let passkey_pct = (has_passkey * 100) / total.max(1);

    if totp_pct < 50 {
        findings.push(AuditFinding {
            severity: Severity::High,
            category: "MFA".into(),
            description: format!(
                "Only {}% ({}/{}) of login entries have TOTP configured.",
                totp_pct, has_totp, total
            ),
            affected_entries: no_totp,
            remediation: "Enable TOTP (two-factor authentication) on all accounts that support it."
                .into(),
        });
        score = score.saturating_sub(25);
    } else if totp_pct < 80 {
        findings.push(AuditFinding {
            severity: Severity::Medium,
            category: "MFA".into(),
            description: format!(
                "{}% ({}/{}) of login entries have TOTP. Aim for 100%.",
                totp_pct, has_totp, total
            ),
            affected_entries: no_totp,
            remediation: "Enable TOTP on remaining accounts.".into(),
        });
        score = score.saturating_sub(10);
    }

    if passkey_pct == 0 && total > 0 {
        findings.push(AuditFinding {
            severity: Severity::Low,
            category: "MFA".into(),
            description: "No login entries have passkeys configured.".into(),
            affected_entries: vec![],
            remediation: "Consider using passkeys (FIDO2/WebAuthn) where supported for phishing-resistant auth.".into(),
        });
        score = score.saturating_sub(5);
    }

    if findings.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Info,
            category: "MFA".into(),
            description: format!(
                "MFA coverage is excellent: {}% TOTP, {}% passkey.",
                totp_pct, passkey_pct
            ),
            affected_entries: vec![],
            remediation: String::new(),
        });
    }

    AuditSection {
        name: "MFA Coverage".into(),
        score,
        findings,
    }
}

/// Audit post-quantum cryptography readiness.
fn audit_pqc_readiness(db: &VaultDatabase) -> AuditSection {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    if db.settings.pqc_enabled {
        findings.push(AuditFinding {
            severity: Severity::Info,
            category: "PQC".into(),
            description: "Vault-level PQC encryption is enabled (ML-KEM-768 + AES-256-GCM hybrid).".into(),
            affected_entries: vec![],
            remediation: String::new(),
        });
    } else {
        findings.push(AuditFinding {
            severity: Severity::Medium,
            category: "PQC".into(),
            description: "Vault is not using post-quantum encryption. Data is protected by AES-256-GCM only.".into(),
            affected_entries: vec![],
            remediation: "Enable PQC to defend against future quantum computer attacks (NIST PQC deadline: 2030).".into(),
        });
        score = score.saturating_sub(20);
    }

    // Check SSH keys for PQC-vulnerable algorithms
    let mut vulnerable_keys = Vec::new();
    for entry in &db.entries {
        if let EntryData::SSHKey(ref data) = entry.data {
            let ktype = data.key_type.to_lowercase();
            if ktype.contains("rsa") || ktype.contains("ecdsa") || ktype.contains("ed25519") {
                vulnerable_keys.push(entry.name.clone());
            }
        }
    }
    if !vulnerable_keys.is_empty() {
        findings.push(AuditFinding {
            severity: Severity::Low,
            category: "PQC".into(),
            description: format!(
                "{} SSH keys use classical algorithms (RSA/ECDSA/Ed25519) vulnerable to quantum attacks.",
                vulnerable_keys.len()
            ),
            affected_entries: vulnerable_keys,
            remediation: "Consider migrating to PQC-safe SSH key types when available.".into(),
        });
        score = score.saturating_sub(10);
    }

    AuditSection {
        name: "PQC Readiness".into(),
        score,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Grading & recommendations
// ---------------------------------------------------------------------------

/// Compute overall letter grade from section scores.
/// Weights: Encryption 25%, Passwords 30%, Access 10%, Retention 10%, MFA 15%, PQC 10%.
fn compute_grade(sections: &[AuditSection]) -> char {
    if sections.is_empty() {
        return 'A';
    }

    let weights: &[(&str, f64)] = &[
        ("Encryption", 0.25),
        ("Password Hygiene", 0.30),
        ("Access Control", 0.10),
        ("Data Retention", 0.10),
        ("MFA Coverage", 0.15),
        ("PQC Readiness", 0.10),
    ];

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for section in sections {
        let w = weights
            .iter()
            .find(|(name, _)| *name == section.name)
            .map(|(_, w)| *w)
            .unwrap_or(0.1);
        weighted_sum += section.score as f64 * w;
        total_weight += w;
    }

    let avg = if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        100.0
    };

    match avg as u32 {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    }
}

/// Generate actionable recommendations from audit sections.
fn generate_recommendations(sections: &[AuditSection]) -> Vec<String> {
    let mut recs = Vec::new();

    for section in sections {
        for finding in &section.findings {
            if !finding.remediation.is_empty()
                && matches!(
                    finding.severity,
                    Severity::Critical | Severity::High | Severity::Medium
                )
            {
                recs.push(format!(
                    "[{}] {}: {}",
                    match finding.severity {
                        Severity::Critical => "CRITICAL",
                        Severity::High => "HIGH",
                        Severity::Medium => "MEDIUM",
                        _ => "INFO",
                    },
                    finding.category,
                    finding.remediation
                ));
            }
        }
    }

    // Deduplicate
    recs.sort();
    recs.dedup();
    recs
}

/// Map audit findings to compliance framework status.
fn check_compliance(sections: &[AuditSection], db: &VaultDatabase) -> ComplianceStatus {
    let get_score = |name: &str| -> u32 {
        sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.score)
            .unwrap_or(0)
    };

    let encryption_score = get_score("Encryption");
    let password_score = get_score("Password Hygiene");
    let access_score = get_score("Access Control");
    let mfa_score = get_score("MFA Coverage");
    let pqc_score = get_score("PQC Readiness");

    // GDPR Art.32: appropriate technical measures (encryption + access control)
    let gdpr_article_32 = encryption_score >= 80 && access_score >= 70;

    // NIST 800-63B: password requirements + MFA
    let nist_800_63b = password_score >= 70 && mfa_score >= 60;

    // PCI-DSS Req.8: strong authentication + unique credentials
    let pci_dss_req8 = password_score >= 80 && mfa_score >= 70;

    // ISO 27001 A.9: access control + organization
    let iso_27001_a9 = access_score >= 70 && encryption_score >= 70;

    // PQC readiness: explicit PQC enabled
    let pqc_ready = db.settings.pqc_enabled && pqc_score >= 80;

    ComplianceStatus {
        gdpr_article_32,
        nist_800_63b,
        pci_dss_req8,
        iso_27001_a9,
        pqc_ready,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a full compliance audit on the vault.
pub fn full_audit(db: &VaultDatabase) -> VaultAuditReport {
    let sections = vec![
        audit_encryption(db),
        audit_passwords(db),
        audit_access_control(db),
        audit_data_retention(db),
        audit_mfa_coverage(db),
        audit_pqc_readiness(db),
    ];

    let overall_grade = compute_grade(&sections);
    let recommendations = generate_recommendations(&sections);
    let compliance = check_compliance(&sections, db);

    VaultAuditReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        vault_name: db.name.clone(),
        overall_grade,
        sections,
        recommendations,
        compliance,
    }
}

/// Format an audit report as human-readable text.
pub fn format_report(report: &VaultAuditReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "=== Vault Audit Report: {} ===\n",
        report.vault_name
    ));
    out.push_str(&format!("Generated: {}\n", report.generated_at));
    out.push_str(&format!("Overall Grade: {}\n\n", report.overall_grade));

    for section in &report.sections {
        out.push_str(&format!("--- {} (Score: {}/100) ---\n", section.name, section.score));
        for finding in &section.findings {
            let sev = match finding.severity {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "INFO",
            };
            out.push_str(&format!("  [{}] {}\n", sev, finding.description));
            if !finding.affected_entries.is_empty() {
                out.push_str(&format!(
                    "    Affected: {}\n",
                    finding.affected_entries.join(", ")
                ));
            }
            if !finding.remediation.is_empty() {
                out.push_str(&format!("    Fix: {}\n", finding.remediation));
            }
        }
        out.push('\n');
    }

    if !report.recommendations.is_empty() {
        out.push_str("--- Recommendations ---\n");
        for (i, rec) in report.recommendations.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n", i + 1, rec));
        }
        out.push('\n');
    }

    out.push_str("--- Compliance Status ---\n");
    let c = &report.compliance;
    out.push_str(&format!(
        "  GDPR Art.32:    {}\n",
        if c.gdpr_article_32 { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  NIST 800-63B:   {}\n",
        if c.nist_800_63b { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  PCI-DSS Req.8:  {}\n",
        if c.pci_dss_req8 { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  ISO 27001 A.9:  {}\n",
        if c.iso_27001_a9 { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "  PQC Ready:      {}\n",
        if c.pqc_ready { "PASS" } else { "FAIL" }
    ));

    out
}

/// Format an audit report as JSON.
pub fn format_report_json(report: &VaultAuditReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    fn make_db(name: &str) -> VaultDatabase {
        VaultDatabase::new(name)
    }

    #[test]
    fn full_audit_empty_vault() {
        let db = make_db("empty");
        let report = full_audit(&db);

        assert_eq!(report.vault_name, "empty");
        assert!(!report.generated_at.is_empty());
        // Empty vault should score well (nothing wrong)
        assert!(
            report.overall_grade == 'A' || report.overall_grade == 'B',
            "empty vault grade should be A or B, got {}",
            report.overall_grade
        );
        assert_eq!(report.sections.len(), 6);
    }

    #[test]
    fn audit_detects_weak_passwords() {
        let mut db = make_db("weak");
        db.add_entry(VaultEntry::new_login(
            "Bad Site",
            "admin",
            "password",
            vec!["https://bad.com".into()],
        ));
        db.add_entry(VaultEntry::new_login(
            "Bad Site 2",
            "admin",
            "123456",
            vec![],
        ));
        db.add_entry(VaultEntry::new_login(
            "Short",
            "user",
            "ab",
            vec![],
        ));

        let report = full_audit(&db);

        // Password section should have critical/high findings
        let pw_section = report
            .sections
            .iter()
            .find(|s| s.name == "Password Hygiene")
            .unwrap();
        assert!(pw_section.score < 80, "weak passwords should lower score");
        assert!(
            pw_section
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical),
            "should have critical finding for weak passwords"
        );
    }

    #[test]
    fn audit_good_hygiene() {
        let mut db = make_db("good");
        db.settings.pqc_enabled = true;
        db.settings.auto_lock_seconds = 300;
        db.settings.clipboard_clear_seconds = 15;

        let mut entry = VaultEntry::new_login(
            "Secure Site",
            "user@example.com",
            "K$9xPm2!qR7vLn4@wBzF",
            vec!["https://secure.example.com".into()],
        );
        entry.folder = Some("Work".into());
        entry.favorite = true;
        if let EntryData::Login(ref mut data) = entry.data {
            data.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
            data.passkey = Some("passkey-data".into());
        }
        db.add_entry(entry);
        db.add_folder("Work");

        let report = full_audit(&db);
        assert!(
            report.overall_grade == 'A' || report.overall_grade == 'B',
            "good hygiene should get A or B, got {}",
            report.overall_grade
        );
    }

    #[test]
    fn grade_calculation() {
        let sections = vec![
            AuditSection {
                name: "Encryption".into(),
                score: 100,
                findings: vec![],
            },
            AuditSection {
                name: "Password Hygiene".into(),
                score: 95,
                findings: vec![],
            },
            AuditSection {
                name: "Access Control".into(),
                score: 90,
                findings: vec![],
            },
            AuditSection {
                name: "Data Retention".into(),
                score: 85,
                findings: vec![],
            },
            AuditSection {
                name: "MFA Coverage".into(),
                score: 80,
                findings: vec![],
            },
            AuditSection {
                name: "PQC Readiness".into(),
                score: 100,
                findings: vec![],
            },
        ];

        let grade = compute_grade(&sections);
        assert_eq!(grade, 'A', "high scores should produce A grade");

        // Low scores -> F
        let low_sections = vec![
            AuditSection {
                name: "Encryption".into(),
                score: 30,
                findings: vec![],
            },
            AuditSection {
                name: "Password Hygiene".into(),
                score: 20,
                findings: vec![],
            },
        ];
        let grade = compute_grade(&low_sections);
        assert_eq!(grade, 'F', "low scores should produce F grade");
    }

    #[test]
    fn compliance_check() {
        let mut db = make_db("compliant");
        db.settings.pqc_enabled = true;

        // Add a well-configured entry
        let mut entry = VaultEntry::new_login(
            "Good",
            "user",
            "Very$ecure!Password99#XyZ",
            vec![],
        );
        entry.folder = Some("Secure".into());
        if let EntryData::Login(ref mut data) = entry.data {
            data.totp_secret = Some("SECRET".into());
        }
        db.add_entry(entry);
        db.add_folder("Secure");

        let report = full_audit(&db);
        // With PQC enabled and good passwords, most compliance should pass
        assert!(report.compliance.gdpr_article_32);
    }

    #[test]
    fn report_formatting_text() {
        let db = make_db("format-test");
        let report = full_audit(&db);
        let text = format_report(&report);

        assert!(text.contains("Vault Audit Report: format-test"));
        assert!(text.contains("Overall Grade:"));
        assert!(text.contains("Compliance Status"));
        assert!(text.contains("GDPR Art.32:"));
        assert!(text.contains("PQC Ready:"));
    }

    #[test]
    fn report_formatting_json() {
        let db = make_db("json-test");
        let report = full_audit(&db);
        let json = format_report_json(&report);

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("invalid JSON");
        assert_eq!(parsed["vault_name"], "json-test");
        assert!(parsed["sections"].is_array());
        assert!(parsed["compliance"].is_object());
    }

    #[test]
    fn password_reuse_detection() {
        let mut db = make_db("reuse");
        // Same password for multiple entries
        db.add_entry(VaultEntry::new_login("Site A", "user1", "shared_password!", vec![]));
        db.add_entry(VaultEntry::new_login("Site B", "user2", "shared_password!", vec![]));
        db.add_entry(VaultEntry::new_login("Site C", "user3", "unique_Passw0rd#42", vec![]));

        let report = full_audit(&db);
        let pw_section = report
            .sections
            .iter()
            .find(|s| s.name == "Password Hygiene")
            .unwrap();

        // Should detect password reuse
        assert!(
            pw_section
                .findings
                .iter()
                .any(|f| f.description.contains("share passwords")),
            "should detect password reuse"
        );
    }

    #[test]
    fn mfa_coverage_low() {
        let mut db = make_db("no-mfa");
        for i in 0..5 {
            db.add_entry(VaultEntry::new_login(
                &format!("Site {i}"),
                &format!("user{i}"),
                &format!("StrongP@ss{i}!XyZ99"),
                vec![],
            ));
        }

        let report = full_audit(&db);
        let mfa_section = report
            .sections
            .iter()
            .find(|s| s.name == "MFA Coverage")
            .unwrap();

        assert!(mfa_section.score < 80, "no MFA should lower score");
        assert!(
            mfa_section
                .findings
                .iter()
                .any(|f| f.description.contains("TOTP")),
            "should flag missing TOTP"
        );
    }
}
