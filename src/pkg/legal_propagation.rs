//! Legal metadata propagation through transitive dependency trees.
//!
//! When a package depends on others, the legal requirements compose:
//! - All legal bases used across the dependency tree are collected
//! - If ANY dependency handles personal data, the consumer must too
//! - Jurisdiction coverage must be a superset of all dependencies
//! - Retention periods use the shortest (most restrictive) value

use std::collections::HashSet;

// ── Legal Metadata (per-package) ────────────────────────────────────────────

/// Legal metadata extracted from a package's tallow.toml `[legal]` section.
#[derive(Debug, Clone, PartialEq)]
pub struct LegalMetadata {
    pub basis: Option<String>,
    pub personal_data: bool,
    pub jurisdictions: Vec<String>,
    pub retain_for: Option<String>,
}

impl Default for LegalMetadata {
    fn default() -> Self {
        Self {
            basis: None,
            personal_data: false,
            jurisdictions: Vec::new(),
            retain_for: None,
        }
    }
}

/// Parse `[legal]` section from a tallow.toml string.
pub fn parse_legal_metadata(manifest_content: &str) -> Option<LegalMetadata> {
    let table: toml::Table = manifest_content.parse().ok()?;
    let legal = table.get("legal")?.as_table()?;

    let basis = legal
        .get("basis")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let personal_data = legal
        .get("personal_data")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let jurisdictions: Vec<String> = legal
        .get("jurisdictions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Also support `default_jurisdiction` (the existing field name)
    let jurisdictions = if jurisdictions.is_empty() {
        legal
            .get("default_jurisdiction")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        jurisdictions
    };

    let retain_for = legal
        .get("retain_for")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(LegalMetadata {
        basis,
        personal_data,
        jurisdictions,
        retain_for,
    })
}

// ── Composed Legal (union of transitive deps) ───────────────────────────────

/// Union of all transitive dependencies' legal metadata.
#[derive(Debug, Clone, Default)]
pub struct ComposedLegal {
    /// All legal bases used across dependencies.
    pub bases: HashSet<String>,
    /// True if ANY dependency handles personal data.
    pub personal_data: bool,
    /// Union of all jurisdictions across dependencies.
    pub jurisdictions: HashSet<String>,
    /// Shortest retention period across all dependencies (most restrictive).
    pub min_retain_for: Option<String>,
}

/// A violation found when validating consumer against composed legal requirements.
#[derive(Debug, Clone, PartialEq)]
pub struct LegalViolation {
    pub code: String,
    pub message: String,
}

/// Conflicting bases that cannot coexist on the same data flow.
const CONFLICTING_PAIRS: &[(&str, &str)] = &[
    ("consent", "public_data"),
];

/// Parse a retention string to approximate days for comparison.
/// Supports formats like "30d", "7d", "365d", "90.days", "30.days".
fn retention_to_days(s: &str) -> Option<u64> {
    let s = s.trim();
    // Try "Nd" or "N.days" format
    if let Some(n) = s.strip_suffix("d") {
        return n.trim().parse().ok();
    }
    if let Some(n) = s.strip_suffix(".days") {
        return n.trim().parse().ok();
    }
    // Try plain number (assume days)
    s.parse().ok()
}

/// Compose legal metadata from all dependencies into a unified view.
///
/// Returns `Err` if conflicting legal bases are found (e.g., consent + public_data).
pub fn compose_legal(deps: &[(String, LegalMetadata)]) -> Result<ComposedLegal, LegalViolation> {
    let mut composed = ComposedLegal::default();

    for (name, meta) in deps {
        if let Some(ref basis) = meta.basis {
            composed.bases.insert(basis.clone());
        }

        if meta.personal_data {
            composed.personal_data = true;
        }

        for j in &meta.jurisdictions {
            composed.jurisdictions.insert(j.clone());
        }

        if let Some(ref retain) = meta.retain_for {
            match (&composed.min_retain_for, retention_to_days(retain)) {
                (None, _) => {
                    composed.min_retain_for = Some(retain.clone());
                }
                (Some(existing), Some(new_days)) => {
                    if let Some(existing_days) = retention_to_days(existing) {
                        if new_days < existing_days {
                            composed.min_retain_for = Some(retain.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        // Check for conflicting bases
        for &(a, b) in CONFLICTING_PAIRS {
            if composed.bases.contains(a) && composed.bases.contains(b) {
                return Err(LegalViolation {
                    code: "E0112".to_string(),
                    message: format!(
                        "conflicting legal bases in dependency tree: .{a} (from one dep) \
                         and .{b} (from another) cannot coexist on the same data flow"
                    ),
                });
            }
        }

        let _ = name; // used for future diagnostics
    }

    Ok(composed)
}

/// Validate that a consumer's @legal annotation satisfies the composed requirements
/// from all transitive dependencies.
pub fn validate_consumer_legal(
    _consumer_basis: Option<&str>,
    consumer_personal_data: bool,
    consumer_jurisdictions: &HashSet<String>,
    consumer_consent_ref: bool,
    composed: &ComposedLegal,
) -> Vec<LegalViolation> {
    let mut violations = Vec::new();

    // If any dep requires personal_data, consumer must declare it
    if composed.personal_data && !consumer_personal_data {
        violations.push(LegalViolation {
            code: "E0113".to_string(),
            message: "dependency handles personal data but consumer's @legal does not declare \
                      personal_data: true"
                .to_string(),
        });
    }

    // If any dep uses consent basis, consumer must have consent_ref
    if composed.bases.contains("consent") && !consumer_consent_ref {
        violations.push(LegalViolation {
            code: "E0112".to_string(),
            message: "dependency uses basis: .consent but consumer has no consent_ref".to_string(),
        });
    }

    // Consumer jurisdictions must be superset of dep jurisdictions
    if !composed.jurisdictions.is_empty() && !consumer_jurisdictions.is_empty() {
        let missing: Vec<_> = composed
            .jurisdictions
            .iter()
            .filter(|j| !consumer_jurisdictions.contains(*j))
            .collect();
        if !missing.is_empty() {
            violations.push(LegalViolation {
                code: "E0114".to_string(),
                message: format!(
                    "dependency requires jurisdiction coverage for {:?} but consumer \
                     only covers {:?}",
                    missing, consumer_jurisdictions
                ),
            });
        }
    }

    violations
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_legal_metadata() {
        let toml = r#"
[package]
name = "test"
version = "1.0.0"

[legal]
basis = "public_data"
personal_data = false
jurisdictions = ["us", "eu"]
retain_for = "30d"
"#;
        let meta = parse_legal_metadata(toml).unwrap();
        assert_eq!(meta.basis.as_deref(), Some("public_data"));
        assert!(!meta.personal_data);
        assert_eq!(meta.jurisdictions, vec!["us", "eu"]);
        assert_eq!(meta.retain_for.as_deref(), Some("30d"));
    }

    #[test]
    fn test_parse_legal_metadata_default_jurisdiction() {
        let toml = r#"
[package]
name = "test"
version = "1.0.0"

[legal]
default_jurisdiction = ["us", "eu"]
"#;
        let meta = parse_legal_metadata(toml).unwrap();
        assert_eq!(meta.jurisdictions, vec!["us", "eu"]);
    }

    #[test]
    fn test_parse_legal_metadata_absent() {
        let toml = r#"
[package]
name = "test"
version = "1.0.0"
"#;
        assert!(parse_legal_metadata(toml).is_none());
    }

    #[test]
    fn test_compose_compatible_bases() {
        let deps = vec![
            ("dep-a".to_string(), LegalMetadata {
                basis: Some("public_data".to_string()),
                personal_data: false,
                jurisdictions: vec!["us".to_string()],
                retain_for: Some("30d".to_string()),
            }),
            ("dep-b".to_string(), LegalMetadata {
                basis: Some("public_data".to_string()),
                personal_data: false,
                jurisdictions: vec!["eu".to_string()],
                retain_for: Some("90d".to_string()),
            }),
        ];

        let composed = compose_legal(&deps).unwrap();
        assert_eq!(composed.bases.len(), 1);
        assert!(composed.bases.contains("public_data"));
        assert!(!composed.personal_data);
        assert!(composed.jurisdictions.contains("us"));
        assert!(composed.jurisdictions.contains("eu"));
        // min_retain_for should be 30d (shortest)
        assert_eq!(composed.min_retain_for.as_deref(), Some("30d"));
    }

    #[test]
    fn test_compose_conflicting_bases() {
        let deps = vec![
            ("dep-a".to_string(), LegalMetadata {
                basis: Some("consent".to_string()),
                personal_data: true,
                jurisdictions: vec![],
                retain_for: None,
            }),
            ("dep-b".to_string(), LegalMetadata {
                basis: Some("public_data".to_string()),
                personal_data: false,
                jurisdictions: vec![],
                retain_for: None,
            }),
        ];

        let err = compose_legal(&deps).unwrap_err();
        assert_eq!(err.code, "E0112");
        assert!(err.message.contains("conflicting"));
    }

    #[test]
    fn test_compose_personal_data_propagates() {
        let deps = vec![
            ("dep-a".to_string(), LegalMetadata {
                basis: Some("research".to_string()),
                personal_data: false,
                jurisdictions: vec![],
                retain_for: None,
            }),
            ("dep-b".to_string(), LegalMetadata {
                basis: Some("research".to_string()),
                personal_data: true,
                jurisdictions: vec![],
                retain_for: None,
            }),
        ];

        let composed = compose_legal(&deps).unwrap();
        assert!(composed.personal_data, "personal_data should propagate from any dep");
    }

    #[test]
    fn test_validate_consumer_missing_personal_data() {
        let composed = ComposedLegal {
            bases: HashSet::new(),
            personal_data: true,
            jurisdictions: HashSet::new(),
            min_retain_for: None,
        };

        let violations = validate_consumer_legal(
            Some("research"),
            false, // consumer does NOT declare personal_data
            &HashSet::new(),
            false,
            &composed,
        );

        assert!(violations.iter().any(|v| v.code == "E0113"));
    }

    #[test]
    fn test_validate_consumer_with_personal_data_ok() {
        let composed = ComposedLegal {
            bases: HashSet::new(),
            personal_data: true,
            jurisdictions: HashSet::new(),
            min_retain_for: None,
        };

        let violations = validate_consumer_legal(
            Some("research"),
            true, // consumer DOES declare personal_data
            &HashSet::new(),
            false,
            &composed,
        );

        assert!(!violations.iter().any(|v| v.code == "E0113"));
    }

    #[test]
    fn test_validate_jurisdiction_superset() {
        let mut dep_jurisdictions = HashSet::new();
        dep_jurisdictions.insert("us".to_string());
        dep_jurisdictions.insert("eu".to_string());
        dep_jurisdictions.insert("uk".to_string());

        let composed = ComposedLegal {
            bases: HashSet::new(),
            personal_data: false,
            jurisdictions: dep_jurisdictions,
            min_retain_for: None,
        };

        // Consumer only covers us and eu, missing uk
        let mut consumer_j = HashSet::new();
        consumer_j.insert("us".to_string());
        consumer_j.insert("eu".to_string());

        let violations = validate_consumer_legal(
            Some("public_data"),
            false,
            &consumer_j,
            false,
            &composed,
        );

        assert!(violations.iter().any(|v| v.code == "E0114"));
    }

    #[test]
    fn test_validate_jurisdiction_superset_ok() {
        let mut dep_jurisdictions = HashSet::new();
        dep_jurisdictions.insert("us".to_string());
        dep_jurisdictions.insert("eu".to_string());

        let composed = ComposedLegal {
            bases: HashSet::new(),
            personal_data: false,
            jurisdictions: dep_jurisdictions,
            min_retain_for: None,
        };

        let mut consumer_j = HashSet::new();
        consumer_j.insert("us".to_string());
        consumer_j.insert("eu".to_string());
        consumer_j.insert("uk".to_string()); // superset

        let violations = validate_consumer_legal(
            Some("public_data"),
            false,
            &consumer_j,
            false,
            &composed,
        );

        assert!(!violations.iter().any(|v| v.code == "E0114"));
    }

    #[test]
    fn test_validate_consent_needs_consent_ref() {
        let mut bases = HashSet::new();
        bases.insert("consent".to_string());

        let composed = ComposedLegal {
            bases,
            personal_data: false,
            jurisdictions: HashSet::new(),
            min_retain_for: None,
        };

        let violations = validate_consumer_legal(
            Some("consent"),
            false,
            &HashSet::new(),
            false, // no consent_ref
            &composed,
        );

        assert!(violations.iter().any(|v| v.code == "E0112"));
    }

    #[test]
    fn test_retention_shortest_wins() {
        let deps = vec![
            ("dep-a".to_string(), LegalMetadata {
                basis: None,
                personal_data: false,
                jurisdictions: vec![],
                retain_for: Some("90d".to_string()),
            }),
            ("dep-b".to_string(), LegalMetadata {
                basis: None,
                personal_data: false,
                jurisdictions: vec![],
                retain_for: Some("7d".to_string()),
            }),
            ("dep-c".to_string(), LegalMetadata {
                basis: None,
                personal_data: false,
                jurisdictions: vec![],
                retain_for: Some("30d".to_string()),
            }),
        ];

        let composed = compose_legal(&deps).unwrap();
        assert_eq!(composed.min_retain_for.as_deref(), Some("7d"));
    }
}
