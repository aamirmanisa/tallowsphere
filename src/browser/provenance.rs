//! Price provenance tracking for HackTheCart.
//!
//! Every price carries a chain showing source, timestamp, extraction
//! method, validator chain, and a final confidence score with breakdown.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ValidationStep {
    pub validator: String,
    pub passed: bool,
    pub adjustment: f64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessTier {
    Fresh,  // < 15 min
    Recent, // < 6 hours
    Stale,  // < 24 hours
    Old,    // > 24 hours
}

#[derive(Debug, Clone)]
pub struct ProvenanceRecord {
    pub id: String,
    pub price_cents: i64,
    pub canonical_product_id: i64,
    pub store_id: i64,

    pub source_name: String,
    pub source_url: Option<String>,
    pub source_trust: f64,

    pub scraped_at: i64,
    pub scrape_duration_ms: i64,
    pub extraction_method: String,
    pub extraction_confidence: f64,

    pub validations: Vec<ValidationStep>,

    /// Explicit unknowns for this record: what the extractor could NOT
    /// establish — a selector that never matched, a field the page did not
    /// carry, a tier that was refused, a policy that blocked a path.
    ///
    /// A record that carries no value and a record that was never able to
    /// look are different facts; `limitations` carries the second so absence
    /// can never read as a clean result.
    pub limitations: Vec<String>,

    pub final_confidence: f64,
    pub freshness_tier: FreshnessTier,
}

#[derive(Debug, Clone)]
pub struct ProvenanceDisplay {
    pub confidence_label: String,
    pub confidence_color: String,
    pub freshness_label: String,
    pub source_label: String,
    pub method_badge: String,
    pub warnings: Vec<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn source_trust_for(name: &str) -> f64 {
    match name {
        s if s.ends_with("_api") => 0.95,
        "kroger_api" | "walmart_api" | "instacart_api" => 0.95,
        "schema_org" | "json_ld" => 0.85,
        "scraped" | "css" => 0.65,
        _ => 0.7,
    }
}

fn pseudo_uuid() -> String {
    // Lightweight UUID-like identifier without external deps.
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("prov-{:032x}", t)
}

impl ProvenanceRecord {
    pub fn new(price_cents: i64, canonical_product_id: i64, store_id: i64, source: &str) -> Self {
        Self {
            id: pseudo_uuid(),
            price_cents,
            canonical_product_id,
            store_id,
            source_name: source.to_string(),
            source_url: None,
            source_trust: source_trust_for(source),
            scraped_at: now_unix(),
            scrape_duration_ms: 0,
            extraction_method: "unknown".to_string(),
            extraction_confidence: 0.8,
            validations: Vec::new(),
            limitations: Vec::new(),
            final_confidence: 0.0,
            freshness_tier: FreshnessTier::Fresh,
        }
    }

    pub fn add_validation(&mut self, step: ValidationStep) {
        self.validations.push(step);
    }

    pub fn compute_final_confidence(&mut self) {
        // Base = source_trust * extraction_confidence.
        let mut conf = self.source_trust * self.extraction_confidence;
        for v in &self.validations {
            if v.passed {
                conf += v.adjustment.abs();
            } else {
                conf -= v.adjustment.abs();
            }
        }
        self.final_confidence = conf.clamp(0.0, 1.0);

        let age = self.age_seconds();
        self.freshness_tier = if age < 15 * 60 {
            FreshnessTier::Fresh
        } else if age < 6 * 3600 {
            FreshnessTier::Recent
        } else if age < 24 * 3600 {
            FreshnessTier::Stale
        } else {
            FreshnessTier::Old
        };
    }

    pub fn age_seconds(&self) -> i64 {
        (now_unix() - self.scraped_at).max(0)
    }

    pub fn is_trustworthy(&self) -> bool {
        self.final_confidence > 0.7
    }

    fn freshness_label(&self) -> String {
        let s = self.age_seconds();
        if s < 60 {
            format!("{}s ago", s)
        } else if s < 3600 {
            format!("{}m ago", s / 60)
        } else if s < 86400 {
            format!("{}h ago", s / 3600)
        } else {
            format!("{}d ago", s / 86400)
        }
    }

    fn pretty_source(&self) -> String {
        self.source_name
            .split('_')
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().chain(c).collect::<String>(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn ui_label(&self) -> String {
        let pct = (self.final_confidence * 100.0).round() as i64;
        format!(
            "Verified {} · {} · {}% confidence",
            self.freshness_label(),
            self.pretty_source(),
            pct
        )
    }

    pub fn to_display(&self) -> ProvenanceDisplay {
        let (label, color) = if self.final_confidence > 0.85 {
            ("High", "#4ade80")
        } else if self.final_confidence > 0.6 {
            ("Medium", "#fbbf24")
        } else {
            ("Low", "#f87171")
        };

        let method_badge = match self.extraction_method.as_str() {
            "json_ld" => "JSON-LD",
            "microdata" => "Microdata",
            "opengraph" => "OpenGraph",
            "api" => "API",
            "css" => "Scraped",
            other => other,
        }
        .to_string();

        let mut warnings = Vec::new();
        if matches!(self.freshness_tier, FreshnessTier::Stale | FreshnessTier::Old) {
            warnings.push("Price may be stale".into());
        }
        if !self.is_trustworthy() {
            warnings.push("Low confidence — verify in store".into());
        }
        for v in &self.validations {
            if !v.passed {
                if let Some(n) = &v.note {
                    warnings.push(format!("{}: {}", v.validator, n));
                }
            }
        }

        // Explicit unknowns ride the EXISTING warnings channel rather than a
        // parallel renderer: a limitation that is stored must be visible, so it
        // cannot be recorded and then silently dropped at render time.
        for l in &self.limitations {
            warnings.push(format!("Unknown: {l}"));
        }

        ProvenanceDisplay {
            confidence_label: label.to_string(),
            confidence_color: color.to_string(),
            freshness_label: self.freshness_label(),
            source_label: self.pretty_source(),
            method_badge,
            warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_record_defaults() {
        let p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        assert_eq!(p.price_cents, 499);
        assert!(p.source_trust > 0.9);
        assert!(p.id.starts_with("prov-"));
    }

    #[test]
    fn add_validation_and_compute() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        p.extraction_method = "api".into();
        p.extraction_confidence = 0.9;
        p.add_validation(ValidationStep {
            validator: "schema".into(),
            passed: true,
            adjustment: 0.05,
            note: None,
        });
        p.add_validation(ValidationStep {
            validator: "bounds".into(),
            passed: true,
            adjustment: 0.05,
            note: None,
        });
        p.compute_final_confidence();
        assert!(p.final_confidence > 0.85);
        assert!(p.is_trustworthy());
    }

    #[test]
    fn failed_validation_lowers_confidence() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "scraped");
        p.extraction_confidence = 0.7;
        p.add_validation(ValidationStep {
            validator: "zscore".into(),
            passed: false,
            adjustment: 0.3,
            note: Some("outlier".into()),
        });
        p.compute_final_confidence();
        assert!(!p.is_trustworthy());
        let d = p.to_display();
        assert!(d.warnings.iter().any(|w| w.contains("zscore")));
    }

    #[test]
    fn stale_detection() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        p.scraped_at = now_unix() - 7 * 3600;
        p.compute_final_confidence();
        assert_eq!(p.freshness_tier, FreshnessTier::Stale);
        let d = p.to_display();
        assert!(d.warnings.iter().any(|w| w.contains("stale")));
    }

    #[test]
    fn old_detection() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        p.scraped_at = now_unix() - 48 * 3600;
        p.compute_final_confidence();
        assert_eq!(p.freshness_tier, FreshnessTier::Old);
    }

    #[test]
    fn ui_label_format() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        p.extraction_confidence = 0.95;
        p.compute_final_confidence();
        let label = p.ui_label();
        assert!(label.contains("Kroger Api"));
        assert!(label.contains("confidence"));
    }

    #[test]
    fn display_colors() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        p.extraction_confidence = 0.95;
        p.compute_final_confidence();
        let d = p.to_display();
        assert_eq!(d.confidence_label, "High");
        assert_eq!(d.confidence_color, "#4ade80");
    }

    #[test]
    fn limitations_start_empty_and_render_nothing() {
        let p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        assert!(p.limitations.is_empty());
        let d = p.to_display();
        assert!(
            !d.warnings.iter().any(|w| w.starts_with("Unknown:")),
            "a clean record must not manufacture an unknown: {:?}",
            d.warnings
        );
    }

    #[test]
    fn stored_limitations_are_rendered() {
        let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        p.extraction_confidence = 0.95;
        p.limitations
            .push("selector 'h1.title' never matched on this page".into());
        p.compute_final_confidence();
        let d = p.to_display();
        assert!(
            d.warnings.iter().any(|w| w.contains("h1.title")),
            "a stored limitation must be visible in the display: {:?}",
            d.warnings
        );
    }

    #[test]
    fn absent_and_empty_are_distinguishable() {
        // The whole point of the field: "we looked and there was nothing" is a
        // different fact from "we could not look", and the record must be able
        // to say the second.
        let mut looked_nothing_there = ProvenanceRecord::new(499, 1, 2, "kroger_api");
        looked_nothing_there.extraction_confidence = 0.95;
        let could_not_look = {
            let mut p = ProvenanceRecord::new(499, 1, 2, "kroger_api");
            p.extraction_confidence = 0.95;
            p.limitations.push("page served a challenge".into());
            p
        };
        let a = looked_nothing_there.to_display();
        let b = could_not_look.to_display();
        assert!(!a.warnings.iter().any(|w| w.starts_with("Unknown:")));
        assert!(b.warnings.iter().any(|w| w.starts_with("Unknown:")));
    }
}
