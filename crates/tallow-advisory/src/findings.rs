//! Finding model — deterministic, serializable, human-readable.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// One advisory finding. `id` is a stable detector id (machine-matchable);
/// `subject` names the object it is about (recipe, peer, or `ledger`).
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub subject: String,
    pub message: String,
    pub suggestion: String,
    pub evidence: BTreeMap<String, Value>,
}

impl Finding {
    pub fn new(
        id: &'static str,
        severity: Severity,
        subject: impl Into<String>,
        message: impl Into<String>,
        suggestion: impl Into<String>,
        evidence: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            id,
            severity,
            subject: subject.into(),
            message: message.into(),
            suggestion: suggestion.into(),
            evidence,
        }
    }
}

/// Deterministic order: severity (descending) → id → subject.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.cmp(b.id))
            .then_with(|| a.subject.cmp(&b.subject))
    });
}

/// (critical, warn, info) counts.
pub fn counts(findings: &[Finding]) -> (usize, usize, usize) {
    let mut c = (0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c.0 += 1,
            Severity::Warn => c.1 += 1,
            Severity::Info => c.2 += 1,
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &'static str, sev: Severity, subject: &str) -> Finding {
        Finding::new(id, sev, subject, "m", "s", BTreeMap::new())
    }

    #[test]
    fn sort_is_severity_then_id_then_subject() {
        let mut v = vec![
            f("b.det", Severity::Info, "x"),
            f("a.det", Severity::Critical, "y"),
            f("a.det", Severity::Critical, "a"),
            f("z.det", Severity::Warn, "q"),
        ];
        sort_findings(&mut v);
        let got: Vec<_> = v
            .iter()
            .map(|f| (f.id, f.severity, f.subject.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("a.det", Severity::Critical, "a"),
                ("a.det", Severity::Critical, "y"),
                ("z.det", Severity::Warn, "q"),
                ("b.det", Severity::Info, "x"),
            ]
        );
    }

    #[test]
    fn counts_work() {
        let v = vec![
            f("a", Severity::Critical, "s"),
            f("b", Severity::Warn, "s"),
            f("c", Severity::Warn, "s"),
            f("d", Severity::Info, "s"),
        ];
        assert_eq!(counts(&v), (1, 2, 1));
    }

    #[test]
    fn json_shape_is_stable() {
        let f = f("x.y", Severity::Warn, "s");
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["severity"], "warn");
        assert_eq!(v["id"], "x.y");
    }
}
