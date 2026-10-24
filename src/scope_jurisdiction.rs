//! Jurisdiction gate: refuse collection from hosts this run is not authorized
//! to touch because of where they live.
//!
//! This is a **table**, not a geolocation service. It matches a host against the
//! suffixes and explicit hosts listed under a blocked jurisdiction and refuses
//! with the code. Nothing here guesses a country from an IP: an inference that
//! is wrong half the time is not a control, it is a liability with a log line.
//!
//! Configuration (`TALLOW_JURISDICTION_CONFIG`, default
//! `configs/tallow/jurisdiction.toml`):
//!
//! ```toml
//! [[blocked]]
//! code = "RU"
//! reason = "not authorized for this engagement"
//! suffixes = [".ru", ".su", ".рф"]
//! hosts = ["example.ru", "203.0.113.9"]
//! ```
//!
//! Rules:
//!
//! * A suffix matches on a label boundary — `.ru` matches `a.ru` and `b.a.ru`,
//!   never `notru`.
//! * `hosts` matches exactly, so an IP or a specific domain can be named even
//!   when its TLD is not blocked.
//! * The gate is **off** when no configuration exists (the common case for
//!   library use), and **fail-closed** when a configuration is named but cannot
//!   be read or parsed: a run that believes it is constrained must not proceed
//!   unconstrained.

use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Blocked {
    pub code: String,
    pub reason: String,
    pub suffixes: Vec<String>,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct JurisdictionTable {
    blocked: Vec<Blocked>,
    /// Set when a configured table could not be loaded.
    failure: Option<String>,
}

#[derive(serde::Deserialize)]
struct File {
    #[serde(default)]
    blocked: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    code: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    suffixes: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
}

impl JurisdictionTable {
    pub fn empty() -> Self {
        JurisdictionTable::default()
    }

    pub fn from_toml(text: &str) -> Self {
        match toml::from_str::<File>(text) {
            Ok(f) => JurisdictionTable {
                blocked: f
                    .blocked
                    .into_iter()
                    .map(|e| Blocked {
                        code: e.code,
                        reason: e.reason,
                        suffixes: e.suffixes.into_iter().map(|s| s.to_ascii_lowercase()).collect(),
                        hosts: e.hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
                    })
                    .collect(),
                failure: None,
            },
            Err(e) => JurisdictionTable {
                blocked: Vec::new(),
                failure: Some(format!("jurisdiction table is not valid TOML: {e}")),
            },
        }
    }

    pub fn load(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) => JurisdictionTable {
                blocked: Vec::new(),
                failure: Some(format!(
                    "jurisdiction table {} unreadable: {e}",
                    path.display()
                )),
            },
        }
    }

    /// The jurisdiction that blocks `host`, if any.
    pub fn blocking(&self, host: &str) -> Option<&Blocked> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.blocked.iter().find(|b| {
            b.hosts.iter().any(|h| h == &host)
                || b.suffixes.iter().any(|s| {
                    // Label boundary: ".ru" matches "a.ru", not "notru".
                    host.ends_with(s.as_str())
                        && host.len() > s.len()
                        && (s.starts_with('.') || host.as_bytes()[host.len() - s.len() - 1] == b'.')
                })
        })
    }

    /// Refuse `host` when its jurisdiction is blocked, or when the table itself
    /// could not be loaded.
    pub fn check(&self, host: &str) -> Result<(), String> {
        if let Some(failure) = &self.failure {
            return Err(format!("jurisdiction: refusing all egress — {failure}"));
        }
        match self.blocking(host) {
            Some(b) => Err(format!(
                "jurisdiction: {host} is under {} — {}",
                b.code,
                if b.reason.is_empty() {
                    "blocked by the run's jurisdiction table"
                } else {
                    b.reason.as_str()
                }
            )),
            None => Ok(()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty() && self.failure.is_none()
    }
}

fn config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("TALLOW_JURISDICTION_CONFIG") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    // The default location is only consulted when it exists: an absent file
    // means "no jurisdiction policy", not "refuse everything".
    let d = PathBuf::from("configs/tallow/jurisdiction.toml");
    if d.exists() {
        Some(d)
    } else {
        None
    }
}

/// The process-wide table: `None` when no policy is configured.
pub fn table() -> Option<&'static JurisdictionTable> {
    static TABLE: OnceLock<Option<JurisdictionTable>> = OnceLock::new();
    TABLE
        .get_or_init(|| config_path().map(|p| JurisdictionTable::load(&p)))
        .as_ref()
}

/// Check a host against the configured table. With no policy configured this is
/// a constant `Ok`.
pub fn check(host: &str) -> Result<(), String> {
    match table() {
        Some(t) => t.check(host),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = r#"
[[blocked]]
code = "RU"
reason = "not authorized for this engagement"
suffixes = [".ru", ".su"]
hosts = ["203.0.113.9"]

[[blocked]]
code = "IR"
suffixes = [".ir"]
"#;

    #[test]
    fn suffix_matches_on_a_label_boundary_only() {
        let t = JurisdictionTable::from_toml(TABLE);
        assert!(t.blocking("example.ru").is_some());
        assert!(t.blocking("a.b.example.ru").is_some());
        assert!(t.blocking("EXAMPLE.RU.").is_some(), "case and trailing dot");
        assert!(t.blocking("notru").is_none(), "a suffix is not a substring");
        assert!(t.blocking("ru").is_none());
        assert!(t.blocking("example.com").is_none());
    }

    #[test]
    fn an_explicit_host_is_blocked_even_without_a_suffix() {
        let t = JurisdictionTable::from_toml(TABLE);
        let b = t.blocking("203.0.113.9").expect("explicit host");
        assert_eq!(b.code, "RU");
        // A neighbouring address in the same block is not the named host.
        assert!(t.check("203.0.113.10").is_ok());
    }

    #[test]
    fn the_refusal_names_the_jurisdiction_and_the_reason() {
        let t = JurisdictionTable::from_toml(TABLE);
        let err = t.check("example.ru").unwrap_err();
        assert!(err.contains("under RU"), "{err}");
        assert!(err.contains("not authorized"), "{err}");
        // A code with no reason still names itself.
        let err = t.check("x.ir").unwrap_err();
        assert!(err.contains("under IR"), "{err}");
    }

    #[test]
    fn an_unreadable_table_refuses_everything() {
        let t = JurisdictionTable::load(std::path::Path::new("/nonexistent/jurisdiction.toml"));
        let err = t.check("example.com").unwrap_err();
        assert!(err.contains("refusing all egress"), "{err}");
    }

    #[test]
    fn malformed_toml_is_a_failure_not_an_empty_table() {
        let t = JurisdictionTable::from_toml("[[blocked]\ncode = ");
        let err = t.check("example.com").unwrap_err();
        assert!(err.contains("not valid TOML"), "{err}");
        assert!(!t.is_empty(), "a failure is not an empty policy");
    }

    #[test]
    fn no_policy_configured_allows_normal_use() {
        assert!(JurisdictionTable::empty().check("example.com").is_ok());
        assert!(JurisdictionTable::empty().is_empty());
    }
}
