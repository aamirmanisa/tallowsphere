//! Standard library: `tallow.advisory` — vulnerability-advisory feed access.
//!
//! Honest, local, file/env-driven advisory data (C5, 2026-09). There is NO
//! implicit network lookup here: `advisory_feed()` reads a local JSON advisory
//! file whose path comes from `TALLOW_ADVISORY_FILE`. When the env var is
//! unset or the file is missing/unparsable, the function returns an honest
//! `Err` — it never fabricates advisory data and never pretends a feed is
//! configured when it is not. Audit verdicts (`tallow audit --cra/--nis2`)
//! consume this module so their vulnerability posture is derived from the
//! configured feed (with source citation per record) rather than a static
//! illustrative table.
//!
//! Feed file schema (`tallow.advisory.feed.v1`):
//! ```json
//! {
//!   "schema_version": "tallow.advisory.feed.v1",
//!   "generated_at": "2026-09-05T00:00:00Z",
//!   "advisories": [
//!     {
//!       "id": "RUSTSEC-2024-0375",
//!       "source": "RustSec",
//!       "package": "rustls",
//!       "severity": "medium",
//!       "url": "https://rustsec.org/advisories/RUSTSEC-2024-0375",
//!       "title": "rustls: ...",
//!       "published_at": "2024-10-01",
//!       "affected": ">=0.20.0, <0.23.2",
//!       "notes": "..."
//!     }
//!   ]
//! }
//! ```
//! Unknown extra fields are ignored; a malformed record is skipped and
//! reported, a malformed file is an honest `Err`.

use super::StdlibResult;
use crate::interp::Value;

pub const ADVISORY_SCHEMA_VERSION: &str = "tallow.advisory.feed.v1";

/// The configured advisory feed path, from `TALLOW_ADVISORY_FILE`.
pub fn advisory_feed_path() -> Result<std::path::PathBuf, String> {
    match std::env::var("TALLOW_ADVISORY_FILE") {
        Ok(p) if !p.trim().is_empty() => {
            let path = std::path::PathBuf::from(p.trim());
            if !path.is_file() {
                return Err(format!(
                    "no advisory feed available: TALLOW_ADVISORY_FILE={} does not name a readable file",
                    path.display()
                ));
            }
            Ok(path)
        }
        _ => Err(
            "no advisory feed configured: set TALLOW_ADVISORY_FILE to a local JSON advisory \
             feed file (schema tallow.advisory.feed.v1) — audit vulnerability verdicts cannot \
             be derived without it"
                .to_string(),
        ),
    }
}

/// Parse the configured advisory feed. Returns (records, skipped_count).
pub fn load_advisory_feed() -> Result<(Vec<serde_json::Value>, usize), String> {
    let path = advisory_feed_path()?;
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read advisory feed {}: {e}", path.display()))?;
    let root: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("cannot parse advisory feed {}: {e}", path.display()))?;
    let advisories = root
        .get("advisories")
        .and_then(|a| a.as_array())
        .ok_or_else(|| {
            format!(
                "advisory feed {} has no \"advisories\" array (schema {ADVISORY_SCHEMA_VERSION})",
                path.display()
            )
        })?;
    let mut records = Vec::new();
    let mut skipped = 0usize;
    for adv in advisories {
        let ok = adv.get("id").and_then(|v| v.as_str()).is_some()
            && adv.get("package").and_then(|v| v.as_str()).is_some();
        if ok {
            records.push(adv.clone());
        } else {
            skipped += 1;
        }
    }
    Ok((records, skipped))
}

/// Match a parsed advisory record against an SBOM component name. Name
/// equality (case-insensitive) is the documented matching rule; version
/// windowing is intentionally NOT evaluated here so the audit never overclaims
/// an "affected/fixed" verdict it cannot prove.
pub fn advisory_matches_component(advisory: &serde_json::Value, component_name: &str) -> bool {
    advisory
        .get("package")
        .and_then(|v| v.as_str())
        .map(|p| p.eq_ignore_ascii_case(component_name))
        .unwrap_or(false)
}

/// Dispatch for `tallow.advisory.*`.
pub fn dispatch(function: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // advisory_feed() — load the configured feed; honest Err when no
        // feed is configured. Returns a Struct { path, schema_version,
        // count, skipped, advisories_json }.
        "advisory_feed" => Some(advisory_feed()),
        _ => None,
    }
}

fn advisory_feed() -> StdlibResult {
    let path = advisory_feed_path()?;
    let (records, skipped) = load_advisory_feed()?;
    let advisories_json = serde_json::to_string(&records)
        .map_err(|e| format!("advisory: cannot encode feed records: {e}"))?;
    Ok(Value::Struct {
        name: "AdvisoryFeed".to_string(),
        fields: vec![
            ("path".to_string(), Value::String(path.display().to_string())),
            (
                "schema_version".to_string(),
                Value::String(ADVISORY_SCHEMA_VERSION.to_string()),
            ),
            ("count".to_string(), Value::Int(records.len() as i128)),
            ("skipped".to_string(), Value::Int(skipped as i128)),
            ("advisories_json".to_string(), Value::String(advisories_json)),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_feed<F: FnOnce() -> ()>(content: &str, f: F) {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let feed = tmp.path().join("feed.json");
        std::fs::write(&feed, content).expect("write feed");
        unsafe {
            std::env::set_var("TALLOW_ADVISORY_FILE", &feed);
        }
        let _ = f();
        unsafe {
            std::env::remove_var("TALLOW_ADVISORY_FILE");
        }
    }

    const SAMPLE_FEED: &str = r#"{
      "schema_version": "tallow.advisory.feed.v1",
      "generated_at": "2026-09-05T00:00:00Z",
      "advisories": [
        {"id": "RUSTSEC-2024-0375", "source": "RustSec", "package": "rustls",
         "severity": "medium", "url": "https://rustsec.org/advisories/RUSTSEC-2024-0375",
         "title": "rustls test advisory", "published_at": "2024-10-01"},
        {"id": "RUSTSEC-2024-0336", "source": "RustSec", "package": "h2",
         "severity": "high", "url": "https://rustsec.org/advisories/RUSTSEC-2024-0336",
         "title": "h2 test advisory"}
      ]
    }"#;

    #[test]
    fn no_env_means_honest_error() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        unsafe {
            std::env::remove_var("TALLOW_ADVISORY_FILE");
        }
        let err = advisory_feed_path().expect_err("must be honest Err without env");
        assert!(
            err.contains("no advisory feed configured"),
            "error must say the feed is not configured, got: {err}"
        );
        match dispatch("advisory_feed", vec![]) {
            Some(Err(msg)) => assert!(msg.contains("no advisory feed configured")),
            other => panic!("advisory_feed() without env must Err, got {other:?}"),
        }
    }

    #[test]
    fn missing_file_is_honest_error() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        let missing = std::path::PathBuf::from("/nonexistent/advisory-feed.json");
        unsafe {
            std::env::set_var("TALLOW_ADVISORY_FILE", &missing);
        }
        let err = advisory_feed_path().expect_err("missing file must error");
        assert!(
            err.contains("does not name a readable file"),
            "error should name the missing file, got: {err}"
        );
        unsafe {
            std::env::remove_var("TALLOW_ADVISORY_FILE");
        }
    }

    #[test]
    fn feed_loads_and_matches_components() {
        with_feed(SAMPLE_FEED, || {
            let (records, skipped) = load_advisory_feed().expect("feed parses");
            assert_eq!(records.len(), 2);
            assert_eq!(skipped, 0);

            let rustls = &records[0];
            assert!(advisory_matches_component(rustls, "rustls"));
            assert!(advisory_matches_component(rustls, "Rustls"));
            assert!(!advisory_matches_component(rustls, "h2"));

            // dispatch() surface returns the structured feed
            match dispatch("advisory_feed", vec![]) {
                Some(Ok(Value::Struct { name, fields })) => {
                    assert_eq!(name, "AdvisoryFeed");
                    let count = fields
                        .iter()
                        .find(|(k, _)| k == "count")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    assert_eq!(count, "2");
                    let json = fields
                        .iter()
                        .find(|(k, _)| k == "advisories_json")
                        .map(|(_, v)| match v {
                            Value::String(s) => s.clone(),
                            _ => String::new(),
                        })
                        .unwrap_or_default();
                    assert!(json.contains("RUSTSEC-2024-0375"));
                }
                other => panic!("advisory_feed() should return AdvisoryFeed struct, got {other:?}"),
            }
        });
    }

    #[test]
    fn malformed_records_skipped_and_reported() {
        with_feed(
            r#"{"advisories":[
                {"id":"A-1","package":"ok","severity":"low"},
                {"package":"missing-id"},
                {"id":"A-2"}
            ]}"#,
            || {
                let (records, skipped) = load_advisory_feed().expect("feed parses");
                assert_eq!(records.len(), 1);
                assert_eq!(skipped, 2, "records missing id or package must be skipped");
            },
        );
    }

    #[test]
    fn unknown_function_is_none() {
        assert!(dispatch("not_a_fn", vec![]).is_none());
    }
}
