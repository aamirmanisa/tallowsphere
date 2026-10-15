//! Job-config classification — single source of truth for which job shapes
//! the Tallow daemon can actually execute.
//!
//! The daemon executor is a file-copy engine that also runs `.tl` scripts by
//! delegating to the `tallow` binary (subprocess — exactly like the CLI
//! scheduler run path). Any config that is neither of those two shapes is
//! rejected UP FRONT by `POST /jobs` (honest submit-time rejection) and would
//! also fail loudly at execution time if it ever reached the executor through
//! another path. The daemon never accepts a job it cannot run and reports
//! success later.

use serde_json::Value;

/// The two job shapes the daemon can execute.
#[derive(Debug, Clone, PartialEq)]
pub enum JobKind {
    /// Throttled whole-file copy: `{"source": "<path>", "dest": "<path>"}`.
    Copy { source: String, dest: String },
    /// `.tl` script run via the `tallow` binary:
    /// `{"type": "tallow_script", "script": "<source>", "name": "<name>"}`.
    TallowScript { name: String, script: String },
}

/// Human-readable description of the supported shapes, embedded in every
/// rejection/error so callers never have to guess.
pub const SUPPORTED_SHAPES: &str = "supported job shapes: \
    copy {\"source\", \"dest\"} or \
    tallow_script {\"type\": \"tallow_script\", \"script\": <source>, \"name\": <optional>}";

/// Classify a job config. Returns the executable kind or an honest `Err`
/// describing why the daemon cannot run this job (never accept-then-fail).
pub fn classify(config: &Value) -> Result<JobKind, String> {
    // Shape 1: tallow_script — `tallow job submit <file>` posts this.
    if config.get("type").and_then(Value::as_str) == Some("tallow_script") {
        let script = config
            .get("script")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "job submit rejected: tallow_script jobs need a string \
                 \"script\" field holding the .tl source"
                    .to_string()
            })?;
        let name = config
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("untitled-script")
            .to_string();
        if script.trim().is_empty() {
            return Err(
                "job submit rejected: tallow_script \"script\" field is empty".to_string(),
            );
        }
        return Ok(JobKind::TallowScript {
            name,
            script: script.to_string(),
        });
    }

    // An explicit `type` that claims something other than what the daemon
    // implements must be rejected — the daemon never silently downgrades an
    // "rsync"/"sync"/... job to a plain file copy (that would be an
    // overclaim). Absent `type` means copy (the daemon's original shape).
    if let Some(t) = config.get("type").and_then(Value::as_str) {
        if t != "tallow_script" && t != "copy" {
            return Err(format!(
                "job submit rejected: daemon cannot execute jobs of type \"{t}\" — {SUPPORTED_SHAPES}"
            ));
        }
    }

    // Shape 2: copy — the daemon's original engine.
    let has_copy_marker = config.get("source").is_some() || config.get("dest").is_some();
    if has_copy_marker {
        let source = config
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "job submit rejected: copy jobs need a string \"source\" field".to_string()
            })?;
        let dest = config.get("dest").and_then(Value::as_str).ok_or_else(|| {
            "job submit rejected: copy jobs need a string \"dest\" field".to_string()
        })?;
        if source.is_empty() || dest.is_empty() {
            return Err(
                "job submit rejected: copy jobs need non-empty \"source\" and \"dest\"".to_string(),
            );
        }
        return Ok(JobKind::Copy {
            source: source.to_string(),
            dest: dest.to_string(),
        });
    }

    // Anything else: immediate honest rejection with the supported list.
    let type_label = config
        .get("type")
        .and_then(Value::as_str)
        .map(|t| format!(" of type \"{t}\""))
        .unwrap_or_default();
    Err(format!(
        "job submit rejected: daemon cannot execute this job{type_label} — {SUPPORTED_SHAPES}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_json(s: &str) -> Value {
        serde_json::from_str(s).expect("valid json fixture")
    }

    #[test]
    fn classify_copy_flat_shape() {
        let k = classify(&config_json(r#"{"source":"/a","dest":"/b"}"#)).expect("copy ok");
        assert_eq!(
            k,
            JobKind::Copy {
                source: "/a".into(),
                dest: "/b".into()
            }
        );
    }

    #[test]
    fn classify_tallow_script_shape() {
        let k = classify(&config_json(
            r#"{"type":"tallow_script","script":"fn main() {}","name":"a.tl"}"#,
        ))
        .expect("script ok");
        assert_eq!(
            k,
            JobKind::TallowScript {
                name: "a.tl".into(),
                script: "fn main() {}".into()
            }
        );
    }

    /// The B8 contract test: a submit of an unsupported job shape must be
    /// rejected immediately with a clear, honest error — never accepted and
    /// left to fail silently later.
    #[test]
    fn submit_unsupported_shape_is_immediate_honest_rejection() {
        for (fixture, needle) in [
            (r#"{"operation":"reindex"}"#, "daemon cannot execute"),
            (r#"{"type":"rsync","source":"/a","dest":"/b"}"#, "of type \"rsync\""),
            (r#"{}"#, "daemon cannot execute"),
            (r#"{"type":"tallow_script"}"#, "need a string \"script\" field"),
            (
                r#"{"type":"tallow_script","script":"   "}"#,
                "script\" field is empty",
            ),
            (r#"{"source":"/a"}"#, "need a string \"dest\" field"),
        ] {
            let err = classify(&config_json(fixture)).expect_err("must reject");
            assert!(
                err.contains(needle),
                "fixture {fixture}: expected error containing {needle:?}, got: {err}"
            );
            // Rejection must mention what the daemon CAN run, so callers can
            // fix the request instead of guessing.
            assert!(err.contains("copy") || err.contains("tallow_script"));
        }
    }

    #[test]
    fn supported_copy_job_classifies() {
        let k = classify(&config_json(r#"{"source":"/x","dest":"/y"}"#)).expect("copy ok");
        assert!(matches!(k, JobKind::Copy { .. }));
    }
}
