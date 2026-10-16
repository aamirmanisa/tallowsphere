//! Standard library: `tallow.legal` — @legal runtime + audit log generation.
//!
//! Real minimal backend (C4, 2026-09): records are persisted as JSONL under
//! a configurable legal-data directory (`TALLOW_LEGAL_DIR`, defaulting to
//! `~/.tallow/legal`):
//!
//!   * `log_audit(entry)`        → appends one JSON object per line to
//!                                 `audit_log.jsonl`
//!   * `read_audit_log(path?)`   → reads `audit_log.jsonl` back as
//!                                 `[]AuditEntry` (default path when omitted)
//!   * `consent_register(...)`   → appends a consent record to
//!                                 `consent_register.jsonl`
//!   * `consent_check(...)`      → answers from the consent register
//!   * `erasure_request(...)`    → appends a GDPR erasure request to
//!                                 `erasure_requests.jsonl`
//!
//! Functions that need machinery this runtime backend does not provide
//! (full CRA/NIS2/DORA/AI-Act report generation, DPIA/SCC/PIA documents,
//! breach notification channels, model-provenance chains) return an honest
//! `Err` naming exactly what is unavailable — they never return a fake
//! success token. Compile-time enforcement lives in the `@legal`/`@consent`/
//! `@erasure` AST passes (src/*pass.rs); this module is the runtime
//! persistence half of that story.

use super::StdlibResult;
use crate::interp::Value;

/// Record kinds written by this backend. Each maps to a JSONL file under the
/// legal-data directory.
///
/// `AUDIT_LOG_FILE` is `pub(crate)`: the native-codegen sink
/// (`src/runtime/enterprise_ffi.rs`) appends its `native_codegen` records to the
/// same file, discriminated by the record's `source` field.
pub(crate) const AUDIT_LOG_FILE: &str = "audit_log.jsonl";
const CONSENT_REGISTER_FILE: &str = "consent_register.jsonl";
const ERASURE_REQUESTS_FILE: &str = "erasure_requests.jsonl";

/// Directory holding legal records: `TALLOW_LEGAL_DIR` or `~/.tallow/legal`.
pub(crate) fn legal_data_dir() -> Result<std::path::PathBuf, String> {
    if let Ok(dir) = std::env::var("TALLOW_LEGAL_DIR") {
        if !dir.trim().is_empty() {
            return Ok(std::path::PathBuf::from(dir));
        }
    }
    let home = dirs::home_dir()
        .ok_or_else(|| "legal: cannot determine home directory (set TALLOW_LEGAL_DIR)".to_string())?;
    Ok(home.join(".tallow").join("legal"))
}

fn utc_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn new_record_id(prefix: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..16])
}

/// Serialize any script-supplied `Value` to a JSON string (mirrors the
/// interp/stdlib json encoding for structs/maps/enums/scalars).
fn value_to_json(val: &Value) -> String {
    match val {
        Value::Nil => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                "null".to_string()
            } else {
                format!("{f}")
            }
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(value_to_json).collect();
            format!("[{}]", inner.join(","))
        }
        Value::Map(pairs) => {
            let entries: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}:{}", value_to_json(k), value_to_json(v)))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Struct { fields, .. } => {
            let entries: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, value_to_json(v)))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Enum {
            variant, fields, ..
        } => {
            if fields.is_empty() {
                format!("\"{variant}\"")
            } else {
                let f: Vec<String> = fields
                    .iter()
                    .map(|(k, v)| format!("\"{k}\":{}", value_to_json(v)))
                    .collect();
                format!("{{\"{variant}\":{{{}}}}}", f.join(","))
            }
        }
        Value::Private(inner) | Value::Secret(inner) | Value::Ok(inner) | Value::Err(inner) => {
            value_to_json(inner)
        }
        _ => "null".to_string(),
    }
}

/// Append one JSON value as a line to `<legal_dir>/<file>`, creating the
/// directory and file as needed. Returns the canonical file path.
///
/// Shared by the script-facing writers (`log_audit`, `consent_register`,
/// `erasure_request`, …) and by the native-codegen audit sink
/// (`crate::runtime::enterprise_ffi::tallow_audit_log`), so both producers land
/// in one file with identical append/creation semantics.
pub(crate) fn append_jsonl(
    file: &str,
    record: &serde_json::Value,
) -> Result<std::path::PathBuf, String> {
    use std::io::Write;
    let dir = legal_data_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("legal: cannot create data dir {}: {e}", dir.display()))?;
    let path = dir.join(file);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("legal: cannot open {} for append: {e}", path.display()))?;
    let mut line = serde_json::to_string(record)
        .map_err(|e| format!("legal: cannot serialize record for {}: {e}", path.display()))?;
    line.push('\n');
    f.write_all(line.as_bytes())
        .map_err(|e| format!("legal: cannot write record to {}: {e}", path.display()))?;
    Ok(path)
}

/// Append one JSON value as a line to `<legal_dir>/<file>` (record-kind
/// wrapper kept for the script-facing call sites' error messages).
fn append_record(kind: &str, file: &str, record: serde_json::Value) -> Result<std::path::PathBuf, String> {
    append_jsonl(file, &record).map_err(|e| format!("legal.{kind}: {e}"))
}

/// Read a JSONL file into a Vec of parsed JSON values (invalid lines are
/// skipped and reported via the returned count).
fn read_jsonl(path: &std::path::Path) -> Result<(Vec<serde_json::Value>, usize), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("legal: cannot read {}: {e}", path.display()))?;
    let mut records = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => records.push(v),
            Err(_) => skipped += 1,
        }
    }
    Ok((records, skipped))
}

/// Convert a parsed JSON object into a Tallow `Value` (strings/numbers/bools
/// become scalar Values, nested objects become Structs with `name`).
fn json_to_value(v: &serde_json::Value, struct_name: &str) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Nil
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(|i| json_to_value(i, struct_name)).collect())
        }
        serde_json::Value::Object(map) => {
            let fields: Vec<(String, Value)> = map
                .iter()
                .map(|(k, val)| (k.clone(), json_to_value(val, k)))
                .collect();
            Value::Struct {
                name: struct_name.to_string(),
                fields,
            }
        }
    }
}

/// Contract-level dispatch for `tallow.legal.*` functions.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // ── Real persistence backend (C4) ────────────────────────────────
        "log_audit" => Some(log_audit(args)),
        "read_audit_log" => Some(read_audit_log(args)),
        "consent_register" => Some(consent_register(args)),
        "consent_check" => Some(consent_check(args)),
        "erasure_request" => Some(erasure_request(args)),
        "subject_access_request" => Some(subject_access_request(args)),
        // ── Genuinely unavailable here — honest Err ─────────────────────
        "generate_report"
        | "check_compliance"
        | "cra_audit"
        | "nis2_audit"
        | "dora_incident_new"
        | "dora_classify"
        | "dora_report"
        | "pia_generate"
        | "retention_schedule"
        | "data_map_generate"
        | "scc_generate"
        | "dpia_generate"
        | "breach_notify"
        | "ai_inference_log_create"
        | "ai_inference_log_entry"
        | "ai_inference_log_verify"
        | "ai_inference_log_export"
        | "human_approval_request"
        | "model_provenance_create"
        | "model_provenance_set"
        | "model_provenance_attest"
        | "model_provenance_verify"
        | "model_provenance_export" => Some(Err(legal_unavailable(function))),
        _ => None,
    }
}

/// Extract the first argument as an object-ish Value (Struct or Map).
fn first_object(args: &[Value]) -> Result<&Value, String> {
    let v = args
        .first()
        .ok_or_else(|| "log_audit(entry) requires an AuditEntry argument".to_string())?;
    match v {
        Value::Struct { .. } | Value::Map(_) => Ok(v),
        other => Err(format!(
            "log_audit(entry) expects a struct, got {}",
            other.as_string()
        )),
    }
}

/// `log_audit(entry: AuditEntry)` — persist one audit record (JSONL) to the
/// legal data dir. The record keeps every declared AuditEntry field plus a
/// server-side `recorded_at` timestamp and the writer identity.
fn log_audit(args: Vec<Value>) -> StdlibResult {
    let entry = first_object(&args)?;
    let mut json = serde_json::from_str::<serde_json::Value>(&value_to_json(entry))
        .map_err(|e| format!("legal.log_audit: cannot encode entry: {e}"))?;
    if let Some(obj) = json.as_object_mut() {
        obj.insert("recorded_at".to_string(), serde_json::json!(utc_rfc3339()));
        obj.insert("recorded_by".to_string(), serde_json::json!("stdlib:legal.log_audit"));
    }
    let path = append_record("audit", AUDIT_LOG_FILE, json)?;
    Ok(Value::Ok(Box::new(Value::Nil)))
}

/// `read_audit_log(path: String)` — read the JSONL audit log back as
/// `[]AuditEntry`. When `path` is empty/omitted the default
/// `TALLOW_LEGAL_DIR/audit_log.jsonl` is used.
fn read_audit_log(args: Vec<Value>) -> StdlibResult {
    let explicit = args.first().and_then(|v| match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    });
    let path = match explicit {
        Some(p) => std::path::PathBuf::from(p),
        None => legal_data_dir()?.join(AUDIT_LOG_FILE),
    };
    if !path.exists() {
        return Ok(Value::Ok(Box::new(Value::Array(Vec::new()))));
    }
    let (records, skipped) = read_jsonl(&path)?;
    let entries: Vec<Value> = records
        .iter()
        .map(|r| json_to_value(r, "AuditEntry"))
        .collect();
    if skipped > 0 {
        eprintln!(
            "warning: legal.read_audit_log skipped {skipped} malformed line(s) in {}",
            path.display()
        );
    }
    Ok(Value::Ok(Box::new(Value::Array(entries))))
}

/// Pull a string field from a struct/map arg or fall back to the positional
/// string argument index.
fn arg_string(args: &[Value], field: &str, pos: usize, fn_name: &str) -> Result<String, String> {
    if let Some(v) = args.first() {
        match v {
            Value::Struct { fields, .. } => {
                if let Some((_, Value::String(s))) = fields.iter().find(|(k, _)| k == field) {
                    if !s.trim().is_empty() {
                        return Ok(s.clone());
                    }
                }
            }
            Value::Map(pairs) => {
                for (k, val) in pairs {
                    if k.as_string() == field {
                        if let Value::String(s) = val {
                            if !s.trim().is_empty() {
                                return Ok(s.clone());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    match args.get(pos) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
        _ => Err(format!(
            "legal.{fn_name}: missing string argument \"{field}\" (positional or in the record object)"
        )),
    }
}

/// `consent_register(subject, purpose)` — append a consent record to
/// `consent_register.jsonl`. Returns the record id.
fn consent_register(args: Vec<Value>) -> StdlibResult {
    let subject = arg_string(&args, "subject", 0, "consent_register")?;
    let purpose = arg_string(&args, "purpose", 1, "consent_register")?;
    let record_id = new_record_id("consent");
    let record = serde_json::json!({
        "event": "consent_register",
        "record_id": record_id,
        "subject": subject,
        "purpose": purpose,
        "status": "registered",
        "registered_at": utc_rfc3339(),
    });
    append_record("consent", CONSENT_REGISTER_FILE, record)?;
    Ok(Value::String(record_id))
}

/// `consent_check(subject, purpose)` — true iff the consent register holds a
/// currently-registered (not withdrawn) record for subject+purpose.
fn consent_check(args: Vec<Value>) -> StdlibResult {
    let subject = arg_string(&args, "subject", 0, "consent_check")?;
    let purpose = arg_string(&args, "purpose", 1, "consent_check")?;
    let path = legal_data_dir()?.join(CONSENT_REGISTER_FILE);
    if !path.exists() {
        return Ok(Value::Bool(false));
    }
    let (records, _skipped) = read_jsonl(&path)?;
    let latest = records.iter().rev().find(|r| {
        r.get("subject").and_then(|v| v.as_str()) == Some(subject.as_str())
            && r.get("purpose").and_then(|v| v.as_str()) == Some(purpose.as_str())
    });
    let granted = match latest {
        Some(r) => match r.get("event").and_then(|v| v.as_str()) {
            Some("consent_register") => r.get("status").and_then(|v| v.as_str()) != Some("withdrawn"),
            Some("consent_withdraw") => false,
            _ => false,
        },
        None => false,
    };
    Ok(Value::Bool(granted))
}

/// `erasure_request(subject)` — append a GDPR right-to-erasure request to
/// `erasure_requests.jsonl`. Returns the request id.
fn erasure_request(args: Vec<Value>) -> StdlibResult {
    let subject = arg_string(&args, "subject", 0, "erasure_request")?;
    let scope = args
        .get(1)
        .and_then(|v| match v {
            Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "all records for subject".to_string());
    let request_id = new_record_id("erasure");
    let record = serde_json::json!({
        "event": "erasure_request",
        "request_id": request_id,
        "subject": subject,
        "scope": scope,
        "status": "requested",
        "requested_at": utc_rfc3339(),
    });
    append_record("erasure", ERASURE_REQUESTS_FILE, record)?;
    Ok(Value::String(request_id))
}

/// `subject_access_request(subject)` — append a GDPR Art.15 access request to
/// the erasure-requests register (same persistence channel, distinct event).
fn subject_access_request(args: Vec<Value>) -> StdlibResult {
    let subject = arg_string(&args, "subject", 0, "subject_access_request")?;
    let request_id = new_record_id("sar");
    let record = serde_json::json!({
        "event": "subject_access_request",
        "request_id": request_id,
        "subject": subject,
        "status": "requested",
        "requested_at": utc_rfc3339(),
    });
    append_record("sar", ERASURE_REQUESTS_FILE, record)?;
    Ok(Value::String(request_id))
}

/// Honest error for functions the runtime backend does not implement.
fn legal_unavailable(function: &str) -> String {
    format!(
        "legal.{function}: not implemented in the stdlib runtime backend — this backend \
         persists audit/consent/erasure records only (log_audit, read_audit_log, \
         consent_register, consent_check, erasure_request, subject_access_request). \
         Report generation, DORA/AI-Act record keeping, model provenance and breach \
         notification need host-side machinery; compile-time @legal/@cra_class/@dora \
         enforcement still runs in the AST passes."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_entry_struct() -> Value {
        Value::Struct {
            name: "AuditEntry".to_string(),
            fields: vec![
                ("timestamp".to_string(), Value::String(utc_rfc3339())),
                (
                    "function".to_string(),
                    Value::String("fetch_page".to_string()),
                ),
                (
                    "legal_basis".to_string(),
                    Value::String("public_data".to_string()),
                ),
                (
                    "purpose".to_string(),
                    Value::String("price research".to_string()),
                ),
                ("personal_data".to_string(), Value::Bool(false)),
                (
                    "jurisdiction".to_string(),
                    Value::Array(vec![Value::String("US".to_string())]),
                ),
                (
                    "robots_txt".to_string(),
                    Value::String("allowed".to_string()),
                ),
                ("records_processed".to_string(), Value::Int(42)),
                (
                    "compliance_status".to_string(),
                    Value::String("ok".to_string()),
                ),
            ],
        }
    }

    fn with_legal_dir<F: FnOnce() -> ()>(f: F) {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("TALLOW_LEGAL_DIR", tmp.path());
        }
        let _ = f();
        unsafe {
            std::env::remove_var("TALLOW_LEGAL_DIR");
        }
    }

    #[test]
    fn log_audit_persists_jsonl_and_reads_back() {
        with_legal_dir(|| {
            let res = dispatch("log_audit", vec![audit_entry_struct()]);
            assert!(matches!(res, Some(Ok(_))), "log_audit must persist, got {res:?}");

            let dir = legal_data_dir().unwrap();
            let log = dir.join(AUDIT_LOG_FILE);
            assert!(log.exists(), "audit_log.jsonl must exist after log_audit");
            let content = std::fs::read_to_string(&log).unwrap();
            assert_eq!(content.lines().count(), 1, "one JSONL record");
            let parsed: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
            assert_eq!(parsed["function"], "fetch_page");
            assert_eq!(parsed["records_processed"], 42);
            assert!(parsed.get("recorded_at").is_some(), "record carries recorded_at");

            // read back as []AuditEntry (declared Result<[]AuditEntry>)
            let read_back = dispatch("read_audit_log", vec![Value::String(String::new())]);
            match read_back {
                Some(Ok(Value::Ok(inner))) => match *inner {
                    Value::Array(entries) => {
                        assert_eq!(entries.len(), 1);
                        if let Value::Struct { name, fields } = &entries[0] {
                            assert_eq!(name, "AuditEntry");
                            assert!(fields.iter().any(|(k, v)| k == "function"
                                && matches!(v, Value::String(s) if s == "fetch_page")));
                        } else {
                            panic!("entry should be an AuditEntry struct");
                        }
                    }
                    other => panic!("read_audit_log should return Ok([]AuditEntry), got {other:?}"),
                },
                other => panic!("read_audit_log should return Ok([]AuditEntry), got {other:?}"),
            }
        });
    }

    #[test]
    fn consent_register_and_check_roundtrip() {
        with_legal_dir(|| {
            let reg = dispatch(
                "consent_register",
                vec![Value::String("alice@example.com".into()), Value::String("marketing".into())],
            );
            let id = match reg {
                Some(Ok(Value::String(id))) => id,
                other => panic!("consent_register should return record id, got {other:?}"),
            };
            assert!(id.starts_with("consent-"));

            let granted = dispatch(
                "consent_check",
                vec![Value::String("alice@example.com".into()), Value::String("marketing".into())],
            );
            assert!(matches!(granted, Some(Ok(Value::Bool(true)))));

            let denied = dispatch(
                "consent_check",
                vec![Value::String("bob@example.com".into()), Value::String("marketing".into())],
            );
            assert!(matches!(denied, Some(Ok(Value::Bool(false)))));
        });
    }

    #[test]
    fn erasure_request_persists() {
        with_legal_dir(|| {
            let res = dispatch("erasure_request", vec![Value::String("alice@example.com".into())]);
            let id = match res {
                Some(Ok(Value::String(id))) => id,
                other => panic!("erasure_request should return request id, got {other:?}"),
            };
            assert!(id.starts_with("erasure-"));
            let path = legal_data_dir().unwrap().join(ERASURE_REQUESTS_FILE);
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(content.contains("alice@example.com"));
            assert!(content.contains("\"status\":\"requested\""));
        });
    }

    #[test]
    fn unconfigured_functions_stay_honest_errors() {
        for (fn_name, args) in [
            ("cra_audit", vec![]),
            ("generate_report", vec![]),
            ("model_provenance_attest", vec![]),
            ("breach_notify", vec![]),
        ] {
            let res = dispatch(fn_name, args);
            match res {
                Some(Err(msg)) => {
                    assert!(msg.contains("not implemented"), "{fn_name}: {msg}");
                    assert!(
                        msg.contains("log_audit"),
                        "{fn_name} error should point at the real backend surface: {msg}"
                    );
                }
                other => panic!("{fn_name} must be an honest Err, got {other:?}"),
            }
        }
        assert!(dispatch("not_a_real_fn", vec![]).is_none());
    }

    #[test]
    fn missing_args_are_honest_errors() {
        with_legal_dir(|| {
            let res = dispatch("log_audit", vec![]);
            assert!(matches!(res, Some(Err(msg)) if msg.contains("requires an AuditEntry")));
            let res = dispatch("consent_register", vec![Value::String("x".into())]);
            assert!(matches!(res, Some(Err(msg)) if msg.contains("missing string argument")));
        });
    }
}
