//! FFI wrappers for enterprise features.
//!
//! Provides PII scanning/redaction, content fingerprinting, HTML parsing
//! (without a browser), and audit logging for compiled Tallow binaries.
//! These bridge interpreter-only capabilities to native code via extern "C".

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};

// ── PII Scanner ──────────────────────────────────────────────────────────

/// Scan text for PII and return a JSON report.
/// Result format: `{"count":N,"redacted_text":"...","types":["Email","Phone",...]}`
/// Caller must free with `tallow_free_string`. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_pii_scan(text: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(text) } {
        Some(s) => s,
        None => {
            set_last_error("pii_scan: null text".to_string());
            return std::ptr::null_mut();
        }
    };
    let result = crate::browser::privacy::scan_and_redact(s);
    let types_json: Vec<String> = result
        .types_found
        .iter()
        .map(|t| format!("\"{:?}\"", t))
        .collect();
    let json = format!(
        r#"{{"count":{},"redacted_text":"{}","types":[{}]}}"#,
        result.count,
        result.redacted_text.replace('\\', "\\\\").replace('"', "\\\""),
        types_json.join(","),
    );
    string_to_cstr(&json)
}

/// Redact PII from text. Returns the redacted string.
/// Caller must free with `tallow_free_string`. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_pii_redact(text: *const c_char) -> *mut c_char {
    let s = match unsafe { cstr_to_str(text) } {
        Some(s) => s,
        None => {
            set_last_error("pii_redact: null text".to_string());
            return std::ptr::null_mut();
        }
    };
    let result = crate::browser::privacy::scan_and_redact(s);
    string_to_cstr(&result.redacted_text)
}

// ── Content Fingerprint ──────────────────────────────────────────────────

/// Compute a SimHash content fingerprint for deduplication.
/// Returns a 64-bit hash value. Returns 0 if input is null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_content_fingerprint(text: *const c_char) -> u64 {
    let s = match unsafe { cstr_to_str(text) } {
        Some(s) => s,
        None => return 0,
    };
    let fp = crate::browser::privacy::ContentFingerprint::from_text(s);
    fp.hash
}

/// Compute similarity between two content fingerprints (0.0 = different, 1.0 = identical).
/// Based on Hamming distance of the 64-bit SimHash values.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_content_similarity(hash1: u64, hash2: u64) -> f64 {
    let xor = hash1 ^ hash2;
    1.0 - (xor.count_ones() as f64 / 64.0)
}

// ── HTML Parser (no browser needed) ──────────────────────────────────────

/// Extract text content from HTML matching a CSS selector. Returns JSON array string.
/// Supports tag selectors (`p`), class selectors (`.price`), and ID selectors (`#title`).
/// Caller must free with `tallow_free_string`. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_extract_text(
    html: *const c_char,
    selector: *const c_char,
) -> *mut c_char {
    let h = match unsafe { cstr_to_str(html) } {
        Some(s) => s,
        None => {
            set_last_error("html_extract_text: null html".to_string());
            return std::ptr::null_mut();
        }
    };
    let s = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("html_extract_text: null selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let results = crate::browser::html_parser::HtmlParser::extract_text(h, s);
    let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
    string_to_cstr(&json)
}

/// Extract all href links from HTML. Returns JSON array string.
/// Caller must free with `tallow_free_string`. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_extract_links(html: *const c_char) -> *mut c_char {
    let h = match unsafe { cstr_to_str(html) } {
        Some(s) => s,
        None => {
            set_last_error("html_extract_links: null html".to_string());
            return std::ptr::null_mut();
        }
    };
    let results = crate::browser::html_parser::HtmlParser::extract_links(h);
    let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
    string_to_cstr(&json)
}

// ── Audit Log ────────────────────────────────────────────────────────────

/// Serialize the append to the JSONL audit sink so concurrent writers from
/// threads of the same process cannot interleave partial lines.
static AUDIT_FILE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Write an entry to the audit log. Returns 0 on success, -1 on error.
///
/// Two sinks, one call:
///
/// 1. The in-memory log (compat; exported via `tallow_audit_export`).
/// 2. The JSONL file sink — one flat record per call appended to
///    `<TALLOW_LEGAL_DIR|~/.tallow/legal>/audit_log.jsonl`, schema
///    `tallow.audit.entry.v1`, discriminated by `"source": "native_codegen"`.
///    This is the cycle-02/08 §3(a) Option A sink: native codegen emits one
///    entry per `@legal` function at function entry.
///
/// `details` is the codegen-supplied JSON object
/// (`{"legal_basis":…,"purpose":…[,"retain_for":…]}`); a non-object payload
/// degrades to `{"details": "<raw>"}` instead of failing. The file write is
/// best-effort in the sense that a failure never panics and never aborts the
/// caller program, but it is reported to the caller as `-1` (the existing
/// error contract). Fields `records_processed`/`compliance_status` are
/// deliberately absent — they are not knowable at entry (anti-hype rule).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_audit_log(action: *const c_char, details: *const c_char) -> i32 {
    let a = match unsafe { cstr_to_str(action) } {
        Some(s) => s,
        None => {
            set_last_error("audit_log: null action".to_string());
            return -1;
        }
    };
    let d = match unsafe { cstr_to_str(details) } {
        Some(s) => s,
        None => "",
    };
    AUDIT_LOG.with(|log| {
        let entry = format!(
            r#"{{"timestamp":"{}","action":"{}","details":"{}"}}"#,
            chrono_now_iso(),
            a.replace('"', "\\\""),
            d.replace('"', "\\\""),
        );
        log.borrow_mut().push(entry);
    });
    match append_audit_jsonl(&a, d) {
        Ok(()) => 0,
        Err(msg) => {
            set_last_error(format!("audit_log: {msg}"));
            -1
        }
    }
}

/// Build and append one `tallow.audit.entry.v1` record to the shared legal
/// JSONL sink (`crate::stdlib::legal::append_jsonl` → `audit_log.jsonl`).
fn append_audit_jsonl(function: &str, details: &str) -> Result<(), String> {
    let parsed = serde_json::from_str::<serde_json::Value>(details)
        .ok()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({ "details": details }));

    let mut record = serde_json::Map::new();
    record.insert(
        "schema".to_string(),
        serde_json::json!("tallow.audit.entry.v1"),
    );
    record.insert("timestamp".to_string(), serde_json::json!(chrono_now_iso()));
    record.insert(
        "source".to_string(),
        serde_json::json!("native_codegen"),
    );
    record.insert("function".to_string(), serde_json::json!(function));
    for key in ["legal_basis", "purpose", "retain_for"] {
        if let Some(v) = parsed.get(key) {
            record.insert(key.to_string(), v.clone());
        }
    }
    // Non-object payloads degrade to `{"details": "<raw>"}` (see doc above);
    // carry that value through so the raw details are never dropped.
    if let Some(v) = parsed.get("details") {
        record.insert("details".to_string(), v.clone());
    }
    record.insert(
        "tallow_version".to_string(),
        serde_json::json!(env!("CARGO_PKG_VERSION")),
    );
    record.insert("pid".to_string(), serde_json::json!(std::process::id()));

    let _guard = AUDIT_FILE_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    crate::stdlib::legal::append_jsonl(
        crate::stdlib::legal::AUDIT_LOG_FILE,
        &serde_json::Value::Object(record),
    )
    .map(|_path| ())
}

/// Export all audit log entries as a JSON array string.
/// Caller must free with `tallow_free_string`. Returns "[]" if empty.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_audit_export() -> *mut c_char {
    AUDIT_LOG.with(|log| {
        let entries = log.borrow();
        let json = format!("[{}]", entries.join(","));
        string_to_cstr(&json)
    })
}

// ── Audit Log Storage ────────────────────────────────────────────────────

thread_local! {
    static AUDIT_LOG: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Simple ISO-8601 timestamp without chrono dependency.
fn chrono_now_iso() -> String {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::stdlib::time::epoch_secs_to_iso(epoch as i64)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_pii_scan_with_email() {
        let text = CString::new("Contact us at test@example.com for info").unwrap();
        let result = tallow_pii_scan(text.as_ptr());
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(json.contains("\"count\":1"));
        assert!(json.contains("[EMAIL_REDACTED]"));
        assert!(json.contains("Email"));
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_pii_scan_no_pii() {
        let text = CString::new("Hello world, no PII here").unwrap();
        let result = tallow_pii_scan(text.as_ptr());
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(json.contains("\"count\":0"));
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_pii_scan_null() {
        let result = tallow_pii_scan(std::ptr::null());
        assert!(result.is_null());
    }

    #[test]
    fn test_pii_redact_email() {
        let text = CString::new("Email: user@domain.com").unwrap();
        let result = tallow_pii_redact(text.as_ptr());
        assert!(!result.is_null());
        let redacted = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(redacted.contains("[EMAIL_REDACTED]"));
        assert!(!redacted.contains("user@domain.com"));
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_pii_redact_null() {
        let result = tallow_pii_redact(std::ptr::null());
        assert!(result.is_null());
    }

    #[test]
    fn test_content_fingerprint_same_text() {
        let text = CString::new("The quick brown fox jumps over the lazy dog").unwrap();
        let hash1 = tallow_content_fingerprint(text.as_ptr());
        let hash2 = tallow_content_fingerprint(text.as_ptr());
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, 0);
    }

    #[test]
    fn test_content_fingerprint_different_text() {
        let text1 = CString::new("The quick brown fox jumps over the lazy dog").unwrap();
        let text2 = CString::new("Completely different content about programming languages").unwrap();
        let hash1 = tallow_content_fingerprint(text1.as_ptr());
        let hash2 = tallow_content_fingerprint(text2.as_ptr());
        // Different texts should (usually) produce different hashes
        // Not guaranteed but extremely likely for very different content
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_content_fingerprint_null() {
        assert_eq!(tallow_content_fingerprint(std::ptr::null()), 0);
    }

    #[test]
    fn test_content_similarity_identical() {
        let sim = tallow_content_similarity(0xDEADBEEF, 0xDEADBEEF);
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_content_similarity_different() {
        let sim = tallow_content_similarity(0x0, 0xFFFFFFFFFFFFFFFF);
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_content_similarity_partial() {
        // One bit different in 64 => similarity = 63/64
        let sim = tallow_content_similarity(0x0, 0x1);
        let expected = 1.0 - (1.0 / 64.0);
        assert!((sim - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_html_extract_text_by_tag() {
        let html = CString::new("<p>Hello</p><p>World</p>").unwrap();
        let sel = CString::new("p").unwrap();
        let result = tallow_html_extract_text(html.as_ptr(), sel.as_ptr());
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(json.contains("Hello"));
        assert!(json.contains("World"));
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_html_extract_text_by_class() {
        let html = CString::new(r#"<div class="price">$9.99</div><div class="name">Widget</div>"#).unwrap();
        let sel = CString::new(".price").unwrap();
        let result = tallow_html_extract_text(html.as_ptr(), sel.as_ptr());
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(json.contains("$9.99"));
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_html_extract_text_null_html() {
        let sel = CString::new("p").unwrap();
        let result = tallow_html_extract_text(std::ptr::null(), sel.as_ptr());
        assert!(result.is_null());
    }

    #[test]
    fn test_html_extract_text_null_selector() {
        let html = CString::new("<p>test</p>").unwrap();
        let result = tallow_html_extract_text(html.as_ptr(), std::ptr::null());
        assert!(result.is_null());
    }

    #[test]
    fn test_html_extract_links() {
        let html = CString::new(
            r#"<a href="https://example.com">Link 1</a><a href="https://test.com">Link 2</a>"#,
        )
        .unwrap();
        let result = tallow_html_extract_links(html.as_ptr());
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(json.contains("https://example.com"));
        assert!(json.contains("https://test.com"));
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_html_extract_links_null() {
        let result = tallow_html_extract_links(std::ptr::null());
        assert!(result.is_null());
    }

    #[test]
    fn test_html_extract_links_no_links() {
        let html = CString::new("<p>No links here</p>").unwrap();
        let result = tallow_html_extract_links(html.as_ptr());
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert_eq!(json, "[]");
        super::super::tallow_free_string(result);
    }

    #[test]
    fn test_audit_log_and_export() {
        // Clear any existing entries
        AUDIT_LOG.with(|log| log.borrow_mut().clear());

        // Keep the JSONL sink hermetic: point TALLOW_LEGAL_DIR at a tempdir for
        // the duration, under the process-global env lock (same pattern as the
        // stdlib legal tests).
        let guard = crate::runtime::egress_http::env_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("TALLOW_LEGAL_DIR", tmp.path());
        }

        let action = CString::new("scrape_page").unwrap();
        let details = CString::new("fetched https://example.com").unwrap();
        assert_eq!(tallow_audit_log(action.as_ptr(), details.as_ptr()), 0);

        let action2 = CString::new("extract_data").unwrap();
        let details2 = CString::new("extracted 42 records").unwrap();
        assert_eq!(tallow_audit_log(action2.as_ptr(), details2.as_ptr()), 0);

        let result = tallow_audit_export();
        assert!(!result.is_null());
        let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("scrape_page"));
        assert!(json.contains("extract_data"));
        super::super::tallow_free_string(result);

        // The file sink: two appended schema-v1 records, and the non-object
        // `details` payload degrades to `{"details": "<raw>"}`.
        let log_path = tmp.path().join(crate::stdlib::legal::AUDIT_LOG_FILE);
        let content = std::fs::read_to_string(&log_path).expect("audit_log.jsonl written");
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "one JSONL record per call: {content}");
        let rec: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON record");
        assert_eq!(rec["schema"], "tallow.audit.entry.v1");
        assert_eq!(rec["source"], "native_codegen");
        assert_eq!(rec["function"], "scrape_page");
        assert_eq!(rec["details"], "fetched https://example.com");
        assert!(rec["timestamp"].as_str().is_some_and(|t| t.contains('T')));
        assert_eq!(rec["tallow_version"], env!("CARGO_PKG_VERSION"));

        unsafe {
            std::env::remove_var("TALLOW_LEGAL_DIR");
        }
        drop(guard);
    }

    #[test]
    fn test_audit_log_null_action() {
        assert_eq!(tallow_audit_log(std::ptr::null(), std::ptr::null()), -1);
    }

    #[test]
    fn test_audit_export_empty() {
        // Use a separate thread to get a clean thread-local
        let handle = std::thread::spawn(|| {
            let result = tallow_audit_export();
            assert!(!result.is_null());
            let json = unsafe { CStr::from_ptr(result).to_str().unwrap() };
            assert_eq!(json, "[]");
            super::super::tallow_free_string(result);
        });
        handle.join().unwrap();
    }
}
