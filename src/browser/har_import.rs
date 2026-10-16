//! HAR 1.2 **import** — the missing half of Tallow's HAR support.
//!
//! `browser::network::HarRecorder` writes HAR, so a capture taken *outside*
//! Tallow had no way into the pipeline: every artifact had to originate from
//! Tallow's own recorder. This module is that entry point, and it holds two
//! invariants:
//!
//! 1. **One shape, not two.** Imported entries land in the same
//!    [`crate::browser::network::HarLog`] structs the recorder emits. A
//!    parallel import-side type would be a second source of truth for what a
//!    capture is, and the two would drift.
//! 2. **Redaction is not optional.** An imported capture passes through the
//!    same [`crate::browser::privacy`] scanner a live capture obeys. If import
//!    were unredacted, "hand me a HAR file" would be a way around the rules
//!    the live path enforces.
//!
//! Import never half-succeeds: a document is either parsed and returned whole,
//! or refused with a reason.

use crate::browser::network::HarLog;

/// Why an import was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarImportError {
    /// Not valid JSON, or not shaped like HAR 1.2.
    Parse(String),
    /// `log.version` is a HAR version this importer does not support. Refused
    /// rather than guessed at: a newer/older shape may mean different fields.
    UnsupportedVersion(String),
    /// A structurally valid HAR carrying no entries.
    ///
    /// Refused because an imported empty capture is indistinguishable, later,
    /// from "we looked and found nothing" — the same reason the extraction rows
    /// distinguish an absent value from an empty one.
    NoEntries,
}

impl std::fmt::Display for HarImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarImportError::Parse(m) => write!(f, "not a HAR document: {m}"),
            HarImportError::UnsupportedVersion(v) => write!(
                f,
                "unsupported HAR version {v:?} (this importer supports 1.2)"
            ),
            HarImportError::NoEntries => {
                write!(f, "the HAR document contains no entries")
            }
        }
    }
}

impl std::error::Error for HarImportError {}

/// Parse a HAR 1.2 document into the recorder's own shapes.
pub fn import_har(json: &str) -> Result<HarLog, HarImportError> {
    let log: HarLog =
        serde_json::from_str(json).map_err(|e| HarImportError::Parse(e.to_string()))?;
    if !log.log.version.starts_with("1.2") {
        return Err(HarImportError::UnsupportedVersion(log.log.version));
    }
    if log.log.entries.is_empty() {
        return Err(HarImportError::NoEntries);
    }
    Ok(log)
}

/// What a redaction pass changed. Counts, not a boolean: "redaction ran" and
/// "redaction found nothing" are different facts, and only the second is a
/// statement about the capture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionSummary {
    /// Text fields the scanner looked at.
    pub fields_scanned: usize,
    /// Fields the scanner actually rewrote.
    pub fields_changed: usize,
    /// Total PII instances replaced.
    pub redactions: usize,
}

impl RedactionSummary {
    /// A pass that scanned fields and changed none of them.
    pub fn is_clean(&self) -> bool {
        self.redactions == 0
    }
}

/// Redact one text field in place, counting the work.
fn redact_field(text: &mut String, summary: &mut RedactionSummary) {
    summary.fields_scanned += 1;
    let result = crate::browser::privacy::scan_and_redact(text);
    if result.count > 0 {
        *text = result.redacted_text;
        summary.fields_changed += 1;
        summary.redactions += result.count;
    }
}

/// Redact an imported capture in place: request URLs, request and response
/// header values, and response body text.
///
/// Headers are scanned as values (not as whole lines) so a redaction cannot
/// swallow a header name and silently change the capture's shape.
pub fn redact_har(log: &mut HarLog) -> RedactionSummary {
    let mut summary = RedactionSummary::default();
    for entry in &mut log.log.entries {
        redact_field(&mut entry.request.url, &mut summary);
        for header in &mut entry.request.headers {
            redact_field(&mut header.value, &mut summary);
        }
        for header in &mut entry.response.headers {
            redact_field(&mut header.value, &mut summary);
        }
        if let Some(text) = entry.response.content.text.as_mut() {
            redact_field(text, &mut summary);
        }
    }
    summary
}

/// Import and redact in one step — the shape callers should reach for, so an
/// unredacted imported capture cannot be produced by simply forgetting the
/// second call.
pub fn import_har_redacted(json: &str) -> Result<(HarLog, RedactionSummary), HarImportError> {
    let mut log = import_har(json)?;
    let summary = redact_har(&mut log);
    Ok((log, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally complete HAR 1.2 capture.
    const MINIMAL: &str = r#"{
      "log": {
        "version": "1.2",
        "creator": { "name": "probe", "version": "1.0" },
        "entries": [
          {
            "startedDateTime": "2026-10-15T00:00:00.000Z",
            "time": 12.5,
            "request": {
              "method": "GET",
              "url": "https://example.invalid/p/1",
              "httpVersion": "HTTP/1.1",
              "headers": [{ "name": "Accept", "value": "text/html" }],
              "queryString": [],
              "bodySize": 0,
              "headersSize": -1
            },
            "response": {
              "status": 200,
              "statusText": "OK",
              "httpVersion": "HTTP/1.1",
              "headers": [{ "name": "Content-Type", "value": "text/html" }],
              "content": { "size": 5, "mimeType": "text/html", "text": "hello" },
              "redirectURL": "",
              "bodySize": 5,
              "headersSize": -1
            },
            "timings": { "blocked": 0, "dns": 1, "connect": 2, "send": 0, "wait": 8, "receive": 1, "ssl": 1 }
          }
        ]
      }
    }"#;

    /// The same capture, with PII in the places a real one carries it.
    const WITH_SECRET: &str = r#"{
      "log": {
        "version": "1.2",
        "creator": { "name": "probe", "version": "1.0" },
        "entries": [
          {
            "startedDateTime": "2026-10-15T00:00:00.000Z",
            "time": 12.5,
            "request": {
              "method": "POST",
              "url": "https://example.invalid/checkout?email=ada@example.com",
              "httpVersion": "HTTP/1.1",
              "headers": [{ "name": "X-Contact", "value": "ada@example.com" }],
              "queryString": [],
              "bodySize": 0,
              "headersSize": -1
            },
            "response": {
              "status": 200,
              "statusText": "OK",
              "httpVersion": "HTTP/1.1",
              "headers": [{ "name": "Content-Type", "value": "text/html" }],
              "content": { "size": 26, "mimeType": "text/html", "text": "receipt for ada@example.com" },
              "redirectURL": "",
              "bodySize": 26,
              "headersSize": -1
            },
            "timings": { "blocked": 0, "dns": 1, "connect": 2, "send": 0, "wait": 8, "receive": 1, "ssl": 1 }
          }
        ]
      }
    }"#;

    #[test]
    fn parses_a_minimal_capture_and_keeps_every_entry() {
        let log = import_har(MINIMAL).expect("a valid HAR 1.2 parses");
        assert_eq!(log.log.version, "1.2");
        assert_eq!(log.log.entries.len(), 1);
        assert_eq!(log.log.entries[0].request.method, "GET");
        assert_eq!(log.log.entries[0].response.status, 200);
    }

    #[test]
    fn refuses_an_unsupported_version_by_name() {
        let bumped = MINIMAL.replace("\"version\": \"1.2\"", "\"version\": \"1.3\"");
        match import_har(&bumped) {
            Err(HarImportError::UnsupportedVersion(v)) => assert_eq!(v, "1.3"),
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    #[test]
    fn refuses_an_empty_capture_rather_than_returning_nothing() {
        const EMPTY: &str = r#"{
          "log": {
            "version": "1.2",
            "creator": { "name": "probe", "version": "1.0" },
            "entries": []
          }
        }"#;
        match import_har(EMPTY) {
            Err(HarImportError::NoEntries) => {}
            other => panic!("expected a no-entries refusal, got {other:?}"),
        }
    }

    #[test]
    fn refuses_a_document_that_is_not_har() {
        match import_har("{\"not\":\"har\"}") {
            Err(HarImportError::Parse(_)) => {}
            other => panic!("expected a parse refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_imported_secret_does_not_survive_redaction() {
        let (log, summary) = import_har_redacted(WITH_SECRET).expect("parses");
        assert!(!summary.is_clean(), "the capture contains PII: {summary:?}");
        assert!(summary.redactions >= 3, "url + header + body: {summary:?}");

        let entry = &log.log.entries[0];
        let all = format!(
            "{} {} {} {}",
            entry.request.url,
            entry.request.headers[0].value,
            entry.response.content.text.as_deref().unwrap_or(""),
            entry.response.headers[0].value,
        );
        assert!(
            !all.contains("ada@example.com"),
            "the raw address survived: {all}"
        );
        assert!(all.contains("[EMAIL_REDACTED]"), "{all}");
    }

    #[test]
    fn the_committed_fixture_parses_and_is_redacted() {
        // Reads the real file rather than an inline copy, so a fixture that
        // drifts — or loses the spec's `serverIPAddress` spelling — fails here.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/har/capture_with_secret.har");
        let raw = std::fs::read_to_string(&path).expect("the fixture is committed");
        let (log, summary) = import_har_redacted(&raw).expect("the committed fixture parses");

        assert_eq!(log.log.entries.len(), 1);
        assert!(summary.redactions >= 3, "{summary:?}");
        // The spec spelling is `serverIPAddress`; our field is `server_ip_address`
        // under `rename_all = "camelCase"`, so this only lands via the alias.
        assert_eq!(
            log.log.entries[0].server_ip_address.as_deref(),
            Some("203.0.113.7")
        );
        // The artifact on disk stays the capture, not the redacted view: the
        // redacted copy is what the pipeline carries, not what it overwrites.
        assert!(!raw.contains("[EMAIL_REDACTED]"));
    }

    #[test]
    fn a_clean_capture_reports_cleanly_rather_than_claiming_a_redaction() {
        let (_log, summary) = import_har_redacted(MINIMAL).expect("parses");
        assert!(summary.is_clean(), "{summary:?}");
        assert!(summary.fields_scanned >= 4, "{summary:?}");
        assert_eq!(summary.fields_changed, 0);
    }
}
