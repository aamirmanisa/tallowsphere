//! Telemetry choke point — slice 1 of R-6.1: classify → redact → route.
//!
//! One function, [`emit_security_event`], is the single path a
//! security-relevant signal takes on its way to a sink. Slice 1 (T-115) wires
//! it for two real signal sources — egress refusals (`runtime.fetch`,
//! `stdlib.http`) and CLI config writes (`tallow config set`) — and makes
//! every event pass through [`crate::metadata_min`]'s strict minimization
//! **before** any sink sees it: URLs are stripped of query strings and
//! fragments, actor names are hashed (`n-<sha256>`), timestamps are floored to
//! the hour, and sizes are padded to 4 KiB blocks. Raw values never reach a
//! sink by construction.
//!
//! # Shape
//!
//! * [`EventClass`] — classification of the signal (`egress_refusal`,
//!   `config_change`, `policy_verdict`).
//! * [`Plane`] — the classification's routing target (`audit` vs `ops`; both
//!   planes share the one journal sink today — ledger/EventStore routing is
//!   deliberate remainder, R-6.1).
//! * [`SecurityEvent`] — the caller-supplied event, raw fields.
//! * [`RedactedSecurityEvent`] — what a sink may see: minimized fields only.
//! * [`SecurityEventSink`] — one `record` method; [`JsonlFileSink`] (0600
//!   append-only journal, default `~/.tallow/security-events.jsonl`) and
//!   [`MemorySink`] (tests) are the two implementations.
//!
//! # Failure policy (fail-open with marker; never fail-loud with payload)
//!
//! If minimization refuses an event (empty actor, unusable target URL), the
//! sink still receives a *marker* record — `note: "redaction_error:<field>"`,
//! no raw payload — and [`emit_security_event`] returns the error to the
//! caller. Call sites on refusal/error paths treat emission as best-effort
//! (`let _ =`): the refusal itself must never depend on the journal being
//! writable. Sink write failures surface as [`EmitError::Sink`] and are
//! likewise non-fatal to the caller's own outcome.
//!
//! # Deliberate remainder (slice 1 does NOT do these)
//! Canary scanning (R-6.10), consent gating (R-6.2), ledger/EventStore/
//! graph routing (the journal is the only sink so far), the `egress_http`
//! call site (file owned by another change today — exact patch recorded in
//! `research/.../impl/T-115.md`), and the CI no-bypass guard (R-6.13).
//!
//! Timestamps are caller-supplied (`at_ms`) so events are reproducible in
//! tests; [`now_ms`] is provided for live call sites.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::metadata_min::{self, MetaError, MetaItem, MetaPolicy};

/// Environment override for the journal path. `0` / `off` / `false` / empty
/// disables journaling entirely ([`EmitError::NoSink`]).
pub const JOURNAL_ENV: &str = "TALLOW_SECURITY_EVENTS";

// ── Classification ───────────────────────────────────────────────────────────

/// Which kind of security signal an event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    /// An egress path refused to run unproxied (invariant N3 class).
    EgressRefusal,
    /// A config write (`tallow config set` and future typed kernels).
    ConfigChange,
    /// A policy verdict (reserved for the ops-gate/consent wiring, R-6.9).
    PolicyVerdict,
    /// An egress path ran **direct** under the explicit `TALLOW_ALLOW_DIRECT`
    /// opt-out (browser zone: `browser.zone` actor, T-207-fu). Leak-by-design
    /// and operator-chosen, but never silent: the bypass is recorded on the
    /// audit plane like a refusal is.
    DirectEgress,
}

impl EventClass {
    /// Stable lowercase wire name — part of the serialized record.
    pub fn as_str(self) -> &'static str {
        match self {
            EventClass::EgressRefusal => "egress_refusal",
            EventClass::ConfigChange => "config_change",
            EventClass::PolicyVerdict => "policy_verdict",
            EventClass::DirectEgress => "direct_egress",
        }
    }

    /// Slice-1 routing classification. Egress refusals, direct-egress
    /// opt-ins and config changes are audit-relevant (security posture);
    /// policy verdicts are ops-plane. Both planes currently land in the same
    /// journal sink — the plane is carried on the record so the future
    /// routing split is data, not a re-classification.
    pub fn plane(self) -> Plane {
        match self {
            EventClass::EgressRefusal | EventClass::ConfigChange | EventClass::DirectEgress => {
                Plane::Audit
            }
            EventClass::PolicyVerdict => Plane::Ops,
        }
    }
}

/// Routing target of a classified event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plane {
    /// Audit plane — will be the append-only ledger (R-6.1 remainder).
    Audit,
    /// Ops plane — local structured journal (slice-1 sink for both planes).
    Ops,
}

// ── Events ───────────────────────────────────────────────────────────────────

/// A security event as supplied by the caller — raw fields, never given to a
/// sink directly.
///
/// * `actor` — who acted/refused, e.g. `"runtime.fetch"`; hashed on emission.
/// * `target` — the URL or config key involved; URL-redacted on emission
///   (`None` stays `None`). For config events pass the *key*, never the value.
/// * `size` — byte size associated with the event (e.g. value length); padded
///   to 4 KiB blocks on emission.
/// * `at_ms` — unix-ms instant; floored to the hour on emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    /// Classification of the signal.
    pub class: EventClass,
    /// Subsystem that emitted the event (hashed before any sink).
    pub actor: String,
    /// URL or config key the event is about (URL-redacted before any sink).
    pub target: Option<String>,
    /// Associated byte size (padded before any sink).
    pub size: usize,
    /// Unix-ms instant (coarsened before any sink).
    pub at_ms: i64,
}

/// A minimized security event — the only shape a [`SecurityEventSink`] ever
/// receives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedSecurityEvent {
    /// Classification, copied from [`SecurityEvent::class`].
    pub class: EventClass,
    /// Routing target derived from the classification.
    pub plane: Plane,
    /// Event id (`<class>-<coarse-ms>`) — never contains raw sub-hour time.
    pub id: String,
    /// Hashed actor (`n-<sha256>`) or `"redaction_error"` for marker records.
    pub actor_hash: String,
    /// Redacted URL / config key, or `None` on absence or redaction failure.
    pub target: Option<String>,
    /// Padded size (4 KiB blocks) or `0` on redaction failure.
    pub size: usize,
    /// Coarsened (hour-floored) unix-ms instant.
    pub at_ms: i64,
    /// `None` for normal records; `Some("redaction_error:<field>")` for
    /// markers — never carries the raw payload.
    pub note: Option<String>,
}

// ── Sinks ────────────────────────────────────────────────────────────────────

/// Anything that can durably record one minimized security event.
pub trait SecurityEventSink {
    /// Record one minimized event. Errors are the sink's own; the choke point
    /// surfaces them as [`EmitError::Sink`] and callers stay non-fatal.
    fn record(&mut self, ev: &RedactedSecurityEvent) -> Result<(), String>;
}

/// In-memory sink (tests, replay).
#[derive(Debug, Default)]
pub struct MemorySink {
    events: Vec<RedactedSecurityEvent>,
}

impl MemorySink {
    /// Empty sink.
    pub fn new() -> Self {
        MemorySink {
            events: Vec::new(),
        }
    }

    /// Events recorded so far, in order.
    pub fn events(&self) -> &[RedactedSecurityEvent] {
        &self.events
    }
}

impl SecurityEventSink for MemorySink {
    fn record(&mut self, ev: &RedactedSecurityEvent) -> Result<(), String> {
        self.events.push(ev.clone());
        Ok(())
    }
}

/// Append-only JSONL journal. One minimized event per line; the file is
/// created on first write and chmod'ed 0600 on unix (best-effort — the ops
/// plane is fail-open, unlike the export plane).
#[derive(Debug, Clone)]
pub struct JsonlFileSink {
    path: PathBuf,
}

impl JsonlFileSink {
    /// Journal at `path`.
    pub fn new(path: PathBuf) -> Self {
        JsonlFileSink { path }
    }

    /// Journal path (for reporting/tests).
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl SecurityEventSink for JsonlFileSink {
    fn record(&mut self, ev: &RedactedSecurityEvent) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let line = serde_json::to_string(ev).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open {}: {e}", self.path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        writeln!(file, "{line}").map_err(|e| format!("append {}: {e}", self.path.display()))
    }
}

// ── Emission ─────────────────────────────────────────────────────────────────

/// Errors from the choke point. All are non-fatal at refusal/error call
/// sites (emission is best-effort); [`EmitError::Redaction`] means a marker
/// record (no payload) was written instead of the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// Minimization refused a field; a marker record was still recorded.
    Redaction(MetaError),
    /// The sink itself failed (I/O, serialization).
    Sink(String),
    /// Journaling is disabled or no journal path is resolvable.
    NoSink,
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::Redaction(e) => write!(f, "security event redaction failed: {e}"),
            EmitError::Sink(s) => write!(f, "security event sink failed: {s}"),
            EmitError::NoSink => write!(f, "security event journal unavailable"),
        }
    }
}

impl std::error::Error for EmitError {}

/// The choke point: classify → minimize via [`crate::metadata_min`] (strict
/// policy) → hand the minimized record to `sink`.
///
/// Returns the minimized record on success. On minimization failure a marker
/// record (`note = "redaction_error:<field>"`, no raw payload) is recorded
/// and [`EmitError::Redaction`] is returned — the raw event is never written.
pub fn emit_security_event(
    sink: &mut dyn SecurityEventSink,
    ev: &SecurityEvent,
) -> Result<RedactedSecurityEvent, EmitError> {
    let coarse_ms = metadata_min::coarse_timestamp(ev.at_ms);
    let id = format!("{}-{}", ev.class.as_str(), coarse_ms);
    let item = MetaItem {
        id: id.clone(),
        name: ev.actor.clone(),
        url: ev.target.clone(),
        size: ev.size,
        created_ms: ev.at_ms,
    };
    match metadata_min::minimize(&MetaPolicy::strict(), &item) {
        Ok(min) => {
            let red = RedactedSecurityEvent {
                class: ev.class,
                plane: ev.class.plane(),
                id: min.id,
                actor_hash: min.name,
                target: min.url,
                size: min.size,
                at_ms: min.created_ms,
                note: None,
            };
            sink.record(&red).map_err(EmitError::Sink)?;
            Ok(red)
        }
        Err(e) => {
            let marker = RedactedSecurityEvent {
                class: ev.class,
                plane: ev.class.plane(),
                id,
                actor_hash: "redaction_error".to_string(),
                target: None,
                size: 0,
                at_ms: coarse_ms,
                note: Some(format!("redaction_error:{}", match &e {
                    MetaError::BadInput(field) => field,
                })),
            };
            let _ = sink.record(&marker);
            Err(EmitError::Redaction(e))
        }
    }
}

/// Journal path: `$TALLOW_SECURITY_EVENTS` if set (and not a disable token),
/// else `~/.tallow/security-events.jsonl`; `None` disables journaling.
pub fn default_journal_path() -> Option<PathBuf> {
    match std::env::var(JOURNAL_ENV) {
        Ok(v) => {
            let t = v.trim();
            if t.is_empty() || matches!(t.to_ascii_lowercase().as_str(), "0" | "off" | "false") {
                None
            } else {
                Some(PathBuf::from(t))
            }
        }
        Err(_) => dirs::home_dir().map(|h| h.join(".tallow").join("security-events.jsonl")),
    }
}

/// Live call-site convenience: emit to the default journal (best-effort).
/// Callers on refusal/error paths use `let _ =` — the refusal's own outcome
/// must never depend on the journal being writable.
pub fn emit_to_default_journal(ev: &SecurityEvent) -> Result<RedactedSecurityEvent, EmitError> {
    let path = default_journal_path().ok_or(EmitError::NoSink)?;
    let mut sink = JsonlFileSink::new(path);
    emit_security_event(&mut sink, ev)
}

/// Wall-clock unix milliseconds — for live call sites; tests pass explicit
/// `at_ms` instead.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Externally computed (printf … | sha256sum) so the hashing convention is
    // grounded outside this module's own code path.
    const SHA256_FETCHER: &str =
        "89008e294b51090a98a32c9d5eed43f6a54b19b54aab3424b5168ef6cc5d5f45";

    fn fetch_refusal_event() -> SecurityEvent {
        SecurityEvent {
            class: EventClass::EgressRefusal,
            actor: "fetcher".to_string(),
            target: Some("socks5h://127.0.0.1:9050?token=SEKRET-VALUE#frag".to_string()),
            size: 1,
            at_ms: 1_700_000_123_456,
        }
    }

    /// SMOKE (R-6.1 slice 1): one emission, and every minimize transform is
    /// proven on the record a sink actually receives — URL query/fragment
    /// gone, actor hashed, timestamp hour-floored, size block-padded, raw
    /// values absent from the wire form.
    #[test]
    fn smoke_emit_security_event_redacts_before_the_sink() {
        let mut sink = MemorySink::new();
        let red = emit_security_event(&mut sink, &fetch_refusal_event()).unwrap();

        assert_eq!(sink.events().len(), 1, "sink must receive exactly one event");
        assert_eq!(sink.events()[0], red);
        assert_eq!(red.class, EventClass::EgressRefusal);
        assert_eq!(red.plane, Plane::Audit, "egress refusals classify to the audit plane");
        assert_eq!(red.actor_hash, format!("n-{SHA256_FETCHER}"), "actor must be hashed");
        assert_eq!(
            red.target.as_deref(),
            Some("socks5h://127.0.0.1:9050"),
            "query string and fragment must be stripped"
        );
        assert_eq!(red.at_ms, 1_699_999_200_000, "timestamp must be hour-floored");
        assert_eq!(red.size, 4096, "size must be padded to a 4 KiB block");
        assert_eq!(red.id, "egress_refusal-1699999200000");

        let wire = serde_json::to_string(&red).unwrap();
        for raw in ["SEKRET-VALUE", "fetcher", "frag", "1700000123456"] {
            assert!(!wire.contains(raw), "raw value {raw:?} leaked into {wire}");
        }

        // The input event is untouched.
        let ev = fetch_refusal_event();
        assert_eq!(ev.actor, "fetcher");
        assert_eq!(ev.at_ms, 1_700_000_123_456);
    }

    /// The journal sink round-trips the minimized record as one JSONL line,
    /// and a redaction refusal writes a marker (never the raw payload).
    #[test]
    fn file_journal_round_trip_and_marker_on_redaction_failure() {
        let dir = std::env::temp_dir().join(format!("tallow-t115-smoke-{}", std::process::id()));
        let path = dir.join("security-events.jsonl");
        let mut sink = JsonlFileSink::new(path.clone());

        let red = emit_security_event(&mut sink, &fetch_refusal_event()).unwrap();
        assert_eq!(red.note, None);

        // Unusable target URL → redact_url refuses → marker record, error out.
        let bad = SecurityEvent {
            class: EventClass::ConfigChange,
            actor: "cli.config".to_string(),
            target: Some("?x=1".to_string()),
            size: 0,
            at_ms: 0,
        };
        assert_eq!(
            emit_security_event(&mut sink, &bad),
            Err(EmitError::Redaction(MetaError::BadInput("url")))
        );

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one event line + one marker line");

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["class"], "egress_refusal");
        assert_eq!(first["plane"], "audit");
        assert_eq!(first["target"], "socks5h://127.0.0.1:9050");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["class"], "config_change");
        assert_eq!(second["note"], "redaction_error:url");
        assert_eq!(second["target"], serde_json::Value::Null);
        assert!(
            !contents.contains("?x=1"),
            "raw refused payload must never reach the journal"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "journal must be 0600");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
