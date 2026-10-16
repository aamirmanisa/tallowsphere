//! SVID rotation wiring — root-crate half of R-5.10 (#120, W3 batch-2 cluster C).
//!
//! Engine: [`tallow_svid::rotation`] (T/2 driver, overlap, atomic swap, bounded
//! timer). This module is the *wiring* the row names explicitly:
//!
//! * **"all wired to key_ledger [`RotationPolicy`] gates"** —
//!   [`record_rotation_events`] maps every rotation event the driver produces
//!   into `key_ledger` key-use records (one logical key id per *generation*,
//!   so an intended re-issue never reads as a reuse finding), and
//!   [`node_key_rotation_policy`] is the annual node-key gate expressed as a
//!   `key_ledger` [`RotationPolicy`] (the model finally gets its call site).
//! * **"rotation alarms in `tallow doctor`"** — [`rotation_report`] builds the
//!   `tallow.doctor.rotation.v1` report value from a rotation-state file
//!   ([`RotationState`], schema `tallow.rotation_state.v1`): the driver's
//!   alarms (Info/Warn/Critical), held generations, and the node-key policy.
//! * **"ledger records every event"** — the state file carries the full
//!   append-only event history; the bridge is what turns it into ledger rows.
//!
//! Clock-free like the engine: callers pass `now` (Unix seconds).

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::key_ledger::{KeyError, KeyUse, KeyUseLedger, RotationPolicy};
use tallow_svid::rotation::{
    AlarmSeverity, HeldCredential, RotationAction, RotationDriver, RotationError, RotationEvent,
    ROTATION_DOMAIN,
};

/// Schema of the rotation-state file consumed by `tallow doctor --rotation`.
pub const ROTATION_STATE_SCHEMA: &str = "tallow.rotation_state.v1";
/// Schema of the doctor rotation report.
pub const ROTATION_REPORT_SCHEMA: &str = "tallow.doctor.rotation.v1";
/// Ledger context used for every rotation-derived key-use record.
pub const SVID_ROTATION_CONTEXT: &str = "svid-rotation";
/// Annual node-key rotation gate (R-5.10: "node key annual rotation").
pub const NODE_KEY_ANNUAL_MAX_AGE_MS: i64 = 365 * 24 * 60 * 60 * 1000;

/// Errors from the ledger/state bridge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The `key_ledger` refused a record.
    #[error("key_ledger refused rotation record: {0}")]
    Ledger(KeyError),
    /// A `Reissued` event carried no successor version (corrupt history).
    #[error("malformed rotation event: {0}")]
    MalformedEvent(String),
    /// The state file was not readable / not valid JSON / wrong schema.
    #[error("rotation state: {0}")]
    State(String),
    /// The engine rejected the state (duplicate subjects, bad windows, …).
    #[error("rotation state: {0}")]
    Engine(RotationError),
}

impl From<KeyError> for WireError {
    fn from(e: KeyError) -> Self {
        WireError::Ledger(e)
    }
}

/// Stable logical key id for one rotated generation:
/// the ledger's reuse detector keys on *identity*, and a re-issue is a new
/// identity by design (the old generation is retired, not reused).
pub fn version_key_id(subject: &str, version: u64) -> String {
    format!("svid:{subject}:v{version}")
}

/// Fingerprint for one generation (matches
/// [`tallow_svid::rotation::HeldCredential::fingerprint`]).
pub fn version_fingerprint(subject: &str, version: u64) -> String {
    format!("{ROTATION_DOMAIN}:{subject}:v{version}")
}

// ---------------------------------------------------------------------------
// State file
// ---------------------------------------------------------------------------

/// Rotation-state file: the held set plus the append-only event history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationState {
    /// [`ROTATION_STATE_SCHEMA`].
    pub schema: String,
    /// Currently held credentials.
    pub held: Vec<HeldCredential>,
    /// Recorded event history (most recent last).
    #[serde(default)]
    pub events: Vec<RotationEvent>,
}

impl RotationState {
    /// New state with an empty history.
    pub fn new(held: Vec<HeldCredential>) -> Self {
        Self {
            schema: ROTATION_STATE_SCHEMA.to_string(),
            held,
            events: Vec::new(),
        }
    }

    /// Parse + schema-check.
    pub fn from_json(json: &str) -> Result<Self, WireError> {
        let state: Self =
            serde_json::from_str(json).map_err(|e| WireError::State(format!("bad JSON: {e}")))?;
        if state.schema != ROTATION_STATE_SCHEMA {
            return Err(WireError::State(format!(
                "unsupported schema {:?} (want {:?})",
                state.schema, ROTATION_STATE_SCHEMA
            )));
        }
        Ok(state)
    }

    /// Pretty JSON (canonical for this struct: field order is fixed).
    pub fn to_json_pretty(&self) -> Result<String, WireError> {
        serde_json::to_string_pretty(self).map_err(|e| WireError::State(e.to_string()))
    }

    /// Build the engine driver over the held set.
    pub fn driver(&self) -> Result<RotationDriver, WireError> {
        RotationDriver::new(self.held.clone()).map_err(WireError::Engine)
    }
}

/// Load a rotation-state file.
pub fn load_state(path: &Path) -> Result<RotationState, WireError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| WireError::State(format!("cannot read {}: {e}", path.display())))?;
    RotationState::from_json(&text)
}

// ---------------------------------------------------------------------------
// key_ledger bridge
// ---------------------------------------------------------------------------

/// Record every rotation event into the key-use ledger. Returns the number of
/// records appended.
///
/// Mapping (documented so the gate stays auditable):
/// * `Reissued { from → to }` ⇒ a use of the **successor** generation id
///   (`svid:<subject>:v<to>`, operation `reissue`). The successor is a fresh
///   identity: no reuse finding is created by an intended rotation.
/// * `Expired` ⇒ a terminal use of the **expired** generation id
///   (`svid:<subject>:v<from>`, operation `expire`).
///
/// Every record lands in the fixed context [`SVID_ROTATION_CONTEXT`]; all
/// timestamps are the event's `ts` (Unix seconds → ms).
pub fn record_rotation_events(
    ledger: &mut KeyUseLedger,
    events: &[RotationEvent],
) -> Result<usize, WireError> {
    let mut appended = 0usize;
    for ev in events {
        let (version, operation) = match ev.action {
            RotationAction::Reissued => (
                ev.to_version.ok_or_else(|| {
                    WireError::MalformedEvent(format!(
                        "reissued event for {:?} lacks to_version",
                        ev.subject
                    ))
                })?,
                "reissue",
            ),
            RotationAction::Expired => (ev.from_version, "expire"),
        };
        ledger.record_key_use(KeyUse {
            key_id: version_key_id(&ev.subject, version),
            context: SVID_ROTATION_CONTEXT.to_string(),
            ts_ms: ev.ts.saturating_mul(1000),
            operation: operation.to_string(),
            fingerprint: version_fingerprint(&ev.subject, version),
        })?;
        appended += 1;
    }
    Ok(appended)
}

/// Annual node-key rotation gate as a `key_ledger` [`RotationPolicy`]
/// (age criterion only; use counts are not meaningful for node keys).
pub fn node_key_rotation_policy() -> RotationPolicy {
    RotationPolicy {
        max_age_ms: NODE_KEY_ANNUAL_MAX_AGE_MS,
        max_uses: 0,
    }
}

// ---------------------------------------------------------------------------
// Doctor report
// ---------------------------------------------------------------------------

/// Build the `tallow.doctor.rotation.v1` report value.
///
/// `state = None` is an explicit, non-silent condition: the report says
/// `"status": "no_state"` (the caller decides the exit code; it is not an
/// alarm-free green).
pub fn rotation_report(state: Option<&RotationState>, now: i64) -> Result<serde_json::Value, WireError> {
    let policy = node_key_rotation_policy();
    let policy_value = serde_json::json!({
        "name": "node_key_annual_rotation",
        "max_age_ms": policy.max_age_ms,
        "max_age_days": NODE_KEY_ANNUAL_MAX_AGE_MS / (24 * 60 * 60 * 1000),
        "criterion": "age",
    });

    let Some(state) = state else {
        return Ok(serde_json::json!({
            "schema": ROTATION_REPORT_SCHEMA,
            "status": "no_state",
            "now": now,
            "note": "no rotation-state file supplied (--rotation-state PATH); alarms need state",
            "node_key_policy": policy_value,
            "alarm_counts": { "critical": 0, "warn": 0, "info": 0 },
            "alarms": [],
            "held": [],
            "event_count": 0,
            "expired_events": 0,
        }));
    };

    let driver = state.driver()?;
    let alarms = driver.alarms(now);
    let critical = alarms
        .iter()
        .filter(|a| a.severity == AlarmSeverity::Critical)
        .count();
    let warn = alarms
        .iter()
        .filter(|a| a.severity == AlarmSeverity::Warn)
        .count();
    let info = alarms
        .iter()
        .filter(|a| a.severity == AlarmSeverity::Info)
        .count();
    let expired_events = state
        .events
        .iter()
        .filter(|e| e.action == RotationAction::Expired)
        .count();

    let held: Vec<serde_json::Value> = state
        .held
        .iter()
        .map(|c| {
            serde_json::json!({
                "subject": c.subject,
                "kind": c.kind,
                "version": c.version,
                "not_before": c.not_before,
                "not_after": c.not_after,
                "reissue_deadline": c.reissue_deadline(),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "schema": ROTATION_REPORT_SCHEMA,
        "status": if critical > 0 { "alarms" } else { "ok" },
        "now": now,
        "node_key_policy": policy_value,
        "alarm_counts": { "critical": critical, "warn": warn, "info": info },
        "alarms": alarms,
        "held": held,
        "event_count": state.events.len(),
        "expired_events": expired_events,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tallow_svid::model::SvidKind;

    const HOUR: i64 = 3600;

    fn cred(subject: &str, version: u64, nb: i64, na: i64) -> HeldCredential {
        HeldCredential::new(subject, SvidKind::WorkloadLeaf, version, nb, na).expect("cred")
    }

    /// Simulated re-issue: successor starts at `now`, same 6 h lifetime.
    fn bump(c: &HeldCredential, now: i64) -> Result<HeldCredential, RotationError> {
        let nb = now.min(c.not_after - 1);
        HeldCredential::new(c.subject.clone(), c.kind, c.version + 1, nb, nb + 6 * HOUR)
    }

    // --- ledger bridge -----------------------------------------------------

    #[test]
    fn rotation_events_bridge_into_ledger_without_reuse_findings() {
        // Subject "a" rotates on time (v1 → v2 at T/2); subject "b" (2 h
        // window) misses its rotation and expires. One tick records both.
        let mut driver = RotationDriver::new(vec![
            cred("a", 1, 0, 6 * HOUR),
            cred("b", 1, 0, 2 * HOUR),
        ])
        .expect("driver");
        let t = 3 * HOUR + 1;
        let actions = driver.tick(t, bump).expect("tick");
        assert_eq!(actions, 2, "b expired + a reissued");

        let mut ledger = KeyUseLedger::new();
        let n = record_rotation_events(&mut ledger, driver.events()).expect("bridge");
        assert_eq!(n, 2);
        // intended rotation must NOT read as reuse
        assert!(ledger.reuse_findings().is_empty(), "rotation ≠ reuse");
        assert!(ledger.check_reuse("svid:a:v2", SVID_ROTATION_CONTEXT).is_ok());
        assert!(ledger.check_reuse("svid:b:v1", SVID_ROTATION_CONTEXT).is_ok());
        // both generations recorded, distinct identities
        assert_eq!(ledger.key_count(), 2);
        // the annual node-key gate is wired to the same model: age-based due list
        let policy = node_key_rotation_policy();
        assert!(
            ledger.rotation_due(&policy, t * 1000 + 1000).is_empty(),
            "fresh keys are not due"
        );
        let far = 366 * 24 * HOUR * 1000;
        let due = ledger.rotation_due(&policy, far);
        assert_eq!(due.len(), 2, "after a year every generation is due: {due:?}");
    }

    #[test]
    fn malformed_reissued_event_is_rejected_and_ledger_untouched() {
        let ev = RotationEvent {
            ts: 10,
            subject: "s".to_string(),
            kind: SvidKind::WorkloadLeaf,
            from_version: 1,
            to_version: None,
            action: RotationAction::Reissued,
            new_not_after: None,
            new_ref: None,
        };
        let mut ledger = KeyUseLedger::new();
        let err = record_rotation_events(&mut ledger, &[ev]).unwrap_err();
        assert!(matches!(err, WireError::MalformedEvent(_)));
        assert!(ledger.is_empty());
    }

    // --- state file --------------------------------------------------------

    #[test]
    fn state_json_round_trips_and_schema_is_checked() {
        let mut driver = RotationDriver::new(vec![cred("s1", 1, 0, 6 * HOUR)]).expect("driver");
        let succ = bump(&driver.held()[0], 3 * HOUR + 1).unwrap();
        driver
            .swap("s1", succ, 3 * HOUR + 1)
            .expect("swap");
        let state = RotationState {
            schema: ROTATION_STATE_SCHEMA.to_string(),
            held: driver.held().to_vec(),
            events: driver.events().to_vec(),
        };
        let json = state.to_json_pretty().expect("ser");
        let back = RotationState::from_json(&json).expect("de");
        assert_eq!(back, state);
        // engine rebuilds from the state
        assert!(back.driver().is_ok());
        // wrong schema refused
        let bad = json.replace(ROTATION_STATE_SCHEMA, "tallow.rotation_state.v999");
        assert!(matches!(RotationState::from_json(&bad), Err(WireError::State(_))));
        // duplicate subjects refused at engine construction
        let dup = RotationState::new(vec![cred("s1", 1, 0, 6 * HOUR), cred("s1", 1, 0, 6 * HOUR)]);
        assert!(matches!(dup.driver(), Err(WireError::Engine(_))));
    }

    // --- doctor report -----------------------------------------------------

    #[test]
    fn report_without_state_is_explicit_no_state_not_green() {
        let report = rotation_report(None, 100).expect("report");
        assert_eq!(report["schema"], ROTATION_REPORT_SCHEMA);
        assert_eq!(report["status"], "no_state");
        assert_eq!(report["alarm_counts"]["critical"], 0);
        assert_eq!(report["held"].as_array().unwrap().len(), 0);
        assert_eq!(report["node_key_policy"]["max_age_days"], 365);
    }

    #[test]
    fn report_surfaces_alarms_and_critical_status() {
        // Held credential expired at 6 h; now = 6 h + 1 ⇒ Critical alarm.
        let state = RotationState::new(vec![cred("dead", 1, 0, 6 * HOUR)]);
        let report = rotation_report(Some(&state), 6 * HOUR + 1).expect("report");
        assert_eq!(report["status"], "alarms");
        assert_eq!(report["alarm_counts"]["critical"], 1);
        let alarms = report["alarms"].as_array().unwrap();
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0]["severity"], "critical");
        assert_eq!(alarms[0]["subject"], "dead");
        // A due-but-live credential at T/2 is a Warn, not Critical.
        let state = RotationState::new(vec![cred("live", 1, 0, 6 * HOUR)]);
        let report = rotation_report(Some(&state), 3 * HOUR).expect("report");
        assert_eq!(report["status"], "ok");
        assert_eq!(report["alarm_counts"]["warn"], 1);
        // event_count reflects the state's history
        let mut st = RotationState::new(vec![cred("live", 1, 0, 6 * HOUR)]);
        st.events.push(RotationEvent {
            ts: 1,
            subject: "live".to_string(),
            kind: SvidKind::WorkloadLeaf,
            from_version: 1,
            to_version: Some(2),
            action: RotationAction::Reissued,
            new_not_after: Some(6 * HOUR + 1),
            new_ref: None,
        });
        let report = rotation_report(Some(&st), 3 * HOUR).expect("report");
        assert_eq!(report["event_count"], 1);
    }
}
