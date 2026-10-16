//! SVID rotation driver — R-5.10 (#120): re-issue at T/2 with overlap,
//! atomic swap, ledger-visible events, bounded timer (W3 batch-2 cluster C).
//!
//! The half-life math lives in [`crate::policy::reissue_deadline_secs`] /
//! [`crate::policy::reissue_due`]; **this module is the driver those helpers
//! were documented to feed** (their header names it). It keeps the same two
//! disciplines as the rest of the identity wave:
//!
//! * **Clock-free.** Callers pass `now` (Unix seconds) explicitly; identical
//!   inputs produce identical event sequences. There is no hidden wall clock
//!   and no sleeping — the live daemon timer (stageable; see the lane log) is
//!   the only piece that is not here.
//! * **Bounded.** [`RotationDriver::run_bounded`] refuses to run an unbounded
//!   timer: it replays `[start, end]` at a fixed step with a hard tick cap
//!   ([`MAX_TICKS`]), so a timer bug can never turn into an endless loop.
//!
//! # Rotation contract (report §5.7, design line 188)
//!
//! `workload SVID: re-issue at T/2 (overlap: old valid ≤ T) ─► atomically
//! swap ─► ledger event`
//!
//! * **Re-issue at T/2**: a held credential is *due* from its half-life
//!   instant (`not_before + span/2`, inclusive) until it expires.
//! * **Overlap**: the successor must already be valid at the swap instant and
//!   must overlap the outgoing credential (`successor.not_before <
//!   old.not_after`). During the overlap both certificates verify; the driver
//!   does not require revocation of the old leaf (it expires within one
//!   lifetime by construction).
//! * **Atomic swap**: [`RotationDriver::swap`] replaces the held credential
//!   and appends the event in one call; there is no state in which the driver
//!   holds zero valid credentials for a subject (the successor must be valid
//!   at `now` — future-dated successors are refused).
//! * **Ledger event**: every swap/expiry appends a [`RotationEvent`]. The
//!   root crate bridges these into `key_ledger` key-use records and doctor
//!   alarms (`src/rotation_wire.rs`).
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * Successor validation (in [`RotationDriver::swap`]): same subject and
//!   kind, `version == old.version + 1`, `not_before > old.not_before`
//!   (forward-only: replays of an older window are refused), valid at `now`
//!   (`not_before <= now < not_after`). While the outgoing credential is
//!   still valid, the successor must overlap it (`not_before < old.not_after`);
//!   a successor for an **already-expired** credential is exempt from the
//!   overlap rule (there is nothing left to overlap) but must still be valid
//!   at `now` and forward-only.
//! * An expired credential still in the set is moved to [`expired`] on the
//!   next tick and recorded as an [`RotationAction::Expired`] event —
//!   a *missed rotation* is never silent. Expired entries are reported once.
//! * A tick callback failure aborts that tick (events already appended for
//!   earlier subjects stay; the failing subject stays held for retry).
//! * Alarm severities: `Critical` = expired-while-held (missed rotation);
//!   `Warn` = due (past T/2) but not yet expired; `Info` = approaching
//!   (within the warn window before T/2). Warn window = `span/4` capped at
//!   15 min, never below 1 s (short-lived credentials get short warnings).
//!
//! [`expired`]: RotationDriver::expired

use serde::{Deserialize, Serialize};

use crate::model::SvidKind;
use crate::policy;

/// Hard cap on [`RotationDriver::run_bounded`] ticks (bounded-timer guard).
pub const MAX_TICKS: u64 = 10_000;
/// Warn-window cap in seconds (see edge rules).
pub const WARN_WINDOW_CAP_SECS: i64 = 15 * 60;
/// Domain tag for rotation fingerprints (ledger bridge stability).
pub const ROTATION_DOMAIN: &str = "tallow-svid-rotation-v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed rotation failures. Every refusal is explicit; there is no
/// "best-effort rotation" fallback.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotationError {
    /// A credential had an empty subject.
    #[error("rotation credential subject must be non-empty")]
    EmptySubject,
    /// A credential's version counter must start at 1.
    #[error("rotation credential version must be >= 1 (got {0})")]
    BadVersion(u64),
    /// A credential's window was degenerate (`not_after <= not_before`).
    #[error("degenerate credential window: not_after {not_after} <= not_before {not_before}")]
    DegenerateWindow {
        /// Window start.
        not_before: i64,
        /// Window end.
        not_after: i64,
    },
    /// Two held credentials shared a subject.
    #[error("duplicate held subject {0:?}")]
    DuplicateSubject(String),
    /// The named subject is not held.
    #[error("unknown held subject {0:?}")]
    UnknownSubject(String),
    /// Successor rejected by the swap contract (payload says which rule).
    #[error("invalid rotation successor: {0}")]
    BadSuccession(String),
    /// `run_bounded` would exceed [`MAX_TICKS`] ticks.
    #[error("refusing unbounded timer: {ticks} ticks exceeds cap {MAX_TICKS}")]
    UnboundedTimer {
        /// Tick count the (start, end, step) triple would produce.
        ticks: u64,
    },
    /// `run_bounded` was given a non-positive step.
    #[error("rotation step must be > 0 (got {0})")]
    BadStep(i64),
    /// A tick callback failed.
    #[error("reissue callback failed for {subject:?}: {message}")]
    Reissue {
        /// Subject whose re-issue failed.
        subject: String,
        /// Human-readable cause.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One credential the driver currently holds (a managed identity).
///
/// `subject` is the stable SPIFFE id string (or an equivalent stable name);
/// `version` is the rotation generation, starting at 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldCredential {
    /// Stable subject identity (SPIFFE id string).
    pub subject: String,
    /// Credential kind (TTL band context).
    pub kind: SvidKind,
    /// Rotation generation (1 = first). Successors are +1.
    pub version: u64,
    /// Window start (Unix seconds).
    pub not_before: i64,
    /// Window end (Unix seconds).
    pub not_after: i64,
}

impl HeldCredential {
    /// Build a validated credential.
    pub fn new(
        subject: impl Into<String>,
        kind: SvidKind,
        version: u64,
        not_before: i64,
        not_after: i64,
    ) -> Result<Self, RotationError> {
        let subject = subject.into();
        if subject.trim().is_empty() {
            return Err(RotationError::EmptySubject);
        }
        if version == 0 {
            return Err(RotationError::BadVersion(version));
        }
        if not_after <= not_before {
            return Err(RotationError::DegenerateWindow {
                not_before,
                not_after,
            });
        }
        Ok(Self {
            subject,
            kind,
            version,
            not_before,
            not_after,
        })
    }

    /// Lifetime in seconds (`not_after - not_before`, positive by construction).
    pub fn span_secs(&self) -> i64 {
        self.not_after.saturating_sub(self.not_before)
    }

    /// Re-issue deadline (T/2 after `not_before`); `None` for degenerate
    /// windows (unreachable for validated credentials — kept total).
    pub fn reissue_deadline(&self) -> Option<i64> {
        policy::reissue_deadline_secs(self.not_before, self.not_after)
    }

    /// True when the credential's window covers `now`.
    pub fn valid_at(&self, now: i64) -> bool {
        self.not_before <= now && now < self.not_after
    }

    /// Warn window for this credential: `span/4`, capped at
    /// [`WARN_WINDOW_CAP_SECS`], at least 1 s.
    pub fn warn_window_secs(&self) -> i64 {
        (self.span_secs() / 4).clamp(1, WARN_WINDOW_CAP_SECS)
    }

    /// Ledger fingerprint for this generation (used by the root-crate bridge).
    pub fn fingerprint(&self) -> String {
        format!("{ROTATION_DOMAIN}:{}:v{}", self.subject, self.version)
    }
}

/// Rotation verdict for one credential at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RotationVerdict {
    /// Before the warn window: nothing to do.
    Fresh,
    /// Inside the warn window, before T/2: prepare.
    Approaching {
        /// The T/2 deadline.
        deadline: i64,
    },
    /// At/after T/2, before expiry: **re-issue now** (overlap).
    Due {
        /// The T/2 deadline.
        deadline: i64,
    },
    /// At/after expiry: missed rotation.
    Expired {
        /// When the credential expired.
        expired_at: i64,
    },
}

/// Verdict of one credential at `now` (pure).
pub fn verdict_at(cred: &HeldCredential, now: i64) -> RotationVerdict {
    if now >= cred.not_after {
        return RotationVerdict::Expired {
            expired_at: cred.not_after,
        };
    }
    match cred.reissue_deadline() {
        Some(deadline) if now >= deadline => RotationVerdict::Due { deadline },
        Some(deadline) if now >= deadline.saturating_sub(cred.warn_window_secs()) => {
            RotationVerdict::Approaching { deadline }
        }
        _ => RotationVerdict::Fresh,
    }
}

/// What happened to a credential, as recorded in the event history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationAction {
    /// Re-issued and atomically swapped (successor version recorded).
    Reissued,
    /// Missed rotation: the credential expired while held.
    Expired,
}

/// One rotation event (append-only history record; the ledger-facing artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationEvent {
    /// When the event was recorded (Unix seconds).
    pub ts: i64,
    /// Subject the event concerns.
    pub subject: String,
    /// Credential kind.
    pub kind: SvidKind,
    /// Version the event moved from.
    pub from_version: u64,
    /// Successor version (`Reissued` only).
    pub to_version: Option<u64>,
    /// What happened.
    pub action: RotationAction,
    /// Successor window end (`Reissued` only).
    pub new_not_after: Option<i64>,
    /// Successor serial/ledger reference when the issuer supplied one.
    pub new_ref: Option<String>,
}

/// Alarm severity reported by [`RotationDriver::alarms`] /
/// `tallow doctor --rotation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmSeverity {
    /// Approaching the T/2 deadline.
    Info,
    /// Past T/2, not yet expired: re-issue overdue.
    Warn,
    /// Expired while held: rotation was missed.
    Critical,
}

/// One rotation alarm for an operator surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationAlarm {
    /// Severity.
    pub severity: AlarmSeverity,
    /// Subject concerned.
    pub subject: String,
    /// Credential kind.
    pub kind: SvidKind,
    /// Held generation at alarm time.
    pub version: u64,
    /// The T/2 deadline (when one applies).
    pub due_at: Option<i64>,
    /// When the credential expires (or expired).
    pub expires_at: i64,
    /// Human-readable message.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Rotation driver over a set of held credentials. Clock-free and
/// deterministic; see module docs for the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationDriver {
    /// Currently held credentials, sorted by subject.
    held: Vec<HeldCredential>,
    /// Credentials that expired while held (reported, never silently dropped).
    expired: Vec<HeldCredential>,
    /// Append-only event history.
    events: Vec<RotationEvent>,
}

impl RotationDriver {
    /// Build a driver over `held` (sorted; duplicate subjects refused).
    pub fn new(mut held: Vec<HeldCredential>) -> Result<Self, RotationError> {
        held.sort_by(|a, b| a.subject.cmp(&b.subject));
        for w in held.windows(2) {
            if w[0].subject == w[1].subject {
                return Err(RotationError::DuplicateSubject(w[0].subject.clone()));
            }
        }
        Ok(Self {
            held,
            expired: Vec::new(),
            events: Vec::new(),
        })
    }

    /// Currently held credentials, ascending by subject.
    pub fn held(&self) -> &[HeldCredential] {
        &self.held
    }

    /// Credentials that expired while held.
    pub fn expired(&self) -> &[HeldCredential] {
        &self.expired
    }

    /// Append-only rotation event history.
    pub fn events(&self) -> &[RotationEvent] {
        &self.events
    }

    /// Per-subject verdicts at `now` (ascending by subject).
    pub fn verdicts(&self, now: i64) -> Vec<(String, RotationVerdict)> {
        self.held
            .iter()
            .map(|c| (c.subject.clone(), verdict_at(c, now)))
            .collect()
    }

    /// Subjects due (or past due) for re-issue at `now` (ascending).
    pub fn due(&self, now: i64) -> Vec<String> {
        self.held
            .iter()
            .filter(|c| {
                matches!(
                    verdict_at(c, now),
                    RotationVerdict::Due { .. } | RotationVerdict::Expired { .. }
                )
            })
            .map(|c| c.subject.clone())
            .collect()
    }

    /// Operator alarms at `now` (severity ascending, then subject).
    pub fn alarms(&self, now: i64) -> Vec<RotationAlarm> {
        let mut out = Vec::new();
        for c in &self.held {
            match verdict_at(c, now) {
                RotationVerdict::Fresh => {}
                RotationVerdict::Approaching { deadline } => out.push(RotationAlarm {
                    severity: AlarmSeverity::Info,
                    subject: c.subject.clone(),
                    kind: c.kind,
                    version: c.version,
                    due_at: Some(deadline),
                    expires_at: c.not_after,
                    message: format!(
                        "SVID for {:?} approaches re-issue deadline (T/2 at {deadline})",
                        c.subject
                    ),
                }),
                RotationVerdict::Due { deadline } => out.push(RotationAlarm {
                    severity: AlarmSeverity::Warn,
                    subject: c.subject.clone(),
                    kind: c.kind,
                    version: c.version,
                    due_at: Some(deadline),
                    expires_at: c.not_after,
                    message: format!(
                        "SVID for {:?} is past its T/2 re-issue deadline ({deadline}) and must be rotated",
                        c.subject
                    ),
                }),
                RotationVerdict::Expired { expired_at } => out.push(RotationAlarm {
                    severity: AlarmSeverity::Critical,
                    subject: c.subject.clone(),
                    kind: c.kind,
                    version: c.version,
                    due_at: None,
                    expires_at: expired_at,
                    message: format!(
                        "SVID for {:?} expired at {expired_at} while still held — rotation was missed",
                        c.subject
                    ),
                }),
            }
        }
        for c in &self.expired {
            out.push(RotationAlarm {
                severity: AlarmSeverity::Critical,
                subject: c.subject.clone(),
                kind: c.kind,
                version: c.version,
                due_at: None,
                expires_at: c.not_after,
                message: format!(
                    "SVID for {:?} expired at {} while still held — rotation was missed",
                    c.subject, c.not_after
                ),
            });
        }
        out.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.subject.cmp(&b.subject))
        });
        out
    }

    /// Atomically swap `subject`'s held credential for `successor`, recording
    /// the [`RotationAction::Reissued`] event. See module docs for the exact
    /// successor contract. Returns the recorded event (owned).
    pub fn swap(
        &mut self,
        subject: &str,
        successor: HeldCredential,
        now: i64,
    ) -> Result<RotationEvent, RotationError> {
        self.swap_with_ref(subject, successor, now, None)
    }

    /// [`RotationDriver::swap`] with an issuer-supplied serial/ledger
    /// reference recorded on the event.
    pub fn swap_with_ref(
        &mut self,
        subject: &str,
        successor: HeldCredential,
        now: i64,
        new_ref: Option<String>,
    ) -> Result<RotationEvent, RotationError> {
        let idx = self
            .held
            .iter()
            .position(|c| c.subject == subject)
            .ok_or_else(|| RotationError::UnknownSubject(subject.to_string()))?;
        let old = self.held[idx].clone();

        if successor.subject != old.subject {
            return Err(RotationError::BadSuccession(format!(
                "subject changed: {:?} -> {:?}",
                old.subject, successor.subject
            )));
        }
        if successor.kind != old.kind {
            return Err(RotationError::BadSuccession(format!(
                "kind changed for {:?}",
                old.subject
            )));
        }
        if successor.version != old.version + 1 {
            return Err(RotationError::BadSuccession(format!(
                "version must advance by exactly 1 ({} -> {})",
                old.version, successor.version
            )));
        }
        if successor.not_before <= old.not_before {
            return Err(RotationError::BadSuccession(format!(
                "successor must start after the outgoing window ({:?})",
                old.subject
            )));
        }
        if !successor.valid_at(now) {
            return Err(RotationError::BadSuccession(format!(
                "successor for {:?} must be valid at {now} (window [{}, {}))",
                old.subject, successor.not_before, successor.not_after
            )));
        }
        if now < old.not_after && successor.not_before >= old.not_after {
            return Err(RotationError::BadSuccession(format!(
                "no overlap for {:?}: successor starts at {} >= old expiry {}",
                old.subject, successor.not_before, old.not_after
            )));
        }

        let event = RotationEvent {
            ts: now,
            subject: old.subject.clone(),
            kind: old.kind,
            from_version: old.version,
            to_version: Some(successor.version),
            action: RotationAction::Reissued,
            new_not_after: Some(successor.not_after),
            new_ref,
        };
        self.held[idx] = successor;
        self.events.push(event.clone());
        Ok(event)
    }

    /// One deterministic tick at `now`: re-issue every [`RotationVerdict::Due`]
    /// credential through `reissue`, move every expired credential to
    /// [`RotationDriver::expired`] with an [`RotationAction::Expired`] event.
    ///
    /// The callback receives the outgoing credential and `now`, and returns
    /// the successor (validated by [`RotationDriver::swap`]). Callback
    /// failure aborts the tick (see module docs).
    pub fn tick<F>(&mut self, now: i64, mut reissue: F) -> Result<usize, RotationError>
    where
        F: FnMut(&HeldCredential, i64) -> Result<HeldCredential, RotationError>,
    {
        let mut actions = 0usize;

        // Expiry first (a credential may pass its deadline and expiry within
        // one step: expiry wins, the rotation was missed).
        let mut i = 0;
        while i < self.held.len() {
            if now >= self.held[i].not_after {
                let old = self.held.remove(i);
                self.events.push(RotationEvent {
                    ts: now,
                    subject: old.subject.clone(),
                    kind: old.kind,
                    from_version: old.version,
                    to_version: None,
                    action: RotationAction::Expired,
                    new_not_after: None,
                    new_ref: None,
                });
                self.expired.push(old);
                actions += 1;
            } else {
                i += 1;
            }
        }

        // Re-issue everything due at `now` (subjects ascending — `held` is
        // sorted and stays sorted: `swap` replaces in place).
        let due: Vec<String> = self
            .held
            .iter()
            .filter(|c| matches!(verdict_at(c, now), RotationVerdict::Due { .. }))
            .map(|c| c.subject.clone())
            .collect();
        for subject in due {
            let idx = self
                .held
                .iter()
                .position(|c| c.subject == subject)
                .ok_or_else(|| RotationError::UnknownSubject(subject.clone()))?;
            let old = self.held[idx].clone();
            let successor = reissue(&old, now).map_err(|e| RotationError::Reissue {
                subject: subject.clone(),
                message: e.to_string(),
            })?;
            self.swap(&subject, successor, now)?;
            actions += 1;
        }
        Ok(actions)
    }

    /// Bounded timer replay: run [`RotationDriver::tick`] at every `start + k*step`
    /// instant, inclusive of `end`, with a hard tick cap of [`MAX_TICKS`].
    /// Returns the number of ticks performed.
    pub fn run_bounded<F>(
        &mut self,
        start: i64,
        end: i64,
        step_secs: i64,
        mut reissue: F,
    ) -> Result<u64, RotationError>
    where
        F: FnMut(&HeldCredential, i64) -> Result<HeldCredential, RotationError>,
    {
        if step_secs <= 0 {
            return Err(RotationError::BadStep(step_secs));
        }
        if end < start {
            return Ok(0);
        }
        let ticks = (end - start) as u64 / step_secs as u64 + 1;
        if ticks > MAX_TICKS {
            return Err(RotationError::UnboundedTimer { ticks });
        }
        for k in 0..ticks {
            let now = start.saturating_add((k as i64).saturating_mul(step_secs));
            self.tick(now, &mut reissue)?;
        }
        Ok(ticks)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::NodeIssuer;
    use crate::model::SpiffeId;
    use crate::verify::verify_workload_chain;
    use rcgen::{KeyPair, PKCS_ED25519};

    const HOUR: i64 = 3600;
    /// 6 h workload lifetime ⇒ deadline at +3 h, expiry at +6 h (test scale).
    const SPAN: i64 = 6 * HOUR;

    fn cred(subject: &str, version: u64, nb: i64, na: i64) -> HeldCredential {
        HeldCredential::new(subject, SvidKind::WorkloadLeaf, version, nb, na).expect("cred")
    }

    fn node_cred(subject: &str, version: u64, nb: i64, na: i64) -> HeldCredential {
        HeldCredential::new(subject, SvidKind::NodeIdentity, version, nb, na).expect("cred")
    }

    /// Simulated re-issue: successor starts at `now` (overlap with the old
    /// window), same lifetime.
    fn bump(c: &HeldCredential, now: i64) -> Result<HeldCredential, RotationError> {
        HeldCredential::new(
            c.subject.clone(),
            c.kind,
            c.version + 1,
            now.min(c.not_after - 1),
            now.min(c.not_after - 1) + SPAN,
        )
    }

    // --- construction ------------------------------------------------------

    #[test]
    fn credential_validation_rules() {
        assert_eq!(
            HeldCredential::new("", SvidKind::WorkloadLeaf, 1, 0, 10),
            Err(RotationError::EmptySubject)
        );
        assert_eq!(
            HeldCredential::new("s", SvidKind::WorkloadLeaf, 0, 0, 10),
            Err(RotationError::BadVersion(0))
        );
        assert_eq!(
            HeldCredential::new("s", SvidKind::WorkloadLeaf, 1, 10, 10),
            Err(RotationError::DegenerateWindow {
                not_before: 10,
                not_after: 10
            })
        );
        let c = cred("spiffe://tallow/n1/svc/daemon", 1, 0, SPAN);
        assert_eq!(c.span_secs(), SPAN);
        assert_eq!(c.reissue_deadline(), Some(SPAN / 2));
        assert!(c.valid_at(0) && c.valid_at(SPAN - 1) && !c.valid_at(SPAN));
    }

    #[test]
    fn driver_sorts_and_rejects_duplicates() {
        let d = RotationDriver::new(vec![cred("b", 1, 0, SPAN), cred("a", 1, 0, SPAN)])
            .expect("driver");
        let subjects: Vec<&str> = d.held().iter().map(|c| c.subject.as_str()).collect();
        assert_eq!(subjects, vec!["a", "b"]);
        assert_eq!(
            RotationDriver::new(vec![cred("a", 1, 0, SPAN), cred("a", 1, 0, SPAN)]),
            Err(RotationError::DuplicateSubject("a".to_string()))
        );
    }

    // --- verdicts / alarms -------------------------------------------------

    #[test]
    fn verdict_boundaries_are_inclusive_at_deadline() {
        let c = cred("a", 1, 1_000, 1_000 + SPAN);
        let deadline = 1_000 + SPAN / 2;
        assert_eq!(
            verdict_at(&c, deadline - 1),
            RotationVerdict::Approaching { deadline }
        );
        assert_eq!(verdict_at(&c, deadline), RotationVerdict::Due { deadline });
        assert_eq!(
            verdict_at(&c, 1_000 + SPAN - 1),
            RotationVerdict::Due { deadline }
        );
        assert_eq!(
            verdict_at(&c, 1_000 + SPAN),
            RotationVerdict::Expired {
                expired_at: 1_000 + SPAN
            }
        );
    }

    #[test]
    fn verdict_fresh_outside_warn_window() {
        let c = cred("a", 1, 1_000, 1_000 + SPAN);
        let warn = c.warn_window_secs();
        assert!(warn >= 1 && warn <= WARN_WINDOW_CAP_SECS);
        let deadline = 1_000 + SPAN / 2;
        assert_eq!(verdict_at(&c, deadline - warn - 1), RotationVerdict::Fresh);
    }

    #[test]
    fn warn_window_is_span_quarter_capped() {
        let short = cred("a", 1, 0, 100);
        assert_eq!(short.warn_window_secs(), 25);
        let long = cred("b", 1, 0, 24 * HOUR);
        assert_eq!(long.warn_window_secs(), WARN_WINDOW_CAP_SECS);
        let tiny = cred("c", 1, 0, 2);
        assert_eq!(tiny.warn_window_secs(), 1, "never below 1 s");
    }

    #[test]
    fn alarms_cover_all_three_severities_in_order() {
        // `now = 11_800`: past "due"'s deadline (0 + 6 h/2 = 10_800) but inside
        // "soon"'s warn window (7 h window ⇒ warn = min(span/4, 900 s) = 900 s,
        // so Approaching starts at 12_600 − 900 = 11_700); "fresh" (window
        // starting at SPAN) never alarms.
        let d = RotationDriver::new(vec![
            cred("due", 1, 0, SPAN),
            cred("fresh", 1, SPAN, 2 * SPAN),
            cred("soon", 1, 0, 7 * HOUR),
        ])
        .expect("driver");
        let now = 11_800;
        let alarms = d.alarms(now);
        let by_subject: std::collections::BTreeMap<&str, AlarmSeverity> = alarms
            .iter()
            .map(|a| (a.subject.as_str(), a.severity))
            .collect();
        assert_eq!(by_subject.get("due"), Some(&AlarmSeverity::Warn));
        assert_eq!(by_subject.get("soon"), Some(&AlarmSeverity::Info));
        assert!(by_subject.get("fresh").is_none(), "fresh never alarms");
        // expired must alarm Critical
        let d2 = RotationDriver::new(vec![cred("dead", 1, 0, SPAN)]).expect("driver");
        let alarms2 = d2.alarms(SPAN + 1);
        assert_eq!(alarms2.len(), 1);
        assert_eq!(alarms2[0].severity, AlarmSeverity::Critical);
        assert_eq!(alarms2[0].subject, "dead");
        // ordering: Critical first, then Warn, then Info (severity descending)
        let d3 = RotationDriver::new(vec![
            cred("a-due", 1, 0, SPAN),
            cred("b-info", 1, 0, 7 * HOUR),
        ])
        .expect("driver");
        let alarms3 = d3.alarms(now);
        let got: Vec<(AlarmSeverity, &str)> = alarms3
            .iter()
            .map(|a| (a.severity, a.subject.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (AlarmSeverity::Warn, "a-due"),
                (AlarmSeverity::Info, "b-info")
            ]
        );
    }

    // --- swap contract -----------------------------------------------------

    #[test]
    fn swap_accepts_valid_successor_and_records_event() {
        let mut d = RotationDriver::new(vec![cred("a", 1, 1_000, 1_000 + SPAN)]).expect("driver");
        let deadline = 1_000 + SPAN / 2;
        let successor = cred("a", 2, deadline, deadline + SPAN);
        let ev = d.swap("a", successor.clone(), deadline).expect("swap");
        assert_eq!(ev.action, RotationAction::Reissued);
        assert_eq!(ev.from_version, 1);
        assert_eq!(ev.to_version, Some(2));
        assert_eq!(d.held()[0], successor);
        assert!(d.events().len() == 1);
    }

    #[test]
    fn swap_refusals_are_typed() {
        let base = || RotationDriver::new(vec![cred("a", 1, 1_000, 1_000 + SPAN)]).expect("driver");
        let deadline = 1_000 + SPAN / 2;

        // unknown subject
        assert_eq!(
            base().swap("nope", cred("nope", 2, deadline, deadline + SPAN), deadline),
            Err(RotationError::UnknownSubject("nope".to_string()))
        );
        // version skip
        assert!(matches!(
            base().swap("a", cred("a", 3, deadline, deadline + SPAN), deadline),
            Err(RotationError::BadSuccession(_))
        ));
        // kind change
        assert!(matches!(
            base().swap("a", node_cred("a", 2, deadline, deadline + SPAN), deadline),
            Err(RotationError::BadSuccession(_))
        ));
        // backwards window (replay)
        assert!(matches!(
            base().swap("a", cred("a", 2, 900, 900 + SPAN), deadline),
            Err(RotationError::BadSuccession(_))
        ));
        // not valid yet (future-dated)
        assert!(matches!(
            base().swap(
                "a",
                cred("a", 2, deadline + 10, deadline + 10 + SPAN),
                deadline
            ),
            Err(RotationError::BadSuccession(_))
        ));
        // no overlap while old still valid
        assert!(matches!(
            base().swap("a", cred("a", 2, 1_000 + SPAN, 1_000 + 2 * SPAN), deadline),
            Err(RotationError::BadSuccession(_))
        ));
        // nothing was mutated by refusals
        let d = base();
        assert_eq!(d.held()[0].version, 1);
        assert!(d.events().is_empty());
    }

    #[test]
    fn expired_credential_successor_may_skip_overlap() {
        let mut d = RotationDriver::new(vec![cred("a", 1, 0, SPAN)]).expect("driver");
        let now = SPAN + 60; // already expired
        let successor = cred("a", 2, now, now + SPAN);
        let ev = d.swap("a", successor, now).expect("late rotation accepted");
        assert_eq!(ev.action, RotationAction::Reissued);
    }

    // --- tick / bounded timer ---------------------------------------------

    #[test]
    fn tick_reissues_due_and_expires_missed() {
        let mut d = RotationDriver::new(vec![
            cred("on-time", 1, 0, SPAN),
            cred("second", 1, 0, SPAN),
        ])
        .expect("driver");
        // One tick past T/2: both due → both re-issued.
        let actions = d.tick(SPAN / 2 + 1, bump).expect("tick");
        assert_eq!(actions, 2);
        assert_eq!(d.events().len(), 2);
        // A tick for a missed window: `never-rotated` expires.
        let mut d2 = RotationDriver::new(vec![cred("never", 1, 0, SPAN)]).expect("driver");
        let actions = d2.tick(SPAN + 1, bump).expect("tick");
        assert_eq!(actions, 1, "one expiry action");
        assert!(d2.held().is_empty());
        assert_eq!(d2.expired().len(), 1);
        assert_eq!(d2.events()[0].action, RotationAction::Expired);
        assert!(d2
            .alarms(SPAN + 2)
            .iter()
            .any(|a| a.severity == AlarmSeverity::Critical));
    }

    #[test]
    fn tick_callback_failure_aborts_tick_and_keeps_subject_held() {
        let mut d = RotationDriver::new(vec![cred("a", 1, 0, SPAN), cred("b", 1, 0, SPAN)])
            .expect("driver");
        let err = d
            .tick(SPAN / 2 + 1, |c, _| {
                if c.subject == "b" {
                    Err(RotationError::Reissue {
                        subject: c.subject.clone(),
                        message: "issuer unavailable".to_string(),
                    })
                } else {
                    bump(c, SPAN / 2 + 1)
                }
            })
            .unwrap_err();
        assert!(matches!(err, RotationError::Reissue { .. }));
        // `a` swapped; `b` still held at version 1 for retry.
        let held: Vec<(&str, u64)> = d
            .held()
            .iter()
            .map(|c| (c.subject.as_str(), c.version))
            .collect();
        assert_eq!(held, vec![("a", 2), ("b", 1)]);
    }

    #[test]
    fn run_bounded_replays_deterministically_over_a_horizon() {
        let mk = || RotationDriver::new(vec![cred("a", 1, 0, SPAN)]).expect("driver");
        let mut d1 = mk();
        let ticks1 = d1.run_bounded(0, 24 * HOUR, HOUR, bump).expect("run");
        let mut d2 = mk();
        let ticks2 = d2.run_bounded(0, 24 * HOUR, HOUR, bump).expect("run");
        assert_eq!(ticks1, ticks2);
        assert_eq!(ticks1, 25, "24 h horizon at 1 h step inclusive");
        assert_eq!(
            d1.events(),
            d2.events(),
            "identical inputs → identical events"
        );
        // 8 rotations in 24 h (re-issue at T/2 ⇒ one 6 h lifetime every 3 h).
        assert_eq!(
            d1.events()
                .iter()
                .filter(|e| e.action == RotationAction::Reissued)
                .count(),
            8
        );
        assert!(d1.expired().is_empty());
        assert!(d1.held()[0].valid_at(24 * HOUR));
    }

    #[test]
    fn run_bounded_refuses_unbounded_and_bad_steps() {
        let mut d = RotationDriver::new(vec![cred("a", 1, 0, SPAN)]).expect("driver");
        assert_eq!(
            d.run_bounded(0, i64::MAX / 2, 1, bump),
            Err(RotationError::UnboundedTimer {
                ticks: (i64::MAX / 2) as u64 + 1
            })
        );
        assert_eq!(
            d.run_bounded(0, 10, 0, bump),
            Err(RotationError::BadStep(0))
        );
        assert_eq!(d.run_bounded(10, 0, 1, bump), Ok(0));
        // cap boundary is exercised exactly (MAX_TICKS ticks is allowed)
        let mut d2 = RotationDriver::new(vec![cred("a", 1, 0, SPAN)]).expect("driver");
        let end = (MAX_TICKS as i64 - 1) * 10;
        assert_eq!(d2.run_bounded(0, end, 10, bump), Ok(MAX_TICKS));
    }

    // --- real crypto: re-issue replay validates ---

    #[test]
    fn driver_reissues_real_chains_and_successor_verifies_in_overlap() {
        let mut issuer = NodeIssuer::generate("node-01").expect("issuer");
        issuer
            .issue_issuer_intermediate(None)
            .expect("intermediate");
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("key");
        let spki = key.public_key_der();
        let id = SpiffeId::new("node-01", "job-worker").expect("id");

        // Real-time base: the node/intermediate chain is issued with wall-clock
        // windows (`issue_issuer_intermediate(None)`), so a fake epoch would
        // make the real intermediate NotYetValid at every simulated time.
        let t0 = crate::issuer::now_unix();
        let first = issuer
            .issue_workload_leaf_window(
                crate::issuer::LeafSubject::SpkiDer(&spki),
                &id,
                t0,
                t0 + SPAN,
            )
            .expect("first leaf");
        let held = HeldCredential::new(id.as_str(), SvidKind::WorkloadLeaf, 1, t0, t0 + SPAN)
            .expect("held");
        let mut driver = RotationDriver::new(vec![held]).expect("driver");

        // The callback does the real issuance for the successor window and
        // verifies the chain at `now` (signature, SAN, band, window).
        let deadline = t0 + SPAN / 2;
        let mut issued = 0usize;
        let mut drv_events = Vec::new();
        driver
            .run_bounded(t0, t0 + 2 * SPAN, HOUR, |c, now| {
                let new =
                    HeldCredential::new(c.subject.clone(), c.kind, c.version + 1, now, now + SPAN)?;
                let chain = issuer
                    .issue_workload_leaf_window(
                        crate::issuer::LeafSubject::SpkiDer(&spki),
                        &id,
                        new.not_before,
                        new.not_after,
                    )
                    .map_err(|e| RotationError::Reissue {
                        subject: c.subject.clone(),
                        message: e.to_string(),
                    })?;
                let verified = verify_workload_chain(&chain.chain, &id, now).map_err(|e| {
                    RotationError::Reissue {
                        subject: c.subject.clone(),
                        message: e.to_string(),
                    }
                })?;
                assert_eq!(verified.not_before, now);
                issued += 1;
                Ok(new)
            })
            .expect("bounded run");
        drv_events.extend(driver.events().iter().cloned());

        assert_eq!(issued, 4, "re-issues at 3/6/9/12 h across the 12 h horizon");
        assert_eq!(drv_events.len(), 4);
        assert!(drv_events
            .iter()
            .all(|e| e.action == RotationAction::Reissued));
        assert!(driver.held()[0].version == 5);
        assert!(driver.expired().is_empty());

        // Overlap property holds for the first rotation: at `deadline` both
        // the original and the successor verify.
        let first_ok = verify_workload_chain(&first.chain, &id, deadline);
        assert!(
            first_ok.is_ok(),
            "old leaf still valid at T/2: {first_ok:?}"
        );
    }

    // --- serde -------------------------------------------------------------

    #[test]
    fn serde_round_trip_driver_state() {
        let mut d = RotationDriver::new(vec![cred("a", 1, 0, SPAN)]).expect("driver");
        d.tick(SPAN / 2 + 1, bump).expect("tick");
        let json = serde_json::to_string(&d).expect("ser");
        let back: RotationDriver = serde_json::from_str(&json).expect("de");
        assert_eq!(back, d);
        assert_eq!(back.events(), d.events());
        // verdict/event/alarm types round-trip too
        let v = verdict_at(&d.held()[0], 1);
        let back: RotationVerdict =
            serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(back, v);
        let a = &d.alarms(2 * SPAN)[0];
        let back: RotationAlarm = serde_json::from_str(&serde_json::to_string(a).unwrap()).unwrap();
        assert_eq!(&back, a);
    }

    #[test]
    fn fingerprint_is_generation_exact() {
        let c = cred("spiffe://tallow/n1/svc/daemon", 3, 0, SPAN);
        assert_eq!(
            c.fingerprint(),
            "tallow-svid-rotation-v1:spiffe://tallow/n1/svc/daemon:v3"
        );
    }
}
