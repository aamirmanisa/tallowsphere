//! Early-warning clock computation (row #179): the statutory notification
//! deadlines a cyber incident starts ticking against, computed locally from
//! one awareness timestamp.
//!
//! Deadlines implemented (each a named constant, no magic numbers):
//!
//! | regime | leg | term | anchor |
//! |---|---|---|---|
//! | CRA (EU 2024/2847, Art. 14) | early warning | 24 h | `agent-09-geopolitics.md:16,90` |
//! | CRA | incident/vulnerability notification | 72 h | idem |
//! | CRA | final report | 14 d (actively exploited vulnerability) / 30 d (severe incident) | idem |
//! | NIS2 (EU 2022/2555, Art. 23) | early warning | 24 h | `agent-09-geopolitics.md:16,90` |
//! | NIS2 | incident notification | 72 h | idem |
//! | NIS2 | final report | 30 d ("one month", modeled as 30 d — stated convention) | idem |
//! | CERT-In (India, 2022 Directions) | report | **6 h** | `agent-09-geopolitics.md:48,90` |
//!
//! Deadline arithmetic is integer-only and injected-clock (`now` is a
//! parameter, never `SystemTime::now()` inside the computation) so a
//! deadline is exactly reproducible — the property the CLI smoke and the
//! conductor battery both depend on.
//!
//! Status rules (fail-closed: every inconsistency is a typed error, never a
//! silent clamp):
//! - `now < awareness_at` → `AwarenessAfterNow` (a clock cannot run before
//!   the event it counts from);
//! - a filed leg that is not applicable to the declared jurisdictions, filed
//!   before awareness, filed twice, or filed in the future → refused;
//! - unfiled: `now > due_at` → `Overdue`; `due_at - now <= term/4` →
//!   `DueSoon`; else `Open`. At exactly `due_at` the leg is still not overdue
//!   (the deadline instant is inclusive).

use serde::{Deserialize, Serialize};

use super::{iso8601_utc, push_field};

/// CRA early-warning term: 24 h.
pub const CRA_EARLY_WARNING_SECS: i64 = 24 * 3600;
/// CRA notification term: 72 h.
pub const CRA_NOTIFICATION_SECS: i64 = 72 * 3600;
/// CRA final report for an actively exploited vulnerability: 14 d.
pub const CRA_FINAL_VULN_SECS: i64 = 14 * 24 * 3600;
/// CRA final report for a severe incident: 30 d.
pub const CRA_FINAL_INCIDENT_SECS: i64 = 30 * 24 * 3600;
/// NIS2 early-warning term: 24 h.
pub const NIS2_EARLY_WARNING_SECS: i64 = 24 * 3600;
/// NIS2 notification term: 72 h.
pub const NIS2_NOTIFICATION_SECS: i64 = 72 * 3600;
/// NIS2 final report term: "one month" modeled as 30 d (stated convention).
pub const NIS2_FINAL_SECS: i64 = 30 * 24 * 3600;
/// CERT-In report term: 6 h from noticing.
pub const CERT_IN_REPORT_SECS: i64 = 6 * 3600;

/// Clock schema id carried by the JSON renderer.
pub const CLOCKS_SCHEMA: &str = "tallow.compliance.clocks.v1";

/// Applicable regulation regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Regime {
    /// EU Cyber Resilience Act.
    Cra,
    /// EU NIS2 Directive.
    Nis2,
    /// India CERT-In Directions.
    CertIn,
}

impl Regime {
    /// Stable lowercase name used in reports and as the CLI/JSON spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Regime::Cra => "cra",
            Regime::Nis2 => "nis2",
            Regime::CertIn => "cert_in",
        }
    }

    /// Parse the canonical spelling; anything else is refused (fail closed
    /// rather than defaulting to a regime that carries criminal-exposure
    /// deadlines for the operator).
    pub fn parse(s: &str) -> Result<Self, ClockError> {
        match s {
            "cra" => Ok(Regime::Cra),
            "nis2" => Ok(Regime::Nis2),
            "cert_in" | "certin" => Ok(Regime::CertIn),
            other => Err(ClockError::UnknownRegime(other.to_string())),
        }
    }
}

/// One notification obligation inside a regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Leg {
    /// 24 h "early warning" (CRA/NIS2).
    EarlyWarning,
    /// 72 h incident/vulnerability notification (CRA/NIS2).
    Notification,
    /// Final report (CRA 14 d/30 d, NIS2 30 d).
    FinalReport,
    /// CERT-In's single 6 h report.
    CertInReport,
}

impl Leg {
    /// Stable lowercase name used in reports and as the CLI/JSON spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Leg::EarlyWarning => "early_warning",
            Leg::Notification => "notification",
            Leg::FinalReport => "final_report",
            Leg::CertInReport => "cert_in_report",
        }
    }

    /// Parse the canonical spelling (accepts the report's own output).
    pub fn parse(s: &str) -> Result<Self, ClockError> {
        match s {
            "early_warning" => Ok(Leg::EarlyWarning),
            "notification" => Ok(Leg::Notification),
            "final_report" => Ok(Leg::FinalReport),
            "cert_in_report" => Ok(Leg::CertInReport),
            other => Err(ClockError::UnknownLeg(other.to_string())),
        }
    }
}

/// What happened — decides which CRA final-report term applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncidentKind {
    /// An actively exploited vulnerability in a product with digital elements.
    ActivelyExploitedVulnerability,
    /// A severe security incident (CRA) / significant incident (NIS2).
    SevereIncident,
}

impl IncidentKind {
    /// Stable spelling (matches the JSON/CLI form).
    pub fn as_str(self) -> &'static str {
        match self {
            IncidentKind::ActivelyExploitedVulnerability => "actively-exploited-vulnerability",
            IncidentKind::SevereIncident => "severe-incident",
        }
    }

    /// Parse the canonical spelling.
    pub fn parse(s: &str) -> Result<Self, ClockError> {
        match s {
            "actively-exploited-vulnerability" => Ok(IncidentKind::ActivelyExploitedVulnerability),
            "severe-incident" => Ok(IncidentKind::SevereIncident),
            other => Err(ClockError::UnknownIncidentKind(other.to_string())),
        }
    }
}

/// Jurisdiction whose regimes apply to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Jurisdiction {
    /// European Union (CRA + NIS2).
    Eu,
    /// India (CERT-In Directions). `in` is the spelling the design uses
    /// (CERT-In); accepted alongside `india`.
    #[serde(alias = "in")]
    India,
}

impl Jurisdiction {
    /// Parse the canonical spelling.
    pub fn parse(s: &str) -> Result<Self, ClockError> {
        match s {
            "eu" => Ok(Jurisdiction::Eu),
            "in" | "india" => Ok(Jurisdiction::India),
            other => Err(ClockError::UnknownJurisdiction(other.to_string())),
        }
    }
}

/// A leg the operator has already filed (the point of the tool is to *meet*
/// deadlines, so filed legs are first-class input, not a status flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiledReport {
    /// Which regime the filing was made under.
    pub regime: Regime,
    /// Which leg was filed.
    pub leg: Leg,
    /// When it was filed (Unix seconds, UTC).
    pub filed_at: i64,
}

/// Input to [`compute`]: one event, one awareness timestamp, the operator's
/// jurisdictions, and any legs already filed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockInput {
    /// When the incident/vulnerability was noticed (Unix seconds).
    pub awareness_at: i64,
    /// What kind of event it is.
    pub kind: IncidentKind,
    /// Jurisdictions declared by the operator (order-insensitive).
    #[serde(default)]
    pub jurisdictions: Vec<Jurisdiction>,
    /// Legs already filed.
    #[serde(default)]
    pub filed: Vec<FiledReport>,
}

/// One computed deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deadline {
    /// Regime the deadline belongs to.
    pub regime: Regime,
    /// Leg within the regime.
    pub leg: Leg,
    /// Statutory term in seconds (the basis of the computation).
    pub term_secs: i64,
    /// `awareness_at + term_secs`.
    pub due_at: i64,
    /// When the leg was filed, if it has been.
    pub filed_at: Option<i64>,
    /// Computed status.
    pub status: LegStatus,
    /// Seconds until `due_at` at evaluation time (negative once overdue).
    pub remaining_secs: i64,
}

/// Status of one leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegStatus {
    /// Not due yet, outside the due-soon window.
    Open,
    /// Not filed, inside the due-soon window (remaining <= term/4).
    DueSoon,
    /// Not filed, `now` is past `due_at`.
    Overdue,
    /// Filed at or before `due_at`.
    MetOnTime,
    /// Filed after `due_at`.
    MetLate,
}

impl LegStatus {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            LegStatus::Open => "open",
            LegStatus::DueSoon => "due_soon",
            LegStatus::Overdue => "overdue",
            LegStatus::MetOnTime => "met_on_time",
            LegStatus::MetLate => "met_late",
        }
    }

    /// True when the leg is unsatisfied at evaluation time.
    pub fn is_unmet(self) -> bool {
        matches!(self, LegStatus::Overdue)
    }
}

/// The computed clock table for one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClockTable {
    /// When the event was noticed.
    pub awareness_at: i64,
    /// Event kind.
    pub kind: IncidentKind,
    /// Evaluation instant the statuses were computed at.
    pub evaluated_at: i64,
    /// Every applicable deadline, earliest first.
    pub deadlines: Vec<Deadline>,
}

impl ClockTable {
    /// Seconds until the next unfiled deadline (`None` when all legs are
    /// filed). Negative when that deadline is already past.
    pub fn seconds_to_next_unfiled(&self) -> Option<i64> {
        self.deadlines
            .iter()
            .filter(|d| d.filed_at.is_none())
            .map(|d| d.remaining_secs)
            .min()
    }

    /// The next unfiled deadline (earliest `due_at`).
    pub fn next_unfiled(&self) -> Option<&Deadline> {
        self.deadlines
            .iter()
            .filter(|d| d.filed_at.is_none())
            .min_by_key(|d| (d.due_at, d.regime, d.leg))
    }

    /// Count of legs with `overdue` status.
    pub fn overdue_count(&self) -> usize {
        self.deadlines
            .iter()
            .filter(|d| d.status.is_unmet())
            .count()
    }

    /// Count of legs filed late.
    pub fn late_count(&self) -> usize {
        self.deadlines
            .iter()
            .filter(|d| d.status == LegStatus::MetLate)
            .count()
    }

    /// Canonical, unambiguous bytes for hashing (fixed field order,
    /// length-prefixed strings) — the report digest basis. Includes
    /// `evaluated_at`: the same input scored at a different instant is a
    /// different report (statuses and remaining windows move with it).
    pub fn canonical_bytes(&self) -> String {
        let mut buf = String::new();
        push_field(&mut buf, CLOCKS_SCHEMA);
        push_field(&mut buf, &self.awareness_at.to_string());
        push_field(&mut buf, &self.evaluated_at.to_string());
        push_field(&mut buf, self.kind.as_str());
        for d in &self.deadlines {
            push_field(&mut buf, d.regime.as_str());
            push_field(&mut buf, d.leg.as_str());
            push_field(&mut buf, &d.term_secs.to_string());
            push_field(&mut buf, &d.due_at.to_string());
            push_field(
                &mut buf,
                &d.filed_at.map(|t| t.to_string()).unwrap_or_default(),
            );
            push_field(&mut buf, d.status.as_str());
        }
        buf
    }

    /// sha256 over [`ClockTable::canonical_bytes`].
    pub fn digest(&self) -> String {
        super::sha256_hex(self.canonical_bytes().as_bytes())
    }

    /// Human/JSON-ready rows.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": CLOCKS_SCHEMA,
            "awareness_at": self.awareness_at,
            "awareness_at_utc": iso8601_utc(self.awareness_at),
            "kind": self.kind.as_str(),
            "evaluated_at": self.evaluated_at,
            "evaluated_at_utc": iso8601_utc(self.evaluated_at),
            "overdue": self.overdue_count(),
            "late": self.late_count(),
            "next_unfiled": self.next_unfiled().map(|d| serde_json::json!({
                "regime": d.regime.as_str(),
                "leg": d.leg.as_str(),
                "due_at": d.due_at,
                "due_at_utc": iso8601_utc(d.due_at),
                "remaining_secs": d.remaining_secs,
                "status": d.status.as_str(),
            })),
            "deadlines": self.deadlines.iter().map(|d| serde_json::json!({
                "regime": d.regime.as_str(),
                "leg": d.leg.as_str(),
                "term_secs": d.term_secs,
                "term": human_term(d.term_secs),
                "due_at": d.due_at,
                "due_at_utc": iso8601_utc(d.due_at),
                "filed_at": d.filed_at,
                "filed_at_utc": d.filed_at.map(iso8601_utc),
                "status": d.status.as_str(),
                "remaining_secs": d.remaining_secs,
            })).collect::<Vec<_>>(),
            "submission": submission_posture(),
            "digest_sha256": self.digest(),
        })
    }

    /// Text rendering used by `--format text`.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "tallow compliance clocks — {} (noticed {} UTC)\n",
            self.kind.as_str(),
            iso8601_utc(self.awareness_at)
        ));
        out.push_str(&format!(
            "evaluated {} UTC · {} deadline(s) · {} overdue · {} filed late\n",
            iso8601_utc(self.evaluated_at),
            self.deadlines.len(),
            self.overdue_count(),
            self.late_count()
        ));
        out.push_str("──────────────────────────────────────────────────────────────\n");
        for d in &self.deadlines {
            out.push_str(&format!(
                "  [{}] {}/{} — {} window · due {} ({} left)\n",
                status_word(d.status),
                d.regime.as_str(),
                d.leg.as_str(),
                human_term(d.term_secs),
                iso8601_utc(d.due_at),
                human_delta(d.remaining_secs),
            ));
            if let Some(filed) = d.filed_at {
                out.push_str(&format!("        filed {} UTC\n", iso8601_utc(filed)));
            }
        }
        out.push_str(&format!(
            "\nlocal-only: {} · digest sha256:{}\n",
            submission_posture()["posture"]
                .as_str()
                .unwrap_or("local_only"),
            self.digest()
        ));
        out
    }
}

fn status_word(status: LegStatus) -> &'static str {
    match status {
        LegStatus::Open => "open",
        LegStatus::DueSoon => "DUE SOON",
        LegStatus::Overdue => "OVERDUE",
        LegStatus::MetOnTime => "met",
        LegStatus::MetLate => "met-late",
    }
}

/// The "no telemetry backdoor" posture block shared by every report
/// (acceptance `final/priority-matrix.md:185`).
pub fn submission_posture() -> serde_json::Value {
    serde_json::json!({
        "posture": "local_only",
        "generated_on_host": true,
        "auto_submitted": false,
        "outbound_network_calls": 0,
        "operator_approval_required": true,
        "operator_approval": "pending",
    })
}

/// `24h`, `6h`, `14d` — human term for report rows. Sub-day and the 24-hour
/// regulatory window stay in hours (that is how the regulations state them);
/// only multi-day terms render as days.
pub fn human_term(secs: i64) -> String {
    if secs % 86_400 == 0 && secs > 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else {
        format!("{secs}s")
    }
}

/// `3h 12m` (sign-carrying) — human remaining/overdue span.
pub fn human_delta(secs: i64) -> String {
    let sign = if secs < 0 { "-" } else { "" };
    let a = secs.abs();
    let (d, h, m) = (a / 86_400, (a % 86_400) / 3600, (a % 3600) / 60);
    if d > 0 {
        format!("{sign}{d}d {h}h")
    } else if h > 0 {
        format!("{sign}{h}h {m}m")
    } else {
        format!("{sign}{m}m")
    }
}

/// Typed refusals. Nothing is clamped or defaulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// `awareness_at` is not a positive Unix timestamp.
    InvalidAwareness(i64),
    /// Evaluation instant precedes awareness.
    AwarenessAfterNow { awareness_at: i64, now: i64 },
    /// Unknown regime spelling.
    UnknownRegime(String),
    /// Unknown leg spelling.
    UnknownLeg(String),
    /// Unknown incident-kind spelling.
    UnknownIncidentKind(String),
    /// Unknown jurisdiction spelling.
    UnknownJurisdiction(String),
    /// A leg was filed twice.
    DuplicateFiled { regime: Regime, leg: Leg },
    /// A leg was filed before the event was noticed.
    FiledBeforeAwareness {
        regime: Regime,
        leg: Leg,
        filed_at: i64,
    },
    /// A filed leg is impossible at the evaluation instant.
    FiledAfterNow {
        regime: Regime,
        leg: Leg,
        filed_at: i64,
        now: i64,
    },
    /// A filed leg does not belong to the declared jurisdictions.
    FiledNotApplicable { regime: Regime, leg: Leg },
    /// No jurisdiction declared — nothing to compute.
    NoJurisdictions,
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClockError::InvalidAwareness(ts) => {
                write!(f, "awareness timestamp {ts} is not a positive Unix timestamp")
            }
            ClockError::AwarenessAfterNow { awareness_at, now } => write!(
                f,
                "awareness {} UTC is after the evaluation instant {} UTC — a clock cannot run \
                 before the event it counts from",
                iso8601_utc(*awareness_at),
                iso8601_utc(*now)
            ),
            ClockError::UnknownRegime(s) => {
                write!(f, "unknown regime {s:?} (expected cra|nis2|cert_in)")
            }
            ClockError::UnknownLeg(s) => write!(
                f,
                "unknown leg {s:?} (expected early_warning|notification|final_report|cert_in_report)"
            ),
            ClockError::UnknownIncidentKind(s) => write!(
                f,
                "unknown incident kind {s:?} (expected actively-exploited-vulnerability|severe-incident)"
            ),
            ClockError::UnknownJurisdiction(s) => {
                write!(f, "unknown jurisdiction {s:?} (expected eu|in)")
            }
            ClockError::DuplicateFiled { regime, leg } => write!(
                f,
                "leg {}/{} was filed twice — pick the operative filing",
                regime.as_str(),
                leg.as_str()
            ),
            ClockError::FiledBeforeAwareness { regime, leg, filed_at } => write!(
                f,
                "leg {}/{} filed {} UTC precedes awareness",
                regime.as_str(),
                leg.as_str(),
                iso8601_utc(*filed_at)
            ),
            ClockError::FiledAfterNow { regime, leg, filed_at, now } => write!(
                f,
                "leg {}/{} filed {} UTC is in the future at evaluation instant {} UTC",
                regime.as_str(),
                leg.as_str(),
                iso8601_utc(*filed_at),
                iso8601_utc(*now)
            ),
            ClockError::FiledNotApplicable { regime, leg } => write!(
                f,
                "leg {}/{} is not applicable to the declared jurisdictions",
                regime.as_str(),
                leg.as_str()
            ),
            ClockError::NoJurisdictions => write!(
                f,
                "no jurisdiction declared — declare eu and/or in to compute clocks"
            ),
        }
    }
}

impl std::error::Error for ClockError {}

/// The deadlines that fire for one event under one set of jurisdictions.
fn applicable_jurisdictions(
    jurisdictions: &[Jurisdiction],
) -> Result<Vec<Jurisdiction>, ClockError> {
    let mut set: Vec<Jurisdiction> = jurisdictions.to_vec();
    set.sort();
    set.dedup();
    if set.is_empty() {
        return Err(ClockError::NoJurisdictions);
    }
    Ok(set)
}

fn legs_for(jurisdiction: Jurisdiction, kind: IncidentKind) -> Vec<(Regime, Leg, i64)> {
    match jurisdiction {
        Jurisdiction::Eu => {
            let final_secs = match kind {
                IncidentKind::ActivelyExploitedVulnerability => CRA_FINAL_VULN_SECS,
                IncidentKind::SevereIncident => CRA_FINAL_INCIDENT_SECS,
            };
            vec![
                (Regime::Cra, Leg::EarlyWarning, CRA_EARLY_WARNING_SECS),
                (Regime::Cra, Leg::Notification, CRA_NOTIFICATION_SECS),
                (Regime::Cra, Leg::FinalReport, final_secs),
                (Regime::Nis2, Leg::EarlyWarning, NIS2_EARLY_WARNING_SECS),
                (Regime::Nis2, Leg::Notification, NIS2_NOTIFICATION_SECS),
                (Regime::Nis2, Leg::FinalReport, NIS2_FINAL_SECS),
            ]
        }
        Jurisdiction::India => vec![(Regime::CertIn, Leg::CertInReport, CERT_IN_REPORT_SECS)],
    }
}

/// Compute the clock table.
///
/// `now` is the evaluation instant (Unix seconds, UTC). All arithmetic is
/// checked; a malformed input is refused with a typed error.
pub fn compute(input: &ClockInput, now: i64) -> Result<ClockTable, ClockError> {
    if input.awareness_at <= 0 {
        return Err(ClockError::InvalidAwareness(input.awareness_at));
    }
    if now < input.awareness_at {
        return Err(ClockError::AwarenessAfterNow {
            awareness_at: input.awareness_at,
            now,
        });
    }
    let jurisdictions = applicable_jurisdictions(&input.jurisdictions)?;

    let mut applicable: Vec<(Regime, Leg, i64)> = Vec::new();
    for j in &jurisdictions {
        for entry in legs_for(*j, input.kind) {
            if !applicable.contains(&entry) {
                applicable.push(entry);
            }
        }
    }

    // Filed legs: uniqueness + plausibility, before any status math.
    let mut seen: Vec<(Regime, Leg)> = Vec::new();
    for f in &input.filed {
        if seen.contains(&(f.regime, f.leg)) {
            return Err(ClockError::DuplicateFiled {
                regime: f.regime,
                leg: f.leg,
            });
        }
        seen.push((f.regime, f.leg));
        if !applicable
            .iter()
            .any(|(r, l, _)| *r == f.regime && *l == f.leg)
        {
            return Err(ClockError::FiledNotApplicable {
                regime: f.regime,
                leg: f.leg,
            });
        }
        if f.filed_at < input.awareness_at {
            return Err(ClockError::FiledBeforeAwareness {
                regime: f.regime,
                leg: f.leg,
                filed_at: f.filed_at,
            });
        }
        if f.filed_at > now {
            return Err(ClockError::FiledAfterNow {
                regime: f.regime,
                leg: f.leg,
                filed_at: f.filed_at,
                now,
            });
        }
    }

    let mut deadlines: Vec<Deadline> = Vec::with_capacity(applicable.len());
    for (regime, leg, term_secs) in applicable {
        let due_at = input
            .awareness_at
            .checked_add(term_secs)
            .ok_or(ClockError::InvalidAwareness(input.awareness_at))?;
        let filed_at = input
            .filed
            .iter()
            .find(|f| f.regime == regime && f.leg == leg)
            .map(|f| f.filed_at);
        let status = match filed_at {
            Some(t) if t <= due_at => LegStatus::MetOnTime,
            Some(_) => LegStatus::MetLate,
            None if now > due_at => LegStatus::Overdue,
            None if due_at - now <= term_secs / 4 => LegStatus::DueSoon,
            None => LegStatus::Open,
        };
        deadlines.push(Deadline {
            regime,
            leg,
            term_secs,
            due_at,
            filed_at,
            status,
            remaining_secs: due_at - now,
        });
    }
    deadlines.sort_by_key(|d| (d.due_at, d.regime, d.leg));

    Ok(ClockTable {
        awareness_at: input.awareness_at,
        kind: input.kind,
        evaluated_at: now,
        deadlines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::parse_timestamp;

    fn t0() -> i64 {
        parse_timestamp("2026-09-14T00:00:00Z").unwrap()
    }

    fn eu_only() -> Vec<Jurisdiction> {
        vec![Jurisdiction::Eu]
    }

    fn full_input() -> ClockInput {
        ClockInput {
            awareness_at: t0(),
            kind: IncidentKind::SevereIncident,
            jurisdictions: vec![Jurisdiction::Eu, Jurisdiction::India],
            filed: Vec::new(),
        }
    }

    #[test]
    fn cert_in_is_the_six_hour_leg_and_is_first() {
        let table = compute(&full_input(), t0() + 60).unwrap();
        let certin = table
            .deadlines
            .iter()
            .find(|d| d.regime == Regime::CertIn)
            .expect("cert-in leg");
        assert_eq!(certin.leg, Leg::CertInReport);
        assert_eq!(certin.term_secs, 6 * 3600);
        assert_eq!(certin.due_at, t0() + 6 * 3600);
        // Sorted earliest-first: the 6 h leg leads.
        assert_eq!(table.deadlines[0].regime, Regime::CertIn);
    }

    #[test]
    fn cra_legs_are_24h_72h_and_30d_for_a_severe_incident() {
        let table = compute(
            &ClockInput {
                jurisdictions: eu_only(),
                ..full_input()
            },
            t0() + 60,
        )
        .unwrap();
        let cra: Vec<&Deadline> = table
            .deadlines
            .iter()
            .filter(|d| d.regime == Regime::Cra)
            .collect();
        assert_eq!(cra.len(), 3);
        assert_eq!(cra[0].due_at, t0() + 24 * 3600);
        assert_eq!(cra[1].due_at, t0() + 72 * 3600);
        assert_eq!(cra[2].due_at, t0() + 30 * 24 * 3600);
    }

    #[test]
    fn cra_final_report_is_14d_for_an_actively_exploited_vulnerability() {
        let table = compute(
            &ClockInput {
                kind: IncidentKind::ActivelyExploitedVulnerability,
                jurisdictions: eu_only(),
                ..full_input()
            },
            t0() + 60,
        )
        .unwrap();
        let final_leg = table
            .deadlines
            .iter()
            .find(|d| d.regime == Regime::Cra && d.leg == Leg::FinalReport)
            .unwrap();
        assert_eq!(final_leg.term_secs, 14 * 24 * 3600);
    }

    #[test]
    fn nis2_adds_its_own_24h_72h_30d_legs() {
        let table = compute(
            &ClockInput {
                jurisdictions: eu_only(),
                ..full_input()
            },
            t0() + 60,
        )
        .unwrap();
        let nis2: Vec<&Deadline> = table
            .deadlines
            .iter()
            .filter(|d| d.regime == Regime::Nis2)
            .collect();
        assert_eq!(nis2.len(), 3);
        assert_eq!(nis2[0].due_at, t0() + 24 * 3600);
        assert_eq!(nis2[1].due_at, t0() + 72 * 3600);
        assert_eq!(nis2[2].due_at, t0() + 30 * 24 * 3600);
    }

    #[test]
    fn status_boundary_at_exactly_the_deadline_is_not_yet_overdue() {
        let input = ClockInput {
            jurisdictions: vec![Jurisdiction::India],
            ..full_input()
        };
        let due = t0() + CERT_IN_REPORT_SECS;
        // One second before: still inside the due-soon window (6 h/4 = 90 m).
        let before = compute(&input, due - 1).unwrap();
        assert_eq!(before.deadlines[0].status, LegStatus::DueSoon);
        // At the deadline instant: inclusive, not overdue.
        let at = compute(&input, due).unwrap();
        assert_eq!(at.deadlines[0].status, LegStatus::DueSoon);
        // One second after: overdue.
        let after = compute(&input, due + 1).unwrap();
        assert_eq!(after.deadlines[0].status, LegStatus::Overdue);
        assert_eq!(after.overdue_count(), 1);
    }

    #[test]
    fn open_due_soon_filed_on_time_and_filed_late_all_reachable() {
        let certin = ClockInput {
            jurisdictions: vec![Jurisdiction::India],
            ..full_input()
        };
        // 4 h in: 2 h left, outside the 90 m due-soon window → open.
        let open_table = compute(&certin, t0() + 4 * 3600).unwrap();
        assert_eq!(open_table.deadlines[0].status, LegStatus::Open);
        // 5 h in: 1 h left, inside the window.
        let soon_table = compute(&certin, t0() + 5 * 3600).unwrap();
        assert_eq!(soon_table.deadlines[0].status, LegStatus::DueSoon);
        let filed_in_time = ClockInput {
            filed: vec![FiledReport {
                regime: Regime::CertIn,
                leg: Leg::CertInReport,
                filed_at: t0() + 5 * 3600,
            }],
            ..certin.clone()
        };
        let table = compute(&filed_in_time, t0() + 7 * 3600).unwrap();
        assert_eq!(table.deadlines[0].status, LegStatus::MetOnTime);
        assert_eq!(table.overdue_count(), 0);
        assert_eq!(table.seconds_to_next_unfiled(), None);

        let filed_late = ClockInput {
            filed: vec![FiledReport {
                regime: Regime::CertIn,
                leg: Leg::CertInReport,
                filed_at: t0() + 7 * 3600,
            }],
            ..certin
        };
        let table = compute(&filed_late, t0() + 8 * 3600).unwrap();
        assert_eq!(table.deadlines[0].status, LegStatus::MetLate);
        assert_eq!(table.late_count(), 1);
        // A late filing is not silently counted as met.
        assert_eq!(table.overdue_count(), 0);
    }

    #[test]
    fn next_unfiled_picks_the_earliest_outstanding_leg_across_regimes() {
        let input = ClockInput {
            filed: vec![FiledReport {
                regime: Regime::CertIn,
                leg: Leg::CertInReport,
                filed_at: t0() + 3600,
            }],
            ..full_input()
        };
        let table = compute(&input, t0() + 2 * 3600).unwrap();
        let next = table.next_unfiled().expect("an unfiled leg remains");
        assert_eq!(next.regime, Regime::Cra);
        assert_eq!(next.leg, Leg::EarlyWarning);
        assert_eq!(table.seconds_to_next_unfiled(), Some(22 * 3600));
        assert_eq!(table.overdue_count(), 0);
    }

    #[test]
    fn duplicates_and_inapplicable_filings_are_refused() {
        let dup = ClockInput {
            filed: vec![
                FiledReport {
                    regime: Regime::CertIn,
                    leg: Leg::CertInReport,
                    filed_at: t0() + 60,
                },
                FiledReport {
                    regime: Regime::CertIn,
                    leg: Leg::CertInReport,
                    filed_at: t0() + 120,
                },
            ],
            ..full_input()
        };
        assert_eq!(
            compute(&dup, t0() + 3600),
            Err(ClockError::DuplicateFiled {
                regime: Regime::CertIn,
                leg: Leg::CertInReport
            })
        );

        let inapplicable = ClockInput {
            jurisdictions: eu_only(),
            filed: vec![FiledReport {
                regime: Regime::CertIn,
                leg: Leg::CertInReport,
                filed_at: t0() + 60,
            }],
            ..full_input()
        };
        assert!(matches!(
            compute(&inapplicable, t0() + 3600),
            Err(ClockError::FiledNotApplicable { .. })
        ));
    }

    #[test]
    fn filed_before_awareness_and_future_filings_are_refused() {
        let early = ClockInput {
            jurisdictions: vec![Jurisdiction::India],
            filed: vec![FiledReport {
                regime: Regime::CertIn,
                leg: Leg::CertInReport,
                filed_at: t0() - 1,
            }],
            ..full_input()
        };
        assert!(matches!(
            compute(&early, t0() + 3600),
            Err(ClockError::FiledBeforeAwareness { .. })
        ));

        let future = ClockInput {
            jurisdictions: vec![Jurisdiction::India],
            filed: vec![FiledReport {
                regime: Regime::CertIn,
                leg: Leg::CertInReport,
                filed_at: t0() + 7200,
            }],
            ..full_input()
        };
        assert!(matches!(
            compute(&future, t0() + 3600),
            Err(ClockError::FiledAfterNow { .. })
        ));
    }

    #[test]
    fn awareness_in_the_future_is_refused() {
        let input = ClockInput {
            jurisdictions: vec![Jurisdiction::India],
            ..full_input()
        };
        assert!(matches!(
            compute(&input, t0() - 1),
            Err(ClockError::AwarenessAfterNow { .. })
        ));
    }

    #[test]
    fn no_jurisdiction_and_bad_spellings_are_refused() {
        let input = ClockInput {
            jurisdictions: Vec::new(),
            ..full_input()
        };
        assert_eq!(compute(&input, t0() + 60), Err(ClockError::NoJurisdictions));
        assert_eq!(
            Regime::parse("gdpr"),
            Err(ClockError::UnknownRegime("gdpr".to_string()))
        );
        assert_eq!(
            Leg::parse("notification_24h"),
            Err(ClockError::UnknownLeg("notification_24h".to_string()))
        );
        assert!(IncidentKind::parse("breach").is_err());
        assert!(Jurisdiction::parse("us").is_err());
        // The parser accepts exactly what the renderer emits.
        for r in [Regime::Cra, Regime::Nis2, Regime::CertIn] {
            assert_eq!(Regime::parse(r.as_str()), Ok(r));
        }
        for l in [
            Leg::EarlyWarning,
            Leg::Notification,
            Leg::FinalReport,
            Leg::CertInReport,
        ] {
            assert_eq!(Leg::parse(l.as_str()), Ok(l));
        }
    }

    #[test]
    fn json_and_text_renders_agree_with_the_table() {
        let table = compute(&full_input(), t0() + 3600).unwrap();
        let json = table.to_json();
        assert_eq!(json["schema"], CLOCKS_SCHEMA);
        assert_eq!(json["deadlines"].as_array().unwrap().len(), 7); // 6 EU legs + 1 CERT-In
        assert_eq!(json["overdue"], 0);
        assert_eq!(json["next_unfiled"]["regime"], "cert_in");
        assert_eq!(json["next_unfiled"]["remaining_secs"], 5 * 3600);
        assert_eq!(json["submission"]["auto_submitted"], false);
        assert_eq!(json["submission"]["outbound_network_calls"], 0);
        assert_eq!(json["digest_sha256"].as_str().unwrap().len(), 64);
        let text = table.render_text();
        assert!(text.contains("cert_in/cert_in_report"));
        assert!(text.contains("local-only"));
        assert!(text.contains("6h"));
    }

    #[test]
    fn digest_is_deterministic_and_sensitive_to_status() {
        let a = compute(&full_input(), t0() + 3600).unwrap();
        let b = compute(&full_input(), t0() + 3600).unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest().len(), 64);
        let different_time = compute(&full_input(), t0() + 7200).unwrap();
        assert_ne!(a.digest(), different_time.digest());
        let with_filing = compute(
            &ClockInput {
                jurisdictions: vec![Jurisdiction::India],
                filed: vec![FiledReport {
                    regime: Regime::CertIn,
                    leg: Leg::CertInReport,
                    filed_at: t0() + 1800,
                }],
                ..full_input()
            },
            t0() + 3600,
        )
        .unwrap();
        assert_ne!(a.digest(), with_filing.digest());
    }

    #[test]
    fn json_input_round_trips_through_serde() {
        let input = full_input();
        let text = serde_json::to_string(&input).unwrap();
        let back: ClockInput = serde_json::from_str(&text).unwrap();
        assert_eq!(input, back);
        // Unknown enum spellings are a deserialization error, not a default.
        assert!(serde_json::from_str::<ClockInput>(
            r#"{"awareness_at":1,"kind":"severe-incident","jurisdictions":["mars"]}"#
        )
        .is_err());
    }

    #[test]
    fn human_terms_and_deltas_render() {
        assert_eq!(human_term(24 * 3600), "24h");
        assert_eq!(human_term(6 * 3600), "6h");
        assert_eq!(human_term(14 * 24 * 3600), "14d");
        assert_eq!(human_delta(3 * 3600 + 12 * 60), "3h 12m");
        assert_eq!(human_delta(-90 * 60), "-1h 30m");
        assert_eq!(human_delta(30), "0m");
    }
}
