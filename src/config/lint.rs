//! KB-7 `tallow config lint` — read-only scoring of the active config against
//! the kernel's hardening baseline (row #66; report §7.3 strict validation,
//! §7.5.1 secure defaults, §7.6.3 operator-gate, §7.7 secrets).
//!
//! The lint pass **never writes**: it loads the artifact through the KB-1
//! loader (so every strict finding is the kernel's own typed diagnostic), then
//! adds baseline findings against the deployed profile posture
//! ([`crate::config::presets`]). Secret handling is metadata-only — `file:`
//! targets are `stat`ed, `env:` names are presence-checked, `vault://` is
//! recognised as the reserved KB-4 seam. **No secret value is ever read,
//! echoed, or fixed by this module** (the loader's own rules refuse literals
//! without echoing them).
//!
//! # Diagnostic codes (KB-7 block, `E7101`+ / `W7101`+; `E7001`–`E7013` belong
//! to the KB-1 kernel, `E6xxx` to the tier gate)
//! | code | severity | meaning |
//! |---|---|---|
//! | `E7101` | error | declared profile's *required* floor is violated (drift) |
//! | `W7101` | warning | no `profile` declared — default-tightest posture applies |
//! | `W7102` | warning | `telemetry = true` (secure default is off, §7.5.1) |
//! | `W7103` | warning | `env:` secret reference (env leaks via `/proc/<pid>/environ`, §7.7) |
//! | `W7104` | warning | `file:` secret target metadata wrong (missing / not a regular file / group-other bits) |
//! | `W7105` | warning | `env:` reference names a variable unset in this environment |
//! | `W7106` | warning | `vault://` reference — resolution is the reserved KB-4 seam (D7) |
//! | `W7107` | warning | configured value relaxes a `GatedDefault` preset floor → operator-gated (§7.6.3) |
//!
//! Zero-trust pack block (row #144, `W7201`–`W7299`): config-surface checks plus
//! a reporting-time *self-assessment* mapped to NCSC's 8 zero-trust design
//! principles, NIST SP 800-207 / SP 800-207A and the Singapore GovZTA pillars.
//! The assessment rows (status per principle + the lint codes that evidence it)
//! ride along in both renderers (`zero_trust` in `--format json`); principles
//! with no config-surface evidence are marked `unsupported` instead of being
//! guessed (see the mapping note
//! `research/tallow-v1/exec/R-08-batch4-C-zerotrust-mapping.md`).
//! | code | severity | meaning |
//! |---|---|---|
//! | `W7201` | warning | declared profile is outside the zero-trust pack's posture floor |
//! | `W7202` | warning | artifact on disk has group/other access (unix metadata) |
//! | `W7203` | warning | `file:` secret target sits in a group/other-writable directory |
//!
//! Secure-by-default pack (row #196, `W7301`–`W7399`): insecure-*default*
//! checks over what the KB-1 artifact can express. `W7301`/`W7302` are pure
//! artifact text analysis — no filesystem access — so they score whether or not
//! metadata probes are enabled; `W7303` needs one `stat` and rides the probe
//! gate like the zero-trust block. No heuristic keyword scanning: every check
//! is a structural fact of the artifact (spec §7.7's own lesson — do not
//! overclaim on keyword heuristics).
//! | code | severity | meaning |
//! |---|---|---|
//! | `W7301` | warning | `file:` secret target is a relative path (resolved from the process CWD) |
//! | `W7302` | warning | `file:` secret target sits directly in a shared scratch root (`/tmp`-class) |
//! | `W7303` | warning | the config artifact's directory is group/other-writable (replaceable posture source) |
//!
//! Exit-code contract (CLI): `0` pass · `1` findings fail (errors, or warnings
//! under `--strict`) · `2` the lint could not run (path/usage errors).

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;

use crate::config::load::ConfigLoad;
use crate::config::presets::{self, FloorKind};
use crate::config::schema::{
    CODE_ARTIFACT, CODE_HISTORY_PATH, CODE_HISTORY_RECORD, CODE_LITERAL_SECRET, CODE_PATH_UNRESOLVED,
    CODE_READ_IO, CODE_SCHEMA_VERSION, CODE_SECRET_RESOLUTION, CODE_TYPE_MISMATCH, CODE_UNKNOWN_KEY,
    CODE_VAULT_SEAM, CODE_WRITE_IO, Config, Profile, SCHEMA_VERSION, SecretRef, SecretSettings,
};

/// Identifier of the baseline table this module scores against (`--format json`
/// carries it; bump when the rule set changes).
pub const BASELINE_ID: &str = "tallow-kernel-baseline-v1";

/// `E7101` — the declared profile's required floor is violated.
pub const CODE_PROFILE_FLOOR: &str = "E7101";
/// `W7101` — no `profile` declared.
pub const CODE_NO_PROFILE: &str = "W7101";
/// `W7102` — telemetry enabled (secure default off).
pub const CODE_TELEMETRY_ON: &str = "W7102";
/// `W7103` — `env:` secret reference.
pub const CODE_ENV_SECRET_REF: &str = "W7103";
/// `W7104` — `file:` secret target metadata is wrong.
pub const CODE_SECRET_TARGET: &str = "W7104";
/// `W7105` — `env:` reference names an unset variable.
pub const CODE_ENV_SECRET_MISSING: &str = "W7105";
/// `W7106` — `vault://` reference (reserved KB-4 seam, D7).
pub const CODE_VAULT_SEAM_REF: &str = "W7106";
/// `W7107` — operator-gated relaxation of a preset default.
pub const CODE_PROFILE_GATED: &str = "W7107";

// ── Zero-trust pack (row #144) ───────────────────────────────────────────────

/// Identifier of the zero-trust pack carried by the self-assessment.
pub const ZT_PACK_ID: &str = "tallow-zero-trust-pack-v1";

/// `W7201` — declared profile is outside the zero-trust pack's posture floor.
pub const CODE_ZT_POSTURE: &str = "W7201";
/// `W7202` — config artifact on disk has group/other access (unix).
pub const CODE_ZT_ARTIFACT_MODE: &str = "W7202";
/// `W7203` — `file:` secret target inside a group/other-writable directory.
pub const CODE_ZT_SECRET_DIR: &str = "W7203";

/// Postures the zero-trust pack accepts as a ZT-compatible declaration.
///
/// `developer`, `performance` and `mobile` are outside the floor: their
/// stances (`presets::PROFILE_POSTURES`) relax diagnostics/hot-reload or
/// egress timeouts, or are speculative placeholders — posture mixes a
/// zero-trust baseline does not accept.
pub const ZT_POSTURE_FLOOR: [Profile; 5] = [
    Profile::Balanced,
    Profile::Privacy,
    Profile::MaximumSecurity,
    Profile::Server,
    Profile::Swarm,
];

// ── Secure-by-default pack (row #196) ────────────────────────────────────────

/// Identifier of the secure-by-default pack carried by the `W73xx` finding
/// codes (allocation block `W7301`–`W7399`; row #196).
pub const SBD_PACK_ID: &str = "tallow-secure-by-default-pack-v1";

/// `W7301` — a `file:` secret target is a relative path.
pub const CODE_SBD_SECRET_RELATIVE: &str = "W7301";
/// `W7302` — a `file:` secret target is a direct member of a shared scratch root.
pub const CODE_SBD_SECRET_SCRATCH: &str = "W7302";
/// `W7303` — the config artifact's directory is group/other-writable.
pub const CODE_SBD_ARTIFACT_DIR: &str = "W7303";

/// Shared scratch roots: locations with world-writable semantics that any
/// local account can write, so a *direct* member is never an
/// operator-controlled secrets location (§7.5.1 "secret files 0600 O_EXCL",
/// §7.7 operator-controlled references). Unix-shaped paths, matched
/// component-wise (`/tmpfoo` is not `/tmp`); `/private/tmp` and
/// `/private/var/tmp` are the macOS spellings of the same two locations.
const SCRATCH_ROOTS: [&str; 5] = [
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/dev/shm",
];

/// Score weights (deterministic; pinned by tests).
const PENALTY_ERROR: u32 = 20;
const PENALTY_WARNING: u32 = 5;
/// Full-marks score.
pub const MAX_SCORE: u32 = 100;

// ── Findings ─────────────────────────────────────────────────────────────────

/// Finding severity. `Error` fails lint even without `--strict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A refusal-class finding (kernel diagnostics, required-floor drift).
    Error,
    /// Drift/advisory (§7.0 posture claims: reported, not refused).
    Warning,
}

impl Severity {
    /// Stable lowercase word.
    pub fn word(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// One lint finding: code, severity, section, key, message, and the fix the
/// operator would apply (`fix` never contains secret material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LintFinding {
    /// Kernel (`E70xx`) or KB-7 (`E71xx`/`W71xx`) code.
    pub code: &'static str,
    /// Severity (drives the exit code).
    pub severity: Severity,
    /// Section the finding is about (`file`/`core`/`secrets`/table name).
    pub section: String,
    /// Dotted key path, when the finding is about one.
    pub key: Option<String>,
    /// What is wrong.
    pub message: String,
    /// Operator fix suggestion.
    pub fix: String,
}

/// Options for a lint run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LintOptions {
    /// Score against this profile's floors as well (`--preset`).
    pub preset: Option<Profile>,
    /// Stat `file:` targets / presence-check `env:` names, and stat the
    /// artifact itself (zero-trust pack `W7202`/`W7203`, secure-by-default pack
    /// `W7303`). Metadata only — values are never read. The static
    /// secure-by-default path-shape checks (`W7301`/`W7302`) do not touch the
    /// filesystem and run regardless of this flag. CLI default `true`; tests
    /// may disable it to stay hermetic.
    pub probe_secret_targets: bool,
    /// Warnings fail the run as well as errors.
    pub strict: bool,
}

impl Default for LintOptions {
    fn default() -> Self {
        LintOptions {
            preset: None,
            probe_secret_targets: true,
            strict: false,
        }
    }
}

/// The lint verdict for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintReport {
    /// Baseline identifier ([`BASELINE_ID`]).
    pub baseline: &'static str,
    /// Artifact path (`None` = in-memory defaults, i.e. no file present).
    pub source: Option<String>,
    /// Effective profile the floors were scored against (declared or `--preset`).
    pub profile: Option<Profile>,
    /// Whether `--strict` was in effect.
    pub strict: bool,
    /// Findings, sorted: errors first, then by code, then by key.
    pub findings: Vec<LintFinding>,
    /// `MAX_SCORE` minus penalties (never negative).
    pub score: u32,
    /// Full-marks score ([`MAX_SCORE`]).
    pub max_score: u32,
    /// Zero-trust self-assessment (row #144). Filled by [`lint`]; a report
    /// built through the private constructor alone carries placeholder rows.
    pub zero_trust: ZeroTrustAssessment,
}

impl LintReport {
    fn new(
        source: Option<String>,
        options: &LintOptions,
        profile: Option<Profile>,
        mut findings: Vec<LintFinding>,
    ) -> Self {
        findings.sort_by(|a, b| {
            (a.severity, a.code, a.key.as_deref(), &a.message).cmp(&(
                b.severity,
                b.code,
                b.key.as_deref(),
                &b.message,
            ))
        });
        let errors = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count() as u32;
        let warnings = findings.len() as u32 - errors;
        let penalty = errors * PENALTY_ERROR + warnings * PENALTY_WARNING;
        LintReport {
            baseline: BASELINE_ID,
            source,
            profile,
            strict: options.strict,
            findings,
            score: MAX_SCORE.saturating_sub(penalty),
            max_score: MAX_SCORE,
            zero_trust: ZeroTrustAssessment::placeholder(),
        }
    }

    /// Error-severity findings.
    pub fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    /// Warning-severity findings.
    pub fn warnings(&self) -> usize {
        self.findings.len() - self.errors()
    }

    /// True when the run passes: no errors, and (unless `--strict`) warnings
    /// do not fail.
    pub fn passed(&self) -> bool {
        self.errors() == 0 && !(self.strict && self.warnings() > 0)
    }

    /// Verdict word (`pass` | `fail`).
    pub fn verdict(&self) -> &'static str {
        if self.passed() {
            "pass"
        } else {
            "fail"
        }
    }

    /// CLI exit code: `0` pass, `1` fail.
    pub fn exit_code(&self) -> i32 {
        if self.passed() {
            0
        } else {
            1
        }
    }

    /// Human-readable report (stable shape; machine consumers should use
    /// [`LintReport::render_json`]).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "tallow config lint — {}\n",
            self.source
                .as_deref()
                .unwrap_or("in-memory defaults (no config file present)")
        ));
        out.push_str(&format!(
            "baseline: {} · profile: {} · strict: {}\n",
            self.baseline,
            self.profile.map(|p| p.word()).unwrap_or("(none declared)"),
            self.strict
        ));
        out.push_str(&format!(
            "score: {}/{} · {} error(s), {} warning(s) · verdict: {}\n",
            self.score,
            self.max_score,
            self.errors(),
            self.warnings(),
            self.verdict()
        ));
        for finding in &self.findings {
            out.push_str(&format!(
                "  {} [{}]{}\n        {}\n        fix: {}\n",
                finding.code,
                finding.section,
                finding
                    .key
                    .as_deref()
                    .map(|k| format!(" `{k}`"))
                    .unwrap_or_default(),
                finding.message,
                finding.fix
            ));
        }
        if self.findings.is_empty() {
            out.push_str("  no findings — config matches the baseline\n");
        } else if !self.strict && self.warnings() > 0 {
            out.push_str("  (warnings do not fail the run; re-run with --strict to make them fail)\n");
        }
        out.push_str(&self.zero_trust.render_rows());
        out
    }

    /// Machine-readable report (stable field names).
    pub fn render_json(&self) -> String {
        let payload = serde_json::json!({
            "baseline": self.baseline,
            "source": self.source,
            "profile": self.profile.map(|p| p.word()),
            "strict": self.strict,
            "score": self.score,
            "max_score": self.max_score,
            "verdict": self.verdict(),
            "passed": self.passed(),
            "errors": self.errors(),
            "warnings": self.warnings(),
            "findings": self.findings,
            "zero_trust": self.zero_trust,
        });
        serde_json::to_string_pretty(&payload)
            .unwrap_or_else(|e| format!("{{\"error\":\"lint report could not be serialized: {e}\"}}"))
    }
}

// ── Zero-trust self-assessment (row #144) ────────────────────────────────────

/// Status of one NCSC principle in the zero-trust self-assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroTrustStatus {
    /// Every mapped check that could be scored passed.
    Covered,
    /// At least one mapped check produced a finding for this artifact.
    Gap,
    /// The principle is wider than the config surface, or checks could not be
    /// scored in this run — the row note says which.
    Partial,
    /// No machine check exists for this principle in the KB-1 config subset.
    Unsupported,
    /// The artifact did not parse — there are no facts to assess.
    NotAssessed,
}

impl ZeroTrustStatus {
    /// Stable lowercase word (also the JSON spelling).
    pub fn word(self) -> &'static str {
        match self {
            ZeroTrustStatus::Covered => "covered",
            ZeroTrustStatus::Gap => "gap",
            ZeroTrustStatus::Partial => "partial",
            ZeroTrustStatus::Unsupported => "unsupported",
            ZeroTrustStatus::NotAssessed => "not_assessed",
        }
    }
}

/// One NCSC-principle row of the zero-trust self-assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZeroTrustRow {
    /// Principle number as spelled by NCSC (`NCSC 1`…`NCSC 8`).
    pub principle: &'static str,
    /// Abbreviated principle title (NCSC wording).
    pub title: &'static str,
    /// Status of this principle for the scored artifact.
    pub status: ZeroTrustStatus,
    /// Lint codes mapped to this principle (each is a machine check).
    pub checks: &'static [&'static str],
    /// NIST cross-reference (SP 800-207 §2.1 tenets / SP 800-207A).
    pub nist: &'static str,
    /// Nearest Singapore GovZTA pillar(s) / enabler(s).
    pub sg: &'static str,
    /// Factual note: fired codes, un-assessable members, or the named gap.
    pub note: String,
}

/// The zero-trust self-assessment carried by every lint report (row #144):
/// one row per NCSC principle, derived from the run's findings — no prose
/// claims, only the checks and their outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZeroTrustAssessment {
    /// Pack identifier ([`ZT_PACK_ID`]).
    pub pack: &'static str,
    /// One row per NCSC principle, in principle order.
    pub rows: Vec<ZeroTrustRow>,
}

impl ZeroTrustAssessment {
    /// Number of rows in `gap` status.
    pub fn gaps(&self) -> usize {
        self.count(ZeroTrustStatus::Gap)
    }

    fn count(&self, status: ZeroTrustStatus) -> usize {
        self.rows.iter().filter(|row| row.status == status).count()
    }

    /// Counts as `(covered, gap, partial, unsupported, not_assessed)`.
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.count(ZeroTrustStatus::Covered),
            self.count(ZeroTrustStatus::Gap),
            self.count(ZeroTrustStatus::Partial),
            self.count(ZeroTrustStatus::Unsupported),
            self.count(ZeroTrustStatus::NotAssessed),
        )
    }

    /// Rows produced before [`lint`] runs: everything is not assessed.
    fn placeholder() -> Self {
        let rows = ZT_PRINCIPLES
            .iter()
            .map(|principle| ZeroTrustRow {
                principle: principle.principle,
                title: principle.title,
                status: ZeroTrustStatus::NotAssessed,
                checks: principle.checks,
                nist: principle.nist,
                sg: principle.sg,
                note: "assessment is computed by `lint` — construct reports through the lint pass"
                    .to_string(),
            })
            .collect();
        ZeroTrustAssessment {
            pack: ZT_PACK_ID,
            rows,
        }
    }

    /// Text block appended to [`LintReport::render_text`].
    pub fn render_rows(&self) -> String {
        let (covered, gaps, partial, unsupported, not_assessed) = self.counts();
        let mut out = String::new();
        out.push_str(&format!(
            "zero-trust self-assessment — {} (NCSC 8 principles · NIST SP 800-207/207A · Singapore GovZTA)\n",
            self.pack
        ));
        for row in &self.rows {
            out.push_str(&format!(
                "  {}  {} — {}\n",
                row.principle,
                row.title,
                row.status.word()
            ));
            if !row.note.is_empty() {
                out.push_str(&format!("        {}\n", row.note));
            }
        }
        out.push_str(&format!(
            "  {covered} covered · {gaps} gap · {partial} partial · {unsupported} unsupported · {not_assessed} not assessed\n"
        ));
        out
    }
}

/// Static per-principle metadata of the pack (see the mapping note for the
/// framework references).
struct ZtPrinciple {
    principle: &'static str,
    title: &'static str,
    checks: &'static [&'static str],
    nist: &'static str,
    sg: &'static str,
}

/// The pack's principle table: NCSC's 8 zero-trust design principles, the
/// config-surface lint checks mapped to each, and the NIST/GovZTA
/// cross-reference. Checks are existing KB-7 codes or the pack's own
/// `W7201`–`W7203`; an empty slice means no config-surface check exists
/// (row status `unsupported`).
const ZT_PRINCIPLES: [ZtPrinciple; 8] = [
    ZtPrinciple {
        principle: "NCSC 1",
        title: "Know your architecture, users, devices, services and data",
        checks: &[
            CODE_ZT_POSTURE,
            CODE_NO_PROFILE,
            CODE_PROFILE_FLOOR,
            CODE_ENV_SECRET_REF,
            CODE_SECRET_TARGET,
            CODE_ENV_SECRET_MISSING,
            CODE_VAULT_SEAM_REF,
        ],
        nist: "SP 800-207 §2.1 tenet 1 (resources), tenet 7 (infrastructure state); SP 800-207A (cloud-native)",
        sg: "GovZTA: Data, Applications & Workloads",
    },
    ZtPrinciple {
        principle: "NCSC 2",
        title: "Know your user, service and device identities",
        checks: &[],
        nist: "SP 800-207 §2.1 tenet 1 (resources), tenet 6 (strictly enforced authn/authz)",
        sg: "GovZTA: Identity, Devices",
    },
    ZtPrinciple {
        principle: "NCSC 3",
        title: "Assess your user behaviour, devices and services",
        checks: &[],
        nist: "SP 800-207 §2.1 tenet 5 (monitor integrity and posture of assets)",
        sg: "GovZTA: Devices",
    },
    ZtPrinciple {
        principle: "NCSC 4",
        title: "Use policies to authorise requests",
        checks: &[CODE_PROFILE_FLOOR, CODE_PROFILE_GATED],
        nist: "SP 800-207 §2.1 tenet 3 (per-session access), tenet 4 (dynamic policy)",
        sg: "GovZTA: Applications & Workloads",
    },
    ZtPrinciple {
        principle: "NCSC 5",
        title: "Authenticate and authorise everywhere",
        checks: &[],
        nist: "SP 800-207 §2.1 tenet 6 (strictly enforced authn/authz), tenet 2 (communication secured)",
        sg: "GovZTA: Identity, Networks",
    },
    ZtPrinciple {
        principle: "NCSC 6",
        title: "Focus your monitoring on users, devices and services",
        checks: &[CODE_TELEMETRY_ON],
        nist: "SP 800-207 §2.1 tenet 5, tenet 7 (infrastructure state)",
        sg: "GovZTA: Visibility & Automation (enabler)",
    },
    ZtPrinciple {
        principle: "NCSC 7",
        title: "Do not trust any network, including your own",
        checks: &[],
        nist: "SP 800-207 §2.1 tenet 2 (no trust from network location)",
        sg: "GovZTA: Networks",
    },
    ZtPrinciple {
        principle: "NCSC 8",
        title: "Choose the safest default when things go wrong",
        checks: &[CODE_ZT_ARTIFACT_MODE, CODE_ZT_SECRET_DIR],
        nist: "SP 800-207 §2.1 tenet 4 (policy strictly enforced)",
        sg: "GovZTA: Data, Applications & Workloads",
    },
];

/// Facts the pack needs from a lint run to score its rows.
#[derive(Debug, Clone, Copy)]
struct ZtFacts {
    /// The artifact parsed (no file-level refusal).
    parsed: bool,
    /// A real artifact path was loaded and inspected.
    on_disk: bool,
    /// A profile is in effect (declared or `--preset`).
    posture: bool,
    /// Filesystem metadata probes ran in this run.
    probes: bool,
}

/// Build the assessment for one run from its findings plus those facts.
fn zero_trust_assessment(facts: ZtFacts, findings: &[LintFinding]) -> ZeroTrustAssessment {
    let fired = |codes: &[&'static str]| -> Vec<&'static str> {
        codes
            .iter()
            .copied()
            .filter(|code| findings.iter().any(|f| f.code == *code))
            .collect()
    };
    let gap_note = |codes: Vec<&'static str>| format!("finding(s): {}", codes.join(", "));
    let mut rows = Vec::with_capacity(ZT_PRINCIPLES.len());
    for (index, principle) in ZT_PRINCIPLES.iter().enumerate() {
        let fired_here = fired(principle.checks);
        let (status, note) = match index {
            // NCSC 1 — posture and data-reference facts are the config surface.
            0 => {
                if !facts.parsed {
                    (
                        ZeroTrustStatus::NotAssessed,
                        "artifact refused — posture/data facts unavailable (kernel is fail-closed)"
                            .to_string(),
                    )
                } else if !fired_here.is_empty() {
                    (ZeroTrustStatus::Gap, gap_note(fired_here))
                } else if !facts.probes {
                    (
                        ZeroTrustStatus::Partial,
                        "secret-reference checks not scored in this run (filesystem probes disabled)"
                            .to_string(),
                    )
                } else {
                    (ZeroTrustStatus::Covered, String::new())
                }
            }
            // NCSC 4 — declared policy: profile floors and gated relaxations.
            3 => {
                if !facts.parsed {
                    (
                        ZeroTrustStatus::NotAssessed,
                        "artifact refused — profile floors not scored".to_string(),
                    )
                } else if !fired_here.is_empty() {
                    (ZeroTrustStatus::Gap, gap_note(fired_here))
                } else if !facts.posture {
                    (
                        ZeroTrustStatus::Partial,
                        "no profile in effect — floors not scored (`W7101`)".to_string(),
                    )
                } else {
                    (ZeroTrustStatus::Covered, String::new())
                }
            }
            // NCSC 6 — only the telemetry stance is config-visible.
            5 => {
                if !facts.parsed {
                    (
                        ZeroTrustStatus::NotAssessed,
                        "artifact refused — no monitoring facts to score".to_string(),
                    )
                } else if !fired_here.is_empty() {
                    (ZeroTrustStatus::Gap, gap_note(fired_here))
                } else {
                    (
                        ZeroTrustStatus::Partial,
                        "only the telemetry stance is config-visible; access-log configuration is \
                         not in the KB-1 subset"
                            .to_string(),
                    )
                }
            }
            // NCSC 8 — safest default: artifact/target protection, fail-closed.
            7 => {
                if !facts.parsed {
                    (
                        ZeroTrustStatus::Covered,
                        "kernel refused the artifact instead of degrading to defaults (fail-closed)"
                            .to_string(),
                    )
                } else if !fired_here.is_empty() {
                    (ZeroTrustStatus::Gap, gap_note(fired_here))
                } else if !facts.probes {
                    (
                        ZeroTrustStatus::Partial,
                        "filesystem probes disabled — artifact/target protection not scored"
                            .to_string(),
                    )
                } else if !facts.on_disk {
                    (
                        ZeroTrustStatus::Partial,
                        "no artifact on disk — artifact-permission check not scored".to_string(),
                    )
                } else {
                    (ZeroTrustStatus::Covered, String::new())
                }
            }
            // Principles with no config-surface evidence.
            _ => (
                ZeroTrustStatus::Unsupported,
                principle_unsupported_note(index).to_string(),
            ),
        };
        rows.push(ZeroTrustRow {
            principle: principle.principle,
            title: principle.title,
            status,
            checks: principle.checks,
            nist: principle.nist,
            sg: principle.sg,
            note,
        });
    }
    ZeroTrustAssessment {
        pack: ZT_PACK_ID,
        rows,
    }
}

/// Why a principle has no config-surface check (row note).
fn principle_unsupported_note(index: usize) -> &'static str {
    match index {
        1 => "identity state is not a config surface (vault/SVID fabric); the config-visible part \
              — `vault://` references — is scored under NCSC 1",
        2 => "behavioural/device-posture signals are not in the KB-1 config subset",
        4 => "daemon/IPC/mesh authentication is not config-visible (`tallow-daemon` auth, \
              `ipc_auth`)",
        6 => "transport/egress policy is not config-visible (`tallow-net` transport policy, Tor \
              stack)",
        _ => "no config-surface evidence",
    }
}

// ── The lint pass ────────────────────────────────────────────────────────────

/// Score one loaded artifact against the baseline. Pure apart from the
/// metadata probes gated by [`LintOptions::probe_secret_targets`]; never
/// writes anything.
pub fn lint(load: &ConfigLoad, options: &LintOptions) -> LintReport {
    let source = load.source().map(|p| p.display().to_string());
    let mut findings: Vec<LintFinding> = Vec::new();

    // 1. The kernel's own diagnostics are findings verbatim: they are typed,
    //    deterministic and never echo secret material.
    for diagnostic in load.diagnostics() {
        findings.push(LintFinding {
            code: diagnostic.code,
            severity: Severity::Error,
            section: diagnostic.section.as_str().to_string(),
            key: diagnostic.key.clone(),
            message: diagnostic.message.clone(),
            fix: fix_for_code(diagnostic.code),
        });
    }

    // A file-level failure means nothing else in the artifact parsed: skip the
    // baseline pass rather than score the in-memory defaults, which would
    // misrepresent the file (present-but-bad ≠ absent, §7.9 rule 1).
    if load.file_error().is_some() {
        let mut report = LintReport::new(source, options, None, findings);
        let assessment = zero_trust_assessment(
            ZtFacts {
                parsed: false,
                on_disk: false,
                posture: false,
                probes: options.probe_secret_targets,
            },
            &report.findings,
        );
        report.zero_trust = assessment;
        return report;
    }

    let core = load.core_result().valid();
    let secrets = load.secrets_result().valid();

    // 2. Profile posture: declared profile plus an explicit `--preset`.
    let declared = core.and_then(|c| c.profile);
    let mut profiles: Vec<Profile> = Vec::new();
    if let Some(preset) = options.preset {
        profiles.push(preset);
    }
    if let Some(declared) = declared {
        if Some(declared) != options.preset {
            profiles.push(declared);
        }
    }
    let effective = options.preset.or(declared);

    let mut floor_covered: BTreeSet<&'static str> = BTreeSet::new();
    if let Some(core) = core {
        if effective.is_none() {
            findings.push(LintFinding {
                code: CODE_NO_PROFILE,
                severity: Severity::Warning,
                section: "core".to_string(),
                key: Some("profile".to_string()),
                message: "no `profile` is declared — the default-tightest posture applies and no \
                          profile floors are scored (§7.2.3: missing declaration stays tightest)"
                    .to_string(),
                fix: "declare a profile (`profile = \"balanced\" | \"privacy\" | \"maximum-security\" | …`) — \
                      see `tallow config presets` for the deployable floor table"
                    .to_string(),
            });
        }

        let cfg = Config::from_sections(core.clone(), secrets.cloned().unwrap_or_default());
        for profile in &profiles {
            for violation in presets::violations(*profile, &cfg) {
                floor_covered.insert(violation.key);
                let (code, severity, fix) = match violation.kind {
                    FloorKind::Required => (
                        CODE_PROFILE_FLOOR,
                        Severity::Error,
                        format!(
                            "set `{} = {}` (tightening is automatic) or drop the profile declaration",
                            violation.key,
                            violation.secure.render()
                        ),
                    ),
                    FloorKind::GatedDefault => (
                        CODE_PROFILE_GATED,
                        Severity::Warning,
                        "operator-gated relaxation (§7.6.3): record the operator authorization, or \
                         restore the preset default"
                            .to_string(),
                    ),
                };
                findings.push(LintFinding {
                    code,
                    severity,
                    section: "core".to_string(),
                    key: Some(violation.key.to_string()),
                    message: violation.message,
                    fix,
                });
            }
        }

        // Zero-trust pack (row #144): the declared posture must sit inside the
        // pack's floor. Scored on the *declared* profile only — `--preset` is a
        // scoring override, not the artifact's posture.
        if let Some(declared) = declared {
            if !ZT_POSTURE_FLOOR.contains(&declared) {
                findings.push(LintFinding {
                    code: CODE_ZT_POSTURE,
                    severity: Severity::Warning,
                    section: "core".to_string(),
                    key: Some("profile".to_string()),
                    message: format!(
                        "declared profile `{}` is outside the zero-trust pack's posture floor \
                         (`balanced`, `privacy`, `maximum-security`, `server`, `swarm`) — its \
                         stance relaxes defaults a ZT baseline keeps tight (§7.2.3)",
                        declared.word()
                    ),
                    fix: "declare a security-leaning profile (e.g. `privacy` or \
                          `maximum-security`), or keep the current profile as a documented, \
                          accepted deviation"
                        .to_string(),
                });
            }
        }

        // Telemetry advisory only when no profile floor already covered it.
        if core.telemetry && !floor_covered.contains("telemetry") {
            findings.push(LintFinding {
                code: CODE_TELEMETRY_ON,
                severity: Severity::Warning,
                section: "core".to_string(),
                key: Some("telemetry".to_string()),
                message: "`telemetry = true` differs from the secure default \
                          (§7.5.1: telemetry is an explicit opt-in, off by default)"
                    .to_string(),
                fix: "set `telemetry = false`, or score under a profile that gates the opt-in \
                      (`tallow config lint --preset performance`)"
                    .to_string(),
            });
        }
    }

    // 2b. Secure-by-default pack (row #196): static secret-path shape checks.
    //     Pure artifact text — no filesystem access — so the probe gate that
    //     guards the metadata checks below does not apply (a `file:` target is
    //     scored whether or not it exists on this host).
    if let Some(secrets) = secrets {
        lint_secret_paths(secrets, &mut findings);
    }

    // 3. Secrets: reference hygiene + metadata probes (never values).
    if options.probe_secret_targets {
        if let Some(secrets) = secrets {
            lint_secrets(secrets, &mut findings);
        }

        // Zero-trust pack (row #144, W7202): the artifact's own on-disk
        // protection — metadata only, same read-only discipline as the
        // secret-target probes.
        if let Some(path) = load.source() {
            if let Some((message, fix)) = artifact_mode_finding(path) {
                findings.push(LintFinding {
                    code: CODE_ZT_ARTIFACT_MODE,
                    severity: Severity::Warning,
                    section: "file".to_string(),
                    key: None,
                    message,
                    fix,
                });
            }
            // Secure-by-default pack (row #196, W7303): the artifact's
            // *directory* protection — 0600 on the file does not protect the
            // path (same reasoning as `W7203` for secret targets).
            if let Some((message, fix)) = artifact_dir_finding(path) {
                findings.push(LintFinding {
                    code: CODE_SBD_ARTIFACT_DIR,
                    severity: Severity::Warning,
                    section: "file".to_string(),
                    key: None,
                    message,
                    fix,
                });
            }
        }
    }

    // Zero-trust pack (row #144): reporting-time self-assessment from the
    // findings above plus the run's facts.
    let mut report = LintReport::new(source, options, effective, findings);
    let assessment = zero_trust_assessment(
        ZtFacts {
            parsed: true,
            on_disk: load.source().is_some(),
            posture: effective.is_some(),
            probes: options.probe_secret_targets,
        },
        &report.findings,
    );
    report.zero_trust = assessment;
    report
}

/// Secret-reference checks. Metadata only: `stat` on `file:` targets, presence
/// check on `env:` names — no value is ever read, and permissions are never
/// modified (unlike the kernel's use-time resolver, lint is read-only).
fn lint_secrets(secrets: &SecretSettings, findings: &mut Vec<LintFinding>) {
    for (name, reference) in &secrets.entries {
        let key = format!("secrets.{name}");
        match reference {
            SecretRef::Env { name: var } => {
                findings.push(LintFinding {
                    code: CODE_ENV_SECRET_REF,
                    severity: Severity::Warning,
                    section: "secrets".to_string(),
                    key: Some(key.clone()),
                    message: format!(
                        "`{key}` resolves `env:{var}` — environment values are readable by \
                         same-user processes (`/proc/<pid>/environ`) and coredumps (§7.7)"
                    ),
                    fix: "prefer `file:/run/secrets/…` (0600, owner-only) or `vault://…` for \
                          daemon-facing secrets"
                        .to_string(),
                });
                if std::env::var_os(var).is_none() {
                    findings.push(LintFinding {
                        code: CODE_ENV_SECRET_MISSING,
                        severity: Severity::Warning,
                        section: "secrets".to_string(),
                        key: Some(key),
                        message: format!(
                            "`env:{var}` is not set in this environment — resolution fails at use \
                             time (hard error, never a silent default)"
                        ),
                        fix: format!(
                            "export `{var}` for the service that consumes this config, or switch \
                             the reference to `file:`/`vault://`"
                        ),
                    });
                }
            }
            SecretRef::File { path } => {
                if let Some((message, fix)) = secret_target_finding(path) {
                    findings.push(LintFinding {
                        code: CODE_SECRET_TARGET,
                        severity: Severity::Warning,
                        section: "secrets".to_string(),
                        key: Some(key.clone()),
                        message,
                        fix,
                    });
                }
                // Zero-trust pack (row #144, W7203): the target's *directory*
                // protection — 0600 on the file does not protect the path.
                if let Some((message, fix)) = secret_dir_finding(path) {
                    findings.push(LintFinding {
                        code: CODE_ZT_SECRET_DIR,
                        severity: Severity::Warning,
                        section: "secrets".to_string(),
                        key: Some(key),
                        message,
                        fix,
                    });
                }
            }
            SecretRef::Vault { uri: _ } => {
                findings.push(LintFinding {
                    code: CODE_VAULT_SEAM_REF,
                    severity: Severity::Warning,
                    section: "secrets".to_string(),
                    key: Some(key),
                    message: "`vault://` resolution is a reserved kernel-internal seam (D7, KB-4): \
                              the reference parses and round-trips, but a consumer resolving it \
                              refuses today (E7011)"
                        .to_string(),
                    fix: "use `env:`/`file:` until KB-4 wires vault resolution, or keep the \
                          reference if the consuming subsystem is not started yet"
                        .to_string(),
                });
            }
        }
    }
}

/// Metadata verdict for one `file:` secret target: `None` = nothing to report.
fn secret_target_finding(path: &Path) -> Option<(String, String)> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            return Some((
                format!(
                    "target `{}` cannot be inspected ({e}) — resolution fails at use time \
                     (hard error, never a silent default)",
                    path.display()
                ),
                format!(
                    "create `{}` as an owner-only (0600) regular file for the consuming service",
                    path.display()
                ),
            ));
        }
    };
    if !meta.file_type().is_file() {
        return Some((
            format!(
                "target `{}` is not a regular file (the resolver refuses symlinks and \
                 directories)",
                path.display()
            ),
            format!("replace `{}` with a regular file (0600)", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some((
                format!(
                    "target `{}` has group/other access (mode {mode:o}) — the resolver tightens it \
                     to 0600 before use; lint is read-only and does not",
                    path.display()
                ),
                format!("chmod 0600 {}", path.display()),
            ));
        }
    }
    None
}

/// On-disk protection of the config artifact itself (zero-trust pack, W7202):
/// `None` = nothing to report. Unix metadata only; a non-file or unreadable
/// source is left to the kernel's own diagnostics.
fn artifact_mode_finding(path: &Path) -> Option<(String, String)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some((
                format!(
                    "artifact `{}` has group/other access (mode {mode:o}) — a local account can \
                     read the declared posture and secret-reference layout; the kernel writes \
                     secret-bearing artifacts 0600 (write policy)",
                    path.display()
                ),
                format!("chmod 0600 {}", path.display()),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    None
}

/// Directory verdict for a `file:` secret target (zero-trust pack, W7203):
/// `None` = nothing to report. A group/other-writable directory lets another
/// local account replace or pre-create the target by name — 0600 on the file
/// does not protect the path.
fn secret_dir_finding(target: &Path) -> Option<(String, String)> {
    let parent = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => return None,
    };
    let meta = std::fs::metadata(parent).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            0o700
        }
    };
    if mode & 0o022 != 0 {
        return Some((
            format!(
                "`file:` target `{}` sits in `{}` (mode {mode:o}) — the directory is writable by \
                 group/other, so another local account can replace or pre-create the target; \
                 0600 on the file does not protect the path",
                target.display(),
                parent.display()
            ),
            format!(
                "move the target into an owner-only directory (0700): `chmod 0700 {}` — or use \
                 an operator-controlled secrets directory (e.g. `/run/secrets`)",
                parent.display()
            ),
        ));
    }
    None
}

/// Static secret-path shape checks (secure-by-default pack, row #196):
/// `W7301` + `W7302` are pure artifact text analysis — no filesystem access —
/// so they run whether or not `LintOptions::probe_secret_targets` is set.
fn lint_secret_paths(secrets: &SecretSettings, findings: &mut Vec<LintFinding>) {
    for (name, reference) in &secrets.entries {
        let SecretRef::File { path } = reference else {
            continue;
        };
        let key = format!("secrets.{name}");
        if !path.is_absolute() {
            findings.push(LintFinding {
                code: CODE_SBD_SECRET_RELATIVE,
                severity: Severity::Warning,
                section: "secrets".to_string(),
                key: Some(key.clone()),
                message: format!(
                    "`{key}` resolves `file:{}` — a relative path: the kernel resolves it from \
                     the process's current working directory, so the secret source is not pinned \
                     by the artifact (whatever directory the process starts in supplies the file)",
                    path.display()
                ),
                fix: "use an absolute path (`file:/run/secrets/…`); `~` is not expanded by the \
                      kernel — a literal relative path is resolved against the CWD"
                    .to_string(),
            });
            continue;
        }
        if let Some(root) = scratch_root_of(path) {
            findings.push(LintFinding {
                code: CODE_SBD_SECRET_SCRATCH,
                severity: Severity::Warning,
                section: "secrets".to_string(),
                key: Some(key.clone()),
                message: format!(
                    "`{key}` resolves `file:{}` — the target sits directly in `{root}`, a shared \
                     scratch location (world-writable, cleared on reboot): a predictable path any \
                     local account can pre-create, not an operator-controlled secrets location \
                     (§7.7). Static check — unlike `W7203` it needs neither an existing target \
                     nor enabled probes",
                    path.display()
                ),
                fix: "move the target into an operator-controlled owner-only directory (0700) — \
                      e.g. `/run/secrets/…`, or an absolute path under the state directory"
                    .to_string(),
            });
        }
    }
}

/// Shared scratch root a `file:` target is a *direct* member of
/// (secure-by-default pack `W7302`): `None` = nothing to report.
///
/// Matched component-wise on the target's parent, so `/tmpfoo` is not `/tmp`.
/// Only direct members (`<root>/name`) are flagged: a 0700 private
/// subdirectory under a scratch root is the standard `mktemp -d` private-
/// scratch pattern, and a genuinely loose intermediate directory is scored by
/// the probe-based `W7203` when it exists on this host.
fn scratch_root_of(path: &Path) -> Option<&'static str> {
    let parent = path.parent()?;
    SCRATCH_ROOTS
        .iter()
        .copied()
        .find(|root| parent == Path::new(root))
}

/// Directory verdict for the config artifact itself (secure-by-default pack,
/// `W7303`): `None` = nothing to report. Mirrors [`secret_dir_finding`] for
/// the artifact's parent — a group/other-writable directory lets another
/// local account replace the artifact by name; `0600` on the file does not
/// protect the path.
fn artifact_dir_finding(path: &Path) -> Option<(String, String)> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => return None,
    };
    let meta = std::fs::metadata(parent).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            0o700
        }
    };
    if mode & 0o022 != 0 {
        return Some((
            format!(
                "artifact `{}` sits in `{}` (mode {mode:o}) — the directory is writable by \
                 group/other, so another local account can replace the config by name; the \
                 loaded posture (profile floors, secret-reference layout) is not protected by \
                 the artifact's own mode",
                path.display(),
                parent.display()
            ),
            format!(
                "chmod 0700 {} — or keep the artifact in an owner-only config directory",
                parent.display()
            ),
        ));
    }
    None
}

/// Operator fix suggestions for the kernel's own codes (KB-1 block).
fn fix_for_code(code: &str) -> String {
    match code {
        CODE_ARTIFACT => {
            "fix the TOML syntax; the kernel refuses a malformed artifact instead of degrading to \
             defaults"
                .to_string()
        }
        CODE_UNKNOWN_KEY => {
            "remove the key or correct the spelling — unknown keys are refused, never ignored"
                .to_string()
        }
        CODE_TYPE_MISMATCH => {
            "use the schema type for the key (`tallow config presets` documents the kernel subset)"
                .to_string()
        }
        CODE_SCHEMA_VERSION => format!(
            "set `schema_version = {SCHEMA_VERSION}` (older versions need a registered migration — \
             KB-3)"
        ),
        CODE_LITERAL_SECRET => {
            "replace the literal with a reference (`env:NAME`, `file:/path`, `vault://…`); config \
             files never store secret values"
                .to_string()
        }
        CODE_READ_IO => "check the path exists and is readable by this user".to_string(),
        CODE_WRITE_IO => {
            "retry once the filesystem issue is resolved; the previous file is left intact"
                .to_string()
        }
        CODE_HISTORY_RECORD | CODE_HISTORY_PATH => {
            "ensure the config-history directory is usable (state dir) — writes are fail-closed on \
             history"
                .to_string()
        }
        CODE_VAULT_SEAM => "use `env:`/`file:` until KB-4 wires vault resolution (D7)".to_string(),
        CODE_PATH_UNRESOLVED => {
            "provide a valid platform config/data directory — the kernel never falls back to `.`"
                .to_string()
        }
        CODE_SECRET_RESOLUTION => {
            "fix the reference target; resolution failures are hard errors".to_string()
        }
        _ => "see the config kernel diagnostics (KB-1) for this code".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load::{load_file, load_from_str};
    use crate::config::test_support::TempDir;

    fn clean_privacy_config(secret_path: &Path) -> String {
        format!(
            "schema_version = 1\nprofile = \"privacy\"\nformat = \"json\"\nno_color = true\n\
             telemetry = false\n\n[secrets]\nkeyfile = \"file:{}\"\n",
            secret_path.display()
        )
    }

    #[cfg(unix)]
    fn make_secret_file(dir: &TempDir, name: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "s3cret-value-not-to-be-read\n").expect("write secret file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set perms");
        path
    }

    #[cfg(not(unix))]
    fn make_secret_file(dir: &TempDir, name: &str, _mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, "s3cret-value-not-to-be-read\n").expect("write secret file");
        path
    }

    #[test]
    fn clean_config_scores_full_marks() {
        let tmp = TempDir::new("lint-clean");
        let secret = make_secret_file(&tmp, "key", 0o600);
        let loaded = load_from_str(&clean_privacy_config(&secret), None);
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            report.findings.is_empty(),
            "clean config must be finding-free: {:?}",
            report.findings
        );
        assert_eq!(report.score, MAX_SCORE);
        assert_eq!(report.verdict(), "pass");
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.errors(), 0);
        assert_eq!(report.warnings(), 0);
    }

    #[test]
    fn absent_file_passes_with_the_no_profile_advisory_and_is_not_created() {
        let tmp = TempDir::new("lint-absent");
        let path = tmp.join("config.toml");
        let loaded = load_file(&path);
        let report = lint(&loaded, &LintOptions::default());
        assert_eq!(report.source, None, "in-memory defaults");
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].code, CODE_NO_PROFILE);
        assert_eq!(report.findings[0].severity, Severity::Warning);
        assert!(report.passed(), "warnings do not fail a non-strict run");
        assert_eq!(report.exit_code(), 0);
        assert!(!path.exists(), "lint never creates a config file");
    }

    #[test]
    fn telemetry_enabled_warns_and_strict_fails_it() {
        let loaded = load_from_str("schema_version = 1\ntelemetry = true\n", None);
        let report = lint(&loaded, &LintOptions::default());
        let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&CODE_TELEMETRY_ON), "{codes:?}");
        assert!(codes.contains(&CODE_NO_PROFILE), "{codes:?}");
        assert_eq!(report.findings.len(), 2, "telemetry + profile advisory");
        assert_eq!(report.score, MAX_SCORE - 2 * PENALTY_WARNING);
        assert!(report.passed());
        assert_eq!(report.exit_code(), 0);

        let strict = lint(
            &loaded,
            &LintOptions {
                strict: true,
                ..LintOptions::default()
            },
        );
        assert!(!strict.passed(), "--strict fails warnings");
        assert_eq!(strict.exit_code(), 1);
    }

    #[test]
    fn declared_profile_floor_violation_is_an_error() {
        let loaded = load_from_str(
            "schema_version = 1\nprofile = \"privacy\"\ntelemetry = true\n",
            None,
        );
        let report = lint(&loaded, &LintOptions::default());
        let floor: Vec<&LintFinding> = report
            .findings
            .iter()
            .filter(|f| f.code == CODE_PROFILE_FLOOR)
            .collect();
        assert_eq!(floor.len(), 1, "{:?}", report.findings);
        assert_eq!(floor[0].severity, Severity::Error);
        assert_eq!(floor[0].key.as_deref(), Some("telemetry"));
        assert!(floor[0].message.contains("`privacy`"), "{}", floor[0].message);
        assert!(floor[0].fix.contains("telemetry = false"), "{}", floor[0].fix);
        // No duplicate telemetry advisory when a floor already covered it.
        assert!(
            !report.findings.iter().any(|f| f.code == CODE_TELEMETRY_ON),
            "{:?}",
            report.findings
        );
        assert_eq!(report.errors(), 1);
        assert!(!report.passed());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn preset_override_scores_against_the_requested_profile() {
        let loaded = load_from_str("schema_version = 1\ntelemetry = true\n", None);
        let report = lint(
            &loaded,
            &LintOptions {
                preset: Some(Profile::MaximumSecurity),
                ..LintOptions::default()
            },
        );
        assert_eq!(report.profile, Some(Profile::MaximumSecurity));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == CODE_PROFILE_FLOOR && f.message.contains("maximum-security")),
            "{:?}",
            report.findings
        );
        assert!(
            !report.findings.iter().any(|f| f.code == CODE_NO_PROFILE),
            "--preset supplies the posture; no advisory"
        );
    }

    #[test]
    fn gated_default_profile_reports_a_gate_not_drift() {
        let loaded = load_from_str(
            "schema_version = 1\nprofile = \"performance\"\ntelemetry = true\n",
            None,
        );
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            report.findings.iter().any(|f| f.code == CODE_PROFILE_GATED),
            "{:?}",
            report.findings
        );
        assert!(
            !report.findings.iter().any(|f| f.code == CODE_PROFILE_FLOOR),
            "performance telemetry is gated, not required: {:?}",
            report.findings
        );
        assert!(report.passed(), "warning severity only");
    }

    #[test]
    fn kernel_diagnostics_become_errors_with_fixes_and_never_echo_values() {
        let text = "schema_version = 1\ntypo_key = true\n[secrets]\napi_key = \"hunter2\"\n";
        let loaded = load_from_str(text, None);
        let report = lint(&loaded, &LintOptions::default());
        let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&CODE_UNKNOWN_KEY), "{codes:?}");
        assert!(codes.contains(&CODE_LITERAL_SECRET), "{codes:?}");
        assert_eq!(report.errors(), 2, "{:?}", report.findings);
        assert_eq!(report.exit_code(), 1);
        for finding in &report.findings {
            assert!(!finding.fix.is_empty(), "{finding:?}");
            assert!(
                !finding.message.contains("hunter2") && !finding.fix.contains("hunter2"),
                "lint must never echo secret material: {finding:?}"
            );
        }
        let rendered = report.render_text();
        assert!(rendered.contains("typo_key"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    #[cfg(unix)]
    fn file_secret_target_metadata_is_checked_read_only() {
        let tmp = TempDir::new("lint-secret-file");
        let loose = make_secret_file(&tmp, "loose", 0o644);
        let missing = tmp.join("missing");
        let text = format!(
            "schema_version = 1\n[secrets]\nloose = \"file:{}\"\nmissing = \"file:{}\"\n",
            loose.display(),
            missing.display()
        );
        let loaded = load_from_str(&text, None);
        let report = lint(&loaded, &LintOptions::default());
        let targets: Vec<&LintFinding> = report
            .findings
            .iter()
            .filter(|f| f.code == CODE_SECRET_TARGET)
            .collect();
        assert_eq!(targets.len(), 2, "loose + missing: {:?}", report.findings);
        assert!(targets.iter().all(|f| f.severity == Severity::Warning));
        assert!(
            report.findings.iter().any(|f| f.code == CODE_NO_PROFILE),
            "fixture declares no profile: {:?}",
            report.findings
        );
        let loose_finding = report
            .findings
            .iter()
            .find(|f| f.key.as_deref() == Some("secrets.loose"))
            .expect("loose finding");
        assert!(loose_finding.message.contains("group/other"), "{loose_finding:?}");
        assert!(loose_finding.fix.contains("chmod 0600"), "{loose_finding:?}");
        // Read-only: lint must NOT tighten the file (the resolver does that at
        // use time, not the scorer).
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&loose)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "lint must not modify the target's permissions");
        // The file contents were never read (the fixture would say so if they
        // were: value appears in no finding).
        let rendered = report.render_json();
        assert!(!rendered.contains("s3cret-value-not-to-be-read"), "{rendered}");
    }

    #[test]
    fn non_regular_secret_target_is_flagged() {
        let tmp = TempDir::new("lint-secret-dir");
        let sub = tmp.join("dir-target");
        std::fs::create_dir(&sub).expect("mkdir");
        let text = format!(
            "schema_version = 1\n[secrets]\nbad = \"file:{}\"\n",
            sub.display()
        );
        let loaded = load_from_str(&text, None);
        let report = lint(&loaded, &LintOptions::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.code == CODE_SECRET_TARGET)
            .expect("target finding");
        assert!(finding.message.contains("not a regular file"), "{finding:?}");
    }

    #[test]
    fn env_and_vault_references_are_flagged() {
        let text = "schema_version = 1\n[secrets]\n\
                    tok = \"env:TALLOW_LINT_DEFINITELY_MISSING_VAR\"\n\
                    vk = \"vault://services/registry/key\"\n";
        let loaded = load_from_str(text, None);
        let report = lint(&loaded, &LintOptions::default());
        let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&CODE_ENV_SECRET_REF), "{codes:?}");
        assert!(codes.contains(&CODE_ENV_SECRET_MISSING), "{codes:?}");
        assert!(codes.contains(&CODE_VAULT_SEAM_REF), "{codes:?}");
        assert_eq!(report.errors(), 0, "all advisory: {:?}", report.findings);
        let vault = report
            .findings
            .iter()
            .find(|f| f.code == CODE_VAULT_SEAM_REF)
            .expect("vault finding");
        assert!(vault.message.contains("KB-4"), "{vault:?}");
    }

    #[test]
    fn set_env_variable_is_not_flagged_as_missing() {
        if std::env::var_os("PATH").is_none() {
            return; // hermetic box without PATH: nothing to assert
        }
        let text = "schema_version = 1\n[secrets]\npath = \"env:PATH\"\n";
        let loaded = load_from_str(text, None);
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            report.findings.iter().any(|f| f.code == CODE_ENV_SECRET_REF),
            "env references are always advisory"
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == CODE_ENV_SECRET_MISSING),
            "PATH is set: no missing-variable finding"
        );
    }

    #[test]
    fn metadata_probes_can_be_disabled_hermetically() {
        let loaded = load_from_str(
            "schema_version = 1\n[secrets]\ntok = \"env:NOPE_MISSING_XYZ\"\n",
            None,
        );
        let report = lint(
            &loaded,
            &LintOptions {
                probe_secret_targets: false,
                ..LintOptions::default()
            },
        );
        assert!(
            !report.findings.iter().any(|f| f.code == CODE_ENV_SECRET_REF),
            "{:?}",
            report.findings
        );
        assert_eq!(report.findings.len(), 1, "profile advisory only");
    }

    #[test]
    fn file_error_skips_the_baseline_pass() {
        let loaded = load_from_str("schema_version = [1,\n", None);
        let report = lint(&loaded, &LintOptions::default());
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].code, CODE_ARTIFACT);
        assert_eq!(report.findings[0].severity, Severity::Error);
        assert_eq!(report.profile, None, "nothing parsed: no posture");
        assert!(!report.passed());
    }

    #[test]
    fn report_is_deterministic_and_errors_sort_first() {
        let text = "schema_version = 1\ntelemetry = true\nprofile = \"privacy\"\n\
                    [secrets]\ntok = \"env:TALLOW_LINT_DETERMINISM_MISSING\"\n";
        let loaded = load_from_str(text, None);
        let a = lint(&loaded, &LintOptions::default());
        let b = lint(&loaded, &LintOptions::default());
        assert_eq!(a.findings, b.findings, "deterministic findings");
        assert_eq!(a.score, b.score);
        let severities: Vec<Severity> = a.findings.iter().map(|f| f.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort();
        assert_eq!(severities, sorted, "errors sort before warnings");
    }

    #[test]
    fn score_arithmetic_is_exact() {
        // 1 error (literal secret) + 1 warning (no profile) → 100 - 20 - 5.
        let loaded = load_from_str(
            "schema_version = 1\n[secrets]\napi_key = \"hunter2\"\n",
            None,
        );
        let report = lint(&loaded, &LintOptions::default());
        assert_eq!(report.errors(), 1);
        assert_eq!(report.warnings(), 1);
        assert_eq!(report.score, MAX_SCORE - PENALTY_ERROR - PENALTY_WARNING);
        // Floor never goes below zero: stack many errors.
        let mut findings = Vec::new();
        for _ in 0..10 {
            findings.push(LintFinding {
                code: CODE_PROFILE_FLOOR,
                severity: Severity::Error,
                section: "core".to_string(),
                key: None,
                message: "x".to_string(),
                fix: "y".to_string(),
            });
        }
        let stacked = LintReport::new(None, &LintOptions::default(), None, findings);
        assert_eq!(stacked.score, 0, "score saturates at zero");
    }

    #[test]
    fn json_report_carries_the_scored_facts() {
        let loaded = load_from_str("schema_version = 1\ntelemetry = true\n", None);
        let report = lint(&loaded, &LintOptions::default());
        let parsed: serde_json::Value =
            serde_json::from_str(&report.render_json()).expect("valid JSON");
        assert_eq!(parsed["baseline"], BASELINE_ID);
        assert_eq!(parsed["verdict"], "pass");
        assert_eq!(parsed["passed"], true);
        assert_eq!(parsed["score"], MAX_SCORE - 2 * PENALTY_WARNING);
        assert_eq!(parsed["warnings"], 2);
        assert_eq!(parsed["findings"].as_array().expect("findings").len(), 2);
        assert_eq!(parsed["findings"][0]["severity"], "warning");
        assert!(
            !parsed["findings"][0]["fix"].as_str().expect("fix").is_empty(),
            "every finding carries a fix"
        );
    }

    #[test]
    fn text_report_shape_is_stable() {
        let loaded = load_from_str("schema_version = 1\ntelemetry = true\n", None);
        let report = lint(&loaded, &LintOptions::default());
        let text = report.render_text();
        assert!(text.contains("tallow config lint —"), "{text}");
        assert!(text.contains(BASELINE_ID), "{text}");
        assert!(text.contains("score:"), "{text}");
        assert!(text.contains("verdict: pass"), "{text}");
        assert!(text.contains("fix:"), "{text}");
        assert!(text.contains("--strict"), "{text}");
    }

    // ── zero-trust pack (row #144) ──────────────────────────────────────────

    #[test]
    fn zero_trust_posture_floor_flags_relaxed_profiles_only() {
        for profile in Profile::ALL {
            let text = format!("schema_version = 1\nprofile = \"{}\"\n", profile.word());
            let loaded = load_from_str(&text, None);
            let report = lint(&loaded, &LintOptions::default());
            let flagged = report.findings.iter().any(|f| f.code == CODE_ZT_POSTURE);
            let in_floor = ZT_POSTURE_FLOOR.contains(&profile);
            assert_eq!(
                flagged, !in_floor,
                "profile `{}`: flagged={flagged}, floor member={in_floor}: {:?}",
                profile.word(),
                report.findings
            );
            if flagged {
                let finding = report
                    .findings
                    .iter()
                    .find(|f| f.code == CODE_ZT_POSTURE)
                    .expect("posture finding");
                assert_eq!(finding.severity, Severity::Warning);
                assert_eq!(finding.key.as_deref(), Some("profile"));
                assert!(finding.message.contains(profile.word()), "{finding:?}");
                assert!(finding.fix.contains("privacy"), "{finding:?}");
                assert!(
                    finding.message.contains("posture floor"),
                    "{finding:?}"
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn zero_trust_artifact_permissions_are_checked_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("zt-artifact");
        let dir = tmp.join("cfg");
        std::fs::create_dir(&dir).expect("mkdir");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "schema_version = 1\nprofile = \"privacy\"\ntelemetry = false\n",
        )
        .expect("write config");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let loaded = load_file(&path);
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == CODE_ZT_ARTIFACT_MODE),
            "0600 artifact must not be flagged: {:?}",
            report.findings
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let loaded = load_file(&path);
        let report = lint(&loaded, &LintOptions::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.code == CODE_ZT_ARTIFACT_MODE)
            .expect("644 artifact finding");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.section, "file");
        assert!(finding.message.contains("group/other"), "{finding:?}");
        assert!(finding.fix.contains("chmod 0600"), "{finding:?}");
        // Read-only: lint must not tighten the artifact either.
        let mode = std::fs::metadata(&path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "lint must not modify the artifact's permissions");
    }

    #[test]
    #[cfg(unix)]
    fn zero_trust_secret_target_directory_is_checked() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("zt-secretdir");
        let safe_dir = tmp.join("safe");
        std::fs::create_dir(&safe_dir).expect("mkdir");
        std::fs::set_permissions(&safe_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let safe = safe_dir.join("key");
        std::fs::write(&safe, "s3cret-value-not-to-be-read\n").expect("write");
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let text = format!(
            "schema_version = 1\n[secrets]\nk = \"file:{}\"\n",
            safe.display()
        );
        let loaded = load_from_str(&text, None);
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            !report.findings.iter().any(|f| f.code == CODE_ZT_SECRET_DIR),
            "0700 target directory must not be flagged: {:?}",
            report.findings
        );

        let loose_dir = tmp.join("loose");
        std::fs::create_dir(&loose_dir).expect("mkdir");
        std::fs::set_permissions(&loose_dir, std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        let loose = loose_dir.join("key");
        std::fs::write(&loose, "s3cret-value-not-to-be-read\n").expect("write");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let text = format!(
            "schema_version = 1\n[secrets]\nk = \"file:{}\"\n",
            loose.display()
        );
        let loaded = load_from_str(&text, None);
        let report = lint(&loaded, &LintOptions::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.code == CODE_ZT_SECRET_DIR)
            .expect("writable-directory finding");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.key.as_deref(), Some("secrets.k"));
        assert!(finding.message.contains("writable by group/other"), "{finding:?}");
        assert!(finding.fix.contains("chmod 0700"), "{finding:?}");
        // The file itself is owner-only: no W7104 for it.
        assert!(
            !report.findings.iter().any(|f| f.code == CODE_SECRET_TARGET),
            "{:?}",
            report.findings
        );
        // Read-only: the directory mode is untouched.
        let mode = std::fs::metadata(&loose_dir)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o777, "lint must not modify the target directory");
    }

    #[test]
    fn zero_trust_assessment_rows_cover_ncsc_principles() {
        // A clean privacy config loaded from a string: no artifact on disk, so
        // the artifact-permission row is partial, not covered.
        let tmp = TempDir::new("zt-assess");
        let secret = make_secret_file(&tmp, "key", 0o600);
        let loaded = load_from_str(&clean_privacy_config(&secret), None);
        let report = lint(&loaded, &LintOptions::default());
        let assessment = &report.zero_trust;
        assert_eq!(assessment.pack, ZT_PACK_ID);
        assert_eq!(assessment.rows.len(), 8);
        assert_eq!(assessment.rows[0].principle, "NCSC 1");
        assert_eq!(assessment.rows[7].principle, "NCSC 8");
        assert_eq!(assessment.rows[0].status, ZeroTrustStatus::Covered);
        assert_eq!(assessment.rows[3].status, ZeroTrustStatus::Covered);
        assert_eq!(assessment.rows[5].status, ZeroTrustStatus::Partial);
        assert_eq!(assessment.rows[7].status, ZeroTrustStatus::Partial);
        for index in [1, 2, 4, 6] {
            assert_eq!(
                assessment.rows[index].status,
                ZeroTrustStatus::Unsupported,
                "row {}: {:?}",
                index,
                assessment.rows[index]
            );
            assert!(assessment.rows[index].checks.is_empty());
        }
        assert_eq!(assessment.gaps(), 0, "{:?}", assessment.rows);
        assert_eq!(assessment.counts(), (2, 0, 2, 4, 0));

        // The same clean config on disk (0600) closes the artifact row.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp.join("config.toml");
            std::fs::write(&path, clean_privacy_config(&secret)).expect("write config");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            let loaded = load_file(&path);
            let report = lint(&loaded, &LintOptions::default());
            assert_eq!(report.zero_trust.rows[7].status, ZeroTrustStatus::Covered);
            assert_eq!(report.zero_trust.counts(), (3, 0, 1, 4, 0));
        }

        // A relaxed posture + no secrets is a gap on NCSC 1.
        let loaded = load_from_str("schema_version = 1\nprofile = \"developer\"\n", None);
        let report = lint(&loaded, &LintOptions::default());
        assert_eq!(report.zero_trust.rows[0].status, ZeroTrustStatus::Gap);
        assert!(
            report.zero_trust.rows[0].note.contains(CODE_ZT_POSTURE),
            "{:?}",
            report.zero_trust.rows[0]
        );
        assert_eq!(report.zero_trust.gaps(), 1);

        // A refused artifact is fail-closed: no facts, but the default row
        // reports the refusal instead of a gap.
        let loaded = load_from_str("schema_version = [1,\n", None);
        let report = lint(&loaded, &LintOptions::default());
        assert_eq!(report.zero_trust.rows[0].status, ZeroTrustStatus::NotAssessed);
        assert_eq!(report.zero_trust.rows[7].status, ZeroTrustStatus::Covered);
        assert!(
            report.zero_trust.rows[7].note.contains("fail-closed"),
            "{:?}",
            report.zero_trust.rows[7]
        );
    }

    #[test]
    fn zero_trust_assessment_is_rendered_in_both_formats() {
        let loaded = load_from_str("schema_version = 1\ntelemetry = true\n", None);
        let report = lint(&loaded, &LintOptions::default());
        let json = report.render_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["zero_trust"]["pack"], ZT_PACK_ID);
        let rows = parsed["zero_trust"]["rows"].as_array().expect("rows");
        assert_eq!(rows.len(), 8);
        assert_eq!(rows[0]["principle"], "NCSC 1");
        assert_eq!(rows[0]["status"], "gap", "{json}");
        assert!(rows[0]["note"].as_str().expect("note").contains("W7101"));
        assert!(
            rows[0]["checks"]
                .as_array()
                .expect("checks")
                .iter()
                .any(|c| c == CODE_ZT_POSTURE),
            "{json}"
        );
        assert_eq!(rows[5]["status"], "gap", "{json}");
        assert!(rows[5]["note"].as_str().expect("note").contains("W7102"));
        assert_eq!(rows[1]["status"], "unsupported");
        // The pack adds no findings to this fixture (telemetry + profile
        // advisory only): the assessment is derived, not duplicated.
        assert_eq!(parsed["findings"].as_array().expect("findings").len(), 2);

        let text = report.render_text();
        assert!(text.contains("zero-trust self-assessment"), "{text}");
        assert!(text.contains(ZT_PACK_ID), "{text}");
        assert!(text.contains("NCSC 8"), "{text}");
        assert!(text.contains("unsupported"), "{text}");
    }

    // ── secure-by-default pack (row #196) ───────────────────────────────────

    #[test]
    fn sbd_relative_secret_path_fires_and_absolute_is_silent() {
        // Fires on the insecure default: a relative `file:` reference — the
        // secret source is whatever directory the process happens to start in.
        let loaded = load_from_str(
            "schema_version = 1\nprofile = \"privacy\"\n[secrets]\ntok = \"file:secrets/token\"\n",
            None,
        );
        let report = lint(&loaded, &LintOptions::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.code == CODE_SBD_SECRET_RELATIVE)
            .unwrap_or_else(|| panic!("relative-path finding: {:?}", report.findings));
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.section, "secrets");
        assert_eq!(finding.key.as_deref(), Some("secrets.tok"));
        assert!(finding.message.contains("relative"), "{finding:?}");
        assert!(finding.message.contains("working directory"), "{finding:?}");
        assert!(finding.fix.contains("absolute"), "{finding:?}");

        // Silent on the secure form: an absolute, owner-only target.
        let tmp = TempDir::new("sbd-abs");
        let secret = make_secret_file(&tmp, "key", 0o600);
        let loaded = load_from_str(
            &format!(
                "schema_version = 1\nprofile = \"privacy\"\n[secrets]\ntok = \"file:{}\"\n",
                secret.display()
            ),
            None,
        );
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == CODE_SBD_SECRET_RELATIVE),
            "{:?}",
            report.findings
        );

        // env:/vault:// refs carry no path: never flagged by this check.
        let loaded = load_from_str(
            "schema_version = 1\n[secrets]\ne = \"env:SBD_TEST_VAR\"\nv = \"vault://x/y\"\n",
            None,
        );
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == CODE_SBD_SECRET_RELATIVE),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn sbd_scratch_root_members_fire_and_static_checks_ignore_the_probe_gate() {
        // Probes disabled on purpose: W7301/W7302 are pure artifact text and
        // must score anyway (a `file:` target needs neither to exist nor to be
        // stat-ed).
        let options = LintOptions {
            probe_secret_targets: false,
            ..LintOptions::default()
        };
        for root in SCRATCH_ROOTS {
            let text = format!(
                "schema_version = 1\nprofile = \"privacy\"\n[secrets]\nk = \"file:{root}/key\"\n"
            );
            let loaded = load_from_str(&text, None);
            let report = lint(&loaded, &options);
            let finding = report
                .findings
                .iter()
                .find(|f| f.code == CODE_SBD_SECRET_SCRATCH)
                .unwrap_or_else(|| panic!("`{root}` must be flagged: {:?}", report.findings));
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.section, "secrets");
            assert_eq!(finding.key.as_deref(), Some("secrets.k"));
            assert!(finding.message.contains(root), "{finding:?}");
            assert_eq!(
                report.findings.len(),
                1,
                "static check only for `{root}`: {:?}",
                report.findings
            );
        }

        // Silent on secure locations, on scratch *descendants* (a 0700 private
        // subdirectory is the mktemp pattern; loose intermediate dirs are
        // W7203's job), and across component boundaries (`/tmpfoo` ≠ `/tmp`).
        for safe in [
            "/run/secrets/k",
            "/etc/tallow/key",
            "/tmp/tallow-private-0700/key",
            "/tmpfoo/key",
            "/var/tmpfoo/key",
        ] {
            let text = format!(
                "schema_version = 1\nprofile = \"privacy\"\n[secrets]\nk = \"file:{safe}\"\n"
            );
            let loaded = load_from_str(&text, None);
            let report = lint(&loaded, &options);
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|f| f.code == CODE_SBD_SECRET_SCRATCH),
                "`{safe}` must not be flagged: {:?}",
                report.findings
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn sbd_artifact_directory_is_checked_probe_gated_and_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("sbd-artdir");
        let dir = tmp.join("cfg");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "schema_version = 1\nprofile = \"privacy\"\ntelemetry = false\n",
        )
        .expect("write config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        // Secure: owner-only directory (artifact also owner-only) → silent.
        let loaded = load_file(&path);
        let report = lint(&loaded, &LintOptions::default());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == CODE_SBD_ARTIFACT_DIR),
            "{:?}",
            report.findings
        );

        // Insecure: group/other-writable directory → flagged.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let loaded = load_file(&path);
        let report = lint(&loaded, &LintOptions::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.code == CODE_SBD_ARTIFACT_DIR)
            .unwrap_or_else(|| panic!("writable-directory finding: {:?}", report.findings));
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.section, "file");
        assert!(
            finding.message.contains("writable by group/other"),
            "{finding:?}"
        );
        assert!(finding.fix.contains("chmod 0700"), "{finding:?}");

        // Probe-gated: with metadata probes disabled the directory is not
        // inspected (same discipline as W7202/W7203).
        let loaded = load_file(&path);
        let report = lint(
            &loaded,
            &LintOptions {
                probe_secret_targets: false,
                ..LintOptions::default()
            },
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.code == CODE_SBD_ARTIFACT_DIR),
            "probe-gated check must be silent with probes off: {:?}",
            report.findings
        );

        // Read-only: lint must not modify the artifact's directory either.
        let mode = std::fs::metadata(&dir)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o777, "lint must not modify the artifact directory");
    }

    #[test]
    fn sbd_pack_id_codes_and_scratch_roots_are_pinned() {
        assert_eq!(SBD_PACK_ID, "tallow-secure-by-default-pack-v1");
        for code in [
            CODE_SBD_SECRET_RELATIVE,
            CODE_SBD_SECRET_SCRATCH,
            CODE_SBD_ARTIFACT_DIR,
        ] {
            assert!(code.starts_with("W73"), "{code}");
        }
        // Additive: no collision with the existing KB-7 / zero-trust codes.
        let mut all: Vec<&str> = vec![
            CODE_PROFILE_FLOOR,
            CODE_NO_PROFILE,
            CODE_TELEMETRY_ON,
            CODE_ENV_SECRET_REF,
            CODE_SECRET_TARGET,
            CODE_ENV_SECRET_MISSING,
            CODE_VAULT_SEAM_REF,
            CODE_PROFILE_GATED,
            CODE_ZT_POSTURE,
            CODE_ZT_ARTIFACT_MODE,
            CODE_ZT_SECRET_DIR,
            CODE_SBD_SECRET_RELATIVE,
            CODE_SBD_SECRET_SCRATCH,
            CODE_SBD_ARTIFACT_DIR,
        ];
        let len_before = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), len_before, "lint code collision");
        // Scratch roots are absolute and distinct (matched component-wise
        // against `file:` parents).
        for root in SCRATCH_ROOTS {
            assert!(Path::new(root).is_absolute(), "{root}");
        }
        let mut roots: Vec<&str> = SCRATCH_ROOTS.to_vec();
        roots.sort_unstable();
        roots.dedup();
        assert_eq!(roots.len(), SCRATCH_ROOTS.len());
    }
}
