//! NIS2 / ZNISM-style self-assessment evidence pack (row #179).
//!
//! The pack is built **from the machine checks that exist in this tree** —
//! never from prose. Three sections:
//!
//! 1. `zero_trust` — the NCSC-8 self-assessment already produced by the KB-7
//!    lint surface (`tallow config lint`, row #144, pack
//!    `tallow-zero-trust-pack-v1`), re-read here row for row.
//! 2. `nis2_art21` — the ten NIS2 Art. 21(2) measures mapped to lint codes
//!    where a check exists, to a named artifact outside this run where one
//!    does (status `external_artifact`), and to `unsupported` /
//!    `operator_input_required` where nothing machine-checkable exists. No
//!    row claims more than its evidence.
//! 3. `nzism_families` — a **curated subset** of NZISM control families
//!    cross-referenced to the same checks. Families outside the subset are
//!    not claimed at all (they simply do not appear).
//!
//! Honesty invariants (pinned by tests): a row is `evidenced` only when it
//! has at least one mapped check; an `unsupported` row has none; the pack
//! carries a digest so the operator can sign what they attest to.

use serde::Serialize;

use tallow::config::lint::{
    lint, LintOptions, LintReport, ZeroTrustStatus, BASELINE_ID, CODE_NO_PROFILE,
    CODE_PROFILE_FLOOR, CODE_ZT_ARTIFACT_MODE, CODE_ZT_POSTURE, CODE_ZT_SECRET_DIR,
};
use tallow::config::load::ConfigLoad;

use super::{iso8601_utc, push_field, sha256_hex};

/// Pack schema id.
pub const ZNISM_SCHEMA: &str = "tallow.compliance.znism-pack.v1";
/// Pack identifier carried in the report.
pub const ZNISM_PACK_ID: &str = "tallow-nis2-znism-self-assessment-v1";

/// Status vocabulary — one word per row, no numeric scores that imply an
/// audit opinion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackStatus {
    /// A mapped machine check ran in this pack and produced no finding.
    Evidenced,
    /// A mapped machine check ran in this pack and produced a finding.
    Gap,
    /// Mapped checks cover only part of the measure.
    Partial,
    /// No machine check exists for this measure in this tree.
    Unsupported,
    /// The artifact did not parse — nothing to assess.
    NotAssessed,
    /// The measure needs an operator declaration (training, policy intent…).
    OperatorInputRequired,
    /// A named artifact outside this run provides the evidence; the pack
    /// does not execute it and says so.
    ExternalArtifact,
}

impl PackStatus {
    /// Stable lowercase word (report/JSON spelling).
    pub fn word(self) -> &'static str {
        match self {
            PackStatus::Evidenced => "evidenced",
            PackStatus::Gap => "gap",
            PackStatus::Partial => "partial",
            PackStatus::Unsupported => "unsupported",
            PackStatus::NotAssessed => "not_assessed",
            PackStatus::OperatorInputRequired => "operator_input_required",
            PackStatus::ExternalArtifact => "external_artifact",
        }
    }
}

/// One self-assessment row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackRow {
    /// Measure/control id (`nis2-21-2-a`, `nzism-GOV-1`, `NCSC 3`, …).
    pub id: String,
    /// Measure title (verbatim from the source spelling).
    pub title: String,
    /// Status, derived only from the run.
    pub status: PackStatus,
    /// Machine checks mapped to this row (lint codes, pack ids).
    pub checks: Vec<&'static str>,
    /// Evidence artifacts (paths / suites / report ids).
    pub evidence: Vec<&'static str>,
    /// Factual note: what fired, what is missing, what the row does not claim.
    pub note: String,
}

/// A pack section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackSection {
    /// Section id.
    pub id: &'static str,
    /// Section title.
    pub title: &'static str,
    /// Rows, in source order.
    pub rows: Vec<PackRow>,
}

/// The operator attestation block — the pack is an input to a human
/// declaration, never a substitute for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attestation {
    /// Machine-readable statement the operator adopts by signing.
    pub statement: &'static str,
    /// Generated on this host.
    pub local_only: bool,
    /// Never transmitted.
    pub auto_submitted: bool,
    /// A human must approve.
    pub operator_approval_required: bool,
    /// Explicitly not a certification or legal opinion.
    pub not_a_certification: bool,
    /// Named limitations the pack does not cover.
    pub limitations: Vec<&'static str>,
    /// Digest the signature would cover.
    pub pack_digest_sha256: String,
}

/// The generated pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZnismPack {
    /// Schema id.
    pub schema: &'static str,
    /// Pack id.
    pub pack: &'static str,
    /// Generation instant (Unix seconds).
    pub generated_at: i64,
    /// Config artifact the checks ran against (`None` = in-memory defaults).
    pub source: Option<String>,
    /// KB-7 baseline id.
    pub baseline: &'static str,
    /// Lint score / max of the underlying run (context, not a compliance score).
    pub score: u32,
    /// Maximum lint score.
    pub max_score: u32,
    /// Findings count of the underlying run.
    pub findings: usize,
    /// Sections.
    pub sections: Vec<PackSection>,
    /// Attestation block.
    pub attestation: Attestation,
    /// sha256 over the canonical bytes.
    pub digest_sha256: String,
}

impl ZnismPack {
    /// All rows.
    pub fn rows(&self) -> impl Iterator<Item = &PackRow> {
        self.sections.iter().flat_map(|s| s.rows.iter())
    }

    /// Count of rows in `status`.
    pub fn count(&self, status: PackStatus) -> usize {
        self.rows().filter(|r| r.status == status).count()
    }

    /// Total rows.
    pub fn row_count(&self) -> usize {
        self.rows().count()
    }

    /// Canonical bytes for hashing. Covers the scored rows *and* the run's
    /// scoring arithmetic (score, findings count), so a different artifact
    /// that moves either is visible in the digest; `generated_at` stays
    /// outside it (the same artifact assessed twice hashes the same).
    pub fn canonical_bytes(&self) -> String {
        let mut buf = String::new();
        push_field(&mut buf, ZNISM_SCHEMA);
        push_field(&mut buf, ZNISM_PACK_ID);
        push_field(&mut buf, self.source.as_deref().unwrap_or_default());
        push_field(&mut buf, self.baseline);
        push_field(&mut buf, &self.score.to_string());
        push_field(&mut buf, &self.findings.to_string());
        for s in &self.sections {
            push_field(&mut buf, s.id);
            for r in &s.rows {
                push_field(&mut buf, &r.id);
                push_field(&mut buf, r.status.word());
                for c in &r.checks {
                    push_field(&mut buf, c);
                }
            }
        }
        buf
    }

    /// Rows rendered for JSON.
    fn json_rows(&self) -> Vec<serde_json::Value> {
        self.sections
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "title": s.title,
                    "rows": s.rows.iter().map(|r| serde_json::json!({
                        "id": r.id,
                        "title": r.title,
                        "status": r.status.word(),
                        "checks": r.checks,
                        "evidence": r.evidence,
                        "note": r.note,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect()
    }

    /// JSON rendering.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "pack": self.pack,
            "generated_at": self.generated_at,
            "generated_at_utc": iso8601_utc(self.generated_at),
            "source": self.source,
            "baseline": self.baseline,
            "lint_context": {
                "score": self.score,
                "max_score": self.max_score,
                "findings": self.findings,
                "note": "the lint score is hardening context for the config artifact, not a compliance verdict",
            },
            "counts": {
                "rows": self.row_count(),
                "evidenced": self.count(PackStatus::Evidenced),
                "gap": self.count(PackStatus::Gap),
                "partial": self.count(PackStatus::Partial),
                "unsupported": self.count(PackStatus::Unsupported),
                "not_assessed": self.count(PackStatus::NotAssessed),
                "operator_input_required": self.count(PackStatus::OperatorInputRequired),
                "external_artifact": self.count(PackStatus::ExternalArtifact),
            },
            "sections": self.json_rows(),
            "attestation": self.attestation,
            "digest_sha256": self.digest_sha256,
        })
    }

    /// Text rendering.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "tallow compliance znism-pack — {} ({})\n",
            self.pack,
            iso8601_utc(self.generated_at)
        ));
        out.push_str(&format!(
            "  source: {} · baseline: {}\n",
            self.source.as_deref().unwrap_or("(in-memory defaults)"),
            self.baseline
        ));
        out.push_str(&format!(
            "  {} row(s) · {} evidenced · {} gap · {} partial · {} unsupported · \
             {} operator input · {} external artifact\n",
            self.row_count(),
            self.count(PackStatus::Evidenced),
            self.count(PackStatus::Gap),
            self.count(PackStatus::Partial),
            self.count(PackStatus::Unsupported),
            self.count(PackStatus::OperatorInputRequired),
            self.count(PackStatus::ExternalArtifact),
        ));
        for section in &self.sections {
            out.push_str(&format!("\n{} — {}\n", section.id, section.title));
            out.push_str("──────────────────────────────────────────────────────────────\n");
            for row in &section.rows {
                out.push_str(&format!(
                    "  [{}] {} — {}\n",
                    row.status.word(),
                    row.id,
                    row.title
                ));
                if !row.note.is_empty() {
                    out.push_str(&format!("        {}\n", row.note));
                }
            }
        }
        out.push_str(&format!("\n{}\n", self.attestation.statement));
        out.push_str(&format!(
            "not a certification · local-only · no automatic submission · digest sha256:{}\n",
            self.digest_sha256
        ));
        out
    }
}

/// How a row's status is derived. Everything is computed from the run;
/// nothing is asserted by hand.
enum Derivation {
    /// Status from whether any of these lint codes fired.
    Findings(&'static [&'static str]),
    /// Status from the zero-trust self-assessment: `min_covered` covered rows
    /// required, otherwise `gap` when any row is in gap, else `partial`.
    ZeroTrust { min_covered: usize },
    /// Evidence lives in a named artifact outside this run.
    External,
    /// Requires an operator declaration.
    Operator,
    /// No machine check exists.
    None,
}

struct Nis2Measure {
    id: &'static str,
    title: &'static str,
    checks: &'static [&'static str],
    evidence: &'static [&'static str],
    note: &'static str,
    derivation: Derivation,
}

/// NIS2 Art. 21(2)(a)–(j), mapped to what this tree can actually check.
const NIS2_MEASURES: &[Nis2Measure] = &[
    Nis2Measure {
        id: "nis2-21-2-a",
        title: "risk analysis and information system security policies",
        checks: &["E7101", "W7101"],
        evidence: &["tallow-kernel-baseline-v1 (KB-7 lint)"],
        note: "scored by the declared-profile floors of the config baseline",
        derivation: Derivation::Findings(&[CODE_PROFILE_FLOOR, CODE_NO_PROFILE]),
    },
    Nis2Measure {
        id: "nis2-21-2-b",
        title: "incident handling",
        checks: &["tallow.compliance.certin.v1", "tallow.compliance.clocks.v1"],
        evidence: &["src/compliance/incident.rs", "src/compliance/clocks.rs"],
        note: "the CERT-In/early-warning generators exist and compute the deadlines; generating a \
               payload is not evidence that one was filed",
        derivation: Derivation::External,
    },
    Nis2Measure {
        id: "nis2-21-2-c",
        title: "business continuity, backup management and disaster recovery",
        checks: &[],
        evidence: &[],
        note: "no machine check in this tree — the pack does not guess",
        derivation: Derivation::None,
    },
    Nis2Measure {
        id: "nis2-21-2-d",
        title: "supply chain security",
        checks: &["trust_foundation_check"],
        evidence: &["scripts/trust_foundation_check.sh", "supply-chain/substrate-scope.toml"],
        note: "run the trust-foundation legs separately; this pack does not execute them",
        derivation: Derivation::External,
    },
    Nis2Measure {
        id: "nis2-21-2-e",
        title: "security in acquisition, development and maintenance, vulnerability handling",
        checks: &["W7202", "W7203"],
        evidence: &["tallow audit --cra (Annex-I checklist)", "src/config/lint.rs"],
        note: "artifact-permission legs are scored here; the CRA Annex-I legs run under `tallow audit --cra`",
        derivation: Derivation::Findings(&[CODE_ZT_ARTIFACT_MODE, CODE_ZT_SECRET_DIR]),
    },
    Nis2Measure {
        id: "nis2-21-2-f",
        title: "policies and procedures to assess the effectiveness of security measures",
        checks: &["W7201"],
        evidence: &["scripts/release_gate.sh", "tallow-zero-trust-pack-v1"],
        note: "posture-floor leg scored here; the release gate is a separate artifact",
        derivation: Derivation::Findings(&[CODE_ZT_POSTURE]),
    },
    Nis2Measure {
        id: "nis2-21-2-g",
        title: "basic cyber hygiene practices and cybersecurity training",
        checks: &[],
        evidence: &[],
        note: "human measures — the operator declares them; nothing here claims to check them",
        derivation: Derivation::Operator,
    },
    Nis2Measure {
        id: "nis2-21-2-h",
        title: "cryptography and, where appropriate, encryption",
        checks: &["zero_trust:CRYPT"],
        evidence: &["crates/tallow-crypto", "tests/consttime_harness.rs"],
        note: "crypto suites run in their own target; the pack links them, it does not re-run them",
        derivation: Derivation::External,
    },
    Nis2Measure {
        id: "nis2-21-2-i",
        title: "human resources security, access control policies and asset management",
        checks: &["W7202", "W7203"],
        evidence: &["src/config/lint.rs", "src/vault/persona_store.rs"],
        note: "artifact permissions and secret-directory legs are scored here",
        derivation: Derivation::Findings(&[CODE_ZT_ARTIFACT_MODE, CODE_ZT_SECRET_DIR]),
    },
    Nis2Measure {
        id: "nis2-21-2-j",
        title: "use of multi-factor authentication and secure communications",
        checks: &["tallow-zero-trust-pack-v1"],
        evidence: &["zero_trust section (NCSC 8 principles)"],
        note: "status mirrors the zero-trust rows: covered rows count as evidence, gaps do not",
        derivation: Derivation::ZeroTrust { min_covered: 3 },
    },
];

struct NzismFamily {
    id: &'static str,
    title: &'static str,
    checks: &'static [&'static str],
    evidence: &'static [&'static str],
    note: &'static str,
    derivation: Derivation,
}

/// Curated NZISM control-family subset cross-referenced to this tree.
const NZISM_FAMILIES: &[NzismFamily] = &[
    NzismFamily {
        id: "nzism-GOV",
        title: "governance and policy (curated subset)",
        checks: &["E7101", "W7101"],
        evidence: &["tallow-kernel-baseline-v1"],
        note: "the config baseline is the only machine-checkable governance surface",
        derivation: Derivation::Findings(&[CODE_PROFILE_FLOOR, CODE_NO_PROFILE]),
    },
    NzismFamily {
        id: "nzism-IDENT",
        title: "identity and authentication (curated subset)",
        checks: &["tallow-zero-trust-pack-v1"],
        evidence: &["zero_trust section", "crates/tallow-svid"],
        note: "status mirrors the zero-trust rows",
        derivation: Derivation::ZeroTrust { min_covered: 2 },
    },
    NzismFamily {
        id: "nzism-ACCESS",
        title: "access control (curated subset)",
        checks: &["W7202", "W7203"],
        evidence: &["src/config/lint.rs", "src/vault/persona_store.rs"],
        note: "file-permission and secret-target legs",
        derivation: Derivation::Findings(&[CODE_ZT_ARTIFACT_MODE, CODE_ZT_SECRET_DIR]),
    },
    NzismFamily {
        id: "nzism-CRYPT",
        title: "cryptography (curated subset)",
        checks: &[],
        evidence: &["crates/tallow-crypto", "tests/consttime_harness.rs"],
        note: "crypto evidence is produced by its own suites, not by this config-surface pack",
        derivation: Derivation::External,
    },
    NzismFamily {
        id: "nzism-LOG",
        title: "logging and audit (curated subset)",
        checks: &[],
        evidence: &["src/agent_ledger.rs", "src/fixity_job.rs"],
        note: "ledger/fixity evidence is produced by its own suites",
        derivation: Derivation::External,
    },
    NzismFamily {
        id: "nzism-INTRUS",
        title: "intrusion detection and incident response (curated subset)",
        checks: &["tallow.compliance.clocks.v1"],
        evidence: &["src/compliance/clocks.rs"],
        note: "the deadline engine exists; detection quality is out of scope here",
        derivation: Derivation::External,
    },
    NzismFamily {
        id: "nzism-PERS",
        title: "personnel and training (curated subset)",
        checks: &[],
        evidence: &[],
        note: "operator declaration only",
        derivation: Derivation::Operator,
    },
];

/// `parsed` — did the artifact get past the kernel's file-level refusal
/// (`load.file_error().is_none()`, the same fact `lint()` scores NCSC 1/4/6
/// with)? An unparseable artifact scores nothing: every config-surface row
/// must read `not_assessed` instead of "no finding fired".
fn row_from(
    id: &str,
    title: &str,
    checks: &'static [&'static str],
    evidence: &'static [&'static str],
    note: &str,
    derivation: &Derivation,
    report: &LintReport,
    parsed: bool,
) -> PackRow {
    let fired: Vec<String> = report
        .findings
        .iter()
        .filter(|f| checks.contains(&f.code))
        .map(|f| f.code.to_string())
        .collect();
    let (status, note) = match derivation {
        Derivation::Findings(_) => {
            if !parsed {
                (
                    PackStatus::NotAssessed,
                    format!("{note} — the artifact did not parse; nothing was scored"),
                )
            } else if fired.is_empty() {
                (
                    PackStatus::Evidenced,
                    format!(
                        "{note} — no mapped check fired in this run ({} mapped)",
                        checks.len()
                    ),
                )
            } else {
                (
                    PackStatus::Gap,
                    format!("{note} — fired: {}", fired.join(", ")),
                )
            }
        }
        Derivation::ZeroTrust { min_covered } => {
            let (covered, gaps, _partial, unsupported, _na) = report.zero_trust.counts();
            if !parsed {
                (
                    PackStatus::NotAssessed,
                    format!("{note} — the artifact did not parse; nothing was scored"),
                )
            } else if gaps > 0 {
                (
                    PackStatus::Gap,
                    format!("{note} — {gaps} zero-trust row(s) in gap"),
                )
            } else if covered >= *min_covered {
                (
                    PackStatus::Evidenced,
                    format!("{note} — {covered} zero-trust row(s) covered"),
                )
            } else {
                (
                    PackStatus::Partial,
                    format!(
                        "{note} — only {covered} covered row(s); {unsupported} unsupported by \
                         config-surface checks"
                    ),
                )
            }
        }
        Derivation::External => (
            PackStatus::ExternalArtifact,
            format!("{note} — evidence artifact named, not executed by this pack"),
        ),
        Derivation::Operator => (PackStatus::OperatorInputRequired, note.to_string()),
        Derivation::None => (PackStatus::Unsupported, note.to_string()),
    };
    PackRow {
        id: id.to_string(),
        title: title.to_string(),
        status,
        checks: checks.to_vec(),
        evidence: evidence.to_vec(),
        note,
    }
}

/// Build the pack from a config artifact (already loaded) and lint options.
pub fn build_pack(load: &ConfigLoad, options: &LintOptions, now: i64) -> ZnismPack {
    let report = lint(load, options);
    // The kernel's file-level refusal is the "did it parse at all" signal —
    // a refused artifact scores nothing (row #144 semantics).
    let parsed = load.file_error().is_none();

    // Section 1 — the zero-trust self-assessment, row for row.
    let zero_trust_rows: Vec<PackRow> = report
        .zero_trust
        .rows
        .iter()
        .map(|r| {
            let status = match r.status {
                ZeroTrustStatus::Covered => PackStatus::Evidenced,
                ZeroTrustStatus::Gap => PackStatus::Gap,
                ZeroTrustStatus::Partial => PackStatus::Partial,
                ZeroTrustStatus::Unsupported => PackStatus::Unsupported,
                ZeroTrustStatus::NotAssessed => PackStatus::NotAssessed,
            };
            PackRow {
                id: r.principle.to_string(),
                title: r.title.to_string(),
                status,
                checks: r.checks.to_vec(),
                evidence: vec!["src/config/lint.rs (zero-trust pack)"],
                note: format!(
                    "{} · NIST {} · SG {} · {}",
                    report.zero_trust.pack, r.nist, r.sg, r.note
                ),
            }
        })
        .collect();

    // Section 2 — NIS2 Art. 21(2).
    let nis2_rows: Vec<PackRow> = NIS2_MEASURES
        .iter()
        .map(|m| {
            row_from(
                m.id,
                m.title,
                m.checks,
                m.evidence,
                m.note,
                &m.derivation,
                &report,
                parsed,
            )
        })
        .collect();

    // Section 3 — curated NZISM subset.
    let nzism_rows: Vec<PackRow> = NZISM_FAMILIES
        .iter()
        .map(|m| {
            row_from(
                m.id,
                m.title,
                m.checks,
                m.evidence,
                m.note,
                &m.derivation,
                &report,
                parsed,
            )
        })
        .collect();

    let sections = vec![
        PackSection {
            id: "zero_trust",
            title: "zero-trust self-assessment (NCSC 8 principles · NIST SP 800-207/207A · Singapore GovZTA)",
            rows: zero_trust_rows,
        },
        PackSection {
            id: "nis2_art21",
            title: "NIS2 Art. 21(2) measures (a)–(j)",
            rows: nis2_rows,
        },
        PackSection {
            id: "nzism_families",
            title: "NZISM-style control families (curated subset — unmapped families are not claimed)",
            rows: nzism_rows,
        },
    ];

    let mut pack = ZnismPack {
        schema: ZNISM_SCHEMA,
        pack: ZNISM_PACK_ID,
        generated_at: now,
        source: load.source().map(|p| p.display().to_string()),
        baseline: BASELINE_ID,
        score: report.score,
        max_score: report.max_score,
        findings: report.findings.len(),
        sections,
        attestation: Attestation {
            statement: "The operator reviews this pack, fills what it marks \
                        `operator_input_required`, and signs it before any submission; it is a \
                        self-assessment aid generated from local machine checks.",
            local_only: true,
            auto_submitted: false,
            operator_approval_required: true,
            not_a_certification: true,
            limitations: vec![
                "config-surface assessment only — nothing here is an audit or certification",
                "artifacts marked `external_artifact` are named, not executed by this pack",
                "rows marked `unsupported` have no machine check in this tree",
            ],
            pack_digest_sha256: String::new(),
        },
        digest_sha256: String::new(),
    };
    let digest = sha256_hex(pack.canonical_bytes().as_bytes());
    pack.digest_sha256 = digest.clone();
    pack.attestation.pack_digest_sha256 = digest;
    pack
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::parse_timestamp;

    fn now() -> i64 {
        parse_timestamp("2026-09-14T03:00:00Z").unwrap()
    }

    fn options() -> LintOptions {
        LintOptions {
            probe_secret_targets: false,
            ..LintOptions::default()
        }
    }

    fn packed(text: &str) -> ZnismPack {
        let load = tallow::config::load::load_from_str(text, None);
        build_pack(&load, &options(), now())
    }

    #[test]
    fn pack_has_three_sections_and_the_expected_row_counts() {
        let pack = packed("profile = \"workstation\"\ntelemetry = false\n");
        assert_eq!(pack.schema, ZNISM_SCHEMA);
        assert_eq!(pack.pack, ZNISM_PACK_ID);
        assert_eq!(pack.sections.len(), 3);
        let zt = &pack.sections[0];
        assert_eq!(zt.id, "zero_trust");
        assert_eq!(zt.rows.len(), 8, "one row per NCSC principle");
        assert_eq!(pack.sections[1].id, "nis2_art21");
        assert_eq!(pack.sections[1].rows.len(), 10, "NIS2 Art. 21(2)(a)-(j)");
        assert_eq!(pack.sections[2].id, "nzism_families");
        assert!(!pack.sections[2].rows.is_empty());
        assert_eq!(pack.row_count(), 8 + 10 + pack.sections[2].rows.len());
    }

    #[test]
    fn honesty_invariants_hold() {
        let pack = packed("profile = \"workstation\"\ntelemetry = true\n");
        for row in pack.rows() {
            if row.status == PackStatus::Evidenced {
                assert!(
                    !row.checks.is_empty(),
                    "evidenced row without checks: {}",
                    row.id
                );
            }
            if row.status == PackStatus::Unsupported {
                assert!(
                    row.checks.is_empty(),
                    "unsupported row claims checks: {}",
                    row.id
                );
            }
        }
        // The pack never claims a row count it does not have.
        let summed = pack.count(PackStatus::Evidenced)
            + pack.count(PackStatus::Gap)
            + pack.count(PackStatus::Partial)
            + pack.count(PackStatus::Unsupported)
            + pack.count(PackStatus::NotAssessed)
            + pack.count(PackStatus::OperatorInputRequired)
            + pack.count(PackStatus::ExternalArtifact);
        assert_eq!(summed, pack.row_count());
    }

    #[test]
    fn statuses_and_digest_track_the_scored_artifact() {
        let clean = packed("profile = \"workstation\"\ntelemetry = false\n");
        // A different artifact either moves a row status or moves nothing —
        // the digest is bound to what was actually scored.
        let other = packed("telemetry = false\n");
        assert!(
            clean.digest_sha256 != other.digest_sha256
                || other.count(PackStatus::Gap) > clean.count(PackStatus::Gap),
            "artifact change must be visible in the pack"
        );
        // An unparseable artifact scores nothing at all — the strictest change.
        let broken = packed("profile = \"workstation\"\nthis is not toml =\n");
        assert_ne!(clean.digest_sha256, broken.digest_sha256);
        assert!(broken.count(PackStatus::NotAssessed) > 0);
    }

    #[test]
    fn zero_trust_section_mirrors_the_lint_assessment_row_for_row() {
        let load = tallow::config::load::load_from_str("profile = \"workstation\"\n", None);
        let report = lint(&load, &options());
        let pack = build_pack(&load, &options(), now());
        assert_eq!(pack.sections[0].rows.len(), report.zero_trust.rows.len());
        for (packed_row, lint_row) in pack.sections[0]
            .rows
            .iter()
            .zip(report.zero_trust.rows.iter())
        {
            assert_eq!(packed_row.id, lint_row.principle);
            assert_eq!(packed_row.title, lint_row.title);
            assert_eq!(packed_row.checks, lint_row.checks.to_vec());
            let expected = match lint_row.status {
                ZeroTrustStatus::Covered => PackStatus::Evidenced,
                ZeroTrustStatus::Gap => PackStatus::Gap,
                ZeroTrustStatus::Partial => PackStatus::Partial,
                ZeroTrustStatus::Unsupported => PackStatus::Unsupported,
                ZeroTrustStatus::NotAssessed => PackStatus::NotAssessed,
            };
            assert_eq!(packed_row.status, expected);
        }
        // Gap parity, stated as a number.
        assert_eq!(
            pack.count(PackStatus::Gap) >= report.zero_trust.gaps(),
            true
        );
    }

    #[test]
    fn digest_is_deterministic_and_bound_to_the_source() {
        let a = packed("profile = \"workstation\"\ntelemetry = false\n");
        let b = packed("profile = \"workstation\"\ntelemetry = false\n");
        assert_eq!(a.digest_sha256, b.digest_sha256);
        assert_eq!(a.digest_sha256.len(), 64);
        assert_eq!(a.attestation.pack_digest_sha256, a.digest_sha256);
        let c = packed("profile = \"server\"\ntelemetry = false\n");
        assert_ne!(a.digest_sha256, c.digest_sha256);
        // Generation time is deliberately outside the digest: the same
        // artifact assessed twice must hash the same.
        let load = tallow::config::load::load_from_str("profile = \"workstation\"\n", None);
        let later = build_pack(&load, &options(), now() + 86_400);
        assert_eq!(
            later.digest_sha256,
            build_pack(&load, &options(), now()).digest_sha256
        );
    }

    #[test]
    fn unparseable_artifacts_score_not_assessed_and_claim_nothing() {
        let pack = packed("profile = \"workstation\"\nthis is not toml =\n");
        for row in pack.rows() {
            // One documented exception: NCSC 8 ("choose the safest default
            // when things go wrong"). The kernel refusing the artifact
            // instead of degrading to defaults *is* the fail-closed behavior
            // that principle scores — mirrored from the row-#144 lint
            // semantics with its refusal note carried through.
            if row.id == "NCSC 8" {
                assert_eq!(row.status, PackStatus::Evidenced);
                assert!(
                    row.note.contains("refused the artifact"),
                    "NCSC 8 must carry the refusal note, got: {}",
                    row.note
                );
                continue;
            }
            assert!(
                matches!(
                    row.status,
                    PackStatus::NotAssessed
                        | PackStatus::Unsupported
                        | PackStatus::OperatorInputRequired
                        | PackStatus::ExternalArtifact
                ),
                "row {} should not be scored on an unparseable artifact",
                row.id
            );
        }
    }

    #[test]
    fn json_and_text_renders_carry_counts_attestation_and_digest() {
        let pack = packed("profile = \"workstation\"\ntelemetry = false\n");
        let json = pack.to_json();
        assert_eq!(json["schema"], ZNISM_SCHEMA);
        assert_eq!(json["counts"]["rows"], pack.row_count());
        assert_eq!(json["attestation"]["local_only"], true);
        assert_eq!(json["attestation"]["auto_submitted"], false);
        assert_eq!(json["attestation"]["not_a_certification"], true);
        assert_eq!(json["sections"][1]["rows"][0]["id"], "nis2-21-2-a");
        assert_eq!(json["digest_sha256"], pack.digest_sha256);
        let text = pack.render_text();
        assert!(text.contains("not a certification"));
        assert!(text.contains("zero_trust"));
        assert!(text.contains("nis2-21-2-j"));
    }

    #[test]
    fn operator_and_unsupported_rows_are_labelled_not_guessed() {
        let pack = packed("profile = \"workstation\"\n");
        let training = pack
            .rows()
            .find(|r| r.id == "nis2-21-2-g")
            .expect("training row");
        assert_eq!(training.status, PackStatus::OperatorInputRequired);
        let continuity = pack
            .rows()
            .find(|r| r.id == "nis2-21-2-c")
            .expect("continuity row");
        assert_eq!(continuity.status, PackStatus::Unsupported);
        assert!(continuity.note.contains("does not guess"));
        let supply = pack
            .rows()
            .find(|r| r.id == "nis2-21-2-d")
            .expect("supply-chain row");
        assert_eq!(supply.status, PackStatus::ExternalArtifact);
        assert!(!supply.evidence.is_empty());
    }
}
