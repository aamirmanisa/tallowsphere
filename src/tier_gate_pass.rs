//! Source-scanning `@tier` annotation pass (task B1.1.2, compiler-pass
//! component; frozen interface §6).
//!
//! This module is the **scanning half** of the `@tier` gate: it walks raw Rust
//! source text, extracts every `@tier(<word>)` annotation occurrence (in
//! comments, doc comments, attributes, or string literals — plain text scan,
//! no lexer), and validates each word against the **existing** tier-gate
//! semantics in [`crate::tier_gate`]:
//!
//! - [`parse_tier_word`] recognizes the four tier words (`scout` … `vault_admin`);
//! - [`is_known_module`] / [`min_tier_for`] recognize words classified in
//!   `TIER_MODULES`.
//!
//! Nothing here re-implements tier semantics: the pass consumes the gate
//! engine's public functions, and [`PassFinding::diagnostic`] projects a
//! finding into the engine's own [`TierDiagnostic`] shape so pass output can
//! be printed next to `check_build` diagnostics in one compile log.
//!
//! # Word classification (pinned)
//!
//! Every annotation occurrence is classified by exactly one rule, first match
//! wins (this is [`classify_word`], the pass's core rule):
//!
//! | # | condition | outcome |
//! |---|---|---|
//! | 1 | word is empty after trim | [`FindingKind::EmptyAnnotation`] |
//! | 2 | `parse_tier_word(word)` is `Some` | *no finding* — valid tier word (`@tier(scout)`, the `docs/tiers/TIER_GATE.md` §2.2 declaration form) |
//! | 3 | `is_known_module(word)` | *no finding* — valid classified-module word (`@tier(vault)`) |
//! | 4 | word has canonical word syntax (lowercase ASCII letters, digits, `_`) | [`FindingKind::UnknownModule`] |
//! | 5 | otherwise | [`FindingKind::MalformedTierWord`] |
//!
//! ## Why this order (deviation, argued — see the AGT-136 report)
//!
//! §6's literal decision list ("`parse_tier_word` fails → MalformedTierWord;
//! word ok but `is_known_module` false → UnknownModule") is **unsatisfiable as
//! written**: with the real `tiers` tables, no word passes both checks, so a
//! literal reading makes *every* word a finding — `@tier(scout)` →
//! UnknownModule (tier words are in no `TIER_MODULES` slice) and
//! `@tier(persona)` → MalformedTierWord (module words are not tier words).
//! That contradicts (a) §6's own test list ("valid → no finding"), and
//! (b) `docs/tiers/TIER_GATE.md` §2.2, where `@tier(scout)` is *the*
//! declaration form. The reading above is the one that satisfies every stated
//! constraint at once: all three kinds reachable, a word accepted by
//! `parse_tier_word` (or classified by `is_known_module`) never yields
//! *Malformed* — in fact never yields any finding — and each kind's name
//! matches its trigger (a syntax-broken word is *malformed*; a canonical word
//! naming no classified module is *unknown*). Kinds 4/5 are split by word
//! syntax, the only deterministic discriminator the two names support.
//!
//! # Determinism
//!
//! Pure and total apart from the two `BadInput` refusals: lines are 1-based,
//! findings ascend with the annotations that produced them (left-to-right per
//! line within a line), and [`render_findings`] is a byte-deterministic
//! `path:line: [Kind] message` listing. One finding is emitted per annotation
//! occurrence; identical occurrences on one line are reported once each (they
//! are distinct source positions), so a `(path, line)` pair repeats only when
//! a single line carries more than one flagged annotation — never because a
//! unit is scanned twice.
//!
//! # Integration (B1.1.2 follow-up; build-level runner: T-123)
//!
//! This file is the pass *logic* plus the build-level gate runner. The
//! per-file annotation pass ([`TierGatePass`]) is wired into `src/main.rs` as
//! "Phase 28b"; the build-level half — collect the gate inputs (declared
//! tier, module references, waiver claims) across every source unit of the
//! build and hand them to the pure engine — is [`run_build_gate`] (T-123),
//! projected into the compile log by [`report_diagnostics`]. Remaining
//! follow-ups: feed multi-file `SourceUnit`s from the import-resolution phase
//! (the current call site passes the single compiled file), source waiver
//! records from the ledger (no record store is wired yet — callers pass the
//! empty set, so every escape hatch denies until one lands), and attach
//! source spans to gate diagnostics. The parent declares the module
//! (`pub mod tier_gate_pass;`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::tier_gate::{
    check_build, is_known_module, min_tier_for, parse_tier_word, GateReport, TierDiagnostic,
    Waiver, CODE_BAD_TIER_DECLARATION, CODE_MODULE_NOT_PERMITTED, CODE_UNKNOWN_MODULE,
    CODE_WAIVER_IN_USE, CODE_WAIVER_RECORD_MISSING,
};

/// The exact byte marker an annotation opens with. `@tier_waiver(…)` does not
/// match (`_`, not `(`); `@tier (x)` does not match (a space is not the
/// marker's `(`).
const MARKER: &str = "@tier(";

/// One source file as the pass sees it: a path label (any stable identifier —
/// repo-relative or absolute) and the text to scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceUnit {
    /// Path label used verbatim in findings and rendered output.
    pub path: String,
    /// Raw source text. Scanned line-wise; no parsing required.
    pub source: String,
}

/// Why an annotation word was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingKind {
    /// The word violates canonical word syntax — it can never be a gate word
    /// as written (uppercase, whitespace, punctuation, non-ASCII…).
    MalformedTierWord,
    /// The word has canonical syntax but is neither a tier word nor a module
    /// classified in any `TIER_MODULES` slice.
    UnknownModule,
    /// Nothing (or only whitespace) between the parentheses.
    EmptyAnnotation,
}

impl FindingKind {
    /// Stable spelling of the kind — the verbatim variant name (serde wire
    /// name and render `[Kind]` tag agree; the interface pins no renames).
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::MalformedTierWord => "MalformedTierWord",
            FindingKind::UnknownModule => "UnknownModule",
            FindingKind::EmptyAnnotation => "EmptyAnnotation",
        }
    }

    /// The tier-gate diagnostic code this kind corresponds to, reusing the
    /// engine's assigned codes: an unusable or empty word is a bad
    /// declaration ([`CODE_BAD_TIER_DECLARATION`], `E6003`); an unclassified
    /// module word is [`CODE_UNKNOWN_MODULE`] (`E6002`).
    pub fn code(&self) -> &'static str {
        match self {
            FindingKind::MalformedTierWord | FindingKind::EmptyAnnotation => {
                CODE_BAD_TIER_DECLARATION
            }
            FindingKind::UnknownModule => CODE_UNKNOWN_MODULE,
        }
    }
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rejected annotation occurrence. `line` is 1-based; `word` is the
/// trimmed annotation word (empty for [`FindingKind::EmptyAnnotation`]);
/// `message` is pinned per kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassFinding {
    /// Path label of the unit the annotation was found in (verbatim).
    pub path: String,
    /// 1-based line number of the annotation.
    pub line: usize,
    /// Which rule rejected the word.
    pub kind: FindingKind,
    /// The trimmed word between the parentheses (empty when empty).
    pub word: String,
    /// Human-readable detail + remediation (pinned per kind).
    pub message: String,
}

impl PassFinding {
    /// Projection into the gate engine's diagnostic shape ([`TierDiagnostic`])
    /// so a pass log and a `check_build` report read identically. The
    /// `module` field carries the word for [`FindingKind::UnknownModule`]
    /// (module-level diagnostic, as in `E6002`) and is empty for declaration
    /// -level kinds (`E6003`), matching `tier_gate`'s convention.
    pub fn diagnostic(&self) -> TierDiagnostic {
        TierDiagnostic {
            code: self.kind.code().to_string(),
            module: match self.kind {
                FindingKind::UnknownModule => self.word.clone(),
                _ => String::new(),
            },
            message: self.message.clone(),
        }
    }
}

/// Refusal of an unusable `scan_unit` input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PassError {
    /// The named field was empty (`"path"` or `"source"`).
    ///
    /// Serialize-only, mirroring the batch precedent: `&'static str` cannot
    /// derive `Deserialize` (serde's borrowed-str impl needs `'de: 'static`).
    BadInput(&'static str),
}

impl fmt::Display for PassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassError::BadInput(field) => write!(f, "bad input: {field}"),
        }
    }
}

impl std::error::Error for PassError {}

/// Extract every `@tier(<word>)` occurrence from `source`, ascending by line
/// (1-based), left-to-right within each line.
///
/// The word is everything between the `(` of the marker and the next `)` on
/// the same line, trimmed. An unterminated occurrence (no `)` on the line)
/// takes the remainder of the line as its word — fail-loud, never silently
/// skipped — and ends scanning of that line.
pub fn annotations(source: &str) -> Vec<(usize, String)> {
    occurrences(source, MARKER)
}

/// Shared scanner for `marker`-opened occurrences: ascending by line
/// (1-based), left-to-right within each line. Content is everything between
/// the marker and the next `)` on the same line, trimmed; an unterminated
/// occurrence takes the remainder of the line and ends that line's scan.
///
/// [`annotations`] uses it with [`MARKER`] (`@tier(`), the waiver-claim
/// scanner with [`WAIVER_MARKER`] (`@tier_waiver(`) — the two markers never
/// match each other's text, so the scans are disjoint.
fn occurrences(source: &str, marker: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    for (idx, line) in source.split('\n').enumerate() {
        let line_no = idx + 1;
        let mut cursor = 0usize;
        while let Some(rel) = line[cursor..].find(marker) {
            let content_start = cursor + rel + marker.len();
            match line[content_start..].find(')') {
                Some(close_rel) => {
                    let word = line[content_start..content_start + close_rel].trim();
                    out.push((line_no, word.to_string()));
                    cursor = content_start + close_rel + 1;
                }
                None => {
                    let word = line[content_start..].trim();
                    out.push((line_no, word.to_string()));
                    break;
                }
            }
        }
    }
    out
}

/// Canonical gate-word syntax: non-empty, lowercase ASCII letters, digits and
/// `_` only. This is the shape of every `Tier::word()` and every
/// `TIER_MODULES` member.
fn canonical_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The pass's core classification rule: `None` when the word is a valid
/// annotation word (a tier word or a classified module word), `Some(kind)`
/// when it is rejected. First match wins; see the module docs for the pinned
/// table and the argued reading of §6.
pub fn classify_word(word: &str) -> Option<FindingKind> {
    if word.is_empty() {
        return Some(FindingKind::EmptyAnnotation);
    }
    if parse_tier_word(word).is_some() {
        return None; // valid tier declaration word
    }
    if is_known_module(word) {
        return None; // valid classified-module word
    }
    if canonical_word(word) {
        Some(FindingKind::UnknownModule)
    } else {
        Some(FindingKind::MalformedTierWord)
    }
}

/// Pinned message for a rejected occurrence.
fn message_for(kind: FindingKind, word: &str) -> String {
    match kind {
        FindingKind::EmptyAnnotation => {
            "@tier annotation: empty word between the parentheses — an annotation \
             must name a tier word (scout|analyst|operator|vault_admin) or a module \
             classified in TIER_MODULES"
                .to_string()
        }
        FindingKind::MalformedTierWord => format!(
            "tier word {word:?} is malformed: not a tier word \
             (scout|analyst|operator|vault_admin) and not a canonical word \
             (lowercase ASCII letters, digits, \"_\") — check the spelling"
        ),
        FindingKind::UnknownModule => format!(
            "word {word:?} is unknown: not a tier word \
             (scout|analyst|operator|vault_admin) and appears in no tier slice \
             (TIER_MODULES) — unknown modules are denied with no fallback allow; \
             check the spelling or classify it in TIER_MODULES"
        ),
    }
}

/// Scan one unit. Empty `path` or empty `source` → [`PassError::BadInput`]
/// (`"path"` / `"source"`). Findings are in ascending line order (per the
/// annotations they come from); a clean unit yields `Ok(vec![])`.
pub fn scan_unit(unit: &SourceUnit) -> Result<Vec<PassFinding>, PassError> {
    if unit.path.is_empty() {
        return Err(PassError::BadInput("path"));
    }
    if unit.source.is_empty() {
        return Err(PassError::BadInput("source"));
    }
    let mut out: Vec<PassFinding> = Vec::new();
    for (line, word) in annotations(&unit.source) {
        let Some(kind) = classify_word(&word) else {
            continue; // accepted word: nothing to report
        };
        out.push(PassFinding {
            path: unit.path.clone(),
            line,
            kind,
            word: word.clone(),
            message: message_for(kind, &word),
        });
    }
    Ok(out)
}

/// Scan many units: results merged in input order (each unit's findings in
/// ascending line order). No cross-unit deduplication happens — a path listed
/// twice is scanned twice, and findings repeat verbatim — so a `(path, line)`
/// pair can only repeat when one line itself carries multiple flagged
/// annotations, never because a unit was silently merged or rescanned.
pub fn check_units(units: &[SourceUnit]) -> Result<Vec<PassFinding>, PassError> {
    let mut out: Vec<PassFinding> = Vec::new();
    for unit in units {
        out.extend(scan_unit(unit)?);
    }
    Ok(out)
}

/// Deterministic multi-line rendering: one `path:line: [Kind] message` line
/// per finding, `\n`-terminated, in input order. No findings → empty string.
pub fn render_findings(findings: &[PassFinding]) -> String {
    let mut out = String::new();
    for f in findings {
        out.push_str(&format!(
            "{}:{}: [{}] {}\n",
            f.path,
            f.line,
            f.kind.as_str(),
            f.message
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Compiler-pass adapter (B1.1.2 adoption)
// ---------------------------------------------------------------------------

use crate::error::{Diagnostic, Diagnostics};
use crate::lexer::Span;

/// Compiler-pass wrapper over [`scan_unit`], wired into `src/main.rs` as
/// "Phase 28b" so `tallow check` / `tallow build` refuse unusable
/// `@tier(...)` annotations exactly like every other policy pass.
///
/// Each [`PassFinding`] becomes a compiler [`Diagnostic`] carrying the
/// finding's pinned code and message (`E6003` for a bad or empty
/// declaration, `E6002` for an unclassified module) with a best-effort span
/// at the offending annotation occurrence.
///
/// Bad input to [`scan_unit`] (empty path/source) yields an empty bag: this
/// pass piggybacks on every compilation and must never fail a build over
/// its own plumbing.
pub struct TierGatePass {
    path: String,
    source: String,
}

impl TierGatePass {
    /// Build the pass for `source` as read from `path`.
    pub fn new(path: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
        }
    }

    /// Scan the unit; map every finding to a compiler error diagnostic.
    pub fn check(self) -> Diagnostics {
        let mut diags = Diagnostics::new();
        let unit = SourceUnit {
            path: self.path,
            source: self.source,
        };
        let findings = match scan_unit(&unit) {
            Ok(f) => f,
            Err(_) => return diags,
        };
        for f in findings {
            let span = span_for(&unit.source, f.line, &f.word);
            diags.push(Diagnostic::error(f.kind.code(), f.message.clone(), span));
        }
        diags
    }
}

/// Best-effort byte span for a finding: the `@tier(word)` occurrence on
/// `line` (1-based), falling back to that line's first `@tier`, then to
/// `0..0` when the line has no occurrence (never panics).
fn span_for(source: &str, line: usize, word: &str) -> Span {
    let mut offset = 0usize;
    for (i, l) in source.split_inclusive('\n').enumerate() {
        if i + 1 == line {
            let annotation = format!("@tier({word})");
            let (rel, len) = match l.find(&annotation) {
                Some(r) => (r, annotation.len()),
                None => match l.find("@tier") {
                    Some(r) => (r, "@tier".len()),
                    None => (0, 0),
                },
            };
            return Span::new(offset + rel, offset + rel + len);
        }
        offset += l.len();
    }
    Span::new(0, 0)
}

// ---------------------------------------------------------------------------
// Build-level gate (T-123): collect across units + tier_gate::check_build
// ---------------------------------------------------------------------------

/// One **build unit** (§2.1: program/profile) as the build-level gate sees
/// it: a scope name plus every [`SourceUnit`] the unit compiles, in build
/// order.
///
/// `name` is the waiver scope string — a [`Waiver`] grant is honored only for
/// the exact build unit it names (§3.1: scope is exactly one build unit). At
/// the current single-file call site `src/main.rs` passes the compiled
/// file's display path; a multi-file build passes the profile/program id
/// and one `SourceUnit` per file (import-resolution wiring is the remaining
/// follow-up).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildUnit {
    /// Build-unit identity — verbatim waiver scope string.
    pub name: String,
    /// All source units of the build, in build order.
    pub units: Vec<SourceUnit>,
}

impl BuildUnit {
    /// Convenience constructor: a build unit with exactly one source unit.
    pub fn single(name: impl Into<String>, unit: SourceUnit) -> Self {
        Self {
            name: name.into(),
            units: vec![unit],
        }
    }
}

/// Marker opening a `@tier_waiver(…)` claim (proposed syntax, §3.1:
/// `@tier_waiver(id: …)`). `@tier(` does not match it (the `_` before the
/// `(`), so the annotation scanner and the claim scanner are disjoint and
/// never double-report.
const WAIVER_MARKER: &str = "@tier_waiver(";

/// The gate inputs the build-level scan collects from a build's units.
///
/// - `declared` — the first `@tier(<tier word>)` annotation in unit order,
///   `None` when the build carries none (⇒ Scout, default-tightest, decided
///   by the engine). Duplicate declarations: first wins (pinned).
/// - `referenced_modules` — every canonical, non-tier annotation word
///   (`@tier(<word>)`, exact match) across all units, in scan order. Known
///   modules are checked against the declared tier; unknown canonical words
///   are denied (`E6002`) with no fallback allow.
/// - `claimed_waiver_ids` — parsed `@tier_waiver(id: …)` claim ids, in scan
///   order; each must resolve to a live record or the engine emits `E6005`
///   ("record missing or expired").
///
/// Non-canonical and empty annotation words are **not** gate inputs: they
/// are annotation-form problems owned by [`scan_unit`] / [`TierGatePass`]
/// (`E6003`), which the caller runs alongside this runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildGateInputs {
    /// First `@tier` declaration word found (first wins), if any.
    pub declared: Option<String>,
    /// Canonical non-tier annotation words, in scan order (duplicates kept;
    /// the engine sorts and dedupes its diagnostics).
    pub referenced_modules: Vec<String>,
    /// Claimed waiver ids from `@tier_waiver(id: …)`, in scan order.
    pub claimed_waiver_ids: Vec<String>,
}

/// Parse a claim's id out of the text between `@tier_waiver(` and `)`.
///
/// Pinned claim syntax is `id: <value>`; a bare value (no `id:` key) is
/// taken verbatim, and so is any other text — an unparseable claim must
/// still reach the record check (it will fail it ⇒ `E6005`, fail-tight),
/// never be silently dropped.
fn claim_id(claim: &str) -> String {
    let c = claim.trim();
    match c.split_once(':') {
        Some((key, value)) if key.trim() == "id" => value.trim().to_string(),
        _ => c.to_string(),
    }
}

/// Scan every unit of `build` and collect the build-level gate inputs. Pure
/// text scan, no lexer; the pinned extraction rules live in
/// [`BuildGateInputs`].
pub fn collect_build_inputs(build: &BuildUnit) -> BuildGateInputs {
    let mut declared: Option<String> = None;
    let mut referenced_modules: Vec<String> = Vec::new();
    let mut claimed_waiver_ids: Vec<String> = Vec::new();
    for unit in &build.units {
        for (_line, word) in annotations(&unit.source) {
            if word.is_empty() {
                continue; // empty annotation: scan_unit owns it (E6003)
            }
            if parse_tier_word(&word).is_some() {
                if declared.is_none() {
                    declared = Some(word); // first declaration wins (pinned)
                }
                continue;
            }
            if canonical_word(&word) {
                referenced_modules.push(word); // module ref (known or unknown)
            }
            // non-canonical, non-tier words: malformed annotation (E6003,
            // scan_unit owns it — not a gate input).
        }
        for (_line, claim) in occurrences(&unit.source, WAIVER_MARKER) {
            claimed_waiver_ids.push(claim_id(&claim));
        }
    }
    BuildGateInputs {
        declared,
        referenced_modules,
        claimed_waiver_ids,
    }
}

/// Run the `@tier` gate for one whole build unit (TIER_GATE.md §2.2):
/// collect the gate inputs across every source unit ([`collect_build_inputs`])
/// and hand them to the pure engine [`check_build`] together with the
/// recorded `waivers` and the caller-stamped `now_ms`.
///
/// - `waivers` — the recorded grants the caller can see. No ledger/waiver
///   record source is wired yet (documented gap), so the current call site
///   passes the empty set: every escape hatch denies until a record store
///   lands.
/// - `now_ms` — caller-stamped (monotonic ledger-derived in the full policy
///   model, §3.3); the gate itself never reads a clock.
///
/// Returns the engine's [`GateReport`] verbatim: `ok = errors.is_empty()`,
/// deterministic for any input ordering. Pair it with [`TierGatePass::check`]
/// (annotation-form findings) and project it with [`report_diagnostics`] to
/// join the compile log.
pub fn run_build_gate(build: &BuildUnit, waivers: &[Waiver], now_ms: i64) -> GateReport {
    let inputs = collect_build_inputs(build);
    let refs: Vec<&str> = inputs
        .referenced_modules
        .iter()
        .map(String::as_str)
        .collect();
    check_build(
        &build.name,
        inputs.declared.as_deref(),
        &refs,
        waivers,
        &inputs.claimed_waiver_ids,
        now_ms,
    )
}

/// Project an engine [`GateReport`] into compiler [`Diagnostics`] so a
/// build-level verdict joins the compile log beside the annotation pass
/// (`E6001`/`E6002`/`E6003`/`E6005` as errors, `W6001` as a warning).
///
/// A [`GateReport`] carries no source positions, so every diagnostic gets
/// the fallback span `0..0` (same convention as [`span_for`]'s final
/// fallback; `render_all` renders it as line 1, column 1).
pub fn report_diagnostics(report: &GateReport) -> Diagnostics {
    let mut diags = Diagnostics::new();
    for d in &report.errors {
        diags.error(static_code(&d.code), d.message.clone(), Span::new(0, 0));
    }
    for d in &report.warnings {
        diags.warning(static_code(&d.code), d.message.clone(), Span::new(0, 0));
    }
    diags
}

/// Map a `GateReport` diagnostic code string back to the engine's `'static`
/// code constant. `check_build` emits only the five assigned codes
/// (`E6001`/`E6002`/`E6003`/`E6005`/`W6001`); a foreign code (hand-built or
/// deserialized report) maps to the deny-side `E6001` so it can never be
/// dropped from the log.
fn static_code(code: &str) -> &'static str {
    if code == CODE_MODULE_NOT_PERMITTED {
        CODE_MODULE_NOT_PERMITTED
    } else if code == CODE_UNKNOWN_MODULE {
        CODE_UNKNOWN_MODULE
    } else if code == CODE_BAD_TIER_DECLARATION {
        CODE_BAD_TIER_DECLARATION
    } else if code == CODE_WAIVER_RECORD_MISSING {
        CODE_WAIVER_RECORD_MISSING
    } else if code == CODE_WAIVER_IN_USE {
        CODE_WAIVER_IN_USE
    } else {
        CODE_MODULE_NOT_PERMITTED // deny-side fallback; unreachable from check_build
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tiers::{modules_for, Tier, TIER_MODULES};

    fn unit(path: &str, source: &str) -> SourceUnit {
        SourceUnit {
            path: path.to_string(),
            source: source.to_string(),
        }
    }

    fn kinds(fs: &[PassFinding]) -> Vec<&str> {
        fs.iter().map(|f| f.kind.as_str()).collect()
    }

    fn lines(fs: &[PassFinding]) -> Vec<usize> {
        fs.iter().map(|f| f.line).collect()
    }

    fn words(fs: &[PassFinding]) -> Vec<&str> {
        fs.iter().map(|f| f.word.as_str()).collect()
    }

    // ---- annotations() extraction ---------------------------------------

    #[test]
    fn annotations_extracts_all_occurrences_left_to_right_per_line() {
        let src = "let a = 1; @tier(scout) @tier(persona)\n\
                   // nothing here\n\
                   /// @tier( vault ) trailing text\n";
        assert_eq!(
            annotations(src),
            vec![
                (1, "scout".to_string()),
                (1, "persona".to_string()),
                (3, "vault".to_string()),
            ]
        );
        // Empty sources: no annotations (and no panic).
        assert!(annotations("").is_empty());
        assert!(annotations("\n\n").is_empty());
    }

    #[test]
    fn annotations_marker_is_exact_and_context_free() {
        let src = "let a = \"@tier(raw_store)\";\n\
                   // @tier(caveats) — doc comment form\n\
                   @tier_waiver(id: w-1)\n\
                   @tier\n\
                   x@tier(shred)y\n";
        assert_eq!(
            annotations(src),
            vec![
                (1, "raw_store".to_string()),
                (2, "caveats".to_string()),
                (5, "shred".to_string()),
            ]
        );
    }

    #[test]
    fn annotations_unterminated_occurrence_takes_rest_of_line() {
        // No `)` on the line: the remainder of the line is the word (trimmed),
        // and the line is done. Fail-loud, never a silent skip.
        assert_eq!(annotations("@tier(boss"), vec![(1, "boss".to_string())]);
        assert_eq!(annotations("@tier("), vec![(1, String::new())]);
        assert_eq!(annotations("@tier(   "), vec![(1, String::new())]);
        // A later, well-formed occurrence is still found (scan resumes on the
        // next line).
        assert_eq!(
            annotations("@tier(boss\n@tier(persona)"),
            vec![(1, "boss".to_string()), (2, "persona".to_string())]
        );
    }

    // ---- classify_word(): the pinned precedence table -------------------

    #[test]
    fn classify_word_pins_the_precedence_table() {
        // 1 · empty → EmptyAnnotation (before any parse attempt).
        assert_eq!(classify_word(""), Some(FindingKind::EmptyAnnotation));
        // 2 · tier words → accepted (the @tier declaration form).
        for w in ["scout", "analyst", "operator", "vault_admin"] {
            assert_eq!(classify_word(w), None, "{w} is a tier word");
        }
        // 3 · classified module words → accepted.
        for m in ["persona", "raw_store", "vault", "key_ledger"] {
            assert_eq!(classify_word(m), None, "{m} is a classified module");
        }
        // …and canonical syntax alone is not enough: an unclassified
        // canonical word is UnknownModule, not Malformed.
        assert_eq!(
            classify_word("_private_ok"),
            Some(FindingKind::UnknownModule)
        );
        // 4 · canonical words classified nowhere → UnknownModule.
        for w in ["personna", "banana", "definitely_not_a_module", "sco"] {
            assert_eq!(classify_word(w), Some(FindingKind::UnknownModule), "{w}");
        }
        // 5 · syntax violations → MalformedTierWord.
        for w in ["Scout", "vault-admin", "vault admin", "scout!", "Vault_Admin", "café", "."] {
            assert_eq!(classify_word(w), Some(FindingKind::MalformedTierWord), "{w}");
        }
    }

    // ---- scan_unit(): the three finding kinds ---------------------------

    #[test]
    fn scan_unit_empty_word_is_empty_annotation() {
        let u = unit("src/a.rs", "@tier()\n/// @tier(  )\n");
        let fs = scan_unit(&u).unwrap();
        assert_eq!(kinds(&fs), vec!["EmptyAnnotation", "EmptyAnnotation"]);
        assert_eq!(lines(&fs), vec![1, 2]);
        assert_eq!(words(&fs), vec!["", ""]);
        assert!(
            fs[0].message.contains("empty word between the parentheses"),
            "message pinned per kind: {}",
            fs[0].message
        );
        assert_eq!(fs[0].path, "src/a.rs");
        // The message string is a per-kind constant.
        assert_eq!(fs[0].message, fs[1].message);
    }

    #[test]
    fn scan_unit_malformed_word_syntax_violations() {
        for bad in ["Scout", "vault-admin", "vault admin", "scout!", "café"] {
            let u = unit("src/a.rs", &format!("// @tier({bad})\n"));
            let fs = scan_unit(&u).unwrap();
            assert_eq!(kinds(&fs), vec!["MalformedTierWord"], "{bad:?}");
            assert_eq!(words(&fs), vec![bad]);
            assert_eq!(fs[0].line, 1);
            assert!(
                fs[0].message.contains(&format!("{bad:?}")),
                "message names the word: {}",
                fs[0].message
            );
            assert!(fs[0].message.contains("canonical word"));
        }
    }

    #[test]
    fn scan_unit_unknown_module_canonical_words() {
        for w in ["personna", "banana", "not_a_module", "definitely_not_a_module"] {
            assert!(parse_tier_word(w).is_none());
            assert!(!is_known_module(w));
            let u = unit("src/a.rs", &format!("@tier({w})\n"));
            let fs = scan_unit(&u).unwrap();
            assert_eq!(kinds(&fs), vec!["UnknownModule"], "{w}");
            assert_eq!(words(&fs), vec![w]);
            assert!(fs[0].message.contains("no fallback allow"));
        }
    }

    #[test]
    fn scan_unit_valid_words_yield_no_finding() {
        // Tier words: the declaration form of docs/tiers/TIER_GATE.md §2.2.
        for w in ["scout", "analyst", "operator", "vault_admin"] {
            let u = unit("src/a.rs", &format!("//! @tier({w}) — build unit declaration\n"));
            assert_eq!(scan_unit(&u).unwrap(), vec![], "{w}");
        }
        // Every module classified in any tier slice: also a clean word, and
        // the tier table agrees (reuse: is_known_module / min_tier_for).
        let mut src = String::new();
        for t in Tier::ALL {
            for m in modules_for(t) {
                assert!(is_known_module(m), "{m} classified");
                assert!(min_tier_for(m).is_some(), "{m} has a minimal tier");
                src.push_str(&format!("// @tier({m})\n"));
            }
        }
        let fs = scan_unit(&unit("src/tiers.rs", &src)).unwrap();
        assert!(fs.is_empty(), "classified modules are valid: {fs:?}");
    }

    #[test]
    fn scan_unit_refuses_empty_path_or_source() {
        assert_eq!(
            scan_unit(&unit("", "// @tier(persona)\n")),
            Err(PassError::BadInput("path"))
        );
        assert_eq!(
            scan_unit(&unit("src/a.rs", "")),
            Err(PassError::BadInput("source"))
        );
        assert_eq!(
            PassError::BadInput("path").to_string(),
            "bad input: path",
            "Display pinned"
        );
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&PassError::BadInput("source"));
    }

    #[test]
    fn scan_unit_one_finding_per_annotation_and_lines_ascend() {
        // Several flagged annotations on ONE line: one finding each, same
        // line — the only way a (path, line) pair repeats.
        let src = "/* @tier(banana) @tier(Scout) */\nlet x = 1;\n// @tier(personna)\n";
        let fs = scan_unit(&unit("src/a.rs", src)).unwrap();
        assert_eq!(
            kinds(&fs),
            vec!["UnknownModule", "MalformedTierWord", "UnknownModule"]
        );
        assert_eq!(lines(&fs), vec![1, 1, 3]);
        assert_eq!(words(&fs), vec!["banana", "Scout", "personna"]);

        // With one annotation per line, lines strictly ascend.
        let one_per_line = "// @tier(banana)\n// @tier(Scout)\n// @tier(personna)\n";
        let fs = scan_unit(&unit("src/a.rs", one_per_line)).unwrap();
        assert_eq!(lines(&fs), vec![1, 2, 3]);
    }

    #[test]
    fn scan_unit_mixed_source_findings_in_ascending_order() {
        let src = "// @tier(scout) valid declaration\n\
                   // @tier(Scout) malformed\n\
                   // @tier(personna) unknown\n\
                   // @tier() empty\n";
        let fs = scan_unit(&unit("src/mixed.rs", src)).unwrap();
        assert_eq!(
            kinds(&fs),
            vec!["MalformedTierWord", "UnknownModule", "EmptyAnnotation"]
        );
        assert_eq!(lines(&fs), vec![2, 3, 4]);
    }

    // ---- check_units() --------------------------------------------------

    #[test]
    fn check_units_merges_in_input_order() {
        let units = vec![
            unit("src/b.rs", "// @tier(Scout)\n// @tier(personna)\n"),
            unit("src/a.rs", "// @tier()\n"),
            unit("src/c.rs", "// @tier(persona)\n"),
        ];
        let fs = check_units(&units).unwrap();
        assert_eq!(
            fs.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
            vec!["src/b.rs", "src/b.rs", "src/a.rs"],
            "units merged in input order, not path-sorted"
        );
        assert_eq!(lines(&fs), vec![1, 2, 1]);
        assert_eq!(
            kinds(&fs),
            vec!["MalformedTierWord", "UnknownModule", "EmptyAnnotation"]
        );
    }

    #[test]
    fn check_units_empty_and_clean_inputs() {
        assert_eq!(check_units(&[]).unwrap(), vec![]);
        let clean = vec![
            unit("src/a.rs", "// @tier(scout)\n// @tier(persona)\n"),
            unit("src/b.rs", "fn f() {}\n"),
        ];
        assert_eq!(check_units(&clean).unwrap(), vec![]);
    }

    #[test]
    fn check_units_duplicate_path_scanned_per_unit_without_dedupe() {
        let src = "// @tier(banana)\n";
        let fs = check_units(&[unit("src/a.rs", src), unit("src/a.rs", src)]).unwrap();
        assert_eq!(fs.len(), 2, "no cross-unit dedupe");
        assert_eq!(fs[0], fs[1], "findings repeat verbatim");
    }

    #[test]
    fn check_units_refuses_on_first_bad_unit() {
        let units = vec![unit("src/a.rs", "ok\n"), unit("", "x\n")];
        assert_eq!(check_units(&units), Err(PassError::BadInput("path")));
    }

    // ---- render_findings() ---------------------------------------------

    #[test]
    fn render_findings_pins_line_format_and_empty_string() {
        let f = PassFinding {
            path: "src/x.rs".to_string(),
            line: 7,
            kind: FindingKind::UnknownModule,
            word: "scout".to_string(),
            message: "M".to_string(),
        };
        assert_eq!(render_findings(&[f]), "src/x.rs:7: [UnknownModule] M\n");
        assert_eq!(render_findings(&[]), "", "empty findings render empty");
        // Multi-finding render: one line per finding, in order, `\n` each.
        let fs = check_units(&[
            unit("src/b.rs", "// @tier(Scout)\n"),
            unit("src/a.rs", "// @tier()\n"),
        ])
        .unwrap();
        let text = render_findings(&fs);
        let mut want = format!(
            "src/b.rs:1: [MalformedTierWord] {}\n",
            message_for(FindingKind::MalformedTierWord, "Scout")
        );
        want.push_str(&format!(
            "src/a.rs:1: [EmptyAnnotation] {}\n",
            message_for(FindingKind::EmptyAnnotation, "")
        ));
        assert_eq!(text, want);
        assert_eq!(text, render_findings(&fs), "render is deterministic");
    }

    #[test]
    fn render_findings_through_units_pins_absolute_format() {
        let fs = scan_unit(&unit("src/a.rs", "// @tier(Scout)\n")).unwrap();
        assert_eq!(
            render_findings(&fs),
            "src/a.rs:1: [MalformedTierWord] tier word \"Scout\" is malformed: not a tier \
             word (scout|analyst|operator|vault_admin) and not a canonical word (lowercase \
             ASCII letters, digits, \"_\") — check the spelling\n"
        );
    }

    // ---- reuse consistency (real tier_gate fns) -------------------------

    #[test]
    fn reuse_parse_tier_word_words_never_yield_a_finding() {
        // §6 reuse-consistency pin, strengthened: a word accepted by
        // parse_tier_word yields no finding at all (so certainly no
        // MalformedTierWord) — and the check calls the real fn.
        for w in ["scout", "analyst", "operator", "vault_admin"] {
            assert!(parse_tier_word(w).is_some());
            let fs = scan_unit(&unit("src/a.rs", &format!("@tier({w})\n"))).unwrap();
            assert!(fs.is_empty(), "{w} must be clean: {fs:?}");
            assert!(!kinds(&fs).contains(&"MalformedTierWord"));
        }
        for junk in ["banana", "Scout", "sco", ""] {
            assert!(parse_tier_word(junk).is_none(), "{junk:?}");
        }
    }

    #[test]
    fn reuse_known_modules_agree_with_tier_table_both_directions() {
        // Forward: every table member is a clean word for the pass and known
        // to the gate (both sides call the real fns; min_tier_for pins the
        // agreeing minimal tier).
        for (t, ms) in TIER_MODULES {
            for m in *ms {
                assert!(is_known_module(m));
                assert!(min_tier_for(m).is_some());
                let _ = t; // table entry context (rank-order table, §8)
                let fs = scan_unit(&unit("src/a.rs", &format!("@tier({m})\n"))).unwrap();
                assert!(fs.is_empty(), "{m} must be clean");
            }
        }
        // Reverse: a canonical word the gate calls unclassified is exactly a
        // word the pass reports UnknownModule.
        for w in ["personna", "not_a_module"] {
            assert!(!is_known_module(w));
            assert_eq!(
                classify_word(w),
                Some(FindingKind::UnknownModule),
                "{w}"
            );
        }
    }

    // ---- codes / diagnostics / serde ------------------------------------

    #[test]
    fn finding_kinds_project_to_tier_diagnostics() {
        use crate::tier_gate::{CODE_BAD_TIER_DECLARATION, CODE_UNKNOWN_MODULE};
        assert_eq!(FindingKind::MalformedTierWord.code(), CODE_BAD_TIER_DECLARATION);
        assert_eq!(FindingKind::EmptyAnnotation.code(), CODE_BAD_TIER_DECLARATION);
        assert_eq!(FindingKind::UnknownModule.code(), CODE_UNKNOWN_MODULE);
        assert_eq!(FindingKind::MalformedTierWord.code(), "E6003");
        assert_eq!(FindingKind::UnknownModule.code(), "E6002");

        let fs = scan_unit(&unit("src/a.rs", "// @tier(personna)\n// @tier(Scout)\n")).unwrap();
        let d_unknown = fs[0].diagnostic();
        assert_eq!(d_unknown.code, "E6002");
        assert_eq!(d_unknown.module, "personna", "module-level diagnostic");
        assert_eq!(
            d_unknown.to_string(),
            format!("E6002 [personna]: {}", fs[0].message)
        );
        let d_malformed = fs[1].diagnostic();
        assert_eq!(d_malformed.code, "E6003");
        assert_eq!(d_malformed.module, "", "declaration-level diagnostic");
        assert_eq!(d_malformed.to_string(), format!("E6003: {}", fs[1].message));
    }

    #[test]
    fn serde_pins_verbatim_wire_names_and_roundtrips() {
        // Kind wire names are verbatim variant names (no rename attribute).
        assert_eq!(
            serde_json::to_string(&FindingKind::MalformedTierWord).unwrap(),
            "\"MalformedTierWord\""
        );
        assert_eq!(
            serde_json::to_string(&FindingKind::EmptyAnnotation).unwrap(),
            "\"EmptyAnnotation\""
        );

        let u = unit("src/a.rs", "// @tier(Scout)\n");
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains("\"path\":\"src/a.rs\""), "{json}");
        assert_eq!(serde_json::from_str::<SourceUnit>(&json).unwrap(), u);

        let fs = scan_unit(&u).unwrap();
        let json = serde_json::to_string(&fs[0]).unwrap();
        assert!(json.contains("\"line\":1"), "{json}");
        assert!(json.contains("\"kind\":\"MalformedTierWord\""), "{json}");
        assert!(json.contains("\"word\":\"Scout\""), "{json}");
        assert_eq!(serde_json::from_str::<PassFinding>(&json).unwrap(), fs[0]);

        // PassError is Serialize-only (batch precedent for &'static str).
        let json = serde_json::to_string(&PassError::BadInput("path")).unwrap();
        assert!(json.contains("BadInput"), "{json}");
        assert!(json.contains("path"), "{json}");
    }

    #[test]
    fn determinism_across_calls_and_input_permutation_of_units() {
        let units = vec![
            unit("src/b.rs", "// @tier(Scout) @tier(personna)\n"),
            unit("src/a.rs", "// @tier()\n// @tier(persona)\n"),
        ];
        let first = check_units(&units).unwrap();
        let second = check_units(&units).unwrap();
        assert_eq!(first, second);
        assert_eq!(render_findings(&first), render_findings(&second));
        let text = render_findings(&first);
        assert_eq!(text.lines().count(), first.len());
        assert!(text.ends_with('\n'), "every finding line is newline-terminated");
    }

    // ---- TierGatePass adapter (B1.1.2 adoption wiring) -------------------

    #[test]
    fn pass_adapter_maps_findings_to_compiler_diagnostics() {
        let src = "@tier(scout)\n@tier(Scout)\n@tier(personna)\n@tier()\n";
        let diags = TierGatePass::new("sample.tl", src).check();
        let codes: Vec<&str> = diags.items.iter().map(|d| d.code).collect();
        assert_eq!(codes, vec!["E6003", "E6002", "E6003"]);
        let lines: Vec<usize> = diags.items.iter().map(|d| d.span.line_col(src).0).collect();
        assert_eq!(lines, vec![2, 3, 4]);
        assert!(diags
            .items
            .iter()
            .all(|d| matches!(d.severity, crate::error::Severity::Error)));
    }

    #[test]
    fn pass_adapter_is_silent_without_findings_and_on_bad_input() {
        assert!(TierGatePass::new("s.tl", "@tier(scout)\n@tier(persona)\n")
            .check()
            .items
            .is_empty());
        // scan_unit refuses empty path/source; the adapter stays a no-op.
        assert!(TierGatePass::new("", "@tier()\n").check().items.is_empty());
        assert!(TierGatePass::new("s.tl", "").check().items.is_empty());
    }

    #[test]
    fn adapter_span_points_at_the_offending_occurrence() {
        let src = "let x = 1;\nlet y = 2; @tier(personna) tail\n";
        let diags = TierGatePass::new("s.tl", src).check();
        let d = &diags.items[0];
        assert_eq!(d.span.line_col(src).0, 2);
        assert_eq!(&src[d.span.start..d.span.end], "@tier(personna)");
    }

    // ---- build-level gate (T-123) ----------------------------------------

    fn build(name: &str, units: &[(&str, &str)]) -> BuildUnit {
        BuildUnit {
            name: name.to_string(),
            units: units.iter().map(|(p, s)| unit(p, s)).collect(),
        }
    }

    fn grant(id: &str, unit_name: &str, mods: &[&str], expires_ms: i64) -> Waiver {
        Waiver {
            id: id.to_string(),
            build_unit: unit_name.to_string(),
            modules: mods.iter().map(|s| s.to_string()).collect(),
            expires_ms,
        }
    }

    fn gate_codes(ds: &[TierDiagnostic]) -> Vec<&str> {
        ds.iter().map(|d| d.code.as_str()).collect()
    }

    fn gate_modules(ds: &[TierDiagnostic]) -> Vec<&str> {
        ds.iter().map(|d| d.module.as_str()).collect()
    }

    #[test]
    fn build_gate_denies_tier_violation_across_units() {
        // Declaration in one unit, the offending reference in another: the
        // build-level run sees both.
        let b = build(
            "b-mixture",
            &[
                ("a.tl", "//! @tier(analyst)\n"),
                ("b.tl", "// @tier(persona)\n"),
            ],
        );
        let r = run_build_gate(&b, &[], 1_000);
        assert!(!r.ok, "operator-only ref under analyst must deny");
        assert_eq!(r.tier, Tier::Analyst);
        assert_eq!(gate_codes(&r.errors), vec!["E6001"]);
        assert_eq!(gate_modules(&r.errors), vec!["persona"]);
        assert!(
            r.errors[0].message.contains("operator"),
            "{}",
            r.errors[0].message
        );
        assert!(r.errors[0].message.contains("analyst"));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn build_gate_missing_declaration_is_scout() {
        let scout_ok = build(
            "b-none",
            &[(
                "a.tl",
                "// @tier(caveats) @tier(raw_store) @tier(source_registry)\n",
            )],
        );
        let r = run_build_gate(&scout_ok, &[], 0);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert_eq!(r.tier, Tier::Scout, "missing @tier ⇒ Scout (tightest)");

        let denied = build("b-none", &[("a.tl", "// @tier(forecast)\n")]);
        let r = run_build_gate(&denied, &[], 0);
        assert!(!r.ok);
        assert_eq!(r.tier, Tier::Scout);
        assert_eq!(gate_modules(&r.errors), vec!["forecast"]);
    }

    #[test]
    fn build_gate_waiver_in_force_admits_and_warns_w6001() {
        let b = build(
            "b-stealth",
            &[
                ("a.tl", "@tier(scout)\n@tier_waiver(id: w-1)\n"),
                ("b.tl", "@tier(persona)\n"),
            ],
        );
        let waivers = [grant("w-1", "b-stealth", &["persona"], 2_000)];
        let r = run_build_gate(&b, &waivers, 1_000);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert!(r.errors.is_empty(), "the live claim resolved: no E6005");
        assert_eq!(r.tier, Tier::Scout);
        assert_eq!(gate_codes(&r.warnings), vec!["W6001"]);
        assert_eq!(gate_modules(&r.warnings), vec!["persona"]);
        assert!(
            r.warnings[0].message.contains("w-1"),
            "{}",
            r.warnings[0].message
        );
    }

    #[test]
    fn build_gate_waiver_scope_and_module_match_are_exact() {
        let b = build("b-mine", &[("a.tl", "@tier(scout) @tier(persona)\n")]);
        // A live grant for another build unit does not cover.
        let other_unit = [grant("w-1", "b-other", &["persona"], 10_000)];
        let r = run_build_gate(&b, &other_unit, 1_000);
        assert!(!r.ok);
        assert_eq!(gate_codes(&r.errors), vec!["E6001"]);
        assert!(r.warnings.is_empty());
        // A live grant not listing the module does not cover either.
        let other_module = [grant("w-1", "b-mine", &["shred"], 10_000)];
        let r = run_build_gate(&b, &other_module, 1_000);
        assert!(!r.ok);
        assert_eq!(gate_codes(&r.errors), vec!["E6001"]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn build_gate_expired_waiver_denies_at_boundary() {
        let b = build("b-stealth", &[("a.tl", "@tier(scout)\n@tier(persona)\n")]);
        let waivers = [grant("w-1", "b-stealth", &["persona"], 2_000)];
        // now < expires ⇒ live ⇒ admitted + W6001.
        let before = run_build_gate(&b, &waivers, 1_999);
        assert!(before.ok, "errors: {:?}", before.errors);
        assert_eq!(gate_codes(&before.warnings), vec!["W6001"]);
        // now == expires ⇒ expired (hard boundary, §3.3) ⇒ E6001, no warning.
        let at = run_build_gate(&b, &waivers, 2_000);
        assert!(!at.ok);
        assert_eq!(gate_codes(&at.errors), vec!["E6001"]);
        assert!(at.warnings.is_empty());
        // now > expires ⇒ same denial.
        let after = run_build_gate(&b, &waivers, 2_001);
        assert!(!after.ok);
        assert_eq!(gate_codes(&after.errors), vec!["E6001"]);
        assert!(after.warnings.is_empty());
    }

    #[test]
    fn build_gate_claimed_but_missing_or_expired_record_errors_e6005() {
        let b = build(
            "b-stealth",
            &[(
                "a.tl",
                "@tier(scout)\n@tier_waiver(id: w-9)\n@tier_waiver(w-bare)\n",
            )],
        );
        // Both claims unresolvable ⇒ one E6005 each (module-level "" sorts
        // first); there is no module ref here, so nothing else fires.
        let r = run_build_gate(&b, &[], 1_000);
        assert!(!r.ok);
        assert_eq!(gate_codes(&r.errors), vec!["E6005", "E6005"]);
        assert_eq!(gate_modules(&r.errors), vec!["", ""]);
        assert!(r
            .errors
            .iter()
            .all(|d| d.message.contains("record missing or expired")));

        // Live records clear both claims (`id:` form and bare form).
        let waivers = [
            grant("w-9", "b-stealth", &["persona"], 2_000),
            grant("w-bare", "b-stealth", &[], 2_000),
        ];
        let r = run_build_gate(&b, &waivers, 1_000);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert!(r.warnings.is_empty(), "no offending ref ⇒ no W6001");
    }

    #[test]
    fn build_gate_stale_claim_plus_violation_denies_both_ways() {
        let b = build(
            "b-stealth",
            &[(
                "a.tl",
                "@tier(scout)\n@tier_waiver(id: w-1)\n@tier(persona)\n",
            )],
        );
        let waivers = [grant("w-1", "b-stealth", &["persona"], 500)];
        let r = run_build_gate(&b, &waivers, 1_000);
        assert!(!r.ok);
        // E6005 for the stale claim (module "") sorts before E6001 [persona].
        assert_eq!(gate_codes(&r.errors), vec!["E6005", "E6001"]);
        assert_eq!(gate_modules(&r.errors), vec!["", "persona"]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn collect_build_inputs_pins_the_extraction_rules() {
        let b = build(
            "b-x",
            &[
                (
                    "a.tl",
                    "@tier(analyst) extra @tier(persona)\n@tier(scout)\n\
                     @tier_waiver(id: w-1) @tier_waiver(w-2)\n",
                ),
                (
                    "b.tl",
                    "@tier(raw_store)\n@tier(personna)\n@tier(Scout)\n@tier()\n\
                     @tier_waiver(id: w-3)\n",
                ),
            ],
        );
        let i = collect_build_inputs(&b);
        assert_eq!(
            i.declared.as_deref(),
            Some("analyst"),
            "first declaration wins"
        );
        assert_eq!(
            i.referenced_modules,
            vec!["persona", "raw_store", "personna"],
            "canonical non-tier words in scan order; malformed/empty excluded"
        );
        assert_eq!(i.claimed_waiver_ids, vec!["w-1", "w-2", "w-3"]);

        // Unknown canonical ref ⇒ E6002 at build level (no fallback allow);
        // each unresolvable claim ⇒ E6005.
        let r = run_build_gate(&b, &[], 0);
        assert_eq!(
            gate_codes(&r.errors),
            vec!["E6005", "E6005", "E6005", "E6001", "E6002"]
        );
        assert_eq!(
            gate_modules(&r.errors),
            vec!["", "", "", "persona", "personna"]
        );
    }

    #[test]
    fn build_gate_report_is_deterministic_and_order_invariant() {
        let waivers = [grant("w-1", "b-d", &["vault"], 5_000)];
        let mk = |refs: &str| build("b-d", &[("a.tl", "@tier(operator)\n"), ("b.tl", refs)]);
        let base = run_build_gate(
            &mk("@tier(vault) @tier(nope) @tier(persona)\n"),
            &waivers,
            1_000,
        );
        assert_eq!(gate_codes(&base.warnings), vec!["W6001"]);
        assert_eq!(gate_modules(&base.errors), vec!["nope"]);
        // Same call again, a reordered reference list, and swapped unit order
        // all yield the identical report.
        assert_eq!(
            run_build_gate(
                &mk("@tier(vault) @tier(nope) @tier(persona)\n"),
                &waivers,
                1_000
            ),
            base
        );
        assert_eq!(
            run_build_gate(
                &mk("@tier(nope) @tier(persona) @tier(vault)\n"),
                &waivers,
                1_000
            ),
            base
        );
        let swapped = build(
            "b-d",
            &[
                ("b.tl", "@tier(vault) @tier(nope) @tier(persona)\n"),
                ("a.tl", "@tier(operator)\n"),
            ],
        );
        assert_eq!(run_build_gate(&swapped, &waivers, 1_000), base);
    }

    #[test]
    fn build_gate_empty_build_and_full_slice_compile() {
        let empty = BuildUnit {
            name: "b-empty".to_string(),
            units: vec![],
        };
        let r = run_build_gate(&empty, &[], 0);
        assert!(r.ok);
        assert_eq!(r.tier, Tier::Scout);

        // The full VaultAdmin slice across two units compiles clean.
        let slice = modules_for(Tier::VaultAdmin);
        assert_eq!(slice.len(), 40);
        let mut a = String::from("@tier(vault_admin)\n");
        for m in &slice[..20] {
            a.push_str(&format!("@tier({m})\n"));
        }
        let mut b_src = String::new();
        for m in &slice[20..] {
            b_src.push_str(&format!("@tier({m})\n"));
        }
        let b = build("b-v", &[("a.tl", a.as_str()), ("b.tl", b_src.as_str())]);
        let r = run_build_gate(&b, &[], 0);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert!(r.errors.is_empty() && r.warnings.is_empty());
        assert_eq!(r.tier, Tier::VaultAdmin);
    }

    #[test]
    fn report_diagnostics_projects_codes_and_severities() {
        let b = build(
            "b-stealth",
            &[(
                "a.tl",
                "@tier(scout) @tier(persona) @tier_waiver(id: w-9)\n",
            )],
        );
        // Deny side: errors become error diagnostics with static codes.
        let r = run_build_gate(&b, &[], 1_000);
        let diags = report_diagnostics(&r);
        assert!(diags.has_errors());
        assert_eq!(diags.error_count(), 2, "E6005 + E6001");
        assert_eq!(diags.warning_count(), 0);
        assert_eq!(
            diags.items.iter().map(|d| d.code).collect::<Vec<_>>(),
            vec!["E6005", "E6001"]
        );
        assert!(diags
            .items
            .iter()
            .all(|d| matches!(d.severity, crate::error::Severity::Error)));
        assert!(diags.items.iter().all(|d| d.span.start == 0 && d.span.end == 0));

        // Admit side: the waiver warning becomes a warning diagnostic.
        let waivers = [grant("w-9", "b-stealth", &["persona"], 2_000)];
        let r = run_build_gate(&b, &waivers, 1_000);
        let diags = report_diagnostics(&r);
        assert!(!diags.has_errors());
        assert_eq!(diags.warning_count(), 1);
        assert_eq!(diags.items[0].code, "W6001");
        assert!(matches!(
            diags.items[0].severity,
            crate::error::Severity::Warning
        ));
    }

    #[test]
    fn build_unit_single_constructor_runs_clean() {
        let s = BuildUnit::single("b-single", unit("a.tl", "@tier(scout)\n"));
        assert_eq!(s.name, "b-single");
        assert_eq!(s.units.len(), 1);
        let r = run_build_gate(&s, &[], 0);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert_eq!(r.tier, Tier::Scout);
    }

    #[test]
    fn build_gate_types_serde_roundtrip() {
        let b = build("b-x", &[("a.tl", "@tier(scout)\n")]);
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("\"name\":\"b-x\""), "{json}");
        assert_eq!(serde_json::from_str::<BuildUnit>(&json).unwrap(), b);

        let i = collect_build_inputs(&b);
        let json = serde_json::to_string(&i).unwrap();
        assert!(json.contains("\"declared\":\"scout\""), "{json}");
        assert_eq!(serde_json::from_str::<BuildGateInputs>(&json).unwrap(), i);
    }
}
