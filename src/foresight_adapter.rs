//! Foresight corpus adapter — fixture-only (task `B4.4` · frozen interface §9 ·
//! B4.4.1–B4.4.3).
//!
//! Offline adapter for public foresight products. The documented sources are
//! the **Global Trends archive** and **RAND** (B4.4.1). The adapter exists so
//! the intel stack can pin the *shape* of foresight records — id, source,
//! title, year, summary, url — and the provenance wiring around them
//! (B4.4.2), while everything stays reproducible and testable without any
//! network.
//!
//! # NO network anywhere
//!
//! This module has no HTTP client, no sockets, no DNS, no filesystem access
//! and no environment lookups. The only corpus it ever parses is
//! [`synthetic_fixture`], an inline `&'static str`. Nothing here fetches
//! anything, ever — that is a design invariant of the adapter, not a
//! configuration detail.
//!
//! # The fixture is a *synthetic sample — not fetched data*
//!
//! [`synthetic_fixture`] returns a hand-written JSON array of at least two
//! records, deliberately labelled a **synthetic sample — not fetched data**
//! (the machine-readable marker is [`SYNTHETIC_LABEL`]). Its titles and
//! summaries are placeholders written to exercise parsing, validation and
//! provenance — they are not excerpts from, and not summaries of, any real
//! publication, and they must never be cited as sourced intelligence or
//! quoted as if retrieved. The `source` fields carry only the two documented
//! source names; the `url` fields are illustrative base-domain placeholders
//! of those sources (see the module docs of [`synthetic_fixture`]).
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * **"Empty" = empty or whitespace-only** for every required text field
//!   (in-repo precedent: `liaison`, `unknowns`, `watchlist`). Stored strings
//!   are kept **verbatim** — the adapter never trims or rewrites a document.
//! * **Validation order is pinned**: documents are scanned in array order;
//!   within a document, fields are checked in declaration order — `id`,
//!   `source`, `title`, `year` (range), `summary`, `url`. The first violation
//!   found is the one reported.
//! * **Duplicate ids** (byte-exact, case-sensitive) are detected *after* the
//!   duplicate-bearing document itself validates: two documents that are both
//!   invalid report the first document's field error, not `DupId`.
//! * **Year bounds are inclusive**: `1900..=2100`.
//! * `[]` parses to an empty corpus (`Ok(vec![])`) — an empty array is valid
//!   JSON of the right shape; the ≥ 2 floor is a property of the shipped
//!   fixture, not of the parser.
//! * **Parse failure is total**: any `serde_json` failure — malformed JSON,
//!   wrong top-level shape, missing field, wrong field type — collapses to
//!   [`AdapterError::BadInput`]`("json")`. Field-level validation (blank
//!   fields, year range) happens only on successfully deserialized documents.
//! * [`provenance_of`] is **fallible** (`Result`) although §9 prints an
//!   infallible signature: the sister clause "empty label → `BadInput`" has
//!   no error channel otherwise. A blank retrieval label is refused rather
//!   than silently minted into a provenance stamp — fail-closed, consistent
//!   with the rest of the interface. See the function docs.
//!
//! Nothing here touches the clock, global state or I/O: identical inputs
//! always produce identical outputs.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Fixture — documented sources + synthetic sample (B4.4.1, B4.4.3) ────────

/// Machine-readable marker for the fixture's status: a **synthetic sample —
/// not fetched data**.
///
/// Pinned in tests so the "this was never fetched" contract cannot be
/// softened by accident (additive symbol; mirrors the
/// `watchlist::VERIFY_BEFORE_ADDING` marker contract).
pub const SYNTHETIC_LABEL: &str = "synthetic sample — not fetched data";

/// Inline synthetic fixture corpus: a JSON array of [`ForesightDoc`] records.
///
/// **This is a synthetic sample — not fetched data.** The records are
/// hand-written to exercise the adapter (parsing, field pins, validation
/// ordering, provenance); their `source` fields use the two documented source
/// names ("Global Trends archive", "RAND") and their `url` fields are
/// illustrative base-domain placeholders of those two sources. Nothing in
/// this corpus was retrieved over a network, and nothing in it may be quoted
/// as a real assessment.
const SYNTHETIC_FIXTURE: &str = r#"[
  {
    "id": "gt-synthetic-2020-01",
    "source": "Global Trends archive",
    "title": "Synthetic sample: shared institutions under multipolar strain",
    "year": 2020,
    "summary": "Hand-written placeholder exercising the adapter end to end; not an excerpt from, and not a summary of, any published assessment.",
    "url": "https://www.dni.gov/"
  },
  {
    "id": "gt-synthetic-2021-02",
    "source": "Global Trends archive",
    "title": "Synthetic sample: technology diffusion and governance lag",
    "year": 2021,
    "summary": "Second placeholder record; demonstrates multi-document parsing, source pinning and per-document validation ordering.",
    "url": "https://www.dni.gov/"
  },
  {
    "id": "rand-synthetic-2024-01",
    "source": "RAND",
    "title": "Synthetic sample: long-horizon risk registers for planners",
    "year": 2024,
    "summary": "Third placeholder record; demonstrates that the fixture spans both documented sources. Not fetched data.",
    "url": "https://www.rand.org/"
  }
]"#;

/// The inline fixture corpus, as a JSON array of [`ForesightDoc`] records.
///
/// **Synthetic sample — not fetched data** (see [`SYNTHETIC_LABEL`]): written
/// by hand to exercise this adapter offline. At least two records; the
/// shipped fixture has three and spans both documented sources (Global Trends
/// archive, RAND). The returned `&'static str` is byte-identical on every
/// call — no clock, no I/O, no randomness.
pub fn synthetic_fixture() -> &'static str {
    SYNTHETIC_FIXTURE
}

// ── Adapter: parse + validate (B4.4.1) ───────────────────────────────────────

/// One foresight product record, in the adapter's neutral shape.
///
/// `source` is expected to carry the documented source name (e.g. "Global
/// Trends archive", "RAND") and `url` the locator; both are validated only
/// for non-blankness here — the adapter is offline and does not resolve or
/// fetch anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForesightDoc {
    /// Stable record id (unique within a corpus; compared byte-exact).
    pub id: String,
    /// Documented source name, e.g. "Global Trends archive" or "RAND".
    pub source: String,
    /// Record title, as carried by the record.
    pub title: String,
    /// Publication year; must lie in `1900..=2100`.
    pub year: u32,
    /// Short summary text.
    pub summary: String,
    /// Locator for the source (illustrative in the synthetic fixture).
    pub url: String,
}

/// Parse and validate a foresight corpus in the fixture JSON shape.
///
/// Steps, in pinned order:
/// 1. `serde_json` deserialization of a top-level array of [`ForesightDoc`].
///    Any failure — malformed JSON, wrong top-level shape, missing field,
///    wrong field type — is `Err(BadInput("json"))`.
/// 2. Per document, in array order: field checks in declaration order —
///    `id`, `source`, `title` non-blank; `year` within `1900..=2100`
///    (inclusive); `summary`, `url` non-blank. First violation wins; blank
///    payloads are the offending field names.
/// 3. Duplicate detection: byte-exact (case-sensitive) ids in array order;
///    the first already-seen id is `Err(DupId)`. A document that is itself
///    invalid reports its field error before its duplicate status.
///
/// `[]` returns `Ok(vec![])` (see module docs). Stored strings are never
/// trimmed. No network, no I/O.
pub fn parse_fixture(json: &str) -> Result<Vec<ForesightDoc>, AdapterError> {
    let docs: Vec<ForesightDoc> =
        serde_json::from_str(json).map_err(|_| AdapterError::BadInput("json"))?;

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for doc in &docs {
        validate_doc(doc)?;
        if !seen.insert(doc.id.as_str()) {
            return Err(AdapterError::DupId);
        }
    }
    Ok(docs)
}

/// Per-document checks, in the pinned declaration order (see [`parse_fixture`]).
fn validate_doc(doc: &ForesightDoc) -> Result<(), AdapterError> {
    if doc.id.trim().is_empty() {
        return Err(AdapterError::BadInput("id"));
    }
    if doc.source.trim().is_empty() {
        return Err(AdapterError::BadInput("source"));
    }
    if doc.title.trim().is_empty() {
        return Err(AdapterError::BadInput("title"));
    }
    if !(1900..=2100).contains(&doc.year) {
        return Err(AdapterError::BadInput("year"));
    }
    if doc.summary.trim().is_empty() {
        return Err(AdapterError::BadInput("summary"));
    }
    if doc.url.trim().is_empty() {
        return Err(AdapterError::BadInput("url"));
    }
    Ok(())
}

// ── Provenance wiring (B4.4.2) ───────────────────────────────────────────────

/// Provenance stamp for a foresight record: where it came from, and under
/// which retrieval label it entered the stack.
///
/// For fixture data the label documents *that it is fixture data and how it
/// was produced* — the fixture was never fetched, and the label is the
/// operator's marker for that (e.g. a run id or a fixture-set name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Copied verbatim from the record's `source` field.
    pub source: String,
    /// Copied verbatim from the record's `url` field.
    pub url: String,
    /// The retrieval label supplied by the caller, stored verbatim.
    pub retrieved_label: String,
}

/// Wire a [`Provenance`] stamp for `doc` under the retrieval label `label`.
///
/// `provenance.source = doc.source` and `provenance.url = doc.url`, both
/// copied verbatim; `retrieved_label` is the caller's `label`, stored
/// verbatim (never trimmed).
///
/// A blank (empty or whitespace-only) label is `Err(BadInput("label"))` —
/// fail-closed: a provenance stamp whose retrieval label says nothing while
/// claiming to say something about retrieval is evidence-integrity-negative,
/// so it is refused instead of minted.
///
/// # Signature note (§9 deviation, argued)
///
/// §9 prints `-> Provenance` but also specifies "empty label → `BadInput`" —
/// the two clauses cannot both hold, because an infallible signature has no
/// error channel. This function follows the behavioral clause and returns
/// `Result<Provenance, AdapterError>`, consistent with every other fallible
/// operation in the frozen interface (e.g. §9 `parse_fixture`, §5 `get`).
pub fn provenance_of(doc: &ForesightDoc, label: &str) -> Result<Provenance, AdapterError> {
    if label.trim().is_empty() {
        return Err(AdapterError::BadInput("label"));
    }
    Ok(Provenance {
        source: doc.source.clone(),
        url: doc.url.clone(),
        retrieved_label: label.to_string(),
    })
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the foresight adapter.
///
/// `Serialize` is derived (wire form = snake_case: `"dup_id"` /
/// `{"bad_input":"id"}`). `Deserialize` is not — the `BadInput(&'static str)`
/// payload cannot be deserialized into a `'static` lifetime; this mirrors the
/// in-repo precedent (`clearness_gate::ClearnessError`,
/// `unknowns::UnknownsError`, `watchlist::WatchlistError`).
///
/// `BadInput` payloads are the offending field / reason tokens: `"json"`,
/// `"id"`, `"source"`, `"title"`, `"year"`, `"summary"`, `"url"`, `"label"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterError {
    /// A named input was missing, blank, malformed or outside its valid
    /// domain; carries the field / reason token.
    BadInput(&'static str),
    /// Two documents in the corpus share an id (byte-exact comparison).
    DupId,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::BadInput(reason) => {
                write!(f, "invalid foresight-adapter input: {reason}")
            }
            AdapterError::DupId => {
                write!(f, "duplicate foresight document id")
            }
        }
    }
}

impl std::error::Error for AdapterError {}

// ── Tests — fixture slice (B4.4.3) ───────────────────────────────────────────
//
// Every corpus consumed below comes from `synthetic_fixture()` (a synthetic
// sample — not fetched data) or from hand-built JSON/structs; nothing is
// fetched, and no test touches a network, a socket or the filesystem.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build one JSON record with every field spelled out.
    #[allow(clippy::too_many_arguments)]
    fn json_doc(id: &str, source: &str, title: &str, year: u32, summary: &str, url: &str) -> String {
        json!({
            "id": id, "source": source, "title": title,
            "year": year, "summary": summary, "url": url,
        })
        .to_string()
    }

    /// Wrap JSON records into one array.
    fn wrap(records: &[String]) -> String {
        format!("[{}]", records.join(","))
    }

    /// A valid in-memory record (fields all fine), for provenance tests.
    fn valid_doc() -> ForesightDoc {
        ForesightDoc {
            id: "t-1".to_string(),
            source: "RAND".to_string(),
            title: "t".to_string(),
            year: 2020,
            summary: "s".to_string(),
            url: "https://www.rand.org/".to_string(),
        }
    }

    #[test]
    fn synthetic_fixture_is_labelled_synthetic_sample_not_fetched() {
        assert!(SYNTHETIC_LABEL.contains("synthetic sample"));
        assert!(SYNTHETIC_LABEL.contains("not fetched data"));
        let fixture = synthetic_fixture();
        let docs = parse_fixture(fixture).expect("fixture must parse");
        assert!(docs.len() >= 2, "fixture floor is ≥ 2 docs, got {}", docs.len());
        assert_eq!(fixture, SYNTHETIC_FIXTURE, "accessor returns the inline const");
    }

    #[test]
    fn synthetic_fixture_uses_only_documented_sources() {
        let docs = parse_fixture(synthetic_fixture()).expect("fixture must parse");
        let mut seen_gt = false;
        let mut seen_rand = false;
        for doc in &docs {
            match doc.source.as_str() {
                "Global Trends archive" => seen_gt = true,
                "RAND" => seen_rand = true,
                other => panic!("undocumented source in fixture: {other:?}"),
            }
        }
        assert!(seen_gt, "fixture must exercise the Global Trends archive source");
        assert!(seen_rand, "fixture must exercise the RAND source");
    }

    #[test]
    fn parse_synthetic_sample_pins_count_and_fields() {
        let docs = parse_fixture(synthetic_fixture()).expect("fixture must parse");
        assert_eq!(docs.len(), 3);
        let ids: Vec<&str> = docs.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(
            ids,
            ["gt-synthetic-2020-01", "gt-synthetic-2021-02", "rand-synthetic-2024-01"]
        );
        let years: Vec<u32> = docs.iter().map(|d| d.year).collect();
        assert_eq!(years, [2020, 2021, 2024]);
        assert_eq!(docs[0].source, "Global Trends archive");
        assert_eq!(docs[2].source, "RAND");
        for doc in &docs {
            assert!(!doc.title.trim().is_empty());
            assert!(!doc.summary.trim().is_empty());
            assert!(!doc.url.trim().is_empty());
            assert!(doc.title.starts_with("Synthetic sample:"), "titles must be self-labelling");
        }
    }

    #[test]
    fn parse_synthetic_sample_is_deterministic() {
        let a = parse_fixture(synthetic_fixture()).expect("parse a");
        let b = parse_fixture(synthetic_fixture()).expect("parse b");
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "re-serialization must be byte-identical across runs"
        );
    }

    #[test]
    fn serde_round_trip_foresight_doc_and_provenance() {
        let docs = parse_fixture(synthetic_fixture()).expect("fixture must parse");
        let encoded = serde_json::to_string(&docs).unwrap();
        let decoded: Vec<ForesightDoc> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, docs);

        let prov = provenance_of(&docs[0], "fixture-set b12").unwrap();
        let encoded = serde_json::to_string(&prov).unwrap();
        let decoded: Provenance = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, prov);
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            value,
            json!({
                "source": "Global Trends archive",
                "url": "https://www.dni.gov/",
                "retrieved_label": "fixture-set b12",
            }),
            "wire shape (field set) pinned; object key order is not part of the contract"
        );
    }

    #[test]
    fn parse_rejects_bad_json_as_bad_input_json() {
        for bad in [
            "",
            "not json at all",
            "{}",       // object, not array
            "42",       // scalar, not array
            "[{}]",     // missing every field
            "[42]",     // element not a record
            "[{\"id\":\"x\",\"source\":\"RAND\",\"title\":\"t\",\"year\":\"2020\",\"summary\":\"s\",\"url\":\"u\"}]", // year wrong type
            "[{\"id\":\"x\",\"source\":\"RAND\",\"title\":\"t\",\"year\":2020,\"summary\":\"s\"}]", // url missing
        ] {
            assert_eq!(
                parse_fixture(bad),
                Err(AdapterError::BadInput("json")),
                "input was {bad:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_blank_fields_with_field_name_tokens() {
        for (field, token) in [
            ("id", "id"),
            ("source", "source"),
            ("title", "title"),
            ("summary", "summary"),
            ("url", "url"),
        ] {
            for blank in ["", "   ", "\t\n"] {
                let mut rec = json!({
                    "id": "t-1", "source": "RAND", "title": "t",
                    "year": 2020, "summary": "s", "url": "https://www.rand.org/",
                });
                rec[field] = json!(blank);
                let corpus = format!("[{}]", rec);
                assert_eq!(
                    parse_fixture(&corpus),
                    Err(AdapterError::BadInput(token)),
                    "field {field:?} blanked with {blank:?} must report {token:?}"
                );
            }
        }
    }

    #[test]
    fn blank_check_does_not_trim_stored_values() {
        let rec = json_doc("  t-1  ", " RAND ", " t ", 2020, " s ", " u ");
        let docs = parse_fixture(&wrap(&[rec])).expect("padded but non-blank parses");
        assert_eq!(docs[0].id, "  t-1  ", "stored verbatim, never trimmed");
        assert_eq!(docs[0].source, " RAND ");
        assert_eq!(docs[0].title, " t ");
        assert_eq!(docs[0].summary, " s ");
        assert_eq!(docs[0].url, " u ");
    }

    #[test]
    fn parse_rejects_year_outside_pinned_inclusive_range() {
        let rec = |year: u32| json_doc("t-1", "RAND", "t", year, "s", "u");
        assert_eq!(
            parse_fixture(&wrap(&[rec(1899)])),
            Err(AdapterError::BadInput("year"))
        );
        assert_eq!(
            parse_fixture(&wrap(&[rec(2101)])),
            Err(AdapterError::BadInput("year"))
        );
        // Inclusive boundaries are accepted.
        assert!(parse_fixture(&wrap(&[rec(1900)])).is_ok());
        assert!(parse_fixture(&wrap(&[rec(2100)])).is_ok());
    }

    #[test]
    fn parse_rejects_duplicate_ids_byte_exact() {
        let a = json_doc("dup-1", "RAND", "t", 2020, "s", "u");
        let b = json_doc("dup-1", "RAND", "t2", 2021, "s2", "u2");
        assert_eq!(
            parse_fixture(&wrap(&[a.clone(), b])),
            Err(AdapterError::DupId)
        );
        // Case-sensitivity: differing case is NOT a duplicate (byte-exact).
        let upper = json_doc("DUP-1", "RAND", "t2", 2021, "s2", "u2");
        assert!(parse_fixture(&wrap(&[a, upper])).is_ok());
    }

    #[test]
    fn parse_empty_array_is_a_valid_empty_corpus() {
        let docs = parse_fixture("[]").expect("empty array is valid");
        assert!(docs.is_empty());
    }

    #[test]
    fn validation_order_is_declaration_order_within_a_document() {
        // source blank AND year out of range → source (declaration order).
        let both = json_doc("t-1", "   ", "t", 1800, "s", "u");
        assert_eq!(
            parse_fixture(&wrap(&[both])),
            Err(AdapterError::BadInput("source"))
        );
        // year out of range AND summary blank → year (year precedes summary).
        let both = json_doc("t-1", "RAND", "t", 1800, " ", "u");
        assert_eq!(
            parse_fixture(&wrap(&[both])),
            Err(AdapterError::BadInput("year"))
        );
        // summary blank AND url blank → summary (summary precedes url).
        let both = json_doc("t-1", "RAND", "t", 2020, " ", "");
        assert_eq!(
            parse_fixture(&wrap(&[both])),
            Err(AdapterError::BadInput("summary"))
        );
    }

    #[test]
    fn documents_are_scanned_in_array_order_first_violation_wins() {
        let good = json_doc("a-1", "RAND", "t", 2020, "s", "u");
        let bad_year = json_doc("b-2", "RAND", "t", 1800, "s", "u");
        // Second doc invalid, third duplicates the first → year error first.
        assert_eq!(
            parse_fixture(&wrap(&[good.clone(), bad_year, good])),
            Err(AdapterError::BadInput("year"))
        );
    }

    #[test]
    fn validation_of_the_duplicate_precedes_dup_reporting() {
        let a = json_doc("dup-2", "RAND", "t", 2020, "s", "u");
        // Duplicate id, but its own title is blank → title error, not DupId.
        let b = json_doc("dup-2", "RAND", " ", 2021, "s2", "u2");
        assert_eq!(
            parse_fixture(&wrap(&[a, b])),
            Err(AdapterError::BadInput("title"))
        );
    }

    #[test]
    fn provenance_wires_source_url_and_label_fields() {
        let doc = valid_doc();
        let prov = provenance_of(&doc, "fixture-run-2026-09-11").unwrap();
        assert_eq!(prov.source, doc.source);
        assert_eq!(prov.url, doc.url);
        assert_eq!(prov.retrieved_label, "fixture-run-2026-09-11");
        // And through the fixture corpus end to end:
        let docs = parse_fixture(synthetic_fixture()).unwrap();
        let prov = provenance_of(&docs[2], "synthetic-sample").unwrap();
        assert_eq!(prov.source, "RAND");
        assert_eq!(prov.url, "https://www.rand.org/");
        assert_eq!(prov.retrieved_label, "synthetic-sample");
    }

    #[test]
    fn provenance_rejects_blank_label() {
        let doc = valid_doc();
        for blank in ["", "   ", "\t"] {
            assert_eq!(
                provenance_of(&doc, blank),
                Err(AdapterError::BadInput("label")),
                "label {blank:?} must be refused"
            );
        }
    }

    #[test]
    fn provenance_stores_label_verbatim_and_is_deterministic() {
        let doc = valid_doc();
        let padded = " fixture-run ";
        let a = provenance_of(&doc, padded).unwrap();
        let b = provenance_of(&doc, padded).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.retrieved_label, " fixture-run ", "verbatim, never trimmed");
    }

    #[test]
    fn error_display_pins() {
        assert_eq!(
            AdapterError::BadInput("id").to_string(),
            "invalid foresight-adapter input: id"
        );
        assert_eq!(
            AdapterError::DupId.to_string(),
            "duplicate foresight document id"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(AdapterError::DupId);
        assert_eq!(boxed.to_string(), "duplicate foresight document id");
    }

    #[test]
    fn error_serde_wire_tokens() {
        assert_eq!(
            serde_json::to_string(&AdapterError::BadInput("id")).unwrap(),
            "{\"bad_input\":\"id\"}"
        );
        assert_eq!(serde_json::to_string(&AdapterError::DupId).unwrap(), "\"dup_id\"");
    }
}
