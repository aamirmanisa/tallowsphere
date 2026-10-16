//! `tallow extract` — produce `tallow.extraction_row.v1` rows from **local** input.
//!
//! # Why this verb never egresses
//!
//! `schemas/tallow/extraction-row.schema.json` pins `"mode": {"enum":
//! ["local_mock"]}` and `non_claims.{live_scraping, external_dataset,
//! production_ready}` as `const: false`. A verb that fetched live URLs and wrote
//! these rows would be asserting `live_scraping: false` about data it had just
//! scraped live — a lying artifact. So `extract` reads HTML you already hold and
//! says so. A live variant is a **claim-policy** change (what may this artifact
//! assert?), not a feature switch, which is why it is not a flag here.
//!
//! # Why it reuses rather than reimplements
//!
//! Selector application lives in `browser::llm_extract` and nowhere else: this
//! module calls [`LlmExtractor::extract_with_schema`] (the public half of the
//! extractor's own `execute_schema`) and [`v1_schema_metadata`] (the same parser
//! as [`ExtractionSchema::from_v1_json`]). A second implementation of "apply this
//! field's selectors" would be a second answer to "what did this page yield".
//!
//! # The gate
//!
//! Output is JSONL and is meant to be checked by the repository's own validator:
//! `scripts/validate_extraction_rows.py --rows <out> --fail-on-invalid`. Rows are
//! written all-or-nothing (temp file + rename), so a failed run leaves no
//! half-written artifact behind for the validator to judge.
//!
//! Exit codes, mirroring the set declared at the top of `src/main.rs`:
//! `0` = rows written · `1` = the schema or the page yielded nothing usable
//! (the offending field is named) · `64` = usage error or unreadable file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};

use crate::browser::llm_extract::{ExtractionSchema, LlmExtractor, v1_schema_metadata};

const EXIT_OK: i32 = 0;
const EXIT_INVALID: i32 = 1;
const EXIT_USAGE: i32 = 64;

const ROW_SCHEMA_VERSION: &str = "tallow.extraction_row.v1";
/// The row contract's `extraction_schema_version` is a `const` — it names the
/// CONTRACT version, not the schema document's own version number.
const CONTRACT_VERSION: &str = "tallow.extraction_schema.v1";
/// `source_evidence` is capped at 256 chars by the row contract.
const EVIDENCE_CAP: usize = 256;

/// `extract --schema <f> --html <f> --out <dir> [--target-id <id>] [--source-url <u>]`
pub fn run_extract_args(args: &[String]) -> i32 {
    if matches!(
        args.first().map(String::as_str),
        Some("-h") | Some("--help")
    ) {
        print_usage();
        return EXIT_OK;
    }
    extract(args)
}

fn print_usage() {
    eprintln!("usage: tallow extract --schema <FILE> --html <FILE> --out <DIR>");
    eprintln!("                      [--target-id <ID>] [--source-url <URL>]");
    eprintln!();
    eprintln!("Extracts tallow.extraction_row.v1 rows from a LOCAL html file using a");
    eprintln!("tallow.extraction_schema.v1 contract. Performs no network access: the row");
    eprintln!("contract permits only `mode: local_mock` with `live_scraping: false`.");
    eprintln!("Exit codes: 0 rows written, 1 nothing usable (the field is named), 64 usage.");
}

/// The parsed command line.
struct Args {
    schema: String,
    html: String,
    out: String,
    target_id: Option<String>,
    source_url: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut schema = None;
    let mut html = None;
    let mut out = None;
    let mut target_id = None;
    let mut source_url = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = || -> Result<String, String> {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{flag}: expected a value"))
        };
        match flag {
            "--schema" => {
                schema = Some(value()?);
                i += 2;
            }
            "--html" => {
                html = Some(value()?);
                i += 2;
            }
            "--out" => {
                out = Some(value()?);
                i += 2;
            }
            "--target-id" => {
                target_id = Some(value()?);
                i += 2;
            }
            "--source-url" => {
                source_url = Some(value()?);
                i += 2;
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    Ok(Args {
        schema: schema.ok_or("--schema is required")?,
        html: html.ok_or("--html is required")?,
        out: out.ok_or("--out is required")?,
        target_id,
        source_url,
    })
}

fn extract(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("extract: {e}");
            print_usage();
            return EXIT_USAGE;
        }
    };

    let read = |path: &str, what: &str| -> Result<String, i32> {
        std::fs::read_to_string(path).map_err(|e| {
            eprintln!("extract: cannot read {what} {path}: {e}");
            EXIT_USAGE
        })
    };
    let schema_text = match read(&parsed.schema, "schema") {
        Ok(t) => t,
        Err(code) => return code,
    };
    let html = match read(&parsed.html, "html") {
        Ok(t) => t,
        Err(code) => return code,
    };

    // Metadata first: it validates the contract version, so a document the
    // loader would reject cannot reach the extractor.
    let meta = match v1_schema_metadata(&schema_text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("extract: {}: {e}", parsed.schema);
            return EXIT_INVALID;
        }
    };
    let schema = match ExtractionSchema::from_v1_json(&schema_text, &meta.schema_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("extract: {}: {e}", parsed.schema);
            return EXIT_INVALID;
        }
    };

    // No engine is contacted by `extract_with_schema` (pure CSS application), so
    // the extractor's LLM fields are inert here. The cache dir goes to the temp
    // tree: `LlmExtractor::new()` would create `.tallow-schemas` in the CWD.
    let cache = std::env::temp_dir().join("tallow-extract-schema-cache");
    let extractor = LlmExtractor::with_config(
        "http://127.0.0.1:1",
        "unused-local-css-path",
        &cache.to_string_lossy(),
    );

    let items = match extractor.extract_with_schema(&html, &schema) {
        Ok(items) => items,
        Err(e) => {
            eprintln!("extract: {}: {e}", parsed.html);
            return EXIT_INVALID;
        }
    };
    if items.is_empty() {
        // An empty artifact that "succeeded" is worse than a refusal: it would be
        // indistinguishable from a page that was never read.
        eprintln!(
            "extract: {}: the contract {} matched no items on this page",
            parsed.html, meta.schema_id
        );
        return EXIT_INVALID;
    }

    let run_id = crate::run_evidence::run_id();
    let target_id = parsed
        .target_id
        .clone()
        .unwrap_or_else(|| stem(&parsed.html));
    let source_url = parsed
        .source_url
        .clone()
        .unwrap_or_else(|| parsed.html.clone());
    let extracted_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    let (rows, limitations) = build_rows(
        &schema,
        &meta,
        &items,
        &run_id,
        &target_id,
        &source_url,
        &extracted_at,
        &parsed.html,
        &parsed.schema,
    );

    // All-or-nothing: build both documents, then rename them into place.
    let (rows_path, quarantine_path) = match write_rows(&parsed.out, &run_id, &rows) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("extract: cannot write rows to {}: {e}", parsed.out);
            return EXIT_USAGE;
        }
    };

    crate::run_evidence::record(
        "extract_rows",
        json!({
            "run_id": run_id,
            "schema_id": meta.schema_id,
            "html": parsed.html,
            "rows": rows.len(),
            "mode": "local_mock",
            "egress": "none",
        }),
    );
    // P4.T2's helper, finally with a real caller: one entry per field the page
    // did not yield, so "we looked and it was not there" is recorded.
    crate::run_evidence::record_limitations(&limitations);

    println!("extract: {} item(s) → {} row(s)", items.len(), rows.len());
    println!("  rows:       {}", rows_path.display());
    println!("  quarantine: {}", quarantine_path.display());
    println!("  schema: {} (no egress performed)", meta.schema_id);
    for l in &limitations {
        println!("  unknown: {l}");
    }
    EXIT_OK
}

fn stem(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Build one row per extracted item, plus the limitation strings for fields the
/// page did not yield. Pure over its inputs — no filesystem, no clock, no egress
/// — so the row contract can be tested without either.
#[allow(clippy::too_many_arguments)]
fn build_rows(
    schema: &ExtractionSchema,
    meta: &crate::browser::llm_extract::SchemaMetadata,
    items: &[HashMap<String, String>],
    run_id: &str,
    target_id: &str,
    source_url: &str,
    extracted_at: &str,
    html_path: &str,
    schema_path: &str,
) -> (Vec<Value>, Vec<String>) {
    let schema_id = if meta.schema_id.is_empty() {
        stem(schema_path)
    } else {
        meta.schema_id.clone()
    };
    let entity = if !meta.entity.is_empty() {
        meta.entity.clone()
    } else if !schema_id.is_empty() {
        schema_id.clone()
    } else {
        "unknown".to_string()
    };
    let evidence = {
        let raw = format!("local html: {html_path}");
        raw.chars().take(EVIDENCE_CAP).collect::<String>()
    };

    let mut rows = Vec::with_capacity(items.len());
    let mut limitations: Vec<String> = Vec::new();

    for (idx, item) in items.iter().enumerate() {
        let mut cells = Map::new();
        let mut required_null_count = 0u64;
        let mut required_null_names: Vec<String> = Vec::new();
        let mut present = 0u64;

        for f in &schema.fields {
            let value = item.get(&f.name);
            if value.is_some() {
                present += 1;
            } else if f.required {
                required_null_count += 1;
                // The row gate keys off this exact prefix.
                required_null_names.push(f.name.clone());
            }
            if value.is_none() {
                limitations.push(format!(
                    "{target_id}: field {:?} not yielded by selector {:?}",
                    f.name, f.selector
                ));
            }
            // `type` must come from the contract; an undeclared type is a plain
            // string cell rather than an invented one.
            let declared = meta
                .field_types
                .get(&f.name)
                .filter(|t| !t.is_empty())
                .cloned()
                .unwrap_or_else(|| "string".to_string());
            cells.insert(
                f.name.clone(),
                json!({
                    "value": value.map(|v| Value::String(v.clone())).unwrap_or(Value::Null),
                    "type": declared,
                    "required": f.required,
                    "confidence": if value.is_some() { 1.0 } else { 0.0 },
                    "null_reason": if value.is_some() { Value::Null } else { Value::String("missing".into()) },
                    "selector_kind": "css",
                    "selector": f.selector,
                    "degraded": false,
                    "source_evidence": evidence,
                }),
            );
        }

        let total = schema.fields.len().max(1) as f64;
        let selector_health = present as f64 / total;
        // The row's confidence is the share of the contract's fields the page
        // actually yielded. `min_row_confidence` below is the contract's own
        // threshold, not a number invented here.
        let row_confidence = selector_health;

        // Status and reason vocabulary follow scripts/validate_extraction_rows.py
        // exactly: it quarantines on `required_null_count > max_null_required_fields`
        // OR `row_confidence < min_row_confidence`, and it requires reasons it can
        // match — a `required_field_null…` prefix per null required field, and the
        // literal `row_confidence_below_min`. A row that disagrees with either
        // rule is a hard error in the gate, so the two must be kept in step.
        let mut quarantine_reasons = Vec::new();
        for name in &required_null_names {
            quarantine_reasons.push(format!("required_field_null: {name}"));
        }
        let below_min_confidence = row_confidence < meta.min_row_confidence;
        if below_min_confidence {
            quarantine_reasons.push("row_confidence_below_min".to_string());
        }
        let should_quarantine =
            required_null_count > meta.max_null_required_fields || below_min_confidence;
        let status = if should_quarantine {
            "quarantined"
        } else {
            "accepted"
        };

        rows.push(json!({
            "schema_version": ROW_SCHEMA_VERSION,
            "row_id": format!("{run_id}-{idx}"),
            "run_id": run_id,
            "target_id": target_id,
            "source_url": source_url,
            "extraction_schema_id": schema_id,
            "extraction_schema_version": CONTRACT_VERSION,
            "entity": entity,
            "row_index": idx,
            "extracted_at_utc": extracted_at,
            "mode": "local_mock",
            "status": status,
            "row_confidence": row_confidence,
            "fields": Value::Object(cells),
            "quality": {
                "required_null_count": required_null_count,
                "selector_health": selector_health,
                "drift_detected": false,
                "quarantine_reasons": quarantine_reasons,
            },
            "non_claims": {
                "live_scraping": false,
                "external_dataset": false,
                "production_ready": false,
            },
        }));
    }

    (rows, limitations)
}

/// Write every row, or none.
///
/// Two files, each through a temp+rename pair: `<run_id>.rows.jsonl` (every row)
/// and `<run_id>.quarantine.jsonl` (only the quarantined ones). The quarantine
/// file is part of the contract, not a convenience — the repository's gate reads
/// it and raises `quarantine_row_missing` for a quarantined row absent from it,
/// and `quarantine_accepted_row_present` for an accepted row present in it. An
/// empty quarantine file is written rather than skipped, so "nothing was
/// quarantined" is a fact on disk instead of an absence.
fn write_rows(out_dir: &str, run_id: &str, rows: &[Value]) -> std::io::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(out_dir)?;
    let dir = Path::new(out_dir);
    let rows_final = dir.join(format!("{run_id}.rows.jsonl"));
    let quarantine_final = dir.join(format!("{run_id}.quarantine.jsonl"));

    let encode = |items: &[&Value]| -> String {
        let mut body = String::new();
        for row in items {
            body.push_str(&serde_json::to_string(row).unwrap_or_default());
            body.push('\n');
        }
        body
    };
    let all: Vec<&Value> = rows.iter().collect();
    let quarantined: Vec<&Value> = rows
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("quarantined"))
        .collect();

    let rows_tmp = dir.join(format!("{run_id}.rows.jsonl.tmp"));
    let quarantine_tmp = dir.join(format!("{run_id}.quarantine.jsonl.tmp"));
    std::fs::write(&rows_tmp, encode(&all))?;
    std::fs::write(&quarantine_tmp, encode(&quarantined))?;
    std::fs::rename(&rows_tmp, &rows_final)?;
    std::fs::rename(&quarantine_tmp, &quarantine_final)?;
    Ok((rows_final, quarantine_final))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/tallow/examples/product-listing.extraction.schema.json"
    ));

    /// `.product .name` is the required field; price/url are optional.
    const FULL_HTML: &str = r#"
        <html><body>
        <div class="product">
          <span class="name">Probe Widget</span>
          <span class="price">$19.99</span>
          <a href="https://example.invalid/p/1">link</a>
        </div>
        </body></html>"#;

    /// The required field is absent; the page is otherwise fine.
    const MISSING_REQUIRED: &str = r#"
        <html><body>
        <div class="product"><span class="price">$19.99</span></div>
        </body></html>"#;

    fn extract_items(html: &str) -> Vec<HashMap<String, String>> {
        let schema = ExtractionSchema::from_v1_json(SCHEMA, "test").expect("schema loads");
        let cache = std::env::temp_dir().join("tallow-extract-schema-cache");
        let ex =
            LlmExtractor::with_config("http://127.0.0.1:1", "unused", &cache.to_string_lossy());
        ex.extract_with_schema(html, &schema).expect("extracts")
    }

    fn rows_for(html: &str) -> (Vec<Value>, Vec<String>) {
        let meta = v1_schema_metadata(SCHEMA).expect("metadata");
        let schema = ExtractionSchema::from_v1_json(SCHEMA, &meta.schema_id).expect("schema");
        let items = extract_items(html);
        build_rows(
            &schema,
            &meta,
            &items,
            "run-1",
            "target",
            "file:///tmp/x.html",
            "2026-10-14T00:00:00Z",
            "/tmp/x.html",
            "schema.json",
        )
    }

    #[test]
    fn a_complete_page_yields_an_accepted_row() {
        let (rows, limitations) = rows_for(FULL_HTML);
        assert_eq!(rows.len(), 1, "one item → one row");
        let row = &rows[0];
        assert_eq!(row["schema_version"], ROW_SCHEMA_VERSION);
        assert_eq!(row["mode"], "local_mock");
        assert_eq!(row["status"], "accepted");
        assert_eq!(row["extraction_schema_version"], CONTRACT_VERSION);
        assert_eq!(row["extraction_schema_id"], "example.product_listing.v1");
        assert_eq!(row["entity"], "product_listing");
        assert_eq!(row["quality"]["required_null_count"], 0);
        // Every schema field must have a cell — the validator's
        // `field_cell_missing` hard error.
        assert_eq!(row["fields"].as_object().unwrap().len(), 3);
        // `non_claims` are pinned false by the contract, not by this code.
        assert_eq!(row["non_claims"]["live_scraping"], false);
        assert_eq!(row["non_claims"]["production_ready"], false);
        // Every cell carries the nine required keys, including the null ones.
        for (_name, cell) in row["fields"].as_object().unwrap() {
            for key in [
                "value",
                "type",
                "required",
                "confidence",
                "null_reason",
                "selector_kind",
                "selector",
                "degraded",
                "source_evidence",
            ] {
                assert!(cell.get(key).is_some(), "cell missing {key}");
            }
        }
        assert!(
            limitations.is_empty(),
            "nothing was absent: {limitations:?}"
        );
    }

    #[test]
    fn a_missing_required_field_quarantines_and_records_a_limitation() {
        let (rows, limitations) = rows_for(MISSING_REQUIRED);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["status"], "quarantined");
        assert_eq!(row["quality"]["required_null_count"], 1);
        assert!(
            !row["quality"]["quarantine_reasons"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        // The absent field is visible BOTH ways: null_reason in the cell, and a
        // limitation string for the evidence sink.
        let name_cell = &row["fields"]["name"];
        assert_eq!(name_cell["value"], Value::Null);
        assert_eq!(name_cell["null_reason"], "missing");
        assert_eq!(name_cell["confidence"], 0.0);
        assert!(
            limitations.iter().any(|l| l.contains("\"name\"")),
            "the absent field must be named: {limitations:?}"
        );
    }

    #[test]
    fn the_declared_type_travels_from_the_contract_into_the_cell() {
        let (rows, _) = rows_for(FULL_HTML);
        let fields = rows[0]["fields"].as_object().unwrap();
        assert_eq!(fields["name"]["type"], "string");
        assert_eq!(fields["price"]["type"], "money");
        assert_eq!(fields["url"]["type"], "url");
    }

    #[test]
    fn every_row_passes_its_own_mechanical_consistency_checks() {
        // The two hard errors my first hand-built row tripped:
        // `field_required_mismatch` (cell.required must match the schema) and
        // `quality_required_null_count` (the count must match reality).
        let meta = v1_schema_metadata(SCHEMA).unwrap();
        let schema = ExtractionSchema::from_v1_json(SCHEMA, &meta.schema_id).unwrap();
        for html in [FULL_HTML, MISSING_REQUIRED] {
            let (rows, _) = rows_for(html);
            for row in rows {
                let cells = row["fields"].as_object().unwrap();
                let mut actual_null_required = 0;
                for f in &schema.fields {
                    let cell = cells.get(&f.name).expect("cell per schema field");
                    assert_eq!(
                        cell["required"].as_bool().unwrap(),
                        f.required,
                        "cell.required must match the schema field"
                    );
                    if f.required && cell["value"].is_null() {
                        actual_null_required += 1;
                    }
                }
                assert_eq!(
                    row["quality"]["required_null_count"].as_u64().unwrap(),
                    actual_null_required,
                    "quality_required_null_count must match the cells"
                );
            }
        }
    }

    #[test]
    fn quarantine_reasons_use_the_gates_vocabulary() {
        let (rows, _) = rows_for(MISSING_REQUIRED);
        let reasons: Vec<String> = rows[0]["quality"]["quarantine_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        // The gate matches a PREFIX here...
        assert!(
            reasons.iter().any(|r| r.starts_with("required_field_null")),
            "{reasons:?}"
        );
        // ...and an exact membership here. Both must be present or the gate
        // reports a hard error against the verb's own honest output.
        assert!(
            reasons.iter().any(|r| r == "row_confidence_below_min"),
            "{reasons:?}"
        );
        // A complete page must carry no quarantine reason at all.
        let (clean, _) = rows_for(FULL_HTML);
        assert!(
            clean[0]["quality"]["quarantine_reasons"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(clean[0]["status"], "accepted");
    }

    #[test]
    fn rows_and_quarantine_are_written_as_two_files() {
        let dir = std::env::temp_dir().join(format!("tallow-extract-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let (quarantined_rows, _) = rows_for(MISSING_REQUIRED);
        let (_r, q) =
            write_rows(&dir.to_string_lossy(), "run-q", &quarantined_rows).expect("write");
        let body = std::fs::read_to_string(&q).expect("quarantine file");
        assert!(body.contains("\"status\":\"quarantined\""), "{body}");
        assert_eq!(body.lines().count(), 1, "only quarantined rows belong here");

        // A clean run writes an EMPTY quarantine file rather than no file, so
        // "nothing was quarantined" is a fact on disk instead of an absence.
        let (clean_rows, _) = rows_for(FULL_HTML);
        let (r2, q2) = write_rows(&dir.to_string_lossy(), "run-c", &clean_rows).expect("write");
        assert!(std::fs::read_to_string(&q2).expect("file").is_empty());
        assert_eq!(
            std::fs::read_to_string(&r2).expect("rows").lines().count(),
            1
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_paths() {
        assert_eq!(run_extract_args(&["--help".to_string()]), EXIT_OK);
        assert_eq!(run_extract_args(&[]), EXIT_USAGE);
        assert_eq!(run_extract_args(&["--schema".to_string()]), EXIT_USAGE);
        assert_eq!(
            run_extract_args(&[
                "--schema".into(),
                "s.json".into(),
                "--html".into(),
                "/nonexistent.html".into(),
                "--out".into(),
                "/tmp/x".into(),
            ]),
            EXIT_USAGE
        );
    }

    #[test]
    fn a_bad_contract_is_refused_before_any_extraction() {
        assert_eq!(
            run_extract_args(&[
                "--schema".into(),
                "/nonexistent-schema.json".into(),
                "--html".into(),
                "/nonexistent.html".into(),
                "--out".into(),
                "/tmp/x".into(),
            ]),
            EXIT_USAGE
        );
    }

    /// The verb must not reach the network: the row contract permits only
    /// `local_mock`, so any egress reference here is a defect. Needles are
    /// assembled so this test cannot satisfy them itself.
    #[test]
    fn the_extract_module_cannot_egress() {
        let src: String = include_str!("extract_cmd.rs")
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("//!"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            concat!("execute", "_get"),
            concat!("egress", "_http"),
            concat!("ur", "eq"),
        ] {
            assert!(!src.contains(needle), "extract must not reference {needle}");
        }
    }
}
