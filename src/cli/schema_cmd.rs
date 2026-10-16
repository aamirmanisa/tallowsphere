//! `tallow schema` — validate a `tallow.extraction_schema.v1` contract from the
//! command line, so a schema can be gated in CI before any run depends on it.
//!
//! House CLI shape (see `sluice_cmd`): `run_<verb>_args(&[String]) -> i32`, and
//! `main.rs` hands the result straight to `std::process::exit`.
//!
//! Exit codes, mirroring the set declared at the top of `src/main.rs`:
//! `0` = valid · `1` = the document is not a valid v1 contract (the offending
//! field is named on stderr) · `64` = usage error or unreadable file.
//!
//! The validation is **not** reimplemented here: this calls
//! [`ExtractionSchema::from_v1_json`], the same loader the extraction path uses.
//! A second validator would be a second source of truth for "is this schema
//! usable", which is exactly how a schema passes CI and then fails at run time.

use crate::browser::llm_extract::ExtractionSchema;

const EXIT_OK: i32 = 0;
const EXIT_INVALID: i32 = 1;
const EXIT_USAGE: i32 = 64;

/// Cache key handed to the loader. A v1 contract carries no domain and this
/// command only validates — nothing is cached — so a constant is the honest
/// value here rather than an invented one.
const CLI_DOMAIN: &str = "schema-cli";

/// `schema check <file>` · `schema --help`.
pub fn run_schema_args(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        Some("-h") | Some("--help") => {
            print_usage();
            EXIT_OK
        }
        Some(other) => {
            eprintln!("schema: unknown subcommand {other:?}");
            print_usage();
            EXIT_USAGE
        }
        None => {
            print_usage();
            EXIT_USAGE
        }
    }
}

fn print_usage() {
    eprintln!("usage: tallow schema check <FILE.extraction.schema.json>");
    eprintln!();
    eprintln!("Validates one `tallow.extraction_schema.v1` contract document.");
    eprintln!("Exit codes: 0 valid, 1 invalid (the failing field is named), 64 usage.");
}

/// `schema check <file>`: resolve the path, read it, validate it.
fn check(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p,
        None => {
            eprintln!("schema check: expected a schema file path");
            print_usage();
            return EXIT_USAGE;
        }
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("schema check: cannot read {path}: {e}");
            return EXIT_USAGE;
        }
    };
    check_text(path, &text)
}

/// The validation itself, split out so it is testable without the filesystem.
/// Returns the process exit code and prints the verdict.
fn check_text(path: &str, text: &str) -> i32 {
    match ExtractionSchema::from_v1_json(text, CLI_DOMAIN) {
        Ok(schema) => {
            println!(
                "ok: {path} — tallow.extraction_schema.v1, {} field(s)",
                schema.fields.len()
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("schema check: {path}: {e}");
            EXIT_INVALID
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped example contract — the same document the plan's P3.T1
    /// verification names.
    const FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/tallow/examples/product-listing.extraction.schema.json"
    ));

    #[test]
    fn the_shipped_example_schema_is_valid() {
        assert_eq!(check_text("example", FIXTURE), EXIT_OK);
    }

    #[test]
    fn a_corrupted_version_is_refused() {
        let bad = FIXTURE.replace("tallow.extraction_schema.v1", "tallow.extraction_schema.v2");
        assert_eq!(check_text("bad", &bad), EXIT_INVALID);
        let err = ExtractionSchema::from_v1_json(&bad, CLI_DOMAIN).unwrap_err();
        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn a_field_without_a_css_selector_names_that_field() {
        let bad = r#"{"schema_version":"tallow.extraction_schema.v1",
                      "fields":[{"name":"price","selectors":[{"kind":"json_path","value":"$.p"}]}]}"#;
        assert_eq!(check_text("bad", bad), EXIT_INVALID);
        let err = ExtractionSchema::from_v1_json(bad, CLI_DOMAIN).unwrap_err();
        assert!(
            err.contains("price"),
            "must name the offending field: {err}"
        );
        assert!(err.contains("no css selector"), "{err}");
    }

    #[test]
    fn the_command_agrees_with_the_loader_it_calls() {
        // Guards the one thing that would make this command worse than useless:
        // a validator whose verdict drifts from the loader the run actually uses.
        assert_eq!(
            check_text("fixture", FIXTURE),
            match ExtractionSchema::from_v1_json(FIXTURE, CLI_DOMAIN) {
                Ok(_) => EXIT_OK,
                Err(_) => EXIT_INVALID,
            }
        );
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        assert_eq!(run_schema_args(&["nope".to_string()]), EXIT_USAGE);
        assert_eq!(run_schema_args(&[]), EXIT_USAGE);
        assert_eq!(run_schema_args(&["--help".to_string()]), EXIT_OK);
    }

    #[test]
    fn a_missing_file_is_a_usage_error_not_a_silent_pass() {
        assert_eq!(
            run_schema_args(&["check".to_string(), "/nonexistent/schema.json".to_string()]),
            EXIT_USAGE
        );
    }
}
