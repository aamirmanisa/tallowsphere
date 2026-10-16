# Strict Row Validation

Status: Advances `TSK-0901` and `TSK-0902` with strict row validation, required-field checks, typed coercion accounting, and invalid-row quarantine output.

## Scope

There are now two distinct row-validation paths:

1. **Fetch/probe run rows** from older scraper `*_full.json` artifacts, validated by `scripts/validate_rows_strict.ps1`.
2. **Schema-defined extraction rows** from the Phase 5 local/mock proof, validated by `scripts/validate_extraction_rows.py`.

The Phase 5 path is local/mock only. It does not fetch websites, use external production datasets, launch browsers, resolve secrets, or claim production extraction readiness.

## Fetch/probe row validator

Script: `scripts/validate_rows_strict.ps1`

It validates every row in each `*_full.json` artifact by enforcing:

- required key presence,
- no unexpected row keys,
- strict type/value checks,
- typed coercion tracking,
- invalid-row quarantine capture.

### Inputs

Required:

- `-InputPath`

`-InputPath` may be:

- a launch directory containing `run_*` folders,
- a single run directory,
- a single `*_full.json` file.

Optional:

- `-ReportPath` override default report output path.
- `-QuarantinePath` override default quarantine output path.
- `-FailOnInvalid` return non-zero when invalid rows are found.

### Fetch/probe row contract

Required row fields:

1. `wave`
2. `url`
3. `status`
4. `body`
5. `body_len`
6. `is_json`
7. `is_graphql`
8. `auth_blocked`
9. `rate_limited`
10. `retryable`
11. `error_kind`

Validation rules:

- `wave`: string matching `^L[1-9][0-9]*$`.
- `url`: absolute `http/https` URI.
- `status`: integer in `[0..599]`.
- `body`: string (non-string values are coercion-attempted).
- `body_len`: integer `>= 0`.
- flag fields: boolean-compatible (`true/false`, `0/1`, boolean, or equivalent string forms).
- `error_kind`: one of `none|transport|server|rate_limited|auth|other`.
- `body_len` must equal `body.Length`.
- unexpected extra fields are treated as errors.

### Fetch/probe outputs

Default output filenames:

- report: `row_validation_report.json`
- quarantine: `row_quarantine.json`

Report schema highlights:

- `passed`
- `rows_total`, `rows_valid`, `rows_invalid`
- `invalid_error_counts`
- `coercion_counts_by_field`
- `runs[]` with per-run details and invalid row objects.

Quarantine schema highlights:

- `rows_invalid`
- `invalid_rows[]` each containing `run_id`, `full_json_path`, `row_index`, `errors[]`, `coercions[]`, and the original fetch/probe `row` payload.

### Fetch/probe usage

```powershell
.\scripts\validate_rows_strict.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223954
```

```powershell
.\scripts\validate_rows_strict.ps1 `
  -InputPath .\artifacts\scraper_runs\parallel10_20260427-223954\run_01 `
  -FailOnInvalid
```

## Phase 5 schema-defined extraction rows

Phase 5 adds `tallow.extraction_row.v1` for normalized local/mock extraction rows. This is separate from the older fetch/probe row shape above.

Contracts and validator:

- Row schema: `schemas/tallow/extraction-row.schema.json`.
- Validation report schema: `schemas/tallow/extraction-row-validation-report.schema.json`.
- Linux-native validator: `scripts/validate_extraction_rows.py`.
- Local/mock proof artifacts: `artifacts/phase5/extraction_rows/`.

Schema-defined rows bind each row to:

- `run_id`, `target_id`, `source_url`, `extraction_schema_id`, and `entity`;
- per-field values, type, required flag, confidence, null reason, selector kind, selector provenance, degradation flag, and bounded source evidence;
- row confidence, required-null count, selector health, drift flag, quarantine reasons, and explicit non-claims.

Focused verification:

```bash
python3 -m unittest tests.test_phase5_extraction_rows -v
cargo test --test extraction_rows -- --nocapture
python3 scripts/validate_extraction_rows.py \
  --schema schemas/tallow/examples/product-listing.extraction.schema.json \
  --row-schema schemas/tallow/extraction-row.schema.json \
  --rows artifacts/phase5/extraction_rows/local_mock_product_rows.jsonl \
  --quarantine-path artifacts/phase5/extraction_rows/local_mock_quarantine.jsonl \
  --report-path artifacts/phase5/extraction_rows/validation_report.json
```

`--fail-on-invalid` intentionally exits non-zero when the quarantine fixture is present; use it as the negative proof that quarantined rows can fail CI:

```bash
python3 scripts/validate_extraction_rows.py \
  --schema schemas/tallow/examples/product-listing.extraction.schema.json \
  --row-schema schemas/tallow/extraction-row.schema.json \
  --rows artifacts/phase5/extraction_rows/local_mock_product_rows.jsonl \
  --quarantine-path artifacts/phase5/extraction_rows/local_mock_quarantine.jsonl \
  --report-path artifacts/phase5/extraction_rows/validation_report.fail_on_invalid.json \
  --fail-on-invalid
```

Do not treat Phase 5 row validation as live website extraction, external dataset validation, browser fallback readiness, vault-backed auth, production compliance, benchmark readiness, or Windows support.
