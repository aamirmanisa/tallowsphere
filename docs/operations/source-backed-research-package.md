# Canonical source-backed research package

> status: verified 2026-09-05 (C6 docs wave — P1-006 Linux-native `scripts/build_research_package.py` flow current).

Status: P1-006 local/mock package initializer.

`scripts/build_research_package.py` creates a repeatable public-source research package from an entity CSV and a markdown query plan. It replaces ad-hoc Ashraf-style glue with one safe local command that validates contracts, builds a request plan, emits a legacy-safe TL transport when representable, and runs a no-network dry-run.

## Safety boundary

This command is public/authorized-source only:

- requires `--public-only`;
- generates `browser_fallback.mode = never`;
- uses GET discovery targets only;
- writes a dry-run report with `executed = 0`;
- uses `--mock-base-url` for local classification and never needs live network I/O;
- does not resolve credentials, bypass login/CAPTCHA/paywalls, contact targets, or claim production/live extraction readiness.

## Command

```bash
python3 scripts/build_research_package.py \
  --slug ashraf_ali_business_inquiry \
  --entities entities.csv \
  --queries queries.md \
  --public-only \
  --output personal_database/ashraf_ali_business_inquiry \
  --mock-base-url http://127.0.0.1:9
```

`queries.md` should contain markdown bullet items; backticked text becomes a discovery query:

```markdown
- `Example Public LLC official registry`
- `Example Public LLC permit record`
```

`entities.csv` should contain at least a `name` column; optional `type` is copied into the inquiry scaffold:

```csv
name,type
Example Public LLC,business
Example Owner,business_role
```

## Outputs

The package directory contains:

- `README.md` — package boundary and file map;
- `<SLUG>.md` — source-backed inquiry scaffold;
- `entities.csv` and `queries.md` — copied inputs;
- `sources_manifest.json` — `tallow.target_manifest.v2` public-source manifest;
- `<slug>.request-plan.v1.json` — generated request plan;
- `<slug>.request-plan-report.json` — request-plan build report;
- `<slug>.legacy-http-batch.tl` — legacy-safe TL transport when GET/global-header compatible;
- `tallow_contract_validation_report.json` — contract validation result;
- `request_plan_dry_run_report.json` — no-network runner report;
- `request_plan_dry_run_artifacts/` — dry-run artifact folder and manifest;
- `run_notes.md` and `tallow_run_report.md` — exact command log and status summary.

## Verification

```bash
python3 -B -m unittest tests.test_research_package_init -v
python3 -m py_compile scripts/build_research_package.py tests/test_research_package_init.py
```

Expected:

```text
Ran 1 test
OK
```
