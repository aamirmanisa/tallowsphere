# Tallow Contract Validation

> status: verified 2026-09-05 (C6 docs wave — Phase 2/5 Linux-native validator doc current).

Status: Phase 2 Linux/CachyOS contract-spine validator, extended in Phase 5 for local/mock extraction-row contracts.

`scripts/validate_tallow_contracts.py` is a stdlib-only validation helper for the Phase 2 contract files under `schemas/tallow/` and `configs/tallow/`. It exists because the active Linux/CachyOS target does not have PowerShell installed, while much of the older scraper tooling is PowerShell-based.

## Validate contracts

```bash
python3 scripts/validate_tallow_contracts.py --report-path artifacts/phase2/contract_validation_report.json
python3 -m json.tool artifacts/phase2/contract_validation_report.json >/dev/null
```

Expected success output:

```text
contract validation passed
```

## Validate migrated target manifests

After running the BLK-008 normalizer, validate the generated v2 artifact too:

```bash
python3 scripts/normalize_tallow_targets.py \
  --input configs/tallow/targets.example.json \
  --write-report-default

python3 scripts/validate_tallow_contracts.py \
  --target-manifest artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json \
  --report-path artifacts/phase2/contract_validation_report.json
```

`--target-manifest` can be supplied multiple times. It rejects migrated artifacts that still contain legacy string targets or that omit v2 `id`, `url`, `method`, compliance, or policy keys.

## What it checks

This is not a full JSON Schema validator. It performs targeted Phase 2 checks that must work without third-party Python packages:

- every contract/index/example JSON file parses;
- `schemas/tallow/contract-index.json` points to existing JSON files;
- the canonical error taxonomy has unique required error kinds and required retry/replay/policy flags;
- `configs/tallow/targets.v2.example.json` uses object targets with `id`, HTTP(S) `url`, `method`, target compliance metadata, and top-level policy metadata;
- optional `--target-manifest` artifacts use the same v2 object-target checks, so generated producer-migration outputs are validated instead of trusting a static example only;
- the product-listing extraction example has fields with `name`, `type`, `required`, and selectors;
- the Phase 5 extraction-row schema declares row identity, schema linkage, per-field confidence/null reasons/selector provenance, quality metadata, and explicit non-claims;
- the Phase 5 extraction-row validation-report schema declares pass/fail, row/quarantine counts, error/null-reason counts, confidence/selector-health summaries, checked paths, and explicit non-claims;
- the artifact manifest schema declares replay, retention, redaction, files, and launch/run identity as required top-level concepts.

## Scope boundaries

Passing the base validator means the contract spine is internally coherent for the scoped contracts it checks. Passing with `--target-manifest` means a generated v2 target-manifest artifact satisfies the current Linux-native v2 object-target checks.

Phase 5 extraction-row contract checks prove schema/report contract coherence only. Use `scripts/validate_extraction_rows.py` plus the Phase 5 artifacts to prove the local/mock row validation path.

It still does **not** mean that legacy PowerShell launchers or Tallow runtime code execute full object-target semantics yet. Live browser/benchmark/production scraper readiness remain later gates.
