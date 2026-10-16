# Tallow Phase 2 Contract Spine

Status: initial contract spine for Phase 2 consolidation.

Phase 2 turns the Phase 0/1 truth map into versioned contracts before feature/performance work. These files define the intended canonical shapes; producer migration is tracked separately.

## Contracts

- `schemas/tallow/target-manifest-v2.schema.json` — object-target manifest contract with request, extraction, browser fallback, artifact, compliance, retry, policy, and migration metadata.
- `configs/tallow/targets.v2.example.json` — canonical example manifest. Legacy string-target manifests should migrate by creating object targets with generated IDs and `method: GET`.
- `scripts/normalize_tallow_targets.py` — Linux-native v1/string-target to v2 object-target normalizer for the first BLK-008 producer-migration slice.
- `scripts/build_tallow_request_plan.py` — Linux-native v2 target-manifest to request-plan adapter with guarded legacy `http.batch` TL emission.
- `scripts/run_tallow_request_plan.py` — Linux-native local/mock runner that consumes `tallow.request_plan.v1` directly for supported GET/POST JSON/GraphQL/retry/artifact semantics.
- `artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json` — generated normalized artifact from `configs/tallow/targets.example.json`.
- `artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.request-plan.v1.json` — request plan preserving normalized target metadata while refusing lossy legacy TL downgrade.
- `artifacts/phase2/request-plans/get-only-legacy-safe.legacy-http-batch.tl` — safe GET/global-header transport proof generated from a request-plan fixture.
- `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json` — local/mock runtime proof for direct request-plan execution of GET, POST JSON GraphQL, retry, and artifact manifest output.
- `schemas/tallow/extraction-schema.schema.json` — schema-first extraction/data-quality contract with selectors, coercion, confidence, null reasons, drift, pagination, and quarantine.
- `schemas/tallow/examples/product-listing.extraction.schema.json` — example extraction schema.
- `schemas/tallow/error-taxonomy.schema.json` and `schemas/tallow/error-taxonomy.v1.json` — canonical cross-layer error kinds with retryable/replayable/policy-escalation flags and legacy row mappings.
- `schemas/tallow/artifact-manifest.schema.json` — per-run artifact manifest contract with hashes, redaction, retention, and replay safety.
- `schemas/tallow/contract-index.json` — index of Phase 2 contract files.

## Status matrix

- Target manifest v2
  - Version: `tallow.target_manifest.v2`
  - Owner file: `schemas/tallow/target-manifest-v2.schema.json`
  - Example: `configs/tallow/targets.v2.example.json`
  - Validator status: contract-defined and checked by `scripts/validate_tallow_contracts.py`; generated migrated artifacts can now be checked with `--target-manifest`
  - Producer status: Linux-native producer-migration slices present via `scripts/normalize_tallow_targets.py`, `scripts/build_tallow_request_plan.py`, and `scripts/run_tallow_request_plan.py`; legacy manifests normalize to v2 object-target artifacts, v2 manifests build request plans that preserve metadata, and the local/mock runner consumes request plans directly for a supported HTTP subset
  - Migration status: `configs/tallow/targets.example.json` normalized to `artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json`; request plan at `artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.request-plan.v1.json`; guarded TL downgrade works for a GET/global-header-safe fixture and fails fast for lossy normalized/v2 examples; local/mock runtime proof at `artifacts/phase2/request-plan-runs/local-get-post-graphql-runtime-proof/execution_report.json`; live/external launcher/runtime consumption, auth, browser fallback, and production policy enforcement remain pending

- Extraction schema
  - Version: `tallow.extraction_schema.v1`
  - Owner file: `schemas/tallow/extraction-schema.schema.json`
  - Example: `schemas/tallow/examples/product-listing.extraction.schema.json`
  - Validator status: contract-defined and checked by `scripts/validate_tallow_contracts.py`
  - Producer status: pending; current full-run rows are fetch/probe rows, not normalized extraction rows
  - Migration status: pending connection from validators/extractors to schema-defined fields

- Error taxonomy
  - Version: `tallow.error_taxonomy.v1`
  - Owner files: `schemas/tallow/error-taxonomy.schema.json`, `schemas/tallow/error-taxonomy.v1.json`
  - Validator status: contract-defined and checked for unique required kinds plus retry/replay/policy flags
  - Producer status: pending; current rows still use legacy `none|transport|server|rate_limited|auth|other`
  - Migration status: canonical taxonomy records `maps_to_row_error_kind_v1` for backward compatibility

- Artifact manifest
  - Version: `tallow.artifact_manifest.v1`
  - Owner file: `schemas/tallow/artifact-manifest.schema.json`
  - Validator status: contract-defined and checked for required identity/files/redaction/retention/replay keys
  - Producer status: pending; current launcher/artifact scripts do not emit this v1 shape on Linux
  - Migration status: pending producer migration from documented PowerShell-era artifact contracts

- Contract index
  - Version: `tallow.contract_index.v1`
  - Owner file: `schemas/tallow/contract-index.json`
  - Validator status: checked for existing JSON paths
  - Producer status: manual for now
  - Migration status: additive; does not change legacy runtime behavior

## Verification

```bash
python3 scripts/validate_tallow_contracts.py --report-path artifacts/phase2/contract_validation_report.json
```

The validator is stdlib-only and Linux-native. It deliberately does not claim full JSON Schema validation.

## Status semantics

- **Contract-defined:** schema/example exists and passes the Linux-native contract validator.
- **Producer-migrated:** scripts/runtime emit or consume the new contract.
- **Runtime-verified:** Tallow/launcher runs produce artifacts matching the contract.

The initial Phase 2 spine reaches contract-defined. The target-manifest contract now has Linux-native producer-migration slices: legacy string-target manifests normalize into validated v2 object-target artifacts, v2 artifacts build request plans that preserve metadata, guarded legacy TL is emitted only for safe GET/global-header downgrades, and a local/mock runner consumes request plans directly for supported GET/POST JSON/GraphQL/retry/artifact-manifest semantics. BLK-008 remains partially open until live/external launcher/runtime policy gates, vault-backed auth, browser fallback, and production compliance are runtime-verified; BLK-009, BLK-010, and BLK-015 remain open until their producer/runtime gates land.
