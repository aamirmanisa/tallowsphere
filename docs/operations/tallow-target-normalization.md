# Tallow Target Manifest Normalization

Status: Phase 2 BLK-008 Linux/CachyOS producer-migration slice.

`scripts/normalize_tallow_targets.py` is a stdlib-only Linux-native adapter that converts legacy target manifests into canonical `tallow.target_manifest.v2` JSON.

It is intentionally a producer/contract adapter. By itself, it does not launch browsers, execute requests, or prove runtime support for POST bodies, GraphQL metadata, browser fallback, artifacts, or compliance enforcement. Later slices add request-plan generation and local/mock request-plan execution; see `docs/operations/tallow-request-plan-builder.md` and `docs/operations/tallow-request-plan-runner.md`.

## Basic migration

```bash
python3 scripts/normalize_tallow_targets.py \
  --input configs/tallow/targets.example.json \
  --write-report-default
```

Default output path:

```text
artifacts/phase2/normalized-targets/<input-stem>.<input-sha256-12>.target-manifest.v2.json
```

Default sibling report when `--write-report-default` is used:

```text
artifacts/phase2/normalized-targets/<input-stem>.<input-sha256-12>.normalization-report.json
```

Current canonical generated fixture:

```text
artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json
artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.normalization-report.json
```

## Validate generated output

```bash
python3 scripts/validate_tallow_contracts.py \
  --target-manifest artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json \
  --report-path artifacts/phase2/contract_validation_report.json
python3 -m json.tool artifacts/phase2/contract_validation_report.json >/dev/null
```

Expected output:

```text
contract validation passed
```

## Compatibility behavior

Default mode is `compat`.

Legacy string targets become v2 object targets with:

- deterministic `id`;
- original HTTP(S) `url`;
- `method: GET`;
- inherited top-level headers under `defaults.headers`;
- mapped retry kinds under `defaults.retry`;
- conservative `defaults.artifact_policy`;
- default `browser_fallback.mode: never`;
- synthesized compliance metadata marked approval-required.

The normalizer preserves target/object fields that already fit the v2 contract, including `headers`, `body`, `graphql`, `auth_ref`, `extraction_schema_ref`, `browser_fallback`, `artifact_policy`, `compliance`, `retry`, and `tags`.

Legacy `payload` maps to v2 `body` with hash redaction. Legacy inline auth is not silently copied into v2; pass `--auth-ref <vault-ref>` to reference a vault/secret entry.

## Strict and production checks

Strict mode fails if important governance fields would need synthesis:

```bash
python3 scripts/normalize_tallow_targets.py \
  --input configs/tallow/targets.example.json \
  --mode strict \
  --check
```

The current legacy example fails strict mode because its targets do not contain target-level compliance metadata.

Use explicit flags only when the operator accepts the synthesis boundary:

```bash
python3 scripts/normalize_tallow_targets.py \
  --input configs/tallow/targets.example.json \
  --mode strict \
  --allow-synthesized-compliance \
  --check
```

Production mode additionally rejects unknown legal basis, approval-required targets, and synthesized compliance. Passing production mode is a future compliance gate, not a default Phase 2 claim.

## Status boundary

This closes the Linux-native v1-to-v2 normalization/validation slice of BLK-008. Later BLK-008 slices add request-plan generation and local/mock runtime proof, but the following remain outside this normalizer's claim.

Still not claimed here:

- legacy PowerShell launcher parity;
- live/external request-plan policy gates;
- vault-backed auth resolution/redaction proof;
- browser fallback execution;
- full Tallow/Rust runtime integration for all object-target semantics;
- extraction schema row validation;
- production compliance gates;
- benchmark/performance readiness.
