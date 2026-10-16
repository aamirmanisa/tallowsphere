# Tallow Request Plan Builder

Status: Phase 2 BLK-008 Linux/CachyOS launcher/injection adapter slice.

`scripts/build_tallow_request_plan.py` consumes a canonical `tallow.target_manifest.v2` manifest and emits a `tallow.request_plan.v1` artifact. The request plan preserves full v2 object-target metadata before any legacy launcher or TL downgrade happens.

This is not, by itself, runtime proof for full v2 execution. It is a guarded producer adapter between target-manifest normalization and request-plan runtime wiring; the separate local/mock runtime slice is documented in `docs/operations/tallow-request-plan-runner.md`.

## Build a request plan

```bash
python3 scripts/build_tallow_request_plan.py \
  --manifest artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json \
  --output artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.request-plan.v1.json \
  --write-report-default
```

Generated normalized-target request plan:

```text
artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.request-plan.v1.json
artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.request-plan-report.json
```

The plan preserves:

- `target_id`, `url`, `method`;
- merged global and per-target headers;
- `body`, `graphql`, `auth_ref`, `extraction_schema_ref` when present;
- inherited or target-level `browser_fallback`, `artifact_policy`, and `retry`;
- target `compliance` metadata;
- a `legacy_http_batch` compatibility section.

## Guarded legacy TL output

The builder can emit a legacy `http.batch` TL transport script only when the request plan can be downgraded to URL-list + global headers without losing request execution semantics:

```bash
python3 scripts/build_tallow_request_plan.py \
  --manifest artifacts/phase2/request-plans/get-only-legacy-safe.target-manifest.v2.json \
  --output artifacts/phase2/request-plans/get-only-legacy-safe.request-plan.v1.json \
  --legacy-tl-output artifacts/phase2/request-plans/get-only-legacy-safe.legacy-http-batch.tl \
  --write-report-default
```

Expected success:

```text
request plan written: artifacts/phase2/request-plans/get-only-legacy-safe.request-plan.v1.json
legacy TL written: artifacts/phase2/request-plans/get-only-legacy-safe.legacy-http-batch.tl
```

The generated TL is a downgrade transport only. Full v2 metadata remains in the request-plan JSON sidecar.

## Fail-fast downgrade behavior

If a manifest contains fields that legacy `http.batch(urls, concurrency, headers)` cannot represent, the request plan is still written for inspection, but the TL file is not emitted and the command exits `2`. If the requested `--legacy-tl-output` already exists from an earlier compatible run, the builder removes that stale file before returning so downstream tools cannot mistake old TL for a current safe downgrade.

Example with the normalized Apollo target artifact:

```bash
python3 scripts/build_tallow_request_plan.py \
  --manifest artifacts/phase2/normalized-targets/targets.example.36b7ab6a20ea.target-manifest.v2.json \
  --output artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.request-plan.v1.json \
  --legacy-tl-output artifacts/phase2/request-plans/targets.example.36b7ab6a20ea.legacy-http-batch.tl \
  --write-report-default
```

Expected result:

```text
exit 2
legacy TL not emitted: manifest contains fields preserved in the request plan that cannot be represented in legacy http.batch TL
```

Known blocking reasons for current artifacts include:

- per-target headers from legacy `per_domain` overrides;
- inherited or target-level retry policy;
- inherited or target-level artifact policy;
- `POST` methods;
- request `body`;
- `graphql` metadata;
- non-`never` browser fallback defaults.

## Verification

```bash
python3 -m unittest tests.test_phase2_request_plan_builder -v
python3 -m py_compile scripts/build_tallow_request_plan.py
./target/debug/tallow check artifacts/phase2/request-plans/get-only-legacy-safe.legacy-http-batch.tl
```

Expected:

```text
OK
check passed: 1 items, 0 warning(s)
```

## Status boundary

This moves BLK-008 further through producer migration:

- normalized v2 target artifacts exist;
- request plans preserve full object-target metadata;
- safe GET/global-header manifests can emit legacy TL transport;
- unsafe/lossy downgrades fail fast instead of silently becoming URL-only GET.

Status after the local/mock runner slice:

- request plans are now consumed directly for local/mock GET, POST JSON GraphQL, retry, and artifact-manifest proof;
- legacy TL downgrade is still only for safe GET/global-header compatibility fixtures;
- unsafe/lossy downgrades fail fast instead of silently becoming URL-only GET.

Still pending before BLK-008 can close:

- live/external policy gates for allowlist/robots/rate-limit/compliance;
- vault-backed auth resolver and redaction proof;
- browser fallback execution with screenshot/HAR artifacts;
- production compliance gates and broader runtime integration.
