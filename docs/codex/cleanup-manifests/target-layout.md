# Target Layout

Goal: keep repo-root clutter out of the root without breaking documented artifact paths.

## Rules

- `tmp/` is for disposable working state and scratch output.
- `artifacts/` is for retained run output, evidence, probes, and generated deliverables.
- Keep existing documented artifact roots when they already appear in docs: `artifact_bundles/`, `bench/`, `benchmarks/`, `doctor/`, `generated_tl/`, `integration/`, `runtime-probes/`, `scraper_runs/`.
- Do not create new root `tmp_*`, `probe_*`, or `artifacts/tmp*` paths.

## Target Tree

```text
tmp/
  cache/
    pip/
    python/
  pytest/
  browser-profiles/
  manual-tests/
  analysis/
  scratch/

artifacts/
  artifact_bundles/
  bench/
  benchmarks/
  doctor/
  generated_tl/
  integration/
  runtime-probes/
  scraper_runs/
  probes/
    browser-new-page/
    page-ops/
    ideabrowser/
    playwright-mcp/
  evidence/
    phases/
    preflight/
    ad-hoc/
  root-clutter/
    tmp-files/
    probe-files/
    unclassified/
```

## Move Map

| Current root clutter bucket | Target | Notes |
| --- | --- | --- |
| Root `tmp_*.log/json/html/csv/sql/sh` files | `tmp/scratch/` | Lowest-risk landing zone for one-off scratch files. |
| Root `tmp_*` directories used for caches or temp state | `tmp/cache/`, `tmp/pytest/`, `tmp/browser-profiles/`, or `tmp/scratch/` | Prefer a specific bucket when obvious; otherwise use `tmp/scratch/<original-name>/`. |
| Root `probe_*` directories | `artifacts/probes/<family>/<original-name>/` | Split by probe family first (`browser-new-page`, `page-ops`, `ideabrowser`). |
| Root `probe_*.txt` files | `artifacts/root-clutter/probe-files/` | Keep filenames unchanged for traceability. |
| `/.playwright-mcp/` | `artifacts/probes/playwright-mcp/` | Treat as retained capture output, not temp state. |
| `artifacts/tmp/` and `artifacts/tmp_*` | `tmp/scratch/` if disposable; otherwise `artifacts/root-clutter/unclassified/` | Avoid keeping a second temp convention under `artifacts/`. |
| `phase*_evidence`, `worker*_preflight`, `dual_cycle`, `expansion` | `artifacts/evidence/` | Normalize ad-hoc evidence folders without touching stable run roots. |

## Practical Default

If a cleanup item is clearly temporary, move it under `tmp/`. If someone may need to inspect or cite it later, move it under `artifacts/`. If classification is uncertain during the safe move, use `artifacts/root-clutter/unclassified/` and preserve the original name.
