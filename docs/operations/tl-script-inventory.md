# TL Script Classification Inventory

> status: verified 2026-09-05 (C6 docs wave — canonical inventory `artifacts/tl-script-inventory.json` exists on disk, 230 KB, 2026-08-08 mtime).

Status: current local classification baseline for P2-003.

The canonical machine-readable inventory is:

```text
artifacts/tl-script-inventory.json
```

It classifies every non-ignored `.tl` file returned by:

```bash
git ls-files -co --exclude-standard '*.tl'
```

The inventory is classification-only. It does **not** execute scripts, grant live-network approval, or make historical/live/browser/vault scripts production-ready.

## Classifications

| Classification | Meaning |
| --- | --- |
| `active example` | Maintained TL source/library/bootstrap files plus language or stdlib examples. This is not a live/browser/vault production-readiness claim. |
| `fixture test` | Test fixtures, self-host tests, import tests, E2E harnesses, and report harnesses. |
| `historical probe` | Temporary/debug/business-specific one-off scripts retained for history only. Promote only with owner, tests, docs, and an inventory update. |
| `unsafe/deprecated` | Live/stealth/bypass/Tor/proxy/deploy/credential/captcha/headed/network-heavy scripts. Do not run as production examples without explicit human/legal approval and fail-closed gates. |
| `superseded by manifest/request-plan` | Legacy generated batch/scraper/crawler/pipeline scripts that should migrate to `sources_manifest.json` plus `request-plan.v1.json`. |

## Current summary

The P2-003 inventory currently records:

| Metric | Count |
| --- | ---: |
| Total `.tl` files | 470 |
| Git-tracked `.tl` files | 220 |
| Untracked `.tl` files | 250 |
| Active examples | 136 |
| Fixture tests | 104 |
| Historical probes | 51 |
| Unsafe/deprecated | 107 |
| Superseded by manifest/request-plan | 72 |

## Verification

Run:

```bash
python3 -B -m unittest tests.test_tl_script_inventory -v
```

The test fails if:

- any non-ignored `.tl` file is missing from the inventory;
- an inventory path is duplicated;
- a classification is outside the allowed set;
- summary counts drift from entries;
- tracked/untracked state drifts from git;
- known unsafe/superseded/fixture examples are mislabeled;
- unsafe/deprecated or superseded entries lack actionable rationale.

## Operator guidance

- Use `examples/` and release-quality generated examples as current references.
- Treat `unsafe/deprecated` scripts as blocked unless a future card adds explicit approvals, local proofs, and fail-closed live gates.
- Treat `superseded by manifest/request-plan` scripts as migration candidates, not current best practice.
- Treat `historical probe` scripts as archive/debug material only.
