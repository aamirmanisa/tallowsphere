# Repo-Root Artifact Classification

Audit source: `tallowsphere/docs/codex/cleanup-execution.md`

Audit result: `git ls-files -- <listed root files>` returned all `70` listed files, so this classification covers the full remaining tracked repo-root loose-clutter set.

## Category Table

| Category | Count | Recommended policy | Basis |
| --- | ---: | --- | --- |
| Active seed/import data files with hardcoded repo-root workflow paths | 11 | Keep at root | Referenced by `hackthecart/infra/scripts/*.js` with explicit `e:/Nixe/<file>` reads/writes; moving them now would be a workflow change, not just cleanup. |
| Hetzner/infrastructure walkthrough screenshots | 11 | Move to tracked reference-assets | Human-reference deployment/setup captures; tracked, but not runtime inputs. |
| Vendor/onboarding walkthrough screenshots | 12 | Move to tracked reference-assets | Human-reference captures for Kroger/USDA/HEB flows; useful context, but root placement adds clutter. |
| Curated app-state reference screenshots | 16 | Move to tracked reference-assets | Visual baselines for app/search/detail states; worth keeping tracked, but not at repo root. |
| Test/proof/regression screenshots | 20 | Move to ignored artifacts in separate reviewed cleanup | Filename patterns indicate ad hoc verification output rather than stable source assets; they are not code-referenced. |

## Per-Category Counts

| Policy | File count |
| --- | ---: |
| Keep at root | 11 |
| Move to tracked reference-assets | 39 |
| Move to ignored artifacts in separate reviewed cleanup | 20 |

## Category Details

### 1. Active seed/import data files

Count: `11`

Recommended policy: `Keep at root`

Files:
`combined_products.json`, `heb_products.json`, `kroger_enriched.sql`, `kroger_enriched_meili.json`, `kroger_final.sql`, `kroger_final_meili.json`, `kroger_meili.json`, `kroger_products.json`, `kroger_seed.sql`, `seed_meili.json`, `seed_production.sql`

Why:
These are the only remaining loose-clutter files with confirmed tracked-text references in the repo. The `hackthecart/infra/scripts` workflow currently reads from and writes to explicit repo-root paths for these files. Until that workflow is relocated or parameterized, cleanup should not move them.

### 2. Hetzner/infrastructure walkthrough screenshots

Count: `11`

Recommended policy: `Move to tracked reference-assets`

Files:
`hetzner-console.jpg`, `hetzner-gen-token.jpg`, `hetzner-htc-dashboard.jpg`, `hetzner-primaryips.jpg`, `hetzner-rescue.jpg`, `hetzner-server-overview.jpg`, `hetzner-servers.jpg`, `hetzner-sshkeys.jpg`, `hetzner-token-created.jpg`, `hetzner-token-reveal.jpg`, `hetzner-tokens.jpg`

Why:
These appear to be operator/reference screenshots for hosting setup. They may still be useful, but they behave like documentation assets, not root-level project files.

### 3. Vendor/onboarding walkthrough screenshots

Count: `12`

Recommended policy: `Move to tracked reference-assets`

Files:
`heb-milk-search.jpg`, `kroger-api-products.jpg`, `kroger-dev.jpg`, `kroger-dev-home.jpg`, `kroger-personal-app.jpg`, `kroger-register-app.jpg`, `kroger-registered.jpg`, `kroger-review-bottom.jpg`, `kroger-step2.jpg`, `kroger-step3-review.jpg`, `kroger-verify.jpg`, `usda-signup.jpg`

Why:
These look like one-off capture sequences for partner/API onboarding and manual verification. They may support docs or historical context, but they do not justify ongoing repo-root placement.

### 4. Curated app-state reference screenshots

Count: `16`

Recommended policy: `Move to tracked reference-assets`

Files:
`homepage-final.png`, `homepage-full.png`, `prod-all-products.jpg`, `prod-chicken-final.jpg`, `prod-final-search.jpg`, `prod-homepage.jpg`, `prod-recipe.jpg`, `prod-search-fixed.jpg`, `prod-search-loaded.jpg`, `prod-store-heb.jpg`, `prod-store-heb-final.jpg`, `prod-working-search.jpg`, `product-detail-final.jpg`, `product-detail-live.jpg`, `recipe-page.png`, `recipe-results.png`

Why:
These look like intentional visual baselines or "known-good" captures. Keeping them tracked can make sense, but they belong with other reviewed reference assets instead of the repo root.

### 5. Test/proof/regression screenshots

Count: `20`

Recommended policy: `Move to ignored artifacts in separate reviewed cleanup`

Files:
`product-click-test.jpg`, `search-chicken.png`, `search-chicken-bottom.png`, `search-chicken-fixed.png`, `search-chicken-images.png`, `test-01-homepage.png`, `test-02-search-eggs.png`, `test-03-search-all.png`, `test-04-search-bread.png`, `test-05-recipe-manual.png`, `test-06-stores.png`, `test-07-store-heb.png`, `test-08-mobile-home.png`, `test-09-mobile-search.png`, `test-10-mobile-recipe.png`, `zip-prompt-first-visit.jpg`, `zip-prompt-test.jpg`, `zip-search-katy.jpg`, `zip-set-katy.jpg`, `zip-typed-katy.jpg`

Why:
These filenames read like ad hoc test evidence, prompt-flow captures, and intermediate debugging outputs. They are good candidates for a reviewed demotion into ignored artifacts rather than a permanent tracked-root inventory.

## Recommended Overall Decision

Treat the remaining tracked repo-root loose clutter as three buckets:

1. Keep the `11` active seed/import files at the repo root for now because current `hackthecart` scripts hardcode those paths.
2. Move the `39` documentation/reference screenshots into a tracked reference-assets home during the next full cleanup pass.
3. Review the `20` test/proof screenshots for demotion into ignored artifacts instead of preserving them as tracked files.

Net recommendation: `59` of the remaining `70` tracked loose-clutter files should leave the repo root in the next-full checklist, while the `11` script-bound data files should stay put until their workflow paths are explicitly redesigned.

## Changed Files

- `tallowsphere/docs/codex/next-full-work/root-artifact-classification.md`
