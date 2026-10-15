# Root Artifact Policy

Audit date: 2026-04-29

This policy resolves the Phase 1 decision work in [next-full-checklist.md](./next-full-checklist.md) without moving tracked root artifacts in the same pass.

## Decision Summary

The remaining tracked repo-root loose-clutter set stays split into three classes:

1. Keep `11` active seed/import data files at the repo root for now.
2. Move `39` tracked documentation/reference screenshots out of the repo root in a separate reviewed move pass.
3. Demote `20` tracked test/proof screenshots into ignored artifacts in a separate reviewed cleanup.

Net: `59` of the remaining `70` tracked loose-clutter files should eventually leave the repo root, but not in this policy pass.

## Keep At Root For Now

These files currently have root-path workflow value and should not move until the dependent scripts are redesigned or parameterized:

- `combined_products.json`
- `heb_products.json`
- `kroger_enriched.sql`
- `kroger_enriched_meili.json`
- `kroger_final.sql`
- `kroger_final_meili.json`
- `kroger_meili.json`
- `kroger_products.json`
- `kroger_seed.sql`
- `seed_meili.json`
- `seed_production.sql`

Reason:

- current `hackthecart/infra/scripts/*` workflows use explicit repo-root paths for this seed/import data
- moving them now would be a behavior change, not just cleanup

## Move Later To Tracked Reference Assets

These files are worth keeping tracked, but not at the repo root. They should move into a tracked reference-assets home in a later reviewed pass.

### Infrastructure Walkthrough Screenshots

- `hetzner-console.jpg`
- `hetzner-gen-token.jpg`
- `hetzner-htc-dashboard.jpg`
- `hetzner-primaryips.jpg`
- `hetzner-rescue.jpg`
- `hetzner-server-overview.jpg`
- `hetzner-servers.jpg`
- `hetzner-sshkeys.jpg`
- `hetzner-token-created.jpg`
- `hetzner-token-reveal.jpg`
- `hetzner-tokens.jpg`

### Vendor Or Onboarding Screenshots

- `heb-milk-search.jpg`
- `kroger-api-products.jpg`
- `kroger-dev.jpg`
- `kroger-dev-home.jpg`
- `kroger-personal-app.jpg`
- `kroger-register-app.jpg`
- `kroger-registered.jpg`
- `kroger-review-bottom.jpg`
- `kroger-step2.jpg`
- `kroger-step3-review.jpg`
- `kroger-verify.jpg`
- `usda-signup.jpg`

### Curated App-State Reference Screenshots

- `homepage-final.png`
- `homepage-full.png`
- `prod-all-products.jpg`
- `prod-chicken-final.jpg`
- `prod-final-search.jpg`
- `prod-homepage.jpg`
- `prod-recipe.jpg`
- `prod-search-fixed.jpg`
- `prod-search-loaded.jpg`
- `prod-store-heb.jpg`
- `prod-store-heb-final.jpg`
- `prod-working-search.jpg`
- `product-detail-final.jpg`
- `product-detail-live.jpg`
- `recipe-page.png`
- `recipe-results.png`

Recommended destination shape for the later move pass:

- `docs/reference-assets/infra/`
- `docs/reference-assets/vendor-onboarding/`
- `docs/reference-assets/app-states/`

## Demote Later To Ignored Artifacts

These files look like test/proof/regression evidence rather than stable tracked assets:

- `product-click-test.jpg`
- `search-chicken.png`
- `search-chicken-bottom.png`
- `search-chicken-fixed.png`
- `search-chicken-images.png`
- `test-01-homepage.png`
- `test-02-search-eggs.png`
- `test-03-search-all.png`
- `test-04-search-bread.png`
- `test-05-recipe-manual.png`
- `test-06-stores.png`
- `test-07-store-heb.png`
- `test-08-mobile-home.png`
- `test-09-mobile-search.png`
- `test-10-mobile-recipe.png`
- `zip-prompt-first-visit.jpg`
- `zip-prompt-test.jpg`
- `zip-search-katy.jpg`
- `zip-set-katy.jpg`
- `zip-typed-katy.jpg`

Recommended destination shape for the later reviewed cleanup:

- `artifacts/reference-tests/`
- `artifacts/manual-proof/`

Those buckets should stay ignored by Git.

## Search Chicken Decision

`search-chicken.png` does not have a tracked-text path dependency that requires it to stay at the repo root.

Current decision:

- do not move `search-chicken.png` by itself
- keep the full `search-chicken*` set together until the whole test/proof screenshot bucket is handled in one reviewed pass

## What This Pass Does Not Do

- no tracked root artifacts were moved in this pass
- no file references were rewritten in this pass

That means the conditional checklist item about updating direct references after a move remains open until the later tracked-asset move pass happens.
