# Cleanup Execution

Audit date: 2026-04-29

Scope: safe cleanup of repo-root disposable clutter in `E:\Nixe` without relocating tracked project assets.

## Result

The disposable-root-clutter pass is complete.

- Root `probe_*` entries: `38 -> 0`
- Root `tmp_*` entries: `14 -> 0`
- Root loose clutter files: `130 -> 70`
- `artifacts/` file count: `2100 -> 2232`
- `tmp/` file count: `34609 -> 34609`
- `.playwright-mcp/` file count: `509 -> 509`

The remaining `70` root loose clutter files are all tracked. Only one of them is currently modified: `search-chicken.png`.

## Moves Performed

- Moved `130` repo-root image artifacts into `artifacts/root-clutter/images/`
- Moved `95` repo-root data/report artifacts into `artifacts/root-clutter/data/`
- Moved `45` additional untracked repo-root JSON/HTML/CSV outputs into `artifacts/root-clutter/data/root-late-pass/`
- Moved `3` repo-root `probe_*.txt` files into `artifacts/root-clutter/probe-files/`
- Moved `14` repo-root `probe_browser_new_page_*` directories into `artifacts/probes/browser-new-page/`
- Moved `20` repo-root `probe_browser_page_ops_*` directories into `artifacts/probes/page-ops/`
- Moved `1` repo-root `probe_ideabrowser_*` directory into `artifacts/probes/ideabrowser/`
- Moved `4` repo-root `pytest-cache-files-*` directories into `tmp/pytest/`
- Moved `14` repo-root `tmp_*` files into `tmp/scratch/`
- Consolidated earlier root temp/probe directories under `tmp/root-legacy/dirs/`:
  - `ideabrowser_mega_1777115000745`
  - `ideabrowser_mega_1777119283558`
  - `ideabrowser_mega_1777119917854`
  - `tmp_bench_compiler_parser`
  - `tmp_chrome_profile_test`
  - `tmp_chrome_profile_test2`
  - `tmp_remote_api`
  - `tmp_tl_probe`
  - `tmp_tools`

## Safety Note

An earlier bulk move temporarily displaced the tracked file `search-chicken.png`. It was restored immediately to the repo root. The file is still present in place and remains modified, not deleted.

## Remaining Root Loose Clutter

These files remain at the repo root because they are tracked project/reference assets, not disposable run output:

```text
combined_products.json
heb_products.json
heb-milk-search.jpg
hetzner-console.jpg
hetzner-gen-token.jpg
hetzner-htc-dashboard.jpg
hetzner-primaryips.jpg
hetzner-rescue.jpg
hetzner-server-overview.jpg
hetzner-servers.jpg
hetzner-sshkeys.jpg
hetzner-token-created.jpg
hetzner-token-reveal.jpg
hetzner-tokens.jpg
homepage-final.png
homepage-full.png
kroger_enriched.sql
kroger_enriched_meili.json
kroger_final.sql
kroger_final_meili.json
kroger_meili.json
kroger_products.json
kroger_seed.sql
kroger-api-products.jpg
kroger-dev.jpg
kroger-dev-home.jpg
kroger-personal-app.jpg
kroger-register-app.jpg
kroger-registered.jpg
kroger-review-bottom.jpg
kroger-step2.jpg
kroger-step3-review.jpg
kroger-verify.jpg
prod-all-products.jpg
prod-chicken-final.jpg
prod-final-search.jpg
prod-homepage.jpg
prod-recipe.jpg
prod-search-fixed.jpg
prod-search-loaded.jpg
prod-store-heb.jpg
prod-store-heb-final.jpg
product-click-test.jpg
product-detail-final.jpg
product-detail-live.jpg
prod-working-search.jpg
recipe-page.png
recipe-results.png
search-chicken.png
search-chicken-bottom.png
search-chicken-fixed.png
search-chicken-images.png
seed_meili.json
seed_production.sql
test-01-homepage.png
test-02-search-eggs.png
test-03-search-all.png
test-04-search-bread.png
test-05-recipe-manual.png
test-06-stores.png
test-07-store-heb.png
test-08-mobile-home.png
test-09-mobile-search.png
test-10-mobile-recipe.png
usda-signup.jpg
zip-prompt-first-visit.jpg
zip-prompt-test.jpg
zip-search-katy.jpg
zip-set-katy.jpg
zip-typed-katy.jpg
```

## Deferred

- `/.playwright-mcp/` remains in place. It is a tracked archive-like bucket and was intentionally excluded from this cleanup pass.
- The worktree still contains many tracked modifications outside the cleanup scope. This pass did not attempt to normalize repo-wide status.
