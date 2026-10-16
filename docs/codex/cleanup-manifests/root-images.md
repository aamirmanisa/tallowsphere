# Root Image Cleanup Manifest

- Inspected root: `tallowsphere`
- Inspected on: `2026-04-29`
- Scope: root-level image files only

## Safe To Move Out Of Repo Root

None at inspection time.

Evidence:
- Root image count: `59`
- Untracked root images: `0`
- Command used for the untracked check: `git ls-files -o --exclude-standard -- <root image file list>`

## Root Images That Should Stay In Place

Reason:
- `58` root images are tracked and clean.
- `1` root image is tracked and modified, so it should not be moved by cleanup.

Tracked and clean:
- `heb-milk-search.jpg`
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
- `homepage-final.png`
- `homepage-full.png`
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
- `prod-all-products.jpg`
- `prod-chicken-final.jpg`
- `prod-final-search.jpg`
- `prod-homepage.jpg`
- `prod-recipe.jpg`
- `prod-search-fixed.jpg`
- `prod-search-loaded.jpg`
- `prod-store-heb.jpg`
- `prod-store-heb-final.jpg`
- `product-click-test.jpg`
- `product-detail-final.jpg`
- `product-detail-live.jpg`
- `prod-working-search.jpg`
- `recipe-page.png`
- `recipe-results.png`
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
- `usda-signup.jpg`
- `zip-prompt-first-visit.jpg`
- `zip-prompt-test.jpg`
- `zip-search-katy.jpg`
- `zip-set-katy.jpg`
- `zip-typed-katy.jpg`

Tracked and modified:
- `search-chicken.png`
