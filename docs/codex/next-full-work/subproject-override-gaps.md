# Subproject Override Gap Audit

Scope: audit whether `tallow-search/extension` plus root `scripts/` and root `docs/` need narrower local `AGENTS` overrides, without creating those override files yet.

## Current AGENTS coverage

| Area | Effective coverage today | What the nearest guidance actually covers | Gap assessment |
| --- | --- | --- | --- |
| `tallow-search/api` and `tallow-search/web` | Root `AGENTS.md` plus `tallow-search/AGENTS.md` | The local file explicitly scopes `tallow-search/` as "a Rust API plus an Astro/Svelte frontend" and gives API/web commands (`cargo test -p tallow-search-api`, `cd web && npm run check`, `cd web && npm run build`) | Coverage is good for API/web work. |
| `tallow-search/extension` | Root `AGENTS.md` plus `tallow-search/AGENTS.md` | The same local file still only talks about API, web, and project docs. It does not mention browser-extension files, browser permissions, or extension-specific verification. | This subtree inherits instructions that are directionally related to the product, but too narrow for the actual extension workflow. |
| Root `scripts/` | Root `AGENTS.md` only | The root file frames root work as the Tallow compiler/runtime in Rust and suggests root Rust commands such as `cargo check` and `cargo test --lib`. | Coverage is too generic for script/tooling work and points readers toward the wrong verification loop. |
| Root `docs/` | Root `AGENTS.md` only | The root file gives workspace-wide search/noise rules and points UI work at `docs/codex/ui-baseline.md`, `docs/codex/accessibility.md`, and `docs/codex/motion-performance.md`. | Coverage is generic but not obviously wrong. The main question is whether a docs-local file would clarify enough to justify another layer. |

## Extension workflow differences versus API/web

`tallow-search/extension` is not another Rust or Astro package. The current subtree is a Manifest V3 browser extension made of `manifest.json`, `background.js`, `popup.html`, `popup.js`, and icons.

The practical workflow differs from `api/` and `web/` in a few important ways:

1. It is browser-runtime code, not Cargo or npm package work.
   There is no local package manifest or documented extension build/check command in the subtree. The main moving parts are Chrome extension APIs such as `chrome.contextMenus`, `chrome.permissions`, `chrome.storage`, and `chrome.tabs`.

2. Verification is interaction-driven.
   Useful checks are things like loading the unpacked extension, opening the popup, saving settings, confirming permission prompts, testing analyze/scrape actions, and verifying context-menu behavior on real `http(s)` pages.

3. Its integration boundary is different.
   The extension defaults to `http://localhost:3001/api/v1`, dynamically requests host permissions, and contains extension-specific transport/CORS behavior such as refusing token use on insecure non-local hosts and warning about `CORS_EXTENSION_ORIGINS`.

4. The failure modes are different.
   Typical breakage here is permission state, popup UX, service-worker behavior, host matching, or API-origin issues. Those are not covered by `cargo test -p tallow-search-api` or `cd web && npm run check`.

That makes `tallow-search/extension` a real workflow split inside the subproject, not just another folder under the existing API/web guidance.

## Recommendations

| Location | Add a local override? | Recommendation |
| --- | --- | --- |
| `tallow-search/extension` | Yes | Add a narrow local override. The current nearest file describes the wrong primary workflow for this subtree. A local file should say this is MV3 browser-extension code, prefer extension-local searches, and verify with the smallest realistic browser-extension loop rather than API/web package commands. It should also call out permission/CORS/token-safety checks because those are first-order behaviors in this directory. |
| Root `scripts/` | Yes | Add a local override. This directory is its own tooling surface, with a heavy mix of `.tl`, `.ps1`, and a few helper `.py` files, plus many benchmark/validation runners. Root Rust commands are not a good default here. A local file should push people toward targeted script execution, explicit note of external-service side effects, and avoiding broad churn across logs, generated outputs, or unrelated helper scripts. |
| Root `docs/` | No, not at `docs/` root right now | Do not add a single docs-wide override yet. `docs/` is too mixed: codex guidance, research, operations, reference HTML, screenshots, and other artifacts all live there. A top-level docs override would either duplicate the root rules or become too broad to stay useful. If repeated work concentrates in `docs/codex/`, a smaller override there would make more sense than a catch-all `docs/AGENTS.md`. |

## Bottom line

There are two clear override gaps and one weak case:

- `tallow-search/extension`: real gap, add a local override.
- Root `scripts/`: real gap, add a local override.
- Root `docs/`: not a good candidate for one shared override yet; keep using the root file unless a narrower docs subtree becomes the stable working surface.
