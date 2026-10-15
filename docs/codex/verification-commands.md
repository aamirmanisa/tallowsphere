# Verification Commands

Use this as the manual baseline for verification in `~/Nixe` until wrapper scripts exist. Start in the smallest relevant subproject, run the narrowest command that proves the change, and only widen the loop when the change crosses package, contract, or workflow boundaries.

## Targeted vs broader checks

- Use targeted checks when the change is isolated to one crate, one package, one route group, one importer, or one frontend app.
- Step up to a broader check when the change touches shared crates, shared workspace dependencies, schema/pipeline contracts, public API shapes, or multiple subprojects.
- If a targeted check fails in a way that suggests integration fallout, widen one level instead of jumping straight to a repo-wide run.
- If a change spans API and web in the same product, verify both sides before signoff.
- For docs-only edits, no code verification is required unless the doc changes a workflow that should be proved immediately.

## Root Tallow compiler/runtime

Run from `~/Nixe`.

- Fast compile sanity: `cargo check`
- Main Rust regression loop: `cargo test --lib`
- Focused regression for one area: `cargo test <name> -- --nocapture`

Use `cargo check` first for small compiler/runtime edits. Move to `cargo test --lib` when behavior changes or when a root crate dependency moved. Use a named test when you are tightening one parser, lexer, type-checking, codegen, runtime, or legal-pass regression.

## HackTheCart API

Run from `~/Nixe/hackthecart`.

- API-only verification: `cargo test -p hackthecart-api`
- Broader Rust workspace verification: `cargo test`

Start with `cargo test -p hackthecart-api` for route, handler, serialization, or API-only behavior. Move to full `cargo test` when the change also touches shared workspace crates such as storage, jobs, mailer, OCR, indexer, or other Rust packages used by the API.

## HackTheCart web

Run from `~/Nixe/hackthecart/web`.

- Main web verification: `npm run build`
- Light Astro sync sanity: `npm run check`

Use `npm run build` as the normal proof for UI changes. `npm run check` is a lighter pass when you only need Astro sync/type generation sanity, but it does not replace `npm run build` for meaningful web changes. If the web change depends on an API contract change, also run the matching API command.

## HackTheCart pipeline and import work

Use the narrowest command that matches the part you changed.

- Canonical import crate: `cd ~/Nixe/hackthecart/import && cargo test`
- Standalone importer crate: `cd ~/Nixe/hackthecart/importers && cargo test`
- Workspace-managed pipeline packages: `cd ~/Nixe/hackthecart && cargo test -p <package>`

Use `hackthecart/import` when you changed the SQLite staging and merge flow. Use `hackthecart/importers` when you changed one of the standalone source importers. Use package-specific `cargo test -p <package>` from `hackthecart/` for workspace-managed pipeline code such as `jobs`, `indexer`, or other Rust pipeline components.

If the change affects pipeline scripts or contract files such as `pipeline*.{mjs,tl}`, `config/default_product_store_config.toml`, or `schema/postgres/25_pipeline_tables.sql`, pair the Rust test with the narrowest data or dry-run validation already documented next to that workflow instead of inventing a new one-off script.

## Tallow Search API

Run from `~/Nixe/tallow-search`.

- API verification: `cargo test -p tallow-search-api`

This is the default check for API routes, schedulers, search execution, persistence adapters, and contract behavior. Keep it targeted unless the change also affects the web app or shared root code.

## Tallow Search web

Run from `~/Nixe/tallow-search/web`.

- Main web verification: `npm run check`
- Build verification: `npm run build`

Use `npm run check` first for normal UI and type-level validation. Add `npm run build` when the change affects routing, adapters, build-time content, or anything that could pass checks but still fail the production bundle. If the web change relies on an API shape change, also run `cargo test -p tallow-search-api`.

## Firecrawl API

Run from `~/Nixe/firecrawl-self-hosted/apps/api`.

Use `pnpm harness ...` for verification here. Do not invent a manual service boot flow.

- Default API test loop: `pnpm harness pnpm test`
- Snips-focused loop: `pnpm harness pnpm test:snips`
- Broader authenticated/fuller coverage: `pnpm harness pnpm test:full`

Start with `pnpm harness pnpm test` for normal API work. Use `pnpm harness pnpm test:snips` when you only changed snips behavior. Escalate to `pnpm harness pnpm test:full` when the change reaches broader end-to-end or authenticated surfaces.

## Practical escalation guide

- One Rust crate or one named regression changed: run the package-level or named test only.
- Shared Rust crate, workspace dependency, or cross-crate plumbing changed: widen to that product's broader Rust test command.
- One frontend app changed without backend contract movement: run that app's normal web command only.
- API contract plus consuming web UI changed together: run both the API and web commands for that product.
- Data/pipeline/config/schema work changed behavior: run the narrow Rust test first, then the closest existing dry-run or data validation already documented for that workflow.
