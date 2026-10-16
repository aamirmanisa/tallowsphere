# HackTheCart Override Gap Audit

## Current AGENTS Coverage

- Effective instruction chain for most HackTheCart work today:
  - `E:\Nixe\AGENTS.md`
  - `E:\Nixe\hackthecart\AGENTS.md`
- Current deeper coverage inside `hackthecart/`: none. `rg --files hackthecart -g AGENTS.md` returns only `hackthecart\AGENTS.md`.
- What the current HackTheCart file already does well:
  - Defines the product-level priority: data correctness over scrape throughput.
  - Calls out the highest-risk directories: `api/`, `web/`, `import/`, `importers/`, `infra/scripts/`, `config/`, and `schema/`.
  - Gives standard verification entry points for workspace Rust, API-only Rust, and the web build.
  - Anchors pipeline work to `config/default_product_store_config.toml`, the checklist markdown, and `schema/postgres/25_pipeline_tables.sql`.
- Main coverage gaps:
  - No path-local instructions for the standalone `hackthecart/import` crate.
  - No path-local guardrails for `infra/scripts/`, which mixes operational Node scripts, `.mjs`/`.js`, `.tl` programs, deploy helpers, and a nested `node_modules/`.
  - No path-local instructions for `data/` or `pipeline_data/`, both of which contain large generated or snapshot-style artifacts that are expensive and low-signal to scan naively.

## Workflow Differences By Area

| Area | Current workflow shape | What is already covered | What is missing |
| --- | --- | --- | --- |
| `hackthecart/api/` | Conventional Rust package in the workspace. Targeted package test command exists: `cargo test -p hackthecart-api`. README is API/server-oriented and mentions route surface and env vars. | Current `hackthecart/AGENTS.md` already says API changes should get targeted route tests and gives the package-specific test command. | No urgent gap. This area is conventional and already close to the right level of guidance. |
| `hackthecart/web/` | Conventional Astro/Svelte frontend. `package.json` exposes `dev`, `build`, `preview`, `check`, `lint`, and `test` aliases. | Root `AGENTS.md` already points UI work at `docs/codex/ui-baseline.md`, `accessibility.md`, and `motion-performance.md`. Local HackTheCart guidance already says web changes should build successfully. | No urgent gap. Existing root + subproject guidance is sufficient for normal web edits. |
| `hackthecart/import/` | Separate Rust crate, not part of the root workspace members. README documents manual dataset acquisition, long-running imports, SQLite output, and Open Food Facts licensing/attribution constraints. Verification is `cd hackthecart/import && cargo test`. | The parent file names `import/` as important, but its command section does not include the crate-local build/test loop or the dump-handling constraints. | Missing crate-local rules about using synthetic fixtures, avoiding full dump downloads unless required, and preserving data-license expectations. |
| `hackthecart/infra/scripts/` | Operational script bucket with many one-off and batch scripts across Node, `.mjs`, `.js`, `.cjs`, Python, and `.tl`. Includes deploy helpers and a nested `node_modules/`. `package.json` has only a few targeted scripts; many files look like direct-entry operational tools. | Parent guidance says pipeline logic should review checklist/config before finishing. | Missing operational guardrails: do not run broad scrapers, deploy scripts, or live-data backfills without explicit need; ignore `node_modules/`; prefer the smallest targeted script/test; treat this directory as high-risk for side effects. |
| `hackthecart/data/` and `hackthecart/pipeline_data/` | Data-heavy snapshot areas with large JSON, JSONL, CSV, upload batches, and reports. Examples observed: `products_all.jsonl` (~14 MB), `all_products.json` (~186 MB), `all_products.csv` (~40 MB). | Root workspace guidance generally says to avoid noisy/generated paths, but these two directories are not named explicitly and are first-class project inputs/outputs in practice. | Missing explicit local guidance to avoid broad scans, sample files instead of opening whole dumps, treat many artifacts as generated, and avoid accidental churn in batch outputs. |

## Recommendation

Additional narrower overrides should be added now, but only for the import/infra/data-heavy paths. `api/` and `web/` do not need deeper overrides yet.

### Add Now

1. `E:\Nixe\hackthecart\import\AGENTS.override.md`
   - Reason: `import/` is a separate crate with its own build/test loop and dataset-handling rules that are not captured by the workspace-level HackTheCart instructions.
   - The override should cover:
     - Use `cd hackthecart/import && cargo test` as the default verification loop.
     - Prefer small synthetic fixtures over full USDA/OFF dumps.
     - Do not download or process the full Open Food Facts dataset unless the task explicitly requires it.
     - Preserve licensing/attribution expectations for OFF-derived data.

2. `E:\Nixe\hackthecart\infra\scripts\AGENTS.override.md`
   - Reason: this directory is operational, side-effect-heavy, multi-runtime, and cluttered with one-off scripts plus a nested `node_modules/`.
   - The override should cover:
     - Treat `node_modules/`, generated CSV/JSON outputs, and target-specific artifacts as low-signal.
     - Do not run deploy scripts, full scrapers, backfills, or live upload helpers unless explicitly requested.
     - Prefer reading `package.json` scripts first, then the smallest relevant script file.
     - Verify with the narrowest runnable command or with static inspection when execution would touch live systems.

3. `E:\Nixe\hackthecart\data\AGENTS.override.md`
   - Reason: this directory mixes seed SQL, helper scripts, and large data artifacts. It needs explicit guidance to keep agents from bulk-reading or rewriting snapshots.
   - The override should cover:
     - Sample large files with targeted reads/searches instead of full-file opens.
     - Treat bulk JSON/JSONL/CSV artifacts as generated or reference data unless the task explicitly says to edit them.
     - Prefer touching source scripts or SQL over mass-editing generated outputs.

4. `E:\Nixe\hackthecart\pipeline_data\AGENTS.override.md`
   - Reason: this is the heaviest snapshot area and is separate from `data/`, so it needs its own local guardrails.
   - The override should cover:
     - Avoid opening full `all_products.*` or batch upload payloads unless absolutely necessary.
     - Read metadata, schemas, or small samples first.
     - Treat upload batches and verification reports as pipeline outputs that should not be regenerated casually.

### Do Not Add Now

1. `E:\Nixe\hackthecart\api\AGENTS.override.md`
   - Not needed yet. The area is conventional, the package-level test command already exists, and the current HackTheCart guidance already tells agents to run targeted API tests.

2. `E:\Nixe\hackthecart\web\AGENTS.override.md`
   - Not needed yet. Root UI guidance plus the existing `npm run build` rule already covers the normal edit loop.

## Bottom Line

HackTheCart does need narrower local overrides now, but the need is concentrated in the non-conventional paths:

- add overrides for `import/`
- add overrides for `infra/scripts/`
- add overrides for `data/`
- add overrides for `pipeline_data/`
- do not add deeper overrides for `api/` or `web/` yet

This keeps the instruction layering aligned with the actual workflow split: conventional package work stays on the current root plus subproject files, while operational and data-heavy paths get explicit local guardrails.
