# Codex Review Checklists

Use this with the root `AGENTS.md`: start in the smallest relevant directory, keep verification narrow, and treat `Nixe` as multiple products rather than one repo-wide app.

## HackTheCart: data-sensitive changes

Apply this when touching `hackthecart/api/`, `hackthecart/import/`, `hackthecart/importers/`, `hackthecart/config/`, `hackthecart/schema/`, `hackthecart/infra/scripts/`, or `hackthecart/pipeline*.{mjs,tl}`.

- Product data correctness beats throughput. Do not invent product fields, dietary flags, nutrition, or cross-store matches.
- Preserve store/source provenance. If a change alters matching, enrichment, or rollups, confirm the provenance still survives into indexed documents.
- Treat `hackthecart/config/default_product_store_config.toml` and `hackthecart/config/default_product_store_config.checklist.md` as contract files, not optional notes.
- If schema or pipeline behavior changes, review the matching tables and route dependencies in `hackthecart/schema/postgres/25_pipeline_tables.sql`.
- Re-check price and recency invariants before signoff: `min_price_cents <= max_price_cents`, no silent zero/negative-price acceptance, and no stale `last_seen_unix` assumptions.
- If a change touches user, household, audit, or legal flows, review it as privacy-sensitive. Do not add raw personal data logging, raw secret serialization, or undocumented data retention behavior.
- `hackthecart/legal/` is draft legal/compliance material. Only edit it when the task explicitly includes legal/compliance docs or evidence.
- Minimum verification should match the change: targeted `cargo test -p hackthecart-api` for API work, plus any narrow data validation or product-quality check needed by the changed pipeline/config path.

## Tallow Search: API contract changes

Apply this when touching `tallow-search/api/src/routes/`, `tallow-search/api/src/scheduler.rs`, `tallow-search/api/src/state.rs`, `tallow-search/api/src/engine*.rs`, or contract docs under `tallow-search/docs/`.

- Treat JSON field names, query params, error envelopes, SSE payloads, webhook payloads, and degraded-state fields as public contracts.
- Do not silently rename or remove aliases. When canonical and alias parameters coexist, canonical behavior should stay authoritative.
- If the finance surface changes, update `tallow-search/docs/finance_contracts.md` in the same change or state why the doc is intentionally unchanged.
- If extraction, sheet, or canonical-output shapes change, review the relevant contract docs such as `tallow-search/docs/mega_sheet_contract.md`.
- Update the narrowest matching contract tests instead of relying on a broad suite. The main drift guards already live in `tallow-search/api/tests/finance_contracts.rs`, `tallow-search/api/tests/level_contract_wiring.rs`, and `tallow-search/api/tests/policy_router_contracts.rs`.
- If the change affects DB-backed payload shape or migration assumptions, also review the `migrations_schema_contract` test path used by `tallow-search` release gates.
- State whether `tallow-search/web/` consumers need coordinated changes. Do not claim live behavior you did not verify.
- Avoid editing `tallow-search/docs/signoff/` unless the task explicitly asks for evidence/signoff refreshes.

## Tallow root: performance- or safety-sensitive compiler/runtime changes

Apply this when touching root Rust engine code under `src/`, `crates/`, `stdlib/`, `tests/`, or `examples/`, especially `src/parser.rs`, `src/lexer.rs`, `src/typeck.rs`, `src/codegen.rs`, `src/legal_pass.rs`, `src/pkg/legal_propagation.rs`, `src/runtime/io_uring_runtime.rs`, or `src/agent_runtime.rs`.

- Treat parser, lexer, type-checking, codegen, runtime, and legal-pass changes as high risk. These can affect compiler speed, runtime stability, or privacy guarantees that downstream projects rely on.
- Review for panic-on-malformed-input regressions, accidental quadratic behavior, hot-path allocation churn, and widened concurrency or I/O failure surfaces.
- If the change affects parse/compile hot paths, compare against the benchmark guidance in `docs/compiler_parser_perf.md` and use `scripts/benchmark_compiler_parser.ps1` when a real performance claim is being made.
- Be extra strict around `private`, `secret`, and `@legal` behavior. A weakening in `src/legal_pass.rs` or `src/pkg/legal_propagation.rs` is a cross-project safety regression, not a local refactor.
- Add or update focused regression tests close to the changed behavior. For compiler/runtime work, "works on one example" is not enough.
- Use the smallest Rust verification loop that proves the change: `cargo check`, `cargo test --lib`, or a targeted `cargo test <name> -- --nocapture`.

## Do not touch without explicit intent

These paths are either vendor-like, generated, noisy, or evidence-oriented. Do not edit them unless the task is specifically about them.

- `firecrawl-self-hosted/`: vendored monorepo with its own guidance and workflows.
- `vendor/`: third-party source copies.
- `node_modules/`, `target/`, `dist/`, `.playwright-mcp/`, `artifacts/`, `tmp/`, `tmp_*`, `probe_*`, `.tallow-schemas*`, `pytest-cache-files-*`: generated, disposable, or high-noise paths.
- `tallow-search/docs/signoff/`: release/signoff evidence, not normal product source.
- `hackthecart/legal/launch-evidence/generated/`: generated launch evidence artifacts.
- Large committed dumps or one-off data roots such as `kroger_data/` should be treated as read-only context unless the task explicitly calls for data regeneration or cleanup.

## Phase 6 recommendation

Do not add a repo-specific `~/.codex/AGENTS.md` for this setup right now. `~/Nixe` already has root and subproject instruction layering, and a global repo-tuned AGENTS file would make that harder to reason about.

An optional user-level `~/.codex/config.toml` is reasonable only for personal defaults such as model, verbosity, or approval settings. Keep repo behavior, path rules, and review policy inside this repo so local `AGENTS.md` files stay authoritative.
