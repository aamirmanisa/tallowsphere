# EXTRACTION ENGINE — RECONCILIATION & FOLDER AUDIT

**Date:** 2026-10-12
**Trigger:** folder-wide audit of `/home/user/Nixe` (41 GB, one repo + 30 adjacent trees).
**Purpose:** reconcile today's `EXTRACTION-ENGINE-SPEC.md` against what already exists, and reduce 123 proposed features to the actually-remaining work.

## 0. Headline

A catalog of 123 "new" extraction features was written today before checking the folder. **Most of them already exist and are real.**

The repo already contains:
- **136 files in `src/browser/`** (3.9 MB) plus **114 stdlib Rust modules** and **86 `.tl` modules**.
- **A better audit than the one written today:** `docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md` — same subject, with file-and-line citations and an explicit REAL / FEATURE-GATED / STUB / MOCK-ONLY verdict per component.
- **Four pre-existing extraction specs:** `docs/tallow-scraper-full-task-list.md` (18 sections), `docs/plans/2026-08-04-tallow-scraper-1000x-upgrade.md`, `docs/plans/2026-05-31-tallow-1000x-scraper-upgrade.md` (12 phases), `docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md`.
- **A completed, QA-passed phase:** `docs/mega/phase5-extraction-rows-10agent/` — Phase 5 schema-defined extraction rows, verdict "Accepted for the scoped Phase 5 completion boundary: local/mock schema-defined extraction rows only", independent QA PASS 2026-06-13T03:33:43Z, with explicit non-claims.

**Therefore:** `EXTRACTION-ENGINE-SPEC.md` is retained only as a feature index. This file holds the verdicts. Do not re-derive any of items 1–11 below without reading the four specs above first.

## 0.1 CORRECTION — the source audit is partly stale (same-day re-verification)

`docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md` was re-verified against the live working tree. **Three of its headline claims are no longer true**, so §2 blockers 1–3 below are largely already done:

| Audit claim | Fresh evidence | Verdict |
|---|---|---|
| `TALLOW_DELTA_CRAWL` "set but never read anywhere in `src/`" | 9 reader sites: `crawl_queue.rs:122,127` (`delta_crawl_enabled()`), `:358`, `:675`; `crawl_pipeline.rs:321,357,383,1161,1234`. Set at `scheduler.rs:929`. | **REFUTED** |
| `plan_incremental_crawl` / `is_unchanged_after_fetch` / `DeltaNeed` have "zero production callers" | `crawl_pipeline.rs:516` calls `is_unchanged_after_fetch`; `:465` uses `plan.unchanged_count()` / `re_crawl`; `:1263` wires `.with_delta(...)`; `:385` resolves `self.delta \|\| delta_crawl_enabled()`. | **REFUTED** |
| `llm_extract` "not registered in `mod.rs` — reachable only via a private `#[path]` submodule" | `mod.rs:49` `pub mod llm_extract;`, `:223` re-export; invoked at `smart_extract.rs:221` (`LlmExtractor::with_config`) and `:235` (`heal_schema`). | **REFUTED** |
| `CrawlResult.unchanged` has "no caller" | `crawl_pipeline.rs:484` sets `ctx.unchanged`, consumed within the pipeline at `:465`; terminal-skip still unconfirmed. | **PARTLY REFUTED** |

Also: spec §1.8 (`@legal` / `@source` annotations) **already exists** — `@legal(basis:, purpose:, personal_data:, retain_for:)` with a `legal_bases` report, plus `tallow pia` (Privacy Impact Assessment) and `tallow sast` (taint analysis) commands.

**Lesson for future audits:** the audit's §1 component verdicts held; its §3/§4 "unwired" claims did not. Wiring state must be re-checked at use time, not inherited.

### Verified remaining (fresh, this audit)

1. **4 FFI symbols missing** — `tallow_crawler_from_sitemap`, `tallow_crawler_from_links`, `tallow_page_cache_create`, `tallow_structured_data_extract`: **0 hits each** in `src/`. The `.tl` natives at `stdlib/browser.tl:305-312, 325-327, 354-356` have no Rust binding.
2. **Content-cache middleware off by default** — `crawl_pipeline.rs:28` ("when disabled (the default)").
3. **Blocking rate limiter in the fetch path** — `crawl_pipeline.rs:295` `std::thread::sleep(wait)`.
4. **No extraction CLI surface** — fresh `tallow --help`: no `extract`, `plan`, `schema`, or `scrape` command. Present instead: `compliance`, `audit`, `pia`, `sast`, `sbom`, `sign`/`verify`, `browser`, `canary`, `fingerprint-audit`, `veil`, `never-check`, `fixity-sweep`, `phone`, `rmdb`, `pin`, `verify-ledger`.
5. **Audit-sourced, not re-verified:** the four feature flags (`parquet-storage`, `s3-storage`, `redis-backend`, `real-ml`) and the Phase 5 remaining list.

## 1. Verdict table by domain

Verdicts below cite the prior audit where it already ruled; `[A]` = `docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md`.

| Domain | Verdict | Evidence |
|---|---|---|
| 1. Language & type system | **MOSTLY MISSING** — the only genuinely new domain | No `Sourced<T>`, capability-typed egress, effect annotations, or compile-time selector/schema validation in the compiler. Partial runtime analogues do exist (below). |
| 2. Fetch / HTTP | **MOSTLY REAL** | Conditional GET REAL-but-opt-in `[A] crawl_pipeline.rs:252-314` · content-addressed cache REAL `[A] crawl_queue.rs:227-296` · robots REAL `browser/robots.rs` · sitemap REAL `browser/sitemap.rs` · retry REAL `browser/retry.rs`, `retry_intelligence.rs` (71K) · `http.batch` REAL `src/codegen.rs` · rate limit REAL but **blocking `thread::sleep`** `[A] crawl_pipeline.rs:229-231` |
| 3. Parsing & extraction | **MOSTLY REAL** | JSON-LD/microdata/OpenGraph REAL `[A] structured_data.rs:49-432` · 4-tier cascade w/ per-field confidence REAL `[A] smart_extract.rs:167-384` · main-content REAL `[A] ai_extract.rs:57-175` · quarantine REAL (Phase 5) · drift/self-heal REAL `schema_drift.rs`, `self_heal.rs` (28K) · PDF/OCR REAL `ocr.rs`, `pdf.rs` · entity REAL `entity.rs` (61K) · **LLM extraction REAL but DORMANT** `[A] llm_extract.rs:186-482`, absent from `mod.rs`, gated off |
| 4. Dynamic content / browser | **REAL** | Fallback policy `fallback.rs` · waits `page.rs` · manual gate `escalation.rs` + `examples/browser_fallback_manual_gate/` · zones `zone.rs` (31K) · pool `pool.rs` (92K) · Firefox `juggler.rs` · vault auth `browser/auth.rs`, `auth_strategy.rs` · capture `visual.rs`, `recording.rs` |
| 5. Scheduling / jobs / distribution | **MOSTLY REAL, one blocker** | SchedulerDaemon REAL w/ cron + overlap prevention `[A] scheduler.rs:605-765` · JobQueue REAL + SQLite backend REAL + Redis FEATURE-GATED `[A] job_queue.rs:226-1140` · DLQ REAL `dlq.rs` · budget/halt/fail-closed REAL `crates/tallow-jobs/budget.rs` · **delta planning REAL but UNWIRED** `[A] scheduler.rs:301-441` · distributed/ = early (5.7–11.1K per file) |
| 6. Storage / provenance | **PARTIAL** | Provenance REAL `browser/provenance.rs`, `stdlib/provenance.tl` · row schema + validator REAL (Phase 5) · idempotent upsert REAL `[A] storage.rs:61-302` · Parquet/S3 FEATURE-GATED `[A] storage.rs:12-321` · dataset diff / replay / lineage-query: **not found** |
| 7. Compliance / policy / safety | **REAL** | `browser/compliance.rs`, `browser/robots.rs`, `browser/privacy.rs`, `browser/provenance.rs` · plan `compliance` block + `schemas/compliance-gate-report.schema.json` · `stdlib/sourcegrade.{tl,rs}` (source grading) · `src/compliance/{clocks,incident,znism}.rs` · egress contract REAL `runtime/egress_http.rs` · approval gate = plan field only |
| 8. Performance | **NOT APPLIED** | No mimalloc/jemalloc, no `lol_html`, no `simd-json`, no bloom dedupe, no DNS cache. `http_parser.rs` claims ~100x vs browser `[A] html_parser.rs:5`. `benches/` = `reliability_bench.rs` + `run_benchmarks.sh` only |
| 9. Observability / QA | **MOSTLY REAL** | `otel.{tl,rs}`, `browser/observability.rs` (19K), `browser/trace.rs` (28K) · 192 test files · fixtures `examples/fixtures/mock_server.py`, `tools/fixtures` · `fuzz/` 5 files · gaps: drift/quarantine reporting, chaos tests |
| 10. CLI / DX | **PARTIAL — unverified** | 81 CLI commands documented (`docs/TALLOW-CAPABILITIES.md` §2). `tallow extract` / `tallow plan *` / `tallow schema *` presence not verified |
| 11. Source adapters | **REAL** | `stdlib/{fred,edgar,filings,geocode,yahoo,spotify,ocr,pdf,csv}.{tl,rs}`, `graphql.{tl,rs}`, `examples/request_plan_post_graphql/` |

## 2. The actually-remaining work

Everything here is either (a) named as a blocker by the prior audit with primitives already built, or (b) a flag flip, or (c) the one genuinely new domain.

### Blockers (glue, not new logic)

1. **Wire schema-first extraction.** Register `llm_extract` in `src/browser/mod.rs`; make the schema-first path default-on so one schema generation per domain+page-type is followed by CSS-speed extraction. `[A] §2 Gap`, `llm_extract.rs:288-418`.
2. **Wire delta / no-op crawl end-to-end.** Three disconnected seams confirmed: `TALLOW_DELTA_CRAWL` is **set** by the scheduler (`scheduler.rs:845-847`) but **never read anywhere in `src/`**; `plan_incremental_crawl` / `is_unchanged_after_fetch` / `DeltaNeed` have **zero production callers**; `CrawlResult.unchanged` is set but **no consumer skips re-extraction**. `[A] §3`.
3. **Parallelize the fetch loop.** `CrawlPipeline::fetch` is sequential and `SchedulerDaemon` caps at `max_concurrent=4` subprocesses (`scheduler.rs:618`); the distributed `JobQueue` backends already exist with cross-worker dedup but are unsurfaced. Also replace the blocking `thread::sleep` rate limiter. `[A] §4 items 3, 6`.

### Flag activations

4. `parquet-storage`, `s3-storage`, `redis-backend`, `real-ml` — all documented as real code, off by default (`[A] §1`). `ml::*` is currently MOCK-ONLY.
5. Enable `HttpCacheMiddleware` by default (`with_content_cache`; doc `crawl_pipeline.rs:28-29`).

### Real impl gaps (no FFI symbol behind declared natives)

6. `crawler_from_sitemap`, `crawler_from_links`, `page_cache_create`, `structured_data_extract` (.tl) are declared `// native` with **no Rust FFI symbol** `[A] §1`. The Rust-side modules exist — the bindings do not.

### Phase 5 declared-remaining

7. Generic schema-driven extraction from arbitrary `tallow.extraction_schema.v1` (currently a hardcoded product-listing path).
8. Parser registry / request-plan integration.
9. Selector-chain / drift primitive wiring beyond the mock path.

### The one genuinely new domain

10. **Language-level extraction types** (`EXTRACTION-ENGINE-SPEC.md` §1): `Sourced<T>` field-level provenance as a type, capability-typed egress, `@egress`/`@reads`/`@writes` effect annotations, compile-time selector and schema validation, tristate `Field<T>` promotion from the existing NULL-vs-`""` runtime behaviour (`runtime/html_ffi.rs`). Nothing in the folder implements these at the compiler level. Cost driver: each touches both `interp.rs` (2.2 MB) and `codegen.rs` (1.25 MB), which must stay byte-identical.

## 3. Out of scope — not to be extended

Present in `src/browser/` but **not** part of this work, per the standing refusal: `stealth.rs`, `stealth_v2.rs`, `stealth_v3.rs`, `advanced_stealth.rs`, `network_stealth.rs`, `tor_stealth.rs`, `fingerprint_coherence.rs`, `fingerprint_validator.rs`, `runtime_fingerprint_audit.rs`, `http2_fingerprint.rs`, `dpi_bypass.rs`, `traffic_morph.rs`, `cookie_farm.rs`, `behavior.rs`, `cadence.rs`, `wordfence_bypass.rs`, `proxy_intelligence.rs`, `residential.rs`, `free_proxies.rs`, `ipv6_pool.rs`, `antibot.rs`, `vendor_detect.rs`, `captcha.rs`, `slider_captcha.rs`, `substitution.rs`. Existence noted for inventory completeness only. The compliant path for anything that requires a human remains the manual gate (`escalation.rs`, `examples/browser_fallback_manual_gate/`).

## 4. Folder inventory (the "entire Nixe/Tallow folder")

**Total: 41 GB.** Largest trees:

- `target/` 19 G — build artifacts (reclaim candidate)
- `artifacts/` 7.5 G — **328 run/receipt dirs**, newest: `egress-diversity`, `gama-api-extract-2026-10-12`, `client-a-deep-2026-10-11`, `credential-rotation-2026-10-10`
- `Tallow/` 5.0 G — **a separate git checkout on `master`**, 60,431 files (`target/` 3 G, `website/` 484 M, `apps/` 321 M, `deploy/`, `audit/`, `crates/`, `docs/`). Duplicate working tree, not the active one.
- `hermes-agent/` 2.4 G · `vendor/` 869 M · `nixreader/` 630 M · `tallow-search/` 402 M · `apps/` 354 M (`tallow-copy`, `tallowsync`) · `luma/` 261 M · `omnix/` 155 M · `firecrawl-self-hosted/` 137 M · `AamiFinancial/` 105 M · `docs/` 103 M (`reports/` 69 M, `research/` 8.8 M, `mega/` 4.7 M, 418 md files)

Code surface:

- `src/` 22 M / **513 `.rs` files** — `interp.rs` 2.2 M, `codegen.rs` 1.25 M, `main.rs` 823 K, `parser.rs` 201 K, `typeck.rs` 165 K, `src/browser/` 136 files, `src/stdlib/` 114 files
- `crates/` **13 crates** — `tallow-crypto` 9.0 M, `tallow-daemon` 1.1 M, `tallow-net` 1.3 M, `tallow-protocol` 1.5 M, `tallow-reader` 1.5 M, `tallow-svid` 452 K, `tallow-jobs` 132 K, `tallow-admission`, `tallow-advisory`, `tallow-copy-engine`, `tallow-locator`, `tallow-registry`
- `stdlib/` **86 `.tl`** · `examples/` 129 files · `tests/` 192 files · `scripts/` 293 files · `schemas/tallow/` 14 contracts · `configs/tallow/` 5 · `fuzz/` 5 · `benches/` 8
- Adjacent trees: `RegionalDevelopmentMCP/` (77 M, `core/` incl. the **empty** `source_policy/`), `Texasmcp/` 78 M, `AamiFinancial/`, `Nabeel/Commodity`, `kroger_*` (~20 M of seeds/JSON), `data/` 52 M, `research/` (incl. `mega-undetected-2026-09-15/` — not reused), `luma/`, `omnix/`, `self-host/`, `supply-chain/`, `heretic/`, `intel_state/`, `dist/`, `logs/`

## 5. Stub census (fresh, this audit)

`todo!()` — **0 files**. `unimplemented!()` — **0 files**. `NotImplemented` — **0**. Zero `src/browser/*.rs` file is under 25 non-comment lines. `stub` appears in 15 files, `mock` in 13. **The 136-file browser tree is genuinely implemented; there is no lazy-stub problem.** The failures are wiring, feature flags, and missing FFI symbols — not missing logic.
