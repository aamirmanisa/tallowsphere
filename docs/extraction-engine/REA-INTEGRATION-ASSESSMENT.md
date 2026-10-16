# REA → TALLOW — Integration Assessment & Implementation Plan

**Date:** 2026-10-12
**Question asked:** extract REA's features, integrate natively into Tallow, hit 1000x across all specifications.
**Answer, in one line:** REA's feature set does not overlap Tallow's except in CDP browser observation, where Tallow is already deeper — so there is nothing to integrate, and the 1000x target as written is not a measurable claim.

Source used for REA: `github.com/morluto/rea` README (MIT), `rea.tools`. Tallow facts are cited to file path.

---

## 1. REA's actual capability surface

REA exposes **17 target types** plus a workflow/evidence layer. Verified from the README capability matrix:

| # | REA target | What it returns | External engine it wraps |
|---|---|---|---|
| 1 | Native binaries | pseudocode, assembly, strings, symbols, calls, refs | Hopper / Ghidra / IDA |
| 2 | Offline ELF layout | sections, segments, symbols, relocations, mitigation candidates | pwntools |
| 3 | Go binaries | compiler version, modules, replacements, build settings | built-in (no Go needed) |
| 4 | WASM artifact | validation, sections, import/export WAT, decoded WAT | WABT |
| 5 | EVM bytecode | dispatch selectors, byte offsets, inferred args, mutability | local carrier |
| 6 | Recorded Linux crashes | per-thread registers/signals, mapping candidates | pwntools, GDB/pwndbg |
| 7 | JavaScript / Electron | modules, imports, source maps, routes, IPC, native add-ons | none (static) |
| 8 | Websites | page structure, scripts, network observations, screenshots | Chrome-family |
| 9 | Saved network captures | requests/responses, payloads, source locations | HAR, mitmdump |
| 10 | .NET assemblies | metadata, CIL instructions, native deps, build comparison | none (static) |
| 11 | Android APKs | manifest, classes, decompiled methods, refs | JADX + JDK |
| 12 | Android devices | devices, packages, processes, logs, dumps, transfers | adb |
| 13 | JEB projects | unit pseudo-code, artifact digests | JEB (commercial) |
| 14 | Android resources | decoded manifest, string tables, locales | Apktool |
| 15 | Firmware | regions, extraction, handoff to native analysis | Binwalk / Unblob |
| 16 | Packages/resources | file inventories, digests, plists, Apple bundle anatomy | none |
| 17 | Process behavior | terminal output, interactions, exit, FS observations, run diffs | native PTY |

**Cross-cutting layer:** provider-neutral graph, evidence records carrying explicit *limitations*, snapshots, version diffing, MCP + CLI dual surface, three-step workflow (decompile → understand → recreate).

## 2. Feature extraction — REA vs Tallow, feature by feature

| REA capability | Tallow status | Evidence |
|---|---|---|
| 1. Native binary decompilation | **ABSENT** | No decompiler integration. `ghidra` 0 hits; `hopper` hits are the Grasshopper cipher (`stdlib/crypto.rs:7758`) and the `AmazonShopper` stealth profile. |
| 2. ELF layout / relocations | **ABSENT** | No ELF parser. |
| 3. Go binary inspection | **ABSENT** | — |
| 4. WASM inspection | **ABSENT** | — |
| 5. EVM bytecode | **ABSENT** | `evm` 0 files. |
| 6. Crash/register analysis | **ABSENT** | `pdb` 1 file (incidental). |
| 7. JS / Electron static analysis | **ABSENT** (adjacent) | Closest: `stdlib/sitescan.rs:902-936` *detects* `sourcemap` URLs on pages. No module/import/IPC graph, no source-map reconstruction, no V8 Inspector use (`inspector` 0 files). |
| 8. Website structure / scripts / network / screenshots | **PRESENT — deeper than REA** | `browser/cdp.rs` 62K (CDP JSON-RPC, session multiplexing), `browser/page.rs` 142K, `browser/network.rs` 94K, `browser/visual.rs` 28K (screenshots, pixel diff, baselines), `browser/trace.rs` 28K (ZIP trace + HTML viewer + network events), `browser/recording.rs` 28K (4K screencast), `browser/markdown.rs` 26K, `browser/snapshot_sampler.rs` 12K. |
| 9. Saved network captures (HAR) | **PARTIAL** | `artifact_policy.har` exists in the request-plan format and `network.rs` captures traffic; no HAR *import* or mitmproxy capture path. |
| 10. .NET / CIL analysis | **ABSENT** | `cil` 15 files, all incidental; no PE/CIL metadata reader. |
| 11. Android APK analysis | **ABSENT** | `apk` hits are MIME magic bytes (`stdlib/mime.rs`, `stdlib/transfer.rs`). No JADX path. |
| 12. Android device (adb) | **ABSENT** | `adb` 43 files, all substring hits. |
| 13. JEB projects | **ABSENT** | — |
| 14. Android resources | **ABSENT** | — |
| 15. Firmware | **ABSENT** | `binwalk` 0, `jadx` 0. |
| 16. Package/archive inventory | **PARTIAL** | `stdlib/transfer.rs:2115-2169` detects `macho`/`macho64`/`macho_fat` magic for MIME classification — file *typing*, not inventory/digest/bundle anatomy. |
| 17. Process behaviour capture | **PARTIAL** | `browser/process.rs` (89K) manages browser processes; `crates/tallow-jobs/exec.rs` runs scripts via `Command`/`Stdio` — **no PTY**, so interactive capture is absent. |
| Evidence records with limitations | **PRESENT, different domain** | `browser/provenance.rs` (price provenance: source, timestamp, extraction method, validator chain, confidence breakdown); `stdlib/provenance.{tl,rs}`; Phase 5 per-field row provenance. |
| Version diffing | **PARTIAL** | `browser/ab_detector.rs` (structural variants), `browser/schema_drift.rs` (selector drift). No general artifact-vs-artifact diff. |
| Provider-neutral graph | **ABSENT** | — |
| Three-step workflow + MCP surface | **ABSENT as MCP** | Tallow is a CLI/language; the MCP surface in this workspace is a separate project (`RegionalDevelopmentMCP`). |

**Net:** of 17 REA target types, **12 are absent** and 5 are absent-or-partial. Of those 12, **11 are static analysis of compiled artifacts**. Tallow has no binary analysis at all.

## 3. Why "1000x across all specifications" cannot be asserted

Three independent reasons. Each is a reason to refuse the claim, not to work around it.

1. **Baseline-zero.** A 1000x improvement is a ratio against a baseline. For the 12 absent capabilities the Tallow baseline is *zero* — there is no ratio, there is `0 → 1`. A multiplier cannot be computed for a feature that does not exist.
2. **Physically bounded metrics.** A single multiplier cannot apply to latency, throughput, memory, and cost simultaneously because they trade off. Concretely: latency is bounded below by network RTT and TLS handshake cost. A 200 ms round trip cannot become 0.2 ms by writing better code. The same applies to target-server response time and disk throughput. Any "1000x across all metrics" claim is falsified by physics, not by effort.
3. **"Hardware requirements" is not a performance metric.** Specs, limits, and capacity are not points on a speed axis. A change cannot be "1000x" on a requirement; it can only reduce a requirement by a factor. The claim as written has no unit.

Also note the standing rule already on this box: **probe-verified claims only**. Asserting an unmeasured 1000x would violate it.

**What is legitimately measurable, and where large multipliers are real:**

| Lever | Why the magnitude is real | Honest ceiling |
|---|---|---|
| Skip unchanged pages (delta crawl) | Re-crawl of an unchanged corpus collapses from `N × (fetch + parse)` to `N × conditional GET`. Amortized cost per page approaches the 304 cost only. | Bounded by the conditional-GET round trip. >100x on unchanged corpora is plausible; 1000x is plausible only for very heavy pages. |
| Schema-first extraction | One schema generation per domain+page-type, then CSS-speed extraction for the other N pages. Removes per-page parsing cost. | Bounded by extraction, not fetching. Large for LLM-per-page baselines; 0x for the already-regex path. |
| HTTP-first before browser | Browser only for JS shells. | ~100x class, already claimed in-tree (`browser/html_parser.rs:5`). |

**Where a 1000x is also blocked by Tallow's own policy — a real tension worth naming:** the egress contract forces Tor by default, enforces a per-host minimum delay (`TALLOW_FETCH_DELAY_MS`, default 250 ms; `runtime/egress_http.rs`), and the crawl pipeline rate-limits per host. Those caps bound fetch throughput *by design*. You cannot honour a per-host politeness limit and get 1000x download throughput at the same time. The magnitude has to come from **not re-fetching** and **not re-parsing** — not from fetching harder.

## 4. Necessity call on native REA integration

**Recommendation: do not integrate REA.**

- REA is an **orchestration layer over external engines** — Hopper, Ghidra, IDA, JADX, pwntools, WABT, Binwalk, apktool, adb. Its own README describes it as an MCP layer that calls those tools. "Native integration avoiding external dependencies" therefore means reimplementing a decompiler, a disassembler, a JADX-equivalent, and a firmware unblobber. That is a research programme, not an engineering sprint, and it discards the only part of REA that is hard to build.
- Two of those engines (**IDA/Hex-Rays, JEB**) are commercial and licence-gated. REA explicitly grants no licence. They cannot be "natively integrated" at any cost.
- **Domain overlap is near zero.** Tallow is a language toolchain + secure transfer + extraction stack. REA analyses compiled artifacts. Nothing in Tallow's product path consumes a decompiler.
- If a specific need arises (e.g. understanding an Electron app you own), REA is MIT and runs locally: `npx rea-agents setup`. That is the entire integration cost — no wrapper, no fork, no data leaves the box.

**The one thing genuinely worth adopting from REA is a convention, not code:** its discipline of attaching **explicit limitations** to every evidence record, and its three-step `investigate → understand → recreate` framing. Tallow's `browser/provenance.rs` already carries confidence breakdowns; extending it to carry stated *unknowns* is a small, worthwhile change.

## 5. Implementation plan — the work that actually yields a large multiplier

All three items are wiring over code that already exists. Evidence from `docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md`.

### W1 — Activate schema-first extraction

- **Change:** register `llm_extract` in `src/browser/mod.rs`; today it is reachable only as a private `#[path]` submodule of `smart_extract.rs:22-28`. Flip `enable_llm_fallback` (`:127`, currently `false`) or expose a global config.
- **Then:** route bulk pages through `LlmExtractor::auto_extract` (`llm_extract.rs:288-418`) so schema generation happens once per domain+page-type and later pages run at CSS speed with zero model cost (`:224-225`, `:275-277`).
- **Acceptance:** per-page extraction cost measured on a fixture corpus, before vs after, reported as ms/page and model calls/page. Model calls/page must be 0 for pages after the first of each domain+page-type.
- **Tests:** existing Phase 5 golden rows must still pass unchanged; add a schema-gen-once assertion and a self-heal assertion (`heal_schema` `:459-482`).

### W2 — Wire delta / no-op crawl end to end

Three confirmed disconnections (`[A] §3`):
1. `TALLOW_DELTA_CRAWL` is **set** by the scheduler (`scheduler.rs:845-847`) and **read nowhere in `src/`** — no interpreter consumer.
2. `plan_incremental_crawl` (`scheduler.rs:397-408`), `DeltaNeed` (`:301-340`), `is_unchanged_after_fetch` (`:429-441`) have **zero production callers** — tests only (`:1697`, `:1725`).
3. `CrawlResult.unchanged` is **set** (`adaptive_crawler.rs:153,185`; `crawl_pipeline.rs:310-311`) but **no caller skips re-extraction** on it.

- **Change:** (a) make the interpreter honour `TALLOW_DELTA_CRAWL`; (b) call `plan_incremental_crawl` against the `CrawlQueue` HTTP cache in the crawl loop; (c) consume `unchanged`/304 to skip fetch *and* extraction. Turn `HttpCacheMiddleware` on by default (`crawl_pipeline.rs:28-29`).
- **Acceptance:** re-crawl of an unchanged N-page fixture — zero extraction invocations, N conditional GETs, measured wall-clock improvement. Every row must still be present in output (skip ≠ drop).
- **Tests:** chaos — kill mid-run, truncated body, 304 storm; assert no duplicate rows and no lost receipts.

### W3 — Parallelize the fetch loop, within the politeness contract

- **Change:** `CrawlPipeline::fetch` is sequential; replace the blocking `thread::sleep` rate limiter (`crawl_pipeline.rs:229-231`) with the existing async per-host limiter; raise `SchedulerDaemon::max_concurrent` (`scheduler.rs:618`, currently 4 subprocesses) and surface the distributed `JobQueue` backends (SQLite real, Redis feature-gated, cross-worker dedup `job_queue.rs:272-290`) instead of spawning a subprocess per URL.
- **Acceptance:** pages/sec measured against the same local fixture, with per-host request rate reported alongside so the speedup cannot be achieved by violating the limit.
- **Honest ceiling:** this item is bounded by policy, not CPU. Report it as a throughput multiplier *at constant per-host request rate*.

### R1 — Close the four declared-but-unbound natives

`crawler_from_sitemap`, `crawler_from_links` (`stdlib/browser.tl:305-312`), `page_cache_create` (`:325-327`), `structured_data_extract` (`:354-356`) are declared `// native` with **no Rust FFI symbol** (`[A] §1`). The Rust-side modules exist (`browser/sitemap.rs`, `browser/structured_data.rs`) — only the bindings are missing.

### R2 — Phase 5 declared-remaining

Generic extraction from arbitrary `tallow.extraction_schema.v1` (currently a hardcoded product-listing path); parser-registry / request-plan integration; selector-chain and drift wiring beyond the mock path. Source: `docs/mega/phase5-extraction-rows-10agent/agent-01-current-state.md`.

### R3 — Feature flags

`parquet-storage`, `s3-storage`, `redis-backend`, `real-ml` are documented as real code, off by default; `ml::*` is currently MOCK-ONLY (`[A] §1`).

### Sequencing

W2 first (largest honest multiplier, all primitives present), then W1, then R1/R2 (contract completeness), then W3 (bounded by policy), then R3.

## 6. Verification methodology (replaces "confirm 1000x")

For each item, report three numbers — never one:

1. **Baseline** measured on the same fixture corpus on the same machine, with the command recorded.
2. **After**, same corpus, same command.
3. **Constraint held** — the policy metric that must not regress: per-host request rate, model calls per page, or rows emitted. A speedup that moves the constraint is a policy violation, not an optimisation.

A claim of "1000x" is accepted only for a named metric on a named corpus with all three numbers, and only where §3 does not rule the magnitude out physically.
