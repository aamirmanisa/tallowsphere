# Tallow 1000x-Class Scraper Upgrade Plan

Date: 2026-05-31
Scope: Root Tallow language, scraper, browser automation, runtime, stdlib, and related data systems.

## Purpose

This plan turns the current Tallow language and scraper/browser stack from a powerful experimental platform into a production-grade scraping, browser, and data automation system. The work is organized for up to 10 parallel agents at any given time. Each phase has research, planning, execution, and verification tasks, plus explicit artifacts and gates.

The goal is not to claim that every page can be scraped 1000x faster. Full browser rendering, network latency, target rate limits, and anti-abuse systems put hard limits on many workloads. A credible 1000x-class upgrade comes from avoiding unnecessary work: HTTP-first execution instead of browser rendering, schema-first extraction instead of repeated AI/manual parsing, incremental recrawls instead of full recrawls, adaptive queueing instead of fixed waves, manifest/cache-assisted skips, and replayable failures instead of manual incident work.

## Current Audit Summary

### Root Tallow Language And Runtime

Primary areas:

- `src/lexer.rs`, `src/parser.rs`, `src/ast.rs`, `src/typeck.rs`: language front end.
- `src/interp.rs`: interpreter and stdlib dispatch runtime.
- `src/codegen.rs`: native code generation path.
- `src/main.rs`: CLI entry point for build, run, check, audit, copy, browser, transfer, scheduler, and related commands.
- `src/*_pass.rs`: legal, privacy, safety, agent, SAST, CRA, NIS2, AI Act, and other policy passes.
- `src/runtime/`: runtime FFI and low-level runtime shims.
- `src/stdlib/` and `stdlib/`: Rust-backed and Tallow-facing standard library surfaces.
- `crates/`: shared Rust crates including `tallow-copy-engine`, `tallow-net`, `tallow-crypto`, `tallow-daemon`, and protocol crates.

Strengths:

- The compiler/runtime has broad language, stdlib, compliance, browser, transfer, crypto, package, and audit ambitions already present in code.
- Compliance and privacy are not bolted on as comments; there are compiler passes dedicated to them.
- The stdlib has real system capabilities: crypto, transfer, browser, HTTP, HTML, JSON, filesystem, compression, OSINT, forensics, time, logging, process, regex, and related modules.

Risks:

- Very large modules such as `src/interp.rs`, `src/codegen.rs`, `src/main.rs`, `src/stdlib/crypto.rs`, `src/stdlib/docs.rs`, and `src/stdlib/transfer.rs` create review and regression risk.
- Some claims in capability docs are aspirational or partially implemented and need feature-by-feature verification.
- Local runtime/toolchain reliability is currently a blocker: `cargo`, `rustc`, and `git` were not on PATH in the inspected shell, PowerShell scripts require execution-policy bypass, and existing Tallow binaries failed with Windows exit code `0xC0000135`, which indicates a missing DLL/runtime dependency.

### Tallow Scraper And Browser System

Primary areas:

- `src/browser/`: CDP browser control, page/element/frame APIs, browser process lifecycle, pool, sessions, stealth, devices, network interception, retry, robots, extraction, visual testing, tracing, and related systems.
- `src/browser/adaptive_crawler.rs`, `src/browser/turbo_crawler.rs`: HTTP-first and adaptive crawler concepts.
- `src/browser/smart_extract.rs`, `src/browser/structured_data.rs`, `src/browser/llm_extract.rs`, `src/browser/selector_chain.rs`, `src/browser/self_heal.rs`, `src/browser/schema_drift.rs`: extraction and repair surfaces.
- `scripts/launch_tallow_parallel.ps1`, `scripts/prepare_tallow_run_config.ps1`, `scripts/queue_dispatcher.ps1`, `scripts/replay_failed_requests.ps1`, and related scripts: existing operations layer.
- `docs/tallow-scraper-full-task-list.md`: current scraper work queue.
- `docs/MEGA_SCRAPER_ENGINE_RESEARCH.md`: broad competitive and architectural research.
- `docs/browser-specs.md`: browser system specification.

Strengths:

- The browser system has real CDP architecture, page/element APIs, device emulation, stealth modules, browser pool concepts, robots/rate-limit logic, trace/visual tooling, and extraction modules.
- The scraper roadmap already names many production requirements: target manifests, retry budgets, output schemas, artifact bundles, replay, dashboards, benchmarks, and compliance reports.
- The system has a plausible moat if it combines Tallow language safety, Rust performance, browser control, schema-first extraction, and legal/compliance enforcement.

Risks:

- Several production-critical items remain open: runtime stability, target manifest depth, queue-based dispatcher, adaptive concurrency, HTTP controls, browser fallback, anti-bot classification, schema-first extraction, duplicate/anomaly checks, Parquet export, structured logs, compliance enforcement, fault injection, golden files, and CI matrix.
- Fixed parallel launch presets are useful for demos but are not a durable production scheduler.
- Browser fallback must become rare and reason-coded, otherwise browser memory/CPU cost will cap throughput.

### Related Data Systems

Relevant neighbors:

- `tallow/`: grocery data/search platform with Rust services, import pipelines, configs, schema contracts, and Astro/Svelte UI.
- `tallow-search/`: Rust API plus Astro/Svelte search frontend.
- `firecrawl-self-hosted/`: vendored Firecrawl monorepo used as a comparison point and possible integration target.
- `docs/operations/`, `docs/qa/`, `docs/architecture/`: run metrics, output convention, replay, schema validation, golden files, alerting, dashboards, and operational contracts.

Strategic relationship:

- Tallow should be the controlled language/runtime and scraper platform.
- Tallow is a product/data proving ground.
- Tallow Search is a search/API consumer surface.
- Firecrawl self-hosted is a baseline open-source scraper API comparison, not the core platform.

## Definition Of 1000x-Class

The program must report gains by workload class. A single blended speedup number is not acceptable.

Credible 1000x-class improvements:

- Warm no-op recrawls where unchanged URLs are skipped from manifests or content fingerprints.
- Incremental crawls where only changed documents or changed records are fetched and extracted.
- HTTP-first extraction where prior browser-only workflows were used.
- Schema-first CSS/JSON extraction where prior per-page AI/manual extraction was used.
- Replayable incidents where operator time drops from hours to seconds.
- Massive duplicate suppression before network fetches.
- Browser session/cookie reuse where previous runs launched a new browser for every page.

Non-goals:

- No claim that raw full browser scraping is 1000x faster.
- No claim that hardware-bound network or disk I/O can be made 1000x faster on the same hardware.
- No bypass of legal, robots, rate-limit, or credential safety requirements to inflate benchmarks.

## Parallel Agent Operating Model

Each phase supports 10 concurrent agents. Every agent receives one narrow task with four required outputs:

- Research notes: files inspected, assumptions, open questions.
- Plan: exact implementation or documentation path.
- Execution: files changed or commands run.
- Verification: test, benchmark, schema check, generated artifact, or explicit blocker.

Coordination rules:

- One phase lead owns integration and prevents overlap.
- Agents work in non-overlapping file areas whenever possible.
- Shared contracts are edited first, implementation second.
- No agent broad-scans noisy roots such as `target/`, `node_modules/`, `dist/`, `tmp/`, `artifacts/`, or `.playwright-mcp/` unless the task is specifically about them.
- Any source changes under `src/`, `crates/`, `stdlib/`, `tests/`, or `examples/` follow the root Tallow review checklist.
- Any Tallow changes preserve product provenance and data quality contracts.
- Any Tallow Search changes preserve public route and payload contracts.

## Phase 0: Baseline Inventory And Reality Check

Goal: Establish the authoritative map of what exists, what works, what is partial, and what is blocked.

Agent tasks:

1. Inventory compiler/runtime modules under `src/`, `crates/`, `stdlib/`, and `tests/`.
2. Inventory scraper/browser modules under `src/browser/`.
3. Inventory stdlib surfaces for HTTP, HTML, JSON, FS, browser, transfer, crypto, and process.
4. Inventory existing `.tl` scraper scripts, PowerShell launchers, target manifests, and config schemas.
5. Inventory tests and benchmarks relevant to parser, runtime, browser, scraper, output, and copy/transfer.
6. Inventory docs and roadmap files: `docs/tallow-scraper-full-task-list.md`, `docs/browser-specs.md`, `docs/MEGA_SCRAPER_ENGINE_RESEARCH.md`, `docs/operations/`, and `docs/qa/`.
7. Inventory Firecrawl self-hosted API, Playwright service, SDKs, and self-host limitations.
8. Inventory Tallow and Tallow Search integration points.
9. Inventory current local build/runtime/toolchain blockers.
10. Produce one consolidated capability matrix: implemented, partial, stubbed, missing, and unknown.

Expected artifacts:

- `docs/mega/tallow-1000x-capability-matrix.md`
- `docs/mega/tallow-1000x-blocker-register.md`
- `docs/mega/tallow-1000x-system-map.md`

Verification:

- Every matrix row links to a file, doc, test, script, or explicit unknown.
- Current runnable commands are listed separately from blocked commands.
- No generated/noise folders are included as product source.

## Phase 1: Runtime And Toolchain Stabilization

Goal: Make Tallow start, build, test, and self-diagnose reliably before performance work begins.

Status: Phase 1 bootstrap implementation is in progress. The workspace now contains the expected diagnostic artifacts: upgraded `tallow_doctor`, a Phase 1 smoke ladder, normalized PowerShell docs, and runtime DLL/PATH/browser checks. Do not treat runtime/toolchain blockers as closed until the doctor and smoke ladder pass from a fresh shell.

Agent tasks:

1. Diagnose Windows `0xC0000135` launch failure for `target/release/tallow.exe`, `target/debug/tallow.exe`, and `.tallow-bin/tallow.exe`.
2. Restore or document PATH expectations for `git`, `cargo`, `rustc`, Node, and package managers.
3. Upgrade `scripts/tallow_doctor.ps1` to detect missing DLL/runtime dependencies, PATH gaps, PowerShell execution policy, writable artifact paths, and binary hash/version.
4. Compare `.tallow-bin/tallow.exe` and `target/release/tallow.exe` capability surfaces and document any mismatch.
5. Add a startup self-check command or doctor subcheck for required stdlib/browser/scraper functions.
6. Document Windows, Linux, and macOS bootstrap steps.
7. Add binary version, binary SHA-256, config hash, script hash, launch timestamp, and working directory to scraper run metadata.
8. Normalize safe PowerShell invocation with `-ExecutionPolicy Bypass` for repo scripts that require it.
9. Add smoke tests or scripts for `tallow --version`, `tallow version`, `tallow check examples/hello_simple.tl`, `tallow run examples/hello_simple.tl`, and `tallow browser path`.
10. Produce a release/bootstrap checklist.

Expected artifacts:

- Updated `scripts/tallow_doctor.ps1`
- Updated `docs/operations/tallow-doctor.md`
- `docs/operations/tallow-runtime-bootstrap.md`
- `scripts/phase1_smoke_ladder.ps1`
- `docs/operations/phase1-smoke-ladder.md`
- `tests` or script-based smoke checks for startup and basic CLI

Verification:

- `tallow --version` exits quickly and correctly.
- `tallow check examples/hello_simple.tl` runs.
- `tallow doctor` reports actionable pass/fail checks.
- The same bootstrap path works from a fresh shell.

## Phase 2: Scraper Architecture Consolidation

Goal: Replace scattered scraper scripts and one-off launch flows with a single scraper runtime model.

Agent tasks:

1. Define the canonical scraper run lifecycle from manifest to artifact bundle.
2. Design target manifest schema with domain, URL patterns, method, headers, payloads, auth mode, parser strategy, legal metadata, robots policy, and rate limits.
3. Design extraction schema contract with required fields, optional fields, selectors, JSON paths, null reasons, confidence, canonical keys, and schema version.
4. Design artifact bundle contract: manifest, raw responses, normalized rows, invalid rows, metrics, logs, replay data, screenshots, HAR files, and summary.
5. Design retry/error taxonomy for DNS, TCP, TLS, timeout, redirect, HTTP status, blocked, challenge, deceptive content, parser failure, schema failure, and write failure.
6. Design domain scheduler model with queue, concurrency, backoff, retry budget, and cooling.
7. Design browser fallback policy model with reason codes and cost controls.
8. Design legal/compliance metadata model for production scraper runs.
9. Map existing scripts into keep, migrate, replace, or retire categories.
10. Produce a migration checklist.

Expected artifacts:

- `docs/architecture/tallow-scraper-runtime.md`
- `docs/architecture/tallow-target-manifest.md`
- `docs/architecture/tallow-extraction-schema.md`
- `docs/architecture/tallow-scraper-artifact-bundle.md`
- `docs/operations/tallow-scraper-migration-checklist.md`

Verification:

- Existing scripts have an explicit migration decision.
- Every required manifest field has a validation rule.
- Output artifact contract is versioned.

## Phase 3: HTTP-First Fetch Engine

Goal: Make static pages, JSON APIs, GraphQL endpoints, feeds, and server-rendered HTML extremely fast without browser overhead.

Agent tasks:

1. Harden the basic HTTP fetch path with one typed request/response contract.
2. Add connect timeout, request timeout, read timeout, and whole-job timeout controls.
3. Add redirect policy controls and max redirect depth.
4. Add compressed response handling with decompression size limits.
5. Add request fingerprint profiles by target group.
6. Add POST and GraphQL payload templates from target manifests.
7. Add normalized classification for DNS, TCP, TLS, timeout, 4xx, 5xx, malformed response, and body-too-large errors.
8. Add response fingerprinting for blocked, soft-blocked, challenge, login-required, and deceptive pages.
9. Add connection reuse, DNS caching, and bounded response buffers.
10. Benchmark HTTP-only extraction throughput on deterministic mock targets.

Expected artifacts:

- Manifest-backed HTTP request builder.
- HTTP error classifier tests.
- GraphQL POST manifest fixture.
- HTTP benchmark smoke report.

Verification:

- HTTP fetch tests pass.
- GraphQL POST manifest tests pass.
- Error classification tests pass.
- Benchmark reports pages/sec, p50, p95, memory, retry rate, and success rate.

## Phase 4: Browser Fallback And Session Reuse

Goal: Use real browser automation only when needed and reuse expensive browser state.

Agent tasks:

1. Implement HTTP-to-browser escalation policy with explicit reason codes.
2. Add fallback reason fields to output artifacts.
3. Add browser session reuse by domain and target group.
4. Add cookie/session handoff from browser back to HTTP where safe.
5. Add screenshot and HAR capture on fallback failures.
6. Add resource blocking defaults for speed mode, with per-domain override.
7. Add DOM extraction batching to reduce CDP round trips.
8. Add browser pool lifecycle metrics: acquired, released, recycled, crashed, active, idle, and per-task duration.
9. Add mock JS-heavy targets to prove fallback behavior.
10. Benchmark HTTP-first plus fallback against browser-only runs.

Expected artifacts:

- Browser fallback policy implementation.
- Browser fallback tests.
- Browser pool metrics.
- Fallback benchmark report.

Verification:

- Browser fallback happens only on approved reason codes.
- Session reuse reduces repeated browser startup.
- HAR/screenshot artifacts exist on fallback failures.
- HTTP-first plus fallback beats browser-only on mixed targets.

## Phase 5: Schema-First Extraction And Self-Healing

Goal: Make extraction reliable, typed, cheap, and repairable.

Agent tasks:

1. Create parser strategy registry: JSON, GraphQL envelope, HTML selectors, structured data, markdown, table, and browser DOM.
2. Add schema-first extraction for each target dataset.
3. Add required/optional field validation and typed coercion.
4. Add null-reason tagging for missing, blocked, unavailable, unsupported, selector-miss, parse-failed, and filtered values.
5. Add extraction confidence scoring.
6. Add selector-chain fallback and selector health metrics.
7. Add schema drift detection.
8. Add LLM-assisted schema generation or repair that runs on setup/failure, not on every page.
9. Add deterministic golden-file tests for extraction outputs.
10. Benchmark CSS/JSON extraction against browser DOM extraction and LLM extraction.

Expected artifacts:

- Extraction strategy registry.
- Extraction schema validator.
- Golden fixtures.
- Drift report format.

Verification:

- Output rows validate against schema.
- Invalid rows are quarantined.
- Golden files are deterministic.
- LLM usage is limited to schema creation or repair paths.

## Phase 6: Adaptive Queue Dispatcher

Goal: Replace fixed parallel waves with intelligent scheduling and backpressure.

Agent tasks:

1. Implement queue-based dispatcher for large target sets.
2. Add per-domain concurrency limits.
3. Add adaptive concurrency based on latency, success rate, challenge rate, and error class.
4. Add retry budgets by domain and error class.
5. Add graceful cancellation.
6. Add partial checkpoint resume.
7. Add backpressure for artifact writing and large response bodies.
8. Add dead-letter queue for failed targets.
9. Add dispatcher integration tests.
10. Benchmark fixed parallel launch versus adaptive queue on mixed targets.

Expected artifacts:

- Dispatcher implementation or hardened dispatcher script.
- Queue state schema.
- Checkpoint format.
- Dispatcher benchmark report.

Verification:

- Dispatcher drains large target sets safely.
- One failing domain does not poison the whole run.
- Cancel/resume works.
- Adaptive mode beats fixed batching on mixed target sets.

## Phase 7: Data Quality, Storage, And Artifacts

Goal: Make every run reproducible, inspectable, and safe to trust.

Agent tasks:

1. Finalize canonical output directory convention.
2. Add run manifest with config hash, binary hash, script hash, target manifest hash, and launch metadata.
3. Add stable `full.json` schema and versioning.
4. Add NDJSON output for large runs.
5. Add deterministic CSV column ordering.
6. Add Parquet export for analytics workloads.
7. Add duplicate detection by canonical keys.
8. Add value-range, anomaly, and outlier checks.
9. Add quality score per run and per domain.
10. Add failure replay from saved request metadata.

Expected artifacts:

- Versioned artifact bundle schema.
- NDJSON/CSV/Parquet export checks.
- Quarantine file format.
- Replay workflow.

Verification:

- Every run emits manifest, metrics, logs, rows, invalid rows, and replay metadata.
- CSV/NDJSON schemas are stable.
- Bad rows are quarantined, not silently accepted.
- Replay can reproduce representative failures.

## Phase 8: Observability And Operations

Goal: Make the platform operable by humans and automation.

Agent tasks:

1. Add structured logs with correlation IDs per run, target, request, and extraction row.
2. Add run-level metrics: throughput, success rate, retry rate, p50, p95, p99, cost per 1k successful pages, and error classes.
3. Add domain-level dashboards.
4. Add alerting for success-rate drops.
5. Add block/challenge spike detection.
6. Add operator incident runbook.
7. Add retry budget reports.
8. Add queue depth and worker saturation metrics.
9. Add scrape latency and extraction latency split.
10. Build monthly benchmark report template.

Expected artifacts:

- Structured log schema.
- Metrics schema.
- Dashboard generator or docs.
- Incident runbook updates.
- Monthly benchmark report template.

Verification:

- Metrics are emitted per run and per domain.
- Alerts trigger on synthetic failure scenarios.
- Operator can identify why a run failed.
- Benchmark report can be generated repeatedly.

## Phase 9: Legal, Privacy, And Secret Safety

Goal: Turn Tallow's compliance story into production runtime enforcement.

Agent tasks:

1. Enforce `@legal` metadata for production scraper scripts.
2. Add robots policy modes: strict, advisory, and off.
3. Add per-target data retention policy.
4. Add automatic purge hooks.
5. Add credential vault integration for authenticated targets.
6. Add secret redaction in logs and artifacts.
7. Add PII detection in extracted data.
8. Add compliance report per run.
9. Add legal audit tests.
10. Update operator checklist and security review checklist.

Expected artifacts:

- Production legal metadata gate.
- Retention policy schema.
- Secret redaction tests.
- Per-run compliance report.

Verification:

- Missing legal metadata fails production runs.
- Secrets do not appear in logs or artifacts.
- Retention policy appears in run manifests.
- Compliance report is generated per run.

## Phase 10: Performance Hot Path Optimization

Goal: Optimize only after architecture and correctness are stable.

Agent tasks:

1. Profile HTTP pipeline CPU hotspots.
2. Profile parser/extraction hotspots.
3. Profile memory allocation and peak RSS per worker.
4. Add bounded buffers and buffer pools.
5. Add SIMD JSON parsing where useful.
6. Add faster HTML extraction path where selector complexity allows it.
7. Add URL/content dedup with Bloom filters or content fingerprints.
8. Add batched database writes or artifact writes.
9. Evaluate io_uring or platform-specific I/O for relevant paths.
10. Produce before/after performance report.

Expected artifacts:

- Profiling reports.
- Targeted hot-path changes.
- Memory benchmark report.
- Before/after benchmark report.

Verification:

- Performance claims are backed by benchmark data.
- Memory usage improves or remains bounded.
- Golden extraction files do not regress.
- Hot-path changes have targeted tests.

## Phase 11: Distributed And Large-Scale Execution

Goal: Scale beyond one machine without losing correctness, observability, or replayability.

Agent tasks:

1. Define distributed node protocol.
2. Add worker registration and heartbeat.
3. Add remote browser pool coordination.
4. Add distributed queue sharding.
5. Add per-node resource limits.
6. Add node failure handling.
7. Add cross-node artifact aggregation.
8. Add distributed metrics.
9. Add local multi-worker simulation tests.
10. Benchmark single-node versus multi-node runs.

Expected artifacts:

- Distributed execution architecture doc.
- Node heartbeat protocol.
- Sharding strategy.
- Multi-node benchmark report.

Verification:

- Workers can join and leave safely.
- Failed nodes do not lose completed artifacts.
- Metrics identify per-node bottlenecks.
- Distributed runs outperform single-node runs on large workloads.

## Phase 12: Competitive Benchmark And Release Gate

Goal: Prove the upgrade with repeatable numbers and block release on regressions.

Agent tasks:

1. Build benchmark corpus: easy, medium, hard, API, JS-heavy, blocked/challenge, no-op, incremental, and mixed targets.
2. Add controlled mock target suite for deterministic tests.
3. Benchmark current Tallow baseline.
4. Benchmark upgraded Tallow.
5. Benchmark Firecrawl self-hosted.
6. Benchmark Scrapy or Crawlee baseline.
7. Compare cost per 1k successful pages.
8. Compare p50, p95, and p99 latency.
9. Compare success rate and operator incident time.
10. Produce release-readiness report.

Expected artifacts:

- Benchmark corpus.
- Benchmark runner.
- Baseline reports.
- Release-readiness report.
- No-regression gates.

Verification:

- Benchmark data is repeatable.
- Claims are separated by workload class.
- Release is blocked until two consecutive benchmark cycles pass.
- `v1.0` is not tagged until runtime stability, extraction quality, compliance gates, and benchmark gates pass.

## Milestone Gates

M0: Audit complete.

- Capability matrix exists.
- Blocker register exists.
- Toolchain/runtime status is known.

M1: Runtime stable.

- Tallow launches reliably.
- Doctor reports actionable checks.
- Basic CLI smoke tests run.

M2: Unified scraper architecture.

- Manifest, extraction schema, artifact bundle, and error taxonomy exist.
- Existing scripts have migration decisions.

M3: HTTP-first scraper.

- Static/API targets run through the fast path.
- GraphQL templates are supported.
- Browser fallback is reason-coded.

M4: Production data quality.

- Schema validation, quarantine, replay, metrics, and artifacts are mandatory.
- Golden files and mock targets exist.

M5: Compliance and operations.

- Legal metadata gates production runs.
- Secrets are redacted.
- Metrics, alerts, dashboards, and incident runbooks exist.

M6: Performance proof.

- Benchmarks compare old Tallow, upgraded Tallow, Firecrawl self-hosted, and at least one open-source baseline.
- 1000x-class claims are limited to the workload classes that prove them.

## First 10-Agent Sprint

Recommended immediate sprint:

1. Agent 1: Diagnose `tallow.exe` `0xC0000135` and document missing runtime dependency.
2. Agent 2: Make `scripts/tallow_doctor.ps1` detect PATH, DLL, binary hash, and execution policy issues.
3. Agent 3: Create the capability matrix skeleton from `src/`, `src/browser/`, `src/stdlib/`, and `crates/`.
4. Agent 4: Create the target manifest schema draft.
5. Agent 5: Create the extraction schema draft.
6. Agent 6: Create the artifact bundle schema draft.
7. Agent 7: Inventory existing scraper scripts and map them to the future lifecycle.
8. Agent 8: Inventory browser fallback and extraction modules for implementation status.
9. Agent 9: Create deterministic mock target requirements for HTTP, GraphQL, JS-heavy, blocked, and malformed pages.
10. Agent 10: Draft benchmark classes and acceptance gates.

Sprint exit criteria:

- Tallow runtime blocker is understood.
- Doctor upgrade plan is ready or implemented.
- Architecture docs exist as drafts.
- The next sprint can implement against contracts instead of inventing while coding.
