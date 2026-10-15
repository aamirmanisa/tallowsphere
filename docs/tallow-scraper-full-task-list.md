# Tallow Scraper Full Task List

> **Docs truth label:** Roadmap ledger / not acceptance evidence. Checkbox state in this file is historical task bookkeeping and must not be treated as proof that runtime, browser, compliance, benchmark, or production scraper behavior is accepted. Use `.hermes/project-memory.md`, `docs/mega/tallow-1000x-blocker-register.md`, `docs/mega/tallow-1000x-capability-matrix.md`, accepted phase reports, and executed gates for current truth. Current accepted scope is Linux/CachyOS local/non-live/offline/fixture/no-secret proof through `docs-truth-continuous`; live scraping, production fallback, real credentials/vaults, destructive retention, paid/live benchmark superiority, deploy/release readiness, and Windows support remain human-gated.

Date: 2026-04-28
Owner: Tallow scraper team
Scope: Build a production-grade, self-hosted scraping engine that can compete with managed scraping APIs on speed, reliability, and cost.

## 0. Current State
- [x] TSK-0001 Validate 10x parallel launch with `.tallow-bin\tallow.exe`.
- [x] TSK-0002 Confirm all 10 runs generated `csv`, `summary`, and `full.json` artifacts.
- [x] TSK-0003 Convert manual 10x launch steps into a reusable script with one command.
- [x] TSK-0004 Add run metadata fields for binary path, git commit, config hash, and launch timestamp.
- [x] TSK-0005 Create one canonical output directory convention and deprecate old formats.

## 1. Goals and Constraints
- [x] TSK-0101 Define P0 success metric: successful extraction rate on target domains.
- [x] TSK-0102 Define P0 success metric: median and p95 scrape latency per page.
- [x] TSK-0103 Define P0 success metric: cost per 1k successful pages.
- [x] TSK-0104 Define P0 success metric: operator time per incident.
- [x] TSK-0105 Define explicit non-goals for v1 to prevent scope creep.
- [x] TSK-0106 Set realistic memory budget per worker and per host.
- [x] TSK-0107 Document that "<1MB RAM" and "10,000x faster" are not v1 acceptance targets.

## 2. Runtime and Toolchain Stability
- [ ] TSK-0201 Resolve binary capability mismatch between `target\release\tallow.exe` and `.tallow-bin\tallow.exe`.
- [ ] TSK-0202 Add startup self-check to fail fast when required stdlib functions are missing.
- [x] TSK-0203 Add `tallow doctor` command for environment and runtime capability checks.
- [ ] TSK-0204 Pin compiler/runtime version in CI and release artifacts.
- [ ] TSK-0205 Add signed release artifacts and checksums.

## 3. Configuration and Target Management
- [x] TSK-0301 Move hardcoded URLs from scripts into versioned target manifests.
- [ ] TSK-0302 Add per-domain config for method, headers, payload, auth mode, and parser strategy.
- [ ] TSK-0303 Add allowlist and denylist support at domain and URL-pattern level.
- [ ] TSK-0304 Add robots policy mode: strict, advisory, and off.
- [ ] TSK-0305 Add rate-limit config per domain and per IP pool.
- [x] TSK-0306 Add configuration schema validation with clear error messages.

## 4. Parallel Execution and Scheduling
- [x] TSK-0401 Build `launch_tallow_parallel.ps1` with configurable worker count and script path.
- [ ] TSK-0402 Add queue-based dispatcher for large target sets instead of fixed wave batching.
- [ ] TSK-0403 Add adaptive concurrency control based on error rate and latency.
- [x] TSK-0404 Add retry budget by domain and by error class.
- [x] TSK-0405 Add exponential backoff with jitter for retryable failures.
- [ ] TSK-0406 Add graceful cancellation and partial checkpoint resume.

## 5. HTTP Engine Improvements
- [ ] TSK-0501 Add per-request timeout, connect timeout, and overall job timeout controls.
- [ ] TSK-0502 Add redirect policy controls and max redirect depth.
- [ ] TSK-0503 Add compressed response handling and safe decompression limits.
- [ ] TSK-0504 Add normalized request fingerprint profiles per target group.
- [ ] TSK-0505 Add robust classification for transport, DNS, TLS, timeout, 4xx, and 5xx errors.
- [ ] TSK-0506 Add support for POST GraphQL payload templates from manifest.

## 6. Browser Fallback Pipeline
- [ ] TSK-0601 Implement escalation policy: HTTP first, browser fallback only when needed.
- [ ] TSK-0602 Add browser action primitives: click, type, wait-for-selector, scroll.
- [ ] TSK-0603 Add browser session reuse policy for related targets.
- [ ] TSK-0604 Add screenshot and HAR capture on fallback failures.
- [ ] TSK-0605 Add fallback reason codes to output artifacts.

## 7. Anti-Bot and Access Strategy
- [ ] TSK-0701 Add challenge detection for Cloudflare, Akamai, DataDome, PerimeterX, and generic WAF pages.
- [ ] TSK-0702 Add response fingerprinting for blocked, soft-blocked, and deception pages.
- [ ] TSK-0703 Add cookie jar rotation and TTL management by domain.
- [ ] TSK-0704 Add proxy tier policy: datacenter, ISP, residential, and mobile.
- [ ] TSK-0705 Add session stickiness windows for login-dependent flows.
- [ ] TSK-0706 Add legal-safe handling for authenticated targets requiring credentials.

## 8. Extraction Layer
- [ ] TSK-0801 Add parser strategy registry: JSON, GraphQL JSON envelope, HTML selectors, and markdown.
- [ ] TSK-0802 Add schema-first extraction for each target dataset.
- [ ] TSK-0803 Add extraction confidence scoring and null-reason tagging.
- [ ] TSK-0804 Add selector healing pipeline with fallback selectors.
- [ ] TSK-0805 Add table and pagination extraction support.
- [ ] TSK-0806 Add diff-based change capture for recurring crawls.

## 9. Data Quality and Validation
- [x] TSK-0901 Add schema validation for every output row before persist.
- [x] TSK-0902 Add required-field validation and typed coercion.
- [ ] TSK-0903 Add duplicate detection by canonical keys.
- [ ] TSK-0904 Add value-range and anomaly checks for numeric fields.
- [ ] TSK-0905 Add quality score per run and per domain.
- [ ] TSK-0906 Add quarantine file for invalid rows.

## 10. Storage, Artifacts, and Formats
- [x] TSK-1001 Standardize artifact bundle: manifest, raw responses, normalized rows, metrics, logs.
- [x] TSK-1002 Add stable JSON schema for `full.json`.
- [x] TSK-1003 Add newline-delimited JSON export for large runs.
- [ ] TSK-1004 Add parquet export option for analytics workloads.
- [x] TSK-1005 Add deterministic CSV column ordering.
- [x] TSK-1006 Add compression option for large artifact sets.

## 11. Observability and Operations
- [ ] TSK-1101 Add structured logs with correlation ID per request.
- [x] TSK-1102 Add run-level metrics: throughput, success rate, retry rate, and p95 latency.
- [x] TSK-1103 Add domain-level dashboards.
- [x] TSK-1104 Add alerting for success-rate drops and spike in block/challenge codes.
- [x] TSK-1105 Add failure replay tool from saved request metadata.
- [x] TSK-1106 Add incident runbook for block events and provider outages.

## 12. Benchmarking Against Competitors
- [x] TSK-1201 Create benchmark corpus with representative easy, medium, and hard targets.
- [x] TSK-1202 Define controlled benchmark protocol: same target windows, same output schema, same retry budget.
- [x] TSK-1203 Run Tallow baseline benchmarks and save raw benchmark artifacts.
- [x] TSK-1204 Record benchmark references for Bright Data, Zyte, Oxylabs, Firecrawl, and ScrapingBee using public docs and trial runs where permitted.
- [x] TSK-1205 Produce monthly benchmark report with trend lines.
- [x] TSK-1206 Gate releases on no-regression thresholds.

## 13. Performance and Resource Optimization
- [ ] TSK-1301 Profile CPU hotspots in parser, HTTP pipeline, and serialization.
- [ ] TSK-1302 Profile memory allocations and reduce peak RSS per worker.
- [ ] TSK-1303 Add bounded buffers and backpressure for high-volume runs.
- [ ] TSK-1304 Add zero-copy or low-copy parsing where practical.
- [ ] TSK-1305 Add adaptive batch sizing by target response profile.
- [ ] TSK-1306 Publish realistic performance targets per hardware tier.

## 14. Security, Legal, and Compliance
- [ ] TSK-1401 Enforce `@legal` metadata for all production scraping scripts.
- [ ] TSK-1402 Add credential vault integration for authenticated targets.
- [ ] TSK-1403 Add secret redaction in logs and artifacts.
- [ ] TSK-1404 Add per-target data retention policy and automatic purge.
- [ ] TSK-1405 Add compliance report generator per run.
- [ ] TSK-1406 Add security review checklist before each major release.

## 15. Testing and QA
- [ ] TSK-1501 Add unit tests for classifiers, retry policy, and output schema.
- [x] TSK-1502 Add integration tests for parallel launcher and artifact generation.
- [ ] TSK-1503 Add fault-injection tests for timeouts, 429s, TLS errors, and proxy failures.
- [x] TSK-1504 Add end-to-end test suite with controlled mock targets.
- [ ] TSK-1505 Add deterministic golden files for output verification.
- [ ] TSK-1506 Add CI matrix for Windows and Linux execution paths.

## 16. DX, CLI, and Documentation
- [x] TSK-1601 Add one command for production run with config file input.
- [x] TSK-1602 Add one command for 10x/50x/100x parallel presets.
- [x] TSK-1603 Add `--dry-run` mode for config validation without network calls.
- [x] TSK-1604 Add quickstart docs for new operators.
- [x] TSK-1605 Add troubleshooting docs for common failure modes.
- [x] TSK-1606 Add operator checklist for pre-run and post-run validation.

## 17. Release Plan
- [ ] TSK-1701 Milestone M1: runtime stability plus reproducible parallel launcher.
- [ ] TSK-1702 Milestone M2: target manifest system plus extraction schemas.
- [ ] TSK-1703 Milestone M3: adaptive concurrency plus observability dashboard.
- [ ] TSK-1704 Milestone M4: benchmark suite plus release gating.
- [ ] TSK-1705 Milestone M5: production hardening and onboarding docs.
- [ ] TSK-1706 Tag `v1.0` only after benchmark and reliability criteria pass for two consecutive cycles.

## 18. Immediate Next Sprint (Recommended)
- [ ] TSK-1801 Build launcher script and commit it.
- [x] TSK-1802 Externalize target URLs into manifest.
- [ ] TSK-1803 Add GraphQL POST payload support from manifest.
- [ ] TSK-1804 Add run metadata and schema-stable `full.json`.
- [x] TSK-1805 Add domain-aware retry and backoff.
- [x] TSK-1806 Add first benchmark report template.
