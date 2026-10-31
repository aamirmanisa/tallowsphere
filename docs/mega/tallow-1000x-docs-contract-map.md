# Tallow 1000x Docs Contract Map

> **Docs truth label:** Authoritative current docs contract map for classifying Tallow/Nixe documentation. It controls which docs are contracts, implemented helpers, roadmap ledgers, research, evidence, or drift risks; it does not create new runtime/live/production capabilities.

Date: 2026-06-22
Status: P2-009 docs-truth maintenance sweep
Last reconciled: 2026-06-22

## Purpose

The Tallow workspace has a lot of useful documentation, but not every document has the same authority. This map separates contract docs from roadmap docs, implemented-helper docs, research docs, and stale or drifting docs. Use it before making implementation decisions so we do not accidentally treat aspirational research as production truth.

Truth boundary for the 2026-06-22 P2-009 sweep: accepted evidence currently covers Linux/CachyOS local/non-live/offline/fixture/no-secret proof slices through Phase 11 plus autonomous P2 hardening cards through `P2-008` (scraper-critical stdlib parity, benchmark/CI scaffolds, native operator CLI, and canonical emitted error objects). This map does not claim ungated live external scraping, production browser fallback, real credentials/vaults, destructive retention, legal approval decisions, paid/live benchmark superiority, deploy/release readiness, or Windows support.

## Classification Legend

| Class | Meaning |
| --- | --- |
| Contract | Describes a shape or behavior that implementation should satisfy. Changes need migration thinking. |
| Roadmap | Tracks planned work or completion status. Useful, but must be reconciled against code. |
| Implemented helper | Documents a script or workflow that exists now, though maturity may vary. |
| Research | Valuable direction or comparison material, but not proof of implementation. |
| Evidence | Historical run, report, or benchmark evidence. Useful for baseline, not automatically current truth. |
| Drift risk | Contains contradictions, stale status, or claims that need verification. |

## Contract Docs

| Document | Class | Why It Matters | Current Caution |
| --- | --- | --- | --- |
| `docs/plans/2026-05-31-tallow-1000x-scraper-upgrade.md` | Contract / roadmap | Main multi-phase execution plan for the 1000x upgrade. | Should be updated only with evidence from Phase gates. |
| `docs/architecture/output-convention.md` | Contract | Defines output naming/layout expectations. | Naming appears stricter in validator script than in docs. |
| `docs/architecture/launch-report-schema.md` | Contract | Defines launch report shape. | Must stay aligned with launcher output. |
| `docs/architecture/full-json-schema.md` | Contract | Defines full JSON run output. | Must be validated against current `.tl` writers. |
| `docs/architecture/artifact-bundle.md` | Contract | Defines portable artifact bundle expectations. | Phase 7 proves local bundle packaging/hash checks only; production launchers and live replay remain later gates. |
| `docs/architecture/ndjson-export.md` | Contract / implemented helper | Documents NDJSON export. | Confirm export output matches artifact bundle expectations. |
| `docs/architecture/parquet-export.md` | Contract / implemented helper | Documents Parquet export. | Task list status may lag script/doc reality. |
| `docs/operations/target-policy.md` | Contract | Defines target policy, allow/deny, robots/rate governance. | Needs expansion with full manifest schema. |
| `configs/tallow/targets.schema.json` | Contract | Current target manifest schema. | Too narrow for final platform. |
| `schemas/tallow/target-manifest-v2.schema.json` | Contract | Phase 2 object-target manifest contract. | Contract-defined; Linux-native normalizer, request-plan artifacts, and local/mock request-plan runtime proof now exist, but live/external policy, auth, browser fallback, and production compliance remain pending. |
| `schemas/tallow/extraction-schema.schema.json` | Contract | Phase 2 schema-first extraction/data-quality contract. | Contract-defined; Phase 5 now proves local/mock normalized extraction-row output and validation, while production/live extractor wiring remains deferred. |
| `schemas/tallow/extraction-row.schema.json` and `schemas/tallow/extraction-row-validation-report.schema.json` | Contract | Phase 5 normalized row and validation-report contracts. | Accepted for local/mock row production, confidence/null reason/selector provenance, quarantine, and artifact proof only; not production/live extraction. |
| `schemas/tallow/error-taxonomy.schema.json` and `schemas/tallow/error-taxonomy.v1.json` | Contract | Defines canonical error kinds plus the `tallow.error_object.v1` emitted error object contract. | P2-008 current contract requires emitted errors to carry `kind`, `message`, `retryable`, `policy_blocked`, `source_target_id`, `url`, and `phase`; request-plan, compliance, extraction, and artifact/package reports preserve legacy fields only as compatibility data with explicit mappings. |
| `schemas/tallow/artifact-manifest.schema.json` | Contract | Phase 2 per-run artifact/redaction/retention/replay manifest contract. | Phase 2/4/5/7/9/10/11 local proof manifests are hash-checked; broader production launchers do not emit this shape yet. |
| `schemas/tallow/compliance-gate-report.schema.json` | Contract | Phase 9 local/no-secret compliance audit report contract. | Proves fake/local vault references, redaction scan, retention dry-run, and destructive-purge refusal only; no real secrets/legal approval. |
| `schemas/tallow/contract-index.json` | Contract | Index of Phase 2/5/9 contract spine files. | Additive manual index until producers/generators own it. |
| `schemas/tallow/full-run.schema.json` | Contract | Current full-run schema. | Writer/schema drift observed around `schema_version`. |

## Implemented Helper Docs

| Document | Class | Why It Matters | Current Caution |
| --- | --- | --- | --- |
| `docs/operations/quickstart.md` | Implemented helper | Describes current launch flow and now starts with the Linux/CachyOS Phase 1 preflight. | PowerShell presets remain legacy scraper-ops helpers until Linux-native producer migration lands. |
| `docs/operations/manifest-injection.md` | Implemented helper | Documents manifest injection into current TL template. | Injection is partial for per-domain headers and non-GET/payload entries. |
| `docs/operations/queue-dispatcher.md` | Implemented helper / roadmap | Documents queue dispatcher and state. | Phase 6 proves local durable scheduler/resume/DLQ behavior only; production external queues remain human-gated. |
| `docs/operations/run-metrics.md` | Implemented helper | Documents run metric extraction. | Phase 7 proves local metrics extraction only; production logs/correlation/alerts remain later gates. |
| `docs/operations/domain-dashboard.md` | Implemented helper | Documents domain dashboard generation. | Phase 7 proves local dashboard JSON only; live SLO integration remains later. |
| `docs/operations/failure-replay.md` | Implemented helper | Documents replay flow. | Phase 7 proves dry-run replay planning only; live replay is human-gated. |
| `docs/operations/operator-checklist.md` | Implemented helper / drift risk | Gives operator release checks and includes the Linux/CachyOS Phase 1 smoke/doctor gate. | Treat as legacy/local checklist unless reconciled with Phase 2-11 manifests and human gates. |
| `docs/operations/tallow-doctor.md` | Implemented helper | Documents active Linux/CachyOS `tallow doctor` plus legacy Windows script. | Keep Linux path as current Phase 1 gate; Windows script remains non-target unless requested. |
| `docs/operations/tallow-contract-validation.md` | Implemented helper | Documents Linux-native Phase 2/5 contract validation, including optional validation of generated v2 target-manifest artifacts with `--target-manifest` and Phase 5 extraction-row schema/report checks. | Validator is targeted/std-lib only, not a full JSON Schema engine. |
| `docs/operations/tallow-target-normalization.md` | Implemented helper | Documents the Linux-native BLK-008 v1/string-target to v2 object-target normalizer and its generated artifact boundary. | Proves normalization/validation only; launcher/runtime object-target execution remains pending. |
| `docs/operations/tallow-request-plan-builder.md` | Implemented helper | Documents the Linux-native request-plan builder and guarded legacy TL emission. | Proves metadata-preserving request-plan generation and safe/fail-fast downgrade only; direct local/mock runtime is documented separately. |
| `docs/operations/tallow-request-plan-runner.md` | Implemented helper | Documents the native operator workflow plus Python compatibility runner for request-plan dry-run, local/mock execution, zero-I/O preflight, compliance-gated native live GET execution, and canonical `tallow.error_object.v1` report rows. | Proves local/mock execution plus approved native live GET only when all local source-manifest/compliance/isolation/fail-closed gates pass; real vault, browser execution, paid benchmarks, destructive retention, and broad live method parity remain later gates. |
| `docs/operations/troubleshooting.md` | Implemented helper | Captures known operational failures and points Linux/CachyOS triage at doctor/smoke first. | Some runtime capability notes should become tests. |
| `docs/operations/compliance-gate.md` | Implemented helper | Documents the Phase 9/P1-010 Linux-native local/no-secret compliance gate and canonical P2-008 error-object findings. | Required proof metadata for request-plan live-preflight/live gates, not legal approval, real-vault/secret resolution, destructive retention, live scraping permission, or deploy readiness. |
| `docs/operations/phase11-proving-grounds.md` | Implemented helper / evidence | Documents the Phase 11 controlled proving-ground route-mix and Tallow import contract proof. | Fixture-only proof; no live scraping, production DB/search-index writes, all-sites rollout, or production product readiness. |
| `docs/qa/launcher-integration-tests.md` | Implemented helper | Documents launcher integration test. | Keep as smoke, not production scheduler proof. |
| `docs/qa/e2e-mock-targets.md` | Implemented helper | Documents mock-target E2E flow. | Should become Phase 1/2 verification gate after binary fix. |
| `docs/qa/golden-files.md` | Implemented helper | Documents golden file generation. | Needs integration into schema/extraction gates. |
| `docs/qa/output-schema-validation.md` | Implemented helper | Documents output schema validation. | Legacy fetch/probe structural validator is separate from the Phase 5 schema-defined extraction-row validator. |
| `docs/qa/row-validation.md` | Implemented helper | Documents strict row validation/quarantine, including the Phase 5 `scripts/validate_extraction_rows.py` local/mock row path. | Phase 5 proof is local/mock only; production launcher outputs and live/external datasets remain later gates. |

## Roadmap Docs

| Document | Class | Why It Matters | Current Caution |
| --- | --- | --- | --- |
| `docs/tallow-scraper-full-task-list.md` | Roadmap / drift risk | Large task ledger for scraper work. | Checkbox completion is roadmap bookkeeping, not acceptance evidence; reconcile against accepted phase packets before using. |
| `docs/mega/m1-m5-release-plan.md` | Roadmap | Prior mega release planning. | Treat as historical unless reconciled with current plan. |
| `docs/mega/MEGA_EXECUTION_BOARD.md` | Roadmap / evidence | Prior execution board. | Historical signal, not current source of truth. |
| `docs/mega/release-readiness.md` | Roadmap | Release readiness notes. | Needs refresh after Phase 1 smoke ladder. |

## Research And Spec Docs

| Document | Class | Why It Matters | Current Caution |
| --- | --- | --- | --- |
| `docs/browser-specs.md` | Research / spec / drift risk | Rich description of browser CLI and subsystem behavior. | Top banner is authoritative for Phase 4 boundaries; detailed sections may still describe aspirational/live features. |
| `docs/MEGA_SCRAPER_ENGINE_RESEARCH.md` | Research / drift risk | Valuable architecture and comparison research. | Historical research/aspirational architecture only; do not treat "production-ready" or speed/superiority claims as verified. |
| `docs/TALLOW-CAPABILITIES.md` | Generated capability inventory / drift risk | Broad generated capability reference. | Useful inventory only; counts/API examples can overclaim relative to accepted gates. |
| `docs/TALLOW_FULL_FEATURES_REPORT.md` | Generated inventory / drift risk | Broad full-feature report. | Label as inventory/reference unless each claim is tied to a gate artifact. |
| `docs/browser-reference.html` | Research / docs output | User-facing browser reference. | Generated/HTML docs may lag actual APIs. |
| `docs/api/index.html` and `docs/api/stdlib-browser.html` | Docs output / drift risk | Generated stdlib API reference. | Underreports large modules such as browser, crypto, transfer, net, and OSINT. |

## Benchmark Evidence

| Document | Class | Why It Matters | Current Caution |
| --- | --- | --- | --- |
| `docs/benchmarks/benchmark-protocol.md` | Contract | Official scraper benchmark artifact protocol, now including the Phase 10 `1.0-local-offline` closure profile. | Local/offline artifacts are accepted for protocol/tooling proof only; official live matrix/performance claims remain human-gated. |
| `docs/benchmarks/benchmark-corpus.md` | Contract | Defines smoke/standard/full benchmark classes. | Needs current corpus proof after runtime fix. |
| `docs/benchmarks/phase10-local-fixture-benchmark.md` | Implemented helper / evidence | Documents the Phase 10 local/offline fixture generator, offline Firecrawl comparator, artifact expectations, and non-claims. | This is not a live benchmark runbook; Firecrawl service/API and performance claims remain human-gated. |
| `docs/benchmarks/fixtures/phase10-local-corpus.json` | Contract / fixture | Tiny `fixture://`-only corpus for local/offline benchmark protocol proof. | Do not treat as official live target manifest or workload-representative benchmark data. |
| `docs/benchmarks/no-regression-thresholds.md` | Contract | Defines release gates. | Thresholds need current baseline data. |
| `docs/benchmarks/monthly-report-2026-04.md` | Evidence | Records a real calibration run. | Shows 10 completed parallel runs but 0 percent JSON/GraphQL success. |
| `docs/benchmarks/copy-benchmark-protocol.md` | Contract | Stronger copy benchmark plan. | Separate from scraper benchmark claims. |

## External And Proving-Ground Docs

| Document | Class | Why It Matters | Current Caution |
| --- | --- | --- | --- |
| `firecrawl-self-hosted/README.md` | External baseline | Firecrawl product/API overview. | Vendored subtree; do not modify casually. |
| `firecrawl-self-hosted/SELF_HOST.md` | External baseline | Self-host limitations and setup. | Self-hosted lacks hosted Fire-engine anti-blocking layer. |
| `firecrawl-self-hosted/apps/api/AGENTS.override.md` | Local guidance | API workflow says use `pnpm harness ...`. | Follow nested guidance if working there. |
| `tallow-search/AGENTS.md` | Local guidance | Project-specific rules and verification. | Prefer over root guidance inside `tallow-search/`. |
| `tallow-search/docs/zacks_canonical_schema.md` | Contract | Finance/Zacks data schema. | Good later structured-data proof, not first platform smoke. |
| `tallow-search/docs/zacks_pipeline_runbook.md` | Roadmap / evidence | Documents Zacks quality gates and current gaps. | Do not run broad rollout as first proof. |
| `tallow/AGENTS.md` | Local guidance | Product correctness rules. | Must follow before touching Tallow. |
| `tallow/config/default_product_store_config.toml` | Contract | Product index and quality contract. | Excellent second-stage proof after platform route proof. |

## Current Accepted Phase Packets

| Phase | Accepted Scope | Acceptance Packet |
| --- | --- | --- |
| Phase 1 Linux/CachyOS substrate | Runtime/toolchain/doctor/smoke substrate only. | `docs/mega/phase1-finalization-10agent/final-integration-report.md`; `docs/mega/phase1-finalization-10agent/agent-10-final-qa-gate.md` |
| Phase 2 contract/local-native | Contract, target normalization, request-plan generation/runtime, zero-I/O policy preflight. | `docs/mega/phase2-completion-10agent/final-integration-report.md`; `docs/mega/phase2-completion-10agent/final-independent-qa-report.md` |
| Phase 3 browser contracts | Browser stdlib facade/contract metadata and CDP pipe/fallback fail-closed boundaries. | `docs/mega/phase3-browser-contracts-10agent/final-integration-report.md`; `docs/mega/phase3-browser-contracts-10agent/final-independent-qa-report.md` |
| Phase 4 browser fallback service | Local/non-live fallback planner/service only. | `docs/mega/phase4-browser-fallback-service-10agent/final-integration-report.md`; `docs/mega/phase4-browser-fallback-service-10agent/final-independent-qa-report.md` |
| Phase 5 extraction rows | Local/mock schema-defined row production, validation, quarantine, artifact proof. | `docs/mega/phase5-extraction-rows-10agent/final-integration-report.md`; `docs/mega/phase5-extraction-rows-10agent/final-independent-qa-report.md` |
| Phase 6 adaptive scheduler | Local durable scheduler/resume/DLQ/blocked-target proof. | `docs/mega/phase6-adaptive-scheduler-10agent/final-integration-report.md`; `docs/mega/phase6-adaptive-scheduler-10agent/final-independent-qa-report.md` |
| Phase 7 artifacts/replay/observability | Local artifact bundle, dry-run replay, metrics, dashboard proof. | `docs/mega/phase7-artifacts-replay-observability-10agent/final-integration-report.md`; `docs/mega/phase7-artifacts-replay-observability-10agent/final-independent-qa-report.md` |
| Phase 9 compliance/vault/retention | Local/no-secret compliance gate proof. | `docs/mega/phase9-compliance-vault-retention-10agent/final-integration-report.md`; `docs/mega/phase9-compliance-vault-retention-10agent/final-independent-qa-report.md` |
| Phase 10 benchmarks/Firecrawl | Local/mock/offline benchmark protocol and Firecrawl fixture-comparison scaffolding. | `docs/mega/phase10-benchmarks-firecrawl-10agent/final-integration-report.md`; `docs/mega/phase10-benchmarks-firecrawl-10agent/final-independent-qa-report.md` |
| Phase 11 controlled proving-ground | Fixture-only Tallow Search route-mix and Tallow import contract proof. | `docs/mega/phase11-proving-grounds-10agent/final-integration-report.md`; `docs/mega/phase11-proving-grounds-10agent/final-independent-qa-report.md` |
| `docs-truth-continuous` | Docs truth labels/map reconciliation for BLK-019 only. | `docs/mega/docs-truth-reconciliation-10agent/final-integration-report.md`; `docs/mega/docs-truth-reconciliation-10agent/final-independent-qa-report.md` after acceptance. |
| P2 production-hardening lane through `P2-008` | Local/offline/no-secret hardening: scraper-critical stdlib parity, benchmark/CI scaffolding, native operator CLI, and canonical emitted error objects. | Current source/tests/scripts/docs listed in this map; P2-009 docs sweep keeps the map/capability/blocker docs aligned with executed gates. |

## Operating Rule

When a doc, source file, and script disagree:

1. Prefer executable source/tests/scripts for current behavior.
2. Prefer architecture/operation docs for intended contracts.
3. Treat roadmap checkboxes as claims to verify, not proof.
4. Treat research docs as design input until matched by code and tests.
5. Update this map when a document becomes authoritative, stale, or superseded.

