# TALLOW EXTRACTION ENGINE — Feature & Specification Catalog

> **SUPERSEDED 2026-10-12 — read `RECONCILIATION-2026-10-12.md` first.**
> A folder-wide audit found this catalog overlaps four pre-existing scraper specs
> (`docs/tallow-scraper-full-task-list.md`, both `docs/plans/*tallow*1000x*`,
> `docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md`) and that most items
> are already implemented across `src/browser/**` (136 files) and `src/stdlib/**`.
> Keep this file only as a categorized feature index; the reconciliation holds verdicts.

**Status:** SUPERSEDED AS A SPEC — retained as a feature index. Nothing here is wired.
**Superseding artifact:** `docs/mega/MEGA-CHECKLIST.md` (phase-by-phase, 57 tracked items). The verdicts that used to live in `RECONCILIATION-2026-10-12.md` now live there too; this file is indexed only, and `docs/mega/MEGA-CHECKLIST.md` §11 governs all T1 exclusions.
**Date:** 2026-10-12
**Scope:** Extraction / collection capabilities buildable *into the Tallow language* (compiler, runtime, stdlib, CLI, plan format).
**Baseline it extends:** `docs/MEGA_SCRAPER_ENGINE_RESEARCH.md` (arsenal inventory), `docs/TALLOW-CAPABILITIES.md` §4/§9, `examples/request-plan.v1.json`, `schemas/tallow/examples/*.extraction.schema.json`.

## Non-claims

- No item below has been implemented or benchmarked. Where a number appears (e.g. "10–50x"), it is a **target to measure**, not a measured result.
- Existing engine facts in this document were read from the repo at the paths named. Anything I assert about current behaviour cites a file.
- No item here circumvents authentication, access control, anti-bot protections, or encryption. See **§12 Excluded**.

## What already exists (do not rebuild)

| Capability | Where |
|---|---|
| HTML parse + CSS select, interpreter and native | `src/stdlib/html.rs` (26.2K), `src/runtime/html_ffi.rs` (22.5K) |
| `Extract.schema` / `.pattern` / `.jsonld` / `.all` | `stdlib/extract.tl`, `src/stdlib/extract.rs` (15.9K) |
| Egress contract: Tor default, `TALLOW_PROXY`, `TALLOW_ALLOW_DIRECT`, hard refusal, per-host delay | `src/runtime/egress_http.rs` (40.4K) |
| Fetch + batch | `src/runtime/fetch.rs` (41.7K), `http.batch` in `src/codegen.rs` |
| CDP browser automation | `src/browser/**` (113 files), `src/runtime/browser.rs` (85.7K) |
| Declarative request plans + compliance block + artifact policy | `examples/request-plan.v1.json`, `scripts/run_tallow_request_plan.py` |
| Local-first compliance reporting | `src/compliance/{clocks,incident,znism}.rs` |
| Jobs: priority queue, retries, dead-letter, budget, halt switch, Ed25519 receipts | `crates/tallow-jobs/{queue,scheduler,recipe,exec,budget,state}.rs` |
| Credential vault (TOTP, PQC, custody, personas) | `src/vault/**` (20 files) |
| io_uring runtime, DNS guard, IP pool, gzip | `src/runtime/{io_uring_runtime,dns_guard,ippool_ffi,gzip_ffi}.rs` |
| Entity resolution | `src/stdlib/entity.rs` (61.1K), `stdlib/entity.tl` |

---

## 1. Language & Type System

The core of "build it into the language": extraction constructs the compiler can check.

- **1.1 `ExtractionSchema` as a first-class type.** `schema Product = "schemas/product.extraction.schema.json"` — a schema reference resolves at compile time to a struct with typed fields, so extraction results are typed, not `Map`.
  - *Lands in:* parser + `src/codegen.rs` + `src/interp.rs`. *Acceptance:* wrong field name is a compile error in both engines. *Parity:* struct layout identical interpreter/native.
- **1.2 Schema → `.tl` codegen.** `tallow schema gen product.schema.json > product.tl` emits struct + validator + provenance wrapper. One source of truth for schema and code.
- **1.3 Compile-time selector validation.** CSS selector string literals are parsed by the compiler; an unknown pseudo-class or malformed selector is a compile error, not a silent zero-match run.
- **1.4 Tristate field model.** Formalize the existing NULL-vs-`""` distinction in `html_ffi.rs` as a language type: `Field<T> = Present(T) | Empty | Absent`. Extraction code cannot collapse "the page had no such element" into "the value is empty".
- **1.5 `Sourced<T>` — field-level provenance as a type.** `Sourced<Product>` carries, per field: value, origin URL, byte range in the source document, sha256 of the retrieved body, fetch timestamp, extractor id, plan hash, confidence. Threaded through the dataflow so provenance cannot be dropped by accident. **This is the primary differentiator in the catalog.**
- **1.6 Capability-typed egress.** `fetch(url, egress: Egress)` where the `Direct` variant requires an explicit capability token. Code without the token does not compile for direct egress — mirroring the runtime refusal already in `egress_http.rs`. *Acceptance:* a plan that would egress direct without an allowance fails to build.
- **1.7 Effect annotations.** `@egress`, `@reads`, `@writes` on functions, statically checked so a "pure" extraction function cannot open a socket. Enables whole-plan audit before execution.
- **1.8 `@source` / `@legal` annotations.** A function or recipe binds to a source-registry entry (§7.2); binding is validated at compile time and stamped into run receipts.
- **1.9 PII classification propagation.** `Pii<T>` / `Secret<T>` markers propagate through dataflow; the compiler refuses to write a `Pii<T>` to an unredacted sink. (Extends the privacy-type claim in the mega doc into something checkable.)
- **1.10 Lazy/streaming sequences.** `Sequence<Row>` for extraction over corpora larger than memory; `map`/`filter`/`take` are lazy, terminal ops are explicit.
- **1.11 Deterministic iteration order guarantee.** Ordered maps/selects everywhere, documented, so identical input yields byte-identical output. Required for §6.3 replay and for parity.
- **1.12 Typed scalars for extracted data.** Decimal (exists: `stdlib/decimal.tl`), Currency, Unit, GeoPoint, Date — parsed from messy source text with a recorded raw vs normalized pair.
- **1.13 Selector-chain fallback.** `select(["h1.title", "h1", "[itemprop=name]"])` — first match wins, and **which** selector matched is recorded in provenance. Legitimate robustness for sources you own or are authorized for; makes schema drift visible instead of silent.
- **1.14 Record-boundary extraction.** `block(selector).records(schema)` — repeat a sub-schema over each matched element (drives `extraction_rows`).
- **1.15 Error type for extraction.** `ExtractError = NoMatch | InvalidValue | SchemaMismatch | PolicyRefused | EgressRefused` — distinct, so quarantine reason codes (§5.11) are derived from types rather than strings.

## 2. Fetch / HTTP Layer

- **2.1 HTTP/2 multiplexing + connection pooling.** Current hot path is `ureq` (HTTP/1.1) per `egress_http.rs` deps. Target: negotiated H2 with a bounded stream count per connection.
- **2.2 DNS cache.** `hickory-resolver` with a bounded LRU; removes DNS latency from the hot path. Complements existing `dns_guard.rs`.
- **2.3 Conditional GET.** `If-None-Match` / `If-Modified-Since`; a 304 reuses the cached body and is recorded as such (not as a fresh fetch).
- **2.4 Content-addressed response cache as a language primitive.** `Cache.if_fresh(url, max_age)` returns the stored body + its sha256, so a re-run is reproducible offline.
- **2.5 Per-host token bucket.** Extends the existing per-host minimum delay (`TALLOW_FETCH_DELAY_MS`, default 250 ms) to a configurable rate *and* burst, still per host so a wide crawl is not serialized globally.
- **2.6 Adaptive backoff honouring `Retry-After`.** On 429/503, respect the header verbatim; otherwise jittered exponential backoff. Never retry in a way that increases load on a host already refusing.
- **2.7 Retry policy as declarative data.** Attempts, backoff class, retryable statuses, idempotency key — per plan, with the policy hash in the receipt.
- **2.8 Robots.txt: fetch, cache, enforce (RFC 9309).** Honours the `robots_mode: "strict"` field that already exists in the plan format.
- **2.9 Sitemap / RSS / Atom discovery** as a frontier source (`sitemap.xml`, `robots.txt` Sitemap lines, feed autodiscovery).
- **2.10 Streaming bodies.** Bodies piped rather than buffered, so a 50 MB response goes straight into a streaming parser.
- **2.11 io_uring I/O path.** Promote `src/runtime/io_uring_runtime.rs` from an available runtime to the extraction hot path where the kernel supports it.
- **2.12 `http.batch` formalized.** Existing codegen builtin gets per-URL `Result`, bounded concurrency, and per-host fairness.
- **2.13 Cookie jar as a first-class type.** Extends `stdlib/cookie_jar.tl` / `src/stdlib/cookie_jar.rs` with per-origin isolation and expiry, used for *your own* authenticated sessions.
- **2.14 Negotiated content encoding.** gzip (exists), brotli, zstd, with the chosen encoding in provenance.
- **2.15 Honest identification.** A configurable User-Agent + contact URL for sources you operate, with the value recorded per request. (No UA spoofing — see §12.)
- **2.16 Request budget pre-flight.** Refuse before egress if the plan's projected request count exceeds the source's declared cap (§7.2).

## 3. Parsing & Extraction

- **3.1 Streaming selector path (`lol_html`).** A second, streaming parse mode for select-and-emit workloads that never builds a DOM. Target: order-of-magnitude over the `scraper` DOM path for large documents.
- **3.2 DOM path retained** for anything needing structure, ancestry, or mutation (`html_ffi.rs` stays the reference implementation).
- **3.3 Schema library expansion.** Beyond product/article/profile/serp/job: company, real-estate-listing, government-record, financial-filing, event, recipe, job-posting, review, contact-info.
- **3.4 Schema versioning + migration.** Every schema carries a version; rows record it; a migration is a declared function, and old rows can be re-normalized.
- **3.5 Structured-data coverage: JSON-LD (exists) + microdata + RDFa + OpenGraph + Twitter cards + `<meta>` heuristics**, merged with precedence rules and conflict reporting.
- **3.6 Table extraction.** `doc.tables()` → typed rows with header inference and colspan/rowspan handling. High value for registries, filings, financials.
- **3.7 Pagination as a plan primitive.** next-link/Cursor/offset strategies with cycle detection, max-pages, and per-page provenance.
- **3.8 Value normalizers.** Dates across formats, numbers with locale separators, currency symbols, phone, address, unit conversion — each records `raw` and `normalized`.
- **3.9 Main-content detection.** Deterministic boilerplate removal (text-density + link-ratio scoring) so extracted text is article body, not nav.
- **3.10 Entity extraction + dedupe.** Wires the existing `entity` module into extraction: person/org/location/identifier resolution, plus near-duplicate detection for records appearing on multiple pages.
- **3.11 Extraction quarantine.** Rows failing validation go to a quarantine sink with a typed reason (`ExtractError`), matching the `extraction_quarantined` counter already in the execution report. Operator-reviewable.
- **3.12 Selector drift detection.** Track per-selector yield across runs; a material drop produces a drift warning *before* the dataset silently empties.
- **3.13 LLM-assisted extraction as an opt-in fallback.** When a typed field is `Absent`, an explicitly enabled local-model pass attempts it; the value is marked lower-confidence, carries the model id and prompt hash in provenance, and never overwrites a schema-derived value.
- **3.14 PDF / document extraction.** Text-layer extraction for PDFs and office documents, with page-number provenance per field, so filings and scanned registries are in scope.
- **3.15 Extraction from APIs, not just HTML.** JSON/GraphQL response shapes declare a schema the same way (`examples/request_plan_post_graphql/` is the seed).
- **3.16 Character-encoding correctness.** Explicit encoding resolution with the detected encoding recorded, so mojibake is a caught error, not a stored value.

## 4. Dynamic Content / Browser

- **4.1 Deterministic render mode.** Fixed viewport, locale, timezone, and clock; animations disabled; results identical across runs. Justified by reproducibility, not by evasion.
- **4.2 Wait strategies.** Beyond `WaitUntil`: selector-present, DOM-stable, network-quiet, and explicit timeout — each recorded in the run report.
- **4.3 Browser fallback policy.** Formalize `browser_fallback.mode` (`never` | `on_empty` | `always`) with cost accounting: how many URLs fell back, and what it cost in wall-clock.
- **4.4 Artifact policy matrix.** Extend the existing `artifact_policy` fields (`capture_body`, `response_snippet_bytes`, `screenshots`, `har`, `dom`) with redaction rules applied *before* storage.
- **4.5 Manual gate / human escalation.** When a page requires login, consent, or a challenge, the run **pauses and routes to the operator**. This is the engine's answer to an access control: a human completes it. Seeds exist in `examples/browser_fallback_manual_gate/` and `stdlib/escalation.tl`.
- **4.6 Session/profile isolation per source.** Independent browser profiles per zone (`src/browser/zone.rs`), so credentials and cookies never cross sources.
- **4.7 Firefox path parity.** `src/browser/juggler.rs` means plans are not Chrome-only; spec the same feature set across both engines.
- **4.8 Browser pool management.** Bounded tabs, recycling, memory ceiling enforcement, and clean teardown of orphaned Chrome processes — with the box's known 4 GiB worker cap in mind.
- **4.9 Authenticated-session support via the vault.** Log in as the operator to sources where the operator holds an account, using `src/vault/**` (TOTP, credential custody), with the credential never entering a `.tl` literal.
- **4.10 Screenshot/DOM capture on policy.** Only where `artifact_policy` permits, with the policy snapshot stored alongside the artifact.
- **4.11 Interaction primitives already present.** Click, type, scroll, `Page.throttle_network()` — documented as first-class plan steps rather than ad-hoc scripts.

## 5. Scheduling, Jobs, Distribution

- **5.1 Extraction jobs on `tallow-jobs`.** `.tl` recipes drive extraction runs; priority queue + bounded retries + dead-letter are inherited, not rebuilt.
- **5.2 Budget caps per day and per recipe.** Requests, bytes, wall-clock, estimated spend — enforced by `budget.rs` **before** dispatch.
- **5.3 Kill switch.** The existing halt file refuses every dispatch fleet-wide, immediately. Extraction inherits it.
- **5.4 Fail-closed policy parsing.** Unparseable budget, ledger, or source-registry entry ⇒ refuse. Never "run anyway".
- **5.5 Signed run receipts.** Ed25519 receipt per run with plan hash, source ids, counts, and outcome; refusals stay out of the signed ledger.
- **5.6 Checkpoint / resume.** Frontier persistence and exactly-once row emission so a killed run resumes without duplicating rows.
- **5.7 Distributed extraction.** `src/browser/distributed/**` exists as a seed: coordinator + workers, idempotent shards, work stealing, and a supervisor that can drain a worker.
- **5.8 Scheduled and change-triggered runs.** Interval schedules plus re-run-on-change (from §6.5 diff), delivered through the existing cron/scheduler path.
- **5.9 Concurrency control per host.** Global worker count is capped by policy, but *per-host* concurrency is what prevents accidental hammering.
- **5.10 Resource ceilings.** Worker memory/CPU limits with the box's cgroup reality encoded (heavy browser fleets must be launched through the scoped runner, not inside the 4 GiB worker limit).

## 6. Storage, Provenance, Evidence

- **6.1 Provenance-bearing rows.** Every row persists `Sourced<T>` data: field values plus byte range, body sha256, fetch time, extractor id, schema version, plan hash, confidence.
- **6.2 Content-addressed artifact store.** Bodies and captures stored by hash, deduped, with `retention_days` (already in the plan format) enforced by a reaper.
- **6.3 Replay.** `tallow plan replay <run-id>` re-derives rows from stored bytes + the recorded plan and must produce byte-identical output. Reproducibility is the acceptance test.
- **6.4 Manifest per dataset.** Plan + schema versions + engine version + source registry revision — recorded with the data so any row can be audited back to its exact conditions.
- **6.5 Dataset diff engine.** Version-to-version change reports: fields added/removed/changed, records appearing/disappearing, with counts. Ports the diff model from binary tooling to sources.
- **6.6 Lineage query.** source → request → response → row → field, queryable, so "where did this number come from" is a query not an investigation.
- **6.7 Export formats.** JSONL (exists), CSV, SQLite, Parquet, and direct DB writes via `db_ffi` (COPY-style batch inserts).
- **6.8 PII-driven redaction and retention.** Field PII tags (§1.9) drive both redaction on export and retention on delete.
- **6.9 Deletion receipts.** A retention expiry or operator deletion produces a signed receipt naming the hashes removed.

## 7. Compliance, Policy, Safety

The defensible differentiator against commercial scraping vendors. Most of the primitives already exist.

- **7.1 Compliance block is mandatory.** Every request carries `source_authority`, `purpose`, `legal_basis`, `pii_policy`, `retention_days`, `robots_mode`, `requires_approval` (format already in `examples/request-plan.v1.json`). A request without one is refused at plan load, not at fetch time.
- **7.2 Source registry.** Authorized sources declared with basis, contact, licence terms, rate caps, and robots policy. **Unknown source ⇒ refuse**, the same fail-closed shape as `budget.rs`.
- **7.3 Egress contract extension.** `egress_http.rs` already enforces Tor-default, explicit direct opt-in, and hard refusal on unparseable proxy. Extend the existing source-level guard tests to cover every new fetch path so no bare client can reappear.
- **7.4 Approval gate.** `requires_approval: true` holds the plan at a human gate before first egress; the approval is a signed receipt naming the approver.
- **7.5 Terms/robots evidence capture.** Snapshot the source's robots.txt and terms at fetch time and store the hash, so the basis for a run is provable after the fact.
- **7.6 Compliance report generation.** Reuse `src/compliance/{clocks,incident,znism}.rs`: local-only, nothing transmitted, operator approves submission, and any claim with no machine check behind it reports `unsupported`.
- **7.7 Audit trail export.** Who/what/when/why for every request, exported as an evidence pack with digests for external signing.
- **7.8 Status boundary enforced in output.** Plans declare a `status_boundary` (already present); generated reports must carry it, so a fixture-scale result can never be presented as a production claim.
- **7.9 Refusal telemetry.** Policy refusals are first-class events with reasons, surfaced in run reports.
- **7.10 Manual gate is the only escalation.** No code path may attempt to satisfy an access control; it pauses for a human (§4.5).

## 8. Performance

Targets, not measurements. Benchmarks must exist before any of these are cited as achieved.

- **8.1 Global allocator.** mimalloc or jemalloc.
- **8.2 Streaming HTML parse.** `lol_html` for select work.
- **8.3 SIMD JSON.** `simd-json` for large API payloads.
- **8.4 SIMD byte search.** `memchr` for simple pattern hits instead of regex.
- **8.5 Bloom-filter URL dedupe.** Bounded-memory frontier for very large crawls.
- **8.6 DNS caching** (§2.2).
- **8.7 Zero-copy parsing.** Borrow from the source buffer where lifetimes allow.
- **8.8 Buffer pooling.** Reuse read buffers in the hot path.
- **8.9 Batch DB writes.** COPY-style inserts.
- **8.10 Kernel-level I/O.** io_uring, `SO_REUSEPORT`, IRQ affinity for self-hosted collectors.
- **8.11 Per-host rather than global rate limiting** (exists; keep it).
- **8.12 Benchmark suite.** `benches/` gains extraction benchmarks: pages/sec streaming vs DOM, rows/sec end-to-end, provenance-write overhead, replay throughput.
- **8.13 Published ceiling table from measurement.** Replace the asserted §5 throughput tables in the mega doc with measured numbers, or mark them explicitly unverified.

## 9. Observability & QA

- **9.1 Run report extension.** The existing execution report gains latency percentiles, per-host stats, per-selector yield, fallback counts, and quarantine breakdown.
- **9.2 Metrics endpoint.** Prometheus-format counters/histograms at the box's standard pattern (relay-style loopback port), for requests, bytes, refusals, quarantine, drift.
- **9.3 Fixture-server test harness.** Extend `examples/fixtures/mock_server.py` into a fixture library: pagination, malformed HTML, encoding traps, challenge page, consent wall, login wall.
- **9.4 Golden-row tests.** Schema conformance tests with expected rows committed, so extraction regressions are caught as diffs.
- **9.5 Interpreter/native parity tests for extraction.** Every extraction feature must produce byte-identical results in both engines — the repo's existing hard constraint applied to this surface.
- **9.6 Fuzzing.** `fuzz/` gains the streaming parser, the schema validator, and the selector compiler.
- **9.7 Chaos tests.** Kill mid-run, truncated bodies, timeouts, 429 storms — assert no duplicate rows and no lost receipts.
- **9.8 Concurrency/load tests** run under the memory ceilings that real workers have.

## 10. CLI & Developer Experience

- **10.1 `tallow extract`** — run a plan or a one-off extraction.
- **10.2 `tallow plan new|validate|lint|dry-run`** — `dry-run` prints exactly what would be fetched without egressing.
- **10.3 `tallow schema gen|check|diff`** — schema→type codegen and schema validation.
- **10.4 `tallow plan replay <run-id>`** — offline reproduction (§6.3).
- **10.5 `tallow dataset diff <a> <b>`** — §6.5 from the CLI.
- **10.6 `tallow provenance <row-id>`** — print the full lineage for one row.
- **10.7 Plan templates.** Listing→detail, sitemap→rows, paginated API, filing index→documents.
- **10.8 Error messages that name the fix.** A refused plan says which policy field failed and which registry entry is missing.
- **10.9 Example expansion.** Every feature gets a `examples/` entry in the existing `request_plan_*` / `extraction_schema_html` style, with a README and a stated non-claims boundary.

## 11. Source Adapters (authorized / open)

- **11.1 Sitemap and feed crawling** (§2.9).
- **11.2 JSON and GraphQL plans** (seed: `examples/request_plan_post_graphql/`, `stdlib/graphql.tl`).
- **11.3 Bulk open-data ingestion.** CSV/TSV, XML, NDJSON, shapefiles-as-attributes.
- **11.4 Open-data adapters consolidated under the plan format** so they are auditable like anything else: `stdlib/{fred,edgar,filings,geocode}.tl` currently make direct calls.
- **11.5 Institutional document extraction.** PDF/filing text-layer extraction (§3.14) for the filings path.
- **11.6 Registry-style public records** where the operator holds an account or the source offers a documented API — via vault-backed sessions (§4.9).

## 12. Excluded — not in scope, not to be specced

Requested or implied by `MEGA_SCRAPER_ENGINE_RESEARCH.md` §3 and §4, and deliberately absent above:

- TLS/H2 fingerprint impersonation (BoringSSL/`wreq` swap for the purpose of appearing as a specific browser).
- Per-anti-bot-vendor cookie farming (Akamai, Cloudflare, PerimeterX, DataDome, Kasada).
- DPI bypass / traffic morphing (Geneva techniques) — §3.5, §3.13.
- Browser stealth vectors, `document.hasFocus()` spoofing, `Function.prototype.toString` cloaking — Gaps 2, 3.
- Timing-distribution shaping to mimic humans (Gaussian→Weibull) — Gap 4.
- IP rotation to defeat rate limits or bans — Gap 5.
- Behavior simulation / "behavioral signals" — Gap 7.
- Timezone-to-IP consistency shaping — Gap 8.
- Decrypting data streams whose keys the operator does not hold.
- Any test suite whose target is "various protections".

The compliant substitutes inside this catalog: **§7.2** (source registry / fail-closed), **§2.8** (robots enforcement), **§2.5–2.7** (rate limits and honest backoff), **§4.5 / §7.10** (manual gate for anything that requires a human), **§11** (sources with a real basis).

## 13. Suggested sequencing

Waves are independently shippable and each ends with tests + a report, per the repo's existing discipline.

1. **Wave A — foundations.** §1.1, 1.2, 1.3, 1.4, 1.15 (typed schema extraction), §3.11 (quarantine), §7.1, 7.2 (policy mandatory + registry), §9.3–9.5 (fixtures, golden rows, parity). Smallest set that makes extraction typed and policed.
2. **Wave B — provenance.** §1.5 (`Sourced<T>`), §6.1–6.4 (provenance rows, artifact store, replay, manifest), §10.6. The differentiator; do it before scale.
3. **Wave C — fetch layer.** §2.1–2.8, §2.10–2.14, §1.6/1.7 (capability egress + effects), §8.1–8.4.
4. **Wave D — extraction depth.** §3.1–3.10, 3.12–3.16, §1.10–1.14, §10.1–10.5.
5. **Wave E — scale and ops.** §5.1–5.10, §8.5–8.13, §9.1–9.2, 9.6–9.8.
6. **Wave F — browser breadth.** §4.1–4.11, §11.1–11.6.

## 14. Open risks

- **Parity cost.** §1.5, §1.6, §3.1 and §8.2 each touch both engines; the dual-engine byte-identical constraint is the dominant cost in this catalog, not the parsing work.
- **`Sourced<T>` ergonomics.** Per-field provenance can make ordinary code verbose; the design must be usable by default, not opt-in ceremony.
- **Provenance storage growth.** Byte-range + hash per field multiplies row size; needs a measured budget (§8.12) before rollout.
- **LLM fallback drift.** §3.13 must never become the primary path, or provenance quality silently degrades.
- **Unmeasured claims.** The mega doc's throughput and moat tables are assertions. Per the box's own rule (probe-verified claims only), they should be measured or withdrawn.
