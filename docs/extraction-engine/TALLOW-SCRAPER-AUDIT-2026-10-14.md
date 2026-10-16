# TALLOW SCRAPER — COMPREHENSIVE AUDIT & REA FEATURE-INTEGRATION FEASIBILITY

**Date:** 2026-10-14 · **Tree:** `/home/user/Nixe` @ branch `v1`, HEAD `384daa3b` (2026-10-14), 4312 dirty entries
**Method:** every claim below is re-verified against the live tree this session (`rg`, `wc`, the built
`target/debug/tallow`, the running services). Inherited claims are marked **[inherited]** and were NOT
trusted. The prior audit warned of exactly this (`RECONCILIATION-2026-10-12.md` §0.1: "wiring state must
be re-checked at use time, not inherited") — five of its open items have since closed, and one new defect
was found.

**Prior art read first (not re-derived):** `docs/extraction-engine/REA-INTEGRATION-ASSESSMENT.md`,
`RECONCILIATION-2026-10-12.md`, `EXTRACTION-ENGINE-SPEC.md` (superseded index),
`docs/mega/MEGA-CHECKLIST.md`, `artifacts/modisoft-rea-2026-10-12/REPORT.md`.

**Assumption labeled:** the request's "Tallow scraper" = the four collection surfaces in this tree
(Rust `stdlib`/`browser`/`runtime`, the `tallow-reader` daemon, the `nixreader` reader, the
`scrape-isolated` sandbox). "The previously listed features" = the REA capability/tool list from the
2026-10-14 REA load (6.5.0) message.

---

## PART A — INVENTORY: what the scraper is today

### A1. Code surface (measured)

| Surface | Files | Lines | Role |
|---|---:|---:|---|
| `src/browser/**` | 136 | 100,234 | CDP/browser engine: pool, stealth, cookies, proxy, robots, retry, capture, crawl |
| `src/stdlib/**` | 114 `.rs` (+86 `.tl`) | 98,742 | Site modules, entity, extract, ocr/pdf, source adapters |
| `src/runtime/**` | 27 | 11,375 | FFI layer: fetch, egress_http, browser, html, db, dns_guard, ippool, crawler, page_cache |
| `crates/tallow-reader/src` | 9 | 1,578 | Warm-pool extraction daemon (HTTP) |
| `nixreader/**` | 66 | 24,921 | Camoufox reader + `reader_service.py` + leak/egress drills |
| `target/debug/tallow` | 1 | 673 MB | Built 2026-10-14 21:00 UTC |

Stub census **[inherited, not re-run]**: 0 `todo!()`, 0 `unimplemented!()`. The browser tree is
implemented; the failures in this system are **wiring, flags, and bindings**, not missing logic.

### A2. The four collection surfaces (each a separate egress plane)

1. **Rust `fetch`/stdlib plane.** Fail-closed to Tor by contract: `src/runtime/fetch.rs`
   (`egress_proxy_url()`, `TOR_SOCKS_URL = socks5h://127.0.0.1:9050`, `TALLOW_ALLOW_DIRECT` as the
   *only* opt-out, `TALLOW_TOR_STREAM_ID` for per-run circuit identity); all HTTP goes through
   `src/runtime/egress_http.rs` (one agent per resolved proxy URL). A source-guard test fails the build
   if a stdlib file regains a bare `ureq::*` call.
2. **Browser plane.** `src/browser/**` driven via `browser/cdp.rs`; `tallow browser` is a live CLI verb.
3. **Reader daemon.** `tallow-reader-daemon` (active). Routes: `/health`, `POST /extract`, `/pool`,
   `POST /shutdown` (`crates/tallow-reader/src/routes/mod.rs:34-40`).
   `ExtractRequest { url, anon }`; `ExtractResult { url, title, content, length, source, member,
   exit_ip, error, cookies }` (`src/engine.rs:16-45`) — `cookies` is a deliberate harvest hook for
   replaying a session server-side (the DataDome `ct` case).
4. **`scrape-isolated` sandbox.** Separate plane with its OWN in-container Tor. Ubuntu 24.04; apt set =
   `tor, nftables, util-linux, curl, python3{,-requests,-socks,-yaml,-venv}` + GTK/NSS/ATK libs for
   Camoufox; Python venv `/opt/venv` with `camoufox, requests, pyyaml, pysocks, beautifulsoup4`.
   **No Node, no npm, no clang.** Gate order (entrypoint.sh) = DNS-leak gate → nft kill-switch + positive
   control → private Tor → `IsTor:true` → allowlist negative control → uid drop.

### A3. Data handling (where output actually goes)

| Store | Path | Content |
|---|---|---|
| Sandbox results | `/var/lib/scrape-isolated/out/results.jsonl`, `camoufox.jsonl`, `.exit_ip` | Per-request records, exit IP attestations |
| Reader cache | `nixreader/reader_cache.sqlite` (19.4 MB) | Reader-side cache/key store |
| Run artifacts | `artifacts/**` (282 dirs) | Per-run evidence packs and receipts |
| Signed receipts | `crates/tallow-jobs/src/scheduler.rs` — `ed25519_dalek::SigningKey` + `tallow_registry::receipt::Receipt`, one per attempt | Auditable dispatch trail |
| Provenance | `src/browser/provenance.rs` (8.8 KB), `src/run_evidence.rs` (13.5 KB), `src/artifact_index.rs` (27 KB) | Confidence breakdown, run evidence, artifact index |
| Compliance | `src/compliance/{clocks,incident,znism}.rs` + `compliance`/`pia`/`sast` CLI verbs | Local-only reports |

`provenance.rs` is **domain-specific**: `ValidationStep`, `ProvenanceRecord { price_cents,
canonical_product_id, store_id, extraction_method, extraction_confidence, final_confidence }`. It carries
confidence but **no explicit unknowns/limitations field** (verified: `rg limitation src/browser/provenance.rs
src/run_evidence.rs` → no hits).

---

## PART B — FRESH VERIFICATION of the 2026-10-12 audit

The prior reconciliation listed 10 open items. Re-measured today:

### B1. CLOSED since 2026-10-12 (the tree moved; do not re-plan these)

| # | Prior claim | Live state | Evidence |
|---|---|---|---|
| 1 | `llm_extract` dormant / gated off | **Schema-first extraction is DEFAULT-ON** | `browser/smart_extract.rs:121-131`: `TALLOW_LLM_EXTRACT` unset ⇒ `llm_on = true`; `mod.rs:49` `pub mod llm_extract;`, `:223` re-export |
| 2 | `TALLOW_DELTA_CRAWL` "set but never read" | **Wired both directions** | Readers `crawl_queue.rs:122,127,358,675` + `crawl_pipeline.rs:320,356,382,1176`; set by `scheduler.rs` |
| 3 | Content cache off by default | **Default ON** | `crawl_pipeline.rs:1196` `enable_content_cache: true`; asserted by test at `:1350` |
| 4 | Blocking `thread::sleep` in the fetch path | **Replaced by a token bucket that does not block** | `crawl_pipeline.rs:261-295` (interceptor consumes a token); test `rate_limit_middleware_does_not_block` `:1331` |
| 5 | 4 declared natives with no FFI symbol | **2 of 4 now bound** | `src/runtime/crawler_ffi.rs:49` `tallow_crawler_from_links`; `src/runtime/page_cache_ffi.rs:47` `tallow_page_cache_create` |

### B2. STILL OPEN (verified absent/unchanged this session)

1. **2 FFI symbols unbound.** `tallow_crawler_from_sitemap`, `tallow_structured_data_extract` → **0 hits
   in `src/`**. `.tl` natives exist (`stdlib/browser.tl:393,442`); Rust modules `browser/sitemap.rs` and
   `browser/structured_data.rs` exist. Bindings only — no new logic.
2. **No extraction CLI surface.** `target/debug/tallow extract|plan|schema|scrape` → `error: unrecognized
   subcommand`. Present instead: `compliance, audit, sast, pia, browser, canary, tor, …`.
3. **4 feature flags still opt-in** (`Cargo.toml:291,294,298`): `parquet-storage`, `s3-storage`,
   `redis-backend`, `real-ml`.
4. **`ml::*` still mock-dominated:** `ml/embeddings.rs` mock=22, `ml_matcher.rs` mock=2, `vector_store.rs`
   mock=1 (vs 17/19/16 functions) — mock strings are pervasive in `embeddings.rs` specifically.
5. **No limitations/unknowns field** in provenance or run evidence (Part A3).
6. **No general dataset diff / replay / lineage query** **[inherited, not re-probed]**.

### B3. NEW DEFECT found this audit — the headline multiplier is currently nominal

`TALLOW_LLM_EXTRACT` now defaults **ON** and the documented lever is "one LLM schema generation per
domain+page-type, then CSS-speed extraction". The engine behind it is Ollama at
`http://localhost:11434` (`smart_extract.rs:113,127`). **Ollama is not installed and not running on this
box** (`command -v ollama` → nothing; `systemctl is-active ollama` → `inactive`).

Consequence, per the code's own documented behaviour: with Ollama unreachable the tier "degrades
gracefully to `ExtractedProduct::failed()`". So the schema-first path is **on by default with no engine
behind it** — it will look enabled in config and behave as a no-op that emits failed rows, spending a
per-page connection attempt. Either install an engine or make the default honest (off unless the engine
answers). An enabled-by-default feature with a missing dependency is worse than a disabled one: it
silently converts "not attempted" into "attempted, failed".

### B4. Build-blocking context (unchanged)

Branch `v1` **does not compile from a clean checkout** since `e5fec4cd` (2026-10-13): `mod rng;` is
tracked in `crates/tallow-crypto/src/lib.rs` but `crates/tallow-crypto/src/rng.rs` was never committed.
Any integration work, CI, or fresh-worktree verification is gated on that one file landing.

---

## PART C — FEASIBILITY: the previously listed REA features → the Tallow scraper

REA on this box is 6.5.0 (207 MCP tools, doctor 5/5). The list splits into three classes.

### C1. Web/JS plane — where REA and Tallow overlap

| REA feature | Tallow today | Verdict |
|---|---|---|
| Website structure / scripts / network / screenshots (`inspect-web-page`, `analyze-web-bundle`) | **Present and deeper**: `cdp.rs` 62 KB, `page.rs` 142 KB, `network.rs` 94 KB, `visual.rs` 28 KB (pixel diff + baselines), `trace.rs` 28 KB, `recording.rs` 28 KB | **Integrate: no.** Nothing to gain; Tallow already owns this surface |
| Browser scenario capture (Playwright CDP) | Tallow drives CDP directly; sandbox has its own Camoufox engine | **Integrate: no.** Duplicative |
| `analyze-javascript-application`, `export-web-scripts` (static JS/Electron) | **ABSENT.** Closest existing capability is sourcemap-URL *detection*: `src/stdlib/sitescan.rs` (12 hits, detect-only). No module/import graph, no sourcemap reconstruction, no V8 inspector | **The one genuinely adjacent lane.** See C3 |
| HAR import / saved-capture readers | **PARTIAL**: `artifact_policy.har` in the plan format + `network.rs` captures traffic; **no HAR import** | **Integrable without refactoring** — pure Rust parse, no new runtime |
| SQLite snapshot inspection | `runtime/db_ffi.rs` + `storage.rs` SQLite backend (REAL) | **Integrate: no.** Duplicative |
| Screenshot compare | `visual.rs` (pixel diff, baselines) + `ab_detector.rs` | **Integrate: no.** Duplicative |
| WebMCP discovery | Nothing that maps to a Tallow product path | **Skip** |

### C2. Compiled-artifact lanes — out of domain, and two are licence-walled

Native decompilation, offline ELF layout, Go binaries, WASM, EVM, crash/register analysis, .NET/CIL,
APK, Android devices, JEB projects, Android resources, firmware, package anatomy. Tallow has **none of
them and no consumer for them** (unchanged from the 2026-10-12 assessment: 12 of 17 target types absent).
Reimplementing natively would mean writing a decompiler, a disassembler, a JADX-equivalent and a firmware
unblobber; **IDA/Hex-Rays and JEB are commercial and licence-gated**, so they cannot be integrated at any
effort level. The corresponding Tallow-side dependencies (`java`, `apktool`, `adb`, `tshark`,
`sigrok-cli`, `wabt`, `wakaru`, `rizin`, `lldb`, `mitmproxy`) are absent from the box and, with two
exceptions, from the sandbox image too. **Verdict: refuse / not applicable** — and for third-party
binaries the ownership/consent gate applies independently of effort.
The generic version of this class — reading an *artifact the operator supplies* — is already served by
REA as an external CLI with no wrapper needed.

### C3. The one integration worth debating (and its real cost)

**Static JavaScript/Electron analysis into the extraction stack.** It is the only listed capability that
(a) Tallow lacks, (b) is genuinely adjacent to collection work (the modisoft run at
`artifacts/modisoft-rea-2026-10-12/` used exactly this), and (c) has a worked example on this box.

Two shapes, and they are not equivalent:

- **Wrapper (additive, reversible).** A new `src/stdlib/js_analyze.rs` + `src/runtime/js_analyze_ffi.rs`
  that shells out to the `rea` CLI over stdio, driven from a `tallow-jobs` recipe. Touches no
  parity-critical code. **But it adds a Node runtime dependency to Tallow's extraction stack**, which
  contradicts the standing 2026-10-12 operator decision ("skip REA entirely — build only the
  Tallow-native Rust extraction stack").
- **In-sandbox (isolation-correct, more invasive).** Add `nodejs` + `rea-agents` to
  `/opt/scrape-isolated/Dockerfile`, rebuild the image, add target hosts to
  `targets.allowlist`, and invoke `rea` from the job layer. Cost: image rebuild + a second runtime in a
  deliberately minimal image, against the precedent that even `clang` was left out to keep the image lean.
  The `scrape.yaml` chokepoint (9050 → filter → Tor 9053, uid 10001 cannot egress) still holds, so the
  *isolation* property survives; only image weight changes.

**Verdict: technically feasible without refactoring; strategically already decided against.** Recommend
keeping REA as an out-of-process CLI (its own MCP + CLI, invoked by the operator or Hermes) rather than
baking it into the scraper — same capability, zero coupling, no Node in the extraction path.

### C4. The adoptable convention (highest value / lowest cost on the whole list)

REA attaches **explicit limitations/unknowns** to every evidence record and frames work as
`investigate → understand → recreate`. Tallow's provenance carries confidence but cannot express
"unknown", so absence is indistinguishable from failure. Extending `ProvenanceRecord` and
`run_evidence.rs` with a typed `unknowns`/`limitations` field is a small, contained change that touches
neither `interp.rs` nor `codegen.rs`. **Verdict: integrable now.**

---

## PART D — Conflicts, dependencies, architectural changes

1. **Parity constraint dominates.** Any language-level addition must be byte-identical across
   `interp.rs` (2.2 MB) and `codegen.rs` (1.25 MB). This is why C4 (a runtime/struct field) is cheap and
   anything typed into the language is not.
2. **Egress contract is closed.** Every new fetch path must go through `runtime/egress_http.rs`; a
   source-guard test fails the build on a bare `ureq::*`. Any REA integration that fetches must inherit
   this or it will not build.
3. **Sandbox has no Node** (verified in the Dockerfile) and denies egress by default at the network layer.
   Any in-sandbox integration needs an image change *and* allowlist entries.
4. **Standing decision conflict.** `REA-INTEGRATION-ASSESSMENT.md` §4 recommends *not* integrating REA;
   the checklist records the operator deciding "skip REA entirely" (2026-10-12, C2/D-2). Reversing that
   needs an explicit decision, not a silent wrapper.
5. **Out-of-scope inventory.** `src/browser/` contains ~25 modules (`stealth*`, `fingerprint*`,
   `dpi_bypass`, `traffic_morph`, `cookie_farm`, `antibot`, `captcha`, `residential`, …) that
   `RECONCILIATION-2026-10-12.md` §3 places out of scope. They are present for inventory completeness and
   are not integration targets. `EXTRACTION-ENGINE-SPEC.md` §12 lists the same exclusions.
6. **No CLI seam for extraction.** With no `tallow extract|plan|schema`, any new capability lands as a
   stdlib module + FFI + a jobs recipe — or inside the sandbox job layer.
7. **Clean-checkout build is broken** (missing `tallow-crypto/src/rng.rs`). Independent of this work, but
   it blocks verifying any of it in a fresh worktree.

---

## PART E — Gaps vs opportunities (ranked by verified value ÷ cost)

**RE-ISSUED 2026-10-15.** Every item below is now closed, closed-with-a-non-claim, or rejected with a
reason. Where a verdict differs from this audit's own expectation, the difference is stated — two of
them were the audit being wrong.

| # | Opportunity | Verdict | Evidence |
|---|---|---|---|
| 1 | Give the schema-first tier an engine, or turn it off honestly (B3) | **CLOSED.** The engine is selectable and the tier is OFF unless configured — the refusal *is* the honest default | `429eb6d2`, `3ba8fe7f` |
| 2 | Bind the 2 remaining FFI symbols | **REJECTED-WITH-REASON for `structured_data_extract`; the audit's cost estimate was wrong.** "Rust modules already exist; only bindings missing" is false: the interpreter reaches it via the stdlib facade, but codegen has **no lowering**, and the registered `%struct.StructuredData` layout is only part of what a binding needs — the native must construct memory including the runtime representation of `[]String` and `Map`. **No correctness defect exists** (interpreter fallback is correct; `--require-native` refuses loudly), so this is a backend gap. The claim that *was* imprecise — `stdlib/browser.tl`'s `// native:` comment, silent about which backend runs it — is corrected. | `29f9976d` |
| 3 | Add the extraction CLI surface | **CLOSED**, verified end to end on both paths against the repo's own row validator, with no-egress proven (established sockets delta 0) | `c09363a4` |
| 4 | Adopt typed `unknowns`/`limitations` (C4) | **CLOSED**, and the helper now has a real caller (the extract verb declares every field its selectors did not yield) | `75ff637a` |
| 5 | HAR import (C1) | **CLOSED.** The blocker was structural, not cosmetic: every HAR struct derived `Serialize` only, so the recorder's own shapes could not be parsed | `11923c2a` |
| 6 | Leave REA as an external CLI (C3) | **CLOSED** with the decision recorded and a runbook | `c64fd997` |
| 7 | Close the clean-checkout build (B4) | **CLOSED — and it took TWO defects, not one.** The audit named one (a missing `rng.rs`). Committing it revealed a second: `8e5bdaac` had landed `src/runtime/fs_ffi.rs`, which calls `provenance::hash_bytes`, while excluding the file defining it. `CLEAN_CHECKOUT_RC=0` now, at `73abec10` | `e923b3e4`, `73abec10` |

**Gaps this audit did not name, found while executing:**

| # | Gap | Verdict |
|---|---|---|
| 8 | **The tier sends third-party page content to a third-party vendor with no policy check.** The request plan already governs that transfer through its per-request `compliance` block; the tier was the one path bypassing its own governance | **CLOSED**, fail-closed: with no policy a remote transfer is refused, and `transfer_allowed` is part of the tier's measured state (`30dfa52e`) |
| 9 | **The tier had no spend ceiling** — `num_predict`/`max_tokens` bounded one response, nothing bounded how many requests a run could make | **CLOSED**: checked before each call, refusing past the cap; the measurement half completes as `disabled-with-a-reason` because it needs a live engine (`8923ea72`) |
| 10 | **`real-ml` was referenced by `cfg` but never declared**, so that branch had never been compiled and every build emitted two warnings | **CLOSED**: declared; the branch compiles and returns an honest error rather than silently substituting a non-semantic engine (`29f9976d`) |

## Non-claims

- No benchmark was run; no throughput multiplier is asserted here.
- `ml::*` mock-dominance and the dataset-diff/replay gaps are **[inherited]** and were not re-probed
  beyond the mock census and the provenance check.
- The two closed FFI symbols were confirmed to be real `pub extern "C"` definitions; their *runtime*
  behaviour under codegen was not executed.
- REA's own arm64 coverage caveats (Wakaru, tshark and sigrok lanes recorded x64-only) stand.
- **The live model call is unverified.** Every engine-side test is offline (request shape, response
  shape, credential refusal, budget, transfer policy); the wire path needs a credential and a
  reachable engine, so it is plausible and not demonstrated.
- **P2.T1 is deferred, not done** — see item 2. Its acceptance tests could not be constructed on this
  box in any case (a network-bound arm cannot be asserted in a unit test locally).
- **P7.T2's Tor-plane proof was not executed** — it needs a browser session, not a docs-only step.
- Per-item status for the execution plan itself lives in
  `docs/plans/2026-10-14-tallow-scraper-execution-plan.md` (Progress 2026-10-15).
