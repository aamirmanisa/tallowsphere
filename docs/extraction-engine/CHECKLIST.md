# TALLOW EXTRACTION — CONSOLIDATED CHECKLIST

**Status:** tracked, living. This is the single checklist; it supersedes the chat-only version.
**Date:** 2026-10-12 · **Scope:** `/home/user/Nixe` extraction/collection work.
**Source docs it consolidates:** `RECONCILIATION-2026-10-12.md`, `EXTRACTION-ENGINE-SPEC.md` (index only), `REA-INTEGRATION-ASSESSMENT.md`, `docs/mega/tallow-1000x-upgrade-2026/scraping-crawling.md` (partly stale — see §A), `docs/mega/phase5-extraction-rows-10agent/`.

---

## §A. Status change — the source audit is partly stale

Re-verified against the live tree on 2026-10-12. **Three headline claims of `scraping-crawling.md` are no longer true:**

| Audit claim | Fresh evidence | Verdict |
|---|---|---|
| `TALLOW_DELTA_CRAWL` "set but never read in `src/`" | 9 reader sites: `crawl_queue.rs:122,127,358,675`; `crawl_pipeline.rs:321,357,383,1161,1234`. Set at `scheduler.rs:929`. | REFUTED |
| `plan_incremental_crawl` / `is_unchanged_after_fetch` / `DeltaNeed` have "zero production callers" | `crawl_pipeline.rs:516` calls `is_unchanged_after_fetch`; `:465` uses `unchanged_count()`/`re_crawl`; `:1263` wires `.with_delta(...)`; `:385` resolves `self.delta \|\| delta_crawl_enabled()`. | REFUTED |
| `llm_extract` "not registered in `mod.rs`" | `mod.rs:49` `pub mod llm_extract;`; `:223` re-export; invoked `smart_extract.rs:221` (`with_config`), `:235` (`heal_schema`). | REFUTED |
| `CrawlResult.unchanged` has "no caller" | Set `crawl_pipeline.rs:484`; consumed in-pipeline `:465`. Terminal skip unconfirmed. | PARTLY REFUTED |

Also already done: `@legal` annotations with a `legal_bases` report; CLI `pia`, `sast`, `compliance`, `audit`.

**Rule for future audits:** component-verdict sections aged well; "unwired" claims did not. **Wiring state must be re-checked at use time, never inherited.**

---

## §B. The work — each item verified fresh this turn

- [ ] **B1. Bind the 4 missing FFI natives.** `tallow_crawler_from_sitemap`, `tallow_crawler_from_links`, `tallow_page_cache_create`, `tallow_structured_data_extract` — **0 hits each in `src/`**; declared `// native` at `stdlib/browser.tl:305-312, 325-327, 354-356`. Rust modules exist (`browser/sitemap.rs`, `browser/structured_data.rs`); only bindings missing.
  *Accept:* each resolves `--require-native`; no silent interpreter fallback.
- [ ] **B2. Turn the crawl content-cache on by default.** `crawl_pipeline.rs:28` — still off by default.
  *Accept:* re-crawl of an unchanged fixture emits 304s and zero re-extractions.
- [ ] **B3. Replace the blocking rate limiter.** `crawl_pipeline.rs:295` `std::thread::sleep(wait)` in the fetch path.
  *Accept:* async per-host limiter; throughput reported **at constant per-host request rate**.
- [ ] **B4. Confirm the terminal delta skip.** Pipeline consumes `unchanged` internally (`:465`, `:484`); terminal consumer unconfirmed.
  *Accept:* evidence either way, then close or file.
- [ ] **B5. Verify then flip 4 feature flags.** `parquet-storage`, `s3-storage`, `redis-backend`, `real-ml` (`ml::*` mock-only). **Audit-sourced — re-verify first.**
- [ ] **B6. Extraction CLI surface.** Fresh `tallow --help` has **no** `extract`, `plan`, `schema`, `scrape`. Spec §10 wholly unimplemented.
- [ ] **B7. Phase 5 remaining.** Generic `tallow.extraction_schema.v1` extraction (currently hardcoded product-listing), parser-registry/request-plan integration, selector-chain wiring. **June-sourced — re-verify.**
- [ ] **B8. Language-level types (only genuinely new domain).** `Sourced<T>` field provenance as a type; capability-typed egress; compile-time selector + schema validation; tristate `Field<T>` promotion. §1.8 `@legal` **already exists** — drop it.
  *Cost driver:* touches `interp.rs` (2.2 MB) + `codegen.rs` (1.25 MB), both byte-identical under the parity harness.
- [ ] **B9. Measure every item the same way — three numbers, never one:** baseline, after, and **constraint held** (per-host rate / model calls per page / rows emitted). A speedup that moves the constraint is a policy violation.

---

## §C. Decisions only the operator can make

- [ ] **C1.** The 5 GB `Tallow/` duplicate checkout (git `master`, 60,431 files, own `target/` 3 G, `website/`, `apps/`, `crates/`) — live or dead?
- [x] **C2. REA — DECIDED: not integrating.** Operator chose "skip REA entirely — build only the Tallow-native Rust extraction stack" (2026-10-12). Verified same day: **nothing from REA is present on the box** — no `rea-agents` (npm global or npx cache), no MCP registration, no repo references outside `REA-INTEGRATION-ASSESSMENT.md`. And **no RE engine is installed**: `ghidra`, `hopper`, `ida`, `jadx`, `wabt`, `binwalk`, `pwntools`, `radare2`, `rizin` all absent; only stock `objdump` (used by `src/codegen.rs` to verify its own hardening) and `gdb`. No Python RE libs (`pwn`, `capstone`, `lief`, `angr`, `pefile`). Reopen only if a target requires binary/JS *static analysis* — then `npx rea-agents setup` locally (MIT) plus a native-analysis engine.
- [ ] **C3.** Build B8, or leave the language untouched?
- [ ] **C4.** Doc sprawl: 4 pre-existing specs + 3 docs in `docs/extraction-engine/`. This file is the consolidation; retire the index?

---

## §D. Housekeeping (verified)

- [ ] **D1.** Reclaim **~22 G** (`target/` 19 G + `Tallow/target/` 3 G). Root at **76%, 36 G free**.
- [ ] **D2.** `artifacts/` 7.5 G across **328** run dirs — retention pass.
- [ ] **D3.** Correct `scraping-crawling.md` §3/§4 so the next agent doesn't inherit its stale claims.

---

## §E. Module classification — the evasion family, correctly sorted

### E0. Governing rule (the box's own policy, not an outside imposition)

`docs/opsec/security-privacy-audit-2026-09-12.md:95`:
> **Out of scope by design (policy):** detection-evasion escalation beyond the doctrine · CAPTCHA-solver services · any network-level scan without an owner-authorized scope · any "undetectable" claim.

`:7` operating guardrails: read-only · public-data-only · robots.txt + `crawl-delay` honoured · **stop-on-block, no escalation** · network scanning only inside owner-authorized scope · no "undetected" claims.
`:90` (R3): "concealment is not a legal strategy — compliance and authorization are."

`docs/opsec/stealth-scanning-statement-of-intent.md:10,38`: postures for **authorized** read-only public-data collection; GET-only; no authentication surfaces; no credentials; no writes to targets; stop-on-block.

### E1. The test

> **Is the target a system that has decided to refuse you, and is the goal to overrule that decision?**

The excluded family exists to defeat **stop-on-block** — the one control the doctrine names as absolute. Attribution resistance for authorized work (Tor, pacing, leak closure) is in-doctrine. Overruling a refusal is not.

### E2. Classification

| Module | What its own doc comment says | Tier |
|---|---|---|
| `stealth.rs` | "design-target JS-vector spoofing", correlated fingerprint properties | **T1 EXCLUDED** |
| `stealth_v2.rs` | "comprehensive anti-detection evasion scripts" vs Google/Cloudflare/PerimeterX | **T1** |
| `stealth_v3.rs` | "advanced anti-detection evasions for DataDome, FingerprintJS, CreepJS" | **T1** |
| `advanced_stealth.rs` | malleable traffic profiles, connection warming | **T1** |
| `network_stealth.rs` | TCP/IP fingerprint correlation | **T1** |
| `tor_stealth.rs` | Tor-aware browser fingerprint matching | **T1** against a refusing target; in-doctrine for attribution resistance **only while stop-on-block holds** |
| `fingerprint_coherence.rs` | coherence validation to defeat cross-referencing anti-bot systems | **T1** |
| `fingerprint_validator.rs` | cross-vector consistency to defeat anti-bot ML | **T1** |
| `http2_fingerprint.rs` | HTTP/2 SETTINGS control vs Akamai/CDN bot detection | **T1** |
| `cookie_farm.rs` | generates anti-bot cookies (`_abck`, `cf_clearance`) via real Chrome | **T1** |
| `behavior.rs` | "human behavior simulation for anti-bot bypass" | **T1** |
| `wordfence_bypass.rs` | "Wordfence JS challenge bypass" | **T1** |
| `antibot.rs` | "unified anti-bot bypass orchestrator" | **T1** |
| `vendor_detect.rs` | identifies which anti-bot system a site uses (in service of the above) | **T1** |
| `traffic_morph.rs` | makes request patterns "statistically indistinguishable from real" users | **T1** |
| `slider_captcha.rs` | trajectories that "pass behavioral analysis" | **T1** |
| `captcha.rs` | **split:** detection + manual solve mode | detection/manual gate = **T3** |
| `captcha.rs` | **split:** "external solver integration" | solver = **T1** — named in the policy as out of scope |
| `dpi_bypass.rs` | Geneva / XTLS-Vision protocol obfuscation | **T2 DUAL-USE** — censorship circumvention is a *different* question from scraping. Excluded from this workstream; reclassifiable if the purpose stated is getting your own traffic through a censoring network. |
| `proxy_intelligence.rs` | ASN classification, diversity enforcement, pool scoring | **T2** — privacy/geo-testing = fine; using egress diversity to get past a refusal = escalation |
| `residential.rs` | commercial rotating-proxy gateways (IPRoyal, Oxylabs, Bright Data) | **T2** — same test |
| `ipv6_pool.rs` | IPv6 pool + mobile proxy rotation | **T2** — same test |
| `free_proxies.rs` | fetches SOCKS5 lists from GitHub, validates | **T2** — same test; plus a standing supply-chain hygiene concern (third-party list ingestion) |
| `cadence.rs` | "never sleep a constant" — jittered pacing | **T3** — pacing is L1 of the doctrine; jittered politeness is good practice |
| `runtime_fingerprint_audit.rs` | "what the page *actually sees*" — self-diagnostic | **T3** |
| `cli/fingerprint_audit_cmd.rs` | `tallow fingerprint-audit` (JA4/JA4H/JA4T, coherence, cohort-k; exit 0/2/64) | **T3** |
| `substitution.rs` | **"Product substitution engine: canonical product → alternatives"** (out of stock, cheaper, generic, dietary swap) | **T3 — MISLISTED EARLIER; belongs in normal product work** |

### E3. Corrections to my earlier list (my errors)

1. **`substitution.rs` is not evasion at all** — it's a product-alternatives graph. I wrongly swept it in.
2. **`runtime_fingerprint_audit.rs` is a self-diagnostic**, not an evasion vector. Wrongly swept in.
3. **I flattened different categories:** `dpi_bypass.rs` (censorship circumvention) and `cadence.rs` (politeness pacing) are not anti-bot evasion. `traffic_morph.rs` genuinely is.
4. **`captcha.rs` is mixed** and must be split: detection + manual solve are in-doctrine; the solver integration is explicitly out of scope by policy.

### E4. Offensive stdlib surface outside `src/browser/` — §E scope extension

§E above was scoped to `src/browser/` only. Sweeping `src/stdlib/` the same way found one more member of the excluded class:

| Module | What its own doc comment says | Tier |
|---|---|---|
| `stdlib/jwt.tl` + `src/stdlib/jwt.rs` (21.6 KB) | **"JSON Web Token analysis, forgery, and attack"** — `JWT.forge`, `attack_none` (alg:none), `attack_weak_secrets` (wordlist brute force against HMAC secrets), `attack_kid_injection`, `attack_alg_confusion` | **T1 EXCLUDED** — this is an **authentication-defeat toolkit**: it mints valid-looking tokens and recovers signing secrets in order to impersonate a user. Defeating an auth control is the same category as defeating an anti-bot control. |

**Checked and NOT offensive** (recorded so it isn't re-flagged):

- `mitm` hits (13 files) are **defensive** — `tallow-crypto/pake/sas.rs:233` describes SAS as *detecting* a MITM ("two endpoints that did two independent PAKE legs (the MITM case) end up with…"), and `tallow-net/transport/tls_config.rs:389` notes that E2E ciphertext survives a TLS-layer MITM. The stack is designed to **resist** MITM, not perform it.
- `transfer_decrypt_payload` (`stdlib/transfer_net.rs:3422`, with a roundtrip test at `:6240`) decrypts **Tallow's own** end-to-end transfer payloads.
- `deobfuscate_string` (`stdlib/crypto.rs:8153`) is **keyed** — `deobfuscate_string(hex_data, key)` requires the key as an argument, so it only works where the key is already held. Not a bypass.

---

## §F. Standing exclusions

- **T1 modules above** — no writing, extending, testing, or speccing. Inventory only. Files remain untouched; this is a scope rule, not a deletion.
- **No "1000x across all specifications" claims.** Baseline-zero for the 12 absent REA capabilities (`0 → 1`, not a ratio); physically bounded metrics (a 200 ms RTT cannot become 0.2 ms); "hardware requirements" has no unit.
- **No re-derivation from the four prior specs** without re-checking wiring state (§A).

---

## §G. What this checklist does NOT contain — the repo's own canonical queues

Verified 2026-10-12. This file is the complete list for the **extraction workstream as scoped by one conversation**. It is **not** the repo's work queue. The repo maintains six canonical artifacts (its own sync rule, quoted in §G.6) and this checklist had been reconciled against none of them.

### G.1 Blocker register — `docs/mega/tallow-1000x-blocker-register.md` (34.8K)

**20 blockers, BLK-001 … BLK-020**, each with a P0/P1/P2 priority, evidence, and a posture. Four are live, and all four read **"local gate complete / production deferred"**:

| Blocker | Pri | Scope | Posture | What remains |
|---|---|---|---|---|
| **BLK-008** | P1 | Manifests / schemas | Phase 4 Local Planner Complete / Production Deferred | live execution, vault auth, live browser fallback, production artifact capture, production compliance |
| **BLK-009** | P1 | Extraction | Phase 5 Local/Mock Complete / Production Deferred | production/live extractor wiring, external dataset governance, browser fallback + live DOM extraction, vault/auth, production compliance. **This is the home of §B1/B2/B3/B7.** |
| **BLK-010** | P1 | Stdlib/runtime drift | Scraper-Critical Parity Complete / Broad Docs Drift Guarded | scraper-critical gate is `open_gaps=0`; the `modules=43 aligned=20 open_gaps=13` figure is the **deferred broad** class, not live work |
| **BLK-015** | P1 | Compliance | Phase 9 Local/No-Secret Gate Complete / Production Deferred | real vault/secret integration, approved live policy execution, production runner enforcement, destructive retention purge, legal/compliance approval |

### G.2 The phase program is DRAINED

`.hermes/phase-autopilot.yaml`: ~20 phases, **every one `status: accepted`**. `.hermes/project-memory.md`: *"as of this checkpoint there are no remaining `status: pending` phases."*

> Correction: my earlier note that Phase 5 was "the next pending phase" came from a June doc and is **wrong** today.

### G.3 Claims ledger — the measurement backlog

`docs/claims-ledger.yaml`: 889 lines, **65 tracked claims** (`R-P1…`, `R-C1…`, `R-T1…`), many marked unverified / target-only with anchors and lanes. Recorded examples: "no io_uring network path", "StubDpdkBackend only", "no SIMD tokenizer in tree", "AES-NI value unmeasured", "arena target-only", unmeasured startup/perf rows conflicting with `tests/perf_binary_startup.rs:3`.

> **This institutionalises B9.** Contribute measurements here rather than inventing a parallel method.

### G.4 Scraper task list §18 — open items

- [ ] **TSK-1801** Build launcher script and commit it.
- [ ] **TSK-1803** Add GraphQL POST payload support from manifest.
- [ ] **TSK-1804** Add run metadata and schema-stable `full.json`.
- (Done: TSK-1802, TSK-1805, TSK-1806.)

### G.5 Standing directive that GATES part of §B

`.hermes/project-memory.md`: *"**Do not jump directly into low-level io_uring/SIMD/distributed work until runtime, contracts, and benchmarks are stable.**"*

Consequences:

- B1 / B2 / B3 / B4 / B7 — local-scope engineering inside BLK-009/BLK-008. **Legitimate to do now.**
- **B5 (flag flips) + every perf item from the spec's §8 are GATED** behind BLK-013 (benchmark protocol) / BLK-014 (benchmark truth). Do not start them.
- Everything the register calls "production/live" — live execution, vault auth, live browser fallback, external dataset governance, production compliance — is **human-gated by policy** (BLK-008/009/015).

### G.6 The repo's own sync rule (verbatim direction)

> "Keep all future broad Nixe/Tallow work synchronized with this project memory file plus the blocker register, execution log, capability matrix, system map, and `.hermes/phase-autopilot.yaml`."

Six canonical artifacts. This checklist is none of them; it should be treated as a derived view, and any item here that contradicts one of them loses.

**Status of §G:** pointer + verified live subset. A full import of all 20 blockers and all 65 claims has **not** been done.

---

## §H. Portable from REA — verified gaps, ranked

REA is MIT. What follows is **concepts and interface shapes**, not the analysis engines. Each item was checked against the tree this session, and each carries a plain-language description so this file reads standalone.

- [ ] **H1. Evidence records that carry stated limitations** — *highest value, lowest cost*
  - **Plain:** every recorded value would also state what it *couldn't* establish.
  - **REA:** attaches evidence **and** explicit unknowns/limitations to every finding.
  - **Tallow today:** `src/browser/provenance.rs` + `src/stdlib/provenance.{tl,rs}` carry source, timestamp, extraction method, validator chain and confidence breakdown — **no limitations field**. `provenance.rs:94`'s `extraction_method: "unknown"` is a sentinel, not the same thing.
  - **Add:** `limitations: [String]` (or a typed `Unknown`) on the provenance record, emitted at every extraction site.
  - **Effort:** small (one schema field + emit sites). **Verdict: do it** — this is what makes provenance defensible rather than decorative. Pairs with §B8.

- [ ] **H2. Execution-free archive/package inventory** — *best fit to Tallow's actual product*
  - **Plain:** list and digest what is inside a foreign archive, without running anything.
  - **REA:** ZIP/APK/IPA/ASAR inventories, digests, plists, Apple bundle anatomy — static, no engine, no execution.
  - **Tallow today:** it *transfers* files and has BLAKE3 `hash`, `pack`/`unpack` (TWD), `sign`/`verify` with SLSA provenance and `fixity-sweep` — but **cannot inventory a foreign archive**. `zip::ZipArchive::new` appears exactly once, at `src/browser/download.rs:803`. Verified: no `inspect`/archive-contents command in `tallow --help`.
  - **Add:** `tallow inspect <archive>` — entry list, sizes, per-entry digests, format anatomy, bundled manifest/plist decode.
  - **Effort:** moderate. **Verdict: do it** — strongest feature fit; you would run it *before* sending or accepting an unknown archive.

- [ ] **H3. PTY-backed process capture** — *verified missing ability*
  - **Plain:** let recipes run **interactive** tools and capture the session faithfully. Today the keyboard input is blanked and only text output is collected, so anything that prompts, asks a password, draws a full-screen UI, or formats output for a terminal misbehaves or hangs.
  - **REA:** native PTY capture — terminal output, interactions, exit, filesystem observations, run-to-run comparison.
  - **Tallow today:** **provably no PTY.** No `portable_pty`, `openpty`, `forkpty` or `pty::` anywhere in `src/` or `crates/`; no pty dependency in any manifest. `crates/tallow-jobs/src/exec.rs:107-109` pins `stdin(Stdio::null())` with piped stdout/stderr.
  - **Add:** PTY-backed recipe execution, plus a run-comparison view.
  - **Effort:** moderate, self-contained in `tallow-jobs` — no language/parity exposure. **Verdict:** do it when recipes need interactive tools.

- [ ] **H4. HAR / saved-capture ingestion** — *missing ability*
  - **Plain:** read a browser network capture and turn it into a re-runnable extraction plan instead of a dead file. A HAR is the standard JSON record of every request and response a browser made; DevTools exports it.
  - **REA:** reads HAR and mitmproxy captures → requests, responses, exposed payloads, source locations.
  - **Tallow today:** `browser/fallback.rs:44` has `pub har: bool` as an **artifact-policy flag** (default `false`), and `stdlib/browser.rs:18` lists HAR capture as an explicit **non-claim**. No ingestion path exists.
  - **Add:** HAR import → replay into the request-plan/extraction path and the fixture harness.
  - **Effort:** small-to-moderate. **Verdict:** medium — do it if captures are already being taken.

- [ ] **H5. Provider registry for extraction backends** — *tidiness, no new capability*
  - **Plain:** Tallow currently picks how to read a page from a fixed list of four methods tried in order — structured data, microdata, OpenGraph, then plain CSS — each with a confidence score, all hardcoded. A registry makes that list pluggable, so a method is added by configuration instead of by editing the chain.
  - **REA:** pluggable analysis providers plus a generated tool catalog.
  - **Tallow today:** `src/browser/smart_extract.rs:167-384` is a hardcoded cascade (JSON-LD 0.95 → microdata 0.85 → OpenGraph 0.75 → CSS 0.55). The *generated catalog* half **already exists** — `scripts/generate_stdlib_surface_manifest.py`.
  - **Add:** a registry so a new backend (table extractor, LLM tier) registers rather than patching the cascade.
  - **Effort:** small-to-moderate. **Verdict:** defer unless adding a backend.

- [x] **H6. Dataset/artifact version-diff reporting — NO ACTION.** Compares two versions of the same thing (two releases, two snapshots) and reports what changed; REA does this for app binaries. Tallow already has `browser/schema_drift.rs`, `browser/ab_detector.rs`, `delta-sync` and `fixity-sweep` covering it. **Fold into H2; do not build separately** — the weakest of the six.

### Already present — do NOT port these

| REA feature | Tallow equivalent |
|---|---|
| Generated tool catalog | `scripts/generate_stdlib_surface_manifest.py` (reports `modules=43 aligned=20 open_gaps=13`) |
| Documented exit-status discipline | `fingerprint-audit` (0/2/64), `fixity-sweep` (0/2) |
| Snapshots / replay | Phase 7 accepted — local artifact/replay/metrics proof |
| Website observation | Tallow is **deeper** (`cdp.rs` 62K, `page.rs` 142K, `network.rs` 94K, `trace.rs`, `visual.rs`, `recording.rs`) |

### Not portable at all — the engines

Hopper, Ghidra, IDA/Hex-Rays, JEB, JADX, pwntools, WABT, Binwalk/Unblob, apktool, adb. This *is* REA's value, and none of it moves. IDA and JEB are licence-gated commercial tools REA explicitly grants no rights to.

**Necessity call:** **H1** and **H2** are the two worth doing — H1 smallest/highest value, H2 the strongest fit for a file-transfer tool. **H3** and **H4** are real missing abilities; do them if recipes need interactivity or captures are already being taken. **H5** is tidiness. **H6** is already covered (no action).
