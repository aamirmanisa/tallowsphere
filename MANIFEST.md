# Manifest

## Publication mapping

This tree was filtered from the private development repository, so publication renumbered every commit.
The two revisions this product is pinned to:

| Role | Development revision | Published revision |
|---|---|---|
| base — before the extraction-engine series | `2d30a0bb` | `03bc941b215b` |
| head — the series applied | `951218fd` | `7364aa59850d` |

The patch series in `patches/` was regenerated **inside the published repository**, so its `From` lines name
published commits. It applies to `03bc941b215b` and reproduces `7364aa59850d`.

## The series

27 commits, **46 files, +6635 / −233** — identical statistics to the same range in the development
tree, which is its own check that filtering changed no content.

| File | Added | Deleted |
|---|---|---|
| `Cargo.toml` | +8 | -0 |
| `crates/tallow-crypto/Cargo.toml` | +1 | -1 |
| `crates/tallow-crypto/src/rng.rs` | +19 | -0 |
| `crates/tallow-locator/src/cli.rs` | +18 | -2 |
| `crates/tallow-locator/src/watchers.rs` | +70 | -6 |
| `docs/TALLOW-CAPABILITIES.md` | +8 | -1 |
| `docs/decisions/REA-2026-10-14.md` | +65 | -0 |
| `docs/extraction-engine/CHECKLIST.md` | +251 | -0 |
| `docs/extraction-engine/EXTRACTION-ENGINE-SPEC.md` | +237 | -0 |
| `docs/extraction-engine/REA-CLI-RUNBOOK.md` | +103 | -0 |
| `docs/extraction-engine/REA-INTEGRATION-ASSESSMENT.md` | +148 | -0 |
| `docs/extraction-engine/RECONCILIATION-2026-10-12.md` | +111 | -0 |
| `docs/extraction-engine/TALLOW-SCRAPER-AUDIT-2026-10-14.md` | +251 | -0 |
| `docs/plans/2026-10-14-tallow-scraper-execution-plan.md` | +728 | -0 |
| `docs/plans/2026-10-14-tallow-scraper-execution-report.md` | +173 | -0 |
| `src/browser/har_import.rs` | +293 | -0 |
| `src/browser/llm_extract.rs` | +898 | -17 |
| `src/browser/llm_transfer.rs` | +233 | -0 |
| `src/browser/mod.rs` | +127 | -122 |
| `src/browser/network.rs` | +53 | -17 |
| `src/browser/provenance.rs` | +63 | -0 |
| `src/browser/smart_extract.rs` | +93 | -53 |
| `src/cli/extract_cmd.rs` | +709 | -0 |
| `src/cli/fingerprint_audit_cmd.rs` | +8 | -1 |
| `src/cli/mod.rs` | +3 | -0 |
| `src/cli/plan_cmd.rs` | +270 | -0 |
| `src/cli/schema_cmd.rs` | +156 | -0 |
| `src/codegen.rs` | +177 | -2 |
| `src/interp.rs` | +39 | -6 |
| `src/main.rs` | +48 | -0 |
| `src/run_evidence.rs` | +51 | -0 |
| `src/runtime/crawler_ffi.rs` | +131 | -0 |
| `src/runtime/html_ffi.rs` | +6 | -1 |
| `src/runtime/mod.rs` | +1 | -0 |
| `src/runtime/structured_data_ffi.rs` | +337 | -0 |
| `src/stdlib/provenance.rs` | +146 | -4 |
| `stdlib/browser.tl` | +8 | -0 |
| `tests/crawler_parity.rs` | +190 | -0 |
| `tests/fixtures/har/capture_with_secret.har` | +49 | -0 |
| `tests/fixtures/har/minimal.har` | +40 | -0 |
| `tests/parity/parity_programs/17_structured_data.tl` | +42 | -0 |
| `tests/parity/parity_programs/18_structured_data_refusal.tl` | +9 | -0 |
| `tests/parity/parity_programs/19_crawler_from_links.tl` | +27 | -0 |
| `tests/parity/parity_programs/20_crawler_from_links_refusal.tl` | +9 | -0 |
| `tests/parity/parity_programs/21_crawler_from_sitemap_refusal.tl` | +10 | -0 |
| `tests/structured_data_parity.rs` | +218 | -0 |

## What was filtered

| Kept | Dropped |
|---|---|
| `src/`, `stdlib/`, `crates/`, `tests/`, `docs/`, `examples/`, `benches/`, `vendor/`, `.cargo/` | `artifacts/` (12,083 files), `.playwright-mcp/`, `.planning/`, `.scratch/`, `.hermes/`, `.claude/`, `apps/`, `deploy/`, `editors/`, `fuzz/`, `nixreader/`, `omnix/`, `projects/`, `research/`, `self-host/`, `smbdealhunter-scraper/`, `supply-chain/`, `tallow-search/` |
| `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml`, `deny.toml`, `.gitignore` | loose data dumps and one-off scripts at the root (grocery JSON/SQL, `fix_*.js`, `out.txt`, `sync_nas.bat`, `test_*.tl`) |
| `README.md` (kept as `README.tallow-upstream.md`), `LICENSE`, `NOTICE`, `AGENTS.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `SECURITY.md`, `TALLOW_SPEC.md`, `TALLOW_UPGRADE_SPEC.md` | nested repositories (`Tallow/`, `hermes-agent/`, `luma/`, `firecrawl-self-hosted/`, `vendor/open-design/`, `heretic/`) — never tracked, and excluded deliberately |

Before → after: **2,582 MB → 94 MB**, **15,922 → 1,866 files** at the
head revision, **1,792 → 736 commits**. Six tracked 101 MB test binaries were dropped — they exceed GitHub's
100 MB object limit by themselves and are the reason a plain push was never possible.

Two of those trees are kept only in part, for the single file in each that the source pulls in at build time:
`vendor/axe-core/` (2 files, referenced by `src/browser/accessibility.rs`) and `scripts/fault_suite.sh`
(referenced by `src/fault_injection.rs`). Nothing else from either tree is here.

## Corrections during publication

The first filter omitted `benches/`, and the published tree then could not parse its own manifest:

```
error: Cargo.toml: can't find `reliability_bench` bench at `benches/reliability_bench.rs`
error: could not parse `tallow` (manifest) due to 1 previous error
```

The root manifest declares `[[bench]] reliability_bench`, and `tallow-crypto` declares `[[bench]]
crypto_benchmarks`; a workspace's *target paths* are part of its package graph, not just its members and
dependencies. The history was re-filtered from a fresh clone with `benches/` included — which is why the
published SHAs here differ from a first draft of this repository, and why the base revision is one that
parses and builds. Caught by running `cargo check` **inside the published tree**; a green check on the
development tree says nothing about it.

A second filter gap surfaced the same way, one class over: `src/browser/accessibility.rs` does
`include_str!` on `vendor/axe-core/axe.min.js`, and `src/fault_injection.rs` on `scripts/fault_suite.sh` —
build-time file references that no manifest mentions, resolved relative to the including file. That run failed
with `couldn't read <path>: No such file or directory` *after* the dependency graph had compiled, which reads
like one bad crate rather than a filter gap. Both are now in the kept set. Three closure classes, three
different failure signatures, one gate: `cargo check` inside the published tree.

## Regenerating the filter

```bash
git clone --no-local --bare <development-repo> base.git
cd base.git
git filter-repo --force \
  --path src --path stdlib --path crates --path tests --path docs --path examples \\
  --path benches --path vendor --path scripts/fault_suite.sh --path .cargo \\
  --path Cargo.toml --path Cargo.lock --path build.rs --path rust-toolchain.toml --path deny.toml \
  --path .gitignore --path LICENSE --path NOTICE --path README.md --path AGENTS.md \
  --path CONTRIBUTING.md --path CHANGELOG.md --path SECURITY.md \
  --path TALLOW_SPEC.md --path TALLOW_UPGRADE_SPEC.md
```

All twelve workspace members live under `crates/`, every target path and every build-time file reference
resolves inside the kept set, and `cargo check` passes against a clean target directory. The filtered tree is
self-contained — a claim this repository earned by failing it twice, not by inspection.

## Build inputs upstream never committed

`schemas/` (14 files) is present in this repository and is **untracked in the development tree**, where
`git status` reports `?? schemas/`. Two CLI test fixtures `include_str!` a schema from it
(`src/cli/extract_cmd.rs`, `src/cli/schema_cmd.rs`), so the lib **test** target cannot compile without it —
and `cargo check`, the gate used while preparing this publication, never compiles `cfg(test)` code and
therefore never saw it. The files are carried here verbatim as an addition rather than filtered content: a
product tree that cannot build its own tests is not self-standing. Upstream's remedy is `git add schemas/`.

Two more instances of the same class, both found because a kept test would not run without them:

- `scripts/` — five files carried verbatim, each named by a test in this tree:
  `run_tallow_request_plan.py` (`tests/test_phase2_request_plan_runner.py`, 23 tests),
  `validate_extraction_rows.py` (the four tests in `tests/test_phase5_extraction_rows.py`, plus the runner's
  extraction step, which imports it), `build_tallow_request_plan.py` and `validate_tallow_contracts.py`
  (`tests/test_generated_public_source_package.py`), and `compliance_gate.py`
  (`tests/test_error_taxonomy.py` imports it). Upstream **tracks** all five; the filter dropped `scripts/`
  except `fault_suite.sh`, so nothing here had to be committed upstream first — they were simply missing.
- `configs/tallow/` — `targets.v2.example.json` is named by `schemas/tallow/contract-index.json`
  (entry `target_manifest_v2_example`), which the contract validator resolves and the generated-package
  test requires; the three sibling files (`README.md`, `targets.example.json`, `targets.schema.json`) are
  named by `docs/architecture/tallow-phase2-contracts.md`. The retailer registry
  `configs/tallow/retailers/*.json` (96 files) is resolved at runtime by `src/stdlib/deals.rs`
  (`configs/tallow/retailers/{retailer}.json`, four call sites) and documented by `stdlib/deals.tl`.
  Upstream **does not track this directory** — `git status` reports `?? configs/tallow/` — so these are the
  development tree's working state, carried because the contract index and the `deals` surface both name
  them. Upstream's remedy is `git add configs/tallow/`.

Every carried file is byte-identical to its development-tree counterpart (sha256 in the commit that
carried it); none was edited on the way in.

A second wave, same method — the remaining red files in `tests/*.py` each named one of these:

- `scripts/` (10 more, all tracked upstream): `benchmark_phase10_fixture.py` and
  `compare_tallow_firecrawl_offline.py` (`tests/test_phase10_benchmark_protocol.py`),
  `generate_stdlib_surface_manifest.py` (`tests/test_phase2_stdlib_surface_manifest.py`),
  `queue_scheduler.py` (`tests/test_phase6_queue_scheduler.py`), `build_domain_dashboard.py`,
  `extract_run_metrics.py`, `package_artifact_bundle.py` and `replay_failed_requests.py`
  (`tests/test_phase7_artifacts_replay.py`), `build_research_package.py`
  (`tests/test_research_package_init.py`), `tallow_production_ci_gates.py`
  (`tests/test_tallow_production_ci_gates.py`).
- `scripts/apollo_turbo_max_parallel_graphql_json.tl` — a `.tl` probe **untracked upstream** like
  `configs/tallow/`, named by `tests/test_tl_script_inventory.py` as an `unsafe/deprecated` entry.

Two files in `tests/*.py` are red for reasons the filter did not cause, and carrying cannot fix them:

- `tests/test_docs_truth_maintenance.py` asserts `docs/TALLOW-CAPABILITIES.md` contains
  "Delta-Sync Flags (24)"; the document says 23 — **in the development tree as well** (line 243, both at
  HEAD and at the published revision `951218fd`). The test, not the document, is the stale side.
- `tests/test_tl_script_inventory.py` requires `artifacts/tl-script-inventory.json` to list **exactly** this
  tree's non-ignored `.tl` files, and hard-codes five entries including `kroger_mega_scrape.tl` and
  `personal_database/ashraf_ali_business_inquiry/…legacy-http-batch.tl`. The upstream inventory has 474
  entries, 342 of which name paths this publication excludes by design. It is a workspace-scope test.

## CI carried, and what was left behind

The development tree's `ci.yml` has 15 jobs. `.github/workflows/ci.yml` here carries 12 of them and omits
three, because a gate that cannot pass is worse than a gate left behind — a permanently red check gets
ignored. `sbom-drift` and `cbom-drift` **are** carried, together with their inputs and their regenerated
artifacts, and both were re-measured green in this tree at `9d3b1f5` (`scripts/sbom-gen.py --check` → rc 0;
`scripts/crypto-inventory.py --check` → rc 0 after `800ca3d` regenerated the inventory `31e27a1` had staled).
The three omissions, each with what adopting it would need:

| Not carried | Why |
|---|---|
| `vet` | inputs carried (`supply-chain/{config,audits.toml,imports.lock}`) but the ledger is empty — `audits.toml` is 35 bytes — so `cargo vet --locked` has nothing to certify against. Unproven here; not wired. |
| `claims-ledger` | inputs carried and the script runs: rc 1 with **13 rows / 23 hard findings** across 65 entries (1 shipped, 43 partial, 21 target-only) plus 48 warnings. Red in the development tree too — the job accepts rc 0\|2 and fails on rc=1 — so wiring it would import a failing check. Worth fixing where the claims live, not by weakening the gate. |
| `fmt` | the tree is not `cargo-fmt` clean: `cargo fmt --all -- --check` reports **7,902 files, 121,519 diff lines** (import-ordering style, `use std::sync::{Arc, mpsc}` against `{mpsc, Arc}`), i.e. rustfmt has never been run across this workspace. A repo-wide style decision, not a defect to fix in passing. |

The three platform `test-*` jobs are green at this revision (`bb31b3f`): the eleven stale room-code fixtures
that made them red at `9d3b1f5` now take their code from the runtime's own mint — test-side only, inside
`mod tests` of `src/stdlib/transfer_net.rs`. The history is in `verification/VERIFICATION.md` known gap 5.

Workflow-level `RUSTFLAGS: "-D warnings"` is deliberately **not** set, and that is a decision rather than an
omission. This tree carries a pre-existing warning baseline (159 in the lib test target alone, including the
Rust 2024 `unsafe_op_in_unsafe_fn` lint across `src/runtime/{env,html}_ffi.rs`); with `-D warnings` every
cargo job would fail on warnings that predate this repository, which measures nothing. The development tree's
own `parity` job neutralizes the same variable for the same documented reason. Making warnings blocking is a
separate work item, not a side effect of publishing.

## Adopting the source of truth: the admission crate

This tree was a snapshot of development `951218fd`. Two later development commits change
`crates/tallow-admission/`, and one of them fixes a defect this repository had already fixed its own
way — so the crate had diverged and two variants of the same security fix were in circulation:

| | variant |
|---|---|
| this repository (`AeadError::StaleCtr`) | `open` authenticated the frame first, then required a strictly increasing counter — deliberately unable to distinguish a stale frame from a tampered one |
| development tree (`AeadError::Replay`, canonical) | `open` refuses a non-advancing counter **before** decryption — cheaper to reject, and distinguishable from a tampered frame |

Both are defensible; shipping both is not. `src/aead.rs`, `tests/verify_v.rs`, `src/io.rs`,
`src/server.rs`, `src/lib.rs` and the crate README are now taken verbatim from development
`f0439314`, so the published crate **is** the source-of-truth crate: `AeadError::Replay`, and no
`StaleCtr` reference anywhere. The sibling commit also lands the pre-auth deadline and connection
cap, so this is the crate's current hardening rather than a one-file port.

Verified by hash: both trees agree byte-for-byte on `aead.rs` and `verify_v.rs`.

The trade-off is recorded rather than resolved silently: refusing replays before decryption leaks a
distinction between an authentic captured frame and garbage, plus a timing difference, where the
`StaleCtr` form leaked neither. The canonical form is canonical because it lives in the development
tree and is fully tested — not because it is the more paranoid of the two.

## Evidence paths the documents cite

254 of this repository's 594 documents cite paths under `artifacts/…` — 1,510 distinct paths — and `artifacts/`
is not here: it is 12,083 files and 2,359 MB of run evidence in the development tree, dropped deliberately
(it also carries 204 files with cookie/session dumps, 10 with authorization headers and one with a private-key
block). Those citations resolve **only** in the development tree. They are left as written rather than
rewritten, because the documents are the record of work that produced those artifacts; read a citation there
and not here.

## Tags

Six tags came through the filter, all ancestors of this revision:

| Tag | What it marks |
|---|---|
| `v0.2`, `v0.3`, `v1.0`, `v1.0.0` | the language/runtime's own releases |
| `v1.1`, `v1.1.1` | the cross-domain release gate's releases |

The gate is a separate published deliverable, and its records live in its own repository, so those two tags
describe a line this repository does not publish. They are kept because they are truthful about the tree's
history — the gate's code is in this tree at those revisions — and dropped if this repository should carry
only its own releases.

## Deliberate omissions — publication pass 2026-10-15

This tree is filtered from the private development tree. Beyond the series mapping above, the
publication pass removed or neutralised the following, and a reader comparing the two trees should
expect them to be absent here:

| omitted | why |
|---|---|
| Engagement and client material — `docs/reports/`, `docs/research/`, `docs/prompts/`, `docs/reference-assets/`, `docs/superpowers/`, and the client-specific examples | Real third parties: surveys, floorplans, onboarding screenshots, investigation prompts |
| `docs/TALLOW_SCOPE_FILE_FOLDER_INDEX.txt`, `docs/ops/disk-reclaim-*` | Internal workspace map and box operations |
| Credential-attack modules — `src/stdlib/{azure_phish,azure_sql,gama_api}.rs`, `src/bin/azure_bypass.rs`, their `.tl` declarations and registrations | Third-party credential material and account-guessing capability. They remain canonical in the private tree |
| Client-named modules — `stdlib/{modisoft,modisoft_recon,modisoft_insights}.tl` | Named after a client engagement |
| Real retailer domains in `src/browser/` profiles | Replaced with documentation domains; the per-site tuning is not published |

Identifiers removed by substitution rather than omission, because the surrounding text is product
documentation: the operator's server address and hostname, home paths, and a personal domain in
patch provenance headers (now the project domain).

Environment, not content: the browser system's per-retailer profiles survive as mechanism with
neutral site data; the four vendored canonical crates are pinned by `crates/CANONICAL-SYNC.sha256`,
which verifies clean and is gated in CI.

### Second pass — retailer targets and the removed-module references (2026-10-15)

The first pass scoped its strip to `src/`, `tests/`, `examples/` and `stdlib/`. A whole-tree scan
afterwards found the same class outside those paths, now handled:

| omitted or neutralised | why |
|---|---|
| `configs/tallow/retailers/` — 96 per-retailer configs, 94 carrying real domains | A customer/target list, not configuration the product needs to ship. One generic specimen is retained (`example.json`, domain `shop-a.example`) so the loader in `src/stdlib/deals.rs` and its documentation still work |
| Retailer domains elsewhere in the tree (25 files: mockups, the research doc, integration tests, `deals.rs`, the browser's built-in retailer table) | Replaced with `shop-NN.example`. **Domain forms only** — a bare name would be unusable, since e.g. `target` is an ordinary English word that appears throughout the compiler |

Kept deliberately, and recorded here so it is a decision rather than an oversight:

- **`patches/` may name modules this tree does not contain.** The series is preserved history; a patch
  that touched a now-omitted module still describes what was done at the time. Redacting it would
  falsify the record.
- **`docs/operations/stub-register.md` and `docs/extraction-engine/TALLOW-SCRAPER-AUDIT-2026-10-14.md`**
  describe audits performed when those modules existed. The omissions table above is the mapping
  between what they discuss and what is present here.
- **Bare retailer names remain in design mockups.** The mockups illustrate the product's UI; retailer
  *domains* are neutralised, brand words are not.

### Third pass — the host surface and the engagement examples (2026-10-15)

The first two passes were scoped: pass one to the code directories, pass two to a dictionary built
from the retailer config names. A whole-tree hostname census (623 distinct non-benign hosts) then
showed what those scopes had missed. It found a class, not a handful of files.

| omitted or neutralised | what it was |
|---|---|
| Content-site hosts in 20 source files (146 occurrences) — `presets.rs`, `corroboration.rs`, `auth.rs` and neighbours | A per-site hardening preset table keyed by real publisher/retailer domains. Same treatment as the retailer profiles: the tuning survives, the site identity does not. Tests keyed to the same domains moved with it |
| `crates/tallow-net/tests/live_relay_tls.rs` | Hardcoded the downstream product's live relay host. Now a neutral default, overridable by environment |
| `src/stdlib/beehiiv.rs`, `src/stdlib/jwt.rs` | A module documenting itself as built from reconnaissance of a named third party, whose owner's name also appeared in a password wordlist. Endpoints now generic; the wordlist entry is gone |
| 19 engagement examples, in four groups: one client's eleven-revision roster downloader, one signup-flow automation in three revisions, five single-target scrapers under two brand names, and five Rust examples driving named sites | Automation written against named third parties, including signup/login flows and proxy scanning. Engine-identifying filenames are part of what is omitted, so the groups are described, not listed. Kept in the private tree |
| `tests/fixtures/*.modisoft` | A fixture carrying the excluded client's name |
| `scripts/apollo_turbo_max_parallel_graphql_json.tl` | A target script for a third-party vendor's GraphQL endpoint |
| A named client in two `docs/opsec/` documents, and the client's name in a filename | Neutralised; the documents' security content is intact |
| Vendor endpoints in `configs/tallow/` | `vendor.example`; the request-plan machinery and its schema are untouched |
| Dead references to the removed examples in `tests/interp_codegen_parity.rs` and `tests/test_tl_script_inventory.py` | The tests iterate the filesystem, so deletions alone are safe — but a shipped test naming the engagements is not neutral |

Deliberately kept, and why:

- **Tracker/analytics hosts** in the browser's plugin blocklists (`google-analytics`, `doubleclick`,
  `hotjar`, `connect.facebook.net`): blocking them *is* the feature.
- **API endpoints the code genuinely calls** — the LLM engine, a market-data feed, a newsletter
  platform, a captcha solver, temporary-mail providers, IP lookups: naming a public API is not
  naming a target.
- **Synthetic test hosts** (`a.com`, `evil.com`, `redirect.com`, `*.example`): test scaffolding.
- **`crates/tallow-reader` and the `substack`/`market` modules**: their site constants are the
  modules' own data sources, not a curated target list.
- **`docs/codex/smbdealhunter-scraper-spec.md`**: removed on the operator's instruction (2026-10-16). It
  documented the operator's own product rather than anything this tree provides, and would have
  published a spec for an unreleased product alongside the engine.
