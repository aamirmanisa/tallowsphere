# Verification

Revisions under test: **`7364aa59`** (the publication head — `951218fd` in the development tree) for the six
suites, the structural gates and the publish audit; **`9d3b1f5`** for the `read_file` contract, the
ignore-reason pass and the egress fix; and **`bb31b3f`** (the current head) for the lib-suite result — every
section names the revision it was measured at. Every figure below was produced by the command shown. Nothing
here is inferred from a different revision, and no number is carried over from an earlier run.

## Suites

| Suite | Command | Result |
|---|---|---|
| Native binding FFI | `cargo test --lib runtime::structured_data_ffi` | **7 passed / 0 failed** |
| `StructuredData.extract` parity | `cargo test --test structured_data_parity` | **2 passed / 0 failed** |
| `Crawler.from_sitemap` parity | `cargo test --test crawler_parity` | **3 passed / 0 failed** |
| Codegen | `cargo test --lib codegen` | **621 passed / 0 failed** (2 ignored) |
| CLI | `cargo test --lib cli::` | **108 passed / 0 failed** |
| Locator | `cargo test -p tallow-locator` | **20 passed / 0 failed** |

**761 passing, 0 failing — across the six suites named above.**

That total is the sum of those six runs and nothing else (7+2+3+621+108+20). The **full lib suite is a
wider run**: `cargo test -p tallow --lib -- --test-threads=2` reports **9,028 tests: 9,007 passed,
0 failed, 21 ignored** (521 s) at `bb31b3f`. The interp suite the six above omit is inside that total, so
this is the first green reading of the whole suite this file can carry.

It was not green earlier the same day. At `9d3b1f5` the same command reported **8,996 passed / 11 failed /
21 ignored**, all eleven in **one group with one cause**: the `stdlib::transfer_net::tests::{chat,group_chat}_*`
fixtures passed a human-readable room code (`'roundtrip-test'`, `'right-code'`, `'group-code-123'`, …) to a
join contract that accepts the 8-symbol v4 mint only (operator directive 2026-10-12), and were refused
fail-closed — `unsupported code '…': not a valid room code … this build accepts the 8-symbol mint only`. The
runtime was right and the fixtures were stale. `bb31b3f` flips them, test-side only inside `mod tests`, to
take their code from the same `room::code::generate_passcode` the runtime mints with, so a fixture cannot
drift from the contract again; the roundtrip fixture additionally had to stop re-minting per message, because
the identical literal had been the only thing making two sessions derive the same key.

The 28 this section previously counted were dispositioned in four passes on 2026-10-15:

| pass | count | what it was |
|---|---|---|
| `444bfc9` | 9 | tests demanding an environment the suite does not have. Eight now carry an explicit `#[ignore]` naming it (browser session: screenshot ×3, accessibility ×2, AntiDetect ×2; and `test_otel_exporter_otlp`, which needs a collector); `test_otel_exporter_prometheus` runs green once its precondition is met |
| `89f5471` | 5 | `self_hosting_interpreted`, `variable_shadowing_in_for_loop`, `test_qkd_session_deterministic`, `test_pqc_migration_audit`, `test_provenance_read_file_carries_fileread_origin` |
| `80a8e7b` | 1 | `browser::cadence::tests::jitter_stays_within_the_window_and_varies` |
| working tree | 2 | `test_mpc_session_create_contribute_compute`, `test_phase57_manifest_url_roundtrip` |

Two further fixes predate that baseline: `complex_enum_with_match` (a 7th significant digit from a
6-digit printer) and `keypair_from_pem` (an `ml-kem-768` that `from_pem` has no branch to return).

**Correction to this file's earlier reading of the six.** They were recorded as "their `.tl` source no
longer parses", panicking at the shared helper's `Parser::parse(tokens).unwrap()`. **They do parse.**
Each panicked at `interp.run(&program).unwrap()` on a fail-closed *runtime* error: `AntiDetect.fingerprint`
returns `Err("no browser connected")` and the test then reads a field on that `Err`, which is what
surfaces as the misleading `unknown method: .color_depth() on Err`; `OtelExporter.export()` refuses
without `OTEL_EXPORTER_OTLP_ENDPOINT`. The code was right and the tests demanded an environment the
suite lacks — the basis on which `444bfc9` fixed them, not a parser change.

### The `read_file` contract

`stdlib/fs.tl` declares `fn read_file(path: String) -> String` and states that a read FAILURE is a loud
runtime error. The interpreter's builtin did neither: it returned `Ok(Value::Ok(Provenance(..)))` on
success and `Ok(Value::Err(..))` on failure. Three consequences, all measured:

- the `Ok` wrapper never reached `.provenance()`, so the lineage the function exists to attach was
  discarded by the first thing that touched it;
- a missing file surfaced as a *value*, so `if let Ok(c) = read_file(p)` — the shape the declaration
  invited — silently never fired;
- `examples/self_host.tl`, already written against the bare contract, made the self-hosting compiler
  emit a stub `.ll` that calls an undefined `@tallow.main` and omits every user function, while
  reporting `Output written to …`. It emits `@tallow.add` now, and `self_hosting_interpreted` passes on
  the IR contents rather than on the output file merely existing.

Fixed in `89f5471`; the stale note in `src/stdlib/fs.rs` that recorded the contract as still open is
corrected in the same commit.

### What is ignored, and why

21 tests, up from the 13 this file previously counted (8 were added by `444bfc9`):

- **7** require a live browser session — `test_accessibility_audit_{get_tree,run}`,
  `test_anti_detect_fingerprint`, `test_anti_detect_webrtc_leak_check`,
  `test_screenshot_{capture_element,compare,save_baseline}`. The calls refuse with `no browser connected`.
- **1** requires a reachable collector — `test_otel_exporter_otlp`.
- **1** requires a live Tor daemon on `127.0.0.1:19051` — `stdlib::net::tests::test_tor_live_newnym_when_daemon_reachable`.
- **2** are register #77 — `codegen::tests::codegen_closure_capture_{uses_env_struct,multiple_vars}`,
  where the `emit_call` fail-loud guard refuses until native env threading across calls lands. These are
  the only ignored tests that are a genuine implementation gap rather than an environment requirement.
- **4** state their reason as a comment rather than a string — `power_function` and
  `recursive_sum_nested_depth` (Windows stack overflow on deep recursion), `http_module_stubs` and
  `http_get_real_request` (require network; `http.get` makes real requests via ureq).
- **6** are `stdlib::osint::tests::{asn_intel_lookup_live, ct_log_enumeration_live, dns_brute_live,
  domain_intel_whois_live, email_intel_breach_check_live, techstack_detect_live}`. All six call
  implementations that exist, and each now names its own requirement: `ASNIntel.lookup` and
  `DomainIntel.whois` query whois on `:43`, `enumerate_ct_logs` queries crt.sh, `enumerate_dns_brute`
  sweeps through the OS resolver, `TechStack.detect` fetches the target through the egress agent, and
  the breach check queries the HIBP k-anonymity range API and Cloudflare DoH. **These six carried a
  bare `#[ignore]` with no reason at all until this pass** — itself a defect against the register's
  convention that a registration be visible, and the reason every other entry in this list has one.
  The two whois lookups are additionally no longer a way around the egress contract: `whois_query`
  used a bare `TcpStream::connect`, so it went direct unconditionally while every other egress in the
  tree rides `runtime::fetch::egress_proxy_url` ("no silent fallback"). It now routes through the same
  `Socks5Connector` as `net.tor_connect`, with the hostname sent to the proxy so DNS resolves at the
  exit, and reaches direct only under `TALLOW_ALLOW_DIRECT`. `enumerate_dns_brute` was NOT the
  same class of bypass, contrary to how this file first recorded it: it calls
  `runtime::dns_guard::check(53, false)` before its first probe, so a plain-`:53` sweep through the
  OS resolver is refused unless `TALLOW_ALLOW_DIRECT` opts in — and that opt-in emits an audited
  `DirectEgress` event ("a leak-by-design opt-in must never be silent"). The guard is wired in eight
  places across `osint`, `net`, `transfer` and the browser zone. What is genuinely absent is the DoH
  path its own comment names as "the sanctioned path" — the sweep refuses, but has no DoH
  implementation to fall back on, so the feature is gated rather than implemented.

Four tests in `interp::tests` that once ran forever (`continue_in_for`, `continue_in_for_loop`,
`for_with_continue`, `range_for_loop_with_continue`) were fixed the same day: the range arm of
`for`-in advanced its counter *after* the match on the block result, so `continue` skipped the
increment. The suite completes for the first time as a result — 544 s, nothing over 60 s.

## Structural gates

- **The published tree is byte-identical to the development tree.** `git ls-tree -r HEAD` here diffed
  against `git ls-tree -r 951218fd -- <kept paths>` in the development repository: **1,855 entries each,
  empty diff**, blob SHAs included. Publication moved content; it did not alter it.
- **The published series is complete and correct.** Applying `patches/` to the published base `03bc941b`
  under `git am` exits 0 and reproduces `7364aa59` with an **empty diff**. Its statistics (46 files,
  +6,635 / −233) equal the development range's, which is independent evidence of the same fact.
- **The package graph is closed.** All twelve workspace members live under `crates/`; no manifest references
  a path outside the kept set. The published tree is self-contained.
- **A clean checkout compiles.** A fresh worktree of the development revision at this content, `cargo check`:
  **RC 0, zero `error[E…]` codes.**
- **Both drift gates the CI carries are green in this tree**, re-measured at `9d3b1f5`:
  `python3 scripts/sbom-gen.py --check scripts/sbom.snapshot.json` → **rc 0**; and
  `python3 scripts/crypto-inventory.py --check scripts/crypto-inventory.json` → **rc 0** after `800ca3d`
  regenerated the artifact (`31e27a1` had added crypto-shaped tokens in `src/stdlib/crypto.rs` after the
  snapshot was last written, so the gate was red at `9d3b1f5` until then: 2,124 → 2,134 occurrences).

## The egress gate

This workstream also closed a pre-existing defect, and the guard proves it in both directions.

- **Before:** `cargo test --lib no_bare_ureq` → `FAILED`, naming
  `["crates/tallow-locator/src/watchers.rs: ureq::get("]` — "unproxied runtime/interpreter HTTP calls found
  — they would egress from the box IP".
- **After:** the same filter → **2 passed / 0 failed**, and no bare-ureq shape remains in the crate.
- **End-to-end, on the built binary:** with no proxy configured the live scan refuses **before any request**
  (exit 3, `egress refused: TALLOW_LOCATOR_PROXY is not set — the locator will not egress from the box IP`,
  once per provider); with the box's Tor SOCKS proxy named it proceeds *past* the egress gate and stops at
  the missing provider token. The refusal is therefore the egress gate, not a general failure.

## The live extraction path

`Crawler.from_sitemap` fetches, so its happy path cannot be exercised offline; it was verified live, against
a reference read **outside** Tallow.

| Step | Observation |
|---|---|
| reference, `torcurl`, first `<loc>` | `https://www.sitemaps.org/` |
| interpreter leg | rc 0 — seed `https://www.sitemaps.org/`, strategy `sitemap`, 84 entries |
| native leg, `--require-native` (no fallback allowed) | rc 0 — byte-identical output |
| comparison | **identical**, and the seed matches the independently-read value |

The egress plane was proven before the run: the host exit IP differed from the box's own, with `IsTor` true.
Two operational details worth keeping: the CLI binary must be **rebuilt** first (`cargo check` and
`cargo test` do not produce one — a stale binary reports a bogus "native build unavailable" and indicts a
binding that is fine), and the live fixture stays out of the repository, because a suite that needs the
network and Tor up fails for reasons unrelated to the code.

## Credentials and the publish audit

- **No key material in the published tree.** Checked by filename (`*.pem`, `.env`, `id_*`), by key shape
  (`BEGIN … PRIVATE KEY`, `ghp_`, `sk-`, `AKIA`), and by assigned-secret pattern. Two hits, both benign and
  verified individually: a doc comment naming the PKCS#8 header it requires (already redacted in-source),
  and AWS's *documented example* access key in a test fixture.
- **The one fixture named for a secret holds synthetic PII only:** `ada@example.com` on a reserved domain, a
  `.invalid` host, and `203.0.113.7` (RFC 5737 documentation range).
- **Tier credential custody:** vault entry `tallow-llm-api-key`, environment fallback `TALLOW_LLM_API_KEY`,
  refusal naming **both** sources when neither is present; a blank value from either source is not a
  credential. No key in a `.tl` literal and none in process `argv` (established by a snapshot-and-search
  probe, not by a live pipe — a search pattern that can match its own command line reports false leaks).
- **`.cargo/config.toml`** carries build tuning only: no registry credential, crates.io sparse protocol, and
  the `+aes` / `aes_armv8` rustflags that prevent a 9× silent slowdown on aarch64.

## The published tree

This repository is a filtered history of the development repository, not a snapshot: `git filter-repo` kept
`src/`, `stdlib/`, `crates/`, `tests/`, `docs/`, `examples/`, `benches/`, `vendor/`, `scripts/fault_suite.sh`,
the manifests and the top-level docs, and dropped `artifacts/` (12,083 files), the oversized blobs, and the
nested repositories. Filters rewrite history, so every revision is remapped; the pins this repository quotes
are its own, and `MANIFEST.md` carries the mapping and the regeneration command.

Filtering has three separate closure classes, each with its own failure signature. Two were found by running
`cargo check` **inside the published tree** — the only gate that catches them, since the development tree is
green for all three:

| class | how it fails when a path is dropped |
|---|---|
| workspace members and `path =` dependencies | cannot resolve the graph |
| target paths (`[[bench]]`, `[[bin]]`, `[[example]]`, `[[test]]`, `[lib]`) | *cannot parse its own manifest* |
| build-time file references (`include_str!`/`include_bytes!`) | one crate fails, after the graph compiled |

Both gaps are recorded in `MANIFEST.md` rather than hidden: `benches/` (the root declares
`[[bench]] reliability_bench`), and the two `include_str!` targets (`vendor/axe-core/axe.min.js` from
`src/browser/accessibility.rs`, `scripts/fault_suite.sh` from `src/fault_injection.rs`).

Measured on this history, at this revision:

| check | result |
|---|---|
| `cargo check` inside the published tree (clean target dir) | **rc 0**, zero errors, zero `error[E…]` codes |
| filtered head tree vs development head, at the kept paths | **byte-identical**, all 1,866 entries |
| the 27-patch series applied to the published base | reproduces the published head exactly |
| history | 736 commits, no gitlinks, no blob over 100 MB, no remotes |

## Known gaps

Stated because a verification record that only lists successes is a sales document.

1. **The interpreter coerces where the compiled leg refuses.** `v.as_string()` accepts any value, so a
   wrong-typed call runs, exits 0 and returns a plausible answer; `tallow check` does not enforce declared
   parameter types, so nothing catches it first. Two arms were made strict in this work (the ones bound);
   the class is far wider and is recorded as a language-level question rather than patched piecemeal.
2. **The tier's live spend measurement** (model calls, tokens, milliseconds per page) needs a live engine and
   a credential; it completes as *disabled with a reason*, which is the intended end state without them.
3. **The `// native` claim for the compiled path** is exact as of this revision — every declared method on
   the extraction surface lowers, and the bound-template fallback no longer hides a missing arm.
4. **Two paths under the dropped `artifacts/` tree are referenced from kept code**: `src/drill.rs` reads
   `artifacts/drills`, and `tests/browser_fallback_service.rs` expects
   `artifacts/phase4/browser-fallback-service-local`. The library and the binary build regardless — these are
   a drill command's data directory and one test's fixture — but that drill path and that test will not find
   their inputs in this repository. A runtime-read audit found no other kept code depending on a dropped
   path; the remaining literal paths it surfaced are temp-file names the code creates itself, plus a
   deliberate traversal-refusal fixture (`../../../etc/passwd`).
5. **~~The three platform `test-*` jobs cannot pass as carried~~ — RESOLVED at `bb31b3f`.** At `9d3b1f5` the
   suite failed on the eleven stale room-code fixtures above (8,996 passed / 11 failed), which would have made
   `test-linux`, `test-windows` and `test-macos` red on the first push. They are flipped — test-side only,
   inside `mod tests` of `src/stdlib/transfer_net.rs`, under an operator decision for that boundary file — and
   the suite now reads 9,007 passed / 0 failed / 21 ignored. What remains absent is by decision, not by
   failure: `fmt`, `vet` and `claims-ledger` are omitted jobs (see `MANIFEST.md`), not red ones.
6. **The Python acceptance surface needed seventeen carried inputs, and is 12-of-15 green.** Fifteen files under
   `tests/*.py` (94 test cases) drive `scripts/`. The filter kept **one** file from that directory (`fault_suite.sh`),
   so ten of those files failed with `can't open file …/scripts/<name>` — a missing-input failure, not a stub one.
   Seventeen scripts and one workflow were carried byte-identically (sha256 in the commits; `MANIFEST.md`
   § "Build inputs upstream never committed" records each and the test that names it), together with
   `configs/tallow/` (the contract example `schemas/tallow/contract-index.json` names, and the 96-file retailer
   registry `src/stdlib/deals.rs` resolves at runtime). Result, measured after the last commit: **12 files green,
   all 7 failures confined to the 3 red files that item 7 describes.** Note the carried `ci.yml` is cargo-only and
   runs none of this surface, so these tests are proof available on demand rather than a gate — that gap is
   deliberate (the same reason `fmt`, `vet` and `claims-ledger` are omitted) and should be revisited before the
   first push.
7. **Three Python test files are red for reasons carrying cannot fix, two of them in the development tree as
   well.** (a) `tests/test_docs_truth_maintenance.py` asserts `docs/TALLOW-CAPABILITIES.md` contains
   "Delta-Sync Flags (24)"; the document says 23 at line 243 — in the development tree too, at both HEAD and at
   the published revision `951218fd`. The test is the stale side. (b) `tests/test_phase2_stdlib_surface_manifest.py`
   requires `stdlib/http.tl` to declare an `HttpRequest` struct and the runtime-dispatched functions
   `get/post/put/delete/batch/server/listen` at the top level; the file is identical here and upstream (49 lines,
   `native fn batch` plus `get`/`post`/`listen` as methods), so this assertion fails identically upstream — a
   standard that outran the stdlib module in both trees. (c) `tests/test_tl_script_inventory.py` requires
   `artifacts/tl-script-inventory.json` to equal this tree's `.tl` set while hard-coding entries for
   `kroger_mega_scrape.tl` and `personal_database/ashraf_ali_business_inquiry/…legacy-http-batch.tl`; the upstream
   inventory has 474 entries, 342 naming paths this publication excludes by design. It is a workspace-scope test,
   like the release-line documents.
8. **~~`open_graph` was a serialized string in AOT and a Map when interpreted~~ — RESOLVED at `daf5164`.** The
   field's declared kind was `String`, so `.len` in AOT read the serialized buffer's byte length while the
   interpreter returned the entry count, and indexing took the array path and read the buffer's first key slot.
   The premise recorded in the binding's header ("codegen has no Map value at all") was wrong: `MapLit` lowers to
   a tagged flat buffer and `emit_map_len`/`emit_map_get`/`emit_map_keys`/`emit_map_values` read it. What was
   missing was routing — both map-receiver sites required a bare variable, so a Map-typed *field* reached neither.
   The field now declares `Map<String,String>`, the native returns that layout, a guard test asserts the invariant
   over `stdlib/*.tl` (20 other Map-typed fields are latent, on structs with no registered layout), and
   `tests/structured_data_parity.rs` pins the map in the reference block. Verified by running the fixture both
   ways: interpreter and `--require-native` legs each rc 0, byte-identical to the reference, `A_og_len` 1,
   `A_og_title` `Hello`, `B_og_len` 0, `D_og_len` 1, `D_og_title` `Hello`.
