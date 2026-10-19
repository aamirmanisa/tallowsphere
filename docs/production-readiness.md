# Production-readiness checklist — Tallow (state: 2026-10-19, HEAD a3637bc)

Every item below is either verified against this tree or explicitly marked
UNVERIFIED. No item may be checked without a command whose output proves it.

## P0 — correctness gaps that produce wrong answers

- [x] **Native `resolve_antibot`** — DONE (eb6144e), enforced by `tests/browser_antibot_parity.rs`: root cause was field access on a non-variable receiver; both planes print identical output. Was blocked on one measured question: why
      `Page::navigate` stalls only when driven via `get_browser_runtime().block_on`
      from compiled code. Exonerated by run: re-navigation, FFI boundary,
      `NetworkAlmostIdle` (37.8 ms), array length at N=2.
      Next probe: Rust test that owns the browser but drives `navigate` through
      `block_on` on the browser runtime — no codegen needed.
      Done when: native and interp produce identical `resolved / final_status /
      attempts / steps[]` on the same page.

- [x] **`Page.goto_antibot`** — DECIDED: stays declared as a specification and must
      refuse loudly on both planes, enforced by `tests/browser_unlowered_gaps.rs`
      (native refusal names the method; interpreter refusal names it; body never runs).
      Rationale: egress is process-level, so the capability belongs to
      `BrowserPool.create`, not a page method.

- [x] **`opts` solver map** — DONE (9153cdd): consumed on the interpreter via the
      stdlib path (`CaptchaSolverConfig`, service defaults to 2captcha); the native
      plane refuses opts at build time instead of dropping them. Pinned by
      `tests/browser_antibot_opts.rs`.

- [ ] **Result-returning FFI failures must be observable.** A native `Err` exits
      before any `print` runs: two sessions were lost to a silent `exit 1`.
      Done when: every FFI that can fail writes its error somewhere the program
      can see (stderr or the returned Result), pinned by a test.

## P0 — verification that is currently missing

- [x] **Every `tests/*.rs` target is accounted for.** 79 targets: 43 now run in CI
      (30 added after a measured local run: 30 green, 9 red), 36 are listed in
      `ci-excluded-suites.txt` with a reason, 0 unaccounted. Enforced by
      `scripts/check_test_coverage.py` (negative control: a stray `tests/zz*.rs`
      exits 1). The 9 red suites are real defects, tracked below, not excluded
      policy.

- [ ] **Array parity at N=0/1/3 for every array lowering.** DONE for
      `query_selector_all` (`tests/browser_array_parity_n.rs`: 0/1/3 lengths correct,
      elements correct on both planes) and `drain_events` (N=2, `browser_array_len`).
      Still owed: `extract_all_text`, `links`, `classes`, `get_cookies`.

- [ ] **Parity tests must assert non-trivial values.** N=1 probes hid every
      length bug; single-element fixtures hid ordering. Enforce a minimum of two
      elements wherever a collection is asserted.

## P0 — red integration suites (measured 2026-10-19, not yet run by CI)

Each was run locally; counts are failures observed. They are listed in
`ci-excluded-suites.txt` so CI stays honest rather than red, but each one is a
defect, not a policy:

- [ ] `request_plan_cli` — 38 failed. Parked earlier as U-218: the verbs never
      existed on any ref. Decide: implement or delete the CLI surface.
- [ ] `deals_integration` — 6 failed.
- [ ] `generated_tl_parity` — 2 failed.
- [x] `pkg_archive` — FIXED: the archiver matched only `.nx`, the legacy
      extension, so every package archived `tallow.toml` and no code. Now `.tl`
      only, per operator direction. 4/4 pass, added to CI.
- [x] `pkg_cache` — FIXED: the test asserted a `cache/packages` layout that does
      not exist; implementation and its module docs both specify
      `~/.tallow/store/v1/<shard>/<hash>`. Test corrected. 6/6 pass, added to CI.
- [x] `stdlib_math_env` — FIXED: the test expected `NaN`, but the documented
      float→display contract is C `printf` semantics (`format_float_c`), which
      spells `nan`. Test corrected; 18/18, in CI.
- [x] `transfer_bwlimit` — FIXED: the test used a stale room code
      (`123-alpha-beta-gamma`); this build accepts only the 8-symbol mint. Now
      `K7M2QPHD`; 2/2, in CI.
- [x] `crawler_parity` — FIXED: `let c = Crawler.from_links(...)` did not record the
      struct type, so `c.strategy` was refused as ambiguous (the field exists on
      Crawler and PaginationInfo). Added the result-kind mapping, the receiver
      kind, and initializer-driven type tracking. 3/3, in CI.
- [ ] `interp_codegen_parity` — 1 failed.

## P1 — honesty of the machine-readable surface

- [ ] **Audit every capability status mechanically.** `goto_antibot` claimed
      `implemented_interp_routed` with zero arms; the claim was fixed by hand.
      Done when: a script greps each registered method against interp/codegen
      arms and fails CI on a mismatch.

- [ ] **`docs/` claims checked against code.** Two stdlib comments asserted an
      interpreter arm that never existed.
      Done when: doc-truth test covers comments naming `src/` symbols.

## P1 — known open items carried from earlier sessions

- [x] **`http_result_model`** — DONE, and the entry was stale: measured
      3 passed / 0 failed on 2026-10-19. The typed `BatchResponse` / `HttpError`
      model it asserts exists in `stdlib/http.tl` and is produced by
      `src/stdlib/http.rs::batch_item`.

- [ ] **`request_plan_cli`** — parked: the verbs never existed on any ref.
      Done when: implemented or removed.

- [ ] **Canonical sync direction** — the product leads the engine on the v9
      handshake and `wire/capabilities.rs`. Port UP into Tallowsphere first,
      verify room-id conformance, then sync. Never sync downward first.

- [ ] **`scripts/sync-canonical-crates.sh` must stay non-destructive** — no
      `rsync --delete`; product-only files would be deleted.

## P1 — release hygiene

- [ ] **Author identity on the published root commit** is a dead domain
      (`f6185df`). Re-author before any public release.
- [ ] **Nothing pushed** — no GitHub push is authorized for any Tallow artifact;
      publication decision is the operator's, explicitly.
- [ ] **Two sendtallow files under a standing no-touch directive** — do not
      modify without a new instruction.

## P2 — quality

- [ ] `cargo fmt` over the workspace hangs on this box; format touched files only,
      or fix the hang (unverified cause).
- [ ] The gold linker is deprecated with known warnings — decide or document.
- [ ] Remaining browser methods declared in `stdlib/browser.tl` but with no
      native arm: the four became three, then two (`goto_antibot`,
      `resolve_antibot`); re-run the census before claiming zero.

## Definition of 100%

1. Every `Page` method either works identically on both planes (proven by a test
   asserting values, not just exit codes) or fails loudly by name and is listed
   as unimplemented — with no third state.
2. The capability registry is generated from, or checked against, the code.
3. CI runs every test target and fails on discoveries, not on silence.
4. No claim in `docs/` or in code comments describes behaviour that does not
   exist.
