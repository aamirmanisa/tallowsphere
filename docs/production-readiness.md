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

- [ ] **`Page.goto_antibot`** — the only remaining Page method with no lowering on either plane; surface now says
      `declared_not_implemented`. Decide: implement the egress-map relaunch
      contract, or delete the declaration and the surface entry.
      Done when: the method either works on both planes or does not exist.

- [ ] **`opts` solver map** — accepted by `page_resolve_antibot` signature, not
      consumed by the interp arm or (future) native arm.
      Done when: `{solver_key, solver_service}` changes behaviour, or the
      parameter is removed.

- [ ] **Result-returning FFI failures must be observable.** A native `Err` exits
      before any `print` runs: two sessions were lost to a silent `exit 1`.
      Done when: every FFI that can fail writes its error somewhere the program
      can see (stderr or the returned Result), pinned by a test.

## P0 — verification that is currently missing

- [ ] **Every `tests/*.rs` target runs in CI.** `cargo test --lib` cannot see
      them; the contract-cli job covers 10 targets of a much larger set.
      Done when: CI enumerates all integration targets and fails on a skip.

- [ ] **Array parity above N=1 for every array lowering** (`query_selector_all`,
      `extract_all_text`, `links`, `classes`, `drain_events`, `get_cookies`).
      One test (`browser_array_len`) covers `drain_events` only.
      Done when: each reports the true length and correct element contents at
      N=0, 1, 3.

- [ ] **Parity tests must assert non-trivial values.** N=1 probes hid every
      length bug; single-element fixtures hid ordering. Enforce a minimum of two
      elements wherever a collection is asserted.

## P1 — honesty of the machine-readable surface

- [ ] **Audit every capability status mechanically.** `goto_antibot` claimed
      `implemented_interp_routed` with zero arms; the claim was fixed by hand.
      Done when: a script greps each registered method against interp/codegen
      arms and fails CI on a mismatch.

- [ ] **`docs/` claims checked against code.** Two stdlib comments asserted an
      interpreter arm that never existed.
      Done when: doc-truth test covers comments naming `src/` symbols.

## P1 — known open items carried from earlier sessions

- [ ] **`http_result_model`** — 0/3 by decision: `http.batch` returns
      `Response`/raw `Err`s while tests assert a typed `BatchResponse`/
      `HttpError` model that exists in neither runtime nor `stdlib/http.tl`.
      Done when: model authored, or assertions relaxed with a recorded rationale.

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
