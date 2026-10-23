# Next steps — Tallow, after the 2026-10-22/23 surface pass

State at the time of writing: `tallowsphere` main `690c2dd`, `tallow-language`
main `d198a49`. Full lib suite 9,154 passed / 0 failed / 33 ignored. All 85
stdlib modules pass `tallow check`. 41 of 41 browser declarations execute.

Boxes are `[ ]` open, `[x]` done. Each open item names its acceptance test —
"it works" is not acceptance.

## 0. Finish the CI run that is in flight

- [ ] `CI` on `690c2dd` is green (it was red on `e77b325`: Windows `find_in_path`
      E0425, and the counts gate at 1118). Both are fixed in `690c2dd`.
      **Acceptance:** every job on that SHA reports success, including
      `Test (Windows)` and `Contract and CLI suites (integration)`.
- [ ] `Tallow Production CI Gates` on the same SHA is green.
- [ ] Confirm no orphaned pending runs from the queue backlog.

## 1. Function behaviour that is still interpreter-only

- [ ] **Native lowering for the new math functions.** `math.asin/acos/atan/
      atan2/cbrt/abs_i/min_i/max_i/clamp_i` execute in the interpreter; the
      native backend prints "no lowering for method … failing loudly so the
      interpreter runs it" and falls back. Correct, not native.
      **Acceptance:** `interp_codegen_parity` covers each; no fallback notice on
      a native build.
- [ ] **Native lowering for the browser `page_*` surface.** All 41 run in the
      interpreter through the current-page registry. The codegen `("Page", …)`
      table knows only the older method set.
      **Acceptance:** a native build of a page_* program does not print the
      fallback notice; parity test alongside `browser_codegen_integration`.
- [ ] **Agent cancellation granularity.** Cancel is observed at the next
      function call in the child; a task that calls nothing cannot be
      interrupted. Decide whether that is the contract (document it) or whether
      the evaluator loop needs its own check.
      **Acceptance:** either a documented limitation plus a test that proves the
      boundary, or a scheduler-level check with a test that cancels a tight loop
      with no calls.

## 2. Test coverage for what was just built

- [ ] **Browser functions have no automated tests.** They were verified with
      runnable `.tl` probes against BBC, a local fixture, and a live WordPress;
      none of that is in `cargo test`. A regression today would ship silently.
      **Acceptance:** `tests/browser_page_helpers.rs` that skips (not fails) when
      no Chrome is present, covering: extract_all_text/attrs, dom snapshot,
      structured data, text_redacted, block_non_essential, wait_for_stable,
      detect_pagination, cookie consent, the 10 delegations, the 3 waiters,
      the 8 callback registrations, and context creation.
- [ ] **WordPress flows need a fixture, not a third-party site.** `wp_login` was
      proven against a local `wordpress:6` + `mariadb:11`, reachable only with
      `TALLOW_ALLOW_DIRECT=1`.
      **Acceptance:** a scripted fixture (compose file + `wp core install`) and
      an `#[ignore]`-by-default test that runs when the opt-in is set.
- [ ] **Parser regression tests** for the four additions — record types,
      `fn()` with no return, contextual keywords, generic aliases — including a
      negative: a keyword must still be a keyword inside an expression.
      **Acceptance:** unit tests in `src/parser.rs` for each, positive and
      negative.

## 3. Correctness debt found but not fixed

- [ ] **`Page.evaluate` double-encodes string results.** `p.evaluate("typeof
      window.tallowAdd")` prints `Ok(""function"")` — the JSON string is quoted
      twice on the way back.
      **Acceptance:** returns `"function"`; a test pins it.
- [ ] **Warnings left in the corpus.** `tallow check` passes all 85 with
      warnings: `type 'any' is not defined` (transfer.tl), `type 'Self' is not
      defined` (browser.tl and others), `Float` in algos. Either the checker
      learns these types or the manifest stops using them.
      **Acceptance:** `check` clean of W0100 across `stdlib/`, or each remaining
      warning justified in a comment with a reason.
- [ ] **`--require-native` refuses programs the interpreter accepts.** Every new
      interpreter-only function widens that gap; decide which side is correct
      per function and record it.

## 4. The published count — operator decision

- [x] **Decided: publish 1,124.** The generator reports 1,124: the six extra are
      `timeseries.tl`'s `method … on TimeSeries` declarations, which no counter
      ever read. Options: publish 1,124 (accurate today), or teach
      `tools/generate.py` to count the `method … on` form and keep 1,118 for
      comparability with earlier releases.
      **Done:** `spec/generated.json`, `tests/language_surface.rs` and this
      document all say 1,124, with the reason inline.

## 5. Release

- [ ] Bump to 1.1.5 (or 1.2.0 given the grammar additions), changelog covering
      the browser surface, agent handles, grammar, and the corpus repair.
- [ ] Tag and run the release workflow; verify all five platform assets are
      published and that `sha256sum -c` passes on the public URLs.
- [ ] Re-run `tools/generate.py` in `tallow-language` against the released SHA
      so the provenance header names the tag, not a mid-pass commit.

## 6. Documentation

- [ ] `docs/operations/stdlib-surface-audit-2026-10-22.md` still says 18
      unimplemented; update to 0 and point at the grammar section.
- [ ] Add an ADR for the contextual-keyword decision (why `type` is a field name
      in one position and a declaration in another) — the spec states the rule,
      the ADR should state why it was chosen over renaming published fields.

## Status at close — 2026-10-23

Done and verified: browser declarations (41, live-proven), agent handle
cancellation, grammar (record types, `fn()`, contextual keywords, generic
aliases, type-scoped names), stdlib manifest 85/85, `Page.evaluate` typing,
checker type names, live-page tests in CI, WordPress fixture + ignored test,
math native lowering, count published as 1,124, ADR 0001, audit doc, and the
1.2.0 release (five platforms, checksums verified, published).

Partly done: **native lowering for the module-level `browser.page_*` helpers.**
Seven now lower in compiled code — `page_content`, `page_text_redacted`,
`page_capture_dom_snapshot`, `page_set_content`, `page_block_non_essential`,
`page_wait_for_stable`, `page_handle_cookie_consent` — through a native
`CURRENT_PAGE` thread-local set by `tallow_browser_new_page` and cleared by
`tallow_page_close`. A null current page branches to `tallow_missing_page_abort`,
which prints the interpreter's sentence and aborts, so a compiled program cannot
quietly read an empty string where the interpreter raises. Verified by a parity
test that runs the same program through both engines and compares stdout
(5/5 browser tests, full lib suite 9,159 passed).

Struct-returning helpers now lower too (seven more arms), and the interpreter was
aligned to the declarations first so both engines return the same shapes —
`declared-vs-returned-2026-10-23.md` records that fix.

Not done: **the array-returning helpers, and native typing for match-arm
bindings.** They run in
the interpreter and the native backend refuses them by name ("no lowering for
method …"), so a `--require-native` build that calls one fails loudly rather
than silently diverging. Closing it needs a native current-page registry set by
`tallow_browser_new_page`, one FFI function per helper, and codegen arms with
parity tests — the same shape as `structured_data_extract`, ×41. That is a
release of its own, not an edit to bolt on.

### Native lowering: the concrete inventory (surveyed, not built)

`emit_stdlib_module_call` has no `"browser"` arm, so every module-level
`browser.page_*` call reaches "call to unknown function" and the build fails
loudly (correct behaviour, but it means the interpreter is the only engine that
runs them). The FFI below already exists — the gap is a current-page handle and
the module arms:

| lowering target | existing FFI |
| --- | --- |
| `page_content` | `tallow_page_content(ptr) -> ptr` |
| `page_dom_snapshot` | `tallow_page_dom_snapshot(ptr) -> ptr` |
| `page_text_redacted` | `tallow_page_text_redacted(ptr) -> ptr` |
| `page_set_content` | `tallow_page_set_content(ptr, ptr) -> i32` |
| `page_add_script_tag` | `tallow_page_add_script_tag(ptr, ptr) -> ptr` |
| `page_add_style_tag` | `tallow_page_add_style_tag(ptr, ptr) -> ptr` |
| `page_add_init_script` | `tallow_page_add_init_script(ptr, ptr) -> ptr` |
| `page_throttle_cpu` | `tallow_page_throttle_cpu(ptr, f64) -> i32` |
| `page_wait_for_url` / `page_wait_for_function` | `tallow_page_wait_for_url` / `_function` |
| `page_emulate_media` | `tallow_page_emulate_media` |
| `page_extract_all_text` | `tallow_page_extract_all_text_array(ptr, ptr)` |

What is missing is the receiver. Native code has no current-page handle — the
interpreter keeps one in a thread-local registry. The work is therefore:

1. `CURRENT_PAGE` thread-local in `src/runtime/browser.rs`, set by
   `tallow_browser_new_page`, cleared by `tallow_page_close`, exposed as
   `tallow_current_page()`.
2. A null-page guard that maps to the interpreter's error rather than an empty
   string — otherwise the two engines diverge exactly where the old `goto`
   bug did (success where the interpreter errors).
3. `"browser" => self.emit_stdlib_browser(method, args)` with the arms above.
4. Parity tests: same program, `tallow run` vs `tallow run --interpret`, outputs
   compared; plus a `--require-native` build that must now succeed.

`page_extract_all_text` was implemented, measured, and then REMOVED again: the
FFI returns a native array whose slots hold C string pointers, and the
`let`-tracking that records the `StringArray` kind keys on a (receiver-kind,
method) pair that a module-level call does not have. Native printed `\u0002`
where the interpreter printed `["A", "B"]`.
The arm is out until the tracking learns the module-level shape — a lowered arm
that emits the wrong KIND still passes `--require-native`, which is exactly the
silent divergence this backend exists to refuse.

Rough size for the rest: each arm is mechanical, but the array-returning and
struct-returning ones each need a tracking or layout addition first.
