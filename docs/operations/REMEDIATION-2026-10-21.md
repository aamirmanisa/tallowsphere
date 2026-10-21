# Remediation — 2026-10-21

Follow-up to [`AUDIT-2026-10-21.md`](AUDIT-2026-10-21.md). Every item below was fixed, and every claim is
backed by a command that was run on the tree that was then committed.

## 1. `tallow-reader` compiles again

`Page::from_cdp` became `async fn` in `400c13b` (2026-10-18). `crates/tallow-reader/src/engine.rs` still
called it synchronously, so `page` was a `Future` and four call sites were invalid.

Fix: `Page::from_cdp(…).await` (one line, `engine.rs:94-99`).

```
$ cargo check -p tallow-reader --locked          → rc=0
$ cargo test  -p tallow-reader --locked          → 7 passed; 0 failed
$ cargo check --workspace --all-targets --locked → rc=0, 0 errors (1m55s)
```

The workspace-wide check is the one that matters: it is the first time all 12 crates have compiled
together since 2026-10-18.

## 2. CI compiles the crates

`.github/workflows/ci.yml`, Check job:

```diff
-      - run: cargo check --locked --all-targets
+      - run: cargo check --locked --workspace --all-targets
```

Without `--workspace`, cargo selects the root package, so the gate passed while a member crate was
broken. YAML re-parsed after the edit (`yaml ok`).

## 3. `deals` stops returning success for work it did not do

| Function | Before | After |
|---|---|---|
| `generate_affiliate_link` | default provider `skimlinks` had no match arm → `_ => url.to_string()`; returned the input URL, rc 0 | provider defaults to the retailer; unknown provider is an error naming the supported set |
| `generate_affiliate_link` (wrappers) | literal `key=INSERT_KEY` (viglink), `id=XXXXX` (skimlinks retailers) | key/id read from `TALLOW_VIGLINK_KEY` / `TALLOW_SKIMLINKS_ID`, error when absent |
| `generate_affiliate_link` (tag) | silent default `tallowdeals-20` | third argument or `TALLOW_AFFILIATE_TAG`; error when neither is set |
| `browser_scrape` | `Ok{status:"contract_stub", live_execution:false}` | error naming `deals.stealth_scrape` / `tallow.browser` |
| `llm_classify` | `Ok{status:"contract_stub"}` | error naming `score_deal_quality` / `categorize_deal` |

This is what register row #68 already required of an "honest stub": a visible refusal, never a silent
fake success.

Tests — `src/stdlib/deals.rs::honesty_tests`:

```
affiliate_link_carries_the_configured_tag            ok
unknown_provider_is_refused_not_passed_through       ok
browser_scrape_refuses_and_names_the_alternative     ok
llm_classify_refuses_and_names_the_alternative       ok
```

`tests/deals_integration.rs` was updated to the real contract (pass a tag; assert the link carries it)
and its stub-shaped assertions were removed rather than left passing on a payload nobody produces:
**13 passed; 0 failed; 6 ignored.**

## 4. #137 — a declared type is enforced against its initialiser

`src/typeck.rs`: when a `let`/`var` carries an annotation, a literal initialiser is compared against it.

```
$ tallow check type137.tl     # before
check passed: 1 items, 0 warning(s)          rc=0
$ tallow check type137.tl     # after
error[E0117]: cannot bind a str literal to `int`: the annotation is the type, and no conversion is applied
  --> type137.tl:2:18
check failed: 1 error(s), 0 warning(s)        rc=1
```

Scope is deliberately narrow: only literal kinds are compared; numeric widening (`1` into `f64`),
optional slots (`str?`), privacy wrappers and every non-literal initialiser are untouched. There is no
inference of coercion rules here.

Tests: `typeck::tests::string_literal_bound_to_int_annotation_is_an_error`,
`typeck::tests::literal_bindings_that_fit_the_annotation_stay_clean`.

Full suite after the change: **9,145 passed; 0 failed; 33 ignored** (500.91 s).

## 5. Documentation truth

- `CHANGELOG.md`: v1.1.2 and v1.1.3 sections added from the commit record (they had shipped with none).
- `docs/release/versioning-policy.md`: corrected the false statement that `release.yml` is "not in this
  repository" — it is, and it built 1.1.3.
- 6 dead relative links in `docs/` repaired (the `E:/Nixe` development paths and the `tallowsphere/…`
  prefixes now point at the files that exist here). Link sweep: **102 checked, 0 dead**.
- `docs/operations/stub-register.md`: #137 marked fixed with its tests; a 2026-10-21 status line records
  this wave; the audit's misreading of #71 (it was closed on 2026-10-17 as "registered, not built") is
  corrected in place.

## 6. What is deliberately not "fixed"

These are registered and are not stubs; converting them into code would mean inventing a product
decision, not removing debt:

| Row | State | Why it stays |
|---|---|---|
| #130 | open | no musl artifact. A musl build needs the C++ toolchain and a decision about the browser backend; publishing an unverified target would be worse than the gap |
| #132 | open | `libtallow.a` is 522 MB (466 MB stripped). The fix is a link-contract change (cdylib or crate split), not a patch |
| #38 | by design | tallowsync relay/chat transport returns a loud `Err` and opens no socket; it is a product gate |
| #68 | by design | feature-gated backends refuse with the disabled feature's name |

## 7. Verification summary

| Command | Result |
|---|---|
| `cargo check --workspace --all-targets --locked` | rc=0, 0 errors |
| `cargo test --lib --locked -- --test-threads=2` | 9,145 passed / 0 failed / 33 ignored |
| `cargo test -p tallow-reader --locked` | 7 passed / 0 failed |
| `cargo test --test deals_integration --locked` | 13 passed / 0 failed / 6 ignored |
| doc link sweep (102 links) | 0 dead |
