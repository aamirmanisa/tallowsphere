# NEVER Release Checklist — Tallow/Nixe collection path (N1–N10)

> **Scope (2026-10-15).** The enforcement named below (`scripts/never_check.sh`) and its companion
> `scripts/kev_gate.sh` belong to the Tallow **language/workspace** release line (`~/Nixe`); neither is
> in this tree. Measured: `never_check.sh` names 19 paths this repository does not carry
> (`apps/tallow-copy/src-tauri/build.rs`, `apps/tallowsync/src-tauri/build.rs`, `artifacts/…`), and
> `kev_gate.sh` needs `scripts/kev/kev.snapshot.json`. The invariant list itself — N1–N10, and the
> refusal to ship the classes they name — is doctrine this repository inherits and does not restate.
> See `MANIFEST.md` § "CI carried, and what was left behind".

> status: published 2026-09-11 (task A1.4.3, batch 02 — AGT-18). Canonical invariant list:
> `artifacts/tallow_intel_uplift_2026-09-11/impl/A1.4.1_never_list.md` (survey date 2026-09-11).
> Mechanically enforced by `scripts/never_check.sh`. Companion (complementary) gate:
> `docs/operations/release-bootstrap-checklist.md` (Phase-1 bootstrap exit gates).
> **Updated 2026-09-11 (A1.4.2 closure):** closure tests P1–P7 + the opsec-corpus consumer all
> landed; N2/N3/N5/N6/N7/N8 flipped PARTIAL → EXISTING TEST; **no open waivers**.
> **Updated 2026-09-13 (R-13/#159):** §2b — Essential-Eight-style CI maturity gates (enforced
> subset + honest self-rating; patch-SLA leg backed by `scripts/kev_gate.sh`, row #77).

**A release is not cut until every row below is checked.** This is the mandatory gate for the NEVER
invariants in the privacy-first collection path — egress, storage, retries, stealth, honesty. Any
new feature touching those areas must name which invariant it touches and which check below
enforces it. Rows that are still `PARTIAL` carry a waiver obligation (§Waiver rule) — they are
*known* gaps, never zero-risk.

## 0 · How to run the gate (exact commands)

From the repo root:

```bash
cd ~/Nixe
bash scripts/never_check.sh                # static guards + cargo test slices (the full gate)
bash scripts/never_check.sh --no-cargo     # static source-guards only (no build; fast)
bash scripts/never_check.sh --live-egress  # ALSO run the live egress check (network + Tor; REQUIRED before a public release)
bash scripts/never_check.sh --selftest     # verdict-logic proof on temp fixtures (no repo side effects)
```

CI: `.github/workflows/never-invariants.yml` runs the full gate on push/PR.
Operator probe: `tallow never-check` (static guards only; exit 1 on any hard fail).

Exit codes: `0` all hard checks pass · `1` one or more hard FAIL · `2` usage/root error.
`[WARN]`, `[SKIP]` and `[PEND]` lines do not affect the exit code; `[FAIL]` always does.
The script is read-only on the source tree (grep/read only); its cargo slices write build
artifacts under `target/` only, as any cargo invocation does.

## 1 · Gate table (statuses mirror A1.4.1)

| # | NEVER invariant | Status today | Primary proof |
|---|---|---|---|
| N1 | No direct egress by default (Tor fail-closed; `TALLOW_ALLOW_DIRECT` is the only opt-out) | EXISTING TEST | `cargo test --lib egress_http` + live `bash tests/egress/check_egress.sh` arm |
| N2 | No bare/unproxied HTTP client outside the shared egress client | EXISTING TEST (repo-wide) | `cargo test --lib no_bare_ureq_calls` (stdlib guard + P7 runtime/interp/crates guard) |
| N3 | No silent proxy fallback on malformed proxy config | EXISTING TEST | refusal tests in `fetch.rs`/`egress_http.rs` + interpreter pin (P1/P2) |
| N4 | No unredacted secrets/private values in output or logs | EXISTING TEST | `cargo test --lib privacy` + `--lib print_private_type_errors` + `--lib print_secret_type_errors` + `--lib redact` |
| N5 | No unbounded retry loop | EXISTING TEST | `cargo test --lib with_retry` + `--lib retry` (incl. P3 hard-cap + saturation) |
| N6 | No PII retention beyond its purpose | EXISTING TEST | `cargo test --lib purpose` + `--lib retention` + `--lib pii` (incl. P4 serve-gate/purge) |
| N7 | No `socks5://` (local DNS) — `socks5h://` only | EXISTING TEST | `cargo test --lib egress_http` upgrade assert + P5 `socks5_scheme_is_upgraded_to_remote_dns` |
| N8 | No stealth-off by default in the browser runtime | EXISTING TEST | `cargo test --lib stealth` + P6 `stealth_default_on_and_optout_explicit` |
| N9 | No browser child inheriting a direct route (incl. IPv6) | EXISTING TEST (on-demand, live) | `bash tests/egress/check_egress.sh` (CDP arms + dual-stack arm) — run via `--live-egress`; **not waivable** |
| N10 | No fake success / silent wrong answer | EXISTING TEST (honesty sweep) | `cargo test --test sec1_honesty_sweep` — **not waivable** |

## 2 · Per-invariant gate detail

Each row lists the exact checks (all are implemented in `scripts/never_check.sh` unless marked
"manual"). Slice notes: cargo filters are substrings of the full test path, so
`cargo test --lib egress_http` runs every test whose module path or name contains it.

### N1 — Tor fail-closed; `TALLOW_ALLOW_DIRECT` is the only opt-out
- `cargo test --lib egress_http` — `tor_is_the_default_and_direct_needs_an_explicit_opt_in`,
  `agent_is_proxy_aware_when_env_set`.
- Live (manual step, scripted as `--live-egress`): `bash tests/egress/check_egress.sh` — with **no
  env at all** compiled `fetch()` must differ from the box IP; the `TALLOW_ALLOW_DIRECT=1` control
  proves the opt-out really goes direct.
- Source guards: `TOR_SOCKS_URL: &str = "socks5h://127.0.0.1:9050"`; `TALLOW_ALLOW_DIRECT` parsed
  in `src/runtime/fetch.rs`.

### N2 — No bare/unproxied HTTP client outside the shared egress client
- `cargo test --lib no_bare_ureq_calls` — `no_bare_ureq_calls_outside_the_egress_client`
  (scans `src/stdlib/*.rs`; `stdlib/http.rs` is exempt because it applies the egress proxy itself)
  + `no_bare_ureq_calls_in_the_runtime_tree` (P7: `src/runtime/`, `src/interp.rs`, `crates/`,
  whole-line comments skipped).
- Static mirror in the gate script: `src/stdlib` scan for `ureq::get|post|put|delete|head|patch(`
  and `ureq::Agent::config_builder()` without `.proxy(` (http.rs exempt).
- P7 closure (2026-09-11): repo-wide guard landed with a minimal, documented allowlist — one
  pre-existing `interp.rs` call tracked as debt (route through `egress_http` in a follow-up, then
  delete the entry). No waiver required.

### N3 — No silent proxy fallback on malformed proxy config  *(closed 2026-09-11)*
- Both native FFI paths hard-refuse (A1.4.2 fix, batch 02/03): `src/runtime/fetch.rs` and
  `src/runtime/egress_http.rs` return a clean error instead of warn-then-proceed-direct; the gate
  pins `will egress UNPROXIED` as a hard not-found check and greps the refusal message.
- Interpreter path refuses: `cargo test --lib interpreter_fetch_refuses_on_bad_proxy` (P2) +
  `grep 'refusing to run unproxied'` source pin.
- Closure tests landed: **P1** `malformed_proxy_url_is_a_hard_refusal` /
  `every_malformed_shape_refuses` (race-free, no env mutation), **P2**
  `interpreter_fetch_refuses_on_bad_proxy`.

### N4 — No unredacted secrets/private values in output or logs
- `cargo test --lib privacy` (privacy_pass + interp auto-redact + browser privacy slices),
  `cargo test --lib print_private_type_errors`, `--lib print_secret_type_errors`, `--lib redact`.
- Source guards: E0200/E0201 messages in `src/typeck.rs`; `secret_cannot_be_printed_at_all` in
  `src/privacy_pass.rs`.
- Known non-invariant residual (from A1.4.1): FFI error strings may echo URLs; cheap check
  `fetch_errors_do_not_echo_credentials` when `fetch.rs` is next touched.

### N5 — No unbounded retry loop
- `cargo test --lib with_retry` (`src/agent_reasoning.rs`), `cargo test --lib retry`
  (`src/browser/retry.rs`, crawl queue/rate-limiter).
- Source guards: `attempt.min(62)` bound in `with_retry`; `max_retries: 3` default in
  `src/browser/retry.rs`.
- P3 closure (2026-09-11): `retry_attempts_are_hard_capped` + `linear_backoff_saturates` —
  `BackoffStrategy::Linear/Fixed` use `saturating_mul`; user-supplied `max_retries` clamps to
  `MAX_RETRIES_HARD_CAP` **inside the retry consumer** (`retry_with_backoff_governed`).

### N6 — No PII retention beyond its stated purpose
- `cargo test --lib purpose` (`dp_pass` E0506 positives/negatives), `--lib retention`
  (`RetentionRegistry` timestamps/expiry/export), `--lib pii` (scan/redact per PII type).
- Source guards: `E0506` in `src/dp_pass.rs`; `RetentionRegistry` + `expires_at` in
  `src/browser/privacy.rs`.
- P4 closure (2026-09-11): `expired_retention_blocks_serving` + `may_serve`/`serve_gate` in
  `src/browser/privacy.rs`; the purge gate wired into the A1.2.x stores —
  `RawStore::purge_expired`/`get_if_live` and `DerivedStore::purge_expired_derived`
  (callback-style; stores stay decoupled from `browser::privacy`).

### N7 — No `socks5://` (local DNS); `socks5h://` only
- `cargo test --lib egress_http` — `tor_is_the_default_and_direct_needs_an_explicit_opt_in`
  asserts the socks5→socks5h upgrade through the shared client.
- Source guards: `strip_prefix("socks5://")` upgrade present in `src/runtime/fetch.rs` and
  `src/stdlib/http.rs`.
- The gate script additionally lists every `socks5://` string literal in `src/` for review
  (informational — the upgrade sites are the hard checks).
- P5 closure (2026-09-11): `socks5_scheme_is_upgraded_to_remote_dns` in `src/runtime/fetch.rs`.

### N8 — Stealth on by default in the browser runtime
- `cargo test --lib stealth` (`stealth_pass` E0400 tests + runtime stealth tests).
- Source guards: `!stealth_disabled()` in the runtime default (`src/runtime/browser.rs`);
  `fn stealth_disabled`; `E0400` in `src/stealth_pass.rs`.
- P6 closure (2026-09-11): `stealth_default_on_and_optout_explicit` — junk `TALLOW_NO_STEALTH`
  values must NOT disable stealth; only explicit `1/true/yes` (case/trim tolerant) does.

### N9 — No browser child inheriting a direct route (incl. IPv6/dual-stack)  *(live only)*
- `bash tests/egress/check_egress.sh` — CDP arms (no env; `TALLOW_TOR=1`) and the dual-stack/IPv6
  arm on `tests/egress/fetch_ip64.tl`. Deliberately excluded from `cargo test` (network + live Tor);
  the release gate script runs it only with `--live-egress` — **but a public release MUST run it**.
- Source guards: browser launch wires `crate::runtime::fetch::egress_proxy_url()`
  (`src/runtime/browser.rs`); `src/browser/process.rs` clears inherited `*_proxy` env before launch
  (`env_remove`) and normalizes the proxy scheme.

### N10 — No fake success / silent wrong answer (honesty sweep)
- `cargo test --test sec1_honesty_sweep` (offline, end-to-end through the public stdlib surface).
- Presence guards: `tests/sec1_honesty_sweep.rs` and its refusal-by-default case
  `s1_brute_login_off_by_default_and_capped_when_opted_in`.
- Policy: this invariant is as much a review norm as a check — new collection code must state which
  N-rows it touches (see §4).

## 2b · E8 — Essential-Eight-style CI maturity gates (R-13 · #159)

An ASD Essential Eight **analog** for this repo (source: `phase2-agents/agent-07-intel-agencies.md`
R-13; row #77 supplies the patch-SLA mechanism via `scripts/kev_gate.sh`). E8 doctrine is a
**small enforced control set** with **maturity levels** and an **honest self-rating** — so this
section is an enforced subset (hard checks, always in the exit code) plus explicitly labeled
rating lines for what is *not yet* met. Static and offline by design; all logic in
`scripts/never_check.sh` §E8.

| Control | Enforced checks (hard) | Rating (honest) |
|---|---|---|
| E8-1 patch applications (patch SLA) | `scripts/kev_gate.sh` present and green — offline KEV/EOL snapshot leg + `cargo audit --no-fetch` RustSec leg; `deny.toml` `vulnerability = "deny"`; CI `cargo-deny` job wired (T-113); `cargo check --locked` in CI | **ML1 met**; ML2 open until the KEV snapshot is refreshed from live feeds (operator, out-of-band — `scripts/kev/kev.snapshot.json` §`_refresh_how`) |
| E8-2 restrict admin privileges | never-gate workflow declares `permissions:` (`contents: read`); no workflow anywhere grants `write-all` | ML2 pending: 7 sibling-project workflows (measured 2026-09-13) still lack an explicit `permissions:` block — WARN by name, not a root-Tallow gate |
| E8-3 artifact signing | `install.sh` pins the Ed25519 release key + fingerprint and verifies fail-closed; `install.ps1` pins the same key; `release.yml` signs with `TALLOW_SIGN_KEY`; `src/signing.rs::sign_package` present | Sigstore remains the second signature arm per `release.yml` |
| E8-4 build-script / macro execution control | every `build.rs` under `src/ crates/ tests/ examples/ stdlib/ apps/` is on the in-script allowlist (2 pinned Tauri desktop builds); `deny.toml` `wildcards = "deny"`; macros execute from the pinned `Cargo.lock` only | a new `build.rs` in scope is a hard FAIL until reviewed and allowlisted with justification |

Run: part of the default gate (`bash scripts/never_check.sh`). Verdict-logic proof:
`bash scripts/never_check.sh --selftest` (9 fixture cases; temp dirs only, no repo side effects).

Non-claims: this is a **static proxy** — it does not observe wall-clock patching; the KEV leg
blocks only on matches within the operator-refreshed local snapshot, and the RustSec leg
(`cargo audit --no-fetch`) is the offline signal that actually matches a Rust dependency tree.
Current measured posture: `research/tallow-v1/exec/R-08-E-77-kev-patch-sla-report.md`.

## 3 · Waiver rule (known PARTIALs and how to waive honestly)

A waiver never deletes a row; it records that a *known* gap is accepted for this release.

- **Format** (record in the release notes, linking this checklist): invariant id (`N#`, closure
  test `P#`), owner, reason, concrete follow-up, and a review/expiry date. Same discipline as
  `docs/operations/release-bootstrap-checklist.md` §Waiver Rules.
- **Open PARTIALs:** none as of 2026-09-11 — the A1.4.2 closure landed P1–P7 + the opsec-corpus
  consumer. For history, the flip list was: N3 → P1/P2 · N2 → P7 · N5 → P3 · N6 → P4 · N7 → P5 ·
  N8 → P6. New gaps enter as `GAP` in A1.4.1 and follow the same mechanism.
- **Not waivable for a public release:** running the live `check_egress.sh` (a FAIL there means
  "EGRESS LEAK — do not treat compiled scraping as anonymous") and a green `sec1_honesty_sweep`
  (N10). If those fail, the release does not ship — no waiver.
- Waivers expire at the next release; re-verify every open waiver by re-running this gate.
- "Silent additions are not allowed; silent removals are." (A1.4.1)

## 4 · Adding / changing invariants

1. A new NEVER invariant starts as `GAP` in the canonical list; before release it either gets a
   closure test (wired into `scripts/never_check.sh`) or an explicit waiver (§3).
2. New features touching egress, storage, retries, stealth, or honesty must name which N-rows they
   touch and which check enforces them (A1.4.1 §How this list is used).
3. Removing an invariant requires deleting its row here *and* its checks in the script in the same
   change — silent removals are allowed, silent additions are not.

## 5 · Check inventory — live vs pending (2026-09-11, post-closure)

**Live in `scripts/never_check.sh` today:** cargo slices `egress_http`, `no_bare_ureq_calls`,
`privacy`, `print_private_type_errors`, `print_secret_type_errors`, `redact`, `with_retry`,
`retry`, `purpose`, `retention`, `pii`, `stealth`; closure slices `malformed_proxy_url_is_a_hard_refusal`,
`every_malformed_shape_refuses`, `interpreter_fetch_refuses_on_bad_proxy`,
`retry_attempts_are_hard_capped`, `linear_backoff_saturates`, `expired_retention_blocks_serving`,
`purge_expired`, `socks5_scheme_is_upgraded_to_remote_dns`, `stealth_default_on_and_optout_explicit`,
`no_bare_ureq_calls_in_the_runtime_tree`; integration `sec1_honesty_sweep` +
`opsec_corpus_acceptance`; static guards for N1–N2–N4–N5–N6–N7–N8–N9; optional live
`check_egress.sh` (`--live-egress`); **E8 analog (§2b)**: KEV-gate run + deny/locked-CI pins,
workflow least-privilege scans, signing pins, build-script allowlist; verdict-logic selftest
(`--selftest`, 9 cases).

**Pending:** none. The `[PEND]` mechanism is retained — new gaps land as TODOs until their closure
test exists.

## Provenance

- Invariants and statuses: `artifacts/tallow_intel_uplift_2026-09-11/impl/A1.4.1_never_list.md`
  (AGT-05, batch 01; all `path:line` refs verified read-only on 2026-09-11).
- Gate script: `scripts/never_check.sh` (task A1.4.3, AGT-18, batch 02; verified `bash -n` +
  `--no-cargo` run — see `batch_02/reports/AGT-18.md`).
- Closure window: A1.4.2 P1–P7 + opsec-corpus consumer (batch-02…batch-06 landed sets; verified in
  the batch-06 integration build — see `batch_0*/reports/` and `git log`).
- Location note: this file lives under `docs/release/` (topic-scoped dir, consistent with
  `docs/operations/`, `docs/architecture/`, …). The Phase-1 bootstrap gates remain in
  `docs/operations/release-bootstrap-checklist.md`; both gates apply to a release.
