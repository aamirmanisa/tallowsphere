# V1 release gates (RG-1…RG-7)

> **Scope (2026-10-15).** This document describes the release line of the Tallow **language/workspace**
> (`~/Nixe`), not this repository. The artifacts it names — `scripts/release_gate.sh`, `never_check.sh`,
> `baseline_battery.py`, `kev_gate.sh`, and the workflows `release.yml`, `never-invariants.yml`,
> `ci-full.yml` — are not in this tree, and their absence is measured rather than assumed:
> `never_check.sh` names 19 paths this tree does not carry (`apps/tallow-copy/…`, `apps/tallowsync/…`,
> `artifacts/…`), `kev_gate.sh` needs `scripts/kev/kev.snapshot.json`, and `ci-full.yml` runs the
> workspace's full matrix, including the two gates this repository still omits (`fmt`, `vet`).
> `claims-ledger` was the third and is now carried (2026-10-20: 72 entries, 0 findings, rc=0).
> What this repository carries and verifies is `.github/workflows/ci.yml` (17 jobs) and
> `.github/workflows/tallow-production-ci-gates.yml`; see `MANIFEST.md` § "CI carried, and what was left
> behind".

**Adopted:** 2026-09-14 (V1 freeze prep) · **Source:** CYCLE-01 §9 toolchain-and-release
(RG-1…RG-7 program exit gate; adopt-by-copy after R-06 observation **O-2** — doc was missing).
**Rule:** every unchecked item needs a waiver (owner + reason + expiry); NW items are
non-waivable. Applied before **every** `v*` tag. Status legend: `[measured]` · `[partial]` ·
`[target-only]` · `[pending F-02/F-03]` · `[not-exercised]`.

**Tag-vs-tree gate delta (noted 2026-09-16).** This file tracks the current tree's gate.
The `v1.0` tag (`70e338a`, 2026-09-14) ships the **pre-R4-1** `scripts/release_gate.sh`
(606 lines): no `--quick`; `S8` claims-ledger expected `rc 1` (`[rc 1 = pre-E3 drift
present; flip to rc 0 at adoption]`); pending-tool skips were recorded as
`SKIP(pending-tool)` in the stage table + TODO file but carried no `STAGE NOT EXECUTED`
banner or `INCOMPLETE` annotation on the `GATE GREEN` line. The post-tag R4-1 changes
(loud skipped-stage visibility; `S8` accept-set `rc 0|2`, rc 1 = RED) landed in commit
`8266181` (2026-09-15). When judging the tagged revision, use the tag's own script
(`git show v1.0:scripts/release_gate.sh`); the tree copy is larger and under active edit
(S9 lane, 2026-09-16) — its script header is the current source of truth.

## RG-1 · Correctness
- [x] `cargo check` workspace, all targets — `[pending F-02: S4 check --locked --all-targets]` (S4 green at w2v4; 1-line `tests/juggler_smoke.rs` API fix landed 2026-09-14).
- [x] Full lib test suite + `tests/zero_trust_conformance.rs` — `[partial: zero_trust_conformance measured (S3); whole-lib sweep carries a documented quarantine boundary (LESSONS #9)]`.
- [ ] `ci-full.yml` deep-gate jobs — `[not-exercised: CI latent in R0]`.
- [ ] Coverage baseline tool + no-decrease check — `[target-only: tool not built]`.
- [ ] Fuzz smoke — `[target-only: wiring]`.
- [x] Honesty sweep — `[measured: counters green in wave batteries]`.
- [x] `tallow check`/`run` on samples — `[measured: S7a–d smoke stages; engine negative proof included]`.

## RG-2 · Performance
- [x] Benchmark protocol executed + archived — `[partial: R-01 live calibration windows scheduled (A 14:03 / B 02:03 UTC); transport/measurement cells measured (M-01/M-05)]`.
- [ ] Regression thresholds (throughput −10% / p95 +15% / success −1.0pp) — `[target-only: wired to the deferred 24-run matrix]`.
- [x] Named metrics (cold-start, copy ratios, …) — `[measured: M-05 cold-start 232.8 ms; M-06 no-op ratios 1.78×/49.25×/6.48× re-scoped honestly]`.

## RG-3 · Security
- [x] Zero open P0 rows in V1 scope — `[measured: R-08 closed (W3 55/55 = 36 verified + 19 A3-rescoped)]`.
- [x] `cargo audit` / `cargo deny` / `cargo vet` — `[partial: vet offline rc=0 (805 exempted); audit network leg pending]`.
- [x] NEVER static+cargo green — `[measured: never_check 73/0 (battery-9)]`; live egress 14/14 — `[pending F-03]`.
- [x] Signing keys resolved + installers fail-closed — `[measured: R-04 key pinned in installers (working tree); B17 commits the pin before tag]`.

## RG-4 · Documentation
- [x] Root README with install/verify/quickstart — `[done 2026-09-14; accuracy pass in F-05]`.
- [ ] `getting-started.html` artifact names match reality — `[check item for F-05]`.
- [x] CHANGELOG + versioning policy — `[done 2026-09-14 (`CHANGELOG.md`, `docs/release/versioning-policy.md`)]`.
- [x] Install signature-verification documented — `[partial: installer docs + README §Security posture]`.
- [ ] `tallow doc` output sanity — `[check item for F-05]`.

## RG-5 · Platform
- [ ] CI matrix (linux gnu+musl, macOS, Windows) — `[not-exercised: CI latent; R0 target = aarch64-linux (exercised)]`.
- [x] Install instructions per OS — `[partial: install.sh fixture-E2E-executed (26 checks) + install.ps1 exercised under pwsh (9 checks) and smoke-gated on windows-latest in release.yml; first real-Windows CI run + real-network E2E pending a remote]`.
- [ ] macOS notarization / Windows signing stories — `[target-only: post-remote]`.

## RG-6 · Release & rollback
- [x] Full release rehearsal (build → bundle → clone → artifacts → installer E2E → 5/5 fail-closed negatives) — `[measured: R-06 local (11 remote steps enumerated w/ runbooks)]`.
- [x] Tag rules + machine-checked tag↔version — `[done: release.yml assertion + versioning policy]`.
- [x] Publish gate refuses unsigned archives — `[done: B17 fix F-1/F-2 (sibling checks + fail-closed assertion)]`.
- [ ] Rollback runbook executed — `[partial: post-remote]`.
- [ ] Reproducible-build toolchain caching — `[partial: `--offline` pins; cosign cache target-only]`.

## RG-7 · Compliance
- [x] SBOM generated + shipped + drift-checked — `[measured: gate S2 (battery-9 regen+check rc=0)]`.
- [x] License compliance — `[partial: MIT everywhere; no policy-violating licenses recorded]`.
- [ ] Audit/PIA documents — `[target-only: no telemetry in scope]`.
- [x] Waivers register — `[none required at adoption]`.

## F-05 rehearsal results (2026-09-14)

_Run: F-chain battery — `release_gate.sh --twice --profile full` (S1c live egress via Tor) ·
`never_check.sh --live-egress` · `claims_ledger_check.sh`. Evidence: `research/tallow-v1/evidence/cycle-05/`._
- **Run A (05:22–05:56, pre-fix): RED.** Finding **F3-01**: `find_chrome_path()` resolved `/snap/bin/chromium` (PATH `which`) over the managed `chrome-headless-shell-153.0.8010.36`; snap confinement never opens the DevTools endpoint under root → interpreter-browser egress arms failed with `Err("timeout waiting for Chrome HTTP endpoint")` (compiled arms returned `nil`, tolerated by design). Root cause pinned by strace + manual replay. Also **F3-02**: a script-level `CARGO_INCREMENTAL` export could not be inherited by pass-2's `env -i` → diverged build fingerprints → full pass-2 rebuild → false binary-drift `rc=3`.
- **Fixes:** managed-first resolution in `src/browser/process.rs::find_chrome_path()` (pre-verified live: native + interpreted probes both on Tor exits); `.cargo/config.toml` `[build] incremental = false` (applies to both passes; removes the incremental-cache churn class).
- **Run B (06:07–06:19, aborted):** S1b RED on incremental-cache churn (the class F3-02 addresses) → superseded.
- **Run C (06:25–06:44) — GREEN [measured]:** GATE GREEN combined rc=0 · pass1 pass=17 red=0 (S9 skip by design) · pass2 rc=0 · RUN-TWICE tables identical, no drift · `never_check --live-egress` **PASS 74/0** · claims rc=2 (accepted; rc 2 = warnings-only — claims-gate semantics, not an error). Live arms observed on Tor exit `185.220.100.243` ≠ box `203.0.113.1`. Evidence: `research/tallow-v1/evidence/cycle-05/release-gate-20260914T062502Z.{log,json}` + archive `artifacts/release-gate/2026-09-14-fea102982342/`.

## Gate gaps carried (owners)

- Coverage-baseline tooling — `[target-only]`, owner: post-freeze tooling.
- Compiler perf regression gate — `[target-only]`, owner: post-freeze tooling.
- S9 baseline battery — [shipped 2026-09-16]: `scripts/baseline_battery.py` (14 engine-labeled §2.7 rows → rows.jsonl under the run archive; registered deferrals: §2.7 loopback rows 10/11). Pending-tool entry closed.
- Non-Linux platform exercises — `[not-exercised]`, owner: post-remote CI.
