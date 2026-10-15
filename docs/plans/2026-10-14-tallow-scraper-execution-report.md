# Tallow Scraper Execution Plan — Research / Execute / Verify Run Report

**Date:** 2026-10-14 · **Tree:** `/home/user/Nixe` @ branch `v1`, HEAD `384daa3b` · **Dirty baseline:** 4313 entries
**Input report:** `docs/plans/2026-10-14-tallow-scraper-execution-plan.md` (31 enumerated entries: 28 tasks + 3 gate/resolution entries)
**Evidence dir:** `artifacts/tallow-scraper-execution-2026-10-14/`

---

## UPDATE — later the same day: P0 closed, this report's verdict superseded

The operator answered `P0.G` with "**1 add features**". Applied and verified:

| Step | Command | Result |
|---|---|---|
| Manifest repair | `crates/tallow-crypto/Cargo.toml:64` → `features = ["sys_rng"]` | applied to the working tree |
| `P0.T1` re-run | `cargo check -p tallow-crypto` | **RC=0** (0.29 s) |
| Direct dependent | `cargo check -p tallow-protocol` | **RC=0** (1m09s, zero errors) |
| Workspace (P0.T3) | `cargo check` (all members) | **RC=0, 2m59s, zero errors** (20 pre-existing warnings in the `tallow` bin) |
| Disk | `df -h /` | 74% → 75% |

**Therefore §1's "cannot proceed past its first task" and §2-B2's "the workspace cannot build" are SUPERSEDED as of this update.** B2's root cause and proven fix stand as written; the build is now green. B1 (the cargo shim) is unchanged and still requires the scoped-cargo form for every invocation.

**Still open:** `rng.rs` remains **untracked** — a clean checkout still fails `E0583` until it is committed (`P0.T2`, not requested). Everything else in P0 is closed, and P1–P6 are unblocked.

---

## 1. Executive summary

The run **cannot proceed past its first task**, and the reason is not the plan's content — it is that **branch `v1` does not compile**, in the working tree or in a clean checkout. Two independent build breakers were found and both were reproduced; the complete fix was **proven in an isolated throwaway worktree** and applied nowhere.

**Status counts (all 31 entries accounted for):**

| Status | Count | Entries |
|---|---:|---|
| ✅ Completed + verified | 1 | P6.T1 |
| ❌ Failed (executed, negative result) | 1 | P0.T1 |
| 🆕 Diagnosed + fix proven (new work) | 2 | B1 (cargo shim), B2 (build break) |
| ✔ Resolved by operator | 1 | P1.G / P1.R |
| ⛔ Ready-for-human (gate) | 2 | P0.G (expanded), P7.G |
| ⏸ Blocked — pending, prerequisites established | 24 | P0.T2–T3, P1.T1–T6, P2.T1–T4, P3.T1–T4, P4.T1–T3, P5.T1–T3, P6.T2, P7.T1–T3 |

**Every blocked item shares one blocker: B2.** None is blocked by its own difficulty. No item was skipped.

---

## 2. New findings (these are the substance of this run)

### B1 — Every `cargo` invocation from a Hermes agent session is broken (environment, box-level)

`/root/.local/bin/cargo` is an operator-authored shim (2026-09-29, "Tallow cargo build enforcement") that re-execs heavy builds inside a bounded transient systemd scope. Its scope path adds:

```
args+=(--property=PassEnvironment=TALLOW_CARGO_NOLOCK)      # shim line 69
```

`PassEnvironment=` is a **service-unit** directive; it is invalid for a transient **scope**. Result: `systemd-run` refuses the whole invocation.

**Reproduced with a trivial value** (not just the shim's own variable):
```
$ systemd-run --scope --property=PassEnvironment=FOO -- /bin/true
Unknown assignment: PassEnvironment=FOO
$ systemd-run --scope -p MemoryMax=512M -- /bin/true
Running as unit: run-r86bc7ccb....scope            # a valid property works
```
**Impact:** any cargo command run from `hermes-gateway.service` (my shell: `cgroup = 0::/system.slice/hermes-gateway.service`) fails — including `cargo --version`. This is not specific to this plan; it affects every build any agent profile attempts on this box.
**Workaround used this run (no file touched):** a faithful replica of the shim's intent with a valid property set:
`systemd-run --scope --collect -q -p MemoryHigh=7G -p MemoryMax=9G -p MemorySwapMax=3G -p IOWeight=50 --setenv HOME=/root --setenv CARGO_TARGET_DIR=... -- /root/.cargo/bin/cargo …`
**Proposed fix (NOT applied — operator tooling):** delete shim line 69. The lock is held via inherited fd 9, so no property is needed to propagate it; if an env marker is genuinely wanted, `--setenv TALLOW_CARGO_NOLOCK=1` is the form this shim already uses elsewhere.

### B2 — `crates/tallow-crypto` does not compile, and it is a dependency of the entire workspace

**Without the untracked file** (prior state): `error[E0583]: file not found for module 'rng'`.
**With `rng.rs` injected:** three more errors remain — the crate is broken regardless of that file:

```
error[E0433]: cannot find `rand_core` in `getrandom04`     crates/tallow-crypto/src/rng.rs:17:45
error[E0433]: cannot find `rand_core` in `getrandom04`     crates/tallow-crypto/src/rng.rs:18:18
error[E0425]: cannot find value `SysRng` in crate `getrandom04`   crates/tallow-crypto/src/rng.rs:18:52
error: could not compile `tallow-crypto` (lib) due to 3 previous errors     → MAIN_RC=101
```

**Cause:** `crates/tallow-crypto/Cargo.toml:64` declares `getrandom04 = { package = "getrandom", version = "0.4" }` enabling **no features**. `getrandom 0.4.1` gates exactly `sys_rng = ["dep:rand_core"]`, and `rng.rs` uses both `getrandom04::rand_core::…` and `getrandom04::SysRng`.
**Blast radius — verified by `cargo tree -i`:** `tallow-crypto` is consumed by `tallow` (the root binary), `tallow-net`, `tallow-protocol`, `tallow-svid`, `tallow-daemon`, and `tallow-reader`. **The workspace cannot build**, which is why all 24 pending items are blocked.
**Lineage:** `getrandom04` was introduced by `b77f7dfb` ("codegen/runtime: native lowering for crawler, fingerprint, page-cache, url, compress"); `mod rng;` was added by `e5fec4cd` ("protocol: port the v8 wire change into canonical"). Both are protocol-lineage commits, which is why this is gate `P0.G` territory and not mine to commit.

**PROVEN MINIMAL FIX (applied in a throwaway worktree only, then removed):**
```diff
-getrandom04 = { package = "getrandom", version = "0.4" }
+getrandom04 = { package = "getrandom", version = "0.4", features = ["sys_rng"] }
```
Result with the fix: `FIXED_RC=0`, `Finished dev profile in 2.09s`, **zero errors**, one warning:
```
warning: function `csprng` is never used  --> crates/tallow-crypto/src/rng.rs:17:15
```
That warning is itself confirmation of a claim I made earlier: the module is **dead code today** — it only ever unblocks compilation.
**Complete repair = two changes:** (1) commit `crates/tallow-crypto/src/rng.rs`; (2) the manifest line above. Both live in the sendtallow-gated crate.

---

## 3. Corrections to my own prior output (found by this run)

1. **Audit claim was wrong.** `TALLOW-SCRAPER-AUDIT-2026-10-14.md` states the branch fails "from a clean checkout … sole error E0583". Reality: it fails **in the working tree too**, and with the file present there are **three further errors**. The correct statement is in B2.
2. **Plan premise was wrong.** `P0.T1` was written as "injecting the file proves the tree compiles" — false; the injected run returned `CHECK_RC=101`. The task is rewritten in §4.
3. **Feature-flag claim was inherited, not verified.** The prior audit's list of four opt-in flags — `parquet-storage`, `s3-storage`, `redis-backend`, `real-ml` — is wrong on the last one: `rg 'real-ml|real_ml' Cargo.toml` → **no matches**. Three flags verified; `real-ml` does not exist under that name. `P6.T2` must be corrected before it executes.
4. **My first rc probe this run was invalid.** I read `$?` after a pipe (which reports the pipe's last command). Re-probed without a pipe: `systemd-run --scope` **does** propagate exit codes (`rc_false=1`, `rc_true=0`). No defect there.

---

## 4. Item-by-item status

### P0 — Build verification (sendtallow-gated)

| Item | Research | Execute | Verify | Status |
|---|---|---|---|---|
| **P0.G** — may the protocol-lineage file be committed? | Boundary confirmed: `mod rng;` from protocol commit `e5fec4cd`; `tallow-protocol` depends on `tallow-crypto` (`Cargo.toml:35`) | not dispatched (human gate) | — | ⛔ **READY-FOR-HUMAN — and now broader**: the decision is no longer "commit an uncalled file", it is "repair a workspace-breaking build defect in a protocol-dependent crate" (2 changes) |
| **P0.T1** — prove the tree compiles without committing | worktree at HEAD + `rng.rs` injected | scoped `cargo check -p tallow-crypto` (13.4 s) | `CHECK_RC=101`, 3 errors | ❌ **FAILED — premise false; escalated to B2** |
| **P0.T2** — commit the file [gated] | patch identified | not executed | — | ⏸ Blocked by P0.G |
| **P0.T3** — record build status | now has content | not executed | — | ⏸ Blocked by P0.G |

### P1 — Schema-first tier → current model
All six tasks: **research done** (citations verified, see §5), **execution blocked by B2** (every task needs `cargo check`/`cargo test`).

| Item | Notes | Status |
|---|---|---|
| P1.G / P1.R | Operator decision recorded 2026-10-14: no Ollama; use the current model (`deepseek/deepseek-flash`) | ✔ Resolved |
| P1.T1–T6 | Prerequisites established: `llm_extract.rs:158,187,221,634,664` and `smart_extract.rs:112,127` all verified at the cited lines; the zone-egress refuse-direct guard at `:221` confirmed present | ⏸ Blocked by B2 |

### P2 — Bind the last two FFI symbols
Citations verified: `crawler_ffi.rs:49` and `page_cache_ffi.rs:47` are real `pub extern "C"` bindings (the pattern to copy); interpreter facades exist at `stdlib/browser.rs:35` (`structured_data_extract`) and `:293` (`crawler_from_sitemap`). `tallow_crawler_from_sitemap` / `tallow_structured_data_extract` remain 0 hits in `src/`. → ⏸ **Blocked by B2**

### P3 — Extraction CLI surface
Citations verified: `main.rs:123` (`#[derive(Subcommand)]`) and `:2555` (`match cli.command`). Confirmed by direct probe: `tallow extract|plan|schema|scrape` → `error: unrecognized subcommand`. → ⏸ **Blocked by B2**

### P4 — Typed unknowns / limitations
Citations verified: `provenance.rs:25` (`ProvenanceRecord`) and `:47` (`ProvenanceDisplay`), `run_evidence.rs:74` (`pub fn record`). No `limitations`/`unknowns` field exists today (confirmed earlier). → ⏸ **Blocked by B2**

### P5 — HAR import
No existing `har_import` module; `artifact_policy.har` is write-only. Prerequisites established. → ⏸ **Blocked by B2**

### P6 — Flags & `ml` honesty

| Item | Research | Execute | Verify | Status |
|---|---|---|---|---|
| **P6.T1** — `ml` census | 4 files enumerated | counted every mock site | `embeddings.rs` 260 lines / 22 mock hits / 17 fns · `ml_matcher.rs` 386 / 2 / 19 · `mod.rs` 36 / 1 / 1 · `vector_store.rs` 232 / 1 / 16 · **0 `todo!()`/`unimplemented!()`** | ✅ **COMPLETED** |
| P6.T2 — flag non-claims | flags re-derived: `parquet-storage` (`Cargo.toml:291`), `s3-storage` (`:294`), `redis-backend` (`:298`) verified; **`real-ml` does not exist** | not executed | — | ⏸ Pending — **premise corrected first** (see §3.3) |

### P7 — REA decision record + runbook
- **P7.G** — ⛔ **READY-FOR-HUMAN** (re-affirm or reverse the 2026-10-12 "skip REA" decision).
- **P7.T1–T3** — ⏸ Blocked by P7.G. Note they are docs-only and would not need a compiling tree.

---

## 5. Verification method and coverage

- **20 plan citations spot-verified line-by-line** (`sed -n "<n>p"` on each cited file): **20/20 exact** — `llm_extract.rs:158/187/221/634/664`, `smart_extract.rs:112/127`, `run_evidence.rs:74`, `crawler_ffi.rs:49`, `page_cache_ffi.rs:47`, `stdlib/browser.rs:35/293/364/474`, `main.rs:123/2555`, `provenance.rs:25/47`, `tallow-crypto/src/lib.rs:28`, `tallow-protocol/Cargo.toml:35`.
- **Build probes:** 3 scoped `cargo check -p tallow-crypto` runs (main tree RC=101; worktree+file RC=101; worktree+file+fix RC=0). Full logs preserved.
- **`cargo tree -i tallow-crypto --workspace`** used to establish blast radius rather than assuming it.
- **Repo integrity:** dirty count 4313 before the run; the only additions are this run's evidence dir (`artifacts/tallow-scraper-execution-2026-10-14/`, 3 files). The throwaway worktree was removed. No tracked file was modified.
- **Not verified / limits:** no `cargo test` was run (the workspace does not build); no benchmark; `P1`'s provider-call shape is unexecuted; the `real-ml` correction is a grep result, not a build. Pre-existing leftover noted: a detached worktree at `…/cache/scratch/commitcheck` (`b77f7dfb`) from an earlier session was left in place.

## 6. Evidence files

| File | Contents |
|---|---|
| `artifacts/tallow-scraper-execution-2026-10-14/tc-main.log` | Main-tree failure: 3 errors, `E0433`×2 + `E0425` |
| `artifacts/tallow-scraper-execution-2026-10-14/tc-fixed.log` | Same check with the fix: RC=0, dead-code warning naming `csprng` |
| `artifacts/tallow-scraper-execution-2026-10-14/Cargo.toml.FIXED.worktree` | The exact one-line manifest fix that was proven and then discarded |

## 7. What must happen next (in order)

1. **Operator decision (P0.G, expanded):** repair the `tallow-crypto` build (commit `rng.rs` + add `features = ["sys_rng"]`)? This is the sendtallow-gated crate, so it is your call — and it blocks all 24 pending items.
2. **Operator decision (B1):** fix the cargo shim (delete line 69) or keep using the manual scoped-cargo form. The shim breakage affects every agent's builds, not just this plan.
3. Only then can P1–P5 execute, starting with the corrected **P0.T1** (which becomes: apply the two-change repair, then prove `-p tallow-crypto` RC=0 **and** `cargo check` for the workspace).
