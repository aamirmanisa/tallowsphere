# Panic policy — per binary

**Sheet item:** U-J02 · **Date:** 2026-10-16
**Gate:** `python3 scripts/panic_policy_check.py` (fails if this document and the tree drift apart)

## The policy

**Every shipped Tallow binary is built with `panic = "abort"`.**

| profile | `panic` | who is built with it |
|---|---|---|
| `[profile.release]` | `abort` | everything built without `--profile` |
| `[profile.max]` | `abort` (inherits `release`) | released artifacts — see README → *Release artifacts use `--profile max`* |
| test / dev | `unwind` (Rust default) | the dev loop and `cargo test` only |

Why `abort` is the right default here:

- **Fail fast.** A panic means an invariant is broken. Unwinding out of it can run destructors over
  half-updated state — a partially-written frame, a lock released mid-update — which is worse than dying.
- **Size and speed.** No landing pads, no unwind tables. This is the same trade the release profiles already
  make (thin/fat LTO, `strip`), and it is consistent with the U-C10 measurements.
- **Isolation is the supervisor's job, at process granularity.** Verified on this box: every long-lived
  Tallow service restarts under systemd — `tallow-relay` and `tallow-search-web` `Restart=always`;
  `tallow-reader-daemon`, `tallow-admissiond`, `tallow-portal`, `tallow-veil-bridge` and `tallow-admin`
  `Restart=on-failure`. The remaining `tallow-*.service` units are `Type=oneshot` **with a matching `.timer`**
  (`tallow-aide-check`, `tallow-rmdb-update`, `tallow-turn-posture`, `tallow-stall-watch`, `tallow-status-gen`,
  `tallow-relay-healthcheck`, …), for which `Restart=` is not applicable by design.
  **So an abort is a restart, not an outage.**

## The consequence you must not misread

`panic = "abort"` means **there is no in-process panic isolation in any shipped artifact.**
`catch_unwind` cannot catch: at the panic point the process aborts.

Measured, not asserted. A probe built with `panic = "abort"` around
`catch_unwind(|| panic!("boom"))`:

```
panic=abort   ->  thread 'main' panicked at src/main.rs:15:9 / boom
                  exit 134   (no RESULT line: the catch never returned)
panic=unwind  ->  RESULT CAUGHT -- in-process isolation works
                  exit 0
```

The tree contains **9 `catch_unwind` call sites in `src/`** whose surrounding comments promise containment.
**8 are on shipped code paths; 1 is inside a unit test** — a split I had wrong when this document was first
written (it said 7 shipped), corrected while annotating them:

| file | sites | lines |
|---|---|---|
| `src/main.rs` | 2 | 16892, 16912 — probe/report runs described as "thread + catch_unwind + hard timeout". Both shipped. |
| `src/interp.rs` | 5 | 3616, 4645, 4796, 32312 shipped — "prevent panic propagation", "Execute child in catch_unwind for crash isolation". **42810 is inside the unit test `secret_type_cannot_be_printed`.** |
| `src/supply_chain.rs` | 2 | `signing_roundtrip_works` — the supply-chain self-test. Both shipped, annotated in place 2026-10-20. |

**They do nothing in release.** They work in dev and in `cargo test`, because both use `unwind` — which is
exactly why two in-tree tests pass while the guarantee they describe is absent from everything that ships:
`spawn_agent_crash_isolation_via_catch_unwind` (`src/interp.rs`) and `guarded_probe_contains_panics`
(`src/main.rs`, which asserts `run_guarded_probe(|| panic!("boom")) == Panicked`). A test that runs under a
profile the artifact is not built with does not test the artifact.

**Annotated in place — decision taken 2026-10-16: keep `abort`, correct the comments.** All 9 sites and both
tests now carry a short note stating the dev/test-only scope and pointing here, so the next reader cannot take
them for a release guarantee. The change is **comment-only** and was verified as such: every added line in the
diff is a comment, and the gate's call-site counts are unchanged.

(`tests/fuzz_safety.rs` also mentions `catch_unwind`; it is a test, not shipped code, so it is out of scope.)

## Decision

**Taken 2026-10-16: option (a) — keep `abort`, correct the comments.** The isolation that matters is already
provided at process granularity by the supervisor, verified above; the defect was the comments reading as a
release guarantee. The next best option was real but worse here:

- ~~**(a) Keep `abort` and correct the comments — recommended.**~~ **DONE.** The isolation that matters is
  already provided at process granularity by the supervisor, verified above. The defect was that the comments
  read as a release guarantee; the mechanical fix was to state "dev/test only" at those 7 sites.
- **(b) Build the binaries that isolate with `panic = "unwind"`.** Buys real in-process containment for the
  interpreter's agent-spawn path and the probe/report paths, at the cost of unwind tables and the fail-fast
  stance — and it contradicts the size/speed trade the release profiles make deliberately. **Not taken.**

The honest reading, and the shipped behaviour, is (a)'s consequence: **the catches are inert in shipped
artifacts.**

## Drift gate

`scripts/panic_policy_check.py` reads `Cargo.toml` and counts the call sites, and fails if either stops
matching what this document says — a new `catch_unwind`, or a changed profile, must update this policy
rather than silently invalidate it.
