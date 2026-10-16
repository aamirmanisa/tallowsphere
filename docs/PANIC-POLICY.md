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

The tree contains **7 `catch_unwind` call sites** whose surrounding comments promise containment:

| file | sites | lines |
|---|---|---|
| `src/main.rs` | 2 | 16892, 16912 — probe/report runs described as "thread + catch_unwind + hard timeout" |
| `src/interp.rs` | 5 | 3616, 4645, 4796, 32312, 42810 — "prevent panic propagation", "Execute child in catch_unwind for crash isolation" |

**They do nothing in release.** They work in dev and in `cargo test`, because both use `unwind` — which is
exactly why the in-tree test `spawn_agent_crash_isolation_via_catch_unwind` (`src/interp.rs:46465`) passes
while the guarantee it describes is absent from everything that ships. A test that runs under a profile the
artifact is not built with does not test the artifact.

(`tests/fuzz_safety.rs` also mentions `catch_unwind`; it is a test, not shipped code, so it is out of scope.)

## Open decision

Two coherent options. This changes how every artifact is built, so it is an operator call, not a quiet edit:

- **(a) Keep `abort` and correct the comments — recommended.** The isolation that matters is already
  provided at process granularity by the supervisor, verified above. The defect is that the comments read as
  a release guarantee; the mechanical fix is to state "dev/test only" at those 7 sites.
- **(b) Build the binaries that isolate with `panic = "unwind"`.** Buys real in-process containment for the
  interpreter's agent-spawn path and the probe/report paths, at the cost of unwind tables and the fail-fast
  stance — and it contradicts the size/speed trade the release profiles make deliberately.

Until one is chosen, the honest reading is (a)'s consequence: **the catches are inert in shipped artifacts.**

## Drift gate

`scripts/panic_policy_check.py` reads `Cargo.toml` and counts the call sites, and fails if either stops
matching what this document says — a new `catch_unwind`, or a changed profile, must update this policy
rather than silently invalidate it.
