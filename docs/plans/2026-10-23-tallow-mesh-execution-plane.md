# Tallow Mesh Execution Plane — Implementation Plan

> **For Hermes:** implement task-by-task; use `subagent-driven-development` if
> dispatching, but see the executor note below before promising parallelism.

**Goal:** turn `src/stdlib/mesh.rs` (an in-memory topology simulation) into a
real execution plane that runs a task graph across N worker threads, replays
deterministically, and fails visibly.

**Architecture:** the coordinator topologically sorts a task graph into waves;
each wave is batched to workers over channels; every task runs under an
epoch-fenced lease; each wave ends with a checkpoint hash written to a JSONL
journal. Replay reads the journal plus derived seeds and must reproduce the
same hashes. Memory writes and control commands sit off the critical path.

**Tech stack:** Rust (std threads, `std::sync::mpsc`, `Mutex`/`Condvar`),
`blake3` (already in `Cargo.toml:57`), `serde_json` (already a dependency),
Tallow interpreter (`src/interp.rs`), stdlib dispatch (`src/stdlib/mod.rs`).

**Design doc:** `docs/architecture/tallow-mesh-execution-plane-2026-10-23.md`
(`577e178`) — read it first; this plan implements it and does not re-argue it.

---

## Preconditions an implementer must know

1. **`Value` is not `Send`.** It holds `Rc<RefCell<…>>`; one interpreter per
   worker thread, never one interpreter shared across threads. `src/stdlib/mesh.rs`
   already documents this at the top.
2. **A bin rebuild costs ~2.5–8 minutes** on this box, and the lib suite is
   ~137 s. Budget accordingly; do not run the full lib suite per micro-task —
   use the named test, then the suite once per phase.
3. **`/run/nixe-heavy-build.lock`** serialises heavy builds. If `cargo` sits with
   no child compiler, an orphaned `chrome-headless` or `rustc` is holding it:
   `fuser -v /run/nixe-heavy-build.lock`, then kill the orphan by PID.
4. **Executor pool is 3** (`delegation.max_concurrent_children: 3`). The five
   phases below therefore run **sequentially** unless the limit is raised. Do not
   dispatch two phases at once; they touch the same files.
5. **M4 (real wire) is gated on an operator decision** — it changes what
   `simulated: true` means. Nothing before M4 depends on it.

---

## Phase M0 — plan, seeds, journal, replay (no workers)

Deliverable: `Mesh.plan` and `Mesh.replay` work on pure tasks in one thread.

### Task 0.1: Create the module skeleton

**Objective:** add `src/mesh/` with an empty-but-compiling surface.

**Files:** create `src/mesh/mod.rs`; modify `src/lib.rs:168` (the module
declaration lives beside `pub mod stdlib;` — verified).

**Step 1:** create `src/mesh/mod.rs`:

```rust
//! Mesh execution plane: task graph → waves → leases → checkpoints.
//! Topology (membership, gossip, DHT) lives in src/stdlib/mesh.rs and is
//! separate on purpose; see docs/architecture/tallow-mesh-execution-plane-2026-10-23.md.

pub mod journal;
pub mod lease;
```

**Step 2:** register the module next to `mod stdlib;` (same file, same style).

**Step 3:** `cargo check --locked` → expected `Finished` with no errors.

**Step 4:** commit `mesh: module skeleton`.

### Task 0.2: `TaskClass` and `Task`

**Objective:** the three task classes with their retry rules as data.

**Files:** `src/mesh/mod.rs`; test in the same file (`#[cfg(test)] mod tests`).

**Step 1 (failing test):**

```rust
#[test]
fn io_task_without_idempotency_key_is_rejected() {
    let t = Task::new("a", "fn_a", vec![], TaskClass::Io, None);
    assert!(t.validate().is_err(), "io tasks must carry an idempotency key");
}
```

**Step 2:** `cargo test --lib mesh::tests::io_task_without_idempotency_key -- --nocapture`
→ FAIL (`Task` undefined).

**Step 3 (implementation):**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskClass { Pure, Io, Llm }

#[derive(Clone, Debug)]
pub struct Task {
    pub id: String,
    pub func: String,
    pub deps: Vec<String>,
    pub class: TaskClass,
    pub idempotency_key: Option<String>,
}

impl Task {
    pub fn new(id: &str, func: &str, deps: Vec<&str>, class: TaskClass,
               idempotency_key: Option<&str>) -> Self { /* … */ }
    pub fn validate(&self) -> Result<(), String> {
        if self.class == TaskClass::Io && self.idempotency_key.is_none() {
            return Err(format!("task '{}': io class requires an idempotency key", self.id));
        }
        Ok(())
    }
}
```

**Step 4:** re-run the test → PASS.
**Step 5:** commit `mesh: task classes and validation`.

### Task 0.3: Topological waves

**Objective:** group independent tasks into waves; reject cycles with the path.

**Files:** `src/mesh/mod.rs`.

**Step 1 (failing tests):**

```rust
#[test]
fn diamond_graph_is_three_waves() { /* a → (b,c) → d == 3 waves */ }

#[test]
fn cycle_is_rejected_with_the_path() {
    // a→b→a; assert the message contains "a -> b -> a"
}
```

**Step 2:** run both → FAIL.
**Step 3:** implement `pub fn plan(tasks: &[Task]) -> Result<Vec<Wave>, String>` with
Kahn's algorithm; on leftover nodes, DFS from the first unvisited node to recover
and print the cycle path as `a -> b -> a`. Parallel tasks keep insertion order
inside a wave (determinism depends on it).
**Step 4:** both tests PASS. **Step 5:** commit `mesh: topological waves`.

### Task 0.4: Derived seeds

**Objective:** one function, three derivations, no randomness anywhere.

**Files:** `src/mesh/mod.rs`.

```rust
pub fn task_seed(mesh_seed: u64, wave: usize, task_id: &str, attempt: u32) -> u64
pub fn shard_seed(mesh_seed: u64, wave: usize, shard: usize) -> u64
pub fn sample_seed(task_seed: u64, i: usize) -> u64
```
Implementation: `blake3::hash(&buf)` over the little-endian fields, take the
first 8 bytes.

**Test:** same inputs → same seed; changing `attempt` changes it; two different
task ids never collide in a 10,000-sample loop.
**Commit:** `mesh: derived seeds`.

### Task 0.5: Journal append + checkpoint hash

**Objective:** append-only JSONL whose checkpoint hash is order-independent.

**Files:** create `src/mesh/journal.rs`.

**Step 1 (failing test):** write two tasks' results in opposite orders into two
temp files; both `checkpoint_hash()` calls must be equal.

**Step 2:** FAIL. **Step 3:** implement:

```rust
pub struct Journal { path: PathBuf }
impl Journal {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self>;
    pub fn append(&mut self, event: &Event) -> std::io::Result<()>; // one JSON object per line
}
pub fn checkpoint_hash(results: &[(String, String)]) -> String {
    // sort by task id, then blake3 over "id\0hash\n"
}
```

**Step 4:** PASS. **Step 5:** commit `mesh: journal and checkpoint hashing`.

### Task 0.6: Replay

**Objective:** replay a journal and reproduce every checkpoint hash.

**Files:** `src/mesh/journal.rs`.

**Test:** run a 50-task plan through a stub executor, write the journal, replay,
compare the ordered list of checkpoint hashes; then corrupt one result line and
assert replay reports the first mismatching wave by index.

**Commit:** `mesh: deterministic replay`.

**GATE M0:** `cargo test --lib mesh::` all green, and
`cargo test --locked --lib mesh` shows ≥12 tests. Quote the count in the commit.

---

## Phase M1 — in-process workers, leases, retry

Deliverable: 200 tasks on 1 and 8 workers produce identical checkpoint hashes.

### Task 1.1: Lease table with epoch fencing

**Files:** create `src/mesh/lease.rs`.

```rust
pub struct Lease { pub task: String, pub worker: usize, pub epoch: u64, pub expires_ms: u64 }
pub struct LeaseTable { /* Mutex<HashMap<String, Lease>> */ }
impl LeaseTable {
    pub fn grant(&self, task: &str, worker: usize, ttl_ms: u64) -> Lease; // bumps epoch
    pub fn accept(&self, task: &str, epoch: u64, worker: usize) -> bool;  // stale epoch → false
    pub fn expire_due(&self, now_ms: u64) -> Vec<String>;
}
```

**Tests:** a stale epoch cannot commit; a second grant increments the epoch; an
expired lease is returned by `expire_due` exactly once.
**Commit:** `mesh: epoch-fenced leases`.

### Task 1.2: Worker thread and channel protocol

**Files:** create `src/mesh/worker.rs`.

Each worker owns one interpreter, receives `Batch { wave, tasks }`, returns
`BatchResult { wave, outcomes }`. Use `std::sync::mpsc` for control and results;
no shared interpreter. A worker that panics on a task must catch it
(`std::panic::catch_unwind`) and report `TaskOutcome::Failed { retryable }`
rather than dying.

**Test:** a batch of 10 tasks returns 10 outcomes in wave order; a task that
panics yields one `Failed`, and the worker survives to run the next batch.
**Commit:** `mesh: worker executor`.

### Task 1.3: Coordinator loop with retry and backoff

**Files:** create `src/mesh/coordinator.rs` (or extend `mod.rs`).

Retry policy: `max_attempts` = 3 pure / 2 io / 1 llm; delay
`min(30 s, 1 s × 2^attempt) × jitter(0.5–1.5)`.

**Test:** a task failing twice then succeeding completes with `attempts == 3`,
and the journal contains two `task_retried` events.
**Commit:** `mesh: coordinator with retry`.

### Task 1.4: Cancellation and shutdown

**Files:** `src/mesh/coordinator.rs`.

`stop(run_id, drain_ms)`: stop leasing, wait up to `drain_ms` for in-flight
tasks, then send `Cancel` and drop the pool. Test with a task that sleeps 5 s
and `drain_ms = 200`: returns within 700 ms and the journal records
`run_stopped(drained: false)`.
**Commit:** `mesh: bounded shutdown`.

### Task 1.5: Acceptance run

**Files:** create `tests/mesh_workers.rs`.

```rust
#[test] // ignored above 8 workers by env guard
fn same_hashes_at_one_and_eight_workers() {
    // 200 pure tasks, fixed seed; run with 1 and with 8;
    // assert checkpoint hash vectors are equal.
}
```

Run: `cargo test --locked --test mesh_workers same_hashes -- --nocapture`
Expected: 1 passed, and the printed hash vector is identical in both runs.
**GATE M1:** this test green + `cargo test --locked --lib mesh` green. Do not
proceed to M2 until M1's test has been green twice in a row (flakiness here
means a nondeterministic seed or an order-dependent merge).

---

## Phase M2 — stragglers and bounded speculation

### Task 2.1: Straggler detection
**Files:** `src/mesh/scheduler.rs`. Threshold `2 × median(task_ms)` computed
from the running wave; emits `straggler_detected` to the journal.
**Test:** with one 5 s sleep among 20 fast tasks, exactly that task is flagged.

### Task 2.2: Speculative duplicate under a new epoch
**Files:** `src/mesh/scheduler.rs`.
**Test:** the duplicate's result is discarded when the original lands first, and
vice versa; the journal shows exactly one `task_committed` per task.

### Task 2.3: Budget cap
**Files:** `src/mesh/scheduler.rs`. `speculation_budget = 10%` of wave tasks;
counting is asserted, not assumed.
**Test:** a wave of 10 with 5 slow tasks issues at most 1 duplicate.

**GATE M2:** `tests/mesh_workers.rs` gains
`straggler_does_not_extend_the_wave`; measured wall time quoted in the commit.

---

## Phase M3 — memory plane and control

### Task 3.1: Bounded activity queue with counted drops
**Files:** create `src/mesh/memory.rs`. Capacity default 1024; drop-oldest;
`dropped_total` counter exposed on `RunStatus`.

### Task 3.2: Batcher and dead-letter list
**Files:** `src/mesh/memory.rs`. Flush on 64 activities or 250 ms; on write
failure retry 3× then dead-letter, queryable by run id.

### Task 3.3: Control commands
**Files:** create `src/mesh/control.rs`: `pause`, `resume`, `inject`, `status`.
`inject` records `(key, value, effective_wave)` in the journal.

**GATE M3:** `tests/mesh_workers.rs::memory_drops_are_counted` and
`inject_applies_from_the_next_wave_only`, both real runs with quoted counters.

---

## Phase M4 — real wire (GATED: operator decision required)

**Blocks:** nothing before it. **Blocked by:** an explicit decision that mesh
nodes may talk over the network, and which transport (the relay, or a new
framed protocol). Do not start this without a recorded answer.

1. `src/mesh/wire.rs`: framing `{version, kind, run_id, payload, sig}`; length-
   prefixed, 1 MiB cap.
2. Add a `simulated: false` path to `src/stdlib/mesh.rs` **only** for nodes that
   completed a join handshake; everything else keeps `simulated: true`.
3. Two-process test: kill one mid-plan; survivor finishes with the same final
   hash as a single-process run.

---

## Phase M5 — publish the surface (blocked until M1 gate is green)

### Task 5.1: Declarations
**Files:** create `stdlib/mesh.tl` — it does **not** exist today, so `mesh` is
engine-only and absent from the published surface. Add the 8 functions and 3
structs from the design doc §3, matching the other manifests (`native fn …`).

### Task 5.2: Count gate
`tests/language_surface.rs` moves 1,124 → 1,132 in the **same commit**, with the
reason inline (the six-declaration lesson from 1.2.0).

### Task 5.3: Spec repo
`tallow-language`: add §2.x mesh semantics (determinism contract, task classes,
retry rules) and regenerate `spec/generated.json` against the engine commit.
**Gate:** `python3 tools/generate.py --engine /home/aamir/tallowsphere` prints
`1124 → 1132` and the spec repo diff is only the mesh additions.

---

## Risks and rollbacks

| risk | sign | rollback |
| --- | --- | --- |
| nondeterministic replay | M1 test passes once then fails | seeds derived from wall clock somewhere — grep for `SystemTime` in `src/mesh/`; must be zero |
| worker panics kill the run | `Failed` count spikes | `catch_unwind` missing on the executor boundary |
| journal grows unbounded | checkpoint time climbs | compact by wave; keep only `task_committed` rows older than N waves |
| memory drops confuse users | `dropped_memory > 0` silently | it is already surfaced on `RunStatus`; document the bound |
| M4 regressions | flaky two-process test | M4 is behind a flag; ship with wire disabled |

Rollback for the whole feature is `git revert` of the phase commits — M0–M3 add
new modules and touch `src/stdlib/mod.rs` only at M5.

---

## Definition of done

1. `cargo test --locked --lib mesh` green (M0–M3 tests).
2. `cargo test --locked --test mesh_workers` green, including the identical-hash
   test at 1 and 8 workers.
3. A journal from a real run replays to the same checkpoint hashes.
4. `tallow run` on `examples/mesh_pipeline.tl` prints a run id and wave count.
5. Surface gate at 1,132 and the spec repo regenerated, only if M5 was approved.

---

## Timeline (sequential — pool is 3, phases share files)

| phase | work | gate |
| --- | --- | --- |
| M0 | 6 tasks, ~2 days | `cargo test --lib mesh` ≥12 tests |
| M1 | 5 tasks, ~3 days | identical hashes at 1 vs 8 workers |
| M2 | 3 tasks, ~2 days | straggler test + measured wall time |
| M3 | 3 tasks, ~2 days | counters + inject test |
| M4 | gated | operator decision |
| M5 | 3 tasks, ~1 day | count 1,132, spec regenerated |

**Human gates:** M4 start (transport decision), M5 publish (surface change).
Everything else is agent-executable with the commands above.
