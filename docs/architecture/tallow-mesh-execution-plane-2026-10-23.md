# Tallow Mesh — the execution plane

Status: design, 2026-10-23. Nothing in this document is implemented. It specifies
what to build, in what order, and how each step is proven.

Sources analysed: MiroFish (`github.com/666ghj/MiroFish`, 81,375 stars, Python,
main) and Kronos (`github.com/shiyu-coder/Kronos`, 43,318 stars, Python, master).
Every pattern below is anchored to a file and line I read, not to a README claim.

---

## 0. What already exists, and what this adds

`src/stdlib/mesh.rs` (561 lines) is **not** a network stack. Its own header says
so: nodes, DHT entries and messages live in one process's global maps and every
returned struct carries `simulated: true`. It models membership and gossip; it
does not execute anything.

This design adds the missing half: **work**. A mesh that can run a task graph
across nodes, survive a straggler, produce the same answer twice, and tell you
why it did not. Call it the *execution plane*; the existing module is the
*topology plane*.

The design deliberately keeps three things separate, because conflating them is
how "parallel" systems become untestable:

| plane | owns | today |
| --- | --- | --- |
| topology | membership, gossip, DHT, subscriptions | `src/stdlib/mesh.rs` (simulated) |
| execution | task graph → waves → leases → results | **new** (`src/mesh/`) |
| memory | what the run learned, batched into a graph | **new** (`src/mesh/memory.rs`) |

---

## 1. What the sources actually do

### 1.1 MiroFish

An agent-swarm simulator: extract entities → build profiles → run two social
platforms in parallel → ingest every action into a temporal memory graph →
report. The parts that matter here:

1. **Plane-level fanout.** `backend/scripts/run_parallel_simulation.py:1585`
   runs `run_twitter_simulation` and `run_reddit_simulation` under a single
   `asyncio.gather`, each with its own round loop (`:1228`, `:1427`). The planes
   are independent: they share a start and a stop, not a per-round lockstep.
   Line `:399` is the same pattern one level down, inside a platform.
2. **Round-based stepping with a per-round journal.**
   `action_logger.log_round_start(round_num + 1, …)` / `log_round_end(round_num +
   1, count)` bracket every round; each agent action is a dataclass record
   (`AgentAction`: round, timestamp, platform, agent, action_type, args, result,
   success). The log is the run's ground truth, separate from the UI.
3. **A command/response IPC with explicit failure semantics.**
   `backend/app/services/simulation_ipc.py` — the orchestrator writes
   `ipc_commands/<uuid>.json` and polls `ipc_responses/<uuid>.json` every 0.5 s
   up to a timeout (`:117–187`), then removes both files; a timeout raises rather
   than an empty answer. Command types are a closed enum (`:25`).
4. **A background ingest queue with batching and a dead-letter list.**
   `zep_graph_memory_updater.py`: `Queue` + daemon `threading.Thread` (`:266`,
   `:304`), `BATCH_SIZE`, `_failed_batches`, and a bounded drain
   (`_DrainDeadlineExceeded`). Memory writing is off the simulation's critical
   path but is not allowed to hang shutdown.
5. **Retry with exponential backoff and jitter** (`backend/app/utils/retry.py`),
   applied to everything that talks to an external service.
6. **A state machine plus bounded graceful shutdown.** `SimulationStatus` /
   `RunnerStatus` enums, `asyncio.Event` for stop, and a `SimulationStopPending`
   guard so "stop" waits for a bounded finalization instead of dropping it.
7. **God's-eye injection**: variables can be pushed into a running world without
   restarting it.

### 1.2 Kronos

A foundation model for financial series: a BSQ tokenizer plus an autoregressive
transformer. Its concurrency lessons are about *batched, bounded, deterministic
execution*:

1. **Batch dimension as a first-class axis.** `predict_batch`
   (`model/kronos.py:562`) normalizes per series (`x_mean`/`x_std` per input,
   `:544`) and issues one forward pass set for the whole batch.
2. **Sample fan-out.** `auto_regressive_inference` (`:389`) repeats each input
   `sample_count` times along a new axis (`:394`) and averages afterwards —
   N stochastic samples of one input, computed together, not N sequential runs.
3. **Bounded context with a ring buffer.** `pre_buffer`/`post_buffer` of
   `max_context` (`:408–414`), with the window slid by index arithmetic
   (`context_start = max(0, context_end - max_context)`, `:433`). Long horizons
   do not grow memory.
4. **Device auto-detect and single placement decision**
   (`cuda` → `mps` → `cpu`, `:495–503`), made once at construction.
5. **`torch.no_grad()` and no cross-iteration state** — each step is a pure
   function of the buffer and the stamps.
6. **Rank-seeded RNG under DDP** (`finetune/utils/training_utils.py:set_seed`):
   `seed + rank`, so workers differ but every worker is reproducible.
7. **Golden regression fixtures** (`tests/data/regression_output_256.csv`) that
   pin exact outputs at fixed context lengths.

---

## 2. The synthesis

The two repos answer different halves of the same question.

MiroFish answers **"how do independent planes run side by side without one
blocking the other, and how do you reconstruct what happened?"** Its answer:
independent pacing, a per-round journal, an out-of-path ingest queue, and IPC
that fails loudly.

Kronos answers **"how do you execute a lot of similar work with bounded
resources and reproducible output?"** Its answer: a batch axis, fan-out samples,
a ring-buffered bounded state, one placement decision, and rank-derived seeds.

Tallow's mesh execution plane is MiroFish's *plane and journal* wrapped around
Kronos's *batch and bounded state*, with one addition neither repo has: the
result must be **checkable** — the same wave, replayed from its journal and
seeds, must produce the same hash on a different node.

### 2.0 Architecture

```
                         ┌──────────────────────────────────────────┐
                         │  control plane  (MiroFish god's-eye)     │
                         │  pause · resume · inject · stop · status │
                         └───────────────┬──────────────────────────┘
                                         │ commands (idempotency key + TTL)
┌────────────────────────────────────────▼───────────────────────────────────┐
│ COORDINATOR                                                                 │
│   plan() ──► waves ──► placement ──► leases ──► barriers ──► checkpoints    │
│      │           │          │            │                       │         │
│      │           │          │            │                       ▼         │
│      │           │          │            │              journal.jsonl      │
│      │           │          │            │            (append-only, BLAKE3)│
│      │           │          │            ▼                                 │
│      │           │          │      ┌─────────── lease table (epoch) ──────┐│
│      │           │          │      │ task  worker  epoch  expires_at      ││
│      │           │          │      └──────────────────────────────────────┘│
│      │           │          ▼                                              │
│      │           │   capacity + locality + class policy                    │
│      │           ▼                                                        │
│      │     wave batch  ──one message per slice──►  WORKERS                 │
│      │                                              ┌───────────────────┐  │
│      ▼                                              │ w1  executor      │  │
│  task graph (deps)                                  │ w2  executor      │  │
│  pure · io · llm                                    │ w3  executor      │  │
│                                                     └─────────┬─────────┘  │
│                                                               │ activities │
│  ┌──────────────── memory plane ──────────────────────────────▼───────────┐│
│  │ bounded queue ─► batcher (64 or 250 ms) ─► graph writer ─► graph       ││
│  │      │ drop-oldest (counted)                        │                  ││
│  │      └────────────────► retry(N) ─► dead-letter ◄────┘                 ││
│  └────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
        topology plane (existing src/stdlib/mesh.rs): membership · gossip · DHT
```

The arrow that matters: nothing in the memory plane is on the path between a
lease and its result, so a slow graph writer slows the run's *memory*, never its
*progress*.

### 2.1 Core objects

```
MeshNode (extends the existing topology node)
  id, role ∈ {coordinator, worker, observer}, capacity, epoch

Wave        the unit of batching and of barrier
  index, tasks[], seed, deadline

Task        one unit of work
  id, fn, args, deps[], seed, attempt, idempotency_key, class ∈ {pure, io, llm}

Lease       temporary ownership of a task by a worker
  task_id, worker_id, epoch, expires_at

Shard       a deterministic partition of a task's input space
  index, count, seed = H(mesh_seed, wave, shard_index)

Journal     append-only events: wave_start, task_leased, task_done,
            task_failed, task_retried, checkpoint, wave_end
```

`Task.class` is load-bearing and must be declared, not inferred:

- `pure` — replayable. Re-executing must produce a byte-identical result hash.
- `io` — side effects; may be retried only if `idempotency_key` is set.
- `llm` — non-deterministic by nature; the journal stores the **response**, and
  replay substitutes the recorded response instead of calling again.

A run that mixes classes without declaring them is rejected at plan time. This
is the Tallow rule applied to concurrency: a refusal is visible, a silent
re-execution is not.

### 2.2 Execution model: waves, not threads

The scheduler topologically sorts the task graph into **waves**. A wave contains
only tasks with satisfied dependencies, so everything in it is independent by
construction — that is what makes batching safe.

```
plan(tasks) → waves[]
for wave in waves:
    journal(wave_start, wave.index, wave.seed)
    leases = place(wave.tasks, workers)      # capacity + locality
    results = gather(leases, deadline)       # structured concurrency
    journal(checkpoint, wave.index, hash(results))
    journal(wave_end, wave.index)
```

Within a wave, dispatch is **batched** (Kronos' batch axis): N tasks go to one
worker in one message, not N messages. Across waves there is a barrier only when
the graph requires it; sibling waves with no dependency edge may overlap, which
is MiroFish's independent pacing applied at the wave level.

### 2.3 Determinism contract

Three seeds, all derived, never random:

```
task_seed  = H(mesh_seed || wave.index || task.id || attempt)
shard_seed = H(mesh_seed || wave.index || shard.index)
sample_i   = H(task_seed || "sample" || i)
```

`H` is BLAKE3 (already a dependency). Consequences:

- A retry on another worker produces the same `pure` result.
- Sample fan-out (Kronos' `sample_count`) yields the same N samples regardless
  of which worker ran them.
- A replay fixture is just `(journal, mesh_seed)`; `mesh replay <journal>` must
  print the same checkpoint hashes or fail the build.

Acceptance: the same 200-task plan run with `--workers 1` and `--workers 8`
produces identical checkpoint hashes and identical result ordering.

### 2.4 Failure, retry, stragglers

- **Lease + epoch fencing.** A worker holds a task only until `expires_at`
  (default `3 × p95(task_class)`). Reassignment increments `epoch`; a result
  arriving from an older epoch is discarded, not merged. This is what stops the
  classic duplicate-write bug that file-queue systems get when a worker stalls
  and wakes up.
- **Retry**: exponential backoff with jitter (MiroFish `retry.py`), bounded by
  attempts per class; `pure` may retry freely, `io` only with an idempotency
  key, `llm` never silently.
- **Stragglers**: after `straggler_after` (default 2 × median), the scheduler may
  issue a *speculative duplicate* under a new epoch and take the first result —
  Kronos' sample fan-out used for latency rather than variance. Bounded by
  `speculation_budget` (default 10% of wave tasks) so a slow mesh degrades in
  cost, not in correctness.
- **Cancellation** propagates wave → task → worker; the existing agent-handle
  cancellation boundary (checked at function calls) is reused, so a task that
  calls nothing is not interruptible — documented, not hidden.

### 2.5 Memory plane

Every completed task emits an `Activity` record, batched by the ingest worker:

```
run → queue (bounded, drop-oldest with a counter) → batcher (N or 250 ms)
    → graph writer → on failure: retry(N) → dead-letter (queryable)
```

This is MiroFish's `ZepGraphMemoryUpdater` shape: off the critical path, batched,
with a dead-letter list rather than silent loss. The difference is that the
graph here is local (`agent_memory.rs` already exists) and every write carries
`(run_id, wave, task_id)` so a replay can reconstruct the graph deterministically.

Bounded: the queue drops oldest under pressure and increments
`mesh_memory_dropped_total`. Dropping is visible; that is the rule.

### 2.6 Control plane (MiroFish's god's-eye view)

Because a mesh is long-running, control must be an explicit API, not signals:

```
mesh.pause(run_id)            # no new waves; in-flight finish
mesh.resume(run_id)
mesh.inject(run_id, key, v)   # next wave sees v; recorded in the journal
mesh.stop(run_id, drain_ms)   # bounded drain, then cancel; SimulationStopPending analogue
mesh.status(run_id)           # counters + per-wave state
```

`inject` must be journalled with the wave index it took effect at, otherwise the
run is no longer replayable.

---

## 3. Language surface

No new keywords. The published surface stays at 36; the mesh is stdlib plus
attributes that already exist as a mechanism.

```tallow
// stdlib/mesh.tl  (declarations; implementations in src/stdlib/mesh_exec.rs)
struct MeshPlan   { run_id: String, waves: i64, tasks: i64, seed: String }
struct WaveStats  { index: i64, tasks: i64, leased: i64, retried: i64, speculative: i64, elapsed_ms: i64 }
struct RunStatus  { state: String, waves_done: i64, waves_total: i64, failed: i64, dropped_memory: i64 }

native fn Mesh.plan(tasks: []MeshTask, options: MeshOptions) -> Result<MeshPlan>
native fn Mesh.run(plan: MeshPlan) -> Result<MeshResult>
native fn Mesh.status(run_id: String) -> RunStatus
native fn Mesh.pause(run_id: String) -> Result<()>
native fn Mesh.resume(run_id: String) -> Result<()>
native fn Mesh.inject(run_id: String, key: String, value: String) -> Result<()>
native fn Mesh.stop(run_id: String, drain_ms: i64) -> Result<()>
native fn Mesh.replay(journal_path: String) -> Result<MeshResult>
```

```tallow
@mesh(parallel: 8, determinism: .replayable, memory: .batched(size: 64, flush_ms: 250))
@legal(basis: .public_data, purpose: "…", personal_data: false)
fn pipeline() {
    let plan = Mesh.plan(tasks, MeshOptions { max_parallel: 8, straggler_after_ms: 5000 })
    let out = Mesh.run(plan) match { Ok(r) -> r, Err(e) -> { bail "mesh: {e}" } }
    print(out.waves_done)
}
```

`@mesh` compiles to plan options; it is checked like `@legal` (a run without
`determinism` is refused when any task class is `pure` and results are compared).
Declarations land in `stdlib/mesh.tl`; the count moves 1,124 → 1,132, and the
surface gate must be updated in the same commit — the mechanism that caught the
1,118/1,124 drift applies here too.

---

## 4. Rust layout

```
src/mesh/
  mod.rs        MeshPlan, Wave, Task, TaskClass, plan() (topological waves)
  scheduler.rs  placement, capacity, speculation, straggler policy
  lease.rs      Lease, epoch fencing, expiry sweeper
  worker.rs     executor loop, task sandbox, cancellation, heartbeat
  journal.rs    append-only JSONL; replay(); checkpoint hashing (BLAKE3)
  memory.rs     bounded queue, batcher, dead-letter, graph writes
  control.rs    pause/resume/inject/stop, status counters
  wire.rs       Phase 3 only: framed protocol over the existing relay transport
src/stdlib/mesh_exec.rs   Value ⇄ struct marshalling; dispatch("Mesh", method)
stdlib/mesh.tl            declarations (published surface)
docs/architecture/tallow-mesh-execution-plane-2026-10-23.md   this file
```

Phase 1 is in-process: a worker pool of OS threads, each with its own
interpreter. It must be threads with separate interpreters, not threads sharing
one — `Value` contains `Rc<RefCell<…>>` and is not `Send`; a shared interpreter
would be a data race the compiler would refuse anyway.

---

## 5. Phases, each with an acceptance test

**M0 — plan and journal, no workers.** Topological waves, seeds, JSONL journal,
`Mesh.replay` over a journal with zero workers (pure functions only).
*Accept:* a 50-task diamond graph replays to identical checkpoint hashes; a
cyclic graph is rejected with a message naming the cycle.

**M1 — in-process workers.** Thread pool of N interpreters, leases with epochs,
retry with backoff, cancellation.
*Accept:* 200 tasks at `--workers 1` and `--workers 8` produce identical hashes;
a task that panics is retried and the run completes with `failed=1`; killing a
worker mid-wave re-leases its tasks and no task runs twice under one epoch.

**M2 — stragglers and speculation.** Straggler detection, duplicate under a new
epoch, first-result-wins, budget cap.
*Accept:* with one artificially slow task (sleep 5 s), wall time drops below the
serial bound and exactly one result is committed; the journal shows the
discarded epoch.

**M3 — memory plane and control.** Bounded ingest queue, batcher, dead letters,
pause/resume/inject/stop with drain.
*Accept:* 10,000 activities with a stalled writer drop oldest and report
`dropped_memory` accurately; `inject` before wave 3 appears in wave 3 only and
replay reproduces it; `stop` returns within `drain_ms + 500 ms`.

**M4 — real wire.** Replace simulated transport with framed messages over the
existing relay; the topology plane's `simulated: true` becomes `false` for nodes
that join a real mesh, and only then.
*Accept:* two processes on one host run a 500-task plan; killing one mid-run
finishes the plan on the survivor with the same final hash as a single-process
run.

---

## 6. Trade-offs, stated plainly

1. **Waves are a barrier.** Batching across a wave maximises throughput; it also
   means one slow task delays the wave unless speculation is on. Kronos has the
   same shape (one forward pass per step) and the same cost.
2. **Determinism costs a journal write per wave** and caps `llm` tasks to
   replaying recorded responses — a replay cannot re-ask a model and stay
   reproducible. That is a deliberate choice, not an oversight.
3. **At-least-once, not exactly-once.** Epoch fencing makes duplicate commits
   detectable, not impossible. `io` tasks need idempotency keys; the plan
   checker refuses to accept them without one.
4. **Speculation trades CPU for latency**, bounded at 10% of a wave; on a small
   mesh this is often a loss and should be off by default under 4 workers.
5. **Threads × interpreters cost memory** (~one process image each). A 16-worker
   pool on this box is ~16× the interpreter footprint; the design prefers few
   fat workers to many thin ones.
6. **Memory-plane drops under pressure** rather than blocking the run. The
   counter is the contract; a caller that needs every activity must raise the
   queue bound and accept the latency.
7. **Phase 4 is the only one that unlocks real distribution**, and it inherits
   every failure mode the simulation hid: partition, reordering, clock skew. The
   lease epoch exists because clock skew is inevitable, not exceptional.
8. **No new keywords means no syntactic sugar**: mesh composition reads like
   library calls. That is a real ergonomic cost, paid to keep the published
   surface stable.

---

## 7. Agent-ready instruction set

Execute in order. Every step ends with a command whose output decides the step.

1. `src/mesh/mod.rs`: `TaskClass`, `Task`, `Wave`, `plan()`. Topological sort;
   reject cycles naming the path. **Verify:** `cargo test --lib mesh::plan_`.
2. `src/mesh/journal.rs`: JSONL append, checkpoint hash = BLAKE3 over sorted
   `(task_id, result_hash)`. **Verify:** `cargo test --lib mesh::journal_replay_`.
3. `src/stdlib/mesh_exec.rs`: `Mesh.plan`, `Mesh.replay`; register in
   `src/stdlib/mod.rs`. **Verify:** `tallow run` on a fixture plan prints the
   same hashes twice (fixture under `tests/fixtures/mesh/`).
4. `src/mesh/lease.rs` + `worker.rs`: pool, epochs, sweep. **Verify:** the M1
   acceptance test as `tests/mesh_workers.rs`, `#[ignore]`d above 8 workers.
5. `src/mesh/scheduler.rs`: straggler + speculation + budget. **Verify:** M2 test.
6. `src/mesh/memory.rs` + `control.rs`. **Verify:** M3 test.
7. `stdlib/mesh.tl` declarations + `stdlib/mesh.rs` count gate update in one
   commit (1,124 → 1,132). **Verify:** `cargo test --locked --test language_surface`.
8. `src/mesh/wire.rs`: framed protocol over the relay; flip `simulated` only for
   real nodes. **Verify:** M4 two-process test.

Do not mark a phase complete on a passing unit test alone: each acceptance test
in §5 is the gate, and each is a real run whose output is quoted in the commit
message.

---

## 8. Provenance of each adopted idea

| idea | source (file:line) | how Tallow uses it |
| --- | --- | --- |
| independent plane pacing | `run_parallel_simulation.py:1585` | sibling waves overlap when no dependency edge |
| per-round journal | `action_logger.log_round_start/end` | wave journal + checkpoint hash |
| uuid command envelope, poll, timeout, cleanup | `simulation_ipc.py:117–187` | control-plane command with idempotency key + TTL |
| background batched ingest with dead letters | `zep_graph_memory_updater.py:266,304` | memory plane queue/batcher/dead-letter |
| exponential backoff with jitter | `utils/retry.py` | retry policy per task class |
| state machine + bounded shutdown | `SimulationStatus`, `SimulationStopPending` | `mesh.stop(drain_ms)` |
| god's-eye injection | README feature 3 / API | `mesh.inject`, journalled per wave |
| batch axis | `kronos.py:562` | one message per wave slice, not per task |
| sample fan-out | `kronos.py:394` | replicated samples for statistics and speculation |
| bounded context ring buffer | `kronos.py:408–414` | bounded per-task state; journal compaction |
| per-series normalization | `kronos.py:544` | per-shard unit-cost estimates for placement |
| single placement decision | `kronos.py:495–503` | capability chosen once per worker at join |
| rank-seeded RNG | `training_utils.py:set_seed` | `task_seed = H(seed, wave, id, attempt)` |
| golden regression fixtures | `tests/data/regression_output_256.csv` | replay fixtures pin checkpoint hashes |

---

## 9. Decision: speculation stays in-process (B3, 2026-10-23)

**Decision.** Speculative duplicates are issued only by the coordinator that owns the
wave. They are never sent to another node by the coordinator, and the wire protocol has
no `speculate` frame. A remote node receives a task only through an epoch lease; when
that lease expires the task is reassigned to a node that is still heartbeating.

**Why.** The two mechanisms answer different failures, and mixing them would make one
unprovable:

- *Speculation* answers "this attempt is slow but the node is alive". The duplicate runs
  in-process under a new epoch, the first commit wins, and the slower attempt is fenced
  by lease epoch. Cost: duplicated work, bounded by `budget_fraction` per wave.
- *Reassignment* answers "this node is gone or unresponsive". Cost: one lease expiry of
  latency, no duplicated execution on a healthy node.

Sending duplicates across the wire would make every node's journal contain results it
did not produce, which breaks `Mesh.replay`: the replay would have to know whether a
commit came from the holder or a duplicate. Keeping duplicates local means the journal's
`task_committed` line is always the commit of the attempt that won, and a remote node's
journal is a record of leases it was granted and results it returned.

**Consequence, stated as a limit.** Speculation cannot hide the latency of a node that is
alive but slow — only reassignment can, and only after the lease expires. That is the
intended trade: a lease is a promise about a time window, not about a task.

**Implementation note.** The duplicate's target worker is chosen to be different from the
slot holding the straggler (`919ca8e`); round-robin dispatch could otherwise queue the
duplicate behind the stall it exists to escape, which was measured at 5.0005 s on a
2-core runner.
