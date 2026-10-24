// tallow.mesh — deterministic task planning and journal replay
//
// The execution plane's published surface. Two functions, both of which run
// today and both of which are pure with respect to their inputs:
//
//   Mesh.plan(tasks, seed)   topological waves, cycles refused by name
//   Mesh.run(tasks, workers, journal, seed)  execute those tasks
//   Mesh.replay(path)        verify a journal against its own checkpoints
//
// `Mesh.run` executes functions of the calling program: every task names one,
// each runs in its own interpreter on a worker thread, and the coordinator
// supplies content-derived seeds, lease fencing and retries by task class.
// Topology (membership, gossip, DHT) lives in `mesh` and runs over real TCP
// sockets: MeshNode.new binds a listener, join dials its bootstraps and
// exchanges a hello, broadcast and dht_put write frames to handshaken peers.
// See docs/architecture/tallow-mesh-execution-plane-2026-10-23.md §10-11.

/// One unit of work in a plan.
///
/// `class` decides what a retry means: `pure` may be retried and replayed,
/// `io` requires `idempotency_key` (refused without one), `llm` is never
/// retried silently because a retry would produce a different answer.
struct MeshTask {
    id:              String,
    func:            String,
    deps:            []String,
    class:           String,
    idempotency_key: String?,
}

/// The wave layout of a plan.
struct MeshPlan {
    /// Number of waves; a wave contains only tasks whose dependencies are met.
    waves:      i64,
    /// Number of tasks in the plan.
    tasks:      i64,
    /// The seed the plan was derived from.
    seed:       i64,
    /// Task count per wave, in wave order.
    wave_sizes: []i64,
}

/// One verified checkpoint from a replayed journal.
struct WaveCheckpoint {
    wave:       i64,
    tasks:      i64,
    checkpoint: String,
}

/// The result of replaying a journal.
struct MeshReplay {
    waves:       i64,
    ok:          bool,
    checkpoints: []WaveCheckpoint,
}

/// The result of executing a plan.
struct MeshRun {
    /// Waves executed.
    waves:      i64,
    /// Tasks that committed a result.
    committed:  i64,
    /// Tasks that exhausted their attempts.
    failed:     i64,
    /// The journal the run wrote (and which `Mesh.replay` verifies).
    journal:    String,
}

/// Execute a plan.
///
/// Every task names a function defined in this program; each task runs in its
/// own interpreter on a worker thread, with the seed, retry policy and
/// checkpoint derived from the plan — not from the clock. `failed > 0` means at
/// least one task exhausted its attempts; the journal names which.
native fn run(tasks: []MeshTask, workers: i64, journal: String, seed: i64) -> MeshRun

/// Sort tasks into waves.
///
/// Validates every task (rejecting an `io` task without an idempotency key),
/// rejects a missing dependency or a duplicate id, and refuses a dependency
/// cycle with the path that forms it, e.g. `a -> b -> a`.
native fn plan(tasks: []MeshTask, mesh_seed: i64) -> MeshPlan

/// Recompute every checkpoint in a journal and compare it with what was
/// recorded. Returns the first wave that disagrees — a replay that "mostly"
/// matches is a failed replay, not a partial success.
native fn replay(journal_path: String) -> MeshReplay
