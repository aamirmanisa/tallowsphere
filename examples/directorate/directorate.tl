// The Tallow Directorate — the five desks as one task graph.
//
// This is the coordination layer, executed for real: `Mesh.plan` validates every
// task class, refuses cycles by path, and returns the wave layout the directorate
// would run. The tools each desk calls live in stdlib/ (detection, crypto,
// browser, http, process, …); cognition, when attached, is an `llm`-class task
// recorded in the journal rather than a hidden guess.
//
// Run: tallow run examples/directorate/directorate.tl
// The output is deterministic: the same plan yields the same wave sizes.

struct MeshTask {
    id:              String,
    func:            String,
    deps:            []String,
    class:           String,
    idempotency_key: String?,
}

fn task(id: String, deps: []String, class: String, key: String?) -> MeshTask {
    return MeshTask { id: id, func: id, deps: deps, class: class, idempotency_key: key }
}

@legal(
    basis:         .public_data,
    purpose:       "plan the directorate's evidence, judgement and action waves",
    personal_data: false
)
fn main() {
    // One literal: the plan is a single graph, and the desks are its waves.
    let all = [
        task("sentinel.collect_iocs",    [], "io",   "sentinel/collect/iocs"),
        task("cartographer.enumerate",   [], "io",   "cartographer/enumerate"),
        task("oracle.inventory_crypto",  [], "pure", nil),
        task("ghost.classify_data",      [], "pure", nil),
        task("quartermaster.observe",    [], "pure", nil),

        task("sentinel.correlate",     ["sentinel.collect_iocs"],   "pure", nil),
        task("cartographer.compare",   ["cartographer.enumerate"],  "pure", nil),
        task("oracle.exposure_model",  ["oracle.inventory_crypto"], "pure", nil),
        task("ghost.plane_choice",     ["ghost.classify_data"],     "pure", nil),
        task("quartermaster.diagnose", ["quartermaster.observe"],   "pure", nil),

        task("oracle.migration_order", ["oracle.exposure_model", "ghost.plane_choice"], "pure", nil),
        task("cartographer.brief",     ["cartographer.compare", "quartermaster.diagnose"], "llm", nil),
        task("sentinel.verdict",       ["sentinel.correlate", "ghost.plane_choice"], "pure", nil),

        task("quartermaster.plan",    ["oracle.migration_order", "cartographer.brief", "sentinel.verdict"], "pure", nil),
        task("quartermaster.execute", ["quartermaster.plan"], "io", "quartermaster/execute"),
    ]

    let plan = Mesh.plan(all, 20261023)
    print(plan.waves)
    print(plan.wave_sizes)
}
