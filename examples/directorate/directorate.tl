// The Tallow Directorate — the five desks as one task graph, executed.
//
// `Mesh.plan` validates the graph (task classes, cycles, idempotency keys) and
// `Mesh.run` executes it: every task names a function in this program, each runs
// in its own interpreter on a worker thread, and the coordinator writes the
// journal. The one `llm`-class task is CARTOGRAPHER's brief: it calls a model
// through `llm.complete`, and the journal records the prompt hash, the response
// hash and — for public data only — the text, so the run is replayable without
// the model.
//
// Run: tallow run examples/directorate/directorate.tl
//
// The desks work on fixtures: this example must run with no network egress. It
// demonstrates the coordination and journal planes, not a collection system —
// the tools a desk would call (http, browser, detection) are separate modules
// with their own tests.

struct MeshTask {
    id:              String,
    func:            String,
    deps:            []String,
    class:           String,
    idempotency_key: String?,
}

fn task(id: String, func: String, deps: []String, class: String, key: String?) -> MeshTask {
    return MeshTask { id: id, func: func, deps: deps, class: class, idempotency_key: key }
}

// ── SENTINEL: evidence collection and grading ────────────────────────────────
fn sentinel_collect_iocs() -> String {
    // Two indicators from a fixture advisory. In production this is the body of
    // an `http` response; the hash is what the desk passes downstream.
    return provenance.hash_body("203.0.113.9\n198.51.100.7\n2001:db8::42")
}

fn sentinel_correlate() -> String {
    // Two independent sources agree on the first indicator; the desk records the
    // digest that both produced rather than asserting agreement.
    return provenance.hash_body("203.0.113.9")
}

fn sentinel_verdict() -> String {
    // Rule-based on purpose: a verdict that changes with a model's mood is not a
    // verdict. The llm path summarises; it does not decide.
    return "confidence=high; sources=2; dissent=none"
}

// ── CARTOGRAPHER: enumerating and describing the surface ─────────────────────
fn cartographer_enumerate() -> String {
    return provenance.hash_body("example.invalid:443,example.invalid:80,api.example.invalid:8443")
}

fn cartographer_compare() -> String {
    return "added=api.example.invalid:8443; removed=none; unchanged=2"
}

// The only model call in the graph. The prompt is a fixed template so a replay
// can hash it; the response is recorded by the mesh journal.
fn cartographer_brief() -> String {
    let c = llm.complete(
        "local",
        "MiniCPM",
        "Summarise in one sentence, without speculation: the exposed surface is example.invalid:443, example.invalid:80, api.example.invalid:8443; one endpoint was added since the previous sweep.",
        256
    )
    return c.text
}

// ── ORACLE: cryptographic inventory and exposure ─────────────────────────────
fn oracle_inventory_crypto() -> String {
    return provenance.hash_body("tls1.3:aes_256_gcm;tls1.3:chacha20_poly1305;rsa:2048")
}

fn oracle_exposure_model() -> String {
    return "rsa:2048=deprecated-by-2030;aead=ok;pqc=absent"
}

fn oracle_migration_order() -> String {
    return "1:rsa:2048->ecdsa_p256;2:enable-x25519mlkem768;3:rotate-certs"
}

// ── GHOST: data classification and plane choice ──────────────────────────────
fn ghost_classify_data() -> String {
    return "class=public;personal=false;retention=90d"
}

fn ghost_plane_choice() -> String {
    // The plane follows the classification, not convenience.
    return "plane=clearnet;reason=public data;memory=in-process"
}

// ── QUARTERMASTER: observation, diagnosis, plan, execution ───────────────────
fn quartermaster_observe() -> String {
    // A real observation of this process, not a placeholder number.
    let pid = process.pid()
    return "pid={pid};workers=2"
}

fn quartermaster_diagnose() -> String {
    return "no saturation;queue=depth 0"
}

fn quartermaster_plan() -> String {
    return "wave1:migrate-signing;wave2:enable-hybrid-kex;wave3:rotate"
}

fn quartermaster_execute() -> String {
    // Execution against a real target needs an idempotency key, which the graph
    // supplies; here the target is a journal entry, so the step is a dry run
    // that still has to be journalled.
    return "executed=0;skipped=3;reason=dry-run"
}

@legal(
    basis:         .public_data,
    purpose:       "plan and execute the directorate's evidence, judgement and action waves",
    personal_data: false
)
fn main() {
    let all = [
        task("sentinel.collect_iocs",   "sentinel_collect_iocs",   [], "io",   "sentinel/collect/iocs"),
        task("cartographer.enumerate",  "cartographer_enumerate",  [], "io",   "cartographer/enumerate"),
        task("oracle.inventory_crypto", "oracle_inventory_crypto", [], "pure", nil),
        task("ghost.classify_data",     "ghost_classify_data",     [], "pure", nil),
        task("quartermaster.observe",   "quartermaster_observe",   [], "pure", nil),

        task("sentinel.correlate",      "sentinel_correlate",      ["sentinel.collect_iocs"],   "pure", nil),
        task("cartographer.compare",    "cartographer_compare",    ["cartographer.enumerate"],  "pure", nil),
        task("oracle.exposure_model",   "oracle_exposure_model",   ["oracle.inventory_crypto"], "pure", nil),
        task("ghost.plane_choice",      "ghost_plane_choice",      ["ghost.classify_data"],     "pure", nil),
        task("quartermaster.diagnose",  "quartermaster_diagnose",  ["quartermaster.observe"],   "pure", nil),

        task("oracle.migration_order",  "oracle_migration_order",  ["oracle.exposure_model", "ghost.plane_choice"], "pure", nil),
        task("cartographer.brief",      "cartographer_brief",      ["cartographer.compare", "quartermaster.diagnose"], "llm", nil),
        task("sentinel.verdict",        "sentinel_verdict",        ["sentinel.correlate", "ghost.plane_choice"], "pure", nil),

        task("quartermaster.plan",      "quartermaster_plan",      ["oracle.migration_order", "cartographer.brief", "sentinel.verdict"], "pure", nil),
        task("quartermaster.execute",   "quartermaster_execute",   ["quartermaster.plan"], "io", "quartermaster/execute"),
    ]

    let plan = Mesh.plan(all, 20261023)
    print(plan.waves)
    print(plan.wave_sizes)

    let journal = ".tallow/directorate.jsonl"
    let run = Mesh.run(all, 2, journal, 20261023)
    print(run.committed)
    print(run.failed)

    let replayed = Mesh.replay(journal)
    print(replayed.ok)
}
