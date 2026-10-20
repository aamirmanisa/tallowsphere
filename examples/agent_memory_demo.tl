// Tallow Agent Memory Demo (v0.2)
// Brain with 4 memory regions on SQLite
//
// Run: tallow run examples/agent_memory_demo.tl

@agent_task(
    id:           task_id,
    timeout:      30.seconds,
    max_requests: 10,
    can_write:    true,
    can_store:    true,
    can_spawn:    false,
    memory_limit: 128.mb,
    autonomy:     3
)
@legal(basis: .research, purpose: "demonstrate agent memory system")
fn memory_agent(task: String) -> String {
    // Agent has a Brain with 4 memory regions:
    //   working  — fast short-term (VecDeque)
    //   episodic — event log (SQLite)
    //   semantic — knowledge graph (SQLite)
    //   procedural — learned skills (SQLite)

    // Working memory: fast key-value store
    brain.working.store("current_task", task)
    let recalled = brain.working.recall("current_task")
    print("Working memory: {recalled}")

    // Episodic memory: event journal
    brain.episodic.record("Started task: {task}")
    brain.episodic.record("Processing data...")
    brain.episodic.record("Task complete")
    let count = brain.episodic.count()
    print("Episodic entries: {count}")

    // Semantic memory: knowledge triples
    brain.semantic.store("Tallow", "is_a", "programming language")
    brain.semantic.store("Tallow", "has_feature", "compile-time privacy")
    brain.semantic.store("Tallow", "has_feature", "agent safety")
    let facts = brain.semantic.count()
    print("Semantic facts: {facts}")

    // Procedural memory: learned skills
    brain.procedural.store("greet", "fn greet(name) { print(name) }", "simple greeting")
    let skill = brain.procedural.recall("greet")
    print("Learned skill: {skill.name} (v{skill.version})")

    "Memory demo complete — all 4 regions operational"
}

fn main() {
    print("=== Tallow Agent Memory System ===")
    print("")

    let result = memory_agent("explore memory regions")
    print("")
    print(result)
}
