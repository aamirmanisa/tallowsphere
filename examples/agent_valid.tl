// @agent_task annotation examples.
//
// An agent function declares its autonomy level, a resource budget, and its
// permission flags; @legal is required on every agent (E0805).
//   L3 (Reactive)   - branching, write/store; cannot spawn children
//   L4 (Autonomous) - may spawn children; must declare a resource budget
//
// Note: `can_spawn: true` on an L3 agent is a compile error (E0623).
//
// Run: tallow run examples/agent_valid.tl

// A plain L3 analyst: strict permission boundaries, budget-capped.
@agent_task(
    id:           task_id,
    timeout:      30.seconds,
    level:        .L3,
    max_requests: 50,
    can_write:    false,
    can_store:    false,
    can_spawn:    false,
    memory_limit: 64.mb
)
@legal(basis: .public_data, purpose: "public market data analysis")
fn analyze_sector(sector: String) -> String {
    // Runs sandboxed: no disk writes, no child agents, killed after 30s.
    "sector {sector}: trend growing, confidence 0.85, sources 3"
}

// An L4 orchestrator: allowed to call (spawn) the L3 analyst above.
@agent_task(
    id:           task_id,
    timeout:      2.minutes,
    level:        .L4,
    can_spawn:    true,
    max_requests: 200,
    memory_limit: 128.mb
)
@legal(basis: .research, purpose: "multi-sector market intelligence")
fn orchestrate(sector: String) -> String {
    let child_report = analyze_sector(sector)
    "orchestrated report -> " + child_report
}

fn main() {
    print("=== @agent_task examples ===")

    print(analyze_sector("semiconductors"))

    print(orchestrate("AI infrastructure"))

    print("All agents stayed inside their declared permission boundaries.")
}
