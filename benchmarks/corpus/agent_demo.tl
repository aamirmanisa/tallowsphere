// Tallow Agent Demo (v0.2)
// Autonomous agents with compile-time safety guarantees
//
// Run: tallow run examples/agent_demo.tl

// A research agent with strict permission boundaries
@agent_task(
    id:           task_id,
    timeout:      30.seconds,
    max_requests: 50,
    can_write:    false,
    can_store:    false,
    can_spawn:    false,
    memory_limit: 128.mb
)
@legal(basis: .research, purpose: "public market data analysis")
fn analyze_market(sector: String) -> String {
    // Agent runs in sandboxed environment
    // Cannot write to disk (can_write: false)
    // Cannot spawn children (can_spawn: false)
    // Auto-killed after 30 seconds
    let report = "Market analysis for: {sector}\n"
    let data = "  Trend: Growing\n  Confidence: 0.85\n  Sources: 3 public APIs"
    report + data
}

// An orchestrator that can spawn sub-agents
@agent_task(
    id:           task_id,
    level:        .L4,
    timeout:      2.minutes,
    max_requests: 200,
    can_spawn:    true,
    memory_limit: 256.mb
)
@legal(basis: .research, purpose: "multi-sector market intelligence")
fn orchestrate(sectors: String) -> String {
    // This agent CAN spawn children (can_spawn: true)
    let result = analyze_market(sectors)
    result
}

fn main() {
    print("=== Tallow Agent System ===")
    print("")

    // Direct agent call
    let report = analyze_market("semiconductors")
    print(report)

    print("")

    // Orchestrated call
    let full_report = orchestrate("AI infrastructure")
    print(full_report)

    print("")
    print("All agents completed within permission boundaries.")
}
