// Tallow Standard Library — Safety-Critical Systems (Phase 44)
// Safety-critical runtime types: redundancy voting, watchdogs, state machines,
// fail-safe defaults, and ICS protocol simulators.
//
// All types are interpreter sentinels — no stdlib module dispatch needed.

// ── Annotations ──────────────────────────────────────────────────────────────
// @no_heap          — function cannot use heap allocation (E2600)
// @no_recursion     — function cannot call itself directly/indirectly (E2601)
// @bounded_by(N)    — all loops must be bounded (E2602-E2604)
// @safety_critical  — existing SIL/ASIL/DAL lattice enforcement

// ── Redundancy — N-modular redundancy voting (TMR pattern) ──────────────────
// Redundancy.vote(values: []T) -> T
//   Returns the majority value via triple-modular redundancy.
//   If no majority exists, returns the first value.

struct RedundancyResult {
    value:     String,
    votes:     i64,
    total:     i64,
    unanimous: bool,
}

// ── Watchdog — Software watchdog timer ──────────────────────────────────────
// Watchdog.create(timeout_ms: i64) -> Watchdog
// Watchdog.kick(watchdog: Watchdog) -> Watchdog  (refreshed)
// Watchdog.check(watchdog: Watchdog) -> bool     (true = expired)

struct Watchdog {
    id:          String,
    timeout_ms:  i64,
    started_at:  i64,
    last_kick:   i64,
    expired:     bool,
}

// ── StateMachine — Verified state transitions ───────────────────────────────
// StateMachine.create(name: String, initial_state: String) -> StateMachine
// StateMachine.add_transition(fsm: StateMachine, from: String, to: String, guard: String) -> StateMachine
// StateMachine.transition(fsm: StateMachine, target: String) -> StateMachineResult

struct StateMachine {
    name:          String,
    current_state: String,
    transitions:   []StateTransition,
    history:       []String,
}

struct StateTransition {
    from:  String,
    to:    String,
    guard: String,
}

struct StateMachineResult {
    success:       bool,
    previous:      String,
    current:       String,
    error_message: String,
}

// ── FailSafe — Fail-safe default behavior ───────────────────────────────────
// FailSafe.create(safe_value: T) -> FailSafe
// FailSafe.execute(failsafe: FailSafe, result: T) -> T
//   Returns result if valid, safe_value on error/nil.

struct FailSafe {
    safe_value:    String,
    trigger_count: i64,
    total_calls:   i64,
}

struct FailSafeResult {
    value:       String,
    used_safe:   bool,
    safe_value:  String,
}

// ── ICS Protocol Types (simulated) ──────────────────────────────────────────
// Modbus.read_register(address: i64) -> ModbusResult
// Dnp3.read_point(address: i64) -> Dnp3Result
// OpcUa.read_node(node_id: String) -> OpcUaResult

struct ModbusResult {
    address:  i64,
    value:    i64,
    status:   String,
    protocol: String,
}

struct Dnp3Result {
    address:  i64,
    value:    i64,
    quality:  String,
    protocol: String,
}

struct OpcUaResult {
    node_id:   String,
    value:     i64,
    status:    String,
    timestamp: String,
    protocol:  String,
}
