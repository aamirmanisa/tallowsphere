// tallow.agent — Agent task runtime
//
// Runtime support for @agent_task annotated functions.
// Provides sandboxing, resource tracking, and inter-agent communication.

/// Agent task handle
struct AgentHandle<T> {
    id:     String,
    status: AgentStatus,
}

/// Agent execution status
enum AgentStatus {
    Pending,
    Running,
    Completed,
    Failed(error: String),
    TimedOut,
    Cancelled,
}

impl AgentHandle<T> {
    /// Wait for agent to complete
    // native: blocks until agent finishes
    native fn await(self) -> Result<T>

    /// Wait with custom timeout (cannot exceed @agent_task timeout)
    // native: blocks with timeout
    native fn await(self, timeout: Duration) -> Result<T>

    /// Cancel the agent
    // native: signals cancellation
    native fn cancel(self) -> Result<()>

    /// Check if completed
    native fn is_done(self) -> bool

    /// Get status
    // native: checks current status
    native fn status(self) -> AgentStatus
}

/// Spawn an agent function (requires can_spawn permission)
// native: starts agent in sandboxed environment
native fn spawn<T>(f: fn() -> T) -> AgentHandle<T>

/// Spawn a named agent
// native: starts named agent
native fn spawn_agent<T>(name: String, f: fn() -> T) -> AgentHandle<T>

/// Wait for all agents to complete
// native: waits for all to finish
native fn await_all<T>(handles: []AgentHandle<T>) -> []Result<T>

/// Wait for first agent to complete
// native: returns index and result of first to finish
native fn await_any<T>(handles: []AgentHandle<T>) -> (usize, Result<T>)

/// Run functions in parallel, collect results
// native: spawns one agent per item, collects results
native fn parallel_map<T, R>(items: []T, f: fn(T) -> R) -> []R

/// Agent resource usage stats
struct AgentStats {
    memory_used:    u64,
    requests_made:  u32,
    elapsed:        Duration,
    cpu_time:       Duration,
}

/// Get stats for current agent
// native: returns resource usage
native fn current_stats() -> AgentStats

// ═══════════════════════════════════════════════════════════════════
// Phase 40: Incident Response & SOAR types
// ═══════════════════════════════════════════════════════════════════

/// SOAR playbook — compiled from YAML-like definition
struct Playbook {
    name:     String,
    trigger:  String,
    steps:    []String,
    compiled: bool,
}

/// Result of executing a playbook
struct PlaybookResult {
    playbook_name: String,
    context:       String,
    status:        String,
    actions_taken: []String,
    actions_count: u32,
}

/// Compile a YAML-like playbook definition
// native: parses name/trigger/steps from line-based YAML
native fn Playbook.compile(yaml: String) -> Playbook

/// Execute a compiled playbook with the given context
// native: runs each step, returns result with actions taken
native fn Playbook.execute(playbook: Playbook, context: String) -> PlaybookResult

/// Validate a playbook has required fields (name, steps, compiled)
// native: checks name non-empty, steps non-empty, compiled=true
native fn Playbook.validate(playbook: Playbook) -> bool

/// Security alert for triage and escalation
struct Alert {
    id:                  String,
    source:              String,
    severity:            String,
    description:         String,
    status:              String,
    priority:            String,
    assigned_to:         String,
    recommended_actions: []String,
    created_at:          String,
}

/// Create a new alert
// native: generates id, sets status=new
native fn Alert.create(source: String, severity: String, description: String) -> Alert

/// Triage an alert — assigns priority, analyst, recommended actions based on severity
// native: critical→P1/soc-lead, high→P2/senior-analyst, medium→P3/analyst, low→P4/junior-analyst
native fn Alert.triage(alert: Alert) -> Alert

/// Escalate an alert — bumps severity one level up, appends reason
// native: low→medium, medium→high, high→critical
native fn Alert.escalate(alert: Alert, reason: String) -> Alert

/// Indicator of Compromise scanner
struct IOCScanner {
    indicators:      []IOC,
    indicator_count: u32,
}

/// Single indicator of compromise
struct IOC {
    type:  String,   // "ip", "domain", "hash", "url", "email"
    value: String,
}

/// Match result from IOC scanning
struct IOCMatch {
    type:  String,
    value: String,
    found: bool,
}

/// Create an empty IOC scanner
// native: returns scanner with empty indicator list
native fn IOCScanner.create() -> IOCScanner

/// Add an indicator to the scanner (immutable update)
// native: validates type in ip,domain,hash,url,email, appends indicator
native fn IOCScanner.add_indicator(scanner: IOCScanner, ioc_type: String, value: String) -> IOCScanner

/// Scan data string for all registered IOCs (string contains matching)
// native: returns array of matches where data contains indicator value
native fn IOCScanner.scan(scanner: IOCScanner, data: String) -> []IOCMatch

/// Result of a containment action (all actions are simulated)
struct ContainmentResult {
    action:    String,
    target:    String,
    success:   bool,
    simulated: bool,
    timestamp: String,
    message:   String,
}

/// Simulate host isolation
// native: simulated — logs action, returns success
native fn ContainmentAction.isolate_host(hostname: String) -> ContainmentResult

/// Simulate IP blocking
// native: simulated — logs action, returns success
native fn ContainmentAction.block_ip(ip: String) -> ContainmentResult

/// Simulate account disabling
// native: simulated — logs action, returns success
native fn ContainmentAction.disable_account(account: String) -> ContainmentResult

/// Simulate file quarantine
// native: simulated — logs action, returns success
native fn ContainmentAction.quarantine_file(path: String) -> ContainmentResult

/// Incident timeline for event reconstruction
struct IncidentTimeline {
    incident_id: String,
    events:      []TimelineEvent,
    event_count: u32,
    created_at:  String,
}

/// Single event in a timeline
struct TimelineEvent {
    timestamp:   String,
    description: String,
    source:      String,
}

/// Create a new incident timeline
// native: creates empty timeline
native fn IncidentTimeline.create(incident_id: String) -> IncidentTimeline

/// Add an event to the timeline (immutable update)
// native: appends event, increments count
native fn IncidentTimeline.add_event(timeline: IncidentTimeline, timestamp: String, description: String, source: String) -> IncidentTimeline

/// Export timeline to JSON string
// native: serializes to JSON
native fn IncidentTimeline.export(timeline: IncidentTimeline) -> String

/// Threat hunt result
struct HuntResult {
    data_source: String,
    query:       String,
    match_count: u32,
    matches:     []HuntMatch,
}

/// Single match from a threat hunt query
struct HuntMatch {
    keyword:     String,
    data_source: String,
    confidence:  f64,
}

/// Correlated findings from multiple hunt results
struct CorrelationResult {
    sources:             []String,
    total_matches:       u32,
    unique_indicators:   u32,
    correlation_score:   f64,
    severity:            String,
}

/// Execute a threat hunting query against a data source
// native: simulated query — matches based on keywords
native fn ThreatHunt.query(data_source: String, query_string: String) -> HuntResult

/// Correlate results from multiple threat hunts
// native: aggregates sources, counts, computes correlation score
native fn ThreatHunt.correlate(results: []HuntResult) -> CorrelationResult
