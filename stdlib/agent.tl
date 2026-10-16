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
    fn await(self) -> Result<T> {
        // native: blocks until agent finishes
    }

    /// Wait with custom timeout (cannot exceed @agent_task timeout)
    fn await(self, timeout: Duration) -> Result<T> {
        // native: blocks with timeout
    }

    /// Cancel the agent
    fn cancel(self) -> Result<()> {
        // native: signals cancellation
    }

    /// Check if completed
    fn is_done(self) -> bool {
        match self.status {
            Completed -> true
            Failed(_) -> true
            TimedOut  -> true
            _         -> false
        }
    }

    /// Get status
    fn status(self) -> AgentStatus {
        // native: checks current status
    }
}

/// Spawn an agent function (requires can_spawn permission)
fn spawn<T>(f: fn() -> T) -> AgentHandle<T> {
    // native: starts agent in sandboxed environment
}

/// Spawn a named agent
fn spawn_agent<T>(name: String, f: fn() -> T) -> AgentHandle<T> {
    // native: starts named agent
}

/// Wait for all agents to complete
fn await_all<T>(handles: []AgentHandle<T>) -> []Result<T> {
    // native: waits for all to finish
}

/// Wait for first agent to complete
fn await_any<T>(handles: []AgentHandle<T>) -> (usize, Result<T>) {
    // native: returns index and result of first to finish
}

/// Run functions in parallel, collect results
fn parallel_map<T, R>(items: []T, f: fn(T) -> R) -> []R {
    // native: spawns one agent per item, collects results
}

/// Agent resource usage stats
struct AgentStats {
    memory_used:    u64,
    requests_made:  u32,
    elapsed:        Duration,
    cpu_time:       Duration,
}

/// Get stats for current agent
fn current_stats() -> AgentStats {
    // native: returns resource usage
}

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
fn Playbook.compile(yaml: String) -> Playbook {
    // native: parses name/trigger/steps from line-based YAML
}

/// Execute a compiled playbook with the given context
fn Playbook.execute(playbook: Playbook, context: String) -> PlaybookResult {
    // native: runs each step, returns result with actions taken
}

/// Validate a playbook has required fields (name, steps, compiled)
fn Playbook.validate(playbook: Playbook) -> bool {
    // native: checks name non-empty, steps non-empty, compiled=true
}

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
fn Alert.create(source: String, severity: String, description: String) -> Alert {
    // native: generates id, sets status=new
}

/// Triage an alert — assigns priority, analyst, recommended actions based on severity
fn Alert.triage(alert: Alert) -> Alert {
    // native: critical→P1/soc-lead, high→P2/senior-analyst, medium→P3/analyst, low→P4/junior-analyst
}

/// Escalate an alert — bumps severity one level up, appends reason
fn Alert.escalate(alert: Alert, reason: String) -> Alert {
    // native: low→medium, medium→high, high→critical
}

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
fn IOCScanner.create() -> IOCScanner {
    // native: returns scanner with empty indicator list
}

/// Add an indicator to the scanner (immutable update)
fn IOCScanner.add_indicator(scanner: IOCScanner, ioc_type: String, value: String) -> IOCScanner {
    // native: validates type in {ip,domain,hash,url,email}, appends indicator
}

/// Scan data string for all registered IOCs (string contains matching)
fn IOCScanner.scan(scanner: IOCScanner, data: String) -> []IOCMatch {
    // native: returns array of matches where data contains indicator value
}

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
fn ContainmentAction.isolate_host(hostname: String) -> ContainmentResult {
    // native: simulated — logs action, returns success
}

/// Simulate IP blocking
fn ContainmentAction.block_ip(ip: String) -> ContainmentResult {
    // native: simulated — logs action, returns success
}

/// Simulate account disabling
fn ContainmentAction.disable_account(account: String) -> ContainmentResult {
    // native: simulated — logs action, returns success
}

/// Simulate file quarantine
fn ContainmentAction.quarantine_file(path: String) -> ContainmentResult {
    // native: simulated — logs action, returns success
}

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
fn IncidentTimeline.create(incident_id: String) -> IncidentTimeline {
    // native: creates empty timeline
}

/// Add an event to the timeline (immutable update)
fn IncidentTimeline.add_event(timeline: IncidentTimeline, timestamp: String, description: String, source: String) -> IncidentTimeline {
    // native: appends event, increments count
}

/// Export timeline to JSON string
fn IncidentTimeline.export(timeline: IncidentTimeline) -> String {
    // native: serializes to JSON
}

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
fn ThreatHunt.query(data_source: String, query_string: String) -> HuntResult {
    // native: simulated query — matches based on keywords
}

/// Correlate results from multiple threat hunts
fn ThreatHunt.correlate(results: []HuntResult) -> CorrelationResult {
    // native: aggregates sources, counts, computes correlation score
}
