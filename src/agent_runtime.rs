//! Agent Runtime — runtime safety mechanisms for agent execution.
//!
//! Provides:
//! - Dead man's switch (heartbeat monitoring)
//! - Human checkpoint pausing
//! - Resource budget tracking with enforcement
//! - Runtime trust score tracking between agent pairs
//! - OTel-compatible span emission and event sourcing
//! - Opt-in unified agent-ledger emission (task A1.1.4): every audit event
//!   queued on the runtime is mirrored into the hash-chained ledger when a
//!   recorder is attached ([`AgentRuntime::set_ledger`] /
//!   [`AgentRuntime::enable_ledger_from_env`], the live `TALLOW_LEDGER_PATH`
//!   gate). Disabled by default — no writes, no behavior change.
//! - Agent health data for production dashboards
//! - Auto-checkpointing at configurable step intervals
//!
//! Not all safety can be checked at compile time. Runtime safety ensures agents
//! don't run forever, don't consume unbounded resources, and can be paused for
//! human review. Trust scores let agents build and adjust reputation with each
//! other at runtime. OTel spans enable production observability via any
//! OTLP-compatible trace viewer.

use std::time::{Duration, Instant};

use crate::agent_observability::{
    AgentEvent, EventStore, OtelSpan, SpanBuffer, SpanKind, SpanStatus,
    generate_span_id, generate_trace_id,
};
use crate::agent_safety_pass::TrustScoreRegistry;

/// Unified-ledger recorder the runtime emits into (task A1.1.4 live wiring):
/// [`Recorder`](crate::agent_ledger::Recorder) over the durable SQLite backend,
/// the same ledger `tallow verify-ledger` reads back.
pub type LedgerRecorder =
    crate::agent_ledger::Recorder<crate::agent_ledger_sqlite::SqliteLedger>;

/// Current time as ISO 8601 string.
fn chrono_now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── EmotionalState ──────────────────────────────────────────────────────────

/// Adaptive emotional signals that modulate agent behavior.
///
/// Three f64 signals in [0.0, 1.0]:
/// - **confidence**: affects decision thresholds (high = bold, low = cautious)
/// - **urgency**: affects resource allocation priority (used as multiplier)
/// - **uncertainty**: triggers checkpoint/human review when high
///
/// Signals update via exponential moving average (EMA) after each operation outcome,
/// preventing wild oscillation while remaining responsive to trends.
#[derive(Debug, Clone)]
pub struct EmotionalState {
    pub confidence: f64,
    pub urgency: f64,
    pub uncertainty: f64,
}

impl EmotionalState {
    /// EMA smoothing factor. Higher = faster adaptation, lower = more stable.
    const ALPHA: f64 = 0.15;

    /// Create default emotional state: moderate confidence, no urgency, moderate uncertainty.
    pub fn new() -> Self {
        Self {
            confidence: 0.5,
            urgency: 0.0,
            uncertainty: 0.5,
        }
    }

    /// Clamp a value to [0.0, 1.0].
    fn clamp(v: f64) -> f64 {
        v.clamp(0.0, 1.0)
    }

    /// Update signals based on an operation outcome using EMA.
    ///
    /// - On success: confidence increases, uncertainty decreases.
    /// - On failure: confidence decreases (2x penalty), uncertainty increases.
    /// - If duration > 2*expected: urgency increases (operations taking too long).
    pub fn record_outcome(&mut self, success: bool, duration_ms: u64, expected_ms: u64) {
        let alpha = Self::ALPHA;

        if success {
            // Confidence moves toward 1.0
            self.confidence = Self::clamp(self.confidence + alpha * (1.0 - self.confidence));
            // Uncertainty moves toward 0.0
            self.uncertainty = Self::clamp(self.uncertainty - alpha * self.uncertainty);
        } else {
            // Confidence decays faster on failure (2x penalty)
            self.confidence = Self::clamp(self.confidence - alpha * self.confidence * 2.0);
            // Uncertainty moves toward 1.0
            self.uncertainty = Self::clamp(self.uncertainty + alpha * (1.0 - self.uncertainty));
        }

        // Urgency increases when operations take longer than expected
        if expected_ms > 0 && duration_ms > 2 * expected_ms {
            let overshoot = (duration_ms as f64 / expected_ms as f64) - 1.0;
            self.urgency = Self::clamp(self.urgency + alpha * overshoot.min(1.0));
        }
    }

    /// Returns true if uncertainty exceeds the given threshold (should pause for human review).
    pub fn should_checkpoint(&self, threshold: f64) -> bool {
        self.uncertainty > threshold
    }

    /// Returns a multiplier for rate limits and concurrency: 1.0 + urgency.
    /// At urgency=0.0 returns 1.0 (no change); at urgency=1.0 returns 2.0 (double speed).
    pub fn urgency_factor(&self) -> f64 {
        1.0 + self.urgency
    }

    /// Auto-update urgency based on remaining budget fraction.
    /// As budget depletes (fraction -> 0.0), urgency increases toward 1.0.
    pub fn update_urgency_from_budget(&mut self, budget_fraction_remaining: f64) {
        self.urgency = Self::clamp(1.0 - budget_fraction_remaining.clamp(0.0, 1.0));
    }

    /// Returns all three signals as a tuple for telemetry.
    pub fn summary(&self) -> (f64, f64, f64) {
        (self.confidence, self.urgency, self.uncertainty)
    }
}

// ── AgentHealthData ─────────────────────────────────────────────────────────

/// Complete health snapshot of an agent for production dashboarding.
///
/// Contains resource usage, timing, goal metrics, emotional signals, and LLM
/// cost data. Returned by `AgentRuntime::health_data()`.
#[derive(Debug, Clone)]
pub struct AgentHealthData {
    pub agent_id: String,
    pub memory_used: u64,
    pub memory_limit: u64,
    pub requests_used: u32,
    pub requests_limit: u32,
    pub uptime_ms: u64,
    pub steps_executed: u32,
    pub goals_attempted: u32,
    pub goals_completed: u32,
    pub goal_completion_rate: f64,
    pub confidence: f64,
    pub urgency: f64,
    pub uncertainty: f64,
    pub llm_calls: u32,
    pub llm_cost_usd: f64,
    pub llm_cache_hit_rate: f64,
}

// ── StepAction ──────────────────────────────────────────────────────────────

/// Action to take before executing an agent step.
#[derive(Debug, Clone, PartialEq)]
pub enum StepAction {
    /// Continue normal execution.
    Continue,
    /// Pause for human checkpoint review.
    PauseForHumanCheckpoint,
}

// ── AgentKillReason ─────────────────────────────────────────────────────────

/// Reason an agent was killed.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentKillReason {
    /// No heartbeat received within configured interval.
    HeartbeatTimeout { interval: Duration, elapsed: Duration },
    /// Resource budget exhausted.
    BudgetExhausted {
        resource: String,
        used: String,
        max: String,
    },
    /// Manually killed by user.
    ManualKill,
}

impl std::fmt::Display for AgentKillReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentKillReason::HeartbeatTimeout { interval, elapsed } => {
                write!(
                    f,
                    "agent killed: no heartbeat for {:.1}s (interval: {:.1}s)",
                    elapsed.as_secs_f64(),
                    interval.as_secs_f64()
                )
            }
            AgentKillReason::BudgetExhausted { resource, used, max } => {
                write!(f, "agent killed: {resource} budget exhausted ({used}/{max})")
            }
            AgentKillReason::ManualKill => write!(f, "agent killed: manual termination"),
        }
    }
}

// ── ResourceBudget ──────────────────────────────────────────────────────────

/// Tracks resource usage against configured limits.
#[derive(Debug, Clone)]
pub struct ResourceBudget {
    pub max_requests: Option<u32>,
    pub requests_used: u32,
    /// Requests reserved for child agents (not yet used, but allocated).
    pub requests_reserved: u32,
    pub max_memory_bytes: Option<u64>,
    pub memory_used_bytes: u64,
    /// Memory reserved for child agents.
    pub memory_reserved: u64,
    pub max_runtime: Option<Duration>,
    pub started_at: Instant,
}

impl ResourceBudget {
    pub fn new(
        max_requests: Option<u32>,
        max_memory_bytes: Option<u64>,
        max_runtime: Option<Duration>,
    ) -> Self {
        Self {
            max_requests,
            requests_used: 0,
            requests_reserved: 0,
            max_memory_bytes,
            memory_used_bytes: 0,
            memory_reserved: 0,
            max_runtime,
            started_at: Instant::now(),
        }
    }

    /// Check all budget limits. Returns Err with kill reason if any exceeded.
    pub fn check(&self) -> Result<(), AgentKillReason> {
        // Check request budget
        if let Some(max) = self.max_requests {
            if self.requests_used >= max {
                return Err(AgentKillReason::BudgetExhausted {
                    resource: "requests".to_string(),
                    used: self.requests_used.to_string(),
                    max: max.to_string(),
                });
            }
        }

        // Check memory budget
        if let Some(max) = self.max_memory_bytes {
            if self.memory_used_bytes >= max {
                return Err(AgentKillReason::BudgetExhausted {
                    resource: "memory".to_string(),
                    used: format!("{}MB", self.memory_used_bytes / (1024 * 1024)),
                    max: format!("{}MB", max / (1024 * 1024)),
                });
            }
        }

        // Check runtime budget
        if let Some(max) = self.max_runtime {
            let elapsed = self.started_at.elapsed();
            if elapsed >= max {
                return Err(AgentKillReason::BudgetExhausted {
                    resource: "runtime".to_string(),
                    used: format!("{:.1}s", elapsed.as_secs_f64()),
                    max: format!("{:.1}s", max.as_secs_f64()),
                });
            }
        }

        Ok(())
    }

    /// Record a network request.
    pub fn record_request(&mut self) {
        self.requests_used += 1;
    }

    /// Record memory usage.
    pub fn record_memory(&mut self, bytes: u64) {
        self.memory_used_bytes += bytes;
    }

    /// Elapsed time since budget started.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Remaining requests before budget exhaustion (accounts for reservations).
    pub fn requests_remaining(&self) -> Option<u32> {
        self.max_requests
            .map(|max| max.saturating_sub(self.requests_used).saturating_sub(self.requests_reserved))
    }

    /// Remaining runtime before budget exhaustion.
    pub fn runtime_remaining(&self) -> Option<Duration> {
        self.max_runtime
            .map(|max| max.saturating_sub(self.started_at.elapsed()))
    }

    /// Remaining memory before budget exhaustion (accounts for reservations).
    pub fn memory_remaining(&self) -> Option<u64> {
        self.max_memory_bytes
            .map(|max| max.saturating_sub(self.memory_used_bytes).saturating_sub(self.memory_reserved))
    }

    /// Carve a child budget from this parent's REMAINING resources.
    ///
    /// Each field uses `min(child_declared, parent_remaining)`.
    /// Parent's remaining is reduced via reservations (not by modifying max).
    /// If child declares `None`, the child field is `None` (unlimited within parent).
    /// If parent has `None` (unlimited), child gets its declared value as-is.
    pub fn split_for_child(
        &mut self,
        child_max_requests: Option<u32>,
        child_memory_limit: Option<u64>,
        child_timeout: Option<Duration>,
    ) -> ResourceBudget {
        // Requests: min(child_declared, parent_remaining)
        let child_requests = match (child_max_requests, self.requests_remaining()) {
            (Some(child), Some(parent_rem)) => {
                let alloc = child.min(parent_rem);
                // Reserve the allocation from the parent (does not modify max)
                self.requests_reserved += alloc;
                Some(alloc)
            }
            (Some(child), None) => {
                // Parent unlimited, child gets its full declared value
                Some(child)
            }
            (None, _) => None, // Child wants unlimited
        };

        // Memory: min(child_declared, parent_remaining)
        let child_memory = match (child_memory_limit, self.memory_remaining()) {
            (Some(child), Some(parent_rem)) => {
                let alloc = child.min(parent_rem);
                self.memory_reserved += alloc;
                Some(alloc)
            }
            (Some(child), None) => Some(child),
            (None, _) => None,
        };

        // Timeout: min(child_declared, parent_remaining_time)
        let child_runtime = match (child_timeout, self.runtime_remaining()) {
            (Some(child), Some(parent_rem)) => Some(child.min(parent_rem)),
            (Some(child), None) => Some(child),
            (None, _) => None,
        };

        ResourceBudget::new(child_requests, child_memory, child_runtime)
    }
}

// ── LlmCostTracker ─────────────────────────────────────────────────────────

/// Per-agent LLM cost tracking with token accumulation and budget enforcement.
///
/// Tracks total input/output tokens, estimates USD cost based on model pricing,
/// and enforces optional budget limits.
#[derive(Debug, Clone)]
pub struct LlmCostTracker {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub budget_usd: Option<f64>,
    pub calls: u32,
    pub cache_hits: u32,
    pub cache_misses: u32,
    /// Bounded prompt->response cache. Key = "<backend>|<normalized prompt>".
    pub reasoning_cache: std::collections::HashMap<String, (u64, crate::agent_reasoning::ReasoningResult)>,
    cache_clock: u64,
    cache_capacity: usize,
}

impl LlmCostTracker {
    /// Create a new cost tracker with an optional budget limit.
    pub fn new(budget: Option<f64>) -> Self {
        Self {
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            budget_usd: budget,
            calls: 0,
            cache_hits: 0,
            cache_misses: 0,
            reasoning_cache: std::collections::HashMap::new(),
            cache_clock: 0,
            cache_capacity: 256,
        }
    }

    /// Record a completed LLM call, accumulating tokens and computing cost.
    pub fn record_call(&mut self, model: &str, input_tokens: u32, output_tokens: u32) {
        self.total_input_tokens += input_tokens as u64;
        self.total_output_tokens += output_tokens as u64;
        self.calls += 1;

        let (input_price, output_price) = model_pricing(model);
        let cost = (input_tokens as f64 / 1_000_000.0) * input_price
            + (output_tokens as f64 / 1_000_000.0) * output_price;
        self.total_cost_usd += cost;
    }

    /// Remaining budget, or None if unlimited.
    pub fn budget_remaining(&self) -> Option<f64> {
        self.budget_usd.map(|b| (b - self.total_cost_usd).max(0.0))
    }

    /// Check if cost has exceeded budget.
    pub fn is_over_budget(&self) -> bool {
        match self.budget_usd {
            Some(budget) => self.total_cost_usd >= budget,
            None => false,
        }
    }

    /// Summary tuple: (input_tokens, output_tokens, cost_usd, calls, budget_remaining).
    pub fn summary(&self) -> (u64, u64, f64, u32, Option<f64>) {
        (
            self.total_input_tokens,
            self.total_output_tokens,
            self.total_cost_usd,
            self.calls,
            self.budget_remaining(),
        )
    }

    /// Record a cache hit (LLM response served from cache).
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    /// Record a cache miss (LLM response required fresh inference).
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    /// Look up a cached reasoning result, bumping its recency. Returns a clone on hit.
    pub fn cache_get(&mut self, key: &str) -> Option<crate::agent_reasoning::ReasoningResult> {
        if let Some((recency, result)) = self.reasoning_cache.get_mut(key) {
            self.cache_clock += 1;
            *recency = self.cache_clock;
            Some(result.clone())
        } else {
            None
        }
    }

    /// Insert/replace a reasoning result in the bounded cache, evicting the least
    /// recently used entry when at capacity.
    pub fn cache_put(&mut self, key: String, result: crate::agent_reasoning::ReasoningResult) {
        self.cache_clock += 1;
        let clock = self.cache_clock;
        if self.reasoning_cache.len() >= self.cache_capacity {
            if let Some(oldest_key) = self
                .reasoning_cache
                .iter()
                .min_by_key(|(_, (rec, _))| *rec)
                .map(|(k, _)| k.clone())
            {
                self.reasoning_cache.remove(&oldest_key);
            }
        }
        self.reasoning_cache.insert(key, (clock, result));
    }

    /// Cache hit rate as fraction [0.0, 1.0]. Returns 0.0 if no cache lookups recorded.
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

/// Per-model pricing in USD per 1 million tokens: (input_price, output_price).
pub fn model_pricing(model: &str) -> (f64, f64) {
    let model_lower = model.to_lowercase();
    if model_lower.contains("gpt-4o") {
        (2.50, 10.00)
    } else if model_lower.contains("gpt-4") {
        (30.00, 60.00)
    } else if model_lower.contains("gpt-3.5") {
        (0.50, 1.50)
    } else if model_lower.contains("claude-opus") || model_lower.contains("opus") {
        (15.00, 75.00)
    } else if model_lower.contains("claude-sonnet") || model_lower.contains("sonnet") {
        (3.00, 15.00)
    } else if model_lower.contains("claude-haiku") || model_lower.contains("haiku") {
        (0.25, 1.25)
    } else {
        // Local/unknown models: zero cost
        (0.0, 0.0)
    }
}

// ── AgentRuntime ────────────────────────────────────────────────────────────

/// Runtime safety wrapper for agent execution.
///
/// Created when an @agent_task function is called. Provides:
/// - Dead man's switch via heartbeat monitoring
/// - Human checkpoint pausing at configured frequency
/// - Resource budget enforcement (requests, memory, runtime)
/// - Trust score tracking between agent pairs
#[derive(Debug)]
pub struct AgentRuntime {
    pub agent_id: String,
    pub heartbeat_interval: Option<Duration>,
    pub last_heartbeat: Instant,
    pub checkpoint_frequency: Option<u32>,
    pub steps_executed: u32,
    pub steps_since_checkpoint: u32,
    pub budget: ResourceBudget,
    pub killed: bool,
    pub kill_reason: Option<AgentKillReason>,
    pub trust_scores: TrustScoreRegistry,
    /// Remaining spawn depth (decremented on each spawn). 0 means no more spawning.
    pub remaining_spawn_depth: u32,
    /// Total agents spawned by this agent so far.
    pub total_agents_spawned: u32,
    /// Maximum total agents this agent may spawn (from annotation).
    pub max_total_agents: Option<u32>,
    /// Adaptive emotional signals (confidence, urgency, uncertainty).
    pub emotional_state: EmotionalState,
    /// If set, pre_step() triggers checkpoint when uncertainty exceeds this threshold.
    pub uncertainty_checkpoint_threshold: Option<f64>,
    /// LLM inference cost tracking with optional budget enforcement.
    pub llm_cost_tracker: LlmCostTracker,
    /// LLM policy for this agent (from annotation), determining inference routing.
    pub llm_policy: Option<crate::agent_reasoning::LlmPolicy>,
    /// Wall-clock start time for uptime tracking.
    pub started_at: Instant,
    /// Goals attempted by this agent (user-reported).
    pub goals_attempted: u32,
    /// Goals successfully completed by this agent (user-reported).
    pub goals_completed: u32,
    /// Auto-checkpoint interval in steps (None = disabled). Separate from
    /// `checkpoint_frequency` which is for human checkpoints.
    pub checkpoint_interval: Option<u32>,
    /// Steps executed since last auto-checkpoint.
    pub steps_since_auto_checkpoint: u32,
    /// OTel trace ID for this agent execution (32 hex chars, propagated to children).
    pub current_trace_id: String,
    /// Current span ID (16 hex chars, updated per step).
    pub current_span_id: String,
    /// Buffered OTel spans for batch export.
    pub span_buffer: SpanBuffer,
    /// Whether a step span is currently open (0.2: gate step_started emission to
    /// one per logical span open→close cycle).
    pub span_open: bool,
    /// Optional event store for append-only event sourcing.
    pub event_store: Option<EventStore>,
    /// Monotonic event sequence counter.
    pub event_sequence: u64,
    /// Buffered audit events, flushed in a batch when the buffer fills or on an
    /// explicit flush (see `flush_events`). Reduces per-event SQLite writes.
    pub pending_events: Vec<AgentEvent>,
    /// Max buffered events before an automatic batch flush.
    pub event_buffer_limit: usize,
    /// Optional unified-ledger emission (task A1.1.4 live wiring).
    ///
    /// When attached, every audit event this runtime queues is ALSO appended
    /// to the hash-chained agent ledger as an `agent_step` entry (via
    /// [`crate::agent_observability::emit_agent_event`]). `None` — the default
    /// for every constructor — leaves the ledger fully off: no writes, no
    /// behavior change. Opt in per runtime with [`AgentRuntime::set_ledger`],
    /// or from the environment with [`AgentRuntime::enable_ledger_from_env`]
    /// (the `TALLOW_LEDGER_PATH` gate the live `@agent_task` path uses).
    pub ledger: Option<LedgerRecorder>,
}

impl AgentRuntime {
    pub fn new(
        agent_id: String,
        heartbeat_interval: Option<Duration>,
        checkpoint_frequency: Option<u32>,
        budget: ResourceBudget,
    ) -> Self {
        Self {
            agent_id,
            heartbeat_interval,
            last_heartbeat: Instant::now(),
            checkpoint_frequency,
            steps_executed: 0,
            steps_since_checkpoint: 0,
            budget,
            killed: false,
            kill_reason: None,
            trust_scores: TrustScoreRegistry::new(),
            remaining_spawn_depth: 3, // Default: up to 3 levels of nesting
            total_agents_spawned: 0,
            max_total_agents: None, // Unlimited by default
            emotional_state: EmotionalState::new(),
            uncertainty_checkpoint_threshold: None, // Disabled unless agent sets it
            llm_cost_tracker: LlmCostTracker::new(None),
            llm_policy: None,
            started_at: Instant::now(),
            goals_attempted: 0,
            goals_completed: 0,
            checkpoint_interval: None,
            steps_since_auto_checkpoint: 0,
            current_trace_id: generate_trace_id(),
            current_span_id: generate_span_id(),
            span_buffer: SpanBuffer::new(),
            span_open: false,
            event_store: None,
            event_sequence: 0,
            pending_events: Vec::new(),
            event_buffer_limit: 64,
            ledger: None,
        }
    }

    /// Create an AgentRuntime with explicit spawn depth and total agents limits.
    pub fn with_spawn_limits(
        agent_id: String,
        heartbeat_interval: Option<Duration>,
        checkpoint_frequency: Option<u32>,
        budget: ResourceBudget,
        max_spawn_depth: u32,
        max_total_agents: Option<u32>,
    ) -> Self {
        Self {
            agent_id,
            heartbeat_interval,
            last_heartbeat: Instant::now(),
            checkpoint_frequency,
            steps_executed: 0,
            steps_since_checkpoint: 0,
            budget,
            killed: false,
            kill_reason: None,
            trust_scores: TrustScoreRegistry::new(),
            remaining_spawn_depth: max_spawn_depth,
            total_agents_spawned: 0,
            max_total_agents,
            emotional_state: EmotionalState::new(),
            uncertainty_checkpoint_threshold: None,
            llm_cost_tracker: LlmCostTracker::new(None),
            llm_policy: None,
            started_at: Instant::now(),
            goals_attempted: 0,
            goals_completed: 0,
            checkpoint_interval: None,
            steps_since_auto_checkpoint: 0,
            current_trace_id: generate_trace_id(),
            current_span_id: generate_span_id(),
            span_buffer: SpanBuffer::new(),
            span_open: false,
            event_store: None,
            event_sequence: 0,
            pending_events: Vec::new(),
            event_buffer_limit: 64,
            ledger: None,
        }
    }

    /// Check if this agent can spawn another child agent.
    /// Returns Ok(()) if spawning is allowed, Err with reason otherwise.
    pub fn can_spawn(&self) -> Result<(), String> {
        if self.remaining_spawn_depth == 0 {
            return Err("spawn depth exceeded: no remaining spawn depth".to_string());
        }
        if let Some(max) = self.max_total_agents {
            if self.total_agents_spawned >= max {
                return Err(format!(
                    "max total agents exceeded: {}/{max}",
                    self.total_agents_spawned
                ));
            }
        }
        Ok(())
    }

    /// Record that a spawn occurred. Decrements depth, increments count.
    pub fn record_spawn(&mut self) {
        self.remaining_spawn_depth = self.remaining_spawn_depth.saturating_sub(1);
        self.total_agents_spawned += 1;
    }

    /// Set the event store and initialize sequence from DB max.
    pub fn set_event_store(&mut self, store: EventStore) {
        if let Ok(max_seq) = store.get_max_sequence(&self.agent_id) {
            self.event_sequence = max_seq;
        }
        self.event_store = Some(store);
    }

    /// Attach a unified-ledger recorder (task A1.1.4 live emission).
    ///
    /// From this point on every audit event queued on this runtime is also
    /// appended to the recorder's ledger as an `agent_step` event. Emission is
    /// best-effort, like the local event store: a rejected append (e.g. a
    /// concurrent writer already extended the chain — see the single-writer
    /// note in [`crate::agent_ledger_sqlite`]) is dropped, never raised.
    pub fn set_ledger(&mut self, rec: LedgerRecorder) {
        self.ledger = Some(rec);
    }

    /// Attach a durable ledger recorder when the environment opts in.
    ///
    /// Gate: `TALLOW_LEDGER_PATH` (unset/blank — the default — returns `false`
    /// and leaves the ledger off: no writes, no behavior change). When set,
    /// opens (or creates) the SQLite ledger at that path and records events
    /// with `actor = agent_id` and `run_id = current_trace_id`, so a live run
    /// writes the same hash-chained ledger `tallow verify-ledger` reads. A
    /// recorder attached to an existing ledger resumes its chain.
    ///
    /// Best-effort: an unopenable path (or a blank agent id) is reported once
    /// on stderr and the ledger stays off. Returns whether emission is on.
    pub fn enable_ledger_from_env(&mut self) -> bool {
        let path = match std::env::var("TALLOW_LEDGER_PATH") {
            Ok(p) if !p.trim().is_empty() => p,
            _ => return false,
        };
        let ledger = match crate::agent_ledger_sqlite::SqliteLedger::open(&path) {
            Ok(ledger) => ledger,
            Err(e) => {
                eprintln!("[tallow] agent ledger: cannot open '{path}': {e}");
                return false;
            }
        };
        match crate::agent_ledger::Recorder::new(ledger, self.agent_id.clone(), self.current_trace_id.clone()) {
            Ok(rec) => {
                self.ledger = Some(rec);
                true
            }
            Err(e) => {
                eprintln!("[tallow] agent ledger: recorder init failed for '{path}': {e}");
                false
            }
        }
    }

    /// Mirror one audit event into the attached unified ledger — best-effort,
    /// and a no-op while the ledger is disabled. Call sites that hand events
    /// directly to the local event store (rather than through `queue_event`)
    /// call this so the unified ledger sees the same event stream.
    pub fn emit_ledger_event(&mut self, event: &AgentEvent) {
        if let Some(ref mut rec) = self.ledger {
            let _ = crate::agent_observability::emit_agent_event(rec, event);
        }
    }

    /// Increment and return the next monotonic event sequence number.
    pub fn next_event_sequence(&mut self) -> u64 {
        self.event_sequence += 1;
        self.event_sequence
    }

    /// Queue an audit event, flushing automatically when the buffer fills.
    fn queue_event(&mut self, event: AgentEvent) {
        // Task A1.1.4 live emission: mirror the audit event into the unified
        // ledger (no-op unless a recorder is attached).
        self.emit_ledger_event(&event);
        self.pending_events.push(event);
        if self.pending_events.len() >= self.event_buffer_limit {
            self.flush_events();
        }
    }

    /// Flush buffered audit events to the event store in one batch (best-effort).
    pub fn flush_events(&mut self) {
        // 0.2: flush closes the current logical span, so a later begin re-opens.
        self.span_open = false;
        if self.pending_events.is_empty() {
            return;
        }
        if let Some(ref store) = self.event_store {
            let batch = std::mem::take(&mut self.pending_events);
            let _ = store.append_batch(&batch);
        } else {
            self.pending_events.clear();
        }
    }

    /// Begin a new step span. Saves current span_id as parent, generates new span_id.
    /// Records "step_started" event to event store if available.
    /// Returns the new span_id.
    pub fn begin_step_span(&mut self) -> String {
        // 0.2: gate to one step_started per logical span. If a span is already
        // open (an earlier begin without a matching end/flush), return the
        // current span_id without emitting another event.
        if self.span_open {
            return self.current_span_id.clone();
        }
        let parent_span_id = self.current_span_id.clone();
        let new_span_id = generate_span_id();
        self.current_span_id = new_span_id.clone();

        // Record event
        if self.event_store.is_some() {
            let seq = self.next_event_sequence();
            let event = AgentEvent {
                agent_id: self.agent_id.clone(),
                sequence: seq,
                timestamp: chrono_now_iso(),
                event_type: "step_started".to_string(),
                payload: serde_json::json!({
                    "step": self.steps_executed,
                    "parent_span_id": parent_span_id
                })
                .to_string(),
                trace_id: Some(self.current_trace_id.clone()),
                span_id: Some(new_span_id.clone()),
            };
            self.queue_event(event);
        }
        self.span_open = true;

        new_span_id
    }

    /// End the current step span with status, push to span_buffer, record event.
    pub fn end_step_span(&mut self, status_code: u32, status_message: &str) {
        self.span_open = false;
        let status = match status_code {
            1 => SpanStatus::ok(),
            2 => SpanStatus::error(status_message),
            _ => SpanStatus::unset(),
        };

        let mut span = OtelSpan::new(
            &self.current_trace_id,
            None, // parent handled via trace context
            &format!("agent.step.{}", self.steps_executed),
            SpanKind::Internal,
        );
        // Override span_id to match the one from begin_step_span
        span.span_id = self.current_span_id.clone();
        span.add_attribute("agent.id", serde_json::json!(&self.agent_id));
        span.add_attribute("agent.steps_executed", serde_json::json!(self.steps_executed));
        span.add_attribute("agent.confidence", serde_json::json!(self.emotional_state.confidence));
        span.add_attribute("agent.requests_used", serde_json::json!(self.budget.requests_used));
        span.end(status);

        self.span_buffer.push(span);

        // Record event
        if self.event_store.is_some() {
            let seq = self.next_event_sequence();
            let event = AgentEvent {
                agent_id: self.agent_id.clone(),
                sequence: seq,
                timestamp: chrono_now_iso(),
                event_type: "step_completed".to_string(),
                payload: serde_json::json!({
                    "steps_executed": self.steps_executed,
                    "confidence": self.emotional_state.confidence,
                    "requests_used": self.budget.requests_used,
                    "status_code": status_code,
                    "status_message": status_message
                })
                .to_string(),
                trace_id: Some(self.current_trace_id.clone()),
                span_id: Some(self.current_span_id.clone()),
            };
            self.queue_event(event);
        }
    }

    /// Record an LLM call as a Client-kind child span with metrics attributes.
    pub fn record_llm_span(
        &mut self,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        latency_ms: u64,
        cost_usd: f64,
        cache_hit: bool,
    ) {
        let mut span = OtelSpan::new(
            &self.current_trace_id,
            Some(&self.current_span_id),
            "llm.call",
            SpanKind::Client,
        );
        span.add_attribute("llm.model", serde_json::json!(model));
        span.add_attribute("llm.input_tokens", serde_json::json!(input_tokens));
        span.add_attribute("llm.output_tokens", serde_json::json!(output_tokens));
        span.add_attribute("llm.latency_ms", serde_json::json!(latency_ms));
        span.add_attribute("llm.cost_usd", serde_json::json!(cost_usd));
        span.add_attribute("llm.cache_hit", serde_json::json!(cache_hit));
        span.end(SpanStatus::ok());

        self.span_buffer.push(span);

        // Record event
        if self.event_store.is_some() {
            let seq = self.next_event_sequence();
            let event = AgentEvent {
                agent_id: self.agent_id.clone(),
                sequence: seq,
                timestamp: chrono_now_iso(),
                event_type: "llm_call".to_string(),
                payload: serde_json::json!({
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "latency_ms": latency_ms,
                    "cost_usd": cost_usd,
                    "cache_hit": cache_hit
                })
                .to_string(),
                trace_id: Some(self.current_trace_id.clone()),
                span_id: Some(self.current_span_id.clone()),
            };
            if let Some(ref store) = self.event_store {
                let _ = store.append(&event);
            }
        }
    }

    /// Inherit parent's trace context for child agent trace correlation.
    pub fn with_trace_context(mut self, trace_id: String, parent_span_id: String) -> Self {
        self.current_trace_id = trace_id;
        self.current_span_id = parent_span_id;
        self
    }

    /// Called before each agent step. Returns the action to take.
    ///
    /// Returns `Err` if the agent should be killed (heartbeat timeout, budget exhausted).
    /// Returns `Ok(PauseForHumanCheckpoint)` if a checkpoint is due.
    /// Returns `Ok(Continue)` for normal execution.
    pub fn pre_step(&mut self) -> Result<StepAction, AgentKillReason> {
        // Already killed?
        if self.killed {
            return Err(self
                .kill_reason
                .clone()
                .unwrap_or(AgentKillReason::ManualKill));
        }

        // Dead man's switch: check heartbeat timeout
        if let Some(interval) = self.heartbeat_interval {
            let elapsed = self.last_heartbeat.elapsed();
            if elapsed > interval {
                self.killed = true;
                let reason = AgentKillReason::HeartbeatTimeout { interval, elapsed };
                self.kill_reason = Some(reason.clone());
                return Err(reason);
            }
        }

        // Budget checks
        self.budget.check().map_err(|reason| {
            self.killed = true;
            self.kill_reason = Some(reason.clone());
            reason
        })?;

        // Uncertainty-driven checkpoint: if uncertainty exceeds configured threshold
        if let Some(threshold) = self.uncertainty_checkpoint_threshold {
            if self.emotional_state.should_checkpoint(threshold) {
                return Ok(StepAction::PauseForHumanCheckpoint);
            }
        }

        // Increment step counters
        self.steps_executed += 1;
        self.steps_since_checkpoint += 1;

        // Human checkpoint
        if let Some(freq) = self.checkpoint_frequency {
            if self.steps_since_checkpoint >= freq {
                self.steps_since_checkpoint = 0;
                return Ok(StepAction::PauseForHumanCheckpoint);
            }
        }

        // Emit step span if event store is available
        if self.event_store.is_some() {
            self.begin_step_span();
        }

        Ok(StepAction::Continue)
    }

    /// Reset the heartbeat timer.
    pub fn heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
    }

    /// Record a network request against the budget.
    pub fn record_request(&mut self) {
        self.budget.record_request();
    }

    /// Record an operation outcome and update emotional signals.
    pub fn record_operation_outcome(&mut self, success: bool, duration_ms: u64, expected_ms: u64) {
        self.emotional_state.record_outcome(success, duration_ms, expected_ms);
    }

    /// Manually kill this agent.
    pub fn kill(&mut self) {
        self.killed = true;
        self.kill_reason = Some(AgentKillReason::ManualKill);
    }

    /// Check if the agent is still alive.
    pub fn is_alive(&self) -> bool {
        !self.killed
    }

    /// Produce a human-readable summary of runtime stats.
    pub fn summary(&self) -> String {
        let status = if self.killed { "KILLED" } else { "ALIVE" };
        let kill_info = self
            .kill_reason
            .as_ref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        format!(
            "Agent '{}': {} steps, {}/{} requests, {:.1}s elapsed, status: {}{}",
            self.agent_id,
            self.steps_executed,
            self.budget.requests_used,
            self.budget
                .max_requests
                .map(|m| m.to_string())
                .unwrap_or("unlimited".to_string()),
            self.budget.elapsed().as_secs_f64(),
            status,
            kill_info,
        )
    }

    /// Record a successful inter-agent call: increase trust from this agent to callee.
    pub fn record_successful_call(&mut self, callee_id: &str) {
        self.trust_scores
            .update_score(&self.agent_id, callee_id, 0.05);
    }

    /// Record a failed inter-agent call: decrease trust from this agent to callee.
    pub fn record_failed_call(&mut self, callee_id: &str) {
        self.trust_scores
            .update_score(&self.agent_id, callee_id, -0.1);
    }

    /// Record a goal attempt by this agent.
    pub fn record_goal_attempt(&mut self) {
        self.goals_attempted += 1;
    }

    /// Record a goal completion by this agent.
    pub fn record_goal_completion(&mut self) {
        self.goals_completed += 1;
    }

    /// Returns true if an auto-checkpoint is due (steps since last >= interval).
    pub fn auto_checkpoint_due(&self) -> bool {
        match self.checkpoint_interval {
            Some(interval) => self.steps_since_auto_checkpoint >= interval,
            None => false,
        }
    }

    /// Reset the auto-checkpoint step counter (call after saving a checkpoint).
    pub fn reset_auto_checkpoint_counter(&mut self) {
        self.steps_since_auto_checkpoint = 0;
    }

    /// Produce a full health data snapshot for dashboarding.
    pub fn health_data(&self) -> AgentHealthData {
        let goal_completion_rate = if self.goals_attempted == 0 {
            0.0
        } else {
            self.goals_completed as f64 / self.goals_attempted as f64
        };

        AgentHealthData {
            agent_id: self.agent_id.clone(),
            memory_used: self.budget.memory_used_bytes,
            memory_limit: self.budget.max_memory_bytes.unwrap_or(0),
            requests_used: self.budget.requests_used,
            requests_limit: self.budget.max_requests.unwrap_or(0),
            uptime_ms: self.started_at.elapsed().as_millis() as u64,
            steps_executed: self.steps_executed,
            goals_attempted: self.goals_attempted,
            goals_completed: self.goals_completed,
            goal_completion_rate,
            confidence: self.emotional_state.confidence,
            urgency: self.emotional_state.urgency,
            uncertainty: self.emotional_state.uncertainty,
            llm_calls: self.llm_cost_tracker.calls,
            llm_cost_usd: self.llm_cost_tracker.total_cost_usd,
            llm_cache_hit_rate: self.llm_cost_tracker.cache_hit_rate(),
        }
    }

    /// Get trust score from this agent to another.
    pub fn trust_for(&self, callee_id: &str) -> f64 {
        self.trust_scores.get_score(&self.agent_id, callee_id)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_runtime(
        heartbeat: Option<Duration>,
        checkpoint: Option<u32>,
        max_requests: Option<u32>,
        max_runtime: Option<Duration>,
    ) -> AgentRuntime {
        AgentRuntime::new(
            "test_agent".to_string(),
            heartbeat,
            checkpoint,
            ResourceBudget::new(max_requests, None, max_runtime),
        )
    }

    // ── pre_step basic ──────────────────────────────────────────────────

    #[test]
    fn pre_step_no_limits_returns_continue() {
        let mut rt = make_runtime(None, None, None, None);
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    #[test]
    fn pre_step_heartbeat_within_interval_returns_continue() {
        let mut rt = make_runtime(Some(Duration::from_secs(60)), None, None, None);
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    #[test]
    fn pre_step_heartbeat_expired_returns_timeout() {
        let mut rt = make_runtime(Some(Duration::from_millis(1)), None, None, None);
        // Wait for heartbeat to expire
        std::thread::sleep(Duration::from_millis(5));
        let err = rt.pre_step().unwrap_err();
        assert!(matches!(err, AgentKillReason::HeartbeatTimeout { .. }));
        assert!(rt.killed);
    }

    #[test]
    fn heartbeat_resets_timer() {
        // Interval 2s, sleeps 50ms: the assertion is about the RESET, not about
        // scheduler punctuality. At 50ms/30ms a loaded CI runner overshot to
        // 157ms and failed the test (macOS leg, 2026-10-21).
        let mut rt = make_runtime(Some(Duration::from_secs(2)), None, None, None);
        std::thread::sleep(Duration::from_millis(50));
        rt.heartbeat(); // reset
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    // ── Budget: requests ────────────────────────────────────────────────

    #[test]
    fn pre_step_under_request_limit_returns_continue() {
        let mut rt = make_runtime(None, None, Some(10), None);
        rt.record_request(); // 1/10
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    #[test]
    fn pre_step_exceeding_requests_returns_budget_exhausted() {
        let mut rt = make_runtime(None, None, Some(2), None);
        rt.record_request();
        rt.record_request();
        let err = rt.pre_step().unwrap_err();
        match &err {
            AgentKillReason::BudgetExhausted { resource, .. } => {
                assert_eq!(resource, "requests");
            }
            other => panic!("expected BudgetExhausted, got {other:?}"),
        }
        assert!(rt.killed);
    }

    #[test]
    fn record_request_increments_counter() {
        let mut rt = make_runtime(None, None, Some(100), None);
        assert_eq!(rt.budget.requests_used, 0);
        rt.record_request();
        assert_eq!(rt.budget.requests_used, 1);
        rt.record_request();
        assert_eq!(rt.budget.requests_used, 2);
    }

    // ── Budget: runtime ─────────────────────────────────────────────────

    #[test]
    fn pre_step_within_runtime_limit_returns_continue() {
        let mut rt = make_runtime(None, None, None, Some(Duration::from_secs(60)));
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    #[test]
    fn pre_step_runtime_exceeded_returns_budget_exhausted() {
        let mut rt = make_runtime(None, None, None, Some(Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        let err = rt.pre_step().unwrap_err();
        match &err {
            AgentKillReason::BudgetExhausted { resource, .. } => {
                assert_eq!(resource, "runtime");
            }
            other => panic!("expected BudgetExhausted, got {other:?}"),
        }
    }

    // ── Checkpoints ─────────────────────────────────────────────────────

    #[test]
    fn checkpoint_frequency_pauses_at_correct_step() {
        let mut rt = make_runtime(None, Some(5), None, None);
        for _ in 0..4 {
            assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        }
        assert_eq!(
            rt.pre_step().unwrap(),
            StepAction::PauseForHumanCheckpoint
        );
    }

    #[test]
    fn checkpoint_counter_resets_after_checkpoint() {
        let mut rt = make_runtime(None, Some(3), None, None);
        // First 3 steps
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        assert_eq!(
            rt.pre_step().unwrap(),
            StepAction::PauseForHumanCheckpoint
        );
        // Next 3 steps (counter reset)
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        assert_eq!(
            rt.pre_step().unwrap(),
            StepAction::PauseForHumanCheckpoint
        );
    }

    // ── Kill ────────────────────────────────────────────────────────────

    #[test]
    fn kill_sets_killed_and_pre_step_returns_manual_kill() {
        let mut rt = make_runtime(None, None, None, None);
        rt.kill();
        assert!(rt.killed);
        assert!(!rt.is_alive());
        let err = rt.pre_step().unwrap_err();
        assert_eq!(err, AgentKillReason::ManualKill);
    }

    // ── Summary ─────────────────────────────────────────────────────────

    #[test]
    fn summary_produces_readable_output() {
        let mut rt = make_runtime(None, None, Some(100), None);
        rt.record_request();
        rt.record_request();
        let _ = rt.pre_step();
        let s = rt.summary();
        assert!(s.contains("test_agent"));
        assert!(s.contains("1 steps")); // 1 step executed
        assert!(s.contains("2/100 requests"));
        assert!(s.contains("ALIVE"));
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn kill_reason_display_formats_correctly() {
        let hb = AgentKillReason::HeartbeatTimeout {
            interval: Duration::from_secs(30),
            elapsed: Duration::from_secs(45),
        };
        assert!(hb.to_string().contains("no heartbeat"));
        assert!(hb.to_string().contains("45.0s"));
        assert!(hb.to_string().contains("30.0s"));

        let budget = AgentKillReason::BudgetExhausted {
            resource: "requests".to_string(),
            used: "100".to_string(),
            max: "50".to_string(),
        };
        assert!(budget.to_string().contains("requests budget exhausted"));
        assert!(budget.to_string().contains("100/50"));

        let manual = AgentKillReason::ManualKill;
        assert!(manual.to_string().contains("manual termination"));
    }

    // ── Combined ────────────────────────────────────────────────────────

    #[test]
    fn combined_heartbeat_budget_checkpoint() {
        let mut rt = AgentRuntime::new(
            "combined_agent".to_string(),
            Some(Duration::from_secs(60)),
            Some(5),
            ResourceBudget::new(Some(100), Some(1024 * 1024 * 512), Some(Duration::from_secs(300))),
        );
        // Normal steps
        for _ in 0..4 {
            assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        }
        // Step 5 triggers checkpoint
        assert_eq!(
            rt.pre_step().unwrap(),
            StepAction::PauseForHumanCheckpoint
        );
        // Continue after checkpoint
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
        assert!(rt.is_alive());
    }

    // ── Trust Scores ────────────────────────────────────────────────────

    #[test]
    fn trust_scores_default_is_0_5() {
        let rt = make_runtime(None, None, None, None);
        assert!((rt.trust_for("other_agent") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn record_successful_call_increases_trust() {
        let mut rt = make_runtime(None, None, None, None);
        let before = rt.trust_for("callee");
        rt.record_successful_call("callee");
        let after = rt.trust_for("callee");
        assert!((after - before - 0.05).abs() < f64::EPSILON);
        assert!((after - 0.55).abs() < f64::EPSILON);
    }

    #[test]
    fn record_failed_call_decreases_trust() {
        let mut rt = make_runtime(None, None, None, None);
        let before = rt.trust_for("callee");
        rt.record_failed_call("callee");
        let after = rt.trust_for("callee");
        assert!((before - after - 0.1).abs() < f64::EPSILON);
        assert!((after - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn trust_score_clamped_at_zero() {
        let mut rt = make_runtime(None, None, None, None);
        // Reduce trust 6 times (-0.1 each) from 0.5 -> should clamp at 0.0
        for _ in 0..6 {
            rt.record_failed_call("bad_agent");
        }
        assert!((rt.trust_for("bad_agent")).abs() < f64::EPSILON);
    }

    #[test]
    fn trust_score_clamped_at_one() {
        let mut rt = make_runtime(None, None, None, None);
        // Increase trust 20 times (+0.05 each) from 0.5 -> should clamp at 1.0
        for _ in 0..20 {
            rt.record_successful_call("great_agent");
        }
        assert!((rt.trust_for("great_agent") - 1.0).abs() < f64::EPSILON);
    }

    // ── ResourceBudget helpers ──────────────────────────────────────────

    #[test]
    fn requests_remaining_tracks_correctly() {
        let mut budget = ResourceBudget::new(Some(10), None, None);
        assert_eq!(budget.requests_remaining(), Some(10));
        budget.record_request();
        budget.record_request();
        assert_eq!(budget.requests_remaining(), Some(8));
    }

    #[test]
    fn runtime_remaining_decreases() {
        let budget = ResourceBudget::new(None, None, Some(Duration::from_secs(60)));
        let remaining = budget.runtime_remaining().unwrap();
        assert!(remaining <= Duration::from_secs(60));
        assert!(remaining >= Duration::from_secs(59)); // should be very close to 60
    }

    #[test]
    fn memory_budget_check() {
        let mut budget = ResourceBudget::new(None, Some(1024), None);
        budget.record_memory(512);
        assert!(budget.check().is_ok());
        budget.record_memory(600); // total: 1112 > 1024
        let err = budget.check().unwrap_err();
        match err {
            AgentKillReason::BudgetExhausted { resource, .. } => {
                assert_eq!(resource, "memory");
            }
            _ => panic!("expected memory budget exhausted"),
        }
    }

    // ── split_for_child ─────────────────────────────────────────────────

    #[test]
    fn split_both_parent_and_child_have_limits() {
        let mut parent = ResourceBudget::new(Some(100), Some(1024), Some(Duration::from_secs(60)));
        let child = parent.split_for_child(Some(30), Some(256), Some(Duration::from_secs(20)));
        assert_eq!(child.max_requests, Some(30));
        assert_eq!(child.max_memory_bytes, Some(256));
        assert_eq!(child.max_runtime.unwrap().as_secs(), 20);
    }

    #[test]
    fn split_child_clamped_to_parent_remaining() {
        let mut parent = ResourceBudget::new(Some(50), Some(512), Some(Duration::from_secs(30)));
        // Child wants more than parent has
        let child = parent.split_for_child(Some(100), Some(1024), Some(Duration::from_secs(60)));
        // Should be clamped to parent's remaining
        assert_eq!(child.max_requests, Some(50));
        assert_eq!(child.max_memory_bytes, Some(512));
        assert!(child.max_runtime.unwrap().as_secs() <= 30);
    }

    #[test]
    fn split_parent_unlimited_child_gets_declared() {
        let mut parent = ResourceBudget::new(None, None, None);
        let child = parent.split_for_child(Some(50), Some(256), Some(Duration::from_secs(10)));
        assert_eq!(child.max_requests, Some(50));
        assert_eq!(child.max_memory_bytes, Some(256));
        assert_eq!(child.max_runtime.unwrap().as_secs(), 10);
    }

    #[test]
    fn split_reduces_parent_remaining() {
        let mut parent = ResourceBudget::new(Some(100), Some(1024), None);
        let _child = parent.split_for_child(Some(30), Some(256), None);
        // Parent remaining should be reduced by 30 requests and 256 bytes
        assert_eq!(parent.requests_remaining(), Some(70));
        assert_eq!(parent.memory_remaining(), Some(768));
    }

    #[test]
    fn split_multiple_sequential_depletes_parent() {
        let mut parent = ResourceBudget::new(Some(100), Some(1000), None);
        let _c1 = parent.split_for_child(Some(40), Some(400), None);
        assert_eq!(parent.requests_remaining(), Some(60));
        assert_eq!(parent.memory_remaining(), Some(600));

        let _c2 = parent.split_for_child(Some(40), Some(400), None);
        assert_eq!(parent.requests_remaining(), Some(20));
        assert_eq!(parent.memory_remaining(), Some(200));

        // Third child wants 40 but only 20 remaining
        let c3 = parent.split_for_child(Some(40), Some(400), None);
        assert_eq!(c3.max_requests, Some(20));
        assert_eq!(c3.max_memory_bytes, Some(200));
    }

    #[test]
    fn split_zero_remaining_gives_zero() {
        let mut parent = ResourceBudget::new(Some(10), None, None);
        // Use up all requests
        for _ in 0..10 {
            parent.record_request();
        }
        assert_eq!(parent.requests_remaining(), Some(0));
        let child = parent.split_for_child(Some(5), None, None);
        assert_eq!(child.max_requests, Some(0));
    }

    #[test]
    fn split_child_unlimited_field_stays_none() {
        let mut parent = ResourceBudget::new(Some(100), Some(1024), Some(Duration::from_secs(60)));
        let child = parent.split_for_child(None, None, None);
        assert_eq!(child.max_requests, None);
        assert_eq!(child.max_memory_bytes, None);
        assert_eq!(child.max_runtime, None);
    }

    #[test]
    fn split_partially_used_parent() {
        let mut parent = ResourceBudget::new(Some(100), Some(1024), None);
        parent.record_request();
        parent.record_request();
        parent.record_memory(100);
        // Parent remaining: 98 requests, 924 bytes
        let child = parent.split_for_child(Some(50), Some(500), None);
        assert_eq!(child.max_requests, Some(50));
        assert_eq!(child.max_memory_bytes, Some(500));
    }

    #[test]
    fn split_memory_remaining_helper() {
        let mut budget = ResourceBudget::new(None, Some(1024), None);
        assert_eq!(budget.memory_remaining(), Some(1024));
        budget.record_memory(300);
        assert_eq!(budget.memory_remaining(), Some(724));
    }

    #[test]
    fn split_child_starts_fresh_counters() {
        let mut parent = ResourceBudget::new(Some(100), Some(1024), None);
        let child = parent.split_for_child(Some(30), Some(256), None);
        assert_eq!(child.requests_used, 0);
        assert_eq!(child.memory_used_bytes, 0);
    }

    // ── Spawn depth and total agents ────────────────────────────────────

    #[test]
    fn spawn_depth_default_allows_spawning() {
        let rt = make_runtime(None, None, None, None);
        assert!(rt.can_spawn().is_ok());
        assert_eq!(rt.remaining_spawn_depth, 3);
    }

    #[test]
    fn spawn_depth_zero_rejects() {
        let rt = AgentRuntime::with_spawn_limits(
            "agent".into(), None, None,
            ResourceBudget::new(None, None, None),
            0, None,
        );
        assert!(rt.can_spawn().is_err());
        assert!(rt.can_spawn().unwrap_err().contains("spawn depth exceeded"));
    }

    #[test]
    fn record_spawn_decrements_depth() {
        let mut rt = AgentRuntime::with_spawn_limits(
            "agent".into(), None, None,
            ResourceBudget::new(None, None, None),
            2, None,
        );
        assert_eq!(rt.remaining_spawn_depth, 2);
        rt.record_spawn();
        assert_eq!(rt.remaining_spawn_depth, 1);
        assert_eq!(rt.total_agents_spawned, 1);
        rt.record_spawn();
        assert_eq!(rt.remaining_spawn_depth, 0);
        assert_eq!(rt.total_agents_spawned, 2);
    }

    #[test]
    fn max_total_agents_enforced() {
        let mut rt = AgentRuntime::with_spawn_limits(
            "agent".into(), None, None,
            ResourceBudget::new(None, None, None),
            10, Some(2),
        );
        assert!(rt.can_spawn().is_ok());
        rt.record_spawn();
        assert!(rt.can_spawn().is_ok());
        rt.record_spawn();
        assert!(rt.can_spawn().is_err());
        assert!(rt.can_spawn().unwrap_err().contains("max total agents exceeded"));
    }

    // ── EmotionalState ──────────────────────────────────────────────────

    #[test]
    fn emotional_state_defaults() {
        let es = EmotionalState::new();
        assert!((es.confidence - 0.5).abs() < f64::EPSILON);
        assert!((es.urgency - 0.0).abs() < f64::EPSILON);
        assert!((es.uncertainty - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn emotional_ema_convergence_after_successes() {
        let mut es = EmotionalState::new();
        // 10 successes should drive confidence high and uncertainty low
        for _ in 0..10 {
            es.record_outcome(true, 100, 200);
        }
        assert!(es.confidence > 0.8, "confidence after 10 successes: {}", es.confidence);
        assert!(es.uncertainty < 0.2, "uncertainty after 10 successes: {}", es.uncertainty);
    }

    #[test]
    fn emotional_ema_decay_after_failures() {
        let mut es = EmotionalState::new();
        // Build up confidence with 10 successes
        for _ in 0..10 {
            es.record_outcome(true, 100, 200);
        }
        let high_conf = es.confidence;
        assert!(high_conf > 0.8);

        // 5 failures should drop confidence significantly
        for _ in 0..5 {
            es.record_outcome(false, 100, 200);
        }
        assert!(es.confidence < high_conf - 0.2,
            "confidence should drop significantly: was {high_conf}, now {}", es.confidence);
    }

    #[test]
    fn emotional_urgency_from_budget() {
        let mut es = EmotionalState::new();
        // 10% remaining -> urgency near 0.9
        es.update_urgency_from_budget(0.1);
        assert!((es.urgency - 0.9).abs() < f64::EPSILON,
            "urgency with 10% budget remaining: {}", es.urgency);

        // 100% remaining -> urgency 0.0
        es.update_urgency_from_budget(1.0);
        assert!((es.urgency - 0.0).abs() < f64::EPSILON);

        // 0% remaining -> urgency 1.0
        es.update_urgency_from_budget(0.0);
        assert!((es.urgency - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn emotional_checkpoint_trigger() {
        let mut es = EmotionalState::new();
        // Default uncertainty is 0.5
        assert!(es.should_checkpoint(0.3)); // 0.5 > 0.3
        assert!(!es.should_checkpoint(0.7)); // 0.5 < 0.7

        // Drive uncertainty high with failures
        for _ in 0..10 {
            es.record_outcome(false, 100, 200);
        }
        assert!(es.should_checkpoint(0.7), "uncertainty after failures: {}", es.uncertainty);
    }

    #[test]
    fn emotional_signal_clamping() {
        let mut es = EmotionalState::new();
        // Many successes: confidence should not exceed 1.0, uncertainty should not go below 0.0
        for _ in 0..100 {
            es.record_outcome(true, 100, 200);
        }
        assert!(es.confidence <= 1.0, "confidence clamped: {}", es.confidence);
        assert!(es.confidence >= 0.0);
        assert!(es.uncertainty >= 0.0, "uncertainty clamped: {}", es.uncertainty);
        assert!(es.uncertainty <= 1.0);

        // Many failures
        for _ in 0..100 {
            es.record_outcome(false, 100, 200);
        }
        assert!(es.confidence >= 0.0, "confidence clamped after failures: {}", es.confidence);
        assert!(es.confidence <= 1.0);
        assert!(es.uncertainty >= 0.0);
        assert!(es.uncertainty <= 1.0);

        // Urgency clamping
        es.update_urgency_from_budget(-0.5); // negative fraction
        assert!(es.urgency >= 0.0 && es.urgency <= 1.0);
        es.update_urgency_from_budget(2.0); // over 1.0 fraction
        assert!(es.urgency >= 0.0 && es.urgency <= 1.0);
    }

    #[test]
    fn emotional_urgency_factor() {
        let mut es = EmotionalState::new();
        assert!((es.urgency_factor() - 1.0).abs() < f64::EPSILON); // no urgency

        es.update_urgency_from_budget(0.5); // 50% remaining -> urgency 0.5
        assert!((es.urgency_factor() - 1.5).abs() < f64::EPSILON);

        es.update_urgency_from_budget(0.0); // 0% remaining -> urgency 1.0
        assert!((es.urgency_factor() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn emotional_summary_returns_tuple() {
        let es = EmotionalState::new();
        let (c, u, unc) = es.summary();
        assert!((c - 0.5).abs() < f64::EPSILON);
        assert!((u - 0.0).abs() < f64::EPSILON);
        assert!((unc - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn emotional_urgency_from_slow_operations() {
        let mut es = EmotionalState::new();
        // Operation takes 3x expected -> should increase urgency
        es.record_outcome(true, 3000, 1000);
        assert!(es.urgency > 0.0, "urgency after slow op: {}", es.urgency);
        // Operation within expected -> urgency unchanged by this mechanism
        let prev = es.urgency;
        es.record_outcome(true, 500, 1000);
        // Urgency should not increase (op was fast)
        assert!((es.urgency - prev).abs() < f64::EPSILON,
            "urgency should not increase for fast op");
    }

    #[test]
    fn emotional_runtime_integration() {
        // Verify EmotionalState is on AgentRuntime and accessible
        let mut rt = make_runtime(None, None, None, None);
        assert!((rt.emotional_state.confidence - 0.5).abs() < f64::EPSILON);

        // Record operation outcome via AgentRuntime
        rt.record_operation_outcome(true, 100, 200);
        assert!(rt.emotional_state.confidence > 0.5);
        assert!(rt.emotional_state.uncertainty < 0.5);
    }

    #[test]
    fn emotional_uncertainty_checkpoint_in_pre_step() {
        let mut rt = make_runtime(None, None, None, None);
        // Set threshold
        rt.uncertainty_checkpoint_threshold = Some(0.3);
        // Default uncertainty is 0.5, which is > 0.3
        assert_eq!(rt.pre_step().unwrap(), StepAction::PauseForHumanCheckpoint);

        // Lower uncertainty by recording successes
        for _ in 0..20 {
            rt.emotional_state.record_outcome(true, 100, 200);
        }
        // Uncertainty should now be well below 0.3
        assert!(rt.emotional_state.uncertainty < 0.3,
            "uncertainty: {}", rt.emotional_state.uncertainty);
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    #[test]
    fn emotional_no_checkpoint_when_threshold_none() {
        let mut rt = make_runtime(None, None, None, None);
        // No threshold set (default) -> should never trigger uncertainty checkpoint
        assert_eq!(rt.pre_step().unwrap(), StepAction::Continue);
    }

    // ── LlmCostTracker ────────────────────────────────────────────────────

    #[test]
    fn cost_tracker_record_call_accumulates() {
        let mut tracker = LlmCostTracker::new(None);
        tracker.record_call("gpt-4o", 100, 50);
        assert_eq!(tracker.total_input_tokens, 100);
        assert_eq!(tracker.total_output_tokens, 50);
        assert_eq!(tracker.calls, 1);
        assert!(tracker.total_cost_usd > 0.0);

        tracker.record_call("gpt-4o", 200, 100);
        assert_eq!(tracker.total_input_tokens, 300);
        assert_eq!(tracker.total_output_tokens, 150);
        assert_eq!(tracker.calls, 2);
    }

    #[test]
    fn cost_tracker_budget_enforcement() {
        let mut tracker = LlmCostTracker::new(Some(0.001)); // Very small budget
        assert!(!tracker.is_over_budget());
        // gpt-4: $30/$60 per 1M tokens. 1000 input tokens = $0.03 > $0.001
        tracker.record_call("gpt-4", 1000, 1000);
        assert!(tracker.is_over_budget());
    }

    #[test]
    fn cost_tracker_budget_remaining_decreases() {
        let mut tracker = LlmCostTracker::new(Some(1.0));
        let before = tracker.budget_remaining().unwrap();
        assert!((before - 1.0).abs() < f64::EPSILON);

        tracker.record_call("gpt-4o", 10000, 5000);
        let after = tracker.budget_remaining().unwrap();
        assert!(after < before, "budget remaining should decrease");
    }

    #[test]
    fn cost_tracker_unlimited_budget() {
        let mut tracker = LlmCostTracker::new(None);
        tracker.record_call("gpt-4", 100000, 50000);
        assert!(!tracker.is_over_budget());
        assert_eq!(tracker.budget_remaining(), None);
    }

    #[test]
    fn cost_tracker_unknown_model_zero_cost() {
        let mut tracker = LlmCostTracker::new(None);
        tracker.record_call("llama3.2", 1000, 500);
        assert!((tracker.total_cost_usd - 0.0).abs() < f64::EPSILON);
        assert_eq!(tracker.total_input_tokens, 1000);
        assert_eq!(tracker.total_output_tokens, 500);
    }

    #[test]
    fn cost_tracker_summary() {
        let mut tracker = LlmCostTracker::new(Some(10.0));
        tracker.record_call("claude-sonnet", 500, 200);
        let (inp, out, cost, calls, remaining) = tracker.summary();
        assert_eq!(inp, 500);
        assert_eq!(out, 200);
        assert!(cost > 0.0);
        assert_eq!(calls, 1);
        assert!(remaining.unwrap() < 10.0);
    }

    #[test]
    fn model_pricing_known_models() {
        assert_eq!(model_pricing("gpt-4o"), (2.50, 10.00));
        assert_eq!(model_pricing("gpt-4"), (30.00, 60.00));
        assert_eq!(model_pricing("gpt-3.5-turbo"), (0.50, 1.50));
        assert_eq!(model_pricing("claude-opus-4"), (15.00, 75.00));
        assert_eq!(model_pricing("claude-sonnet-4"), (3.00, 15.00));
        assert_eq!(model_pricing("claude-haiku-3"), (0.25, 1.25));
        assert_eq!(model_pricing("llama3.2"), (0.0, 0.0));
    }

    #[test]
    fn cost_tracker_on_agent_runtime() {
        let rt = make_runtime(None, None, None, None);
        assert_eq!(rt.llm_cost_tracker.calls, 0);
        assert_eq!(rt.llm_cost_tracker.total_input_tokens, 0);
        assert!(!rt.llm_cost_tracker.is_over_budget());
    }

    // ── Cache Hit Tracking ──────────────────────────────────────────────

    #[test]
    fn cache_hit_rate_returns_zero_when_no_calls() {
        let tracker = LlmCostTracker::new(None);
        assert!((tracker.cache_hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_hit_rate_returns_correct_ratio() {
        let mut tracker = LlmCostTracker::new(None);
        tracker.record_cache_hit();
        tracker.record_cache_hit();
        tracker.record_cache_hit();
        tracker.record_cache_miss();
        // 3 hits / 4 total = 0.75
        assert!((tracker.cache_hit_rate() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_hit_rate_all_hits() {
        let mut tracker = LlmCostTracker::new(None);
        tracker.record_cache_hit();
        tracker.record_cache_hit();
        assert!((tracker.cache_hit_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_hit_rate_all_misses() {
        let mut tracker = LlmCostTracker::new(None);
        tracker.record_cache_miss();
        tracker.record_cache_miss();
        assert!((tracker.cache_hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    // ── OTel Trace Context on AgentRuntime ──────────────────────────────

    #[test]
    fn agent_runtime_is_send() {
        // The Arc<Mutex> memory refactor makes AgentRuntime (and thus a spawned
        // agent task) Send. Compile-fails if any member is !Send.
        fn assert_send<T: Send + 'static>() {}
        assert_send::<AgentRuntime>();
    }

    #[test]
    fn runtime_new_creates_trace_and_span_ids() {
        let rt = make_runtime(None, None, None, None);
        assert_eq!(rt.current_trace_id.len(), 32);
        assert!(rt.current_trace_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(rt.current_span_id.len(), 16);
        assert!(rt.current_span_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn next_event_sequence_is_monotonic() {
        let mut rt = make_runtime(None, None, None, None);
        assert_eq!(rt.event_sequence, 0);
        assert_eq!(rt.next_event_sequence(), 1);
        assert_eq!(rt.next_event_sequence(), 2);
        assert_eq!(rt.next_event_sequence(), 3);
    }

    #[test]
    fn with_trace_context_propagates_parent_ids() {
        let rt = make_runtime(None, None, None, None);
        let parent_trace = "aabbccdd11223344aabbccdd11223344".to_string();
        let parent_span = "1122334455667788".to_string();
        let child_rt = rt.with_trace_context(parent_trace.clone(), parent_span.clone());
        assert_eq!(child_rt.current_trace_id, parent_trace);
        assert_eq!(child_rt.current_span_id, parent_span);
    }

    #[test]
    fn begin_step_span_with_event_store() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use rusqlite::Connection;
        use crate::agent_observability::EventStore;

        let mut rt = make_runtime(None, None, None, None);
        let conn = Connection::open_in_memory().unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let store = EventStore::new(shared).unwrap();
        rt.set_event_store(store);

        let old_span = rt.current_span_id.clone();
        let new_span = rt.begin_step_span();

        // Span ID should have changed
        assert_ne!(new_span, old_span);
        assert_eq!(rt.current_span_id, new_span);

        // Event should have been recorded
        assert_eq!(rt.event_sequence, 1);
    }

    #[test]
    fn end_step_span_pushes_to_buffer() {
        let mut rt = make_runtime(None, None, None, None);
        assert_eq!(rt.span_buffer.len(), 0);
        rt.end_step_span(1, "");
        assert_eq!(rt.span_buffer.len(), 1);
    }

    #[test]
    fn begin_step_span_gated_single_event_per_open_span() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use rusqlite::Connection;
        use crate::agent_observability::EventStore;

        let mut rt = make_runtime(None, None, None, None);
        let conn = Connection::open_in_memory().unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let store = EventStore::new(shared).unwrap();
        rt.set_event_store(store);

        // Second begin within an open span: same span_id, no new event.
        let id1 = rt.begin_step_span();
        let id2 = rt.begin_step_span();
        assert_eq!(id1, id2, "open-span begin must not start a new span");

        rt.flush_events();
        let events = rt.event_store.as_ref().unwrap().query_events("test_agent", 0).unwrap();
        assert_eq!(events.len(), 1, "one step_started per logical span");
        assert_eq!(events[0].event_type, "step_started");
    }

    #[test]
    fn end_step_span_records_event_with_payload() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use rusqlite::Connection;
        use crate::agent_observability::EventStore;

        let mut rt = make_runtime(None, None, None, None);
        let conn = Connection::open_in_memory().unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let store = EventStore::new(std::sync::Arc::clone(&shared)).unwrap();
        rt.set_event_store(store);

        rt.begin_step_span();
        rt.end_step_span(1, "");
        // Buffered audit events must be flushed before they are queryable.
        rt.flush_events();

        // Should have 2 events: step_started + step_completed
        let query_store = EventStore::new(shared).unwrap();
        let events = query_store.query_events("test_agent", 0).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "step_started");
        assert_eq!(events[1].event_type, "step_completed");

        // step_completed payload should have expected fields
        let payload: serde_json::Value = serde_json::from_str(&events[1].payload).unwrap();
        assert!(payload.get("steps_executed").is_some());
        assert!(payload.get("confidence").is_some());
        assert!(payload.get("requests_used").is_some());
    }

    #[test]
    fn record_llm_span_creates_client_span() {
        let mut rt = make_runtime(None, None, None, None);
        rt.record_llm_span("gpt-4o", 100, 50, 500, 0.001, false);

        assert_eq!(rt.span_buffer.len(), 1);
        let spans = rt.span_buffer.drain();
        let span_json = spans[0].to_otlp_json();
        assert_eq!(span_json["kind"], 3); // Client
        assert_eq!(span_json["name"], "llm.call");

        // Check LLM-specific attributes
        let attrs = span_json["attributes"].as_array().unwrap();
        let attr_keys: Vec<&str> = attrs.iter()
            .map(|a| a["key"].as_str().unwrap())
            .collect();
        assert!(attr_keys.contains(&"llm.model"));
        assert!(attr_keys.contains(&"llm.input_tokens"));
        assert!(attr_keys.contains(&"llm.output_tokens"));
        assert!(attr_keys.contains(&"llm.latency_ms"));
        assert!(attr_keys.contains(&"llm.cost_usd"));
        assert!(attr_keys.contains(&"llm.cache_hit"));
    }

    #[test]
    fn set_event_store_initializes_sequence_from_db() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use rusqlite::Connection;
        use crate::agent_observability::{EventStore, AgentEvent};

        let conn = Connection::open_in_memory().unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let store = EventStore::new(std::sync::Arc::clone(&shared)).unwrap();

        // Pre-populate some events
        let event = AgentEvent {
            agent_id: "test_agent".to_string(),
            sequence: 42,
            timestamp: "2026-03-04T12:00:00Z".to_string(),
            event_type: "old_event".to_string(),
            payload: "{}".to_string(),
            trace_id: None,
            span_id: None,
        };
        store.append(&event).unwrap();

        // Now create runtime and set event store — sequence should recover
        let mut rt = make_runtime(None, None, None, None);
        let store2 = EventStore::new(shared).unwrap();
        rt.set_event_store(store2);
        assert_eq!(rt.event_sequence, 42);

        // Next sequence should be 43
        assert_eq!(rt.next_event_sequence(), 43);
    }

    #[test]
    fn pre_step_emits_span_when_event_store_set() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use rusqlite::Connection;
        use crate::agent_observability::EventStore;

        let mut rt = make_runtime(None, None, None, None);
        let conn = Connection::open_in_memory().unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let store = EventStore::new(shared).unwrap();
        rt.set_event_store(store);

        let result = rt.pre_step();
        assert_eq!(result.unwrap(), StepAction::Continue);

        // Should have recorded a step_started event
        assert!(rt.event_sequence > 0, "event_sequence should be > 0 after pre_step with event store");
    }

    // ── AgentHealthData ──────────────────────────────────────────────────

    #[test]
    fn health_data_populates_from_runtime() {
        let mut rt = make_runtime(None, None, Some(100), None);
        rt.budget.max_memory_bytes = Some(1024 * 1024);
        rt.budget.memory_used_bytes = 2048;
        rt.budget.record_request();
        rt.budget.record_request();
        rt.budget.record_request();
        let _ = rt.pre_step(); // steps_executed = 1
        rt.goals_attempted = 5;
        rt.goals_completed = 3;
        rt.emotional_state.confidence = 0.9;
        rt.emotional_state.urgency = 0.2;
        rt.emotional_state.uncertainty = 0.1;
        rt.llm_cost_tracker.record_call("gpt-4o", 100, 50);

        let hd = rt.health_data();
        assert_eq!(hd.agent_id, "test_agent");
        assert_eq!(hd.memory_used, 2048);
        assert_eq!(hd.memory_limit, 1024 * 1024);
        assert_eq!(hd.requests_used, 3);
        assert_eq!(hd.requests_limit, 100);
        assert_eq!(hd.steps_executed, 1);
        assert_eq!(hd.goals_attempted, 5);
        assert_eq!(hd.goals_completed, 3);
        assert!((hd.confidence - 0.9).abs() < f64::EPSILON);
        assert!((hd.urgency - 0.2).abs() < f64::EPSILON);
        assert!((hd.uncertainty - 0.1).abs() < f64::EPSILON);
        assert_eq!(hd.llm_calls, 1);
        assert!(hd.llm_cost_usd > 0.0);
    }

    #[test]
    fn health_data_uptime_positive() {
        let rt = make_runtime(None, None, None, None);
        std::thread::sleep(Duration::from_millis(5));
        let hd = rt.health_data();
        assert!(hd.uptime_ms > 0, "uptime_ms should be > 0");
    }

    #[test]
    fn goal_completion_rate_zero_when_no_goals() {
        let rt = make_runtime(None, None, None, None);
        let hd = rt.health_data();
        assert!((hd.goal_completion_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn goal_completion_rate_correct_after_recording() {
        let mut rt = make_runtime(None, None, None, None);
        rt.record_goal_attempt();
        rt.record_goal_attempt();
        rt.record_goal_attempt();
        rt.record_goal_attempt();
        rt.record_goal_completion();
        rt.record_goal_completion();
        rt.record_goal_completion();
        // 3/4 = 0.75
        let hd = rt.health_data();
        assert!((hd.goal_completion_rate - 0.75).abs() < f64::EPSILON);
    }

    // ── Auto-checkpoint ──────────────────────────────────────────────────

    #[test]
    fn auto_checkpoint_due_false_when_interval_none() {
        let rt = make_runtime(None, None, None, None);
        assert!(!rt.auto_checkpoint_due());
    }

    #[test]
    fn auto_checkpoint_due_true_when_steps_exceed_interval() {
        let mut rt = make_runtime(None, None, None, None);
        rt.checkpoint_interval = Some(5);
        rt.steps_since_auto_checkpoint = 4;
        assert!(!rt.auto_checkpoint_due());
        rt.steps_since_auto_checkpoint = 5;
        assert!(rt.auto_checkpoint_due());
        rt.steps_since_auto_checkpoint = 10;
        assert!(rt.auto_checkpoint_due());
    }

    #[test]
    fn reset_auto_checkpoint_counter_resets() {
        let mut rt = make_runtime(None, None, None, None);
        rt.checkpoint_interval = Some(5);
        rt.steps_since_auto_checkpoint = 7;
        rt.reset_auto_checkpoint_counter();
        assert_eq!(rt.steps_since_auto_checkpoint, 0);
        assert!(!rt.auto_checkpoint_due());
    }

    // ── A1.1.4: unified-ledger live emission ────────────────────────────

    #[test]
    fn queued_events_mirror_into_the_attached_ledger() {
        use crate::agent_ledger::LedgerBackend as _;
        use crate::agent_observability::AgentEvent;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let rec = LedgerRecorder::new(
            crate::agent_ledger_sqlite::SqliteLedger::open(&path).unwrap(),
            "agent:test",
            "run-ledger-live",
        )
        .unwrap();
        let mut rt = make_runtime(None, None, None, None);
        rt.set_ledger(rec);

        // Queue one audit event through the live mirror point.
        let event = AgentEvent {
            agent_id: "test_agent".to_string(),
            sequence: rt.next_event_sequence(),
            timestamp: "2026-09-11T00:00:00Z".to_string(),
            event_type: "step_completed".to_string(),
            payload: "{\"n\":1}".to_string(),
            trace_id: None,
            span_id: None,
        };
        rt.queue_event(event);

        // The mirror is inline: read the chain back from disk.
        let backend = crate::agent_ledger_sqlite::SqliteLedger::open(&path).unwrap();
        let all = backend.read_all().unwrap();
        assert_eq!(all.len(), 1, "exactly one mirrored event");
        assert_eq!(all[0].actor, "agent:test");
        assert_eq!(all[0].run_id, "run-ledger-live");
        let payload = &all[0].payload;
        assert!(
            payload.contains("step_completed"),
            "ledger payload carries the event type: {payload}"
        );
        // Inner payload may be nested as an escaped JSON string; normalize.
        let unescaped = payload.replace('\\', "");
        assert!(
            unescaped.contains("\"n\":1"),
            "ledger payload carries the event payload: {payload}"
        );
    }
}
