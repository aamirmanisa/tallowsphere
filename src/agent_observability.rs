//! Agent Observability — OTel-compatible span generation and event sourcing.
//!
//! Provides:
//! - OTel span types (OtelSpan, SpanKind, SpanStatus, SpanEvent) with OTLP/JSON export
//! - SpanBuffer for buffered span collection and batch export
//! - EventStore for append-only event sourcing backed by SQLite
//! - AgentEvent for immutable state transition records with monotonic sequence numbers
//!
//! OTel spans are compatible with any OTLP/JSON receiver (Jaeger, Zipkin, Grafana Tempo).
//! EventStore provides the crash-replay audit trail for every agent state transition.
//!
//! ## Unified-ledger emission (task A1.1.4 — live)
//! [`emit_agent_event`] bridges an `AgentEvent` into the unified, hash-chained
//! agent ledger as an `agent_step` entry. It is wired into the live agent path:
//! [`crate::agent_runtime::AgentRuntime`] mirrors every audit event it queues
//! through the bridge when a [`Recorder`](crate::agent_ledger::Recorder) is
//! attached (and the interpreter's direct-to-store lifecycle events —
//! `checkpoint`, `shutdown`, `recovered` — are emitted the same way).
//! Emission is opt-in —
//! `TALLOW_LEDGER_PATH` in the environment, or `AgentRuntime::set_ledger` —
//! and a runtime with no recorder attached behaves exactly as before.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Generate a 32 hex char trace ID (16 random bytes).
pub fn generate_trace_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Random base seed for span IDs, initialized exactly once from the OS RNG.
static SPAN_ID_BASE: OnceLock<u64> = OnceLock::new();

/// Monotonic counter incremented once per span-ID request.
static SPAN_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a 16 hex char span ID (monotonic, seeded once from the OS RNG).
///
/// Span IDs only need uniqueness (not cryptographic strength), so instead of a
/// per-call random draw we bump an atomic counter seeded once from the OS RNG.
/// `{:016x}` yields a fixed-width, zero-padded lowercase hex string, preserving
/// the OTel 16-char span ID contract consumers parse today.
pub fn generate_span_id() -> String {
    let base = *SPAN_ID_BASE.get_or_init(|| {
        let mut seed = [0u8; 8];
        rand::fill(&mut seed);
        u64::from_ne_bytes(seed)
    });
    let n = base.wrapping_add(SPAN_ID_COUNTER.fetch_add(1, Ordering::Relaxed));
    format!("{n:016x}")
}

/// Current time as nanoseconds since Unix epoch.
pub fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// ── SpanKind ───────────────────────────────────────────────────────────────

/// OTel span kind, matching the OTLP spec values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpanKind {
    Unspecified = 0,
    Internal = 1,
    Server = 2,
    Client = 3,
    Producer = 4,
    Consumer = 5,
}

impl SpanKind {
    /// OTLP integer representation.
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }
}

// ── SpanStatus ─────────────────────────────────────────────────────────────

/// OTel span status: 0=unset, 1=ok, 2=error.
#[derive(Debug, Clone)]
pub struct SpanStatus {
    /// Status code: 0=unset, 1=ok, 2=error.
    pub code: u32,
    /// Optional human-readable message (typically set for error status).
    pub message: String,
}

impl SpanStatus {
    pub fn unset() -> Self {
        Self {
            code: 0,
            message: String::new(),
        }
    }

    pub fn ok() -> Self {
        Self {
            code: 1,
            message: String::new(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            code: 2,
            message: message.to_string(),
        }
    }
}

// ── SpanEvent ──────────────────────────────────────────────────────────────

/// An event (annotation/log) attached to a span.
#[derive(Debug, Clone)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp_unix_nano: u64,
    pub attributes: Vec<(String, serde_json::Value)>,
}

impl SpanEvent {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            timestamp_unix_nano: now_unix_nano(),
            attributes: Vec::new(),
        }
    }

    pub fn with_attribute(mut self, key: &str, value: serde_json::Value) -> Self {
        self.attributes.push((key.to_string(), value));
        self
    }
}

// ── OtelSpan ───────────────────────────────────────────────────────────────

/// An OTel-compatible span with trace context, timing, attributes, and events.
#[derive(Debug, Clone)]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: SpanKind,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: Vec<(String, serde_json::Value)>,
    pub events: Vec<SpanEvent>,
    pub status: SpanStatus,
}

impl OtelSpan {
    /// Create a new span with generated span_id and current start time.
    pub fn new(trace_id: &str, parent_span_id: Option<&str>, name: &str, kind: SpanKind) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            span_id: generate_span_id(),
            parent_span_id: parent_span_id.map(|s| s.to_string()),
            name: name.to_string(),
            kind,
            start_time_unix_nano: now_unix_nano(),
            end_time_unix_nano: 0,
            attributes: Vec::new(),
            events: Vec::new(),
            status: SpanStatus::unset(),
        }
    }

    /// End this span with a status and record the end timestamp.
    pub fn end(&mut self, status: SpanStatus) {
        self.end_time_unix_nano = now_unix_nano();
        self.status = status;
    }

    /// Add an attribute to this span.
    pub fn add_attribute(&mut self, key: &str, value: serde_json::Value) {
        self.attributes.push((key.to_string(), value));
    }

    /// Add an event to this span.
    pub fn add_event(&mut self, event: SpanEvent) {
        self.events.push(event);
    }

    /// Convert attributes to OTLP JSON format:
    /// `[{"key": k, "value": {"stringValue": v}}]` for strings,
    /// `[{"key": k, "value": {"intValue": v}}]` for integers, etc.
    fn attributes_to_otlp(attrs: &[(String, serde_json::Value)]) -> serde_json::Value {
        let arr: Vec<serde_json::Value> = attrs
            .iter()
            .map(|(key, val)| {
                let typed_value = match val {
                    serde_json::Value::String(s) => {
                        serde_json::json!({"stringValue": s})
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            serde_json::json!({"intValue": i.to_string()})
                        } else if let Some(f) = n.as_f64() {
                            serde_json::json!({"doubleValue": f})
                        } else {
                            serde_json::json!({"stringValue": n.to_string()})
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        serde_json::json!({"boolValue": b})
                    }
                    _ => {
                        serde_json::json!({"stringValue": val.to_string()})
                    }
                };
                serde_json::json!({"key": key, "value": typed_value})
            })
            .collect();
        serde_json::Value::Array(arr)
    }

    /// Emit this span as OTLP/JSON with lowerCamelCase field names.
    /// Timestamps are strings per OTLP spec.
    pub fn to_otlp_json(&self) -> serde_json::Value {
        let events: Vec<serde_json::Value> = self
            .events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "timeUnixNano": e.timestamp_unix_nano.to_string(),
                    "attributes": Self::attributes_to_otlp(&e.attributes)
                })
            })
            .collect();

        let mut span = serde_json::json!({
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": self.kind.as_u32(),
            "startTimeUnixNano": self.start_time_unix_nano.to_string(),
            "endTimeUnixNano": self.end_time_unix_nano.to_string(),
            "attributes": Self::attributes_to_otlp(&self.attributes),
            "events": events,
            "status": {
                "code": self.status.code,
                "message": &self.status.message
            }
        });

        if let Some(ref parent) = self.parent_span_id {
            span.as_object_mut()
                .unwrap()
                .insert("parentSpanId".to_string(), serde_json::json!(parent));
        }

        span
    }
}

// ── SpanBuffer ─────────────────────────────────────────────────────────────

/// Buffered collection of OTel spans for batch export.
#[derive(Debug)]
pub struct SpanBuffer {
    spans: Vec<OtelSpan>,
}

impl SpanBuffer {
    pub fn new() -> Self {
        Self { spans: Vec::new() }
    }

    /// Add a completed span to the buffer.
    pub fn push(&mut self, span: OtelSpan) {
        self.spans.push(span);
    }

    /// Take all spans, leaving the buffer empty.
    pub fn drain(&mut self) -> Vec<OtelSpan> {
        std::mem::take(&mut self.spans)
    }

    /// Number of spans in the buffer.
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Export all buffered spans as a complete OTLP/JSON envelope.
    ///
    /// Format:
    /// ```json
    /// {"resourceSpans": [{"resource": {"attributes": []},
    ///   "scopeSpans": [{"scope": {"name": "tallow-agent"}, "spans": [...]}]}]}
    /// ```
    pub fn to_otlp_json(&self) -> serde_json::Value {
        let spans: Vec<serde_json::Value> =
            self.spans.iter().map(|s| s.to_otlp_json()).collect();

        serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": []
                },
                "scopeSpans": [{
                    "scope": {
                        "name": "tallow-agent"
                    },
                    "spans": spans
                }]
            }]
        })
    }
}

// ── AgentEvent ─────────────────────────────────────────────────────────────

/// An immutable event record for agent state transitions (event sourcing).
#[derive(Debug, Clone)]
pub struct AgentEvent {
    pub agent_id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub event_type: String,
    pub payload: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

// ── EventStore ─────────────────────────────────────────────────────────────

/// Schema for the agent_events table.
pub const EVENT_STORE_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS agent_events (\
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    agent_id TEXT NOT NULL, \
    sequence INTEGER NOT NULL, \
    timestamp TEXT NOT NULL DEFAULT (datetime('now')), \
    event_type TEXT NOT NULL, \
    payload TEXT NOT NULL DEFAULT '{}', \
    trace_id TEXT, \
    span_id TEXT\
);\
CREATE INDEX IF NOT EXISTS idx_events_agent ON agent_events(agent_id, sequence);\
CREATE INDEX IF NOT EXISTS idx_events_type ON agent_events(event_type);";

/// Append-only event store backed by SQLite.
///
/// Shares the Brain's SQLite connection via `Arc<Mutex<Connection>>`.
/// Events are never updated or deleted — append-only for audit integrity.
#[derive(Debug)]
pub struct EventStore {
    db: Arc<Mutex<Connection>>,
    /// When set, all ops route through the unified-store coordinator (2.0),
    /// preserving FIFO + read-your-own-writes. When None (backward compat),
    /// ops lock `db` directly.
    pub client: Option<crate::agent_store::StoreClient>,
}

impl EventStore {
    /// Create a new EventStore, executing schema creation on the connection.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        {
            let db = conn.lock().map_err(|_| "store lock poisoned".to_string())?;
            db.execute_batch(EVENT_STORE_SCHEMA)
                .map_err(|e| format!("failed to create event store schema: {e}"))?;
        }
        Ok(Self { db: conn, client: None })
    }

    /// Create a store that routes ops through a shared coordinator client.
    pub fn with_client(
        conn: Arc<Mutex<Connection>>,
        client: crate::agent_store::StoreClient,
    ) -> Result<Self, String> {
        {
            let db = conn.lock().map_err(|_| "store lock poisoned".to_string())?;
            db.execute_batch(EVENT_STORE_SCHEMA)
                .map_err(|e| format!("failed to create event store schema: {e}"))?;
        }
        Ok(Self { db: conn, client: Some(client) })
    }

    /// Run `op` against the connection, either through the coordinator client
    /// (FIFO, read-your-own-writes) or by locking `db` directly.
    fn run_conn<T>(&self, op: impl FnOnce(&mut Connection) -> Result<T, String> + Send + 'static) -> Result<T, String>
    where
        T: Send + 'static,
    {
        if let Some(ref client) = self.client {
            client.run(op)
        } else {
            let mut db = self.db.lock().map_err(|_| "store lock poisoned".to_string())?;
            op(&mut db)
        }
    }

    /// Append an event. Append-only: never UPDATE or DELETE.
    pub fn append(&self, event: &AgentEvent) -> Result<(), String> {
        let (agent_id, sequence, timestamp, event_type, payload, trace_id, span_id) = (
            event.agent_id.clone(),
            event.sequence,
            event.timestamp.clone(),
            event.event_type.clone(),
            event.payload.clone(),
            event.trace_id.clone(),
            event.span_id.clone(),
        );
        self.run_conn(move |db| {
            db.execute(
                "INSERT INTO agent_events (agent_id, sequence, timestamp, event_type, payload, trace_id, span_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    agent_id, sequence, timestamp, event_type, payload, trace_id, span_id
                ],
            )
            .map_err(|e| format!("failed to append event: {e}"))?;
            Ok(())
        })
    }

    /// Append many events in a single transaction, collapsing N fsync/commit
    /// round-trips into one BEGIN + one COMMIT. Preserves append-only semantics.
    pub fn append_batch(&self, events: &[AgentEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let owned: Vec<(
            String, u64, String, String, String, Option<String>, Option<String>,
        )> = events
            .iter()
            .map(|e| {
                (
                    e.agent_id.clone(),
                    e.sequence,
                    e.timestamp.clone(),
                    e.event_type.clone(),
                    e.payload.clone(),
                    e.trace_id.clone(),
                    e.span_id.clone(),
                )
            })
            .collect();
        self.run_conn(move |db| {
            let tx = db
                .transaction()
                .map_err(|e| format!("failed to begin event batch: {e}"))?;
            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO agent_events (agent_id, sequence, timestamp, event_type, payload, trace_id, span_id) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    )
                    .map_err(|e| format!("failed to prepare event batch: {e}"))?;
                for (agent_id, sequence, timestamp, event_type, payload, trace_id, span_id) in &owned {
                    stmt.execute(rusqlite::params![
                        agent_id, sequence, timestamp, event_type, payload, trace_id, span_id
                    ])
                    .map_err(|e| format!("failed to append event in batch: {e}"))?;
                }
            }
            tx.commit()
                .map_err(|e| format!("failed to commit event batch: {e}"))?;
            Ok(())
        })
    }

    /// Get the maximum sequence number for an agent (0 if no events exist).
    /// Used for crash recovery sequence initialization.
    pub fn get_max_sequence(&self, agent_id: &str) -> Result<u64, String> {
        let agent_id = agent_id.to_string();
        self.run_conn(move |db| {
            let seq: i64 = db
                .query_row(
                    "SELECT COALESCE(MAX(sequence), 0) FROM agent_events WHERE agent_id = ?1",
                    rusqlite::params![agent_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("failed to get max sequence: {e}"))?;
            Ok(seq as u64)
        })
    }

    /// Query events for an agent with sequence > since_sequence, ordered ASC.
    pub fn query_events(
        &self,
        agent_id: &str,
        since_sequence: u64,
    ) -> Result<Vec<AgentEvent>, String> {
        let agent_id = agent_id.to_string();
        self.run_conn(move |db| {
            let mut stmt = db
                .prepare(
                    "SELECT agent_id, sequence, timestamp, event_type, payload, trace_id, span_id \
                     FROM agent_events WHERE agent_id = ?1 AND sequence > ?2 ORDER BY sequence ASC",
                )
                .map_err(|e| format!("failed to prepare query: {e}"))?;

            let rows = stmt
                .query_map(rusqlite::params![agent_id, since_sequence], |row| {
                    Ok(AgentEvent {
                        agent_id: row.get(0)?,
                        sequence: row.get::<_, i64>(1)? as u64,
                        timestamp: row.get(2)?,
                        event_type: row.get(3)?,
                        payload: row.get(4)?,
                        trace_id: row.get(5)?,
                        span_id: row.get(6)?,
                    })
                })
                .map_err(|e| format!("failed to query events: {e}"))?;

            let mut events = Vec::new();
            for row in rows {
                events.push(row.map_err(|e| format!("row error: {e}"))?);
            }
            Ok(events)
        })
    }
}

// ── CheckpointStore ───────────────────────────────────────────────────

/// Schema for the agent_checkpoints table.
pub const CHECKPOINT_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS agent_checkpoints (\
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    agent_id TEXT NOT NULL, \
    timestamp TEXT NOT NULL DEFAULT (datetime('now')), \
    steps_executed INTEGER NOT NULL, \
    requests_used INTEGER NOT NULL, \
    memory_used INTEGER NOT NULL, \
    confidence REAL NOT NULL, \
    urgency REAL NOT NULL, \
    uncertainty REAL NOT NULL, \
    working_memory TEXT NOT NULL, \
    llm_tracker TEXT NOT NULL, \
    event_sequence INTEGER NOT NULL, \
    goals_attempted INTEGER NOT NULL DEFAULT 0, \
    goals_completed INTEGER NOT NULL DEFAULT 0\
);\
CREATE INDEX IF NOT EXISTS idx_checkpoints_agent ON agent_checkpoints(agent_id, timestamp);";

/// Data restored from a checkpoint row.
#[derive(Debug, Clone)]
pub struct CheckpointData {
    pub agent_id: String,
    pub timestamp: String,
    pub steps_executed: u32,
    pub requests_used: u32,
    pub memory_used: u64,
    pub confidence: f64,
    pub urgency: f64,
    pub uncertainty: f64,
    pub working_memory: String,
    pub llm_tracker: String,
    pub event_sequence: u64,
    pub goals_attempted: u32,
    pub goals_completed: u32,
}

/// Persistent checkpoint store backed by SQLite.
///
/// Shares the Brain/EventStore's SQLite connection via `Arc<Mutex<Connection>>`.
/// Saves and loads agent runtime state for crash recovery.
#[derive(Debug)]
pub struct CheckpointStore {
    db: Arc<Mutex<Connection>>,
    /// When set, ops route through the unified-store coordinator (2.0).
    pub client: Option<crate::agent_store::StoreClient>,
}

impl CheckpointStore {
    /// Create a new CheckpointStore, executing schema creation on the connection.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        {
            let db = conn.lock().map_err(|_| "store lock poisoned".to_string())?;
            db.execute_batch(CHECKPOINT_SCHEMA)
                .map_err(|e| format!("failed to create checkpoint schema: {e}"))?;
        }
        Ok(Self { db: conn, client: None })
    }

    /// Create a store that routes ops through a shared coordinator client.
    pub fn with_client(
        conn: Arc<Mutex<Connection>>,
        client: crate::agent_store::StoreClient,
    ) -> Result<Self, String> {
        {
            let db = conn.lock().map_err(|_| "store lock poisoned".to_string())?;
            db.execute_batch(CHECKPOINT_SCHEMA)
                .map_err(|e| format!("failed to create checkpoint schema: {e}"))?;
        }
        Ok(Self { db: conn, client: Some(client) })
    }

    /// Run `op` against the connection, through the coordinator client (FIFO,
    /// read-your-own-writes) or by locking `db` directly (backward compat).
    fn run_conn<T>(&self, op: impl FnOnce(&mut Connection) -> Result<T, String> + Send + 'static) -> Result<T, String>
    where
        T: Send + 'static,
    {
        if let Some(ref client) = self.client {
            client.run(op)
        } else {
            let mut db = self.db.lock().map_err(|_| "store lock poisoned".to_string())?;
            op(&mut db)
        }
    }

    /// Save a checkpoint from the current AgentRuntime state.
    ///
    /// `working_memory_json` should be a JSON-serialized array of working memory items.
    /// LlmCostTracker is serialized as a JSON object inline.
    pub fn save_checkpoint(
        &self,
        agent_id: &str,
        rt: &crate::agent_runtime::AgentRuntime,
        working_memory_json: &str,
        event_sequence: u64,
    ) -> Result<(), String> {
        let llm_tracker_json = serde_json::json!({
            "input_tokens": rt.llm_cost_tracker.total_input_tokens,
            "output_tokens": rt.llm_cost_tracker.total_output_tokens,
            "cost_usd": rt.llm_cost_tracker.total_cost_usd,
            "calls": rt.llm_cost_tracker.calls,
            "cache_hits": rt.llm_cost_tracker.cache_hits,
            "cache_misses": rt.llm_cost_tracker.cache_misses,
        })
        .to_string();

        let (agent_id, working_memory_json, llm_tracker_json, event_sequence) = (
            agent_id.to_string(),
            working_memory_json.to_string(),
            llm_tracker_json,
            event_sequence,
        );
        let (steps, requests, memory, confidence, urgency, uncertainty, ga, gc) = (
            rt.steps_executed,
            rt.budget.requests_used,
            rt.budget.memory_used_bytes,
            rt.emotional_state.confidence,
            rt.emotional_state.urgency,
            rt.emotional_state.uncertainty,
            rt.goals_attempted,
            rt.goals_completed,
        );
        self.run_conn(move |db| {
            db.execute(
                "INSERT INTO agent_checkpoints \
                 (agent_id, steps_executed, requests_used, memory_used, \
                  confidence, urgency, uncertainty, working_memory, \
                  llm_tracker, event_sequence, goals_attempted, goals_completed) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    agent_id, steps, requests, memory, confidence, urgency, uncertainty,
                    working_memory_json, llm_tracker_json, event_sequence, ga, gc,
                ],
            )
            .map_err(|e| format!("failed to save checkpoint: {e}"))?;
            Ok(())
        })
    }

    /// Load the latest checkpoint for an agent. Returns None if no checkpoints exist.
    pub fn load_latest_checkpoint(
        &self,
        agent_id: &str,
    ) -> Result<Option<CheckpointData>, String> {
        let agent_id = agent_id.to_string();
        self.run_conn(move |db| {
            let mut stmt = db
                .prepare(
                    "SELECT agent_id, timestamp, steps_executed, requests_used, \
                     memory_used, confidence, urgency, uncertainty, \
                     working_memory, llm_tracker, event_sequence, \
                     goals_attempted, goals_completed \
                     FROM agent_checkpoints WHERE agent_id = ?1 \
                     ORDER BY id DESC LIMIT 1",
                )
                .map_err(|e| format!("failed to prepare checkpoint query: {e}"))?;

            let result = stmt.query_row(rusqlite::params![agent_id], |row| {
                Ok(CheckpointData {
                    agent_id: row.get(0)?,
                    timestamp: row.get(1)?,
                    steps_executed: row.get::<_, i32>(2)? as u32,
                    requests_used: row.get::<_, i32>(3)? as u32,
                    memory_used: row.get::<_, i64>(4)? as u64,
                    confidence: row.get(5)?,
                    urgency: row.get(6)?,
                    uncertainty: row.get(7)?,
                    working_memory: row.get(8)?,
                    llm_tracker: row.get(9)?,
                    event_sequence: row.get::<_, i64>(10)? as u64,
                    goals_attempted: row.get::<_, i32>(11)? as u32,
                    goals_completed: row.get::<_, i32>(12)? as u32,
                })
            });

            match result {
                Ok(data) => Ok(Some(data)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(format!("failed to load checkpoint: {e}")),
            }
        })
    }

    /// Count the number of checkpoints stored for an agent.
    pub fn count_checkpoints(&self, agent_id: &str) -> Result<u64, String> {
        let agent_id = agent_id.to_string();
        self.run_conn(move |db| {
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM agent_checkpoints WHERE agent_id = ?1",
                    rusqlite::params![agent_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("failed to count checkpoints: {e}"))?;
            Ok(count as u64)
        })
    }
}

// ── IdempotencyStore ──────────────────────────────────────────────────

/// Schema for the idempotency_keys table.
pub const IDEMPOTENCY_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS idempotency_keys (\
    key TEXT PRIMARY KEY, \
    result TEXT NOT NULL, \
    status_code INTEGER, \
    created_at TEXT NOT NULL DEFAULT (datetime('now')), \
    expires_at TEXT\
);";

/// Generate a deterministic idempotency key from agent_id, URL, and HTTP method.
///
/// Returns `"idem_"` + first 32 hex chars of SHA-256(agent_id + url + method).
pub fn generate_idempotency_key(agent_id: &str, url: &str, method: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(url.as_bytes());
    hasher.update(method.as_bytes());
    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    format!("idem_{}", &hex[..32])
}

/// Idempotency store for deduplicating external operations in agent context.
///
/// Shares the Brain/EventStore/CheckpointStore SQLite connection via `Arc<Mutex<Connection>>`.
/// Before making an HTTP call, check if the key exists; if so, return the cached result.
/// After a successful HTTP call, record the result for future deduplication.
#[derive(Debug)]
pub struct IdempotencyStore {
    db: Arc<Mutex<Connection>>,
    /// When set, ops route through the unified-store coordinator (2.0).
    pub client: Option<crate::agent_store::StoreClient>,
}

impl IdempotencyStore {
    /// Create a new IdempotencyStore, executing schema creation on the connection.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        {
            let db = conn.lock().map_err(|_| "store lock poisoned".to_string())?;
            db.execute_batch(IDEMPOTENCY_SCHEMA)
                .map_err(|e| format!("failed to create idempotency schema: {e}"))?;
        }
        Ok(Self { db: conn, client: None })
    }

    /// Create a store that routes ops through a shared coordinator client.
    pub fn with_client(
        conn: Arc<Mutex<Connection>>,
        client: crate::agent_store::StoreClient,
    ) -> Result<Self, String> {
        {
            let db = conn.lock().map_err(|_| "store lock poisoned".to_string())?;
            db.execute_batch(IDEMPOTENCY_SCHEMA)
                .map_err(|e| format!("failed to create idempotency schema: {e}"))?;
        }
        Ok(Self { db: conn, client: Some(client) })
    }

    /// Run `op` against the connection, through the coordinator client (FIFO,
    /// read-your-own-writes) or by locking `db` directly (backward compat).
    fn run_conn<T>(&self, op: impl FnOnce(&mut Connection) -> Result<T, String> + Send + 'static) -> Result<T, String>
    where
        T: Send + 'static,
    {
        if let Some(ref client) = self.client {
            client.run(op)
        } else {
            let mut db = self.db.lock().map_err(|_| "store lock poisoned".to_string())?;
            op(&mut db)
        }
    }

    /// Check if an idempotency key exists and is not expired.
    ///
    /// Returns `Some((result, status_code))` if the key exists and hasn't expired,
    /// `None` otherwise.
    pub fn check(&self, key: &str) -> Result<Option<(String, Option<i32>)>, String> {
        let key = key.to_string();
        self.run_conn(move |db| {
            let mut stmt = db
                .prepare(
                    "SELECT result, status_code FROM idempotency_keys \
                     WHERE key = ?1 AND (expires_at IS NULL OR expires_at > datetime('now'))",
                )
                .map_err(|e| format!("failed to prepare idempotency check: {e}"))?;

            let result = stmt.query_row(rusqlite::params![key], |row| {
                let result: String = row.get(0)?;
                let status_code: Option<i32> = row.get(1)?;
                Ok((result, status_code))
            });

            match result {
                Ok(data) => Ok(Some(data)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(format!("failed to check idempotency key: {e}")),
            }
        })
    }

    /// Record an idempotency key with its result, status code, and optional TTL in hours.
    ///
    /// Uses INSERT OR IGNORE so existing keys are never overwritten.
    pub fn record(
        &self,
        key: &str,
        result: &str,
        status_code: i32,
        ttl_hours: Option<u32>,
    ) -> Result<(), String> {
        let (key, result, expires_at) = (key.to_string(), result.to_string(), ttl_hours.map(|h| format!("+{h} hours")));
        self.run_conn(move |db| {
            db.execute(
                "INSERT OR IGNORE INTO idempotency_keys (key, result, status_code, expires_at) \
                 VALUES (?1, ?2, ?3, CASE WHEN ?4 IS NOT NULL THEN datetime('now', ?4) ELSE NULL END)",
                rusqlite::params![key, result, status_code, expires_at],
            )
            .map_err(|e| format!("failed to record idempotency key: {e}"))?;
            Ok(())
        })
    }

    /// Delete expired idempotency keys. Returns the number of rows deleted.
    pub fn cleanup_expired(&self) -> Result<u64, String> {
        self.run_conn(move |db| {
            let deleted = db
                .execute(
                    "DELETE FROM idempotency_keys WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')",
                    [],
                )
                .map_err(|e| format!("failed to cleanup expired idempotency keys: {e}"))?;
            Ok(deleted as u64)
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

// ── A1.1.4: emission into the unified ledger ────────────────────────────────

/// Emit one agent action ([`AgentEvent`]) into the unified hash-chained
/// ledger as an `agent_step` event (task A1.1.4 — emission from agent
/// actions; pair with [`Recorder`](crate::agent_ledger::Recorder)).
///
/// **Live call sites:** `AgentRuntime::queue_event` (every queued audit
/// event — the `step_started`/`step_completed` span lifecycle) and the
/// interpreter's direct-to-store lifecycle events (`checkpoint`, `shutdown`,
/// `recovered`), both via
/// [`AgentRuntime::emit_ledger_event`](crate::agent_runtime::AgentRuntime::emit_ledger_event).
/// Both are no-ops until a recorder is attached (the `TALLOW_LEDGER_PATH`
/// opt-in), so the ledger off means zero writes.
///
/// The event's fields are carried in the ledger payload as canonical JSON;
/// the event's own `payload` string is embedded **verbatim as a string** so
/// the emission is deterministic and never re-interprets caller data. The
/// ledger owns the envelope id/ts/hash; `AgentEvent::sequence` keeps its
/// meaning for the local SQLite event store.
pub fn emit_agent_event<B: crate::agent_ledger::LedgerBackend>(
    rec: &mut crate::agent_ledger::Recorder<B>,
    ev: &AgentEvent,
) -> Result<crate::ledger_events::EventEnvelope, crate::agent_ledger::LedgerError> {
    let payload = serde_json::json!({
        "agent_id": ev.agent_id,
        "sequence": ev.sequence,
        "timestamp": ev.timestamp,
        "event_type": ev.event_type,
        "payload": ev.payload,
        "trace_id": ev.trace_id,
        "span_id": ev.span_id,
    })
    .to_string();
    rec.record(crate::ledger_events::EventKind::AgentStep, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ID Generation ──────────────────────────────────────────────────

    #[test]
    fn generate_trace_id_returns_32_hex_chars() {
        let id = generate_trace_id();
        assert_eq!(id.len(), 32, "trace_id length: {}", id.len());
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "trace_id not all hex: {id}"
        );
    }

    #[test]
    fn generate_span_id_returns_16_hex_chars() {
        let id = generate_span_id();
        assert_eq!(id.len(), 16, "span_id length: {}", id.len());
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "span_id not all hex: {id}"
        );
    }

    #[test]
    fn generate_trace_id_unique() {
        let a = generate_trace_id();
        let b = generate_trace_id();
        assert_ne!(a, b, "two trace IDs should differ");
    }

    #[test]
    fn generate_span_id_unique() {
        let a = generate_span_id();
        let b = generate_span_id();
        assert_ne!(a, b, "two span IDs should differ");
    }

    #[test]
    fn generate_span_id_unique_across_many_calls() {
        let n = 4096usize;
        let ids: std::collections::HashSet<String> =
            (0..n).map(|_| generate_span_id()).collect();
        // Every call must return a distinct, well-formed span ID.
        assert_eq!(ids.len(), n, "span IDs must be unique across {n} calls");
        for id in &ids {
            assert_eq!(id.len(), 16, "span_id length: {id}");
            assert!(
                id.chars().all(|c| c.is_ascii_hexdigit()),
                "span_id not all hex: {id}"
            );
        }
    }

    #[test]
    fn generate_span_id_monotonically_increments() {
        let a = u64::from_str_radix(&generate_span_id(), 16).unwrap();
        let b = u64::from_str_radix(&generate_span_id(), 16).unwrap();
        // Fixed-width zero-padded hex; wrapping add preserves order even at u64::MAX.
        assert_eq!(b, a.wrapping_add(1), "span IDs should increment by 1");
    }

    // ── now_unix_nano ──────────────────────────────────────────────────

    #[test]
    fn now_unix_nano_returns_reasonable_value() {
        let ts = now_unix_nano();
        // Should be after 2024-01-01 in nanoseconds
        assert!(
            ts > 1_700_000_000_000_000_000,
            "timestamp too small: {ts}"
        );
    }

    // ── SpanStatus ─────────────────────────────────────────────────────

    #[test]
    fn span_status_code_values() {
        assert_eq!(SpanStatus::unset().code, 0);
        assert_eq!(SpanStatus::ok().code, 1);
        assert_eq!(SpanStatus::error("fail").code, 2);
        assert_eq!(SpanStatus::error("fail").message, "fail");
    }

    // ── SpanKind ───────────────────────────────────────────────────────

    #[test]
    fn span_kind_values() {
        assert_eq!(SpanKind::Unspecified.as_u32(), 0);
        assert_eq!(SpanKind::Internal.as_u32(), 1);
        assert_eq!(SpanKind::Server.as_u32(), 2);
        assert_eq!(SpanKind::Client.as_u32(), 3);
        assert_eq!(SpanKind::Producer.as_u32(), 4);
        assert_eq!(SpanKind::Consumer.as_u32(), 5);
    }

    // ── OtelSpan ───────────────────────────────────────────────────────

    #[test]
    fn otel_span_to_otlp_json_produces_valid_json() {
        let mut span = OtelSpan::new("abc123def456abc123def456abc123de", None, "test-span", SpanKind::Internal);
        span.add_attribute("key1", serde_json::json!("value1"));
        span.add_attribute("key2", serde_json::json!(42));
        span.end(SpanStatus::ok());

        let json = span.to_otlp_json();

        // lowerCamelCase field names
        assert!(json.get("traceId").is_some(), "missing traceId");
        assert!(json.get("spanId").is_some(), "missing spanId");
        assert!(json.get("name").is_some(), "missing name");
        assert!(json.get("kind").is_some(), "missing kind");
        assert!(json.get("startTimeUnixNano").is_some(), "missing startTimeUnixNano");
        assert!(json.get("endTimeUnixNano").is_some(), "missing endTimeUnixNano");
        assert!(json.get("attributes").is_some(), "missing attributes");
        assert!(json.get("events").is_some(), "missing events");
        assert!(json.get("status").is_some(), "missing status");

        // Timestamps as strings per OTLP spec
        assert!(json["startTimeUnixNano"].is_string());
        assert!(json["endTimeUnixNano"].is_string());

        // Attributes in OTLP format
        let attrs = json["attributes"].as_array().unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0]["key"], "key1");
        assert!(attrs[0]["value"]["stringValue"].is_string());
        assert_eq!(attrs[1]["key"], "key2");
        // Integer attributes use intValue as string
        assert!(attrs[1]["value"]["intValue"].is_string());

        // No parentSpanId when None
        assert!(json.get("parentSpanId").is_none());
    }

    #[test]
    fn otel_span_with_parent_includes_parent_span_id() {
        let span = OtelSpan::new(
            "abc123def456abc123def456abc123de",
            Some("parent12345678"),
            "child-span",
            SpanKind::Internal,
        );
        let json = span.to_otlp_json();
        assert_eq!(json["parentSpanId"], "parent12345678");
    }

    #[test]
    fn otel_span_with_events() {
        let mut span = OtelSpan::new("aabb", None, "test", SpanKind::Internal);
        let evt = SpanEvent::new("step_started")
            .with_attribute("step", serde_json::json!(1));
        span.add_event(evt);
        span.end(SpanStatus::ok());

        let json = span.to_otlp_json();
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["name"], "step_started");
        assert!(events[0]["timeUnixNano"].is_string());
        let attrs = events[0]["attributes"].as_array().unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0]["key"], "step");
    }

    #[test]
    fn otel_span_bool_attribute() {
        let mut span = OtelSpan::new("aabb", None, "test", SpanKind::Client);
        span.add_attribute("cache_hit", serde_json::json!(true));
        let json = span.to_otlp_json();
        let attrs = json["attributes"].as_array().unwrap();
        assert_eq!(attrs[0]["value"]["boolValue"], true);
    }

    #[test]
    fn otel_span_float_attribute() {
        let mut span = OtelSpan::new("aabb", None, "test", SpanKind::Client);
        span.add_attribute("cost", serde_json::json!(1.5));
        let json = span.to_otlp_json();
        let attrs = json["attributes"].as_array().unwrap();
        assert!((attrs[0]["value"]["doubleValue"].as_f64().unwrap() - 1.5).abs() < f64::EPSILON);
    }

    // ── SpanBuffer ─────────────────────────────────────────────────────

    #[test]
    fn span_buffer_push_drain_len() {
        let mut buf = SpanBuffer::new();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());

        let span1 = OtelSpan::new("t1", None, "s1", SpanKind::Internal);
        let span2 = OtelSpan::new("t1", None, "s2", SpanKind::Internal);
        buf.push(span1);
        buf.push(span2);
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());

        let drained = buf.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn span_buffer_to_otlp_json_envelope() {
        let mut buf = SpanBuffer::new();
        let mut span = OtelSpan::new("t1", None, "test", SpanKind::Internal);
        span.end(SpanStatus::ok());
        buf.push(span);

        let json = buf.to_otlp_json();

        // Check envelope structure
        let resource_spans = json["resourceSpans"].as_array().unwrap();
        assert_eq!(resource_spans.len(), 1);

        let resource = &resource_spans[0]["resource"];
        assert!(resource["attributes"].is_array());

        let scope_spans = resource_spans[0]["scopeSpans"].as_array().unwrap();
        assert_eq!(scope_spans.len(), 1);
        assert_eq!(scope_spans[0]["scope"]["name"], "tallow-agent");

        let spans = scope_spans[0]["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "test");
    }

    // ── EventStore ─────────────────────────────────────────────────────

    fn make_event_store() -> EventStore {
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        EventStore::new(shared).unwrap()
    }

    fn make_event(agent_id: &str, seq: u64, event_type: &str) -> AgentEvent {
        AgentEvent {
            agent_id: agent_id.to_string(),
            sequence: seq,
            timestamp: "2026-03-04T12:00:00Z".to_string(),
            event_type: event_type.to_string(),
            payload: "{}".to_string(),
            trace_id: None,
            span_id: None,
        }
    }

    #[test]
    fn event_store_new_creates_table() {
        let store = make_event_store();
        // Verify table exists by querying it
        let result = store.get_max_sequence("nonexistent");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn event_store_routes_through_coordinator_read_your_own_writes() {
        // 2.0: EventStore via a coordinator client preserves FIFO ordering and
        // read-your-own-writes (append then immediate query sees the row).
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let mut coord = crate::agent_store::StoreCoordinator::spawn(conn.clone());
        let store = EventStore::with_client(conn.clone(), coord.client.clone()).unwrap();
        let mut ev = AgentEvent {
            agent_id: "a1".into(),
            sequence: 1,
            timestamp: "ts".into(),
            event_type: "step".into(),
            payload: "{}".into(),
            trace_id: Some("trace1".into()),
            span_id: Some("span1".into()),
        };
        store.append(&ev).unwrap();
        ev.sequence = 2;
        store.append(&ev).unwrap();
        let events = store.query_events("a1", 0).unwrap();
        assert_eq!(events.len(), 2, "coordinator path must be read-your-own-writes");
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        coord.shutdown();
    }

    #[test]
    fn event_store_append_inserts_event() {
        let store = make_event_store();
        let event = make_event("agent1", 1, "step_started");
        let result = store.append(&event);
        assert!(result.is_ok());

        let max = store.get_max_sequence("agent1").unwrap();
        assert_eq!(max, 1);
    }

    #[test]
    fn event_store_append_batch_inserts_all_in_order() {
        let store = make_event_store();
        let events: Vec<AgentEvent> = (1..=5).map(|i| make_event("a1", i as u64, "step")).collect();
        store.append_batch(&events).unwrap();
        assert_eq!(store.get_max_sequence("a1").unwrap(), 5);
        let evs = store.query_events("a1", 0).unwrap();
        assert_eq!(evs.len(), 5);
        assert_eq!(evs[0].sequence, 1);
        assert_eq!(evs[4].sequence, 5);
    }

    #[test]
    fn event_store_append_batch_empty_is_noop() {
        let store = make_event_store();
        assert!(store.append_batch(&[]).is_ok());
        assert_eq!(store.get_max_sequence("a1").unwrap(), 0);
    }

    #[test]
    fn event_store_get_max_sequence_empty() {
        let store = make_event_store();
        assert_eq!(store.get_max_sequence("nobody").unwrap(), 0);
    }

    #[test]
    fn event_store_get_max_sequence_after_inserts() {
        let store = make_event_store();
        store.append(&make_event("a1", 1, "start")).unwrap();
        store.append(&make_event("a1", 2, "step")).unwrap();
        store.append(&make_event("a1", 5, "end")).unwrap();
        assert_eq!(store.get_max_sequence("a1").unwrap(), 5);
    }

    #[test]
    fn event_store_query_events_returns_in_order() {
        let store = make_event_store();
        store.append(&make_event("a1", 1, "start")).unwrap();
        store.append(&make_event("a1", 3, "step")).unwrap();
        store.append(&make_event("a1", 2, "step")).unwrap();

        let events = store.query_events("a1", 0).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[2].sequence, 3);
    }

    #[test]
    fn event_store_query_events_since_sequence() {
        let store = make_event_store();
        store.append(&make_event("a1", 1, "start")).unwrap();
        store.append(&make_event("a1", 2, "step")).unwrap();
        store.append(&make_event("a1", 3, "end")).unwrap();

        let events = store.query_events("a1", 1).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 2);
        assert_eq!(events[1].sequence, 3);
    }

    #[test]
    fn event_store_append_only_persists() {
        let store = make_event_store();
        store.append(&make_event("a1", 1, "first")).unwrap();
        store.append(&make_event("a1", 2, "second")).unwrap();
        store.append(&make_event("a1", 3, "third")).unwrap();

        // All three should be there
        let events = store.query_events("a1", 0).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "first");
        assert_eq!(events[1].event_type, "second");
        assert_eq!(events[2].event_type, "third");
    }

    #[test]
    fn event_store_multiple_agents_isolated() {
        let store = make_event_store();
        store.append(&make_event("a1", 1, "start")).unwrap();
        store.append(&make_event("a2", 1, "start")).unwrap();
        store.append(&make_event("a1", 2, "end")).unwrap();

        let a1_events = store.query_events("a1", 0).unwrap();
        assert_eq!(a1_events.len(), 2);
        let a2_events = store.query_events("a2", 0).unwrap();
        assert_eq!(a2_events.len(), 1);

        assert_eq!(store.get_max_sequence("a1").unwrap(), 2);
        assert_eq!(store.get_max_sequence("a2").unwrap(), 1);
    }

    #[test]
    fn agent_event_with_trace_context_roundtrips() {
        let store = make_event_store();
        let event = AgentEvent {
            agent_id: "a1".to_string(),
            sequence: 1,
            timestamp: "2026-03-04T12:00:00Z".to_string(),
            event_type: "step_started".to_string(),
            payload: r#"{"step":1}"#.to_string(),
            trace_id: Some("aabbccdd11223344aabbccdd11223344".to_string()),
            span_id: Some("1122334455667788".to_string()),
        };
        store.append(&event).unwrap();

        let events = store.query_events("a1", 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].trace_id.as_deref(),
            Some("aabbccdd11223344aabbccdd11223344")
        );
        assert_eq!(events[0].span_id.as_deref(), Some("1122334455667788"));
        assert_eq!(events[0].payload, r#"{"step":1}"#);
    }

    #[test]
    fn event_store_shared_connection() {
        // Verify EventStore can share a connection (Arc<Mutex<Connection>>)
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        let store1 = EventStore::new(Arc::clone(&shared)).unwrap();
        // Second store on same connection should work (idempotent schema)
        let store2 = EventStore::new(Arc::clone(&shared)).unwrap();

        store1.append(&make_event("a1", 1, "from_store1")).unwrap();
        // store2 should see it
        let events = store2.query_events("a1", 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "from_store1");
    }

    // ── CheckpointStore ─────────────────────────────────────────────────

    fn make_checkpoint_store() -> (CheckpointStore, Arc<Mutex<Connection>>) {
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        let store = CheckpointStore::new(Arc::clone(&shared)).unwrap();
        (store, shared)
    }

    fn make_test_runtime() -> crate::agent_runtime::AgentRuntime {
        use crate::agent_runtime::{AgentRuntime, ResourceBudget};
        use std::time::Duration;
        let mut rt = AgentRuntime::new(
            "test_agent".to_string(),
            None,
            None,
            ResourceBudget::new(Some(100), Some(1024 * 1024), Some(Duration::from_secs(60))),
        );
        rt.steps_executed = 10;
        rt.budget.requests_used = 5;
        rt.budget.memory_used_bytes = 2048;
        rt.emotional_state.confidence = 0.8;
        rt.emotional_state.urgency = 0.3;
        rt.emotional_state.uncertainty = 0.2;
        rt.goals_attempted = 4;
        rt.goals_completed = 3;
        rt.llm_cost_tracker.record_call("gpt-4o", 100, 50);
        rt.llm_cost_tracker.record_cache_hit();
        rt
    }

    #[test]
    fn checkpoint_store_new_creates_table() {
        let (store, _) = make_checkpoint_store();
        // Should be able to query without error
        let count = store.count_checkpoints("nobody").unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn checkpoint_store_save_inserts_row() {
        let (store, _) = make_checkpoint_store();
        let rt = make_test_runtime();
        store.save_checkpoint("test_agent", &rt, "[]", 42).unwrap();
        let count = store.count_checkpoints("test_agent").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn checkpoint_store_load_returns_none_when_empty() {
        let (store, _) = make_checkpoint_store();
        let result = store.load_latest_checkpoint("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn checkpoint_store_load_returns_latest_after_multiple_saves() {
        let (store, _) = make_checkpoint_store();
        let mut rt = make_test_runtime();
        rt.steps_executed = 5;
        store.save_checkpoint("test_agent", &rt, "[1]", 10).unwrap();

        rt.steps_executed = 15;
        store.save_checkpoint("test_agent", &rt, "[1,2]", 20).unwrap();

        rt.steps_executed = 25;
        store.save_checkpoint("test_agent", &rt, "[1,2,3]", 30).unwrap();

        let latest = store.load_latest_checkpoint("test_agent").unwrap().unwrap();
        assert_eq!(latest.steps_executed, 25);
        assert_eq!(latest.event_sequence, 30);
        assert_eq!(latest.working_memory, "[1,2,3]");
    }

    #[test]
    fn checkpoint_data_fields_roundtrip() {
        let (store, _) = make_checkpoint_store();
        let rt = make_test_runtime();
        let wm_json = r#"[{"key":"fact","value":"sky is blue"}]"#;
        store.save_checkpoint("test_agent", &rt, wm_json, 42).unwrap();

        let cp = store.load_latest_checkpoint("test_agent").unwrap().unwrap();
        assert_eq!(cp.agent_id, "test_agent");
        assert_eq!(cp.steps_executed, 10);
        assert_eq!(cp.requests_used, 5);
        assert_eq!(cp.memory_used, 2048);
        assert!((cp.confidence - 0.8).abs() < f64::EPSILON);
        assert!((cp.urgency - 0.3).abs() < f64::EPSILON);
        assert!((cp.uncertainty - 0.2).abs() < f64::EPSILON);
        assert_eq!(cp.working_memory, wm_json);
        assert_eq!(cp.event_sequence, 42);
        assert_eq!(cp.goals_attempted, 4);
        assert_eq!(cp.goals_completed, 3);

        // Verify LLM tracker JSON
        let llm: serde_json::Value = serde_json::from_str(&cp.llm_tracker).unwrap();
        assert_eq!(llm["calls"], 1);
        assert_eq!(llm["cache_hits"], 1);
        assert_eq!(llm["input_tokens"], 100);
        assert_eq!(llm["output_tokens"], 50);
    }

    #[test]
    fn checkpoint_store_count_returns_correct_count() {
        let (store, _) = make_checkpoint_store();
        let rt = make_test_runtime();
        assert_eq!(store.count_checkpoints("test_agent").unwrap(), 0);
        store.save_checkpoint("test_agent", &rt, "[]", 1).unwrap();
        assert_eq!(store.count_checkpoints("test_agent").unwrap(), 1);
        store.save_checkpoint("test_agent", &rt, "[]", 2).unwrap();
        assert_eq!(store.count_checkpoints("test_agent").unwrap(), 2);
    }

    #[test]
    fn checkpoint_store_shared_connection_with_event_store() {
        // CheckpointStore and EventStore can share the same connection
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        let _event_store = EventStore::new(Arc::clone(&shared)).unwrap();
        let cp_store = CheckpointStore::new(Arc::clone(&shared)).unwrap();

        let rt = make_test_runtime();
        cp_store.save_checkpoint("test_agent", &rt, "[]", 1).unwrap();
        assert_eq!(cp_store.count_checkpoints("test_agent").unwrap(), 1);
    }

    // ── IdempotencyStore ──────────────────────────────────────────────

    fn make_idempotency_store() -> IdempotencyStore {
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        IdempotencyStore::new(shared).unwrap()
    }

    #[test]
    fn generate_idempotency_key_deterministic() {
        let k1 = generate_idempotency_key("agent1", "https://example.com", "GET");
        let k2 = generate_idempotency_key("agent1", "https://example.com", "GET");
        assert_eq!(k1, k2, "same inputs must produce same key");
        assert!(k1.starts_with("idem_"), "key must start with idem_");
        // "idem_" (5) + 32 hex chars = 37
        assert_eq!(k1.len(), 37, "key length: {}", k1.len());
    }

    #[test]
    fn generate_idempotency_key_different_urls() {
        let k1 = generate_idempotency_key("agent1", "https://example.com/a", "GET");
        let k2 = generate_idempotency_key("agent1", "https://example.com/b", "GET");
        assert_ne!(k1, k2, "different URLs must produce different keys");
    }

    #[test]
    fn generate_idempotency_key_different_agents() {
        let k1 = generate_idempotency_key("agent1", "https://example.com", "GET");
        let k2 = generate_idempotency_key("agent2", "https://example.com", "GET");
        assert_ne!(k1, k2, "different agents must produce different keys");
    }

    #[test]
    fn generate_idempotency_key_different_methods() {
        let k1 = generate_idempotency_key("agent1", "https://example.com", "GET");
        let k2 = generate_idempotency_key("agent1", "https://example.com", "POST");
        assert_ne!(k1, k2, "different methods must produce different keys");
    }

    #[test]
    fn idempotency_store_new_creates_table() {
        let store = make_idempotency_store();
        // Should be able to query without error
        let result = store.check("nonexistent");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn idempotency_store_routes_through_coordinator_read_your_own_writes() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let mut coord = crate::agent_store::StoreCoordinator::spawn(conn.clone());
        let store = IdempotencyStore::with_client(conn.clone(), coord.client.clone()).unwrap();
        store.record("k1", "result-abc", 200, None).unwrap();
        // An immediate check must observe the just-recorded key (FIFO per client).
        let got = store.check("k1").unwrap();
        assert_eq!(got, Some(("result-abc".into(), Some(200))));
        coord.shutdown();
    }

    #[test]
    fn idempotency_store_check_returns_none_for_unknown() {
        let store = make_idempotency_store();
        let result = store.check("unknown_key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn idempotency_store_record_and_check_roundtrip() {
        let store = make_idempotency_store();
        store.record("key1", "response body", 200, None).unwrap();
        let result = store.check("key1").unwrap();
        assert!(result.is_some());
        let (body, status) = result.unwrap();
        assert_eq!(body, "response body");
        assert_eq!(status, Some(200));
    }

    #[test]
    fn idempotency_store_record_with_ttl_and_expiry() {
        let store = make_idempotency_store();
        // Record with 24h TTL — should be available right now
        store.record("key_ttl", "cached", 200, Some(24)).unwrap();
        let result = store.check("key_ttl").unwrap();
        assert!(result.is_some());

        // Manually expire the key by setting expires_at to the past
        {
            let conn = Connection::open_in_memory().unwrap();
            let shared = Arc::new(Mutex::new(conn));
            let store2 = IdempotencyStore::new(Arc::clone(&shared)).unwrap();
            store2.record("expired_key", "old", 200, Some(1)).unwrap();
            // Manually set expires_at to the past
            let db = shared.lock().unwrap();
            db.execute(
                "UPDATE idempotency_keys SET expires_at = datetime('now', '-1 hour') WHERE key = ?1",
                rusqlite::params!["expired_key"],
            )
            .unwrap();
            // Now check — should return None because it expired
            drop(db);
            let result = store2.check("expired_key").unwrap();
            assert!(result.is_none(), "expired key should return None");
        }
    }

    #[test]
    fn idempotency_store_cleanup_expired() {
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        let store = IdempotencyStore::new(Arc::clone(&shared)).unwrap();

        // Insert a key and manually expire it
        store.record("exp1", "data1", 200, Some(1)).unwrap();
        store.record("exp2", "data2", 200, Some(1)).unwrap();
        store.record("fresh", "data3", 200, Some(24)).unwrap();

        // Expire the first two
        {
            let db = shared.lock().unwrap();
            db.execute(
                "UPDATE idempotency_keys SET expires_at = datetime('now', '-1 hour') WHERE key IN ('exp1', 'exp2')",
                [],
            )
            .unwrap();
        }

        let deleted = store.cleanup_expired().unwrap();
        assert_eq!(deleted, 2, "should delete 2 expired entries");

        // Fresh one should still exist
        assert!(store.check("fresh").unwrap().is_some());
        assert!(store.check("exp1").unwrap().is_none());
    }

    #[test]
    fn idempotency_store_insert_or_ignore_no_overwrite() {
        let store = make_idempotency_store();
        store.record("key1", "first_result", 200, None).unwrap();
        // Record again with different data — should be ignored
        store.record("key1", "second_result", 404, None).unwrap();

        let (body, status) = store.check("key1").unwrap().unwrap();
        assert_eq!(body, "first_result", "INSERT OR IGNORE should keep original");
        assert_eq!(status, Some(200));
    }

    #[test]
    fn idempotency_store_shared_connection_with_others() {
        // Verify IdempotencyStore can share a connection with EventStore and CheckpointStore
        let conn = Connection::open_in_memory().unwrap();
        let shared = Arc::new(Mutex::new(conn));
        let _event_store = EventStore::new(Arc::clone(&shared)).unwrap();
        let _cp_store = CheckpointStore::new(Arc::clone(&shared)).unwrap();
        let idem_store = IdempotencyStore::new(Arc::clone(&shared)).unwrap();

        idem_store.record("test_key", "data", 200, None).unwrap();
        let result = idem_store.check("test_key").unwrap();
        assert!(result.is_some());
    }

    // ── A1.1.4: agent-action emission ──────────────────────────────────────

    #[test]
    fn agent_event_emits_to_ledger_as_agent_step() {
        let mut rec = crate::agent_ledger::Recorder::new(
            crate::agent_ledger::MemoryLedger::new(),
            "agent:obs",
            "run-9",
        )
        .unwrap();
        let ev = AgentEvent {
            agent_id: "a-1".to_string(),
            sequence: 3,
            timestamp: "t0".to_string(),
            event_type: "checkpoint".to_string(),
            payload: "{\"k\":1}".to_string(),
            trace_id: Some("tr-1".to_string()),
            span_id: None,
        };
        let env = emit_agent_event(&mut rec, &ev).unwrap();
        assert_eq!(env.kind, crate::ledger_events::EventKind::AgentStep);
        assert_eq!(env.prev_hash, "GENESIS");
        assert!(
            env.payload.contains("\"event_type\":\"checkpoint\""),
            "{}",
            env.payload
        );
        assert!(env.payload.contains("\"agent_id\":\"a-1\""), "{}", env.payload);
        // A second event links to the first.
        let env2 = emit_agent_event(&mut rec, &ev).unwrap();
        assert_eq!(env2.prev_hash, env.hash);
    }
}
