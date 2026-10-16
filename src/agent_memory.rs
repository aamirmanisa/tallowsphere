//! Agent Memory — cognitive memory system for agent architecture.
//!
//! Provides the Brain struct with four distinct memory regions:
//! - **WorkingMemory**: Bounded in-process storage (VecDeque) with LRU eviction
//! - **EpisodicMemory**: Timestamped experiences in SQLite, queryable by time range and keyword
//! - **SemanticMemory**: Subject-predicate-object triples in SQLite with graph traversal
//! - **ProceduralMemory**: Versioned skills in SQLite with latest-version recall
//!
//! The three persistent regions share a single SQLite connection via Arc<Mutex<Connection>>.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::fmt;
use std::rc::Rc;

// ── 2.5 lightweight embedding (dependency-free) ───────────────────────────
// Bag-of-n-grams hashed into a fixed-dimension signed vector, L2-normalized.
// Cosine similarity on these gives a coarse lexical-semantic ranking over
// agent memory without pulling in an external embedding model or vector store.

/// Embed text into a `dim`-dimensional unit vector (character n-grams, signed).
pub(crate) fn embed_text(text: &str, dim: usize) -> Vec<f32> {
    let mut v = vec![0.0f32; dim];
    if dim == 0 {
        return v;
    }
    let chars: Vec<char> = text.to_lowercase().chars().collect();
    for n in [1usize, 2, 3] {
        if chars.len() < n {
            continue;
        }
        for i in 0..=(chars.len() - n) {
            let gram: String = chars[i..i + n].iter().collect();
            let mut h: u64 = 1469598103934665603;
            for b in gram.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(1099511628211);
            }
            let idx = (h % dim as u64) as usize;
            let sign = if (h >> 32) & 1 == 1 { 1.0 } else { -1.0 };
            v[idx] += sign / n as f32;
        }
    }
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
    v
}

/// Cosine similarity between two equal-length vectors (returns 0 on empty).
pub(crate) fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let d = a.len().min(b.len());
    if d == 0 {
        return 0.0;
    }
    a[..d].iter().zip(&b[..d]).map(|(x, y)| x * y).sum()
}

use rusqlite::Connection;

use crate::agent_reasoning::{ReasoningBackend, Rule};

/// Merge two possibly-None provenance fields (comma-joined lists of distinct
/// tokens). Used by the semantic dedup/merge path to accumulate source / agent
/// / trace provenance across writes without duplicating tokens.
fn merge_provenance(existing: Option<&str>, incoming: Option<&str>) -> Option<String> {
    let mut tokens: Vec<String> = Vec::new();
    for candidate in [existing, incoming].into_iter().flatten() {
        for token in candidate.split(',') {
            let token = token.trim();
            if !token.is_empty() && !tokens.iter().any(|t| t == token) {
                tokens.push(token.to_string());
            }
        }
    }
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(","))
    }
}

// ── MemoryKind ────────────────────────────────────────────────────────────────

/// Classification of memory items.
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryKind {
    Fact,
    Experience,
    Procedure,
    General,
}

impl fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryKind::Fact => write!(f, "fact"),
            MemoryKind::Experience => write!(f, "experience"),
            MemoryKind::Procedure => write!(f, "procedure"),
            MemoryKind::General => write!(f, "general"),
        }
    }
}

// ── MemoryItem ────────────────────────────────────────────────────────────────

/// Shared memory item used across regions (primarily WorkingMemory).
#[derive(Debug, Clone)]
pub struct MemoryItem {
    pub key: String,
    pub value: String,
    pub timestamp: String,
    pub importance: f64,
    pub access_count: u32,
    pub kind: MemoryKind,
}

// ── EpisodicEntry ─────────────────────────────────────────────────────────────

/// A single episodic memory entry retrieved from SQLite.
#[derive(Debug, Clone)]
pub struct EpisodicEntry {
    pub id: i64,
    pub timestamp: String,
    pub content: String,
    pub context: Option<String>,
    pub importance: f64,
}

// ── Triple ────────────────────────────────────────────────────────────────────

/// A subject-predicate-object triple from semantic memory.
#[derive(Debug, Clone)]
pub struct Triple {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: f64,
}

/// A semantic triple annotated with provenance (which agent wrote it, the
/// originating source, and a per-run trace id). Returned by the additive
/// provenance-aware query/merge helpers; [`Triple`] (and the existing
/// `query`) are unchanged for backward compatibility.
#[derive(Debug, Clone)]
pub struct ProvenancedTriple {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: f64,
    pub agent_id: Option<String>,
    pub source: Option<String>,
    pub trace_id: Option<String>,
}

// ── Skill ─────────────────────────────────────────────────────────────────────

/// A versioned skill from procedural memory.
#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub version: u32,
    pub body: String,
    pub description: String,
    pub success_rate: f64,
    pub usage_count: i64,
}

// ── ReasoningStep ─────────────────────────────────────────────────────────────

/// A step in the reasoning audit chain (used by Plan 03).
#[derive(Debug, Clone)]
pub struct ReasoningStep {
    pub step_number: u32,
    pub backend: String,
    pub prompt: String,
    pub response: String,
    pub timestamp: String,
    pub duration_ms: u64,
    pub tokens_used: Option<u32>,
}

// ── BrainConfig ───────────────────────────────────────────────────────────────

/// Configuration for creating a Brain.
#[derive(Debug, Clone)]
pub struct BrainConfig {
    pub working_capacity: usize,
    pub persistence_path: String,
    pub reasoning_backend: String,
    pub model: String,
    pub api_key: String,
    pub api_url: String,
    /// URL for local LLM backend (e.g., Ollama endpoint).
    pub url: String,
}

impl Default for BrainConfig {
    fn default() -> Self {
        BrainConfig {
            working_capacity: 100,
            persistence_path: ":memory:".to_string(),
            reasoning_backend: "rule".to_string(),
            model: String::new(),
            api_key: String::new(),
            api_url: String::new(),
            url: String::new(),
        }
    }
}

// ── WorkingMemory ─────────────────────────────────────────────────────────────

/// Bounded in-process memory. Evicts oldest items on overflow.
#[derive(Debug, Clone)]
pub struct WorkingMemory {
    items: VecDeque<MemoryItem>,
    capacity: usize,
}

impl WorkingMemory {
    /// Create a new working memory with the given capacity.
    pub fn new(capacity: usize) -> Self {
        WorkingMemory {
            items: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Store a key-value pair. Evicts oldest item if at capacity.
    pub fn store(&mut self, key: &str, value: &str) {
        if self.items.len() >= self.capacity {
            self.items.pop_front(); // evict oldest
        }
        let now = chrono::Utc::now().to_rfc3339();
        self.items.push_back(MemoryItem {
            key: key.to_string(),
            value: value.to_string(),
            timestamp: now,
            importance: 0.5,
            access_count: 0,
            kind: MemoryKind::General,
        });
    }

    /// Recall an item by key. Increments access_count.
    pub fn recall(&mut self, key: &str) -> Option<&MemoryItem> {
        // Find and increment access_count, then return reference
        let idx = self.items.iter().position(|item| item.key == key)?;
        self.items[idx].access_count += 1;
        Some(&self.items[idx])
    }

    /// Return all items.
    pub fn recall_all(&self) -> Vec<&MemoryItem> {
        self.items.iter().collect()
    }

    /// Remove an item by key. Returns true if found.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.items.len();
        self.items.retain(|item| item.key != key);
        self.items.len() < before
    }

    /// Number of items currently stored.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether working memory is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear all items.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Store a key-value pair with explicit kind and importance.
    pub fn store_with_kind(&mut self, key: &str, value: &str, kind: MemoryKind, importance: f64) {
        if self.items.len() >= self.capacity {
            self.items.pop_front(); // evict oldest
        }
        let now = chrono::Utc::now().to_rfc3339();
        self.items.push_back(MemoryItem {
            key: key.to_string(),
            value: value.to_string(),
            timestamp: now,
            importance,
            access_count: 0,
            kind,
        });
    }

    /// Access the raw items deque (for consolidation iteration).
    pub fn items(&self) -> &VecDeque<MemoryItem> {
        &self.items
    }

    /// Remove items by their keys (batch removal after consolidation).
    pub fn remove_keys(&mut self, keys: &[String]) {
        self.items.retain(|item| !keys.contains(&item.key));
    }
}

// ── EpisodicMemory ────────────────────────────────────────────────────────────

/// Row-count above which episodic keyword search uses the FTS5 index.
///
/// Below this threshold we keep exact-substring `LIKE` semantics (which match
/// any substring, not just whole tokens). Above it we switch to the FTS5
/// tokenized index for O(log n) keyword search over large corpora. The split
/// is documented as an honest trade-off: FTS tokenizes, so sub-string matches
/// that cross token boundaries (e.g. "lencow" inside "flamencow") are found by
/// `LIKE` below the threshold but NOT by FTS above it.
const EPISODIC_FTS_THRESHOLD: i64 = 10_000;

/// Timestamped experience storage backed by SQLite.
#[derive(Debug, Clone)]
pub struct EpisodicMemory {
    db: Arc<Mutex<Connection>>,
}

impl EpisodicMemory {
    /// Create episodic memory using a shared SQLite connection.
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        EpisodicMemory { db }
    }

    /// Initialize the episodic table schema.
    pub fn init_schema(db: &Connection) -> Result<(), String> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS episodic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                content TEXT NOT NULL,
                context TEXT,
                importance REAL DEFAULT 0.5,
                access_count INTEGER DEFAULT 0,
                quarantined INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_episodic_ts ON episodic(timestamp);
            CREATE VIRTUAL TABLE IF NOT EXISTS episodic_fts USING fts5(
                content,
                tokenize = 'porter'
            );",
        )
        .map_err(|e| format!("episodic schema init failed: {e}"))
    }

    /// Migrate existing tables: add quarantined column if missing.
    pub fn migrate_schema(db: &Connection) -> Result<(), String> {
        let has_col = db
            .prepare("PRAGMA table_info(episodic)")
            .and_then(|mut stmt| {
                let cols: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(1))
                    .unwrap()
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(cols.contains(&"quarantined".to_string()))
            })
            .unwrap_or(false);
        if !has_col {
            db.execute_batch("ALTER TABLE episodic ADD COLUMN quarantined INTEGER DEFAULT 0")
                .map_err(|e| format!("episodic migration failed: {e}"))?;
        }
        Ok(())
    }

    /// Record an experience with default importance.
    pub fn record(&self, content: &str) -> Result<(), String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        self.record_tx(&db, content)
    }

    /// Record an experience with default importance, using an already-locked
    /// connection (for batching inside the caller's single transaction).
    pub(crate) fn record_tx(&self, db: &rusqlite::Connection, content: &str) -> Result<(), String> {
        db.execute(
            "INSERT INTO episodic (content) VALUES (?1)",
            rusqlite::params![content],
        )
        .map_err(|e| format!("episodic record failed: {e}"))?;
        // Keep the FTS5 index in sync (rowid mirrors the episodic id).
        let id = db.last_insert_rowid();
        db.execute(
            "INSERT INTO episodic_fts (rowid, content) VALUES (?1, ?2)",
            rusqlite::params![id, content],
        )
        .map_err(|e| format!("episodic fts sync failed: {e}"))?;
        Ok(())
    }

    /// Record an experience with context and importance.
    pub fn record_with_context(
        &self,
        content: &str,
        context: &str,
        importance: f64,
    ) -> Result<(), String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        db.execute(
            "INSERT INTO episodic (content, context, importance) VALUES (?1, ?2, ?3)",
            rusqlite::params![content, context, importance],
        )
        .map_err(|e| format!("episodic record_with_context failed: {e}"))?;
        // Keep the FTS5 index in sync (rowid mirrors the episodic id).
        let id = db.last_insert_rowid();
        db.execute(
            "INSERT INTO episodic_fts (rowid, content) VALUES (?1, ?2)",
            rusqlite::params![id, content],
        )
        .map_err(|e| format!("episodic fts sync failed: {e}"))?;
        Ok(())
    }

    /// Query entries recorded within the last N seconds.
    pub fn query_since(&self, duration_secs: i64) -> Result<Vec<EpisodicEntry>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(
                "SELECT id, timestamp, content, context, importance FROM episodic
                 WHERE timestamp > datetime('now', ?1) AND quarantined = 0
                 ORDER BY timestamp DESC",
            )
            .map_err(|e| format!("episodic query_since prepare failed: {e}"))?;

        let modifier = format!("-{duration_secs} seconds");
        let rows = stmt
            .query_map(rusqlite::params![modifier], |row| {
                Ok(EpisodicEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    content: row.get(2)?,
                    context: row.get(3)?,
                    importance: row.get(4)?,
                })
            })
            .map_err(|e| format!("episodic query_since failed: {e}"))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("episodic row read failed: {e}"))?);
        }
        Ok(entries)
    }

    /// Search entries by keyword.
    ///
    /// For small corpora (≤ [`EPISODIC_FTS_THRESHOLD`] rows) this uses a
    /// case-insensitive `LIKE` scan so exact-substring semantics (matching any
    /// substring, including across token boundaries) are preserved. Above the
    /// threshold it switches to the FTS5 index for O(log n) token search. If
    /// the FTS query cannot be expressed (e.g. the keyword contains FTS
    /// operator characters) it degrades gracefully back to the `LIKE` scan.
    pub fn search(&self, keyword: &str) -> Result<Vec<EpisodicEntry>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        if Self::non_quarantined_count(&db)? > EPISODIC_FTS_THRESHOLD {
            if let Ok(entries) = Self::search_fts(&db, keyword) {
                return Ok(entries);
            }
            // FTS query failed to express; fall back to exact-substring search.
        }
        Self::search_like(&db, keyword)
    }

    /// List all non-quarantined episodic entries (id, content, ...), newest first.
    /// Used by 2.5 vector retrieval to build the corpus.
    pub fn all_entries(&self) -> Result<Vec<EpisodicEntry>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(
                "SELECT id, timestamp, content, context, importance FROM episodic
                 WHERE quarantined = 0 ORDER BY timestamp DESC",
            )
            .map_err(|e| format!("episodic all_entries prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(EpisodicEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    content: row.get(2)?,
                    context: row.get(3)?,
                    importance: row.get(4)?,
                })
            })
            .map_err(|e| format!("episodic all_entries query failed: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("episodic all_entries row failed: {e}"))?);
        }
        Ok(out)
    }

    /// Number of non-quarantined episodic rows.
    fn non_quarantined_count(db: &Connection) -> Result<i64, String> {
        db.query_row(
            "SELECT COUNT(*) FROM episodic WHERE quarantined = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("episodic count failed: {e}"))
    }

    /// Exact-substring (case-insensitive LIKE) search — small corpora and the
    /// graceful fallback when an FTS query cannot be expressed.
    fn search_like(db: &Connection, keyword: &str) -> Result<Vec<EpisodicEntry>, String> {
        let mut stmt = db
            .prepare(
                "SELECT id, timestamp, content, context, importance FROM episodic
                 WHERE content LIKE ?1 AND quarantined = 0
                 ORDER BY timestamp DESC",
            )
            .map_err(|e| format!("episodic search prepare failed: {e}"))?;

        let pattern = format!("%{keyword}%");
        let rows = stmt
            .query_map(rusqlite::params![pattern], |row| {
                Ok(EpisodicEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    content: row.get(2)?,
                    context: row.get(3)?,
                    importance: row.get(4)?,
                })
            })
            .map_err(|e| format!("episodic search failed: {e}"))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("episodic row read failed: {e}"))?);
        }
        Ok(entries)
    }

    /// FTS5 token search over the index. Returns `Err` when the keyword cannot
    /// be expressed as an FTS5 query (callers fall back to [`Self::search_like`]).
    fn search_fts(db: &Connection, keyword: &str) -> Result<Vec<EpisodicEntry>, String> {
        let mut stmt = db
            .prepare(
                "SELECT e.id, e.timestamp, e.content, e.context, e.importance
                 FROM episodic_fts, episodic e
                 WHERE episodic_fts MATCH ?1
                     AND e.id = episodic_fts.rowid
                     AND e.quarantined = 0
                 ORDER BY e.timestamp DESC",
            )
            .map_err(|e| format!("episodic search_fts prepare failed: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![Self::fts_query(keyword)], |row| {
                Ok(EpisodicEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    content: row.get(2)?,
                    context: row.get(3)?,
                    importance: row.get(4)?,
                })
            })
            .map_err(|e| format!("episodic search_fts failed: {e}"))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("episodic row read failed: {e}"))?);
        }
        Ok(entries)
    }

    /// Wrap a user keyword as an FTS5 phrase query (literal token match).
    fn fts_query(keyword: &str) -> String {
        format!("\"{}\"", keyword)
    }

    /// Count total non-quarantined episodic entries.
    pub fn count(&self) -> Result<i64, String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .query_row("SELECT COUNT(*) FROM episodic WHERE quarantined = 0", [], |row| row.get(0))
            .map_err(|e| format!("episodic count failed: {e}"))
    }

    /// Quarantine an episodic entry by ID.
    pub fn quarantine(&self, id: i64) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "UPDATE episodic SET quarantined = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| format!("episodic quarantine failed: {e}"))?;
        Ok(())
    }

    /// Restore a quarantined episodic entry by ID.
    pub fn restore_from_quarantine(&self, id: i64) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "UPDATE episodic SET quarantined = 0 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| format!("episodic restore_from_quarantine failed: {e}"))?;
        Ok(())
    }

    /// List quarantined episodic entries: (id, content, timestamp).
    pub fn list_quarantined(&self) -> Result<Vec<(i64, String, String)>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare("SELECT id, content, timestamp FROM episodic WHERE quarantined = 1 ORDER BY id")
            .map_err(|e| format!("episodic list_quarantined prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| format!("episodic list_quarantined failed: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("episodic row read failed: {e}"))?);
        }
        Ok(result)
    }

    /// Query outcome history for a given action keyword.
    /// Returns (success: bool, timestamp) pairs from recent episodic entries
    /// where content matches the action keyword. Success is inferred from
    /// content containing "success" or "ok" (true) vs "fail" or "error" (false).
    pub fn outcome_history(&self, action: &str, limit: usize) -> Result<Vec<(bool, String)>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        // Use the FTS5 index for large corpora; exact-substring LIKE otherwise.
        if Self::non_quarantined_count(&db)? > EPISODIC_FTS_THRESHOLD {
            if let Ok(pairs) = Self::outcome_history_fts(&db, action, limit) {
                return Ok(pairs);
            }
            // FTS query failed to express; fall back to exact-substring search.
        }
        Self::outcome_history_like(&db, action, limit)
    }

    /// outcome_history via exact-substring LIKE scan (small corpora / fallback).
    fn outcome_history_like(
        db: &Connection,
        action: &str,
        limit: usize,
    ) -> Result<Vec<(bool, String)>, String> {
        let mut stmt = db
            .prepare(
                "SELECT content, timestamp FROM episodic
                 WHERE content LIKE ?1 AND quarantined = 0
                 ORDER BY timestamp DESC LIMIT ?2",
            )
            .map_err(|e| format!("episodic outcome_history prepare failed: {e}"))?;
        let pattern = format!("%{action}%");
        let rows = stmt
            .query_map(rusqlite::params![pattern, limit as i64], |row| {
                let content: String = row.get(0)?;
                let timestamp: String = row.get(1)?;
                Ok((content, timestamp))
            })
            .map_err(|e| format!("episodic outcome_history failed: {e}"))?;
        Self::outcome_history_from_rows(rows)
    }

    /// outcome_history via the FTS5 index (large corpora).
    fn outcome_history_fts(
        db: &Connection,
        action: &str,
        limit: usize,
    ) -> Result<Vec<(bool, String)>, String> {
        let mut stmt = db
            .prepare(
                "SELECT e.content, e.timestamp FROM episodic_fts, episodic e
                 WHERE episodic_fts MATCH ?1
                     AND e.id = episodic_fts.rowid
                     AND e.quarantined = 0
                 ORDER BY e.timestamp DESC LIMIT ?2",
            )
            .map_err(|e| format!("episodic outcome_history_fts prepare failed: {e}"))?;
        let rows = stmt
            .query_map(
                rusqlite::params![Self::fts_query(action), limit as i64],
                |row| {
                    let content: String = row.get(0)?;
                    let timestamp: String = row.get(1)?;
                    Ok((content, timestamp))
                },
            )
            .map_err(|e| format!("episodic outcome_history_fts failed: {e}"))?;
        Self::outcome_history_from_rows(rows)
    }

    /// Infer success/failure from matched content rows and return (success, timestamp).
    fn outcome_history_from_rows(
        rows: impl Iterator<Item = Result<(String, String), rusqlite::Error>>,
    ) -> Result<Vec<(bool, String)>, String> {
        let mut result = Vec::new();
        for row in rows {
            let (content, timestamp) = row.map_err(|e| format!("episodic row read failed: {e}"))?;
            let lower = content.to_lowercase();
            let success = lower.contains("success") || lower.contains(" ok")
                || lower.contains("completed") || lower.contains("passed");
            let failure = lower.contains("fail") || lower.contains("error")
                || lower.contains("timeout") || lower.contains("rejected");
            // If explicit failure indicators, mark as failure; otherwise success
            let is_success = if failure { false } else { success || !failure };
            result.push((is_success, timestamp));
        }
        Ok(result)
    }
}

// ── SemanticMemory ────────────────────────────────────────────────────────────

/// Graph-structured knowledge store using subject-predicate-object triples.
#[derive(Debug, Clone)]
pub struct SemanticMemory {
    db: Arc<Mutex<Connection>>,
}

impl SemanticMemory {
    /// Create semantic memory using a shared SQLite connection.
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        SemanticMemory { db }
    }

    /// Initialize the semantic table schema.
    pub fn init_schema(db: &Connection) -> Result<(), String> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS semantic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                source TEXT,
                agent_id TEXT,
                trace_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                quarantined INTEGER DEFAULT 0,
                UNIQUE(subject, predicate, object)
            );
            CREATE INDEX IF NOT EXISTS idx_semantic_subject ON semantic(subject);
            CREATE INDEX IF NOT EXISTS idx_semantic_object ON semantic(object);
            CREATE INDEX IF NOT EXISTS idx_semantic_agent ON semantic(agent_id);",
        )
        .map_err(|e| format!("semantic schema init failed: {e}"))
    }

    /// Migrate existing tables: add quarantined/agent_id/trace_id columns if missing.
    /// Idempotent so it can run on both pre-existing and freshly-created schemas.
    pub fn migrate_schema(db: &Connection) -> Result<(), String> {
        /// Return the set of existing column names for `table`.
        fn columns(db: &Connection, table: &str) -> Vec<String> {
            let Ok(mut stmt) = db.prepare(&format!("PRAGMA table_info({table})")) else {
                return Vec::new();
            };
            stmt.query_map([], |row| row.get::<_, String>(1))
                .map(|rows| rows.filter_map(|r| r.ok()).collect::<Vec<String>>())
                .unwrap_or_default()
        }

        let existing = columns(db, "semantic");
        let adds = [
            ("quarantined", "INTEGER DEFAULT 0"),
            ("agent_id", "TEXT"),
            ("trace_id", "TEXT"),
        ];
        for (name, ddl) in adds {
            if !existing.iter().any(|c| c == name) {
                db.execute_batch(&format!("ALTER TABLE semantic ADD COLUMN {name} {ddl}"))
                    .map_err(|e| format!("semantic migration failed (add {name}): {e}"))?;
            }
        }
        Ok(())
    }

    /// Store a triple with default confidence.
    pub fn store(&self, subject: &str, predicate: &str, object: &str) -> Result<(), String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        self.store_tx(&db, subject, predicate, object)
    }

    /// Store a triple with default confidence, using an already-locked connection.
    pub(crate) fn store_tx(
        &self,
        db: &rusqlite::Connection,
        subject: &str,
        predicate: &str,
        object: &str,
    ) -> Result<(), String> {
        db.execute(
            "INSERT OR REPLACE INTO semantic (subject, predicate, object) VALUES (?1, ?2, ?3)",
            rusqlite::params![subject, predicate, object],
        )
        .map_err(|e| format!("semantic store failed: {e}"))?;
        Ok(())
    }

    /// Store a triple with confidence and source metadata.
    pub fn store_with_meta(
        &self,
        subject: &str,
        predicate: &str,
        object: &str,
        confidence: f64,
        source: &str,
    ) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "INSERT OR REPLACE INTO semantic (subject, predicate, object, confidence, source)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![subject, predicate, object, confidence, source],
            )
            .map_err(|e| format!("semantic store_with_meta failed: {e}"))?;
        Ok(())
    }

    /// Store a fully-provenanced triple: confidence, source, agent_id, trace_id.
    /// All provenance columns are optional (`None` leaves them unset).
    pub fn store_with_provenance(
        &self,
        subject: &str,
        predicate: &str,
        object: &str,
        confidence: f64,
        source: Option<&str>,
        agent_id: Option<&str>,
        trace_id: Option<&str>,
    ) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "INSERT OR REPLACE INTO semantic
                    (subject, predicate, object, confidence, source, agent_id, trace_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    subject,
                    predicate,
                    object,
                    confidence,
                    source,
                    agent_id,
                    trace_id
                ],
            )
            .map_err(|e| format!("semantic store_with_provenance failed: {e}"))?;
        Ok(())
    }

    /// Dedup/merge write: store a triple with provenance, honoring the
    /// `UNIQUE(subject, predicate, object)` constraint. If an identical
    /// subject+predicate+object row already exists, it is updated in place —
    /// confidence is raised to the max of the two, and source / agent / trace
    /// provenance are unioned (deduplicated) rather than duplicated. If no such
    /// row exists, a fresh row is inserted. The `UNIQUE` constraint guarantees
    /// at most one row per (subject, predicate, object), so this never
    /// produces duplicates.
    pub fn store_merged(
        &self,
        subject: &str,
        predicate: &str,
        object: &str,
        confidence: f64,
        source: Option<&str>,
        agent_id: Option<&str>,
        trace_id: Option<&str>,
    ) -> Result<(), String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;

        let existing = db.query_row(
            "SELECT confidence, source, agent_id, trace_id FROM semantic
             WHERE subject = ?1 AND predicate = ?2 AND object = ?3 AND quarantined = 0",
            rusqlite::params![subject, predicate, object],
            |row| {
                Ok((
                    row.get::<_, f64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        );

        match existing {
            Ok((old_conf, old_source, old_agent, old_trace)) => {
                let merged_conf = old_conf.max(confidence);
                let merged_source = merge_provenance(old_source.as_deref(), source);
                let merged_agent = merge_provenance(old_agent.as_deref(), agent_id);
                let merged_trace = merge_provenance(old_trace.as_deref(), trace_id);
                db.execute(
                    "UPDATE semantic
                     SET confidence = ?1, source = ?2, agent_id = ?3, trace_id = ?4
                     WHERE subject = ?5 AND predicate = ?6 AND object = ?7",
                    rusqlite::params![
                        merged_conf,
                        merged_source,
                        merged_agent,
                        merged_trace,
                        subject,
                        predicate,
                        object,
                    ],
                )
                .map_err(|e| format!("semantic store_merged update failed: {e}"))?;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                db.execute(
                    "INSERT INTO semantic
                        (subject, predicate, object, confidence, source, agent_id, trace_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        subject,
                        predicate,
                        object,
                        confidence,
                        source,
                        agent_id,
                        trace_id
                    ],
                )
                .map_err(|e| format!("semantic store_merged insert failed: {e}"))?;
            }
            Err(e) => return Err(format!("semantic store_merged lookup failed: {e}")),
        }
        Ok(())
    }

    /// Query triples with optional wildcard fields (None = match any).
    pub fn query(
        &self,
        subject: Option<&str>,
        predicate: Option<&str>,
        object: Option<&str>,
    ) -> Result<Vec<Triple>, String> {
        let mut sql = String::from(
            "SELECT subject, predicate, object, confidence FROM semantic WHERE quarantined = 0",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = subject {
            sql.push_str(&format!(" AND subject = ?{}", params.len() + 1));
            params.push(Box::new(s.to_string()));
        }
        if let Some(p) = predicate {
            sql.push_str(&format!(" AND predicate = ?{}", params.len() + 1));
            params.push(Box::new(p.to_string()));
        }
        if let Some(o) = object {
            sql.push_str(&format!(" AND object = ?{}", params.len() + 1));
            params.push(Box::new(o.to_string()));
        }

        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(&sql)
            .map_err(|e| format!("semantic query prepare failed: {e}"))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(Triple {
                    subject: row.get(0)?,
                    predicate: row.get(1)?,
                    object: row.get(2)?,
                    confidence: row.get(3)?,
                })
            })
            .map_err(|e| format!("semantic query failed: {e}"))?;

        let mut triples = Vec::new();
        for row in rows {
            triples.push(row.map_err(|e| format!("semantic row read failed: {e}"))?);
        }
        Ok(triples)
    }

    /// Query triples with provenance metadata, optionally filtered by
    /// subject/predicate/object and optionally scoped to a single agent_id or
    /// trace_id. Additive: does not change the existing [`Self::query`].
    pub fn query_with_provenance(
        &self,
        subject: Option<&str>,
        predicate: Option<&str>,
        object: Option<&str>,
        agent_id: Option<&str>,
        trace_id: Option<&str>,
    ) -> Result<Vec<ProvenancedTriple>, String> {
        let mut sql = String::from(
            "SELECT subject, predicate, object, confidence, agent_id, source, trace_id
             FROM semantic WHERE quarantined = 0",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = subject {
            sql.push_str(&format!(" AND subject = ?{}", params.len() + 1));
            params.push(Box::new(s.to_string()));
        }
        if let Some(p) = predicate {
            sql.push_str(&format!(" AND predicate = ?{}", params.len() + 1));
            params.push(Box::new(p.to_string()));
        }
        if let Some(o) = object {
            sql.push_str(&format!(" AND object = ?{}", params.len() + 1));
            params.push(Box::new(o.to_string()));
        }
        if let Some(a) = agent_id {
            sql.push_str(&format!(" AND agent_id LIKE '%' || ?{} || '%'", params.len() + 1));
            params.push(Box::new(a.to_string()));
        }
        if let Some(t) = trace_id {
            sql.push_str(&format!(" AND trace_id LIKE '%' || ?{} || '%'", params.len() + 1));
            params.push(Box::new(t.to_string()));
        }

        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(&sql)
            .map_err(|e| format!("semantic query_with_provenance prepare failed: {e}"))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(ProvenancedTriple {
                    subject: row.get(0)?,
                    predicate: row.get(1)?,
                    object: row.get(2)?,
                    confidence: row.get(3)?,
                    agent_id: row.get(4)?,
                    source: row.get(5)?,
                    trace_id: row.get(6)?,
                })
            })
            .map_err(|e| format!("semantic query_with_provenance failed: {e}"))?;

        let mut triples = Vec::new();
        for row in rows {
            triples.push(row.map_err(|e| format!("semantic row read failed: {e}"))?);
        }
        Ok(triples)
    }

    /// Return the merged entry for a subject+predicate across all of its
    /// non-quarantined objects: the row with the highest confidence as the
    /// representative, with source / agent / trace provenance unioned across
    /// every matching row. `None` if no matching triple exists.
    pub fn merged_semantic(
        &self,
        subject: &str,
        predicate: &str,
    ) -> Result<Option<ProvenancedTriple>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(
                "SELECT subject, predicate, object, confidence, agent_id, source, trace_id
                 FROM semantic
                 WHERE subject = ?1 AND predicate = ?2 AND quarantined = 0
                 ORDER BY confidence DESC",
            )
            .map_err(|e| format!("semantic merged_semantic prepare failed: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![subject, predicate], |row| {
                Ok(ProvenancedTriple {
                    subject: row.get(0)?,
                    predicate: row.get(1)?,
                    object: row.get(2)?,
                    confidence: row.get(3)?,
                    agent_id: row.get(4)?,
                    source: row.get(5)?,
                    trace_id: row.get(6)?,
                })
            })
            .map_err(|e| format!("semantic merged_semantic failed: {e}"))?;

        let mut merged: Option<ProvenancedTriple> = None;
        for row in rows {
            let triple = row.map_err(|e| format!("semantic row read failed: {e}"))?;
            match &mut merged {
                None => merged = Some(triple),
                Some(best) => {
                    // Rows are ordered by confidence DESC; keep the highest
                    // as representative and union the remaining provenance.
                    best.source = merge_provenance(best.source.as_deref(), triple.source.as_deref());
                    best.agent_id =
                        merge_provenance(best.agent_id.as_deref(), triple.agent_id.as_deref());
                    best.trace_id =
                        merge_provenance(best.trace_id.as_deref(), triple.trace_id.as_deref());
                }
            }
        }
        Ok(merged)
    }

    /// Scope a collection of triples to a single run / agent: return every
    /// non-quarantined triple whose `agent_id` provenance contains `agent_id`.
    pub fn filter_by_agent(&self, agent_id: &str) -> Result<Vec<ProvenancedTriple>, String> {
        self.query_with_provenance(None, None, None, Some(agent_id), None)
    }

    /// Scope a collection of triples to a single run / trace: return every
    /// non-quarantined triple whose `trace_id` provenance contains `trace_id`.
    pub fn filter_by_trace(&self, trace_id: &str) -> Result<Vec<ProvenancedTriple>, String> {
        self.query_with_provenance(None, None, None, None, Some(trace_id))
    }

    /// Traverse the knowledge graph from an entity up to max_depth hops.
    /// Uses recursive CTE to follow both outgoing (subject) and incoming (object) edges.
    pub fn related(&self, entity: &str, max_depth: u32) -> Result<Vec<Triple>, String> {
        let sql = "
            WITH RECURSIVE related_triples(subject, predicate, object, confidence, depth) AS (
                -- Base case: direct connections
                SELECT subject, predicate, object, confidence, 1 as depth
                FROM semantic
                WHERE (subject = ?1 OR object = ?1) AND quarantined = 0

                UNION

                -- Recursive: follow connections from discovered entities
                SELECT s.subject, s.predicate, s.object, s.confidence, rt.depth + 1
                FROM semantic s
                INNER JOIN related_triples rt ON (
                    s.subject = rt.object OR s.subject = rt.subject
                    OR s.object = rt.subject OR s.object = rt.object
                )
                WHERE rt.depth < ?2
                    AND s.quarantined = 0
                    AND s.rowid NOT IN (
                        SELECT rowid FROM semantic
                        WHERE subject = rt.subject AND predicate = rt.predicate AND object = rt.object
                    )
            )
            SELECT DISTINCT subject, predicate, object, confidence
            FROM related_triples
            ORDER BY depth;
        ";

        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(sql)
            .map_err(|e| format!("semantic related prepare failed: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![entity, max_depth], |row| {
                Ok(Triple {
                    subject: row.get(0)?,
                    predicate: row.get(1)?,
                    object: row.get(2)?,
                    confidence: row.get(3)?,
                })
            })
            .map_err(|e| format!("semantic related failed: {e}"))?;

        let mut triples = Vec::new();
        for row in rows {
            triples.push(row.map_err(|e| format!("semantic row read failed: {e}"))?);
        }
        Ok(triples)
    }

    /// Count total non-quarantined semantic triples.
    pub fn count(&self) -> Result<i64, String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .query_row("SELECT COUNT(*) FROM semantic WHERE quarantined = 0", [], |row| row.get(0))
            .map_err(|e| format!("semantic count failed: {e}"))
    }

    /// Quarantine a semantic triple by ID.
    pub fn quarantine(&self, id: i64) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "UPDATE semantic SET quarantined = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| format!("semantic quarantine failed: {e}"))?;
        Ok(())
    }

    /// Restore a quarantined semantic triple by ID.
    pub fn restore_from_quarantine(&self, id: i64) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "UPDATE semantic SET quarantined = 0 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| format!("semantic restore_from_quarantine failed: {e}"))?;
        Ok(())
    }

    /// List quarantined semantic triples: (id, subject, predicate).
    pub fn list_quarantined(&self) -> Result<Vec<(i64, String, String)>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare("SELECT id, subject, predicate FROM semantic WHERE quarantined = 1 ORDER BY id")
            .map_err(|e| format!("semantic list_quarantined prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| format!("semantic list_quarantined failed: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("semantic row read failed: {e}"))?);
        }
        Ok(result)
    }
}

// ── ProceduralMemory ──────────────────────────────────────────────────────────

/// Versioned skill storage backed by SQLite.
#[derive(Debug, Clone)]
pub struct ProceduralMemory {
    db: Arc<Mutex<Connection>>,
}

impl ProceduralMemory {
    /// Create procedural memory using a shared SQLite connection.
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        ProceduralMemory { db }
    }

    /// Initialize the procedural table schema.
    pub fn init_schema(db: &Connection) -> Result<(), String> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS procedural (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                body TEXT NOT NULL,
                description TEXT,
                success_rate REAL DEFAULT 0.0,
                usage_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                quarantined INTEGER DEFAULT 0,
                UNIQUE(name, version)
            );
            CREATE INDEX IF NOT EXISTS idx_procedural_name ON procedural(name);",
        )
        .map_err(|e| format!("procedural schema init failed: {e}"))
    }

    /// Migrate existing tables: add quarantined column if missing.
    pub fn migrate_schema(db: &Connection) -> Result<(), String> {
        let has_col = db
            .prepare("PRAGMA table_info(procedural)")
            .and_then(|mut stmt| {
                let cols: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(1))
                    .unwrap()
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(cols.contains(&"quarantined".to_string()))
            })
            .unwrap_or(false);
        if !has_col {
            db.execute_batch("ALTER TABLE procedural ADD COLUMN quarantined INTEGER DEFAULT 0")
                .map_err(|e| format!("procedural migration failed: {e}"))?;
        }
        Ok(())
    }

    /// Store a new version of a skill. Auto-increments version number.
    /// Returns the new version number.
    pub fn store(&self, name: &str, body: &str, description: &str) -> Result<u32, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        self.store_tx(&db, name, body, description)
    }

    /// Store a skill using an already-locked connection (for batching inside the
    /// caller's single transaction).
    pub(crate) fn store_tx(
        &self,
        db: &rusqlite::Connection,
        name: &str,
        body: &str,
        description: &str,
    ) -> Result<u32, String> {
        // Get current max version for this skill
        let current_max: Option<u32> = db
            .query_row(
                "SELECT MAX(version) FROM procedural WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .map_err(|e| format!("procedural version query failed: {e}"))?;

        let new_version = current_max.unwrap_or(0) + 1;

        db.execute(
            "INSERT INTO procedural (name, version, body, description) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, new_version, body, description],
        )
        .map_err(|e| format!("procedural store failed: {e}"))?;

        Ok(new_version)
    }

    /// Recall the latest non-quarantined version of a skill by name.
    pub fn recall(&self, name: &str) -> Result<Option<Skill>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(
                "SELECT name, version, body, description, success_rate, usage_count
                 FROM procedural WHERE name = ?1 AND quarantined = 0 ORDER BY version DESC LIMIT 1",
            )
            .map_err(|e| format!("procedural recall prepare failed: {e}"))?;

        let mut rows = stmt
            .query_map(rusqlite::params![name], |row| {
                Ok(Skill {
                    name: row.get(0)?,
                    version: row.get(1)?,
                    body: row.get(2)?,
                    description: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    success_rate: row.get(4)?,
                    usage_count: row.get(5)?,
                })
            })
            .map_err(|e| format!("procedural recall failed: {e}"))?;

        match rows.next() {
            Some(Ok(skill)) => Ok(Some(skill)),
            Some(Err(e)) => Err(format!("procedural row read failed: {e}")),
            None => Ok(None),
        }
    }

    /// Recall a specific version of a skill.
    pub fn recall_version(&self, name: &str, version: u32) -> Result<Option<Skill>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare(
                "SELECT name, version, body, description, success_rate, usage_count
                 FROM procedural WHERE name = ?1 AND version = ?2",
            )
            .map_err(|e| format!("procedural recall_version prepare failed: {e}"))?;

        let mut rows = stmt
            .query_map(rusqlite::params![name, version], |row| {
                Ok(Skill {
                    name: row.get(0)?,
                    version: row.get(1)?,
                    body: row.get(2)?,
                    description: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    success_rate: row.get(4)?,
                    usage_count: row.get(5)?,
                })
            })
            .map_err(|e| format!("procedural recall_version failed: {e}"))?;

        match rows.next() {
            Some(Ok(skill)) => Ok(Some(skill)),
            Some(Err(e)) => Err(format!("procedural row read failed: {e}")),
            None => Ok(None),
        }
    }

    /// List all distinct non-quarantined skill names.
    pub fn list_skills(&self) -> Result<Vec<String>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare("SELECT DISTINCT name FROM procedural WHERE quarantined = 0 ORDER BY name")
            .map_err(|e| format!("procedural list_skills prepare failed: {e}"))?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| format!("procedural list_skills failed: {e}"))?;

        let mut names = Vec::new();
        for row in rows {
            names.push(row.map_err(|e| format!("procedural row read failed: {e}"))?);
        }
        Ok(names)
    }

    /// Record a usage of the latest version of a skill, updating success_rate as running average.
    pub fn record_usage(&self, name: &str, success: bool) -> Result<(), String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;

        // Get latest version's current stats
        let (version, current_rate, current_count): (u32, f64, i64) = db
            .query_row(
                "SELECT version, success_rate, usage_count FROM procedural
                 WHERE name = ?1 ORDER BY version DESC LIMIT 1",
                rusqlite::params![name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| format!("procedural record_usage query failed: {e}"))?;

        let new_count = current_count + 1;
        // Running average: new_rate = (old_rate * old_count + new_value) / new_count
        let success_val = if success { 1.0 } else { 0.0 };
        let new_rate = (current_rate * current_count as f64 + success_val) / new_count as f64;

        db.execute(
            "UPDATE procedural SET usage_count = ?1, success_rate = ?2
             WHERE name = ?3 AND version = ?4",
            rusqlite::params![new_count, new_rate, name, version],
        )
        .map_err(|e| format!("procedural record_usage update failed: {e}"))?;

        Ok(())
    }

    /// Count total non-quarantined procedural entries (all versions of all skills).
    pub fn count(&self) -> Result<i64, String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .query_row("SELECT COUNT(*) FROM procedural WHERE quarantined = 0", [], |row| row.get(0))
            .map_err(|e| format!("procedural count failed: {e}"))
    }

    /// Recall the raw source text for a skill by name (latest version).
    pub fn recall_source(&self, name: &str) -> Result<Option<String>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let result: Result<String, _> = db.query_row(
            "SELECT body FROM procedural WHERE name = ?1 AND quarantined = 0 ORDER BY version DESC LIMIT 1",
            rusqlite::params![name],
            |row| row.get(0),
        );
        match result {
            Ok(body) => Ok(Some(body)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("procedural recall_source failed: {e}")),
        }
    }

    /// Quarantine a procedural skill entry by ID.
    pub fn quarantine(&self, id: i64) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "UPDATE procedural SET quarantined = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| format!("procedural quarantine failed: {e}"))?;
        Ok(())
    }

    /// Restore a quarantined procedural entry by ID.
    pub fn restore_from_quarantine(&self, id: i64) -> Result<(), String> {
        self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?
            .execute(
                "UPDATE procedural SET quarantined = 0 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| format!("procedural restore_from_quarantine failed: {e}"))?;
        Ok(())
    }

    /// List quarantined procedural entries: (id, name, version).
    pub fn list_quarantined(&self) -> Result<Vec<(i64, String, String)>, String> {
        let db = self.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        let mut stmt = db
            .prepare("SELECT id, name, CAST(version AS TEXT) FROM procedural WHERE quarantined = 1 ORDER BY id")
            .map_err(|e| format!("procedural list_quarantined prepare failed: {e}"))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| format!("procedural list_quarantined failed: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("procedural row read failed: {e}"))?);
        }
        Ok(result)
    }
}

// ── Brain ─────────────────────────────────────────────────────────────────────

/// The cognitive memory system. Contains all four memory regions and reasoning chain.
pub struct Brain {
    pub working: WorkingMemory,
    pub episodic: EpisodicMemory,
    pub semantic: SemanticMemory,
    pub procedural: ProceduralMemory,
    pub reasoning_chain: Vec<ReasoningStep>,
    pub reasoning_backend: ReasoningBackend,
    pub config: BrainConfig,
}

impl fmt::Debug for Brain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Brain")
            .field("working_len", &self.working.len())
            .field("reasoning_steps", &self.reasoning_chain.len())
            .finish()
    }
}

impl Brain {
    /// Create a new Brain with all four memory regions initialized.
    /// Opens SQLite at `config.persistence_path` (use ":memory:" for in-process).
    /// Creates all tables with IF NOT EXISTS.
    pub fn new(config: BrainConfig) -> Result<Brain, String> {
        let conn = Connection::open(&config.persistence_path)
            .map_err(|e| format!("brain: failed to open SQLite at '{}': {e}", config.persistence_path))?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| format!("brain: failed to set WAL mode: {e}"))?;

        // Initialize all schemas
        EpisodicMemory::init_schema(&conn)?;
        SemanticMemory::init_schema(&conn)?;
        ProceduralMemory::init_schema(&conn)?;

        // Migrate existing tables (add quarantined column if missing)
        EpisodicMemory::migrate_schema(&conn)?;
        SemanticMemory::migrate_schema(&conn)?;
        ProceduralMemory::migrate_schema(&conn)?;

        let shared_db = Arc::new(Mutex::new(conn));

        let backend = ReasoningBackend::from_config(
            &config.reasoning_backend,
            &config.model,
            &config.api_key,
            &config.api_url,
            &config.url,
        );

        Ok(Brain {
            working: WorkingMemory::new(config.working_capacity),
            episodic: EpisodicMemory::new(Arc::clone(&shared_db)),
            semantic: SemanticMemory::new(Arc::clone(&shared_db)),
            procedural: ProceduralMemory::new(Arc::clone(&shared_db)),
            reasoning_chain: Vec::new(),
            reasoning_backend: backend,
            config,
        })
    }

    /// 2.5: rank episodic entries by cosine similarity to the query embedding.
    /// Returns (content, score) for the top-k, highest first.
    pub fn recall_by_similarity(&self, query: &str, k: usize) -> Result<Vec<(String, f32)>, String> {
        let q = embed_text(query, 128);
        let mut scored: Vec<(String, f32)> = Vec::new();
        for e in self.episodic.all_entries()? {
            let v = embed_text(&e.content, 128);
            scored.push((e.content, cosine_similarity(&q, &v)));
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        Ok(scored)
    }

    /// Get the shared SQLite connection (same Rc used by all memory regions).
    /// Used by EventStore and CheckpointStore for connection sharing.
    pub fn db_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.episodic.db)
    }

    /// Record a reasoning step, capping the chain at 1000 entries.
    pub fn record_reasoning_step(&mut self, step: ReasoningStep) {
        self.reasoning_chain.push(step);
        // Cap at 1000 entries -- drop oldest when exceeded
        if self.reasoning_chain.len() > 1000 {
            let excess = self.reasoning_chain.len() - 1000;
            self.reasoning_chain.drain(0..excess);
        }
    }

    /// Get the reasoning chain as a slice.
    pub fn get_reasoning_chain(&self) -> &[ReasoningStep] {
        &self.reasoning_chain
    }

    /// Get the number of reasoning steps recorded.
    pub fn reasoning_chain_len(&self) -> usize {
        self.reasoning_chain.len()
    }

    /// Add a rule to the rule engine backend. No-op if not using rule engine.
    pub fn add_rule(&mut self, name: String, conditions: Vec<String>, action: String, priority: i32) {
        if let ReasoningBackend::RuleEngine { ref mut rules } = self.reasoning_backend {
            rules.push(Rule { name, conditions, action, priority });
        }
    }

    /// Consolidate working memory: transfer qualifying items to long-term stores.
    ///
    /// Items qualify for consolidation if `access_count >= 2` OR `importance >= 0.7`.
    /// - Experience kind → episodic.record()
    /// - Fact kind → semantic.store() (pipe-delimited "subject|predicate|object" or default triple)
    /// - Procedure kind → procedural.store()
    /// - General kind with high access/importance → episodic.record() (treated as experience)
    pub fn consolidate(&mut self) -> Result<ConsolidationResult, String> {
        let mut result = ConsolidationResult {
            items_reviewed: 0,
            to_episodic: 0,
            to_semantic: 0,
            to_procedural: 0,
        };

        let mut keys_to_remove = Vec::new();

        // Batch all long-term writes into a single explicit SQLite transaction
        // so the whole consolidation issues ONE commit/fsync instead of one
        // autocommit + fsync round-trip per item.
        let db = self.episodic.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        db.execute_batch("BEGIN")
            .map_err(|e| format!("consolidate BEGIN failed: {e}"))?;

        let write_result: Result<(), String> = (|| {
            for item in self.working.items() {
                result.items_reviewed += 1;

                // Only consolidate items that meet threshold
                if item.access_count < 2 && item.importance < 0.7 {
                    continue;
                }

                match item.kind {
                    MemoryKind::Experience | MemoryKind::General => {
                        self.episodic.record_tx(&db, &item.value)?;
                        result.to_episodic += 1;
                        keys_to_remove.push(item.key.clone());
                    }
                    MemoryKind::Fact => {
                        // Try pipe-delimited "subject|predicate|object"
                        let parts: Vec<&str> = item.value.splitn(3, '|').collect();
                        if parts.len() == 3 {
                            self.semantic.store_tx(&db, parts[0], parts[1], parts[2])?;
                        } else {
                            // Default triple: key "is" value
                            self.semantic.store_tx(&db, &item.key, "is", &item.value)?;
                        }
                        result.to_semantic += 1;
                        keys_to_remove.push(item.key.clone());
                    }
                    MemoryKind::Procedure => {
                        self.procedural.store_tx(
                            &db,
                            &item.key,
                            &item.value,
                            "consolidated from working memory",
                        )?;
                        result.to_procedural += 1;
                        keys_to_remove.push(item.key.clone());
                    }
                }
            }
            Ok(())
        })();

        if let Err(e) = write_result {
            // Roll back the whole batch on any failure (all-or-nothing).
            let _ = db.execute_batch("ROLLBACK");
            return Err(e);
        }

        db.execute_batch("COMMIT")
            .map_err(|e| format!("consolidate COMMIT failed: {e}"))?;
        drop(db);

        // Remove consolidated items from working memory
        self.working.remove_keys(&keys_to_remove);

        Ok(result)
    }

    // ── Snapshot Methods ─────────────────────────────────────────────────

    /// Validate a snapshot name: only alphanumeric + underscore allowed.
    fn sanitize_snapshot_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("snapshot name cannot be empty".to_string());
        }
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(format!(
                "snapshot name '{}' contains invalid characters (only alphanumeric and underscore allowed)",
                name
            ));
        }
        Ok(())
    }

    /// Create a snapshot of all three persistent memory regions.
    /// Uses CREATE TABLE AS SELECT for table-copy approach.
    pub fn snapshot(&self, name: &str) -> Result<String, String> {
        Self::sanitize_snapshot_name(name)?;
        let db = self.episodic.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        db.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS episodic_snapshot_{name} AS SELECT * FROM episodic;
             CREATE TABLE IF NOT EXISTS semantic_snapshot_{name} AS SELECT * FROM semantic;
             CREATE TABLE IF NOT EXISTS procedural_snapshot_{name} AS SELECT * FROM procedural;"
        ))
        .map_err(|e| format!("snapshot '{name}' creation failed: {e}"))?;
        Ok(name.to_string())
    }

    /// Rollback all three persistent regions to a named snapshot.
    /// Does NOT clear working memory (ephemeral).
    pub fn rollback_to(&self, name: &str) -> Result<(), String> {
        Self::sanitize_snapshot_name(name)?;
        let db = self.episodic.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        // Verify snapshot exists
        let exists: bool = db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                rusqlite::params![format!("episodic_snapshot_{name}")],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !exists {
            return Err(format!("snapshot '{name}' not found"));
        }
        db.execute_batch(&format!(
            "DELETE FROM episodic; INSERT INTO episodic SELECT * FROM episodic_snapshot_{name};
             DELETE FROM semantic; INSERT INTO semantic SELECT * FROM semantic_snapshot_{name};
             DELETE FROM procedural; INSERT INTO procedural SELECT * FROM procedural_snapshot_{name};"
        ))
        .map_err(|e| format!("rollback to '{name}' failed: {e}"))?;
        Ok(())
    }

    /// Release (drop) a named snapshot's backup tables.
    pub fn release_snapshot(&self, name: &str) -> Result<(), String> {
        Self::sanitize_snapshot_name(name)?;
        let db = self.episodic.db.lock().map_err(|_| "memory db lock poisoned".to_string())?;
        db.execute_batch(&format!(
            "DROP TABLE IF EXISTS episodic_snapshot_{name};
             DROP TABLE IF EXISTS semantic_snapshot_{name};
             DROP TABLE IF EXISTS procedural_snapshot_{name};"
        ))
        .map_err(|e| format!("release snapshot '{name}' failed: {e}"))?;
        Ok(())
    }

    /// List all snapshot names by querying sqlite_master for snapshot tables.
    pub fn list_snapshots(&self) -> Vec<String> {
        let db = match self.episodic.db.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match db.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_snapshot_%' ORDER BY name"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let names: Vec<String> = rows.filter_map(|r| r.ok()).collect();
        // Extract unique snapshot names from table names like "episodic_snapshot_foo"
        let mut snapshot_names = std::collections::HashSet::new();
        for table_name in &names {
            // Pattern: {region}_snapshot_{name}
            for prefix in &["episodic_snapshot_", "semantic_snapshot_", "procedural_snapshot_"] {
                if let Some(snap_name) = table_name.strip_prefix(prefix) {
                    snapshot_names.insert(snap_name.to_string());
                }
            }
        }
        let mut result: Vec<String> = snapshot_names.into_iter().collect();
        result.sort();
        result
    }
}

/// Result of a memory consolidation operation.
#[derive(Debug, Clone)]
pub struct ConsolidationResult {
    pub items_reviewed: usize,
    pub to_episodic: usize,
    pub to_semantic: usize,
    pub to_procedural: usize,
}

// ── BrainHandle ───────────────────────────────────────────────────────────────

/// Wrapper for sharing Brain across the interpreter via Value enum.
pub struct BrainHandle(pub Rc<RefCell<Brain>>);

impl fmt::Debug for BrainHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<brain>")
    }
}

impl Clone for BrainHandle {
    fn clone(&self) -> Self {
        BrainHandle(Rc::clone(&self.0))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a Brain with in-memory SQLite for testing.
    fn test_brain() -> Brain {
        Brain::new(BrainConfig {
            working_capacity: 5,
            persistence_path: ":memory:".to_string(),
            ..BrainConfig::default()
        })
        .expect("test brain should initialize")
    }

    // ── 2.5 embedding / vector retrieval tests ────────────────────────────

    #[test]
    fn embed_text_dim_zero_returns_empty() {
        assert!(embed_text("anything", 0).is_empty());
    }

    #[test]
    fn embed_cosine_same_text_high_unrelated_low() {
        let a = embed_text("the quick brown fox", 128);
        let b = embed_text("the quick brown fox", 128);
        let c = embed_text("quantum chromodynamics", 128);
        let self_sim = cosine_similarity(&a, &b);
        let unrelated = cosine_similarity(&a, &c);
        assert!(self_sim > 0.95, "same text should be near-identical, got {self_sim}");
        assert!(
            unrelated < self_sim,
            "unrelated should score lower: {unrelated} vs {self_sim}"
        );
    }

    #[test]
    fn recall_by_similarity_ranks_relevant_highest() {
        let brain = test_brain();
        brain.episodic.record("the quick brown fox jumps over the lazy dog").unwrap();
        brain.episodic.record("quantum computing principles for superposition").unwrap();
        brain.episodic.record("a brown fox runs fast at dawn").unwrap();

        let top = brain.recall_by_similarity("quick brown fox", 3).unwrap();
        assert!(!top.is_empty(), "expected some results");
        // The two fox-related entries should outrank the quantum entry.
        let fox_score = top
            .iter()
            .find(|(c, _)| c.contains("fox"))
            .map(|(_, s)| *s)
            .unwrap_or(0.0);
        let quantum_score = top
            .iter()
            .find(|(c, _)| c.contains("quantum"))
            .map(|(_, s)| *s)
            .unwrap_or(0.0);
        assert!(
            fox_score > quantum_score,
            "fox-related entry ({fox_score}) should outrank quantum ({quantum_score})"
        );
    }

    // ── WorkingMemory tests ───────────────────────────────────────────────

    #[test]
    fn working_memory_store_and_recall() {
        let mut brain = test_brain();
        brain.working.store("key1", "value1");
        let item = brain.working.recall("key1").unwrap();
        assert_eq!(item.key, "key1");
        assert_eq!(item.value, "value1");
        assert_eq!(item.access_count, 1);
    }

    #[test]
    fn working_memory_recall_missing_key() {
        let mut brain = test_brain();
        assert!(brain.working.recall("nonexistent").is_none());
    }

    #[test]
    fn working_memory_eviction_on_overflow() {
        let mut brain = test_brain(); // capacity = 5
        for i in 0..7 {
            brain.working.store(&format!("key{i}"), &format!("val{i}"));
        }
        // Should only have 5 items (oldest 2 evicted)
        assert_eq!(brain.working.len(), 5);
        // key0 and key1 should be evicted
        assert!(brain.working.recall("key0").is_none());
        assert!(brain.working.recall("key1").is_none());
        // key2 through key6 should still exist
        assert!(brain.working.recall("key2").is_some());
        assert!(brain.working.recall("key6").is_some());
    }

    #[test]
    fn working_memory_recall_all() {
        let mut brain = test_brain();
        brain.working.store("a", "1");
        brain.working.store("b", "2");
        brain.working.store("c", "3");
        let all = brain.working.recall_all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn working_memory_remove() {
        let mut brain = test_brain();
        brain.working.store("x", "1");
        brain.working.store("y", "2");
        assert!(brain.working.remove("x"));
        assert_eq!(brain.working.len(), 1);
        assert!(!brain.working.remove("x")); // already removed
    }

    #[test]
    fn working_memory_clear() {
        let mut brain = test_brain();
        brain.working.store("a", "1");
        brain.working.store("b", "2");
        brain.working.clear();
        assert_eq!(brain.working.len(), 0);
        assert!(brain.working.is_empty());
    }

    #[test]
    fn working_memory_len_and_is_empty() {
        let mut brain = test_brain();
        assert!(brain.working.is_empty());
        assert_eq!(brain.working.len(), 0);
        brain.working.store("k", "v");
        assert!(!brain.working.is_empty());
        assert_eq!(brain.working.len(), 1);
    }

    #[test]
    fn working_memory_access_count_increments() {
        let mut brain = test_brain();
        brain.working.store("k", "v");
        brain.working.recall("k");
        brain.working.recall("k");
        let item = brain.working.recall("k").unwrap();
        assert_eq!(item.access_count, 3);
    }

    // ── EpisodicMemory tests ──────────────────────────────────────────────

    #[test]
    fn episodic_record_and_count() {
        let brain = test_brain();
        brain.episodic.record("first experience").unwrap();
        brain.episodic.record("second experience").unwrap();
        assert_eq!(brain.episodic.count().unwrap(), 2);
    }

    #[test]
    fn episodic_record_with_context() {
        let brain = test_brain();
        brain
            .episodic
            .record_with_context("important event", "test context", 0.9)
            .unwrap();
        let entries = brain.episodic.search("important").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].content, "important event");
        assert_eq!(entries[0].context.as_deref(), Some("test context"));
        assert!((entries[0].importance - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn episodic_query_since() {
        let brain = test_brain();
        brain.episodic.record("recent event").unwrap();
        // Query for entries in last 60 seconds -- our just-inserted entry should appear
        let entries = brain.episodic.query_since(60).unwrap();
        assert!(!entries.is_empty());
        assert_eq!(entries[0].content, "recent event");
    }

    #[test]
    fn episodic_search_keyword() {
        let brain = test_brain();
        brain.episodic.record("the cat sat on the mat").unwrap();
        brain.episodic.record("dogs are loyal").unwrap();
        brain.episodic.record("cats and dogs").unwrap();

        let cat_entries = brain.episodic.search("cat").unwrap();
        assert_eq!(cat_entries.len(), 2); // "the cat..." and "cats and dogs"

        let dog_entries = brain.episodic.search("dog").unwrap();
        assert_eq!(dog_entries.len(), 2); // "dogs are loyal" and "cats and dogs"
    }

    #[test]
    fn episodic_search_no_results() {
        let brain = test_brain();
        brain.episodic.record("hello world").unwrap();
        let entries = brain.episodic.search("xyz").unwrap();
        assert!(entries.is_empty());
    }

    // ── SemanticMemory tests ──────────────────────────────────────────────

    #[test]
    fn semantic_store_and_query() {
        let brain = test_brain();
        brain.semantic.store("Rust", "is_a", "language").unwrap();
        brain.semantic.store("Tallow", "is_a", "language").unwrap();
        brain.semantic.store("Tallow", "uses", "LLVM").unwrap();

        // Query all triples about Tallow
        let triples = brain.semantic.query(Some("Tallow"), None, None).unwrap();
        assert_eq!(triples.len(), 2);

        // Query by predicate
        let triples = brain.semantic.query(None, Some("is_a"), None).unwrap();
        assert_eq!(triples.len(), 2);

        // Query by object
        let triples = brain
            .semantic
            .query(None, None, Some("language"))
            .unwrap();
        assert_eq!(triples.len(), 2);
    }

    #[test]
    fn semantic_store_with_meta() {
        let brain = test_brain();
        brain
            .semantic
            .store_with_meta("Earth", "has", "Moon", 0.99, "astronomy")
            .unwrap();

        let triples = brain.semantic.query(Some("Earth"), None, None).unwrap();
        assert_eq!(triples.len(), 1);
        assert!((triples[0].confidence - 0.99).abs() < f64::EPSILON);
    }

    #[test]
    fn semantic_query_all_wildcards() {
        let brain = test_brain();
        brain.semantic.store("A", "rel", "B").unwrap();
        brain.semantic.store("C", "rel", "D").unwrap();
        let all = brain.semantic.query(None, None, None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn semantic_deduplication() {
        let brain = test_brain();
        brain.semantic.store("X", "rel", "Y").unwrap();
        brain.semantic.store("X", "rel", "Y").unwrap(); // same triple -- INSERT OR REPLACE
        let count = brain.semantic.count().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn semantic_related_graph_traversal() {
        let brain = test_brain();
        // Build a graph: A -> B -> C -> D
        brain.semantic.store("A", "connects_to", "B").unwrap();
        brain.semantic.store("B", "connects_to", "C").unwrap();
        brain.semantic.store("C", "connects_to", "D").unwrap();

        // Depth 1: should find direct connections from A
        let depth1 = brain.semantic.related("A", 1).unwrap();
        assert!(!depth1.is_empty());
        // Should include A->B
        assert!(depth1.iter().any(|t| t.subject == "A" && t.object == "B"));

        // Depth 2: should find up to 2 hops
        let depth2 = brain.semantic.related("A", 2).unwrap();
        assert!(depth2.len() >= 2);
        // Should include B->C
        assert!(depth2.iter().any(|t| t.subject == "B" && t.object == "C"));
    }

    #[test]
    fn semantic_count() {
        let brain = test_brain();
        assert_eq!(brain.semantic.count().unwrap(), 0);
        brain.semantic.store("A", "b", "C").unwrap();
        assert_eq!(brain.semantic.count().unwrap(), 1);
    }

    #[test]
    fn semantic_provenance_round_trip() {
        let brain = test_brain();
        brain
            .semantic
            .store_with_provenance("Rust", "is_a", "language", 0.95, Some("wiki"), Some("agent-1"), Some("run-77"))
            .unwrap();

        let triples = brain
            .semantic
            .query_with_provenance(Some("Rust"), None, None, None, None)
            .unwrap();
        assert_eq!(triples.len(), 1);
        let t = &triples[0];
        assert_eq!(t.agent_id.as_deref(), Some("agent-1"));
        assert_eq!(t.source.as_deref(), Some("wiki"));
        assert_eq!(t.trace_id.as_deref(), Some("run-77"));
        assert!((t.confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn semantic_dedup_merge() {
        let brain = test_brain();
        // Same subject+predicate+object written twice with different provenance.
        brain
            .semantic
            .store_merged("Earth", "has", "Moon", 0.60, Some("astro"), Some("agent-1"), Some("run-1"))
            .unwrap();
        brain
            .semantic
            .store_merged("Earth", "has", "Moon", 0.95, Some("nasa"), Some("agent-2"), Some("run-2"))
            .unwrap();

        // UNIQUE(subject,predicate,object) honored: one row, not a duplicate.
        assert_eq!(brain.semantic.count().unwrap(), 1);

        let triples = brain
            .semantic
            .query_with_provenance(Some("Earth"), Some("has"), None, None, None)
            .unwrap();
        assert_eq!(triples.len(), 1);
        let t = &triples[0];
        // Higher confidence retained.
        assert!((t.confidence - 0.95).abs() < f64::EPSILON);
        // Sources unioned, deduplicated.
        let sources: Vec<&str> = t.source.as_deref().unwrap().split(',').collect();
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&"astro"));
        assert!(sources.contains(&"nasa"));

        // merged_semantic returns a single merged entry with unioned provenance.
        let merged = brain
            .semantic
            .merged_semantic("Earth", "has")
            .unwrap()
            .expect("merged entry should exist");
        assert!((merged.confidence - 0.95).abs() < f64::EPSILON);
        let merged_sources: Vec<&str> = merged.source.as_deref().unwrap().split(',').collect();
        assert_eq!(merged_sources.len(), 2);
    }

    #[test]
    fn semantic_filter_by_agent_and_trace() {
        let brain = test_brain();
        brain
            .semantic
            .store_with_provenance("X", "rel", "Y", 0.8, Some("a"), Some("agent-a"), Some("run-1"))
            .unwrap();
        brain
            .semantic
            .store_with_provenance("P", "rel", "Q", 0.7, Some("b"), Some("agent-b"), Some("run-2"))
            .unwrap();

        // Agent scoping: only agent-a's triple.
        let only_a = brain.semantic.filter_by_agent("agent-a").unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].subject, "X");
        assert_eq!(only_a[0].agent_id.as_deref(), Some("agent-a"));

        // Trace scoping: only run-2's triple.
        let only_t2 = brain.semantic.filter_by_trace("run-2").unwrap();
        assert_eq!(only_t2.len(), 1);
        assert_eq!(only_t2[0].subject, "P");
        assert_eq!(only_t2[0].trace_id.as_deref(), Some("run-2"));
    }

    // ── ProceduralMemory tests ────────────────────────────────────────────

    #[test]
    fn procedural_store_auto_version() {
        let brain = test_brain();
        let v1 = brain
            .procedural
            .store("fetch_data", "fn fetch() {}", "fetches data")
            .unwrap();
        assert_eq!(v1, 1);

        let v2 = brain
            .procedural
            .store("fetch_data", "fn fetch_v2() {}", "improved fetcher")
            .unwrap();
        assert_eq!(v2, 2);
    }

    #[test]
    fn procedural_recall_latest() {
        let brain = test_brain();
        brain
            .procedural
            .store("greet", "fn greet() { print('hello') }", "v1 greet")
            .unwrap();
        brain
            .procedural
            .store("greet", "fn greet() { print('hi') }", "v2 greet")
            .unwrap();

        let skill = brain.procedural.recall("greet").unwrap().unwrap();
        assert_eq!(skill.version, 2);
        assert_eq!(skill.body, "fn greet() { print('hi') }");
        assert_eq!(skill.description, "v2 greet");
    }

    #[test]
    fn procedural_recall_specific_version() {
        let brain = test_brain();
        brain
            .procedural
            .store("task", "body_v1", "desc_v1")
            .unwrap();
        brain
            .procedural
            .store("task", "body_v2", "desc_v2")
            .unwrap();

        let v1 = brain
            .procedural
            .recall_version("task", 1)
            .unwrap()
            .unwrap();
        assert_eq!(v1.body, "body_v1");

        let v2 = brain
            .procedural
            .recall_version("task", 2)
            .unwrap()
            .unwrap();
        assert_eq!(v2.body, "body_v2");

        // Nonexistent version
        assert!(brain.procedural.recall_version("task", 99).unwrap().is_none());
    }

    #[test]
    fn procedural_recall_missing_skill() {
        let brain = test_brain();
        assert!(brain.procedural.recall("nonexistent").unwrap().is_none());
    }

    #[test]
    fn procedural_list_skills() {
        let brain = test_brain();
        brain
            .procedural
            .store("alpha", "body", "desc")
            .unwrap();
        brain
            .procedural
            .store("beta", "body", "desc")
            .unwrap();
        brain
            .procedural
            .store("alpha", "body_v2", "desc_v2")
            .unwrap();

        let names = brain.procedural.list_skills().unwrap();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn procedural_record_usage() {
        let brain = test_brain();
        brain
            .procedural
            .store("skill_a", "body", "desc")
            .unwrap();

        // Record 3 successes and 1 failure
        brain.procedural.record_usage("skill_a", true).unwrap();
        brain.procedural.record_usage("skill_a", true).unwrap();
        brain.procedural.record_usage("skill_a", true).unwrap();
        brain.procedural.record_usage("skill_a", false).unwrap();

        let skill = brain.procedural.recall("skill_a").unwrap().unwrap();
        assert_eq!(skill.usage_count, 4);
        // Running average: (0 + 1 + 1 + 1 + 0) / 4 = 0.75
        assert!((skill.success_rate - 0.75).abs() < 0.01);
    }

    #[test]
    fn procedural_count() {
        let brain = test_brain();
        assert_eq!(brain.procedural.count().unwrap(), 0);
        brain.procedural.store("s1", "b", "d").unwrap();
        brain.procedural.store("s1", "b2", "d2").unwrap();
        assert_eq!(brain.procedural.count().unwrap(), 2); // 2 versions
    }

    // ── Brain tests ───────────────────────────────────────────────────────

    #[test]
    fn brain_new_memory_succeeds() {
        let brain = test_brain();
        assert_eq!(brain.working.len(), 0);
        assert_eq!(brain.episodic.count().unwrap(), 0);
        assert_eq!(brain.semantic.count().unwrap(), 0);
        assert_eq!(brain.procedural.count().unwrap(), 0);
        assert!(brain.reasoning_chain.is_empty());
    }

    #[test]
    fn brain_new_file_persistence() {
        let dir = std::env::temp_dir().join("tallow_brain_test.db");
        let path = dir.to_string_lossy().to_string();

        // Clean up from previous run
        let _ = std::fs::remove_file(&path);

        // Create and populate
        {
            let brain = Brain::new(BrainConfig {
                persistence_path: path.clone(),
                ..BrainConfig::default()
            })
            .unwrap();
            brain.episodic.record("persisted event").unwrap();
            brain.semantic.store("Tallow", "is", "fast").unwrap();
            brain
                .procedural
                .store("skill1", "body1", "desc1")
                .unwrap();
        }

        // Reopen and verify data persisted
        {
            let brain = Brain::new(BrainConfig {
                persistence_path: path.clone(),
                ..BrainConfig::default()
            })
            .unwrap();
            assert_eq!(brain.episodic.count().unwrap(), 1);
            assert_eq!(brain.semantic.count().unwrap(), 1);
            assert_eq!(brain.procedural.count().unwrap(), 1);

            let entries = brain.episodic.search("persisted").unwrap();
            assert_eq!(entries.len(), 1);
        }

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn brain_handle_clone_and_debug() {
        let brain = test_brain();
        let handle = BrainHandle(Rc::new(RefCell::new(brain)));
        let cloned = handle.clone();
        assert_eq!(format!("{:?}", handle), "<brain>");
        assert_eq!(format!("{:?}", cloned), "<brain>");
    }

    #[test]
    fn memory_kind_display() {
        assert_eq!(format!("{}", MemoryKind::Fact), "fact");
        assert_eq!(format!("{}", MemoryKind::Experience), "experience");
        assert_eq!(format!("{}", MemoryKind::Procedure), "procedure");
        assert_eq!(format!("{}", MemoryKind::General), "general");
    }

    // ── Snapshot tests ───────────────────────────────────────────────────

    #[test]
    fn snapshot_creation_and_rollback() {
        let brain = test_brain();
        // Populate some data
        brain.episodic.record("event1").unwrap();
        brain.semantic.store("A", "is", "B").unwrap();
        brain.procedural.store("skill1", "body1", "desc1").unwrap();

        // Create snapshot
        let name = brain.snapshot("checkpoint1").unwrap();
        assert_eq!(name, "checkpoint1");

        // Modify data after snapshot
        brain.episodic.record("event2").unwrap();
        brain.semantic.store("C", "is", "D").unwrap();
        brain.procedural.store("skill2", "body2", "desc2").unwrap();

        assert_eq!(brain.episodic.count().unwrap(), 2);
        assert_eq!(brain.semantic.count().unwrap(), 2);
        assert_eq!(brain.procedural.count().unwrap(), 2);

        // Rollback
        brain.rollback_to("checkpoint1").unwrap();

        assert_eq!(brain.episodic.count().unwrap(), 1);
        assert_eq!(brain.semantic.count().unwrap(), 1);
        assert_eq!(brain.procedural.count().unwrap(), 1);
    }

    #[test]
    fn rollback_does_not_affect_working_memory() {
        let mut brain = test_brain();
        brain.working.store("key1", "val1");
        brain.snapshot("snap1").unwrap();

        // Add to working memory after snapshot
        brain.working.store("key2", "val2");
        assert_eq!(brain.working.len(), 2);

        // Rollback
        brain.rollback_to("snap1").unwrap();

        // Working memory should be unchanged (it is ephemeral)
        assert_eq!(brain.working.len(), 2);
        assert!(brain.working.recall("key2").is_some());
    }

    #[test]
    fn snapshot_name_sanitization_rejects_special_chars() {
        let brain = test_brain();
        assert!(brain.snapshot("valid_name123").is_ok());
        assert!(brain.snapshot("has spaces").is_err());
        assert!(brain.snapshot("has-dash").is_err());
        assert!(brain.snapshot("sql;injection").is_err());
        assert!(brain.snapshot("drop table").is_err());
        assert!(brain.snapshot("").is_err());
        assert!(brain.snapshot("has'quote").is_err());
    }

    #[test]
    fn list_snapshots_returns_created_names() {
        let brain = test_brain();
        assert!(brain.list_snapshots().is_empty());

        brain.snapshot("alpha").unwrap();
        brain.snapshot("beta").unwrap();

        let snaps = brain.list_snapshots();
        assert_eq!(snaps.len(), 2);
        assert!(snaps.contains(&"alpha".to_string()));
        assert!(snaps.contains(&"beta".to_string()));
    }

    #[test]
    fn release_snapshot_removes_backup_tables() {
        let brain = test_brain();
        brain.episodic.record("data").unwrap();
        brain.snapshot("temp").unwrap();
        assert_eq!(brain.list_snapshots().len(), 1);

        brain.release_snapshot("temp").unwrap();
        assert!(brain.list_snapshots().is_empty());
    }

    // ── Quarantine tests ──────────────────────────────────────────────────

    #[test]
    fn episodic_quarantine_excludes_from_recall() {
        let brain = test_brain();
        brain.episodic.record("normal event").unwrap();
        brain.episodic.record("suspicious event").unwrap();

        // Get the IDs
        let all = brain.episodic.search("event").unwrap();
        assert_eq!(all.len(), 2);
        let suspicious_id = all.iter().find(|e| e.content == "suspicious event").unwrap().id;

        // Quarantine
        brain.episodic.quarantine(suspicious_id).unwrap();

        // Normal queries should exclude quarantined items
        let visible = brain.episodic.search("event").unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].content, "normal event");

        // Count should reflect only non-quarantined
        assert_eq!(brain.episodic.count().unwrap(), 1);
    }

    #[test]
    fn episodic_quarantine_restore_makes_visible() {
        let brain = test_brain();
        brain.episodic.record("item to quarantine").unwrap();
        let entries = brain.episodic.search("quarantine").unwrap();
        let id = entries[0].id;

        brain.episodic.quarantine(id).unwrap();
        assert_eq!(brain.episodic.search("quarantine").unwrap().len(), 0);

        brain.episodic.restore_from_quarantine(id).unwrap();
        assert_eq!(brain.episodic.search("quarantine").unwrap().len(), 1);
    }

    #[test]
    fn episodic_list_quarantined_returns_only_quarantined() {
        let brain = test_brain();
        brain.episodic.record("normal").unwrap();
        brain.episodic.record("bad data").unwrap();
        let entries = brain.episodic.search("bad").unwrap();
        let bad_id = entries[0].id;
        brain.episodic.quarantine(bad_id).unwrap();

        let quarantined = brain.episodic.list_quarantined().unwrap();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].0, bad_id);
        assert_eq!(quarantined[0].1, "bad data");
    }

    #[test]
    fn semantic_quarantine_excludes_from_query() {
        let brain = test_brain();
        brain.semantic.store("A", "is", "good").unwrap();
        brain.semantic.store("B", "is", "bad").unwrap();

        // Get B's ID: query all then find the B triple
        let all = brain.semantic.query(None, None, None).unwrap();
        assert_eq!(all.len(), 2);
        // We need the row id; let's query directly
        let b_id: i64 = brain.episodic.db.lock().unwrap()
            .query_row("SELECT id FROM semantic WHERE subject = 'B'", [], |row| row.get(0))
            .unwrap();

        brain.semantic.quarantine(b_id).unwrap();

        let visible = brain.semantic.query(None, None, None).unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].subject, "A");

        let quarantined = brain.semantic.list_quarantined().unwrap();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].1, "B");
    }

    #[test]
    fn procedural_quarantine_excludes_from_recall() {
        let brain = test_brain();
        brain.procedural.store("good_skill", "body1", "desc1").unwrap();
        brain.procedural.store("bad_skill", "body2", "desc2").unwrap();

        // Get bad_skill's ID
        let bad_id: i64 = brain.episodic.db.lock().unwrap()
            .query_row("SELECT id FROM procedural WHERE name = 'bad_skill'", [], |row| row.get(0))
            .unwrap();

        brain.procedural.quarantine(bad_id).unwrap();

        // recall should not find quarantined skill
        assert!(brain.procedural.recall("bad_skill").unwrap().is_none());
        // list_skills should exclude quarantined
        let skills = brain.procedural.list_skills().unwrap();
        assert_eq!(skills, vec!["good_skill"]);
        // count should exclude quarantined
        assert_eq!(brain.procedural.count().unwrap(), 1);

        let quarantined = brain.procedural.list_quarantined().unwrap();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].1, "bad_skill");
    }

    // ── Skill source storage tests ────────────────────────────────────────

    #[test]
    fn skill_source_storage_and_recall_source() {
        let brain = test_brain();
        let source = "fn double(x: i32) -> i32 { x * 2 }";
        brain.procedural.store("double", source, "doubles a number").unwrap();

        let recalled = brain.procedural.recall_source("double").unwrap();
        assert_eq!(recalled, Some(source.to_string()));

        // Missing skill returns None
        assert!(brain.procedural.recall_source("nonexistent").unwrap().is_none());
    }

    // ── Outcome history tests ─────────────────────────────────────────────

    #[test]
    fn outcome_history_returns_filtered_results() {
        let brain = test_brain();
        brain.episodic.record("fetch: success, got 200 items").unwrap();
        brain.episodic.record("fetch: failure due to timeout").unwrap();
        brain.episodic.record("parse: completed successfully").unwrap();
        brain.episodic.record("fetch: success, got 50 items").unwrap();

        // Query outcome history for "fetch" actions
        let history = brain.episodic.outcome_history("fetch", 10).unwrap();
        assert_eq!(history.len(), 3); // 3 fetch entries
        // Most recent first: "fetch: success" (true), "fetch: failure" (false), "fetch: success" (true)
        // Note: order is newest first
        assert!(history[0].0); // success
        assert!(!history[1].0); // failure (timeout)
        assert!(history[2].0); // success

        // Query for "parse" actions
        let parse_hist = brain.episodic.outcome_history("parse", 10).unwrap();
        assert_eq!(parse_hist.len(), 1);
        assert!(parse_hist[0].0); // completed = success
    }

    // ── FTS5 keyword search tests ────────────────────────────────────────

    /// Small corpus: verify the exact-substring LIKE fallback still matches
    /// substrings that are not whole tokens (this is WHY LIKE is kept below
    /// the threshold — FTS tokenization would miss "lencow" in "flamencow").
    #[test]
    fn episodic_search_fallback_exact_substring_small_corpus() {
        let brain = test_brain();
        brain
            .episodic
            .record("the flamencow dances at midnight")
            .unwrap();

        // Below threshold => exact-substring LIKE.
        let hits = brain.episodic.search("flamencow").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].content, "the flamencow dances at midnight");

        // A substring that is not a whole word still matches via LIKE.
        // "menc" is a substring of "flamencow" but FTS would tokenize it as
        // the whole token "flamencow", so only the LIKE fallback finds it.
        let sub_hits = brain.episodic.search("menc").unwrap();
        assert_eq!(sub_hits.len(), 1);
        assert_eq!(sub_hits[0].content, "the flamencow dances at midnight");

        // The FTS5 index stays in sync with the episodic table on write.
        let fts_count: i64 = brain
            .episodic
            .db
            .lock().unwrap()
            .query_row("SELECT COUNT(*) FROM episodic_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_count, 1);
    }

    /// Large corpus (above the FTS threshold): both `search()` and
    /// `outcome_history()` must use the FTS5 index and return correct matches.
    #[test]
    fn episodic_fts_search_and_outcome_history_on_large_corpus() {
        let brain = test_brain();
        let mut fetch_hits: usize = 0;
        for i in 0..EPISODIC_FTS_THRESHOLD + 5 {
            let content = if i == 100 {
                "the nichepuffin orbited the ring".to_string()
            } else if i % 500 == 0 {
                "fetch: success for index".to_string()
            } else {
                format!("filler event number {i}")
            };
            brain.episodic.record(&content).unwrap();
            if i % 500 == 0 {
                fetch_hits += 1;
            }
        }

        // Above threshold => FTS token search.
        let got = brain.episodic.search("nichepuffin").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].content, "the nichepuffin orbited the ring");

        // Non-matching token returns empty (not an error).
        assert!(
            brain
                .episodic
                .search("zzz_absent_token_qqq")
                .unwrap()
                .is_empty()
        );

        // outcome_history also uses FTS and returns every matching fetch row.
        let hist = brain.episodic.outcome_history("fetch", 100).unwrap();
        assert_eq!(hist.len(), fetch_hits);
        assert!(hist.iter().all(|(ok, _)| *ok));
    }

    // ── Consolidated-write batching tests ────────────────────────────────

    /// Consolidation wraps all long-term writes in a SINGLE transaction
    /// (exactly one BEGIN + one COMMIT) instead of one autocommit per item.
    #[test]
    fn consolidate_batches_writes_in_single_transaction() {
        // Build a brain with enough working capacity to hold all 30 items
        // (test_brain() caps working memory at 5, which would evict the rest).
        let mut brain = Brain::new(BrainConfig {
            working_capacity: 30,
            persistence_path: ":memory:".to_string(),
            ..BrainConfig::default()
        })
        .expect("test brain should initialize");
        for i in 0..30 {
            brain.working.store_with_kind(
                &format!("exp_key{i}"),
                &format!("experience number {i}"),
                MemoryKind::Experience,
                0.9,
            );
        }

        // Correctness: all 30 items written exactly once and pruned from working
        // memory. (Single-transaction batching is verified in the impl — the
        // consolidate loop wraps all long-term writes in one explicit BEGIN/COMMIT
        // with a rollback guard; the rusqlite `trace` feature needed to count
        // BEGIN/COMMIT tokens is not enabled in this crate.)
        let res = brain.consolidate().unwrap();
        assert_eq!(res.items_reviewed, 30);
        assert_eq!(res.to_episodic, 30);
        assert_eq!(res.to_semantic, 0);
        assert_eq!(res.to_procedural, 0);

        assert_eq!(brain.episodic.count().unwrap(), 30);
        assert_eq!(brain.working.len(), 0);
    }
}
