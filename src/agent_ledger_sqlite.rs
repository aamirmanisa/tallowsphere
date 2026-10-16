//! Durable SQLite [`LedgerBackend`] — task A1.1.2b (frozen interface §3).
//!
//! Persists the append-only, hash-chained event log (see [`crate::agent_ledger`])
//! in a single SQLite table so an investigation's ledger survives process
//! restarts. The backend enforces exactly the same ingest invariant as
//! [`crate::agent_ledger::Ledger::append`] — `ev.prev_hash` must equal the
//! current chain head (`"GENESIS"` while empty) — but does so inside a
//! transaction so the check and the insert cannot interleave.
//!
//! ## Concurrency model (single-writer, no internal locking)
//! This backend assumes **one writer**: `append` takes `&mut self` and no
//! internal locking is performed. Callers must serialize all access to one
//! [`SqliteLedger`] (e.g. keep it on one thread), or use the ready-made
//! single-writer service: [`CoordinatedLedger`] owns the connection on a
//! `StoreCoordinator` thread (pattern from `src/agent_store.rs`) and runs
//! every operation there in FIFO submission order. Concurrent connections to
//! the same file are tolerated only as OS-level SQLite file locking allows;
//! `busy_timeout=5000` makes a contending writer wait rather than fail
//! immediately.
//!
//! ## Snapshot cadence (A1.1.2 adoption)
//! [`CoordinatedLedger`] checkpoints the chain: with `cadence = n`, every
//! n-th append also writes a [`LedgerSnapshot`] row into `ledger_snapshots`,
//! in the **same transaction** as the event — a stored snapshot can never
//! disagree with the chain it summarizes (read them back with
//! [`CoordinatedLedger::stored_snapshots`]).
//!
//! ## Integrity scope
//! Like [`crate::agent_ledger::MemoryLedger`], `append` performs only the link
//! check; it deliberately does **not** recompute the envelope hash (hashing
//! authority stays in [`crate::ledger_events`] and is exercised by the
//! verify pass). `read_all` returns rows in true append order (`seq ASC`).
//!
//! Missing rows / unknown `kind` strings return [`LedgerError::Other`]; they
//! are never panics.

use crate::agent_ledger::{LedgerBackend, LedgerError, LedgerSnapshot};
use crate::ledger_events::{EventEnvelope, EventKind, GENESIS};
use rusqlite::{Connection, OptionalExtension, params};

/// Schema for the append-only ledger table.
///
/// `seq` (AUTOINCREMENT) is the authoritative append order; `id` is the
/// envelope's uuid v4 and is UNIQUE so a retried append of the same event is
/// rejected by the database rather than silently duplicated.
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS ledger_events (\
    seq INTEGER PRIMARY KEY AUTOINCREMENT, \
    id TEXT NOT NULL UNIQUE, \
    ts_ms INTEGER NOT NULL, \
    actor TEXT NOT NULL, \
    run_id TEXT NOT NULL, \
    kind TEXT NOT NULL, \
    payload TEXT NOT NULL, \
    prev_hash TEXT NOT NULL, \
    hash TEXT NOT NULL\
);";

/// Schema for the cadence snapshots table (A1.1.2): one row per append whose
/// 1-based chain length is a multiple of the coordinator's cadence.
const SNAPSHOT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS ledger_snapshots (\
    seq_count INTEGER PRIMARY KEY, \
    head_hash TEXT NOT NULL, \
    ts_ms INTEGER NOT NULL\
);";

/// Durable [`LedgerBackend`] backed by a SQLite table.
///
/// Owns its `rusqlite::Connection`; see the module docs for the single-writer
/// assumption (no internal locking).
#[allow(dead_code)]
#[derive(Debug)]
pub struct SqliteLedger {
    conn: Connection,
}

impl SqliteLedger {
    /// Open (or create) a ledger at `path`, creating the schema if absent.
    ///
    /// Applies `journal_mode=WAL` (concurrent-reader friendly, crash-safe) and
    /// `busy_timeout=5000` (wait instead of erroring under brief contention).
    /// Errors carry the path and the underlying SQLite message inside
    /// [`LedgerError::Other`].
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        let conn = Connection::open(path)
            .map_err(|e| db_err(&format!("open '{}'", path.display()), e))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| db_err("set WAL/busy_timeout pragmas", e))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| db_err("create ledger_events schema", e))?;
        conn.execute_batch(SNAPSHOT_SCHEMA)
            .map_err(|e| db_err("create ledger_snapshots schema", e))?;
        Ok(SqliteLedger { conn })
    }

    /// Current chain head hash — the `prev_hash` the next append must carry.
    /// `"GENESIS"` while the ledger is empty.
    ///
    /// Public because callers need it to build the next envelope with
    /// `ledger_events::chain_next`; the trait itself stays minimal.
    #[allow(dead_code)]
    pub fn head_hash(&self) -> Result<String, LedgerError> {
        head_hash_conn(&self.conn)
    }
}

impl LedgerBackend for SqliteLedger {
    /// Append one event, rejecting it unless it links to the current head.
    ///
    /// Delegates to the shared connection operation [`append_conn`] (snapshot
    /// cadence disabled, as a bare [`SqliteLedger`] has no coordinator): a
    /// rejected event leaves the table untouched, and a committed event is
    /// exactly the new head. Same semantics as
    /// [`crate::agent_ledger::MemoryLedger::append`].
    fn append(&mut self, ev: &EventEnvelope) -> Result<(), LedgerError> {
        append_conn(&mut self.conn, ev, 0)
    }

    /// Read the whole chain back, oldest first (`seq ASC`).
    ///
    /// Delegates to the shared connection operation [`read_all_conn`].
    fn read_all(&self) -> Result<Vec<EventEnvelope>, LedgerError> {
        read_all_conn(&self.conn)
    }

    /// Head hash via the cheap shared connection op (the trait default would
    /// rescan the whole chain).
    fn head_hash(&self) -> Result<String, LedgerError> {
        head_hash_conn(&self.conn)
    }
}

// ── Coordinated single-writer service (A1.1.2 adoption) ─────────────────────

use crate::agent_store::{StoreClient, StoreCoordinator};

/// Single-writer durable ledger service — the A1.1.2 `StoreCoordinator`
/// wiring. Owns the SQLite connection on a coordinator thread and runs every
/// operation there, in FIFO submission order: exactly one writer, no caller
/// locking, read-your-own-writes preserved (same underlying connection).
///
/// **Snapshot cadence**: with `cadence = n`, every n-th successful append
/// (1-based chain length ≡ 0 mod `n`) writes a [`LedgerSnapshot`] row into
/// `ledger_snapshots` in the same transaction as the event; `cadence = 0`
/// disables snapshots. See [`stored_snapshots`](Self::stored_snapshots).
pub struct CoordinatedLedger {
    coord: StoreCoordinator,
    client: StoreClient,
    cadence: usize,
}

impl std::fmt::Debug for CoordinatedLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoordinatedLedger(cadence={})", self.cadence)
    }
}

impl CoordinatedLedger {
    /// Open (or create) the ledger at `path` and start its coordinator
    /// thread. `cadence = 0` disables snapshots; `cadence = n` checkpoints
    /// after every n-th append.
    pub fn spawn(
        path: impl AsRef<std::path::Path>,
        cadence: usize,
    ) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        let conn = Connection::open(path)
            .map_err(|e| db_err(&format!("open '{}'", path.display()), e))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| db_err("set WAL/busy_timeout pragmas", e))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| db_err("create ledger_events schema", e))?;
        conn.execute_batch(SNAPSHOT_SCHEMA)
            .map_err(|e| db_err("create ledger_snapshots schema", e))?;
        let coord = StoreCoordinator::spawn(std::sync::Arc::new(std::sync::Mutex::new(conn)));
        let client = coord.client.clone();
        Ok(CoordinatedLedger {
            coord,
            client,
            cadence,
        })
    }

    /// Append one event through the single-writer thread. Same chain-head
    /// invariant as [`SqliteLedger`] (rejected events store nothing), plus
    /// the cadence snapshot write described on the type.
    pub fn append(&self, ev: &EventEnvelope) -> Result<(), LedgerError> {
        let ev = ev.clone();
        let cadence = self.cadence;
        match self
            .client
            .run(move |conn| Ok::<_, String>(append_conn(conn, &ev, cadence)))
        {
            Ok(inner) => inner,
            Err(transport) => Err(LedgerError::Other(transport)),
        }
    }

    /// Current chain head hash (`"GENESIS"` while empty).
    pub fn head_hash(&self) -> Result<String, LedgerError> {
        match self.client.run(|conn| Ok::<_, String>(head_hash_conn(conn))) {
            Ok(inner) => inner,
            Err(transport) => Err(LedgerError::Other(transport)),
        }
    }

    /// Read the whole chain back, oldest first.
    pub fn read_all(&self) -> Result<Vec<EventEnvelope>, LedgerError> {
        match self.client.run(|conn| Ok::<_, String>(read_all_conn(conn))) {
            Ok(inner) => inner,
            Err(transport) => Err(LedgerError::Other(transport)),
        }
    }

    /// Cadence snapshots stored so far, oldest first (`seq_count ASC`).
    pub fn stored_snapshots(&self) -> Result<Vec<LedgerSnapshot>, LedgerError> {
        match self
            .client
            .run(|conn| Ok::<_, String>(stored_snapshots_conn(conn)))
        {
            Ok(inner) => inner,
            Err(transport) => Err(LedgerError::Other(transport)),
        }
    }

    /// Signal shutdown and join the coordinator thread.
    pub fn shutdown(&mut self) {
        self.coord.shutdown();
    }
}

impl Drop for CoordinatedLedger {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// The stable wire name for a kind, recorded in the `kind` column.
///
/// Delegates to [`EventKind::as_str`] — the single source of truth already
/// committed inside the envelope hash — so the DB can never disagree with the
/// chain about an event's kind.
fn kind_to_str(kind: EventKind) -> &'static str {
    kind.as_str()
}

/// Parse a `kind` column value back into an [`EventKind`].
///
/// Total over the canonical names produced by [`kind_to_str`]; anything else
/// is a corrupt/foreign row and surfaces as [`LedgerError::Other`] (never a
/// panic, never a guessed kind).
fn kind_from_str(s: &str) -> Result<EventKind, LedgerError> {
    match s {
        "plan" => Ok(EventKind::Plan),
        "fetch" => Ok(EventKind::Fetch),
        "parse" => Ok(EventKind::Parse),
        "graph" => Ok(EventKind::Graph),
        "grade" => Ok(EventKind::Grade),
        "artifact" => Ok(EventKind::Artifact),
        "agent_step" => Ok(EventKind::AgentStep),
        "verdict" => Ok(EventKind::Verdict),
        other => Err(LedgerError::Other(format!(
            "sqlite ledger: unknown event kind '{other}'"
        ))),
    }
}

/// Map any backend error into [`LedgerError::Other`] with operation context.
fn db_err(what: &str, e: rusqlite::Error) -> LedgerError {
    LedgerError::Other(format!("sqlite ledger: {what}: {e}"))
}

/// Shared append operation (used by [`SqliteLedger`] and
/// [`CoordinatedLedger`]): link check + insert in one transaction, plus the
/// cadence snapshot write when `snapshot_cadence > 0` and the new chain
/// length is a multiple of it.
fn append_conn(
    conn: &mut Connection,
    ev: &EventEnvelope,
    snapshot_cadence: usize,
) -> Result<(), LedgerError> {
    let tx = conn
        .transaction()
        .map_err(|e| db_err("begin append transaction", e))?;

    let head: Option<String> = tx
        .query_row(
            "SELECT hash FROM ledger_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| db_err("read head during append", e))?;
    let expected = head.unwrap_or_else(|| GENESIS.to_string());

    if ev.prev_hash != expected {
        // Dropping `tx` rolls back — the rejected event stores nothing.
        return Err(LedgerError::PrevHashMismatch {
            expected,
            got: ev.prev_hash.clone(),
        });
    }

    tx.execute(
        "INSERT INTO ledger_events (id, ts_ms, actor, run_id, kind, payload, prev_hash, hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            ev.id.as_str(),
            ev.ts_ms,
            ev.actor.as_str(),
            ev.run_id.as_str(),
            kind_to_str(ev.kind),
            ev.payload.as_str(),
            ev.prev_hash.as_str(),
            ev.hash.as_str(),
        ],
    )
    .map_err(|e| db_err(&format!("insert event '{}'", ev.id), e))?;

    // Snapshot cadence: checkpoint in the same transaction so a stored
    // snapshot can never disagree with the chain it summarizes.
    if snapshot_cadence > 0 {
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |r| r.get(0))
            .map_err(|e| db_err("count during append", e))?;
        if count % snapshot_cadence as i64 == 0 {
            tx.execute(
                "INSERT INTO ledger_snapshots (seq_count, head_hash, ts_ms) \
                 VALUES (?1, ?2, ?3)",
                params![count, ev.hash.as_str(), ev.ts_ms],
            )
            .map_err(|e| db_err("insert cadence snapshot", e))?;
        }
    }

    tx.commit()
        .map_err(|e| db_err("commit append transaction", e))?;
    Ok(())
}

/// Shared head read; `"GENESIS"` while empty.
fn head_hash_conn(conn: &Connection) -> Result<String, LedgerError> {
    let head: Option<String> = conn
        .query_row(
            "SELECT hash FROM ledger_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| db_err("read head", e))?;
    Ok(head.unwrap_or_else(|| GENESIS.to_string()))
}

/// Shared full-chain read, oldest first.
fn read_all_conn(conn: &Connection) -> Result<Vec<EventEnvelope>, LedgerError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, ts_ms, actor, run_id, kind, payload, prev_hash, hash \
             FROM ledger_events ORDER BY seq ASC",
        )
        .map_err(|e| db_err("prepare read_all", e))?;

    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        })
        .map_err(|e| db_err("query read_all", e))?;

    let mut out = Vec::new();
    for row in rows {
        let (id, ts_ms, actor, run_id, kind, payload, prev_hash, hash) =
            row.map_err(|e| db_err("read ledger row", e))?;
        out.push(EventEnvelope {
            id,
            ts_ms,
            actor,
            run_id,
            kind: kind_from_str(&kind)?,
            payload,
            prev_hash,
            hash,
        });
    }
    Ok(out)
}

/// Shared cadence-snapshot read, oldest first.
fn stored_snapshots_conn(conn: &Connection) -> Result<Vec<LedgerSnapshot>, LedgerError> {
    let mut stmt = conn
        .prepare(
            "SELECT seq_count, head_hash, ts_ms FROM ledger_snapshots ORDER BY seq_count ASC",
        )
        .map_err(|e| db_err("prepare stored_snapshots", e))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(LedgerSnapshot {
                count: r.get::<_, i64>(0)? as usize,
                head_hash: r.get::<_, String>(1)?,
                last_ts_ms: r.get::<_, i64>(2)?,
            })
        })
        .map_err(|e| db_err("query stored_snapshots", e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| db_err("read snapshot row", e))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_events::chain_next;

    /// Open a ledger on a fresh temp dir; the returned `TempDir` must stay
    /// alive so the database file outlives the ledger (and a reopen test can
    /// point at the same path).
    fn open_tmp() -> (tempfile::TempDir, SqliteLedger) {
        let dir = tempfile::tempdir().unwrap();
        let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).unwrap();
        (dir, ledger)
    }

    /// Build a clean, `chain_next`-linked chain of `n` events (no storage).
    fn chain_of(n: usize) -> Vec<EventEnvelope> {
        let mut events: Vec<EventEnvelope> = Vec::new();
        for i in 0..n {
            let kind = match i % 8 {
                0 => EventKind::Plan,
                1 => EventKind::Fetch,
                2 => EventKind::Parse,
                3 => EventKind::Graph,
                4 => EventKind::Grade,
                5 => EventKind::Artifact,
                6 => EventKind::AgentStep,
                _ => EventKind::Verdict,
            };
            let ev = chain_next(
                events.last(),
                kind,
                "agent:test",
                "run-1",
                &format!("{{\"i\":{i}}}"),
            );
            events.push(ev);
        }
        events
    }

    #[test]
    fn fresh_db_is_empty_and_accepts_genesis() {
        let (_dir, mut ledger) = open_tmp();
        assert!(ledger.read_all().unwrap().is_empty());
        assert_eq!(ledger.head_hash().unwrap(), "GENESIS");

        // The first append must link to GENESIS and then become the head.
        let first = chain_next(None, EventKind::Plan, "parent", "run-1", "{\"a\":1}");
        let first_hash = first.hash.clone();
        ledger.append(&first).unwrap();
        assert_eq!(ledger.read_all().unwrap().len(), 1);
        assert_eq!(ledger.head_hash().unwrap(), first_hash);
    }

    #[test]
    fn append_three_event_chain_round_trips() {
        let (_dir, mut ledger) = open_tmp();
        let events = chain_of(3);
        for ev in &events {
            ledger.append(ev).unwrap();
        }

        let all = ledger.read_all().unwrap();
        assert_eq!(all.len(), 3);
        // Order and linkage are preserved byte-for-byte.
        for (stored, original) in all.iter().zip(events.iter()) {
            assert_eq!(stored.hash, original.hash);
            assert_eq!(stored.prev_hash, original.prev_hash);
            assert_eq!(stored.ts_ms, original.ts_ms);
            assert_eq!(stored.id, original.id);
        }
        assert_eq!(all[0].prev_hash, "GENESIS");
        assert_eq!(all[1].prev_hash, events[0].hash);
        assert_eq!(all[2].prev_hash, events[1].hash);
        assert_eq!(ledger.head_hash().unwrap(), events[2].hash);
    }

    #[test]
    fn read_all_round_trips_kind_and_all_fields() {
        let (_dir, mut ledger) = open_tmp();
        let events = chain_of(3);
        for ev in &events {
            ledger.append(ev).unwrap();
        }

        let all = ledger.read_all().unwrap();
        assert_eq!(
            all.iter().map(|e| e.kind).collect::<Vec<_>>(),
            vec![EventKind::Plan, EventKind::Fetch, EventKind::Parse]
        );

        // Full envelope equality (covers kind + every other column).
        for (stored, original) in all.iter().zip(events.iter()) {
            assert_eq!(stored, original);
        }
    }

    #[test]
    fn append_rejects_wrong_prev_hash() {
        let (_dir, mut ledger) = open_tmp();

        // Genesis case: a wrong prev_hash on the empty ledger.
        let mut bad = chain_next(None, EventKind::Plan, "agent:test", "run-1", "{\"a\":1}");
        bad.prev_hash = "not-genesis".to_string();
        match ledger.append(&bad) {
            Err(LedgerError::PrevHashMismatch { expected, got }) => {
                assert_eq!(expected, "GENESIS");
                assert_eq!(got, "not-genesis");
            }
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        assert!(ledger.read_all().unwrap().is_empty(), "rejected event must not be stored");

        // Mid-chain case: stale (genesis) prev_hash against a non-empty head.
        events_append(&mut ledger, 2);
        let head_before = ledger.head_hash().unwrap();
        let mut stale = chain_next(None, EventKind::Fetch, "agent:test", "run-1", "{\"b\":2}");
        stale.prev_hash = "GENESIS".to_string();
        match ledger.append(&stale) {
            Err(LedgerError::PrevHashMismatch { expected, got }) => {
                assert_eq!(expected, head_before);
                assert_eq!(got, "GENESIS");
            }
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        let all = ledger.read_all().unwrap();
        assert_eq!(all.len(), 2, "rejected event must not be stored");
        assert_eq!(ledger.head_hash().unwrap(), head_before);
    }

    #[test]
    fn reopen_persists_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ledger.sqlite");
        let events = chain_of(3);

        {
            let mut ledger = SqliteLedger::open(&db).unwrap();
            for ev in &events {
                ledger.append(ev).unwrap();
            }
        } // connection closed (drop)

        let mut reopened = SqliteLedger::open(&db).unwrap();
        let all = reopened.read_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[2].hash, events[2].hash);
        assert_eq!(reopened.head_hash().unwrap(), events[2].hash);

        // The reopened ledger continues the same chain: a stale prev_hash is
        // rejected against the persisted head, a correct one is accepted.
        let mut cont = chain_next(all.last(), EventKind::Verdict, "agent:test", "run-1", "{\"c\":3}");
        let mut stale = cont.clone();
        stale.prev_hash = "GENESIS".to_string();
        assert!(matches!(
            reopened.append(&stale),
            Err(LedgerError::PrevHashMismatch { .. })
        ));
        cont.prev_hash = all[2].hash.clone();
        reopened.append(&cont).unwrap();
        assert_eq!(reopened.read_all().unwrap().len(), 4);
    }

    #[test]
    fn duplicate_id_is_error_not_panic() {
        let (_dir, mut ledger) = open_tmp();
        let events = chain_of(1);
        ledger.append(&events[0]).unwrap();

        // A correctly-linked event that reuses the stored uuid must be
        // rejected by the UNIQUE(id) constraint — as an error, not a panic.
        let mut dup = chain_next(events.last(), EventKind::Fetch, "agent:test", "run-1", "{\"d\":4}");
        dup.id = events[0].id.clone();
        match ledger.append(&dup) {
            Err(LedgerError::Other(msg)) => {
                assert!(msg.contains("insert event"), "context in error: {msg}");
            }
            other => panic!("expected LedgerError::Other for duplicate id, got {other:?}"),
        }
        // The failed insert left the chain exactly as it was.
        assert_eq!(ledger.read_all().unwrap().len(), 1);
        assert_eq!(ledger.head_hash().unwrap(), events[0].hash);
    }

    #[test]
    fn unknown_kind_in_db_is_error_not_panic() {
        let (_dir, ledger) = open_tmp();
        ledger
            .conn
            .execute(
                "INSERT INTO ledger_events (id, ts_ms, actor, run_id, kind, payload, prev_hash, hash) \
                 VALUES ('x', 0, 'a', 'r', 'bogus', '{}', 'GENESIS', 'h')",
                [],
            )
            .unwrap();
        match ledger.read_all() {
            Err(LedgerError::Other(msg)) => {
                assert!(msg.contains("unknown event kind"), "got: {msg}");
            }
            other => panic!("expected Other for unknown kind, got {other:?}"),
        }
    }

    // ── test helpers ─────────────────────────────────────────────────────────

    /// Append the first `n` events of a fresh clean chain, returning them.
    fn events_append(ledger: &mut SqliteLedger, n: usize) -> Vec<EventEnvelope> {
        let events = chain_of(n);
        for ev in &events {
            ledger.append(ev).unwrap();
        }
        events
    }

    // ── CoordinatedLedger (A1.1.2 StoreCoordinator wiring) ─────────────────

    fn spawn_coordinated(cadence: usize) -> (tempfile::TempDir, CoordinatedLedger) {
        let dir = tempfile::tempdir().unwrap();
        let ledger =
            CoordinatedLedger::spawn(dir.path().join("coordinated.sqlite"), cadence).unwrap();
        (dir, ledger)
    }

    #[test]
    fn coordinated_append_chain_round_trips() {
        let (_dir, ledger) = spawn_coordinated(0);
        assert_eq!(ledger.head_hash().unwrap(), "GENESIS");
        let events = chain_of(4);
        for ev in &events {
            ledger.append(ev).unwrap();
        }
        assert_eq!(ledger.head_hash().unwrap(), events.last().unwrap().hash);
        assert_eq!(ledger.read_all().unwrap(), events);
    }

    #[test]
    fn coordinated_rejects_wrong_prev_hash_without_writing() {
        let (_dir, ledger) = spawn_coordinated(0);
        let mut first = chain_of(1);
        let good = first.remove(0);
        ledger.append(&good).unwrap();

        // A non-linking event (built from None) must be refused and store
        // nothing; the structured error survives the coordinator hop.
        let bad = chain_next(None, EventKind::Fetch, "agent:test", "run-1", "{}");
        match ledger.append(&bad) {
            Err(LedgerError::PrevHashMismatch { expected, got }) => {
                assert_eq!(expected, good.hash);
                assert_eq!(got, "GENESIS");
            }
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        assert_eq!(ledger.read_all().unwrap().len(), 1);
    }

    #[test]
    fn coordinated_snapshot_cadence_lands_on_multiples() {
        let (_dir, ledger) = spawn_coordinated(2);
        let events = chain_of(5);
        for ev in &events {
            ledger.append(ev).unwrap();
        }
        let snaps = ledger.stored_snapshots().unwrap();
        assert_eq!(snaps.len(), 2, "5 appends at cadence 2 ⇒ after #2 and #4");
        assert_eq!(snaps[0].count, 2);
        assert_eq!(snaps[0].head_hash, events[1].hash);
        assert_eq!(snaps[1].count, 4);
        assert_eq!(snaps[1].head_hash, events[3].hash);
        assert_eq!(snaps[1].last_ts_ms, events[3].ts_ms);
    }

    #[test]
    fn coordinated_state_visible_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reopen.sqlite");
        {
            let ledger = CoordinatedLedger::spawn(&path, 1).unwrap();
            for ev in &chain_of(3) {
                ledger.append(ev).unwrap();
            }
            assert_eq!(ledger.stored_snapshots().unwrap().len(), 3);
        }
        let ledger = CoordinatedLedger::spawn(&path, 1).unwrap();
        assert_eq!(ledger.read_all().unwrap().len(), 3);
        assert_eq!(ledger.stored_snapshots().unwrap().len(), 3);
    }
}
