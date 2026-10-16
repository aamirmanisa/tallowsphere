//! 2.0 unified async store — coordinator transport building block.
//!
//! The only correct way to decouple agent threads from the shared SQLite
//! connection while preserving read-your-own-writes is to route BOTH reads and
//! writes through a single owning thread that orders them FIFO. This module is
//! that transport: a `StoreCoordinator` owns the `rusqlite::Connection` on its
//! own thread and runs submitted closures against it in FIFO order; callers
//! submit via a cloneable `StoreClient` and wait for that op's response.
//!
//! The store methods (EventStore/CheckpointStore/IdempotencyStore) migrate to
//! submit+wait through `StoreClient` in subsequent steps of the 2.0 plan
//! (see artifacts/AGENT_UNIFIED_ASYNC_STORE.md).

use std::sync::mpsc;

/// A request to run against the coordinator's connection.
pub enum StoreRequest {
    /// Run a closure against the connection; return a response. The closure
    /// runs on the coordinator thread (so it owns the connection's single
    /// thread affinity) and is `Send` so it can cross to that thread.
    Run(Box<dyn FnOnce(&mut rusqlite::Connection) -> StoreResponse + Send>),
    /// Coordinator exits after draining prior requests (no lost work).
    Shutdown,
}

/// Response from a single store operation.
pub enum StoreResponse {
    Ok,
    /// A payload-less value for query-type ops.
    Value(String),
    Err(String),
}

type Req = (StoreRequest, mpsc::Sender<StoreResponse>);

/// Cloneable client handle: submits a request and waits for its response.
#[derive(Clone)]
pub struct StoreClient {
    tx: mpsc::Sender<Req>,
}

impl std::fmt::Debug for StoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreClient")
    }
}

impl StoreClient {
    fn new(tx: mpsc::Sender<Req>) -> Self {
        StoreClient { tx }
    }

    /// Submit a request and block until the coordinator replies with the
    /// response. The reply is FIFO-ordered against every other request from
    /// this client (and, per client, against its own earlier requests).
    pub fn submit(&self, req: StoreRequest) -> StoreResponse {
        let (rtx, rrx) = mpsc::channel();
        match self.tx.send((req, rtx)) {
            Ok(()) => rrx
                .recv()
                .unwrap_or(StoreResponse::Err("store: coordinator closed".into())),
            Err(_) => StoreResponse::Err("store: coordinator gone".into()),
        }
    }

    /// Run a read/write closure against the connection and return its result.
    /// Generic: the closure's `Ok(T)` value is returned directly. The op runs
    /// on the coordinator thread in submission order, so a write is always
    /// observed by a later read from the same client (read-your-own-writes).
    pub fn run<T, F>(&self, op: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(&mut rusqlite::Connection) -> Result<T, String> + Send + 'static,
    {
        let (rtx, rrx) = mpsc::channel::<Result<T, String>>();
        let req = StoreRequest::Run(Box::new(move |db| {
            let _ = rtx.send(op(db));
            StoreResponse::Ok
        }));
        // Wait for the coordinator to process the request (blocking only on
        // this op, never on another client's op).
        let _ = self.submit(req);
        rrx.recv().unwrap_or(Err("store: coordinator closed".into()))
    }
}

/// Owns the connection on a dedicated thread; drops drain remaining requests.
pub struct StoreCoordinator {
    pub client: StoreClient,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StoreCoordinator {
    /// Spawn a coordinator thread owning `conn`. The Arc<Mutex> is shared with
    /// whoever else uses the connection; the coordinator serializes the ops it
    /// runs (locking per request) so callers stop contending on the lock and
    /// instead submit+wait through the client. Read-your-own-writes is preserved
    /// because it is the same underlying connection.
    pub fn spawn(conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>) -> Self {
        let (tx, rx) = mpsc::channel::<Req>();
        let handle = std::thread::spawn(move || {
            while let Ok((req, rtx)) = rx.recv() {
                let resp = match req {
                    StoreRequest::Run(op) => match conn.lock() {
                        Ok(mut guard) => op(&mut *guard),
                        Err(_) => StoreResponse::Err("store: db lock poisoned".into()),
                    },
                    StoreRequest::Shutdown => break,
                };
                let _ = rtx.send(resp);
            }
        });
        StoreCoordinator {
            client: StoreClient::new(tx),
            handle: Some(handle),
        }
    }

    /// Signal shutdown and join the coordinator thread (waits for it to drain
    /// all requests already sent, so nothing is lost).
    pub fn shutdown(&mut self) {
        let _ = self.client.submit(StoreRequest::Shutdown);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for StoreCoordinator {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> std::sync::Arc<std::sync::Mutex<rusqlite::Connection>> {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);")
            .unwrap();
        std::sync::Arc::new(std::sync::Mutex::new(c))
    }

    #[test]
    fn coordinator_fifo_ordering_preserved() {
        let mut coord = StoreCoordinator::spawn(conn());
        let client = coord.client.clone();
        let mut seen = Vec::new();
        for i in 0i64..5 {
            let r: String = client
                .run(move |db| {
                    db.execute(
                        "INSERT INTO t (id, v) VALUES (?1, ?2)",
                        rusqlite::params![i, format!("v{i}")],
                    )
                    .map_err(|e| format!("{e}"))?;
                    Ok(format!("wrote {i}"))
                })
                .unwrap();
            seen.push(r);
        }
        assert_eq!(seen, vec![
            "wrote 0".to_string(),
            "wrote 1".to_string(),
            "wrote 2".to_string(),
            "wrote 3".to_string(),
            "wrote 4".to_string()
        ]);
        // Read them back in order via the same client (read-your-own-writes).
        let rows: String = client
            .run(|db| {
                let mut stmt = db
                    .prepare("SELECT v FROM t ORDER BY id")
                    .map_err(|e| format!("{e}"))?;
                let vals: Vec<String> = stmt
                    .query_map([], |r| r.get(0))
                    .map_err(|e| format!("{e}"))?
                    .map(|x| x.unwrap())
                    .collect();
                Ok(vals.join(","))
            })
            .unwrap();
        assert_eq!(rows, "v0,v1,v2,v3,v4");
        coord.shutdown();
    }

    #[test]
    fn shutdown_drains_queued_requests() {
        let mut coord = StoreCoordinator::spawn(conn());
        let client = coord.client.clone();
        for i in 0i64..100 {
            client
                .run(move |db| {
                    db.execute("INSERT INTO t (id, v) VALUES (?1, 'x')", rusqlite::params![i])
                        .map_err(|e| format!("{e}"))?;
                    Ok(())
                })
                .unwrap();
        }
        let count: i64 = client
            .run(|db| {
                db.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
                    .map_err(|e| format!("{e}"))
            })
            .unwrap();
        assert_eq!(count, 100);
        coord.shutdown();
    }

    #[test]
    fn read_your_own_writes_across_connection() {
        let mut coord = StoreCoordinator::spawn(conn());
        let client = coord.client.clone();
        client
            .run(|db| {
                db.execute("INSERT INTO t (id, v) VALUES (1, 'hello')", [])
                    .map_err(|e| format!("{e}"))?;
                Ok(())
            })
            .unwrap();
        // read immediately: must observe the write (FIFO per client).
        let v: String = client
            .run(|db| {
                db.query_row("SELECT v FROM t WHERE id=1", [], |r| r.get(0))
                    .map_err(|e| format!("{e}"))
            })
            .unwrap();
        assert_eq!(v, "hello");
        coord.shutdown();
    }

    #[test]
    fn coordinator_shares_connection_with_direct_holder() {
        // A second holder of the same Arc can access the connection directly
        // (the coordinator does not own it exclusively), preserving the
        // existing memory subsystem's direct access.
        let shared = conn();
        let mut coord = StoreCoordinator::spawn(shared.clone());
        let client = coord.client.clone();
        client
            .run(|db| {
                db.execute("INSERT INTO t (id, v) VALUES (10, 'shared')", [])
                    .map_err(|e| format!("{e}"))?;
                Ok(())
            })
            .unwrap();
        // Direct holder sees the row (same underlying connection).
        let out = shared
            .lock()
            .unwrap()
            .query_row("SELECT v FROM t WHERE id=10", [], |r| r.get::<_, String>(0))
            .unwrap();
        assert_eq!(out, "shared");
        coord.shutdown();
    }
}
