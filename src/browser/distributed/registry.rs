//! Distributed session registry with TTL-based expiration.
//!
//! Maps external session IDs to their owning node and internal session,
//! with automatic expiration and garbage collection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// A single session entry tracking which node owns a browser session.
#[derive(Clone, Debug)]
pub struct SessionEntry {
    /// The node that owns this session.
    pub node_id: String,
    /// The node-local session identifier.
    pub internal_session_id: String,
    /// When the session was first registered.
    pub created_at: Instant,
    /// When the last command was sent to this session.
    pub last_command: Instant,
    /// Time-to-live: session expires if idle longer than this.
    pub ttl: Duration,
}

impl SessionEntry {
    /// Returns `true` if the session has exceeded its TTL since the last command.
    pub fn is_expired(&self) -> bool {
        self.last_command.elapsed() > self.ttl
    }

    /// Update `last_command` to the current instant (keep-alive).
    pub fn touch(&mut self) {
        self.last_command = Instant::now();
    }
}

/// Thread-safe registry mapping external session IDs to [`SessionEntry`] values.
///
/// Sessions are automatically removed on lookup if expired, and can be
/// bulk-cleaned via [`gc`](SessionRegistry::gc).
#[derive(Clone)]
pub struct SessionRegistry {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    default_ttl: Duration,
}

impl SessionRegistry {
    /// Create a new registry with the given default TTL for sessions.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Register a new session mapping.
    pub async fn register(
        &self,
        session_id: String,
        node_id: String,
        internal_session_id: String,
    ) {
        let now = Instant::now();
        let entry = SessionEntry {
            node_id,
            internal_session_id,
            created_at: now,
            last_command: now,
            ttl: self.default_ttl,
        };
        self.sessions.lock().await.insert(session_id, entry);
    }

    /// Look up a session by its external ID.
    ///
    /// Returns `None` if the session does not exist or has expired.
    /// Expired sessions are removed on access. Active sessions are touched.
    pub async fn lookup(&self, session_id: &str) -> Option<SessionEntry> {
        let mut sessions = self.sessions.lock().await;
        let entry = sessions.get(session_id)?;
        if entry.is_expired() {
            sessions.remove(session_id);
            return None;
        }
        let entry = sessions.get_mut(session_id).unwrap();
        entry.touch();
        Some(entry.clone())
    }

    /// Remove a session by its external ID.
    pub async fn remove(&self, session_id: &str) {
        self.sessions.lock().await.remove(session_id);
    }

    /// Garbage-collect all expired sessions. Returns the number removed.
    pub async fn gc(&self) -> usize {
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|_, entry| !entry.is_expired());
        before - sessions.len()
    }

    /// Return the number of currently registered (not necessarily live) sessions.
    pub async fn count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Return all external session IDs owned by the given node.
    pub async fn sessions_for_node(&self, node_id: &str) -> Vec<String> {
        self.sessions
            .lock()
            .await
            .iter()
            .filter(|(_, entry)| entry.node_id == node_id)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn register_and_lookup() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        reg.register(
            "ext-1".into(),
            "node-a".into(),
            "internal-42".into(),
        )
        .await;

        let entry = reg.lookup("ext-1").await.expect("should exist");
        assert_eq!(entry.node_id, "node-a");
        assert_eq!(entry.internal_session_id, "internal-42");
    }

    #[tokio::test]
    async fn lookup_missing_returns_none() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        assert!(reg.lookup("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn remove_session() {
        let reg = SessionRegistry::new(Duration::from_secs(60));
        reg.register("ext-1".into(), "node-a".into(), "int-1".into())
            .await;
        assert_eq!(reg.count().await, 1);

        reg.remove("ext-1").await;
        assert_eq!(reg.count().await, 0);
        assert!(reg.lookup("ext-1").await.is_none());
    }

    #[tokio::test]
    async fn expired_session_returns_none() {
        let reg = SessionRegistry::new(Duration::from_millis(1));
        reg.register("ext-1".into(), "node-a".into(), "int-1".into())
            .await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(reg.lookup("ext-1").await.is_none());
        // Expired entry should have been removed by lookup
        assert_eq!(reg.count().await, 0);
    }

    #[tokio::test]
    async fn gc_removes_expired() {
        let reg = SessionRegistry::new(Duration::from_millis(1));
        reg.register("ext-1".into(), "node-a".into(), "int-1".into())
            .await;
        reg.register("ext-2".into(), "node-b".into(), "int-2".into())
            .await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let removed = reg.gc().await;
        assert_eq!(removed, 2);
        assert_eq!(reg.count().await, 0);
    }
}
