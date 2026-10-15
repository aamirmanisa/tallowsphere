//! Sentinel heartbeat / lease lifecycle — the sentinel presence model
//! (frozen interface B11 §2, B3.3.1–B3.3.3).
//!
//! A **sentinel** is a named watcher whose *presence* is asserted by a
//! renewable [`Lease`] plus a stream of heartbeats. Two independent signals
//! make the model honest:
//!
//! - the **lease** says who currently owns the sentinel identity (`holder`)
//!   and until when (`acquired_ms + ttl_ms`), so two operators cannot both
//!   believe they own the same watcher;
//! - the **heartbeats** are the liveness evidence: a sentinel that stops
//!   answering is not silently dead, it loses its lease and falls to
//!   [`SentinelState::Suspended`] — *resumable*, keeping its identity,
//!   counters and history.
//!
//! Lifecycle (frozen B3.3.1–B3.3.3):
//!
//! - [`SentinelManager::register`] ⇒ `Starting` (no lease yet);
//! - [`SentinelManager::start`] from `Starting | Suspended` ⇒ `Running` with
//!   a fresh lease `(holder, now, ttl)`;
//! - [`SentinelManager::heartbeat`] (Running only): `heartbeats += 1`,
//!   `last_heartbeat_ms = now`; a lease that has expired by `now` ⇒ state
//!   `Suspended` + `Err(LeaseExpired)` (the expiry verdict is still
//!   recorded), otherwise the lease is renewed to `now`;
//! - [`SentinelManager::suspend`] from `Running` ⇒ `Suspended`, lease
//!   cleared;
//! - [`SentinelManager::stop`] from any non-`Stopped` state ⇒ `Stopped`
//!   (terminal), lease cleared;
//! - [`SentinelManager::restart`] from `Suspended | Stopped` ⇒ `Starting`,
//!   `restarts += 1`;
//! - [`SentinelManager::stale`] lists the forgotten middle ground: sentinels
//!   still `Running` whose lease has silently lapsed.
//!
//! Why `Suspended` instead of dead on expiry: a lapsed lease is usually a
//! lost operator or a broken link, not a reason to destroy state. Suspension
//! is the resumable middle rung; only [`SentinelManager::stop`] is terminal,
//! and even it can be revived by `restart` (the state machine view) — the
//! *operator* may declare a sentinel dead, the *clock alone* may not.
//!
//! Invariants (enforced by the private `Vec<Sentinel>`; unrepresentable from
//! outside the module):
//!
//! - `lease.is_some()` **iff** `state == Running` — every transition into
//!   `Running` installs a lease, every transition out of `Running` clears it;
//! - ids are `sn-<seq:03>`, `seq` = registration order starting at 1;
//! - every method is a pure function of its arguments and the stored state
//!   (no clock reads, no randomness), so a scripted call sequence replays
//!   identically.
//!
//! Wire form: the frozen §2 leaves serde at the default (variant names —
//! `"Running"`, …; unlike §1/§3 which pin `snake_case` explicitly).
//! [`SentinelError`] derives `Serialize` only: its `BadInput(&'static str)`
//! payload cannot be derive-`Deserialize`d into a `'static` lifetime (repo
//! precedent: `clearness_gate`, `unknowns`, `mode_diversity`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Lifecycle state of a sentinel (frozen B3.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SentinelState {
    /// Registered, no lease yet — waiting for its first `start`.
    Starting,
    /// Leased and heartbeating: presence asserted.
    Running,
    /// Presence lost — lease lapsed (heartbeat expiry) or operator
    /// suspension. Resumable via `start` or `restart`.
    Suspended,
    /// Terminal — only `restart` may revive it.
    Stopped,
}

impl SentinelState {
    /// True iff the sentinel is expected to be heartbeating (`Running`).
    /// Additive helper; the frozen §2 lists no methods on this enum.
    pub const fn is_active(self) -> bool {
        matches!(self, SentinelState::Running)
    }

    /// True iff the state is terminal (`Stopped`) — reachable only via
    /// `stop`, excepted only by `restart`. Additive helper.
    pub const fn is_terminal(self) -> bool {
        matches!(self, SentinelState::Stopped)
    }
}

/// A presence lease: `holder` owns the sentinel identity for `ttl_ms`
/// starting at `acquired_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// Who holds the lease (the operator asserting presence).
    pub holder: String,
    /// Instant the current TTL window started (renewal moves this).
    pub acquired_ms: i64,
    /// Time-to-live of the lease window (ms); positive for leases created
    /// through the manager (`start` rejects `ttl_ms <= 0`).
    pub ttl_ms: i64,
}

impl Lease {
    /// Expired iff `now >= acquired_ms + ttl_ms` (frozen boundary: the exact
    /// instant `acquired + ttl` is already expired — half-open window
    /// `[acquired, acquired + ttl)`). The addition saturates, so an extreme
    /// `acquired_ms` near [`i64::MAX`] cannot wrap into a stale "never
    /// expires" region.
    pub fn expired(&self, now_ms: i64) -> bool {
        now_ms >= self.acquired_ms.saturating_add(self.ttl_ms)
    }

    /// Renew the lease at `now_ms`: the TTL window restarts (`acquired_ms =
    /// now_ms`); the holder is unchanged.
    pub fn renew(&mut self, now_ms: i64) {
        self.acquired_ms = now_ms;
    }
}

/// A registered sentinel (frozen B3.3.1). The manager is the only writer;
/// the fields are public for read-side consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sentinel {
    /// Stable id, `sn-<seq:03>` (registration order, 1-based).
    pub id: String,
    /// Operator-facing name.
    pub name: String,
    /// Lifecycle state.
    pub state: SentinelState,
    /// Current lease; `Some` iff `state == Running`.
    pub lease: Option<Lease>,
    /// Cumulative heartbeat count (never reset, including across restarts).
    pub heartbeats: u64,
    /// Instant of the last heartbeat (`None` before the first one).
    pub last_heartbeat_ms: Option<i64>,
    /// Cumulative successful restarts (never reset).
    pub restarts: u32,
}

/// Read-side projection of a sentinel (frozen B3.3.2) — the operator-visible
/// surface: what a monitoring view may show without handing out the mutable
/// manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelView {
    /// Lifecycle state.
    pub state: SentinelState,
    /// Cumulative heartbeat count.
    pub heartbeats: u64,
    /// Instant of the last heartbeat.
    pub last_heartbeat_ms: Option<i64>,
    /// Cumulative restart count.
    pub restarts: u32,
    /// Holder of the current lease (`None` unless `Running`).
    pub lease_holder: Option<String>,
}

/// The sentinel registry and its lifecycle operations (frozen B3.3.1–B3.3.3).
///
/// The registry is private: sentinel state can only move through the methods
/// below, which keeps the `lease.is_some() ⟺ Running` invariant airtight.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SentinelManager {
    sentinels: Vec<Sentinel>,
}

impl SentinelManager {
    /// An empty registry. Additive helper (the field list is private, so
    /// this is the only way to construct a manager).
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered sentinels. Additive helper.
    pub fn len(&self) -> usize {
        self.sentinels.len()
    }

    /// Index of `id`, or [`SentinelError::UnknownSentinel`].
    fn index_of(&self, id: &str) -> Result<usize, SentinelError> {
        self.sentinels
            .iter()
            .position(|s| s.id == id)
            .ok_or(SentinelError::UnknownSentinel)
    }

    /// Register a sentinel: state `Starting`, no lease, zero counters; id
    /// `sn-<seq:03>` with `seq` = registration order (a failed registration
    /// consumes no id).
    ///
    /// Errors: empty `name` ⇒ [`SentinelError::BadInput`]`("name")`.
    pub fn register(&mut self, name: &str, now_ms: i64) -> Result<&Sentinel, SentinelError> {
        if name.is_empty() {
            return Err(SentinelError::BadInput("name"));
        }
        // `now_ms` is part of the frozen signature; a sentinel is born with
        // no lease, so there is no time-based state to record at this step.
        let _ = now_ms;
        let id = format!("sn-{:03}", self.sentinels.len() + 1);
        self.sentinels.push(Sentinel {
            id,
            name: name.to_string(),
            state: SentinelState::Starting,
            lease: None,
            heartbeats: 0,
            last_heartbeat_ms: None,
            restarts: 0,
        });
        Ok(self.sentinels.last().expect("just pushed"))
    }

    /// Start (or resume) a sentinel: `Starting | Suspended` ⇒ `Running` with
    /// a fresh lease `(holder, now_ms, ttl_ms)`.
    ///
    /// Errors, in check order (pinned; the frozen §2 does not order them):
    /// unknown id ⇒ [`SentinelError::UnknownSentinel`]; empty `holder` ⇒
    /// `BadInput("holder")`; `ttl_ms <= 0` ⇒ `BadInput("ttl_ms")`; any other
    /// state (`Running`, `Stopped`) ⇒ [`SentinelError::BadTransition`].
    pub fn start(
        &mut self,
        id: &str,
        holder: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<(), SentinelError> {
        let idx = self.index_of(id)?;
        if holder.is_empty() {
            return Err(SentinelError::BadInput("holder"));
        }
        if ttl_ms <= 0 {
            return Err(SentinelError::BadInput("ttl_ms"));
        }
        let sentinel = &mut self.sentinels[idx];
        match sentinel.state {
            SentinelState::Starting | SentinelState::Suspended => {}
            _ => return Err(SentinelError::BadTransition),
        }
        sentinel.state = SentinelState::Running;
        sentinel.lease = Some(Lease {
            holder: holder.to_string(),
            acquired_ms: now_ms,
            ttl_ms,
        });
        Ok(())
    }

    /// Record a heartbeat (`Running` only): `heartbeats += 1` and
    /// `last_heartbeat_ms = now_ms` happen **before** the lease check, so a
    /// heartbeat that exposes an expired lease still counts as evidence the
    /// sentinel spoke.
    ///
    /// If the lease has expired by `now_ms` the sentinel drops to
    /// `Suspended` (resumable), its dead lease is cleared, and the call
    /// returns [`SentinelError::LeaseExpired`]. Otherwise the lease is
    /// renewed to `now_ms`.
    ///
    /// Errors: unknown id ⇒ `UnknownSentinel`; non-`Running` ⇒
    /// `BadTransition`; lapsed lease ⇒ `LeaseExpired` (state is moved —
    /// the error reports the verdict, it is not a no-op).
    pub fn heartbeat(&mut self, id: &str, now_ms: i64) -> Result<(), SentinelError> {
        let idx = self.index_of(id)?;
        let sentinel = &mut self.sentinels[idx];
        if sentinel.state != SentinelState::Running {
            return Err(SentinelError::BadTransition);
        }
        sentinel.heartbeats += 1;
        sentinel.last_heartbeat_ms = Some(now_ms);
        // `Running` implies `lease.is_some()` by the module invariant; the
        // `None` fallback is defensive only (fail-safe: treat a missing
        // lease as lapsed rather than running unleased).
        let lease_expired = sentinel
            .lease
            .as_ref()
            .map_or(true, |lease| lease.expired(now_ms));
        if lease_expired {
            sentinel.state = SentinelState::Suspended;
            sentinel.lease = None;
            return Err(SentinelError::LeaseExpired);
        }
        if let Some(lease) = sentinel.lease.as_mut() {
            lease.renew(now_ms);
        }
        Ok(())
    }

    /// Suspend a running sentinel: `Running` ⇒ `Suspended`, lease cleared
    /// (a suspended watcher holds no lease; resumption re-leases).
    ///
    /// Errors: unknown id ⇒ `UnknownSentinel`; any state other than
    /// `Running` ⇒ `BadTransition`.
    pub fn suspend(&mut self, id: &str, now_ms: i64) -> Result<(), SentinelError> {
        let idx = self.index_of(id)?;
        // `now_ms` is part of the frozen signature; suspension records no
        // timestamp (no such field exists on `Sentinel`).
        let _ = now_ms;
        let sentinel = &mut self.sentinels[idx];
        if sentinel.state != SentinelState::Running {
            return Err(SentinelError::BadTransition);
        }
        sentinel.state = SentinelState::Suspended;
        sentinel.lease = None;
        Ok(())
    }

    /// Stop a sentinel: any state except `Stopped` ⇒ `Stopped` (terminal),
    /// lease cleared. Only `restart` may leave `Stopped`.
    ///
    /// Errors: unknown id ⇒ `UnknownSentinel`; already `Stopped` ⇒
    /// `BadTransition` (the terminal state is not re-enterable).
    pub fn stop(&mut self, id: &str, now_ms: i64) -> Result<(), SentinelError> {
        let idx = self.index_of(id)?;
        // `now_ms` is part of the frozen signature; stopping records no
        // timestamp.
        let _ = now_ms;
        let sentinel = &mut self.sentinels[idx];
        if sentinel.state == SentinelState::Stopped {
            return Err(SentinelError::BadTransition);
        }
        sentinel.state = SentinelState::Stopped;
        sentinel.lease = None;
        Ok(())
    }

    /// Restart a sentinel: `Suspended | Stopped` ⇒ `Starting`,
    /// `restarts += 1`. Counters (`heartbeats`, `last_heartbeat_ms`,
    /// `restarts`) and identity are preserved — a restart is a new lease
    /// cycle, not a new sentinel.
    ///
    /// Errors: unknown id ⇒ `UnknownSentinel`; `Running` or `Starting` ⇒
    /// `BadTransition` (a live sentinel is suspended first; a `Starting` one
    /// is simply started).
    pub fn restart(&mut self, id: &str, now_ms: i64) -> Result<(), SentinelError> {
        let idx = self.index_of(id)?;
        // `now_ms` is part of the frozen signature; restart records no
        // timestamp (the new lease is created by `start`).
        let _ = now_ms;
        let sentinel = &mut self.sentinels[idx];
        match sentinel.state {
            SentinelState::Suspended | SentinelState::Stopped => {}
            _ => return Err(SentinelError::BadTransition),
        }
        sentinel.state = SentinelState::Starting;
        sentinel.restarts += 1;
        Ok(())
    }

    /// Read-side projection of one sentinel (B3.3.2). Unknown id ⇒
    /// `UnknownSentinel`.
    pub fn view(&self, id: &str) -> Result<SentinelView, SentinelError> {
        let sentinel = &self.sentinels[self.index_of(id)?];
        Ok(SentinelView {
            state: sentinel.state,
            heartbeats: sentinel.heartbeats,
            last_heartbeat_ms: sentinel.last_heartbeat_ms,
            restarts: sentinel.restarts,
            lease_holder: sentinel.lease.as_ref().map(|lease| lease.holder.clone()),
        })
    }

    /// The forgotten middle ground (B3.3.3): sentinels still `Running` whose
    /// lease has lapsed by `now_ms` — nobody has heartbeated them since the
    /// lease died, so they are silently unowned. Sorted by id.
    ///
    /// `Suspended`/`Stopped` sentinels are not stale (their state already
    /// says so), and a renewed lease keeps its sentinel off this list.
    pub fn stale(&self, now_ms: i64) -> Vec<&Sentinel> {
        let mut stale: Vec<&Sentinel> = self
            .sentinels
            .iter()
            .filter(|s| {
                s.state == SentinelState::Running
                    && s.lease
                        .as_ref()
                        .is_some_and(|lease| lease.expired(now_ms))
            })
            .collect();
        stale.sort_by(|a, b| a.id.cmp(&b.id));
        stale
    }
}

/// Errors from sentinel lifecycle operations.
///
/// `Serialize` is derived (wire form = variant name, matching
/// `release_marks::MarkError` style). `Deserialize` is not derived — the
/// `BadInput(&'static str)` payload cannot be deserialized into a `'static`
/// lifetime (repo precedent: `clearness_gate`, `unknowns`, `mode_diversity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SentinelError {
    /// A required input was empty or otherwise malformed; carries the field
    /// name (`"name"`, `"holder"`, `"ttl_ms"`).
    BadInput(&'static str),
    /// No sentinel with that id exists in the registry.
    UnknownSentinel,
    /// The requested state change is not on the lifecycle ladder (e.g.
    /// `start` on a `Running` sentinel, `stop` on a `Stopped` one).
    BadTransition,
    /// The sentinel's lease had already lapsed when the heartbeat arrived;
    /// the sentinel was moved to `Suspended` (resumable) by that call.
    LeaseExpired,
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SentinelError::BadInput(field) => match *field {
                "ttl_ms" => write!(f, "invalid input: lease ttl_ms must be > 0"),
                other => write!(f, "invalid input: {other} must be non-empty"),
            },
            SentinelError::UnknownSentinel => {
                write!(f, "unknown sentinel: no sentinel with that id exists")
            }
            SentinelError::BadTransition => write!(
                f,
                "illegal sentinel transition: the requested state change is not \
                 on the lifecycle ladder (starting -> running -> suspended -> stopped)"
            ),
            SentinelError::LeaseExpired => write!(
                f,
                "lease expired: sentinel suspended (resumable via start or restart)"
            ),
        }
    }
}

impl std::error::Error for SentinelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T0: i64 = 1_000;

    /// Register and return the new id (ids are the handle for every op).
    fn reg(m: &mut SentinelManager, name: &str, now_ms: i64) -> String {
        m.register(name, now_ms).expect("register ok").id.clone()
    }

    fn ids(stale: &[&Sentinel]) -> Vec<String> {
        stale.iter().map(|s| s.id.clone()).collect()
    }

    // ── registration ─────────────────────────────────────────────────────

    #[test]
    fn register_ids_are_sequential_and_state_is_starting() {
        let mut m = SentinelManager::new();
        assert_eq!(reg(&mut m, "alpha", T0), "sn-001");
        assert_eq!(reg(&mut m, "beta", T0), "sn-002");
        assert_eq!(reg(&mut m, "gamma", T0), "sn-003");
        assert_eq!(m.len(), 3);
        let v = m.view("sn-001").unwrap();
        assert_eq!(v.state, SentinelState::Starting);
        assert!(!v.state.is_active());
        assert!(!v.state.is_terminal());
        assert_eq!(v.heartbeats, 0);
        assert_eq!(v.last_heartbeat_ms, None);
        assert_eq!(v.restarts, 0);
        assert_eq!(v.lease_holder, None);
    }

    #[test]
    fn register_rejects_empty_name_and_does_not_consume_an_id() {
        let mut m = SentinelManager::new();
        assert_eq!(
            m.register("", T0),
            Err(SentinelError::BadInput("name")),
            "empty name must be refused"
        );
        assert_eq!(m.len(), 0, "failed registration consumes no id");
        // The next id is still sn-001 — ids are registration order, not
        // attempt order.
        assert_eq!(reg(&mut m, "alpha", T0), "sn-001");
    }

    #[test]
    fn register_only_rejects_truly_empty_names() {
        // Literal reading of the frozen "empty name" rule: only `""` is
        // refused; whitespace-only names are caller decision, not ours.
        let mut m = SentinelManager::new();
        assert!(m.register(" ", T0).is_ok());
        assert!(m.register("\t", T0).is_ok());
        assert_eq!(m.len(), 2);
    }

    // ── start / heartbeat guards ─────────────────────────────────────────

    #[test]
    fn start_and_heartbeat_guards_reject_unknown_and_bad_inputs() {
        let mut m = SentinelManager::new();
        assert_eq!(m.start("nope", "op", 100, T0), Err(SentinelError::UnknownSentinel));
        assert_eq!(m.heartbeat("nope", T0), Err(SentinelError::UnknownSentinel));
        assert_eq!(m.view("nope"), Err(SentinelError::UnknownSentinel));
        assert_eq!(m.suspend("nope", T0), Err(SentinelError::UnknownSentinel));
        assert_eq!(m.stop("nope", T0), Err(SentinelError::UnknownSentinel));
        assert_eq!(m.restart("nope", T0), Err(SentinelError::UnknownSentinel));

        let id = reg(&mut m, "alpha", T0);
        // bad payload on a known id
        assert_eq!(m.start(&id, "", 100, T0), Err(SentinelError::BadInput("holder")));
        assert_eq!(m.start(&id, "op", 0, T0), Err(SentinelError::BadInput("ttl_ms")));
        assert_eq!(m.start(&id, "op", -7, T0), Err(SentinelError::BadInput("ttl_ms")));
        // failed starts leave the sentinel untouched
        assert_eq!(m.view(&id).unwrap().state, SentinelState::Starting);
        // heartbeat before running is a bad transition
        assert_eq!(m.heartbeat(&id, T0), Err(SentinelError::BadTransition));

        // pinned check order: unknown id wins over bad payload …
        assert_eq!(m.start("nope", "", 0, T0), Err(SentinelError::UnknownSentinel));

        m.start(&id, "op-1", 100, T0).unwrap();
        // … and on a Running sentinel the payload is validated before the
        // transition is refused.
        assert_eq!(m.start(&id, "op-2", 0, T0), Err(SentinelError::BadInput("ttl_ms")));
        assert_eq!(m.start(&id, "op-2", 100, T0), Err(SentinelError::BadTransition));
    }

    // ── lifecycle walk ───────────────────────────────────────────────────

    #[test]
    fn full_lifecycle_walk() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "watchtower", T0);

        m.start(&id, "op-1", 500, T0).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Running);
        assert!(v.state.is_active());
        assert_eq!(v.lease_holder.as_deref(), Some("op-1"));

        m.heartbeat(&id, T0 + 100).unwrap();
        m.heartbeat(&id, T0 + 200).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.heartbeats, 2);
        assert_eq!(v.last_heartbeat_ms, Some(T0 + 200));

        m.suspend(&id, T0 + 250).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Suspended);
        assert_eq!(v.lease_holder, None);

        // resume directly from Suspended
        m.start(&id, "op-2", 500, T0 + 300).unwrap();
        assert_eq!(m.view(&id).unwrap().state, SentinelState::Running);
        assert_eq!(m.view(&id).unwrap().lease_holder.as_deref(), Some("op-2"));

        m.stop(&id, T0 + 400).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Stopped);
        assert!(v.state.is_terminal());
        assert_eq!(v.lease_holder, None);

        m.restart(&id, T0 + 500).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Starting);
        assert_eq!(v.restarts, 1);
        // history survives the whole walk
        assert_eq!(v.heartbeats, 2);
        assert_eq!(v.last_heartbeat_ms, Some(T0 + 200));

        m.start(&id, "op-3", 500, T0 + 600).unwrap();
        assert_eq!(m.view(&id).unwrap().state, SentinelState::Running);
        assert_eq!(m.view(&id).unwrap().lease_holder.as_deref(), Some("op-3"));
    }

    #[test]
    fn start_from_suspended_resumes_with_fresh_lease() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "alpha", T0);
        m.start(&id, "op-1", 100, T0).unwrap(); // window [T0, T0+100)
        m.suspend(&id, T0 + 10).unwrap();
        m.start(&id, "op-2", 100, T0 + 20).unwrap(); // window [T0+20, T0+120)
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Running);
        assert_eq!(v.lease_holder.as_deref(), Some("op-2"));
        // T0+110 is past the *old* window (expired at T0+100): success here
        // proves the resume installed a fresh window, not the old one.
        m.heartbeat(&id, T0 + 110).unwrap();
        assert_eq!(m.view(&id).unwrap().heartbeats, 1);
    }

    // ── heartbeat / lease ────────────────────────────────────────────────

    #[test]
    fn heartbeat_increments_and_renews() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "alpha", T0);
        m.start(&id, "op", 100, T0).unwrap(); // window [T0, T0+100)
        m.heartbeat(&id, T0 + 99).unwrap(); // fresh; renews to [T0+99, T0+199)
        // Without renewal the window would have died at T0+100; T0+150 is
        // only fresh because the heartbeat moved `acquired_ms`.
        m.heartbeat(&id, T0 + 150).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Running);
        assert_eq!(v.heartbeats, 2);
        assert_eq!(v.last_heartbeat_ms, Some(T0 + 150));
        assert_eq!(v.lease_holder.as_deref(), Some("op"));
    }

    #[test]
    fn heartbeat_at_or_after_lease_expiry_suspends_resumable() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "alpha", 0);
        m.start(&id, "op", 100, 0).unwrap(); // window [0, 100)
        m.heartbeat(&id, 99).unwrap(); // 99 < 100: fresh; renews to [99, 199)
        // boundary: now == acquired + ttl is already expired
        assert_eq!(m.heartbeat(&id, 199), Err(SentinelError::LeaseExpired));
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Suspended, "lapsed ⇒ suspended");
        assert_eq!(v.lease_holder, None, "dead lease is cleared");
        assert_eq!(v.heartbeats, 2, "the heartbeat still counted");
        assert_eq!(v.last_heartbeat_ms, Some(199), "…and was recorded");
        // suspended sentinels do not heartbeat
        assert_eq!(m.heartbeat(&id, 200), Err(SentinelError::BadTransition));
        // resumable
        m.start(&id, "op-2", 50, 300).unwrap();
        assert_eq!(m.view(&id).unwrap().state, SentinelState::Running);
    }

    #[test]
    fn lease_expired_boundary_and_renew() {
        let mut lease = Lease {
            holder: "op".into(),
            acquired_ms: 500,
            ttl_ms: 100,
        };
        assert!(!lease.expired(599), "599 < 600: still live");
        assert!(lease.expired(600), "boundary 600 == acquired + ttl: expired");
        assert!(lease.expired(601));
        lease.renew(700);
        assert!(!lease.expired(799), "renewal moves the window");
        assert!(lease.expired(800));
        // saturation: an extreme acquired + ttl cannot wrap into "never
        // expires inside the representable range"
        let far = Lease {
            holder: "op".into(),
            acquired_ms: i64::MAX - 1,
            ttl_ms: 100,
        };
        assert!(!far.expired(i64::MAX - 1));
        assert!(far.expired(i64::MAX));
    }

    // ── suspend / stop / restart ─────────────────────────────────────────

    #[test]
    fn suspend_requires_running_and_clears_lease() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "alpha", T0);
        assert_eq!(m.suspend(&id, T0), Err(SentinelError::BadTransition));
        m.start(&id, "op", 100, T0).unwrap();
        m.suspend(&id, T0 + 10).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Suspended);
        assert_eq!(v.lease_holder, None);
        // not re-suspendable
        assert_eq!(m.suspend(&id, T0 + 20), Err(SentinelError::BadTransition));
    }

    #[test]
    fn stop_is_terminal_from_every_live_state() {
        let mut m = SentinelManager::new();
        let a = reg(&mut m, "a", T0);
        let b = reg(&mut m, "b", T0);
        let c = reg(&mut m, "c", T0);

        m.stop(&a, T0).unwrap(); // from Starting
        assert_eq!(m.view(&a).unwrap().state, SentinelState::Stopped);

        m.start(&b, "op", 100, T0).unwrap();
        m.stop(&b, T0 + 10).unwrap(); // from Running
        let vb = m.view(&b).unwrap();
        assert_eq!(vb.state, SentinelState::Stopped);
        assert_eq!(vb.lease_holder, None, "stopping releases the lease");

        m.start(&c, "op", 100, T0).unwrap();
        m.suspend(&c, T0 + 10).unwrap();
        m.stop(&c, T0 + 20).unwrap(); // from Suspended
        assert_eq!(m.view(&c).unwrap().state, SentinelState::Stopped);

        // already stopped: nothing works but restart
        assert_eq!(m.stop(&a, T0 + 30), Err(SentinelError::BadTransition));
        assert_eq!(m.start(&a, "op", 100, T0 + 30), Err(SentinelError::BadTransition));
        assert_eq!(m.heartbeat(&a, T0 + 30), Err(SentinelError::BadTransition));
        assert_eq!(m.suspend(&a, T0 + 30), Err(SentinelError::BadTransition));
    }

    #[test]
    fn restart_rules_and_counting() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "alpha", T0);
        // Starting is not restartable (just start it)
        assert_eq!(m.restart(&id, T0), Err(SentinelError::BadTransition));
        m.start(&id, "op", 100, T0).unwrap();
        // Running is not restartable (suspend or stop first)
        assert_eq!(m.restart(&id, T0 + 1), Err(SentinelError::BadTransition));
        m.suspend(&id, T0 + 2).unwrap();
        m.restart(&id, T0 + 3).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Starting);
        assert_eq!(v.restarts, 1);
        // Starting again: not restartable until it has run (or stopped)
        assert_eq!(m.restart(&id, T0 + 4), Err(SentinelError::BadTransition));
        m.start(&id, "op", 100, T0 + 5).unwrap();
        m.stop(&id, T0 + 6).unwrap();
        m.restart(&id, T0 + 7).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Starting);
        assert_eq!(v.restarts, 2);
    }

    #[test]
    fn restart_preserves_identity_and_counters() {
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "keep-me", T0);
        m.start(&id, "op", 100, T0).unwrap();
        m.heartbeat(&id, T0 + 50).unwrap();
        m.suspend(&id, T0 + 60).unwrap();
        m.restart(&id, T0 + 70).unwrap();
        let v = m.view(&id).unwrap();
        assert_eq!(v.state, SentinelState::Starting);
        assert_eq!(v.heartbeats, 1);
        assert_eq!(v.last_heartbeat_ms, Some(T0 + 50));
        assert_eq!(v.restarts, 1);
        assert_eq!(id, "sn-001", "identity survives restart");
        // and it can be re-armed with a new holder
        m.start(&id, "op-2", 100, T0 + 80).unwrap();
        assert_eq!(m.view(&id).unwrap().lease_holder.as_deref(), Some("op-2"));
    }

    // ── stale listing ────────────────────────────────────────────────────

    #[test]
    fn stale_listing_sorted_and_filtered() {
        let mut m = SentinelManager::new();
        let a = reg(&mut m, "a", 0); // sn-001, ttl 100 → dies at 100
        let b = reg(&mut m, "b", 0); // sn-002, ttl 10  → dies at 10 (earlier!)
        let c = reg(&mut m, "c", 0); // sn-003, suspended → never stale
        let d = reg(&mut m, "d", 0); // sn-004, stopped   → never stale
        m.start(&a, "op", 100, 0).unwrap();
        m.start(&b, "op", 10, 0).unwrap();
        m.start(&c, "op", 10, 0).unwrap();
        m.start(&d, "op", 10, 0).unwrap();
        m.suspend(&c, 5).unwrap();
        m.stop(&d, 5).unwrap();

        assert!(m.stale(9).is_empty(), "nothing has lapsed yet");
        assert_eq!(ids(&m.stale(50)), vec!["sn-002"], "only the lapsed runner");
        // both lapsed now: sorted by id, not by expiry order
        assert_eq!(ids(&m.stale(100)), vec!["sn-001", "sn-002"]);
        assert_eq!(ids(&m.stale(999)), vec!["sn-001", "sn-002"]);
        // a heartbeat keeps a sentinel off the list
        m.heartbeat(&a, 100).unwrap_err(); // a is still Running: lapsed ⇒ suspended…
        assert_eq!(ids(&m.stale(999)), vec!["sn-002"], "…and then not stale");
    }

    // ── views ────────────────────────────────────────────────────────────

    #[test]
    fn view_reports_fields_and_unknown_id() {
        let mut m = SentinelManager::new();
        assert_eq!(m.view("sn-404"), Err(SentinelError::UnknownSentinel));
        let id = reg(&mut m, "alpha", T0);
        let v = m.view(&id).unwrap();
        assert_eq!(
            v,
            SentinelView {
                state: SentinelState::Starting,
                heartbeats: 0,
                last_heartbeat_ms: None,
                restarts: 0,
                lease_holder: None,
            }
        );
        m.start(&id, "op-9", 100, T0).unwrap();
        assert_eq!(m.view(&id).unwrap().lease_holder.as_deref(), Some("op-9"));
    }

    // ── determinism ──────────────────────────────────────────────────────

    /// One scripted run: returns the manager plus its serialized views and
    /// stale listings at several probe instants.
    fn script() -> (SentinelManager, Vec<String>, Vec<Vec<String>>) {
        let mut m = SentinelManager::new();
        let a = reg(&mut m, "alpha", 0);
        let b = reg(&mut m, "beta", 0);
        let c = reg(&mut m, "gamma", 0);
        m.start(&a, "op-a", 100, 0).unwrap();
        m.start(&b, "op-b", 10, 0).unwrap();
        m.start(&c, "op-c", 50, 0).unwrap();
        m.heartbeat(&a, 40).unwrap();
        assert_eq!(m.heartbeat(&c, 60), Err(SentinelError::LeaseExpired));
        m.restart(&c, 70).unwrap();
        m.suspend(&a, 80).unwrap();
        let views = [&a, &b, &c]
            .iter()
            .map(|id| serde_json::to_string(&m.view(id).unwrap()).unwrap())
            .collect();
        let stales = [9, 55, 130, 999]
            .iter()
            .map(|&now| ids(&m.stale(now)))
            .collect();
        (m, views, stales)
    }

    #[test]
    fn determinism_identical_runs_identical_state() {
        let one = script();
        let two = script();
        assert_eq!(one.0, two.0, "same script ⇒ equal manager state");
        assert_eq!(one.1, two.1, "same script ⇒ equal serialized views");
        assert_eq!(one.2, two.2, "same script ⇒ equal stale listings");
    }

    // ── serde ────────────────────────────────────────────────────────────

    #[test]
    fn serde_state_wire_form_and_roundtrip() {
        for state in [
            SentinelState::Starting,
            SentinelState::Running,
            SentinelState::Suspended,
            SentinelState::Stopped,
        ] {
            let s = serde_json::to_string(&state).unwrap();
            assert_eq!(s, format!("\"{state:?}\""), "unit variant wire form");
            assert_eq!(serde_json::from_str::<SentinelState>(&s).unwrap(), state);
        }
        assert_eq!(
            serde_json::to_string(&SentinelState::Suspended).unwrap(),
            "\"Suspended\""
        );
    }

    #[test]
    fn serde_lease_sentinel_and_view_roundtrip_with_exact_shape() {
        let lease = Lease {
            holder: "op-1".into(),
            acquired_ms: 5,
            ttl_ms: 50,
        };
        assert_eq!(
            serde_json::to_value(&lease).unwrap(),
            json!({"holder": "op-1", "acquired_ms": 5, "ttl_ms": 50})
        );
        assert_eq!(
            serde_json::from_value::<Lease>(serde_json::to_value(&lease).unwrap()).unwrap(),
            lease
        );

        let sentinel = Sentinel {
            id: "sn-001".into(),
            name: "watch".into(),
            state: SentinelState::Running,
            lease: Some(lease.clone()),
            heartbeats: 3,
            last_heartbeat_ms: Some(9),
            restarts: 1,
        };
        assert_eq!(
            serde_json::to_value(&sentinel).unwrap(),
            json!({
                "id": "sn-001",
                "name": "watch",
                "state": "Running",
                "lease": {"holder": "op-1", "acquired_ms": 5, "ttl_ms": 50},
                "heartbeats": 3,
                "last_heartbeat_ms": 9,
                "restarts": 1
            })
        );
        assert_eq!(
            serde_json::from_value::<Sentinel>(serde_json::to_value(&sentinel).unwrap()).unwrap(),
            sentinel
        );

        let view = SentinelView {
            state: SentinelState::Running,
            heartbeats: 3,
            last_heartbeat_ms: Some(9),
            restarts: 1,
            lease_holder: Some("op-1".into()),
        };
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            json!({
                "state": "Running",
                "heartbeats": 3,
                "last_heartbeat_ms": 9,
                "restarts": 1,
                "lease_holder": "op-1"
            })
        );
        assert_eq!(
            serde_json::from_value::<SentinelView>(serde_json::to_value(&view).unwrap()).unwrap(),
            view
        );
        // absent option wire forms
        let idle = SentinelView {
            state: SentinelState::Starting,
            heartbeats: 0,
            last_heartbeat_ms: None,
            restarts: 0,
            lease_holder: None,
        };
        assert_eq!(
            serde_json::to_value(&idle).unwrap(),
            json!({
                "state": "Starting",
                "heartbeats": 0,
                "last_heartbeat_ms": null,
                "restarts": 0,
                "lease_holder": null
            })
        );
        // a manager-created sentinel serializes to the same shape
        let mut m = SentinelManager::new();
        let id = reg(&mut m, "watch", 0);
        m.start(&id, "op-1", 50, 5).unwrap();
        let live = m.view(&id).unwrap();
        assert_eq!(
            serde_json::from_value::<SentinelView>(serde_json::to_value(&live).unwrap()).unwrap(),
            live
        );
    }

    #[test]
    fn serde_error_wire_forms() {
        assert_eq!(
            serde_json::to_value(SentinelError::BadInput("name")).unwrap(),
            json!({"BadInput": "name"})
        );
        assert_eq!(
            serde_json::to_value(SentinelError::LeaseExpired).unwrap(),
            json!("LeaseExpired")
        );
        assert_eq!(
            serde_json::to_value(SentinelError::UnknownSentinel).unwrap(),
            json!("UnknownSentinel")
        );
        assert_eq!(
            serde_json::to_value(SentinelError::BadTransition).unwrap(),
            json!("BadTransition")
        );
        // Display is implemented for every variant
        for err in [
            SentinelError::BadInput("name"),
            SentinelError::BadInput("holder"),
            SentinelError::BadInput("ttl_ms"),
            SentinelError::UnknownSentinel,
            SentinelError::BadTransition,
            SentinelError::LeaseExpired,
        ] {
            assert!(!err.to_string().is_empty());
        }
    }
}
