//! Server-side admission state machine.
//!
//! Pure: bytes in → [`Action`]s out. Every unauthenticated failure yields
//! [`Action::Cover`] (byte-identical 404); post-admission failures yield a
//! plain [`Action::Close`] — a cover 404 mid-session would be nonsense to a
//! real client and must never be the server's behavior (reference semantics).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead::AeadChan;
use crate::devkeys::ServerIdentity;
use crate::framing::{frame, FrameDecoder};
use crate::io::MAX_PRE_AUTH_CONNECTIONS;
use crate::handshake::{
    build_msg2, client_sig_digest, derive_session, key_fp, random_bytes, random_pad, s1_digest,
    s2_digest, s3_digest, server_sig_digest,
};
use crate::{now_ms, MAGIC1, MAGIC3, TS_WINDOW_MS};

/// Audit events emitted by sessions (format mirrors the reference logs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// Admission succeeded.
    AuthOk {
        device: String,
        role: String,
        key_fp: String,
        /// Fingerprint of the device's Ed25519 public key — stable across
        /// sessions (the session `key_fp` is per-connection; v1 audit ruling
        /// N-1: carry both so admissions are correlatable by device).
        dev_fp: String,
    },
    /// An allowed action was performed.
    Allow {
        device: String,
        role: String,
        act: String,
    },
    /// A denied action was attempted.
    Deny {
        device: String,
        role: String,
        act: String,
    },
}

impl AuditEvent {
    /// Canonical log line (`AUTH ok ...` / `ALLOW ...` / `DENY ...`).
    pub fn line(&self) -> String {
        match self {
            AuditEvent::AuthOk {
                device,
                role,
                key_fp,
                dev_fp,
            } => {
                format!("AUTH ok device={device} role={role} fp={key_fp} dev_fp={dev_fp}")
            }
            AuditEvent::Allow { device, role, act } => {
                format!("ALLOW device={device} role={role} act={act}")
            }
            AuditEvent::Deny { device, role, act } => {
                format!("DENY device={device} role={role} act={act}")
            }
        }
    }
}

/// Audit sink: invoked once per event, possibly from multiple connection threads.
pub type AuditSink = Arc<dyn Fn(AuditEvent) + Send + Sync>;

/// Device status in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

/// One registry entry.
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub id: String,
    pub ed: VerifyingKey,
    pub role: String,
    pub status: DeviceStatus,
}

impl DeviceEntry {
    /// Whether this device may currently be admitted.
    pub fn is_active(&self) -> bool {
        self.status == DeviceStatus::Active
    }
}

/// Registry lookup interface (the static map here is the v0 test shape; the
/// production registry will be backed by the console's device store).
pub trait DeviceRegistry: Send + Sync {
    fn get(&self, id: &str) -> Option<DeviceEntry>;
}

/// Simple in-memory registry.
#[derive(Default)]
pub struct StaticRegistry {
    map: HashMap<String, DeviceEntry>,
}

impl StaticRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace an entry (keyed by `entry.id`).
    pub fn insert(&mut self, entry: DeviceEntry) {
        self.map.insert(entry.id.clone(), entry);
    }
}

impl DeviceRegistry for StaticRegistry {
    fn get(&self, id: &str) -> Option<DeviceEntry> {
        self.map.get(id).cloned()
    }
}

/// What the I/O layer must do next for one session.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Write these bytes.
    Write(Vec<u8>),
    /// Write the cover bytes, then close.
    Cover,
    /// Close (plain).
    Close,
}

/// Bounded server-wide replay set (caps at 4096 nonces, clear-on-overflow —
/// mirrors the reference's bounded set).
#[derive(Default)]
struct ReplaySet {
    seen: HashSet<[u8; 32]>,
}

impl ReplaySet {
    fn check_and_insert(&mut self, nonce: &[u8; 32]) -> bool {
        if self.seen.contains(nonce) {
            return false;
        }
        self.seen.insert(*nonce);
        if self.seen.len() > 4096 {
            self.seen.clear();
        }
        true
    }
}

/// Shared server context: identity, registry, audit sink, replay set.
pub struct ServerCore {
    identity: ServerIdentity,
    registry: Arc<dyn DeviceRegistry>,
    audit: Option<AuditSink>,
    replay: Mutex<ReplaySet>,
    /// Concurrent PRE-AUTH connections (v1 hardening, 2026-10-15). Bounded by
    /// `MAX_PRE_AUTH_CONNECTIONS`; a connection released from this count once
    /// its session authenticates (see `try_enter_pre_auth`).
    pre_auth: AtomicUsize,
}

/// RAII slot in the pre-auth connection accounting. Dropping it (on ANY exit
/// path from `conn_loop`, including early returns and panics) frees the slot,
/// so a slot cannot leak.
pub struct PreAuthSlot(Arc<ServerCore>);

impl Drop for PreAuthSlot {
    fn drop(&mut self) {
        self.0.pre_auth.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ServerCore {
    /// Claim a pre-auth connection slot, or `None` when the cap is reached.
    pub fn try_enter_pre_auth(self: &Arc<Self>) -> Option<PreAuthSlot> {
        loop {
            let cur = self.pre_auth.load(Ordering::SeqCst);
            if cur >= MAX_PRE_AUTH_CONNECTIONS {
                return None;
            }
            if self
                .pre_auth
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(PreAuthSlot(Arc::clone(self)));
            }
        }
    }

    /// Current pre-auth occupancy (for metrics/tests).
    pub fn pre_auth_count(&self) -> usize {
        self.pre_auth.load(Ordering::SeqCst)
    }

    /// Build a core (held behind an `Arc`; clone via [`ServerCore::accept`]).
    pub fn new(
        identity: ServerIdentity,
        registry: Arc<dyn DeviceRegistry>,
        audit: Option<AuditSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity,
            registry,
            audit,
            replay: Mutex::new(ReplaySet::default()),
            pre_auth: AtomicUsize::new(0),
        })
    }

    /// Start a new per-connection session.
    pub fn accept(self: &Arc<Self>) -> ServerSession {
        ServerSession::new(Arc::clone(self))
    }

    fn emit(&self, ev: AuditEvent) {
        if let Some(sink) = &self.audit {
            sink(ev);
        }
    }

    fn replay_ok(&self, nonce: &[u8; 32]) -> bool {
        self.replay
            .lock()
            .expect("replay lock")
            .check_and_insert(nonce)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Wait1,
    Wait3,
    Session,
}

/// Per-connection server state machine.
pub struct ServerSession {
    core: Arc<ServerCore>,
    phase: Phase,
    dec: FrameDecoder,
    msg1: Vec<u8>,
    s1: [u8; 32],
    s2: [u8; 32],
    eph_s: Option<StaticSecret>,
    nonce_s: [u8; 32],
    eph_c_pub: [u8; 32],
    send: Option<AeadChan>,
    recv: Option<AeadChan>,
    device: Option<DeviceEntry>,
    cover_sent: bool,
    closed: bool,
}

impl ServerSession {
    pub(crate) fn new(core: Arc<ServerCore>) -> Self {
        Self {
            core,
            phase: Phase::Wait1,
            dec: FrameDecoder::new(),
            msg1: Vec::new(),
            s1: [0u8; 32],
            s2: [0u8; 32],
            eph_s: None,
            nonce_s: [0u8; 32],
            eph_c_pub: [0u8; 32],
            send: None,
            recv: None,
            device: None,
            cover_sent: false,
            closed: false,
        }
    }

    /// Whether the session has been admitted (auth complete, open).
    pub fn is_authenticated(&self) -> bool {
        matches!(self.phase, Phase::Session) && !self.closed
    }

    /// Feed raw bytes (framed); returns actions for the I/O layer.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Action> {
        if self.closed {
            return Vec::new();
        }
        self.dec.push(chunk);
        let mut out = Vec::new();
        while let Some(payload) = self.dec.pop_frame() {
            let acts = self.step(&payload);
            let stop = acts
                .iter()
                .any(|a| matches!(a, Action::Cover | Action::Close));
            out.extend(acts);
            if stop {
                self.closed = true;
                break;
            }
        }
        out
    }

    /// The linger deadline fired (no bytes arrived in time).
    pub fn on_deadline(&mut self) -> Vec<Action> {
        if self.closed {
            return Vec::new();
        }
        match self.phase {
            Phase::Session => Vec::new(),
            _ => self.fail(),
        }
    }

    fn fail(&mut self) -> Vec<Action> {
        if self.phase == Phase::Session {
            self.closed = true;
            vec![Action::Close]
        } else if !self.cover_sent {
            self.cover_sent = true;
            self.closed = true;
            vec![Action::Cover]
        } else {
            self.closed = true;
            Vec::new()
        }
    }

    fn step(&mut self, payload: &[u8]) -> Vec<Action> {
        match self.phase {
            Phase::Wait1 => self.step_wait1(payload),
            Phase::Wait3 => self.step_wait3(payload),
            Phase::Session => self.step_session(payload),
        }
    }

    fn step_wait1(&mut self, payload: &[u8]) -> Vec<Action> {
        if payload.len() < 3 + 32 || &payload[..3] != MAGIC1 {
            return self.fail();
        }
        self.eph_c_pub.copy_from_slice(&payload[3..35]);
        self.msg1 = payload.to_vec();
        self.s1 = s1_digest(&self.msg1);

        // fresh ephemeral server keypair + nonce per connection
        let eph_bytes: [u8; 32] = random_bytes(32).try_into().expect("32 bytes");
        let eph_s = StaticSecret::from(eph_bytes);
        let eph_s_pub = PublicKey::from(&eph_s);
        let mut nonce_s = [0u8; 32];
        nonce_s.copy_from_slice(&random_bytes(32));

        let digest = server_sig_digest(&self.s1, eph_s_pub.as_bytes(), &nonce_s);
        let sig_s = self.core.identity.ed.sign(&digest).to_bytes();
        let msg2 = build_msg2(eph_s_pub.as_bytes(), &nonce_s, &sig_s, random_pad());

        self.s2 = s2_digest(&self.s1, &msg2);
        self.eph_s = Some(eph_s);
        self.nonce_s = nonce_s;
        self.phase = Phase::Wait3;
        vec![Action::Write(frame(&msg2))]
    }

    fn step_wait3(&mut self, payload: &[u8]) -> Vec<Action> {
        const TAIL: usize = 8 + 64;
        if payload.len() < 3 + 1 + TAIL || &payload[..3] != MAGIC3 {
            return self.fail();
        }
        let id_end = payload.len() - TAIL;
        let device_id = match std::str::from_utf8(&payload[3..id_end]) {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => return self.fail(),
        };
        let ts = u64::from_be_bytes(payload[id_end..id_end + 8].try_into().expect("8 bytes"));
        let mut sig_c = [0u8; 64];
        sig_c.copy_from_slice(&payload[payload.len() - 64..]);

        let entry = match self.core.registry.get(&device_id) {
            Some(e) if e.is_active() => e,
            _ => return self.fail(),
        };

        let digest = client_sig_digest(&self.s2, device_id.as_bytes(), ts);
        let sig = Signature::from_bytes(&sig_c);
        if entry.ed.verify_strict(&digest, &sig).is_err() {
            return self.fail();
        }

        let now = now_ms();
        if (now as i128 - ts as i128).unsigned_abs() > TS_WINDOW_MS as u128 {
            return self.fail();
        }
        if !self.core.replay_ok(&self.nonce_s) {
            return self.fail();
        }

        let s3 = s3_digest(&self.s2, payload);
        let eph_c_pub = PublicKey::from(self.eph_c_pub);
        let dh1 = self
            .eph_s
            .as_ref()
            .expect("eph_s")
            .diffie_hellman(&eph_c_pub);
        let dh2 = self.core.identity.x.diffie_hellman(&eph_c_pub);
        let keys = derive_session(&dh1, &dh2, &self.nonce_s, &s3);

        let fp = key_fp(&keys.k_s2c);
        self.send = Some(AeadChan::new(&keys.k_s2c, 0)); // server → client
        self.recv = Some(AeadChan::new(&keys.k_c2s, 0)); // client → server
        self.device = Some(entry.clone());
        self.phase = Phase::Session;
        self.core.emit(AuditEvent::AuthOk {
            device: device_id,
            role: entry.role.clone(),
            key_fp: fp,
            dev_fp: key_fp(&entry.ed.to_bytes()),
        });
        vec![Action::Write(frame(b"OK"))]
    }

    fn step_session(&mut self, payload: &[u8]) -> Vec<Action> {
        let plain = match self.recv.as_ref().expect("recv").open(payload) {
            Ok(p) => p,
            Err(_) => {
                self.closed = true;
                return vec![Action::Close];
            }
        };
        let req: Value = match serde_json::from_slice(&plain) {
            Ok(v) => v,
            Err(_) => {
                self.closed = true;
                return vec![Action::Close];
            }
        };
        let act = req
            .get("act")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let device = self.device.as_ref().expect("device set at admission");
        let device_id = device.id.clone();
        let role = device.role.clone();

        let resp = if crate::policy::action_allowed(&role, &act) {
            self.core.emit(AuditEvent::Allow {
                device: device_id,
                role,
                act: act.clone(),
            });
            let result = req.get("data").cloned().unwrap_or(Value::Null);
            json!({ "ok": true, "act": act, "result": result })
        } else {
            self.core.emit(AuditEvent::Deny {
                device: device_id,
                role,
                act: act.clone(),
            });
            json!({ "ok": false, "code": "denied" })
        };
        let bytes = serde_json::to_vec(&resp).expect("json serialize");
        let sealed = self.send.as_mut().expect("send").seal(&bytes);
        vec![Action::Write(frame(&sealed))]
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;
    use crate::io::MAX_PRE_AUTH_CONNECTIONS;

    fn core() -> Arc<ServerCore> {
        ServerCore::new(
            crate::devkeys::server_identity(),
            Arc::new(StaticRegistry::new()),
            None,
        )
    }

    /// The cap admits exactly MAX_PRE_AUTH_CONNECTIONS slots and refuses the
    /// next one. Pre-fix there was no accounting at all, so an unbounded number
    /// of connections were accepted (each spawning a thread).
    #[test]
    fn cap_admits_the_maximum_then_refuses() {
        let c = core();
        let mut slots = Vec::new();
        for i in 0..MAX_PRE_AUTH_CONNECTIONS {
            slots.push(
                c.try_enter_pre_auth()
                    .unwrap_or_else(|| panic!("slot {i} must be admitted under the cap")),
            );
        }
        assert_eq!(c.pre_auth_count(), MAX_PRE_AUTH_CONNECTIONS);
        assert!(
            c.try_enter_pre_auth().is_none(),
            "connection {} must be REFUSED: the cap is {MAX_PRE_AUTH_CONNECTIONS}",
            MAX_PRE_AUTH_CONNECTIONS + 1
        );
        assert_eq!(
            c.pre_auth_count(),
            MAX_PRE_AUTH_CONNECTIONS,
            "a refused connection must not consume a slot"
        );
        drop(slots);
    }

    /// Every slot is released on drop, so the count returns to zero and no slot
    /// leaks — the failure mode the RAII guard exists to prevent.
    #[test]
    fn slots_are_released_on_drop() {
        let c = core();
        {
            let _a = c.try_enter_pre_auth().expect("a");
            let _b = c.try_enter_pre_auth().expect("b");
            assert_eq!(c.pre_auth_count(), 2);
        }
        assert_eq!(c.pre_auth_count(), 0, "both slots must be freed on drop");

        // and the full capacity is usable again afterwards
        let mut slots = Vec::new();
        for _ in 0..MAX_PRE_AUTH_CONNECTIONS {
            slots.push(c.try_enter_pre_auth().expect("re-acquire after release"));
        }
        assert!(c.try_enter_pre_auth().is_none());
        drop(slots);
        assert_eq!(c.pre_auth_count(), 0);
    }

    /// A slot released under concurrency is reclaimed: many threads claiming and
    /// releasing must never drive the counter above the cap nor leak below zero.
    #[test]
    fn concurrent_claim_release_never_exceeds_the_cap() {
        use std::sync::atomic::AtomicUsize;
        let c = core();
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = Arc::clone(&c);
            let peak = Arc::clone(&peak);
            handles.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    if let Some(slot) = c.try_enter_pre_auth() {
                        let n = c.pre_auth_count();
                        peak.fetch_max(n, Ordering::SeqCst);
                        assert!(n <= MAX_PRE_AUTH_CONNECTIONS);
                        drop(slot);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(c.pre_auth_count(), 0, "all slots released");
        assert!(
            peak.load(Ordering::SeqCst) <= MAX_PRE_AUTH_CONNECTIONS,
            "the cap was exceeded under concurrency"
        );
    }
}
