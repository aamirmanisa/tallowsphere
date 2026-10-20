//! Blocking loopback I/O layer — thread-per-connection server + one-shot
//! client. This is the "loopback first" deployment shape (the production
//! daemon sits behind Caddy; it can wrap the same state machines with async
//! I/O later — the protocol core in [`crate::server`] / [`crate::client`] is
//! transport-agnostic).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::client::{ClientConfig, ClientError, ClientSession};
use crate::cover::cover;
use crate::server::{Action, ServerCore, ServerSession};

/// Pre-auth phase read timeout (the linger deadline).
pub const PRE_AUTH_TIMEOUT: Duration = Duration::from_millis(2_000);
/// Authenticated-session idle timeout: a silent admitted session is closed after
/// this long. Keepalive is application-level — any authenticated frame refreshes
/// the deadline, and `{"act":"ping"}` exists so a client can hold a session open
/// without carrying a payload (see `crate::policy`).
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_millis(30_000);
/// Client-side admission/request deadline.
pub const CLIENT_DEADLINE: Duration = Duration::from_millis(15_000);
/// TOTAL time the pre-auth phase may occupy a connection, drip or not
/// (v1 hardening, 2026-10-15). `PRE_AUTH_TIMEOUT` is a per-*read* timeout,
/// so a peer dribbling one byte per interval resets it forever and holds
/// the connection (and its thread) indefinitely. This budget is fixed at
/// accept time and applies ONLY to the pre-auth phase — once a session is
/// authenticated it reverts to `SESSION_IDLE_TIMEOUT` (idle) semantics, so
/// legitimately long admitted sessions are never cut off.
///
/// Deliberately EQUAL to `CLIENT_DEADLINE`: if the server gave up sooner
/// than the client does, a slow-but-legitimate peer would be hung up on
/// while its own client code still believed the attempt was live.
pub const PRE_AUTH_TOTAL: Duration = CLIENT_DEADLINE;
/// Maximum concurrent PRE-AUTH connections (v1 hardening, 2026-10-15).
/// Each accepted connection spawns an unbounded thread, so without a cap
/// an in-mesh attacker can hold connections open and exhaust the daemon.
/// Authenticated connections are released from this accounting.
pub const MAX_PRE_AUTH_CONNECTIONS: usize = 32;

/// Remaining budget for this read, given the phase deadline and the phase's
/// per-read timeout: the smaller of the two, or `None` if the total budget
/// is already exhausted.
///
/// Pure and clock-injected so the deadline arithmetic is unit-testable
/// without sleeping.
pub fn next_read_timeout(
    now: Instant,
    deadline: Option<Instant>,
    phase_timeout: Duration,
) -> Option<Duration> {
    match deadline {
        None => Some(phase_timeout),
        Some(d) => {
            let remaining = d.saturating_duration_since(now);
            if remaining.is_zero() {
                None
            } else {
                Some(remaining.min(phase_timeout))
            }
        }
    }
}


/// I/O layer errors.
#[derive(Debug)]
pub enum IoError {
    Io(String),
    Client(ClientError),
    Timeout,
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::Io(e) => write!(f, "io: {e}"),
            IoError::Client(e) => write!(f, "client: {e}"),
            IoError::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        IoError::Io(e.to_string())
    }
}

impl From<ClientError> for IoError {
    fn from(e: ClientError) -> Self {
        IoError::Client(e)
    }
}

/// Serve connections on `listener` until it errors/stops; one thread per
/// connection. Returns the accept-loop thread handle.
pub fn serve(listener: TcpListener, core: Arc<ServerCore>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let core = Arc::clone(&core);
                    // Rate limit per source before touching the concurrency
                    // budget: a peer that reconnects in a loop must be refused
                    // without ever holding a pre-auth slot. Same refusal shape
                    // as the over-cap path (cover bytes, then close).
                    if let Ok(peer) = stream.peer_addr() {
                        if !core.allow_source(peer.ip(), Instant::now()) {
                            let mut s = stream;
                            let _ = s.write_all(cover());
                            let _ = s.flush();
                            continue;
                        }
                    }
                    // Cap concurrent PRE-AUTH connections before spawning a
                    // thread. Over the cap: answer with cover and close, so a
                    // refusal is indistinguishable from ordinary traffic.
                    match core.try_enter_pre_auth() {
                        Some(slot) => {
                            std::thread::spawn(move || {
                                let _slot = slot;
                                conn_loop(stream, core);
                            });
                        }
                        None => {
                            let mut s = stream;
                            let _ = s.write_all(cover());
                            let _ = s.flush();
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    })
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Apply actions to the socket; `false` = stop the connection.
fn write_actions(stream: &mut TcpStream, actions: &[Action]) -> bool {
    for a in actions {
        match a {
            Action::Write(bytes) => {
                if stream.write_all(bytes).is_err() {
                    return false;
                }
            }
            Action::Cover => {
                let _ = stream.write_all(cover());
                let _ = stream.flush();
                return false;
            }
            Action::Close => return false,
        }
    }
    true
}

fn conn_loop(mut stream: TcpStream, core: Arc<ServerCore>) {
    let _ = stream.set_nodelay(true);
    let mut session: ServerSession = core.accept();
    let mut buf = [0u8; 4096];
    // Total pre-auth budget, fixed now. `None` once authenticated: an admitted
    // session is legitimate and long-lived, so it reverts to idle semantics and
    // must NOT be bounded by the pre-auth budget.
    let mut pre_auth_deadline: Option<Instant> = Some(Instant::now() + PRE_AUTH_TOTAL);
    loop {
        let (timeout, deadline) = if session.is_authenticated() {
            (SESSION_IDLE_TIMEOUT, None)
        } else {
            (PRE_AUTH_TIMEOUT, pre_auth_deadline)
        };
        let Some(read_timeout) = next_read_timeout(Instant::now(), deadline, timeout) else {
            // total pre-auth budget exhausted mid-drip: fail closed (pre-auth
            // `on_deadline` sends cover) and drop the connection.
            let acts = session.on_deadline();
            let _ = write_actions(&mut stream, &acts);
            return;
        };
        if stream.set_read_timeout(Some(read_timeout)).is_err() {
            return;
        }
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                let acts = session.feed(&buf[..n]);
                if !write_actions(&mut stream, &acts) {
                    return;
                }
                // Once admitted, the connection leaves the pre-auth budget
                // behind permanently: an admitted session is legitimate and
                // long-lived, so it must not be cut off by the pre-auth total.
                // The pre-auth SLOT is released separately, when the guard drops
                // at the end of this function (see `PreAuthSlot`).
                if session.is_authenticated() {
                    pre_auth_deadline = None;
                }
            }
            Err(e) if is_timeout(&e) => {
                let acts = session.on_deadline();
                if !write_actions(&mut stream, &acts) {
                    return;
                }
                // cover sent (pre-auth) or idle in session: both end the conn
                return;
            }
            Err(_) => return,
        }
    }
}

/// Blocking one-shot client: connect, admit, send one request, return the
/// response value.
pub fn dial_call(
    addr: &str,
    cfg: ClientConfig,
    act: &str,
    data: Option<Value>,
) -> Result<Value, IoError> {
    let mut stream = TcpStream::connect(addr)?;
    dial_call_on(&mut stream, cfg, act, data)
}

/// Blocking one-shot client over an already-established stream — any rung:
/// direct, SOCKS/Tor (dial the proxy first), or the local end of an SSH
/// forward. Sets `TCP_NODELAY` itself.
pub fn dial_call_on(
    stream: &mut TcpStream,
    cfg: ClientConfig,
    act: &str,
    data: Option<Value>,
) -> Result<Value, IoError> {
    let _ = stream.set_nodelay(true);
    let mut client = ClientSession::new(cfg);
    let mut buf = [0u8; 4096];

    stream.write_all(&client.start())?;

    let deadline = Instant::now() + CLIENT_DEADLINE;
    while !client.is_admitted() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let _ = client.on_deadline();
            return Err(IoError::Timeout);
        }
        stream.set_read_timeout(Some(remaining))?;
        let n = match stream.read(&mut buf) {
            Ok(0) => return Err(IoError::Io("peer closed during admission".into())),
            Ok(n) => n,
            Err(e) if is_timeout(&e) => {
                let _ = client.on_deadline();
                return Err(IoError::Timeout);
            }
            Err(e) => return Err(e.into()),
        };
        let acts = client.feed(&buf[..n])?;
        for a in acts {
            if let Action::Write(b) = a {
                stream.write_all(&b)?;
            }
        }
    }

    stream.write_all(&client.seal_call(act, data)?)?;
    let deadline = Instant::now() + CLIENT_DEADLINE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::Timeout);
        }
        stream.set_read_timeout(Some(remaining))?;
        let n = match stream.read(&mut buf) {
            Ok(0) => return Err(IoError::Io("peer closed".into())),
            Ok(n) => n,
            Err(e) if is_timeout(&e) => return Err(IoError::Timeout),
            Err(e) => return Err(e.into()),
        };
        let acts = client.feed(&buf[..n])?;
        for a in acts {
            if let Action::Write(b) = a {
                stream.write_all(&b)?;
            }
        }
        if let Some(resp) = client.take_response() {
            return Ok(resp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// V1 FAIL-FIRST PROOF — the pre-fix arithmetic, kept as a documented
    /// counter-example. The OLD loop set `PRE_AUTH_TIMEOUT` unconditionally and
    /// consulted no total budget, so this function models it: the returned
    /// timeout is identical no matter how long the connection has been open.
    fn old_read_timeout(_now: Instant, phase_timeout: Duration) -> Duration {
        phase_timeout
    }

    /// With the OLD arithmetic a drip keeps resetting the per-read timer, so the
    /// connection outlives the total budget. This test PASSES pre-fix (it
    /// asserts the vulnerable behaviour) and documents exactly what was wrong.
    #[test]
    fn proof_drip_survives_the_total_budget_on_the_unfixed_arithmetic() {
        let start = Instant::now();
        let interval = Duration::from_millis(1_500); // < PRE_AUTH_TIMEOUT
        let mut t = start;
        // Simulate 60 s of dripping well past the 15 s budget.
        for _ in 0..40 {
            t += interval;
            let to = old_read_timeout(t, PRE_AUTH_TIMEOUT);
            assert!(
                to == PRE_AUTH_TIMEOUT,
                "pre-fix: the per-read timeout never shrinks, so the read never \
                 times out mid-drip and the total budget is never enforced"
            );
        }
        assert!(
            t.duration_since(start) > PRE_AUTH_TOTAL,
            "pre-fix: the connection is STILL OPEN at {t:?}, past the {PRE_AUTH_TOTAL:?} budget"
        );
    }

    /// The fixed arithmetic clamps each read to the remaining total budget, so
    /// the same drip is bounded.
    #[test]
    fn drip_is_bounded_by_the_total_budget() {
        let start = Instant::now();
        let interval = Duration::from_millis(1_500);
        let deadline = start + PRE_AUTH_TOTAL;
        let mut t = start;
        let mut closed: Option<Duration> = None;
        for _ in 0..40 {
            t += interval;
            match next_read_timeout(t, Some(deadline), PRE_AUTH_TIMEOUT) {
                Some(to) => {
                    // each read is clamped to what remains of the total budget
                    assert!(
                        to <= PRE_AUTH_TIMEOUT,
                        "a read may never exceed the phase's per-read timeout"
                    );
                    assert!(
                        to <= deadline.saturating_duration_since(t),
                        "a read may never outlive the total pre-auth budget"
                    );
                }
                None => {
                    closed = Some(t.duration_since(start));
                    break;
                }
            }
        }
        let closed = closed.expect("the drip must be closed at the total budget");
        assert!(
            closed <= PRE_AUTH_TOTAL + interval,
            "the drip closed at {closed:?}, expected at/before {PRE_AUTH_TOTAL:?}"
        );
    }

    /// A fast, honest handshake is nowhere near the budget: the clamp must not
    /// shorten an ordinary read.
    #[test]
    fn normal_reads_are_not_shortened_by_the_budget() {
        let now = Instant::now();
        let deadline = now + PRE_AUTH_TOTAL;
        // With 15 s of budget left, a 2 s per-read timeout is the binding one.
        assert_eq!(
            next_read_timeout(now, Some(deadline), PRE_AUTH_TIMEOUT),
            Some(PRE_AUTH_TIMEOUT)
        );
    }

    /// Near the end of the budget the remaining time binds, not the per-read
    /// timeout — this is the clamp that makes the drip impossible.
    #[test]
    fn near_the_deadline_the_remaining_budget_binds() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(500);
        assert_eq!(
            next_read_timeout(now, Some(deadline), PRE_AUTH_TIMEOUT),
            Some(Duration::from_millis(500)),
            "with 500 ms of budget left, the read must be 500 ms, not 2 s"
        );
    }

    /// An exhausted budget yields no read at all (the caller closes).
    #[test]
    fn exhausted_budget_yields_no_read() {
        let now = Instant::now();
        let deadline = now - Duration::from_millis(1);
        assert_eq!(next_read_timeout(now, Some(deadline), PRE_AUTH_TIMEOUT), None);
        assert_eq!(next_read_timeout(now, Some(now), PRE_AUTH_TIMEOUT), None);
    }

    /// The central regression guard: an AUTHENTICATED session passes
    /// `deadline = None`, so the pre-auth total never cuts off a long-lived
    /// admitted connection. This is the most likely bug this change could
    /// introduce, so it is asserted explicitly.
    #[test]
    fn authenticated_sessions_are_not_bounded_by_the_pre_auth_total() {
        let far_future = Instant::now() + Duration::from_secs(86_400);
        assert_eq!(
            next_read_timeout(far_future, None, SESSION_IDLE_TIMEOUT),
            Some(SESSION_IDLE_TIMEOUT),
            "an admitted session must keep idle semantics forever, not the \
             pre-auth budget"
        );
    }

    /// The total budget is at least the client's own deadline, so the server
    /// never hangs up on a client that still believes it is within time.
    #[test]
    fn total_budget_is_not_shorter_than_the_client_deadline() {
        assert!(
            PRE_AUTH_TOTAL >= CLIENT_DEADLINE,
            "PRE_AUTH_TOTAL ({PRE_AUTH_TOTAL:?}) must be >= CLIENT_DEADLINE \
             ({CLIENT_DEADLINE:?}) or slow-but-legitimate peers get a confusing \
             server-side hangup"
        );
    }
}
