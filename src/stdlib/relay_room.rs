//! Relay room sessions on the SendTallow product relay — WebSocket wire.
//!
//! Stage 3 / Slice 2 (2026-09-15): the language speaks the product relay's
//! WebSocket wire directly — raw postcard `Message` frames, the same wire the
//! SendTallow browser client uses (`tallow-relay serve --ws-addr ...`, route
//! `GET /ws`):
//!
//! * `join`       — legacy 2-peer room: `RoomJoin{room_id, password_hash,
//!   forward_to_relay: None}` → `RoomJoined{peer_present}`.
//! * `join_multi` — multi-peer room: `RoomJoinMulti{room_id, password_hash,
//!   requested_capacity}` → `RoomJoinedMulti{peer_id, existing_peers}`;
//!   peers receive `PeerJoinedRoom{peer_id}` / `PeerLeftRoom{peer_id}`.
//! * payloads    — legacy: raw frames both ways. Multi: wrapped in
//!   `Targeted{from_peer, to_peer, payload}` (relay overwrites `from_peer`;
//!   `to_peer` 0xFF = broadcast, or a specific peer id).
//! * auth        — optional relay password → BLAKE3 hash in the join frame;
//!   wrong/missing password → `HandshakeFailed` → hard error.
//! * `send`/`send_bytes`/`send_to` — payload send; `recv` — next event or
//!   payload with a timeout (`kind`: payload | peer_arrived | peer_departed |
//!   peer_joined | peer_left | timeout | closed | error); `raw` carries the
//!   exact payload bytes.
//! * `leave` — close the WS connection and drop the session.
//!
//! Architecture: each session owns a dedicated worker thread with a
//! long-lived tokio runtime. The socket is created, and every operation is
//! driven on that same runtime, so the stream's I/O registration stays valid
//! across separate `.tl` calls (a fresh runtime per call would orphan the
//! socket registration — "A Tokio 1.x context was found, but it is being
//! shutdown"). `.tl` calls talk to the worker over std mpsc channels.
//!
//! Interop proven against the real product relay in `tests/relay_ws_interop.rs`
//! (2026-09-15: legacy 1/0 ×2; multi + auth + binary added same evening).

use std::collections::HashMap;
use std::sync::mpsc as std_mpsc;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use crate::interp::Value;

use super::StdlibResult;

// ── Session registry ──

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Which room flavor to join.
enum JoinMode {
    Legacy,
    Multi { capacity: u8 },
}

/// Result of the join handshake.
enum JoinOutcome {
    Legacy {
        peer_present: bool,
    },
    Multi {
        peer_id: u8,
        existing_peers: Vec<u8>,
    },
}

/// Commands sent to a session worker thread.
enum Cmd {
    Send {
        data: Vec<u8>,
        /// Some(peer_id) = targeted (multi only); None = legacy raw / multi broadcast.
        to_peer: Option<u8>,
        reply: std_mpsc::Sender<Result<usize, String>>,
    },
    Recv {
        timeout_ms: u64,
        reply: std_mpsc::Sender<Result<Next, String>>,
    },
    Close {
        reply: std_mpsc::Sender<()>,
    },
}

static ROOMS: LazyLock<Mutex<HashMap<u64, std_mpsc::Sender<Cmd>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ROOM_ID_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

fn next_room_id() -> u64 {
    let mut counter = ROOM_ID_COUNTER.lock().unwrap();
    *counter += 1;
    *counter
}

// ── Wire helpers ──

use tokio_tungstenite::tungstenite::Message as WsMsg;

/// One received wire frame.
enum Next {
    Binary(Vec<u8>),
    Closed,
    Timeout,
}

/// Read the next binary WS frame, skipping ping/pong/other control frames.
async fn next_binary(ws: &mut WsStream, timeout: Option<Duration>) -> Result<Next, String> {
    let fut = async {
        loop {
            match futures_util::StreamExt::next(ws).await {
                None => return Ok(Next::Closed),
                Some(Err(e)) => return Err(format!("ws recv: {e}")),
                Some(Ok(WsMsg::Binary(b))) => return Ok(Next::Binary(b.to_vec())),
                Some(Ok(WsMsg::Close(_))) => return Ok(Next::Closed),
                // Ping/Pong/Text/Frame frames: skip (the relay is binary-only).
                Some(Ok(_)) => continue,
            }
        }
    };
    match timeout {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(result) => result,
            Err(_) => Ok(Next::Timeout),
        },
        None => fut.await,
    }
}

/// Connect + join handshake on the worker's runtime.
async fn connect_and_join(
    url: &str,
    room_id: [u8; 32],
    password_hash: Option<Vec<u8>>,
    mode: JoinMode,
) -> Result<(WsStream, JoinOutcome), String> {
    let (mut ws, _response) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("connect {url}: {e}"))?;

    let join_bytes = match &mode {
        JoinMode::Legacy => {
            let join = tallow_protocol::wire::Message::RoomJoin {
                room_id: room_id.to_vec(),
                password_hash,
                forward_to_relay: None,
            };
            postcard::to_stdvec(&join).map_err(|e| format!("encode RoomJoin: {e}"))?
        }
        JoinMode::Multi { capacity } => {
            let join = tallow_protocol::wire::Message::RoomJoinMulti {
                room_id: room_id.to_vec(),
                password_hash,
                requested_capacity: *capacity,
            };
            postcard::to_stdvec(&join).map_err(|e| format!("encode RoomJoinMulti: {e}"))?
        }
    };
    futures_util::SinkExt::send(&mut ws, WsMsg::Binary(join_bytes.into()))
        .await
        .map_err(|e| format!("send join: {e}"))?;

    match next_binary(&mut ws, Some(Duration::from_secs(10))).await {
        Ok(Next::Binary(bytes)) => match postcard::from_bytes::<tallow_protocol::wire::Message>(&bytes)
        {
            Ok(tallow_protocol::wire::Message::RoomJoined { peer_present }) => {
                Ok((ws, JoinOutcome::Legacy { peer_present }))
            }
            Ok(tallow_protocol::wire::Message::RoomJoinedMulti {
                peer_id,
                existing_peers,
            }) => Ok((
                ws,
                JoinOutcome::Multi {
                    peer_id,
                    existing_peers,
                },
            )),
            Ok(tallow_protocol::wire::Message::HandshakeFailed { reason }) => {
                Err(format!("relay rejected join: {reason}"))
            }
            Ok(other) => Err(format!("unexpected first message: {other:?}")),
            Err(e) => Err(format!("decode join response: {e}")),
        },
        Ok(Next::Closed) => Err("relay closed the connection during handshake".to_string()),
        Ok(Next::Timeout) => Err("timed out waiting for join response".to_string()),
        Err(e) => Err(e),
    }
}

/// Spawn the session worker: it owns the runtime + socket for the session's
/// lifetime and answers commands from the registry.
fn spawn_worker(
    url: String,
    room_id: [u8; 32],
    password_hash: Option<Vec<u8>>,
    mode: JoinMode,
) -> (std_mpsc::Sender<Cmd>, std_mpsc::Receiver<Result<JoinOutcome, String>>) {
    let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
    let (join_tx, join_rx) = std_mpsc::channel::<Result<JoinOutcome, String>>();

    std::thread::Builder::new()
        .name("tallow-relay-room".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(connect_and_join(&url, room_id, password_hash, mode)) {
                Ok((mut ws, outcome)) => {
                    let (is_multi, my_peer_id) = match &outcome {
                        JoinOutcome::Legacy { .. } => (false, 0u8),
                        JoinOutcome::Multi { peer_id, .. } => (true, *peer_id),
                    };
                    let _ = join_tx.send(Ok(outcome));
                    loop {
                        match cmd_rx.recv() {
                            Ok(Cmd::Send { data, to_peer, reply }) => {
                                let len = data.len();
                                let frame: Result<Vec<u8>, String> = if is_multi {
                                    let to = to_peer.unwrap_or(0xFF);
                                    let msg = tallow_protocol::wire::Message::Targeted {
                                        from_peer: my_peer_id,
                                        to_peer: to,
                                        payload: data,
                                    };
                                    postcard::to_stdvec(&msg)
                                        .map_err(|e| format!("encode Targeted: {e}"))
                                } else if to_peer.is_some() {
                                    Err("RelayRoom.send_to requires a multi room (use RelayRoom.join_multi)"
                                        .to_string())
                                } else {
                                    Ok(data)
                                };
                                match frame {
                                    Ok(frame) => {
                                        let result = rt.block_on(async {
                                            futures_util::SinkExt::send(
                                                &mut ws,
                                                WsMsg::Binary(frame.into()),
                                            )
                                            .await
                                            .map_err(|e| format!("ws send: {e}"))
                                        });
                                        let _ = reply.send(result.map(|_| len));
                                    }
                                    Err(e) => {
                                        let _ = reply.send(Err(e));
                                    }
                                }
                            }
                            Ok(Cmd::Recv { timeout_ms, reply }) => {
                                let result = rt.block_on(async {
                                    next_binary(&mut ws, Some(Duration::from_millis(timeout_ms)))
                                        .await
                                });
                                let _ = reply.send(result);
                            }
                            Ok(Cmd::Close { reply }) => {
                                let _ = rt.block_on(async {
                                    let _ = futures_util::SinkExt::send(&mut ws, WsMsg::Close(None))
                                        .await;
                                });
                                let _ = reply.send(());
                                break;
                            }
                            // All senders dropped — session is gone.
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    let _ = join_tx.send(Err(e));
                }
            }
        })
        .expect("spawn relay-room worker");

    (cmd_tx, join_rx)
}

fn take_sender(id: u64) -> Result<std_mpsc::Sender<Cmd>, String> {
    ROOMS
        .lock()
        .unwrap()
        .remove(&id)
        .ok_or_else(|| format!("RelayRoom session {id} not found (already left?)"))
}

fn put_sender(id: u64, tx: std_mpsc::Sender<Cmd>) {
    ROOMS.lock().unwrap().insert(id, tx);
}

// ── Event classification ──

/// A relay event surfaced to `.tl` as a `RelayEvent` struct.
struct RelayEvent {
    kind: String,
    data: String,
    len: usize,
    peer_id: i128,
    from_peer: i128,
    to_peer: i128,
    raw: Vec<u8>,
}

impl RelayEvent {
    fn empty(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            data: String::new(),
            len: 0,
            peer_id: 0,
            from_peer: 0,
            to_peer: 0,
            raw: Vec::new(),
        }
    }

    fn to_value(self) -> Value {
        Value::Struct {
            name: "RelayEvent".to_string(),
            fields: vec![
                ("kind".to_string(), Value::String(self.kind)),
                ("data".to_string(), Value::String(self.data)),
                ("data_len".to_string(), Value::Int(self.len as i128)),
                ("peer_id".to_string(), Value::Int(self.peer_id)),
                ("from_peer".to_string(), Value::Int(self.from_peer)),
                ("to_peer".to_string(), Value::Int(self.to_peer)),
                ("raw".to_string(), Value::Bytes(self.raw)),
            ],
        }
    }
}

/// Classify a frame: known control messages become events; everything else is
/// a raw payload. Only the documented control variants are matched, so an
/// app payload that happens to decode as some other `Message` variant still
/// passes through as a payload.
fn classify_frame(bytes: &[u8]) -> RelayEvent {
    use tallow_protocol::wire::Message;
    if let Ok(msg) = postcard::from_bytes::<Message>(bytes) {
        match msg {
            Message::PeerArrived => {
                return RelayEvent::empty("peer_arrived");
            }
            Message::PeerDeparted => {
                return RelayEvent::empty("peer_departed");
            }
            Message::PeerJoinedRoom { peer_id } => {
                let mut ev = RelayEvent::empty("peer_joined");
                ev.peer_id = peer_id as i128;
                return ev;
            }
            Message::PeerLeftRoom { peer_id } => {
                let mut ev = RelayEvent::empty("peer_left");
                ev.peer_id = peer_id as i128;
                return ev;
            }
            Message::HandshakeFailed { reason } => {
                let mut ev = RelayEvent::empty("error");
                ev.data = reason;
                return ev;
            }
            Message::Targeted {
                from_peer,
                to_peer,
                payload,
            } => {
                return RelayEvent {
                    kind: "payload".to_string(),
                    data: String::from_utf8_lossy(&payload).into_owned(),
                    len: payload.len(),
                    peer_id: 0,
                    from_peer: from_peer as i128,
                    to_peer: to_peer as i128,
                    raw: payload,
                };
            }
            _ => {}
        }
    }
    RelayEvent {
        kind: "payload".to_string(),
        data: String::from_utf8_lossy(bytes).into_owned(),
        len: bytes.len(),
        peer_id: 0,
        from_peer: 0,
        to_peer: 0,
        raw: bytes.to_vec(),
    }
}

// ── Argument / handle helpers ──

fn string_arg(args: &[Value], idx: usize, usage: &str) -> Result<String, String> {
    args.get(idx)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| usage.to_string())
}

/// Payload argument: exact bytes from `Bytes`, otherwise the string's UTF-8.
fn payload_arg(args: &[Value], idx: usize, usage: &str) -> Result<Vec<u8>, String> {
    match args.get(idx) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(v) => {
            let s = v.as_string();
            if s.is_empty() {
                Err(usage.to_string())
            } else {
                Ok(s.into_bytes())
            }
        }
        None => Err(usage.to_string()),
    }
}

/// Strict `Bytes`-only payload (for `send_bytes`).
fn bytes_arg(args: &[Value], idx: usize, usage: &str) -> Result<Vec<u8>, String> {
    match args.get(idx) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(usage.to_string()),
        None => Err(usage.to_string()),
    }
}

fn extract_field_int(object: &Value, field: &str) -> Result<i128, String> {
    if let Value::Struct { fields, .. } = object {
        fields
            .iter()
            .find(|(n, _)| n == field)
            .and_then(|(_, v)| match v {
                Value::Int(n) => Some(*n),
                _ => None,
            })
            .ok_or_else(|| format!("missing or non-integer field '{field}'"))
    } else {
        Err("expected struct value".to_string())
    }
}

fn extract_room_id(handle: Option<&Value>) -> Result<u64, String> {
    match handle {
        Some(object) => Ok(extract_field_int(object, "_room_id")? as u64),
        None => Err("expected a RelayRoom handle".to_string()),
    }
}

/// Build the `.tl`-visible RelayRoom handle struct.
#[allow(clippy::too_many_arguments)]
fn build_handle(
    url: String,
    code: String,
    room_id_hex: String,
    mode: &str,
    peer_present: bool,
    peer_id: u8,
    existing_peers: Vec<u8>,
    id: u64,
) -> Value {
    Value::Struct {
        name: "RelayRoom".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(url)),
            ("code".to_string(), Value::String(code)),
            ("room_id".to_string(), Value::String(room_id_hex)),
            ("mode".to_string(), Value::String(mode.to_string())),
            ("peer_present".to_string(), Value::Bool(peer_present)),
            ("peer_id".to_string(), Value::Int(peer_id as i128)),
            (
                "existing_peers".to_string(),
                Value::Array(
                    existing_peers
                        .into_iter()
                        .map(|p| Value::Int(p as i128))
                        .collect(),
                ),
            ),
            ("connected".to_string(), Value::Bool(true)),
            ("_room_id".to_string(), Value::Int(id as i128)),
        ],
    }
}

// ── Operations ──

/// Shared join plumbing: derive room id, spawn worker, await handshake.
fn join_common(
    url: String,
    code: String,
    password: Option<String>,
    mode: JoinMode,
    mode_name: &str,
) -> StdlibResult {
    if !tallow_protocol::room::code::is_supported_code(&code) {
        return Err(format!(
            "unsupported code '{}': {} — this build accepts the 8-symbol mint only (e.g. K7M2QPHD)",
            code,
            tallow_protocol::room::code::unsupported_code_reason(&code).unwrap_or("not a v4 passcode")
        ));
    }
    let room_id = tallow_protocol::room::code::resolve_room_id(&code).0;
    let room_id_hex = blake3::Hash::from_bytes(room_id).to_hex().to_string();
    let password_hash: Option<Vec<u8>> =
        password.as_ref().map(|p| blake3::hash(p.as_bytes()).as_bytes().to_vec());

    let id = next_room_id();
    let (cmd_tx, join_rx) = spawn_worker(url.clone(), room_id, password_hash, mode);

    match join_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(outcome)) => {
            put_sender(id, cmd_tx);
            match outcome {
                JoinOutcome::Legacy { peer_present } => Ok(build_handle(
                    url, code, room_id_hex, "legacy", peer_present, 0, Vec::new(), id,
                )),
                JoinOutcome::Multi {
                    peer_id,
                    existing_peers,
                } => {
                    let peer_present = !existing_peers.is_empty();
                    Ok(build_handle(
                        url,
                        code,
                        room_id_hex,
                        "multi",
                        peer_present,
                        peer_id,
                        existing_peers,
                        id,
                    ))
                }
            }
        }
        Ok(Err(e)) => Err(format!("RelayRoom.{mode_name}: {e}")),
        Err(_) => Err(format!(
            "RelayRoom.{mode_name}: timed out waiting for the session worker"
        )),
    }
}

/// `RelayRoom.join(url, code, password?) -> RelayRoom` (legacy 2-peer room)
pub(crate) fn room_join(args: Vec<Value>) -> StdlibResult {
    let url = string_arg(&args, 0, "RelayRoom.join requires a ws:// URL")?;
    let code = string_arg(&args, 1, "RelayRoom.join requires a code phrase")?;
    let password = args
        .get(2)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty());
    join_common(url, code, password, JoinMode::Legacy, "join")
}

/// `RelayRoom.join_multi(url, code, capacity?, password?) -> RelayRoom`
pub(crate) fn room_join_multi(args: Vec<Value>) -> StdlibResult {
    let url = string_arg(&args, 0, "RelayRoom.join_multi requires a ws:// URL")?;
    let code = string_arg(&args, 1, "RelayRoom.join_multi requires a code phrase")?;
    let capacity = match args.get(2) {
        Some(Value::Int(n)) if *n > 0 => (*n).min(255) as u8,
        _ => 0,
    };
    let password = args
        .get(3)
        .map(|v| v.as_string())
        .filter(|s| !s.is_empty());
    join_common(
        url,
        code,
        password,
        JoinMode::Multi { capacity },
        "join_multi",
    )
}

/// Shared send plumbing.
fn send_impl(room_id: u64, data: Vec<u8>, to_peer: Option<u8>) -> StdlibResult {
    let tx = take_sender(room_id)?;
    let (reply_tx, reply_rx) = std_mpsc::channel();
    let send_result = tx.send(Cmd::Send {
        data,
        to_peer,
        reply: reply_tx,
    });
    let result = match send_result {
        Ok(()) => reply_rx
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| "session worker did not answer".to_string()),
        Err(_) => Err("session worker is gone".to_string()),
    };
    put_sender(room_id, tx);

    match result {
        Ok(Ok(len)) => Ok(Value::Struct {
            name: "RelaySendOutcome".to_string(),
            fields: vec![
                ("sent".to_string(), Value::Bool(true)),
                ("bytes".to_string(), Value::Int(len as i128)),
            ],
        }),
        Ok(Err(e)) => Err(format!("RelayRoom.send: {e}")),
        Err(e) => Err(format!("RelayRoom.send: {e}")),
    }
}

/// `RelayRoom.send(room, data: String|Bytes) -> RelaySendOutcome`
pub(crate) fn room_send(args: Vec<Value>) -> StdlibResult {
    let room_id = extract_room_id(args.first())?;
    let data = payload_arg(&args, 1, "RelayRoom.send requires data (String or Bytes)")?;
    send_impl(room_id, data, None)
}

/// `RelayRoom.send_bytes(room, data: Bytes) -> RelaySendOutcome`
pub(crate) fn room_send_bytes(args: Vec<Value>) -> StdlibResult {
    let room_id = extract_room_id(args.first())?;
    let data = bytes_arg(&args, 1, "RelayRoom.send_bytes requires Bytes (e.g. KeyPair public_key)")?;
    send_impl(room_id, data, None)
}

/// `RelayRoom.send_to(room, peer_id, data: String|Bytes) -> RelaySendOutcome`
pub(crate) fn room_send_to(args: Vec<Value>) -> StdlibResult {
    let room_id = extract_room_id(args.first())?;
    let peer_id = match args.get(1) {
        Some(Value::Int(n)) if (1..=255).contains(n) => *n as u8,
        _ => {
            return Err(
                "RelayRoom.send_to requires a peer_id (1..=255; 255 = broadcast)".to_string(),
            )
        }
    };
    let data = payload_arg(&args, 2, "RelayRoom.send_to requires data (String or Bytes)")?;
    send_impl(room_id, data, Some(peer_id))
}

/// `RelayRoom.recv(room, timeout_ms?) -> RelayEvent`
pub(crate) fn room_recv(args: Vec<Value>) -> StdlibResult {
    let room_id = extract_room_id(args.first())?;
    let timeout_ms = match args.get(1) {
        Some(Value::Int(n)) if *n > 0 => *n as u64,
        _ => 10_000,
    };

    let tx = take_sender(room_id)?;
    let (reply_tx, reply_rx) = std_mpsc::channel();
    let send_result = tx.send(Cmd::Recv {
        timeout_ms,
        reply: reply_tx,
    });
    let result = match send_result {
        Ok(()) => reply_rx
            .recv_timeout(Duration::from_millis(timeout_ms + 15_000))
            .map_err(|_| "session worker did not answer".to_string()),
        Err(_) => Err("session worker is gone".to_string()),
    };
    put_sender(room_id, tx);

    let event = match result {
        Ok(Ok(Next::Binary(bytes))) => classify_frame(&bytes),
        Ok(Ok(Next::Closed)) => RelayEvent::empty("closed"),
        Ok(Ok(Next::Timeout)) => RelayEvent::empty("timeout"),
        Ok(Err(e)) => {
            let mut ev = RelayEvent::empty("error");
            ev.data = e;
            ev
        }
        Err(e) => {
            let mut ev = RelayEvent::empty("error");
            ev.data = e;
            ev
        }
    };
    Ok(event.to_value())
}

/// `RelayRoom.leave(room)`
pub(crate) fn room_leave(args: Vec<Value>) -> StdlibResult {
    let room_id = extract_room_id(args.first())?;
    let tx = ROOMS.lock().unwrap().remove(&room_id);
    if let Some(tx) = tx {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        let _ = tx.send(Cmd::Close { reply: reply_tx });
        let _ = reply_rx.recv_timeout(Duration::from_secs(5));
    }
    Ok(Value::Nil)
}

/// `RelayRoom.status(room) -> RelayRoom` (echo with live `connected` flag)
pub(crate) fn room_status(args: Vec<Value>) -> StdlibResult {
    let room = args.first().cloned().ok_or("expected a RelayRoom handle")?;
    let room_id = extract_room_id(Some(&room))?;
    let connected = ROOMS.lock().unwrap().contains_key(&room_id);
    if let Value::Struct { fields, .. } = room {
        let mut out: Vec<(String, Value)> = fields
            .into_iter()
            .filter(|(n, _)| n != "connected")
            .collect();
        out.push(("connected".to_string(), Value::Bool(connected)));
        Ok(Value::Struct {
            name: "RelayRoom".to_string(),
            fields: out,
        })
    } else {
        Err("expected a RelayRoom handle".to_string())
    }
}

/// `RelayRoom.room_id(code) -> String` (hex room id for diagnostics)
pub(crate) fn room_id_of(args: Vec<Value>) -> StdlibResult {
    let code = string_arg(&args, 0, "RelayRoom.room_id requires a code phrase")?;
    if !tallow_protocol::room::code::is_supported_code(&code) {
        return Err(format!(
            "unsupported code '{}': {} — this build accepts the 8-symbol mint only (e.g. K7M2QPHD)",
            code,
            tallow_protocol::room::code::unsupported_code_reason(&code).unwrap_or("not a v4 passcode")
        ));
    }
    let room_id = tallow_protocol::room::code::resolve_room_id(&code).0;
    Ok(Value::String(
        blake3::Hash::from_bytes(room_id).to_hex().to_string(),
    ))
}

// ── Dispatch entry points ──

/// Namespace dispatch: `RelayRoom.join(...)`, `relay_room.join(...)` etc.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "join" | "connect" => Some(room_join(args)),
        "join_multi" | "multi" | "connect_multi" => Some(room_join_multi(args)),
        "send" => Some(room_send(args)),
        "send_bytes" => Some(room_send_bytes(args)),
        "send_to" => Some(room_send_to(args)),
        "recv" | "receive" => Some(room_recv(args)),
        "leave" | "close" | "disconnect" => Some(room_leave(args)),
        "status" => Some(room_status(args)),
        "room_id" | "room_id_of" => Some(room_id_of(args)),
        other => Some(Err(format!("RelayRoom has no function '{other}'"))),
    }
}

/// Method dispatch on RelayRoom handles: `room.send(...)`, `room.send_bytes(...)`,
/// `room.send_to(...)`, `room.recv(...)`, `room.leave()`, `room.status()`.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let mut full = Vec::with_capacity(args.len() + 1);
    full.push(object.clone());
    full.extend(args);
    match method {
        "send" => Some(room_send(full)),
        "send_bytes" => Some(room_send_bytes(full)),
        "send_to" => Some(room_send_to(full)),
        "recv" | "receive" => Some(room_recv(full)),
        "leave" | "close" | "disconnect" => Some(room_leave(full)),
        "status" => Some(room_status(full)),
        other => Some(Err(format!("RelayRoom has no method '{other}'"))),
    }
}
