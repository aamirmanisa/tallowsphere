// tallow.relay_room — Relay room sessions on the SendTallow product relay
// (WebSocket wire; raw postcard Message frames — same wire as the product's
// browser client). Stage 3 / Slice 2.
//
// Legacy 2-peer rooms (`join`): the relay pairs two peers on the same code
// phrase; `RoomJoined.peer_present` reports whether the other side is already
// waiting; PeerArrived / PeerDeparted arrive as events.
//
// Multi-peer rooms (`join_multi`): the relay assigns a peer id
// (`RoomJoinedMulti{peer_id, existing_peers}`); peers join/leave raise
// peer_joined / peer_left events; payloads travel in Targeted envelopes
// (broadcast = to_peer 255).
//
// Password auth: pass the relay's password to join/join_multi; wrong or
// missing password → hard error ("relay rejected join: authentication failed").

struct RelayRoom {
    url: String,
    code: String,
    room_id: String,
    mode: String,          // "legacy" | "multi"
    peer_present: bool,
    peer_id: i64,          // multi only (0 = legacy)
    existing_peers: []i64, // multi only (empty = legacy / first in room)
    connected: bool,
}

struct RelayEvent {
    kind: String,   // payload | peer_arrived | peer_departed | peer_joined | peer_left | timeout | closed | error
    data: String,   // lossy utf-8 rendering of a payload
    data_len: i64,
    peer_id: i64,   // peer_joined / peer_left: the peer that joined/left
    from_peer: i64, // multi payloads: sender id (relay-assigned)
    to_peer: i64,   // multi payloads: 255 = broadcast, else target id
    raw: Bytes,     // exact payload bytes
}

struct RelaySendOutcome {
    sent: bool,
    bytes: i64,
}

// Join a legacy 2-peer room (ws://host:port/ws). Hard error on auth reject/timeout.
fn RelayRoom.join(url: String, code: String, password: String = "") -> RelayRoom
    // native: websocket connect + RoomJoin postcard frame + RoomJoined await

// Join a multi-peer room; relay-assigned peer ids are 0-based (0 <= existing_peers < capacity).
fn RelayRoom.join_multi(url: String, code: String, capacity: i64 = 0, password: String = "") -> RelayRoom
    // native: websocket connect + RoomJoinMulti postcard frame + RoomJoinedMulti await

// Send a payload (utf-8 string; legacy raw / multi broadcast).
fn RelayRoom.send(self, data: String) -> RelaySendOutcome
    // native: binary WS frame (multi: Targeted to_peer=255)

// Send exact bytes (legacy raw / multi broadcast).
fn RelayRoom.send_bytes(self, data: Bytes) -> RelaySendOutcome
    // native: binary WS frame (multi: Targeted to_peer=255)

// Send a payload to one peer in a multi room (255 = broadcast).
fn RelayRoom.send_to(self, peer_id: i64, data: String) -> RelaySendOutcome
    // native: Targeted postcard frame

// Receive the next event or payload.
// kind: payload | peer_arrived | peer_departed | peer_joined | peer_left | timeout | closed | error
fn RelayRoom.recv(self, timeout_ms: i64 = 10000) -> RelayEvent
    // native: next binary WS frame, classified

// Close the room session.
fn RelayRoom.leave(self)
    // native: WS close + drop session

// Live status of a room handle (same shape as join's result).
fn RelayRoom.status(self) -> RelayRoom
    // native: registry lookup

// Deterministic room id (hex) for a code phrase — BLAKE3(code).
fn RelayRoom.room_id(code: String) -> String
    // native: derive_room_id hex
