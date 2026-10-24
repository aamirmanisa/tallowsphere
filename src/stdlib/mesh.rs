//! Standard library: `tallow.mesh` -- peer-to-peer gossip and DHT over TCP.
//!
//! This is a real network plane, not a simulation. `MeshNode.new` binds a TCP
//! listener on `127.0.0.1:<port>`; `join` dials the bootstrap addresses and
//! exchanges a `hello` frame; `broadcast` writes a `gossip` frame to every
//! handshaken peer; `dht_put` replicates a `dht` frame the same way. A peer is
//! reported `connected: true` only after its `hello` arrived, and a peer's
//! `simulated` field is `!connected` — it cannot be true for a link that works.
//!
//! Wire format: one JSON object per line, no framing beyond `\n`:
//!
//! ```text
//! {"t":"hello","node":"node-9001-1","port":9001}
//! {"t":"gossip","id":"node-9001-1:3","from":"node-9001-1","topic":"t","v":{...}}
//! {"t":"dht","key":"k","v":{"t":"string","s":"value"}}
//! ```
//!
//! `Value` is `!Send` (it holds `Rc<RefCell<..>>`), so no `Value` is stored
//! across threads: payloads become [`DhtValue`], a plain `Send` enum, before
//! they reach the registry or the wire.
//!
//! Limits, stated rather than implied: gossip forwards one hop, so a message
//! reaches the sender's peers and their peers, not the whole network; a dropped
//! peer is not redialled; and the DHT is a replicated key-value store with
//! last-write-wins, not a partitioned distributed hash table.

use super::StdlibResult;
use crate::interp::Value;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

// ══════════════════════════════════════════════════════════════════
// State
// ══════════════════════════════════════════════════════════════════

/// One live connection. The writer is shared with the node's send path; the
/// peer id is filled in when that side's `hello` arrives.
struct PeerLink {
    addr: String,
    writer: Mutex<TcpStream>,
    peer_id: Mutex<Option<String>>,
}

/// Everything a node owns. The accept thread and every connection thread hold
/// an `Arc` of this, so a node stays alive while a socket is open even if the
/// interpreter has dropped the struct that named it.
struct NodeShared {
    node_id: String,
    port: i128,
    bootstrap: Vec<String>,
    joined: AtomicBool,
    listening: AtomicBool,
    peers: Mutex<Vec<Arc<PeerLink>>>,
    subscriptions: Mutex<Vec<String>>,
    inbox: Mutex<Vec<(String, DhtValue)>>,
    dht: Mutex<HashMap<String, DhtValue>>,
    seen: Mutex<HashSet<String>>,
    sent_seq: AtomicU64,
}

/// All mesh nodes keyed by node_id.
static MESH_NODES: LazyLock<Mutex<HashMap<String, Arc<NodeShared>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Counter for generating unique node IDs.
static MESH_NODE_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

/// Send+Sync-safe representation of a Value for storage and for the wire.
#[derive(Clone, Debug)]
enum DhtValue {
    String(String),
    Int(i128),
    Float(f64),
    Bool(bool),
    Nil,
}

impl DhtValue {
    fn from_value(v: &Value) -> Self {
        match v {
            Value::String(s) => DhtValue::String(s.clone()),
            Value::Int(n) => DhtValue::Int(*n),
            Value::Float(f) => DhtValue::Float(*f),
            Value::Bool(b) => DhtValue::Bool(*b),
            Value::Nil => DhtValue::Nil,
            // Complex values cross the wire as their display form; there is no
            // structural decoder for them on the far side.
            other => DhtValue::String(other.as_string()),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            DhtValue::String(s) => Value::String(s.clone()),
            DhtValue::Int(n) => Value::Int(*n),
            DhtValue::Float(f) => Value::Float(*f),
            DhtValue::Bool(b) => Value::Bool(*b),
            DhtValue::Nil => Value::Nil,
        }
    }

    fn to_wire(&self) -> serde_json::Value {
        match self {
            DhtValue::String(s) => serde_json::json!({"t": "string", "s": s}),
            DhtValue::Int(n) => serde_json::json!({"t": "int", "s": n.to_string()}),
            DhtValue::Float(f) => serde_json::json!({"t": "float", "s": f.to_string()}),
            DhtValue::Bool(b) => serde_json::json!({"t": "bool", "s": b.to_string()}),
            DhtValue::Nil => serde_json::json!({"t": "nil"}),
        }
    }

    fn from_wire(v: &serde_json::Value) -> DhtValue {
        let s = v.get("s").and_then(|x| x.as_str()).unwrap_or("");
        match v.get("t").and_then(|x| x.as_str()).unwrap_or("nil") {
            "string" => DhtValue::String(s.to_string()),
            "int" => DhtValue::Int(s.parse().unwrap_or(0)),
            "float" => DhtValue::Float(s.parse().unwrap_or(0.0)),
            "bool" => DhtValue::Bool(s == "true"),
            _ => DhtValue::Nil,
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// Public dispatch entry points
// ══════════════════════════════════════════════════════════════════

/// Dispatch a `MeshNode.*` constructor/static function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(mesh_node_new(args)),
        _ => None,
    }
}

/// Dispatch a method call on a MeshNode or PeerInfo struct.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, .. } = object {
        match name.as_str() {
            "MeshNode" => Some(mesh_node_method(object, method, args)),
            "PeerInfo" => Some(peer_info_method(object, method)),
            _ => None,
        }
    } else {
        None
    }
}

/// Reset all global mesh state (for test isolation).
///
/// Stops every listener and drops every connection. The threads exit on their
/// own: the accept loop checks `listening` on its next tick, and connection
/// readers see EOF when the streams drop.
pub fn reset_all() {
    let nodes: Vec<Arc<NodeShared>> = {
        let mut map = MESH_NODES.lock().unwrap();
        let v = map.values().cloned().collect();
        map.clear();
        v
    };
    for n in nodes {
        n.listening.store(false, Ordering::SeqCst);
        if let Ok(mut peers) = n.peers.lock() {
            peers.clear();
        }
    }
    *MESH_NODE_COUNTER.lock().unwrap() = 0;
    // Give accept threads a tick to release their ports before the next test
    // binds the same one.
    std::thread::sleep(Duration::from_millis(40));
}

// ══════════════════════════════════════════════════════════════════
// Constructor
// ══════════════════════════════════════════════════════════════════

fn mesh_node_new(args: Vec<Value>) -> StdlibResult {
    let port = args
        .first()
        .map(|v| match v {
            Value::Int(n) => *n,
            _ => 0,
        })
        .unwrap_or(0);

    let bootstrap: Vec<String> = args
        .get(1)
        .map(|v| match v {
            Value::Array(items) => items.iter().map(|x| x.as_string()).collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default();

    let counter = {
        let mut c = MESH_NODE_COUNTER.lock().unwrap();
        *c += 1;
        *c
    };
    let node_id = format!("node-{}-{}", port, counter);

    // A real listener. Port 0 asks the OS for a free port; the reported port is
    // the one actually bound, so a caller can dial it.
    let bind_port = match u16::try_from(port) {
        Ok(p) if p > 0 => p,
        _ => 0,
    };
    let listener = bind_with_retry(bind_port)?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let node = Arc::new(NodeShared {
        node_id: node_id.clone(),
        port: bound as i128,
        bootstrap,
        joined: AtomicBool::new(false),
        listening: AtomicBool::new(true),
        peers: Mutex::new(Vec::new()),
        subscriptions: Mutex::new(Vec::new()),
        inbox: Mutex::new(Vec::new()),
        dht: Mutex::new(HashMap::new()),
        seen: Mutex::new(HashSet::new()),
        sent_seq: AtomicU64::new(0),
    });

    MESH_NODES
        .lock()
        .unwrap()
        .insert(node_id.clone(), Arc::clone(&node));

    {
        let node = Arc::clone(&node);
        std::thread::Builder::new()
            .name(format!("mesh-accept-{bound}"))
            .spawn(move || accept_loop(node, listener))
            .map_err(|e| format!("mesh: cannot start accept thread: {e}"))?;
    }

    Ok(Value::Struct {
        name: "MeshNode".to_string(),
        fields: vec![
            ("node_id".to_string(), Value::String(node_id)),
            ("port".to_string(), Value::Int(bound as i128)),
            ("peers".to_string(), Value::Array(Vec::new())),
            // A bound, listening socket is real; nothing about this result is
            // simulated any more.
            ("simulated".to_string(), Value::Bool(false)),
        ],
    })
}

/// Bind `127.0.0.1:port`, retrying briefly: a listener released by the previous
/// test can still be closing when the next one binds the same port.
fn bind_with_retry(port: u16) -> Result<TcpListener, String> {
    let mut last = String::new();
    for attempt in 0..25 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => return Ok(l),
            Err(e) => {
                last = e.to_string();
                if attempt < 24 {
                    std::thread::sleep(Duration::from_millis(40));
                }
            }
        }
    }
    Err(format!("mesh: cannot bind 127.0.0.1:{port}: {last}"))
}

// ══════════════════════════════════════════════════════════════════
// Networking
// ══════════════════════════════════════════════════════════════════

fn accept_loop(node: Arc<NodeShared>, listener: TcpListener) {
    while node.listening.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, addr)) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                let writer = match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let link = Arc::new(PeerLink {
                    addr: addr.to_string(),
                    writer: Mutex::new(writer),
                    peer_id: Mutex::new(None),
                });
                node.peers.lock().unwrap().push(Arc::clone(&link));
                let node2 = Arc::clone(&node);
                std::thread::spawn(move || connection_loop(node2, link, stream));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn connection_loop(node: Arc<NodeShared>, link: Arc<PeerLink>, stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        if !node.listening.load(Ordering::SeqCst) {
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(frame) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    handle_frame(&node, &link, &frame);
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn handle_frame(node: &Arc<NodeShared>, link: &Arc<PeerLink>, frame: &serde_json::Value) {
    match frame.get("t").and_then(|v| v.as_str()).unwrap_or("") {
        "hello" => {
            let peer = frame
                .get("node")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if peer.is_empty() {
                return;
            }
            let mut slot = link.peer_id.lock().unwrap();
            let first_time = slot.is_none();
            *slot = Some(peer);
            drop(slot);
            if first_time {
                // Answer once, so the dialing side learns who accepted.
                let _ = send_frame(
                    link,
                    &serde_json::json!({"t": "hello", "node": node.node_id, "port": node.port}),
                );
            }
        }
        "gossip" => {
            let id = frame.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                return;
            }
            let fresh = node.seen.lock().unwrap().insert(id.to_string());
            if !fresh {
                return;
            }
            let topic = frame
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = DhtValue::from_wire(frame.get("v").unwrap_or(&serde_json::Value::Null));
            let subscribed = node.subscriptions.lock().unwrap().iter().any(|t| *t == topic);
            if subscribed {
                node.inbox.lock().unwrap().push((topic.clone(), value.clone()));
            }
            // One more hop: a peer that is not subscribed still relays, so a
            // two-hop neighbourhood hears the message.
            let relay = serde_json::json!({
                "t": "gossip",
                "id": id,
                "from": frame.get("from"),
                "topic": topic,
                "v": value.to_wire()
            });
            let peers: Vec<Arc<PeerLink>> = node.peers.lock().unwrap().clone();
            for peer in &peers {
                if Arc::ptr_eq(peer, link) {
                    continue;
                }
                let _ = send_frame(peer, &relay);
            }
        }
        "dht" => {
            let key = frame.get("key").and_then(|v| v.as_str()).unwrap_or("");
            if key.is_empty() {
                return;
            }
            let value = DhtValue::from_wire(frame.get("v").unwrap_or(&serde_json::Value::Null));
            node.dht.lock().unwrap().insert(key.to_string(), value);
        }
        _ => {}
    }
}

fn send_frame(link: &Arc<PeerLink>, frame: &serde_json::Value) -> Result<(), String> {
    let mut w = link.writer.lock().unwrap();
    let mut line = frame.to_string();
    line.push('\n');
    w.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

// ══════════════════════════════════════════════════════════════════
// Method dispatch
// ══════════════════════════════════════════════════════════════════

fn mesh_node_method(object: &Value, method: &str, args: Vec<Value>) -> StdlibResult {
    let node_id = extract_node_id(object)?;

    match method {
        "join" => mesh_node_join(&node_id),
        "broadcast" => mesh_node_broadcast(&node_id, args),
        "subscribe" => mesh_node_subscribe(&node_id, args),
        "peers" => mesh_node_peers(&node_id),
        "dht_put" => mesh_dht_put(&node_id, args),
        "dht_get" => mesh_dht_get(&node_id, args),
        "receive" => mesh_node_receive(&node_id, args),
        _ => Err(format!("MeshNode has no method '{method}'")),
    }
}

fn peer_info_method(object: &Value, method: &str) -> StdlibResult {
    if let Value::Struct { fields, .. } = object {
        if let Some((_, value)) = fields.iter().find(|(k, _)| k == method) {
            return Ok(value.clone());
        }
        return Err(format!("PeerInfo has no field '{method}'"));
    }
    Err("PeerInfo method called on non-struct".to_string())
}

fn extract_node_id(object: &Value) -> Result<String, String> {
    if let Value::Struct { fields, .. } = object {
        return fields
            .iter()
            .find(|(k, _)| k == "node_id")
            .map(|(_, v)| v.as_string())
            .ok_or_else(|| "MeshNode missing node_id field".to_string());
    }
    Err("expected MeshNode struct".to_string())
}

fn node_by_id(node_id: &str) -> Result<Arc<NodeShared>, String> {
    MESH_NODES
        .lock()
        .unwrap()
        .get(node_id)
        .cloned()
        .ok_or_else(|| format!("MeshNode '{node_id}' not found"))
}

// ══════════════════════════════════════════════════════════════════
// MeshNode operations
// ══════════════════════════════════════════════════════════════════

fn mesh_node_join(node_id: &str) -> StdlibResult {
    let node = node_by_id(node_id)?;
    node.joined.store(true, Ordering::SeqCst);

    for addr in &node.bootstrap {
        let addr = addr.trim().to_string();
        let stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => return Err(format!("mesh: cannot connect to bootstrap {addr}: {e}")),
        };
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));

        let link = Arc::new(PeerLink {
            addr: addr.clone(),
            writer: Mutex::new(stream.try_clone().map_err(|e| e.to_string())?),
            peer_id: Mutex::new(None),
        });
        send_frame(
            &link,
            &serde_json::json!({"t": "hello", "node": node.node_id, "port": node.port}),
        )?;

        // Wait for the peer's hello so `peers()` can name it. The reader thread
        // for this connection starts after the handshake line is consumed.
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(n) if n > 0 => {
                if let Ok(frame) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                    if let Some(peer) = frame.get("node").and_then(|v| v.as_str()) {
                        *link.peer_id.lock().unwrap() = Some(peer.to_string());
                    }
                }
            }
            _ => return Err(format!("mesh: bootstrap {addr} did not answer with a hello")),
        }

        node.peers.lock().unwrap().push(Arc::clone(&link));
        let node2 = Arc::clone(&node);
        let rest = reader.into_inner();
        std::thread::spawn(move || connection_loop(node2, link, rest));
    }

    Ok(Value::Bool(true))
}

fn mesh_node_broadcast(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let topic = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "broadcast requires a topic argument".to_string())?;
    let message = args.get(1).cloned().unwrap_or(Value::Nil);
    let node = node_by_id(node_id)?;

    let seq = node.sent_seq.fetch_add(1, Ordering::SeqCst) + 1;
    let id = format!("{}:{seq}", node.node_id);
    node.seen.lock().unwrap().insert(id.clone());

    let value = DhtValue::from_value(&message);
    let frame = serde_json::json!({
        "t": "gossip", "id": id, "from": node.node_id, "topic": topic, "v": value.to_wire()
    });

    // A node subscribed to its own topic sees its own message: loopback is
    // local delivery, not a wire round trip.
    if node.subscriptions.lock().unwrap().iter().any(|t| *t == topic) {
        node.inbox.lock().unwrap().push((topic.clone(), value));
    }

    let peers: Vec<Arc<PeerLink>> = node.peers.lock().unwrap().clone();
    let mut sent = 0i128;
    for peer in &peers {
        if peer.peer_id.lock().unwrap().is_some() && send_frame(peer, &frame).is_ok() {
            sent += 1;
        }
    }
    Ok(Value::Int(sent))
}

fn mesh_node_subscribe(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let topic = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "subscribe requires a topic argument".to_string())?;
    let node = node_by_id(node_id)?;
    let mut subs = node.subscriptions.lock().unwrap();
    if !subs.contains(&topic) {
        subs.push(topic);
    }
    Ok(Value::Bool(true))
}

fn mesh_node_peers(node_id: &str) -> StdlibResult {
    let node = node_by_id(node_id)?;
    let peers: Vec<Arc<PeerLink>> = node.peers.lock().unwrap().clone();

    let mut seen = HashSet::new();
    let mut out: Vec<Value> = Vec::new();
    for peer in peers {
        let id = peer.peer_id.lock().unwrap().clone();
        // The same peer can be reachable twice (dial + accept). Report it once.
        let key = id.clone().unwrap_or_else(|| peer.addr.clone());
        if !seen.insert(key.clone()) {
            continue;
        }
        let connected = id.is_some();
        out.push(Value::Struct {
            name: "PeerInfo".to_string(),
            fields: vec![
                ("node_id".to_string(), Value::String(key)),
                ("address".to_string(), Value::String(peer.addr.clone())),
                ("connected".to_string(), Value::Bool(connected)),
                // Derived, not declared: a link is simulated exactly until its
                // hello arrives.
                ("simulated".to_string(), Value::Bool(!connected)),
            ],
        });
    }
    Ok(Value::Array(out))
}

fn mesh_dht_put(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let key = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "dht_put requires a key argument".to_string())?;
    let value = args.get(1).cloned().unwrap_or(Value::Nil);
    let node = node_by_id(node_id)?;
    let dv = DhtValue::from_value(&value);

    node.dht.lock().unwrap().insert(key.clone(), dv.clone());

    let frame = serde_json::json!({"t": "dht", "key": key, "v": dv.to_wire()});
    let peers: Vec<Arc<PeerLink>> = node.peers.lock().unwrap().clone();
    for peer in &peers {
        if peer.peer_id.lock().unwrap().is_some() {
            let _ = send_frame(peer, &frame);
        }
    }
    Ok(Value::Bool(true))
}

fn mesh_dht_get(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let key = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "dht_get requires a key argument".to_string())?;
    let node = node_by_id(node_id)?;

    // A replicated put may still be in flight; give the reader a moment.
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if let Some(val) = node.dht.lock().unwrap().get(&key) {
            return Ok(Value::Ok(Box::new(val.to_value())));
        }
        if Instant::now() >= deadline {
            return Ok(Value::Err(Box::new(Value::String("key not found".to_string()))));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn mesh_node_receive(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let topic = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "receive requires a topic argument".to_string())?;
    let node = node_by_id(node_id)?;

    // Delivery is asynchronous: wait briefly for something to arrive so that
    // `receive` after `broadcast` is not a race the caller must sleep through.
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        {
            let mut inbox = node.inbox.lock().unwrap();
            let mut kept = Vec::new();
            let mut out = Vec::new();
            for (t, msg) in inbox.drain(..) {
                if t == topic {
                    out.push(msg.to_value());
                } else {
                    kept.push((t, msg));
                }
            }
            *inbox = kept;
            if !out.is_empty() {
                return Ok(Value::Array(out));
            }
        }
        if Instant::now() >= deadline {
            return Ok(Value::Array(Vec::new()));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

/// Global test lock for mesh tests — shared across mesh.rs and interp.rs test modules.
/// All mesh tests MUST hold this lock: the registry and the ports are global.
#[cfg(test)]
pub static MESH_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = super::MESH_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        guard
    }

    #[test]
    fn test_mesh_node_new_binds_a_real_port() {
        let _lock = setup();
        let node = mesh_node_new(vec![Value::Int(9000), Value::Array(vec![])]).unwrap();
        let Value::Struct { name, fields } = &node else {
            panic!("expected MeshNode struct")
        };
        assert_eq!(name, "MeshNode");
        let port = fields.iter().find(|(k, _)| k == "port").unwrap();
        assert!(matches!(port.1, Value::Int(9000)));
        let simulated = fields.iter().find(|(k, _)| k == "simulated").unwrap();
        assert!(
            matches!(simulated.1, Value::Bool(false)),
            "a bound socket is not simulated"
        );
        // The port really is listening.
        assert!(TcpStream::connect("127.0.0.1:9000").is_ok());
    }

    #[test]
    fn test_mesh_node_join_connects_peers() {
        let _lock = setup();
        let n1 = mesh_node_new(vec![Value::Int(9001), Value::Array(vec![])]).unwrap();
        let n2 = mesh_node_new(vec![
            Value::Int(9002),
            Value::Array(vec![Value::String("localhost:9001".to_string())]),
        ])
        .unwrap();

        let id1 = extract_node_id(&n1).unwrap();
        let id2 = extract_node_id(&n2).unwrap();
        mesh_node_join(&id1).unwrap();
        mesh_node_join(&id2).unwrap();

        // The dialer learned who answered over the wire.
        let peers = mesh_node_peers(&id2).unwrap();
        let Value::Array(items) = peers else {
            panic!("expected array")
        };
        assert_eq!(items.len(), 1, "one peer");
        assert_eq!(extract_node_id(&items[0]).unwrap(), id1);

        // The acceptor learned the dialer's id from its hello.
        let back = mesh_node_peers(&id1).unwrap();
        let Value::Array(back) = back else {
            panic!("expected array")
        };
        assert!(!back.is_empty(), "acceptor must list the dialing peer");
    }

    #[test]
    fn test_mesh_broadcast_and_receive() {
        let _lock = setup();
        let n1 = mesh_node_new(vec![Value::Int(9010), Value::Array(vec![])]).unwrap();
        let id1 = extract_node_id(&n1).unwrap();
        mesh_node_join(&id1).unwrap();
        mesh_node_subscribe(&id1, vec![Value::String("test/topic".to_string())]).unwrap();

        let sent = mesh_node_broadcast(
            &id1,
            vec![
                Value::String("test/topic".to_string()),
                Value::String("hello mesh".to_string()),
            ],
        )
        .unwrap();
        assert!(matches!(sent, Value::Int(0)), "no peers to send to");

        let msgs = mesh_node_receive(&id1, vec![Value::String("test/topic".to_string())]).unwrap();
        let Value::Array(items) = msgs else {
            panic!("expected array of messages")
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_string(), "hello mesh");
    }

    #[test]
    fn test_mesh_gossip_crosses_the_wire() {
        let _lock = setup();
        let a = mesh_node_new(vec![Value::Int(9011), Value::Array(vec![])]).unwrap();
        let b = mesh_node_new(vec![
            Value::Int(9012),
            Value::Array(vec![Value::String("127.0.0.1:9011".to_string())]),
        ])
        .unwrap();
        let (ida, idb) = (extract_node_id(&a).unwrap(), extract_node_id(&b).unwrap());
        mesh_node_join(&ida).unwrap();
        mesh_node_join(&idb).unwrap();
        mesh_node_subscribe(&idb, vec![Value::String("t".to_string())]).unwrap();

        let sent = mesh_node_broadcast(
            &ida,
            vec![
                Value::String("t".to_string()),
                Value::String("hello wire".to_string()),
            ],
        )
        .unwrap();
        assert!(matches!(sent, Value::Int(1)), "one handshaken peer: {sent:?}");

        let got = mesh_node_receive(&idb, vec![Value::String("t".to_string())]).unwrap();
        let Value::Array(msgs) = got else {
            panic!("expected array")
        };
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].as_string(), "hello wire");
    }

    #[test]
    fn test_mesh_dht_put_get_roundtrip() {
        let _lock = setup();
        let n1 = mesh_node_new(vec![Value::Int(9020), Value::Array(vec![])]).unwrap();
        let id1 = extract_node_id(&n1).unwrap();
        mesh_dht_put(
            &id1,
            vec![
                Value::String("my-key".to_string()),
                Value::String("my-value".to_string()),
            ],
        )
        .unwrap();

        let result = mesh_dht_get(&id1, vec![Value::String("my-key".to_string())]).unwrap();
        if let Value::Ok(val) = result {
            assert_eq!(val.as_string(), "my-value");
        } else {
            panic!("expected Ok(value), got {result:?}");
        }
    }

    #[test]
    fn test_mesh_dht_replicates_to_peers() {
        let _lock = setup();
        let a = mesh_node_new(vec![Value::Int(9021), Value::Array(vec![])]).unwrap();
        let b = mesh_node_new(vec![
            Value::Int(9022),
            Value::Array(vec![Value::String("127.0.0.1:9021".to_string())]),
        ])
        .unwrap();
        let (ida, idb) = (extract_node_id(&a).unwrap(), extract_node_id(&b).unwrap());
        mesh_node_join(&ida).unwrap();
        mesh_node_join(&idb).unwrap();

        mesh_dht_put(
            &ida,
            vec![
                Value::String("k".to_string()),
                Value::String("v".to_string()),
            ],
        )
        .unwrap();
        let got = mesh_dht_get(&idb, vec![Value::String("k".to_string())]).unwrap();
        match got {
            Value::Ok(v) => assert_eq!(v.as_string(), "v"),
            other => panic!("replication failed: {other:?}"),
        }
    }

    #[test]
    fn test_mesh_dht_get_missing_key() {
        let _lock = setup();
        let n = mesh_node_new(vec![Value::Int(9023), Value::Array(vec![])]).unwrap();
        let id = extract_node_id(&n).unwrap();
        let result = mesh_dht_get(&id, vec![Value::String("nonexistent".to_string())]).unwrap();
        if let Value::Err(msg) = result {
            assert_eq!(msg.as_string(), "key not found");
        } else {
            panic!("expected Err for missing key, got {result:?}");
        }
    }

    #[test]
    fn test_mesh_node_peers_returns_peer_info() {
        let _lock = setup();
        let n1 = mesh_node_new(vec![Value::Int(9030), Value::Array(vec![])]).unwrap();
        let n2 = mesh_node_new(vec![
            Value::Int(9031),
            Value::Array(vec![Value::String("localhost:9030".to_string())]),
        ])
        .unwrap();

        let id1 = extract_node_id(&n1).unwrap();
        let id2 = extract_node_id(&n2).unwrap();
        mesh_node_join(&id1).unwrap();
        mesh_node_join(&id2).unwrap();

        let peers = mesh_node_peers(&id2).unwrap();
        let Value::Array(items) = peers else {
            panic!("expected array of PeerInfo")
        };
        assert_eq!(items.len(), 1);
        let Value::Struct { name, fields } = &items[0] else {
            panic!("expected PeerInfo struct")
        };
        assert_eq!(name, "PeerInfo");
        let nid = fields.iter().find(|(k, _)| k == "node_id").unwrap();
        assert_eq!(nid.1.as_string(), id1);
        let connected = fields.iter().find(|(k, _)| k == "connected").unwrap();
        assert!(matches!(connected.1, Value::Bool(true)));
    }

    #[test]
    fn test_mesh_join_to_a_dead_bootstrap_is_an_error_not_a_fake_peer() {
        let _lock = setup();
        let a = mesh_node_new(vec![
            Value::Int(9032),
            Value::Array(vec![Value::String("127.0.0.1:9".to_string())]),
        ])
        .unwrap();
        let id = extract_node_id(&a).unwrap();
        let err = mesh_node_join(&id).unwrap_err();
        assert!(err.contains("cannot connect"), "unexpected error: {err}");
        let peers = mesh_node_peers(&id).unwrap();
        let Value::Array(list) = peers else {
            panic!("expected array")
        };
        assert!(list.is_empty(), "a failed dial must not create a peer");
    }
}
