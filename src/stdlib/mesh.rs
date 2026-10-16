//! Standard library: `tallow.mesh` -- Peer-to-peer mesh networking with gossip and DHT.
//!
//! IMPORTANT: this module is an in-memory simulation of mesh networking, not a
//! real network protocol. Nodes, DHT entries, and messages live only in this
//! process's global state; nothing is sent over the wire. Every returned struct
//! carries a `simulated: true` field so callers can never mistake simulation
//! for real networking. `MeshNode.new` does perform one real action: it binds a
//! UDP socket on the requested port to validate availability.
//!
//! Global registries store string-serialized values (not Value) because
//! Value contains Rc<RefCell<...>> types that are not Send/Sync.

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

// ══════════════════════════════════════════════════════════════════
// Global registries (in-process simulation state — see module docs)
// ══════════════════════════════════════════════════════════════════

/// All mesh nodes keyed by node_id.
static MESH_NODES: LazyLock<Mutex<HashMap<String, MeshNodeState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Global DHT key-value store (shared across all nodes).
/// Values stored as (type_tag, string_repr) to avoid Value's !Send types.
static MESH_DHT: LazyLock<Mutex<HashMap<String, DhtValue>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Topic-based message store: topic -> Vec<(sender_id, DhtValue)>.
static MESH_MESSAGES: LazyLock<Mutex<HashMap<String, Vec<(String, DhtValue)>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Counter for generating unique node IDs.
static MESH_NODE_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

// ══════════════════════════════════════════════════════════════════
// Internal state
// ══════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
struct MeshNodeState {
    node_id: String,
    port: i128,
    bootstrap: Vec<String>,
    peers: Vec<String>,         // connected peer node_ids
    subscriptions: Vec<String>, // subscribed topics
    joined: bool,
}

/// Send+Sync-safe representation of a Value for global storage.
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
            // For complex types, serialize as string representation
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
pub fn reset_all() {
    MESH_NODES.lock().unwrap().clear();
    MESH_DHT.lock().unwrap().clear();
    MESH_MESSAGES.lock().unwrap().clear();
    *MESH_NODE_COUNTER.lock().unwrap() = 0;
}

// ══════════════════════════════════════════════════════════════════
// Constructor
// ══════════════════════════════════════════════════════════════════

fn mesh_node_new(args: Vec<Value>) -> StdlibResult {
    let port = args
        .first()
        .and_then(|v| match v {
            Value::Int(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0);

    let bootstrap: Vec<String> = args
        .get(1)
        .and_then(|v| match v {
            Value::Array(items) => Some(items.iter().map(|i| i.as_string()).collect()),
            _ => None,
        })
        .unwrap_or_default();

    // One real action: validate the requested port is bindable (UDP), so the
    // simulated node's port is at least a plausible local port. Port 0 means
    // "auto" and skips validation.
    if port != 0 {
        std::net::UdpSocket::bind(("0.0.0.0", port as u16))
            .map_err(|e| format!("mesh: port {port} unavailable: {e}"))?;
    }

    let mut counter = MESH_NODE_COUNTER.lock().unwrap();
    *counter += 1;
    let node_id = format!("node-{}-{}", port, *counter);
    drop(counter);

    let state = MeshNodeState {
        node_id: node_id.clone(),
        port,
        bootstrap: bootstrap.clone(),
        peers: Vec::new(),
        subscriptions: Vec::new(),
        joined: false,
    };

    MESH_NODES.lock().unwrap().insert(node_id.clone(), state);

    Ok(Value::Struct {
        name: "MeshNode".to_string(),
        fields: vec![
            ("node_id".to_string(), Value::String(node_id)),
            ("port".to_string(), Value::Int(port)),
            (
                "peers".to_string(),
                Value::Array(Vec::new()),
            ),
            // Explicit honesty marker: this node is simulated in-process.
            ("simulated".to_string(), Value::Bool(true)),
        ],
    })
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
        "dht_get" => mesh_dht_get(args),
        "receive" => mesh_node_receive(args),
        _ => Err(format!("MeshNode has no method '{method}'")),
    }
}

fn peer_info_method(object: &Value, method: &str) -> StdlibResult {
    if let Value::Struct { fields, .. } = object {
        match method {
            "node_id" => {
                let val = fields
                    .iter()
                    .find(|(k, _)| k == "node_id")
                    .map(|(_, v)| v.clone())
                    .unwrap_or(Value::Nil);
                Ok(val)
            }
            _ => Err(format!("PeerInfo has no method '{method}'")),
        }
    } else {
        Err("PeerInfo method called on non-struct".to_string())
    }
}

fn extract_node_id(object: &Value) -> Result<String, String> {
    if let Value::Struct { fields, .. } = object {
        fields
            .iter()
            .find(|(k, _)| k == "node_id")
            .map(|(_, v)| v.as_string())
            .ok_or_else(|| "MeshNode missing node_id field".to_string())
    } else {
        Err("expected MeshNode struct".to_string())
    }
}

// ══════════════════════════════════════════════════════════════════
// MeshNode operations
// ══════════════════════════════════════════════════════════════════

fn mesh_node_join(node_id: &str) -> StdlibResult {
    let mut nodes = MESH_NODES.lock().unwrap();
    let node = nodes
        .get(node_id)
        .ok_or_else(|| format!("MeshNode '{node_id}' not found"))?
        .clone();

    // Mark as joined
    nodes.get_mut(node_id).unwrap().joined = true;

    // Connect to bootstrap peers
    for addr in &node.bootstrap {
        // Extract port from address like "localhost:9001"
        let bootstrap_port: Option<i128> = addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<i128>().ok());

        if let Some(bp) = bootstrap_port {
            // Find a node with matching port
            let peer_id: Option<String> = nodes
                .iter()
                .find(|(_, s)| s.port == bp && s.node_id != node_id)
                .map(|(id, _)| id.clone());

            if let Some(pid) = peer_id {
                // Mutual connection
                let my_id = node_id.to_string();
                if !nodes[node_id].peers.contains(&pid) {
                    nodes.get_mut(node_id).unwrap().peers.push(pid.clone());
                }
                if !nodes[&pid].peers.contains(&my_id) {
                    nodes.get_mut(&pid).unwrap().peers.push(my_id);
                }
            }
        }
    }

    Ok(Value::Bool(true))
}

fn mesh_node_broadcast(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let topic = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "broadcast requires a topic argument".to_string())?;
    let message = args.get(1).cloned().unwrap_or(Value::Nil);

    let nodes = MESH_NODES.lock().unwrap();
    let node = nodes
        .get(node_id)
        .ok_or_else(|| format!("MeshNode '{node_id}' not found"))?;
    let peer_count = node.peers.len() as i128;
    drop(nodes);

    // Add message to topic
    let mut messages = MESH_MESSAGES.lock().unwrap();
    messages
        .entry(topic)
        .or_default()
        .push((node_id.to_string(), DhtValue::from_value(&message)));

    Ok(Value::Int(peer_count))
}

fn mesh_node_subscribe(node_id: &str, args: Vec<Value>) -> StdlibResult {
    let topic = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "subscribe requires a topic argument".to_string())?;

    let mut nodes = MESH_NODES.lock().unwrap();
    let node = nodes
        .get_mut(node_id)
        .ok_or_else(|| format!("MeshNode '{node_id}' not found"))?;

    if !node.subscriptions.contains(&topic) {
        node.subscriptions.push(topic);
    }

    Ok(Value::Bool(true))
}

fn mesh_node_peers(node_id: &str) -> StdlibResult {
    let nodes = MESH_NODES.lock().unwrap();
    let node = nodes
        .get(node_id)
        .ok_or_else(|| format!("MeshNode '{node_id}' not found"))?;

    let peer_infos: Vec<Value> = node
        .peers
        .iter()
        .map(|pid| {
            let peer_port = nodes
                .get(pid)
                .map(|s| s.port)
                .unwrap_or(0);
            Value::Struct {
                name: "PeerInfo".to_string(),
                fields: vec![
                    ("node_id".to_string(), Value::String(pid.clone())),
                    (
                        "address".to_string(),
                        Value::String(format!("localhost:{}", peer_port)),
                    ),
                    ("connected".to_string(), Value::Bool(true)),
                    // Honesty marker: connectivity is simulated, not probed.
                    ("simulated".to_string(), Value::Bool(true)),
                ],
            }
        })
        .collect();

    Ok(Value::Array(peer_infos))
}

fn mesh_dht_put(_node_id: &str, args: Vec<Value>) -> StdlibResult {
    let key = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "dht_put requires a key argument".to_string())?;
    let value = args.get(1).cloned().unwrap_or(Value::Nil);

    MESH_DHT.lock().unwrap().insert(key, DhtValue::from_value(&value));
    Ok(Value::Bool(true))
}

fn mesh_dht_get(args: Vec<Value>) -> StdlibResult {
    let key = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "dht_get requires a key argument".to_string())?;

    let dht = MESH_DHT.lock().unwrap();
    match dht.get(&key) {
        Some(val) => Ok(Value::Ok(Box::new(val.to_value()))),
        None => Ok(Value::Err(Box::new(Value::String("key not found".to_string())))),
    }
}

fn mesh_node_receive(args: Vec<Value>) -> StdlibResult {
    let topic = args
        .first()
        .map(|v| v.as_string())
        .ok_or_else(|| "receive requires a topic argument".to_string())?;

    let messages = MESH_MESSAGES.lock().unwrap();
    match messages.get(&topic) {
        Some(msgs) => {
            let values: Vec<Value> = msgs.iter().map(|(_, msg)| msg.to_value()).collect();
            Ok(Value::Array(values))
        }
        None => Ok(Value::Array(Vec::new())),
    }
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

/// Global test lock for mesh tests — shared across mesh.rs and interp.rs test modules.
/// All mesh tests MUST hold this lock to prevent race conditions on global state.
#[cfg(test)]
pub static MESH_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        // FIX16: recover from a poisoned lock instead of panicking. interp.rs's
        // own mesh integration tests share this lock; if one of them panics
        // while holding it (e.g. an unrelated dispatch regression makes
        // `MeshNode.new` UndefinedFn), the mutex is poisoned and every later
        // `lock().unwrap()` would fail — cascading into all mesh tests. Because
        // setup() fully resets the global state right after locking, taking
        // the guard back from a poisoned mutex is safe and restores a clean
        // baseline. (The underlying interp.rs routing bug is tracked in FIX16.)
        let guard = super::MESH_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        guard
    }

    #[test]
    fn test_mesh_node_new() {
        let _lock = setup();
        let result = mesh_node_new(vec![
            Value::Int(9000),
            Value::Array(vec![]),
        ]);
        assert!(result.is_ok());
        let node = result.unwrap();
        if let Value::Struct { name, fields } = &node {
            assert_eq!(name, "MeshNode");
            let node_id = fields.iter().find(|(k, _)| k == "node_id").unwrap();
            assert!(node_id.1.as_string().contains("9000"));
            let port = fields.iter().find(|(k, _)| k == "port").unwrap();
            assert!(matches!(port.1, Value::Int(9000)));
        } else {
            panic!("expected MeshNode struct");
        }
    }

    #[test]
    fn test_mesh_node_join_connects_peers() {
        let _lock = setup();
        // Create two nodes
        let n1 = mesh_node_new(vec![Value::Int(9001), Value::Array(vec![])]).unwrap();
        let n2 = mesh_node_new(vec![
            Value::Int(9002),
            Value::Array(vec![Value::String("localhost:9001".to_string())]),
        ])
        .unwrap();

        let id1 = extract_node_id(&n1).unwrap();
        let id2 = extract_node_id(&n2).unwrap();

        // Join both
        mesh_node_join(&id1).unwrap();
        mesh_node_join(&id2).unwrap();

        // n2 should have n1 as peer (connected via bootstrap)
        let nodes = MESH_NODES.lock().unwrap();
        assert!(
            nodes[&id2].peers.contains(&id1),
            "n2 should have n1 as peer"
        );
        assert!(
            nodes[&id1].peers.contains(&id2),
            "n1 should have n2 as peer (mutual)"
        );
    }

    #[test]
    fn test_mesh_broadcast_and_receive() {
        let _lock = setup();
        let n1 = mesh_node_new(vec![Value::Int(9010), Value::Array(vec![])]).unwrap();
        let id1 = extract_node_id(&n1).unwrap();
        mesh_node_join(&id1).unwrap();

        // Subscribe and broadcast
        mesh_node_subscribe(&id1, vec![Value::String("test/topic".to_string())]).unwrap();
        mesh_node_broadcast(
            &id1,
            vec![
                Value::String("test/topic".to_string()),
                Value::String("hello mesh".to_string()),
            ],
        )
        .unwrap();

        // Receive
        let msgs = mesh_node_receive(vec![Value::String("test/topic".to_string())]).unwrap();
        if let Value::Array(items) = msgs {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].as_string(), "hello mesh");
        } else {
            panic!("expected array of messages");
        }
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

        let result = mesh_dht_get(vec![Value::String("my-key".to_string())]).unwrap();
        if let Value::Ok(val) = result {
            assert_eq!(val.as_string(), "my-value");
        } else {
            panic!("expected Ok(value), got {:?}", result);
        }
    }

    #[test]
    fn test_mesh_dht_get_missing_key() {
        let _lock = setup();
        let result = mesh_dht_get(vec![Value::String("nonexistent".to_string())]).unwrap();
        if let Value::Err(msg) = result {
            assert_eq!(msg.as_string(), "key not found");
        } else {
            panic!("expected Err for missing key, got {:?}", result);
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
        if let Value::Array(items) = peers {
            assert_eq!(items.len(), 1);
            if let Value::Struct { name, fields } = &items[0] {
                assert_eq!(name, "PeerInfo");
                let nid = fields.iter().find(|(k, _)| k == "node_id").unwrap();
                assert_eq!(nid.1.as_string(), id1);
                let connected = fields.iter().find(|(k, _)| k == "connected").unwrap();
                assert!(matches!(connected.1, Value::Bool(true)));
            } else {
                panic!("expected PeerInfo struct");
            }
        } else {
            panic!("expected array of PeerInfo");
        }
    }
}
