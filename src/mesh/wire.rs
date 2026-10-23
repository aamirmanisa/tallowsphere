//! Mesh wire: framed, signed envelopes between coordinator and nodes.
//!
//! Design decisions (M4, recorded in docs/operations/mesh-m4-2026-10-23.md):
//!
//! - **A dedicated frame, not the CDP relay.** The relay multiplexes browser
//!   sessions by target id and has no notion of waves or task leases; borrowing
//!   it would mean shipping mesh semantics as relay payloads with no shared
//!   invariants. A 1 MiB length-prefixed JSON frame is small enough to audit.
//! - **Every frame is signed by its sender.** Join and Result carry the node's
//!   Ed25519 signature; Welcome carries the server's. The in-process control
//!   plane did not need this because the caller already owned the process;
//!   across a socket it is the difference between "a node said stop" and "the
//!   operator said stop".
//! - **Nonces are per-run and monotonic.** `(run_id, kind, nonce)` is rejected
//!   on replay, so a captured `stop` cannot be re-sent to stop a later run.
//! - **A frame that fails verification is dropped and counted**, never
//!   downgraded to "trusted because it parsed".

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};

pub const WIRE_VERSION: u8 = 1;
pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub version: u8,
    pub kind: String,
    pub run_id: String,
    pub wave: u64,
    pub node: String,
    pub nonce: u64,
    pub payload: Value,
    pub sig: Vec<u8>,
}

impl Envelope {
    pub fn new(kind: &str, run_id: &str, wave: u64, node: &str, nonce: u64, payload: Value) -> Self {
        Envelope {
            version: WIRE_VERSION,
            kind: kind.to_string(),
            run_id: run_id.to_string(),
            wave,
            node: node.to_string(),
            nonce,
            payload,
            sig: Vec::new(),
        }
    }

    /// Bytes that the signature covers. Field order and separators are fixed
    /// here, not inherited from a serializer's map ordering: two senders must
    /// sign the same bytes for the same message or verification is a lottery.
    pub fn canonical(&self) -> Vec<u8> {
        let payload = serde_json::to_string(&self.payload).unwrap_or_default();
        format!(
            "tallow-mesh/{}/{}/{}/{}/{}/{}/{}",
            self.version, self.kind, self.run_id, self.wave, self.node, self.nonce, payload
        )
        .into_bytes()
    }

    pub fn sign(&mut self, key: &SigningKey) {
        self.sig = key.sign(&self.canonical()).to_bytes().to_vec();
    }

    pub fn verify(&self, vk: &VerifyingKey) -> bool {
        let Ok(bytes) = <[u8; 64]>::try_from(self.sig.as_slice()) else {
            return false;
        };
        vk.verify(&self.canonical(), &Signature::from_bytes(&bytes))
            .is_ok()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "v": self.version,
            "kind": self.kind,
            "run_id": self.run_id,
            "wave": self.wave,
            "node": self.node,
            "nonce": self.nonce,
            "payload": self.payload,
            "sig": hex(&self.sig),
        })
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let kind = v["kind"].as_str().ok_or("frame: missing kind")?;
        let sig_hex = v["sig"].as_str().ok_or("frame: missing sig")?;
        Ok(Envelope {
            version: v["v"].as_u64().unwrap_or(0) as u8,
            kind: kind.to_string(),
            run_id: v["run_id"].as_str().unwrap_or_default().to_string(),
            wave: v["wave"].as_u64().unwrap_or(0),
            node: v["node"].as_str().unwrap_or_default().to_string(),
            nonce: v["nonce"].as_u64().unwrap_or(0),
            payload: v["payload"].clone(),
            sig: unhex(sig_hex)?,
        })
    }
}

/// Write one frame: `u32` big-endian length, then JSON. The length is checked
/// before allocation so a hostile peer cannot ask for a gigabyte.
pub fn write_frame<W: Write>(w: &mut W, env: &Envelope) -> io::Result<()> {
    let body = serde_json::to_vec(&env.to_json())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("mesh frame {} bytes exceeds {MAX_FRAME}", body.len()),
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Buffered frame reader.
///
/// A socket with a read timeout cannot be decoded with `read_exact`: a timeout
/// lands mid-frame, the bytes already consumed are gone, and the next decode
/// starts in the middle of a length prefix. This reader keeps what it has read
/// and only reports "nothing yet" when the buffer is empty at a frame boundary —
/// so a slow or frozen peer delays a frame instead of corrupting the stream.
pub struct FrameReader<R: Read> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner,
            buf: Vec::new(),
        }
    }

    /// `Ok(None)` means "no complete frame yet" — not an error, and not a
    /// partial frame thrown away.
    pub fn next(&mut self) -> io::Result<Option<Envelope>> {
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
                if len == 0 || len > MAX_FRAME {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("mesh frame length {len} outside 1..={MAX_FRAME}"),
                    ));
                }
                if self.buf.len() >= 4 + len {
                    let body: Vec<u8> = self.buf[4..4 + len].to_vec();
                    self.buf.drain(..4 + len);
                    let value: Value = serde_json::from_slice(&body)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    let env = Envelope::from_json(&value)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok(Some(env));
                }
            }
            let mut chunk = [0u8; 8192];
            match self.inner.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mesh peer closed",
                    ))
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if (e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut)
                        && self.buf.is_empty() =>
                {
                    return Ok(None)
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Mid-frame: keep what we have and try again.
                    continue
                }
                Err(e) => return Err(e),
            }
        }
    }
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Envelope> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mesh frame length {len} outside 1..={MAX_FRAME}"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Envelope::from_json(&value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Who is allowed to speak, and as whom.
pub struct Trust {
    nodes: HashMap<String, VerifyingKey>,
    operators: HashSet<[u8; 32]>,
    /// Nonces already seen, keyed `run_id:node:kind` — the replay guard.
    seen: HashSet<String>,
}

impl Trust {
    pub fn new() -> Self {
        Trust {
            nodes: HashMap::new(),
            operators: HashSet::new(),
            seen: HashSet::new(),
        }
    }

    pub fn allow_node(mut self, name: &str, vk: VerifyingKey) -> Self {
        self.nodes.insert(name.to_string(), vk);
        self
    }

    pub fn allow_operator(mut self, vk: VerifyingKey) -> Self {
        self.operators.insert(vk.to_bytes());
        self
    }

    pub fn node(&self, name: &str) -> Option<&VerifyingKey> {
        self.nodes.get(name)
    }

    /// Verify a frame from a named node, and refuse a nonce that was already
    /// used for this run+node+kind.
    pub fn accept_node(&mut self, env: &Envelope) -> Result<(), String> {
        let vk = self
            .nodes
            .get(&env.node)
            .ok_or_else(|| format!("unknown node {}", env.node))?;
        if !env.verify(vk) {
            return Err(format!("bad signature from {}", env.node));
        }
        self.check_nonce(env)
    }

    /// Control frames may be signed by any allowed operator; the frame's `node`
    /// field names the operator.
    pub fn accept_operator(&mut self, env: &Envelope) -> Result<(), String> {
        let Ok(bytes) = <[u8; 64]>::try_from(env.sig.as_slice()) else {
            return Err("control: malformed signature".to_string());
        };
        let sig = Signature::from_bytes(&bytes);
        let mut ok = false;
        for key in &self.operators {
            let Ok(vk) = VerifyingKey::from_bytes(key) else {
                continue;
            };
            if vk.verify(&env.canonical(), &sig).is_ok() {
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(format!("control: signature is not from an allowed operator ({})", env.node));
        }
        self.check_nonce(env)
    }

    fn check_nonce(&mut self, env: &Envelope) -> Result<(), String> {
        let key = format!("{}:{}:{}:{}", env.run_id, env.node, env.kind, env.nonce);
        if !self.seen.insert(key) {
            return Err(format!(
                "replayed frame: {} nonce {} from {}",
                env.kind, env.nonce, env.node
            ));
        }
        Ok(())
    }
}

impl Default for Trust {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex: odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex: {e}")))
        .collect()
}

pub fn key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SigningKey, VerifyingKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let vk = key.verifying_key();
        (key, vk)
    }

    #[test]
    fn a_signed_frame_round_trips_and_verifies() {
        let (key, vk) = pair();
        let mut env = Envelope::new("join", "run-1", 0, "w1", 1, json!({"x": 1}));
        env.sign(&key);
        let mut buf = Vec::new();
        write_frame(&mut buf, &env).unwrap();
        let got = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(got.kind, "join");
        assert!(got.verify(&vk));
    }

    #[test]
    fn tampering_with_the_payload_breaks_the_signature() {
        let (key, vk) = pair();
        let mut env = Envelope::new("assign", "run-1", 2, "w1", 1, json!({"task": "a"}));
        env.sign(&key);
        env.payload = json!({"task": "b"});
        assert!(!env.verify(&vk));
    }

    #[test]
    fn a_replayed_nonce_is_refused() {
        let (key, vk) = pair();
        let mut trust = Trust::new().allow_node("w1", vk);
        let mut env = Envelope::new("result", "run-1", 1, "w1", 5, json!({}));
        env.sign(&key);
        assert!(trust.accept_node(&env).is_ok());
        assert!(trust.accept_node(&env).unwrap_err().contains("replayed"));
    }

    #[test]
    fn an_unsigned_frame_is_refused() {
        let (_key, vk) = pair();
        let mut trust = Trust::new().allow_node("w1", vk);
        let env = Envelope::new("result", "run-1", 1, "w1", 9, json!({}));
        assert!(trust.accept_node(&env).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused_before_allocation() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
        let err = read_frame(&mut buf.as_slice()).unwrap_err();
        assert!(err.to_string().contains("outside"));
    }

    #[test]
    fn only_allowed_operators_can_send_control() {
        let (op, op_vk) = pair();
        let (other, _) = {
            let k = SigningKey::from_bytes(&[9u8; 32]);
            let v = k.verifying_key();
            (k, v)
        };
        let mut trust = Trust::new().allow_operator(op_vk);
        let mut good = Envelope::new("control", "run-1", 0, "operator", 1, json!({"cmd": "stop"}));
        good.sign(&op);
        assert!(trust.accept_operator(&good).is_ok());
        let mut bad = Envelope::new("control", "run-1", 0, "operator", 2, json!({"cmd": "stop"}));
        bad.sign(&other);
        assert!(trust.accept_operator(&bad).is_err());
    }
}
