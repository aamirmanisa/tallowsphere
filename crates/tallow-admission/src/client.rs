//! Client-side admission state machine.
//!
//! Pure: bytes in → [`Action`]s out. The client verifies the server's
//! identity against its **pinned** server key; on any handshake failure it
//! emits nothing further (a rogue server learns zero bytes about the device).

use std::collections::VecDeque;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde_json::Value;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead::AeadChan;
use crate::devkeys::DeviceIdentity;
use crate::framing::{frame, FrameDecoder};
use crate::handshake::{
    build_msg1, build_msg3, client_sig_digest, derive_session, key_fp, random_bytes, random_pad,
    s1_digest, s2_digest, s3_digest, server_sig_digest,
};
use crate::server::Action;
use crate::{now_ms, MAGIC2};

/// Client failure modes (mirrors the reference error strings where they exist).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("bad-msg2")]
    BadMsg2,
    #[error("server-auth-failed")]
    ServerAuthFailed,
    #[error("admission-refused")]
    AdmissionRefused,
    #[error("decrypt-fail")]
    DecryptFailed,
    #[error("client-deadline")]
    Deadline,
    #[error("not-admitted")]
    NotAdmitted,
}

/// Client configuration: device identity, pinned server keys, test knobs.
pub struct ClientConfig {
    /// Local device identity (id + Ed25519 key).
    pub device: DeviceIdentity,
    /// Pinned server Ed25519 public key.
    pub server_ed: VerifyingKey,
    /// Pinned server X25519 public key.
    pub server_x: PublicKey,
    /// Test knob: override the handshake timestamp (milliseconds).
    pub ts_override: Option<u64>,
    /// Test knob: flip one signature bit (tamper scenario).
    pub tamper_sig: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Wait2,
    WaitOk,
    Session,
}

/// Per-connection client state machine.
pub struct ClientSession {
    cfg: ClientConfig,
    phase: Phase,
    dec: FrameDecoder,
    eph_c: StaticSecret,
    msg1: Vec<u8>,
    s2: [u8; 32],
    msg3: Vec<u8>,
    eph_s_pub: [u8; 32],
    nonce_s: [u8; 32],
    send: Option<AeadChan>,
    recv: Option<AeadChan>,
    responses: VecDeque<Value>,
    admitted: bool,
    key_fp: Option<String>,
    closed: bool,
}

impl ClientSession {
    /// New session: generates the client ephemeral keypair and msg1.
    pub fn new(cfg: ClientConfig) -> Self {
        let eph_bytes: [u8; 32] = random_bytes(32).try_into().expect("32 bytes");
        let eph_c = StaticSecret::from(eph_bytes);
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(PublicKey::from(&eph_c).as_bytes());
        let msg1 = build_msg1(&eph_pub, random_pad());
        Self {
            cfg,
            phase: Phase::Wait2,
            dec: FrameDecoder::new(),
            eph_c,
            msg1,
            s2: [0u8; 32],
            msg3: Vec::new(),
            eph_s_pub: [0u8; 32],
            nonce_s: [0u8; 32],
            send: None,
            recv: None,
            responses: VecDeque::new(),
            admitted: false,
            key_fp: None,
            closed: false,
        }
    }

    /// The framed msg1 to send on connect.
    pub fn start(&self) -> Vec<u8> {
        frame(&self.msg1)
    }

    /// msg1 payload (unframed) — used by the rogue-server test to rebuild a
    /// rogue msg2 against the exact transcript.
    pub fn msg1_payload(&self) -> &[u8] {
        &self.msg1
    }

    /// Whether admission completed.
    pub fn is_admitted(&self) -> bool {
        self.admitted
    }

    /// Session key fingerprint (kC2S) once admitted.
    pub fn key_fp(&self) -> Option<String> {
        self.key_fp.clone()
    }

    /// Pop the next response payload (session phase).
    pub fn take_response(&mut self) -> Option<Value> {
        self.responses.pop_front()
    }

    /// Feed raw bytes (framed); returns actions for the I/O layer.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Action>, ClientError> {
        if self.closed {
            return Ok(Vec::new());
        }
        self.dec.push(chunk);
        let mut out = Vec::new();
        while let Some(payload) = self.dec.pop_frame() {
            match self.step(&payload) {
                Ok(acts) => out.extend(acts),
                Err(e) => {
                    self.closed = true;
                    return Err(e);
                }
            }
        }
        Ok(out)
    }

    /// The client deadline fired (no bytes arrived in time).
    pub fn on_deadline(&mut self) -> Result<Vec<Action>, ClientError> {
        if self.admitted {
            Ok(Vec::new())
        } else {
            self.closed = true;
            Err(ClientError::Deadline)
        }
    }

    /// Seal one request frame (session phase only).
    pub fn seal_call(&mut self, act: &str, data: Option<Value>) -> Result<Vec<u8>, ClientError> {
        let send = self.send.as_mut().ok_or(ClientError::NotAdmitted)?;
        let mut obj = serde_json::Map::new();
        obj.insert("act".to_string(), Value::String(act.to_string()));
        if let Some(d) = data {
            obj.insert("data".to_string(), d);
        }
        let bytes = serde_json::to_vec(&Value::Object(obj)).expect("json serialize");
        Ok(frame(&send.seal(&bytes)))
    }

    fn step(&mut self, payload: &[u8]) -> Result<Vec<Action>, ClientError> {
        match self.phase {
            Phase::Wait2 => self.step_wait2(payload),
            Phase::WaitOk => self.step_wait_ok(payload),
            Phase::Session => self.step_session(payload),
        }
    }

    fn step_wait2(&mut self, payload: &[u8]) -> Result<Vec<Action>, ClientError> {
        if payload.len() < 3 + 32 + 32 + 64 || &payload[..3] != MAGIC2 {
            return Err(ClientError::BadMsg2);
        }
        self.eph_s_pub.copy_from_slice(&payload[3..35]);
        self.nonce_s.copy_from_slice(&payload[35..67]);
        let mut sig_s = [0u8; 64];
        sig_s.copy_from_slice(&payload[67..131]);

        let s1 = s1_digest(&self.msg1);
        let digest = server_sig_digest(&s1, &self.eph_s_pub, &self.nonce_s);
        let sig = Signature::from_bytes(&sig_s);
        if self.cfg.server_ed.verify_strict(&digest, &sig).is_err() {
            return Err(ClientError::ServerAuthFailed);
        }
        self.s2 = s2_digest(&s1, payload);

        let ts = self.cfg.ts_override.unwrap_or_else(now_ms);
        let digest2 = client_sig_digest(&self.s2, self.cfg.device.id.as_bytes(), ts);
        let mut sig_c = self.cfg.device.ed.sign(&digest2).to_bytes();
        if self.cfg.tamper_sig {
            sig_c[0] ^= 0x01;
        }
        self.msg3 = build_msg3(&self.cfg.device.id, ts, &sig_c);
        self.phase = Phase::WaitOk;
        Ok(vec![Action::Write(frame(&self.msg3))])
    }

    fn step_wait_ok(&mut self, payload: &[u8]) -> Result<Vec<Action>, ClientError> {
        if payload != b"OK" {
            return Err(ClientError::AdmissionRefused);
        }
        // derive session keys exactly like the server
        let s3 = s3_digest(&self.s2, &self.msg3);
        let eph_s_pub = PublicKey::from(self.eph_s_pub);
        let dh1 = self.eph_c.diffie_hellman(&eph_s_pub);
        let dh2 = self.eph_c.diffie_hellman(&self.cfg.server_x);
        let keys = derive_session(&dh1, &dh2, &self.nonce_s, &s3);

        self.key_fp = Some(key_fp(&keys.k_c2s));
        self.send = Some(AeadChan::new(&keys.k_c2s, 0)); // client → server
        self.recv = Some(AeadChan::new(&keys.k_s2c, 0)); // server → client
        self.admitted = true;
        self.phase = Phase::Session;
        Ok(Vec::new())
    }

    fn step_session(&mut self, payload: &[u8]) -> Result<Vec<Action>, ClientError> {
        let plain = self
            .recv
            .as_mut()
            .expect("recv")
            .open(payload)
            .map_err(|_| ClientError::DecryptFailed)?;
        let resp: Value = serde_json::from_slice(&plain).map_err(|_| ClientError::DecryptFailed)?;
        self.responses.push_back(resp);
        Ok(Vec::new())
    }
}
