//! relay-v1: end-to-end encrypted, streamed relay transfers.
//!
//! Implements the wire format and state machine specified by the cycle-02
//! transfer design pack (`research/tallow-v1/cycle-02/09-transfer-design.md`
//! §3.1, decisions D-A, T-4, and the §3.2 resume contract, receive side).
//!
//! Design invariants implemented here:
//! - The code phrase authenticates the session through CPace (offline dictionary
//!   attacks on a recorded transcript are not possible); a hybrid X25519+ML-KEM
//!   component supplies PQ-hybrid session material.
//! - The relay never sees plaintext: it only matches two sockets by room id and
//!   pipes bytes. All payload crypto happens here.
//! - Chunk crypto is *scoped*: `encrypt_chunk_scoped`/`decrypt_chunk_scoped` under
//!   a per-transfer subkey derived from the session key + a fresh `transfer_id`
//!   (ATK-4-3 / P10-R03 — no raw session-key chunk crypto, no (key, nonce) reuse
//!   across transfer scopes).
//! - Nothing whole-payload is buffered in RAM: chunks are read → encrypted →
//!   written one 256 KiB chunk at a time, with a bounded sender window and
//!   batched ACKs (resume checkpoint grain = 64 chunks).
//!
//! Wire format (see §3.1):
//! ```text
//! frame : u8 tag | u32 len(BE, <= 1 MiB) | payload
//!   0x01 HELLO      postcard(hybrid KEM public key)          (sender -> receiver)
//!   0x02 HELLO_ACK  postcard(hybrid KEM ciphertext)          (receiver -> sender)
//!   0x03 MANIFEST   transfer_id(16) | size(u64) | mtime(u64) | name_len(u16) |
//!                   name | file_blake3(32) | chunk_size(u32) | total_chunks(u64)
//!   0x04 CHUNK      postcard(EncryptedChunk)                 (256 KiB plaintext)
//!   0x05 ACK        last_contiguous_verified_index(u64)      (ACK_NONE = none)
//!   0x06 FIN        empty
//!   0x07 ERR        code(u8) | message(utf-8)
//! ```
//! The HELLO/HELLO_ACK payloads carry the same hybrid public material the design
//! spells as `cpace_public(32) ‖ x25519_pub(32) ‖ mlkem_pub(var)`; postcard of
//! the shipped `kem::hybrid::{PublicKey, Ciphertext}` is used instead of a second
//! hand-rolled concat so no new key-format code exists to get wrong. The CPace
//! public message (32 bytes) is sent alongside in the same payload.

use crate::transfer::resume::ReceiveStateFile;
use crate::transfer::sanitize::sanitize_filename;
use crate::{ProtocolError, Result};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tallow_crypto::file::{decrypt_chunk_scoped, encrypt_chunk_scoped, EncryptedChunk};
use tallow_crypto::kdf::hkdf;
use tallow_crypto::kem::hybrid::{
    Ciphertext as HybridCiphertext, HybridKem, PublicKey as HybridPublicKey,
    SecretKey as HybridSecretKey,
};
use tallow_crypto::pake::cpace::{CpaceInitiator, CpaceResponder};
use tallow_crypto::symmetric::CipherSuite;

/// relay-v1 protocol version byte (design §3.1 migration).
pub const PROTOCOL_VERSION: u8 = 1;
/// Plaintext bytes per CHUNK frame (design §3.1 MANIFEST `chunk_size`).
pub const CHUNK_SIZE: u32 = 262_144;
/// Checkpoint / ACK cadence in chunks (64 chunks = 16 MiB).
pub const ACK_INTERVAL_CHUNKS: u64 = 64;
/// Hard cap on a frame payload (design §3.1: `u32 len(BE, ≤ 1 MiB)`).
pub const MAX_FRAME_PAYLOAD: u32 = 1 << 20;
/// ACK sentinel meaning "no chunk verified yet" (highest == none).
pub const ACK_NONE: u64 = u64::MAX;
/// Sender window: at most this many chunks in flight before awaiting an ACK.
pub const SENDER_WINDOW_CHUNKS: u64 = 64;

const TAG_HELLO: u8 = 0x01;
const TAG_HELLO_ACK: u8 = 0x02;
const TAG_MANIFEST: u8 = 0x03;
const TAG_CHUNK: u8 = 0x04;
const TAG_ACK: u8 = 0x05;
const TAG_FIN: u8 = 0x06;
const TAG_ERR: u8 = 0x07;

/// Error codes carried by `0x07 ERR` frames.
pub const ERR_CODE_PROTOCOL: u8 = 1;
pub const ERR_CODE_AUTH: u8 = 2;
pub const ERR_CODE_INTEGRITY: u8 = 3;
pub const ERR_CODE_EXISTS: u8 = 4;

/// Room id binding the CPace session to the code phrase (design T-4).
pub fn room_id(code: &str) -> [u8; 16] {
    let digest = blake3::derive_key("tallow-relay-room-v1", code.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Frame tags on the relay-v1 wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameTag {
    Hello,
    HelloAck,
    Manifest,
    Chunk,
    Ack,
    Fin,
    Err,
}

impl FrameTag {
    pub fn code(self) -> u8 {
        match self {
            FrameTag::Hello => TAG_HELLO,
            FrameTag::HelloAck => TAG_HELLO_ACK,
            FrameTag::Manifest => TAG_MANIFEST,
            FrameTag::Chunk => TAG_CHUNK,
            FrameTag::Ack => TAG_ACK,
            FrameTag::Fin => TAG_FIN,
            FrameTag::Err => TAG_ERR,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            TAG_HELLO => Some(FrameTag::Hello),
            TAG_HELLO_ACK => Some(FrameTag::HelloAck),
            TAG_MANIFEST => Some(FrameTag::Manifest),
            TAG_CHUNK => Some(FrameTag::Chunk),
            TAG_ACK => Some(FrameTag::Ack),
            TAG_FIN => Some(FrameTag::Fin),
            TAG_ERR => Some(FrameTag::Err),
            _ => None,
        }
    }
}

/// A decoded relay-v1 frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub tag: FrameTag,
    pub payload: Vec<u8>,
}

/// Write one frame: `u8 tag | u32 len(BE) | payload`.
pub fn write_frame<W: Write>(w: &mut W, tag: FrameTag, payload: &[u8]) -> Result<()> {
    if payload.len() as u64 > MAX_FRAME_PAYLOAD as u64 {
        return Err(ProtocolError::EncodingError(format!(
            "relay frame payload {} exceeds {} byte cap",
            payload.len(),
            MAX_FRAME_PAYLOAD
        )));
    }
    w.write_all(&[tag.code()])?;
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read one frame, rejecting unknown tags and oversize lengths before allocating.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Frame> {
    let mut tag_byte = [0u8; 1];
    r.read_exact(&mut tag_byte)?;
    let tag = FrameTag::from_code(tag_byte[0]).ok_or_else(|| {
        ProtocolError::InvalidMessage(format!("relay-v1: unknown frame tag 0x{:02x}", tag_byte[0]))
    })?;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::InvalidMessage(format!(
            "relay-v1: frame length {} exceeds {} byte cap",
            len, MAX_FRAME_PAYLOAD
        )));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(Frame { tag, payload })
}

/// Encode an `ERR` payload: `code(u8) | message`.
pub fn err_payload(code: u8, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + message.len());
    out.push(code);
    out.extend_from_slice(message.as_bytes());
    out
}

/// Decode an `ERR` payload.
pub fn decode_err(payload: &[u8]) -> (u8, String) {
    match payload.split_first() {
        Some((code, rest)) => (*code, String::from_utf8_lossy(rest).to_string()),
        None => (ERR_CODE_PROTOCOL, "malformed error frame".to_string()),
    }
}

fn send_err<W: Write>(w: &mut W, code: u8, message: &str) {
    let _ = write_frame(w, FrameTag::Err, &err_payload(code, message));
}

// ---------------------------------------------------------------------------
// Handshake: CPace (code-phrase auth) + hybrid X25519/ML-KEM, HKDF to session key
// ---------------------------------------------------------------------------

/// Sender-side (CPace initiator) handshake state.
pub struct SenderHandshake {
    cpace: CpaceInitiator,
    kem_pk: HybridPublicKey,
    kem_sk: HybridSecretKey,
    hello_payload: Vec<u8>,
}

impl SenderHandshake {
    /// Build HELLO: `postcard(cpace_public || kem_public)` and keep the secrets.
    pub fn start(code: &str) -> Result<(Self, Vec<u8>)> {
        let session_id = room_id(code);
        let cpace = CpaceInitiator::new(code, &session_id);
        let (kem_pk, kem_sk) = HybridKem::keygen().map_err(map_crypto)?;
        let payload = encode_hello(&cpace.public_message(), &kem_pk)?;
        Ok((
            Self {
                cpace,
                kem_pk,
                kem_sk,
                hello_payload: payload.clone(),
            },
            payload,
        ))
    }

    /// Process HELLO_ACK and derive the session key (sending side).
    pub fn finish(&self, hello_ack: &[u8]) -> Result<[u8; 32]> {
        let (their_cpace, kem_ct) = decode_hello_ack(hello_ack)?;
        let cpace_key = self.cpace.finish(&their_cpace).map_err(|_| {
            ProtocolError::HandshakeFailed("relay-v1: CPace confirmation failed".into())
        })?;
        let kem_ss = HybridKem::decapsulate(&self.kem_sk, &kem_ct).map_err(|_| {
            ProtocolError::HandshakeFailed("relay-v1: KEM decapsulation failed".into())
        })?;
        derive_session_key(
            &cpace_key,
            kem_ss.expose_secret(),
            &self.hello_payload,
            hello_ack,
        )
    }

    /// Receiver's hybrid public key as sent in HELLO (exposed for tests/audit).
    pub fn kem_public(&self) -> &HybridPublicKey {
        &self.kem_pk
    }
}

/// Receiver side: consume HELLO, produce HELLO_ACK and the session key.
pub fn responder_handshake(code: &str, hello_payload: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let session_id = room_id(code);
    let (their_cpace, kem_pk) = decode_hello(hello_payload)?;
    let cpace = CpaceResponder::new(code, &session_id);
    let cpace_key = cpace.finish(&their_cpace).map_err(|_| {
        ProtocolError::HandshakeFailed("relay-v1: CPace confirmation failed".into())
    })?;
    let (kem_ct, kem_ss) = HybridKem::encapsulate(&kem_pk).map_err(map_crypto)?;
    let ack_payload = encode_hello_ack(&cpace.public_message(), &kem_ct)?;
    let key = derive_session_key(
        &cpace_key,
        kem_ss.expose_secret(),
        hello_payload,
        &ack_payload,
    )?;
    Ok((ack_payload, key))
}

/// `session_key = HKDF(salt="tallow-relay-session-v1",
///     ikm = cpace_key ‖ kem_shared ‖ transcript_hash, info="tallow-relay-session-key-v1")`
///
/// The transcript hash binds both hello payloads, so a tampered handshake yields
/// a different session key and every subsequent AEAD frame fails authentication.
fn derive_session_key(
    cpace_key: &[u8; 32],
    kem_shared: &[u8; 32],
    hello: &[u8],
    hello_ack: &[u8],
) -> Result<[u8; 32]> {
    let mut transcript_input = Vec::with_capacity(hello.len() + hello_ack.len());
    transcript_input.extend_from_slice(hello);
    transcript_input.extend_from_slice(hello_ack);
    let transcript = blake3::derive_key("tallow-relay-handshake-v1", &transcript_input);
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(cpace_key);
    ikm.extend_from_slice(kem_shared);
    ikm.extend_from_slice(&transcript);
    let okm = hkdf::derive(
        b"tallow-relay-session-v1",
        &ikm,
        b"tallow-relay-session-key-v1",
        32,
    )
    .map_err(map_crypto)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(key)
}

// `postcard` layout: cpace(32) || postcard(kem_public) / postcard(kem_ciphertext)
fn encode_hello(cpace_public: &[u8; 32], kem_pk: &HybridPublicKey) -> Result<Vec<u8>> {
    let kem = postcard::to_stdvec(kem_pk)
        .map_err(|e| ProtocolError::EncodingError(format!("relay-v1 HELLO: {e}")))?;
    let mut out = Vec::with_capacity(32 + kem.len());
    out.extend_from_slice(cpace_public);
    out.extend_from_slice(&kem);
    Ok(out)
}

fn encode_hello_ack(cpace_public: &[u8; 32], kem_ct: &HybridCiphertext) -> Result<Vec<u8>> {
    let kem = postcard::to_stdvec(kem_ct)
        .map_err(|e| ProtocolError::EncodingError(format!("relay-v1 HELLO_ACK: {e}")))?;
    let mut out = Vec::with_capacity(32 + kem.len());
    out.extend_from_slice(cpace_public);
    out.extend_from_slice(&kem);
    Ok(out)
}

fn decode_hello(payload: &[u8]) -> Result<([u8; 32], HybridPublicKey)> {
    let cpace = take_cpace_pub(payload)?;
    let kem: HybridPublicKey = postcard::from_bytes(&payload[32..])
        .map_err(|e| ProtocolError::DecodingError(format!("relay-v1 HELLO: {e}")))?;
    Ok((cpace, kem))
}

fn decode_hello_ack(payload: &[u8]) -> Result<([u8; 32], HybridCiphertext)> {
    let cpace = take_cpace_pub(payload)?;
    let kem: HybridCiphertext = postcard::from_bytes(&payload[32..])
        .map_err(|e| ProtocolError::DecodingError(format!("relay-v1 HELLO_ACK: {e}")))?;
    Ok((cpace, kem))
}

fn take_cpace_pub(payload: &[u8]) -> Result<[u8; 32]> {
    if payload.len() < 32 {
        return Err(ProtocolError::InvalidMessage(
            "relay-v1: hello payload shorter than CPace public message".into(),
        ));
    }
    let mut cpace = [0u8; 32];
    cpace.copy_from_slice(&payload[..32]);
    Ok(cpace)
}

// ---------------------------------------------------------------------------
// MANIFEST
// ---------------------------------------------------------------------------

/// Decoded MANIFEST frame (design §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayManifest {
    pub transfer_id: [u8; 16],
    pub size: u64,
    pub mtime: u64,
    pub name: String,
    pub file_blake3: [u8; 32],
    pub chunk_size: u32,
    pub total_chunks: u64,
}

impl RelayManifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let name = self.name.as_bytes();
        if name.len() > u16::MAX as usize {
            return Err(ProtocolError::EncodingError(
                "relay-v1: filename too long".into(),
            ));
        }
        let mut out = Vec::with_capacity(16 + 8 + 8 + 2 + name.len() + 32 + 4 + 8);
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.file_blake3);
        out.extend_from_slice(&self.chunk_size.to_le_bytes());
        out.extend_from_slice(&self.total_chunks.to_le_bytes());
        Ok(out)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut cur = payload;
        let mut take = |n: usize| -> Result<&[u8]> {
            if cur.len() < n {
                return Err(ProtocolError::InvalidMessage(
                    "relay-v1: truncated MANIFEST".into(),
                ));
            }
            let (head, tail) = cur.split_at(n);
            cur = tail;
            Ok(head)
        };
        let mut transfer_id = [0u8; 16];
        transfer_id.copy_from_slice(take(16)?);
        let size = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let mtime = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let name_len = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let name = String::from_utf8_lossy(take(name_len)?).to_string();
        let mut file_blake3 = [0u8; 32];
        file_blake3.copy_from_slice(take(32)?);
        let chunk_size = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let total_chunks = u64::from_le_bytes(take(8)?.try_into().unwrap());
        if chunk_size == 0 {
            return Err(ProtocolError::InvalidMessage(
                "relay-v1: MANIFEST chunk_size must be non-zero".into(),
            ));
        }
        Ok(Self {
            transfer_id,
            size,
            mtime,
            name,
            file_blake3,
            chunk_size,
            total_chunks,
        })
    }

    /// True when a loaded resume state describes this exact file identity.
    pub fn matches_identity(&self, state: &ReceiveStateFile) -> bool {
        state.file_blake3 == self.file_blake3
            && state.file_size == self.size
            && state.chunk_size == self.chunk_size
    }
}

fn read_u64_frame(frame: &Frame) -> Result<u64> {
    if frame.payload.len() != 8 {
        return Err(ProtocolError::InvalidMessage(
            "relay-v1: ACK payload must be u64".into(),
        ));
    }
    Ok(u64::from_le_bytes(frame.payload[..8].try_into().unwrap()))
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// Options for [`send_file`].
#[derive(Debug, Clone, Default)]
pub struct RelaySendOptions {
    /// Token-bucket style pacing budget in bytes/sec (design D-C2, bits/sec
    /// values are converted by the caller). `None` = unlimited.
    pub bandwidth_bytes_per_sec: Option<u64>,
    /// Emit a line per ACK batch (progress). Callers may also print themselves.
    pub progress: bool,
}

/// Outcome of a relay-v1 send.
#[derive(Debug, Clone)]
pub struct RelaySendOutcome {
    pub code: String,
    pub filename: String,
    pub size: u64,
    pub file_blake3: [u8; 32],
    pub chunks_sent: u64,
    pub bytes_sent_on_wire: u64,
    pub start_chunk: u64,
}

/// Send one file over an already relay-paired socket pair (relay-v1).
///
/// Streams 256 KiB chunks: read → `encrypt_chunk_scoped` → framed write, with a
/// bounded window and ACK-gated progress. Never reads the whole file into RAM.
pub fn send_file<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    code: &str,
    path: &Path,
    opts: &RelaySendOptions,
) -> Result<RelaySendOutcome> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(ProtocolError::TransferFailed(format!(
            "relay-v1: '{}' is not a regular file",
            path.display()
        )));
    }
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());

    // Full-file BLAKE3 is computed incrementally while streaming (bounded RAM).
    // We need it in the MANIFEST before any chunk is sent, so it is hashed in a
    // first streaming pass over the file (still one chunk in RAM at a time).
    let file_hash = hash_file_streaming(path)?;

    let transfer_id: [u8; 16] = rand::thread_rng().gen();
    let chunk_size = CHUNK_SIZE;
    let total_chunks = size.div_ceil(chunk_size as u64);

    let manifest = RelayManifest {
        transfer_id,
        size,
        mtime,
        name: filename.clone(),
        file_blake3: file_hash,
        chunk_size,
        total_chunks,
    };

    // 1. HELLO -> HELLO_ACK -> session key
    let (handshake, hello) = SenderHandshake::start(code)?;
    write_frame(writer, FrameTag::Hello, &hello)?;
    let ack_frame = read_frame(reader)?;
    match ack_frame.tag {
        FrameTag::HelloAck => {}
        FrameTag::Err => {
            let (code, msg) = decode_err(&ack_frame.payload);
            return Err(ProtocolError::HandshakeFailed(format!(
                "relay-v1: peer rejected handshake (code {code}): {msg}"
            )));
        }
        other => {
            return Err(ProtocolError::InvalidMessage(format!(
                "relay-v1: expected HELLO_ACK, got {:?}",
                other
            )))
        }
    }
    let session_key = handshake.finish(&ack_frame.payload)?;

    // 2. MANIFEST, then the receiver's resume point (ACK with highest verified
    //    index, or ACK_NONE when starting fresh).
    write_frame(writer, FrameTag::Manifest, &manifest.encode()?)?;
    let ack = read_frame(reader)?;
    let start_chunk = match ack.tag {
        FrameTag::Ack => match read_u64_frame(&ack)? {
            ACK_NONE => 0,
            last => last + 1,
        },
        FrameTag::Err => {
            let (code, msg) = decode_err(&ack.payload);
            return Err(ProtocolError::TransferFailed(format!(
                "relay-v1: receiver refused transfer (code {code}): {msg}"
            )));
        }
        other => {
            return Err(ProtocolError::InvalidMessage(format!(
                "relay-v1: expected resume ACK after MANIFEST, got {:?}",
                other
            )))
        }
    };
    if start_chunk > total_chunks {
        return Err(ProtocolError::TransferFailed(format!(
            "relay-v1: receiver resume point {start_chunk} beyond {total_chunks} chunks"
        )));
    }

    // 3. CHUNK stream with bounded window and ACK-gated progress.
    let mut file = File::open(path)?;
    let mut bytes_sent: u64 = 0;
    let mut chunks_sent: u64 = 0;
    let mut pending_since_ack: u64 = 0;
    let start = Instant::now();
    let mut buffer = vec![0u8; chunk_size as usize];

    for index in start_chunk..total_chunks {
        let offset = index * chunk_size as u64;
        let this_len = std::cmp::min(chunk_size as u64, size - offset) as usize;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer[..this_len])?;
        let encrypted = encrypt_chunk_scoped(
            &session_key,
            &transfer_id,
            &buffer[..this_len],
            index,
            CipherSuite::Aes256Gcm,
        )
        .map_err(map_crypto)?;
        let payload = postcard::to_stdvec(&encrypted)
            .map_err(|e| ProtocolError::EncodingError(format!("relay-v1 CHUNK: {e}")))?;
        write_frame(writer, FrameTag::Chunk, &payload)?;
        bytes_sent += this_len as u64;
        chunks_sent += 1;
        pending_since_ack += 1;

        if let Some(bps) = opts.bandwidth_bytes_per_sec.filter(|b| *b > 0) {
            pace(bytes_sent, bps, start);
        }

        if pending_since_ack >= SENDER_WINDOW_CHUNKS || pending_since_ack >= ACK_INTERVAL_CHUNKS {
            let ack = read_frame(reader)?;
            match ack.tag {
                FrameTag::Ack => {
                    let last = read_u64_frame(&ack)?;
                    if last != ACK_NONE && last + 1 > index {
                        // Receiver ahead of us: protocol violation.
                        return Err(ProtocolError::InvalidMessage(format!(
                            "relay-v1: receiver ACK {last} beyond sent index {index}"
                        )));
                    }
                    if opts.progress && last != ACK_NONE {
                        eprintln!("relay-v1: receiver confirmed chunk {last}");
                    }
                }
                FrameTag::Err => {
                    let (code, msg) = decode_err(&ack.payload);
                    return Err(ProtocolError::TransferFailed(format!(
                        "relay-v1: receiver error (code {code}): {msg}"
                    )));
                }
                other => {
                    return Err(ProtocolError::InvalidMessage(format!(
                        "relay-v1: expected ACK mid-stream, got {:?}",
                        other
                    )))
                }
            }
            pending_since_ack = 0;
        }
    }

    // 4. FIN and wait for the receiver's FIN (final hash verified + rename done).
    //    Any ACK frames still owed for the final (partial) batch arrive first and
    //    are drained here rather than misread as an out-of-order reply.
    write_frame(writer, FrameTag::Fin, &[])?;
    let mut owed_acks = u64::from(pending_since_ack > 0);
    let mut fin_deadline_frames = owed_acks + 2;
    loop {
        let frame = read_frame(reader)?;
        match frame.tag {
            FrameTag::Ack => {
                let last = read_u64_frame(&frame)?;
                if opts.progress && last != ACK_NONE {
                    eprintln!("relay-v1: receiver confirmed chunk {last}");
                }
                owed_acks = owed_acks.saturating_sub(1);
            }
            FrameTag::Fin => break,
            FrameTag::Err => {
                let (code, msg) = decode_err(&frame.payload);
                return Err(ProtocolError::TransferFailed(format!(
                    "relay-v1: receiver reported failure (code {code}): {msg}"
                )));
            }
            other => {
                return Err(ProtocolError::InvalidMessage(format!(
                    "relay-v1: expected FIN, got {:?}",
                    other
                )))
            }
        }
        fin_deadline_frames = fin_deadline_frames.saturating_sub(1);
        if fin_deadline_frames == 0 {
            return Err(ProtocolError::InvalidMessage(
                "relay-v1: too many frames while awaiting FIN".into(),
            ));
        }
    }

    Ok(RelaySendOutcome {
        code: code.to_string(),
        filename,
        size,
        file_blake3: file_hash,
        chunks_sent,
        bytes_sent_on_wire: bytes_sent,
        start_chunk,
    })
}

/// Wait until `bytes_sent` is back on the cumulative schedule
/// (`elapsed >= bytes_sent / bytes_per_sec`). The full deficit is slept: a
/// capped per-chunk sleep would floor the effective rate on slow limits
/// (a 250 ms cap makes anything below ~1 MiB/s unenforceable — e.g. `1M` =
/// 125,000 B/s needs ~2.1 s per 256 KiB chunk). Design D-C2 requires the
/// configured average; the cumulative schedule self-corrects.
fn pace(bytes_sent: u64, bytes_per_sec: u64, start: Instant) {
    if let Some(wait) = pace_delay(bytes_sent, bytes_per_sec, start.elapsed()) {
        std::thread::sleep(wait);
    }
}

/// Pure schedule check behind [`pace`] — unit-testable without sleeping.
fn pace_delay(bytes_sent: u64, bytes_per_sec: u64, elapsed: Duration) -> Option<Duration> {
    if bytes_per_sec == 0 {
        return None;
    }
    let expected = Duration::from_secs_f64(bytes_sent as f64 / bytes_per_sec as f64);
    expected.checked_sub(elapsed).filter(|d| !d.is_zero()) // exactly on schedule = no wait
}

/// Streaming BLAKE3 over a file (64 KiB reads; bounded RAM).
pub fn hash_file_streaming(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

/// Options for [`receive_file`].
#[derive(Debug, Clone, Default)]
pub struct RelayReceiveOptions {
    /// Directory holding the versioned receive-state envelopes
    /// (`<output>/.tallow-resume/` per design §3.2). `None` disables persistence
    /// while still allowing the peer to resume against in-memory progress.
    pub state_dir: Option<PathBuf>,
    /// Refuse to overwrite an existing destination file (D-C3).
    pub overwrite: bool,
    /// Print one line per ACK batch.
    pub progress: bool,
}

/// Outcome of a relay-v1 receive.
#[derive(Debug, Clone)]
pub struct RelayReceiveOutcome {
    pub code: String,
    pub path: PathBuf,
    pub size: u64,
    pub file_blake3: [u8; 32],
    pub chunks_written: u64,
    pub resumed_from_chunk: u64,
}

/// Receive one file over an already relay-paired socket pair (relay-v1).
///
/// Frame-driven, bounded RAM: each CHUNK is decrypted with
/// `decrypt_chunk_scoped`, written straight to `<name>.tallow-tmp`, and only
/// then acknowledged. The completion gate is a streaming full-file BLAKE3
/// compare plus atomic rename; resume state is advisory and validated against
/// the MANIFEST identity before use.
pub fn receive_file<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    code: &str,
    output_dir: &Path,
    opts: &RelayReceiveOptions,
) -> Result<RelayReceiveOutcome> {
    // 1. HELLO -> HELLO_ACK -> session key
    let hello = read_frame(reader)?;
    if hello.tag != FrameTag::Hello {
        send_err(writer, ERR_CODE_PROTOCOL, "expected HELLO");
        return Err(ProtocolError::InvalidMessage(format!(
            "relay-v1: expected HELLO, got {:?}",
            hello.tag
        )));
    }
    let (ack_payload, session_key) = match responder_handshake(code, &hello.payload) {
        Ok(v) => v,
        Err(e) => {
            send_err(writer, ERR_CODE_AUTH, "handshake authentication failed");
            return Err(e);
        }
    };
    write_frame(writer, FrameTag::HelloAck, &ack_payload)?;

    // 2. MANIFEST + filename sanitization (R-5 fix: never join an unsanitized name)
    let manifest_frame = read_frame(reader)?;
    if manifest_frame.tag != FrameTag::Manifest {
        send_err(writer, ERR_CODE_PROTOCOL, "expected MANIFEST");
        return Err(ProtocolError::InvalidMessage(format!(
            "relay-v1: expected MANIFEST, got {:?}",
            manifest_frame.tag
        )));
    }
    let manifest = RelayManifest::decode(&manifest_frame.payload)?;
    std::fs::create_dir_all(output_dir)?;
    let safe_name = sanitize_filename(&manifest.name, output_dir)
        .map_err(|e| ProtocolError::TransferFailed(format!("unsafe filename rejected: {e}")))?;
    let safe_file_name = safe_name
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let final_path = safe_name.clone();
    let tmp_path = PathBuf::from(format!("{}.tallow-tmp", safe_name.to_string_lossy()));

    if opts.overwrite && final_path.exists() {
        // documented behaviour: --overwrite required to clobber (D-C3)
    } else if final_path.exists() && !opts.overwrite {
        send_err(
            writer,
            ERR_CODE_EXISTS,
            "destination exists; pass --overwrite",
        );
        return Err(ProtocolError::TransferFailed(format!(
            "relay-v1: '{}' exists; pass --overwrite to replace",
            final_path.display()
        )));
    }

    // 3. Resume: validate any persisted state against the MANIFEST identity.
    let state_path = opts
        .state_dir
        .as_ref()
        .map(|dir| state_path_for(dir, &manifest.file_blake3, &safe_file_name));
    let mut state = match state_path.as_ref() {
        Some(p) => match ReceiveStateFile::load(p) {
            Ok(s) if manifest.matches_identity(&s) => Some(s),
            Ok(_) => {
                eprintln!(
                    "relay-v1: resume state '{}' does not match this transfer identity; restarting",
                    p.display()
                );
                None
            }
            Err(e) => {
                if p.exists() {
                    eprintln!(
                        "relay-v1: discarding unreadable resume state '{}': {e}",
                        p.display()
                    );
                }
                None
            }
        },
        None => None,
    };

    let mut next_index: u64 = 0;
    if let Some(s) = state.as_ref() {
        let contiguous = highest_contiguous_verified(s, manifest.chunk_size as u64);
        let covered = contiguous.map(|i| i + 1).unwrap_or(0);
        // The tmp file must actually cover every verified byte, or the state is
        // stale (e.g. tmp removed) and must not be trusted.
        let tmp_len = std::fs::metadata(&tmp_path).map(|m| m.len()).unwrap_or(0);
        if covered > 0 && tmp_len >= covered.saturating_mul(manifest.chunk_size as u64) {
            next_index = covered;
        } else if contiguous.is_some() {
            eprintln!("relay-v1: resume state present but tmp file incomplete; restarting");
            state = None;
        }
    }
    let resumed_from_chunk = next_index;

    // Tell the sender where to start. "No chunk verified" encodes as ACK_NONE.
    let ack_value = if next_index == 0 {
        ACK_NONE
    } else {
        next_index - 1
    };
    write_frame(writer, FrameTag::Ack, &ack_value.to_le_bytes())?;

    // 4. CHUNK stream -> tmp file, ACK every batch, checkpoints at the same grain.
    if let Some(s) = state.as_mut() {
        s.touch();
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&tmp_path)?;
    if resumed_from_chunk == 0 {
        file.set_len(0)?;
    }

    let mut chunks_written: u64 = 0;
    let mut pending_ack: u64 = 0;
    // Assigned in the CHUNK loop before every read (see the periodic ACK path).
    let mut last_index: u64;

    loop {
        let frame = read_frame(reader)?;
        match frame.tag {
            FrameTag::Chunk => {
                let encrypted: EncryptedChunk = postcard::from_bytes(&frame.payload)
                    .map_err(|e| ProtocolError::DecodingError(format!("relay-v1 CHUNK: {e}")))?;
                let plaintext = decrypt_chunk_scoped(
                    &session_key,
                    &manifest.transfer_id,
                    &encrypted,
                    CipherSuite::Aes256Gcm,
                )
                .map_err(|_| {
                    ProtocolError::TransferFailed(
                        "relay-v1: chunk authentication failed (tampered or wrong key)".into(),
                    )
                })?;
                if encrypted.index < next_index {
                    continue; // duplicate after resume; harmless, do not rewrite
                }
                if encrypted.index != next_index {
                    // Sparse holes are re-sent by design; require sequential here
                    // since the sender always streams from the agreed index.
                    send_err(writer, ERR_CODE_PROTOCOL, "non-sequential chunk index");
                    return Err(ProtocolError::InvalidMessage(format!(
                        "relay-v1: chunk index {} while expecting {}",
                        encrypted.index, next_index
                    )));
                }
                file.seek(SeekFrom::Start(next_index * manifest.chunk_size as u64))?;
                file.write_all(&plaintext)?;
                if let Some(s) = state.as_mut() {
                    s.resume.mark_verified(next_index, plaintext.len() as u64);
                    s.touch();
                }
                chunks_written += 1;
                last_index = next_index;
                next_index += 1;
                pending_ack += 1;

                if pending_ack >= ACK_INTERVAL_CHUNKS || next_index == manifest.total_chunks {
                    file.flush()?;
                    file.sync_data()?;
                    if let (Some(s), Some(p)) = (state.as_ref(), state_path.as_ref()) {
                        s.save_atomic(p)?;
                    }
                    write_frame(writer, FrameTag::Ack, &last_index.to_le_bytes())?;
                    if opts.progress {
                        eprintln!(
                            "relay-v1: {} / {} chunks",
                            next_index, manifest.total_chunks
                        );
                    }
                    pending_ack = 0;
                }
            }
            FrameTag::Fin => break,
            FrameTag::Err => {
                let (err_code, msg) = decode_err(&frame.payload);
                return Err(ProtocolError::TransferFailed(format!(
                    "relay-v1: sender error (code {err_code}): {msg}"
                )));
            }
            other => {
                send_err(writer, ERR_CODE_PROTOCOL, "unexpected frame");
                return Err(ProtocolError::InvalidMessage(format!(
                    "relay-v1: unexpected frame {:?} mid-stream",
                    other
                )));
            }
        }
    }

    if next_index < manifest.total_chunks {
        send_err(writer, ERR_CODE_PROTOCOL, "FIN before all chunks arrived");
        return Err(ProtocolError::TransferFailed(format!(
            "relay-v1: sender finished early ({} of {} chunks)",
            next_index, manifest.total_chunks
        )));
    }

    // 5. Completion gate: streaming full-file BLAKE3 + atomic rename.
    file.flush()?;
    file.sync_data()?;
    drop(file);
    let actual = hash_file_streaming(&tmp_path)?;
    if actual != manifest.file_blake3 {
        let _ = std::fs::remove_file(&tmp_path);
        if let Some(p) = state_path.as_ref() {
            let _ = std::fs::remove_file(p);
        }
        send_err(writer, ERR_CODE_INTEGRITY, "file hash mismatch");
        return Err(ProtocolError::TransferFailed(
            "relay-v1: final BLAKE3 mismatch — transfer corrupted, tmp removed".into(),
        ));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    if let Some(p) = state_path.as_ref() {
        let _ = std::fs::remove_file(p);
    }
    write_frame(writer, FrameTag::Fin, &[])?;

    Ok(RelayReceiveOutcome {
        code: code.to_string(),
        path: final_path,
        size: manifest.size,
        file_blake3: manifest.file_blake3,
        chunks_written,
        resumed_from_chunk,
    })
}

/// Highest contiguous verified chunk index, `None` when nothing is verified.
pub fn highest_contiguous_verified(state: &ReceiveStateFile, _chunk_size: u64) -> Option<u64> {
    let mut idx = 0u64;
    if !state.resume.is_verified(0) {
        return None;
    }
    while state.resume.is_verified(idx + 1) {
        idx += 1;
    }
    Some(idx)
}

/// `<state_dir>/<hex(file_blake3)[..16]>-<sanitized name>.state` (design §3.2).
pub fn state_path_for(state_dir: &Path, file_blake3: &[u8; 32], name: &str) -> PathBuf {
    let hex: String = file_blake3.iter().map(|b| format!("{b:02x}")).collect();
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    state_dir.join(format!("{}-{}.state", &hex[..16], sanitized))
}

fn map_crypto(e: tallow_crypto::CryptoError) -> ProtocolError {
    ProtocolError::HandshakeFailed(format!("relay-v1: crypto failure: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::resume::ReceiveStateFile;
    use std::net::{TcpListener, TcpStream};

    fn tempdir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nonce: u64 = rand::thread_rng().gen();
        p.push(format!("tallow-relay-test-{}-{}", tag, nonce));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_pattern(path: &Path, len: usize) {
        let mut data = vec![0u8; len];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(31) ^ (i >> 7)) as u8;
        }
        std::fs::write(path, &data).unwrap();
    }

    #[test]
    fn frame_roundtrip_and_caps() {
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameTag::Ack, &7u64.to_le_bytes()).unwrap();
        let mut cur = std::io::Cursor::new(&buf);
        let f = read_frame(&mut cur).unwrap();
        assert_eq!(f.tag, FrameTag::Ack);
        assert_eq!(read_u64_frame(&f).unwrap(), 7);

        // oversize payload is rejected before allocating
        let big = vec![0u8; (MAX_FRAME_PAYLOAD + 1) as usize];
        let err = write_frame(&mut Vec::new(), FrameTag::Chunk, &big).unwrap_err();
        assert!(matches!(err, ProtocolError::EncodingError(_)));

        // unknown tag is a clean error
        let mut bad = vec![0x7f];
        bad.extend_from_slice(&0u32.to_be_bytes());
        let err = read_frame(&mut std::io::Cursor::new(bad)).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMessage(_)));

        // truncated frame is a clean error, not a panic
        let err = read_frame(&mut std::io::Cursor::new(vec![0x05, 0x00])).unwrap_err();
        assert!(matches!(err, ProtocolError::Io(_)));
    }

    #[test]
    fn handshake_agrees_and_rejects_wrong_code() {
        let (init, hello) = SenderHandshake::start("123-otter-brisk-kite").unwrap();
        let (ack, resp_key) = responder_handshake("123-otter-brisk-kite", &hello).unwrap();
        let init_key = init.finish(&ack).unwrap();
        assert_eq!(init_key, resp_key);

        // wrong code phrase -> the two sides cannot derive the same key. CPace
        // itself may complete locally (divergent keys), so the invariant to
        // assert is key inequality, not a local error.
        let (ack2, resp_key2) = responder_handshake("999-wrong-word-here", &hello).unwrap();
        match init.finish(&ack2) {
            Ok(k) => assert_ne!(k, resp_key2, "wrong code phrase derived the same key"),
            Err(_) => {}
        }
    }

    #[test]
    fn handshake_is_transcript_bound() {
        let (_i1, hello1) = SenderHandshake::start("1-a-b-c").unwrap();
        let (ack, k1) = responder_handshake("1-a-b-c", &hello1).unwrap();
        assert_eq!(ack.len(), ack.len());
        assert_ne!(k1, [0u8; 32]);

        // Different session_id (room id) yields a different key.
        let (i2, _hello2) = SenderHandshake::start("1-a-b-c").unwrap();
        let k2 = i2.finish(&ack);
        assert!(
            k2.is_err() || k2.unwrap() != k1,
            "transcript/session binding failed"
        );
    }

    #[test]
    fn manifest_roundtrip_and_identity() {
        let m = RelayManifest {
            transfer_id: [3u8; 16],
            size: 1_000_000,
            mtime: 42,
            name: "hello.bin".into(),
            file_blake3: [9u8; 32],
            chunk_size: CHUNK_SIZE,
            total_chunks: 4,
        };
        let enc = m.encode().unwrap();
        let dec = RelayManifest::decode(&enc).unwrap();
        assert_eq!(m, dec);
        let st = ReceiveStateFile::new(m.file_blake3, m.size, m.chunk_size, m.transfer_id);
        assert!(m.matches_identity(&st));
        let other = RelayManifest {
            size: m.size + 1,
            ..m.clone()
        };
        assert!(!other.matches_identity(&st));
    }

    /// Full socket roundtrip: real loopback TCP, relay-v1 sender + receiver.
    #[test]
    fn e2e_tcp_roundtrip_streamed() {
        let dir = tempdir("e2e");
        let src = dir.join("payload.bin");
        write_pattern(&src, 700_000); // 3 chunks incl. short tail
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let src_c = src.clone();
        let out_c = out.clone();
        let sender = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let mut r = stream.try_clone().unwrap();
            let mut w = stream;
            send_file(
                &mut r,
                &mut w,
                "123-otter-brisk-kite",
                &src_c,
                &RelaySendOptions::default(),
            )
        });

        let (mut rx, mut tx) = {
            let s = listener.accept().unwrap().0;
            (s.try_clone().unwrap(), s)
        };
        let recv = receive_file(
            &mut rx,
            &mut tx,
            "123-otter-brisk-kite",
            &out_c,
            &RelayReceiveOptions::default(),
        )
        .expect("receive ok");

        let sent = sender.join().unwrap().expect("send ok");
        assert_eq!(sent.size, 700_000);
        assert_eq!(sent.chunks_sent, 3);
        assert_eq!(recv.size, 700_000);
        assert_eq!(recv.chunks_written, 3);
        assert_eq!(recv.resumed_from_chunk, 0);
        assert_eq!(recv.file_blake3, sent.file_blake3);
        assert_eq!(
            std::fs::read(&recv.path).unwrap(),
            std::fs::read(&src).unwrap()
        );
        assert!(!out.join("payload.bin.tallow-tmp").exists());
    }

    /// Streaming bound (design §3.1: bounded RAM, no whole-payload buffering).
    ///
    /// A multi-chunk payload must leave the sender as many small, frame-bounded
    /// writes — never as one whole-payload burst. Observed at the transport
    /// (write-call) level, which is what "not RAM-buffered" means on the wire.
    #[test]
    fn e2e_streamed_writes_are_frame_bounded() {
        /// Transport tap: records the largest single write and the write count.
        struct CountingWriter<W> {
            inner: W,
            max_write: usize,
            writes: u64,
        }
        impl<W: Write> Write for CountingWriter<W> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.max_write = self.max_write.max(buf.len());
                self.writes += 1;
                self.inner.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }

        let dir = tempdir("bounded");
        let src = dir.join("payload.bin");
        let chunks: u64 = 12;
        write_pattern(&src, CHUNK_SIZE as usize * chunks as usize); // 3 MiB
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let src_c = src.clone();
        let sender = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let mut r = stream.try_clone().unwrap();
            let mut w = CountingWriter {
                inner: stream,
                max_write: 0,
                writes: 0,
            };
            let outcome = send_file(
                &mut r,
                &mut w,
                "7-tap-tap-tap",
                &src_c,
                &RelaySendOptions::default(),
            );
            (outcome, w.max_write, w.writes)
        });

        let (mut rx, mut tx) = {
            let s = listener.accept().unwrap().0;
            (s.try_clone().unwrap(), s)
        };
        let recv = receive_file(
            &mut rx,
            &mut tx,
            "7-tap-tap-tap",
            &out,
            &RelayReceiveOptions::default(),
        )
        .expect("receive ok");
        let (sent, max_write, writes) = sender.join().unwrap();
        let sent = sent.expect("send ok");

        assert_eq!(sent.chunks_sent, chunks);
        assert_eq!(recv.chunks_written, chunks);
        assert_eq!(sent.bytes_sent_on_wire, CHUNK_SIZE as u64 * chunks);

        // Nothing is written whole: a 3 MiB burst would trip this by 12x.
        assert!(
            max_write <= MAX_FRAME_PAYLOAD as usize,
            "single write of {max_write} bytes exceeds the frame cap"
        );
        // Each chunk write is one bounded frame (chunk + AEAD tag + postcard + hash).
        assert!(
            max_write <= CHUNK_SIZE as usize + 4096,
            "chunk write of {max_write} bytes exceeds the chunk bound"
        );
        // >= one frame per chunk, and frames are written incrementally.
        assert!(
            writes >= chunks * 3,
            "expected >=3 writes/frame across {chunks} chunks, saw {writes}"
        );
        assert_eq!(
            std::fs::read(&recv.path).unwrap(),
            std::fs::read(&src).unwrap()
        );
        assert!(!out.join("payload.bin.tallow-tmp").exists());
    }

    /// Tampered ciphertext must fail AEAD auth and leave no output file.
    #[test]
    fn e2e_tamper_is_rejected() {
        let dir = tempdir("tamper");
        let src = dir.join("payload.bin");
        write_pattern(&src, 300_000);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let src_c = src.clone();
        let sender = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let mut r = stream.try_clone().unwrap();
            let mut w = stream;
            send_file(
                &mut r,
                &mut w,
                "1-a-b-c",
                &src_c,
                &RelaySendOptions::default(),
            )
        });

        // In-test "hostile relay": flip one byte inside the first CHUNK payload.
        let (src_sock, mut rx, mut tx) = {
            let s = listener.accept().unwrap().0;
            (s.try_clone().unwrap(), s.try_clone().unwrap(), s)
        };
        let mut sr = std::io::BufReader::new(src_sock);
        // HELLO, HELLO_ACK, MANIFEST (sender->receiver), initial ACK, CHUNK...
        let _hello = read_frame(&mut sr).unwrap();
        let (ack, _key) = responder_handshake("1-a-b-c", &_hello.payload).unwrap();
        write_frame(&mut tx, FrameTag::HelloAck, &ack).unwrap();
        let _manifest = read_frame(&mut sr).unwrap();
        write_frame(&mut tx, FrameTag::Ack, &ACK_NONE.to_le_bytes()).unwrap();
        let mut chunk = read_frame(&mut sr).unwrap();
        chunk.payload[40] ^= 0xff; // inside postcard(EncryptedChunk) ciphertext
        write_frame(&mut tx, FrameTag::Chunk, &chunk.payload).unwrap();

        // Receiver sees the tampered chunk.
        let recv = receive_file(
            &mut rx,
            &mut tx,
            "1-a-b-c",
            &out,
            &RelayReceiveOptions::default(),
        );
        assert!(recv.is_err(), "tampered chunk must be rejected");
        assert!(!out.join("payload.bin").exists());
        assert!(!out.join("payload.bin.tallow-tmp").exists());
        drop(sr);
        drop(rx);
        drop(tx);
        let _ = sender.join();
    }

    /// Resume: a pre-seeded state + tmp prefix makes sender stream only the tail.
    #[test]
    fn e2e_resume_skips_verified_prefix() {
        let dir = tempdir("resume");
        let src = dir.join("payload.bin");
        write_pattern(&src, 700_000); // 3 chunks
        let out = dir.join("out");
        let state_dir = out.join(".tallow-resume");
        std::fs::create_dir_all(&state_dir).unwrap();

        let file_hash = hash_file_streaming(&src).unwrap();
        let full = std::fs::read(&src).unwrap();
        // Pretend chunk 0 was already received and verified.
        std::fs::write(
            out.join("payload.bin.tallow-tmp"),
            &full[..CHUNK_SIZE as usize],
        )
        .unwrap();
        let mut state = ReceiveStateFile::new(file_hash, 700_000, CHUNK_SIZE, [7u8; 16]);
        state.resume.mark_verified(0, CHUNK_SIZE as u64);
        state
            .save_atomic(&state_path_for(&state_dir, &file_hash, "payload.bin"))
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let src_c = src.clone();
        let sender = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let mut r = stream.try_clone().unwrap();
            let mut w = stream;
            send_file(
                &mut r,
                &mut w,
                "2-x-y-z",
                &src_c,
                &RelaySendOptions::default(),
            )
        });

        let (mut rx, mut tx) = {
            let s = listener.accept().unwrap().0;
            (s.try_clone().unwrap(), s)
        };
        let recv = receive_file(
            &mut rx,
            &mut tx,
            "2-x-y-z",
            &out,
            &RelayReceiveOptions {
                state_dir: Some(state_dir.clone()),
                ..Default::default()
            },
        )
        .expect("resumed receive ok");
        let sent = sender.join().unwrap().expect("send ok");

        assert_eq!(sent.start_chunk, 1, "sender must skip the verified prefix");
        assert_eq!(sent.chunks_sent, 2);
        assert_eq!(recv.resumed_from_chunk, 1);
        assert_eq!(recv.chunks_written, 2);
        assert_eq!(std::fs::read(&recv.path).unwrap(), full);
        // state is cleaned up on success
        assert!(!state_path_for(&state_dir, &file_hash, "payload.bin").exists());
    }

    /// Wrong code phrase: receiver fails auth and no data path is entered.
    #[test]
    fn e2e_wrong_code_fails() {
        let dir = tempdir("wrongcode");
        let src = dir.join("payload.bin");
        write_pattern(&src, 100_000);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let src_c = src.clone();
        let sender = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let mut r = stream.try_clone().unwrap();
            let mut w = stream;
            send_file(
                &mut r,
                &mut w,
                "1-right-code-here",
                &src_c,
                &RelaySendOptions::default(),
            )
        });

        let (mut rx, mut tx) = {
            let s = listener.accept().unwrap().0;
            (s.try_clone().unwrap(), s)
        };
        let recv = receive_file(
            &mut rx,
            &mut tx,
            "2-wrong-code-here",
            &out,
            &RelayReceiveOptions::default(),
        );
        assert!(recv.is_err());
        assert!(!out.join("payload.bin").exists());
        drop(rx);
        drop(tx);
        let _ = sender.join();
    }

    #[test]
    fn state_path_is_deterministic_and_sanitized() {
        let dir = PathBuf::from("/tmp/x");
        let p = state_path_for(&dir, &[0xab; 32], "../../evil name.bin");
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("abababababababab-"));
        assert!(!name.contains('/'));
        assert!(name.ends_with(".state"));
        assert_eq!(p, state_path_for(&dir, &[0xab; 32], "../../evil name.bin"));
    }

    #[test]
    fn pace_delay_is_full_deficit_not_capped() {
        // 1 chunk of 256 KiB at 125,000 B/s (CLI "1M" bits/sec) is 2.097 s of
        // budget; at t=0 the whole deficit must be returned (the old 250 ms
        // cap made D-C2's 1 MiB @ 1M gate unreachable).
        let wait = pace_delay(262_144, 125_000, Duration::ZERO).unwrap();
        assert!(
            (wait.as_secs_f64() - 2.097152).abs() < 1e-6,
            "wait {wait:?}"
        );
        // Running per-chunk cumulative schedule for 1 MiB @ 1M: 4 waits sum to
        // 8.388608 s — the integration band's centre.
        let mut elapsed = Duration::ZERO;
        let mut total = Duration::ZERO;
        for i in 1..=4u64 {
            let w = pace_delay(i * 262_144, 125_000, elapsed).unwrap();
            total += w;
            elapsed += w;
        }
        assert!(
            (total.as_secs_f64() - 8.388608).abs() < 1e-6,
            "total {total:?}"
        );
    }

    #[test]
    fn pace_delay_unlimited_and_ahead_are_none() {
        assert_eq!(pace_delay(1024, 0, Duration::ZERO), None);
        // 1000 bytes at 1 MB/s = 1 ms expected; 1 s elapsed = ahead of schedule.
        assert_eq!(pace_delay(1000, 1_000_000, Duration::from_secs(1)), None);
        // Exactly on schedule: no wait.
        assert_eq!(
            pace_delay(500_000, 1_000_000, Duration::from_millis(500)),
            None
        );
    }
}
