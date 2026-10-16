//! Key-transparency (KT) **local** append-only log + offline signed tree-head
//! export — task U-220 (W3 build; backdrop: U-201 §3.2 item 8 “T-kt”, gap
//! G-10, programme refs R-5.6 / §5.6).
//!
//! # Audit-only label — read this before trusting anything here
//!
//! [`KT_LOG_ROLE`]: this module is a **single-device, audit-only evidence log**
//! for SVID issuance/rotation events. It is **not** a public transparency
//! service: there is no gossip fabric, no cross-witness monitor, no fork
//! detection (U-201 Q-8 — do not overclaim). What it does give:
//!
//! * append-only, hash-chained entries — any edit, relink, reorder, or
//!   interior deletion of the on-disk JSONL is detected by [`KtLog::verify_chain`]
//!   and refuses to reopen ([`KtLog::open`] validates before extending);
//! * a deterministic tree head (root hash over all entries) — the same entry
//!   sequence always recomputes the same root ([`tree_root_of`]);
//! * [`KtLog::export_tree_head`] — an Ed25519-signed head meant to be retained
//!   **offline / out of band** on a schedule. Once a head has left this
//!   machine, a later rewrite — including a clean **tail truncation**, which
//!   the chain alone cannot see — contradicts the retained head:
//!   [`SignedTreeHead::verify_against_log`];
//! * compact **inclusion** proofs for any log size and **consistency** proofs
//!   for power-of-two old sizes, with prefix recomputation for the rest — see
//!   the proofs section below ([`InclusionProof`], [`ConsistencyProof`]).
//!
//! What it does **not** give: protection against a writer who rewrites the
//! whole file before any head was ever exported. The chain is tamper-*evident*;
//! a head the operator already holds apart from the writer is what makes a
//! rewrite provable.
//!
//! # Crypto reuse (no new primitives are minted here)
//!
//! * Hashing: BLAKE3 (existing crate dependency), the same family used by
//!   [`crate::merkle_audit`].
//! * Signatures: Ed25519 through the existing in-repo helpers
//!   [`crate::signing::sign_artifact`] / [`crate::signing::verify_artifact`]
//!   (SHA-256-then-Ed25519 — the construction package signing and
//!   `merkle_audit::SignedAnchor` already use) and
//!   [`crate::signing::generate_keypair`] for key material.
//! * GOVERNANCE **D2** (hybrid signing v1): the Ed25519+ML-DSA hybrid
//!   co-signature binding for enrollment/rotation stays at the enrollment
//!   layer (tallow-crypto `HybridSigner`, outside this crate); the KT log
//!   binds it as opaque payload bytes (`payload_hash`) and signs the tree
//!   head with Ed25519 in v1. No classical-only claim is made at the cert
//!   layer by this module.
//!
//! # Storage
//!
//! JSONL, one [`KtEntry`] per line, at a caller-provided path. On unix the
//! file is created `0600` and tightened back to `0600` on reopen (same
//! hygiene as the daemon token file, T-110). Single-writer by convention —
//! no file locking is performed.
//!
//! # DID posture (W3 · #211 · R-5.14)
//!
//! [`DID_POSTURE`]: `did:key`-style multibase **naming** of public keys for KT
//! entries / exported artifacts only — no ledger DIDs, no runtime resolver,
//! `did:web` not a core mechanism. See the DID section below the log API
//! ([`did_key_encode`] / [`did_key_decode`] / [`SignedTreeHead::signer_did_key`]).
//!
//! # Inclusion / consistency proofs (W3 · #80 · R-5.6)
//!
//! [`InclusionProof`] answers *"is entry X committed by head H?"* without
//! shipping the log: [`KtLog::prove_inclusion`] / [`prove_inclusion`] emit the
//! O(log n) sibling path, [`InclusionProof::verify`] /
//! [`SignedTreeHead::verify_inclusion`] recompute the root. Every position is
//! derived from `(leaf_index, tree_size)`; the proof carries no direction bits
//! to lie about. Works for every log size.
//!
//! [`ConsistencyProof`] answers *"does the newer head extend the older one
//! (no rewrite)?"* — compactly **only for power-of-two `old_size`**, because
//! the duplicate-last fold is not structurally prefix-stable: for a
//! non-power-of-two `m`, the old root's borderline `node(x, x)` has no
//! counterpart among the larger tree's nodes, so no compact proof can bind
//! the two roots (pinned by test). Arbitrary sizes use
//! [`TreeHead::verify_prefix_of`] / [`SignedTreeHead::verify_extends`], which
//! recompute the committed prefix root from the prefix entries — audit-local,
//! costs the prefix rather than a proof. Both legs fail closed like the rest of
//! the module and change nothing about its role ([`KT_LOG_ROLE`]): still an
//! audit-only local log — proofs serve the offline head holder, they are not a
//! gossip/transparency service.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Honest one-line role label ([`KtLog`] doc: audit-only, not a public
/// transparency service). Callers that surface KT state (doctor probes,
/// operator reports) should print this verbatim.
pub const KT_LOG_ROLE: &str = "audit-only local evidence log for SVID issuance/rotation; \
NOT a public transparency service (no gossip, no fork detection; single-device \
audit anchor only)";

// ─────────────────────────────────────────────────────────────────────────────
// Hash helpers (domain-separated; deterministic, no randomness anywhere)
// ─────────────────────────────────────────────────────────────────────────────

/// Genesis link for `seq == 0`: `BLAKE3(b"tallow-kt-log-v1|genesis")` (hex).
pub fn genesis_hash() -> String {
    hex::encode(blake3::hash(b"tallow-kt-log-v1|genesis").as_bytes())
}

/// Root hash of an empty log: `BLAKE3(b"tallow-kt-log-v1|empty")` (hex).
pub fn empty_tree_root() -> String {
    hex::encode(blake3::hash(b"tallow-kt-log-v1|empty").as_bytes())
}

/// Payload digest bound into an entry: `BLAKE3("tallow-kt-log-v1|payload|" || payload)` (hex).
///
/// The payload itself stays with the caller (the evidence body); only this
/// digest is persisted, so a holder of the payload can recompute it and
/// require the log to contain it.
pub fn payload_hash(payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(18 + payload.len());
    buf.extend_from_slice(b"tallow-kt-log-v1|payload|");
    buf.extend_from_slice(payload);
    hex::encode(blake3::hash(&buf).as_bytes())
}

/// Chain hash of one entry (hex):
/// `BLAKE3("tallow-kt-log-v1|entry|" || seq_be || "|" || prev_hash || "|" || payload_hash || "|" || ts_be)`.
fn entry_hash_hex(seq: u64, prev_hash: &str, payload_hash: &str, timestamp: u64) -> String {
    let mut buf = Vec::with_capacity(24 + 8 + 64 + 64 + 8);
    buf.extend_from_slice(b"tallow-kt-log-v1|entry|");
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.push(b'|');
    buf.extend_from_slice(prev_hash.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(payload_hash.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&timestamp.to_be_bytes());
    hex::encode(blake3::hash(&buf).as_bytes())
}

fn leaf_of(entry_hash: &str) -> String {
    let mut buf = Vec::with_capacity(18 + entry_hash.len());
    buf.extend_from_slice(b"tallow-kt-log-v1|leaf|");
    buf.extend_from_slice(entry_hash.as_bytes());
    hex::encode(blake3::hash(&buf).as_bytes())
}

fn node_of(left: &str, right: &str) -> String {
    let mut buf = Vec::with_capacity(18 + left.len() + 1 + right.len());
    buf.extend_from_slice(b"tallow-kt-log-v1|node|");
    buf.extend_from_slice(left.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(right.as_bytes());
    hex::encode(blake3::hash(&buf).as_bytes())
}

/// Deterministic Merkle-ish root over a full entry sequence (hex).
///
/// Leaves are the per-entry chain hashes (`BLAKE3` domain-separated);
/// internal nodes are `BLAKE3(left || '|' || right)`; an odd count at any
/// level duplicates the last node (same shape as
/// `crate::merkle_audit::compute_merkle_root`). Recomputing from the same
/// entries always yields the same root — no hidden state, no clock.
/// Empty log ⇒ [`empty_tree_root`].
pub fn tree_root_of(entries: &[KtEntry]) -> String {
    if entries.is_empty() {
        return empty_tree_root();
    }
    let mut level: Vec<String> = entries.iter().map(|e| leaf_of(&e.entry_hash)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                &level[i] // duplicate last if odd
            };
            next.push(node_of(left, right));
            i += 2;
        }
        level = next;
    }
    level.pop().expect("non-empty level")
}

// ─────────────────────────────────────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────────────────────────────────────

/// One append-only log entry.
///
/// Field order is also the JSONL serialization order:
/// `{seq, prev_hash, payload_hash, timestamp, entry_hash}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtEntry {
    /// Monotonic position, starting at 0; verified to equal the line index.
    pub seq: u64,
    /// Hex chain hash of the previous entry ([`genesis_hash`] for `seq == 0`).
    pub prev_hash: String,
    /// Hex digest of the payload ([`payload_hash`]); the payload itself is
    /// caller-held evidence.
    pub payload_hash: String,
    /// Unix milliseconds when the entry was appended (caller-supplied via
    /// [`KtLog::append_at`] where determinism matters).
    pub timestamp: u64,
    /// Hex chain hash of this entry (binds seq + prev_hash + payload_hash +
    /// timestamp).
    pub entry_hash: String,
}

/// An unsigned snapshot of the log: length + deterministic root + time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHead {
    /// Number of entries the head covers.
    pub chain_len: u64,
    /// Hex Merkle-ish root over those entries ([`tree_root_of`]).
    pub root_hash: String,
    /// Unix milliseconds the head was produced.
    pub timestamp: u64,
}

/// A [`TreeHead`] signed with an Ed25519 key — the offline export artifact.
///
/// Meant to be written out (JSON) and retained apart from the log machine on
/// a schedule. It is an **audit anchor only** (see [`KT_LOG_ROLE`]); it is
/// not a gossip/cosignature input for any public service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// The committed head.
    pub head: TreeHead,
    /// Hex Ed25519 verifying key that produced `signature`.
    pub signer: String,
    /// Hex Ed25519 signature over the canonical head payload (SHA-256-then-
    /// Ed25519 via [`crate::signing::sign_artifact`]).
    pub signature: String,
}

impl SignedTreeHead {
    /// Verify the signature against `expected_signer` (the operator-pinned
    /// key). Fails if the recorded `signer` differs from the pinned key, or
    /// the signature does not verify over the head bytes.
    pub fn verify_signature(&self, expected_signer: &VerifyingKey) -> Result<(), KtError> {
        let signer_hex = hex::encode(expected_signer.as_bytes());
        if self.signer != signer_hex {
            return Err(KtError::SignerMismatch {
                expected: signer_hex,
                found: self.signer.clone(),
            });
        }
        let sig = hex::decode(&self.signature)
            .ok_or_else(|| KtError::BadSignature("signature is not valid hex".to_string()))?;
        let payload = sth_payload(&self.head);
        match crate::signing::verify_artifact(&payload, &sig, expected_signer) {
            Ok(true) => Ok(()),
            Ok(false) => Err(KtError::BadSignature("signature did not verify".to_string())),
            Err(e) => Err(KtError::BadSignature(e)),
        }
    }

    /// Verify this head against a full entry sequence: the length must match
    /// exactly and the recomputed root must equal the committed root. This is
    /// how **tail truncation** (or extension) of the log is detected — the
    /// chain alone cannot see a clean tail cut.
    pub fn verify_against(&self, entries: &[KtEntry]) -> Result<(), KtError> {
        let found_len = entries.len() as u64;
        if self.head.chain_len != found_len {
            return Err(KtError::ChainLengthMismatch {
                expected: self.head.chain_len,
                found: found_len,
            });
        }
        let found_root = tree_root_of(entries);
        if self.head.root_hash != found_root {
            return Err(KtError::RootHashMismatch {
                expected: self.head.root_hash.clone(),
                found: found_root,
            });
        }
        Ok(())
    }

    /// Convenience: [`SignedTreeHead::verify_against`] for a live [`KtLog`].
    pub fn verify_against_log(&self, log: &KtLog) -> Result<(), KtError> {
        self.verify_against(&log.entries)
    }
}

/// Canonical bytes the tree-head signature covers:
/// `b"tallow-kt-log-v1|sth|" || chain_len_be || "|" || root_hash_ascii || "|" || ts_be`.
fn sth_payload(head: &TreeHead) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 8 + 64 + 8);
    buf.extend_from_slice(b"tallow-kt-log-v1|sth|");
    buf.extend_from_slice(&head.chain_len.to_be_bytes());
    buf.push(b'|');
    buf.extend_from_slice(head.root_hash.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&head.timestamp.to_be_bytes());
    buf
}

/// KT log error: I/O, malformed storage, chain verification, and signature
/// failures. All verification failures are hard errors (fail-closed).
#[derive(Debug)]
pub enum KtError {
    /// Underlying filesystem failure.
    Io(std::io::Error),
    /// A JSONL line did not parse (1-based `line`).
    MalformedLine {
        /// 1-based line number.
        line: usize,
        /// Parser message.
        reason: String,
    },
    /// Serialization failure while encoding an entry.
    Encode(String),
    /// [`KtLog::append`] / [`KtLog::append_at`] refuse empty payloads.
    EmptyPayload,
    /// [`KtLog::export_tree_head`] refuses an empty log.
    EmptyLog,
    /// Entry `seq` did not equal its position (reorder or interior deletion).
    SeqMismatch {
        /// Expected position.
        expected: u64,
        /// Found `seq` value.
        found: u64,
    },
    /// `prev_hash` did not link to the previous entry's hash (relink/tamper).
    PrevHashMismatch {
        /// Offending entry position.
        seq: u64,
    },
    /// Recomputed entry hash differed from the stored one (field tamper).
    EntryHashMismatch {
        /// Offending entry position.
        seq: u64,
    },
    /// Head length disagreed with the entry count (tail truncation/extension).
    ChainLengthMismatch {
        /// Length committed by the head.
        expected: u64,
        /// Length actually present.
        found: u64,
    },
    /// Recomputed root disagreed with the committed root (content rewrite).
    RootHashMismatch {
        /// Root committed by the head.
        expected: String,
        /// Root recomputed from the entries.
        found: String,
    },
    /// Signed head was produced by a key other than the pinned one.
    SignerMismatch {
        /// Pinned signer (hex).
        expected: String,
        /// Signer recorded in the head (hex).
        found: String,
    },
    /// Signature malformed or did not verify.
    BadSignature(String),
    /// The log path is a symlink (refused; storage hygiene).
    SymlinkRefused(String),
    /// The log path exists but is not a regular file.
    NotRegularFile(String),
    /// [`prove_inclusion`] / [`KtLog::prove_inclusion`]: `index` was not a
    /// valid leaf position (also raised for any proof whose `tree_size` is 0).
    LeafIndexOutOfRange {
        /// Requested leaf index.
        index: u64,
        /// Size of the tree it was requested against.
        tree_size: u64,
    },
    /// A proof carried the wrong number of nodes for its `(leaf_index,
    /// tree_size)` — truncated or padded transcripts fail closed.
    ProofShapeMismatch {
        /// Node count the shape requires.
        expected: usize,
        /// Node count the proof carried.
        found: usize,
    },
    /// [`prove_consistency`]: the compact consistency leg is claimed only for
    /// power-of-two old sizes (see [`ConsistencyProof`]); arbitrary sizes use
    /// [`TreeHead::verify_prefix_of`].
    ConsistencyRequiresPowerOfTwo {
        /// Rejected `old_size`.
        old_size: u64,
    },
}

impl std::fmt::Display for KtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KtError::Io(e) => write!(f, "kt-log: io: {e}"),
            KtError::MalformedLine { line, reason } => {
                write!(f, "kt-log: malformed JSONL at line {line}: {reason}")
            }
            KtError::Encode(e) => write!(f, "kt-log: encode: {e}"),
            KtError::EmptyPayload => write!(f, "kt-log: refusing empty payload"),
            KtError::EmptyLog => write!(f, "kt-log: refusing to export a head over an empty log"),
            KtError::SeqMismatch { expected, found } => write!(
                f,
                "kt-log: seq mismatch at position {expected}: found seq {found} (reorder or interior truncation)"
            ),
            KtError::PrevHashMismatch { seq } => {
                write!(f, "kt-log: prev_hash mismatch at seq {seq} (chain broken)")
            }
            KtError::EntryHashMismatch { seq } => {
                write!(f, "kt-log: entry_hash mismatch at seq {seq} (entry tampered)")
            }
            KtError::ChainLengthMismatch { expected, found } => write!(
                f,
                "kt-log: head covers {expected} entries but {found} are present (truncation or extension)"
            ),
            KtError::RootHashMismatch { expected, found } => write!(
                f,
                "kt-log: tree root mismatch: head says {expected}, entries recompute {found}"
            ),
            KtError::SignerMismatch { expected, found } => write!(
                f,
                "kt-log: signer mismatch: pinned {expected}, head signed by {found}"
            ),
            KtError::BadSignature(e) => write!(f, "kt-log: bad signature: {e}"),
            KtError::SymlinkRefused(p) => write!(f, "kt-log: refusing symlink path {p}"),
            KtError::NotRegularFile(p) => write!(f, "kt-log: refusing non-regular file {p}"),
            KtError::LeafIndexOutOfRange { index, tree_size } => write!(
                f,
                "kt-log: leaf index {index} out of range for tree size {tree_size}"
            ),
            KtError::ProofShapeMismatch { expected, found } => write!(
                f,
                "kt-log: proof shape mismatch: expected {expected} proof nodes, found {found}"
            ),
            KtError::ConsistencyRequiresPowerOfTwo { old_size } => write!(
                f,
                "kt-log: compact consistency proof requires a power-of-two old_size (got {old_size}); \
use TreeHead::verify_prefix_of for arbitrary sizes"
            ),
        }
    }
}

impl std::error::Error for KtError {}

impl From<std::io::Error> for KtError {
    fn from(e: std::io::Error) -> Self {
        KtError::Io(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The log
// ─────────────────────────────────────────────────────────────────────────────

/// Append-only, hash-chained KT log persisted as JSONL at a caller-provided
/// path (unix: created `0600`, tightened on reopen).
///
/// Role: **audit-only evidence log** for SVID issuance/rotation — see
/// [`KT_LOG_ROLE`] and the module docs. Not a transparency service.
///
/// Usage: [`KtLog::open`] (validates any existing file before extending it),
/// [`KtLog::append`] / [`KtLog::append_at`], [`KtLog::verify_chain`], and
/// [`KtLog::export_tree_head`] on a schedule. Re-opening the same path
/// continues the chain (`seq` picks up where the file ended). Single-writer
/// by convention; the file handle stays open for the log's lifetime.
#[derive(Debug)]
pub struct KtLog {
    path: PathBuf,
    entries: Vec<KtEntry>,
    file: fs::File,
    /// Set by [`KtLog::open_read_only`]: a read-only handle, nothing created, mode untouched.
    /// Appending to such a handle is refused without writing.
    read_only: bool,
}

impl KtLog {
    /// Open (or create) the log at `path` and continue from its current end.
    ///
    /// * Existing file: every line is parsed and the **whole chain is verified
    ///   before the write handle is opened** — a tampered file fails to reopen
    ///   ([`KtError::EntryHashMismatch`]/[`KtError::PrevHashMismatch`]/
    ///   [`KtError::SeqMismatch`]/[`KtError::MalformedLine`]). Blank lines are
    ///   skipped; anything else unparseable is a hard error.
    /// * New file: created on unix with mode `0600`.
    /// * Existing file with group/other bits: tightened to `0600`.
    /// * Symlinks and non-regular files are refused.
    ///
    /// The parent directory must already exist (the log does not invent one).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KtError> {
        let path = path.as_ref().to_path_buf();

        let existing = match fs::symlink_metadata(&path) {
            Ok(md) => Some(md),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(KtError::Io(e)),
        };
        if let Some(md) = &existing {
            if md.file_type().is_symlink() {
                return Err(KtError::SymlinkRefused(path.display().to_string()));
            }
            if !md.is_file() {
                return Err(KtError::NotRegularFile(path.display().to_string()));
            }
        }

        // Read + validate before opening the write handle: a tampered file
        // must never be silently extended.
        let entries = if existing.is_some() {
            let text = fs::read_to_string(&path)?;
            let mut entries = Vec::new();
            for (i, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let entry: KtEntry = serde_json::from_str(line).map_err(|e| {
                    KtError::MalformedLine {
                        line: i + 1,
                        reason: e.to_string(),
                    }
                })?;
                entries.push(entry);
            }
            verify_entries(&entries)?;
            entries
        } else {
            Vec::new()
        };

        let mut opts = fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata()?.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
        }

        Ok(KtLog {
            path,
            entries,
            file,
            read_only: false,
        })
    }

    /// Open an **existing** log for reading only: no create, no append handle, no mode change.
    ///
    /// [`KtLog::open`] is the WRITE path — `create(true).append(true)`, mode `0600`, and it
    /// tightens any group/other bit back to `0600`. A caller that only *reads* — the anchor account
    /// verifying the head it is about to record — therefore cannot use it: it would need write
    /// permission on the log, and the next write-open would undo the operator's group-read grant.
    /// This is the read half of that split.
    ///
    /// * An absent path is an **error**: a reader must never bring a log into existence.
    /// * Symlinks and non-regular files are refused, exactly as in [`KtLog::open`].
    /// * The whole chain is validated before anything is returned (same rules as [`KtLog::open`]).
    /// * The file mode is **not** touched, so a deliberate `0640` grant survives a read.
    ///
    /// [`KtLog::append`] / [`KtLog::append_at`] / [`KtLog::append_json`] on the result fail with
    /// `PermissionDenied` without writing a byte.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, KtError> {
        let path = path.as_ref().to_path_buf();

        let md = fs::symlink_metadata(&path)?;
        if md.file_type().is_symlink() {
            return Err(KtError::SymlinkRefused(path.display().to_string()));
        }
        if !md.is_file() {
            return Err(KtError::NotRegularFile(path.display().to_string()));
        }

        let text = fs::read_to_string(&path)?;
        let mut entries = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: KtEntry = serde_json::from_str(line).map_err(|e| KtError::MalformedLine {
                line: i + 1,
                reason: e.to_string(),
            })?;
            entries.push(entry);
        }
        verify_entries(&entries)?;

        // A read-only handle. The mode is left exactly as the operator set it — the whole point of
        // this constructor is that reading cannot tighten, extend or create anything.
        let file = fs::File::open(&path)?;
        Ok(KtLog {
            path,
            entries,
            file,
            read_only: true,
        })
    }

    /// Path this log is persisted at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of entries chained so far.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in chain order.
    pub fn entries(&self) -> &[KtEntry] {
        &self.entries
    }

    /// Current chain head hash ([`genesis_hash`] for an empty log).
    pub fn head_hash(&self) -> String {
        self.entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(genesis_hash)
    }

    /// Append `payload`, timestamped now (unix ms). Payload bytes are hashed;
    /// the bytes themselves stay with the caller. Returns the new entry.
    pub fn append(&mut self, payload: &[u8]) -> Result<&KtEntry, KtError> {
        self.append_at(payload, now_millis())
    }

    /// Append `payload` with an explicit timestamp — the deterministic entry
    /// point (tests, replayed imports).
    pub fn append_at(&mut self, payload: &[u8], timestamp: u64) -> Result<&KtEntry, KtError> {
        if self.read_only {
            return Err(KtError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "the KT log '{}' was opened read-only — this handle cannot append (open it \
                     with KtLog::open for the write path)",
                    self.path.display()
                ),
            )));
        }
        if payload.is_empty() {
            return Err(KtError::EmptyPayload);
        }
        let seq = self.entries.len() as u64;
        let prev_hash = self.head_hash();
        let payload_hash = payload_hash(payload);
        let entry_hash = entry_hash_hex(seq, &prev_hash, &payload_hash, timestamp);
        let entry = KtEntry {
            seq,
            prev_hash,
            payload_hash,
            timestamp,
            entry_hash,
        };
        let mut line = serde_json::to_string(&entry).map_err(|e| KtError::Encode(e.to_string()))?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.entries.push(entry);
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Append a JSON payload (serialized canonically via `serde_json::to_vec`).
    /// Convenience for evidence bodies such as SVID issuance/rotation events
    /// (which carry the hybrid co-signature per GOVERNANCE D2).
    pub fn append_json(&mut self, payload: &serde_json::Value) -> Result<&KtEntry, KtError> {
        let bytes = serde_json::to_vec(payload).map_err(|e| KtError::Encode(e.to_string()))?;
        self.append(&bytes)
    }

    /// Verify the entire in-memory chain: seq == position, prev_hash linkage,
    /// and recomputed entry hashes. Detects field tampering, relinking,
    /// reordering, and interior truncation. (Tail truncation needs an
    /// exported head — use [`SignedTreeHead::verify_against_log`].)
    pub fn verify_chain(&self) -> Result<(), KtError> {
        verify_entries(&self.entries)
    }

    /// Deterministic tree root over the current entries ([`tree_root_of`]).
    pub fn tree_root(&self) -> String {
        tree_root_of(&self.entries)
    }

    /// A [`TreeHead`] for the current log, timestamped now.
    pub fn tree_head(&self) -> TreeHead {
        self.tree_head_at(now_millis())
    }

    /// A [`TreeHead`] with an explicit timestamp (deterministic head export).
    pub fn tree_head_at(&self, timestamp: u64) -> TreeHead {
        TreeHead {
            chain_len: self.entries.len() as u64,
            root_hash: self.tree_root(),
            timestamp,
        }
    }

    /// Export a signed tree head (offline retention artifact).
    ///
    /// Refuses an empty log and refuses to sign over a chain that fails
    /// [`KtLog::verify_chain`] — a head must never bless a broken log.
    /// Signature: Ed25519 via [`crate::signing::sign_artifact`] over the
    /// canonical head payload ([`sth_payload`]).
    pub fn export_tree_head(&self, key: &SigningKey) -> Result<SignedTreeHead, KtError> {
        if self.entries.is_empty() {
            return Err(KtError::EmptyLog);
        }
        self.verify_chain()?;
        let head = self.tree_head();
        let payload = sth_payload(&head);
        let signature = crate::signing::sign_artifact(&payload, key);
        Ok(SignedTreeHead {
            head,
            signer: hex::encode(key.verifying_key().as_bytes()),
            signature: hex::encode(&signature),
        })
    }

    /// Flush the OS write buffer to disk (not called per append; call before
    /// snapshotting/archiving the file).
    pub fn sync(&self) -> Result<(), KtError> {
        self.file.sync_all().map_err(KtError::Io)
    }

    /// Compact inclusion proof for the entry at `index` (see [`InclusionProof`]):
    /// the sibling path from that entry's leaf to [`KtLog::tree_root`]. O(n)
    /// work to build (the level structure is rebuilt); the proof itself is
    /// O(log n) nodes.
    pub fn prove_inclusion(&self, index: usize) -> Result<InclusionProof, KtError> {
        prove_inclusion(&self.entries, index)
    }
}

/// Verify a full entry sequence as a chain (free function so an exported or
/// externally received copy can be checked without a [`KtLog`] handle).
pub fn verify_entries(entries: &[KtEntry]) -> Result<(), KtError> {
    let mut prev = genesis_hash();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(KtError::SeqMismatch {
                expected: i as u64,
                found: e.seq,
            });
        }
        if e.prev_hash != prev {
            return Err(KtError::PrevHashMismatch { seq: e.seq });
        }
        let recomputed = entry_hash_hex(e.seq, &e.prev_hash, &e.payload_hash, e.timestamp);
        if recomputed != e.entry_hash {
            return Err(KtError::EntryHashMismatch { seq: e.seq });
        }
        prev = e.entry_hash.clone();
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Inclusion / consistency proofs (W3 · #80 · R-5.6)
//
// Shape notes (read before extending):
//
// * Leaves are the domain-separated leaf digests of entry hashes ([`leaf_of`]);
//   internal nodes are [`node_of`]; level k+1 pairs level k left-to-right and
//   duplicates the last node when the count is odd — exactly the fold
//   [`tree_root_of`] performs. Proofs never restate the fold: they carry only
//   sibling values, and the verifier re-derives every level's shape from
//   `(leaf_index, tree_size)` / `(old_size, new_size)`.
// * The duplicate-last fold is *not* structurally prefix-stable: for a
//   non-power-of-two `m`, T(m)'s borderline `node(x, x)` has no counterpart
//   among T(n)'s nodes (pinned by test), so no compact transcript can bind a
//   bigger tree to the old root. Compact consistency is therefore offered
//   only for power-of-two `old_size` whose root is literally the
//   `(log2 m, 0)` node of the larger tree; arbitrary sizes use recomputation
//   ([`TreeHead::verify_prefix_of`] / [`SignedTreeHead::verify_extends`]).
//   Inclusion proofs work for every size.
// * Both legs are audit-local statements against a head the verifier pins;
//   they do not turn this module into a gossip service ([`KT_LOG_ROLE`]).
// ─────────────────────────────────────────────────────────────────────────────

/// Compact Merkle inclusion proof for one entry of the tree committed to by a
/// [`TreeHead`] / [`SignedTreeHead`].
///
/// * `leaf_index` / `tree_size` fix the position; the sibling side at every
///   level is derived from those numbers, so the proof carries no direction
///   bits to lie about. Levels at which the node is the *duplicated last
///   node* consume no element — the verifier recomputes `node(h, h)` itself.
/// * `entry_hash` is the proven entry's chain hash; the leaf preimage is
///   recomputed from it with the same domain separation [`tree_root_of`] uses.
/// * `siblings` is bottom-up; its length is exactly the number of
///   non-duplicated levels for the position, and any other count fails
///   [`InclusionProof::verify`] with [`KtError::ProofShapeMismatch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Position of the entry in the log.
    pub leaf_index: u64,
    /// Number of entries the proof is valid against.
    pub tree_size: u64,
    /// Chain hash of the proven entry ([`KtEntry::entry_hash`]).
    pub entry_hash: String,
    /// Sibling node values, bottom-up (hex).
    pub siblings: Vec<String>,
}

/// Compact consistency proof that the tree committed to by an older head is a
/// prefix of the tree committed to by a newer head.
///
/// Offered **only for power-of-two `old_size`** (including `1`): those — and
/// only those — roots are structurally embedded in the larger tree as its
/// `(log2 old_size, 0)` node, so `old_root` folds up to `new_root` with
/// `siblings.len() == ceil(log2 new_size) − log2(old_size)` node values. For
/// arbitrary sizes the module's duplicate-last fold has no such embedding; use
/// [`TreeHead::verify_prefix_of`] / [`SignedTreeHead::verify_extends`] instead
/// (recomputation from the prefix entries, no compact claim).
///
/// `old_root` / `new_root` are checked against the heads in
/// [`ConsistencyProof::verify`] (defense in depth), so a transcript spliced
/// across different head pairs fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Size of the older tree (power of two; `1` allowed).
    pub old_size: u64,
    /// Size of the newer tree (`>= old_size`).
    pub new_size: u64,
    /// Root committed by the older head.
    pub old_root: String,
    /// Root committed by the newer head.
    pub new_root: String,
    /// Sibling node values folding `old_root` up to `new_root`, bottom-up from
    /// level `log2(old_size)` (hex).
    pub siblings: Vec<String>,
}

impl InclusionProof {
    /// Verify against a tree root — the `root_hash` of a [`TreeHead`], or a
    /// [`SignedTreeHead`]'s head root. Fail-closed: shape first, then hash.
    /// A `tree_size` of `0` or an out-of-range `leaf_index` is refused.
    pub fn verify(&self, root_hash: &str) -> Result<(), KtError> {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return Err(KtError::LeafIndexOutOfRange {
                index: self.leaf_index,
                tree_size: self.tree_size,
            });
        }
        let expected = inclusion_sibling_count(self.leaf_index, self.tree_size);
        if self.siblings.len() != expected {
            return Err(KtError::ProofShapeMismatch {
                expected,
                found: self.siblings.len(),
            });
        }
        let mut h = leaf_of(&self.entry_hash);
        let mut idx = self.leaf_index;
        let mut len = self.tree_size;
        let mut next = 0usize;
        while len > 1 {
            if idx % 2 == 0 {
                if idx + 1 < len {
                    h = node_of(&h, &self.siblings[next]);
                    next += 1;
                } else {
                    h = node_of(&h, &h); // duplicated last node at this level
                }
            } else {
                h = node_of(&self.siblings[next], &h);
                next += 1;
            }
            idx /= 2;
            len = len.div_ceil(2);
        }
        if h != root_hash {
            return Err(KtError::RootHashMismatch {
                expected: root_hash.to_string(),
                found: h,
            });
        }
        Ok(())
    }
}

impl ConsistencyProof {
    /// Verify against the two heads this proof claims to connect. Checks the
    /// `old_size`/`new_size`/`old_root`/`new_root` bindings first, then folds
    /// `old_root` up to `new_root`.
    ///
    /// Signatures are **not** checked here: call
    /// [`SignedTreeHead::verify_signature`] on both heads with the pinned key
    /// in addition to this call.
    pub fn verify(&self, old_head: &TreeHead, new_head: &TreeHead) -> Result<(), KtError> {
        if self.old_size != old_head.chain_len {
            return Err(KtError::ChainLengthMismatch {
                expected: old_head.chain_len,
                found: self.old_size,
            });
        }
        if self.new_size != new_head.chain_len {
            return Err(KtError::ChainLengthMismatch {
                expected: new_head.chain_len,
                found: self.new_size,
            });
        }
        if self.old_root != old_head.root_hash {
            return Err(KtError::RootHashMismatch {
                expected: old_head.root_hash.clone(),
                found: self.old_root.clone(),
            });
        }
        if self.new_root != new_head.root_hash {
            return Err(KtError::RootHashMismatch {
                expected: new_head.root_hash.clone(),
                found: self.new_root.clone(),
            });
        }
        if self.old_size == 0 || !self.old_size.is_power_of_two() || self.old_size > self.new_size {
            return Err(KtError::ConsistencyRequiresPowerOfTwo {
                old_size: self.old_size,
            });
        }
        let l = self.old_size.trailing_zeros();
        let expected = levels_needed(self.new_size).saturating_sub(l) as usize;
        if self.siblings.len() != expected {
            return Err(KtError::ProofShapeMismatch {
                expected,
                found: self.siblings.len(),
            });
        }
        let mut h = self.old_root.clone();
        for sib in &self.siblings {
            h = node_of(&h, sib);
        }
        if h != new_head.root_hash {
            return Err(KtError::RootHashMismatch {
                expected: new_head.root_hash.clone(),
                found: h,
            });
        }
        Ok(())
    }
}

impl TreeHead {
    /// Non-compact consistency check for arbitrary sizes: the committed prefix
    /// (the first `chain_len` entries) must recompute to `root_hash`.
    ///
    /// `entries` must be the log's entry sequence with `len() >= chain_len`
    /// (the current full sequence when checking that a retained head was
    /// extended, not rewritten). Fails closed with
    /// [`KtError::ChainLengthMismatch`] when fewer entries are supplied and
    /// [`KtError::RootHashMismatch`] on any prefix rewrite. This is the
    /// general fallback where no compact [`ConsistencyProof`] exists
    /// (non-power-of-two `chain_len`) — it needs the prefix entries, not a
    /// proof (audit-local; see the module docs).
    pub fn verify_prefix_of(&self, entries: &[KtEntry]) -> Result<(), KtError> {
        let m = self.chain_len as usize;
        if entries.len() < m {
            return Err(KtError::ChainLengthMismatch {
                expected: self.chain_len,
                found: entries.len() as u64,
            });
        }
        let found_root = tree_root_of(&entries[..m]);
        if found_root != self.root_hash {
            return Err(KtError::RootHashMismatch {
                expected: self.root_hash.clone(),
                found: found_root,
            });
        }
        Ok(())
    }
}

impl SignedTreeHead {
    /// [`InclusionProof`] against the head this record commits to: the proof's
    /// `tree_size` must equal [`SignedTreeHead::head`]`.chain_len`, then the
    /// sibling path is folded against the committed root. Check
    /// [`SignedTreeHead::verify_signature`] with the pinned key as well — this
    /// method checks structure + hash path only.
    pub fn verify_inclusion(&self, proof: &InclusionProof) -> Result<(), KtError> {
        if proof.tree_size != self.head.chain_len {
            return Err(KtError::ChainLengthMismatch {
                expected: self.head.chain_len,
                found: proof.tree_size,
            });
        }
        proof.verify(&self.head.root_hash)
    }

    /// [`TreeHead::verify_prefix_of`] for a full (or at least `chain_len`-long)
    /// entry sequence: this retained head is a consistent prefix of it.
    pub fn verify_extends(&self, entries: &[KtEntry]) -> Result<(), KtError> {
        self.head.verify_prefix_of(entries)
    }
}

/// Prove inclusion of the entry at `index` in an entry sequence — free function
/// so an exported/log copy proves without a [`KtLog`] handle (mirrors
/// [`verify_entries`]).
pub fn prove_inclusion(entries: &[KtEntry], index: usize) -> Result<InclusionProof, KtError> {
    if entries.is_empty() {
        return Err(KtError::EmptyLog);
    }
    if index >= entries.len() {
        return Err(KtError::LeafIndexOutOfRange {
            index: index as u64,
            tree_size: entries.len() as u64,
        });
    }
    let mut level = leaf_level(entries);
    let mut idx = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if idx % 2 == 0 {
            if idx + 1 < level.len() {
                siblings.push(level[idx + 1].clone());
            }
            // Duplicated last node: the sibling is the node itself — no element.
        } else {
            siblings.push(level[idx - 1].clone());
        }
        level = fold_one_level(&level);
        idx /= 2;
    }
    Ok(InclusionProof {
        leaf_index: index as u64,
        tree_size: entries.len() as u64,
        entry_hash: entries[index].entry_hash.clone(),
        siblings,
    })
}

/// Prove that the tree of the first `old_size` entries is committed as a prefix
/// of the tree over all `entries` — compact form, **power-of-two `old_size`
/// only** (see [`ConsistencyProof`] for why; arbitrary sizes use
/// [`TreeHead::verify_prefix_of`]).
pub fn prove_consistency(entries: &[KtEntry], old_size: usize) -> Result<ConsistencyProof, KtError> {
    let new_size = entries.len();
    if entries.is_empty() {
        return Err(KtError::EmptyLog);
    }
    if old_size == 0 || old_size > new_size {
        return Err(KtError::ChainLengthMismatch {
            expected: old_size as u64,
            found: new_size as u64,
        });
    }
    if !old_size.is_power_of_two() {
        return Err(KtError::ConsistencyRequiresPowerOfTwo {
            old_size: old_size as u64,
        });
    }
    let mut levels = vec![leaf_level(entries)];
    while levels.last().expect("non-empty levels").len() > 1 {
        let next = fold_one_level(levels.last().expect("just checked"));
        levels.push(next);
    }
    let l = old_size.trailing_zeros() as usize;
    let old_root = levels[l][0].clone();
    let mut siblings = Vec::new();
    let mut j = l;
    while levels[j].len() >= 2 {
        siblings.push(levels[j][1].clone());
        j += 1;
    }
    let new_root = levels
        .last()
        .expect("non-empty levels")
        .first()
        .expect("root present")
        .clone();
    Ok(ConsistencyProof {
        old_size: old_size as u64,
        new_size: new_size as u64,
        old_root,
        new_root,
        siblings,
    })
}

/// Leaf digests of an entry sequence, in order (level 0 of the tree).
fn leaf_level(entries: &[KtEntry]) -> Vec<String> {
    entries.iter().map(|e| leaf_of(&e.entry_hash)).collect()
}

/// Fold one level of the duplicate-last tree: pair left-to-right, duplicate
/// the last node when the count is odd. Same construction as the inner loop of
/// [`tree_root_of`].
fn fold_one_level(level: &[String]) -> Vec<String> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        let left = &level[i];
        let right = if i + 1 < level.len() {
            &level[i + 1]
        } else {
            &level[i] // duplicate last if odd
        };
        next.push(node_of(left, right));
        i += 2;
    }
    next
}

/// Number of proof elements a valid [`InclusionProof`] carries for a position:
/// one per level except levels where the node is the duplicated last node
/// (those consume nothing — the verifier recomputes `node(h, h)`).
fn inclusion_sibling_count(leaf_index: u64, tree_size: u64) -> usize {
    let mut idx = leaf_index;
    let mut len = tree_size;
    let mut count = 0usize;
    while len > 1 {
        if idx % 2 == 1 || idx + 1 < len {
            count += 1;
        }
        idx /= 2;
        len = len.div_ceil(2);
    }
    count
}

/// Number of fold levels from `size` leaves to the root: `ceil(log2(size))`
/// (`0` for a single leaf).
fn levels_needed(size: u64) -> u32 {
    if size <= 1 {
        0
    } else {
        64 - (size - 1).leading_zeros()
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// DID posture — `did:key`-style naming for public keys (W3 · #211 · R-5.14)
//
// Boundary (read this before extending anything here):
//
// * ALLOWED: multibase/[`did:key`](https://w3c-ccg.github.io/did-method-key/)-style
//   **naming** of public keys — a self-describing encoding of key material this
//   log already holds (Ed25519 verifying keys today). It is meant for KT
//   entries and exported audit artifacts (e.g. naming the signer of an exported
//   [`SignedTreeHead`]) so external verifiers that live in the DID/VC world can
//   compare names.
// * REJECTED (posture, not an accident): blockchain-anchored DID methods, and
//   any runtime DID-resolver dependency. Those publish relationship metadata
//   (a privacy regression) and add availability coupling; R-5.14 rejects them
//   for core identity. `did:web` is likewise not a core mechanism — the decoder
//   refuses every method other than `key`.
// * There is **no network access anywhere in this section** — encode/decode are
//   pure byte transforms. A `did:key` here names material; it resolves nothing.
// ─────────────────────────────────────────────────────────────────────────────

/// Honest one-line posture label (R-5.14): naming only, no ledger DIDs, no
/// resolver, no `did:web` as core. Print verbatim where KT export naming is
/// surfaced to operators.
pub const DID_POSTURE: &str = "did:key-style multibase naming for public keys in KT entries and \
exported audit artifacts only; ledger-anchored DID methods, runtime resolvers, and did:web-as-core \
are rejected (R-5.14). No network access: a did:key names key material, it resolves nothing.";

/// Multicodec varint prefix for `ed25519-pub` (`0xed` varint-encoded), the only
/// key type this module names. X25519-pub (`0xec01`) and other codes are
/// refused by [`did_key_decode`] (`UnsupportedKeyType`).
pub const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// `did:key` decoding/validation failures. All are hard errors (fail-closed);
/// none of them imply network access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidKeyError {
    /// Not a `did:` URI at all.
    NotDid,
    /// `did:<method>:…` with `method != "key"` — ledger/Web/pkh methods are
    /// rejected by posture (R-5.14), not unsupported by accident.
    UnsupportedMethod(String),
    /// Multibase prefix missing or not base58btc (`z`).
    UnsupportedMultibase(char),
    /// Base58btc payload malformed (invalid alphabet character / empty payload).
    BadBase58,
    /// Multicodec prefix is not Ed25519-pub (`0xed`).
    UnsupportedKeyType(u64),
    /// Key material is not 32 bytes.
    BadKeyLength(usize),
    /// The 32 bytes are not a valid Ed25519 compressed point.
    InvalidKey,
    /// [`SignedTreeHead::signer_did_key`]: the `signer` field is not valid hex.
    BadHexSigner,
}

impl std::fmt::Display for DidKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidKeyError::NotDid => write!(f, "kt-log did: not a did: URI"),
            DidKeyError::UnsupportedMethod(m) => write!(
                f,
                "kt-log did: method `{m}` rejected — posture allows did:key naming only \
(no ledger DIDs, no runtime resolver, did:web not core; R-5.14)"
            ),
            DidKeyError::UnsupportedMultibase(c) => write!(
                f,
                "kt-log did: multibase prefix `{c}` unsupported — base58btc (`z`) only"
            ),
            DidKeyError::BadBase58 => write!(f, "kt-log did: base58btc payload malformed"),
            DidKeyError::UnsupportedKeyType(code) => write!(
                f,
                "kt-log did: multicodec 0x{code:x} unsupported — only ed25519-pub (0xed) is named here"
            ),
            DidKeyError::BadKeyLength(n) => {
                write!(f, "kt-log did: key material length {n} (expected 32)")
            }
            DidKeyError::InvalidKey => {
                write!(f, "kt-log did: key bytes are not a valid Ed25519 point")
            }
            DidKeyError::BadHexSigner => {
                write!(f, "kt-log did: signer field is not valid hex")
            }
        }
    }
}

impl std::error::Error for DidKeyError {}

/// Encode an Ed25519 verifying key as a `did:key` URI:
/// `did:key:z` + base58btc(`0xed 0x01` ‖ pubkey bytes). Deterministic, no
/// network, no resolver — see [`DID_POSTURE`].
pub fn did_key_encode(vk: &VerifyingKey) -> String {
    let mut material = Vec::with_capacity(2 + 32);
    material.extend_from_slice(&ED25519_PUB_MULTICODEC);
    material.extend_from_slice(vk.as_bytes());
    let mut s = String::with_capacity(8 + 1 + 45);
    s.push_str("did:key:z");
    s.push_str(&base58btc::encode(&material));
    s
}

/// Decode a `did:key` URI back to an Ed25519 verifying key. Strict, fail-closed:
/// any method other than `key` → [`DidKeyError::UnsupportedMethod`]; any
/// multibase other than base58btc → [`DidKeyError::UnsupportedMultibase`]; any
/// multicodec other than Ed25519-pub → [`DidKeyError::UnsupportedKeyType`].
pub fn did_key_decode(s: &str) -> Result<VerifyingKey, DidKeyError> {
    let rest = s.strip_prefix("did:").ok_or(DidKeyError::NotDid)?;
    let (method, tail) = match rest.split_once(':') {
        Some((m, t)) => (m, t),
        None => return Err(DidKeyError::NotDid),
    };
    if method != "key" {
        return Err(DidKeyError::UnsupportedMethod(method.to_string()));
    }
    let mb = tail.chars().next().ok_or(DidKeyError::BadBase58)?;
    if mb != 'z' {
        return Err(DidKeyError::UnsupportedMultibase(mb));
    }
    let payload = base58btc::decode(&tail[1..]).ok_or(DidKeyError::BadBase58)?;
    let (code, key_bytes) = read_multicodec(&payload).ok_or(DidKeyError::BadBase58)?;
    if code != 0xed {
        return Err(DidKeyError::UnsupportedKeyType(code));
    }
    if key_bytes.len() != 32 {
        return Err(DidKeyError::BadKeyLength(key_bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key_bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| DidKeyError::InvalidKey)
}

/// Shape+material check: `true` only if `s` fully decodes as an Ed25519
/// `did:key` (safe as a pre-filter before [`did_key_decode`]).
pub fn is_did_key(s: &str) -> bool {
    did_key_decode(s).is_ok()
}

/// First varint of a multicodec-prefixed payload: `(code, remaining bytes)`.
fn read_multicodec(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 9 {
            return None; // varint longer than the spec allows here
        }
        value |= ((b & 0x7f) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, &bytes[i + 1..]));
        }
    }
    None
}

impl SignedTreeHead {
    /// The head signer's public key as a `did:key` name (export-artifact naming
    /// per [`DID_POSTURE`] — no resolver is consulted).
    pub fn signer_did_key(&self) -> Result<String, DidKeyError> {
        let bytes = hex::decode(&self.signer).ok_or(DidKeyError::BadHexSigner)?;
        if bytes.len() != 32 {
            return Err(DidKeyError::BadKeyLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let vk = VerifyingKey::from_bytes(&arr).map_err(|_| DidKeyError::InvalidKey)?;
        Ok(did_key_encode(&vk))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal base58btc (multibase `z`) — crate has no base58 dependency; same
// inline-module approach as the minimal hex below. Bitcoin alphabet, leading
// zero bytes map to leading '1' characters (base58btc canonical form).
// ─────────────────────────────────────────────────────────────────────────────

mod base58btc {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// Encode bytes as base58btc (no multibase prefix; caller adds `z`).
    pub fn encode(bytes: &[u8]) -> String {
        let zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let mut digits: Vec<u8> = Vec::new(); // base58 digits, little-endian
        for &b in &bytes[zeros..] {
            let mut carry = b as u32;
            for d in digits.iter_mut() {
                carry += (*d as u32) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let mut s = String::with_capacity(zeros + digits.len());
        for _ in 0..zeros {
            s.push('1');
        }
        for &d in digits.iter().rev() {
            s.push(ALPHABET[d as usize] as char);
        }
        s
    }

    /// Decode base58btc; `None` on any character outside the alphabet.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new(); // base256, little-endian
        for c in s.chars() {
            let idx = ALPHABET.iter().position(|&a| a as char == c)? as u32;
            let mut carry = idx;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let zeros = s.chars().take_while(|&c| c == '1').count();
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        Some(out)
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Minimal hex (crate has no `hex` dependency elsewhere either — same approach
// as `crate::merkle_audit`)
// ─────────────────────────────────────────────────────────────────────────────

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16)?;
            let lo = (bytes[i + 1] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 2;
        }
        Some(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;
    use tempfile::tempdir;

    /// Fixed timestamps keep the tests deterministic.
    const T0: u64 = 1_700_000_000_000;

    fn tmp_log() -> (tempfile::TempDir, KtLog) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        let log = KtLog::open(&path).unwrap();
        (dir, log)
    }

    fn seed3(log: &mut KtLog) {
        log.append_at(b"svc:a issue serial-1", T0).unwrap();
        log.append_at(b"svc:a rotate serial-2", T0 + 1).unwrap();
        log.append_at(b"svc:b issue serial-3", T0 + 2).unwrap();
    }

    #[test]
    fn test_append_chains_and_verifies() {
        let (_dir, mut log) = tmp_log();
        assert!(log.is_empty());
        seed3(&mut log);
        assert_eq!(log.len(), 3);
        log.verify_chain().unwrap();
        for (i, e) in log.entries().iter().enumerate() {
            assert_eq!(e.seq, i as u64);
            assert_eq!(e.payload_hash.len(), 64);
            assert_eq!(e.entry_hash.len(), 64);
        }
        assert_eq!(log.entries()[1].prev_hash, log.entries()[0].entry_hash);
        assert_eq!(log.head_hash(), log.entries()[2].entry_hash);
    }

    #[test]
    fn test_first_prev_hash_is_genesis() {
        let (_dir, mut log) = tmp_log();
        log.append_at(b"svc:a issue serial-1", T0).unwrap();
        assert_eq!(log.entries()[0].prev_hash, genesis_hash());
    }

    #[test]
    fn test_empty_log_verifies_and_root_is_constant() {
        let (_dir, log) = tmp_log();
        log.verify_chain().unwrap();
        assert_eq!(log.tree_root(), empty_tree_root());
        assert_eq!(log.head_hash(), genesis_hash());
    }

    #[test]
    fn test_tamper_payload_hash_detected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        log.entries[1].payload_hash = "00".repeat(32);
        match log.verify_chain() {
            Err(KtError::EntryHashMismatch { seq: 1 }) => {}
            other => panic!("expected EntryHashMismatch at seq 1, got {other:?}"),
        }
    }

    #[test]
    fn test_tamper_timestamp_detected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        log.entries[1].timestamp += 1;
        match log.verify_chain() {
            Err(KtError::EntryHashMismatch { seq: 1 }) => {}
            other => panic!("expected EntryHashMismatch at seq 1, got {other:?}"),
        }
    }

    #[test]
    fn test_tamper_entry_hash_detected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        log.entries[1].entry_hash = "00".repeat(32);
        match log.verify_chain() {
            Err(KtError::EntryHashMismatch { seq: 1 }) => {}
            other => panic!("expected EntryHashMismatch at seq 1, got {other:?}"),
        }
    }

    #[test]
    fn test_tamper_prev_hash_detected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        log.entries[2].prev_hash = "11".repeat(32);
        match log.verify_chain() {
            Err(KtError::PrevHashMismatch { seq: 2 }) => {}
            other => panic!("expected PrevHashMismatch at seq 2, got {other:?}"),
        }
    }

    #[test]
    fn test_reorder_detected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        log.entries.swap(0, 1);
        match log.verify_chain() {
            Err(KtError::SeqMismatch {
                expected: 0,
                found: 1,
            }) => {}
            other => panic!("expected SeqMismatch at position 0, got {other:?}"),
        }
    }

    #[test]
    fn test_interior_truncation_detected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        log.entries.remove(1);
        match log.verify_chain() {
            Err(KtError::SeqMismatch {
                expected: 1,
                found: 2,
            }) => {}
            other => panic!("expected SeqMismatch at position 1, got {other:?}"),
        }
    }

    #[test]
    fn test_tail_truncation_detected_via_signed_head() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        let (sk, vk) = generate_keypair();
        let sth = {
            let mut log = KtLog::open(&path).unwrap();
            seed3(&mut log);
            let sth = log.export_tree_head(&sk).unwrap();
            // The offline holder keeps the head apart from the log.
            fs::write(
                dir.path().join("sth.json"),
                serde_json::to_vec(&sth).unwrap(),
            )
            .unwrap();
            sth
        };
        assert_eq!(sth.head.chain_len, 3);

        // Attacker cuts the tail cleanly (no interior damage).
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        let reopened = KtLog::open(&path).unwrap();
        // The chain alone cannot see a clean tail cut...
        reopened.verify_chain().unwrap();
        // ...but the retained head contradicts it.
        let sth: SignedTreeHead =
            serde_json::from_str(&fs::read_to_string(dir.path().join("sth.json")).unwrap())
                .unwrap();
        sth.verify_signature(&vk).unwrap();
        match sth.verify_against_log(&reopened) {
            Err(KtError::ChainLengthMismatch {
                expected: 3,
                found: 2,
            }) => {}
            other => panic!("expected ChainLengthMismatch 3 vs 2, got {other:?}"),
        }
    }

    #[test]
    fn test_tree_head_deterministic_across_independent_logs() {
        let (_dir1, mut a) = tmp_log();
        let (_dir2, mut b) = tmp_log();
        seed3(&mut a);
        seed3(&mut b);
        assert_eq!(a.tree_root(), b.tree_root());
        assert_eq!(a.entries(), b.entries());
        assert_ne!(a.tree_root(), empty_tree_root());

        // Same length, different payload ⇒ different root.
        let (_dir3, mut c) = tmp_log();
        c.append_at(b"svc:a issue serial-1", T0).unwrap();
        c.append_at(b"svc:a rotate serial-2", T0 + 1).unwrap();
        c.append_at(b"svc:b issue serial-999", T0 + 2).unwrap();
        assert_ne!(a.tree_root(), c.tree_root());
    }

    #[test]
    fn test_signed_tree_head_roundtrip_verifies() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        let (sk, vk) = generate_keypair();
        let sth = log.export_tree_head(&sk).unwrap();
        assert_eq!(sth.signer, hex::encode(vk.as_bytes()));
        sth.verify_signature(&vk).unwrap();
        sth.verify_against_log(&log).unwrap();
        // Head fields match the log.
        assert_eq!(sth.head.chain_len, 3);
        assert_eq!(sth.head.root_hash, log.tree_root());
    }

    #[test]
    fn test_signed_tree_head_wrong_key_rejected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        let (sk, _vk) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let sth = log.export_tree_head(&sk).unwrap();
        match sth.verify_signature(&vk2) {
            Err(KtError::SignerMismatch { .. }) => {}
            other => panic!("expected SignerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_signed_tree_head_tampered_head_rejected() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        let (sk, vk) = generate_keypair();
        let mut sth = log.export_tree_head(&sk).unwrap();
        sth.head.root_hash = "00".repeat(32);
        match sth.verify_signature(&vk) {
            Err(KtError::BadSignature(_)) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn test_export_empty_log_refused() {
        let (_dir, log) = tmp_log();
        let (sk, _vk) = generate_keypair();
        match log.export_tree_head(&sk) {
            Err(KtError::EmptyLog) => {}
            other => panic!("expected EmptyLog, got {other:?}"),
        }
    }

    #[test]
    fn test_empty_payload_rejected() {
        let (_dir, mut log) = tmp_log();
        match log.append_at(b"", T0) {
            Err(KtError::EmptyPayload) => {}
            other => panic!("expected EmptyPayload, got {other:?}"),
        }
        assert!(log.is_empty());
    }

    #[test]
    fn test_reopen_continues_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        {
            let mut log = KtLog::open(&path).unwrap();
            log.append_at(b"svc:a issue serial-1", T0).unwrap();
            log.append_at(b"svc:a rotate serial-2", T0 + 1).unwrap();
        }
        let mut log = KtLog::open(&path).unwrap();
        assert_eq!(log.len(), 2);
        log.verify_chain().unwrap();
        log.append_at(b"svc:b issue serial-3", T0 + 2).unwrap();
        assert_eq!(log.entries()[2].seq, 2);
        assert_eq!(
            log.entries()[2].prev_hash,
            log.entries()[1].entry_hash
        );
        assert_eq!(log.len(), 3);
        log.verify_chain().unwrap();
        // On-disk shape: one JSON object per line, nothing else.
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
        let first: KtEntry = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first, log.entries()[0]);
        assert_eq!(first.payload_hash, payload_hash(b"svc:a issue serial-1"));
    }

    #[test]
    fn test_reopen_rejects_tampered_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        {
            let mut log = KtLog::open(&path).unwrap();
            log.append_at(b"svc:a issue serial-1", T0).unwrap();
            log.append_at(b"svc:a rotate serial-2", T0 + 1).unwrap();
        }
        // Flip one hex digit of the first line's payload_hash on disk.
        let text = fs::read_to_string(&path).unwrap();
        let marker = "\"payload_hash\":\"";
        let idx = text.find(marker).unwrap() + marker.len();
        let mut bytes = text.into_bytes();
        bytes[idx] = if bytes[idx] == b'a' { b'b' } else { b'a' };
        fs::write(&path, &bytes).unwrap();

        match KtLog::open(&path) {
            Err(KtError::EntryHashMismatch { seq: 0 }) => {}
            other => panic!("expected EntryHashMismatch at seq 0, got {other:?}"),
        }
    }

    #[test]
    fn test_malformed_line_rejected_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        fs::write(&path, b"not-json-at-all\n").unwrap();
        match KtLog::open(&path) {
            Err(KtError::MalformedLine { line: 1, .. }) => {}
            other => panic!("expected MalformedLine at line 1, got {other:?}"),
        }
    }

    #[test]
    fn read_only_open_needs_no_write_access_and_leaves_the_mode_alone() {
        // The anchor-account case: a log this account may read but never write.
        let dir = tempdir().unwrap();
        let path = dir.path().join("kt.log");
        {
            let mut w = KtLog::open(&path).unwrap();
            w.append_at(b"first", T0).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }

        let r = KtLog::open_read_only(&path).unwrap();
        assert_eq!(r.len(), 1, "the reader sees the whole chain");
        r.verify_chain().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640,
                "a read-only open must not tighten the mode — that is the whole point"
            );
        }
    }

    #[test]
    fn read_only_open_refuses_a_missing_log_instead_of_creating_one() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent.log");
        assert!(
            KtLog::open_read_only(&path).is_err(),
            "an absent log is an error for a reader"
        );
        assert!(
            !path.exists(),
            "a read path must never bring a log into existence"
        );
        // The write path still creates it, so the two halves stay distinguishable.
        assert!(KtLog::open(&path).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn appending_to_a_read_only_handle_is_refused_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("kt.log");
        {
            let mut w = KtLog::open(&path).unwrap();
            w.append_at(b"only entry", T0).unwrap();
        }
        let before = fs::read_to_string(&path).unwrap();

        let mut r = KtLog::open_read_only(&path).unwrap();
        let err = r.append_at(b"must not land", T0).unwrap_err();
        assert!(
            matches!(err, KtError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "the refusal is a PermissionDenied, not a silent no-op: {err:?}"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "not one byte may reach the file"
        );
        assert_eq!(r.len(), 1, "the in-memory chain must not grow");
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_file_mode_0600_and_tightened_on_reopen() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        {
            let mut log = KtLog::open(&path).unwrap();
            log.append_at(b"svc:a issue serial-1", T0).unwrap();
        }
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new log file must be 0600");

        // Loosen it, reopen, expect tightening back to 0600 and the chain intact.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let log = KtLog::open(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "reopen must tighten to 0600");
        assert_eq!(log.len(), 1);
        log.verify_chain().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_refused() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.jsonl");
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        match KtLog::open(&link) {
            Err(KtError::SymlinkRefused(_)) => {}
            other => panic!("expected SymlinkRefused, got {other:?}"),
        }
    }

    #[test]
    fn test_append_json_and_verify_entries_free_fn() {
        let (_dir, mut log) = tmp_log();
        log.append_json(&serde_json::json!({
            "event": "svid.issue",
            "svc": "spiffe://tallow/node-1/svc/a",
            "serial": "01"
        }))
        .unwrap();
        log.append_at(b"svc:a rotate serial-2", T0).unwrap();
        log.verify_chain().unwrap();
        // An exported copy verifies without any KtLog handle.
        verify_entries(log.entries()).unwrap();
        // And the recomputed root over the copy matches the live log.
        assert_eq!(tree_root_of(log.entries()), log.tree_root());
    }

    // ── DID posture (#211 · R-5.14) ─────────────────────────────────────────

    fn vk_from_hex(h: &str) -> VerifyingKey {
        let bytes = hex::decode(h).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).unwrap()
    }

    #[test]
    fn test_base58btc_known_vectors() {
        // base58btc (Bitcoin alphabet) ground truths; the longer vectors were
        // cross-computed with an independent stdlib-only Python encoder.
        assert_eq!(base58btc::encode(b""), "");
        assert_eq!(base58btc::encode(&[0]), "1");
        assert_eq!(base58btc::encode(&[0, 0, 1]), "112");
        assert_eq!(base58btc::encode(&[1]), "2");
        assert_eq!(base58btc::encode(&[1, 0]), "5R");
        assert_eq!(
            base58btc::encode(&(0u8..32).collect::<Vec<u8>>()),
            "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"
        );
        assert_eq!(
            base58btc::encode(&[0xffu8; 32]),
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
        );
        // Round-trips, including leading zero bytes → leading '1' characters.
        for v in [
            vec![],
            vec![0u8],
            vec![0, 0, 1],
            vec![1, 0],
            vec![0u8; 3],
            (0u8..32).collect::<Vec<u8>>(),
            vec![0xff; 32],
        ] {
            let enc = base58btc::encode(&v);
            assert_eq!(base58btc::decode(&enc).unwrap(), v, "roundtrip {v:?}");
        }
        assert_eq!(base58btc::decode("0OIl"), None); // characters outside the alphabet
    }

    #[test]
    fn test_did_key_roundtrip_and_shape() {
        let (_sk, vk) = generate_keypair();
        let did = did_key_encode(&vk);
        assert!(
            did.starts_with("did:key:z6Mk"),
            "ed25519 did:key names start with z6Mk: {did}"
        );
        let back = did_key_decode(&did).unwrap();
        assert_eq!(back.as_bytes(), vk.as_bytes());
        assert!(is_did_key(&did));
    }

    #[test]
    fn test_did_key_rfc8032_vector() {
        // RFC 8032 TEST 1: secret 9d61…, public key d75a…; the did:key string
        // is 0xed01 ‖ pubkey, base58btc-encoded (cross-checked in Python).
        let sk_bytes =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&sk_bytes);
        let sk = SigningKey::from_bytes(&arr);
        let vk = sk.verifying_key();
        assert_eq!(
            hex::encode(vk.as_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let did = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
        assert_eq!(did_key_encode(&vk), did);
        assert_eq!(did_key_encode(&vk_from_hex(&hex::encode(vk.as_bytes()))), did);
        assert_eq!(did_key_decode(did).unwrap().as_bytes(), vk.as_bytes());
    }

    #[test]
    fn test_did_key_rejects_non_key_methods() {
        // Posture (R-5.14): ledger/Web/pkh methods are rejected by design.
        for s in ["did:web:example.com", "did:ion:EiD-example", "did:pkh:tz:tz1"] {
            match did_key_decode(s) {
                Err(DidKeyError::UnsupportedMethod(_)) => {}
                other => panic!("expected UnsupportedMethod for {s}, got {other:?}"),
            }
        }
        assert!(!is_did_key("did:web:example.com"));
    }

    #[test]
    fn test_did_key_rejects_bad_multibase() {
        // `f` is the multibase prefix for hex, not base58btc.
        match did_key_decode("did:key:fed01") {
            Err(DidKeyError::UnsupportedMultibase('f')) => {}
            other => panic!("expected UnsupportedMultibase('f'), got {other:?}"),
        }
        // A bare base58 string without the `z` prefix.
        let (_, vk) = generate_keypair();
        let did = did_key_encode(&vk);
        let no_z = format!("did:key:{}", &did["did:key:z".len()..]);
        match did_key_decode(&no_z) {
            Err(DidKeyError::UnsupportedMultibase(_)) => {}
            other => panic!("expected UnsupportedMultibase for {no_z}, got {other:?}"),
        }
    }

    #[test]
    fn test_did_key_rejects_wrong_key_type_and_length() {
        // X25519-pub multicodec (0xec01) is a different key type — refused.
        let mut x = vec![0xec, 0x01];
        x.extend_from_slice(&[7u8; 32]);
        let s = format!("did:key:z{}", base58btc::encode(&x));
        match did_key_decode(&s) {
            Err(DidKeyError::UnsupportedKeyType(0xec)) => {}
            other => panic!("expected UnsupportedKeyType(0xec), got {other:?}"),
        }
        // Truncated key material (31 bytes).
        let mut t = vec![0xed, 0x01];
        t.extend_from_slice(&[7u8; 31]);
        let s = format!("did:key:z{}", base58btc::encode(&t));
        match did_key_decode(&s) {
            Err(DidKeyError::BadKeyLength(31)) => {}
            other => panic!("expected BadKeyLength(31), got {other:?}"),
        }
    }

    #[test]
    fn test_did_key_rejects_invalid_point_and_garbage() {
        // bytes([0x02; 32]): x² = (y²−1)/(d·y²+1) is a non-residue for this y
        // (Euler's criterion, independently checked in Python) — decompression
        // must fail, i.e. not a valid Ed25519 compressed point.
        let mut bad = vec![0xed, 0x01];
        bad.extend_from_slice(&[0x02u8; 32]);
        let s = format!("did:key:z{}", base58btc::encode(&bad));
        match did_key_decode(&s) {
            Err(DidKeyError::InvalidKey) => {}
            other => panic!("expected InvalidKey, got {other:?}"),
        }
        // Characters outside the base58 alphabet.
        match did_key_decode("did:key:z0OIl") {
            Err(DidKeyError::BadBase58) => {}
            other => panic!("expected BadBase58, got {other:?}"),
        }
        // Not a DID at all / no method / empty.
        assert!(matches!(did_key_decode("no-did-here"), Err(DidKeyError::NotDid)));
        assert!(matches!(did_key_decode("did:key"), Err(DidKeyError::NotDid)));
        assert!(matches!(did_key_decode(""), Err(DidKeyError::NotDid)));
    }

    #[test]
    fn test_signed_tree_head_signer_did_key() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        let (sk, vk) = generate_keypair();
        let sth = log.export_tree_head(&sk).unwrap();
        assert_eq!(sth.signer_did_key().unwrap(), did_key_encode(&vk));

        // Tampered signer fields fail closed.
        let mut sth_hex = sth.clone();
        sth_hex.signer = "zz".to_string();
        assert!(matches!(sth_hex.signer_did_key(), Err(DidKeyError::BadHexSigner)));

        let mut sth_len = sth.clone();
        sth_len.signer = "abcd".to_string();
        assert!(matches!(sth_len.signer_did_key(), Err(DidKeyError::BadKeyLength(2))));

        let mut sth_point = sth.clone();
        sth_point.signer = hex::encode(&[0x02u8; 32]); // non-decompressible point
        assert!(matches!(sth_point.signer_did_key(), Err(DidKeyError::InvalidKey)));

        // The posture label itself is available to callers/doctor output.
        assert!(DID_POSTURE.contains("ledger") && DID_POSTURE.contains("resolver"));
    }

    // ── proofs (#80 · R-5.6) ────────────────────────────────────────────────

    fn seed_n(log: &mut KtLog, n: usize) {
        for i in 0..n {
            log.append_at(format!("svc:a issue serial-{i}").as_bytes(), T0 + i as u64)
                .unwrap();
        }
    }

    #[test]
    fn test_inclusion_proof_every_index_every_size() {
        for n in 1..=12usize {
            let (_dir, mut log) = tmp_log();
            seed_n(&mut log, n);
            let root = log.tree_root();
            for i in 0..n {
                let proof = log.prove_inclusion(i).unwrap();
                assert_eq!(proof.leaf_index, i as u64);
                assert_eq!(proof.tree_size, n as u64);
                assert_eq!(proof.entry_hash, log.entries()[i].entry_hash);
                proof
                    .verify(&root)
                    .unwrap_or_else(|e| panic!("n={n} i={i}: {e}"));
            }
        }
    }

    #[test]
    fn test_inclusion_proof_rejects_out_of_range_and_empty() {
        let (_dir, mut log) = tmp_log();
        assert!(matches!(prove_inclusion(&[], 0), Err(KtError::EmptyLog)));
        seed3(&mut log);
        match log.prove_inclusion(3) {
            Err(KtError::LeafIndexOutOfRange {
                index: 3,
                tree_size: 3,
            }) => {}
            other => panic!("expected LeafIndexOutOfRange, got {other:?}"),
        }
        // A proof claiming an empty tree is malformed at verification time.
        let bad = InclusionProof {
            leaf_index: 0,
            tree_size: 0,
            entry_hash: log.entries()[0].entry_hash.clone(),
            siblings: Vec::new(),
        };
        match bad.verify(&log.tree_root()) {
            Err(KtError::LeafIndexOutOfRange {
                index: 0,
                tree_size: 0,
            }) => {}
            other => panic!("expected LeafIndexOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn test_inclusion_proof_adversarial_paths_rejected() {
        let (_dir, mut log) = tmp_log();
        seed_n(&mut log, 7); // 7 → 4 → 2 → 1: exercises the duplicate-last spine
        let root = log.tree_root();
        let good = log.prove_inclusion(6).unwrap();
        assert_eq!(good.siblings.len(), 2, "index 6 sits on the duplicated spine");

        // Flipped sibling value.
        let mut bad = good.clone();
        bad.siblings[0] = "00".repeat(32);
        match bad.verify(&root) {
            Err(KtError::RootHashMismatch { .. }) => {}
            other => panic!("expected RootHashMismatch, got {other:?}"),
        }
        // Dropped / padded transcripts fail on shape before any hashing.
        let mut bad = good.clone();
        bad.siblings.pop();
        match bad.verify(&root) {
            Err(KtError::ProofShapeMismatch {
                expected: 2,
                found: 1,
            }) => {}
            other => panic!("expected ProofShapeMismatch, got {other:?}"),
        }
        let mut bad = good.clone();
        bad.siblings.push("ab".repeat(32));
        match bad.verify(&root) {
            Err(KtError::ProofShapeMismatch {
                expected: 2,
                found: 3,
            }) => {}
            other => panic!("expected ProofShapeMismatch, got {other:?}"),
        }
        // A different (real) entry hash under the same root is rejected.
        let mut bad = good.clone();
        bad.entry_hash = log.entries()[0].entry_hash.clone();
        match bad.verify(&root) {
            Err(KtError::RootHashMismatch { .. }) => {}
            other => panic!("expected RootHashMismatch, got {other:?}"),
        }
        // Wrong position with the same transcript is rejected.
        let mut bad = good;
        bad.leaf_index = 0;
        assert!(bad.verify(&root).is_err(), "wrong leaf_index must not verify");
        // And the honest proof still verifies afterwards.
        log.prove_inclusion(6).unwrap().verify(&root).unwrap();
    }

    #[test]
    fn test_inclusion_proof_against_signed_head() {
        let (_dir, mut log) = tmp_log();
        seed3(&mut log);
        let (sk, vk) = generate_keypair();
        let sth = log.export_tree_head(&sk).unwrap();
        let proof = log.prove_inclusion(1).unwrap();
        sth.verify_signature(&vk).unwrap();
        sth.verify_inclusion(&proof).unwrap();

        // A proof minted for a different tree size is refused by the head.
        let (_dir2, mut other_log) = tmp_log();
        seed_n(&mut other_log, 5);
        let p2 = other_log.prove_inclusion(0).unwrap();
        match sth.verify_inclusion(&p2) {
            Err(KtError::ChainLengthMismatch {
                expected: 3,
                found: 5,
            }) => {}
            other => panic!("expected ChainLengthMismatch, got {other:?}"),
        }
        // A head whose committed root was altered rejects the honest proof.
        let mut sth_t = sth.clone();
        sth_t.head.root_hash = "00".repeat(32);
        assert!(sth_t.verify_inclusion(&proof).is_err());
    }

    #[test]
    fn test_consistency_proof_power_of_two_roundtrip() {
        for old in [1usize, 2, 4, 8] {
            for new in [old, old + 1, old + 3, old * 2] {
                let (_dir, mut log) = tmp_log();
                seed_n(&mut log, new);
                let old_head = TreeHead {
                    chain_len: old as u64,
                    root_hash: tree_root_of(&log.entries()[..old]),
                    timestamp: T0,
                };
                let new_head = log.tree_head_at(T0 + 1);
                let proof = prove_consistency(log.entries(), old).unwrap();
                assert_eq!(proof.old_root, old_head.root_hash);
                assert_eq!(proof.new_root, new_head.root_hash);
                proof
                    .verify(&old_head, &new_head)
                    .unwrap_or_else(|e| panic!("old={old} new={new}: {e}"));

                // Folding against a rewritten new root (or old root) fails.
                let mut forged = new_head.clone();
                forged.root_hash = "00".repeat(32);
                assert!(proof.verify(&old_head, &forged).is_err());
                let mut forged_old = old_head.clone();
                forged_old.root_hash = "11".repeat(32);
                assert!(proof.verify(&forged_old, &new_head).is_err());
            }
        }
    }

    #[test]
    fn test_consistency_proof_rejections() {
        let (_dir, mut log) = tmp_log();
        seed_n(&mut log, 9);
        match prove_consistency(log.entries(), 3) {
            Err(KtError::ConsistencyRequiresPowerOfTwo { old_size: 3 }) => {}
            other => panic!("expected ConsistencyRequiresPowerOfTwo, got {other:?}"),
        }
        assert!(matches!(
            prove_consistency(log.entries(), 0),
            Err(KtError::ChainLengthMismatch { .. })
        ));
        assert!(matches!(
            prove_consistency(log.entries(), 10),
            Err(KtError::ChainLengthMismatch { .. })
        ));

        let old_head = TreeHead {
            chain_len: 4,
            root_hash: tree_root_of(&log.entries()[..4]),
            timestamp: T0,
        };
        let new_head = log.tree_head_at(T0 + 1);
        // Tampered sibling.
        let mut proof = prove_consistency(log.entries(), 4).unwrap();
        proof.siblings[0] = "00".repeat(32);
        match proof.verify(&old_head, &new_head) {
            Err(KtError::RootHashMismatch { .. }) => {}
            other => panic!("expected RootHashMismatch, got {other:?}"),
        }
        // Dropped sibling.
        let mut proof = prove_consistency(log.entries(), 4).unwrap();
        proof.siblings.pop();
        match proof.verify(&old_head, &new_head) {
            Err(KtError::ProofShapeMismatch {
                expected: 2,
                found: 1,
            }) => {}
            other => panic!("expected ProofShapeMismatch, got {other:?}"),
        }
        // Size field disagreeing with the supplied heads.
        let mut proof = prove_consistency(log.entries(), 4).unwrap();
        proof.new_size = 8;
        assert!(matches!(
            proof.verify(&old_head, &new_head),
            Err(KtError::ChainLengthMismatch { .. })
        ));
        // Wrong old root (spliced across head pairs).
        let proof = prove_consistency(log.entries(), 4).unwrap();
        let wrong_old = TreeHead {
            chain_len: 4,
            root_hash: "11".repeat(32),
            timestamp: T0,
        };
        assert!(matches!(
            proof.verify(&wrong_old, &new_head),
            Err(KtError::RootHashMismatch { .. })
        ));
    }

    #[test]
    fn test_consistency_arbitrary_sizes_prefix_recomputation() {
        let (_dir, mut log) = tmp_log();
        seed_n(&mut log, 6);
        let old_head = TreeHead {
            chain_len: 3,
            root_hash: tree_root_of(&log.entries()[..3]),
            timestamp: T0,
        };
        // Honest: the retained head is a prefix of the full log.
        old_head.verify_prefix_of(log.entries()).unwrap();

        // Structural fact that forces the compact leg to power-of-two sizes:
        // for m = 3 the old tree's borderline node node(c, c) is not a node of
        // the larger tree — while node(a, b) and node(c, d) are.
        let l0: Vec<String> = log.entries().iter().map(|e| leaf_of(&e.entry_hash)).collect();
        let l1 = fold_one_level(&l0);
        let l2 = fold_one_level(&l1);
        let mut nodes: Vec<String> = l1.clone();
        nodes.extend(l2.clone());
        assert!(
            !nodes.contains(&node_of(&l0[2], &l0[2])),
            "duplicate-last borderline node must be absent from the larger tree"
        );
        assert!(nodes.contains(&node_of(&l0[0], &l0[1])));
        assert!(nodes.contains(&node_of(&l0[2], &l0[3])));

        // A rewrite of an already-committed entry is caught.
        let mut rewritten = log.entries().to_vec();
        rewritten[1].payload_hash = payload_hash(b"svc:a rotate serial-1 REWRITTEN");
        rewritten[1].entry_hash = entry_hash_hex(
            1,
            &rewritten[0].entry_hash,
            &rewritten[1].payload_hash,
            rewritten[1].timestamp,
        );
        match old_head.verify_prefix_of(&rewritten) {
            Err(KtError::RootHashMismatch { .. }) => {}
            other => panic!("expected RootHashMismatch, got {other:?}"),
        }
        // Fewer entries than the head length is refused.
        match old_head.verify_prefix_of(&log.entries()[..2]) {
            Err(KtError::ChainLengthMismatch {
                expected: 3,
                found: 2,
            }) => {}
            other => panic!("expected ChainLengthMismatch, got {other:?}"),
        }
        // The signed-head convenience agrees.
        let (sk, _vk) = generate_keypair();
        let sth = log.export_tree_head(&sk).unwrap();
        sth.verify_extends(log.entries()).unwrap();
        assert!(sth.verify_extends(&log.entries()[..5]).is_err());
    }

    #[test]
    fn test_offline_audit_flow_inclusion_and_consistency() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("svid-kt.jsonl");
        let (sk, vk) = generate_keypair();

        // Phase 1: a head is exported over the first 4 entries and retained.
        let head4 = {
            let mut log = KtLog::open(&path).unwrap();
            seed_n(&mut log, 4);
            log.export_tree_head(&sk).unwrap()
        };
        // Phase 2: three more entries; a second head is exported.
        let (head7, entries7) = {
            let mut log = KtLog::open(&path).unwrap();
            for i in 4..7usize {
                log.append_at(format!("svc:a issue serial-{i}").as_bytes(), T0 + i as u64)
                    .unwrap();
            }
            (log.export_tree_head(&sk).unwrap(), log.entries().to_vec())
        };
        head4.verify_signature(&vk).unwrap();
        head7.verify_signature(&vk).unwrap();

        // Inclusion: entry 5 is committed by head7 — proven compactly.
        let p5 = prove_inclusion(&entries7, 5).unwrap();
        head7.verify_inclusion(&p5).unwrap();
        // The same proof does not verify against the earlier, smaller head.
        match head4.verify_inclusion(&p5) {
            Err(KtError::ChainLengthMismatch {
                expected: 4,
                found: 7,
            }) => {}
            other => panic!("expected ChainLengthMismatch, got {other:?}"),
        }

        // Consistency: the retained head4 (power of two) folds into head7.
        let cons = prove_consistency(&entries7, 4).unwrap();
        cons.verify(&head4.head, &head7.head).unwrap();

        // A later audit against a rewritten prefix fails — both legs.
        let mut rewritten = entries7.clone();
        rewritten[1].payload_hash = payload_hash(b"svc:a rotate serial-1 REWRITTEN");
        rewritten[1].entry_hash = entry_hash_hex(
            1,
            &rewritten[0].entry_hash,
            &rewritten[1].payload_hash,
            rewritten[1].timestamp,
        );
        assert!(head4.head.verify_prefix_of(&rewritten).is_err());
        assert!(head7.verify_against(&rewritten).is_err());

        // A clean tail truncation to 5 entries: head4 still holds against the
        // truncated log via the compact fold (no prefix entries needed) while
        // head7 demonstrably does not cover it any more.
        let five = entries7[..5].to_vec();
        let head5 = TreeHead {
            chain_len: 5,
            root_hash: tree_root_of(&five),
            timestamp: T0,
        };
        let cons5 = prove_consistency(&five, 4).unwrap();
        cons5.verify(&head4.head, &head5).unwrap();
        match head7.verify_against(&five) {
            Err(KtError::ChainLengthMismatch {
                expected: 7,
                found: 5,
            }) => {}
            other => panic!("expected ChainLengthMismatch, got {other:?}"),
        }
        // The truncated tree genuinely is not the 7-entry tree.
        assert_ne!(head5.root_hash, head7.head.root_hash);
    }
}
