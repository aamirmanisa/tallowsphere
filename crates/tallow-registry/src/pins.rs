//! Peer pin registry (`pins.json`) — the pin-store side of the
//! pin + registry-verify arc (fix-wave B R5; lane E design). Doctrine:
//! **pin + registry-verify, NOT trust-on-first-use**; no third party in the
//! trust path.
//!
//! A pin row is `{id, kind, mode, status, source, created_ms, updated_ms,
//! notes}`:
//!
//! - `id` — lowercase hex, 32 bytes: a peer **identity id** (kind
//!   `"identity"`; the BLAKE3 hybrid-public-key fingerprint from
//!   `tallow-crypto::keys::identity::id_for_public_key`) or the **sha256 of a
//!   server's SubjectPublicKeyInfo DER** (kind `"spki"`; the transport-side
//!   pin consumed by `tallow-net`'s pinned TLS verifier).
//! - `mode` — `"pinned"` (v1, the only mode; reserved for later observation
//!   modes without changing the row shape).
//! - `status` — `"active"` | `"revoked"`.
//! - `source` — how the pin entered the store: `"operator"`, `"qr"`, `"oob"`,
//!   or `"self"`. Rows enter ONLY through an explicit [`PinsStore::add`] call
//!   (the CLI surfaces this as `tallow pin add`) — never as a side effect of
//!   a connection.
//!
//! **Fail-closed discipline:** verification paths resolve pins through
//! [`PinsStore::require_active_identity_pin`] /
//! [`PinsStore::require_active_spki_pin`]. Absent or revoked rows are
//! *errors* — never "accept and record". The actionable message ("unverified
//! peer; compare the safety code, then `tallow pin add <id>`") belongs to the
//! caller. Nothing enters the trust store implicitly.
//!
//! Every pin / re-pin / revoke is meant to be receipt-logged by the caller
//! (kinds `pin.add` / `pin.repin` / `pin.revoke` appended to the shared
//! receipts ledger): this module returns the facts, the CLI appends the
//! signed receipts.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::now_ms;

/// Pin kind: 32-byte peer identity id (BLAKE3 fingerprint), hex.
pub const PIN_KIND_IDENTITY: &str = "identity";
/// Pin kind: sha256 of a server SubjectPublicKeyInfo DER, hex.
pub const PIN_KIND_SPKI: &str = "spki";
/// The v1 pin mode (only mode; reserved name for later observation modes).
pub const PIN_MODE_PINNED: &str = "pinned";
/// Accepted sources for a pin row.
pub const PIN_SOURCES: [&str; 4] = ["operator", "qr", "oob", "self"];

/// One pin row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRow {
    /// Lowercase hex, 32 bytes (see module docs for the kind-specific meaning).
    pub id: String,
    /// `"identity"` | `"spki"`.
    pub kind: String,
    /// `"pinned"` (v1).
    pub mode: String,
    /// `"active"` | `"revoked"`.
    pub status: String,
    /// `"operator"` | `"qr"` | `"oob"` | `"self"`.
    pub source: String,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinsDoc {
    v: u32,
    pins: Vec<PinRow>,
}

/// Pin-store errors.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid pin id (want 64 hex chars / 32 bytes): {0}")]
    Id(String),
    #[error("invalid pin kind: {0} (want `identity` or `spki`)")]
    Kind(String),
    #[error("invalid pin source: {0} (want one of operator|qr|oob|self)")]
    Source(String),
    #[error("unknown pin: {0}")]
    Unknown(String),
    #[error("pin already revoked: {0}")]
    AlreadyRevoked(String),
    /// Fail-closed verdict: the peer has no active pin. Callers must refuse
    /// (or demand an explicit out-of-band provisioning act), never accept.
    #[error(
        "peer is not pinned: {0} (compare the safety code out-of-band, then `tallow pin add {0}`)"
    )]
    NotPinned(String),
    /// Fail-closed verdict: the only pin present is revoked.
    #[error("pin is revoked: {0}")]
    Revoked(String),
    #[error("pin kind mismatch: row is `{got}`, wanted `{want}`")]
    KindMismatch { got: String, want: String },
}

/// Outcome of an `add` (relevant to which receipt the caller appends).
#[derive(Debug, Clone)]
pub struct PinChange {
    pub row: PinRow,
    /// `true` when the row already existed (this is a re-pin).
    pub repin: bool,
}

/// Read-only verdict for a pin lookup.
#[derive(Debug, Clone)]
pub enum PinVerdict {
    Active(PinRow),
    Revoked(PinRow),
    Absent,
}

/// The pins store (load, mutate, atomic save).
pub struct PinsStore {
    path: PathBuf,
    doc: PinsDoc,
}

fn normalize_id(id: &str) -> Result<String, PinError> {
    let raw = hex::decode(id).map_err(|e| PinError::Id(e.to_string()))?;
    if raw.len() != 32 {
        return Err(PinError::Id(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    Ok(hex::encode(raw))
}

fn validate_kind(kind: &str) -> Result<(), PinError> {
    match kind {
        PIN_KIND_IDENTITY | PIN_KIND_SPKI => Ok(()),
        other => Err(PinError::Kind(other.to_string())),
    }
}

fn validate_source(source: &str) -> Result<(), PinError> {
    if PIN_SOURCES.contains(&source) {
        Ok(())
    } else {
        Err(PinError::Source(source.to_string()))
    }
}

impl PinsStore {
    /// Create an empty pins file if missing; otherwise load it.
    pub fn init(path: &Path) -> Result<Self, PinError> {
        if path.exists() {
            return Self::load(path);
        }
        let store = Self {
            path: path.to_path_buf(),
            doc: PinsDoc {
                v: 1,
                pins: Vec::new(),
            },
        };
        store.save()?;
        Ok(store)
    }

    /// Load an existing pins file (never creates anything — reads are
    /// fail-visible on a missing store).
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let text = std::fs::read_to_string(path)?;
        let doc: PinsDoc = serde_json::from_str(&text)?;
        Ok(Self {
            path: path.to_path_buf(),
            doc,
        })
    }

    /// Atomic save (write tmp file, rename over target).
    pub fn save(&self) -> Result<(), PinError> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&self.doc)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Add or re-pin a row. `created_ms` is preserved across re-pins; a
    /// re-pin flips the row back to `active` and refreshes source/notes.
    /// The row is only valid once an explicit provisioning act calls this —
    /// never automatically.
    pub fn add(
        &mut self,
        id: &str,
        kind: &str,
        source: &str,
        notes: Option<String>,
    ) -> Result<PinChange, PinError> {
        validate_kind(kind)?;
        validate_source(source)?;
        let id = normalize_id(id)?;
        let now = now_ms();
        let (row, repin) = match self.doc.pins.iter().position(|r| r.id == id) {
            Some(i) => {
                let row = &mut self.doc.pins[i];
                row.kind = kind.to_string();
                row.status = "active".to_string();
                row.source = source.to_string();
                row.notes = notes;
                row.updated_ms = now;
                let done = self.doc.pins[i].clone();
                (done, true)
            }
            None => {
                let row = PinRow {
                    id: id.clone(),
                    kind: kind.to_string(),
                    mode: PIN_MODE_PINNED.to_string(),
                    status: "active".to_string(),
                    source: source.to_string(),
                    created_ms: now,
                    updated_ms: now,
                    notes,
                };
                self.doc.pins.push(row.clone());
                (row, false)
            }
        };
        Ok(PinChange { row, repin })
    }

    /// Revoke an active row (errors on unknown or already-revoked rows).
    pub fn revoke(&mut self, id: &str) -> Result<PinRow, PinError> {
        let id = normalize_id(id)?;
        let want = id.clone();
        let row = self
            .doc
            .pins
            .iter_mut()
            .find(|r| r.id == want)
            .ok_or(PinError::Unknown(id.clone()))?;
        if row.status == "revoked" {
            return Err(PinError::AlreadyRevoked(id));
        }
        row.status = "revoked".to_string();
        row.updated_ms = now_ms();
        Ok(row.clone())
    }

    /// Lookup by id.
    pub fn get(&self, id: &str) -> Option<&PinRow> {
        let ok = normalize_id(id).ok()?;
        self.doc.pins.iter().find(|r| r.id == ok)
    }

    /// All rows, in insertion order.
    pub fn list(&self) -> &[PinRow] {
        &self.doc.pins
    }

    /// Read-only verdict (no fail-closed semantics — for display paths).
    pub fn verdict(&self, id: &str) -> PinVerdict {
        match self.get(id) {
            Some(r) if r.status == "active" => PinVerdict::Active(r.clone()),
            Some(r) => PinVerdict::Revoked(r.clone()),
            None => PinVerdict::Absent,
        }
    }

    /// Fail-closed resolution used by verification paths: returns the expected
    /// **identity** pin bytes only for an active `kind = "identity"` row.
    /// Absent ⇒ [`PinError::NotPinned`]; revoked ⇒ [`PinError::Revoked`];
    /// wrong kind ⇒ [`PinError::KindMismatch`]. Callers MUST treat every
    /// error as refuse.
    pub fn require_active_identity_pin(&self, id: &str) -> Result<[u8; 32], PinError> {
        self.require_active_pin(id, PIN_KIND_IDENTITY)
    }

    /// Fail-closed resolution for the transport (SPKI) pin — see
    /// [`Self::require_active_identity_pin`].
    pub fn require_active_spki_pin(&self, id: &str) -> Result<[u8; 32], PinError> {
        self.require_active_pin(id, PIN_KIND_SPKI)
    }

    fn require_active_pin(&self, id: &str, want: &str) -> Result<[u8; 32], PinError> {
        let row = self
            .get(id)
            .ok_or_else(|| PinError::NotPinned(id.to_string()))?;
        if row.status != "active" {
            return Err(PinError::Revoked(id.to_string()));
        }
        if row.kind != want {
            return Err(PinError::KindMismatch {
                got: row.kind.clone(),
                want: want.to_string(),
            });
        }
        let raw = hex::decode(&row.id).map_err(|e| PinError::Id(e.to_string()))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|v: Vec<u8>| PinError::Id(format!("expected 32 bytes, got {}", v.len())))?;
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("tallow-pins-unit-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn hex32(b: u8) -> String {
        hex::encode([b; 32])
    }

    #[test]
    fn lifecycle_and_fail_closed_resolution() {
        let dir = tmpdir("lifecycle");
        let path = dir.join("pins.json");
        let mut store = PinsStore::init(&path).unwrap();

        let id = hex32(0x11);
        let c = store.add(&id, PIN_KIND_IDENTITY, "oob", None).unwrap();
        assert!(!c.repin);
        assert_eq!(store.require_active_identity_pin(&id).unwrap(), [0x11; 32]);

        // Re-pin: preserved created_ms, repin flag set.
        let c2 = store.add(&id, PIN_KIND_IDENTITY, "operator", None).unwrap();
        assert!(c2.repin);
        assert_eq!(c2.row.created_ms, c.row.created_ms);

        // Wrong kind is a hard error for the identity resolver.
        let id2 = hex32(0x22);
        store.add(&id2, PIN_KIND_SPKI, "oob", None).unwrap();
        assert!(matches!(
            store.require_active_identity_pin(&id2),
            Err(PinError::KindMismatch { .. })
        ));
        assert_eq!(store.require_active_spki_pin(&id2).unwrap(), [0x22; 32]);

        // Revoke: resolvers refuse; re-add flips back to active.
        store.revoke(&id2).unwrap();
        assert!(matches!(
            store.require_active_spki_pin(&id2),
            Err(PinError::Revoked(_))
        ));
        let c3 = store.add(&id2, PIN_KIND_SPKI, "operator", None).unwrap();
        assert!(c3.repin);
        assert!(store.require_active_spki_pin(&id2).is_ok());

        // Absent = fail closed.
        assert!(matches!(
            store.require_active_identity_pin(&hex32(0x33)),
            Err(PinError::NotPinned(_))
        ));
        // Double revoke refused.
        store.revoke(&id2).unwrap();
        assert!(matches!(
            store.revoke(&id2),
            Err(PinError::AlreadyRevoked(_))
        ));
    }

    #[test]
    fn rejects_bad_inputs() {
        let dir = tmpdir("bad");
        let path = dir.join("pins.json");
        let mut store = PinsStore::init(&path).unwrap();
        assert!(matches!(
            store.add("zz", PIN_KIND_IDENTITY, "oob", None),
            Err(PinError::Id(_))
        ));
        assert!(matches!(
            store.add(&hex32(1), "ed25519", "oob", None),
            Err(PinError::Kind(_))
        ));
        assert!(matches!(
            store.add(&hex32(1), PIN_KIND_IDENTITY, "web", None),
            Err(PinError::Source(_))
        ));
        assert!(matches!(store.revoke(&hex32(9)), Err(PinError::Unknown(_))));
    }

    #[test]
    fn load_never_creates_and_survives_roundtrip() {
        let dir = tmpdir("roundtrip");
        let path = dir.join("pins.json");
        assert!(PinsStore::load(&path).is_err());
        assert!(!path.exists());

        let mut store = PinsStore::init(&path).unwrap();
        let id = hex32(0x44);
        store
            .add(&id, PIN_KIND_IDENTITY, "qr", Some("phone".into()))
            .unwrap();
        // Mutations are in-memory; persistence is explicit (callers append the
        // receipt first, then `save()` — the CLI flow).
        store.save().unwrap();
        drop(store);

        let reloaded = PinsStore::load(&path).unwrap();
        let row = reloaded.get(&id).unwrap();
        assert_eq!(row.source, "qr");
        assert_eq!(row.mode, PIN_MODE_PINNED);
        assert_eq!(row.status, "active");
        assert_eq!(row.notes.as_deref(), Some("phone"));
    }
}
