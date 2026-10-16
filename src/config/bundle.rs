//! Signed config bundles — R-7.4 / R-7.8 (W3 rows **#153** now-leg + **#198** Ed25519 leg).
//!
//! Design source: `phase7-config/07-config-system-draft.md` R-7.4 ("Signed config
//! bundles (Ed25519 now, ML-DSA hybrid later); verify-before-load for
//! system/swarm scopes; key rotation via `key_ledger`") and R-7.8 ("config bundle
//! export/import now … secrets never sync as values").
//!
//! A **bundle** is the exact config artifact text plus a signed envelope:
//!
//! ```text
//! { "body": { magic, bundle_version, alg, scope, created_ms, config_toml },
//!   "signatures": [ { alg, key_id, public_key, signature } ] }
//! ```
//!
//! Signing bytes are the canonical `serde_json` encoding of `body` (struct field
//! order, no maps — deterministic); the signature is Ed25519 over the SHA-256 of
//! those bytes ([`crate::signing::sign_artifact`] / [`crate::signing::verify_artifact`],
//! the same construction the package/installer verify chain uses). Zero new
//! dependencies.
//!
//! # Fail-closed rules (verify-before-load)
//!
//! 1. an **unsigned** bundle is refused (`E7024`) — v1 is signed-only;
//! 2. any signature that does not verify refuses the whole bundle (`E7025`) —
//!    this is the tamper refusal (body text, scope, timestamps and the embedded
//!    public key are all inside the signed bytes);
//! 3. `alg` must be [`ALG_ED25519`]; the reserved
//!    [`ALG_MLDSA_HYBRID_RESERVED`] word is **parsed and explicitly refused**
//!    (`E7023` — "ML-DSA hybrid later" per row #198), never silently accepted;
//! 4. the **verified scopes** (`system`, `swarm`) demand a *pinned* trusted
//!    signer: no trust anchors supplied, a signer outside them, or an unsigned
//!    sibling signature on an otherwise valid bundle → refused (`E7026`);
//!    non-verified scopes accept a self-signed bundle as *integrity-only*, and
//!    an explicit trust list is still enforced for them;
//! 5. [`load_scoped`] is the reader-side gate: a plain (unsigned) artifact at a
//!    `system`/`swarm` scope is refused (`E7027`) before any parse;
//! 6. export refuses to sign an artifact that fails strict kernel validation
//!    (`E7029`) — "sign only what the kernel would accept";
//! 7. import order is **verify → strict kernel load → atomic write**
//!    ([`crate::config::write::commit`], so the D6 history revision and the
//!    atomic staged replace the kernel already owns apply unchanged); a refusal
//!    writes nothing and records nothing.
//!
//! # Diagnostic codes (bundle block `E7020`–`E7031`, inside the kernel's reserved
//! `E7001`–`E7099` range — see [`super`])
//! | code | meaning |
//! |---|---|
//! | `E7020` | bundle artifact could not be parsed (or produced) |
//! | `E7021` | not a bundle — magic mismatch |
//! | `E7022` | unsupported bundle format version |
//! | `E7023` | unsupported signature algorithm (incl. the reserved ML-DSA hybrid, refused as "later") |
//! | `E7024` | unsigned bundle — refused |
//! | `E7025` | signature does not verify — bundle refused (tamper / wrong key) |
//! | `E7026` | signer not pinned for the bundle's scope — refused (verify-before-load) |
//! | `E7027` | plain artifact at a `system`/`swarm` scope — refused |
//! | `E7028` | invalid key material (key file / embedded key) |
//! | `E7029` | export refused: source artifact failed strict kernel validation |
//! | `E7030` | declared import scope ≠ bundle scope (relabel refused) |
//! | `E7031` | bundle I/O failure |
//!
//! # Residual legs (honest — not this lane)
//! - **ML-DSA hybrid** (row #198 "later"): refused explicitly today; no hybrid
//!   verifier exists.
//! - **Mesh sync** (`config sync --peer`, #153): needs P5 identity + mesh
//!   transport (W5); this module ships export/import only.
//! - **Key rotation via `key_ledger`** (#198): bundles carry `key_id` + signer
//!   public key; pinning is by explicit file today, no revision floor yet.
//! - [`load_scoped`] is the gate the (KB-2) scope-resolution read path must call;
//!   KB-2 is not landed, so no live startup read path consumes it yet.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::load::{self, ConfigLoad};
use super::schema::ConfigError;
use super::write::{self, WriteOptions};
use crate::signing;

// ── Format constants ─────────────────────────────────────────────────────────

/// Magic string in every bundle body; a mismatch is `E7021`.
pub const BUNDLE_MAGIC: &str = "tallow-config-bundle";
/// Format version this build writes and reads.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;
/// The only signature algorithm v1 accepts.
pub const ALG_ED25519: &str = "ed25519";
/// Reserved hybrid algorithm word (row #198: "ML-DSA hybrid later"). Parsed and
/// refused with `E7023` — never accepted silently.
pub const ALG_MLDSA_HYBRID_RESERVED: &str = "ml-dsa-87+ed25519";

// ── Diagnostics (bundle block E7020–E7031) ───────────────────────────────────

/// `E7020` — bundle artifact could not be parsed (or produced).
pub const CODE_BUNDLE_MALFORMED: &str = "E7020";
/// `E7021` — magic mismatch: not a tallow config bundle.
pub const CODE_BUNDLE_MAGIC: &str = "E7021";
/// `E7022` — unsupported bundle format version.
pub const CODE_BUNDLE_VERSION: &str = "E7022";
/// `E7023` — unsupported signature algorithm.
pub const CODE_BUNDLE_ALG: &str = "E7023";
/// `E7024` — unsigned bundle refused.
pub const CODE_BUNDLE_UNSIGNED: &str = "E7024";
/// `E7025` — signature verification failed (tamper refusal).
pub const CODE_BUNDLE_SIGNATURE: &str = "E7025";
/// `E7026` — signer not trusted/pinned for the bundle's scope.
pub const CODE_BUNDLE_UNTRUSTED: &str = "E7026";
/// `E7027` — plain artifact at a `system`/`swarm` scope.
pub const CODE_SCOPE_UNSIGNED_LOAD: &str = "E7027";
/// `E7028` — invalid key material.
pub const CODE_BUNDLE_KEY: &str = "E7028";
/// `E7029` — export refused: source artifact failed strict validation.
pub const CODE_BUNDLE_EXPORT: &str = "E7029";
/// `E7030` — declared import scope ≠ bundle scope.
pub const CODE_BUNDLE_SCOPE_MISMATCH: &str = "E7030";
/// `E7031` — bundle I/O failure.
pub const CODE_BUNDLE_IO: &str = "E7031";

// ── Scope ────────────────────────────────────────────────────────────────────

/// The bundle-side scope names.
///
/// The eight R-7.2 resolution scopes (`defaults < profile < system < user <
/// device < project < agent < session`, `07-config-system-draft.md` R-7.2 /
/// R-7.4) plus the **swarm** scope named by rows #153/#198. The full layered
/// resolution engine is KB-2's (`scopes.rs`/`resolve.rs`, not landed); this enum
/// is exactly the vocabulary a bundle carries and the two scopes that demand a
/// pinned signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigScope {
    /// Built-in defaults scope.
    Defaults,
    /// Profile scope (hardening profile layer).
    Profile,
    /// System-wide scope — **verified**: requires a pinned trusted signer.
    System,
    /// Per-user scope (the default config location).
    User,
    /// Per-device scope.
    Device,
    /// Per-project scope.
    Project,
    /// Per-agent scope.
    Agent,
    /// Per-session scope.
    Session,
    /// Swarm / multi-agent scope — **verified**: requires a pinned trusted signer.
    Swarm,
}

impl ConfigScope {
    /// Every accepted scope, in R-7.2 ladder order (swarm last).
    pub const ALL: [ConfigScope; 9] = [
        ConfigScope::Defaults,
        ConfigScope::Profile,
        ConfigScope::System,
        ConfigScope::User,
        ConfigScope::Device,
        ConfigScope::Project,
        ConfigScope::Agent,
        ConfigScope::Session,
        ConfigScope::Swarm,
    ];

    /// The scopes whose artifacts must carry a pinned signer (R-7.4:
    /// "verify-before-load for system/swarm scopes").
    pub const VERIFIED: [ConfigScope; 2] = [ConfigScope::System, ConfigScope::Swarm];

    /// Canonical word (JSON word + CLI word).
    pub fn word(self) -> &'static str {
        match self {
            ConfigScope::Defaults => "defaults",
            ConfigScope::Profile => "profile",
            ConfigScope::System => "system",
            ConfigScope::User => "user",
            ConfigScope::Device => "device",
            ConfigScope::Project => "project",
            ConfigScope::Agent => "agent",
            ConfigScope::Session => "session",
            ConfigScope::Swarm => "swarm",
        }
    }

    /// Exact-match parse of the canonical word (case-sensitive, like
    /// [`super::schema::Profile::parse`]).
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.word() == word)
    }

    /// Whether this scope requires a **pinned** trusted signer
    /// (`system`/`swarm`, R-7.4).
    pub fn requires_verified_signer(self) -> bool {
        matches!(self, ConfigScope::System | ConfigScope::Swarm)
    }
}

/// Helper for `expected` fields of bundle diagnostics.
pub const EXPECTED_SCOPE: &str =
    "one of `defaults|profile|system|user|device|project|agent|session|swarm`";

// ── Errors ───────────────────────────────────────────────────────────────────

/// Typed bundle error. Every variant carries one `E70xx` code; [`BundleError::code`]
/// returns it and the `Display` form is prefixed with it (kernel style).
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// `E7020` — bundle artifact could not be parsed (or produced).
    #[error("E7020: bundle artifact could not be parsed as a signed config bundle: {message}")]
    Malformed {
        /// What failed.
        message: String,
    },

    /// `E7021` — magic mismatch: this is not a tallow config bundle.
    #[error("E7021: not a tallow config bundle: expected magic `{expected}`, found `{found}`")]
    Magic {
        /// The expected magic.
        expected: &'static str,
        /// What the artifact carried.
        found: String,
    },

    /// `E7022` — unsupported bundle format version.
    #[error(
        "E7022: unsupported bundle format version {found} (this build reads/writes v{BUNDLE_FORMAT_VERSION})"
    )]
    Version {
        /// The offending version.
        found: u32,
    },

    /// `E7023` — unsupported signature algorithm (including the reserved
    /// ML-DSA hybrid word, refused as "later" per row #198).
    #[error(
        "E7023: unsupported bundle signature algorithm `{found}` — v1 accepts `{ALG_ED25519}`; \
         the reserved hybrid word `{ALG_MLDSA_HYBRID_RESERVED}` stays refused until the ML-DSA leg lands (row #198: later)"
    )]
    Alg {
        /// The offending algorithm word.
        found: String,
    },

    /// `E7024` — unsigned bundle refused.
    #[error("E7024: unsigned bundle refused — bundles are signed (scope `{scope}` carries no signature)")]
    Unsigned {
        /// Bundle scope word.
        scope: &'static str,
    },

    /// `E7025` — signature does not verify: tamper or wrong key.
    #[error(
        "E7025: bundle signature verification failed for signer `{key_id}` ({detail}) — refusing the bundle (tamper or wrong key)"
    )]
    Signature {
        /// Embedded key id of the failing signature.
        key_id: String,
        /// Why it failed.
        detail: String,
    },

    /// `E7026` — signer not pinned for this scope (verify-before-load gate).
    #[error(
        "E7026: bundle signer `{key_id}` is not a trusted signer for scope `{scope}` ({detail}) — refusing (R-7.4 verify-before-load)"
    )]
    Untrusted {
        /// Bundle scope word.
        scope: &'static str,
        /// Embedded key id of the untrusted signer.
        key_id: String,
        /// Why it is refused (no anchors / not in the list / unpinned sibling).
        detail: String,
    },

    /// `E7027` — plain artifact at a verified scope.
    #[error(
        "E7027: scope `{scope}` requires a signed bundle — {path:?} is not a verifiable tallow config bundle ({detail}); \
         plain artifacts are refused (R-7.4 verify-before-load)"
    )]
    ScopeRequiresSignedBundle {
        /// The scope that demanded a bundle.
        scope: &'static str,
        /// The artifact that is not a bundle.
        path: PathBuf,
        /// Underlying parse detail.
        detail: String,
    },

    /// `E7028` — invalid key material.
    #[error("E7028: invalid key material ({what}): {message}")]
    KeyMaterial {
        /// Which key material failed (file / embedded key).
        what: String,
        /// What is wrong (never echoes secret bytes).
        message: String,
    },

    /// `E7029` — export refused: the source artifact fails strict validation.
    #[error("E7029: export refused — the source config did not pass strict kernel validation: {message}")]
    ExportRefused {
        /// The kernel diagnostic.
        message: String,
    },

    /// `E7030` — the declared import scope differs from the bundle's scope.
    #[error(
        "E7030: bundle scope `{bundle}` does not match the requested import scope `{requested}` — refusing the relabel"
    )]
    ScopeMismatch {
        /// Scope inside the signed body.
        bundle: &'static str,
        /// Scope requested on the command line.
        requested: &'static str,
    },

    /// `E7031` — bundle I/O failure.
    #[error("E7031: bundle I/O failed ({what}): {message}")]
    Io {
        /// Which I/O step failed.
        what: String,
        /// Underlying I/O message.
        message: String,
    },

    /// Kernel error pass-through (strict load / atomic write / history).
    #[error("{0}")]
    Config(#[from] ConfigError),
}

impl BundleError {
    /// The reserved diagnostic code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            BundleError::Malformed { .. } => CODE_BUNDLE_MALFORMED,
            BundleError::Magic { .. } => CODE_BUNDLE_MAGIC,
            BundleError::Version { .. } => CODE_BUNDLE_VERSION,
            BundleError::Alg { .. } => CODE_BUNDLE_ALG,
            BundleError::Unsigned { .. } => CODE_BUNDLE_UNSIGNED,
            BundleError::Signature { .. } => CODE_BUNDLE_SIGNATURE,
            BundleError::Untrusted { .. } => CODE_BUNDLE_UNTRUSTED,
            BundleError::ScopeRequiresSignedBundle { .. } => CODE_SCOPE_UNSIGNED_LOAD,
            BundleError::KeyMaterial { .. } => CODE_BUNDLE_KEY,
            BundleError::ExportRefused { .. } => CODE_BUNDLE_EXPORT,
            BundleError::ScopeMismatch { .. } => CODE_BUNDLE_SCOPE_MISMATCH,
            BundleError::Io { .. } => CODE_BUNDLE_IO,
            BundleError::Config(e) => e.code(),
        }
    }

    /// Process exit code for the CLI: `1` = checked and refused,
    /// `2` = could not run (I/O, key material, usage).
    pub fn exit_code(&self) -> i32 {
        match self {
            BundleError::Io { .. } | BundleError::KeyMaterial { .. } => 2,
            _ => 1,
        }
    }
}

// ── Bundle types ─────────────────────────────────────────────────────────────

/// The signed portion of a bundle — everything the signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleBody {
    /// Always [`BUNDLE_MAGIC`].
    pub magic: String,
    /// Bundle format version ([`BUNDLE_FORMAT_VERSION`]).
    pub bundle_version: u32,
    /// Signature algorithm word ([`ALG_ED25519`] for v1).
    pub alg: String,
    /// The scope this artifact is for.
    pub scope: ConfigScope,
    /// Creator-supplied creation instant (unix ms). Caller-supplied so exports
    /// can be reproducible in tests.
    pub created_ms: u64,
    /// The exact config artifact (TOML) text — never a resolved secret value:
    /// secret-class keys stay references by kernel rule (`E7005`).
    pub config_toml: String,
}

/// One detached Ed25519 signature over the canonical body bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    /// Algorithm word ([`ALG_ED25519`]).
    pub alg: String,
    /// Stable key id: `ed25519:<16 hex chars of sha256(pubkey)>`.
    pub key_id: String,
    /// Hex-encoded 32-byte Ed25519 verifying key (self-describing bundle).
    pub public_key: String,
    /// Hex-encoded 64-byte Ed25519 signature over the canonical body bytes.
    pub signature: String,
}

/// A signed config bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundle {
    /// The signed body.
    pub body: BundleBody,
    /// Detached signatures. v1 exports exactly one; verification refuses a
    /// bundle where any listed signature fails or (for verified scopes) is not
    /// pinned.
    pub signatures: Vec<BundleSignature>,
}

/// Assurance level of a verified bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Assurance {
    /// Signer pinned by the caller (trust anchors) — origin + integrity.
    OriginPinned,
    /// Signature verified against the embedded key only — integrity, not origin
    /// (allowed for non-verified scopes; never for `system`/`swarm`).
    IntegrityOnly,
}

impl Assurance {
    /// Canonical word.
    pub fn word(self) -> &'static str {
        match self {
            Assurance::OriginPinned => "origin-pinned",
            Assurance::IntegrityOnly => "integrity-only",
        }
    }
}

/// The outcome of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    /// Scope from the signed body.
    pub scope: ConfigScope,
    /// Key id of the (first) verified signature.
    pub key_id: String,
    /// Hex signer public key.
    pub signer: String,
    /// Body creation instant.
    pub created_ms: u64,
    /// The verified artifact text (what a load/write may consume).
    pub config_toml: String,
    /// Origin/integrity level achieved.
    pub assurance: Assurance,
    /// SHA-256 of the canonical signed body bytes (evidence-friendly).
    pub body_sha256: String,
}

impl VerifiedBundle {
    /// Deterministic JSON rendering (for `--format json` and tests).
    pub fn render_json(&self) -> serde_json::Value {
        serde_json::json!({
            "scope": self.scope.word(),
            "key_id": self.key_id,
            "signer": self.signer,
            "created_ms": self.created_ms,
            "assurance": self.assurance.word(),
            "body_sha256": self.body_sha256,
            "config_bytes": self.config_toml.len(),
        })
    }
}

/// Result of writing a bundle to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    /// Path the bundle was written to.
    pub path: PathBuf,
    /// Bundle bytes written.
    pub bytes: usize,
    /// Bundle scope.
    pub scope: ConfigScope,
    /// Signer key id.
    pub key_id: String,
    /// SHA-256 of the canonical signed body bytes.
    pub body_sha256: String,
}

impl ExportOutcome {
    /// Deterministic JSON rendering.
    pub fn render_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "op": "export",
            "path": self.path.display().to_string(),
            "bytes": self.bytes,
            "scope": self.scope.word(),
            "key_id": self.key_id,
            "body_sha256": self.body_sha256,
        })
    }
}

/// Result of an import (or a dry-run import).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Verified bundle scope.
    pub scope: ConfigScope,
    /// Signer key id.
    pub key_id: String,
    /// Assurance achieved.
    pub assurance: Assurance,
    /// Target config path.
    pub target: PathBuf,
    /// True when nothing was written (validation-only run).
    pub dry_run: bool,
    /// Config-history revision recorded by the kernel write path.
    pub revision: Option<u64>,
    /// BLAKE3 of the accepted artifact.
    pub content_blake3: String,
    /// Artifact size in bytes.
    pub bytes: usize,
    /// SHA-256 of the canonical signed body bytes.
    pub body_sha256: String,
}

impl ImportOutcome {
    /// Deterministic JSON rendering.
    pub fn render_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "op": if self.dry_run { "import-dry-run" } else { "import" },
            "scope": self.scope.word(),
            "key_id": self.key_id,
            "assurance": self.assurance.word(),
            "target": self.target.display().to_string(),
            "bytes": self.bytes,
            "revision": self.revision,
            "content_blake3": self.content_blake3,
            "body_sha256": self.body_sha256,
        })
    }
}

// ── Trust anchors ────────────────────────────────────────────────────────────

/// The caller's pinned signer set (verify-before-load trust anchor).
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    keys: Vec<(String, VerifyingKey)>,
}

impl TrustAnchors {
    /// No anchors: non-verified scopes verify integrity-only; verified scopes
    /// (`system`/`swarm`) are refused.
    pub fn none() -> Self {
        TrustAnchors { keys: Vec::new() }
    }

    /// True when no anchor is pinned.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Number of pinned keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Pin one verifying key.
    pub fn with_key(mut self, key: VerifyingKey) -> Self {
        let id = key_id_of(&key);
        if !self.keys.iter().any(|(k, _)| *k == id) {
            self.keys.push((id, key));
        }
        self
    }

    /// Load one anchor file per path (32 raw bytes or 64 hex chars, as the
    /// package-signing key files).
    pub fn from_files(paths: &[PathBuf]) -> Result<Self, BundleError> {
        let mut anchors = TrustAnchors::none();
        for path in paths {
            anchors = anchors.with_key(ed25519_verifying_key_from_file(path)?);
        }
        Ok(anchors)
    }

    /// The pinned key id for a verifying key, when pinned.
    pub fn find(&self, key: &VerifyingKey) -> Option<&str> {
        self.keys
            .iter()
            .find(|(_, k)| k == key)
            .map(|(id, _)| id.as_str())
    }

    /// Pinned key ids (stable order).
    pub fn key_ids(&self) -> Vec<String> {
        self.keys.iter().map(|(id, _)| id.clone()).collect()
    }
}

// ── Hex / key helpers ────────────────────────────────────────────────────────

/// Hex-encode bytes (lowercase).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.len() % 2 != 0 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    for i in (0..t.len()).step_by(2) {
        out.push(u8::from_str_radix(&t[i..i + 2], 16).ok()?);
    }
    Some(out)
}

/// Stable signer/key id: `ed25519:<first 16 hex of sha256(public key)>`.
pub fn key_id_of(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    format!("{ALG_ED25519}:{}", hex_encode(&digest[..8]))
}

/// SHA-256 of the canonical signed body bytes, hex.
pub fn body_sha256(body: &BundleBody) -> Result<String, BundleError> {
    Ok(hex_encode(&Sha256::digest(canonical_body_bytes(body)?)))
}

/// The bytes a bundle signature covers: canonical `serde_json` encoding of the
/// body (struct field order — deterministic; no maps involved).
pub fn canonical_body_bytes(body: &BundleBody) -> Result<Vec<u8>, BundleError> {
    serde_json::to_vec(body).map_err(|e| BundleError::Malformed {
        message: format!("canonical body encoding failed: {e}"),
    })
}

/// Read a key file: 32 raw bytes, or 64 hex characters (with optional trailing
/// whitespace). Same shape as the package-signing key files.
fn read_key_bytes(path: &Path) -> Result<[u8; 32], BundleError> {
    let data = fs::read(path).map_err(|e| BundleError::Io {
        what: format!("read key file {}", path.display()),
        message: e.to_string(),
    })?;
    if data.len() == 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data);
        return Ok(buf);
    }
    let text = String::from_utf8_lossy(&data);
    if let Some(bytes) = hex_decode(&text) {
        if bytes.len() == 32 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes);
            return Ok(buf);
        }
    }
    Err(BundleError::KeyMaterial {
        what: format!("key file {}", path.display()),
        message: format!(
            "expected 32 raw bytes or 64 hex chars, found {} bytes",
            data.len()
        ),
    })
}

/// Load an Ed25519 signing key from a key file (32 raw bytes / 64 hex chars).
pub fn ed25519_signing_key_from_file(path: &Path) -> Result<SigningKey, BundleError> {
    Ok(SigningKey::from_bytes(&read_key_bytes(path)?))
}

/// Load an Ed25519 verifying key from a key file (32 raw bytes / 64 hex chars).
pub fn ed25519_verifying_key_from_file(path: &Path) -> Result<VerifyingKey, BundleError> {
    let bytes = read_key_bytes(path)?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| BundleError::KeyMaterial {
        what: format!("key file {}", path.display()),
        message: format!("not a valid Ed25519 verifying key: {e}"),
    })
}

/// Generate a fresh Ed25519 keypair for bundle signing.
///
/// Writes `<out>` (32-byte seed, owner-only `0600` on unix) and `<out>.pub`
/// (64 hex chars + newline). Returns both paths.
pub fn write_keypair(out: &Path) -> Result<(PathBuf, PathBuf), BundleError> {
    let (signing_key, verifying_key) = signing::generate_keypair();
    let pub_path = PathBuf::from(format!("{}.pub", out.display()));

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| BundleError::Io {
                what: format!("create key directory {}", parent.display()),
                message: e.to_string(),
            })?;
        }
    }

    fs::write(out, signing_key.to_bytes()).map_err(|e| BundleError::Io {
        what: format!("write key {}", out.display()),
        message: e.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600)).map_err(|e| {
            BundleError::Io {
                what: format!("chmod 0600 {}", out.display()),
                message: e.to_string(),
            }
        })?;
    }

    fs::write(&pub_path, format!("{}\n", hex_encode(&verifying_key.to_bytes()))).map_err(|e| {
        BundleError::Io {
            what: format!("write public key {}", pub_path.display()),
            message: e.to_string(),
        }
    })?;

    Ok((out.to_path_buf(), pub_path))
}

// ── Export ───────────────────────────────────────────────────────────────────

/// Build a signed bundle for the config artifact at `config_path`.
///
/// The artifact is validated strictly first (`E7029` on refusal — an artifact
/// the kernel would refuse is never signed). `created_ms` is caller-supplied so
/// exports are reproducible in tests.
pub fn export_bundle(
    config_path: &Path,
    scope: ConfigScope,
    key: &SigningKey,
    created_ms: u64,
) -> Result<ConfigBundle, BundleError> {
    let config_toml = fs::read_to_string(config_path).map_err(|e| BundleError::Io {
        what: format!("read config {}", config_path.display()),
        message: e.to_string(),
    })?;

    // Never sign an artifact the kernel would refuse (E7029).
    load::load_from_str(&config_toml, Some(config_path.to_path_buf()))
        .into_strict()
        .map_err(|e| BundleError::ExportRefused {
            message: e.to_string(),
        })?;

    let body = BundleBody {
        magic: BUNDLE_MAGIC.to_string(),
        bundle_version: BUNDLE_FORMAT_VERSION,
        alg: ALG_ED25519.to_string(),
        scope,
        created_ms,
        config_toml,
    };
    let canonical = canonical_body_bytes(&body)?;
    let signature = signing::sign_artifact(&canonical, key);
    let verifying_key = key.verifying_key();

    Ok(ConfigBundle {
        body,
        signatures: vec![BundleSignature {
            alg: ALG_ED25519.to_string(),
            key_id: key_id_of(&verifying_key),
            public_key: hex_encode(&verifying_key.to_bytes()),
            signature: hex_encode(&signature),
        }],
    })
}

/// Render a bundle as the on-disk artifact (pretty JSON + trailing newline).
pub fn render_bundle(bundle: &ConfigBundle) -> Result<String, BundleError> {
    let mut text = serde_json::to_string_pretty(bundle).map_err(|e| BundleError::Malformed {
        message: format!("bundle serialization failed: {e}"),
    })?;
    text.push('\n');
    Ok(text)
}

/// Export + write a bundle to `out` (owner-only `0600` on unix — distribution is
/// an explicit operator act).
pub fn export_bundle_to(
    config_path: &Path,
    scope: ConfigScope,
    key: &SigningKey,
    created_ms: u64,
    out: &Path,
) -> Result<ExportOutcome, BundleError> {
    let bundle = export_bundle(config_path, scope, key, created_ms)?;
    let text = render_bundle(&bundle)?;

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| BundleError::Io {
                what: format!("create bundle directory {}", parent.display()),
                message: e.to_string(),
            })?;
        }
    }
    fs::write(out, text.as_bytes()).map_err(|e| BundleError::Io {
        what: format!("write bundle {}", out.display()),
        message: e.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600)).map_err(|e| {
            BundleError::Io {
                what: format!("chmod 0600 {}", out.display()),
                message: e.to_string(),
            }
        })?;
    }

    Ok(ExportOutcome {
        path: out.to_path_buf(),
        bytes: text.len(),
        scope,
        key_id: key_id_of(&key.verifying_key()),
        body_sha256: body_sha256(&bundle.body)?,
    })
}

// ── Verify ───────────────────────────────────────────────────────────────────

/// Parse bundle bytes (strict: unknown fields refused).
pub fn parse_bundle(bytes: &[u8]) -> Result<ConfigBundle, BundleError> {
    let bundle: ConfigBundle = serde_json::from_slice(bytes).map_err(|e| BundleError::Malformed {
        message: format!("not a JSON bundle document: {e}"),
    })?;
    // Magic/version/alg are checked in verify_bundle so parse stays a pure parse;
    // magic is cheap enough to check here as the first fail-closed gate for
    // readers that stop at parse.
    if bundle.body.magic != BUNDLE_MAGIC {
        return Err(BundleError::Magic {
            expected: BUNDLE_MAGIC,
            found: bundle.body.magic.clone(),
        });
    }
    Ok(bundle)
}

/// Verify a parsed bundle against the caller's trust anchors.
///
/// Fail-closed rules — see the module docs. On success the returned
/// [`VerifiedBundle`] carries the *verified* artifact text; only that text may
/// be loaded or written.
pub fn verify_bundle(
    bundle: &ConfigBundle,
    trust: &TrustAnchors,
) -> Result<VerifiedBundle, BundleError> {
    // 1. Magic (a bundle built by hand may bypass parse_bundle).
    if bundle.body.magic != BUNDLE_MAGIC {
        return Err(BundleError::Magic {
            expected: BUNDLE_MAGIC,
            found: bundle.body.magic.clone(),
        });
    }
    // 2. Format version.
    if bundle.body.bundle_version != BUNDLE_FORMAT_VERSION {
        return Err(BundleError::Version {
            found: bundle.body.bundle_version,
        });
    }
    // 3. Body algorithm word (the reserved hybrid word is refused explicitly).
    if bundle.body.alg != ALG_ED25519 {
        return Err(BundleError::Alg {
            found: bundle.body.alg.clone(),
        });
    }
    // 4. Must be signed.
    if bundle.signatures.is_empty() {
        return Err(BundleError::Unsigned {
            scope: bundle.body.scope.word(),
        });
    }

    let canonical = canonical_body_bytes(&bundle.body)?;
    let scope = bundle.body.scope;

    let mut verified: Vec<(String, VerifyingKey)> = Vec::new();
    for sig in &bundle.signatures {
        if sig.alg != ALG_ED25519 {
            return Err(BundleError::Alg {
                found: sig.alg.clone(),
            });
        }
        let pk_bytes = hex_decode(&sig.public_key).ok_or_else(|| BundleError::KeyMaterial {
            what: format!("embedded public key for `{}`", sig.key_id),
            message: "not valid hex".to_string(),
        })?;
        let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|v: Vec<u8>| {
            BundleError::KeyMaterial {
                what: format!("embedded public key for `{}`", sig.key_id),
                message: format!("expected 32 bytes, found {}", v.len()),
            }
        })?;
        let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| BundleError::KeyMaterial {
            what: format!("embedded public key for `{}`", sig.key_id),
            message: format!("not a valid Ed25519 verifying key: {e}"),
        })?;

        // Self-describing check: the key id must match the embedded key.
        if key_id_of(&vk) != sig.key_id {
            return Err(BundleError::Signature {
                key_id: sig.key_id.clone(),
                detail: "embedded public key does not match the declared key id".to_string(),
            });
        }

        let sig_bytes = hex_decode(&sig.signature).ok_or_else(|| BundleError::Signature {
            key_id: sig.key_id.clone(),
            detail: "signature is not valid hex".to_string(),
        })?;
        let ok = signing::verify_artifact(&canonical, &sig_bytes, &vk).map_err(|e| {
            BundleError::Signature {
                key_id: sig.key_id.clone(),
                detail: e,
            }
        })?;
        if !ok {
            return Err(BundleError::Signature {
                key_id: sig.key_id.clone(),
                detail: "signature is not valid for the signed body".to_string(),
            });
        }
        verified.push((sig.key_id.clone(), vk));
    }

    // 5. Trust gate (R-7.4 verify-before-load for system/swarm).
    let mut assurance = Assurance::IntegrityOnly;
    for (key_id, vk) in &verified {
        match trust.find(vk) {
            Some(_) => assurance = Assurance::OriginPinned,
            None => {
                if scope.requires_verified_signer() {
                    return Err(BundleError::Untrusted {
                        scope: scope.word(),
                        key_id: key_id.clone(),
                        detail: if trust.is_empty() {
                            "no trusted signer was supplied for this scope".to_string()
                        } else {
                            format!(
                                "not among the {} pinned trust anchor(s): {}",
                                trust.len(),
                                trust.key_ids().join(", ")
                            )
                        },
                    });
                }
                if !trust.is_empty() {
                    return Err(BundleError::Untrusted {
                        scope: scope.word(),
                        key_id: key_id.clone(),
                        detail: format!(
                            "explicit trust list supplied ({} pinned key(s)) does not include this signer",
                            trust.len()
                        ),
                    });
                }
            }
        }
    }

    let (key_id, signer) = verified
        .first()
        .map(|(id, vk)| (id.clone(), hex_encode(&vk.to_bytes())))
        .expect("signatures are non-empty (checked above)");

    Ok(VerifiedBundle {
        scope,
        key_id,
        signer,
        created_ms: bundle.body.created_ms,
        config_toml: bundle.body.config_toml.clone(),
        assurance,
        body_sha256: hex_encode(&Sha256::digest(&canonical)),
    })
}

/// Read a bundle file. (Thin I/O helper so the CLI maps failures to `E7031`.)
pub fn read_bundle_bytes(path: &Path) -> Result<Vec<u8>, BundleError> {
    fs::read(path).map_err(|e| BundleError::Io {
        what: format!("read bundle {}", path.display()),
        message: e.to_string(),
    })
}

/// Parse + verify bundle bytes in one step.
pub fn verify_bundle_bytes(
    bytes: &[u8],
    trust: &TrustAnchors,
) -> Result<VerifiedBundle, BundleError> {
    let bundle = parse_bundle(bytes)?;
    verify_bundle(&bundle, trust)
}

// ── Import ───────────────────────────────────────────────────────────────────

/// Import a bundle: **verify → strict kernel load → atomic kernel write**.
///
/// Nothing is written (and no config-history revision is recorded) on any
/// refusal. `expected_scope` is the caller-declared scope (`--scope` on the
/// CLI): when present it must equal the bundle's signed scope (`E7030`).
/// `dry_run` validates and reports without writing.
pub fn import_bundle(
    bundle_bytes: &[u8],
    target: &Path,
    expected_scope: Option<ConfigScope>,
    trust: &TrustAnchors,
    dry_run: bool,
    opts: &WriteOptions<'_>,
) -> Result<ImportOutcome, BundleError> {
    let verified = verify_bundle_bytes(bundle_bytes, trust)?;

    if let Some(expected) = expected_scope {
        if expected != verified.scope {
            return Err(BundleError::ScopeMismatch {
                bundle: verified.scope.word(),
                requested: expected.word(),
            });
        }
    }

    // Strict kernel validation *before* any write (same verdict the kernel
    // write path will reach; gives dry-run a real answer).
    load::load_from_str(&verified.config_toml, Some(target.to_path_buf()))
        .into_strict()?;

    if dry_run {
        return Ok(ImportOutcome {
            scope: verified.scope,
            key_id: verified.key_id,
            assurance: verified.assurance,
            target: target.to_path_buf(),
            dry_run: true,
            revision: None,
            content_blake3: blake3::hash(verified.config_toml.as_bytes())
                .to_hex()
                .to_string(),
            bytes: verified.config_toml.len(),
            body_sha256: verified.body_sha256,
        });
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| BundleError::Io {
                what: format!("create target directory {}", parent.display()),
                message: e.to_string(),
            })?;
        }
    }

    let committed = write::commit(target, &verified.config_toml, opts)?;

    Ok(ImportOutcome {
        scope: verified.scope,
        key_id: verified.key_id,
        assurance: verified.assurance,
        target: committed.path,
        dry_run: false,
        revision: committed.revision,
        content_blake3: committed.content_blake3,
        bytes: committed.bytes,
        body_sha256: verified.body_sha256,
    })
}

// ── Verify-before-load gate ──────────────────────────────────────────────────

/// Reader-side gate for R-7.4: load a scope's config artifact.
///
/// - `system`/`swarm` scope: the artifact **must** be a signed bundle and must
///   verify against a pinned signer; a plain artifact is refused (`E7027`)
///   before any parse, and the *verified* text is what gets loaded.
/// - every other scope: plain kernel load ([`load::load_file`]).
///
/// KB-2 (scope resolution) is the module that will call this from a live read
/// path; until then it is the tested gate surface.
pub fn load_scoped(
    path: &Path,
    scope: ConfigScope,
    trust: &TrustAnchors,
) -> Result<ConfigLoad, BundleError> {
    if !scope.requires_verified_signer() {
        return Ok(load::load_file(path));
    }

    let bytes = read_bundle_bytes(path)?;
    let verified = match parse_bundle(&bytes).and_then(|b| verify_bundle(&b, trust)) {
        Ok(v) => v,
        Err(e) if matches!(e, BundleError::Signature { .. } | BundleError::Untrusted { .. }) => {
            // A genuine bundle that fails verification / trust stays reported as
            // such (tamper and trust refusals must not be masked as "not a
            // bundle").
            return Err(e);
        }
        Err(e) => {
            return Err(BundleError::ScopeRequiresSignedBundle {
                scope: scope.word(),
                path: path.to_path_buf(),
                detail: e.to_string(),
            });
        }
    };

    Ok(load::load_from_str(
        &verified.config_toml,
        Some(path.to_path_buf()),
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_support::TempDir;

    const VALID: &str = "schema_version = 1\nprofile = \"server\"\ntelemetry = false\n";
    const VALID_B: &str = "schema_version = 1\nprofile = \"balanced\"\nno_color = true\n";
    const INVALID: &str = "schema_version = 1\nnot_a_key = true\n";

    fn write_config(dir: &TempDir, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture subdir");
        }
        std::fs::write(&path, text).expect("write fixture config");
        path
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn key_b() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn anchors_for(keys: &[&SigningKey]) -> TrustAnchors {
        let mut anchors = TrustAnchors::none();
        for k in keys {
            anchors = anchors.with_key(k.verifying_key());
        }
        anchors
    }

    fn opts_in(dir: &TempDir) -> WriteOptions<'static> {
        WriteOptions::with_history_dir(dir.join("history"))
    }

    #[test]
    fn scope_words_round_trip_and_verified_set() {
        for scope in ConfigScope::ALL {
            assert_eq!(ConfigScope::parse(scope.word()), Some(scope));
        }
        assert_eq!(ConfigScope::parse("System"), None, "parse is case-sensitive");
        assert_eq!(
            ConfigScope::VERIFIED,
            [ConfigScope::System, ConfigScope::Swarm]
        );
        assert!(ConfigScope::System.requires_verified_signer());
        assert!(ConfigScope::Swarm.requires_verified_signer());
        assert!(!ConfigScope::User.requires_verified_signer());
    }

    #[test]
    fn export_bundle_is_deterministic_and_self_describing() {
        let dir = TempDir::new("bundle-det");
        let cfg = write_config(&dir, "config.toml", VALID);
        let a = export_bundle(&cfg, ConfigScope::User, &key(), 1_700_000_000_000).unwrap();
        let b = export_bundle(&cfg, ConfigScope::User, &key(), 1_700_000_000_000).unwrap();
        assert_eq!(a, b, "same inputs ⇒ identical bundle (deterministic)");
        assert_eq!(
            render_bundle(&a).unwrap(),
            render_bundle(&b).unwrap(),
            "rendered artifact is byte-identical"
        );
        assert_eq!(a.signatures[0].key_id, key_id_of(&key().verifying_key()));
        assert_eq!(a.body.magic, BUNDLE_MAGIC);
    }

    #[test]
    fn export_refuses_artifact_the_kernel_would_refuse() {
        let dir = TempDir::new("bundle-refuse");
        let cfg = write_config(&dir, "config.toml", INVALID);
        let err = export_bundle(&cfg, ConfigScope::User, &key(), 1).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_EXPORT, "{err}");
    }

    #[test]
    fn verify_round_trip_user_scope_integrity_only() {
        let dir = TempDir::new("bundle-rt");
        let cfg = write_config(&dir, "config.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        let verified = verify_bundle(&bundle, &TrustAnchors::none()).unwrap();
        assert_eq!(verified.scope, ConfigScope::User);
        assert_eq!(verified.config_toml, VALID);
        assert_eq!(verified.assurance, Assurance::IntegrityOnly);
        assert_eq!(verified.created_ms, 42);
        assert_eq!(verified.body_sha256.len(), 64);
    }

    #[test]
    fn import_round_trip_records_history_revision() {
        let dir = TempDir::new("bundle-import");
        let cfg = write_config(&dir, "config.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        let bytes = render_bundle(&bundle).unwrap();
        let target = dir.join("out/config.toml");

        let opts = opts_in(&dir);
        let outcome = import_bundle(
            bytes.as_bytes(),
            &target,
            None,
            &TrustAnchors::none(),
            false,
            &opts,
        )
        .unwrap();
        assert_eq!(outcome.revision, Some(1));
        assert!(!outcome.dry_run);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), VALID);
        assert!(dir.join("history/000001/meta.toml").exists());
    }

    #[test]
    fn dry_run_import_writes_nothing() {
        let dir = TempDir::new("bundle-dry");
        let cfg = write_config(&dir, "config.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        let bytes = render_bundle(&bundle).unwrap();
        let target = dir.join("out/config.toml");
        let outcome = import_bundle(
            bytes.as_bytes(),
            &target,
            None,
            &TrustAnchors::none(),
            true,
            &opts_in(&dir),
        )
        .unwrap();
        assert!(outcome.dry_run && outcome.revision.is_none());
        assert!(!target.exists(), "dry-run must not create the target");
        assert!(!dir.join("history").exists(), "dry-run must not record history");
    }

    #[test]
    fn tampered_config_text_is_refused_and_writes_nothing() {
        let dir = TempDir::new("bundle-tamper1");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.body.config_toml = VALID_B.to_string(); // swap in another valid artifact
        let bytes = render_bundle(&bundle).unwrap();
        let target = dir.join("out/config.toml");

        let err = import_bundle(
            bytes.as_bytes(),
            &target,
            None,
            &TrustAnchors::none(),
            false,
            &opts_in(&dir),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_SIGNATURE, "{err}");
        assert!(!target.exists(), "tamper refusal must not write");
        assert!(!dir.join("history").exists(), "tamper refusal must not record");

        let verr = verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none()).unwrap_err();
        assert_eq!(verr.code(), CODE_BUNDLE_SIGNATURE);
    }

    #[test]
    fn tampered_scope_relabel_is_refused() {
        let dir = TempDir::new("bundle-tamper2");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.body.scope = ConfigScope::System; // elevate a user bundle
        let bytes = render_bundle(&bundle).unwrap();
        let err =
            verify_bundle_bytes(bytes.as_bytes(), &anchors_for(&[&key()])).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_SIGNATURE, "{err}");
    }

    #[test]
    fn swapped_public_key_is_refused() {
        let dir = TempDir::new("bundle-tamper3");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        // attacker rewrites the embedded key to their own (signature stays)
        let attacker = key_b().verifying_key();
        bundle.signatures[0].public_key = hex_encode(&attacker.to_bytes());
        bundle.signatures[0].key_id = key_id_of(&attacker);
        let bytes = render_bundle(&bundle).unwrap();
        let err = verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none()).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_SIGNATURE, "{err}");
    }

    #[test]
    fn altered_timestamp_is_refused() {
        let dir = TempDir::new("bundle-tamper4");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.body.created_ms = 43;
        let bytes = render_bundle(&bundle).unwrap();
        let err = verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none()).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_SIGNATURE, "{err}");
    }

    #[test]
    fn unsigned_bundle_is_refused() {
        let dir = TempDir::new("bundle-unsigned");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.signatures.clear();
        let bytes = render_bundle(&bundle).unwrap();
        let err = verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none()).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_UNSIGNED, "{err}");
    }

    #[test]
    fn reserved_mldsa_hybrid_alg_is_refused_explicitly() {
        let dir = TempDir::new("bundle-mldsa");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.body.alg = ALG_MLDSA_HYBRID_RESERVED.to_string();
        let bytes = render_bundle(&bundle).unwrap();
        let err = verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none()).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_ALG, "{err}");
        assert!(err.to_string().contains("later"), "{err}");
    }

    #[test]
    fn unknown_version_and_magic_are_refused() {
        let dir = TempDir::new("bundle-ver");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.body.bundle_version = 99;
        let bytes = render_bundle(&bundle).unwrap();
        assert_eq!(
            verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none())
                .unwrap_err()
                .code(),
            CODE_BUNDLE_VERSION
        );

        let mut bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        bundle.body.magic = "not-a-bundle".to_string();
        let bytes = render_bundle(&bundle).unwrap();
        assert_eq!(
            verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none())
                .unwrap_err()
                .code(),
            CODE_BUNDLE_MAGIC
        );
    }

    #[test]
    fn malformed_artifacts_are_refused() {
        assert_eq!(
            parse_bundle(b"not json at all").unwrap_err().code(),
            CODE_BUNDLE_MALFORMED
        );
        // Extra/unknown top-level field: deny_unknown_fields.
        assert_eq!(
            parse_bundle(br#"{"body":{},"signatures":[],"extra":1}"#)
                .unwrap_err()
                .code(),
            CODE_BUNDLE_MALFORMED
        );
    }

    #[test]
    fn verified_scope_requires_pinned_signer() {
        let dir = TempDir::new("bundle-sys");
        let cfg = write_config(&dir, "config.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::System, &key(), 42).unwrap();
        let bytes = render_bundle(&bundle).unwrap();

        // (a) no anchors at all → refused
        let err = verify_bundle_bytes(bytes.as_bytes(), &TrustAnchors::none()).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_UNTRUSTED, "{err}");
        assert!(err.to_string().contains("no trusted signer"), "{err}");

        // (b) wrong anchor → refused
        let err = verify_bundle_bytes(bytes.as_bytes(), &anchors_for(&[&key_b()])).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_UNTRUSTED, "{err}");

        // (c) pinned signer → origin-pinned
        let verified =
            verify_bundle_bytes(bytes.as_bytes(), &anchors_for(&[&key()])).unwrap();
        assert_eq!(verified.assurance, Assurance::OriginPinned);
        assert_eq!(verified.scope, ConfigScope::System);
    }

    #[test]
    fn unpinned_sibling_signature_on_verified_scope_is_refused() {
        let dir = TempDir::new("bundle-sibling");
        let cfg = write_config(&dir, "config.toml", VALID);
        let mut bundle = export_bundle(&cfg, ConfigScope::System, &key(), 42).unwrap();
        let canonical = canonical_body_bytes(&bundle.body).unwrap();
        let outsider = key_b();
        bundle.signatures.push(BundleSignature {
            alg: ALG_ED25519.to_string(),
            key_id: key_id_of(&outsider.verifying_key()),
            public_key: hex_encode(&outsider.verifying_key().to_bytes()),
            signature: hex_encode(&signing::sign_artifact(&canonical, &outsider)),
        });
        let err =
            verify_bundle_bytes(&render_bundle(&bundle).unwrap().as_bytes(), &anchors_for(&[&key()]))
                .unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_UNTRUSTED, "{err}");
    }

    #[test]
    fn explicit_trust_list_is_enforced_for_non_verified_scopes_too() {
        let dir = TempDir::new("bundle-pin-user");
        let cfg = write_config(&dir, "config.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        let bytes = render_bundle(&bundle).unwrap();
        let err = verify_bundle_bytes(bytes.as_bytes(), &anchors_for(&[&key_b()])).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_UNTRUSTED, "{err}");
    }

    #[test]
    fn import_scope_mismatch_is_refused() {
        let dir = TempDir::new("bundle-mismatch");
        let cfg = write_config(&dir, "config.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::User, &key(), 42).unwrap();
        let bytes = render_bundle(&bundle).unwrap();
        let target = dir.join("out/config.toml");
        let err = import_bundle(
            bytes.as_bytes(),
            &target,
            Some(ConfigScope::System),
            &anchors_for(&[&key()]),
            false,
            &opts_in(&dir),
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_SCOPE_MISMATCH, "{err}");
        assert!(!target.exists());
    }

    #[test]
    fn import_refuses_signed_but_invalid_artifact() {
        let dir = TempDir::new("bundle-badcfg");
        // Build a correctly signed bundle whose artifact is invalid TOML for the kernel.
        let body = BundleBody {
            magic: BUNDLE_MAGIC.to_string(),
            bundle_version: BUNDLE_FORMAT_VERSION,
            alg: ALG_ED25519.to_string(),
            scope: ConfigScope::User,
            created_ms: 7,
            config_toml: INVALID.to_string(),
        };
        let canonical = canonical_body_bytes(&body).unwrap();
        let bundle = ConfigBundle {
            body,
            signatures: vec![BundleSignature {
                alg: ALG_ED25519.to_string(),
                key_id: key_id_of(&key().verifying_key()),
                public_key: hex_encode(&key().verifying_key().to_bytes()),
                signature: hex_encode(&signing::sign_artifact(&canonical, &key())),
            }],
        };
        let bytes = render_bundle(&bundle).unwrap();
        let target = dir.join("out/config.toml");
        let err = import_bundle(
            bytes.as_bytes(),
            &target,
            None,
            &anchors_for(&[&key()]),
            false,
            &opts_in(&dir),
        )
        .unwrap_err();
        // The kernel aggregate refusal (E7013) carries the E7002 unknown-key
        // diagnostic; both are kernel-side, and nothing is written.
        assert_eq!(err.code(), super::super::schema::CODE_REFUSED, "{err}");
        assert!(err.to_string().contains("E7002"), "{err}");
        assert!(!target.exists());
    }

    #[test]
    fn load_scoped_refuses_plain_artifact_at_verified_scopes() {
        let dir = TempDir::new("bundle-gate");
        let plain = write_config(&dir, "system/config.toml", VALID);

        // user scope: plain load works (kernel path)
        assert!(load_scoped(&plain, ConfigScope::User, &TrustAnchors::none()).is_ok());

        // system + swarm scopes: plain artifact refused before any parse
        for scope in ConfigScope::VERIFIED {
            let err = load_scoped(&plain, scope, &anchors_for(&[&key()])).unwrap_err();
            assert_eq!(err.code(), CODE_SCOPE_UNSIGNED_LOAD, "{err}");
            assert!(err.to_string().contains(scope.word()), "{err}");
        }
    }

    #[test]
    fn load_scoped_accepts_verified_bundle_at_system_scope() {
        let dir = TempDir::new("bundle-gate-ok");
        let cfg = write_config(&dir, "src.toml", VALID);
        let bundle = export_bundle(&cfg, ConfigScope::System, &key(), 42).unwrap();
        let path = dir.join("system.bundle.json");
        std::fs::write(&path, render_bundle(&bundle).unwrap()).unwrap();

        // pinned → loads the verified text
        let loaded = load_scoped(&path, ConfigScope::System, &anchors_for(&[&key()])).unwrap();
        assert_eq!(loaded.core().unwrap().profile, Some(super::super::schema::Profile::Server));

        // unpinned → trust refusal, not a silent load
        let err = load_scoped(&path, ConfigScope::System, &TrustAnchors::none()).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_UNTRUSTED, "{err}");

        // a genuine bundle with a broken signature stays a signature refusal
        let mut tampered = bundle.clone();
        tampered.body.config_toml = VALID_B.to_string();
        std::fs::write(&path, render_bundle(&tampered).unwrap()).unwrap();
        let err = load_scoped(&path, ConfigScope::System, &anchors_for(&[&key()])).unwrap_err();
        assert_eq!(err.code(), CODE_BUNDLE_SIGNATURE, "{err}");
    }

    #[test]
    fn key_files_round_trip() {
        let dir = TempDir::new("bundle-keys");
        let key_path = dir.join("bundle.ed25519");
        let (private, public) = write_keypair(&key_path).unwrap();
        assert_eq!(private, key_path);
        assert_eq!(public, PathBuf::from(format!("{}.pub", key_path.display())));

        let sk = ed25519_signing_key_from_file(&private).unwrap();
        let vk = ed25519_verifying_key_from_file(&public).unwrap();
        assert_eq!(sk.verifying_key(), vk);

        // anchors load from the .pub file
        let anchors = TrustAnchors::from_files(&[public.clone()]).unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors.key_ids()[0], key_id_of(&vk));

        // wrong-size key file is key-material refusal
        let bad = dir.join("bad.key");
        std::fs::write(&bad, b"short").unwrap();
        assert_eq!(
            ed25519_signing_key_from_file(&bad).unwrap_err().code(),
            CODE_BUNDLE_KEY
        );
    }

    #[test]
    fn exit_codes_and_codes_are_stable() {
        assert_eq!(
            BundleError::Io {
                what: "x".into(),
                message: "y".into()
            }
            .exit_code(),
            2
        );
        assert_eq!(
            BundleError::Signature {
                key_id: "k".into(),
                detail: "d".into()
            }
            .exit_code(),
            1
        );
        assert_eq!(
            BundleError::Malformed {
                message: "m".into()
            }
            .code(),
            CODE_BUNDLE_MALFORMED
        );
    }
}
