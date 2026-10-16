//! KB-1 typed config tree, schema version, secret references, key-class
//! metadata, and the kernel's typed error enum (`E7001`–`E7099`).
//!
//! The typed tree is the *only* authoritative shape of a kernel-managed
//! config artifact. Everything the loader accepts is representable here;
//! everything this tree serializes is accepted by the loader (round-trip
//! pinned by tests). Unknown keys are refused — there is no fallback path
//! (§7.3 rule 6, U-202 KB-1).
//!
//! Diagnostic codes reserved for this kernel (parent decision D5; range free
//! in-tree at assignment — `E6xxx` belongs to the tier gate):
//!
//! | code | variant | meaning |
//! |---|---|---|
//! | `E7001` | [`ConfigError::Artifact`] | TOML artifact could not be parsed/produced |
//! | `E7002` | [`ConfigError::UnknownKey`] | unknown key / unknown section — refused, never ignored |
//! | `E7003` | [`ConfigError::TypeMismatch`] | value type mismatch (or unknown enum word) |
//! | `E7004` | [`ConfigError::SchemaVersion`] | version missing/malformed/zero/older/newer (downgrade guard) |
//! | `E7005` | [`ConfigError::LiteralSecret`] | literal value in a secret-class key |
//! | `E7006` | [`ConfigError::Read`] | config file cannot be read |
//! | `E7007` | [`ConfigError::Write`] | atomic write failed (previous file intact) |
//! | `E7008` | [`ConfigError::HistoryRecord`] | revision could not be recorded → write refused |
//! | `E7009` | [`ConfigError::HistoryPath`] | config-history location unusable |
//! | `E7010` | [`ConfigError::SecretResolution`] | secret reference unresolvable at use time |
//! | `E7011` | [`ConfigError::VaultSeam`] | `vault://` resolution seam (D7, KB-4 wires it) |
//! | `E7012` | [`ConfigError::PathUnresolved`] | required base directory unavailable (no `"."` fallback) |
//! | `E7013` | [`ConfigError::Refused`] | aggregate refusal carrying per-section diagnostics |

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── Schema version ───────────────────────────────────────────────────────────

/// Current schema version of kernel-managed config artifacts. A `schema_version`
/// newer than this is refused (downgrade guard); an older one is refused until
/// KB-3 registers a migration path.
pub const SCHEMA_VERSION: u32 = 1;

/// Key holding the required schema version of the artifact.
pub const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Top-level table holding secret-class keys (values must be references).
pub const SECRETS_KEY: &str = "secrets";

// ── Reserved diagnostic codes (D5: E7001–E7099) ──────────────────────────────

/// `E7001` — TOML artifact could not be parsed (or produced).
pub const CODE_ARTIFACT: &str = "E7001";
/// `E7002` — unknown key / unknown section: refused, never ignored.
pub const CODE_UNKNOWN_KEY: &str = "E7002";
/// `E7003` — value type mismatch (or unknown enum word) for a typed key.
pub const CODE_TYPE_MISMATCH: &str = "E7003";
/// `E7004` — `schema_version` missing, malformed, zero, older-without-migration,
/// or newer than [`SCHEMA_VERSION`] (downgrade guard).
pub const CODE_SCHEMA_VERSION: &str = "E7004";
/// `E7005` — literal value in a secret-class key (a reference is required).
pub const CODE_LITERAL_SECRET: &str = "E7005";
/// `E7006` — the config file exists but cannot be read.
pub const CODE_READ_IO: &str = "E7006";
/// `E7007` — the atomic write failed; the previous file is left intact.
pub const CODE_WRITE_IO: &str = "E7007";
/// `E7008` — the config-history revision could not be recorded (write refused).
pub const CODE_HISTORY_RECORD: &str = "E7008";
/// `E7009` — the config-history location is unresolvable/unusable.
pub const CODE_HISTORY_PATH: &str = "E7009";
/// `E7010` — a secret reference failed to resolve at use time.
pub const CODE_SECRET_RESOLUTION: &str = "E7010";
/// `E7011` — `vault://` resolution is a reserved kernel-internal seam (D7).
pub const CODE_VAULT_SEAM: &str = "E7011";
/// `E7012` — a required base directory is unavailable; refuse, never guess (A4).
pub const CODE_PATH_UNRESOLVED: &str = "E7012";
/// `E7013` — aggregate refusal: the artifact failed strict validation.
pub const CODE_REFUSED: &str = "E7013";

// ── Sections & diagnostics ───────────────────────────────────────────────────

/// Which part of the artifact a diagnostic refuses (D3: refusals are scoped to
/// the subsystem bound to the section, not the whole binary).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigSection {
    /// The artifact itself (syntax / read-level refusal — everything is refused).
    File,
    /// Kernel root scalars (`schema_version`, `profile`, `format`, `no_color`,
    /// `telemetry`).
    Core,
    /// The `[secrets]` table (reference-only values).
    Secrets,
    /// A top-level table outside the KB-1 subset (e.g. `[browser]`): only the
    /// subsystem that would consume that table is refused.
    Other(String),
}

impl ConfigSection {
    /// Stable lowercase name (section `Other` carries its own table name).
    pub fn as_str(&self) -> &str {
        match self {
            ConfigSection::File => "file",
            ConfigSection::Core => "core",
            ConfigSection::Secrets => "secrets",
            ConfigSection::Other(name) => name.as_str(),
        }
    }
}

impl fmt::Display for ConfigSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One strict-validation finding: reserved code, refused section, and the key
/// it is about (when known). `message` never contains secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiagnostic {
    /// Reserved kernel code (`E7001`…`E7099`).
    pub code: &'static str,
    /// The section this finding refuses (D3 scoping).
    pub section: ConfigSection,
    /// Dotted key path when the finding is about a key.
    pub key: Option<String>,
    /// Human message — must never embed secret values.
    pub message: String,
}

impl ConfigDiagnostic {
    /// Construct a diagnostic.
    pub fn new(
        code: &'static str,
        section: ConfigSection,
        key: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        ConfigDiagnostic {
            code,
            section,
            key,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] {}", self.code, self.section, self.message)
    }
}

/// A refused section: every diagnostic that contributed, for the subsystem
/// bound to that section (D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionRefusal {
    /// The refused section.
    pub section: ConfigSection,
    /// All findings for that section, in deterministic order.
    pub diagnostics: Vec<ConfigDiagnostic>,
}

impl SectionRefusal {
    /// Build a refusal from its diagnostics (panics never; empty is allowed but
    /// callers only construct refusals from ≥1 diagnostics).
    pub fn new(section: ConfigSection, diagnostics: Vec<ConfigDiagnostic>) -> Self {
        SectionRefusal {
            section,
            diagnostics,
        }
    }

    /// Codes contributing to this refusal.
    pub fn codes(&self) -> Vec<&'static str> {
        self.diagnostics.iter().map(|d| d.code).collect()
    }
}

impl fmt::Display for SectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "config section `{}` refused ({} diagnostic(s)): {}",
            self.section,
            self.diagnostics.len(),
            self.diagnostics
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

impl std::error::Error for SectionRefusal {}

// ── Typed kernel errors ──────────────────────────────────────────────────────

/// Typed kernel error. Every variant carries one reserved code; [`ConfigError::code`]
/// returns it and the `Display` form is prefixed with it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `E7001` — TOML artifact could not be parsed (or produced).
    #[error("E7001: config artifact error: {message}")]
    Artifact {
        /// What failed, including the source path when one was known.
        message: String,
    },

    /// `E7002` — unknown key or unknown section: refused, never ignored.
    #[error("E7002: unknown key `{key}` in section `{section}` (strict config — unknown keys are refused, never ignored)")]
    UnknownKey {
        /// Section the unknown key would have belonged to.
        section: ConfigSection,
        /// Dotted key path.
        key: String,
    },

    /// `E7003` — value type mismatch (or unknown enum word) for a typed key.
    #[error("E7003: type mismatch for `{key}` in section `{section}`: expected {expected}, found {found}")]
    TypeMismatch {
        /// Section the key belongs to.
        section: ConfigSection,
        /// Dotted key path.
        key: String,
        /// Expected value description.
        expected: &'static str,
        /// Description of the value actually found.
        found: String,
    },

    /// `E7004` — `schema_version` missing, malformed, zero, older-without-
    /// migration, or newer than [`SCHEMA_VERSION`] (downgrade guard).
    #[error("E7004: unsupported schema_version {found}: {detail}")]
    SchemaVersion {
        /// The offending value (or `absent`).
        found: String,
        /// Why it is refused.
        detail: String,
    },

    /// `E7005` — literal value in a secret-class key; a reference is required.
    #[error("E7005: secret-class key `{key}` must hold a reference (`env:NAME`, `file:PATH`, `vault://…`): {detail}")]
    LiteralSecret {
        /// Dotted key path (or `<secret-ref>` for schema-level parses).
        key: String,
        /// Why the value is not an acceptable reference (never echoes the value).
        detail: String,
    },

    /// `E7006` — the config file exists but cannot be read.
    #[error("E7006: cannot read config file {path:?}: {message}")]
    Read {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O message.
        message: String,
    },

    /// `E7007` — the atomic write failed; the previous file is left intact.
    #[error("E7007: atomic write failed for {path:?} (previous file left intact): {message}")]
    Write {
        /// Target path of the failed write.
        path: PathBuf,
        /// Underlying failure.
        message: String,
    },

    /// `E7008` — the config-history revision could not be recorded; the write
    /// is refused (fail-closed: no unrecorded accepted writes).
    #[error("E7008: config-history revision could not be recorded at {path:?}: {message}")]
    HistoryRecord {
        /// Revision file/dir that could not be written.
        path: PathBuf,
        /// Underlying failure.
        message: String,
    },

    /// `E7009` — the config-history location is unresolvable/unusable.
    #[error("E7009: config-history location unusable: {message}")]
    HistoryPath {
        /// Why the location is unusable.
        message: String,
    },

    /// `E7010` — a secret reference failed to resolve at use time. Resolution
    /// failures are hard errors: never a silent default.
    #[error("E7010: secret reference ({scheme}) failed to resolve: {detail}")]
    SecretResolution {
        /// Reference scheme (`env`, `file`, `vault`).
        scheme: &'static str,
        /// What failed (never the secret itself).
        detail: String,
    },

    /// `E7011` — `vault://` parsing landed in KB-1; resolution is a reserved
    /// kernel-internal seam (D7) wired by KB-4.
    #[error("E7011: `vault://` reference cannot be resolved by the KB-1 kernel — vault resolution is a reserved kernel-internal seam (D7) and lands with KB-4 ({uri})")]
    VaultSeam {
        /// The raw `vault://…` URI (a reference, never a secret value).
        uri: String,
    },

    /// `E7012` — a required base directory is unavailable. Refuse; the kernel
    /// never falls back to `"."` or a guess (U-202 anomaly A4).
    #[error("E7012: required base directory not available: {what} (refusing — the kernel never falls back to `\".\"`; A4)")]
    PathUnresolved {
        /// Which base directory was required.
        what: String,
    },

    /// `E7013` — aggregate refusal: the artifact failed strict validation.
    /// The individual codes live on the wrapped refusal's diagnostics.
    #[error("E7013: config refused: {0}")]
    Refused(Box<SectionRefusal>),
}

impl ConfigError {
    /// The reserved kernel code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::Artifact { .. } => CODE_ARTIFACT,
            ConfigError::UnknownKey { .. } => CODE_UNKNOWN_KEY,
            ConfigError::TypeMismatch { .. } => CODE_TYPE_MISMATCH,
            ConfigError::SchemaVersion { .. } => CODE_SCHEMA_VERSION,
            ConfigError::LiteralSecret { .. } => CODE_LITERAL_SECRET,
            ConfigError::Read { .. } => CODE_READ_IO,
            ConfigError::Write { .. } => CODE_WRITE_IO,
            ConfigError::HistoryRecord { .. } => CODE_HISTORY_RECORD,
            ConfigError::HistoryPath { .. } => CODE_HISTORY_PATH,
            ConfigError::SecretResolution { .. } => CODE_SECRET_RESOLUTION,
            ConfigError::VaultSeam { .. } => CODE_VAULT_SEAM,
            ConfigError::PathUnresolved { .. } => CODE_PATH_UNRESOLVED,
            ConfigError::Refused(_) => CODE_REFUSED,
        }
    }
}

// ── Enums: profile, output format ────────────────────────────────────────────

/// Hardening profile names (report §11 profile set). KB-1 parses and
/// round-trips the word; profile *behavior* (presets, tighten-only rule) lands
/// with KB-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Default balanced posture.
    Balanced,
    /// Privacy-leaning posture.
    Privacy,
    /// Maximum-security posture.
    MaximumSecurity,
    /// Performance-leaning posture.
    Performance,
    /// Developer ergonomics posture.
    Developer,
    /// Headless server posture.
    Server,
    /// Mobile posture.
    Mobile,
    /// Swarm / multi-agent posture.
    Swarm,
}

impl Profile {
    /// Every accepted profile, in canonical order.
    pub const ALL: [Profile; 8] = [
        Profile::Balanced,
        Profile::Privacy,
        Profile::MaximumSecurity,
        Profile::Performance,
        Profile::Developer,
        Profile::Server,
        Profile::Mobile,
        Profile::Swarm,
    ];

    /// Canonical TOML word for the profile.
    pub fn word(self) -> &'static str {
        match self {
            Profile::Balanced => "balanced",
            Profile::Privacy => "privacy",
            Profile::MaximumSecurity => "maximum-security",
            Profile::Performance => "performance",
            Profile::Developer => "developer",
            Profile::Server => "server",
            Profile::Mobile => "mobile",
            Profile::Swarm => "swarm",
        }
    }

    /// Exact-match parse of the canonical word (case-sensitive).
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.word() == word)
    }
}

/// `format` — CLI output format for `tallow config` and related surfaces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Human-readable text (current default).
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
}

impl OutputFormat {
    /// Every accepted word.
    pub const ALL: [OutputFormat; 2] = [OutputFormat::Text, OutputFormat::Json];

    /// Canonical TOML word.
    pub fn word(self) -> &'static str {
        match self {
            OutputFormat::Text => "text",
            OutputFormat::Json => "json",
        }
    }

    /// Exact-match parse of the canonical word.
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.word() == word)
    }
}

/// Helper for `expected` fields of diagnostics.
pub(crate) const EXPECTED_PROFILE: &str =
    "one of `balanced|privacy|maximum-security|performance|developer|server|mobile|swarm`";
/// Helper for `expected` fields of diagnostics.
pub(crate) const EXPECTED_FORMAT: &str = "one of `text|json`";

// ── Secret references (D7 seam) ──────────────────────────────────────────────

/// A config value stored **by reference** (R-7.5; §11 "secrets handling").
///
/// - `env:NAME` — read environment variable `NAME` at use time.
/// - `file:/path` — read an owner-only regular file at use time.
/// - `vault://…` — parse + round-trip now; resolution is a reserved
///   kernel-internal seam (D7) until KB-4 wires the vault read path.
///
/// Anything else (a literal) is refused at parse time (`E7005`): secret-class
/// keys never hold plaintext in config.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecretRef {
    /// `env:NAME`.
    Env {
        /// Environment variable name.
        name: String,
    },
    /// `file:/path`.
    File {
        /// Path to the owner-only secret file.
        path: PathBuf,
    },
    /// `vault://<path>` — kernel-internal resolution seam (D7).
    Vault {
        /// The full original `vault://…` URI.
        uri: String,
    },
}

const ENV_PREFIX: &str = "env:";
const FILE_PREFIX: &str = "file:";
const VAULT_PREFIX: &str = "vault://";

impl SecretRef {
    /// Parse a raw config value into a reference.
    ///
    /// `key` is the dotted config key used in the error text. A value with no
    /// known scheme — including any looks-like-a-secret literal — is refused
    /// with [`CODE_LITERAL_SECRET`]; the error never echoes the value.
    pub fn parse(raw: &str, key: &str) -> Result<Self, ConfigError> {
        let value = raw.trim();
        if let Some(name) = value.strip_prefix(ENV_PREFIX) {
            if name.is_empty() {
                return Err(ConfigError::LiteralSecret {
                    key: key.to_string(),
                    detail: "`env:` reference has an empty variable name".to_string(),
                });
            }
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(ConfigError::LiteralSecret {
                    key: key.to_string(),
                    detail: "`env:` variable name contains non-[A-Za-z0-9_] characters"
                        .to_string(),
                });
            }
            return Ok(SecretRef::Env {
                name: name.to_string(),
            });
        }
        if let Some(path) = value.strip_prefix(FILE_PREFIX) {
            if path.is_empty() {
                return Err(ConfigError::LiteralSecret {
                    key: key.to_string(),
                    detail: "`file:` reference has an empty path".to_string(),
                });
            }
            return Ok(SecretRef::File {
                path: PathBuf::from(path),
            });
        }
        if let Some(rest) = value.strip_prefix(VAULT_PREFIX) {
            if rest.is_empty() {
                return Err(ConfigError::LiteralSecret {
                    key: key.to_string(),
                    detail: "`vault://` reference has an empty URI body".to_string(),
                });
            }
            return Ok(SecretRef::Vault {
                uri: value.to_string(),
            });
        }
        Err(ConfigError::LiteralSecret {
            key: key.to_string(),
            detail: "no `env:`/`file:`/`vault://` scheme — values look literal, and literals \
                     are refused in secret-class keys"
                .to_string(),
        })
    }

    /// Reference scheme word (`env` | `file` | `vault`).
    pub fn scheme(&self) -> &'static str {
        match self {
            SecretRef::Env { .. } => "env",
            SecretRef::File { .. } => "file",
            SecretRef::Vault { .. } => "vault",
        }
    }

    /// Canonical string form (the exact text serialized back to TOML).
    pub fn to_canonical(&self) -> String {
        match self {
            SecretRef::Env { name } => format!("{ENV_PREFIX}{name}"),
            SecretRef::File { path } => format!("{FILE_PREFIX}{}", path.display()),
            SecretRef::Vault { uri } => uri.clone(),
        }
    }

    /// Resolve the reference **at use time**. Failures are hard errors — the
    /// caller refuses the operation, never falls back to a default. The
    /// resolved value must never be logged.
    ///
    /// `vault://` still returns the reserved seam error (`E7011`, D7): KB-1
    /// parses and round-trips vault references but does not resolve them.
    pub fn resolve(&self) -> Result<String, ConfigError> {
        match self {
            SecretRef::Env { name } => {
                let value = std::env::var(name).map_err(|_| ConfigError::SecretResolution {
                    scheme: "env",
                    detail: format!("variable `{name}` is not set in the environment"),
                })?;
                if value.trim().is_empty() {
                    return Err(ConfigError::SecretResolution {
                        scheme: "env",
                        detail: format!("variable `{name}` resolved to an empty value"),
                    });
                }
                Ok(value)
            }
            SecretRef::File { path } => read_owner_only_secret(path),
            SecretRef::Vault { uri } => Err(ConfigError::VaultSeam { uri: uri.clone() }),
        }
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_canonical())
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        // The toml deserializer appends key context (`in \`secrets.foo\``) to
        // the message; the code prefix is what classification keys on.
        Self::parse(&raw, "<secret-ref>").map_err(serde::de::Error::custom)
    }
}

/// Read a secret from an owner-only regular file (same policy as the daemon
/// token path, T-110): no symlinks/dirs; loose group/other bits are tightened
/// to 0600 before the contents are trusted; an empty value is refused.
fn read_owner_only_secret(path: &Path) -> Result<String, ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::symlink_metadata(path).map_err(|e| ConfigError::SecretResolution {
                scheme: "file",
                detail: format!("cannot stat `{}`: {e}", path.display()),
            })?;
        if !meta.file_type().is_file() {
            return Err(ConfigError::SecretResolution {
                scheme: "file",
                detail: format!(
                    "`{}` is not a regular file (refusing symlink/dir)",
                    path.display()
                ),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| ConfigError::SecretResolution {
                    scheme: "file",
                    detail: format!(
                        "`{}` has group/other access and could not be tightened to 0600: {e}",
                        path.display()
                    ),
                },
            )?;
            tracing::warn!(
                path = ?path,
                mode = format!("{mode:o}"),
                "secret file permissions were not owner-only; tightened to 0600"
            );
        }
    }
    #[cfg(not(unix))]
    {
        if !path.is_file() {
            return Err(ConfigError::SecretResolution {
                scheme: "file",
                detail: format!("`{}` is not a regular file", path.display()),
            });
        }
    }

    let value = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::SecretResolution {
            scheme: "file",
            detail: format!("cannot read `{}`: {e}", path.display()),
        })?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(ConfigError::SecretResolution {
            scheme: "file",
            detail: format!("`{}` is empty — refusing (no silent default)", path.display()),
        });
    }
    Ok(value)
}

// ── Key-class metadata (consumed by KB-2 locks) ──────────────────────────────

/// Key classes from report §11 ("free / operator / locked / device /
/// secret-ref"). KB-1 records the class of every known key; enforcement
/// (lock table, precedence) lands with KB-2. `secrets.*` is additionally
/// enforced structurally today (reference-only values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyClass {
    /// Settable from any scope that is allowed to write config.
    Free,
    /// Operator-controlled; lockable by a higher scope in KB-2.
    Operator,
    /// Locked by higher-scope policy (metadata only until KB-2 scopes exist).
    Locked,
    /// Device-scope only.
    Device,
    /// Must hold a secret *reference* (never a literal).
    SecretRef,
}

impl KeyClass {
    /// Stable lowercase word.
    pub fn word(self) -> &'static str {
        match self {
            KeyClass::Free => "free",
            KeyClass::Operator => "operator",
            KeyClass::Locked => "locked",
            KeyClass::Device => "device",
            KeyClass::SecretRef => "secret-ref",
        }
    }
}

/// Metadata row for one known config key path (`secrets.*` is a wildcard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMeta {
    /// Dotted key path; `secrets.*` matches every `[secrets]` entry.
    pub path: &'static str,
    /// Class of the key.
    pub class: KeyClass,
}

/// Every key of the KB-1 subset with its class.
pub const KEY_METADATA: &[KeyMeta] = &[
    KeyMeta {
        path: SCHEMA_VERSION_KEY,
        class: KeyClass::Operator,
    },
    KeyMeta {
        path: "profile",
        class: KeyClass::Operator,
    },
    KeyMeta {
        path: "format",
        class: KeyClass::Free,
    },
    KeyMeta {
        path: "no_color",
        class: KeyClass::Free,
    },
    KeyMeta {
        path: "telemetry",
        class: KeyClass::Operator,
    },
    KeyMeta {
        path: "secrets.*",
        class: KeyClass::SecretRef,
    },
];

/// Root scalar keys of the KB-1 core section.
pub const CORE_KEYS: &[&str] = &[
    SCHEMA_VERSION_KEY,
    "profile",
    "format",
    "no_color",
    "telemetry",
];

/// Class of a dotted key path, if the key is known to this kernel.
pub fn key_class(path: &str) -> Option<KeyClass> {
    if let Some(meta) = KEY_METADATA.iter().find(|m| m.path == path) {
        return Some(meta.class);
    }
    if let Some(rest) = path.strip_prefix("secrets.") {
        if !rest.is_empty() && !rest.contains('.') {
            return Some(KeyClass::SecretRef);
        }
    }
    None
}

// ── Section settings ─────────────────────────────────────────────────────────

/// Validated core settings (root scalars of the KB-1 subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSettings {
    /// Artifact schema version (validated equal to [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Optional hardening profile word.
    pub profile: Option<Profile>,
    /// CLI output format.
    pub format: OutputFormat,
    /// Disable colored output.
    pub no_color: bool,
    /// Telemetry opt-in (secure default: disabled).
    pub telemetry: bool,
}

impl Default for CoreSettings {
    fn default() -> Self {
        CoreSettings {
            schema_version: SCHEMA_VERSION,
            profile: None,
            format: OutputFormat::Text,
            no_color: false,
            telemetry: false,
        }
    }
}

/// Validated `[secrets]` section: name → reference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretSettings {
    /// Secret-class entries, reference-only by construction.
    pub entries: BTreeMap<String, SecretRef>,
}

// ── The typed tree ───────────────────────────────────────────────────────────

/// The KB-1 typed configuration tree — 1:1 with the TOML artifact.
///
/// Strict by construction: `deny_unknown_fields`, required `schema_version`,
/// reference-only `secrets` values. Serialization skips defaults so a written
/// artifact is minimal and round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Required artifact schema version.
    pub schema_version: u32,
    /// Optional hardening profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// CLI output format.
    #[serde(default, skip_serializing_if = "is_default_format")]
    pub format: OutputFormat,
    /// Disable colored output.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_color: bool,
    /// Telemetry opt-in (secure default: disabled).
    #[serde(default, skip_serializing_if = "is_false")]
    pub telemetry: bool,
    /// Secret-class entries: reference-only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretRef>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn is_default_format(f: &OutputFormat) -> bool {
    *f == OutputFormat::Text
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: SCHEMA_VERSION,
            profile: None,
            format: OutputFormat::Text,
            no_color: false,
            telemetry: false,
            secrets: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Serialize the tree to TOML text (the artifact form written to disk).
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Artifact {
            message: format!("serialize: {e}"),
        })
    }

    /// Strict deserialization of a TOML artifact straight into the typed tree
    /// (serde `deny_unknown_fields` + reference-only secrets). The sectioned
    /// loader ([`crate::config::load`]) produces the same verdicts with
    /// per-section attribution; this entry point is for whole-file consumers
    /// and round-trip tests.
    pub fn from_toml_str_strict(text: &str) -> Result<Self, ConfigError> {
        toml::from_str::<Config>(text).map_err(classify_artifact_error)
    }

    /// Project the core section out of the tree.
    pub fn core_settings(&self) -> CoreSettings {
        CoreSettings {
            schema_version: self.schema_version,
            profile: self.profile,
            format: self.format,
            no_color: self.no_color,
            telemetry: self.telemetry,
        }
    }

    /// Project the secrets section out of the tree.
    pub fn secret_settings(&self) -> SecretSettings {
        SecretSettings {
            entries: self.secrets.clone(),
        }
    }

    /// Rebuild the tree from validated sections (the loader's join point).
    pub fn from_sections(core: CoreSettings, secrets: SecretSettings) -> Self {
        Config {
            schema_version: core.schema_version,
            profile: core.profile,
            format: core.format,
            no_color: core.no_color,
            telemetry: core.telemetry,
            secrets: secrets.entries,
        }
    }

    /// True when the artifact carries at least one secret-class entry (drives
    /// the `0600` file-permission policy on unix).
    pub fn has_secret_values(&self) -> bool {
        !self.secrets.is_empty()
    }
}

/// Best-effort classification of a toml deserialize error into a typed kernel
/// error (`E7002`/`E7003`/`E7004`/`E7005`; everything else stays `E7001`).
///
/// Errors raised by this module's own deserializers carry their reserved code
/// as the message prefix — those keep their code. The sectioned loader remains
/// the precise authority; this mapper exists for whole-file callers.
pub(crate) fn classify_artifact_error(err: toml::de::Error) -> ConfigError {
    let message = err.message().to_string();
    for code in [
        CODE_LITERAL_SECRET,
        CODE_SCHEMA_VERSION,
        CODE_TYPE_MISMATCH,
        CODE_UNKNOWN_KEY,
    ] {
        if let Some(rest) = message.strip_prefix(code) {
            let detail = rest.trim_start_matches(':').trim().to_string();
            return match code {
                CODE_LITERAL_SECRET => ConfigError::LiteralSecret {
                    key: "<secret-ref>".to_string(),
                    detail,
                },
                CODE_SCHEMA_VERSION => ConfigError::SchemaVersion {
                    found: "see message".to_string(),
                    detail,
                },
                _ => ConfigError::Artifact {
                    message: format!("{code}: {detail}"),
                },
            };
        }
    }
    if message.contains("missing field") && message.contains(SCHEMA_VERSION_KEY) {
        return ConfigError::SchemaVersion {
            found: "absent".to_string(),
            detail: "missing required key `schema_version` — every kernel artifact is versioned"
                .to_string(),
        };
    }
    if message.contains("unknown field") {
        let key = extract_backticked(&message, "unknown field ")
            .unwrap_or_else(|| "<unknown>".to_string());
        return ConfigError::UnknownKey {
            section: ConfigSection::Core,
            key,
        };
    }
    if message.contains("invalid type")
        || message.contains("unknown variant")
        || message.contains("invalid value")
        || message.contains("missing field")
    {
        return ConfigError::TypeMismatch {
            section: ConfigSection::Core,
            key: extract_backticked(&message, "for key ").unwrap_or_else(|| "<unknown>".to_string()),
            expected: "the typed schema (see `tallow config validate`)",
            found: message.clone(),
        };
    }
    ConfigError::Artifact { message: err.to_string() }
}

fn extract_backticked(message: &str, after: &str) -> Option<String> {
    let idx = message.find(after)?;
    let rest = &message[idx + after.len()..];
    let start = rest.find('`')? + 1;
    let end = rest[start..].find('`')? + start;
    Some(rest[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "registry_token".to_string(),
            SecretRef::Env {
                name: "TALLOW_REGISTRY_TOKEN".to_string(),
            },
        );
        secrets.insert(
            "vault_key".to_string(),
            SecretRef::Vault {
                uri: "vault://services/registry/key".to_string(),
            },
        );
        Config {
            schema_version: SCHEMA_VERSION,
            profile: Some(Profile::Privacy),
            format: OutputFormat::Json,
            no_color: true,
            telemetry: false,
            secrets,
        }
    }

    #[test]
    fn round_trip_full_config() {
        let cfg = sample_config();
        let text = cfg.to_toml_string().expect("serialize");
        let back = Config::from_toml_str_strict(&text).expect("strict parse");
        assert_eq!(cfg, back, "typed tree must round-trip through TOML");

        // Defaults are skipped on serialize: a default tree writes only the
        // required version key and parses back identically.
        let default_text = Config::default().to_toml_string().expect("serialize");
        assert!(default_text.contains("schema_version = 1"), "{default_text}");
        assert!(!default_text.contains("format"), "default skipped: {default_text}");
        let default_back = Config::from_toml_str_strict(&default_text).expect("strict parse");
        assert_eq!(Config::default(), default_back);
    }

    #[test]
    fn serde_strict_unknown_field_rejected() {
        let err = Config::from_toml_str_strict("schema_version = 1\ntypo_key = true\n")
            .expect_err("unknown field must be refused");
        assert_eq!(err.code(), CODE_UNKNOWN_KEY);
        assert!(
            err.to_string().contains("typo_key"),
            "message must name the key: {err}"
        );
    }

    #[test]
    fn serde_missing_schema_version_rejected() {
        let err = Config::from_toml_str_strict("telemetry = false\n")
            .expect_err("version is required");
        assert_eq!(err.code(), CODE_SCHEMA_VERSION);
    }

    #[test]
    fn serde_wrong_type_rejected() {
        let err = Config::from_toml_str_strict("schema_version = 1\nno_color = \"yes\"\n")
            .expect_err("type mismatch must be refused");
        assert_eq!(err.code(), CODE_TYPE_MISMATCH);
    }

    #[test]
    fn serde_literal_secret_rejected() {
        let err = Config::from_toml_str_strict(
            "schema_version = 1\n[secrets]\napi_key = \"hunter2\"\n",
        )
        .expect_err("literal secret must be refused");
        assert_eq!(err.code(), CODE_LITERAL_SECRET);
        assert!(
            !err.to_string().contains("hunter2"),
            "error text must never echo the value: {err}"
        );
    }

    #[test]
    fn profile_words_round_trip_and_reject_unknown() {
        assert_eq!(Profile::ALL.len(), 8);
        for p in Profile::ALL {
            assert_eq!(Profile::parse(p.word()), Some(p), "{}", p.word());
        }
        assert_eq!(Profile::parse("maximum-security"), Some(Profile::MaximumSecurity));
        assert_eq!(Profile::parse("MaximumSecurity"), None, "case-sensitive");
        assert_eq!(Profile::parse("maximum_security"), None);
        assert_eq!(Profile::parse(""), None);
    }

    #[test]
    fn output_format_words_round_trip() {
        for f in OutputFormat::ALL {
            assert_eq!(OutputFormat::parse(f.word()), Some(f));
        }
        assert_eq!(OutputFormat::parse("yaml"), None);
        assert_eq!(OutputFormat::default(), OutputFormat::Text);
    }

    #[test]
    fn key_class_lookup_and_metadata_invariants() {
        assert_eq!(key_class("format"), Some(KeyClass::Free));
        assert_eq!(key_class("no_color"), Some(KeyClass::Free));
        assert_eq!(key_class("telemetry"), Some(KeyClass::Operator));
        assert_eq!(key_class("profile"), Some(KeyClass::Operator));
        assert_eq!(key_class("schema_version"), Some(KeyClass::Operator));
        assert_eq!(key_class("secrets.token"), Some(KeyClass::SecretRef));
        assert_eq!(key_class("secrets."), None);
        assert_eq!(key_class("secrets.a.b"), None);
        assert_eq!(key_class("nope"), None);
        // Every core key has metadata and a class matching its enforcement.
        for key in CORE_KEYS {
            assert!(key_class(key).is_some(), "core key `{key}` lacks metadata");
        }
        assert!(KEY_METADATA.iter().any(|m| m.class == KeyClass::SecretRef));
    }

    #[test]
    fn secret_ref_parse_accepts_exact_schemes() {
        let env = SecretRef::parse("env:TALLOW_TOKEN", "secrets.x").expect("env ref");
        assert_eq!(env.scheme(), "env");
        assert_eq!(env.to_canonical(), "env:TALLOW_TOKEN");

        let file = SecretRef::parse("file:/run/secrets/token", "secrets.x").expect("file ref");
        assert_eq!(file.scheme(), "file");
        assert_eq!(file.to_canonical(), "file:/run/secrets/token");

        let vault = SecretRef::parse("vault://svc/key", "secrets.x").expect("vault ref");
        assert_eq!(vault.scheme(), "vault");
        assert_eq!(vault.to_canonical(), "vault://svc/key");
    }

    #[test]
    fn secret_ref_parse_refuses_literals_and_malformed() {
        for (raw, needle) in [
            ("hunter2", "literal"),
            ("", "literal"),
            ("env:", "empty variable name"),
            ("env:bad name", "non-[A-Za-z0-9_]"),
            ("file:", "empty path"),
            ("vault://", "empty URI body"),
        ] {
            let err = SecretRef::parse(raw, "secrets.k").expect_err(raw);
            assert_eq!(err.code(), CODE_LITERAL_SECRET, "raw={raw:?}");
            assert!(
                !err.to_string().contains("hunter2"),
                "must not echo the value: {err}"
            );
            assert!(
                err.to_string().contains(needle),
                "detail for {raw:?}: {err}"
            );
        }
    }

    #[test]
    fn secret_ref_resolution_failures_are_typed() {
        let missing = SecretRef::Env {
            name: "TALLOW_U214_DEFINITELY_MISSING_VAR".to_string(),
        };
        let err = missing.resolve().expect_err("missing env must fail");
        assert_eq!(err.code(), CODE_SECRET_RESOLUTION);
        assert!(err.to_string().contains("not set"), "{err}");

        let file = SecretRef::File {
            path: PathBuf::from("/nonexistent/u214-secret-file"),
        };
        let err = file.resolve().expect_err("missing file must fail");
        assert_eq!(err.code(), CODE_SECRET_RESOLUTION);

        let vault = SecretRef::Vault {
            uri: "vault://svc/key".to_string(),
        };
        let err = vault.resolve().expect_err("vault seam");
        assert_eq!(err.code(), CODE_VAULT_SEAM, "D7: resolution is a reserved seam");
        assert!(err.to_string().contains("KB-4"), "{err}");
    }

    #[test]
    fn secret_ref_debug_shows_reference_only() {
        let debug = format!("{:?}", sample_config().secrets["registry_token"]);
        assert!(debug.contains("TALLOW_REGISTRY_TOKEN"), "{debug}");
        assert!(debug.contains("Env"), "{debug}");
    }

    #[test]
    fn error_codes_pin_display_prefix() {
        let samples: Vec<ConfigError> = vec![
            ConfigError::Artifact { message: "x".into() },
            ConfigError::UnknownKey {
                section: ConfigSection::Core,
                key: "k".into(),
            },
            ConfigError::TypeMismatch {
                section: ConfigSection::Core,
                key: "k".into(),
                expected: "a boolean",
                found: "a string".into(),
            },
            ConfigError::SchemaVersion {
                found: "99".into(),
                detail: "newer".into(),
            },
            ConfigError::LiteralSecret {
                key: "secrets.k".into(),
                detail: "d".into(),
            },
            ConfigError::Read {
                path: PathBuf::from("/x"),
                message: "m".into(),
            },
            ConfigError::Write {
                path: PathBuf::from("/x"),
                message: "m".into(),
            },
            ConfigError::HistoryRecord {
                path: PathBuf::from("/x"),
                message: "m".into(),
            },
            ConfigError::HistoryPath { message: "m".into() },
            ConfigError::SecretResolution {
                scheme: "env",
                detail: "d".into(),
            },
            ConfigError::VaultSeam { uri: "vault://x".into() },
            ConfigError::PathUnresolved { what: "config_dir".into() },
            ConfigError::Refused(Box::new(SectionRefusal::new(
                ConfigSection::Core,
                vec![ConfigDiagnostic::new(
                    CODE_UNKNOWN_KEY,
                    ConfigSection::Core,
                    Some("k".into()),
                    "unknown key `k`",
                )],
            ))),
        ];
        for err in samples {
            let code = err.code();
            assert!(
                code.starts_with('E') && code.len() == 5,
                "code shape: {code}"
            );
            assert!(
                err.to_string().starts_with(code),
                "Display must start with {code}: {err}"
            );
        }
    }

    #[test]
    fn diagnostic_and_refusal_display() {
        let d = ConfigDiagnostic::new(
            CODE_UNKNOWN_KEY,
            ConfigSection::Other("browser".into()),
            Some("browser.foo".into()),
            "unknown config table `browser`",
        );
        assert_eq!(
            d.to_string(),
            "E7002 [browser] unknown config table `browser`"
        );
        let refusal = SectionRefusal::new(ConfigSection::Core, vec![d.clone()]);
        assert_eq!(refusal.codes(), vec![CODE_UNKNOWN_KEY]);
        assert!(refusal.to_string().contains("core"), "{refusal}");
    }
}
