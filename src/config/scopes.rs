//! KB-2 scope ladder, layer ingest and the lock table (row #84, R-7.2).
//!
//! The R-7.2 scope stack (`defaults < profile < system < user < device <
//! project < agent < session`, `07-config-system-draft.md:40`) with the
//! `swarm` scope as a **system-class** source. This module owns the
//! vocabulary and the *ingest* gate; [`crate::config::resolve`] owns the
//! merge.
//!
//! # Reused vocabulary
//! [`ConfigScope`] is **not** re-declared here: the signed-bundle block
//! (rows #153/#198) already carries the exact R-7.2 ladder
//! ([`crate::config::bundle::ConfigScope`]) and both surfaces must agree on
//! scope words (a bundle's `scope` is a resolution layer's scope). KB-2 adds
//! the *ordering* ([`LADDER`]/[`APPLICATION_ORDER`]/[`ladder_index`]) and
//! the layer/authority/lock machinery on top.
//!
//! # Layer ingest is kernel-validated
//! Every layer artifact is parsed through [`load::load_from_str`] and refused
//! when the **core** or **secrets** sections carry findings (`E7043`): a
//! string where the schema wants a boolean is a hard error at ingest — never
//! a best-effort parse (§7.2.2 "No type coercion"). Foreign tables
//! (`[browser]`, …) pass through — they belong to other subsystems.
//!
//! # Authority gate (verify-before-load)
//! `system`/`swarm` layers may **only** be built from a
//! [`VerifiedBundle`] ([`ScopeLayer::from_verified_bundle`]); a plain file
//! layer at those scopes is refused with the bundle gate's `E7027`
//! semantics. All other file scopes are `PlainFile` layers.
//!
//! # Locks are orthogonal to precedence (§7.2.1)
//! A layer may carry a `[lock]` control table (`"key.path" = true`). Locks
//! are only **honoured** from system-class scopes; a lock declared lower is
//! refused ([`ScopeError::LockOrigin`], `E7041`) rather than ignored.
//! `[lock]`/`[merge]` are control tables: they are stripped from the layer's
//! value tree at ingest and never reach the merged config.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use toml::Value;

pub use crate::config::bundle::{CODE_SCOPE_UNSIGNED_LOAD, ConfigScope, EXPECTED_SCOPE, VerifiedBundle};
use crate::config::load;
use crate::config::schema::{
    ConfigDiagnostic, ConfigError, ConfigSection, SCHEMA_VERSION, SCHEMA_VERSION_KEY,
};

// ── Reserved diagnostic codes (KB-2 block) ───────────────────────────────────

/// `E7040` — unknown scope word (refused, never defaulted) or a scope that is
/// not part of the resolution ladder.
pub const CODE_SCOPE_UNKNOWN: &str = "E7040";
/// `E7041` — lock violation, a malformed `[lock]` table, or a lock declared
/// outside a system-class scope. Names the lock origin.
pub const CODE_SCOPE_LOCK: &str = "E7041";
/// `E7042` — deep-merge conflict: structural kind mismatch across scopes
/// (table vs scalar/array) or a malformed `[merge]` directive. No coercion.
pub const CODE_SCOPE_MERGE: &str = "E7042";
/// `E7043` — scope-layer artifact failed kernel validation, or a layer was
/// built for the wrong kind of scope (`defaults`/`profile` are compiled-in,
/// `session` is env-sourced).
pub const CODE_SCOPE_LAYER: &str = "E7043";
/// `E7044` — malformed session override (`TALLOW_CONFIG_*` environment).
pub const CODE_SCOPE_SESSION: &str = "E7044";

// ── The ladder ───────────────────────────────────────────────────────────────

/// The R-7.2 resolution ladder, ascending precedence (swarm excluded — it is
/// system-class, see [`APPLICATION_ORDER`]).
pub const LADDER: [ConfigScope; 8] = [
    ConfigScope::Defaults,
    ConfigScope::Profile,
    ConfigScope::System,
    ConfigScope::User,
    ConfigScope::Device,
    ConfigScope::Project,
    ConfigScope::Agent,
    ConfigScope::Session,
];

/// Canonical **application order** of layers: the [`LADDER`] with `swarm`
/// applied as a system-class source immediately above `system`. Resolution
/// sorts layers by this order (stable — layers of the same scope keep their
/// input order, e.g. `config.toml` before `conf.d/*.toml`).
pub const APPLICATION_ORDER: [ConfigScope; 9] = [
    ConfigScope::Defaults,
    ConfigScope::Profile,
    ConfigScope::System,
    ConfigScope::Swarm,
    ConfigScope::User,
    ConfigScope::Device,
    ConfigScope::Project,
    ConfigScope::Agent,
    ConfigScope::Session,
];

/// Position of a scope in [`APPLICATION_ORDER`] (0 = lowest precedence).
pub fn ladder_index(scope: ConfigScope) -> usize {
    APPLICATION_ORDER
        .iter()
        .position(|s| *s == scope)
        .expect("every ConfigScope is in APPLICATION_ORDER")
}

/// Precedence rank on the R-7.2 ladder: `defaults` 0 … `session` 7. `swarm`
/// shares `system`'s rank (system-class, §7.2.1).
pub fn rank(scope: ConfigScope) -> u8 {
    match scope {
        ConfigScope::Defaults => 0,
        ConfigScope::Profile => 1,
        ConfigScope::System | ConfigScope::Swarm => 2,
        ConfigScope::User => 3,
        ConfigScope::Device => 4,
        ConfigScope::Project => 5,
        ConfigScope::Agent => 6,
        ConfigScope::Session => 7,
    }
}

/// Whether `higher` outranks `lower` in the resolution order.
pub fn is_above(higher: ConfigScope, lower: ConfigScope) -> bool {
    ladder_index(higher) > ladder_index(lower)
}

/// Whether a scope is system-class (`system`/`swarm` — the scopes that may
/// carry locks and demand verified signers).
pub fn is_system_class(scope: ConfigScope) -> bool {
    scope.requires_verified_signer()
}

/// Exact-match scope parse (the canonical word). Unknown words are refused
/// (`E7040`) — never silently defaulted to a nearby scope.
pub fn parse_scope(word: &str) -> Result<ConfigScope, ScopeError> {
    ConfigScope::parse(word).ok_or_else(|| ScopeError::UnknownScope {
        word: word.to_string(),
    })
}

// ── Merge directive ──────────────────────────────────────────────────────────

/// Per-key array-merge opt-in (§7.2.2: "arrays replace by default; explicit
/// `merge = "append"` opt-in per key"). Declared in a layer's `[merge]`
/// control table: `"key.path" = "append"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDirective {
    /// Append this key's arrays across layers instead of replacing.
    Append,
}

impl MergeDirective {
    /// Canonical word.
    pub fn word(self) -> &'static str {
        match self {
            MergeDirective::Append => "append",
        }
    }

    /// Exact-match parse. The only accepted word is `append` (`replace` is
    /// the default behavior, not a directive).
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "append" => Some(MergeDirective::Append),
            _ => None,
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Typed KB-2 error. Every variant carries one reserved code; [`ScopeError::code`]
/// returns it and the `Display` form is prefixed with it (kernel style).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// `E7040` — unknown scope word.
    UnknownScope {
        /// The refused word.
        word: String,
    },

    /// `E7027` — a plain (unverified) layer at a system-class scope.
    /// Reuses the bundle gate's code: "verify-before-load for system/swarm".
    AuthorityRequired {
        /// The system-class scope the plain layer targeted.
        scope: ConfigScope,
    },

    /// `E7041` — a lock was declared outside a system-class scope.
    LockOrigin {
        /// The locked key path.
        key: String,
        /// The (non-system) scope that tried to declare the lock.
        origin: ConfigScope,
    },

    /// `E7041` — a lower-precedence scope tried to override a locked key.
    /// The message names the lock origin; values are never echoed.
    LockViolation {
        /// The locked key path.
        key: String,
        /// The system-class scope that owns the lock.
        locked_by: ConfigScope,
        /// The scope that tried to override it.
        overridden_by: ConfigScope,
        /// What the resolution did (never a value).
        detail: String,
    },

    /// `E7041`/`E7042` — a malformed `[lock]`/`[merge]` control table.
    InvalidControl {
        /// Which control table (`lock` | `merge`).
        table: &'static str,
        /// The offending entry path, when known.
        path: Option<String>,
        /// The scope that declared it.
        origin: ConfigScope,
        /// Why it is refused.
        detail: String,
    },

    /// `E7042` — structural deep-merge kind conflict across scopes (table vs
    /// scalar/array). No coercion, no silent override.
    MergeConflict {
        /// The conflicting key path.
        key: String,
        /// Scope holding the lower value.
        lower: ConfigScope,
        /// Scope whose layer conflicts.
        higher: ConfigScope,
        /// What conflicted.
        detail: String,
    },

    /// `E7043` — layer built for the wrong kind of scope (`defaults`/
    /// `profile` are compiled-in, `session` is env-sourced).
    LayerKind {
        /// The scope in question.
        scope: ConfigScope,
        /// Which constructor to use instead.
        detail: String,
    },

    /// `E7043` — the layer artifact failed kernel validation.
    LayerRefused {
        /// The layer's scope.
        scope: ConfigScope,
        /// Layer source path, when known.
        source: Option<PathBuf>,
        /// Kernel diagnostics that caused the refusal (core/secrets/file).
        diagnostics: Vec<ConfigDiagnostic>,
    },

    /// `E7044` — malformed session override.
    SessionOverride {
        /// The offending environment variable name.
        name: String,
        /// Why it is refused.
        detail: String,
    },
}

impl ScopeError {
    /// The reserved kernel code for this error (`E7xxx`).
    pub fn code(&self) -> &'static str {
        match self {
            ScopeError::UnknownScope { .. } => CODE_SCOPE_UNKNOWN,
            ScopeError::AuthorityRequired { .. } => CODE_SCOPE_UNSIGNED_LOAD,
            ScopeError::LockOrigin { .. }
            | ScopeError::LockViolation { .. } => CODE_SCOPE_LOCK,
            ScopeError::InvalidControl { table, .. } => {
                if *table == "lock" {
                    CODE_SCOPE_LOCK
                } else {
                    CODE_SCOPE_MERGE
                }
            }
            ScopeError::MergeConflict { .. } => CODE_SCOPE_MERGE,
            ScopeError::LayerKind { .. } | ScopeError::LayerRefused { .. } => CODE_SCOPE_LAYER,
            ScopeError::SessionOverride { .. } => CODE_SCOPE_SESSION,
        }
    }
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            ScopeError::UnknownScope { word } => write!(
                f,
                "{code}: unknown scope `{word}` — expected {EXPECTED_SCOPE} (refusing; scopes are never guessed)"
            ),
            ScopeError::AuthorityRequired { scope } => write!(
                f,
                "{code}: plain (unverified) layer at scope `{}` — `system`/`swarm` layers must arrive as a verified bundle \
                 (verify-before-load, R-7.4; see `tallow config bundle`)",
                scope.word()
            ),
            ScopeError::LockOrigin { key, origin } => write!(
                f,
                "{code}: lock on `{key}` declared at scope `{}` — locks may only originate at a system-class scope \
                 (`system`/`swarm`; §7.2.1 locks are orthogonal to precedence)",
                origin.word()
            ),
            ScopeError::LockViolation {
                key,
                locked_by,
                overridden_by,
                detail,
            } => write!(
                f,
                "{code}: lock violation on `{key}`: locked at scope `{}`, overridden by scope `{}` — {detail}",
                locked_by.word(),
                overridden_by.word()
            ),
            ScopeError::InvalidControl {
                table,
                path,
                origin,
                detail,
            } => write!(
                f,
                "{code}: malformed `[{table}]` control table at scope `{}`{} — {detail}",
                origin.word(),
                path.as_ref()
                    .map(|p| format!(" (entry `{p}`)"))
                    .unwrap_or_default()
            ),
            ScopeError::MergeConflict {
                key,
                lower,
                higher,
                detail,
            } => write!(
                f,
                "{code}: merge conflict on `{key}`: scope `{}` and scope `{}` disagree structurally — {detail} \
                 (no coercion: the kernel never best-effort parses)",
                lower.word(),
                higher.word()
            ),
            ScopeError::LayerKind { scope, detail } => write!(
                f,
                "{code}: scope `{}` is not a file layer — {detail}",
                scope.word()
            ),
            ScopeError::LayerRefused {
                scope,
                source,
                diagnostics,
            } => {
                write!(
                    f,
                    "{code}: scope `{}` layer{} failed kernel validation ({} diagnostic(s)): {}",
                    scope.word(),
                    source
                        .as_ref()
                        .map(|p| format!(" ({})", p.display()))
                        .unwrap_or_default(),
                    diagnostics.len(),
                    diagnostics
                        .iter()
                        .map(|d| d.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            }
            ScopeError::SessionOverride { name, detail } => write!(
                f,
                "{code}: malformed session override `{name}` — {detail}"
            ),
        }
    }
}

impl std::error::Error for ScopeError {}

// ── Layer authority ──────────────────────────────────────────────────────────

/// How a layer's authority was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerAuthority {
    /// Compiled-in overlay (`defaults` defaults, `profile` selector).
    Builtin,
    /// Plain file layer (scopes below system-class).
    File,
    /// A verified signed bundle (system-class scopes — verify-before-load).
    VerifiedBundle {
        /// Hex signer public key of the verified signature.
        signer: String,
        /// Key id of the verified signature.
        key_id: String,
    },
}

impl LayerAuthority {
    /// Stable lowercase word.
    pub fn word(&self) -> &'static str {
        match self {
            LayerAuthority::Builtin => "builtin",
            LayerAuthority::File => "file",
            LayerAuthority::VerifiedBundle { .. } => "verified-bundle",
        }
    }

    /// Whether this layer passed the signed-bundle verification gate.
    pub fn is_verified(&self) -> bool {
        matches!(self, LayerAuthority::VerifiedBundle { .. })
    }
}

// ── Scope layers ─────────────────────────────────────────────────────────────

/// One resolution layer: a scope, its provenance, its authority, and the
/// (control-stripped) value table it contributes.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeLayer {
    scope: ConfigScope,
    source: Option<PathBuf>,
    authority: LayerAuthority,
    table: toml::Table,
    locks: BTreeMap<String, bool>,
    merge_directives: BTreeMap<String, MergeDirective>,
}

impl ScopeLayer {
    /// The layer's scope.
    pub fn scope(&self) -> ConfigScope {
        self.scope
    }

    /// Where the layer came from (`None` for compiled-in/in-memory layers).
    pub fn source(&self) -> Option<&std::path::Path> {
        self.source.as_deref()
    }

    /// How the layer's authority was established.
    pub fn authority(&self) -> &LayerAuthority {
        &self.authority
    }

    /// The layer's value tree — **without** the `[lock]`/`[merge]` control
    /// tables (they are control metadata, see [`ScopeLayer::locks`] /
    /// [`ScopeLayer::merge_directives`]).
    pub fn table(&self) -> &toml::Table {
        &self.table
    }

    /// Lock entries declared by this layer (`[lock]` table, all `true`).
    pub fn locks(&self) -> &BTreeMap<String, bool> {
        &self.locks
    }

    /// Array-merge directives declared by this layer (`[merge]` table).
    pub fn merge_directives(&self) -> &BTreeMap<String, MergeDirective> {
        &self.merge_directives
    }

    /// Parse + ingest a **file-scope** layer artifact.
    ///
    /// Refused: `system`/`swarm` (`E7027` — use
    /// [`ScopeLayer::from_verified_bundle`]) and the non-file scopes
    /// `defaults`/`profile`/`session` (`E7043`).
    pub fn parse(
        scope: ConfigScope,
        text: &str,
        source: impl Into<Option<PathBuf>>,
    ) -> Result<Self, ScopeError> {
        let authority = match scope {
            ConfigScope::System | ConfigScope::Swarm => {
                return Err(ScopeError::AuthorityRequired { scope });
            }
            ConfigScope::Defaults | ConfigScope::Profile => {
                return Err(ScopeError::LayerKind {
                    scope,
                    detail: "`defaults`/`profile` are compiled-in overlays — build them with \
                             `ScopeLayer::builtin_defaults` / `ScopeLayer::from_builtin`"
                        .to_string(),
                });
            }
            ConfigScope::Session => {
                return Err(ScopeError::LayerKind {
                    scope,
                    detail: "`session` overrides come from `--set`/`TALLOW_CONFIG_*` \
                             (`ScopeLayer::session_overrides_from_env`), never a file"
                        .to_string(),
                });
            }
            ConfigScope::User | ConfigScope::Device | ConfigScope::Project | ConfigScope::Agent => {
                LayerAuthority::File
            }
        };
        Self::build(scope, text, source.into(), authority)
    }

    /// Build a layer from an already-parsed table (programmatic callers and
    /// tests). Kernel validation still applies; session/defaults/profile
    /// refuse (use the dedicated constructors); system-class refuses a plain
    /// table (`E7027`).
    pub fn from_table(scope: ConfigScope, table: toml::Table) -> Result<Self, ScopeError> {
        let authority = match scope {
            ConfigScope::System | ConfigScope::Swarm => {
                return Err(ScopeError::AuthorityRequired { scope });
            }
            ConfigScope::Defaults | ConfigScope::Profile => {
                return Err(ScopeError::LayerKind {
                    scope,
                    detail: "use `ScopeLayer::builtin_defaults` / `ScopeLayer::from_builtin`"
                        .to_string(),
                });
            }
            ConfigScope::Session => {
                return Err(ScopeError::LayerKind {
                    scope,
                    detail: "use `ScopeLayer::session_overrides_from_env`".to_string(),
                });
            }
            _ => LayerAuthority::File,
        };
        Self::from_table_with_authority(scope, table, authority)
    }

    /// Build the compiled-in **defaults** layer (§7.2.1 row 0: not a file).
    pub fn builtin_defaults(table: toml::Table) -> Result<Self, ScopeError> {
        Self::from_table_with_authority(ConfigScope::Defaults, table, LayerAuthority::Builtin)
    }

    /// Build a compiled-in overlay for `defaults`/`profile` (the profile
    /// bundle ships with the binary, §7.2.1 row 1).
    pub fn from_builtin(scope: ConfigScope, table: toml::Table) -> Result<Self, ScopeError> {
        match scope {
            ConfigScope::Defaults | ConfigScope::Profile => {
                Self::from_table_with_authority(scope, table, LayerAuthority::Builtin)
            }
            other => Err(ScopeError::LayerKind {
                scope: other,
                detail: "builtin overlays exist only for `defaults`/`profile`".to_string(),
            }),
        }
    }

    /// Build a layer from a **verified** bundle (the only path to a
    /// `system`/`swarm` layer — verify-before-load, R-7.4).
    pub fn from_verified_bundle(
        verified: &VerifiedBundle,
        source: impl Into<Option<PathBuf>>,
    ) -> Result<Self, ScopeError> {
        Self::build(
            verified.scope,
            &verified.config_toml,
            source.into(),
            LayerAuthority::VerifiedBundle {
                signer: verified.signer.clone(),
                key_id: verified.key_id.clone(),
            },
        )
    }

    fn from_table_with_authority(
        scope: ConfigScope,
        mut table: toml::Table,
        authority: LayerAuthority,
    ) -> Result<Self, ScopeError> {
        if authority == LayerAuthority::Builtin {
            stamp_builtin_version(&mut table);
        }
        let text = toml::to_string_pretty(&table).map_err(|e| ScopeError::LayerKind {
            scope,
            detail: format!("layer table could not be serialized for validation: {e}"),
        })?;
        Self::build(scope, &text, None, authority)
    }

    fn build(
        scope: ConfigScope,
        text: &str,
        source: Option<PathBuf>,
        authority: LayerAuthority,
    ) -> Result<Self, ScopeError> {
        // 1. Kernel gate: the layer is a kernel artifact. Core/secrets
        //    findings refuse it (`E7043`) — precedent: unknown keys, type
        //    mismatches, literal secrets. Foreign tables pass through.
        let loaded = load::load_from_str(text, source.clone());
        if loaded.file_error().is_some()
            || !loaded.core_result().is_valid()
            || !loaded.secrets_result().is_valid()
        {
            let diagnostics: Vec<ConfigDiagnostic> = loaded
                .diagnostics()
                .iter()
                .filter(|d| !matches!(d.section, ConfigSection::Other(_)))
                .cloned()
                .collect();
            return Err(ScopeError::LayerRefused {
                scope,
                source,
                diagnostics,
            });
        }

        let mut table: toml::Table = match toml::from_str(text) {
            Ok(t) => t,
            Err(e) => {
                return Err(ScopeError::LayerRefused {
                    scope,
                    source,
                    diagnostics: vec![ConfigDiagnostic::new(
                        crate::config::schema::CODE_ARTIFACT,
                        ConfigSection::File,
                        None,
                        format!("layer is not valid TOML: {}", e.message()),
                    )],
                });
            }
        };

        // 2. Control tables are metadata, not config: strip + validate.
        let (locks, merge_directives) = take_control_tables(scope, &mut table)?;

        Ok(ScopeLayer {
            scope,
            source,
            authority,
            table,
            locks,
            merge_directives,
        })
    }

    /// Test-only constructor for verified system-class layers (production
    /// callers go through [`ScopeLayer::from_verified_bundle`]).
    #[cfg(test)]
    pub(crate) fn verified_for_test(
        scope: ConfigScope,
        text: &str,
    ) -> Result<Self, ScopeError> {
        Self::build(
            scope,
            text,
            None,
            LayerAuthority::VerifiedBundle {
                signer: "test-signer".to_string(),
                key_id: "test-key".to_string(),
            },
        )
    }
}

/// Strip + validate the `[lock]`/`[merge]` control tables (`§7.2.1`/`§7.2.2`).
fn take_control_tables(
    scope: ConfigScope,
    table: &mut toml::Table,
) -> Result<(BTreeMap<String, bool>, BTreeMap<String, MergeDirective>), ScopeError> {
    let mut locks = BTreeMap::new();
    if let Some(value) = table.remove("lock") {
        let entries = value.as_table().ok_or_else(|| ScopeError::InvalidControl {
            table: "lock",
            path: None,
            origin: scope,
            detail: "`[lock]` must be a table of `\"key.path\" = true` entries".to_string(),
        })?;
        for (key, entry) in entries.iter() {
            if key.is_empty() || key.contains(' ') {
                return Err(ScopeError::InvalidControl {
                    table: "lock",
                    path: Some(key.clone()),
                    origin: scope,
                    detail: "lock keys are non-empty dotted key paths".to_string(),
                });
            }
            match entry {
                Value::Boolean(true) => {
                    locks.insert(key.clone(), true);
                }
                other => {
                    return Err(ScopeError::InvalidControl {
                        table: "lock",
                        path: Some(key.clone()),
                        origin: scope,
                        detail: format!(
                            "lock entries are declared `true` (remove the entry to unlock); found {}",
                            kind_word(other)
                        ),
                    });
                }
            }
        }
    }

    let mut merge_directives = BTreeMap::new();
    if let Some(value) = table.remove("merge") {
        let entries = value.as_table().ok_or_else(|| ScopeError::InvalidControl {
            table: "merge",
            path: None,
            origin: scope,
            detail: "`[merge]` must be a table of `\"key.path\" = \"append\"` entries".to_string(),
        })?;
        for (key, entry) in entries.iter() {
            if key.is_empty() || key.contains(' ') {
                return Err(ScopeError::InvalidControl {
                    table: "merge",
                    path: Some(key.clone()),
                    origin: scope,
                    detail: "merge keys are non-empty dotted key paths".to_string(),
                });
            }
            let word = entry.as_str().ok_or_else(|| ScopeError::InvalidControl {
                table: "merge",
                path: Some(key.clone()),
                origin: scope,
                detail: format!(
                    "merge directives are string words (`\"append\"`); found {}",
                    kind_word(entry)
                ),
            })?;
            match MergeDirective::parse(word) {
                Some(d) => {
                    merge_directives.insert(key.clone(), d);
                }
                None => {
                    return Err(ScopeError::InvalidControl {
                        table: "merge",
                        path: Some(key.clone()),
                        origin: scope,
                        detail: format!(
                            "unknown merge directive `{word}` — the only opt-in is `append` \
                             (arrays replace by default; §7.2.2)"
                        ),
                    });
                }
            }
        }
    }

    Ok((locks, merge_directives))
}

/// Compiled-in / env-sourced layers are version-stamped by the kernel (they
/// are not file artifacts and do not carry their own `schema_version`); file
/// and bundle layers must carry it themselves.
fn stamp_builtin_version(table: &mut toml::Table) {
    table
        .entry(SCHEMA_VERSION_KEY.to_string())
        .or_insert(Value::Integer(SCHEMA_VERSION as i64));
}

/// Human kind word for a TOML value (never its content — mirrors the kernel's
/// `describe_value`).
pub(crate) fn kind_word(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "a string",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Boolean(_) => "a boolean",
        Value::Datetime(_) => "a datetime",
        Value::Array(_) => "an array",
        Value::Table(_) => "a table",
    }
}

// ── Lock table ───────────────────────────────────────────────────────────────

/// The resolved lock table: key path → the system-class scope that locked it.
/// Locks are orthogonal to precedence — the lock origin wins over every later
/// scope (§7.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockTable {
    locks: BTreeMap<String, ConfigScope>,
}

impl LockTable {
    /// Collect the lock table from a layer set. A lock declared outside a
    /// system-class scope is **refused** (`E7041`), never ignored. When
    /// several system-class layers lock the same key, the last one in input
    /// order owns it.
    pub fn from_layers(layers: &[ScopeLayer]) -> Result<Self, ScopeError> {
        let mut locks: BTreeMap<String, ConfigScope> = BTreeMap::new();
        for layer in layers {
            for key in layer.locks().keys() {
                if !is_system_class(layer.scope()) {
                    return Err(ScopeError::LockOrigin {
                        key: key.clone(),
                        origin: layer.scope(),
                    });
                }
                locks.insert(key.clone(), layer.scope());
            }
        }
        Ok(LockTable { locks })
    }

    /// The scope that locked `key`, if any.
    pub fn locked_by(&self, key: &str) -> Option<ConfigScope> {
        self.locks.get(key).copied()
    }

    /// Every lock, deterministically ordered by key path.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ConfigScope)> {
        self.locks.iter()
    }

    /// Number of locks.
    pub fn len(&self) -> usize {
        self.locks.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }
}

impl fmt::Display for LockTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} lock(s)", self.locks.len())
    }
}

// ── Scope discovery (§7.2.1 locations) ───────────────────────────────────────

/// The proposed config artifact paths for a file-backed scope (§7.2.1
/// "location" column). `defaults`/`profile` (compiled-in) and `session`
/// (env-sourced) return an empty list. A missing platform config directory
/// is `E7012` — never a `"."` fallback.
pub fn scope_layer_paths(
    scope: ConfigScope,
    agent: Option<&str>,
) -> Result<Vec<PathBuf>, ConfigError> {
    let base = |what: &str| -> Result<PathBuf, ConfigError> {
        dirs::config_dir().ok_or_else(|| ConfigError::PathUnresolved {
            what: what.to_string(),
        })
    };
    Ok(match scope {
        ConfigScope::Defaults | ConfigScope::Profile | ConfigScope::Session => Vec::new(),
        ConfigScope::System => vec![
            PathBuf::from("/etc/tallow/config.toml"),
            PathBuf::from("/etc/tallow/conf.d"),
        ],
        ConfigScope::User => vec![base("user config directory")?
            .join(load::CONFIG_DIR_NAME)
            .join(load::CONFIG_FILE_NAME)],
        ConfigScope::Device => vec![base("user config directory")?
            .join(load::CONFIG_DIR_NAME)
            .join("config.d")
            .join("device.toml")],
        ConfigScope::Project => vec![
            PathBuf::from("tallow.toml"),
            PathBuf::from(".tallow/config.toml"),
        ],
        ConfigScope::Agent => {
            let name = agent.ok_or_else(|| ConfigError::PathUnresolved {
                what: "agent name (required for the `agent` scope path)".to_string(),
            })?;
            if name.is_empty() || name.contains('/') || name.contains("..") {
                return Err(ConfigError::PathUnresolved {
                    what: format!("agent name `{name}` is not a plain file name component"),
                });
            }
            vec![base("user config directory")?
                .join(load::CONFIG_DIR_NAME)
                .join("config.d")
                .join("agents")
                .join(format!("{name}.toml"))]
        }
        ConfigScope::Swarm => vec![base("user config directory")?
            .join(load::CONFIG_DIR_NAME)
            .join("config.d")
            .join("swarm.toml")],
    })
}

/// Build a `session` layer table from `TALLOW_CONFIG_<KEY>` environment
/// entries (§7.2.1 row 8: `--set key=value` / `TALLOW_CONFIG_<KEY>`).
///
/// Rules (fail-closed, no guessing): the name must be exactly
/// `TALLOW_CONFIG_` + a non-empty key suffix; the suffix is lowercased into
/// the key. The value is parsed as a TOML scalar when it parses; otherwise it
/// stays a **string** (that is not coercion — a string that does not
/// type-match the schema is still refused by the kernel gate, §7.2.2). An
/// empty value is refused (`E7044`).
pub fn session_overrides_from_env<I>(vars: I) -> Result<toml::Table, ScopeError>
where
    I: IntoIterator<Item = (String, String)>,
{
    const PREFIX: &str = "TALLOW_CONFIG_";
    let mut table = toml::Table::new();
    for (name, raw) in vars {
        let Some(suffix) = name.strip_prefix(PREFIX) else {
            continue;
        };
        if suffix.is_empty() {
            return Err(ScopeError::SessionOverride {
                name,
                detail: "missing key suffix (expected `TALLOW_CONFIG_<KEY>`)".to_string(),
            });
        }
        if raw.trim().is_empty() {
            return Err(ScopeError::SessionOverride {
                name,
                detail: "empty value — session overrides are explicit, never a silent unset"
                    .to_string(),
            });
        }
        let key = suffix.to_ascii_lowercase();
        // Parse as a TOML value when possible; otherwise keep the raw string.
        let parsed = toml::from_str::<toml::Table>(&format!("v = {}", raw.trim()))
            .ok()
            .and_then(|mut t| t.remove("v"))
            .unwrap_or_else(|| Value::String(raw.trim().to_string()));
        // `__` separates nested key segments (env names cannot carry dots).
        insert_dotted(&mut table, &key, parsed);
    }
    Ok(table)
}

/// Insert `value` at a `__`-separated dotted key path, creating intermediate
/// tables.
fn insert_dotted(table: &mut toml::Table, key: &str, value: Value) {
    let mut segments = key.split("__").peekable();
    let mut current = table;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            current.insert(segment.to_string(), value);
            return;
        }
        let entry = current
            .entry(segment.to_string())
            .or_insert_with(|| Value::Table(toml::Table::new()));
        match entry {
            Value::Table(t) => current = t,
            _ => {
                // A scalar already sits at this prefix: refuse to guess a
                // shape — drop the nested insert (the kernel gate refuses
                // the resulting layer anyway).
                return;
            }
        }
    }
}

impl ScopeLayer {
    /// Build the `session` layer from `TALLOW_CONFIG_<KEY>` environment
    /// entries (see [`session_overrides_from_env`]). The returned layer is
    /// `Builtin`-authority (env-sourced, no file).
    pub fn session_layer<I>(vars: I) -> Result<Self, ScopeError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut table = session_overrides_from_env(vars)?;
        stamp_builtin_version(&mut table);
        Self::build(
            ConfigScope::Session,
            &serialize_table(&table)?,
            None,
            LayerAuthority::Builtin,
        )
    }
}

fn serialize_table(table: &toml::Table) -> Result<String, ScopeError> {
    toml::to_string_pretty(table).map_err(|e| ScopeError::SessionOverride {
        name: "<session table>".to_string(),
        detail: format!("could not serialize session overrides for validation: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(scope: ConfigScope, text: &str) -> ScopeLayer {
        ScopeLayer::parse(scope, text, None).expect("layer parses")
    }

    #[test]
    fn ladder_order_monotonic_and_swarm_is_system_class() {
        // Everything on the R-7.2 ladder appears exactly once, ascending.
        for pair in APPLICATION_ORDER.windows(2) {
            assert!(ladder_index(pair[0]) < ladder_index(pair[1]), "{pair:?}");
        }
        assert_eq!(ladder_index(ConfigScope::Defaults), 0);
        assert_eq!(ladder_index(ConfigScope::Session), 8);
        // rank(): the R-7.2 precedence numbers with swarm sharing system's.
        assert_eq!(rank(ConfigScope::Defaults), 0);
        assert_eq!(rank(ConfigScope::System), 2);
        assert_eq!(rank(ConfigScope::Swarm), 2, "swarm is system-class");
        assert_eq!(rank(ConfigScope::User), 3);
        assert_eq!(rank(ConfigScope::Session), 7);
        for pair in LADDER.windows(2) {
            assert!(is_above(pair[1], pair[0]), "{pair:?}");
        }
        assert!(is_above(ConfigScope::System, ConfigScope::Profile));
        assert!(!is_above(ConfigScope::Profile, ConfigScope::System));
        assert_eq!(APPLICATION_ORDER.len(), 9, "ladder + swarm");
    }

    #[test]
    fn parse_scope_words_and_unknown_refusal() {
        for scope in ConfigScope::ALL {
            assert_eq!(parse_scope(scope.word()).expect("known word"), scope);
        }
        for bad in ["root", "User", "global", ""] {
            let err = parse_scope(bad).expect_err("unknown scope refused");
            assert_eq!(err.code(), CODE_SCOPE_UNKNOWN);
            assert!(err.to_string().contains(bad), "{err}");
            assert!(err.to_string().contains("never"), "no guessing: {err}");
        }
    }

    #[test]
    fn system_class_plain_layer_refused_verified_accepted() {
        let text = "schema_version = 1\ntelemetry = false\n";
        for scope in [ConfigScope::System, ConfigScope::Swarm] {
            let err = ScopeLayer::parse(scope, text, None).expect_err("plain system layer refused");
            assert_eq!(err.code(), CODE_SCOPE_UNSIGNED_LOAD, "{err}");
            assert!(err.to_string().contains(scope.word()), "{err}");
        }
        let verified = ScopeLayer::verified_for_test(ConfigScope::System, text).expect("verified");
        assert_eq!(verified.scope(), ConfigScope::System);
        assert!(verified.authority().is_verified());
        assert_eq!(verified.authority().word(), "verified-bundle");
        // Non-system file scopes are plain-file layers.
        let user = layer(ConfigScope::User, text);
        assert_eq!(user.authority(), &LayerAuthority::File);
    }

    #[test]
    fn non_file_scopes_refuse_file_layers() {
        for scope in [ConfigScope::Defaults, ConfigScope::Profile, ConfigScope::Session] {
            let err = ScopeLayer::parse(scope, "schema_version = 1\n", None)
                .expect_err("non-file scope refused");
            assert_eq!(err.code(), CODE_SCOPE_LAYER, "{err}");
            assert!(err.to_string().contains(scope.word()), "{err}");
        }
        // The dedicated constructors work.
        let defaults = ScopeLayer::builtin_defaults(
            toml::from_str("schema_version = 1").unwrap(),
        )
        .expect("builtin defaults");
        assert_eq!(defaults.scope(), ConfigScope::Defaults);
        assert_eq!(defaults.authority(), &LayerAuthority::Builtin);
        let err = ScopeLayer::builtin_defaults(
            toml::from_str("schema_version = 1").unwrap(),
        );
        assert!(err.is_ok());
        let err = ScopeLayer::from_builtin(
            ConfigScope::User,
            toml::from_str("schema_version = 1").unwrap(),
        )
        .expect_err("builtin only for defaults/profile");
        assert_eq!(err.code(), CODE_SCOPE_LAYER);
    }

    #[test]
    fn layer_ingest_refuses_kernel_findings_no_coercion() {
        // String where the schema wants a boolean → E7003 inside E7043.
        let err = ScopeLayer::parse(ConfigScope::User, "schema_version = 1\nno_color = \"yes\"\n", None)
            .expect_err("type mismatch refused at ingest");
        assert_eq!(err.code(), CODE_SCOPE_LAYER);
        let text = err.to_string();
        assert!(text.contains("E7003"), "{text}");
        assert!(text.contains("no_color"), "{text}");
        assert!(text.contains("user"), "{text}");

        // Unknown root key → E7002; missing schema_version → E7004.
        let err = ScopeLayer::parse(ConfigScope::User, "schema_version = 1\ntelemetri = true\n", None)
            .expect_err("unknown key refused");
        assert!(err.to_string().contains("E7002"), "{err}");
        let err = ScopeLayer::parse(ConfigScope::User, "telemetry = false\n", None)
            .expect_err("missing version refused");
        assert!(err.to_string().contains("E7004"), "{err}");

        // Foreign tables pass through (they belong to other subsystems).
        let user = layer(ConfigScope::User, "schema_version = 1\n\n[browser]\nnav_timeout_ms = 10\n");
        assert!(user.table().get("browser").is_some());
    }

    #[test]
    fn control_tables_are_stripped_and_validated() {
        let text = "schema_version = 1\ntelemetry = true\n\n[lock]\n\"telemetry\" = true\n\n[merge]\n\"browser.allow\" = \"append\"\n";
        let system = ScopeLayer::verified_for_test(ConfigScope::System, text).expect("verified");
        assert!(
            system.table().get("lock").is_none() && system.table().get("merge").is_none(),
            "control tables never reach the merged config: {:?}",
            system.table()
        );
        assert_eq!(system.locks().get("telemetry"), Some(&true));
        assert_eq!(
            system.merge_directives().get("browser.allow"),
            Some(&MergeDirective::Append)
        );

        // Lock shape refusals.
        let err = ScopeLayer::verified_for_test(
            ConfigScope::System,
            "schema_version = 1\n[lock]\n\"telemetry\" = \"yes\"\n",
        )
        .expect_err("non-bool lock refused");
        assert_eq!(err.code(), CODE_SCOPE_LOCK, "{err}");
        let err = ScopeLayer::verified_for_test(
            ConfigScope::System,
            "schema_version = 1\n[lock]\n\"a b\" = true\n",
        )
        .expect_err("bad lock key refused");
        assert_eq!(err.code(), CODE_SCOPE_LOCK, "{err}");
        // Merge directive refusals (the only opt-in is `append`).
        let err = ScopeLayer::verified_for_test(
            ConfigScope::System,
            "schema_version = 1\n[merge]\n\"a\" = \"replace\"\n",
        )
        .expect_err("only append is a directive");
        assert_eq!(err.code(), CODE_SCOPE_MERGE, "{err}");
        assert!(err.to_string().contains("append"), "{err}");
    }

    #[test]
    fn lock_origins_must_be_system_class() {
        let system = ScopeLayer::verified_for_test(
            ConfigScope::System,
            "schema_version = 1\ntelemetry = true\n[lock]\n\"telemetry\" = true\n",
        )
        .expect("verified");
        let user = layer(
            ConfigScope::User,
            "schema_version = 1\n\n[lock]\n\"telemetry\" = true\n",
        );
        // System-only: fine.
        let locks = LockTable::from_layers(&[system.clone()]).expect("system locks");
        assert_eq!(locks.locked_by("telemetry"), Some(ConfigScope::System));
        assert_eq!(locks.len(), 1);
        assert!(!locks.is_empty());
        // A user-scope lock is refused, naming the origin.
        let err = LockTable::from_layers(&[system, user]).expect_err("user lock refused");
        assert_eq!(err.code(), CODE_SCOPE_LOCK, "{err}");
        let text = err.to_string();
        assert!(text.contains("user"), "{text}");
        assert!(text.contains("telemetry"), "{text}");
    }

    #[test]
    fn scope_layer_paths_and_session_overrides() {
        // Non-file scopes have no paths.
        for scope in [ConfigScope::Defaults, ConfigScope::Profile, ConfigScope::Session] {
            assert!(scope_layer_paths(scope, None).unwrap().is_empty());
        }
        // System paths per §7.2.1.
        let system = scope_layer_paths(ConfigScope::System, None).unwrap();
        assert_eq!(system[0], PathBuf::from("/etc/tallow/config.toml"));
        assert!(system[1].ends_with("conf.d"));
        // Agent needs a plain name component.
        assert!(scope_layer_paths(ConfigScope::Agent, None).is_err());
        assert!(scope_layer_paths(ConfigScope::Agent, Some("../x")).is_err());
        assert!(scope_layer_paths(ConfigScope::Agent, Some("planner")).unwrap()[0]
            .ends_with("agents/planner.toml"));
        // Project paths are repo-relative.
        let project = scope_layer_paths(ConfigScope::Project, None).unwrap();
        assert_eq!(project, vec![PathBuf::from("tallow.toml"), PathBuf::from(".tallow/config.toml")]);

        // Session env overrides: prefix filter, lowercase key, TOML scalar
        // parse with a string fallback, explicit refusals.
        let table = session_overrides_from_env([
            ("TALLOW_CONFIG_FORMAT".to_string(), "json".to_string()),
            ("TALLOW_CONFIG_NO_COLOR".to_string(), "true".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ])
        .expect("session overrides");
        assert_eq!(table.get("format"), Some(&Value::String("json".to_string())));
        assert_eq!(table.get("no_color"), Some(&Value::Boolean(true)));
        assert!(table.get("path").is_none(), "foreign env vars are ignored");
        let err = session_overrides_from_env([("TALLOW_CONFIG_".to_string(), "x".to_string())])
            .expect_err("empty suffix refused");
        assert_eq!(err.code(), CODE_SCOPE_SESSION, "{err}");
        let err = session_overrides_from_env([("TALLOW_CONFIG_X".to_string(), " ".to_string())])
            .expect_err("empty value refused");
        assert_eq!(err.code(), CODE_SCOPE_SESSION, "{err}");
        // The session layer builds and validates.
        let session = ScopeLayer::session_layer([(
            "TALLOW_CONFIG_NO_COLOR".to_string(),
            "true".to_string(),
        )])
        .expect("session layer");
        assert_eq!(session.scope(), ConfigScope::Session);
    }
}
