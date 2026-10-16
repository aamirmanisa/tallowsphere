//! KB-3 (row #48, R-7.3): config versioning, forward-only migration ladder,
//! mandatory snapshots, staged apply with health check + auto-revert.
//!
//! # Version model
//! The artifact version is the `schema_version` integer (KB-1). For the
//! migrator, an artifact **without** the key is version **0** (pre-versioning
//! legacy); a malformed value (non-integer, negative) is refused (`E7051`). An
//! artifact **newer** than [`SCHEMA_VERSION`] is refused (`E7055` — the
//! downgrade guard, mirroring the loader's `E7004` at the migrator boundary).
//! `migrate_to_current` is the identity (bytes unchanged) on a current artifact.
//!
//! # Forward-only ladder
//! One [`Migrator`] per registered step, always `N -> N+1` ([`MIGRATORS`] is
//! the compiled-in registry; it starts with the trivial v0 -> v1 stamp, as
//! §7.4 rule 2 prescribes). [`validate_registry`] refuses a registry that is
//! not a clean forward ladder (`E7054`). [`plan_ladder`] refuses a target older
//! than the artifact (`E7052` — forward-only; roll back by *revision*, not by
//! version) and refuses a version with no registered path (`E7053` — the
//! ladder never guesses). Every step must leave `schema_version == step.to`
//! (post-condition), and the final text must pass the **strict kernel loader**
//! before it is returned — a migrated artifact is never handed out unvalidated.
//! Migrators edit a [`toml_edit::DocumentMut`], so the rest of the artifact
//! (comments, key order, tables the kernel isolates per D3) survives the
//! migration untouched.
//!
//! # Snapshots (mandatory, fail-closed)
//! A snapshot is a recorded revision ([`capture_snapshot`] wraps the KB-1
//! store at `config-history/<rev>/` with `config.toml` + `meta.toml`, BLAKE3 +
//! monotonic revision). Reading a revision verifies the artifact BLAKE3
//! against the recorded hash ([`revision_content`]) — a tampered/corrupted
//! store refuses to serve (`E7056`). [`restore_snapshot`] is a **byte-faithful
//! atomic replace** (temp file in the same directory + fsync + rename) and is
//! deliberately *loader-independent*: the point of a snapshot is byte
//! fidelity, so a pre-versioning v0 snapshot restores even though the loader
//! refuses v0. [`rollback_to`] is the `tallow config rollback --to <rev>`
//! primitive (same operation, CLI-named).
//!
//! # Staged apply, health check, auto-revert (§7.4 rule 3)
//! [`staged_apply`]: (1) strictly validate the candidate — nothing is written
//! when it is not strictly clean; (2) capture the mandatory pre-apply snapshot
//! of the currently deployed bytes; (3) deploy through the KB-1 staged write
//! ([`write::commit`]: record revision -> atomic replace, both fail-closed);
//! (4) run the caller's **health probe**; (5) healthy -> mark the deployed
//! revision `good` in `<rev>/status.toml`; failing probe -> **auto-revert**:
//! restore the snapshot byte-identically (or remove the file when there was no
//! prior artifact), mark the deployed revision `reverted` (note = probe
//! reason) and emit one `ConfigChange` ledger event (hashes only, never
//! values). A revert is a *safe outcome* ([`HealthOutcome::Reverted`]), not an
//! error; a revert that cannot restore is a loud `E7056`.
//! [`migrate_file`] composes this for the "first load after an upgrade" flow:
//! version checks -> pre-migration snapshot -> ladder -> staged apply with the
//! [`load_probe`] health check, and on migration failure it restores the
//! snapshot and reports [`MigrateError::Reverted`] (`E7058`).
//!
//! # Diff
//! [`diff_revisions`] flattens both verified revisions to dotted keys and
//! produces a deterministic (sorted, `BTreeMap`-driven) `Added`/`Removed`/
//! `Changed` entry list — the `tallow config diff <revA> <revB>` data model.
//!
//! # Codes (KB-3 block, E7050–E7059; E7001–E7099 reserved to this kernel, D5)
//! | code | kind | meaning |
//! |---|---|---|
//! | `E7050` | error | artifact handed to the migrator is not parseable TOML, or the migrated output fails strict validation |
//! | `E7051` | error | `schema_version` present but malformed (non-integer / negative) |
//! | `E7052` | error | refusal of downgrade: requested target older than the artifact (forward-only) |
//! | `E7053` | error | ladder step failed / unknown version with no registered migrator (never guessed) |
//! | `E7054` | error | the migrator registry is not a clean forward ladder (defect guard) |
//! | `E7055` | error | artifact newer than the kernel `SCHEMA_VERSION` — refuse (downgrade guard) |
//! | `E7056` | error | snapshot store failure: capture / verification / restore (fail-closed, byte fidelity) |
//! | `E7057` | error | staged apply refused (invalid candidate, deploy failure) |
//! | `E7058` | error | migration failed and the pre-migration snapshot was restored byte-identically |
//! | `E7059` | error | revision status sidecar (`<rev>/status.toml`) could not be written/read |
//!
//! # Non-goals (this lane)
//! CLI arms (`config rollback --to <rev>`, `config diff <revA> <revB>`,
//! `config migrate [--check]`) are parent-applied — exact patch recorded in
//! `research/tallow-v1/exec/R-08-batch4-H-kb3-migrations.md` §OPEN. Signature on
//! snapshots is the bundle path's business ([`crate::config::bundle`]);
//! `system`/`swarm` scope layers keep the verify-before-load gate.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use toml_edit::DocumentMut;

use crate::config::{load, write};
use crate::config::schema::{SCHEMA_VERSION, SCHEMA_VERSION_KEY};

// ── Diagnostic codes (KB-3 block, E7050–E7059) ───────────────────────────────

/// `E7050` — artifact not parseable as TOML, or the migrated output fails strict validation.
pub const CODE_MIGRATE_ARTIFACT: &str = "E7050";
/// `E7051` — `schema_version` present but malformed (non-integer / negative).
pub const CODE_MIGRATE_VERSION: &str = "E7051";
/// `E7052` — refusal of downgrade (forward-only ladder).
pub const CODE_MIGRATE_DOWNGRADE: &str = "E7052";
/// `E7053` — ladder step failed, or unknown version with no registered migrator.
pub const CODE_MIGRATE_STEP: &str = "E7053";
/// `E7054` — the migrator registry is not a clean forward ladder.
pub const CODE_MIGRATE_REGISTRY: &str = "E7054";
/// `E7055` — artifact newer than the kernel `SCHEMA_VERSION` (downgrade guard).
pub const CODE_MIGRATE_NEWER: &str = "E7055";
/// `E7056` — snapshot store failure (capture / verification / restore).
pub const CODE_MIGRATE_SNAPSHOT: &str = "E7056";
/// `E7057` — staged apply refused.
pub const CODE_MIGRATE_APPLY: &str = "E7057";
/// `E7058` — migration failed; the pre-migration snapshot was restored.
pub const CODE_MIGRATE_REVERTED: &str = "E7058";
/// `E7059` — revision status sidecar failure.
pub const CODE_MIGRATE_STATUS: &str = "E7059";

// ── Typed errors ─────────────────────────────────────────────────────────────

/// Typed KB-3 error. Every variant carries one reserved code; [`MigrateError::code`]
/// returns it and the `Display` form is prefixed with it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrateError {
    /// `E7050` — artifact not parseable as TOML, or the migrated output fails
    /// strict validation (the loader is the final gate).
    #[error("E7050: config migration artifact error: {message}")]
    Artifact {
        /// What failed.
        message: String,
    },

    /// `E7051` — `schema_version` present but malformed.
    #[error("E7051: malformed `schema_version` in the artifact: found {found} (must be a non-negative integer)")]
    Version {
        /// Description of the offending value (never a secret).
        found: String,
    },

    /// `E7052` — refusal of downgrade: forward-only ladder.
    #[error("E7052: refusing downgrade: artifact is schema_version {from}, requested target {to} — migrations are forward-only; roll back by revision (`config rollback --to <rev>`) instead")]
    Downgrade {
        /// The artifact's version.
        from: u32,
        /// The requested target version.
        to: u32,
    },

    /// `E7053` — a ladder step failed (application or post-condition).
    #[error("E7053: migration step `{step}` ({from} -> {to}) failed: {message}")]
    StepFailed {
        /// Registered migrator name.
        step: &'static str,
        /// Step source version.
        from: u32,
        /// Step destination version.
        to: u32,
        /// What failed (application error, or post-condition detail).
        message: String,
    },

    /// `E7053` — unknown version: no registered migrator for this step.
    #[error("E7053: unknown schema_version {from}: no registered migrator for this version (target {target}) — refusing, the ladder never guesses")]
    UnknownVersion {
        /// The artifact's version.
        from: u32,
        /// The requested target version.
        target: u32,
    },

    /// `E7054` — the migrator registry is not a clean forward ladder.
    #[error("E7054: migrator registry is not a clean forward ladder: {detail}")]
    RegistryInvalid {
        /// Registry defect detail.
        detail: String,
    },

    /// `E7055` — artifact newer than the kernel (downgrade guard).
    #[error("E7055: artifact schema_version {found} is newer than this kernel supports ({kernel}) — refusing (downgrade guard; mirrors the loader's E7004)")]
    NewerThanKernel {
        /// The artifact's version.
        found: u32,
        /// The kernel's [`SCHEMA_VERSION`].
        kernel: u32,
    },

    /// `E7056` — snapshot store failure (fail-closed; byte fidelity).
    #[error("E7056: snapshot store failure: {message}")]
    Snapshot {
        /// What failed.
        message: String,
    },

    /// `E7057` — staged apply refused.
    #[error("E7057: staged apply refused: {message}")]
    Apply {
        /// What failed.
        message: String,
    },

    /// `E7058` — migration failed; the pre-migration snapshot was restored.
    #[error("E7058: migration {from} -> {to} failed and the pre-migration snapshot (revision {snapshot_revision}) was restored byte-identically: {reason}")]
    Reverted {
        /// Source version the migration started from.
        from: u32,
        /// Target version it was migrating to.
        to: u32,
        /// Why the ladder failed.
        reason: String,
        /// Revision of the restored pre-migration snapshot.
        snapshot_revision: u64,
    },

    /// `E7059` — revision status sidecar failure.
    #[error("E7059: revision status sidecar failure: {message}")]
    Status {
        /// What failed.
        message: String,
    },
}

impl MigrateError {
    /// The reserved kernel code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            MigrateError::Artifact { .. } => CODE_MIGRATE_ARTIFACT,
            MigrateError::Version { .. } => CODE_MIGRATE_VERSION,
            MigrateError::Downgrade { .. } => CODE_MIGRATE_DOWNGRADE,
            MigrateError::StepFailed { .. } | MigrateError::UnknownVersion { .. } => {
                CODE_MIGRATE_STEP
            }
            MigrateError::RegistryInvalid { .. } => CODE_MIGRATE_REGISTRY,
            MigrateError::NewerThanKernel { .. } => CODE_MIGRATE_NEWER,
            MigrateError::Snapshot { .. } => CODE_MIGRATE_SNAPSHOT,
            MigrateError::Apply { .. } => CODE_MIGRATE_APPLY,
            MigrateError::Reverted { .. } => CODE_MIGRATE_REVERTED,
            MigrateError::Status { .. } => CODE_MIGRATE_STATUS,
        }
    }
}

// ── Version model + registry ─────────────────────────────────────────────────

/// One registered forward migration step (`N -> N+1`).
///
/// The migrator edits the parsed document in place; comments, key order and
/// tables the kernel does not own survive. Its **contract**: leave
/// `schema_version == to` behind (checked as a post-condition by the ladder).
#[derive(Debug, Clone, Copy)]
pub struct Migrator {
    /// Source schema version of the step.
    pub from: u32,
    /// Destination schema version (always `from + 1`).
    pub to: u32,
    /// Stable step name (used in diagnostics; also recorded in
    /// [`Migrated::steps`]).
    pub name: &'static str,
    /// The step itself.
    pub apply: fn(&mut DocumentMut) -> Result<(), MigrateError>,
}

/// The compiled-in forward-only migration registry.
///
/// §7.4 rule 2: "one registered migrator per step (`N → N+1`)"; the registry
/// starts with the trivial v0 -> v1 stamp (versioning itself). Future schema
/// bumps append steps here — never renumber, never add a backward step.
pub static MIGRATORS: &[Migrator] = &[Migrator {
    from: 0,
    to: 1,
    name: "v0-stamp-schema-version",
    apply: stamp_v0_to_v1,
}];

/// The trivial first migration: a pre-versioning artifact (no
/// `schema_version`) gets the stamp.
fn stamp_v0_to_v1(doc: &mut DocumentMut) -> Result<(), MigrateError> {
    set_document_version(doc, 1)
}

/// Read the version of a parsed document: missing key = `0` (pre-versioning
/// legacy), non-integer/negative = `E7051`.
pub fn document_version(doc: &DocumentMut) -> Result<u32, MigrateError> {
    match doc.get(SCHEMA_VERSION_KEY) {
        None => Ok(0),
        Some(item) => match item.as_integer() {
            Some(n) if n >= 0 && n <= i64::from(u32::MAX) => Ok(n as u32),
            Some(n) => Err(MigrateError::Version {
                found: n.to_string(),
            }),
            None => Err(MigrateError::Version {
                found: format!(
                    "a {} — expected an integer",
                    item.type_name()
                ),
            }),
        },
    }
}

/// Read the version of an artifact string (parse + [`document_version`]).
pub fn artifact_version(text: &str) -> Result<u32, MigrateError> {
    let doc: DocumentMut = text.parse().map_err(|e| MigrateError::Artifact {
        message: format!("not parseable as a TOML document: {e}"),
    })?;
    document_version(&doc)
}

/// Stamp `schema_version = version` into a parsed document (in place when the
/// key exists — the rest of the artifact is untouched).
pub fn set_document_version(doc: &mut DocumentMut, version: u32) -> Result<(), MigrateError> {
    doc.as_table_mut()
        .insert(SCHEMA_VERSION_KEY, toml_edit::value(i64::from(version)));
    Ok(())
}

/// Refuse a registry that is not a clean forward ladder: every step must be
/// `N -> N+1` with a non-empty name and a unique source version (`E7054`).
pub fn validate_registry(registry: &[Migrator]) -> Result<(), MigrateError> {
    for (i, step) in registry.iter().enumerate() {
        if step.name.is_empty() {
            return Err(MigrateError::RegistryInvalid {
                detail: format!("migrator #{i} has an empty name"),
            });
        }
        if step.to != step.from + 1 {
            return Err(MigrateError::RegistryInvalid {
                detail: format!(
                    "migrator `{}` is not a single forward step: {} -> {} (must be N -> N+1)",
                    step.name, step.from, step.to
                ),
            });
        }
        if registry[..i].iter().any(|prev| prev.from == step.from) {
            return Err(MigrateError::RegistryInvalid {
                detail: format!(
                    "duplicate source version {} (migrator `{}` duplicates an earlier step)",
                    step.from, step.name
                ),
            });
        }
    }
    Ok(())
}

/// Plan the ladder from `from` to `to` (`E7052` on a downgrade, `E7053` on a
/// version with no registered step).
pub fn plan_ladder(
    registry: &[Migrator],
    from: u32,
    to: u32,
) -> Result<Vec<Migrator>, MigrateError> {
    validate_registry(registry)?;
    if from > to {
        return Err(MigrateError::Downgrade { from, to });
    }
    let mut plan = Vec::new();
    let mut cur = from;
    while cur < to {
        let step = registry
            .iter()
            .find(|m| m.from == cur)
            .ok_or(MigrateError::UnknownVersion { from: cur, target: to })?;
        plan.push(*step);
        cur = step.to;
    }
    Ok(plan)
}

// ── Migration ────────────────────────────────────────────────────────────────

/// Result of a successful (possibly empty) migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrated {
    /// Version the artifact had.
    pub from_version: u32,
    /// Version the artifact now has (the requested target).
    pub to_version: u32,
    /// Step names applied, in order (empty on an already-current artifact).
    pub steps: Vec<&'static str>,
    /// The migrated artifact text (strictly valid; byte-identical to the input
    /// when no step was needed).
    pub text: String,
}

/// Run the ladder over `text` up to `target_version`.
///
/// Refusals: `E7052` (target older than the artifact), `E7053` (unknown
/// version / failing step / post-condition violation), `E7054` (broken
/// registry), `E7055` (artifact newer than the kernel's [`SCHEMA_VERSION`]
/// when that is the target), `E7050` (output that does not pass the strict
/// loader). Never writes anything.
pub fn migrate_text_with(
    text: &str,
    registry: &[Migrator],
    target_version: u32,
) -> Result<Migrated, MigrateError> {
    validate_registry(registry)?;
    let mut doc: DocumentMut = text.parse().map_err(|e| MigrateError::Artifact {
        message: format!("not parseable as a TOML document: {e}"),
    })?;
    let from = document_version(&doc)?;

    if from == target_version {
        return Ok(Migrated {
            from_version: from,
            to_version: from,
            steps: Vec::new(),
            text: text.to_string(),
        });
    }
    if from > target_version {
        if target_version == SCHEMA_VERSION {
            return Err(MigrateError::NewerThanKernel {
                found: from,
                kernel: SCHEMA_VERSION,
            });
        }
        return Err(MigrateError::Downgrade {
            from,
            to: target_version,
        });
    }

    let plan = plan_ladder(registry, from, target_version)?;
    let mut steps = Vec::with_capacity(plan.len());
    for step in &plan {
        (step.apply)(&mut doc).map_err(|e| MigrateError::StepFailed {
            step: step.name,
            from: step.from,
            to: step.to,
            message: e.to_string(),
        })?;
        // Post-condition: applying step N -> N+1 must leave version N+1.
        let after = document_version(&doc)?;
        if after != step.to {
            return Err(MigrateError::StepFailed {
                step: step.name,
                from: step.from,
                to: step.to,
                message: format!(
                    "post-condition violated: schema_version is {after} after the step, expected {}",
                    step.to
                ),
            });
        }
        steps.push(step.name);
    }

    let out = doc.to_string();
    // The loader is the final gate: a migrated artifact the kernel would
    // refuse is never returned (and never deployed). Only in-range targets can
    // be judged by this kernel: a target beyond SCHEMA_VERSION is not this
    // binary's to validate (production always targets SCHEMA_VERSION via
    // `migrate_to_current`).
    if target_version <= SCHEMA_VERSION {
        let verdict = load::load_from_str(&out, None);
        if !verdict.is_strictly_valid() {
            let detail = verdict
                .strict_error()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown strict-validation failure".to_string());
            return Err(MigrateError::Artifact {
                message: format!("migrated output failed strict kernel validation: {detail}"),
            });
        }
    }

    Ok(Migrated {
        from_version: from,
        to_version: target_version,
        steps,
        text: out,
    })
}

/// [`migrate_text_with`] with the compiled-in [`MIGRATORS`] registry and the
/// kernel's current [`SCHEMA_VERSION`] as the target.
pub fn migrate_to_current(text: &str) -> Result<Migrated, MigrateError> {
    migrate_text_with(text, MIGRATORS, SCHEMA_VERSION)
}

// ── Snapshots (revision store + byte-faithful restore) ───────────────────────

/// A captured snapshot: a recorded revision of the config-history store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Monotonic revision number.
    pub revision: u64,
    /// The revision directory written.
    pub dir: PathBuf,
    /// BLAKE3 hash of the snapshot bytes.
    pub blake3: String,
    /// Size in bytes.
    pub bytes: usize,
}

/// Captured bytes of one revision, hash-verified against its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionContent {
    /// Revision number.
    pub revision: u64,
    /// The artifact text exactly as recorded.
    pub text: String,
    /// BLAKE3 hash of `text` (verified equal to the recorded hash).
    pub blake3: String,
}

/// Outcome of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// Revision the bytes were restored from.
    pub revision: u64,
    /// Bytes written to the target.
    pub bytes: usize,
    /// BLAKE3 hash of the restored bytes.
    pub blake3: String,
}

/// Capture `content` as a snapshot revision under `root` (fail-closed: a
/// snapshot that cannot be recorded refuses the operation — `E7056`).
pub fn capture_snapshot(
    root: &Path,
    content: &str,
    source: &Path,
    now_ms: u64,
) -> Result<Snapshot, MigrateError> {
    let record = write::record_revision(root, content, source, None, now_ms).map_err(|e| {
        MigrateError::Snapshot {
            message: format!("cannot record snapshot: {e}"),
        }
    })?;
    Ok(Snapshot {
        revision: record.revision,
        dir: record.dir,
        blake3: record.content_blake3,
        bytes: content.len(),
    })
}

/// Read one revision's artifact, verifying its BLAKE3 against the recorded
/// metadata (tamper/corruption -> `E7056`).
pub fn revision_content(root: &Path, revision: u64) -> Result<RevisionContent, MigrateError> {
    let meta = write::read_revision_meta(root, revision).map_err(|e| MigrateError::Snapshot {
        message: format!("cannot read revision {revision} metadata: {e}"),
    })?;
    let path = write::history_revision_dir(root, revision).join("config.toml");
    let text = fs::read_to_string(&path).map_err(|e| MigrateError::Snapshot {
        message: format!("cannot read revision {revision} artifact {}: {e}", path.display()),
    })?;
    let blake3 = blake3::hash(text.as_bytes()).to_hex().to_string();
    if blake3 != meta.content_blake3 {
        return Err(MigrateError::Snapshot {
            message: format!(
                "revision {revision} artifact hash {blake3} does not match the recorded hash {} \
                 — the store is tampered/corrupted; refusing to serve it",
                meta.content_blake3
            ),
        });
    }
    Ok(RevisionContent {
        revision,
        text,
        blake3,
    })
}

/// Restore one revision to `target`, **byte-identically** (verify -> atomic
/// replace: temp file in the target directory, fsync, rename).
///
/// Loader-independent by design: a snapshot must restore even when the
/// artifact it holds is not loadable by the current kernel (e.g. a
/// pre-versioning v0 snapshot); restoring is byte replay, not a new write.
pub fn restore_snapshot(
    target: &Path,
    root: &Path,
    revision: u64,
) -> Result<Restored, MigrateError> {
    let content = revision_content(root, revision)?;
    atomic_replace_bytes(target, content.text.as_bytes())?;
    Ok(Restored {
        revision,
        bytes: content.text.len(),
        blake3: content.blake3,
    })
}

/// `tallow config rollback --to <rev>` — restore revision `revision` of the
/// store under `root` onto `target` (the CLI arm is a §OPEN patch).
pub fn rollback_to(target: &Path, root: &Path, revision: u64) -> Result<Restored, MigrateError> {
    restore_snapshot(target, root, revision)
}

// ── Revision status sidecar (`mark revision good`) ───────────────────────────

/// Status word of a deployed revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevisionStatusWord {
    /// The post-apply health check passed.
    Good,
    /// The post-apply health check failed and the pre-apply snapshot was
    /// restored.
    Reverted,
}

/// Recorded status of one revision (`<rev>/status.toml`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionStatusRecord {
    /// The status word.
    pub status: RevisionStatusWord,
    /// Unix-ms instant the status was recorded.
    pub at_ms: u64,
    /// Free-form note (never contains config values).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn status_path(root: &Path, revision: u64) -> PathBuf {
    write::history_revision_dir(root, revision).join("status.toml")
}

/// Mark a revision `good`/`reverted` (writes `<rev>/status.toml`, `0600`).
pub fn mark_revision_status(
    root: &Path,
    revision: u64,
    status: RevisionStatusWord,
    at_ms: u64,
    note: Option<&str>,
) -> Result<PathBuf, MigrateError> {
    let record = RevisionStatusRecord {
        status,
        at_ms,
        note: note.map(str::to_string),
    };
    let text = toml::to_string_pretty(&record).map_err(|e| MigrateError::Status {
        message: format!("cannot serialize revision {revision} status: {e}"),
    })?;
    let path = status_path(root, revision);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(MigrateError::Status {
            message: format!(
                "revision {revision} directory {} does not exist (status can only mark recorded revisions)",
                parent.display()
            ),
        });
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(write::CONFIG_FILE_MODE);
    }
    let mut file = options.open(&path).map_err(|e| MigrateError::Status {
        message: format!("cannot write {}: {e}", path.display()),
    })?;
    file.write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| MigrateError::Status {
            message: format!("cannot write {}: {e}", path.display()),
        })?;
    Ok(path)
}

/// Read a revision's status marker (`None` when the revision was never marked).
pub fn read_revision_status(
    root: &Path,
    revision: u64,
) -> Result<Option<RevisionStatusRecord>, MigrateError> {
    let path = status_path(root, revision);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(MigrateError::Status {
                message: format!("cannot read {}: {e}", path.display()),
            })
        }
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| MigrateError::Status {
            message: format!("cannot parse {}: {e}", path.display()),
        })
}

// ── Staged apply + health check + auto-revert ────────────────────────────────

/// Options for [`staged_apply`] / [`migrate_file`].
pub struct ApplyOptions<'a> {
    /// Revision store root (`write::default_history_dir()` in production).
    pub history_root: PathBuf,
    /// Unix file-mode policy for the deployed artifact.
    pub perms: write::FilePermsPolicy,
    /// Ledger seam: deploy + revert events (best-effort, never blocks).
    pub ledger: Option<&'a dyn write::LedgerSink>,
    /// Clock used for snapshot/status timestamps (injectable for tests).
    pub now_ms: u64,
}

impl<'a> ApplyOptions<'a> {
    /// Production posture: the D6 history root given by the caller, `0600`
    /// perms, the default journal ledger, wall-clock timestamps.
    pub fn at(history_root: impl Into<PathBuf>) -> Self {
        ApplyOptions {
            history_root: history_root.into(),
            perms: write::FilePermsPolicy::OwnerOnlyAlways,
            ledger: Some(&write::DEFAULT_LEDGER),
            now_ms: unix_ms_now(),
        }
    }

    /// Silence the ledger seam (unit paths / tests).
    pub fn without_ledger(mut self) -> Self {
        self.ledger = None;
        self
    }

    /// Attach an explicit ledger sink.
    pub fn with_ledger(mut self, sink: &'a dyn write::LedgerSink) -> Self {
        self.ledger = Some(sink);
        self
    }

    /// Fix the clock (deterministic tests).
    pub fn with_now_ms(mut self, now_ms: u64) -> Self {
        self.now_ms = now_ms;
        self
    }

    /// File-mode policy for the deployed artifact.
    pub fn with_perms(mut self, perms: write::FilePermsPolicy) -> Self {
        self.perms = perms;
        self
    }
}

/// Verdict of the post-apply health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthOutcome {
    /// The probe passed; the deployed revision is marked `good`.
    Healthy,
    /// The probe failed and the pre-apply state was restored byte-identically
    /// (or removed, when there was no prior artifact).
    Reverted {
        /// Probe failure reason.
        reason: String,
        /// Revision the bytes were restored from (`None`: no prior artifact —
        /// the deployed file was removed).
        restored_from: Option<u64>,
        /// Bytes restored.
        restored_bytes: usize,
    },
}

/// Outcome of a staged apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The deployed config file.
    pub target: PathBuf,
    /// Revision recorded for the deployed candidate.
    pub revision: u64,
    /// BLAKE3 hash of the candidate as deployed.
    pub deployed_blake3: String,
    /// Size in bytes of the candidate as deployed.
    pub deployed_bytes: usize,
    /// The mandatory pre-apply snapshot revision (`None`: no prior artifact).
    pub snapshot_revision: Option<u64>,
    /// Health verdict (and revert details when one happened).
    pub health: HealthOutcome,
}

/// Staged apply with a post-apply health check and auto-revert (§7.4 rule 3).
///
/// See the module docs for the exact order of operations. The `health` probe
/// is a caller-supplied closure (production: [`load_probe`]; the doctor probe
/// and daemon `/health` land with their own waves) returning `Err(reason)` to
/// force the revert.
pub fn staged_apply(
    target: &Path,
    candidate: &str,
    health: impl FnOnce() -> Result<(), String>,
    opts: &ApplyOptions<'_>,
) -> Result<ApplyOutcome, MigrateError> {
    let snapshot = capture_current_snapshot(target, opts)?;
    deploy_staged(target, candidate, health, opts, snapshot)
}

/// The pre-apply snapshot of the currently deployed artifact (`None` when the
/// target does not exist). Fail-closed: a snapshot that cannot be captured
/// refuses the apply (`E7056`).
fn capture_current_snapshot(
    target: &Path,
    opts: &ApplyOptions<'_>,
) -> Result<Option<Snapshot>, MigrateError> {
    match fs::read_to_string(target) {
        Ok(bytes) => Ok(Some(capture_snapshot(
            &opts.history_root,
            &bytes,
            target,
            opts.now_ms,
        )?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(MigrateError::Snapshot {
            message: format!("cannot read {} for the pre-apply snapshot: {e}", target.display()),
        }),
    }
}

/// Steps 1 + 3 + 4 + 5 of the staged apply, with the snapshot supplied by the
/// caller (so [`migrate_file_with`] can reuse its pre-migration snapshot as
/// the recovery anchor instead of recording a duplicate revision).
fn deploy_staged(
    target: &Path,
    candidate: &str,
    health: impl FnOnce() -> Result<(), String>,
    opts: &ApplyOptions<'_>,
    snapshot: Option<Snapshot>,
) -> Result<ApplyOutcome, MigrateError> {
    // 1. The candidate must be strictly clean under the kernel loader:
    //    nothing is written when it is not.
    let verdict = load::load_from_str(candidate, Some(target.to_path_buf()));
    if !verdict.is_strictly_valid() {
        let detail = verdict
            .strict_error()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown strict-validation failure".to_string());
        return Err(MigrateError::Apply {
            message: format!("candidate artifact failed strict kernel validation: {detail}"),
        });
    }

    // 3. Deploy through the KB-1 staged write: record revision -> atomic
    //    replace, both fail-closed (an accepted write is never unrecorded).
    let write_opts = write::WriteOptions {
        history: write::HistoryPolicy::At(opts.history_root.clone()),
        perms: opts.perms,
        ledger: opts.ledger,
    };
    let commit_outcome =
        write::commit(target, candidate, &write_opts).map_err(|e| MigrateError::Apply {
            message: format!("deploy failed: {e}"),
        })?;
    let revision = commit_outcome
        .revision
        .ok_or_else(|| MigrateError::Apply {
            message: "internal: the deploy recorded no revision".to_string(),
        })?;

    // 4. Health check.
    match health() {
        Ok(()) => {
            // 5a. Mark revision good (best-effort bookkeeping: the deploy is
            //     healthy — a marker failure is a warning, not a revert).
            if let Err(e) = mark_revision_status(
                &opts.history_root,
                revision,
                RevisionStatusWord::Good,
                opts.now_ms,
                None,
            ) {
                tracing::warn!("config migration: revision {revision} marked-good write failed: {e}");
            }
            Ok(ApplyOutcome {
                target: target.to_path_buf(),
                revision,
                deployed_blake3: commit_outcome.content_blake3,
                deployed_bytes: commit_outcome.bytes,
                snapshot_revision: snapshot.as_ref().map(|s| s.revision),
                health: HealthOutcome::Healthy,
            })
        }
        Err(reason) => {
            // 5b. Auto-revert: restore the pre-apply state byte-identically
            //     (or remove the file when there was no prior artifact).
            let (restored_from, restored_bytes, restored_blake3) = match &snapshot {
                Some(snapshot) => {
                    let restored =
                        restore_snapshot(target, &opts.history_root, snapshot.revision)?;
                    (
                        Some(restored.revision),
                        restored.bytes,
                        restored.blake3,
                    )
                }
                None => {
                    fs::remove_file(target).map_err(|e| MigrateError::Snapshot {
                        message: format!(
                            "auto-revert could not remove {} (no prior artifact): {e}",
                            target.display()
                        ),
                    })?;
                    (None, 0, blake3::hash(b"").to_hex().to_string())
                }
            };

            let note = format!(
                "auto-revert: health check failed after deploying revision {revision}: {reason}"
            );
            if let Err(e) = mark_revision_status(
                &opts.history_root,
                revision,
                RevisionStatusWord::Reverted,
                opts.now_ms,
                Some(&note),
            ) {
                tracing::warn!(
                    "config migration: revision {revision} marked-reverted write failed: {e}"
                );
            }
            if let Some(sink) = opts.ledger {
                let event = write::ConfigWriteEvent {
                    path: target.to_path_buf(),
                    bytes: restored_bytes,
                    revision: restored_from,
                    content_blake3: restored_blake3,
                };
                if let Err(e) = sink.record_config_write(&event) {
                    tracing::debug!(
                        "config migration revert ledger seam (best-effort): {e}"
                    );
                }
            }
            Ok(ApplyOutcome {
                target: target.to_path_buf(),
                revision,
                deployed_blake3: commit_outcome.content_blake3,
                deployed_bytes: commit_outcome.bytes,
                snapshot_revision: snapshot.as_ref().map(|s| s.revision),
                health: HealthOutcome::Reverted {
                    reason,
                    restored_from,
                    restored_bytes,
                },
            })
        }
    }
}

/// The default post-apply health probe: the deployed artifact must strictly
/// load under the current kernel and carry the current [`SCHEMA_VERSION`].
pub fn load_probe(target: &Path) -> Result<(), String> {
    let text = fs::read_to_string(target)
        .map_err(|e| format!("cannot read {}: {e}", target.display()))?;
    let verdict = load::load_from_str(&text, Some(target.to_path_buf()));
    match verdict.into_strict() {
        Ok(cfg) if cfg.schema_version == SCHEMA_VERSION => Ok(()),
        Ok(cfg) => Err(format!(
            "deployed artifact carries schema_version {} (expected {SCHEMA_VERSION})",
            cfg.schema_version
        )),
        Err(e) => Err(format!("post-apply strict load failed: {e}")),
    }
}

// ── File-level migration (first load after an upgrade) ───────────────────────

/// Outcome of [`migrate_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMigration {
    /// No config artifact exists — nothing to migrate (defaults apply).
    NoArtifact,
    /// The artifact is already at the target version (no-op).
    AlreadyCurrent {
        /// The artifact's (current) version.
        version: u32,
    },
    /// The artifact was migrated and deployed (or migrated then auto-reverted
    /// by the health check — see `outcome.health`).
    Migrated {
        /// Version the artifact had.
        from_version: u32,
        /// Version it now has.
        to_version: u32,
        /// Step names applied, in order.
        steps: Vec<&'static str>,
        /// Staged-apply outcome (health verdict included).
        outcome: ApplyOutcome,
    },
}

/// [`migrate_file_with`] with the compiled-in registry and the kernel's
/// current [`SCHEMA_VERSION`].
pub fn migrate_file(
    target: &Path,
    opts: &ApplyOptions<'_>,
) -> Result<FileMigration, MigrateError> {
    migrate_file_with(target, MIGRATORS, SCHEMA_VERSION, opts)
}

/// Migrate the artifact at `target` forward to `target_version` and deploy it
/// through the staged path (§7.4 rule 2: "run at first load after an upgrade").
///
/// Order: version checks -> **mandatory pre-migration snapshot** -> ladder
/// (compute-only, strict-loader gated) -> staged apply with the [`load_probe`]
/// health check. A migration failure restores the snapshot and reports
/// [`MigrateError::Reverted`] (`E7058`); a failing post-apply probe is handled
/// by the staged apply's auto-revert ([`HealthOutcome::Reverted`]).
pub fn migrate_file_with(
    target: &Path,
    registry: &[Migrator],
    target_version: u32,
    opts: &ApplyOptions<'_>,
) -> Result<FileMigration, MigrateError> {
    let text = match fs::read_to_string(target) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileMigration::NoArtifact)
        }
        Err(e) => {
            return Err(MigrateError::Artifact {
                message: format!("cannot read {}: {e}", target.display()),
            })
        }
    };

    let from = artifact_version(&text)?;
    if from == target_version {
        return Ok(FileMigration::AlreadyCurrent { version: from });
    }
    if from > target_version {
        if target_version == SCHEMA_VERSION {
            return Err(MigrateError::NewerThanKernel {
                found: from,
                kernel: SCHEMA_VERSION,
            });
        }
        return Err(MigrateError::Downgrade {
            from,
            to: target_version,
        });
    }

    // Mandatory pre-migration snapshot, before the ladder runs (fail-closed).
    let snapshot = capture_snapshot(&opts.history_root, &text, target, opts.now_ms)?;

    let migrated = match migrate_text_with(&text, registry, target_version) {
        Ok(migrated) => migrated,
        Err(error) => {
            // Restore byte-identically. (When the ladder failed before any
            // deploy — the only path today — this is a verified no-op that
            // still proves the recovery anchor; the deploy below never ran.)
            let restored = restore_snapshot(target, &opts.history_root, snapshot.revision)?;
            if let Some(sink) = opts.ledger {
                let event = write::ConfigWriteEvent {
                    path: target.to_path_buf(),
                    bytes: restored.bytes,
                    revision: Some(restored.revision),
                    content_blake3: restored.blake3,
                };
                if let Err(e) = sink.record_config_write(&event) {
                    tracing::debug!(
                        "config migration restore ledger seam (best-effort): {e}"
                    );
                }
            }
            return Err(MigrateError::Reverted {
                from,
                to: target_version,
                reason: error.to_string(),
                snapshot_revision: snapshot.revision,
            });
        }
    };

    // The pre-migration snapshot doubles as the pre-apply recovery anchor —
    // one anchor, no duplicate revision.
    let outcome = deploy_staged(
        target,
        &migrated.text,
        || load_probe(target),
        opts,
        Some(snapshot),
    )?;
    Ok(FileMigration::Migrated {
        from_version: from,
        to_version: target_version,
        steps: migrated.steps,
        outcome,
    })
}

// ── Diff ─────────────────────────────────────────────────────────────────────

/// One key-level change between two revisions.
#[derive(Debug, Clone, PartialEq)]
pub enum DiffChange {
    /// Key present only in the newer revision.
    Added {
        /// The added value.
        value: toml::Value,
    },
    /// Key present only in the older revision.
    Removed {
        /// The removed value.
        value: toml::Value,
    },
    /// Key present in both with different values.
    Changed {
        /// Older value.
        from: toml::Value,
        /// Newer value.
        to: toml::Value,
    },
}

/// A key-level diff entry (dotted key path + change).
#[derive(Debug, Clone, PartialEq)]
pub struct DiffEntry {
    /// Dotted key path (deterministic, sorted).
    pub key: String,
    /// What changed.
    pub change: DiffChange,
}

/// Deterministic diff between two recorded revisions (§7.4 rule 3:
/// `tallow config diff <revA> <revB>`).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigDiff {
    /// Older revision.
    pub from: u64,
    /// Newer revision.
    pub to: u64,
    /// Entries, sorted by key (empty when the revisions are equivalent).
    pub entries: Vec<DiffEntry>,
}

impl ConfigDiff {
    /// True when the two revisions carry equivalent key/value sets.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stable human-readable rendering (the CLI text form).
    pub fn render(&self) -> String {
        if self.entries.is_empty() {
            return format!(
                "revision {} -> {}: no changes",
                self.from, self.to
            );
        }
        let mut out = format!(
            "revision {} -> {}: {} change(s)\n",
            self.from,
            self.to,
            self.entries.len()
        );
        for entry in &self.entries {
            match &entry.change {
                DiffChange::Added { value } => {
                    out.push_str(&format!("+ {} = {}\n", entry.key, value))
                }
                DiffChange::Removed { value } => {
                    out.push_str(&format!("- {} = {}\n", entry.key, value))
                }
                DiffChange::Changed { from, to } => {
                    out.push_str(&format!("~ {}: {} -> {}\n", entry.key, from, to))
                }
            }
        }
        out
    }
}

/// Diff two revisions of the store under `root` (both hash-verified; `E7056`
/// on a tampered store, `E7050` on an unparseable revision).
pub fn diff_revisions(root: &Path, from: u64, to: u64) -> Result<ConfigDiff, MigrateError> {
    let old = revision_content(root, from)?;
    let new = revision_content(root, to)?;
    let old_table: toml::Table = toml::from_str(&old.text).map_err(|e| MigrateError::Artifact {
        message: format!("revision {from} is not parseable TOML: {e}"),
    })?;
    let new_table: toml::Table = toml::from_str(&new.text).map_err(|e| MigrateError::Artifact {
        message: format!("revision {to} is not parseable TOML: {e}"),
    })?;

    let mut old_flat = BTreeMap::new();
    let mut new_flat = BTreeMap::new();
    flatten_table("", &old_table, &mut old_flat);
    flatten_table("", &new_table, &mut new_flat);

    let mut entries = Vec::new();
    for (key, old_value) in &old_flat {
        match new_flat.get(key) {
            None => entries.push(DiffEntry {
                key: key.clone(),
                change: DiffChange::Removed {
                    value: old_value.clone(),
                },
            }),
            Some(new_value) if new_value != old_value => entries.push(DiffEntry {
                key: key.clone(),
                change: DiffChange::Changed {
                    from: old_value.clone(),
                    to: new_value.clone(),
                },
            }),
            Some(_) => {}
        }
    }
    for (key, new_value) in &new_flat {
        if !old_flat.contains_key(key) {
            entries.push(DiffEntry {
                key: key.clone(),
                change: DiffChange::Added {
                    value: new_value.clone(),
                },
            });
        }
    }
    // `old_flat` is sorted; appended `Added` rows come after `Removed`/
    // `Changed` rows. Re-sort for one deterministic order across both passes.
    entries.sort_by(|a, b| a.key.cmp(&b.key));

    Ok(ConfigDiff { from, to, entries })
}

/// Flatten a TOML table to dotted key -> leaf value (empty tables stay leaves).
fn flatten_table(prefix: &str, table: &toml::Table, out: &mut BTreeMap<String, toml::Value>) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::Table(inner) if !inner.is_empty() => {
                flatten_table(&path, inner, out);
            }
            other => {
                out.insert(path, other.clone());
            }
        }
    }
}

// ── Internals ────────────────────────────────────────────────────────────────

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Atomic byte-faithful replace: temp file in the target directory (`O_EXCL`,
/// `0600`), fsync, rename over the target, fsync the directory.
///
/// Mirrors the KB-1 staging discipline ([`write::commit`]) on purpose, but is
/// deliberately **not** routed through the loader: a snapshot restore is byte
/// replay and must not be gatekept by the schema of the day.
fn atomic_replace_bytes(target: &Path, bytes: &[u8]) -> Result<(), MigrateError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(write::KERNEL_DIR_MODE)
                .create(parent)
                .map_err(|e| MigrateError::Snapshot {
                    message: format!("cannot create {}: {e}", parent.display()),
                })?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent).map_err(|e| MigrateError::Snapshot {
                message: format!("cannot create {}: {e}", parent.display()),
            })?;
        }
    }

    let file_name = target.file_name().ok_or_else(|| MigrateError::Snapshot {
        message: format!("restore target {} has no file name", target.display()),
    })?;
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{n}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let write_result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(write::CONFIG_FILE_MODE);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(MigrateError::Snapshot {
            message: format!("staging the restore for {} failed: {e}", target.display()),
        });
    }
    if let Err(e) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(MigrateError::Snapshot {
            message: format!("restore rename over {} failed: {e}", target.display()),
        });
    }
    #[cfg(unix)]
    {
        if let Ok(dir_file) = File::open(parent) {
            let _ = dir_file.sync_all();
        }
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const V0_LEGACY: &str = "telemetry = true\nno_color = false\n";
    const CURRENT: &str = "schema_version = 1\ntelemetry = true\nno_color = false\n";

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<write::ConfigWriteEvent>>,
    }

    impl write::LedgerSink for RecordingSink {
        fn record_config_write(&self, ev: &write::ConfigWriteEvent) -> Result<(), String> {
            self.events.lock().expect("lock").push(ev.clone());
            Ok(())
        }
    }

    fn opts_at(dir: &Path) -> ApplyOptions<'static> {
        ApplyOptions::at(dir.to_path_buf())
            .without_ledger()
            .with_now_ms(1_700_000_000_000)
    }

    fn opts_with_sink<'a>(dir: &Path, sink: &'a dyn write::LedgerSink) -> ApplyOptions<'a> {
        ApplyOptions::at(dir.to_path_buf())
            .with_ledger(sink)
            .with_now_ms(1_700_000_000_000)
    }

    // ── Registry / ladder ────────────────────────────────────────────────────

    #[test]
    fn registry_is_a_clean_forward_ladder_up_to_current() {
        validate_registry(MIGRATORS).expect("compiled-in registry is a clean ladder");
        assert!(!MIGRATORS.is_empty());
        assert_eq!(MIGRATORS[0].from, 0, "the ladder starts at v0 (legacy)");
        assert_eq!(
            MIGRATORS.last().expect("non-empty").to,
            SCHEMA_VERSION,
            "the ladder reaches the kernel's current version"
        );
    }

    #[test]
    fn refuses_downgrade_unknown_and_malformed_versions() {
        // Forward-only: a target older than the artifact is a refusal.
        let err = plan_ladder(MIGRATORS, 1, 0).expect_err("downgrade refused");
        assert_eq!(err.code(), CODE_MIGRATE_DOWNGRADE, "{err}");

        // Unknown version: an artifact whose step is not registered.
        let err = migrate_text_with(V0_LEGACY, &[], 1).expect_err("no ladder");
        assert_eq!(err.code(), CODE_MIGRATE_STEP, "{err}");
        assert!(err.to_string().contains("unknown schema_version 0"), "{err}");

        // Newer than the kernel: downgrade guard (mirrors loader E7004).
        let err = migrate_to_current("schema_version = 2\ntelemetry = true\n")
            .expect_err("newer refused");
        assert_eq!(err.code(), CODE_MIGRATE_NEWER, "{err}");

        // Malformed versions.
        let err = artifact_version("schema_version = \"one\"\n").expect_err("string version");
        assert_eq!(err.code(), CODE_MIGRATE_VERSION, "{err}");
        let err = artifact_version("schema_version = -1\n").expect_err("negative version");
        assert_eq!(err.code(), CODE_MIGRATE_VERSION, "{err}");

        // Registry defect: a backward step is not a ladder.
        static BACKWARD: &[Migrator] = &[Migrator {
            from: 1,
            to: 0,
            name: "backward",
            apply: stamp_v0_to_v1,
        }];
        let err = validate_registry(BACKWARD).expect_err("backward refused");
        assert_eq!(err.code(), CODE_MIGRATE_REGISTRY, "{err}");
        // ... and a duplicate source version is not a ladder either.
        static DUPLICATE: &[Migrator] = &[
            Migrator {
                from: 0,
                to: 1,
                name: "a",
                apply: stamp_v0_to_v1,
            },
            Migrator {
                from: 0,
                to: 1,
                name: "b",
                apply: stamp_v0_to_v1,
            },
        ];
        let err = validate_registry(DUPLICATE).expect_err("duplicate refused");
        assert_eq!(err.code(), CODE_MIGRATE_REGISTRY, "{err}");
    }

    #[test]
    fn migrate_to_current_is_identity_on_a_current_artifact() {
        let migrated = migrate_to_current(CURRENT).expect("identity");
        assert_eq!(migrated.from_version, SCHEMA_VERSION);
        assert_eq!(migrated.to_version, SCHEMA_VERSION);
        assert!(migrated.steps.is_empty());
        assert_eq!(migrated.text, CURRENT, "no step -> bytes unchanged");
    }

    #[test]
    fn ladder_runs_every_step_in_order_and_stamps_each_version() {
        // Synthetic two-step ladder exercising the walk (0 -> 1 -> 2).
        fn to_one(doc: &mut DocumentMut) -> Result<(), MigrateError> {
            set_document_version(doc, 1)?;
            doc.as_table_mut().insert("telemetry", toml_edit::value(false));
            Ok(())
        }
        fn to_two(doc: &mut DocumentMut) -> Result<(), MigrateError> {
            set_document_version(doc, 2)?;
            doc.as_table_mut().insert("no_color", toml_edit::value(true));
            Ok(())
        }
        static LADDER: &[Migrator] = &[
            Migrator {
                from: 0,
                to: 1,
                name: "synthetic-0-1",
                apply: to_one,
            },
            Migrator {
                from: 1,
                to: 2,
                name: "synthetic-1-2",
                apply: to_two,
            },
        ];
        let out = migrate_text_with("profile = \"privacy\"\n", LADDER, 2).expect("ladder");
        assert_eq!(out.from_version, 0);
        assert_eq!(out.steps, vec!["synthetic-0-1", "synthetic-1-2"]);
        let table: toml::Table = toml::from_str(&out.text).expect("parse");
        assert_eq!(table.get("schema_version").and_then(|v| v.as_integer()), Some(2));
        assert_eq!(
            table.get("telemetry").and_then(|v| v.as_bool()),
            Some(false),
            "step 0->1 value survives step 1->2"
        );

        // Post-condition violation is refused (a defective step).
        fn forgets_to_stamp(doc: &mut DocumentMut) -> Result<(), MigrateError> {
            doc.as_table_mut()
                .insert("profile", toml_edit::value("privacy"));
            Ok(())
        }
        static BROKEN: &[Migrator] = &[Migrator {
            from: 0,
            to: 1,
            name: "forgets-to-stamp",
            apply: forgets_to_stamp,
        }];
        let err = migrate_text_with("telemetry = true\n", BROKEN, 1).expect_err("post-condition");
        assert_eq!(err.code(), CODE_MIGRATE_STEP, "{err}");
        assert!(err.to_string().contains("post-condition"), "{err}");
    }

    #[test]
    fn migrated_output_preserves_foreign_tables_and_comments_but_is_loader_gated() {
        // A v0 artifact with a foreign table the kernel isolates (D3) plus a
        // comment: the stamp must not disturb them, but the strict kernel bar
        // refuses foreign tables (the same bar `write::commit` uses).
        let v0 = "# operator note\ntelemetry = true\n\n[browser]\nzone = \"tor\"\n";
        let err = migrate_to_current(v0).expect_err("strict bar refuses foreign tables");
        assert_eq!(err.code(), CODE_MIGRATE_ARTIFACT, "{err}");

        // Without foreign tables, the migration preserves comments + keys.
        let v0 = "# operator note\ntelemetry = true\n";
        let out = migrate_to_current(v0).expect("migrate");
        assert!(out.text.contains("# operator note"), "{}", out.text);
        assert!(out.text.contains("telemetry = true"), "{}", out.text);
        let table: toml::Table = toml::from_str(&out.text).expect("parse");
        assert_eq!(
            table.get("schema_version").and_then(|v| v.as_integer()),
            Some(1)
        );
    }

    // ── Snapshots ────────────────────────────────────────────────────────────

    #[test]
    fn stamp_lands_at_root_next_to_a_table() {
        // `secrets` is a kernel-owned subtable; the stamp must be a ROOT key
        // even though the document already carries a table (toml_edit
        // placement). If the stamp landed inside `[secrets]`, the strict gate
        // below would refuse the migrated output.
        let v0 = "telemetry = true\n[secrets]\ntok = \"env:TALLOW_X\"\n";
        let out = migrate_to_current(v0).expect("migrate");
        let table: toml::Table = toml::from_str(&out.text).expect("parse");
        assert_eq!(
            table.get("schema_version").and_then(|v| v.as_integer()),
            Some(1),
            "stamp must be root-level: {}",
            out.text
        );
        let secrets = table
            .get("secrets")
            .and_then(|v| v.as_table())
            .expect("secrets table");
        assert!(
            !secrets.contains_key("schema_version"),
            "stamp must not be swallowed by [secrets]: {}",
            out.text
        );
        assert_eq!(
            secrets.get("tok").and_then(|v| v.as_str()),
            Some("env:TALLOW_X"),
            "secrets survive the migration: {}",
            out.text
        );
        assert!(load::load_from_str(&out.text, None).is_strictly_valid(), "{}", out.text);
    }

    #[test]
    fn snapshot_roundtrip_is_byte_identical_and_tamper_refused() {
        let tmp = crate::config::test_support::TempDir::new("kb3-snap");
        let hist = tmp.join("hist");
        let sample = "schema_version = 1\ntelemetry = true\n[secrets]\ntok = \"env:TALLOW_X\"\n";

        let snap = capture_snapshot(&hist, sample, &tmp.join("config.toml"), 42).expect("capture");
        assert_eq!(snap.revision, 1);
        assert_eq!(
            snap.blake3,
            blake3::hash(sample.as_bytes()).to_hex().to_string()
        );

        let content = revision_content(&hist, snap.revision).expect("verified read");
        assert_eq!(content.text, sample);
        assert_eq!(content.blake3, snap.blake3);

        let target = tmp.join("restore/config.toml");
        let restored = restore_snapshot(&target, &hist, snap.revision).expect("restore");
        assert_eq!(restored.revision, 1);
        assert_eq!(restored.bytes, sample.len());
        assert_eq!(
            fs::read(&target).expect("read"),
            sample.as_bytes(),
            "restore is byte-identical"
        );
        // Second capture is monotonic.
        let snap2 = capture_snapshot(&hist, CURRENT, &tmp.join("config.toml"), 43).expect("s2");
        assert_eq!(snap2.revision, 2);

        // Tamper: the store refuses to serve a revision whose bytes changed.
        let artifact = write::history_revision_dir(&hist, 1).join("config.toml");
        fs::write(&artifact, "schema_version = 1\ntelemetry = false\n").expect("tamper");
        let err = revision_content(&hist, 1).expect_err("tamper refused");
        assert_eq!(err.code(), CODE_MIGRATE_SNAPSHOT, "{err}");
        assert!(err.to_string().contains("tampered"), "{err}");
        // ... and so does a restore off it.
        let err = restore_snapshot(&target, &hist, 1).expect_err("restore refused");
        assert_eq!(err.code(), CODE_MIGRATE_SNAPSHOT, "{err}");
    }

    #[test]
    fn rollback_to_revision_restores_bytes() {
        let tmp = crate::config::test_support::TempDir::new("kb3-rollback");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        fs::write(&target, CURRENT).expect("seed");
        capture_snapshot(&hist, CURRENT, &target, 1).expect("snapshot");

        // Deploy something else, then roll back to revision 1.
        fs::write(&target, "schema_version = 1\ntelemetry = false\n").expect("deploy");
        let restored = rollback_to(&target, &hist, 1).expect("rollback");
        assert_eq!(restored.revision, 1);
        assert_eq!(fs::read_to_string(&target).expect("read"), CURRENT);
    }

    #[test]
    fn revision_status_sidecar_roundtrips() {
        let tmp = crate::config::test_support::TempDir::new("kb3-status");
        let hist = tmp.join("hist");
        capture_snapshot(&hist, CURRENT, &tmp.join("config.toml"), 5).expect("snapshot");
        assert!(
            read_revision_status(&hist, 1).expect("read").is_none(),
            "unmarked revision reads as None"
        );

        let path = mark_revision_status(
            &hist,
            1,
            RevisionStatusWord::Reverted,
            6,
            Some("probe failed"),
        )
        .expect("mark");
        assert!(path.ends_with("000001/status.toml"));
        let record = read_revision_status(&hist, 1).expect("read").expect("some");
        assert_eq!(record.status, RevisionStatusWord::Reverted);
        assert_eq!(record.at_ms, 6);
        assert_eq!(record.note.as_deref(), Some("probe failed"));

        // Marking an unknown revision refuses (status marks recorded revisions).
        let err = mark_revision_status(&hist, 99, RevisionStatusWord::Good, 7, None)
            .expect_err("unknown revision");
        assert_eq!(err.code(), CODE_MIGRATE_STATUS, "{err}");
    }

    // ── Staged apply / health / auto-revert ──────────────────────────────────

    #[test]
    fn staged_apply_marks_healthy_deployment_good() {
        let tmp = crate::config::test_support::TempDir::new("kb3-apply-ok");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        fs::write(&target, CURRENT).expect("seed");
        let candidate = "schema_version = 1\ntelemetry = true\nno_color = true\n";

        let out = staged_apply(&target, candidate, || Ok(()), &opts_at(&hist)).expect("apply");
        assert_eq!(out.health, HealthOutcome::Healthy);
        assert_eq!(out.snapshot_revision, Some(1), "pre-apply snapshot recorded");
        assert_eq!(out.revision, 2, "candidate recorded as the next revision");
        assert_eq!(fs::read_to_string(&target).expect("read"), candidate);
        let status = read_revision_status(&hist, out.revision)
            .expect("read")
            .expect("marked");
        assert_eq!(status.status, RevisionStatusWord::Good);
    }

    #[test]
    fn staged_apply_auto_reverts_on_health_failure() {
        let tmp = crate::config::test_support::TempDir::new("kb3-apply-revert");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        let before = CURRENT;
        fs::write(&target, before).expect("seed");
        let candidate = "schema_version = 1\ntelemetry = true\nno_color = true\n";
        let sink = RecordingSink::default();

        let out = staged_apply(
            &target,
            candidate,
            || Err("probe: simulated health-check failure".to_string()),
            &opts_with_sink(&hist, &sink),
        )
        .expect("apply-with-revert is a safe outcome");

        match &out.health {
            HealthOutcome::Reverted {
                reason,
                restored_from,
                restored_bytes,
            } => {
                assert!(reason.contains("simulated health-check failure"), "{reason}");
                assert_eq!(*restored_from, Some(1), "reverted to the pre-apply snapshot");
                assert_eq!(*restored_bytes, before.len());
            }
            other => panic!("expected Reverted, got {other:?}"),
        }
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            before,
            "auto-revert is byte-identical"
        );

        // The deployed candidate revision exists and is marked reverted.
        assert_eq!(out.revision, 2);
        let status = read_revision_status(&hist, out.revision)
            .expect("read")
            .expect("marked reverted");
        assert_eq!(status.status, RevisionStatusWord::Reverted);
        assert!(
            status.note.as_deref().unwrap_or("").contains("auto-revert"),
            "{:?}",
            status.note
        );

        // Ledger saw the deploy (commit) and the revert (restore) — hashes only.
        let events = sink.events.lock().expect("lock");
        assert_eq!(events.len(), 2, "deploy + revert events");
        assert_eq!(events[0].revision, Some(out.revision));
        assert_eq!(events[1].revision, Some(1), "revert event names the snapshot");
        assert_eq!(events[1].bytes, before.len());
        assert_eq!(
            events[1].content_blake3,
            blake3::hash(before.as_bytes()).to_hex().to_string()
        );
    }

    #[test]
    fn staged_apply_with_no_prior_artifact_reverts_by_removal() {
        let tmp = crate::config::test_support::TempDir::new("kb3-apply-absent");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        let out = staged_apply(
            &target,
            CURRENT,
            || Err("probe: nope".to_string()),
            &opts_at(&hist),
        )
        .expect("apply");
        assert_eq!(out.snapshot_revision, None, "nothing to snapshot");
        match &out.health {
            HealthOutcome::Reverted {
                restored_from: None,
                restored_bytes: 0,
                ..
            } => {}
            other => panic!("expected revert-to-absent, got {other:?}"),
        }
        assert!(!target.exists(), "pre-state was absent: revert removes it");
    }

    #[test]
    fn staged_apply_refuses_invalid_candidate_before_any_write() {
        let tmp = crate::config::test_support::TempDir::new("kb3-apply-bad");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        let err = staged_apply(
            &target,
            "schema_version = 1\nbogus_key = true\n",
            || Ok(()),
            &opts_at(&hist),
        )
        .expect_err("invalid candidate refused");
        assert_eq!(err.code(), CODE_MIGRATE_APPLY, "{err}");
        assert!(err.to_string().contains("bogus_key"), "{err}");
        assert!(!target.exists(), "nothing deployed");
        assert_eq!(
            write::latest_revision(&hist).expect("latest"),
            None,
            "nothing recorded"
        );
    }

    // ── File-level migration ─────────────────────────────────────────────────

    #[test]
    fn v0_fixture_migrates_and_snapshot_exists() {
        let tmp = crate::config::test_support::TempDir::new("kb3-upgrade");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        fs::write(&target, V0_LEGACY).expect("seed v0");

        let outcome = migrate_file(&target, &opts_at(&hist)).expect("migrate");
        let (from_version, to_version, steps, apply_outcome) = match outcome {
            FileMigration::Migrated {
                from_version,
                to_version,
                steps,
                outcome,
            } => (from_version, to_version, steps, outcome),
            other => panic!("expected Migrated, got {other:?}"),
        };
        assert_eq!((from_version, to_version), (0, 1));
        assert_eq!(steps, vec!["v0-stamp-schema-version"]);
        assert_eq!(apply_outcome.health, HealthOutcome::Healthy);
        assert_eq!(apply_outcome.snapshot_revision, Some(1));

        // The deployed file is version 1, still strictly valid, values intact.
        let text = fs::read_to_string(&target).expect("read");
        assert_eq!(artifact_version(&text).expect("version"), 1);
        assert!(load::load_from_str(&text, None).is_strictly_valid(), "{text}");
        let table: toml::Table = toml::from_str(&text).expect("parse");
        assert_eq!(
            table.get("telemetry").and_then(|v| v.as_bool()),
            Some(true),
            "legacy values survive the migration"
        );

        // Mandatory pre-migration snapshot: the ORIGINAL v0 bytes, byte-identical.
        let snap = revision_content(&hist, 1).expect("snapshot content");
        assert_eq!(snap.text, V0_LEGACY);

        // The migration is idempotent: a second run is a no-op.
        match migrate_file(&target, &opts_at(&hist)).expect("second run") {
            FileMigration::AlreadyCurrent { version } => assert_eq!(version, 1),
            other => panic!("expected AlreadyCurrent, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_migration_restores_byte_identical_snapshot() {
        let tmp = crate::config::test_support::TempDir::new("kb3-corrupt");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        fs::write(&target, V0_LEGACY).expect("seed v0");

        // A defective step: stamps the version but writes a value the kernel
        // refuses (a string where `telemetry` wants a bool).
        fn corrupt(doc: &mut DocumentMut) -> Result<(), MigrateError> {
            set_document_version(doc, 1)?;
            doc.as_table_mut()
                .insert("telemetry", toml_edit::value("yes"));
            Ok(())
        }
        static CORRUPT: &[Migrator] = &[Migrator {
            from: 0,
            to: 1,
            name: "corrupt-0-1",
            apply: corrupt,
        }];
        let corrupt_sink = RecordingSink::default();

        // (a) The ladder refuses the invalid output before any write.
        let err = migrate_text_with(V0_LEGACY, CORRUPT, 1).expect_err("invalid output refused");
        assert_eq!(err.code(), CODE_MIGRATE_ARTIFACT, "{err}");
        assert!(err.to_string().contains("strict kernel validation"), "{err}");

        // (b) Through the file-level flow the failure is wrapped as a restore
        //     (E7058) and the target bytes are byte-identical.
        let err = migrate_file_with(&target, CORRUPT, 1, &opts_with_sink(&hist, &corrupt_sink))
            .expect_err("corrupted migration refused");
        assert_eq!(err.code(), CODE_MIGRATE_REVERTED, "{err}");
        assert!(err.to_string().contains("strict kernel validation"), "{err}");
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            V0_LEGACY,
            "restored/untouched bytes are byte-identical"
        );
        let snap = revision_content(&hist, 1).expect("snapshot content");
        assert_eq!(snap.text, V0_LEGACY);
        let events = corrupt_sink.events.lock().expect("lock");
        assert_eq!(events.len(), 1, "the restore is ledger-recorded");
        assert_eq!(events[0].revision, Some(1));
        drop(events);

        // A failing step (not just invalid output) takes the same restore path
        // and reports E7058 with the snapshot revision it restored. Fresh store
        // so the snapshot revision is 1 again.
        let hist2 = tmp.join("hist2");
        fn fails(doc: &mut DocumentMut) -> Result<(), MigrateError> {
            set_document_version(doc, 1)?;
            Err(MigrateError::Artifact {
                message: "simulated corrupt migrator".to_string(),
            })
        }
        static FAILS: &[Migrator] = &[Migrator {
            from: 0,
            to: 1,
            name: "fails-0-1",
            apply: fails,
        }];
        let fails_sink = RecordingSink::default();
        let err = migrate_file_with(&target, FAILS, 1, &opts_with_sink(&hist2, &fails_sink))
            .expect_err("failing migration refused");
        assert_eq!(err.code(), CODE_MIGRATE_REVERTED, "{err}");
        match err {
            MigrateError::Reverted {
                snapshot_revision,
                ref reason,
                ..
            } => {
                assert_eq!(snapshot_revision, 1, "the pre-migration snapshot");
                assert!(reason.contains("simulated corrupt migrator"), "{reason}");
            }
            other => panic!("expected Reverted, got {other:?}"),
        }
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            V0_LEGACY,
            "byte-identical after the restore"
        );
        // The restore is verified against the store before it is served.
        let snap = revision_content(&hist2, 1).expect("snapshot content");
        assert_eq!(snap.text, V0_LEGACY);
        // ... and the restore was ledger-recorded (no deploy happened).
        let events = fails_sink.events.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].revision, Some(1));
    }

    #[test]
    fn migrate_file_reports_no_artifact_and_already_current() {
        let tmp = crate::config::test_support::TempDir::new("kb3-noop");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        match migrate_file(&target, &opts_at(&hist)).expect("no artifact") {
            FileMigration::NoArtifact => {}
            other => panic!("expected NoArtifact, got {other:?}"),
        }
        fs::write(&target, CURRENT).expect("seed");
        match migrate_file(&target, &opts_at(&hist)).expect("already current") {
            FileMigration::AlreadyCurrent { version } => assert_eq!(version, SCHEMA_VERSION),
            other => panic!("expected AlreadyCurrent, got {other:?}"),
        }
        // Neither run touched the store.
        assert_eq!(write::latest_revision(&hist).expect("latest"), None);
    }

    // ── Diff ─────────────────────────────────────────────────────────────────

    #[test]
    fn diff_revisions_is_deterministic_and_labeled() {
        let tmp = crate::config::test_support::TempDir::new("kb3-diff");
        let hist = tmp.join("hist");
        let src = tmp.join("config.toml");
        capture_snapshot(
            &hist,
            "schema_version = 1\ntelemetry = true\nno_color = false\n[secrets]\ntok = \"env:A\"\n",
            &src,
            1,
        )
        .expect("r1");
        capture_snapshot(
            &hist,
            "schema_version = 1\ntelemetry = false\nprofile = \"privacy\"\n[secrets]\ntok = \"env:A\"\n",
            &src,
            2,
        )
        .expect("r2");

        let diff = diff_revisions(&hist, 1, 2).expect("diff");
        assert_eq!((diff.from, diff.to), (1, 2));
        let keys: Vec<&str> = diff.entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["no_color", "profile", "telemetry"],
            "sorted, stable order"
        );
        assert!(matches!(
            diff.entries[0].change,
            DiffChange::Removed { .. }
        ));
        assert!(matches!(
            diff.entries[1].change,
            DiffChange::Added { .. }
        ));
        assert!(matches!(
            diff.entries[2].change,
            DiffChange::Changed { .. }
        ));
        assert!(!diff.is_empty());
        let rendered = diff.render();
        assert!(rendered.contains("+ profile = \"privacy\""), "{rendered}");
        assert!(rendered.contains("~ telemetry: true -> false"), "{rendered}");
        assert!(rendered.contains("- no_color = false"), "{rendered}");

        // Stability: repeated calls are byte-identical.
        let again = diff_revisions(&hist, 1, 2).expect("diff again");
        assert_eq!(diff, again);
        assert_eq!(diff.render(), again.render());

        // Reversed: kinds flip, nothing phantom.
        let reversed = diff_revisions(&hist, 2, 1).expect("reversed");
        let rkeys: Vec<&str> = reversed.entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(rkeys, vec!["no_color", "profile", "telemetry"]);
        assert!(matches!(
            reversed.entries[0].change,
            DiffChange::Added { .. }
        ));
        assert!(matches!(
            reversed.entries[1].change,
            DiffChange::Removed { .. }
        ));
        // Identical revisions diff to nothing (and `[secrets]` reference rows
        // are compared as values, not resolved).
        let nonce = capture_snapshot(&hist, "schema_version = 1\ntelemetry = true\n", &src, 3)
            .expect("r3");
        let same = capture_snapshot(&hist, "schema_version = 1\ntelemetry = true\n", &src, 4)
            .expect("r4");
        assert!(diff_revisions(&hist, nonce.revision, same.revision)
            .expect("identical")
            .is_empty());
    }
}
