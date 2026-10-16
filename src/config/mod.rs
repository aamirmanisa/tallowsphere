//! Tallow config kernel (W3 config wave, U-202 blueprint — KB-1..KB-8).
//!
//! KB-1 is the typed, versioned, fail-closed core the rest of the config wave
//! builds on. Nothing here touches the network; the only I/O is the config
//! file itself and the config-history revision store.
//!
//! # Modules
//! - [`schema`] — the typed tree ([`schema::Config`], `#[serde(deny_unknown_fields)]`),
//!   the required [`schema::SCHEMA_VERSION`], secret references
//!   ([`schema::SecretRef`]), key-class metadata ([`schema::KeyClass`]) and the
//!   typed error enum with the reserved `E7001`–`E7099` diagnostic codes
//!   (parent decision D5).
//! - [`load`] — strict fail-closed parse. Unknown keys, type mismatches and bad
//!   versions produce typed diagnostics; the [`load::ConfigLoad`] result carries
//!   **per-section** outcomes (`core`, `secrets`) so a strict failure refuses
//!   only the affected subsystem, never the whole binary (parent decision D3).
//! - [`write`] — atomic staged writes (temp file in the same directory, fsync,
//!   rename; `0600` on unix for secret-bearing files), the config-history
//!   revision hook at `dirs::state_dir()/tallow/config-history` (dir 0700 /
//!   files 0600; parent decision D6) recording every accepted write, and the
//!   best-effort ledger seam (parent decision D8).
//! - [`scopes`]/[`resolve`] (KB-2, row #84) — the R-7.2 layered scope stack
//!   (`defaults < profile < system < user < device < project < agent <
//!   session`, `swarm` system-class). [`scopes`] carries the ladder ordering,
//!   kernel-validated layer ingest (a string where the schema wants a boolean
//!   is refused — no coercion) and the `[lock]` table (locks are orthogonal
//!   to precedence; locks may only originate at a system-class scope, and
//!   `system`/`swarm` layers must arrive as **verified bundles** — the
//!   verify-before-load gate reuses the bundle block's `E7027` semantics).
//!   [`resolve`] deep-merges the layers with per-key provenance: winner,
//!   shadowed scopes and the `locked_by` origin (`config get --explain`
//!   data model); arrays replace unless `[merge] "key" = "append"`;
//!   structural kind conflicts are refused (`E7042`, never coerced).
//! - [`migrate`] (KB-3, row #48) — versioning, forward-only migration ladder,
//!   mandatory snapshots, staged apply with health check + auto-revert.
//!   [`migrate::migrate_to_current`] walks the registered `N -> N+1` ladder
//!   (a v0 legacy artifact is one without `schema_version`) and only returns
//!   an artifact the strict loader accepts; downgrades and
//!   newer-than-kernel artifacts are refused, a missing step is never
//!   guessed. [`migrate::capture_snapshot`]/[`migrate::restore_snapshot`]
//!   record revisions under the KB-1 store and restore them
//!   **byte-identically** (hash-verified, loader-independent);
//!   [`migrate::staged_apply`] validates the candidate, snapshots the
//!   deployed bytes, deploys through [`write::commit`], runs the health probe
//!   and auto-reverts to the snapshot on failure (revision status sidecar
//!   `<rev>/status.toml` + one ledger event); [`migrate::diff_revisions`] is
//!   the deterministic `config diff` data model. CLI arms
//!   (`config rollback --to <rev>`, `config diff <revA> <revB>`,
//!   `config migrate`) are parent-applied — §OPEN of
//!   `research/tallow-v1/exec/R-08-batch4-H-kb3-migrations.md`.
//! - [`presets`] (KB-7, row #66) — the hardening preset tables: per-profile
//!   stances + tier ceilings (report §7.2.3) and the tighten-only *floor*
//!   engine. Floors the KB-1 subset cannot express yet are recorded as
//!   `[target-only]` pending rows.
//! - [`lint`] (KB-7, row #66) — read-only `tallow config lint` scoring: kernel
//!   diagnostics plus baseline findings (secure defaults §7.5.1, profile floor
//!   drift, secrets-reference hygiene §7.7), deterministic score, text/JSON
//!   rendering. Never writes and never reads a secret value. Also carries the
//!   zero-trust pack (row #144): `W7201`–`W7203` checks plus a reporting-time
//!   self-assessment mapped to the NCSC 8 principles / NIST SP 800-207·207A /
//!   GovZTA pillars (`zero_trust` in `--format json`).
//! - [`cli`] — the `tallow config {lint,presets,bundle}` entry points (exit
//!   codes 0 = pass · 1 = findings · 2 = could not run).
//! - [`bundle`] (rows #153/#198) — signed config bundles (R-7.4/R-7.8): the
//!   Ed25519-signed export/import format, fail-closed verification, and the
//!   `system`/`swarm` *verify-before-load* gate ([`bundle::load_scoped`]).
//!   ML-DSA hybrid, mesh sync and `key_ledger` rotation stay open legs.
//!
//! # Diagnostic codes (parent decision D5: `E7001`–`E7099` reserved to this kernel)
//! | code | kind | meaning |
//! |---|---|---|
//! | `E7001` | error | TOML artifact could not be parsed (or produced) |
//! | `E7002` | error | unknown key / unknown section (strict: refused, never ignored) |
//! | `E7003` | error | value type mismatch (or unknown enum word) for a typed key |
//! | `E7004` | error | `schema_version` missing, malformed, zero, older-without-migration, or newer (downgrade guard) |
//! | `E7005` | error | literal value in a secret-class key — a reference is required |
//! | `E7006` | error | config file exists but cannot be read |
//! | `E7007` | error | atomic write failed (previous file left intact) |
//! | `E7008` | error | config-history revision could not be recorded → write refused (fail-closed) |
//! | `E7009` | error | config-history location unresolvable/unusable |
//! | `E7010` | error | secret reference failed to resolve at use time |
//! | `E7011` | error | `vault://` resolution seam (D7) — reserved, KB-4 wires it |
//! | `E7012` | error | required base directory unavailable — no `"."` fallback (A4 fix) |
//! | `E7013` | error | aggregate refusal: the artifact failed strict validation (details in the refusal) |
//!
//! KB-2 block (`scopes.rs`/`resolve.rs`, row #84 — `E7040`–`E7044`):
//! | code | kind | meaning |
//! |---|---|---|
//! | `E7040` | error | unknown scope word — refused, never defaulted to a nearby scope |
//! | `E7041` | error | lock violation / malformed `[lock]` table / lock outside a system-class scope (names the lock origin) |
//! | `E7042` | error | deep-merge conflict: structural kind mismatch across scopes (no coercion) or a malformed `[merge]` directive |
//! | `E7043` | error | scope-layer artifact failed kernel validation, or a layer was built for a non-file scope |
//! | `E7044` | error | malformed session override (`TALLOW_CONFIG_*`) |
//! | `E7027` | error | (reused) plain layer at a `system`/`swarm` scope — verified bundles only |
//!
//! KB-3 block (`migrate.rs`, row #48 — `E7050`–`E7059`):
//! | code | kind | meaning |
//! |---|---|---|
//! | `E7050` | error | artifact handed to the migrator is not parseable TOML, or the migrated output fails strict validation |
//! | `E7051` | error | `schema_version` present but malformed (non-integer / negative) |
//! | `E7052` | error | refusal of downgrade: requested target older than the artifact (forward-only) |
//! | `E7053` | error | ladder step failed / unknown version with no registered migrator |
//! | `E7054` | error | the migrator registry is not a clean forward ladder |
//! | `E7055` | error | artifact newer than the kernel `SCHEMA_VERSION` (downgrade guard) |
//! | `E7056` | error | snapshot store failure (capture / verification / restore) |
//! | `E7057` | error | staged apply refused (invalid candidate, deploy failure) |
//! | `E7058` | error | migration failed; the pre-migration snapshot was restored byte-identically |
//! | `E7059` | error | revision status sidecar (`<rev>/status.toml`) failure |
//!
//! Bundle block (`bundle.rs`, rows #153/#198 — `E7020`–`E7031`):
//! | code | kind | meaning |
//! |---|---|---|
//! | `E7020` | error | bundle artifact could not be parsed (or produced) |
//! | `E7021` | error | not a bundle — magic mismatch |
//! | `E7022` | error | unsupported bundle format version |
//! | `E7023` | error | unsupported signature algorithm (the reserved ML-DSA hybrid word is refused as "later") |
//! | `E7024` | error | unsigned bundle — refused |
//! | `E7025` | error | signature does not verify — bundle refused (tamper / wrong key) |
//! | `E7026` | error | signer not pinned for the bundle's scope — refused (verify-before-load) |
//! | `E7027` | error | plain (unsigned) artifact at a `system`/`swarm` scope — refused |
//! | `E7028` | error | invalid key material (key file / embedded key) |
//! | `E7029` | error | export refused: source artifact failed strict kernel validation |
//! | `E7030` | error | declared import scope ≠ bundle scope (relabel refused) |
//! | `E7031` | error | bundle I/O failure |
//!
//! # Scope (KB-1) and non-goals
//! KB-1 ships the kernel **only**. Swapping the `tallow config {get,set,list,path}`
//! CLI arms onto it and the doctor probe are parent-applied follow-ups (U-202
//! §3). Roadmap so later tasks extend instead of re-architecting:
//! - **KB-2 (scopes)** — **landed** (row #84): [`scopes`]/[`resolve`] carry
//!   the ladder ordering + kernel-validated layer ingest, the system-class
//!   authority gate (verify-before-load, `E7027`), the lock table, and the
//!   deep-merge resolver with per-key provenance. Remaining legs are
//!   parent-applied: the `config get/set --scope/--explain` CLI arms and the
//!   `[secrets]`-ACL surface (recorded in
//!   `research/tallow-v1/exec/R-08-batch4-D-kb2-scopes.md` §OPEN).
//! - **KB-3 (history/versioning)** — **landed** (row #48): [`migrate`] carries
//!   the forward-only `N -> N+1` ladder (built on
//!   [`write::record_revision`]/[`write::read_revision_meta`]), mandatory
//!   pre-migration/pre-apply snapshots with byte-faithful restore, staged
//!   apply + health probe + auto-revert (revision status sidecar) and the
//!   deterministic revision diff. CLI arms (`config rollback --to <rev>`,
//!   `config diff <revA> <revB>`, `config migrate`) are parent-applied —
//!   patch in `research/tallow-v1/exec/R-08-batch4-H-kb3-migrations.md` §OPEN.
//! - **KB-4 (secrets)** — `vault://` resolution behind the kernel-internal seam
//!   ([`schema::SecretRef::resolve`] returns the reserved `E7011` today, D7).
//! - **KB-5** tier docs de-drift; **KB-6** doctor config probe (consumes
//!   [`load`]); **KB-7** profiles preset behavior + `config lint` — **landed**
//!   (see [`presets`] + [`lint`]: floor tables, read-only scoring, CLI arms;
//!   the *apply* surface stays behind the operator-authorization boundary,
//!   §7.6.3); **KB-8** never-invariants hooks.

pub mod bundle;
pub mod cli;
pub mod lint;
pub mod load;
pub mod migrate;
pub mod presets;
pub mod resolve;
pub mod schema;
pub mod scopes;
pub mod write;

#[cfg(test)]
pub(crate) mod test_support;

pub use load::{
    ConfigLoad, SectionResult, default_config_path, load_default, load_file, load_from_str,
};
pub use schema::{
    CODE_ARTIFACT, CODE_HISTORY_PATH, CODE_HISTORY_RECORD, CODE_LITERAL_SECRET, CODE_PATH_UNRESOLVED,
    CODE_READ_IO, CODE_REFUSED, CODE_SCHEMA_VERSION, CODE_SECRET_RESOLUTION, CODE_TYPE_MISMATCH,
    CODE_UNKNOWN_KEY, CODE_VAULT_SEAM, CODE_WRITE_IO, Config, ConfigDiagnostic, ConfigError,
    ConfigSection, CoreSettings, KeyClass, OutputFormat, Profile, SCHEMA_VERSION, SecretRef,
    SecretSettings, SectionRefusal,
};
pub use write::{
    CommitOutcome, ConfigWriteEvent, FilePermsPolicy, HistoryPolicy, LedgerSink, RevisionMeta,
    RevisionRecord, WriteOptions, commit, default_history_dir, history_revision_dir,
    latest_revision, next_revision, read_revision_meta, record_revision,
};

// KB-7 (row #66) surfaces — see [`presets`] / [`lint`] module docs.
pub use lint::{
    BASELINE_ID, CODE_ENV_SECRET_MISSING, CODE_ENV_SECRET_REF, CODE_NO_PROFILE, CODE_PROFILE_FLOOR,
    CODE_PROFILE_GATED, CODE_SECRET_TARGET, CODE_TELEMETRY_ON, CODE_VAULT_SEAM_REF, LintFinding,
    LintOptions, LintReport, MAX_SCORE, Severity,
};
pub use presets::{
    AppliedFloor, Floor, FloorCheck, FloorKind, PROFILE_POSTURES, PresetValue, ProfilePosture,
};

// KB-2 (row #84) surfaces — see [`scopes`] / [`resolve`] module docs.
pub use resolve::{Provenance, Resolved, resolve_layers};
pub use scopes::{
    APPLICATION_ORDER, CODE_SCOPE_LAYER, CODE_SCOPE_LOCK, CODE_SCOPE_MERGE, CODE_SCOPE_SESSION,
    CODE_SCOPE_UNKNOWN, LADDER, LayerAuthority, LockTable, MergeDirective, ScopeError, ScopeLayer,
    is_above, is_system_class, ladder_index, parse_scope, rank, scope_layer_paths,
    session_overrides_from_env,
};

// KB-3 (row #48) surfaces — see [`migrate`] module docs.
pub use migrate::{
    ApplyOptions, ApplyOutcome, CODE_MIGRATE_APPLY, CODE_MIGRATE_ARTIFACT, CODE_MIGRATE_DOWNGRADE,
    CODE_MIGRATE_NEWER, CODE_MIGRATE_REGISTRY, CODE_MIGRATE_REVERTED, CODE_MIGRATE_SNAPSHOT,
    CODE_MIGRATE_STATUS, CODE_MIGRATE_STEP, CODE_MIGRATE_VERSION, ConfigDiff, DiffChange, DiffEntry,
    FileMigration, HealthOutcome, MIGRATORS, MigrateError, Migrated, Migrator, RevisionContent,
    RevisionStatusRecord, RevisionStatusWord, Snapshot, artifact_version, capture_snapshot,
    diff_revisions, document_version, load_probe, migrate_file, migrate_file_with, migrate_text_with,
    migrate_to_current, plan_ladder, read_revision_status, restore_snapshot, revision_content,
    rollback_to, set_document_version, staged_apply, validate_registry,
};

// Rows #153/#198 surfaces — see [`bundle`] module docs.
pub use bundle::{
    ALG_ED25519, ALG_MLDSA_HYBRID_RESERVED, Assurance, BUNDLE_FORMAT_VERSION, BUNDLE_MAGIC,
    BundleBody, BundleError, BundleSignature, CODE_BUNDLE_ALG, CODE_BUNDLE_EXPORT, CODE_BUNDLE_IO,
    CODE_BUNDLE_KEY, CODE_BUNDLE_MAGIC, CODE_BUNDLE_MALFORMED, CODE_BUNDLE_SCOPE_MISMATCH,
    CODE_BUNDLE_SIGNATURE, CODE_BUNDLE_UNSIGNED, CODE_BUNDLE_UNTRUSTED, CODE_BUNDLE_VERSION,
    CODE_SCOPE_UNSIGNED_LOAD, ConfigBundle, ConfigScope, EXPECTED_SCOPE, ExportOutcome,
    ImportOutcome, TrustAnchors, VerifiedBundle,
};
