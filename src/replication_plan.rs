//! Replication planning layer — store walking, scan diffing and policy
//! config (task A1.3.2 remainder, frozen interface B05 §2; companion to the
//! committed file-level primitives in [`crate::replication`], which this
//! module reuses and never edits).
//!
//! Three responsibilities, kept deliberately lean:
//!
//! 1. **Walking** ([`walk_store`]) — enumerate the content-addressed artifacts
//!    of one store root, handling both layouts the design freezes
//!    (`impl/A1.3.1_replication_design.md` §D4):
//!    - sharded raw: `root/<ab>/<cd>/<sha256hex>` objects + `root/meta/<hash>.json`
//!      provenance sidecars ([`crate::raw_store`]);
//!    - non-sharded derived: `root/derived/<key>` objects + `root/meta/<key>.json`
//!      sidecars ([`crate::derived_store`]).
//!
//!    The walk is **cheap and metadata-only**: the `hash` recorded in a
//!    [`WalkEntry`] is the *layout-claimed* key (the file name), not a re-hash
//!    of the bytes. Full byte re-verification is the fixity job's work
//!    (A1.3.3); the planner re-reads a copy only where it is about to count it
//!    (see [`diff_scans`]).
//!
//! 2. **Diffing** ([`diff_scans`]) — compare a primary scan against zero or
//!    more peer scans and produce a [`PlanDiff`]:
//!    - *missing*: primary artifacts (kind + key) that **no** peer holds at all
//!      — the copy list;
//!    - *mismatched*: peer entries that carry the same kind + key as a primary
//!      artifact but do **not** agree (recorded size differs, or the bytes at
//!      their path re-hash to something other than the key) — the repair list;
//!    - *copies_short_of_target*: number of primary artifacts whose count of
//!      verified copies (the primary itself + every peer copy that passes the
//!      size check and the sha256 re-hash) is below `target_copies`.
//!
//!    Per design D1/D5 a copy counts **only** if its bytes hash to the
//!    recorded sha256 — size/mtime/seals are never trusted. Verification of a
//!    peer candidate therefore re-hashes the file via
//!    [`crate::replication::sha256_file`]; a file that cannot be read counts
//!    as *not verified* (it lands in `mismatched`). The primary scan is the
//!    reference identity set; it is trusted as-is (fixity owns primary-side
//!    rot detection).
//!
//!    Counting granularity is the artifact — the `(kind, hash)` pair. A raw
//!    object and its `meta` sidecar are two artifacts that replicate together
//!    (D5: "a raw object without its sidecar is an incomplete record"), so a
//!    shortfall can be reported for the object, the sidecar, or both. For the
//!    common one-sidecar-per-object stores this equals the per-hash count.
//!
//! 3. **Config** ([`parse_config`]) — parse the `replicas.toml` registry /
//!    policy sketch from D5 into [`ReplicaConfig`]. The `toml` crate (v1) is
//!    already a workspace dependency, so no new dependency is introduced and
//!    no hand-rolled parser is needed; the accepted subset and every default
//!    are documented on [`parse_config`].
//!
//! Everything here is synchronous, deterministic in output order, and performs
//! no writes. `walk_store` sorts its output by `(kind, hash, path)`; store
//! output order is otherwise irrelevant to the diff.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::replication::sha256_file;

// ── types (frozen §2) ────────────────────────────────────────────────────────

/// Which artifact layer a [`WalkEntry`] belongs to.
///
/// Ordering is declaration order and only used for deterministic sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WalkKind {
    /// Sharded raw object: `root/<ab>/<cd>/<sha256hex>`.
    Raw,
    /// Non-sharded derived object: `root/derived/<key>`.
    Derived,
    /// Sidecar metadata: `root/meta/<hash>.json` (raw) or `root/meta/<key>.json`
    /// (derived). The `hash` is the file stem.
    Meta,
}

/// One artifact found by [`walk_store`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Layout-claimed sha256 hex key: the object file name, or the sidecar
    /// file stem (`meta/<hash>.json` → `<hash>`). Not re-hashed at walk time.
    pub hash: String,
    /// Which layer the entry belongs to.
    pub kind: WalkKind,
    /// Byte length of the file on disk.
    pub size: u64,
    /// Absolute or caller-relative path of the file.
    pub path: PathBuf,
}

/// Result of comparing a primary scan against peer scans ([`diff_scans`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDiff {
    /// Primary artifacts present in **no** peer scan (need copying).
    pub missing: Vec<WalkEntry>,
    /// Peer entries that share a primary artifact's kind+key but fail
    /// verification: recorded size disagrees, or re-hash of the file bytes
    /// does not equal the key, or the file is unreadable (need repair).
    pub mismatched: Vec<WalkEntry>,
    /// Number of primary artifacts with fewer than `target_copies` verified
    /// copies (primary itself counts as one). "Shortfalls are reported, not
    /// hidden" (D5).
    pub copies_short_of_target: usize,
}

// ── walking (frozen §2) ──────────────────────────────────────────────────────

/// Walk one store root and return its artifacts, sorted by
/// `(kind, hash, path)`.
///
/// Handles both frozen layouts at once, shallowly and deterministically:
///
/// - `root/<ab>/<cd>/<file>` where both directories are two lowercase hex
///   chars and `<file>` is a 64-char lowercase hex sha256 → [`WalkKind::Raw`];
/// - `root/derived/<file>` with the same 64-hex file-name rule →
///   [`WalkKind::Derived`];
/// - `root/meta/<stem>.json` with a 64-hex stem → [`WalkKind::Meta`].
///
/// Anything else (root-level files, foreign directories, non-hex names,
/// subdirectories where files are expected) is skipped silently — stores also
/// accumulate quarantine files (`<name>.quarantine-<ms>`) and editor droppings,
/// none of which are artifacts. Directories that *are* part of a layout but
/// cannot be read propagate an [`io::Error`];
/// `meta/`/`derived/` simply being absent is not an error (an empty set is
/// returned for that layer).
///
/// `store_id` (e.g. `"T0"`) is the registry id of the store being walked; it is
/// used to identify the store in error messages (the frozen [`WalkEntry`] has
/// no store field). A `root` that does not exist or is not a directory is
/// `ErrorKind::NotFound`.
pub fn walk_store(root: &Path, store_id: &str) -> io::Result<Vec<WalkEntry>> {
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "walk_store[{store_id}]: store root {} does not exist or is not a directory",
                root.display()
            ),
        ));
    }
    let mut out = Vec::new();
    collect_raw(root, store_id, &mut out)?;
    collect_derived(&root.join("derived"), store_id, &mut out)?;
    collect_meta(&root.join("meta"), store_id, &mut out)?;
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.hash.cmp(&b.hash))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(out)
}

/// `root/<ab>/<cd>/<hash>` — sharded raw objects only.
fn collect_raw(root: &Path, store_id: &str, out: &mut Vec<WalkEntry>) -> io::Result<()> {
    for shard in read_dir_ctx(root, store_id)? {
        let shard = entry_ctx(shard, root, store_id)?;
        let sname = match shard.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue, // non-UTF-8 names cannot be store keys
        };
        if !is_hex2(&sname) || !ftype_ctx(&shard, store_id)?.is_dir() {
            continue; // meta/, derived/, foreign dirs and files
        }
        let shard_dir = shard.path();
        for sub in read_dir_ctx(&shard_dir, store_id)? {
            let sub = entry_ctx(sub, &shard_dir, store_id)?;
            let sub_name = match sub.file_name().to_str() {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !is_hex2(&sub_name) || !ftype_ctx(&sub, store_id)?.is_dir() {
                continue;
            }
            let leaf_dir = sub.path();
            for leaf in read_dir_ctx(&leaf_dir, store_id)? {
                let leaf = entry_ctx(leaf, &leaf_dir, store_id)?;
                let name = match leaf.file_name().to_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                if !is_hex64(&name) {
                    continue; // quarantine copies, strays
                }
                let md = meta_ctx(&leaf, store_id)?;
                if !md.is_file() {
                    continue; // symlinks / dirs are not artifacts
                }
                out.push(WalkEntry {
                    hash: name,
                    kind: WalkKind::Raw,
                    size: md.len(),
                    path: leaf.path(),
                });
            }
        }
    }
    Ok(())
}

/// `derived/<key>` — non-sharded derived objects only.
fn collect_derived(dir: &Path, store_id: &str, out: &mut Vec<WalkEntry>) -> io::Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()), // layer absent
        Err(e) => return Err(dir_ctx_err(dir, store_id, e)),
    };
    for ent in rd {
        let ent = entry_ctx(ent, dir, store_id)?;
        let name = match ent.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !is_hex64(&name) {
            continue;
        }
        let md = meta_ctx(&ent, store_id)?;
        if !md.is_file() {
            continue;
        }
        out.push(WalkEntry {
            hash: name,
            kind: WalkKind::Derived,
            size: md.len(),
            path: ent.path(),
        });
    }
    Ok(())
}

/// `meta/<stem>.json` — sidecars for either layer.
fn collect_meta(dir: &Path, store_id: &str, out: &mut Vec<WalkEntry>) -> io::Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()), // layer absent
        Err(e) => return Err(dir_ctx_err(dir, store_id, e)),
    };
    for ent in rd {
        let ent = entry_ctx(ent, dir, store_id)?;
        let name = match ent.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let stem = match name.strip_suffix(".json") {
            Some(s) if is_hex64(s) => s.to_string(),
            _ => continue,
        };
        let md = meta_ctx(&ent, store_id)?;
        if !md.is_file() {
            continue;
        }
        out.push(WalkEntry {
            hash: stem,
            kind: WalkKind::Meta,
            size: md.len(),
            path: ent.path(),
        });
    }
    Ok(())
}

/// Exactly two lowercase hex chars — one sharding level (`ab`, `cd`).
fn is_hex2(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Exactly 64 lowercase hex chars — a sha256 key as the stores write it.
fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn read_dir_ctx(dir: &Path, store_id: &str) -> io::Result<fs::ReadDir> {
    fs::read_dir(dir).map_err(|e| dir_ctx_err(dir, store_id, e))
}

fn dir_ctx_err(dir: &Path, store_id: &str, e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!("walk_store[{store_id}]: cannot read {}: {e}", dir.display()),
    )
}

fn entry_ctx(ent: io::Result<fs::DirEntry>, dir: &Path, store_id: &str) -> io::Result<fs::DirEntry> {
    ent.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "walk_store[{store_id}]: unreadable entry under {}: {e}",
                dir.display()
            ),
        )
    })
}

fn ftype_ctx(ent: &fs::DirEntry, store_id: &str) -> io::Result<fs::FileType> {
    ent.file_type().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "walk_store[{store_id}]: cannot stat {}: {e}",
                ent.path().display()
            ),
        )
    })
}

fn meta_ctx(ent: &fs::DirEntry, store_id: &str) -> io::Result<fs::Metadata> {
    ent.metadata().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "walk_store[{store_id}]: cannot stat {}: {e}",
                ent.path().display()
            ),
        )
    })
}

// ── diffing (frozen §2) ──────────────────────────────────────────────────────

/// Diff a primary scan against peer scans and plan copies/repairs.
///
/// Identity is the exact `(kind, hash)` pair (a sidecar is not a copy of its
/// object). For every distinct primary artifact, in primary order:
///
/// - **Not present in any peer** → pushed to [`PlanDiff::missing`].
/// - **Present in one or more peers** → each peer candidate is verified:
///   its recorded `size` must equal the primary's, and the bytes at its
///   `path` must re-hash (sha256) to the key. A candidate passing both counts
///   as one verified peer copy; a candidate failing either (including an
///   unreadable file) is pushed to [`PlanDiff::mismatched`].
///
/// The primary artifact counts as one copy of itself. If
/// `1 + verified_peer_copies < target_copies`, the artifact contributes 1 to
/// [`PlanDiff::copies_short_of_target`]; missing artifacts contribute when
/// `1 < target_copies`. `target_copies = 1` therefore means "the primary copy
/// is enough" and never reports a shortfall, while `missing` still lists
/// artifacts no peer holds (they remain valid copy candidates).
///
/// Ordering is deterministic: `missing` follows primary order; `mismatched`
/// follows primary order, then peer-scan order, then candidate order within a
/// scan. Duplicate keys *within* the primary scan are compared once (first
/// occurrence defines the identity; later duplicates are ignored).
pub fn diff_scans(
    primary: &[WalkEntry],
    peers: &[Vec<WalkEntry>],
    target_copies: usize,
) -> PlanDiff {
    // Index peer entries by (kind, key) — key borrowed from `peers`.
    let mut index: BTreeMap<(WalkKind, &str), Vec<&WalkEntry>> = BTreeMap::new();
    for scan in peers {
        for e in scan {
            index
                .entry((e.kind, e.hash.as_str()))
                .or_default()
                .push(e);
        }
    }

    let mut missing: Vec<WalkEntry> = Vec::new();
    let mut mismatched: Vec<WalkEntry> = Vec::new();
    let mut copies_short_of_target: usize = 0;
    let mut seen: BTreeSet<(WalkKind, &str)> = BTreeSet::new();

    for e in primary {
        let key = (e.kind, e.hash.as_str());
        if !seen.insert(key) {
            continue; // duplicate key within the primary scan
        }
        match index.get(&key) {
            None => {
                missing.push(e.clone());
                if 1 < target_copies {
                    copies_short_of_target += 1;
                }
            }
            Some(candidates) => {
                let mut verified: usize = 1; // the primary's own copy
                for c in candidates {
                    let size_ok = c.size == e.size;
                    let hash_ok = size_ok
                        && sha256_file(&c.path)
                            .map(|h| h == e.hash)
                            .unwrap_or(false);
                    if hash_ok {
                        verified += 1;
                    } else {
                        mismatched.push((*c).clone());
                    }
                }
                if verified < target_copies {
                    copies_short_of_target += 1;
                }
            }
        }
    }

    PlanDiff {
        missing,
        mismatched,
        copies_short_of_target,
    }
}

// ── config (frozen §2) ───────────────────────────────────────────────────────

/// Default for `retries` when the key is absent; also the hard cap (D1:
/// "retries bounded at 3").
const RETRIES_CAP: u32 = 3;

/// Default `priority` for a store table that omits it (lowest priority —
/// sorts after every explicit priority below 100).
const DEFAULT_PRIORITY: u8 = 100;

/// Replication policy + store registry, as read from `replicas.toml` (D5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaConfig {
    /// N — declared target copies incl. the primary. Shortfalls below N are
    /// reported by the planner, never hidden.
    pub target_copies: usize,
    /// Post-copy re-verification policy. Defaults to `true` and must not
    /// inherit the `nas-sync.toml` `verify=false` habit (D1); a config may
    /// still state it explicitly either way.
    pub verify_always: bool,
    /// Bounded retry count (clamped to the D1 cap of 3).
    pub retries: u32,
    /// Store registry, sorted by `(priority, id)` ascending.
    pub stores: Vec<StoreCfg>,
}

/// One store registry entry (`[stores.<id>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCfg {
    /// Table key, e.g. `"T0"`.
    pub id: String,
    /// Free-form role label from the D5 sketch: `primary`, `mirror`,
    /// `dark-archive`, … (required, non-empty).
    pub role: String,
    /// Store root (the D5 key is `bindir`), e.g.
    /// `~/Nixe/data/stores/raw`.
    pub root: PathBuf,
    /// Ledger-snapshot directory for this store (`ledgerdir`), if any.
    pub ledgerdir: Option<PathBuf>,
    /// Replication priority; lower runs/repairs first.
    pub priority: u8,
    /// Whether the store participates (T2 ships `enabled = false` until its
    /// device is provisioned).
    pub enabled: bool,
}

/// Parse the `replicas.toml` registry/policy sketch (D5) into a
/// [`ReplicaConfig`].
///
/// The `toml` crate is already a workspace dependency, so this uses
/// `toml::Value` + explicit extraction (no serde derive plumbing) — **no new
/// dependency** and no hand-rolled parser.
///
/// Accepted subset and defaults (everything else in the document is ignored,
/// including `manifest_version`; unknown keys never fail the parse):
///
/// | key                  | rule |
/// |----------------------|------|
/// | `target_copies`      | required integer ≥ 1 |
/// | `verify_always`      | optional bool, default `true` (D1: never inherit `verify=false`) |
/// | `retries`            | optional int ≥ 0, default `3`; values above 3 are clamped to 3 (D1 bound) |
/// | `[stores.<id>]`      | at least one table required |
/// | `...role`            | required non-empty string |
/// | `...bindir`          | required non-empty string → `StoreCfg::root` |
/// | `...ledgerdir`       | optional non-empty string |
/// | `...priority`        | optional int 0..=255, default 100 |
/// | `...enabled`         | optional bool, default `true` |
///
/// Stores come back sorted by `(priority, id)`. Errors are human-readable
/// strings naming `replicas.toml`, the offending store id, and the key.
pub fn parse_config(text: &str) -> Result<ReplicaConfig, String> {
    let doc: toml::Value =
        toml::from_str(text).map_err(|e| format!("replicas.toml: invalid TOML: {e}"))?;
    let table = doc
        .as_table()
        .ok_or_else(|| "replicas.toml: top level must be a TOML table".to_string())?;

    let target_copies = match table.get("target_copies") {
        Some(v) => v
            .as_integer()
            .ok_or_else(|| "replicas.toml: `target_copies` must be an integer".to_string())?,
        None => {
            return Err("replicas.toml: missing required key `target_copies`".to_string());
        }
    };
    if target_copies < 1 {
        return Err(format!(
            "replicas.toml: `target_copies` must be >= 1 (got {target_copies})"
        ));
    }
    let target_copies = target_copies as usize;

    let verify_always = match table.get("verify_always") {
        Some(v) => v
            .as_bool()
            .ok_or_else(|| "replicas.toml: `verify_always` must be a boolean".to_string())?,
        None => true,
    };

    let retries = match table.get("retries") {
        Some(v) => {
            let r = v
                .as_integer()
                .ok_or_else(|| "replicas.toml: `retries` must be an integer".to_string())?;
            if r < 0 {
                return Err(format!("replicas.toml: `retries` must be >= 0 (got {r})"));
            }
            (r as u32).min(RETRIES_CAP)
        }
        None => RETRIES_CAP,
    };

    let stores_tbl = match table.get("stores") {
        Some(v) => v
            .as_table()
            .ok_or_else(|| "replicas.toml: `stores` must be a table of store tables".to_string())?,
        None => {
            return Err("replicas.toml: missing required [stores] section".to_string());
        }
    };
    if stores_tbl.is_empty() {
        return Err(
            "replicas.toml: [stores] declares no stores — at least one (T0 primary) is required"
                .to_string(),
        );
    }

    let mut stores: Vec<StoreCfg> = Vec::with_capacity(stores_tbl.len());
    for (id, v) in stores_tbl {
        let t = v
            .as_table()
            .ok_or_else(|| format!("replicas.toml: [stores.{id}] must be a table"))?;

        let role = req_str(t, id, "role")?;
        let bindir = req_str(t, id, "bindir")?;

        let ledgerdir = match t.get("ledgerdir") {
            Some(x) => {
                let s = x.as_str().ok_or_else(|| {
                    format!("replicas.toml: [stores.{id}] `ledgerdir` must be a string")
                })?;
                if s.is_empty() {
                    return Err(format!(
                        "replicas.toml: [stores.{id}] `ledgerdir` must not be empty"
                    ));
                }
                Some(PathBuf::from(s))
            }
            None => None,
        };

        let priority = match t.get("priority") {
            Some(x) => {
                let p = x.as_integer().ok_or_else(|| {
                    format!("replicas.toml: [stores.{id}] `priority` must be an integer")
                })?;
                u8::try_from(p).map_err(|_| {
                    format!("replicas.toml: [stores.{id}] `priority` out of range 0..=255")
                })?
            }
            None => DEFAULT_PRIORITY,
        };

        let enabled = match t.get("enabled") {
            Some(x) => x.as_bool().ok_or_else(|| {
                format!("replicas.toml: [stores.{id}] `enabled` must be a boolean")
            })?,
            None => true,
        };

        stores.push(StoreCfg {
            id: id.clone(),
            role: role.to_string(),
            root: PathBuf::from(bindir),
            ledgerdir,
            priority,
            enabled,
        });
    }
    stores.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));

    Ok(ReplicaConfig {
        target_copies,
        verify_always,
        retries,
        stores,
    })
}

/// Required non-empty string key in a store table.
fn req_str<'a>(t: &'a toml::Table, id: &str, key: &str) -> Result<&'a str, String> {
    let s = t.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
        format!("replicas.toml: [stores.{id}] missing required string `{key}`")
    })?;
    if s.is_empty() {
        return Err(format!(
            "replicas.toml: [stores.{id}] `{key}` must not be empty"
        ));
    }
    Ok(s)
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::sha256_hex;

    /// Write `bytes` at `path` (creating parents) and return its sha256 hex.
    fn seed(path: &Path, bytes: &[u8]) -> String {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
        sha256_hex(bytes)
    }

    fn entry(kind: WalkKind, hash: &str, size: u64, path: &Path) -> WalkEntry {
        WalkEntry {
            hash: hash.to_string(),
            kind,
            size,
            path: path.to_path_buf(),
        }
    }

    fn hashes(entries: &[WalkEntry]) -> Vec<(&WalkKind, &str)> {
        entries.iter().map(|e| (&e.kind, e.hash.as_str())).collect()
    }

    // ── walking ──

    #[test]
    fn walk_sharded_raw_layout_reports_objects_and_sidecars() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("stores/raw");
        let payload = b"raw object bytes";
        let hash = sha256_hex(payload);
        let obj = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
        seed(&obj, payload);
        let sidecar = root.join("meta").join(format!("{hash}.json"));
        let sc = br#"{"url":"https://example.invalid/x","content_type":"text/plain","ts_ms":1}"#;
        seed(&sidecar, sc);

        let got = walk_store(&root, "T0").unwrap();
        assert_eq!(got.len(), 2, "one object + one sidecar: {got:?}");

        let o = &got[0];
        assert_eq!(o.kind, WalkKind::Raw);
        assert_eq!(o.hash, hash);
        assert_eq!(o.size, payload.len() as u64);
        assert_eq!(o.path, obj);
        // Raw sorts before Meta (declaration order).
        let m = &got[1];
        assert_eq!(m.kind, WalkKind::Meta);
        assert_eq!(m.hash, hash, "sidecar hash = file stem");
        assert_eq!(m.size, sc.len() as u64);
        assert_eq!(m.path, sidecar);

        // Deterministic across runs.
        assert_eq!(walk_store(&root, "T0").unwrap(), got);
    }

    #[test]
    fn walk_non_sharded_derived_layout() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("stores/derived");
        let key = sha256_hex(b"source-hash\npipeline-v1");
        let obj = root.join("derived").join(&key);
        let payload = b"derived bytes (extracted text)";
        seed(&obj, payload);
        let sidecar = root.join("meta").join(format!("{key}.json"));
        let sc = br#"{"source_hash":"aabb","pipeline_version":"v1","ts_ms":7}"#;
        seed(&sidecar, sc);

        let got = walk_store(&root, "T0-derived").unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].kind, WalkKind::Derived);
        assert_eq!(got[0].hash, key);
        assert_eq!(got[0].size, payload.len() as u64);
        assert_eq!(got[0].path, obj);
        assert_eq!(got[1].kind, WalkKind::Meta);
        assert_eq!(got[1].hash, key);
        assert_eq!(got[1].size, sc.len() as u64);
        assert_eq!(got[1].path, sidecar);
    }

    #[test]
    fn walk_skips_strays_and_is_deterministic() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("stores/raw");
        // One genuine raw object + sidecar.
        let hash = sha256_hex(b"keeper");
        seed(
            &root.join(&hash[0..2]).join(&hash[2..4]).join(&hash),
            b"keeper",
        );
        seed(&root.join("meta").join(format!("{hash}.json")), b"{}");
        // Strays that must never be reported as artifacts:
        seed(&root.join("README.md"), b"not an object");
        seed(&root.join("meta").join("notes.json"), b"{}"); // stem not hex
        seed(&root.join("meta").join("deadbeef.json"), b"{}"); // too short
        seed(&root.join("derived").join("stray.txt"), b"nope");
        seed(&root.join("zz").join("ff").join("f".repeat(64).as_str()), b"bad shard");
        seed(
            &root.join(&hash[0..2]).join(&hash[2..4]).join("x.bin"),
            b"bad leaf",
        );
        // Quarantine leftovers (frozen naming from crate::replication).
        seed(
            &root
                .join(&hash[0..2])
                .join(&hash[2..4])
                .join(format!("{hash}.quarantine-42")),
            b"evidence",
        );

        let got = walk_store(&root, "T1").unwrap();
        assert_eq!(hashes(&got), vec![(&WalkKind::Raw, hash.as_str()), (&WalkKind::Meta, hash.as_str())]);
        assert_eq!(walk_store(&root, "T1").unwrap(), got, "stable order");
    }

    #[test]
    fn walk_missing_root_is_not_found_and_names_store() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("no-such-store");
        let err = walk_store(&missing, "T2").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let msg = err.to_string();
        assert!(msg.contains("T2"), "error names the store: {msg}");
        assert!(msg.contains("no-such-store"), "error names the path: {msg}");
    }

    // ── diffing ──

    /// The missing/mismatch/shortfall matrix, target_copies = 2.
    #[test]
    fn diff_matrix_missing_mismatch_shortfall() {
        let d = tempfile::tempdir().unwrap();
        let prim = d.path().join("primary");
        let pa = prim.join("a.raw");
        let pb = prim.join("b.raw");
        let pc = prim.join("c.raw");
        let pd = prim.join("d.raw");
        let ha = seed(&pa, b"alpha");
        let hb = seed(&pb, b"bravo");
        let hc = seed(&pc, b"charlie");
        let hd = seed(&pd, b"delta");
        let primary = vec![
            entry(WalkKind::Raw, &ha, 5, &pa),
            entry(WalkKind::Raw, &hb, 5, &pb),
            entry(WalkKind::Raw, &hc, 7, &pc),
            entry(WalkKind::Raw, &hd, 5, &pd),
        ];

        // peer1: A good; C present but bytes corrupted (same claimed size).
        let p1 = d.path().join("peer1");
        let p1a = p1.join("a.raw");
        seed(&p1a, b"alpha");
        let p1c = p1.join("c.raw");
        assert_ne!(seed(&p1c, b"charLIE"), hc, "corrupt copy has other bytes");
        // peer2: D good; C entry lies about its size (file bytes are fine).
        let p2 = d.path().join("peer2");
        let p2d = p2.join("d.raw");
        seed(&p2d, b"delta");
        let p2c = p2.join("c.raw");
        seed(&p2c, b"charlie");
        // peer3: A good again — multiple peer copies all count.
        let p3 = d.path().join("peer3");
        let p3a = p3.join("a.raw");
        seed(&p3a, b"alpha");

        let peers = vec![
            vec![entry(WalkKind::Raw, &ha, 5, &p1a), entry(WalkKind::Raw, &hc, 7, &p1c)],
            vec![entry(WalkKind::Raw, &hd, 5, &p2d), entry(WalkKind::Raw, &hc, 999, &p2c)],
            vec![entry(WalkKind::Raw, &ha, 5, &p3a)],
        ];

        let diff = diff_scans(&primary, &peers, 2);

        // B present in no peer → missing.
        assert_eq!(hashes(&diff.missing), vec![(&WalkKind::Raw, hb.as_str())]);
        // Both C candidates fail: one by re-hash, one by size lie.
        assert_eq!(
            hashes(&diff.mismatched),
            vec![(&WalkKind::Raw, hc.as_str()), (&WalkKind::Raw, hc.as_str())]
        );
        assert_eq!(diff.mismatched[0].size, 7, "corrupt-bytes candidate size");
        assert_eq!(diff.mismatched[1].size, 999, "size-lie candidate recorded size");
        // A: 1 primary + 2 verified = 3 ≥ 2. D: 2 ≥ 2. B: 1 < 2. C: 1 < 2.
        assert_eq!(diff.copies_short_of_target, 2, "B and C are short");
    }

    #[test]
    fn diff_sidecar_is_a_distinct_artifact() {
        let d = tempfile::tempdir().unwrap();
        let prim = d.path().join("primary");
        let payload = b"object with sidecar";
        let h = sha256_hex(payload);
        let obj = prim.join(&h[0..2]).join(&h[2..4]).join(&h);
        seed(&obj, payload);
        let sc = prim.join("meta").join(format!("{h}.json"));
        seed(&sc, b"{\"url\":\"x\"}");
        let primary = vec![
            entry(WalkKind::Raw, &h, payload.len() as u64, &obj),
            entry(WalkKind::Meta, &h, 11, &sc),
        ];

        // Peer holds only the object, not the sidecar.
        let peer = d.path().join("peer");
        let peer_obj = peer.join(&h[0..2]).join(&h[2..4]).join(&h);
        seed(&peer_obj, payload);
        let peers = vec![vec![entry(WalkKind::Raw, &h, payload.len() as u64, &peer_obj)]];

        let diff = diff_scans(&primary, &peers, 2);
        // Object: verified 2/2. Sidecar: absent everywhere → missing + short.
        assert_eq!(hashes(&diff.missing), vec![(&WalkKind::Meta, h.as_str())]);
        assert!(diff.mismatched.is_empty());
        assert_eq!(diff.copies_short_of_target, 1, "the sidecar is short");
    }

    #[test]
    fn diff_unreadable_peer_copy_is_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let prim = d.path().join("primary");
        let obj = prim.join("o.raw");
        let h = seed(&obj, b"present here");
        let primary = vec![entry(WalkKind::Raw, &h, 12, &obj)];

        // Entry was walked, then the file vanished / is unreadable.
        let ghost = d.path().join("peer").join("o.raw");
        let peers = vec![vec![entry(WalkKind::Raw, &h, 12, &ghost)]];

        let diff = diff_scans(&primary, &peers, 2);
        assert!(diff.missing.is_empty(), "present entry, not missing");
        assert_eq!(hashes(&diff.mismatched), vec![(&WalkKind::Raw, h.as_str())]);
        assert_eq!(diff.mismatched[0].path, ghost);
        assert_eq!(diff.copies_short_of_target, 1);
    }

    #[test]
    fn diff_fully_replicated_and_minimal_targets() {
        let d = tempfile::tempdir().unwrap();
        let prim = d.path().join("primary");
        let obj = prim.join("o.raw");
        let h = seed(&obj, b"fully replicated");
        let primary = vec![entry(WalkKind::Raw, &h, 17, &obj)];
        let peer = d.path().join("peer");
        let po = peer.join("o.raw");
        seed(&po, b"fully replicated");
        let peers = vec![vec![entry(WalkKind::Raw, &h, 17, &po)]];

        let diff = diff_scans(&primary, &peers, 2);
        assert!(diff.missing.is_empty());
        assert!(diff.mismatched.is_empty());
        assert_eq!(diff.copies_short_of_target, 0);

        // target_copies = 1: the primary alone suffices → never short…
        let diff = diff_scans(&primary, &[], 1);
        assert_eq!(diff.missing.len(), 1, "absent from all peers → still a copy candidate");
        assert!(diff.mismatched.is_empty());
        assert_eq!(diff.copies_short_of_target, 0, "1 verified copy meets target 1");

        // …while target_copies = 3 flags the same artifact.
        let diff = diff_scans(&primary, &[], 3);
        assert_eq!(diff.copies_short_of_target, 1);

        // Empty primary → empty plan.
        let diff = diff_scans(&[], &[vec![]], 3);
        assert!(diff.missing.is_empty() && diff.mismatched.is_empty());
        assert_eq!(diff.copies_short_of_target, 0);
    }

    // ── config ──

    const D5_FIXTURE: &str = r#"
# data/replication/replicas.toml — store registry (D5 sketch)
manifest_version = "1.0"
target_copies    = 3
verify_always    = true
retries          = 3

[stores.T0]
role     = "primary"
bindir   = "~/Nixe/data/stores/raw"
ledgerdir= "~/Nixe/data/ledger/snapshots"
priority = 0

[stores.T1]
role     = "mirror"
bindir   = "/var/lib/tallow/replica/raw"
ledgerdir= "/var/lib/tallow/replica/ledger/snapshots"
priority = 10

[stores.T2]
role     = "dark-archive"
bindir   = "/mnt/tallow-archive/stores/raw"
ledgerdir= "/mnt/tallow-archive/ledger/snapshots"
priority = 20
enabled  = false
"#;

    #[test]
    fn parse_config_d5_fixture() {
        let cfg = parse_config(D5_FIXTURE).unwrap();
        assert_eq!(cfg.target_copies, 3);
        assert!(cfg.verify_always);
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.stores.len(), 3);

        let ids: Vec<&str> = cfg.stores.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["T0", "T1", "T2"], "sorted by (priority, id)");

        let t0 = &cfg.stores[0];
        assert_eq!(t0.role, "primary");
        assert_eq!(t0.root, PathBuf::from("~/Nixe/data/stores/raw"));
        assert_eq!(
            t0.ledgerdir,
            Some(PathBuf::from("~/Nixe/data/ledger/snapshots"))
        );
        assert_eq!(t0.priority, 0);
        assert!(t0.enabled, "enabled defaults to true when the key is absent");

        let t2 = &cfg.stores[2];
        assert_eq!(t2.role, "dark-archive");
        assert_eq!(t2.priority, 20);
        assert!(!t2.enabled, "T2 ships disabled until the device exists");
    }

    #[test]
    fn parse_config_defaults_and_retries_clamp() {
        let cfg = parse_config(
            r#"
target_copies = 2
retries      = 5

[stores.only]
role   = "primary"
bindir = "/tmp/x"
"#,
        )
        .unwrap();
        assert!(cfg.verify_always, "defaults to true — never inherits verify=false");
        assert_eq!(cfg.retries, 5.min(3), "D1 bound: retries clamp to 3");
        assert_eq!(cfg.stores.len(), 1);
        let s = &cfg.stores[0];
        assert_eq!(s.id, "only");
        assert_eq!(s.priority, 100, "priority default (lowest)");
        assert!(s.enabled);
        assert_eq!(s.ledgerdir, None);

        // retries = 0 is allowed (explicitly no retries).
        let cfg = parse_config(
            "target_copies = 1\nretries = 0\n[stores.a]\nrole = \"primary\"\nbindir = \"/tmp/a\"\n",
        )
        .unwrap();
        assert_eq!(cfg.retries, 0);
    }

    #[test]
    fn parse_config_rejects_malformed_toml() {
        let err = parse_config("target_copies = ").unwrap_err();
        assert!(err.contains("invalid TOML"), "{err}");
        let err = parse_config("= not a key").unwrap_err();
        assert!(err.contains("invalid TOML"), "{err}");
    }

    #[test]
    fn parse_config_rejects_missing_or_empty_requirements() {
        // No target_copies.
        let err = parse_config("[stores.T0]\nrole='primary'\nbindir='/x'\n").unwrap_err();
        assert!(err.contains("target_copies"), "{err}");

        // target_copies non-integer and out of domain.
        let err = parse_config("target_copies = \"three\"\n").unwrap_err();
        assert!(err.contains("target_copies"), "{err}");
        let err = parse_config("target_copies = 0\n").unwrap_err();
        assert!(err.contains(">= 1"), "{err}");

        // No [stores] section / empty [stores] table.
        let err = parse_config("target_copies = 1\n").unwrap_err();
        assert!(err.contains("[stores]"), "{err}");
        let err = parse_config("target_copies = 1\n[stores]\n").unwrap_err();
        assert!(err.contains("no stores"), "{err}");

        // Store missing bindir → names the store and the key.
        let err = parse_config(
            "target_copies = 1\n[stores.T1]\nrole = \"mirror\"\n",
        )
        .unwrap_err();
        assert!(err.contains("T1") && err.contains("bindir"), "{err}");

        // Store missing role.
        let err = parse_config(
            "target_copies = 1\n[stores.T1]\nbindir = \"/x\"\n",
        )
        .unwrap_err();
        assert!(err.contains("T1") && err.contains("role"), "{err}");

        // Empty role string.
        let err = parse_config(
            "target_copies = 1\n[stores.T1]\nrole = \"\"\nbindir = \"/x\"\n",
        )
        .unwrap_err();
        assert!(err.contains("must not be empty"), "{err}");

        // priority out of u8 range.
        let err = parse_config(
            "target_copies = 1\n[stores.T1]\nrole = \"mirror\"\nbindir = \"/x\"\npriority = 300\n",
        )
        .unwrap_err();
        assert!(err.contains("priority"), "{err}");
    }
}
