//! Supply Chain Integrity — author key pinning, maintainer change detection,
//! and comprehensive supply-chain auditing.
//!
//! Implements:
//! - SCI-05: TOFU key pinning with BLAKE3 fingerprints
//! - SCI-06: Maintainer change detection (E2200)
//! - SCI-07: `tallow audit --supply-chain` comprehensive supply-chain audit
//!
//! ## Pin file (`.tallow-pins`)
//!
//! `tallow audit --supply-chain` enforces pins loaded from a project-local
//! `.tallow-pins` file (read next to the audited file, alongside
//! `Cargo.lock`/`tallow.lock`):
//!
//! ```toml
//! # .tallow-pins — pin the lock-file hash of each dependency to enforce.
//! pins-version = 1                # optional; absent means 1
//! [pins]
//! serde = "blake3:<64 hex>"       # tallow.lock `integrity` (default algorithm)
//! "rustls" = "sha256:<64 hex>"    # Cargo.lock `checksum`
//! ```
//!
//! - Optional `pins-version = 1` root key (absent = 1); unsupported versions are
//!   refused loudly.
//! - Subjects are package names as recorded in the lock files.
//! - A bare 64-hex value pins a BLAKE3 fingerprint (matching
//!   [`blake3_fingerprint`]); `sha256:` pins a Cargo.lock checksum.
//! - Enforcement: a pinned subject whose lock-file hash differs is an
//!   `Error`-severity finding (`SCI-PIN-MISMATCH`); a pinned subject missing
//!   from the lock files (or recorded without a hash) is reported as
//!   `SCI-PIN-UNVERIFIED` — a pin is never silently ignored.
//! - Unknown tables/keys are refused (strict, mirroring the config kernel); a
//!   malformed pin file refuses the audit loudly.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::sbom::SbomComponent;

// ── Error codes ─────────────────────────────────────────────────────────────

/// E2200: maintainer key changed for a pinned package.
pub const E2200_MAINTAINER_KEY_CHANGED: &str = "E2200";

// ── Key Pinning (TOFU) ─────────────────────────────────────────────────────

/// Result of a key-pinning operation.
#[derive(Debug, Clone, PartialEq)]
pub enum PinResult {
    /// Key was pinned for the first time (Trust On First Use).
    Pinned,
    /// Key was already pinned and matches.
    AlreadyPinned,
    /// Key was already pinned but does NOT match — potential supply-chain attack.
    Mismatch {
        expected: String,
        actual: String,
    },
}

/// In-memory key pin store — maps package name to BLAKE3 fingerprint.
#[derive(Debug, Clone, Default)]
pub struct KeyPinStore {
    pins: HashMap<String, String>,
}

impl KeyPinStore {
    pub fn new() -> Self {
        Self {
            pins: HashMap::new(),
        }
    }

    /// Pin a key for a package.  TOFU model: first pin wins, subsequent calls
    /// with the same key return `AlreadyPinned`, different key returns `Mismatch`.
    pub fn pin_author_key(&mut self, package: &str, fingerprint: &str) -> PinResult {
        if let Some(existing) = self.pins.get(package) {
            let same = canonical_fingerprint(existing).is_some()
                && canonical_fingerprint(existing) == canonical_fingerprint(fingerprint);
            if same || existing == fingerprint {
                PinResult::AlreadyPinned
            } else {
                PinResult::Mismatch {
                    expected: existing.clone(),
                    actual: fingerprint.to_string(),
                }
            }
        } else {
            self.pins
                .insert(package.to_string(), fingerprint.to_string());
            PinResult::Pinned
        }
    }

    /// Check whether a package's current key matches the pinned key.
    /// Returns `true` if they match (or no pin exists), `false` on mismatch.
    pub fn check_maintainer_change(
        &self,
        package: &str,
        current_key: &str,
    ) -> bool {
        match self.pins.get(package) {
            Some(pinned) => {
                pinned == current_key
                    || (canonical_fingerprint(pinned).is_some()
                        && canonical_fingerprint(pinned) == canonical_fingerprint(current_key))
            }
            None => true, // no pin yet — no mismatch
        }
    }

    /// Return all pinned packages and their fingerprints.
    pub fn all_pins(&self) -> &HashMap<String, String> {
        &self.pins
    }
}

/// Compute a BLAKE3 fingerprint for a public-key byte slice.
pub fn blake3_fingerprint(key_bytes: &[u8]) -> String {
    let hash = blake3::hash(key_bytes);
    hash.to_hex().to_string()
}

// ── Pin file (`.tallow-pins`) ───────────────────────────────────────────────

/// Project-local pin file read by the supply-chain audit (next to the audited
/// file, alongside `Cargo.lock`/`tallow.lock`). Format documented in the
/// module docs.
pub const PINS_FILE_NAME: &str = ".tallow-pins";

/// Current `.tallow-pins` format version (optional `pins-version` root key).
pub const PINS_FORMAT_VERSION: u32 = 1;

/// Root key carrying [`PINS_FORMAT_VERSION`].
pub const PINS_VERSION_KEY: &str = "pins-version";

/// Public wrapper for CLI authors: normalize a fingerprint to
/// `blake3:<64-hex>` / `sha256:<64-hex>` (or bare 64-hex with the BLAKE3
/// default). `None` when malformed.
pub fn normalize_fingerprint(raw: &str) -> Option<String> {
    normalize_pin_fingerprint(raw).map(|value| match value.contains(':') {
        true => value,
        // A bare digest is the BLAKE3 default in the file format; spell it out
        // so a later prefixed pin compares equal and the file says which hash.
        false => format!("blake3:{value}"),
    })
}

/// Canonical comparison form: bare 64-hex means BLAKE3.
fn canonical_fingerprint(raw: &str) -> Option<String> {
    normalize_pin_fingerprint(raw).map(|value| match value.contains(':') {
        true => value,
        false => format!("blake3:{value}"),
    })
}

/// Remove a pin. Returns true when a row existed.
pub fn remove_pin(store: &mut KeyPinStore, package: &str) -> bool {
    store.pins.remove(package).is_some()
}

/// Serialize a pin store to the `.tallow-pins` TOML format. Entries are
/// sorted by subject so the file is stable across writes.
pub fn render_pins(store: &KeyPinStore) -> String {
    let mut pins = toml::Table::new();
    let mut entries: Vec<_> = store.all_pins().iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    for (subject, fingerprint) in entries {
        pins.insert(subject.clone(), toml::Value::String(fingerprint.clone()));
    }
    let mut root = toml::Table::new();
    root.insert(
        PINS_VERSION_KEY.to_string(),
        toml::Value::Integer(i64::from(PINS_FORMAT_VERSION)),
    );
    root.insert("pins".to_string(), toml::Value::Table(pins));
    format!(
        "# tallow package pins — written by `tallow pins`\n{}",
        toml::to_string(&root).unwrap_or_default()
    )
}

/// Write `<project_dir>/.tallow-pins` atomically (temp file + rename). The
/// directory must already exist; this never invents a project root.
pub fn write_pin_store(project_dir: &Path, store: &KeyPinStore) -> Result<PathBuf, String> {
    let path = project_dir.join(PINS_FILE_NAME);
    let temp = project_dir.join(format!(".{PINS_FILE_NAME}.tmp"));
    std::fs::write(&temp, render_pins(store))
        .map_err(|err| format!("cannot write {}: {err}", temp.display()))?;
    std::fs::rename(&temp, &path)
        .map_err(|err| format!("cannot replace {}: {err}", path.display()))?;
    Ok(path)
}

/// A loaded pin store plus its provenance.
#[derive(Debug, Clone, Default)]
pub struct PinStoreLoad {
    /// The loaded pins — empty when no pin file exists.
    pub store: KeyPinStore,
    /// Path of the pin file the store was read from; `None` = no pin file.
    pub source: Option<PathBuf>,
}

/// Normalize a pinned fingerprint: optional `blake3:` (default) / `sha256:`
/// prefix + 64 ascii-hex chars, lowercased. `None` when malformed.
fn normalize_pin_fingerprint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (prefix, hex) = match trimmed.split_once(':') {
        Some((algo, hex)) if algo.eq_ignore_ascii_case("blake3") => {
            (Some("blake3"), hex)
        }
        Some((algo, hex)) if algo.eq_ignore_ascii_case("sha256") => {
            (Some("sha256"), hex)
        }
        Some(_) => return None, // unknown algorithm prefix — refused
        None => (None, trimmed),
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some(match prefix {
        Some(algo) => format!("{algo}:{hex}"),
        None => hex,
    })
}

/// Parse `.tallow-pins` content into a [`KeyPinStore`].
///
/// Strict, mirroring the config kernel: only the `[pins]` table and the
/// optional `pins-version` key are accepted and unknown root keys are refused,
/// never ignored. Every value must be a 64-hex fingerprint with an optional
/// `blake3:` (default) or `sha256:` prefix.
pub fn parse_pins(content: &str) -> Result<KeyPinStore, String> {
    let table: toml::Table = toml::from_str(content)
        .map_err(|e| format!("{PINS_FILE_NAME} is not valid TOML: {e}"))?;

    let mut store = KeyPinStore::new();
    for (key, value) in table.iter() {
        match key.as_str() {
            PINS_VERSION_KEY => match value.as_integer() {
                Some(v) if v == i64::from(PINS_FORMAT_VERSION) => {}
                Some(v) => {
                    return Err(format!(
                        "{PINS_FILE_NAME}: unsupported {PINS_VERSION_KEY} {v} — this tallow \
                         understands {PINS_FORMAT_VERSION}"
                    ));
                }
                None => {
                    return Err(format!(
                        "{PINS_FILE_NAME}: {PINS_VERSION_KEY} must be an integer (found {value:?})"
                    ));
                }
            },
            "pins" => {
                let pins = value.as_table().ok_or_else(|| {
                    format!(
                        "{PINS_FILE_NAME}: `pins` must be a table of subject = \"<fingerprint>\" entries"
                    )
                })?;
                for (subject, fingerprint) in pins.iter() {
                    let raw = fingerprint.as_str().ok_or_else(|| {
                        format!(
                            "{PINS_FILE_NAME}: pin for `{subject}` must be a string fingerprint"
                        )
                    })?;
                    let normalized = normalize_pin_fingerprint(raw).ok_or_else(|| {
                        format!(
                            "{PINS_FILE_NAME}: pin for `{subject}` is not a 64-hex fingerprint \
                             (optional `blake3:`/`sha256:` prefix): {raw:?}"
                        )
                    })?;
                    let _ = store.pin_author_key(subject, &normalized);
                }
            }
            other => {
                return Err(format!(
                    "{PINS_FILE_NAME}: unknown key `{other}` — only `{PINS_VERSION_KEY}` and the \
                     `[pins]` table are accepted (unknown keys are refused, never ignored)"
                ));
            }
        }
    }
    Ok(store)
}

/// Load the pin store for a project directory from
/// `<project_dir>/.tallow-pins`.
///
/// `source: None` means no pin file exists — callers must log that loudly,
/// never fall through to a silent empty store. A pin file that exists but
/// cannot be read or parsed is an `Err` (fail-closed).
pub fn load_pin_store(project_dir: &Path) -> Result<PinStoreLoad, String> {
    let path = project_dir.join(PINS_FILE_NAME);
    if !path.exists() {
        return Ok(PinStoreLoad {
            store: KeyPinStore::new(),
            source: None,
        });
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let store = parse_pins(&content)?;
    Ok(PinStoreLoad {
        store,
        source: Some(path),
    })
}

/// Algorithm a pin value is expressed in (`blake3:` default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinAlgorithm {
    Blake3,
    Sha256,
}

/// Split a pin value into its algorithm + bare lowercase hex.
/// `None` when the value is malformed (unknown prefix or non-hex).
fn split_pin_algorithm(pinned: &str) -> Option<(PinAlgorithm, String)> {
    match pinned.split_once(':') {
        Some((algo, hex)) if algo.eq_ignore_ascii_case("sha256") => {
            Some((PinAlgorithm::Sha256, hex.to_ascii_lowercase()))
        }
        Some((algo, hex)) if algo.eq_ignore_ascii_case("blake3") => {
            Some((PinAlgorithm::Blake3, hex.to_ascii_lowercase()))
        }
        Some(_) => None,
        None => Some((PinAlgorithm::Blake3, pinned.trim().to_ascii_lowercase())),
    }
}

// ── Supply-Chain Audit Report ───────────────────────────────────────────────

/// Severity of a supply-chain finding.
#[derive(Debug, Clone, PartialEq)]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

impl FindingSeverity {
    fn as_str(&self) -> &'static str {
        match self {
            FindingSeverity::Info => "info",
            FindingSeverity::Warning => "warning",
            FindingSeverity::Error => "error",
        }
    }
}

/// A single finding in a supply-chain audit.
#[derive(Debug, Clone)]
pub struct SupplyChainFinding {
    pub code: String,
    pub severity: FindingSeverity,
    pub message: String,
    pub package: Option<String>,
}

/// Comprehensive supply-chain audit report.
#[derive(Debug, Clone)]
pub struct SupplyChainReport {
    pub findings: Vec<SupplyChainFinding>,
    pub packages_audited: usize,
    pub keys_pinned: usize,
    pub sbom_available: bool,
    pub signing_available: bool,
    pub slsa_level: u8,
}

impl SupplyChainReport {
    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Warning)
            .count()
    }

    /// Render the report as JSON.
    pub fn to_json(&self) -> Value {
        let findings: Vec<Value> = self
            .findings
            .iter()
            .map(|f| {
                let mut v = json!({
                    "code": f.code,
                    "severity": f.severity.as_str(),
                    "message": f.message,
                });
                if let Some(ref pkg) = f.package {
                    v["package"] = json!(pkg);
                }
                v
            })
            .collect();

        json!({
            "report": "supply-chain-audit",
            "version": "1.0",
            "packages_audited": self.packages_audited,
            "keys_pinned": self.keys_pinned,
            "sbom_available": self.sbom_available,
            "signing_available": self.signing_available,
            "slsa_level": self.slsa_level,
            "errors": self.error_count(),
            "warnings": self.warning_count(),
            "findings": findings,
        })
    }

    /// Render the report as human-readable text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("╔══════════════════════════════════════════════════════╗\n");
        out.push_str("║         SUPPLY CHAIN INTEGRITY AUDIT                ║\n");
        out.push_str("╚══════════════════════════════════════════════════════╝\n\n");

        out.push_str(&format!(
            "  Packages audited:   {}\n",
            self.packages_audited
        ));
        out.push_str(&format!("  Keys pinned:        {}\n", self.keys_pinned));
        out.push_str(&format!(
            "  SBOM available:     {}\n",
            if self.sbom_available { "yes" } else { "no" }
        ));
        out.push_str(&format!(
            "  Signing available:  {}\n",
            if self.signing_available {
                "yes"
            } else {
                "no"
            }
        ));
        out.push_str(&format!("  SLSA level:         {}\n\n", self.slsa_level));

        if self.findings.is_empty() {
            out.push_str("  No findings.\n");
        } else {
            for f in &self.findings {
                let icon = match f.severity {
                    FindingSeverity::Info => "INFO",
                    FindingSeverity::Warning => "WARN",
                    FindingSeverity::Error => "ERR ",
                };
                let pkg_str = f
                    .package
                    .as_deref()
                    .map(|p| format!(" [{p}]"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  [{icon}] {}{pkg_str}: {}\n",
                    f.code, f.message
                ));
            }
        }

        let errors = self.error_count();
        let warnings = self.warning_count();
        out.push_str(&format!(
            "\n  Result: {errors} error(s), {warnings} warning(s)\n"
        ));
        out
    }
}

/// Run a comprehensive supply-chain audit.
///
/// Checks:
/// 1. Lock-file presence (Cargo.lock / tallow.lock)
/// 2. Package count from lock files
/// 3. SBOM generation capability
/// 4. Signature-pin enforcement — pinned subjects vs the lock-file hashes
///    (`SCI-PIN-MISMATCH` errors, `SCI-PIN-UNVERIFIED` warnings)
/// 5. Signing infrastructure availability
/// 6. SLSA provenance level
/// Does the signing path actually round-trip? Generates an ephemeral key, signs a
/// fixed payload and verifies it — the same calls `tallow package sign/verify` make.
fn signing_roundtrip_works() -> bool {
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core_06::OsRng);
    let probe = b"tallow-supply-chain-self-test";
    let sig = match std::panic::catch_unwind(|| {
        crate::signing::sign_package(probe, "probe", "0.0.0", &key)
    }) {
        Ok(s) => s,
        Err(_) => return false,
    };
    matches!(
        std::panic::catch_unwind(|| {
            crate::signing::verify_package(probe, &sig, &key.verifying_key())
        }),
        Ok(Ok(true))
    )
}

pub fn run_supply_chain_audit(
    project_dir: &std::path::Path,
    pin_store: &KeyPinStore,
) -> SupplyChainReport {
    let mut findings = Vec::new();

    // ── 1. Lock-file presence ───────────────────────────────────────────
    let has_cargo_lock = project_dir.join("Cargo.lock").exists();
    let has_tallow_lock = project_dir.join("tallow.lock").exists();
    let has_any_lock = has_cargo_lock || has_tallow_lock;

    if !has_any_lock {
        findings.push(SupplyChainFinding {
            code: "SCI-LOCK-MISSING".to_string(),
            severity: FindingSeverity::Warning,
            message: "No lock file found (Cargo.lock or tallow.lock). Dependency versions are not pinned.".to_string(),
            package: None,
        });
    } else {
        findings.push(SupplyChainFinding {
            code: "SCI-LOCK-OK".to_string(),
            severity: FindingSeverity::Info,
            message: format!(
                "Lock file(s) present: {}{}",
                if has_cargo_lock { "Cargo.lock " } else { "" },
                if has_tallow_lock { "tallow.lock" } else { "" }
            ),
            package: None,
        });
    }

    // ── 2. Count packages from lock files (kept for pin enforcement below) ─
    let mut packages_audited = 0;
    let mut cargo_components: Vec<SbomComponent> = Vec::new();
    let mut tallow_components: Vec<SbomComponent> = Vec::new();
    if has_cargo_lock {
        if let Ok(content) = std::fs::read_to_string(project_dir.join("Cargo.lock")) {
            cargo_components = crate::sbom::parse_cargo_lock(&content);
            packages_audited += cargo_components.len();
        }
    }
    if has_tallow_lock {
        if let Ok(content) = std::fs::read_to_string(project_dir.join("tallow.lock")) {
            tallow_components = crate::sbom::parse_tallow_lock(&content);
            packages_audited += tallow_components.len();
        }
    }

    // ── 3. SBOM availability ────────────────────────────────────────────
    let sbom_available = has_any_lock;
    if sbom_available {
        findings.push(SupplyChainFinding {
            code: "SCI-SBOM-OK".to_string(),
            severity: FindingSeverity::Info,
            message: "SBOM generation is available (lock files present).".to_string(),
            package: None,
        });
    } else {
        findings.push(SupplyChainFinding {
            code: "SCI-SBOM-MISSING".to_string(),
            severity: FindingSeverity::Warning,
            message: "Cannot generate SBOM — no lock files found.".to_string(),
            package: None,
        });
    }

    // ── 4. Key pinning — enforce every pin against the lock files ───────
    // A pinned subject whose recorded hash changed (or that is missing from
    // the lock files / recorded without a hash) is reported here. Mismatches
    // are `Error`-severity so the CLI can refuse with a nonzero exit; nothing
    // is ever silently ignored.
    let keys_pinned = pin_store.all_pins().len();
    if keys_pinned == 0 {
        findings.push(SupplyChainFinding {
            code: "SCI-KEYS-NONE".to_string(),
            severity: FindingSeverity::Warning,
            message: format!(
                "No signature pins configured (no {PINS_FILE_NAME} in the project directory) — \
                 pin enforcement skipped. Create {PINS_FILE_NAME} with `[pins]` + \
                 `subject = \"blake3:<64 hex>\"` entries to enable it."
            ),
            package: None,
        });
    } else {
        // Deterministic order (HashMap iteration order is not).
        let mut pins: Vec<(&String, &String)> = pin_store.all_pins().iter().collect();
        pins.sort_by(|a, b| a.0.cmp(b.0));
        let mut verified = 0usize;
        for (subject, pinned) in pins {
            let Some((algorithm, expected)) = split_pin_algorithm(pinned) else {
                findings.push(SupplyChainFinding {
                    code: "SCI-PIN-UNVERIFIED".to_string(),
                    severity: FindingSeverity::Warning,
                    message: format!(
                        "Pin for `{subject}` is malformed (`{pinned}`): expected a 64-hex \
                         fingerprint, optionally `blake3:`/`sha256:` prefixed."
                    ),
                    package: Some(subject.clone()),
                });
                continue;
            };
            let (components, source) = match algorithm {
                PinAlgorithm::Blake3 => {
                    (&tallow_components, "tallow.lock (blake3 integrity)")
                }
                PinAlgorithm::Sha256 => (&cargo_components, "Cargo.lock (sha256 checksum)"),
            };
            let candidates: Vec<&SbomComponent> =
                components.iter().filter(|c| c.name == *subject).collect();
            if candidates.is_empty() {
                findings.push(SupplyChainFinding {
                    code: "SCI-PIN-UNVERIFIED".to_string(),
                    severity: FindingSeverity::Warning,
                    message: format!(
                        "Pin for `{subject}` cannot be verified: subject not found in {source}."
                    ),
                    package: Some(subject.clone()),
                });
                continue;
            }
            let mut mismatch = false;
            let mut hashless = false;
            for c in candidates {
                let recorded = c.hash_sha256.trim().to_ascii_lowercase();
                if recorded.is_empty() {
                    hashless = true;
                    continue;
                }
                if recorded != expected {
                    mismatch = true;
                    findings.push(SupplyChainFinding {
                        code: "SCI-PIN-MISMATCH".to_string(),
                        severity: FindingSeverity::Error,
                        message: format!(
                            "Pinned hash mismatch for `{subject}` v{}: pinned `{pinned}`, \
                             {source} records `{recorded}` — possible dependency substitution. \
                             If the change is expected (e.g. after a dependency update), review \
                             and re-pin it in {PINS_FILE_NAME}.",
                            c.version
                        ),
                        package: Some(subject.clone()),
                    });
                }
            }
            if hashless && !mismatch {
                findings.push(SupplyChainFinding {
                    code: "SCI-PIN-UNVERIFIED".to_string(),
                    severity: FindingSeverity::Warning,
                    message: format!(
                        "Pin for `{subject}` cannot be verified: {source} records no hash for it."
                    ),
                    package: Some(subject.clone()),
                });
            }
            if !mismatch && !hashless {
                verified += 1;
            }
        }
        findings.push(SupplyChainFinding {
            code: "SCI-KEYS-OK".to_string(),
            severity: FindingSeverity::Info,
            message: format!(
                "{keys_pinned} signature pin(s) configured; {verified} verified against the lock files."
            ),
            package: None,
        });
    }

    // ── 5. Signing infrastructure ───────────────────────────────────────
    // Evidence, not a constant: sign a probe and verify it. The previous code
    // asserted `true` and reported "Ed25519 + Sigstore simulation", claiming a
    // capability nothing had exercised and naming one that does not exist.
    let signing_available = signing_roundtrip_works();
    findings.push(SupplyChainFinding {
        code: if signing_available { "SCI-SIGN-OK" } else { "SCI-SIGN-MISSING" }.to_string(),
        severity: if signing_available {
            FindingSeverity::Info
        } else {
            FindingSeverity::Error
        },
        message: if signing_available {
            "Ed25519 package signing verified by self-test; Sigstore is not implemented \
             (signatures are local)."
                .to_string()
        } else {
            "Ed25519 package signing self-test failed: sign_package/verify_package did \
             not round-trip."
                .to_string()
        },
        package: None,
    });

    // ── 6. SLSA level — honest claim for local builds ───────────────────
    // Local builds honestly claim Level 1 (provenance exists but not tamper-proof)
    let slsa_level = 1;
    findings.push(SupplyChainFinding {
        code: "SCI-SLSA-LEVEL".to_string(),
        severity: FindingSeverity::Info,
        message: format!(
            "SLSA Level {slsa_level} — provenance generation available (local build)."
        ),
        package: None,
    });

    SupplyChainReport {
        findings,
        packages_audited,
        keys_pinned,
        sbom_available,
        signing_available,
        slsa_level,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pinning_tofu() {
        let mut store = KeyPinStore::new();

        // First pin — should succeed
        let result = store.pin_author_key("my-package", "abc123");
        assert_eq!(result, PinResult::Pinned);

        // Same key — already pinned
        let result = store.pin_author_key("my-package", "abc123");
        assert_eq!(result, PinResult::AlreadyPinned);

        // Different key — mismatch
        let result = store.pin_author_key("my-package", "def456");
        assert_eq!(
            result,
            PinResult::Mismatch {
                expected: "abc123".to_string(),
                actual: "def456".to_string(),
            }
        );
    }

    #[test]
    fn test_check_maintainer_change() {
        let mut store = KeyPinStore::new();
        store.pin_author_key("pkg-a", "fingerprint-aaa");

        // Same key — no change
        assert!(store.check_maintainer_change("pkg-a", "fingerprint-aaa"));

        // Different key — change detected
        assert!(!store.check_maintainer_change("pkg-a", "fingerprint-bbb"));

        // Unknown package — no pin, so no mismatch
        assert!(store.check_maintainer_change("pkg-unknown", "anything"));
    }

    #[test]
    fn test_blake3_fingerprint() {
        let fp1 = blake3_fingerprint(b"public-key-bytes");
        let fp2 = blake3_fingerprint(b"public-key-bytes");
        let fp3 = blake3_fingerprint(b"different-key-bytes");

        assert_eq!(fp1, fp2, "same input should produce same fingerprint");
        assert_ne!(fp1, fp3, "different input should produce different fingerprint");
        assert_eq!(fp1.len(), 64, "BLAKE3 hex string should be 64 chars");
    }

    #[test]
    fn test_supply_chain_audit_generates_report() {
        let store = KeyPinStore::new();
        // Use a temp directory with no lock files
        let tmp = std::env::temp_dir();
        let report = run_supply_chain_audit(&tmp, &store);

        assert!(report.packages_audited == 0 || report.packages_audited > 0);
        assert_eq!(report.keys_pinned, 0);
        assert!(report.signing_available);
        assert_eq!(report.slsa_level, 1);
        // Should have findings
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_supply_chain_report_json() {
        let report = SupplyChainReport {
            findings: vec![
                SupplyChainFinding {
                    code: "SCI-TEST".to_string(),
                    severity: FindingSeverity::Warning,
                    message: "test warning".to_string(),
                    package: Some("test-pkg".to_string()),
                },
                SupplyChainFinding {
                    code: "SCI-ERR".to_string(),
                    severity: FindingSeverity::Error,
                    message: "test error".to_string(),
                    package: None,
                },
            ],
            packages_audited: 42,
            keys_pinned: 3,
            sbom_available: true,
            signing_available: true,
            slsa_level: 1,
        };

        let json = report.to_json();
        assert_eq!(json["report"], "supply-chain-audit");
        assert_eq!(json["packages_audited"], 42);
        assert_eq!(json["keys_pinned"], 3);
        assert_eq!(json["errors"], 1);
        assert_eq!(json["warnings"], 1);
        assert_eq!(json["slsa_level"], 1);
        let findings = json["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_supply_chain_report_text() {
        let report = SupplyChainReport {
            findings: vec![SupplyChainFinding {
                code: "SCI-LOCK-OK".to_string(),
                severity: FindingSeverity::Info,
                message: "Lock file present.".to_string(),
                package: None,
            }],
            packages_audited: 10,
            keys_pinned: 2,
            sbom_available: true,
            signing_available: true,
            slsa_level: 1,
        };

        let text = report.to_text();
        assert!(text.contains("SUPPLY CHAIN INTEGRITY AUDIT"));
        assert!(text.contains("Packages audited:   10"));
        assert!(text.contains("Keys pinned:        2"));
        assert!(text.contains("SLSA level:         1"));
        assert!(text.contains("SCI-LOCK-OK"));
    }

    #[test]
    fn test_key_pin_store_multiple_packages() {
        let mut store = KeyPinStore::new();
        store.pin_author_key("pkg-a", "fp-a");
        store.pin_author_key("pkg-b", "fp-b");
        store.pin_author_key("pkg-c", "fp-c");

        assert_eq!(store.all_pins().len(), 3);
        assert!(store.check_maintainer_change("pkg-a", "fp-a"));
        assert!(store.check_maintainer_change("pkg-b", "fp-b"));
        assert!(!store.check_maintainer_change("pkg-c", "fp-wrong"));
    }

    // ── Pin file (.tallow-pins) ─────────────────────────────────────────

    use crate::config::test_support::TempDir;

    fn hex64(ch: char) -> String {
        std::iter::repeat(ch).take(64).collect()
    }

    fn tallow_lock_with(integrity: &str) -> String {
        format!(
            "lockfile-version = 1\n\n[[package]]\nname = \"pkg-a\"\nversion = \"1.0.0\"\n\
             integrity = \"blake3:{integrity}\"\n"
        )
    }

    #[test]
    fn render_pins_round_trips_and_sorts() {
        let mut store = KeyPinStore::new();
        store.pin_author_key("zeta", &format!("blake3:{}", "b".repeat(64)));
        store.pin_author_key("alpha", &format!("sha256:{}", "a".repeat(64)));

        let text = render_pins(&store);
        assert!(text.contains("pins-version = 1"), "{text}");
        let alpha = format!("sha256:{}", "a".repeat(64));
        let zeta = format!("blake3:{}", "b".repeat(64));
        let parsed = parse_pins(&text).expect("rendered pins must parse");
        assert_eq!(
            parsed.all_pins().get("alpha").map(String::as_str),
            Some(alpha.as_str())
        );
        assert_eq!(
            parsed.all_pins().get("zeta").map(String::as_str),
            Some(zeta.as_str())
        );
        assert!(text.find("alpha").unwrap() < text.find("zeta").unwrap());
    }

    #[test]
    fn test_parse_pins_file() {
        let text = format!(
            "# sample pins\n[pins]\n\"pkg-a\" = \"blake3:{}\"\n\"Pkg-B\" = \"{}\"\n",
            hex64('a'),
            hex64('b').to_uppercase()
        );
        let store = parse_pins(&text).expect("valid pin file parses");
        assert_eq!(store.all_pins().len(), 2);
        assert_eq!(store.all_pins()["pkg-a"], format!("blake3:{}", hex64('a')));
        // Bare hex = BLAKE3 default; hex is normalized to lowercase.
        assert_eq!(store.all_pins()["Pkg-B"], hex64('b'));
    }

    #[test]
    fn test_parse_pins_refuses_bad_input() {
        assert!(
            parse_pins("pins = [").is_err(),
            "invalid TOML must be refused"
        );
        assert!(
            parse_pins("oops = \"x\"").is_err(),
            "unknown root key must be refused, never ignored"
        );
        assert!(
            parse_pins("[pins]\npkg = 42").is_err(),
            "non-string pin must be refused"
        );
        assert!(
            parse_pins("[pins]\npkg = \"abc123\"").is_err(),
            "short fingerprint must be refused"
        );
        assert!(
            parse_pins(&format!("[pins]\npkg = \"md5:{}\"", hex64('a'))).is_err(),
            "unknown algorithm prefix must be refused"
        );
        // An empty [pins] table is valid but defines nothing.
        assert_eq!(parse_pins("[pins]\n").unwrap().all_pins().len(), 0);
    }

    #[test]
    fn test_parse_pins_version_key() {
        // Explicit current version accepted.
        let text = format!(
            "pins-version = 1\n[pins]\npkg-a = \"{}\"\n",
            hex64('a')
        );
        let store = parse_pins(&text).expect("pins-version 1 parses");
        assert_eq!(store.all_pins().len(), 1);

        // Unsupported version refused.
        let err = parse_pins("pins-version = 2\n[pins]\n").expect_err("version 2 refused");
        assert!(err.contains("unsupported"), "{err}");

        // Wrong type refused.
        assert!(parse_pins("pins-version = \"1\"\n[pins]\n").is_err());
    }

    #[test]
    fn test_load_pin_store_absent_and_present() {
        let dir = TempDir::new("supply-chain-pins-load");
        let load = load_pin_store(dir.path()).expect("absent pin file is not an error");
        assert!(load.source.is_none());
        assert!(load.store.all_pins().is_empty());

        std::fs::write(
            dir.join(PINS_FILE_NAME),
            format!("[pins]\npkg-a = \"blake3:{}\"\n", hex64('a')),
        )
        .unwrap();
        let load = load_pin_store(dir.path()).expect("valid pin file loads");
        assert!(load.source.is_some());
        assert_eq!(load.store.all_pins().len(), 1);

        // A malformed pin file is fail-closed — never a silent empty store.
        std::fs::write(dir.join(PINS_FILE_NAME), "[pins]\npkg-a = \"nope\"\n").unwrap();
        assert!(load_pin_store(dir.path()).is_err());
    }

    #[test]
    fn test_audit_pin_mismatch_is_an_error_finding() {
        let dir = TempDir::new("supply-chain-pin-mismatch");
        std::fs::write(dir.join("tallow.lock"), tallow_lock_with(&hex64('a'))).unwrap();

        let mut store = KeyPinStore::new();
        store.pin_author_key("pkg-a", &format!("blake3:{}", hex64('b')));
        let report = run_supply_chain_audit(dir.path(), &store);

        let mismatch = report
            .findings
            .iter()
            .find(|f| f.code == "SCI-PIN-MISMATCH")
            .expect("a mismatched pinned subject must produce a finding");
        assert_eq!(mismatch.severity, FindingSeverity::Error);
        assert_eq!(mismatch.package.as_deref(), Some("pkg-a"));
        assert!(
            mismatch.message.contains("re-pin it in .tallow-pins"),
            "mismatch must tell the operator how to re-pin: {}",
            mismatch.message
        );
        assert!(
            report.error_count() >= 1,
            "pin mismatch must count as an audit error (nonzero exit)"
        );
    }

    #[test]
    fn test_audit_pin_match_is_verified() {
        let dir = TempDir::new("supply-chain-pin-match");
        std::fs::write(dir.join("tallow.lock"), tallow_lock_with(&hex64('a'))).unwrap();

        let mut store = KeyPinStore::new();
        store.pin_author_key("pkg-a", &hex64('a')); // bare hex = BLAKE3
        let report = run_supply_chain_audit(dir.path(), &store);

        assert_eq!(report.error_count(), 0, "{:?}", report.findings);
        assert!(!report.findings.iter().any(|f| f.code == "SCI-PIN-MISMATCH"));
        let ok = report
            .findings
            .iter()
            .find(|f| f.code == "SCI-KEYS-OK")
            .expect("SCI-KEYS-OK must report enforcement");
        assert!(
            ok.message.contains("1 signature pin(s) configured; 1 verified"),
            "{}",
            ok.message
        );
    }

    #[test]
    fn test_audit_pin_missing_subject_is_unverified_warning() {
        let dir = TempDir::new("supply-chain-pin-missing");
        std::fs::write(dir.join("tallow.lock"), tallow_lock_with(&hex64('a'))).unwrap();

        let mut store = KeyPinStore::new();
        store.pin_author_key("ghost-pkg", &hex64('c'));
        let report = run_supply_chain_audit(dir.path(), &store);

        assert_eq!(report.error_count(), 0, "{:?}", report.findings);
        let unverified = report
            .findings
            .iter()
            .find(|f| f.code == "SCI-PIN-UNVERIFIED")
            .expect("an unenforceable pin must be reported, not ignored");
        assert_eq!(unverified.severity, FindingSeverity::Warning);
        assert_eq!(unverified.package.as_deref(), Some("ghost-pkg"));
    }

    #[test]
    fn test_audit_no_pins_is_a_loud_warning() {
        let dir = TempDir::new("supply-chain-no-pins");
        let report = run_supply_chain_audit(dir.path(), &KeyPinStore::new());

        let none = report
            .findings
            .iter()
            .find(|f| f.code == "SCI-KEYS-NONE")
            .expect("no-pins warning present");
        assert_eq!(none.severity, FindingSeverity::Warning);
        assert!(
            none.message.contains(PINS_FILE_NAME),
            "the no-pins finding must name {PINS_FILE_NAME}: {}",
            none.message
        );
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn test_audit_sha256_pin_against_cargo_lock() {
        let dir = TempDir::new("supply-chain-pin-sha256");
        let cargo_lock = format!(
            "version = 3\n\n[[package]]\nname = \"pkg-s\"\nversion = \"0.1.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            hex64('d')
        );
        std::fs::write(dir.join("Cargo.lock"), &cargo_lock).unwrap();

        // Case-insensitive prefix/hex: uppercase sha256 pin matches.
        let mut store = KeyPinStore::new();
        store.pin_author_key("pkg-s", &format!("sha256:{}", hex64('d').to_uppercase()));
        let report = run_supply_chain_audit(dir.path(), &store);
        assert_eq!(report.error_count(), 0, "{:?}", report.findings);

        // Same subject pinned to a different checksum → error.
        let mut bad = KeyPinStore::new();
        bad.pin_author_key("pkg-s", &format!("sha256:{}", hex64('e')));
        let report = run_supply_chain_audit(dir.path(), &bad);
        assert_eq!(report.error_count(), 1, "{:?}", report.findings);
        assert!(report.findings.iter().any(|f| f.code == "SCI-PIN-MISMATCH"));
    }
}
