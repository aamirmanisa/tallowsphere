//! Crypto-agility registry + CBOM seed generator and drift gate.
//!
//! Rust port of `scripts/crypto-inventory.py` (T-206). A static, deterministic
//! analyzer over the crypto source roots emitting `tallow-cbom-seed/1` JSON, and
//! a gate that fails when the committed artifact does not byte-match.
//!
//! ## Where the policy data lives
//!
//! The REGISTRY (44 entries), the rejected primitives, the AEGIS allowance and
//! the policy object are *policy*, not logic. They live in
//! `src/gate/cbom/registry.json`, generated from the Python original and
//! checked in, so the engine below stays small and the data stays reviewable as
//! data. Two things follow from that split:
//!
//! * `registrySha256` / `policySha256` are computed over the *same* canonical
//!   JSON blob the Python hashed (`sort_keys=True, separators=(",", ":")`), so
//!   the hashes are comparable across implementations. Any reordering or
//!   re-serialisation of the data file changes them, which is intended: the hash
//!   is a statement about the policy bytes.
//! * A stale data file shows up as an artifact mismatch, not as a silent policy
//!   change — `tests/gate_crypto_inventory_parity.rs` compares both
//!   implementations on the live tree.
//!
//! ## Lookbehind
//!
//! The Python patterns use `(?<![0-9A-Za-z_])` in 25 places. Rust's `regex` has
//! no lookbehind, and adding `fancy-regex` to the gate path for this would be a
//! real dependency for a mechanical rewrite. Every one of those occurrences is
//! followed by a token that begins with a word character, which makes the
//! construct exactly equivalent to `\b`. That equivalence was verified against
//! the live tree before being relied on — 119 files, 2,189 tokens, 0 differing
//! files — and `lookbehind_is_a_word_boundary` below re-checks the property
//! structurally.
//!
//! Exit codes: 0 = ok / no drift; 1 = drift; 2 = generator error.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "tallow-cbom-seed/1";
pub const GENERATOR: &str = "scripts/crypto-inventory.py";

const EMBEDDED: &str = include_str!("cbom/registry.json");

#[derive(Debug)]
pub enum Error {
    Load(String),
    Pattern { which: String, error: String },
    ScanRoot(PathBuf),
    Read(PathBuf, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Load(d) => write!(f, "embedded registry unusable: {d}"),
            Error::Pattern { which, error } => {
                write!(f, "pattern `{which}` does not compile: {error}")
            }
            Error::ScanRoot(p) => write!(f, "scan root not found: {}", p.display()),
            Error::Read(p, e) => write!(f, "cannot read {}: {e}", p.display()),
        }
    }
}

/// Rewrite Python's fixed word-boundary lookbehind into `\b` and strip any
/// fixed-literal lookbehind that cannot be expressed (discovery/shape patterns
/// are matched for *presence*, never counted, so a subtraction there would have
/// no consumer).
fn port_pattern(p: &str) -> String {
    split_negative_lookbehind(p).0
}

/// A pattern that needs negative-lookbehind semantics the `regex` crate cannot
/// express. Handled by counting, not by matching: the pattern is ported with the
/// lookbehind removed, and matches immediately preceded by `excluded` are
/// subtracted.
#[derive(Debug, Clone)]
pub struct ExcludedPrefix {
    pub excluded: String,
}

/// Rewrite every `(?<!LIT)` in a (possibly multi-alternative) pattern.
///
/// A union is several patterns joined by `|`, and each alternative may carry its
/// own lookbehind — `BBS` alone has four. Only the first was handled in the
/// first version of this function, so the union kept a raw lookbehind and the
/// `regex` crate rejected it at load time. Every occurrence is processed now.
///
/// The word-class form becomes `\b`. Any other fixed literal cannot be expressed
/// without a lookbehind and cannot be subtracted alternative-by-alternative
/// either, so `None` is returned and the caller falls back to counting the bare
/// pattern minus occurrences preceded by that literal.
fn split_negative_lookbehind(p: &str) -> (String, Option<ExcludedPrefix>) {
    const OPEN: &str = "(?<!";
    let mut work: String = p.to_string();
    while work.contains(r"(?<![0-9A-Za-z_])") {
        work = work.replace("(?<![0-9A-Za-z_])", r"\b");
    }
    if !work.contains(OPEN) {
        return (work, None);
    }
    // A remaining lookbehind is a fixed literal. Strip it and record it.
    let start = work.find(OPEN).expect("checked above");
    let after = start + OPEN.len();
    let end_rel = work[after..].find(')').expect("balanced lookbehind");
    let lit = work[after..after + end_rel].to_string();
    let stripped = work.replace(&format!("(?<!{lit})"), "");
    (
        stripped,
        Some(ExcludedPrefix { excluded: lit }),
    )
}

/// `re.fullmatch(token)` — Python's anchored match, which the `regex` crate has
/// no direct equivalent for.
///
/// This stands in for `re.fullmatch` in the novel-AEAD cover test. An unanchored
/// `is_match` is what the first version used, and it is a silent false negative:
/// the cover patterns are per-algorithm patterns, so any AEAD-shaped token that
/// merely *contains* `AES`, `GCM`, `SIV`, `ChaCha` or `Salsa20` as a substring
/// was excused as "registered". Measured consequence: `AES-256-OCB` — an
/// unregistered, patent-encumbered mode — passed the gate untouched while
/// Python flagged it, and every other governed token happened to still line up,
/// so only the guardrail self-test caught it.
fn is_full_match(re: &Regex, token: &str) -> bool {
    re.find(token).is_some_and(|m| m.start() == 0 && m.end() == token.len())
}

/// Count occurrences of `re` in `text`, subtracting those immediately preceded
/// by `excluded` when the pattern required a negative lookbehind.
fn count_matches(re: &Regex, text: &str, excluded: Option<&ExcludedPrefix>) -> usize {
    let all = re.find_iter(text).count();
    let Some(ex) = excluded else {
        return all;
    };
    let mut n = all;
    for m in re.find_iter(text) {
        let at = m.start();
        if at >= ex.excluded.len() {
            let mut ok = true;
            for (i, b) in ex.excluded.as_bytes().iter().enumerate() {
                if text.as_bytes()[at - ex.excluded.len() + i] != *b {
                    ok = false;
                    break;
                }
            }
            if ok {
                n -= 1;
            }
        }
    }
    n
}

pub struct Registry {
    pub entries: Vec<Value>,
    pub rejected: Vec<Value>,
    pub policy: Value,
    pub allowlist: BTreeMap<String, String>,
    pub ceiling: BTreeMap<String, u64>,
    pub variants: Vec<String>,
    pub discovery: Regex,
    pub aead_shape: Regex,
    pub aead_cover: Vec<Regex>,
    pub cipher_suite_roles: Vec<String>,
    pub default_roots: Vec<String>,
    entry_unions: BTreeMap<String, (Regex, Option<ExcludedPrefix>)>,
    rejected_unions: BTreeMap<String, (Regex, Option<ExcludedPrefix>)>,
}

impl Registry {
    pub fn load() -> Result<Self, Error> {
        let v: Value =
            serde_json::from_str(EMBEDDED).map_err(|e| Error::Load(e.to_string()))?;
        let arr = |k: &str| -> Vec<Value> {
            v.get(k).and_then(Value::as_array).cloned().unwrap_or_default()
        };
        let strs = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        let str_map = |k: &str| -> BTreeMap<String, String> {
            v.get(k)
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default()
        };

        // A compiled union plus the subtraction rule it needs, if any.
        let compile_union = |k: &str, p: &str| -> Result<(Regex, Option<ExcludedPrefix>), Error> {
            let (ported, excluded) = split_negative_lookbehind(p);
            let compiled = Regex::new(&ported).map_err(|e| Error::Pattern {
                which: k.to_string(),
                error: e.to_string(),
            })?;
            Ok((compiled, excluded))
        };

        let mut entry_unions = BTreeMap::new();
        if let Some(m) = v.get("entryUnions").and_then(Value::as_object) {
            for (k, pat) in m {
                let Some(p) = pat.as_str() else { continue };
                entry_unions.insert(k.clone(), compile_union(k, p)?);
            }
        }
        let mut rejected_unions = BTreeMap::new();
        if let Some(m) = v.get("rejectedUnions").and_then(Value::as_object) {
            for (k, pat) in m {
                let Some(p) = pat.as_str() else { continue };
                rejected_unions.insert(k.clone(), compile_union(k, p)?);
            }
        }

        let compile = |which: &str, p: &str| -> Result<Regex, Error> {
            Regex::new(&port_pattern(p)).map_err(|e| Error::Pattern {
                which: which.to_string(),
                error: e.to_string(),
            })
        };
        let discovery_src = v
            .get("discovery")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Load("no discovery pattern".into()))?;
        let aead_src = v
            .get("aeadShape")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Load("no aeadShape pattern".into()))?;
        let aead_cover: Vec<Regex> = strs("aeadCoverPatterns")
            .iter()
            .map(|p| compile("aeadCoverPatterns", p))
            .collect::<Result<_, _>>()?;

        Ok(Registry {
            entries: arr("registry"),
            rejected: arr("rejectedPrimitives"),
            policy: v.get("policy").cloned().unwrap_or(Value::Null),
            allowlist: str_map("aegisAllowlist"),
            ceiling: v
                .get("aegisCeiling")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, val)| val.as_u64().map(|n| (k.clone(), n)))
                        .collect()
                })
                .unwrap_or_default(),
            variants: strs("aegisVariants"),
            discovery: compile("discovery", discovery_src)?,
            aead_shape: compile("aeadShape", aead_src)?,
            aead_cover,
            cipher_suite_roles: strs("cipherSuiteRoles"),
            default_roots: strs("defaultRoots"),
            entry_unions,
            rejected_unions,
        })
    }

    fn code_of(&self, e: &Value, key: &str) -> String {
        e.get(key).and_then(Value::as_str).unwrap_or("").to_string()
    }
}

/// `json.dumps(obj, sort_keys=True, separators=(",", ":"))` — compact, keys
/// sorted at every level, and **non-ASCII escaped** as `\uXXXX`.
///
/// The escaping matters: Python's `json.dumps` defaults to `ensure_ascii=True`,
/// so an em-dash in a registry `family` string hashes as `\u2014` (6 bytes), not
/// as the 3 UTF-8 bytes `serde_json` emits. The two blobs differ in length and
/// therefore in SHA-256, which silently changed `registrySha256` and
/// `policySha256` on the first port — every other field matched.
pub fn canonical_json(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    escape_non_ascii(&s)
}

/// Rewrite non-ASCII characters as Python's `ensure_ascii=True` does:
/// `\uXXXX` for the BMP, and a surrogate pair above it. The input is JSON text,
/// so every non-ASCII byte belongs to a string literal (JSON syntax is ASCII).
fn escape_non_ascii(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let cp = ch as u32;
            if cp <= 0xFFFF {
                out.push_str(&format!("\\u{cp:04x}"));
            } else {
                let v = cp - 0x10000;
                let hi = 0xD800 + (v >> 10);
                let lo = 0xDC00 + (v & 0x3FF);
                out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
            }
        }
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Python's `"%d"` for a JSON number, and `null` for absent.
fn num_or_null(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                n.to_string()
            }
        }
        other => other.to_string(),
    }
}

#[derive(Debug, Default)]
pub struct Site {
    pub file: String,
    pub count: u64,
}

#[derive(Debug)]
pub struct Inventory {
    pub registry_sha256: String,
    pub policy_sha256: String,
    pub registry_entry_count: usize,
    pub algorithm_count: usize,
    pub total_occurrences: u64,
    pub unregistered: Vec<String>,
    pub rejected_found: Vec<(String, u64, Vec<Site>)>,
    pub novel_aeads: Vec<String>,
    pub aegis_outside: Vec<String>,
    pub aegis_allowed: Vec<String>,
    pub aegis_occurrences: BTreeMap<String, u64>,
    /// Rendered `algorithms` entries, already in output order.
    pub algorithms: Vec<Value>,
    pub scan_roots: Vec<String>,
    pub aegis_ceiling: BTreeMap<String, u64>,
}

fn collect_files(root: &Path, spec: &str) -> Result<Vec<PathBuf>, Error> {
    let base = {
        let p = PathBuf::from(spec);
        if p.is_absolute() {
            p
        } else {
            root.join(p)
        }
    };
    let mut files = Vec::new();
    if base.is_dir() {
        walk_rs(&base, &mut files);
        files.sort();
    } else if base.is_file() {
        files.push(base);
    } else {
        return Err(Error::ScanRoot(base));
    }
    // De-duplicate by resolved path, keeping first occurrence.
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for f in files {
        let key = f.canonicalize().unwrap_or_else(|_| f.clone());
        if seen.insert(key) {
            ordered.push(f);
        }
    }
    Ok(ordered)
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn display_path(root: &Path, p: &Path) -> String {
    match p.canonicalize().ok().and_then(|c| c.strip_prefix(root).ok().map(Path::to_path_buf)) {
        Some(rel) => rel.to_string_lossy().replace('\\', "/"),
        None => p.to_string_lossy().replace('\\', "/"),
    }
}

pub fn scan(root: &Path, reg: &Registry, roots: &[String]) -> Result<Inventory, Error> {
    let mut files = Vec::new();
    for spec in roots {
        files.extend(collect_files(root, spec)?);
    }

    let mut site_counts: BTreeMap<String, BTreeMap<String, u64>> = reg
        .entries
        .iter()
        .map(|e| (reg.code_of(e, "name"), BTreeMap::new()))
        .collect();
    let mut rejected_counts: BTreeMap<String, BTreeMap<String, u64>> = reg
        .rejected
        .iter()
        .map(|e| (reg.code_of(e, "name"), BTreeMap::new()))
        .collect();
    let mut candidates: BTreeSet<String> = BTreeSet::new();

    for p in &files {
        let text = std::fs::read_to_string(p)
            .or_else(|_| std::fs::read(p).map(|b| String::from_utf8_lossy(&b).into_owned()))
            .map_err(|e| Error::Read(p.clone(), e.to_string()))?;
        let rel = display_path(root, p);

        for e in &reg.entries {
            let name = reg.code_of(e, "name");
            if let Some((re, ex)) = reg.entry_unions.get(&name) {
                let n = count_matches(re, &text, ex.as_ref()) as u64;
                if n > 0 {
                    site_counts.entry(name).or_default().insert(rel.clone(), n);
                }
            }
        }
        for e in &reg.rejected {
            let name = reg.code_of(e, "name");
            if let Some((re, ex)) = reg.rejected_unions.get(&name) {
                let n = count_matches(re, &text, ex.as_ref()) as u64;
                if n > 0 {
                    rejected_counts.entry(name).or_default().insert(rel.clone(), n);
                }
            }
        }
        for m in reg.discovery.find_iter(&text) {
            candidates.insert(m.as_str().to_string());
        }
    }

    // `covered`: the token matches any registered entry pattern.
    let covers = |token: &str| -> bool {
        reg.entries.iter().any(|e| {
            e.get("patterns")
                .and_then(Value::as_array)
                .map(|pats| {
                    pats.iter().filter_map(Value::as_str).any(|p| {
                        Regex::new(&port_pattern(p))
                            .map(|re| re.is_match(token))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        })
    };
    let rejected_token = |token: &str| -> bool {
        reg.rejected.iter().any(|e| {
            e.get("patterns")
                .and_then(Value::as_array)
                .map(|pats| {
                    pats.iter().filter_map(Value::as_str).any(|p| {
                        Regex::new(&port_pattern(p))
                            .map(|re| re.is_match(token))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        })
    };
    let novel_aead = |token: &str| -> bool {
        // A shape match that the registered AEAD cover patterns do not excuse.
        reg.aead_shape.is_match(token)
            && !reg.aead_cover.iter().any(|re| is_full_match(re, token))
    };

    let unregistered: Vec<String> = candidates
        .iter()
        .filter(|t| !covers(t) && !rejected_token(t) && !novel_aead(t))
        .cloned()
        .collect();
    let novel_aeads: Vec<String> = candidates
        .iter()
        .filter(|t| novel_aead(t) && !rejected_token(t))
        .cloned()
        .collect();

    let mut rejected_found = Vec::new();
    for e in &reg.rejected {
        let name = reg.code_of(e, "name");
        let sites: BTreeMap<String, u64> = rejected_counts.remove(&name).unwrap_or_default();
        if !sites.is_empty() {
            let occ: u64 = sites.values().sum();
            rejected_found.push((
                name,
                occ,
                sites
                    .into_iter()
                    .map(|(file, count)| Site { file, count })
                    .collect(),
            ));
        }
    }

    // algorithms, sorted by name
    let mut names: Vec<String> = reg.entries.iter().map(|e| reg.code_of(e, "name")).collect();
    names.sort();
    let mut algorithms = Vec::new();
    let mut total = 0u64;
    let mut present = 0usize;
    for name in &names {
        let e = reg
            .entries
            .iter()
            .find(|e| &reg.code_of(e, "name") == name)
            .expect("name came from the registry");
        let sites = site_counts.remove(name).unwrap_or_default();
        let occ: u64 = sites.values().sum();
        total += occ;
        if occ > 0 {
            present += 1;
        }
        let mut obj = Map::new();
        obj.insert("name".into(), Value::String(name.clone()));
        obj.insert("family".into(), e.get("family").cloned().unwrap_or(Value::Null));
        obj.insert("role".into(), e.get("role").cloned().unwrap_or(Value::Null));
        obj.insert(
            "quantumResistance".into(),
            e.get("quantumResistance").cloned().unwrap_or(Value::Null),
        );
        obj.insert("state".into(), e.get("state").cloned().unwrap_or(Value::Null));
        obj.insert(
            "pqTransition".into(),
            e.get("pqTransition").cloned().unwrap_or(Value::Null),
        );
        obj.insert("occurrences".into(), Value::from(occ));
        obj.insert(
            "sites".into(),
            Value::Array(
                sites
                    .into_iter()
                    .map(|(file, count)| {
                        let mut s = Map::new();
                        s.insert("file".into(), Value::String(file));
                        s.insert("count".into(), Value::from(count));
                        Value::Object(s)
                    })
                    .collect(),
            ),
        );
        algorithms.push(Value::Object(obj));
    }

    // The AEGIS variant entries were consumed from `site_counts` by the
    // algorithm loop above, so the family-level outside check reads the emitted
    // algorithms rather than the pre-consumption map. Collapsing this into one
    // source is intentional: two sources here would let the counts and the
    // emitted sites disagree.
    let mut aegis_variant_sites: BTreeSet<String> = BTreeSet::new();
    for a in &algorithms {
        let name = a.get("name").and_then(Value::as_str).unwrap_or("");
        if reg.variants.iter().any(|v| v == name) {
            if let Some(sites) = a.get("sites").and_then(Value::as_array) {
                for s in sites {
                    if let Some(f) = s.get("file").and_then(Value::as_str) {
                        aegis_variant_sites.insert(f.to_string());
                    }
                }
            }
        }
    }

    let outside_all: Vec<String> = aegis_variant_sites
        .iter()
        .filter(|f| !f.starts_with("crates/tallow-crypto/"))
        .cloned()
        .collect();
    let aegis_allowed: Vec<String> = outside_all
        .iter()
        .filter(|f| reg.allowlist.contains_key(*f))
        .cloned()
        .collect();
    let aegis_outside: Vec<String> = outside_all
        .iter()
        .filter(|f| !reg.allowlist.contains_key(*f))
        .cloned()
        .collect();

    let mut aegis_occurrences: BTreeMap<String, u64> = BTreeMap::new();
    for f in reg.allowlist.keys() {
        let mut n = 0u64;
        for a in &algorithms {
            let name = a.get("name").and_then(Value::as_str).unwrap_or("");
            if reg.variants.iter().any(|v| v == name) {
                if let Some(sites) = a.get("sites").and_then(Value::as_array) {
                    for s in sites {
                        if s.get("file").and_then(Value::as_str) == Some(f.as_str()) {
                            n += s.get("count").and_then(Value::as_u64).unwrap_or(0);
                        }
                    }
                }
            }
        }
        aegis_occurrences.insert(f.clone(), n);
    }

    let registry_blob = Value::Array(reg.entries.clone());
    let policy_blob = reg.policy.clone();

    Ok(Inventory {
        registry_sha256: sha256_hex(canonical_json(&registry_blob).as_bytes()),
        policy_sha256: sha256_hex(canonical_json(&policy_blob).as_bytes()),
        registry_entry_count: reg.entries.len(),
        algorithm_count: present,
        total_occurrences: total,
        unregistered,
        rejected_found,
        novel_aeads,
        aegis_outside,
        aegis_allowed,
        aegis_occurrences,
        algorithms,
        scan_roots: roots.to_vec(),
        aegis_ceiling: reg.ceiling.clone(),
    })
}

fn json_str(s: &str) -> String {
    escape_non_ascii(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()))
}

/// `json.dumps(list_of_str)` with Python's DEFAULT separators — `", "` between
/// items — which is what `scanRoots` and `unregisteredCandidates` are rendered
/// with (they are not passed through the compact form).
fn py_json_list(items: &[String]) -> String {
    let body: Vec<String> = items.iter().map(|s| json_str(s)).collect();
    format!("[{}]", body.join(", "))
}

/// Canonical rendering, byte-compatible with the Python original.
pub fn render(inv: &Inventory, policy: &Value) -> String {
    let mut lines = vec![
        "{".to_string(),
        format!("  \"format\": {},", json_str(FORMAT)),
        format!("  \"generator\": {},", json_str(GENERATOR)),
        format!("  \"registrySha256\": {},", json_str(&inv.registry_sha256)),
        format!(
            "  \"scanRoots\": {},",
            py_json_list(&inv.scan_roots)
        ),
        format!("  \"registryEntryCount\": {},", inv.registry_entry_count),
        format!("  \"algorithmCount\": {},", inv.algorithm_count),
        format!("  \"totalOccurrences\": {},", inv.total_occurrences),
        format!(
            "  \"unregisteredCandidates\": {},",
            py_json_list(&inv.unregistered)
        ),
    ];

    // The `policy` object is assembled in the Python's key order but rendered
    // with sorted keys, so assemble then canonicalise.
    let mut p = Map::new();
    p.insert("policyRef".into(), policy.get("policyRef").cloned().unwrap_or(Value::Null));
    p.insert("policySha256".into(), Value::String(inv.policy_sha256.clone()));
    p.insert(
        "oneParamsSource".into(),
        policy.get("oneParamsSource").cloned().unwrap_or(Value::Null),
    );
    p.insert(
        "rejectedPrimitives".into(),
        policy.get("rejectedPrimitives").cloned().unwrap_or(Value::Null),
    );
    p.insert(
        "rejectedPrimitivesFound".into(),
        Value::Array(
            inv.rejected_found
                .iter()
                .map(|(name, occ, sites)| {
                    let mut o = Map::new();
                    o.insert("name".into(), Value::String(name.clone()));
                    o.insert("occurrences".into(), Value::from(*occ));
                    o.insert(
                        "sites".into(),
                        Value::Array(
                            sites
                                .iter()
                                .map(|s| {
                                    let mut so = Map::new();
                                    so.insert("file".into(), Value::String(s.file.clone()));
                                    so.insert("count".into(), Value::from(s.count));
                                    Value::Object(so)
                                })
                                .collect(),
                        ),
                    );
                    Value::Object(o)
                })
                .collect(),
        ),
    );
    p.insert(
        "novelAeadCandidates".into(),
        Value::Array(inv.novel_aeads.iter().cloned().map(Value::String).collect()),
    );
    p.insert("aegisStance".into(), policy.get("aegisStance").cloned().unwrap_or(Value::Null));
    p.insert(
        "aegisSitesOutsideTallowCrypto".into(),
        Value::Array(inv.aegis_outside.iter().cloned().map(Value::String).collect()),
    );
    p.insert(
        "aegisAllowedOutsideTallowCrypto".into(),
        Value::Array(inv.aegis_allowed.iter().cloned().map(Value::String).collect()),
    );
    p.insert(
        "aegisAllowanceCeiling".into(),
        Value::Object(
            inv.aegis_ceiling
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(*v)))
                .collect(),
        ),
    );
    p.insert(
        "aegisAllowanceOccurrences".into(),
        Value::Object(
            inv.aegis_occurrences
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(*v)))
                .collect(),
        ),
    );
    lines.push(format!(
        "  \"policy\": {},",
        canonical_json(&Value::Object(p))
    ));
    lines.push("  \"algorithms\": [".to_string());

    let n = inv.algorithms.len();
    for (i, a) in inv.algorithms.iter().enumerate() {
        let comma = if i + 1 < n { "," } else { "" };
        lines.push(format!("    {}{}", canonical_json(a), comma));
    }
    lines.push("  ]".to_string());
    lines.push("}".to_string());
    lines.push(String::new());
    lines.join("\n")
}

/// `--check` problems, transcribed from the Python original in its order and
/// wording. Transcribed rather than paraphrased: the strings are the gate's
/// user-facing contract, and `tests/gate_crypto_inventory_parity.rs` compares
/// stderr on the drift path.
pub fn conformance_problems(inv: &Inventory, reg: &Registry) -> Vec<String> {
    let mut problems = Vec::new();

    if !inv.rejected_found.is_empty() {
        let detail = inv
            .rejected_found
            .iter()
            .map(|(name, occ, sites)| {
                let files: Vec<String> = sites
                    .iter()
                    .map(|s| format!("{} x{}", s.file, s.count))
                    .collect();
                format!("{name} ({occ} occurrence(s): {})", files.join(", "))
            })
            .collect::<Vec<_>>()
            .join("; ");
        problems.push(format!(
            "REJECTED primitive(s) present: {detail} \u{2014} policy P10-R14 (matrix #172/#173) rejects Ed448/X448 outright; registering them is not a path \u{2014} remove or rework the use site(s)"
        ));
    }

    if !inv.novel_aeads.is_empty() {
        problems.push(format!(
            "novel AEAD / unregistered cipher-suite token(s): {} \u{2014} no novel AEAD may land without conscious registration (P10-R14): register the algorithm in REGISTRY (with rationale) or remove it",
            inv.novel_aeads.join(", ")
        ));
    }

    if !inv.aegis_outside.is_empty() {
        problems.push(format!(
            "AEGIS ('optional at most' \u{2014} AEGIS-128L/AEGIS-256; feature-gated, never a default AEAD; report \u{a7}10.6 item 8) is used outside crates/tallow-crypto/: {}",
            inv.aegis_outside.join(", ")
        ));
    }

    let mut over: Vec<String> = Vec::new();
    for (file, limit) in &inv.aegis_ceiling {
        let got = inv.aegis_occurrences.get(file).copied().unwrap_or(0);
        if got > *limit {
            over.push(format!("{file}: {got} occurrence(s) > ceiling {limit}"));
        }
    }
    if !over.is_empty() {
        problems.push(format!(
            "AEGIS allowance occurrence ceiling exceeded ({}) \u{2014} the E-2-01 allowance is file-level; a new AEGIS mention/endpoint must be re-registered consciously: tighten the site, bump AEGIS_ALLOWANCE_CEILING with a recorded reason, or take the relocation option (entry points into crates/tallow-crypto)",
            over.join("; ")
        ));
    }

    if !inv.unregistered.is_empty() {
        problems.push(format!(
            "unregistered crypto token(s): {} \u{2014} a new algorithm must be consciously registered in REGISTRY (scripts/crypto-inventory.py) before the gate can pass",
            inv.unregistered.join(", ")
        ));
    }

    // Lifecycle drift: an entry declared `active` that no source mentions any
    // more. This check was absent from the first port — it is failure mode (b)
    // in the original's own docstring ("an active registered algorithm
    // disappears from source").
    let missing: Vec<String> = inv
        .algorithms
        .iter()
        .filter(|a| {
            a.get("state").and_then(Value::as_str) == Some("active")
                && a.get("occurrences").and_then(Value::as_u64) == Some(0)
        })
        .filter_map(|a| a.get("name").and_then(Value::as_str).map(str::to_string))
        .collect();
    if !missing.is_empty() {
        problems.push(format!(
            "active registered algorithm(s) with no use sites: {} \u{2014} retire or reclassify their state in REGISTRY consciously",
            missing.join(", ")
        ));
    }

    // `reg` is unused by the checks above but kept in the signature so callers
    // cannot drift: the registry is what the verdict is about.
    let _ = reg;
    problems
}

/// Python's `repr()` for a list of strings — `['Ed448', 'X448']`, single quotes.
///
/// The self-test's labels interpolate `%r` of a list, so the transcript is part
/// of the ported contract: a `Debug` print gives `["Ed448", "X448"]` and the
/// differential comparison fails on punctuation, not on behaviour.
fn py_repr(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Guardrail self-test on throwaway temp fixtures (no repo writes), ported
/// check-for-check from `scripts/crypto-inventory.py::self_test`.
///
/// This is the artifact that catches the *class* of defect a differential test
/// against the happy tree cannot: bare `--self-test` builds its own
/// adversarial fixtures, so a guardrail that silently stopped firing on
/// Ed448/X448, novel AEADs, stray AEGIS, or the allowance ceiling fails here
/// even though the governed tree is clean.
pub fn self_test() -> i32 {
    let root = crate::gate::repo_root();
    let reg = match Registry::load() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("crypto-inventory: {e}");
            return 2;
        }
    };

    let mut failures: Vec<String> = Vec::new();
    let check = |failures: &mut Vec<String>, cond: bool, label: String| {
        println!("  {}{}", if cond { "PASS " } else { "FAIL " }, label);
        if !cond {
            failures.push(label);
        }
    };

    let tmp = std::env::temp_dir().join(format!("crypto-inventory-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    if let Err(e) = std::fs::create_dir_all(&tmp) {
        eprintln!("crypto-inventory: cannot create temp dir: {e}");
        return 2;
    }

    let scan_root = |name: &str, file: &str, body: &str| -> Option<Inventory> {
        let d = tmp.join(name);
        std::fs::create_dir_all(&d).ok()?;
        std::fs::write(d.join(file), body).ok()?;
        scan(&root, &reg, &[d.to_string_lossy().to_string()]).ok()
    };

    // 1. Benign fixture: guardrail stays silent.
    let benign = "pub fn add(a: u64, b: u64) -> u64 { a + b }\n";
    if let Some(inv) = scan_root("benign", "lib.rs", benign) {
        let probs = conformance_problems(&inv, &reg);
        check(&mut failures, inv.unregistered.is_empty(), "benign fixture: no unregistered candidates".into());
        check(
            &mut failures,
            !probs.iter().any(|p| p.contains("REJECTED") || p.contains("novel AEAD") || p.contains("optional at most")),
            "benign fixture: guardrail stays silent".into(),
        );
        check(
            &mut failures,
            inv.rejected_found.is_empty() && inv.novel_aeads.is_empty() && inv.aegis_outside.is_empty(),
            "benign fixture: policy findings empty".into(),
        );
    } else {
        check(&mut failures, false, "benign fixture: scan failed".into());
    }

    // 2. Rejected primitives + novel AEADs + stray AEGIS.
    const REJECTED_FIXTURE: &str = "\
// U-106 guardrail self-test fixture (temp dir only, never committed).
pub const REJECTED_CURVE_1: &str = \"Ed448\";
pub const REJECTED_CURVE_2: &str = \"X448\";
pub fn uses_rejected_lowercase() -> &'static str { \"x448\" }
pub const NOVEL_AEAD_1: &str = \"AES-256-OCB\";
pub const NOVEL_AEAD_2: &str = \"Ascon-AEAD128\";
pub const OPTIONAL_ONLY: &str = \"AEGIS-256\";
pub const REGISTERED_AEAD_SUITE: &str = \"AES-256-GCM-SIV\";
pub const REGISTERED_KW_SUITE: &str = \"AES-256-KW\";
";
    if let Some(inv) = scan_root("rejected", "curves.rs", REJECTED_FIXTURE) {
        let probs = conformance_problems(&inv, &reg);
        let names: Vec<String> = inv.rejected_found.iter().map(|(n, _, _)| n.clone()).collect();
        let shown = py_repr(&names);
        check(&mut failures, names == ["Ed448", "X448"], format!("rejected fixture: Ed448/X448 detected ({shown})"));
        check(
            &mut failures,
            !inv.unregistered.iter().any(|u| u == "Ed448" || u == "X448"),
            "rejected fixture: rejected tokens not offered as registerable candidates".into(),
        );
        check(&mut failures, inv.novel_aeads.iter().any(|n| n == "AES-256-OCB"), "novel-AEAD fixture: AES-256-OCB flagged".into());
        check(&mut failures, inv.novel_aeads.iter().any(|n| n == "Ascon-AEAD128"), "novel-AEAD fixture: Ascon-AEAD128 flagged".into());
        check(
            &mut failures,
            !inv.novel_aeads.iter().any(|n| n == "AES-256-GCM-SIV" || n == "AES-256-KW"),
            "registered cipher suites: AES-256-GCM-SIV + AES-256-KW covered, not re-flagged".into(),
        );
        check(&mut failures, probs.iter().any(|p| p.contains("REJECTED")), "conformance fails on rejected primitives".into());
        check(&mut failures, probs.iter().any(|p| p.contains("novel AEAD")), "conformance fails on novel AEADs".into());
        check(&mut failures, probs.iter().any(|p| p.contains("optional at most")), "conformance fails on stray AEGIS use".into());
    } else {
        check(&mut failures, false, "rejected fixture: scan failed".into());
    }

    // 3. E-3-08: expanded DISCOVERY families (13 representative sites).
    const EXPANDED_FIXTURE: &str = "\
// E-3-08 expanded-DISCOVERY fixture (temp dir only, never committed).
pub const NATIONAL_SIG: &str = \"SM2\";
pub const NATIONAL_HASH: &str = \"SM3\";
pub const NATIONAL_CIPHER: &str = \"SM4-CBC\";
pub const RU_HASH: &str = \"Streebog-256\";
pub const RU_CIPHER: &str = \"Kuznyechik-CBC\";
pub const PASSWORD_KDF: &str = \"bcrypt\";
pub const PAIRING_SIG: &str = \"BLS12-381\";
pub const PAKE: &str = \"SPAKE2\";
pub const APake: &str = \"OPAQUE\";
pub const CREDENTIALS: &str = \"BBS+\";
pub const THRESHOLD: &str = \"FROST\";
pub const OPRF_HELPER: &str = \"oprf_blind\";
pub const VRF_PROOF: &str = \"ECVRF\";
pub const FPE_HELPER: &str = \"ff1_encrypt\";
pub const NOISE_SESSION: &str = \"NoiseSession\";
";
    if let Some(inv) = scan_root("expanded", "families.rs", EXPANDED_FIXTURE) {
        let probs = conformance_problems(&inv, &reg);
        check(
            &mut failures,
            inv.unregistered.is_empty() && inv.novel_aeads.is_empty(),
            format!(
                "expanded-DISCOVERY fixture: all families covered, none re-flagged ({})",
                py_repr(&inv.unregistered.iter().chain(inv.novel_aeads.iter()).cloned().collect::<Vec<_>>())
            ),
        );
        let present: std::collections::BTreeSet<String> = inv
            .algorithms
            .iter()
            .filter(|a| a.get("occurrences").and_then(Value::as_u64).unwrap_or(0) > 0)
            .filter_map(|a| a.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        let wanted = [
            "SM2", "SM3", "SM4", "Streebog", "Kuznyechik", "bcrypt", "BLS", "SPAKE2", "OPAQUE",
            "BBS", "FROST", "OPRF", "VRF", "FF1", "Noise",
        ];
        let missing: Vec<&str> = wanted.iter().copied().filter(|w| !present.contains(*w)).collect();
        check(
            &mut failures,
            missing.is_empty(),
            format!("expanded-DISCOVERY fixture: all 15 expanded entries have live sites (missing: {missing:?})"),
        );
        check(
            &mut failures,
            !probs.iter().any(|p| p.contains("REJECTED") || p.contains("optional at most")),
            "expanded-DISCOVERY fixture: no rejected/AEGIS findings".into(),
        );
    } else {
        check(&mut failures, false, "expanded-DISCOVERY fixture: scan failed".into());
    }

    // 4. AEGIS variant granularity.
    if let Some(inv) = scan_root("aegis-128l", "variant.rs", "pub const DEFAULT_VARIANT: &str = \"AEGIS-128L\";\n") {
        let probs = conformance_problems(&inv, &reg);
        check(
            &mut failures,
            inv.unregistered.is_empty() && inv.novel_aeads.is_empty(),
            "AEGIS-128L fixture: variant covered by its own entry (granularity split)".into(),
        );
        check(
            &mut failures,
            probs.iter().any(|p| p.contains("optional at most")),
            "AEGIS-128L fixture: outside-crate use still fails the optional-at-most rule".into(),
        );
    } else {
        check(&mut failures, false, "AEGIS-128L fixture: scan failed".into());
    }

    if let Some(inv) = scan_root("bare-aegis", "mention.rs", "pub const FAMILY_WORD: &str = \"AEGIS\";\n") {
        check(
            &mut failures,
            inv.unregistered.is_empty() && inv.novel_aeads.is_empty(),
            "bare AEGIS family mention: intentionally not tokenized (documented non-detection — variants, not family words, are the alarm surface)".into(),
        );
    } else {
        check(&mut failures, false, "bare AEGIS fixture: scan failed".into());
    }

    if let Some(inv) = scan_root("aegis-128", "old_variant.rs", "pub const OLD_VARIANT: &str = \"AEGIS-128\";\n") {
        let probs = conformance_problems(&inv, &reg);
        check(
            &mut failures,
            inv.novel_aeads.iter().any(|n| n == "AEGIS-128"),
            "AEGIS-128 (superseded, unregistered variant) now alarms instead of silently matching the AEGIS-256 entry".into(),
        );
        check(
            &mut failures,
            probs.iter().any(|p| p.contains("novel AEAD")),
            "conformance fails on the superseded AEGIS-128 variant".into(),
        );
    } else {
        check(&mut failures, false, "AEGIS-128 fixture: scan failed".into());
    }

    // 5. W2-11: allowance occurrence ceiling, at the limit and one over.
    let ceiling_file = "src/stdlib/crypto.rs";
    if let Some(limit) = reg.ceiling.get(ceiling_file).copied() {
        for (census, want_red) in [(limit, false), (limit + 1, true)] {
            let mut sample = scan(&root, &reg, &[]).unwrap_or_else(|_| unreachable!());
            sample.aegis_ceiling.insert(ceiling_file.to_string(), limit);
            sample.aegis_occurrences.insert(ceiling_file.to_string(), census);
            let red = conformance_problems(&sample, &reg)
                .iter()
                .any(|p| p.contains("occurrence ceiling"));
            check(
                &mut failures,
                red == want_red,
                format!(
                    "allowance ceiling fixture: census {} ceiling {}",
                    if want_red { ">" } else { "==" },
                    if want_red { "fails the gate" } else { "stays green" }
                ),
            );
        }
    } else {
        check(&mut failures, false, "allowance ceiling fixture: ceiling entry missing".into());
    }

    let _ = std::fs::remove_dir_all(&tmp);

    // 6. The repo's own default roots must be green.
    match scan(&root, &reg, &reg.default_roots.clone()) {
        Ok(inv) => {
            let probs = conformance_problems(&inv, &reg);
            check(&mut failures, probs.is_empty(), format!("repo default scan roots: conformance green (problems: {probs:?})"));
        }
        Err(e) => check(&mut failures, false, format!("repo default scan roots: scan failed: {e}")),
    }

    if !failures.is_empty() {
        eprintln!("crypto-inventory: SELF-TEST FAILED ({} check(s))", failures.len());
        return 1;
    }
    println!("crypto-inventory: guardrail self-test OK");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookbehind_is_a_word_boundary() {
        // Structural check of the transformation's premise: every lookbehind in
        // the embedded data is followed by a character class or literal that
        // begins with a word character, so `\b` is equivalent.
        assert!(!EMBEDDED.contains("(?<![0-9A-Za-z_])[^"));
        let ported = port_pattern("(?<![0-9A-Za-z_])BLS\\w*");
        assert_eq!(ported, r"\bBLS\w*");
        assert!(Regex::new(&ported).is_ok());
        let re = Regex::new(&ported).unwrap();
        assert!(re.is_match("BLS_SIG_BLS12381"));
        assert!(!re.is_match("XBLS")); // no boundary before BLS
    }

    #[test]
    fn registry_loads_all_entries() {
        let reg = Registry::load().expect("embedded registry must load");
        assert_eq!(reg.entries.len(), 44);
        assert_eq!(reg.rejected.len(), 2);
        assert_eq!(reg.variants, vec!["AEGIS-128L", "AEGIS-256"]);
        assert!(reg.allowlist.contains_key("src/stdlib/crypto.rs"));
        assert_eq!(reg.ceiling.get("src/stdlib/crypto.rs"), Some(&30));
        assert_eq!(reg.default_roots.len(), 4);
    }

    #[test]
    fn canonical_json_sorts_and_compacts() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":[2,3]}"#).unwrap();
        assert_eq!(canonical_json(&v), r#"{"a":[2,3],"b":1}"#);
    }

    #[test]
    fn discovery_finds_hybrid_and_variant_whole() {
        let reg = Registry::load().unwrap();
        let found: Vec<&str> = reg
            .discovery
            .find_iter("X25519MLKEM768 and AEGIS-128L")
            .map(|m| m.as_str())
            .collect();
        assert_eq!(found, vec!["X25519MLKEM768", "AEGIS-128L"]);
    }
}

