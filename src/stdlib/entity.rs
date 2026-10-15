//! Standard library: `tallow.entity` — general entity resolution / record linkage.
//!
//! Offline, deterministic clustering of records that may or may not refer to
//! the same real-world entity (person, company, store, operator) across
//! independent sources. Answers questions like "is the operator of store A
//! the same as company B?" by comparing normalized identity fields.
//!
//! Building blocks:
//! - `entity.name_key(s)` / `domain_key` / `address_key` / `phone_key` /
//!   `email_key` — blocking-key construction over each identity field
//!   (name/domain keys reuse `tallow.recordlink`; address keys reuse its
//!   canonical street expansion; phone/email/domain normalization lives here).
//! - `entity.block_key(record)` — coarse Soundex(first name token) + ZIP5
//!   compound key, delegating to `recordlink.block_key` (over-inclusive by
//!   design; precision is recovered by pairwise scoring).
//! - `entity.<field>_similarity(a, b)` — per-field similarity in [0,1] built
//!   on the existing Jaro–Winkler / token-set primitives from `recordlink`.
//! - `entity.pair(rec_a, rec_b, keys?)` — pairwise verdict + per-field scores.
//! - `entity.resolve(candidates, keys?)` — connected-component clustering of
//!   records into `EntityCluster { cluster_id, canonical, members, score,
//!   evidence }`, with deterministic canonical-id assignment.
//!
//! # Precision posture
//!
//! Resolution is deliberately conservative (high precision, false negatives
//! preferred over false merges). Merges require a strong identifier (exact
//! normalized email/phone/address) paired with name agreement, or a high
//! combined score; disagreeing addresses/emails/phones *veto* merges unless a
//! stronger identifier overrides. All thresholds are plain arguments on the
//! optional `keys` record and can be relaxed by the caller.
//!
//! # Provenance
//!
//! Every output `EntityMember` carries a `provenance` field. When an input
//! record has a `provenance` field of its own it is passed through verbatim;
//! otherwise the field is `nil`. The full provenance model (roadmap #2)
//! plugs in later without changing this module's shapes.
//!
//! # Determinism
//!
//! Input order never affects output: records are ordered by record id (ties
//! broken by input index) before clustering, so canonical members, cluster
//! ids (`cl-0001`, ...) and scores are stable across runs and input orders.
//! Callers that merge across sources should prefix ids with their source
//! (e.g. `txabc:123`, `sos:456`) to keep ids globally unique.

use super::recordlink;
use super::StdlibResult;
use crate::interp::{type_name, Value};

// ── Field weights (combined-score contribution, renormalized over the
//    fields present on BOTH records) ──────────────────────────────────
const W_NAME: f64 = 0.50;
const W_ADDR: f64 = 0.25;
const W_PHONE: f64 = 0.10;
const W_EMAIL: f64 = 0.10;
const W_DOMAIN: f64 = 0.05;

/// Conservative merge-decision thresholds, all overridable per call through
/// the `keys` argument of `pair`/`resolve`.
#[derive(Clone, Debug)]
pub struct Params {
    /// Combined-score floor for a multi-field merge. High by default.
    pub combined_min: f64,
    /// Min name similarity when the normalized addresses are exactly equal.
    pub exact_addr_name_min: f64,
    /// Min name similarity for an exact-phone merge (no address agreement).
    pub phone_name_min: f64,
    /// Min address similarity for an exact-phone merge (no name agreement).
    pub phone_addr_min: f64,
    /// Min name similarity for an exact-email merge.
    pub email_name_min: f64,
    /// Below this address similarity two present addresses contradict.
    pub addr_contradict: f64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            combined_min: 0.88,
            exact_addr_name_min: 0.72,
            phone_name_min: 0.80,
            phone_addr_min: 0.90,
            email_name_min: 0.50,
            addr_contradict: 0.50,
        }
    }
}

/// Which record fields hold the identity attributes. All names are caller
/// configurable through the `keys` argument; defaults match the documented
/// candidate shape (`id`, `name`, `address`, `phone`, `email`, `domain`).
#[derive(Clone, Debug)]
pub struct KeySpec {
    pub id: String,
    pub name: String,
    pub address: String,
    pub phone: String,
    pub email: String,
    pub domain: String,
}

impl Default for KeySpec {
    fn default() -> Self {
        KeySpec {
            id: "id".into(),
            name: "name".into(),
            address: "address".into(),
            phone: "phone".into(),
            email: "email".into(),
            domain: "domain".into(),
        }
    }
}

// ── Normalization / blocking keys ─────────────────────────────────────

/// Canonical comparable name key (sorted unique tokens) — delegates to
/// `recordlink.name_key`.
pub fn name_key(s: &str) -> String {
    recordlink::name_key(s)
}

/// Clean, comparable host: lowercase, scheme/path/port/`www.` stripped.
/// `"WWW.Acme-Store.com:443/x"` → `"acme-store.com"`.
pub fn domain_key(raw: &str) -> String {
    let mut h = raw.trim().to_lowercase();
    for s in ["https://", "http://", "ftp://"] {
        if let Some(rest) = h.strip_prefix(s) {
            h = rest.to_string();
            break;
        }
    }
    for sep in ['/', '?', '#'] {
        if let Some(idx) = h.find(sep) {
            h.truncate(idx);
        }
    }
    if let Some(idx) = h.rfind(':') {
        if h[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            h.truncate(idx);
        }
    }
    while let Some(rest) = h.strip_prefix("www.") {
        h = rest.to_string();
    }
    h.trim_end_matches('.').to_string()
}

/// Canonical comparable address — delegates to `recordlink.normalize_address`
/// (`"123 Main St #4"` → `"123 main street apt 4"`).
pub fn address_key(raw: &str) -> String {
    recordlink::normalize_address(raw)
}

/// Comparable phone key: digits only; a US leading `1` on an 11-digit
/// number is dropped. `"(512) 555-0142"`, `"512-555-0142"` and
/// `"+1 (512) 555-0142"` all → `"5125550142"`.
pub fn phone_key(raw: &str) -> String {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 11 && digits.starts_with('1') {
        digits[1..].to_string()
    } else {
        digits
    }
}

/// Comparable email key: lowercased, `mailto:` stripped, trimmed.
pub fn email_key(raw: &str) -> String {
    raw.trim()
        .strip_prefix("mailto:")
        .unwrap_or(raw.trim())
        .trim()
        .to_lowercase()
}

/// Coarse compound blocking key from a name+address pair — delegates to
/// `recordlink.block_key` (Soundex of the first name token + ZIP5). Used by
/// `resolve` internally to restrict pairwise comparison to plausible
/// candidates, and exposed for callers doing their own bucketing.
pub fn block_key(name: &str, address: &str) -> String {
    recordlink::block_key(name, address)
}

// ── Per-field similarity ──────────────────────────────────────────────

/// Name similarity in [0,1] — delegates to `recordlink.name_similarity`
/// (best of Jaro–Winkler / token-set over normalized names).
pub fn name_similarity(a: &str, b: &str) -> f64 {
    recordlink::name_similarity(a, b)
}

/// Address similarity in [0,1] — delegates to `recordlink.address_similarity`
/// (canonical street forms, token-set + Jaro–Winkler).
pub fn address_similarity(a: &str, b: &str) -> f64 {
    recordlink::address_similarity(a, b)
}

/// Phone similarity in [0,1]. Both blank → 0.5 (neutral, no evidence);
/// exactly one blank → 0.0; identical digit keys → 1.0; otherwise
/// Jaro–Winkler over the digit strings.
pub fn phone_similarity(a: &str, b: &str) -> f64 {
    let ka = phone_key(a);
    let kb = phone_key(b);
    if ka.is_empty() && kb.is_empty() {
        return 0.5;
    }
    if ka.is_empty() || kb.is_empty() {
        return 0.0;
    }
    if ka == kb {
        return 1.0;
    }
    recordlink::jaro_winkler(&ka, &kb)
}

/// Email similarity in [0,1]. Both blank → 0.5; one blank → 0.0; identical
/// keys → 1.0; otherwise Jaro–Winkler over the full normalized addresses.
/// Note: the resolver treats *differing* emails as weak contradiction, not
/// partial credit — `resolve` uses equality as the strong signal.
pub fn email_similarity(a: &str, b: &str) -> f64 {
    let ka = email_key(a);
    let kb = email_key(b);
    if ka.is_empty() && kb.is_empty() {
        return 0.5;
    }
    if ka.is_empty() || kb.is_empty() {
        return 0.0;
    }
    if ka == kb {
        return 1.0;
    }
    recordlink::jaro_winkler(&ka, &kb)
}

/// Domain similarity in [0,1]. Both blank → 0.5; one blank → 0.0; equal
/// hosts → 1.0; a subdomain/superdomain relation → 0.9; otherwise
/// Jaro–Winkler over the cleaned hosts.
pub fn domain_similarity(a: &str, b: &str) -> f64 {
    let ka = domain_key(a);
    let kb = domain_key(b);
    if ka.is_empty() && kb.is_empty() {
        return 0.5;
    }
    if ka.is_empty() || kb.is_empty() {
        return 0.0;
    }
    if ka == kb {
        return 1.0;
    }
    if ka.ends_with(&format!(".{kb}")) || kb.ends_with(&format!(".{ka}")) {
        return 0.9;
    }
    recordlink::jaro_winkler(&ka, &kb)
}

/// Dispatch per-field similarity by kind name (`name`, `address`, `phone`,
/// `email`, `domain`; `website`/`url` are accepted for `domain`). Unknown
/// kinds return a hard error rather than a fabricated score.
pub fn field_similarity(kind: &str, a: &str, b: &str) -> Result<f64, String> {
    match kind {
        "name" => Ok(name_similarity(a, b)),
        "address" => Ok(address_similarity(a, b)),
        "phone" => Ok(phone_similarity(a, b)),
        "email" => Ok(email_similarity(a, b)),
        "domain" | "website" | "url" | "web" => Ok(domain_similarity(a, b)),
        other => Err(format!("similarity: unknown field kind `{other}` (expected name/address/phone/email/domain)")),
    }
}

// ── Record model ──────────────────────────────────────────────────────

/// One candidate record, normalized up front so pairwise scoring never
/// re-normalizes and never depends on evaluation order.
#[derive(Clone, Debug)]
struct Rec {
    id: String,
    idx: usize,
    name_raw: String,
    addr_raw: String,
    prov: Value,
    name_n: String,
    addr_n: String,
    phone_n: String,
    email_n: String,
    domain_n: String,
    /// `recordlink.block_key(name, address)` — "SNDX|ZIP5".
    block: String,
    /// Soundex part of `block`.
    sndx: String,
    /// ZIP5 part of `block` ("" when absent).
    zip: String,
}

/// Extract `(key, value)` entries from a `Value` the interpreter can hand us:
/// a typed struct (`Value::Struct`) or a map literal / parsed JSON
/// (`Value::Map` with string keys). Anything else has no readable fields.
fn entries(v: &Value) -> Option<Vec<(String, Value)>> {
    match v {
        Value::Struct { fields, .. } => Some(fields.clone()),
        Value::Map(pairs) => {
            let mut out = Vec::new();
            for (k, val) in pairs {
                if let Value::String(s) = k {
                    out.push((s.clone(), val.clone()));
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn find_field<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Render a record field to comparable text. Nested/non-scalar values are
/// ignored (empty) — identity fields are scalar strings by convention.
fn val_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => {
            if f.fract() == 0.0 {
                format!("{}", *f as i64)
            } else {
                format!("{f}")
            }
        }
        Value::Bool(b) => b.to_string(),
        Value::Private(inner) | Value::Secret(inner) => val_text(inner),
        _ => String::new(),
    }
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Float(f) => Some(*f),
        Value::Int(i) => Some(*i as f64),
        _ => None,
    }
}

/// Build a `Rec` from a candidate `Value`, honoring the caller's `KeySpec`.
fn make_rec(v: &Value, spec: &KeySpec, idx: usize) -> Rec {
    let fields = entries(v).unwrap_or_default();
    let id_raw = find_field(&fields, &spec.id).map(val_text).unwrap_or_default();
    let name_raw = find_field(&fields, &spec.name).map(val_text).unwrap_or_default();
    let addr_raw = find_field(&fields, &spec.address).map(val_text).unwrap_or_default();
    let phone_raw = find_field(&fields, &spec.phone).map(val_text).unwrap_or_default();
    let email_raw = find_field(&fields, &spec.email).map(val_text).unwrap_or_default();
    let domain_raw = find_field(&fields, &spec.domain).map(val_text).unwrap_or_default();
    let prov = find_field(&fields, "provenance").cloned().unwrap_or(Value::Nil);
    let id = if id_raw.is_empty() {
        format!("rec-{idx}")
    } else {
        id_raw
    };
    let name_clean = name_raw.trim().to_string();
    let addr_clean = addr_raw.trim().to_string();
    // Normalize everything before constructing `Rec` so no field borrows a
    // sibling that was already moved into the struct.
    let name_n = recordlink::normalize_name(&name_raw);
    let addr_n = recordlink::normalize_address(&addr_raw);
    let phone_n = phone_key(&phone_raw);
    let email_n = email_key(&email_raw);
    let domain_n = domain_key(&domain_raw);
    let block = block_key(&name_clean, &addr_clean);
    let (sndx, zip) = match block.split_once('|') {
        Some((s, z)) => (s.to_string(), z.to_string()),
        None => (block.clone(), String::new()),
    };
    Rec {
        id,
        idx,
        name_raw: name_clean,
        addr_raw: addr_clean,
        prov,
        name_n,
        addr_n,
        phone_n,
        email_n,
        domain_n,
        block,
        sndx,
        zip,
    }
}

fn display_name(r: &Rec) -> String {
    if r.name_raw.is_empty() {
        r.id.clone()
    } else {
        r.name_raw.clone()
    }
}

/// Over-inclusive blocking test used by `resolve` to restrict pairwise
/// comparison: same first-token Soundex and ZIPs that are equal *or* absent
/// on either side. Empty ZIP acts as a wildcard so a record without an
/// address still gets compared against address-bearing candidates.
fn blocks_overlap(a: &Rec, b: &Rec) -> bool {
    a.sndx == b.sndx && (a.zip == b.zip || a.zip.is_empty() || b.zip.is_empty())
}

// ── Pairwise scoring ──────────────────────────────────────────────────

/// Per-field similarity snapshot for one record pair.
#[derive(Clone, Debug)]
pub struct FieldScores {
    pub name_sim: f64,
    pub addr_sim: f64,
    pub phone_sim: f64,
    pub email_sim: f64,
    pub domain_sim: f64,
    pub name_both: bool,
    pub addr_both: bool,
    pub phone_both: bool,
    pub email_both: bool,
    pub domain_both: bool,
    pub exact_email: bool,
    pub exact_phone: bool,
    pub exact_addr: bool,
    /// Both sides carry a leading house number and the numbers disagree.
    pub addr_houses_disagree: bool,
    /// Weighted combination over fields present on both sides, in [0,1].
    pub combined: f64,
}

impl FieldScores {
    fn any_comparable(&self) -> bool {
        self.name_both
            || self.addr_both
            || self.phone_both
            || self.email_both
            || self.domain_both
    }
}

/// Leading house number of a normalized address: the first whitespace token
/// that starts with an ASCII digit, reduced to its leading digit run (strips
/// unit letters). PO boxes / unit-first addresses yield `None`.
fn house_number(norm: &str) -> Option<String> {
    let tok = norm.split_whitespace().next()?;
    if !tok.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    let digits: String = tok
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    // Compare numerically (leading zeros are meaningless: "007" == "7").
    let trimmed = digits.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0" } else { trimmed }.to_string())
}

fn score_records(a: &Rec, b: &Rec) -> FieldScores {
    let name_both = !a.name_n.is_empty() && !b.name_n.is_empty();
    let addr_both = !a.addr_n.is_empty() && !b.addr_n.is_empty();
    let phone_both = !a.phone_n.is_empty() && !b.phone_n.is_empty();
    let email_both = !a.email_n.is_empty() && !b.email_n.is_empty();
    let domain_both = !a.domain_n.is_empty() && !b.domain_n.is_empty();

    let name_sim = if name_both {
        name_similarity(&a.name_raw, &b.name_raw)
    } else {
        0.0
    };
    let addr_sim = if addr_both {
        address_similarity(&a.addr_raw, &b.addr_raw)
    } else {
        0.0
    };
    // Phone: identical digit keys are the signal; a partial overlap only
    // contributes Jaro–Winkler credit inside `combined`.
    let exact_phone = phone_both && a.phone_n == b.phone_n;
    let phone_sim = if phone_both {
        if exact_phone {
            1.0
        } else {
            recordlink::jaro_winkler(&a.phone_n, &b.phone_n)
        }
    } else {
        0.0
    };
    // Email: differing emails are weak contradiction, so inside the
    // combined score a non-exact email contributes 0 (never partial credit).
    let exact_email = email_both && a.email_n == b.email_n;
    let email_sim = if email_both {
        if exact_email {
            1.0
        } else {
            0.0
        }
    } else {
        0.0
    };
    let exact_domain = domain_both && a.domain_n == b.domain_n;
    let subdomain = domain_both
        && !exact_domain
        && (a.domain_n.ends_with(&format!(".{}", b.domain_n))
            || b.domain_n.ends_with(&format!(".{}", a.domain_n)));
    let domain_sim = if exact_domain {
        1.0
    } else if subdomain {
        0.9
    } else {
        0.0
    };

    // Weighted mean over fields present on both sides (weights renormalized).
    let mut weighted = 0.0;
    let mut total_w = 0.0;
    if name_both {
        weighted += W_NAME * name_sim;
        total_w += W_NAME;
    }
    if addr_both {
        weighted += W_ADDR * addr_sim;
        total_w += W_ADDR;
    }
    if phone_both {
        weighted += W_PHONE * phone_sim;
        total_w += W_PHONE;
    }
    if email_both {
        weighted += W_EMAIL * email_sim;
        total_w += W_EMAIL;
    }
    if domain_both {
        weighted += W_DOMAIN * domain_sim;
        total_w += W_DOMAIN;
    }
    let combined = if total_w > 0.0 { weighted / total_w } else { 0.0 };
    let exact_addr = addr_both && a.addr_n == b.addr_n;
    let addr_houses_disagree = match (house_number(&a.addr_n), house_number(&b.addr_n)) {
        (Some(ha), Some(hb)) => addr_both && !exact_addr && ha != hb,
        _ => false,
    };

    FieldScores {
        name_sim,
        addr_sim,
        phone_sim,
        email_sim,
        domain_sim,
        name_both,
        addr_both,
        phone_both,
        email_both,
        domain_both,
        exact_email,
        exact_phone,
        exact_addr,
        addr_houses_disagree,
        combined,
    }
}

/// Conservative merge decision. Returns `(merged, reason)` where `reason` is
/// one of: `exact_email`, `exact_phone`, `exact_address`, `combined`,
/// `no_overlap`, `below_threshold`, `conflicting_address`,
/// `conflicting_email`, `conflicting_phone`.
pub fn decide(fs: &FieldScores, p: &Params) -> (bool, String) {
    if !fs.any_comparable() {
        return (false, "no_overlap".into());
    }
    let name_ok_for_id = !fs.name_both || fs.name_sim >= p.email_name_min;
    // Contradicting addresses veto everything except an exact email backed
    // by a plausibly-similar name (operator moved / operates elsewhere).
    if fs.addr_both
        && !fs.exact_addr
        && (fs.addr_sim < p.addr_contradict || fs.addr_houses_disagree)
    {
        if fs.exact_email && name_ok_for_id {
            return (true, "exact_email".into());
        }
        return (false, "conflicting_address".into());
    }
    // Differing emails contradict, unless the records are near-duplicates
    // (near-exact name) or share an exact address.
    if fs.email_both && !fs.exact_email && !fs.exact_addr {
        if !(fs.name_both && fs.name_sim >= 0.95) {
            return (false, "conflicting_email".into());
        }
    }
    // Differing phones contradict, unless records share an exact address or
    // near-exact names.
    if fs.phone_both && !fs.exact_phone && !fs.exact_addr {
        if fs.name_both && fs.name_sim < 0.97 {
            return (false, "conflicting_phone".into());
        }
    }
    // Strong identifiers first (highest precision).
    if fs.exact_email && name_ok_for_id {
        return (true, "exact_email".into());
    }
    if fs.exact_phone
        && ((fs.name_both && fs.name_sim >= p.phone_name_min)
            || (fs.addr_both && fs.addr_sim >= p.phone_addr_min))
    {
        return (true, "exact_phone".into());
    }
    // An exact physical address with a name floor: spelling/suffix variants
    // of the same store ("Acme Corp" vs "Acme Corporation" at 123 Main St).
    if fs.exact_addr && fs.name_both && fs.name_sim >= p.exact_addr_name_min {
        return (true, "exact_address".into());
    }
    // Weighted multi-field agreement with a name floor.
    if fs.name_both && fs.name_sim >= 0.5 && fs.combined >= p.combined_min {
        return (true, "combined".into());
    }
    (false, "below_threshold".into())
}

// ── Params / KeySpec parsing from the `keys` argument ─────────────────

fn parse_keys(keys: &Value) -> Result<(KeySpec, Params), String> {
    let mut spec = KeySpec::default();
    let mut p = Params::default();
    let fields = match keys {
        Value::Nil => return Ok((spec, p)),
        v => entries(v).ok_or_else(|| {
            format!(
                "keys: expected a struct/map of option overrides, got {}",
                type_name(v)
            )
        })?,
    };
    let get_str = |key: &str, fallback: &str| -> String {
        match find_field(&fields, key) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(other) => {
                // non-string field name: keep fallback, do not error out of
                // an otherwise usable config
                let _ = other;
                fallback.to_string()
            }
            None => fallback.to_string(),
        }
    };
    let get_f = |key: &str, fallback: f64| -> f64 {
        match find_field(&fields, key).and_then(as_f64) {
            Some(v) => v,
            None => fallback,
        }
    };
    spec.id = get_str("id", &spec.id);
    spec.name = get_str("name", &spec.name);
    spec.address = get_str("address", &spec.address);
    spec.phone = get_str("phone", &spec.phone);
    spec.email = get_str("email", &spec.email);
    spec.domain = get_str("domain", &spec.domain);
    p.combined_min = get_f("combined_min", p.combined_min);
    p.exact_addr_name_min = get_f("exact_addr_name_min", p.exact_addr_name_min);
    p.phone_name_min = get_f("phone_name_min", p.phone_name_min);
    p.phone_addr_min = get_f("phone_addr_min", p.phone_addr_min);
    p.email_name_min = get_f("email_name_min", p.email_name_min);
    p.addr_contradict = get_f("addr_contradict", p.addr_contradict);
    // Sanity: thresholds must stay in their domain.
    for (k, v) in [
        ("combined_min", p.combined_min),
        ("exact_addr_name_min", p.exact_addr_name_min),
        ("phone_name_min", p.phone_name_min),
        ("phone_addr_min", p.phone_addr_min),
        ("email_name_min", p.email_name_min),
        ("addr_contradict", p.addr_contradict),
    ] {
        if !(0.0..=1.0).contains(&v) {
            return Err(format!("keys: threshold `{k}` must be in [0,1], got {v}"));
        }
    }
    Ok((spec, p))
}

// ── Output construction ───────────────────────────────────────────────

fn mk_float(v: f64) -> Value {
    Value::Float(v)
}

fn member_value(rec: &Rec, cluster_id: &str, score: f64) -> Value {
    Value::Struct {
        name: "EntityMember".into(),
        fields: vec![
            ("cluster_id".into(), Value::String(cluster_id.into())),
            ("record_id".into(), Value::String(rec.id.clone())),
            ("name".into(), Value::String(display_name(rec))),
            ("score".into(), mk_float(score)),
            // Optional provenance passthrough: present only when the source
            // record carried one. The provenance module (roadmap #2) can
            // later populate this field without changing this shape.
            ("provenance".into(), rec.prov.clone()),
        ],
    }
}

fn evidence_value(rec: &Rec, canonical_id: &str, field: &str, sim: f64, note: &str) -> Value {
    Value::Struct {
        name: "EntityEvidence".into(),
        fields: vec![
            ("record_id".into(), Value::String(rec.id.clone())),
            ("compared_to".into(), Value::String(canonical_id.into())),
            ("field".into(), Value::String(field.into())),
            ("similarity".into(), mk_float(sim)),
            ("note".into(), Value::String(note.into())),
        ],
    }
}

fn cluster_value(
    cluster_id: &str,
    canonical: &Rec,
    members: &[Value],
    evidence: Vec<Value>,
    score: f64,
) -> Value {
    Value::Struct {
        name: "EntityCluster".into(),
        fields: vec![
            ("cluster_id".into(), Value::String(cluster_id.into())),
            ("canonical_id".into(), Value::String(canonical.id.clone())),
            ("canonical".into(), Value::String(display_name(canonical))),
            ("score".into(), mk_float(score)),
            ("members".into(), Value::Array(members.to_vec())),
            ("evidence".into(), Value::Array(evidence)),
        ],
    }
}

/// Best single supporting field for a member vs its cluster canonical.
/// Prefers exact strong identifiers, then the highest raw field similarity.
fn best_field(fs: &FieldScores) -> (String, f64) {
    if fs.exact_email {
        return ("email".into(), 1.0);
    }
    if fs.exact_phone {
        return ("phone".into(), 1.0);
    }
    if fs.exact_addr {
        return ("address".into(), 1.0);
    }
    let mut best: (String, f64) = ("combined".into(), fs.combined);
    if fs.name_both && fs.name_sim > best.1 {
        best = ("name".into(), fs.name_sim);
    }
    if fs.addr_both && fs.addr_sim > best.1 {
        best = ("address".into(), fs.addr_sim);
    }
    if fs.phone_both && fs.phone_sim > best.1 {
        best = ("phone".into(), fs.phone_sim);
    }
    best
}

// ── Core resolve ──────────────────────────────────────────────────────

/// Cluster `candidates` (each a struct/map with the identity fields named by
/// `keys`) into an array of `EntityCluster` structs. Deterministic, offline,
/// conservative — see module docs.
pub fn resolve(candidates: &[Value], keys: &Value) -> Result<Vec<Value>, String> {
    let (spec, p) = parse_keys(keys)?;
    let mut recs: Vec<Rec> = candidates
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if entries(v).is_none() {
                Err(format!(
                    "resolve: candidate {} is {} — expected a struct/map record",
                    i + 1,
                    type_name(v)
                ))
            } else {
                Ok(make_rec(v, &spec, i))
            }
        })
        .collect::<Result<_, String>>()?;
    let n = recs.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    // Deterministic order: by record id, ties by input index.
    recs.sort_by(|a, b| (&a.id, a.idx).cmp(&(&b.id, b.idx)));

    // Union-Find over merge decisions.
    let mut parent: Vec<usize> = (0..n).collect();
    let mut rank = vec![0u8; n];
    // Weakest-link score per component root (1.0 = trivial singleton).
    let mut comp_score = vec![1.0f64; n];
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        let mut cur = x;
        while parent[cur] != cur {
            let next = parent[cur];
            parent[cur] = r;
            cur = next;
        }
        r
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if !blocks_overlap(&recs[i], &recs[j]) {
                continue;
            }
            let fs = score_records(&recs[i], &recs[j]);
            let (merged, _reason) = decide(&fs, &p);
            if !merged {
                continue;
            }
            let ri = find(&mut parent, i);
            let rj = find(&mut parent, j);
            if ri != rj {
                // Union by rank; keep the lower index as root for stable ids.
                let (lo, hi) = if rank[ri] < rank[rj] { (ri, rj) } else { (rj, ri) };
                parent[hi] = lo;
                if rank[lo] == rank[hi] {
                    rank[lo] += 1;
                }
                comp_score[lo] = comp_score[lo].min(comp_score[hi]).min(fs.combined);
            }
        }
    }

    // Group sorted records by root; clusters surface in first-seen order.
    let mut order: Vec<usize> = Vec::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut root_to_group = std::collections::HashMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        let g = match root_to_group.get(&r) {
            Some(g) => *g,
            None => {
                root_to_group.insert(r, groups.len());
                order.push(r);
                groups.push(Vec::new());
                groups.len() - 1
            }
        };
        groups[g].push(i);
    }

    let mut out = Vec::with_capacity(groups.len());
    for (seq, group) in groups.iter().enumerate() {
        let canonical_idx = group[0]; // smallest (id, idx) in the cluster
        let canonical = &recs[canonical_idx];
        let cluster_id = format!("cl-{:04}", seq + 1);
        let root = find(&mut parent, canonical_idx);
        let score = comp_score[root];
        let mut members: Vec<Value> = Vec::with_capacity(group.len());
        let mut evidence: Vec<Value> = Vec::new();
        for &mi in group {
            let m = &recs[mi];
            if mi == canonical_idx {
                members.push(member_value(m, &cluster_id, 1.0));
                continue;
            }
            let fs = score_records(m, canonical);
            let (merged, reason) = decide(&fs, &p);
            let (field, sim) = best_field(&fs);
            members.push(member_value(m, &cluster_id, fs.combined));
            let note = if merged {
                reason
            } else {
                "transitive_link (direct pair below threshold)".to_string()
            };
            evidence.push(evidence_value(m, &canonical.id, &field, sim, &note));
        }
        out.push(cluster_value(&cluster_id, canonical, &members, evidence, score));
    }
    Ok(out)
}

/// Pairwise score + verdict for two records. Verdict is `match`/`no` with a
/// machine-readable reason; all per-field similarities ride along.
pub fn pair(a: &Value, b: &Value, keys: &Value) -> Result<Value, String> {
    let (spec, p) = parse_keys(keys)?;
    if entries(a).is_none() {
        return Err(format!("pair: record A is {} — expected a struct/map", type_name(a)));
    }
    if entries(b).is_none() {
        return Err(format!("pair: record B is {} — expected a struct/map", type_name(b)));
    }
    let ra = make_rec(a, &spec, 0);
    let rb = make_rec(b, &spec, 1);
    let fs = score_records(&ra, &rb);
    let (merged, reason) = decide(&fs, &p);
    let verdict = if merged { "match" } else { "no" };
    Ok(Value::Struct {
        name: "PairScore".into(),
        fields: vec![
            ("verdict".into(), Value::String(verdict.into())),
            ("reason".into(), Value::String(reason)),
            ("combined".into(), mk_float(fs.combined)),
            ("name".into(), mk_float(fs.name_sim)),
            ("address".into(), mk_float(fs.addr_sim)),
            ("phone".into(), mk_float(fs.phone_sim)),
            ("email".into(), mk_float(fs.email_sim)),
            ("domain".into(), mk_float(fs.domain_sim)),
        ],
    })
}

// ── Dispatch helpers ──────────────────────────────────────────────────

fn str_arg<'a>(args: &'a [Value], idx: usize, fname: &str) -> Result<&'a str, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(format!(
            "{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("{fname}: missing argument {}", idx + 1)),
    }
}

fn record_arg<'a>(args: &'a [Value], idx: usize, fname: &str) -> Result<&'a Value, String> {
    match args.get(idx) {
        Some(v) if entries(v).is_some() => Ok(v),
        Some(other) => Err(format!(
            "{fname}: argument {} expected a record (struct/map), got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("{fname}: missing argument {}", idx + 1)),
    }
}

/// The optional trailing `keys` argument (struct/map of overrides, or nil).
fn keys_arg<'a>(args: &'a [Value], idx: usize) -> &'a Value {
    match args.get(idx) {
        Some(Value::Nil) | None => &Value::Nil,
        Some(v) => v,
    }
}

fn unary_str(args: Vec<Value>, fname: &str, f: fn(&str) -> String) -> StdlibResult {
    let a = str_arg(&args, 0, fname)?;
    Ok(Value::String(f(a)))
}

fn binary_sim(args: Vec<Value>, fname: &str, f: fn(&str, &str) -> f64) -> StdlibResult {
    let a = str_arg(&args, 0, fname)?;
    let b = str_arg(&args, 1, fname)?;
    Ok(Value::Float(f(a, b)))
}

fn record_block_dispatch(args: Vec<Value>) -> StdlibResult {
    let rec = record_arg(&args, 0, "block_key")?;
    let spec = KeySpec::default();
    let r = make_rec(rec, &spec, 0);
    Ok(Value::String(r.block))
}

fn similarity_dispatch(args: Vec<Value>) -> StdlibResult {
    let kind = str_arg(&args, 0, "similarity")?;
    let a = str_arg(&args, 1, "similarity")?;
    let b = str_arg(&args, 2, "similarity")?;
    field_similarity(kind, a, b).map(Value::Float)
}

fn pair_dispatch(args: Vec<Value>) -> StdlibResult {
    let a = record_arg(&args, 0, "pair")?;
    let b = record_arg(&args, 1, "pair")?;
    let keys = keys_arg(&args, 2);
    pair(a, b, keys)
}

fn resolve_dispatch(args: Vec<Value>) -> StdlibResult {
    let candidates = match args.first() {
        Some(Value::Array(items)) => items.clone(),
        Some(other) => {
            return Err(format!(
                "resolve: argument 1 expected Array of records, got {}",
                type_name(other)
            ))
        }
        None => return Err("resolve: missing argument 1 (candidates array)".into()),
    };
    let keys = keys_arg(&args, 1);
    resolve(&candidates, keys).map(Value::Array)
}

// ── Dispatch ──────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "name_key" => Some(unary_str(args, "name_key", name_key)),
        "domain_key" => Some(unary_str(args, "domain_key", domain_key)),
        "address_key" => Some(unary_str(args, "address_key", address_key)),
        "phone_key" => Some(unary_str(args, "phone_key", phone_key)),
        "email_key" => Some(unary_str(args, "email_key", email_key)),
        "block_key" => Some(record_block_dispatch(args)),
        "name_similarity" => Some(binary_sim(args, "name_similarity", name_similarity)),
        "address_similarity" => Some(binary_sim(args, "address_similarity", address_similarity)),
        "phone_similarity" => Some(binary_sim(args, "phone_similarity", phone_similarity)),
        "email_similarity" => Some(binary_sim(args, "email_similarity", email_similarity)),
        "domain_similarity" => Some(binary_sim(args, "domain_similarity", domain_similarity)),
        "similarity" => Some(similarity_dispatch(args)),
        "pair" => Some(pair_dispatch(args)),
        "resolve" => Some(resolve_dispatch(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "name_key"
            | "domain_key"
            | "address_key"
            | "phone_key"
            | "email_key"
            | "block_key"
            | "name_similarity"
            | "address_similarity"
            | "phone_similarity"
            | "email_similarity"
            | "domain_similarity"
            | "similarity"
            | "pair"
            | "resolve"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// Build a candidate record struct. `prov` is an optional provenance
    /// value to test passthrough.
    fn rec(id: &str, name: &str, addr: &str, phone: &str, email: &str, domain: &str) -> Value {
        Value::Struct {
            name: "EntityCandidate".into(),
            fields: vec![
                ("id".into(), Value::String(id.into())),
                ("name".into(), Value::String(name.into())),
                ("address".into(), Value::String(addr.into())),
                ("phone".into(), Value::String(phone.into())),
                ("email".into(), Value::String(email.into())),
                ("domain".into(), Value::String(domain.into())),
            ],
        }
    }

    fn mk_keys(overrides: &[(&str, f64)]) -> Value {
        Value::Struct {
            name: "EntityKeys".into(),
            fields: overrides
                .iter()
                .map(|(k, v)| ((*k).to_string(), Value::Float(*v)))
                .collect(),
        }
    }

    /// Cluster a candidate set and return (cluster list, member counts).
    fn run(cands: &[Value], keys: &Value) -> Vec<Value> {
        resolve(cands, keys).expect("resolve should succeed")
    }

    fn member_count(cluster: &Value) -> usize {
        match cluster {
            Value::Struct { fields, .. } => {
                let members = find_field(fields, "members").expect("cluster.members");
                match members {
                    Value::Array(a) => a.len(),
                    _ => panic!("members not an array"),
                }
            }
            _ => panic!("not a cluster struct"),
        }
    }

    fn cluster_ids(clusters: &[Value]) -> Vec<String> {
        clusters
            .iter()
            .map(|c| match c {
                Value::Struct { fields, .. } => match find_field(fields, "cluster_id") {
                    Some(Value::String(s)) => s.clone(),
                    _ => panic!("no cluster_id"),
                },
                _ => panic!("not a cluster"),
            })
            .collect()
    }

    fn member_ids(cluster: &Value) -> Vec<String> {
        match cluster {
            Value::Struct { fields, .. } => {
                let members = find_field(fields, "members").expect("members");
                match members {
                    Value::Array(arr) => arr
                        .iter()
                        .map(|m| match m {
                            Value::Struct { fields, .. } => {
                                match find_field(fields, "record_id") {
                                    Some(Value::String(s)) => s.clone(),
                                    _ => panic!("no record_id"),
                                }
                            }
                            _ => panic!("member not a struct"),
                        })
                        .collect(),
                    _ => panic!("members not array"),
                }
            }
            _ => panic!("not a cluster"),
        }
    }

    fn get_cluster_field<'a>(cluster: &'a Value, key: &str) -> &'a Value {
        match cluster {
            Value::Struct { fields, .. } => find_field(fields, key).expect(key),
            _ => panic!("not a cluster"),
        }
    }

    // ── Normalization / blocking keys ─────────────────────────────────

    #[test]
    fn phone_email_domain_keys_normalize_variants() {
        // Formatting variants collapse to one digit key.
        let k1 = phone_key("(512) 555-0142");
        let k2 = phone_key("512-555-0142");
        let k3 = phone_key("+1 (512) 555-0142");
        assert_eq!(k1, "5125550142");
        assert_eq!(k1, k2);
        assert_eq!(k2, k3);
        // An 11-digit non-US-leading-1 number is kept whole.
        assert_eq!(phone_key("44 20 7946 0958"), "442079460958");
        assert_eq!(phone_key(""), "");

        // Email case / mailto normalization.
        assert_eq!(email_key("  QuikFoods.Lathrop@Example.COM "), "quikfoods.lathrop@example.com");
        assert_eq!(email_key("mailto:ops@acme.example"), "ops@acme.example");

        // Domain cleanup.
        assert_eq!(domain_key("WWW.Acme-Store.com:443/x?y=1"), "acme-store.com");
        assert_eq!(domain_key("https://QuikFoods.com"), "quikfoods.com");
        assert_eq!(domain_key("http://www.www.example.com."), "example.com");

        // Address key delegates to the canonical street expansion.
        assert_eq!(address_key("123 Main St"), address_key("123 MAIN STREET"));
        assert_eq!(address_key("4500 Parmer Ln, Apt #4"), address_key("4500 parmer lane apt 4"));

        // Name key delegates to the sorted-token key.
        assert_eq!(name_key("Acme Corporation"), name_key("Corporation Acme"));
    }

    #[test]
    fn block_key_reuses_recordlink_and_blocks_overlap() {
        // Same store under two spellings/address phrasings → same block.
        let a = make_rec(&rec("a", "Acme Corp", "123 Main St Austin TX 78701", "", "", ""), &KeySpec::default(), 0);
        let b = make_rec(&rec("b", "Acme Corporation", "123 Main Street Austin Texas 78701", "", "", ""), &KeySpec::default(), 1);
        assert_eq!(a.block, "A250|78701");
        assert_eq!(a.block, b.block);
        assert!(blocks_overlap(&a, &b));
        // Different first token / ZIP → different blocks.
        let c = make_rec(&rec("c", "Zebra LLC", "900 Congress Ave Austin TX 78701", "", "", ""), &KeySpec::default(), 2);
        assert!(!blocks_overlap(&a, &c));
        // Empty ZIP acts as a wildcard (record with no address still
        // compares against address-bearing candidates with the same name).
        let d = make_rec(&rec("d", "Acme Corp", "", "", "", ""), &KeySpec::default(), 3);
        assert!(blocks_overlap(&a, &d));
    }

    #[test]
    fn field_similarity_ranges() {
        assert!(name_similarity("Acme Corp", "Acme Corporation") > 0.85);
        assert!(name_similarity("Zebra Liquor", "Alpha Grocery") < 0.6);
        assert!(close(phone_similarity("(512) 555-0142", "512-555-0142"), 1.0));
        assert!(close(phone_similarity("", ""), 0.5));
        assert!(close(phone_similarity("5125550142", ""), 0.0));
        assert!(phone_similarity("5125550142", "5125550199") < 1.0);
        assert!(close(email_similarity("a@example.com", "A@Example.COM"), 1.0));
        assert!(close(domain_similarity("www.QuikFoods.com", "quikfoods.com"), 1.0));
        assert!(close(domain_similarity("store.acme.com", "acme.com"), 0.9));
        assert!(close(field_similarity("phone", "512-555-0142", "(512) 555-0142").unwrap(), 1.0));
        assert!(field_similarity("ssn", "a", "b").is_err());
    }

    // ── Pair decisions ────────────────────────────────────────────────

    #[test]
    fn pair_verdicts_are_conservative() {
        // Identical store under two spellings + formatting variants → match.
        let a = rec("a1", "Quik Food Store", "1103 Lathrop Dr Austin TX 78704", "(512) 555-0142", "quikfoods.lathrop@example.com", "");
        let b = rec("b1", "Quik Foods", "1103 Lathrop Drive Austin TX 78704", "512-555-0142", "QUIKFOODS.LATHROP@example.com", "");
        let p = pair(&a, &b, &Value::Nil).expect("pair ok");
        match &p {
            Value::Struct { name, fields } => {
                assert_eq!(name, "PairScore");
                let get = |k: &str| find_field(fields, k).unwrap().clone();
                assert!(matches!(get("verdict"), Value::String(s) if s == "match"));
                // Exact email is the strongest identifier and fires first.
                assert!(matches!(get("reason"), Value::String(s) if s == "exact_email"));
                assert!(matches!(get("email"), Value::Float(f) if f == 1.0));
                assert!(matches!(get("phone"), Value::Float(f) if f == 1.0));
                assert!(matches!(get("combined"), Value::Float(f) if f >= 0.9));
            }
            other => panic!("expected PairScore struct, got {}", type_name(other)),
        }

        // Genuinely different entities → no.
        let x = rec("x1", "Zebra Liquor", "100 Congress Ave Austin TX 78701", "5125551000", "zebra@example.com", "zebraliquor.com");
        let y = rec("y1", "Alpha Grocery", "900 Parmer Ln Austin TX 78753", "7375552000", "alpha@example.com", "alphagrocery.com");
        let p2 = pair(&x, &y, &Value::Nil).expect("pair ok");
        match &p2 {
            Value::Struct { fields, .. } => {
                let get = |k: &str| find_field(fields, k).unwrap().clone();
                assert!(matches!(get("verdict"), Value::String(s) if s == "no"));
            }
            other => panic!("expected PairScore, got {}", type_name(other)),
        }

        // Disjoint short addresses force the address-contradiction veto.
        let v1 = rec("v1", "Zebra Liquor", "100 main st", "5125551000", "", "");
        let v2 = rec("v2", "Acme Corp", "900 oak ave", "5125559000", "", "");
        let pv = pair(&v1, &v2, &Value::Nil).expect("pair ok");
        match &pv {
            Value::Struct { fields, .. } => {
                let get = |k: &str| find_field(fields, k).unwrap().clone();
                assert!(matches!(get("verdict"), Value::String(s) if s == "no"));
                assert!(
                    matches!(get("reason"), Value::String(s) if s == "conflicting_address"),
                    "two present + disagreeing addresses must veto"
                );
            }
            other => panic!("expected PairScore, got {}", type_name(other)),
        }

        // Same brand name, different physical stores → no (address veto).
        let m1 = rec("m1", "Quick Mart", "1103 Lathrop Dr Austin TX 78704", "5125550142", "", "");
        let m2 = rec("m2", "Quick Mart", "900 Congress Ave Austin TX 78701", "5125559000", "", "");
        let p3 = pair(&m1, &m2, &Value::Nil).expect("pair ok");
        match &p3 {
            Value::Struct { fields, .. } => {
                let get = |k: &str| find_field(fields, k).unwrap().clone();
                assert!(matches!(get("verdict"), Value::String(s) if s == "no"), "same brand + different stores must not merge");
                // Disagreeing house numbers are a hard contradiction.
                assert!(matches!(get("reason"), Value::String(s) if s == "conflicting_address"));
            }
            other => panic!("expected PairScore, got {}", type_name(other)),
        }
    }

    #[test]
    fn pair_thresholds_are_arguments() {
        // Two records share an exact phone but their names barely overlap —
        // conservative defaults refuse the merge...
        let a = rec("w1", "Quik Stop Foods", "", "5125550142", "", "");
        let b = rec("w2", "Corner Deli", "", "5125550142", "", "");
        let strict = pair(&a, &b, &Value::Nil).expect("pair ok");
        match &strict {
            Value::Struct { fields, .. } => {
                let verdict = find_field(fields, "verdict").unwrap();
                assert!(matches!(verdict, Value::String(s) if s == "no"));
            }
            other => panic!("expected PairScore, got {}", type_name(other)),
        }
        // ...but relaxing the exact-phone name floor is an explicit argument.
        let relaxed = mk_keys(&[("phone_name_min", 0.2)]);
        let loose = pair(&a, &b, &relaxed).expect("pair ok");
        match &loose {
            Value::Struct { fields, .. } => {
                let verdict = find_field(fields, "verdict").unwrap();
                assert!(matches!(verdict, Value::String(s) if s == "match"));
            }
            other => panic!("expected PairScore, got {}", type_name(other)),
        }
    }

    // ── Resolve ───────────────────────────────────────────────────────

    #[test]
    fn same_store_two_spellings_with_phone_email_variants_clusters() {
        let cands = vec![
            rec("r-101", "Quik Food Store", "1103 Lathrop Dr Austin TX 78704", "(512) 555-0142", "quikfoods.lathrop@example.com", ""),
            rec("r-202", "Quik Foods", "1103 Lathrop Drive Austin TX 78704", "512-555-0142", "QUIKFOODS.LATHROP@example.com", ""),
            rec("r-303", "Quik Food Store 1103", "1103 Lathrop Dr", "+1-512-555-0142", "", ""),
            // A genuinely different store in the same zip must stay out.
            rec("r-404", "Zebra Liquor", "1109 Lathrop Dr Austin TX 78704", "5125558888", "zebra@example.com", ""),
        ];
        let clusters = run(&cands, &Value::Nil);
        // r-101/r-202/r-303 cluster together; r-404 stays singleton.
        assert_eq!(clusters.len(), 2, "expected 2 clusters, got {}", clusters.len());
        let big = clusters
            .iter()
            .find(|c| member_count(c) == 3)
            .expect("a 3-member cluster");
        let ids = member_ids(big);
        assert_eq!(ids, vec!["r-101", "r-202", "r-303"]);
        // Deterministic canonical id: smallest record id.
        assert!(matches!(get_cluster_field(big, "canonical_id"), Value::String(s) if s == "r-101"));
        assert!(matches!(get_cluster_field(big, "canonical"), Value::String(s) if s == "Quik Food Store"));
        // Members carry evidence against the canonical.
        match get_cluster_field(big, "evidence") {
            Value::Array(ev) => {
                assert_eq!(ev.len(), 2, "canonical member has no evidence entry");
                for e in ev {
                    match e {
                        Value::Struct { fields, .. } => {
                            assert!(find_field(fields, "record_id").is_some());
                            assert!(matches!(find_field(fields, "compared_to"), Some(Value::String(s)) if s == "r-101"));
                            assert!(find_field(fields, "field").is_some());
                            assert!(find_field(fields, "note").is_some());
                        }
                        other => panic!("evidence not a struct: {}", type_name(other)),
                    }
                }
            }
            other => panic!("evidence not an array: {}", type_name(other)),
        }
        // Cluster score reflects the weakest merge link.
        match get_cluster_field(big, "score") {
            Value::Float(f) => assert!(*f >= 0.9, "cluster score {f}"),
            other => panic!("score not float: {}", type_name(other)),
        }
        // Singleton has one member, no evidence, score 1.0.
        let single = clusters.iter().find(|c| member_count(c) == 1).unwrap();
        assert!(matches!(get_cluster_field(single, "canonical_id"), Value::String(s) if s == "r-404"));
        match get_cluster_field(single, "evidence") {
            Value::Array(a) => assert!(a.is_empty()),
            other => panic!("evidence not array: {}", type_name(other)),
        }
    }

    #[test]
    fn genuinely_different_entities_never_merge() {
        let cands = vec![
            rec("s-1", "Zebra Liquor", "100 Congress Ave Austin TX 78701", "5125551000", "zebra@example.com", "zebraliquor.com"),
            rec("s-2", "Alpha Grocery", "900 Parmer Ln Austin TX 78753", "7375552000", "alpha@example.com", "alphagrocery.com"),
            // Same brand name but a different physical store: must NOT merge
            // with s-3 (precision guard against brand-level over-merging).
            rec("s-3", "Quick Mart", "1103 Lathrop Dr Austin TX 78704", "5125550142", "", ""),
            rec("s-4", "Quick Mart", "900 Congress Ave Austin TX 78701", "5125559000", "", ""),
            // Name-similar but unrelated.
            rec("s-5", "Alpha Grocery Market", "2300 Willow Creek Dr Austin TX 78741", "5125557777", "", ""),
        ];
        let clusters = run(&cands, &Value::Nil);
        assert_eq!(clusters.len(), 5, "all five records are distinct entities: {}", clusters.len());
        for c in &clusters {
            assert_eq!(member_count(c), 1, "no cluster may hold distinct entities");
        }
    }

    #[test]
    fn resolve_is_deterministic_across_input_order() {
        let a = rec("b-1", "Quik Food Store", "1103 Lathrop Dr Austin TX 78704", "(512) 555-0142", "q@example.com", "");
        let b = rec("a-2", "Quik Foods", "1103 Lathrop Drive Austin TX 78704", "512-555-0142", "Q@example.com", "");
        let c = rec("c-3", "Zebra Liquor", "100 Congress Ave Austin TX 78701", "5125551000", "", "");
        let forward = run(&[a.clone(), b.clone(), c.clone()], &Value::Nil);
        let shuffled = run(&[c.clone(), a.clone(), b.clone()], &Value::Nil);
        assert_eq!(forward.len(), 2);
        assert_eq!(shuffled.len(), 2);
        assert_eq!(cluster_ids(&forward), cluster_ids(&shuffled));
        // Same clusters, same members, same canonical regardless of order.
        let f_ids: Vec<Vec<String>> = forward.iter().map(member_ids).collect();
        let s_ids: Vec<Vec<String>> = shuffled.iter().map(member_ids).collect();
        assert_eq!(f_ids, s_ids);
        for cl in &forward {
            match get_cluster_field(cl, "cluster_id") {
                Value::String(s) => assert!(s.starts_with("cl-"), "id {s}"),
                other => panic!("bad cluster_id {}", type_name(other)),
            }
        }
        // Cluster with the lexicographically smallest record id is canonical
        // for the merged pair: a-2 is the canonical member.
        let merged = forward.iter().find(|c| member_count(c) == 2).unwrap();
        assert!(matches!(get_cluster_field(merged, "canonical_id"), Value::String(s) if s == "a-2"));
    }

    #[test]
    fn resolve_honors_threshold_arguments() {
        // Defaults: strong name agreement → merged via `combined`.
        // (Address only on side A, so the pair is not an exact address and
        // must clear `combined_min`.)
        let a = rec("t-1", "Quick Food Store", "1103 Lathrop Dr Austin TX 78704", "", "", "");
        let b = rec("t-2", "Quik Foods", "", "", "", "");
        // Defaults: strong name + very close address → merged via combined.
        let default = run(&[a.clone(), b.clone()], &Value::Nil);
        assert_eq!(default.len(), 1, "default thresholds should merge the pair");
        // A stricter combined floor is a plain argument and refuses.
        let strict_keys = mk_keys(&[("combined_min", 0.99)]);
        let strict = run(&[a.clone(), b.clone()], &strict_keys);
        assert_eq!(strict.len(), 2, "raised combined_min must prevent the merge");
    }

    #[test]
    fn provenance_passthrough_rides_on_members() {
        let prov = Value::Struct {
            name: "SourceRef".into(),
            fields: vec![
                ("source".into(), Value::String("txabc".into())),
                ("record".into(), Value::String("lic-123".into())),
            ],
        };
        let with_prov = Value::Struct {
            name: "EntityCandidate".into(),
            fields: vec![
                ("id".into(), Value::String("p-1".into())),
                ("name".into(), Value::String("Quik Food Store".into())),
                ("address".into(), Value::String("1103 Lathrop Dr Austin TX 78704".into())),
                ("phone".into(), Value::String("5125550142".into())),
                ("provenance".into(), prov.clone()),
            ],
        };
        let no_prov = Value::Struct {
            name: "EntityCandidate".into(),
            fields: vec![
                ("id".into(), Value::String("p-2".into())),
                ("name".into(), Value::String("Quik Foods".into())),
                ("address".into(), Value::String("1103 Lathrop Drive Austin TX 78704".into())),
                ("phone".into(), Value::String("512-555-0142".into())),
            ],
        };
        let clusters = run(&[with_prov, no_prov], &Value::Nil);
        assert_eq!(clusters.len(), 1);
        match get_cluster_field(&clusters[0], "members") {
            Value::Array(members) => {
                for m in members {
                    match m {
                        Value::Struct { fields, .. } => {
                            let pid = find_field(fields, "record_id").unwrap().clone();
                            let provenance = find_field(fields, "provenance").unwrap();
                            if matches!(pid, Value::String(s) if s == "p-1") {
                                match provenance {
                                    Value::Struct { name, fields: pf } => {
                                        assert_eq!(name, "SourceRef");
                                        assert!(matches!(find_field(pf, "source"), Some(Value::String(s)) if s == "txabc"));
                                    }
                                    other => panic!("expected passthrough provenance, got {}", type_name(other)),
                                }
                            } else {
                                assert!(matches!(provenance, Value::Nil), "no provenance → nil field");
                            }
                        }
                        other => panic!("member not struct: {}", type_name(other)),
                    }
                }
            }
            other => panic!("members not array: {}", type_name(other)),
        }
    }

    #[test]
    fn dispatch_routes() {
        // Keys delegate through dispatch.
        let r = dispatch("phone_key", vec![Value::String("(512) 555-0142".into())]);
        assert!(matches!(r.unwrap().unwrap(), Value::String(s) if s == "5125550142"));
        // Resolve via dispatch with a struct candidate array.
        let cands = Value::Array(vec![
            rec("d-1", "Quik Food Store", "1103 Lathrop Dr Austin TX 78704", "5125550142", "", ""),
            rec("d-2", "Quik Foods", "1103 Lathrop Drive Austin TX 78704", "512-555-0142", "", ""),
        ]);
        let r = dispatch("resolve", vec![cands, Value::Nil]);
        match r.unwrap().unwrap() {
            Value::Array(clusters) => assert_eq!(clusters.len(), 1),
            other => panic!("expected cluster array, got {}", type_name(&other)),
        }
        // Wrong arity / wrong types → honest errors, never panics.
        assert!(dispatch("resolve", vec![]).unwrap().is_err());
        assert!(dispatch("resolve", vec![Value::String("nope".into())]).unwrap().is_err());
        assert!(dispatch("resolve", vec![Value::Array(vec![]), Value::String("k".into())]).unwrap().is_err());
        assert!(dispatch("pair", vec![Value::String("x".into())]).unwrap().is_err());
        // Unknown function → None.
        assert!(dispatch("not_a_function", vec![]).is_none());
    }

    #[test]
    fn interp_end_to_end() {
        // Full lex→parse→interpret path: proves module-namespace routing for
        // the lowercase spelling, the capitalized `Entity` spelling (resolved
        // through the lowercase fallback), and map-literal candidates.
        let src = r#"
        fn main() {
            let a = {"id": "i-1", "name": "Quik Food Store", "address": "1103 Lathrop Dr Austin TX 78704", "phone": "(512) 555-0142", "email": "qfs@example.com"}
            let b = {"id": "i-2", "name": "Quik Foods", "address": "1103 Lathrop Drive Austin TX 78704", "phone": "512-555-0142", "email": "QFS@example.com"}
            let z = {"id": "i-9", "name": "Zebra Liquor", "address": "100 Congress Ave Austin TX 78701", "phone": "5125551000", "email": "z@example.com"}
            let p = entity.pair(a, b)
            let p2 = Entity.pair(a, z)
            print(p.verdict)
            print(p2.verdict)
            print(entity.phone_key("+1 (512) 555-0142"))
            let cs = Entity.resolve([a, b, z], nil)
            let c0 = cs[0]
            let c1 = cs[1]
            print(c0.cluster_id)
            print(c0.canonical_id)
            print(c1.cluster_id)
            print(c1.canonical_id)
        }
        "#;
        let (tokens, lex_errs) = crate::lexer::tokenize(src);
        assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        let mut interp = crate::interp::Interpreter::new();
        interp.run(&program).expect("interp run failed");
        assert_eq!(interp.output[0], "match", "pair(a,b) must merge");
        assert_eq!(interp.output[1], "no", "pair(a,z) must not merge");
        assert_eq!(interp.output[2], "5125550142");
        // Deterministic ids: smallest-id cluster first; canonical member is
        // the smallest record id inside each cluster.
        assert_eq!(interp.output[3], "cl-0001");
        assert_eq!(interp.output[4], "i-1");
        assert_eq!(interp.output[5], "cl-0002");
        assert_eq!(interp.output[6], "i-9");
    }
}
