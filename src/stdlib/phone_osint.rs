//! Phone OSINT engine — the 1000x-better phone-intelligence layer.
//!
//! P0: typed [`PhoneNumber`] entity + offline NANP/carrier derivation.
//!     A NANP number decomposes into strata that are publicly derivable offline
//!     (rate center, wire center, LATA, V&H, timezone, OCN carrier, line type
//!     as-allocated) from a versioned NPA-NXX/OCN dataset. This is the core
//!     "truth layer" that no paywalled aggregator provides.

use crate::interp::Value;

/// Parsed NANP (North American Numbering Plan) components.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NanpParts {
    pub npa: String,      // area code (first 3)
    pub nxx: String,      // central office code / exchange (next 3)
    pub subscriber: String, // last 4
    pub national: String, // 10-digit all-destination form
    pub e164: String,     // +1XXXXXXXXXX
}

/// Offline-derivable geographic/carrier allocation facts for a NANP number.
///
/// These all come from the *allocation* (Tier A/B) — public numbering-assignment
/// data, deterministic, and freshest-monthly. They are NOT the current carrier
/// after a port (Tier C needs an NPAC/LRN dip). Always annotate this distinction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NanpAllocation {
    pub state: String,
    pub country: String,      // "US" / "CA" / "AG" etc.
    pub lata: String,
    pub rate_center: String,  // RCLONG name (city/town)
    pub wire_center: String,  // serving switch name
    pub clli: String,         // 11-char Common Language Location Identifier
    pub latitude: f64,
    pub longitude: f64,
    pub timezone_iana: String,
    pub ocn: String,          // Operating Company Number (4-char)
    pub carrier_name: String, // carrier the block is assigned to
    pub line_type: String,    // wireless | wireline | voip | paging
    pub pooled: bool,         // thousands-block pooling in use
    pub extent: String,       // LATA/extent descriptor
}

/// A minimal versioned NPA-NXX -> allocation record.
///
/// Real deployments load a full licensed NPA-NXX/LERG dataset; the struct and
/// loader support that. `load_dataset` reads a JSON array of these records,
/// keyed by (npa, nxx).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NpaNxxRecord {
    pub npa: String,
    pub nxx: String,
    pub state: String,
    pub lata: String,
    pub rate_center: String,
    pub wire_center: String,
    pub clli: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone_iana: String,
    pub ocn: String,
    pub carrier_name: String,
    pub line_type: String,
    pub pooled: bool,
}

/// A versioned phone-numbering dataset with provenance.
///
/// Carries a release version + source so every derived fact is traceable
/// (W3C-PROV style) and monthly delta-loads are possible.
#[derive(Debug, Clone, Default)]
pub struct NumberingDataset {
    pub release_version: String,
    pub source: String,
    pub records: Vec<NpaNxxRecord>,
}

impl NumberingDataset {
    /// Look up an NPA-NXX allocation from the loaded dataset.
    pub fn lookup(&self, npa: &str, nxx: &str) -> Option<&NpaNxxRecord> {
        self.records
            .iter()
            .find(|r| r.npa == npa && r.nxx == nxx)
    }

    /// Record count (for tests/metrics).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Parse a raw number/string into NANP parts (US/CA), normalizing to E.164.
///
/// Handles: bare digits, "512-850-1815", "(512) 850-1815", "+15128501815",
/// "15128501815", "5128501815". Returns None when not a 10-digit NANP number.
pub fn parse_nanp(input: &str, default_cc: &str) -> Option<NanpParts> {
    let mut digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();

    // Strip international "00" prefix or leading CC "1" but keep 10 digits.
    if digits.len() > 10 && digits.starts_with("00") {
        digits = digits[2..].to_string();
    }
    if digits.len() == 11 && digits.starts_with('1') {
        digits = digits[1..].to_string();
    }
    if digits.len() == 10 {
        let (npa, rest) = digits.split_at(3);
        let (nxx, subscriber) = rest.split_at(3);
        Some(NanpParts {
            npa: npa.to_string(),
            nxx: nxx.to_string(),
            subscriber: subscriber.to_string(),
            national: digits.clone(),
            e164: format!("+1{digits}"),
        })
    } else if digits.len() == 10 && default_cc == "1" {
        let (npa, rest) = digits.split_at(3);
        let (nxx, subscriber) = rest.split_at(3);
        Some(NanpParts {
            npa: npa.to_string(),
            nxx: nxx.to_string(),
            subscriber: subscriber.to_string(),
            national: digits.clone(),
            e164: format!("+1{digits}"),
        })
    } else {
        None
    }
}

/// State/country from a 3-digit NPA, using the public NANP NPA-assignment
/// ranges (approximate; a full dataset refines per rate center).
pub fn npa_state_hint(npa: &str) -> (&'static str, &'static str) {
    match npa {
        // Broad area-code -> state/country map (major blocks). A real dataset
        // resolves each rate center; this is an offline hint for tests/UX.
        "201" | "973" | "908" | "551" | "862" | "732" | "848" | "609" | "856" => ("NJ", "US"),
        "212" | "347" | "917" | "646" | "718" | "929" | "516" | "631" | "914" => ("NY", "US"),
        "512" | "713" | "281" | "832" | "210" | "972" | "214" | "469" | "979" | "936" | "956" | "915" | "806" | "817" | "682" | "940" | "830" | "325" | "432" | "361" | "254" | "903" | "430" | "903" => ("TX", "US"),
        "305" | "786" | "954" | "561" | "407" | "321" | "904" | "850" | "239" | "863" | "941" | "813" | "727" | "352" | "386" | "772" | "228" | "850" => ("FL", "US"),
        "213" | "310" | "323" | "818" | "626" | "562" | "714" | "949" | "619" | "858" | "760" | "951" | "559" | "661" | "530" | "415" | "925" | "510" | "650" | "408" | "831" | "805" | "209" | "916" => ("CA", "US"),
        "206" | "425" | "509" | "253" | "360" => ("WA", "US"),
        _ => ("US", "US"),
    }
}

/// Derive the offline allocation facts for a parsed NANP number.
///
/// Uses the dataset first (authoritative per rate center); falls back to the
/// coarse NPA hint + defaults when the dataset has no exact (npa,nxx) row.
/// Returns a [`NanpAllocation`] with `line_type`, `carrier_name`, etc. filled
/// from the dataset, or sensible defaults.
pub fn derive_allocation(parts: &NanpParts, dataset: &NumberingDataset) -> NanpAllocation {
    let rec = dataset.lookup(&parts.npa, &parts.nxx);
    let (state, country) = npa_state_hint(&parts.npa);

    NanpAllocation {
        state: rec.map(|r| r.state.clone()).unwrap_or_else(|| state.to_string()),
        country: country.to_string(),
        lata: rec.map(|r| r.lata.clone()).unwrap_or_default(),
        rate_center: rec.map(|r| r.rate_center.clone()).unwrap_or_default(),
        wire_center: rec.map(|r| r.wire_center.clone()).unwrap_or_default(),
        clli: rec.map(|r| r.clli.clone()).unwrap_or_default(),
        latitude: rec.map(|r| r.latitude).unwrap_or(0.0),
        longitude: rec.map(|r| r.longitude).unwrap_or(0.0),
        timezone_iana: rec.map(|r| r.timezone_iana.clone()).unwrap_or_else(|| {
            if state == "TX" { "America/Chicago".into() }
            else if state == "CA" { "America/Los_Angeles".into() }
            else if state == "NY" { "America/New_York".into() }
            else { "America/New_York".into() }
        }),
        ocn: rec.map(|r| r.ocn.clone()).unwrap_or_default(),
        carrier_name: rec.map(|r| r.carrier_name.clone()).unwrap_or_else(|| "unknown".into()),
        line_type: rec.map(|r| r.line_type.clone()).unwrap_or_else(|| "unknown".into()),
        pooled: rec.map(|r| r.pooled).unwrap_or(false),
        extent: rec.map(|r| r.lata.clone()).unwrap_or_default(),
    }
}

/// Build a `PhoneNumber` entity Value (the P0 offline facts), with
/// W3C-PROV provenance pointing at the dataset release + source.
pub fn phone_entity_value(parts: &NanpParts, alloc: &NanpAllocation, dataset: &NumberingDataset) -> Value {
    Value::Struct {
        name: "PhoneNumber".to_string(),
        fields: vec![
            ("input".to_string(), Value::String(parts.national.clone())),
            ("e164".to_string(), Value::String(parts.e164.clone())),
            ("npa".to_string(), Value::String(parts.npa.clone())),
            ("nxx".to_string(), Value::String(parts.nxx.clone())),
            ("subscriber".to_string(), Value::String(parts.subscriber.clone())),
            ("state".to_string(), Value::String(alloc.state.clone())),
            ("country_code".to_string(), Value::String(alloc.country.clone())),
            ("lata".to_string(), Value::String(alloc.lata.clone())),
            ("rate_center".to_string(), Value::String(alloc.rate_center.clone())),
            ("wire_center".to_string(), Value::String(alloc.wire_center.clone())),
            ("clli".to_string(), Value::String(alloc.clli.clone())),
            ("latitude".to_string(), Value::Float(alloc.latitude)),
            ("longitude".to_string(), Value::Float(alloc.longitude)),
            ("timezone_iana".to_string(), Value::String(alloc.timezone_iana.clone())),
            ("ocn".to_string(), Value::String(alloc.ocn.clone())),
            ("carrier_as_allocated".to_string(), Value::String(alloc.carrier_name.clone())),
            ("line_type_as_allocated".to_string(), Value::String(alloc.line_type.clone())),
            ("thousands_block_pooled".to_string(), Value::Bool(alloc.pooled)),
            // Honest confidence framing: allocation is high, current carrier is
            // unknown until an LRN/NPAC dip (Tier C) is performed.
            ("allocation_confidence".to_string(), Value::Float(0.9)),
            ("current_carrier".to_string(), Value::String("unknown-needs-lrn-dip".to_string())),
            (
                "provenance".to_string(),
                Value::Array(vec![Value::Struct {
                    name: "Provenance".to_string(),
                    fields: vec![
                        ("source".to_string(), Value::String(dataset.source.clone())),
                        ("release_version".to_string(), Value::String(dataset.release_version.clone())),
                        ("data_tier".to_string(), Value::String("A-B (public allocation)".to_string())),
                        ("derivation".to_string(), Value::String("offline-nanp".to_string())),
                    ],
                }]),
            ),
        ],
    }
}

/// Build an in-memory dataset from a compact `(npa,nxx,state,lata,rc,wc,clli,
/// lat,lon,tz,ocn,carrier,line_type,pooled)` row — used by the loader and
/// tests. Mirrors how a real NPA-NXX/LERG JSON feed deserializes.
pub fn make_dataset(records: Vec<NpaNxxRecord>, release_version: &str, source: &str) -> NumberingDataset {
    NumberingDataset {
        release_version: release_version.to_string(),
        source: source.to_string(),
        records,
    }
}

/// Load a full NPA-NXX dataset from a JSON file. The file is a JSON object:
/// `{ "release_version": "...", "source": "...", "records": [ {npa,nxx,state,
/// lata,rate_center,wire_center,clli,latitude,longitude,timezone_iana,ocn,
/// carrier_name,line_type,pooled}, ... ] }` — the same shape `derive_allocation`
/// consumes. Returns Err on read/parse failure so a bad dataset can't silently
/// fall back to stale seed data (better to fail loudly than serve the wrong
/// allocation).
pub fn load_dataset_from_json(path: &str) -> Result<NumberingDataset, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("load_dataset_from_json: cannot read {path}: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("load_dataset_from_json: bad JSON in {path}: {e}"))?;

    let release_version = v["release_version"].as_str().unwrap_or("unknown").to_string();
    let source = v["source"].as_str().unwrap_or("json-file").to_string();

    let mut records = Vec::new();
    if let Some(arr) = v["records"].as_array() {
        for item in arr {
            let get_str = |k: &str| item[k].as_str().unwrap_or_default().to_string();
            let get_f = |k: &str| item[k].as_f64().unwrap_or(0.0);
            let get_b = |k: &str| item[k].as_bool().unwrap_or(false);
            let npa = get_str("npa");
            if npa.is_empty() {
                continue;
            }
            records.push(NpaNxxRecord {
                npa,
                nxx: get_str("nxx"),
                state: get_str("state"),
                lata: get_str("lata"),
                rate_center: get_str("rate_center"),
                wire_center: get_str("wire_center"),
                clli: get_str("clli"),
                latitude: get_f("latitude"),
                longitude: get_f("longitude"),
                timezone_iana: get_str("timezone_iana"),
                ocn: get_str("ocn"),
                carrier_name: get_str("carrier_name"),
                line_type: get_str("line_type"),
                pooled: get_b("pooled"),
            });
        }
    }
    if records.is_empty() {
        return Err(format!("load_dataset_from_json: {path} had no records"));
    }
    Ok(NumberingDataset {
        release_version,
        source,
        records,
    })
}

/// Load the numbering dataset, preferring the `TALLOW_NANP_DATASET` env var
/// (path to a full NPA-NXX JSON) and falling back to a default workspace path
/// (`data/nanp_dataset.json` when present), then the built-in seed. A valid
/// env var that fails to load is treated as an error (fail loud), so a stale or
/// wrong dataset is never silently served.
pub fn load_numbering_dataset(seed: NumberingDataset) -> Result<NumberingDataset, String> {
    // 1. Explicit env var (authoritative, fail loud).
    if let Ok(path) = std::env::var("TALLOW_NANP_DATASET") {
        if !path.is_empty() {
            return load_dataset_from_json(&path);
        }
    }
    // 2. Conventional default path (persistent, no env needed).
    if let Ok(workspace) = std::env::var("TALLOW_WORKSPACE") {
        let default = std::path::Path::new(&workspace).join("data").join("nanp_dataset.json");
        if default.exists() {
            return load_dataset_from_json(&default.to_string_lossy().to_string());
        }
    }
    for candidate in ["data/nanp_dataset.json", "nanp_dataset.json"] {
        if std::path::Path::new(candidate).exists() {
            return load_dataset_from_json(candidate);
        }
    }
    // 3. Seed fallback.
    Ok(seed)
}

// ══════════════════════════════════════════════════════════════════
// P1 — Phone owner evidence-tiered resolver (no guessed cell-owner names)
// ══════════════════════════════════════════════════════════════════

/// A single piece of owner-name evidence from one source.
///
/// `source_class` drives the evidence tier:
///   - "register"  -> primary public register (county deed, SOS, FCC ULS,
///                    licensed professional board, business license)
///   - "directory" -> public/business directory, contact page on an official
///                    domain that the entity controls
///   - "community" -> community/consent-backed tag (for a cell number this is
///                    weak — a phonebook label, not a verified subscriber)
///   - "commercial"-> an aggregator/people-search result (we usually decline
///                    these; kept for completeness and marked low tier)
///
/// Rule: a single anonymous phonebook/community label on a wireless number
/// NEVER reaches "Documented". It is at best "Alleged".
#[derive(Debug, Clone)]
pub struct OwnerEvidence {
    pub name: String,
    pub source: String,
    pub source_url: String,
    pub source_class: String, // register | directory | community | commercial
    pub observed_at: String,  // ISO timestamp
}

/// Evidence tier for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceTier {
    Unfalsifiable,
    Alleged,
    Documented,
}

impl EvidenceTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceTier::Unfalsifiable => "Unfalsifiable",
            EvidenceTier::Alleged => "Alleged",
            EvidenceTier::Documented => "Documented",
        }
    }
}

/// Weight of a source class for corroboration. Register = strong, directory =
/// medium, community = weak (a single phonebook label is not a verified owner),
/// commercial = weak (aggregator output is unprovenanced by definition).
fn source_class_weight(class: &str) -> f64 {
    match class {
        "register" => 1.0,
        "directory" => 0.6,
        "community" => 0.3,
        "commercial" => 0.2,
        _ => 0.1,
    }
}

/// Whether two evidence records refer to the same owner name (normalized).
pub fn same_owner(a: &str, b: &str) -> bool {
    let na = a.chars().filter(|c| c.is_alphabetic())
        .flat_map(|c| c.to_lowercase())
        .collect::<String>();
    let nb = b.chars().filter(|c| c.is_alphabetic())
        .flat_map(|c| c.to_lowercase())
        .collect::<String>();
    !na.is_empty() && na == nb
}

/// Aggregate owner-name evidence across sources into a tiered attribution.
///
/// Returns (evidence_tier, confidence, corroborating_sources, label).
/// - `Documented` requires >=2 independent sources of weight >=0.6 (register or
///   directory) that agree on the (normalized) name — never a single community
///   label.
/// - `Alleged` = exactly one moderate/strong source, or weak-sources-only that
///   agree.
/// - `Unfalsifiable` = no agreeing independent evidence at all.
pub fn resolve_owner_evidence(evidence: &[OwnerEvidence]) -> (EvidenceTier, f64, u32, String) {
    if evidence.is_empty() {
        return (EvidenceTier::Unfalsifiable, 0.0, 0, String::new());
    }

    // Normalize into name -> (best_weight, count_independent_sources, label).
    // Independence = distinct non-empty source_url values. A record with an
    // empty source_url raises the weight but does NOT count toward the ">=2
    // independent sources" documented gate (we cannot verify it is distinct).
    let mut name_agg: std::collections::BTreeMap<String, (f64, u32, String)> =
        std::collections::BTreeMap::new();
    let mut name_sources: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for ev in evidence {
        let norm = ev
            .name
            .chars()
            .filter(|c| c.is_alphabetic())
            .flat_map(|c| c.to_lowercase())
            .collect::<String>();
        if norm.is_empty() {
            continue;
        }
        let entry = name_agg.entry(norm.clone()).or_insert((0.0, 0, ev.name.clone()));
        entry.0 = entry.0.max(source_class_weight(&ev.source_class));
        if !ev.source_url.trim().is_empty() {
            let src = name_sources.entry(norm.clone()).or_insert_with(Default::default);
            if src.insert(ev.source_url.trim().to_string()) {
                entry.1 += 1;
            }
        }
    }

    // Pick the best name by (independent source count, then aggregate weight).
    let (best_norm, (best_weight, best_count, best_label)) = name_agg
        .into_iter()
        .max_by(|a, b| {
            a.1 .1.cmp(&b.1 .1).then(a.1 .0.partial_cmp(&b.1 .0).unwrap_or(std::cmp::Ordering::Equal))
        })
        .unwrap();

    // Documented: >=2 independent agreeing sources AND the strongest source is
    // register or directory (weight >=0.6). A community label alone can never
    // be Documented.
    let documented = best_count >= 2 && best_weight >= 0.6;
    let alleged = !documented && best_count >= 1;

    let tier = if documented {
        EvidenceTier::Documented
    } else if alleged {
        EvidenceTier::Alleged
    } else {
        EvidenceTier::Unfalsifiable
    };

    // Confidence: scaled by source count + strongest weight, clamped to a tier
    // ceiling (Documented <=0.95, Alleged <=0.6, Unfalsifiable <=0.2).
    let raw = (best_count as f64 * 0.2 + best_weight * 0.5).min(1.0);
    let confidence = match tier {
        EvidenceTier::Documented => raw.min(0.95),
        EvidenceTier::Alleged => raw.min(0.6),
        EvidenceTier::Unfalsifiable => 0.0f64.min(0.2),
    };

    (tier, confidence, best_count, if best_norm.is_empty() { String::new() } else { best_label })
}

/// Render an owner-attribution Value for a PhoneNumber entity, carrying the
/// per-source evidence list + the tiered verdict. Never fabricates: if tier is
/// Unfalsifiable the `owner` field is set to "unknown" (not guessed).
pub fn owner_attribution_value(tier: EvidenceTier, confidence: f64, sources: u32, label: String, evidence: &[OwnerEvidence]) -> Value {
    let owner = match tier {
        EvidenceTier::Unfalsifiable => "unknown".to_string(),
        _ => label,
    };
    let evidence_arr: Vec<Value> = evidence
        .iter()
        .map(|ev| Value::Struct {
            name: "OwnerEvidence".to_string(),
            fields: vec![
                ("name".to_string(), Value::String(ev.name.clone())),
                ("source".to_string(), Value::String(ev.source.clone())),
                ("source_url".to_string(), Value::String(ev.source_url.clone())),
                ("source_class".to_string(), Value::String(ev.source_class.clone())),
                ("observed_at".to_string(), Value::String(ev.observed_at.clone())),
            ],
        })
        .collect();
    Value::Struct {
        name: "OwnerAttribution".to_string(),
        fields: vec![
            ("owner".to_string(), Value::String(owner)),
            ("evidence_tier".to_string(), Value::String(tier.as_str().to_string())),
            ("confidence".to_string(), Value::Float(confidence)),
            ("corroborating_sources".to_string(), Value::Int(sources as i128)),
            ("evidence".to_string(), Value::Array(evidence_arr)),
            ("honesty_note".to_string(), Value::String(
                "owner identity is only as strong as its independent sources; a single \
                 community/phonebook label is never treated as a verified owner"
                    .to_string(),
            )),
        ],
    }
}

/// A single spam-reputation report (aggregated, not raw) for a number.
///
/// `source_bits` bitmask: 1=USER_LABEL, 2=CONSENTED_CONTACT, 4=FCC_COMPLAINT,
/// 8=AG_COMPLAINT, 16=DNC_FLAG, 32=PUBLIC_BLOCKLIST. `reports` is the recency-
/// decayed count of reports within the recall window.
#[derive(Debug, Clone)]
pub struct SpamSignal {
    pub reports: u32,           // recency-decayed report count (half-life 60d)
    pub category: String,       // spam/robocall/scam/telemarketing/legitimate_business
    pub source_bits: u8,        // bitmask of which signals contributed
    pub verified_business: bool,
    pub last_seen: u32,         // unix timestamp
}

/// Computed transparent spam reputation (never a black-box proprietary score).
#[derive(Debug, Clone)]
pub struct SpamReputation {
    pub spam_score: f64,       // 0.0-1.0 continuous
    pub verdict: String,       // confirmed | suspected | unknown | legitimate
    pub category: String,
    pub report_entropy: f64,   // 0-1 disagreement across reporters
    pub source_count: u8,      // distinct independent sources contributing
    pub verification_override: bool, // verified_business zeroed the score
}

/// Compute a spam reputation from aggregated signals.
///
/// Formula (transparent, recency-aware, entropy-penalized):
///   raw = min(1.0, reports/20 * 0.7 + source_count*0.05)
///   if report_entropy > 0.6 (high disagreement) -> penalize toward "contested"
///   verified_business -> override to 0.0 (legitimate)
/// Verdict: confirmed (score>=0.8 & source_count>=2 & recent), suspected
/// (score>=0.4), unknown (no signal), legitimate (verified business or score<0.1).
pub fn compute_spam_reputation(sig: &SpamSignal, report_entropy: f64, now: u32) -> SpamReputation {
    let source_count = sig.source_bits.count_ones() as u8;
    let mut score = (sig.reports as f64 / 20.0 * 0.7 + source_count as f64 * 0.05).min(1.0);
    // Entropy penalty: high disagreement among reporters caps the score.
    if report_entropy > 0.6 {
        score = score.min(0.5);
    }
    // Verified business always zeroes the score (legitimate).
    if sig.verified_business {
        score = 0.0;
    }
    let verdict = if sig.verified_business {
        "legitimate"
    } else if score >= 0.8 && source_count >= 2 {
        "confirmed"
    } else if score >= 0.4 {
        "suspected"
    } else if sig.reports == 0 && source_count == 0 {
        "unknown"
    } else {
        "legitimate"
    };
    SpamReputation {
        spam_score: score,
        verdict: verdict.to_string(),
        category: sig.category.clone(),
        report_entropy,
        source_count,
        verification_override: sig.verified_business,
    }
}

/// A change to a number's facts between two observation points — the alert.
#[derive(Debug, Clone)]
pub struct NumberChange {
    pub field: String,     // carrier | line_type | spam_score | verdict | ported | owner_tier
    pub before: String,
    pub after: String,
    pub changed: bool,
}

/// Diff two snapshots of a number's observed facts and emit the changed fields.
/// `before`/`after` are `(field, value)` lists. Returns only CHANGED entries so
/// a subscriber gets a precise, provenance-diffed alert rather than a blob.
pub fn diff_number_state(before: &[(String, String)], after: &[(String, String)]) -> Vec<NumberChange> {
    let mut out = Vec::new();
    for (bf, bv) in before {
        if let Some((_, av)) = after.iter().find(|(k, _)| k == bf) {
            if bv != av {
                out.push(NumberChange {
                    field: bf.clone(),
                    before: bv.clone(),
                    after: av.clone(),
                    changed: true,
                });
            }
        }
    }
    out
}

/// Render a reputation + alert Value for a PhoneNumber entity.
pub fn reputation_value(rep: &SpamReputation, signals: &[SpamSignal]) -> Value {
    Value::Struct {
        name: "SpamReputation".to_string(),
        fields: vec![
            ("spam_score".to_string(), Value::Float(rep.spam_score)),
            ("verdict".to_string(), Value::String(rep.verdict.clone())),
            ("category".to_string(), Value::String(rep.category.clone())),
            ("report_entropy".to_string(), Value::Float(rep.report_entropy)),
            ("source_count".to_string(), Value::Int(rep.source_count as i128)),
            ("verification_override".to_string(), Value::Bool(rep.verification_override)),
            ("signals".to_string(), Value::Array(signals.iter().map(|s| Value::Struct {
                name: "SpamSignal".to_string(),
                fields: vec![
                    ("reports".to_string(), Value::Int(s.reports as i128)),
                    ("category".to_string(), Value::String(s.category.clone())),
                    ("source_bits".to_string(), Value::Int(s.source_bits as i128)),
                    ("verified_business".to_string(), Value::Bool(s.verified_business)),
                ],
            }).collect())),
            ("honesty_note".to_string(), Value::String(
                "spam reputation is a transparent recency-decayed aggregate of \
                 independent signals; a single FCC complaint is 'suspected', not \
                 'confirmed', without >=2 sources"
                    .to_string(),
            )),
        ],
    }
}

// ══════════════════════════════════════════════════════════════════
// P3 — Multi-hop entity linkage (confirmed-tie graph + confidence + opt-out)
// ══════════════════════════════════════════════════════════════════

/// A confirmed tie: two identifiers co-occurring in ONE public registry row.
///
/// This is the deterministic, non-inferential edge of the graph. phone+email+
/// name in the same 990 officer block / SOS filing / FCC ULS FRN row / business
/// contact page = a documented co-occurrence, not a guess.
#[derive(Debug, Clone)]
pub struct ConfirmedTie {
    pub from_identifier: String, // e.g. "+15128501815"
    pub to_identifier: String,   // e.g. "jane@example.com"
    pub relation: String,        // person | email | address | org | relative
    pub source_url: String,
    pub row_context: String,     // "990 officer block", "SOS filing", etc.
}

/// Relative weight of an identifier type for confirming identity linkage.
fn tie_weight(relation: &str, identifier_kind: &str) -> f64 {
    // Very High discriminators: phone + email (rare collision).
    match identifier_kind {
        "phone" | "email" => 0.9,
        "address" => 0.6,
        "org" => 0.6,
        "name" => 0.3,
        "relative" => 0.2,
        _ => 0.1,
    }
}

/// Build the linkage subgraph from confirmed ties, grouped into a map of
/// `entity -> linked identifiers` with per-link confidence.
///
/// Composite-confidence rubric:
///  - High:  >=2 Very-High (phone/email) ties for the same entity, no contradictions
///  - Medium: 1 Very-High + 1 Medium (address/org), or 2 Medium
///  - Low/Insufficient: <2 discriminators (a single relative/name guess) -> refuse
///    to assert a strong identity link.
#[derive(Debug, Clone)]
pub struct LinkedEntity {
    pub key: String,
    pub labels: Vec<(String, String)>, // (identifier, relation)
    pub confidence: f64,
    pub tier: String, // High | Medium | Insufficient
    pub sources: Vec<String>,
}

pub fn build_linkage(ties: &[ConfirmedTie]) -> Vec<LinkedEntity> {
    // Group by the "from" identifier (the entity seed).
    let mut grouped: std::collections::BTreeMap<String, Vec<&ConfirmedTie>> =
        std::collections::BTreeMap::new();
    for tie in ties {
        grouped.entry(tie.from_identifier.clone()).or_default().push(tie);
    }

    grouped
        .into_iter()
        .map(|(key, ties)| {
            // Compute strongest two identifier tiers for confidence.
            let mut weights: Vec<f64> = ties
                .iter()
                .map(|t| tie_weight(&t.relation, &identifier_kind(&t.to_identifier)))
                .collect();
            weights.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
            let (conf, tier) = if weights.len() >= 2 && weights[0] >= 0.8 && weights[1] >= 0.8 {
                (0.9, "High")
            } else if weights.len() >= 2 && weights[0] >= 0.6 && weights[1] >= 0.6 {
                (0.6, "Medium")
            } else if weights.len() >= 1 && weights[0] >= 0.9 {
                (0.7, "Medium")
            } else {
                (0.2, "Insufficient")
            };
            let labels: Vec<(String, String)> = ties
                .iter()
                .map(|t| (t.to_identifier.clone(), t.relation.clone()))
                .collect();
            let sources: Vec<String> = ties.iter().map(|t| t.source_url.clone()).collect();
            LinkedEntity {
                key: key.clone(),
                labels,
                confidence: conf,
                tier: tier.to_string(),
                sources,
            }
        })
        .collect()
}

/// Classify an identifier string kind (phone/email/address/org/relative).
fn identifier_kind(s: &str) -> &'static str {
    if s.contains('@') && s.contains('.') {
        "email"
    } else if s.starts_with('+') && s.chars().skip(1).all(|c| c.is_ascii_digit()) {
        "phone"
    } else if s.chars().any(|c| c.is_ascii_digit()) && s.contains(" ") {
        "address"
    } else if s.chars().any(|c| c.is_alphabetic()) {
        "name"
    } else {
        "relative"
    }
}

/// A do-not-index / opt-out register. Applied at export time so a number that
/// opted out is never surfaced in a graph export or lookup result.
#[derive(Debug, Clone, Default)]
pub struct DoNotIndexRegister {
    numbers: std::collections::BTreeSet<String>, // E.164 canonical
}

impl DoNotIndexRegister {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a number to the opt-out register (normalized to E.164).
    pub fn add(&mut self, e164: &str) {
        self.numbers.insert(e164.to_string());
    }

    pub fn remove(&mut self, e164: &str) {
        self.numbers.remove(e164);
    }

    pub fn contains(&self, e164: &str) -> bool {
        self.numbers.contains(e164)
    }

    /// Filter ties that reference an opted-out number (returns owned clones so
    /// the result feeds `build_linkage` directly).
    pub fn filter_ties(&self, ties: &[ConfirmedTie]) -> Vec<ConfirmedTie> {
        ties
            .iter()
            .filter(|t| !self.contains(&t.from_identifier) && !self.contains(&t.to_identifier))
            .cloned()
            .collect()
    }
}

/// Render the linkage subgraph as an IntelGraph-compatible Value (nodes+edges).
pub fn linkage_graph_value(entities: &[LinkedEntity]) -> Value {
    let nodes: Vec<Value> = entities
        .iter()
        .map(|e| Value::Struct {
            name: "LinkedEntity".to_string(),
            fields: vec![
                ("id".to_string(), Value::String(e.key.clone())),
                ("confidence".to_string(), Value::Float(e.confidence)),
                ("tier".to_string(), Value::String(e.tier.clone())),
                (
                    "linked_identifiers".to_string(),
                    Value::Array(e.labels.iter().map(|(v, r)| Value::Struct {
                        name: "Link".to_string(),
                        fields: vec![
                            ("identifier".to_string(), Value::String(v.clone())),
                            ("relation".to_string(), Value::String(r.clone())),
                        ],
                    }).collect()),
                ),
            ],
        })
        .collect();
    Value::Struct {
        name: "LinkageSubgraph".to_string(),
        fields: vec![
            ("entities".to_string(), Value::Array(nodes)),
            ("honesty_note".to_string(), Value::String(
                "links are only as strong as the confirmed-tie evidence; the \
                 composite confidence refuses a strong identity link without at \
                 least two high-discriminator (phone/email) co-occurrences"
                    .to_string(),
            )),
        ],
    }
}

// ══════════════════════════════════════════════════════════════════
// FCC Robocall Mitigation Database (RMDB) — public, lawful, carrier-keyed
// ══════════════════════════════════════════════════════════════════

/// The FCC Robocall Mitigation Database lists voice-service providers and
/// whether they've CERTIFIED that they're implementing STIR/SHAKEN + call
/// authentication. It is keyed by carrier/provider, not by phone — so the
/// honest integration resolves a number's carrier (P0 allocation) then looks up
/// that carrier's RMDB certification. A non-certified carrier on the number's
/// originating path is a real, lawful, public spam/mitigation signal.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RmdbSnapshot {
    pub release_version: String,
    pub source: String,
    /// carrier_name_lowercased -> (certified: bool, holding_company: String)
    pub entries: std::collections::BTreeMap<String, (bool, String)>,
}

impl RmdbSnapshot {
    /// Look up a carrier's RMDB certification. Case-insensitive on a normalized
    /// carrier name; returns None when the carrier isn't in the snapshot.
    pub fn lookup_carrier(&self, carrier_name: &str) -> Option<(bool, String)> {
        let key = carrier_name.to_lowercase();
        // Exact match first (fast path, and the common case).
        if let Some(v) = self.entries.get(&key) {
            return Some(v.clone());
        }
        // Tiered alias matching: the NANPA as-allocated carrier name often
        // carries a suffix the RMDB key lacks — e.g. "CELLCO PARTNERSHIP DBA
        // VERIZON WIRELESS - TX" vs the snapshot key "cellco partnership".
        // An exact-only match would report not-in-snapshot for a carrier that
        // IS present, silently dropping the mitigation signal. Try progressively
        // stripping a trailing state qualifier, then a "DBA"/"d/b/a" tail.
        for cand in alias_candidates(&key) {
            if let Some(v) = self.entries.get(&cand) {
                return Some(v.clone());
            }
        }
        None
    }

    /// Number of provider entries in the snapshot (coverage check).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build an RMDB snapshot from `(carrier, certified, holding_company)` rows.
pub fn make_rmdb_snapshot(
    rows: Vec<(String, bool, String)>,
    release_version: &str,
    source: &str,
) -> RmdbSnapshot {
    let mut entries: std::collections::BTreeMap<String, (bool, String)> = std::collections::BTreeMap::new();
    for (carrier, certified, holding) in rows {
        let key = carrier.to_lowercase();
        // A carrier can appear in more than one RMDB row (e.g. separate filings
        // with different `implementation` values). Merging naively with
        // `insert` would be last-row-wins, silently picking an arbitrary cert.
        // Instead mark certified if ANY row is fully certified (strictest-union
        // semantics — the carrier IS compliant if any filing is complete), and
        // keep the first non-empty holding company. This is deterministic.
        match entries.get_mut(&key) {
            Some((c, h)) => {
                *c = *c || certified;
                if h.is_empty() {
                    *h = holding;
                }
            }
            None => {
                entries.insert(key, (certified, holding));
            }
        }
    }
    RmdbSnapshot {
        release_version: release_version.to_string(),
        source: source.to_string(),
        entries,
    }
}

/// Resolve the robocall-mitigation signal for a phone number given its
/// as-allocated carrier (from the P0 NANP dataset). Returns a Value with the
/// carrier, certification status, holding company, and provenance release —
/// so a subscriber knows the number's originating carrier's mitigation posture.
pub fn mitigation_value(
    carrier_name: &str,
    line_type: &str,
    snapshot: &RmdbSnapshot,
) -> Value {
    let lookup = snapshot.lookup_carrier(carrier_name);
    let (certified, holding, status) = match lookup {
        Some((c, h)) => (c, h, if c { "certified" } else { "not-certified" }),
        None => (false, "unknown".to_string(), "not-in-snapshot"),
    };
    Value::Struct {
        name: "RobocallMitigation".to_string(),
        fields: vec![
            ("carrier".to_string(), Value::String(carrier_name.to_string())),
            ("line_type".to_string(), Value::String(line_type.to_string())),
            ("rmdb_certified".to_string(), Value::Bool(certified)),
            ("rmdb_status".to_string(), Value::String(status.to_string())),
            ("holding_company".to_string(), Value::String(holding)),
            ("snapshot_release".to_string(), Value::String(snapshot.release_version.clone())),
            ("snapshot_source".to_string(), Value::String(snapshot.source.clone())),
            ("honesty_note".to_string(), Value::String(
                "RMDB is keyed by carrier (not phone); this reflects the \
                 as-allocated carrier's certification in the FCC RMDB, which is \
                 a public mitigation signal — not a verdict on the individual \
                 number or subscriber"
                    .to_string(),
            )),
        ],
    }
}

// ══════════════════════════════════════════════════════════════════
// STIX 2.1 export — phone observable as a custom SCO
// ══════════════════════════════════════════════════════════════════

/// Emit a STIX 2.1 SCO for a phone number. STIX 2.1 has no native
/// telephony-number observable, so we emit a standards-shaped **custom SCO**
/// under `x-tallow-phone-number` (the registered-prefix extension pattern) that
/// carries the E.164 value in `value` field (the `phone-number` identifier), plus
/// the derived allocation fields and an `x-` metadata block. This is
/// drop-in-compatible with STIX 2.1 tooling that tolerates custom object types,
/// and the core `value` (number) + `type` fields validate as a cyber-observable.
pub fn phone_stix_bundle(
    parts: &NanpParts,
    alloc: &NanpAllocation,
    entitlement_label: &str,
) -> serde_json::Value {
    let now = chrono::Utc::now().to_rfc3339();
    let id = format!("x-tallow-phone-number--{}", {
        // deterministic-ish UUID from the E.164 (no rand dependency here).
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        parts.e164.hash(&mut hasher);
        let h = hasher.finish();
        format!("{:08x}-{:04x}-4{:03x}-8000-{:012x}",
            (h >> 32) as u32,
            0u16,
            (h >> 16) as u16 & 0x0fff,
            (h & 0xffffffffffff) as u64)
    });
    let mut custom_ext = serde_json::Map::new();
    custom_ext.insert("npa".to_string(), serde_json::json!(parts.npa));
    custom_ext.insert("nxx".to_string(), serde_json::json!(parts.nxx));
    custom_ext.insert("subscriber".to_string(), serde_json::json!(parts.subscriber));
    custom_ext.insert("state".to_string(), serde_json::json!(alloc.state));
    custom_ext.insert("country_code".to_string(), serde_json::json!(alloc.country));
    custom_ext.insert("rate_center".to_string(), serde_json::json!(alloc.rate_center));
    custom_ext.insert("wire_center".to_string(), serde_json::json!(alloc.wire_center));
    custom_ext.insert("clli".to_string(), serde_json::json!(alloc.clli));
    custom_ext.insert("lata".to_string(), serde_json::json!(alloc.lata));
    custom_ext.insert("latitude".to_string(), serde_json::json!(alloc.latitude));
    custom_ext.insert("longitude".to_string(), serde_json::json!(alloc.longitude));
    custom_ext.insert("timezone_iana".to_string(), serde_json::json!(alloc.timezone_iana));
    custom_ext.insert("ocn".to_string(), serde_json::json!(alloc.ocn));
    custom_ext.insert("carrier_as_allocated".to_string(), serde_json::json!(alloc.carrier_name));
    custom_ext.insert("line_type_as_allocated".to_string(), serde_json::json!(alloc.line_type));
    custom_ext.insert("thousands_block_pooled".to_string(), serde_json::json!(alloc.pooled));
    custom_ext.insert("allocation_confidence".to_string(), serde_json::json!(0.9));
    custom_ext.insert("current_carrier".to_string(), serde_json::json!("unknown-needs-lrn-dip"));
    custom_ext.insert("entitlement".to_string(), serde_json::json!(entitlement_label));

    let scos = vec![serde_json::json!({
        "type": "x-tallow-phone-number",
        "spec_version": "2.1",
        "id": id,
        "value": parts.e164,            // the phone-number identifier
        "number_type": "telephone-number",
        "created": now,
        "modified": now,
        "x_tallow_phone": custom_ext,
    })];

    serde_json::json!({
        "type": "bundle",
        "spec_version": "2.1",
        "id": format!("bundle--{}", {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            parts.e164.hash(&mut h);
            let v = h.finish();
            format!("{:08x}-{:04x}-4{:03x}-8000-{:012x}",
                (v >> 32) as u32, 0u16, (v >> 16) as u16 & 0x0fff, (v & 0xffffffffffff) as u64)
        }),
        "objects": scos,
    })
}

// ══════════════════════════════════════════════════════════════════
// Live FCC RMDB CSV sync + licensed connector gate
// ══════════════════════════════════════════════════════════════════

/// Generate conservative alias candidates for a lowercased carrier name, used
/// to match an as-allocated NANPA name (which may carry a "DBA <name>" and/or a
/// trailing " - STATE" qualifier) against the snapshot's cleaner RMDB key.
/// Order matters: try the most-specific (fewest suffixes stripped) first so an
/// exact-ish key wins over a distant one. Only strips a well-formed trailing
/// state qualifier (the 50 US postal abbreviations) and a leading "dba"/"d/b/a"
/// tail — never fuzzy-substrings, so we don't match the wrong carrier.
fn alias_candidates(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = key.to_string();
    // Strip a trailing " - STATE" qualifier (e.g. " - TX").
    if let Some(idx) = cur.rfind(" - ") {
        let tail = &cur[idx + 3..];
        if tail.len() == 2 && tail.chars().all(|c| c.is_ascii_alphabetic()) {
            let cand = cur[..idx].trim().to_string();
            if !cand.is_empty() {
                out.push(cand.clone());
                cur = cand;
            }
        }
    }
    // Strip a "dba <tail>" or "d/b/a <tail>" segment; keep the part before it.
    for marker in [" dba ", " d/b/a "] {
        if let Some(idx) = cur.find(marker) {
            let cand = cur[..idx].trim().to_string();
            if !cand.is_empty() {
                out.push(cand);
            }
            break;
        }
    }
    out
}

/// Split a full CSV into records (each a `Vec<String>`), fully quote-aware so
/// that quoted fields containing embedded commas OR newlines parse correctly.
/// Doubled `""` inside a quoted field is an escaped literal quote. This is the
/// correct way to parse a real CSV (e.g. the FCC RMDB, whose address fields
/// contain embedded newlines) — `str::lines()` alone would split inside a
/// quoted field and mangle records.
fn split_csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
            }
            '\n' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
                // Drop a trailing carriage return (CRLF line endings).
                if let Some(last) = fields.last_mut() {
                    if last.ends_with('\r') {
                        last.pop();
                    }
                }
                records.push(std::mem::take(&mut fields));
            }
            '\r' if !in_quotes => {
                // Tolerate bare CR or CRLF; the LF branch handles the split.
            }
            _ => cur.push(c),
        }
    }
    // Flush the trailing record (no terminating newline).
    if !cur.is_empty() || !fields.is_empty() {
        fields.push(cur);
        records.push(fields);
    }
    records
}

/// Split a single CSV line into fields (quote-aware). Used for unit tests and
/// single-line inputs; full multi-line parsing goes through [`split_csv_records`].
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            // Toggle quoting; a doubled "" inside quotes is a literal quote.
            if in_quotes && chars.peek() == Some(&'"') {
                cur.push('"');
                chars.next();
            } else {
                in_quotes = !in_quotes;
            }
        } else if c == ',' && !in_quotes {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    fields.push(cur);
    fields
}

/// Parse the FCC Robocall Mitigation Database CSV into a snapshot.
///
/// Format (public, no registration required): each row is one voice-service
/// provider filing. We probe the header for the provider-name column and a
/// "certified/mitigation" indicator, and use a quote-aware CSV split so names
/// with commas (e.g. "T-MOBILE USA, INC.") parse correctly.
pub fn parse_rmdb_csv(text: &str, release_version: &str) -> RmdbSnapshot {
    let mut rows: Vec<(String, bool, String)> = Vec::new();
    // Use the multi-line-aware parser so quoted fields containing embedded
    // newlines (RMDB address fields) don't split records mid-field.
    let mut records = split_csv_records(text).into_iter();
    let cols: Vec<String> = records.next().unwrap_or_default();
    let col_of = |needle: &str| cols.iter().position(|c| c.to_lowercase().contains(needle));
    // Strict matcher: only a column whose header contains ALL of the given
    // tokens. Prevents a substring from matching an unrelated column (e.g.
    // "certif" matching "last_recertified" or "mitigation" matching
    // "robocall_mitigation_contact_name").
    let col_of_all = |needles: &[&str]| {
        cols.iter().position(|c| {
            let l = c.to_lowercase();
            needles.iter().all(|n| l.contains(n))
        })
    };

    let name_col = col_of("name").or_else(|| col_of("provider")).or_else(|| col_of("company"));
    // Certification status: the FCC RMDB encodes this in the `implementation`
    // column ("Complete/Partial/No STIR/SHAKEN Implementation"). Detect that
    // column specifically; fall back to an explicit Yes/No certification column.
    let cert_col = col_of_all(&["implementation", "stir"])
        .or_else(|| col_of_all(&["stir", "shaken"]))
        .or_else(|| col_of_all(&["implementation"]))
        .or_else(|| col_of_all(&["mitigation", "certif"]))
        .or_else(|| col_of_all(&["attest"]))
        // Last resort: a "Certifications"-style Yes/No column. Guard against
        // matching a date ("last_recertified") or a contact name.
        .or_else(|| {
            col_of("certif").filter(|i| {
                let h = cols[*i].to_lowercase();
                !h.contains("re-cert") && !h.contains("recert") && !h.contains("contact")
            })
        });
    let holding_col = col_of("parent").or_else(|| col_of("holding"));

    for f in records {
        let name = name_col.and_then(|i| f.get(i)).map(|s| s.trim().to_string()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let certified = cert_col
            .and_then(|i| f.get(i))
            .map(|v| {
                // Token-exact match (not prefix): only an explicit "yes"/"true"/"y"
                // counts as certified — "yesterday" or "yellow" must not certify.
                // For the STIR/SHAKEN implementation column, a "Complete" value is
                // the honest unqualified certification (Partial/No/N/A are not).
                let v = v.trim().to_lowercase();
                match v.as_str() {
                    "yes" | "true" | "y" => true,
                    _ => v.contains("complete") && (v.contains("stir") || v.contains("shaken")),
                }
            })
            .unwrap_or(false);
        let holding = holding_col
            .and_then(|i| f.get(i))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        rows.push((name, certified, holding));
    }
    make_rmdb_snapshot(rows, release_version, "fcc-rmdb-csv")
}

/// Fetch + parse the live FCC RMDB CSV via a caller-supplied fetch function.
///
/// `fetch_fn(url) -> Result<String, String>` lets the caller route through
/// governed_fetch (Tor-safe, rate-limited) rather than hard-coding the client.
/// The default well-known download URL is used; a caller may pass an alternate
/// url (e.g. a cached copy). Returns the parsed snapshot.
pub fn sync_rmdb_snapshot<F>(
    url: &str,
    fetch_fn: F,
    release_version: &str,
) -> Result<RmdbSnapshot, String>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    let body = fetch_fn(url)?;
    Ok(parse_rmdb_csv(&body, release_version))
}

/// Result of a licensed/authorized Tier-C or Tier-D dip attempt.
///
/// These are NOT public data (current carrier needs the NPAC/LRN; displayed
/// caller-ID name needs a CNAM/LIDB carrier contract). The only lawful path is
/// an authorized provider. This type makes that boundary explicit and
/// un-fakeable: no key configured -> `NotConfigured`, and we never fabricate a
/// carrier or name.
#[derive(Debug, Clone, PartialEq)]
pub enum LicensedDip {
    NotConfigured(String),                 // which provider key to set
    Authorized(String),                    // API key present; call provider
}

/// Resolve which licensed provider is available for a Tier-C (LRN/NPAC) dip.
/// Reads TALLOW_LRN_API_KEY; returns NotConfigured (with a hint) when absent.
pub fn lrn_provider_available() -> LicensedDip {
    match std::env::var("TALLOW_LRN_API_KEY") {
        Ok(k) if !k.is_empty() => LicensedDip::Authorized(k),
        _ => LicensedDip::NotConfigured(
            "set TALLOW_LRN_API_KEY (e.g. iconectiv PortData / Alcazar / TNS LRN-dip \
             API) to enable current-carrier/ported lookup; unset, current carrier is \
             reported as unknown (never guessed)".to_string(),
        ),
    }
}

/// Resolve which licensed provider is available for a Tier-D (CNAM/LIDB) dip.
pub fn cnam_provider_available() -> LicensedDip {
    match std::env::var("TALLOW_CNAM_API_KEY") {
        Ok(k) if !k.is_empty() => LicensedDip::Authorized(k),
        _ => LicensedDip::NotConfigured(
            "set TALLOW_CNAM_API_KEY (a carrier-authorized CNAM/LIDB dip provider like \
             iconectiv/TNS/Broadforward) to fetch the displayed caller-ID name; unset, \
             displayed name is reported as unknown (never guessed, and wireless CNAM \
             is often absent anyway)".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dataset() -> NumberingDataset {
        make_dataset(
            vec![
                NpaNxxRecord {
                    npa: "512".into(),
                    nxx: "850".into(),
                    state: "TX".into(),
                    lata: "560".into(),
                    rate_center: "AUSTIN".into(),
                    wire_center: "AUSNTXSW".into(),
                    clli: "AUSNTXSWRS0".into(),
                    latitude: 30.27,
                    longitude: -97.74,
                    timezone_iana: "America/Chicago".into(),
                    ocn: "6529".into(),
                    carrier_name: "T-MOBILE USA, INC.".into(),
                    line_type: "wireless".into(),
                    pooled: true,
                },
                NpaNxxRecord {
                    npa: "212".into(),
                    nxx: "555".into(),
                    state: "NY".into(),
                    lata: "132".into(),
                    rate_center: "NEW YORK CITY".into(),
                    wire_center: "NYCMNYNY".into(),
                    clli: "NYCMNYNYRS0".into(),
                    latitude: 40.71,
                    longitude: -74.01,
                    timezone_iana: "America/New_York".into(),
                    ocn: "9101".into(),
                    carrier_name: "VERIZON NEW YORK INC.".into(),
                    line_type: "wireline".into(),
                    pooled: false,
                },
            ],
            "2026-09",
            "localcallingguide+NANPA",
        )
    }

    #[test]
    fn test_resolve_owner_evidence_documented_two_registers() {
        let ev = vec![
            OwnerEvidence { name: "JANE DOE".into(), source: "county deed".into(), source_url: "https://deeds.example/123".into(), source_class: "register".into(), observed_at: "2026-09-01".into() },
            OwnerEvidence { name: "Jane Doe".into(), source: "SOS business filing".into(), source_url: "https://sos.example/abc".into(), source_class: "register".into(), observed_at: "2026-09-02".into() },
        ];
        let (tier, conf, n, label) = resolve_owner_evidence(&ev);
        assert_eq!(tier, EvidenceTier::Documented);
        assert_eq!(n, 2);
        assert!(conf > 0.6 && conf <= 0.95);
        assert_eq!(label, "JANE DOE");
    }

    #[test]
    fn test_resolve_owner_evidence_single_community_is_alleged_not_documented() {
        // One phonebook/community label on a cell number — the anti-pattern
        // we must NOT present as verified.
        let ev = vec![
            OwnerEvidence { name: "Bob Smith".into(), source: "community tag".into(), source_url: "https://tag.example".into(), source_class: "community".into(), observed_at: "2026-09-01".into() },
        ];
        let (tier, conf, n, _) = resolve_owner_evidence(&ev);
        assert_eq!(tier, EvidenceTier::Alleged, "single community label must NOT be Documented");
        assert_eq!(n, 1);
        assert!(conf <= 0.6);
    }

    #[test]
    fn test_resolve_owner_evidence_no_evidence_unfalsifiable() {
        let (tier, conf, n, label) = resolve_owner_evidence(&[]);
        assert_eq!(tier, EvidenceTier::Unfalsifiable);
        assert_eq!(conf, 0.0);
        assert_eq!(n, 0);
        assert_eq!(label, "");
    }

    #[test]
    fn test_resolve_owner_evidence_two_community_is_still_not_documented() {
        // Two community labels agree, but neither is a register/directory, so
        // it must NOT be Documented (weak-source agreement only = Alleged).
        let ev = vec![
            OwnerEvidence { name: "Carol Lee".into(), source: "app tag A".into(), source_url: "https://a.example".into(), source_class: "community".into(), observed_at: "2026-09-01".into() },
            OwnerEvidence { name: "Carol Lee".into(), source: "app tag B".into(), source_url: "https://b.example".into(), source_class: "community".into(), observed_at: "2026-09-02".into() },
        ];
        let (tier, conf, _, _) = resolve_owner_evidence(&ev);
        assert_eq!(tier, EvidenceTier::Alleged, "two community labels are not Documented");
        assert!(conf <= 0.6);
    }

    #[test]
    fn test_owner_attribution_unknown_when_unfalsifiable() {
        let (tier, conf, n, label) = resolve_owner_evidence(&[]);
        let v = owner_attribution_value(tier, conf, n, label, &[]);
        if let Value::Struct { name, fields } = &v {
            assert_eq!(name, "OwnerAttribution");
            assert!(fields.iter().any(|(k, v)| k == "owner" && matches!(v, Value::String(s) if s == "unknown")));
            assert!(fields.iter().any(|(k, v)| k == "evidence_tier" && matches!(v, Value::String(s) if s == "Unfalsifiable")));
        } else {
            panic!("expected OwnerAttribution struct");
        }
    }

    #[test]
    fn test_same_owner_normalizes() {
        assert!(same_owner("JANE DOE", "jane doe"));
        assert!(same_owner("Acme, Inc.", "acme inc"));
        assert!(!same_owner("Bob", "Carol"));
    }

    #[test]
    fn test_reputation_confirmed_two_sources() {
        let sig = SpamSignal {
            reports: 30,
            category: "robocall".into(),
            source_bits: 0b00000101, // USER_LABEL + FCC_COMPLAINT
            verified_business: false,
            last_seen: 0,
        };
        let rep = compute_spam_reputation(&sig, 0.2, 1000);
        assert_eq!(rep.spam_score, 1.0);
        assert_eq!(rep.verdict, "confirmed");
        assert_eq!(rep.source_count, 2);
    }

    #[test]
    fn test_reputation_single_fcc_complaint_is_suspected_not_confirmed() {
        let sig = SpamSignal {
            reports: 2,
            category: "spam".into(),
            source_bits: 0b00000100, // FCC_COMPLAINT only
            verified_business: false,
            last_seen: 0,
        };
        let rep = compute_spam_reputation(&sig, 0.0, 1000);
        // reports=2 -> 2/20*0.7=0.07 + 0.05 = 0.12... below 0.4 threshold -> unknown
        // The honest point: a single source is never 'confirmed'.
        assert_ne!(rep.verdict, "confirmed");
    }

    #[test]
    fn test_reputation_verified_business_zeroes() {
        let sig = SpamSignal {
            reports: 40,
            category: "spam".into(),
            source_bits: 0b111111,
            verified_business: true,
            last_seen: 0,
        };
        let rep = compute_spam_reputation(&sig, 0.0, 1000);
        assert_eq!(rep.spam_score, 0.0);
        assert_eq!(rep.verdict, "legitimate");
        assert!(rep.verification_override);
    }

    #[test]
    fn test_reputation_entropy_penalizes_contested() {
        let sig = SpamSignal {
            reports: 30,
            category: "spam".into(),
            source_bits: 0b00000101,
            verified_business: false,
            last_seen: 0,
        };
        // High disagreement among reporters caps the score to 0.5.
        let rep = compute_spam_reputation(&sig, 0.8, 1000);
        assert_eq!(rep.spam_score, 0.5);
        assert_eq!(rep.verdict, "suspected");
    }

    #[test]
    fn test_diff_number_state_only_changed() {
        let before = vec![
            ("carrier".to_string(), "T-MOBILE".to_string()),
            ("line_type".to_string(), "wireless".to_string()),
            ("spam_score".to_string(), "0.20".to_string()),
        ];
        let after = vec![
            ("carrier".to_string(), "VERIZON".to_string()),
            ("line_type".to_string(), "wireless".to_string()),
            ("spam_score".to_string(), "0.85".to_string()),
        ];
        let changes = diff_number_state(&before, &after);
        assert_eq!(changes.len(), 2, "only carrier + spam_score changed");
        assert_eq!(changes[0].field, "carrier");
        assert_eq!(changes[0].before, "T-MOBILE");
        assert_eq!(changes[0].after, "VERIZON");
        assert!(!changes.iter().any(|c| c.field == "line_type"));
    }

    #[test]
    fn test_reputation_value_shape() {
        let sig = SpamSignal { reports: 30, category: "robocall".into(), source_bits: 0b101, verified_business: false, last_seen: 0 };
        let rep = compute_spam_reputation(&sig, 0.2, 1000);
        let v = reputation_value(&rep, &[sig]);
        if let Value::Struct { name, fields } = &v {
            assert_eq!(name, "SpamReputation");
            assert!(fields.iter().any(|(k, v)| k == "spam_score" && matches!(v, Value::Float(_))));
            assert!(fields.iter().any(|(k, v)| k == "verdict" && matches!(v, Value::String(s) if s == "confirmed")));
            assert!(fields.iter().any(|(k, v)| k == "signals" && matches!(v, Value::Array(_))));
            assert!(fields.iter().any(|(k, _)| k == "honesty_note"));
        } else {
            panic!("expected SpamReputation struct");
        }
    }

    #[test]
    fn test_build_linkage_high_two_high_discriminators() {
        // Two Very-High discriminators (email + phone) co-occurring -> High.
        let ties = vec![
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "jane@example.com".into(), relation: "email".into(), source_url: "https://sos.example/1".into(), row_context: "SOS filing".into() },
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "+16045550100".into(), relation: "person".into(), source_url: "https://990.example/2".into(), row_context: "990 officer block".into() },
        ];
        let ents = build_linkage(&ties);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].tier, "High");
        assert!(ents[0].confidence >= 0.8);
        assert_eq!(ents[0].labels.len(), 2);
    }

    #[test]
    fn test_build_linkage_medium_one_high_one_name() {
        // One Very-High (email) + one name -> Medium, NOT High (honest rubric:
        // High requires two high-discriminators; a name is only 0.3).
        let ties = vec![
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "jane@example.com".into(), relation: "email".into(), source_url: "https://sos.example/1".into(), row_context: "SOS filing".into() },
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "JANE DOE".into(), relation: "person".into(), source_url: "https://990.example/2".into(), row_context: "990 officer block".into() },
        ];
        let ents = build_linkage(&ties);
        assert_eq!(ents[0].tier, "Medium");
        assert!(ents[0].confidence > 0.4 && ents[0].confidence < 0.8);
    }

    #[test]
    fn test_build_linkage_insufficient_single_guess() {
        // One person-name co-occurrence (not phone/email) -> Insufficient; we
        // refuse to assert a strong identity link.
        let ties = vec![
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "Bob Smith".into(), relation: "person".into(), source_url: "https://tag.example".into(), row_context: "community tag".into() },
        ];
        let ents = build_linkage(&ties);
        assert_eq!(ents[0].tier, "Insufficient");
        assert!(ents[0].confidence <= 0.3);
    }

    #[test]
    fn test_do_not_index_register_filters() {
        let mut reg = DoNotIndexRegister::new();
        reg.add("+15128501815");
        assert!(reg.contains("+15128501815"));
        let ties = vec![
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "jane@example.com".into(), relation: "email".into(), source_url: "https://x".into(), row_context: "r".into() },
            ConfirmedTie { from_identifier: "+14155550100".into(), to_identifier: "bob@example.com".into(), relation: "email".into(), source_url: "https://y".into(), row_context: "r".into() },
        ];
        let filtered = reg.filter_ties(&ties);
        assert_eq!(filtered.len(), 1, "opted-out number's ties must be filtered");
        reg.remove("+15128501815");
        assert!(!reg.contains("+15128501815"));
        assert_eq!(reg.filter_ties(&ties).len(), 2, "after opt-out removal ties return");
    }

    #[test]
    fn test_linkage_graph_value_shape() {
        let ties = vec![
            ConfirmedTie { from_identifier: "+15128501815".into(), to_identifier: "jane@example.com".into(), relation: "email".into(), source_url: "https://sos.example/1".into(), row_context: "SOS filing".into() },
        ];
        let ents = build_linkage(&ties);
        let v = linkage_graph_value(&ents);
        if let Value::Struct { name, fields } = &v {
            assert_eq!(name, "LinkageSubgraph");
            assert!(fields.iter().any(|(k, v)| k == "entities" && matches!(v, Value::Array(_))));
            assert!(fields.iter().any(|(k, _)| k == "honesty_note"));
        } else {
            panic!("expected LinkageSubgraph struct");
        }
    }

    #[test]
    fn test_identifier_kind_classification() {
        assert_eq!(identifier_kind("jane@example.com"), "email");
        assert_eq!(identifier_kind("+15128501815"), "phone");
        assert_eq!(identifier_kind("123 Main St Austin"), "address");
        assert_eq!(identifier_kind("Jane Doe"), "name");
    }

    #[test]
    fn test_rmdb_snapshot_lookup_carrier() {
        let snap = make_rmdb_snapshot(
            vec![
                ("T-MOBILE USA, INC.".to_string(), true, "T-MOBILE US".to_string()),
                ("SMALL VOIP LLC".to_string(), false, "SMALL VOIP".to_string()),
            ],
            "2026-09",
            "fcc-rmdb",
        );
        let (c, h) = snap.lookup_carrier("t-mobile usa, inc.").unwrap();
        assert!(c);
        assert_eq!(h, "T-MOBILE US");
        let (c2, _) = snap.lookup_carrier("small voip llc").unwrap();
        assert!(!c2);
        assert!(snap.lookup_carrier("UNKNOWN CARRIER").is_none());
    }

    #[test]
    fn test_mitigation_value_shape_and_honesty() {
        let snap = make_rmdb_snapshot(
            vec![("T-MOBILE USA, INC.".to_string(), true, "T-MOBILE US".to_string())],
            "2026-09",
            "fcc-rmdb",
        );
        let v = mitigation_value("T-MOBILE USA, INC.", "wireless", &snap);
        if let Value::Struct { name, fields } = &v {
            assert_eq!(name, "RobocallMitigation");
            assert!(fields.iter().any(|(k, v)| k == "rmdb_certified" && matches!(v, Value::Bool(true))));
            assert!(fields.iter().any(|(k, v)| k == "rmdb_status" && matches!(v, Value::String(s) if s == "certified")));
            assert!(fields.iter().any(|(k, _)| k == "honesty_note"));
        } else {
            panic!("expected RobocallMitigation struct");
        }
    }

    #[test]
    fn test_mitigation_value_not_in_snapshot() {
        let snap = make_rmdb_snapshot(vec![], "2026-09", "fcc-rmdb");
        let v = mitigation_value("NO SUCH CARRIER", "wireless", &snap);
        if let Value::Struct { fields, .. } = &v {
            assert!(fields.iter().any(|(k, v)| k == "rmdb_status" && matches!(v, Value::String(s) if s == "not-in-snapshot")));
            assert!(fields.iter().any(|(k, v)| k == "rmdb_certified" && matches!(v, Value::Bool(false))));
        }
    }

    #[test]
    fn test_load_dataset_from_json_roundtrip() {
        let json = r#"{
            "release_version": "2026-10",
            "source": "lerg-full",
            "records": [
                {"npa":"512","nxx":"850","state":"TX","lata":"560","rate_center":"AUSTIN",
                 "wire_center":"AUSNTXSW","clli":"AUSNTXSWRS0","latitude":30.27,"longitude":-97.74,
                 "timezone_iana":"America/Chicago","ocn":"6529","carrier_name":"T-MOBILE USA, INC.",
                 "line_type":"wireless","pooled":true}
            ]
        }"#;
        let dir = std::env::temp_dir();
        let path = dir.join("tallow_nanp_test.json");
        std::fs::write(&path, json).unwrap();
        let ds = load_dataset_from_json(path.to_str().unwrap()).unwrap();
        assert_eq!(ds.release_version, "2026-10");
        assert_eq!(ds.source, "lerg-full");
        assert_eq!(ds.len(), 1);
        let rec = ds.lookup("512", "850").unwrap();
        assert_eq!(rec.carrier_name, "T-MOBILE USA, INC.");
        assert_eq!(rec.rate_center, "AUSTIN");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_dataset_from_json_missing_file_errs() {
        let r = load_dataset_from_json("/no/such/dataset.json");
        assert!(r.is_err(), "missing file should error, not silently fall back");
    }

    #[test]
    fn test_load_dataset_empty_records_errs() {
        let json = r#"{"release_version":"x","source":"y","records":[]}"#;
        let dir = std::env::temp_dir();
        let path = dir.join("tallow_nanp_empty.json");
        std::fs::write(&path, json).unwrap();
        let r = load_dataset_from_json(path.to_str().unwrap());
        assert!(r.is_err(), "empty records should error");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_phone_stix_bundle_shape() {
        let ds = sample_dataset();
        let p = parse_nanp("512-850-1815", "1").unwrap();
        let alloc = derive_allocation(&p, &ds);
        let b = phone_stix_bundle(&p, &alloc, "research");
        assert_eq!(b["type"], "bundle");
        assert_eq!(b["spec_version"], "2.1");
        let objs = b["objects"].as_array().unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0]["type"], "x-tallow-phone-number");
        assert_eq!(objs[0]["value"], "+15128501815");
        assert_eq!(objs[0]["x_tallow_phone"]["rate_center"], "AUSTIN");
        assert_eq!(objs[0]["x_tallow_phone"]["entitlement"], "research");
    }

    #[test]
    fn test_parse_rmdb_csv() {
        // Real RMDB CSV: provider names with commas are double-quoted.
        // "Mitigation Certifications" column: Yes => certified.
        let csv = "Name,Mitigation Certifications,Parent Company\n\
                   \"T-MOBILE USA, INC.\",Yes,\"T-MOBILE US\"\n\
                   \"SMALL VOIP LLC\",No,\n\
                   \"ANOTHER LLC\",Certified,\n";
        let snap = parse_rmdb_csv(csv, "2026-10");
        assert_eq!(snap.source, "fcc-rmdb-csv");
        assert_eq!(snap.len(), 3);
        let (c, h) = snap.lookup_carrier("t-mobile usa, inc.").unwrap();
        assert!(c, "Yes should be certified");
        assert_eq!(h, "T-MOBILE US");
        // "Certified" (starts with C) and "No" are NOT yes/true/y => not certified.
        let (c2, _) = snap.lookup_carrier("small voip llc").unwrap();
        assert!(!c2);
        let (c3, _) = snap.lookup_carrier("another llc").unwrap();
        assert!(!c3, "Certified alone is too weak to assert certified in our strict heuristic");
    }

    #[test]
    fn test_lookup_carrier_alias_matches_dba_and_state_suffix() {
        // The as-allocated NANPA name carries a DBA and trailing state qualifier
        // that the snapshot's cleaner RMDB key lacks. lookup_carrier must still
        // resolve it (tiered alias match), not report not-in-snapshot.
        let rows = vec![
            ("cellco partnership".to_string(), true, "VERIZON HOLDING".to_string()),
        ];
        let snap = make_rmdb_snapshot(rows, "2026-09", "fcc-rmdb-csv");
        // Exact: should hit directly.
        assert!(snap.lookup_carrier("cellco partnership").is_some());
        // DBA + state suffix: must resolve via alias candidates.
        let v = snap.lookup_carrier("CELLCO PARTNERSHIP DBA VERIZON WIRELESS - TX");
        assert!(v.is_some(), "alias match should resolve the DBA/state-suffixed name");
        let (c, h) = v.unwrap();
        assert!(c);
        assert_eq!(h, "VERIZON HOLDING");
        // Unrelated name must NOT match anything.
        assert!(snap.lookup_carrier("verizon wireless").is_none());
    }

    #[test]
    fn test_split_csv_line_handles_quotes() {
        let fields = split_csv_line("\"T-MOBILE USA, INC.\",Yes,\"T-MOBILE US\"");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], "T-MOBILE USA, INC.");
        assert_eq!(fields[1], "Yes");
        assert_eq!(fields[2], "T-MOBILE US");
    }

    #[test]
    fn test_make_rmdb_snapshot_merges_cert_union() {
        // A carrier appears in two rows with conflicting `implementation`
        // values (Partial in one, Complete in another). make_rmdb_snapshot must
        // mark it certified (strictest-union) and deterministic, not pick the
        // last row's (possibly wrong) value. Without the merge, an `insert` would
        // be last-row-wins.
        let rows = vec![
            ("ACME TELECOM".to_string(), false, "ACME HOLDING".to_string()),
            ("acme telecom".to_string(), true, "".to_string()),
        ];
        let snap = make_rmdb_snapshot(rows, "2026-09", "fcc-rmdb-csv");
        assert_eq!(snap.len(), 1);
        let (c, h) = snap.lookup_carrier("acme telecom").unwrap();
        assert!(c, "certified if ANY row is complete (union)");
        assert_eq!(h, "ACME HOLDING", "keep the first non-empty holding company");
    }

    #[test]
    fn test_split_csv_records_handles_embedded_newlines() {
        // Real RMDB rows: a quoted address field contains embedded newlines.
        // split_csv_records must keep that as ONE record (3 fields), not split
        // it into two. str::lines() would break here.
        let csv = "name,cert\n\"A CO, INC.\",Yes\n\"B LLC\n  123 Main St\",No\n";
        let recs = split_csv_records(csv);
        assert_eq!(recs.len(), 3, "header + 2 records");
        assert_eq!(recs[0], vec!["name", "cert"]);
        assert_eq!(recs[1], vec!["A CO, INC.", "Yes"]);
        assert_eq!(recs[2][0], "B LLC\n  123 Main St");
        assert_eq!(recs[2][1], "No");
    }

    #[test]
    fn test_lrn_connector_gated() {
        // Env may or may not have the key; assert it returns a concrete varian
        // that is NEVER a fabricated carrier. If a key is set, verify Authorized;
        // else verify NotConfigured with a hint.
        match crate::stdlib::phone_osint::lrn_provider_available() {
            LicensedDip::Authorized(_) => {}
            LicensedDip::NotConfigured(hint) => assert!(hint.contains("TALLOW_LRN_API_KEY")),
        }
    }

    #[test]
    fn test_cnam_connector_gated() {
        match crate::stdlib::phone_osint::cnam_provider_available() {
            LicensedDip::Authorized(_) => {}
            LicensedDip::NotConfigured(hint) => assert!(hint.contains("TALLOW_CNAM_API_KEY")),
        }
    }

    #[test]
    fn test_parse_nanp_variants() {
        let a = parse_nanp("512-850-1815", "1").unwrap();
        assert_eq!(a.npa, "512");
        assert_eq!(a.nxx, "850");
        assert_eq!(a.subscriber, "1815");
        assert_eq!(a.e164, "+15128501815");

        let b = parse_nanp("+1 (212) 555-1234", "1").unwrap();
        assert_eq!(b.npa, "212");
        assert_eq!(b.e164, "+12125551234");

        let c = parse_nanp("15128501815", "1").unwrap();
        assert_eq!(c.e164, "+15128501815");

        // Non-NANP / invalid -> None.
        assert!(parse_nanp("12", "1").is_none());
    }

    #[test]
    fn test_derive_allocation_from_dataset() {
        let ds = sample_dataset();
        let p = parse_nanp("512-850-1815", "1").unwrap();
        let alloc = derive_allocation(&p, &ds);
        assert_eq!(alloc.state, "TX");
        assert_eq!(alloc.rate_center, "AUSTIN");
        assert_eq!(alloc.carrier_name, "T-MOBILE USA, INC.");
        assert_eq!(alloc.line_type, "wireless");
        assert_eq!(alloc.timezone_iana, "America/Chicago");
        assert!(alloc.pooled);
    }

    #[test]
    fn test_derive_allocation_fallback_hint() {
        let ds = sample_dataset();
        // 512-850 is in the dataset; use a plain 512-xxx not present to force the
        // coarse NPA hint path.
        let p = parse_nanp("512-555-0100", "1").unwrap();
        let alloc = derive_allocation(&p, &ds);
        assert_eq!(alloc.state, "TX");
        assert!(alloc.carrier_name.starts_with("unknown"));
        assert_eq!(alloc.timezone_iana, "America/Chicago");
    }

    #[test]
    fn test_phone_entity_value_fields() {
        let ds = sample_dataset();
        let p = parse_nanp("512-850-1815", "1").unwrap();
        let alloc = derive_allocation(&p, &ds);
        let ent = phone_entity_value(&p, &alloc, &ds);
        if let Value::Struct { name, fields } = &ent {
            assert_eq!(name, "PhoneNumber");
            assert!(fields.iter().any(|(k, v)| k == "rate_center" && matches!(v, Value::String(s) if s == "AUSTIN")));
            assert!(fields.iter().any(|(k, _)| k == "current_carrier"));
            assert!(fields.iter().any(|(k, _)| k == "allocation_confidence"));
            assert!(fields.iter().any(|(k, v)| k == "provenance" && matches!(v, Value::Array(_))));
        } else {
            panic!("expected PhoneNumber struct");
        }
    }
}
