//! Standard library: `tallow.provenance` — collection-level provenance and
//! source grading for fetched/crawled content.
//!
//! Every fact harvested from the network carries a [`CollectionRecord`]:
//! where it came from (`source_url`), how fresh it is (`fetched_at`),
//! which egress path fetched it (`egress_label` / `egress_tier`), the HTTP
//! outcome (`status_code`), a content fingerprint (`body_hash`), a chain of
//! [`ValidationStep`] checks, a folded numeric `confidence`, and a final
//! letter `grade` (A/B/C/D/F).
//!
//! # Model reuse (no fork)
//!
//! The freshness and validation vocabulary is *aliased* from the existing
//! Tallow provenance model in `src/browser/provenance.rs` — the
//! [`FreshnessTier`] enum and [`ValidationStep`] struct are re-exported
//! here (`pub use`), not duplicated. Confidence is folded with the same
//! arithmetic as `ProvenanceRecord::compute_final_confidence` there:
//! base × validators, passed steps add `|adjustment|`, failed steps
//! subtract `|adjustment|`, result clamped to [0, 1]. Freshness bands use
//! the same cutoffs as that model: < 15 min Fresh, < 6 h Recent,
//! < 24 h Stale, else Old. (The shared file cannot host a common helper
//! this wave — new-files-only constraint — so the 5-line fold loop and the
//! cutoff constants are mirrored here with pointers to the canonical site.)
//!
//! # API (as surfaced in `stdlib/provenance.tl`)
//!
//! - `Provenance.record(url, egress_label, egress_tier, status_code, body_hash)` → CollectionRecord
//! - `Provenance.record_at(..., fetched_at)` → CollectionRecord (explicit epoch)
//! - `Provenance.add_validator(rec, validator, passed, adjustment, note?)` → CollectionRecord
//! - `Provenance.grade(rec)` → CollectionRecord with recomputed confidence + letter grade
//! - `Provenance.freshness(rec)` → "Fresh" | "Recent" | "Stale" | "Old"
//! - `Provenance.hash_body(body)` → sha256 hex digest of the body's UTF-8 bytes
//! - `Provenance.hash_bytes(data)` → sha256 hex digest of raw `Bytes` (binary-safe; the one to
//!   use on `fs.read_bytes` — `hash_body` refuses a `Bytes` argument rather than fingerprint its
//!   encoded form)
//! - `Provenance.to_json(rec)` / `Provenance.from_json(json)` → durable roundtrip
//!
//! Lowercase `provenance.record` etc. resolve identically (namespace-case
//! normalization in the interpreter, roadmap #1).
//!
//! # Grade rubric (letters A–F)
//!
//! Grade = clamp(status_base + egress_penalty + confidence_penalty +
//! freshness_penalty, 0..=5) mapped over `['F','F','D','C','B','A']`:
//!
//! | axis | value | delta |
//! |---|---|---|
//! | status | 200 = 5 · 2xx-other = 4 · 3xx = 3 · 4xx = 2 · 5xx/0 = 0 | — |
//! | egress tier | residential/mobile/fiber/campus/isp = 0 · datacenter/hosting/cloud/vps/proxy/shared/vpn = −1 · tor = −2 · unknown = −1 | — |
//! | confidence | ≥ 0.7 = 0 · ≥ 0.5 = −1 · < 0.5 = −2 | (trust bar mirrors `is_trustworthy`) |
//! | freshness | Fresh/Recent = 0 · Stale = −1 · Old = −2 | (cutoffs from browser model) |
//!
//! So a 200 from a residential egress, fetched moments ago with ≥ 0.7
//! confidence grades **A**; a 503 over Tor grades **F**; a 404 grades **D**;
//! old/datacenter fetches sit in between.

use super::StdlibResult;
use crate::interp::{Value, type_name};
use sha2::{Digest, Sha256};

// ── Aliased model types (single source of truth: src/browser/provenance.rs) ──
pub use crate::browser::provenance::{FreshnessTier, ValidationStep};

/// Default base confidence assigned when `record(...)` is called without an
/// explicit base-confidence argument. Matches the browser model's default
/// trust floor for unvalidated extractions.
pub const DEFAULT_BASE_CONFIDENCE: f64 = 0.8;

/// Freshness cutoffs mirroring `ProvenanceRecord::compute_final_confidence`
/// in src/browser/provenance.rs (Fresh < 15 min, Recent < 6 h, Stale < 24 h).
pub const FRESHNESS_CUTOFF_FRESH_SECS: i64 = 15 * 60;
pub const FRESHNESS_CUTOFF_RECENT_SECS: i64 = 6 * 3600;
pub const FRESHNESS_CUTOFF_STALE_SECS: i64 = 24 * 3600;

/// A provenance sticker for one fetched/crawled collection event.
#[derive(Debug, Clone)]
pub struct CollectionRecord {
    /// Canonical URL the content was fetched from.
    pub source_url: String,
    /// Unix epoch seconds when the fetch happened (how-fresh clock).
    pub fetched_at: i64,
    /// Human label of the egress path used (e.g. "pool-us-res-01").
    pub egress_label: String,
    /// Class of egress: residential | mobile | datacenter | proxy | tor | …
    pub egress_tier: String,
    /// HTTP status code of the fetch; 0 = no response / network failure.
    pub status_code: i64,
    /// Content fingerprint (sha256 hex of the body) for tamper/dedup checks.
    pub body_hash: String,
    /// Validation chain applied after the fetch (aliased model type).
    pub validators: Vec<ValidationStep>,
    /// Numeric confidence: base before `grade()`, folded after `grade()`.
    pub confidence: f64,
    /// Letter grade (A/B/C/D/F) written by `grade()`; empty before grading.
    pub grade: String,
}

impl CollectionRecord {
    /// Constructor — every field is explicit except the validator chain,
    /// which starts empty. `base_confidence` is clamped to [0, 1].
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        source_url: &str,
        fetched_at: i64,
        egress_label: &str,
        egress_tier: &str,
        status_code: i64,
        body_hash: &str,
        base_confidence: f64,
    ) -> Self {
        Self {
            source_url: source_url.to_string(),
            fetched_at,
            egress_label: egress_label.to_string(),
            egress_tier: egress_tier.to_string(),
            status_code,
            body_hash: body_hash.to_string(),
            validators: Vec::new(),
            confidence: base_confidence.clamp(0.0, 1.0),
            grade: String::new(),
        }
    }

    /// Append one validation step (same semantics as the browser model's
    /// `add_validation`). Call before `grade()` so the step folds in.
    pub fn add_validator(&mut self, step: ValidationStep) {
        self.validators.push(step);
    }

    /// Age of the record in seconds, floored at 0 (mirrors browser model).
    pub fn age_seconds(&self) -> i64 {
        (now_unix() - self.fetched_at).max(0)
    }

    /// Freshness band using the browser model's cutoffs.
    pub fn freshness_tier(&self) -> FreshnessTier {
        let age = self.age_seconds();
        if age < FRESHNESS_CUTOFF_FRESH_SECS {
            FreshnessTier::Fresh
        } else if age < FRESHNESS_CUTOFF_RECENT_SECS {
            FreshnessTier::Recent
        } else if age < FRESHNESS_CUTOFF_STALE_SECS {
            FreshnessTier::Stale
        } else {
            FreshnessTier::Old
        }
    }

    /// Fold validator adjustments over the stored base confidence using the
    /// browser model arithmetic (passed += |adj|, failed −= |adj|, clamp
    /// [0, 1]). Pure — does not mutate.
    pub fn fold_confidence(&self) -> f64 {
        let mut conf = self.confidence;
        for v in &self.validators {
            if v.passed {
                conf += v.adjustment.abs();
            } else {
                conf -= v.adjustment.abs();
            }
        }
        conf.clamp(0.0, 1.0)
    }

    /// Recompute confidence from the validator chain, derive the letter
    /// grade from status/egress/confidence/freshness, store both, and
    /// return the letter. Call once, after all `add_validator` steps.
    pub fn grade(&mut self) -> String {
        let conf = self.fold_confidence();
        self.confidence = conf;
        let idx = status_base(self.status_code)
            + egress_tier_penalty(&self.egress_tier)
            + confidence_penalty(conf)
            + freshness_penalty(self.freshness_tier());
        let letter = letter_for(idx);
        self.grade = letter.to_string();
        letter.to_string()
    }

    /// Trust bar mirroring the browser model's `> 0.7` threshold, extended
    /// for fetched content: the fetch must also have succeeded (2xx). A 503
    /// with high validator confidence is still not a trustworthy fact.
    pub fn is_trustworthy(&self) -> bool {
        (200..300).contains(&self.status_code) && self.fold_confidence() > 0.7
    }

    /// Durable JSON form (all fields incl. validators). Reversible via
    /// [`CollectionRecord::from_json`].
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.to_json_value()).unwrap_or_else(|_| "{}".to_string())
    }

    fn to_json_value(&self) -> serde_json::Value {
        let validators: Vec<serde_json::Value> = self
            .validators
            .iter()
            .map(|v| {
                serde_json::json!({
                    "validator": v.validator,
                    "passed": v.passed,
                    "adjustment": v.adjustment,
                    "note": v.note,
                })
            })
            .collect();
        serde_json::json!({
            "source_url": self.source_url,
            "fetched_at": self.fetched_at,
            "egress_label": self.egress_label,
            "egress_tier": self.egress_tier,
            "status_code": self.status_code,
            "body_hash": self.body_hash,
            "validators": validators,
            "confidence": self.confidence,
            "grade": self.grade,
        })
    }

    /// Parse the JSON form written by [`CollectionRecord::to_json`].
    pub fn from_json(json: &str) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("provenance.from_json: {e}"))?;
        Self::from_json_value(&v)
    }

    fn from_json_value(v: &serde_json::Value) -> Result<Self, String> {
        let obj = v
            .as_object()
            .ok_or_else(|| "provenance.from_json: expected JSON object".to_string())?;
        let get_str = |k: &str| -> Result<String, String> {
            obj.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| format!("provenance.from_json: missing/invalid string field `{k}`"))
        };
        let get_i64 = |k: &str| -> Result<i64, String> {
            obj.get(k)
                .and_then(|x| x.as_i64())
                .ok_or_else(|| format!("provenance.from_json: missing/invalid int field `{k}`"))
        };
        let get_f64 = |k: &str| -> Result<f64, String> {
            obj.get(k)
                .and_then(|x| x.as_f64())
                .ok_or_else(|| format!("provenance.from_json: missing/invalid float field `{k}`"))
        };

        let mut validators = Vec::new();
        if let Some(arr) = obj.get("validators").and_then(|x| x.as_array()) {
            for step in arr {
                let so = step.as_object().ok_or_else(|| {
                    "provenance.from_json: validator entry is not an object".to_string()
                })?;
                let note = match so.get("note") {
                    Some(serde_json::Value::String(s)) => Some(s.clone()),
                    _ => None,
                };
                validators.push(ValidationStep {
                    validator: so
                        .get("validator")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    passed: so.get("passed").and_then(|x| x.as_bool()).unwrap_or(false),
                    adjustment: so.get("adjustment").and_then(|x| x.as_f64()).unwrap_or(0.0),
                    note,
                });
            }
        }

        Ok(Self {
            source_url: get_str("source_url")?,
            fetched_at: get_i64("fetched_at")?,
            egress_label: get_str("egress_label")?,
            egress_tier: get_str("egress_tier")?,
            status_code: get_i64("status_code")?,
            body_hash: get_str("body_hash")?,
            validators,
            confidence: get_f64("confidence")?,
            grade: get_str("grade")?,
        })
    }
}

// ── Grade rubric internals ─────────────────────────────────────────────

/// Letter index from HTTP status. 200 = best (5); 5xx or no response = 0.
fn status_base(status: i64) -> i32 {
    match status {
        200 => 5,
        201..=299 => 4,
        300..=399 => 3,
        400..=499 => 2,
        _ => 0,
    }
}

/// Egress-class penalty. Residential-grade IPs are least likely to be
/// bot-walled or poisoned; Tor/datacenter exits more so.
fn egress_tier_penalty(tier: &str) -> i32 {
    match tier.to_ascii_lowercase().as_str() {
        "residential" | "mobile" | "fiber" | "campus" | "isp" => 0,
        "datacenter" | "hosting" | "cloud" | "vps" | "proxy" | "shared" | "vpn" => -1,
        "tor" => -2,
        _ => -1,
    }
}

/// Confidence penalty bands (trust bar mirrors browser `> 0.7`).
fn confidence_penalty(conf: f64) -> i32 {
    if conf >= 0.7 {
        0
    } else if conf >= 0.5 {
        -1
    } else {
        -2
    }
}

/// Freshness penalty over the aliased tier (cutoffs in browser model).
fn freshness_penalty(tier: FreshnessTier) -> i32 {
    match tier {
        FreshnessTier::Fresh | FreshnessTier::Recent => 0,
        FreshnessTier::Stale => -1,
        FreshnessTier::Old => -2,
    }
}

fn letter_for(idx: i32) -> char {
    // idx 0..=5 → F F D C B A (5xx → F, 4xx → D, 3xx → C, 2xx-other → B, 200 → A)
    const LETTERS: [char; 6] = ['F', 'F', 'D', 'C', 'B', 'A'];
    LETTERS[idx.clamp(0, 5) as usize]
}

// ── Content fingerprinting ─────────────────────────────────────────────

/// sha256 hex digest of raw bytes — the binary-safe sibling of [`hash_body`].
///
/// This is the function to use for a file's contents (`fs.read_bytes`) or any
/// other `Bytes` value: it never goes through text encoding, so the digest is
/// the artifact's true sha256.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// sha256 hex digest of a fetched body — the `body_hash` stored on records.
///
/// Fingerprints the argument's **UTF-8 bytes** (that is what a fetched body is:
/// text). It is not a file hasher — feeding it the `Bytes` value from
/// `fs.read_bytes` would fingerprint that value's encoded form. That
/// composition is refused at runtime (see `hash_body_dispatch`); use
/// [`hash_bytes`] instead.
pub fn hash_body(body: &str) -> String {
    hash_bytes(body.as_bytes())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Value <-> CollectionRecord bridges ─────────────────────────────────

/// Struct type name exposed to .tl scripts (routed in dispatch_method).
pub const RECORD_STRUCT_NAME: &str = "CollectionRecord";
/// Validator sub-struct type name inside the record's `validators` array.
pub const STEP_STRUCT_NAME: &str = "ValidationStep";

fn record_to_value(r: &CollectionRecord) -> Value {
    let validators: Vec<Value> = r
        .validators
        .iter()
        .map(|v| Value::Struct {
            name: STEP_STRUCT_NAME.to_string(),
            fields: vec![
                ("validator".into(), Value::String(v.validator.clone())),
                ("passed".into(), Value::Bool(v.passed)),
                ("adjustment".into(), Value::Float(v.adjustment)),
                (
                    "note".into(),
                    match &v.note {
                        Some(n) => Value::String(n.clone()),
                        None => Value::Nil,
                    },
                ),
            ],
        })
        .collect();
    Value::Struct {
        name: RECORD_STRUCT_NAME.to_string(),
        fields: vec![
            ("source_url".into(), Value::String(r.source_url.clone())),
            ("fetched_at".into(), Value::Int(r.fetched_at as i128)),
            ("egress_label".into(), Value::String(r.egress_label.clone())),
            ("egress_tier".into(), Value::String(r.egress_tier.clone())),
            ("status_code".into(), Value::Int(r.status_code as i128)),
            ("body_hash".into(), Value::String(r.body_hash.clone())),
            ("validators".into(), Value::Array(validators)),
            ("confidence".into(), Value::Float(r.confidence)),
            ("grade".into(), Value::String(r.grade.clone())),
        ],
    }
}

fn value_to_record(v: &Value) -> Result<CollectionRecord, String> {
    let fields = match v {
        Value::Struct { name, fields } if name == RECORD_STRUCT_NAME => fields,
        other => {
            return Err(format!(
                "provenance: expected a CollectionRecord, got {}",
                type_name(other)
            ));
        }
    };
    let field = |k: &str| -> Result<Value, String> {
        fields
            .iter()
            .find(|(fk, _)| fk == k)
            .map(|(_, fv)| fv.clone())
            .ok_or_else(|| format!("provenance: record missing field `{k}`"))
    };
    let f_str = |k: &str| -> Result<String, String> {
        match field(k)? {
            Value::String(s) => Ok(s),
            other => Err(format!(
                "provenance: field `{k}` expected String, got {}",
                type_name(&other)
            )),
        }
    };
    let f_int = |k: &str| -> Result<i64, String> {
        match field(k)? {
            Value::Int(i) => {
                i64::try_from(i).map_err(|_| format!("provenance: field `{k}` out of i64 range"))
            }
            other => Err(format!(
                "provenance: field `{k}` expected Int, got {}",
                type_name(&other)
            )),
        }
    };
    let f_float = |k: &str| -> Result<f64, String> {
        match field(k)? {
            Value::Float(f) => Ok(f),
            other => Err(format!(
                "provenance: field `{k}` expected Float, got {}",
                type_name(&other)
            )),
        }
    };

    let validators = match field("validators")? {
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let (vname, vfields) = match item {
                    Value::Struct { name, fields } if name == STEP_STRUCT_NAME => {
                        (name.clone(), fields)
                    }
                    other => {
                        return Err(format!(
                            "provenance: validator entry expected ValidationStep, got {}",
                            type_name(&other)
                        ));
                    }
                };
                let _ = vname;
                let vget = |k: &str| -> Result<Value, String> {
                    vfields
                        .iter()
                        .find(|(fk, _)| fk == k)
                        .map(|(_, fv)| fv.clone())
                        .ok_or_else(|| format!("provenance: validator missing field `{k}`"))
                };
                let validator = match vget("validator")? {
                    Value::String(s) => s,
                    other => {
                        return Err(format!(
                            "provenance: validator `validator` expected String, got {}",
                            type_name(&other)
                        ));
                    }
                };
                let passed = match vget("passed")? {
                    Value::Bool(b) => b,
                    other => {
                        return Err(format!(
                            "provenance: validator `passed` expected Bool, got {}",
                            type_name(&other)
                        ));
                    }
                };
                let adjustment = match vget("adjustment")? {
                    Value::Float(f) => f,
                    other => {
                        return Err(format!(
                            "provenance: validator `adjustment` expected Float, got {}",
                            type_name(&other)
                        ));
                    }
                };
                let note = match vget("note")? {
                    Value::String(s) => Some(s),
                    Value::Nil => None,
                    other => {
                        return Err(format!(
                            "provenance: validator `note` expected String?, got {}",
                            type_name(&other)
                        ));
                    }
                };
                out.push(ValidationStep {
                    validator,
                    passed,
                    adjustment,
                    note,
                });
            }
            out
        }
        other => {
            return Err(format!(
                "provenance: `validators` expected Array, got {}",
                type_name(&other)
            ));
        }
    };

    Ok(CollectionRecord {
        source_url: f_str("source_url")?,
        fetched_at: f_int("fetched_at")?,
        egress_label: f_str("egress_label")?,
        egress_tier: f_str("egress_tier")?,
        status_code: f_int("status_code")?,
        body_hash: f_str("body_hash")?,
        validators,
        confidence: f_float("confidence")?,
        grade: f_str("grade")?,
    })
}

// ── Dispatch ───────────────────────────────────────────────────────────

/// Route a `provenance` / `Provenance` module function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    // Tolerate dot-prefixed names (osint-style `Provenance.record` routing)
    // in case a caller forwards the full namespace.
    let function = function
        .strip_prefix("Provenance.")
        .or_else(|| function.strip_prefix("provenance."))
        .unwrap_or(function);
    match function {
        "record" => Some(record_dispatch(args)),
        "record_at" => Some(record_at_dispatch(args)),
        "add_validator" => Some(add_validator_dispatch(args)),
        "grade" => Some(record_op_dispatch(args, "grade", op_grade)),
        "freshness" => Some(record_op_dispatch(args, "freshness", op_freshness)),
        "hash_body" => Some(hash_body_dispatch(args)),
        "hash_bytes" => Some(hash_bytes_dispatch(args)),
        "to_json" => Some(record_op_dispatch(args, "to_json", op_to_json)),
        "from_json" => Some(from_json_dispatch(args)),
        _ => None,
    }
}

fn str_arg<'a>(args: &'a [Value], idx: usize, fname: &str) -> Result<&'a str, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(format!(
            "provenance.{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("provenance.{fname}: missing argument {}", idx + 1)),
    }
}

fn int_arg(args: &[Value], idx: usize, fname: &str) -> Result<i64, String> {
    match args.get(idx) {
        Some(Value::Int(i)) => i64::try_from(*i)
            .map_err(|_| format!("provenance.{fname}: argument {} out of i64 range", idx + 1)),
        Some(other) => Err(format!(
            "provenance.{fname}: argument {} expected Int, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("provenance.{fname}: missing argument {}", idx + 1)),
    }
}

fn float_arg(args: &[Value], idx: usize, fname: &str) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(other) => Err(format!(
            "provenance.{fname}: argument {} expected Float, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("provenance.{fname}: missing argument {}", idx + 1)),
    }
}

fn bool_arg(args: &[Value], idx: usize, fname: &str) -> Result<bool, String> {
    match args.get(idx) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!(
            "provenance.{fname}: argument {} expected Bool, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("provenance.{fname}: missing argument {}", idx + 1)),
    }
}

fn record_arg(args: &[Value], idx: usize, fname: &str) -> Result<CollectionRecord, String> {
    match args.get(idx) {
        Some(v) => {
            value_to_record(v).map_err(|e| format!("provenance.{fname}: argument {}: {e}", idx + 1))
        }
        None => Err(format!("provenance.{fname}: missing argument {}", idx + 1)),
    }
}

/// Shared tail of `record` / `record_at`: read the 6 leading args, then the
/// optional `fetched_at` / `base_confidence` positionals if present.
fn record_from_args(args: Vec<Value>, fname: &str, require_fetched_at: bool) -> StdlibResult {
    let url = str_arg(&args, 0, fname)?;
    let label = str_arg(&args, 1, fname)?;
    let tier = str_arg(&args, 2, fname)?;
    let status = int_arg(&args, 3, fname)?;
    let body_hash = str_arg(&args, 4, fname)?;
    // Positionals 6+ are optional: fetched_at (Int), base_confidence (Float).
    let fetched_at = if require_fetched_at {
        int_arg(&args, 5, fname)?
    } else if let Some(Value::Int(i)) = args.get(5) {
        i64::try_from(*i).map_err(|_| format!("provenance.{fname}: fetched_at out of i64 range"))?
    } else {
        now_unix()
    };
    let base = if let Some(Value::Float(f)) = args.get(6) {
        *f
    } else {
        DEFAULT_BASE_CONFIDENCE
    };
    Ok(record_to_value(&CollectionRecord::record(
        url, fetched_at, label, tier, status, body_hash, base,
    )))
}

fn record_dispatch(args: Vec<Value>) -> StdlibResult {
    record_from_args(args, "record", false)
}

fn record_at_dispatch(args: Vec<Value>) -> StdlibResult {
    record_from_args(args, "record_at", true)
}

fn add_validator_dispatch(args: Vec<Value>) -> StdlibResult {
    let mut rec = record_arg(&args, 0, "add_validator")?;
    let name = str_arg(&args, 1, "add_validator")?.to_string();
    let passed = bool_arg(&args, 2, "add_validator")?;
    let adjustment = float_arg(&args, 3, "add_validator")?;
    let note = match args.get(4) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Nil) | None => None,
        Some(other) => {
            return Err(format!(
                "provenance.add_validator: argument 5 expected String?, got {}",
                type_name(other)
            ));
        }
    };
    rec.add_validator(ValidationStep {
        validator: name,
        passed,
        adjustment,
        note,
    });
    Ok(record_to_value(&rec))
}

/// Apply an op that maps one record to one value (grade mutates then
/// re-emits the updated record).
fn record_op_dispatch(
    args: Vec<Value>,
    fname: &str,
    op: fn(&mut CollectionRecord) -> Result<Value, String>,
) -> StdlibResult {
    let mut rec = record_arg(&args, 0, fname)?;
    op(&mut rec)
}

fn op_grade(rec: &mut CollectionRecord) -> Result<Value, String> {
    let _ = rec.grade();
    Ok(record_to_value(rec))
}

fn op_freshness(rec: &mut CollectionRecord) -> Result<Value, String> {
    Ok(Value::String(
        freshness_label(rec.freshness_tier()).to_string(),
    ))
}

fn op_to_json(rec: &mut CollectionRecord) -> Result<Value, String> {
    Ok(Value::String(rec.to_json()))
}

fn hash_body_dispatch(args: Vec<Value>) -> StdlibResult {
    // A `Bytes` argument is the G-14 composition (`hash_body(read_bytes(p))`).
    // While `read_bytes` handed back base64 text this ran at rc=0 and produced
    // the sha256 of the encoding — a plausible, wrong, silent digest. Name the
    // reason and the fix instead.
    if let Some(Value::Bytes(_)) = args.first() {
        return Err(
            "provenance.hash_body: argument 1 expected String, got Bytes — hash_body fingerprints \
             text (the argument's UTF-8 bytes), not raw content; use provenance.hash_bytes for a \
             file's true sha256"
                .into(),
        );
    }
    let body = str_arg(&args, 0, "hash_body")?;
    Ok(Value::String(hash_body(body)))
}

/// `provenance.hash_bytes(data: Bytes) -> String` — sha256 of raw bytes.
///
/// `Bytes` only: accepting a `String` here would recreate the ambiguity this
/// pair exists to remove (a base64 `String` would be decoded by one caller and
/// hashed literally by the next).
fn hash_bytes_dispatch(args: Vec<Value>) -> StdlibResult {
    match args.first() {
        Some(Value::Bytes(b)) => Ok(Value::String(hash_bytes(b))),
        Some(other) => Err(format!(
            "provenance.hash_bytes: argument 1 expected Bytes, got {} — hash_bytes fingerprints raw \
             content; hash text with provenance.hash_body",
            type_name(other)
        )),
        None => Err("provenance.hash_bytes: missing argument 1".into()),
    }
}

fn from_json_dispatch(args: Vec<Value>) -> StdlibResult {
    let json = str_arg(&args, 0, "from_json")?;
    let rec = CollectionRecord::from_json(json)?;
    Ok(record_to_value(&rec))
}

/// Route method calls on `CollectionRecord` struct values (`rec.grade()`).
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match object {
        Value::Struct { name, .. } if name == RECORD_STRUCT_NAME => {
            let mut all = vec![object.clone()];
            all.extend(args);
            match method {
                "grade" => Some(record_op_dispatch(all, "grade", op_grade)),
                "freshness" => Some(record_op_dispatch(all, "freshness", op_freshness)),
                "to_json" => Some(record_op_dispatch(all, "to_json", op_to_json)),
                "add_validator" => Some(add_validator_dispatch(all)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn freshness_label(tier: FreshnessTier) -> &'static str {
    match tier {
        FreshnessTier::Fresh => "Fresh",
        FreshnessTier::Recent => "Recent",
        FreshnessTier::Stale => "Stale",
        FreshnessTier::Old => "Old",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        now_unix()
    }

    /// Canned fixture: a 200 fetch over a residential egress (fresh).
    fn fixture_ok() -> CollectionRecord {
        CollectionRecord::record(
            "https://example.com/prices",
            now(),
            "us-res-01",
            "residential",
            200,
            "ab12",
            DEFAULT_BASE_CONFIDENCE,
        )
    }

    /// Canned fixture: same URL, Tor egress, 503.
    fn fixture_tor_503() -> CollectionRecord {
        CollectionRecord::record(
            "https://example.com/prices",
            now(),
            "tor-pool-07",
            "tor",
            503,
            "cd34",
            DEFAULT_BASE_CONFIDENCE,
        )
    }

    /// Canned fixture: same URL/egress as `fixture_ok` but a 404 status.
    fn fixture_404() -> CollectionRecord {
        CollectionRecord::record(
            "https://example.com/prices",
            now(),
            "us-res-01",
            "residential",
            404,
            "ef56",
            DEFAULT_BASE_CONFIDENCE,
        )
    }

    fn field_of(v: &Value, key: &str) -> Value {
        match v {
            Value::Struct { name, fields } => {
                assert_eq!(name, RECORD_STRUCT_NAME, "expected CollectionRecord struct");
                fields
                    .iter()
                    .find(|(k, _)| k == key)
                    .unwrap_or_else(|| panic!("missing field {key}"))
                    .1
                    .clone()
            }
            other => panic!("expected struct, got {:?}", type_name(other)),
        }
    }

    #[test]
    fn record_constructor_fills_fields() {
        let r = fixture_ok();
        assert_eq!(r.source_url, "https://example.com/prices");
        assert_eq!(r.egress_label, "us-res-01");
        assert_eq!(r.egress_tier, "residential");
        assert_eq!(r.status_code, 200);
        assert_eq!(r.body_hash, "ab12");
        assert!(r.validators.is_empty());
        assert_eq!(r.confidence, DEFAULT_BASE_CONFIDENCE);
        assert_eq!(r.grade, "");
        assert_eq!(r.freshness_tier(), FreshnessTier::Fresh);
    }

    #[test]
    fn grade_classifies_200_residential_as_a() {
        let mut r = fixture_ok();
        assert_eq!(r.grade(), "A");
        assert_eq!(r.grade, "A");
        assert!(r.is_trustworthy());
    }

    #[test]
    fn grade_classifies_503_tor_as_f() {
        let mut r = fixture_tor_503();
        assert_eq!(r.grade(), "F");
        assert!(!r.is_trustworthy(), "503 fetch is never trustworthy");
    }

    #[test]
    fn grade_classifies_404_residential_as_d() {
        let mut r = fixture_404();
        assert_eq!(r.grade(), "D");
    }

    #[test]
    fn same_url_two_egresses_differing_statuses_sort_correctly() {
        // Same URL; egress/status differences must move the letter.
        let mut a = fixture_ok();
        let mut b = fixture_tor_503();
        let mut d = fixture_404();
        let ga = a.grade();
        let gb = b.grade();
        let gd = d.grade();
        // A > D > F ordering by trust.
        let rank = |g: &str| match g {
            "A" => 5,
            "B" => 4,
            "C" => 3,
            "D" => 2,
            "F" => 0,
            _ => panic!("unexpected grade {g}"),
        };
        assert!(rank(&ga) > rank(&gd), "{ga} should outrank {gd}");
        assert!(rank(&gd) > rank(&gb), "{gd} should outrank {gb}");
        assert_eq!((ga.as_str(), gb.as_str(), gd.as_str()), ("A", "F", "D"));
    }

    #[test]
    fn datacenter_egress_downgrades_once() {
        let mut r = CollectionRecord::record(
            "https://example.com/prices",
            now(),
            "pool-dc-2",
            "datacenter",
            200,
            "aa",
            DEFAULT_BASE_CONFIDENCE,
        );
        assert_eq!(r.grade(), "B"); // 200 (5) − datacenter (1) = B
    }

    #[test]
    fn stale_and_old_fetches_downgrade() {
        let mut stale = CollectionRecord::record(
            "https://example.com/prices",
            now() - 7 * 3600,
            "us-res-01",
            "residential",
            200,
            "aa",
            DEFAULT_BASE_CONFIDENCE,
        );
        // 200 (5) − Stale (1) = 4 → B
        assert_eq!(stale.freshness_tier(), FreshnessTier::Stale);
        assert_eq!(stale.grade(), "B");

        let mut old = CollectionRecord::record(
            "https://example.com/prices",
            now() - 48 * 3600,
            "us-res-01",
            "residential",
            200,
            "aa",
            DEFAULT_BASE_CONFIDENCE,
        );
        assert_eq!(old.freshness_tier(), FreshnessTier::Old);
        assert_eq!(old.grade(), "C"); // 5 − 2 = 3 → C
    }

    #[test]
    fn validators_fold_like_browser_model() {
        // Failing validation subtracts |adj|: 0.8 − 0.5 = 0.3 → conf < 0.5 → −2.
        let mut r = fixture_ok();
        r.add_validator(ValidationStep {
            validator: "html_parse".into(),
            passed: false,
            adjustment: 0.5,
            note: Some("gibberish body".into()),
        });
        assert!((r.fold_confidence() - 0.3).abs() < 1e-9);
        let letter = r.grade();
        assert_eq!(letter, "C"); // 5 + 0 − 2 (conf<0.5) = 3
        assert!(!r.is_trustworthy());

        // Passing validation adds: 0.8 + 0.05 = 0.85 → still A band.
        let mut ok = fixture_ok();
        ok.add_validator(ValidationStep {
            validator: "schema".into(),
            passed: true,
            adjustment: 0.05,
            note: None,
        });
        assert!((ok.fold_confidence() - 0.85).abs() < 1e-9);
        assert_eq!(ok.grade(), "A");
    }

    #[test]
    fn json_roundtrip_preserves_every_field() {
        let mut r = fixture_ok();
        r.add_validator(ValidationStep {
            validator: "schema".into(),
            passed: true,
            adjustment: 0.05,
            note: Some("json-ld ok".into()),
        });
        let _ = r.grade();
        let json = r.to_json();
        let back = CollectionRecord::from_json(&json).expect("roundtrip parse");
        assert_eq!(back.source_url, r.source_url);
        assert_eq!(back.fetched_at, r.fetched_at);
        assert_eq!(back.egress_label, r.egress_label);
        assert_eq!(back.egress_tier, r.egress_tier);
        assert_eq!(back.status_code, r.status_code);
        assert_eq!(back.body_hash, r.body_hash);
        assert_eq!(back.grade, r.grade);
        assert!((back.confidence - r.confidence).abs() < 1e-9);
        assert_eq!(back.validators.len(), 1);
        assert_eq!(back.validators[0].validator, "schema");
        assert!(back.validators[0].passed);
        assert!((back.validators[0].adjustment - 0.05).abs() < 1e-9);
        assert_eq!(back.validators[0].note.as_deref(), Some("json-ld ok"));
    }

    #[test]
    fn grade_is_stable_through_json_roundtrip() {
        let mut a = fixture_ok();
        let mut b = fixture_tor_503();
        let mut d = fixture_404();
        let (ga, gb, gd) = (a.grade(), b.grade(), d.grade());

        // Roundtrip each, re-grade the parsed copy — classification holds.
        let a2 = CollectionRecord::from_json(&a.to_json()).unwrap();
        let mut a2 = a2;
        assert_eq!(a2.grade(), ga);
        assert_eq!(a2.grade, ga);

        let b2 = CollectionRecord::from_json(&b.to_json()).unwrap();
        let mut b2 = b2;
        assert_eq!(b2.grade(), gb);

        let d2 = CollectionRecord::from_json(&d.to_json()).unwrap();
        let mut d2 = d2;
        assert_eq!(d2.grade(), gd);
    }

    #[test]
    fn hash_body_is_deterministic_sha256() {
        let h1 = hash_body("<html>prices</html>");
        let h2 = hash_body("<html>prices</html>");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(h1, hash_body("<html>other</html>"));
    }

    #[test]
    fn freshness_thresholds_mirror_browser_model() {
        let mk = |age: i64| {
            CollectionRecord::record(
                "https://example.com/x",
                now() - age,
                "us-res-01",
                "residential",
                200,
                "h",
                DEFAULT_BASE_CONFIDENCE,
            )
        };
        assert_eq!(mk(0).freshness_tier(), FreshnessTier::Fresh);
        assert_eq!(mk(14 * 60).freshness_tier(), FreshnessTier::Fresh);
        assert_eq!(mk(15 * 60).freshness_tier(), FreshnessTier::Recent);
        assert_eq!(mk(5 * 3600).freshness_tier(), FreshnessTier::Recent);
        assert_eq!(mk(6 * 3600).freshness_tier(), FreshnessTier::Stale);
        assert_eq!(mk(23 * 3600).freshness_tier(), FreshnessTier::Stale);
        assert_eq!(mk(24 * 3600).freshness_tier(), FreshnessTier::Old);
    }

    #[test]
    fn dispatch_routes_module_functions() {
        // record → struct
        let rec = dispatch(
            "record",
            vec![
                Value::String("https://example.com/prices".into()),
                Value::String("us-res-01".into()),
                Value::String("residential".into()),
                Value::Int(200),
                Value::String("ab12".into()),
            ],
        )
        .expect("routable")
        .expect("record ok");
        assert!(matches!(field_of(&rec, "status_code"), Value::Int(200)));
        assert!(matches!(field_of(&rec, "egress_label"), Value::String(s) if s == "us-res-01"));

        // add_validator on the struct value
        let with_v = dispatch(
            "add_validator",
            vec![
                rec.clone(),
                Value::String("schema".into()),
                Value::Bool(true),
                Value::Float(0.05),
            ],
        )
        .expect("routable")
        .expect("add_validator ok");

        // grade on the struct value
        let graded = dispatch("grade", vec![with_v])
            .expect("routable")
            .expect("grade ok");
        assert!(matches!(field_of(&graded, "grade"), Value::String(s) if s == "A"));

        // to_json / from_json roundtrip through dispatch
        let json = dispatch("to_json", vec![graded.clone()])
            .expect("routable")
            .expect("to_json ok");
        let Value::String(json_s) = json else {
            panic!("expected JSON string");
        };
        let back = dispatch("from_json", vec![Value::String(json_s)])
            .expect("routable")
            .expect("from_json ok");
        assert!(matches!(field_of(&back, "grade"), Value::String(s) if s == "A"));

        // hash_body helper
        let h = dispatch("hash_body", vec![Value::String("body".into())])
            .expect("routable")
            .expect("hash ok");
        assert!(matches!(h, Value::String(s) if s.len() == 64));

        // method-call routing: rec.grade() via dispatch_method
        let via_method = dispatch_method(&rec, "grade", vec![])
            .expect("method routable")
            .expect("method grade ok");
        assert!(matches!(field_of(&via_method, "grade"), Value::String(s) if s == "A"));

        // unknown function → None
        assert!(dispatch("warp", vec![]).is_none());
        // wrong-typed arg → honest Err
        let err = dispatch(
            "record",
            vec![
                Value::Int(42),
                Value::String("l".into()),
                Value::String("t".into()),
                Value::Int(200),
                Value::String("h".into()),
            ],
        )
        .expect("routable");
        assert!(err.is_err(), "expected type error on url arg");
        // wrong struct to grade → honest Err
        let bogus = dispatch("grade", vec![Value::Int(1)]).expect("routable");
        assert!(bogus.is_err());
    }

    #[test]
    fn record_at_honors_explicit_timestamp() {
        let past = now() - 90_000; // >24h: Old
        let rec = dispatch(
            "record_at",
            vec![
                Value::String("https://example.com/prices".into()),
                Value::String("us-res-01".into()),
                Value::String("residential".into()),
                Value::Int(200),
                Value::String("ab12".into()),
                Value::Int(past as i128),
            ],
        )
        .expect("routable")
        .expect("record_at ok");
        assert!(matches!(field_of(&rec, "fetched_at"), Value::Int(i) if i == past as i128));
        let graded = dispatch("grade", vec![rec])
            .expect("routable")
            .expect("grade ok");
        assert!(matches!(field_of(&graded, "grade"), Value::String(s) if s == "C"));
    }

    #[test]
    fn interp_end_to_end() {
        // Exercises namespace resolution (lowercase + capitalized spelling),
        // record/grade dispatch, method-call routing, and JSON roundtrip
        // through the real interpreter.
        let src = r#"
        fn main() {
            let h = provenance.hash_body("hello body")
            print(h)
            let rec = Provenance.record("https://example.com/prices", "us-res-01", "residential", 200, h)
            let rec2 = provenance.add_validator(rec, "html_parse", true, 0.05, "parsed ok")
            let graded = Provenance.grade(rec2)
            print(graded.grade)
            let j = provenance.to_json(graded)
            let copy = provenance.from_json(j)
            let copy2 = copy.grade()
            print(copy2.grade)
            print(provenance.freshness(graded))
        }
        "#;
        let (tokens, lex_errs) = crate::lexer::tokenize(src);
        assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        let mut interp = crate::interp::Interpreter::new();
        interp.run(&program).expect("interp run failed");
        assert_eq!(interp.output.len(), 4, "output: {:?}", interp.output);
        assert_eq!(interp.output[0].len(), 64, "hash should be 64 hex chars");
        assert_eq!(interp.output[1], "A", "graded record should be A");
        assert_eq!(
            interp.output[2], "A",
            "grade must survive the JSON roundtrip"
        );
        assert_eq!(interp.output[3], "Fresh");
    }

    /// G-14 regression, end-to-end through the real interpreter: a file's raw
    /// bytes must fingerprint to the file's true sha256, and the old silent
    /// composition must fail loudly instead of reporting a plausible wrong one.
    ///
    /// Fixture is the card's payload.bin (16 bytes, non-UTF-8):
    ///   true sha256      274d198c0ff7f261224e0b8d53c5fd7de6dc4041c320819772b71028fd187fdc
    ///   true BLAKE3      78fe41492badfb8986070d7f34ec720eaedb57e58c67a52f200d2cd2767fa42b
    ///   sha256(base64)   dafabbf68b59101b3b5cd4f7caecb0b9b6e52374f8e2ee19e3996042be4f920b
    #[test]
    fn interp_read_bytes_hashes_to_true_sha256_and_refuses_hash_body() {
        const PAYLOAD: &[u8] = b"binary\x00payload\xff\xfe";
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, PAYLOAD).expect("write fixture");
        let path = path.to_string_lossy().to_string();

        let run = |src: &str| -> (Vec<String>, Option<String>) {
            let (tokens, lex_errs) = crate::lexer::tokenize(src);
            assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
            let program = crate::parser::Parser::parse(tokens).expect("parse error");
            let mut interp = crate::interp::Interpreter::new();
            let err = interp.run(&program).err().map(|e| e.to_string());
            (interp.output.clone(), err)
        };

        // (a) the binary-safe path: raw bytes in, true sha256 out.
        let (out, err) = run(&format!(
            "fn main() {{ let b = fs.read_bytes(\"{path}\")\n print(provenance.hash_bytes(b)) }}"
        ));
        assert_eq!(err, None, "hash_bytes must succeed");
        assert_eq!(
            out,
            vec!["274d198c0ff7f261224e0b8d53c5fd7de6dc4041c320819772b71028fd187fdc".to_string()],
            "hash_bytes(read_bytes(file)) must be the file's true sha256"
        );

        // (b) the composition the card filed: it must NOT succeed silently.
        let (out, err) = run(&format!(
            "fn main() {{ let b = fs.read_bytes(\"{path}\")\n print(provenance.hash_body(b)) }}"
        ));
        assert!(out.is_empty(), "nothing may be printed: {out:?}");
        let msg = err.expect("hash_body(read_bytes) must fail, not report a wrong digest");
        assert!(msg.contains("Bytes"), "reason must name the type: {msg}");
        assert!(
            msg.contains("hash_bytes"),
            "reason must name the fix: {msg}"
        );
        assert!(
            !msg.contains("dafabbf6"),
            "must not fall through to hashing the encoded form: {msg}"
        );

        // (c) control: the old value really was sha256(base64(file)) — pinned so
        // a future change that re-merges the two paths is visible here.
        let (out, _) = run(
            "fn main() { print(provenance.hash_body(\"YmluYXJ5AHBheWxvYWT//g==\")) }",
        );
        assert_eq!(
            out,
            vec!["dafabbf68b59101b3b5cd4f7caecb0b9b6e52374f8e2ee19e3996042be4f920b".to_string()],
            "text hashing is unchanged: sha256 of the base64 text"
        );
    }

    /// `hash_bytes` is Bytes-only and `hash_body` is String-only, so neither can
    /// silently absorb the other's input.
    #[test]
    fn hash_bytes_and_hash_body_are_type_separated() {
        let payload: &[u8] = b"binary\x00payload\xff\xfe";
        let raw = dispatch("hash_bytes", vec![Value::Bytes(payload.to_vec())])
            .expect("routable")
            .expect("hash_bytes ok");
        match raw {
            Value::String(s) => assert_eq!(
                s,
                "274d198c0ff7f261224e0b8d53c5fd7de6dc4041c320819772b71028fd187fdc"
            ),
            other => panic!("expected hex digest String, got {other:?}"),
        }
        assert_eq!(hash_body("hello body"), hash_bytes(b"hello body"));

        let err = dispatch("hash_bytes", vec![Value::String("hello body".into())])
            .expect("routable")
            .expect_err("a String is not Bytes");
        assert!(err.contains("expected Bytes, got String"), "{err}");
        assert!(err.contains("hash_body"), "{err}");

        let err = dispatch("hash_body", vec![Value::Bytes(payload.to_vec())])
            .expect("routable")
            .expect_err("Bytes is not String");
        assert!(err.contains("expected String, got Bytes"), "{err}");
        assert!(err.contains("hash_bytes"), "{err}");
    }
}
