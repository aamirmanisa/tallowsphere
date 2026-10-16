//! Canary tokens — generation, validation, scanning, and manifest embedding.
//!
//! A canary token is a per-investigation tripwire string planted into data
//! that may leave the operator's control (manifests, exports, shared
//! artifacts). If the token later surfaces somewhere it was not planted for,
//! the data moved further than intended — a detectable, provable leak.
//!
//! Token format (frozen interface §5):
//!
//! ```text
//! TLW-<KIND>-<16 hex random>-<4 hex checksum>
//! ```
//!
//! * `<KIND>` ∈ {`URL`, `MARKER`, `SERIAL`} — see [`CanaryKind::as_str`].
//! * `<16 hex random>` — 8 random bytes (uuid v4), lower-case hex.
//! * `<4 hex checksum>` — first 4 hex chars of
//!   `sha256(<16 hex random> as ASCII bytes)`.
//!
//! The checksum is computed over the *hex-string form* of the random part so
//! an auditor holding only the token text can recompute it. It is a 16-bit
//! truncation (as specified), so a corrupted token is accepted by
//! [`is_valid`] with probability ≈ 2⁻¹⁶; it is a corruption tripwire, not a
//! cryptographic authenticator.
//!
//! ## Sink scoping (R-6.10)
//!
//! Emission is scope-gated: a canary is only ever emitted to sinks the
//! investigation **explicitly declared** in a [`SinkScope`] — never globally
//! injected, and never to "any write" (rejected as a false-positive storm).
//! The scope starts empty and grows only via [`SinkScope::declare`]; the only
//! emission path is [`emit_manifest`] (the raw JSON embed is private), and it
//! refuses undeclared sinks and invalid canaries alike — a refusal emits
//! nothing.
//!
//! The audit ledger is itself a declared sink ([`CanarySinkKind::Ledger`])
//! and is exempt from canary **scanning** ([`CanarySinkKind::is_scan_exempt`]):
//! it legitimately records the events it is handed, so scanning it for the
//! canaries it was meant to record would self-trip.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a canary is planted as. Descriptive only: `KIND` is part of the token
/// text so an operator can tell at a glance which surface leaked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum CanaryKind {
    /// Planted in a URL (query parameter, path segment, redirect target).
    Url,
    /// Free-standing text marker embedded in a document/manifest.
    Marker,
    /// Serial-number-shaped token for databases/receipts/exports.
    Serial,
}

impl CanaryKind {
    /// Upper-case `KIND` segment used in the token text.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            CanaryKind::Url => "URL",
            CanaryKind::Marker => "MARKER",
            CanaryKind::Serial => "SERIAL",
        }
    }
}

/// Lower-case hex encoding (local — `hex` crate is not a dependency).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Generate a fresh canary token of `kind`.
///
/// Randomness source: 8 bytes from a uuid v4 (≈60 effective bits — uuid fixes
/// the version/variant nibbles). Collision-free for any realistic canary
/// population (birthday bound: ~10⁻¹³ at 1,000 tokens).
#[allow(dead_code)]
pub fn generate(kind: CanaryKind) -> String {
    let uuid = uuid::Uuid::new_v4().into_bytes();
    let random_hex = to_hex(&uuid[..8]);
    let checksum = checksum_of(&random_hex);
    format!("TLW-{}-{}-{}", kind.as_str(), random_hex, checksum)
}

/// First 4 hex chars of `sha256(random_hex)`: the token checksum.
fn checksum_of(random_hex: &str) -> String {
    let digest = Sha256::digest(random_hex.as_bytes());
    to_hex(digest.as_slice())[..4].to_string()
}

/// True when `s` has the exact shape `TLW-<KIND>-<16 lower hex>-<4 lower hex>`
/// and the checksum matches the random part.
///
/// Strictness is deliberate (canonical form): upper-case hex, lower-case
/// `kind`, extra segments, or truncation all fail.
#[allow(dead_code)]
pub fn is_valid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 4 {
        return false;
    }
    if parts[0] != "TLW" {
        return false;
    }
    if !matches!(parts[1], "URL" | "MARKER" | "SERIAL") {
        return false;
    }
    let is_lower_hex = |t: &str| t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let random = parts[2];
    if random.len() != 16 || !is_lower_hex(random) {
        return false;
    }
    let checksum = parts[3];
    if checksum.len() != 4 || !is_lower_hex(checksum) {
        return false;
    }
    checksum_of(random) == checksum
}

/// One occurrence of a canary token in scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CanaryHit {
    /// The canary that matched.
    pub token: String,
    /// Byte offset of the match start in the scanned text.
    pub offset: usize,
}

/// Find every occurrence of every canary in `text`.
///
/// * Results are sorted by byte offset (ties: token lexicographic) for
///   deterministic output.
/// * Duplicate/empty entries in `canaries` are ignored (one hit list, not one
///   per duplicate).
/// * Offsets are byte offsets (usable directly in `&text[o..o + token.len()]`),
///   not char indices.
/// * No length filtering: any literal string passed as a canary is matched
///   as-is (tokens are validated by the caller, e.g. with [`is_valid`]).
#[allow(dead_code)]
pub fn scan(text: &str, canaries: &[String]) -> Vec<CanaryHit> {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut hits: Vec<CanaryHit> = Vec::new();
    for canary in canaries {
        if canary.is_empty() || !seen.insert(canary.as_str()) {
            continue;
        }
        for (offset, _) in text.match_indices(canary.as_str()) {
            hits.push(CanaryHit {
                token: canary.clone(),
                offset,
            });
        }
    }
    hits.sort_by(|a, b| a.offset.cmp(&b.offset).then_with(|| a.token.cmp(&b.token)));
    hits
}

/// Raw JSON embed primitive — **unchecked**: no sink declaration, no canary
/// validation. Private by design: the only emission path is [`emit_manifest`],
/// which enforces declared-sink scope (R-6.10). Kept separate so the JSON
/// mechanics stay directly testable.
///
/// Insert a top-level `"canary":"<token>"` field into a JSON **object**.
///
/// Documented limits (deliberately no float/edge-case heroics):
/// * Input must parse as a JSON object; invalid JSON, arrays, and scalars are
///   returned byte-for-byte unchanged.
/// * Output is compact re-serialization — original whitespace and key order
///   are not preserved (the result is always valid JSON).
/// * An existing top-level `"canary"` field is **overwritten** (the last
///   planted token wins); pass the token you mean to plant.
/// * Non-finite float handling is whatever `serde_json` does; not special-cased.
#[allow(dead_code)]
fn embed_manifest_raw(manifest_json: &str, canary: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(manifest_json) else {
        return manifest_json.to_string();
    };
    let Some(obj) = value.as_object_mut() else {
        return manifest_json.to_string();
    };
    obj.insert(
        "canary".to_string(),
        serde_json::Value::String(canary.to_string()),
    );
    serde_json::to_string(&value).unwrap_or_else(|_| manifest_json.to_string())
}

// ── Declared sinks and scoped emission (R-6.10) ─────────────────────────────

/// Class of an outbound sink a canary may be emitted to.
///
/// Descriptive (like [`CanaryKind`]): emission checks the declaration of the
/// sink id, not this label. The label tells operator-facing reports which
/// surface a sink is, and expresses the ledger scan-exemption
/// ([`Self::is_scan_exempt`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum CanarySinkKind {
    /// Manifest / shared-artifact embedding (JSON or document field).
    Manifest,
    /// Structured export or serial-shaped output (databases, receipts).
    Export,
    /// URL surface (query parameter, path segment, redirect target).
    Url,
    /// Local log line or captured tool output copy.
    Log,
    /// Outbound tool call (AI/agentic path).
    ToolCall,
    /// Append-only audit ledger — a declared sink, exempt from scanning.
    Ledger,
}

impl CanarySinkKind {
    /// Lower-snake label used in operator-facing messages.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            CanarySinkKind::Manifest => "manifest",
            CanarySinkKind::Export => "export",
            CanarySinkKind::Url => "url",
            CanarySinkKind::Log => "log",
            CanarySinkKind::ToolCall => "tool_call",
            CanarySinkKind::Ledger => "ledger",
        }
    }

    /// True only for [`CanarySinkKind::Ledger`] (R-6.10: "ledger exempt as a
    /// declared sink"). The ledger legitimately records the events it is
    /// handed, so scanning it for the canaries it was meant to record would
    /// self-trip; every other kind is scan-eligible.
    #[allow(dead_code)]
    pub fn is_scan_exempt(&self) -> bool {
        matches!(self, CanarySinkKind::Ledger)
    }
}

impl std::fmt::Display for CanarySinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One sink explicitly declared for a canary scope:
/// `id` is the stable operator-chosen name (what runs and evidence refer
/// to), `kind` classifies the surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DeclaredSink {
    /// Stable operator-chosen sink id.
    pub id: String,
    /// Descriptive classification of the sink (see [`CanarySinkKind`]).
    pub kind: CanarySinkKind,
}

impl DeclaredSink {
    /// New declared sink named `id` with surface class `kind`.
    #[allow(dead_code)]
    pub fn new(id: impl Into<String>, kind: CanarySinkKind) -> Self {
        DeclaredSink {
            id: id.into(),
            kind,
        }
    }
}

/// A refused declaration: `id` is already declared with another kind.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DeclareConflict {
    /// `id` was declared before with a different kind — refusing to guess
    /// which declaration the operator meant.
    KindConflict {
        /// The contended sink id.
        id: String,
        /// Kind of the existing declaration.
        existing: CanarySinkKind,
        /// Kind the conflicting declaration attempted.
        attempted: CanarySinkKind,
    },
}

impl std::fmt::Display for DeclareConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeclareConflict::KindConflict {
                id,
                existing,
                attempted,
            } => write!(
                f,
                "sink `{id}` already declared as {existing} — refusing conflicting declaration as {attempted}"
            ),
        }
    }
}

impl std::error::Error for DeclareConflict {}

/// Explicit opt-in registry of the sinks a canary may be emitted to.
///
/// Starts **empty**: with nothing declared, no emission is possible (canaries
/// are never globally injected — R-6.10). Sinks are added one by one via
/// [`SinkScope::declare`]; re-declaring an identical sink is a no-op,
/// re-declaring the same id with a different kind is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SinkScope {
    sinks: Vec<DeclaredSink>,
}

impl SinkScope {
    /// Empty scope — nothing declared, nothing emittable (explicit opt-in).
    #[allow(dead_code)]
    pub fn new() -> Self {
        SinkScope { sinks: Vec::new() }
    }

    /// Declare `sink` for this scope. Idempotent for an identical
    /// declaration; refuses the same id with a different kind.
    #[allow(dead_code)]
    pub fn declare(&mut self, sink: DeclaredSink) -> Result<(), DeclareConflict> {
        if let Some(existing) = self.sinks.iter().find(|s| s.id == sink.id) {
            if existing.kind == sink.kind {
                return Ok(());
            }
            return Err(DeclareConflict::KindConflict {
                id: sink.id,
                existing: existing.kind,
                attempted: sink.kind,
            });
        }
        self.sinks.push(sink);
        Ok(())
    }

    /// True when `id` is a declared sink of this scope.
    #[allow(dead_code)]
    pub fn is_declared(&self, id: &str) -> bool {
        self.sinks.iter().any(|s| s.id == id)
    }

    /// The declared sink with id `id`, if any.
    #[allow(dead_code)]
    pub fn sink(&self, id: &str) -> Option<&DeclaredSink> {
        self.sinks.iter().find(|s| s.id == id)
    }

    /// All declared sinks, in declaration order.
    #[allow(dead_code)]
    pub fn declared(&self) -> &[DeclaredSink] {
        &self.sinks
    }
}

/// Why a canary emission was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EmissionRefused {
    /// The sink was never declared in the scope. Canary tokens are never
    /// globally injected (R-6.10) — refusal means *nothing was emitted*.
    UndeclaredSink {
        /// The sink id the caller attempted to emit to.
        sink: String,
        /// Ids declared in the scope at refusal time (for the operator).
        declared: Vec<String>,
    },
    /// The canary fails [`is_valid`]: planting it would create a tripwire
    /// [`crate::canary_monitor::sweep`] can never fire (it drops invalid
    /// canaries before scanning) — a silently dead control.
    InvalidCanary {
        /// The rejected token text.
        canary: String,
    },
}

impl std::fmt::Display for EmissionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmissionRefused::UndeclaredSink { sink, declared } => write!(
                f,
                "sink `{sink}` is not declared for this canary scope (declared: [{}]) — canaries are never emitted to undeclared sinks",
                declared.join(", ")
            ),
            EmissionRefused::InvalidCanary { canary } => {
                write!(f, "refusing to embed invalid canary `{canary}`")
            }
        }
    }
}

impl std::error::Error for EmissionRefused {}

/// Emit `canary` into a JSON manifest — **only** if `sink_id` is a declared
/// sink of `scope`, and only for a valid canary.
///
/// This is the sole public emission path for canary tokens (R-6.10,
/// declared-sink scope). Returns the payload with the top-level `"canary"`
/// field set (JSON mechanics: [`embed_manifest_raw`]) or an
/// [`EmissionRefused`]; on refusal **nothing is emitted** — there is no
/// global injection and no fallback write.
#[allow(dead_code)]
pub fn emit_manifest(
    scope: &SinkScope,
    sink_id: &str,
    manifest_json: &str,
    canary: &str,
) -> Result<String, EmissionRefused> {
    if !scope.is_declared(sink_id) {
        return Err(EmissionRefused::UndeclaredSink {
            sink: sink_id.to_string(),
            declared: scope.declared().iter().map(|s| s.id.clone()).collect(),
        });
    }
    if !is_valid(canary) {
        return Err(EmissionRefused::InvalidCanary {
            canary: canary.to_string(),
        });
    }
    Ok(embed_manifest_raw(manifest_json, canary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generates_thousand_unique_valid_tokens() {
        let kinds = [CanaryKind::Url, CanaryKind::Marker, CanaryKind::Serial];
        let mut seen: HashSet<String> = HashSet::new();
        for i in 0..1000 {
            let kind = kinds[i % kinds.len()];
            let t = generate(kind);
            assert!(is_valid(&t), "generated token failed validation: {t}");
            assert!(t.starts_with(&format!("TLW-{}-", kind.as_str())));
            assert!(seen.insert(t.clone()), "duplicate token: {t}");
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn generated_token_shape_is_canonical() {
        let t = generate(CanaryKind::Url);
        let parts: Vec<&str> = t.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "TLW");
        assert_eq!(parts[1], "URL");
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[3], checksum_of(parts[2]));
        // as_str mapping
        assert_eq!(CanaryKind::Marker.as_str(), "MARKER");
        assert_eq!(CanaryKind::Serial.as_str(), "SERIAL");
    }

    #[test]
    fn checksum_detects_corruption_of_one_char() {
        let token = generate(CanaryKind::Marker);
        assert!(is_valid(&token));
        let parts: Vec<&str> = token.split('-').collect();
        let random = parts[2];
        let checksum = parts[3];

        // Flip char 0 of the random part (a↔b style: always a change).
        let mut flipped_first = String::from(random);
        let repl_first = if random.as_bytes()[0] == b'a' { "b" } else { "a" };
        flipped_first.replace_range(0..1, repl_first);
        let tampered = format!("TLW-MARKER-{flipped_first}-{checksum}");
        assert!(!is_valid(&tampered), "checksum missed corruption at pos 0");

        // Flip the last char of the random part too (two independent flips
        // make an accidental 16-bit checksum collision essentially impossible
        // while keeping the test trivially simple).
        let mut flipped_last = String::from(random);
        let last = random.as_bytes()[random.len() - 1];
        let repl_last = if last == b'f' { "e" } else { "f" };
        flipped_last.replace_range(random.len() - 1..random.len(), repl_last);
        let tampered2 = format!("TLW-MARKER-{flipped_last}-{checksum}");
        assert!(!is_valid(&tampered2), "checksum missed corruption at last pos");

        // Corrupt the checksum part itself (replacement always differs).
        let mut bad_checksum = String::from(checksum);
        let repl_cs = if checksum.as_bytes()[0] == b'0' { "1" } else { "0" };
        bad_checksum.replace_range(0..1, repl_cs);
        let tampered3 = format!("TLW-MARKER-{random}-{bad_checksum}");
        assert!(!is_valid(&tampered3), "checksum mismatch not detected");
    }

    #[test]
    fn is_valid_rejects_malformed_tokens() {
        let good = generate(CanaryKind::Serial);
        assert!(is_valid(&good));
        assert!(!is_valid(""));
        assert!(!is_valid("TLW-URL-0123456789abcdef")); // missing checksum
        assert!(!is_valid("TLW-NOPE-0123456789abcdef-dead")); // bad kind word
        assert!(!is_valid("XXX-URL-0123456789abcdef-dead")); // bad prefix
        assert!(!is_valid("tlw-URL-0123456789abcdef-dead")); // lower-case prefix
        assert!(!is_valid("TLW-url-0123456789abcdef-dead")); // lower-case kind
        assert!(!is_valid("TLW-URL-0123456789ABCDEF-dead")); // upper-case hex
        assert!(!is_valid("TLW-URL-0123456789abcde-dead")); // 15 hex chars
        assert!(!is_valid("TLW-URL-0123456789abcdef-x")); // short checksum
        assert!(!is_valid(" TLW-URL-0123456789abcdef-dead")); // leading space
        assert!(!is_valid(&format!("{good} "))); // trailing space
    }

    #[test]
    fn scan_finds_embedded_tokens_with_byte_offsets() {
        let a = generate(CanaryKind::Url);
        let b = generate(CanaryKind::Serial);
        let prefix = "intro line\n";
        let text = format!("{prefix}[{a}] middle [{b}] tail [{a}]");
        let hits = scan(&text, &[a.clone(), b.clone()]);
        assert_eq!(hits.len(), 3, "expected the three planted occurrences");

        // Expected offsets, computed from segment lengths (all-ASCII skeleton).
        let o1 = prefix.len() + "[".len(); // after '['
        let o2 = o1 + a.len() + "] middle [".len();
        let o3 = o2 + b.len() + "] tail [".len();
        assert_eq!(hits[0], CanaryHit { token: a.clone(), offset: o1 });
        assert_eq!(hits[1], CanaryHit { token: b.clone(), offset: o2 });
        assert_eq!(hits[2], CanaryHit { token: a.clone(), offset: o3 });

        // Offsets really slice back to the tokens.
        for h in &hits {
            assert_eq!(&text[h.offset..h.offset + h.token.len()], h.token.as_str());
        }
    }

    #[test]
    fn scan_offsets_are_byte_offsets_with_multibyte_prefix() {
        let t = generate(CanaryKind::Marker);
        let prefix = "→→"; // 2 chars, 6 UTF-8 bytes
        let text = format!("{prefix}{t}");
        let hits = scan(&text, std::slice::from_ref(&t));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 6);
        assert_eq!(&text[hits[0].offset..hits[0].offset + t.len()], t.as_str());
    }

    #[test]
    fn scan_reports_no_false_positives_and_dedupes_input() {
        let t = generate(CanaryKind::Url);
        assert!(scan("nothing to see", &[]).is_empty());
        assert!(scan("nothing to see", &[t.clone()]).is_empty());
        assert!(scan("abc", &[String::new()]).is_empty()); // empty canary ignored

        // Same canary listed twice must not double-report.
        let text = format!("{t} x {t}");
        let hits = scan(&text, &[t.clone(), t.clone()]);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].offset < hits[1].offset);
    }

    #[test]
    fn embed_keeps_valid_json_and_inserts_canary() {
        let t = generate(CanaryKind::Marker);
        let json = r#"{"source":"example","nested":{"a":[1,2,3]},"count":2}"#;
        let out = embed_manifest_raw(json, &t);
        let v: serde_json::Value =
            serde_json::from_str(&out).expect("embed must keep valid JSON");
        assert_eq!(v["canary"], serde_json::Value::String(t.clone()));
        assert_eq!(v["source"], "example");
        assert_eq!(v["nested"]["a"][2], 3);
        assert_eq!(v["count"], 2);
    }

    #[test]
    fn embed_overwrites_existing_canary_field() {
        let t = generate(CanaryKind::Serial);
        let out = embed_manifest_raw(r#"{"canary":"TLW-URL-oldoldoldoldold-0000"}"#, &t);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["canary"], serde_json::Value::String(t));
    }

    #[test]
    fn embed_returns_input_unchanged_when_unsafe_to_edit() {
        let t = generate(CanaryKind::Url);
        for input in ["not json", "[1,2,3]", "42", r#""a string""#, "", "{broken"] {
            assert_eq!(
                embed_manifest_raw(input, &t),
                input,
                "unsafe input must pass through unchanged: {input:?}"
            );
        }
    }

    #[test]
    fn embedded_canary_is_scannable_after_serialization() {
        let t = generate(CanaryKind::Url);
        let doc = embed_manifest_raw(r#"{"a":1}"#, &t);
        let hits = scan(&doc, std::slice::from_ref(&t));
        assert_eq!(hits.len(), 1);
        assert_eq!(&doc[hits[0].offset..hits[0].offset + t.len()], t.as_str());
    }

    // ── R-6.10: canary scoping to declared sinks ────────────────────────────

    /// A scope with exactly one declared sink: `manifest.public`.
    fn manifest_scope() -> SinkScope {
        let mut scope = SinkScope::new();
        scope
            .declare(DeclaredSink::new("manifest.public", CanarySinkKind::Manifest))
            .expect("first declaration must succeed");
        scope
    }

    #[test]
    fn declared_sink_receives_the_canary() {
        // (a) positive direction: a declared sink accepts the canary, and
        // the planted token is live (scannable).
        let scope = manifest_scope();
        let t = generate(CanaryKind::Marker);
        let out = emit_manifest(&scope, "manifest.public", r#"{"a":1}"#, &t)
            .expect("declared sink must accept the canary");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["canary"], serde_json::Value::String(t.clone()));
        assert_eq!(v["a"], 1);
        assert_eq!(scan(&out, std::slice::from_ref(&t)).len(), 1);
    }

    #[test]
    fn undeclared_sink_is_refused_and_emits_nothing() {
        // (b) negative direction: a sink that was never declared can never
        // receive the canary — no global injection, no fallback write.
        let scope = manifest_scope();
        let t = generate(CanaryKind::Marker);
        let err = emit_manifest(&scope, "log.rotated", r#"{"a":1}"#, &t)
            .expect_err("undeclared sink must be refused");
        assert_eq!(
            err,
            EmissionRefused::UndeclaredSink {
                sink: "log.rotated".to_string(),
                declared: vec!["manifest.public".to_string()],
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("log.rotated"), "{msg}");
        assert!(msg.contains("manifest.public"), "{msg}");

        // Refusal is per-sink, not a scope lockout: the declared sibling
        // still accepts the same token.
        assert!(emit_manifest(&scope, "manifest.public", r#"{"a":1}"#, &t).is_ok());
    }

    #[test]
    fn empty_scope_refuses_every_sink_no_global_injection() {
        // Explicit opt-in: with nothing declared, nothing is emittable.
        let scope = SinkScope::new();
        assert!(scope.declared().is_empty());
        for sink in ["manifest.public", "log.rotated", "ledger.audit", "tool.shell"] {
            let t = generate(CanaryKind::Url);
            let err = emit_manifest(&scope, sink, r#"{"a":1}"#, &t)
                .expect_err("an undeclared sink must be refused");
            assert!(matches!(err, EmissionRefused::UndeclaredSink { .. }));
        }
    }

    #[test]
    fn declare_is_idempotent_and_kind_conflicts_are_refused() {
        let mut scope = SinkScope::new();
        let sink = DeclaredSink::new("export.sqlite", CanarySinkKind::Export);
        scope.declare(sink.clone()).unwrap();
        scope.declare(sink.clone()).unwrap(); // identical: no-op
        assert_eq!(scope.declared(), std::slice::from_ref(&sink));

        let conflict = scope
            .declare(DeclaredSink::new("export.sqlite", CanarySinkKind::Log))
            .expect_err("same id with a different kind must be refused");
        match conflict {
            DeclareConflict::KindConflict {
                id,
                existing,
                attempted,
            } => {
                assert_eq!(id, "export.sqlite");
                assert_eq!(existing, CanarySinkKind::Export);
                assert_eq!(attempted, CanarySinkKind::Log);
            }
        }
        // The refused conflict left the original declaration untouched.
        assert_eq!(
            scope.sink("export.sqlite").map(|s| s.kind),
            Some(CanarySinkKind::Export)
        );
    }

    #[test]
    fn invalid_canary_is_refused_at_emission_time() {
        // A checksum-corrupt token would never fire in
        // `canary_monitor::sweep`; planting it would be a silently dead
        // tripwire, so emission refuses it outright.
        let scope = manifest_scope();
        let mut bad = generate(CanaryKind::Marker);
        let flip = if bad.ends_with('0') { '1' } else { '0' };
        bad.pop();
        bad.push(flip);
        assert!(!is_valid(&bad), "fixture must be invalid");
        let err = emit_manifest(&scope, "manifest.public", "{}", &bad)
            .expect_err("invalid canary must be refused");
        assert_eq!(err, EmissionRefused::InvalidCanary { canary: bad });
    }

    #[test]
    fn ledger_is_a_declared_sink_exempt_from_scanning() {
        // R-6.10: "ledger exempt as a declared sink".
        assert!(CanarySinkKind::Ledger.is_scan_exempt());
        for kind in [
            CanarySinkKind::Manifest,
            CanarySinkKind::Export,
            CanarySinkKind::Url,
            CanarySinkKind::Log,
            CanarySinkKind::ToolCall,
        ] {
            assert!(!kind.is_scan_exempt(), "{kind} must not be scan-exempt");
        }

        // Scan-exemption is not declaration-exemption: the ledger must still
        // be declared before anything can be emitted to it.
        let mut scope = SinkScope::new();
        let t = generate(CanaryKind::Serial);
        assert!(emit_manifest(&scope, "ledger.audit", "{}", &t).is_err());
        scope
            .declare(DeclaredSink::new("ledger.audit", CanarySinkKind::Ledger))
            .unwrap();
        assert!(emit_manifest(&scope, "ledger.audit", "{}", &t).is_ok());
    }

    #[test]
    fn sink_scope_serde_roundtrip() {
        let scope = manifest_scope();
        let json = serde_json::to_string(&scope).unwrap();
        let back: SinkScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, scope);
        assert!(back.is_declared("manifest.public"));
        assert_eq!(scope.declared().len(), 1);
    }
}
