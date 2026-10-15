//! CERT-In incident report generator (row #179).
//!
//! India's CERT-In Directions (28 Apr 2022) require the specified incident
//! classes to be reported **within 6 hours** of noticing. This module turns a
//! local incident draft plus the operator's own ledger events into a
//! submission-ready payload — the operator reviews and files it; nothing is
//! transmitted (spec `agent-09-geopolitics.md:48,90`, acceptance
//! `final/priority-matrix.md:185`).
//!
//! Properties the tests pin:
//! - **Redacted before rendering.** Any ledger field whose key names a secret
//!   (`token`, `password`, `authorization`, …) is replaced with `[REDACTED]`
//!   and counted; the count rides in the report so the operator can see that
//!   redaction happened rather than trusting it.
//! - **Evidence-linked.** Ledger events are folded into a chain digest
//!   (each event's canonical JSON digested against the previous digest) so an
//!   edited ledger no longer matches the report.
//! - **Digest + optional signature.** The report carries a sha256 over its
//!   canonical bytes; with `--key` (Ed25519 seed, 32 raw bytes or 64 hex
//!   chars — same convention as `tallow config bundle`) it is also signed.
//! - **Fail-closed validation.** Missing contact e-mail, detection after
//!   awareness, malformed ledger lines (with line numbers) are refusals, not
//!   warnings: a wrong incident report is worse than none.

use serde::{Deserialize, Serialize};
use std::path::Path;

use super::clocks::{self, ClockInput, ClockTable, IncidentKind, Jurisdiction, LegStatus, Regime};
use super::{iso8601_utc, push_field, sha256_hex};

/// Report schema id.
pub const CERTIN_SCHEMA: &str = "tallow.compliance.certin.v1";
/// Signature algorithm tag used in [`SignatureBlock`].
pub const SIG_ALG_ED25519: &str = "ed25519";

/// CERT-In Annex-I incident classes (curated subset of the Directions'
/// Annex-I list; `Other` covers the remainder with a written description).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertInClass {
    /// Unauthorised access to IT systems/data.
    UnauthorisedAccess,
    /// Data breach.
    DataBreach,
    /// Ransomware.
    Ransomware,
    /// Malicious code attacks (virus/worm/trojan/bot/cryptominer/spyware).
    MaliciousCode,
    /// DoS/DDoS attacks.
    Ddos,
    /// Identity theft, spoofing and phishing.
    IdentityTheftPhishing,
    /// Website intrusion / defacement or unauthorised changes.
    WebsiteIntrusionDefacement,
    /// Attacks on servers such as database, mail and DNS.
    ServerAttack,
    /// Anything else in the Annex-I list — the description carries the detail.
    Other,
}

impl CertInClass {
    /// Stable lowercase spelling (CLI/JSON form).
    pub fn as_str(&self) -> &'static str {
        match self {
            CertInClass::UnauthorisedAccess => "unauthorised_access",
            CertInClass::DataBreach => "data_breach",
            CertInClass::Ransomware => "ransomware",
            CertInClass::MaliciousCode => "malicious_code",
            CertInClass::Ddos => "ddos",
            CertInClass::IdentityTheftPhishing => "identity_theft_phishing",
            CertInClass::WebsiteIntrusionDefacement => "website_intrusion_defacement",
            CertInClass::ServerAttack => "server_attack",
            CertInClass::Other => "other",
        }
    }

    /// Annex-I wording quoted in the report (the operator submits this row).
    pub fn annex_label(&self) -> &'static str {
        match self {
            CertInClass::UnauthorisedAccess => "Unauthorised access to IT systems / data",
            CertInClass::DataBreach => "Data breach",
            CertInClass::Ransomware => "Ransomware",
            CertInClass::MaliciousCode => {
                "Malicious code attacks (virus / worm / trojan / bot / cryptominer / spyware)"
            }
            CertInClass::Ddos => "Denial of Service (DoS) / Distributed DoS (DDoS) attacks",
            CertInClass::IdentityTheftPhishing => "Identity theft, spoofing and phishing attacks",
            CertInClass::WebsiteIntrusionDefacement => {
                "Website intrusion / defacement or unauthorised changes"
            }
            CertInClass::ServerAttack => "Attacks on servers such as database, mail and DNS",
            CertInClass::Other => "Other (as described in the incident description)",
        }
    }

    /// Parse the canonical spelling; unknown spellings are refused.
    pub fn parse(s: &str) -> Result<Self, IncidentError> {
        match s {
            "unauthorised_access" => Ok(CertInClass::UnauthorisedAccess),
            "data_breach" => Ok(CertInClass::DataBreach),
            "ransomware" => Ok(CertInClass::Ransomware),
            "malicious_code" => Ok(CertInClass::MaliciousCode),
            "ddos" => Ok(CertInClass::Ddos),
            "identity_theft_phishing" => Ok(CertInClass::IdentityTheftPhishing),
            "website_intrusion_defacement" => Ok(CertInClass::WebsiteIntrusionDefacement),
            "server_attack" => Ok(CertInClass::ServerAttack),
            "other" => Ok(CertInClass::Other),
            other => Err(IncidentError::UnknownClass(other.to_string())),
        }
    }
}

/// One affected system row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedSystem {
    /// Hostname or asset identifier.
    pub name: String,
    /// Free-form kind (`server`, `workstation`, `network-device`, …).
    pub kind: String,
    /// Addresses the operator chooses to disclose (IPs, public URLs).
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// Coordinates the CERT-In acknowledgement goes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorContact {
    /// Contact person name.
    pub name: String,
    /// Organisation legal name.
    pub organisation: String,
    /// E-mail — the field CERT-In actually acknowledges on.
    pub email: String,
    /// Telephone (optional).
    #[serde(default)]
    pub phone: Option<String>,
}

/// Operator-supplied incident draft (the `--spec` file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDraft {
    /// Operator-assigned incident id (also used as the file stem).
    pub incident_id: String,
    /// Annex-I class.
    pub class: CertInClass,
    /// When the incident was noticed (Unix seconds, UTC). Starts the 6 h clock.
    pub awareness_at: i64,
    /// When it was technically detected, if distinct and known.
    #[serde(default)]
    pub detection_at: Option<i64>,
    /// What happened (the operator's own words; redaction applies to ledger
    /// fields, not to this text — the operator owns it).
    pub description: String,
    /// Affected systems.
    #[serde(default)]
    pub affected_systems: Vec<AffectedSystem>,
    /// Mitigation / remedial actions taken so far.
    #[serde(default)]
    pub mitigation: Vec<String>,
    /// Contact block.
    pub contact: OperatorContact,
}

/// One parsed + redacted ledger event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LedgerEvent {
    /// 1-based line number in the ledger file.
    pub line_no: usize,
    /// Event timestamp (Unix seconds).
    pub ts: i64,
    /// Event kind (free-form, operator's ledger vocabulary).
    pub kind: String,
    /// The full redacted event object.
    pub fields: serde_json::Value,
    /// How many values were replaced with `[REDACTED]` in this event.
    pub redactions: usize,
}

/// Evidence summary carried by the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceSummary {
    /// Ledger file the events came from (`None` = no ledger supplied).
    pub source: Option<String>,
    /// Number of events folded into the chain.
    pub events: usize,
    /// Number of redacted values across all events.
    pub redactions: usize,
    /// Chain digest over the events (see [`chain_digest`]).
    pub chain_sha256: String,
}

/// A detached Ed25519 signature over the report's canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureBlock {
    /// Algorithm tag ([`SIG_ALG_ED25519`]).
    pub alg: &'static str,
    /// Verifying key, lowercase hex (32 bytes).
    pub public_key_hex: String,
    /// Signature, lowercase hex (64 bytes).
    pub signature_hex: String,
    /// Digest the signature covers (the report digest).
    pub signed_digest_sha256: String,
}

/// The generated report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertInReport {
    /// Schema id.
    pub schema: &'static str,
    /// The operator's draft, verbatim.
    pub incident: IncidentDraft,
    /// Annex-I wording for the chosen class.
    pub annex_i_class: &'static str,
    /// The 6 h clock (plus any other declared jurisdictions), computed with
    /// the same engine as `compliance clocks`.
    pub clocks: ClockTable,
    /// Ledger evidence summary.
    pub evidence: EvidenceSummary,
    /// sha256 over the canonical bytes.
    pub digest_sha256: String,
    /// Detached signature, when a key was supplied.
    pub signature: Option<SignatureBlock>,
}

/// Value substituted for redacted fields.
pub const REDACTED: &str = "[REDACTED]";

/// Key fragments that mark a ledger value as secret (case-insensitive
/// substring match on the JSON key).
pub const SECRET_KEY_PATTERNS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "cookie",
    "session",
    "private_key",
    "credential",
    "passphrase",
];

/// Typed refusals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentError {
    /// Unknown Annex-I class spelling.
    UnknownClass(String),
    /// A required field is empty.
    Empty { field: &'static str },
    /// Contact e-mail has no `@` — CERT-In cannot acknowledge it.
    ContactEmail(String),
    /// Detection instant precedes awareness.
    DetectionAfterAwareness {
        detection_at: i64,
        awareness_at: i64,
    },
    /// Incident id has characters unsafe for a file stem / submission id.
    UnsafeIncidentId(String),
    /// Ledger line did not parse.
    LedgerLine { line_no: usize, message: String },
    /// Ledger event is missing a required field.
    LedgerField {
        line_no: usize,
        field: &'static str,
        message: String,
    },
    /// Signature key could not be read.
    KeyFile(String),
    /// Clock computation refused the input (propagated).
    Clock(clocks::ClockError),
    /// I/O failure.
    Io(String),
}

impl std::fmt::Display for IncidentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentError::UnknownClass(s) => write!(
                f,
                "unknown CERT-In class {s:?} (expected one of: unauthorised_access, data_breach, \
                 ransomware, malicious_code, ddos, identity_theft_phishing, \
                 website_intrusion_defacement, server_attack, other)"
            ),
            IncidentError::Empty { field } => write!(f, "{field} must not be empty"),
            IncidentError::ContactEmail(e) => write!(
                f,
                "contact e-mail {e:?} is not an address CERT-In can acknowledge (no `@`)"
            ),
            IncidentError::DetectionAfterAwareness {
                detection_at,
                awareness_at,
            } => write!(
                f,
                "detection {} UTC is after awareness {} UTC",
                iso8601_utc(*detection_at),
                iso8601_utc(*awareness_at)
            ),
            IncidentError::UnsafeIncidentId(id) => write!(
                f,
                "incident id {id:?} must be non-empty and contain only [A-Za-z0-9._-]"
            ),
            IncidentError::LedgerLine { line_no, message } => {
                write!(f, "ledger line {line_no}: {message}")
            }
            IncidentError::LedgerField {
                line_no,
                field,
                message,
            } => {
                write!(f, "ledger line {line_no}: field {field}: {message}")
            }
            IncidentError::KeyFile(m) => write!(f, "signing key: {m}"),
            IncidentError::Clock(e) => write!(f, "clock computation refused: {e}"),
            IncidentError::Io(m) => write!(f, "io: {m}"),
        }
    }
}

impl std::error::Error for IncidentError {}

impl From<clocks::ClockError> for IncidentError {
    fn from(e: clocks::ClockError) -> Self {
        IncidentError::Clock(e)
    }
}

fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEY_PATTERNS.iter().any(|p| k.contains(p))
}

/// Recursively replace secret-looking values with [`REDACTED`], returning the
/// number of replacements. Objects/arrays keep their shape; only the values
/// of matching keys (and of matching keys nested in arrays) are dropped.
fn redact_value(value: &mut serde_json::Value, count: &mut usize, key_is_secret: bool) {
    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let secret = key_is_secret || is_secret_key(&k);
                if let Some(v) = map.get_mut(&k) {
                    match v {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            redact_value(v, count, secret)
                        }
                        _ if secret => {
                            *v = serde_json::Value::String(REDACTED.to_string());
                            *count += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item, count, key_is_secret);
            }
        }
        _ if key_is_secret => {
            *value = serde_json::Value::String(REDACTED.to_string());
            *count += 1;
        }
        _ => {}
    }
}

/// Parse a JSONL ledger: one JSON object per line, requiring `ts`
/// (unix seconds or an accepted timestamp string) and `kind` (string).
/// Blank lines are skipped; every other line must parse — a partially-read
/// ledger is never silently accepted.
pub fn parse_ledger_jsonl(text: &str) -> Result<Vec<LedgerEvent>, IncidentError> {
    let mut events = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| IncidentError::LedgerLine {
                line_no,
                message: e.to_string(),
            })?;
        let object = value.as_object().ok_or_else(|| IncidentError::LedgerLine {
            line_no,
            message: "expected a JSON object".to_string(),
        })?;
        // `ts`: number (unix seconds) or accepted timestamp string.
        let ts = match object.get("ts") {
            Some(serde_json::Value::Number(n)) => {
                n.as_i64().ok_or_else(|| IncidentError::LedgerField {
                    line_no,
                    field: "ts",
                    message: "expected integer unix seconds".to_string(),
                })?
            }
            Some(serde_json::Value::String(s)) => {
                super::parse_timestamp(s).map_err(|m| IncidentError::LedgerField {
                    line_no,
                    field: "ts",
                    message: m,
                })?
            }
            _ => {
                return Err(IncidentError::LedgerField {
                    line_no,
                    field: "ts",
                    message: "missing (unix seconds or `YYYY-MM-DDTHH:MM:SSZ`)".to_string(),
                })
            }
        };
        if ts <= 0 {
            return Err(IncidentError::LedgerField {
                line_no,
                field: "ts",
                message: "must be a positive unix timestamp".to_string(),
            });
        }
        let kind = object
            .get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IncidentError::LedgerField {
                line_no,
                field: "kind",
                message: "missing (string)".to_string(),
            })?
            .to_string();
        if kind.is_empty() {
            return Err(IncidentError::LedgerField {
                line_no,
                field: "kind",
                message: "must not be empty".to_string(),
            });
        }
        let mut redactions = 0usize;
        // Start at the top level: keys inside are matched individually, so
        // pass `false` and let the recursion decide per key.
        redact_value(&mut value, &mut redactions, false);
        events.push(LedgerEvent {
            line_no,
            ts,
            kind,
            fields: value,
            redactions,
        });
    }
    Ok(events)
}

/// Fold the events into a chain digest: `h_0 = sha256(schema)`;
/// `h_i = sha256(h_{i-1} "|" ts "|" kind "|" canonical_json)`.
///
/// Local tamper-evidence only — it proves the report was built from *these*
/// events; it is not a signature and claims no external anchoring.
pub fn chain_digest(events: &[LedgerEvent]) -> String {
    let mut h = sha256_hex(CERTIN_SCHEMA.as_bytes());
    for e in events {
        let json = serde_json::to_string(&e.fields).unwrap_or_else(|_| "{}".to_string());
        let mut buf = String::new();
        push_field(&mut buf, &h);
        push_field(&mut buf, &e.ts.to_string());
        push_field(&mut buf, &e.kind);
        push_field(&mut buf, &json);
        h = sha256_hex(buf.as_bytes());
    }
    h
}

fn validate_incident_id(id: &str) -> Result<(), IncidentError> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(IncidentError::UnsafeIncidentId(id.to_string()));
    }
    Ok(())
}

fn validate_draft(draft: &IncidentDraft) -> Result<(), IncidentError> {
    validate_incident_id(&draft.incident_id)?;
    if draft.description.trim().is_empty() {
        return Err(IncidentError::Empty {
            field: "description",
        });
    }
    if draft.contact.name.trim().is_empty() {
        return Err(IncidentError::Empty {
            field: "contact.name",
        });
    }
    if draft.contact.organisation.trim().is_empty() {
        return Err(IncidentError::Empty {
            field: "contact.organisation",
        });
    }
    if !draft.contact.email.contains('@') || draft.contact.email.trim().is_empty() {
        return Err(IncidentError::ContactEmail(draft.contact.email.clone()));
    }
    if let Some(d) = draft.detection_at {
        if d > draft.awareness_at {
            return Err(IncidentError::DetectionAfterAwareness {
                detection_at: d,
                awareness_at: draft.awareness_at,
            });
        }
    }
    Ok(())
}

/// Load an Ed25519 signing seed from a file: 32 raw bytes or 64 hex chars
/// (with optional whitespace) — the same convention as
/// `tallow config bundle keygen`.
pub fn load_signing_seed(path: &Path) -> Result<[u8; 32], IncidentError> {
    let bytes = std::fs::read(path)
        .map_err(|e| IncidentError::KeyFile(format!("{}: {e}", path.display())))?;
    if bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(seed);
    }
    let text = String::from_utf8(bytes)
        .map_err(|e| IncidentError::KeyFile(format!("{}: not utf-8: {e}", path.display())))?;
    let hex = text.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(IncidentError::KeyFile(format!(
            "{}: expected 32 raw bytes or 64 hex chars",
            path.display()
        )));
    }
    let mut seed = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).unwrap_or("");
        seed[i] = u8::from_str_radix(s, 16)
            .map_err(|e| IncidentError::KeyFile(format!("{}: bad hex: {e}", path.display())))?;
    }
    Ok(seed)
}

/// Everything the report digest covers, in a fixed order, length-prefixed
/// (no JSON map ordering dependence, no concatenation ambiguity).
pub fn canonical_bytes(
    draft: &IncidentDraft,
    evidence: &EvidenceSummary,
    clocks: &ClockTable,
) -> String {
    let mut buf = String::new();
    push_field(&mut buf, CERTIN_SCHEMA);
    push_field(&mut buf, &draft.incident_id);
    push_field(&mut buf, draft.class.as_str());
    push_field(&mut buf, draft.class.annex_label());
    push_field(&mut buf, &draft.awareness_at.to_string());
    push_field(
        &mut buf,
        &draft
            .detection_at
            .map(|t| t.to_string())
            .unwrap_or_default(),
    );
    push_field(&mut buf, &draft.description);
    for s in &draft.affected_systems {
        push_field(&mut buf, &s.name);
        push_field(&mut buf, &s.kind);
        for a in &s.addresses {
            push_field(&mut buf, a);
        }
    }
    for m in &draft.mitigation {
        push_field(&mut buf, m);
    }
    push_field(&mut buf, &draft.contact.name);
    push_field(&mut buf, &draft.contact.organisation);
    push_field(&mut buf, &draft.contact.email);
    push_field(&mut buf, draft.contact.phone.as_deref().unwrap_or_default());
    push_field(&mut buf, &evidence.source.clone().unwrap_or_default());
    push_field(&mut buf, &evidence.events.to_string());
    push_field(&mut buf, &evidence.redactions.to_string());
    push_field(&mut buf, &evidence.chain_sha256);
    push_field(&mut buf, &clocks.digest());
    buf
}

/// Build the CERT-In report.
///
/// `now` is the evaluation instant; `jurisdictions` declares which regimes
/// the clocks cover (`[Jurisdiction::India]` gives the 6 h leg alone).
pub fn build(
    draft: &IncidentDraft,
    ledger_path: Option<&Path>,
    jurisdictions: &[Jurisdiction],
    now: i64,
) -> Result<CertInReport, IncidentError> {
    validate_draft(draft)?;
    let (events, source) = match ledger_path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| IncidentError::Io(format!("{}: {e}", path.display())))?;
            (parse_ledger_jsonl(&text)?, Some(path.display().to_string()))
        }
        None => (Vec::new(), None),
    };
    let evidence = EvidenceSummary {
        source,
        events: events.len(),
        redactions: events.iter().map(|e| e.redactions).sum(),
        chain_sha256: chain_digest(&events),
    };
    let clocks = clocks::compute(
        &ClockInput {
            awareness_at: draft.awareness_at,
            kind: IncidentKind::SevereIncident,
            jurisdictions: jurisdictions.to_vec(),
            filed: Vec::new(),
        },
        now,
    )?;
    let digest_sha256 = sha256_hex(canonical_bytes(draft, &evidence, &clocks).as_bytes());
    Ok(CertInReport {
        schema: CERTIN_SCHEMA,
        incident: draft.clone(),
        annex_i_class: draft.class.annex_label(),
        clocks,
        evidence,
        digest_sha256,
        signature: None,
    })
}

/// Sign the report's digest with an Ed25519 seed.
impl CertInReport {
    /// Attach a detached signature over the report's canonical bytes.
    pub fn sign_with_seed(
        &mut self,
        seed: [u8; 32],
        draft: &IncidentDraft,
    ) -> Result<(), IncidentError> {
        let signer = tallow_crypto::sig::ed25519::Ed25519Signer::from_seed(seed);
        let bytes = canonical_bytes(draft, &self.evidence, &self.clocks);
        let sig = signer.sign(bytes.as_bytes());
        let pk = signer.verifying_key_bytes();
        self.signature = Some(SignatureBlock {
            alg: SIG_ALG_ED25519,
            public_key_hex: to_hex(&pk),
            signature_hex: to_hex(&sig),
            signed_digest_sha256: self.digest_sha256.clone(),
        });
        Ok(())
    }

    /// The CERT-In deadline (India leg), when India is a declared jurisdiction.
    pub fn cert_in_deadline(&self) -> Option<&super::clocks::Deadline> {
        self.clocks
            .deadlines
            .iter()
            .find(|d| d.regime == Regime::CertIn)
    }

    /// Does the embedded clock show the 6 h leg still outstanding?
    pub fn report_outstanding(&self) -> bool {
        self.cert_in_deadline()
            .map(|d| {
                matches!(
                    d.status,
                    LegStatus::Open | LegStatus::DueSoon | LegStatus::Overdue
                )
            })
            .unwrap_or(false)
    }

    /// JSON rendering (`tallow compliance incident --format json`).
    pub fn to_json(&self) -> serde_json::Value {
        let cert_in = self.cert_in_deadline();
        serde_json::json!({
            "schema": CERTIN_SCHEMA,
            "incident_id": self.incident.incident_id,
            "class": self.incident.class.as_str(),
            "annex_i_class": self.annex_i_class,
            "awareness_at": self.incident.awareness_at,
            "awareness_at_utc": iso8601_utc(self.incident.awareness_at),
            "detection_at": self.incident.detection_at,
            "detection_at_utc": self.incident.detection_at.map(iso8601_utc),
            "description": self.incident.description,
            "affected_systems": self.incident.affected_systems.iter().map(|s| serde_json::json!({
                "name": s.name,
                "kind": s.kind,
                "addresses": s.addresses,
            })).collect::<Vec<_>>(),
            "mitigation": self.incident.mitigation,
            "contact": {
                "name": self.incident.contact.name,
                "organisation": self.incident.contact.organisation,
                "email": self.incident.contact.email,
                "phone": self.incident.contact.phone,
            },
            "cert_in_deadline": cert_in.map(|d| serde_json::json!({
                "term_secs": d.term_secs,
                "term": clocks::human_term(d.term_secs),
                "due_at": d.due_at,
                "due_at_utc": iso8601_utc(d.due_at),
                "status": d.status.as_str(),
                "remaining_secs": d.remaining_secs,
            })),
            "clocks": self.clocks.to_json(),
            "evidence": {
                "source": self.evidence.source,
                "events": self.evidence.events,
                "redactions": self.evidence.redactions,
                "chain_sha256": self.evidence.chain_sha256,
            },
            "digest_sha256": self.digest_sha256,
            "signature": self.signature,
            "submission": clocks::submission_posture(),
            "redaction_policy": {
                "patterns": SECRET_KEY_PATTERNS,
                "replacement": REDACTED,
            },
        })
    }

    /// Text rendering (the human-review renderer).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "tallow compliance incident — {} ({})\n",
            self.incident.incident_id,
            self.incident.class.as_str()
        ));
        out.push_str("══════════════════════════════════════════════════════════════\n");
        out.push_str(&format!(
            "  CERT-In Annex-I class: {}\n",
            self.annex_i_class
        ));
        out.push_str(&format!(
            "  Noticed:   {} UTC\n",
            iso8601_utc(self.incident.awareness_at)
        ));
        if let Some(d) = self.incident.detection_at {
            out.push_str(&format!("  Detected:  {} UTC\n", iso8601_utc(d)));
        }
        match self.cert_in_deadline() {
            Some(d) => out.push_str(&format!(
                "  6h deadline: {} UTC [{}] — {}\n",
                iso8601_utc(d.due_at),
                d.status.as_str(),
                clocks::human_delta(d.remaining_secs)
            )),
            None => out.push_str("  6h deadline: n/a (India not declared)\n"),
        }
        out.push_str(&format!("  Description: {}\n", self.incident.description));
        out.push_str(&format!(
            "  Affected systems: {}\n",
            self.incident.affected_systems.len()
        ));
        out.push_str(&format!(
            "  Mitigation actions: {}\n",
            self.incident.mitigation.len()
        ));
        out.push_str(&format!(
            "  Contact: {} · {} <{}>\n",
            self.incident.contact.name,
            self.incident.contact.organisation,
            self.incident.contact.email
        ));
        out.push_str(&format!(
            "  Evidence: {} event(s) from {} · redactions {} · chain sha256:{}\n",
            self.evidence.events,
            self.evidence.source.as_deref().unwrap_or("(no ledger)"),
            self.evidence.redactions,
            self.evidence.chain_sha256
        ));
        out.push_str(&format!("  digest sha256:{}\n", self.digest_sha256));
        match &self.signature {
            Some(s) => out.push_str(&format!("  signature: {} by {}\n", s.alg, s.public_key_hex)),
            None => out.push_str("  signature: none (pass --key to sign with an Ed25519 seed)\n"),
        }
        out.push_str(
            "\n  No automatic submission: this payload was generated locally and is\n  \
             ready for operator review and filing. Nothing was transmitted\n  \
             (outbound_network_calls = 0).\n",
        );
        out
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::parse_timestamp;

    fn t0() -> i64 {
        parse_timestamp("2026-09-14T00:00:00Z").unwrap()
    }

    fn draft() -> IncidentDraft {
        IncidentDraft {
            incident_id: "INC-2026-001".to_string(),
            class: CertInClass::DataBreach,
            awareness_at: t0(),
            detection_at: Some(t0() - 600),
            description: "Unauthorised read of a customer export bucket".to_string(),
            affected_systems: vec![AffectedSystem {
                name: "s3-export".to_string(),
                kind: "object-storage".to_string(),
                addresses: vec!["198.51.100.7".to_string()],
            }],
            mitigation: vec!["Rotated the exposed credential".to_string()],
            contact: OperatorContact {
                name: "A. Operator".to_string(),
                organisation: "Example GmbH".to_string(),
                email: "security@example.invalid".to_string(),
                phone: Some("+00 000 000".to_string()),
            },
        }
    }

    const LEDGER: &str = r#"{"ts": 1757800000, "kind": "auth.failed_burst", "actor": "svc-export", "detail": "12 attempts", "api_key": "AKIAEXAMPLEKEY", "nested": {"session_id": "s3cr3t-session"}}
{"ts": "2026-09-13T23:50:00Z", "kind": "alert.raised", "severity": "high", "token": "ghp_example"}
{"ts": 1757810000, "kind": "containment.applied", "actor": "ops", "detail": "credential rotated"}
"#;

    #[test]
    fn six_hour_deadline_is_embedded_from_awareness() {
        let report = build(&draft(), None, &[Jurisdiction::India], t0() + 3600).unwrap();
        let d = report.cert_in_deadline().expect("cert-in leg");
        assert_eq!(d.term_secs, 6 * 3600);
        assert_eq!(d.due_at, t0() + 6 * 3600);
        // 1 h in: 5 h remain, outside the 90 m due-soon window → open.
        assert_eq!(d.status, LegStatus::Open);
        assert!(report.report_outstanding());
    }

    #[test]
    fn report_status_tracks_the_clock() {
        // 1 h in: 5 h left, outside the 90 m due-soon window → open.
        let early = build(&draft(), None, &[Jurisdiction::India], t0() + 3600).unwrap();
        assert_eq!(early.cert_in_deadline().unwrap().status, LegStatus::Open);
        // 6 h + 1 s: overdue, and the report says so.
        let late = build(&draft(), None, &[Jurisdiction::India], t0() + 6 * 3600 + 1).unwrap();
        assert_eq!(late.cert_in_deadline().unwrap().status, LegStatus::Overdue);
        assert!(late.report_outstanding());
        // No India declared → no 6 h leg in the payload.
        let eu = build(&draft(), None, &[Jurisdiction::Eu], t0() + 3600).unwrap();
        assert!(eu.cert_in_deadline().is_none());
        assert!(!eu.report_outstanding());
    }

    #[test]
    fn ledger_parses_and_redacts_secret_looking_fields() {
        let events = parse_ledger_jsonl(LEDGER).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].line_no, 1);
        assert_eq!(events[1].ts, t0() - 600); // timestamp string form accepted
        assert_eq!(events[1].kind, "alert.raised");
        // api_key + nested session_id on line 1, token on line 2.
        assert_eq!(events[0].redactions, 2);
        assert_eq!(events[1].redactions, 1);
        assert_eq!(events[2].redactions, 0);
        let line1 = events[0].fields.to_string();
        assert!(!line1.contains("AKIAEXAMPLEKEY"), "{line1}");
        assert!(!line1.contains("s3cr3t-session"), "{line1}");
        assert!(line1.contains(REDACTED));
        // Non-secret fields survive verbatim.
        assert_eq!(events[0].fields["detail"], "12 attempts");
        assert_eq!(events[2].fields["actor"], "ops");
        assert!(!events[1].fields.to_string().contains("ghp_example"));
    }

    #[test]
    fn malformed_ledger_lines_are_refused_with_line_numbers() {
        let err = parse_ledger_jsonl("{\"ts\": 1, \"kind\": \"a\"}\nnot json\n").unwrap_err();
        match err {
            IncidentError::LedgerLine { line_no, .. } => assert_eq!(line_no, 2),
            other => panic!("expected LedgerLine, got {other:?}"),
        }
        let err = parse_ledger_jsonl("{\"kind\": \"a\"}\n").unwrap_err();
        match err {
            IncidentError::LedgerField { line_no, field, .. } => {
                assert_eq!((line_no, field), (1, "ts"))
            }
            other => panic!("expected LedgerField, got {other:?}"),
        }
        let err = parse_ledger_jsonl("{\"ts\": 1, \"kind\": \"\"}\n").unwrap_err();
        assert!(matches!(
            err,
            IncidentError::LedgerField { field: "kind", .. }
        ));
    }

    #[test]
    fn chain_digest_is_stable_and_detects_an_edited_event() {
        let events = parse_ledger_jsonl(LEDGER).unwrap();
        let a = chain_digest(&events);
        let b = chain_digest(&parse_ledger_jsonl(LEDGER).unwrap());
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        // Editing one non-secret field changes the chain.
        let mut edited = events.clone();
        edited[2].fields["detail"] = serde_json::json!("credential rotated (backdated)");
        assert_ne!(a, chain_digest(&edited));
        // Empty ledger still has the schema-seeded digest.
        assert_eq!(chain_digest(&[]).len(), 64);
    }

    #[test]
    fn report_evidence_summary_counts_events_and_redactions() {
        let dir = std::env::temp_dir().join(format!("tallow-certin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        std::fs::write(&path, LEDGER).unwrap();
        let report = build(&draft(), Some(&path), &[Jurisdiction::India], t0() + 60).unwrap();
        assert_eq!(report.evidence.events, 3);
        assert_eq!(report.evidence.redactions, 3);
        assert_eq!(
            report.evidence.chain_sha256,
            chain_digest(&parse_ledger_jsonl(LEDGER).unwrap())
        );
        assert!(report.evidence.source.unwrap().ends_with("ledger.jsonl"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn draft_validation_refuses_unfiled_ready_errors() {
        let mut bad = draft();
        bad.contact.email = "not-an-email".to_string();
        assert!(matches!(
            build(&bad, None, &[Jurisdiction::India], t0() + 60),
            Err(IncidentError::ContactEmail(_))
        ));

        let mut bad = draft();
        bad.description = "  ".to_string();
        assert!(matches!(
            build(&bad, None, &[Jurisdiction::India], t0() + 60),
            Err(IncidentError::Empty {
                field: "description"
            })
        ));

        let mut bad = draft();
        bad.detection_at = Some(t0() + 1);
        assert!(matches!(
            build(&bad, None, &[Jurisdiction::India], t0() + 3600),
            Err(IncidentError::DetectionAfterAwareness { .. })
        ));

        let mut bad = draft();
        bad.incident_id = "../escape".to_string();
        assert!(matches!(
            build(&bad, None, &[Jurisdiction::India], t0() + 60),
            Err(IncidentError::UnsafeIncidentId(_))
        ));
    }

    #[test]
    fn digest_is_stable_and_recomputed_over_the_canonical_bytes() {
        let a = build(&draft(), None, &[Jurisdiction::India], t0() + 60).unwrap();
        let b = build(&draft(), None, &[Jurisdiction::India], t0() + 60).unwrap();
        assert_eq!(a.digest_sha256, b.digest_sha256);
        let expected = sha256_hex(canonical_bytes(&a.incident, &a.evidence, &a.clocks).as_bytes());
        assert_eq!(a.digest_sha256, expected);
        let mut edited = draft();
        edited.description = "different words".to_string();
        let c = build(&edited, None, &[Jurisdiction::India], t0() + 60).unwrap();
        assert_ne!(a.digest_sha256, c.digest_sha256);
    }

    #[test]
    fn signature_verifies_and_does_not_cover_a_tampered_report() {
        let seed = [7u8; 32];
        let mut report = build(&draft(), None, &[Jurisdiction::India], t0() + 60).unwrap();
        report
            .sign_with_seed(seed, &report.incident.clone())
            .unwrap();
        let sig = report.signature.clone().expect("signature");
        assert_eq!(sig.alg, "ed25519");
        let pk = hex32(&sig.public_key_hex);
        let signature = hex64(&sig.signature_hex);
        let message = canonical_bytes(&report.incident, &report.evidence, &report.clocks);
        tallow_crypto::sig::ed25519::verify(&pk, message.as_bytes(), &signature)
            .expect("signature verifies over the canonical bytes");
        // The signed digest matches the report digest.
        assert_eq!(sig.signed_digest_sha256, report.digest_sha256);

        // Tampering with a field after signing breaks verification.
        let mut tampered = report.incident.clone();
        tampered.description = "attacker edited this".to_string();
        let tampered_bytes = canonical_bytes(&tampered, &report.evidence, &report.clocks);
        assert!(
            tallow_crypto::sig::ed25519::verify(&pk, tampered_bytes.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn json_and_text_renders_carry_the_posture_and_digest() {
        let report = build(&draft(), None, &[Jurisdiction::India], t0() + 3600).unwrap();
        let json = report.to_json();
        assert_eq!(json["schema"], CERTIN_SCHEMA);
        assert_eq!(json["class"], "data_breach");
        assert_eq!(json["cert_in_deadline"]["due_at"], t0() + 6 * 3600);
        assert_eq!(json["cert_in_deadline"]["term"], "6h");
        assert_eq!(json["submission"]["auto_submitted"], false);
        assert_eq!(json["submission"]["outbound_network_calls"], 0);
        assert_eq!(json["redaction_policy"]["replacement"], REDACTED);
        let text = report.render_text();
        assert!(text.contains("No automatic submission"));
        assert!(text.contains("INC-2026-001"));
        assert!(text.contains("6h deadline"));
    }

    #[test]
    fn signing_seed_loader_accepts_both_documented_forms() {
        let dir = std::env::temp_dir().join(format!("tallow-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("raw.key");
        std::fs::write(&raw, [9u8; 32]).unwrap();
        assert_eq!(load_signing_seed(&raw).unwrap(), [9u8; 32]);
        let hex = dir.join("hex.key");
        std::fs::write(&hex, format!("{}\n", "0b".repeat(32))).unwrap();
        assert_eq!(load_signing_seed(&hex).unwrap(), [11u8; 32]);
        let bad = dir.join("bad.key");
        std::fs::write(&bad, "zz").unwrap();
        assert!(matches!(
            load_signing_seed(&bad),
            Err(IncidentError::KeyFile(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn class_spellings_round_trip_and_unknown_ones_are_refused() {
        for class in [
            CertInClass::UnauthorisedAccess,
            CertInClass::DataBreach,
            CertInClass::Ransomware,
            CertInClass::MaliciousCode,
            CertInClass::Ddos,
            CertInClass::IdentityTheftPhishing,
            CertInClass::WebsiteIntrusionDefacement,
            CertInClass::ServerAttack,
            CertInClass::Other,
        ] {
            assert_eq!(CertInClass::parse(class.as_str()), Ok(class));
            assert!(!class.annex_label().is_empty());
        }
        assert_eq!(
            CertInClass::parse("phishing"),
            Err(IncidentError::UnknownClass("phishing".to_string()))
        );
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    fn hex64(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }
}
