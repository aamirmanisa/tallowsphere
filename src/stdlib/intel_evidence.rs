//! Standard library: `tallow.intel` — evidence that cannot leave on a dead
//! grant (N38), budget refusals that carry their own receipt (N39), and
//! redaction with declassification as a recorded act (N40).
//!
//! # Why this module exists
//!
//! A collected record is only evidence if the authority that permitted its
//! collection is still in force at the moment it moves. Two things can go
//! wrong that a log line will not catch:
//!
//! 1. **A grant that is no longer live.** `scope.grant(Net)` mints an opaque
//!    `Grant<Net>` value, and the scope register it consults carries an
//!    optional `expires_at`. Re-checking the register at *export* time — not
//!    only at collection time — is the difference between "authorized once"
//!    and "authorized now". [`export_records`] refuses a record whose target
//!    is no longer covered, naming the requirement that failed.
//! 2. **A budget refusal nobody can show.** `budget:unbounded` is not a
//!    refusal: when no limit is supplied the answer is "allowed, no limit",
//!    stated as such. When a supplied limit is crossed, the refusal is a
//!    [`BudgetReceipt`] — a serialisable value, not a log line — naming the
//!    kind, the limit the *caller* supplied, the consumer, the moment (unix ms
//!    plus a monotonic delta) and what was attempted.
//!
//! # Refusal codes (stable, machine-readable)
//!
//! | code | ground |
//! |---|---|
//! | `export:no-grant` | no live `Grant<Net>` was presented, or it names another effect, or the record carries no grant id |
//! | `export:grant-expired` | the register entry covering the target lapsed (`scope:expired`) |
//! | `export:scope-not-listed` | the register refused the target on another ground (the `scope:*` code travels in `scope_code`) |
//! | `export:no-target` | the record names no target; absence is a refusal, not a pass |
//!
//! | code | ground |
//! |---|---|
//! | `redact:no-reason` | a declassification names a field but gives no reason |
//! | `redact:no-consumer` | a declassification names a field but no consumer of the released value |
//! | `redact:unknown-field` | a declassification names a field (or dotted path) the record does not have, or names none at all |
//! | `redact:duplicate-field` | two declassifications name the same field; one receipt per field, or a reader cannot tell whose authority applied |
//!
//! `redact:declassified` is the *receipt* code, not a refusal: it marks a
//! secret that was released on a recorded authority.
//!
//! # N40 — redaction, and why a declassification is an act
//!
//! `Secret<T>` **does** exist at runtime: `Value::Secret(Box<Value>)`
//! (`src/interp.rs:181`), minted by a cast to a secret-qualified type
//! (`src/interp.rs:3769`) and by the crypto natives. A record field can hold
//! one — `FieldDecl` has no qualifier slot, but a field typed with a
//! `type X = secret T` alias resolves to `Type::Secret` and carries the wrapper
//! at run time (`stdlib/crypto.tl:22`). So redaction keys on two signals, both
//! owned by the runtime and neither a guess:
//!
//! 1. the value is `Value::Secret(_)` — a type-level fact that survived into
//!    the value, and
//! 2. `crate::secret_fields::is_secret(struct, field)` — the same table the
//!    display path consults (`src/interp.rs:687`; `src/secret_fields.rs`),
//!    keyed by the enclosing struct's name. A `Map` record has no struct name,
//!    so this signal cannot fire for one.
//!
//! **Unknown fields pass through unchanged; this module does not guess that a
//! field is secret from its name.** Both errors are real, so the choice is
//! stated rather than left implicit:
//!
//! - a name heuristic over-redacts. Public evidence legitimately carries
//!   fields called `token` (an extracted CSRF token, a sitemap `lastmod`
//!   token), and rewriting those makes the record unreadable;
//! - worse, a heuristic makes *declassification* meaningless. The caller could
//!   no longer tell a type-level secret from a pattern match, so "released on
//!   whose authority" would describe a guess.
//!
//! The cost is stated plainly: a caller who puts a secret into a field typed
//! public gets it back in the clear. The fix is to type the field secret; it is
//! not this pass's job to guess.
//!
//! `Private<T>` is **not** withheld here. The runtime prints it in the clear
//! (`src/interp.rs:650`: `Value::Private(v) => v.as_string()`), so treating it
//! as secret in this pass would make this module disagree with every other
//! output path about what a `Private` is. That disagreement is the bug, not
//! this refusal to work around it.
//!
//! Scope of the walk: fields of the record, recursively through nested structs
//! and maps, addressed by dotted path (`keypair.identity`). **Array elements
//! are not redacted in place.** A path cannot name an array position in a way a
//! receipt could record as authority, so a `Secret` inside an array is not
//! silently emitted: [`redact_record`] refuses to render the record at all.
//!
//! A redacted value is replaced by `[redacted:<path>]` — the marker names the
//! field and carries no character, length or prefix of the value. A
//! declassification of a field that is *not* withheld is accepted and produces
//! no receipt (nothing left the secrecy lattice) — a caller is not asked to
//! know which fields the runtime classifies as secret.
//!
//! # What a `Grant` does and does not carry
//!
//! The runtime value is `Value::Struct { name: "Grant", fields: [("effect", …)] }`
//! and it carries **no id and no expiry of its own** — `src/scope.rs` has no
//! grant registry, and `src/interp.rs::scope_grant` mints the value without
//! recording it. So "live" here means two checkable things and no more:
//!
//! - the value is a real `Grant` (unconstructible from source — no struct of
//!   that name exists, so a forged `Grant` cannot be built in a `.tl` program),
//!   and it names the effect the export consumes (`Net`, the only effect
//!   `typeck::KNOWN_EFFECTS` enforces);
//! - the record names a grant id (`grant_id`), and the *register* still
//!   authorises the record's target for today.
//!
//! The runtime cannot prove that a record's `grant_id` refers to the presented
//! token, because neither carries an id. That gap is stated here rather than
//! papered over: what is enforced is "a live token was presented AND a grant id
//! was claimed AND the host is still covered", which is exactly the check a
//! revoked or too-narrow authorization fails.
//!
//! # API (as surfaced in `stdlib/evidence.tl`)
//!
//! - `intel.export(records, grant)` → ExportOutcome
//! - `intel.budget_charge(kind, limit, used, attempted, consumer?)` → BudgetOutcome
//! - `intel.receipt_json(receipt)` → String (a receipt already in the result, rendered to JSON)
//! - `intel.redact(record, declassify?)` → RedactionOutcome (the record with every
//!   withheld field replaced, plus one receipt per released field)
//! - `intel.redaction_receipt_json(receipt)` → String (the same for a declassification receipt)

use super::StdlibResult;
use crate::interp::{Value, type_name};
use crate::scope::{Decision, Refusal, ScopeRegister};
use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ══════════════════════════════════════════════════════════════════
// Vocabulary
// ══════════════════════════════════════════════════════════════════

/// Runtime module name. `intel.export(…)` is the call site spelling.
pub const RUNTIME_MODULE: &str = "intel";

/// Schema tag on an export outcome.
pub const EXPORT_SCHEMA: &str = "tallow.intel_export.v1";

/// Schema tag on a budget refusal receipt.
pub const RECEIPT_SCHEMA: &str = "tallow.budget_receipt.v1";

/// The effect an export consumes. Export is egress, and `Net` is the only
/// effect the type checker enforces (`typeck::KNOWN_EFFECTS`), so a token
/// minted for anything else is not authority to move evidence.
pub const EXPORT_EFFECT: &str = "Net";

pub const CODE_NO_GRANT: &str = "export:no-grant";
pub const CODE_GRANT_EXPIRED: &str = "export:grant-expired";
pub const CODE_SCOPE_NOT_LISTED: &str = "export:scope-not-listed";
pub const CODE_NO_TARGET: &str = "export:no-target";

pub const CODE_BUDGET_WITHIN: &str = "budget:within";
pub const CODE_BUDGET_UNBOUNDED: &str = "budget:unbounded";
pub const CODE_BUDGET_BYTES_EXCEEDED: &str = "budget:bytes-exceeded";
pub const CODE_BUDGET_RATE_EXCEEDED: &str = "budget:rate-exceeded";

/// Schema tag on a redaction outcome.
pub const REDACTION_SCHEMA: &str = "tallow.intel_redaction.v1";

/// Schema tag on a declassification receipt.
pub const DECLASSIFICATION_SCHEMA: &str = "tallow.declassification_receipt.v1";

pub const CODE_REDACT_NO_REASON: &str = "redact:no-reason";
pub const CODE_REDACT_NO_CONSUMER: &str = "redact:no-consumer";
pub const CODE_REDACT_UNKNOWN_FIELD: &str = "redact:unknown-field";
pub const CODE_REDACT_DUPLICATE_FIELD: &str = "redact:duplicate-field";

/// The receipt code for a secret that was released on a recorded authority.
/// Not a refusal.
pub const CODE_REDACT_DECLASSIFIED: &str = "redact:declassified";

// ══════════════════════════════════════════════════════════════════
// Grant token
// ══════════════════════════════════════════════════════════════════

/// A capability value as the runtime holds it.
///
/// Mirrors `src/interp.rs::scope_grant`: a struct named `Grant` whose `effect`
/// field is the effect name that was minted. Nothing else about it is
/// inspectable, so nothing else is claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantToken {
    pub effect: String,
}

impl GrantToken {
    /// Read a grant out of a runtime value. Any value that is not a `Grant`
    /// struct yields `None` — a string `"Net"`, a struct named `GrantNet`, or a
    /// map with an `effect` key are all *not* authority.
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Struct { name, fields } if name == "Grant" => {
                let effect = fields
                    .iter()
                    .find(|(k, _)| k == "effect")
                    .and_then(|(_, v)| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                Some(GrantToken { effect })
            }
            _ => None,
        }
    }

    /// True when this token authorises an export.
    pub fn is_live_for_export(&self) -> bool {
        self.effect == EXPORT_EFFECT
    }

    /// How the token reads in a refusal.
    fn describe(&self) -> String {
        if self.effect.is_empty() {
            "a Grant with no effect".to_string()
        } else {
            format!("Grant<{}>", self.effect)
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// N38 — grant-bound export
// ══════════════════════════════════════════════════════════════════

/// One record offered for export.
///
/// `target` is what the scope register is asked about — a host or a URL;
/// `grant_id` is the record's own claim about which authority covers it. Both
/// are optional in the *type* because an omitted field must be refused with a
/// code that says so, not defaulted into a permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: String,
    pub target: Option<String>,
    pub grant_id: Option<String>,
}

impl EvidenceRecord {
    /// A record that passes every structural requirement.
    pub fn new(id: &str, target: &str, grant_id: &str) -> Self {
        EvidenceRecord {
            id: id.to_string(),
            target: Some(target.to_string()),
            grant_id: Some(grant_id.to_string()),
        }
    }

    /// Read a record from the runtime value a `.tl` caller passed.
    ///
    /// Accepts a `Struct` (named `EvidenceRecord` by the manifest) or a `Map`,
    /// because a record built by `json.parse` is the other honest source.
    fn from_value(value: &Value) -> Result<Self, String> {
        let field = |key: &str| -> Option<&Value> {
            match value {
                Value::Struct { fields, .. } => {
                    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
                }
                Value::Map(pairs) => pairs.iter().find_map(|(k, v)| match k {
                    Value::String(s) if s == key => Some(v),
                    _ => None,
                }),
                _ => None,
            }
        };
        match value {
            Value::Struct { .. } | Value::Map(_) => {}
            other => {
                return Err(format!(
                    "intel.export: a record must be an EvidenceRecord struct or a map, got {}",
                    type_name(other)
                ));
            }
        }
        let text = |key: &str| -> Option<String> {
            match field(key) {
                Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
                _ => None,
            }
        };
        Ok(EvidenceRecord {
            id: text("id").unwrap_or_default(),
            target: text("target"),
            grant_id: text("grant_id"),
        })
    }
}

/// Why one record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRefusal {
    /// The record's id, or `<unnamed>` when it carried none.
    pub record_id: String,
    /// The target as offered, when one was offered.
    pub target: Option<String>,
    /// One of the `export:*` codes in this module.
    pub code: &'static str,
    /// One line a human can read, naming the failed requirement.
    pub detail: String,
    /// The register's own code (`scope:not-listed`, `scope:expired`,
    /// `scope:register-unreadable`, …) when a register decision produced the
    /// refusal. `None` when the failure was in the call, not the register.
    pub scope_code: Option<&'static str>,
}

/// The gate's answer: what may leave, and what may not, with reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    pub admitted: Vec<EvidenceRecord>,
    pub refused: Vec<ExportRefusal>,
}

impl ExportOutcome {
    /// Fail-closed aggregate: a partial export is **not** a success. A caller
    /// that wants the admitted subset reads `admitted`, but it cannot mistake
    /// a refused record for a clean run.
    pub fn ok(&self) -> bool {
        self.refused.is_empty()
    }

    fn to_value(&self) -> Value {
        let admitted = self
            .admitted
            .iter()
            .map(|r| Value::Struct {
                name: "EvidenceRecord".to_string(),
                fields: vec![
                    ("id".to_string(), Value::String(r.id.clone())),
                    ("target".to_string(), opt_string(&r.target)),
                    ("grant_id".to_string(), opt_string(&r.grant_id)),
                ],
            })
            .collect();
        let refused = self
            .refused
            .iter()
            .map(|r| Value::Struct {
                name: "ExportRefusal".to_string(),
                fields: vec![
                    ("record_id".to_string(), Value::String(r.record_id.clone())),
                    ("target".to_string(), opt_string(&r.target)),
                    ("code".to_string(), Value::String(r.code.to_string())),
                    ("detail".to_string(), Value::String(r.detail.clone())),
                    (
                        "scope_code".to_string(),
                        opt_string(&r.scope_code.map(|c| c.to_string())),
                    ),
                ],
            })
            .collect();
        Value::Struct {
            name: "ExportOutcome".to_string(),
            fields: vec![
                (
                    "schema".to_string(),
                    Value::String(EXPORT_SCHEMA.to_string()),
                ),
                ("ok".to_string(), Value::Bool(self.ok())),
                (
                    "admitted_count".to_string(),
                    Value::Int(self.admitted.len() as i128),
                ),
                ("admitted".to_string(), Value::Array(admitted)),
                ("refused".to_string(), Value::Array(refused)),
            ],
        }
    }
}

fn opt_string(v: &Option<String>) -> Value {
    match v {
        Some(s) => Value::String(s.clone()),
        None => Value::Nil,
    }
}

/// Export evidence under a grant, consulting the same register the topology
/// plane consults before a packet is built.
///
/// `today` is passed in rather than read from the clock, exactly as
/// [`ScopeRegister::authorize`] takes it, so a decision is deterministic and
/// testable.
///
/// Order of checks, per record: the grant (whole call, so a dead grant refuses
/// every record), then the record's own grant id, then its target, then the
/// register. Each failure names one requirement.
pub fn export_records(
    records: &[EvidenceRecord],
    grant: Option<&GrantToken>,
    register: &ScopeRegister,
    today: &str,
) -> ExportOutcome {
    let (grant_ok, grant_detail) = match grant {
        None => (
            false,
            "no grant was presented; export requires a Grant<Net> minted by scope.grant(Net)"
                .to_string(),
        ),
        Some(token) if !token.is_live_for_export() => (
            false,
            format!(
                "the presented {} is not authority to export; export requires Grant<{}>",
                token.describe(),
                EXPORT_EFFECT
            ),
        ),
        Some(_) => (true, String::new()),
    };

    let mut admitted = Vec::new();
    let mut refused = Vec::new();
    for record in records {
        let record_id = if record.id.trim().is_empty() {
            "<unnamed>".to_string()
        } else {
            record.id.clone()
        };
        if !grant_ok {
            refused.push(ExportRefusal {
                record_id,
                target: record.target.clone(),
                code: CODE_NO_GRANT,
                detail: grant_detail.clone(),
                scope_code: None,
            });
            continue;
        }
        if record
            .grant_id
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            refused.push(ExportRefusal {
                record_id,
                target: record.target.clone(),
                code: CODE_NO_GRANT,
                detail: "the record carries no grant id, so nothing ties it to a live authority"
                    .to_string(),
                scope_code: None,
            });
            continue;
        }
        let target = match record.target.as_deref().map(str::trim) {
            Some(t) if !t.is_empty() => t,
            _ => {
                refused.push(ExportRefusal {
                    record_id,
                    target: None,
                    code: CODE_NO_TARGET,
                    detail: "the record names no target; an absent target is a refusal, not a pass"
                        .to_string(),
                    scope_code: None,
                });
                continue;
            }
        };
        match register.authorize(target, "GET", today) {
            Decision::Allowed(_) => admitted.push(record.clone()),
            Decision::Refused(Refusal::Expired {
                expires_at, today, ..
            }) => refused.push(ExportRefusal {
                record_id,
                target: Some(target.to_string()),
                code: CODE_GRANT_EXPIRED,
                detail: format!(
                    "the grant covering '{target}' expired on {expires_at} (today {today}); \
                     evidence cannot leave on a lapsed authorization"
                ),
                scope_code: Some("scope:expired"),
            }),
            Decision::Refused(other) => refused.push(ExportRefusal {
                record_id,
                target: Some(target.to_string()),
                code: CODE_SCOPE_NOT_LISTED,
                detail: format!(
                    "the scope register does not authorise '{target}': {} — {}",
                    other.code(),
                    other.explain()
                ),
                scope_code: Some(other.code()),
            }),
        }
    }
    ExportOutcome { admitted, refused }
}

// ══════════════════════════════════════════════════════════════════
// N39 — budget refusal receipts
// ══════════════════════════════════════════════════════════════════

/// Which ceiling was crossed. Only these two kinds exist here; anything else
/// is a usage error, not a silently-accepted label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// Bytes moved.
    Bytes,
    /// Operations per window. The window belongs to the caller: `used` is what
    /// the caller has already spent in *its* window, and this function does not
    /// keep a clock of its own for it.
    Rate,
}

impl BudgetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetKind::Bytes => "bytes",
            BudgetKind::Rate => "rate",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bytes" | "byte" => Ok(BudgetKind::Bytes),
            "rate" | "rps" | "ops" => Ok(BudgetKind::Rate),
            other => Err(format!(
                "intel.budget_charge: unknown budget kind '{other}' (known: bytes, rate)"
            )),
        }
    }

    fn exceeded_code(self) -> &'static str {
        match self {
            BudgetKind::Bytes => CODE_BUDGET_BYTES_EXCEEDED,
            BudgetKind::Rate => CODE_BUDGET_RATE_EXCEEDED,
        }
    }
}

/// One attempted charge against a budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRequest {
    pub kind: BudgetKind,
    /// The limit the *caller* supplied. `None` means the caller set no ceiling,
    /// which is reported as unbounded rather than invented.
    pub limit: Option<i64>,
    /// Already consumed in the caller's window.
    pub used: i64,
    /// Requested by this call.
    pub attempted: i64,
    /// Module/caller name as it appears to the runtime.
    pub consumer: String,
}

/// The refusal, as data.
///
/// Every field is populated at the moment of refusal; `to_json` makes the
/// receipt portable so it can be handed to a person or another process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetReceipt {
    pub schema: &'static str,
    pub code: &'static str,
    pub kind: &'static str,
    pub limit: Option<i64>,
    pub used: i64,
    pub attempted: i64,
    /// `used + attempted - limit`: how far past the ceiling the call would have
    /// gone.
    pub overflow: i64,
    pub consumer: String,
    /// Wall-clock moment of the refusal, unix epoch milliseconds.
    pub at_unix_ms: i64,
    /// Monotonic milliseconds since this process's evidence clock origin (the
    /// first call into this module). Unaffected by wall-clock adjustment, and
    /// not comparable across processes — which is why both numbers travel.
    pub monotonic_delta_ms: u64,
}

impl BudgetReceipt {
    /// JSON rendering, so a caller can show the receipt to someone.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!(
                "{{\"schema\":\"{}\",\"code\":\"receipt-unserialisable\",\"detail\":{:?}}}",
                RECEIPT_SCHEMA,
                e.to_string()
            )
        })
    }

    fn to_value(&self) -> Value {
        Value::Struct {
            name: "BudgetReceipt".to_string(),
            fields: vec![
                ("schema".into(), Value::String(self.schema.to_string())),
                ("code".into(), Value::String(self.code.to_string())),
                ("kind".into(), Value::String(self.kind.to_string())),
                (
                    "limit".into(),
                    self.limit.map_or(Value::Nil, |v| Value::Int(v as i128)),
                ),
                ("used".into(), Value::Int(self.used as i128)),
                ("attempted".into(), Value::Int(self.attempted as i128)),
                ("overflow".into(), Value::Int(self.overflow as i128)),
                ("consumer".into(), Value::String(self.consumer.clone())),
                ("at_unix_ms".into(), Value::Int(self.at_unix_ms as i128)),
                (
                    "monotonic_delta_ms".into(),
                    Value::Int(self.monotonic_delta_ms as i128),
                ),
            ],
        }
    }
}

/// The charge decision. `receipt` is `Some` exactly when the budget was
/// exceeded — a within-budget call produces no receipt, and an unbounded call
/// produces none either (it is not a refusal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetVerdict {
    pub allowed: bool,
    pub code: &'static str,
    pub limit: Option<i64>,
    pub receipt: Option<BudgetReceipt>,
}

impl BudgetVerdict {
    fn to_value(&self) -> Value {
        Value::Struct {
            name: "BudgetOutcome".to_string(),
            fields: vec![
                ("schema".into(), Value::String(RECEIPT_SCHEMA.to_string())),
                ("allowed".into(), Value::Bool(self.allowed)),
                ("code".into(), Value::String(self.code.to_string())),
                (
                    "limit".into(),
                    self.limit.map_or(Value::Nil, |v| Value::Int(v as i128)),
                ),
                (
                    "receipt".into(),
                    self.receipt.as_ref().map_or(Value::Nil, |r| r.to_value()),
                ),
            ],
        }
    }
}

/// Charge one attempt against a budget.
///
/// The limit comes from the call and nowhere else: there is no default ceiling
/// in this module, so a caller that supplies none is told `budget:unbounded`
/// and the attempt is allowed. A negative limit, `used` or `attempted` is a
/// usage error rather than a comparison nobody intended.
pub fn charge(
    request: &BudgetRequest,
    at_unix_ms: i64,
    monotonic_delta_ms: u64,
) -> Result<BudgetVerdict, String> {
    if request.used < 0 || request.attempted < 0 {
        return Err(format!(
            "intel.budget_charge: used ({}) and attempted ({}) must be non-negative",
            request.used, request.attempted
        ));
    }
    if let Some(limit) = request.limit {
        if limit < 0 {
            return Err(format!(
                "intel.budget_charge: limit {limit} must be non-negative; omit it to say 'no ceiling'"
            ));
        }
    }
    let Some(limit) = request.limit else {
        return Ok(BudgetVerdict {
            allowed: true,
            code: CODE_BUDGET_UNBOUNDED,
            limit: None,
            receipt: None,
        });
    };
    // i128 so a huge `used` and a huge `attempted` cannot wrap into "within".
    let total = request.used as i128 + request.attempted as i128;
    if total <= limit as i128 {
        return Ok(BudgetVerdict {
            allowed: true,
            code: CODE_BUDGET_WITHIN,
            limit: Some(limit),
            receipt: None,
        });
    }
    Ok(BudgetVerdict {
        allowed: false,
        code: request.kind.exceeded_code(),
        limit: Some(limit),
        receipt: Some(BudgetReceipt {
            schema: RECEIPT_SCHEMA,
            code: request.kind.exceeded_code(),
            kind: request.kind.as_str(),
            limit: Some(limit),
            used: request.used,
            attempted: request.attempted,
            overflow: (total - limit as i128) as i64,
            consumer: request.consumer.clone(),
            at_unix_ms,
            monotonic_delta_ms,
        }),
    })
}

// ══════════════════════════════════════════════════════════════════
// N40 — redaction, with declassification as a recorded act
// ══════════════════════════════════════════════════════════════════

/// The marker a withheld value is replaced with: `[redacted:<path>]`.
///
/// It names the field and carries no character, length or prefix of the value.
pub fn redaction_marker(path: &str) -> String {
    format!("[redacted:{path}]")
}

/// One request to release a withheld field in the clear.
///
/// `reason` and `consumer` are optional in the *type* so their absence is a
/// coded refusal (`redact:no-reason`, `redact:no-consumer`) rather than a
/// default — the same shape as [`EvidenceRecord::grant_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declassification {
    /// Field name, or dotted path for a nested field (`keypair.identity`).
    pub field: String,
    pub reason: Option<String>,
    pub consumer: Option<String>,
}

impl Declassification {
    pub fn new(field: &str, reason: &str, consumer: &str) -> Self {
        Declassification {
            field: field.to_string(),
            reason: Some(reason.to_string()),
            consumer: Some(consumer.to_string()),
        }
    }

    /// Read a request from the runtime value a `.tl` caller passed.
    fn from_value(value: &Value) -> Result<Self, String> {
        match value {
            Value::Struct { .. } | Value::Map(_) => {}
            other => {
                return Err(format!(
                    "intel.redact: a declassification must be a Declassification struct or a map, got {}",
                    type_name(other)
                ));
            }
        }
        Ok(Declassification {
            field: record_text(value, "field").unwrap_or_default(),
            reason: record_text(value, "reason"),
            consumer: record_text(value, "consumer"),
        })
    }
}

/// Why one declassification was refused. The field stays withheld: a refusal
/// never releases anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionRefusal {
    /// One of the `redact:*` refusal codes in this module.
    pub code: &'static str,
    /// The field as the request named it, or `<unnamed>`.
    pub field: String,
    /// One line a human can read, naming the failed requirement.
    pub detail: String,
}

/// A released secret, and the authority that released it — as data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionReceipt {
    pub schema: &'static str,
    pub code: &'static str,
    /// The path that was released, e.g. `keypair.identity`.
    pub field: String,
    pub reason: String,
    /// Who receives the value in the clear.
    pub consumer: String,
    /// Wall-clock moment of the release, unix epoch milliseconds.
    pub at_unix_ms: i64,
    /// Monotonic milliseconds since this process's evidence clock origin.
    pub monotonic_delta_ms: u64,
}

impl RedactionReceipt {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!(
                "{{\"schema\":\"{}\",\"code\":\"receipt-unserialisable\",\"detail\":{:?}}}",
                DECLASSIFICATION_SCHEMA,
                e.to_string()
            )
        })
    }

    fn to_value(&self) -> Value {
        Value::Struct {
            name: "RedactionReceipt".to_string(),
            fields: vec![
                ("schema".into(), Value::String(self.schema.to_string())),
                ("code".into(), Value::String(self.code.to_string())),
                ("field".into(), Value::String(self.field.clone())),
                ("reason".into(), Value::String(self.reason.clone())),
                ("consumer".into(), Value::String(self.consumer.clone())),
                ("at_unix_ms".into(), Value::Int(self.at_unix_ms as i128)),
                (
                    "monotonic_delta_ms".into(),
                    Value::Int(self.monotonic_delta_ms as i128),
                ),
            ],
        }
    }
}

/// The redacted record and the account of what was withheld, released and
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutcome {
    /// The record rendered to JSON, every withheld field replaced. This is the
    /// only form the record leaves in: handing back a `Value` tree would carry
    /// a second copy of each unreleased secret and invite a display path that
    /// does not consult the withholding rules.
    pub record_json: String,
    /// Paths replaced by [`redaction_marker`].
    pub redacted_fields: Vec<String>,
    /// Paths released in the clear, one receipt each.
    pub released_fields: Vec<String>,
    pub receipts: Vec<RedactionReceipt>,
    pub refused: Vec<RedactionRefusal>,
}

impl RedactionOutcome {
    /// Fail-closed, exactly as [`ExportOutcome::ok`]: a refused declassification
    /// is not a clean run, even though the record still renders.
    pub fn ok(&self) -> bool {
        self.refused.is_empty()
    }

    fn to_value(&self) -> Value {
        let strings = |items: &[String]| -> Value {
            Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
        };
        let refused = self
            .refused
            .iter()
            .map(|r| Value::Struct {
                name: "RedactionRefusal".to_string(),
                fields: vec![
                    ("code".to_string(), Value::String(r.code.to_string())),
                    ("field".to_string(), Value::String(r.field.clone())),
                    ("detail".to_string(), Value::String(r.detail.clone())),
                ],
            })
            .collect();
        Value::Struct {
            name: "RedactionOutcome".to_string(),
            fields: vec![
                (
                    "schema".to_string(),
                    Value::String(REDACTION_SCHEMA.to_string()),
                ),
                ("ok".to_string(), Value::Bool(self.ok())),
                (
                    "record_json".to_string(),
                    Value::String(self.record_json.clone()),
                ),
                (
                    "redacted_fields".to_string(),
                    strings(&self.redacted_fields),
                ),
                (
                    "released_fields".to_string(),
                    strings(&self.released_fields),
                ),
                (
                    "receipts".to_string(),
                    Value::Array(self.receipts.iter().map(|r| r.to_value()).collect()),
                ),
                ("refused".to_string(), Value::Array(refused)),
            ],
        }
    }
}

/// Read one named field out of a runtime record (a named struct or a map).
fn record_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Struct { fields, .. } => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        Value::Map(pairs) => pairs.iter().find_map(|(k, v)| match k {
            Value::String(s) if s == key => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

/// A named field's text, `None` when the field is absent, not a string, or
/// blank. Blank and absent are the same answer here: both mean "not given".
fn record_text(value: &Value, key: &str) -> Option<String> {
    match record_field(value, key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Dotted path for a nested field.
fn join_path(prefix: &str, field: &str) -> String {
    if prefix.is_empty() {
        field.to_string()
    } else {
        format!("{prefix}.{field}")
    }
}

/// The two runtime-owned signals that a field is withheld. See the module docs:
/// neither is a name guess, and an unknown field is never withheld.
fn is_withheld(struct_name: &str, field: &str, value: &Value) -> bool {
    matches!(value, Value::Secret(_)) || crate::secret_fields::is_secret(struct_name, field)
}

/// Every addressable field path in a record: struct and map fields, including
/// nested ones. Array elements are deliberately not addressable (see docs).
fn collect_field_paths(value: &Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        Value::Struct { fields, .. } => {
            for (key, nested) in fields {
                let path = join_path(prefix, key);
                out.push(path.clone());
                collect_field_paths(nested, &path, out);
            }
        }
        Value::Map(pairs) => {
            for (key, nested) in pairs {
                if let Value::String(key) = key {
                    let path = join_path(prefix, key);
                    out.push(path.clone());
                    collect_field_paths(nested, &path, out);
                }
            }
        }
        _ => {}
    }
}

/// Copy the record, replacing or releasing withheld fields. `releases` holds
/// `(path, reason, consumer)` already validated against the record.
fn rewrite_record(
    value: &Value,
    prefix: &str,
    releases: &[(String, String, String)],
    redacted: &mut Vec<String>,
    released: &mut Vec<String>,
    receipts: &mut Vec<RedactionReceipt>,
    at_unix_ms: i64,
    monotonic_delta_ms: u64,
) -> Value {
    let mut copy_field = |key: &str, field_value: &Value, struct_name: &str| -> Value {
        let path = join_path(prefix, key);
        if !is_withheld(struct_name, key, field_value) {
            return rewrite_record(
                field_value,
                &path,
                releases,
                redacted,
                released,
                receipts,
                at_unix_ms,
                monotonic_delta_ms,
            );
        }
        match releases.iter().find(|(p, _, _)| *p == path) {
            // Released: the value in the clear. A `Secret` wrapper is dropped
            // here — that is what declassification means — and only here.
            Some((_, reason, consumer)) => {
                released.push(path.clone());
                receipts.push(RedactionReceipt {
                    schema: DECLASSIFICATION_SCHEMA,
                    code: CODE_REDACT_DECLASSIFIED,
                    field: path,
                    reason: reason.clone(),
                    consumer: consumer.clone(),
                    at_unix_ms,
                    monotonic_delta_ms,
                });
                match field_value {
                    Value::Secret(inner) => (**inner).clone(),
                    other => other.clone(),
                }
            }
            None => {
                redacted.push(path.clone());
                Value::String(redaction_marker(&path))
            }
        }
    };
    match value {
        Value::Struct { name, fields } => Value::Struct {
            name: name.clone(),
            fields: fields
                .iter()
                .map(|(key, field_value)| (key.clone(), copy_field(key, field_value, name)))
                .collect(),
        },
        Value::Map(pairs) => Value::Map(
            pairs
                .iter()
                .map(|(key, field_value)| {
                    let key_name = match key {
                        Value::String(s) => s.clone(),
                        // No name, no path: `is_secret` cannot fire and no
                        // declassification can address it.
                        _ => String::new(),
                    };
                    // A map has no struct name, so the table cannot match.
                    (key.clone(), copy_field(&key_name, field_value, ""))
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Render one value as JSON. Refuses a `Secret` and anything it does not know
/// how to render by name, because a silent `"[SECRET]"` would be a redaction
/// marker that names no field.
fn render_evidence(value: &Value) -> Result<serde_json::Value, String> {
    use serde_json::Value as J;
    Ok(match value {
        Value::Nil => J::Null,
        Value::Bool(b) => J::Bool(*b),
        // An integer beyond i64 travels as a decimal string rather than being
        // truncated into a Number.
        Value::Int(n) => match i64::try_from(*n) {
            Ok(i) => J::Number(i.into()),
            Err(_) => J::String(n.to_string()),
        },
        Value::Float(f) => match serde_json::Number::from_f64(*f) {
            Some(n) => J::Number(n),
            None => {
                return Err(format!(
                    "intel.redact: a record field holds {f}, which JSON cannot carry"
                ));
            }
        },
        Value::String(s) => J::String(s.clone()),
        // Private prints in the clear everywhere else in the runtime
        // (`interp.rs:650`), so it renders as its inner value here too.
        Value::Private(inner) => render_evidence(inner)?,
        Value::Array(items) => J::Array(
            items
                .iter()
                .map(render_evidence)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Map(pairs) => {
            let mut object = serde_json::Map::new();
            for (key, nested) in pairs {
                let key = match key {
                    Value::String(s) => s.clone(),
                    other => {
                        return Err(format!(
                            "intel.redact: a record field name must be a string, got {}",
                            type_name(other)
                        ));
                    }
                };
                object.insert(key, render_evidence(nested)?);
            }
            J::Object(object)
        }
        Value::Struct { fields, .. } => {
            let mut object = serde_json::Map::new();
            for (key, nested) in fields {
                object.insert(key.clone(), render_evidence(nested)?);
            }
            J::Object(object)
        }
        // The renderer is the second door: a secret that reached here was not
        // redacted, and emitting it (even as "[SECRET]" naming no field) would
        // be a claim this module cannot make.
        Value::Secret(_) => {
            return Err(
                "intel.redact: a Secret value reached the renderer unredacted; refusing to serialise \
                 the record (a secret inside an array cannot be redacted in place)"
                    .to_string(),
            );
        }
        other => {
            return Err(format!(
                "intel.redact: a record field holds {}, which cannot be rendered as evidence",
                type_name(other)
            ));
        }
    })
}

/// Redact a record, releasing only what a declassification names.
///
/// Checks per declassification, in this order: the field must exist in the
/// record (a typo is not an authority), it must not already be released, and
/// the reason and consumer must be present and non-blank. A refused
/// declassification releases nothing.
pub fn redact_record(
    record: &Value,
    declassifications: &[Declassification],
    at_unix_ms: i64,
    monotonic_delta_ms: u64,
) -> Result<RedactionOutcome, String> {
    match record {
        Value::Struct { .. } | Value::Map(_) => {}
        other => {
            return Err(format!(
                "intel.redact: a record must be an EvidenceRecord struct or a map, got {}",
                type_name(other)
            ));
        }
    }
    let mut paths = Vec::new();
    collect_field_paths(record, "", &mut paths);

    let mut refused = Vec::new();
    let mut releases: Vec<(String, String, String)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for request in declassifications {
        let name = request.field.trim();
        let detail = |what: &str| format!("declassification of '{name}': {what}");
        if name.is_empty() {
            refused.push(RedactionRefusal {
                code: CODE_REDACT_UNKNOWN_FIELD,
                field: "<unnamed>".to_string(),
                detail: "a declassification must name a field; an unnamed release is a refusal"
                    .to_string(),
            });
            continue;
        }
        if !paths.iter().any(|p| p == name) {
            refused.push(RedactionRefusal {
                code: CODE_REDACT_UNKNOWN_FIELD,
                field: name.to_string(),
                detail: detail("the record has no such field"),
            });
            continue;
        }
        if seen.iter().any(|s| s == name) {
            refused.push(RedactionRefusal {
                code: CODE_REDACT_DUPLICATE_FIELD,
                field: name.to_string(),
                detail: detail(
                    "already named by an earlier declassification; one receipt per field",
                ),
            });
            continue;
        }
        seen.push(name.to_string());
        // Blank and absent are the same answer: "not given". A reason of "   "
        // is not an authority, so it must not reach the release path.
        let reason = request
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty());
        let consumer = request
            .consumer
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty());
        let (reason, consumer) = match (reason, consumer) {
            (Some(reason), Some(consumer)) => (reason, consumer),
            (reason, _) => {
                let (code, what) = if reason.is_none() {
                    (CODE_REDACT_NO_REASON, "no reason was given")
                } else {
                    (CODE_REDACT_NO_CONSUMER, "no consumer was given")
                };
                refused.push(RedactionRefusal {
                    code,
                    field: name.to_string(),
                    detail: format!(
                        "{}; a release without a recorded authority is not a release",
                        detail(what)
                    ),
                });
                continue;
            }
        };
        releases.push((name.to_string(), reason.to_string(), consumer.to_string()));
    }

    let mut redacted_fields = Vec::new();
    let mut released_fields = Vec::new();
    let mut receipts = Vec::new();
    let rewritten = rewrite_record(
        record,
        "",
        &releases,
        &mut redacted_fields,
        &mut released_fields,
        &mut receipts,
        at_unix_ms,
        monotonic_delta_ms,
    );
    let record_json = serde_json::to_string(&render_evidence(&rewritten)?)
        .map_err(|e| format!("intel.redact: could not serialise the redacted record: {e}"))?;
    Ok(RedactionOutcome {
        record_json,
        redacted_fields,
        released_fields,
        receipts,
        refused,
    })
}

// ══════════════════════════════════════════════════════════════════
// Clock
// ══════════════════════════════════════════════════════════════════

/// The two numbers a receipt carries: wall clock for a human, monotonic for
/// reasoning about order without trusting the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moment {
    pub unix_ms: i64,
    pub monotonic_delta_ms: u64,
}

/// Process-local monotonic origin, set on first use.
fn monotonic_origin() -> Instant {
    use std::sync::OnceLock;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

/// The moment of a refusal, measured now.
pub fn now() -> Moment {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Moment {
        unix_ms,
        monotonic_delta_ms: monotonic_origin().elapsed().as_millis() as u64,
    }
}

// ══════════════════════════════════════════════════════════════════
// Dispatch
// ══════════════════════════════════════════════════════════════════

fn int_arg(args: &[Value], idx: usize, fname: &str) -> Result<i64, String> {
    match args.get(idx) {
        Some(Value::Int(i)) => i64::try_from(*i)
            .map_err(|_| format!("intel.{fname}: argument {} out of i64 range", idx + 1)),
        Some(other) => Err(format!(
            "intel.{fname}: argument {} expected Int, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("intel.{fname}: missing argument {}", idx + 1)),
    }
}

fn str_arg(args: &[Value], idx: usize, fname: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!(
            "intel.{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("intel.{fname}: missing argument {}", idx + 1)),
    }
}

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    // Tolerate a caller forwarding the full namespace.
    let function = function
        .strip_prefix("intel.")
        .or_else(|| function.strip_prefix("evidence."))
        .unwrap_or(function);
    match function {
        "export" => Some(export_dispatch(args)),
        "budget_charge" => Some(budget_charge_dispatch(function, args)),
        "receipt_json" => Some(receipt_json_dispatch(args)),
        "redact" => Some(redact_dispatch(args)),
        "redaction_receipt_json" => Some(redaction_receipt_json_dispatch(args)),
        _ => None,
    }
}

fn export_dispatch(args: Vec<Value>) -> StdlibResult {
    let records_value = args
        .first()
        .ok_or_else(|| "intel.export: missing argument 1 (records)".to_string())?;
    let items = match records_value {
        Value::Array(items) => items,
        other => {
            return Err(format!(
                "intel.export: argument 1 expected []EvidenceRecord, got {}",
                type_name(other)
            ));
        }
    };
    let mut records = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        records
            .push(EvidenceRecord::from_value(item).map_err(|e| format!("{e} (record {})", i + 1))?);
    }
    // Argument 2 is the capability. It is read, never constructed: a value that
    // is not a real `Grant` struct is no grant at all.
    let grant = args.get(1).and_then(GrantToken::from_value);
    let register = ScopeRegister::load_default();
    let outcome = export_records(
        &records,
        grant.as_ref(),
        &register,
        &crate::scope::utc_today(),
    );
    Ok(outcome.to_value())
}

fn budget_charge_dispatch(function: &str, args: Vec<Value>) -> StdlibResult {
    let kind = BudgetKind::parse(&str_arg(&args, 0, "budget_charge")?)?;
    let limit = match args.get(1) {
        Some(Value::Nil) | None => None,
        Some(Value::Int(_)) => Some(int_arg(&args, 1, "budget_charge")?),
        Some(other) => {
            return Err(format!(
                "intel.budget_charge: argument 2 expected Int? (the limit), got {}",
                type_name(other)
            ));
        }
    };
    let used = int_arg(&args, 2, "budget_charge")?;
    let attempted = int_arg(&args, 3, "budget_charge")?;
    let consumer = match args.get(4) {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        Some(Value::Nil) | None => format!("{RUNTIME_MODULE}.{function}"),
        Some(other) => {
            return Err(format!(
                "intel.budget_charge: argument 5 expected String? (the consumer), got {}",
                type_name(other)
            ));
        }
    };
    let request = BudgetRequest {
        kind,
        limit,
        used,
        attempted,
        consumer,
    };
    let moment = now();
    let verdict = charge(&request, moment.unix_ms, moment.monotonic_delta_ms)?;
    Ok(verdict.to_value())
}

fn receipt_json_dispatch(args: Vec<Value>) -> StdlibResult {
    let Some(Value::Struct { name, fields }) = args.first() else {
        return Err(format!(
            "intel.receipt_json: argument 1 expected BudgetReceipt, got {}",
            args.first().map(type_name).unwrap_or("nothing")
        ));
    };
    if name != "BudgetReceipt" {
        return Err(format!(
            "intel.receipt_json: argument 1 expected BudgetReceipt, got struct {name}"
        ));
    }
    // Render the receipt the caller holds, field for field. Nothing is
    // reconstructed from constants: the receipt is data, and re-labelling it
    // here would be a second, quieter opinion about what was refused.
    let mut object = serde_json::Map::new();
    for (key, value) in fields {
        let rendered = match value {
            Value::String(s) => serde_json::Value::String(s.clone()),
            Value::Int(i) => serde_json::Value::Number((*i as i64).into()),
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Nil => serde_json::Value::Null,
            other => {
                return Err(format!(
                    "intel.receipt_json: field '{key}' holds {}, which a receipt cannot carry",
                    type_name(other)
                ));
            }
        };
        object.insert(key.clone(), rendered);
    }
    for required in [
        "kind",
        "consumer",
        "used",
        "attempted",
        "overflow",
        "at_unix_ms",
        "monotonic_delta_ms",
    ] {
        if !object.contains_key(required) {
            return Err(format!(
                "intel.receipt_json: receipt is missing `{required}`, so it is not a receipt"
            ));
        }
    }
    let rendered = serde_json::Value::Object(object);
    Ok(Value::String(serde_json::to_string(&rendered).map_err(
        |e| format!("intel.receipt_json: could not serialise the receipt: {e}"),
    )?))
}

fn redact_dispatch(args: Vec<Value>) -> StdlibResult {
    let record = args
        .first()
        .ok_or_else(|| "intel.redact: missing argument 1 (record)".to_string())?;
    let requests = match args.get(1) {
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                Declassification::from_value(item)
                    .map_err(|e| format!("{e} (declassification {})", i + 1))
            })
            .collect::<Result<Vec<_>, _>>()?,
        // No declassification at all is the normal case, not an error: the
        // record is redacted and nothing is released.
        Some(Value::Nil) | None => Vec::new(),
        Some(other) => {
            return Err(format!(
                "intel.redact: argument 2 expected []Declassification, got {}",
                type_name(other)
            ));
        }
    };
    let moment = now();
    Ok(redact_record(record, &requests, moment.unix_ms, moment.monotonic_delta_ms)?.to_value())
}

fn redaction_receipt_json_dispatch(args: Vec<Value>) -> StdlibResult {
    let Some(Value::Struct { name, fields }) = args.first() else {
        return Err(format!(
            "intel.redaction_receipt_json: argument 1 expected RedactionReceipt, got {}",
            args.first().map(type_name).unwrap_or("nothing")
        ));
    };
    if name != "RedactionReceipt" {
        return Err(format!(
            "intel.redaction_receipt_json: argument 1 expected RedactionReceipt, got struct {name}"
        ));
    }
    // Field for field, like `receipt_json`: the receipt is data, and re-deriving
    // any part of it here would be a second opinion about what was released.
    let mut object = serde_json::Map::new();
    for (key, value) in fields {
        let rendered = match value {
            Value::String(s) => serde_json::Value::String(s.clone()),
            Value::Int(i) => serde_json::Value::Number((*i as i64).into()),
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Nil => serde_json::Value::Null,
            other => {
                return Err(format!(
                    "intel.redaction_receipt_json: field '{key}' holds {}, which a receipt cannot carry",
                    type_name(other)
                ));
            }
        };
        object.insert(key.clone(), rendered);
    }
    for required in [
        "field",
        "reason",
        "consumer",
        "at_unix_ms",
        "monotonic_delta_ms",
    ] {
        if !object.contains_key(required) {
            return Err(format!(
                "intel.redaction_receipt_json: receipt is missing `{required}`, so it is not a receipt"
            ));
        }
    }
    let rendered = serde_json::Value::Object(object);
    Ok(Value::String(serde_json::to_string(&rendered).map_err(
        |e| format!("intel.redaction_receipt_json: could not serialise the receipt: {e}"),
    )?))
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: &str = "2026-10-27";

    /// `ScopeRegister` has no public constructor from entries (and `src/scope.rs`
    /// is owned by another lane), so tests load a real register file — the same
    /// code path production uses.
    fn register(name: &str, toml: &str) -> ScopeRegister {
        let dir = std::env::temp_dir().join(format!("tallow-intel-evidence-{name}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("authorized-hosts.toml");
        std::fs::write(&path, toml).expect("write register");
        ScopeRegister::load(&path)
    }

    fn listing(host: &str, expires: Option<&str>) -> String {
        let expiry = match expires {
            Some(d) => format!("expires_at = \"{d}\"\n"),
            None => String::new(),
        };
        format!(
            "[[authorized]]\nhost = \"{host}\"\nbasis = \"ownership\"\ngranted_by = \"operator\"\ngranted_at = \"2026-01-01\"\n{expiry}"
        )
    }

    fn net_grant() -> GrantToken {
        // Exactly what `scope.grant(Net)` puts in the interpreter.
        GrantToken::from_value(&Value::Struct {
            name: "Grant".to_string(),
            fields: vec![("effect".to_string(), Value::String("Net".to_string()))],
        })
        .expect("a Grant struct is a grant")
    }

    fn record(id: &str, target: &str, grant_id: &str) -> EvidenceRecord {
        EvidenceRecord::new(id, target, grant_id)
    }

    /// `Value` has no `PartialEq`, so assertions read named fields.
    fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
        match value {
            Value::Struct { fields, .. } => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn int_field(value: &Value, key: &str) -> Option<i128> {
        match field(value, key) {
            Some(Value::Int(i)) => Some(*i),
            _ => None,
        }
    }

    fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
        match field(value, key) {
            Some(Value::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn bool_field(value: &Value, key: &str) -> Option<bool> {
        match field(value, key) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    fn is_nil(value: &Value, key: &str) -> bool {
        matches!(field(value, key), Some(Value::Nil))
    }

    // ── N38 ──────────────────────────────────────────────────────

    #[test]
    fn intel_evidence_valid_grant_passes() {
        let reg = register("valid", &listing("owned.example", None));
        let records = vec![
            record("r1", "https://owned.example/report", "g-1"),
            record("r2", "owned.example", "g-2"),
        ];
        let outcome = export_records(&records, Some(&net_grant()), &reg, TODAY);
        assert!(outcome.ok(), "refused: {:?}", outcome.refused);
        assert_eq!(outcome.admitted.len(), 2);
        assert!(outcome.refused.is_empty());
        // The value form carries the schema and the admitted count.
        let value = outcome.to_value();
        assert_eq!(int_field(&value, "admitted_count"), Some(2));
        assert_eq!(bool_field(&value, "ok"), Some(true));
        assert_eq!(str_field(&value, "schema"), Some(EXPORT_SCHEMA));
    }

    #[test]
    fn intel_evidence_missing_grant_is_refused() {
        let reg = register("missing-grant", &listing("owned.example", None));
        let records = vec![record("r1", "https://owned.example/report", "g-1")];

        // (a) no token at all
        let outcome = export_records(&records, None, &reg, TODAY);
        assert!(!outcome.ok());
        assert_eq!(outcome.admitted.len(), 0);
        assert_eq!(outcome.refused[0].code, CODE_NO_GRANT);

        // (b) a token for another effect is not authority to export
        let other = GrantToken {
            effect: "Budget".to_string(),
        };
        let outcome = export_records(&records, Some(&other), &reg, TODAY);
        assert_eq!(outcome.refused[0].code, CODE_NO_GRANT);
        assert!(outcome.refused[0].detail.contains("Grant<Budget>"));

        // (c) a live token, but the record claims no grant id
        let unnamed = EvidenceRecord {
            id: "r2".to_string(),
            target: Some("https://owned.example/report".to_string()),
            grant_id: None,
        };
        let outcome = export_records(&[unnamed], Some(&net_grant()), &reg, TODAY);
        assert_eq!(outcome.refused[0].code, CODE_NO_GRANT);
        assert!(outcome.refused[0].detail.contains("no grant id"));

        // (d) a struct that is not named `Grant` is not a grant, even with the field
        let forged = Value::Struct {
            name: "GrantLike".to_string(),
            fields: vec![("effect".to_string(), Value::String("Net".to_string()))],
        };
        assert!(GrantToken::from_value(&forged).is_none());
    }

    #[test]
    fn intel_evidence_expired_grant_is_refused() {
        let reg = register("expired", &listing("owned.example", Some("2026-01-01")));
        let records = vec![record("r1", "https://owned.example/report", "g-1")];
        let outcome = export_records(&records, Some(&net_grant()), &reg, TODAY);
        assert!(!outcome.ok());
        assert_eq!(outcome.refused[0].code, CODE_GRANT_EXPIRED);
        assert_eq!(outcome.refused[0].scope_code, Some("scope:expired"));
        assert!(outcome.refused[0].detail.contains("2026-01-01"));

        // The same entry expiring today is still valid for today.
        let reg = register("expires-today", &listing("owned.example", Some(TODAY)));
        let outcome = export_records(&records, Some(&net_grant()), &reg, TODAY);
        assert!(outcome.ok(), "refused: {:?}", outcome.refused);
    }

    #[test]
    fn intel_evidence_unlisted_target_is_refused() {
        let reg = register("unlisted", &listing("owned.example", None));
        let records = vec![record("r1", "https://other.example/report", "g-1")];
        let outcome = export_records(&records, Some(&net_grant()), &reg, TODAY);
        assert!(!outcome.ok());
        assert_eq!(outcome.refused[0].code, CODE_SCOPE_NOT_LISTED);
        assert_eq!(outcome.refused[0].scope_code, Some("scope:not-listed"));
        assert_eq!(
            outcome.refused[0].target.as_deref(),
            Some("https://other.example/report")
        );

        // A register that could not be read fails closed, and says so.
        let broken = register("broken", "authorized = \"not-a-list\"");
        let outcome = export_records(&records, Some(&net_grant()), &broken, TODAY);
        assert_eq!(outcome.refused[0].code, CODE_SCOPE_NOT_LISTED);
        assert_eq!(
            outcome.refused[0].scope_code,
            Some("scope:register-malformed")
        );
    }

    #[test]
    fn intel_evidence_record_with_no_target_is_refused() {
        let reg = register("no-target", &listing("owned.example", None));
        let records = vec![
            EvidenceRecord {
                id: "r1".to_string(),
                target: None,
                grant_id: Some("g-1".to_string()),
            },
            EvidenceRecord {
                id: "r2".to_string(),
                target: Some("   ".to_string()),
                grant_id: Some("g-1".to_string()),
            },
        ];
        let outcome = export_records(&records, Some(&net_grant()), &reg, TODAY);
        assert!(!outcome.ok());
        assert_eq!(outcome.refused.len(), 2);
        for refusal in &outcome.refused {
            assert_eq!(refusal.code, CODE_NO_TARGET);
            assert_eq!(refusal.scope_code, None);
        }
    }

    // ── N39 ──────────────────────────────────────────────────────

    fn request(limit: Option<i64>, used: i64, attempted: i64) -> BudgetRequest {
        BudgetRequest {
            kind: BudgetKind::Bytes,
            limit,
            used,
            attempted,
            consumer: "topology.connect_scan".to_string(),
        }
    }

    #[test]
    fn intel_evidence_budget_exceeded_returns_fully_populated_receipt() {
        let verdict =
            charge(&request(Some(1000), 900, 400), 1_700_000_000_123, 42).expect("a valid charge");
        assert!(!verdict.allowed);
        assert_eq!(verdict.code, CODE_BUDGET_BYTES_EXCEEDED);
        assert_eq!(verdict.limit, Some(1000));

        let receipt = verdict
            .receipt
            .expect("an exceeded budget carries a receipt");
        assert_eq!(receipt.schema, RECEIPT_SCHEMA);
        assert_eq!(receipt.code, CODE_BUDGET_BYTES_EXCEEDED);
        assert_eq!(receipt.kind, "bytes");
        assert_eq!(receipt.limit, Some(1000));
        assert_eq!(receipt.used, 900);
        assert_eq!(receipt.attempted, 400);
        assert_eq!(receipt.overflow, 300);
        assert_eq!(receipt.consumer, "topology.connect_scan");
        assert_eq!(receipt.at_unix_ms, 1_700_000_000_123);
        assert_eq!(receipt.monotonic_delta_ms, 42);

        // The receipt is data: it serialises, and every field survives.
        let json = receipt.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["schema"], RECEIPT_SCHEMA);
        assert_eq!(parsed["code"], CODE_BUDGET_BYTES_EXCEEDED);
        assert_eq!(parsed["kind"], "bytes");
        assert_eq!(parsed["limit"], 1000);
        assert_eq!(parsed["used"], 900);
        assert_eq!(parsed["attempted"], 400);
        assert_eq!(parsed["overflow"], 300);
        assert_eq!(parsed["consumer"], "topology.connect_scan");
        assert_eq!(parsed["at_unix_ms"], 1_700_000_000_123i64);
        assert_eq!(parsed["monotonic_delta_ms"], 42);
    }

    #[test]
    fn intel_evidence_budget_within_limit_produces_no_receipt() {
        let verdict =
            charge(&request(Some(1000), 100, 200), 1_700_000_000_000, 7).expect("a valid charge");
        assert!(verdict.allowed);
        assert_eq!(verdict.code, CODE_BUDGET_WITHIN);
        assert_eq!(verdict.limit, Some(1000));
        assert!(verdict.receipt.is_none());

        // Exactly at the limit is within it.
        let verdict = charge(&request(Some(1000), 600, 400), 1, 1).expect("a valid charge");
        assert!(verdict.allowed);
        assert!(verdict.receipt.is_none());
    }

    #[test]
    fn intel_evidence_budget_unbounded_is_not_a_refusal() {
        let verdict = charge(&request(None, 10_000_000, 10_000_000), 1, 1).expect("a valid charge");
        assert!(verdict.allowed, "an absent limit is not a refusal");
        assert_eq!(verdict.code, CODE_BUDGET_UNBOUNDED);
        assert_eq!(verdict.limit, None);
        assert!(verdict.receipt.is_none());
    }

    #[test]
    fn intel_evidence_rate_budget_names_its_own_kind() {
        let mut req = request(Some(5), 5, 1);
        req.kind = BudgetKind::Rate;
        req.consumer = "intel.export".to_string();
        let verdict = charge(&req, 99, 3).expect("a valid charge");
        assert!(!verdict.allowed);
        assert_eq!(verdict.code, CODE_BUDGET_RATE_EXCEEDED);
        let receipt = verdict.receipt.expect("receipt");
        assert_eq!(receipt.kind, "rate");
        assert_eq!(receipt.overflow, 1);
        assert_eq!(receipt.consumer, "intel.export");
    }

    #[test]
    fn intel_evidence_budget_rejects_a_negative_limit_rather_than_comparing_it() {
        let err = charge(&request(Some(-1), 0, 1), 1, 1).expect_err("negative limit");
        assert!(err.contains("non-negative"), "got: {err}");
        let err = charge(&request(Some(10), -1, 1), 1, 1).expect_err("negative used");
        assert!(err.contains("non-negative"), "got: {err}");
    }

    // ── dispatch surface ─────────────────────────────────────────

    #[test]
    fn intel_evidence_dispatch_routes_its_three_functions() {
        assert!(dispatch("export", vec![Value::Array(vec![])]).is_some());
        assert!(
            dispatch(
                "budget_charge",
                vec![
                    Value::String("bytes".into()),
                    Value::Int(10),
                    Value::Int(5),
                    Value::Int(1),
                ]
            )
            .is_some()
        );
        assert!(dispatch("nope", vec![]).is_none());
        // The N40 surface routes, and an omitted declassification list is the
        // normal case rather than an argument error.
        let redacted = dispatch(
            "redact",
            vec![Value::Struct {
                name: "EvidenceRecord".into(),
                fields: vec![("api_key".into(), secret("sk-live-abcdef"))],
            }],
        )
        .expect("routed")
        .expect("no argument error");
        assert_eq!(bool_field(&redacted, "ok"), Some(true));
        assert!(str_field(&redacted, "record_json")
            .unwrap_or_default()
            .contains("[redacted:api_key]"));

        // An unbounded call at the dispatch boundary says so, and allows.
        let out = dispatch(
            "budget_charge",
            vec![
                Value::String("rate".into()),
                Value::Nil,
                Value::Int(4),
                Value::Int(9),
            ],
        )
        .expect("routed")
        .expect("no argument error");
        assert!(matches!(out, Value::Struct { .. }));
        assert_eq!(bool_field(&out, "allowed"), Some(true));
        assert_eq!(str_field(&out, "code"), Some(CODE_BUDGET_UNBOUNDED));
        assert!(is_nil(&out, "receipt"));
        assert!(is_nil(&out, "limit"));

        // A crossed limit at the dispatch boundary carries a receipt that names
        // the consumer the runtime dispatched (no consumer argument supplied).
        let exceeded = dispatch(
            "budget_charge",
            vec![
                Value::String("bytes".into()),
                Value::Int(64),
                Value::Int(60),
                Value::Int(9),
            ],
        )
        .expect("routed")
        .expect("no argument error");
        assert_eq!(bool_field(&exceeded, "allowed"), Some(false));
        assert_eq!(
            str_field(&exceeded, "code"),
            Some(CODE_BUDGET_BYTES_EXCEEDED)
        );
        let receipt = field(&exceeded, "receipt").expect("a receipt on refusal");
        assert_eq!(str_field(receipt, "consumer"), Some("intel.budget_charge"));
        assert_eq!(str_field(receipt, "kind"), Some("bytes"));
        assert_eq!(int_field(receipt, "overflow"), Some(5));
        assert_eq!(int_field(receipt, "limit"), Some(64));
        assert_eq!(int_field(receipt, "attempted"), Some(9));
        assert!(int_field(receipt, "at_unix_ms").unwrap_or(0) > 0);
        // The monotonic delta is measured, not fabricated: it may be 0 ms on a
        // fast box, but the field must exist and be non-negative.
        assert!(int_field(receipt, "monotonic_delta_ms").unwrap_or(-1) >= 0);

        // And the receipt serialises through the runtime surface.
        let json = dispatch("receipt_json", vec![receipt.clone()])
            .expect("routed")
            .expect("serialisable");
        match json {
            Value::String(s) => {
                let parsed: serde_json::Value = serde_json::from_str(&s).expect("valid json");
                assert_eq!(parsed["consumer"], "intel.budget_charge");
                assert_eq!(parsed["code"], CODE_BUDGET_BYTES_EXCEEDED);
                assert_eq!(parsed["overflow"], 5);
            }
            other => panic!("expected a JSON string, got {}", type_name(&other)),
        }
    }

    #[test]
    fn intel_evidence_module_is_registered_and_names_are_stable() {
        assert!(crate::stdlib::is_registered_module(RUNTIME_MODULE));
        assert_eq!(CODE_NO_GRANT, "export:no-grant");
        assert_eq!(CODE_GRANT_EXPIRED, "export:grant-expired");
        assert_eq!(CODE_SCOPE_NOT_LISTED, "export:scope-not-listed");
        assert_eq!(CODE_NO_TARGET, "export:no-target");
        assert_eq!(CODE_BUDGET_UNBOUNDED, "budget:unbounded");
        assert_eq!(CODE_REDACT_NO_REASON, "redact:no-reason");
        assert_eq!(CODE_REDACT_NO_CONSUMER, "redact:no-consumer");
        assert_eq!(CODE_REDACT_UNKNOWN_FIELD, "redact:unknown-field");
        assert_eq!(CODE_REDACT_DECLASSIFIED, "redact:declassified");
    }

    // ── N40 ──────────────────────────────────────────────────────

    /// A value the runtime wraps at a cast to a secret-qualified type.
    fn secret(s: &str) -> Value {
        Value::Secret(Box::new(Value::String(s.to_string())))
    }

    fn evidence_record(fields: Vec<(&str, Value)>) -> Value {
        Value::Struct {
            name: "EvidenceRecord".to_string(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    fn decl(field: &str, reason: Option<&str>, consumer: Option<&str>) -> Declassification {
        Declassification {
            field: field.to_string(),
            reason: reason.map(str::to_string),
            consumer: consumer.map(str::to_string),
        }
    }

    fn parsed(outcome: &RedactionOutcome) -> serde_json::Value {
        serde_json::from_str(&outcome.record_json).expect("the redacted record is JSON")
    }

    #[test]
    fn intel_evidence_redact_withholds_secrets_and_leaves_unknown_fields_alone() {
        let record = evidence_record(vec![
            ("id", Value::String("r1".into())),
            ("api_key", secret("sk-live-abcdef123456")),
            // A field whose name looks secret but which the runtime does not
            // classify: it is public evidence and must survive.
            ("csrf_token", Value::String("public-token-value".into())),
            (
                "keypair",
                Value::Struct {
                    name: "AgeKeypair".to_string(),
                    fields: vec![
                        ("recipient".into(), Value::String("age1public".into())),
                        // Withheld by `secret_fields::SECRET_FIELDS`, a table the
                        // runtime owns — not by a guess about the name.
                        (
                            "identity".into(),
                            Value::String("AGE-SECRET-KEY-1PRIVATE".into()),
                        ),
                    ],
                },
            ),
        ]);
        let outcome = redact_record(&record, &[], 1_700_000_000_000, 5).expect("redacts");
        assert!(outcome.ok());
        assert_eq!(
            outcome.redacted_fields,
            vec!["api_key".to_string(), "keypair.identity".to_string()]
        );
        assert!(outcome.released_fields.is_empty());
        assert!(outcome.receipts.is_empty());

        // Neither the value nor a prefix of it survives, and no length either.
        assert!(!outcome.record_json.contains("sk-live"));
        assert!(!outcome.record_json.contains("PRIVATE"));
        let json = parsed(&outcome);
        assert_eq!(json["api_key"], "[redacted:api_key]");
        assert_eq!(json["keypair"]["identity"], "[redacted:keypair.identity]");
        assert_eq!(json["csrf_token"], "public-token-value");
        assert_eq!(json["keypair"]["recipient"], "age1public");
        assert_eq!(json["id"], "r1");

        // The value form carries the schema, the flag and the same rendering.
        let value = outcome.to_value();
        assert_eq!(str_field(&value, "schema"), Some(REDACTION_SCHEMA));
        assert_eq!(bool_field(&value, "ok"), Some(true));
        assert_eq!(
            str_field(&value, "record_json"),
            Some(outcome.record_json.as_str())
        );
    }

    #[test]
    fn intel_evidence_declassification_releases_a_field_and_records_the_act() {
        let record = evidence_record(vec![
            ("api_key", secret("sk-live-abcdef")),
            ("id", Value::String("r1".into())),
        ]);
        let requests = vec![
            Declassification::new(
                "api_key",
                "the account owner asked for their own key",
                "billing.exporter",
            ),
            // A field that was never withheld: accepted, nothing to record.
            Declassification::new("id", "not withheld anyway", "billing.exporter"),
        ];
        let outcome = redact_record(&record, &requests, 1_700_000_000_123, 42).expect("redacts");
        assert!(outcome.ok(), "refused: {:?}", outcome.refused);
        assert_eq!(parsed(&outcome)["api_key"], "sk-live-abcdef");
        assert!(outcome.redacted_fields.is_empty());
        assert_eq!(outcome.released_fields, vec!["api_key".to_string()]);

        assert_eq!(outcome.receipts.len(), 1);
        let receipt = &outcome.receipts[0];
        assert_eq!(receipt.schema, DECLASSIFICATION_SCHEMA);
        assert_eq!(receipt.code, CODE_REDACT_DECLASSIFIED);
        assert_eq!(receipt.field, "api_key");
        assert_eq!(receipt.reason, "the account owner asked for their own key");
        assert_eq!(receipt.consumer, "billing.exporter");
        assert_eq!(receipt.at_unix_ms, 1_700_000_000_123);
        assert_eq!(receipt.monotonic_delta_ms, 42);

        // And the receipt is portable on its own.
        let receipt_json: serde_json::Value =
            serde_json::from_str(&receipt.to_json()).expect("receipt json");
        assert_eq!(receipt_json["consumer"], "billing.exporter");
        assert_eq!(receipt_json["code"], CODE_REDACT_DECLASSIFIED);
    }

    #[test]
    fn intel_evidence_declassification_without_authority_is_refused_not_defaulted() {
        let record = evidence_record(vec![
            ("api_key", secret("sk-live-abcdef")),
            ("session_key", secret("sess-xyz")),
            ("export_key", secret("export-xyz")),
        ]);
        let requests = vec![
            decl("api_key", None, Some("billing.exporter")),
            decl("session_key", Some("rotation audit"), None),
            // Blank is not a reason.
            decl("export_key", Some("   "), Some("billing.exporter")),
            decl("nope", Some("wanted it"), Some("billing.exporter")),
            decl("", Some("wanted it"), Some("billing.exporter")),
            // A second mention of an already-named field.
            decl("api_key", Some("second opinion"), Some("other.exporter")),
        ];
        let outcome = redact_record(&record, &requests, 1, 1).expect("redacts");
        assert!(!outcome.ok());
        let codes: Vec<&str> = outcome.refused.iter().map(|r| r.code).collect();
        assert_eq!(
            codes,
            vec![
                CODE_REDACT_NO_REASON,
                CODE_REDACT_NO_CONSUMER,
                CODE_REDACT_NO_REASON,
                CODE_REDACT_UNKNOWN_FIELD,
                CODE_REDACT_UNKNOWN_FIELD,
                CODE_REDACT_DUPLICATE_FIELD,
            ]
        );
        // Fail-closed: a refusal releases nothing, so every secret stays withheld.
        assert!(outcome.receipts.is_empty());
        assert!(outcome.released_fields.is_empty());
        assert_eq!(outcome.redacted_fields.len(), 3);
        assert!(!outcome.record_json.contains("sk-live"));
        assert_eq!(parsed(&outcome)["api_key"], "[redacted:api_key]");
    }

    #[test]
    fn intel_evidence_redaction_receipt_json_renders_the_receipt() {
        let record = evidence_record(vec![("api_key", secret("sk-live-abcdef"))]);
        let requests = vec![Declassification::new(
            "api_key",
            "audited",
            "billing.exporter",
        )];
        let value = redact_record(&record, &requests, 7, 3)
            .expect("redacts")
            .to_value();
        let Value::Array(receipts) = field(&value, "receipts").expect("receipts") else {
            panic!("receipts must be an array");
        };
        assert_eq!(receipts.len(), 1);

        let rendered = dispatch("redaction_receipt_json", vec![receipts[0].clone()])
            .expect("routed")
            .expect("renders");
        let Value::String(rendered) = rendered else {
            panic!("expected a JSON string");
        };
        let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(json["field"], "api_key");
        assert_eq!(json["reason"], "audited");
        assert_eq!(json["consumer"], "billing.exporter");
        assert_eq!(json["code"], CODE_REDACT_DECLASSIFIED);
        assert_eq!(json["at_unix_ms"], 7);

        // A struct that is not a receipt is refused, not rendered.
        let not_a_receipt = evidence_record(vec![("field", Value::String("api_key".into()))]);
        let err = dispatch("redaction_receipt_json", vec![not_a_receipt])
            .expect("routed")
            .expect_err("not a receipt");
        assert!(err.contains("RedactionReceipt"), "got: {err}");
    }
}
