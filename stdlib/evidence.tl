// tallow.intel — grant-bound evidence export and budget refusal receipts.
//
// Two properties this module makes checkable rather than assertable.
//
// N38 — evidence cannot leave the process on a dead grant. `intel.export`
// re-consults the same scope register (`configs/tallow/scope/authorized-hosts.toml`)
// that the topology plane consults before a packet is built, at export time
// rather than at collection time. A record is refused when the presented value
// is not a live `Grant<Net>`, when the record claims no grant id, when it names
// no target, or when the register no longer covers the record's target — and
// the refusal says which of those failed: `export:no-grant`,
// `export:grant-expired`, `export:scope-not-listed`, `export:no-target`.
// An absent target is a refusal, not a pass. `ok` is false if any record was
// refused, so a partial export cannot be mistaken for a clean one.
//
// N39 — a budget refusal carries its own receipt. `intel.budget_charge` takes
// the limit from its arguments and nothing else: no limit means
// `budget:unbounded` and an allowed call, not a refusal. A crossed limit
// returns a BudgetReceipt as data — kind, limit, used, attempted, overflow,
// consumer, unix ms and a monotonic delta — which `intel.receipt_json` renders
// for a human. Every field of a receipt is populated at refusal time.
//
// The grant value is never produced here: `scope.grant(Net)` is its only
// producer, and a native declaration cannot return a `Grant` (E0145).
//
// N40 — a secret field never serialises without a recorded declassification.
// `intel.redact` returns the record with every field the runtime knows to be
// secret replaced by `[redacted:<field>]`: an at-run-time `Secret` value, or a
// field named by `secret_fields::SECRET_FIELDS` for the enclosing struct. The
// marker names the field and carries no character, length or prefix of the
// value. A field is released in the clear only by a Declassification naming it
// with a reason and a consumer; each release produces a RedactionReceipt
// recording field, reason, consumer and unix ms. A missing reason or consumer,
// an unnamed or absent field, or a second mention of the same field is a coded
// refusal (`redact:no-reason`, `redact:no-consumer`, `redact:unknown-field`,
// `redact:duplicate-field`) and a refusal releases nothing. Unknown fields pass
// through unchanged: this module never guesses that a field is secret from its
// name, because a wrong guess either destroys readable evidence or makes the
// receipt describe a heuristic instead of an authority.

// One collected record offered for export. `target` and `grant_id` are
// optional in the type on purpose: an omitted field must be refused with a
// code that names it, never defaulted into a permission.
struct EvidenceRecord {
    id:       String,
    target:   String?,
    grant_id: String?,
}

// Why one record was refused. `code` is one of the four `export:*` codes above;
// `scope_code` carries the register's own code (`scope:not-listed`,
// `scope:expired`, `scope:register-unreadable`, ...) when the register decided.
struct ExportRefusal {
    record_id:  String,
    target:     String?,
    code:       String,
    detail:     String,
    scope_code: String?,
}

// The gate's answer. `ok` is true only when `refused` is empty.
struct ExportOutcome {
    schema:         String,
    ok:             Bool,
    admitted_count: Int,
    admitted:       []EvidenceRecord,
    refused:        []ExportRefusal,
}

// The refusal, as data. `at_unix_ms` is the wall-clock moment; `monotonic_delta_ms`
// is milliseconds since this process's evidence-clock origin (monotonic, not
// comparable across processes — both travel for that reason).
struct BudgetReceipt {
    schema:             String,
    code:               String,
    kind:               String,
    limit:              Int?,
    used:               Int,
    attempted:          Int,
    overflow:           Int,
    consumer:           String,
    at_unix_ms:         Int,
    monotonic_delta_ms: Int,
}

// The charge decision. `receipt` is non-nil exactly when the budget was
// exceeded: a within-budget call produces none, and so does an unbounded one.
struct BudgetOutcome {
    schema:  String,
    allowed: Bool,
    code:    String,
    limit:   Int?,
    receipt: BudgetReceipt?,
}

// Export evidence under a grant. `grant` must be a live Grant<Net> minted by
// scope.grant(Net); the record's target must still be covered by the scope
// register today. Returns per-record admissions and refusals.
native fn intel.export(records: []EvidenceRecord, grant: Grant<Net>) -> ExportOutcome

// Charge one attempt against a byte or rate budget. `kind` is "bytes" or
// "rate"; `limit` is the ceiling the caller supplies (nil = no ceiling, which
// is reported as budget:unbounded and is not a refusal); `used` is what the
// caller has already spent in its own window; `attempted` is this call.
// `consumer` defaults to the runtime dispatch name "intel.budget_charge".
native fn intel.budget_charge(kind: String, limit: Int?, used: Int, attempted: Int, consumer: String?) -> BudgetOutcome

// Render a receipt to JSON so it can be shown to someone. Renders the receipt
// it is given, field for field; it does not re-derive or relabel anything.
native fn intel.receipt_json(receipt: BudgetReceipt) -> String

// One request to release a withheld field in the clear. `reason` and `consumer`
// are optional in the type so that their absence is a coded refusal rather than
// a default — the same shape as EvidenceRecord.grant_id.
struct Declassification {
    field:    String,
    reason:   String?,
    consumer: String?,
}

// A released secret, and the authority that released it.
struct RedactionReceipt {
    schema:             String,
    code:               String,
    field:              String,
    reason:             String,
    consumer:           String,
    at_unix_ms:         Int,
    monotonic_delta_ms: Int,
}

// Why one declassification was refused. The field stays withheld: a refusal
// never releases anything.
struct RedactionRefusal {
    code:   String,
    field:  String,
    detail: String,
}

// The redacted record — as JSON, the only form it leaves in, so that no second
// copy of an unreleased secret travels — plus what was withheld, released and
// refused. `ok` is false if any declassification was refused, even though the
// record still renders.
struct RedactionOutcome {
    schema:          String,
    ok:              Bool,
    record_json:     String,
    redacted_fields: []String,
    released_fields: []String,
    receipts:        []RedactionReceipt,
    refused:         []RedactionRefusal,
}

// Redact an evidence record. Pass `[]` in `declassify` to release nothing.
// Fields are addressed by name, or by dotted path for a nested field
// (`keypair.identity`).
native fn intel.redact(record: EvidenceRecord, declassify: []Declassification) -> RedactionOutcome

// Render a declassification receipt to JSON, field for field, exactly as
// intel.receipt_json does for a budget receipt.
native fn intel.redaction_receipt_json(receipt: RedactionReceipt) -> String
