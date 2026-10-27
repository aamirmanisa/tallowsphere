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
