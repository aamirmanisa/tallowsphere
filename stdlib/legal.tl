// tallow.legal — @legal runtime + audit record persistence
//
// Runtime half of the @legal system. Compile-time annotation checks run in
// the legal/consent/erasure AST passes; this module's functions persist
// audit, consent, and erasure records to the legal data directory
// (env TALLOW_LEGAL_DIR, default ~/.tallow/legal) as JSONL files:
//   - log_audit            → audit_log.jsonl
//   - read_audit_log       → reads audit_log.jsonl back
//   - consent_register/consent_check → consent_register.jsonl
//   - erasure_request / subject_access_request → erasure_requests.jsonl
// Report-generation / DORA / AI-Act / model-provenance functions are NOT
// implemented by this backend and return an honest error when called.

/// Legal basis values (corresponds to GDPR Art.6)
enum Basis {
    PublicData,          // hiQ v. LinkedIn precedent
    Consent,             // explicit user consent
    LegitimateInterest,  // requires LIA completion
    Research,            // academic/journalistic
    Contract,            // contractual necessity
    VitalInterests,      // emergency situations
    LegalObligation,     // required by law
}

/// Jurisdiction values
enum Jurisdiction {
    US,     // CCPA, CFAA
    EU,     // GDPR
    UK,     // UK GDPR
    CA,     // PIPEDA
    AU,     // Privacy Act 1988
    BR,     // LGPD
    JP,     // APPI
    SG,     // PDPA
    CN,     // PIPL
    Global, // most restrictive of all applicable
}

/// Audit log entry persisted by log_audit / read back by read_audit_log
struct AuditEntry {
    timestamp:         String,
    function:          String,
    legal_basis:       String,
    purpose:           String,
    personal_data:     bool,
    jurisdiction:      []String,
    robots_txt:        String,
    rate_limit:        String?,
    retain_until:      String?,
    records_processed: u64,
    compliance_status: String,
    tallow_version:      String,
}

/// Write audit entry to the JSONL audit log (TALLOW_LEGAL_DIR/audit_log.jsonl)
fn log_audit(entry: AuditEntry) -> Result<()> {
    // native: appends one JSON object per line, returns Ok(())
}

/// Read audit log entries back from the JSONL audit log (default
/// TALLOW_LEGAL_DIR/audit_log.jsonl when path is empty)
fn read_audit_log(path: String) -> Result<[]AuditEntry> {
    // native: parses each JSONL line into an AuditEntry struct
}

/// Record explicit consent (GDPR Art.6/7, CCPA) — appends to
/// TALLOW_LEGAL_DIR/consent_register.jsonl and returns a record id
fn consent_register(subject: String, purpose: String) -> String {
    // native: persists {subject, purpose, status: registered, registered_at}
}

/// True iff the consent register holds a current registration for the
/// subject + purpose pair
fn consent_check(subject: String, purpose: String) -> Bool {
    // native: answers from consent_register.jsonl
}

/// Log a GDPR right-to-erasure request (Art.17) — appends to
/// TALLOW_LEGAL_DIR/erasure_requests.jsonl and returns a request id
fn erasure_request(subject: String) -> String {
    // native: persists {subject, status: requested, requested_at}
}

/// Log a GDPR subject-access request (Art.15) — same register as erasure
/// requests, distinct event type; returns a request id
fn subject_access_request(subject: String) -> String {
    // native: persists {event: subject_access_request, ...}
}

/// Generate compliance report
fn generate_report(entries: []AuditEntry) -> String {
    // native: generates human-readable compliance report
}

/// Check compliance for jurisdiction
fn check_compliance(entries: []AuditEntry, jurisdiction: Jurisdiction) -> ComplianceResult {
    // native: validates entries against jurisdiction rules
}

struct ComplianceResult {
    compliant:  bool,
    violations: []String,
    warnings:   []String,
}

// ── CRA (Cyber Resilience Act, EU 2024/2847) ──────────────────────

/// CRA product classification per Annex III/IV
enum CraClass {
    Default,         // general digital product
    ClassI,          // Annex III Class I (password managers, VPNs, etc.)
    ClassII,         // Annex III Class II (firewalls, IDS, HSMs, etc.)
    Critical,        // Annex IV critical products (smart meters, gateways)
}

/// CRA compliance report
struct CraReport {
    product_class:     CraClass,
    sbom_generated:    bool,
    vuln_handling:     bool,
    secure_defaults:   bool,
    update_capability: bool,
    annex_i_items:     []CraCheckItem,
}

struct CraCheckItem {
    requirement: String,
    status:      String,  // "pass" | "fail" | "n/a"
    notes:       String,
}

/// Generate CRA compliance report for the current project
fn cra_audit() -> CraReport {
    // native: runs CRA compliance checks and returns structured report
}

// ── NIS2 Directive (EU 2022/2555) ──────────────────────────────────

/// BSI TR-02102 algorithm recommendation status
enum BsiStatus {
    Recommended,
    Acceptable,
    Deprecated,
    Forbidden,
}

/// Crypto algorithm policy entry
struct AlgorithmPolicy {
    name:        String,
    status:      BsiStatus,
    note:        String,
    replacement: String?,
}

/// NIS2 Art.21 compliance report
struct Nis2Report {
    crypto_inventory: []AlgorithmPolicy,
    deprecated_count: u32,
    forbidden_count:  u32,
    art21_measures:   []Nis2Measure,
}

struct Nis2Measure {
    article: String,
    measure: String,
    status:  String,  // "compliant" | "non_compliant" | "partial"
}

/// Generate NIS2 Art.21 compliance report
fn nis2_audit() -> Nis2Report {
    // native: collects crypto inventory and checks BSI TR-02102 compliance
}

// ── DORA (Digital Operational Resilience Act, EU 2022/2554) ────────

/// DORA ICT incident severity per RTS criteria
enum DoraSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// DORA ICT incident record per Art.19
struct DoraCitIncident {
    id:                          String,
    detection_time:              String,
    classification_time:         String?,
    description:                 String,
    severity:                    DoraSeverity,
    affected_clients_pct:        f64,
    duration_hours:              f64,
    financial_impact:            f64,
    data_records_affected:       i64,
    cross_border:                bool,
    critical_function_impaired:  bool,
    root_cause:                  String?,
    recovery_actions:            []String,
    notification_status:         String,
}

/// Create a new ICT incident with auto-generated ID and timestamp
fn dora_incident_new(description: String) -> DoraCitIncident {
    // native: creates incident with UUID and ISO-8601 detection_time
}

/// Auto-classify incident severity per DORA RTS criteria
/// CRITICAL: critical_function_impaired AND (duration > 24h OR records > 100K)
/// HIGH:     critical_function_impaired OR clients > 10% OR records > 5,000
/// MEDIUM:   clients > 1% OR duration > 2h OR cross_border
/// LOW:      all other incidents
fn dora_classify(incident: DoraCitIncident) -> DoraCitIncident {
    // native: updates severity and classification_time
}

/// Generate DORA-compliant incident report JSON for regulatory notification
fn dora_report(incident: DoraCitIncident) -> String {
    // native: serializes incident to JSON per DORA Art.19 format
}

// ── EU AI Act (Regulation 2024/1689) ────────────────────────────

/// AI system risk classification per Art.6
enum AiRiskLevel {
    Prohibited,    // Art.5 — banned AI practices
    High,          // Annex III — biometrics, critical infra, employment, etc.
    Limited,       // Art.50 — transparency obligations
    Minimal,       // No specific obligations
}

/// AI system registration for EU database (Art.71)
struct AiSystemInfo {
    system_id:       String,
    risk:            AiRiskLevel,
    purpose:         String,
    deployer_info:   bool,
    art9_compliant:  bool,
}

// ── EU AI Act — Art.12 Inference Logging ────────────────────────

/// AI inference log entry (Art.12 record-keeping)
struct InferenceEntry {
    timestamp:   String,
    input_hash:  String,   // BLAKE3 hash (privacy: no raw input)
    output:      String,
    entry_hash:  String,   // chain hash for tamper evidence
}

/// AI inference log with tamper-evident hash chain
struct AiInferenceLog {
    system_id:  String,
    entries:    []InferenceEntry,
    hash_chain: String,
    created_at: String,
}

/// Create a new inference log for an AI system
fn ai_inference_log_create(system_id: String) -> AiInferenceLog {
    // native: creates log with genesis hash chain
}

/// Log an inference event (input hashed for privacy)
fn ai_inference_log_entry(log: AiInferenceLog, input: String, output: String) -> AiInferenceLog {
    // native: appends entry with BLAKE3 chain hash
}

/// Verify log integrity (recompute hash chain)
fn ai_inference_log_verify(log: AiInferenceLog) -> bool {
    // native: returns true if hash chain is valid
}

/// Export log as JSON for Art.12 audit
fn ai_inference_log_export(log: AiInferenceLog) -> String {
    // native: JSON serialization
}

// ── EU AI Act — Art.14 Human Oversight ──────────────────────────

/// Human approval gate result
struct HumanApproval {
    decision:  String,
    subject:   String,
    reason:    String,
    approved:  bool,
    reviewer:  String,
    timestamp: String,
}

/// Request human approval for a high-risk decision (Art.14)
fn human_approval_request(decision: String, subject: String, reason: String) -> HumanApproval {
    // native: blocks until human approves (auto-approves in interpreter)
}

// ── EU AI Act — Annex IV Model Provenance ───────────────────────

/// Model provenance chain (Annex IV technical documentation)
struct ModelProvenance {
    model_id:      String,
    training_data: String,
    pipeline:      String,
    metrics:       String,
    deployer:      String,
    created_at:    String,
    attestation:   String,   // BLAKE3 hash of all fields
    attested_at:   String,
}

/// Create a new model provenance record
fn model_provenance_create(model_id: String) -> ModelProvenance {
    // native: creates provenance with empty fields
}

/// Set a provenance field (immutable update)
fn model_provenance_set(prov: ModelProvenance, field: String, value: String) -> ModelProvenance {
    // native: returns updated provenance
}

/// Attest provenance with BLAKE3 cryptographic hash
fn model_provenance_attest(prov: ModelProvenance) -> ModelProvenance {
    // native: computes attestation hash of all fields
}

/// Verify attestation integrity
fn model_provenance_verify(prov: ModelProvenance) -> bool {
    // native: recomputes and compares attestation hash
}

/// Export provenance as JSON (for Annex IV documentation)
fn model_provenance_export(prov: ModelProvenance) -> String {
    // native: JSON serialization of provenance chain
}
