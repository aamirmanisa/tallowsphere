// Tallow Standard Library — Container & Cloud Security (Phase 42)
// Cloud security types, container verification, and policy enforcement primitives.
//
// All types are interpreter sentinels — no stdlib module dispatch needed.

// ── IacScanner — Infrastructure as Code security scanning ─────────────────────
// IacScanner.check(config_string: String) -> IacResult
//   Scans IaC config (Terraform/CloudFormation-like) for security misconfigurations.

struct IacResult {
    findings:       []IacFinding,
    critical_count: i64,
    high_count:     i64,
    medium_count:   i64,
    low_count:      i64,
    total:          i64,
    passed:         bool,
}

struct IacFinding {
    rule:     String,
    severity: String,
    message:  String,
    line:     i64,
}

// ── CloudPolicy — Cloud security policy enforcement ───────────────────────────
// CloudPolicy.create(name: String, rules_json: String) -> CloudPolicy
// CloudPolicy.enforce(policy: CloudPolicy, resource: String) -> PolicyResult

struct CloudPolicy {
    name:        String,
    rules:       []PolicyRule,
    rules_count: i64,
}

struct PolicyRule {
    id:       String,
    check:    String,
    severity: String,
}

struct PolicyResult {
    policy_name: String,
    resource:    String,
    passed:      bool,
    violations:  []String,
    score:       i64,
}

// ── IdentityAudit — Cloud identity/IAM audit ─────────────────────────────────
// IdentityAudit.analyze(principals_json: String) -> IdentityAuditResult

struct IdentityAuditResult {
    principals_count:  i64,
    over_privileged:   []String,
    graph_depth:       i64,
    risk_score:        f64,
}

// ── StorageScan — Cloud storage security scanning ─────────────────────────────
// StorageScan.check(bucket_config: String) -> StorageScanResult

struct StorageScanResult {
    bucket_name:   String,
    public_access: bool,
    encryption:    String,
    versioning:    bool,
    logging:       bool,
    risk_level:    String,
}

// ── ServiceMesh — Service mesh verification ───────────────────────────────────
// ServiceMesh.verify(mesh_config: String) -> ServiceMeshResult

struct ServiceMeshResult {
    mesh_name:    String,
    mtls_enabled: bool,
    policies:     []String,
    services:     i64,
    compliant:    bool,
}

// ── CloudTrail — Cloud audit trail anomaly detection ──────────────────────────
// CloudTrail.analyze(events_json: String) -> CloudTrailResult
//   Uses z-score anomaly detection on event frequency.

struct CloudTrailResult {
    total_events:     i64,
    anomalies:        []CloudTrailAnomaly,
    suspicious_events: []String,
    risk_score:       f64,
}

struct CloudTrailAnomaly {
    event_type: String,
    count:      i64,
    z_score:    f64,
    flagged:    bool,
}

// ── SeccompProfile — Seccomp BPF profile generation ───────────────────────────
// SeccompProfile.generate(allowed_syscalls: String) -> SeccompProfile
//   Generates simulated BPF bytecode via BLAKE3 hash.

struct SeccompProfile {
    default_action: String,
    syscalls:       []String,
    bpf_bytecode:   String,
    syscall_count:  i64,
}

// ── ContainerImage — Container image verification ─────────────────────────────
// ContainerImage.verify(image_hash: String, expected_hash: String) -> Bool
//   OCI SHA-256 digest comparison.

// ── EbpfPolicy — eBPF security policy compilation ────────────────────────────
// EbpfPolicy.compile(rules: String) -> EbpfPolicy

struct EbpfPolicy {
    rules:        []String,
    bytecode:     String,
    rules_count:  i64,
    compiled:     bool,
}
