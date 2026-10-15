// Tallow Standard Library — Detection Engineering (Phase 39)
// Threat hunting types and detection engineering primitives.
//
// All types are interpreter sentinels — no stdlib module dispatch needed.

// ── YaraRule — Simulated YARA-X rule execution ───────────────────────────────
// YaraRule.compile(rule_string: String) -> YaraRule
// YaraRule.scan(rule: YaraRule, data: String) -> []YaraMatch
// YaraRule.match_count(result: []YaraMatch) -> Int

struct YaraRule {
    rule_name:      String,
    patterns_count: i64,
    source:         String,
    compiled:       bool,
}

struct YaraMatch {
    pattern_name: String,
    matched_data: String,
    offset:       i64,
}

// ── SigmaRule — Sigma detection rule with multi-target emission ──────────────
// SigmaRule.parse(yaml_string: String) -> SigmaRule
// SigmaRule.emit(rule: SigmaRule, target: String) -> String
//   targets: "splunk" (SPL), "elastic" (KQL), "sentinel" (KQL)
// SigmaRule.validate(rule: SigmaRule) -> Bool

struct SigmaRule {
    title:         String,
    status:        String,
    level:         String,
    logsource:     String,
    has_detection: bool,
    source:        String,
    valid:         bool,
}

// ── HuntHypothesis — Threat hunting workflow ─────────────────────────────────
// HuntHypothesis.create(name: String, description: String) -> HuntHypothesis
// HuntHypothesis.set_field(hyp: HuntHypothesis, field: String, value: any) -> HuntHypothesis
// HuntHypothesis.test(hyp: HuntHypothesis, evidence: []any) -> HuntResult

struct HuntHypothesis {
    id:            String,
    name:          String,
    description:   String,
    status:        String,
    confidence:    f64,
    evidence:      []String,
    mitre_tactics: []String,
    created:       String,
}

struct HuntResult {
    hypothesis:     String,
    status:         String,
    confidence:     f64,
    evidence_count: i64,
}

// ── LogQuery — Structured log querying ───────────────────────────────────────
// LogQuery.create(source: String, query_string: String) -> LogQuery
// LogQuery.execute(query: LogQuery) -> LogQueryResult

struct LogQuery {
    source:   String,
    query:    String,
    executed: bool,
}

struct LogQueryResult {
    source:      String,
    query:       String,
    matches:     i64,
    executed_at: String,
    success:     bool,
}

// ── AnomalyDetector — Statistical anomaly detection ─────────────────────────
// AnomalyDetector.create(method: String) -> AnomalyDetector
//   methods: "zscore" (mean ± 2*stddev), "iqr" (Q1-1.5*IQR to Q3+1.5*IQR)
// AnomalyDetector.add_datapoint(detector: AnomalyDetector, value: f64) -> AnomalyDetector
// AnomalyDetector.detect(detector: AnomalyDetector, value: f64) -> Bool
// AnomalyDetector.threshold(detector: AnomalyDetector) -> f64

struct AnomalyDetector {
    method:     String,
    datapoints: []f64,
}

// ── BehaviorChain — Temporal pattern detection ───────────────────────────────
// BehaviorChain.create(name: String) -> BehaviorChain
// BehaviorChain.add_event(chain: BehaviorChain, event_type: String, timestamp: String) -> BehaviorChain
// BehaviorChain.matches_pattern(chain: BehaviorChain, pattern: []String) -> Bool

struct BehaviorChain {
    name:        String,
    events:      []ChainEvent,
    event_count: i64,
}

struct ChainEvent {
    event_type: String,
    timestamp:  String,
}

// ── ThreatModel — STRIDE threat modeling ─────────────────────────────────────
// ThreatModel.create(system_name: String) -> ThreatModel
// ThreatModel.add_threat(model: ThreatModel, category: String, description: String) -> ThreatModel
//   STRIDE categories: S (Spoofing), T (Tampering), R (Repudiation),
//                       I (Info Disclosure), D (Denial of Service), E (Elevation of Privilege)
// ThreatModel.analyze(model: ThreatModel) -> ThreatAnalysis

struct ThreatModel {
    system_name:  String,
    threats:      []Threat,
    threat_count: i64,
}

struct Threat {
    category:      String,
    category_name: String,
    description:   String,
}

struct ThreatAnalysis {
    system_name:       String,
    threat_count:      i64,
    categories_covered: i64,
    stride_coverage:   f64,
    risk_level:        String,
    threats:           []Threat,
}

// ── HuntNotebook — Investigation lifecycle ───────────────────────────────────
// HuntNotebook.create(title: String) -> HuntNotebook
// HuntNotebook.add_finding(notebook: HuntNotebook, finding: String) -> HuntNotebook
// HuntNotebook.conclude(notebook: HuntNotebook, conclusion: String) -> HuntReport

struct HuntNotebook {
    id:         String,
    title:      String,
    status:     String,
    findings:   []String,
    conclusion: String?,
    created:    String,
}

struct HuntReport {
    title:          String,
    status:         String,
    findings_count: i64,
    conclusion:     String,
    report:         String,
}
