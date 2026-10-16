// Tallow Standard Library — Observability & Telemetry (Phase 41)
// Distributed tracing, metrics, SLI/SLO, alerting, and health check primitives.
//
// All types are interpreter sentinels — no stdlib module dispatch needed.

// ── Span — Distributed tracing spans ─────────────────────────────────────────
// Span.start(name: String, trace_id: String) -> Span
// Span.end(span: Span) -> Span (with duration_ms computed)
// Span.add_attribute(span: Span, key: String, value: String) -> Span

struct Span {
    span_id:      String,
    trace_id:     String,
    name:         String,
    start_time:   i64,
    end_time:     i64,
    duration_ms:  i64,
    status:       String,
    attributes:   Map<String, String>,
}

// ── Metric — Metrics collection (counter, gauge, histogram) ──────────────────
// Metric.counter(name: String, value: f64) -> Metric
// Metric.gauge(name: String, value: f64) -> Metric
// Metric.histogram(name: String, value: f64) -> Metric

struct Metric {
    name:       String,
    value:      f64,
    metric_type: String,
    timestamp:  String,
}

// ── OtelExporter — Simulated OTLP/Prometheus export ──────────────────────────
// OtelExporter.create(format: String) -> OtelExporter
//   formats: "otlp", "prometheus"
// OtelExporter.export(exporter: OtelExporter, data: any) -> String

struct OtelExporter {
    format:          String,
    export_count:    i64,
}

// ── TraceSampler — Trace sampling strategies ─────────────────────────────────
// TraceSampler.create(strategy: String, rate: f64) -> TraceSampler
//   strategies: "always", "probabilistic", "rate_limiting"
// TraceSampler.should_sample(sampler: TraceSampler) -> Bool

struct TraceSampler {
    strategy:     String,
    rate:         f64,
    sample_count: i64,
}

// ── CorrelationEngine — Signal correlation ───────────────────────────────────
// CorrelationEngine.create() -> CorrelationEngine
// CorrelationEngine.add_signal(engine: CorrelationEngine, signal_type: String, data: String) -> CorrelationEngine
// CorrelationEngine.correlate(engine: CorrelationEngine) -> CorrelationResult

struct CorrelationEngine {
    signals:      []CorrelationSignal,
    signal_count: i64,
}

struct CorrelationSignal {
    signal_type: String,
    data:        String,
}

struct CorrelationResult {
    signal_count:    i64,
    signal_types:    []String,
    correlated:      bool,
    correlation_id:  String,
}

// ── SLI — Service Level Indicator ────────────────────────────────────────────
// SLI.create(name: String, target: f64, unit: String) -> SLI
// SLI.record(sli: SLI, value: f64) -> SLI

struct SLI {
    name:             String,
    target:           f64,
    unit:             String,
    measurements:     []f64,
    measurement_count: i64,
}

// ── SLO — Service Level Objective ────────────────────────────────────────────
// SLO.create(name: String, target_percent: f64, window_days: i64) -> SLO
// SLO.evaluate(slo: SLO, sli: SLI) -> SLOResult

struct SLO {
    name:            String,
    target_percent:  f64,
    window_days:     i64,
}

struct SLOResult {
    slo_name:               String,
    sli_name:               String,
    target_percent:         f64,
    actual_percent:         f64,
    burn_rate:              f64,
    error_budget_remaining: f64,
    in_violation:           bool,
}

// ── AlertRule — Alerting based on conditions ─────────────────────────────────
// AlertRule.create(name: String, condition: String, threshold: f64) -> AlertRule
//   conditions: "gt" (greater than), "lt" (less than), "eq" (equal)
// AlertRule.evaluate(rule: AlertRule, current_value: f64) -> AlertResult

struct AlertRule {
    name:      String,
    condition: String,
    threshold: f64,
}

struct AlertResult {
    rule_name:  String,
    fired:      bool,
    severity:   String,
    current:    f64,
    threshold:  f64,
    message:    String,
}

// ── HealthCheck — Service health with circuit breaker ────────────────────────
// HealthCheck.create(name: String, endpoint: String) -> HealthCheck
// HealthCheck.execute(check: HealthCheck) -> HealthResult
// HealthCheck.circuit_breaker_status(check: HealthCheck) -> String
//   returns: "closed" (healthy), "open" (unhealthy), "half_open" (testing)

struct HealthCheck {
    name:             String,
    endpoint:         String,
    consecutive_fails: i64,
    status:           String,
}

struct HealthResult {
    name:     String,
    endpoint: String,
    status:   String,
    latency_ms: i64,
    message:  String,
}
