//! Observability dashboard for scraping operations (T3.27).
//!
//! Tracks per-target metrics (latency percentiles, success rates, error breakdown)
//! and exports Prometheus + JSON formats for external dashboards.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const MAX_LATENCY_SAMPLES: usize = 1000;

#[derive(Debug, Clone)]
pub struct RequestResult {
    pub success: bool,
    pub status_code: Option<u16>,
    pub latency_ms: f64,
    pub bytes: usize,
    pub items_extracted: u32,
    pub error_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TargetStatus {
    Healthy,
    Degraded,
    Failing,
    Down,
}

#[derive(Debug, Clone)]
pub struct TargetMetrics {
    pub target: String,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub blocked_requests: u64,
    pub captcha_encounters: u64,
    pub server_errors: u64,
    pub timeout_count: u64,
    pub parse_failures: u64,

    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub latency_samples: Vec<f64>,

    pub items_extracted: u64,
    pub bytes_downloaded: u64,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,

    pub success_rate_1h: f64,
    pub success_rate_24h: f64,

    pub health_score: f64,
    pub status: TargetStatus,
}

impl TargetMetrics {
    fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            total_requests: 0,
            successful_requests: 0,
            blocked_requests: 0,
            captcha_encounters: 0,
            server_errors: 0,
            timeout_count: 0,
            parse_failures: 0,
            latency_p50_ms: 0.0,
            latency_p95_ms: 0.0,
            latency_p99_ms: 0.0,
            latency_samples: Vec::new(),
            items_extracted: 0,
            bytes_downloaded: 0,
            last_success: None,
            last_failure: None,
            success_rate_1h: 1.0,
            success_rate_24h: 1.0,
            health_score: 1.0,
            status: TargetStatus::Healthy,
        }
    }

    fn recompute_percentiles(&mut self) {
        if self.latency_samples.is_empty() {
            return;
        }
        let mut sorted = self.latency_samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |p: f64| {
            let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
            sorted[idx]
        };
        self.latency_p50_ms = pct(0.50);
        self.latency_p95_ms = pct(0.95);
        self.latency_p99_ms = pct(0.99);
    }

    fn recompute_health(&mut self) {
        let rate = if self.total_requests > 0 {
            self.successful_requests as f64 / self.total_requests as f64
        } else {
            1.0
        };
        self.success_rate_1h = rate;
        self.success_rate_24h = rate;
        // Penalize for blocks/captcha
        let penalty = (self.blocked_requests + self.captcha_encounters) as f64
            / self.total_requests.max(1) as f64;
        self.health_score = (rate - penalty * 0.5).clamp(0.0, 1.0);
        self.status = if self.total_requests == 0 {
            TargetStatus::Healthy
        } else if self.health_score >= 0.9 {
            TargetStatus::Healthy
        } else if self.health_score >= 0.7 {
            TargetStatus::Degraded
        } else if self.health_score >= 0.3 {
            TargetStatus::Failing
        } else {
            TargetStatus::Down
        };
    }
}

#[derive(Debug, Clone)]
pub struct GlobalStats {
    pub total_requests: u64,
    pub total_items: u64,
    pub total_bytes: u64,
    pub active_targets: usize,
    pub failing_targets: usize,
    pub overall_success_rate: f64,
    pub started_at: Instant,
}

impl GlobalStats {
    fn new() -> Self {
        Self {
            total_requests: 0,
            total_items: 0,
            total_bytes: 0,
            active_targets: 0,
            failing_targets: 0,
            overall_success_rate: 1.0,
            started_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeatmapCell {
    pub success_rate: f64,
    pub request_count: u64,
    pub color: String,
}

#[derive(Debug, Clone)]
pub struct HeatmapData {
    pub targets: Vec<String>,
    pub hours: Vec<i64>,
    pub cells: Vec<Vec<HeatmapCell>>,
}

pub struct ObservabilityDashboard {
    targets: Arc<RwLock<HashMap<String, TargetMetrics>>>,
    global_stats: Arc<RwLock<GlobalStats>>,
}

impl ObservabilityDashboard {
    pub fn new() -> Self {
        Self {
            targets: Arc::new(RwLock::new(HashMap::new())),
            global_stats: Arc::new(RwLock::new(GlobalStats::new())),
        }
    }

    pub fn record_request(&self, target: &str, result: RequestResult) {
        let mut targets = self.targets.write().unwrap();
        let m = targets
            .entry(target.to_string())
            .or_insert_with(|| TargetMetrics::new(target));

        m.total_requests += 1;
        m.bytes_downloaded += result.bytes as u64;
        m.items_extracted += result.items_extracted as u64;

        if m.latency_samples.len() >= MAX_LATENCY_SAMPLES {
            m.latency_samples.remove(0);
        }
        m.latency_samples.push(result.latency_ms);

        if result.success {
            m.successful_requests += 1;
            m.last_success = Some(Instant::now());
        } else {
            m.last_failure = Some(Instant::now());
            match result.status_code {
                Some(403) | Some(429) => m.blocked_requests += 1,
                Some(s) if s >= 500 => m.server_errors += 1,
                _ => {}
            }
            if let Some(et) = &result.error_type {
                match et.as_str() {
                    "timeout" => m.timeout_count += 1,
                    "captcha" => m.captcha_encounters += 1,
                    "parse" => m.parse_failures += 1,
                    _ => {}
                }
            }
        }

        m.recompute_percentiles();
        m.recompute_health();

        let mut gs = self.global_stats.write().unwrap();
        gs.total_requests += 1;
        gs.total_items += result.items_extracted as u64;
        gs.total_bytes += result.bytes as u64;
        gs.active_targets = targets.len();
        gs.failing_targets = targets
            .values()
            .filter(|t| matches!(t.status, TargetStatus::Failing | TargetStatus::Down))
            .count();
        let total_ok: u64 = targets.values().map(|t| t.successful_requests).sum();
        let total_all: u64 = targets.values().map(|t| t.total_requests).sum();
        gs.overall_success_rate = if total_all > 0 {
            total_ok as f64 / total_all as f64
        } else {
            1.0
        };
    }

    pub fn target_health(&self, target: &str) -> Option<TargetMetrics> {
        self.targets.read().unwrap().get(target).cloned()
    }

    pub fn all_targets(&self) -> Vec<TargetMetrics> {
        self.targets.read().unwrap().values().cloned().collect()
    }

    pub fn failing_targets(&self) -> Vec<String> {
        self.targets
            .read()
            .unwrap()
            .values()
            .filter(|t| matches!(t.status, TargetStatus::Failing | TargetStatus::Down))
            .map(|t| t.target.clone())
            .collect()
    }

    pub fn global(&self) -> GlobalStats {
        self.global_stats.read().unwrap().clone()
    }

    pub fn heatmap_24h(&self) -> HeatmapData {
        let targets_map = self.targets.read().unwrap();
        let mut target_names: Vec<String> = targets_map.keys().cloned().collect();
        target_names.sort();
        target_names.truncate(100);

        let hours: Vec<i64> = (0..24).collect();
        let mut cells = Vec::with_capacity(target_names.len());
        for name in &target_names {
            let m = targets_map.get(name).unwrap();
            let row: Vec<HeatmapCell> = (0..24)
                .map(|_| HeatmapCell {
                    success_rate: m.success_rate_1h,
                    request_count: m.total_requests / 24,
                    color: health_color(m.health_score),
                })
                .collect();
            cells.push(row);
        }

        HeatmapData {
            targets: target_names,
            hours,
            cells,
        }
    }

    pub fn export_prometheus(&self) -> String {
        let targets = self.targets.read().unwrap();
        let mut out = String::new();
        out.push_str("# HELP tallow_requests_total Total requests per target\n");
        out.push_str("# TYPE tallow_requests_total counter\n");
        for m in targets.values() {
            out.push_str(&format!(
                "tallow_requests_total{{target=\"{}\"}} {}\n",
                m.target, m.total_requests
            ));
        }
        out.push_str("# HELP tallow_requests_success_total Successful requests\n");
        out.push_str("# TYPE tallow_requests_success_total counter\n");
        for m in targets.values() {
            out.push_str(&format!(
                "tallow_requests_success_total{{target=\"{}\"}} {}\n",
                m.target, m.successful_requests
            ));
        }
        out.push_str("# HELP tallow_latency_p95_ms p95 latency in ms\n");
        out.push_str("# TYPE tallow_latency_p95_ms gauge\n");
        for m in targets.values() {
            out.push_str(&format!(
                "tallow_latency_p95_ms{{target=\"{}\"}} {}\n",
                m.target, m.latency_p95_ms
            ));
        }
        out.push_str("# HELP tallow_health_score Composite health 0-1\n");
        out.push_str("# TYPE tallow_health_score gauge\n");
        for m in targets.values() {
            out.push_str(&format!(
                "tallow_health_score{{target=\"{}\"}} {}\n",
                m.target, m.health_score
            ));
        }
        out
    }

    pub fn export_json(&self) -> serde_json::Value {
        let targets = self.targets.read().unwrap();
        let gs = self.global_stats.read().unwrap();
        let targets_json: Vec<serde_json::Value> = targets
            .values()
            .map(|m| {
                serde_json::json!({
                    "target": m.target,
                    "total_requests": m.total_requests,
                    "successful_requests": m.successful_requests,
                    "blocked_requests": m.blocked_requests,
                    "captcha_encounters": m.captcha_encounters,
                    "server_errors": m.server_errors,
                    "timeout_count": m.timeout_count,
                    "parse_failures": m.parse_failures,
                    "latency_p50_ms": m.latency_p50_ms,
                    "latency_p95_ms": m.latency_p95_ms,
                    "latency_p99_ms": m.latency_p99_ms,
                    "items_extracted": m.items_extracted,
                    "bytes_downloaded": m.bytes_downloaded,
                    "success_rate_1h": m.success_rate_1h,
                    "health_score": m.health_score,
                    "status": format!("{:?}", m.status),
                })
            })
            .collect();
        serde_json::json!({
            "global": {
                "total_requests": gs.total_requests,
                "total_items": gs.total_items,
                "total_bytes": gs.total_bytes,
                "active_targets": gs.active_targets,
                "failing_targets": gs.failing_targets,
                "overall_success_rate": gs.overall_success_rate,
                "uptime_secs": gs.started_at.elapsed().as_secs(),
            },
            "targets": targets_json,
        })
    }
}

impl Default for ObservabilityDashboard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Prometheus HTTP /metrics endpoint
// ---------------------------------------------------------------------------

/// Default TCP port for the Prometheus `/metrics` endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// A running lightweight Prometheus `/metrics` HTTP server.
///
/// Obtained from [`serve_metrics`]. It serves the dashboard's Prometheus
/// exposition (`export_prometheus`) over plain TCP on `GET /metrics` until
/// [`MetricsServer::stop`] is called.
pub struct MetricsServer {
    /// The bound TCP port (differs from the requested port when `0` was used).
    pub port: u16,
    handle: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl MetricsServer {
    /// Request the serving thread to stop. The accept loop notices within one
    /// poll interval (~10 ms).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Stop the server and block until the serving thread exits.
    pub fn join(&mut self) -> std::thread::Result<()> {
        self.stop();
        if let Some(h) = self.handle.take() {
            h.join()
        } else {
            Ok(())
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        // Ask the serving thread to exit on drop (never block here).
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Start a minimal Prometheus `/metrics` HTTP endpoint for a dashboard.
///
/// Binds a `std::net::TcpListener` on `127.0.0.1:{port}` in a background thread
/// and answers `GET /metrics` with [`ObservabilityDashboard::export_prometheus`]
/// rendered as `text/plain` (Prometheus exposition format) — a dependency-free
/// scrape target for Prometheus/Grafana/HPA and other tooling. Any other path
/// returns `404 Not Found`.
///
/// `port == 0` asks the OS for an ephemeral free port; use
/// [`MetricsServer::port`] to learn the actual bound port.
pub fn serve_metrics(
    dashboard: Arc<ObservabilityDashboard>,
    port: u16,
) -> std::io::Result<MetricsServer> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let bound_port = listener.local_addr()?.port();
    // Non-blocking so the accept loop can observe the stop flag.
    listener.set_nonblocking(true)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !stop_worker.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_metrics_connection(stream, &dashboard),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });

    Ok(MetricsServer {
        port: bound_port,
        handle: Some(handle),
        stop,
    })
}

/// Read one small request and write a single response. A per-connection read
/// timeout keeps a slow/broken client from stalling the serving loop.
fn handle_metrics_connection(mut stream: std::net::TcpStream, dashboard: &ObservabilityDashboard) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    let request_line = head.lines().next().unwrap_or("");

    let (status, content_type, body) = if request_line.starts_with("GET /metrics") {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            dashboard.export_prometheus(),
        )
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn health_color(score: f64) -> String {
    if score >= 0.9 {
        "#22c55e".into()
    } else if score >= 0.7 {
        "#eab308".into()
    } else if score >= 0.3 {
        "#f97316".into()
    } else {
        "#ef4444".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(latency: f64) -> RequestResult {
        RequestResult {
            success: true,
            status_code: Some(200),
            latency_ms: latency,
            bytes: 1024,
            items_extracted: 5,
            error_type: None,
        }
    }

    fn blocked() -> RequestResult {
        RequestResult {
            success: false,
            status_code: Some(429),
            latency_ms: 50.0,
            bytes: 0,
            items_extracted: 0,
            error_type: None,
        }
    }

    #[test]
    fn records_and_classifies() {
        let d = ObservabilityDashboard::new();
        d.record_request("amazon", ok(100.0));
        d.record_request("amazon", blocked());
        let m = d.target_health("amazon").unwrap();
        assert_eq!(m.total_requests, 2);
        assert_eq!(m.successful_requests, 1);
        assert_eq!(m.blocked_requests, 1);
    }

    #[test]
    fn computes_percentiles() {
        let d = ObservabilityDashboard::new();
        for i in 1..=100 {
            d.record_request("t", ok(i as f64));
        }
        let m = d.target_health("t").unwrap();
        assert!(m.latency_p50_ms >= 49.0 && m.latency_p50_ms <= 51.0);
        assert!(m.latency_p95_ms >= 94.0);
    }

    #[test]
    fn prometheus_export_contains_metrics() {
        let d = ObservabilityDashboard::new();
        d.record_request("walmart", ok(10.0));
        let p = d.export_prometheus();
        assert!(p.contains("tallow_requests_total"));
        assert!(p.contains("walmart"));
    }

    #[test]
    fn failing_targets_listed() {
        let d = ObservabilityDashboard::new();
        for _ in 0..10 {
            d.record_request("bad", blocked());
        }
        assert!(d.failing_targets().contains(&"bad".to_string()));
    }

    #[test]
    fn metrics_http_endpoint_serves_prometheus_text() {
        let d = Arc::new(ObservabilityDashboard::new());
        d.record_request("amazon", ok(10.0));
        let mut server = serve_metrics(Arc::clone(&d), 0).expect("metrics server binds");

        let mut s = std::net::TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write request");
        let mut resp = String::new();
        s.read_to_string(&mut resp).expect("read response");

        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "expected 200 OK, got: {resp}"
        );
        assert!(
            resp.contains("tallow_requests_total"),
            "prometheus metric missing: {resp}"
        );
        assert!(resp.contains("amazon"));
        assert!(
            resp.contains("text/plain"),
            "content type should be text/plain: {resp}"
        );

        server.join().expect("metrics server thread exits");
    }

    #[test]
    fn metrics_http_endpoint_404s_unknown_path() {
        let d = Arc::new(ObservabilityDashboard::new());
        let mut server = serve_metrics(Arc::clone(&d), 0).expect("metrics server binds");

        let mut s = std::net::TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write request");
        let mut resp = String::new();
        s.read_to_string(&mut resp).expect("read response");

        assert!(
            resp.starts_with("HTTP/1.1 404 Not Found"),
            "expected 404, got: {resp}"
        );

        server.join().expect("metrics server thread exits");
    }
}
