//! Schema drift detection for scraping operations (T3.26).
//!
//! Tracks field-level null/empty/valid rates per retailer and alerts when
//! current rates deviate from baseline beyond a configurable threshold.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const SECS_PER_HOUR: i64 = 3600;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct HourlyBucket {
    pub hour_timestamp: i64,
    pub total: u64,
    pub nulls: u64,
    pub empties: u64,
}

#[derive(Debug, Clone)]
pub struct FieldStats {
    pub retailer: String,
    pub field_name: String,
    pub total_samples: u64,
    pub null_count: u64,
    pub empty_count: u64,
    pub valid_count: u64,
    pub hourly_buckets: Vec<HourlyBucket>,
    pub baseline_null_rate: f64,
    pub current_null_rate: f64,
    pub drift_detected: bool,
}

impl FieldStats {
    fn new(retailer: &str, field: &str) -> Self {
        Self {
            retailer: retailer.to_string(),
            field_name: field.to_string(),
            total_samples: 0,
            null_count: 0,
            empty_count: 0,
            valid_count: 0,
            hourly_buckets: Vec::new(),
            baseline_null_rate: 0.0,
            current_null_rate: 0.0,
            drift_detected: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct DriftAlert {
    pub retailer: String,
    pub field_name: String,
    pub baseline_null_rate: f64,
    pub current_null_rate: f64,
    pub delta: f64,
    pub severity: DriftSeverity,
    pub detected_at: i64,
}

pub struct SchemaDriftDetector {
    field_stats: Arc<RwLock<HashMap<(String, String), FieldStats>>>,
    alert_threshold: f64,
    baseline_window_hours: i64,
}

impl SchemaDriftDetector {
    pub fn new(alert_threshold: f64) -> Self {
        Self {
            field_stats: Arc::new(RwLock::new(HashMap::new())),
            alert_threshold,
            baseline_window_hours: 24,
        }
    }

    pub fn with_baseline_window(mut self, hours: i64) -> Self {
        self.baseline_window_hours = hours;
        self
    }

    pub fn record(&self, retailer: &str, field: &str, value: Option<&str>) {
        let key = (retailer.to_string(), field.to_string());
        let mut map = self.field_stats.write().unwrap();
        let stats = map
            .entry(key)
            .or_insert_with(|| FieldStats::new(retailer, field));

        stats.total_samples += 1;
        let (is_null, is_empty) = match value {
            None => (true, false),
            Some(s) if s.trim().is_empty() => (false, true),
            Some(_) => (false, false),
        };
        if is_null {
            stats.null_count += 1;
        } else if is_empty {
            stats.empty_count += 1;
        } else {
            stats.valid_count += 1;
        }

        let hour = now_secs() / SECS_PER_HOUR * SECS_PER_HOUR;
        match stats.hourly_buckets.last_mut() {
            Some(b) if b.hour_timestamp == hour => {
                b.total += 1;
                if is_null {
                    b.nulls += 1;
                }
                if is_empty {
                    b.empties += 1;
                }
            }
            _ => stats.hourly_buckets.push(HourlyBucket {
                hour_timestamp: hour,
                total: 1,
                nulls: if is_null { 1 } else { 0 },
                empties: if is_empty { 1 } else { 0 },
            }),
        }

        // Recompute rates
        let now = now_secs();
        let baseline_cutoff = now - self.baseline_window_hours * SECS_PER_HOUR;
        let current_cutoff = now - SECS_PER_HOUR;

        let (mut b_total, mut b_null) = (0u64, 0u64);
        let (mut c_total, mut c_null) = (0u64, 0u64);
        for b in &stats.hourly_buckets {
            if b.hour_timestamp < baseline_cutoff {
                continue;
            }
            if b.hour_timestamp < current_cutoff {
                b_total += b.total;
                b_null += b.nulls + b.empties;
            } else {
                c_total += b.total;
                c_null += b.nulls + b.empties;
            }
        }

        stats.baseline_null_rate = if b_total > 0 {
            b_null as f64 / b_total as f64
        } else {
            0.0
        };
        stats.current_null_rate = if c_total > 0 {
            c_null as f64 / c_total as f64
        } else {
            0.0
        };
        stats.drift_detected =
            (stats.current_null_rate - stats.baseline_null_rate).abs() > self.alert_threshold
                && c_total >= 10;
    }

    pub fn check_drift(&self) -> Vec<DriftAlert> {
        self.all_drifted()
    }

    pub fn stats_for(&self, retailer: &str, field: &str) -> Option<FieldStats> {
        let map = self.field_stats.read().unwrap();
        map.get(&(retailer.to_string(), field.to_string())).cloned()
    }

    pub fn all_drifted(&self) -> Vec<DriftAlert> {
        let map = self.field_stats.read().unwrap();
        let now = now_secs();
        let mut alerts = Vec::new();
        for stats in map.values() {
            if !stats.drift_detected {
                continue;
            }
            let delta = stats.current_null_rate - stats.baseline_null_rate;
            let severity = if delta.abs() > 0.05 {
                DriftSeverity::Critical
            } else {
                DriftSeverity::Warning
            };
            alerts.push(DriftAlert {
                retailer: stats.retailer.clone(),
                field_name: stats.field_name.clone(),
                baseline_null_rate: stats.baseline_null_rate,
                current_null_rate: stats.current_null_rate,
                delta,
                severity,
                detected_at: now,
            });
        }
        alerts
    }
}

impl Default for SchemaDriftDetector {
    fn default() -> Self {
        Self::new(0.03)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_classify_values() {
        let d = SchemaDriftDetector::new(0.03);
        d.record("amazon", "price", Some("19.99"));
        d.record("amazon", "price", Some(""));
        d.record("amazon", "price", None);
        let s = d.stats_for("amazon", "price").unwrap();
        assert_eq!(s.total_samples, 3);
        assert_eq!(s.valid_count, 1);
        assert_eq!(s.empty_count, 1);
        assert_eq!(s.null_count, 1);
    }

    #[test]
    fn detects_no_drift_with_insufficient_samples() {
        let d = SchemaDriftDetector::new(0.03);
        d.record("a", "f", None);
        assert!(d.all_drifted().is_empty());
    }

    #[test]
    fn tracks_hourly_buckets() {
        let d = SchemaDriftDetector::new(0.03);
        for _ in 0..5 {
            d.record("walmart", "title", Some("ok"));
        }
        let s = d.stats_for("walmart", "title").unwrap();
        assert_eq!(s.hourly_buckets.len(), 1);
        assert_eq!(s.hourly_buckets[0].total, 5);
    }
}
