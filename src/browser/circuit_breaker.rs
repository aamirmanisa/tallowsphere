//! Circuit Breaker per Target (T3.20)
//!
//! Tracks success/failure rate per target host and opens a circuit when
//! the error rate exceeds a threshold within a rolling window.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open(Instant),
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    pub target: String,
    pub state: CircuitState,
    pub failure_threshold: f64,
    pub min_samples: u32,
    pub window_seconds: u64,
    pub half_open_after_seconds: u64,
    pub observations: Vec<(Instant, bool)>,
}

impl CircuitBreaker {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            state: CircuitState::Closed,
            failure_threshold: 0.5,
            min_samples: 20,
            window_seconds: 60,
            half_open_after_seconds: 30,
            observations: Vec::new(),
        }
    }

    pub fn should_allow(&mut self) -> bool {
        match self.state.clone() {
            CircuitState::Closed => true,
            CircuitState::Open(until) => {
                if Instant::now() >= until {
                    self.state = CircuitState::HalfOpen;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    pub fn on_success(&mut self) {
        self.observations.push((Instant::now(), true));
        self.trim_window();
        if matches!(self.state, CircuitState::HalfOpen) {
            self.state = CircuitState::Closed;
            self.observations.clear();
        }
    }

    pub fn on_failure(&mut self) {
        self.observations.push((Instant::now(), false));
        self.trim_window();
        if matches!(self.state, CircuitState::HalfOpen) {
            self.state = CircuitState::Open(
                Instant::now() + Duration::from_secs(self.half_open_after_seconds),
            );
            return;
        }
        self.check_threshold();
    }

    fn trim_window(&mut self) {
        let window = Duration::from_secs(self.window_seconds);
        let now = Instant::now();
        self.observations.retain(|(when, _)| now.duration_since(*when) <= window);
    }

    fn check_threshold(&mut self) {
        if (self.observations.len() as u32) < self.min_samples {
            return;
        }
        let failures = self.observations.iter().filter(|(_, s)| !s).count();
        let rate = failures as f64 / self.observations.len() as f64;
        if rate >= self.failure_threshold {
            self.state = CircuitState::Open(
                Instant::now() + Duration::from_secs(self.half_open_after_seconds),
            );
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.observations.is_empty() {
            return 1.0;
        }
        let ok = self.observations.iter().filter(|(_, s)| *s).count();
        ok as f64 / self.observations.len() as f64
    }
}

#[derive(Debug, Clone)]
pub struct BreakerStats {
    pub target: String,
    pub state: CircuitState,
    pub recent_success_rate: f64,
    pub recent_request_count: u32,
    pub currently_blocking: bool,
    pub time_until_retry: Option<Duration>,
}

pub struct CircuitBreakerRegistry {
    breakers: Arc<Mutex<HashMap<String, CircuitBreaker>>>,
}

impl CircuitBreakerRegistry {
    pub fn new() -> Self {
        Self {
            breakers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_or_create(&self, target: &str) -> CircuitBreaker {
        let mut map = self.breakers.lock().unwrap();
        map.entry(target.to_string())
            .or_insert_with(|| CircuitBreaker::new(target))
            .clone()
    }

    pub fn allow_request(&self, target: &str) -> bool {
        let mut map = self.breakers.lock().unwrap();
        let b = map.entry(target.to_string()).or_insert_with(|| CircuitBreaker::new(target));
        b.should_allow()
    }

    pub fn record_success(&self, target: &str) {
        let mut map = self.breakers.lock().unwrap();
        let b = map.entry(target.to_string()).or_insert_with(|| CircuitBreaker::new(target));
        b.on_success();
    }

    pub fn record_failure(&self, target: &str) {
        let mut map = self.breakers.lock().unwrap();
        let b = map.entry(target.to_string()).or_insert_with(|| CircuitBreaker::new(target));
        b.on_failure();
    }

    pub fn stats(&self) -> HashMap<String, BreakerStats> {
        let map = self.breakers.lock().unwrap();
        let mut out = HashMap::new();
        let now = Instant::now();
        for (k, b) in map.iter() {
            let (blocking, ttr) = match b.state {
                CircuitState::Open(until) => {
                    if until > now {
                        (true, Some(until - now))
                    } else {
                        (false, None)
                    }
                }
                _ => (false, None),
            };
            out.insert(
                k.clone(),
                BreakerStats {
                    target: k.clone(),
                    state: b.state.clone(),
                    recent_success_rate: b.success_rate(),
                    recent_request_count: b.observations.len() as u32,
                    currently_blocking: blocking,
                    time_until_retry: ttr,
                },
            );
        }
        out
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed_and_allows() {
        let mut b = CircuitBreaker::new("example.com");
        assert!(b.should_allow());
        assert_eq!(b.state, CircuitState::Closed);
    }

    #[test]
    fn opens_after_threshold_failures() {
        let mut b = CircuitBreaker::new("example.com");
        b.min_samples = 5;
        b.failure_threshold = 0.5;
        for _ in 0..2 {
            b.on_success();
        }
        for _ in 0..3 {
            b.on_failure();
        }
        assert!(matches!(b.state, CircuitState::Open(_)));
    }

    #[test]
    fn does_not_open_below_min_samples() {
        let mut b = CircuitBreaker::new("example.com");
        b.min_samples = 20;
        for _ in 0..5 {
            b.on_failure();
        }
        assert_eq!(b.state, CircuitState::Closed);
    }

    #[test]
    fn registry_tracks_per_target() {
        let reg = CircuitBreakerRegistry::new();
        reg.record_success("a.com");
        reg.record_failure("b.com");
        let s = reg.stats();
        assert_eq!(s.len(), 2);
        assert!(reg.allow_request("a.com"));
    }

    #[test]
    fn half_open_after_timeout() {
        let mut b = CircuitBreaker::new("x");
        b.min_samples = 2;
        b.failure_threshold = 0.5;
        b.half_open_after_seconds = 0;
        b.on_failure();
        b.on_failure();
        assert!(matches!(b.state, CircuitState::Open(_)));
        std::thread::sleep(Duration::from_millis(10));
        assert!(b.should_allow());
        assert_eq!(b.state, CircuitState::HalfOpen);
        b.on_success();
        assert_eq!(b.state, CircuitState::Closed);
    }
}
