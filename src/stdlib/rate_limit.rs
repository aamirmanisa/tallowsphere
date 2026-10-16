//! Standard library: `tallow.rate_limit` — rate limiting, request distribution,
//! backoff, and concurrent request pacing.
//!
//! # API
//! - `RateLimiter.new(max_per_second)` — create a rate limiter
//! - `limiter.wait()` — block until a token is available
//! - `limiter.try_acquire()` — try to acquire without blocking
//! - `RateLimiter.distribute(urls, concurrency)` — distributed request pacing
//! - `RateLimiter.backoff(attempt)` — exponential backoff delay in ms

use super::StdlibResult;
use crate::interp::{type_name, Value};


use std::time::{Duration, Instant};

/// Token bucket rate limiter
struct RateLimiter {
    rate: f64,                   // tokens per second
    tokens: f64,                 // current tokens
    last_refill: Instant,
    max_tokens: f64,
}

impl RateLimiter {
    fn new(max_per_second: f64) -> Self {
        RateLimiter {
            rate: max_per_second,
            tokens: max_per_second,
            last_refill: Instant::now(),
            max_tokens: max_per_second,
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn wait(&mut self, timeout_ms: u64) -> bool {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn available(&self) -> f64 {
        // Read-only view — use a snapshot
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        (self.tokens + elapsed * self.rate).min(self.max_tokens)
    }
}

/// Exponential backoff: returns delay in milliseconds for a given attempt number.
/// attempt 1 → 1000ms, 2 → 2000ms, 3 → 4000ms, 4 → 8000ms, capping at 60s.
fn backoff_ms(attempt: u32) -> u64 {
    let base = 1000u64;
    let max = 60_000u64;
    let delay = base * (1u64 << (attempt.min(6) - 1));
    delay.min(max)
}

/// Jitter: add ±25% random variation to a delay
fn jitter(delay_ms: u64) -> u64 {
    let quarter = delay_ms / 4;
    if quarter == 0 { return delay_ms; }
    let variation = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64) % (quarter * 2);
    delay_ms - quarter + variation
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(rl_new(args)),
        "backoff" => Some(rl_backoff(args)),
        "distribute" => Some(rl_distribute(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "RateLimiter") {
        return None;
    }
    match method {
        "wait" => Some(rl_wait(object, args)),
        "try_acquire" => Some(rl_try_acquire(object)),
        "available" => Some(rl_available(object)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "new" | "backoff" | "distribute")
}

// ── RateLimiter.new(max_per_second) ──

fn rl_new(args: Vec<Value>) -> StdlibResult {
    let rate = match args.first() {
        Some(Value::Int(i)) => *i as f64,
        Some(Value::Float(f)) => *f,
        Some(other) => return Err(format!("RateLimiter.new: expected number, got {}", type_name(other))),
        None => 10.0, // default 10/sec
    };
    let rl = RateLimiter::new(rate.max(0.01));
    Ok(Value::Struct {
        name: "RateLimiter".into(),
        fields: vec![
            ("rate".into(), Value::Float(rate)),
            ("available".into(), Value::Float(rl.available())),
        ],
    })
}

// ── limiter.wait(timeout_ms?) ──

fn rl_wait(object: &Value, args: Vec<Value>) -> StdlibResult {
    let mut rl = extract_rl(object)?;
    let timeout = match args.first() {
        Some(Value::Int(i)) => *i as u64,
        Some(Value::Float(f)) => (*f * 1000.0) as u64,
        None => 5000, // default 5s timeout
        Some(other) => return Err(format!("wait: expected milliseconds, got {}", type_name(other))),
    };
    if rl.wait(timeout) {
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

// ── limiter.try_acquire() ──

fn rl_try_acquire(object: &Value) -> StdlibResult {
    let mut rl = extract_rl(object)?;
    Ok(Value::Bool(rl.try_acquire()))
}

// ── limiter.available() ──

fn rl_available(object: &Value) -> StdlibResult {
    let rl = extract_rl(object)?;
    Ok(Value::Float(rl.available()))
}

// ── RateLimiter.backoff(attempt) ──

fn rl_backoff(args: Vec<Value>) -> StdlibResult {
    let attempt = match args.first() {
        Some(Value::Int(i)) => *i as u32,
        Some(other) => return Err(format!("backoff: expected attempt number, got {}", type_name(other))),
        None => return Err("backoff: missing attempt argument".into()),
    };
    let delay = jitter(backoff_ms(attempt));
    Ok(Value::Int(delay as i128))
}

// ── RateLimiter.distribute(urls, concurrency) ──

fn rl_distribute(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("RateLimiter.distribute: requires (urls, concurrency)".into());
    }
    let urls = match &args[0] {
        Value::Array(arr) => arr.clone(),
        other => return Err(format!("distribute: expected [String] urls, got {}", type_name(other))),
    };
    let concurrency = match &args[1] {
        Value::Int(i) => (*i as usize).max(1).min(100),
        other => return Err(format!("distribute: expected concurrency int, got {}", type_name(other))),
    };

    // Return a distribution plan: batched groups of URLs
    let batch_size = (urls.len() + concurrency - 1) / concurrency;
    let mut batches = Vec::new();

    for chunk in urls.chunks(batch_size.max(1)) {
        batches.push(Value::Array(chunk.to_vec()));
    }

    Ok(Value::Struct {
        name: "DistributionPlan".into(),
        fields: vec![
            ("total_urls".into(), Value::Int(urls.len() as i128)),
            ("concurrency".into(), Value::Int(concurrency as i128)),
            ("batch_size".into(), Value::Int(batch_size as i128)),
            ("num_batches".into(), Value::Int(batches.len() as i128)),
            ("batches".into(), Value::Array(batches)),
        ],
    })
}

// ── Helpers ──

fn extract_rl(value: &Value) -> Result<RateLimiter, String> {
    match value {
        Value::Struct { name, fields } if name == "RateLimiter" => {
            let rate = fields.iter()
                .find(|(n,_)| n == "rate")
                .and_then(|(_, v)| if let Value::Float(f) = v { Some(*f) } else { None })
                .unwrap_or(10.0);
            Ok(RateLimiter::new(rate.max(0.01)))
        }
        _ => Err(format!("Expected RateLimiter, got {}", type_name(value))),
    }
}
