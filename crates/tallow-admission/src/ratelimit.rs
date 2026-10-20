//! Per-source connection rate limiting (v1 hardening, door level).
//!
//! The pre-auth slot cap bounds *concurrency*; it does not bound *rate*. A peer
//! that connects, reads the cover response and reconnects can cycle thousands of
//! times per second without ever holding a slot. This limiter adds a token
//! bucket per source IP, checked before a slot is claimed, so a flood is refused
//! the same way an over-cap connection is: cover bytes, then close.
//!
//! Clock-injected and pure apart from the map, so the arithmetic is testable
//! without sleeping (same pattern as `io::next_read_timeout`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tokens a source may hold: the largest burst accepted before refill matters.
pub const SOURCE_BURST: f64 = 20.0;
/// Tokens restored per second of wall time.
pub const SOURCE_REFILL_PER_SEC: f64 = 10.0;
/// Hard bound on tracked sources. TCP peers cannot spoof their address, but a
/// /64 still offers 2^64 of them, so the map must not grow without limit.
pub const MAX_TRACKED_SOURCES: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token-bucket limiter keyed by source address.
#[derive(Debug)]
pub struct SourceLimiter {
    buckets: HashMap<IpAddr, Bucket>,
    burst: f64,
    refill_per_sec: f64,
}

impl Default for SourceLimiter {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            burst: SOURCE_BURST,
            refill_per_sec: SOURCE_REFILL_PER_SEC,
        }
    }
}

/// Parse a positive finite limit, falling back to `default` on anything else.
/// Pure so the fallback rules are testable without touching the environment.
fn parse_limit(raw: &str, default: f64) -> f64 {
    match raw.trim().parse::<f64>() {
        Ok(v) if v.is_finite() && v > 0.0 => v,
        _ => default,
    }
}

impl SourceLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from `TALLOW_ADMISSION_RATE_BURST` and
    /// `TALLOW_ADMISSION_RATE_REFILL` (tokens per second).
    ///
    /// The defaults assume one client per TCP peer. Behind a terminating proxy
    /// every peer is the proxy, so the bucket becomes a *global* rate: set these
    /// to the intended global budget, or terminate admission at the edge.
    pub fn from_env() -> Self {
        let burst = std::env::var("TALLOW_ADMISSION_RATE_BURST")
            .map(|v| parse_limit(&v, SOURCE_BURST))
            .unwrap_or(SOURCE_BURST);
        let refill = std::env::var("TALLOW_ADMISSION_RATE_REFILL")
            .map(|v| parse_limit(&v, SOURCE_REFILL_PER_SEC))
            .unwrap_or(SOURCE_REFILL_PER_SEC);
        Self {
            buckets: HashMap::new(),
            burst,
            refill_per_sec: refill,
        }
    }

    /// Charge one token to `ip` at `now`; `false` means rate-limited.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.allow_with(ip, now, self.burst, self.refill_per_sec)
    }

    /// `allow` with explicit bucket parameters (tests use short windows).
    pub fn allow_with(
        &mut self,
        ip: IpAddr,
        now: Instant,
        burst: f64,
        refill_per_sec: f64,
    ) -> bool {
        if !self.buckets.contains_key(&ip) && self.buckets.len() >= MAX_TRACKED_SOURCES {
            self.prune(now, burst, refill_per_sec);
        }
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Make room by dropping buckets that have refilled to full (they carry no
    /// debt, so forgetting them changes no future decision), then — if still
    /// full — the least-recently-seen half.
    fn prune(&mut self, now: Instant, burst: f64, refill_per_sec: f64) {
        self.buckets.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens + elapsed * refill_per_sec < burst
        });
        if self.buckets.len() >= MAX_TRACKED_SOURCES {
            let mut seen: Vec<(IpAddr, Instant)> =
                self.buckets.iter().map(|(ip, b)| (*ip, b.last)).collect();
            seen.sort_by_key(|(_, t)| *t);
            for (ip, _) in seen.into_iter().take(self.buckets.len() / 2) {
                self.buckets.remove(&ip);
            }
        }
    }

    /// Number of tracked sources (metrics/tests).
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn a_burst_is_accepted_then_refused() {
        let mut l = SourceLimiter::new();
        let t0 = Instant::now();
        for i in 0..SOURCE_BURST as usize {
            assert!(l.allow(ip(1), t0), "burst connection {i} must pass");
        }
        assert!(!l.allow(ip(1), t0), "one past the burst must be refused");
        // A different source is unaffected.
        assert!(l.allow(ip(2), t0));
    }

    #[test]
    fn tokens_refill_with_time() {
        let mut l = SourceLimiter::new();
        let t0 = Instant::now();
        for _ in 0..SOURCE_BURST as usize {
            assert!(l.allow(ip(1), t0));
        }
        assert!(!l.allow(ip(1), t0));
        // One full second restores SOURCE_REFILL_PER_SEC tokens.
        let t1 = t0 + Duration::from_secs(1);
        for i in 0..SOURCE_REFILL_PER_SEC as usize {
            assert!(l.allow(ip(1), t1), "refilled token {i} must pass");
        }
        assert!(!l.allow(ip(1), t1), "refill is bounded by the one second");
    }

    #[test]
    fn refund_never_exceeds_the_burst() {
        let mut l = SourceLimiter::new();
        let t0 = Instant::now();
        assert!(l.allow(ip(1), t0));
        // A long idle period must not bank more than the burst.
        let t1 = t0 + Duration::from_secs(3600);
        for _ in 0..SOURCE_BURST as usize {
            assert!(l.allow(ip(1), t1));
        }
        assert!(!l.allow(ip(1), t1));
    }

    #[test]
    fn limits_parse_or_fall_back() {
        assert_eq!(parse_limit("5", SOURCE_BURST), 5.0);
        assert_eq!(parse_limit(" 2.5 ", SOURCE_REFILL_PER_SEC), 2.5);
        assert_eq!(parse_limit("0", SOURCE_BURST), SOURCE_BURST);
        assert_eq!(parse_limit("-3", SOURCE_BURST), SOURCE_BURST);
        assert_eq!(parse_limit("nan", SOURCE_BURST), SOURCE_BURST);
        assert_eq!(parse_limit("inf", SOURCE_BURST), SOURCE_BURST);
        assert_eq!(parse_limit("", SOURCE_BURST), SOURCE_BURST);
        assert_eq!(parse_limit("ten", SOURCE_BURST), SOURCE_BURST);
    }

    #[test]
    fn the_map_is_bounded_and_drops_only_full_buckets() {
        let mut l = SourceLimiter::new();
        let t0 = Instant::now();
        // Fill the table, leaving one source in debt.
        for i in 0..MAX_TRACKED_SOURCES {
            let a = (i / 256) as u8;
            let b = (i % 256) as u8;
            let addr = IpAddr::V4(Ipv4Addr::new(10, a, 0, b));
            for _ in 0..(SOURCE_BURST as usize) {
                l.allow(addr, t0);
            }
        }
        let debtor = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        assert!(!l.allow(debtor, t0), "debtor must be in debt before prune");
        // A new source forces a prune; the map stays bounded and the debtor
        // (still in debt) survives, so the refusal cannot be evaded by churn.
        let fresh = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 99));
        assert!(l.allow(fresh, t0));
        assert!(l.tracked() <= MAX_TRACKED_SOURCES);
        assert!(!l.allow(debtor, t0), "a debtor must not be forgotten by churn");
    }
}
