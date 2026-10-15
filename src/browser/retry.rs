//! Retry logic with configurable backoff for browser operations.
//!
//! Provides `.with_retry()` wrapper functionality:
//! - `RetryConfig`: max retries + backoff strategy
//! - `BackoffStrategy`: exponential, linear, or fixed delay
//! - `retry_with_backoff`: async retry wrapper with retryable error classification

use std::collections::HashMap;
use std::time::Duration;

use crate::browser::error::{BrowserError, NavigationError};

// ── Backoff Strategy ────────────────────────────────────────────────────────

/// Backoff strategy for retry delays between attempts.
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Exponential backoff: delay = min(initial_ms * multiplier^attempt, max_ms) +/- jitter.
    Exponential {
        initial_ms: u64,
        multiplier: f64,
        max_ms: u64,
    },
    /// Linear backoff: delay = interval_ms * (attempt + 1).
    Linear { interval_ms: u64 },
    /// Fixed delay between retries.
    Fixed { interval_ms: u64 },
}

impl BackoffStrategy {
    /// Calculate the delay in milliseconds for a given attempt number (0-based).
    pub fn delay_for(&self, attempt: u32) -> u64 {
        match self {
            BackoffStrategy::Exponential {
                initial_ms,
                multiplier,
                max_ms,
            } => {
                let base = (*initial_ms as f64) * multiplier.powi(attempt as i32);
                let capped = base.min(*max_ms as f64) as u64;

                // Add jitter: +/- 10%
                let jitter_range = capped / 10;
                if jitter_range > 0 {
                    let jitter = (rand::random::<u64>() % (jitter_range * 2 + 1)) as i64
                        - jitter_range as i64;
                    (capped as i64 + jitter).max(0) as u64
                } else {
                    capped
                }
            }
            BackoffStrategy::Linear { interval_ms } => {
                // NEVER N5: saturate — a huge `interval_ms`/`attempt` pair must
                // not overflow-panic (debug) or wrap to a tiny delay (release).
                interval_ms.saturating_mul(attempt as u64 + 1)
            }
            BackoffStrategy::Fixed { interval_ms } => {
                // Fixed does not scale with the attempt index; the identity
                // `saturating_mul(1)` keeps the overflow-safe contract explicit
                // and identical across the non-exponential arms (NEVER N5).
                interval_ms.saturating_mul(1)
            }
        }
    }
}

// ── Retry Config ────────────────────────────────────────────────────────────

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries (total attempts = max_retries + 1).
    pub max_retries: u32,
    /// Backoff strategy for delays between retries.
    pub backoff: BackoffStrategy,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff: BackoffStrategy::Exponential {
                initial_ms: 100,
                multiplier: 2.0,
                max_ms: 5000,
            },
        }
    }
}

/// Hard upper bound on a caller-supplied `RetryConfig::max_retries` (NEVER
/// invariant N5: no unbounded retry loop).
///
/// A `u32` counter does terminate "eventually", but "eventually" can be
/// ~4e9 attempts — a denial-of-service on the target and a deanonymization-
/// grade timing signal. [`RetryConfig::sanitized`] clamps to this value and
/// the retry consumer ([`retry_with_backoff_governed`]) applies it before
/// iterating, so a hostile or typo'd config cannot drive an
/// effectively-unbounded loop.
pub const MAX_RETRIES_HARD_CAP: u32 = 20;

impl RetryConfig {
    /// Clamp this config to the NEVER-safe hard bounds (N5).
    ///
    /// `max_retries` is clamped to [`MAX_RETRIES_HARD_CAP`]; the backoff
    /// strategies are overflow-safe by construction (`saturating_mul`), so no
    /// other field needs rewriting. Returns an owned copy.
    pub fn sanitized(&self) -> RetryConfig {
        RetryConfig {
            max_retries: self.max_retries.min(MAX_RETRIES_HARD_CAP),
            backoff: self.backoff.clone(),
        }
    }
}

// ── Error Classification ────────────────────────────────────────────────────

/// Determine if a BrowserError is retryable.
///
/// Retryable errors are transient failures that may succeed on retry:
/// - ConnectionFailed, Timeout, ProcessCrashed
/// - NavigationFailed with Timeout variant
/// - RateLimitExceeded (429) and Captcha/challenge errors — treated as
///   **backoff-not-fatal**: they signal a domain-level soft block, so the
///   fetch loop should back off (honoring `Retry-After`) and retry rather
///   than treating them as permanent.
///
/// Non-retryable errors are permanent failures:
/// - CdpError, ElementNotFound, ContextClosed
/// - RobotsTxtDisallowed, DownloadFailed, CaptchaNotFound
/// - NavigationFailed with DnsFailure, SslError, ConnectionRefused
pub fn is_retryable(err: &BrowserError) -> bool {
    match err {
        BrowserError::ConnectionFailed(_) => true,
        BrowserError::Timeout { .. } => true,
        BrowserError::ProcessCrashed(_) => true,
        BrowserError::NavigationFailed(nav_err) => matches!(nav_err, NavigationError::Timeout),
        BrowserError::CdpError { .. } => false,
        BrowserError::ElementNotFound { .. } => false,
        BrowserError::ContextClosed => false,
        BrowserError::RobotsTxtDisallowed(_) => false,
        // 429 → domain-level backoff, retryable.
        BrowserError::RateLimitExceeded(_) => true,
        BrowserError::DownloadFailed(_) => false,
        BrowserError::JsonError(_) => false,
        BrowserError::FileNotFound(_) => false,
        BrowserError::ShadowRootNotFound => false,
        BrowserError::IframeAccessDenied { .. } => false,
        BrowserError::InterceptError(_) => false,
        BrowserError::FetchDomainError { .. } => false,
        BrowserError::PoolError(_) => true,
        BrowserError::PoolExhausted => true,
        BrowserError::SessionError(_) => false,
        BrowserError::StorageError(_) => false,
        BrowserError::EncryptionError(_) => false,
        BrowserError::AuthError(_) => false,
        // 403 anti-bot challenge → backoff-not-fatal, retryable.
        BrowserError::CaptchaError(_) => true,
        BrowserError::CaptchaSolveTimeout => true,
        BrowserError::CaptchaNotFound => false,
        BrowserError::ActionFailed(_) => false,
        BrowserError::ChecksumMismatch { .. } => false,
        // A missing pin is a policy refusal — retrying cannot make a pin appear.
        BrowserError::UnpinnedArtifact { .. } => false,
    }
}

// ── Retry-After + soft-block classification ────────────────────────────────

/// Parse the HTTP `Retry-After` header into milliseconds.
///
/// Mirrors `retry_intelligence::parse_retry_after`: accepts either an integer
/// number of seconds (`Retry-After: 30`) or an HTTP-date. HTTP-dates are
/// collapsed to a conservative 5s default. Returns `None` when the header is
/// absent or unparseable.
pub fn parse_retry_after(headers: &HashMap<String, String>) -> Option<u64> {
    let value = headers
        .get("retry-after")
        .or_else(|| headers.get("Retry-After"))
        .or_else(|| headers.get("retry-After"))?;

    // Try parsing as seconds (integer).
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(secs.saturating_mul(1000));
    }

    // HTTP-date form — fall back to a conservative delay.
    if value.contains(',') || value.contains("GMT") {
        return Some(5_000);
    }

    None
}

/// How a failed attempt should be handled by the retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryKind {
    /// Transient network/server failure — retry with normal backoff.
    Transient,
    /// Rate-limit / anti-bot soft block — report to the domain governor,
    /// honor `Retry-After`, back off (not fatal).
    SoftBackoff,
    /// Permanent failure — do not retry.
    Permanent,
}

impl RetryKind {
    /// Whether this kind should be retried.
    pub fn is_retryable(&self) -> bool {
        matches!(self, RetryKind::Transient | RetryKind::SoftBackoff)
    }
}

/// Outcome of a single attempt, feeding the retry governor.
///
/// Carries the underlying error plus enough context to decide between a plain
/// transient retry and a domain-level soft block (429 / 403-challenge) that
/// should be reported via [`crate::browser::ratelimit::DomainRateManager::report_soft_block`]
/// and backed off per the server's `Retry-After`.
#[derive(Debug)]
pub struct RetrySignal {
    /// The underlying browser error.
    pub err: BrowserError,
    /// Parsed `Retry-After` (ms) if the server provided one.
    pub retry_after_ms: Option<u64>,
    /// True for a 429 / anti-bot challenge — domain-level soft block.
    pub soft_block: bool,
    /// Domain that experienced the block (for governor reporting).
    pub domain: String,
}

impl RetrySignal {
    /// Build a signal from a bare error (no response context).
    pub fn from_error(err: BrowserError) -> Self {
        Self {
            err,
            retry_after_ms: None,
            soft_block: false,
            domain: String::new(),
        }
    }

    /// Build a signal from an HTTP response: status code + headers + domain.
    ///
    /// Classifies 429 and anti-bot challenges (403 challenge / 503 interstitial)
    /// as a domain-level soft block and parses `Retry-After` when present.
    pub fn from_response(
        err: BrowserError,
        status: Option<u16>,
        headers: &HashMap<String, String>,
        domain: &str,
    ) -> Self {
        let retry_after_ms = parse_retry_after(headers);
        let soft_block = matches!(status, Some(429) | Some(403) | Some(503))
            || matches!(&err, BrowserError::RateLimitExceeded(_) | BrowserError::CaptchaError(_));
        Self {
            err,
            retry_after_ms,
            soft_block,
            domain: domain.to_string(),
        }
    }

    /// Classify this signal for the retry loop.
    pub fn classify(&self) -> RetryKind {
        if self.soft_block {
            return RetryKind::SoftBackoff;
        }
        if is_retryable(&self.err) {
            RetryKind::Transient
        } else {
            RetryKind::Permanent
        }
    }
}

// ── Retry Function ──────────────────────────────────────────────────────────

/// Execute an async operation with retry logic.
///
/// Retries the operation up to `config.max_retries` times on retryable errors,
/// with delays determined by the configured backoff strategy.
/// Non-retryable errors cause immediate failure.
///
/// This is a thin wrapper over [`retry_with_backoff_governed`] for callers that
/// only yield `BrowserError` and do not need soft-block / `Retry-After` handling.
///
/// # Example
/// ```ignore
/// let result = retry_with_backoff(
///     || async { page.navigate("https://example.com").await },
///     &RetryConfig::default(),
/// ).await;
/// ```
pub async fn retry_with_backoff<F, Fut, T>(
    f: F,
    config: &RetryConfig,
) -> Result<T, BrowserError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, BrowserError>>,
{
    let mut f = f;
    retry_with_backoff_governed(
        || {
            let fut = f();
            async move { fut.await.map_err(RetrySignal::from_error) }
        },
        config,
        |_| {},
    )
    .await
}

/// Execute an async operation with Retry-After + soft-block-aware retry.
///
/// This is the **primary** retry path for the fetch loop. It unifies the two
/// previously-divergent retry paths (`retry::retry_with_backoff` and
/// `retry_intelligence::recommend_retry`) behind one governing loop:
///
/// - Each attempt yields a [`RetrySignal`] which may carry a parsed
///   `Retry-After` and a soft-block flag.
/// - Soft blocks (429, 403 anti-bot challenge, 503 interstitial) are treated as
///   **backoff-not-fatal**: the loop invokes `on_soft_block(&domain)` so callers
///   can report the block to the domain-level governor
///   (`DomainRateManager::report_soft_block`), then sleeps on the server's
///   `Retry-After` when present (falling back to the configured backoff).
/// - Transient errors use the configured exponential/linear/fixed backoff.
/// - Permanent errors fail immediately.
pub async fn retry_with_backoff_governed<F, Fut, T, G>(
    mut f: F,
    config: &RetryConfig,
    mut on_soft_block: G,
) -> Result<T, BrowserError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, RetrySignal>>,
    G: FnMut(&str),
{
    // NEVER N5: clamp the caller's config before iterating — a hostile
    // `max_retries` (e.g. `u32::MAX`) must not translate into ~4e9 attempts.
    let config = config.sanitized();
    let mut last_err = None;
    for attempt in 0..=config.max_retries {
        match f().await {
            Ok(v) => return Ok(v),
            Err(signal) => {
                let kind = signal.classify();
                if attempt == config.max_retries || !kind.is_retryable() {
                    return Err(signal.err);
                }
                if matches!(kind, RetryKind::SoftBackoff) {
                    // Report the domain-level soft block to the governor.
                    on_soft_block(&signal.domain);
                }
                let delay_ms = if matches!(kind, RetryKind::SoftBackoff) {
                    // Honor the server's Retry-After when present.
                    signal
                        .retry_after_ms
                        .unwrap_or_else(|| config.backoff.delay_for(attempt))
                } else {
                    config.backoff.delay_for(attempt)
                };
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                last_err = Some(signal.err);
            }
        }
    }
    Err(last_err.unwrap())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // ── Backoff delay tests ─────────────────────────────────────────────

    #[test]
    fn exponential_backoff_delays() {
        let strategy = BackoffStrategy::Exponential {
            initial_ms: 100,
            multiplier: 2.0,
            max_ms: 5000,
        };

        // Test without jitter influence by checking approximate ranges
        // attempt 0: 100ms +/- 10%
        let d0 = strategy.delay_for(0);
        assert!(d0 >= 90 && d0 <= 110, "attempt 0 should be ~100ms, got {d0}");

        // attempt 1: 200ms +/- 10%
        let d1 = strategy.delay_for(1);
        assert!(
            d1 >= 180 && d1 <= 220,
            "attempt 1 should be ~200ms, got {d1}"
        );

        // attempt 2: 400ms +/- 10%
        let d2 = strategy.delay_for(2);
        assert!(
            d2 >= 360 && d2 <= 440,
            "attempt 2 should be ~400ms, got {d2}"
        );

        // attempt 10: should be capped at 5000ms +/- 10%
        let d10 = strategy.delay_for(10);
        assert!(
            d10 >= 4500 && d10 <= 5500,
            "attempt 10 should be capped at ~5000ms, got {d10}"
        );
    }

    #[test]
    fn linear_backoff_delays() {
        let strategy = BackoffStrategy::Linear { interval_ms: 100 };

        assert_eq!(strategy.delay_for(0), 100); // 100 * (0+1) = 100
        assert_eq!(strategy.delay_for(1), 200); // 100 * (1+1) = 200
        assert_eq!(strategy.delay_for(2), 300); // 100 * (2+1) = 300
        assert_eq!(strategy.delay_for(4), 500); // 100 * (4+1) = 500
    }

    #[test]
    fn fixed_backoff_delays() {
        let strategy = BackoffStrategy::Fixed { interval_ms: 250 };

        assert_eq!(strategy.delay_for(0), 250);
        assert_eq!(strategy.delay_for(1), 250);
        assert_eq!(strategy.delay_for(5), 250);
        assert_eq!(strategy.delay_for(100), 250);
    }

    // ── Error classification tests ──────────────────────────────────────

    #[test]
    fn is_retryable_classification() {
        // Retryable
        assert!(is_retryable(&BrowserError::ConnectionFailed(
            "ws failed".into()
        )));
        assert!(is_retryable(&BrowserError::Timeout {
            operation: "navigate",
            detail: "30s".into(),
        }));
        assert!(is_retryable(&BrowserError::ProcessCrashed(
            "signal 11".into()
        )));
        assert!(is_retryable(&BrowserError::NavigationFailed(
            NavigationError::Timeout
        )));

        // NOT retryable
        assert!(!is_retryable(&BrowserError::CdpError {
            code: -32601,
            message: "not found".into(),
        }));
        assert!(!is_retryable(&BrowserError::ElementNotFound {
            selector: "div".into(),
        }));
        assert!(!is_retryable(&BrowserError::ContextClosed));
        assert!(!is_retryable(&BrowserError::RobotsTxtDisallowed(
            "/private".into()
        )));
        // Backoff-not-fatal (429 / anti-bot challenge) — retryable
        assert!(is_retryable(&BrowserError::RateLimitExceeded(
            "example.com".into()
        )));
        assert!(!is_retryable(&BrowserError::DownloadFailed(
            "404".into()
        )));
        assert!(!is_retryable(&BrowserError::JsonError(
            "parse error".into()
        )));
    }

    #[test]
    fn navigation_dns_failure_not_retryable() {
        assert!(!is_retryable(&BrowserError::NavigationFailed(
            NavigationError::DnsFailure("bad host".into())
        )));
    }

    #[test]
    fn navigation_ssl_error_not_retryable() {
        assert!(!is_retryable(&BrowserError::NavigationFailed(
            NavigationError::SslError("cert expired".into())
        )));
    }

    #[test]
    fn navigation_connection_refused_not_retryable() {
        assert!(!is_retryable(&BrowserError::NavigationFailed(
            NavigationError::ConnectionRefused
        )));
    }

    // ── Async retry tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn retry_succeeds_after_failure() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let config = RetryConfig {
            max_retries: 3,
            backoff: BackoffStrategy::Fixed { interval_ms: 1 }, // minimal delay for testing
        };

        let result = retry_with_backoff(
            || {
                let a = attempts_clone.clone();
                async move {
                    let count = a.fetch_add(1, Ordering::SeqCst);
                    if count < 2 {
                        // Fail first 2 attempts
                        Err(BrowserError::ConnectionFailed("temporary".into()))
                    } else {
                        // Succeed on 3rd attempt
                        Ok(42u32)
                    }
                }
            },
            &config,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_gives_up_after_max() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let config = RetryConfig {
            max_retries: 2,
            backoff: BackoffStrategy::Fixed { interval_ms: 1 },
        };

        let result: Result<u32, BrowserError> = retry_with_backoff(
            || {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Err(BrowserError::ConnectionFailed("permanent".into()))
                }
            },
            &config,
        )
        .await;

        assert!(result.is_err());
        // max_retries=2 means 3 total attempts (0, 1, 2)
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_stops_on_non_retryable_error() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let config = RetryConfig {
            max_retries: 5,
            backoff: BackoffStrategy::Fixed { interval_ms: 1 },
        };

        let result: Result<u32, BrowserError> = retry_with_backoff(
            || {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    // Non-retryable error — should stop immediately
                    Err(BrowserError::ElementNotFound {
                        selector: "div".into(),
                    })
                }
            },
            &config,
        )
        .await;

        assert!(result.is_err());
        // Should stop after first attempt (non-retryable)
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn default_retry_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert!(matches!(
            config.backoff,
            BackoffStrategy::Exponential {
                initial_ms: 100,
                multiplier,
                max_ms: 5000,
            } if (multiplier - 2.0).abs() < f64::EPSILON
        ));
    }

    // ── NEVER N5: hard cap + overflow-safe backoff ──────────────────────

    #[tokio::test]
    async fn retry_attempts_are_hard_capped() {
        // A hostile / typo'd config must not drive an effectively-unbounded
        // loop: `u32::MAX` retries terminate "eventually" — ~4e9 attempts.
        let hostile = RetryConfig {
            max_retries: u32::MAX,
            backoff: BackoffStrategy::Fixed { interval_ms: 1 },
        };
        assert!(
            hostile.sanitized().max_retries <= MAX_RETRIES_HARD_CAP,
            "sanitized() must clamp max_retries to the hard cap"
        );

        // The consumer applies the clamp: exactly CAP + 1 attempts even
        // though the config asked for u32::MAX retries.
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        let result: Result<u32, BrowserError> = retry_with_backoff(
            || {
                let a = attempts_clone.clone();
                async move {
                    let n = a.fetch_add(1, Ordering::SeqCst);
                    // Fail fast on an un-clamped loop instead of spinning ~4e9
                    // times (holds the never-runs invariant even if one day the
                    // clamp is dropped from the consumer).
                    assert!(
                        n <= MAX_RETRIES_HARD_CAP,
                        "retry loop exceeded MAX_RETRIES_HARD_CAP (attempt {n})"
                    );
                    Err(BrowserError::ConnectionFailed("hard cap".into()))
                }
            },
            &hostile,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), MAX_RETRIES_HARD_CAP + 1);

        // A sane config under the cap is passed through unchanged.
        let sane = RetryConfig {
            max_retries: 3,
            backoff: BackoffStrategy::Fixed { interval_ms: 1 },
        };
        assert_eq!(sane.sanitized().max_retries, 3);
    }

    #[test]
    fn linear_backoff_saturates() {
        // Overflow at the extremes must saturate, never panic (debug) or wrap
        // to a small delay (release): both would break the retry budget.
        let linear = BackoffStrategy::Linear {
            interval_ms: u64::MAX,
        };
        assert_eq!(linear.delay_for(u32::MAX), u64::MAX);
        assert_eq!(linear.delay_for(1), u64::MAX); // MAX * 2 saturates
        assert_eq!(linear.delay_for(0), u64::MAX); // MAX * 1 = MAX

        // Ordinary values keep exact linear behavior.
        let small = BackoffStrategy::Linear { interval_ms: 100 };
        assert_eq!(small.delay_for(0), 100);
        assert_eq!(small.delay_for(1), 200);
        assert_eq!(small.delay_for(4), 500);

        // Fixed returns its interval verbatim at the largest attempt index —
        // no scaling arithmetic, so u64::MAX can never overflow.
        let fixed = BackoffStrategy::Fixed {
            interval_ms: u64::MAX,
        };
        assert_eq!(fixed.delay_for(u32::MAX), u64::MAX);
    }
}
