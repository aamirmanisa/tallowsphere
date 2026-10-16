// tallow.rate_limit — token-bucket rate limiting, backoff, and request distribution.
//
// Token bucket rate limiter for pacing API calls, exponential backoff with jitter
// for retry logic, and URL batching for concurrent request distribution.

struct RateLimiter {
    rate: Float,
    available: Float,
}

struct DistributionPlan {
    total_urls: Int,
    concurrency: Int,
    batch_size: Int,
    num_batches: Int,
    batches: [[String]],
}

// Create a rate limiter that allows max_per_second requests per second.
fn RateLimiter.new(max_per_second: Float) -> RateLimiter

// Block until a token is available, or timeout_ms expires. Returns true if acquired.
fn RateLimiter.wait(self, timeout_ms: Int?) -> Bool

// Try to acquire a token without blocking. Returns true if acquired.
fn RateLimiter.try_acquire(self) -> Bool

// Current number of available tokens (may be fractional).
fn RateLimiter.available(self) -> Float

// Exponential backoff with jitter. Returns delay in milliseconds for attempt N.
// attempt 1→1s, 2→2s, 3→4s, 4→8s, 5→16s, 6→32s, cap at 60s.
fn RateLimiter.backoff(attempt: Int) -> Int

// Distribute URLs into batched groups for concurrent processing.
fn RateLimiter.distribute(urls: [String], concurrency: Int) -> DistributionPlan
