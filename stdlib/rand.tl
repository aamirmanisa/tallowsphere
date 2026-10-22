// tallow.rand — Cryptographically secure random number generation
//
// All random generation uses CSPRNG. No weak PRNGs.

/// Generate cryptographically secure random bytes
// native: CSPRNG bytes
native fn bytes(count: usize) -> Bytes

/// Generate random u64
// native: CSPRNG u64
native fn u64() -> u64

/// Generate random i64
// native: CSPRNG i64
native fn i64() -> i64

/// Generate random f64 in [0.0, 1.0)
// native: CSPRNG f64
native fn f64() -> f64

/// Generate random u64 in range [min, max)
// native: uniform random in range
native fn range(min: u64, max: u64) -> u64

/// Generate URL-safe base64 token
// native: random base64url string
native fn token(length: u32) -> String

/// Generate UUID v4
// native: random UUID v4
native fn uuid() -> String

/// Shuffle a slice in place
// native: Fisher-Yates shuffle using CSPRNG
native fn shuffle<T>(items: []T)

/// Pick random element from slice
fn choice<T>(items: []T) -> T? {
    if items.len == 0 { return nil }
    items[range(0, items.len)]
}

/// Pick n random elements without replacement
// native: reservoir sampling
native fn sample<T>(items: []T, n: usize) -> []T
