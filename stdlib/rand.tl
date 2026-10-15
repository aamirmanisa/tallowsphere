// tallow.rand — Cryptographically secure random number generation
//
// All random generation uses CSPRNG. No weak PRNGs.

/// Generate cryptographically secure random bytes
fn bytes(count: usize) -> Bytes {
    // native: CSPRNG bytes
}

/// Generate random u64
fn u64() -> u64 {
    // native: CSPRNG u64
}

/// Generate random i64
fn i64() -> i64 {
    // native: CSPRNG i64
}

/// Generate random f64 in [0.0, 1.0)
fn f64() -> f64 {
    // native: CSPRNG f64
}

/// Generate random u64 in range [min, max)
fn range(min: u64, max: u64) -> u64 {
    // native: uniform random in range
}

/// Generate URL-safe base64 token
fn token(length: u32) -> String {
    // native: random base64url string
}

/// Generate UUID v4
fn uuid() -> String {
    // native: random UUID v4
}

/// Shuffle a slice in place
fn shuffle<T>(items: []T) {
    // native: Fisher-Yates shuffle using CSPRNG
}

/// Pick random element from slice
fn choice<T>(items: []T) -> T? {
    if items.len == 0 { return nil }
    items[range(0, items.len)]
}

/// Pick n random elements without replacement
fn sample<T>(items: []T, n: usize) -> []T {
    // native: reservoir sampling
}
