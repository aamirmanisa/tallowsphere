// Invalid differential privacy usage -- should trigger errors

// E0500: add_noise without @epsilon
fn bad_query(data: f64) -> f64 {
    data.add_noise(epsilon: 0.1)
}

// E0501: negative epsilon
@epsilon(-1.0)
fn negative_eps(data: f64) -> f64 {
    data
}

// E0506: purpose mismatch
@purpose("analytics")
fn analytics_fn(x: f64) -> f64 { x }

@purpose("marketing")
fn marketing_fn(x: f64) -> f64 {
    analytics_fn(x)
}
