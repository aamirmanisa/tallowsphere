// tallow.test — Testing framework

/// Assert value is true
fn assert(condition: bool) {
    if !condition {
        panic("assertion failed")
    }
}

/// Assert with message
fn assert(condition: bool, msg: String) {
    if !condition {
        panic("assertion failed: " + msg)
    }
}

/// Assert equality
fn assert_eq<T>(left: T, right: T) {
    if left != right {
        panic("assertion failed: left != right")
    }
}

/// Assert inequality
fn assert_ne<T>(left: T, right: T) {
    if left == right {
        panic("assertion failed: left == right")
    }
}

/// Assert Result is Ok
fn assert_ok<T>(result: Result<T>) -> T {
    result match {
        Ok(v)  -> v
        Err(e) -> panic("expected Ok, got Err: " + e)
    }
}

/// Assert Result is Err
fn assert_err<T>(result: Result<T>) {
    result match {
        Ok(_)  -> panic("expected Err, got Ok")
        Err(_) -> {}
    }
}

/// Assert value is nil
fn assert_nil<T>(value: T?) {
    if value != nil {
        panic("expected nil")
    }
}

/// Assert value is not nil
fn assert_not_nil<T>(value: T?) -> T {
    if value == nil {
        panic("expected non-nil")
    }
    value
}

/// Assert that a function panics
// native: catches panic, fails if no panic occurred
native fn assert_panics(f: fn())

/// Approximate equality for floats
fn assert_approx(left: f64, right: f64, epsilon: f64) {
    let diff = left - right
    if diff < 0.0 { diff = 0.0 - diff }
    if diff > epsilon {
        panic("assertion failed: {left} !~= {right} (epsilon: {epsilon})")
    }
}
