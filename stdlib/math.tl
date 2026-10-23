// tallow.math — Math utilities

const PI:  f64 = 3.14159265358979323846
const E:   f64 = 2.71828182845904523536
const TAU: f64 = 6.28318530717958647692

native fn abs(x: f64) -> f64
native fn min(a: f64, b: f64) -> f64
native fn max(a: f64, b: f64) -> f64
native fn clamp(x: f64, lo: f64, hi: f64) -> f64

// Trigonometric (native implementations)
native fn sin(x: f64) -> f64
native fn cos(x: f64) -> f64
native fn tan(x: f64) -> f64
native fn asin(x: f64) -> f64
native fn acos(x: f64) -> f64
native fn atan(x: f64) -> f64
native fn atan2(y: f64, x: f64) -> f64

// Exponential/logarithmic
native fn sqrt(x: f64) -> f64
native fn cbrt(x: f64) -> f64
native fn pow(base: f64, exp: f64) -> f64
native fn exp(x: f64) -> f64
native fn ln(x: f64) -> f64
native fn log2(x: f64) -> f64
native fn log10(x: f64) -> f64

// Rounding
native fn floor(x: f64) -> f64
native fn ceil(x: f64) -> f64
native fn round(x: f64) -> f64
native fn trunc(x: f64) -> f64

// Integer math
native fn abs_i(x: i64) -> i64
native fn min_i(a: i64, b: i64) -> i64
native fn max_i(a: i64, b: i64) -> i64
native fn clamp_i(x: i64, lo: i64, hi: i64) -> i64
native fn gcd(a: i64, b: i64) -> i64
native fn lcm(a: i64, b: i64) -> i64

// Infinity/NaN
native fn is_nan(x: f64) -> bool
native fn is_infinite(x: f64) -> bool
native fn is_finite(x: f64) -> bool
