//! Constant-time operations to prevent timing side-channels

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time equality comparison
///
/// Compares two byte slices in constant time to prevent timing attacks.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise.
/// Always returns `false` if the slices have different lengths.
///
/// # Security note
///
/// The length check (`a.len() != b.len()`) is NOT constant-time — a length
/// mismatch causes an early return, leaking whether the lengths are equal.
/// When comparing fixed-length values such as 60-character safety numbers,
/// both inputs MUST be exactly the expected length before calling this function.
/// The byte comparison itself is constant-time via the `subtle` crate.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Constant-time selection
///
/// Selects between two values based on a condition, in constant time.
///
/// # Arguments
///
/// * `condition` - If true, select `a`, otherwise select `b`
/// * `a` - First value
/// * `b` - Second value
///
/// # Returns
///
/// Either `a` or `b` depending on condition, selected in constant time.
pub fn ct_select<T: ConditionallySelectable + Copy>(condition: bool, a: T, b: T) -> T {
    let choice = Choice::from(condition as u8);
    T::conditional_select(&b, &a, choice)
}

/// Constant-time byte selection
///
/// Specialized version for byte slices that copies into a destination buffer.
///
/// # Arguments
///
/// * `condition` - If true, select from `a`, otherwise from `b`
/// * `a` - First byte slice
/// * `b` - Second byte slice
/// * `dest` - Destination buffer
///
/// # Panics
///
/// Panics if `a`, `b`, and `dest` don't all have the same length.
pub fn ct_select_bytes(condition: bool, a: &[u8], b: &[u8], dest: &mut [u8]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), dest.len());

    let choice = Choice::from(condition as u8);
    for i in 0..dest.len() {
        dest[i] = u8::conditional_select(&b[i], &a[i], choice);
    }
}

/// Compare two values and return -1, 0, or 1 in constant time
///
/// Uses `i128` widening to avoid unsigned overflow issues that arise when
/// operands have the MSB set. The subtraction, shift, and negation are all
/// branchless ALU operations on every major architecture.
///
/// # Arguments
///
/// * `a` - First value
/// * `b` - Second value
///
/// # Returns
///
/// - `-1` if a < b
/// - `0` if a == b
/// - `1` if a > b
pub fn ct_compare_u64(a: u64, b: u64) -> i8 {
    // Widen to i128 so the subtraction never wraps.
    // diff is in [-2^64+1, 2^64-1], safely within i128 range.
    let diff = (a as i128) - (b as i128);
    // Arithmetic right-shift by 127 extracts the sign: -1 if negative, 0 otherwise.
    let negative = (diff >> 127) as i8; // -1 when a < b
    let positive = ((-diff) >> 127) as i8; // -1 when a > b
    negative - positive // -1 - 0 = -1, 0 - (-1) = 1, 0 - 0 = 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hello!"));
    }

    #[test]
    fn test_ct_select() {
        assert_eq!(ct_select(true, 42u8, 99u8), 42);
        assert_eq!(ct_select(false, 42u8, 99u8), 99);
    }

    #[test]
    fn test_ct_select_bytes() {
        let a = b"hello";
        let b = b"world";
        let mut dest = [0u8; 5];

        ct_select_bytes(true, a, b, &mut dest);
        assert_eq!(&dest, b"hello");

        ct_select_bytes(false, a, b, &mut dest);
        assert_eq!(&dest, b"world");
    }

    #[test]
    fn test_ct_compare_u64() {
        assert_eq!(ct_compare_u64(10, 20), -1);
        assert_eq!(ct_compare_u64(20, 10), 1);
        assert_eq!(ct_compare_u64(15, 15), 0);
        assert_eq!(ct_compare_u64(0, 0), 0);
        assert_eq!(ct_compare_u64(u64::MAX, u64::MAX), 0);
        // Edge cases that caught the original wrapping_sub bug:
        assert_eq!(ct_compare_u64(0, u64::MAX), -1);
        assert_eq!(ct_compare_u64(u64::MAX, 0), 1);
        assert_eq!(ct_compare_u64(u64::MAX, 1), 1);
        assert_eq!(ct_compare_u64(1, u64::MAX), -1);
        // Values with MSB set (the original bug trigger)
        assert_eq!(ct_compare_u64(1u64 << 63, 0), 1);
        assert_eq!(ct_compare_u64(0, 1u64 << 63), -1);
        assert_eq!(ct_compare_u64(12748708674506622310, 0), 1);
        assert_eq!(ct_compare_u64(0, 12748708674506622310), -1);
    }
}
