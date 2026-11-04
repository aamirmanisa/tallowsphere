//! Turning measured per-exit goodput into shard weights.
//!
//! Kept pure and network-free: the bench takes the measurements, this decides
//! what they mean. The rules that matter are all failure modes of a naive
//! ratio — a dead exit must not produce a divide-by-zero or drop out of the
//! plan, and a wildly faster exit must not ask for a ratio so extreme that the
//! slow leg gets a shard below the chunk floor.

/// Weight given to a path whose measured goodput is zero (or unmeasurable).
///
/// Not zero: a zero weight is rejected by [`crate::plan::plan_shards_weighted`],
/// and dropping a path is a decision for the operator, not a side effect of one
/// bad probe. A failing exit keeps a minimal share and is allowed to fail again
/// visibly.
pub const FLOOR_WEIGHT: u32 = 1;

/// Maximum weight any single path can be assigned.
///
/// 100:1 keeps the largest plausible ratio between a datacentre link and a
/// saturated cellular path while bounding how small the slow leg's shard can
/// get for a given transfer.
pub const MAX_WEIGHT: u32 = 100;

/// Convert per-exit goodput (bytes per second, same order as the exits) into
/// integer weights.
///
/// The fastest path gets [`MAX_WEIGHT`] and every other path is scaled against
/// it, floored at [`FLOOR_WEIGHT`]. A path measured at zero gets the floor
/// rather than being removed: the caller can still see it fail.
///
/// Returns an empty vector only for empty input.
pub fn weights_from_goodput(goodput_bytes_per_sec: &[f64]) -> Vec<u32> {
    if goodput_bytes_per_sec.is_empty() {
        return Vec::new();
    }
    let fastest = goodput_bytes_per_sec
        .iter()
        .copied()
        .filter(|v| v.is_finite() && *v > 0.0)
        .fold(0.0_f64, f64::max);

    if fastest <= 0.0 {
        // Nothing measured: every path is equally unknown, so split evenly.
        return vec![FLOOR_WEIGHT; goodput_bytes_per_sec.len()];
    }

    goodput_bytes_per_sec
        .iter()
        .map(|v| {
            if !v.is_finite() || *v <= 0.0 {
                return FLOOR_WEIGHT;
            }
            let scaled = (*v / fastest) * f64::from(MAX_WEIGHT);
            let rounded = scaled.round();
            // `as` saturates, but clamp explicitly so the bound is obvious.
            (rounded as u32).clamp(FLOOR_WEIGHT, MAX_WEIGHT)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastest_path_gets_the_maximum() {
        assert_eq!(weights_from_goodput(&[5.0e6, 5.0e5]), vec![100, 10]);
    }

    #[test]
    fn a_dead_path_keeps_the_floor_instead_of_vanishing() {
        let w = weights_from_goodput(&[5.0e6, 0.0]);
        assert_eq!(w, vec![100, 1]);
        assert_eq!(w.len(), 2, "the failing path must stay in the plan");
    }

    #[test]
    fn nothing_measured_splits_evenly() {
        assert_eq!(weights_from_goodput(&[0.0, 0.0, 0.0]), vec![1, 1, 1]);
    }

    #[test]
    fn extreme_ratios_are_bounded() {
        let w = weights_from_goodput(&[1.0e9, 1.0]);
        assert_eq!(w[0], MAX_WEIGHT);
        assert_eq!(w[1], FLOOR_WEIGHT);
    }

    #[test]
    fn non_finite_measurements_do_not_poison_the_result() {
        let w = weights_from_goodput(&[f64::NAN, 5.0e6, f64::INFINITY]);
        assert_eq!(w.len(), 3);
        assert_eq!(w[0], FLOOR_WEIGHT, "NaN must not become a weight");
        assert!(w.iter().all(|x| *x >= FLOOR_WEIGHT && *x <= MAX_WEIGHT));
    }

    #[test]
    fn empty_input_yields_no_weights() {
        assert!(weights_from_goodput(&[]).is_empty());
    }
}
