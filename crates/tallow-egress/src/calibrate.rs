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

/// Median of the finite samples, or `None` when there are none.
///
/// The probe takes several samples because a single one is not trustworthy on a
/// congested path: Tor measured 1.2, 1.6, 1.7, 1.9 and 2.32 MB/s across five
/// readings on the same box within minutes. The median rejects that kind of
/// outlier, which a mean would carry into the weight ratio.
pub fn median(samples: &[f64]) -> Option<f64> {
    let mut finite: Vec<f64> = samples
        .iter()
        .copied()
        .filter(|v| v.is_finite() && *v > 0.0)
        .collect();
    if finite.is_empty() {
        return None;
    }
    finite.sort_by(|a, b| a.partial_cmp(b).expect("finite values compare"));
    let mid = finite.len() / 2;
    Some(if finite.len() % 2 == 0 {
        (finite[mid - 1] + finite[mid]) / 2.0
    } else {
        finite[mid]
    })
}

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

    #[test]
    fn median_of_odd_samples_is_the_middle_one() {
        assert_eq!(median(&[1.2, 2.32, 1.7]), Some(1.7));
    }

    #[test]
    fn median_of_even_samples_averages_the_middle_pair() {
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), Some(2.5));
    }

    #[test]
    fn median_ignores_non_finite_and_zero_samples() {
        assert_eq!(median(&[f64::NAN, 0.0, 5.0, f64::INFINITY, 7.0]), Some(6.0));
    }

    #[test]
    fn median_of_nothing_is_none() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[0.0, f64::NAN]), None);
    }
}
