//! Straggler detection and bounded speculation.
//!
//! A straggler is a task whose elapsed time exceeds a multiple of the wave's
//! median. When one is found, the scheduler may dispatch a duplicate under a NEW
//! lease epoch and take whichever result arrives first — the epoch fence makes
//! the loser's result uncommittable, so "first wins" is enforced by the same
//! mechanism that stops stale commits.
//!
//! Speculation trades CPU for latency and is bounded: at most
//! `budget_fraction` of a wave's tasks may be duplicated, so a slow mesh slows
//! the run's cost, never its correctness.

use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct SpeculationPolicy {
    pub enabled: bool,
    /// Duplicate only when a task exceeds `threshold_multiplier × median`.
    pub threshold_multiplier: f64,
    /// Fraction of a wave's tasks that may be duplicated (0.0–0.5).
    pub budget_fraction: f64,
}

impl Default for SpeculationPolicy {
    fn default() -> Self {
        SpeculationPolicy {
            // Off under small pools: below ~4 workers a duplicate usually
            // competes for the same CPU and makes the run slower.
            enabled: false,
            threshold_multiplier: 2.0,
            budget_fraction: 0.10,
        }
    }
}

impl SpeculationPolicy {
    pub fn for_workers(workers: usize) -> Self {
        let mut p = Self::default();
        p.enabled = workers >= 4;
        p
    }

    pub fn budget_for(&self, wave_tasks: usize) -> usize {
        ((wave_tasks as f64) * self.budget_fraction.clamp(0.0, 0.5)).floor() as usize
    }
}

/// Median of a slice of durations, in milliseconds. Empty → 0.
pub fn median_ms(samples: &[u64]) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    let mid = v.len() / 2;
    if v.len() % 2 == 0 {
        (v[mid - 1] + v[mid]) / 2
    } else {
        v[mid]
    }
}

/// Is `elapsed` a straggler given the durations of the tasks that already
/// finished in this wave?
///
/// Requires at least 3 completed samples: a median of one or two samples is not
/// a baseline, and speculating on it would duplicate ordinary tasks.
pub fn is_straggler(elapsed: Duration, completed: &[u64], multiplier: f64) -> bool {
    if completed.len() < 3 {
        return false;
    }
    let med = median_ms(completed);
    if med == 0 {
        return false;
    }
    elapsed.as_millis() as u64 > (med as f64 * multiplier) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_handles_odd_even_and_empty() {
        assert_eq!(median_ms(&[]), 0);
        assert_eq!(median_ms(&[5]), 5);
        assert_eq!(median_ms(&[1, 3, 2]), 2);
        assert_eq!(median_ms(&[1, 2, 3, 4]), 2);
    }

    #[test]
    fn straggler_needs_a_baseline() {
        // two samples are not a baseline, however slow the third looks
        assert!(!is_straggler(Duration::from_millis(9_000), &[10, 10], 2.0));
        assert!(is_straggler(
            Duration::from_millis(9_000),
            &[10, 10, 10],
            2.0
        ));
    }

    #[test]
    fn zero_median_never_marks_a_straggler() {
        assert!(!is_straggler(Duration::from_millis(50), &[0, 0, 0], 2.0));
    }

    #[test]
    fn budget_is_a_floor_fraction_of_the_wave() {
        let p = SpeculationPolicy {
            enabled: true,
            threshold_multiplier: 2.0,
            budget_fraction: 0.10,
        };
        assert_eq!(p.budget_for(10), 1);
        assert_eq!(p.budget_for(9), 0);
        assert_eq!(p.budget_for(100), 10);
    }

    #[test]
    fn speculation_is_off_below_four_workers() {
        assert!(!SpeculationPolicy::for_workers(1).enabled);
        assert!(!SpeculationPolicy::for_workers(3).enabled);
        assert!(SpeculationPolicy::for_workers(4).enabled);
        assert!(SpeculationPolicy::for_workers(16).enabled);
    }
}
