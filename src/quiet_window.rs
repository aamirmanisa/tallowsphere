//! Quiet windows — rate-limited intake and alerting for intelligence collection.
//!
//! One config ([`QuietConfig`]) drives four policies (frozen interface §7,
//! B2.4.1–B2.4.3):
//!
//! 1. **Quiet windows** ([`ingest_allowed`]) — wall-clock intervals during
//!    which no new ingest may be accepted. A window is the half-open interval
//!    `[start_ms, end_ms)`: the start instant is *inside* the window
//!    (inclusive), the end instant is *outside* (exclusive). A window with
//!    `start_ms >= end_ms` is empty and matches no instant.
//! 2. **Consolidation silence** ([`ingest_allowed`]) — a cooldown of
//!    `consolidation_ms` after the last accepted ingest (`last_ingest_ms`),
//!    so freshly acquired material settles before the next intake. Also
//!    half-open: the blocked span is `[last, last + consolidation_ms)`;
//!    exactly `consolidation_ms` after the last ingest, intake is allowed
//!    again. With no prior ingest (`None`) there is no cooldown. An instant
//!    *before* `last_ingest_ms` (clock skew) is not "within" the cooldown and
//!    is governed by the windows alone.
//! 3. **Digest batching** ([`should_digest`], [`digest_batches`]) — below-
//!    interrupt material is accumulated and flushed in fixed-size batches of
//!    `digest_size` items (chunked in input order; the final partial batch is
//!    kept — it will never grow, because nothing more may join it). A
//!    `digest_size` of `0` is an invalid configuration ([`QuietError::
//!    InvalidConfig`]); [`should_digest`] can never fire for it.
//! 4. **Alert tiers** ([`classify_alert`]) — every alert is classified before
//!    it can interrupt the operator: `Silent` (severity `0`), `Immediate`
//!    (severity `>= interrupt_severity`), else `Digest`.
//!
//! Why interrupts are rate-limited: an interrupt is a scarce, attention-
//! destroying resource. Promoting everything to [`AlertTier::Immediate`]
//! collapses the operator's attention budget (alert fatigue), so only
//! severity at or above the configured threshold may break silence; the rest
//! rides the next digest.
//!
//! Every function is **pure** — a function of its arguments only, no clock
//! reads, no randomness — so a schedule replays identically for the same
//! inputs.

use serde::{Deserialize, Serialize};

/// A half-open time interval `[start_ms, end_ms)` on the caller's clock.
///
/// `start_ms` is inclusive, `end_ms` exclusive (frozen §7 pin). If
/// `start_ms >= end_ms` the interval is empty and matches no instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive start instant (ms).
    pub start_ms: i64,
    /// Exclusive end instant (ms).
    pub end_ms: i64,
}

/// The full quiet-window / batched-digest / alert-tier policy.
///
/// `digest_size == 0` is invalid ([`validate`], [`digest_batches`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietConfig {
    /// Quiet windows; an instant inside any of them blocks ingest.
    pub windows: Vec<TimeWindow>,
    /// Cooldown after the last accepted ingest (ms).
    pub consolidation_ms: i64,
    /// Digest batch size (items per digest); must be `>= 1`.
    pub digest_size: usize,
    /// Severity at or above which an alert may interrupt immediately.
    pub interrupt_severity: u8,
}

/// How an alert may reach the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertTier {
    /// May interrupt silence now.
    Immediate,
    /// Held for the next digest batch.
    Digest,
    /// Suppressed entirely (severity `0`).
    Silent,
}

/// Errors from quiet-window policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuietError {
    /// `digest_size == 0` — batches of nothing can never be flushed.
    InvalidConfig,
}

impl std::fmt::Display for QuietError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuietError::InvalidConfig => {
                write!(f, "invalid quiet-window config: digest_size must be >= 1")
            }
        }
    }
}

impl std::error::Error for QuietError {}

/// Validate the static parts of a config. Currently the only invalidity is
/// `digest_size == 0` (frozen §7); windows may be empty/inverted and the
/// other fields are unconstrained by the interface.
pub fn validate(cfg: &QuietConfig) -> Result<(), QuietError> {
    if cfg.digest_size == 0 {
        return Err(QuietError::InvalidConfig);
    }
    Ok(())
}

/// True iff `now_ms` lies in `[w.start_ms, w.end_ms)`.
fn in_window(w: &TimeWindow, now_ms: i64) -> bool {
    now_ms >= w.start_ms && now_ms < w.end_ms
}

/// May new material be ingested at `now_ms`?
///
/// `false` inside any quiet window (inclusive start, exclusive end) or within
/// `consolidation_ms` after `last_ingest_ms` (consolidation silence:
/// `[last, last + consolidation_ms)`, so exactly `consolidation_ms` later is
/// allowed and the very instant of the last ingest is not). Otherwise `true`.
pub fn ingest_allowed(cfg: &QuietConfig, last_ingest_ms: Option<i64>, now_ms: i64) -> bool {
    if cfg.windows.iter().any(|w| in_window(w, now_ms)) {
        return false;
    }
    if let Some(last) = last_ingest_ms {
        let elapsed = now_ms - last;
        if elapsed >= 0 && elapsed < cfg.consolidation_ms {
            return false;
        }
    }
    true
}

/// Is the pending set large enough to flush a digest?
///
/// `pending >= digest_size`. An invalid config (`digest_size == 0`) can never
/// flush — this predicate returns `false` for it; the error is reported by
/// [`validate`] / [`digest_batches`] (a `bool` return has no error channel).
pub fn should_digest(cfg: &QuietConfig, pending: usize) -> bool {
    cfg.digest_size != 0 && pending >= cfg.digest_size
}

/// Split `items` into digest batches of at most `cfg.digest_size` items, in
/// input order; the last batch may be partial and is kept.
///
/// `digest_size == 0` => [`QuietError::InvalidConfig`]. An empty input yields
/// an empty batch list (nothing to flush).
pub fn digest_batches(cfg: &QuietConfig, items: &[String]) -> Result<Vec<Vec<String>>, QuietError> {
    if cfg.digest_size == 0 {
        return Err(QuietError::InvalidConfig);
    }
    Ok(items
        .chunks(cfg.digest_size)
        .map(|chunk| chunk.to_vec())
        .collect())
}

/// Classify an alert by severity.
///
/// Pins: severity `0` => [`AlertTier::Silent`] (checked first — a degenerate
/// threshold of `0` still cannot promote no-op alerts); severity `>=
/// interrupt_severity` => [`AlertTier::Immediate`]; otherwise
/// [`AlertTier::Digest`].
pub fn classify_alert(cfg: &QuietConfig, severity: u8) -> AlertTier {
    if severity == 0 {
        return AlertTier::Silent;
    }
    if severity >= cfg.interrupt_severity {
        return AlertTier::Immediate;
    }
    AlertTier::Digest
}

#[cfg(test)]
mod tests {
    use super::*;

    /// House config: two windows, 300 ms cooldown, batches of 3, interrupt
    /// threshold 3.
    fn cfg() -> QuietConfig {
        QuietConfig {
            windows: vec![
                TimeWindow {
                    start_ms: 1_000,
                    end_ms: 2_000,
                },
                TimeWindow {
                    start_ms: 5_000,
                    end_ms: 5_100,
                },
            ],
            consolidation_ms: 300,
            digest_size: 3,
            interrupt_severity: 3,
        }
    }

    fn items(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("item-{i:02}")).collect()
    }

    #[test]
    fn window_boundaries_start_inclusive_end_exclusive() {
        let c = cfg();
        // Outside, before.
        assert!(ingest_allowed(&c, None, 999), "before window => allowed");
        // Start is INSIDE (inclusive).
        assert!(!ingest_allowed(&c, None, 1_000), "start is inside");
        assert!(!ingest_allowed(&c, None, 1_500), "middle is inside");
        assert!(!ingest_allowed(&c, None, 1_999), "last instant inside");
        // End is OUTSIDE (exclusive).
        assert!(ingest_allowed(&c, None, 2_000), "end is outside");
        // Second window obeys the same rule.
        assert!(ingest_allowed(&c, None, 4_999));
        assert!(!ingest_allowed(&c, None, 5_000));
        assert!(!ingest_allowed(&c, None, 5_099));
        assert!(ingest_allowed(&c, None, 5_100));
        // Gap between windows is open.
        assert!(ingest_allowed(&c, None, 3_000));
    }

    #[test]
    fn empty_and_inverted_windows_match_nothing() {
        let c = QuietConfig {
            windows: vec![
                TimeWindow {
                    start_ms: 4_000,
                    end_ms: 3_000, // inverted
                },
                TimeWindow {
                    start_ms: 6_000,
                    end_ms: 6_000, // empty
                },
            ],
            consolidation_ms: 0,
            digest_size: 1,
            interrupt_severity: 1,
        };
        for t in [0i64, 3_500, 4_000, 5_000, 6_000, 7_000] {
            assert!(ingest_allowed(&c, None, t), "no window matches at {t}");
        }
        // No windows at all, no prior ingest: always allowed.
        let open = QuietConfig {
            windows: vec![],
            ..cfg()
        };
        assert!(ingest_allowed(&open, None, 1_500), "no windows => open");
    }

    #[test]
    fn consolidation_silence_pins() {
        let mut c = cfg();
        c.windows.clear();
        c.consolidation_ms = 300;
        assert!(!ingest_allowed(&c, Some(0), 0), "elapsed 0 blocked (inclusive)");
        assert!(!ingest_allowed(&c, Some(0), 1), "within cooldown");
        assert!(!ingest_allowed(&c, Some(0), 299), "last instant within");
        assert!(ingest_allowed(&c, Some(0), 300), "elapsed == c => allowed (exclusive end)");
        assert!(ingest_allowed(&c, Some(0), 301));
        // No prior ingest => no cooldown.
        assert!(ingest_allowed(&c, None, 0));
        // Clock skew: instant before the last ingest is not "within" the
        // cooldown window [last, last + c).
        assert!(ingest_allowed(&c, Some(1_000), 500), "skew before last => not in span");
        // consolidation_ms == 0 => empty cooldown span, never blocks.
        c.consolidation_ms = 0;
        for t in [0i64, 1, 1_000] {
            assert!(
                ingest_allowed(&c, Some(1_000), t),
                "zero cooldown never blocks (t={t})"
            );
        }
    }

    #[test]
    fn windows_and_consolidation_both_apply() {
        let c = cfg(); // windows [1000,2000) & [5000,5100); cooldown 300
        // Inside a window wins regardless of cooldown state.
        assert!(!ingest_allowed(&c, Some(1_900), 1_950), "window beats clear cooldown");
        // Window over, cooldown elapsed => allowed.
        assert!(ingest_allowed(&c, Some(1_000), 2_100));
        // Window over, cooldown active => blocked.
        assert!(!ingest_allowed(&c, Some(2_000), 2_100));
        // Cooldown exactly over at window edge => allowed.
        assert!(ingest_allowed(&c, Some(1_700), 2_000), "window end + cooldown end");
        // Both clear in the gap.
        assert!(ingest_allowed(&c, Some(2_000), 2_300));
    }

    #[test]
    fn should_digest_threshold_pins() {
        let c = cfg(); // digest_size 3
        assert!(!should_digest(&c, 0));
        assert!(!should_digest(&c, 2));
        assert!(should_digest(&c, 3), "pending == size => digest");
        assert!(should_digest(&c, 4));
        let one = QuietConfig {
            digest_size: 1,
            ..cfg()
        };
        assert!(should_digest(&one, 1));
        // Invalid config never fires (error surfaces via digest_batches).
        let zero = QuietConfig {
            digest_size: 0,
            ..cfg()
        };
        assert!(!should_digest(&zero, 0));
        assert!(!should_digest(&zero, 10));
    }

    #[test]
    fn digest_batches_chunk_in_order_last_partial_kept() {
        let c = cfg(); // size 3
        let got = digest_batches(&c, &items(7)).unwrap();
        let lens: Vec<usize> = got.iter().map(|b| b.len()).collect();
        assert_eq!(lens, vec![3, 3, 1], "chunk order + partial tail");
        assert_eq!(got[2], vec!["item-06".to_string()]);
        // Flattening preserves input order and content exactly.
        let flat: Vec<String> = got.iter().flatten().cloned().collect();
        assert_eq!(flat, items(7));
        // Exact multiple => no empty tail batch.
        let exact = digest_batches(&c, &items(6)).unwrap();
        assert_eq!(
            exact.iter().map(|b| b.len()).collect::<Vec<_>>(),
            vec![3, 3]
        );
        // Empty input => no batches.
        assert!(digest_batches(&c, &[]).unwrap().is_empty());
        // Single short batch.
        let short = digest_batches(&c, &items(2)).unwrap();
        assert_eq!(short.len(), 1);
        assert_eq!(short[0].len(), 2);
    }

    #[test]
    fn digest_batches_invalid_config() {
        let zero = QuietConfig {
            digest_size: 0,
            ..cfg()
        };
        assert_eq!(
            digest_batches(&zero, &items(4)),
            Err(QuietError::InvalidConfig)
        );
        assert_eq!(digest_batches(&zero, &[]), Err(QuietError::InvalidConfig));
        assert_eq!(validate(&zero), Err(QuietError::InvalidConfig));
        assert_eq!(validate(&cfg()), Ok(()));
    }

    #[test]
    fn alert_tiers_and_threshold_equality() {
        let c = cfg(); // interrupt_severity 3
        assert_eq!(classify_alert(&c, 0), AlertTier::Silent);
        assert_eq!(classify_alert(&c, 1), AlertTier::Digest);
        assert_eq!(classify_alert(&c, 2), AlertTier::Digest);
        assert_eq!(classify_alert(&c, 3), AlertTier::Immediate, "equality interrupts");
        assert_eq!(classify_alert(&c, 4), AlertTier::Immediate);
        assert_eq!(classify_alert(&c, 255), AlertTier::Immediate);

        // Threshold 1: only 0 is silent.
        let strict = QuietConfig {
            interrupt_severity: 1,
            ..cfg()
        };
        assert_eq!(classify_alert(&strict, 0), AlertTier::Silent);
        assert_eq!(classify_alert(&strict, 1), AlertTier::Immediate);

        // Degenerate threshold 0: severity 0 stays Silent (checked first —
        // a no-op alert must never be promotable), everything else interrupts.
        let degen = QuietConfig {
            interrupt_severity: 0,
            ..cfg()
        };
        assert_eq!(classify_alert(&degen, 0), AlertTier::Silent);
        assert_eq!(classify_alert(&degen, 1), AlertTier::Immediate);

        // Threshold 255: only 255 interrupts.
        let maxthr = QuietConfig {
            interrupt_severity: 255,
            ..cfg()
        };
        assert_eq!(classify_alert(&maxthr, 254), AlertTier::Digest);
        assert_eq!(classify_alert(&maxthr, 255), AlertTier::Immediate);
    }

    #[test]
    fn error_display_and_std_error() {
        let e = QuietError::InvalidConfig;
        assert_eq!(
            e.to_string(),
            "invalid quiet-window config: digest_size must be >= 1"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(QuietError::InvalidConfig);
        assert!(boxed.to_string().contains("digest_size"));
    }

    #[test]
    fn serde_roundtrips_and_shapes() {
        let w = TimeWindow {
            start_ms: -5,
            end_ms: 10,
        };
        let back: TimeWindow = serde_json::from_str(&serde_json::to_string(&w).unwrap()).unwrap();
        assert_eq!(w, back);

        let c = cfg();
        let back: QuietConfig = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(c, back);

        for tier in [AlertTier::Immediate, AlertTier::Digest, AlertTier::Silent] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: AlertTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
        assert_eq!(serde_json::to_string(&AlertTier::Immediate).unwrap(), "\"Immediate\"");

        let e = QuietError::InvalidConfig;
        let back: QuietError = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(e, back);
        assert_eq!(serde_json::to_string(&e).unwrap(), "\"InvalidConfig\"");
    }

    #[test]
    fn determinism_repeated_calls() {
        let c = cfg();
        let a = (ingest_allowed(&c, Some(1_500), 1_600), ingest_allowed(&c, Some(0), 400));
        let b = (ingest_allowed(&c, Some(1_500), 1_600), ingest_allowed(&c, Some(0), 400));
        assert_eq!(a, b, "same inputs => same verdicts");
        for _ in 0..5 {
            assert_eq!(digest_batches(&c, &items(7)).unwrap(), digest_batches(&c, &items(7)).unwrap());
            assert_eq!(classify_alert(&c, 3), classify_alert(&c, 3));
            assert_eq!(should_digest(&c, 3), should_digest(&c, 3));
        }
    }

    #[test]
    fn full_policy_night_cycle_scenario() {
        const MIN: i64 = 60_000;
        let c = QuietConfig {
            windows: vec![
                TimeWindow {
                    start_ms: 2 * 60 * MIN, // 02:00
                    end_ms: 2 * 60 * MIN + 30 * MIN, // 02:30
                },
                TimeWindow {
                    start_ms: 23 * 60 * MIN + 45 * MIN, // 23:45
                    end_ms: 24 * 60 * MIN,              // 24:00
                },
            ],
            consolidation_ms: 10 * MIN,
            digest_size: 5,
            interrupt_severity: 4,
        };
        // 01:59:59 — open; ingest accepted at 01:00.
        assert!(ingest_allowed(&c, Some(60 * MIN), 2 * 60 * MIN - 1_000));
        // 02:00:00 boundary — window start inclusive => blocked.
        assert!(!ingest_allowed(&c, Some(60 * MIN), 2 * 60 * MIN));
        // Mid-window — blocked.
        assert!(!ingest_allowed(&c, Some(60 * MIN), 2 * 60 * MIN + 5 * MIN));
        // 02:30:00 — window end exclusive AND cooldown long over => allowed.
        assert!(ingest_allowed(&c, Some(60 * MIN), 2 * 60 * MIN + 30 * MIN));
        // Ingest landed 02:30; +5 min still consolidating; +10 min open.
        assert!(!ingest_allowed(&c, Some(2 * 60 * MIN + 30 * MIN), 2 * 60 * MIN + 35 * MIN));
        assert!(ingest_allowed(&c, Some(2 * 60 * MIN + 30 * MIN), 2 * 60 * MIN + 40 * MIN));
        // 23:50 — evening window blocks.
        assert!(!ingest_allowed(&c, Some(20 * 60 * MIN), 23 * 60 * MIN + 50 * MIN));
        // Midnight boundary — exclusive end => allowed.
        assert!(ingest_allowed(&c, Some(20 * 60 * MIN), 24 * 60 * MIN));
        // Digest cadence: 4 findings held, 5 flushes as one batch; 12 => 5+5+2.
        assert!(!should_digest(&c, 4));
        assert!(should_digest(&c, 5));
        let batches = digest_batches(&c, &items(12)).unwrap();
        assert_eq!(batches.iter().map(|b| b.len()).collect::<Vec<_>>(), vec![5, 5, 2]);
        // Alert discipline through the night: 0 silent, 1..3 digest, 4+ immediate.
        assert_eq!(classify_alert(&c, 0), AlertTier::Silent);
        assert_eq!(classify_alert(&c, 3), AlertTier::Digest);
        assert_eq!(classify_alert(&c, 4), AlertTier::Immediate);
    }
}
