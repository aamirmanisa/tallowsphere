//! Price history tracking, stats, trends, and deal scoring.
//!
//! Consumes raw price observations (from the crawler / `price_observations`
//! table) and produces summary statistics, trend detection, chart-ready
//! downsampled series, and deal scores.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct PricePoint {
    pub timestamp: i64,
    pub price_cents: i64,
    pub sale_price_cents: Option<i64>,
    pub in_stock: bool,
    pub source: String,
}

impl PricePoint {
    /// Effective price = sale if present, else regular.
    pub fn effective_cents(&self) -> i64 {
        self.sale_price_cents.unwrap_or(self.price_cents)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendDirection {
    Rising,
    Falling,
    Stable,
    Volatile,
}

#[derive(Debug, Clone)]
pub struct HistoryStats {
    pub current_cents: Option<i64>,
    pub min_cents: i64,
    pub max_cents: i64,
    pub mean_cents: i64,
    pub median_cents: i64,
    pub stddev: f64,
    pub min_date: i64,
    pub max_date: i64,
    pub trend: TrendDirection,
    pub change_7d_percent: f64,
    pub change_30d_percent: f64,
    pub change_90d_percent: f64,
    pub is_lowest_in_30d: bool,
    pub is_lowest_in_90d: bool,
    pub is_lowest_ever: bool,
}

#[derive(Debug, Clone)]
pub struct PriceHistory {
    pub canonical_product_id: i64,
    pub store_id: i64,
    pub points: Vec<PricePoint>,
    pub stats: HistoryStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DealRarity {
    Common,
    Uncommon,
    Rare,
    HistoricLow,
}

#[derive(Debug, Clone)]
pub struct DealScore {
    pub score: f64,
    pub current_cents: i64,
    pub vs_mean_percent: f64,
    pub vs_min_percent: f64,
    pub rarity: DealRarity,
    pub reasoning: String,
}

const SECS_PER_DAY: i64 = 86_400;

/// In-memory price history engine. A real deployment would read from the
/// `price_observations` table; for now this keeps data in a nested map so
/// the module is independently testable.
#[derive(Default)]
pub struct PriceHistoryEngine {
    // (product_id, store_id) -> observations sorted by timestamp
    store: BTreeMap<(i64, i64), Vec<PricePoint>>,
}

impl PriceHistoryEngine {
    pub fn new() -> Self {
        Self { store: BTreeMap::new() }
    }

    /// Insert a raw observation. Keeps the underlying series sorted.
    pub fn record(&mut self, product_id: i64, store_id: i64, point: PricePoint) {
        let entry = self.store.entry((product_id, store_id)).or_default();
        entry.push(point);
        entry.sort_by_key(|p| p.timestamp);
    }

    /// Get history for a product/store over the last `days` (use a large
    /// value like i32::MAX for "all time").
    pub fn get_history(&self, product_id: i64, store_id: i64, days: i32) -> PriceHistory {
        let all = self
            .store
            .get(&(product_id, store_id))
            .cloned()
            .unwrap_or_default();

        let points: Vec<PricePoint> = if days <= 0 || days == i32::MAX {
            all
        } else if let Some(latest) = all.last().map(|p| p.timestamp) {
            let cutoff = latest - (days as i64) * SECS_PER_DAY;
            all.into_iter().filter(|p| p.timestamp >= cutoff).collect()
        } else {
            all
        };

        let stats = Self::compute_stats(&points);
        PriceHistory {
            canonical_product_id: product_id,
            store_id,
            points,
            stats,
        }
    }

    /// Compute summary statistics from a slice of points.
    pub fn compute_stats(points: &[PricePoint]) -> HistoryStats {
        if points.is_empty() {
            return HistoryStats {
                current_cents: None,
                min_cents: 0,
                max_cents: 0,
                mean_cents: 0,
                median_cents: 0,
                stddev: 0.0,
                min_date: 0,
                max_date: 0,
                trend: TrendDirection::Stable,
                change_7d_percent: 0.0,
                change_30d_percent: 0.0,
                change_90d_percent: 0.0,
                is_lowest_in_30d: false,
                is_lowest_in_90d: false,
                is_lowest_ever: false,
            };
        }

        let values: Vec<i64> = points.iter().map(|p| p.effective_cents()).collect();
        let min = *values.iter().min().unwrap();
        let max = *values.iter().max().unwrap();
        let sum: i64 = values.iter().sum();
        let mean = sum / values.len() as i64;

        let mut sorted = values.clone();
        sorted.sort();
        let median = sorted[sorted.len() / 2];

        let mean_f = mean as f64;
        let var = values
            .iter()
            .map(|v| {
                let d = *v as f64 - mean_f;
                d * d
            })
            .sum::<f64>()
            / values.len() as f64;
        let stddev = var.sqrt();

        let min_date = points.first().unwrap().timestamp;
        let max_date = points.last().unwrap().timestamp;
        let current = values.last().copied();

        let change = |days: i64| -> f64 {
            let cutoff = max_date - days * SECS_PER_DAY;
            let baseline = points
                .iter()
                .find(|p| p.timestamp >= cutoff)
                .map(|p| p.effective_cents())
                .unwrap_or(values[0]);
            let cur = *values.last().unwrap();
            if baseline == 0 {
                0.0
            } else {
                ((cur - baseline) as f64 / baseline as f64) * 100.0
            }
        };

        let change_7d = change(7);
        let change_30d = change(30);
        let change_90d = change(90);

        let lowest_within = |days: i64| -> bool {
            let cutoff = max_date - days * SECS_PER_DAY;
            let window_min = points
                .iter()
                .filter(|p| p.timestamp >= cutoff)
                .map(|p| p.effective_cents())
                .min()
                .unwrap_or(i64::MAX);
            current.map(|c| c <= window_min).unwrap_or(false)
        };

        let is_lowest_in_30d = lowest_within(30);
        let is_lowest_in_90d = lowest_within(90);
        let is_lowest_ever = current.map(|c| c <= min).unwrap_or(false);

        let trend = Self::detect_trend(points);

        HistoryStats {
            current_cents: current,
            min_cents: min,
            max_cents: max,
            mean_cents: mean,
            median_cents: median,
            stddev,
            min_date,
            max_date,
            trend,
            change_7d_percent: change_7d,
            change_30d_percent: change_30d,
            change_90d_percent: change_90d,
            is_lowest_in_30d,
            is_lowest_in_90d,
            is_lowest_ever,
        }
    }

    /// Classify the overall trend using least-squares slope and coefficient
    /// of variation as a volatility proxy.
    pub fn detect_trend(points: &[PricePoint]) -> TrendDirection {
        if points.len() < 2 {
            return TrendDirection::Stable;
        }

        let n = points.len() as f64;
        let xs: Vec<f64> = (0..points.len()).map(|i| i as f64).collect();
        let ys: Vec<f64> = points.iter().map(|p| p.effective_cents() as f64).collect();

        let mean_x = xs.iter().sum::<f64>() / n;
        let mean_y = ys.iter().sum::<f64>() / n;

        let mut num = 0.0;
        let mut den = 0.0;
        for i in 0..points.len() {
            num += (xs[i] - mean_x) * (ys[i] - mean_y);
            den += (xs[i] - mean_x).powi(2);
        }
        let slope = if den == 0.0 { 0.0 } else { num / den };

        let var = ys.iter().map(|v| (v - mean_y).powi(2)).sum::<f64>() / n;
        let stddev = var.sqrt();
        let cv = if mean_y == 0.0 { 0.0 } else { stddev / mean_y };

        if cv > 0.15 {
            TrendDirection::Volatile
        } else if slope > mean_y * 0.001 {
            TrendDirection::Rising
        } else if slope < -mean_y * 0.001 {
            TrendDirection::Falling
        } else {
            TrendDirection::Stable
        }
    }

    /// Score the current price as a deal relative to historical values.
    pub fn deal_score(history: &PriceHistory) -> DealScore {
        let stats = &history.stats;
        let current = stats.current_cents.unwrap_or(0);

        let vs_mean = if stats.mean_cents > 0 {
            ((current - stats.mean_cents) as f64 / stats.mean_cents as f64) * 100.0
        } else {
            0.0
        };
        let vs_min = if stats.min_cents > 0 {
            ((current - stats.min_cents) as f64 / stats.min_cents as f64) * 100.0
        } else {
            0.0
        };

        // Score: lower-vs-mean -> higher score. Historic low = 100.
        let mut score = 50.0 - vs_mean; // ~50 when equal to mean
        if stats.is_lowest_ever {
            score = 100.0;
        } else if stats.is_lowest_in_90d {
            score = score.max(85.0);
        } else if stats.is_lowest_in_30d {
            score = score.max(70.0);
        }
        let score = score.clamp(0.0, 100.0);

        let rarity = if stats.is_lowest_ever {
            DealRarity::HistoricLow
        } else if stats.is_lowest_in_90d {
            DealRarity::Rare
        } else if stats.is_lowest_in_30d {
            DealRarity::Uncommon
        } else {
            DealRarity::Common
        };

        let reasoning = format!(
            "current {}c, mean {}c ({:+.1}% vs mean), min {}c ({:+.1}% vs min), trend {:?}",
            current, stats.mean_cents, vs_mean, stats.min_cents, vs_min, stats.trend
        );

        DealScore {
            score,
            current_cents: current,
            vs_mean_percent: vs_mean,
            vs_min_percent: vs_min,
            rarity,
            reasoning,
        }
    }

    /// Uniform-bucket downsampling. Averages points within each bucket so
    /// chart clients get at most ~target_count points.
    pub fn downsample(points: &[PricePoint], target_count: usize) -> Vec<PricePoint> {
        if target_count == 0 || points.len() <= target_count {
            return points.to_vec();
        }
        let bucket_size = (points.len() + target_count - 1) / target_count;
        let mut out = Vec::with_capacity(target_count);
        for chunk in points.chunks(bucket_size) {
            let ts = chunk.iter().map(|p| p.timestamp).sum::<i64>() / chunk.len() as i64;
            let price = chunk.iter().map(|p| p.price_cents).sum::<i64>() / chunk.len() as i64;
            let sale_vals: Vec<i64> =
                chunk.iter().filter_map(|p| p.sale_price_cents).collect();
            let sale = if sale_vals.is_empty() {
                None
            } else {
                Some(sale_vals.iter().sum::<i64>() / sale_vals.len() as i64)
            };
            let in_stock = chunk.iter().any(|p| p.in_stock);
            out.push(PricePoint {
                timestamp: ts,
                price_cents: price,
                sale_price_cents: sale,
                in_stock,
                source: chunk[0].source.clone(),
            });
        }
        out
    }

    /// Fill gaps in observations by forward-filling the last known value
    /// at fixed intervals.
    pub fn gap_fill(points: &[PricePoint], interval_hours: i64) -> Vec<PricePoint> {
        if points.len() < 2 || interval_hours <= 0 {
            return points.to_vec();
        }
        let step = interval_hours * 3600;
        let mut out = Vec::new();
        for i in 0..points.len() - 1 {
            out.push(points[i].clone());
            let gap = points[i + 1].timestamp - points[i].timestamp;
            if gap > step * 2 {
                let mut t = points[i].timestamp + step;
                while t < points[i + 1].timestamp {
                    let mut filled = points[i].clone();
                    filled.timestamp = t;
                    out.push(filled);
                    t += step;
                }
            }
        }
        out.push(points.last().unwrap().clone());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(ts: i64, price: i64) -> PricePoint {
        PricePoint {
            timestamp: ts,
            price_cents: price,
            sale_price_cents: None,
            in_stock: true,
            source: "test".into(),
        }
    }

    #[test]
    fn stats_basic() {
        let pts = vec![mk(0, 1000), mk(SECS_PER_DAY, 900), mk(2 * SECS_PER_DAY, 800)];
        let s = PriceHistoryEngine::compute_stats(&pts);
        assert_eq!(s.min_cents, 800);
        assert_eq!(s.max_cents, 1000);
        assert_eq!(s.mean_cents, 900);
        assert_eq!(s.current_cents, Some(800));
        assert!(s.is_lowest_ever);
        assert_eq!(s.trend, TrendDirection::Falling);
    }

    #[test]
    fn stats_empty() {
        let s = PriceHistoryEngine::compute_stats(&[]);
        assert_eq!(s.current_cents, None);
        assert_eq!(s.trend, TrendDirection::Stable);
    }

    #[test]
    fn trend_rising() {
        let pts: Vec<_> = (0..10).map(|i| mk(i * SECS_PER_DAY, 1000 + i * 20)).collect();
        assert_eq!(PriceHistoryEngine::detect_trend(&pts), TrendDirection::Rising);
    }

    #[test]
    fn trend_volatile() {
        let pts = vec![
            mk(0, 1000),
            mk(SECS_PER_DAY, 500),
            mk(2 * SECS_PER_DAY, 1500),
            mk(3 * SECS_PER_DAY, 400),
        ];
        assert_eq!(
            PriceHistoryEngine::detect_trend(&pts),
            TrendDirection::Volatile
        );
    }

    #[test]
    fn engine_record_and_query() {
        let mut e = PriceHistoryEngine::new();
        for i in 0..5 {
            e.record(1, 1, mk(i * SECS_PER_DAY, 1000 - i * 50));
        }
        let h = e.get_history(1, 1, i32::MAX);
        assert_eq!(h.points.len(), 5);
        assert_eq!(h.stats.min_cents, 800);
    }

    #[test]
    fn deal_score_historic_low() {
        let pts = vec![mk(0, 2000), mk(SECS_PER_DAY, 1800), mk(2 * SECS_PER_DAY, 1500)];
        let stats = PriceHistoryEngine::compute_stats(&pts);
        let h = PriceHistory {
            canonical_product_id: 1,
            store_id: 1,
            points: pts,
            stats,
        };
        let d = PriceHistoryEngine::deal_score(&h);
        assert_eq!(d.rarity, DealRarity::HistoricLow);
        assert!((d.score - 100.0).abs() < 0.01);
    }

    #[test]
    fn downsample_reduces() {
        let pts: Vec<_> = (0..100).map(|i| mk(i, 1000 + i)).collect();
        let out = PriceHistoryEngine::downsample(&pts, 10);
        assert!(out.len() <= 10);
        assert!(!out.is_empty());
    }

    #[test]
    fn downsample_small_passthrough() {
        let pts = vec![mk(0, 100), mk(1, 200)];
        let out = PriceHistoryEngine::downsample(&pts, 10);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn gap_fill_inserts() {
        let pts = vec![mk(0, 1000), mk(10 * 3600, 1100)];
        let out = PriceHistoryEngine::gap_fill(&pts, 1);
        assert!(out.len() > 2);
    }
}
