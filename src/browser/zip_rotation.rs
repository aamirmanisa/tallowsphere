//! Geographic ZIP code rotation (T3.24).
//!
//! Many retailers (Walmart, Target, Kroger, Best Buy, Home Depot, Lowe's) serve
//! different prices, availability, and layouts based on the delivery ZIP code.
//! This rotator seeds a representative set of ZIPs per retailer, picks the
//! least-recently-used next, and tracks success/failure for adaptive ranking.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    Northeast,
    Southeast,
    Midwest,
    Southwest,
    West,
    Pacific,
}

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub zip: String,
    pub state: String,
    pub population: u32,
    pub region: Region,
    pub last_used: Option<i64>,
    pub success_count: u64,
    pub failure_count: u64,
}

#[derive(Debug, Clone)]
pub struct ZipPool {
    pub retailer: String,
    pub zips: Vec<ZipEntry>,
    pub current_index: usize,
}

pub struct ZipRotator {
    pools: HashMap<String, ZipPool>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 20 representative US ZIPs across all regions, used for every retailer seed.
fn default_zip_set() -> Vec<(&'static str, &'static str, u32, Region)> {
    vec![
        // Midwest
        ("46204", "IN", 800_000, Region::Midwest),
        ("60601", "IL", 2_700_000, Region::Midwest),
        ("44101", "OH", 370_000, Region::Midwest),
        ("63101", "MO", 300_000, Region::Midwest),
        // Southeast
        ("30303", "GA", 500_000, Region::Southeast),
        ("33101", "FL", 470_000, Region::Southeast),
        ("28202", "NC", 870_000, Region::Southeast),
        // Southwest
        ("77001", "TX", 2_300_000, Region::Southwest),
        ("75201", "TX", 1_300_000, Region::Southwest),
        ("85001", "AZ", 1_600_000, Region::Southwest),
        // West
        ("90001", "CA", 3_900_000, Region::West),
        ("94101", "CA", 870_000, Region::West),
        ("80201", "CO", 720_000, Region::West),
        ("89101", "NV", 640_000, Region::West),
        ("84101", "UT", 200_000, Region::West),
        // Northeast
        ("10001", "NY", 8_400_000, Region::Northeast),
        ("02101", "MA", 690_000, Region::Northeast),
        ("19101", "PA", 1_600_000, Region::Northeast),
        // Pacific
        ("98101", "WA", 740_000, Region::Pacific),
        ("97201", "OR", 650_000, Region::Pacific),
    ]
}

impl Default for ZipRotator {
    fn default() -> Self {
        Self::new()
    }
}

impl ZipRotator {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    /// Seed all major retailers with the default 20 ZIPs.
    pub fn seed_defaults(&mut self) {
        let retailers = [
            "walmart",
            "target",
            "kroger",
            "bestbuy",
            "homedepot",
            "lowes",
        ];
        for retailer in retailers {
            let mut zips = Vec::new();
            for (zip, state, pop, region) in default_zip_set() {
                zips.push(ZipEntry {
                    zip: zip.to_string(),
                    state: state.to_string(),
                    population: pop,
                    region,
                    last_used: None,
                    success_count: 0,
                    failure_count: 0,
                });
            }
            self.pools.insert(
                retailer.to_string(),
                ZipPool {
                    retailer: retailer.to_string(),
                    zips,
                    current_index: 0,
                },
            );
        }
    }

    /// Add a custom ZIP pool for a retailer.
    pub fn add_pool(&mut self, retailer: &str, zips: Vec<ZipEntry>) {
        self.pools.insert(
            retailer.to_string(),
            ZipPool {
                retailer: retailer.to_string(),
                zips,
                current_index: 0,
            },
        );
    }

    /// Pick next ZIP for a retailer using least-recently-used.
    ///
    /// Ties are broken by higher success rate, then lower failure count.
    pub fn next_zip(&mut self, retailer: &str) -> Option<String> {
        let pool = self.pools.get_mut(retailer)?;
        if pool.zips.is_empty() {
            return None;
        }

        // Find the LRU entry (None counts as oldest).
        let mut best: Option<usize> = None;
        let mut best_key: (i64, f64, u64) = (i64::MAX, f64::MIN, u64::MAX);
        for (i, z) in pool.zips.iter().enumerate() {
            let last = z.last_used.unwrap_or(i64::MIN);
            let total = z.success_count + z.failure_count;
            let success_rate = if total == 0 {
                0.5
            } else {
                z.success_count as f64 / total as f64
            };
            // Sort key: older first, then higher success_rate, then fewer failures
            let key = (last, -success_rate, z.failure_count);
            // Custom compare since f64 isn't Ord
            let better = match best {
                None => true,
                Some(_) => {
                    key.0 < best_key.0
                        || (key.0 == best_key.0 && -key.1 > -best_key.1)
                        || (key.0 == best_key.0 && (key.1 - best_key.1).abs() < 1e-12 && key.2 < best_key.2)
                }
            };
            if better {
                best = Some(i);
                best_key = key;
            }
        }

        let idx = best?;
        pool.zips[idx].last_used = Some(now_secs());
        pool.current_index = idx;
        Some(pool.zips[idx].zip.clone())
    }

    /// Record a success or failure for (retailer, zip).
    pub fn record_result(&mut self, retailer: &str, zip: &str, success: bool) {
        if let Some(pool) = self.pools.get_mut(retailer) {
            if let Some(entry) = pool.zips.iter_mut().find(|z| z.zip == zip) {
                if success {
                    entry.success_count += 1;
                } else {
                    entry.failure_count += 1;
                }
            }
        }
    }

    /// Get a ZIP for a specific region (first match), if any.
    pub fn zip_for_region(&self, retailer: &str, region: Region) -> Option<String> {
        let pool = self.pools.get(retailer)?;
        pool.zips
            .iter()
            .find(|z| z.region == region)
            .map(|z| z.zip.clone())
    }

    /// Read-only accessor for a pool.
    pub fn pool(&self, retailer: &str) -> Option<&ZipPool> {
        self.pools.get(retailer)
    }

    /// Number of retailers seeded.
    pub fn retailer_count(&self) -> usize {
        self.pools.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_defaults_populates_six_retailers_with_twenty_zips() {
        let mut r = ZipRotator::new();
        r.seed_defaults();
        assert_eq!(r.retailer_count(), 6);
        for retailer in ["walmart", "target", "kroger", "bestbuy", "homedepot", "lowes"] {
            let p = r.pool(retailer).expect("pool exists");
            assert_eq!(p.zips.len(), 20);
        }
    }

    #[test]
    fn next_zip_rotates_through_unused_before_repeating() {
        let mut r = ZipRotator::new();
        r.seed_defaults();
        let mut seen = Vec::new();
        for _ in 0..20 {
            let z = r.next_zip("walmart").expect("zip");
            seen.push(z);
        }
        // Every ZIP seen at least once
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 20);
    }

    #[test]
    fn record_result_updates_counts() {
        let mut r = ZipRotator::new();
        r.seed_defaults();
        r.record_result("target", "10001", true);
        r.record_result("target", "10001", true);
        r.record_result("target", "10001", false);
        let pool = r.pool("target").unwrap();
        let entry = pool.zips.iter().find(|z| z.zip == "10001").unwrap();
        assert_eq!(entry.success_count, 2);
        assert_eq!(entry.failure_count, 1);
    }

    #[test]
    fn zip_for_region_returns_matching_region() {
        let mut r = ZipRotator::new();
        r.seed_defaults();
        let z = r.zip_for_region("walmart", Region::Pacific).unwrap();
        assert!(z == "98101" || z == "97201");
    }

    #[test]
    fn next_zip_none_for_unknown_retailer() {
        let mut r = ZipRotator::new();
        r.seed_defaults();
        assert!(r.next_zip("costco").is_none());
    }
}
