//! Affiliate link wrapping and click tracking.
//!
//! Detects which affiliate network a product URL belongs to, rewrites the URL
//! to include our tracking tag, estimates commission, and records clicks for
//! later analytics and attribution.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A single affiliate network configuration.
#[derive(Debug, Clone)]
pub struct AffiliateNetwork {
    pub code: String,
    pub name: String,
    pub tracking_param: String,
    pub our_tag: String,
    pub commission_percent: f64,
}

/// Result of wrapping a URL with an affiliate tag.
#[derive(Debug, Clone)]
pub struct WrappedLink {
    pub original_url: String,
    pub wrapped_url: String,
    pub network: String,
    pub estimated_commission_cents: i64,
}

/// Recorded click event (in-memory; persistence handled elsewhere).
#[derive(Debug, Clone)]
pub struct ClickRecord {
    pub user_id: i64,
    pub original_url: String,
    pub wrapped_url: String,
    pub network: String,
    pub clicked_at: i64,
}

pub struct AffiliateManager {
    networks: HashMap<String, AffiliateNetwork>,
    /// network code → our tag (duplicated for O(1) lookup without lock).
    user_tags: HashMap<String, String>,
    clicks: Arc<Mutex<Vec<ClickRecord>>>,
}

impl Default for AffiliateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AffiliateManager {
    pub fn new() -> Self {
        let mut networks = HashMap::new();
        let mut user_tags = HashMap::new();

        let defaults = [
            ("amazon",    "Amazon Associates",   "tag",         "hackthecart-20",      4.0),
            ("walmart",   "Walmart Affiliate",   "wmlspartner", "hackthecart",         4.0),
            ("target",    "Target Affiliate",    "afsrc",       "hackthecart",         5.0),
            ("bestbuy",   "Best Buy Affiliate",  "ref",         "hackthecart",         1.0),
            ("skimlinks", "Skimlinks",           "sref",        "hackthecart",         5.0),
            ("rakuten",   "Rakuten Advertising", "u1",          "hackthecart",         5.0),
            ("impact",    "Impact.com",          "irclickid",   "hackthecart",         5.0),
            ("cj",        "CJ Affiliate",        "sid",         "hackthecart",         5.0),
        ];

        for (code, name, param, tag, pct) in defaults {
            let net = AffiliateNetwork {
                code: code.to_string(),
                name: name.to_string(),
                tracking_param: param.to_string(),
                our_tag: tag.to_string(),
                commission_percent: pct,
            };
            user_tags.insert(code.to_string(), tag.to_string());
            networks.insert(code.to_string(), net);
        }

        Self {
            networks,
            user_tags,
            clicks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Override the tag for a specific network (e.g. from env / config).
    pub fn set_tag(&mut self, network: &str, tag: String) {
        if let Some(net) = self.networks.get_mut(network) {
            net.our_tag = tag.clone();
        }
        self.user_tags.insert(network.to_string(), tag);
    }

    /// Detect which network a URL belongs to, based on host.
    pub fn detect_network(url: &str) -> Option<String> {
        let lower = url.to_ascii_lowercase();
        let host_part = lower
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&lower);
        let host = host_part.split('/').next().unwrap_or("");

        if host.contains("amazon.") || host.contains("amzn.to") {
            Some("amazon".to_string())
        } else if host.contains("walmart.com") {
            Some("walmart".to_string())
        } else if host.contains("target.com") {
            Some("target".to_string())
        } else if host.contains("bestbuy.com") {
            Some("bestbuy".to_string())
        } else if host.contains("rakuten.") {
            Some("rakuten".to_string())
        } else {
            // Fall back to skimlinks for unknown retailers (they handle routing).
            Some("skimlinks".to_string())
        }
    }

    /// Wrap a URL with the appropriate affiliate tracking parameters.
    pub fn wrap(&self, url: &str, product_price_cents: i64) -> WrappedLink {
        let network = Self::detect_network(url).unwrap_or_else(|| "skimlinks".to_string());
        let tag = self
            .user_tags
            .get(&network)
            .cloned()
            .unwrap_or_else(|| "hackthecart".to_string());

        let wrapped = match network.as_str() {
            "amazon"    => Self::wrap_amazon(url, &tag),
            "walmart"   => Self::wrap_walmart(url, &tag),
            "skimlinks" => Self::wrap_skimlinks(url, &tag),
            other => {
                // Generic: append the configured tracking param.
                if let Some(net) = self.networks.get(other) {
                    Self::append_param(url, &net.tracking_param, &tag)
                } else {
                    url.to_string()
                }
            }
        };

        let pct = self
            .networks
            .get(&network)
            .map(|n| n.commission_percent)
            .unwrap_or(0.0);
        let est = ((product_price_cents as f64) * pct / 100.0).round() as i64;

        WrappedLink {
            original_url: url.to_string(),
            wrapped_url: wrapped,
            network,
            estimated_commission_cents: est,
        }
    }

    /// Amazon: append `?tag=hackthecart-20` (or replace if present).
    pub fn wrap_amazon(url: &str, tag: &str) -> String {
        Self::append_param(url, "tag", tag)
    }

    /// Walmart: append `?wmlspartner=hackthecart`.
    pub fn wrap_walmart(url: &str, tag: &str) -> String {
        Self::append_param(url, "wmlspartner", tag)
    }

    /// Skimlinks: rewrite via go.skimresources.com.
    pub fn wrap_skimlinks(url: &str, tag: &str) -> String {
        format!(
            "https://go.skimresources.com/?id={}&xs=1&url={}",
            tag,
            urlencode(url)
        )
    }

    /// Append or replace a query parameter in a URL (simple, no crate dep).
    fn append_param(url: &str, key: &str, value: &str) -> String {
        // Strip existing occurrences of `key=...` so we don't duplicate.
        let (base, fragment) = match url.split_once('#') {
            Some((b, f)) => (b.to_string(), Some(f.to_string())),
            None => (url.to_string(), None),
        };

        let (path, query) = match base.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (base.clone(), None),
        };

        let mut kept: Vec<String> = Vec::new();
        if let Some(q) = query {
            for pair in q.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
                if k != key {
                    kept.push(pair.to_string());
                }
            }
        }
        kept.push(format!("{}={}", key, value));

        let mut out = format!("{}?{}", path, kept.join("&"));
        if let Some(f) = fragment {
            out.push('#');
            out.push_str(&f);
        }
        out
    }

    /// Record a click. Persistence is the caller's responsibility; this keeps
    /// an in-memory buffer that can be drained for batch insert.
    pub fn record_click(&self, user_id: i64, url: &str) {
        let network = Self::detect_network(url).unwrap_or_default();
        let wrapped = self.wrap(url, 0).wrapped_url;
        let record = ClickRecord {
            user_id,
            original_url: url.to_string(),
            wrapped_url: wrapped,
            network,
            clicked_at: current_epoch_secs(),
        };
        if let Ok(mut buf) = self.clicks.lock() {
            buf.push(record);
        }
    }

    /// Drain and return all buffered clicks (for batch persistence).
    pub fn drain_clicks(&self) -> Vec<ClickRecord> {
        self.clicks
            .lock()
            .map(|mut b| std::mem::take(&mut *b))
            .unwrap_or_default()
    }

    pub fn networks(&self) -> &HashMap<String, AffiliateNetwork> {
        &self.networks
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn current_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_amazon() {
        assert_eq!(
            AffiliateManager::detect_network("https://www.amazon.com/dp/B0XYZ"),
            Some("amazon".to_string())
        );
    }

    #[test]
    fn wraps_amazon_tag() {
        let m = AffiliateManager::new();
        let w = m.wrap("https://www.amazon.com/dp/B0XYZ", 10_00);
        assert!(w.wrapped_url.contains("tag=hackthecart-20"));
        assert_eq!(w.network, "amazon");
        assert_eq!(w.estimated_commission_cents, 40); // 4% of $10
    }

    #[test]
    fn replaces_existing_tag() {
        let m = AffiliateManager::new();
        let w = m.wrap("https://www.amazon.com/dp/B0XYZ?tag=other-20&foo=bar", 0);
        assert!(w.wrapped_url.contains("tag=hackthecart-20"));
        assert!(!w.wrapped_url.contains("tag=other-20"));
        assert!(w.wrapped_url.contains("foo=bar"));
    }

    #[test]
    fn skimlinks_unknown_host() {
        let m = AffiliateManager::new();
        let w = m.wrap("https://random-store.example.com/p/123", 2000);
        assert_eq!(w.network, "skimlinks");
        assert!(w.wrapped_url.contains("go.skimresources.com"));
    }
}
