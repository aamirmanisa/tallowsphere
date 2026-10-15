//! Advanced proxy intelligence: ASN classification, diversity enforcement,
//! enhanced scoring, domain-aware strategy, and pool health analytics.
//!
//! Integrates with `proxy.rs` to provide smarter proxy selection based on
//! ASN trust scores, geographic matching, and per-domain requirements.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::browser::proxy::{ProxyEntry, ProxyHealth, ProxyPool, ProxyTier};

// ─────────────────────────────────────────────────────────────────────────────
// External Reputation Screening (IPQS / ipinfo feed + TTL cache)
// ─────────────────────────────────────────────────────────────────────────────

/// Default cache TTL for reputation records (6 hours).
pub const DEFAULT_REPUTATION_TTL: Duration = Duration::from_secs(6 * 3600);

/// External IP-reputation result: whether the IP is a known proxy/VPN/hosting
/// endpoint, its fraud score, ASN, and geo, as reported by a third-party feed.
#[derive(Debug, Clone)]
pub struct ReputationRecord {
    /// The IP address this record describes.
    pub ip: String,
    /// True if the feed flags this IP as a proxy / VPN / hosting endpoint.
    pub is_proxy: bool,
    /// Fraud score 0-100 from the feed (higher = riskier). 0 when unknown.
    pub fraud_score: u8,
    /// Autonomous System number reported for this IP.
    pub asn: u32,
    /// ASN organization / ISP name.
    pub asn_org: String,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// Free-form geo label (city, region).
    pub geo: String,
    /// When the record was fetched.
    pub fetched_at: Instant,
    /// How long the record stays valid in the cache.
    pub ttl: Duration,
}

impl ReputationRecord {
    /// Neutral fail-open record used when a lookup errors (keeps pool alive).
    pub fn neutral(ip: &str, asn: u32) -> Self {
        Self {
            ip: ip.to_string(),
            is_proxy: false,
            fraud_score: 0,
            asn,
            asn_org: String::new(),
            country: "XX".into(),
            geo: String::new(),
            fetched_at: Instant::now(),
            ttl: DEFAULT_REPUTATION_TTL,
        }
    }

    /// Whether this record signals a proxy that should be avoided/downgraded.
    pub fn is_bad(&self) -> bool {
        self.is_proxy || self.fraud_score >= 60
    }
}

/// Client that screens proxy IPs against an external reputation / geo feed,
/// with an in-memory TTL cache. Fail-open: on any lookup error it returns a
/// neutral record instead of breaking the pool.
#[derive(Debug, Clone)]
pub struct EgressReputationClient {
    cache: HashMap<String, ReputationRecord>,
    ttl: Duration,
}

impl EgressReputationClient {
    /// Create a client with the default 6-hour cache TTL.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            ttl: DEFAULT_REPUTATION_TTL,
        }
    }

    /// Return the cached record for `ip` if present and not expired.
    pub fn cached(&self, ip: &str) -> Option<&ReputationRecord> {
        self.cache.get(ip).and_then(|r| {
            if r.fetched_at.elapsed() < r.ttl {
                Some(r)
            } else {
                None
            }
        })
    }

    /// Look up the external reputation / geo for `ip` with a fallback `asn`.
    ///
    /// Checks the in-memory TTL cache first; on a miss it performs a real HTTP
    /// lookup to IPQualityScore (if `TALLOW_IPQS_KEY` is set) or the free
    /// ipinfo.io endpoint for ASN + geo. The result is cached with a TTL.
    /// Always returns a record — on network/parse errors a neutral, fail-open
    /// record is produced so the proxy pool is never broken.
    pub fn ip_reputation(&mut self, ip: &str, asn: u32) -> ReputationRecord {
        if let Some(r) = self.cached(ip) {
            return r.clone();
        }
        let record = match fetch_external_reputation(ip) {
            Some(r) => r,
            None => ReputationRecord::neutral(ip, asn),
        };
        // Opportunistic eviction of expired entries to bound cache growth.
        if self.cache.len() > 4096 {
            self.cache.retain(|_, r| r.fetched_at.elapsed() < r.ttl);
        }
        self.cache.insert(ip.to_string(), record.clone());
        record
    }

    /// Explicitly set the cache TTL (mostly for tests / tuning).
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }
}

impl Default for EgressReputationClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform the actual HTTP reputation lookup for `ip`.
///
/// Priority: IPQualityScore when `TALLOW_IPQS_KEY` is set (proxy + fraud score
/// + ASN + geo), otherwise the free ipinfo.io endpoint for ASN + geo. Returns
/// `None` on any failure so the caller can fail open.
fn fetch_external_reputation(ip: &str) -> Option<ReputationRecord> {
    if let Ok(key) = std::env::var("TALLOW_IPQS_KEY") {
        if !key.is_empty() {
            if let Some(r) = fetch_ipqs(ip, &key) {
                return Some(r);
            }
        }
    }
    fetch_ipinfo(ip)
}

/// IPQualityScore lookup (needs `TALLOW_IPQS_KEY`). Gives proxy/fraud/ASN/geo.
fn fetch_ipqs(ip: &str, key: &str) -> Option<ReputationRecord> {
    let url = format!("https://ipqualityscore.com/api/json/ip/{key}/{ip}");
    // T-207: contract-bound lookup — egress reputation is only meaningful
    // when the query itself rides the egress.
    let agent = crate::runtime::egress_http::agent_with_timeouts(
        Some(std::time::Duration::from_secs(10)),
        None,
    );
    let body = agent.get(&url).call().ok()?.body_mut().read_to_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    if !v.get("success").and_then(|x| x.as_bool()).unwrap_or(false) {
        return None;
    }
    let is_proxy = v.get("proxy").and_then(|x| x.as_bool()).unwrap_or(false)
        || v.get("vpn").and_then(|x| x.as_bool()).unwrap_or(false)
        || v.get("tor").and_then(|x| x.as_bool()).unwrap_or(false);
    let fraud = v
        .get("fraud_score")
        .and_then(|x| x.as_u64())
        .unwrap_or(0)
        .min(100) as u8;
    let asn = v
        .get("ASN")
        .and_then(|x| x.as_str())
        .and_then(|s| s.trim_start_matches("AS").parse::<u32>().ok())
        .unwrap_or(0);
    let asn_org = v.get("ISP").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let country = v
        .get("country_code")
        .and_then(|x| x.as_str())
        .unwrap_or("XX")
        .to_string();
    let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let region = v.get("region").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(ReputationRecord {
        ip: ip.to_string(),
        is_proxy,
        fraud_score: fraud,
        asn,
        asn_org,
        country,
        geo: join_geo(&city, &region),
        fetched_at: Instant::now(),
        ttl: DEFAULT_REPUTATION_TTL,
    })
}

/// Free ipinfo.io lookup for ASN + geo (no key required). Does not report
/// proxy status, so `is_proxy`/`fraud_score` stay neutral (fail-open).
fn fetch_ipinfo(ip: &str) -> Option<ReputationRecord> {
    let url = format!("https://ipinfo.io/json/{ip}");
    // T-207: contract-bound lookup (Tor by default).
    let agent = crate::runtime::egress_http::agent_with_timeouts(
        Some(std::time::Duration::from_secs(10)),
        None,
    );
    let body = agent.get(&url).call().ok()?.body_mut().read_to_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    // org is typically "AS7922 Comcast Cable Communications, LLC".
    let org_str = v.get("org").and_then(|x| x.as_str()).unwrap_or("");
    let (mut asn, asn_org) = parse_org(org_str);
    // ipinfo's structured `asn` object is more reliable when present.
    if asn == 0 {
        asn = v
            .get("asn")
            .and_then(|x| x.get("asn"))
            .and_then(|x| x.as_str())
            .and_then(|s| s.trim_start_matches("AS").parse::<u32>().ok())
            .unwrap_or(0);
    }
    let country = v
        .get("country")
        .and_then(|x| x.as_str())
        .unwrap_or("XX")
        .to_string();
    let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let region = v.get("region").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(ReputationRecord {
        ip: ip.to_string(),
        is_proxy: false,
        fraud_score: 0,
        asn,
        asn_org,
        country,
        geo: join_geo(&city, &region),
        fetched_at: Instant::now(),
        ttl: DEFAULT_REPUTATION_TTL,
    })
}

/// Join city/region into a "City, Region" label (trims empty sides).
fn join_geo(city: &str, region: &str) -> String {
    match (city.is_empty(), region.is_empty()) {
        (false, false) => format!("{city}, {region}"),
        (false, true) => city.to_string(),
        (true, false) => region.to_string(),
        (true, true) => String::new(),
    }
}

/// Parse an "AS7922 Organization" org string into (asn, org_name).
fn parse_org(org: &str) -> (u32, String) {
    let t = org.trim();
    let lower = t.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("as") {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            if let Ok(n) = digits.parse::<u32>() {
                let name = rest[digits.len()..].trim().to_string();
                return (n, name);
            }
        }
    }
    (0, t.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// ASN Types & Database
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of an Autonomous System Number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsnType {
    /// Residential ISPs (Comcast, AT&T, Verizon). Trust 85-95.
    Residential,
    /// Mobile carriers (T-Mobile, AT&T Wireless). Trust 90-100.
    Mobile,
    /// ISP-grade proxies: datacenter speed, residential ASN. Trust 80-90.
    Isp,
    /// Major cloud / datacenter providers (AWS, GCP, Hetzner). Trust 20-40.
    Datacenter,
    /// Smaller hosting providers. Trust 30-50.
    Hosting,
    /// Universities and research networks. Trust 70-80.
    Education,
    /// Enterprise / corporate networks. Trust 60-75.
    Corporate,
    /// Tor exit nodes. Trust 10-30.
    Tor,
    /// CDN edge nodes (Cloudflare, Fastly, Akamai). Trust 15-35.
    Cdn,
}

impl AsnType {
    /// Convert a `ProxyTier` to the closest `AsnType`.
    pub fn from_proxy_tier(tier: ProxyTier) -> Self {
        match tier {
            ProxyTier::Mobile => AsnType::Mobile,
            ProxyTier::Residential => AsnType::Residential,
            ProxyTier::Isp => AsnType::Isp,
            ProxyTier::Datacenter => AsnType::Datacenter,
            ProxyTier::Tor => AsnType::Tor,
            ProxyTier::Direct => AsnType::Isp, // direct is local network
        }
    }

    /// Display name.
    pub fn name(&self) -> &'static str {
        match self {
            AsnType::Residential => "residential",
            AsnType::Mobile => "mobile",
            AsnType::Isp => "isp",
            AsnType::Datacenter => "datacenter",
            AsnType::Hosting => "hosting",
            AsnType::Education => "education",
            AsnType::Corporate => "corporate",
            AsnType::Tor => "tor",
            AsnType::Cdn => "cdn",
        }
    }
}

impl std::fmt::Display for AsnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Information about a single Autonomous System.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    /// AS number (e.g. 7922 for Comcast).
    pub asn: u32,
    /// Organization name.
    pub organization: String,
    /// Classification.
    pub asn_type: AsnType,
    /// Trust score 0-100 — higher means less likely to be blocked.
    pub trust_score: u8,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// Protection services known to block this ASN.
    pub known_blocked_by: Vec<String>,
}

/// Hardcoded ASN intelligence database.
#[derive(Debug, Clone)]
pub struct AsnDatabase {
    entries: HashMap<u32, AsnInfo>,
}

impl Default for AsnDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl AsnDatabase {
    /// Build the built-in database of 200+ well-known ASNs.
    pub fn new() -> Self {
        let mut entries = HashMap::with_capacity(220);

        // Helper to insert one entry concisely.
        macro_rules! asn {
            ($asn:expr, $org:expr, $ty:expr, $trust:expr, $cc:expr $(, blocked: [$($b:expr),*])?) => {
                entries.insert($asn, AsnInfo {
                    asn: $asn,
                    organization: $org.into(),
                    asn_type: $ty,
                    trust_score: $trust,
                    country: $cc.into(),
                    known_blocked_by: vec![$($($b.into()),*)?],
                });
            };
        }

        // ── US Residential ISPs ──────────────────────────────────────────
        asn!(7922, "Comcast", AsnType::Residential, 90, "US");
        asn!(7018, "AT&T", AsnType::Residential, 92, "US");
        asn!(701, "Verizon", AsnType::Residential, 91, "US");
        asn!(11351, "Charter/Spectrum", AsnType::Residential, 89, "US");
        asn!(22773, "Cox Communications", AsnType::Residential, 88, "US");
        asn!(
            20115,
            "Charter Communications",
            AsnType::Residential,
            87,
            "US"
        );
        asn!(10796, "TWC/Spectrum", AsnType::Residential, 87, "US");
        asn!(33491, "Comcast Cable", AsnType::Residential, 89, "US");
        asn!(6389, "BellSouth/AT&T", AsnType::Residential, 88, "US");
        asn!(11426, "TWC/Spectrum", AsnType::Residential, 86, "US");
        asn!(11427, "TWC/Spectrum", AsnType::Residential, 86, "US");
        asn!(5650, "Frontier", AsnType::Residential, 85, "US");
        asn!(209, "CenturyLink/Lumen", AsnType::Residential, 85, "US");
        asn!(20001, "TWC/Spectrum", AsnType::Residential, 86, "US");
        asn!(6128, "Cablevision", AsnType::Residential, 87, "US");
        asn!(13676, "AT&T Internet", AsnType::Residential, 90, "US");
        asn!(36114, "Mediacom", AsnType::Residential, 84, "US");
        asn!(12271, "TWC/Spectrum", AsnType::Residential, 86, "US");
        asn!(11232, "Midco", AsnType::Residential, 85, "US");
        asn!(30036, "Mediacom", AsnType::Residential, 84, "US");
        asn!(33363, "BHN/Spectrum", AsnType::Residential, 86, "US");
        asn!(7843, "TWC/Spectrum", AsnType::Residential, 86, "US");
        asn!(20057, "AT&T Wireless", AsnType::Mobile, 95, "US");
        asn!(21928, "T-Mobile", AsnType::Mobile, 96, "US");
        asn!(6167, "Verizon Wireless", AsnType::Mobile, 94, "US");
        asn!(7065, "US Cellular", AsnType::Mobile, 92, "US");
        asn!(21581, "Cricket Wireless", AsnType::Mobile, 91, "US");
        asn!(46375, "Sprint/T-Mobile", AsnType::Mobile, 93, "US");
        asn!(10507, "Sprint", AsnType::Mobile, 93, "US");

        // ── EU Residential ISPs ──────────────────────────────────────────
        asn!(3320, "Deutsche Telekom", AsnType::Residential, 90, "DE");
        asn!(6830, "Liberty Global", AsnType::Residential, 88, "EU");
        asn!(3209, "Vodafone DE", AsnType::Residential, 89, "DE");
        asn!(12322, "Free/Proxad", AsnType::Residential, 88, "FR");
        asn!(3215, "Orange France", AsnType::Residential, 90, "FR");
        asn!(5410, "Bouygues Telecom", AsnType::Residential, 88, "FR");
        asn!(12876, "Online/Scaleway", AsnType::Isp, 78, "FR");
        asn!(5089, "Virgin Media", AsnType::Residential, 89, "GB");
        asn!(2856, "BT", AsnType::Residential, 91, "GB");
        asn!(5607, "Sky UK", AsnType::Residential, 88, "GB");
        asn!(6739, "Vodafone ES/ONO", AsnType::Residential, 87, "ES");
        asn!(12479, "Orange Spain", AsnType::Residential, 88, "ES");
        asn!(3269, "Telecom Italia", AsnType::Residential, 87, "IT");
        asn!(12874, "Fastweb", AsnType::Residential, 86, "IT");
        asn!(5602, "KPN", AsnType::Residential, 89, "NL");
        asn!(1136, "KPN/XS4ALL", AsnType::Residential, 89, "NL");
        asn!(6848, "Telenet", AsnType::Residential, 88, "BE");
        asn!(15557, "SFR", AsnType::Residential, 87, "FR");
        asn!(8220, "COLT", AsnType::Corporate, 68, "EU");
        asn!(6805, "Telefonica DE", AsnType::Residential, 87, "DE");
        asn!(680, "DFN", AsnType::Education, 76, "DE");

        // ── EU Mobile ────────────────────────────────────────────────────
        asn!(29975, "Vodafone IT Mobile", AsnType::Mobile, 92, "IT");
        asn!(12956, "Telefonica Intl", AsnType::Mobile, 90, "ES");
        asn!(31334, "Vodafone DE Mobile", AsnType::Mobile, 91, "DE");
        asn!(15169, "Google",                AsnType::Datacenter,  25, "US", blocked: ["cloudflare", "akamai", "datadome"]);

        // ── UK/CA/AU/JP Residential ──────────────────────────────────────
        asn!(577, "Bell Canada", AsnType::Residential, 89, "CA");
        asn!(812, "Rogers", AsnType::Residential, 88, "CA");
        asn!(6327, "Shaw/Rogers", AsnType::Residential, 87, "CA");
        asn!(852, "Telus", AsnType::Residential, 88, "CA");
        asn!(1221, "Telstra", AsnType::Residential, 89, "AU");
        asn!(4804, "Microplex/Telstra", AsnType::Residential, 86, "AU");
        asn!(7545, "TPG Telecom", AsnType::Residential, 85, "AU");
        asn!(4713, "OCN/NTT Japan", AsnType::Residential, 90, "JP");
        asn!(2516, "KDDI", AsnType::Residential, 90, "JP");
        asn!(17676, "SoftBank BB", AsnType::Residential, 88, "JP");
        asn!(9605, "NTT Docomo", AsnType::Mobile, 93, "JP");

        // ── Major Cloud / Datacenter ─────────────────────────────────────
        asn!(16509, "Amazon/AWS",            AsnType::Datacenter,  22, "US", blocked: ["cloudflare", "akamai", "datadome", "perimeterx"]);
        asn!(14618, "Amazon/AWS",            AsnType::Datacenter,  22, "US", blocked: ["cloudflare", "akamai", "datadome", "perimeterx"]);
        asn!(8075,  "Microsoft Azure",       AsnType::Datacenter,  25, "US", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(8068,  "Microsoft",             AsnType::Datacenter,  28, "US", blocked: ["cloudflare", "akamai"]);
        asn!(36351, "SoftLayer/IBM",         AsnType::Datacenter,  24, "US", blocked: ["cloudflare", "akamai"]);
        asn!(24940, "Hetzner",               AsnType::Datacenter,  20, "DE", blocked: ["cloudflare", "akamai", "datadome", "perimeterx", "incapsula"]);
        asn!(16276, "OVH",                   AsnType::Datacenter,  22, "FR", blocked: ["cloudflare", "akamai", "datadome", "perimeterx"]);
        asn!(14061, "DigitalOcean",          AsnType::Datacenter,  20, "US", blocked: ["cloudflare", "akamai", "datadome", "perimeterx", "incapsula"]);
        asn!(63949, "Linode/Akamai",         AsnType::Datacenter,  22, "US", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(20473, "Vultr/Choopa",          AsnType::Datacenter,  20, "US", blocked: ["cloudflare", "akamai", "datadome", "perimeterx", "incapsula"]);
        asn!(13238, "Yandex",                AsnType::Datacenter,  30, "RU", blocked: ["cloudflare"]);
        asn!(45090, "Tencent Cloud",         AsnType::Datacenter,  25, "CN", blocked: ["cloudflare", "akamai"]);
        asn!(37963, "Alibaba Cloud",         AsnType::Datacenter,  23, "CN", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(132203,"Tencent Cloud",         AsnType::Datacenter,  24, "CN", blocked: ["cloudflare"]);
        asn!(55967, "BaiShan/CDN", AsnType::Datacenter, 25, "CN");
        asn!(398101,"GCP",                   AsnType::Datacenter,  22, "US", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(19871, "Network Solutions", AsnType::Hosting, 35, "US");
        asn!(62567, "DigitalOcean",          AsnType::Datacenter,  20, "US", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(46606, "Unity/GCP", AsnType::Datacenter, 24, "US");
        asn!(396982,"Google Cloud",          AsnType::Datacenter,  23, "US", blocked: ["cloudflare", "akamai"]);
        asn!(19527, "Google", AsnType::Datacenter, 25, "US");

        // ── Hosting / VPS ────────────────────────────────────────────────
        asn!(46664, "VolumeDrive", AsnType::Hosting, 30, "US");
        asn!(30083, "HEG/Hetzner",           AsnType::Hosting,     32, "DE", blocked: ["cloudflare", "akamai"]);
        asn!(55286, "ServerMania", AsnType::Hosting, 33, "CA");
        asn!(36352, "ColoCrossing",          AsnType::Hosting,     28, "US", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(62468, "TotalServer", AsnType::Hosting, 30, "US");
        asn!(62785, "ISPER", AsnType::Hosting, 32, "US");
        asn!(53667, "FranTech/Ponynet",      AsnType::Hosting,     25, "US", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(25369, "Hydra Communications", AsnType::Hosting, 30, "US");
        asn!(32400, "Akamai/Prolexic", AsnType::Hosting, 35, "US");
        asn!(197540,"Netcup",                AsnType::Hosting,     32, "DE", blocked: ["cloudflare"]);
        asn!(51167, "Contabo",               AsnType::Hosting,     30, "DE", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(34549, "meerfarbig", AsnType::Hosting, 33, "DE");
        asn!(4785, "xTom", AsnType::Hosting, 28, "US");
        asn!(60729, "Zwiesel/strato", AsnType::Hosting, 34, "DE");
        asn!(28753, "IONOS/1&1", AsnType::Hosting, 35, "DE");
        asn!(8560, "IONOS/1&1", AsnType::Hosting, 36, "DE");

        // ── CDN ──────────────────────────────────────────────────────────
        asn!(13335, "Cloudflare",            AsnType::Cdn,         18, "US", blocked: ["akamai", "datadome"]);
        asn!(54113, "Fastly",                AsnType::Cdn,         20, "US", blocked: ["cloudflare", "datadome"]);
        asn!(20940, "Akamai",                AsnType::Cdn,         22, "US", blocked: ["cloudflare"]);
        asn!(16625, "Akamai", AsnType::Cdn, 22, "US");
        asn!(2906, "Netflix/OCDN", AsnType::Cdn, 30, "US");
        asn!(32934, "Meta/Facebook", AsnType::Cdn, 28, "US");
        asn!(13414, "Twitter/X", AsnType::Cdn, 28, "US");
        asn!(36183, "Akamai/Edgecast", AsnType::Cdn, 22, "US");
        asn!(30148, "Sucuri/GoDaddy", AsnType::Cdn, 25, "US");
        asn!(19551, "Incapsula/Imperva", AsnType::Cdn, 20, "US");

        // ── Education ────────────────────────────────────────────────────
        asn!(3701, "MIT", AsnType::Education, 78, "US");
        asn!(32, "Stanford", AsnType::Education, 78, "US");
        asn!(26, "UC Berkeley", AsnType::Education, 77, "US");
        asn!(3356, "Level3/Lumen", AsnType::Corporate, 65, "US");
        asn!(174, "Cogent", AsnType::Corporate, 60, "US");
        asn!(6939, "Hurricane Electric", AsnType::Corporate, 55, "US");
        asn!(2914, "NTT America", AsnType::Corporate, 62, "US");
        asn!(1299, "Arelion/Telia", AsnType::Corporate, 63, "EU");
        asn!(6453, "Tata Communications", AsnType::Corporate, 60, "IN");
        asn!(2497, "IIJ", AsnType::Corporate, 65, "JP");
        asn!(6461, "Zayo", AsnType::Corporate, 62, "US");
        asn!(3491, "PCCW", AsnType::Corporate, 60, "HK");
        asn!(6762, "Telecom Italia Sparkle", AsnType::Corporate, 62, "IT");

        // ── Corporate / Enterprise ───────────────────────────────────────
        asn!(714, "Apple", AsnType::Corporate, 70, "US");
        asn!(46489, "Twitch/Amazon", AsnType::Corporate, 65, "US");
        asn!(394699,"Cloudflare WARP",       AsnType::Corporate,   45, "US", blocked: ["akamai"]);
        asn!(7684, "Sakura Internet", AsnType::Hosting, 40, "JP");
        asn!(4766, "Korea Telecom", AsnType::Residential, 88, "KR");
        asn!(9318, "SKB/SK Telecom", AsnType::Residential, 87, "KR");
        asn!(4837, "China Unicom", AsnType::Residential, 82, "CN");
        asn!(4134, "China Telecom", AsnType::Residential, 82, "CN");
        asn!(9808, "China Mobile", AsnType::Mobile, 84, "CN");

        // ── Tor Exit Nodes (well-known relay ASNs) ───────────────────────
        asn!(205100, "F3 Netze/Tor",         AsnType::Tor,         15, "DE", blocked: ["cloudflare", "akamai", "datadome", "perimeterx", "incapsula"]);
        asn!(200462, "NiceVPS/Tor",          AsnType::Tor,         12, "NL", blocked: ["cloudflare", "akamai", "datadome", "perimeterx", "incapsula"]);
        asn!(44103, "Sia Nano IT/Tor",       AsnType::Tor,         14, "LV", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(51396, "Pfcloud/Tor",           AsnType::Tor,         10, "DE", blocked: ["cloudflare", "akamai", "datadome", "perimeterx", "incapsula"]);

        // ── ISP-Grade ────────────────────────────────────────────────────
        asn!(46562, "Performive", AsnType::Isp, 82, "US");
        asn!(19318, "Interserver", AsnType::Isp, 78, "US");
        asn!(30633, "Leaseweb", AsnType::Isp, 75, "NL");
        asn!(60068, "CDN77", AsnType::Isp, 72, "GB");

        // ── More US Residential for coverage ─────────────────────────────
        asn!(11404, "Wave Broadband", AsnType::Residential, 85, "US");
        asn!(6983, "ITC DeltaCom", AsnType::Residential, 84, "US");
        asn!(22394, "Viasat", AsnType::Residential, 80, "US");
        asn!(22561, "CenturyTel", AsnType::Residential, 84, "US");
        asn!(7029, "Windstream", AsnType::Residential, 84, "US");
        asn!(18566, "MegaPath", AsnType::Residential, 82, "US");
        asn!(33588, "Bresnan/Charter", AsnType::Residential, 86, "US");
        asn!(13385, "Xfinity/Comcast", AsnType::Residential, 89, "US");

        // ── Additional US Residential ────────────────────────────────
        asn!(6079, "RCN", AsnType::Residential, 85, "US");
        asn!(19108, "Suddenlink/Altice", AsnType::Residential, 84, "US");
        asn!(11492, "CABLE ONE", AsnType::Residential, 83, "US");
        asn!(11776, "Atlantic Broadband", AsnType::Residential, 84, "US");
        asn!(23089, "Buckeye Cablevision", AsnType::Residential, 82, "US");
        asn!(12083, "WOW/WideOpenWest", AsnType::Residential, 84, "US");
        asn!(10835, "Verizon Business", AsnType::Residential, 88, "US");
        asn!(13977, "Fuse Internet", AsnType::Residential, 82, "US");
        asn!(11686, "EduNet/Consolidated", AsnType::Residential, 83, "US");
        asn!(32133, "NCC/TDS Telecom", AsnType::Residential, 83, "US");
        asn!(40285, "Google Fiber", AsnType::Residential, 91, "US");
        asn!(11025, "Verizon Online", AsnType::Residential, 89, "US");

        // ── Additional EU/UK Residential ─────────────────────────────
        asn!(8412, "TIM/Telecom Italia", AsnType::Residential, 87, "IT");
        asn!(3352, "Telefonica Espana", AsnType::Residential, 89, "ES");
        asn!(12430, "Vodafone Spain", AsnType::Residential, 87, "ES");
        asn!(12334, "R Cable/Euskaltel", AsnType::Residential, 84, "ES");
        asn!(15480, "A1 Telekom Austria", AsnType::Residential, 87, "AT");
        asn!(8447, "A1/Telekom Austria", AsnType::Residential, 87, "AT");
        asn!(6730, "Sunrise/UPC CH", AsnType::Residential, 88, "CH");
        asn!(3303, "Swisscom", AsnType::Residential, 90, "CH");
        asn!(15600, "Cyta", AsnType::Residential, 84, "CY");
        asn!(47541, "VNET/T-Mobile CZ", AsnType::Residential, 85, "CZ");
        asn!(5588, "GTS Poland", AsnType::Residential, 85, "PL");
        asn!(5617, "Orange Poland", AsnType::Residential, 87, "PL");
        asn!(12741, "Netia", AsnType::Residential, 84, "PL");
        asn!(16086, "DNA Finland", AsnType::Residential, 87, "FI");
        asn!(1759, "Telia Finland", AsnType::Residential, 88, "FI");
        asn!(29518, "Bredband2/Telia SE", AsnType::Residential, 87, "SE");
        asn!(3301, "Telia Sweden", AsnType::Residential, 89, "SE");
        asn!(2119, "Telenor Norway", AsnType::Residential, 89, "NO");
        asn!(29695, "Altibox Norway", AsnType::Residential, 86, "NO");

        // ── Additional Asia-Pacific ──────────────────────────────────
        asn!(7552, "Viettel", AsnType::Residential, 83, "VN");
        asn!(45899, "VNPT", AsnType::Residential, 82, "VN");
        asn!(4760, "HKT/PCCW", AsnType::Residential, 87, "HK");
        asn!(9269, "HK Broadband", AsnType::Residential, 86, "HK");
        asn!(4657, "Starhub", AsnType::Residential, 87, "SG");
        asn!(9506, "Singtel", AsnType::Residential, 88, "SG");
        asn!(24203, "Globe Telecom", AsnType::Residential, 82, "PH");
        asn!(4818, "DiGi Telecom", AsnType::Mobile, 86, "MY");
        asn!(17858, "LG Uplus", AsnType::Residential, 86, "KR");
        asn!(3786, "LG Dacom/LGU+", AsnType::Residential, 85, "KR");
        asn!(17421, "Mobiltel/A1 BG", AsnType::Mobile, 84, "BG");
        asn!(38266, "Airtel India", AsnType::Mobile, 84, "IN");
        asn!(55836, "Reliance Jio", AsnType::Mobile, 85, "IN");
        asn!(45609, "BSNL India", AsnType::Residential, 82, "IN");

        // ── Latin America Residential ────────────────────────────────
        asn!(7303, "Telecom Argentina", AsnType::Residential, 84, "AR");
        asn!(11664, "Techtel/LMDS", AsnType::Residential, 82, "AR");
        asn!(
            8167,
            "Rede/NET/Claro Brasil",
            AsnType::Residential,
            85,
            "BR"
        );
        asn!(28573, "Claro/NET Brasil", AsnType::Residential, 85, "BR");
        asn!(18881, "VIVO/Telefonica BR", AsnType::Residential, 86, "BR");
        asn!(7738, "Telemar/Oi", AsnType::Residential, 83, "BR");
        asn!(8151, "Telmex Mexico", AsnType::Residential, 84, "MX");
        asn!(13999, "Mega Cable MX", AsnType::Residential, 83, "MX");

        // ── Additional Hosting / VPS ─────────────────────────────────
        asn!(47583, "Hostinger",             AsnType::Hosting,     28, "LT", blocked: ["cloudflare", "akamai", "datadome"]);
        asn!(394695,"Oracle Cloud",          AsnType::Datacenter,  24, "US", blocked: ["cloudflare", "akamai"]);
        asn!(212238,"Scaleway/Dedibox",      AsnType::Hosting,     30, "FR", blocked: ["cloudflare"]);

        // ── Additional Education ─────────────────────────────────────
        asn!(786, "JANET UK", AsnType::Education, 76, "GB");
        asn!(2200, "Renater France", AsnType::Education, 76, "FR");
        asn!(11537, "Internet2/Abilene", AsnType::Education, 78, "US");

        Self { entries }
    }

    /// Look up an ASN.
    pub fn lookup(&self, asn: u32) -> Option<&AsnInfo> {
        self.entries.get(&asn)
    }

    /// Return all ASNs of a given type.
    pub fn by_type(&self, asn_type: AsnType) -> Vec<&AsnInfo> {
        self.entries
            .values()
            .filter(|info| info.asn_type == asn_type)
            .collect()
    }

    /// Return all ASNs for a country.
    pub fn by_country(&self, country: &str) -> Vec<&AsnInfo> {
        self.entries
            .values()
            .filter(|info| info.country == country)
            .collect()
    }

    /// Check if a given ASN is known to be blocked by a specific protection.
    pub fn is_blocked_by(&self, asn: u32, protection: &str) -> bool {
        self.entries
            .get(&asn)
            .map(|info| info.known_blocked_by.iter().any(|b| b == protection))
            .unwrap_or(false)
    }

    /// Get trust score for an ASN. Returns 50 (neutral) for unknown ASNs.
    pub fn trust_score(&self, asn: u32) -> u8 {
        self.entries
            .get(&asn)
            .map(|info| info.trust_score)
            .unwrap_or(50)
    }

    /// Total entries in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ASN Diversity Enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// Policy for enforcing ASN diversity across proxy usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnDiversityPolicy {
    /// Minimum interval before reusing the same ASN for a given domain.
    pub min_interval_same_asn: Duration,
    /// Maximum consecutive requests from the same ASN to a single domain.
    pub max_consecutive_same_asn: u32,
    /// Prefer residential/mobile ASNs when available.
    pub prefer_residential: bool,
    /// Actively avoid datacenter ASNs.
    pub avoid_datacenter: bool,
    /// Target diversity score (0.0-1.0): higher = more diverse ASN spread.
    pub target_diversity_score: f64,
}

impl Default for AsnDiversityPolicy {
    fn default() -> Self {
        Self {
            min_interval_same_asn: Duration::from_secs(60),
            max_consecutive_same_asn: 2,
            prefer_residential: true,
            avoid_datacenter: false,
            target_diversity_score: 0.7,
        }
    }
}

/// Tracks recent ASN usage to enforce diversity.
#[derive(Debug, Clone)]
pub struct AsnUsageTracker {
    /// Per-domain: ring buffer of (ASN, timestamp) for recent requests.
    domain_history: HashMap<String, VecDeque<(u32, Instant)>>,
    /// Per-domain: count of consecutive requests from the same ASN.
    consecutive_count: HashMap<String, (u32, u32)>, // (asn, count)
    /// Maximum history entries per domain.
    max_history: usize,
    /// The active policy.
    pub policy: AsnDiversityPolicy,
}

impl AsnUsageTracker {
    pub fn new(policy: AsnDiversityPolicy) -> Self {
        Self {
            domain_history: HashMap::new(),
            consecutive_count: HashMap::new(),
            max_history: 200,
            policy,
        }
    }

    /// Record that a request to `domain` used `asn`.
    pub fn record(&mut self, domain: &str, asn: u32) {
        let history = self
            .domain_history
            .entry(domain.to_string())
            .or_insert_with(|| VecDeque::with_capacity(self.max_history));
        if history.len() >= self.max_history {
            history.pop_front();
        }
        history.push_back((asn, Instant::now()));

        let entry = self
            .consecutive_count
            .entry(domain.to_string())
            .or_insert((asn, 0));
        if entry.0 == asn {
            entry.1 += 1;
        } else {
            *entry = (asn, 1);
        }
    }

    /// Check whether using `asn` for `domain` right now is acceptable.
    pub fn is_allowed(&self, domain: &str, asn: u32) -> bool {
        // Check consecutive limit
        if let Some(&(last_asn, count)) = self.consecutive_count.get(domain) {
            if last_asn == asn && count >= self.policy.max_consecutive_same_asn {
                return false;
            }
        }

        // Check min interval
        if let Some(history) = self.domain_history.get(domain) {
            for &(hist_asn, timestamp) in history.iter().rev() {
                if timestamp.elapsed() > self.policy.min_interval_same_asn {
                    break; // older entries are fine
                }
                if hist_asn == asn {
                    return false;
                }
            }
        }

        true
    }

    /// Compute diversity score for a domain's recent requests.
    /// Returns 0.0 (all same ASN) to 1.0 (all unique ASNs).
    pub fn diversity_score(&self, domain: &str) -> f64 {
        let history = match self.domain_history.get(domain) {
            Some(h) if !h.is_empty() => h,
            _ => return 1.0, // no history = perfect diversity
        };

        let total = history.len() as f64;
        let unique: HashSet<u32> = history.iter().map(|(asn, _)| *asn).collect();
        let unique_count = unique.len() as f64;

        // Shannon entropy normalized to [0, 1]
        if unique_count <= 1.0 {
            return 0.0;
        }

        // Simple ratio: unique ASNs / total requests, capped at 1.0
        (unique_count / total).min(1.0)
    }

    /// Prune entries older than the min interval from all domains.
    pub fn cleanup(&mut self) {
        let cutoff = self.policy.min_interval_same_asn * 3; // keep 3x the window
        for history in self.domain_history.values_mut() {
            while let Some(&(_, ts)) = history.front() {
                if ts.elapsed() > cutoff {
                    history.pop_front();
                } else {
                    break;
                }
            }
        }
        // Remove empty entries
        self.domain_history.retain(|_, h| !h.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enhanced Proxy Scoring
// ─────────────────────────────────────────────────────────────────────────────

/// Enhanced multi-factor proxy quality score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyScore {
    /// Raw success rate [0.0, 1.0]. Weight: 0.30
    pub success_rate: f64,
    /// Latency quality [0.0, 1.0] (lower latency = higher score). Weight: 0.15
    pub latency_score: f64,
    /// ASN trust score normalized to [0.0, 1.0]. Weight: 0.25
    pub asn_trust: f64,
    /// Geographic match quality [0.0, 1.0]. Weight: 0.10
    pub geo_match: f64,
    /// Freshness of health data [0.0, 1.0]. Weight: 0.05
    pub freshness: f64,
    /// Consecutive success streak bonus [0.0, 1.0]. Weight: 0.10
    pub consecutive_success: f64,
    /// Past success on this specific domain [0.0, 1.0]. Weight: 0.05
    pub domain_history: f64,
    /// Weighted total score [0.0, 1.0].
    pub total: f64,
}

impl ProxyScore {
    /// Weights for each factor.
    const W_SUCCESS_RATE: f64 = 0.30;
    const W_LATENCY: f64 = 0.15;
    const W_ASN_TRUST: f64 = 0.25;
    const W_GEO_MATCH: f64 = 0.10;
    const W_FRESHNESS: f64 = 0.05;
    const W_CONSECUTIVE: f64 = 0.10;
    const W_DOMAIN_HIST: f64 = 0.05;

    /// Compute a composite score from individual factors.
    pub fn compute(
        health: &ProxyHealth,
        asn_trust_score: u8,
        geo_matches: bool,
        domain: Option<&str>,
        domain_success_count: u64,
    ) -> Self {
        let success_rate = health.success_rate();

        // Latency: 0-200ms = 1.0, 200-2000ms = linear decay, 2000+ = 0.0
        let latency_score = if health.avg_latency_ms <= 200.0 {
            1.0
        } else if health.avg_latency_ms >= 2000.0 {
            0.0
        } else {
            1.0 - (health.avg_latency_ms - 200.0) / 1800.0
        };

        let asn_trust = asn_trust_score as f64 / 100.0;
        let geo_match = if geo_matches { 1.0 } else { 0.3 };

        let freshness = if health.last_check.elapsed() < Duration::from_secs(60) {
            1.0
        } else if health.last_check.elapsed() < Duration::from_secs(300) {
            0.7
        } else {
            0.3
        };

        // Consecutive success: reward streaks up to 20
        let consecutive_success = if health.consecutive_fail == 0 {
            let streak = health.success_count.min(20) as f64;
            streak / 20.0
        } else {
            0.0
        };

        // Domain history: has this proxy previously worked on this domain?
        let domain_history = if domain_success_count == 0 {
            0.5 // neutral — no data
        } else {
            (domain_success_count.min(10) as f64 / 10.0).min(1.0)
        };

        let total = success_rate * Self::W_SUCCESS_RATE
            + latency_score * Self::W_LATENCY
            + asn_trust * Self::W_ASN_TRUST
            + geo_match * Self::W_GEO_MATCH
            + freshness * Self::W_FRESHNESS
            + consecutive_success * Self::W_CONSECUTIVE
            + domain_history * Self::W_DOMAIN_HIST;

        Self {
            success_rate,
            latency_score,
            asn_trust,
            geo_match,
            freshness,
            consecutive_success,
            domain_history,
            total,
        }
    }

    /// Apply a multiplicative penalty to `total` based on an external
    /// reputation record. Fail-open: `None` (no data) leaves the score
    /// unchanged; a record flagging a proxy or high fraud score is dampened so
    /// the proxy is deprioritised (not hard-removed) during selection.
    pub fn with_reputation_penalty(mut self, rep: Option<&ReputationRecord>) -> Self {
        if let Some(rep) = rep {
            let factor = if rep.is_proxy {
                0.30
            } else if rep.fraud_score >= 60 {
                0.40
            } else if rep.fraud_score >= 30 {
                0.75
            } else {
                1.0
            };
            self.total *= factor;
        }
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Proxy Strategy
// ─────────────────────────────────────────────────────────────────────────────

/// Per-domain proxy selection strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainProxyStrategy {
    /// Domain this strategy applies to (e.g. "shop-a.example").
    pub domain: String,
    /// Required ASN type — only proxies from this type will be used.
    pub required_asn_type: Option<AsnType>,
    /// Minimum trust score required.
    pub min_trust_score: u8,
    /// Preferred country code for geographic match.
    pub preferred_country: Option<String>,
    /// Whether to use sticky sessions for this domain.
    pub sticky_session: bool,
    /// ASN numbers known to be blocked by this domain.
    pub known_blocks: Vec<u32>,
    /// Last proxy URL that successfully completed a request.
    pub last_successful_proxy: Option<String>,
    /// Recent successful (proxy_url, unix_timestamp_secs) pairs.
    pub success_history: Vec<(String, i64)>,
}

impl DomainProxyStrategy {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            required_asn_type: None,
            min_trust_score: 0,
            preferred_country: None,
            sticky_session: false,
            known_blocks: Vec::new(),
            last_successful_proxy: None,
            success_history: Vec::new(),
        }
    }

    /// Record a successful proxy use.
    pub fn record_success(&mut self, proxy_url: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.last_successful_proxy = Some(proxy_url.to_string());
        self.success_history.push((proxy_url.to_string(), now));
        // Cap history
        if self.success_history.len() > 100 {
            self.success_history.drain(0..50);
        }
    }

    /// Record a blocked ASN.
    pub fn record_block(&mut self, asn: u32) {
        if !self.known_blocks.contains(&asn) {
            self.known_blocks.push(asn);
        }
    }

    /// Check if an ASN is known to be blocked.
    pub fn is_asn_blocked(&self, asn: u32) -> bool {
        self.known_blocks.contains(&asn)
    }

    /// Count how many times a proxy URL has succeeded on this domain.
    pub fn proxy_success_count(&self, proxy_url: &str) -> u64 {
        self.success_history
            .iter()
            .filter(|(url, _)| url == proxy_url)
            .count() as u64
    }
}

/// Built-in domain strategy database for common protected sites.
#[derive(Debug, Clone)]
pub struct DomainStrategyDatabase {
    strategies: HashMap<String, DomainProxyStrategy>,
}

impl Default for DomainStrategyDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainStrategyDatabase {
    /// Build the default strategy database for well-known domains.
    pub fn new() -> Self {
        let mut strategies = HashMap::new();

        // Walmart: Akamai Bot Manager — residential only, sticky session
        strategies.insert(
            "shop-a.example".into(),
            DomainProxyStrategy {
                domain: "shop-a.example".into(),
                required_asn_type: Some(AsnType::Residential),
                min_trust_score: 80,
                preferred_country: Some("US".into()),
                sticky_session: true,
                known_blocks: vec![
                    16509, 14618, // AWS
                    15169, // Google
                    24940, // Hetzner
                    14061, // DigitalOcean
                    20473, // Vultr
                ],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // Kroger: Akamai — ISP or Residential
        strategies.insert(
            "kroger.com".into(),
            DomainProxyStrategy {
                domain: "kroger.com".into(),
                required_asn_type: None, // ISP or Residential both work
                min_trust_score: 70,
                preferred_country: Some("US".into()),
                sticky_session: true,
                known_blocks: vec![
                    24940, 14061, 20473, // Hetzner, DO, Vultr
                    16509, 14618, // AWS
                ],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // Target: permissive Redsky API
        strategies.insert(
            "shop-b.example".into(),
            DomainProxyStrategy {
                domain: "shop-b.example".into(),
                required_asn_type: None,
                min_trust_score: 30,
                preferred_country: Some("US".into()),
                sticky_session: false,
                known_blocks: Vec::new(),
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // Amazon: strict — residential/mobile only
        strategies.insert(
            "amazon.com".into(),
            DomainProxyStrategy {
                domain: "amazon.com".into(),
                required_asn_type: Some(AsnType::Residential),
                min_trust_score: 85,
                preferred_country: Some("US".into()),
                sticky_session: true,
                known_blocks: vec![
                    24940, 16276, 14061, 20473, 63949, // hosting providers
                    13335, // Cloudflare
                ],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // HEB: Incapsula WAF
        strategies.insert(
            "shop-d.example".into(),
            DomainProxyStrategy {
                domain: "shop-d.example".into(),
                required_asn_type: Some(AsnType::Residential),
                min_trust_score: 80,
                preferred_country: Some("US".into()),
                sticky_session: true,
                known_blocks: vec![24940, 14061, 20473, 16276, 63949],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // Costco: Akamai
        strategies.insert(
            "costco.com".into(),
            DomainProxyStrategy {
                domain: "costco.com".into(),
                required_asn_type: Some(AsnType::Residential),
                min_trust_score: 80,
                preferred_country: Some("US".into()),
                sticky_session: true,
                known_blocks: vec![24940, 14061, 20473, 16276],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // Generic Cloudflare-protected site pattern
        strategies.insert(
            "_cloudflare_default".into(),
            DomainProxyStrategy {
                domain: "_cloudflare_default".into(),
                required_asn_type: Some(AsnType::Residential),
                min_trust_score: 80,
                preferred_country: None,
                sticky_session: false,
                known_blocks: vec![24940, 14061, 20473, 16276, 63949, 36352, 53667, 51167],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        // Generic Akamai-protected site pattern
        strategies.insert(
            "_akamai_default".into(),
            DomainProxyStrategy {
                domain: "_akamai_default".into(),
                required_asn_type: None,
                min_trust_score: 70,
                preferred_country: None,
                sticky_session: true,
                known_blocks: vec![24940, 14061, 20473, 16276, 63949],
                last_successful_proxy: None,
                success_history: Vec::new(),
            },
        );

        Self { strategies }
    }

    /// Look up a strategy by domain. Falls back to protection-based defaults.
    pub fn get(&self, domain: &str) -> Option<&DomainProxyStrategy> {
        // Exact match first
        if let Some(s) = self.strategies.get(domain) {
            return Some(s);
        }
        // Try stripping www.
        let stripped = domain.strip_prefix("www.").unwrap_or(domain);
        self.strategies.get(stripped)
    }

    /// Get a mutable reference to a strategy, creating a default if missing.
    pub fn get_or_create(&mut self, domain: &str) -> &mut DomainProxyStrategy {
        let key = domain.strip_prefix("www.").unwrap_or(domain).to_string();
        self.strategies
            .entry(key.clone())
            .or_insert_with(|| DomainProxyStrategy::new(&key))
    }

    /// Get the Cloudflare default strategy template.
    pub fn cloudflare_default(&self) -> Option<&DomainProxyStrategy> {
        self.strategies.get("_cloudflare_default")
    }

    /// Get the Akamai default strategy template.
    pub fn akamai_default(&self) -> Option<&DomainProxyStrategy> {
        self.strategies.get("_akamai_default")
    }

    /// Number of registered domain strategies.
    pub fn len(&self) -> usize {
        self.strategies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy Pool Health Dashboard
// ─────────────────────────────────────────────────────────────────────────────

/// Per-tier health summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierHealth {
    pub total: usize,
    pub alive: usize,
    pub dead: usize,
    pub avg_latency_ms: f64,
    pub avg_success_rate: f64,
}

/// Comprehensive health snapshot of the proxy pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPoolHealth {
    /// Total proxies in pool.
    pub total_proxies: usize,
    /// Proxies with alive = true.
    pub alive: usize,
    /// Proxies with alive = false.
    pub dead: usize,
    /// Health breakdown per proxy tier.
    pub by_tier: HashMap<String, TierHealth>,
    /// Count of proxies per ASN type.
    pub by_asn_type: HashMap<String, usize>,
    /// Average latency across all alive proxies (ms).
    pub avg_latency_ms: f64,
    /// Average success rate across all alive proxies.
    pub avg_success_rate: f64,
    /// ASN distribution diversity: 0.0 = monoculture, 1.0 = all unique.
    pub diversity_score: f64,
    /// Country codes represented in the alive pool.
    pub geographic_coverage: Vec<String>,
}

impl std::fmt::Display for ProxyPoolHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Proxy Pool Health")?;
        writeln!(
            f,
            "  Total: {} | Alive: {} | Dead: {}",
            self.total_proxies, self.alive, self.dead
        )?;
        writeln!(
            f,
            "  Avg latency: {:.1}ms | Avg success: {:.1}%",
            self.avg_latency_ms,
            self.avg_success_rate * 100.0
        )?;
        writeln!(
            f,
            "  Diversity: {:.2} | Geo: {}",
            self.diversity_score,
            self.geographic_coverage.join(", ")
        )?;
        for (tier, th) in &self.by_tier {
            writeln!(
                f,
                "  [{tier}] {}/{} alive, {:.1}ms avg, {:.0}% success",
                th.alive,
                th.total,
                th.avg_latency_ms,
                th.avg_success_rate * 100.0
            )?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy Intelligence Engine (ties it all together)
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata attached to a proxy for intelligent selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAsnMeta {
    /// The AS number this proxy belongs to.
    pub asn: u32,
    /// Country code from the ASN database.
    pub country: String,
    /// ASN type classification.
    pub asn_type: AsnType,
    /// Trust score from the ASN database.
    pub trust_score: u8,
}

/// The intelligence engine: sits on top of `ProxyPool` to make smarter decisions.
#[derive(Debug, Clone)]
pub struct ProxyIntelligence {
    /// ASN classification database.
    pub asn_db: AsnDatabase,
    /// Per-proxy ASN metadata (indexed parallel to ProxyPool.proxies).
    pub proxy_asn: Vec<Option<ProxyAsnMeta>>,
    /// ASN diversity tracker.
    pub diversity: AsnUsageTracker,
    /// Domain-specific strategies.
    pub domain_strategies: DomainStrategyDatabase,
    /// Per-domain risk-escalation level (0 = none, 1 = residential+, 2 = mobile+).
    /// Raised on a block signal so the domain escalates DC -> residential -> mobile.
    pub escalation_levels: HashMap<String, u8>,
    /// External IP-reputation client (IPQS/ipinfo + TTL cache). Fail-open.
    pub reputation: EgressReputationClient,
    /// External reputation records, indexed parallel to `proxy_asn` / the pool.
    pub external_reputation: Vec<Option<ReputationRecord>>,
}

impl ProxyIntelligence {
    /// Create a new intelligence engine with default databases.
    pub fn new() -> Self {
        Self {
            asn_db: AsnDatabase::new(),
            proxy_asn: Vec::new(),
            diversity: AsnUsageTracker::new(AsnDiversityPolicy::default()),
            domain_strategies: DomainStrategyDatabase::new(),
            escalation_levels: HashMap::new(),
            reputation: EgressReputationClient::new(),
            external_reputation: Vec::new(),
        }
    }

    /// Create with a custom diversity policy.
    pub fn with_policy(policy: AsnDiversityPolicy) -> Self {
        Self {
            asn_db: AsnDatabase::new(),
            proxy_asn: Vec::new(),
            diversity: AsnUsageTracker::new(policy),
            domain_strategies: DomainStrategyDatabase::new(),
            escalation_levels: HashMap::new(),
            reputation: EgressReputationClient::new(),
            external_reputation: Vec::new(),
        }
    }

    /// Register ASN metadata for a proxy at a given index.
    /// Call this when adding proxies to the pool.
    pub fn register_proxy_asn(&mut self, index: usize, asn: u32) {
        // Grow the vec if needed
        while self.proxy_asn.len() <= index {
            self.proxy_asn.push(None);
        }

        let meta = self
            .asn_db
            .lookup(asn)
            .map(|info| ProxyAsnMeta {
                asn: info.asn,
                country: info.country.clone(),
                asn_type: info.asn_type,
                trust_score: info.trust_score,
            })
            .unwrap_or(ProxyAsnMeta {
                asn,
                country: "XX".into(),
                asn_type: AsnType::Datacenter, // unknown = assume datacenter
                trust_score: 50,
            });

        self.proxy_asn[index] = Some(meta);
    }

    /// Register ASN metadata inferred from the proxy's tier (when actual ASN
    /// is unknown). Uses a synthetic ASN based on index.
    pub fn register_proxy_from_tier(
        &mut self,
        index: usize,
        tier: ProxyTier,
        country: Option<&str>,
    ) {
        while self.proxy_asn.len() <= index {
            self.proxy_asn.push(None);
        }

        let asn_type = AsnType::from_proxy_tier(tier);
        let trust_score = match asn_type {
            AsnType::Mobile => 93,
            AsnType::Residential => 88,
            AsnType::Isp => 82,
            AsnType::Datacenter => 25,
            AsnType::Hosting => 35,
            AsnType::Education => 75,
            AsnType::Corporate => 65,
            AsnType::Tor => 15,
            AsnType::Cdn => 20,
        };

        self.proxy_asn[index] = Some(ProxyAsnMeta {
            asn: 1_000_000 + index as u32, // synthetic ASN
            country: country.unwrap_or("XX").into(),
            asn_type,
            trust_score,
        });
    }

    /// Screen the proxy at `index` against the external reputation feed and
    /// record the result. Fail-open: on a lookup error a neutral record is
    /// stored and no trust change happens, so the pool is never broken.
    ///
    /// Used by the health-check path (probe-before-crawl). When the feed flags
    /// the IP as a proxy/hosting endpoint or reports a high fraud score, the
    /// proxy's internal ASN trust is downgraded so `select_best`/`score_proxy`
    /// deprioritise it.
    pub fn refresh_reputation(&mut self, index: usize, ip: &str, asn: u32) -> ReputationRecord {
        let record = self.reputation.ip_reputation(ip, asn);
        while self.external_reputation.len() <= index {
            self.external_reputation.push(None);
        }
        self.external_reputation[index] = Some(record.clone());

        if record.is_bad() {
            if let Some(meta) = self.proxy_asn.get_mut(index).and_then(|m| m.as_mut()) {
                let floor = if record.is_proxy { 10 } else { 30 };
                if meta.trust_score > floor {
                    meta.trust_score = floor;
                }
            }
        }
        record
    }

    /// Compute an enhanced score for a proxy given its index and target domain.
    pub fn score_proxy(
        &self,
        index: usize,
        health: &ProxyHealth,
        domain: &str,
        preferred_country: Option<&str>,
    ) -> ProxyScore {
        let meta = self.proxy_asn.get(index).and_then(|m| m.as_ref());
        let trust = meta.map(|m| m.trust_score).unwrap_or(50);
        let geo_matches = match (meta, preferred_country) {
            (Some(m), Some(pref)) => m.country == pref,
            _ => false,
        };

        let domain_success = self
            .domain_strategies
            .get(domain)
            .map(|s| {
                // Count successes for any proxy at this index
                // Since we don't have the URL here, use success_history length as heuristic
                s.success_history.len() as u64
            })
            .unwrap_or(0);

        ProxyScore::compute(health, trust, geo_matches, Some(domain), domain_success)
            .with_reputation_penalty(self.external_reputation.get(index).and_then(|r| r.as_ref()))
    }

    /// Select the best proxy index from a pool for a given domain.
    /// Returns `None` if no suitable proxy is available.
    pub fn select_best(&self, pool: &ProxyPool, domain: &str) -> Option<usize> {
        let strategy = self.domain_strategies.get(domain);
        let preferred_country = strategy
            .and_then(|s| s.preferred_country.as_deref())
            .or(Some("US")); // default US
        let min_trust = strategy.map(|s| s.min_trust_score).unwrap_or(0);
        let required_type = strategy.and_then(|s| s.required_asn_type);
        // Risk-adaptive escalation floor for this domain (0 = none, 1 = residential+,
        // 2 = mobile+), raised via `escalate_domain` on a block signal.
        let escalation_level = self.escalation_levels.get(domain).copied().unwrap_or(0);

        let mut best_index: Option<usize> = None;
        let mut best_score: f64 = f64::NEG_INFINITY;

        for (i, proxy) in pool.proxies.iter().enumerate() {
            // Skip dead / banned proxies
            if !pool.health[i].alive {
                continue;
            }
            if pool.health[i].banned_domains.contains(domain) {
                continue;
            }

            // Skip proxies with a bad external reputation (known proxy / high
            // fraud score). Fail-open: no cached record => no skip.
            if let Some(Some(rep)) = self.external_reputation.get(i) {
                if rep.is_bad() {
                    continue;
                }
            }

            let meta = self.proxy_asn.get(i).and_then(|m| m.as_ref());
            let proxy_type = meta.map(|m| m.asn_type).unwrap_or(AsnType::Datacenter);

            // Enforce required ASN type
            if let Some(req_type) = required_type {
                // Allow residential when mobile is required and vice versa
                let type_ok = match req_type {
                    AsnType::Residential => matches!(
                        proxy_type,
                        AsnType::Residential | AsnType::Mobile | AsnType::Isp
                    ),
                    AsnType::Mobile => matches!(proxy_type, AsnType::Mobile | AsnType::Residential),
                    _ => proxy_type == req_type,
                };
                if !type_ok {
                    continue;
                }
            }

            // Risk-adaptive escalation floor: a domain that has been blocked is
            // restricted to higher-trust tiers for subsequent requests.
            let escalation_ok = match escalation_level {
                0 => true,
                1 => matches!(
                    proxy_type,
                    AsnType::Residential | AsnType::Mobile | AsnType::Isp
                ),
                2 => matches!(proxy_type, AsnType::Residential | AsnType::Mobile),
                _ => true,
            };
            if !escalation_ok {
                continue;
            }

            // Enforce min trust score
            let trust = meta.map(|m| m.trust_score).unwrap_or(50);
            if trust < min_trust {
                continue;
            }

            // Check ASN not blocked for this domain
            if let Some(meta) = meta {
                if let Some(strat) = strategy {
                    if strat.is_asn_blocked(meta.asn) {
                        continue;
                    }
                }
            }

            // Check diversity policy
            if let Some(meta) = meta {
                if !self.diversity.is_allowed(domain, meta.asn) {
                    continue;
                }
            }

            // Avoid datacenter if policy says so
            if self.diversity.policy.avoid_datacenter {
                let proxy_type = meta.map(|m| m.asn_type).unwrap_or(AsnType::Datacenter);
                if proxy_type == AsnType::Datacenter {
                    continue;
                }
            }

            // Score
            let score = self.score_proxy(i, &pool.health[i], domain, preferred_country);

            // Apply residential preference bonus
            let mut adjusted = score.total;
            if self.diversity.policy.prefer_residential {
                let proxy_type = meta.map(|m| m.asn_type).unwrap_or(AsnType::Datacenter);
                match proxy_type {
                    AsnType::Mobile => adjusted += 0.08,
                    AsnType::Residential => adjusted += 0.05,
                    AsnType::Isp => adjusted += 0.02,
                    _ => {}
                }
            }

            if adjusted > best_score {
                best_score = adjusted;
                best_index = Some(i);
            }
        }

        best_index
    }

    /// Record that a request through proxy at `index` to `domain` succeeded.
    pub fn record_success(&mut self, index: usize, domain: &str, proxy_url: &str) {
        if let Some(meta) = self.proxy_asn.get(index).and_then(|m| m.as_ref()) {
            self.diversity.record(domain, meta.asn);
        }
        let strategy = self.domain_strategies.get_or_create(domain);
        strategy.record_success(proxy_url);
    }

    /// Record that a request through proxy at `index` to `domain` was blocked.
    pub fn record_block(&mut self, index: usize, domain: &str) {
        if let Some(meta) = self.proxy_asn.get(index).and_then(|m| m.as_ref()) {
            self.diversity.record(domain, meta.asn);
            let strategy = self.domain_strategies.get_or_create(domain);
            strategy.record_block(meta.asn);
        }
    }

    /// Risk-adaptive escalation: promote `domain` one step up the tier ladder
    /// (DC -> residential -> mobile). Used on a block signal so subsequent
    /// requests for the domain only use higher-trust tiers. `select_best`
    /// enforces the resulting floor via the `escalation_levels` map.
    pub fn escalate_domain(&mut self, domain: &str) {
        let level = self
            .escalation_levels
            .entry(domain.to_string())
            .or_insert(0);
        if *level < 2 {
            *level += 1;
        }
    }

    /// Generate a comprehensive health snapshot of the proxy pool.
    pub fn pool_health(&self, pool: &ProxyPool) -> ProxyPoolHealth {
        let total_proxies = pool.proxies.len();
        let mut alive = 0usize;
        let mut dead = 0usize;
        let mut total_latency = 0.0f64;
        let mut total_success_rate = 0.0f64;
        let mut alive_count_for_avg = 0usize;
        let mut tier_map: HashMap<String, (usize, usize, usize, f64, f64)> = HashMap::new(); // total, alive, dead, lat_sum, sr_sum
        let mut asn_type_counts: HashMap<String, usize> = HashMap::new();
        let mut countries: HashSet<String> = HashSet::new();
        let mut asn_set: HashSet<u32> = HashSet::new();

        for (i, proxy) in pool.proxies.iter().enumerate() {
            let h = &pool.health[i];
            let tier_name = proxy.tier.name().to_string();

            let entry = tier_map.entry(tier_name).or_insert((0, 0, 0, 0.0, 0.0));
            entry.0 += 1; // total

            if h.alive {
                alive += 1;
                entry.1 += 1;
                entry.3 += h.avg_latency_ms;
                entry.4 += h.success_rate();
                total_latency += h.avg_latency_ms;
                total_success_rate += h.success_rate();
                alive_count_for_avg += 1;
            } else {
                dead += 1;
                entry.2 += 1;
            }

            // ASN metadata
            if let Some(Some(meta)) = self.proxy_asn.get(i) {
                *asn_type_counts
                    .entry(meta.asn_type.name().to_string())
                    .or_insert(0) += 1;
                countries.insert(meta.country.clone());
                asn_set.insert(meta.asn);
            }

            // Country from proxy entry
            if let Some(cc) = &proxy.country {
                countries.insert(cc.clone());
            }
        }

        let by_tier: HashMap<String, TierHealth> = tier_map
            .into_iter()
            .map(|(name, (total, alive, dead, lat_sum, sr_sum))| {
                let avg_lat = if alive > 0 {
                    lat_sum / alive as f64
                } else {
                    0.0
                };
                let avg_sr = if alive > 0 {
                    sr_sum / alive as f64
                } else {
                    0.0
                };
                (
                    name,
                    TierHealth {
                        total,
                        alive,
                        dead,
                        avg_latency_ms: avg_lat,
                        avg_success_rate: avg_sr,
                    },
                )
            })
            .collect();

        let avg_latency_ms = if alive_count_for_avg > 0 {
            total_latency / alive_count_for_avg as f64
        } else {
            0.0
        };
        let avg_success_rate = if alive_count_for_avg > 0 {
            total_success_rate / alive_count_for_avg as f64
        } else {
            0.0
        };

        // Diversity: unique ASNs / total proxies
        let diversity_score = if total_proxies > 0 {
            (asn_set.len() as f64 / total_proxies as f64).min(1.0)
        } else {
            0.0
        };

        let mut geographic_coverage: Vec<String> = countries.into_iter().collect();
        geographic_coverage.sort();

        ProxyPoolHealth {
            total_proxies,
            alive,
            dead,
            by_tier,
            by_asn_type: asn_type_counts,
            avg_latency_ms,
            avg_success_rate,
            diversity_score,
            geographic_coverage,
        }
    }

    /// Periodic maintenance: prune stale diversity data.
    pub fn cleanup(&mut self) {
        self.diversity.cleanup();
    }
}

impl Default for ProxyIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn_database_has_entries() {
        let db = AsnDatabase::new();
        assert!(
            db.len() >= 200,
            "expected 200+ ASN entries, got {}",
            db.len()
        );
    }

    #[test]
    fn asn_lookup_comcast() {
        let db = AsnDatabase::new();
        let info = db.lookup(7922).expect("Comcast should be in DB");
        assert_eq!(info.organization, "Comcast");
        assert_eq!(info.asn_type, AsnType::Residential);
        assert!(info.trust_score >= 85);
        assert_eq!(info.country, "US");
    }

    #[test]
    fn asn_lookup_aws() {
        let db = AsnDatabase::new();
        let info = db.lookup(16509).expect("AWS should be in DB");
        assert_eq!(info.asn_type, AsnType::Datacenter);
        assert!(info.trust_score <= 30);
        assert!(info.known_blocked_by.contains(&"cloudflare".to_string()));
    }

    #[test]
    fn asn_by_type() {
        let db = AsnDatabase::new();
        let residential = db.by_type(AsnType::Residential);
        assert!(residential.len() >= 20, "expected 20+ residential ASNs");

        let mobile = db.by_type(AsnType::Mobile);
        assert!(mobile.len() >= 5, "expected 5+ mobile ASNs");

        let datacenter = db.by_type(AsnType::Datacenter);
        assert!(datacenter.len() >= 10, "expected 10+ datacenter ASNs");
    }

    #[test]
    fn asn_blocked_by() {
        let db = AsnDatabase::new();
        assert!(db.is_blocked_by(24940, "cloudflare")); // Hetzner
        assert!(db.is_blocked_by(14061, "akamai")); // DigitalOcean
        assert!(!db.is_blocked_by(7922, "cloudflare")); // Comcast — not blocked
    }

    #[test]
    fn diversity_tracker_basic() {
        let policy = AsnDiversityPolicy {
            min_interval_same_asn: Duration::ZERO, // only test consecutive limit
            max_consecutive_same_asn: 2,
            ..Default::default()
        };
        let mut tracker = AsnUsageTracker::new(policy);

        // First use: allowed
        assert!(tracker.is_allowed("example.com", 7922));
        tracker.record("example.com", 7922);

        // Second consecutive: allowed (max is 2)
        assert!(tracker.is_allowed("example.com", 7922));
        tracker.record("example.com", 7922);

        // Third consecutive: blocked
        assert!(!tracker.is_allowed("example.com", 7922));

        // Different ASN: always allowed
        assert!(tracker.is_allowed("example.com", 7018));
    }

    #[test]
    fn diversity_score_calculation() {
        let policy = AsnDiversityPolicy::default();
        let mut tracker = AsnUsageTracker::new(policy);

        // No history = 1.0
        assert_eq!(tracker.diversity_score("example.com"), 1.0);

        // All same ASN = 0.0
        for _ in 0..10 {
            tracker.record("example.com", 7922);
        }
        assert!(tracker.diversity_score("example.com") < 0.2);

        // Mix of ASNs
        let mut tracker2 = AsnUsageTracker::new(AsnDiversityPolicy::default());
        for asn in [7922, 7018, 701, 11351, 22773] {
            tracker2.record("mixed.com", asn);
        }
        assert!(tracker2.diversity_score("mixed.com") >= 0.9);
    }

    #[test]
    fn proxy_score_computation() {
        let mut health = ProxyHealth::new();
        for _ in 0..10 {
            health.record_success(150.0);
        }

        let score = ProxyScore::compute(&health, 90, true, Some("example.com"), 5);
        assert!(
            score.total > 0.7,
            "high-quality proxy should score >0.7, got {}",
            score.total
        );
        assert!(score.asn_trust > 0.8);
        assert_eq!(score.geo_match, 1.0);
    }

    #[test]
    fn proxy_score_bad_proxy() {
        let mut health = ProxyHealth::new();
        for _ in 0..20 {
            health.record_failure(None);
        }

        let score = ProxyScore::compute(&health, 20, false, Some("example.com"), 0);
        assert!(
            score.total < 0.35,
            "bad proxy should score <0.35, got {}",
            score.total
        );
    }

    #[test]
    fn domain_strategy_database() {
        let db = DomainStrategyDatabase::new();
        assert!(db.len() >= 5);

        let walmart = db.get("shop-a.example").expect("walmart strategy");
        assert_eq!(walmart.required_asn_type, Some(AsnType::Residential));
        assert!(walmart.min_trust_score >= 80);
        assert!(walmart.sticky_session);

        let target = db.get("shop-b.example").expect("target strategy");
        assert!(target.required_asn_type.is_none());
        assert!(target.min_trust_score < 50);

        let amazon = db.get("amazon.com").expect("amazon strategy");
        assert!(amazon.min_trust_score >= 85);
    }

    #[test]
    fn domain_strategy_success_recording() {
        let mut strat = DomainProxyStrategy::new("test.com");
        strat.record_success("socks5://1.2.3.4:1080");
        strat.record_success("socks5://1.2.3.4:1080");
        strat.record_success("socks5://5.6.7.8:1080");

        assert_eq!(strat.proxy_success_count("socks5://1.2.3.4:1080"), 2);
        assert_eq!(strat.proxy_success_count("socks5://5.6.7.8:1080"), 1);
        assert_eq!(
            strat.last_successful_proxy,
            Some("socks5://5.6.7.8:1080".into())
        );
    }

    #[test]
    fn intelligence_select_best() {
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry {
            url: "socks5://dc-1:1080".into(),
            tier: ProxyTier::Datacenter,
            country: Some("US".into()),
            label: "dc-1".into(),
            username: None,
            password: None,
        });
        pool.add(ProxyEntry {
            url: "socks5://res-1:1080".into(),
            tier: ProxyTier::Residential,
            country: Some("US".into()),
            label: "res-1".into(),
            username: None,
            password: None,
        });

        let mut intel = ProxyIntelligence::new();
        intel.register_proxy_asn(0, 24940); // Hetzner
        intel.register_proxy_asn(1, 7922); // Comcast

        // For shop-a.example (residential required, Hetzner blocked) should pick res-1
        let best = intel.select_best(&pool, "shop-a.example");
        assert_eq!(best, Some(1), "should select residential proxy for walmart");

        // For shop-b.example (permissive) — both are candidates, but residential scores higher
        let best = intel.select_best(&pool, "shop-b.example");
        assert_eq!(
            best,
            Some(1),
            "residential should still score higher for target"
        );
    }

    #[test]
    fn intelligence_pool_health() {
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry {
            url: "socks5://a:1080".into(),
            tier: ProxyTier::Residential,
            country: Some("US".into()),
            label: "a".into(),
            username: None,
            password: None,
        });
        pool.add(ProxyEntry {
            url: "socks5://b:1080".into(),
            tier: ProxyTier::Datacenter,
            country: Some("DE".into()),
            label: "b".into(),
            username: None,
            password: None,
        });

        let mut intel = ProxyIntelligence::new();
        intel.register_proxy_asn(0, 7922);
        intel.register_proxy_asn(1, 24940);

        let health = intel.pool_health(&pool);
        assert_eq!(health.total_proxies, 2);
        assert_eq!(health.alive, 2);
        assert_eq!(health.dead, 0);
        assert!(health.geographic_coverage.contains(&"US".to_string()));
        assert!(health.geographic_coverage.contains(&"DE".to_string()));
        assert!(health.by_tier.contains_key("residential"));
        assert!(health.by_tier.contains_key("datacenter"));
    }

    #[test]
    fn intelligence_record_block_updates_strategy() {
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry {
            url: "socks5://x:1080".into(),
            tier: ProxyTier::Datacenter,
            country: Some("US".into()),
            label: "x".into(),
            username: None,
            password: None,
        });

        let mut intel = ProxyIntelligence::new();
        intel.register_proxy_asn(0, 24940);

        // Record a block
        intel.record_block(0, "newsite.com");

        let strat = intel
            .domain_strategies
            .get("newsite.com")
            .expect("strategy should have been created");
        assert!(strat.is_asn_blocked(24940));
    }

    #[test]
    fn asn_type_from_proxy_tier() {
        assert_eq!(AsnType::from_proxy_tier(ProxyTier::Mobile), AsnType::Mobile);
        assert_eq!(
            AsnType::from_proxy_tier(ProxyTier::Residential),
            AsnType::Residential
        );
        assert_eq!(AsnType::from_proxy_tier(ProxyTier::Tor), AsnType::Tor);
        assert_eq!(
            AsnType::from_proxy_tier(ProxyTier::Datacenter),
            AsnType::Datacenter
        );
    }

    #[test]
    fn register_proxy_from_tier() {
        let mut intel = ProxyIntelligence::new();
        intel.register_proxy_from_tier(0, ProxyTier::Residential, Some("US"));
        intel.register_proxy_from_tier(1, ProxyTier::Tor, None);

        let meta0 = intel.proxy_asn[0].as_ref().unwrap();
        assert_eq!(meta0.asn_type, AsnType::Residential);
        assert!(meta0.trust_score >= 80);

        let meta1 = intel.proxy_asn[1].as_ref().unwrap();
        assert_eq!(meta1.asn_type, AsnType::Tor);
        assert!(meta1.trust_score <= 20);
    }
}
