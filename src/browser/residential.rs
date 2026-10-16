//! Residential + mobile (carrier) proxy provider adapters.
//!
//! Commercial rotating-proxy gateways (IPRoyal, Oxylabs, Bright Data,
//! Smartproxy, Webshare) all expose a single HTTP/SOCKS5 endpoint with
//! `user:pass` auth, where the *username* encodes country/ASN/session.
//! This module turns provider config into authenticated [`ProxyEntry`]s
//! for the [`ProxyPool`](super::proxy::ProxyPool).
//!
//! The critical realization from the anti-bot research: **Tor and datacenter
//! IPs fail reputation checks on PerimeterX / Akamai / AWS WAF targets BEFORE
//! any sensor runs.** Residential and mobile-carrier IPs are the actual unlock,
//! and this adapter is how they get wired into the pool.

use super::proxy::{ProxyEntry, ProxyTier};

/// A single residential/mobile gateway endpoint configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Gateway hostname, e.g. `geo.iproyal.com`.
    pub host: String,
    /// Gateway port, e.g. `12321`.
    pub port: u16,
    /// Connection scheme: `"http"` or `"socks5"`.
    pub scheme: String,
    /// Base username (customer id / user). Country/ASN/session suffixes are
    /// appended by the provider-specific builders below.
    pub username: String,
    /// Gateway password.
    pub password: String,
    /// Proxy quality tier this gateway provides.
    pub tier: ProxyTier,
}

impl GatewayConfig {
    /// Build an authenticated [`ProxyEntry`] from a fully-composed username.
    pub fn endpoint(&self, username: &str) -> ProxyEntry {
        ProxyEntry::with_auth(
            &format!("{}://{}:{}", self.scheme, self.host, self.port),
            self.tier,
            username,
            &self.password,
        )
    }
}

/// A residential/mobile proxy provider.
///
/// Implementors produce `Vec<ProxyEntry>` for a target country and an
/// optional sticky-session id. A `None` session mints a fresh IP per request
/// (rotating); a `Some(id)` pins the session to a single exit IP (sticky).
pub trait ResidentialProvider {
    fn name(&self) -> &'static str;
    fn endpoints(&self, country: Option<&str>, sticky_session: Option<&str>) -> Vec<ProxyEntry>;
}

/// IPRoyal — residential (~$1.75/GB) and mobile.
///
/// Username format: `<user>_country-<cc>_session-<id>` (sticky) or
/// `<user>_country-<cc>` (rotating). Gateway: `geo.iproyal.com:12321`.
#[derive(Debug, Clone)]
pub struct IpRoyal {
    pub cfg: GatewayConfig,
}

impl ResidentialProvider for IpRoyal {
    fn name(&self) -> &'static str {
        "iproyal"
    }

    fn endpoints(&self, country: Option<&str>, sticky_session: Option<&str>) -> Vec<ProxyEntry> {
        let mut u = self.cfg.username.clone();
        if let Some(cc) = country {
            u.push_str(&format!("_country-{}", cc.to_lowercase()));
        }
        if let Some(sid) = sticky_session {
            u.push_str(&format!("_session-{sid}"));
        }
        vec![self.cfg.endpoint(&u)]
    }
}

/// Oxylabs — residential (`pr.oxylabs.io:7777`) and mobile
/// (`mobile-pr.oxylabs.io:40000`).
///
/// Username format: `customer-<user>-cc-<cc>-sessid-<id>` (sticky) or
/// `customer-<user>-cc-<cc>` (rotating).
#[derive(Debug, Clone)]
pub struct Oxylabs {
    pub cfg: GatewayConfig,
}

impl ResidentialProvider for Oxylabs {
    fn name(&self) -> &'static str {
        "oxylabs"
    }

    fn endpoints(&self, country: Option<&str>, sticky_session: Option<&str>) -> Vec<ProxyEntry> {
        let mut u = format!("customer-{}", self.cfg.username);
        if let Some(cc) = country {
            u.push_str(&format!("-cc-{}", cc.to_lowercase()));
        }
        if let Some(sid) = sticky_session {
            u.push_str(&format!("-sessid-{sid}"));
        }
        vec![self.cfg.endpoint(&u)]
    }
}

/// Bright Data — residential (`brd.superproxy.io:22225`).
///
/// Username format: `brd-customer-<cid>-zone-<zone>-session-<id>` (sticky) or
/// `brd-customer-<cid>-zone-<zone>` (rotating).
#[derive(Debug, Clone)]
pub struct BrightData {
    pub cfg: GatewayConfig,
    /// Zone name (e.g. `residential_proxy1`).
    pub zone: String,
}

impl ResidentialProvider for BrightData {
    fn name(&self) -> &'static str {
        "brightdata"
    }

    fn endpoints(&self, country: Option<&str>, sticky_session: Option<&str>) -> Vec<ProxyEntry> {
        let mut u = format!("brd-customer-{}-zone-{}", self.cfg.username, self.zone);
        // Bright Data encodes country via a separate `-country-<cc>` suffix.
        if let Some(cc) = country {
            u.push_str(&format!("-country-{}", cc.to_lowercase()));
        }
        if let Some(sid) = sticky_session {
            u.push_str(&format!("-session-{sid}"));
        }
        vec![self.cfg.endpoint(&u)]
    }
}

/// Convenience constructors with the canonical gateway endpoints.
impl IpRoyal {
    pub fn residential(username: &str, password: &str) -> Self {
        Self {
            cfg: GatewayConfig {
                host: "geo.iproyal.com".into(),
                port: 12321,
                scheme: "http".into(),
                username: username.into(),
                password: password.into(),
                tier: ProxyTier::Residential,
            },
        }
    }
}

impl Oxylabs {
    pub fn residential(username: &str, password: &str) -> Self {
        Self {
            cfg: GatewayConfig {
                host: "pr.oxylabs.io".into(),
                port: 7777,
                scheme: "http".into(),
                username: username.into(),
                password: password.into(),
                tier: ProxyTier::Residential,
            },
        }
    }

    /// Mobile (carrier) IPs — highest trust for the Akamai/CoStar tier.
    pub fn mobile(username: &str, password: &str) -> Self {
        Self {
            cfg: GatewayConfig {
                host: "mobile-pr.oxylabs.io".into(),
                port: 40000,
                scheme: "http".into(),
                username: username.into(),
                password: password.into(),
                tier: ProxyTier::Mobile,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iproyal_rotating_us() {
        let p = IpRoyal::residential("user123", "pw");
        let eps = p.endpoints(Some("US"), None);
        assert_eq!(eps.len(), 1);
        let e = &eps[0];
        assert_eq!(e.url, "http://geo.iproyal.com:12321");
        assert_eq!(e.tier, ProxyTier::Residential);
        assert_eq!(e.username.as_deref(), Some("user123_country-us"));
        assert_eq!(e.password.as_deref(), Some("pw"));
        assert!(e.has_auth());
    }

    #[test]
    fn iproyal_sticky_session() {
        let p = IpRoyal::residential("user123", "pw");
        let eps = p.endpoints(Some("US"), Some("abc123"));
        assert_eq!(eps[0].username.as_deref(), Some("user123_country-us_session-abc123"));
    }

    #[test]
    fn oxylabs_mobile_sticky() {
        let p = Oxylabs::mobile("cust", "pw");
        let eps = p.endpoints(Some("US"), Some("s1"));
        assert_eq!(eps[0].url, "http://mobile-pr.oxylabs.io:40000");
        assert_eq!(eps[0].tier, ProxyTier::Mobile);
        assert_eq!(eps[0].username.as_deref(), Some("customer-cust-cc-us-sessid-s1"));
    }

    #[test]
    fn brightdata_zone() {
        let p = BrightData {
            cfg: GatewayConfig {
                host: "brd.superproxy.io".into(),
                port: 22225,
                scheme: "http".into(),
                username: "hl_12345".into(),
                password: "pw".into(),
                tier: ProxyTier::Residential,
            },
            zone: "res_proxy1".into(),
        };
        let eps = p.endpoints(None, Some("sess"));
        assert_eq!(
            eps[0].username.as_deref(),
            Some("brd-customer-hl_12345-zone-res_proxy1-session-sess")
        );
    }
}
