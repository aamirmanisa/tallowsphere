//! Provider watchers — lawful catalog sources with fixture + HTTP paths.
//!
//! **Compliance (binding, SPEC-v2 §11):** own keys only; official provider
//! APIs only; never third-party endpoints; polite polling (caller cadence);
//! fail-close on errors (a dark watcher contributes zero offers, it never
//! guesses). The CLI does not touch the network unless `--live` is explicit.
//!
//! Each watcher normalizes its provider's catalog JSON into [`Offer`]s. The
//! HTTP path takes an injectable transport closure so the full request →
//! parse → normalize pipeline is unit-testable without network access.

use crate::model::Offer;
use serde_json::Value;
use std::path::PathBuf;

/// Watcher errors (stringly on purpose: operator-facing, no key material).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WatchError(pub String);

/// A catalog source.
pub trait Watcher {
    fn id(&self) -> &'static str;
    fn offers(&self) -> Result<Vec<Offer>, WatchError>;
}

/// Region → (city, country) tables (v1 static; provider location metadata
/// is not always free to fetch — documented as static v1).
pub fn hetzner_location(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "hel1" => ("Helsinki", "FI"),
        "nbg1" => ("Nuremberg", "DE"),
        "fsn1" => ("Falkenstein", "DE"),
        "ash" => ("Ashburn", "US"),
        "sin" => ("Singapore", "SG"),
        _ => return None,
    })
}

pub fn vultr_region(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "ams" => ("Amsterdam", "NL"),
        "fra" => ("Frankfurt", "DE"),
        "sto" => ("Stockholm", "SE"),
        "ewr" => ("New Jersey", "US"),
        _ => return None,
    })
}

pub fn do_region(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "ams3" => ("Amsterdam 3", "NL"),
        "fra1" => ("Frankfurt 1", "DE"),
        "sfo3" => ("San Francisco 3", "US"),
        _ => return None,
    })
}

/// Fetch a value from a JSON object by dotted path (helper for normalizers).
fn get<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn f(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn u(v: Option<&Value>) -> Option<u32> {
    f(v).map(|x| x as u32)
}

/// Hetzner Cloud: `server_types` + `pricing.server_types` joined by name.
/// Real shape: `GET /v1/server_types` + `GET /v1/pricing`.
pub fn parse_hetzner(v: &Value) -> Result<Vec<Offer>, WatchError> {
    let types = get(v, "server_types")
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError("hetzner: missing server_types[]".into()))?;
    let pricing = get(v, "pricing.server_types")
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError("hetzner: missing pricing.server_types[]".into()))?;
    let mut out = Vec::new();
    for t in types {
        let name = t.get("name").and_then(Value::as_str).unwrap_or_default();
        let cores = u(t.get("cores")).unwrap_or(0);
        let mem_gb = f(t.get("memory")).unwrap_or(0.0);
        let disk = u(t.get("disk")).unwrap_or(0);
        let arch = match t.get("architecture").and_then(Value::as_str) {
            Some("arm") => "arm64",
            _ => "x86_64",
        };
        let sid = t
            .get("id")
            .map(|x| x.to_string())
            .unwrap_or_else(|| format!("\"{name}\""));
        let Some(price_rows) = pricing
            .iter()
            .find(|p| p.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|p| p.get("prices"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for row in price_rows {
            let loc = row.get("location").and_then(Value::as_str).unwrap_or("");
            let Some((city, country)) = hetzner_location(loc) else {
                continue;
            };
            let price = f(get(row, "price_monthly.net"))
                .or_else(|| f(get(row, "price_monthly.gross")))
                .unwrap_or(f64::NAN);
            if !price.is_finite() {
                continue;
            }
            out.push(Offer {
                provider: "hetzner".into(),
                plan: name.into(),
                region: loc.into(),
                city: city.into(),
                country: country.into(),
                price_month_eur: price,
                vcpu: cores,
                mem_mb: (mem_gb * 1024.0) as u32,
                disk_gb: disk,
                arch: arch.into(),
                source_id: sid.clone(),
            });
        }
    }
    Ok(out)
}

/// Vultr: `plans[]` × their `locations[]` resolved via `regions[]`.
pub fn parse_vultr(v: &Value) -> Result<Vec<Offer>, WatchError> {
    let plans = get(v, "plans")
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError("vultr: missing plans[]".into()))?;
    let regions = get(v, "regions").and_then(Value::as_array);
    let region = |code: &str| -> Option<(String, String)> {
        if let Some(rs) = regions {
            if let Some(r) = rs
                .iter()
                .find(|r| r.get("id").and_then(Value::as_str) == Some(code))
            {
                let city = r
                    .get("city")
                    .and_then(Value::as_str)
                    .unwrap_or(code)
                    .to_string();
                let country = r
                    .get("country")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                return Some((city, country));
            }
        }
        vultr_region(code).map(|(c, cc)| (c.to_string(), cc.to_string()))
    };
    let mut out = Vec::new();
    for p in plans {
        let pid = p.get("id").and_then(Value::as_str).unwrap_or_default();
        let vcpu = u(p.get("vcpu_count")).unwrap_or(0);
        let ram_mb = u(p.get("ram")).unwrap_or(0);
        let disk = u(p.get("disk")).unwrap_or(0);
        let price = f(p.get("monthly_cost")).unwrap_or(f64::NAN);
        if !price.is_finite() {
            continue;
        }
        let Some(locs) = p.get("locations").and_then(Value::as_array) else {
            continue;
        };
        for l in locs {
            let code = l.as_str().unwrap_or("");
            let Some((city, country)) = region(code) else {
                continue;
            };
            out.push(Offer {
                provider: "vultr".into(),
                plan: pid.into(),
                region: code.into(),
                city,
                country,
                price_month_eur: price,
                vcpu,
                mem_mb: ram_mb,
                disk_gb: disk,
                arch: "x86_64".into(),
                source_id: pid.into(),
            });
        }
    }
    Ok(out)
}

/// DigitalOcean: `sizes[]` × `regions[]` (flat pricing per size in v1).
pub fn parse_digitalocean(v: &Value) -> Result<Vec<Offer>, WatchError> {
    let sizes = get(v, "sizes")
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError("digitalocean: missing sizes[]".into()))?;
    let regions = get(v, "regions")
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError("digitalocean: missing regions[]".into()))?;
    let mut out = Vec::new();
    for s in sizes {
        let slug = s.get("slug").and_then(Value::as_str).unwrap_or_default();
        let vcpu = u(s.get("vcpus")).unwrap_or(0);
        let ram_mb = u(s.get("memory")).unwrap_or(0);
        let disk = u(s.get("disk")).unwrap_or(0);
        let price = f(s.get("price_monthly")).unwrap_or(f64::NAN);
        if !price.is_finite() {
            continue;
        }
        for r in regions {
            let code = r.get("slug").and_then(Value::as_str).unwrap_or("");
            let country = r
                .get("country")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| do_region(code).map(|(_, cc)| cc.to_string()));
            let Some(country) = country else { continue };
            let city = r
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(code)
                .to_string();
            out.push(Offer {
                provider: "digitalocean".into(),
                plan: slug.into(),
                region: code.into(),
                city,
                country,
                price_month_eur: price,
                vcpu,
                mem_mb: ram_mb,
                disk_gb: disk,
                arch: "x86_64".into(),
                source_id: slug.into(),
            });
        }
    }
    Ok(out)
}

/// OVH: order-catalog shape, simplified in v1 (plans already region-resolved
/// in the fixture — the live catalog requires the OVH cart API, follow-up).
pub fn parse_ovh(v: &Value) -> Result<Vec<Offer>, WatchError> {
    let plans = get(v, "plans")
        .and_then(Value::as_array)
        .ok_or_else(|| WatchError("ovh: missing plans[]".into()))?;
    let mut out = Vec::new();
    for p in plans {
        let code = p.get("code").and_then(Value::as_str).unwrap_or_default();
        let price = f(p.get("price_monthly")).unwrap_or(f64::NAN);
        if !price.is_finite() {
            continue;
        }
        let region = p.get("region").and_then(Value::as_str).unwrap_or("");
        let Some(city) = p.get("city").and_then(Value::as_str) else {
            continue;
        };
        let Some(country) = p.get("country").and_then(Value::as_str) else {
            continue;
        };
        out.push(Offer {
            provider: "ovh".into(),
            plan: code.into(),
            region: region.into(),
            city: city.into(),
            country: country.into(),
            price_month_eur: price,
            vcpu: u(p.get("vcpu")).unwrap_or(0),
            mem_mb: u(p.get("memory")).unwrap_or(0),
            disk_gb: u(p.get("disk")).unwrap_or(0),
            arch: "x86_64".into(),
            source_id: code.into(),
        });
    }
    Ok(out)
}

/// Dispatch by provider id (fixture + HTTP share this).
pub fn parse_provider(id: &str, v: &Value) -> Result<Vec<Offer>, WatchError> {
    match id {
        "hetzner" => parse_hetzner(v),
        "vultr" => parse_vultr(v),
        "digitalocean" => parse_digitalocean(v),
        "ovh" => parse_ovh(v),
        other => Err(WatchError(format!("unknown provider: {other}"))),
    }
}

/// Fixture watcher: reads `{dir}/{id}.json` and normalizes it.
/// Deterministic source used by tests, rehearsals, and the CLI default.
pub struct FixtureWatcher {
    id: &'static str,
    path: PathBuf,
}

impl FixtureWatcher {
    pub fn new(id: &'static str, dir: &std::path::Path) -> Self {
        Self {
            id,
            path: dir.join(format!("{id}.json")),
        }
    }
}

impl Watcher for FixtureWatcher {
    fn id(&self) -> &'static str {
        self.id
    }

    fn offers(&self) -> Result<Vec<Offer>, WatchError> {
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| WatchError(format!("{}: read {}: {e}", self.id, self.path.display())))?;
        let v: Value = serde_json::from_str(&raw)
            .map_err(|e| WatchError(format!("{}: bad fixture JSON: {e}", self.id)))?;
        parse_provider(self.id, &v)
    }
}

/// Injectable transport: returns `(status, body)`.
pub type Transport =
    Box<dyn Fn(&str, &[(&str, &str)]) -> Result<(u16, String), String> + Send + Sync>;

/// HTTP watcher: official API, own key from env. `--live` only.
pub struct HttpWatcher {
    id: &'static str,
    url: String,
    token_env: &'static str,
    transport: Transport,
}

impl HttpWatcher {
    pub fn new(id: &'static str, url: &str, token_env: &'static str, transport: Transport) -> Self {
        Self {
            id,
            url: url.into(),
            token_env,
            transport,
        }
    }

    /// The **caller-supplied egress plane**, as a transport.
    ///
    /// The locator does not own egress: this refuses unless `TALLOW_LOCATOR_PROXY`
    /// names the proxy to ride (e.g. `socks5://127.0.0.1:9050` for this box's Tor
    /// SOCKS port), so a live scan cannot leave from the box IP by default. A
    /// configured-but-unusable proxy refuses too — never a silent fallback to a
    /// direct connection, which is the failure this replaced.
    pub fn proxied_transport() -> Result<Transport, String> {
        let url = std::env::var("TALLOW_LOCATOR_PROXY").ok();
        Self::proxied_transport_from(url.as_deref())
    }

    /// Env-independent core of [`Self::proxied_transport`], so the refusal is
    /// testable without mutating the process environment.
    fn proxied_transport_from(proxy_url: Option<&str>) -> Result<Transport, String> {
        const REFUSAL: &str = "egress refused: TALLOW_LOCATOR_PROXY is not set";
        let url = proxy_url
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                format!("{REFUSAL} — the locator will not egress from the box IP (set it to the proxy to use, e.g. socks5://127.0.0.1:9050)")
            })?;
        let proxy = ureq::Proxy::new(url)
            .map_err(|e| format!("egress refused: TALLOW_LOCATOR_PROXY is not a usable proxy URL ({url}): {e}"))?;
        // `.proxy(…)` is mandatory, not decorative: the tree's egress guard bans a
        // hand-built `config_builder()` agent that never sets one.
        let agent = ureq::Agent::config_builder()
            .proxy(Some(proxy))
            .build()
            .new_agent();
        Ok(Box::new(move |url: &str, headers: &[(&str, &str)]| {
            let mut req = agent.get(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            match req.call() {
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    let body = resp
                        .body_mut()
                        .read_to_string()
                        .map_err(|e| format!("body: {e}"))?;
                    Ok((status, body))
                }
                Err(e) => Err(format!("{e}")),
            }
        }))
    }

    /// What the caller must set for `--live`: the proxy the scan rides.
    pub fn live_proxy_env() -> &'static str {
        "TALLOW_LOCATOR_PROXY"
    }

    /// Provider endpoints + token env names (official APIs, v1).
    pub fn endpoint(id: &str) -> Option<(&'static str, &'static str)> {
        Some(match id {
            "hetzner" => ("https://api.hetzner.cloud/v1/pricing", "HCLOUD_TOKEN"),
            "vultr" => ("https://api.vultr.com/v2/plans", "VULTR_API_KEY"),
            "digitalocean" => (
                "https://api.digitalocean.com/v2/sizes",
                "DIGITALOCEAN_TOKEN",
            ),
            "ovh" => (
                "https://api.ovh.com/v1/order/catalog/public/vps",
                "OVH_APP_KEY",
            ),
            _ => return None,
        })
    }
}

impl Watcher for HttpWatcher {
    fn id(&self) -> &'static str {
        self.id
    }

    fn offers(&self) -> Result<Vec<Offer>, WatchError> {
        let token = std::env::var(self.token_env).map_err(|_| {
            WatchError(format!(
                "{}: missing key env {} (live mode requires own provider keys)",
                self.id, self.token_env
            ))
        })?;
        if token.trim().is_empty() {
            return Err(WatchError(format!(
                "{}: empty token in {}",
                self.id, self.token_env
            )));
        }
        let auth = format!("Bearer {token}");
        let (status, body) = (self.transport)(&self.url, &[("Authorization", auth.as_str())])
            .map_err(|e| WatchError(format!("{}: transport: {e}", self.id)))?;
        if !(200..300).contains(&status) {
            return Err(WatchError(format!("{}: HTTP {status}", self.id)));
        }
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| WatchError(format!("{}: bad JSON: {e}", self.id)))?;
        parse_provider(self.id, &v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HETZNER: &str = r#"{
      "server_types": [
        {"id": 1, "name": "cx22", "cores": 2, "memory": 4, "disk": 40, "architecture": "x86"},
        {"id": 3, "name": "cax11", "cores": 2, "memory": 4, "disk": 40, "architecture": "arm"}
      ],
      "pricing": {
        "server_types": [
          {"name": "cx22", "prices": [
            {"location": "hel1", "price_monthly": {"net": "4.35", "currency": "EUR"}},
            {"location": "ash", "price_monthly": {"net": "4.99", "currency": "EUR"}}
          ]},
          {"name": "cax11", "prices": [
            {"location": "hel1", "price_monthly": {"net": "3.79", "currency": "EUR"}}
          ]}
        ]
      }
    }"#;

    #[test]
    fn hetzner_fixture_normalizes() {
        let v: Value = serde_json::from_str(HETZNER).unwrap();
        let offers = parse_hetzner(&v).unwrap();
        assert_eq!(offers.len(), 3);
        let hel = offers
            .iter()
            .find(|o| o.plan == "cx22" && o.region == "hel1")
            .unwrap();
        assert_eq!(hel.country, "FI");
        assert!((hel.price_month_eur - 4.35).abs() < 1e-9);
        assert_eq!(hel.mem_mb, 4096);
        let arm = offers.iter().find(|o| o.plan == "cax11").unwrap();
        assert_eq!(arm.arch, "arm64");
    }

    #[test]
    fn http_watcher_parses_via_injected_transport() {
        let t: Transport = Box::new(|_url, headers| {
            assert_eq!(headers[0].0, "Authorization");
            assert!(headers[0].1.starts_with("Bearer "));
            Ok((200, HETZNER.to_string()))
        });
        let w = HttpWatcher::new(
            "hetzner",
            "https://api.hetzner.cloud/v1/pricing",
            "TEST_TOKEN_ENV",
            t,
        );
        std::env::set_var("TEST_TOKEN_ENV", "tok");
        let offers = w.offers().unwrap();
        std::env::remove_var("TEST_TOKEN_ENV");
        assert_eq!(offers.len(), 3);
    }

    #[test]
    fn live_transport_refuses_without_a_configured_proxy() {
        // The property that matters: no proxy configured = no egress, not a
        // silent direct connection from the box IP. (`Transport` is a boxed
        // closure and so has no `Debug`, hence the explicit matches.)
        for absent in [None, Some(""), Some("   ")] {
            match HttpWatcher::proxied_transport_from(absent) {
                Ok(_) => panic!("an unset proxy must refuse, not build a direct client"),
                Err(e) => {
                    assert!(e.contains("TALLOW_LOCATOR_PROXY"), "{e}");
                    assert!(e.contains("egress refused"), "{e}");
                }
            }
        }
    }

    #[test]
    fn live_transport_refuses_an_unusable_proxy_url() {
        match HttpWatcher::proxied_transport_from(Some("://")) {
            Ok(_) => panic!("an unusable proxy URL must refuse, not fall back to direct"),
            Err(e) => assert!(e.contains("egress refused"), "{e}"),
        }
    }

    #[test]
    fn live_transport_accepts_the_boxes_tor_socks_proxy() {
        match HttpWatcher::proxied_transport_from(Some("socks5://127.0.0.1:9050")) {
            Ok(_) => {}
            Err(e) => panic!("the documented proxy form must build a transport: {e}"),
        }
    }

    #[test]
    fn http_watcher_missing_key_is_error() {
        let t: Transport = Box::new(|_, _| Ok((200, "{}".into())));
        let w = HttpWatcher::new("hetzner", "u", "NO_SUCH_TOKEN_ENV", t);
        assert!(w.offers().is_err());
    }

    #[test]
    fn http_watcher_http_error_is_error() {
        let t: Transport = Box::new(|_, _| Ok((403, "denied".into())));
        let w = HttpWatcher::new("hetzner", "u", "TEST_TOKEN_ENV2", t);
        std::env::set_var("TEST_TOKEN_ENV2", "tok");
        let r = w.offers();
        std::env::remove_var("TEST_TOKEN_ENV2");
        assert!(r.is_err());
    }

    #[test]
    fn vultr_and_ovh_normalize() {
        let vultr: Value = json!({
          "plans": [{"id": "vc2-1c-2gb", "vcpu_count": 1, "ram": 2048, "disk": 55, "monthly_cost": 5.0, "locations": ["ams", "ewr"]}],
          "regions": [{"id": "ams", "city": "Amsterdam", "country": "NL"}, {"id": "ewr", "city": "New Jersey", "country": "US"}]
        });
        let offers = parse_vultr(&vultr).unwrap();
        assert_eq!(offers.len(), 2);
        assert!(offers.iter().any(|o| o.country == "NL"));
        let ovh: Value = json!({
          "plans": [{"code": "vps-2-4-80", "vcpu": 2, "memory": 4096, "disk": 80, "price_monthly": 7.19, "region": "GRA", "city": "Gravelines", "country": "FR"}]
        });
        let offers = parse_ovh(&ovh).unwrap();
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].country, "FR");
    }
}
