//! DNS-over-HTTPS resolver using hickory-resolver
//!
//! Prevents plaintext DNS queries from leaking hostnames to local network observers.

use crate::error::NetworkError;
use crate::Result;
use std::net::IpAddr;

/// DNS-over-HTTPS resolver
#[derive(Debug)]
pub struct DohResolver {
    /// DoH endpoint URL
    endpoint: String,
}

/// Well-known DoH providers
pub const DOH_CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";
pub const DOH_GOOGLE: &str = "https://dns.google/dns-query";
pub const DOH_QUAD9: &str = "https://dns.quad9.net/dns-query";

impl DohResolver {
    /// Create a new DoH resolver with a custom endpoint
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    /// Create a DoH resolver using Cloudflare (default)
    pub fn cloudflare() -> Self {
        Self::new(DOH_CLOUDFLARE.to_string())
    }

    /// Resolve a hostname via DNS-over-HTTPS
    ///
    /// All DNS queries go over HTTPS, preventing plaintext DNS leaks.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::config::{CLOUDFLARE, GOOGLE, QUAD9};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::TokioResolver;

        // hickory 0.26 replaced the per-provider `cloudflare_https()` helpers
        // and `TokioConnectionProvider` with a `ServerGroup`-based config plus a
        // runtime provider passed to `builder_with_config`. `TokioResolver` is
        // the Tokio-specialized resolver type. The DoH provider group is picked
        // from the configured well-known endpoint.
        let config = if self.endpoint.contains("cloudflare") {
            ResolverConfig::https(&CLOUDFLARE)
        } else if self.endpoint.contains("google") {
            ResolverConfig::https(&GOOGLE)
        } else if self.endpoint.contains("quad9") {
            ResolverConfig::https(&QUAD9)
        } else {
            ResolverConfig::https(&CLOUDFLARE)
        };

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|e| {
                NetworkError::DnsResolution(format!("failed to build DoH resolver: {}", e))
            })?;

        // `TokioResolver::lookup_ip` yields a future that completes on the
        // caller's Tokio reactor; await it directly.
        let response = resolver.lookup_ip(hostname).await.map_err(|e| {
            NetworkError::DnsResolution(format!("DoH resolution failed for '{}': {}", hostname, e))
        })?;

        let addrs: Vec<IpAddr> = response.iter().collect();

        if addrs.is_empty() {
            return Err(NetworkError::DnsResolution(format!(
                "DoH returned no addresses for '{}'",
                hostname
            )));
        }

        Ok(addrs)
    }

    /// Get the endpoint URL
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_resolver() {
        let resolver = DohResolver::new("https://custom.dns/query".to_string());
        assert_eq!(resolver.endpoint(), "https://custom.dns/query");
    }

    #[test]
    fn test_cloudflare_default() {
        let resolver = DohResolver::cloudflare();
        assert!(resolver.endpoint().contains("cloudflare"));
    }
}
