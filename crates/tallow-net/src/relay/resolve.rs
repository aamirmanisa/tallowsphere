//! Proxy-aware relay address resolution
//!
//! Centralizes DNS resolution strategy to prevent DNS leaks when a proxy
//! is active. Three-branch decision tree:
//!
//! 1. IP literal (e.g., `18.119.135.151:4433`) -- no DNS needed
//! 2. Tor mode -- hostname sent to proxy for DNS resolution inside Tor
//! 3. Generic SOCKS5 -- resolve via DNS-over-HTTPS (no system resolver)
//! 4. No proxy -- system DNS via `tokio::net::lookup_host()`

use crate::error::NetworkError;
use crate::privacy::ProxyConfig;
use crate::Result;
use std::net::SocketAddr;
use tracing::debug;

/// Result of proxy-aware relay resolution
#[derive(Debug, Clone)]
pub enum ResolvedRelay {
    /// Relay address (direct IP literal or resolved address)
    ///
    /// `server_name` carries the DNS name when the relay was dialed by name —
    /// required for strict TLS certificate validation; `None` for IP literals.
    Addr {
        /// Resolved relay socket address
        addr: SocketAddr,
        /// DNS name dialed (strict TLS verification name), when known
        server_name: Option<String>,
    },
    /// Hostname to be resolved by the proxy (Tor mode -- no local resolution)
    Hostname {
        /// Relay hostname
        host: String,
        /// Relay port
        port: u16,
    },
}

/// Resolve a relay address with proxy awareness
///
/// Decision tree:
/// 1. If relay string parses as `SocketAddr` (IP:port) -> `ResolvedRelay::Addr` (no DNS)
/// 2. If proxy is active + Tor mode -> `ResolvedRelay::Hostname` (proxy resolves)
/// 3. If proxy is active + generic SOCKS5 -> resolve via DoH -> `ResolvedRelay::Addr`
/// 4. If no proxy -> system DNS -> `ResolvedRelay::Addr`
pub async fn resolve_relay_proxy(
    relay: &str,
    proxy: Option<&ProxyConfig>,
) -> Result<ResolvedRelay> {
    // Branch 1: IP literal -- no DNS needed regardless of proxy config
    if let Ok(addr) = relay.parse::<SocketAddr>() {
        debug!("relay address is IP literal: {}", addr);
        return Ok(ResolvedRelay::Addr {
            addr,
            server_name: None,
        });
    }

    // Parse host:port from the relay string
    let (host, port) = parse_host_port(relay)?;

    match proxy {
        // Branch 2: Tor mode -- send hostname to proxy, no local DNS
        Some(cfg) if cfg.tor_mode => {
            debug!(
                "Tor mode: sending hostname '{}' to proxy for DNS resolution",
                host
            );
            Ok(ResolvedRelay::Hostname {
                host: host.to_string(),
                port,
            })
        }

        // Branch 3: Generic SOCKS5 -- resolve via DNS-over-HTTPS
        Some(_) => {
            debug!("generic SOCKS5: resolving '{}' via DNS-over-HTTPS", host);
            let resolver = crate::privacy::DohResolver::cloudflare();
            let addrs = resolver.resolve(host).await?;
            let ip = addrs.into_iter().next().ok_or_else(|| {
                NetworkError::DnsResolution(format!("DoH returned no addresses for '{}'", host))
            })?;
            Ok(ResolvedRelay::Addr {
                addr: SocketAddr::new(ip, port),
                server_name: Some(host.to_string()),
            })
        }

        // Branch 4: No proxy -- system DNS
        None => {
            debug!("no proxy: resolving '{}' via system DNS", host);
            let addr = tokio::net::lookup_host(relay)
                .await
                .map_err(|e| {
                    NetworkError::DnsResolution(format!(
                        "failed to resolve relay '{}': {}",
                        relay, e
                    ))
                })?
                .next()
                .ok_or_else(|| {
                    NetworkError::DnsResolution(format!("no addresses found for relay '{}'", relay))
                })?;
            Ok(ResolvedRelay::Addr {
                addr,
                server_name: Some(host.to_string()),
            })
        }
    }
}

/// Parse a `host:port` string into components
///
/// Handles standard hostnames (`relay.example.com:4433`), IPv6 brackets
/// (`[::1]:4433`), and validates that a port is present.
fn parse_host_port(relay: &str) -> Result<(&str, u16)> {
    // Handle IPv6 bracket notation: [::1]:port
    if relay.starts_with('[') {
        if let Some(bracket_end) = relay.find(']') {
            let host = &relay[1..bracket_end];
            let remainder = &relay[bracket_end + 1..];
            if let Some(port_str) = remainder.strip_prefix(':') {
                let port: u16 = port_str.parse().map_err(|_| {
                    NetworkError::DnsResolution(format!(
                        "invalid port in relay address '{}'",
                        relay
                    ))
                })?;
                return Ok((host, port));
            }
        }
        return Err(NetworkError::DnsResolution(format!(
            "invalid IPv6 relay address '{}' -- expected [host]:port",
            relay
        )));
    }

    // Standard host:port -- split on LAST ':' to handle hostnames with colons
    if let Some(colon_pos) = relay.rfind(':') {
        let host = &relay[..colon_pos];
        let port_str = &relay[colon_pos + 1..];
        let port: u16 = port_str.parse().map_err(|_| {
            NetworkError::DnsResolution(format!(
                "invalid port '{}' in relay address '{}'",
                port_str, relay
            ))
        })?;
        Ok((host, port))
    } else {
        Err(NetworkError::DnsResolution(format!(
            "relay address '{}' missing port -- expected host:port",
            relay
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ip_literal_no_proxy() {
        let result = resolve_relay_proxy("18.119.135.151:4433", None)
            .await
            .unwrap();
        match result {
            ResolvedRelay::Addr { addr, .. } => {
                assert_eq!(addr.to_string(), "18.119.135.151:4433");
            }
            ResolvedRelay::Hostname { .. } => panic!("expected Addr for IP literal"),
        }
    }

    #[tokio::test]
    async fn test_resolve_ip_literal_with_tor_proxy() {
        let proxy = ProxyConfig::tor_default();
        let result = resolve_relay_proxy("18.119.135.151:4433", Some(&proxy))
            .await
            .unwrap();
        match result {
            ResolvedRelay::Addr { addr, .. } => {
                assert_eq!(addr.to_string(), "18.119.135.151:4433");
            }
            ResolvedRelay::Hostname { .. } => {
                panic!("expected Addr for IP literal even with proxy")
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_ip_literal_with_generic_proxy() {
        let proxy = ProxyConfig {
            socks5_addr: "127.0.0.1:1080".parse().unwrap(),
            tor_mode: false,
            auth: None,
        };
        let result = resolve_relay_proxy("18.119.135.151:4433", Some(&proxy))
            .await
            .unwrap();
        match result {
            ResolvedRelay::Addr { addr, .. } => {
                assert_eq!(addr.to_string(), "18.119.135.151:4433");
            }
            ResolvedRelay::Hostname { .. } => {
                panic!("expected Addr for IP literal even with proxy")
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_hostname_tor_returns_hostname() {
        let proxy = ProxyConfig::tor_default();
        let result = resolve_relay_proxy("relay.example.com:4433", Some(&proxy))
            .await
            .unwrap();
        match result {
            ResolvedRelay::Hostname { host, port } => {
                assert_eq!(host, "relay.example.com");
                assert_eq!(port, 4433);
            }
            ResolvedRelay::Addr { .. } => {
                panic!("expected Hostname for Tor mode, got Addr");
            }
        }
    }

    #[test]
    fn test_parse_host_port_standard() {
        let (host, port) = parse_host_port("relay.example.com:4433").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 4433);
    }

    #[test]
    fn test_parse_host_port_subdomain() {
        let (host, port) = parse_host_port("sub.domain.example.com:4433").unwrap();
        assert_eq!(host, "sub.domain.example.com");
        assert_eq!(port, 4433);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:4433").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 4433);
    }

    #[test]
    fn test_parse_host_port_missing_port() {
        let result = parse_host_port("relay.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        let result = parse_host_port("relay.example.com:abc");
        assert!(result.is_err());
    }

    // Note: test_resolve_hostname_no_proxy_uses_system is #[ignore] because
    // it requires a real working DNS resolver which may not be available in CI.
    #[tokio::test]
    #[ignore]
    async fn test_resolve_hostname_no_proxy_uses_system() {
        let result = resolve_relay_proxy("dns.google:443", None).await;
        assert!(result.is_ok());
        match result.unwrap() {
            ResolvedRelay::Addr { addr, .. } => {
                assert_eq!(addr.port(), 443);
            }
            ResolvedRelay::Hostname { .. } => {
                panic!("expected Addr from system DNS resolution");
            }
        }
    }

    // Note: test_resolve_hostname_generic_proxy is #[ignore] because it
    // requires real DNS-over-HTTPS connectivity.
    #[tokio::test]
    #[ignore]
    async fn test_resolve_hostname_generic_proxy_uses_doh() {
        let proxy = ProxyConfig {
            socks5_addr: "127.0.0.1:1080".parse().unwrap(),
            tor_mode: false,
            auth: None,
        };
        let result = resolve_relay_proxy("dns.google:443", Some(&proxy)).await;
        assert!(result.is_ok());
        match result.unwrap() {
            ResolvedRelay::Addr { addr, .. } => {
                assert_eq!(addr.port(), 443);
            }
            ResolvedRelay::Hostname { .. } => {
                panic!("expected Addr from DoH resolution");
            }
        }
    }
}
