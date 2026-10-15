//! Integration tests for proxy configuration and DNS resolution
//!
//! Tests the proxy-aware relay resolution pipeline and ProxyConfig construction.
//! These tests do NOT require a running SOCKS5 proxy -- they verify the decision
//! logic (which branch is taken) rather than actual network connectivity.

use tallow_net::privacy::{ProxyAuth, ProxyConfig};
use tallow_net::relay::{resolve_relay_proxy, ResolvedRelay};

#[tokio::test]
async fn test_ip_literal_bypasses_dns_without_proxy() {
    let result = resolve_relay_proxy("18.119.135.151:4433", None)
        .await
        .unwrap();
    match result {
        ResolvedRelay::Addr { addr, .. } => {
            assert_eq!(addr.ip().to_string(), "18.119.135.151");
            assert_eq!(addr.port(), 4433);
        }
        ResolvedRelay::Hostname { .. } => {
            panic!("expected Addr for IP literal, got Hostname");
        }
    }
}

#[tokio::test]
async fn test_ip_literal_bypasses_dns_with_tor_proxy() {
    let proxy = ProxyConfig::tor_default();
    let result = resolve_relay_proxy("18.119.135.151:4433", Some(&proxy))
        .await
        .unwrap();
    match result {
        ResolvedRelay::Addr { addr, .. } => {
            assert_eq!(addr.ip().to_string(), "18.119.135.151");
            assert_eq!(addr.port(), 4433);
        }
        ResolvedRelay::Hostname { .. } => {
            panic!("IP literal should always resolve to Addr, even with Tor proxy");
        }
    }
}

#[tokio::test]
async fn test_hostname_with_tor_returns_hostname_for_proxy_resolution() {
    let proxy = ProxyConfig::tor_default();
    let result = resolve_relay_proxy("relay.tallow.app:4433", Some(&proxy))
        .await
        .unwrap();
    match result {
        ResolvedRelay::Hostname { host, port } => {
            assert_eq!(host, "relay.tallow.app");
            assert_eq!(port, 4433);
        }
        ResolvedRelay::Addr { .. } => {
            panic!("Tor mode should return Hostname for proxy-side DNS resolution");
        }
    }
}

#[tokio::test]
async fn test_proxy_config_from_url_socks5() {
    let cfg = ProxyConfig::from_url("socks5://10.0.0.1:1080").unwrap();
    assert_eq!(cfg.socks5_addr.ip().to_string(), "10.0.0.1");
    assert_eq!(cfg.socks5_addr.port(), 1080);
    assert!(!cfg.tor_mode);
    assert!(cfg.auth.is_none());
}

#[tokio::test]
async fn test_proxy_config_from_url_socks5h_sets_tor_mode() {
    let cfg = ProxyConfig::from_url("socks5h://127.0.0.1:9050").unwrap();
    assert!(cfg.tor_mode, "socks5h:// scheme should set tor_mode = true");
}

#[tokio::test]
async fn test_proxy_config_from_url_with_auth() {
    let cfg = ProxyConfig::from_url("socks5://user:p4ssw0rd@10.0.0.1:1080").unwrap();
    assert_eq!(cfg.socks5_addr.port(), 1080);
    let auth = cfg.auth.as_ref().expect("auth should be set");
    assert_eq!(auth.username, "user");
    assert_eq!(auth.password, "p4ssw0rd");
}

#[tokio::test]
async fn test_proxy_config_tor_default() {
    let cfg = ProxyConfig::tor_default();
    assert!(cfg.tor_mode);
    assert_eq!(cfg.socks5_addr.port(), 9050);
    assert!(cfg.socks5_addr.ip().is_loopback());
    assert!(cfg.auth.is_none());
}

#[tokio::test]
async fn test_proxy_config_to_connector() {
    let cfg = ProxyConfig {
        socks5_addr: "127.0.0.1:1080".parse().unwrap(),
        tor_mode: false,
        auth: Some(ProxyAuth {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        }),
    };
    let connector = cfg.to_connector();
    assert_eq!(connector.proxy_addr().port(), 1080);
}

#[tokio::test]
async fn test_proxy_config_invalid_url_returns_error() {
    let result = ProxyConfig::from_url("not-a-valid-proxy");
    assert!(result.is_err(), "invalid URL should return error");
}

#[tokio::test]
async fn test_resolve_missing_port_returns_error() {
    let result = resolve_relay_proxy("relay.example.com", None).await;
    assert!(
        result.is_err(),
        "relay address without port should return error"
    );
}

#[tokio::test]
async fn test_resolve_ipv6_literal() {
    let result = resolve_relay_proxy("[::1]:4433", None).await.unwrap();
    match result {
        ResolvedRelay::Addr { addr, .. } => {
            assert_eq!(addr.port(), 4433);
        }
        ResolvedRelay::Hostname { .. } => {
            panic!("IPv6 literal should resolve to Addr");
        }
    }
}

#[tokio::test]
async fn test_resolve_ipv6_bracket_with_tor_proxy() {
    // IPv6 literal should be treated as IP literal even with Tor proxy
    let proxy = ProxyConfig::tor_default();
    let result = resolve_relay_proxy("[::1]:4433", Some(&proxy))
        .await
        .unwrap();
    match result {
        ResolvedRelay::Addr { addr, .. } => {
            assert_eq!(addr.port(), 4433);
        }
        ResolvedRelay::Hostname { .. } => {
            panic!("IPv6 literal should be treated as IP literal, not hostname");
        }
    }
}
