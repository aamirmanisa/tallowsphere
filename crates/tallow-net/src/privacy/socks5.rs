//! SOCKS5 proxy connector using tokio-socks

use crate::error::NetworkError;
use crate::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Proxy configuration for routing relay connections through SOCKS5
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// SOCKS5 proxy address
    pub socks5_addr: SocketAddr,
    /// Whether this is a Tor proxy (affects DNS resolution strategy)
    pub tor_mode: bool,
    /// Optional proxy authentication
    pub auth: Option<ProxyAuth>,
}

/// Authentication credentials for a SOCKS5 proxy
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    /// Username for proxy authentication
    pub username: String,
    /// Password for proxy authentication
    pub password: String,
}

impl ProxyConfig {
    /// Parse a SOCKS5 proxy URL
    ///
    /// Accepted formats:
    /// - `socks5://host:port`
    /// - `socks5h://host:port` (DNS resolved by proxy)
    /// - `socks5://user:pass@host:port`
    /// - `host:port` (no scheme)
    pub fn from_url(url: &str) -> Result<Self> {
        // Strip scheme prefix
        let (is_socks5h, remainder) = if let Some(r) = url.strip_prefix("socks5h://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("socks5://") {
            (false, r)
        } else {
            (false, url)
        };

        // Check for user:pass@host:port
        let (auth, addr_str) = if let Some(at_pos) = remainder.rfind('@') {
            let cred_str = &remainder[..at_pos];
            let addr_part = &remainder[at_pos + 1..];
            // Split credentials on first ':'
            if let Some(colon_pos) = cred_str.find(':') {
                let username = cred_str[..colon_pos].to_string();
                let password = cred_str[colon_pos + 1..].to_string();
                (Some(ProxyAuth { username, password }), addr_part)
            } else {
                // Username only, no password
                (
                    Some(ProxyAuth {
                        username: cred_str.to_string(),
                        password: String::new(),
                    }),
                    addr_part,
                )
            }
        } else {
            (None, remainder)
        };

        let addr: SocketAddr = addr_str.parse().map_err(|e| {
            NetworkError::ConnectionFailed(format!(
                "Invalid SOCKS5 proxy address '{}': {}",
                addr_str, e
            ))
        })?;

        // socks5h scheme implies DNS via proxy (Tor-like behavior)
        let tor_mode = is_socks5h;

        Ok(Self {
            socks5_addr: addr,
            tor_mode,
            auth,
        })
    }

    /// Create a ProxyConfig for Tor's default SOCKS5 port (127.0.0.1:9050)
    pub fn tor_default() -> Self {
        Self {
            socks5_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            tor_mode: true,
            auth: None,
        }
    }

    /// Create a `Socks5Connector` from this config
    pub fn to_connector(&self) -> Socks5Connector {
        let mut connector = Socks5Connector::new(self.socks5_addr);
        if let Some(ref auth) = self.auth {
            connector = connector.with_auth(auth.username.clone(), auth.password.clone());
        }
        connector
    }
}

/// SOCKS5 proxy connector for Tor integration
#[derive(Debug, Clone)]
pub struct Socks5Connector {
    /// Proxy address (e.g., 127.0.0.1:9050 for Tor)
    proxy_addr: SocketAddr,
    /// Optional username for authentication
    username: Option<String>,
    /// Optional password for authentication
    password: Option<String>,
}

impl Socks5Connector {
    /// Create a new SOCKS5 connector
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            username: None,
            password: None,
        }
    }

    /// Parse a proxy URL (e.g., "socks5://127.0.0.1:9050")
    ///
    /// Supports optional authentication: `socks5://user:pass@host:port`
    pub fn from_url(url: &str) -> Result<Self> {
        let remainder = url
            .strip_prefix("socks5://")
            .or_else(|| url.strip_prefix("socks5h://"))
            .unwrap_or(url);

        // Check for user:pass@host:port
        if let Some(at_pos) = remainder.rfind('@') {
            let cred_str = &remainder[..at_pos];
            let addr_str = &remainder[at_pos + 1..];

            let addr: SocketAddr = addr_str.parse().map_err(|e| {
                NetworkError::ConnectionFailed(format!(
                    "Invalid SOCKS5 proxy address '{}': {}",
                    addr_str, e
                ))
            })?;

            let mut connector = Self::new(addr);
            if let Some(colon_pos) = cred_str.find(':') {
                connector.username = Some(cred_str[..colon_pos].to_string());
                connector.password = Some(cred_str[colon_pos + 1..].to_string());
            }
            return Ok(connector);
        }

        let addr: SocketAddr = remainder.parse().map_err(|e| {
            NetworkError::ConnectionFailed(format!(
                "Invalid SOCKS5 proxy address '{}': {}",
                remainder, e
            ))
        })?;

        Ok(Self::new(addr))
    }

    /// Set authentication credentials
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    /// Connect to a target address through the SOCKS5 proxy
    ///
    /// **WARNING**: This method takes a pre-resolved `SocketAddr`, meaning
    /// DNS resolution already happened on the local machine. For Tor usage,
    /// prefer [`connect_hostname`] which sends the hostname to the proxy so
    /// DNS resolution happens inside the Tor network (no DNS leak).
    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream> {
        let stream = if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            Socks5Stream::connect_with_password(self.proxy_addr, target, user, pass)
                .await
                .map_err(|e| {
                    NetworkError::ConnectionFailed(format!(
                        "SOCKS5 connection to {} via {} failed: {}",
                        target, self.proxy_addr, e
                    ))
                })?
        } else {
            Socks5Stream::connect(self.proxy_addr, target)
                .await
                .map_err(|e| {
                    NetworkError::ConnectionFailed(format!(
                        "SOCKS5 connection to {} via {} failed: {}",
                        target, self.proxy_addr, e
                    ))
                })?
        };

        Ok(stream.into_inner())
    }

    /// Connect to a hostname through the SOCKS5 proxy (DNS resolved by proxy)
    ///
    /// This is the preferred mode for Tor — the hostname is sent to the proxy
    /// so DNS resolution happens inside the Tor network.
    pub async fn connect_hostname(&self, host: &str, port: u16) -> Result<TcpStream> {
        let target = (host, port);

        let stream = if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            Socks5Stream::connect_with_password(self.proxy_addr, target, user, pass)
                .await
                .map_err(|e| {
                    NetworkError::ConnectionFailed(format!(
                        "SOCKS5 connection to {}:{} via {} failed: {}",
                        host, port, self.proxy_addr, e
                    ))
                })?
        } else {
            Socks5Stream::connect(self.proxy_addr, target)
                .await
                .map_err(|e| {
                    NetworkError::ConnectionFailed(format!(
                        "SOCKS5 connection to {}:{} via {} failed: {}",
                        host, port, self.proxy_addr, e
                    ))
                })?
        };

        Ok(stream.into_inner())
    }

    /// Get the proxy address
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_url() {
        let conn = Socks5Connector::from_url("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(conn.proxy_addr.port(), 9050);
    }

    #[test]
    fn test_from_url_no_prefix() {
        let conn = Socks5Connector::from_url("127.0.0.1:1080").unwrap();
        assert_eq!(conn.proxy_addr.port(), 1080);
    }

    #[test]
    fn test_from_url_with_auth() {
        let conn = Socks5Connector::from_url("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(conn.proxy_addr.port(), 1080);
        assert_eq!(conn.username.as_deref(), Some("user"));
        assert_eq!(conn.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_with_auth() {
        let conn = Socks5Connector::new("127.0.0.1:9050".parse().unwrap())
            .with_auth("user".to_string(), "pass".to_string());
        assert!(conn.username.is_some());
        assert!(conn.password.is_some());
    }

    // --- ProxyConfig tests ---

    #[test]
    fn test_proxy_config_from_url_basic() {
        let cfg = ProxyConfig::from_url("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(cfg.socks5_addr.port(), 9050);
        assert!(!cfg.tor_mode);
        assert!(cfg.auth.is_none());
    }

    #[test]
    fn test_proxy_config_from_url_with_auth() {
        let cfg = ProxyConfig::from_url("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(cfg.socks5_addr.port(), 1080);
        assert!(!cfg.tor_mode);
        let auth = cfg.auth.unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn test_proxy_config_from_url_socks5h() {
        let cfg = ProxyConfig::from_url("socks5h://127.0.0.1:9050").unwrap();
        assert_eq!(cfg.socks5_addr.port(), 9050);
        assert!(cfg.tor_mode);
    }

    #[test]
    fn test_proxy_config_from_url_no_scheme() {
        let cfg = ProxyConfig::from_url("127.0.0.1:1080").unwrap();
        assert_eq!(cfg.socks5_addr.port(), 1080);
        assert!(!cfg.tor_mode);
        assert!(cfg.auth.is_none());
    }

    #[test]
    fn test_proxy_config_tor_default() {
        let cfg = ProxyConfig::tor_default();
        assert_eq!(cfg.socks5_addr, SocketAddr::from(([127, 0, 0, 1], 9050)));
        assert!(cfg.tor_mode);
        assert!(cfg.auth.is_none());
    }

    #[test]
    fn test_to_connector_with_auth() {
        let cfg = ProxyConfig {
            socks5_addr: "127.0.0.1:1080".parse().unwrap(),
            tor_mode: false,
            auth: Some(ProxyAuth {
                username: "test_user".to_string(),
                password: "test_pass".to_string(),
            }),
        };
        let conn = cfg.to_connector();
        assert_eq!(conn.proxy_addr.port(), 1080);
        assert_eq!(conn.username.as_deref(), Some("test_user"));
        assert_eq!(conn.password.as_deref(), Some("test_pass"));
    }

    #[test]
    fn test_to_connector_without_auth() {
        let cfg = ProxyConfig::tor_default();
        let conn = cfg.to_connector();
        assert_eq!(conn.proxy_addr.port(), 9050);
        assert!(conn.username.is_none());
        assert!(conn.password.is_none());
    }
}
