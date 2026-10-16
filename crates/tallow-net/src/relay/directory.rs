//! Relay server directory and discovery
//!
//! Manages a list of relay servers with latency probing to select the
//! lowest-latency relay for a given transfer.

use crate::Result;
use std::net::SocketAddr;
use std::time::Duration;

/// Relay server information
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// Server address
    pub addr: SocketAddr,
    /// Geographic region
    pub region: String,
    /// Latency probe result
    pub latency: Option<Duration>,
}

/// Directory of available relay servers
#[derive(Debug)]
pub struct RelayDirectory {
    /// Known relay servers
    relays: Vec<RelayInfo>,
}

impl RelayDirectory {
    /// Create a new empty relay directory
    pub fn new() -> Self {
        Self { relays: Vec::new() }
    }

    /// Create a directory with pre-configured relays
    pub fn with_relays(relays: Vec<RelayInfo>) -> Self {
        Self { relays }
    }

    /// Add a relay server to the directory
    pub fn add_relay(&mut self, info: RelayInfo) {
        self.relays.push(info);
    }

    /// Fetch relay list from a directory service URL.
    ///
    /// In v1, this populates from a hardcoded default if no relays are
    /// configured. A future version will fetch from a directory service.
    pub async fn fetch_relays(&mut self) -> Result<()> {
        // In v1, if no relays are configured, we don't have a directory
        // service to fetch from. The user must specify a relay via CLI.
        if self.relays.is_empty() {
            tracing::info!(
                "No relay directory service configured; use --relay to specify a server"
            );
        }
        Ok(())
    }

    /// Probe latency to all relays using a TCP connect measurement.
    ///
    /// Measures round-trip time by timing a TCP connection attempt to each
    /// relay's address.
    pub async fn probe_latency(&mut self) -> Result<()> {
        for relay in &mut self.relays {
            let start = std::time::Instant::now();
            match tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(relay.addr),
            )
            .await
            {
                Ok(Ok(_stream)) => {
                    relay.latency = Some(start.elapsed());
                    tracing::debug!(
                        "Relay {} latency: {:?}",
                        relay.addr,
                        relay.latency.unwrap_or_default()
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!("Relay {} probe failed: {}", relay.addr, e);
                    relay.latency = None;
                }
                Err(_) => {
                    tracing::warn!("Relay {} probe timed out", relay.addr);
                    relay.latency = None;
                }
            }
        }

        // Sort by latency (None = unreachable, pushed to end)
        self.relays.sort_by(|a, b| match (&a.latency, &b.latency) {
            (Some(la), Some(lb)) => la.cmp(lb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        Ok(())
    }

    /// Get best relay by latency (lowest latency first)
    pub fn best_relay(&self) -> Option<&RelayInfo> {
        self.relays.first()
    }

    /// Get all known relays
    pub fn relays(&self) -> &[RelayInfo] {
        &self.relays
    }

    /// Get the number of reachable relays
    pub fn reachable_count(&self) -> usize {
        self.relays.iter().filter(|r| r.latency.is_some()).count()
    }
}

impl Default for RelayDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_directory() {
        let dir = RelayDirectory::new();
        assert!(dir.relays().is_empty());
        assert!(dir.best_relay().is_none());
    }

    #[test]
    fn test_add_relay() {
        let mut dir = RelayDirectory::new();
        dir.add_relay(RelayInfo {
            addr: "127.0.0.1:4433".parse().unwrap(),
            region: "local".to_string(),
            latency: Some(Duration::from_millis(5)),
        });
        assert_eq!(dir.relays().len(), 1);
        assert!(dir.best_relay().is_some());
    }

    #[test]
    fn test_with_relays() {
        let relays = vec![
            RelayInfo {
                addr: "1.2.3.4:4433".parse().unwrap(),
                region: "us-east".to_string(),
                latency: Some(Duration::from_millis(50)),
            },
            RelayInfo {
                addr: "5.6.7.8:4433".parse().unwrap(),
                region: "eu-west".to_string(),
                latency: Some(Duration::from_millis(100)),
            },
        ];
        let dir = RelayDirectory::with_relays(relays);
        assert_eq!(dir.relays().len(), 2);
    }

    #[test]
    fn test_reachable_count() {
        let relays = vec![
            RelayInfo {
                addr: "1.2.3.4:4433".parse().unwrap(),
                region: "us".to_string(),
                latency: Some(Duration::from_millis(10)),
            },
            RelayInfo {
                addr: "5.6.7.8:4433".parse().unwrap(),
                region: "eu".to_string(),
                latency: None,
            },
        ];
        let dir = RelayDirectory::with_relays(relays);
        assert_eq!(dir.reachable_count(), 1);
    }
}
