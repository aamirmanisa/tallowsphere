//! mDNS-based local network discovery
//!
//! Uses mdns-sd to advertise and discover Tallow peers on the local network.
//! Service type: _tallow._tcp.local.

use crate::error::NetworkError;
use crate::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Tallow mDNS service type
const SERVICE_TYPE: &str = "_tallow._tcp.local.";

/// mDNS peer discovery
pub struct MdnsDiscovery {
    service_name: String,
    peers: Arc<Mutex<Vec<DiscoveredPeer>>>,
    daemon: Option<ServiceDaemon>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl std::fmt::Debug for MdnsDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsDiscovery")
            .field("service_name", &self.service_name)
            .field("peers", &self.peers)
            .field("daemon", &self.daemon.as_ref().map(|_| "ServiceDaemon"))
            .field("shutdown_tx", &self.shutdown_tx)
            .finish()
    }
}

/// Discovered peer information
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Peer identifier
    pub id: String,
    /// Peer address
    pub addr: SocketAddr,
    /// Device name
    pub name: String,
    /// Peer fingerprint (if advertised)
    pub fingerprint: Option<String>,
}

impl MdnsDiscovery {
    /// Create a new mDNS discovery instance
    pub fn new(service_name: String) -> Self {
        Self {
            service_name,
            peers: Arc::new(Mutex::new(Vec::new())),
            daemon: None,
            shutdown_tx: None,
        }
    }

    /// Register this device as a Tallow peer on the local network
    pub fn advertise(&mut self, port: u16, fingerprint: &str) -> Result<()> {
        let daemon = ServiceDaemon::new().map_err(|e| {
            NetworkError::DiscoveryError(format!("Failed to create mDNS daemon: {}", e))
        })?;

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "tallow-peer".to_string());

        let mut properties = HashMap::new();
        properties.insert("fp".to_string(), fingerprint.to_string());
        properties.insert("v".to_string(), "1".to_string());

        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &self.service_name,
            &format!("{}.", hostname),
            "",
            port,
            properties,
        )
        .map_err(|e| {
            NetworkError::DiscoveryError(format!("Failed to create service info: {}", e))
        })?;

        daemon.register(service).map_err(|e| {
            NetworkError::DiscoveryError(format!("Failed to register service: {}", e))
        })?;

        self.daemon = Some(daemon);
        Ok(())
    }

    /// Start browsing for Tallow peers on the local network
    pub fn start(&mut self) -> Result<()> {
        let daemon = if let Some(ref d) = self.daemon {
            d.clone()
        } else {
            let d = ServiceDaemon::new().map_err(|e| {
                NetworkError::DiscoveryError(format!("Failed to create mDNS daemon: {}", e))
            })?;
            self.daemon = Some(d.clone());
            d
        };

        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| NetworkError::DiscoveryError(format!("Failed to start browse: {}", e)))?;

        let peers = Arc::clone(&self.peers);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn background thread to process mDNS events
        std::thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                // Use a short sleep + try_recv pattern instead of recv_timeout
                // to avoid depending on the channel's exact error type
                std::thread::sleep(std::time::Duration::from_millis(200));
                while let Ok(event) = receiver.try_recv() {
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            let addresses = info.get_addresses();
                            if let Some(addr) = addresses.iter().next() {
                                let peer = DiscoveredPeer {
                                    id: info.get_fullname().to_string(),
                                    addr: SocketAddr::new(*addr, info.get_port()),
                                    name: info.get_hostname().to_string(),
                                    fingerprint: info
                                        .get_properties()
                                        .get_property_val_str("fp")
                                        .map(|s| s.to_string()),
                                };

                                let mut guard = peers.lock().unwrap_or_else(|e| e.into_inner());
                                if !guard.iter().any(|p| p.id == peer.id) {
                                    guard.push(peer);
                                }
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            let mut guard = peers.lock().unwrap_or_else(|e| e.into_inner());
                            guard.retain(|p| p.id != fullname);
                        }
                        _ => {}
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop discovery and unregister
    pub fn stop(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }

        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.shutdown();
        }

        Ok(())
    }

    /// Get discovered peers
    pub fn discovered_peers(&self) -> Vec<DiscoveredPeer> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
