//! DNS Service Discovery records

use std::collections::HashMap;
use std::net::SocketAddr;

/// DNS-SD service record
#[derive(Debug, Clone)]
pub struct DnsServiceRecord {
    /// Service instance name
    pub instance: String,
    /// Service type (e.g., "_tallow._tcp")
    pub service_type: String,
    /// Domain
    pub domain: String,
    /// Target address
    pub addr: SocketAddr,
    /// TXT record attributes
    pub attributes: HashMap<String, String>,
}

impl DnsServiceRecord {
    /// Create a new service record
    pub fn new(instance: String, service_type: String, domain: String, addr: SocketAddr) -> Self {
        Self {
            instance,
            service_type,
            domain,
            addr,
            attributes: HashMap::new(),
        }
    }

    /// Add a TXT record attribute
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }
}
