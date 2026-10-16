//! IPv6 address pool management and mobile proxy rotation.
//!
//! Two capabilities:
//!
//! 1. **IPv6 Pool** — Generate random addresses within a /48 or /64 prefix.
//!    A /48 gives 2^80 unique addresses, making IP-based blocking nearly
//!    impossible.  China alone has 600M+ IPv6 users; a single /48 allocation
//!    dwarfs any blocklist.
//!
//! 2. **Mobile Proxy Rotation** — Manage mobile proxy endpoints with automatic
//!    IP rotation via HTTP endpoint, AT modem commands, or ADB airplane-mode
//!    toggle.  Mobile carrier IPs (CGNAT) are the highest-trust proxy type —
//!    anti-bot systems cannot block them without blocking real users.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rand::Rng;

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 Prefix
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed IPv6 network prefix (e.g. `2001:db8:1234::/48`).
#[derive(Debug, Clone)]
pub struct Ipv6Prefix {
    /// Base network address in big-endian byte order.
    network: [u8; 16],
    /// Prefix length: 48 or 64 are the expected values, but any 0-128 works.
    prefix_len: u8,
}

impl Ipv6Prefix {
    /// Parse a prefix string like `"2001:db8:1234::/48"`.
    pub fn parse(s: &str) -> Result<Self, Ipv6ParseError> {
        let (addr_part, len_part) = s
            .rsplit_once('/')
            .ok_or_else(|| Ipv6ParseError(format!("missing /prefix_len in '{s}'")))?;

        let prefix_len: u8 = len_part
            .parse()
            .map_err(|_| Ipv6ParseError(format!("invalid prefix length '{len_part}'")))?;

        if prefix_len > 128 {
            return Err(Ipv6ParseError(format!(
                "prefix length {prefix_len} exceeds 128"
            )));
        }

        let network = parse_ipv6_addr(addr_part)?;

        // Zero out the host bits in the base address.
        let mut masked = network;
        for bit in prefix_len..128 {
            let byte_idx = (bit / 8) as usize;
            let bit_idx = 7 - (bit % 8);
            masked[byte_idx] &= !(1 << bit_idx);
        }

        Ok(Self {
            network: masked,
            prefix_len,
        })
    }

    /// How many host bits are available for randomization.
    pub fn host_bits(&self) -> u32 {
        128 - self.prefix_len as u32
    }

    /// Theoretical pool size (2^host_bits).  Returns `u128::MAX` when
    /// host_bits >= 128 to avoid overflow.
    pub fn pool_size(&self) -> u128 {
        let bits = self.host_bits();
        if bits >= 128 {
            u128::MAX
        } else {
            1u128 << bits
        }
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = format_ipv6(&self.network);
        write!(f, "{addr}/{}", self.prefix_len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 Pool
// ─────────────────────────────────────────────────────────────────────────────

/// IPv6 address pool backed by a prefix.
///
/// Generates random addresses within the prefix and tracks a cooldown window
/// so the same address is not reused too quickly.
pub struct Ipv6Pool {
    prefix: Ipv6Prefix,
    generated_count: AtomicU64,
    /// Maps address string → last-used instant.
    used_addresses: DashMap<String, Instant>,
    cooldown: Duration,
}

impl Ipv6Pool {
    /// Create a pool from a prefix string like `"2001:db8:1234::/48"`.
    pub fn from_prefix(prefix_str: &str) -> Result<Self, Ipv6ParseError> {
        let prefix = Ipv6Prefix::parse(prefix_str)?;
        Ok(Self {
            prefix,
            generated_count: AtomicU64::new(0),
            used_addresses: DashMap::new(),
            cooldown: Duration::from_secs(300), // 5 min default
        })
    }

    /// Create a pool with a custom cooldown duration.
    pub fn with_cooldown(prefix_str: &str, cooldown: Duration) -> Result<Self, Ipv6ParseError> {
        let mut pool = Self::from_prefix(prefix_str)?;
        pool.cooldown = cooldown;
        Ok(pool)
    }

    /// Generate a random IPv6 address within the prefix.
    pub fn next_address(&self) -> String {
        let mut rng = rand::rng();
        let mut bytes = self.prefix.network;

        // Randomize host bits.
        let prefix_len = self.prefix.prefix_len;
        for bit in prefix_len..128 {
            let byte_idx = (bit / 8) as usize;
            let bit_idx = 7 - (bit % 8);
            if rng.random_bool(0.5) {
                bytes[byte_idx] |= 1 << bit_idx;
            } else {
                bytes[byte_idx] &= !(1 << bit_idx);
            }
        }

        self.generated_count.fetch_add(1, Ordering::Relaxed);
        format_ipv6(&bytes)
    }

    /// Generate `count` unique addresses.
    pub fn generate_batch(&self, count: usize) -> Vec<String> {
        let mut rng = rand::rng();
        let mut out = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::with_capacity(count);

        while out.len() < count {
            let mut bytes = self.prefix.network;
            let prefix_len = self.prefix.prefix_len;
            for bit in prefix_len..128 {
                let byte_idx = (bit / 8) as usize;
                let bit_idx = 7 - (bit % 8);
                if rng.random_bool(0.5) {
                    bytes[byte_idx] |= 1 << bit_idx;
                } else {
                    bytes[byte_idx] &= !(1 << bit_idx);
                }
            }

            let addr = format_ipv6(&bytes);
            if seen.insert(addr.clone()) {
                out.push(addr);
            }
        }

        self.generated_count
            .fetch_add(count as u64, Ordering::Relaxed);
        out
    }

    /// Check if an address is available (not in cooldown).
    pub fn is_available(&self, addr: &str) -> bool {
        match self.used_addresses.get(addr) {
            Some(entry) => entry.value().elapsed() >= self.cooldown,
            None => true,
        }
    }

    /// Mark an address as used (starts cooldown).
    pub fn mark_used(&self, addr: &str) {
        self.used_addresses.insert(addr.to_string(), Instant::now());
    }

    /// Theoretical pool size.
    pub fn pool_size(&self) -> u128 {
        self.prefix.pool_size()
    }

    /// Snapshot statistics.
    pub fn stats(&self) -> Ipv6PoolStats {
        Ipv6PoolStats {
            prefix: self.prefix.to_string(),
            prefix_len: self.prefix.prefix_len,
            theoretical_size: self.prefix.pool_size(),
            generated_count: self.generated_count.load(Ordering::Relaxed),
            active_cooldowns: self
                .used_addresses
                .iter()
                .filter(|e| e.value().elapsed() < self.cooldown)
                .count(),
        }
    }

    /// Evict expired cooldown entries to reclaim memory.
    pub fn cleanup(&self) {
        self.used_addresses
            .retain(|_, ts| ts.elapsed() < self.cooldown);
    }
}

/// Statistics for an `Ipv6Pool`.
#[derive(Debug, Clone)]
pub struct Ipv6PoolStats {
    pub prefix: String,
    pub prefix_len: u8,
    pub theoretical_size: u128,
    pub generated_count: u64,
    pub active_cooldowns: usize,
}

impl fmt::Display for Ipv6PoolStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "IPv6 Pool: {}", self.prefix)?;
        writeln!(f, "  Prefix length:     /{}", self.prefix_len)?;
        writeln!(f, "  Theoretical size:  2^{}", 128 - self.prefix_len)?;
        writeln!(f, "  Generated:         {}", self.generated_count)?;
        write!(f, "  Active cooldowns:  {}", self.active_cooldowns)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mobile Proxy Rotation
// ─────────────────────────────────────────────────────────────────────────────

/// A single mobile proxy endpoint with IP rotation capability.
#[derive(Debug, Clone)]
pub struct MobileEndpoint {
    /// SOCKS5 or HTTP proxy URL (e.g. `socks5://host:port`).
    pub proxy_url: String,
    /// Mobile carrier name (e.g. "t-mobile", "att", "verizon").
    pub carrier: String,
    /// How to trigger an IP rotation on this endpoint.
    pub rotation_method: RotationMethod,
    /// Last time the IP was rotated.
    pub last_rotation: Option<Instant>,
    /// Minimum interval between rotations (carrier-dependent).
    pub min_rotation_interval: Duration,
    /// The IP address currently assigned (populated after rotation check).
    pub current_ip: Option<String>,
    /// Total rotations performed.
    pub rotation_count: u64,
}

impl MobileEndpoint {
    /// Whether enough time has passed to allow another rotation.
    pub fn can_rotate(&self) -> bool {
        match self.last_rotation {
            Some(t) => t.elapsed() >= self.min_rotation_interval,
            None => true,
        }
    }
}

/// Method used to trigger an IP rotation on a mobile proxy.
#[derive(Debug, Clone)]
pub enum RotationMethod {
    /// Call an HTTP endpoint to trigger rotation (most proxy services).
    HttpEndpoint {
        url: String,
        method: String, // "GET" or "POST"
    },
    /// Send AT commands via serial port (physical modem farms).
    /// `AT+CFUN=0` (radio off) then `AT+CFUN=1` (radio on).
    AtCommand { port: String },
    /// Toggle airplane mode via ADB (Android phone farms).
    AdbAirplaneMode { device_id: String },
    /// No explicit rotation — IP changes naturally via carrier CGNAT.
    Natural,
}

/// Strategy governing when mobile proxy IPs are rotated.
#[derive(Debug, Clone)]
pub enum MobileRotationStrategy {
    /// Rotate before each request.
    PerRequest,
    /// Rotate every N duration.
    Timed(Duration),
    /// Rotate after N requests through the endpoint.
    AfterRequests(u32),
    /// Rotate only when a block/captcha is detected (reactive).
    OnBlock,
}

/// Manages a fleet of mobile proxy endpoints with rotation.
pub struct MobileProxyManager {
    endpoints: Vec<MobileEndpoint>,
    rotation_strategy: MobileRotationStrategy,
    /// Round-robin index for endpoint selection.
    next_index: usize,
    /// Per-endpoint request counter (for `AfterRequests` strategy).
    request_counts: Vec<u32>,
}

impl MobileProxyManager {
    /// Create an empty manager with the default `OnBlock` strategy.
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            rotation_strategy: MobileRotationStrategy::OnBlock,
            next_index: 0,
            request_counts: Vec::new(),
        }
    }

    /// Create a manager with a specific rotation strategy.
    pub fn with_strategy(strategy: MobileRotationStrategy) -> Self {
        Self {
            endpoints: Vec::new(),
            rotation_strategy: strategy,
            next_index: 0,
            request_counts: Vec::new(),
        }
    }

    /// Add a mobile endpoint.
    pub fn add_endpoint(&mut self, endpoint: MobileEndpoint) {
        self.endpoints.push(endpoint);
        self.request_counts.push(0);
    }

    /// Number of registered endpoints.
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Get the next proxy URL, potentially triggering a rotation based on
    /// the current strategy.  Returns `Err` if no endpoints are configured.
    pub async fn next_proxy(&mut self) -> Result<String, MobileProxyError> {
        if self.endpoints.is_empty() {
            return Err(MobileProxyError("no mobile endpoints configured".into()));
        }

        let idx = self.next_index % self.endpoints.len();
        self.next_index = idx + 1;
        self.request_counts[idx] += 1;

        let needs_rotation = match &self.rotation_strategy {
            MobileRotationStrategy::PerRequest => true,
            MobileRotationStrategy::Timed(interval) => self.endpoints[idx]
                .last_rotation
                .map(|t| t.elapsed() >= *interval)
                .unwrap_or(true),
            MobileRotationStrategy::AfterRequests(n) => self.request_counts[idx] >= *n,
            MobileRotationStrategy::OnBlock => false, // caller triggers manually
        };

        if needs_rotation && self.endpoints[idx].can_rotate() {
            self.rotate(idx).await?;
            self.request_counts[idx] = 0;
        }

        Ok(self.endpoints[idx].proxy_url.clone())
    }

    /// Force-rotate a specific endpoint.  Returns the proxy URL.
    pub async fn rotate(&mut self, index: usize) -> Result<String, MobileProxyError> {
        if index >= self.endpoints.len() {
            return Err(MobileProxyError(format!(
                "endpoint index {index} out of range (have {})",
                self.endpoints.len()
            )));
        }

        let endpoint = &mut self.endpoints[index];

        if !endpoint.can_rotate() {
            // Not enough time since last rotation — skip silently.
            return Ok(endpoint.proxy_url.clone());
        }

        match &endpoint.rotation_method {
            RotationMethod::HttpEndpoint { url, method } => {
                rotate_via_http(url, method).await?;
                // Wait for carrier to assign a new IP.
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            RotationMethod::AtCommand { port } => {
                rotate_via_at_command(port).await?;
                // Modem reconnection takes longer.
                tokio::time::sleep(Duration::from_secs(8)).await;
            }
            RotationMethod::AdbAirplaneMode { device_id } => {
                rotate_via_adb(device_id).await?;
                // Airplane mode cycle: 3s off + 8s reconnect.
                tokio::time::sleep(Duration::from_secs(11)).await;
            }
            RotationMethod::Natural => {
                // Nothing to do — IP changes on its own.
            }
        }

        endpoint.last_rotation = Some(Instant::now());
        endpoint.rotation_count += 1;
        endpoint.current_ip = None; // invalidated — caller should re-check

        Ok(endpoint.proxy_url.clone())
    }

    /// Rotate all endpoints that are eligible.
    pub async fn rotate_all(&mut self) -> Vec<Result<String, MobileProxyError>> {
        let mut results = Vec::with_capacity(self.endpoints.len());
        for i in 0..self.endpoints.len() {
            results.push(self.rotate(i).await);
        }
        results
    }

    /// Get current IPs for all endpoints: `(proxy_url, current_ip)`.
    pub fn current_ips(&self) -> Vec<(String, Option<String>)> {
        self.endpoints
            .iter()
            .map(|e| (e.proxy_url.clone(), e.current_ip.clone()))
            .collect()
    }

    /// Update the known current IP for an endpoint (call after verifying
    /// through the proxy).
    pub fn set_current_ip(&mut self, index: usize, ip: String) {
        if let Some(ep) = self.endpoints.get_mut(index) {
            ep.current_ip = Some(ip);
        }
    }

    /// Snapshot statistics.
    pub fn stats(&self) -> MobileProxyStats {
        MobileProxyStats {
            endpoint_count: self.endpoints.len(),
            total_rotations: self.endpoints.iter().map(|e| e.rotation_count).sum(),
            endpoints: self
                .endpoints
                .iter()
                .map(|e| MobileEndpointStats {
                    proxy_url: e.proxy_url.clone(),
                    carrier: e.carrier.clone(),
                    current_ip: e.current_ip.clone(),
                    rotation_count: e.rotation_count,
                    last_rotation_ago: e.last_rotation.map(|t| t.elapsed()),
                })
                .collect(),
        }
    }
}

impl Default for MobileProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the mobile proxy fleet.
#[derive(Debug, Clone)]
pub struct MobileProxyStats {
    pub endpoint_count: usize,
    pub total_rotations: u64,
    pub endpoints: Vec<MobileEndpointStats>,
}

/// Per-endpoint statistics.
#[derive(Debug, Clone)]
pub struct MobileEndpointStats {
    pub proxy_url: String,
    pub carrier: String,
    pub current_ip: Option<String>,
    pub rotation_count: u64,
    pub last_rotation_ago: Option<Duration>,
}

impl fmt::Display for MobileProxyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Mobile Proxies: {} endpoints, {} total rotations",
            self.endpoint_count, self.total_rotations
        )?;
        for ep in &self.endpoints {
            let ip = ep.current_ip.as_deref().unwrap_or("unknown");
            let ago = ep
                .last_rotation_ago
                .map(|d| format!("{}s ago", d.as_secs()))
                .unwrap_or_else(|| "never".into());
            writeln!(
                f,
                "  [{}/{}] ip={} rotations={} last={}",
                ep.carrier, ep.proxy_url, ip, ep.rotation_count, ago
            )?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when parsing an IPv6 prefix string.
#[derive(Debug, Clone)]
pub struct Ipv6ParseError(pub String);

impl fmt::Display for Ipv6ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPv6 parse error: {}", self.0)
    }
}

impl std::error::Error for Ipv6ParseError {}

/// Error from mobile proxy operations.
#[derive(Debug, Clone)]
pub struct MobileProxyError(pub String);

impl fmt::Display for MobileProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mobile proxy error: {}", self.0)
    }
}

impl std::error::Error for MobileProxyError {}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an IPv6 address string into 16 bytes.
///
/// Handles full form (`2001:0db8:0000:0000:0000:0000:0000:0001`),
/// abbreviated groups (`2001:db8::1`), and the `::` zero-compression.
fn parse_ipv6_addr(s: &str) -> Result<[u8; 16], Ipv6ParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok([0u8; 16]);
    }

    // Split on "::" to handle zero-compression.
    let (left, right) = if let Some(pos) = s.find("::") {
        let l = &s[..pos];
        let r = &s[pos + 2..];
        (l, Some(r))
    } else {
        (s, None)
    };

    let parse_groups = |part: &str| -> Result<Vec<u16>, Ipv6ParseError> {
        if part.is_empty() {
            return Ok(Vec::new());
        }
        part.split(':')
            .map(|g| {
                u16::from_str_radix(g, 16)
                    .map_err(|_| Ipv6ParseError(format!("invalid hex group '{g}'")))
            })
            .collect()
    };

    let left_groups = parse_groups(left)?;

    let groups: Vec<u16> = if let Some(right_str) = right {
        let right_groups = parse_groups(right_str)?;
        let total = left_groups.len() + right_groups.len();
        if total > 8 {
            return Err(Ipv6ParseError(format!(
                "too many groups ({total}) in '{s}'"
            )));
        }
        let zeros = 8 - total;
        let mut g = Vec::with_capacity(8);
        g.extend_from_slice(&left_groups);
        g.extend(std::iter::repeat(0u16).take(zeros));
        g.extend_from_slice(&right_groups);
        g
    } else {
        if left_groups.len() != 8 {
            return Err(Ipv6ParseError(format!(
                "expected 8 groups, got {} in '{s}'",
                left_groups.len()
            )));
        }
        left_groups
    };

    let mut bytes = [0u8; 16];
    for (i, &g) in groups.iter().enumerate() {
        bytes[i * 2] = (g >> 8) as u8;
        bytes[i * 2 + 1] = (g & 0xff) as u8;
    }

    Ok(bytes)
}

/// Format 16 bytes as a full IPv6 address string.
fn format_ipv6(bytes: &[u8; 16]) -> String {
    let groups: Vec<String> = (0..8)
        .map(|i| {
            let val = ((bytes[i * 2] as u16) << 8) | (bytes[i * 2 + 1] as u16);
            format!("{val:04x}")
        })
        .collect();
    groups.join(":")
}

/// Trigger IP rotation via an HTTP endpoint.
async fn rotate_via_http(url: &str, method: &str) -> Result<(), MobileProxyError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Minimal HTTP client — avoid pulling in reqwest just for this.
    let parsed = url
        .strip_prefix("http://")
        .ok_or_else(|| MobileProxyError(format!("rotation URL must be http://: '{url}'")))?;

    let (host_port, path) = parsed
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((parsed, "/".into()));

    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };

    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| MobileProxyError("rotation HTTP connect timeout".into()))?
        .map_err(|e| MobileProxyError(format!("rotation HTTP connect: {e}")))?;

    let req = format!("{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| MobileProxyError(format!("rotation HTTP write: {e}")))?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .map_err(|_| MobileProxyError("rotation HTTP read timeout".into()))?
        .map_err(|e| MobileProxyError(format!("rotation HTTP read: {e}")))?;

    if n == 0 {
        return Err(MobileProxyError("rotation HTTP: empty response".into()));
    }

    let resp = String::from_utf8_lossy(&buf[..n]);
    if !resp.contains("200") && !resp.contains("OK") && !resp.contains("ok") {
        return Err(MobileProxyError(format!(
            "rotation HTTP unexpected response: {}",
            &resp[..resp.len().min(120)]
        )));
    }

    Ok(())
}

/// Trigger IP rotation by sending AT commands through a serial port.
///
/// Sequence: `AT+CFUN=0` (radio off) → wait → `AT+CFUN=1` (radio on).
async fn rotate_via_at_command(port: &str) -> Result<(), MobileProxyError> {
    use tokio::process::Command;

    // Send AT+CFUN=0 to disable radio (airplane mode on).
    let off = Command::new("sh")
        .arg("-c")
        .arg(format!("echo 'AT+CFUN=0' > {port}"))
        .output()
        .await
        .map_err(|e| MobileProxyError(format!("AT command radio-off failed: {e}")))?;

    if !off.status.success() {
        return Err(MobileProxyError(format!(
            "AT+CFUN=0 failed: {}",
            String::from_utf8_lossy(&off.stderr)
        )));
    }

    // Wait for radio to fully power down.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Send AT+CFUN=1 to re-enable radio (airplane mode off).
    let on = Command::new("sh")
        .arg("-c")
        .arg(format!("echo 'AT+CFUN=1' > {port}"))
        .output()
        .await
        .map_err(|e| MobileProxyError(format!("AT command radio-on failed: {e}")))?;

    if !on.status.success() {
        return Err(MobileProxyError(format!(
            "AT+CFUN=1 failed: {}",
            String::from_utf8_lossy(&on.stderr)
        )));
    }

    Ok(())
}

/// Trigger IP rotation via ADB airplane-mode toggle on an Android device.
async fn rotate_via_adb(device_id: &str) -> Result<(), MobileProxyError> {
    use tokio::process::Command;

    // Enable airplane mode.
    let on = Command::new("adb")
        .args([
            "-s",
            device_id,
            "shell",
            "cmd",
            "connectivity",
            "airplane-mode",
            "enable",
        ])
        .output()
        .await
        .map_err(|e| MobileProxyError(format!("adb airplane-on failed: {e}")))?;

    if !on.status.success() {
        return Err(MobileProxyError(format!(
            "adb airplane enable failed: {}",
            String::from_utf8_lossy(&on.stderr)
        )));
    }

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Disable airplane mode.
    let off = Command::new("adb")
        .args([
            "-s",
            device_id,
            "shell",
            "cmd",
            "connectivity",
            "airplane-mode",
            "disable",
        ])
        .output()
        .await
        .map_err(|e| MobileProxyError(format!("adb airplane-off failed: {e}")))?;

    if !off.status.success() {
        return Err(MobileProxyError(format!(
            "adb airplane disable failed: {}",
            String::from_utf8_lossy(&off.stderr)
        )));
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv6 prefix parsing ─────────────────────────────────────────────

    #[test]
    fn parse_prefix_48() {
        let prefix = Ipv6Prefix::parse("2001:db8:1234::/48").unwrap();
        assert_eq!(prefix.prefix_len, 48);
        assert_eq!(prefix.host_bits(), 80);
        assert_eq!(prefix.pool_size(), 1u128 << 80);
        // First 6 bytes should be 0x2001:0db8:1234.
        assert_eq!(prefix.network[0], 0x20);
        assert_eq!(prefix.network[1], 0x01);
        assert_eq!(prefix.network[2], 0x0d);
        assert_eq!(prefix.network[3], 0xb8);
        assert_eq!(prefix.network[4], 0x12);
        assert_eq!(prefix.network[5], 0x34);
        // Host bytes should be zeroed.
        for &b in &prefix.network[6..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn parse_prefix_64() {
        let prefix = Ipv6Prefix::parse("2001:db8:abcd:ef00::/64").unwrap();
        assert_eq!(prefix.prefix_len, 64);
        assert_eq!(prefix.host_bits(), 64);
        assert_eq!(prefix.pool_size(), 1u128 << 64);
    }

    #[test]
    fn parse_prefix_128() {
        let prefix = Ipv6Prefix::parse("2001:db8::1/128").unwrap();
        assert_eq!(prefix.prefix_len, 128);
        assert_eq!(prefix.host_bits(), 0);
        assert_eq!(prefix.pool_size(), 1);
    }

    #[test]
    fn parse_prefix_invalid_no_slash() {
        assert!(Ipv6Prefix::parse("2001:db8::").is_err());
    }

    #[test]
    fn parse_prefix_invalid_len() {
        assert!(Ipv6Prefix::parse("2001:db8::/200").is_err());
    }

    #[test]
    fn prefix_display() {
        let prefix = Ipv6Prefix::parse("2001:0db8:1234::/48").unwrap();
        let s = prefix.to_string();
        assert!(s.contains("/48"), "display should contain /48: {s}");
        assert!(s.starts_with("2001:0db8:1234:0000:"));
    }

    // ── IPv6 address generation ─────────────────────────────────────────

    #[test]
    fn next_address_within_prefix() {
        let pool = Ipv6Pool::from_prefix("2001:db8:abcd::/48").unwrap();
        let addr = pool.next_address();

        // Must start with the prefix.
        assert!(
            addr.starts_with("2001:0db8:abcd:"),
            "address {addr} should start with 2001:0db8:abcd:"
        );
    }

    #[test]
    fn next_address_uniqueness() {
        let pool = Ipv6Pool::from_prefix("2001:db8::/48").unwrap();
        let mut addrs = std::collections::HashSet::new();
        for _ in 0..1000 {
            let addr = pool.next_address();
            addrs.insert(addr);
        }
        // With 2^80 address space, 1000 should all be unique.
        assert_eq!(addrs.len(), 1000, "all 1000 addresses should be unique");
    }

    #[test]
    fn generate_batch() {
        let pool = Ipv6Pool::from_prefix("2001:db8:ff::/48").unwrap();
        let batch = pool.generate_batch(500);
        assert_eq!(batch.len(), 500);

        // All unique.
        let unique: std::collections::HashSet<_> = batch.iter().collect();
        assert_eq!(unique.len(), 500);
    }

    #[test]
    fn generated_count_tracked() {
        let pool = Ipv6Pool::from_prefix("2001:db8::/48").unwrap();
        assert_eq!(pool.stats().generated_count, 0);

        pool.next_address();
        pool.next_address();
        pool.next_address();
        assert_eq!(pool.stats().generated_count, 3);

        pool.generate_batch(10);
        assert_eq!(pool.stats().generated_count, 13);
    }

    // ── Cooldown ────────────────────────────────────────────────────────

    #[test]
    fn cooldown_tracking() {
        let pool = Ipv6Pool::with_cooldown("2001:db8::/48", Duration::from_secs(60)).unwrap();
        let addr = pool.next_address();

        assert!(pool.is_available(&addr));
        pool.mark_used(&addr);
        assert!(!pool.is_available(&addr));
    }

    #[test]
    fn pool_size_48() {
        let pool = Ipv6Pool::from_prefix("2001:db8::/48").unwrap();
        assert_eq!(pool.pool_size(), 1u128 << 80);
    }

    #[test]
    fn pool_size_64() {
        let pool = Ipv6Pool::from_prefix("2001:db8:abcd:ef00::/64").unwrap();
        assert_eq!(pool.pool_size(), 1u128 << 64);
    }

    // ── IPv6 address parsing ────────────────────────────────────────────

    #[test]
    fn parse_full_ipv6() {
        let bytes = parse_ipv6_addr("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[14], 0x00);
        assert_eq!(bytes[15], 0x01);
    }

    #[test]
    fn parse_abbreviated_ipv6() {
        let bytes = parse_ipv6_addr("2001:db8::1").unwrap();
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x0d);
        assert_eq!(bytes[3], 0xb8);
        // Middle should be zeros.
        for &b in &bytes[4..14] {
            assert_eq!(b, 0);
        }
        assert_eq!(bytes[14], 0x00);
        assert_eq!(bytes[15], 0x01);
    }

    #[test]
    fn parse_all_zeros() {
        let bytes = parse_ipv6_addr("::").unwrap();
        assert_eq!(bytes, [0u8; 16]);
    }

    #[test]
    fn parse_loopback() {
        let bytes = parse_ipv6_addr("::1").unwrap();
        assert_eq!(bytes[15], 1);
        for &b in &bytes[..15] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn format_roundtrip() {
        let original = "2001:0db8:1234:5678:9abc:def0:1234:5678";
        let bytes = parse_ipv6_addr(original).unwrap();
        let formatted = format_ipv6(&bytes);
        assert_eq!(formatted, original);
    }

    // ── Mobile proxy manager ────────────────────────────────────────────

    #[test]
    fn mobile_manager_basics() {
        let mut mgr = MobileProxyManager::new();
        assert!(mgr.is_empty());

        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "t-mobile".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 0,
        });

        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());
    }

    #[test]
    fn mobile_endpoint_can_rotate() {
        let mut ep = MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "att".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 0,
        };

        // Never rotated — should be allowed.
        assert!(ep.can_rotate());

        // Just rotated — should not be allowed.
        ep.last_rotation = Some(Instant::now());
        assert!(!ep.can_rotate());
    }

    #[test]
    fn mobile_current_ips() {
        let mut mgr = MobileProxyManager::new();
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "t-mobile".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: Some("100.64.1.1".into()),
            rotation_count: 0,
        });
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.2:1080".into(),
            carrier: "verizon".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 0,
        });

        let ips = mgr.current_ips();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].1, Some("100.64.1.1".into()));
        assert_eq!(ips[1].1, None);
    }

    #[test]
    fn mobile_set_current_ip() {
        let mut mgr = MobileProxyManager::new();
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "att".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 0,
        });

        mgr.set_current_ip(0, "100.64.2.3".into());
        assert_eq!(mgr.current_ips()[0].1, Some("100.64.2.3".into()));
    }

    #[test]
    fn mobile_stats() {
        let mut mgr = MobileProxyManager::new();
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "t-mobile".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 5,
        });
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.2:1080".into(),
            carrier: "att".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 3,
        });

        let stats = mgr.stats();
        assert_eq!(stats.endpoint_count, 2);
        assert_eq!(stats.total_rotations, 8);
        assert_eq!(stats.endpoints[0].carrier, "t-mobile");
        assert_eq!(stats.endpoints[1].carrier, "att");
    }

    #[tokio::test]
    async fn mobile_next_proxy_round_robin() {
        let mut mgr = MobileProxyManager::with_strategy(MobileRotationStrategy::OnBlock);
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "t-mobile".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 0,
        });
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.2:1080".into(),
            carrier: "att".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::from_secs(30),
            current_ip: None,
            rotation_count: 0,
        });

        let first = mgr.next_proxy().await.unwrap();
        let second = mgr.next_proxy().await.unwrap();
        let third = mgr.next_proxy().await.unwrap();

        assert_eq!(first, "socks5://10.0.0.1:1080");
        assert_eq!(second, "socks5://10.0.0.2:1080");
        assert_eq!(third, "socks5://10.0.0.1:1080"); // wraps around
    }

    #[tokio::test]
    async fn mobile_next_proxy_empty_errors() {
        let mut mgr = MobileProxyManager::new();
        let result = mgr.next_proxy().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mobile_rotate_natural_is_instant() {
        let mut mgr = MobileProxyManager::new();
        mgr.add_endpoint(MobileEndpoint {
            proxy_url: "socks5://10.0.0.1:1080".into(),
            carrier: "t-mobile".into(),
            rotation_method: RotationMethod::Natural,
            last_rotation: None,
            min_rotation_interval: Duration::ZERO,
            current_ip: Some("1.2.3.4".into()),
            rotation_count: 0,
        });

        let url = mgr.rotate(0).await.unwrap();
        assert_eq!(url, "socks5://10.0.0.1:1080");
        // current_ip should be cleared after rotation.
        assert_eq!(mgr.current_ips()[0].1, None);
        // rotation_count should be incremented.
        assert_eq!(mgr.stats().total_rotations, 1);
    }

    #[tokio::test]
    async fn mobile_rotate_out_of_range() {
        let mut mgr = MobileProxyManager::new();
        let result = mgr.rotate(99).await;
        assert!(result.is_err());
    }

    // ── Prefix /64 address generation ───────────────────────────────────

    #[test]
    fn address_within_64_prefix() {
        let pool = Ipv6Pool::from_prefix("2001:db8:abcd:ef00::/64").unwrap();
        for _ in 0..100 {
            let addr = pool.next_address();
            assert!(
                addr.starts_with("2001:0db8:abcd:ef00:"),
                "address {addr} must start with 2001:0db8:abcd:ef00:"
            );
        }
    }

    #[test]
    fn cleanup_expired() {
        let pool = Ipv6Pool::with_cooldown("2001:db8::/48", Duration::from_millis(1)).unwrap();
        let addr = pool.next_address();
        pool.mark_used(&addr);

        // Wait for cooldown to expire.
        std::thread::sleep(Duration::from_millis(5));
        pool.cleanup();

        // After cleanup, the used_addresses map should be empty.
        assert_eq!(pool.used_addresses.len(), 0);
    }
}
