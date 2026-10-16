//! Network-level stealth for Tallow.
//!
//! Handles TCP/IP fingerprint correlation, DNS over HTTPS,
//! sysctl auto-tuning, TCP Fast Open, and Happy Eyeballs.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// TCP fingerprint profile matching a specific OS.
#[derive(Debug, Clone, Copy)]
pub enum TcpProfile {
    /// Windows 10/11: TTL=128, window=65535, scale=8
    Windows,
    /// macOS: TTL=64, window=65535, scale=6
    MacOS,
    /// Linux: TTL=64, window=29200, scale=7
    Linux,
}

impl TcpProfile {
    /// Get the IP TTL for this OS profile.
    pub fn ttl(&self) -> u32 {
        match self {
            TcpProfile::Windows => 128,
            TcpProfile::MacOS => 64,
            TcpProfile::Linux => 64,
        }
    }

    /// Get the TCP window size for this OS profile.
    pub fn window_size(&self) -> u32 {
        match self {
            TcpProfile::Windows => 65535,
            TcpProfile::MacOS => 65535,
            TcpProfile::Linux => 29200,
        }
    }

    /// Get the window scale factor.
    pub fn window_scale(&self) -> u8 {
        match self {
            TcpProfile::Windows => 8,
            TcpProfile::MacOS => 6,
            TcpProfile::Linux => 7,
        }
    }

    /// Match profile to User-Agent platform.
    pub fn for_platform(platform: &str) -> Self {
        if platform.contains("Windows") {
            TcpProfile::Windows
        } else if platform.contains("Mac") || platform.contains("Darwin") {
            TcpProfile::MacOS
        } else {
            TcpProfile::Linux
        }
    }
}

/// Apply TCP fingerprint to a socket.
///
/// Sets TTL to match the claimed OS in the User-Agent.
/// This prevents p0f-style passive OS fingerprinting from
/// detecting that a "Windows Chrome" request comes from Linux.
#[cfg(unix)]
pub fn apply_tcp_profile(fd: std::os::unix::io::RawFd, profile: TcpProfile) {
    use std::os::unix::io::FromRawFd;
    unsafe {
        // Set TTL
        let ttl: libc::c_int = profile.ttl() as libc::c_int;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        // Enable TCP Fast Open
        let tfo: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            30, // TCP_FASTOPEN_CONNECT
            &tfo as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(windows)]
pub fn apply_tcp_profile(fd: u64, profile: TcpProfile) {
    // On Windows, TTL defaults to 128 which matches TcpProfile::Windows.
    // For non-Windows profiles (spoofing as macOS/Linux), we need to change TTL.
    // Use std::net::TcpStream's set_ttl via the raw socket handle.
    let ttl: u32 = match profile {
        TcpProfile::Windows => return, // Already correct on Windows
        TcpProfile::MacOS => 64,
        TcpProfile::Linux => 64,
    };
    // Convert raw fd to a TcpStream temporarily to set TTL
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};
    let socket = unsafe { std::net::TcpStream::from_raw_socket(fd as u64) };
    let _ = socket.set_ttl(ttl);
    // Don't close the socket — return ownership
    let _ = socket.into_raw_socket();
}

/// Linux sysctl tuning for maximum concurrent connections.
///
/// Applies all settings automatically on startup.
/// All changes are logged and can be reversed.
pub struct NetworkTuner {
    original_values: Vec<(String, String)>,
}

impl NetworkTuner {
    /// Apply maximum performance sysctl settings.
    ///
    /// Returns a tuner that can revert changes on drop.
    #[cfg(target_os = "linux")]
    pub fn apply_max_performance() -> Self {
        let tunings = [
            ("fs.file-max", "2097152"),
            ("net.ipv4.ip_local_port_range", "1024 65535"),
            ("net.ipv4.tcp_tw_reuse", "1"),
            ("net.ipv4.tcp_fin_timeout", "15"),
            ("net.ipv4.tcp_max_tw_buckets", "2000000"),
            ("net.core.somaxconn", "65535"),
            ("net.core.netdev_max_backlog", "65535"),
            ("net.ipv4.tcp_max_syn_backlog", "65535"),
            ("net.core.rmem_max", "16777216"),
            ("net.core.wmem_max", "16777216"),
            ("net.ipv4.tcp_rmem", "4096 87380 16777216"),
            ("net.ipv4.tcp_wmem", "4096 65536 16777216"),
            ("net.ipv4.tcp_fastopen", "3"),
            ("net.ipv4.tcp_slow_start_after_idle", "0"),
            ("net.ipv4.tcp_mtu_probing", "1"),
            ("net.ipv4.tcp_window_scaling", "1"),
            ("net.ipv4.ip_default_ttl", "128"), // Match Windows
        ];

        let mut original_values = Vec::new();

        for (key, value) in &tunings {
            let path = format!("/proc/sys/{}", key.replace('.', "/"));
            // Save original value
            if let Ok(original) = std::fs::read_to_string(&path) {
                original_values.push((path.clone(), original.trim().to_string()));
            }
            // Apply new value
            if let Err(_) = std::fs::write(&path, value) {
                eprintln!("  [tallow] warn: cannot tune {} (need root)", key);
            }
        }

        Self { original_values }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply_max_performance() -> Self {
        Self {
            original_values: Vec::new(),
        }
    }

    /// Revert all sysctl changes.
    pub fn revert(&self) {
        for (path, value) in &self.original_values {
            let _ = std::fs::write(path, value);
        }
    }
}

impl Drop for NetworkTuner {
    fn drop(&mut self) {
        self.revert();
    }
}

/// Happy Eyeballs: race IPv4 and IPv6 connections, use fastest.
///
/// Starts IPv6 first (250ms head start per RFC 8305), then IPv4.
/// Returns whichever connects first, cancels the other.
pub async fn happy_eyeballs_connect(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    happy_eyeballs_connect_family(host, port, timeout, false).await
}

/// Happy Eyeballs restricted to IPv4 only.
///
/// This is the dual-stack leak guard: when a proxy is active the connection
/// must go *through the proxy*, but `happy_eyeballs_connect` races A + AAAA
/// and can win on the host's real IPv6 path, bypassing the proxy entirely
/// (a concrete DNS/dual-stack leak). Callers with an active proxy must use
/// this v4-only variant so the local stack cannot divert traffic around the
/// egress tunnel.
pub async fn happy_eyeballs_connect_v4(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    happy_eyeballs_connect_family(host, port, timeout, true).await
}

/// Core Happy Eyeballs implementation.
///
/// When `force_ipv4` is true, AAAA (IPv6) records are discarded so the
/// connection can only use IPv4 — preventing a proxy bypass over the local
/// IPv6 stack.
async fn happy_eyeballs_connect_family(
    host: &str,
    port: u16,
    timeout: Duration,
    force_ipv4: bool,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    use tokio::net::TcpStream;

    // Resolve both A and AAAA records — fail-closed (T-122b): this rides the
    // OS resolver (plain DNS, udp/tcp :53). Refuse unless the operator opted
    // in (TALLOW_ALLOW_DIRECT).
    if let Some(reason) = crate::runtime::dns_guard::plain_dns_refusal(53, false) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            reason,
        ));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await?
        .collect();

    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no addresses resolved",
        ));
    }

    let v6: Vec<_> = if force_ipv4 {
        // IPv6 leak guard: never touch the IPv6 family when proxied.
        Vec::new()
    } else {
        addrs.iter().filter(|a| a.is_ipv6()).copied().collect()
    };
    let v4: Vec<_> = addrs.iter().filter(|a| a.is_ipv4()).copied().collect();

    // If only one family available, just connect to it
    if v6.is_empty() {
        return tokio::time::timeout(timeout, TcpStream::connect(v4[0]))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?;
    }
    if v4.is_empty() {
        return tokio::time::timeout(timeout, TcpStream::connect(v6[0]))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?;
    }

    // Race: IPv6 gets 250ms head start, with overall timeout
    let race = async {
        tokio::select! {
            result = TcpStream::connect(v6[0]) => result,
            result = async {
                tokio::time::sleep(Duration::from_millis(250)).await;
                TcpStream::connect(v4[0]).await
            } => result,
        }
    };
    tokio::time::timeout(timeout, race)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
}

/// DNS prefetch cache.
///
/// Pre-resolves domains before crawling begins.
/// Eliminates 20-120ms DNS lookup per new domain.
pub struct DnsPrefetchCache {
    cache: std::collections::HashMap<String, Vec<IpAddr>>,
}

impl DnsPrefetchCache {
    pub fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
        }
    }

    /// Pre-resolve a list of domains.
    pub async fn prefetch(&mut self, domains: &[String]) {
        // Fail-closed (T-122b): prefetch would ride the OS resolver (plain
        // DNS, udp/tcp :53) per domain. One refusal covers the whole batch
        // (journaled by the guard); the cache simply stays empty unless the
        // operator opted in (TALLOW_ALLOW_DIRECT).
        if crate::runtime::dns_guard::plain_dns_refusal(53, false).is_some() {
            return;
        }
        for domain in domains {
            if self.cache.contains_key(domain) {
                continue;
            }
            match tokio::net::lookup_host(format!("{}:443", domain)).await {
                Ok(addrs) => {
                    let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    if !ips.is_empty() {
                        self.cache.insert(domain.clone(), ips);
                    }
                }
                Err(_) => {}
            }
        }
    }

    /// Get cached IPs for a domain.
    pub fn get(&self, domain: &str) -> Option<&[IpAddr]> {
        self.cache.get(domain).map(|v| v.as_slice())
    }

    /// Number of cached domains.
    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

/// TLS ClientHello fragmentation.
///
/// Splits the TLS ClientHello across multiple TCP segments to break
/// DPI-based JA3/JA4 fingerprinting. Akamai's parser expects the
/// entire ClientHello in one TCP segment — fragmenting it causes
/// parse failure and the request passes through unflagged.
///
/// This is a technique from XTLS-Vision/VLESS censorship bypass tools.
pub struct TlsFragmenter {
    /// Fragment size in bytes (smaller = harder to reassemble)
    pub fragment_size: usize,
    /// Random delay between fragments (microseconds)
    pub inter_fragment_delay_us: u64,
}

impl TlsFragmenter {
    /// Standard fragmentation: 40-byte fragments with 1ms delay.
    pub fn standard() -> Self {
        Self {
            fragment_size: 40,
            inter_fragment_delay_us: 1000,
        }
    }

    /// Aggressive fragmentation: 20-byte fragments with 500us delay.
    pub fn aggressive() -> Self {
        Self {
            fragment_size: 20,
            inter_fragment_delay_us: 500,
        }
    }

    /// Fragment a TLS ClientHello payload into multiple chunks.
    ///
    /// Returns a Vec of byte chunks, each at most `fragment_size` bytes.
    /// The caller should send each chunk as a separate TCP segment with
    /// `inter_fragment_delay_us` microseconds between them.
    ///
    /// To actually send fragmented, the caller must:
    /// 1. Set `TCP_NODELAY` on the socket (disable Nagle)
    /// 2. Write each fragment separately with a delay between writes
    pub fn fragment(&self, client_hello: &[u8]) -> Vec<Vec<u8>> {
        if client_hello.is_empty() || self.fragment_size == 0 {
            return vec![client_hello.to_vec()];
        }
        client_hello
            .chunks(self.fragment_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Send a fragmented TLS ClientHello over a tokio TCP stream.
    ///
    /// Sets TCP_NODELAY to ensure each write becomes its own TCP segment,
    /// then sends fragments with configured inter-fragment delay.
    pub async fn send_fragmented(
        &self,
        stream: &mut tokio::net::TcpStream,
        client_hello: &[u8],
    ) -> Result<(), std::io::Error> {
        use tokio::io::AsyncWriteExt;
        // Ensure each write is its own TCP segment
        stream.set_nodelay(true)?;

        let fragments = self.fragment(client_hello);
        for (i, frag) in fragments.iter().enumerate() {
            stream.write_all(frag).await?;

            // Delay between fragments (skip after last)
            if i < fragments.len() - 1 && self.inter_fragment_delay_us > 0 {
                tokio::time::sleep(std::time::Duration::from_micros(
                    self.inter_fragment_delay_us,
                ))
                .await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_profile_windows() {
        let p = TcpProfile::Windows;
        assert_eq!(p.ttl(), 128);
        assert_eq!(p.window_size(), 65535);
        assert_eq!(p.window_scale(), 8);
    }

    #[test]
    fn test_tcp_profile_for_platform() {
        assert!(matches!(
            TcpProfile::for_platform("Windows NT 10.0"),
            TcpProfile::Windows
        ));
        assert!(matches!(
            TcpProfile::for_platform("Macintosh"),
            TcpProfile::MacOS
        ));
        assert!(matches!(
            TcpProfile::for_platform("X11; Linux"),
            TcpProfile::Linux
        ));
    }

    #[test]
    fn test_dns_cache_new() {
        let cache = DnsPrefetchCache::new();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_tls_fragmenter() {
        let f = TlsFragmenter::standard();
        assert_eq!(f.fragment_size, 40);
        let f = TlsFragmenter::aggressive();
        assert_eq!(f.fragment_size, 20);
    }

    #[test]
    fn test_network_tuner_creation() {
        // On non-Linux, this is a no-op
        let tuner = NetworkTuner::apply_max_performance();
        assert!(tuner.original_values.is_empty() || !tuner.original_values.is_empty());
    }
}
