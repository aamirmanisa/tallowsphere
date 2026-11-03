//! Host path-capability probe.
//!
//! Answers one question with evidence instead of assertion: how many
//! *independent* paths does this host actually have, and can any of them be
//! aggregated? Reads `/proc` and `/sys` only — no network, no root, no side
//! effects. Every claim in [`CapabilityReport::verdict`] is derived from a file
//! that was actually read, and is omitted when the file is absent.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Classification of a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkKind {
    /// A real uplink device.
    Physical,
    /// Tunnel over an existing path (does not add capacity).
    WireGuard,
    /// Bridge for containers.
    Bridge,
    /// veth pair end for a container.
    Virtual,
    /// Loopback.
    Loopback,
    /// Anything unrecognised.
    Other,
}

/// One interface as seen by the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkInfo {
    /// Interface name.
    pub name: String,
    /// Classification.
    pub kind: LinkKind,
    /// MTU if readable.
    pub mtu: Option<u64>,
}

/// Everything the probe could establish about this host's egress capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Kernel release.
    pub kernel: String,
    /// `net.mptcp.enabled`, if the kernel exposes MPTCP.
    pub mptcp_enabled: Option<bool>,
    /// `net.mptcp.pm_type` (0 = full mesh/endpoint API, 1 = in-kernel).
    pub mptcp_pm_type: Option<String>,
    /// `net.mptcp.scheduler`.
    pub mptcp_scheduler: Option<String>,
    /// Interfaces present.
    pub links: Vec<LinkInfo>,
    /// Bond interfaces found under `/proc/net/bonding`.
    pub bond_interfaces: Vec<String>,
    /// Count of devices that represent a genuinely separate path.
    pub distinct_paths: usize,
    /// Human-readable conclusions, one claim per evidence line.
    pub verdict: Vec<String>,
}

fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn classify(name: &str) -> LinkKind {
    if name == "lo" {
        LinkKind::Loopback
    } else if name.starts_with("wg") {
        LinkKind::WireGuard
    } else if name.starts_with("br-") || name == "docker0" {
        LinkKind::Bridge
    } else if name.starts_with("veth") || name.starts_with("tap") || name.starts_with("tun") {
        LinkKind::Virtual
    } else if name.starts_with("eth") || name.starts_with("en") || name.starts_with("wl") {
        LinkKind::Physical
    } else {
        LinkKind::Other
    }
}

fn read_links() -> Vec<LinkInfo> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut links: Vec<LinkInfo> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let mtu = read_trim(Path::new("/sys/class/net").join(&name).join("mtu"))
                .and_then(|s| s.parse::<u64>().ok());
            Some(LinkInfo {
                kind: classify(&name),
                name,
                mtu,
            })
        })
        .collect();
    links.sort_by(|a, b| a.name.cmp(&b.name));
    links
}

fn read_bonds() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/proc/net/bonding") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

/// Probe the host. Cheap enough to call on every `egress-bench` run.
pub fn probe_host() -> CapabilityReport {
    let kernel = read_trim("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|| format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH));
    let links = read_links();
    let bond_interfaces = read_bonds();

    let mptcp_enabled = read_trim("/proc/sys/net/mptcp/enabled").map(|v| v == "1");
    let mptcp_pm_type = read_trim("/proc/sys/net/mptcp/pm_type");
    let mptcp_scheduler = read_trim("/proc/sys/net/mptcp/scheduler");

    let distinct_paths = links
        .iter()
        .filter(|l| l.kind == LinkKind::Physical)
        .count();

    let mut verdict = Vec::new();

    match distinct_paths {
        0 => verdict.push(
            "no physical uplink device found; egress capacity cannot be aggregated".to_string(),
        ),
        1 => verdict.push(format!(
            "1 physical uplink ({}); link bonding has nothing to bond — a second \
             independent path must come from the provider",
            links
                .iter()
                .find(|l| l.kind == LinkKind::Physical)
                .map(|l| l.name.as_str())
                .unwrap_or("unknown")
        )),
        n => verdict.push(format!(
            "{n} physical uplinks present; bonding is possible but raises aggregate \
             throughput only — a single TCP flow still rides one link"
        )),
    }

    if links.iter().any(|l| l.kind == LinkKind::WireGuard) {
        verdict.push(
            "a WireGuard interface is present but tunnels over the existing uplink: \
             it adds privacy, not capacity"
                .to_string(),
        );
    }

    match mptcp_enabled {
        Some(true) => verdict.push(
            "kernel MPTCP is enabled: a single flow can use several paths, but only \
             against a peer that also supports it, and only when this host has two \
             paths to offer"
                .to_string(),
        ),
        Some(false) => verdict
            .push("kernel MPTCP is present but disabled (sysctl net.mptcp.enabled=0)".to_string()),
        None => verdict.push(
            "kernel exposes no MPTCP knobs; multi-path TCP is unavailable on this host".to_string(),
        ),
    }

    if bond_interfaces.is_empty() {
        verdict.push("no bonded interface is configured".to_string());
    } else {
        verdict.push(format!(
            "bond interfaces configured: {}",
            bond_interfaces.join(", ")
        ));
    }

    CapabilityReport {
        kernel,
        mptcp_enabled,
        mptcp_pm_type,
        mptcp_scheduler,
        links,
        bond_interfaces,
        distinct_paths,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_is_stable() {
        assert_eq!(classify("lo"), LinkKind::Loopback);
        assert_eq!(classify("eth0"), LinkKind::Physical);
        assert_eq!(classify("wg0"), LinkKind::WireGuard);
        assert_eq!(classify("docker0"), LinkKind::Bridge);
        assert_eq!(classify("veth1234"), LinkKind::Virtual);
        assert_eq!(classify("weird9"), LinkKind::Other);
    }

    #[test]
    fn probe_returns_a_verdict_on_any_host() {
        let report = probe_host();
        assert!(
            !report.verdict.is_empty(),
            "probe must always conclude something"
        );
        assert_eq!(
            report.distinct_paths,
            report
                .links
                .iter()
                .filter(|l| l.kind == LinkKind::Physical)
                .count()
        );
    }
}
