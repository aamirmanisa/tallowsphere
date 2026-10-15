//! DPI bypass and protocol obfuscation for Tallow.
//!
//! Implements techniques from the Geneva project (UMD), XTLS-Vision
//! traffic fragmentation, Encrypted Client Hello (ECH), and
//! protocol mimicry for defeating deep packet inspection.

use tokio::io::AsyncWriteExt;

use crate::browser::network_stealth::TlsFragmenter;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};

/// DPI bypass strategy: a sequence of packet manipulations
/// that defeats a specific firewall/detection system.
///
/// Based on the Geneva project which auto-discovers bypass strategies
/// by genetically evolving packet manipulation sequences.
#[derive(Debug, Clone)]
pub struct DpiBypassStrategy {
    /// Human-readable name
    pub name: String,
    /// Target system this bypasses (e.g., "akamai", "cloudflare", "gfw")
    pub target: String,
    /// Sequence of packet manipulations
    pub actions: Vec<PacketAction>,
    /// Whether this strategy is currently working
    pub verified: bool,
}

/// Individual packet manipulation action.
#[derive(Debug, Clone)]
pub enum PacketAction {
    /// Fragment the TCP segment at the given offset
    Fragment { offset: usize },
    /// Duplicate a packet
    Duplicate,
    /// Tamper with TCP flags
    TamperFlags { flags: u8 },
    /// Add delay between segments
    Delay { ms: u64 },
    /// Drop a packet (for testing)
    Drop,
    /// Send a TCP RST to confuse stateful DPI
    SendRst,
    /// Modify TTL to expire before reaching the firewall
    SetTtl { ttl: u8 },
    /// Split TLS ClientHello across multiple TCP segments
    FragmentTlsHello { chunk_size: usize },
    /// Insert garbage data between TCP segments
    InsertGarbage { size: usize },
    /// Send packet with corrupt TCP checksum — DPI reads it, server drops it
    CorruptChecksum,
    /// Send TCP segment 2 before segment 1 to confuse reassembly in DPI
    ReverseFragments,
    /// Send TCP urgent/out-of-band data that DPI may misparse
    OutOfBand { byte: u8 },
    /// Add IPv6 extension header to break DPI parsers
    Ipv6ExtHeader { header_type: u8 },
    /// Split TLS records at the record layer (distinct from TCP segmentation)
    TlsRecordFragment { max_record_size: u16 },
}

/// Known DPI bypass strategies for major anti-bot systems.
pub fn known_strategies() -> Vec<DpiBypassStrategy> {
    vec![
        DpiBypassStrategy {
            name: "TLS Hello Fragmentation (XTLS-Vision)".into(),
            target: "akamai".into(),
            actions: vec![
                PacketAction::FragmentTlsHello { chunk_size: 40 },
                PacketAction::Delay { ms: 1 },
            ],
            verified: true,
        },
        DpiBypassStrategy {
            name: "Aggressive TLS Fragment".into(),
            target: "cloudflare".into(),
            actions: vec![
                PacketAction::FragmentTlsHello { chunk_size: 20 },
                PacketAction::Delay { ms: 2 },
                PacketAction::InsertGarbage { size: 10 },
            ],
            verified: false,
        },
        DpiBypassStrategy {
            name: "TTL-based evasion".into(),
            target: "gfw".into(),
            actions: vec![
                PacketAction::SetTtl { ttl: 1 },
                PacketAction::SendRst,
                PacketAction::SetTtl { ttl: 64 },
            ],
            verified: false,
        },
        DpiBypassStrategy {
            name: "TCP Segmentation".into(),
            target: "perimeterx".into(),
            actions: vec![
                PacketAction::Fragment { offset: 5 },
                PacketAction::Delay { ms: 3 },
                PacketAction::Fragment { offset: 10 },
            ],
            verified: false,
        },
        DpiBypassStrategy {
            name: "Checksum Corruption".into(),
            target: "generic".into(),
            actions: vec![PacketAction::CorruptChecksum, PacketAction::Delay { ms: 1 }],
            verified: false,
        },
        DpiBypassStrategy {
            name: "Reverse Fragment".into(),
            target: "generic".into(),
            actions: vec![
                PacketAction::ReverseFragments,
                PacketAction::Delay { ms: 2 },
            ],
            verified: false,
        },
        DpiBypassStrategy {
            name: "IPv6 Extension Header Bypass".into(),
            target: "generic".into(),
            actions: vec![
                PacketAction::Ipv6ExtHeader { header_type: 0 }, // Hop-by-hop
                PacketAction::FragmentTlsHello { chunk_size: 40 },
            ],
            verified: false,
        },
        DpiBypassStrategy {
            name: "TLS Record Split".into(),
            target: "generic".into(),
            actions: vec![
                PacketAction::TlsRecordFragment {
                    max_record_size: 40,
                },
                PacketAction::Delay { ms: 1 },
            ],
            verified: false,
        },
    ]
}

/// Execute a DPI bypass strategy on a TCP stream.
/// Applies packet manipulations before/during TLS handshake.
pub async fn execute_strategy(
    strategy: &DpiBypassStrategy,
    stream: &mut tokio::net::TcpStream,
    client_hello: &[u8],
) -> Result<(), String> {
    for action in &strategy.actions {
        match action {
            PacketAction::Fragment { offset } => {
                let offset = (*offset).min(client_hello.len());
                let (first, second) = client_hello.split_at(offset);
                stream
                    .set_nodelay(true)
                    .map_err(|e| format!("set_nodelay failed: {e}"))?;
                stream
                    .write_all(first)
                    .await
                    .map_err(|e| format!("fragment write 1 failed: {e}"))?;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                stream
                    .write_all(second)
                    .await
                    .map_err(|e| format!("fragment write 2 failed: {e}"))?;
            }
            PacketAction::Delay { ms } => {
                tokio::time::sleep(std::time::Duration::from_millis(*ms)).await;
            }
            PacketAction::SetTtl { ttl } => {
                stream
                    .set_ttl(*ttl as u32)
                    .map_err(|e| format!("set_ttl failed: {e}"))?;
            }
            PacketAction::FragmentTlsHello { chunk_size } => {
                let fragmenter = TlsFragmenter {
                    fragment_size: *chunk_size,
                    inter_fragment_delay_us: 1000,
                };
                fragmenter
                    .send_fragmented(stream, client_hello)
                    .await
                    .map_err(|e| format!("TLS hello fragmentation failed: {e}"))?;
            }
            PacketAction::TlsRecordFragment { max_record_size } => {
                let fragmenter = TlsFragmenter {
                    fragment_size: *max_record_size as usize,
                    inter_fragment_delay_us: 500,
                };
                fragmenter
                    .send_fragmented(stream, client_hello)
                    .await
                    .map_err(|e| format!("TLS record fragmentation failed: {e}"))?;
            }
            PacketAction::CorruptChecksum => {
                eprintln!(
                    "DPI bypass: checksum corruption requires raw sockets, \
                     skipping CorruptChecksum action"
                );
            }
            PacketAction::ReverseFragments => {
                let mid = client_hello.len() / 2;
                let (first_half, second_half) = client_hello.split_at(mid);
                stream
                    .set_nodelay(true)
                    .map_err(|e| format!("set_nodelay failed: {e}"))?;
                // Send second half first, then first half
                stream
                    .write_all(second_half)
                    .await
                    .map_err(|e| format!("reverse fragment write 1 failed: {e}"))?;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                stream
                    .write_all(first_half)
                    .await
                    .map_err(|e| format!("reverse fragment write 2 failed: {e}"))?;
            }
            PacketAction::OutOfBand { byte } => {
                // MSG_OOB is Unix-only; on Windows this is a no-op with a warning
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    let fd = stream.as_raw_fd();
                    let buf = [*byte];
                    // SAFETY: sending 1 byte of OOB data on a valid fd
                    let ret = unsafe {
                        libc::send(fd, buf.as_ptr() as *const libc::c_void, 1, libc::MSG_OOB)
                    };
                    if ret < 0 {
                        eprintln!(
                            "DPI bypass: OOB send failed: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = byte;
                    eprintln!(
                        "DPI bypass: OutOfBand (MSG_OOB) is only supported on Unix, skipping"
                    );
                }
            }
            PacketAction::InsertGarbage { size } => {
                let garbage: Vec<u8> = (0..*size).map(|i| (i & 0xFF) as u8).collect();
                stream
                    .write_all(&garbage)
                    .await
                    .map_err(|e| format!("garbage insert write failed: {e}"))?;
            }
            PacketAction::Duplicate
            | PacketAction::TamperFlags { .. }
            | PacketAction::Drop
            | PacketAction::SendRst => {
                eprintln!(
                    "DPI bypass: {:?} requires raw socket / nfqueue, skipping",
                    action
                );
            }
            PacketAction::Ipv6ExtHeader { .. } => {
                eprintln!(
                    "DPI bypass: IPv6 extension header injection requires raw socket, skipping"
                );
            }
        }
    }
    Ok(())
}

/// Encrypted Client Hello (ECH) configuration.
///
/// ECH encrypts the TLS SNI field so network observers cannot see
/// which domain you're connecting to. The outer SNI shows a cover
/// domain (typically the CDN), while the inner encrypted SNI contains
/// the actual target domain.
///
/// Supported by Cloudflare and Firefox since 2024.
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// The public name (outer SNI, visible to network)
    pub public_name: String,
    /// ECH config list (base64-encoded, obtained from DNS HTTPS record)
    pub ech_config_list: String,
    /// Whether to retry without ECH if the server doesn't support it
    pub retry_without_ech: bool,
}

impl EchConfig {
    /// Create a template ECH config for a Cloudflare-protected domain.
    ///
    /// This returns a config with an empty `ech_config_list`. To get a
    /// ready-to-use config, call [`fetch_ech_config`] instead, e.g.:
    ///
    /// ```ignore
    /// let ech = fetch_ech_config("cloudflare-dns.com").await?;
    /// ```
    pub fn cloudflare(_target_domain: &str) -> Self {
        Self {
            public_name: "cloudflare-ech.com".into(),
            ech_config_list: String::new(),
            retry_without_ech: true,
        }
    }

    /// Check if ECH is configured and ready to use.
    pub fn is_ready(&self) -> bool {
        !self.ech_config_list.is_empty()
    }
}

/// Fetch the real ECH configuration for a domain by querying its DNS HTTPS
/// (type 65) record.
///
/// Tries two resolution strategies in order:
/// 1. Standard DNS HTTPS record lookup via the system resolver.
/// 2. DNS-over-HTTPS (DoH) query to Cloudflare (1.1.1.1) as a fallback.
///
/// Returns an [`EchConfig`] with the base64-encoded `ech_config_list`
/// extracted from the SVCB `echconfig` parameter.
pub async fn fetch_ech_config(domain: &str) -> Result<EchConfig, String> {
    // Attempt 1: hickory-resolver standard DNS lookup for HTTPS records.
    match fetch_ech_via_dns(domain).await {
        Ok(cfg) => return Ok(cfg),
        Err(dns_err) => {
            eprintln!("DNS HTTPS lookup for {domain} failed ({dns_err}), trying DoH fallback");
        }
    }

    // Attempt 2: DoH fallback via Cloudflare's JSON API.
    fetch_ech_via_doh(domain).await
}

/// Resolve the HTTPS DNS record for `domain` and extract the ECH config.
async fn fetch_ech_via_dns(domain: &str) -> Result<EchConfig, String> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts, CLOUDFLARE};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::https(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
    .map_err(|e| format!("failed to build DNS resolver: {e}"))?;

    let lookup = resolver
        .lookup(domain, RecordType::HTTPS)
        .await
        .map_err(|e| format!("DNS HTTPS lookup failed for {domain}: {e}"))?;

    for record in lookup.answers() {
        let RData::HTTPS(https) = &record.data else {
            continue;
        };
        let (priority, target_name, svc_params) = (https.0.svc_priority, https.0.target_name.clone(), https.0.svc_params.clone());
        // Skip AliasMode records (priority == 0).
        if priority == 0 {
            continue;
        }
        for (key, value) in svc_params {
            if key == SvcParamKey::EchConfigList {
                if let SvcParamValue::EchConfigList(ech_data) = value {
                    let encoded = base64_encode(&ech_data.0);
                    if encoded.is_empty() {
                        continue;
                    }
                    // Derive the public_name from the SVCB target; fall back
                    // to the queried domain itself.
                    let target = target_name.to_string();
                    let public_name = if target == "." || target.is_empty() {
                        domain.to_string()
                    } else {
                        target.trim_end_matches('.').to_string()
                    };
                    return Ok(EchConfig {
                        public_name,
                        ech_config_list: encoded,
                        retry_without_ech: true,
                    });
                }
            }
        }
    }

    Err(format!("no ECH config found in HTTPS records for {domain}"))
}

/// Fallback: query Cloudflare DoH JSON API for the HTTPS record and parse
/// the `ech` parameter out of the SVCB wire-format data field.
async fn fetch_ech_via_doh(domain: &str) -> Result<EchConfig, String> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={domain}&type=HTTPS");

    // T-207: the DoH lookup is WAN egress — ride the zone contract.
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
    if let Some(zp) = crate::browser::zone::browser_zone_reqwest_proxy()
        .map_err(|reason| format!("browser-zone egress contract refused: {reason}"))?
    {
        builder = builder.proxy(zp);
    }
    let client = builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DoH request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("DoH returned HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("DoH response parse failed: {e}"))?;

    // Cloudflare JSON DNS response shape:
    //   { "Answer": [ { "type": 65, "data": "1 . alpn=h2,h3 ech=AAAA..." } ] }
    let answers = body["Answer"]
        .as_array()
        .ok_or_else(|| format!("DoH response has no Answer array for {domain}"))?;

    for answer in answers {
        let record_type = answer["type"].as_u64().unwrap_or(0);
        if record_type != 65 {
            // Not an HTTPS record.
            continue;
        }
        let data = match answer["data"].as_str() {
            Some(d) => d,
            None => continue,
        };

        // The "data" field is a presentation-format SVCB record, e.g.:
        //   "1 . alpn=h2,h3 ech=<base64>"
        // Parse out the ech= parameter.
        if let Some(ech_value) = extract_ech_from_svcb_presentation(data) {
            if ech_value.is_empty() {
                continue;
            }
            // Try to find a target name from the presentation (second token).
            let target = data
                .split_whitespace()
                .nth(1)
                .unwrap_or(domain)
                .trim_end_matches('.');
            let public_name = if target == "." || target.is_empty() {
                domain.to_string()
            } else {
                target.to_string()
            };
            return Ok(EchConfig {
                public_name,
                ech_config_list: ech_value,
                retry_without_ech: true,
            });
        }
    }

    Err(format!(
        "no ECH config found in DoH HTTPS records for {domain}"
    ))
}

/// Extract the `ech=` value from an SVCB presentation-format string.
///
/// The presentation format looks like:
///   `1 . alpn=h2,h3 ech=<base64> ipv4hint=...`
fn extract_ech_from_svcb_presentation(data: &str) -> Option<String> {
    // Split on whitespace and look for a token starting with "ech="
    // or "echconfig=".
    for token in data.split_whitespace() {
        if let Some(val) = token.strip_prefix("ech=") {
            return Some(val.to_string());
        }
        if let Some(val) = token.strip_prefix("echconfig=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Protocol mimicry engine.
///
/// Makes scraping traffic look like a different protocol or service.
/// Based on XTLS VLESS+Reality which impersonates real TLS certificates.
#[derive(Debug, Clone)]
pub enum ProtocolMimicry {
    /// Traffic looks like normal HTTPS to a cover domain
    HttpsCover {
        /// Domain to impersonate in SNI
        cover_domain: String,
    },
    /// Traffic looks like WebSocket upgrade
    WebSocket {
        /// WebSocket upgrade path
        path: String,
    },
    /// Traffic looks like gRPC
    Grpc {
        /// gRPC service name
        service: String,
    },
    /// Traffic looks like HTTP/2 server push
    H2Push,
    /// No mimicry — direct connection
    None,
}

impl ProtocolMimicry {
    /// Get headers needed for this mimicry mode.
    pub fn extra_headers(&self) -> Vec<(String, String)> {
        match self {
            ProtocolMimicry::WebSocket { path } => vec![
                ("Upgrade".into(), "websocket".into()),
                ("Connection".into(), "Upgrade".into()),
                ("Sec-WebSocket-Version".into(), "13".into()),
                ("Sec-WebSocket-Key".into(), generate_ws_key()),
            ],
            ProtocolMimicry::Grpc { service } => vec![
                ("Content-Type".into(), "application/grpc".into()),
                ("TE".into(), "trailers".into()),
                ("Grpc-Accept-Encoding".into(), "gzip".into()),
            ],
            _ => Vec::new(),
        }
    }
}

/// Genetic algorithm strategy evolution engine.
///
/// Inspired by the Geneva project (UMD) which uses genetic algorithms
/// to automatically discover DPI bypass strategies. This struct maintains
/// a population of strategies, evaluates their fitness based on real-world
/// success/failure, and evolves new strategies via selection, crossover,
/// and mutation.
#[derive(Debug, Clone)]
pub struct GenevaStrategy {
    /// Current population of bypass strategies
    pub population: Vec<DpiBypassStrategy>,
    /// Fitness score for each strategy (higher = better)
    pub fitness_scores: Vec<f64>,
    /// Current generation number
    pub generation: u32,
}

impl GenevaStrategy {
    /// Create a new Geneva engine with a random population seeded from known strategies.
    ///
    /// The population is filled by cycling through known strategies and cloning them,
    /// giving each a unique name with its population index.
    pub fn new(population_size: usize) -> Self {
        let known = known_strategies();
        let mut population = Vec::with_capacity(population_size);
        for i in 0..population_size {
            let mut strategy = known[i % known.len()].clone();
            strategy.name = format!("{} (gen0-{})", strategy.name, i);
            population.push(strategy);
        }
        let fitness_scores = vec![0.0; population_size];
        Self {
            population,
            fitness_scores,
            generation: 0,
        }
    }

    /// Update the fitness of a strategy based on observed results.
    ///
    /// Success increases fitness, failure decreases it. Lower latency
    /// provides a bonus to reward faster strategies.
    pub fn evaluate(&mut self, strategy_idx: usize, success: bool, latency_ms: u64) {
        if strategy_idx >= self.fitness_scores.len() {
            return;
        }
        if success {
            // Reward success; bonus inversely proportional to latency
            let latency_bonus = 1.0 / (1.0 + latency_ms as f64 / 1000.0);
            self.fitness_scores[strategy_idx] += 1.0 + latency_bonus;
        } else {
            // Penalize failure
            self.fitness_scores[strategy_idx] -= 0.5;
            if self.fitness_scores[strategy_idx] < 0.0 {
                self.fitness_scores[strategy_idx] = 0.0;
            }
        }
    }

    /// Evolve the population: select top performers, crossover, and mutate.
    ///
    /// The top 50% of strategies survive. Children are created by crossing
    /// two parents' action sequences. Random mutation swaps, inserts, or
    /// removes actions from offspring.
    pub fn evolve(&mut self) {
        use rand::Rng;

        let pop_size = self.population.len();
        if pop_size < 2 {
            return;
        }

        // Sort indices by fitness (descending)
        let mut indices: Vec<usize> = (0..pop_size).collect();
        indices.sort_by(|a, b| {
            self.fitness_scores[*b]
                .partial_cmp(&self.fitness_scores[*a])
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Top half survives
        let survivors = pop_size / 2;
        let mut rng = rand::rng();

        let mut new_population = Vec::with_capacity(pop_size);
        let mut new_fitness = Vec::with_capacity(pop_size);

        // Keep survivors
        for &idx in indices.iter().take(survivors) {
            new_population.push(self.population[idx].clone());
            new_fitness.push(self.fitness_scores[idx] * 0.9); // decay
        }

        // Fill rest with crossover children
        self.generation += 1;
        let all_actions = Self::action_pool();

        while new_population.len() < pop_size {
            let parent_a = &new_population[rng.random_range(0..survivors)];
            let parent_b = &new_population[rng.random_range(0..survivors)];

            // Crossover: take first half from A, second half from B
            let mid_a = parent_a.actions.len() / 2;
            let mid_b = parent_b.actions.len() / 2;
            let mut child_actions: Vec<PacketAction> = parent_a.actions[..mid_a.max(1)].to_vec();
            child_actions.extend_from_slice(&parent_b.actions[mid_b..]);

            // Mutation: 30% chance to insert a random action
            if rng.random_range(0..100) < 30 && !all_actions.is_empty() {
                let action = all_actions[rng.random_range(0..all_actions.len())].clone();
                let pos = rng.random_range(0..=child_actions.len());
                child_actions.insert(pos, action);
            }

            // Mutation: 20% chance to remove a random action (if >1 remain)
            if rng.random_range(0..100) < 20 && child_actions.len() > 1 {
                let pos = rng.random_range(0..child_actions.len());
                child_actions.remove(pos);
            }

            let child_idx = new_population.len();
            new_population.push(DpiBypassStrategy {
                name: format!("evolved (gen{}-{})", self.generation, child_idx),
                target: parent_a.target.clone(),
                actions: child_actions,
                verified: false,
            });
            new_fitness.push(0.0);
        }

        self.population = new_population;
        self.fitness_scores = new_fitness;
    }

    /// Return a reference to the strategy with the highest fitness score.
    pub fn best_strategy(&self) -> &DpiBypassStrategy {
        let best_idx = self
            .fitness_scores
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx)
            .unwrap_or(0);
        &self.population[best_idx]
    }

    /// Pool of all possible actions for mutation.
    fn action_pool() -> Vec<PacketAction> {
        vec![
            PacketAction::Fragment { offset: 5 },
            PacketAction::Fragment { offset: 10 },
            PacketAction::Duplicate,
            PacketAction::TamperFlags { flags: 0x02 },
            PacketAction::Delay { ms: 1 },
            PacketAction::Delay { ms: 5 },
            PacketAction::SendRst,
            PacketAction::SetTtl { ttl: 1 },
            PacketAction::SetTtl { ttl: 64 },
            PacketAction::FragmentTlsHello { chunk_size: 20 },
            PacketAction::FragmentTlsHello { chunk_size: 40 },
            PacketAction::InsertGarbage { size: 10 },
            PacketAction::CorruptChecksum,
            PacketAction::ReverseFragments,
            PacketAction::OutOfBand { byte: 0x00 },
            PacketAction::Ipv6ExtHeader { header_type: 0 },
            PacketAction::TlsRecordFragment {
                max_record_size: 40,
            },
        ]
    }
}

/// Generate a random WebSocket key (base64-encoded 16 bytes).
fn generate_ws_key() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.random::<u8>()).collect();
    base64_encode(&bytes)
}

/// Simple base64 encoding (no dependency needed for 16 bytes).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Anti-bot challenge deobfuscator.
///
/// Inspired by NSA Ghidra's pattern recognition approach.
/// Identifies and decodes common anti-bot JavaScript patterns.
pub struct ChallengeDeobfuscator;

impl ChallengeDeobfuscator {
    /// Detect what type of anti-bot challenge is in the response.
    pub fn detect_challenge(body: &str) -> Option<ChallengeType> {
        let lower = body.to_lowercase();

        if lower.contains("_cf_chl_opt") || lower.contains("cf-challenge") {
            return Some(ChallengeType::Cloudflare);
        }
        if lower.contains("_abck") || lower.contains("bmak") {
            return Some(ChallengeType::Akamai);
        }
        if lower.contains("_px") || lower.contains("perimeterx") || lower.contains("/captcha") {
            return Some(ChallengeType::PerimeterX);
        }
        if lower.contains("datadome") || lower.contains("dd.js") {
            return Some(ChallengeType::DataDome);
        }
        if lower.contains("kasada") || lower.contains("cd.js") {
            return Some(ChallengeType::Kasada);
        }
        if lower.contains("incapsula") || lower.contains("reese84") {
            return Some(ChallengeType::Imperva);
        }

        None
    }

    /// Extract the challenge script URL from the response body.
    pub fn extract_challenge_url(body: &str) -> Option<String> {
        // Look for script tags with challenge-related paths
        let prefixes = [
            "/cdn-cgi/challenge-platform/",
            "/_sec/cp_challenge/",
            "/-/bmak/",
            "/px/client/",
        ];

        for prefix in &prefixes {
            if let Some(start) = body.find(prefix) {
                let remaining = &body[start..];
                if let Some(end) = remaining.find('"') {
                    return Some(remaining[..end].to_string());
                }
            }
        }

        None
    }
}

/// Types of anti-bot challenge systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Cloudflare,
    Akamai,
    PerimeterX,
    DataDome,
    Kasada,
    Imperva,
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeType::Cloudflare => write!(f, "Cloudflare"),
            ChallengeType::Akamai => write!(f, "Akamai"),
            ChallengeType::PerimeterX => write!(f, "PerimeterX"),
            ChallengeType::DataDome => write!(f, "DataDome"),
            ChallengeType::Kasada => write!(f, "Kasada"),
            ChallengeType::Imperva => write!(f, "Imperva"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_strategies() {
        let strategies = known_strategies();
        assert!(!strategies.is_empty());
        assert!(strategies.iter().any(|s| s.target == "akamai"));
    }

    #[test]
    fn test_ech_config() {
        let ech = EchConfig::cloudflare("target.com");
        assert_eq!(ech.public_name, "cloudflare-ech.com");
        assert!(!ech.is_ready()); // No config list yet
    }

    #[test]
    fn test_detect_cloudflare() {
        assert_eq!(
            ChallengeDeobfuscator::detect_challenge("<html>_cf_chl_opt</html>"),
            Some(ChallengeType::Cloudflare)
        );
    }

    #[test]
    fn test_detect_akamai() {
        assert_eq!(
            ChallengeDeobfuscator::detect_challenge("<script>var _abck</script>"),
            Some(ChallengeType::Akamai)
        );
    }

    #[test]
    fn test_detect_perimeterx() {
        assert_eq!(
            ChallengeDeobfuscator::detect_challenge("window._px = true"),
            Some(ChallengeType::PerimeterX)
        );
    }

    #[test]
    fn test_detect_none() {
        assert_eq!(
            ChallengeDeobfuscator::detect_challenge("<html><body>Hello</body></html>"),
            None
        );
    }

    #[test]
    fn test_protocol_mimicry_websocket() {
        let ws = ProtocolMimicry::WebSocket { path: "/ws".into() };
        let headers = ws.extra_headers();
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Upgrade" && v == "websocket")
        );
    }

    #[test]
    fn test_ws_key_generation() {
        let key = generate_ws_key();
        assert!(key.len() > 10);
        assert!(
            key.ends_with('=')
                || key
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '+' || c == '/')
        );
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }
}
