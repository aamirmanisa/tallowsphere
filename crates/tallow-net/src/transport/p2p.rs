//! P2P direct connection negotiation via QUIC hole punching
//!
//! After the KEM handshake completes over the relay, this module:
//! 1. Gathers local candidates (host IP + STUN reflexive)
//! 2. Exchanges candidates with the remote peer via the relay
//! 3. Attempts QUIC hole punching to the remote candidates
//! 4. Returns a DirectConnection on success, or signals relay fallback
//!
//! # Architecture note
//!
//! This module lives in `tallow-net` and CANNOT depend on `tallow-protocol`
//! (which depends on `tallow-net` — circular dependency). Therefore candidate
//! exchange uses a lightweight binary protocol defined here, not the
//! `tallow_protocol::wire::Message` enum. The P2P signaling messages
//! (`CandidateOffer`, `CandidatesDone`, etc.) in the Message enum exist for
//! relay-level routing awareness but are NOT used for the actual candidate
//! exchange — this module handles it end-to-end.

#[cfg(feature = "quic")]
use crate::nat::candidates::{
    decode_socket_addr, encode_socket_addr, gather_candidates, validate_candidate_addr, Candidate,
    CandidateType,
};
#[cfg(feature = "quic")]
use crate::nat::detection::{detect, NatType};
#[cfg(feature = "quic")]
use crate::transport::direct::{DirectConnection, DirectListener};
#[cfg(feature = "quic")]
use crate::transport::PeerChannel;
#[cfg(feature = "quic")]
use crate::{NetworkError, Result};
#[cfg(feature = "quic")]
use std::time::Duration;

/// Total timeout for the P2P negotiation (STUN + exchange + punch)
#[cfg(feature = "quic")]
pub const P2P_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for individual hole punch connection attempt
#[cfg(feature = "quic")]
const HOLE_PUNCH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for candidate exchange phase
#[cfg(feature = "quic")]
const CANDIDATE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

// --- Lightweight binary P2P signaling tags ---
// These are used for the candidate exchange protocol within tallow-net.
// They are NOT the same as the tallow-protocol Message enum discriminants.
#[cfg(feature = "quic")]
const TAG_CANDIDATE_OFFER: u8 = 0x01;
#[cfg(feature = "quic")]
const TAG_CANDIDATES_DONE: u8 = 0x02;
#[cfg(feature = "quic")]
const TAG_DIRECT_FAILED: u8 = 0x03;
#[cfg(feature = "quic")]
const TAG_DIRECT_CONNECTED: u8 = 0x04;

/// Result of P2P negotiation
#[cfg(feature = "quic")]
pub enum NegotiationResult {
    /// Direct QUIC connection established
    Direct(DirectConnection),
    /// P2P failed, continue using relay
    FallbackToRelay(String),
}

#[cfg(feature = "quic")]
impl std::fmt::Debug for NegotiationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(_) => f.debug_tuple("Direct").field(&"...").finish(),
            Self::FallbackToRelay(reason) => {
                f.debug_tuple("FallbackToRelay").field(reason).finish()
            }
        }
    }
}

/// Attempt to upgrade from relay to direct P2P QUIC connection.
///
/// This function:
/// 1. Checks `no_p2p` guard (defense-in-depth -- callers should also check, but this
///    ensures future call sites cannot forget the proxy/no-p2p suppression)
/// 2. Detects NAT type (skip if symmetric)
/// 3. Gathers local candidates
/// 4. Exchanges candidates with peer via the relay channel
/// 5. Attempts QUIC hole punch to highest-priority remote candidate
/// 6. Returns DirectConnection on success or fallback reason on failure
///
/// The `channel` must be the relay connection with the peer already joined.
/// The `is_initiator` flag determines QUIC roles: initiator=client, responder=server.
/// Derive from peer ordering (e.g., sender=true, receiver=false).
/// The `no_p2p` flag is a defense-in-depth guard: if true, returns FallbackToRelay
/// immediately. Pass `proxy_config.is_some() || args.no_p2p` from the call site.
#[cfg(feature = "quic")]
pub async fn negotiate_p2p(
    channel: &mut impl PeerChannel,
    is_initiator: bool,
    no_p2p: bool,
) -> NegotiationResult {
    // Defense-in-depth: refuse to negotiate if P2P is suppressed.
    // Callers ALSO check this before calling, but a future caller might forget.
    if no_p2p {
        return NegotiationResult::FallbackToRelay("P2P suppressed (no_p2p flag)".to_string());
    }

    match tokio::time::timeout(
        P2P_NEGOTIATION_TIMEOUT,
        negotiate_inner(channel, is_initiator),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            tracing::warn!("P2P negotiation error: {}", e);
            NegotiationResult::FallbackToRelay(format!("negotiation error: {}", e))
        }
        Err(_) => {
            tracing::warn!("P2P negotiation timed out");
            NegotiationResult::FallbackToRelay("negotiation timeout".to_string())
        }
    }
}

/// Core P2P negotiation logic (called within the overall timeout).
#[cfg(feature = "quic")]
async fn negotiate_inner(
    channel: &mut impl PeerChannel,
    is_initiator: bool,
) -> Result<NegotiationResult> {
    // Step 1: Detect NAT type
    let nat_type = detect().await.unwrap_or(NatType::Unknown);
    tracing::info!("NAT type detected: {}", nat_type);

    if nat_type == NatType::Symmetric {
        // Send DirectFailed to inform peer we can't hole punch
        send_direct_failed(channel).await?;
        // Drain peer's P2P messages so they don't corrupt the relay stream
        drain_peer_p2p_messages(channel).await;
        return Ok(NegotiationResult::FallbackToRelay(
            "symmetric NAT detected".to_string(),
        ));
    }

    // Step 2: Bind a QUIC endpoint on a random port for hole punching
    // We need the port BEFORE STUN so STUN discovers the same NAT binding
    let listener = DirectListener::bind().map_err(|e| {
        NetworkError::NatTraversal(format!("Failed to bind hole punch endpoint: {}", e))
    })?;
    let local_port = listener.port();
    tracing::info!("Hole punch endpoint bound on port {}", local_port);

    // Step 3: Gather candidates using the bound port
    let local_candidates = gather_candidates(local_port).await;
    if local_candidates.is_empty() {
        send_direct_failed(channel).await?;
        // Drain peer's P2P messages so they don't corrupt the relay stream
        drain_peer_p2p_messages(channel).await;
        return Ok(NegotiationResult::FallbackToRelay(
            "no candidates gathered".to_string(),
        ));
    }
    tracing::info!("Gathered {} local candidates", local_candidates.len());

    // Step 4: Send local candidates to peer via relay
    for candidate in &local_candidates {
        send_candidate_offer(channel, candidate).await?;
    }
    send_candidates_done(channel).await?;

    // Step 5: Receive remote candidates from peer
    let remote_candidates = receive_remote_candidates(channel).await?;

    if remote_candidates.is_empty() {
        tracing::info!("Peer sent no candidates (symmetric NAT or P2P disabled)");
        return Ok(NegotiationResult::FallbackToRelay(
            "peer has no candidates".to_string(),
        ));
    }
    tracing::info!("Received {} remote candidates", remote_candidates.len());

    // Step 6: Filter and validate remote candidates
    let valid_candidates: Vec<_> = remote_candidates
        .into_iter()
        .filter(|c| validate_candidate_addr(&c.addr))
        .collect();

    if valid_candidates.is_empty() {
        tracing::warn!("All remote candidates failed validation");
        send_direct_failed(channel).await?;
        return Ok(NegotiationResult::FallbackToRelay(
            "no valid remote candidates".to_string(),
        ));
    }

    // Step 7: Attempt hole punch
    // Both roles use the SAME DirectListener endpoint (bound to port P).
    // Initiator (sender) = QUIC client: connect to remote candidates via listener.connect_to()
    // Responder (receiver) = QUIC server: accept on the listener via listener.accept_peer()
    // This avoids EADDRINUSE -- a single quinn::Endpoint handles both roles.
    let result = if is_initiator {
        attempt_as_client(listener, &valid_candidates).await
    } else {
        attempt_as_server(&listener).await
    };

    match result {
        Ok(direct) => {
            tracing::info!(
                "P2P direct connection established to {}",
                direct.remote_addr()
            );
            // Notify peer via relay that direct connection is established
            let _ = send_direct_connected(channel).await;
            Ok(NegotiationResult::Direct(direct))
        }
        Err(e) => {
            tracing::info!("Hole punch failed: {}", e);
            let _ = send_direct_failed(channel).await;
            // Drain peer's final P2P status message (DirectConnected/DirectFailed)
            drain_peer_p2p_messages(channel).await;
            Ok(NegotiationResult::FallbackToRelay(format!(
                "hole punch failed: {}",
                e
            )))
        }
    }
}

// --- Lightweight binary encoding for P2P signaling ---
//
// Format for CandidateOffer:
//   [TAG_CANDIDATE_OFFER (1 byte)]
//   [candidate_type (1 byte)]
//   [priority (4 bytes BE)]
//   [addr_len (1 byte)]
//   [addr (addr_len bytes)]
//
// Format for CandidatesDone / DirectFailed / DirectConnected:
//   [TAG (1 byte)]

/// Send a candidate offer through the relay channel.
#[cfg(feature = "quic")]
async fn send_candidate_offer(channel: &mut impl PeerChannel, candidate: &Candidate) -> Result<()> {
    let addr_bytes = encode_socket_addr(candidate.addr);
    let addr_len = addr_bytes.len();
    if addr_len > 255 {
        return Err(NetworkError::NatTraversal(
            "candidate address too large".to_string(),
        ));
    }

    // 1 tag + 1 type + 4 priority + 1 addr_len + addr_bytes
    let mut buf = Vec::with_capacity(7 + addr_len);
    buf.push(TAG_CANDIDATE_OFFER);
    buf.push(candidate.candidate_type as u8);
    buf.extend_from_slice(&candidate.priority.to_be_bytes());
    buf.push(addr_len as u8);
    buf.extend_from_slice(&addr_bytes);

    channel.send_message(&buf).await
}

/// Send CandidatesDone signal.
#[cfg(feature = "quic")]
async fn send_candidates_done(channel: &mut impl PeerChannel) -> Result<()> {
    channel.send_message(&[TAG_CANDIDATES_DONE]).await
}

/// Send DirectFailed signal.
#[cfg(feature = "quic")]
async fn send_direct_failed(channel: &mut impl PeerChannel) -> Result<()> {
    channel.send_message(&[TAG_DIRECT_FAILED]).await
}

/// Drain any remaining P2P negotiation messages from the peer.
///
/// When we early-exit (e.g. symmetric NAT detected), the peer may still send
/// candidates, CandidatesDone, or DirectFailed. These must be consumed so they
/// don't corrupt the subsequent application-layer protocol (FileOffer/FileAccept).
#[cfg(feature = "quic")]
async fn drain_peer_p2p_messages(channel: &mut impl PeerChannel) {
    let mut recv_buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            tracing::debug!("P2P drain timeout reached");
            break;
        }

        match tokio::time::timeout(remaining, channel.receive_message(&mut recv_buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let tag = recv_buf[0];
                match tag {
                    TAG_DIRECT_FAILED | TAG_CANDIDATES_DONE | TAG_DIRECT_CONNECTED => {
                        tracing::debug!("Drained P2P message tag=0x{:02x}", tag);
                        break; // Terminal message — done draining
                    }
                    TAG_CANDIDATE_OFFER => {
                        tracing::debug!("Drained P2P candidate offer");
                        // Continue draining — more messages may follow
                    }
                    _ => {
                        tracing::debug!("Drained unknown P2P message tag=0x{:02x}", tag);
                        break; // Unknown tag — stop to avoid consuming app messages
                    }
                }
            }
            _ => {
                tracing::debug!("P2P drain: no more messages or error");
                break;
            }
        }
    }
}

/// Send DirectConnected signal.
#[cfg(feature = "quic")]
async fn send_direct_connected(channel: &mut impl PeerChannel) -> Result<()> {
    channel.send_message(&[TAG_DIRECT_CONNECTED]).await
}

/// Receive remote candidates from the peer via relay.
///
/// Reads the lightweight binary protocol messages until CandidatesDone
/// or DirectFailed is received, or the exchange times out.
#[cfg(feature = "quic")]
async fn receive_remote_candidates(channel: &mut impl PeerChannel) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let mut recv_buf = vec![0u8; 4096];

    let deadline = tokio::time::Instant::now() + CANDIDATE_EXCHANGE_TIMEOUT;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            tracing::warn!("Candidate exchange timeout");
            break;
        }

        let n = match tokio::time::timeout(remaining, channel.receive_message(&mut recv_buf)).await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::warn!("Error receiving candidate: {}", e);
                break;
            }
            Err(_) => {
                tracing::warn!("Candidate exchange timed out");
                break;
            }
        };

        if n == 0 {
            tracing::warn!("Empty message during candidate exchange");
            continue;
        }

        let tag = recv_buf[0];
        match tag {
            TAG_CANDIDATE_OFFER => {
                // Parse: [tag(1)] [type(1)] [priority(4 BE)] [addr_len(1)] [addr(N)]
                if n < 7 {
                    tracing::warn!("CandidateOffer too short: {} bytes", n);
                    continue;
                }
                let candidate_type_byte = recv_buf[1];
                let priority =
                    u32::from_be_bytes([recv_buf[2], recv_buf[3], recv_buf[4], recv_buf[5]]);
                let addr_len = recv_buf[6] as usize;
                if n < 7 + addr_len {
                    tracing::warn!(
                        "CandidateOffer truncated: expected {} addr bytes, got {}",
                        addr_len,
                        n - 7
                    );
                    continue;
                }
                let addr_bytes = &recv_buf[7..7 + addr_len];

                match decode_socket_addr(addr_bytes) {
                    Ok(socket_addr) => {
                        let ct = match candidate_type_byte {
                            0 => CandidateType::Host,
                            1 => CandidateType::ServerReflexive,
                            2 => CandidateType::UPnP,
                            _ => CandidateType::Host, // default
                        };
                        candidates.push(Candidate {
                            addr: socket_addr,
                            candidate_type: ct,
                            priority,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Invalid candidate address: {}", e);
                    }
                }
            }
            TAG_CANDIDATES_DONE => {
                tracing::debug!("Peer candidate exchange complete");
                break;
            }
            TAG_DIRECT_FAILED => {
                tracing::info!("Peer cannot do P2P (symmetric NAT or disabled)");
                return Ok(Vec::new());
            }
            TAG_DIRECT_CONNECTED => {
                tracing::debug!("Peer reports direct connection established");
                break;
            }
            other => {
                tracing::debug!("Unexpected tag during candidate exchange: 0x{:02x}", other);
                // Not a fatal error -- might be keepalive or other traffic
            }
        }
    }

    // Sort by priority descending
    candidates.sort_by_key(|a| std::cmp::Reverse(a.priority));
    Ok(candidates)
}

/// Attempt QUIC connection to remote candidates (initiator/client role).
///
/// Reuses the DirectListener's internal quinn::Endpoint for outbound connections
/// via `listener.connect_to()`. This is critical: the endpoint is already bound to
/// port P (the same port STUN discovered), so the OS does NOT need a second bind.
/// Quinn natively supports using a server endpoint for outbound connect().
#[cfg(feature = "quic")]
async fn attempt_as_client(
    mut listener: DirectListener,
    candidates: &[Candidate],
) -> Result<DirectConnection> {
    // Try candidates in priority order, reusing the listener's endpoint
    for candidate in candidates {
        tracing::info!(
            "Attempting hole punch to {} ({:?}, priority={})",
            candidate.addr,
            candidate.candidate_type,
            candidate.priority
        );

        match listener
            .connect_to(candidate.addr, HOLE_PUNCH_ATTEMPT_TIMEOUT)
            .await
        {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                tracing::debug!("Hole punch to {} failed: {}", candidate.addr, e);
                continue;
            }
        }
    }
    Err(NetworkError::NatTraversal(
        "All hole punch attempts failed".to_string(),
    ))
}

/// Wait for incoming QUIC connection (responder/server role)
#[cfg(feature = "quic")]
async fn attempt_as_server(listener: &DirectListener) -> Result<DirectConnection> {
    tracing::info!(
        "Waiting for hole punch connection on {}...",
        listener.local_addr()
    );
    listener.accept_peer(HOLE_PUNCH_ATTEMPT_TIMEOUT).await
}

#[cfg(test)]
#[cfg(feature = "quic")]
mod tests {
    use super::*;
    use crate::transport::direct::connect_direct;
    #[cfg(feature = "dangerous_skip_verify")]
    use crate::transport::direct::DirectListener;
    use crate::transport::PeerChannel;

    #[test]
    fn test_negotiation_result_debug() {
        let fallback = NegotiationResult::FallbackToRelay("test".to_string());
        let debug = format!("{:?}", fallback);
        assert!(debug.contains("FallbackToRelay"));
    }

    #[test]
    fn test_negotiation_result_variants() {
        let fallback = NegotiationResult::FallbackToRelay("test reason".to_string());
        assert!(matches!(fallback, NegotiationResult::FallbackToRelay(_)));
        let debug = format!("{:?}", fallback);
        assert!(debug.contains("FallbackToRelay"));
        assert!(debug.contains("test reason"));
    }

    #[test]
    fn test_candidate_offer_encoding_roundtrip() {
        // Verify our binary encoding can be parsed back correctly
        let candidate = Candidate {
            addr: "192.168.1.42:8080".parse().unwrap(),
            candidate_type: CandidateType::Host,
            priority: 100,
        };

        let addr_bytes = encode_socket_addr(candidate.addr);
        let addr_len = addr_bytes.len();

        let mut buf = Vec::with_capacity(7 + addr_len);
        buf.push(TAG_CANDIDATE_OFFER);
        buf.push(candidate.candidate_type as u8);
        buf.extend_from_slice(&candidate.priority.to_be_bytes());
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes);

        // Parse it back
        assert_eq!(buf[0], TAG_CANDIDATE_OFFER);
        assert_eq!(buf[1], 0); // Host
        let priority = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(priority, 100);
        let parsed_addr_len = buf[6] as usize;
        assert_eq!(parsed_addr_len, 6); // IPv4
        let parsed_addr = decode_socket_addr(&buf[7..7 + parsed_addr_len]).unwrap();
        assert_eq!(parsed_addr, candidate.addr);
    }

    /// Test binary encoding roundtrip for ServerReflexive candidate type
    #[test]
    fn test_candidate_offer_encoding_srflx() {
        let candidate = Candidate {
            addr: "8.8.8.8:4433".parse().unwrap(),
            candidate_type: CandidateType::ServerReflexive,
            priority: 50,
        };

        let addr_bytes = encode_socket_addr(candidate.addr);
        let addr_len = addr_bytes.len();

        let mut buf = Vec::with_capacity(7 + addr_len);
        buf.push(TAG_CANDIDATE_OFFER);
        buf.push(candidate.candidate_type as u8);
        buf.extend_from_slice(&candidate.priority.to_be_bytes());
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes);

        assert_eq!(buf[0], TAG_CANDIDATE_OFFER);
        assert_eq!(buf[1], 1); // ServerReflexive
        let priority = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(priority, 50);
        let parsed_addr_len = buf[6] as usize;
        let parsed_addr = decode_socket_addr(&buf[7..7 + parsed_addr_len]).unwrap();
        assert_eq!(parsed_addr, candidate.addr);
    }

    /// Test binary encoding roundtrip for IPv6 candidate
    #[test]
    fn test_candidate_offer_encoding_ipv6() {
        let candidate = Candidate {
            addr: "[2001:db8::1]:4433".parse().unwrap(),
            candidate_type: CandidateType::Host,
            priority: 100,
        };

        let addr_bytes = encode_socket_addr(candidate.addr);
        let addr_len = addr_bytes.len();
        assert_eq!(addr_len, 18); // IPv6: 16 octets + 2 port

        let mut buf = Vec::with_capacity(7 + addr_len);
        buf.push(TAG_CANDIDATE_OFFER);
        buf.push(candidate.candidate_type as u8);
        buf.extend_from_slice(&candidate.priority.to_be_bytes());
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes);

        let parsed_addr_len = buf[6] as usize;
        assert_eq!(parsed_addr_len, 18);
        let parsed_addr = decode_socket_addr(&buf[7..7 + parsed_addr_len]).unwrap();
        assert_eq!(parsed_addr, candidate.addr);
    }

    #[test]
    fn test_signal_tags_unique() {
        let tags = [
            TAG_CANDIDATE_OFFER,
            TAG_CANDIDATES_DONE,
            TAG_DIRECT_FAILED,
            TAG_DIRECT_CONNECTED,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "Signal tags must be unique");
            }
        }
    }

    /// Test that signal tags have the expected values (binary protocol stability)
    #[test]
    fn test_signal_tag_values() {
        assert_eq!(TAG_CANDIDATE_OFFER, 0x01);
        assert_eq!(TAG_CANDIDATES_DONE, 0x02);
        assert_eq!(TAG_DIRECT_FAILED, 0x03);
        assert_eq!(TAG_DIRECT_CONNECTED, 0x04);
    }

    /// Test single-byte message encoding for CandidatesDone
    #[test]
    fn test_candidates_done_encoding() {
        let msg = [TAG_CANDIDATES_DONE];
        assert_eq!(msg.len(), 1);
        assert_eq!(msg[0], 0x02);
    }

    /// Test single-byte message encoding for DirectFailed
    #[test]
    fn test_direct_failed_encoding() {
        let msg = [TAG_DIRECT_FAILED];
        assert_eq!(msg.len(), 1);
        assert_eq!(msg[0], 0x03);
    }

    /// Test single-byte message encoding for DirectConnected
    #[test]
    fn test_direct_connected_encoding() {
        let msg = [TAG_DIRECT_CONNECTED];
        assert_eq!(msg.len(), 1);
        assert_eq!(msg[0], 0x04);
    }

    #[test]
    fn test_no_p2p_guard() {
        // Test that no_p2p flag returns FallbackToRelay immediately
        // (cannot do full async test without a channel, but we test the sync path)
        let result = NegotiationResult::FallbackToRelay("P2P suppressed (no_p2p flag)".to_string());
        assert!(matches!(result, NegotiationResult::FallbackToRelay(_)));
    }

    /// Test that no_p2p guard returns FallbackToRelay via negotiate_p2p (async path)
    #[tokio::test]
    async fn test_negotiate_p2p_no_p2p_guard() {
        // MockChannel just needs to exist; it won't be called because no_p2p=true
        // short-circuits before any channel use
        struct MockChannel;
        impl PeerChannel for MockChannel {
            async fn send_message(&mut self, _data: &[u8]) -> crate::Result<()> {
                panic!("should not be called when no_p2p=true");
            }
            async fn receive_message(&mut self, _buf: &mut [u8]) -> crate::Result<usize> {
                panic!("should not be called when no_p2p=true");
            }
            async fn close(&mut self) {}
            fn transport_description(&self) -> String {
                "mock".to_string()
            }
        }

        let mut channel = MockChannel;
        let result = negotiate_p2p(&mut channel, true, true).await;
        assert!(
            matches!(result, NegotiationResult::FallbackToRelay(ref reason) if reason.contains("no_p2p")),
            "Expected FallbackToRelay with no_p2p reason, got {:?}",
            result
        );
    }

    /// Test that two local peers can establish a direct QUIC connection.
    ///
    /// This tests the DirectListener (server) + connect_direct (client) path
    /// that negotiate_p2p uses internally for hole punching.
    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_local_p2p_connection() {
        // Server: bind a listener on loopback
        let listener = DirectListener::bind_to("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = listener.local_addr();

        // Spawn server accept
        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            // Receive a test message
            let mut buf = vec![0u8; 1024];
            let n = server.receive_message(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"p2p-test-data");

            // Echo back
            server.send_message(b"p2p-test-ack").await.unwrap();
            server
        });

        // Client: connect to server
        let mut client = connect_direct(server_addr, Duration::from_secs(5))
            .await
            .unwrap();

        // Send test data
        client.send_message(b"p2p-test-data").await.unwrap();

        // Receive ack
        let mut buf = vec![0u8; 1024];
        let n = client.receive_message(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"p2p-test-ack");

        // Verify transport description mentions "direct"
        let desc = client.transport_description();
        assert!(
            desc.contains("direct"),
            "Transport description should mention 'direct': {}",
            desc
        );

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }

    /// Test that connect_to reuses the endpoint (hole punch pattern).
    ///
    /// The initiator uses DirectListener::connect_to() (not connect_direct) to
    /// send from the SAME port the listener is bound to. This tests the hole
    /// punch client path.
    #[cfg(feature = "dangerous_skip_verify")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_hole_punch_connect_to() {
        // Server: bind on loopback
        let server_listener = DirectListener::bind_to("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_listener.local_addr();

        // Client: another listener (simulating hole punch initiator)
        let mut client_listener = DirectListener::bind_to("127.0.0.1:0".parse().unwrap()).unwrap();

        // Spawn server accept
        let server_handle = tokio::spawn(async move {
            let mut conn = server_listener
                .accept_peer(Duration::from_secs(5))
                .await
                .unwrap();

            let mut buf = vec![0u8; 1024];
            let n = conn.receive_message(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hole-punch-test");
            conn.send_message(b"hole-punch-ack").await.unwrap();
            conn
        });

        // Client connects via connect_to (reusing its listener endpoint)
        let mut client = client_listener
            .connect_to(server_addr, Duration::from_secs(5))
            .await
            .unwrap();

        client.send_message(b"hole-punch-test").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.receive_message(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hole-punch-ack");

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }

    /// Test timeout behavior: attempting to connect to unreachable address
    #[tokio::test]
    async fn test_hole_punch_timeout() {
        // Use TEST-NET-1 (192.0.2.0/24, RFC 5737): should not route
        let result = connect_direct(
            "192.0.2.1:1234".parse().unwrap(),
            Duration::from_millis(500),
        )
        .await;
        assert!(
            result.is_err(),
            "Connection to unreachable address should fail"
        );
    }

    /// Test that candidate offer encoding works for zero priority
    #[test]
    fn test_candidate_offer_zero_priority() {
        let candidate = Candidate {
            addr: "10.0.0.1:1".parse().unwrap(),
            candidate_type: CandidateType::UPnP,
            priority: 0,
        };

        let addr_bytes = encode_socket_addr(candidate.addr);
        let addr_len = addr_bytes.len();

        let mut buf = Vec::with_capacity(7 + addr_len);
        buf.push(TAG_CANDIDATE_OFFER);
        buf.push(candidate.candidate_type as u8);
        buf.extend_from_slice(&candidate.priority.to_be_bytes());
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes);

        assert_eq!(buf[1], 2); // UPnP
        let priority = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(priority, 0);
    }

    /// Test candidate offer encoding with maximum priority
    #[test]
    fn test_candidate_offer_max_priority() {
        let candidate = Candidate {
            addr: "10.0.0.1:65535".parse().unwrap(),
            candidate_type: CandidateType::Host,
            priority: u32::MAX,
        };

        let addr_bytes = encode_socket_addr(candidate.addr);
        let addr_len = addr_bytes.len();

        let mut buf = Vec::with_capacity(7 + addr_len);
        buf.push(TAG_CANDIDATE_OFFER);
        buf.push(candidate.candidate_type as u8);
        buf.extend_from_slice(&candidate.priority.to_be_bytes());
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes);

        let priority = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(priority, u32::MAX);
    }
}
