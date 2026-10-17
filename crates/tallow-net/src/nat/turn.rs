//! TURN client for relayed connections
//!
//! Provides relay-based NAT traversal via the TURN protocol (RFC 5766).
//! In Tallow v1, TURN is available as a fallback when direct connections
//! and UDP hole punching both fail. The primary relay mechanism is
//! Tallow's own relay server.

use crate::{NetworkError, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

/// STUN magic cookie (RFC 5389 §6).
const MAGIC_COOKIE: u32 = 0x2112_A442;
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
/// UDP transport identifier (RFC 5766 §14.7).
const REQUESTED_UDP: u8 = 17;

/// TURN client for relayed connections
#[derive(Debug)]
pub struct TurnClient {
    /// TURN server address
    server: SocketAddr,
    /// TURN credentials (zeroized on drop per M-79)
    username: Zeroizing<String>,
    /// TURN password (used for MESSAGE-INTEGRITY in authenticated requests).
    /// Wrapped in `Zeroizing` to ensure credential material is wiped from
    /// memory when the client is dropped.
    #[allow(dead_code)]
    password: Zeroizing<String>,
    /// Allocated relay address (if any)
    relay_addr: Option<SocketAddr>,
    /// UDP socket for TURN communication
    socket: Option<UdpSocket>,
}

impl TurnClient {
    /// Create a new TURN client
    pub fn new(server: SocketAddr, username: String, password: String) -> Self {
        Self {
            server,
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            relay_addr: None,
            socket: None,
        }
    }

    /// Allocate a relay address from the TURN server (RFC 5766 §6).
    ///
    /// Sends an Allocate request with `REQUESTED-TRANSPORT=UDP`. A TURN server
    /// answers an unauthenticated request with `401 Unauthorized` carrying a
    /// `REALM` and `NONCE`; the request is then repeated with `USERNAME`,
    /// `REALM`, `NONCE` and a `MESSAGE-INTEGRITY` attribute keyed by
    /// `MD5(username:realm:password)` (long-term credential mechanism,
    /// RFC 5389 §10.2). The success response's `XOR-RELAYED-ADDRESS` is parsed
    /// and returned — the server's own address is never reported as the relay.
    pub async fn allocate(&mut self) -> Result<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| NetworkError::NatTraversal(format!("Failed to bind UDP socket: {}", e)))?;

        // 1. Unauthenticated Allocate: establish the 401 challenge.
        let txn = rand::random::<[u8; 12]>();
        let request = build_allocate_request(&txn, None, None, None, 600);
        socket.send_to(&request, self.server).await.map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to send TURN allocate: {}", e))
        })?;

        let response = receive_message(&socket).await?;
        let challenge = match response_type(&response) {
            ALLOCATE_SUCCESS => {
                // Some servers allow anonymous allocation; accept it but still
                // require a relayed address.
                let addr = xor_relayed_address(&response, &txn).ok_or_else(|| {
                    NetworkError::NatTraversal(
                        "TURN success response has no XOR-RELAYED-ADDRESS".to_string(),
                    )
                })?;
                self.socket = Some(socket);
                self.relay_addr = Some(addr);
                return Ok(addr);
            }
            ALLOCATE_ERROR => response,
            other => {
                return Err(NetworkError::NatTraversal(format!(
                    "Unexpected TURN response type: 0x{:04x}",
                    other
                )));
            }
        };

        let (code, realm, nonce) = parse_error_challenge(&challenge).ok_or_else(|| {
            NetworkError::NatTraversal("TURN 401 challenge missing ERROR-CODE/REALM/NONCE".into())
        })?;
        if code != 401 {
            return Err(NetworkError::NatTraversal(format!(
                "TURN allocation rejected with error {} (check credentials)",
                code
            )));
        }

        // 2. Authenticated Allocate with MESSAGE-INTEGRITY.
        let key = long_term_key(self.username.as_str(), &realm, self.password.as_str());
        let txn2 = rand::random::<[u8; 12]>();
        let authenticated =
            build_allocate_request(&txn2, Some(self.username.as_str()), Some(&realm), Some(&nonce), 600);
        let mut authenticated = authenticated;
        add_message_integrity(&mut authenticated, &key);

        socket.send_to(&authenticated, self.server).await.map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to send authenticated TURN allocate: {}", e))
        })?;

        let response = receive_message(&socket).await?;
        match response_type(&response) {
            ALLOCATE_SUCCESS => {
                if response_txn(&response) != txn2 {
                    return Err(NetworkError::NatTraversal(
                        "TURN response transaction id does not match the request".to_string(),
                    ));
                }
                let addr = xor_relayed_address(&response, &txn2).ok_or_else(|| {
                    NetworkError::NatTraversal(
                        "TURN success response has no XOR-RELAYED-ADDRESS".to_string(),
                    )
                })?;
                tracing::info!(
                    "TURN allocation successful: relay {} via {} (user: {})",
                    addr,
                    self.server,
                    self.username.as_str()
                );
                self.socket = Some(socket);
                self.relay_addr = Some(addr);
                Ok(addr)
            }
            ALLOCATE_ERROR => {
                let code = parse_error_challenge(&response).map(|(c, _, _)| c).unwrap_or(0);
                Err(NetworkError::NatTraversal(format!(
                    "TURN allocation rejected with error {} (check credentials)",
                    code
                )))
            }
            other => Err(NetworkError::NatTraversal(format!(
                "Unexpected TURN response type: 0x{:04x}",
                other
            ))),
        }
    }

    /// Send data through the TURN relay to a peer.
    ///
    /// Wraps data in a TURN Send indication (RFC 5766 Section 10).
    pub async fn send(&self, data: &[u8], to: SocketAddr) -> Result<()> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            NetworkError::NatTraversal("TURN client has no bound socket".to_string())
        })?;

        // Build Send indication (0x0016)
        // XOR-PEER-ADDRESS attribute (0x0012) + DATA attribute (0x0013)
        let peer_attr = encode_xor_address(to);
        let data_attr = encode_data_attribute(data);

        let attr_len = peer_attr.len() + data_attr.len();
        let txn_id: [u8; 12] = rand::random();

        let mut msg = Vec::with_capacity(20 + attr_len);
        msg.extend_from_slice(&0x0016u16.to_be_bytes()); // Send Indication
        msg.extend_from_slice(&(attr_len as u16).to_be_bytes());
        msg.extend_from_slice(&0x2112A442u32.to_be_bytes());
        msg.extend_from_slice(&txn_id);
        msg.extend_from_slice(&peer_attr);
        msg.extend_from_slice(&data_attr);

        socket
            .send_to(&msg, self.server)
            .await
            .map_err(|e| NetworkError::NatTraversal(format!("TURN send failed: {}", e)))?;

        Ok(())
    }

    /// Get the allocated relay address, if any
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.relay_addr
    }
}

/// Append one STUN attribute, padded to a 4-byte boundary.
fn push_attr(msg: &mut Vec<u8>, typ: u16, value: &[u8]) {
    msg.extend_from_slice(&typ.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(value);
    while msg.len() % 4 != 0 {
        msg.push(0);
    }
}

/// Encode an Allocate request (RFC 5766 §6.1).
fn build_allocate_request(
    txn: &[u8; 12],
    username: Option<&str>,
    realm: Option<&str>,
    nonce: Option<&str>,
    lifetime: u32,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, ATTR_REQUESTED_TRANSPORT, &[REQUESTED_UDP, 0, 0, 0]);
    if let Some(value) = username {
        push_attr(&mut attrs, ATTR_USERNAME, value.as_bytes());
    }
    if let Some(value) = realm {
        push_attr(&mut attrs, ATTR_REALM, value.as_bytes());
    }
    if let Some(value) = nonce {
        push_attr(&mut attrs, ATTR_NONCE, value.as_bytes());
    }
    push_attr(&mut attrs, ATTR_LIFETIME, &lifetime.to_be_bytes());

    let mut msg = Vec::with_capacity(20 + attrs.len());
    msg.extend_from_slice(&ALLOCATE_REQUEST.to_be_bytes());
    msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txn);
    msg.extend_from_slice(&attrs);
    msg
}

/// RFC 1321 MD5. Local implementation because `md-5 0.10` is not in the
/// offline crate cache and the long-term key needs exactly this digest.
fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let mut k = [0u32; 64];
    for (index, slot) in k.iter_mut().enumerate() {
        *slot = ((index as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32;
    }

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    let mut message = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in message.chunks_exact(64) {
        let mut m = [0u32; 16];
        for word in 0..16 {
            let start = word * 4;
            m[word] = u32::from_le_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for round in 0..64 {
            let (f, g) = match round {
                0..=15 => ((b & c) | (!b & d), round),
                16..=31 => ((d & b) | (!d & c), (5 * round + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * round + 5) % 16),
                _ => (c ^ (b | !d), (7 * round) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(k[round])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[round]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// Long-term credential key: `MD5(username ":" realm ":" password)`
/// (RFC 5389 §10.2.2).
fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    md5_digest(format!("{username}:{realm}:{password}").as_bytes())
}

/// Append MESSAGE-INTEGRITY (HMAC-SHA1 over the message with the attribute
/// value zeroed) and fix the header length to include it (RFC 5389 §15.4).
fn add_message_integrity(msg: &mut Vec<u8>, key: &[u8]) {
    let offset = msg.len();
    push_attr(msg, ATTR_MESSAGE_INTEGRITY, &[0u8; 20]);
    let total = (msg.len() - 20) as u16;
    msg[2..4].copy_from_slice(&total.to_be_bytes());

    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    msg[offset + 4..offset + 24].copy_from_slice(&tag);
}

async fn receive_message(socket: &UdpSocket) -> Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((len, _from))) if len >= 20 => Ok(buf[..len].to_vec()),
        Ok(Ok(_)) => Err(NetworkError::NatTraversal(
            "TURN response too short".to_string(),
        )),
        Ok(Err(e)) => Err(NetworkError::NatTraversal(format!(
            "TURN receive error: {}",
            e
        ))),
        Err(_) => Err(NetworkError::NatTraversal(
            "TURN allocation timed out".to_string(),
        )),
    }
}

fn response_type(msg: &[u8]) -> u16 {
    u16::from_be_bytes([msg[0], msg[1]])
}

fn response_txn(msg: &[u8]) -> [u8; 12] {
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&msg[8..20]);
    txn
}

fn attributes(msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut offset = 20usize;
    while offset + 4 <= msg.len() {
        let typ = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let len = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]) as usize;
        let start = offset + 4;
        let end = start.saturating_add(len).min(msg.len());
        out.push((typ, msg[start..end].to_vec()));
        offset = start + len + ((4 - (len % 4)) % 4);
    }
    out
}

/// `(error code, realm, nonce)` from a 401 challenge.
fn parse_error_challenge(msg: &[u8]) -> Option<(u16, String, String)> {
    let mut code = None;
    let mut realm = None;
    let mut nonce = None;
    for (typ, value) in attributes(msg) {
        match typ {
            ATTR_ERROR_CODE if value.len() >= 4 => {
                let class = (value[2] & 0x07) as u16;
                let number = value[3] as u16;
                code = Some(class * 100 + number);
            }
            ATTR_REALM => realm = String::from_utf8(value).ok(),
            ATTR_NONCE => nonce = String::from_utf8(value).ok(),
            _ => {}
        }
    }
    Some((code?, realm?, nonce?))
}

/// Parse XOR-RELAYED-ADDRESS (RFC 5766 §14.5).
fn xor_relayed_address(msg: &[u8], txn: &[u8; 12]) -> Option<SocketAddr> {
    for (typ, value) in attributes(msg) {
        if typ != ATTR_XOR_RELAYED_ADDRESS {
            continue;
        }
        if value.len() < 8 {
            return None;
        }
        let family = value[1];
        let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
        match family {
            0x01 => {
                let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]])
                    ^ MAGIC_COOKIE;
                return Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(raw)),
                    port,
                ));
            }
            0x02 if value.len() >= 20 => {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(txn);
                let mut octets = [0u8; 16];
                for index in 0..16 {
                    octets[index] = value[4 + index] ^ mask[index];
                }
                return Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                ));
            }
            _ => return None,
        }
    }
    None
}

/// Encode an XOR-PEER-ADDRESS attribute for TURN
fn encode_xor_address(addr: SocketAddr) -> Vec<u8> {
    let mut attr = Vec::with_capacity(12);
    attr.extend_from_slice(&0x0012u16.to_be_bytes()); // XOR-PEER-ADDRESS
    attr.extend_from_slice(&0x0008u16.to_be_bytes()); // Length: 8 for IPv4

    attr.push(0x00); // Reserved
    attr.push(0x01); // Family: IPv4

    let port = addr.port() ^ 0x2112; // XOR with magic cookie high bits
    attr.extend_from_slice(&port.to_be_bytes());

    if let std::net::IpAddr::V4(ip) = addr.ip() {
        let xored = u32::from(ip) ^ 0x2112A442;
        attr.extend_from_slice(&xored.to_be_bytes());
    }

    attr
}

/// Encode a DATA attribute for TURN
fn encode_data_attribute(data: &[u8]) -> Vec<u8> {
    let padding = (4 - (data.len() % 4)) % 4;
    let mut attr = Vec::with_capacity(4 + data.len() + padding);
    attr.extend_from_slice(&0x0013u16.to_be_bytes()); // DATA
    attr.extend_from_slice(&(data.len() as u16).to_be_bytes());
    attr.extend_from_slice(data);
    attr.resize(attr.len() + padding, 0x00); // Pad to 4-byte boundary
    attr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_turn_client() {
        let client = TurnClient::new(
            "198.51.100.1:3478".parse().unwrap(),
            "user".to_string(),
            "pass".to_string(),
        );
        assert!(client.relay_addr().is_none());
    }

    #[test]
    fn test_encode_xor_address() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let encoded = encode_xor_address(addr);
        assert_eq!(encoded.len(), 12);
        assert_eq!(encoded[0..2], 0x0012u16.to_be_bytes());
    }

    #[test]
    fn test_encode_data_attribute() {
        let data = b"hello";
        let encoded = encode_data_attribute(data);
        assert_eq!(encoded[0..2], 0x0013u16.to_be_bytes());
        // Length should be 5
        assert_eq!(encoded[2..4], 5u16.to_be_bytes());
        // Data starts at offset 4
        assert_eq!(&encoded[4..9], b"hello");
        // Padded to 8 bytes total (4 header + 5 data + 3 padding)
        assert_eq!(encoded.len(), 12);
    }

    // ── TURN authentication flow (row #59) ────────────────────────────────

    fn wrap_message(typ: u16, txn: [u8; 12], attrs: Vec<u8>) -> Vec<u8> {
        let mut msg = Vec::with_capacity(20 + attrs.len());
        msg.extend_from_slice(&typ.to_be_bytes());
        msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txn);
        msg.extend_from_slice(&attrs);
        msg
    }

    fn build_error_response(txn: [u8; 12], code: u16, realm: &str, nonce: &str) -> Vec<u8> {
        let mut attrs = Vec::new();
        let class = (code / 100) as u8;
        let number = (code % 100) as u8;
        push_attr(&mut attrs, ATTR_ERROR_CODE, &[0, 0, class, number]);
        push_attr(&mut attrs, ATTR_REALM, realm.as_bytes());
        push_attr(&mut attrs, ATTR_NONCE, nonce.as_bytes());
        wrap_message(ALLOCATE_ERROR, txn, attrs)
    }

    fn build_success_response(txn: [u8; 12], relay: SocketAddr) -> Vec<u8> {
        let mut attrs = Vec::new();
        let mut value = vec![0u8, 0x01];
        value.extend_from_slice(&(relay.port() ^ 0x2112).to_be_bytes());
        match relay.ip() {
            IpAddr::V4(ip) => {
                value.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes())
            }
            IpAddr::V6(_) => panic!("test helper builds IPv4 only"),
        }
        push_attr(&mut attrs, ATTR_XOR_RELAYED_ADDRESS, &value);
        push_attr(&mut attrs, ATTR_LIFETIME, &600u32.to_be_bytes());
        wrap_message(ALLOCATE_SUCCESS, txn, attrs)
    }

    /// Recompute MESSAGE-INTEGRITY the way a server would: zero the attribute
    /// value, HMAC the whole message, compare.
    fn verify_message_integrity(msg: &[u8], key: &[u8]) -> bool {
        let mut offset = 20usize;
        while offset + 4 <= msg.len() {
            let typ = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
            let len = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]) as usize;
            if typ == ATTR_MESSAGE_INTEGRITY && len == 20 && offset + 24 <= msg.len() {
                let mut copy = msg.to_vec();
                for byte in &mut copy[offset + 4..offset + 24] {
                    *byte = 0;
                }
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(&copy);
                let expected = mac.finalize().into_bytes();
                return expected[..] == msg[offset + 4..offset + 24];
            }
            offset += 4 + len + ((4 - (len % 4)) % 4);
        }
        false
    }

    #[test]
    fn md5_matches_rfc1321_vectors() {
        fn hex(digest: [u8; 16]) -> String {
            digest.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        assert_eq!(hex(md5_digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5_digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(md5_digest(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
    }

    #[test]
    fn xor_relayed_address_parses_ipv4() {
        let txn = [7u8; 12];
        let relay: SocketAddr = "203.0.113.9:50000".parse().unwrap();
        let response = build_success_response(txn, relay);
        assert_eq!(xor_relayed_address(&response, &txn), Some(relay));
    }

    #[tokio::test]
    async fn allocate_solves_401_challenge_and_parses_relay_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let relay: SocketAddr = "203.0.113.9:50000".parse().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];

            // First request: no MESSAGE-INTEGRITY, no USERNAME → 401 challenge.
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            assert!(!verify_message_integrity(
                &buf[..len],
                &long_term_key("user", "tallow", "pass")
            ));
            let first = response_txn(&buf[..len]);
            let challenge = build_error_response(first, 401, "tallow", "nonce-1");
            server.send_to(&challenge, from).await.unwrap();

            // Second request: must carry MESSAGE-INTEGRITY under the derived key.
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let key = long_term_key("user", "tallow", "pass");
            assert!(
                verify_message_integrity(&buf[..len], &key),
                "authenticated Allocate must carry a valid MESSAGE-INTEGRITY"
            );
            let second = response_txn(&buf[..len]);
            let success = build_success_response(second, relay);
            server.send_to(&success, from).await.unwrap();
        });

        let mut client = TurnClient::new(server_addr, "user".into(), "pass".into());
        let allocated = client.allocate().await.unwrap();
        assert_eq!(allocated, relay, "relay address must come from XOR-RELAYED-ADDRESS");
        assert_eq!(client.relay_addr(), Some(relay));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn allocate_refuses_when_success_has_no_relayed_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let txn = response_txn(&buf[..len]);
            // Success with no XOR-RELAYED-ADDRESS: the old code returned the
            // server's own address here.
            let reply = wrap_message(ALLOCATE_SUCCESS, txn, Vec::new());
            server.send_to(&reply, from).await.unwrap();
        });

        let mut client = TurnClient::new(server_addr, "user".into(), "pass".into());
        let err = client.allocate().await.unwrap_err();
        assert!(
            err.to_string().contains("XOR-RELAYED-ADDRESS"),
            "unexpected error: {err}"
        );
        server_task.await.unwrap();
    }
}
