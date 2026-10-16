//! Integration test for PeerChannel over direct QUIC connections
//!
//! Tests the PeerChannel abstraction by creating a DirectListener (sender side)
//! and connecting from a client (receiver side) to verify bidirectional
//! message framing works end-to-end.
//!
//! QUIC's open_bi() doesn't send a STREAM frame until data is written, so
//! tests spawn server and client concurrently with the client writing first
//! to trigger the stream creation.

// Self-signed relay/peer fixtures: the QUIC client verifies peer certs in the
// strict default since fix-wave B (2026-09-28), so this suite runs only in the
// `dangerous_skip_verify` opt-in lane.
#[cfg(all(feature = "quic", feature = "dangerous_skip_verify"))]
mod direct_transfer_tests {
    use std::time::Duration;
    use tallow_net::transport::direct::{connect_direct, DirectListener};
    use tallow_net::transport::PeerChannel;

    /// Bind a loopback-only listener for tests.
    fn loopback_listener() -> DirectListener {
        DirectListener::bind_to("127.0.0.1:0".parse().unwrap()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peer_channel_roundtrip() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            // Verify transport description
            assert!(
                server.transport_description().starts_with("direct LAN"),
                "Server transport should be 'direct LAN ...'"
            );

            // Receive from client
            let mut buf = vec![0u8; 1024];
            let n = server.receive_message(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello from receiver");

            // Echo back
            server.send_message(&buf[..n]).await.unwrap();
            server
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        assert!(
            client.transport_description().starts_with("direct LAN"),
            "Client transport should be 'direct LAN ...'"
        );

        // Client writes first to trigger STREAM frame
        client.send_message(b"hello from receiver").await.unwrap();

        // Receive echo
        let mut buf = vec![0u8; 1024];
        let n = client.receive_message(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from receiver");

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peer_channel_multiple_messages() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(5)).await.unwrap();

            let mut buf = vec![0u8; 4096];
            for i in 0u32..50 {
                let n = server.receive_message(&mut buf).await.unwrap();
                let expected = format!("message-{:04}", i);
                assert_eq!(
                    std::str::from_utf8(&buf[..n]).unwrap(),
                    expected,
                    "Message {} mismatch",
                    i
                );
            }
            server
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Send 50 messages from client to server
        for i in 0u32..50 {
            let msg = format!("message-{:04}", i);
            client.send_message(msg.as_bytes()).await.unwrap();
        }

        let mut server = server_handle.await.unwrap();
        client.close().await;
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peer_channel_large_payload() {
        let listener = loopback_listener();
        let addr = listener.local_addr();

        let server_handle = tokio::spawn(async move {
            let mut server = listener.accept_peer(Duration::from_secs(10)).await.unwrap();

            let mut buf = vec![0u8; 600_000];
            let n = server.receive_message(&mut buf).await.unwrap();
            (server, n, buf)
        });

        let mut client = connect_direct(addr, Duration::from_secs(5)).await.unwrap();

        // Send a 512KB payload
        let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 256) as u8).collect();
        client.send_message(&payload).await.unwrap();

        let (mut server, n, buf) = server_handle.await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], &payload[..]);

        client.close().await;
        server.close().await;
    }
}
