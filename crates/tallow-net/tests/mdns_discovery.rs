//! Integration tests for mDNS advertise/browse
//!
//! These tests require a multicast-capable network and are marked `#[ignore]`
//! for CI environments where multicast may be blocked.

mod mdns_tests {
    use std::time::Duration;
    use tallow_net::discovery::lan::{discover_sender, LanAdvertiser};

    /// Test that advertising and discovering works on the same machine.
    ///
    /// Requires multicast support -- ignored in CI.
    #[tokio::test]
    #[ignore]
    async fn test_advertise_and_discover() {
        let room_hash = [0xABu8; 32];
        let port = 54321;

        // Start advertising
        let _advertiser =
            LanAdvertiser::new(port, "test1234", &room_hash).expect("advertiser creation");

        // Give mDNS time to propagate
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Browse for the sender
        let peer = discover_sender(&room_hash, Duration::from_secs(5))
            .await
            .expect("browse should not error");

        assert!(peer.is_some(), "Should discover the advertised sender");
        let peer = peer.unwrap();
        assert_eq!(peer.addr.port(), port);
        assert_eq!(peer.fingerprint.as_deref(), Some("test1234"));
    }

    /// Test that room code filtering works.
    ///
    /// Requires multicast support -- ignored in CI.
    #[tokio::test]
    #[ignore]
    async fn test_discover_with_room_filter() {
        let room_hash_a = [0x01u8; 32];
        let room_hash_b = [0x02u8; 32];

        // Advertise room A
        let _advertiser_a =
            LanAdvertiser::new(55001, "aaaa1111", &room_hash_a).expect("advertiser A");

        tokio::time::sleep(Duration::from_secs(1)).await;

        // Browse for room B -- should NOT find room A
        let peer = discover_sender(&room_hash_b, Duration::from_secs(3))
            .await
            .expect("browse should not error");

        assert!(
            peer.is_none(),
            "Should NOT discover sender for different room code"
        );
    }

    /// Test that browse times out cleanly when no advertiser exists.
    #[tokio::test]
    #[ignore]
    async fn test_discover_timeout() {
        let room_hash = [0xFFu8; 32];

        let peer = discover_sender(&room_hash, Duration::from_secs(2))
            .await
            .expect("browse should not error");

        assert!(peer.is_none(), "Should return None on timeout");
    }
}
