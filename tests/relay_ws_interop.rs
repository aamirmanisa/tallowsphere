//! Language ↔ product-relay WebSocket interop test (Stage 3 / Slice 2).
//!
//! Speaks the product relay's WebSocket wire directly — raw postcard `Message`
//! frames, the same wire the SendTallow product's browser client uses:
//!
//!   1. `language_client_joins_product_relay_ws_room` — legacy 2-peer room:
//!      A joins -> `RoomJoined{peer_present:false}`; B joins -> `true` + A
//!      receives `PeerArrived`; payloads both ways byte-identically.
//!   2. `multi_room_interop` — 3-peer room: `RoomJoinedMulti` peer ids +
//!      `PeerJoinedRoom`/`PeerLeftRoom` broadcasts; `Targeted` broadcast and
//!      unicast (binary payload, byte-exact; non-targeted peer isolated).
//!   3. `password_auth_interop` — relay started with `--pass`:
//!      wrong hash -> `HandshakeFailed{"authentication failed"}`;
//!      correct hash -> `RoomJoined`.
//!
//! Requires a running product relay (built from the stage-2 wiring branch):
//!
//!   tallow-relay serve --addr 127.0.0.1:4433 --ws-addr 127.0.0.1:4434
//!   tallow-relay serve --addr 127.0.0.1:4433 --ws-addr 127.0.0.1:4434 --pass <pw>
//!
//! Point the test at it with `TALLOW_RELAY_WS=ws://127.0.0.1:4434/ws`
//! (and `TALLOW_RELAY_WS_PASS=<pw>` for the auth test).
//! When the env vars are unset the tests skip with a note (so they never fail
//! unrelated runs).

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use tallow_protocol::room::code::derive_room_id;
use tallow_protocol::wire::Message;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn join_frame(room_id: [u8; 32]) -> WsMsg {
    let msg = Message::RoomJoin {
        room_id: room_id.to_vec(),
        password_hash: None,
        forward_to_relay: None,
    };
    WsMsg::Binary(postcard::to_stdvec(&msg).expect("encode RoomJoin").into())
}

fn join_multi_frame(room_id: [u8; 32], password_hash: Option<Vec<u8>>) -> WsMsg {
    let msg = Message::RoomJoinMulti {
        room_id: room_id.to_vec(),
        password_hash,
        requested_capacity: 0,
    };
    WsMsg::Binary(postcard::to_stdvec(&msg).expect("encode RoomJoinMulti").into())
}

async fn recv_binary(ws: &mut Ws) -> Vec<u8> {
    loop {
        match ws.next().await.expect("ws closed").expect("ws error") {
            WsMsg::Binary(b) => return b.to_vec(),
            WsMsg::Ping(_) | WsMsg::Pong(_) => continue,
            WsMsg::Close(_) => panic!("unexpected close frame"),
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}

fn relay_url_or_skip(test: &str) -> Option<String> {
    match std::env::var("TALLOW_RELAY_WS") {
        Ok(u) => Some(u),
        Err(_) => {
            eprintln!("skip {test}: TALLOW_RELAY_WS not set (need a running product relay)");
            None
        }
    }
}

#[tokio::test]
async fn language_client_joins_product_relay_ws_room() {
    let url = match relay_url_or_skip("language_client_joins_product_relay_ws_room") {
        Some(u) => u,
        None => return,
    };

    let room_id = derive_room_id("language-ws-interop-slice2");

    // A joins first.
    let (mut a, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect A");
    a.send(join_frame(room_id)).await.expect("send join A");
    let joined_a: Message = postcard::from_bytes(&recv_binary(&mut a).await)
        .expect("decode RoomJoined (A)");
    assert!(
        matches!(joined_a, Message::RoomJoined { peer_present: false }),
        "A got {joined_a:?}"
    );

    // B joins second.
    let (mut b, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect B");
    b.send(join_frame(room_id)).await.expect("send join B");
    let joined_b: Message = postcard::from_bytes(&recv_binary(&mut b).await)
        .expect("decode RoomJoined (B)");
    assert!(
        matches!(joined_b, Message::RoomJoined { peer_present: true }),
        "B got {joined_b:?}"
    );

    // A is notified of B's arrival.
    let arrived: Message =
        postcard::from_bytes(&recv_binary(&mut a).await).expect("decode PeerArrived");
    assert!(matches!(arrived, Message::PeerArrived), "A got {arrived:?}");

    // A -> B raw payload.
    let ab = b"hello-from-language-ws-client".to_vec();
    a.send(WsMsg::Binary(ab.clone().into()))
        .await
        .expect("A payload");
    assert_eq!(recv_binary(&mut b).await, ab, "B payload mismatch");

    // B -> A raw payload.
    let ba = b"ack-from-language-ws-client".to_vec();
    b.send(WsMsg::Binary(ba.clone().into()))
        .await
        .expect("B payload");
    assert_eq!(recv_binary(&mut a).await, ba, "A payload mismatch");

    println!("INTEROP OK: room joined via product relay WS; payloads exchanged both ways");
}

#[tokio::test]
async fn multi_room_interop() {
    let url = match relay_url_or_skip("multi_room_interop") {
        Some(u) => u,
        None => return,
    };

    let room_id = derive_room_id("language-ws-multi-slice2");

    // A joins: peer_id 1, no existing peers.
    let (mut a, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect A");
    a.send(join_multi_frame(room_id, None))
        .await
        .expect("join A");
    match postcard::from_bytes::<Message>(&recv_binary(&mut a).await).expect("decode A") {
        Message::RoomJoinedMulti {
            peer_id,
            existing_peers,
        } => {
            assert_eq!(peer_id, 0);
            assert!(existing_peers.is_empty(), "A existing {existing_peers:?}");
        }
        other => panic!("A got {other:?}"),
    }

    // B joins: peer_id 2, existing [1]; A sees PeerJoinedRoom{2}.
    let (mut b, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect B");
    b.send(join_multi_frame(room_id, None))
        .await
        .expect("join B");
    match postcard::from_bytes::<Message>(&recv_binary(&mut b).await).expect("decode B") {
        Message::RoomJoinedMulti {
            peer_id,
            existing_peers,
        } => {
            assert_eq!(peer_id, 1);
            assert_eq!(existing_peers, vec![0]);
        }
        other => panic!("B got {other:?}"),
    }
    match postcard::from_bytes::<Message>(&recv_binary(&mut a).await).expect("decode join note") {
        Message::PeerJoinedRoom { peer_id } => assert_eq!(peer_id, 1),
        other => panic!("A join note got {other:?}"),
    }

    // C joins: peer_id 3, existing [1,2]; A and B see PeerJoinedRoom{3}.
    let (mut c, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect C");
    c.send(join_multi_frame(room_id, None))
        .await
        .expect("join C");
    match postcard::from_bytes::<Message>(&recv_binary(&mut c).await).expect("decode C") {
        Message::RoomJoinedMulti {
            peer_id,
            existing_peers,
        } => {
            assert_eq!(peer_id, 2);
            assert_eq!(existing_peers, vec![0, 1]);
        }
        other => panic!("C got {other:?}"),
    }
    for (name, ws) in [("A", &mut a), ("B", &mut b)] {
        match postcard::from_bytes::<Message>(&recv_binary(ws).await).expect("decode join note") {
            Message::PeerJoinedRoom { peer_id } => {
                assert_eq!(peer_id, 2, "{name} join note peer")
            }
            other => panic!("{name} join note got {other:?}"),
        }
    }

    // A broadcasts a Targeted payload: B and C receive it, from_peer overwritten to 1.
    let bc = Message::Targeted {
        from_peer: 0,
        to_peer: 0xFF,
        payload: b"broadcast-from-a".to_vec(),
    };
    a.send(WsMsg::Binary(postcard::to_stdvec(&bc).unwrap().into()))
        .await
        .expect("A broadcast");
    for (name, ws) in [("B", &mut b), ("C", &mut c)] {
        match postcard::from_bytes::<Message>(&recv_binary(ws).await).expect("decode broadcast") {
            Message::Targeted {
                from_peer,
                to_peer,
                payload,
            } => {
                assert_eq!(from_peer, 0, "{name} from_peer");
                assert_eq!(to_peer, 0xFF, "{name} to_peer");
                assert_eq!(payload, b"broadcast-from-a", "{name} payload");
            }
            other => panic!("{name} broadcast got {other:?}"),
        }
    }

    // A unicasts a BINARY payload to peer 2: B receives it byte-exact; C stays isolated.
    let bin = vec![0x00u8, 0xFF, 0x80, 0x01, 0xC3, 0x28, 0x9F, 0xFE];
    let uni = Message::Targeted {
        from_peer: 0,
        to_peer: 1,
        payload: bin.clone(),
    };
    a.send(WsMsg::Binary(postcard::to_stdvec(&uni).unwrap().into()))
        .await
        .expect("A unicast");
    match postcard::from_bytes::<Message>(&recv_binary(&mut b).await).expect("decode unicast") {
        Message::Targeted {
            from_peer,
            to_peer,
            payload,
        } => {
            assert_eq!(from_peer, 0);
            assert_eq!(to_peer, 1);
            assert_eq!(payload, bin, "binary payload must round-trip byte-exact");
        }
        other => panic!("B unicast got {other:?}"),
    }
    let isolated =
        tokio::time::timeout(std::time::Duration::from_millis(700), c.next()).await;
    assert!(isolated.is_err(), "C must not receive the unicast: {isolated:?}");

    // C leaves: A and B see PeerLeftRoom{3}.
    c.close(None).await.expect("close C");
    for (name, ws) in [("A", &mut a), ("B", &mut b)] {
        match postcard::from_bytes::<Message>(&recv_binary(ws).await).expect("decode left") {
            Message::PeerLeftRoom { peer_id } => assert_eq!(peer_id, 2, "{name} left peer"),
            other => panic!("{name} left got {other:?}"),
        }
    }

    println!("MULTI INTEROP OK: 3-peer room; broadcast + unicast (binary) + departure via product relay WS");
}

#[tokio::test]
async fn password_auth_interop() {
    let url = match relay_url_or_skip("password_auth_interop") {
        Some(u) => u,
        None => return,
    };
    let pass = match std::env::var("TALLOW_RELAY_WS_PASS") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!("skip password_auth_interop: TALLOW_RELAY_WS_PASS not set (need a --pass relay)");
            return;
        }
    };

    let room_id = derive_room_id("language-ws-auth-slice2");

    // Wrong hash -> HandshakeFailed.
    let (mut x, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect X");
    let wrong = Message::RoomJoin {
        room_id: room_id.to_vec(),
        password_hash: Some(blake3::hash(b"definitely-wrong").as_bytes().to_vec()),
        forward_to_relay: None,
    };
    x.send(WsMsg::Binary(postcard::to_stdvec(&wrong).unwrap().into()))
        .await
        .expect("send wrong");
    match postcard::from_bytes::<Message>(&recv_binary(&mut x).await).expect("decode reject") {
        Message::HandshakeFailed { reason } => assert_eq!(reason, "authentication failed"),
        other => panic!("expected HandshakeFailed, got {other:?}"),
    }

    // Correct hash -> RoomJoined.
    let (mut y, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect Y");
    let good = Message::RoomJoin {
        room_id: room_id.to_vec(),
        password_hash: Some(blake3::hash(pass.as_bytes()).as_bytes().to_vec()),
        forward_to_relay: None,
    };
    y.send(WsMsg::Binary(postcard::to_stdvec(&good).unwrap().into()))
        .await
        .expect("send good");
    match postcard::from_bytes::<Message>(&recv_binary(&mut y).await).expect("decode accept") {
        Message::RoomJoined { peer_present: false } => {}
        other => panic!("expected RoomJoined, got {other:?}"),
    }

    println!("AUTH INTEROP OK: wrong-password rejected, correct-password accepted (product relay WS)");
}
