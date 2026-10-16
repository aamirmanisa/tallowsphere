// examples/relay_room_multi_demo.tl — Stage 3 / Slice 2 hardening: multi-peer.
//
// Three peers join ONE multi room on the SendTallow product relay (raw
// postcard WS wire — `tallow-relay serve --ws-addr`):
//
//   A joins (peer_id 0) -> B joins (peer_id 1; A sees peer_joined 1)
//   C joins (peer_id 2; A and B see peer_joined 2)
//   B broadcasts "from-b"        -> A and C receive it (from_peer 1)
//   A sends "only-b" to peer 1   -> B receives it; C times out (isolated)
//   B leaves                     -> A and C see peer_left 1
//
// Peer ids are relay-assigned and 0-based (A=0, B=1, C=2).
//
// Usage:
//   tallow run examples/relay_room_multi_demo.tl -- [ws_url] [code]
// Defaults: ws://127.0.0.1:4454/ws · relay-room-multi-demo
//
// Scope note: loopback-only interop demo (language client ↔ product relay on
// 127.0.0.1) — no external egress, no personal data.

@cra_class(.default)
@legal(basis: .research, purpose: "local loopback interop demo — language client to a SendTallow product relay on 127.0.0.1; no external network, no personal data", personal_data: false)
@persona(id: "relayroom-multi-local", cover_class: .researcher, compartment: "relayroom-multi", fingerprint_seed: "relayroom-multi-local-0915")
@burn_plan(persona: "relayroom-multi-local", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowRelayRoomMultiDemo/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let args = env.args()
    let url = if args.len >= 1 { args[0] } else { "ws://127.0.0.1:4454/ws" }
    let code = if args.len >= 2 { args[1] } else { "relay-room-multi-demo" }

    print("== RelayRoom multi-peer demo — product relay WS wire ==")
    print("relay : {url}")
    print("code  : {code}")
    print("room  : {RelayRoom.room_id(code)}")
    print("")

    let a = RelayRoom.join_multi(url, code)
    print("A joined · peer_id={a.peer_id} · existing={a.existing_peers.len}")

    let b = RelayRoom.join_multi(url, code)
    print("B joined · peer_id={b.peer_id} · existing={b.existing_peers.len}")

    let e1 = a.recv(3000)
    print("A saw  : {e1.kind} · peer_id={e1.peer_id}")

    let c = RelayRoom.join_multi(url, code)
    print("C joined · peer_id={c.peer_id} · existing={c.existing_peers.len}")

    let e2 = a.recv(3000)
    print("A saw  : {e2.kind} · peer_id={e2.peer_id}")
    let e3 = b.recv(3000)
    print("B saw  : {e3.kind} · peer_id={e3.peer_id}")
    print("")

    b.send("from-b")
    let got_a = a.recv(3000)
    let got_c = c.recv(3000)
    print("A got  : {got_a.kind} · \"{got_a.data}\" · from={got_a.from_peer}")
    print("C got  : {got_c.kind} · \"{got_c.data}\" · from={got_c.from_peer}")

    a.send_to(1, "only-b")
    let tb = b.recv(3000)
    print("B got  : {tb.kind} · \"{tb.data}\" · from={tb.from_peer}")
    let tc = c.recv(700)
    print("C next : {tc.kind} (expect timeout — targeted frame is not for C)")
    print("")

    b.leave()
    let l1 = a.recv(3000)
    let l2 = c.recv(3000)
    print("A saw  : {l1.kind} · peer_id={l1.peer_id}")
    print("C saw  : {l2.kind} · peer_id={l2.peer_id}")

    a.leave()
    c.leave()

    let ok = e1.kind == "peer_joined" && e1.peer_id == 1
        && e2.kind == "peer_joined" && e2.peer_id == 2
        && e3.kind == "peer_joined" && e3.peer_id == 2
        && got_a.kind == "payload" && got_a.data == "from-b" && got_a.from_peer == 1
        && got_c.kind == "payload" && got_c.data == "from-b" && got_c.from_peer == 1
        && tb.kind == "payload" && tb.data == "only-b" && tb.from_peer == 0
        && tc.kind == "timeout"
        && l1.kind == "peer_left" && l1.peer_id == 1
        && l2.kind == "peer_left" && l2.peer_id == 1

    if ok {
        print("")
        print("MULTI DEMO OK")
    } else {
        print("")
        print("MULTI DEMO MISMATCH")
        process.exit(2)
    }
}
