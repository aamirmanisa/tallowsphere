// examples/relay_room_demo.tl — Stage 3 / Slice 2 flagship demo.
//
// A single .tl program drives BOTH ends of a room on the SendTallow product
// relay (raw postcard WS wire — the same wire `tallow-relay serve --ws-addr`
// speaks, and the same code path the product's browser client uses):
//
//   A joins -> B joins (A receives PeerArrived)
//   A sends "hello-from-tl" -> B receives it
//   B sends "ack-from-tl"   -> A receives it
//   both leave
//
// Usage:
//   tallow run examples/relay_room_demo.tl -- [ws_url] [code]
// Defaults: ws://127.0.0.1:4434/ws · relay-room-demo
//
// Scope note: loopback-only interop demo (language client ↔ product relay on
// 127.0.0.1) — no external egress, no personal data.

@cra_class(.default)
@legal(basis: .research, purpose: "local loopback interop demo — language client to a SendTallow product relay on 127.0.0.1; no external network, no personal data", personal_data: false)
@persona(id: "relayroom-demo-local", cover_class: .researcher, compartment: "relayroom-demo", fingerprint_seed: "relayroom-demo-local-0915")
@burn_plan(persona: "relayroom-demo-local", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowRelayRoomDemo/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let args = env.args()
    let url = if args.len >= 1 { args[0] } else { "ws://127.0.0.1:4434/ws" }
    let code = if args.len >= 2 { args[1] } else { "relay-room-demo" }

    print("== RelayRoom demo — product relay WS wire ==")
    print("relay : {url}")
    print("code  : {code}")
    print("room  : {RelayRoom.room_id(code)}")
    print("")

    let a = RelayRoom.join(url, code)
    print("A joined · peer_present={a.peer_present}")

    let b = RelayRoom.join(url, code)
    print("B joined · peer_present={b.peer_present}")

    let ev = a.recv(3000)
    print("A event: {ev.kind}")

    a.send("hello-from-tl")
    let got = b.recv(3000)
    print("B got  : {got.kind} · {got.data_len} bytes · \"{got.data}\"")

    b.send("ack-from-tl")
    let ack = a.recv(3000)
    print("A got  : {ack.kind} · {ack.data_len} bytes · \"{ack.data}\"")

    a.leave()
    b.leave()

    if got.kind == "payload" && got.data == "hello-from-tl" && ack.kind == "payload" && ack.data == "ack-from-tl" {
        print("")
        print("RELAYROOM DEMO OK")
    } else {
        print("")
        print("RELAYROOM DEMO MISMATCH")
        process.exit(2)
    }
}
