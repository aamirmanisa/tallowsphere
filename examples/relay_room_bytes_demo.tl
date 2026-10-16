// examples/relay_room_bytes_demo.tl — Stage 3 / Slice 2 hardening: binary payloads.
//
// One .tl program drives BOTH ends of a legacy room on the SendTallow product
// relay and round-trips EXACT BYTES: the payload is an ML-KEM-768 public key
// (1184 raw bytes, not valid utf-8) obtained from the built-in
// `KeyPair.generate`. The receiver compares the received `raw` bytes by hex
// against the sender's hex — byte-identical or the demo fails.
//
//   A joins -> B joins (A receives PeerArrived)
//   A send_bytes(public_key) -> B verifies raw.len + raw.hex() equality
//   B sends a text ack         -> A receives it (string path still fine)
//
// Usage:
//   tallow run examples/relay_room_bytes_demo.tl -- [ws_url] [code]
// Defaults: ws://127.0.0.1:4454/ws · relay-room-bytes-demo
//
// Scope note: loopback-only interop demo (language client ↔ product relay on
// 127.0.0.1) — no external egress, no personal data.

@cra_class(.default)
@legal(basis: .research, purpose: "local loopback interop demo — language client to a SendTallow product relay on 127.0.0.1; no external network, no personal data", personal_data: false)
@persona(id: "relayroom-bytes-local", cover_class: .researcher, compartment: "relayroom-bytes", fingerprint_seed: "relayroom-bytes-local-0915")
@burn_plan(persona: "relayroom-bytes-local", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowRelayRoomBytesDemo/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let args = env.args()
    let url = if args.len >= 1 { args[0] } else { "ws://127.0.0.1:4454/ws" }
    let code = if args.len >= 2 { args[1] } else { "relay-room-bytes-demo" }

    // Fresh ML-KEM-768 keypair — the public key is 1184 raw bytes (non-utf8).
    let kp = KeyPair.generate("ml-kem-768")
    let pk = kp.public_key
    let pk_hex = pk.hex()

    print("== RelayRoom binary-payload demo — product relay WS wire ==")
    print("relay   : {url}")
    print("payload : ML-KEM-768 public key · {pk.len} raw bytes · {pk_hex.len} hex chars")
    print("")

    let a = RelayRoom.join(url, code)
    let b = RelayRoom.join(url, code)
    print("A joined · peer_present={a.peer_present}")
    print("B joined · peer_present={b.peer_present}")

    let arr = a.recv(3000)
    print("A event : {arr.kind}")

    a.send_bytes(pk)
    let got = b.recv(3000)
    let got_raw = got.raw
    let got_hex = got_raw.hex()
    print("B got   : {got.kind} · {got.data_len} bytes")

    let ok1 = got.kind == "payload" && got.data_len == pk.len && got_raw.len == pk.len && got_hex == pk_hex

    b.send("text-ack")
    let ack = a.recv(3000)
    let ok2 = ack.kind == "payload" && ack.data == "text-ack"
    print("A got   : {ack.kind} · \"{ack.data}\"")

    a.leave()
    b.leave()

    if ok1 && ok2 {
        print("")
        print("BYTES DEMO OK")
    } else {
        print("")
        print("BYTES DEMO MISMATCH (ok1={ok1} ok2={ok2})")
        process.exit(2)
    }
}
