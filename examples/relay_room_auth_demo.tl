// examples/relay_room_auth_demo.tl — Stage 3 / Slice 2 hardening: relay password.
//
// Joins a password-protected SendTallow product relay (`tallow-relay serve
// --pass <pw>`). The password is sent ONLY as its BLAKE3 hash inside the join
// frame; a wrong or missing password makes the relay answer HandshakeFailed
// ("authentication failed") and this program exits non-zero with that message.
//
// Usage:
//   tallow run examples/relay_room_auth_demo.tl -- [ws_url] [code] [password]
// Defaults: ws://127.0.0.1:4454/ws · relay-room-auth-demo · (no password)
//
// Exit: 0 = join accepted; non-zero = rejected/timeout (message on stderr).
//
// Scope note: loopback-only interop demo (language client ↔ product relay on
// 127.0.0.1) — no external egress, no personal data; the password is never
// printed (only its length is reported).

@cra_class(.default)
@legal(basis: .research, purpose: "local loopback interop demo — language client to a SendTallow product relay on 127.0.0.1; no external network, no personal data", personal_data: false)
@persona(id: "relayroom-auth-local", cover_class: .researcher, compartment: "relayroom-auth", fingerprint_seed: "relayroom-auth-local-0915")
@burn_plan(persona: "relayroom-auth-local", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowRelayRoomAuthDemo/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let args = env.args()
    let url = if args.len >= 1 { args[0] } else { "ws://127.0.0.1:4454/ws" }
    let code = if args.len >= 2 { args[1] } else { "relay-room-auth-demo" }
    let password = if args.len >= 3 { args[2] } else { "" }

    print("== RelayRoom auth demo — product relay WS wire ==")
    print("relay    : {url}")
    print("password : <provided len={password.len}>")
    print("")

    let a = RelayRoom.join(url, code, password)
    print("A joined · peer_present={a.peer_present}")
    a.leave()
    print("")
    print("AUTH DEMO OK")
}
