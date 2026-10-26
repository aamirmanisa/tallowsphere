// N07 — JA4 client fingerprint. The fingerprint must describe the ClientHello
// that actually went on the wire, so it is computed from the recorded bytes
// rather than from the client configuration. Server on 46006 is a rustls
// listener in tests/topology_scan.rs.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback JA4 fingerprint measurement; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let j = topology.ja4("127.0.0.1", 46006, 3000, "localhost")
    print("ja4={j.ja4}")
    print("ciphers={j.ciphers} extensions={j.extensions} sni={j.sni}")
}
