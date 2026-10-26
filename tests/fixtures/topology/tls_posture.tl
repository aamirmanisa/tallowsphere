// N06 — TLS posture. The server on 46003 is a rustls listener in
// tests/topology_scan.rs presenting a self-signed certificate for "localhost".
// The report must show the negotiated version and cipher, the certificate's own
// names, and trusted=false — an untrusted certificate is a posture, not a
// reason to refuse to look.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback TLS posture probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.tls_posture("127.0.0.1", 46003, 3000, "localhost")
    print("version={r.version} cipher={r.cipher}")
    print("trusted={r.trusted} chain_len={r.chain_len}")
    print("sans={r.sans}")
}
