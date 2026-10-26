// N04 — host discovery union. ICMP echo proves presence strongly; a TCP SYN to
// an open port proves it too. Neither method's silence proves absence, which is
// why the result reports a confidence and the methods that spoke.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback host discovery; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let d = topology.discover("127.0.0.1", "icmp_echo,tcp_syn", "46001", 500, 50)
    print("alive={d.alive} confidence={d.confidence}")
}
