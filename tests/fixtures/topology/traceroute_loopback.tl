// N08 — TTL walk. Loopback answers at hop 1: a UDP probe to a closed port
// produces ICMP port-unreachable, which is both the responder and the
// destination-reached signal. A traceroute that cannot see hop 1 is broken.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback traceroute; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.traceroute("127.0.0.1", 4, 500, 2)
    print("reached={r.reached}")
    for h in r.hops {
        print("ttl={h.ttl} responders={h.responders} multipath={h.multipath}")
    }
}
