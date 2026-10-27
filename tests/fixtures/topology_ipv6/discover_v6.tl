// N09 — IPv6 host discovery: an ICMPv6 echo request (type 128) is answered by
// the loopback stack with an echo reply (type 129). A reply proves presence, so
// it must carry confidence 0.9 and a measured RTT.
@cra_class(.default)
@legal(basis: .research, purpose: "IPv6 loopback host discovery; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let d = topology.v6_discover("::1", 500)
    print("v6 discover target={d.target} alive={d.alive} confidence={d.confidence} rtt_ms={d.rtt_ms}")
}
