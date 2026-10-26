// N02 — UDP scan. 46007 is a UDP listener in tests/topology_scan.rs; 46009 is
// closed. On loopback the closed port answers with ICMP port-unreachable, which
// a connected socket surfaces as ECONNREFUSED — that is the only case UDP can
// call "closed" rather than "open|filtered".
@cra_class(.default)
@legal(basis: .research, purpose: "loopback UDP scan; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.udp_scan("127.0.0.1", "46007,46009", 600, 50)
    print("open={r.open} closed={r.closed} open_or_filtered={r.open_or_filtered}")
}
