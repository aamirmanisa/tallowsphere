// N09 — a closed IPv6 port must be reported closed, not filtered: on loopback
// nothing can sit in the path, so silence would be a scanner bug rather than a
// firewall.
@cra_class(.default)
@legal(basis: .research, purpose: "IPv6 loopback port probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.v6_connect_scan("::1", "46023", 500, 50)
    print("v6 closed open={s.open} closed={s.closed} sent={s.sent}")
}
