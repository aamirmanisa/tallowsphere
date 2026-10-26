// The scanner must consult the authorization register before it builds a
// packet. `203.0.113.7` is TEST-NET-3 and is deliberately absent from
// configs/tallow/scope/authorized-hosts.toml.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted target", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.connect_scan("203.0.113.7", "80", 200, 20)
    print("should not reach here {s.sent}")
}
