// N09 — an IPv6 target the register does not list must be refused, exactly as
// an unlisted IPv4 target is. 2001:db8::1 is RFC 3849 documentation space and
// is deliberately absent from the fixture register.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted IPv6 target", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.v6_connect_scan("2001:db8::1", "80", 200, 20)
    print("should not reach here sent={s.sent}")
}
