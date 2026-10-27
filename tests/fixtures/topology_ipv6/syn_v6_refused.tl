// N09 — a raw TCP SYN over IPv6 is not possible here: it needs IPV6_HDRINCL,
// which this build does not set. The request must be refused by name and must
// NOT come back as an empty scan, which would read as "nothing is open".
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: raw IPv6 technique refusal", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.syn_scan("::1", "46021", 200, 20)
    print("should not reach here open={s.open}")
}
