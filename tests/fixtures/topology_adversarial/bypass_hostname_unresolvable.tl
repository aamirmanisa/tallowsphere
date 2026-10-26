// Adversarial ordering probe: a hostname that cannot resolve at all.
// Doctrine says the scope register is consulted BEFORE a packet is built. If the
// register ran first this target would be refused as not-listed; if the code
// resolves first, the failure is a resolver error and a DNS query was already
// put on the wire for a target nobody authorized.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: ordering of resolve vs authorize", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("no-such-host.invalid", "46523", 100, 20)
    print("CANARY_UNRESOLVABLE_SCANNED")
}
