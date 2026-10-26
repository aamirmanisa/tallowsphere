// Adversarial surface: stdlib/topology.tl declares `native fn parse_ports`.
// A declared surface that the dispatch table does not implement is a lie a
// caller can only discover at run time.
@cra_class(.default)
@legal(basis: .research, purpose: "surface fixture: declared parse_ports", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let ports = topology.parse_ports("22,80")
    print("CANARY_PARSE_PORTS n={ports}")
}
