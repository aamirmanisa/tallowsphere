// Adversarial boundary: a three-port spec at the very top of the range.
@cra_class(.default)
@legal(basis: .research, purpose: "boundary fixture: top three ports", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("127.0.0.1", "65533-65535", 200, 50)
    print("BOUNDARY_TOP3 n={r.closed} filtered={r.filtered} open={r.open}")
}
