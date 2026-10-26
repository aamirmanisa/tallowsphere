// Adversarial boundary: port 65535 is the top of the u16 range and must scan.
@cra_class(.default)
@legal(basis: .research, purpose: "boundary fixture: top-of-range port", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("127.0.0.1", "65535", 200, 50)
    print("BOUNDARY_65535 closed={r.closed} filtered={r.filtered} open={r.open}")
}
