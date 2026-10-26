// Adversarial boundary: timeout 0 must not hang, panic or divide by zero.
@cra_class(.default)
@legal(basis: .research, purpose: "boundary fixture: zero timeout", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("127.0.0.1", "46500", 0, 20)
    print("BOUNDARY_TIMEOUT0 open={r.open} closed={r.closed} filtered={r.filtered}")
}
