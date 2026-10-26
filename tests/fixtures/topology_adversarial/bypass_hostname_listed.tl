// Adversarial: 'localhost' is in the register and resolves to 127.0.0.1; the
// scan must proceed. This is the control for the two hostname refusals below.
@cra_class(.default)
@legal(basis: .research, purpose: "scope control: registered hostname", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("localhost", "46521", 100, 20)
    print("CANARY_HOST_LISTED scanned closed={r.closed} filtered={r.filtered}")
}
