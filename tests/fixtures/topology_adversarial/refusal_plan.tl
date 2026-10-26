// Adversarial: topology.plan resolves the target and is dispatched, so it gets
// the same gate as the scanners. It must refuse before it estimates anything.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted target refusal", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let p = topology.plan("203.0.113.7", "80", "syn", 20, 200)
    print("CANARY_PLAN_RETURNED packets={p.packets}")
}
