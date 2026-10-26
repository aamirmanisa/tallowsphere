// Adversarial: topology.fin_scan against unlisted TEST-NET-3 (203.0.113.7).
// The call must be refused by the scope register before a probe is built; the
// canary must therefore never print.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted target refusal", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.fin_scan("203.0.113.7", "80", 200, 20)
    print("CANARY_TOPOLOGY_CALL_RETURNED")
}
