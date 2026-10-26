// Adversarial P0: a hand-written string tag must NOT dispatch as the module.
// Only Value::Module dispatches; a String receiver is data and must refuse.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: module tag as string literal", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let t = "__module_topology__"
    let r = t.connect_scan("127.0.0.1", "46530", 100, 20)
    print("CANARY_DISPATCH_LITERAL")
}
