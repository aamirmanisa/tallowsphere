// Adversarial P0: the same tag carried through an explicitly string-typed
// binding and a parameter must not dispatch either.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: module tag as typed string", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")

@legal(basis: .research, purpose: "negative fixture: module tag as typed string", personal_data: false)
fn poke(tag: String) {
    let r = tag.connect_scan("127.0.0.1", "46531", 100, 20)
    print("CANARY_DISPATCH_TYPED")
}

fn main() with Net {
    let t: string = "__module_topology__"
    poke(t)
}
