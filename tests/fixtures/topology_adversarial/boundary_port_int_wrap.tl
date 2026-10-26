// Adversarial: the Int `port` argument of banner/tls_posture/ja4 is cast with
// `as u16`, which wraps. 70000 is not a port; it must be refused, not silently
// truncated to 4464 (a port the operator never named).
@cra_class(.default)
@legal(basis: .research, purpose: "boundary fixture: out-of-range int port", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let b = topology.banner("127.0.0.1", 70000, 200, "none")
    print("CANARY_BANNER_WRAPPED product={b.product}")
}
