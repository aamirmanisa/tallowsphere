// Adversarial boundary: rps 0 must be clamped, not used as a divisor.
@cra_class(.default)
@legal(basis: .research, purpose: "boundary fixture: zero rps", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let p = topology.plan("127.0.0.1", "46501-46503", "connect", 0, 50)
    print("BOUNDARY_RPS0 rps={p.rps} packets={p.packets} estimated_ms={p.estimated_ms}")
    let r = topology.connect_scan("127.0.0.1", "46501,46502", 50, 0)
    print("BOUNDARY_RPS0_SCAN open={r.open} closed={r.closed} filtered={r.filtered}")
}
