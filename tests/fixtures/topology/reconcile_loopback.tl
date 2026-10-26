// N12 — cross-technique reconciliation. 46011 is a TCP listener, 46013 is
// closed; both techniques should agree, so the record must show no
// disagreement and full confidence. Agreement is the case worth pinning first:
// a merge that flags everything proves nothing.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback reconciliation; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.reconcile("127.0.0.1", "46011,46013", "syn,connect", 1000, 50)
    print("open={r.open} closed={r.closed} disagreements={r.disagreements}")
    for p in r.ports {
        print("port={p.port} verdict={p.verdict} conf={p.confidence} disagree={p.disagreement}")
    }
}
