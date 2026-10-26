// N01/N10/N11 — the topology slice, over loopback so the test needs no
// external egress. The listener on 45995 is opened by tests/topology_scan.rs;
// 45996 and 45997 are closed, and a closed port must say so rather than being
// reported as filtered.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback host-discovery probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let p = topology.plan("127.0.0.1", "45995-45997", "syn", 50, 500)
    print("plan packets={p.packets} ports={p.ports_count}")
    let s = topology.syn_scan("127.0.0.1", "45995-45997", 500, 50)
    print("syn open={s.open} closed={s.closed} filtered={s.filtered}")
}
