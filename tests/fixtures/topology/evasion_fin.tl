// N03 — FIN scan. RFC 793: an open port ignores a segment with no SYN, a closed
// port answers RST. So silence is open|filtered, never open, and the result
// carries that caveat. The listener on 45998 is opened by tests/topology_scan.rs;
// 45999 and 46000 are closed.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback evasion-technique probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.fin_scan("127.0.0.1", "45998-46000", 500, 50)
    print("fin open_or_filtered={s.open_or_filtered} closed={s.closed}")
    print("caveat={s.caveat}")
}
