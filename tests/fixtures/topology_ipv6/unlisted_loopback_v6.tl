// N09 — the gate cannot be talked around by an IPv6 literal. Run from the
// workspace root, where the operational register lists 127.0.0.1 but not ::1:
// the scan must be refused, and a listener bound on [::1]:46021 must never see
// a connection. That is the "before any probe" claim, measured rather than
// asserted.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted IPv6 loopback target", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.v6_connect_scan("::1", "46031", 500, 50)
    print("should not reach here open={s.open}")
}
