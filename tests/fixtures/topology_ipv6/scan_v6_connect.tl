// N09 — IPv6 connect scan. The listener on [::1]:46021 must come back open and
// the closed port must come back closed (RST), from the same evidence a v4
// connect scan uses: the kernel's connect() either completed, was refused, or
// did not.
@cra_class(.default)
@legal(basis: .research, purpose: "IPv6 loopback port probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.v6_connect_scan("::1", "46021,46023", 500, 50)
    print("v6 connect target={s.target} technique={s.technique} open={s.open} closed={s.closed}")
}
