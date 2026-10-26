// N05 — banner, HTTP path. The listener on 46005 answers the HEAD probe with a
// Server header; the product/version split must come from that header.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback banner probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let b = topology.banner("127.0.0.1", 46005, 800, "http")
    print("product={b.product} version={b.version}")
    print("banner={b.banner}")
}
