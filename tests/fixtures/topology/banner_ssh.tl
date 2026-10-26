// N05 — banner. The listener on 46004 greets like an SSH daemon (RFC 4253
// identification string). The product/version must come from the banner itself,
// not from a port-number guess.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback banner probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let b = topology.banner("127.0.0.1", 46004, 800, "none")
    print("product={b.product} version={b.version}")
    print("banner={b.banner}")
}
