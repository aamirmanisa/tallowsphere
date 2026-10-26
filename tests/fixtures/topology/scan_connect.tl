// The unprivileged half: a connect scan must reach the same verdicts without
// CAP_NET_RAW, so the tool is usable on a machine where raw sockets are denied.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback host-discovery probe; no external egress", personal_data: false)
@persona(id: "topo-fixture", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-fixture-1")
@burn_plan(persona: "topo-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let s = topology.connect_scan("127.0.0.1", "45992-45994", 500, 50)
    print("connect open={s.open} closed={s.closed}")
}
