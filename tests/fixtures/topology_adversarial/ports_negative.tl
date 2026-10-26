// Adversarial: malformed port specification "-1" must be a refusal,
// never a panic and never an empty successful scan. Target is loopback so the
// only thing under test is parse_ports.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: malformed port specification", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("127.0.0.1", "-1", 100, 20)
    print("CANARY_SCAN_COMPLETED")
}
