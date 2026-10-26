// Adversarial: 'ubuntu-16gb-hel1-1' resolves (via /etc/hosts) to 127.0.1.1,
// which is NOT the allowlisted 127.0.0.1. An unlisted name must be refused.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted hostname", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("ubuntu-16gb-hel1-1", "46522", 100, 20)
    print("CANARY_HOST_UNLISTED scanned closed={r.closed} filtered={r.filtered}")
}
