// Adversarial scope-bypass attempt: FQDN-style trailing dot for the allowlisted loopback address ('127.0.0.1.').
// If this spelling reaches 127.0.0.1 without the register having listed it, the
// string comparison in the gate has been bypassed.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: scope-bypass spelling", personal_data: false)
@persona(id: "topo-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "topo-adv-1")
@burn_plan(persona: "topo-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowTopologyAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("127.0.0.1.", "46520", 100, 20)
    print("CANARY_BYPASS_SCANNED open={r.open} closed={r.closed} filtered={r.filtered}")
}
