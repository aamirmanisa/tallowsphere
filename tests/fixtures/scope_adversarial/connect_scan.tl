// Adversarial: a topology connect scan of an authorised-looking loopback port
// while NO authorization register exists at all. The test binds
// 127.0.0.1:47101 first, so "refused before a socket is opened" is measured by
// the accept never firing rather than by the absence of stdout alone.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: absent-register refusal", personal_data: false)
@persona(id: "scope-adv", cover_class: .researcher, compartment: "topology", fingerprint_seed: "scope-adv-1")
@burn_plan(persona: "scope-adv", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowScopeAdversarial/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let r = topology.connect_scan("127.0.0.1", "47101", 200, 20)
    print("CANARY_SCAN_RETURNED")
}
