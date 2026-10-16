@legal(basis: .research, purpose: "which IP family does the compiled fetch use")
@cra_class(.class_i)
@persona(id: "egress-fetch64", cover_class: .researcher, compartment: "egress-1", fingerprint_seed: "egress-fetch64-seed-2d84")
@burn_plan(persona: "egress-fetch64", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowEgressProbe/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let r = fetch("https://api64.ipify.org")
    print("family_ip=" + r.text())
}
