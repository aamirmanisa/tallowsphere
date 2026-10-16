// /// script
// requires = ["egress-dep"]
// ///
@legal(basis: .research, purpose: "egress check: fetch() under --script inline-dependency mode (G14)")
@cra_class(.class_i)
@persona(id: "egress-script", cover_class: .researcher, compartment: "egress-5", fingerprint_seed: "egress-script-seed-8a41")
@burn_plan(persona: "egress-script", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowEgressProbe/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let r = fetch("https://api.ipify.org")
    print("script_ip=" + r.text())
}
