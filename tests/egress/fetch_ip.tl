@legal(basis: .research, purpose: "egress check: what IP does the compiled HTTP path use")
@cra_class(.class_i)
@persona(id: "egress-fetch", cover_class: .researcher, compartment: "egress-1", fingerprint_seed: "egress-fetch-seed-7c1a")
@burn_plan(persona: "egress-fetch", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowEgressProbe/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let r = fetch("https://api.ipify.org")
    print("fetch_ip=" + r.text())
}
