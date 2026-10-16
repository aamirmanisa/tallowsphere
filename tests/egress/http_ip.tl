@legal(basis: .research, purpose: "egress check: what IP does the interpreted stdlib http.get path use (G12)")
@cra_class(.class_i)
@persona(id: "egress-http", cover_class: .researcher, compartment: "egress-3", fingerprint_seed: "egress-http-seed-9f2c")
@burn_plan(persona: "egress-http", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowEgressProbe/1.0 (+https://tallow.invalid/bot)")
fn main() {
    let r = http.get("https://api.ipify.org")
    print("http_ip=" + r.text())
}
