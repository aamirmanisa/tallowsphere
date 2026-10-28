// N18 — the negative fixture. `203.0.113.7` is TEST-NET-3 and is deliberately absent
// from configs/tallow/scope/authorized-hosts.toml, so the matrix must refuse it by
// name BEFORE a request is built. No fixture server exists on this port: if the gate
// were bypassed the matrix would fail with a transport error instead of a scope
// refusal, and the test would say so.
@cra_class(.default)
@legal(basis: .research, purpose: "negative fixture: unlisted target", personal_data: false)
@persona(id: "api-fixture", cover_class: .researcher, compartment: "intel-api", fingerprint_seed: "api-fixture-1")
@burn_plan(persona: "api-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowApiMatrixFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let src = "https://fixture.test/openapi.json"
    let eps = [api.endpoint("GET", "/public", nil, nil, src)]
    let m = api.method_matrix("http://203.0.113.7:46111", eps, 500)
    print("should not reach here count=" + m.count)
}
