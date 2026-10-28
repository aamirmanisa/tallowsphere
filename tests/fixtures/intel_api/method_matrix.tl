// N18 — method matrix against a loopback fixture.
//
// Six paths, one per shape the matrix must distinguish:
//
//   /public      OPTIONS answers 204 with `Allow` and `Access-Control-Allow-Origin: *`
//   /no-options  OPTIONS is refused 405, HEAD answers 200 with `Server`/`Content-Type`
//   /bearer      OPTIONS answers 401 with `WWW-Authenticate: Bearer ...`
//   /bare-401    OPTIONS answers 401 with NO `WWW-Authenticate` — must not be read as `basic`
//   /users/{id}  a template (`{{id}}` in this literal — braces interpolate): never
//                requested, counted in `skipped_templated`
//
// `GET /public` and `POST /public` are declared separately on purpose: one path is one
// probe, and `declared_methods` is what the document said versus what `Allow` showed.
//
// The port is fixed so the program is self-contained; tests/intel_api_method_matrix.rs
// binds it. Nothing here leaves loopback.
@cra_class(.default)
@legal(basis: .research, purpose: "loopback method-matrix probe; no external egress", personal_data: false)
@persona(id: "api-fixture", cover_class: .researcher, compartment: "intel-api", fingerprint_seed: "api-fixture-1")
@burn_plan(persona: "api-fixture", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .none, bot_identity: "TallowApiMatrixFixture/1.0 (+https://tallow.invalid/bot)")
fn main() with Net {
    let src = "https://fixture.test/openapi.json"
    let eps = [
        api.endpoint("GET", "/public", nil, nil, src),
        api.endpoint("POST", "/public", nil, nil, src),
        api.endpoint("GET", "/no-options", nil, nil, src),
        api.endpoint("GET", "/bearer", nil, nil, src),
        api.endpoint("GET", "/bare-401", nil, nil, src),
        api.endpoint("GET", "/users/{{id}}", nil, nil, src),
    ]

    let m = api.method_matrix("http://127.0.0.1:46111", eps, 2000)
    print("matrix count=" + m.count + " options=" + m.options_answered + " head=" + m.head_fallbacks + " templated=" + m.skipped_templated)
    print("grant=" + m.scope_grant)
    for r in m.rows {
        print("row path=" + r.path + " method=" + r.method + " status=" + r.status + " allow=" + r.allow + " auth=" + r.auth + " cors=" + r.cors + " from=" + r.cors_source + " declared=" + r.declared_methods)
        print("ev " + r.evidence)
    }
}
