// Release-quality local example: public-source GET batch.
// Runs only against the loopback fixture server documented in examples/README.md.
// Non-claims: no public internet, no secrets, no browser fallback, no production compliance.

import tallow.http

@cra_class(.class_i)
@legal(basis: .public_data, purpose: "local fixture public-source GET batch example", personal_data: false, robots_txt: .respect)
fn main() {
    let target_urls = [
        "http://127.0.0.1:18080/status?case=batch-a",
        "http://127.0.0.1:18080/api/products"
    ]

    let headers = {
        "Accept": "application/json",
        "User-Agent": "TallowExamples/1.0 local-fixture"
    }

    let l1_concurrency = 2
    let responses = http.batch(target_urls, l1_concurrency, headers)
    print("public_source_get_batch planned=" + target_urls.len.to_string())
    print("public_source_get_batch responses=" + responses.len.to_string())
}
