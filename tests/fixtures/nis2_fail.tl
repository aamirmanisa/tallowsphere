// Fixture: NIS2 FAIL case — forbidden algorithm (MD5, BSI TR-02102).
// `tallow audit --nis2` must exit 2 (nis2_errors > 0).
@legal(basis: .legitimate_interest, purpose: "legacy hash compatibility", lia_completed: true)
fn legacy_digest(data: String) -> String {
    data.hash(algo: .md5)
}

fn main() {
    print(legacy_digest("x"))
}
