type Password = secret String
type Token = secret String

// Should trigger E1200: secret-dependent branch
fn bad_compare(pw: Password, input: String) -> bool {
    if pw == input {
        true
    } else {
        false
    }
}

// Should be clean: uses allowlisted method
fn good_verify(pw: Password, hash: String) -> bool {
    pw.verify(hash)
}

// Should trigger E1203: secret-dependent index
fn bad_index(key: Token, data: []i32) -> i32 {
    let idx = key.len()
    data[idx]
}

fn main() {
    let pw = "test123" as Password
    let ok = good_verify(pw, "hash")
    print("verify: {ok}")
}
