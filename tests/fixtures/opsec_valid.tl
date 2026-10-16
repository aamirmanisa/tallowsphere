@opsec(profile: "alpha")
fn alpha_work() -> String { "alpha" }

@opsec(profile: "alpha")
fn alpha_helper() -> String { alpha_work() }

fn shared_util() -> String { "shared" }

fn main() {
    let x = alpha_helper()
    let y = shared_util()
    print(x)
    print(y)
}
