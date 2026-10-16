@opsec(profile: "alpha")
fn alpha_work() -> String { "alpha" }

@opsec(profile: "beta")
fn beta_work() -> String { alpha_work() }

fn main() {
    let x = beta_work()
    print(x)
}
