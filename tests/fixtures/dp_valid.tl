// Valid differential privacy usage

@epsilon(0.1)
fn private_average(data: f64) -> f64 {
    data.add_noise(epsilon: 0.1)
}

@epsilon(0.5)
@purpose("analytics")
fn analyze_data(x: f64) -> f64 {
    x.add_noise(epsilon: 0.5)
}

@purpose("analytics")
fn report(x: f64) -> f64 {
    analyze_data(x)
}

fn main() {
    let noisy = private_average(42.0)
    print("noisy value: {noisy}")
    let result = analyze_data(100.0)
    print("analyzed: {result}")
}
