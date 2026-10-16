@safety_critical(level: .asil_d)
@requires(speed >= 0.0)
@ensures(result >= 0.0)
fn braking_distance(speed: f64, friction: f64) -> f64 {
    (speed * speed) / (2.0 * friction * 9.81)
}

@safety_critical(level: .asil_b)
fn log_telemetry(data: i32) -> i32 {
    data
}

fn main() {
    let dist = braking_distance(100.0, 0.7)
    print("Braking distance: {dist}")
}
