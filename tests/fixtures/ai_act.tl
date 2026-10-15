@ai_risk_level(.minimal)
fn simple_filter(items: []String) -> []String {
    items
}

@ai_risk_level(.high, human_oversight: true, risk_assessment: true, data_governance: true, transparency: true)
fn credit_scoring(income: f64, history: i32) -> f64 {
    income * 0.5
}

fn main() {
    let items = simple_filter(["a", "b"])
    print("filtered: {items.len()}")
    let score = credit_scoring(50000.0, 10)
    print("score: {score}")
}
