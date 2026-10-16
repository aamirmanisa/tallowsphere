// base.tl — foundational types, imported transitively

struct Vec2 {
    x: f64,
    y: f64,
}

fn vec2_add(a: Vec2, b: Vec2) -> Vec2 {
    Vec2 { x: a.x + b.x, y: a.y + b.y }
}
