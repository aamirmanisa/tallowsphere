// base.tl — foundational types, imported transitively

pub struct Vec2 {
    x: f64,
    y: f64,
}

pub fn vec2_add(a: Vec2, b: Vec2) -> Vec2 {
    Vec2 { x: a.x + b.x, y: a.y + b.y }
}
