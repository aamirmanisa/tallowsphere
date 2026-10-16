// main.tl — multi-file project demo

import math
import models

fn main() {
    // Use imported math functions
    let sum = add(10, 20)
    let product = multiply(5, 6)
    let fact = factorial(5)
    print("Sum: {sum}")
    print("Product: {product}")
    print("5! = {fact}")

    // Use imported struct
    let p = Point { x: 3.0, y: 4.0 }
    print("Distance: {p.distance()}")

    let cfg = Config { name: "debug", value: 1 }
    print("Config: {cfg.name} = {cfg.value}")

    // Use Vec2 from base.tl (transitive import: main → models → base)
    let v1 = Vec2 { x: 1.0, y: 2.0 }
    let v2 = Vec2 { x: 3.0, y: 4.0 }
    let v3 = vec2_add(v1, v2)
    print("Vec2 add: ({v3.x}, {v3.y})")
}
