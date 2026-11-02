struct Point {
    x: i64,
    y: i64
}

struct Person {
    name: String,
    age: i64
}

impl Person {
    fn greet(self) -> String {
        "Hello, I'm {self.name}"
    }
}

fn distance_squared(p: Point) -> i64 {
    p.x * p.x + p.y * p.y
}

fn main() {
    // Struct construction and field access
    let origin = Point { x: 0, y: 0 }
    print("Origin: ({origin.x}, {origin.y})")

    let pt = Point { x: 3, y: 4 }
    print("Point: ({pt.x}, {pt.y})")
    print("Distance squared: {distance_squared(pt)}")

    // Person struct with string field
    let alice = Person { name: "Alice", age: 30 }
    print("{alice.name} is {alice.age} years old")

    // Method call
    print(alice.greet())
}
