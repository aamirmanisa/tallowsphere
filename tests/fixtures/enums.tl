// Enum declaration, construction, and pattern matching

enum Direction {
    North,
    South,
    East,
    West
}

enum Shape {
    Circle(radius: f64),
    Rectangle(width: f64, height: f64),
    Point
}

fn describe(d: Direction) -> String {
    match d {
        North -> "up"
        South -> "down"
        East  -> "right"
        West  -> "left"
    }
}

fn main() {
    // Unit variants
    let d = Direction.North
    print(describe(d))

    // Data variants
    let s = Shape.Circle(radius: 5.0)
    match s {
        Circle(r) -> print("circle r=" + to_string(r))
        Rectangle(w, h) -> print("rect")
        Point -> print("point")
    }

    // Multiple matches
    let shapes = [Shape.Point, Shape.Circle(radius: 3.0), Shape.Rectangle(width: 4.0, height: 5.0)]
    for shape in shapes {
        match shape {
            Point -> print(".")
            Circle(r) -> print("O")
            Rectangle(w, h) -> print("#")
        }
    }
}
