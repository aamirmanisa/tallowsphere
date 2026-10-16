// Struct declaration, methods, and spread syntax

struct Point {
    x: i32,
    y: i32
}

struct Config {
    host: String,
    port: i32,
    debug: bool
}

impl Point {
    fn distance(self) -> f64 {
        // Simplified: just return magnitude squared
        self.x * self.x + self.y * self.y
    }
}

fn main() {
    // Basic struct
    let p = Point { x: 3, y: 4 }
    print(p.x)
    print(p.y)

    // Spread syntax
    let base = Config { host: "localhost", port: 8080, debug: false }
    let dev = Config { ...base, debug: true, port: 3000 }
    print(dev.host)
    print(dev.port)
    print(dev.debug)

    // Struct display
    print(p)
}
