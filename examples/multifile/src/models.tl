// models.tl — data types (imports from base.tl transitively)
import base

struct Point {
    x: f64,
    y: f64,
}

impl Point {
    fn distance(self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}

struct Config {
    name: String,
    value: i64,
}
