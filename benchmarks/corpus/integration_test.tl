// Tallow Compiler Integration Test
// Every feature that compiles to native binary is tested here

struct Vec2 {
    x: i64,
    y: i64
}

impl Vec2 {
    fn magnitude_sq(self) -> i64 {
        self.x * self.x + self.y * self.y
    }

    fn add(self, other: Vec2) -> Vec2 {
        Vec2 { x: self.x + other.x, y: self.y + other.y }
    }
}

enum Direction {
    North,
    South,
    East,
    West
}

fn apply(f: fn(i64) -> i64, x: i64) -> i64 {
    f(x)
}

fn direction_name(d: i64) -> String {
    match d {
        0 -> "north"
        1 -> "south"
        2 -> "east"
        3 -> "west"
        _ -> "unknown"
    }
}

fn fizzbuzz(n: i64) -> String {
    if n % 15 == 0 {
        "FizzBuzz"
    } else if n % 3 == 0 {
        "Fizz"
    } else if n % 5 == 0 {
        "Buzz"
    } else {
        "num"
    }
}

fn main() {
    var pass = 0
    var fail = 0

    // Test 1: Basic arithmetic
    let result = 2 + 3 * 4
    if result == 14 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: arithmetic")
    }

    // Test 2: String interpolation
    let name = "Tallow"
    let msg = "Hello, {name}!"
    if msg.starts_with("Hello") {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: interpolation")
    }

    // Test 3: String operations
    let s = "Hello, World!"
    if s.contains("World") {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: contains")
    }

    if s.upper() == "HELLO, WORLD!" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: upper")
    }

    // Test 4: Arrays
    let nums = [10, 20, 30, 40, 50]
    if nums.len == 5 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: array.len")
    }

    // Test 5: Map
    let doubled = nums.map { x: i64 -> x * 2 }
    if doubled.len == 5 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: map.len")
    }

    // Test 6: Filter
    let big = nums.filter { x: i64 -> x > 25 }
    if big.len == 3 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: filter.len")
    }

    // Test 7: For loop sum
    var sum = 0
    for i in 0..10 {
        sum = sum + i
    }
    if sum == 45 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: for loop sum = {sum}")
    }

    // Test 8: While loop
    var count = 0
    while count < 5 {
        count = count + 1
    }
    if count == 5 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: while loop count = {count}")
    }

    // Test 9: Closures with capture
    let multiplier = 7
    let mul_fn = { x: i64 -> x * multiplier }
    if apply(mul_fn, 6) == 42 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: closure capture")
    }

    // Test 10: Multiple captures
    let base = 100
    let offset = 50
    let compute = { x: i64 -> x + base + offset }
    if apply(compute, 5) == 155 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: multiple captures")
    }

    // Test 11: Match expression
    let grade = match 90 {
        100 -> "A+"
        90  -> "A"
        80  -> "B"
        _   -> "C"
    }
    if grade == "A" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: match")
    }

    // Test 12: Struct construction + field access
    let pt = Vec2 { x: 3, y: 4 }
    if pt.x == 3 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: struct field")
    }

    // Test 13: Struct method
    if pt.magnitude_sq() == 25 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: struct method")
    }

    // Test 14: Enum variants
    let dir = Direction.East
    if direction_name(dir) == "east" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: enum variant")
    }

    // Test 15: String replace
    let replaced = "foo bar baz".replace("bar", "qux")
    if replaced == "foo qux baz" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: replace")
    }

    // Test 16: String trim
    if "  hello  ".trim() == "hello" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: trim")
    }

    // Test 17: Split
    let parts = "a,b,c".split(",")
    if parts.len == 3 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: split.len")
    }

    // Test 18: FizzBuzz function
    if fizzbuzz(15) == "FizzBuzz" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: fizzbuzz(15)")
    }
    if fizzbuzz(9) == "Fizz" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: fizzbuzz(9)")
    }
    if fizzbuzz(10) == "Buzz" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: fizzbuzz(10)")
    }

    // Test 21: Boolean display
    let has_world = "hello world".contains("world")
    if has_world {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: bool in if")
    }

    // Test 22: Nested if/else
    let temp = 75
    let weather = if temp > 90 {
        "hot"
    } else if temp > 70 {
        "nice"
    } else {
        "cold"
    }
    if weather == "nice" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: nested if")
    }

    // Test 23: String slice
    if "hello world".slice(0, 5) == "hello" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: slice")
    }

    // Test 24: String repeat
    if "-".repeat(3) == "---" {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: repeat")
    }

    // Test 25: to_int
    if "123".to_int() == 123 {
        pass = pass + 1
    } else {
        fail = fail + 1
        print("FAIL: to_int")
    }

    // Summary
    let total = pass + fail
    print("=== Integration Test Results ===")
    print("{pass}/{total} passed")
    if fail == 0 {
        print("ALL TESTS PASSED")
    } else {
        print("{fail} FAILED")
    }
}
