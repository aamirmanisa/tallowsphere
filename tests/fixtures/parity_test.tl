// parity_test.tl -- Tests all codegen parity features
// Expected output is deterministic (no rand, no time)

enum Color { Red, Green, Blue }

fn safe_divide(a: i64, b: i64) -> Result<i64> {
    if b == 0 { return Err("division by zero") }
    Ok(a / b)
}

fn add(a: i64, b: i64) -> i64 {
    a + b
}

fn greet(name: String) -> String {
    "hello {name}"
}

fn main() {
    // === String methods ===
    let s = "  hello world  "
    print(s.trim())
    print(s.trim_start())
    print(s.trim_end())
    print("hello".reverse())
    print("hello world".contains("world"))
    print("hello".len())
    print("hello world".starts_with("hello"))
    print("hello world".ends_with("world"))
    print("HELLO".lower())
    print("hello".upper())
    print("hello world".replace("world", "tallow"))
    print("hello".repeat(3))

    // === Array methods ===
    let arr = [10, 20, 30, 40, 50]
    print(arr.first())
    print(arr.last())
    print(arr.len())
    print(arr.contains(30))
    print(arr.contains(99))
    print(arr.sum())
    print(arr.min())
    print(arr.max())

    let taken = arr.take(3)
    print(taken.len())

    let skipped = arr.skip(2)
    print(skipped.len())

    // === Result methods ===
    let r1 = safe_divide(10, 2)
    print(r1.is_ok())
    print(r1.unwrap_or(0))

    let r2 = safe_divide(10, 0)
    print(r2.is_err())
    print(r2.unwrap_or(-1))

    // === Map methods ===
    let m = {"name": "tallow", "version": "0.4"}
    print(m.len())
    print(m.contains_key("name"))
    print(m.get("name"))

    // === Enum match ===
    let c = Color.Green
    match c {
        Red -> print("red")
        Green -> print("green")
        Blue -> print("blue")
    }

    // === Basic control flow ===
    for i in 0..5 {
        print(i)
    }

    var count = 0
    while count < 3 {
        print(count)
        count = count + 1
    }

    // === Math operations ===
    print(math.sqrt(16.0))
    print(math.abs(-7.0))
    print(math.floor(3.9))
    print(math.ceil(3.1))

    // === Functions ===
    print(add(17, 25))
    print(greet("tallow"))

    // === Boolean operations ===
    print(true)
    print(false)
    print(5 > 3)
    print(5 < 3)
    print(5 == 5)
    print(5 != 3)

    // === String interpolation ===
    let lang = "tallow"
    let ver = "0.4"
    print("language: {lang}, version: {ver}")

    print("PARITY TEST COMPLETE")
}
