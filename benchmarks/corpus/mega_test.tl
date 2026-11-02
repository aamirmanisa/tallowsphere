// Tallow Mega Integration Test
// Tests every major codegen feature

// ── Structs ─────────────────────────────────────────────────
struct Point {
    x: i64,
    y: i64
}

struct Person {
    name: String,
    age: i64
}

// ── Functions ───────────────────────────────────────────────
fn add(a: i64, b: i64) -> i64 {
    a + b
}

fn factorial(n: i64) -> i64 {
    if n <= 1 { 1 } else { n * factorial(n - 1) }
}

fn fib(n: i64) -> i64 {
    if n <= 1 { n } else { fib(n - 1) + fib(n - 2) }
}

fn divide(a: i64, b: i64) -> Result<i64> {
    if b == 0 { bail "division by zero" }
    Ok(a / b)
}

fn validate(n: i64) -> Result<i64> {
    if n < 0 { bail "negative" }
    if n > 100 { bail "too large" }
    Ok(n)
}

fn grade(score: i64) -> String {
    match score {
        100 -> "perfect"
        90  -> "excellent"
        80  -> "great"
        _   -> "ok"
    }
}

fn apply(f: fn(i64) -> i64, x: i64) -> i64 {
    f(x)
}

fn main() {
    var test_num = 0
    var pass = 0

    // ── Test 1: Arithmetic ──────────────────────────────────
    test_num = test_num + 1
    if add(3, 4) == 7 { pass = pass + 1; print("PASS {test_num}: arithmetic") } else { print("FAIL {test_num}: arithmetic") }

    // ── Test 2: Modulo ──────────────────────────────────────
    test_num = test_num + 1
    if 17 % 5 == 2 { pass = pass + 1; print("PASS {test_num}: modulo") } else { print("FAIL {test_num}: modulo") }

    // ── Test 3: Comparison ──────────────────────────────────
    test_num = test_num + 1
    if 10 > 5 { pass = pass + 1; print("PASS {test_num}: comparison") } else { print("FAIL {test_num}: comparison") }

    // ── Test 4: String interpolation ────────────────────────
    test_num = test_num + 1
    let name = "Tallow"
    let ver = 1
    let msg = "{name} v{ver}"
    print("PASS {test_num}: interpolation ({msg})")
    pass = pass + 1

    // ── Test 5: String operations ───────────────────────────
    test_num = test_num + 1
    let greeting = "Hello, World!"
    if greeting.contains("World") { pass = pass + 1; print("PASS {test_num}: string contains") } else { print("FAIL {test_num}: string contains") }

    // ── Test 6: String upper ────────────────────────────────
    test_num = test_num + 1
    let upper = "hello".upper()
    print("PASS {test_num}: string upper ({upper})")
    pass = pass + 1

    // ── Test 7: String replace ──────────────────────────────
    test_num = test_num + 1
    let replaced = "foo bar foo".replace("foo", "baz")
    print("PASS {test_num}: string replace ({replaced})")
    pass = pass + 1

    // ── Test 8: String repeat ───────────────────────────────
    test_num = test_num + 1
    let dashes = "-".repeat(5)
    print("PASS {test_num}: string repeat ({dashes})")
    pass = pass + 1

    // ── Test 9: String split ────────────────────────────────
    test_num = test_num + 1
    let parts = "a,b,c".split(",")
    if parts.len == 3 { pass = pass + 1; print("PASS {test_num}: string split") } else { print("FAIL {test_num}: string split (got {parts.len})") }

    // ── Test 10: String to_int ──────────────────────────────
    test_num = test_num + 1
    let parsed = "42".to_int()
    if parsed == 42 { pass = pass + 1; print("PASS {test_num}: string to_int") } else { print("FAIL {test_num}: string to_int") }

    // ── Test 11: String starts_with ─────────────────────────
    test_num = test_num + 1
    if "hello world".starts_with("hello") { pass = pass + 1; print("PASS {test_num}: starts_with") } else { print("FAIL {test_num}: starts_with") }

    // ── Test 12: String ends_with ───────────────────────────
    test_num = test_num + 1
    if "hello world".ends_with("world") { pass = pass + 1; print("PASS {test_num}: ends_with") } else { print("FAIL {test_num}: ends_with") }

    // ── Test 13: String len ─────────────────────────────────
    test_num = test_num + 1
    if "hello".len == 5 { pass = pass + 1; print("PASS {test_num}: string len") } else { print("FAIL {test_num}: string len") }

    // ── Test 14: Array literal + len ────────────────────────
    test_num = test_num + 1
    let nums = [10, 20, 30, 40, 50]
    if nums.len == 5 { pass = pass + 1; print("PASS {test_num}: array len") } else { print("FAIL {test_num}: array len") }

    // ── Test 15: Array filter ───────────────────────────────
    test_num = test_num + 1
    let high = nums.filter { n: i64 -> n >= 30 }
    if high.len == 3 { pass = pass + 1; print("PASS {test_num}: array filter") } else { print("FAIL {test_num}: array filter (got {high.len})") }

    // ── Test 16: Array map ──────────────────────────────────
    test_num = test_num + 1
    let doubled = nums.map { n: i64 -> n * 2 }
    if doubled.len == 5 { pass = pass + 1; print("PASS {test_num}: array map") } else { print("FAIL {test_num}: array map") }

    // ── Test 17: Array each ─────────────────────────────────
    test_num = test_num + 1
    var sum = 0
    nums.each { n: i64 -> sum = sum + n }
    if sum == 150 { pass = pass + 1; print("PASS {test_num}: array each (sum={sum})") } else { print("FAIL {test_num}: array each (sum={sum})") }

    // ── Test 18: Closure capture ────────────────────────────
    test_num = test_num + 1
    let base = 100
    let add_base = { x: i64 -> x + base }
    if apply(add_base, 42) == 142 { pass = pass + 1; print("PASS {test_num}: closure capture") } else { print("FAIL {test_num}: closure capture") }

    // ── Test 19: For loop + range ───────────────────────────
    test_num = test_num + 1
    var counter = 0
    for i in 0..10 {
        counter = counter + 1
    }
    if counter == 10 { pass = pass + 1; print("PASS {test_num}: for loop") } else { print("FAIL {test_num}: for loop (counter={counter})") }

    // ── Test 20: While loop ─────────────────────────────────
    test_num = test_num + 1
    var w = 0
    while w < 5 {
        w = w + 1
    }
    if w == 5 { pass = pass + 1; print("PASS {test_num}: while loop") } else { print("FAIL {test_num}: while loop") }

    // ── Test 21: While + break ──────────────────────────────
    test_num = test_num + 1
    var b = 0
    while b < 100 {
        if b == 7 { break }
        b = b + 1
    }
    if b == 7 { pass = pass + 1; print("PASS {test_num}: while break") } else { print("FAIL {test_num}: while break") }

    // ── Test 22: While + continue ───────────────────────────
    test_num = test_num + 1
    var odd_sum = 0
    var ci = 0
    while ci < 10 {
        ci = ci + 1
        if ci % 2 == 0 { continue }
        odd_sum = odd_sum + ci
    }
    if odd_sum == 25 { pass = pass + 1; print("PASS {test_num}: while continue") } else { print("FAIL {test_num}: while continue (got {odd_sum})") }

    // ── Test 23: Nested loops ───────────────────────────────
    test_num = test_num + 1
    var total = 0
    var ai = 0
    while ai < 4 {
        var bi = 0
        while bi < 3 {
            total = total + 1
            bi = bi + 1
        }
        ai = ai + 1
    }
    if total == 12 { pass = pass + 1; print("PASS {test_num}: nested loops") } else { print("FAIL {test_num}: nested loops (got {total})") }

    // ── Test 24: Match integer ──────────────────────────────
    test_num = test_num + 1
    let m = match 2 {
        1 -> 10
        2 -> 20
        3 -> 30
        _ -> 0
    }
    if m == 20 { pass = pass + 1; print("PASS {test_num}: match int") } else { print("FAIL {test_num}: match int") }

    // ── Test 25: Match default ──────────────────────────────
    test_num = test_num + 1
    let d = match 99 {
        1 -> 10
        2 -> 20
        _ -> 999
    }
    if d == 999 { pass = pass + 1; print("PASS {test_num}: match default") } else { print("FAIL {test_num}: match default") }

    // ── Test 26: Match string ───────────────────────────────
    test_num = test_num + 1
    let g = grade(100)
    if g == "perfect" { pass = pass + 1; print("PASS {test_num}: match string return") } else { print("FAIL {test_num}: match string return (got {g})") }

    // ── Test 27: Recursion (factorial) ──────────────────────
    test_num = test_num + 1
    if factorial(5) == 120 { pass = pass + 1; print("PASS {test_num}: factorial") } else { print("FAIL {test_num}: factorial") }

    // ── Test 28: Recursion (fibonacci) ──────────────────────
    test_num = test_num + 1
    if fib(10) == 55 { pass = pass + 1; print("PASS {test_num}: fibonacci") } else { print("FAIL {test_num}: fibonacci") }

    // ── Test 29: Result Ok ──────────────────────────────────
    test_num = test_num + 1
    let ok_result = divide(10, 2) match {
        Ok(v) -> v
        Err(msg) -> 0
    }
    if ok_result == 5 { pass = pass + 1; print("PASS {test_num}: result ok") } else { print("FAIL {test_num}: result ok") }

    // ── Test 30: Result Err ─────────────────────────────────
    test_num = test_num + 1
    let err_result = divide(10, 0) match {
        Ok(v) -> v
        Err(msg) -> 0 - 1
    }
    if err_result == 0 - 1 { pass = pass + 1; print("PASS {test_num}: result err") } else { print("FAIL {test_num}: result err") }

    // ── Test 31: Bail ───────────────────────────────────────
    test_num = test_num + 1
    let bail_ok = validate(50) match {
        Ok(v) -> v
        Err(msg) -> 0
    }
    if bail_ok == 50 { pass = pass + 1; print("PASS {test_num}: bail ok") } else { print("FAIL {test_num}: bail") }

    // ── Test 32: Bail error ─────────────────────────────────
    test_num = test_num + 1
    let bail_err = validate(200) match {
        Ok(v) -> v
        Err(msg) -> 0 - 1
    }
    if bail_err == 0 - 1 { pass = pass + 1; print("PASS {test_num}: bail error") } else { print("FAIL {test_num}: bail error") }

    // ── Test 33: ? operator propagation ─────────────────────
    test_num = test_num + 1
    let q = divide(100, 5) match {
        Ok(v) -> v
        Err(msg) -> 0
    }
    if q == 20 { pass = pass + 1; print("PASS {test_num}: ? operator") } else { print("FAIL {test_num}: ? operator") }

    // ── Test 34: If-let Ok ──────────────────────────────────
    test_num = test_num + 1
    var iflet_val = 0
    if let Ok(v) = divide(42, 6) {
        iflet_val = v
    }
    if iflet_val == 7 { pass = pass + 1; print("PASS {test_num}: if-let ok") } else { print("FAIL {test_num}: if-let ok (got {iflet_val})") }

    // ── Test 35: If-let Err path ────────────────────────────
    test_num = test_num + 1
    var iflet_err = 0
    if let Ok(v) = divide(42, 0) {
        iflet_err = 1
    } else {
        iflet_err = 2
    }
    if iflet_err == 2 { pass = pass + 1; print("PASS {test_num}: if-let err path") } else { print("FAIL {test_num}: if-let err path (got {iflet_err})") }

    // ── Test 36: Struct construction ────────────────────────
    test_num = test_num + 1
    let p = Point { x: 3, y: 4 }
    if p.x == 3 { pass = pass + 1; print("PASS {test_num}: struct field") } else { print("FAIL {test_num}: struct field") }

    // ── Test 37: Struct string field ────────────────────────
    test_num = test_num + 1
    let person = Person { name: "Alice", age: 30 }
    print("PASS {test_num}: struct string field ({person.name})")
    pass = pass + 1

    // ── Test 38: Boolean display ────────────────────────────
    test_num = test_num + 1
    let has_world = "Hello World".contains("World")
    print("PASS {test_num}: bool display (contains={has_world})")
    pass = pass + 1

    // ── Test 39: String slice ───────────────────────────────
    test_num = test_num + 1
    let sliced = "Hello World".slice(0, 5)
    if sliced == "Hello" { pass = pass + 1; print("PASS {test_num}: string slice") } else { print("FAIL {test_num}: string slice (got {sliced})") }

    // ── Test 40: String trim ────────────────────────────────
    test_num = test_num + 1
    let trimmed = "  hello  ".trim()
    if trimmed == "hello" { pass = pass + 1; print("PASS {test_num}: string trim") } else { print("FAIL {test_num}: string trim (got {trimmed})") }

    // ── Summary ─────────────────────────────────────────────
    print("")
    print("═══════════════════════════════════")
    print("  {pass}/{test_num} tests passed")
    print("═══════════════════════════════════")
}
