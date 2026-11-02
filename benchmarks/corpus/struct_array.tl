struct Price {
    value: i64,
    name: String,
}

fn main() {
    let p1 = Price { value: 100, name: "apple" }
    let p2 = Price { value: 200, name: "banana" }

    // Test: struct field access (should already work)
    print(p1.value)
    print(p1.name)

    // Test: array of structs
    let prices = [p1, p2]
    print(prices.len)

    // Test: for loop over struct array
    for p in prices {
        print(p.value)
    }
}
