struct Item {
    name: String,
    value: i64,
}

fn sum_values(items: []Item) -> i64 {
    var total = 0
    for item in items {
        total = total + item.value
    }
    total
}

fn main() {
    let a = Item { name: "x", value: 10 }
    let b = Item { name: "y", value: 20 }
    let items = [a, b]
    let result = sum_values(items)
    print("Total: {result}")
}
