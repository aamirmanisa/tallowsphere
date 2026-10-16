struct User {
    name: String,
    age: i64,
}

fn main() {
    let u = User { name: "Alice", age: 30 }

    // String interpolation with struct field access
    print("Name: {u.name}")
    print("Age: {u.age}")

    // Result with string value
    let ok = Ok("hello")
    print(ok)

    let err = Err("something failed")
    print(err)

    // Nested: struct field in for loop with interpolation
    let users = [
        User { name: "Alice", age: 30 },
        User { name: "Bob", age: 25 }
    ]
    for u in users {
        print("{u.name} is {u.age} years old")
    }
}
