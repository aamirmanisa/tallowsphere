struct Person {
    name: String,
    age: i32,
    city: String
}

struct Schema {
    name: String,
    age: String,
    email: String
}

fn main() {
    let people = [
        Person { name: "Alice", age: 25, city: "NYC" },
        Person { name: "Bob", age: 26, city: "NYC" },
        Person { name: "Carol", age: 25, city: "LA" },
        Person { name: "Dave", age: 30, city: "NYC" },
        Person { name: "Eve", age: 31, city: "LA" },
        Person { name: "Frank", age: 25, city: "NYC" }
    ]

    let anon = people.anonymize(k: 2)
    print("anonymized {anon.len()} records")

    let schema = Schema { name: "String", age: "i32", email: "Email" }
    let synthetic = Dataset.synthesize(schema, n: 5)
    print("synthesized {synthetic.len()} records")
}
