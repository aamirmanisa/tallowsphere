fn main() {
    let greeting = "Hello, World!"

    // Length
    print(greeting.len)

    // Contains
    if greeting.contains("World") {
        print("found World")
    }

    // Starts with / ends with
    if greeting.starts_with("Hello") {
        print("starts with Hello")
    }
    if greeting.ends_with("!") {
        print("ends with !")
    }

    // Upper / Lower
    let upper = greeting.upper()
    print(upper)
    let lower = greeting.lower()
    print(lower)

    // Replace
    let replaced = greeting.replace("World", "Tallow")
    print(replaced)

    // Trim
    let padded = "  spaces  "
    let trimmed = padded.trim()
    print(trimmed)

    // Repeat
    let dash = "-"
    let line = dash.repeat(10)
    print(line)

    // Parse int
    let num_str = "42"
    let num = num_str.to_int()
    print(num + 8)

    // Split
    let csv = "a,b,c"
    let parts = csv.split(",")
    print(parts.len)

    // Slice
    let sub = greeting.slice(0, 5)
    print(sub)

    // Is empty
    let empty = ""
    if empty.is_empty() {
        print("empty string")
    }
}
