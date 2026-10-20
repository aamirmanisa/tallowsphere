fn main() {
    defer { print("first-defer") }
    defer { print("second-defer") }
    print("body")
}
