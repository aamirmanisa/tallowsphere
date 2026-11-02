fn main() {
    let a = "hello"
    let b = "hello"
    let c = "world"

    // String equality
    if a == b {
        print("a == b: true")
    } else {
        print("a == b: false")
    }

    if a == c {
        print("a == c: true")
    } else {
        print("a == c: false")
    }

    // String inequality
    if a != c {
        print("a != c: true")
    } else {
        print("a != c: false")
    }
}
