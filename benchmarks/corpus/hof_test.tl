fn main() {
    // Test map
    let nums = [1, 2, 3, 4, 5]
    let doubled = nums.map { x -> x * 2 }
    print("Doubled:")
    for x in doubled {
        print(x)
    }

    // Test filter
    let evens = nums.filter { x -> x % 2 == 0 }
    print("Evens:")
    for x in evens {
        print(x)
    }

    // Test each
    print("Each:")
    nums.each { x -> print(x * 10) }
}
