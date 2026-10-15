fn main() {
    let nums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    // filter then map
    let even_doubled = nums.filter { x: i64 -> x % 2 == 0 }
    let result = even_doubled.map { x: i64 -> x * 10 }

    // Print length
    print(result.len)

    // Print each
    result.each { x: i64 -> print(x) }

    // Simple sum using for loop
    var total = 0
    for x in nums {
        total = total + x
    }
    print(total)
}
