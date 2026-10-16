fn main() {
    // Array with map
    let nums = [1, 2, 3, 4, 5]
    let doubled = nums.map { x: i64 -> x * 2 }
    doubled.each { x: i64 -> print(x) }

    // Filter
    let evens = nums.filter { x: i64 -> x % 2 == 0 }
    print(evens.len)

    // Map + print
    let squares = [10, 20, 30]
    let sq = squares.map { x: i64 -> x * x }
    sq.each { x: i64 -> print(x) }
}
