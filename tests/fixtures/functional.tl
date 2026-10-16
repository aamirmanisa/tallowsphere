// Functional programming: closures, map, filter, reduce, chaining

fn apply(f: Fn, x: i32) -> i32 {
    f(x)
}

fn compose(f: Fn, g: Fn) -> Fn {
    { x -> f(g(x)) }
}

fn main() {
    // Higher-order functions
    let double = { x -> x * 2 }
    let add10 = { x -> x + 10 }
    print(apply(double, 5))
    print(apply(add10, 5))

    // Method chaining
    let nums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    let result = nums
        .filter({ x -> x % 2 == 0 })
        .map({ x -> x * x })
    print(result)

    // Reduce
    let sum = nums.reduce({ acc, x -> acc + x })
    print("sum = " + to_string(sum))

    // find / any / all
    let first_big = nums.find({ x -> x > 7 })
    print("first > 7: " + to_string(first_big))

    print(nums.any({ x -> x > 9 }))
    print(nums.all({ x -> x > 0 }))

    // sort + reverse
    let unsorted = [5, 3, 8, 1, 9, 2]
    print(unsorted.sort())
    print(unsorted.sort().reverse())

    // zip + enumerate
    let keys = ["a", "b", "c"]
    let vals = [1, 2, 3]
    print(keys.zip(vals))
    print(keys.enumerate())
}
