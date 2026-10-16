fn apply(f: Fn, x: i32) -> i32 {
    f(x)
}

fn main() {
    let double = { x -> x * 2 }
    let result = apply(double, 5)
    print(result)

    let nums = [1, 2, 3, 4, 5]
    let squared = nums.map({ n -> n * n })
    print(squared)

    let big = nums.filter({ n -> n > 3 })
    print(big)
}
