fn main() {
    // Match with wildcard, value hits explicit arm
    let x = 2
    let a = match x {
        1 -> 10
        2 -> 20
        3 -> 30
        _ -> 99
    }
    print(a)

    // Match with wildcard, value hits default
    let y = 42
    let b = match y {
        1 -> 100
        2 -> 200
        3 -> 300
        _ -> -1
    }
    print(b)

    // Match with many arms
    let z = 5
    let c = match z {
        1 -> 10
        2 -> 20
        3 -> 30
        4 -> 40
        5 -> 50
        _ -> 0
    }
    print(c)
}
