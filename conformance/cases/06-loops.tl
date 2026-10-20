fn main() {
    var total = 0
    for i in [1, 2, 3, 4] {
        total += i
    }
    print(total)

    var n = 0
    while n < 3 {
        n += 1
    }
    print(n)

    var seen = ""
    for x in [1, 2, 3, 4] {
        if x == 2 { continue }
        if x == 4 { break }
        seen = "{seen}{x}"
    }
    print(seen)
}
