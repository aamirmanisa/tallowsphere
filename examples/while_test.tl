fn main() {
    // Basic while loop
    var i = 0
    while i < 5 {
        i = i + 1
    }
    print(i)

    // While with break
    var j = 0
    while j < 100 {
        if j == 7 {
            break
        }
        j = j + 1
    }
    print(j)

    // While with continue
    var sum = 0
    var k = 0
    while k < 10 {
        k = k + 1
        if k % 2 == 0 {
            continue
        }
        sum = sum + k
    }
    print(sum)

    // Nested loops
    var total = 0
    var a = 0
    while a < 3 {
        var b = 0
        while b < 3 {
            total = total + 1
            b = b + 1
        }
        a = a + 1
    }
    print(total)
}
