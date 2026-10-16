// 01_control_flow.tl — deterministic control-flow probe.
// Exercises if/else-if/else, while + break, while + continue, and nested loops.
// Both the tree-walker and the CodeGen/native path must print EXACTLY this output.

fn main() {
    // if / else if / else
    let score = 87
    if score >= 90 {
        print("grade A")
    } else if score >= 80 {
        print("grade B")
    } else {
        print("grade C")
    }

    // while + break
    var i = 0
    while i < 100 {
        if i == 5 {
            break
        }
        i = i + 1
    }
    print("break at {i}")

    // while + continue (sum of odd numbers under 10)
    var sum = 0
    var k = 0
    while k < 10 {
        k = k + 1
        if k % 2 == 0 {
            continue
        }
        sum = sum + k
    }
    print("odd sum {sum}")

    // nested while loops
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
    print("nested {total}")
}
