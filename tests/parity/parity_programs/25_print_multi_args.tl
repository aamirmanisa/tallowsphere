// print(...) with more than one argument.
//
// The native backend printed only the first argument and exited 0, so this
// program produced "1" instead of "1 2 3" on the compiled plane while the
// interpreter printed the whole line. Output loss with a success exit code is
// worse than a refusal, so this fixture pins the framing: every argument, one
// space between them, one newline at the end.

fn main() {
    print(1, 2, 3)
    let label = "pair"
    print(label, 4)
    let a = [1, 2, 3]
    print(a[0], a[2])
    print("solo")
}
