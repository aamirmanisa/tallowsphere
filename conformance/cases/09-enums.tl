enum Color { Red, Green, Blue }

fn name_of(c: Color) -> String {
    match c {
        0 -> "red"
        1 -> "green"
        2 -> "blue"
        _ -> "unknown"
    }
}

fn main() {
    print(name_of(Color.Red))
    print(name_of(Color.Blue))
}
