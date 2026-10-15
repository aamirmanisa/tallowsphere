enum Color {
    Red,
    Green,
    Blue
}

fn color_name(c: Color) -> String {
    match c {
        0 -> "red"
        1 -> "green"
        2 -> "blue"
        _ -> "unknown"
    }
}

fn main() {
    let c = Color.Red
    print(color_name(c))

    let g = Color.Green
    print(color_name(g))

    let b = Color.Blue
    print(color_name(b))

    // Match on enum
    let status = Color.Green
    let msg = match status {
        0 -> "stop"
        1 -> "go"
        2 -> "calm"
        _ -> "???"
    }
    print(msg)
}
