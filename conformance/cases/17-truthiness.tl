fn main() {
    print(if 0 { "T" } else { "F" })
    print(if "" { "T" } else { "F" })
    print(if nil { "T" } else { "F" })
    print(if [] { "T" } else { "F" })
    print(if 1 { "T" } else { "F" })
    print(if "x" { "T" } else { "F" })
}
