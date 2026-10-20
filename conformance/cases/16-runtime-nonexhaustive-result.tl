fn main() {
    let r = Ok(1)
    let s = r match { Err(e) -> "err" }
    print(s)
}
