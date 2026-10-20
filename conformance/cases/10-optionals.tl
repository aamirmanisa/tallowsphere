fn find(hit: bool) -> i64? {
    if hit {
        return 7
    }
    return nil
}

fn main() {
    print(find(true))
    print(find(false))
    print(find(true) == nil)
    print(find(false) == nil)
}
