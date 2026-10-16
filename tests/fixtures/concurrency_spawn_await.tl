fn main() {
    print("m:start")
    let h = spawn worker(5)
    print("m:after-spawn")
    let v = spawn_await(h)
    print("m:val")
    print(v)
    print("m:end")
}
fn worker(x: i32) -> i32 { x * 10 }
