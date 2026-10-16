// bench_io.tl
// I/O-ish benchmark: in a loop create a temp file, write content, read it back,
// then delete it. Exercises the filesystem binding repeatedly.
// Category: io.
//
// Run:
//   tallow run benches/tl/bench_io.tl

fn io_cycle(count: i64) -> i64 {
    var ok = 0
    var i = 0
    while i < count {
        let path = fs.temp_file()
        let payload = "line-{i}: " + "some payload data to write through the fs module"
        fs.write_file(path, payload)
        let read_back = fs.read_file(path)
        if read_back.len() == payload.len() {
            ok = ok + 1
        }
        fs.delete(path)
        i = i + 1
    }
    return ok
}

fn main() {
    let iterations = 100
    let verified = io_cycle(iterations)
    print("io_cycle({iterations}) verified = {verified}")
    print("IO_OK")
}
