// F1 cooperative-scheduler fixture: FIFO task order + suspend-on-await proof.
//
// In coop mode (TALLOW_SCHED=coop) nothing runs until a driver pumps the queue:
//   main spawns mid + other (deferred), then awaits mid.
// The driver runs ready tasks FIFO, so the deterministic trace is:
//   main:await-mid, mid:start, mid:waiting, other:run, leaf:run, mid:done,
//   main:mid-done, 42, 1
// "other:run" appearing BETWEEN "mid:waiting" and "mid:done" is the proof that
// mid's await really suspended it: the scheduler made progress on another ready
// task instead of mid blocking the only thread.
//
// spawn_await returns Result<Value> (the established contract in legacy-thread
// and native modes alike); the fixture unwraps with .unwrap() so the trace
// prints the raw values and the expected order below stays exact.
fn leaf() -> i32 {
    print("leaf:run")
    40
}

fn mid() -> i32 {
    print("mid:start")
    let h = spawn leaf()
    print("mid:waiting")
    let r = spawn_await(h).unwrap()
    print("mid:done")
    r + 2
}

fn other() -> i32 {
    print("other:run")
    1
}

fn main() {
    let hm = spawn mid()
    let ho = spawn other()
    print("main:await-mid")
    let rm = spawn_await(hm)
    print("main:mid-done")
    print(rm.unwrap())
    let ro = spawn_await(ho)
    print(ro.unwrap())
}
