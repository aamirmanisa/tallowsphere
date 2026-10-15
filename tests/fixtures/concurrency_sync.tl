// Phase 1: Synchronization primitives (Mutex, RwLock, Barrier, Once)
// Verifies: All four primitives construct and work via module dispatch

fn main() {
    // Test 1: Mutex — construct, lock, read value, unlock
    let m = sync.mutex(42)
    print(m.value)
    let guard = m.lock()
    print(guard.value)

    // Test 2: RwLock — construct, read value
    let rw = sync.rwlock("hello-rwlock")
    print(rw.value)
    let r = rw.read()
    print(r.value)

    // Test 3: Barrier — construct, wait
    let b = sync.barrier(2)
    b.wait()
    print("barrier-ok")

    // Test 4: Once — construct, do (should return true)
    let o = sync.once()
    print(o.called)
    let result = o.do()
    print(result)

    print("sync-test-done")
}
