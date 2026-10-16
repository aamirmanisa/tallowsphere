// Phase 1: Channel communication test
// Verifies: channel() creates a channel, send/recv work in main goroutine,
// try_recv works on empty buffer, and ordering is FIFO.

fn main() {
    // Test 1: Basic send/recv
    let ch = channel(10)
    ch.send("hello-channel")
    let msg = ch.recv()
    print(msg)

    // Test 2: Multiple messages (FIFO)
    ch.send("first")
    ch.send("second")
    ch.send("third")
    let a = ch.recv()
    let b = ch.recv()
    let c = ch.recv()
    print(a)
    print(b)
    print(c)

    // Test 3: try_recv on empty channel returns Nil
    let empty_result = ch.try_recv()
    print(empty_result)

    print("channel-test-done")
}
