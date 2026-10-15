// Channels demo: bounded + unbounded channels via the sync module.
//
// Run: tallow run examples/channels_demo.tl

fn main() {
    print("=== Tallow Channels Demo ===")

    // Bounded channel (capacity 4)
    let ch = sync.channel(4)
    print("Channel created (capacity 4)")

    // Send values, then receive them in order
    ch.send("hello from producer")
    ch.send("data packet 1")
    ch.send("data packet 2")
    print("Sent 3 messages")

    let msg1 = ch.recv()
    let msg2 = ch.recv()
    let msg3 = ch.recv()
    print("Received: {msg1}, {msg2}, {msg3}")

    // try_recv on an empty channel: non-blocking, returns nil
    let empty = ch.try_recv()
    print("try_recv on empty channel: {empty}")

    // Unbounded channel
    let u = sync.unbounded()
    u.send(1)
    u.send(2)
    let a = u.recv()
    let b = u.recv()
    let s = a + b
    print("Unbounded received sum: {s}")

    print("Done")
}
