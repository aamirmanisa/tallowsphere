// tallow.sync — Channels, mutexes, atomics
//
// Concurrency primitives for safe shared-state communication.

/// Typed channel for message passing
struct Chan<T> {
    // internal: bounded or unbounded channel
}

/// Create a bounded channel
// native: creates bounded channel
native fn channel<T>(capacity: usize) -> Chan<T>

/// Create an unbounded channel
// native: creates unbounded channel
native fn unbounded<T>() -> Chan<T>

impl Chan<T> {
    /// Send value to channel (blocks if full)
    // native: sends value
    native fn send(self, value: T) -> Result<()>

    /// Receive value from channel (blocks if empty)
    // native: receives value
    native fn recv(self) -> Result<T>

    /// Try to receive without blocking
    // native: returns nil if empty
    native fn try_recv(self) -> T?

    /// Close the channel
    // native: closes channel
    native fn close(self)

    /// Number of items in channel
    // native: current queue length
    native fn len(self) -> usize
}

/// Mutex for mutual exclusion
struct Mutex<T> {
    // internal: OS mutex wrapping T
}

// native: creates mutex
native fn mutex<T>(value: T) -> Mutex<T>

impl Mutex<T> {
    /// Lock and get mutable reference
    // native: acquires lock, returns guard
    native fn lock(self) -> Result<T>

    /// Try to lock without blocking
    // native: returns nil if already locked
    native fn try_lock(self) -> T?
}

/// Atomic integer
struct AtomicI64 {
    // internal: atomic i64
}

// native: creates atomic
native fn atomic(value: i64) -> AtomicI64

impl AtomicI64 {
    fn load(self) -> i64 { /* native */ }
    fn store(self, value: i64) { /* native */ }
    fn add(self, delta: i64) -> i64 { /* native: returns previous value */ }
    fn sub(self, delta: i64) -> i64 { /* native */ }
    fn compare_swap(self, expected: i64, new: i64) -> bool { /* native */ }
}

/// WaitGroup for synchronizing goroutine-like tasks
struct WaitGroup {
    // internal: counter
}

// native: creates wait group
native fn wait_group() -> WaitGroup

impl WaitGroup {
    fn add(self, count: i64) { /* native */ }
    fn done(self) { /* native: decrements by 1 */ }
    fn wait(self) { /* native: blocks until counter is 0 */ }
}
