// tallow.sync — Channels, mutexes, atomics
//
// Concurrency primitives for safe shared-state communication.

/// Typed channel for message passing
struct Chan<T> {
    // internal: bounded or unbounded channel
}

/// Create a bounded channel
fn channel<T>(capacity: usize) -> Chan<T> {
    // native: creates bounded channel
}

/// Create an unbounded channel
fn unbounded<T>() -> Chan<T> {
    // native: creates unbounded channel
}

impl Chan<T> {
    /// Send value to channel (blocks if full)
    fn send(self, value: T) -> Result<()> {
        // native: sends value
    }

    /// Receive value from channel (blocks if empty)
    fn recv(self) -> Result<T> {
        // native: receives value
    }

    /// Try to receive without blocking
    fn try_recv(self) -> T? {
        // native: returns nil if empty
    }

    /// Close the channel
    fn close(self) {
        // native: closes channel
    }

    /// Number of items in channel
    fn len(self) -> usize {
        // native: current queue length
    }
}

/// Mutex for mutual exclusion
struct Mutex<T> {
    // internal: OS mutex wrapping T
}

fn mutex<T>(value: T) -> Mutex<T> {
    // native: creates mutex
}

impl Mutex<T> {
    /// Lock and get mutable reference
    fn lock(self) -> Result<T> {
        // native: acquires lock, returns guard
    }

    /// Try to lock without blocking
    fn try_lock(self) -> T? {
        // native: returns nil if already locked
    }
}

/// Atomic integer
struct AtomicI64 {
    // internal: atomic i64
}

fn atomic(value: i64) -> AtomicI64 {
    // native: creates atomic
}

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

fn wait_group() -> WaitGroup {
    // native: creates wait group
}

impl WaitGroup {
    fn add(self, count: i64) { /* native */ }
    fn done(self) { /* native: decrements by 1 */ }
    fn wait(self) { /* native: blocks until counter is 0 */ }
}
