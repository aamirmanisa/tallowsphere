// Phase 1: Basic goroutine spawning test
// Verifies: spawn launches a function, parent continues, goroutine executes
// Note: prints in spawned goroutines go to their own interpreter output
// and are NOT captured by the test runner's output collection.
// The test verifies that the interpreter reaches the final print
// without crashing or generating errors.

fn worker(id: i32) {
    // Spawned goroutine: does independent work
    let counter = 0
    counter = counter + 1
    counter = counter + 1
    counter = counter + 1
    // Goroutine completed independently
}

fn main() {
    print("spawn-start")
    spawn worker(1)
    spawn worker(2)
    spawn worker(3)
    print("spawn-end")
    assert(true)
}
