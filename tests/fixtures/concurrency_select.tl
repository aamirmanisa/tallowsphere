// Phase 1: Select across multiple channels
// Verifies: select receives from the first ready channel,
// and default fires when no channel is ready.

fn main() {
    let ch1 = sync.channel(10)
    let ch2 = sync.channel(10)

    // Send on ch1, leave ch2 empty
    ch1.send("from-ch1")

    // Test 1: Select with data on one channel + default
    select {
        recv(ch1) -> val {
            print(val)
        }
        recv(ch2) -> val {
            print(val)
        }
        default {
            print("default-should-not-fire")
        }
    }

    // Test 2: Both empty with default — default should fire
    select {
        recv(ch2) -> val {
            print("should-not-receive")
        }
        default {
            print("default-fired")
        }
    }

    // Test 3: Send on both, select picks one (non-deterministic)
    ch1.send("A")
    ch2.send("B")

    select {
        recv(ch1) -> val {
            print(val)
        }
        recv(ch2) -> val {
            print(val)
        }
    }

    print("select-test-done")
}
