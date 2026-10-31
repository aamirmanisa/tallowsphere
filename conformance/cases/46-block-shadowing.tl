// An inner `let` shadows the outer binding only inside its block.
//
// The native plane kept one flat name table, so the inner binding overwrote the
// outer slot permanently: the block printed 2 (correct) and so did the line
// after it (wrong, the outer value is 1). Fixed by snapshotting every
// name-to-binding table on block entry and restoring it on exit.
fn main() {
    let a = 1
    {
        let a = 2
        print(a)
    }
    print(a)

    // The same, nested two deep, and with the outer value read again after.
    let b = 10
    {
        let b = 20
        {
            let b = 30
            print(b)
        }
        print(b)
    }
    print(b)
}
