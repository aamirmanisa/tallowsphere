// Index assignment must store.
//
// The native Assign lowering handled identifiers and field accesses only; any
// other target fell into a branch that computed the right-hand side and threw
// it away. So `a[1] = 20` left the element at its old value and the program
// exited 0 looking healthy. Both the array and map forms are pinned here.
// Fixed by an `Index` arm in the Assign lowering: maps route to the map store,
// arrays to a bounds-checked slot store, strings are refused as immutable.
fn main() {
    var a = [1, 2, 3]
    a[1] = 20
    print(a[1])

    var m = {"a": 1}
    m["a"] = 5
    print(m["a"])

    // Store then read back through a computed index.
    var i = 0
    a[i] = 99
    print(a[0])
}
