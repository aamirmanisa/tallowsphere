// Positive half of the spawn row: the same task with the forwarded row declared
// on the spawning body compiles. A spawned task is not an escape hatch — it is
// a call that runs later, so the caller owns the row it reaches.
@legal(basis: .public_data, purpose: "spawn row fixture")
fn worker(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}

@legal(basis: .public_data, purpose: "spawn row fixture")
fn outer(g: Grant<Net>, h: String) with Net(connect) {
    spawn worker(g, h)
}

@legal(basis: .public_data, purpose: "spawn row fixture")
fn main() {
    print("no network here")
}
