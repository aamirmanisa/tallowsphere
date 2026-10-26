// G01 (audit F-9/F-10): the `spawn` arm of the expression walk was `{}`, so a
// task expression was never checked — neither its row nor its arguments. A
// `spawn` is a call: `worker` declares `Net(connect)`, so spawning it from a
// body with no row is a requirement of *this* body and is refused here.
@legal(basis: .public_data, purpose: "spawn row fixture")
fn worker(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}

@legal(basis: .public_data, purpose: "spawn row fixture")
fn outer(g: Grant<Net>, h: String) {
    spawn worker(g, h)
}

@legal(basis: .public_data, purpose: "spawn row fixture")
fn main() {
    print("no network here")
}
