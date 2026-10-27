// 23_named_default_args.tl — G03: named and default arguments.
//
// Both the tree-walker and the CodeGen/native path must print EXACTLY this
// output. Three facts are pinned:
//
//  * a named argument binds to the parameter with that name, whatever its
//    position in the call;
//  * an omitted defaulted argument takes its declared default;
//  * a default is evaluated at CALL time — `announce()` prints once per call,
//    so two calls print the marker twice.

fn announce() -> i64 {
    print("(default evaluated)")
    return 7
}

fn connect(host: String, port: i64 = 443, tls: bool = true) -> String {
    var suffix = ""
    if tls == false {
        suffix = ":plain"
    }
    return "{host}:{port}{suffix}"
}

fn probe(p: i64 = announce()) -> i64 {
    return p
}

fn main() {
    // every default taken
    print(connect("example.test"))
    // named, skipping the defaulted middle parameter
    print(connect("example.test", tls: false))
    // named out of order
    print(connect(host: "example.test", port: 8443))
    // all positional
    print(connect("example.test", 8443, false))
    // call-time evaluation of a default
    print("probe1 {probe()}")
    print("probe2 {probe()}")
}
