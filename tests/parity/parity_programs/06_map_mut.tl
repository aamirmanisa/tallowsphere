// 06_map_mut.tl — MAP .set() MUTATION canary.
//
// Interpreter: builds a 10-entry map via .set() in a loop, reads one key back,
// prints the real values (len=10, k3=3), rc=0.
//
// Native: the .set() lowering is a SILENT MISCOMPILE — it exits 0 (no crash,
// no error) but produces len=0 and nil. This is the worst failure mode: the
// program "succeeds" while the output is garbage, and `tallow run`'s
// interpreter fallback never fires (no signal to trigger it). This canary
// surfaces the divergence so it is a first-class parity failure, not a
// hidden back-end gap.
//
// NOT covered by 05_maps.tl (which only tests a static map literal + [] read
// + .get()). Run via: tallow build + direct binary, or the parity runner.

fn main() {
    var m = {}
    var i = 0
    while i < 10 {
        m = m.set("k" + "{i}", i)
        i = i + 1
    }
    print("len {m.len()}")
    print("k3 {m["k3"]}")
    print("MAP_MUT_OK")
}
