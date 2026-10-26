// The library half of N-9: it holds the only `main`, and its span must be
// rendered against THIS file, not against the entry file that imports it.
fn main() { // LIB_ONLY_MARKER_n9
    print("library main, never an entry point")
}
