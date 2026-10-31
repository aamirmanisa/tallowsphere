// `.len` on a map must be the number of entries.
//
// A map's i64 payload slot sits where a length-prefixed array keeps its count,
// but the field-read path did not check for a map: it fell through to `strlen`,
// which reads the payload's low byte and answers 1 for any non-empty map. The
// method-call path already guarded for maps; the field spelling did not.
// Fixed by routing a map receiver to the count slot before the strlen path.
fn main() {
    let m = {"a": 1, "b": 2, "c": 3}
    print(m.len)

    let empty = {}
    print(empty.len)

    var grown = {"x": 1}
    grown = grown.insert("y", 2)
    print(grown.len)
}
