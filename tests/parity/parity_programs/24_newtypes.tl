// G10 — type aliases and newtypes, in one program that exercises all five
// required behaviours. Run by `tests/newtype_parity.rs` (interpreter vs
// `--require-native`) and by `tests/parity_runner.rs` (which sweeps this
// directory).
//
//   1. `UserId("x")` constructs.
//   2. No implicit conversion either way: every crossing is spelled out.
//   3. The escape hatch is `.inner` — the choice is documented in
//      TALLOW_SPEC.md and pinned by tests/newtype_parity.rs.
//   4. Two newtypes over the same target are distinct types.
//   5. Interpreted and compiled legs agree byte for byte.

// An alias is transparent: `Port` *is* `u16`.
type Port = u16

// A newtype is not: `UserId` and `String` are different types.
newtype UserId = String

// A newtype over a scalar, and a second newtype over the same target as the
// first — `UserId` and `Handle` are unrelated even though both wrap a string.
newtype Meter = Float
newtype Handle = String

fn describe(id: UserId) -> String {
    // The explicit unwrap: `.inner` yields the wrapped value.
    return "user:{id.inner}"
}

fn double(dist: Meter) -> Float {
    return dist.inner * 2.0
}

fn main() {
    // An alias crosses freely in both directions, because it is the same type.
    let port: Port = 8443
    let widened: u16 = port
    print("port {widened}")

    // A newtype is constructed, never coerced.
    let id = UserId("ada")
    print(describe(id))

    // Unwrap is explicit and repeatable: `.inner` is the wrapped value.
    print("inner {id.inner}")

    // Re-wrap is also explicit: a `String` becomes a `UserId` only through the
    // constructor.
    let again: UserId = UserId(id.inner)
    print(describe(again))

    // A handle is a different newtype over the same target. It is constructed
    // the same way and is not interchangeable with a `UserId`.
    let h = Handle("h-1")
    print("handle {h.inner}")

    // A newtype over a scalar.
    let m = Meter(1.5)
    print("meter {double(m)}")

    // A newtype value survives an ordinary binding and a call round-trip
    // without ever becoming its target.
    let copied: UserId = again
    print(describe(copied))
}
