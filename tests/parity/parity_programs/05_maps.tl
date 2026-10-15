// 05_maps.tl — deterministic map probe.
// Exercises associative maps: literal construction, bracket-index access,
// and .get(key) access. NOTE: map support differs between the tree-walker
// and CodeGen/native, so this program is a TARGETED divergence probe — it is
// expected to reveal gaps first (see README "How the parity runner works").
// Deterministic, no random/time/network.

fn main() {
    let user = { "name": "Ada", "age": 36, "active": true }

    print("name {user["name"]}")
    print("age {user["age"]}")
    print("active {user["active"]}")

    let via_get = user.get("name")
    print("got {via_get}")

    let missing = user.get("not_a_key")
    print("missing {missing}")

    print("size {user.len()}")
}
