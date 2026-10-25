//! Runs the MLS core loop and prints what actually happened, so the protocol can
//! be verified even when an unrelated `#[cfg(test)]` block in the tree does not
//! compile.
//!
//! cargo run --example mls_probe --features mls

// The example uses the feature-gated module, and `cargo check --all-targets`
// (CI's Check and Clippy jobs) compiles every example. Without the feature this
// builds a stub that says so rather than failing on an unresolved import.
#[cfg(feature = "mls")]
use tallow::mls;

#[cfg(not(feature = "mls"))]
fn main() {
    eprintln!("mls_probe needs --features mls");
    std::process::exit(1);
}

#[cfg(feature = "mls")]
fn main() {
    let (alice, _alice_kp) = mls::create_group("alice").expect("create group");
    let (bob_pending, bob_kp) = mls::key_package_new("bob").expect("bob key package");

    let (welcome, epoch_add) = mls::add_member(&alice, &bob_kp).expect("add bob");
    println!("epoch_after_add={epoch_add}");

    let (bob, bob_epoch) = mls::join_from_welcome(&bob_pending, &welcome).expect("bob joins");
    println!("bob_epoch={bob_epoch}");

    let (ct, _) = mls::encrypt(&alice, "68656c6c6f206d6c73").expect("encrypt");
    let (kind, pt, _) = mls::process(&bob, &ct).expect("decrypt");
    println!("kind={kind} plaintext={pt}");

    let (members, epoch) = mls::group_info(&bob).expect("group info");
    println!("members={members} epoch={epoch}");

    // An outsider must not read the group.
    let (mallory, _) = mls::create_group("mallory").expect("mallory");
    let outsider = mls::process(&mallory, &ct);
    println!("outsider_open={}", if outsider.is_ok() { "LEAK" } else { "refused" });
}
