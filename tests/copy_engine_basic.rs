use std::fs;

use tallow::interp::Value;
use tallow::stdlib;

fn field_int(value: &Value, name: &str) -> i128 {
    let Value::Struct { fields, .. } = value else {
        panic!("expected struct, got {value:?}");
    };
    fields
        .iter()
        .find_map(|(key, value)| {
            if key == name {
                if let Value::Int(number) = value {
                    Some(*number)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing integer field {name}"))
}

#[test]
fn transfer_fast_copy_routes_through_copy_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source.txt");
    let destination = tmp.path().join("destination.txt");
    fs::write(&source, b"hello from copy engine").unwrap();

    let result = stdlib::dispatch(
        "transfer",
        "fast_copy",
        vec![
            Value::String(source.to_string_lossy().to_string()),
            Value::String(destination.to_string_lossy().to_string()),
        ],
    )
    .expect("transfer.fast_copy should route")
    .expect("transfer.fast_copy should succeed");

    assert_eq!(fs::read(&destination).unwrap(), b"hello from copy engine");
    assert_eq!(field_int(&result, "bytes_copied"), 22);
}

#[test]
fn transfer_fast_copy_dir_routes_through_copy_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let nested = source.join("nested");
    let destination = tmp.path().join("destination");
    fs::create_dir_all(&nested).unwrap();
    fs::write(source.join("a.txt"), b"a").unwrap();
    fs::write(nested.join("b.txt"), b"bb").unwrap();

    let result = stdlib::dispatch(
        "transfer",
        "fast_copy_dir",
        vec![
            Value::String(source.to_string_lossy().to_string()),
            Value::String(destination.to_string_lossy().to_string()),
        ],
    )
    .expect("transfer.fast_copy_dir should route")
    .expect("transfer.fast_copy_dir should succeed");

    assert_eq!(fs::read(destination.join("a.txt")).unwrap(), b"a");
    assert_eq!(
        fs::read(destination.join("nested").join("b.txt")).unwrap(),
        b"bb"
    );
    assert_eq!(field_int(&result, "files_copied"), 2);
    assert_eq!(field_int(&result, "bytes_copied"), 3);
}
