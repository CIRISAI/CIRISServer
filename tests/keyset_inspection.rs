//! Exercise the inspect verdict against real folder shapes.
use std::fs;
#[tokio::test]
async fn keyset_inspection_distinguishes_the_cases() {
    let base = std::env::temp_dir().join(format!("ciris-inspect-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    // (a) empty
    let empty = base.join("empty");
    fs::create_dir_all(&empty).unwrap();
    // (b) complete keyset
    let full = base.join("full");
    fs::create_dir_all(&full).unwrap();
    fs::write(full.join("alice-v1.ed25519.seed"), [7u8; 32]).unwrap();
    fs::write(full.join("alice-v1.mldsa65.seed"), [8u8; 32]).unwrap();
    fs::write(full.join("alice-v1.backend"), b"software").unwrap();
    // (c) HALF keyset — the classical seed copied, the PQC half left behind
    let half = base.join("half");
    fs::create_dir_all(&half).unwrap();
    fs::write(half.join("alice-v1.ed25519.seed"), [7u8; 32]).unwrap();
    // (d) two keysets — ambiguous
    let two = base.join("two");
    fs::create_dir_all(&two).unwrap();
    fs::write(two.join("alice-v1.ed25519.seed"), [7u8; 32]).unwrap();
    fs::write(two.join("bob-v1.ed25519.seed"), [9u8; 32]).unwrap();

    for (label, dir) in [
        ("empty", &empty),
        ("full", &full),
        ("half", &half),
        ("two", &two),
    ] {
        let alias = ciris_server::identity::find_portable_alias(dir);
        println!(
            "{label:>6}: {:?}",
            alias
                .as_ref()
                .map(|a| a.as_str())
                .map_err(|e| e.to_string())
        );
    }
    let _ = fs::remove_dir_all(&base);
}
