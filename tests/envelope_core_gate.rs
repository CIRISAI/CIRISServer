//! Every envelope this node authors goes through `attest::envelope_core`, which
//! drops null members persist would refuse (CC 2.6.1.1.1). A site typing an
//! envelope directly brings the failure back for whichever optional field it
//! writes, and only when that field is empty.
//!
//! The exceptions carry bytes somebody else signed, which must not be touched.

use std::path::Path;

/// `path` may call `EnvelopeCore::from_value` itself.
const SIGNED_BYTES: &[(&str, &str)] = &[
    (
        "src/attest.rs",
        "the door itself, and re-opening signed rows",
    ),
    ("src/accord.rs", "the founders' signed genesis body"),
    ("src/auth/attestation.rs", "an envelope the caller signed"),
    (
        "src/mesh_config_surface.rs",
        "reads back rows already typed",
    ),
    (
        "src/registry/builds.rs",
        "a pipeline's signed Contribution and grant, re-opened to check and store",
    ),
];

fn scan(dir: &Path, found: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).expect("read src").flatten() {
        let p = e.path();
        if p.is_dir() {
            scan(&p, found);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let src = std::fs::read_to_string(&p).expect("read source");
            if src.contains("EnvelopeCore::from_value(") {
                found.push(p.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

#[test]
fn only_signed_bytes_skip_the_envelope_door() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    scan(&root.join("src"), &mut found);
    let prefix = format!("{}/", root.to_string_lossy().replace('\\', "/"));
    let strays: Vec<&str> = found
        .iter()
        .map(|p| p.strip_prefix(&prefix).unwrap_or(p))
        .filter(|p| !SIGNED_BYTES.iter().any(|(ok, _)| ok == p))
        .collect();
    assert!(
        strays.is_empty(),
        "these type an envelope without `attest::envelope_core`: {strays:?}"
    );
    assert!(
        found.len() >= 2,
        "the scan found almost nothing, so this gate proves nothing: {found:?}"
    );
}
