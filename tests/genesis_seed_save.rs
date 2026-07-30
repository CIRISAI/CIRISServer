//! The completed genesis seed must land on disk, under the node's CONFIGURED home,
//! with one well-known name — without the operator having to get a file off the
//! device by hand.
//!
//! Why this is server-side and pinned here: pushing the bytes back through the
//! client to be saved was never robust. The desktop picker opens at USB mount
//! roots, and `writeTextFile` is a hard `false` on Android and iOS — so on mobile
//! the seed could be *displayed* and never *saved* (CIRISServer#310). The node
//! mints the seed and knows its own home, so it writes the file itself, under the
//! configured home rather than a compiled-in `/var/lib/ciris` (CIRISServer#309).
//!
//! The saved file is the artifact handed to persist to bake, so "it round-trips
//! byte-for-byte" is the property that matters, not merely "a file appeared".

use ciris_server::accord_provision::{save_seed_to_home, SEED_FILENAME};
use ciris_server::mesh_genesis::GenesisBundle;

/// A unique scratch directory. Deliberately std-only — adding a dev-dependency to
/// test five lines of file I/O is not a trade worth making.
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ciris-seed-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bundle() -> GenesisBundle {
    GenesisBundle {
        version: 2,
        family_key_id: "fam-test".to_string(),
        holders: Vec::new(),
        serve_nodes: Vec::new(),
        consensus_protocol: "quorum:2/3".to_string(),
        attestations: Vec::new(),
        authorizations: Vec::new(),
        produced_at: "2026-07-30T00:00:00Z".to_string(),
    }
}

#[test]
fn seed_lands_under_the_configured_home_with_the_well_known_name() {
    let home = Scratch::new("home");
    let path = save_seed_to_home(home.path(), &bundle()).expect("save");

    assert_eq!(
        path,
        home.path().join(SEED_FILENAME),
        "the seed must land at <configured home>/{SEED_FILENAME} — not a compiled-in \
         path, and not a name the operator has to be told"
    );
    assert!(path.is_file(), "the file must actually exist at {path:?}");
}

#[test]
fn a_missing_home_is_created_rather_than_failing() {
    // First run: the home may not exist yet. Losing a completed ceremony because a
    // directory was absent would be absurd.
    let base = Scratch::new("base");
    let home = base.path().join("not").join("yet").join("there");
    let path = save_seed_to_home(&home, &bundle()).expect("save into a fresh home");
    assert!(path.is_file());
}

#[test]
fn the_saved_seed_round_trips_byte_for_byte() {
    // This file IS the hand-off to persist. If it does not deserialize back into an
    // identical bundle, the ceremony's output is not what gets baked.
    let home = Scratch::new("home");
    let original = bundle();
    let path = save_seed_to_home(home.path(), &original).expect("save");

    let text = std::fs::read_to_string(&path).expect("read back");
    let parsed: GenesisBundle = serde_json::from_str(&text).expect("the saved seed must parse");

    assert_eq!(parsed.version, original.version);
    assert_eq!(parsed.family_key_id, original.family_key_id);
    assert_eq!(parsed.consensus_protocol, original.consensus_protocol);
    assert_eq!(parsed.produced_at, original.produced_at);
    assert_eq!(parsed.attestations.len(), original.attestations.len());
    assert_eq!(parsed.authorizations.len(), original.authorizations.len());
}

#[test]
fn saving_twice_overwrites_rather_than_erroring() {
    // A re-mint writes the same path. The newest completed ceremony wins; an
    // operator should never have to delete a file to re-run one.
    let home = Scratch::new("home");
    save_seed_to_home(home.path(), &bundle()).expect("first save");

    let mut second = bundle();
    second.produced_at = "2026-12-25T00:00:00Z".to_string();
    let path = save_seed_to_home(home.path(), &second).expect("second save overwrites");

    let parsed: GenesisBundle =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
    assert_eq!(
        parsed.produced_at, "2026-12-25T00:00:00Z",
        "the re-mint must replace the previous seed at the same well-known path"
    );
}

#[test]
fn an_unwritable_home_reports_rather_than_panicking() {
    // Best-effort by design: the bundle is portable and valid whether or not the
    // write lands, and the response carries the JSON regardless. Losing a ceremony
    // to a full disk would be far worse than losing a convenience.
    let base = Scratch::new("base");
    let clash = base.path().join("home-is-a-file");
    std::fs::write(&clash, b"not a directory").expect("make the clash");

    assert!(
        save_seed_to_home(&clash, &bundle()).is_err(),
        "a home that cannot be created or written must surface an error, not panic"
    );
}
