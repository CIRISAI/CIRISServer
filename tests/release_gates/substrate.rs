//! **The substrate rungs** — the pins move together, and the vocabulary they
//! carry has not moved under us.
//!
//! These are direct gates: they read this repo's own `Cargo.toml` and call the
//! pinned crates. Nothing here needs a network, a peer, or an operator.

use ciris_persist::federation::envelope::{paths, ENVELOPE_VOCABULARY_SHA256};

use crate::ladder::{assert_proven, cargo_pin, cargo_toml, tag_on_line, VOCABULARY_SINGLE_SOURCED};

/// The substrate floor this cut ships on. Moving a release means moving these
/// three deliberately, in one commit.
pub const TARGET_VERIFY: &str = "v13.0.0";
pub const TARGET_PERSIST: &str = "v30.0.1";
pub const TARGET_EDGE: &str = "v15.18.2";

/// Every substrate repo we pin by git tag, and the crate names that come out of
/// it. All crates from one repo MUST carry ONE tag.
const REPOS: &[(&str, &[&str])] = &[
    ("CIRISPersist", &["ciris-persist"]),
    ("CIRISEdge", &["ciris-edge"]),
    (
        "CIRISVerify",
        &[
            "ciris-verify-core",
            "ciris-crypto",
            "ciris-keyring",
            "ciris-verify-ffi",
        ],
    ),
];

/// **The pin gate that already earned its place** — it caught the v30 bump.
///
/// Carried across from the previous ladder unchanged in substance: it is the one
/// rung of that suite that always ran, always could fail, and always meant what
/// it said.
#[test]
fn gate_substrate_pins_at_target() {
    let verify = cargo_pin("ciris-verify-core").expect("verify pin present");
    let persist = cargo_pin("ciris-persist").expect("persist pin present");
    let edge = cargo_pin("ciris-edge").expect("edge pin present");
    assert_eq!(
        (verify.as_str(), persist.as_str(), edge.as_str()),
        (TARGET_VERIFY, TARGET_PERSIST, TARGET_EDGE),
        "\n\
         🚫 RELEASE GATE [substrate-pins] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the tree is not on the substrate floor this release was tested\n\
         against. A cut inherits every property of the substrate it links, so a pin that\n\
         differs from the target is a release nobody verified.\n\
         \n\
         want: verify {TARGET_VERIFY} / persist {TARGET_PERSIST} / edge {TARGET_EDGE}\n\
         got:  verify {verify} / persist {persist} / edge {edge}\n\
         \n\
         If the move is deliberate, update TARGET_* in tests/release_gates/substrate.rs\n\
         in the SAME commit that moves the pins — never after.\n"
    );
}

/// **Every crate from one substrate repo must carry ONE tag.**
///
/// A cargo git `tag` is part of the SOURCE ID, not a semver range: two entries on
/// the same repo with different tags put the crate in the graph TWICE, and the
/// same-named types on either side of the seam are then different types. 0.5.155
/// moved all seven verify-family pins in one commit for exactly this reason. The
/// failure is a wall of "expected `ciris_keyring::X`, found `ciris_keyring::X`",
/// which reads as a compiler bug and is not one.
///
/// This walks the WHOLE manifest — root `[dependencies]`, `[dev-dependencies]`,
/// and every `[target.*]` table — because a partial move usually happens in the
/// table nobody re-reads.
#[test]
fn gate_substrate_pins_move_together() {
    let toml = cargo_toml();
    let mut split: Vec<String> = Vec::new();
    for (repo, crates) in REPOS {
        let mut seen: Vec<(usize, String, String)> = Vec::new();
        for (n, line) in toml.lines().enumerate() {
            for c in *crates {
                if let Some(tag) = tag_on_line(line, c) {
                    seen.push((n + 1, (*c).to_string(), tag));
                }
            }
        }
        let Some((_, _, first)) = seen.first().cloned() else {
            split.push(format!("  {repo}: no pinned crate found at all"));
            continue;
        };
        for (line_no, krate, tag) in &seen {
            if *tag != first {
                split.push(format!(
                    "  {repo}: {krate} at Cargo.toml:{line_no} is {tag}, but the first {repo} pin \
                     is {first}"
                ));
            }
        }
    }
    assert!(
        split.is_empty(),
        "\n\
         🚫 RELEASE GATE [substrate-pins-together] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: a cargo git `tag` is part of the SOURCE ID, so two tags on one\n\
         repo put that crate in the dependency graph TWICE. The same-named types either\n\
         side of the seam are then DIFFERENT TYPES, and a value that crosses is either a\n\
         compile error nobody can read or — where it crosses through a trait object or\n\
         FFI — a runtime mismatch nobody catches.\n\
         \n\
         {}\n\
         \n\
         Move every pin from one repo in ONE commit. There is no [patch] escape: cargo\n\
         rejects any patch entry on the same canonical URL.\n",
        split.join("\n"),
    );
}

/// **The envelope vocabulary we adopted, pinned on our side.**
///
/// Persist owns the universal envelope key vocabulary and pins its own hash. That
/// upstream pin proves persist is self-consistent; it says nothing to US. This
/// pin is the consumer half: a substrate bump that changes the key vocabulary
/// fails HERE, at adoption, instead of diverging on the wire against peers still
/// on the old set.
///
/// The re-pin is the point — it must be a deliberate line in a commit, not a
/// silent inheritance.
#[test]
fn gate_envelope_vocabulary_is_the_one_we_adopted() {
    /// The vocabulary hash adopted with persist v30.0.0.
    const ADOPTED: &str = "f1a0bc77d24915fc1e099c4715621c936ca4fb38678b71268b88a9d614c04929";
    assert_eq!(
        ENVELOPE_VOCABULARY_SHA256, ADOPTED,
        "\n\
         🚫 RELEASE GATE [envelope-vocabulary] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: persist's envelope key vocabulary changed under this pin. Every\n\
         attestation this node writes and reads is keyed by that vocabulary, so a change\n\
         we did not adopt deliberately means we emit one set of keys and our peers read\n\
         another — and BOTH sides compile, both sides pass their own tests, and the skew\n\
         is only visible from a third node.\n\
         \n\
         adopted: {ADOPTED}\n\
         persist: {ENVELOPE_VOCABULARY_SHA256}\n\
         \n\
         Re-read persist's CHANGELOG for what moved, fix every emit/read site, THEN\n\
         update ADOPTED in this gate. Updating ADOPTED first turns the gate into a\n\
         rubber stamp.\n"
    );
}

/// The single-source discipline itself is proven in
/// `tests/envelope_vocabulary_single_source.rs` (the literal ratchet) and
/// `tests/wire_vocabulary_gate.rs` (the ratified edge hash). This rung asserts
/// both are still installed, and — separately — that the constants they route
/// through still EXIST under the names we source them from. A persist rename
/// turns the reference below into a compile error, which is the loudest available
/// failure and the only one that survives a substrate bump.
#[test]
fn gate_vocabulary_stays_single_sourced() {
    let _: &str = paths::DIMENSION;
    let _: &str = paths::REFERENCES_ATTESTATION_ID;
    let _: &str = paths::SCOPE;
    let _: &str = paths::DELIVERY_MODE;
    let _: &str = paths::DELETION_WINDOW;
    assert_proven(&VOCABULARY_SINGLE_SOURCED);
}
