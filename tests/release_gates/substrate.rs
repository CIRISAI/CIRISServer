//! **The substrate rungs** — the pins move together, and the vocabulary they
//! carry has not moved under us.
//!
//! These are direct gates: they read this repo's own `Cargo.toml` and call the
//! pinned crates. Nothing here needs a network, a peer, or an operator.

use ciris_persist::federation::envelope::{paths, ENVELOPE_VOCABULARY_SHA256};

use crate::ladder::{
    assert_proven, cargo_pin, tag_on_line, workspace_manifests, VOCABULARY_SINGLE_SOURCED,
};

/// The substrate floor this cut ships on. Moving a release means moving these
/// three deliberately, in one commit.
pub const TARGET_VERIFY: &str = "v13.3.1";
pub const TARGET_PERSIST: &str = "v32.1.0";
pub const TARGET_EDGE: &str = "v17.4.0";

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
/// This walks every manifest in the WORKSPACE — the root's `[dependencies]`,
/// `[dev-dependencies]` and every `[target.*]` table, plus each `[workspace]
/// members` manifest — because a partial move usually happens in the table
/// nobody re-reads.
///
/// # Why "workspace", and not just "manifest"
///
/// It read the root manifest alone until the edge v17.3.0 adoption, where the
/// root moved to v17.3.0 and `crates/ciris-lens-core` stayed on v17.0.0. The
/// lock then carried TWO `ciris-edge` stanzas — the exact condition the message
/// below describes — and this gate passed, because the second pin was in a file
/// it never opened.
///
/// That is the repo's recurring shape: one name answering two questions. The
/// gate was named for a property of the dependency GRAPH but scoped to a single
/// FILE, and the two agree right up until a workspace member disagrees. Note
/// that lens-core is the member CI compiles in a separate step for exactly this
/// family of reason (CIRISServer#373) — nothing about it is incidental.
#[test]
fn gate_substrate_pins_move_together() {
    let manifests = workspace_manifests();

    // DID IT LOOK? A scanner that silently examined only the root would pass this
    // gate for the same reason the old one did, and read identically from the
    // outside. So name what was examined and refuse a root-only scan while a
    // member is declared — the distinct-zeroes rule: "found no mismatch" and
    // "never opened the file" must not be the same result.
    let examined: Vec<&str> = manifests.iter().map(|(p, _)| p.as_str()).collect();
    let root_text = &manifests[0].1;
    let declared: Vec<String> = root_text
        .split_once("members = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(inner, _)| {
            inner
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .collect()
        })
        .unwrap_or_default();
    for m in &declared {
        let want = format!("{m}/Cargo.toml");
        assert!(
            examined.iter().any(|p| *p == want),
            "workspace member `{m}` was NEVER EXAMINED by this gate — it scanned {examined:?}. \
             An unscanned member is how a second `ciris-edge` tag reached Cargo.lock while this \
             gate stayed green."
        );
    }

    let mut split: Vec<String> = Vec::new();
    for (repo, crates) in REPOS {
        // (file, line, crate, tag) across EVERY manifest in the workspace — the
        // dependency graph is a workspace-wide fact, not a per-manifest one.
        let mut seen: Vec<(String, usize, String, String)> = Vec::new();
        for (path, toml) in &manifests {
            for (n, line) in toml.lines().enumerate() {
                for c in *crates {
                    if let Some(tag) = tag_on_line(line, c) {
                        seen.push((path.clone(), n + 1, (*c).to_string(), tag));
                    }
                }
            }
        }
        let Some((_, _, _, first)) = seen.first().cloned() else {
            split.push(format!("  {repo}: no pinned crate found at all"));
            continue;
        };
        for (path, line_no, krate, tag) in &seen {
            if *tag != first {
                split.push(format!(
                    "  {repo}: {krate} at {path}:{line_no} is {tag}, but the first {repo} pin \
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
    const ADOPTED: &str = "1213fd3cf3109df92805cb1f6b0e39ae7637812b4fba23206a7860ba381107b2";
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
