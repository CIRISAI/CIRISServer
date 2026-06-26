//! STH consistency-proof conformance (CEG §10.3.1 — compliance D17 transparency_log).
//!
//! This is the Rust lane of the CIRIS conformance two-lane model: the feature
//! runs Rust-to-Rust across the pinned substrate crates and is NOT on the Python
//! wheel surface, so it is gated here (in CIRISServer, against the pinned triple)
//! rather than by bolting an artificial PyO3 surface onto the Python harness.
//!
//! The load-bearing cross-artifact property: **`ciris-persist` builds an RFC 6962
//! §2.1.2 signed-tree-head consistency proof, and the independently-published
//! `ciris-verify-core` verifies it** — the two crates agree on the transparency-log
//! math, so an append-only stream can prove "no retroactive insertion" to a
//! consumer that only trusts verify-core. Mirrors CIRISConformance's discipline:
//! drive the real published crates, assert behaviour, and prove the negative
//! (a forged root / tampered proof must fail closed).

use ciris_persist::federation::stream_sth::{consistency_proof, StreamChunkLeaf};
use ciris_verify_core::transparency::{
    verify_consistency, InMemoryTransparencyStore, TransparencyStore,
};
use sha2::{Digest, Sha256};

/// A deterministic 32-byte leaf "chunk sha".
fn leaf(seed: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([seed]);
    h.finalize().into()
}

/// The Merkle root of the first `n` leaves, computed via verify-core's store with
/// persist's `StreamChunkLeaf` — the SAME leaf `consistency_proof` uses internally,
/// so the roots line up with the proof.
fn root_of(hashes: &[[u8; 32]]) -> [u8; 32] {
    let store: InMemoryTransparencyStore<StreamChunkLeaf> = InMemoryTransparencyStore::new(None);
    for h in hashes {
        store.append(StreamChunkLeaf::new(*h)).expect("append leaf");
    }
    store.root().expect("merkle root")
}

#[test]
fn persist_builds_sth_consistency_proof_that_verify_core_accepts() {
    let hashes = [leaf(1), leaf(2), leaf(3), leaf(4), leaf(5), leaf(6)];
    let old_root = root_of(&hashes[..3]);
    let new_root = root_of(&hashes[..6]);

    // persist (pinned ciris-persist) builds the RFC 6962 consistency proof.
    let proof = consistency_proof(&hashes, 3, 6)
        .expect("consistency_proof ok")
        .expect("stream holds >= to_size chunks");
    assert_eq!(proof.old_tree_size, 3);
    assert_eq!(proof.new_tree_size, 6);

    // verify-core (independently published) confirms the new tree is a legal,
    // append-only extension of the old — D17's "no retroactive modification".
    assert!(
        verify_consistency(&old_root, 3, &new_root, 6, &proof).expect("verify ok"),
        "verify-core rejected a valid persist-built consistency proof — the two \
         crates disagree on RFC 6962 §2.1.2"
    );
}

#[test]
fn forged_root_fails_consistency_closed() {
    let hashes = [leaf(1), leaf(2), leaf(3), leaf(4)];
    let old_root = root_of(&hashes[..2]);
    let new_root = root_of(&hashes[..4]);
    let proof = consistency_proof(&hashes, 2, 4).unwrap().unwrap();

    // A new_root that doesn't match the proof must NOT verify (a retroactive
    // edit would surface here).
    let mut forged = new_root;
    forged[0] ^= 0xff;
    assert!(
        !verify_consistency(&old_root, 2, &forged, 4, &proof).expect("verify ok"),
        "a forged new_root verified — the consistency check is not fail-closed"
    );

    // A tampered proof node must NOT verify either.
    let mut tampered = proof.clone();
    if let Some(node) = tampered.proof_hashes.get_mut(0) {
        node[0] ^= 0xff;
    }
    assert!(
        !verify_consistency(&old_root, 2, &new_root, 4, &tampered).expect("verify ok"),
        "a tampered consistency proof verified — fail-closed property broken"
    );
}
