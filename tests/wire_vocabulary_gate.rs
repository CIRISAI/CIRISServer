//! Cohabitation wire-vocabulary drift gate (CIRISServer#128 / CIRISEdge#241).
//!
//! CC 0.7 froze the edge wire vocabulary (`WIRE_VOCABULARY.md` v1.0.1) and edge
//! exports its sha256 as [`ciris_edge::WIRE_VOCABULARY_HASH`]. This test pins the
//! ratified value on OUR side, so a future edge bump that silently changes the
//! Tier-1 vocabulary (a wire break requiring the CC §4.5.1 amendment path) fails
//! CIRISServer's build instead of drifting apart on the mesh. This is CIRISServer's
//! half of the cohabitation gate the edge conformance suite pins upstream.

/// The ratified v1.0.1 vocabulary hash (`WIRE_VOCABULARY.md` §front-matter).
const RATIFIED_HASH_HEX: &str = "c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c";

#[test]
fn edge_wire_vocabulary_matches_ratified_v1_0_1() {
    let expected: Vec<u8> = (0..RATIFIED_HASH_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&RATIFIED_HASH_HEX[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(
        ciris_edge::WIRE_VOCABULARY_HASH.as_slice(),
        expected.as_slice(),
        "edge wire vocabulary drifted from ratified WIRE_VOCABULARY.md v1.0.1 — a \
         wire break: reconcile the CC §4.5.1 amendment + our opaque-kind allocations \
         (CIRISServer#128) before bumping the edge pin",
    );
}
