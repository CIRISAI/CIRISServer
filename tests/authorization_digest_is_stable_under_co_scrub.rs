//! **A holder authorization must survive the co-scrub that follows it.**
//!
//! The seed ceremony accumulates TWO things over the same bundle, in one linear
//! pass per holder:
//!
//!   1. `bundle.authorizations` — the m-of-n proof. Each holder signs
//!      `authorization_digest(bundle)`.
//!   2. the serve node's SCRUB SET — each holder appends its scrub so the
//!      canonical reaches family quorum and persist will accept it as
//!      serve-capable.
//!
//! CIRISPersist v31.2.0 widened the digest preimage from `key_id` alone to the
//! whole `KeyRecord` minus two node-local fields (CIRISServer#398 §5), to stop
//! record substitution under an unchanged id. That is right, and it swept in
//! `scrub_key_id` / `scrub_signature_*` / `additional_scrubs` — the one part of
//! the record the ceremony is *designed* to mutate after a holder has signed.
//!
//! So the two accumulations became circular: B1's co-scrub of the serve node
//! changes the bytes A1 already authorized, and A1's signature — a perfectly
//! honest signature over the bundle it was shown — stops verifying. The ceremony
//! reports `have=2 needed=2 complete=false` and asks for a third holder that
//! cannot help, because the failure is not a quorum shortfall.
//!
//! This is the shape of CIRISPersist#541: an unsigned refresh rewriting
//! envelope-covered columns. Same class, different plane — a signature covering
//! a field that legitimately changes after signing.
//!
//! This test needs no keys and no ceremony: it asks only whether the digest
//! MOVES when the scrub set advances. If it does, every authorization taken
//! before the advance is dead, and no amount of additional holders fixes it.

use ciris_server::mesh_genesis::{authorization_digest, GenesisBundle};

/// The fixture: persist's own BAKED canonical bundle by default, so this runs
/// hermetically on any machine and in CI. It carries the shape under test — a
/// serve node with a primary scrub plus at least one additional one — because
/// persist's baked seed is itself the output of a two-holder ceremony.
///
/// `CIRIS_GENESIS_BUNDLE` overrides it with a freshly minted seed, which is how
/// this was first run against the 2026-08-14 bundle.
fn bundle() -> GenesisBundle {
    match std::env::var("CIRIS_GENESIS_BUNDLE")
        .ok()
        .filter(|p| !p.trim().is_empty())
    {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("CIRIS_GENESIS_BUNDLE={path}: {e}"));
            serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{path} is not a GenesisBundle: {e}"))
        }
        None => ciris_persist::federation::genesis::canonical_genesis_bundle().clone(),
    }
}

#[test]
fn a_late_co_scrub_does_not_move_the_authorization_digest() {
    let mut b = bundle();
    assert!(
        !b.serve_nodes.is_empty(),
        "fixture must carry a serve node — that is the record the ceremony co-scrubs"
    );

    // The digest as every holder that signed AFTER the co-scrub saw it.
    let after = authorization_digest(&b).expect("digest of the co-scrubbed bundle");

    // Rewind exactly what `cosign_genesis_impl` appends after `authorize_bundle`
    // has already taken the holder's signature: the additional scrubs on the
    // serve node. Nothing else is touched — same records, same roles, same
    // pubkeys, same attestations, same charter.
    let rewound: Vec<_> = b.serve_nodes[0]
        .record
        .additional_scrubs
        .drain(..)
        .collect();
    assert!(
        !rewound.is_empty(),
        "fixture must carry a serve node whose scrub set ADVANCED during the \
         ceremony — that is the mutation under test"
    );
    let before = authorization_digest(&b).expect("digest of the pre-co-scrub bundle");

    assert_eq!(
        hex(&before),
        hex(&after),
        "\nTHE CO-SCRUB MOVED THE AUTHORIZATION DIGEST.\n\
         \n\
         A holder that signed the bundle before the {} late scrub(s) landed on \
         serve node `{}` signed different bytes than a verifier now recomputes. \
         Its authorization is unverifiable — not because the holder did anything \
         wrong, but because the ceremony rewrote a field the signature covers.\n\
         \n\
         The ceremony then reports `complete=false` with have == needed, and the \
         card asks for another holder. Another holder cannot help: every new \
         signature is taken over bytes the NEXT co-scrub will move again.\n\
         \n\
         Fix belongs in the preimage: the scrub set is accumulating quorum \
         evidence over the record's own canonical bytes (already bound via \
         original_content_hash), not producer-authored content. It must be \
         excluded from `authorization_digest`, exactly as `persist_row_hash` and \
         `pqc_completed_at` already are.\n",
        rewound.len(),
        b.serve_nodes[0].record.key_id,
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
