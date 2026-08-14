//! **A ceremony must not spend a holder key on a build that cannot sign validly.**
//!
//! `authorization_digest` returned the canonical preimage until persist
//! v31.2.0. A build linked to an older persist signs bytes no current verifier
//! recomputes, so every authorization it takes is dead — and the ceremony looks
//! like it worked right up until someone tries to bake the seed.
//!
//! On 2026-08-14 that question ("which persist produced this seed?") was asked
//! only AFTER two YubiKeys had been touched, and answering it took a diagnosis
//! on both sides of the substrate. The distinguishing fact was a length.
//!
//! This pins the property the ceremony's step-zero guard depends on. It is
//! deliberately the plainest possible assertion: if this fails, no ceremony this
//! build runs can produce a usable seed.

#[test]
fn the_authorization_digest_is_a_signable_32_byte_hash() {
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let d = ciris_server::mesh_genesis::authorization_digest(baked).expect("digest");

    assert_eq!(
        d.len(),
        32,
        "authorization_digest returned {} bytes, not 32.\n\
         \n\
         32 bytes is SHA-256 — the form every hardware token can sign. Anything \
         larger is the canonical PREIMAGE, which is what persist returned before \
         v31.2.0 and what made a YubiKey C_Sign refuse outright (\"plaintext \
         input data has a bad length\") once the preimage widened to 83,060 \
         bytes.\n\
         \n\
         If this build links an older persist, every signature a ceremony takes \
         is over bytes a current verifier will not recompute, and the seed is \
         unusable. Check the persist pin before running a ceremony.",
        d.len()
    );
}
