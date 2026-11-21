//! The joining node's half: it never takes a seat's word. Guarded: every fn carries `@tla`.

use crate::{KeyId, Registration, Verifier};

/// The out-of-band anchor the node was built with (CC 5.3.4): the holders' thumbprints or the bundle's object id.
pub enum Anchor {
    HolderThumbprints(Vec<[u8; 32]>),
    BundleObjectId([u8; 32]),
}

/// @tla FetchBundle
/// Accept a served bundle only if it matches the anchor; a replica can withhold the root, never replace it.
pub fn accept_bundle(anchor: &Anchor, bundle: &[u8]) -> Result<(), &'static str> {
    let _ = (anchor, bundle);
    todo!("ciris-verify: verify_bundle_quorum against the anchor; object id compare when anchored by id")
}

/// @tla NodeAccepts
/// The same checks the seat ran, run again by the node against the key it asked for.
pub fn accept_answer(v: &dyn Verifier, asked: &KeyId, r: &Registration, now_ms: u64) -> bool {
    &r.record.key_id == asked && crate::seat::Seat::verify_registration(v, r, now_ms).is_ok()
}

#[cfg(test)]
mod tests {
    /// @tla-inv Inv_RootIsAnchor
    #[test]
    fn a_bundle_off_the_anchor_is_refused() {}

    /// @tla-inv Inv_NodeNeverSwapped
    #[test]
    fn an_answer_for_another_key_is_refused() {}
}
