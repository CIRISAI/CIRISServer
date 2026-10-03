//! **The ceremony's spares are the real ones** (FSD/FINAL_GENESIS.md).
//!
//! The final genesis commits to A2/B2/C2 — each holder's recovery key and the
//! charter's successor set — from `genesis/accord_ceremony_keys.json`, a copy
//! of CIRISVerify's committed custody trail. A copy is only as good as its
//! provenance, so this pins the HOLDERS in the same file to the roster persist
//! bakes: if A1/B1/C1 match, the file came from the real ceremony, and the
//! spares beside them did too.
//!
//! Production roster only: a test-anchor build swaps the roster for synthetic
//! holders, so this binary is compiled out there.
#![cfg(not(feature = "test-anchor"))]

use ciris_server::final_genesis::{accord_ceremony_keys, RECOVERY_PAIRING};

#[test]
fn the_files_holders_are_persists_baked_roster() {
    let keys = accord_ceremony_keys();
    assert_eq!(keys.len(), 6, "A1, B1, C1, A2, B2, C2");
    let roster = ciris_persist::federation::genesis::effective_accord_holder_records();
    assert_eq!(roster.len(), 3);
    for h in roster.iter() {
        let k = keys
            .get(&h.record.key_id)
            .unwrap_or_else(|| panic!("{} is not in the ceremony file", h.record.key_id));
        assert_eq!(
            k.pubkey_ed25519_base64, h.record.pubkey_ed25519_base64,
            "{}",
            k.key_id
        );
        assert_eq!(
            Some(&k.pubkey_ml_dsa_65_base64),
            h.record.pubkey_ml_dsa_65_base64.as_ref(),
            "{}",
            k.key_id
        );
    }
}

#[test]
fn each_holder_recovers_with_its_own_distinct_spare() {
    let keys = accord_ceremony_keys();
    let roster: Vec<String> = ciris_persist::federation::genesis::effective_accord_holder_records()
        .iter()
        .map(|h| h.record.key_id.clone())
        .collect();
    let mut spares = std::collections::BTreeSet::new();
    for (holder, spare) in RECOVERY_PAIRING {
        assert!(roster.iter().any(|r| r == holder), "{holder} is seated");
        assert!(
            !roster.iter().any(|r| r == spare),
            "{spare} is not a seated holder"
        );
        let k = keys.get(spare).expect("the spare is recorded");
        assert!(
            !k.pubkey_ml_dsa_65_base64.is_empty(),
            "{spare} has both halves"
        );
        assert!(
            spares.insert(k.pubkey_ed25519_base64.clone()),
            "{spare} is not shared"
        );
    }
}
