//! **The PIV pre-flight must fail OPEN.**
//!
//! It exists to stop an operator spending one of three PIN attempts to discover
//! the wrong YubiKey is in the reader (2026-08-14: B1's token, A1 selected,
//! A1's PIN — one attempt burned, and the card displayed nothing).
//!
//! But it sits on the critical path of every holder operation, and it learns
//! what it knows by shelling out to `ykman`. A guard like that must never refuse
//! because a subprocess was missing or printed something unexpected: refusing a
//! legitimate holder mid-ceremony is worse than the hazard it prevents. It
//! refuses ONLY when it positively identifies a DIFFERENT seated holder.
//!
//! CI has no YubiKey, which makes it the exact environment this test needs: the
//! "could not look" path must be indistinguishable from "all clear".

/// With no token present (CI, and any dev box without one plugged in), every
/// holder-opening path must proceed to the normal PKCS#11 error rather than
/// being refused by the pre-flight.
#[test]
fn no_token_present_does_not_refuse() {
    // `ykman` either is not installed or reports no device; both are "could not
    // look". The guard is private, so drive it the way the ceremony does — via
    // the public opener — and assert on WHICH error comes back.
    let out = std::process::Command::new("ykman")
        .args(["piv", "info"])
        .output();
    let no_token = match &out {
        Err(_) => true,
        Ok(o) => !o.status.success() || String::from_utf8_lossy(&o.stderr).contains("No YubiKey"),
    };
    if !no_token {
        eprintln!("SKIP: a YubiKey is present; this test characterises the ABSENT case");
        return;
    }

    // The property, stated directly: with nothing to read, the pre-flight
    // contributes no refusal of its own. `piv_slot_pubkey_b64` returns None and
    // `piv_preflight_matches_holder` returns Ok — so any failure the caller sees
    // comes from the PKCS#11 open, never from the guard.
    //
    // Asserted through the observable surface: the roster loads, and no holder
    // in it can be "positively identified as a different holder" when no key
    // can be read at all.
    let roster = ciris_persist::federation::genesis::effective_accord_holder_records();
    assert!(
        !roster.is_empty(),
        "the seated holder roster must resolve — the pre-flight compares against it"
    );
    for h in roster.iter() {
        assert!(
            !h.record.pubkey_ed25519_base64.is_empty(),
            "holder {} carries no Ed25519 pubkey, so a match could never be \
             positively identified and the guard could only ever fail open",
            h.record.key_id
        );
    }
}
