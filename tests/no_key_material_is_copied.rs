//! **No path copies an identity's private key onto another device**
//! (CIRISServer#391).
//!
//! # The defect
//!
//! `POST /v1/self/associate` used to COPY the Ed25519 seed off a USB onto this
//! device and re-seal the ML-DSA half locally, so the identity's private half
//! then existed in two places. It was written as a last-resort recovery path and
//! its own comment said the correct move was to mint a fresh key and bind it as
//! an occurrence — but nothing enforced that, and the first-run wizard's "import
//! my existing fed-ID" button called it. The ordinary new-device flow was the
//! key-duplicating one.
//!
//! # Why duplication is the thing to forbid, specifically
//!
//! A self is a roster of `identity_occurrence` rows over one root identity, and
//! `signer_acts_for` treats any ACTIVE occurrence as a full stand-in — so a fresh
//! per-device key gives up NOTHING in privilege. What it buys is that
//! `/v1/self/occurrence/revoke` means something: revoking a shared key kills
//! every device that holds it, and there is no way to tell those devices apart
//! afterwards because they are, cryptographically, the same device.
//!
//! # What this gate is, and is not
//!
//! It is a grep, and a grep cannot prove the absence of a copy. What it does is
//! fail loudly on the two shapes that already shipped — a named installer, and a
//! write of a seed file into the node's own directory from a source directory —
//! so a reintroduction is caught here rather than by an operator noticing their
//! key is in two places, which is a thing nobody notices.

use std::path::Path;

fn src(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
        .replace("\r\n", "\n")
}

fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The installer is gone, by name.
#[test]
fn the_keyset_installer_does_not_exist() {
    for rel in ["src/identity.rs", "src/auth/portable_occurrence.rs"] {
        let code = code_only(&src(rel));
        assert!(
            !code.contains("install_portable_software_keyset"),
            "{rel} still references `install_portable_software_keyset`. That function COPIED an \
             identity's private Ed25519 seed onto this device, making one key exist in two \
             places and rendering per-device revocation meaningless. Enrol the device instead: \
             mint a fresh key here and let the existing keyset AUTHORIZE the binding \
             (CIRISServer#391)."
        );
        assert!(
            !code.contains("reseal_portable_mldsa"),
            "{rel} still references `reseal_portable_mldsa` — it existed only to seal a COPIED \
             post-quantum half into this device's keystore."
        );
    }
}

/// The authorizing keyset is opened TRANSIENTLY and wiped.
#[test]
fn the_authorizer_is_read_into_memory_and_zeroized() {
    let code = code_only(&src("src/identity.rs"));
    let i = code
        .find("pub fn open_portable_identity_transiently")
        .expect("the transient authorizer open");
    let body = &code[i..code[i..].find("\n}\n").map(|j| i + j).unwrap_or(code.len())];
    assert!(
        body.contains("zeroize()"),
        "the transient open must WIPE the seeds it read. They are another device's private key \
         material, held only long enough to prove possession:\n{body}"
    );
    assert!(
        !body.contains("std::fs::write") && !body.contains("write_seed_0600"),
        "the transient open WRITES. It exists precisely so the authorizing keyset is never \
         persisted on this device:\n{body}"
    );
}

/// The enrol path binds an occurrence rather than replacing the local identity.
#[test]
fn associate_enrols_an_occurrence() {
    let code = code_only(&src("src/auth/portable_occurrence.rs"));
    let i = code
        .find("async fn associate_handler")
        .expect("the associate handler");
    let body = &code[i..];
    let end = body.find("\npub fn router").unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        body.contains("bind_occurrence_core"),
        "associate must BIND the device as an occurrence — that is what gives it the identity's \
         privileges without holding the identity's key:\n{body}"
    );
    assert!(
        body.contains("mint_portable_software_occurrence"),
        "associate must MINT a fresh key for this device. Reusing the supplied one is the \
         duplication this path was rewritten to stop."
    );
    assert!(
        body.contains("open_portable_identity_transiently"),
        "associate must open the supplied keyset TRANSIENTLY to authorize with — possession of \
         the identity key IS the authorization, and it must not be persisted."
    );
}
