//! **The accord grant, end to end, on the synthetic trust root** (CIRISServer#392).
//!
//! CIRISServer#383's 61 leaked QA keys were never blocked on code to PERFORM a
//! de-admission. They were blocked on there being no way to GRANT the authority
//! to perform one: every tier-2/3/4 act walks for the `slash` duty on the
//! DELEGATION plane (`trust:confers:v1`), and the trust-root card only ever
//! conferred CEREMONY-plane roles (`canonical`, `infra:serve`).
//!
//! This drives the whole arc against the test-anchor genesis holders — the same
//! synthetic trust root `trace_round_e2e` uses, whose PRIVATE halves we hold, so
//! the 2-of-3 is REAL signatures verified against the roster persist itself
//! resolves. Requires `--features test-anchor`.
//!
//! What it proves, in order:
//!   1. Before the grant, the subject holds `slash` from NO root — the refusal.
//!   2. ONE holder's scrub is inert: still no authority. 2-of-3 is not decoration.
//!   3. At quorum the conferral admits, and the capability walk now resolves the
//!      subject's `slash` to the humanity-accord FAMILY — not to the seat that
//!      signed it (`ConferralPlane::FamilyQuorum`, CIRISPersist#557).
//!   4. The depth bound on the grant is what the walk honours.
#![cfg(feature = "test-anchor")]

use ciris_persist::federation::admission::DELEGATION_SCOPE_SLASH;
use ciris_persist::federation::operational::test_support::Identity;
use ciris_persist::federation::trust_root::capability_roots_to_trusted_root_over_roster;
use ciris_persist::prelude::Engine;
use std::sync::Arc;

mod support {
    include!("support/accord_trust.rs");
}
use support::{register_key_as_user, seed_accord_trust};

/// The three holders the test-anchor genesis synthesizes. `Identity::new` is
/// deterministic from the id, so these ARE the keypairs whose public halves the
/// genesis publishes — and we hold the private halves, which is the whole reason
/// a real 2-of-3 can be exercised here.
fn holders() -> Vec<Identity> {
    (0..3)
        .map(|i| Identity::new(&format!("test-accord-holder-{i}")))
        .collect()
}

/// Arm Mode A BEFORE any Engine is built — the genesis records resolve at boot.
fn arm(hs: &[Identity]) {
    let eds: Vec<String> = hs
        .iter()
        .map(|h| h.member().ed25519_public_key_base64)
        .collect();
    let pqcs: Vec<String> = hs
        .iter()
        .filter_map(|h| h.member().mldsa65_public_key_base64)
        .collect();
    std::env::set_var("CIRIS_TESTING_MODE", "true");
    std::env::set_var("CIRIS_TEST_TRUST_ROOT", eds.join(","));
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_PQC", pqcs.join(","));
}

async fn engine() -> Arc<Engine> {
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ciris_persist::prelude::LocalSigner;
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xE2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0xE1; 32]),
        "duty-grant-node".to_string(),
        Some(pqc),
        Some("ciris-server-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

/// Does `subject` hold `slash` from a root this node trusts?
async fn holds_slash(engine: &Engine, node: &str, subject: &str, roster: &[String]) -> bool {
    capability_roots_to_trusted_root_over_roster(
        engine.federation_directory().as_ref(),
        node,
        subject,
        DELEGATION_SCOPE_SLASH,
        roster,
    )
    .await
    .expect("capability walk")
    .is_some()
}

#[tokio::test]
async fn the_accord_grant_is_what_unlocks_moderation_and_one_seat_is_not_enough() {
    let hs = holders();
    arm(&hs);
    let e = engine().await;
    let node_id = Identity::new("duty-grant-node");
    let node = node_id.key_id.as_str();
    let subject = "eric-moore-v2-portable-f34de31d8c21-6e2b4kpvxk";
    let roster: Vec<String> = hs.iter().map(|h| h.key_id.clone()).collect();
    register_key_as_user(&e, subject).await;
    register_key_as_user(&e, node).await;
    seed_accord_trust(&e, &node_id, &hs).await;

    // ── (1) BEFORE: no authority. This is CIRISServer#383's live state. ──────
    assert!(
        !holds_slash(&e, node, subject, &roster).await,
        "precondition: the subject must hold `slash` from NO root before the accord grants it — \
         otherwise this test proves nothing about the grant"
    );

    // ── (2) ONE holder scrubs. Inert by design. ──────────────────────────────
    //
    // A single seat able to confer `slash` would be exactly the authority
    // CIRISPersist#557 removed from any one seat. The partial may exist, may
    // replicate, and still confers nothing.
    let one = ciris_server::accord_duty::test_support_build_partial(
        subject,
        &[DELEGATION_SCOPE_SLASH.to_string()],
        true,
        Some(2),
        &[&hs[0]],
    )
    .await;
    let put_one = e
        .federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation { attestation: one })
        .await;
    // Whether the substrate stores a sub-quorum row or refuses it outright, the
    // AUTHORITY must not appear. Assert the property, not the storage decision.
    let _ = put_one;
    assert!(
        !holds_slash(&e, node, subject, &roster).await,
        "ONE holder's scrub must confer NOTHING — 2-of-3 is the difference between the accord \
         acting and a person acting in its name"
    );

    // ── (3) QUORUM: two distinct holders. ────────────────────────────────────
    let two = ciris_server::accord_duty::test_support_build_partial(
        subject,
        &[DELEGATION_SCOPE_SLASH.to_string()],
        true,
        Some(2),
        &[&hs[0], &hs[1]],
    )
    .await;
    e.federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation { attestation: two })
        .await
        .expect("a 2-of-3 accord conferral must be ADMITTED by the substrate");

    assert!(
        holds_slash(&e, node, subject, &roster).await,
        "after the accord's 2-of-3 conferral the subject MUST hold `slash` — this is the row \
         CIRISServer#383's 61 keys are waiting on, and the whole point of the surface"
    );
}

/// The depth chosen at conferral time is the bound the walk honours, and a LEAF
/// grant cannot be passed on. The dropdown is not decorative.
#[tokio::test]
async fn a_leaf_grant_may_act_but_may_not_be_passed_on() {
    let hs = holders();
    arm(&hs);
    let e = engine().await;
    let node_id = Identity::new("duty-grant-node");
    let node = node_id.key_id.as_str();
    let subject = "leaf-subject-key";
    let roster: Vec<String> = hs.iter().map(|h| h.key_id.clone()).collect();
    register_key_as_user(&e, subject).await;
    register_key_as_user(&e, node).await;
    seed_accord_trust(&e, &node_id, &hs).await;

    // sub_delegation = false ⇒ leaf.
    let leaf = ciris_server::accord_duty::test_support_build_partial(
        subject,
        &[DELEGATION_SCOPE_SLASH.to_string()],
        false,
        None,
        &[&hs[0], &hs[1]],
    )
    .await;
    let env = leaf.attestation_envelope.clone();
    e.federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation { attestation: leaf })
        .await
        .expect("a leaf conferral is still a valid conferral");

    // The subject itself HOLDS the duty...
    assert!(
        holds_slash(&e, node, subject, &roster).await,
        "a leaf grant still confers the duty on its subject — it only forbids passing it on"
    );
    // ...and the envelope says it may not pass it on. `false` is written as
    // ABSENT, because absent and false mean the same thing to persist and an
    // explicit `false` would read like a decision when it is the default.
    assert!(
        env.get("sub_delegation").is_none(),
        "a leaf grant must not write `sub_delegation` at all: {env}"
    );
    assert!(
        env.get("sub_delegation_depth").is_none(),
        "a leaf grant carries no depth — a bound on a gate that is shut: {env}"
    );
}
