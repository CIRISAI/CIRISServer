//! **The whole arc, on the synthetic trust root** — sign in, claim, confer,
//! moderate (CIRISServer#393/#395/#396/#397).
//!
//! Every step below was a live defect during the 0.5.168 bring-up, and each was
//! found only by driving the real desktop app and reading a log. They are pinned
//! together here because they were never independent: each fix moved the failure
//! one step later, and three of them were a PREVIOUS fix's premise going stale.
//!
//! The order is the order a human experiences:
//!
//!  1. **Google sign-in does not claim the node.** It creates an account; the
//!     node stays claimable. (A ROOT named after the auth pair closed first-run
//!     and 409'd the wizard's own claim.)
//!  2. **The claim names the owner after the PERSON**, `wa-root-<fed-id>` —
//!     which is what canonical-server-1 has in production — and carries the
//!     sign-in pair onto it.
//!  3. **The duplicate holder is retired**, so one provider identity resolves to
//!     one cert.
//!  4. **A retired cert stops answering**, and the pair resolves to the OWNER —
//!     not to nothing, which would let the deterministic wa_id re-create the
//!     retired row on the next sign-in and undo the retirement.
//!  5. **A claimed personal node refuses an unknown identity**, because a
//!     personal node is not a sign-up surface.
//!  6. **The accord's 2-of-3 confers `slash`**, and only then does the subject
//!     hold moderation authority — one seat alone confers nothing.
//!
//! Requires `--features test-anchor`: step 6 signs with the genesis holders'
//! real private halves, against the roster persist itself resolves.
#![cfg(feature = "test-anchor")]

use ciris_persist::federation::admission::DELEGATION_SCOPE_SLASH;
use ciris_persist::federation::operational::test_support::Identity;
use ciris_persist::federation::trust_root::capability_roots_to_trusted_root_over_roster;
use ciris_persist::prelude::Engine;
use ciris_persist::wa_cert::WaRole;
use ciris_server::auth::{oauth, store};
use std::sync::Arc;

mod support {
    include!("support/accord_trust.rs");
}
use support::{register_key_as_user, seed_accord_trust};

const OWNER_FEDID: &str = "eric-moore-v2-portable-f34de31d8c21-6e2b4kpvxk";
const GOOGLE_SUBJECT: &str = "110265575142761676421";

fn holders() -> Vec<Identity> {
    (0..3)
        .map(|i| Identity::new(&format!("test-accord-holder-{i}")))
        .collect()
}

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

async fn engine(node: &Identity) -> Arc<Engine> {
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ciris_persist::prelude::LocalSigner;
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0xF1; 32]),
        node.key_id.clone(),
        Some(pqc),
        Some("ciris-server-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

async fn holds_slash(e: &Engine, node: &str, subject: &str, roster: &[String]) -> bool {
    capability_roots_to_trusted_root_over_roster(
        e.federation_directory().as_ref(),
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
async fn a_google_owner_claims_a_node_and_the_accord_grants_them_moderation() {
    let hs = holders();
    arm(&hs);
    let node_id = Identity::new("e2e-personal-node");
    let e = engine(&node_id).await;
    let node = node_id.key_id.clone();
    let roster: Vec<String> = hs.iter().map(|h| h.key_id.clone()).collect();

    // ── 1. Google sign-in creates an account and does NOT claim the node ─────
    assert!(
        ciris_server::auth::bootstrap::is_first_run(&e).await,
        "precondition: a fresh node is unclaimed"
    );
    let signed_in =
        oauth::test_support_resolve_oauth_user(&e, "google", GOOGLE_SUBJECT, Some("eric@ciris.ai"))
            .await
            .expect("the founder's first sign-in creates a local identity");
    assert_ne!(
        store::get(&e, &signed_in).await.unwrap().unwrap().role,
        WaRole::Root,
        "a door must not decide who owns the house — the OAuth account is not the owner"
    );
    assert!(
        ciris_server::auth::bootstrap::is_first_run(&e).await,
        "…and the node must still be claimable, or the wizard's own claim 409s"
    );

    // ── 2-3. The claim binds the owner to the FED-ID and retires the duplicate ─
    //
    // Modelled directly rather than driven over HTTP: `setup_root` needs a live
    // claim PIN + a signed owner-binding, which is its own harness. What matters
    // to the arc is the STATE the claim leaves, and every assertion below reads
    // that state through the same code the app does.
    let owner_wa = format!("wa-root-{OWNER_FEDID}");
    let mut owner = store::get(&e, &signed_in).await.unwrap().unwrap();
    owner.wa_id = owner_wa.clone();
    owner.jwt_kid = format!("kid-{owner_wa}");
    owner.name = format!("root:{OWNER_FEDID}");
    owner.role = WaRole::Root;
    store::upsert(&e, owner).await.expect("bind the owner");
    store::set_active(&e, &signed_in, false)
        .await
        .expect("retire the duplicate holder of the pair");

    assert!(
        !ciris_server::auth::bootstrap::is_first_run(&e).await,
        "the node is now claimed"
    );

    // ── 4. The pair resolves to the OWNER, not the retired cert, not nothing ──
    let resolved = store::get_by_oauth(&e, "google", GOOGLE_SUBJECT)
        .await
        .expect("the pair must resolve")
        .expect("…to a live cert");
    assert_eq!(
        resolved.wa_id, owner_wa,
        "the sign-in must resolve to the OWNER. Resolving to the retired cert signs the human in \
         with observer rights; resolving to NOTHING lets the deterministic wa_id re-create the \
         retired row and undo the retirement."
    );

    // ── 5. A claimed PERSONAL node is not a sign-up surface ──────────────────
    let stranger =
        oauth::test_support_resolve_oauth_user(&e, "google", "999999999999999", None).await;
    assert!(
        stranger.is_err(),
        "a claimed personal node must refuse an unknown identity — otherwise anyone who can reach \
         the port gets an account for proving they control an unrelated email"
    );

    // ── 6. Only the ACCORD's 2-of-3 confers moderation ───────────────────────
    register_key_as_user(&e, OWNER_FEDID).await;
    register_key_as_user(&e, &node).await;
    seed_accord_trust(&e, &node_id, &hs).await;

    assert!(
        !holds_slash(&e, &node, OWNER_FEDID, &roster).await,
        "being the OWNER is not being a MODERATOR — CIRISServer#383's whole point"
    );

    // One seat is not the accord.
    let one = ciris_server::accord_duty::test_support_build_partial(
        OWNER_FEDID,
        &[DELEGATION_SCOPE_SLASH.to_string()],
        true,
        Some(2),
        &[&hs[0]],
    )
    .await;
    let _ = e
        .federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation { attestation: one })
        .await;
    assert!(
        !holds_slash(&e, &node, OWNER_FEDID, &roster).await,
        "one holder's scrub must confer nothing — that is the authority CIRISPersist#557 took \
         away from any single seat"
    );

    // Two of three IS the accord.
    let two = ciris_server::accord_duty::test_support_build_partial(
        OWNER_FEDID,
        &[DELEGATION_SCOPE_SLASH.to_string()],
        true,
        Some(2),
        &[&hs[0], &hs[1]],
    )
    .await;
    e.federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation { attestation: two })
        .await
        .expect("a 2-of-3 accord conferral must be admitted");

    assert!(
        holds_slash(&e, &node, OWNER_FEDID, &roster).await,
        "after the accord's 2-of-3 the owner MUST hold `slash` — this is the row the 61 leaked \
         QA keys of CIRISServer#383 are waiting on"
    );
}

/// **Ambiguity fails closed** (CIRISServer#397). Two live certs claiming one
/// provider identity is a broken invariant, not a question with a best answer.
/// Picking one is what signed a human in with the wrong rights and no error.
#[tokio::test]
async fn two_live_certs_claiming_one_identity_refuse_rather_than_choose() {
    let hs = holders();
    arm(&hs);
    let node_id = Identity::new("e2e-ambiguity-node");
    let e = engine(&node_id).await;

    let first =
        oauth::test_support_resolve_oauth_user(&e, "google", GOOGLE_SUBJECT, Some("eric@ciris.ai"))
            .await
            .expect("first sign-in creates");

    // A second LIVE cert carrying the same pair — the state the claim used to
    // leave behind before the duplicate was retired.
    let mut dup = store::get(&e, &first).await.unwrap().unwrap();
    dup.wa_id = format!("wa-root-{OWNER_FEDID}");
    dup.jwt_kid = format!("kid-wa-root-{OWNER_FEDID}");
    dup.role = WaRole::Root;
    store::upsert(&e, dup).await.expect("second live holder");

    assert!(
        store::get_by_oauth(&e, "google", GOOGLE_SUBJECT)
            .await
            .is_err(),
        "with TWO live holders the lookup must REFUSE, not choose. Choosing is how the owner was \
         silently signed in as an observer on their own node."
    );
}

/// **The claim's cleanup must survive its own fail-closed reader** (#397/#398).
///
/// This is the regression Codex caught, and the reason it escaped the test above
/// is worth recording: that test MODELS the claim (upsert the owner, deactivate
/// the duplicate) rather than calling `setup_root`. It asserted the state I
/// intended the claim to leave, so it could not see that the claim had stopped
/// being able to leave it.
///
/// A test that reproduces the post-state of the code under test proves the
/// post-state is coherent. It proves nothing about whether the code still
/// reaches it. Here the cleanup routed through `get_by_oauth`, which by then
/// REFUSED the exact two-live-holders state the cleanup exists to resolve — so
/// it retired nothing, and sign-in stayed ambiguous forever.
///
/// So this pins the PRIMITIVE the cleanup depends on: the scan must SEE both
/// holders at the moment the resolver refuses them.
#[tokio::test]
async fn the_scan_sees_what_the_resolver_refuses() {
    let hs = holders();
    arm(&hs);
    let node_id = Identity::new("e2e-repair-node");
    let e = engine(&node_id).await;

    let signed_in =
        oauth::test_support_resolve_oauth_user(&e, "google", GOOGLE_SUBJECT, Some("eric@ciris.ai"))
            .await
            .expect("first sign-in creates");

    // The claim stamps the pair onto the owner — now BOTH are live.
    let owner_wa = format!("wa-root-{OWNER_FEDID}");
    let mut owner = store::get(&e, &signed_in).await.unwrap().unwrap();
    owner.wa_id = owner_wa.clone();
    owner.jwt_kid = format!("kid-{owner_wa}");
    owner.role = WaRole::Root;
    store::upsert(&e, owner).await.expect("bind the owner");

    // The READER refuses this state — correctly.
    assert!(
        store::get_by_oauth(&e, "google", GOOGLE_SUBJECT)
            .await
            .is_err(),
        "two live holders must make the sign-in resolver refuse"
    );

    // …and the REPAIR path must still be able to see and fix it. Sharing one
    // entry point is what silently disabled the cleanup.
    let holders_seen = store::live_oauth_holders(&e, "google", GOOGLE_SUBJECT)
        .await
        .expect("the scan must not refuse — it exists FOR this state");
    assert_eq!(
        holders_seen.len(),
        2,
        "the scan must see BOTH holders at the moment the resolver refuses them, or the claim \
         cannot retire the duplicate and sign-in stays ambiguous forever"
    );
    assert!(
        holders_seen.iter().any(|c| c.wa_id == owner_wa),
        "…including the owner, so the cleanup knows which one to keep"
    );
}
