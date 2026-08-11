//! **The owner is named after the PERSON, never after the door** (CIRISServer#391).
//!
//! Signing in with Google on an unclaimed node used to CLAIM it: `determine_role`
//! handed SYSTEM_ADMIN to the first OAuth user, and `create_oauth_user` wrote a
//! ROOT keyed to the auth pair — `oauth-<provider>-<external_id>`.
//!
//! Three things went wrong at once, and the third is the one that matters:
//!
//!  1. The owner was named after the DOOR. Everywhere else the owner is
//!     `wa-root-<identity_key_id>`, derived from the federation identity — the
//!     thing that signs CEG rows and that the node's
//!     `ownership:responsible_party:node:v1` edge points FROM. Production
//!     (canonical-server-1) already has the identity-derived shape.
//!  2. It closed first-run, so the wizard's own claim step — the step that binds
//!     the owner to their fed-ID and writes the ownership edge — died on
//!     `409 root already claimed` and the app fell back to local login.
//!  3. **The owner held no key.** OAuth carries no key material, so the node's
//!     "owner" could not sign a single federation row. An owner that cannot sign
//!     is not an owner; it is a session with a grand title.
//!
//! OAuth proves a human controls an email. Ownership comes from the CLAIM, from
//! the federation identity, on ONE path — whether the human arrives by Google or
//! by password.

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::WaRole;
use ciris_server::auth::store;
use ed25519_dalek::SigningKey;
use std::sync::Arc;

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xC1; 32]),
        "ciris-server".to_string(),
        Some(pqc),
        Some("ciris-server-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// A fresh node stays UNCLAIMED after an OAuth sign-in.
///
/// This is the whole fix in one assertion: the door may let you in, and it may
/// not decide who lives here.
#[tokio::test]
async fn an_oauth_sign_in_does_not_claim_an_unclaimed_node() {
    let e = engine().await;
    assert!(
        ciris_server::auth::bootstrap::is_first_run(&e).await,
        "precondition: the node starts unclaimed"
    );

    // The OAuth path creates its account...
    let wa_id = ciris_server::auth::oauth::test_support_resolve_oauth_user(
        &e,
        "google",
        "110265575142761676421",
        Some("eric@ciris.ai"),
    )
    .await
    .expect("oauth sign-in creates a local identity");

    // ...and that account is NOT the owner.
    let cert = store::get(&e, &wa_id)
        .await
        .expect("store")
        .expect("the oauth account exists");
    assert_ne!(
        cert.role,
        WaRole::Root,
        "an OAuth sign-in must not mint a ROOT — the owner is established by the CLAIM, from \
         the federation identity. Got a ROOT named {wa_id}, which is the auth pair, not a person."
    );
    assert!(
        ciris_server::auth::bootstrap::is_first_run(&e).await,
        "the node must STILL be claimable after an OAuth sign-in — otherwise the wizard's claim \
         step 409s and the user is bounced back to local login with their fed-ID bound to nothing"
    );
}

/// The owner id is derived from the federation identity, and that derivation is
/// the same one production already uses.
#[tokio::test]
async fn the_owner_wa_id_is_derived_from_the_federation_identity() {
    // canonical-server-1's live ROOT is `wa-root-eric-moore-v2-portable-…`, and
    // its ownership edge points from `eric-moore-v2-portable-…`. Pin the shape so
    // a future change cannot quietly reintroduce a door-derived owner.
    let fedid = "eric-moore-v2-portable-f34de31d8c21-6e2b4kpvxk";
    let derived = ciris_server::auth::bootstrap::test_support_root_wa_id(fedid);
    assert_eq!(derived, format!("wa-root-{fedid}"));
    assert!(
        !derived.starts_with("oauth-"),
        "the owner must never be named after an auth provider"
    );
}

/// **The claim IS the authentication** (CIRISServer#393).
///
/// The wizard's remaining steps — age band, federation announce, replication
/// consent — need an owner session, and it only knew how to get one by POSTing a
/// username and password. An OAuth owner has none, so the log read:
///
/// ```text
/// claim_accepted role=SYSTEM_ADMIN waId=wa-root-eric-moore-v2-…
/// owner_login SKIPPED (waId_present=true password_present=false)
/// set_age SKIPPED · announce SKIPPED · federation_consent SKIPPED
/// claim_settled claimed=true login=false
/// ```
///
/// The node was claimed correctly and the app fell back to the login screen with
/// three safety-relevant steps silently skipped. Asking someone to prove with a
/// password what they just proved with a one-time PIN and a hybrid signature over
/// the owner-binding is asking for weaker evidence, twice.
#[test]
fn the_claim_response_carries_an_owner_session() {
    let src = include_str!("../src/auth/bootstrap.rs");
    let decl = src
        .split("struct SetupRootResponse {")
        .nth(1)
        .expect("the claim response struct")
        .split("\n}")
        .next()
        .expect("its body");
    assert!(
        decl.contains("session: super::session::SessionGrant"),
        "the claim must return a session — without one it succeeds into a dead end for any owner \
         who has no password, which is every OAuth owner"
    );
    assert!(
        decl.contains("serde(flatten)"),
        "flattened, so the wire shape matches /v1/auth/login and the native exchanges exactly"
    );
    // Minted for the OWNER, through the ONE issuance point — not a parallel site
    // with its own token policy.
    assert!(
        src.contains("SessionGrant::issue(\n                        &wa_id,")
            || src.contains("SessionGrant::issue(&wa_id"),
        "the session must be issued for the newly-bound owner via SessionGrant::issue"
    );
}

/// **One provider identity resolves to ONE cert** (CIRISServer#395).
///
/// This shipped and was caught only by reading a token prefix in a log. The
/// OAuth sign-in creates an OBSERVER account (correct — a door does not own the
/// house); the claim then binds the owner and carries the sign-in pair across.
/// With BOTH certs holding the pair, `get_by_oauth` had two answers to one
/// question, and the next Google sign-in resolved to the OBSERVER. The user was
/// signed in, saw no error, and silently held observer rights on their own node
/// — a failure that surfaces at the first owner-gated act, far from its cause.
///
/// The retirement must key on the PAIR, not on the adopt path. An earlier
/// version retired only an adopted ROOT placeholder, and once OAuth stopped
/// minting ROOTs that condition never fired again — the cleanup was coupled to a
/// condition that had been fixed away, while the ambiguity it existed to prevent
/// remained.
#[test]
fn a_duplicate_holder_of_the_owners_provider_pair_is_retired() {
    let src = include_str!("../src/auth/bootstrap.rs");
    assert!(
        src.contains("store::live_oauth_holders(&st.engine, prov, ext)"),
        "the claim must SCAN for holders of the owner's provider pair. Two earlier shapes were \
         wrong: keying on the adopt path stopped firing the moment OAuth stopped minting ROOTs, \
         and routing through `get_by_oauth` made the cleanup take the Err arm on the exact \
         two-live-holders state it exists to resolve (Codex review) — retiring nothing and \
         leaving sign-in ambiguous forever."
    );
    assert!(
        !src.contains("store::get_by_oauth(&st.engine, prov, ext)"),
        "the cleanup must NOT use the fail-closed reader — a repair path cannot depend on a \
         reader that refuses the state the repair is for"
    );
    assert!(
        src.contains("c.wa_id != wa_id"),
        "…and retire only the holders that are NOT the owner"
    );
    assert!(
        src.contains("set_active(&st.engine, &other.wa_id, false)"),
        "retire by deactivating"
    );
    assert!(
        !src.contains("delete_wa_cert"),
        "deactivate, never delete — the row is audit history of a real sign-in"
    );
}

/// **A retired cert must not answer, AND the owner must** (CIRISServer#395).
///
/// This took three attempts, and the middle one made things worse — worth
/// recording, because the failure was a fix that was locally right:
///
///  1. Both certs held the pair, so the lookup had two answers and returned the
///     OBSERVER. The owner was signed in with observer rights, no error.
///  2. Retiring the duplicate had no effect: the index answers with a row
///     whatever its `active` flag says, so the retired cert kept answering.
///  3. Filtering the retired row to `None` was WORSE. `create_oauth_user`
///     derives a DETERMINISTIC `wa_id` from the pair, so "not found" made the
///     next sign-in UPSERT the retired row back to life. The retirement survived
///     exactly until the next login.
///
/// The question was never "is this row active" — it is "which LIVE cert holds
/// this provider identity". After a claim that is the owner, because the claim
/// stamps the pair onto it.
#[tokio::test]
async fn a_provider_pair_resolves_to_the_live_cert_not_a_retired_one() {
    let e = engine().await;
    let observer = ciris_server::auth::oauth::test_support_resolve_oauth_user(
        &e,
        "google",
        "110265575142761676421",
        Some("eric@ciris.ai"),
    )
    .await
    .expect("oauth sign-in creates a local identity");

    // The claim binds the owner and carries the pair across.
    let owner_wa = "wa-root-eric-moore-v2-portable-f34de31d8c21-6e2b4kpvxk";
    let mut owner_cert = store::get(&e, &observer)
        .await
        .expect("store")
        .expect("the observer exists");
    owner_cert.wa_id = owner_wa.to_string();
    owner_cert.name = format!("root:{owner_wa}");
    owner_cert.jwt_kid = format!("kid-{owner_wa}");
    owner_cert.role = WaRole::Root;
    store::upsert(&e, owner_cert).await.expect("bind the owner");
    // …and retires the duplicate.
    store::set_active(&e, &observer, false)
        .await
        .expect("retire the duplicate");

    let hit = store::get_by_oauth(&e, "google", "110265575142761676421")
        .await
        .expect("store")
        .expect("the pair must still resolve — to the OWNER");
    assert_eq!(
        hit.wa_id, owner_wa,
        "the provider pair must resolve to the LIVE cert (the owner), not the retired one and          not nothing. Returning nothing is worse than returning the retired row: the sign-in          path then re-creates it under the same deterministic wa_id and undoes the retirement."
    );
    assert_eq!(hit.role, WaRole::Root, "…and that cert is the owner");
}

/// **A personal node is not a sign-up surface** (CIRISServer#396).
///
/// Auto-creating an account for any presentable Google identity belongs to a
/// MANAGED deployment (CIRISManager / web), where an operator provisions people
/// ahead of time and an observer account is a meaningful default. On a personal
/// install the node has exactly ONE human, and a stranger who can reach the port
/// must get nothing for proving they control an unrelated email.
///
/// First-run is the deliberate exception: the owner's first sign-in is how they
/// establish themselves, before any cert exists to recognise them.
#[tokio::test]
async fn a_claimed_personal_node_refuses_an_unknown_oauth_identity() {
    let e = engine().await;

    // FIRST RUN: the owner's own first sign-in is allowed to create.
    let first = ciris_server::auth::oauth::test_support_resolve_oauth_user(
        &e,
        "google",
        "110265575142761676421",
        Some("eric@ciris.ai"),
    )
    .await
    .expect("the founder's first sign-in must be allowed to create an identity");

    // Claim the node (the founder becomes ROOT).
    let mut cert = store::get(&e, &first)
        .await
        .expect("store")
        .expect("exists");
    cert.wa_id = "wa-root-owner".into();
    cert.jwt_kid = "kid-wa-root-owner".into();
    cert.role = WaRole::Root;
    store::upsert(&e, cert).await.expect("bind the owner");

    // NOW a stranger presents a valid Google identity this node has never seen.
    let stranger = ciris_server::auth::oauth::test_support_resolve_oauth_user(
        &e,
        "google",
        "999999999999999999999",
        Some("stranger@example.com"),
    )
    .await;
    assert!(
        stranger.is_err(),
        "a claimed personal node created an account for an unknown Google identity — anyone who \
         can reach the port would get a foothold for proving they control some unrelated email"
    );

    // And the refusal is the SAME typed reason a known-but-unlinked identity
    // gets, so the wire cannot be used to enumerate who is enrolled here.
    assert_eq!(
        stranger.unwrap_err(),
        "auth.oauth.no_local_identity",
        "the refusal must not distinguish 'unknown to this node' from 'known but not linked' — \
         that difference is exactly what an enumeration probe is looking for"
    );
}
