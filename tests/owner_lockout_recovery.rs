//! **Boot self-heals an owner locked out by the pre-#403 logout**
//! (CIRISServer#403).
//!
//! The old logout deactivated the owner's ROOT cert. That leaves a state no
//! legitimate flow produces: ZERO active roots while the CEG owner-binding
//! edge — the actual source of truth for who owns this node — still stands.
//! Nodes in that state exist, and without a heal they reopen first-run and
//! mint a claim PIN for a node that HAS an owner.
//!
//! `bootstrap_if_needed` now reads the binding (`is_steward_bound`) when it
//! finds no active root; if the bound owner's derived ROOT row exists but is
//! INACTIVE, it reactivates the row, warns loudly, and reports
//! `AlreadyBootstrapped` — so first-run stays closed and no PIN is minted.
//! The heal runs on the restart the operator performs anyway: no ceremony, no
//! lossy re-claim.
//!
//! The other half matters just as much: a FRESH node (no binding, no row)
//! must still report `NoSeedAvailable` — a heal that fires without the CEG
//! edge would be a way to conjure owners.

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::bootstrap::{self, BootstrapOutcome};
use ciris_server::auth::ownership::{
    apply_signed_owner_binding, build_signed_owner_binding, is_steward_bound,
    OWNER_BINDING_INFRA_SCOPES,
};
use ciris_server::auth::store;

const NODE_KEY_ID: &str = "ciris-lockout-node";
const USER_KEY_ID: &str = "ciris-lockout-owner";

/// The node's in-memory substrate — the `tests/claim_remote.rs` fixture.
async fn node() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xC1; 32]),
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer"),
    )
}

/// The responsible USER's signer (distinct keypair).
fn user_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC4; 32], format!("{USER_KEY_ID}-pqc"))
            .expect("user ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xC3; 32]),
        USER_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{USER_KEY_ID}-pqc")),
    )
}

/// Bind the user as this node's owner through the REAL claim machinery — the
/// same user-signed `delegates_to(user → node, infra:*)` the wizard persists.
async fn bind_owner(engine: &Engine) {
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        NODE_KEY_ID,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");

    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding =
        build_signed_owner_binding(&user_signer(), NODE_KEY_ID, &scopes, cohort_scope::SELF)
            .await
            .expect("user signs the owner-binding");
    apply_signed_owner_binding(
        engine,
        NODE_KEY_ID,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("node applies the owner-binding");
    assert_eq!(
        is_steward_bound(engine, NODE_KEY_ID).await.as_deref(),
        Some(USER_KEY_ID),
        "fixture: the CEG owner-binding must stand before the lockout is staged"
    );
}

/// The owner ROOT the claim mints, under the DERIVED id the heal looks up.
async fn owner_root(engine: &Engine) -> String {
    let wa_id = bootstrap::test_support_root_wa_id(USER_KEY_ID);
    let now = chrono::Utc::now();
    store::upsert(
        engine,
        WaCert {
            wa_id: wa_id.clone(),
            name: format!("root:{USER_KEY_ID}"),
            role: WaRole::Root,
            pubkey: USER_KEY_ID.to_string(),
            jwt_kid: format!("{wa_id}-jwt"),
            password_hash: None,
            api_key_hash: None,
            oauth_provider: None,
            oauth_external_id: None,
            oauth_links: None,
            veilid_id: None,
            auto_minted: true,
            parent_wa_id: None,
            parent_signature: None,
            scopes: serde_json::json!(["*"]),
            custom_permissions: None,
            adapter_id: None,
            adapter_name: None,
            adapter_metadata: None,
            token_type: TokenType::Standard,
            created: now,
            last_login: None,
            active: true,
        },
    )
    .await
    .expect("stamp the owner ROOT");
    wa_id
}

/// THE RECOVERY: a bound node whose ROOT was deactivated (the pre-#403 logout
/// state) boots straight back to owned — cert reactivated, first-run closed,
/// no claim PIN minted (the PIN mints only on `NoSeedAvailable`).
#[tokio::test]
async fn a_deactivated_owner_root_is_reactivated_at_boot_when_the_binding_stands() {
    let e = node().await;
    bind_owner(&e).await;
    let wa_id = owner_root(&e).await;

    // Stage the lockout exactly as the old logout produced it.
    store::set_active(&e, &wa_id, false)
        .await
        .expect("deactivate the ROOT directly");
    assert!(
        store::list_by_role(&e, WaRole::Root, 8)
            .await
            .expect("store")
            .is_empty(),
        "fixture: zero ACTIVE roots — the locked-out state"
    );

    let outcome = bootstrap::bootstrap_if_needed(&e, NODE_KEY_ID)
        .await
        .expect("bootstrap");
    assert_eq!(
        outcome,
        BootstrapOutcome::AlreadyBootstrapped,
        "a bound node with an inactive owner ROOT must heal, not reopen first-run — \
         NoSeedAvailable here mints a claim PIN for a node that HAS an owner"
    );
    let cert = store::get(&e, &wa_id).await.expect("store").expect("row");
    assert!(cert.active, "the owner's ROOT must be ACTIVE again");
    assert!(
        !bootstrap::is_first_run(&e).await,
        "first-run must be closed after the heal"
    );
}

/// The heal must NOT fire on a fresh node: no binding, no row, no owner —
/// `NoSeedAvailable`, exactly as before.
#[tokio::test]
async fn a_fresh_node_still_reports_no_seed_and_gets_no_false_heal() {
    let e = node().await;
    let outcome = bootstrap::bootstrap_if_needed(&e, NODE_KEY_ID)
        .await
        .expect("bootstrap");
    assert_eq!(
        outcome,
        BootstrapOutcome::NoSeedAvailable,
        "a fresh node must keep the first-run claim path — a heal that fires without \
         the CEG owner-binding would be a way to conjure owners"
    );
    assert!(bootstrap::is_first_run(&e).await);
}

/// A binding WITHOUT the derived ROOT row is not healable — there is nothing
/// safe to reactivate, so the claim path stays available. (The claim route
/// itself reconciles a bound-but-rowless node; the heal's job is only the
/// inactive-row lockout.)
#[tokio::test]
async fn a_binding_with_no_root_row_does_not_fabricate_one() {
    let e = node().await;
    bind_owner(&e).await;

    let outcome = bootstrap::bootstrap_if_needed(&e, NODE_KEY_ID)
        .await
        .expect("bootstrap");
    assert_eq!(
        outcome,
        BootstrapOutcome::NoSeedAvailable,
        "no row ⇒ nothing to reactivate — the heal must never MINT a cert"
    );
    assert!(
        store::get(&e, &bootstrap::test_support_root_wa_id(USER_KEY_ID))
            .await
            .expect("store")
            .is_none(),
        "…and no row may appear as a side effect"
    );
}
