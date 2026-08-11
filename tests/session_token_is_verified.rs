//! **A session token's secret half must be VERIFIED** (CIRISServer#394).
//!
//! `issue_session_token` minted `sess:<wa_id>:<random>` and `resolve_bearer`
//! parsed the `wa_id` back out, loaded that cert, checked `active`, and
//! authenticated the caller — **without ever looking at the random half**. Any
//! string in that position worked, so the token was a bearer credential whose
//! secret was decorative:
//!
//! ```text
//! Authorization: Bearer sess:wa-root-<owner>:FORGEDXXXXXX
//!   GET  /v1/auth/me        200   role: SYSTEM_ADMIN
//!   POST /v1/admin/preview  200
//! ```
//!
//! And the `wa_id` was not a secret either. `GET /v1/auth/owner-hint` is
//! unauthenticated and returns the owner's `name`, which is the `wa_id` minus
//! its `wa-` prefix — so an unauthenticated GET yielded everything needed to
//! forge a SYSTEM_ADMIN session, on a node that binds `0.0.0.0`.
//!
//! # The lesson, which the agent already had right
//!
//! Their `validate_api_key` looks the key up by `_get_key_id` — a sha256 prefix,
//! an INDEX — and then gates on `bcrypt.checkpw(api_key, stored.key_hash)`
//! before checking `is_active` and `expires_at`. We had built the index and
//! skipped the gate. An identifier derived from a credential is not a check of
//! that credential; it only says which credential is being claimed.
//!
//! Here the gate is an HMAC over `(wa_id, nonce)` under a per-process secret,
//! compared in constant time. Self-verifying, so it needs no store, and it is
//! bound to the `wa_id` so a MAC minted for one identity cannot be replayed
//! against another.

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::{session, store};
use ed25519_dalek::SigningKey;
use std::sync::Arc;

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xD2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xD1; 32]),
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

async fn owner(e: &Engine, wa_id: &str) {
    let now = chrono::Utc::now();
    store::upsert(
        e,
        WaCert {
            wa_id: wa_id.to_string(),
            name: format!("root:{wa_id}"),
            role: WaRole::Root,
            pubkey: format!("system-of:{wa_id}"),
            jwt_kid: format!("kid-{wa_id}"),
            password_hash: None,
            api_key_hash: None,
            oauth_provider: None,
            oauth_external_id: None,
            oauth_links: None,
            veilid_id: None,
            auto_minted: false,
            adapter_id: None,
            adapter_name: None,
            adapter_metadata: None,
            scopes: serde_json::json!([]),
            custom_permissions: None,
            token_type: TokenType::Standard,
            parent_wa_id: None,
            parent_signature: None,
            created: now,
            last_login: None,
            active: true,
        },
    )
    .await
    .expect("stamp the owner");
}

/// **THE VULNERABILITY, pinned.** A token with the right `wa_id` and a junk
/// secret must NOT authenticate.
#[tokio::test]
async fn a_forged_session_token_is_rejected() {
    let e = engine().await;
    let wa = "wa-root-eric-moore-v2-portable-f34de31d8c21-6e2b4kpvxk";
    owner(&e, wa).await;

    // Everything an attacker needs is public: `owner-hint` hands out the name,
    // and the wa_id is that name with a `wa-` prefix.
    for forged in [
        format!("sess:{wa}:FORGEDXXXXXX"),
        format!("sess:{wa}:"),
        format!("sess:{wa}:aaaa.bbbb"),
        // A well-formed nonce with a wrong MAC — the near-miss that a
        // length-only or prefix-only check would wave through.
        format!("sess:{wa}:abcdefghijklmnopqrstuvwx.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ] {
        let caller = session::resolve_bearer(&e, &forged).await.expect("store");
        assert!(
            caller.is_none(),
            "a forged session token authenticated as the owner: {forged}. The wa_id is PUBLIC \
             (owner-hint serves it unauthenticated), so if the secret half is not checked, an \
             unauthenticated GET is enough to become SYSTEM_ADMIN."
        );
    }
}

/// A genuinely issued token still works — the gate must not be a wall.
#[tokio::test]
async fn a_real_session_token_still_authenticates() {
    let e = engine().await;
    let wa = "wa-root-real-owner";
    owner(&e, wa).await;

    let token = session::test_support_issue_session_token(wa);
    let caller = session::resolve_bearer(&e, &token)
        .await
        .expect("store")
        .expect("a token this process minted must authenticate");
    assert_eq!(caller.wa_id, wa);
}

/// A MAC minted for ONE identity must not authenticate ANOTHER. Binding the MAC
/// to the `wa_id` is what stops an attacker who holds their own valid session
/// from re-pointing it at the owner — the privilege escalation a bare random
/// nonce would still allow.
#[tokio::test]
async fn a_valid_mac_cannot_be_replayed_against_a_different_identity() {
    let e = engine().await;
    let victim = "wa-root-victim";
    let attacker = "wa-observer-attacker";
    owner(&e, victim).await;
    owner(&e, attacker).await;

    let mine = session::test_support_issue_session_token(attacker);
    // Swap the identity, keep the secret: `sess:<victim>:<attacker's nonce.mac>`.
    let secret = mine
        .strip_prefix(&format!("sess:{attacker}:"))
        .expect("token shape");
    let swapped = format!("sess:{victim}:{secret}");

    assert!(
        session::resolve_bearer(&e, &swapped)
            .await
            .expect("store")
            .is_none(),
        "a MAC issued for {attacker} authenticated as {victim} — the MAC must cover the wa_id, \
         or any valid session can be re-pointed at the owner"
    );
}

/// Tokens from BEFORE the fix (no MAC segment) are rejected rather than
/// grandfathered. Accepting them would preserve the exact forgery this closes.
#[tokio::test]
async fn a_pre_fix_token_shape_is_not_grandfathered() {
    let e = engine().await;
    let wa = "wa-root-legacy";
    owner(&e, wa).await;
    assert!(
        session::resolve_bearer(&e, &format!("sess:{wa}:MjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw"))
            .await
            .expect("store")
            .is_none(),
        "a pre-#394 token (random half, no MAC) must NOT be accepted — it is indistinguishable \
         from a forgery, because that IS the forgery"
    );
}
