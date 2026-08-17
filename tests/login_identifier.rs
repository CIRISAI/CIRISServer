//! **Which identifier does `POST /v1/auth/login` accept?** (CIRISServer#389)
//!
//! CIRISAgent hit this adopting CIRISServer#1028: they proxied `/v1/auth/*` to
//! the node, deleted 2752 lines of Python, and the node refused the owner
//! credential the Python accepted — `401 invalid credentials`, with nothing in
//! the log to say why. They could not tell "this node has never heard of that
//! user" from "the stored hash did not match", and those have opposite fixes.
//!
//! The logging half of the answer lives in `session.rs::login`. This is the
//! other half, and it is the part that could not be answered by reading the
//! code quickly: **the name match is the WHOLE name, exactly.**
//!
//! # The asymmetry that makes this a trap
//!
//! `GET /v1/auth/owner-hint` reports `first_name`, computed as
//! `c.name.split_whitespace().next()`. So a node whose owner cert is named
//! `"jeff smith"` advertises `first_name: "jeff"` — and `"jeff"` is exactly the
//! one thing `resolve_login` will NOT accept. The hint is a hint for a HUMAN
//! ("is this your node?"), never a login identifier, but nothing said so and
//! the two live three functions apart.
//!
//! That is the same one-name-two-axes shape this codebase keeps finding: one
//! string answering "who should I greet?" and "who may I sign in?" — and it is
//! only wrong in one direction, which is why it survived review.
//!
//! # What is deliberately NOT changed
//!
//! Matching stays exact. Accepting a first name would make login ambiguous the
//! moment two people share one — on the path where ambiguity means signing in
//! as the wrong person. The fix is for the caller to send what was stamped; the
//! node's job is to SAY so, which it now does in the log and here.

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::store::{self, LoginMatch};
use ed25519_dalek::SigningKey;
use std::sync::Arc;

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xB2; 32], "ciris-server-pqc".to_string())
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xB1; 32]),
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

/// An owner ROOT the way `POST /v1/setup/root` stamps one: `owner_username`
/// becomes the cert `name`.
fn owner(wa_id: &str, name: &str) -> WaCert {
    let now = chrono::Utc::now();
    WaCert {
        wa_id: wa_id.to_string(),
        name: name.to_string(),
        role: WaRole::Root,
        pubkey: format!("system-of:{wa_id}"),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: Some(ciris_server::auth::session::hash_password("hunter2")),
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
    }
}

/// The whole name matches; the first token — the one `owner-hint` advertises —
/// does not. This IS CIRISAgent's failure, reproduced.
#[tokio::test]
async fn login_matches_the_whole_name_not_the_first_token_owner_hint_shows() {
    let e = engine().await;
    store::upsert(&e, owner("wa-root-jeff", "jeff smith"))
        .await
        .expect("stamp the owner ROOT");

    // (1) The exact stamped name resolves.
    let hit = store::resolve_login_detailed(&e, "jeff smith")
        .await
        .expect("store")
        .expect("the exact stamped name must resolve");
    assert_eq!(hit.0.wa_id, "wa-root-jeff");
    assert_eq!(hit.1, LoginMatch::Name);

    // (2) The FIRST NAME does not — and this is what owner-hint shows, so a
    //     client that reads the hint and posts it back gets 401.
    let miss = store::resolve_login_detailed(&e, "jeff")
        .await
        .expect("store")
        .expect_err("a first name alone must NOT resolve");
    assert_eq!(
        miss.scanned, 1,
        "the miss must report that it DID scan a cert — 'scanned 0' means an empty store (a \
         different database), 'scanned 1' means a name mismatch. Collapsing those two is the \
         whole reason #389 was filed"
    );
    assert_eq!(
        miss.names,
        vec!["jeff smith".to_string()],
        "the miss carries the names it could have matched, so the log turns a guess into a lookup"
    );

    // (3) So does an unrelated identifier — same shape, and notably the QA
    //     suite's `admin`, which is the agent's DEFAULT WA name and simply is
    //     not what the node's wizard stamped.
    let miss = store::resolve_login_detailed(&e, "admin")
        .await
        .expect("store")
        .expect_err("an unrelated name must not resolve");
    assert_eq!(miss.scanned, 1);

    // (4) The wa_id always works, whatever the name is — the identifier a
    //     machine should use when it has one.
    let hit = store::resolve_login_detailed(&e, "wa-root-jeff")
        .await
        .expect("store")
        .expect("wa_id must resolve");
    assert_eq!(hit.1, LoginMatch::WaId);
}

/// An EMPTY store and a NAME MISMATCH are different answers, and the miss report
/// keeps them apart. Without this the node says "invalid credentials" whether it
/// is reading the wrong database entirely or simply disagrees about a name —
/// and an operator cannot tell a configuration error from a typo.
#[tokio::test]
async fn a_miss_distinguishes_an_empty_store_from_a_name_mismatch() {
    let e = engine().await;

    let miss = store::resolve_login_detailed(&e, "anyone")
        .await
        .expect("store")
        .expect_err("nothing is stamped yet");
    assert_eq!(
        miss.scanned, 0,
        "zero scanned == this node's wa_cert store is empty; it is not reading the database the \
         account was created in"
    );
    assert!(miss.names.is_empty());

    store::upsert(&e, owner("wa-root-a", "someone else"))
        .await
        .expect("stamp");
    let miss = store::resolve_login_detailed(&e, "anyone")
        .await
        .expect("store")
        .expect_err("still no match");
    assert_eq!(
        miss.scanned, 1,
        "non-zero scanned == the certs are here and none is called that — a DIFFERENT fix"
    );
}

/// **ANTI-ENUMERATION PIN** (CIRISServer#389): the two 401 branches — "no cert
/// resolved" and "password mismatch" — return BYTE-IDENTICAL bodies with the
/// SAME reason_id. The reason_id is new surface area, and new surface area is
/// where a distinguisher would sneak in: give the two branches two ids and the
/// wire says which accounts exist, which is exactly what the shared "invalid
/// credentials" sentence was closed against.
#[tokio::test]
async fn the_two_401_branches_are_byte_identical_including_the_reason_id() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    let e = engine().await;
    store::upsert(&e, owner("wa-root-jeff", "jeff smith"))
        .await
        .expect("stamp the owner ROOT");
    let app = ciris_server::auth::session::router(e.clone());

    let login = |body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    };

    // Branch 1: the identifier resolves to NOTHING.
    let miss = app
        .clone()
        .oneshot(login(
            serde_json::json!({"username": "nobody", "password": "whatever"}),
        ))
        .await
        .expect("miss call");
    assert_eq!(miss.status(), StatusCode::UNAUTHORIZED);
    let miss_body = miss.into_body().collect().await.expect("body").to_bytes();

    // Branch 2: the identifier resolves, the PASSWORD is wrong.
    let mismatch = app
        .clone()
        .oneshot(login(
            serde_json::json!({"username": "jeff smith", "password": "wrong"}),
        ))
        .await
        .expect("mismatch call");
    assert_eq!(mismatch.status(), StatusCode::UNAUTHORIZED);
    let mismatch_body = mismatch
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();

    assert_eq!(
        miss_body, mismatch_body,
        "the two 401 bodies differ — a caller can now probe which accounts exist by \
         diffing refusals. Both branches must emit the identical bytes"
    );
    let v: serde_json::Value = serde_json::from_slice(&miss_body).expect("json body");
    assert_eq!(
        v.get("reason_id").and_then(|x| x.as_str()),
        Some("auth.login.invalid_credentials"),
        "one shared reason_id for both causes — the distinction lives in the node's LOG, \
         where it belongs (that split is the whole of #389)"
    );
}

/// The OAuth pair resolves, and is reported as such — so a log line can say
/// which of the three keys matched rather than leaving it ambiguous.
#[tokio::test]
async fn the_oauth_pair_resolves_and_reports_how_it_matched() {
    let e = engine().await;
    let mut c = owner("wa-root-g", "google owner");
    c.oauth_provider = Some("google".into());
    c.oauth_external_id = Some("12345".into());
    store::upsert(&e, c).await.expect("stamp");

    let hit = store::resolve_login_detailed(&e, "google:12345")
        .await
        .expect("store")
        .expect("the provider:external_id pair must resolve");
    assert_eq!(hit.1, LoginMatch::Oauth);
    assert_eq!(hit.0.wa_id, "wa-root-g");
}
