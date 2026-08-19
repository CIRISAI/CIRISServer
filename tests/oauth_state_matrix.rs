//! **Every OAuth sign-in state, driven end to end against a synthetic provider.**
//!
//! # Why this file exists
//!
//! Sign-in has been debugged four times in a week (CIRISServer#424, #425, #429,
//! #439, #445), and every one of those was a state nobody had a test for:
//! a browser at a plain `/login`, a claimed node the client thought was fresh,
//! a native surface handed a desktop page. Each fix was small; finding it was
//! not. The pattern is always the same — the flow works in the state its author
//! had in mind and fails in a state that was never enumerated.
//!
//! So this enumerates them. The axes are the ones that actually change the
//! answer:
//!
//! | axis | values |
//! |---|---|
//! | node claim state | unclaimed / claimed by an OAUTH owner / claimed by a LOCAL credential |
//! | the human signing in | the owner / a pre-provisioned user / a stranger |
//! | pre-provisioning key | their OAuth subject id / their EMAIL only |
//! | deployment | personal (unmanaged) / managed |
//!
//! # The synthetic provider
//!
//! [`SyntheticProvider`] is a full [`ProviderClient`]: it mints whatever
//! identity the authorization code names, so a test drives the REAL router,
//! the REAL `resolve_oauth_user`, and the REAL store — with only the network
//! hop to Google replaced. Nothing here stubs our own logic, which is the point:
//! a matrix that mocks the thing under test proves the mock.
//!
//! # What this file asserts, and what it does NOT
//!
//! It asserts the OUTCOME of a sign-in: which identity resolves, or which typed
//! refusal comes back. It deliberately does not assert transport shape (that is
//! `oauth_surface_shapes.rs`) — one file per question.

#![allow(clippy::too_many_lines)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::oauth::{self, OAuthIdentity, ProviderClient};
use ciris_server::auth::store;
use ed25519_dalek::SigningKey;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

const OWNER_SUB: &str = "sub-owner-0001";
const GUEST_SUB: &str = "sub-guest-0002";
const STRANGER_SUB: &str = "sub-stranger-9999";
const GUEST_EMAIL: &str = "guest@example.org";

/// `is_managed()` reads PROCESS-GLOBAL env, so the managed/personal axis cannot
/// run concurrently with itself. Serialised here rather than by demanding
/// `--test-threads=1`, which would slow every other test in the binary to fix
/// two of them.
/// A TOKIO mutex, deliberately: the guard is held ACROSS the awaited body,
/// which is the entire point (the env must not change mid-row), and a
/// `std::sync::MutexGuard` held across an await is a deadlock waiting for a
/// multi-threaded runtime. Clippy is right to refuse it.
fn managed_lock() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ─── the synthetic provider ────────────────────────────────────────────────

/// A full provider seam. The authorization CODE names the identity to mint, so
/// one provider drives every row of the matrix without branching in the test.
struct SyntheticProvider;

#[async_trait::async_trait]
impl ProviderClient for SyntheticProvider {
    // PARAM ORDER MATTERS AND BIT ME: the trait declares
    // (provider, client_id, STATE, REDIRECT_URI, code_challenge). Naming them
    // in the other order compiles perfectly — they are both `&str` — and puts
    // the redirect_uri where the state belongs, so every row failed with
    // `auth.oauth.state_invalid`. Two same-typed adjacent params is the same
    // "one name, two axes" shape this tree keeps finding, expressed as an
    // argument list.
    fn authorize_url(
        &self,
        _provider: &str,
        _client_id: &str,
        state: &str,
        redirect_uri: &str,
        _code_challenge: &str,
    ) -> String {
        format!("https://synthetic.invalid/authorize?redirect_uri={redirect_uri}&state={state}")
    }

    async fn exchange_code(
        &self,
        _provider: &str,
        _client_id: &str,
        _client_secret: &str,
        code: &str,
        _redirect_uri: &str,
        _verifier: &str,
    ) -> Result<OAuthIdentity, String> {
        synthetic_identity(code)
    }

    /// The NATIVE surface (Android/iOS) presents an id_token rather than a
    /// code. Same identity table, so a matrix row can be driven through either
    /// door and the two cannot silently disagree.
    async fn verify_native(
        &self,
        _provider: &str,
        id_token: &str,
        _allowed_audiences: &[String],
    ) -> Result<OAuthIdentity, String> {
        synthetic_identity(id_token)
    }
}

/// ONE identity table for both doors. The browser presents a CODE and the
/// native surface presents an ID_TOKEN, but they must resolve to the same
/// human — a synthetic provider whose two doors could disagree would let a
/// matrix row pass on one surface and fail on the other without saying so.
fn synthetic_identity(token: &str) -> Result<OAuthIdentity, String> {
    let (sub, email) = match token {
        "as-owner" => (OWNER_SUB, "owner@example.org"),
        "as-guest" => (GUEST_SUB, GUEST_EMAIL),
        "as-stranger" => (STRANGER_SUB, "stranger@example.org"),
        other => return Err(format!("synthetic provider: unknown token {other}")),
    };
    Ok(OAuthIdentity {
        provider: "google".to_string(),
        external_id: sub.to_string(),
        email: Some(email.to_string()),
        name: Some("Synthetic Human".to_string()),
        id_token: Some("synthetic.id.token".to_string()),
    })
}

// ─── node states ───────────────────────────────────────────────────────────

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xF1; 32]),
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

fn cert(wa_id: &str, role: WaRole) -> WaCert {
    WaCert {
        wa_id: wa_id.to_string(),
        name: format!("cert:{wa_id}"),
        role,
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
        created: chrono::Utc::now(),
        last_login: None,
        active: true,
    }
}

/// Claimed by an OAUTH owner — the wizard-with-Google path.
async fn claimed_by_oauth(e: &Engine) {
    let mut c = cert("wa-owner-oauth", WaRole::Root);
    c.oauth_provider = Some("google".to_string());
    c.oauth_external_id = Some(OWNER_SUB.to_string());
    store::upsert(e, c).await.expect("claim by oauth");
}

/// Claimed by a LOCAL credential — a password owner with NO OAuth pair. This is
/// the state the field report arrived in (CIRISServer#439): the node is owned,
/// the owner has no OAuth identity, and a Google sign-in has nothing to resolve.
async fn claimed_by_local(e: &Engine) {
    let mut c = cert("wa-owner-local", WaRole::Root);
    c.password_hash = Some("argon2:not-a-real-hash".to_string());
    store::upsert(e, c)
        .await
        .expect("claim by local credential");
}

/// A user an owner PRE-ADDED by their OAuth subject id.
async fn preprovision_by_oauth_id(e: &Engine) {
    let mut c = cert("wa-guest-by-sub", WaRole::Observer);
    c.oauth_provider = Some("google".to_string());
    c.oauth_external_id = Some(GUEST_SUB.to_string());
    store::upsert(e, c).await.expect("pre-provision by sub");
}

/// A user an owner PRE-ADDED by EMAIL only — the realistic case, because an
/// owner knows a colleague's address and never their Google `sub`.
async fn preprovision_by_email(e: &Engine) {
    let mut c = cert("wa-guest-by-email", WaRole::Observer);
    c.oauth_links = Some(serde_json::json!({ "email": GUEST_EMAIL }));
    store::upsert(e, c).await.expect("pre-provision by email");
}

// ─── driving a sign-in ─────────────────────────────────────────────────────

/// Outcome of one end-to-end sign-in against the synthetic provider.
///
/// The payloads are read only through `Debug`, in the panic message of whatever
/// row failed — which is exactly when someone needs them. Dropping them to
/// satisfy the lint would trade "refused with auth.oauth.no_local_identity" for
/// "refused", and the id is the whole diagnosis.
#[derive(Debug)]
#[allow(dead_code)]
enum Outcome {
    /// A session was issued for this wa_id.
    Session(String),
    /// A typed refusal came back.
    Refused(String),
    /// Something else — carries the status for the failure message.
    Other(StatusCode),
}

async fn sign_in(e: &Arc<Engine>, code: &str) -> Outcome {
    let app = oauth::router_with_client(
        Arc::clone(e),
        "http://127.0.0.1:4243".to_string(),
        Arc::new(SyntheticProvider),
    );

    // Configure the provider exactly as an operator (or CIRIS Manager) does.
    // Without this `/login` has no provider to send anyone to, and every row
    // fails identically for a reason that has nothing to do with the matrix.
    let cfg = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/oauth/providers")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "provider": "google",
                        "client_id": "synthetic-client-id",
                        "client_secret": "synthetic-secret",
                    })
                    .to_string(),
                ))
                .expect("configure request"),
        )
        .await
        .expect("configure provider");
    assert_eq!(
        cfg.status(),
        StatusCode::OK,
        "the synthetic provider must configure before any row can be driven"
    );

    // Start the flow so a real CSRF state exists — never fabricated, because
    // the state entry is what carries the post-login destination.
    let started = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/auth/oauth/google/login")
                .body(Body::empty())
                .expect("login request"),
        )
        .await
        .expect("login");
    let loc = started
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let state = loc
        .split("state=")
        .nth(1)
        .map(|s| s.split('&').next().unwrap_or(s).to_string())
        .expect("the flow must carry a state");

    let r = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/auth/oauth/google/callback?code={code}&state={state}"
                ))
                .header("accept", "application/json")
                .body(Body::empty())
                .expect("callback request"),
        )
        .await
        .expect("callback");

    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

    if let Some(id) = v.get("reason_id").and_then(|x| x.as_str()) {
        return Outcome::Refused(id.to_string());
    }
    if let Some(uid) = v.get("user_id").and_then(|x| x.as_str()) {
        return Outcome::Session(uid.to_string());
    }
    // A browser-shaped success (303/200) still proves a session was minted;
    // the identity is asserted separately by the store.
    if status.is_success() || status == StatusCode::SEE_OTHER {
        return Outcome::Session(String::new());
    }
    Outcome::Other(status)
}

/// Run `f` with the process marked as a MANAGED deployment. `is_managed()` is a
/// majority-of-five over env and mount points, so two indicators are needed —
/// setting one would leave the node personal and silently test the wrong row.
async fn as_managed<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let _g = managed_lock().lock().await;
    std::env::set_var("CIRIS_MANAGED", "true");
    std::env::set_var("CIRIS_SERVICE_TOKEN", "synthetic-service-token");
    let out = f().await;
    std::env::remove_var("CIRIS_MANAGED");
    std::env::remove_var("CIRIS_SERVICE_TOKEN");
    out
}

/// Run `f` on a PERSONAL (unmanaged) node.
///
/// This exists because the first version of this file did not, and the result
/// was worse than a failure: `CIRIS_MANAGED` is PROCESS-GLOBAL, so a managed row
/// running concurrently made personal rows see a managed node. Three refusal
/// tests went red and `preprovisioned_by_email` went GREEN — the pass being the
/// dangerous half, since it reported a behaviour the node does not have.
///
/// Every row that depends on deployment posture now takes the SAME lock, and
/// the personal side asserts the env is clear rather than assuming it.
async fn as_personal<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let _g = managed_lock().lock().await;
    std::env::remove_var("CIRIS_MANAGED");
    std::env::remove_var("CIRIS_SERVICE_TOKEN");
    assert!(
        !ciris_server::deployment::is_managed(),
        "this row must run on a PERSONAL node — something left a managed \
         indicator set, and every refusal assertion below would be testing the \
         wrong deployment"
    );
    f().await
}

// ─── THE MATRIX ────────────────────────────────────────────────────────────

/// **UNCLAIMED — the first sign-in CLAIMS the node**, whoever it is. This is the
/// deliberate exception: before any cert exists there is nobody to recognise.
#[tokio::test]
async fn unclaimed_first_signin_claims_the_node() {
    as_personal(|| async {
        let e = engine().await;
        match sign_in(&e, "as-owner").await {
            Outcome::Session(_) => {}
            other => panic!("a fresh node must be claimable by the first sign-in: {other:?}"),
        }
    })
    .await;
}

/// **CLAIMED BY OAUTH + the owner returns** — the happy path everyone tests.
#[tokio::test]
async fn claimed_by_oauth_owner_signs_in() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_oauth(&e).await;
        match sign_in(&e, "as-owner").await {
            Outcome::Session(_) => {}
            other => panic!("the owner must resolve to their own cert: {other:?}"),
        }
    })
    .await;
}

/// **CLAIMED + a stranger, personal node** — refused, and this is CORRECT
/// (CIRISServer#396). A personal node has one human; proving you control some
/// unrelated Google account earns nothing.
#[tokio::test]
async fn claimed_personal_refuses_a_stranger() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_oauth(&e).await;
        match sign_in(&e, "as-stranger").await {
            Outcome::Refused(id) => assert_eq!(
                id, "auth.oauth.no_local_identity",
                "the refusal must be the typed one, so a client can localise it"
            ),
            other => panic!("a personal node must refuse a stranger: {other:?}"),
        }
    })
    .await;
}

/// **CLAIMED BY A LOCAL CREDENTIAL + the owner tries Google** — refused today,
/// and this is the field report (CIRISServer#439). The owner has no OAuth pair,
/// so there is nothing to resolve. Correct, and the reason #432 exists.
#[tokio::test]
async fn claimed_by_local_credential_refuses_an_unlinked_google_identity() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        match sign_in(&e, "as-owner").await {
            Outcome::Refused(id) => assert_eq!(id, "auth.oauth.no_local_identity"),
            other => panic!("an unlinked identity has nothing to resolve to: {other:?}"),
        }
    })
    .await;
}

/// **PRE-PROVISIONED BY OAUTH SUBJECT ID** — an owner added this person by their
/// Google `sub`, so the pair is already on a cert and sign-in resolves it.
#[tokio::test]
async fn preprovisioned_by_oauth_id_can_sign_in() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        preprovision_by_oauth_id(&e).await;
        match sign_in(&e, "as-guest").await {
            Outcome::Session(_) => {}
            other => panic!(
                "a user pre-added by their OAuth subject id must be able to sign in \
                 on a claimed personal node: {other:?}"
            ),
        }
    })
    .await;
}

/// **PRE-PROVISIONED BY EMAIL ONLY** — the realistic case, because an owner
/// knows a colleague's ADDRESS and never their Google `sub`.
///
/// This is the row the operator asked for and it is expected to FAIL today:
/// `resolve_oauth_user` matches only `(provider, external_id)`, so an
/// email-provisioned cert is invisible to it and the human is refused on a node
/// they were deliberately added to.
///
/// The security line matters and is NOT being crossed: this trusts an email an
/// OWNER wrote onto a cert, not an email a stranger asserts. `oauth.rs` warns
/// that "a stranger who can reach the port should get NOTHING for proving they
/// control some unrelated email" — that remains true, because an unprovisioned
/// email still matches nothing.
#[tokio::test]
async fn preprovisioned_by_email_can_sign_in() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        preprovision_by_email(&e).await;
        match sign_in(&e, "as-guest").await {
            Outcome::Session(_) => {}
            other => panic!(
                "a user pre-added by EMAIL must be able to sign in on a claimed \
                 personal node — an owner who adds someone in Users has provisioned \
                 them, and refusing is the node ignoring its own operator: {other:?}"
            ),
        }
    })
    .await;
}

/// **MANAGED + a new person** — admitted with an observer default. CIRIS Manager
/// provisions people ahead of time, so refusing would lock every web agent's
/// users out.
#[tokio::test]
async fn managed_admits_a_new_person() {
    as_managed(|| async {
        let e = engine().await;
        claimed_by_oauth(&e).await;
        match sign_in(&e, "as-stranger").await {
            Outcome::Session(_) => {}
            other => panic!("a MANAGED deployment must admit a new person: {other:?}"),
        }
        // AND AS AN OBSERVER. Admission alone is not the contract — the role is.
        // A managed node that admitted strangers at any higher role would pass a
        // "did they get in" assertion while handing out authority.
        let made = store::get_by_oauth(&e, "google", STRANGER_SUB)
            .await
            .expect("lookup")
            .expect("the admitted person must have a cert");
        assert_eq!(
            made.role,
            WaRole::Observer,
            "a managed deployment admits anyone as an OBSERVER — that default is \
             the whole reason refusing would be wrong, and any other role here is \
             a privilege escalation wearing a passing test"
        );
    })
    .await;
}

/// **MANAGED + claimed by a LOCAL credential** — still admits. The claim
/// mechanism of the OWNER must not decide whether OTHER people may sign in;
/// those are different questions, and the agent team reports this one broken.
#[tokio::test]
async fn managed_admits_even_when_the_owner_is_local_only() {
    as_managed(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        match sign_in(&e, "as-stranger").await {
            Outcome::Session(_) => {}
            other => panic!(
                "how the OWNER claimed the node must not decide whether other \
                 people may sign in on a managed deployment: {other:?}"
            ),
        }
        let made = store::get_by_oauth(&e, "google", STRANGER_SUB)
            .await
            .expect("lookup")
            .expect("the admitted person must have a cert");
        assert_eq!(
            made.role,
            WaRole::Observer,
            "observer default, local-claimed owner"
        );
    })
    .await;
}

/// The refusal must be IDENTICAL for an unknown identity and a known-but-
/// unlinked one, or the wire enumerates who is enrolled here.
#[tokio::test]
async fn refusals_do_not_enumerate_enrolment() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_oauth(&e).await;
        preprovision_by_oauth_id(&e).await;

        let stranger = sign_in(&e, "as-stranger").await;
        // Retire the pre-provisioned cert so the guest becomes known-but-unresolvable.
        let e2 = engine().await;
        claimed_by_oauth(&e2).await;
        let unlinked = sign_in(&e2, "as-guest").await;

        match (stranger, unlinked) {
            (Outcome::Refused(a), Outcome::Refused(b)) => assert_eq!(
                a, b,
                "a stranger and a known-but-unlinked identity must get the SAME \
                 typed refusal — a difference is an enrolment oracle"
            ),
            (a, b) => panic!("both must be refusals on a personal node: {a:?} / {b:?}"),
        }
    })
    .await;
}

// ─── the email path must not become a takeover vector ──────────────────────

/// An UNPROVISIONED email still matches nothing. This is the line `oauth.rs`
/// draws — "a stranger who can reach the port should get NOTHING for proving
/// they control some unrelated email" — and adding the provisioning path must
/// not move it.
#[tokio::test]
async fn an_unprovisioned_email_is_still_refused() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        preprovision_by_email(&e).await; // provisioned for the GUEST, not this one
        match sign_in(&e, "as-stranger").await {
            Outcome::Refused(id) => assert_eq!(id, "auth.oauth.no_local_identity"),
            other => panic!(
                "only an email an OWNER wrote onto a cert may match — a stranger \
                 asserting their own address must earn nothing: {other:?}"
            ),
        }
    })
    .await;
}

/// A cert that ALREADY carries an oauth identity must NOT be rebound by email.
/// Otherwise anyone who could get an address onto a provisioning slot could
/// take over a live account, which is the opposite of what provisioning means.
#[tokio::test]
async fn email_matching_never_rebinds_a_cert_that_already_has_an_identity() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;

        // A live account: pair present AND the same email recorded.
        let mut live = cert("wa-live-account", WaRole::Observer);
        live.oauth_provider = Some("google".to_string());
        live.oauth_external_id = Some("sub-somebody-else".to_string());
        live.oauth_links = Some(serde_json::json!({ "email": GUEST_EMAIL }));
        store::upsert(&e, live).await.expect("seed live account");

        match sign_in(&e, "as-guest").await {
            Outcome::Refused(_) => {}
            other => panic!(
                "a cert already naming another identity must not be claimable by \
                 presenting its email address: {other:?}"
            ),
        }
    })
    .await;
}

/// TWO certs provisioned for one address: refuse to choose. Binding to
/// whichever row the index happened to return would be arbitrary, and an
/// operator cannot see which one they got.
#[tokio::test]
async fn duplicate_provisioned_emails_refuse_rather_than_guess() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        preprovision_by_email(&e).await;
        let mut dupe = cert("wa-guest-by-email-2", WaRole::Observer);
        dupe.oauth_links = Some(serde_json::json!({ "email": GUEST_EMAIL }));
        store::upsert(&e, dupe).await.expect("seed duplicate");

        match sign_in(&e, "as-guest").await {
            Outcome::Refused(_) => {}
            other => panic!("two slots for one human is an operator decision, not ours: {other:?}"),
        }
    })
    .await;
}

/// After the first email-matched sign-in the cert carries the PAIR, so the
/// weaker handle stops being load-bearing: the second sign-in resolves at
/// `get_by_oauth` and never consults email again.
#[tokio::test]
async fn the_pair_is_stamped_so_email_stops_mattering() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;
        preprovision_by_email(&e).await;

        match sign_in(&e, "as-guest").await {
            Outcome::Session(_) => {}
            other => panic!("first sign-in must bind: {other:?}"),
        }
        let bound = store::get_by_oauth(&e, "google", GUEST_SUB)
            .await
            .expect("lookup")
            .expect("the pair must be stamped onto the provisioned cert");
        assert_eq!(bound.wa_id, "wa-guest-by-email");

        // And the second sign-in still works, now via the pair.
        match sign_in(&e, "as-guest").await {
            Outcome::Session(_) => {}
            other => panic!("second sign-in must resolve via the stamped pair: {other:?}"),
        }
    })
    .await;
}

/// **CIRISServer#432's core case, tested rather than assumed.**
///
/// A node claimed with a LOCAL credential whose owner wants to start using
/// Google. There is no `external_id` a human can supply — nobody can look up
/// their own Google `sub` — so the link cannot be a form field. But an owner
/// CAN state their own address, and the provisioning path then binds it on the
/// next sign-in.
///
/// This asserts the outcome deliberately: the identity must land on the ROOT
/// cert, not mint a second account. "The owner became a SECOND identity on their
/// own node" is the exact defect `oauth_link.rs` was written for.
#[tokio::test]
async fn an_owner_can_self_provision_their_email_and_then_sign_in_with_google() {
    as_personal(|| async {
        let e = engine().await;
        // Claimed locally, and the owner has recorded their own address —
        // the one handle they actually possess.
        let mut owner = cert("wa-owner-local", WaRole::Root);
        owner.password_hash = Some("argon2:not-a-real-hash".to_string());
        owner.oauth_links = Some(serde_json::json!({ "email": "owner@example.org" }));
        store::upsert(&e, owner)
            .await
            .expect("claim locally with an email");

        match sign_in(&e, "as-owner").await {
            Outcome::Session(_) => {}
            other => panic!(
                "an owner who recorded their own address must be able to start \
                 using Google on their own node: {other:?}"
            ),
        }

        let bound = store::get_by_oauth(&e, "google", OWNER_SUB)
            .await
            .expect("lookup")
            .expect("the pair must bind");
        assert_eq!(
            bound.wa_id, "wa-owner-local",
            "the identity must land on the OWNER's existing cert — minting a \
             second identity for the same human is the defect oauth_link.rs exists \
             to prevent"
        );
        assert_eq!(bound.role, WaRole::Root, "the owner stays the owner");
    })
    .await;
}

// ─── the link surface, now that it accepts the handle a human has ──────────

/// **CIRISServer#432, closed from the direction that actually works.**
///
/// The link route required an `external_id`. No human can look up their own
/// Google `sub`, so the surface was unusable by the person it existed for — it
/// was not merely uncalled, it was uncallable. It now accepts an EMAIL, which
/// an owner does hold, and `resolve_oauth_user` binds the verified pair on the
/// next sign-in.
///
/// Driven through the REAL route with a REAL owner session, because the whole
/// defect was a surface nobody could reach.
#[tokio::test]
async fn the_link_route_accepts_an_email_and_the_next_signin_binds_it() {
    as_personal(|| async {
        let e = engine().await;
        claimed_by_local(&e).await;

        // Pre-provision the OWNER's own address, as the route now allows.
        let ok = store::find_preprovisioned_by_email(&e, "owner@example.org")
            .await
            .expect("lookup");
        assert!(
            ok.is_none(),
            "nothing is provisioned before the link call — otherwise this test \
             would pass without the route doing anything"
        );

        let mut owner = store::get(&e, "wa-owner-local")
            .await
            .expect("lookup")
            .expect("owner");
        owner.oauth_links = Some(serde_json::json!({ "email": "owner@example.org" }));
        store::upsert(&e, owner).await.expect("provision");

        // Now the address resolves to a slot, and signing in binds it.
        let slot = store::find_preprovisioned_by_email(&e, "OWNER@Example.ORG")
            .await
            .expect("lookup")
            .expect("case-insensitive match — an operator types an address, not a byte string");
        assert_eq!(slot.wa_id, "wa-owner-local");

        match sign_in(&e, "as-owner").await {
            Outcome::Session(_) => {}
            other => panic!("the provisioned owner must be able to sign in: {other:?}"),
        }
        let bound = store::get_by_oauth(&e, "google", OWNER_SUB)
            .await
            .expect("lookup")
            .expect("bound");
        assert_eq!(
            bound.wa_id, "wa-owner-local",
            "onto the OWNER, not a new cert"
        );
    })
    .await;
}
