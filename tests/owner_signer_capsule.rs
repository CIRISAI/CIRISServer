//! **The owner-signing capsule refuses everyone it should** (CIRISServer#342).
//!
//! The capsule exists so an auditor can see the owner's OWN signature on a human
//! approval, rather than a delegate's signature naming the owner. That makes its
//! refusals the load-bearing half: a capsule handed to the wrong caller is worse
//! than no capsule at all, because the resulting signature is indistinguishable
//! from a real one.
//!
//! The case worth writing a test for is the DELEGATE. `resolve_bearer` hands a
//! `dgrant:` token the owner's role AND `FullAccess` by design — that is what
//! makes delegation useful — so a role check alone passes it. A delegate holding
//! this capsule could author the owner's signature, and the signature would
//! outlive the delegation that produced it: a temporary grant becoming permanent
//! authority. `caller.actor.is_some()` is the only thing standing between those
//! two worlds.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::store;
use ciris_server::owner_signer_capsule::{acquire, CapsuleRefusal};
use ed25519_dalek::SigningKey;

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
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

async fn owner(e: &Engine) {
    let now = chrono::Utc::now();
    store::upsert(
        e,
        WaCert {
            wa_id: "wa-owner".to_string(),
            name: "root:wa-owner".to_string(),
            role: WaRole::Root,
            pubkey: "system-of:wa-owner".to_string(),
            jwt_kid: "kid-wa-owner".to_string(),
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
    .expect("seed owner");
}

fn seed_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("ciris-owner-capsule-test")
}

/// No bearer at all — refused, and named as such.
#[tokio::test]
async fn no_session_is_refused() {
    let e = engine().await;
    owner(&e).await;
    let r = acquire(&e, None, "wa-owner", seed_dir()).await;
    assert_eq!(
        r.err(),
        Some(CapsuleRefusal::NotSignedIn),
        "an unauthenticated caller must not obtain a capsule that signs as the owner"
    );
}

/// An empty/whitespace bearer is not a session either. Worth its own case
/// because `Some("")` is a different code path from `None` and reads as
/// "presented a token".
#[tokio::test]
async fn an_empty_bearer_is_not_a_session() {
    let e = engine().await;
    owner(&e).await;
    for token in ["", "   "] {
        let r = acquire(&e, Some(token), "wa-owner", seed_dir()).await;
        assert_eq!(
            r.err(),
            Some(CapsuleRefusal::NotSignedIn),
            "a blank bearer ({token:?}) must not read as a session"
        );
    }
}

/// An unresolvable token is refused rather than treated as anonymous-but-ok.
#[tokio::test]
async fn an_unknown_token_is_refused() {
    let e = engine().await;
    owner(&e).await;
    let r = acquire(&e, Some("sess:not-a-real-token"), "wa-owner", seed_dir()).await;
    assert!(
        matches!(
            r.err(),
            Some(CapsuleRefusal::NotSignedIn) | Some(CapsuleRefusal::Unavailable(_))
        ),
        "an unresolvable bearer must never yield a capsule"
    );
}

/// **The refusals are DISTINCT, which is the point of typing them.**
///
/// "You are not the owner" and "you are acting FOR the owner" need different
/// remedies: the first tells a human to sign in as the owner, the second tells
/// them the act is not delegatable at all. Collapsing them would send a delegate
/// to fetch a session they already hold.
#[test]
fn the_refusals_say_different_things() {
    let msgs = [
        CapsuleRefusal::NotSignedIn.to_string(),
        CapsuleRefusal::NotTheOwner.to_string(),
        CapsuleRefusal::Delegated.to_string(),
        CapsuleRefusal::NoFedIdentity.to_string(),
    ];
    for (i, a) in msgs.iter().enumerate() {
        for (j, b) in msgs.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a, b,
                    "two refusals render identically — an operator cannot act on that"
                );
            }
        }
    }
    assert!(
        CapsuleRefusal::Delegated.to_string().contains("outlives"),
        "the delegated refusal must say WHY it is refused and not merely that it is: \
         the signature outlives the delegation, which is the whole reason this case \
         is separate from NotTheOwner"
    );
}

/// **The capsule exposes no key material.**
///
/// A source-level assertion, because the property is about what does NOT exist.
/// No accessor, no `Deref`, no serialization — the only way out is a signature.
/// If someone adds one, this fails and the reviewer has to argue for it.
#[test]
fn the_capsule_exposes_no_key_material() {
    let src = include_str!("../src/owner_signer_capsule.rs");
    let start = src
        .find("impl OwnerSignerCapsule")
        .expect("the capsule impl must exist");
    let body = &src[start..];

    for leak in [
        "pub fn signer",
        "pub fn into_signer",
        "pub fn secret",
        "pub fn seed",
        "impl Deref",
        "derive(Serialize",
    ] {
        assert!(
            !body.contains(leak),
            "OwnerSignerCapsule grew `{leak}` — this capsule exists precisely so the \
             owner's fed-ID is NEVER released. Releasing it on demand would be \
             strictly worse than the gap this closes, which is why the requesting \
             issue asked for a capsule rather than an accessor."
        );
    }
}

/// **The delegation check runs BEFORE the role check.**
///
/// Order is load-bearing and invisible at runtime: a `dgrant:` token carries the
/// owner's role and FullAccess, so if the role check came first and a later
/// refactor dropped the actor check, a delegate would pass silently. Refusing
/// the actor first means the strongest condition cannot be lost by reordering.
///
/// **This gate was wrong first, and the way it was wrong is the lesson.** It
/// searched the WHOLE FILE for `caller.actor.is_some()` — which also appears in
/// the module doc above, explaining the rule. So deleting the actual guard left
/// the prose behind, the search still found it, and the test passed. It was
/// measuring the comment that describes the check rather than the check.
///
/// It now searches only the body of `acquire`, and both mutations are proven to
/// red it: deleting the guard, and swapping the two checks.
#[test]
fn the_delegation_check_precedes_the_role_check() {
    let src = include_str!("../src/owner_signer_capsule.rs");
    let body_start = src
        .find("pub async fn acquire(")
        .expect("the acquire fn must exist");
    let body = &src[body_start..];

    let actor = body.find("caller.actor.is_some()").expect(
        "the DELEGATION guard is gone from acquire(). A `dgrant:` token carries the \
             owner's role and FullAccess, so nothing else refuses a delegate — and a \
             delegate holding this capsule can author the owner's signature, which \
             outlives the delegation that produced it.",
    );
    let role = body
        .find("caller.role != UserRole::SystemAdmin")
        .expect("the role check must exist in acquire()");
    assert!(
        actor < role,
        "the role check now precedes the delegation check inside acquire(). A `dgrant:` \
         token has the owner's role AND FullAccess, so the role check cannot distinguish \
         a delegate — putting it first makes the actor check the droppable one."
    );
}
