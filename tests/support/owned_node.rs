//! **A claimed node with a signed-in PERSON, in-process** — the fixture the
//! household and self-device suites share (`tests/family_crud.rs`,
//! `tests/self_node_release.rs`).
//!
//! Each [`Person`] is a whole node: its own in-memory substrate keyed by its own
//! hybrid node signer, an owner whose fed-ID is MINTED (a real Ed25519 half and
//! a sealed ML-DSA-65 half under a unique alias — the route opens that pen off
//! disk to sign, so a directory row with no custody behind it would sign
//! nothing), the owner-binding the claim writes, and an owner session. The
//! routes run through the real router with `tower::ServiceExt::oneshot`.
//!
//! Two people are two nodes, as in production: Alice's session can only ever
//! author as Alice. A family row reaches Bob's node the way replication would
//! carry it — the SIGNED row, re-admitted through the same persist door a
//! peer's apply uses ([`Person::receive_families_from`]).
//!
//! NB: files under `tests/support/` are not auto-compiled as test binaries; each
//! suite pulls this in with an explicit `#[path]`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::identity::UserIdentityBackend;

/// One `CIRIS_HOME` for the whole test binary — the mint seals the ML-DSA half
/// under `keys_dir()`, which hangs off it. Set ONCE (tests run in parallel);
/// what keeps two owners apart is the per-person ALIAS.
fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "ciris-owned-node-home-{}-{}",
            std::process::id(),
            env!("CARGO_CRATE_NAME")
        ));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

/// The owner's minted fed-ID, as the route will re-open it.
pub struct OwnerIdentity {
    pub alias: String,
    pub key_id: String,
    pub seed_dir: PathBuf,
    pub pubkey_ed25519_base64: String,
    pub pubkey_ml_dsa_65_base64: String,
}

impl OwnerIdentity {
    /// Mint under an alias unique to this process AND call — a per-process name
    /// alone is one name for every parallel test thread.
    async fn mint(name: &str) -> Self {
        static NTH: AtomicU32 = AtomicU32::new(0);
        // The keyring's per-directory master key is created on first use; two
        // mints racing it leave one blob unopenable. Serialize the mint only.
        static MINT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _minting = MINT.lock().await;
        let alias = format!(
            "{name}-{}-{}",
            std::process::id(),
            NTH.fetch_add(1, Ordering::Relaxed)
        );
        let seed_dir = ciris_home().join(&alias);
        std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
        let minted = ciris_server::identity::mint_user_identity(
            UserIdentityBackend::Software,
            &alias,
            Some(name),
            seed_dir.clone(),
            ciris_server::identity::ActiveAlias::Adopt,
        )
        .await
        .expect("mint the owner's fed-ID");
        Self {
            alias,
            key_id: minted.key_id,
            seed_dir,
            pubkey_ed25519_base64: minted.pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64: minted.pubkey_ml_dsa_65_base64,
        }
    }

    /// The owner's own signer, re-opened from the SAME custody the route reads.
    pub async fn signer(&self) -> LocalSigner {
        ciris_server::identity::hardware_user_signers(
            UserIdentityBackend::Software,
            &self.alias,
            self.seed_dir.clone(),
        )
        .await
        .expect("re-open the owner's minted fed-ID")
        .0
    }

    /// The owner's key record, as a registration any node can hold.
    pub fn key_record(&self) -> SignedKeyRecord {
        user_record(
            &self.key_id,
            &self.pubkey_ed25519_base64,
            &self.pubkey_ml_dsa_65_base64,
        )
    }
}

pub fn user_record(key_id: &str, ed_b64: &str, pqc_b64: &str) -> SignedKeyRecord {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
    SignedKeyRecord {
        record: KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: ed_b64.to_string(),
            pubkey_ml_dsa_65_base64: Some(pqc_b64.to_string()),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::USER.into(),
            identity_ref: key_id.to_string(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        },
    }
}

/// An in-memory substrate keyed by a fresh hybrid node signer.
async fn node_engine() -> Arc<Engine> {
    static SEED: AtomicU8 = AtomicU8::new(0x10);
    let s = SEED.fetch_add(2, Ordering::Relaxed);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[s.wrapping_add(1); 32], "node-pqc".to_string())
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[s; 32]),
        "ciris-server".to_string(),
        Some(pqc),
        Some("node-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// A node, its owner, and the owner's session.
pub struct Person {
    pub name: String,
    pub engine: Arc<Engine>,
    pub owner: OwnerIdentity,
    pub node_key_id: String,
    /// The owner's session bearer on THIS node.
    pub bearer: String,
    wa_id: String,
}

impl Person {
    /// A claimed node for `name`: node key registered as a NODE, owner fed-ID
    /// minted and registered, the owner-binding `delegates_to(owner → node)`
    /// signed with the owner's pen, and an owner session.
    ///
    /// The binding is placed at FEDERATION tier (`emit_steward_binding`), i.e.
    /// this node is ANNOUNCED. [`Self::new_unannounced`] is the claim as the
    /// wizard leaves it when the person opts out of announcing.
    pub async fn new(name: &str) -> Self {
        Self::new_placed(name, true).await
    }

    /// A claimed node whose owner did NOT announce it: the owner-binding at
    /// `cohort_scope: self`, as the claim writes it (CIRISServer#655 / #673).
    pub async fn new_unannounced(name: &str) -> Self {
        Self::new_placed(name, false).await
    }

    async fn new_placed(name: &str, announced: bool) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "ciris_server=warn".into()),
            )
            .with_test_writer()
            .try_init();
        let engine = node_engine().await;
        let node_key_id = engine
            .local_derived_key_id()
            .await
            .expect("derive the node key id");
        ciris_server::attest::register_key(
            &engine,
            ciris_server::attest::KeySigner::Engine(&engine),
            &node_key_id,
            identity_type::NODE,
            serde_json::Value::Null,
        )
        .await
        .expect("register the node key");
        let owner = OwnerIdentity::mint(name).await;
        engine
            .federation_directory()
            .put_public_key(owner.key_record())
            .await
            .expect("register the owner's key");
        if announced {
            let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
                .iter()
                .map(|s| s.to_string())
                .collect();
            ciris_server::auth::ownership::emit_steward_binding(
                &engine,
                &owner.signer().await,
                &node_key_id,
                &scopes,
            )
            .await
            .expect("emit the owner-binding");
        } else {
            bind_self_scoped(&engine, &owner.signer().await, &node_key_id).await;
        }
        let wa_id = format!("wa-{}", owner.alias);
        let bearer = mint_session(&engine, &wa_id, WaRole::Root).await;
        Self {
            name: name.to_string(),
            engine,
            owner,
            node_key_id,
            bearer,
            wa_id,
        }
    }

    pub fn key(&self) -> &str {
        &self.owner.key_id
    }

    /// The routes under test, over THIS node.
    pub fn router(&self) -> Router {
        ciris_server::family_api::router(Arc::clone(&self.engine), self.owner.seed_dir.clone())
            .merge(ciris_server::self_devices::router(
                Arc::clone(&self.engine),
                self.owner.seed_dir.clone(),
            ))
            .merge(ciris_server::auth::occurrence::router(
                Arc::clone(&self.engine),
                ciris_persist::prelude::HybridPolicy::Strict,
            ))
    }

    /// Register `other`'s owner key here, as a Key round would.
    pub async fn knows(&self, other: &Person) {
        self.engine
            .federation_directory()
            .put_public_key(other.owner.key_record())
            .await
            .expect("register another person's key");
    }

    /// A session on this node that is NOT the owner's (an OBSERVER).
    pub async fn stranger_session(&self) -> String {
        mint_session(
            &self.engine,
            &format!("{}-guest", self.wa_id),
            WaRole::Observer,
        )
        .await
    }

    /// A DELEGATED session (`dgrant:`) for this node's owner — the owner's role
    /// and FullAccess, but `actor` set. The durable `delegates_to(owner → actor)`
    /// edge is emitted first: `resolve_bearer` re-checks it on every use.
    pub async fn delegated_session(&self) -> String {
        const SCOPE: &str = "owner:act-on-behalf";
        let client_id = format!("{}-helper", self.owner.alias);
        // A REAL key: the delegate is a registered identity the edge names.
        let ed = SigningKey::from_bytes(&[0x77; 32]);
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[0x78; 32], format!("{client_id}-pqc"))
            .expect("delegate ML-DSA seed");
        use ciris_keyring::PqcSigner as _;
        let client = user_record(
            &client_id,
            &BASE64.encode(ed.verifying_key().to_bytes()),
            &BASE64.encode(pqc.public_key().await.expect("delegate ML-DSA pk")),
        );
        self.engine
            .federation_directory()
            .put_public_key(client)
            .await
            .expect("register the delegate's key");
        ciris_server::auth::ownership::emit_signed_attestation(
            &self.engine,
            &self.owner.signer().await,
            ciris_persist::federation::types::attestation_type::DELEGATES_TO,
            &client_id,
            ciris_persist::federation::delegates_to_envelope(
                &client_id,
                &[SCOPE.to_string()],
                false,
            ),
            None,
        )
        .await
        .expect("emit delegates_to(owner -> actor)");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        ciris_server::auth::session::register_delegated_grant(
            ciris_server::auth::session::DelegatedGrant {
                owner_wa_id: self.wa_id.clone(),
                owner_role: ciris_server::auth::roles::UserRole::SystemAdmin,
                owner_key_id: self.owner.key_id.clone(),
                client_id,
                scope: SCOPE.to_string(),
                expires_at: now + 600,
                issued_at: now,
                purpose: Some("a helper".to_string()),
                attestation_id: None,
                constraints: ciris_server::auth::session::DelegationConstraints::default(),
            },
        )
    }

    /// Carry every SIGNED family row and membership removal `from` holds onto
    /// this node, through the same persist doors a replication apply uses. A
    /// row this node already holds is skipped (that is persist's answer too —
    /// `put_family` is an INSERT; see FSD §3.5).
    pub async fn receive_families_from(&self, from: &Person) {
        let src = from.engine.federation_directory();
        let dst = self.engine.federation_directory();
        for served in src
            .list_signed_families_since(None, u32::MAX)
            .await
            .expect("list signed families")
        {
            let id = served.family.family.family_key_id.clone();
            if dst.lookup_family(&id).await.expect("lookup").is_none() {
                dst.put_family(served.family).await.unwrap_or_else(|e| {
                    panic!("{} admits {id} from {}: {e}", self.name, from.name)
                });
            }
        }
        for served in src
            .list_signed_family_membership_revocations_since(None, u32::MAX)
            .await
            .expect("list signed family removals")
        {
            let _ = dst
                .put_family_membership_revocation(served.revocation)
                .await;
        }
    }

    /// One request through the router, as this node's owner (or `bearer`).
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        self.call_on(self.router(), method, path, bearer, body)
            .await
    }

    /// [`Self::call`] through a router the suite composed itself (a surface
    /// [`Self::router`] does not merge, e.g. contacts).
    pub async fn call_on(
        &self,
        router: Router,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&v).expect("json"))
            }
            None => Body::empty(),
        };
        let resp = router
            .oneshot(req.body(body).expect("request"))
            .await
            .expect("route");
        let status = resp.status();
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("body")
            .to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
            })
        };
        (status, json)
    }

    /// As the owner.
    pub async fn as_owner(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let bearer = self.bearer.clone();
        self.call(method, path, Some(&bearer), body).await
    }
}

/// The owner-binding `delegates_to(owner → node)` at `cohort_scope: self` —
/// the claim's own placement, before any announce — signed by the owner and
/// applied through the claim's door.
pub async fn bind_self_scoped(engine: &Engine, owner: &LocalSigner, node_key_id: &str) {
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let self_scope = ciris_persist::federation::types::cohort_scope::SELF;
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        owner,
        node_key_id,
        &scopes,
        self_scope,
    )
    .await
    .expect("the owner signs a self-scoped owner-binding");
    ciris_server::auth::ownership::apply_signed_owner_binding(
        engine,
        node_key_id,
        self_scope,
        ciris_persist::prelude::HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("apply the self-scoped owner-binding");
}

/// An active `wa_cert` + a bound session bearer on `engine`.
pub async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!([]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Session,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await.expect("mint wa_cert");
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
}

/// Assert a refusal's status AND its stable id.
#[track_caller]
pub fn assert_refused(got: &(StatusCode, serde_json::Value), status: u16, id: &str) {
    assert_eq!(
        (got.0.as_u16(), got.1["reason_id"].as_str()),
        (status, Some(id)),
        "expected {status} {id}, got {} {}",
        got.0,
        got.1
    );
}
