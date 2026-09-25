// The drive's in-process fixture, `include!`d by `tests/drive_crud.rs` and
// `tests/drive_split_viewer_key.rs` (two binaries because the split test sets
// the process-global WIRE identity, which no single-identity test may share).
//
// Nothing under test is stubbed: an in-memory substrate keyed by a hybrid node
// signer, an owner whose fed-ID is MINTED onto disk the way `POST
// /v1/self/identity` mints one (a file is signed with the person's pen), an
// owner-binding emitted by that pen, a real session bearer, and the real
// `drive::router` on a bound TCP listener.

#[allow(unused_imports)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[allow(unused_imports)]
use base64::Engine as _;
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::identity::UserIdentityBackend;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

pub const NODE_ALIAS: &str = "ciris-server";

/// This node: in-memory substrate, HYBRID node signer (0xA1 / 0xA2).
pub async fn node_engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_ALIAS}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
        NODE_ALIAS.to_string(),
        Some(pqc),
        Some(format!("{NODE_ALIAS}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// The engine's edge signer — the SAME two halves under the DERIVED id, which
/// is what compose hands `drive::router` (`chat_node_signer`).
pub async fn node_edge_signer(engine: &Engine) -> Arc<ciris_edge::identity::LocalSigner> {
    let key_id = engine.local_derived_key_id().await.expect("derived id");
    edge_signer_for(&key_id, 0xA1, 0xA2)
}

/// An edge signer for any seeded identity.
pub fn edge_signer_for(
    key_id: &str,
    ed_seed: u8,
    pqc_seed: u8,
) -> Arc<ciris_edge::identity::LocalSigner> {
    Arc::new(ciris_edge::identity::LocalSigner::new(
        key_id.to_owned(),
        Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[ed_seed; 32], key_id)
                .expect("ed25519 signer"),
        ),
        Some(Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
                .expect("pqc half"),
        )),
    ))
}

/// Register the node's own key as a NODE, the way compose's boot does.
pub async fn register_self(engine: &Engine) -> String {
    let key_id = engine.local_derived_key_id().await.expect("derived id");
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register node key");
    key_id
}

/// Seed a hybrid key record straight into the directory.
pub async fn seed_key(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8, kind: &str) {
    let ed = SigningKey::from_bytes(&[ed_seed; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
        .expect("ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: kind.into(),
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
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("seed key {key_id}: {e}"));
}

/// One `CIRIS_HOME` per test binary (the ML-DSA seal lives under it).
pub fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ciris-drive-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

/// The owner's fed-ID, actually held on disk — see `tests/contacts_chat.rs`
/// `OwnerIdentity` for why a directory row alone cannot sign a file.
pub struct OwnerIdentity {
    pub alias: String,
    pub key_id: String,
    pub seed_dir: PathBuf,
    pub pubkey_ed25519_base64: String,
    pub pubkey_ml_dsa_65_base64: String,
}

impl OwnerIdentity {
    pub async fn mint() -> Self {
        static NTH: AtomicU32 = AtomicU32::new(0);
        // Serialized: the software seal's per-directory master key races when
        // several tests create it at once (see contacts_chat's note).
        static MINT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _minting = MINT.lock().await;
        let alias = format!(
            "drive-owner-{}-{}",
            std::process::id(),
            NTH.fetch_add(1, Ordering::Relaxed)
        );
        let seed_dir = ciris_home().join(&alias);
        std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
        let minted = ciris_server::identity::mint_user_identity(
            UserIdentityBackend::Software,
            &alias,
            Some("Drive Owner"),
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
}

/// Register the owner's key and bind them as responsible for `node`.
pub async fn bind_owner(engine: &Engine, owner: &OwnerIdentity, node: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": owner.key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: owner.key_id.clone(),
        pubkey_ed25519_base64: owner.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: Some(owner.pubkey_ml_dsa_65_base64.clone()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: owner.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the owner's user key");
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(engine, &owner.signer().await, node, &scopes)
        .await
        .expect("emit owner-binding delegates_to(user -> node)");
}

/// An active `wa_cert` + a session bearer.
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
    ciris_server::auth::store::upsert(engine, cert)
        .await
        .expect("mint wa_cert");
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
}

/// A DELEGATED bearer for the owner — the owner-signed `delegates_to` edge the
/// session re-checks on every use, then the in-memory grant.
pub async fn mint_delegated_token(
    engine: &Engine,
    owner: &OwnerIdentity,
    owner_wa_id: &str,
    client_id: &str,
) -> String {
    use ciris_persist::federation::types::attestation_type;
    const SCOPE: &str = "owner:act-on-behalf";
    // The delegate is a registered key in its own right, as a real agent is:
    // the `delegates_to` edge names it, and persist refuses an edge to nobody.
    seed_key(engine, client_id, 0x5A, 0x5B, identity_type::AGENT).await;
    ciris_server::auth::ownership::emit_signed_attestation(
        engine,
        &owner.signer().await,
        attestation_type::DELEGATES_TO,
        client_id,
        ciris_persist::federation::delegates_to_envelope(client_id, &[SCOPE.to_string()], false),
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
            owner_wa_id: owner_wa_id.to_string(),
            owner_role: ciris_server::auth::roles::UserRole::SystemAdmin,
            owner_key_id: owner.key_id.clone(),
            client_id: client_id.to_string(),
            scope: SCOPE.to_string(),
            expires_at: now + 600,
            issued_at: now,
            purpose: Some("a helper the owner delegated to".to_string()),
            attestation_id: None,
            constraints: ciris_server::auth::session::DelegationConstraints::default(),
        },
    )
}

/// Serve the drive router on an ephemeral port.
pub async fn serve_drive(
    engine: Arc<Engine>,
    node_signer: Arc<ciris_edge::identity::LocalSigner>,
    seed_dir: PathBuf,
) -> String {
    let app = ciris_server::drive::router(engine, node_signer, seed_dir, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ciris_server=warn".into()),
        )
        .with_test_writer()
        .try_init();
}

/// A reqwest response as `(status, json)`, never panicking on a non-JSON body.
pub async fn status_json(resp: reqwest::Response) -> (u16, serde_json::Value) {
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, json)
}
