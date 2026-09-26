//! **`GET /v1/trust-root` reports the node's own acceptance, and the kind in
//! the route's own tokens** (CIRISServer#681).
//!
//! The listing read `accepted` from a `user_accepts` field that persist's
//! `TrustRootVerdict` never had, so every root, including the one the node is
//! entrenched under, read `accepted: false`; and `root_kind` came out as
//! persist's enum spelling (`Family` / `Key`) where the route documents
//! `family` / `key`. Found by CIRISClient's trust-root CSD review.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const NODE_ALIAS: &str = "ciris-node-reading-its-trust-root";

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
    s
}

fn signer_for(alias: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(alias, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(alias, 2), format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .expect("bind subject (#659)");
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: ident.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_root_this_node_accepted_reads_accepted_and_the_kind_is_lowercase() {
    use tower::ServiceExt as _;
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE_ALIAS)), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let node = engine
        .local_derived_key_id()
        .await
        .expect("node derived id");
    register(&engine, &signer_for(NODE_ALIAS), &node, identity_type::NODE).await;
    ciris_server::mesh_genesis::install_baked_trust_root(&engine)
        .await
        .expect("the baked trust root installs");
    let accepted_root = ciris_persist::federation::trust_root::trusted_roots_of(
        engine.federation_directory().as_ref(),
        &node,
        chrono::Utc::now(),
    )
    .await
    .expect("node's roots")
    .first()
    .cloned()
    .expect("premise: the node accepted the baked root");

    let app = ciris_server::trust_root_api::router(Arc::clone(&engine), node.clone());
    let resp = app
        .oneshot(
            axum::http::Request::get("/v1/trust-root")
                // The route is loopback-only; this is what the real listener
                // attaches for a caller on this host.
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    40000,
                ))))
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let roots = v["roots"].as_array().expect("roots");
    let entry = roots
        .iter()
        .find(|r| r["root_key_id"] == accepted_root.as_str())
        .unwrap_or_else(|| panic!("the accepted root is listed: {v}"));
    assert_eq!(
        entry["accepted"], true,
        "the node's own trust edge reaches this root, so it reads accepted: {entry}"
    );
    for r in roots {
        let kind = r["root_kind"].as_str().unwrap_or_default();
        assert!(
            matches!(kind, "family" | "key" | "unreadable"),
            "root_kind is the route's documented token, not persist's enum spelling: {r}"
        );
    }
}
