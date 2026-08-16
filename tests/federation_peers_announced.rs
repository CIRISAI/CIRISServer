//! **A peer you have HEARD must appear, and must not be dressed as one you
//! have ADMITTED** (CIRISServer#289).
//!
//! edge has been writing announced-peer bookmarks all along —
//! `reticulum.rs record_announced_peer`, whose own comment names
//! `GET /v1/federation/peers` as the intended consumer (CIRISEdge#362) — and
//! nothing on this side ever read them. A node this one had heard announce, but
//! never admitted, was simply invisible: the operator saw an empty list while
//! the store held the evidence.
//!
//! The failure mode this guards against is the OPPOSITE one, though. A bookmark
//! carries no provenance: anyone can emit an announce. Rendering it as an
//! ordinary peer would manufacture standing out of hearsay, so it must project
//! `canonical=false` with `trust="unknown"`, and an admitted key for the same
//! `key_id` must WIN — the row with provenance beats the row without.
//!
//! Drives the real `collect_peers` path through `federation_peers::router`.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::algorithm;
use ciris_persist::federation::{KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::federation_peers;
use ed25519_dalek::SigningKey;

const NODE_KEY_ID: &str = "ciris-server";
const HEARD_KEY_ID: &str = "peer-heard-not-admitted";

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xC1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// Record an announce the way edge does.
async fn record_announce(engine: &Engine, key_id: &str) {
    engine
        .federation_directory()
        .record_announced_peer(
            key_id,
            &base64_pub(0xD1),
            None,
            Some("node"),
            chrono::Utc::now(),
        )
        .await
        .expect("record_announced_peer");
}

fn base64_pub(seed: u8) -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    B64.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

/// Admit a key for real, so the anti-join can be observed rather than assumed.
async fn admit(engine: &Engine, key_id: &str) {
    let now = chrono::Utc::now();
    let ed = base64_pub(0xD1);
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: "node".to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "ab".repeat(32),
        scrub_signature_classical: ed,
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
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
        .expect("put_public_key");
}

/// Serve the real router on an ephemeral port and GET the peer list, so this
/// exercises the production path rather than a private helper.
async fn list_peers(engine: Arc<Engine>) -> Vec<serde_json::Value> {
    let app = federation_peers::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let _h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let body: serde_json::Value = reqwest::get(format!("http://{addr}/v1/federation/peers"))
        .await
        .expect("GET /v1/federation/peers")
        .json()
        .await
        .expect("peers json");
    body.get("peers")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_else(|| panic!("no `peers` array in {body}"))
}

fn field<'a>(p: &'a serde_json::Value, k: &str) -> &'a serde_json::Value {
    p.get(k).unwrap_or(&serde_json::Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_announced_peer_is_listed_as_unknown_and_not_canonical() {
    let engine = node().await;
    record_announce(&engine, HEARD_KEY_ID).await;

    let peers = list_peers(Arc::clone(&engine)).await;

    let heard = peers
        .iter()
        .find(|p| field(p, "key_id") == HEARD_KEY_ID)
        .unwrap_or_else(|| {
            panic!(
                "the announced peer is missing from the listing. edge recorded the \
                 bookmark; if nothing reads it, a node you have heard announce is \
                 invisible to the operator while the store holds the evidence — which \
                 is CIRISServer#289. Got: {peers:?}"
            )
        });

    assert!(
        field(heard, "canonical") == false,
        "an ANNOUNCED peer rendered as canonical. Announces are unverified — anyone \
         can emit one — so this would manufacture founding-server standing out of \
         hearsay."
    );
    assert_eq!(
        field(heard, "trust"),
        "unknown",
        "an announced peer must read `unknown`, not `trusted`. A bookmark carries no \
         provenance; presenting it at the same trust as an admitted key erases the \
         distinction the operator is being asked to act on."
    );
    assert!(
        !field(heard, "last_seen").is_null(),
        "the liveness signal was dropped — `last_seen_at` is the one thing a bookmark \
         has that an admitted row does not, and it is why the row is worth showing."
    );
}

/// **Admission wins.** Verified against persist rather than assumed: the same
/// `key_id` must appear exactly once, as the admitted row.
#[tokio::test(flavor = "multi_thread")]
async fn an_admitted_key_supersedes_its_own_announce_bookmark() {
    let engine = node().await;
    record_announce(&engine, HEARD_KEY_ID).await;
    admit(&engine, HEARD_KEY_ID).await;

    let peers = list_peers(Arc::clone(&engine)).await;

    let matching: Vec<_> = peers
        .iter()
        .filter(|p| field(p, "key_id") == HEARD_KEY_ID)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "the same peer appeared {} times — once admitted and once as its own stale \
         announce bookmark. A duplicated peer is worse than a missing one: the \
         operator cannot tell which row is authoritative. Got: {peers:?}",
        matching.len()
    );
    assert_ne!(
        field(matching[0], "trust"),
        "unknown",
        "the bookmark won over the admitted key. The row WITH provenance must beat the \
         row without, or admitting a peer would visibly downgrade it."
    );
}
