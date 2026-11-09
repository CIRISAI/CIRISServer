//! CEG-native build manifests (`src/registry/builds.rs`, CIRISServer#537),
//! against a real SQLite Engine. Ported from CIRISRegistry
//! `tests/build_manifest_fold.rs` at `f04b149`, onto this server's pins.
//!
//! What this file can and cannot show. It shows every refusal, and that verify's
//! own producer emits exactly this door's wire shape. It does NOT show a
//! blessed pipeline being admitted: blessing needs a trust root this node
//! accepts, and minting one takes the accord ceremony (or the `test-anchor`
//! software root). That path is not yet exercised in this repo.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ciris_persist::federation::envelope::EnvelopeCore;
use ciris_persist::federation::types::SignedAttestation;
use ciris_persist::federation::{attestation_emit, EmitAttestationInput, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::registry::builds::{
    build_manifest_dimension, contribution_envelope, BuildFacts, SignedContribution,
};
use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};
use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const NODE: &str = "fold-test-node";
const MANIFEST: &[u8] = br#"{"version":"9.9.9","files":{"ciris_engine/__init__.py":"aa"}}"#;

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[0xD2; 32], format!("{NODE}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                ed25519_dalek::SigningKey::from_bytes(&[0xD1; 32]),
                NODE.to_string(),
                Some(pqc),
                Some(format!("{NODE}-pqc")),
            )),
            "sqlite::memory:",
        )
        .await
        .expect("sqlite engine"),
    )
}

fn facts(manifest: &[u8]) -> BuildFacts {
    BuildFacts {
        target: "python-source-tree".to_string(),
        build_id: "build-1".to_string(),
        binary_hash: "aa".repeat(32),
        binary_version: "9.9.9".to_string(),
        manifest_hash: hex::encode(Sha256::digest(manifest)),
        manifest_size: manifest.len() as u64,
    }
}

/// A self-signed `node` record for `id`: a real key, blessed by nobody.
async fn self_record(id: &HybridSigningIdentity) -> SignedKeyRecord {
    self_record_claiming(id, &[]).await
}

/// The same, with the record CLAIMING `roles` — signed by the key itself, so
/// the claim is backed by nobody.
async fn self_record_claiming(id: &HybridSigningIdentity, roles: &[&str]) -> SignedKeyRecord {
    let m = id.directory_member().expect("member");
    let rec = produce_scrubbed_key_record(
        id,
        ScrubTarget {
            key_id: id.key_id().to_string(),
            pubkey_ed25519_base64: m.ed25519_public_key_base64.clone(),
            pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64.clone().expect("hybrid"),
            identity_type: "node".to_string(),
            roles: roles.iter().map(|r| (*r).to_string()).collect(),
        },
        &chrono::Utc::now().to_rfc3339(),
        None,
        &[],
    )
    .await
    .expect("self record");
    serde_json::from_value(serde_json::to_value(&rec).unwrap()).expect("persist wire shape")
}

/// Stamp `envelope` through persist's emit chokepoint and sign it as `pipeline`.
async fn sign(pipeline: &HybridSigningIdentity, envelope: serde_json::Value) -> SignedContribution {
    let core = EnvelopeCore::from_value(envelope).expect("envelope core");
    let mut input = EmitAttestationInput::with_envelope("scores", core, "federation");
    input.attested_key_id = Some(pipeline.key_id().to_string());
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, pipeline.key_id(), chrono::Utc::now())
            .expect("stamp");
    let (ed, pqc) = pipeline.sign_bound(&canonical).await.expect("sign");
    SignedContribution {
        signed_envelope: input.attestation_envelope.to_value(),
        ed25519_signature_base64: ed,
        mldsa65_signature_base64: pqc,
    }
}

fn body(c: &SignedContribution, manifest: &[u8], record: Option<&SignedKeyRecord>) -> String {
    serde_json::json!({
        "contribution": c,
        "manifest_base64": base64::engine::general_purpose::STANDARD.encode(manifest),
        "pipeline_record": record,
    })
    .to_string()
}

async fn post(engine: &Arc<Engine>, body: String) -> (StatusCode, serde_json::Value) {
    let app = ciris_server::registry::router(Arc::clone(engine), NODE.to_string());
    let req = Request::post("/v1/builds")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// Every build-manifest row `key` authored, through persist's bounded query
/// (the unbounded read is test-build-only since persist v56). Narrowed to the
/// family: since persist v57 registering a key writes a `key:record:v1` row
/// under the key's own name, which is not a Contribution.
async fn rows_by(
    engine: &Arc<Engine>,
    key: &str,
) -> Vec<ciris_persist::federation::types::Attestation> {
    use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    let dir = engine.federation_directory();
    let mut pages = AttestationQuery::by(key, FOLD_PAGE)
        .dimension_prefix("provenance:build_manifest:")
        .pages();
    let mut out = Vec::new();
    while let Some(rows) = pages.next(dir.as_ref()).await.expect("paged read") {
        out.extend(rows);
    }
    out
}

async fn get(engine: &Arc<Engine>, uri: &str) -> StatusCode {
    let app = ciris_server::registry::router(Arc::clone(engine), NODE.to_string());
    app.oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// The load-bearing refusal. A real key, a valid signature, a matching
/// manifest, and no blessing: the door refuses and stores nothing.
#[tokio::test]
async fn a_valid_signature_from_an_unblessed_pipeline_is_refused_and_nothing_is_stored() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-unblessed").unwrap();
    let record = self_record(&pipeline).await;
    let c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;

    let (status, json) = post(&engine, body(&c, MANIFEST, Some(&record))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    assert_eq!(json["error"], "pipeline_not_blessed");

    let rows = rows_by(&engine, "ci-unblessed").await;
    assert!(rows.is_empty(), "a refused Contribution must not be stored");
    assert_eq!(
        get(&engine, "/v1/builds/9.9.9").await,
        StatusCode::NOT_FOUND
    );
    let sha = facts(MANIFEST).manifest_hash;
    assert_eq!(
        get(&engine, &format!("/v1/builds/manifest/{sha}")).await,
        StatusCode::NOT_FOUND,
        "the manifest bytes of a refused Contribution must not be served"
    );
}

/// The accord-role authority reads a role off the stored key record, so the
/// thing that must not work is a key writing that role onto its own record.
/// persist's admission gate is the enforcement point; this pins that the door
/// inherits it and does not admit a build on a self-declared role.
#[tokio::test]
async fn a_pipeline_that_declares_its_own_infra_attest_role_is_not_blessed() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-self-declared").unwrap();
    let record = self_record_claiming(&pipeline, &["infra:attest"]).await;
    let c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;

    let (status, json) = post(&engine, body(&c, MANIFEST, Some(&record))).await;
    assert_ne!(
        status,
        StatusCode::CREATED,
        "a self-declared role bought a build: {json}"
    );
    assert!(
        json["error"] == "unknown_pipeline" || json["error"] == "pipeline_not_blessed",
        "expected the record or the blessing to be refused, got {json}"
    );
    assert_eq!(
        get(&engine, "/v1/builds/9.9.9").await,
        StatusCode::NOT_FOUND
    );
}

/// The read re-checks. A row that reached the directory some other way (here:
/// written straight through persist, as anti-entropy would) from an unblessed
/// pipeline is not a build.
#[tokio::test]
async fn an_unblessed_row_already_in_the_directory_is_not_served() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-replicated").unwrap();
    let directory = engine.federation_directory();
    directory
        .put_public_key(self_record(&pipeline).await)
        .await
        .expect("key");

    let core = EnvelopeCore::from_value(contribution_envelope(&facts(MANIFEST))).unwrap();
    let mut input = EmitAttestationInput::with_envelope("scores", core, "federation");
    input.attested_key_id = Some(pipeline.key_id().to_string());
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, pipeline.key_id(), chrono::Utc::now())
            .unwrap();
    let (ed, pqc) = pipeline.sign_bound(&canonical).await.unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let sig = ciris_crypto::HybridSignature {
        crypto_kind: ciris_crypto::CRYPTO_KIND_CIRIS_V1,
        classical: ciris_crypto::TaggedClassicalSignature {
            algorithm: ciris_crypto::ClassicalAlgorithm::Ed25519,
            signature: b64.decode(ed).unwrap(),
            public_key: Vec::new(),
        },
        pqc: ciris_crypto::TaggedPqcSignature {
            algorithm: ciris_crypto::PqcAlgorithm::MlDsa65,
            signature: b64.decode(pqc).unwrap(),
            public_key: Vec::new(),
        },
        mode: ciris_crypto::SignatureMode::HybridRequired,
    };
    let (row, _) =
        attestation_emit::assemble(pipeline.key_id().to_string(), &canonical, sig, input).unwrap();
    directory
        .put_attestation(SignedAttestation { attestation: row })
        .await
        .expect("persist admits it");
    assert_eq!(rows_by(&engine, "ci-replicated").await.len(), 1);

    assert_eq!(
        get(&engine, "/v1/builds/9.9.9").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_manifest_that_does_not_hash_to_the_attested_value_is_refused() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-swap").unwrap();
    let c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;
    let (status, json) =
        // Same length, different bytes: the size check passes, the hash does not.
        post(&engine, body(&c, &MANIFEST.to_ascii_uppercase(), Some(&self_record(&pipeline).await))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "manifest_hash_mismatch");
}

/// Size is checked before the hash (CC 5.3.2.5).
#[tokio::test]
async fn a_manifest_of_the_wrong_length_is_refused_before_it_is_hashed() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-size").unwrap();
    let mut f = facts(MANIFEST);
    f.manifest_size += 1;
    let c = sign(&pipeline, contribution_envelope(&f)).await;
    let (status, json) = post(
        &engine,
        body(&c, MANIFEST, Some(&self_record(&pipeline).await)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "manifest_size_mismatch");
}

#[tokio::test]
async fn an_envelope_altered_after_signing_is_refused() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-tamper").unwrap();
    let mut c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;
    c.signed_envelope["build"]["binary_hash"] = serde_json::json!("00".repeat(32));
    let (status, json) = post(
        &engine,
        body(&c, MANIFEST, Some(&self_record(&pipeline).await)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["error"], "signature_invalid");
}

#[tokio::test]
async fn a_pipeline_this_node_has_never_seen_is_refused_by_name() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-stranger").unwrap();
    let c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;
    let (status, json) = post(&engine, body(&c, MANIFEST, None)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "unknown_pipeline");
}

/// A key record for someone else cannot be used to introduce a signer.
#[tokio::test]
async fn a_pipeline_record_for_a_different_key_is_refused() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-a").unwrap();
    let other = HybridSigningIdentity::generate("ci-b").unwrap();
    let c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;
    let (status, json) = post(
        &engine,
        body(&c, MANIFEST, Some(&self_record(&other).await)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "contribution_malformed");
}

/// The dimension must name the build's own target, with the version segment.
#[tokio::test]
async fn a_dimension_for_another_target_is_refused() {
    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-dim").unwrap();
    let mut env = contribution_envelope(&facts(MANIFEST));
    env["dimension"] = serde_json::json!(build_manifest_dimension("ios-mobile-bundle"));
    let c = sign(&pipeline, env).await;
    let (status, json) = post(
        &engine,
        body(&c, MANIFEST, Some(&self_record(&pipeline).await)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "dimension_mismatch");
}

/// Verify's own producer is the wire shape (CIRISVerify#299, fixed in 19.0.0):
/// a `row` mirror, the `:v1` dimension, `manifest_size`. Its output goes
/// through this door unchanged and reaches the blessing check, which is the
/// last one. Measured here so a producer-side regression says so.
#[tokio::test]
async fn verifys_own_contribution_passes_the_door_up_to_the_blessing() {
    use ciris_verify_core::manifest_contribution::{
        sign_build_manifest_contribution, BuildAttestation,
    };

    let engine = engine().await;
    let pipeline = HybridSigningIdentity::generate("ci-verify-shape").unwrap();
    let f = facts(MANIFEST);
    let obj = sign_build_manifest_contribution(
        &pipeline,
        &BuildAttestation {
            target: &f.target,
            binary_hash: &f.binary_hash,
            build_id: &f.build_id,
            binary_version: &f.binary_version,
            manifest_hash: &f.manifest_hash,
            manifest_size: f.manifest_size,
        },
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let env = obj.body["signed_envelope"].clone();
    assert!(
        EnvelopeCore::from_value(env.clone()).unwrap().row.is_some(),
        "row mirror"
    );
    assert_eq!(env["dimension"], build_manifest_dimension(&f.target));

    let c: SignedContribution =
        serde_json::from_value(obj.body.clone()).expect("verify's body IS the wire shape");
    let (status, json) = post(
        &engine,
        body(&c, MANIFEST, Some(&self_record(&pipeline).await)),
    )
    .await;
    // Size, hash, dimension, mirror and the hybrid signature all passed: the
    // only refusal left is the one a self-signed record earns.
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    assert_eq!(json["error"], "pipeline_not_blessed");
}

/// persist's canonical bytes are JCS, which is what lets a verify `SelfSigner`
/// sign a persist-stamped envelope without a second canonicalizer.
#[tokio::test]
async fn persists_canonical_bytes_are_jcs() {
    let pipeline = HybridSigningIdentity::generate("ci-jcs").unwrap();
    let c = sign(&pipeline, contribution_envelope(&facts(MANIFEST))).await;
    assert_eq!(
        attestation_emit::canonicalize(&c.signed_envelope).unwrap(),
        ciris_verify_core::jcs::canonicalize(&c.signed_envelope).unwrap()
    );
}

/// The surface follows the role gate: a node the accord did not confer the
/// slice on mounts none of it, so `/v1/builds` is a route it does not serve.
#[tokio::test]
async fn an_unconferred_node_does_not_mount_the_builds_surface() {
    let engine = engine().await;
    let slice = ciris_server::registry_slice::resolve(&engine, NODE, true).await;
    assert!(
        !slice.serves(),
        "premise: a fresh node is not conferred: {slice:?}"
    );
    let app = ciris_server::registry::router_if_conferred(&slice, Arc::clone(&engine), NODE.into());
    for (method, uri) in [("POST", "/v1/builds"), ("GET", "/v1/builds/9.9.9")] {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let status = app.clone().oneshot(req).await.unwrap().status();
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {uri} on an unconferred node"
        );
    }
}
