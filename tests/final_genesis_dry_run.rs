//! **The final genesis, rehearsed** (`FSD/FINAL_GENESIS.md` §3 "Dry run").
//!
//! The ceremony routes driven end to end over HTTP, in process, with three
//! SOFTWARE holders standing in for A1/B1/C1:
//!
//! 1. arm a three-holder test anchor (persist's `test_ceremony_inputs`), so
//!    the compiled roster the plan reads IS those three holders;
//! 2. `POST /plan` with the serve node, the successor set and one recovery
//!    key per holder (all from persist's minter inputs);
//! 3. every holder signs what it owes, round one then round two, through
//!    `POST /sign` with its test seed — the route's software signer;
//! 4. `POST /finish` — persist assembles the ONE bundle and runs
//!    `verify_ceremony_outputs` (the doors a booting node runs);
//! 5. the bundle installs as a node's baked genesis
//!    (`install_test_ceremony_outputs_json`).
//!
//! What this does NOT prove: a real YubiKey signing the items (input sizes),
//! and a fleet adopting the bundle at boot. Those are the hardware test and
//! the native-harness run.
#![cfg(feature = "test-anchor")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use tower::ServiceExt;

fn seeds() -> [[u8; 32]; 3] {
    [[0x11; 32], [0x22; 32], [0x33; 32]]
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(if method == "GET" {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn three_software_holders_mint_the_final_genesis_through_the_routes() {
    // (1) The anchor, armed BEFORE anything reads it.
    let produced_at = chrono::Utc::now();
    let (block, holders, inputs) = ciris_persist::federation::genesis::test_ceremony_inputs(
        &seeds(),
        &[0x44; 32],
        produced_at,
        None,
    )
    .expect("persist's software ceremony inputs");
    for (k, v) in block.env_pairs() {
        std::env::set_var(k, v);
    }
    std::env::set_var("CIRIS_TESTING_MODE", "true");
    let roster = ciris_persist::federation::genesis::effective_accord_holder_records();
    assert_eq!(
        roster.len(),
        3,
        "premise: the armed anchor IS the compiled roster"
    );

    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[0x55; 32]),
                "final-genesis-dry-run".to_string(),
                None,
                None,
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    let home = std::env::temp_dir().join(format!(
        "ciris-final-genesis-{}-{}",
        std::process::id(),
        produced_at.timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let app = ciris_server::accord_provision::router(engine, home.clone());

    // (2) Plan: the serve node as a FULL record (it is not in this directory),
    // the successor set and every holder's recovery key, from persist's inputs.
    // The recovery keys as `POST /recovery-key` records them (read off each
    // spare's hardware in the real ceremony; written directly here), and a plan
    // that names none — it must take the recorded ones.
    std::fs::create_dir_all(home.join("final-genesis")).unwrap();
    std::fs::write(
        home.join("final-genesis").join("recovery-keys.json"),
        serde_json::to_string(&inputs.recovery_keys).unwrap(),
    )
    .unwrap();
    let (s, planned) = call(
        &app,
        "POST",
        "/v1/accord/final-genesis/plan",
        serde_json::json!({
            "serve_nodes": inputs.serve_nodes,
            "successor_keys": inputs.successor_keys,
            "clock_checked": true,
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "plan: {planned}");
    assert_eq!(planned["complete"], false);

    // A second plan without `replace` is refused: one ceremony at a time.
    let (s, _) = call(
        &app,
        "POST",
        "/v1/accord/final-genesis/plan",
        serde_json::json!({
            "serve_nodes": inputs.serve_nodes,
            "successor_keys": inputs.successor_keys,
            "recovery_keys": inputs.recovery_keys,
            "clock_checked": true,
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Finishing early names what is owed.
    let (s, early) = call(
        &app,
        "POST",
        "/v1/accord/final-genesis/finish",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "finish before signing: {early}");

    // (3) Round one: every holder signs the records and rows. Round two opens
    // only once all three have signed the charter.
    let sign = |i: usize| {
        let app = app.clone();
        let key_id = holders[i].key_id.clone();
        async move {
            call(
                &app,
                "POST",
                "/v1/accord/final-genesis/sign",
                serde_json::json!({
                    "key_id": key_id,
                    "mldsa_usb_path": "/unused/in/the/dry/run",
                    "test_holder_seed_b64":
                        base64::engine::general_purpose::STANDARD.encode(seeds()[i]),
                }),
            )
            .await
        }
    };
    for i in 0..3 {
        let (s, out) = sign(i).await;
        assert_eq!(s, StatusCode::OK, "round one, holder {i}: {out}");
    }
    for i in 0..3 {
        let (s, out) = sign(i).await;
        assert_eq!(s, StatusCode::OK, "round two, holder {i}: {out}");
    }
    let (s, status) = call(
        &app,
        "GET",
        "/v1/accord/final-genesis",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(status["complete"], true, "every item signed: {status}");
    let (s, again) = sign(0).await;
    assert_eq!(s, StatusCode::CONFLICT, "nothing left to sign: {again}");

    // (4) Finish: persist assembles and verifies.
    let (s, done) = call(
        &app,
        "POST",
        "/v1/accord/final-genesis/finish",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "finish: {done}");
    assert_eq!(done["verified"]["quorum_verified"], 3, "{done}");
    assert_eq!(done["verified"]["community_key_id"], "ciris-canonical");
    assert_eq!(
        done["verified"]["founders"], 3,
        "the three holders found the community"
    );
    let bundle_path = home.join("final-genesis").join("canonical_seed.json");
    let bundle_json = std::fs::read_to_string(&bundle_path).expect("the bundle is written");

    // (5) The one artifact parses as a v3 bundle carrying both genesis records
    // and installs as a node's baked genesis.
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json).unwrap();
    assert_eq!(
        bundle["version"], 3,
        "bundle v3 (genesis heads inside attestations)"
    );
    let atts = bundle["attestations"].as_array().expect("attestations");
    assert!(
        atts.iter().any(|a| a.get("family").is_some()),
        "the accord family record is in the bundle"
    );
    assert!(
        atts.iter().any(|a| a.get("community").is_some()),
        "the ciris-canonical birth is in the bundle"
    );
    ciris_persist::federation::genesis::install_test_ceremony_outputs_json(&bundle_json)
        .expect("the bundle installs as the baked genesis");

    let _ = std::fs::remove_dir_all(&home);
}
