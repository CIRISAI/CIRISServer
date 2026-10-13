//! The node's ONE absolute halt gate (`src/halt_gate.rs`, CC 4.2.1.1 rc7):
//! while a constitutional halt is in effect, no agent reasoning is admitted
//! through any door. Proven here at the HTTP ingest, with the same latch the
//! accord path writes; the lens-core doors ask the same predicate (the unit
//! test in `halt_gate.rs` pins that), and a source scan pins that every door
//! asks it and that compose installs it.
//!
//! Its own binary: the gate's home is process-wide, installed once.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::ingest_http::{self, CANONICAL_INGEST_PATH};
use ciris_server::mesh_config_effect::MeshConfigEffect;

async fn post(
    engine: Arc<Engine>,
    refusals: &ingest_http::IngestRefusals,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let app = ingest_http::router(engine, refusals.clone(), MeshConfigEffect::unwired());
    let req = Request::builder()
        .method("POST")
        .uri(CANONICAL_INGEST_PATH)
        .header("content-type", "application/json")
        .header("user-agent", "CIRIS-AccordMetrics/1.0")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn while_a_halt_is_in_effect_the_ingest_door_refuses_and_counts_it() {
    let home = std::env::temp_dir().join(format!("halt-gate-ingest-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let _ = std::fs::remove_file(ciris_server::accord_halt::halt_latch_path(&home));
    ciris_server::halt_gate::install(home.clone());
    assert!(ciris_server::halt_gate::is_installed());

    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x5A; 32]),
        "node-halt-gate".into(),
        None,
        None,
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .unwrap(),
    );
    let refusals = ingest_http::IngestRefusals::new();
    let batch = br#"{"events":[{"trace":{"trace_id":"trace-gate-0001","components":[{"event_type":"LLM_CALL","data":{"model":"gpt-4o"}}]}}]}"#.to_vec();

    // No latch: the door does its ordinary work (whatever it decides, it is
    // not the halt refusal).
    let (open_status, open_body) = post(Arc::clone(&engine), &refusals, batch.clone()).await;
    assert_ne!(open_status, StatusCode::LOCKED, "{open_body}");

    // One holder's halt, as the accord path writes it.
    let rec = ciris_server::accord_halt::HaltRecord::new(
        "constitutional".into(),
        "halt-gate-001".into(),
        vec!["accord-holder-a".into()],
        1,
        chrono::Utc::now().to_rfc3339(),
        Some("node-halt-gate".into()),
        Some("ab".repeat(32)),
    );
    ciris_server::accord_halt::latch_halt(&home, &rec).unwrap();
    assert!(ciris_server::halt_gate::in_effect());

    let (status, body) = post(Arc::clone(&engine), &refusals, batch.clone()).await;
    assert_eq!(status, StatusCode::LOCKED, "{body}");
    assert_eq!(
        body["error"].as_str(),
        Some(ciris_server::halt_gate::REFUSAL_HALT_IN_EFFECT),
        "{body}"
    );
    let ledger = refusals.snapshot();
    assert!(
        ledger.refusals_in_window >= 1,
        "the refusal is counted: {ledger:?}"
    );

    // The latch ends; the door opens again.
    std::fs::remove_file(ciris_server::accord_halt::halt_latch_path(&home)).unwrap();
    assert!(!ciris_server::halt_gate::in_effect());
    let (status, body) = post(engine, &refusals, batch).await;
    assert_ne!(status, StatusCode::LOCKED, "{body}");
    let _ = std::fs::remove_dir_all(&home);
}

/// Every door an agent's reasoning crosses asks the ONE gate, and compose
/// installs it. A door without the ask is a door around the halt; a hook left
/// uninstalled is the class CIRISServer paid six releases for once.
#[test]
fn every_agent_door_asks_the_gate_and_compose_installs_it() {
    let root = env!("CARGO_MANIFEST_DIR");
    for (file, needle) in [
        ("src/ingest_http.rs", "crate::halt_gate::in_effect()"),
        (
            "crates/ciris-lens-core/src/role/handler.rs",
            "crate::halt_gate::halted()",
        ),
        (
            "crates/ciris-lens-core/src/capture/client.rs",
            "crate::halt_gate::halted()",
        ),
        (
            "crates/ciris-lens-core/src/ffi/pyo3.rs",
            "crate::halt_gate::halted()",
        ),
        (
            "src/compose.rs",
            "crate::halt_gate::install(cfg.home.clone())",
        ),
        ("src/compose.rs", "crate::halt_gate::is_installed()"),
        (
            "src/halt_gate.rs",
            "ciris_lens_core::halt_gate::set_halt_gate(in_effect)",
        ),
    ] {
        let src = std::fs::read_to_string(format!("{root}/{file}")).expect("read source");
        assert!(src.contains(needle), "{file} must contain `{needle}`");
    }
}
