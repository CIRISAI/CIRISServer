//! The node's halt predicate (`src/halt_gate.rs`, CC 4.2.1.1 rc7) has ONE
//! reader — the agent's act gate, through `GET /v1/accord/halt-status` — and
//! NO data door reads it: a halt is an agent pause with zero data disruption
//! by construction. 0.5.225 refused the HTTP ingest, the relay and both
//! capture paths 423 while halted; 0.5.226 removed those readers (CC on
//! re-pin 17) because a refused act's terminal ACTION_RESULT travels exactly
//! those paths to the record — a door that refuses it makes the pause erase
//! its own evidence.
//!
//! Proven here two ways: the HTTP ingest does its ordinary work while the
//! latch stands (same answer as with no latch), and a source scan pins that
//! no file outside `halt_gate.rs` and `compose.rs` names the predicate —
//! add a reader to a data door and this goes red (the L3 mutant for CC
//! 4.2.1.1's "zero data disruption").
//!
//! Its own binary: the predicate's home is process-wide, installed once.

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
async fn while_a_halt_is_in_effect_the_ingest_door_does_its_ordinary_work() {
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

    // No latch: the door's ordinary answer for this (unsigned) batch.
    let (open_status, open_body) = post(Arc::clone(&engine), &refusals, batch.clone()).await;
    assert_ne!(open_status, StatusCode::LOCKED, "{open_body}");
    let open_error = open_body["error"].as_str().map(str::to_owned);

    // One holder's halt, as the accord path writes it. The predicate sees it…
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

    // …and the data door does not: same status, same (non-halt) answer.
    let (status, body) = post(Arc::clone(&engine), &refusals, batch.clone()).await;
    assert_eq!(status, open_status, "{body}");
    assert_ne!(status, StatusCode::LOCKED, "{body}");
    assert_ne!(
        body["error"].as_str(),
        Some(ciris_server::halt_gate::REFUSAL_HALT_IN_EFFECT),
        "a data door answered the halt refusal: {body}"
    );
    assert_eq!(
        body["error"].as_str().map(str::to_owned),
        open_error,
        "{body}"
    );

    std::fs::remove_file(ciris_server::accord_halt::halt_latch_path(&home)).unwrap();
    assert!(!ciris_server::halt_gate::in_effect());
    let _ = std::fs::remove_dir_all(&home);
}

/// Every `.rs` file under `src/` and `crates/ciris-lens-core/src/` except
/// the predicate's own module and `compose.rs` (which installs it and asserts
/// it installed, and reads nothing). The ONLY reader is the agent's act gate
/// over the served status; the served status is built from the latch record
/// in `accord.rs::halt_status`, not from this predicate.
#[test]
fn no_data_door_reads_the_latch() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for dir in ["src", "crates/ciris-lens-core/src"] {
        walk(&root.join(dir), &mut |path| {
            // Forward slashes on every host: Windows hands back `src\\compose.rs`,
            // and the allow-list below is spelled the POSIX way (main went red
            // on windows-latest at c70f96bb for exactly this).
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "src/halt_gate.rs" {
                return;
            }
            let src = std::fs::read_to_string(path).expect("read source");
            for (i, line) in src.lines().enumerate() {
                if !line.contains("halt_gate::") {
                    continue;
                }
                let allowed = rel == "src/compose.rs"
                    && (line.contains("halt_gate::install(")
                        || line.contains("halt_gate::is_installed()"));
                if !allowed {
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        });
    }
    assert!(
        offenders.is_empty(),
        "a data door reads the constitutional-halt latch (CC 4.2.1.1: the agent's act gate is \
         its one reader; a refused act's ACTION_RESULT must reach the record):\n{}",
        offenders.join("\n")
    );
    // The installer is still there, so the served status has a home to read.
    let compose = std::fs::read_to_string(root.join("src/compose.rs")).unwrap();
    assert!(compose.contains("crate::halt_gate::install(cfg.home.clone())"));
    assert!(compose.contains("crate::halt_gate::is_installed()"));
    // And lens-core carries no hook to arm: a hook left installed-but-unasked
    // is the "arming ≠ driving" class.
    assert!(!root
        .join("crates/ciris-lens-core/src/halt_gate.rs")
        .exists());
}

fn walk(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path)) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path);
        }
    }
}
