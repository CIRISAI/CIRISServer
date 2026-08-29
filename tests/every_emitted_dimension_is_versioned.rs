//! **Gate: every dimension this repo emits carries a `:vN`, and persist really
//! refuses one that does not.**
//!
//! # The defect this exists to catch
//!
//! A producer was written whose dimension had no version segment. It compiled, its
//! unit tests were green, its envelope was well-formed, and **every emission would
//! have been rejected at `put_attestation`** — the loop logging "attestation
//! failed" once a minute while nothing ever reached a peer (CIRISServer#504).
//!
//! Nothing local catches that, because nothing local reaches the put door. The
//! rule it teaches is general: **a producer is not tested until its row has been
//! through admission.**
//!
//! # Why two halves, and why the empirical one comes first
//!
//! [`persist_really_refuses_an_unversioned_dimension`] puts a deliberately
//! unversioned row through a real engine. It pins the RULE against the substrate
//! rather than against this file's belief about the substrate — the discipline this
//! repo already applies where two implementations must agree.
//!
//! [`every_dimension_literal_in_src_is_versioned`] then scrapes the tree, so a new
//! producer trips on a fast unit test rather than in a peer's logs.
//!
//! The empirical half is what makes the structural half trustworthy: if persist
//! ever drops the requirement, the first test reds and tells you the second is now
//! merely a convention rather than a gate.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, KeyRecord,
};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes()));
    s
}

fn signer_for(key_id: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(key_id, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(key_id, 2), format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        identity_type::NODE,
        &ed_pub,
        Some(&pqc_pub),
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
                identity_type: identity_type::NODE.into(),
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

/// Build a well-formed `scores` row whose ONLY defect is `dimension`.
fn spec_with_dimension(node: &str, dimension: &str) -> ciris_server::attest::Spec {
    let envelope = serde_json::json!({
        "dimension": dimension,
        "attesting_key_id": node,
        "subject_key_ids": [node],
        "score": 1.0,
        "confidence": 1.0,
        "cohort_scope": cohort_scope::FEDERATION,
        "witness_relation": "self",
    });
    ciris_server::attest::Spec::new(attestation_type::SCORES, cohort_scope::FEDERATION, envelope)
        .about(node)
        .weighing(Some(1.0))
}

/// **The empirical half.** A versioned dimension is admitted; the same row with the
/// version stripped is REFUSED. Both directions, so this fails if persist ever
/// stops enforcing the rule rather than silently becoming a no-op.
#[tokio::test]
async fn persist_really_refuses_an_unversioned_dimension() {
    const NODE: &str = "dimension-gate-node";
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE)), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    register(&engine, &signer_for(NODE), NODE).await;

    // Versioned: admitted.
    let ok = ciris_server::attest::Emit::stamp(NODE, spec_with_dimension(NODE, "config:load:v1"))
        .expect("stamp")
        .sign_and_assemble(ciris_server::attest::KeySigner::Engine(&engine))
        .await
        .expect("sign");
    ciris_server::attest::put(&engine, ok)
        .await
        .expect("a VERSIONED dimension must be admitted — if this fails the gate below is moot");

    // Same row, version stripped: refused.
    let bad = ciris_server::attest::Emit::stamp(NODE, spec_with_dimension(NODE, "config:load"))
        .expect("stamp")
        .sign_and_assemble(ciris_server::attest::KeySigner::Engine(&engine))
        .await
        .expect("sign");
    let err = ciris_server::attest::put(&engine, bad)
        .await
        .expect_err("persist MUST refuse a scores dimension with no :vN segment");
    let msg = err.to_string();
    assert!(
        msg.contains("version") || msg.contains("dimension"),
        "the refusal should name the dimension rule, got: {msg}"
    );
}

/// **The structural half.** Scrape every dimension literal this repo emits and
/// require a `:vN` on each, so a new producer trips here rather than in a peer's
/// logs a minute at a time.
#[test]
fn every_dimension_literal_in_src_is_versioned() {
    fn versioned(d: &str) -> bool {
        d.rsplit(':').next().is_some_and(|last| {
            last.len() >= 2
                && last.starts_with('v')
                && last[1..].chars().all(|c| c.is_ascii_digit())
        })
    }

    // The two shapes an emitted dimension takes in this tree: the single-sourced
    // `(paths::DIMENSION): "…"` and the raw `"dimension": "…"` an older producer
    // may still carry.
    let patterns = [r#"(paths::DIMENSION): ""#, r#""dimension": ""#];
    let mut checked = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for entry in walk("src") {
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        for line in text.lines() {
            let trimmed = line.trim_start();
            // Skip doc comments and commentary — a dimension NAMED in prose is not
            // a dimension EMITTED, and this gate is about what reaches the wire.
            if trimmed.starts_with("//") {
                continue;
            }
            for pat in patterns {
                let Some(idx) = line.find(pat) else { continue };
                let rest = &line[idx + pat.len()..];
                let Some(end) = rest.find('"') else { continue };
                let dim = &rest[..end];
                // A `{}`-interpolated or constant-referencing value is not a literal
                // this gate can judge; the constants themselves are checked where
                // they are defined.
                if dim.is_empty() || dim.contains('{') {
                    continue;
                }
                checked += 1;
                if !versioned(dim) {
                    offenders.push(format!("{}: {dim}", entry.display()));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "the scraper matched NOTHING — a balanced fixture proves nothing; the emit \
         shape must have changed and this gate needs updating"
    );
    assert!(
        offenders.is_empty(),
        "every emitted dimension must carry a :vN segment or persist refuses the row \
         at admission (CIRISServer#504). Offenders:\n  {}",
        offenders.join("\n  ")
    );
}

fn walk(dir: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out
}
