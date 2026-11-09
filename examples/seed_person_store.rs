//! Fill a stopped PERSON's node with a store of the shape a long-lived node holds,
//! so a contact can be tested against it. Synthetic keys and synthetic people: it
//! reads aggregates and moves no production data.
//!
//! Every row is really signed by a freshly generated hybrid key and goes through
//! the door production uses, so what lands is what a node admits. Rows are dated
//! back across the shape's days, because old rows sorting before a fresh grant are
//! what the test is for. A row the door refuses is counted, not forced in.
//!
//! usage: seed_person_store <db> <shape.json> <root_key_id> [scale]
//!
//! `scale` (default 1.0) multiplies every row count, for a quick smoke run.
use std::collections::BTreeMap;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, KeyRecord, SignedKeyRecord,
};
use ciris_persist::federation::{EncryptionPubkeys, IdentityOccurrence, SignedIdentityOccurrence};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::attest::{put, Emit, KeySigner, Spec};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn seed(alias: &str, half: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(alias.as_bytes());
    h.update([half]);
    h.finalize().into()
}

async fn signer_for(label: &str) -> (LocalSigner, String) {
    let ed = SigningKey::from_bytes(&seed(label, 1));
    let key_id = ciris_verify_core::fedcode::derive_key_id(label, ed.verifying_key().as_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(label, 2), format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let _ = pqc.public_key().await.expect("ML-DSA-65 public key");
    let signer =
        LocalSigner::from_parts(ed, key_id.clone(), Some(pqc), Some(format!("{key_id}-pqc")));
    (signer, key_id)
}

async fn register(
    engine: &Engine,
    signer: &LocalSigner,
    key_id: &str,
    kind: &str,
    at: DateTime<Utc>,
) -> Result<(), String> {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer
        .sign_hybrid(b"probe")
        .await
        .map_err(|e| e.to_string())?;
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        kind,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .map_err(|e| e.to_string())?;
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| e.to_string())?;
    let sig = signer
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| e.to_string())?;
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: kind.to_owned(),
                identity_ref: key_id.to_owned(),
                valid_from: at,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_owned(),
                scrub_timestamp: at,
                pqc_completed_at: Some(at),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .map_err(|e| e.to_string())
}

/// The instant of row `i` of `n`: the shape's busy days take their share and the
/// rest spread evenly across the fortnight.
fn date_for(i: usize, n: usize, days: &[(u32, u32, f64)]) -> DateTime<Utc> {
    let total: f64 = days.iter().map(|d| d.2).sum();
    let mut at = (i as f64 + 0.5) / n.max(1) as f64 * total;
    for (month, day, weight) in days {
        if at < *weight {
            let secs = (at / weight * 86_000.0) as i64;
            return Utc
                .with_ymd_and_hms(2026, *month, *day, 0, 0, 0)
                .single()
                .expect("a real date")
                + Duration::seconds(secs);
        }
        at -= weight;
    }
    Utc.with_ymd_and_hms(2026, 10, 30, 23, 0, 0)
        .single()
        .expect("a real date")
}

async fn sign_put(
    engine: &Engine,
    signer: &LocalSigner,
    key_id: &str,
    spec: Spec,
    at: DateTime<Utc>,
) -> Result<(), String> {
    let row = Emit::stamp_at(key_id, spec, at)
        .map_err(|e| e.to_string())?
        .sign_and_assemble(KeySigner::Local(signer))
        .await
        .map_err(|e| e.to_string())?;
    put(engine, row)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Admitted and refused rows per dimension, and the first words of each refusal.
#[derive(Default)]
struct Tally(BTreeMap<String, (usize, usize, BTreeMap<String, usize>)>);

impl Tally {
    fn note(&mut self, dim: &str, got: Result<(), String>) {
        let e = self.0.entry(dim.to_owned()).or_default();
        match got {
            Ok(()) => e.0 += 1,
            Err(why) => {
                e.1 += 1;
                let short: String = why.chars().take(140).collect();
                *e.2.entry(short).or_default() += 1;
            }
        }
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [db, shape_path, root, rest @ ..] = args.as_slice() else {
        panic!("usage: seed_person_store <db> <shape.json> <root_key_id> [scale]");
    };
    let scale: f64 = rest.first().map_or(1.0, |s| s.parse().expect("scale"));
    let shape: serde_json::Value =
        serde_json::from_slice(&std::fs::read(shape_path).expect("read shape")).expect("JSON");
    let rows = |dim: &str| -> usize {
        let n = shape["dimensions"][dim]["rows"].as_u64().unwrap_or(0) as f64;
        (n * scale).round() as usize
    };
    let signers_of = |dim: &str| -> usize {
        let n = shape["dimensions"][dim]["signers"].as_u64().unwrap_or(0) as f64;
        ((n * scale).round() as usize).max(1)
    };
    let days: Vec<(u32, u32, f64)> = shape["days"]
        .as_array()
        .expect("days")
        .iter()
        .map(|d| {
            let (m, day) = d["day"]
                .as_str()
                .expect("day")
                .split_once('-')
                .expect("MM-DD");
            (
                m.parse().expect("month"),
                day.parse().expect("day"),
                d["rows"].as_f64().expect("rows"),
            )
        })
        .collect();

    let started = std::time::Instant::now();
    let (pen, _) = signer_for("synthetic-seeder").await;
    let engine = Engine::with_signer(Arc::new(pen), &format!("sqlite:///{db}"))
        .await
        .expect("open the store");
    let dir = engine.federation_directory();
    let born = Utc
        .with_ymd_and_hms(2026, 10, 16, 0, 0, 0)
        .single()
        .expect("date");
    let mut tally = Tally::default();

    // The people. Occurrence signers are the people; the rest of key:record are
    // their nodes. Every signer is one real key, one real proof of possession.
    let total_keys = rows("key:record:v1");
    let people = signers_of("identity:occurrence:v1").min(total_keys / 2);
    let mut users = Vec::with_capacity(people);
    let mut nodes = Vec::with_capacity(total_keys - people);
    // A capture grant must name an agent, so its few owners each have one.
    let owners = signers_of("consent:community_trust:v1").min(people);
    let mut agents = Vec::with_capacity(owners);
    for i in 0..total_keys {
        let (role, kind) = if i < people {
            ("user", identity_type::USER)
        } else if i + owners >= total_keys {
            ("agent", identity_type::AGENT)
        } else {
            ("node", identity_type::NODE)
        };
        let (signer, key_id) = signer_for(&format!("synthetic-{role}-{i}")).await;
        tally.note(
            "key:record:v1",
            register(&engine, &signer, &key_id, kind, born).await,
        );
        match role {
            "user" => users.push((signer, key_id)),
            "agent" => agents.push(key_id),
            _ => nodes.push((signer, key_id)),
        }
        if i % 500 == 499 {
            eprintln!("keys {} of {total_keys}, {:?}", i + 1, started.elapsed());
        }
    }

    // A person's devices. The roster door may hold a person's second device.
    let want = rows("identity:occurrence:v1");
    for i in 0..want.min(nodes.len()) {
        let (pen, owner) = &users[i % users.len()];
        let occ = &nodes[i % nodes.len()].1;
        let at = date_for(i, want, &days);
        let keys = EncryptionPubkeys {
            x25519_base64: B64.encode(seed(occ, 3)),
            ml_kem_768_base64: B64.encode(seed(occ, 4).repeat(37)),
        };
        let envelope = serde_json::json!({
            "attesting_key_id": owner,
            "identity_key_id": owner,
            "occurrence_key_id": occ,
            "device_class": "laptop",
            "encryption_pubkeys": {
                "x25519_base64": keys.x25519_base64,
                "ml_kem_768_base64": keys.ml_kem_768_base64,
            },
            "asserted_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "valid_until": serde_json::Value::Null,
            "hardware_attestation": serde_json::Value::Null,
        });
        let got = async {
            let (signed_envelope, signature) =
                ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                    &ciris_persist::signing::LocalSelfSigner::new(pen),
                    envelope,
                )
                .await
                .map_err(|e| e.to_string())?;
            dir.put_identity_occurrence(SignedIdentityOccurrence {
                identity_occurrence: IdentityOccurrence {
                    identity_key_id: owner.clone(),
                    occurrence_key_id: occ.clone(),
                    device_class: "laptop".to_owned(),
                    hardware_attestation: None,
                    asserted_at: at,
                    valid_until: None,
                    encryption_pubkeys: Some(keys.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                },
                attesting_key_id: owner.clone(),
                signed_envelope,
                signature,
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
        .await;
        tally.note("identity:occurrence:v1", got);
    }
    eprintln!("occurrences done, {:?}", started.elapsed());

    // Owner-bindings: each person's node, at federation scope.
    let want = rows("ownership:responsible_party:node");
    for i in 0..want {
        let (pen, owner) = &users[i % users.len()];
        let node = &nodes[i % nodes.len()].1;
        let got = match ciris_server::auth::ownership::build_owner_binding_envelope(
            owner,
            node,
            &["infra:*".to_owned()],
        ) {
            Ok(envelope) => {
                sign_put(
                    &engine,
                    pen,
                    owner,
                    Spec::new(
                        attestation_type::DELEGATES_TO,
                        cohort_scope::FEDERATION,
                        envelope,
                    )
                    .about(node),
                    date_for(i, want, &days),
                )
                .await
            }
            Err(e) => Err(e.to_string()),
        };
        tally.note("ownership:responsible_party:node", got);
    }
    eprintln!("bindings done, {:?}", started.elapsed());

    // Each key's acceptance of the root.
    let want = rows("trust:accepts:v1");
    let all: Vec<&(LocalSigner, String)> = users.iter().chain(nodes.iter()).collect();
    for (i, (pen, key_id)) in all.iter().enumerate().take(want) {
        let got = match engine
            .trust_acceptance_envelope(root, &["infra:attest", "infra:serve"])
            .await
        {
            Ok(mut envelope) => {
                envelope[ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID] =
                    serde_json::Value::String(format!("trust-edge:{key_id}:{root}"));
                sign_put(
                    &engine,
                    pen,
                    key_id,
                    Spec::new(
                        attestation_type::DELEGATES_TO,
                        cohort_scope::FEDERATION,
                        envelope,
                    )
                    .attested_to(root),
                    date_for(i, want, &days),
                )
                .await
            }
            Err(e) => Err(e.to_string()),
        };
        tally.note("trust:accepts:v1", got);
    }
    eprintln!("acceptances done, {:?}", started.elapsed());

    // Capture grants from a few owners, as a handful of busy owners write them.
    let want = rows("consent:community_trust:v1");
    for i in 0..want {
        let (pen, owner) = &users[i % owners];
        let node = &nodes[i % owners].1;
        let agent = &agents[i % owners];
        let mut envelope = serde_json::json!({ "id": format!("seed-ct-{i}"), "score": 1.0 });
        envelope[ciris_persist::federation::envelope::paths::DIMENSION] =
            serde_json::Value::from("consent:community_trust:v1");
        let spec = Spec::new(attestation_type::SCORES, cohort_scope::FEDERATION, envelope)
            .about_all(node, &[node.clone(), owner.clone(), agent.clone()]);
        // After the owner's binding on that node, which is among the first dated.
        let at = date_for(i, want, &days) + Duration::hours(6);
        let got = sign_put(&engine, pen, owner, spec, at).await;
        tally.note("consent:community_trust:v1", got);
    }

    // Replication grants between synthetic people.
    let want = rows("consent:replication:v1");
    let grantors = signers_of("consent:replication:v1").min(users.len());
    for i in 0..want {
        let (pen, grantor) = &users[i % grantors];
        let peer = &nodes[(i + 1) % nodes.len()].1;
        let envelope = serde_json::json!({
            (ciris_persist::federation::envelope::paths::DIMENSION): "consent:replication:v1",
            "attesting_key_id": grantor,
            "subject_key_ids": [peer],
            "score": 1.0,
            "cohort_scope": cohort_scope::FEDERATION,
            "witness_relation": "self",
            "topical_relation": "bilateral_pair",
            "subject_kind": "consent_replication",
            "payload": {
                "grants": "replication",
                "direction": "egress",
                "kinds": ["Attestation"],
                "attestation_prefixes": ["chat:"],
                "principle": "share",
                "audience": "federation",
                "restrictions": [],
            },
        });
        let spec =
            Spec::new(attestation_type::SCORES, cohort_scope::FEDERATION, envelope).about(peer);
        let got = sign_put(&engine, pen, grantor, spec, date_for(i, want, &days)).await;
        tally.note("consent:replication:v1", got);
    }

    // One device's own claims, the bulk of the rows, all long expired.
    let want = rows("session:claim:v1");
    let (pen, device) = &nodes[0];
    let community = users[0].1.clone();
    for i in 0..want {
        let at = date_for(i, want, &days);
        let until = at + Duration::seconds(120);
        let envelope = serde_json::json!({
            (ciris_persist::federation::envelope::paths::DIMENSION): "session:claim:v1",
            "score": 1.0,
            "community_id": community,
            "session_id": format!("seed-session-{i}"),
            "claimed_at": ciris_server::session_claims::canonical_instant(at),
            "valid_until": ciris_server::session_claims::canonical_instant(until),
        });
        let spec = Spec::new(attestation_type::SCORES, cohort_scope::SELF, envelope)
            .weighing(Some(1.0))
            .expiring(Some(until));
        let got = sign_put(&engine, pen, device, spec, at).await;
        tally.note("session:claim:v1", got);
        if i % 1000 == 999 {
            eprintln!("claims {} of {want}, {:?}", i + 1, started.elapsed());
        }
    }

    let mut report = serde_json::Map::new();
    for (dim, (admitted, refused, why)) in &tally.0 {
        report.insert(
            dim.clone(),
            serde_json::json!({ "admitted": admitted, "refused": refused, "why": why }),
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "seed_secs": started.elapsed().as_secs(),
            "scale": scale,
            "dimensions": report,
        })
    );
}
