//! Fill a test store with the canonical's SHAPE, for a test seat (no production
//! data moves). Reads aggregates only: route counts per destination, keyless
//! routes per month, keys per type.
//!
//! Routes go through persist's trusted-local door, unsigned and `advisory`, like
//! the keyless rows they stand for. The biggest destinations are filled first
//! and with keyless routes, as on the canonical. Keys are local rows with real
//! Ed25519 public keys and NO valid registration signature, and attestations are
//! not seeded: this reproduces directory size and fan-out, not admission, so a
//! peer refuses these key rows if they are offered to it. Keyed routes are unsigned
//! here too, where most of the canonical's are signed.
//!
//! usage: seed_synthetic_seat <db> <shape.json>
use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use ciris_persist::federation::self_at_login::{BindingProvenance, TransportDestination};
use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::Backend as _;
use sha2::{Digest, Sha256};

fn digest(parts: &[&str]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    h.finalize().into()
}

fn month_start(month: &str) -> DateTime<Utc> {
    let (y, m) = month.split_once('-').expect("month is YYYY-MM");
    Utc.with_ymd_and_hms(
        y.parse().expect("year"),
        m.parse().expect("month"),
        1,
        0,
        0,
        0,
    )
    .single()
    .expect("a real month")
}

/// One route's month, in file order; keyless first, so each month holds what the
/// aggregates say it holds.
fn month_slots(shape: &serde_json::Value, keyless: bool) -> Vec<DateTime<Utc>> {
    let mut out = Vec::new();
    for m in shape["routes_by_month"]
        .as_array()
        .expect("routes_by_month")
    {
        let at = month_start(m["month"].as_str().expect("month"));
        let free = m["keyless"].as_u64().expect("keyless");
        let n = if keyless {
            free
        } else {
            m["routes"].as_u64().expect("routes") - free
        };
        for i in 0..n {
            out.push(at + chrono::Duration::seconds((i * 97) as i64));
        }
    }
    out
}

fn key_record(key_id: &str, id_type: &str, at: DateTime<Utc>) -> KeyRecord {
    let ed = ed25519_dalek::SigningKey::from_bytes(&digest(&["key", key_id]));
    let public = B64.encode(ed.verifying_key().to_bytes());
    KeyRecord {
        key_id: key_id.to_owned(),
        pubkey_ed25519_base64: public.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_owned(),
        identity_ref: key_id.to_owned(),
        valid_from: at,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: hex::encode(digest(&["record", key_id])),
        scrub_signature_classical: public,
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_owned(),
        scrub_timestamp: at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let db = args
        .next()
        .expect("usage: seed_synthetic_seat <db> <shape.json>");
    let path = args
        .next()
        .expect("usage: seed_synthetic_seat <db> <shape.json>");
    let shape: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read shape")).expect("shape is JSON");
    let backend = ciris_persist::store::sqlite::SqliteBackend::open(db.clone())
        .await
        .expect("open store");
    backend.run_migrations().await.expect("migrate store");

    let joined = Utc
        .with_ymd_and_hms(2026, 7, 1, 0, 0, 0)
        .single()
        .expect("date");
    let mut keys = Vec::new();
    for (id_type, n) in shape["keys_by_type"].as_object().expect("keys_by_type") {
        // The seat's own ceremony mints these; persist refuses them without evidence.
        if id_type.contains("accord_holder") || id_type.contains("canonical") {
            continue;
        }
        for i in 0..n.as_u64().expect("key count") {
            let id = format!("synthetic-{}-{i}", id_type.replace(',', "-"));
            backend
                .put_public_key(SignedKeyRecord {
                    record: key_record(&id, id_type, joined),
                })
                .await
                .expect("put key");
            // CC 3.4.7.3 Clause A: an agent key holds no route.
            if id_type != "agent" {
                keys.push(id);
            }
        }
    }

    // Destinations, biggest first: (size, how many of that size).
    let mut sizes: BTreeMap<u64, u64> = BTreeMap::new();
    for (size, n) in shape["dest_size_histogram"].as_object().expect("histogram") {
        sizes.insert(size.parse().expect("size"), n.as_u64().expect("count"));
    }
    let mut keyless = month_slots(&shape, true).into_iter();
    let mut keyed = month_slots(&shape, false).into_iter();
    let (mut route, mut holder, mut written, mut without_key) = (0u64, 0usize, 0u64, 0u64);
    for (size, count) in sizes.iter().rev() {
        for d in 0..*count {
            let destination =
                hex::encode(&digest(&["dest", &size.to_string(), &d.to_string()])[..16]);
            for _ in 0..*size {
                route += 1;
                let (occurrence_key_id, asserted_at) = match keyless.next() {
                    Some(at) => {
                        without_key += 1;
                        (format!("synthetic-keyless-{route}"), at)
                    }
                    None => {
                        let at = keyed.next().expect("the histogram and the months agree");
                        holder += 1;
                        (keys[(holder - 1) % keys.len()].clone(), at)
                    }
                };
                backend
                    .put_transport_destination(&TransportDestination {
                        occurrence_key_id,
                        transport_kind: "reticulum".into(),
                        destination: destination.clone(),
                        asserted_at,
                        last_seen_at: None,
                        transport_ed25519_pubkey_base64: None,
                        transport_x25519_pubkey_base64: None,
                        binding_provenance: BindingProvenance::Advisory,
                        epoch: 1,
                        retired_at: None,
                    })
                    .await
                    .expect("put route");
                written += 1;
            }
        }
    }
    println!("seeded {db}: {written} routes, {without_key} keyless, no attestations");
}
