//! In-process probe for the item-2 attribution gate (CIRISServer#609 RCA).
//!
//! Runs EXACTLY the chain edge runs on an inbound frame, against a copied node
//! database, and prints every input and the verdict — no inference:
//!   1. `SqliteBackend::open` (no Engine, no genesis)
//!   2. `FederationDirectory::list_signed_transport_destinations_for(key)` — persist's reader
//!   3. `ciris_edge::verify::hybrid_reticulum_route_present(rows, dest)` — the predicate
//!   4. `RootingDirectory::hybrid_transport_binding_exists(key, dest)` — the blanket impl edge calls
//!
//! usage: probe_td_read <db> <peer_key_id> <dest_hex>
use ciris_edge::RootingDirectory;
use ciris_persist::federation::FederationDirectory;

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("db path");
    let key = std::env::args().nth(2).expect("peer key_id");
    let dest_hex = std::env::args().nth(3).expect("dest hex");
    let mut dest = [0u8; 16];
    hex::decode_to_slice(&dest_hex, &mut dest).expect("dest is 16 bytes hex");

    let backend = ciris_persist::store::sqlite::SqliteBackend::open(path.clone())
        .await
        .expect("open sqlite backend");
    println!("opened {path}");

    // 2. persist's reader
    match backend.list_signed_transport_destinations_for(&key).await {
        Ok(rows) => {
            println!(
                "[2] list_signed_transport_destinations_for({key}) -> {} row(s)",
                rows.len()
            );
            for r in &rows {
                println!(
                    "     kind={} dest={} eq_dest={} prov={:?} epoch={} retired={:?} attesting={} ed={} mldsa={}",
                    r.transport_destination.transport_kind,
                    r.transport_destination.destination,
                    r.transport_destination.destination == dest_hex,
                    r.transport_destination.binding_provenance,
                    r.transport_destination.epoch,
                    r.transport_destination.retired_at.is_some(),
                    r.attesting_key_id,
                    !r.signature.ed25519_signature_base64.is_empty(),
                    r.signature.mldsa65_signature_base64.is_some(),
                );
            }
            // 3. the predicate
            println!(
                "[3] hybrid_reticulum_route_present(rows, {dest_hex}) = {}",
                ciris_edge::verify::hybrid_reticulum_route_present(&rows, dest)
            );
        }
        Err(e) => println!("[2] READ ERROR (edge turns this into false): {e:#}"),
    }
    // 4. the door edge actually calls
    let rooting: std::sync::Arc<dyn RootingDirectory> = std::sync::Arc::new(backend);
    println!(
        "[4] RootingDirectory::hybrid_transport_binding_exists({key}, {dest_hex}) = {}",
        rooting.hybrid_transport_binding_exists(&key, dest).await
    );
}
