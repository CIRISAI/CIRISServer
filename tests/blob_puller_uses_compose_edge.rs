//! CIRISServer#604 — the blob puller must take the `Edge` compose holds, never
//! the process-global `ciris_edge::current_edge()`.
//!
//! The standalone binary builds its own `Arc<Edge>` and never publishes the
//! global handle; only the #221 embedded fold (`init_edge_runtime`) does. A
//! puller that resolved the global spawned on every agent node and on no
//! standalone node — the canonical's first boot on 0.5.211 logged "blob puller
//! NOT spawned — no shared Edge handle yet" while the ladders (embedded on both
//! roles) stayed green. Source-scraped because `start_replication_runtime`
//! needs a live Reticulum transport no in-process fixture builds; the chat
//! ladder asserts the spawn line on both standalone nodes.

use std::path::Path;

fn read(p: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(p)).expect(p)
}

#[test]
fn the_puller_shim_never_resolves_the_process_global_edge() {
    let backend = read("src/backend.rs");
    let start = backend
        .find("pub async fn spawn_blob_puller(")
        .expect("spawn_blob_puller is where the puller is built");
    let body = &backend[start..];
    assert!(
        !body.contains("current_edge()"),
        "backend::spawn_blob_puller (or its helper) resolves `ciris_edge::current_edge()` — \
         that handle exists only in the embedded fold; a standalone node gets no puller \
         (CIRISServer#604). Take the Edge compose holds as a parameter."
    );
    assert!(
        body.contains("edge: Arc<ciris_edge::Edge>"),
        "spawn_blob_puller must take compose's `Arc<ciris_edge::Edge>` explicitly"
    );
}

#[test]
fn compose_hands_its_own_edge_to_the_puller() {
    let compose = read("src/compose.rs");
    let call = compose
        .find("crate::backend::spawn_blob_puller(")
        .expect("compose spawns the puller from start_replication_runtime");
    let window = &compose[call..call + 200];
    assert!(
        window.contains("Arc::clone(edge)"),
        "compose must pass the `Arc<Edge>` it built (or was handed by the fold) to the \
         puller, not leave it to a global lookup: {window}"
    );
}
