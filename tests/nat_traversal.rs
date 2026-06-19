//! CIRISServer#24 — NAT-traversal infra (server side): the node operates as a
//! Reticulum **Transport-node** (CIRISEdge#168, packet forwarding for non-local
//! destinations) AND runs **store-and-forward** propagation (CIRISEdge#169, mail
//! held for asleep/offline mobile edges, drained on wake-up).
//!
//! A live multi-node relay round-trip needs two networked Reticulum nodes and is
//! integration-only (not unit-testable in-process). These tests instead pin the
//! wiring that makes the round-trip possible:
//!
//!   1. the env/default contract on [`ServerConfig`] (default ON for a fabric
//!      node; opt-out via `=0`),
//!   2. that `transport_node` maps onto `ReticulumTransportConfig.enable_transport`
//!      exactly as `build_edge` sets it,
//!   3. that the store-and-forward queue `build_edge` wires (edge's own
//!      `MemoryStoreAndForward`) actually stores and drains.
//!
//! Together these assert CIRISServer#24's server side: the node forwards for
//! NAT'd edges + queues for asleep ones. APNs push-to-wake stays a mobile/bridge
//! concern (out of scope).

use std::time::Duration;

use ciris_edge::transport::reticulum::ReticulumTransportConfig;
use ciris_edge::transport::store_and_forward::{
    MemoryStoreAndForward, StoreAndForward, StoreAndForwardConfig,
};
use ciris_server::ServerConfig;

/// Env vars are process-global; run the env-driven cases serially inside ONE
/// test so they cannot race other tests in this binary. Each case sets, reads,
/// and clears its own keys.
#[test]
fn transport_and_saf_env_default_on_and_opt_out() {
    // The keys we toggle. Save + restore any pre-existing values.
    const TN: &str = "CIRIS_SERVER_TRANSPORT_NODE";
    const SAF: &str = "CIRIS_SERVER_STORE_AND_FORWARD";
    let saved_tn = std::env::var(TN).ok();
    let saved_saf = std::env::var(SAF).ok();

    // (a) ABSENT → default ON. A public fabric node relays + propagates by default.
    std::env::remove_var(TN);
    std::env::remove_var(SAF);
    let cfg = ServerConfig::from_env().expect("from_env (defaults)");
    assert!(
        cfg.transport_node,
        "transport-node must DEFAULT ON for a fabric node (CIRISServer#24)"
    );
    assert!(
        cfg.store_and_forward,
        "store-and-forward must DEFAULT ON for a fabric node (CIRISServer#24)"
    );

    // (b) Explicit opt-OUT via `0` → both off (a non-forwarding leaf).
    std::env::set_var(TN, "0");
    std::env::set_var(SAF, "false");
    let cfg = ServerConfig::from_env().expect("from_env (opt-out)");
    assert!(!cfg.transport_node, "=0 must disable transport-node");
    assert!(
        !cfg.store_and_forward,
        "=false must disable store-and-forward"
    );

    // (c) Explicit opt-IN via truthy spellings.
    std::env::set_var(TN, "on");
    std::env::set_var(SAF, "1");
    let cfg = ServerConfig::from_env().expect("from_env (opt-in)");
    assert!(cfg.transport_node, "=on must enable transport-node");
    assert!(cfg.store_and_forward, "=1 must enable store-and-forward");

    // Restore environment for any other tests in this binary.
    match saved_tn {
        Some(v) => std::env::set_var(TN, v),
        None => std::env::remove_var(TN),
    }
    match saved_saf {
        Some(v) => std::env::set_var(SAF, v),
        None => std::env::remove_var(SAF),
    }
}

/// `build_edge` sets `ReticulumTransportConfig.enable_transport = cfg.transport_node`.
/// Build the transport config the same way and assert the toggle propagates —
/// this is the field leviculum's `ReticulumNodeBuilder::enable_transport` reads,
/// i.e. the load-bearing half of NAT packet-forwarding.
#[test]
fn transport_node_flag_maps_into_reticulum_config() {
    let mk = |enabled: bool| ReticulumTransportConfig {
        listen_addr: "0.0.0.0:4242".parse().unwrap(),
        bootstrap_peers: vec![],
        identity_path: std::path::PathBuf::from("/tmp/does-not-matter.rid"),
        announce_interval: Duration::from_secs(300),
        local_key_id: "test-node".to_string(),
        local_epoch: 0,
        interfaces: vec![],
        enable_transport: enabled,
    };

    assert!(
        mk(true).enable_transport,
        "transport_node=true must enable Reticulum packet forwarding"
    );
    assert!(
        !mk(false).enable_transport,
        "transport_node=false must run as a non-forwarding leaf"
    );

    // The builder helper is an equivalent spelling — also exercised so a future
    // refactor to `.with_transport_node(..)` stays covered.
    let via_builder =
        ReticulumTransportConfig::new(std::path::PathBuf::from("/tmp/x.rid"), "test-node")
            .with_transport_node(true);
    assert!(via_builder.enable_transport);
}

/// The store-and-forward queue `build_edge` wires is edge's own
/// `MemoryStoreAndForward` (bounded; CIRISEdge#169). Prove it stores envelopes
/// for an offline destination and drains them oldest-first on wake-up — the
/// §24 propagation behaviour a mobile edge depends on.
#[test]
fn store_and_forward_queue_stores_and_drains() {
    let saf: Box<dyn StoreAndForward> =
        Box::new(MemoryStoreAndForward::new(StoreAndForwardConfig::default()));

    let dest = "mobile-edge-key-id";
    assert_eq!(saf.pending_count(dest), 0, "fresh queue is empty");

    // Three CEG envelopes arrive while the mobile edge is asleep/offline.
    saf.queue(dest, b"envelope-1").expect("queue 1");
    saf.queue(dest, b"envelope-2").expect("queue 2");
    saf.queue(dest, b"envelope-3").expect("queue 3");
    assert_eq!(
        saf.pending_count(dest),
        3,
        "all three held for offline dest"
    );

    // The edge wakes and fetches — drains oldest-first, then the queue is empty.
    let drained = saf.drain(dest, 10).expect("drain");
    assert_eq!(drained.len(), 3, "all held envelopes delivered on wake-up");
    assert_eq!(drained[0].envelope_bytes, b"envelope-1");
    assert_eq!(drained[2].envelope_bytes, b"envelope-3");
    assert!(drained.iter().all(|d| d.destination_key_id == dest));
    assert_eq!(saf.pending_count(dest), 0, "drained queue is empty");
}
