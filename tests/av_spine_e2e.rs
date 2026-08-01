//! **CIRISServer#336 ask 3** — stand up the A/V path (publisher → relay →
//! subscriber) from the SERVER, for interop testing.
//!
//! # What this proves that edge's own e2e does not
//!
//! Edge ships `tests/realtime_av_spine_e2e.rs` and it is green. That proves the
//! spine works *inside edge*. It cannot prove the spine is reachable from a
//! consumer, because a test living in the crate can reach `pub(crate)` items,
//! private test helpers, and dev-dependencies that a downstream crate cannot.
//!
//! This test is deliberately written **only against edge's public API, from
//! outside the crate**. If it compiles, the A/V surface is genuinely consumable
//! by the server; if it stops compiling on an edge bump, the surface regressed
//! for every consumer while edge's own suite stayed green. That is the same
//! inside-vs-outside gap that let the mesh-repro harness pass its own prefixes
//! and prove a path production could not take.
//!
//! # The transport-blind seam
//!
//! The spine is transport-blind over `AvLinkSender` / `AvLinkReceiver`, so the
//! interop path needs no Reticulum: we plug in-memory channels. That is the
//! point of the seam — the same code carries real links in production and these
//! in tests, so the thing under test is the spine rather than the transport.

use ciris_edge::transport::realtime_av_dispatcher::{
    AvDispatcherError, AvInboundLink, AvLinkReceiver, AvLinkSender, AvSubscriberLink,
};
use ciris_edge::transport::realtime_av_runtime::{AvPublisher, AvRelay, AvSubscriber};
use ciris_edge::transport::realtime_av_session::AvSession;
use tokio::sync::{mpsc, Mutex};

/// One in-memory link half — the caller-plugged byte stream the dispatcher
/// fans onto. Production plugs a leviculum link here; the spine cannot tell.
struct MemSender(mpsc::UnboundedSender<Vec<u8>>);

#[async_trait::async_trait]
impl AvLinkSender for MemSender {
    async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError> {
        self.0
            .send(bytes.to_vec())
            .map_err(|_| AvDispatcherError::SendFailed("mem link closed".into()))
    }
}

struct MemReceiver(Mutex<mpsc::UnboundedReceiver<Vec<u8>>>);

#[async_trait::async_trait]
impl AvLinkReceiver for MemReceiver {
    async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
        self.0
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| AvDispatcherError::RecvFailed("mem link closed".into()))
    }
}

fn mem_link() -> (MemSender, MemReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    (MemSender(tx), MemReceiver(Mutex::new(rx)))
}

/// Glass-to-glass through the server's dependency on edge: a chunk published by
/// `AvPublisher`, forwarded by `AvRelay` (ciphertext only — the relay never
/// holds the epoch DEK), and reconstructed byte-intact by `AvSubscriber`.
#[tokio::test(flavor = "multi_thread")]
async fn av_spine_publisher_relay_subscriber_from_the_server() {
    let stream = ciris_edge::transport::realtime_av::StreamId([7u8; 32]);

    // ── the session + epoch DEK (X-Wing MLS exporter) ───────────────────────
    let (session, dek) = AvSession::create(stream, "ciris-server-av-publisher", Vec::new())
        .expect("AvSession::create must be reachable from a consumer crate");
    let epoch = session.epoch();
    // AvPublisher::from_session consumes the DEK; the subscriber needs it too.
    let sub_dek = ciris_edge::transport::realtime_av::EpochDek::from_bytes(*dek.as_bytes());

    // ── links: publisher → relay → subscriber ───────────────────────────────
    let (pub_out, relay_in) = mem_link();
    let (relay_out, sub_in) = mem_link();

    let transit_pub_relay = [0x11u8; 32];
    let transit_relay_sub = [0x22u8; 32];

    let mut publisher = AvPublisher::from_session(
        stream,
        session,
        dek,
        vec![AvSubscriberLink {
            subscriber: "ciris-av-relay-1".to_string(),
            transit_key: transit_pub_relay,
            link_id: b"ciris-av-relay-1".to_vec(),
            outbound_send: Box::new(pub_out),
        }],
    )
    .expect("publisher from session");

    assert_eq!(publisher.epoch(), epoch, "epoch must survive construction");
    assert_eq!(publisher.subscriber_count(), 1);

    let relay = AvRelay::new(
        stream,
        vec![AvSubscriberLink {
            subscriber: "ciris-av-subscriber-1".to_string(),
            transit_key: transit_relay_sub,
            link_id: b"ciris-av-subscriber-1".to_vec(),
            outbound_send: Box::new(relay_out),
        }],
    )
    .expect("relay builds");

    // The relay must be PUMPED: `spawn_pump` consumes it and drives the inbound
    // link, decoding each sealed chunk, opening the inbound outer AEAD, and
    // fanning ciphertext downstream. Without this the relay holds a downstream
    // and never reads — which is exactly the silent stall this test caught on
    // its first run, and the reason interop needs a consumer-side e2e at all.
    let _pump = relay.spawn_pump(
        AvInboundLink {
            transit_key: transit_pub_relay,
            link_id: b"ciris-av-relay-1".to_vec(),
            inbound_recv: Box::new(relay_in),
        },
        transit_pub_relay,
        b"ciris-av-relay-1".to_vec(),
    );

    let mut rx = AvSubscriber::subscribe(
        stream,
        &sub_dek,
        &"ciris-av-relay-1".to_string(),
        AvInboundLink {
            transit_key: transit_relay_sub,
            link_id: b"ciris-av-subscriber-1".to_vec(),
            inbound_recv: Box::new(sub_in),
        },
    )
    .expect("subscriber subscribes");

    // ── publish ─────────────────────────────────────────────────────────────
    let frame = b"CIRIS A/V interop frame - server side".as_slice();
    let seq = publisher.publish_opaque(frame).await.expect("publish");

    // ── receive, byte-intact ────────────────────────────────────────────────
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("a chunk must arrive within 10s — the spine is not moving bytes")
        .expect("the receive loop must stay alive");

    assert_eq!(chunk.plaintext, frame, "chunk must arrive byte-intact");
    assert_eq!(chunk.stream_id, stream, "stream id must survive the mesh");
    assert_eq!(chunk.chunk_seq, seq, "chunk seq must survive the mesh");
    assert_eq!(chunk.epoch, epoch, "epoch must survive the mesh");
}
