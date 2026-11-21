//! The directory seat: the bare minimum a seated serve node does so that a node can join the mesh.
//!
//! It holds one kind of thing, a node's own registration (its `key:record`, its signed `transport_destination`
//! binding and, for an announced node, the owner-binding that announces it), and it does four things with it:
//! admit, answer, refer and copy between replicas. It signs nothing and decides nothing the rows do not decide.
//!
//! Every function in `seat` and `client` is traced to `tla/DirectorySeat.tla` by a `@tla <Name>` line (or opts out
//! with `@tla-none: <reason>`); `scripts/trace_check.py` fails the build when the two sides disagree.

pub mod client;
pub mod seat;

/// `key_id` = H(composite public key) (CC 2.6.1). The seat recomputes it; it never takes it from the row.
pub type KeyId = [u8; 32];
/// A Reticulum destination hash (CC 3.3.6.3).
pub type TransportId = [u8; 16];

/// A key's own record of this form. Self-signed; liveness only by a record of this form (CEREMONY.md section 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_id: KeyId,
    pub composite_pubkey: Vec<u8>,
    pub valid_until_ms: u64,
    pub signature: Vec<u8>,
}

/// The node's signed identity occurrence carrying `transport_destination` (CC 3.3.6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub key_id: KeyId,
    pub transport: TransportId,
    pub transit_xwing_pubkey: Vec<u8>,
    pub onion_hop_xwing_pubkey: Option<Vec<u8>>,
    /// `onion_relay: {opt_out: true}` absent. An owner's relay offer is what lets a forwarder refer the route.
    pub relay_offered: bool,
    /// The signed instant; the newest wins (TLA+ `ver`). Never the arrival order.
    pub asserted_at_ms: u64,
    pub signature: Vec<u8>,
}

/// The owner's `delegates_to(owner -> node)` at `cohort_scope: federation`, with the owner's record: the announce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    pub owner: KeyRecord,
    pub owner_binding: Vec<u8>,
}

/// One message: the record and the route together, so no route ever arrives before its key (the refusal class
/// behind the canonical's redelivery loops and CIRISEdge#1004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub record: KeyRecord,
    pub binding: Binding,
    pub announce: Option<Announce>,
}

/// The crypto the seat needs, and only this. Implemented over ciris-verify in production.
pub trait Verifier {
    fn key_id_of(&self, composite_pubkey: &[u8]) -> KeyId;
    fn verify(&self, signer: &KeyRecord, message: &[u8], signature: &[u8]) -> bool;
    /// Signing bytes of a row (deterministic CBOR, CC 2.6.1.2).
    fn record_bytes(&self, r: &KeyRecord) -> Vec<u8>;
    fn binding_bytes(&self, b: &Binding) -> Vec<u8>;
    /// The owner-binding names this node, is at federation scope, is live and verifies under `owner`.
    fn announces(&self, a: &Announce, node: &KeyId, now_ms: u64) -> bool;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    KeyIdMismatch,
    BadRecordSignature,
    BadBindingSignature,
    BindingNamesAnotherKey,
    RecordExpired,
    BadAnnounce,
}
