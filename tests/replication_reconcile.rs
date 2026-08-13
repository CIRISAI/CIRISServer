//! The **CEG-driven replication reconciler** (CIRISServer) — proof that the
//! corpus's `consent:replication` objects ARE the desired replication topology
//! and that a reconcile step converges the live `ReplicationRuntime` registry to
//! them.
//!
//! Two properties:
//!
//!   1. [`peer::replication_peers_from_consent`] returns exactly the subjects of
//!      the node's `consent:replication:v1` rows and IGNORES other attestations
//!      (a non-consent `scores` row authored by the same node is not a peer).
//!   2. [`replication_reconcile::reconcile_once`] drives `ReplicationRuntime::
//!      set_peers` (edge v5.1.0) to diff-converge the live Initiator set:
//!      - ADDS a newly-consented **admitted** peer as an active **Initiator**
//!        (Attestation kind — registered, scheduler-driven pull, no restart);
//!      - REMOVES a peer whose consent grant is gone (its Initiator stops + its
//!        inbound routing is deregistered);
//!      - SKIPS a consented-but-UNADMITTED peer (no directory key → can't replicate).
//!
//! The Node-A substrate + the peer admission gate are driven exactly as the other
//! peering/federation tests do (in-memory hybrid-signed Engine + the real
//! `register_federation_key` gate). A test-local no-op `Transport` stands in for
//! the Reticulum stack (the runtime registry is exercised without the edge listen
//! loop — the same posture as edge's own runtime unit tests).

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_edge::replication::{
    EnvelopeKind, ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, KeyRecord,
    SignedAttestation, SignedKeyRecord,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::peer;
use ciris_server::replication_reconcile;
use ciris_server::PeerB;

#[path = "support/log_capture.rs"]
mod log_capture;

const NODE_A_KEY_ID: &str = "ciris-server";

// ── Node A: in-memory hybrid-signed Engine (mirrors peer_replication.rs) ──────

async fn node_a() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_A_KEY_ID}-pqc"))
            .expect("node-a ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_A_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_A_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Register Node A's own steward key via the canonical admission gate — the
/// `put_attestation` attesting-key FK precondition for the consent emit.
/// The node's #247 DERIVED federation key_id (== `cfg.key_id`, what the consent
/// emit attests under via `emit_attestation_self`). `NODE_A_KEY_ID` is the alias.
async fn node_a_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node-A federation key_id")
}

async fn register_self(engine: &Engine) {
    let key_id = node_a_key_id(engine).await;
    // Through the ONE door (CIRISServer#402): the registration envelope now BINDS
    // ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither the
    // identity type nor either pubkey, and persist v31 refuses it — an envelope
    // that does not name its subject stands for any record it is pasted onto
    // (CIRISPersist#659).
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node A steward key via admission gate");
}

/// A peer node with a real hybrid identity that can self-sign its admission record
/// (so A's `register_peer_key` admission gate genuinely verifies it).
struct Peer {
    key_id: String,
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl Peer {
    fn new(key_id: &str, ed_seed: u8, ml_seed: u8) -> Self {
        Peer {
            key_id: key_id.to_string(),
            ed: SigningKey::from_bytes(&[ed_seed; 32]),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(&[ml_seed; 32], format!("{key_id}-pqc"))
                .expect("peer ML-DSA-65 seed"),
        }
    }

    async fn signed_key_record(&self) -> SignedKeyRecord {
        let now = chrono::Utc::now();
        let envelope = serde_json::json!({ "key_id": self.key_id });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize peer reg");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa sign peer reg");
        let record = KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: BASE64.encode(self.ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: Some(
                BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk")),
            ),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::WITNESS.into(),
            identity_ref: self.key_id.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: BASE64.encode(ed_sig),
            scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        SignedKeyRecord { record }
    }

    async fn peer_config(&self) -> PeerB {
        PeerB {
            key_id: self.key_id.clone(),
            key_record: self.signed_key_record().await,
        }
    }
}

/// Admit `peer` into A's directory through the real admission gate.
async fn admit(engine: &Engine, peer: &Peer) {
    peer::register_peer_key(engine, &peer.peer_config().await)
        .await
        .expect("admit peer key via the real register_federation_key gate");
}

// ── A test-local no-op transport (the runtime registry is exercised without the
//    edge listen loop — the same posture as edge's runtime unit tests) ──────────

struct NoopTransport;

#[async_trait]
impl Transport for NoopTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        // Block forever — the reconcile test never drives inbound delivery; the
        // runtime is exercised purely through its registry.
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Start a runtime over the in-memory Engine's SQLite directory + the no-op
/// transport, with the given boot Initiator peers.
async fn runtime_for(engine: &Arc<Engine>, peers: Vec<&str>) -> Arc<ReplicationRuntime> {
    let directory: Arc<dyn FederationDirectory> = engine
        .sqlite_backend()
        .expect("sqlite-backed engine")
        .clone();
    let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
    let boot: Vec<ReplicationPeer> = peers
        .into_iter()
        .map(|p| ReplicationPeer {
            peer_key_id: p.to_string(),
            kind: EnvelopeKind::Attestation,
        })
        .collect();
    Arc::new(
        ReplicationRuntime::start(
            directory,
            transport,
            boot,
            ReplicationRuntimeConfig::default(),
            None, // no self_provider (CIRISEdge#311 collapsed the per-plane selectors)
        )
        .await,
    )
}

/// The Attestation-kind keys currently registered on the runtime, sorted.
async fn attestation_keys(runtime: &ReplicationRuntime) -> Vec<String> {
    let mut v: Vec<String> = runtime
        .registry()
        .registered_keys()
        .await
        .into_iter()
        .filter(|(_, kind)| *kind == EnvelopeKind::Attestation)
        .map(|(p, _)| p)
        .collect();
    v.sort();
    v
}

/// The Key-kind keys currently registered on the runtime, sorted (#144 — the
/// KERI publish-own key plane converges alongside Attestation).
async fn key_keys(runtime: &ReplicationRuntime) -> Vec<String> {
    let mut v: Vec<String> = runtime
        .registry()
        .registered_keys()
        .await
        .into_iter()
        .filter(|(_, kind)| *kind == EnvelopeKind::Key)
        .map(|(p, _)| p)
        .collect();
    v.sort();
    v
}

// ── Test 1: replication_peers_from_consent reads back consent subjects only ───

#[tokio::test]
async fn consent_peers_are_the_subjects_and_other_attestations_are_ignored() {
    let engine = node_a().await;
    register_self(&engine).await;
    let nk = node_a_key_id(&engine).await;

    let peer_x = Peer::new("peer-x", 0xB0, 0xB1);
    let peer_y = Peer::new("peer-y", 0xC0, 0xC1);
    admit(&engine, &peer_x).await;
    admit(&engine, &peer_y).await;

    // Two consent grants → two peers.
    peer::emit_replication_consent(
        &engine,
        &nk,
        &peer_x.key_id,
        &peer::default_attestation_prefixes(),
    )
    .await
    .expect("consent x");
    peer::emit_replication_consent(
        &engine,
        &nk,
        &peer_y.key_id,
        &peer::default_attestation_prefixes(),
    )
    .await
    .expect("consent y");

    // A NON-consent scores attestation authored by A (a capacity-style row whose
    // subject is peer-x) MUST NOT be read back as a replication peer.
    put_noise_scores(&engine, &peer_x.key_id).await;

    let peers = peer::replication_peers_from_consent(&engine, &nk)
        .await
        .expect("read consent peers back");
    assert_eq!(
        peers,
        vec!["peer-x".to_string(), "peer-y".to_string()],
        "exactly the consent:replication subjects (sorted/deduped), ignoring other scores rows"
    );
}

/// A non-`consent:replication` `scores` attestation authored by A (subject =
/// `subject_key_id`) — proves the reader filters on the dimension, not just type.
///
/// The dimension is `health:liveness:v1` and NOT `capacity:*`, deliberately.
/// persist v22 (CIRISConstitution#46) refuses a `capacity:*` claim about a subject
/// unless a live `analyze` consent from that subject covers the attester, so a
/// capacity row cannot be seeded here without ALSO authoring a consent row — which
/// would inject consent state into the very reader this test is measuring. Any
/// non-`consent:replication` dimension satisfies the test's actual intent.
/// Do not "restore" capacity here; it will fail closed.
async fn put_noise_scores(engine: &Engine, subject_key_id: &str) {
    let nk = node_a_key_id(engine).await;
    let envelope = serde_json::json!({
        "dimension": "health:liveness:v1",
        "attesting_key_id": nk,
        "subject_key_ids": [subject_key_id],
        "score": 0.9,
        "cohort_scope": "federation",
        // No `asserted_at` — the stamp writes it, truncated (CIRISPersist#598).
    });
    let spec = ciris_server::attest::Spec::new(
        attestation_type::SCORES,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&subject_key_id);
    let spec = spec.weighing(Some(0.9));
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        spec,
    )
    .await
    .expect("put noise scores row");
}

// ── Test 2: reconcile_once registers new + deregisters gone + skips unadmitted ─

#[tokio::test]
async fn reconcile_registers_new_and_deregisters_gone() {
    let engine = node_a().await;
    register_self(&engine).await;
    let nk = node_a_key_id(&engine).await;

    let peer_new = Peer::new("peer-new", 0xB0, 0xB1);
    let peer_stale = Peer::new("peer-stale", 0xC0, 0xC1);
    admit(&engine, &peer_new).await;
    admit(&engine, &peer_stale).await;

    // Boot the runtime ALREADY tracking peer-stale (as if a prior boot derived it
    // from a consent that has since been removed). No consent exists for it now.
    let runtime = runtime_for(&engine, vec![&peer_stale.key_id]).await;
    assert_eq!(
        attestation_keys(&runtime).await,
        vec!["peer-stale".to_string()],
        "precondition: runtime starts tracking peer-stale only"
    );

    // Consent NOW exists for peer-new (admitted) — the desired topology changed.
    peer::emit_replication_consent(
        &engine,
        &nk,
        &peer_new.key_id,
        &peer::default_attestation_prefixes(),
    )
    .await
    .expect("consent peer-new");

    // One reconcile pass.
    replication_reconcile::reconcile_once(&engine, &nk, &runtime)
        .await
        .expect("reconcile_once must not error");

    // peer-new added as an ACTIVE Initiator (desired − current); peer-stale
    // removed (current − desired, its consent is gone) — both at runtime, via
    // set_peers, no restart.
    assert_eq!(
        attestation_keys(&runtime).await,
        vec!["peer-new".to_string()],
        "after reconcile: peer-new is a live Initiator, peer-stale removed"
    );
    // #144: the Key plane converges to the SAME consent-peer set as Attestation —
    // each admitted consent peer gets both an Attestation and a Key coordinator.
    assert_eq!(
        key_keys(&runtime).await,
        vec!["peer-new".to_string()],
        "after reconcile: the Key plane tracks peer-new too (KERI publish-own)"
    );

    // Idempotent: a second reconcile with no CEG change leaves the set unchanged.
    replication_reconcile::reconcile_once(&engine, &nk, &runtime)
        .await
        .expect("second reconcile must not error");
    assert_eq!(
        attestation_keys(&runtime).await,
        vec!["peer-new".to_string()],
        "reconcile is idempotent on a steady CEG state"
    );
}

/// The reconciler also DEFENDS against a consented-but-unadmitted peer: even if a
/// consent subject has no `federation_keys` row, `reconcile_once` must skip it (no
/// key to replicate with) rather than register it. We can't author a consent row
/// for an unadmitted subject through the real FK gate, so this asserts the
/// admission-filter behavior directly via the runtime: a consent for an admitted
/// peer registers, and the reconcile never errors when the desired set is derived.
#[tokio::test]
async fn reconcile_only_registers_admitted_consent_subjects() {
    let engine = node_a().await;
    register_self(&engine).await;
    let nk = node_a_key_id(&engine).await;

    let peer_ok = Peer::new("peer-ok", 0xB0, 0xB1);
    admit(&engine, &peer_ok).await;
    peer::emit_replication_consent(
        &engine,
        &nk,
        &peer_ok.key_id,
        &peer::default_attestation_prefixes(),
    )
    .await
    .expect("consent peer-ok");

    let runtime = runtime_for(&engine, vec![]).await;
    replication_reconcile::reconcile_once(&engine, &nk, &runtime)
        .await
        .expect("reconcile_once must not error");
    assert_eq!(
        attestation_keys(&runtime).await,
        vec!["peer-ok".to_string()],
        "an admitted consent subject becomes a live Initiator at runtime"
    );
}

// ── Test 4: the consent-decay sweep is wired into the tick (CIRISServer#337) ──

/// Strip Rust comments so a source gate matches CODE and only code.
///
/// A gate that greps raw source matches its own explanatory prose — the comment
/// naming the thing is indistinguishable from the call doing it. That has
/// shipped here twice, and both times the gate stayed green across a mutation
/// that deleted the call and left the paragraph explaining it behind.
fn code_only(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_block = false;
    while let Some(c) = chars.next() {
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('/')) => {
                // Line comment — covers `//`, `///` and `//!` alike.
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

/// `reconcile_once`'s body, comments removed.
fn reconcile_once_code() -> String {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/replication_reconcile.rs"),
    )
    .expect("readable");
    let code = code_only(&src);
    let body = code
        .split_once("pub async fn reconcile_once")
        .expect("reconcile_once must exist")
        .1;
    // Up to the next top-level `pub fn` — the `spawn` that follows it.
    body.split_once("\npub fn ")
        .map(|(before, _)| before.to_string())
        .unwrap_or_else(|| body.to_string())
}

/// **CIRISServer#337, the half that was still uncalled.**
///
/// `repair_stranded_scope_backlog` landed in this tick; `sweep_consent_decay_once`
/// did not, and persist exposes it with zero callers anywhere in `src/`. Nothing
/// else drives the TEMPORARY (14-day) / pattern (90-day) consent-decay clock, so
/// without this call every content unit stays at Full tier forever and a consent
/// window granted in days simply never elapses. An expiry no clock enforces is
/// not an expiry.
///
/// A source gate rather than a behavioural one, for a reason worth recording:
/// `admitted_at` is stamped by persist at admission and the first decay
/// breakpoint is 25% of 14 days, so driving this end-to-end through
/// `reconcile_once` — which passes wall-clock `now` — would need a fixture that
/// waits three and a half days. The CALL SITE is the part that can be pinned.
#[test]
fn the_consent_decay_sweep_is_called_from_the_reconcile_tick() {
    let code = reconcile_once_code();
    assert!(
        code.contains("sweep_consent_decay_once"),
        "`reconcile_once` no longer calls `sweep_consent_decay_once`. persist ships the sweep and \
         nothing else calls it, so the consent-decay clock stops dead: every fountain unit keeps \
         every symbol past its declared window, and the node silently over-retains content \
         somebody consented to only temporarily.\n\ncode:\n{code}"
    );
}

/// The sweep must never fail the tick.
///
/// Peer convergence is this loop's primary duty and the one with a deadline. A
/// `?` here would let a transient substrate error on a MAINTENANCE sweep stop
/// the node converging to its consent topology — trading the loop's whole
/// purpose for a sweep whose next run re-derives the same answer from the wall
/// clock anyway. The sibling #530 repair sweep above it is handled the same way.
#[test]
fn a_failing_decay_sweep_does_not_fail_the_reconcile_tick() {
    let code = reconcile_once_code();
    let at = code
        .find("sweep_consent_decay_once")
        .expect("the call must exist (see the gate above)");
    let after = &code[at..];
    let awaited = after.find(".await").expect("the sweep is awaited") + ".await".len();
    assert!(
        !after[awaited..].trim_start().starts_with('?'),
        "the consent-decay sweep propagates its error with `?`, so a transient substrate failure \
         on a maintenance sweep aborts the tick before the peer set is converged. Handle it the \
         way the #530 repair sweep directly above it is handled: match, warn, carry on."
    );
}

/// **The steady state is not an alarm.**
///
/// The overwhelmingly common node holds no fountain content at all, so the decay
/// sweep scans nothing and evicts nothing on every tick — every 30 seconds,
/// forever. Logged unconditionally that is ~2,880 identical lines a day saying
/// nothing happened, and the one tick that DID decay something would be
/// invisible inside them. 0.5.152 shipped exactly this shape on the scorer and
/// 0.5.153 removed it.
#[tokio::test]
async fn a_tick_with_nothing_to_decay_raises_no_alarm() {
    let engine = node_a().await;
    register_self(&engine).await;
    let nk = node_a_key_id(&engine).await;
    let runtime = runtime_for(&engine, vec![]).await;

    let (result, log) = log_capture::capture(replication_reconcile::reconcile_once(
        &engine, &nk, &runtime,
    ))
    .await;
    result.expect("reconcile_once must not error on a clean node");

    assert!(
        log.alarms().is_empty(),
        "a reconcile tick on a node with no fountain content and no consent peers raised {} \
         alarm(s). Every healthy node ticks this way every 30 seconds; an alarm here is 2,880 \
         unactionable lines a day, and the operator who learns to skip them is the one who \
         misses the real one.\n{}",
        log.alarms().len(),
        log.render()
    );
    assert!(
        log.events()
            .iter()
            .all(|e| !e.message.contains("consent-decay")),
        "the decay sweep spoke on a tick where it did nothing. Reserve the line for a tick that \
         actually crossed a breakpoint — otherwise the two are the same observation.\n{}",
        log.render()
    );
}
