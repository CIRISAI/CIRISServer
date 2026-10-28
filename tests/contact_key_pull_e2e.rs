//! **A pasted stranger's Key reaches the asker over a real recovery round.**
//!
//! The five-platform cross-chat stage, 2026-10-25: the linux node pasted the
//! Android owner's fedcode v3, got `contacts.awaiting_key_body`, and the Key never
//! arrived. The canonical HELD the stranger's `key:record:v1` row (federation
//! tier), both nodes held each other's `delegates_to(node → humanity-accord)`, and
//! the only peer the linux node had was the canonical — yet no logged hop named
//! the stranger. This drives the exact production path in process: the server's
//! `request_key_body` (edge's `PersistLens::with_replication`), the scheduler's
//! recovery Pull (`send_recovery_pull`), the responder's `subject_holdings`, and
//! the asker's apply.
#![cfg(feature = "test-anchor")]

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use ciris_edge::replication::{
    DirectoryStateAdapter, DriveStep, EnvelopeKind, FederationDirectoryReplicationBridge,
    MutableDirectoryStateAdapter, ReplicationCoordinator, ReplicationMessage, SessionRole,
};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{cohort_scope, identity_type};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::attest::{register_key, KeySigner};

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "ciris_edge=debug,ciris_persist=warn".into()),
            )
            .with_test_writer()
            .try_init();
    });
}

fn genesis_holders() -> Vec<ciris_persist::federation::operational::test_support::Identity> {
    use ciris_persist::federation::operational::test_support::Identity;
    (0..3)
        .map(|i| Identity::new(&format!("test-accord-holder-{i}")))
        .collect()
}

fn arm_test_trust_root() {
    let holders = genesis_holders();
    let eds: Vec<String> = holders
        .iter()
        .map(|h| h.member().ed25519_public_key_base64)
        .collect();
    let pqcs: Vec<String> = holders
        .iter()
        .filter_map(|h| h.member().mldsa65_public_key_base64)
        .collect();
    std::env::set_var("CIRIS_TESTING_MODE", "true");
    std::env::set_var("CIRIS_TEST_TRUST_ROOT", eds.join(","));
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_PQC", pqcs.join(","));
}

fn pen(alias: &str, seed: u8) -> (LocalSigner, String) {
    let ed = SigningKey::from_bytes(&[seed; 32]);
    let key_id = ciris_verify_core::fedcode::derive_key_id(alias, ed.verifying_key().as_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        key_id.clone(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    );
    (signer, key_id)
}

struct Node {
    engine: Arc<Engine>,
    key_id: String,
}

/// A node whose engine key self-registers as `node` (what every boot writes).
async fn node(alias: &str, seed: u8) -> Node {
    let (engine_pen, _) = pen(alias, seed);
    let engine = Arc::new(
        Engine::with_signer(Arc::new(engine_pen), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    let key_id = engine.local_derived_key_id().await.expect("derived key id");
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &key_id,
        identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("node self-registers");
    Node { engine, key_id }
}

/// Copy `who`'s own key-plane rows into `on` (what first contact carries).
async fn carry_key(on: &Node, from: &Engine, key_id: &str) {
    let dir = from.federation_directory();
    let rec = dir
        .lookup_public_key(key_id)
        .await
        .expect("read key")
        .unwrap_or_else(|| panic!("{key_id} held at the source"));
    on.engine
        .federation_directory()
        .put_public_key(ciris_persist::federation::SignedKeyRecord { record: rec })
        .await
        .unwrap_or_else(|e| panic!("{} holds {key_id}: {e}", on.key_id));
}

/// Each node's OWN `delegates_to(node → root)` at federation, held by both.
async fn accept_shared_root(nodes: &[&Node], root: &str, serve_node_key_id: &str) {
    for n in nodes {
        ciris_persist::federation::operational::test_support::establish_trust_root_side(
            n.engine.federation_directory().as_ref(),
            root,
            serve_node_key_id,
            "infra:serve",
        )
        .await
        .expect("root-side trust legs");
        let trust_edge = serde_json::json!({
            "dimension": ciris_persist::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
            "scope": ["infra:attest", "infra:serve"],
        });
        let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(trust_edge)
            .expect("trust edge envelope");
        let mut te = ciris_persist::federation::EmitAttestationInput::with_envelope(
            ciris_persist::federation::types::attestation_type::DELEGATES_TO,
            core,
            cohort_scope::FEDERATION,
        );
        te.attested_key_id = Some(root.to_string());
        te.subject_key_ids = vec![root.to_string()];
        n.engine
            .emit_attestation_self(te)
            .await
            .expect("own delegates_to");
    }
    for n in nodes {
        let mine = n
            .engine
            .federation_directory()
            .list_attestations_by(&n.key_id)
            .await
            .expect("own rows");
        for other in nodes.iter().filter(|o| o.key_id != n.key_id) {
            for row in mine.iter().filter(|a| a.attested_key_id == root) {
                other
                    .engine
                    .federation_directory()
                    .put_attestation(ciris_persist::federation::SignedAttestation {
                        attestation: row.clone(),
                    })
                    .await
                    .expect("peer holds the acceptance");
            }
        }
    }
}

fn bridge(n: &Node) -> Arc<FederationDirectoryReplicationBridge> {
    Arc::new(
        FederationDirectoryReplicationBridge::new(
            n.engine.federation_directory(),
            Arc::new(Vec::new),
        )
        .with_local_key_id(Some(n.key_id.clone())),
    )
}

struct Loopback {
    to_peer: tokio::sync::mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl ciris_edge::transport::Transport for Loopback {
    fn id(&self) -> ciris_edge::transport::TransportId {
        ciris_edge::transport::TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<ciris_edge::transport::TransportSendOutcome, ciris_edge::transport::TransportError>
    {
        let _ = self.to_peer.send(envelope_bytes.to_vec()).await;
        Ok(ciris_edge::transport::TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<ciris_edge::transport::InboundFrame>,
    ) -> Result<(), ciris_edge::transport::TransportError> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

fn msg_name(m: &ReplicationMessage) -> String {
    match m {
        ReplicationMessage::Summary(s) => format!("Summary({} refs)", s.refs.len()),
        ReplicationMessage::Diff(_) => "Diff".into(),
        ReplicationMessage::Deliver(d) => format!("Deliver({:?})", d),
        ReplicationMessage::Fetch(f) => format!("Fetch({})", f.want.len()),
        ReplicationMessage::Pull(p) => format!("Pull({})", p.subject_key_id),
        ReplicationMessage::CursorPull(_) => "CursorPull".into(),
    }
}

async fn send_step(coord: &ReplicationCoordinator, step: &DriveStep) {
    let msgs: &[ReplicationMessage] = match step {
        DriveStep::SendThenWait(m) | DriveStep::SendThenComplete(m, _) => m,
        DriveStep::Complete(_) | DriveStep::Refused => &[],
    };
    for m in msgs {
        coord.send_message(m).await.expect("loopback send");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pasted_strangers_key_arrives_from_the_canonical_over_a_recovery_pull() {
    init_tracing();
    arm_test_trust_root();
    let asker = node("ciris-node-bootstrap-asker", 0x31).await;
    let canonical = node("ciris-canonical-1-probe", 0x41).await;

    // The stranger: a person's fedID, self-registered at the canonical (as the
    // Android owner's key reached it 21:45:43).
    let (stranger_pen, stranger) = pen("qa-node-stranger", 0x51);
    register_key(
        &canonical.engine,
        KeySigner::Local(&stranger_pen),
        &stranger,
        identity_type::USER,
        serde_json::Value::Null,
    )
    .await
    .expect("stranger registered at the canonical");

    // First contact: each holds the other's Key, and both accept one root.
    carry_key(&canonical, &asker.engine, &asker.key_id).await;
    carry_key(&asker, &canonical.engine, &canonical.key_id).await;
    accept_shared_root(&[&asker, &canonical], "probe-root", &canonical.key_id).await;

    assert!(
        asker
            .engine
            .federation_directory()
            .lookup_public_key(&stranger)
            .await
            .unwrap()
            .is_none(),
        "precondition: the asker does not hold the stranger"
    );

    let asker_bridge = bridge(&asker);
    let canon_bridge = bridge(&canonical);

    // What the canonical would serve to this requester, asked directly.
    let direct = ciris_edge::replication::StateProvider::subject_refs(
        &DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(asker.key_id.clone()),
        EnvelopeKind::Key,
        &stranger,
    )
    .await;
    eprintln!(
        "canonical subject_refs(Key, stranger) for the asker: {} ref(s)",
        direct.len()
    );

    // The server's contacts path, verbatim.
    let asker_dir = asker.engine.federation_directory();
    let lens = ciris_edge::contact::PersistLens::new(asker_dir.as_ref())
        .with_replication(asker_bridge.clone());
    assert!(
        ciris_edge::contact::DirectoryLens::request_key_body(&lens, &stranger).await,
        "the asker queues the Key Pull"
    );

    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (c_tx, mut c_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let asker_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: c_tx }),
        canonical.key_id.clone(),
        EnvelopeKind::Key,
        SessionRole::Initiator,
        Arc::new(
            DirectoryStateAdapter::new(asker_bridge.clone()).with_peer(canonical.key_id.clone()),
        ),
        Arc::new(MutableDirectoryStateAdapter::new(asker_bridge.clone())),
    );
    let canon_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: a_tx }),
        asker.key_id.clone(),
        EnvelopeKind::Key,
        SessionRole::Responder,
        Arc::new(DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(asker.key_id.clone())),
        Arc::new(MutableDirectoryStateAdapter::new(canon_bridge)),
    );

    // The scheduler's recovery round (run_one_recovery_round), by hand.
    asker_coord.begin_round().await;
    let pulled = asker_coord
        .send_recovery_pull()
        .await
        .expect("recovery pull sends");
    assert_eq!(
        pulled.as_deref(),
        Some(stranger.as_str()),
        "the queued name is Pulled"
    );

    for _ in 0..24 {
        let mut progressed = false;
        while let Ok(bytes) = c_rx.try_recv() {
            let msg =
                ReplicationCoordinator::parse_inbound_bytes(&bytes).expect("parse at canonical");
            eprintln!("  canonical <- {}", msg_name(&msg));
            let s = canon_coord
                .drive_round_step(Some(msg))
                .await
                .expect("responder step");
            eprintln!("  canonical => {s:?}");
            send_step(&canon_coord, &s).await;
            progressed = true;
        }
        while let Ok(bytes) = a_rx.try_recv() {
            let msg = ReplicationCoordinator::parse_inbound_bytes(&bytes).expect("parse at asker");
            eprintln!("  asker <- {}", msg_name(&msg));
            let s = asker_coord
                .drive_round_step(Some(msg))
                .await
                .expect("initiator step");
            eprintln!("  asker => {s:?}");
            send_step(&asker_coord, &s).await;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    let held = asker
        .engine
        .federation_directory()
        .lookup_public_key(&stranger)
        .await
        .unwrap();
    assert!(
        held.is_some(),
        "the stranger's Key reached the asker (canonical offered {} ref(s) directly)",
        direct.len()
    );
}

/// Drive `asker` ↔ `canonical` until neither side has anything left to send.
async fn pump(
    asker_coord: &ReplicationCoordinator,
    a_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    canon_coord: &ReplicationCoordinator,
    c_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    for _ in 0..24 {
        let mut progressed = false;
        while let Ok(bytes) = c_rx.try_recv() {
            let msg =
                ReplicationCoordinator::parse_inbound_bytes(&bytes).expect("parse at canonical");
            let s = canon_coord
                .drive_round_step(Some(msg))
                .await
                .expect("responder step");
            send_step(canon_coord, &s).await;
            progressed = true;
        }
        while let Ok(bytes) = a_rx.try_recv() {
            let msg = ReplicationCoordinator::parse_inbound_bytes(&bytes).expect("parse at asker");
            let s = asker_coord
                .drive_round_step(Some(msg))
                .await
                .expect("initiator step");
            send_step(asker_coord, &s).await;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
}

/// **The recovery queue starves a pasted contact; a direct Key Pull does not.**
///
/// The five-platform run of 2026-10-26: linux's recovery queue held 270 names
/// the canonical's own rows had delivered, and each Key round took ONE — always
/// a name the peer delivered before an unrouted one, and a contact paste is
/// unrouted. The canonical held the contact's key the whole time and was never
/// asked (tracked: CIRISEdge#904). The pending-contacts pass now sends each
/// peer a Key-plane subject Pull directly (`start_pull`), which is what this
/// drives after showing the queue's pick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_key_pull_reaches_a_contact_the_recovery_queue_starves() {
    use ciris_edge::replication::ReplicationDirectory;
    init_tracing();
    arm_test_trust_root();
    let asker = node("ciris-node-bootstrap-starved", 0x32).await;
    let canonical = node("ciris-canonical-1-starve", 0x42).await;
    let (stranger_pen, stranger) = pen("qa-node-starved-contact", 0x52);
    register_key(
        &canonical.engine,
        KeySigner::Local(&stranger_pen),
        &stranger,
        identity_type::USER,
        serde_json::Value::Null,
    )
    .await
    .expect("stranger registered at the canonical");
    carry_key(&canonical, &asker.engine, &asker.key_id).await;
    carry_key(&asker, &canonical.engine, &canonical.key_id).await;
    accept_shared_root(&[&asker, &canonical], "starve-root", &canonical.key_id).await;

    let asker_bridge = bridge(&asker);
    let canon_bridge = bridge(&canonical);

    // The contact paste (unrouted), then a name the canonical's rows delivered.
    let asker_dir = asker.engine.federation_directory();
    let lens = ciris_edge::contact::PersistLens::new(asker_dir.as_ref())
        .with_replication(asker_bridge.clone());
    assert!(ciris_edge::contact::DirectoryLens::request_key_body(&lens, &stranger).await);
    asker_bridge.note_missing_signer(
        EnvelopeKind::Attestation,
        "ciris-gate-peer-unmet",
        Some(&canonical.key_id),
    );

    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (c_tx, mut c_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let asker_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: c_tx }),
        canonical.key_id.clone(),
        EnvelopeKind::Key,
        SessionRole::Initiator,
        Arc::new(
            DirectoryStateAdapter::new(asker_bridge.clone()).with_peer(canonical.key_id.clone()),
        ),
        Arc::new(MutableDirectoryStateAdapter::new(asker_bridge.clone())),
    );
    let canon_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: a_tx }),
        asker.key_id.clone(),
        EnvelopeKind::Key,
        SessionRole::Responder,
        Arc::new(DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(asker.key_id.clone())),
        Arc::new(MutableDirectoryStateAdapter::new(canon_bridge)),
    );

    // The queue's pick. Before edge's CIRISEdge#904 fix the routed name won and
    // the person's contact waited; with it, a name a person is waiting on is
    // asked first. Either way the direct Pull below lands the key, so the
    // pending-contacts pass works on both sides of that edge release.
    asker_coord.begin_round().await;
    let pulled = asker_coord
        .send_recovery_pull()
        .await
        .expect("recovery pull");
    assert!(
        matches!(pulled.as_deref(), Some("ciris-gate-peer-unmet"))
            || pulled.as_deref() == Some(stranger.as_str()),
        "the recovery queue took a queued name: {pulled:?}"
    );
    pump(&asker_coord, &mut a_rx, &canon_coord, &mut c_rx).await;
    if pulled.as_deref() == Some(stranger.as_str()) {
        assert!(
            asker_dir
                .lookup_public_key(&stranger)
                .await
                .unwrap()
                .is_some(),
            "edge #904: the person's contact was asked first and arrived"
        );
    } else {
        assert!(
            asker_dir
                .lookup_public_key(&stranger)
                .await
                .unwrap()
                .is_none(),
            "a round spent on the routed name did not bring the contact's key"
        );
    }

    // The pending-contacts pass's direct Pull.
    asker_coord
        .start_pull(&stranger)
        .await
        .expect("direct Key Pull sends");
    pump(&asker_coord, &mut a_rx, &canon_coord, &mut c_rx).await;
    assert!(
        asker_dir
            .lookup_public_key(&stranger)
            .await
            .unwrap()
            .is_some(),
        "the direct Key Pull brought the contact's key from the canonical"
    );
}

/// **A contact's announced owner-binding reaches the asker on a subject Pull.**
///
/// The five-platform run of 2026-10-26: after the add, linux held the android
/// owner's Key but not their `delegates_to(owner → node)` at federation, so the
/// contact request (a directed consent grant) had no node to reach. The
/// canonical held the binding, but refused an Attestation subject Pull (not
/// publicly pullable) and its advertise walk was ~20 min behind (tracked:
/// CIRISEdge#907). The pending-contacts pass asks with exactly this Pull.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_contacts_announced_owner_binding_arrives_on_a_subject_pull() {
    use ciris_server::auth::ownership::{
        announced_nodes_of, apply_signed_owner_binding, build_signed_owner_binding,
        promote_owner_binding_to_federation, OWNER_BINDING_INFRA_SCOPES,
    };
    init_tracing();
    arm_test_trust_root();
    let asker = node("ciris-node-bootstrap-resolver", 0x33).await;
    let canonical = node("ciris-canonical-1-resolve", 0x43).await;

    // The contact: a person who announced one node, as the canonical holds them.
    let (contact_pen, contact) = pen("qa-node-resolve-contact", 0x53);
    let (contact_node_pen, contact_node) = pen("ciris-node-bootstrap-contact", 0x63);
    for (p, id, ty) in [
        (&contact_pen, &contact, identity_type::USER),
        (&contact_node_pen, &contact_node, identity_type::NODE),
    ] {
        register_key(
            &canonical.engine,
            KeySigner::Local(p),
            id,
            ty,
            serde_json::Value::Null,
        )
        .await
        .expect("contact keys registered at the canonical");
    }
    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let binding =
        build_signed_owner_binding(&contact_pen, &contact_node, &scopes, cohort_scope::SELF)
            .await
            .expect("binding");
    apply_signed_owner_binding(
        &canonical.engine,
        &contact_node,
        cohort_scope::SELF,
        ciris_persist::prelude::HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("the canonical holds the contact's binding");
    promote_owner_binding_to_federation(&canonical.engine, &contact_pen, &contact_node)
        .await
        .expect("the contact announced");
    assert!(
        announced_nodes_of(&canonical.engine, &contact)
            .await
            .unwrap()
            .contains(&contact_node),
        "precondition: the canonical resolves the contact to their node"
    );

    // The asker after the add: it holds the contact's Key, not their binding.
    carry_key(&canonical, &asker.engine, &asker.key_id).await;
    carry_key(&asker, &canonical.engine, &canonical.key_id).await;
    carry_key(&asker, &canonical.engine, &contact).await;
    // NOT the contact's node key: the 2026-10-27 run's asker held the person's
    // key (the add) but not their node's, and persist refused the binding. The
    // node is named by the contact code (`owned_nodes`); its key is pulled first.
    accept_shared_root(&[&asker, &canonical], "resolve-root", &canonical.key_id).await;
    assert!(
        announced_nodes_of(&asker.engine, &contact)
            .await
            .unwrap()
            .is_empty(),
        "precondition: the asker resolves the contact to no node"
    );

    let asker_bridge = bridge(&asker);
    // The canonical publishes every announced node, as compose installs it in
    // production (`announced_relay::selector`); edge serves a third party's
    // owner-binding only for a node the responder publishes (#752 / #907).
    let canon_bridge = Arc::new(
        FederationDirectoryReplicationBridge::new(
            canonical.engine.federation_directory(),
            Arc::new(Vec::new),
        )
        .with_local_key_id(Some(canonical.key_id.clone()))
        .with_kind_publish_selector(Some(
            ciris_server::announced_relay::selector_for_sets(
                vec![canonical.key_id.clone()],
                Some(ciris_server::announced_relay::RelaySets {
                    announced_nodes: vec![contact_node.clone()],
                    owners: vec![contact.clone()],
                }),
            ),
        )),
    );
    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (c_tx, mut c_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let asker_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: c_tx }),
        canonical.key_id.clone(),
        EnvelopeKind::Attestation,
        SessionRole::Initiator,
        Arc::new(
            DirectoryStateAdapter::new(asker_bridge.clone()).with_peer(canonical.key_id.clone()),
        ),
        Arc::new(MutableDirectoryStateAdapter::new(asker_bridge.clone())),
    );
    let canon_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: a_tx }),
        asker.key_id.clone(),
        EnvelopeKind::Attestation,
        SessionRole::Responder,
        Arc::new(DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(asker.key_id.clone())),
        Arc::new(MutableDirectoryStateAdapter::new(canon_bridge.clone())),
    );

    // The resolve pass: the code's node key first (Key plane, public), then the
    // person's records again.
    let (ka_tx, mut ka_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (kc_tx, mut kc_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let asker_key_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: kc_tx }),
        canonical.key_id.clone(),
        EnvelopeKind::Key,
        SessionRole::Initiator,
        Arc::new(
            DirectoryStateAdapter::new(asker_bridge.clone()).with_peer(canonical.key_id.clone()),
        ),
        Arc::new(MutableDirectoryStateAdapter::new(asker_bridge.clone())),
    );
    let canon_key_coord = ReplicationCoordinator::new(
        Arc::new(Loopback { to_peer: ka_tx }),
        asker.key_id.clone(),
        EnvelopeKind::Key,
        SessionRole::Responder,
        Arc::new(DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(asker.key_id.clone())),
        Arc::new(MutableDirectoryStateAdapter::new(canon_bridge.clone())),
    );
    asker_key_coord
        .start_pull(&contact_node)
        .await
        .expect("Key subject Pull for the code's node sends");
    pump(&asker_key_coord, &mut ka_rx, &canon_key_coord, &mut kc_rx).await;
    assert!(
        asker_dir_holds(&asker, &contact_node).await,
        "the code's node key arrived on the public Key plane"
    );
    // Then what `pull_subject_testimony(canonical, contact)` sends on the
    // Attestation plane. Asked BEFORE the node key, persist refuses the binding
    // (`attested_key_id … resolves as neither` — the 2026-10-27 deadlock) and
    // edge then backs off re-asking it (CIRISEdge#544).
    asker_coord
        .start_pull(&contact)
        .await
        .expect("the person-records Pull");
    pump(&asker_coord, &mut a_rx, &canon_coord, &mut c_rx).await;

    assert!(
        announced_nodes_of(&asker.engine, &contact)
            .await
            .unwrap()
            .contains(&contact_node),
        "the contact's announced owner-binding reached the asker on a subject Pull, so a \
         directed grant naming them has a node to reach (tracked: CIRISEdge#907)"
    );
}

async fn asker_dir_holds(n: &Node, key_id: &str) -> bool {
    matches!(
        n.engine
            .federation_directory()
            .lookup_public_key(key_id)
            .await,
        Ok(Some(_))
    )
}
