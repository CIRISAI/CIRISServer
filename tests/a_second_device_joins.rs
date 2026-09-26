//! **A second device, approved on the first** (CIRISServer#678).
//!
//! The maintainer's goal for 0.5.218: sign in with a fed-ID on a second device
//! by approving a request on the first, and files just show up. The first
//! device claims the second through `POST /v1/setup/claim-remote`; these pin
//! the three things that did not follow from the claim:
//!
//! 1. **Linked without a grant, without a reboot.** The owner's other node is a
//!    replication initiator on the next reconcile pass — read from the
//!    owner-bindings (`own_device_peers`), with no `consent:replication` row —
//!    and a release (the owner's `withdraws` of the binding) unlinks it. The
//!    claim handler converges before it kicks (a source gate: the nudge, not a
//!    bare kick, follows the local record).
//! 2. **Old self files re-wrap for the new device.** Two engines: the second
//!    device provisions its content occurrence, the SIGNED row crosses to the
//!    first, and the first — only once the owner's pen opens there — re-wraps
//!    every self file written before the claim to it. Idempotent.
//! 3. **Announce another device from the one holding the pen.**
//!    `POST /v1/self/nodes/{node}/announce` re-signs that node's owner-binding
//!    at `federation`; idempotent; a node that is not the caller's is refused
//!    by name.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_edge::replication::{
    EnvelopeKind, ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig, SessionRole,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{attestation_type, cohort_scope, identity_type};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::wa_cert::WaRole;
use ed25519_dalek::SigningKey;

#[allow(dead_code)] // one fixture, several binaries: each uses a different subset
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

// ── helpers ────────────────────────────────────────────────────────────────

/// A second node's substrate, keyed by its own hybrid signer.
async fn other_engine(alias: &str, ed: u8, pqc: u8) -> Arc<Engine> {
    let pqc_signer = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[ed; 32]),
        alias.to_string(),
        Some(pqc_signer),
        Some(format!("{alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

fn infra_scopes() -> Vec<String> {
    ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The owner-binding claim-remote records LOCALLY for the target: user-signed,
/// at `self` (`record_claimed_target_locally`).
async fn record_claim_locally(engine: &Engine, owner: &OwnerIdentity, node: &str) {
    let signer = owner.signer().await;
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &signer,
        node,
        &infra_scopes(),
        cohort_scope::SELF,
    )
    .await
    .expect("build the claim's owner-binding");
    ciris_server::auth::ownership::apply_signed_owner_binding(
        engine,
        node,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("record the claimed target's owner-binding locally");
}

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
        std::future::pending::<()>().await;
        Ok(())
    }
}

async fn runtime_for(engine: &Arc<Engine>) -> Arc<ReplicationRuntime> {
    let directory: Arc<dyn FederationDirectory> = engine
        .sqlite_backend()
        .expect("sqlite-backed engine")
        .clone();
    Arc::new(
        ReplicationRuntime::start(
            directory,
            Arc::new(NoopTransport),
            Vec::<ReplicationPeer>::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await,
    )
}

async fn initiators(runtime: &ReplicationRuntime) -> Vec<String> {
    let mut v: Vec<String> = runtime
        .registry()
        .registered_keys()
        .await
        .into_iter()
        .filter(|(_, k, role)| *k == EnvelopeKind::Attestation && *role == SessionRole::Initiator)
        .map(|(p, _, _)| p)
        .collect();
    v.sort();
    v
}

// ── 1. linked without a grant ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owners_other_device_is_linked_without_a_grant_and_unlinked_on_release() {
    init_tracing();
    let engine = node_engine().await;
    let owner = OwnerIdentity::mint().await;
    let node = register_self(&engine).await;
    bind_owner(&engine, &owner, &node).await;

    // The second device, as claim-remote leaves it here: its hybrid key
    // admitted, and the owner's binding onto it recorded at `self`.
    let second = "second-device-node";
    seed_key(&engine, second, 0xC1, 0xC2, identity_type::NODE).await;
    record_claim_locally(&engine, &owner, second).await;
    // A key the owner does NOT own, admitted too: never linked.
    seed_key(
        &engine,
        "someone-elses-node",
        0xD1,
        0xD2,
        identity_type::NODE,
    )
    .await;

    assert!(
        engine
            .federation_directory()
            .list_live_consent_grants_by(&owner.key_id)
            .await
            .expect("grants by the owner")
            .is_empty()
            && engine
                .federation_directory()
                .list_live_consent_grants_by(&node)
                .await
                .expect("grants by the node")
                .is_empty(),
        "precondition: no consent:replication grant exists anywhere"
    );
    assert_eq!(
        ciris_server::replication_reconcile::own_device_peers(&engine, &node).await,
        vec![second.to_string()],
        "the owner's other node — and only it — is this node's own-device peer"
    );

    let runtime = runtime_for(&engine).await;
    let converged = ciris_server::replication_reconcile::reconcile_once(&engine, &node, &runtime)
        .await
        .expect("reconcile");
    assert!(converged.peers.contains(second), "{converged:?}");
    assert_eq!(
        initiators(&runtime).await,
        vec![second.to_string()],
        "one reconcile pass makes the second device an initiator — no grant, no reboot"
    );

    // RELEASE: the owner withdraws the binding; the next pass unlinks.
    let binding = engine
        .federation_directory()
        .list_attestations_for(second)
        .await
        .expect("rows about the second device")
        .into_iter()
        .find(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attesting_key_id == owner.key_id
        })
        .expect("the recorded owner-binding");
    let signer = owner.signer().await;
    ciris_server::attest::emit(
        &engine,
        ciris_server::attest::KeySigner::Local(&signer),
        ciris_server::attest::Spec::new(
            attestation_type::WITHDRAWS,
            binding.cohort_scope.clone(),
            ciris_persist::federation::withdraws_attestation_envelope(
                &binding.attestation_id,
                attestation_type::DELEGATES_TO,
            ),
        )
        .about(second),
    )
    .await
    .expect("the owner withdraws the binding");
    ciris_server::replication_reconcile::reconcile_once(&engine, &node, &runtime)
        .await
        .expect("reconcile after release");
    assert!(
        initiators(&runtime).await.is_empty(),
        "a released device is no longer linked"
    );
}

/// Converge, THEN kick: after the claim's local record, the handler nudges the
/// reconciler (whose pass kicks on the gain) rather than kicking a round the
/// new device is not yet an initiator of.
#[test]
fn claim_remote_converges_the_new_device_before_it_kicks() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/claim_remote.rs"),
    )
    .expect("readable")
    .replace("\r\n", "\n");
    let handler = src
        .split_once("async fn claim_remote_handler")
        .expect("the handler exists")
        .1;
    let handler = handler
        .split_once("\n}\n")
        .map_or(handler, |(body, _)| body);
    let record = handler
        .find("record_claimed_target_locally(")
        .expect("the handler records the target locally");
    let nudge = handler
        .find("crate::replication_reconcile::nudge(")
        .expect("the handler converges the peer set after a claim (CIRISServer#678)");
    assert!(
        nudge > record,
        "the nudge must follow the local record: the reconcile pass it starts reads the \
         target's key and owner-binding that the record writes"
    );
    assert!(
        !handler[record..].contains("kick_replication("),
        "a bare kick after the claim rounds toward every peer EXCEPT the one just claimed; \
         the reconcile pass kicks on the gain (note_convergence)"
    );
}

// ── 2. old self files re-wrap for the new device ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_self_files_are_rewrapped_for_the_new_device_by_the_pen_holder() {
    use ciris_persist::federation::blobs::BlobStorage as _;
    init_tracing();

    // FIRST DEVICE: owned, serving the drive, holding a self file.
    let first = node_engine().await;
    let owner = OwnerIdentity::mint().await;
    let first_key = register_self(&first).await;
    bind_owner(&first, &owner, &first_key).await;
    let bearer = mint_session(&first, "wa-second-device-owner", WaRole::Root).await;
    let base = serve_drive(
        Arc::clone(&first),
        node_edge_signer(&first).await,
        owner.seed_dir.clone(),
    )
    .await;
    let client = reqwest::Client::new();
    let (s, v) = status_json(
        client
            .post(format!("{base}/v1/files"))
            .bearer_auth(&bearer)
            .json(&serde_json::json!({
                "cohort": "self",
                "bytes_base64": BASE64.encode(b"written before the second device existed"),
                "media_type": "text/plain",
                "filename": "before.txt",
            }))
            .send()
            .await
            .expect("POST /v1/files"),
    )
    .await;
    assert_eq!(s, 200, "self upload: {v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();
    let (s, meta) = status_json(
        client
            .get(format!("{base}/v1/files/{id}/meta?cohort=self"))
            .bearer_auth(&bearer)
            .send()
            .await
            .expect("meta"),
    )
    .await;
    assert_eq!(s, 200, "{meta}");
    let sha: [u8; 32] = hex::decode(meta["at_rest_sha256"].as_str().expect("at-rest sha"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    // SECOND DEVICE: its own engine, claimed by the same owner, provisioning
    // its content-KEM occurrence the way its self-room tick does.
    let second = other_engine("ciris-second-device", 0xC1, 0xC2).await;
    let second_key = register_self(&second).await;
    bind_owner(&second, &owner, &second_key).await;
    let (occurrence, how) =
        ciris_server::backend::provision_engine_occurrence(&second, &owner.key_id)
            .await
            .expect("the second device provisions its occurrence");
    assert_eq!(how, "created");

    // THE CROSSING: what replication carries to the first device — the second
    // node's key, the owner's binding onto it (claim-remote's local record),
    // and the SIGNED occurrence row, through the receiver's gated door.
    seed_key(&first, &second_key, 0xC1, 0xC2, identity_type::NODE).await;
    record_claim_locally(&first, &owner, &second_key).await;
    let signed = second
        .federation_directory()
        .list_signed_identity_occurrences_for(&owner.key_id)
        .await
        .expect("the second device's signed occurrences");
    let row = signed
        .into_iter()
        .find(|o| o.identity_occurrence.occurrence_key_id == occurrence)
        .expect("the provisioned occurrence rides the signed plane");
    first
        .federation_directory()
        .put_identity_occurrence(row)
        .await
        .expect("the first device admits the second device's occurrence");

    let recipients = |e: Arc<Engine>| async move {
        e.sqlite_backend()
            .expect("sqlite")
            .list_at_rest_grant_recipients(&sha)
            .await
            .expect("grant recipients")
    };
    assert!(
        !recipients(Arc::clone(&first)).await.contains(&occurrence),
        "precondition: the file was sealed before the second device existed"
    );

    // NO PEN HERE (yet): the pass names the pending device and does nothing.
    let report = ciris_server::self_rewrap::rewrap_for_new_devices(&first, &first_key).await;
    assert_eq!(report.owner.as_deref(), Some(owner.key_id.as_str()));
    assert_eq!(report.pending, vec![occurrence.clone()], "{report:?}");
    assert!(
        report.no_pen_here && report.rewrapped.is_empty(),
        "{report:?}"
    );
    assert!(!recipients(Arc::clone(&first)).await.contains(&occurrence));

    // THE PEN OPENS HERE (what compose registers at boot): the re-wrap runs.
    ciris_server::node_key::set_user_seed_dir(owner.seed_dir.clone(), owner.alias.clone());
    let report = ciris_server::self_rewrap::rewrap_for_new_devices(&first, &first_key).await;
    assert!(!report.no_pen_here, "{report:?}");
    assert_eq!(report.rewrapped.len(), 1, "{report:?}");
    assert_eq!(report.rewrapped[0].0, occurrence);
    assert!(
        report.rewrapped[0].1 >= 1,
        "the old file was granted: {report:?}"
    );
    assert!(
        recipients(Arc::clone(&first)).await.contains(&occurrence),
        "the self file written before the claim is now wrapped to the second device"
    );

    // IDEMPOTENT: nothing pending on the next tick, and the door itself adds
    // nothing a second time.
    let again = ciris_server::self_rewrap::rewrap_for_new_devices(&first, &first_key).await;
    assert!(
        again.pending.is_empty() && again.rewrapped.is_empty(),
        "{again:?}"
    );
    let direct = first
        .rekey_self_occurrence_add(&owner.key_id, std::slice::from_ref(&occurrence))
        .await
        .expect("re-run the door");
    assert_eq!(
        direct.granted.iter().map(|(_, n)| n).sum::<usize>(),
        0,
        "a second re-wrap grants nothing new"
    );
}

// ── 3. announce another device from the one holding the pen ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pen_holder_announces_another_device_and_refuses_a_node_not_its_own() {
    init_tracing();
    let engine = node_engine().await;
    let owner = OwnerIdentity::mint().await;
    let node = register_self(&engine).await;
    bind_owner(&engine, &owner, &node).await;
    let second = "announced-second-device";
    seed_key(&engine, second, 0xC3, 0xC4, identity_type::NODE).await;
    record_claim_locally(&engine, &owner, second).await;
    seed_key(&engine, "a-stranger-node", 0xD3, 0xD4, identity_type::NODE).await;

    let bearer = mint_session(&engine, "wa-announce-owner", WaRole::Root).await;
    let app = ciris_server::self_devices::router(Arc::clone(&engine), owner.seed_dir.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = reqwest::Client::new();
    let post = |path: String, bearer: Option<String>| {
        let mut req = client.post(format!("{base}{path}"));
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        async move { status_json(req.send().await.expect("POST")).await }
    };

    let federation_bindings = || async {
        engine
            .federation_directory()
            .list_attestations_for(second)
            .await
            .expect("rows about the second device")
            .into_iter()
            .filter(|a| {
                a.attestation_type == attestation_type::DELEGATES_TO
                    && a.attesting_key_id == owner.key_id
                    && a.cohort_scope == cohort_scope::FEDERATION
            })
            .count()
    };
    assert_eq!(
        federation_bindings().await,
        0,
        "precondition: held at `self` only"
    );

    let path = format!("/v1/self/nodes/{second}/announce");
    let (s, v) = post(path.clone(), None).await;
    assert_eq!(
        (s, v["reason_id"].as_str()),
        (401, Some("self.owner_session_required")),
        "{v}"
    );

    let (s, v) = post(path.clone(), Some(bearer.clone())).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["owner"], owner.key_id.as_str());
    assert_eq!(v["already_announced"], false, "{v}");
    assert_eq!(v["this_node"], false, "{v}");
    assert!(
        v["promoted_owner_binding_attestation_id"].is_string(),
        "{v}"
    );
    assert_eq!(
        federation_bindings().await,
        1,
        "the owner's binding onto the second device is now federation-scoped"
    );

    let (s, v) = post(path, Some(bearer.clone())).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["already_announced"], true, "idempotent: {v}");
    assert_eq!(federation_bindings().await, 1);

    for other in ["a-stranger-node", "never-heard-of-it"] {
        let (s, v) = post(
            format!("/v1/self/nodes/{other}/announce"),
            Some(bearer.clone()),
        )
        .await;
        assert_eq!(
            (s, v["reason_id"].as_str()),
            (403, Some("self.announce_not_your_node")),
            "{other}: {v}"
        );
    }
}

// ── 5. a self file the first device wrote LISTS on the second (0.5.218) ─────

/// **The second device lists its owner's self file** — the self-files
/// ladder's `mine_on_b`, in-process. On persist v49 / edge v32 the ladder's
/// second device READ a self file by id (`409 drive.not_fetched`: the row is
/// there) while `GET /v1/drive` listed nothing. This carries one self file
/// row to a second engine the way replication does and asks both doors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_file_written_on_the_first_device_lists_on_the_second() {
    init_tracing();
    let first = node_engine().await;
    let owner = OwnerIdentity::mint().await;
    let first_key = register_self(&first).await;
    bind_owner(&first, &owner, &first_key).await;
    let bearer = mint_session(&first, "wa-lists-first", WaRole::Root).await;
    let base = serve_drive(
        Arc::clone(&first),
        node_edge_signer(&first).await,
        owner.seed_dir.clone(),
    )
    .await;
    let client = reqwest::Client::new();
    let (s, v) = status_json(
        client
            .post(format!("{base}/v1/files"))
            .bearer_auth(&bearer)
            .json(&serde_json::json!({
                "cohort": "self",
                "bytes_base64": BASE64.encode(b"listed on both devices"),
                "media_type": "text/plain",
                "filename": "both.txt",
            }))
            .send()
            .await
            .expect("POST /v1/files"),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();

    // The second device: same owner, and what replication carries to it.
    let second = other_engine("ciris-lists-second", 0xD1, 0xD2).await;
    let second_key = register_self(&second).await;
    bind_owner(&second, &owner, &second_key).await;
    seed_key(&second, &first_key, 0xA1, 0xA2, identity_type::NODE).await;
    record_claim_locally(&second, &owner, &first_key).await;
    let row = first
        .federation_directory()
        .get_attestation(&id)
        .await
        .expect("read")
        .expect("the file row");
    eprintln!(
        "ROW on first: tier={} scope={} attester={}",
        row.tier, row.cohort_scope, row.attesting_key_id
    );
    second
        .federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation { attestation: row })
        .await
        .expect("the second device admits the file row");

    let bearer2 = mint_session(&second, "wa-lists-second", WaRole::Root).await;
    let base2 = serve_drive(
        Arc::clone(&second),
        node_edge_signer(&second).await,
        owner.seed_dir.clone(),
    )
    .await;
    let (s, by_id) = status_json(
        client
            .get(format!("{base2}/v1/files/{id}?cohort=self"))
            .bearer_auth(&bearer2)
            .send()
            .await
            .expect("GET by id"),
    )
    .await;
    eprintln!("BY ID on second: {s} {by_id}");
    let (s, listing) = status_json(
        client
            .get(format!("{base2}/v1/drive?cohort=self"))
            .bearer_auth(&bearer2)
            .send()
            .await
            .expect("GET /v1/drive"),
    )
    .await;
    eprintln!("LISTING on second: {s} {listing}");
    assert_eq!(s, 200, "{listing}");
    assert!(
        listing["entries"]
            .as_array()
            .is_some_and(|e| e.iter().any(|x| x["attestation_id"] == id.as_str())),
        "the second device lists its owner's self file: {listing}"
    );
}
