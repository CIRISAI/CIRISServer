//! # A split node signs its consent as itself (CIRISServer#563)
//!
//! The Android run-without-AI leg (CIRISAgent#1149) died at boot with:
//!
//! ```text
//! re-author consent ciris-node-bootstrap-4w7a7jm6j5 -> ciris-canonical-1-…:
//! refusing to emit a consent grant naming "ciris-node-bootstrap-4w7a7jm6j5":
//! this engine signs as "ciris-agent-bootstrap-lbylhuoe7f" …
//! ```
//!
//! The engine signs as the ACTOR (the agent's alias, on purpose — passing the
//! node alias is #380's two-identities refusal). Boot mints or adopts the NODE
//! key through `node_key::node_signer`, whose `LocalSigner::key_id()` is the
//! keystore ALIAS while the node is registered as `derived_key_id()`. The
//! consent guard compared the alias to the derived id, so the boot re-author
//! that moves the actor's grants onto the node — the cure for CIRISServer#312 —
//! refused every grant it was asked to move. `tests/consent_survives_the_key_split.rs`
//! registered its node under a bare label and never saw it.
//!
//! This binary drives the PRODUCTION objects: a sealed keystore in a scratch
//! identity dir, `resolve_node_identity`'s split, `register_node_key`'s id, and
//! the re-author — then the runtime emit path with no explicit signer, which on
//! a split node must author as the node through the pen the process holds.
//!
//! One test, two phases, because the held node signer is process-wide.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The actor: the agent's own bootstrap alias, as the app passes it.
const ACTOR_ALIAS: &str = "ciris-agent-bootstrap";
const PEER: &str = "ciris-canonical-1-for-the-split-test";
const PEER_2: &str = "a-second-peer-consented-at-runtime";
const PEER_3: &str = "a-third-peer-named-through-the-actor";

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
    s
}

fn signer_for(alias: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(alias, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(alias, 2), format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .expect("bind subject (#659)");
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: ident.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

fn scratch_identity_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ciris-563-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("scratch identity dir");
    dir
}

// CIRISServer#599/#601 (0.5.211): the first half of this test is the UNCLAIMED
// split home — every grant is the provisional machine-authored kind, signed as
// the key that was NAMED (no 0.5.203 redirect). The second half claims the node,
// anchors the agent to the human, and shows the human's grant naming the agent.
#[tokio::test]
async fn the_split_node_reauthors_at_boot_and_authors_at_runtime_as_itself() {
    // The engine signs as the ACTOR — the embedded fold and the headless boot alike.
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(ACTOR_ALIAS)), "sqlite::memory:")
            .await
            .expect("engine signing as the actor"),
    );
    let actor = engine
        .local_derived_key_id()
        .await
        .expect("actor derived id");
    register(
        &engine,
        &signer_for(ACTOR_ALIAS),
        &actor,
        identity_type::AGENT,
    )
    .await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;
    register(&engine, &signer_for(PEER_2), PEER_2, identity_type::NODE).await;
    register(&engine, &signer_for(PEER_3), PEER_3, identity_type::NODE).await;

    // ── Before the split: the wizard peers with the canonical. The engine is the
    //    only pen, so the grant is the ACTOR'S — the state every agent-hosted node
    //    is in after first setup.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &actor,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the actor authors the wizard-time grant");

    // ── The boot split, with the production objects: a sealed node keystore in
    //    the identity dir, the node key registered under its DERIVED id.
    let identity_dir = scratch_identity_dir();
    let resolution =
        ciris_server::node_key::resolve_node_identity(&engine, &actor, ACTOR_ALIAS, &identity_dir)
            .await
            .expect("resolve the node identity");
    assert!(resolution.did_split(), "an actor-configured key splits");
    let node = resolution.node_key_id.clone();
    let node_signer = resolution
        .signer
        .clone()
        .expect("the split holds the node's signer");
    assert_ne!(
        node_signer.key_id(),
        node.as_str(),
        "premise: the node signer names its key by ALIAS ({:?}) while the node is \
         registered as the DERIVED id ({node:?}) — the two conventions the guard must \
         both recognise",
        node_signer.key_id()
    );
    assert_eq!(node_signer.derived_key_id(), node);
    // The public record the split holds is the NODE's — what a peer registers
    // to admit this node's rows (Codex on #564) — and a peer CAN register it.
    let record_json = ciris_server::node_key::held_node_key_record_json()
        .expect("the split holds the node's self-signed key record");
    let record: ciris_persist::federation::SignedKeyRecord =
        serde_json::from_str(&record_json).expect("a SignedKeyRecord");
    assert_eq!(
        record.record.key_id, node,
        "the served record names the NODE key"
    );
    assert_eq!(record.record.identity_type, identity_type::NODE);
    let peer_engine = Engine::with_signer(Arc::new(signer_for(PEER)), "sqlite::memory:")
        .await
        .expect("a peer's engine");
    peer_engine
        .register_federation_key(record)
        .await
        .expect("a peer admits the node key from the served record");

    // ── Phase 1: the boot re-author — the exact call that crashed the Android node.
    // ── 0.5.211 (CIRISServer#601): NO redirect. A machine author signs as the
    // key that was named, and every read is persist's by-principals fold. ──
    //
    // The grant authored BEFORE the split (as the actor) is still the actor's:
    // nothing moves it onto the node, because the node key is not a principal
    // of the agent and every runtime read is keyed by the engine's key.
    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, &actor)
            .await
            .expect("read as the actor — the production read"),
        vec![PEER.to_string()],
        "the pre-split grant stays where the reads look"
    );
    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("read as the node")
            .is_empty(),
        "the node has no consent of its own yet"
    );
    // Naming the NODE explicitly authors as the node, through the held signer.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        PEER_2,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("a runtime emit naming the node authors as the node through the held signer");
    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("read as the node"),
        vec![PEER_2.to_string()]
    );
    assert!(
        !ciris_server::peer::replication_peers_from_consent(&engine, &actor)
            .await
            .expect("read as the actor")
            .contains(&PEER_2.to_string()),
        "a row the NODE authored is the node's, not the agent's — no cross-machine blanket"
    );
    // Naming the ACTOR authors as the actor — the engine's own key.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &actor,
        PEER_3,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("a grant named for the actor on a split node is authored AS the actor");
    assert!(
        !ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("read as the node")
            .contains(&PEER_3.to_string()),
        "the actor's grant is not the node's (0.5.211: no redirect, no blanket)"
    );
    // "Did not land under the actor" is a statement about the ROW's author, so
    // it is asserted on the grant rows — the unioned production read now sees
    // every grantor for this node by design (CIRISServer#599).
    assert!(
        engine
            .federation_directory()
            .list_live_consent_grants_by(&actor)
            .await
            .expect("grants by the actor")
            .iter()
            .any(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER_3)),
        "and it IS authored under the actor — the key every read uses"
    );
    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &actor)
            .await
            .expect("read as the actor — the production read")
            .contains(&PEER_3.to_string()),
        "and the production read (engine key) resolves it (#599 / #601)"
    );

    // ── Phase 4: widening coverage (adding a contact) supersedes the ACTOR's
    //    standing grant (PEER, authored before the split and never moved) with a
    //    row the same attester signs — the actor (Codex P2 on #564, read under
    //    0.5.211's no-redirect rule). Named for the actor, like the contacts
    //    surface does.
    let defaults = ciris_server::peer::default_attestation_prefixes();
    let extra = ["hard_case:", "location:", "capacity:", "trace:"]
        .into_iter()
        .find(|p| !defaults.iter().any(|d| d == p))
        .expect("a prefix outside the default set, so the widening is real")
        .to_string();
    let coverage = ciris_server::peer::ensure_replication_consent_covers(
        &engine,
        &actor,
        PEER,
        std::slice::from_ref(&extra),
    )
    .await
    .expect("widen the node's grant");
    assert!(coverage.freshly_emitted, "a new, wider grant was written");
    assert!(
        coverage.superseded_attestation_id.is_some(),
        "the supersedes composer succeeded — the corpus says the narrower grant is retired"
    );
    let rows = engine
        .federation_directory()
        .list_attestations_by(&actor)
        .await
        .expect("the actor's rows");
    let supersedes: Vec<_> = rows
        .iter()
        .filter(|a| {
            a.attestation_type == ciris_persist::federation::types::attestation_type::SUPERSEDES
        })
        .collect();
    assert_eq!(
        supersedes.len(),
        1,
        "exactly one supersedes row, authored by the actor — the grant's own attester"
    );
    assert_eq!(
        supersedes[0]
            .attestation_envelope
            .get(ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID)
            .and_then(|v| v.as_str()),
        coverage.superseded_attestation_id.as_deref(),
        "and it retires the grant the coverage call says it retired"
    );
    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &actor)
            .await
            .expect("read as the actor")
            .contains(&PEER.to_string()),
        "consent to the peer is never momentarily absent across the widening"
    );

    // ── Phase 5: the CC#46 `analyze` grant is the ACTOR's consent to be scored
    //    (the machine named, signed by the machine named — no redirect), and it
    //    must RESOLVE through the by-principals fold keyed by the actor, which
    //    is what the canonical's scorer asks (Codex P1 on #564, 0.5.211 reading).
    let analyze = ciris_server::peer::emit_analyze_consent(&engine, &actor, PEER)
        .await
        .expect("the analyze grant authors as the actor and resolves");
    assert!(analyze.is_some(), "a fresh analyze grant was written");
    let resolved = engine
        .resolve_scoped_consent_by_principals(
            PEER,
            &actor,
            ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE,
            None,
            chrono::Utc::now(),
        )
        .await
        .expect("resolve");
    assert!(
        matches!(
            resolved,
            ciris_persist::federation::hard_case::ConsentState::Granted
        ),
        "the peer may now score THIS AGENT (the actor — the key the scorer is handed): {resolved:?}"
    );
    assert!(
        ciris_server::peer::emit_analyze_consent(&engine, &actor, PEER)
            .await
            .expect("idempotent")
            .is_none(),
        "a second call finds the resolved stance and writes nothing"
    );

    // ── And the guard still refuses a pen that is not the node's.
    let err = ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        &node,
        "yet-another-peer",
        &ciris_server::peer::default_attestation_prefixes(),
        &ciris_server::peer::ConsentGrantOptions {
            author_signer: Some(Arc::new(signer_for(PEER))),
            ..Default::default()
        },
    )
    .await
    .expect_err("an explicit signer that does not hold the node key is refused");
    assert!(err
        .to_string()
        .contains("refusing to emit a consent grant naming"));

    // ── CIRISServer#601 (0.5.211): the CLAIMED split home ──────────────────
    // The human claims the NODE; the agent (the engine's key) must then become
    // an occurrence of the human — the login ceremony — or persist's
    // by-principals fold finds no human behind the agent, and the human's
    // grant, which names the AGENT, is invisible to every read keyed by it.
    let seed_dir = std::env::temp_dir().join(format!(
        "ciris-split-owner-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
    let alias = format!("split-owner-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Split Owner"),
        seed_dir.clone(),
        ciris_server::identity::ActiveAlias::Adopt,
    )
    .await
    .expect("mint the owner");
    let owner = minted.key_id.clone();
    let owner_signer = ciris_server::identity::hardware_user_signers(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        seed_dir.clone(),
    )
    .await
    .expect("re-open the owner")
    .0;
    register(&engine, &owner_signer, &owner, identity_type::USER).await;
    ciris_server::node_key::set_user_seed_dir(seed_dir.clone(), alias.clone());
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(&engine, &owner_signer, &node, &scopes)
        .await
        .expect("the human claims the NODE");
    assert!(
        engine
            .steward_bindings_of(&actor)
            .await
            .expect("stewards of the agent")
            .is_empty(),
        "before the ceremony nobody stands behind the agent"
    );
    // PRODUCTION'S SHAPE (CIRISServer#632, measured on the production-shaped
    // ladder under persist v48.0.0): the 1-phase first-run claim never anchored
    // the agent, so the covering door skipped it and persist's sweep, which
    // reads the ENGINE key, found no grant — `offerable=0`. The covering door
    // anchors first, so consent FOR the agent is written on every claim path.
    const PEER_0: &str = "a-peer-covered-before-anyone-anchored-the-agent";
    register(&engine, &signer_for(PEER_0), PEER_0, identity_type::NODE).await;
    ciris_server::peer::ensure_replication_consent_covers(
        &engine,
        &node,
        PEER_0,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the covering door on a claimed, UNANCHORED split home");
    assert!(
        engine
            .steward_bindings_of(&actor)
            .await
            .expect("stewards of the agent")
            .contains(&owner),
        "the covering door anchored the agent to its human (occurrence anchor)"
    );
    assert!(
        engine
            .consent_peers_by_principals(&actor)
            .await
            .expect("by-principals for the agent")
            .contains(&PEER_0.to_string()),
        "and wrote the human's grant FOR the agent — the row persist's sweep reads"
    );
    assert!(
        ciris_server::node_key::anchor_agent_to_owner(&engine)
            .await
            .expect("a later pass")
            .is_none(),
        "idempotent: the anchor already stands"
    );
    // The human consents FOR THIS AGENT, and the agent's own read finds it.
    const PEER_4: &str = "a-peer-consented-by-the-human-for-the-agent";
    register(&engine, &signer_for(PEER_4), PEER_4, identity_type::NODE).await;
    ciris_server::peer::emit_replication_consent(
        &engine,
        &actor,
        PEER_4,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the owner authors, naming the agent");
    let by_owner = engine
        .federation_directory()
        .list_live_consent_grants_by(&owner)
        .await
        .expect("grants by the owner");
    let row = by_owner
        .iter()
        .find(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER_4))
        .expect("the grant is the HUMAN's");
    assert_eq!(
        ciris_persist::federation::consent_by_humans::for_key_id_of(&row.attestation_envelope),
        Some(actor.as_str()),
        "and it names THIS agent — never a blanket"
    );
    assert!(
        engine
            .consent_peers_by_principals(&actor)
            .await
            .expect("by-principals read for the agent")
            .contains(&PEER_4.to_string()),
        "the read every runtime path uses (keyed by the agent) resolves the human's grant"
    );
    assert!(
        !engine
            .consent_peers_by_principals(&node)
            .await
            .expect("by-principals read for the node")
            .contains(&PEER_4.to_string()),
        "a grant FOR the agent is not the node's consent — no blanket across the human's machines"
    );
    // CIRISServer#632 — the COVERING door (what `POST /v1/federation/peering`
    // and `POST /v1/contacts` call) consents once per own key the human is
    // bound to: the NODE key (edge's send-set, the Rooted walk) AND the AGENT
    // (persist's promotion sweep reads the engine's key). One call, two grants,
    // each read by the plane that needs it; neither a blanket.
    const PEER_5: &str = "a-peer-covered-for-both-of-the-humans-machine-keys";
    register(&engine, &signer_for(PEER_5), PEER_5, identity_type::NODE).await;
    ciris_server::peer::ensure_replication_consent_covers(
        &engine,
        &node,
        PEER_5,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the covering door consents for the node AND the anchored agent");
    assert!(
        engine
            .consent_peers_by_principals(&node)
            .await
            .expect("by-principals for the node")
            .contains(&PEER_5.to_string()),
        "the NODE's plane (edge send-set / Rooted) sees the peer"
    );
    assert!(
        engine
            .consent_peers_by_principals(&actor)
            .await
            .expect("by-principals for the agent")
            .contains(&PEER_5.to_string()),
        "the AGENT's plane (persist's promotion sweep reads the engine key) sees the peer"
    );
    let rows_for_5: Vec<(String, Option<String>)> = engine
        .federation_directory()
        .list_live_consent_grants_by(&owner)
        .await
        .expect("grants by the owner")
        .iter()
        .filter(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER_5))
        .map(|g| {
            (
                g.attesting_key_id.clone(),
                ciris_persist::federation::consent_by_humans::for_key_id_of(
                    &g.attestation_envelope,
                )
                .map(str::to_owned),
            )
        })
        .collect();
    let all_for_5: Vec<(String, Option<String>)> = engine
        .federation_directory()
        .list_attestations_for(PEER_5)
        .await
        .map(|rows| {
            rows.iter()
                .map(|g| {
                    (
                        g.attesting_key_id.clone(),
                        ciris_persist::federation::consent_by_humans::for_key_id_of(
                            &g.attestation_envelope,
                        )
                        .map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    // Count from the RAW rows: persist v47's attester-keyed live reader holds one
    // grant per (author, peer) (`consent_peer_set` INSERT OR REPLACE), so it
    // shows only the last-written of the two; the per-key projection — what the
    // two plane assertions above read — holds both.
    let for_keys: Vec<String> = all_for_5
        .iter()
        .filter(|(author, _)| author == &owner)
        .filter_map(|(_, f)| f.clone())
        .collect();
    assert!(
        for_keys.contains(&node) && for_keys.contains(&actor) && for_keys.len() == 2,
        "two grants by the human, one FOR each machine key: {for_keys:?}"
    );
    // And the attester-keyed live reader keeps BOTH: persist v48.0.0 (V152,
    // CIRISPersist#905) keys `consent_peer_set` by `for_key_id`, so a human
    // bound to two machine keys holds two live grants toward one peer and
    // withdrawing one no longer drops the other's peer row. (Under v47 this
    // reader showed only the last-written — the node's — which is why the
    // covering door still writes the requested key last: harmless now, and
    // the order a v47 reader needed.)
    let mut live_for: Vec<Option<String>> = rows_for_5
        .iter()
        .filter(|(author, _)| author == &owner)
        .map(|(_, f)| f.clone())
        .collect();
    live_for.sort();
    let mut want = vec![Some(actor.clone()), Some(node.clone())];
    want.sort();
    assert_eq!(
        live_for, want,
        "the attester-keyed live reader keeps one live grant per (author, FOR key, peer)"
    );
    // CIRISServer#632 — the DIRECT emitter (what `POST /v1/federation/peering`,
    // the delivery controller's canonical grant and the admin door call) fans
    // out the same way when it is asked for the NODE: the production-shaped
    // ladder read `offerable=0` on persist v48.0.0 because only the covering
    // door did this, and production's canonical grant never goes through it.
    const PEER_6: &str = "a-peer-consented-through-the-direct-emitter";
    register(&engine, &signer_for(PEER_6), PEER_6, identity_type::NODE).await;
    ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        PEER_6,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the direct emitter, asked for the node");
    for (plane, key) in [("node", &node), ("agent", &actor)] {
        assert!(
            engine
                .consent_peers_by_principals(key)
                .await
                .expect("by-principals read")
                .contains(&PEER_6.to_string()),
            "the {plane} plane sees the peer consented through the direct emitter"
        );
    }
    // CIRISServer#632 — edge's serve gate (leg B) asks whether the WIRE key, the
    // node, trusts a root the recipient's `infra:serve` roots to. The engine's
    // acceptance is the ACTOR's on a split install; the node key needs its own.
    ciris_server::mesh_genesis::install_baked_trust_root(&engine)
        .await
        .expect("the baked trust root installs and is accepted");
    let root = ciris_server::mesh_genesis::charter_root_key_id(
        ciris_persist::federation::genesis::canonical_genesis_bundle(),
    )
    .expect("the baked bundle names a root");
    let now = chrono::Utc::now();
    let dir = engine.federation_directory();
    for (who, key) in [("agent (engine)", &actor), ("node (wire)", &node)] {
        assert!(
            ciris_persist::federation::trust_root::trusted_roots_of(dir.as_ref(), key, now)
                .await
                .expect("trusted_roots_of")
                .contains(&root),
            "the {who} key accepts the baked root at federation tier"
        );
    }
    let _ = std::fs::remove_dir_all(&seed_dir);
    let _ = std::fs::remove_dir_all(&identity_dir);
}
