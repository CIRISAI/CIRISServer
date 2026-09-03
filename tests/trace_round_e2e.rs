//! **The in-process two-node Attestation round** — a sealed `trace:*` actually
//! crossing from an agent-shaped node to a canonical-shaped one, with no docker,
//! no transport, and no harness.
//!
//! # Why this exists
//!
//! Every predicate in the trace-delivery arc was found the same expensive way: a
//! full mesh harness run surfaced one silent gate, it got fixed, the next run
//! surfaced the next one. That cost a round trip per predicate — because nothing
//! on this side ever ran an actual anti-entropy **round**. Our tests covered our
//! own surfaces (emit, promote, scope, admission) and the substrate covered its
//! own; the *seam between them* — the thing that was actually broken every single
//! time — was covered by neither.
//!
//! Concretely, this test exercises the seam that produced:
//!
//! * **CIRISEdge#414** — the #396 send-consent gate darkening the RECEIVE side, so
//!   a canonical holding `infra:serve` withheld the whole Attestation plane
//!   because it had authored no grant *toward the agent*.
//! * **CIRISEdge#416** — `local_holdings` returning advertise-filtered refs
//!   instead of real holdings, so `want` could never shrink.
//! * **CIRISPersist#509 / #530** — a trace promoted to federation *tier* while
//!   still `cohort_scope=self`, past the tier gate and never offered.
//!
//! All three are *round* properties. None is visible from either side alone.
//!
//! # What it drives
//!
//! Two real `Engine`s on `sqlite::memory:`, two real
//! `FederationDirectoryReplicationBridge`s over them, and a hand-pumped
//! `Session` pair — initiator (agent) ↔ responder (canonical) — exchanging real
//! `ReplicationMessage`s until the round completes. The assertion is the one that
//! matters: **the canonical's corpus contains the agent's trace afterwards.**
//!
//! Note `#[tokio::test(flavor = "multi_thread")]` is load-bearing:
//! `DirectoryStateAdapter` bridges edge's sync `StateProvider` trait to persist's
//! async surface via `block_in_place` + `block_on`, which panics on a
//! current-thread runtime.
//!
//! # What still calls persist directly, and why
//!
//! The CROSSING is edge's — `attestation_bind::publish` places the second trace
//! here, and `advertise_verdict` is held against edge's own `local_refs`. What
//! remains on persist remains because edge does not own it, not because it was
//! missed:
//!
//! * **`promote_consented_backlog`** — persist's consent-driven SWEEP, the
//!   production placement path (`replication_reconcile::reconcile_once`) and the
//!   only thing that ever places a trace sealed BEFORE its grant existed. Edge
//!   has no sweep; `share` is per-row. Both doors are driven below.
//! * **`emit_attestation_self`** — AUTHORSHIP. Edge ships producers for the two
//!   rows it authors itself (`owner_binding_attestation`,
//!   `replication_consent_attestation`) and none for `trace:*`; persist's emit
//!   chokepoint is what stamps the instants into the signed bytes
//!   (CIRISPersist#598) and binds the row mirror (#643).
//! * **`put_public_key` / `signed_canonical_record_with_roles` /
//!   `establish_trust_root_side`** — the KEY and TRUST-ROOT planes. Accord
//!   conferral is a 2-of-3 co-scrub against a roster persist resolves itself; a
//!   fixture cannot reach it through any edge surface, which is the whole reason
//!   this file needs `--features test-anchor`.
//! * **`list_attestations_by` / `get_attestation` / `has_accord_conferred_role` /
//!   `capability_roots_to_trusted_root`** — READS of the corpus and of the serve
//!   gate's two legs. Edge's read DX is per-plane (`chat::ChatMessage::from_row`
//!   opens a room); there is no `trace:*` opener, and the round's question is
//!   "is the row THERE", which is persist's to answer.

//! Requires `--features test-anchor`: conferring `infra:serve` is an ACCORD act
//! (2-of-3 co-scrub), not a field you can set — persist refuses a self-claimed
//! role with `InfraAttestRoleNotAccordConferred`, which is the substrate working.
//! The signing helpers that let a test perform a genuine co-scrub live behind
//! that feature. This is the same wall the mesh harness hit when its canonical
//! was minted with `roles = None`.
#![cfg(feature = "test-anchor")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_edge::replication::{
    DirectoryStateAdapter, EnvelopeKind, FederationDirectoryReplicationBridge,
    MutableDirectoryStateAdapter, ReplicationMessage, ReplicationOutcome, Session, SessionRole,
    StateApplier, StateProvider,
};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, cohort_scope, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};

/// Surface edge's own diagnostics inside the test. Since edge v15.2.1 the
/// `apply_*` family is LOUD (CIRISEdge#423) — a delivered envelope that fails to
/// land now names the arm and the refusal token instead of returning a silent
/// `false`. Without a subscriber those warnings go nowhere, so the harness would
/// still be reading absence-of-work as absence-of-problem.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "ciris_edge=warn,ciris_persist=warn".into()),
            )
            .with_test_writer()
            .try_init();
    });
}

/// Roles a real canonical carries. Without these the producer's #379/#386 gate
/// withholds every `trace:*` — the defect that cost one whole harness run.
const INFRA_SERVE: &str = "infra:serve";
const INFRA_ATTEST: &str = "infra:attest";

struct Node {
    engine: Arc<Engine>,
    key_id: String,
    ed_pub: String,
    pqc_pub: String,
    /// **The same hardware material, keyed the way edge's replication DX takes
    /// it** — and the two keyings are opposites, which is the trap this field
    /// exists to keep out of every call site.
    ///
    /// `attestation_bind::custody_for` compares `LocalSigner.key_id` to the
    /// row's `attesting_key_id` VERBATIM (edge v20.0.0 `attestation_bind.rs:663`
    /// and `:696`), so edge's signer carries the DERIVED federation id. Persist's
    /// `LocalSigner` above carries the ALIAS, because `derive_key_id` is applied
    /// to it downstream — the field is either the derive input or its output,
    /// never both. Handing edge a signer keyed the persist way makes every
    /// crossing refuse with `CustodyIsNotTheActor`, and handing persist one keyed
    /// edge's way double-derives.
    edge_signer: ciris_edge::identity::LocalSigner,
}

async fn node(alias: &str, ed_seed: u8, pqc_seed: u8) -> Node {
    let signing_key = SigningKey::from_bytes(&[ed_seed; 32]);
    let ed_pub = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let pqc_pub = BASE64.encode(pqc.public_key().await.expect("pqc pubkey"));
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        alias.to_string(),
        Some(Arc::clone(&pqc)),
        Some(format!("{alias}-pqc")),
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine"),
    );
    let key_id = engine.local_derived_key_id().await.expect("derived key_id");

    // Edge's signer over the SAME seeds — not a second identity. Built from the
    // seed bytes rather than converted from the persist signer because persist
    // keeps its classical half private (`crate::identity`: "one cannot be
    // converted into the other").
    let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
        ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[ed_seed; 32], format!("{alias}-ed"))
            .expect("ed25519 software signer over the node's seed"),
    );
    // Proven, not assumed: a signer whose public half differs from the one this
    // node REGISTERS produces a widening that canonicalizes, signs, and is then
    // refused at the put door for a reason that reads like a persist bug.
    assert_eq!(
        BASE64.encode(classical.public_key().await.expect("edge classical pubkey")),
        ed_pub,
        "the edge signer must carry the same classical half the directory registers"
    );
    let edge_signer =
        ciris_edge::identity::LocalSigner::new(key_id.clone(), classical, Some(Arc::clone(&pqc)));

    Node {
        engine,
        key_id,
        ed_pub,
        pqc_pub,
        edge_signer,
    }
}

/// The three accord holders the test-anchor genesis synthesizes. Their key_ids
/// are FIXED by persist (`test-accord-holder-{i}`) and `Identity::new` is
/// deterministic from the id — so constructing them here yields exactly the
/// keypairs whose PUBLIC halves we publish via `CIRIS_TEST_TRUST_ROOT*`, and
/// whose PRIVATE halves we still hold to co-scrub with. That identity is the
/// whole trick: the co-scrub gate resolves its roster from the EFFECTIVE
/// genesis records (`accord_holder_roster_key_ids`), never from caller input,
/// so ad-hoc holders can never satisfy it (which is why
/// `test_support::confer_roles`, which invents `{tag}-h{i}`, cannot work
/// through `put_public_key` — see CIRISPersist#534).
fn genesis_holders() -> Vec<ciris_persist::federation::operational::test_support::Identity> {
    use ciris_persist::federation::operational::test_support::Identity;
    (0..3)
        .map(|i| Identity::new(&format!("test-accord-holder-{i}")))
        .collect()
}

/// Arm Mode A (CIRISServer#321): publish the holders' PUBLIC halves so persist's
/// test-anchor genesis synthesizes accord_holder rows for them. MUST run before
/// any `Engine` is built — the genesis records are resolved at boot.
///
/// Mode A rather than Mode B (mock FIPS custody), and the reason is no longer
/// the one that used to be written here. This said Mode B's
/// `MockAttestedMember` "does not expose the member's ML-DSA private half
/// (CIRISVerify#221)". That closed: at our pin the struct carries
/// `pub holder: HybridSigningIdentity` (`accord_custody_attestation.rs:833`) and
/// upstream's own note calls it "a USABLE hybrid signer, not just pubkeys"
/// (`:1244`), with a deterministic ML-DSA-65 half (`:958`).
///
/// Mode A stays here because this is a ROUND test — it wants real signatures over
/// the legacy quorum bar, not a custody-admission scenario. Mode B belongs in its
/// own file against persist's
/// `check_canonical_role_admission_over_roster_with_custody_root`
/// (`admission.rs:7360`), fed a `MockYubicoCa` root; that is CIRISServer#321 and
/// it is not blocked by anything upstream.
fn arm_test_trust_root(holders: &[ciris_persist::federation::operational::test_support::Identity]) {
    let eds: Vec<String> = holders
        .iter()
        .map(|h| h.member().ed25519_public_key_base64)
        .collect();
    let pqcs: Vec<String> = holders
        .iter()
        .filter_map(|h| h.member().mldsa65_public_key_base64)
        .collect();
    // The AND-gate: the `test-anchor` FEATURE alone is inert — verify's
    // `test_anchor_active()` additionally requires this runtime signal (and
    // REFUSES if any production environment marker is set, so this can never
    // arm in prod). Without it `test_trust_root_override()` returns None, the
    // genesis synthesizes nothing, and the co-scrub tallies 0 signatures
    // against an empty roster.
    std::env::set_var("CIRIS_TESTING_MODE", "true");
    std::env::set_var("CIRIS_TEST_TRUST_ROOT", eds.join(","));
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_PQC", pqcs.join(","));
}

/// Confer `roles` on `who` by co-scrubbing its record with 2 of the 3 GENESIS
/// holders — the legitimate accord act, with real signatures, verified against
/// the roster persist itself resolves.
async fn confer_roles(on: &Node, who: &Node, roles: &[&str]) {
    use ciris_persist::federation::operational::test_support::signed_canonical_record_with_roles;
    let holders = genesis_holders();
    // persist v31.0.0 (#659): the registration envelope now binds `key_id` AND
    // both pubkey legs, so the fixture must pass the subject's real pubkeys.
    // Before, an authority's signature over any envelope lifted onto any row.
    let rec = signed_canonical_record_with_roles(
        &who.key_id,
        identity_type::NODE,
        &who.ed_pub,
        Some(&who.pqc_pub),
        roles.iter().map(|r| (*r).to_owned()).collect(),
        serde_json::json!({ "key_id": who.key_id, "conferred_by": "test-anchor-genesis" }),
        &[&holders[0], &holders[1]], // 2-of-3
    );
    on.engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("accord-confer roles (2-of-3 co-scrub by the genesis holders)");
}

/// Register `who` in `on`'s directory with NO conferred roles (the ordinary path).
async fn register(on: &Node, who: &Node, id_type: &str, roles: Vec<String>) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: who.key_id.clone(),
        pubkey_ed25519_base64: who.ed_pub.clone(),
        pubkey_ml_dsa_65_base64: Some(who.pqc_pub.clone()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: who.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": who.key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: who.ed_pub.clone(),
        scrub_signature_pqc: None,
        scrub_key_id: who.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: roles,
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    on.engine
        .sqlite_backend()
        .expect("sqlite backend")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register key");
}

/// Seal ONE `trace:complete:v1` at `(tier=local, cohort_scope=self)` — where
/// every producer's row starts, and the only place persist lets a local row sit
/// ("local-tier rows MUST be `self`"). Returns its `attestation_id`.
///
/// Still `emit_attestation_self`, and deliberately: edge's replication DX owns
/// the CROSSING, not authorship. It ships producers for the two rows it is
/// itself the author of (`owner_binding_attestation`,
/// `replication_consent_attestation`) and none for `trace:*` — a trace is the
/// agent's claim, and persist's emit chokepoint is what stamps the instants into
/// the signed bytes (CIRISPersist#598) and binds the row mirror (#643).
async fn seal_trace(n: &Node, trace_id: &str) -> String {
    let trace_envelope = serde_json::json!({
        "dimension": "trace:complete:v1",
        // persist requires BOTH of these non-empty on any `trace:*` envelope
        // (admission.rs:1342 — `for field in ["trace_id", "agent_id_hash"]`),
        // else TraceDimensionInvalid.
        "trace_id": trace_id,
        "agent_id_hash": "0000000000000000000000000000000000000000000000000000000000000001",
        // EXACTLY ONE of "trace" (inline object) / "manifest" (content-addressed).
        // Inline is the simpler shape for a round test; the manifest form would
        // additionally require schema/content_hash/byte_len.
        "trace": { "summary": "in-process round e2e", "steps": 1 },
        "attesting_key_id": n.key_id,
        "subject_key_ids": [n.key_id],
        "score": 1.0,
        "cohort_scope": cohort_scope::SELF,
        // NO `asserted_at` here: the emit chokepoint stamps it, TRUNCATED to the
        // microsecond floor postgres can hold. A producer that writes the field
        // itself is honoured rather than overwritten, so a hand-written
        // `Utc::now()` put nanoseconds into the signed bytes — which persist v31
        // refuses outright rather than rounding (CIRISPersist#598).
    });
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(trace_envelope)
        .expect("trace envelope");
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        ciris_persist::federation::types::attestation_type::SCORES,
        core,
        cohort_scope::SELF,
    );
    input.attested_key_id = Some(n.key_id.clone());
    input.subject_key_ids = vec![n.key_id.clone()];
    n.engine
        .emit_attestation_self(input)
        .await
        .expect("seal a trace")
}

/// **Place a sealed trace through EDGE's one door** — `attestation_bind`'s
/// federation form.
///
/// `publish`, not `share`: edge deliberately leaves `federation` out of `With`
/// ("`federation` reads like 'the mesh' and means 'anyone at all, in the clear',
/// and it should be something you typed", `attestation_bind.rs:417`), and
/// `federation` is exactly where a trace goes — persist's sweep stamps the
/// covering grant's `audience`, which defaults to `federation`
/// (`ConsentGrantOptions::default`). The narrowing that keeps a trace off a
/// stranger's disk is NOT the cohort: `trace:*` resolves
/// `Projection::Capability(infra:serve)`, so the audience is narrowed per
/// RECIPIENT at send/fetch by the #379/#386 serve gate. Saying `publish` out
/// loud is right, and it is what the sweep was doing silently.
///
/// `CrossingBasis::ConsentGrant` naming the live grant — byte-for-byte the basis
/// `promote_consented_backlog` builds (persist v40.0.0 `engine.rs:3688` and
/// `:3740`), so the two doors describe the SAME nine-axis crossing and a
/// difference between them would be a difference in the substrate, not in how
/// they were asked.
///
/// Returns the id of the row the wider audience actually reads — the WIDENING,
/// not the row passed in. That distinction is the whole reason `Shared` carries
/// an id at all.
async fn place_through_edge(n: &Node, attestation_id: &str, grant_id: &str) -> String {
    use ciris_edge::replication::attestation_bind::{publish, CrossingBasis, Shared, Signers};

    let dir = n.engine.federation_directory();
    let row = dir
        .get_attestation(attestation_id)
        .await
        .expect("read the sealed row back")
        .unwrap_or_else(|| panic!("row {attestation_id} does not exist"));

    let crossing = publish(
        dir.as_ref(),
        &row,
        CrossingBasis::ConsentGrant {
            attestation_id: grant_id.to_owned(),
        },
        Signers {
            node: &n.edge_signer,
            // The node IS the attester of its own trace, so there is no separate
            // actor to hold. `None` here is a statement, not an omission — an
            // unsigned row by someone else would WAIT rather than be re-authored
            // in this node's name.
            actor: None,
        },
    )
    .await
    .expect("edge places the trace at the federation");

    match crossing.shared {
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            attestation_id
        }
        Shared::AwaitingActor {
            attestation_id,
            age_ms,
        } => panic!(
            "the trace {attestation_id} waits for its actor after {age_ms} ms — this node \
             authored it, so `custody_for` should have signed with the node's own key. \
             Check that `Node::edge_signer.key_id` is the DERIVED federation id and not \
             the alias"
        ),
    }
}

fn bridge(n: &Node) -> Arc<FederationDirectoryReplicationBridge> {
    let dir = n.engine.federation_directory();
    Arc::new(
        FederationDirectoryReplicationBridge::new(dir, Arc::new(Vec::new))
            .with_local_key_id(Some(n.key_id.clone())),
    )
}

/// Pump messages between two sessions until both are done or the budget is spent.
/// Returns how many envelopes the responder ADMITTED — the number that matters.
/// One side of a round: its session, its state access, and WHO IT IS.
///
/// Bundled rather than passed as eight positional arguments, and not merely to
/// satisfy a lint: with two `(session, provider, applier, peer)` triples side by
/// side, transposing the two peer ids is a silent mistake that resolves a
/// different question and answers "unspecified" for a correctly-consented pair.
/// Naming the side makes the direction explicit at every call site.
struct RoundSide<'a> {
    session: &'a mut Session,
    provider: &'a dyn StateProvider,
    applier: &'a mut dyn StateApplier,
    /// This side's own key id — passed to the PEER's `on_message` as the
    /// authenticated sender (CIRISEdge#426).
    key_id: &'a str,
}

fn drive_round(initiator: RoundSide<'_>, responder: RoundSide<'_>) -> usize {
    let RoundSide {
        session: initiator,
        provider: init_provider,
        applier: init_applier,
        key_id: init_peer,
    } = initiator;
    let RoundSide {
        session: responder,
        provider: resp_provider,
        applier: resp_applier,
        key_id: resp_peer,
    } = responder;
    let mut admitted_total = 0usize;

    let mut to_responder: Vec<ReplicationMessage> = match initiator.start_round(init_provider) {
        ReplicationOutcome::Send(msgs) => msgs,
        ReplicationOutcome::SendAndComplete { msgs, .. } => msgs,
        other => panic!("initiator start_round produced no messages: {other:?}"),
    };
    let mut to_initiator: Vec<ReplicationMessage> = Vec::new();

    // Bounded: a round that cannot converge is a FAILURE, not a hang — this is
    // the in-process analogue of the harness's "driver starts, never finishes".
    for _ in 0..24 {
        if to_responder.is_empty() && to_initiator.is_empty() {
            break;
        }
        for msg in std::mem::take(&mut to_responder) {
            match responder.on_message(msg, resp_provider, resp_applier, Some(init_peer)) {
                ReplicationOutcome::Send(msgs) => to_initiator.extend(msgs),
                ReplicationOutcome::SendAndComplete { msgs, .. } => to_initiator.extend(msgs),
                ReplicationOutcome::Applied { admitted, .. } => admitted_total += admitted,
                _ => {}
            }
        }
        for msg in std::mem::take(&mut to_initiator) {
            match initiator.on_message(msg, init_provider, init_applier, Some(resp_peer)) {
                ReplicationOutcome::Send(msgs) => to_responder.extend(msgs),
                ReplicationOutcome::SendAndComplete { msgs, .. } => to_responder.extend(msgs),
                ReplicationOutcome::Applied { admitted, .. } => admitted_total += admitted,
                _ => {}
            }
        }
    }
    admitted_total
}

/// THE round: an agent's sealed, consent-scoped `trace:*` reaches a canonical.
///
/// Deliberately mirrors the production shape rather than a convenient one:
/// the canonical carries `infra:serve`+`infra:attest`, the agent authors a real
/// `consent:replication:v1` grant covering `trace:`, and the canonical has
/// authored NO grant back — which is exactly the asymmetry that darkened the
/// receive side before CIRISEdge#414.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_trace_reaches_canonical_over_a_real_round() {
    init_tracing();
    arm_test_trust_root(&genesis_holders());
    let agent = node("agent", 0xA1, 0xA2).await;
    let canonical = node("canonical", 0xC1, 0xC2).await;

    // Both directories know both keys. The canonical carries the conferred roles
    // that ARE its standing consent to receive (#379/#386).
    register(&agent, &agent, identity_type::NODE, Vec::new()).await;
    register(&canonical, &agent, identity_type::NODE, Vec::new()).await;
    // The canonical's conferred roles ARE its standing consent to receive.
    confer_roles(&agent, &canonical, &[INFRA_SERVE, INFRA_ATTEST]).await;
    confer_roles(&canonical, &canonical, &[INFRA_SERVE, INFRA_ATTEST]).await;

    // LEG B (CIRISEdge#386, fixture from CIRISPersist#536): conferral alone is
    // leg A — the serve gate additionally requires the canonical's `infra:serve`
    // to ROOT to a trust root the AGENT trusts, so two nodes serve each other
    // only under a COMMON valid root and un-trust stops serving immediately.
    // Stands up all four `trust_root_valid` legs (the accord:lifecycle one is
    // accord_holder-reserved, hence the fixture) plus the scope-carrying edge.
    //
    // The REAL-USER flow (CIRISPersist#536, v21.17.0): the helper stands up the
    // ROOT-side legs it alone can do (root self-declaration + the accord_holder
    // witness + the accord:lifecycle freshness attestation, which is
    // accord_holder-reserved), and the real node emits its OWN
    // `delegates_to(user -> root)` edge signed by its OWN key — the one edge that
    // must genuinely come from the user.
    // Establish the root-side legs in BOTH directories. Edge v15.2.1's loud apply
    // path proved why: the canonical was REFUSING the replicated trust-root rows
    // with "attesting_key_id trace-round-e2e-root does not exist in
    // federation_keys" — it had never been told the root exists. A trust root is
    // shared state, not the sender's private opinion.
    for n in [&agent, &canonical] {
        ciris_persist::federation::operational::test_support::establish_trust_root_side(
            n.engine.federation_directory().as_ref(),
            "trace-round-e2e-root",
            &canonical.key_id,
            INFRA_SERVE,
        )
        .await
        .expect("root-side trust legs");
    }

    // The agent's own honest trust edge, signed by its real engine key.
    let trust_edge = serde_json::json!({
        "scope": [INFRA_ATTEST, INFRA_SERVE],
    });
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(trust_edge)
        .expect("trust edge envelope");
    let mut te = ciris_persist::federation::EmitAttestationInput::with_envelope(
        ciris_persist::federation::types::attestation_type::DELEGATES_TO,
        core,
        cohort_scope::FEDERATION,
    );
    te.attested_key_id = Some("trace-round-e2e-root".to_string());
    te.subject_key_ids = vec!["trace-round-e2e-root".to_string()];
    agent
        .engine
        .emit_attestation_self(te)
        .await
        .expect("the agent emits its OWN delegates_to(agent -> root) trust edge");

    // The agent consents to replicate `trace:` to the canonical. NOTE the default
    // prefix set is ["capacity:"] — a defaulted grant sweeps no traces at all,
    // which is itself a silent failure this test refuses to reproduce.
    let grant = ciris_server::peer::emit_replication_consent(
        &agent.engine,
        &agent.key_id,
        &canonical.key_id,
        &["trace:"],
    )
    .await
    .expect("agent authors a consent:replication grant covering trace:");

    // ══ TWO DOORS PLACE A TRACE, AND BOTH ARE PRODUCTION ═════════════════
    //
    // A sealed trace starts at `(tier=local, cohort_scope=self)` and has to be
    // both CROSSED into the mesh and WIDENED to an audience before the offer
    // filter will look at it. Since persist v39.0.0 those are two verbs, and
    // this node reaches them two different ways:
    //
    //   1. `promote_consented_backlog` — persist's consent-driven SWEEP, run
    //      every tick by `replication_reconcile::reconcile_once`. It is what
    //      places a trace sealed BEFORE its grant existed, and it is the only
    //      thing that ever places a trace today.
    //   2. `attestation_bind::publish` — EDGE's one door, per row, at the
    //      moment the producer holds it. The same composition (`enter_mesh`
    //      then a `supersedes` the actor signs), asked directly.
    //
    // Both are driven here because "we moved onto edge's DX" is only a true
    // statement if a row placed edge's way crosses the wire exactly like one
    // placed persist's way — and that is a ROUND property, invisible from
    // either door alone. This test is the only instrument that can see it.
    let swept = seal_trace(&agent, "round-e2e-trace-0001").await;
    let sweep = agent
        .engine
        .promote_consented_backlog()
        .await
        .expect("promote the consented backlog");
    // v39.0.0 folded the #530 repair motion INTO this sweep: pass 1 enters the
    // mesh, pass 2 widens rows already in it at an undiscoverable scope. There
    // is no second call to make — `repair_stranded_scope_backlog` is gone.
    assert!(
        sweep.promoted > 0 || sweep.widened > 0,
        "the trace must be placed by the consent edge — the sweep neither entered it \
         into the mesh ({} promoted) nor widened it to the grant's audience ({} \
         widened), so it is still invisible to the offer filter \
         (CIRISPersist#509/#530). {} row(s) await their actor's signer",
        sweep.promoted,
        sweep.widened,
        sweep.awaiting_actor,
    );

    // Sealed AFTER the sweep ON PURPOSE. The sweep walks every local-tier row
    // the grant covers, so a trace sealed before it would be placed by door 1
    // and prove nothing about door 2 — the fixture would be balanced, and a
    // balanced fixture tests nothing.
    let by_edge = seal_trace(&agent, "round-e2e-trace-0002").await;
    let placed_by_edge = place_through_edge(&agent, &by_edge, &grant.attestation_id).await;
    assert_ne!(
        placed_by_edge, by_edge,
        "a widening is a NEW `supersedes` row and its id is what the audience reads \
         — if `share` handed back the id it was given, nothing was widened and the \
         row the canonical can see is still the narrow one"
    );
    // Both doors leave the CLAIM row behind at `self` and place a widening. The
    // pair is the design (the narrow row is what the actor signed; the widening
    // is a separate claim they also signed), and a reader that cannot tell them
    // apart reports the trace as retracted by its own placement.
    for (door, narrow) in [
        ("the consent sweep", &swept),
        ("edge's `publish`", &by_edge),
    ] {
        let row = agent
            .engine
            .federation_directory()
            .get_attestation(narrow)
            .await
            .expect("read the narrow row back")
            .unwrap_or_else(|| panic!("{door}: the claim row vanished"));
        assert_eq!(
            row.cohort_scope,
            cohort_scope::SELF,
            "{door} must not rewrite the audience inside the bytes the actor signed \
             — that smuggling is why `attestation_promote` was deleted"
        );
    }

    // DIAGNOSTIC: does leg B actually resolve from the agent's records?
    {
        use ciris_persist::federation::trust_root::capability_roots_to_trusted_root;
        let dir = agent.engine.federation_directory();
        let r = capability_roots_to_trusted_root(
            dir.as_ref(),
            &agent.key_id,
            &canonical.key_id,
            INFRA_SERVE,
        )
        .await;
        // Leg B is the live frontier: the fixture returns Ok(()) but the walk
        // it exists to satisfy still resolves nothing (CIRISPersist#536).
        eprintln!(
            "LEG B WALK (expect false until #536 lands): {:?}",
            r.map(|o| o.is_some())
        );
        let role = ciris_persist::federation::admission::has_accord_conferred_role(
            dir.as_ref(),
            &canonical.key_id,
            INFRA_SERVE,
        )
        .await;
        // Leg A is REAL COVERAGE and must not regress: accord conferral through a
        // genuine 2-of-3 co-scrub gives the canonical its serve capability.
        assert_eq!(
            role.ok(),
            Some(true),
            "leg A regressed: the canonical must hold accord-conferred `infra:serve` \
             after a genuine 2-of-3 co-scrub by the genesis holders (#379/#386 leg A)"
        );
    }

    // Two bridges, each peer-bound as production binds them.
    let agent_bridge = bridge(&agent);
    let canon_bridge = bridge(&canonical);
    let agent_provider =
        DirectoryStateAdapter::new(agent_bridge.clone()).with_peer(canonical.key_id.clone());
    let canon_provider =
        DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(agent.key_id.clone());
    let mut agent_applier = MutableDirectoryStateAdapter::new(agent_bridge);
    let mut canon_applier = MutableDirectoryStateAdapter::new(canon_bridge);

    let offered_refs = agent_provider.local_refs(EnvelopeKind::Attestation);
    eprintln!(
        "AGENT OFFERS {} ref(s) to the canonical",
        offered_refs.len()
    );

    // ══ THE MIRRORED PREDICATE, HELD AGAINST THE REAL ONE ════════════════
    //
    // `federation_delivery::advertise_verdict` re-derives edge's
    // `attestation_is_advertised` because edge keeps it private
    // (v20.0.0 `replication/bridge.rs:4552`). A mirrored rule with nothing
    // comparing it to the original is the shape this codebase keeps paying for,
    // and this one had already drifted twice on the same two arms — answering
    // "withheld" for `Capability`/`Subject` where edge answers "advertised", so
    // a terminally-placed `trace:*` row was reported to the operator as stranded.
    //
    // The differential runs in ONE direction, and deliberately: `local_refs`
    // applies MORE than the projection filter (the per-peer consent and serve
    // gates sit on top of it), so "our predicate offers it" does not imply edge
    // advertises it. The converse does: a row edge PUT ON THE WIRE cannot be one
    // our predicate calls stranded. That is precisely the drift, and it is a
    // fact about the real filter, not about a second copy of the rule.
    {
        use ciris_persist::federation::namespace as ns;
        use sha2::Digest as _;
        // Edge's wire hash for this plane is `content_hash_of(&Attestation)` —
        // the sha256 of the BARE row's `serde_json::to_vec` (edge v20.0.0
        // `bridge.rs:7256`, and `:5811` for why the plane keys on it). NOT the
        // row's `original_content_hash`, which digests the ENVELOPE alone; using
        // that matched nothing and the vacuity guard below caught it.
        let by_hash: std::collections::HashSet<[u8; 32]> =
            offered_refs.iter().map(|r| r.envelope_hash).collect();
        let mine = agent
            .engine
            .federation_directory()
            .list_attestations_by(&agent.key_id)
            .await
            .expect("the agent's own corpus");
        let mut checked = 0usize;
        let mut traces_checked = 0usize;
        for a in &mine {
            let wire_hash: [u8; 32] = sha2::Sha256::digest(
                serde_json::to_vec(a).expect("serialize the row edge advertises"),
            )
            .into();
            if !by_hash.contains(&wire_hash) {
                continue;
            }
            let dim = a
                .attestation_envelope
                .get(ciris_persist::federation::envelope::paths::DIMENSION)
                .and_then(|d| d.as_str())
                .unwrap_or_default();
            let proj = ns::projection_for(
                ns::Plane::Attestation { dimension: dim },
                &a.cohort_scope,
                ns::registry::authority_for(dim).class,
                ns::is_withdraw_or_revocation(&a.attestation_type),
            );
            let verdict = ciris_server::federation_delivery::advertise_verdict(
                &proj,
                &a.attesting_key_id,
                &agent.key_id,
            );
            assert!(
                verdict.is_offered(),
                "edge PUT {} ({dim}, scope={}, {proj:?}) on the wire, and our mirrored \
                 predicate calls it `{}`. The operator surface would report it as \
                 `stranded_covered_rows` and send someone to re-scope a row that is \
                 already placed. Re-read edge's `attestation_is_advertised` \
                 (v20.0.0 bridge.rs:4584) and fix `advertise_verdict` to match it",
                a.attestation_id,
                a.cohort_scope,
                verdict.as_str(),
            );
            checked += 1;
            if dim.starts_with("trace:") {
                traces_checked += 1;
            }
        }
        // The join itself is load-bearing, and it already failed once: a
        // differential whose two sides stop matching passes VACUOUSLY, which is
        // the one failure mode a differential must not have. This guard is what
        // turned a green "0 rows compared" into a red naming the reason.
        assert!(
            checked > 0 && traces_checked > 0,
            "the ref→row join matched {checked} row(s) and {traces_checked} trace(s) — \
             the differential above would have passed without comparing anything. \
             `EnvelopeRef.envelope_hash` is no longer sha256(serde_json::to_vec(row))"
        );
        eprintln!(
            "ADVERTISE DIFFERENTIAL: {checked} offered row(s) ({traces_checked} trace) \
             agree with edge's own filter"
        );
    }

    let mut initiator = Session::new(SessionRole::Initiator, EnvelopeKind::Attestation);
    let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);

    // Anti-entropy converges over ROUNDS, not in one pass: the first round lands
    // what the peer can admit given its current state, and a later round carries
    // what that state then unlocks (a trace whose admission depends on the consent
    // grant that arrived alongside it). Drive until quiescent rather than assuming
    // one round is the whole conversation.
    let mut admitted = 0usize;
    for _ in 0..4 {
        initiator.reset();
        responder.reset();
        admitted += drive_round(
            RoundSide {
                session: &mut initiator,
                provider: &agent_provider,
                applier: &mut agent_applier,
                key_id: &agent.key_id,
            },
            RoundSide {
                session: &mut responder,
                provider: &canon_provider,
                applier: &mut canon_applier,
                key_id: &canonical.key_id,
            },
        );
    }

    assert!(
        admitted > 0,
        "the round completed but the canonical admitted NOTHING. This is the exact \
         end-state the mesh harness kept reporting: every upstream predicate green \
         (sealed, consented, promoted, offerable) and still zero arrivals. Check, in \
         order: the responder's RECEIVE path is not gated by its own SEND consent \
         (CIRISEdge#414); `local_holdings` returns real holdings rather than \
         advertise-filtered refs (CIRISEdge#416); the trace's cohort_scope permits \
         the offer",
    );

    // The assertion that actually means "it shipped": the row is in the
    // canonical's corpus, attested by the agent.
    let landed = canonical
        .engine
        .federation_directory()
        .list_attestations_by(&agent.key_id)
        .await
        .expect("read the canonical's corpus");
    let traces: Vec<_> = landed
        .iter()
        .filter(|a| {
            a.attestation_envelope
                .get(ciris_persist::federation::envelope::paths::DIMENSION)
                .and_then(|d| d.as_str())
                .is_some_and(|d| d.starts_with("trace:"))
        })
        .collect();
    // ── THE RELEASE CRITERION — it crossed on persist v30.1.0 / edge v15.18.3 ──
    // This was a named soft frontier for the whole arc: it logged and returned
    // green, so the suite could stay honest about a gap it could not yet close.
    // Four causes had to fall first, and not one of them was visible from a
    // single side — which is the entire reason this harness exists:
    //
    //   * CIRISEdge#414 — the #396 SEND-consent gate darkening the RECEIVE side,
    //     so a canonical holding `infra:serve` withheld the whole Attestation
    //     plane because it had authored no grant back toward the agent.
    //   * CIRISEdge#416 — `local_holdings` returning advertise-filtered refs
    //     instead of real holdings, so `want` could never shrink.
    //   * CIRISEdge#423 made the apply path LOUD, and it paid immediately: four
    //     previously-invisible refusals turned out to be a FIXTURE gap (the trust
    //     root established only in the SENDER's directory). `admitted` 1 → 5.
    //   * CIRISPersist#610 — `set_attestation_cohort_scope` updated the row
    //     without upserting `signed_wire_index`, so the promoted trace advertised
    //     a hash the wire index could not serve: `wanted=6 packed=5 dropped=1`,
    //     the one dropped ref being the trace. THAT is why the row was offered
    //     and then neither admitted nor refused — it was never packed, and the
    //     accounting that said so existed only on the SENDER. `admitted` is 6.
    //
    // `release_gates::planes::gate_trace_flow_over_replication` reads this file
    // and goes red if the assertion below is ever softened back to a log line.
    assert!(
        !traces.is_empty(),
        "THE RELEASE CRITERION: no `trace:*` reached the canonical over a real \
         anti-entropy round. {admitted} envelope(s) admitted, so the round itself \
         worked and consent rows crossed — it is the trace specifically that did \
         not. Check the sender's ledger FIRST (withholds_by_reason), not the \
         receiver: a serve-gate withhold and a Deliver-pack drop look identical \
         from this side. Prior causes, both now closed: CIRISEdge#455 (serve gate \
         withholds at per-peer advertise when infra:serve is claimed but not \
         accord-conferred) and CIRISPersist#610 (set_attestation_cohort_scope \
         updated the row without upserting signed_wire_index, so the promoted \
         trace advertised a hash the index could not serve — `wanted=6 packed=5 \
         dropped=1`)."
    );

    // ── AND THE CONVERSION'S OWN CRITERION ────────────────────────────────
    // Edge's door is not adopted until a row placed through it crosses. The
    // assertion above passes on EITHER trace, so it cannot see the difference:
    // door 1 alone would keep it green while `attestation_bind::publish` placed
    // nothing the canonical could read. Name both trace ids.
    let arrived: std::collections::BTreeSet<&str> = traces
        .iter()
        .filter_map(|a| {
            a.attestation_envelope
                .get("trace_id")
                .and_then(|t| t.as_str())
        })
        .collect();
    for (door, trace_id) in [
        ("persist's consent sweep", "round-e2e-trace-0001"),
        ("edge's `attestation_bind::publish`", "round-e2e-trace-0002"),
    ] {
        assert!(
            arrived.contains(trace_id),
            "{door} placed a trace that never reached the canonical. Arrived: {arrived:?} \
             ({} trace row(s), {admitted} envelope(s) admitted). A door that places a row \
             the wire cannot carry has not replaced the other one — read the SENDER's \
             ledger first (`withholds_by_reason`), because a serve-gate withhold and a \
             Deliver-pack drop are indistinguishable from here",
            traces.len(),
        );
    }
    eprintln!(
        "TRACE PLANE CROSSED: {} trace:* row(s) in the canonical's corpus, from both \
         doors ({arrived:?})",
        traces.len()
    );
}

/// The negative that keeps the positive honest: with NO consent grant, the agent
/// must offer nothing. If this ever passes traces, the #396 SEND gate has been
/// weakened — the fail-secure half that CIRISEdge#414 explicitly preserved while
/// opening the receive side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_grant_the_producer_offers_nothing() {
    let agent = node("agent2", 0xB1, 0xB2).await;
    let canonical = node("canonical2", 0xD1, 0xD2).await;
    // No conferral needed: this asserts the producer's SEND gate, which is
    // consent-driven and independent of the recipient's roles.
    register(&agent, &agent, identity_type::NODE, Vec::new()).await;
    register(&agent, &canonical, identity_type::NODE, Vec::new()).await;

    // NO emit_replication_consent — that is the whole point.
    let agent_bridge = bridge(&agent);
    let provider = DirectoryStateAdapter::new(agent_bridge).with_peer(canonical.key_id.clone());

    let refs = provider.local_refs(EnvelopeKind::Attestation);
    assert!(
        refs.is_empty(),
        "a producer with NO consent:replication grant toward the peer must advertise \
         nothing on the Attestation plane (CIRISEdge#396 item 1, fail-secure). Got {} \
         ref(s) — the send-side gate has regressed",
        refs.len(),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// COORDINATOR-DRIVEN VARIANT (CIRISAgent#932 — the "driver starts, never
// terminates" stall)
// ═══════════════════════════════════════════════════════════════════════════
//
// The round test above hand-pumps `Session` and CONVERGES for the Attestation
// kind. The live harness drives the same sessions through `ReplicationCoordinator`
// and does NOT. That difference is the whole remaining search space, so this
// drives the coordinator layer instead — same engines, same bridges, same
// providers — to localize the stall to (or exonerate) that layer.
//
// The structural suspicion this probes: `drive_round_step` holds the `session`
// tokio-Mutex and then acquires the `applier` Mutex, and `on_message` runs the
// provider's `block_in_place` + `block_on` INSIDE both guards. A blocking bridge
// read under two held async locks is exactly the shape that presents as
// "driver starts, no terminal line, no error".
//
// RESULT: it CONVERGES. Full exchange, both sides terminal:
//   I start -> SendThenWait[Summary]
//   R <-Summary -> SendThenWait[Summary,Diff]   I <-Summary -> SendThenWait[Diff]
//   I <-Diff    -> SendThenWait[Deliver]        R <-Diff    -> SendThenWait[Deliver]
//   R <-Deliver -> Complete                     I <-Deliver -> Complete
//
// So the coordinator layer is EXONERATED for CIRISAgent#932, and with the
// hand-pumped round above the exoneration set is: Session state machine,
// bridge/providers (incl. #416 local_holdings), and ReplicationCoordinator.
// Whatever stalls the live harness is ABOVE this line — the runtime/scheduler
// that drives coordinators, `deliver_inbound` routing, or the real transport.
//
// One trap this test encodes, because it cost a false-positive "livelock" here:
// `drive_round_step` RETURNS the messages to send; it does NOT send them. A
// harness that forgets to pump them sees a round that never progresses and
// looks exactly like the stall being investigated.
//
// BOUNDED: a non-terminating round FAILS with the reproduction rather than
// hanging, so this stays a debuggable assertion if it ever regresses.

/// `drive_round_step` RETURNS the messages to send; it does not send them.
/// The caller owns the wire. (Getting this wrong makes the round look like a
/// livelock — nothing ever reaches the peer.)
async fn send_step(
    coord: &ciris_edge::replication::ReplicationCoordinator,
    step: &ciris_edge::replication::DriveStep,
) {
    use ciris_edge::replication::DriveStep;
    let msgs: &[ReplicationMessage] = match step {
        DriveStep::SendThenWait(m) => m,
        DriveStep::SendThenComplete(m, _) => m,
        DriveStep::Complete(_) | DriveStep::Refused => &[],
    };
    for m in msgs {
        coord.send_message(m).await.expect("send via loopback");
    }
}

fn step_name(s: &ciris_edge::replication::DriveStep) -> String {
    use ciris_edge::replication::DriveStep;
    match s {
        DriveStep::SendThenWait(m) => format!("SendThenWait({})", m.len()),
        DriveStep::SendThenComplete(m, _) => format!("SendThenComplete({})", m.len()),
        DriveStep::Complete(_) => "Complete".to_string(),
        // A refusal is a TERMINAL, SPEAKING outcome — surfacing it by name is
        // the difference between "the driver went quiet" and "the driver said no".
        other => format!("{other:?}"),
    }
}

/// The wire verb, by name, for the round trace.
///
/// Exhaustive ON PURPOSE — no `_` arm. A new `ReplicationMessage` variant is a
/// wire-compat event (v1 peers serde-REFUSE an unknown tag rather than ignoring
/// it), so it must break this build and be named deliberately. `Pull` arrived
/// with edge v15.22.0 / CIRISEdge#462 and this is exactly the compile failure
/// that discipline is for — a wildcard here would have logged the receive axis as
/// "other" and told nobody it existed.
fn msg_name(m: &ReplicationMessage) -> &'static str {
    match m {
        ReplicationMessage::Summary(_) => "Summary",
        ReplicationMessage::Diff(_) => "Diff",
        ReplicationMessage::Deliver(_) => "Deliver",
        ReplicationMessage::Fetch(_) => "Fetch",
        ReplicationMessage::Pull(_) => "Pull",
        // v16.3.0 / CIRISEdge#474 — the cursor plane's request verb, and the
        // discipline above working as intended: adopting edge broke this build,
        // which is how the sixth verb got named instead of silently counted as
        // "other". `CursorPull` → `Deliver`, resumed on `evidence_at`, carrying
        // `accord_quorum_evidence` — the first kind served off a cursor rather
        // than the content-hash Summary/Diff/Fetch flow.
        ReplicationMessage::CursorPull(_) => "CursorPull",
    }
}

struct Loopback {
    to_peer: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Simulated link MDU. `Some(n)` = frames LARGER than `n` are silently
    /// dropped while `send` still reports `Delivered` — the exact shape of a
    /// transport that reports success while the frame never reaches the wire
    /// (CIRISAgent#932's "swallowed between coordinator and wire").
    mdu: Option<usize>,
    /// Every frame size that crossed, for measurement.
    sizes: Arc<std::sync::Mutex<Vec<usize>>>,
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
        self.sizes
            .lock()
            .expect("sizes lock")
            .push(envelope_bytes.len());
        if let Some(mdu) = self.mdu {
            if envelope_bytes.len() > mdu {
                // Silently dropped — but reported Delivered, exactly like a
                // reverse path that falls through to the resource gate and
                // never gets a slot.
                return Ok(ciris_edge::transport::TransportSendOutcome::Delivered);
            }
        }
        let _ = self.to_peer.send(envelope_bytes.to_vec()).await;
        Ok(ciris_edge::transport::TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<ciris_edge::transport::InboundFrame>,
    ) -> Result<(), ciris_edge::transport::TransportError> {
        // Frames are delivered directly via `deliver_inbound` in this harness.
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Drive one coordinator-level Attestation round under a simulated link MDU.
/// `mdu = None` ⇒ every frame crosses. `Some(n)` ⇒ frames larger than `n` are
/// SILENTLY DROPPED while `send` still reports `Delivered` — the exact shape of
/// a reverse path that falls through to the resource gate and never gets a slot.
/// Returns `(converged, frame_sizes)`.
async fn drive_coordinator_round(mdu: Option<usize>, tag: &str) -> (bool, Vec<usize>) {
    use ciris_edge::replication::{DriveStep, ReplicationCoordinator};

    arm_test_trust_root(&genesis_holders());
    let agent = node(&format!("agent-{tag}"), 0xE1, 0xE2).await;
    let canonical = node(&format!("canon-{tag}"), 0xF1, 0xF2).await;
    register(&agent, &agent, identity_type::NODE, Vec::new()).await;
    register(&canonical, &agent, identity_type::NODE, Vec::new()).await;
    confer_roles(&agent, &canonical, &[INFRA_SERVE, INFRA_ATTEST]).await;
    confer_roles(&canonical, &canonical, &[INFRA_SERVE, INFRA_ATTEST]).await;

    ciris_server::peer::emit_replication_consent(
        &agent.engine,
        &agent.key_id,
        &canonical.key_id,
        &["trace:"],
    )
    .await
    .expect("consent grant");

    let sizes: Arc<std::sync::Mutex<Vec<usize>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (c_tx, mut c_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let agent_bridge = bridge(&agent);
    let canon_bridge = bridge(&canonical);
    let agent_coord = ReplicationCoordinator::new(
        Arc::new(Loopback {
            to_peer: c_tx,
            mdu,
            sizes: Arc::clone(&sizes),
        }),
        canonical.key_id.clone(),
        EnvelopeKind::Attestation,
        SessionRole::Initiator,
        Arc::new(
            DirectoryStateAdapter::new(agent_bridge.clone()).with_peer(canonical.key_id.clone()),
        ),
        Arc::new(MutableDirectoryStateAdapter::new(agent_bridge)),
    );
    let canon_coord = ReplicationCoordinator::new(
        Arc::new(Loopback {
            to_peer: a_tx,
            mdu,
            sizes: Arc::clone(&sizes),
        }),
        agent.key_id.clone(),
        EnvelopeKind::Attestation,
        SessionRole::Responder,
        Arc::new(DirectoryStateAdapter::new(canon_bridge.clone()).with_peer(agent.key_id.clone())),
        Arc::new(MutableDirectoryStateAdapter::new(canon_bridge)),
    );

    // Drive: initiator starts, then pump both directions until terminal.
    let budget = std::time::Duration::from_secs(20);
    let driven = tokio::time::timeout(budget, async {
        let mut responder_done = false;
        let mut step = agent_coord
            .drive_round_step(None)
            .await
            .expect("initiator start_round");
        eprintln!("  I start => {}", step_name(&step));
        send_step(&agent_coord, &step).await;
        for _ in 0..48 {
            // BOTH sides must reach terminal. Tracking only the initiator hides
            // the #932 signature exactly: when the big Deliver is lost, the
            // INITIATOR still completes (it receives the peer's small Deliver)
            // while the RESPONDER waits forever for a payload that never lands.
            if responder_done
                && matches!(
                    step,
                    DriveStep::Complete(_) | DriveStep::SendThenComplete(_, _)
                )
            {
                return true;
            }
            // Responder consumes whatever the initiator sent.
            let mut progressed = false;
            while let Ok(bytes) = c_rx.try_recv() {
                let msg = ReplicationCoordinator::parse_inbound_bytes(&bytes)
                    .expect("parse inbound at responder");
                eprintln!("  R <- {}", msg_name(&msg));
                let s = canon_coord
                    .drive_round_step(Some(msg))
                    .await
                    .expect("responder step");
                eprintln!("  R => {}", step_name(&s));
                send_step(&canon_coord, &s).await;
                if matches!(
                    s,
                    DriveStep::Complete(_) | DriveStep::SendThenComplete(_, _)
                ) {
                    responder_done = true;
                }
                progressed = true;
                if matches!(
                    s,
                    DriveStep::Complete(_) | DriveStep::SendThenComplete(_, _)
                ) {
                    // responder done; keep pumping for the initiator
                }
            }
            while let Ok(bytes) = a_rx.try_recv() {
                let msg = ReplicationCoordinator::parse_inbound_bytes(&bytes)
                    .expect("parse inbound at initiator");
                eprintln!("  I <- {}", msg_name(&msg));
                step = agent_coord
                    .drive_round_step(Some(msg))
                    .await
                    .expect("initiator step");
                eprintln!("  I => {}", step_name(&step));
                send_step(&agent_coord, &step).await;
                progressed = true;
            }
            if !progressed {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        false
    })
    .await;

    let sizes_out = sizes.lock().expect("sizes lock").clone();
    (matches!(driven, Ok(true)), sizes_out)
}

/// BASELINE: with no MDU limit the coordinator-level round converges — the
/// layer is exonerated for CIRISAgent#932.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coordinator_driven_attestation_round_terminates() {
    let (converged, sizes) = drive_coordinator_round(None, "base").await;
    let max = sizes.iter().copied().max().unwrap_or(0);
    eprintln!("ATTESTATION ROUND FRAME SIZES: {sizes:?} (max {max} bytes)");
    assert!(
        converged,
        "the coordinator-driven Attestation round must reach a terminal DriveStep \
         (frames: {sizes:?})"
    );

    // THE #932 SIZE FACT, pinned. Every control frame in the round is tiny; the
    // Deliver frame carrying the attestation envelopes is orders of magnitude
    // larger than any Reticulum PACKET MDU (~hundreds of bytes). So on the real
    // wire the Deliver is FORCED onto the resource path — the branch every
    // small-payload kind (Key/IdentityOccurrence/TransportDestination) never
    // takes, which is exactly why those complete while Attestation does not.
    assert!(
        max > 4096,
        "expected the Attestation Deliver frame to be far larger than a packet MDU \
         — if this ever drops below a few KB the size hypothesis for #932 needs \
         revisiting (max was {max} bytes; frames {sizes:?})"
    );
}

/// FIXED IN edge v15.2.0 — but this pin STAYS, and here is why it still passes.
///
/// The cure lives in the RETICULUM TRANSPORT (a `CFRG` fragment protocol +
/// inbound reassembler, with the residual gap — degenerate MDU below
/// `MIN_FRAGMENTABLE_MDU`, or backpressure mid-fragment-send — now a LOUD
/// throttled WARN instead of a silent drop). This harness uses a loopback
/// transport, so it sits ABOVE that layer and cannot exercise fragmentation:
/// what it still models is a NON-FRAGMENTING transport that reports `Delivered`
/// and drops. That remains exactly the residual class edge now warns about, so
/// the pin keeps its value as the shape-of-failure regression rather than as a
/// claim about the current wire.
///
/// Note also that the new `MAX_DELIVER_ENVELOPE_BYTES` budget (512 KiB) does not
/// bear on the observed case: the failing Deliver was ~19 KB, ~27x UNDER that
/// budget. The batch cap bounds how much is packed; FRAGMENTATION is what carries
/// an over-MDU frame. Both are needed, and only the latter addresses #932.
///
/// REPRODUCTION: a transport that SILENTLY DROPS oversized frames while
/// reporting `Delivered` produces CIRISAgent#932's exact signature — the round
/// starts, the small frames flow, and it never terminates. Pins the failure mode
/// so a fix can be demonstrated against it rather than argued about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_deliver_silently_dropped_reproduces_932() {
    // 1 KiB: comfortably above every control frame, far below the Deliver.
    let (converged, sizes) = drive_coordinator_round(Some(1024), "mdu").await;
    let max = sizes.iter().copied().max().unwrap_or(0);
    eprintln!("MDU-LIMITED ROUND FRAME SIZES: {sizes:?} (max {max} bytes)");
    assert!(
        !converged,
        "a silently-dropped oversized Deliver MUST stall the round — if this now \
         converges, either the Deliver got small enough to fit or the protocol \
         gained a retry/fragmentation path. Both are good news, but this pin has \
         to be re-derived (frames: {sizes:?})"
    );
    assert!(
        sizes.len() >= 3,
        "the round should still exchange its SMALL control frames before stalling \
         — that asymmetry (small frames flow, the big one vanishes) IS the #932 \
         signature (frames: {sizes:?})"
    );
}
