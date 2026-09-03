//! Agent-embedded federation-delivery controller (CIRISServer#205, subsuming
//! #204).
//!
//! # The gap this closes
//!
//! A *compose* node (ciris-server's own boot, [`crate::compose::serve`]) drives
//! federation delivery to the canonical mesh from a stack of controllers wired at
//! boot: [`crate::compose::start_replication_runtime`] (the `ReplicationRuntime`
//! over the shared Reticulum transport), [`crate::replication_reconcile::spawn`]
//! (the consent-topology reconcile loop) and [`crate::compose::spawn_announce_logger`]
//! (RNS rooting visibility). The AGENT embeds an Edge via `init_edge_runtime`
//! (edge's pyo3 ctor) but never runs any of that — so on the agent side the CEG
//! trace chain seals + signs locally but **nothing is delivered to Node A**: the
//! replication runtime is never started, no `consent:replication` topology is
//! authored for the baked canonical peer, and the rooting exchange is invisible.
//!
//! # The one entry the agent calls
//!
//! [`run_federation_delivery`] grabs the in-process embedded handles
//! (`ciris_persist::…::current_rust_engine()` + `ciris_edge::current_edge()`,
//! installed by the persist/edge pyo3 ctors) and, IN-PROCESS:
//!
//!   1. Reads the baked canonical record's `transport_hints`
//!      ([`Engine::canonical_bootstrap_hints`]) → the canonical `key_id`s (the
//!      replication targets) + their dialable ip addresses (logged; see the
//!      dial-set caveat below — subsumes #204).
//!   2. ROOTS each admitted canonical's transport binding (reachability only) so
//!      `knows_peer(canonical)` is true. It authors NO consent:
//!      `consent:replication` is an explicit owner act — the agent's setup wizard
//!      POSTs `/v1/federation/consent` (owner-gated, so necessarily AFTER the
//!      owner claim) when the owner opts into sharing. A pure server makes no
//!      traces and never auto-consents to replicate them.
//!   3. Starts (or, post-#312, receives the already-composed) ONE
//!      `ReplicationRuntime` over the shared transport
//!      ([`crate::compose::start_replication_runtime`] — the SAME core, single
//!      composition per process). The canonical enters the REPLICATION topology
//!      purely via an owner-authored consent:replication grant — the hot path
//!      reads CEG alone; rooting alone dials but replicates nothing.
//!   4. Spawns the consent-topology reconcile loop
//!      ([`crate::replication_reconcile::reconcile_once`] on `cadence_seconds`).
//!   5. Spawns the announce logger over `edge.events()` so RNS rooting is visible.
//!
//! The runtime + its scheduler tasks + the reconcile loop are held for the process
//! lifetime in a process static ([`hold`]), so a Python caller dropping the return
//! value never tears delivery down.
//!
//! # Post-boot ordering (the CIRISServer#205 caveat, verified against edge v9.2.0)
//!
//! Compose's own comment says `install_replication_routing` "MUST run BEFORE
//! `edge.run()`". On the AGENT path the Edge is ALREADY running. This is
//! nevertheless safe: `Edge::run` clones the `Arc<OnceLock>` replication registry
//! and reads it LIVE per inbound frame (`replication_registry.get()` inside the
//! run loop), so a post-boot `install_replication_routing` populates the SAME
//! `OnceLock` the running loop holds and is observed on the next inbound frame.
//! Starting the `ReplicationRuntime` and cloning `reticulum_transport()` are both
//! `&self` accessors on the live Edge — safe at any time.
//!
//! **The one thing that is genuinely build-time-only** is the transport's TCP
//! bootstrap **dial** set: `ReticulumTransport` seeds `add_tcp_client(bootstrap_peers)`
//! at build time and exposes NO runtime add-peer. So this controller CANNOT dial a
//! *new* address that was not in the edge's `bootstrap_peers` at
//! `init_edge_runtime` time. It reads + logs the canonical ip hints (subsuming
//! #204's read), and delivery reaches Node A once the canonical address is present
//! in the edge's init `bootstrap_peers` OR the peer is reachable via an announce
//! over a shared interface. Seeding that dial at init is the agent-side half of
//! #204 (CIRISAgent#896) — this controller drives everything ELSE end to end.

use std::sync::Arc;
#[cfg(feature = "python")]
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use ciris_edge::replication::ReplicationRuntime;
use ciris_edge::Edge;
use ciris_persist::prelude::Engine;
use tokio::sync::watch;

/// A started delivery controller. Holding this keeps the `ReplicationRuntime`
/// scheduler + the reconcile-loop task alive; dropping it drops the strong
/// runtime `Arc` and signals the reconcile loop to stop. In the wheel it is
/// stashed in the [`hold`] process static so a Python caller need not retain it.
pub struct DeliveryController {
    /// The live replication runtime (the reconcile loop mutates its peer set).
    pub runtime: Arc<ReplicationRuntime>,
    /// The canonical `key_id`s seeded as replication targets (for observability).
    pub canonical_targets: Vec<String>,
    /// Shutdown signal for the reconcile loop.
    reconcile_shutdown: watch::Sender<bool>,
    /// The reconcile-loop task handle (held so the task is not detached-and-lost).
    _reconcile_join: tokio::task::JoinHandle<()>,
}

impl Drop for DeliveryController {
    fn drop(&mut self) {
        let _ = self.reconcile_shutdown.send(true);
    }
}

/// Process-global hold for the started controller + the runtime that drives its
/// spawned tasks. The `tokio::runtime::Runtime` MUST be held here: the controller
/// starts the `ReplicationRuntime` scheduler + the reconcile loop via
/// `tokio::spawn` onto this runtime, and those tasks stop the instant the runtime
/// is dropped. Holding it in a `static` gives the delivery machinery the process
/// lifetime (mirrors compose retaining the `Arc<ReplicationRuntime>` for the
/// node's lifetime).
///
/// Gated on `python`: the only entry that installs into it ([`start_and_hold`])
/// grabs the persist pyo3 engine static, which exists only in the wheel build.
#[cfg(feature = "python")]
static HELD: OnceLock<(tokio::runtime::Runtime, Arc<DeliveryController>)> = OnceLock::new();

/// The held runtime + controller, for in-process callers outside this module.
///
/// The fold has exactly ONE runtime and every in-process entry point must use
/// it. A second `Runtime::new()` inside a pyo3 call would block on a different
/// reactor than the one holding the Edge and the delivery loop — the class of
/// bug that produced the fold-boot panics (#264 reentrancy shield, verify #204).
#[cfg(feature = "python")]
pub(crate) fn held() -> Option<&'static (tokio::runtime::Runtime, Arc<DeliveryController>)> {
    HELD.get()
}

/// Whether [`start_and_hold`] has already installed a controller in this process.
#[cfg(feature = "python")]
pub fn is_started() -> bool {
    HELD.get().is_some()
}

/// Stash the driving runtime + controller for the process lifetime. First call
/// wins (delivery is started exactly once per process — a second start would spin
/// up a duplicate `ReplicationRuntime` on the one transport). Returns the seeded
/// canonical-target count of whichever controller is now held.
#[cfg(feature = "python")]
fn hold(rt: tokio::runtime::Runtime, controller: Arc<DeliveryController>) -> usize {
    match HELD.set((rt, controller)) {
        Ok(()) => HELD
            .get()
            .map(|(_, c)| c.canonical_targets.len())
            .unwrap_or(0),
        Err((rt, _dupe)) => {
            // Lost the race / a second call: drop the freshly-built runtime (its
            // Drop shuts down the just-spawned duplicate tasks) and report the
            // already-held controller's target count.
            drop(rt);
            HELD.get()
                .map(|(_, c)| c.canonical_targets.len())
                .unwrap_or(0)
        }
    }
}

/// Grab the in-process embedded handles installed by the persist/edge pyo3 ctors,
/// build a dedicated multi-thread runtime, start the delivery controller on it,
/// and hold both for the process lifetime. Returns the number of admitted
/// canonical replication targets seeded. Idempotent per process: a second call is
/// a no-op that returns the already-held target count.
///
/// This is the entry the wheel's `#[pyfunction] start_federation_delivery` calls.
/// It creates its OWN runtime (rather than borrowing the agent's) so the
/// controller's task lifetimes are explicit and owned here — the same
/// single-runtime shape compose uses, just held in a `static` instead of a stack
/// frame. Gated on `python`: `current_rust_engine()` lives in persist's pyo3 FFI
/// surface, which only compiles into the wheel.
#[cfg(feature = "python")]
pub fn start_and_hold(cadence_seconds: Option<u64>, announce_logger: bool) -> Result<usize> {
    if is_started() {
        tracing::info!("federation delivery already started in this process — no-op");
        return Ok(HELD
            .get()
            .map(|(_, c)| c.canonical_targets.len())
            .unwrap_or(0));
    }

    // The in-process embedded handles: persist's engine static (pyo3) + edge's
    // downstream `current_edge()` accessor (CIRISEdge#289). A clear error (not a
    // panic) if the agent calls this before its engine/edge are up.
    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine().context(
        "federation delivery: no in-process persist Engine (current_rust_engine() is None) — call \
         after the embedded engine is initialized",
    )?;
    let edge: Arc<Edge> = ciris_edge::current_edge().map_err(|e| {
        anyhow::anyhow!(
            "federation delivery: no in-process embedded Edge (current_edge() failed: {e}) — call \
             after init_edge_runtime()"
        )
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ciris-fed-delivery")
        .build()
        .context("build federation-delivery runtime")?;
    // #393 item 2 / #406: publish THIS node's SIGNED transport destination
    // before delivery rounds begin. compose::serve does this for served nodes;
    // the BARE embedded topology (agent fold pre-serve, mesh-repro harness
    // agent) reaches delivery only through here — without it the peer's PQ
    // attribution gate refuses every non-bootstrap frame from us
    // ("no hybrid-verified TransportDestination binds this transport
    // identity") and traces can never ship. Same producer, every topology.
    let node_key_id = edge.signer_key_id().to_string();
    // ── Waiting for claim ─────────────────────────────────────────────────────
    //
    // An agent-carrying node that nobody owns must not join the mesh. Held BEFORE
    // the transport destination is published, because publishing is already
    // joining: it is what makes this node dialable and what a peer's attribution
    // gate reads. Holding after it would announce a node we then refuse to run.
    //
    // Not an error. The node is up, its claim surface is serving, and the PIN +
    // NodeCode banner printed at `claim_pin` is the instruction for clearing it.
    // `reprime_federation_delivery` is the resume once the claim lands.
    if let crate::node_key::StartupGate::WaitingForClaim { actor_key_id } =
        rt.block_on(crate::node_key::startup_gate(&engine))
    {
        WAITING_FOR_CLAIM.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::warn!(
            actor_key_id = %actor_key_id,
            "waiting for claim to continue startup — this node carries an agent and has no \
             owner, so `may_act_through` cannot be answered for anything the brain authors \
             (CC 3.4.7.3 Clause D is fail-closed). Claim it with the NodeCode + PIN printed \
             at boot (POST /v1/setup/root), then call reprime_federation_delivery."
        );
        return Ok(0);
    }
    WAITING_FOR_CLAIM.store(false, std::sync::atomic::Ordering::SeqCst);

    rt.block_on(crate::compose::publish_self_transport_destination(
        &engine,
        &edge,
        &node_key_id,
    ));
    // STAGE 1 on the DELIVERY path too. The embedded agent never runs
    // serve_with_adapter, so wiring this only in compose would leave every agent
    // node without a trust root while the composed node looked fine — the same
    // shape as the AV-77 arming split below.
    rt.block_on(async {
        if let Err(e) = crate::mesh_genesis::install_baked_trust_root(&engine).await {
            tracing::error!(error = %e, "stage 1 (baked trust root) FAILED on the delivery \
                                         path — this node will withhold every trace:* row");
        }
    });

    // CIRISPersist#543 AV-77 (v22.0.0) — arm the in-band peer de-admission gate on
    // the DELIVERY path too. The embedded agent never runs `serve_with_adapter`, so
    // arming only there would leave every agent node's sanction gate dormant while
    // the composed node's looked armed — the same "wired but unreachable by any
    // host" shape persist hit shipping it. Self-proving (reads the value back) and
    // fatal on mismatch; see `compose::arm_peer_deadmission_gate`.
    rt.block_on(crate::compose::arm_peer_deadmission_gate(&engine))?;
    // TEST-ANCHOR-ONLY (CIRISEdge#386 leg B): the bare embedded agent reaches
    // delivery ONLY through here — it never runs serve_with_adapter, where
    // `maybe_test_bless_self` mints the leg-B trust-root graph. Without this, the
    // agent's own directory holds no charter / trust edge / lifecycle, so
    // `capability_roots_to_trusted_root` finds no trusted root and the agent
    // withholds every trace attestation (the observed NO-CARRIER). Runs the SAME
    // ceremony the composed node runs; a loud no-op unless CIRIS_TESTING_MODE=true
    // + a seed; compiled out of production entirely (the `test-anchor` feature is
    // absent there). Before `engine`/`edge` are moved into the controller below.
    #[cfg(feature = "test-anchor")]
    rt.block_on(crate::test_bless::maybe_test_bless_delivery_self(&engine))?;
    let controller = rt.block_on(run_federation_delivery(
        engine,
        edge,
        cadence_seconds,
        announce_logger,
    ))?;
    let controller = Arc::new(controller);
    Ok(hold(rt, controller))
}

/// Re-prime canonical delivery on a post-restart re-serve (CIRISServer#288).
///
/// The embedded fold's setup-complete restart is an in-process reload: the edge
/// runtime + persist engine are reused process-singletons, and
/// [`start_and_hold`] is `is_started()`-guarded, so the canonical prime never
/// re-fires — `knows_peer(canonical)` stays false and the sealed trace has no
/// delivery peer (`peer_count_canonical: 0`). This re-drives ONLY the prime
/// ([`prime_canonicals`]: read baked hints → re-root each canonical's transport
/// binding — reachability only, no consent) against the CURRENT handles, on the held
/// runtime — the already-running reconcile loop then delivers on its next tick.
///
/// It does NOT rebuild the [`ReplicationRuntime`]: the reused edge's
/// `replication_registry` is a set-once `OnceLock`, so a fresh runtime could not
/// re-register. Re-rooting on the held runtime is sufficient.
///
/// Idempotent; safe to call on every post-restart re-serve. If delivery was
/// never started, this is equivalent to [`start_and_hold`] (a first start).
#[cfg(feature = "python")]
pub fn reprime_and_hold(cadence_seconds: Option<u64>, announce_logger: bool) -> Result<usize> {
    if !is_started() {
        // Never started (e.g. reprime called on a cold path) → a normal first start.
        return start_and_hold(cadence_seconds, announce_logger);
    }
    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine().context(
        "reprime: no in-process persist Engine (current_rust_engine() is None) — call after the \
         embedded engine is initialized",
    )?;
    let edge: Arc<Edge> = ciris_edge::current_edge().map_err(|e| {
        anyhow::anyhow!("reprime: no in-process embedded Edge (current_edge() failed: {e})")
    })?;
    let node_key_id = edge.signer_key_id().to_string();
    // Drive the async prime on the HELD runtime (already owns the delivery tasks).
    let (rt, _controller) = HELD.get().expect("is_started() checked above");
    let admitted = rt.block_on(prime_canonicals(&engine, &edge, &node_key_id))?;
    tracing::info!(
        canonical_targets = ?admitted,
        "federation delivery REPRIMED — canonical peers re-rooted on the held runtime \
         (post-restart self-heal, CIRISServer#288)"
    );
    Ok(admitted.len())
}

/// **What edge's advertise filter does with one of THIS node's own rows.**
///
/// Four answers, not two, because "not offered to everyone" and "not offered at
/// all" are opposite findings and this surface used to report them as one
/// number. `Withheld` is a placement fault the producer must fix; the two
/// `OfferedPending*` readings are correct placements whose RECIPIENT is chosen
/// one layer downstream, at send/fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertiseVerdict {
    /// On the wire to every consented peer.
    Offered,
    /// On the wire at the list level; WHICH peer receives it is decided by the
    /// #379/#386 serve gate against the recipient's effective `infra:serve`.
    /// This is the `trace:*` reading.
    OfferedPendingRecipientServeGate,
    /// On the wire at the list level; narrowed per recipient by the DATA
    /// SUBJECT's grant (the CC#46 `scores:*` reading).
    OfferedPendingSubjectGrant,
    /// Not advertised at all — the row is stranded where it sits.
    Withheld,
}

impl AdvertiseVerdict {
    /// Does edge put this row on the wire at all?
    #[must_use]
    pub fn is_offered(self) -> bool {
        !matches!(self, AdvertiseVerdict::Withheld)
    }

    /// The token reported on the operator surface.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AdvertiseVerdict::Offered => "offered",
            AdvertiseVerdict::OfferedPendingRecipientServeGate => {
                "offered_pending_recipient_serve_gate"
            }
            AdvertiseVerdict::OfferedPendingSubjectGrant => "offered_pending_subject_grant",
            AdvertiseVerdict::Withheld => "withheld",
        }
    }
}

/// **Edge's advertise decision, reproduced — because edge does not export it.**
///
/// `FederationDirectoryReplicationBridge::attestation_is_advertised` (edge
/// v20.0.0 `src/replication/bridge.rs:4552`) and the `attestation_projection`
/// it dispatches on (`:4727`) are PRIVATE associated fns. A consumer that needs
/// to answer "would edge offer this row?" — which is the first question anyone
/// debugging a stalled plane asks — has no choice but to re-derive it. This is
/// that re-derivation, in ONE place, with edge's arms enumerated exhaustively.
///
/// It is a mirrored rule and it should not exist; the fix is upstream, one
/// exported predicate. Until then it lives here rather than inline in the
/// diagnostic, so that `tests/trace_round_e2e.rs` can hold it against the real
/// thing — edge's own `local_refs`, over a real placed row — instead of against
/// a second copy of itself. That differential is the only mechanism that catches
/// a drift; a comment promising to stay in sync is not one, and this predicate
/// has now drifted twice.
///
/// The drift both times was the same two arms. `Capability` and `Subject`
/// answered `false` here while edge answers `true`, so a `trace:*` row placed at
/// `cohort_scope=federation` — the WIDEST projection a trace ever reaches, since
/// the Trace family resolves `Capability(infra:serve)` at every commons tier and
/// never widens past it — was reported as stranded under a hint telling the
/// operator to go re-scope rows that were already terminally placed.
///
/// `attesting_key_id` / `node_key_id` serve the `SelfOwn` arm: it is
/// publish-YOUR-OWN (the KERI shape), NOT "never advertised". A `self`-scoped
/// row IS advertised, by its own producer.
#[must_use]
pub fn advertise_verdict(
    projection: &ciris_persist::federation::namespace::Projection,
    attesting_key_id: &str,
    node_key_id: &str,
) -> AdvertiseVerdict {
    use ciris_persist::federation::namespace::Projection;
    match projection {
        Projection::Global | Projection::Cohort => AdvertiseVerdict::Offered,
        Projection::Capability(_) => AdvertiseVerdict::OfferedPendingRecipientServeGate,
        Projection::Subject => AdvertiseVerdict::OfferedPendingSubjectGrant,
        Projection::SelfOwn => {
            if attesting_key_id == node_key_id {
                AdvertiseVerdict::Offered
            } else {
                AdvertiseVerdict::Withheld
            }
        }
    }
}

/// Gather the live, per-canonical-peer delivery state — the queryable half of
/// "why isn't the trace sailing?" (CIRISServer#294). Pure async over the current
/// edge/engine; the wheel wrapper [`delivery_status_json`] supplies the handles.
#[cfg(feature = "python")]
async fn gather_delivery_status(
    engine: Option<Arc<Engine>>,
    edge: Arc<Edge>,
    started: bool,
    held_targets: Option<Vec<String>>,
) -> serde_json::Value {
    use serde_json::json;
    let node_key_id = edge.signer_key_id().to_string();
    // The peers delivery cares about: the held controller's seeded canonical
    // targets when running, else the baked canonical hints (so the answer is
    // meaningful even before start / after a restart that didn't re-prime).
    let targets: Vec<String> = match held_targets {
        Some(t) => t,
        None => match &engine {
            Some(eng) => match eng.canonical_bootstrap_hints().await {
                Ok(hints) => distinct_canonical_key_ids(&hints),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        },
    };
    // ── The TRACE PLANE gate (CIRISServer#327 / CIRISPersist#509) ───────────
    // A sealed trace only reaches a canonical if BOTH of these hold, and the
    // whole #315 saga was spent discovering them one live run at a time:
    //
    //   1. a LIVE self-authored `consent:replication:v1` grant COVERS the
    //      `trace:` dimension prefix — `promote_consented_backlog` only sweeps
    //      rows a grant's `attestation_prefixes` cover, and the server's own
    //      default is `["capacity:"]`, so a defaulted grant never promotes a
    //      single trace no matter how many are sealed; and
    //   2. that grant's `audience` is the cohort the payload inherits —
    //      promotion stamps `cohort_scope` FROM the audience (#509's second
    //      half), and the replication offer filter keys on `cohort_scope`, not
    //      tier. A trace promoted to `tier=federation` while still
    //      `cohort_scope=self` is invisible to the round: the empirically
    //      settled differential (consent crossed at (federation, federation);
    //      traces did not at (self, federation)).
    //
    // Both are read-only projections of already-verified state — no emit, no
    // sweep, no side effects — so this is safe to poll from a harness.
    let trace_plane = match &engine {
        Some(eng) => {
            let node = node_key_id.clone();
            match eng
                .federation_directory()
                .list_live_consent_grants_by(&node)
                .await
            {
                Ok(grants) => {
                    let mut prefixes: Vec<String> = Vec::new();
                    let mut audiences: Vec<String> = Vec::new();
                    for g in &grants {
                        for p in
                            ciris_persist::federation::consent_grammar::grant_attestation_prefixes(
                                &g.attestation_envelope,
                            )
                        {
                            if !prefixes.contains(&p) {
                                prefixes.push(p);
                            }
                        }
                        // The audience the payload will inherit at promotion.
                        // Absent ⇒ persist's `default_audience()` (federation).
                        let aud = g
                            .attestation_envelope
                            .get("payload")
                            .and_then(|p| p.get("audience"))
                            .and_then(|a| a.as_str())
                            .unwrap_or("federation")
                            .to_string();
                        if !audiences.contains(&aud) {
                            audiences.push(aud);
                        }
                    }
                    // `covers` is persist's own prefix matcher — the SAME fn the
                    // sweep uses, so this can never disagree with it (the
                    // trailing colon is significant: `trace:` does not cover
                    // `trace_summary:v1`).
                    let covers_trace = ciris_persist::federation::consent_grammar::covers(
                        &prefixes,
                        "trace:complete:v1",
                    );

                    // ── ARMED-BUT-STRANDED (the tier this block originally
                    // lacked, and which let it over-promise) ────────────────
                    // The grant checks above answer "will FUTURE rows be swept
                    // and to what audience?" — they say NOTHING about rows
                    // ALREADY on disk. A row sealed or promoted before the
                    // grant existed (or promoted through the tier-only path)
                    // can sit at `(cohort_scope=self, tier=federation)`:
                    // covered by the grant, past the tier gate, and STILL
                    // never offered, because the replication offer filter keys
                    // on `cohort_scope`. The plane is armed and the payload is
                    // stranded — reported "armed" by the first version of this
                    // diagnostic, which is precisely the over-promise the
                    // agent-harness run caught (CIRISAgent#932).
                    //
                    // Cost note: `list_attestations_by` is unpaged, so this is
                    // O(rows authored by this node). Fine for a node/harness
                    // diagnostic; do not call it on a hot path.
                    // The predicate below is edge's OWN advertise decision, not a
                    // paraphrase of it. The first version of this block guessed
                    // (`cohort_scope == "self"` ⇒ stranded) and reported
                    // `stranded_covered_rows: 0` against three visibly stranded
                    // rows (CIRISAgent#932) — a parallel predicate that drifted
                    // from the one that actually decides, which is the same
                    // one-name-two-processors defect this codebase has been
                    // cataloguing. So: call the SAME persist fns edge's
                    // `attestation_is_advertised` (bridge.rs) calls —
                    // `authority_for` → `is_withdraw_or_revocation` →
                    // `projection_for` — and reproduce its publish-own arm.
                    //
                    // NOTE the arm that broke the guess: `SelfOwn` is NOT
                    // "never advertised". It is publish-YOUR-OWN (KERI shape) —
                    // a `self`-scoped row IS advertised **by its own producer**.
                    // So a `(self, federation)` row authored by THIS node is
                    // offerable, and the strand (if any) lies elsewhere. That is
                    // why this now reports the projection instead of asserting a
                    // verdict it cannot support.
                    //
                    // AND the arm that broke the FIX: reproducing edge's
                    // predicate means reproducing ALL of it, and the second
                    // version still answered `false` for the two arms edge
                    // answers `true`. Both versions failed the same way — a
                    // parallel predicate that agrees with the real one on the
                    // rows you happen to be looking at. The arms are enumerated
                    // exhaustively below against edge's OWN source, and the
                    // per-recipient narrowing the `Capability` / `Subject` arms
                    // carry is reported as ITS OWN verdict rather than collapsed
                    // into "withheld".
                    //
                    // This copy exists only because edge does not export the
                    // predicate: `attestation_is_advertised` and
                    // `attestation_projection` are private associated fns on
                    // `FederationDirectoryReplicationBridge` (edge v20.0.0
                    // `replication/bridge.rs:4552` / `:4727`). The right fix is
                    // upstream — one exported predicate, and this block calls it.
                    use ciris_persist::federation::namespace as ns;
                    let mut covered_rows = 0usize;
                    let mut stranded = 0usize;
                    // Rows the projection filter OFFERS and the per-recipient
                    // serve gate then decides (the `trace:*` cell). Counted apart
                    // from `stranded` because they are the OPPOSITE finding:
                    // correctly placed, and gated one layer downstream.
                    let mut capability_gated = 0usize;
                    let mut by_projection: std::collections::BTreeMap<String, usize> =
                        std::collections::BTreeMap::new();
                    if !grants.is_empty() {
                        if let Ok(mine) =
                            eng.federation_directory().list_attestations_by(&node).await
                        {
                            for a in &mine {
                                let dim = a
                                    .attestation_envelope
                                    .get(ciris_persist::federation::envelope::paths::DIMENSION)
                                    .and_then(|d| d.as_str())
                                    .unwrap_or_default();
                                if dim.is_empty()
                                    || !ciris_persist::federation::consent_grammar::covers(
                                        &prefixes, dim,
                                    )
                                {
                                    continue;
                                }
                                covered_rows += 1;
                                let authority = ns::registry::authority_for(dim).class;
                                let is_tombstone =
                                    ns::is_withdraw_or_revocation(&a.attestation_type);
                                // persist v35 added the PLANE, v36 decomposed the
                                // Attestation plane per dimension family. These
                                // rows are attestations, and `dim` is already in
                                // hand for `authority_for` above — so the plane
                                // costs no new read, which is what persist's
                                // inventory predicted for this site.
                                //
                                // Adopted straight to v36 rather than through v35
                                // first: at v35 the Attestation row was DEFERRED
                                // to pre-#713 behaviour, so a v35-only rewrite
                                // here would have been pure spelling that looked
                                // behavioural — teaching the next reader that the
                                // site had been re-verified when nothing about
                                // its answers had changed.
                                let proj = ns::projection_for(
                                    ns::Plane::Attestation { dimension: dim },
                                    &a.cohort_scope,
                                    authority,
                                    is_tombstone,
                                );
                                // Edge's publish-own arm: SelfOwn advertises iff
                                // the producer is in the node's OWN self-set.
                                // These rows came from `list_attestations_by(node)`,
                                // so the producer IS this node — hence SelfOwn
                                // here is ADVERTISED, not withheld.
                                //
                                // ONE predicate, in [`advertise_verdict`], where a
                                // test can hold it against edge's real `local_refs`
                                // over a real placed row. Inline, it was a second
                                // copy of edge's rule that nothing compared to
                                // anything, and it drifted on the same two arms
                                // twice — `Capability` / `Subject` answered
                                // "withheld" where edge answers "advertised", which
                                // reported a correctly placed `trace:*` row as
                                // stranded and sent the operator to re-scope rows
                                // that were already terminally placed.
                                let verdict = advertise_verdict(&proj, &a.attesting_key_id, &node);
                                match verdict {
                                    AdvertiseVerdict::Withheld => stranded += 1,
                                    AdvertiseVerdict::OfferedPendingRecipientServeGate => {
                                        capability_gated += 1;
                                    }
                                    AdvertiseVerdict::Offered
                                    | AdvertiseVerdict::OfferedPendingSubjectGrant => {}
                                }
                                *by_projection
                                    .entry(format!(
                                        "{:?}/{}/{}",
                                        proj,
                                        a.cohort_scope,
                                        verdict.as_str()
                                    ))
                                    .or_default() += 1;
                            }
                        }
                    }

                    let hint = if grants.is_empty() {
                        "NO live self-authored consent:replication grant — nothing will ever be \
                         promoted or offered. Author one (POST /v1/federation/consent) before \
                         expecting any trace to cross."
                    } else if !covers_trace {
                        "grant(s) present but NONE cover `trace:` — promote_consented_backlog \
                         will never sweep a trace row, so sealed traces stay local-tier forever. \
                         The server's default prefix set is [\"capacity:\"]; re-author the grant \
                         with `trace:` in attestation_prefixes."
                    } else if audiences.iter().any(|a| a == "self") {
                        "a covering grant's audience is `self` — promotion will stamp \
                         cohort_scope=self and the replication offer filter (which keys on \
                         cohort_scope, NOT tier) will never offer the row. Widen the grant's \
                         audience."
                    } else if stranded > 0 {
                        // ARMED BUT STRANDED — the tier that stops this block
                        // over-promising (CIRISAgent#932). The grant is correct
                        // AND rows on disk are still unofferable.
                        "ARMED BUT STRANDED: the grant is correct (covers `trace:`, non-self \
                         audience) but `stranded_covered_rows` rows already on disk sit at \
                         cohort_scope=self and will NEVER be offered — self/family project \
                         SelfOwn (structurally invisible), so tier is irrelevant. Arming the \
                         plane does NOT retroactively re-scope rows sealed or promoted before \
                         the grant existed, or promoted via a tier-only path. Needs BOTH \
                         halves: scope-aware seal-time promotion for NEW rows, and a repair \
                         sweep to re-scope the EXISTING ones (the (a)+(c) pattern already \
                         settled for the tier half in CIRISPersist#509)."
                    } else if covered_rows == 0 {
                        "trace plane armed, but this node holds NO rows covered by the grant \
                         yet — nothing has been sealed (or nothing matches the covered \
                         prefixes). Not a fault: emit first, then re-read."
                    } else if capability_gated > 0 {
                        // PLACED AND CAPABILITY-GATED — the reading that used to
                        // be swallowed by `stranded > 0` above, which reported a
                        // placement fault for rows whose placement is correct.
                        "PLACED AND CAPABILITY-GATED: the grant is correct and \
                         `capability_gated_rows` covered row(s) are placed at their WIDEST \
                         projection. `trace:*` resolves Capability(infra:serve) at every \
                         commons tier and never widens further, so cohort_scope=federation \
                         is the TERMINAL placement here, not a strand — there is nothing \
                         left to widen and no repair sweep to run. Edge advertises them; \
                         whether each RECIPIENT receives one is decided per peer by the \
                         #379/#386 serve gate. If nothing ships, read \
                         `withholds.by_reason` — and read its two legs APART: \
                         `serve_capability_missing` is leg A (no accord-conferred \
                         `infra:serve` on the peer's KEY RECORD, minted locally), while \
                         `serve_capability_not_rooted` is leg B (the `delegates_to` GRAPH \
                         walk, `capability_roots_to_trusted_root`). Leg B needs a live, \
                         FEDERATION-TIER `delegates_to(root -> peer, infra:serve)` in THIS \
                         node's own directory — a row authored by the root ON THE PEER that \
                         must REPLICATE here. Leg A passing while leg B fails means exactly \
                         that: the conferral row has not arrived, which is a CARRIAGE fault \
                         on the peer->us direction (consent is DIRECTED — check the peer's \
                         own consent:replication grant naming us), not a fault in these rows."
                    } else {
                        "trace plane armed and every covered row is OFFERABLE by edge's own \
                         advertise predicate (see rows_by_projection for the per-row \
                         Projection/scope/verdict). NOTE `SelfOwn` is publish-YOUR-OWN, so a \
                         self-scoped row authored by THIS node is offered, not withheld — do not \
                         read `cohort_scope=self` as stranded on its own. If the round still \
                         moves nothing, the gate is DOWNSTREAM of the offer filter (recipient \
                         infra:serve, attester registration, or round servicing — see \
                         round_diagnostics), not here."
                    };
                    json!({
                        "live_self_grants": grants.len(),
                        "covered_prefixes": prefixes,
                        "covers_trace": covers_trace,
                        "promotion_audiences": audiences,
                        // Rows THIS node authored whose dimension the grant covers,
                        // and how many of those are unofferable at cohort_scope=self.
                        // `stranded > 0` with an otherwise-correct grant is the
                        // armed-but-stranded interlock (CIRISAgent#932).
                        "covered_rows": covered_rows,
                        "stranded_covered_rows": stranded,
                        // Covered rows edge DOES advertise, whose recipient is
                        // then chosen by the #379/#386 serve gate rather than by
                        // scope. Reported apart from `stranded` because "placed at
                        // its widest projection" and "unofferable" are opposite
                        // findings this diagnostic used to report as one number.
                        "capability_gated_rows": capability_gated,
                        // Per-row breakdown through edge's OWN advertise
                        // predicate: "<Projection>/<cohort_scope>/<verdict>".
                        // Report the projection rather than a guessed verdict —
                        // if the round still sees nothing while every row reads
                        // `offered`, the gate is NOT the offer filter and the
                        // next probe belongs downstream (CIRISAgent#932).
                        "rows_by_projection": by_projection,
                        "hint": hint,
                    })
                }
                Err(e) => json!({ "error": format!("list_live_consent_grants_by: {e}") }),
            }
        }
        None => json!({ "error": "no engine handle — trace-plane gate not readable" }),
    };

    let mut peers = Vec::with_capacity(targets.len());
    for t in &targets {
        // knows_peer = transport-rooted (prime succeeded); kex_present =
        // resolve_peer_kex_pubkeys is Some (the IdentityOccurrence enc-keys
        // replicated) — the two gates a sealed envelope must clear to be
        // deliverable. Both false with no FramesDropped WARN ⇒ never primed;
        // both true but no delivery ⇒ look at the driver (leviculum#25 loss).
        let knows_peer = match edge.reticulum_transport() {
            Some(tr) => tr.knows_peer(t).await,
            None => false,
        };
        let kex_present = edge
            .resolve_peer_kex_pubkeys(t)
            .await
            .ok()
            .flatten()
            .is_some();
        peers.push(json!({
            "key_id": t,
            "knows_peer": knows_peer,
            "kex_present": kex_present,
            "deliverable": knows_peer && kex_present,
        }));
    }

    // ── Round diagnostics (troubleshootability) ─────────────────────────────
    // When a peer is `knows_peer:true` but `kex_present:false`, the reverse
    // IdentityOccurrence round is not completing — and WHY it's not completing
    // is the question that cost a multi-week investigation (2026-07 KEX-none:
    // the round `transport timeout after 30s` under canonical concurrent-peer
    // contention; see FSD/RNS_LIFECYCLE_STATES.md). Surface the edge send-failure
    // classes + envelope throughput here so the NEXT occurrence is a one-query
    // differential instead of an archaeology dig — whatever the cause turns out
    // to be.
    let snap = edge.metrics().snapshot();
    let any_knows_peer = peers.iter().any(|p| p["knows_peer"] == json!(true));
    let any_kex_missing = peers
        .iter()
        .any(|p| p["knows_peer"] == json!(true) && p["kex_present"] == json!(false));

    json!({
        "delivery_started": started,
        // Held-pending-claim is NOT "not started": the node is healthy and waiting
        // on a human, which an operator must be able to tell from a crash or a
        // missing transport.
        "waiting_for_claim": crate::federation_delivery::is_waiting_for_claim(),
        "edge_up": true,
        "node_key_id": node_key_id,
        "transport_present": edge.reticulum_transport().is_some(),
        "canonical_targets": targets,
        "peers": peers,
        // The two preconditions a sealed trace must clear BEFORE the round is
        // even asked (CIRISPersist#509): a live grant covering `trace:`, and a
        // non-self audience for promotion to stamp. Read this FIRST when a
        // trace does not cross — a defaulted grant is silent, not loud.
        "trace_plane": trace_plane,
        // Round-servicing diagnostics — read these when a peer is knows_peer:true
        // but kex_present:false. `hint` names the layer + the doc to open.
        "round_diagnostics": round_diagnostics_json(&snap, started, any_knows_peer, any_kex_missing),
        // FramesDropped (in-flight loss on an interface disconnect) is emitted as
        // an edge WARN + NodeEvent (leviculum v0.9.3+ciris.1 / edge v13.3.1) — grep
        // the node log for `frames=` on the peer's iface if a deliverable peer
        // still isn't receiving.
        "note": "frames-dropped surfaces as an edge WARN/NodeEvent; see leviculum#25",
    })
}

/// **CIRISServer#377 — the round diagnostics, split BY PLANE.**
///
/// # The defect this closes
///
/// `envelopes_sent_total` / `envelopes_received_total` sat at the top of
/// `round_diagnostics` reading as totals for the carriage this node performs.
/// They are not. Edge's `inc_sent` / `inc_received` are called **only** from
/// `src/edge.rs` — the application/durable send path — and the anti-entropy
/// replication plane, which is what actually carries `trace:*` rows to a
/// canonical, touches neither. So a run that landed 15 `trace_events` on the
/// canonical, summarized and scored, reported `envelopes_sent_total: 0`.
/// Reporting broken while working. That is CIRISEdge#434, root-caused and
/// CLOSED upstream: `replication_envelopes_served_total` (CIRISEdge#433, live
/// since edge v15.x and present in v15.20.0) is the plane-correct counter, and
/// #434's own closing guidance was explicit — *"do not key trace-pipeline
/// health on `envelopes_sent_total`; it measures the application/durable plane
/// only."* [`crate::operator_surface`] adopted that. This surface did not, and
/// `harness/mesh-repro/scenarios/traceflow.sh` greps THIS one. Its stage 5
/// `ship` rung therefore could never pass — a check that could not fail, inside
/// the instrument built to catch exactly that.
///
/// # Why the split, and not merely a corrected field
///
/// The same misreading produced the issue's second complaint: `round_outcomes`
/// counted 4 `error`s while `send_failures_by_class` stayed `{}`, which looks
/// like "failures tallied but never classified". It is not. `send_failures_total`
/// is the **application** plane and `replication_round_outcomes_total` is the
/// **replication** plane — two different planes under one heading, which is why
/// they can read `4` and `{}` at once without either being wrong. Renaming one
/// field would have left that trap in place. Nesting each counter under the
/// plane that writes it makes the category error unstateable.
///
/// The replication plane's own refusal axis — the classification the issue
/// actually wanted — exists and is now surfaced: `apply_refusals_by_kind` and
/// `key_apply_refusals_by_reason`.
///
/// # Every zero names its cause
///
/// Per this repo's [`crate::operator_surface`] discipline, no count is emitted
/// bare. `carriage.standing` and `receive.standing` come from
/// [`crate::operator_surface::carriage_standing`] /
/// [`crate::operator_surface::receive_standing`] — the SAME functions
/// `GET /v1/node/state` answers with, not a second derivation of the same
/// question — so `unreadable` / `not_exercised` / `idle` / `moving` /
/// `withholding` are distinguished here too, and `rounds_total` rides along as
/// the denominator that makes a zero interpretable.
///
/// # The receive half, and the gap that closed (CIRISEdge#457)
///
/// This function used to carry a caveat here and an `accepted_total_unavailable`
/// string on the wire: edge booked `ApplyOutcome::Refused` and booked neither
/// `Admitted` nor `Duplicate`, so `receive.standing: "clean"` could not separate
/// "everything offered was applied" from "nothing was offered". Edge v15.20.1
/// closed it — `replication_applied_total` and `replication_duplicate_total`,
/// booked at the same #425 apply choke as the refusals — so the caveat is DELETED
/// rather than softened. A stale caveat is worse than none: it tells a reader not
/// to trust a number that is now trustworthy.
///
/// `receive.standing` accordingly splits `clean` into `idle` (rounds ran, nothing
/// was offered to us), `converged` (rows arrived and we already held every one)
/// and `applying` (rows arrived and changed state here), and `applied_total` /
/// `duplicate_total` / `decided_total` ride beside the refusal count. The one
/// thing `decided_total` still does NOT include is `ApplyOutcome::Deserialize`,
/// which edge books nowhere on purpose — undecodable bytes are wire corruption,
/// not a policy decision. That exclusion is stated on the operator surface's
/// `note` rather than left for a reader to discover from a total that does not
/// add up.
///
/// Pure over the metrics bundle + the two peer predicates, so the hint ladder
/// and every plane assignment are unit-testable without an Edge
/// (`tests/delivery_round_diagnostics.rs`).
#[must_use]
pub fn round_diagnostics_json(
    snap: &ciris_edge::observability::EdgeMetricsBundle,
    started: bool,
    any_knows_peer: bool,
    any_kex_missing: bool,
) -> serde_json::Value {
    use crate::operator_surface::{carriage_standing, receive_standing};
    use serde_json::json;

    // ── application plane (edge.rs `send_*` / `dispatch_inbound`) ────────────
    let mut failures_by_class: std::collections::BTreeMap<String, u64> = Default::default();
    for ((_transport, class), n) in &snap.send_failures_total {
        *failures_by_class.entry(class.clone()).or_insert(0) += n;
    }
    let app_sent_total: u64 = snap.envelopes_sent_total.values().sum();
    let app_recv_total: u64 = snap.envelopes_received_total.values().sum();

    // ── replication plane (bridge serve exit / apply choke point) ────────────
    // CIRISEdge#370 Ask 2 (edge v13.5.0): anti-entropy round outcomes are
    // counted in EdgeMetrics — so the round-not-completing case is queryable
    // (round_timed_out climbing) instead of a log grep.
    let mut round_outcomes: std::collections::BTreeMap<String, u64> = Default::default();
    for (outcome, n) in &snap.replication_round_outcomes_total {
        round_outcomes.insert(outcome.as_str().to_string(), *n);
    }
    let rounds_total: u64 = snap.replication_round_outcomes_total.values().sum();
    let round_timed_out = round_outcomes.get("timed_out").copied().unwrap_or(0);
    let round_completed = round_outcomes.get("completed").copied().unwrap_or(0);
    // CIRISEdge#373 (edge v13.6.0): inbound frames dropped because a stalled
    // responder reply parked the coordinator drain. The tripwire — should sit at
    // 0. Non-zero = the trace is being actively LOST (a reply is still stalling
    // long enough to fill the channel), even for a deliverable peer.
    let backpressure_drops = snap.replication_inbound_backpressure_drops;

    // CIRISEdge#433 — THE send counter for this plane. Keyed by the same
    // `EnvelopeKind` the replication wire uses, rendered through edge's own
    // `as_wire_str` so the token here is the token on the wire (one vocabulary,
    // never a hand-mirrored copy — SRV-1/#322).
    let served_total: u64 = snap.replication_envelopes_served_total.values().sum();
    let mut served_by_kind: std::collections::BTreeMap<String, u64> = Default::default();
    for (kind, n) in &snap.replication_envelopes_served_total {
        served_by_kind.insert(kind.as_wire_str().to_string(), *n);
    }
    // CIRISEdge#433 — the withhold ledger: "served nothing" vs "REFUSED to serve"
    // reported identically before this existed, and the difference is the whole
    // diagnosis when a trace does not cross.
    let withholds_total: u64 = snap.withholds_by_reason.values().sum();
    let mut withholds_by_reason: std::collections::BTreeMap<String, u64> = Default::default();
    for (reason, n) in &snap.withholds_by_reason {
        withholds_by_reason.insert(reason.as_str().to_string(), *n);
    }
    // persist v24.2.0 / CIRISPersist#565 — the receive-plane refusal axes. THIS
    // is the classification the #377 report asked for: the WARN it quoted
    // (`delivered envelope REFUSED — not applied`, CIRISEdge#425 choke point)
    // books here, on the replication plane, next to the rounds that carried it.
    let apply_refusals_total: u64 = snap.apply_refusals_by_kind.values().sum();
    let mut apply_refusals_by_kind: std::collections::BTreeMap<String, u64> = Default::default();
    for (kind, n) in &snap.apply_refusals_by_kind {
        apply_refusals_by_kind.insert(kind.as_wire_str().to_string(), *n);
    }
    let key_refusals: std::collections::BTreeMap<String, u64> = snap
        .key_apply_refusals_by_reason
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    // CIRISEdge#457 — the accepted-apply axes. THE thing this surface could not
    // say until edge v15.20.1: whether anything a peer offered actually landed.
    // Two maps, never one: an admit changed local state and a duplicate did not.
    let applied_total: u64 = snap.replication_applied_total.values().sum();
    let mut applied_by_kind: std::collections::BTreeMap<String, u64> = Default::default();
    for (kind, n) in &snap.replication_applied_total {
        applied_by_kind.insert(kind.as_wire_str().to_string(), *n);
    }
    let duplicate_total: u64 = snap.replication_duplicate_total.values().sum();
    let mut duplicate_by_kind: std::collections::BTreeMap<String, u64> = Default::default();
    for (kind, n) in &snap.replication_duplicate_total {
        duplicate_by_kind.insert(kind.as_wire_str().to_string(), *n);
    }

    let carriage = carriage_standing(Some(snap));
    let receive = receive_standing(Some(snap));
    // The receive denominator, from `operator_surface` — NOT re-summed here.
    // #377 was two readers of one bundle, one right and one wrong; a second
    // definition of "offered" would be that defect with a new name.
    let decided_total = crate::operator_surface::receive_decided_total(snap);

    // The differential — read straight off the counters. Each branch names the
    // layer + the doc to open, so an operator doesn't re-derive the ladder.
    let hint = if !started {
        "delivery not started — call start_federation_delivery / reprime_federation_delivery"
    } else if !any_knows_peer {
        "no peer rooted (knows_peer all false) — prime never seeded a canonical; check canonical_bootstrap_hints + prime_canonicals"
    } else if backpressure_drops > 0 {
        // The #373 backstop is firing: a responder reply stalled long enough to
        // fill the coordinator drain, so inbound TRACE frames are being dropped.
        // Highest-signal failure when present — the trace is actively being lost
        // even if the peer is deliverable.
        "inbound frames DROPPED (round_diagnostics.replication_plane.inbound_backpressure_drops > 0, CIRISEdge#373) — a responder reply is stalling long enough to park the coordinator drain and the trace is being LOST. The reverse-path reply is not reaching the peer's current live link (#353); escalate (reply-over-arrival-link is the held follow-up). Watch replication_plane.round_outcomes.timed_out and the node log for `responder reply send TIMED OUT`"
    } else if withholds_total > 0 {
        // CIRISEdge#433 — the loudest thing a node can say about its own
        // carriage, and it outranks every transport branch below: nothing left
        // because THIS node declined to serve it. No transport fix applies.
        "this node WITHHELD rows it holds (replication_plane.withholds.total > 0, CIRISEdge#433) — carriage is being refused at a serving-path gate, not lost in transport. `withholds.by_reason` names the branch that decided; the serve gate's legs A+B (#379/#386: the role on the key record AND the delegates_to trust-root walk) are the usual pair"
    } else if !any_kex_missing {
        "peers deliverable (or no kex gap) — if a deliverable peer still isn't receiving, grep the node log for `frames=` (leviculum#25 in-flight loss)"
    } else if round_timed_out > 0 && round_timed_out >= round_completed {
        // The direct signal now that edge v13.5.0 counts round outcomes: rounds
        // are timing out more than completing → the reverse IdentityOccurrence
        // round isn't being serviced. This is the FSD KEX-none RCA (canonical
        // round contention under concurrent-peer load, transport-layer ceiling —
        // CIRISEdge#370 / leviculum concurrency).
        "kex missing + round_timed_out >= round_completed — the reverse IdentityOccurrence round is TIMING OUT, not completing. This is canonical round contention under concurrent-peer load (FSD/RNS_LIFECYCLE_STATES.md KEX-none RCA; transport-layer ceiling per CIRISEdge#370). Check the canonical's live peer count — advisory/low-legitimacy peers starving real ones"
    } else if failures_by_class.get("timeout").copied().unwrap_or(0) > 0 {
        "kex missing + transport send timeouts — reverse round transport timing out; likely canonical round contention (FSD KEX-none RCA). Corroborate with replication_plane.round_outcomes.timed_out. NOTE the plane: send_failures_by_class is the APPLICATION plane (announce/durable sends), so it corroborates transport health, it does not measure replication carriage"
    } else if failures_by_class.get("unreachable").copied().unwrap_or(0) > 0 {
        "kex missing + unreachable — transport/routing gap: the responder has no Reticulum destination for us (not rooted at the peer, or path lost), NOT a round-servicing problem"
    } else if served_total > 0 && decided_total == 0 {
        // CIRISServer#377 — the plane-correct form of the old `sent_total > 0 &&
        // recv_total == 0` branch, which asked the APPLICATION plane a question
        // only the replication plane could answer and so never fired on a real
        // carriage stall. The receive half used to be unassertable — edge counted
        // apply refusals and not accepted applies — so "none received" was not a
        // statement this node could make. CIRISEdge#457 made it one, and this is
        // the branch that needed it: rows out, NOTHING in, is one-way carriage.
        "kex missing: this node's replication plane HAS served rows (replication_plane.carriage.envelopes_served_total > 0) and NOTHING has been offered back to its apply path (replication_plane.receive.decided_total == 0, CIRISEdge#457) — carriage is one-way. The reverse IdentityOccurrence round is not landing back at all (reverse-path to a NAT'd peer; see #353 / leviculum#27)"
    } else if served_total > 0 {
        // Rows moved BOTH ways, so the reverse path is not dead — which makes
        // this a different diagnosis from the branch above and, before #457, an
        // indistinguishable one.
        "kex missing, but rows have moved in BOTH directions (carriage.envelopes_served_total > 0 and receive.decided_total > 0) — the transport is not one-way, so this is the IdentityOccurrence round specifically failing to complete rather than a reverse-path gap. Read replication_plane.receive.standing: `applying`/`converged` means peers are reaching us; check round_outcomes.timed_out for contention"
    } else {
        "kex missing, peer rooted, no round timeouts, withholds or send failures yet — round may be mid-first-cycle; if it persists, watch replication_plane.round_outcomes for timed_out (contention) vs refused (malformed/out-of-state peer)"
    };

    json!({
        // ── the plane that carries `trace:*` to a canonical ──────────────────
        // Read THIS to answer "did this node ship anything?". CIRISEdge#433/#434.
        "replication_plane": {
            "carriage": {
                // Standing FIRST: the count below is uninterpretable without it.
                // `idle` (rounds ran, nothing was owed) and `not_exercised` (no
                // round has ever finished) both show 0 and are different facts.
                "standing": carriage.as_str(),
                "envelopes_served_total": served_total,
                "by_kind": served_by_kind,
                // The denominator. A zero served count against zero rounds is
                // not a carriage statement at all.
                "rounds_total": rounds_total,
            },
            "withholds": {
                "total": withholds_total,
                "by_reason": withholds_by_reason,
            },
            "receive": {
                // Standing FIRST, same as carriage: `idle` (rounds ran, nothing
                // was offered), `converged` (offered, all already held) and
                // `applying` (offered, admitted here) all report zero refusals
                // and are three different facts — one token until CIRISEdge#457.
                "standing": receive.as_str(),
                "apply_refusals_total": apply_refusals_total,
                "by_kind": apply_refusals_by_kind,
                "key_refusals_by_reason": key_refusals,
                // CIRISEdge#457 — the accepted-apply axes, kept apart because an
                // admit changed local state and a duplicate did not.
                "applied_total": applied_total,
                "applied_by_kind": applied_by_kind,
                "duplicate_total": duplicate_total,
                "duplicate_by_kind": duplicate_by_kind,
                // The denominator the three counts above divide up: every offered
                // row that reached an apply decision. Undecodable bytes reach no
                // decision and edge books them nowhere, so they are absent from
                // this rather than folded into it.
                "decided_total": decided_total,
                // The outer denominator — whether this node was ever asked.
                "rounds_total": rounds_total,
            },
            // CIRISEdge#370 Ask 2 (v13.5.0): anti-entropy round outcome counts —
            // timed_out climbing vs completed is the direct KEX-none signal.
            "round_outcomes": round_outcomes,
            // CIRISEdge#373 (v13.6.0): the trace-loss tripwire — should be 0.
            "inbound_backpressure_drops": backpressure_drops,
        },
        // ── the application/durable plane (edge.rs `send_*`) ─────────────────
        // These counters do NOT observe replication carriage. Keying trace-plane
        // health on them is the #377 defect; the `note` travels with them so a
        // reader who arrives at this object alone cannot repeat it.
        "application_plane": {
            "envelopes_sent_total": app_sent_total,
            "envelopes_received_total": app_recv_total,
            "send_failures_by_class": failures_by_class,
            "note": "APPLICATION plane only (edge.rs send_*/dispatch_inbound). Anti-entropy replication — the plane that carries trace:* — increments none of these, so 0 here says nothing about carriage. Read replication_plane.carriage instead (CIRISEdge#434).",
        },
        "hint": hint,
    })
}

/// `ciris_server.delivery_status()` backing fn (CIRISServer#294) — a one-shot
/// snapshot of federation-delivery state so "why isn't the trace sailing for
/// peer X?" is a single query, not log archaeology. Same in-process accessor
/// pattern as `first_run_claim_pin()` / `compose_status()`. Never over the wire.
/// TEST-ANCHOR-FENCED consent author (mesh-repro traceflow E2E): author this
/// node's `consent:replication` grant for `peer_key_id` WITHOUT the HTTP owner
/// gate. The harness agent is a bare embedded boot — no serve stack, no owner
/// session — so it cannot reach the owner-gated `POST /v1/federation/consent`.
/// REFUSED unless `CIRIS_TESTING_MODE=true`: production consent is exclusively
/// the explicit owner act over HTTP. Returns the grant attestation_id.
#[cfg(feature = "python")]
/// **CIRISConstitution#46 — resolve the `analyze` stance** (CIRISServer#331 ask 2).
/// READ-ONLY: never authors, in any mode. Unlike [`author_consent_testing`] this
/// carries no testing-mode fence, because reading your own consent state is not a
/// privileged act and the agent's drift detector needs it in production.
///
/// Returns `granted` / `revoked` / `expired` / `unspecified` — persist's ONE
/// canonical scoped fold, so a caller can assert the RESOLVED STANCE instead of
/// row existence (a row that folds to `unspecified` reads as consented while the
/// gate still refuses).
///
/// `subject_key_id` defaults to THIS node — the common case is "may `attester`
/// score me?".
/// Gated on `python` like its neighbours: it reaches the persist pyo3 engine
/// static and the [`HELD`] runtime, neither of which exists in the binary build.
#[cfg(feature = "python")]
pub fn analyze_consent_stance(
    attester_key_id: &str,
    subject_key_id: Option<&str>,
) -> Result<String> {
    use ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE;
    use ciris_persist::federation::hard_case::ConsentState;

    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine()
        .context("analyze_consent_stance: no in-process persist Engine")?;
    let (rt, _controller) = HELD
        .get()
        .context("analyze_consent_stance: federation delivery not started")?;
    let subject = match subject_key_id {
        Some(s) => s.to_string(),
        // The node's DERIVED federation key id — the attester `emit_attestation_self`
        // stamps. Resolving against an alias asks a different question and answers
        // `unspecified` for a perfectly consented pair (the 0.5.138 identity-fork
        // class, in miniature).
        None => rt.block_on(engine.local_derived_key_id())?,
    };
    let stance = rt.block_on(engine.federation_directory().resolve_scoped_consent(
        attester_key_id,
        &subject,
        ANALYZE_CONSENT_SCOPE,
        None,
        chrono::Utc::now(),
    ))?;
    Ok(match stance {
        ConsentState::Granted => "granted",
        ConsentState::Revoked => "revoked",
        ConsentState::Expired => "expired",
        ConsentState::Unspecified => "unspecified",
    }
    .to_string())
}

/// Author this node's directed `consent:replication` grant from the EMBEDDED
/// host — the fold's only path to consent.
///
/// # Why this is not test-only any more
///
/// "The substrate trusts, the server (user) consents." 0.5.146 stopped the
/// substrate boot-authoring a replication grant, which is right — a node must not
/// consent on its owner's behalf. But the owner-gated route that replaces it,
/// `POST /v1/federation/consent` (`federation_admin.rs`), is mounted at
/// `compose.rs` inside `serve_with_adapter`, and the embedded agent boots through
/// `start_and_hold`, which mounts NO HTTP router. So in the fold there was no
/// path by which consent could exist AT ALL: every trace stayed at
/// `(cohort_scope=self, tier=local)` because nothing had ever consented.
///
/// Measured, not inferred: on 0.5.146 a fold node shows `consent:replication`
/// rows = 0, while `consent:community_trust:v1` promoted cleanly to
/// federation/federation — so the promoter works and the traces are stranded for
/// exactly one reason, nobody consented.
///
/// # The gate
///
/// The HTTP route's owner gate exists because HTTP is a REMOTE surface. This is
/// not remote: the caller is the node's own host process, already holding the
/// Engine and the signing key. Gating it on a session it cannot have would be
/// theatre.
///
/// What it CAN check, and does, is that the node has been **claimed** — a ROOT
/// owner exists. On an unclaimed node there is no owner to consent for, so this
/// refuses. That is the same authority the HTTP route resolves to, established at
/// claim time rather than per-request. The harness fence remains as an
/// alternative for `CIRIS_TESTING_MODE`, which runs on unclaimed nodes.
#[cfg(feature = "python")]
pub fn author_consent_embedded(
    peer_key_id: &str,
    prefixes: &[String],
    analyze: bool,
) -> Result<String> {
    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine()
        .context("author_federation_consent: no in-process persist Engine")?;

    // Claimed-node gate. `CIRIS_TESTING_MODE` is the harness's alternative — it
    // runs on unclaimed nodes with no owner to claim them.
    let testing = std::env::var("CIRIS_TESTING_MODE").as_deref() == Ok("true");
    if !testing {
        let (rt_probe, _c) = HELD
            .get()
            .context("author_federation_consent: federation delivery not started")?;
        let claimed = rt_probe.block_on(crate::auth::store::list_by_role(
            &engine,
            ciris_persist::wa_cert::WaRole::Root,
            1,
        ));
        let has_owner = matches!(claimed, Ok(ref v) if !v.is_empty());
        if !has_owner {
            anyhow::bail!(
                "author_federation_consent refused: this node has no ROOT owner — it has not \
                 been claimed, so there is no owner on whose behalf to consent. Claim the node \
                 first (POST /v1/setup/root), or set CIRIS_TESTING_MODE for the harness."
            );
        }
    }

    let edge: Arc<Edge> = ciris_edge::current_edge()
        .map_err(|e| anyhow::anyhow!("author_federation_consent: no embedded Edge: {e}"))?;
    let node_key_id = edge.signer_key_id().to_string();
    let (rt, _controller) = HELD
        .get()
        .context("author_federation_consent: federation delivery not started")?;
    let grant = rt.block_on(crate::peer::emit_replication_consent(
        &engine,
        &node_key_id,
        peer_key_id,
        prefixes,
    ))?;

    // ── CIRISConstitution#46 — the `analyze` grant, the SECOND half ──────────
    //
    // Without this the peer may HOLD our traces and may never SCORE them:
    // `check_capacity_consent_admission` refuses a federation-tier `capacity:*`
    // row about S from P unless a live `analyze` consent S -> P sits in the
    // SCORING node's own corpus. The grant this function just authored does not
    // supply it — different dimension, different edge direction.
    //
    // This mirrors `POST /v1/federation/consent`, which has taken an `analyze`
    // flag since #331 ask 1. Until now the fold could not author the row under
    // ANY argument, because the parameter did not exist here — so the two
    // consent paths were asymmetric, and the one every embedded agent must use
    // was the incomplete one. Measured on the production canonical: 240
    // `consent:replication:v1` rows replicated in from 240 distinct peers, and
    // ZERO `consent:state:*` rows of any kind. Every one of those peers
    // consented to send; not one could consent to be scored.
    //
    // NON-FATAL, as on the HTTP route: the replication grant is already durable,
    // and failing here would discard a consent the owner actually gave.
    let analyze_id = if analyze {
        match rt.block_on(crate::peer::emit_analyze_consent(
            &engine,
            &node_key_id,
            peer_key_id,
        )) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    peer_key_id,
                    error = %e,
                    "replication consent authored but the CC#46 `analyze` grant FAILED — this                      peer can receive our traces and may NOT score them; capacity scoring stays                      dead for this node until it is re-authored"
                );
                None
            }
        }
    } else {
        // A LEGITIMATE configuration, not an error: you MAY send traces without
        // consenting to be analyzed. Degraded, not refused — and it is the shape
        // 240 production peers are in by SILENCE rather than by choice, so name
        // all three costs at the moment of the decision.
        tracing::warn!(
            peer_key_id,
            "consent:replication authored WITHOUT the CC#46 `analyze` grant. This is ALLOWED — \
             traces will flow. What it costs: (1) you build NO reputation, because every \
             capacity:* claim about you is refused, so none can ever exist; (2) you cannot use \
             streams or services that require third-party capability attestations, since you \
             will have none; (3) some peers may refuse to interact with you at all. Pass \
             analyze=True if being scored is why the traces are being sent."
        );
        None
    };

    tracing::info!(
        peer_key_id,
        attestation_id = %grant.attestation_id,
        freshly_emitted = grant.freshly_emitted,
        prefixes = ?prefixes,
        owner_claimed = !testing,
        analyze_grant = ?analyze_id,
        "consent:replication authored from the embedded host (the fold's consent path)"
    );
    Ok(grant.attestation_id)
}

#[cfg(feature = "python")]
pub fn author_consent_testing(peer_key_id: &str, prefixes: &[String]) -> Result<String> {
    if std::env::var("CIRIS_TESTING_MODE").as_deref() != Ok("true") {
        anyhow::bail!(
            "author_consent_testing refused: CIRIS_TESTING_MODE is not 'true' — production \
             consent is the owner-gated POST /v1/federation/consent only"
        );
    }
    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine()
        .context("author_consent_testing: no in-process persist Engine")?;
    let edge: Arc<Edge> = ciris_edge::current_edge()
        .map_err(|e| anyhow::anyhow!("author_consent_testing: no embedded Edge: {e}"))?;
    let node_key_id = edge.signer_key_id().to_string();
    let (rt, _controller) = HELD
        .get()
        .context("author_consent_testing: federation delivery not started")?;
    let grant = rt.block_on(crate::peer::emit_replication_consent(
        &engine,
        &node_key_id,
        peer_key_id,
        prefixes,
    ))?;
    tracing::info!(
        peer_key_id,
        attestation_id = %grant.attestation_id,
        freshly_emitted = grant.freshly_emitted,
        "consent:replication authored via TESTING-MODE harness entry (fenced; prod = HTTP owner gate)"
    );
    Ok(grant.attestation_id)
}

#[cfg(feature = "python")]
pub fn delivery_status_json() -> String {
    let started = is_started();
    let edge = match ciris_edge::current_edge() {
        Ok(e) => e,
        Err(e) => {
            return serde_json::json!({
                "delivery_started": started,
                "waiting_for_claim": is_waiting_for_claim(),
                "edge_up": false,
                "error": e.to_string(),
            })
            .to_string()
        }
    };
    let engine = ciris_persist::ffi::pyo3::current_rust_engine();
    let held_targets = HELD.get().map(|(_, c)| c.canonical_targets.clone());
    let fut = gather_delivery_status(engine, edge, started, held_targets);
    // Run on the held delivery runtime when we have one; else a throwaway
    // current-thread runtime just for the point-in-time queries.
    let value = match HELD.get() {
        Some((rt, _)) => rt.block_on(fut),
        None => match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(fut),
            Err(e) => serde_json::json!({
                "delivery_started": started,
                "waiting_for_claim": is_waiting_for_claim(),
                "error": format!("delivery_status runtime: {e}"),
            }),
        },
    };
    value.to_string()
}

/// The default reconcile cadence, matching the compose default
/// ([`crate::config_reconcile::DEFAULT_REPLICATION_RECONCILE_SECS`]).
pub const DEFAULT_DELIVERY_CADENCE_SECS: u64 =
    crate::config_reconcile::DEFAULT_REPLICATION_RECONCILE_SECS;

/// Bring up the delivery controller against the given in-process embedded engine +
/// edge. Must be `await`ed on the runtime that will own the spawned tasks (see
/// [`start_and_hold`]). Returns the assembled [`DeliveryController`] — the caller
/// is responsible for holding it. Takes the handles as params (rather than reading
/// the persist pyo3 static) so the whole controller compiles + is checked in the
/// default (non-`python`) build; the wheel wrapper [`start_and_hold`] supplies the
/// process singletons.
/// Prime the admitted canonical peers for REACHABILITY: read the baked canonical
/// record(s) and ROOT each admitted canonical's transport binding so
/// `knows_peer(canonical)` is true. Authors NO consent — `consent:replication`
/// is an explicit owner act (`POST /v1/federation/consent`); rooting only makes
/// the canonical dialable, it moves nothing until an owner consent grant exists.
/// Returns the admitted canonical `key_id`s. Shared by first-boot start
/// ([`run_federation_delivery`]) AND the post-restart reprime
/// ([`reprime_and_hold`], CIRISServer#288): a restart re-drives THIS against the
/// current handles to re-establish canonical as a delivery peer — without
/// rebuilding the `ReplicationRuntime` (the edge's set-once `replication_registry`
/// OnceLock forbids re-registration on a reused edge), so the already-running
/// reconcile loop picks the re-rooted target up on its next tick.
async fn prime_canonicals(
    engine: &Arc<Engine>,
    edge: &Arc<Edge>,
    node_key_id: &str,
) -> Result<Vec<String>> {
    // 2. Read the baked canonical record(s): key_ids (replication targets) + ip
    //    hints (dial addresses — logged; see the dial-set caveat in the module
    //    doc). Subsumes #204's read of the transport_hints.
    let hints = engine
        .canonical_bootstrap_hints()
        .await
        .map_err(|e| anyhow::anyhow!("read canonical bootstrap hints: {e}"))?;
    let canonical_key_ids = distinct_canonical_key_ids(&hints);
    let dial_addrs = crate::compose::ip_addrs_from_hints(&hints);
    tracing::info!(
        node_key_id = %node_key_id,
        canonical_targets = ?canonical_key_ids,
        dial_addrs = ?dial_addrs,
        "federation delivery: seeding from the baked canonical record(s) (transport dial set is \
         fixed at init — see #204; delivery reaches Node A once the address is in the edge's init \
         bootstrap_peers or reachable via an announce)"
    );

    // 3. Determine which baked canonicals are ADMITTED (have a federation_keys
    //    row) so step 3b can ROOT a transport path to them. This authors NO
    //    consent. `consent:replication` is ALWAYS an explicit owner act — authored
    //    via `POST /v1/federation/consent` by the agent's setup wizard when the
    //    owner opts into sharing (e.g. "Send traces to CIRIS L3C"). A pure server
    //    generates no traces and so never auto-consents to replicate them; rooting
    //    here is pure REACHABILITY ("this node CAN dial the canonical") and moves
    //    nothing until an owner-authored consent grant exists — the reconcile loop
    //    reads that grant via `list_consent_peers` and converges the runtime to it.
    let directory = engine.federation_directory();
    let mut admitted_targets: Vec<String> = Vec::with_capacity(canonical_key_ids.len());
    for canonical in &canonical_key_ids {
        match directory.lookup_public_key(canonical).await {
            Ok(Some(_)) => admitted_targets.push(canonical.clone()),
            Ok(None) => tracing::warn!(
                canonical = %canonical,
                "federation delivery: baked canonical key is NOT an admitted federation_keys row — \
                 skipping (nothing to root)"
            ),
            Err(e) => tracing::warn!(
                canonical = %canonical,
                error = %e,
                "federation delivery: directory lookup for canonical failed — skipping"
            ),
        }
    }

    // 3b. PRIME the admitted explicit-hash canonical peers (CIRISServer#205 gap #1).
    //    `ciris-canonical-1` is a v7.0.0 EXPLICIT-HASH destination that CANNOT
    //    announce (Leviculum `ExplicitHashCannotAnnounce`), so `knows_peer(canonical)`
    //    stays false and sends can't address it — zero delivery — until the peer is
    //    ROOTED out-of-band via edge's prime mechanism. persist v13.5.0 (#397) now
    //    carries the transport-tier `(dest-hash, transport-Ed25519)` binding in the
    //    directory, so we resolve + prime each admitted canonical here (mirrors edge
    //    v9.3.0's `PyEdge::prime_peer` — the same `inject_rooted_peer_for_test` core).
    //    Best-effort: a missing/undecodable binding WARNs and skips (the expected
    //    state until Node A publishes its transport binding via the canonical
    //    address-update) — never fatal. `reticulum_transport()` is `None` on a
    //    transport-less build → warn + skip the whole prime step (targets stay
    //    admitted). Matches the crate's reticulum surface (compose/holonomic call
    //    `reticulum_transport()` unconditionally — the edge dep always pins
    //    `transport-reticulum`, so no server-side cfg gate is needed).
    match edge.reticulum_transport() {
        Some(transport) => {
            for canonical in &admitted_targets {
                match directory.list_transport_destinations_for(canonical).await {
                    Ok(dests) => match resolve_reticulum_prime_binding(&dests) {
                        Ok(Some((dest_hash, ed25519))) => {
                            let before = transport.knows_peer(canonical).await;
                            transport
                                .inject_rooted_peer_for_test(canonical, dest_hash, ed25519)
                                .await;
                            let after = transport.knows_peer(canonical).await;
                            tracing::info!(
                                canonical = %canonical,
                                dest_hash = %hex::encode(dest_hash),
                                knows_peer_before = before,
                                knows_peer_after = after,
                                "federation delivery: primed {canonical}"
                            );
                        }
                        Ok(None) => tracing::warn!(
                            canonical = %canonical,
                            "federation delivery: {canonical}: no reticulum transport-tier binding \
                             in directory — cannot prime (explicit-hash canonical stays unrooted; \
                             publish it via the canonical address-update)"
                        ),
                        Err(e) => tracing::warn!(
                            canonical = %canonical,
                            error = %e,
                            "federation delivery: {canonical}: reticulum transport binding failed \
                             to decode — cannot prime, skipping this target"
                        ),
                    },
                    Err(e) => tracing::warn!(
                        canonical = %canonical,
                        error = %e,
                        "federation delivery: directory transport-destination lookup for \
                         {canonical} failed — cannot prime, skipping this target"
                    ),
                }
            }
        }
        None => tracing::warn!(
            "federation delivery: embedded edge has no Reticulum transport — cannot prime the \
             explicit-hash canonicals (they stay unrooted until announce-reachable)"
        ),
    }
    Ok(admitted_targets)
}

/// Whether delivery is held at "waiting for claim".
///
/// Distinct from "not started": a held node is healthy and waiting on a human, and
/// an operator reading `delivery_status_json` must be able to tell that from a
/// crash or a missing transport.
static WAITING_FOR_CLAIM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when startup is held pending an ownership claim.
#[must_use]
pub fn is_waiting_for_claim() -> bool {
    WAITING_FOR_CLAIM.load(std::sync::atomic::Ordering::SeqCst)
}

/// Ceiling for reconcile-failure backoff.
///
/// Five minutes: long enough that a sustained outage costs almost nothing, short
/// enough that a recovered peer reconverges without an operator intervening. The
/// floor is the configured cadence, so a healthy node's timing is unchanged.
const MAX_RECONCILE_BACKOFF_SECS: u64 = 300;

pub async fn run_federation_delivery(
    engine: Arc<Engine>,
    edge: Arc<Edge>,
    cadence_seconds: Option<u64>,
    announce_logger: bool,
) -> Result<DeliveryController> {
    let node_key_id = edge.signer_key_id().to_string();

    // 2-3b. Prime the admitted canonical peers (read baked hints → ROOT each
    //    canonical's transport binding — reachability only, NO consent). The
    //    post-restart reprime re-drives exactly this (CIRISServer#288).
    let admitted_targets = prime_canonicals(&engine, &edge, &node_key_id).await?;

    // 4. Start (or receive — single composition, #312) the ONE ReplicationRuntime
    //    over the shared transport. No seed set: a canonical enters the REPLICATION
    //    topology only once an owner has authored a consent:replication grant to it
    //    (POST /v1/federation/consent, post-claim); rooting above just makes it
    //    dialable. The runtime's one hot path reads that CEG consent state back.
    let runtime = crate::compose::start_replication_runtime(&engine, &edge, &node_key_id)
        .await?
    .context(
        "federation delivery: the embedded Edge has no Reticulum transport — cannot deliver (boot \
         the edge with disable_reticulum=false)",
    )?;

    // 5. Announce logger — RNS rooting visibility over the edge's event bus.
    if announce_logger {
        crate::compose::spawn_announce_logger(edge.events());
        crate::compose::spawn_event_bus_logger(edge.events());
        tracing::info!("federation delivery: announce logger subscribed to the edge event bus");
    }

    // 6. The reconcile loop — converge the live runtime to the corpus's
    //    consent:replication topology on a cadence tick. Uses `reconcile_once`
    //    directly (this controller has no ResolvedConfig watch; the cadence is the
    //    fixed `cadence_seconds` param, defaulting to the compose default).
    let cadence = Duration::from_secs(
        cadence_seconds
            .unwrap_or(DEFAULT_DELIVERY_CADENCE_SECS)
            .max(1),
    );
    let (reconcile_shutdown, mut shutdown_rx) = watch::channel(false);
    let reconcile_engine = Arc::clone(&engine);
    let reconcile_runtime = Arc::clone(&runtime);
    let reconcile_node_key = node_key_id.clone();
    let reconcile_join = tokio::spawn(async move {
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            cadence_secs = cadence.as_secs(),
            "federation-delivery reconcile loop started (consent:replication topology → set_peers)"
        );
        let mut last_logged: Option<usize> = None;
        // Decay a failing reconcile instead of re-running it at full cadence
        // forever. Resets to the floor on the first success, so a peer that
        // recovers is not still being punished for an earlier blip.
        let mut backoff =
            crate::backoff::Backoff::new(cadence, Duration::from_secs(MAX_RECONCILE_BACKOFF_SECS));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("federation-delivery reconcile loop shutting down");
                        return;
                    }
                    continue;
                }
            }
            match crate::replication_reconcile::reconcile_once(
                &reconcile_engine,
                &reconcile_node_key,
                &reconcile_runtime,
            )
            .await
            {
                Ok(count) => {
                    backoff.succeed();
                    // SELF-PROTECTION, not shedding. Reconcile is this node's own
                    // optional housekeeping; the accept loop and the read API are
                    // not. #501 was a node that measured its own CPU stall, raised
                    // the warning correctly, and kept doing background work at full
                    // cadence until HTTP became unschedulable. When the node is
                    // starving it now does less of what only it cares about.
                    //
                    // Deliberately NOT a load-shed declaration: this changes only
                    // our own pacing, is invisible to peers, and asserts nothing on
                    // anyone's behalf. Refusing a peer's work is an attributed act.
                    if crate::degradation::under_resource_stall() {
                        tracing::debug!(
                            "federation-delivery: resource stall — pausing one reconcile cadence \
                             to leave scheduling headroom"
                        );
                        tokio::select! {
                            () = tokio::time::sleep(cadence) => {}
                            changed = shutdown_rx.changed() => {
                                if changed.is_err() || *shutdown_rx.borrow() {
                                    return;
                                }
                            }
                        }
                        // RESET, or the pause buys nothing (Codex, PR #502). The
                        // interval's next deadline elapses DURING the sleep, so the
                        // following `tick()` is already ready and fires at once —
                        // the stall branch would shift a reconcile by a couple of
                        // seconds rather than omitting one, on exactly the hosts
                        // with no headroom to spare. `reset` puts the next deadline
                        // a full cadence from now, so a stalled node genuinely
                        // halves its reconcile rate.
                        interval.reset();
                    }
                    if last_logged != Some(count) {
                        tracing::info!(
                            consent_peers = count,
                            "federation delivery converged to {count} consent peers",
                        );
                        last_logged = Some(count);
                    }
                }
                Err(e) => {
                    let wait = backoff.fail();
                    tracing::warn!(
                        error = %e,
                        consecutive_failures = backoff.consecutive_failures(),
                        backoff_secs = wait.as_secs(),
                        at_ceiling = backoff.at_ceiling(),
                        "federation-delivery reconcile tick failed — backing off"
                    );
                    // Stay interruptible while waiting: a node shutting down must
                    // not have to sit through a ceiling-length backoff first.
                    tokio::select! {
                        () = tokio::time::sleep(wait) => {}
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                tracing::info!(
                                    "federation-delivery reconcile loop shutting down (during backoff)"
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }
    });

    tracing::info!(
        canonical_targets = admitted_targets.len(),
        "federation delivery controller started (embedded edge now drives replication + rooting to \
         the canonical mesh)"
    );

    Ok(DeliveryController {
        runtime,
        canonical_targets: admitted_targets,
        reconcile_shutdown,
        _reconcile_join: reconcile_join,
    })
}

/// The distinct canonical `key_id`s carried by the `(key_id, TransportHint)` pairs
/// [`Engine::canonical_bootstrap_hints`] returns — the replication targets. Order
/// is preserved by first appearance; duplicates (a canonical with multiple hints)
/// collapse to one. Pure so it is unit-testable without an engine.
pub(crate) fn distinct_canonical_key_ids(
    hints: &[(String, ciris_persist::federation::types::TransportHint)],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (key_id, _hint) in hints {
        if !out.iter().any(|k| k == key_id) {
            out.push(key_id.clone());
        }
    }
    out
}

/// Select the reticulum transport-tier binding from a directory's transport
/// destinations for an occurrence and decode it into the raw `prime` inputs.
///
/// Picks the first entry with `transport_kind == "reticulum"` that carries a
/// `transport_ed25519_pubkey_base64` (the #397 field), then decodes:
///   - `destination` (lowercase hex) → the 16-byte RNS dest-hash,
///   - `transport_ed25519_pubkey_base64` (base64-standard) → the 32-byte
///     transport-tier Ed25519 verifying key.
///
/// Returns:
///   - `Ok(Some((dest_hash, ed25519)))` — a usable binding to prime with.
///   - `Ok(None)` — no reticulum entry carries a transport ed25519 pubkey yet
///     (Node A hasn't published its transport binding — the caller WARNs + skips).
///   - `Err(_)` — an entry was found but its hex/base64 is malformed or the wrong
///     length (the caller WARNs + skips that target).
///
/// Pure over its input slice so the resolve/decode/selection logic is unit-testable
/// without a live directory or transport (the actual `inject_rooted_peer_for_test`
/// needs a live edge — covered by the agent live-lens QA).
pub(crate) fn resolve_reticulum_prime_binding(
    dests: &[ciris_persist::federation::TransportDestination],
) -> Result<Option<([u8; 16], [u8; 32])>> {
    use base64::Engine as _;

    let Some(entry) = dests
        .iter()
        .find(|d| d.transport_kind == "reticulum" && d.transport_ed25519_pubkey_base64.is_some())
    else {
        return Ok(None);
    };
    // Safe: the `find` predicate guarantees `Some`.
    let pubkey_b64 = entry
        .transport_ed25519_pubkey_base64
        .as_deref()
        .expect("find predicate guarantees transport_ed25519_pubkey_base64 is Some");

    let dest_hash_vec = hex::decode(&entry.destination).with_context(|| {
        format!(
            "reticulum destination must be lowercase hex; got {:?}",
            entry.destination
        )
    })?;
    let dest_hash: [u8; 16] = dest_hash_vec.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "reticulum dest-hash must decode to 16 bytes; got {}",
            dest_hash_vec.len()
        )
    })?;

    let ed_vec = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64)
        .context("transport_ed25519_pubkey_base64 must be base64-standard")?;
    let ed25519: [u8; 32] = ed_vec.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "transport ed25519 pubkey must decode to 32 bytes; got {}",
            ed_vec.len()
        )
    })?;

    Ok(Some((dest_hash, ed25519)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::types::TransportHint;

    fn hint(dest: &str, kind: &str) -> TransportHint {
        TransportHint {
            destination: dest.to_string(),
            kind: kind.to_string(),
        }
    }

    #[test]
    fn distinct_key_ids_dedupes_multi_hint_canonical() {
        // One canonical with two hints (ip + reticulum) + a second canonical.
        let hints = vec![
            ("canon-1".to_string(), hint("108.61.242.236:4243", "ip")),
            ("canon-1".to_string(), hint("abcd", "reticulum")),
            ("canon-2".to_string(), hint("10.0.0.1:4243", "ip")),
        ];
        let ids = distinct_canonical_key_ids(&hints);
        assert_eq!(ids, vec!["canon-1".to_string(), "canon-2".to_string()]);
    }

    #[test]
    fn distinct_key_ids_empty_on_no_hints() {
        assert!(distinct_canonical_key_ids(&[]).is_empty());
    }

    #[test]
    fn build_replication_peers_wires_every_plane_per_target() {
        use ciris_edge::replication::EnvelopeKind;
        // The delivery controller hands the admitted canonical targets to the SAME
        // peer-assembly the compose boot path uses. Asserted as an exact ORDERED
        // list rather than a count: a count passes when a plane is swapped for
        // another, and the planes are not interchangeable.
        let desired = vec!["canon-1".to_string(), "peer-b".to_string()];
        let peers = crate::compose::build_replication_peers(&desired);
        let expected = [
            EnvelopeKind::Attestation,
            EnvelopeKind::Key,
            // KEX (CIRISEdge#305).
            EnvelopeKind::IdentityOccurrence,
            // The PQ transport-attribution plane (CIRISEdge#406).
            EnvelopeKind::TransportDestination,
            // The chat roster — without it a `cohort_scope: community` row
            // arrives somewhere with no community to be a member of.
            EnvelopeKind::Community,
            // And its removals: the roster is append-only, so admissions
            // without revocations replicate a membership that can only grow.
            EnvelopeKind::CommunityMembershipRevocation,
        ];
        assert_eq!(peers.len(), desired.len() * expected.len());
        for (target_index, target) in desired.iter().enumerate() {
            for (plane_index, kind) in expected.iter().enumerate() {
                let peer = &peers[target_index * expected.len() + plane_index];
                assert_eq!(&peer.peer_key_id, target);
                assert_eq!(
                    std::mem::discriminant(&peer.kind),
                    std::mem::discriminant(kind),
                    "target {target}, plane {plane_index}"
                );
            }
        }
    }

    /// The reconcile coordinator and the boot coordinator must wire the SAME
    /// planes — they used to be two hand-maintained lists, and the copy had
    /// already drifted (its comment said "ALL THREE planes" while listing four).
    /// `replication_reconcile` now calls this assembly instead of restating it,
    /// so this pins that there is ONE list: a peer hot-added at reconcile
    /// converges exactly what a peer added at boot does.
    #[test]
    fn the_reconcile_path_wires_the_same_planes_as_boot() {
        let boot = crate::compose::build_replication_peers(&["p".to_string()]);
        let reconcile =
            crate::compose::build_replication_peers(std::slice::from_ref(&"p".to_string()));
        assert_eq!(boot.len(), reconcile.len());
        for (b, r) in boot.iter().zip(reconcile.iter()) {
            assert_eq!(b.peer_key_id, r.peer_key_id);
            assert_eq!(
                std::mem::discriminant(&b.kind),
                std::mem::discriminant(&r.kind)
            );
        }
    }

    #[test]
    fn build_replication_peers_empty_target_set() {
        assert!(crate::compose::build_replication_peers(&[]).is_empty());
    }

    // ---- resolve_reticulum_prime_binding ----

    use base64::Engine as _;
    use ciris_persist::federation::TransportDestination;

    /// A `TransportDestination` fixture. `dest`/`ed_b64` are the raw address +
    /// transport-Ed25519 (already encoded as the store carries them).
    fn dest(kind: &str, dest_hex: &str, ed_b64: Option<&str>) -> TransportDestination {
        TransportDestination {
            occurrence_key_id: "canon-1".to_string(),
            transport_kind: kind.to_string(),
            destination: dest_hex.to_string(),
            asserted_at: chrono::Utc::now(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: ed_b64.map(str::to_string),
            transport_x25519_pubkey_base64: None,
            binding_provenance: ciris_persist::federation::self_at_login::BindingProvenance::Rooted,
            epoch: 0,
            retired_at: None,
        }
    }

    /// 16-byte dest-hash as lowercase hex + a valid 32-byte base64 ed25519.
    fn good_hex_16() -> String {
        hex::encode([0xABu8; 16])
    }
    fn good_ed_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode([0x11u8; 32])
    }

    #[test]
    fn prime_binding_decodes_reticulum_entry_16_32() {
        let dests = vec![dest("reticulum", &good_hex_16(), Some(&good_ed_b64()))];
        let (dh, ed) = resolve_reticulum_prime_binding(&dests)
            .expect("decodes")
            .expect("some binding");
        assert_eq!(dh, [0xAB; 16]);
        assert_eq!(ed, [0x11; 32]);
    }

    #[test]
    fn prime_binding_picks_the_reticulum_entry_with_a_transport_ed25519() {
        // A websocket entry (ignored), a reticulum entry WITHOUT a transport key
        // (not primeable — must be skipped), then the reticulum entry WITH one.
        let dests = vec![
            dest("websocket", "wss://example.test", Some(&good_ed_b64())),
            dest("reticulum", &good_hex_16(), None),
            dest(
                "reticulum",
                &hex::encode([0xCDu8; 16]),
                Some(&good_ed_b64()),
            ),
        ];
        let (dh, ed) = resolve_reticulum_prime_binding(&dests)
            .expect("decodes")
            .expect("some binding");
        assert_eq!(dh, [0xCD; 16]);
        assert_eq!(ed, [0x11; 32]);
    }

    #[test]
    fn prime_binding_none_when_no_reticulum_transport_key() {
        // Reticulum entry exists but carries no transport ed25519 (Node A hasn't
        // published the #397 binding yet) → None (caller warns "no binding").
        let dests = vec![
            dest("websocket", "wss://example.test", Some(&good_ed_b64())),
            dest("reticulum", &good_hex_16(), None),
        ];
        assert!(resolve_reticulum_prime_binding(&dests)
            .expect("ok")
            .is_none());
    }

    #[test]
    fn prime_binding_none_on_empty() {
        assert!(resolve_reticulum_prime_binding(&[]).expect("ok").is_none());
    }

    #[test]
    fn prime_binding_err_on_bad_dest_hash_length() {
        // Valid hex but only 8 bytes → not a 16-byte dest-hash → Err (skip target).
        let dests = vec![dest(
            "reticulum",
            &hex::encode([0u8; 8]),
            Some(&good_ed_b64()),
        )];
        assert!(resolve_reticulum_prime_binding(&dests).is_err());
    }

    #[test]
    fn prime_binding_err_on_non_hex_dest() {
        let dests = vec![dest("reticulum", "not-hex-zzzz", Some(&good_ed_b64()))];
        assert!(resolve_reticulum_prime_binding(&dests).is_err());
    }

    #[test]
    fn prime_binding_err_on_bad_ed25519_length() {
        // Valid base64 but 16 bytes → not a 32-byte ed25519 → Err (skip target).
        let short_ed = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let dests = vec![dest("reticulum", &good_hex_16(), Some(&short_ed))];
        assert!(resolve_reticulum_prime_binding(&dests).is_err());
    }

    #[test]
    fn prime_binding_err_on_non_base64_ed25519() {
        let dests = vec![dest("reticulum", &good_hex_16(), Some("!!!not base64!!!"))];
        assert!(resolve_reticulum_prime_binding(&dests).is_err());
    }
}
