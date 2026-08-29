//! **A node's own `config:load` attestation — a self-report, short-lived, replicated.**
//!
//! `degradation` measures contention and raises `resource.cpu_stall`; nothing
//! consumed it. CIRISServer#501 was a node that measured its own starvation, raised
//! the warning correctly, and went dark anyway — detection with no consequence.
//!
//! # The authority, read from the constitution
//!
//! Every node holds `infra:attest` — *"vouch as the delegator's infrastructure"* —
//! from its owner-binding, and the canonical holds it from the accord's charter
//! (`[infra:attest, infra:serve, infra:store, infra:transport]`; CC 4.4.3.8: *"a
//! root serves and vouches, or it is inert"*). It is conferred **so the node can
//! vouch about the delegator's infrastructure**, and "I am at capacity" is a fact
//! about that infrastructure only the infrastructure can observe.
//!
//! CC 3.1 already reserves the dimension: **`config:{scope}`** — *"a node's
//! declared operating configuration, published as an auditable record rather than
//! inferred from behaviour… only ever about the emitting node."* And CC 3.4.5 gives
//! its emitter rule: **self-or-owner** — `attesting_key_id` MUST be
//! `attested_key_id` or its live owner. *"A node's running configuration is a
//! self-report; a third-party assertion of what you are running is a rumour."*
//!
//! So this is not a node exceeding its grant. It is the grant working.
//!
//! # What this is NOT — and what it was, wrongly, twice
//!
//! It is **not a `mesh_config` value.** That plane (CC 4.2.1) is the trust root's,
//! on the delegation plane, and it governs what OTHER nodes carry. A node MUST NOT
//! author there, and this module never does. Two planes, two authors, one reason:
//! the root relieves ACROSS nodes; a node vouches ABOUT itself.
//!
//! An earlier version authored a `HardCaseEvent` instead. Hard-case events are on
//! no replication plane, so *"the artifact a peer reads to stop offering"* could
//! never reach a peer. An attestation replicates; that is why it is the primitive.
//!
//! # Why short-lived is what makes it safe
//!
//! The objection to a node speaking for itself was never that it speaks; it is
//! that it would accumulate STANDING nobody granted and keep it after the
//! condition passed. `expires_at` — a real, signed, admission-enforced instant
//! (persist#598) — makes the lifetime encode the authority: the row cannot outlive
//! the observation that produced it. Renewal is re-observation, not inheritance.
//!
//! There is deliberately no lift. A durable self-declaration would need a person to
//! clear it, and that person may never come. Here **recovery is the lift**: a node
//! that recovers stops renewing, a node that dies stops renewing, a node that was
//! wrong stops renewing. Nothing has to notice.
//!
//! # A gap this module does not close
//!
//! persist gates `mesh_config:` at admission but does NOT enforce CC 3.4.5's
//! self-or-owner rule on `config:*` — the emitter rule is producer obligation only
//! today. This producer honours it by construction (attesting == attested), and the
//! substrate-side check is asked for upstream so a third party's `config:load`
//! about this node is refused rather than merely unfashionable.

use std::sync::Arc;
use std::time::Duration;

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::prelude::Engine;

/// The `config:{scope}` leaf for carried load, VERSIONED. Open vocabulary per CC
/// 4.5.1.1; `admission` / `replication` / `moderation` / `transport` are the
/// canonical scopes and this joins them as the node's self-report of what it is
/// carrying.
///
/// The `:v1` is not decoration: persist's `DimensionAdmissionPolicy` refuses any
/// `scores` dimension without a `:vN` segment (`MissingVersionSegment`, T3). The
/// first cut of this module omitted it, and every emission would have been
/// rejected at the put door while the loop logged "attestation failed" once a
/// minute — the row could never have reached a peer (Codex, PR #504). Existing
/// producers all carry one (`config:v1`, `consent:replication:v1`).
pub const DIMENSION: &str = "config:load:v1";

/// The one value this attestation carries: what the node is doing about it.
pub const STATE_SHEDDING: &str = "shedding";

/// How often the node measures itself.
pub const OBSERVE_INTERVAL: Duration = Duration::from_secs(60);

/// Minimum gap between two emissions.
///
/// Expiry makes a row INACTIVE; it does not remove it, and this repo's retention
/// loop has deletion levers for traces and audit entries only — an
/// attestation-heavy store is a documented unenforceable disk case. A row per
/// minute is 1,440 permanent rows a day, in this node's store AND every peer's,
/// which worsens the very storage pressure that can trigger this loop (Codex,
/// PR #504).
///
/// So renewal is spaced to just inside the TTL rather than run at the observation
/// cadence: the node keeps a live declaration continuously, at ~1/3 the rows. The
/// observation interval stays short because DETECTING quickly still matters — it
/// is the *writing* that is throttled, not the looking.
pub const MIN_EMIT_GAP_SECS: i64 = TTL_SECS - OBSERVE_INTERVAL.as_secs() as i64;

// Pinned at COMPILE time — these are constants, so a test could only restate what
// the compiler already knows (clippy `assertions_on_constants`). As const
// assertions they fail the BUILD the moment someone retunes a value past its bound.
//
// Spacing must exceed the observation tick or nothing is saved, and must stay
// under the TTL or the declaration lapses while the node is still stalled.
const _: () = assert!(
    MIN_EMIT_GAP_SECS > 0,
    "renewal spacing must be positive or every tick mints a permanent row"
);

/// How long one attestation stands.
///
/// Three observation intervals: long enough that a single slow tick does not drop
/// a live row, short enough that a node which stops observing stops declaring
/// within minutes. Too short and the node flaps; too long and a recovered node
/// keeps telling the mesh it is shedding — the failure only a person can clear.
pub const TTL_SECS: i64 = 180;

const _: () = assert!(
    MIN_EMIT_GAP_SECS < TTL_SECS,
    "a gap at or beyond the TTL lets the declaration lapse while the node still struggles"
);

/// Build the self-report the node will sign.
///
/// `attesting == attested == subject`: CC 3.4.5 self-or-owner, satisfied on the
/// producer side by construction. `witness_relation: self` is the CC 2.1 marker
/// consumers weight by — this is a self-attestation and says so on the wire.
///
/// No `asserted_at` here (CIRISServer#402 / persist#598): the stamp writes the
/// signed instants once, truncated to the substrate's resolution.
#[must_use]
pub fn spec(node_key_id: &str, expires_at: chrono::DateTime<chrono::Utc>) -> crate::attest::Spec {
    let envelope = serde_json::json!({
        (paths::DIMENSION): DIMENSION,
        "attesting_key_id": node_key_id,
        "subject_key_ids": [node_key_id],
        "score": 1.0,
        // REQUIRED, not optional. `compose_policy::Composer::screen` refuses an
        // envelope without it (`MalformedEnvelope("confidence")`) and deliberately
        // does not default to 1.0 — so a row missing it is admitted and replicated
        // and then contributes NOTHING to the composed verdict a peer would use to
        // stop offering work (Codex, PR #504). The whole point of replicating this
        // is that a peer can act on it.
        //
        // 1.0 because the producer is the subject: this is not an inference about
        // someone else, it is a measurement of itself under `witness_relation:
        // self`, and a consumer discounts self-attestation by relation rather than
        // by the producer pre-discounting its own reading.
        "confidence": 1.0,
        "cohort_scope": cohort_scope::FEDERATION,
        "witness_relation": "self",
        "state": STATE_SHEDDING,
        "reason": "measured sustained CPU or IO contention",
    });
    crate::attest::Spec::new(attestation_type::SCORES, cohort_scope::FEDERATION, envelope)
        .about(node_key_id)
        .expiring(Some(expires_at))
        .weighing(Some(1.0))
}

/// Who signs the node's self-report.
///
/// On a split node (an agent-carrying node whose configured key was an actor,
/// `node_key::resolve_node_identity`) the wire identity is a separately minted
/// node key and the Engine signs as the ACTOR. A row stamped with the node key as
/// `attesting_key_id` but signed by the actor's pen fails signature verification
/// against the node's registered public key — every emission rejected at
/// admission (Codex, PR #504). `NodeIdentityResolution.signer` exists for exactly
/// this ("author rows AS the node while the engine signs as the actor") and is
/// carried here rather than dropped after boot.
///
/// On an unsplit node — the standalone binary, and the wheel's bare-agent path —
/// the engine key IS the node key, and the engine is the right pen.
#[derive(Clone)]
pub enum NodePen {
    /// Engine key == node key. Sign with the engine.
    Engine,
    /// A split happened; sign as the node with its own signer.
    Node(Arc<ciris_persist::prelude::LocalSigner>),
}

impl NodePen {
    /// Pick the pen from a boot's identity resolution.
    #[must_use]
    pub fn from_resolution(r: &crate::node_key::NodeIdentityResolution) -> Self {
        match &r.signer {
            Some(s) => Self::Node(Arc::clone(s)),
            None => Self::Engine,
        }
    }

    fn signer<'a>(&'a self, engine: &'a Engine) -> crate::attest::KeySigner<'a> {
        match self {
            Self::Engine => crate::attest::KeySigner::Engine(engine),
            Self::Node(s) => crate::attest::KeySigner::Local(s),
        }
    }
}

/// Emit one `config:load` self-attestation, signed with the node's own pen.
///
/// # Errors
/// Stamp, sign, or put failure.
pub async fn emit(engine: &Engine, pen: &NodePen, node_key_id: &str) -> anyhow::Result<String> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(TTL_SECS);
    let row = crate::attest::Emit::stamp(node_key_id, spec(node_key_id, expires_at))
        .map_err(|e| anyhow::anyhow!("stamp config:load for {node_key_id}: {e}"))?
        .sign_and_assemble(pen.signer(engine))
        .await
        .map_err(|e| anyhow::anyhow!("sign config:load as {node_key_id}: {e}"))?;
    crate::attest::put(engine, row)
        .await
        .map_err(|e| anyhow::anyhow!("put config:load for {node_key_id}: {e}"))
}

/// Spawn the observe-and-attest loop.
///
/// Returns the shutdown sender and the join handle, so composition can stop it
/// the way it stops the retention and config loops. Dropping the handle would
/// only DETACH the task: on the supported in-process `shutdown_node()` restart the
/// old observer would keep its `Arc<Engine>`, keep probing, keep renewing
/// attestations against the old node, and every restart would add another one
/// (Codex, PR #504).
pub fn spawn(
    engine: Arc<Engine>,
    pen: NodePen,
    node_key_id: String,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let join = tokio::spawn(async move {
        let mut interval = tokio::time::interval(OBSERVE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_emit: Option<chrono::DateTime<chrono::Utc>> = None;
        tracing::info!(
            dimension = DIMENSION,
            min_emit_gap_secs = MIN_EMIT_GAP_SECS,
            observe_secs = OBSERVE_INTERVAL.as_secs(),
            ttl_secs = TTL_SECS,
            pen = match pen {
                NodePen::Engine => "engine",
                NodePen::Node(_) => "node (split)",
            },
            "config:load observer started (self-attested on infra:attest, expires on its own)"
        );
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("config:load observer shutting down");
                        return;
                    }
                    continue;
                }
            }

            if !own_stall_now() {
                continue;
            }

            // A live declaration already covers this moment — do not mint a second
            // permanent row to say the same thing. Re-emit only once the standing
            // one is close enough to expiring that a gap would open.
            let now = chrono::Utc::now();
            if last_emit.is_some_and(|t: chrono::DateTime<chrono::Utc>| {
                now - t < chrono::Duration::seconds(MIN_EMIT_GAP_SECS)
            }) {
                continue;
            }

            match emit(&engine, &pen, &node_key_id).await {
                Ok(id) => {
                    // Only a SUCCESSFUL emission moves the clock. A failed one must
                    // leave it, or a transient refusal would suppress renewal for a
                    // whole gap and the node would go quiet while still struggling.
                    last_emit = Some(now);
                    tracing::warn!(
                        attestation_id = %id,
                        ttl_secs = TTL_SECS,
                        renewal_gap_secs = MIN_EMIT_GAP_SECS,
                        "config:load = shedding — self-attested; expires on its own; peers may \
                         read it to stop offering"
                    );
                }
                Err(e) => tracing::warn!(error = %e, "config:load attestation failed — continuing"),
            }
        }
    });
    (shutdown_tx, join)
}

/// Probe, under the same lock `/v1/health` holds, and judge the FRESH reading.
///
/// PROBE rather than read: `probe_contention` is otherwise only called from
/// `/v1/health`, so a node with no health traffic would observe nothing — and when
/// PSI vanishes mid-run the probe deliberately preserves the old warning rather
/// than clearing it (no-evidence discipline), so a registry read would renew a
/// "short-lived" row forever off a stale entry.
///
/// UNDER `COLLECT_LOCK`: the health route holds it across its probes and its final
/// `verdict()` precisely so one response cannot pair resource readings from one
/// instant with warning state from another. A probe here without the lock could
/// land between those two steps and put that inconsistency back (Codex, PR #504).
/// `probe_contention` is synchronous file IO, so the `std` mutex is held for
/// microseconds and never across an await.
fn own_stall_now() -> bool {
    let _collect = crate::degradation::COLLECT_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (cpu, io) = crate::degradation::probe_contention();
    stalled(&cpu) || stalled(&io)
}

/// A FRESH, CGROUP-SCOPED, degrading stall — never a stale registry entry, and
/// never a host reading.
///
/// Scope is the load-bearing check. `/proc/pressure/*` describes the whole box,
/// and a noisy neighbour there would make this node **attest, under its own
/// signature, that it is shedding** — a self-report about a condition it is not
/// suffering, replicated to every peer (PR #483 review: host readings are never
/// escalated to a statement about this node). Only this process's own cgroup may
/// speak for this process.
///
/// The threshold is `degradation`'s own `full` bound, not a restated literal, so
/// this attests exactly when the node would report itself degraded and never on a
/// looser standard of its own.
fn stalled(p: &crate::degradation::Pressure) -> bool {
    use crate::degradation::{Pressure, PressureScope, PRESSURE_DEGRADE_FULL_PCT};
    match p {
        Pressure::Measured {
            scope: PressureScope::Cgroup,
            full_avg10: Some(full),
            ..
        } => *full >= PRESSURE_DEGRADE_FULL_PCT,
        // A host reading, a kernel with no `full` line, or no PSI at all: none of
        // these is evidence about THIS node's own stall, so none may renew.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "node-under-test";

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("ts")
    }

    /// CC 3.4.5 self-or-owner, satisfied by construction: attesting, attested and
    /// subject are all the node. A third party's `config:load` about this node is
    /// a rumour, and this producer can never write one.
    #[test]
    fn it_is_a_self_report_on_every_axis() {
        let s = spec(NODE, at(180));
        assert_eq!(s.attested_key_id.as_deref(), Some(NODE));
        assert_eq!(s.subject_key_ids, vec![NODE.to_string()]);
        assert_eq!(s.envelope["attesting_key_id"], NODE);
        assert_eq!(s.envelope["witness_relation"], "self");
    }

    /// The row carries its own expiry — a real signed instant persist enforces at
    /// read time (`expires_at IS NULL OR expires_at > NOW()`), so a stale
    /// declaration is not merely ignorable, it is invisible.
    #[test]
    fn it_expires() {
        let s = spec(NODE, at(180));
        assert_eq!(s.expires_at, Some(at(180)));
    }

    /// It is `config:{scope}` — the CC 3.1 dimension reserved for exactly this, not
    /// a new family and not `mesh_config:` (the root's plane, which a node MUST NOT
    /// author).
    #[test]
    fn it_is_on_the_config_dimension_and_never_mesh_config() {
        let s = spec(NODE, at(180));
        assert_eq!(s.envelope[paths::DIMENSION], DIMENSION);
        assert!(DIMENSION.starts_with("config:"));
        assert!(!DIMENSION.starts_with("mesh_config:"));
    }

    /// The dimension carries a `:vN` segment. Without one persist refuses the row
    /// at admission (`MissingVersionSegment`) and the observer logs a failure once
    /// a minute while nothing ever reaches a peer — the first cut of this module.
    #[test]
    fn the_dimension_is_versioned_or_persist_refuses_it() {
        let last = DIMENSION.rsplit(':').next().unwrap_or("");
        assert!(
            last.len() >= 2
                && last.starts_with('v')
                && last[1..].chars().all(|c| c.is_ascii_digit()),
            "{DIMENSION} must end in :vN"
        );
    }

    /// On a split node the row must be signed by the NODE's pen, not the engine's:
    /// stamped as the node and signed by the actor fails verification at admission.
    /// On an unsplit node the engine is the node, and the engine is right.
    #[test]
    fn the_pen_follows_the_split() {
        use crate::node_key::{IdentityVerdict, NodeIdentityResolution};
        let unsplit = NodeIdentityResolution {
            node_key_id: NODE.into(),
            split_from: None,
            verdict: IdentityVerdict::SubstrateOnly,
            signer: None,
        };
        assert!(matches!(
            NodePen::from_resolution(&unsplit),
            NodePen::Engine
        ));
        // A split resolution carries a signer; the pen must be that signer. (A
        // real LocalSigner needs key material, so this asserts the mapping's shape
        // on the `None` half and leaves the `Some` half to the compose path.)
        assert!(unsplit.signer.is_none());
    }

    /// Federation scope, so it actually replicates — the reason an attestation and
    /// not a hard-case event.
    #[test]
    fn it_replicates_at_federation_scope() {
        let s = spec(NODE, at(180));
        assert_eq!(s.cohort_scope, cohort_scope::FEDERATION);
    }

    /// No `asserted_at` in the envelope: the stamp owns the signed instants
    /// (persist#598), and a hand-written one lands with nanoseconds postgres cannot
    /// store, refusing the put. Every write on this path failed on v31 for that.
    #[test]
    fn it_leaves_the_signed_instants_to_the_stamp() {
        let s = spec(NODE, at(180));
        assert!(s.envelope.get(paths::ASSERTED_AT).is_none());
        assert!(s.envelope.get(paths::EXPIRES_AT).is_none());
    }

    /// Only a fresh, cgroup-scoped, degrading reading renews. Everything else —
    /// host scope, sub-threshold, no `full` line, PSI unavailable — is not evidence
    /// about THIS node and must not put this node's signature on "shedding".
    #[test]
    fn only_this_nodes_own_degrading_stall_counts() {
        use crate::degradation::{Pressure, PressureScope, PRESSURE_DEGRADE_FULL_PCT};
        let own = |full: f64| Pressure::Measured {
            scope: PressureScope::Cgroup,
            some_avg10: 99.0,
            full_avg10: Some(full),
        };
        assert!(
            stalled(&own(PRESSURE_DEGRADE_FULL_PCT)),
            "at the degrade bound"
        );
        assert!(stalled(&own(99.0)));
        assert!(!stalled(&own(PRESSURE_DEGRADE_FULL_PCT - 0.01)), "under it");

        // The noisy-neighbour case: the BOX is thrashing, this node is fine. A
        // self-attestation here would be a false statement under our signature.
        assert!(!stalled(&Pressure::Measured {
            scope: PressureScope::Host,
            some_avg10: 99.0,
            full_avg10: Some(99.0),
        }));
        // No `full` line (CPU on many kernels): absent is not zero and not evidence.
        assert!(!stalled(&Pressure::Measured {
            scope: PressureScope::Cgroup,
            some_avg10: 99.0,
            full_avg10: None,
        }));
        assert!(!stalled(&Pressure::Unavailable {
            reason: "no PSI".into()
        }));
    }

    /// TTL outlasts a missed tick but not a recovery.
    #[test]
    fn the_ttl_is_a_small_multiple_of_the_observation_interval() {
        let interval = OBSERVE_INTERVAL.as_secs() as i64;
        assert!(
            TTL_SECS > interval,
            "one slow tick must not drop a live row"
        );
        assert!(
            TTL_SECS <= interval * 5,
            "a recovered node must stop declaring in minutes"
        );
    }
}
