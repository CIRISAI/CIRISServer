//! **The node's own short-lived load-shed observation.**
//!
//! `degradation` measures contention and raises `resource.cpu_stall`; the ops to
//! declare a load shed exist; nothing connected them. CIRISServer#501 was a node
//! that measured its own starvation, raised the warning correctly, and went dark
//! anyway — detection with no consequence.
//!
//! # Why a node may author this at all
//!
//! An `admin_action:` is a governance act by a PERSON, and persist enforces that:
//! `check_admin_action_attribution` refuses one without a `delegation_id`. A node
//! has no delegation and no such standing, so it does not author an admin action.
//! It authors an OBSERVATION about itself — its own hard-case kind, outside the
//! human-attribution plane rather than sneaking through it.
//!
//! # Why short-lived is what makes it safe
//!
//! The objection to a node acting under its own authority was never that it
//! speaks; it is that it would ACCUMULATE STANDING nobody granted, and keep it
//! after the condition passed. An expiry makes the lifetime encode the authority:
//! the act cannot outlive the observation that produced it.
//!
//! It also removes the need for anyone to clean up. A durable self-declaration
//! needs a human to lift it, and that human may never come — the eternal emergency
//! `mesh_config_effect` explicitly refuses to create. Here **recovery is the
//! lift**: a node that recovers stops renewing, a node that dies stops renewing, a
//! node that was wrong stops renewing. Nothing has to notice.
//!
//! Renewal is re-observation, not inheritance: every renewal is a fresh
//! measurement under the same authority as the first.
//!
//! # Failure direction
//!
//! Too short: the node stops declaring while still struggling, peers resume
//! offering, and it declares again — noisy, self-correcting. Too long: a healthy
//! node keeps telling the mesh it is shedding and only a person can clear it. The
//! first failure the system repairs; the second it cannot. So the TTL is a small
//! multiple of the observation interval, and no larger.
//!
//! # What this does NOT do
//!
//! It refuses nobody. Enforcement stays cooperative — the declaration is the
//! artifact a peer reads to stop offering, and no node decrees another's
//! behaviour. Automating a REFUSAL (`refuse_writes`) would be a node deciding
//! about a PEER with nobody in the loop, which is a different question and is not
//! answered here.

use std::sync::Arc;
use std::time::Duration;

use ciris_persist::prelude::Engine;

/// How often the node measures itself.
pub const OBSERVE_INTERVAL: Duration = Duration::from_secs(60);

/// How long one observation stands.
///
/// Three observation intervals: long enough that a single missed or slow tick does
/// not drop a live declaration, short enough that a node which stops observing
/// stops declaring within a few minutes.
pub const OBSERVATION_TTL_SECS: i64 = 180;

/// Spawn the observe-and-declare loop.
pub fn spawn(engine: Arc<Engine>, node_key_id: String) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(OBSERVE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            observe_secs = OBSERVE_INTERVAL.as_secs(),
            ttl_secs = OBSERVATION_TTL_SECS,
            "load-shed observer started (node-authored, self-expiring; recovery is the lift)"
        );
        loop {
            interval.tick().await;

            // PROBE, do not merely read. `probe_contention` is what refreshes the
            // stall warnings, and it is otherwise only called from `/v1/health` —
            // so a node with no health traffic would observe nothing and declare
            // nothing, exactly when it is least able to serve that request.
            let _ = crate::degradation::probe_contention();
            if !crate::degradation::under_resource_stall() {
                continue;
            }

            match crate::admin_ops::record_node_observation(
                &engine,
                crate::admin_ops::SelfAct::ShedLoad,
                &node_key_id,
                chrono::Utc::now(),
                chrono::Duration::seconds(OBSERVATION_TTL_SECS),
                "this node measured sustained CPU or IO contention and is carrying less",
            )
            .await
            {
                Ok(event_id) => tracing::warn!(
                    event_id = %event_id,
                    ttl_secs = OBSERVATION_TTL_SECS,
                    "load shed DECLARED by this node about itself — expires on its own; \
                     peers may read it to stop offering"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    "load-shed observation could not be recorded — continuing"
                ),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The TTL must outlast a missed tick but not a recovery.
    ///
    /// Below one interval, a single slow tick drops a live declaration and the node
    /// flaps. Far above it, a recovered node keeps telling the mesh it is shedding
    /// — the failure only a human can clear.
    #[test]
    fn the_ttl_is_a_small_multiple_of_the_observation_interval() {
        let interval = OBSERVE_INTERVAL.as_secs() as i64;
        assert!(
            OBSERVATION_TTL_SECS > interval,
            "a single missed tick must not drop a live declaration"
        );
        assert!(
            OBSERVATION_TTL_SECS <= interval * 5,
            "a recovered node must stop declaring within minutes, not hours"
        );
    }
}
