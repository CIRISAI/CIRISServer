//! **Pull this node's owner's own testimony** — the RECEIVE axis
//! (CIRISServer#392, on CIRISEdge#462).
//!
//! # The gap
//!
//! `GET /v1/setup/owned-nodes` projects from `engine.nodes_stewarded_by(owner)`, a
//! purely LOCAL persist read. Claim a fresh node with a portable fed-ID that
//! already stewards ciris-canonical-1 and the list comes back with only `self`,
//! while canonical-1 — asked the same question — answers with the owner and six
//! nodes. The projection was right; the graph under it was empty, and nothing
//! moved the rows.
//!
//! Same gap for `trust:confers:v1`: a moderation duty conferred on the fed-ID at
//! one node did not follow the fed-ID to a node it claimed, so the authority was
//! real and unexercisable.
//!
//! # Why anti-entropy could not fix it
//!
//! Anti-entropy is advertise-based: `want = remote ∖ holdings`, generated purely
//! from what a peer chooses to advertise. It has no way to express "give me the
//! rows about ME". And for the `self`/`family` plane it cannot ever work —
//! `projection_for` maps those to `Projection::SelfOwn` (publish-own), so nobody
//! advertises them at any setting. A subject-initiated pull is not an optimization
//! there; it is the only mechanism that can exist.
//!
//! Edge v15.22.0 adds the verb: `ReplicationRuntime::pull_subject_testimony`,
//! fail-closed to the subject, sweeping the five subject-pullable kinds and both
//! testimonial axes (`data_subject` + `sender`) on the Attestation plane, with the
//! G2 capacity-score carve. This module is the consumer.
//!
//! # When it runs
//!
//! At IDENTITY-LOAD, not at boot: the trigger is this node learning who its owner
//! is — the first-run claim, or a later boot that already has one. A node with no
//! owner has no subject to pull for, and saying so is more useful than pulling
//! nothing and calling it success.
//!
//! # Fail-VISIBLE
//!
//! Every exit here logs which of three states it is in — no owner, no peers, or
//! dispatched-to-N — because "pulled nothing" and "could not pull" are different
//! facts and collapsing them is the distinct-zeroes defect this repo keeps paying
//! for. The pull itself is fire-and-forget by design (the reply converges over the
//! peer's next round), so the dispatch log is the only place the attempt is
//! visible at all.

use std::sync::Arc;

use ciris_persist::prelude::Engine;

/// What one pull attempt did — returned so callers can log or test it, never
/// collapsed to a bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// The node has no bound owner yet — nothing to pull FOR. Not a failure.
    NoOwner,
    /// No replication runtime (no Reticulum transport this boot) — could not pull.
    NoRuntime,
    /// An owner exists but this node knows no replication peers to ask.
    NoPeers { owner: String },
    /// Dispatched to `peers`; `failures` names any peer whose send failed.
    Dispatched {
        owner: String,
        peers: Vec<String>,
        failures: Vec<String>,
    },
}

/// **Ask every known replication peer for the owner's own testimony.**
///
/// Fire-and-forget per edge's contract: the Pull carries no session state, and
/// the peer's Summary reply converges through the ordinary round loop. So this
/// returns as soon as the sends are dispatched — the rows land asynchronously and
/// `owned-nodes` fills in as they do.
pub async fn pull_owner_testimony(engine: &Arc<Engine>, node_key_id: &str) -> PullOutcome {
    // A split install is several keys (CIRISServer#632): the caller passes the
    // edge signer — the ACTOR — while the owner-binding and the owner's consent
    // grants name the NODE key. Every read below folds over all of them.
    let own = own_keys(node_key_id);
    let Some(owner) = owner_of_any(engine, &own).await else {
        tracing::info!(
            node_key_id = %node_key_id,
            own_keys = %own.join(", "),
            "receive-axis pull SKIPPED — this node has no bound owner yet, so there is no subject \
             to pull testimony for (CIRISEdge#462). This is the unclaimed state, not a failure."
        );
        return PullOutcome::NoOwner;
    };

    let Some(runtime) = crate::compose::held_replication_runtime() else {
        tracing::warn!(
            owner = %owner,
            "receive-axis pull UNAVAILABLE — no replication runtime this boot (no Reticulum \
             transport), so the owner's testimony cannot be recovered. owned-nodes and any \
             conferred duty will show only what this node already holds."
        );
        return PullOutcome::NoRuntime;
    };

    let peers = peers_to_ask(engine, &own).await;

    if peers.is_empty() {
        tracing::warn!(
            owner = %owner,
            node_key_id = %node_key_id,
            own_keys = %own.join(", "),
            "receive-axis pull found NO PEERS — the owner's testimony exists somewhere, but this \
             node knows nowhere to ask. Distinct from 'asked and got nothing': check \
             consent:replication grants."
        );
        return PullOutcome::NoPeers { owner };
    }

    let mut failures = Vec::new();
    for peer in &peers {
        if let Err(e) = runtime.pull_subject_testimony(peer, &owner).await {
            // Do NOT swallow: a dropped Pull silently loses the SelfOwn plane's
            // recovery while the caller believes it was dispatched.
            tracing::warn!(peer = %peer, owner = %owner, error = %e, "receive-axis pull FAILED for this peer");
            failures.push(format!("{peer}: {e}"));
        }
    }

    tracing::info!(
        owner = %owner,
        peers = %peers.join(", "),
        peer_count = peers.len(),
        failed = failures.len(),
        "receive-axis pull DISPATCHED (CIRISEdge#462) — asked each peer for every row where this \
         owner is the data_subject or the sender. Replies converge over each peer's next round; \
         owned-nodes and conferred duties fill in as they land."
    );
    PullOutcome::Dispatched {
        owner,
        peers,
        failures,
    }
}

/// **This node's own keys**, the caller's first, deduped: the key the caller
/// names, the wire identity (the NODE key on a split install) and the actor
/// identity. A read keyed on "this node's key" must fold over all of them — the
/// owner-binding moves to the node key at the split while the edge signer still
/// answers the actor (CIRISServer#632).
#[must_use]
pub fn own_keys(node_key_id: &str) -> Vec<String> {
    let mut own = vec![node_key_id.to_string()];
    for k in [
        crate::node_key::wire_identity(),
        crate::node_key::actor_identity(),
    ]
    .into_iter()
    .flatten()
    {
        if !own.iter().any(|o| o == k) {
            own.push(k.to_string());
        }
    }
    own
}

/// The bound owner of the first of `own` that has one.
pub async fn owner_of_any(engine: &Engine, own: &[String]) -> Option<String> {
    for k in own {
        if let Some(owner) = crate::auth::ownership::is_steward_bound(engine, k).await {
            return Some(owner);
        }
    }
    None
}

/// **The peers a receive-axis pull asks** — sorted, deduped, never one of `own`.
///
/// CIRISServer#601: this read was `list_consent_peers(node)`, which answers only
/// grants the MACHINE authored. Once a node is claimed its consent is authored
/// by the OWNER (consent is by humans, #599) and names the machine via
/// `for_key_id`, so every claimed node found "NO PEERS" and the owner's
/// testimony was never pulled. The peers now come from the same by-principals
/// read the replication runtime uses
/// ([`crate::peer::replication_peers_from_consent`] over
/// `consent_peers_by_principals`, revocation folded, person subjects resolved to
/// their bound nodes), unioned over every key this node is.
pub async fn peers_to_ask(engine: &Arc<Engine>, own: &[String]) -> Vec<String> {
    let mut peers: Vec<String> = Vec::new();
    for k in own {
        match crate::peer::replication_peers_from_consent(engine, k).await {
            Ok(found) => {
                for p in found {
                    if !own.contains(&p) && !peers.contains(&p) {
                        peers.push(p);
                    }
                }
            }
            // Not swallowed into "no peers": a failed read is a different fact.
            Err(e) => tracing::warn!(
                key_id = %k,
                error = %format!("{e:#}"),
                "receive-axis pull: consent peer read FAILED for this key — its peers are \
                 missing from the pull"
            ),
        }
    }
    peers.sort();
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four outcomes must stay DISTINCT. Collapsing "no owner" into "no peers"
    /// (or either into a bare `false`) is the exact shape that made the original
    /// bug invisible: an empty owned-nodes list read as "you own nothing" when the
    /// truth was "nothing was ever asked for".
    #[test]
    fn the_outcomes_are_four_distinguishable_facts() {
        let owner = "eric-moore-v2-portable".to_string();
        let all = [
            PullOutcome::NoOwner,
            PullOutcome::NoRuntime,
            PullOutcome::NoPeers {
                owner: owner.clone(),
            },
            PullOutcome::Dispatched {
                owner,
                peers: vec!["ciris-canonical-1".into()],
                failures: vec![],
            },
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(
                    i == j,
                    a == b,
                    "outcomes {i} and {j} must not compare equal"
                );
            }
        }
    }

    /// A dispatch that partially failed is still a dispatch, and must carry WHICH
    /// peers failed — a caller that only sees "dispatched" cannot retry the right
    /// half.
    #[test]
    fn a_partial_failure_names_the_peers_that_failed() {
        let o = PullOutcome::Dispatched {
            owner: "o".into(),
            peers: vec!["a".into(), "b".into()],
            failures: vec!["b: transport closed".into()],
        };
        match o {
            PullOutcome::Dispatched { failures, .. } => {
                assert_eq!(failures.len(), 1);
                assert!(failures[0].starts_with("b:"), "the failing peer is named");
            }
            _ => panic!("expected Dispatched"),
        }
    }
}
