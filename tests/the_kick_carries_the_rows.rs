//! **A kick must carry the rows its reason names** (CIRISEdge#636 follow-ups).
//!
//! # The shape
//!
//! `compose::kick_replication` rounds toward every peer NOW instead of at the
//! next 30s cadence tick. It is called from handlers that just authored
//! something, and each call passes a `reason` string naming what it is carrying.
//!
//! The failure this gates is that the reason can be true while the round is
//! empty. A round publishes a self-plane row only if the row's attester is in
//! the publish-own set, and the rows an ANNOUNCE exists to cross — the
//! owner-binding `delegates_to(user → node)` and the owner's occurrences — are
//! attested by the OWNER, who is resolvable only after the claim. So an
//! announce that kicks before admitting the owner rounds toward every peer
//! carrying none of the rows it says it is carrying, and the binding waits for
//! the poll that admits the owner (measured: +41s on the v26.1.0 chat ladder,
//! one full cadence after a kick that had already "succeeded").
//!
//! Nothing fails when this regresses. The kick logs success, the rows are held
//! locally, the peers are reachable, and the only symptom is that `bound`
//! arrives a cadence late — which reads as ordinary mesh latency.
//!
//! # Why a source gate
//!
//! The property is an ORDER between two statements in one handler. A behavioural
//! test would need a two-node mesh with a real transport and would then be
//! asserting on a timing difference — exactly the kind of test that goes flaky
//! and gets deleted. The order is cheap to read and cheap to keep.

/// The announce handler admits the owner into the publish-own set BEFORE it
/// kicks — not after, and not only via the 30s poll.
#[test]
fn announce_admits_the_owner_before_it_kicks() {
    let src = std::fs::read_to_string("src/claim_remote.rs").expect("read src/claim_remote.rs");
    let admit = src.find("publish_own_set_admit_owner").expect(
        "the announce path must admit this node's owner into the publish-own set; \
                 without it the kick below rounds toward every peer carrying none of the \
                 owner-attested rows the announce exists to cross",
    );
    let kick = src
        .find(r#"kick_replication("owner-binding announced")"#)
        .expect("the announce path must still kick");
    assert!(
        admit < kick,
        "publish_own_set_admit_owner must come BEFORE kick_replication in the announce \
         handler (found admit at {admit}, kick at {kick}). Kicking first is not a \
         smaller version of the fix — it is the bug: the round is selected against the \
         publish-own set as it stands AT THE KICK."
    );
}

/// The poll that admits the owner kicks when it actually gains them.
///
/// The announce path is not the only way an owner appears (a re-rooted
/// ownership, a claim that lands by another door), so the task that notices is
/// the task that must round. Silent-gain was the original defect: the set grew
/// and nothing carried what it unlocked until the next unrelated tick.
#[test]
fn the_publish_own_poll_kicks_when_the_set_gains_the_owner() {
    let src = std::fs::read_to_string("src/compose.rs").expect("read src/compose.rs");
    let refresh = src
        .find("if refresh_publish_own_set(&engine, &node, &keys).await {")
        .expect(
            "the publish-own updater must branch on whether the set actually GAINED the \
             owner — an unconditional kick every 30s is a round per tick forever, and no \
             kick at all leaves the owner's rows unadvertised until something else rounds",
        );
    let tail = &src[refresh..];
    let kick = tail
        .find("kick_replication")
        .expect("the publish-own updater must kick when it gains the owner");
    assert!(
        kick < tail.find("\n            }").unwrap_or(usize::MAX),
        "the kick must be INSIDE the gained-the-owner branch"
    );
}

/// The community-DEK binding is read from whichever store the node has.
///
/// Here for the same reason as the two above: a door that only one half of the
/// deployments can walk is dark for the other half and says nothing about it.
/// `community_dek_blob_epoch` is the reader that makes a community blob
/// servable when this node does not hold the citing row, and reaching for
/// `sqlite_backend()` alone made the whole path dead on a Postgres node —
/// persist's `postgres` feature is unioned in on Linux, which is the
/// deployment shape.
#[test]
fn the_dek_binding_is_read_from_both_backends() {
    let src = std::fs::read_to_string("src/backend.rs").expect("read src/backend.rs");
    let start = src
        .find("async fn dek_binding(")
        .expect("ServerBlobChunkSource must resolve the community-DEK binding in one place");
    let body = &src[start..];
    let end = body.find("\n    }").unwrap_or(body.len());
    let body = &body[..end];
    for backend in ["postgres_backend", "sqlite_backend"] {
        assert!(
            body.contains(backend),
            "dek_binding must consult `{backend}` — a blob whose binding cannot be read \
             falls through to the referencing-row arm, which answers only for rows this \
             node happens to hold, so the serve is silently withheld on half the \
             deployment shapes"
        );
    }
}

/// BOTH loops that drive `reconcile_once` carry a gain.
///
/// There are two, and which one runs depends on how the process was started: a
/// composed node runs `replication_reconcile::spawn`, and a bare embedded agent
/// reaches delivery only through `run_federation_delivery` and never runs
/// compose's controller at all. A kick written into one of them is not "the
/// kicker for this node" — it is the kicker for half the ways a node can exist,
/// and the first revision of this fix did exactly that, with a comment
/// asserting the other loop would handle it.
///
/// So the property is not "someone kicks" but "neither caller decides for
/// itself": both must route through `note_convergence`, which owns the diff and
/// the kick. A second implementation that happens to be correct today is the
/// shape that forked last time.
#[test]
fn both_reconcile_loops_route_through_one_decision() {
    for (file, what) in [
        (
            "src/replication_reconcile.rs",
            "the composed node's controller",
        ),
        (
            "src/federation_delivery.rs",
            "the agent-embedded delivery controller",
        ),
    ] {
        let src = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file}: {e}"));
        assert!(
            src.contains("note_convergence"),
            "{what} ({file}) drives reconcile_once, so it must record the converged set \
             through `note_convergence` — the one place that diffs the set and kicks on a \
             gain. Deciding locally is how this broke: the embedded path reconciled, gained \
             a peer, and carried nothing."
        );
    }
    let recon = std::fs::read_to_string("src/replication_reconcile.rs").expect("read");
    let body_start = recon
        .find("pub fn note_convergence(")
        .expect("note_convergence must exist");
    let body = &recon[body_start..];
    let end = body.find("\n}").unwrap_or(body.len());
    assert!(
        body[..end].contains("kick_replication"),
        "note_convergence must be where the kick happens; if the kick moves back out to the \
         callers, the two of them are free to disagree again"
    );
}
