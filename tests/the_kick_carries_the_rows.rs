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

/// Read a source file with LINE ENDINGS NORMALISED.
///
/// Every scan in this file looks for shapes that span lines — a needle
/// containing `\n`, a `"\n}"` to find where a function body ends. On Windows
/// git checks the tree out with CRLF, so those needles match nothing and the
/// gate fails with "expected to find …" against source that is perfectly
/// correct. That is what happened: three lanes green, windows-latest red, on a
/// property that holds on every platform.
///
/// Normalising here rather than in each test, because the next scan added to
/// this file will have the same problem and will not remember.
fn read_src(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// THE KICK ITSELF ADMITS THE OWNER — one place, no call site to forget.
///
/// This test used to assert an ORDER between two statements in the announce
/// handler: admit, then kick. That was true and unkeepable. The announce
/// handler spelled it; the fold's post-claim author door
/// (`federation_delivery`) did not, and authored the heal, the owner anchor and
/// the migrated grants before kicking against a set that still held only the
/// node key. A call site cannot tell whether the rows it just wrote are
/// owner-attested, so the ordering does not belong to call sites.
///
/// So the property is now structural: `kick_replication` refreshes the
/// publish-own set inside its own task, before `round_now_all`. Every kick
/// carries the owner's rows whether or not its author thought about it, and the
/// assertion is about one function instead of N handlers.
#[test]
fn the_kick_admits_the_owner_before_it_rounds() {
    let src = read_src("src/compose.rs");
    let start = src
        .find("pub(crate) fn kick_replication(")
        .expect("kick_replication must exist");
    let body = &src[start..];
    let end = body.find("\n}\n").map_or(body.len(), |j| j + 2);
    let body = &body[..end];

    let admit = body.find("refresh_publish_own_set").expect(
        "kick_replication must refresh the publish-own set itself — a round publishes a \
             self-plane row only if its attester is in that set, and the owner is resolvable \
             only after the claim. Pushing this back out to the callers is what left the \
             fold's author door kicking against a node-only set.",
    );
    let round = body
        .find("round_now_all")
        .expect("kick_replication must still round");
    assert!(
        admit < round,
        "the owner must be admitted BEFORE the round is requested (admit at {admit}, round at \
         {round}) — a round selects its rows against the set as it stands when it starts"
    );
}

/// The poll still carries a gain, and a kick it could not dispatch stays owed.
///
/// The kick admits the owner itself now, but the poll is still the only thing
/// that NOTICES an owner arriving by a door that does not kick (a re-rooted
/// ownership, a claim landing elsewhere). Two failure modes, both seen:
///
/// * silent gain — the set grew and nothing carried what it unlocked until some
///   unrelated round happened by;
/// * a lost kick — the updater is spawned from inside `RUNTIME.get_or_try_init`,
///   so at startup it can gain the owner while the runtime is still
///   unpublished. The kick then returns false, and because the owner is now IN
///   the set, no later poll sees a gain to retry. Permanently lost, on the nodes
///   that were readiest.
///
/// Asserted as three facts rather than a brace window, since the same refresh
/// call appears in `kick_replication` too and a positional scan matched the
/// wrong one.
#[test]
fn the_publish_own_poll_carries_a_gain_and_retries_a_lost_kick() {
    let src = read_src("src/compose.rs");
    for (needle, why) in [
        (
            "if refresh_publish_own_set(held).await {\n                        owed = true;",
            "a GAIN must record a debt — an unconditional kick every 30s is a round per tick \
             forever, and no kick at all leaves the owner's rows unadvertised",
        ),
        (
            "if owed && kick_replication(",
            "the debt must be paid by an actual kick, and cleared only when that kick \
             reports it dispatched",
        ),
        (
            "let wait = if owed { 1 } else { 30 };",
            "an owed kick must be retried PROMPTLY — sleeping the full cadence before the \
             retry leaves exactly the delay this exists to remove",
        ),
    ] {
        assert!(
            src.contains(needle),
            "{why}\n\nexpected to find: {needle:?}"
        );
    }
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
    let src = read_src("src/backend.rs");
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
        let src = read_src(file);
        assert!(
            src.contains("note_convergence"),
            "{what} ({file}) drives reconcile_once, so it must record the converged set \
             through `note_convergence` — the one place that diffs the set and kicks on a \
             gain. Deciding locally is how this broke: the embedded path reconciled, gained \
             a peer, and carried nothing."
        );
    }
    let recon = read_src("src/replication_reconcile.rs");
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
