//! **A canonical relays the devices people announced** (CC 5.4.6,
//! CIRISConstitution#111; CIRISServer#655).
//!
//! # The ruling
//!
//! *"A person is contactable through the nodes they chose to announce, and that
//! set IS their public roster."* Announce is per node: `POST
//! /v1/federation/announce` (this node) and `POST /v1/self/nodes/{id}/announce`
//! (another of the owner's nodes) widen that node's owner-binding to
//! `cohort_scope: federation`, and [`crate::auth::ownership::announced_nodes_of`]
//! is the one read of the result. The maintainer's ruling of 2026-09-30 adds the
//! other half: announced devices are discoverable by EVERYONE — the canonical
//! relays them.
//!
//! # The fault this closes
//!
//! Measured on the native harness (`harness/native/topologies/selffiles.yaml`):
//! person `one` owns D1 and D2, both announced; X — another person's node —
//! peers D1 and the canonical C. X's `GET /v1/self/occurrences?identity_key_id=
//! <one>` listed ONE of `one`'s two devices. C held D2's key record and
//! occurrence, and offered neither: the three `SelfOwn` planes (`Key`,
//! `IdentityOccurrence`, `TransportDestination`) advertise only the subjects in
//! the node's self-publish set, and C's self set is C (plus its owner, if it
//! has one). A person's roster was complete only for a reader that happened to
//! peer every one of their devices directly — "contactable through the nodes
//! they announced" held for nobody who had not already met them.
//!
//! # The switch edge built for this
//!
//! Edge v34.0.0 (CIRISEdge#678) gave the host a per-kind publish set for the
//! `SelfOwn` planes — `ReplicationRuntimeConfig::kind_publish_selector`, read
//! by the bridge's `self_own_subjects(kind)`. `Some(set)` REPLACES the
//! self-publish set for that plane; `None` leaves the plane on it. What the
//! set names is the SUBJECT of the row, not its attester: the Key plane keeps a
//! record whose `key_id` is in the set, the IdentityOccurrence plane an
//! occurrence whose `occurrence_key_id` is. Neither plane consults the
//! recipient's reach — CIRISEdge#671's first-contact rule lives on the
//! Attestation plane (`bridge.rs` `reach_withholds`) — so a set installed here
//! reaches an unconsented, Attributed-stranger peer exactly as it reaches a
//! consented one. The IdentityOccurrence plane then runs CIRISEdge#682's
//! announce gate per subject (`identity_rows_withheld_from`), which serves an
//! owned node's occurrence to everyone only when that node is announced: the
//! set below and edge's gate are the same predicate from two sides, and a
//! node that drops out of one drops out of the other.
//!
//! # What is relayed — and the four things that never are
//!
//! - **`Key`**: this node's own publish set ∪ every announced node ∪ each such
//!   node's OWNER. The owner's key record is not optional: a reader verifies
//!   the occurrence (signed by the identity) and the owner-binding (authored by
//!   the owner) against it, and without it the device list is a list of rows
//!   the reader must refuse.
//! - **`IdentityOccurrence`**: this node's own publish set ∪ every announced
//!   node. NOT the owners: an occurrence subject is an occurrence key, and a
//!   person key as a subject would be a row about the person rather than one of
//!   their announced devices.
//! - **`TransportDestination`**: `None` — the self-publish set, untouched.
//!   Routes are not relayed; the contact code carries them, to the person the
//!   owner chose to give it to.
//! - **Every other plane**: `None`. Edge consults the selector only for the
//!   three `SelfOwn` planes, and this module answers `None` for everything
//!   else as well, so a later edge that widened the consultation would not
//!   inherit a relay nobody decided on. Consent grants, self-scoped rows and
//!   the owner-binding itself ride the Attestation plane under its own gates.
//! - **An unannounced node**: never, on any plane. Announce is per node and
//!   the person's other choices do not leak onto it.
//!
//! # What this does NOT carry — the owner-binding
//!
//! A reader's public roster (`GET /v1/self/occurrences`) shows an occurrence
//! only if the reader's OWN directory says the node is announced
//! (`announced_nodes_of`), and that is read from the owner-binding
//! `delegates_to(owner → node)` at `federation` — an Attestation-plane row the
//! selector is never consulted for. Toward an Attributed stranger that plane is
//! CIRISEdge#671's first-contact reach, which carries "this node's allegiance
//! facts" only: `attestation_is_allegiance_fact` (edge v36.1.0
//! `replication/bridge.rs:6031-6039`) requires the row's attester to be in THIS
//! node's self-publish set, so a canonical never relays a third party's
//! owner-binding to an unconsented peer (`reach_withholds`, `bridge.rs:6114`,
//! "the recipient is an Attributed stranger (first contact)"). A device of the
//! owner DOES pass it — the owner is in that device's self set — so an outsider
//! that peers ANY one of the person's devices learns every binding that device
//! holds, and this relay supplies the key records and occurrences behind them.
//! An outsider that peers the canonical and none of the person's devices gets
//! the rows but not the binding; closing that is edge's first-contact rule to
//! widen, not a server set.
//!
//! # Who relays
//!
//! The ruling says "the canonical". A node knows it serves infrastructure when
//! it holds `infra:serve` from a root it trusts —
//! `capability_roots_to_trusted_root(me, me, infra:serve)`, persist's
//! composed capability walk (the same leg B the trace serve gate asks about a
//! recipient, asked here about ourselves). That is exactly what genesis
//! requires of a serve node (`mesh_genesis`: a serve node must carry an
//! `infra:serve` grant from the charter root) and what the test-anchor bless
//! writes (`test_bless::has_capability_grant`). Every other node answers
//! `None` for every plane and is byte-for-byte the pre-#678 behaviour. The
//! predicate is re-asked on every refresh, so a canonical blessed after boot
//! starts relaying without a restart, and one whose grant is withdrawn stops.
//!
//! # Cost, and where it is paid
//!
//! The selector closure runs inside edge's sweep, once per plane per round per
//! peer; it reads a snapshot behind a lock and never touches the database.
//! The snapshot is recomputed OFF the sweep, by the publish-own updater in
//! `compose` — the loop that already keeps the self-publish set current —
//! every [`RELAY_REFRESH`], and immediately when [`nudge`] fires (every
//! `kick_replication`: an announce, a release, an eviction, a claim). An
//! announce made on ANOTHER node reaches this one as an inbound row, which
//! nothing kicks on; the period bounds that lag.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use ciris_edge::replication::bridge::KindPublishSelector;
use ciris_edge::replication::EnvelopeKind;
use ciris_persist::prelude::Engine;

/// How often the relay set is recomputed when nothing nudges it. Announce is
/// rare and every local change nudges; this bounds only the lag of an announce
/// made on another node and carried here by replication.
pub const RELAY_REFRESH: Duration = Duration::from_secs(60);

/// Page size for the occurrence enumeration. The same default the bridge's
/// since-cursor sweeps use.
const OCCURRENCE_PAGE: u32 = 1024;

/// Hard stop on the enumeration — 4096 pages × 1024 rows, far above any real
/// corpus and far below "forever" (the same bound edge puts on a `Full`
/// drain, CIRISEdge#531). Hitting it truncates the relay for one pass, loudly.
const MAX_OCCURRENCE_PAGES: usize = 4096;

/// The relay sets, computed off the hot path. Sorted and deduplicated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelaySets {
    /// Every node whose owner-binding is live at `federation` scope — the
    /// devices people announced.
    pub announced_nodes: Vec<String>,
    /// The owners of those nodes (their key records verify the occurrence and
    /// the binding on the reader's side).
    pub owners: Vec<String>,
}

impl RelaySets {
    /// Nothing to relay.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.announced_nodes.is_empty() && self.owners.is_empty()
    }
}

/// **THE selection** — what one `SelfOwn` plane publishes, given this node's
/// own publish set and the relay snapshot. Pure, so the privacy negatives are
/// testable without a runtime.
///
/// `relay == None` (not a relay, or not computed yet) answers `None` for every
/// kind, which edge reads as "the self-publish set": the pre-#678 behaviour.
/// The answer REPLACES the self set for its kind (edge's contract), so it is
/// always `own ∪ relayed` — a relay that forgot to include itself would stop
/// publishing its OWN key record.
#[must_use]
pub fn selection_for(
    kind: EnvelopeKind,
    own: &[String],
    relay: Option<&RelaySets>,
) -> Option<Vec<String>> {
    let relay = relay?;
    let relayed: Vec<&String> = match kind {
        EnvelopeKind::Key => relay
            .announced_nodes
            .iter()
            .chain(relay.owners.iter())
            .collect(),
        EnvelopeKind::IdentityOccurrence => relay.announced_nodes.iter().collect(),
        // Routes stay on the self set: the contact code carries them. Every
        // other kind is not ours to answer (see the module docs).
        _ => return None,
    };
    let mut set: BTreeSet<String> = own.iter().cloned().collect();
    set.extend(relayed.into_iter().cloned());
    Some(set.into_iter().collect())
}

/// The shared snapshot the selector closure reads. `None` = not relaying.
type Snapshot = Arc<RwLock<Option<Arc<RelaySets>>>>;

/// This process's relay state: the snapshot, and the wake-up the refresh
/// waits on.
struct RelayState {
    snapshot: Snapshot,
    wake: tokio::sync::Notify,
}

static STATE: OnceLock<RelayState> = OnceLock::new();

fn state() -> &'static RelayState {
    STATE.get_or_init(|| RelayState {
        snapshot: Arc::new(RwLock::new(None)),
        wake: tokio::sync::Notify::new(),
    })
}

/// The selector compose installs on the ONE replication runtime. It reads the
/// live self-publish set (`own`, the same `RwLock` the `self_provider` reads,
/// so the owner admitted after a claim is in the union the moment they are in
/// the self set) and this module's snapshot. No I/O: two read locks and a
/// clone.
#[must_use]
pub fn selector(own: Arc<RwLock<Vec<String>>>) -> KindPublishSelector {
    selector_over(own, Arc::clone(&state().snapshot))
}

fn selector_over(own: Arc<RwLock<Vec<String>>>, snapshot: Snapshot) -> KindPublishSelector {
    KindPublishSelector::new(move |kind| {
        // Cheap exit for the planes we never answer, before any lock.
        if !matches!(kind, EnvelopeKind::Key | EnvelopeKind::IdentityOccurrence) {
            return None;
        }
        let relay = snapshot.read().ok().and_then(|s| s.clone())?;
        let own = own.read().map(|o| o.clone()).unwrap_or_default();
        selection_for(kind, &own, Some(&relay))
    })
}

/// A selector over a caller-held snapshot, for in-process tests that build a
/// bridge by hand rather than through compose.
#[must_use]
pub fn selector_for_sets(own: Vec<String>, relay: Option<RelaySets>) -> KindPublishSelector {
    selector_over(
        Arc::new(RwLock::new(own)),
        Arc::new(RwLock::new(relay.map(Arc::new))),
    )
}

/// Ask for a recompute now. Called from `kick_replication`, so an announce, a
/// release or a claim on THIS node moves the relay on the same round rather
/// than the next [`RELAY_REFRESH`]. Coalesced: a burst of kicks is one pass.
pub fn nudge() {
    state().wake.notify_one();
}

/// Wait for a nudge, at most `period`. The publish-own updater's sleep.
pub(crate) async fn wait_for_nudge(period: Duration) -> bool {
    tokio::time::timeout(period, state().wake.notified())
        .await
        .is_ok()
}

/// Does this node serve infrastructure — does any key that is "us" hold
/// `infra:serve` from a root that key itself trusts? See the module docs for
/// why this is the predicate for "the canonical". A read failure answers
/// `false`: a node that cannot establish it is a relay does not start
/// publishing third parties' records on a guess.
pub async fn serves_infrastructure(engine: &Engine, own_key_ids: &[String]) -> bool {
    use ciris_persist::federation::trust_root::{
        capability_roots_to_trusted_root, INFRA_SERVE_SCOPE,
    };
    let dir = engine.federation_directory();
    for k in own_key_ids {
        match capability_roots_to_trusted_root(dir.as_ref(), k, k, INFRA_SERVE_SCOPE).await {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(e) => tracing::debug!(
                key_id = %k,
                error = %format!("{e:#}"),
                "announced relay: could not walk this key's infra:serve capability — \
                 treated as not held"
            ),
        }
    }
    false
}

/// **Every announced node this directory knows, and their owners.**
///
/// Enumerated from the signed IdentityOccurrence plane — the rows a roster is
/// made of — rather than from the attestation log, which on a canonical is
/// orders of magnitude larger: each distinct `identity_key_id` is a person who
/// has devices here, and [`crate::auth::ownership::announced_nodes_of`] (the
/// one read the roster endpoint also uses) answers which of their nodes they
/// announced. A node announced by someone with no signed occurrence here has
/// no roster row here to relay either; its absence is the correct answer.
///
/// # Errors
/// The directory could not be read. A partial answer is never returned: a
/// relay built from half a corpus would silently drop people.
pub async fn announced_relay_sets(engine: &Engine) -> Result<RelaySets, String> {
    let dir = engine.federation_directory();
    let mut identities: BTreeSet<String> = BTreeSet::new();
    let mut since: Option<(chrono::DateTime<chrono::Utc>, String)> = None;
    let mut pages = 0usize;
    loop {
        let page = dir
            .list_signed_identity_occurrences_since(since.clone(), OCCURRENCE_PAGE)
            .await
            .map_err(|e| format!("list_signed_identity_occurrences_since: {e:#}"))?;
        let short = page.len() < OCCURRENCE_PAGE as usize;
        for row in &page {
            identities.insert(row.occurrence.identity_occurrence.identity_key_id.clone());
        }
        let next = page
            .last()
            .map(ciris_persist::federation::ServedIdentityOccurrence::resume_pair);
        pages += 1;
        if short || next.is_none() || next == since {
            break;
        }
        if pages >= MAX_OCCURRENCE_PAGES {
            tracing::warn!(
                pages,
                "announced relay: occurrence enumeration hit its page bound — the relay set \
                 for this pass is TRUNCATED (CIRISEdge#531 bound)"
            );
            break;
        }
        since = next;
    }
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut owners: BTreeSet<String> = BTreeSet::new();
    for identity in identities {
        let announced = crate::auth::ownership::announced_nodes_of(engine, &identity).await?;
        if announced.is_empty() {
            continue;
        }
        owners.insert(identity);
        nodes.extend(announced);
    }
    Ok(RelaySets {
        announced_nodes: nodes.into_iter().collect(),
        owners: owners.into_iter().collect(),
    })
}

/// One refresh pass: decide whether this node relays, recompute the sets if
/// it does, and publish the snapshot. Returns whether the snapshot CHANGED, so
/// the caller can kick a round on a real transition and stay quiet otherwise.
///
/// `recheck_role` re-asks [`serves_infrastructure`]. The periodic pass does;
/// a [`nudge`] does not, because a nudge fires on every `kick_replication` —
/// every chat row — and on the nodes that are NOT relays (nearly all of them)
/// a nudge must cost nothing: with no snapshot and no recheck this returns
/// before touching the database. A relay recomputes its sets on every nudge;
/// that is the node the recompute is for.
///
/// Logs its own cost: every periodic pass on this node must (the 15-minute
/// read-API stall was a pass nobody had timed).
pub async fn refresh(engine: &Engine, own_key_ids: &[String], recheck_role: bool) -> bool {
    let relaying = state()
        .snapshot
        .read()
        .map(|s| s.is_some())
        .unwrap_or(false);
    if !recheck_role && !relaying {
        return false;
    }
    let started = std::time::Instant::now();
    let serves = if recheck_role {
        serves_infrastructure(engine, own_key_ids).await
    } else {
        relaying
    };
    let next: Option<Arc<RelaySets>> = if serves {
        match announced_relay_sets(engine).await {
            Ok(sets) => Some(Arc::new(sets)),
            Err(e) => {
                // Keep the previous snapshot: a read failure is not "nobody
                // announced anything", and flapping the relay off and on with
                // the store would withdraw every person's roster for a pass.
                tracing::warn!(
                    error = %e,
                    "announced relay: could not enumerate announced nodes — keeping the \
                     previous relay set"
                );
                return false;
            }
        }
    } else {
        None
    };
    let elapsed = started.elapsed();
    let snapshot = &state().snapshot;
    let changed = {
        let Ok(mut w) = snapshot.write() else {
            return false;
        };
        let changed = w.as_deref() != next.as_deref();
        if changed {
            *w = next.clone();
        }
        changed
    };
    if changed {
        match &next {
            Some(s) => tracing::info!(
                announced_nodes = s.announced_nodes.len(),
                owners = s.owners.len(),
                elapsed_ms = elapsed.as_millis() as u64,
                "announced relay: this node serves infrastructure and now relays the Key and \
                 IdentityOccurrence rows of every announced device and its owner (CC 5.4.6, \
                 CIRISServer#655) — routes are not relayed"
            ),
            None => tracing::info!(
                elapsed_ms = elapsed.as_millis() as u64,
                "announced relay: OFF — this node holds no infra:serve from a root it trusts; \
                 its SelfOwn planes publish only its own set"
            ),
        }
    } else if elapsed > Duration::from_secs(1) {
        tracing::warn!(
            elapsed_ms = elapsed.as_millis() as u64,
            "announced relay: a refresh pass took over a second"
        );
    } else {
        tracing::debug!(
            elapsed_ms = elapsed.as_millis() as u64,
            "announced relay: refresh pass, unchanged"
        );
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    fn relay() -> RelaySets {
        RelaySets {
            announced_nodes: s(&["d2"]),
            owners: s(&["one"]),
        }
    }

    #[test]
    fn not_a_relay_answers_none_for_every_kind() {
        for kind in EnvelopeKind::ALL {
            assert_eq!(selection_for(kind, &s(&["me"]), None), None, "{kind:?}");
        }
    }

    #[test]
    fn key_plane_is_own_plus_announced_nodes_plus_their_owners() {
        assert_eq!(
            selection_for(EnvelopeKind::Key, &s(&["me", "my-owner"]), Some(&relay())),
            Some(s(&["d2", "me", "my-owner", "one"]))
        );
    }

    #[test]
    fn occurrence_plane_is_own_plus_announced_nodes_never_the_person() {
        let got = selection_for(
            EnvelopeKind::IdentityOccurrence,
            &s(&["me"]),
            Some(&relay()),
        )
        .expect("relayed");
        assert_eq!(got, s(&["d2", "me"]));
        assert!(
            !got.contains(&"one".to_owned()),
            "a person key is never an occurrence subject"
        );
    }

    /// Routes, and every plane edge does not consult, stay on the self set —
    /// including the Attestation plane, which carries consent grants and every
    /// self-scoped row.
    #[test]
    fn routes_and_every_other_plane_are_never_relayed() {
        for kind in EnvelopeKind::ALL {
            if matches!(kind, EnvelopeKind::Key | EnvelopeKind::IdentityOccurrence) {
                continue;
            }
            assert_eq!(
                selection_for(kind, &s(&["me"]), Some(&relay())),
                None,
                "{kind:?} must stay on the self-publish set"
            );
        }
    }

    /// The closure reads the LIVE self set: an owner admitted after the
    /// selector was built is in the union without a rebuild.
    #[test]
    fn the_selector_unions_the_live_self_set() {
        let own = Arc::new(RwLock::new(s(&["me"])));
        let snap: Snapshot = Arc::new(RwLock::new(Some(Arc::new(relay()))));
        let sel = selector_over(Arc::clone(&own), Arc::clone(&snap));
        assert_eq!(sel.select(EnvelopeKind::Key), Some(s(&["d2", "me", "one"])));
        own.write().unwrap().push("my-owner".into());
        assert_eq!(
            sel.select(EnvelopeKind::Key),
            Some(s(&["d2", "me", "my-owner", "one"]))
        );
        assert_eq!(sel.select(EnvelopeKind::TransportDestination), None);
        *snap.write().unwrap() = None;
        assert_eq!(sel.select(EnvelopeKind::Key), None, "relay off = self set");
    }
}
