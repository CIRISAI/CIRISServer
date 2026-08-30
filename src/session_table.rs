//! # The session table — which occurrence of my self is handling what
//!
//! A **self** is a fed identity plus the N nodes it stewards — its *occurrences*.
//! An attestation addressed to a fed id fans out to every one of them (a fed id
//! has no transport path of its own; see [`crate::key_convention`]). Exactly one
//! occurrence may act on it. This module is how that is decided.
//!
//! # It is a NAT table, not a leader election
//!
//! The first cut of this modelled ONE handler per self, and that is wrong. A self
//! is doing several things at once, on different nodes, on purpose:
//!
//! ```text
//!   my self (one fed id, four occurrences)
//!     ├── node 1  agent "scout"          ── session x ──▶ community A
//!     ├── node 2  agent "echo"           ── session y ──▶ community A
//!     ├── node 3  me, chatting           ── session z ──▶ community B
//!     └── node 4  me, on video           ── session a ──▶ community B
//! ```
//!
//! Four occurrences, four live sessions, two communities, all at once and all
//! legitimately mine. So the claim is keyed by [`SessionKey`] —
//! `(community, session)` — and resolves to the occurrence handling THAT session,
//! exactly as a NAT table maps a flow rather than a host. "Which node is my
//! self?" is not a question with an answer; "which node is handling session z in
//! community B?" is.
//!
//! # The two primitives
//!
//! 1. **Things to claim.** An addressed attestation arrives at every occurrence
//!    with no owner — the mesh equivalent of CIRISAgent's `__shared__` partition,
//!    which its occurrences transfer to themselves with `transfer_task_ownership`.
//! 2. **Clearing claims.** A claim is published, renewed, and released on the CEG
//!    **self tier**, which is built precisely for this: `receive_axis` records
//!    that `projection_for` maps self/family to `Projection::SelfOwn` —
//!    publish-own, advertised by nobody — so a subject-initiated pull
//!    (`pull_subject_testimony`) "is not an optimization there; it is the only
//!    mechanism that can exist". Each occurrence publishes its OWN claims and
//!    pulls its siblings'. No occurrence ever asserts a claim on another's behalf.
//!
//! # I6 — An unclaimed attestation is not acted on. Ever.
//!
//! Not by a quorum, not by the lowest id, and **not by a single-node self**. If
//! nothing here is attended by a human or an agent, the correct behaviour is to
//! leave the attestation unhandled and say so. Being the only occurrence confers
//! no authority to act; it just means there is one place where nobody is home.
//! [`Attendance`] therefore has no "unclaimed" variant — an unattended occurrence
//! is absent from the table rather than present with a weak claim, so there is no
//! value that could be silently promoted into a right to act.
//!
//! # Why the agent's mechanism does not port
//!
//! CIRISAgent's occurrences share ONE database — the config says so outright,
//! "enables multiple instances against same database" — so its claim is an atomic
//! DB operation (`task_try_claim_shared`, create-if-not-exists). Mesh occurrences
//! each hold their own persist DB and reconcile by replication; there is no
//! compare-and-swap across them. Porting the transfer verbatim would import a race
//! already latent upstream: `transfer_task_ownership` reads the row, checks it
//! still says `__shared__`, then upserts — two occurrences can both read, both
//! pass, and both write. In one process that window is narrow; under replication
//! lag it is the normal case.
//!
//! # The table replicates BETWEEN selves, not just within one
//!
//! Ownership of a session has to be legible to both parties, or the sender
//! cannot tell a considered silence from a dropped message. So claims replicate
//! on two paths, and they are not the same path:
//!
//! - **Within my self** — sibling occurrences learn my claims on the CEG self
//!   tier. `Projection::SelfOwn` means nobody advertises those rows, so they move
//!   only by subject-initiated pull (`pull_subject_testimony`, fail-closed to the
//!   subject). My occurrences qualify; a peer never does.
//! - **Between selves** — the peer learns who owns the session from a
//!   COMMUNITY-scoped claim, replicated under the same directed-consent grant
//!   that already carries the conversation.
//!
//! The second path has a failure mode worth stating, because this codebase has
//! already been bitten by it. `consent:replication:v1` grants cover PREFIXES, and
//! `contacts_chat` records what happens when a prefix is missing: a peer you had
//! already federated with held a grant covering `capacity:`/`trace:` only, so
//! `chat:` rows stayed ineligible and "the people you know best were exactly the
//! people you could not message" — with every call reporting success. A claim on
//! [`SESSION_ATTESTATION_PREFIX`] that is not in the grant replicates to nobody,
//! silently, and the visible symptom is not an error but a peer who appears to be
//! ignoring you. Any surface emitting claims must add the prefix through
//! `peer::ensure_contact_consent_covers` exactly as chat does, never assume it.
//!
//! So concurrent claims are treated as expected rather than prevented, and
//! [`SessionTable::resolve`] settles them with a rule every occurrence computes
//! identically — earliest claim wins, ties broken on the lowest occurrence id.
//! Convergent without coordination. Handling must still be idempotent per
//! attestation id: determinism only bites once views agree, and replication lag
//! means they transiently do not.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// Which conversation, in which community. The NAT-table key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey {
    /// The community the session belongs to.
    pub community_id: String,
    /// The session within it.
    pub session_id: String,
}

impl SessionKey {
    /// Build a key.
    pub fn new(community_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            community_id: community_id.into(),
            session_id: session_id.into(),
        }
    }
}

/// Who is attending an occurrence — the only two things that confer a right to
/// act.
///
/// There is deliberately no `Unattended` variant. An occurrence with nobody home
/// holds no claim and appears nowhere in the table; absence is the encoding. A
/// third variant would be a value that looks claim-shaped and could be promoted
/// into one by a careless comparison, which is exactly what I6 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attendance {
    /// An agent is running here and is attending this session.
    Agent,
    /// A human holds a live session here.
    Human,
}

/// One row: this session is being handled by this occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The occurrence's NODE key id — its address, and the tie-break key.
    pub occurrence_key_id: String,
    /// Who is attending it.
    pub attended_by: Attendance,
    /// When the claim was first taken. The primary conflict-resolution key, so
    /// it must NOT be advanced by a renewal.
    pub claimed_at: DateTime<Utc>,
    /// Last heartbeat. A claim that stops being renewed becomes claimable again,
    /// or a node that dies holds its sessions forever.
    pub renewed_at: DateTime<Utc>,
}

/// How long a claim survives without renewal.
///
/// Generous: reclaiming from a live-but-quiet occurrence produces two handlers
/// for one session, which is worse than a late reply.
pub const CLAIM_TTL_SECS: i64 = 900;

/// The CEG dimension a session claim is published under.
///
/// Versioned (`:v1`) because persist's `DimensionAdmissionPolicy` refuses any
/// `scores`/attestation dimension without a `:vN` segment
/// (`MissingVersionSegment`), and because the shape of a claim is exactly the
/// kind of thing that gets a v2.
pub const SESSION_CLAIM_DIMENSION: &str = "session:claim:v1";

/// The consent prefix a session claim replicates under.
///
/// A grant that does not carry this prefix drops every claim silently — see the
/// module note. Deliberately NOT `chat:`: claims govern any addressed session,
/// and scoping them to chat would leave video, moderation, and claim flows with
/// no ownership signal at all.
pub const SESSION_ATTESTATION_PREFIX: &str = "session:";

/// What a claim attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The session was unclaimed (or the prior claim had gone stale) and is now
    /// ours.
    Claimed,
    /// We already held it; the heartbeat was refreshed.
    Renewed,
    /// Someone else holds it. Their id, so the caller can say who.
    HeldBy(String),
}

/// The table of live session claims across the occurrences of one self.
#[derive(Debug, Clone, Default)]
pub struct SessionTable {
    rows: HashMap<SessionKey, Claim>,
}

impl SessionTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Is this claim still live at `now`?
    #[must_use]
    fn is_live(claim: &Claim, now: DateTime<Utc>) -> bool {
        claim.renewed_at >= now - Duration::seconds(CLAIM_TTL_SECS)
    }

    /// **Primitive 1 — claim a thing.**
    ///
    /// Takes the session if it is unheld or the holder has gone stale; renews if
    /// it is already ours; otherwise reports who holds it. `attended_by` is
    /// required, which is I6 expressed in the type: there is no way to claim a
    /// session with nobody home.
    pub fn try_claim(
        &mut self,
        session: SessionKey,
        me: &str,
        attended_by: Attendance,
        now: DateTime<Utc>,
    ) -> ClaimOutcome {
        match self.rows.get_mut(&session) {
            Some(existing) if existing.occurrence_key_id == me && Self::is_live(existing, now) => {
                existing.renewed_at = now;
                existing.attended_by = attended_by;
                ClaimOutcome::Renewed
            }
            Some(existing) if Self::is_live(existing, now) => {
                ClaimOutcome::HeldBy(existing.occurrence_key_id.clone())
            }
            // Absent, or present but stale: ours. `claimed_at` restarts, because
            // this is a new claim and not a continuation of the dead one.
            _ => {
                self.rows.insert(
                    session,
                    Claim {
                        occurrence_key_id: me.to_owned(),
                        attended_by,
                        claimed_at: now,
                        renewed_at: now,
                    },
                );
                ClaimOutcome::Claimed
            }
        }
    }

    /// **Primitive 2 — clear a claim.**
    ///
    /// Only the holder may release: a claim is self-published on the CEG self
    /// tier, and no occurrence speaks for another. Returns whether anything was
    /// released. Dropping a stale foreign row is left to expiry rather than done
    /// here, so that releasing stays a statement about one's own state.
    pub fn release(&mut self, session: &SessionKey, me: &str) -> bool {
        match self.rows.get(session) {
            Some(c) if c.occurrence_key_id == me => {
                self.rows.remove(session);
                true
            }
            _ => false,
        }
    }

    /// Who is handling this session right now, if anyone.
    ///
    /// `None` means unclaimed, which per I6 means **nobody acts** — it is a real
    /// answer and must never be collapsed into a default handler.
    #[must_use]
    pub fn handler_for(&self, session: &SessionKey, now: DateTime<Utc>) -> Option<&str> {
        self.rows
            .get(session)
            .filter(|c| Self::is_live(c, now))
            .map(|c| c.occurrence_key_id.as_str())
    }

    /// May THIS occurrence act on an attestation for this session?
    ///
    /// The question every occurrence asks itself after the fan-out delivers.
    #[must_use]
    pub fn may_act(&self, session: &SessionKey, me: &str, now: DateTime<Utc>) -> bool {
        self.handler_for(session, now) == Some(me)
    }

    /// Merge a sibling's self-published claim, settling any conflict.
    ///
    /// Called as self-tier rows arrive by subject-pull. Two occurrences can hold
    /// the same session transiently (no CAS across the mesh — see the module
    /// note), so this settles it with a rule every occurrence computes
    /// identically: **earliest `claimed_at` wins, ties broken on the lowest
    /// occurrence id**. Both sides converge on the same survivor without talking.
    pub fn resolve(&mut self, session: SessionKey, incoming: Claim) {
        match self.rows.get(&session) {
            Some(held) => {
                let incoming_wins = (incoming.claimed_at, incoming.occurrence_key_id.as_str())
                    < (held.claimed_at, held.occurrence_key_id.as_str());
                if incoming_wins {
                    self.rows.insert(session, incoming);
                }
            }
            None => {
                self.rows.insert(session, incoming);
            }
        }
    }

    /// Drop every claim that has aged out. Housekeeping; `handler_for` already
    /// treats a stale row as absent.
    pub fn expire(&mut self, now: DateTime<Utc>) {
        self.rows.retain(|_, c| Self::is_live(c, now));
    }

    /// Live claims held by one occurrence — the "what am I attending" view.
    #[must_use]
    pub fn sessions_held_by(&self, me: &str, now: DateTime<Utc>) -> Vec<&SessionKey> {
        let mut held: Vec<&SessionKey> = self
            .rows
            .iter()
            .filter(|(_, c)| c.occurrence_key_id == me && Self::is_live(c, now))
            .map(|(k, _)| k)
            .collect();
        held.sort();
        held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(community: &str, session: &str) -> SessionKey {
        SessionKey::new(community, session)
    }

    /// **I6.** No claim, no action — and being the only occurrence changes
    /// nothing. This is the rule the whole module exists to enforce.
    #[test]
    fn an_unclaimed_attestation_is_never_acted_on_even_by_a_lone_occurrence() {
        let now = Utc::now();
        let table = SessionTable::new();
        let s = key("community-b", "session-z");

        assert_eq!(table.handler_for(&s, now), None);
        assert!(
            !table.may_act(&s, "my-only-node", now),
            "a single-node self has no standing to act on an unclaimed \
             attestation — one occurrence with nobody home is still nobody home"
        );
    }

    /// The NAT property: four occurrences, four live sessions, two communities,
    /// all concurrent and all correct.
    #[test]
    fn four_occurrences_hold_four_concurrent_sessions_across_two_communities() {
        let now = Utc::now();
        let mut t = SessionTable::new();

        let x = key("community-a", "x");
        let y = key("community-a", "y");
        let z = key("community-b", "z");
        let a = key("community-b", "a");

        assert_eq!(
            t.try_claim(x.clone(), "node-1", Attendance::Agent, now),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            t.try_claim(y.clone(), "node-2", Attendance::Agent, now),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            t.try_claim(z.clone(), "node-3", Attendance::Human, now),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            t.try_claim(a.clone(), "node-4", Attendance::Human, now),
            ClaimOutcome::Claimed
        );

        assert_eq!(t.handler_for(&x, now), Some("node-1"));
        assert_eq!(t.handler_for(&y, now), Some("node-2"));
        assert_eq!(t.handler_for(&z, now), Some("node-3"));
        assert_eq!(t.handler_for(&a, now), Some("node-4"));

        // And each occurrence acts ONLY on its own session.
        assert!(t.may_act(&z, "node-3", now));
        assert!(!t.may_act(&z, "node-4", now));
        assert_eq!(t.sessions_held_by("node-3", now), vec![&z]);
    }

    /// A second occurrence cannot take a live session out from under the holder.
    #[test]
    fn a_live_claim_is_not_stealable() {
        let now = Utc::now();
        let mut t = SessionTable::new();
        let s = key("community-a", "x");

        t.try_claim(s.clone(), "node-1", Attendance::Human, now);
        assert_eq!(
            t.try_claim(s.clone(), "node-2", Attendance::Human, now),
            ClaimOutcome::HeldBy("node-1".to_owned())
        );
        assert_eq!(t.handler_for(&s, now), Some("node-1"));

        // The holder renewing keeps it, and does NOT reset `claimed_at` — that
        // field is the conflict-resolution key.
        let later = now + Duration::seconds(60);
        assert_eq!(
            t.try_claim(s.clone(), "node-1", Attendance::Human, later),
            ClaimOutcome::Renewed
        );
    }

    /// A node that dies must not hold its sessions forever.
    #[test]
    fn a_stale_claim_becomes_claimable_again() {
        let now = Utc::now();
        let mut t = SessionTable::new();
        let s = key("community-a", "x");

        t.try_claim(s.clone(), "node-1", Attendance::Human, now);
        let after = now + Duration::seconds(CLAIM_TTL_SECS + 1);

        // Stale reads as unhandled — and therefore as "nobody acts", not as
        // "node-1 still acts".
        assert_eq!(t.handler_for(&s, after), None);
        assert!(!t.may_act(&s, "node-1", after));

        assert_eq!(
            t.try_claim(s.clone(), "node-2", Attendance::Agent, after),
            ClaimOutcome::Claimed
        );
        assert_eq!(t.handler_for(&s, after), Some("node-2"));
    }

    /// Only the holder releases. A claim is a statement about oneself.
    #[test]
    fn only_the_holder_can_clear_its_own_claim() {
        let now = Utc::now();
        let mut t = SessionTable::new();
        let s = key("community-b", "z");

        t.try_claim(s.clone(), "node-3", Attendance::Human, now);
        assert!(
            !t.release(&s, "node-4"),
            "a sibling must not release my claim"
        );
        assert_eq!(t.handler_for(&s, now), Some("node-3"));

        assert!(t.release(&s, "node-3"));
        assert_eq!(t.handler_for(&s, now), None);
    }

    /// The dimension is versioned and sits under its own prefix. Both are load
    /// bearing: an unversioned dimension is refused outright by persist, and a
    /// prefix mismatch means the grant never covers the claim, which fails
    /// SILENTLY rather than loudly.
    #[test]
    fn the_claim_dimension_is_versioned_and_matches_its_consent_prefix() {
        assert!(
            SESSION_CLAIM_DIMENSION.starts_with(SESSION_ATTESTATION_PREFIX),
            "a claim published on {SESSION_CLAIM_DIMENSION} is not covered by a \
             grant for {SESSION_ATTESTATION_PREFIX} — it would replicate to nobody"
        );
        let last = SESSION_CLAIM_DIMENSION
            .rsplit(':')
            .next()
            .expect("dimension has segments");
        assert!(
            last.starts_with('v') && last[1..].parse::<u32>().is_ok(),
            "persist refuses a dimension without a :vN segment \
             (MissingVersionSegment): {SESSION_CLAIM_DIMENSION}"
        );
        assert_ne!(
            SESSION_ATTESTATION_PREFIX, "chat:",
            "claims govern any addressed session, not only chat"
        );
    }

    /// Concurrent claims converge: both sides reach the same survivor with no
    /// coordination, whichever order the self-tier rows arrive in.
    #[test]
    fn concurrent_claims_converge_on_the_same_survivor_from_either_side() {
        let now = Utc::now();
        let s = key("community-a", "x");

        let earlier = Claim {
            occurrence_key_id: "node-2".to_owned(),
            attended_by: Attendance::Human,
            claimed_at: now,
            renewed_at: now,
        };
        let later = Claim {
            occurrence_key_id: "node-1".to_owned(),
            attended_by: Attendance::Human,
            claimed_at: now + Duration::seconds(5),
            renewed_at: now + Duration::seconds(5),
        };

        // node-1's view: it holds the session, then learns of node-2's earlier claim.
        let mut a = SessionTable::new();
        a.resolve(s.clone(), later.clone());
        a.resolve(s.clone(), earlier.clone());

        // node-2's view: the same two facts, opposite order.
        let mut b = SessionTable::new();
        b.resolve(s.clone(), earlier.clone());
        b.resolve(s.clone(), later.clone());

        let at = now + Duration::seconds(10);
        assert_eq!(a.handler_for(&s, at), Some("node-2"), "earliest claim wins");
        assert_eq!(
            a.handler_for(&s, at),
            b.handler_for(&s, at),
            "both sides converge"
        );
    }

    /// Same instant, two claimants — the tie-break is a total order, so both
    /// sides still agree.
    #[test]
    fn a_simultaneous_tie_breaks_on_the_lowest_occurrence_id() {
        let now = Utc::now();
        let s = key("community-a", "x");
        let mk = |id: &str| Claim {
            occurrence_key_id: id.to_owned(),
            attended_by: Attendance::Agent,
            claimed_at: now,
            renewed_at: now,
        };

        let mut a = SessionTable::new();
        a.resolve(s.clone(), mk("node-9"));
        a.resolve(s.clone(), mk("node-1"));

        let mut b = SessionTable::new();
        b.resolve(s.clone(), mk("node-1"));
        b.resolve(s.clone(), mk("node-9"));

        assert_eq!(a.handler_for(&s, now), Some("node-1"));
        assert_eq!(b.handler_for(&s, now), Some("node-1"));
    }
}
