//! **One device handles each exchange** — session claims (CC 3.1.3.1,
//! CIRISPersist#782; the maintainer's ruling of 2026-09-30 pulling them into
//! 0.5.218). The design, the inventory of every place this node ACTS for its
//! person, and what is deliberately NOT gated live in `FSD/SESSION_CLAIMS.md`.
//!
//! # The problem
//!
//! A person is one federated identity plus the N nodes they own — the
//! *occurrences* of their self. Replication delivers a row addressed to that
//! person to EVERY one of those nodes, because a fed-ID has no transport path
//! of its own. So every autonomous reaction this server has — the self room's
//! MLS add/remove commits, the re-wrap of old self files for a new device —
//! ran on every device the person owns. Two devices committing an add at the
//! same epoch fork the self room; two devices re-wrapping the same blob write
//! two key-grant sets for one grant. Persist has carried the routing table
//! that fixes this since v38.7.0 (`session:claim:v1`, `handler_for`), and until
//! this module the server never read or wrote a single row of it (zero hits
//! for `session_claim`, `session:claim` or `handler_for` in src, tests or the
//! harness).
//!
//! # What persist decides, and what this module decides
//!
//! Persist owns the row, its projection (`Cohort` at every commons tier,
//! `SelfOwn` at `self`), the admission rule (a claim is a SELF-REPORT —
//! attester == attested == the claiming occurrence, a third party is refused at
//! the door, `check_session_self_report_admission`), the merge (earliest
//! `claimed_at`, ties on the lowest occurrence key id) and the read
//! ([`handler_for`]). This module never re-implements any of it: every "who
//! handles this?" goes through [`handler_for`], and the surface enumerates
//! which exchanges exist but asks persist who holds each one. A second copy
//! of the merge rule here would be the mirrored-rule class again.
//!
//! What persist cannot own is ATTENDANCE — "a human is present on this device"
//! is not a storage fact. That is this module's: [`Attendance`].
//!
//! # Attendance is the person's authenticated session, not the boot
//!
//! A device is *attended* while the person's own session (a verified owner
//! bearer, never a delegated `dgrant:` one — a helper acting for the person is
//! not the person) has touched it within [`PRESENCE_IDLE`]. The one place every
//! such request resolves is `auth::session::resolve_bearer`, which calls
//! [`Attendance::note_presence`]. A device that merely BOOTED is not attended:
//! a headless node the person never looks at must not take the self room's
//! commit duty just because it came up first, and a claim derived from boot
//! would do exactly that on every restart.
//!
//! # The invariant, kept here as persist keeps it
//!
//! **An unclaimed exchange is never acted on** — not by the lowest id, and not
//! by a single-device self. [`gate`] returns [`Verdict::Act`] only when
//! [`handler_for`] names THIS occurrence; [`Verdict::Unclaimed`] and
//! [`Verdict::HandledElsewhere`] both mean "do not act", and each is logged by
//! name at the site. There is no weak-claim value to promote.
//!
//! # Claim on demand, renew on the cadence
//!
//! A site that has work calls [`gate`]. If nobody holds the exchange AND this
//! device is attended AND it can sign as its own occurrence, the gate writes
//! the claim right there (so the work does not wait a whole renewal period),
//! kicks replication so the person's other devices see it on a round-trip,
//! and re-reads the fold — the device acts only if persist then names it.
//! The exchange is remembered, and the `session_claims` loop (a named
//! `loop_cadence` phase) renews it while the person stays; when they leave,
//! nothing renews, and the claim goes stale after [`SESSION_CLAIM_TTL`] and is
//! claimable by whichever device they are on next.
//!
//! # A renewal under persist v51 — and what v52 changes (CIRISPersist#946)
//!
//! Persist v51's liveness is the CONSUMER's horizon measured from `claimed_at`
//! (`claim_is_live(claim, now, ttl)`), and persist's doc is explicit that a
//! renewal does not move `claimed_at` ("the holder would lose its own
//! session"). Those two together mean a same-instant renewal cannot extend
//! anything on v51: the claim dies `ttl` after it was first taken. So on v51 a
//! renewal here is a SUCCESSOR LEASE — a fresh claim row written only by the
//! device the fold already names as the holder. Because a non-holder never
//! claims while a live claim exists ([`step`]), the holder's own leases are the
//! only live claims, and the earliest of them keeps naming the holder. The one
//! residual is a simultaneous first claim by two attended devices: the loser
//! stops renewing when it sees the winner, but its single lease can outlive
//! the winner's first one and hand the session over ONCE, after which the new
//! holder renews and the old one defers. One handover, never two handlers in
//! one view. CC 3.1.3.1 moves the horizon into the row (`valid_until`, signed,
//! lease ≤ 86 400 s, a renewal is a `supersedes` that keeps `claimed_at`);
//! persist v52 (#946) carries it, and [`write_claim`] names the spot.
//!
//! # At persist v52.0.0 — the lease is in the row; the fold still is not
//!
//! v52 (CIRISPersist#946) made `valid_until` REQUIRED on every `session:*` row
//! and bounded it (`claimed_at ≤ valid_until ≤ claimed_at + 86 400 s`,
//! `admission::check_session_lease_bound`, at every door), so every claim
//! written here now carries `valid_until = claimed_at + TTL` — the honest end
//! of a [`SESSION_CLAIM_TTL`] lease, signed.
//!
//! What v52 did NOT move is the READ. `session_claim::handler_for` still folds
//! `claim_is_live(claim, now, ttl)` = `now − claimed_at < ttl` with the
//! CONSUMER's ttl; it reads neither `valid_until` nor `supersedes` (and
//! `list_attestations_for` does not drop a superseded row). So the renewal CC
//! 3.1.3.1 describes — a `supersedes` of the previous lease that KEEPS
//! `claimed_at` and moves `valid_until` forward — would be judged by its
//! unchanged `claimed_at` and expire the holder at `claimed_at + TTL` in every
//! view, on every device: the session would be handed over every two minutes
//! while the person sat at the holder. That is worse than the v51 behaviour
//! it is meant to improve, so the renewal stays the successor lease described
//! above (a fresh claim by the device the fold already names, its own
//! `claimed_at`, its own `valid_until`), which v52's bound admits and v52's
//! fold keeps live. The day persist's fold reads `valid_until` and honours
//! `supersedes` (the read half of #946), [`renew_once`] turns into that
//! supersedes and `SESSION_CLAIM_TTL` stops being a consumer constant; until
//! then a server-side liveness fold over `valid_until` would be a second copy
//! of persist's rule (the mirrored-rule class), so none is written here.
//!
//! # At persist v52.0.1 — the read half landed; a renewal keeps `claimed_at`
//!
//! persist v52.0.1 (CIRISPersist#946 read side, found by this server's v52
//! adopt) judges each claim row live iff `now < its signed valid_until`
//! (`session_claim::row_is_live`), the consumer ttl only a fallback for a
//! pre-v52 row with none. So the successor-lease workaround above is GONE.
//! A renewal is now a new self-report row that KEEPS the exchange's ORIGINAL
//! `claimed_at` — earliest-wins is stable across renewals, so another device
//! never sees the handler move — and carries `valid_until = now + TTL`,
//! capped at `claimed_at + SESSION_LEASE_MAX_SECS` (86 400 s, persist's
//! bound). Past the cap no renewal can extend the lease, so the holder writes
//! a FRESH claim with a new `claimed_at`; its older claim stays live to the cap,
//! so the holder is unchanged through the handover.
//!
//! The renewal is a fresh `scores` row, not a `supersedes`: persist's own
//! v52.0.1 renewal witness writes it exactly so (a second claim row, same
//! `claimed_at`, a later `valid_until`), the fold is type-agnostic, and in this
//! substrate a `supersedes` is the placement/widening primitive — re-placing a
//! `self`-scoped claim through it buys nothing a reader can see. The original
//! `claimed_at` is the one the fold names (`handler_for`), kept per exchange
//! in [`Attendance`] too so a renewal never re-derives it from the clock.
//!
//! Every one of this person's devices runs this binary, so every one of them
//! applies the same [`SESSION_CLAIM_TTL`] — the convergence argument needs one
//! horizon, and until the horizon is in the row, one constant is how it gets
//! one.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::admission::{envelope_dimension, nodes_stewarded_by, owner_of};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::session_claim::{
    claim_from_envelope, handler_for, SessionClaim, SESSION_CLAIM_DIMENSION,
};
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::prelude::{Engine, LocalSigner};

// ─── The horizons ───────────────────────────────────────────────────────────

/// **How long a claim holds without a successor** — 120 s.
///
/// Long enough that a holder that renews every [`SESSION_CLAIM_RENEW_AFTER`]
/// (60 s) on a 30 s loop always has a live lease with a full renewal period of
/// slack: one missed tick, a slow directory read or a replication round-trip
/// never opens a gap in which nobody holds the session. Short enough that when
/// the person puts a device down, their other device can take the exchange
/// within two minutes — the self room's next add, or a new device's re-wrap,
/// waits at most that long for the device they moved to. The same value on
/// every device (see the module docs): it is the horizon persist's
/// `claim_is_live` measures, until CIRISPersist#946 signs it into the row.
pub const SESSION_CLAIM_TTL: Duration = Duration::from_secs(120);

/// **The renewal loop's period** — 30 s, the node's common loop period (every
/// default cadence is a multiple of 30 s, which is what `loop_cadence`'s
/// separation argument rests on).
pub const SESSION_CLAIM_RENEW_EVERY: Duration = Duration::from_secs(30);

/// **A holder writes its successor lease once its newest is this old** — 60 s,
/// half the TTL. Renewing every tick would be a row every 30 s per exchange
/// for as long as the person is present (they replicate to every device); at
/// half the TTL it is one a minute, and the newest lease always has at least
/// 60 s left when the next one is written.
pub const SESSION_CLAIM_RENEW_AFTER: Duration = Duration::from_secs(60);

/// **How long after the person's last request a device stays attended** —
/// 10 minutes. A client polls far more often than this while it is open, so
/// an open app keeps its device attended; a closed one lets it go. Long enough
/// to cover the gap the second-device flow creates: the person approves on the
/// first device, the second boots, provisions and publishes its KeyPackage,
/// and the first must still be attended when that arrives to commit the add.
pub const PRESENCE_IDLE: Duration = Duration::from_secs(10 * 60);

// ─── The exchanges this server names ────────────────────────────────────────

/// The self room's COMMIT duty: adding, removing and rejoining the person's
/// devices. One session for the whole duty, not one per joiner, because an
/// MLS group's commits must come from one committer at a time — two devices
/// adding two different joiners at the same epoch fork the room exactly as
/// two adding the same one do. CC 3.1.3.1 names "a moderation duty" as an
/// exchange; this is that shape.
pub const SELF_ROOM_MEMBERSHIP_SESSION: &str = "self_room:membership";

/// The re-wrap of old self files for ONE new device: `self_rewrap:<occurrence>`.
/// Per occurrence, because the capability is per occurrence — the new device
/// itself cannot re-wrap for itself (it holds none of the old DEKs), so it
/// must never be the one that takes its own re-wrap, and a per-person session
/// would let it (the fold would name whoever claimed first for ANY device).
#[must_use]
pub fn rewrap_session(occurrence_key_id: &str) -> String {
    format!("self_rewrap:{occurrence_key_id}")
}

/// The community an exchange of the person's SELF is keyed under: the self
/// room's content group id, edge's single definition of "this person's self
/// room" (`ciris_edge::self_room::room`). Never re-derived here.
#[must_use]
pub fn self_community(owner_key_id: &str) -> String {
    ciris_edge::self_room::room(owner_key_id)
        .content_group_id()
        .to_owned()
}

// The three signed members of a claim (CC 2.1 / CC 3.1.3.1). Persist exports
// no path constants for them (its reader, `claim_from_envelope`, spells them
// inline), so they are named once here and `a_written_claim_is_one_persist_can
// _read` round-trips a written envelope through persist's own reader: a rename
// upstream fails that test instead of silently producing rows nobody folds.
const COMMUNITY_ID: &str = "community_id";
const SESSION_ID: &str = "session_id";
const CLAIMED_AT: &str = "claimed_at";
/// persist v52 (CIRISPersist#946): the lease's signed end. Persist's gate
/// spells it inline too (`check_session_lease_bound`); the round-trip test
/// below writes a claim through the real door, so a rename upstream refuses
/// the row and fails the test.
const VALID_UNTIL: &str = "valid_until";

/// CC 2.6.2 canonical instant: RFC 3339, milliseconds, `Z`.
#[must_use]
pub fn canonical_instant(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn ttl() -> chrono::Duration {
    chrono::Duration::from_std(SESSION_CLAIM_TTL).expect("a 120 s TTL fits a chrono duration")
}

// ─── The state machine ──────────────────────────────────────────────────────

/// What one device does about one exchange on one tick. Pure — see [`step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nobody holds it and the person is here: take it.
    Claim,
    /// We hold it and our newest lease is due: write the successor.
    Renew,
    /// We hold it and our newest lease is fresh: nothing to write.
    Hold,
    /// Another occurrence holds a LIVE claim. Never contested — a live claim
    /// is not stealable, and contesting it is the one thing that would make
    /// "earliest wins" flap.
    Defer { handler: String },
    /// The person is not here: write nothing and let our claim go stale.
    Lapse,
}

/// **The claim / renew / lapse decision**, given what the fold says now.
///
/// - not attended → [`Step::Lapse`], whatever the fold says: a device the
///   person left must stop renewing, or it holds the session forever;
/// - nobody holds it → [`Step::Claim`];
/// - someone else holds it → [`Step::Defer`];
/// - we hold it → [`Step::Renew`] when our newest lease is at least
///   [`SESSION_CLAIM_RENEW_AFTER`] old (or unknown — a restarted process does
///   not remember what it wrote, and one extra lease is cheaper than a gap),
///   else [`Step::Hold`].
#[must_use]
pub fn step(
    attended: bool,
    handler: Option<&SessionClaim>,
    me: &str,
    newest_lease: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> Step {
    if !attended {
        return Step::Lapse;
    }
    match handler {
        None => Step::Claim,
        Some(h) if h.occurrence_key_id != me => Step::Defer {
            handler: h.occurrence_key_id.clone(),
        },
        Some(_) => match newest_lease {
            Some(at)
                if now.signed_duration_since(at)
                    < chrono::Duration::from_std(SESSION_CLAIM_RENEW_AFTER).expect("60 s fits") =>
            {
                Step::Hold
            }
            _ => Step::Renew,
        },
    }
}

/// **May this device act on this exchange?** Only [`Verdict::Act`] says yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The fold names this occurrence. Act.
    Act,
    /// The fold names another occurrence of the same person. Do not act; that
    /// device does.
    HandledElsewhere { occurrence: String },
    /// Nobody holds it. Do not act — not even as the only device (CC 3.1.3.1).
    Unclaimed,
}

impl Verdict {
    /// The fold's answer, mapped for `me`. `None` is [`Verdict::Unclaimed`]
    /// and nothing else.
    #[must_use]
    pub fn of(handler: Option<&SessionClaim>, me: &str) -> Self {
        match handler {
            Some(h) if h.occurrence_key_id == me => Self::Act,
            Some(h) => Self::HandledElsewhere {
                occurrence: h.occurrence_key_id.clone(),
            },
            None => Self::Unclaimed,
        }
    }

    /// `true` only for [`Verdict::Act`].
    #[must_use]
    pub fn acts(&self) -> bool {
        matches!(self, Self::Act)
    }
}

// ─── Attendance ─────────────────────────────────────────────────────────────

/// One exchange this device has offered to handle.
#[derive(Debug, Clone)]
struct Exchange {
    owner: String,
    occurrence: String,
    /// When THIS process last wrote a lease (a claim or a renewal), if ever —
    /// what the renewal cadence measures.
    newest_lease: Option<chrono::DateTime<chrono::Utc>>,
    /// The exchange's ORIGINAL `claimed_at` — every renewal carries it
    /// (persist v52.0.1: a renewal keeps `claimed_at`, so earliest-wins is
    /// stable). `None` until this process claims or reads it from the fold.
    claimed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// **Whether the person is on this device, and which exchanges this device
/// has offered to handle.** One per device: production uses
/// [`Attendance::global`] (a process is a device); a test that stands two
/// devices up in one process gives each its own.
#[derive(Debug, Default)]
pub struct Attendance {
    presence: Mutex<Option<std::time::Instant>>,
    exchanges: Mutex<BTreeMap<(String, String), Exchange>>,
    acted: Mutex<HashSet<String>>,
}

impl Attendance {
    /// A device with nobody on it and nothing offered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This process's attendance.
    pub fn global() -> &'static Attendance {
        static GLOBAL: OnceLock<Attendance> = OnceLock::new();
        GLOBAL.get_or_init(Attendance::new)
    }

    /// The person made an authenticated request on this device, now.
    pub fn note_presence(&self) {
        *self.presence.lock().expect("attendance poisoned") = Some(std::time::Instant::now());
    }

    /// The person left (a test's lever; production lets [`PRESENCE_IDLE`]
    /// pass instead).
    pub fn end_presence(&self) {
        *self.presence.lock().expect("attendance poisoned") = None;
    }

    /// Has the person touched this device within [`PRESENCE_IDLE`]?
    #[must_use]
    pub fn attended(&self) -> bool {
        self.presence
            .lock()
            .expect("attendance poisoned")
            .is_some_and(|at| at.elapsed() < PRESENCE_IDLE)
    }

    fn offer(&self, community: &str, session: &str, owner: &str, occurrence: &str) {
        let mut ex = self.exchanges.lock().expect("attendance poisoned");
        ex.entry((community.to_owned(), session.to_owned()))
            .and_modify(|e| {
                e.owner = owner.to_owned();
                e.occurrence = occurrence.to_owned();
            })
            .or_insert_with(|| Exchange {
                owner: owner.to_owned(),
                occurrence: occurrence.to_owned(),
                newest_lease: None,
                claimed_at: None,
            });
    }

    fn leased(
        &self,
        community: &str,
        session: &str,
        at: chrono::DateTime<chrono::Utc>,
        claimed_at: chrono::DateTime<chrono::Utc>,
    ) {
        if let Some(e) = self
            .exchanges
            .lock()
            .expect("attendance poisoned")
            .get_mut(&(community.to_owned(), session.to_owned()))
        {
            e.newest_lease = Some(at);
            e.claimed_at = Some(claimed_at);
        }
    }

    /// The exchange's original `claimed_at`, as this process last wrote it.
    #[must_use]
    pub fn claimed_at(
        &self,
        community: &str,
        session: &str,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        self.exchanges
            .lock()
            .expect("attendance poisoned")
            .get(&(community.to_owned(), session.to_owned()))
            .and_then(|e| e.claimed_at)
    }

    fn snapshot(&self) -> Vec<((String, String), Exchange)> {
        self.exchanges
            .lock()
            .expect("attendance poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn forget(&self, community: &str, session: &str) {
        self.exchanges
            .lock()
            .expect("attendance poisoned")
            .remove(&(community.to_owned(), session.to_owned()));
    }

    /// **Idempotent per act** (CC 3.1.3.1: "consumers MUST still make handling
    /// idempotent per attestation id — views transiently disagree"). A site
    /// records the act it completed; [`Self::already_acted`] answers before
    /// the next attempt. Recorded only on SUCCESS, so a failed act retries.
    pub fn record_act(&self, act_id: &str) {
        self.acted
            .lock()
            .expect("attendance poisoned")
            .insert(act_id.to_owned());
    }

    /// Has this device already completed `act_id`?
    #[must_use]
    pub fn already_acted(&self, act_id: &str) -> bool {
        self.acted
            .lock()
            .expect("attendance poisoned")
            .contains(act_id)
    }
}

// ─── The occurrence's own pen ───────────────────────────────────────────────

/// How this device signs AS the occurrence the fold knows it by. A claim is a
/// self-report of the OCCURRENCE — the node key the owner-binding names — so
/// on an actor/node split install it is the held node signer, never the
/// engine's actor key (the axis this codebase has got wrong nine times:
/// `wire_identity()` / the bound key, never `local_derived_key_id()` blindly).
pub enum NodePen {
    /// The engine IS the node (a standalone install).
    Engine,
    /// The split's held node signer, registered under its DERIVED id.
    Held(Arc<LocalSigner>),
}

impl NodePen {
    /// The pen that signs as `occurrence`, or `None` when this process holds
    /// no key that is that occurrence — then it cannot claim, and says so.
    pub async fn for_occurrence(engine: &Engine, occurrence: &str) -> Option<Self> {
        if let Some(held) = crate::node_key::held_node_signer() {
            if held.derived_key_id() == occurrence {
                return Some(Self::Held(held));
            }
        }
        match engine.local_derived_key_id().await {
            Ok(k) if k == occurrence => Some(Self::Engine),
            _ => None,
        }
    }

    fn signer<'a>(
        &'a self,
        engine: &'a Engine,
        occurrence: &'a str,
    ) -> crate::attest::KeySigner<'a> {
        match self {
            Self::Engine => crate::attest::KeySigner::Engine(engine),
            Self::Held(s) => crate::attest::KeySigner::LocalAs(s.as_ref(), occurrence),
        }
    }
}

/// **Write one claim** — `session:claim:v1`, a self-report of `occurrence`,
/// at `self`, through the one attest door. `claimed_at` is the caller's (a
/// fresh claim and a v51 successor lease both pass `now`).
///
/// The lease is in the SIGNED envelope (persist v52, CIRISPersist#946, CC
/// 3.1.3.1): `valid_until = claimed_at + TTL` — required on every `session:*`
/// row, refused without it (`check_session_lease_bound`), and bounded to a
/// day, which a 120 s lease is far inside. `expires_at` states the same
/// instant for anything that sweeps expired rows. persist's fold still reads
/// the consumer TTL from `claimed_at` (see the module docs, "At persist
/// v52.0.0"), and both horizons are the same [`SESSION_CLAIM_TTL`], so the
/// row's lease and the fold's agree on every device.
pub async fn write_claim(
    engine: &Engine,
    signer: crate::attest::KeySigner<'_>,
    community: &str,
    session: &str,
    claimed_at: chrono::DateTime<chrono::Utc>,
    valid_until: chrono::DateTime<chrono::Utc>,
) -> Result<String, crate::attest::Error> {
    let envelope = claim_envelope(community, session, claimed_at, valid_until);
    let spec = crate::attest::Spec::new(attestation_type::SCORES, cohort_scope::SELF, envelope)
        .weighing(Some(1.0))
        .expiring(Some(valid_until));
    crate::attest::emit(engine, signer, spec).await
}

/// **The lease a claim written `now` carries** (persist v52.0.1): `now +
/// TTL`, never past `claimed_at + SESSION_LEASE_MAX_SECS` (persist's bound,
/// `check_session_lease_bound`). `None` once the cap leaves less than a full
/// TTL — then a renewal could not keep the session a full period, and the
/// holder claims afresh instead ([`lease_for`]).
#[must_use]
pub fn renewal_lease(
    claimed_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let cap = claimed_at
        + chrono::Duration::seconds(ciris_persist::federation::admission::SESSION_LEASE_MAX_SECS);
    let wanted = now + ttl();
    (wanted <= cap).then_some(wanted)
}

/// `(claimed_at, valid_until)` for the lease this device writes now: a renewal
/// keeping `original` while the cap allows, else a fresh claim dated `now`.
#[must_use]
pub fn lease_for(
    original: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    match original.and_then(|c| renewal_lease(c, now).map(|v| (c, v))) {
        Some(renewal) => renewal,
        None => (now, now + ttl()),
    }
}

/// The signed members of one claim — ONE builder, so the unit test that runs
/// persist's own lease gate over it judges exactly what [`write_claim`] signs.
fn claim_envelope(
    community: &str,
    session: &str,
    claimed_at: chrono::DateTime<chrono::Utc>,
    valid_until: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        (paths::DIMENSION): SESSION_CLAIM_DIMENSION,
        "score": 1.0,
        COMMUNITY_ID: community,
        SESSION_ID: session,
        CLAIMED_AT: canonical_instant(claimed_at),
        VALID_UNTIL: canonical_instant(valid_until),
    })
}

/// Who this device is, for its person: the occurrence the owner-binding
/// names, and that owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occupant {
    /// The person (the owner fed-ID key).
    pub owner: String,
    /// This device's occurrence — the node key the owner-binding names.
    pub occurrence: String,
}

impl Occupant {
    /// Resolve from this node's own keys (`peer::own_keys_of_this_node`): the
    /// first one bound to an owner. `None` on an unowned node — which has no
    /// person to handle anything for.
    pub async fn of_node(engine: &Engine, node_key_id: &str) -> Option<Self> {
        let dir = engine.federation_directory();
        // The NODE key first: on a split install the engine key is the ACTOR,
        // and the occurrence the fold knows is the node the binding moved to.
        let mut keys: Vec<String> = [
            crate::node_key::wire_identity().map(str::to_owned),
            crate::node_key::held_node_signer().map(|h| h.derived_key_id()),
        ]
        .into_iter()
        .flatten()
        .collect();
        for k in crate::peer::own_keys_of_this_node(node_key_id) {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        for k in keys {
            if let Ok(Some(owner)) = owner_of(dir.as_ref(), &k).await {
                return Some(Self {
                    owner,
                    occurrence: k,
                });
            }
        }
        None
    }
}

/// **THE GATE.** Call before every ACT in `FSD/SESSION_CLAIMS.md`'s inventory.
///
/// Reads [`handler_for`]; if nobody holds `(community, session)` and this
/// device is attended and can sign as its occurrence, claims it on the spot
/// and reads again. Offers the exchange to `attendance` either way (so the
/// renewal loop keeps a held one and the surface can name it). Returns what
/// the fold says for THIS occurrence, and logs the refusals by name — `site`
/// is the act's name in those lines.
pub async fn gate(
    engine: &Engine,
    attendance: &Attendance,
    who: &Occupant,
    community: &str,
    session: &str,
    site: &'static str,
) -> Verdict {
    gate_at(
        engine,
        attendance,
        who,
        community,
        session,
        site,
        chrono::Utc::now(),
    )
    .await
}

/// [`gate`] at a stated instant — a claim written here is dated `now`. For a
/// test that must see a claim lapse without waiting out the TTL; production
/// always passes the clock through [`gate`].
pub async fn gate_at(
    engine: &Engine,
    attendance: &Attendance,
    who: &Occupant,
    community: &str,
    session: &str,
    site: &'static str,
    now: chrono::DateTime<chrono::Utc>,
) -> Verdict {
    let dir = engine.federation_directory();
    let read = |now| {
        let dir = Arc::clone(&dir);
        async move { handler_for(dir.as_ref(), &who.owner, community, session, now, ttl()).await }
    };
    let mut handler = match read(now).await {
        Ok(h) => h,
        Err(e) => {
            // A failed read is NOT "unclaimed, so maybe me" — it is "unknown",
            // and unknown never acts.
            tracing::warn!(
                site, community, session, error = %e,
                "session claim: the handler read failed — nobody acts this tick"
            );
            return Verdict::Unclaimed;
        }
    };
    attendance.offer(community, session, &who.owner, &who.occurrence);
    if handler.is_none() && attendance.attended() {
        match claim_now(engine, attendance, who, community, session, now, None).await {
            Ok(()) => {
                handler = read(now).await.unwrap_or(None);
            }
            Err(e) => tracing::warn!(
                site, community, session, error = %e,
                "session claim: this device is attended and could not write its claim"
            ),
        }
    }
    let verdict = Verdict::of(handler.as_ref(), &who.occurrence);
    match &verdict {
        Verdict::Act => tracing::debug!(
            site, community, session, occurrence = %who.occurrence,
            "session claim: handled HERE — this device acts"
        ),
        Verdict::HandledElsewhere { occurrence } => tracing::info!(
            site, community, session, handler = %occurrence,
            "session claim: handled by occurrence {occurrence} — this device does not act"
        ),
        Verdict::Unclaimed => tracing::info!(
            site,
            community,
            session,
            attended = attendance.attended(),
            "session claim: unclaimed — nobody acts (the person is on none of their devices \
             that can handle this; it runs where they next are)"
        ),
    }
    verdict
}

/// Write this device's lease on `(community, session)`: a RENEWAL keeping
/// `original` when there is one and the cap allows (persist v52.0.1), else a
/// fresh claim dated `now` ([`lease_for`]).
async fn claim_now(
    engine: &Engine,
    attendance: &Attendance,
    who: &Occupant,
    community: &str,
    session: &str,
    now: chrono::DateTime<chrono::Utc>,
    original: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), String> {
    let (claimed_at, valid_until) = lease_for(original, now);
    let Some(pen) = NodePen::for_occurrence(engine, &who.occurrence).await else {
        return Err(format!(
            "this process holds no pen for occurrence {} — a claim is its self-report",
            who.occurrence
        ));
    };
    let id = write_claim(
        engine,
        pen.signer(engine, &who.occurrence),
        community,
        session,
        claimed_at,
        valid_until,
    )
    .await
    .map_err(|e| format!("{e}"))?;
    attendance.leased(community, session, now, claimed_at);
    tracing::info!(
        community, session, occurrence = %who.occurrence, attestation_id = %id,
        claimed_at = %canonical_instant(claimed_at),
        valid_until = %canonical_instant(valid_until),
        renewal = original == Some(claimed_at),
        "session claim WRITTEN — this device holds the exchange while the person is here"
    );
    let _ = crate::compose::kick_replication("session:claim");
    Ok(())
}

/// What one renewal pass did, per exchange — for the loop's log and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalLine {
    pub community: String,
    pub session: String,
    pub step: Step,
}

/// **One renewal pass** over every exchange this device has offered.
pub async fn renew_once(engine: &Engine, attendance: &Attendance) -> Vec<RenewalLine> {
    renew_once_at(engine, attendance, chrono::Utc::now()).await
}

/// [`renew_once`] at a stated instant (see [`gate_at`]).
pub async fn renew_once_at(
    engine: &Engine,
    attendance: &Attendance,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<RenewalLine> {
    let dir = engine.federation_directory();
    let attended = attendance.attended();
    let mut out = Vec::new();
    for ((community, session), ex) in attendance.snapshot() {
        let handler = match handler_for(dir.as_ref(), &ex.owner, &community, &session, now, ttl())
            .await
        {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(%community, %session, error = %e, "session claim renewal: read failed this tick");
                continue;
            }
        };
        let s = step(
            attended,
            handler.as_ref(),
            &ex.occurrence,
            ex.newest_lease,
            now,
        );
        match &s {
            Step::Claim | Step::Renew => {
                let who = Occupant {
                    owner: ex.owner.clone(),
                    occurrence: ex.occurrence.clone(),
                };
                // A renewal keeps the exchange's ORIGINAL claimed_at — the one
                // the fold names (it is ours: Step::Renew means we hold it),
                // else the one this process wrote. A fresh claim has none.
                let original = match &s {
                    Step::Renew => handler.as_ref().map(|h| h.claimed_at).or(ex.claimed_at),
                    _ => None,
                };
                if let Err(e) = claim_now(
                    engine, attendance, &who, &community, &session, now, original,
                )
                .await
                {
                    tracing::warn!(%community, %session, error = %e, "session claim renewal could not write");
                }
            }
            Step::Lapse => {
                // Nothing written. Once our newest lease is past the TTL the
                // exchange is no longer ours in any view: stop tracking it.
                let stale = ex
                    .newest_lease
                    .is_none_or(|at| now.signed_duration_since(at) >= ttl());
                if stale {
                    attendance.forget(&community, &session);
                }
            }
            Step::Hold | Step::Defer { .. } => {}
        }
        out.push(RenewalLine {
            community,
            session,
            step: s,
        });
    }
    out
}

/// **The `session_claims` loop** — renews held exchanges on its own
/// `loop_cadence` slot while the person stays, and lets them lapse when they
/// leave. Stops when `shutdown` flips.
pub fn spawn(
    engine: Arc<Engine>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut schedule =
            crate::loop_cadence::Cadence::new("session_claims", SESSION_CLAIM_RENEW_EVERY);
        tracing::info!(
            period_secs = SESSION_CLAIM_RENEW_EVERY.as_secs(),
            ttl_secs = SESSION_CLAIM_TTL.as_secs(),
            renew_after_secs = SESSION_CLAIM_RENEW_AFTER.as_secs(),
            presence_idle_secs = PRESENCE_IDLE.as_secs(),
            "session claims loop spawned (CC 3.1.3.1): one device handles each exchange"
        );
        let mut last: BTreeMap<(String, String), Step> = BTreeMap::new();
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                () = schedule.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                    continue;
                }
            }
            for line in renew_once(&engine, Attendance::global()).await {
                let key = (line.community.clone(), line.session.clone());
                // Transition-only for the steady states; a write is always news.
                let news = matches!(line.step, Step::Claim | Step::Renew)
                    || last.get(&key) != Some(&line.step);
                if news {
                    tracing::info!(
                        community = %line.community, session = %line.session, step = ?line.step,
                        "session claims"
                    );
                }
                last.insert(key, line.step);
            }
        }
        tracing::info!("session claims loop stopped");
    })
}

// ─── GET /v1/self/sessions ──────────────────────────────────────────────────

fn refuse(code: StatusCode, id: &'static str, text: &'static str, detail: String) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": text, "reason_id": id, "detail": detail })),
    )
        .into_response()
}

/// A live claim's state, worded for the person — `(state_id, text)`.
fn state(here: bool) -> (&'static str, &'static str) {
    if here {
        (
            "session.state.handled_here",
            "This device is answering for you in this exchange.",
        )
    } else {
        (
            "session.state.handled_elsewhere",
            "Another of your devices is answering for you in this exchange.",
        )
    }
}

/// The distinct `(community, session)` pairs any of `owner`'s occurrences has
/// a well-formed, self-reported claim row for. ENUMERATION only — who holds
/// each is asked of [`handler_for`], never decided here.
async fn claimed_exchanges(engine: &Engine, owner: &str) -> Result<Vec<(String, String)>, String> {
    let dir = engine.federation_directory();
    let occurrences = nodes_stewarded_by(dir.as_ref(), owner)
        .await
        .map_err(|e| format!("nodes_stewarded_by({owner}): {e}"))?;
    let mut seen = std::collections::BTreeSet::new();
    for occ in occurrences {
        let rows = dir
            .list_attestations_for(&occ)
            .await
            .map_err(|e| format!("list_attestations_for({occ}): {e}"))?;
        for row in rows {
            if envelope_dimension(&row.attestation_envelope) != Some(SESSION_CLAIM_DIMENSION)
                || row.attesting_key_id != occ
                || row.attested_key_id != occ
            {
                continue;
            }
            if let Some((c, s, _)) = claim_from_envelope(&row.attestation_envelope, &occ) {
                seen.insert((c, s));
            }
        }
    }
    Ok(seen.into_iter().collect())
}

/// The surface's body, separated from the route so a test can read it for
/// either of two in-process devices.
pub async fn sessions_view(
    engine: &Engine,
    attendance: &Attendance,
    owner: &str,
    this_device: &str,
) -> Result<serde_json::Value, String> {
    let dir = engine.federation_directory();
    let labels = crate::self_devices::labels_for(engine, owner).await;
    let now = chrono::Utc::now();
    let mut sessions = Vec::new();
    for (community, session) in claimed_exchanges(engine, owner).await? {
        let Some(h) = handler_for(dir.as_ref(), owner, &community, &session, now, ttl())
            .await
            .map_err(|e| format!("handler_for: {e}"))?
        else {
            continue; // every claim for it has lapsed: nobody is answering
        };
        let here = h.occurrence_key_id == this_device;
        let (state_id, state_text) = state(here);
        sessions.push(serde_json::json!({
            "community_id": community,
            "session_id": session,
            "handler_occurrence_key_id": h.occurrence_key_id,
            "handler_label": labels.get(&h.occurrence_key_id),
            "claimed_at": canonical_instant(h.claimed_at),
            "live_until": canonical_instant(h.claimed_at + ttl()),
            "this_device": here,
            "state_id": state_id,
            "state": state_text,
        }));
    }
    Ok(serde_json::json!({
        "owner_key_id": owner,
        "this_device": this_device,
        "attended": attendance.attended(),
        "ttl_seconds": SESSION_CLAIM_TTL.as_secs(),
        "sessions": sessions,
    }))
}

/// `GET /v1/self/sessions` — every exchange of the person's that some device
/// is answering, and which one, so the client can say "answering on <device>".
/// Owner-authenticated; a delegated session may READ it (the family gate's
/// rule: reads admit a delegate, writes do not).
async fn list_sessions(State(engine): State<Arc<Engine>>, headers: HeaderMap) -> Response {
    let caller =
        match crate::family_api::owner_caller(&engine, &headers, true).await {
            Ok(c) => c,
            Err(crate::family_api::GateRefusal::Store(d)) => return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "self.sessions_unavailable",
                "The node could not read which of your devices is answering. Try again shortly.",
                d,
            ),
            Err(crate::family_api::GateRefusal::NoSession) => {
                return refuse(
                    StatusCode::UNAUTHORIZED,
                    "self.owner_session_required",
                    "Your devices are the owner's own surface. Sign in as the owner of this node.",
                    String::new(),
                )
            }
            Err(_) => {
                return refuse(
                    StatusCode::FORBIDDEN,
                    "self.owner_session_required",
                    "Your devices are the owner's own surface. Sign in as the owner of this node.",
                    String::new(),
                )
            }
        };
    // THIS device, as the fold knows it: the occurrence bound to the owner.
    let this_device = Occupant::of_node(&engine, &caller.node_key_id)
        .await
        .map_or(caller.node_key_id.clone(), |o| o.occurrence);
    match sessions_view(
        &engine,
        Attendance::global(),
        &caller.owner_key_id,
        &this_device,
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(d) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "self.sessions_unavailable",
            "The node could not read which of your devices is answering. Try again shortly.",
            d,
        ),
    }
}

/// The session-claims surface.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/v1/self/sessions", axum::routing::get(list_sessions))
        .with_state(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("fixture instant")
    }
    fn claim(occ: &str, when: &str) -> SessionClaim {
        SessionClaim {
            occurrence_key_id: occ.to_owned(),
            claimed_at: at(when),
        }
    }
    const NOW: &str = "2026-09-30T12:00:00Z";

    /// The invariant first: nobody holding it is never "so I will".
    #[test]
    fn an_unclaimed_exchange_is_not_acted_on_even_by_a_lone_device() {
        assert_eq!(Verdict::of(None, "me"), Verdict::Unclaimed);
        assert!(!Verdict::Unclaimed.acts());
        assert!(!Verdict::HandledElsewhere {
            occurrence: "other".into()
        }
        .acts());
        assert!(Verdict::of(Some(&claim("me", NOW)), "me").acts());
    }

    #[test]
    fn an_attended_device_claims_what_nobody_holds() {
        assert_eq!(step(true, None, "me", None, at(NOW)), Step::Claim);
    }

    #[test]
    fn a_device_never_contests_a_live_claim() {
        assert_eq!(
            step(true, Some(&claim("other", NOW)), "me", None, at(NOW)),
            Step::Defer {
                handler: "other".into()
            },
            "a live claim is not stealable — contesting it is what would make earliest-wins flap"
        );
    }

    #[test]
    fn the_holder_renews_at_half_the_ttl_and_holds_before() {
        let held = claim("me", "2026-09-30T11:59:00Z");
        assert_eq!(
            step(
                true,
                Some(&held),
                "me",
                Some(at("2026-09-30T11:59:30Z")),
                at(NOW)
            ),
            Step::Hold,
            "30 s old: fresh"
        );
        assert_eq!(
            step(
                true,
                Some(&held),
                "me",
                Some(at("2026-09-30T11:59:00Z")),
                at(NOW)
            ),
            Step::Renew,
            "60 s old: write the successor lease"
        );
        assert_eq!(
            step(true, Some(&held), "me", None, at(NOW)),
            Step::Renew,
            "a restarted process does not know its newest lease: one extra beats a gap"
        );
    }

    #[test]
    fn a_device_the_person_left_lapses_whatever_the_fold_says() {
        for h in [None, Some(claim("me", NOW)), Some(claim("other", NOW))] {
            assert_eq!(
                step(false, h.as_ref(), "me", Some(at(NOW)), at(NOW)),
                Step::Lapse
            );
        }
    }

    /// The renewal cadence must leave slack inside the TTL: a holder's newest
    /// lease always has at least one loop period left when it is renewed.
    #[test]
    fn the_horizons_leave_a_full_period_of_slack() {
        assert!(SESSION_CLAIM_RENEW_AFTER + SESSION_CLAIM_RENEW_EVERY < SESSION_CLAIM_TTL);
        assert!(SESSION_CLAIM_TTL < PRESENCE_IDLE);
        assert!(
            SESSION_CLAIM_TTL.as_secs() <= 86_400,
            "CC 3.1.3.1 bounds a lease at a day"
        );
    }

    /// The members this module writes are the ones persist's reader reads —
    /// and, since persist v52 (CIRISPersist#946), the ones persist's lease gate
    /// admits: `valid_until` present, after `claimed_at`, within a day.
    #[test]
    fn a_written_claim_is_one_persist_can_read() {
        let (claimed_at, valid_until) = lease_for(None, at(NOW));
        let env = claim_envelope("c1", SELF_ROOM_MEMBERSHIP_SESSION, claimed_at, valid_until);
        ciris_persist::federation::admission::check_session_lease_bound(
            SESSION_CLAIM_DIMENSION,
            &env,
        )
        .expect("persist v52's lease bound admits the claim this module signs");
        assert_eq!(env[VALID_UNTIL], "2026-09-30T12:02:00.000Z");
        let mut bare = env.clone();
        bare.as_object_mut().expect("object").remove(VALID_UNTIL);
        assert!(
            ciris_persist::federation::admission::check_session_lease_bound(
                SESSION_CLAIM_DIMENSION,
                &bare,
            )
            .is_err(),
            "a claim without valid_until is malformed at v52 — the pre-v52 row shape"
        );
        let (c, s, got) = claim_from_envelope(&env, "occ").expect("persist folds it");
        assert_eq!(
            (c.as_str(), s.as_str()),
            ("c1", SELF_ROOM_MEMBERSHIP_SESSION)
        );
        assert_eq!(got.claimed_at, at(NOW));
        assert_eq!(canonical_instant(at(NOW)), "2026-09-30T12:00:00.000Z");
    }

    /// persist v52.0.1: a renewal KEEPS the exchange's original `claimed_at`
    /// and moves `valid_until` to `now + TTL`, never past `claimed_at + 1 day`
    /// (persist's bound, which its gate admits); once the cap leaves less than
    /// a full TTL the holder claims afresh, dated now.
    #[test]
    fn a_renewal_keeps_claimed_at_until_the_cap_forces_a_fresh_claim() {
        let original = at(NOW);
        // Three renewals, an hour apart: same claimed_at, a moving lease.
        for hours in [1, 2, 3] {
            let now = original + chrono::Duration::hours(hours);
            let (c, v) = lease_for(Some(original), now);
            assert_eq!(c, original, "renewal {hours} keeps claimed_at");
            assert_eq!(v, now + ttl(), "renewal {hours} leases a full TTL from now");
            ciris_persist::federation::admission::check_session_lease_bound(
                SESSION_CLAIM_DIMENSION,
                &claim_envelope("c1", "s", c, v),
            )
            .expect("persist admits the renewal");
        }
        // The last renewal the cap allows: exactly at the bound.
        let cap = original
            + chrono::Duration::seconds(
                ciris_persist::federation::admission::SESSION_LEASE_MAX_SECS,
            );
        let last = cap - ttl();
        assert_eq!(lease_for(Some(original), last), (original, cap));
        // Past it: a FRESH claim, dated now — the renewal would exceed a day.
        let past = last + chrono::Duration::seconds(1);
        assert_eq!(lease_for(Some(original), past), (past, past + ttl()));
        assert!(renewal_lease(original, past).is_none());
        // No original: a fresh claim.
        assert_eq!(lease_for(None, original), (original, original + ttl()));
    }

    #[test]
    fn presence_is_the_persons_request_and_ends() {
        let a = Attendance::new();
        assert!(!a.attended(), "a device that only booted is not attended");
        a.note_presence();
        assert!(a.attended());
        a.end_presence();
        assert!(!a.attended());
    }

    #[test]
    fn an_act_is_recorded_once_and_only_on_success() {
        let a = Attendance::new();
        assert!(!a.already_acted("x"));
        a.record_act("x");
        assert!(a.already_acted("x"));
    }
}
