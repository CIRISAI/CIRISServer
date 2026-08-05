//! The **named-moderator existence invariant** (CC 4.5.4; FSD
//! MODERATION_CHILD_SAFETY §A) — THE load-bearing child-safety invariant.
//!
//! > A group without a named, accountable moderator cannot exist.
//!
//! Every multi-party `community` MUST, at all times, name ≥1 provisioned,
//! owner-bound identity holding the `moderate` scope for that group. The group's
//! ability to federate / operate is GATED on this. There is never an unmoderated
//! window: an auto-promotion rule fills any gap, and if no eligible moderator can
//! be named, the group **FAILS SECURE** — it MUST NOT federate. Better no group
//! than an unmoderated one (the predator-enabling state is made structurally
//! unreachable). Every surveyed network fails OPEN; CIRIS fails SECURE
//! (`FSD/SAFETY_LANDSCAPE.md`).
//!
//! ## COMPOSED from persist v9.0.0
//!
//! - `admission::is_named_moderator(directory, k, community_id, "moderate")` —
//!   the per-key CC 4.5.4 predicate (owner-bound authority root, zero-hop or via
//!   a live `moderate`-scoped chain). [`community_has_live_moderator`] composes
//!   it across the roster.
//! - `Community` / `CommunityMember` (`lookup_community`) — the roster the
//!   existence gate scans.
//! - `admission::DELEGATION_SCOPE_MODERATE` — the duty scope.
//!
//! ## BUILT server-side (the group-level invariant the per-key predicate lacks)
//!
//! persist ships the per-key predicate; this builds the GROUP-LEVEL existence
//! verdict + the deterministic merit-ranking auto-promotion (CC 4.5.4) on top:
//!
//! - [`community_has_live_moderator`] — does ANY roster member satisfy the
//!   predicate? (the existence test).
//! - [`existence_verdict`] — Operate / Quiesce; fail-secure when none.
//! - [`auto_promotion_outcome`] — the deterministic merit pick on a lapse
//!   (highest `moderation_track_record`; tiebreak score → earliest membership →
//!   lexicographic key_id). Deterministic ⇒ every node computes the SAME
//!   promotion ⇒ no split-brain on "who is the moderator now."
//!
//! ## FAIL CLOSED on an unreadable merit signal (CIRISServer#357 part 1)
//!
//! `auto_promotion_outcome` replaced an `Option<String>`-returning
//! `auto_promotion_candidate`. Two answers were not enough: "merit was read and
//! named nobody" and "merit could not be read" are different facts, and the old
//! shape could express neither — an unreachable ledger reads `0` for every
//! member, `0` ranks like any other number, and the function returned
//! `Some(whoever sorted first)`. The Option-shaped sibling is deliberately NOT
//! kept: it is exactly where the two zeroes collapsed.
//!
//! Upstream-asks (FSD §9 #11/#12): wire the existence predicate into persist's
//! community-admission path; add the `hard_case:community_unmoderated:{C}` /
//! `hard_case:community_moderator_promoted:{C}` reserved reasons so the
//! lapse/promotion is auditable, not silent.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::admission;
use ciris_persist::federation::types::CommunityMember;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::Engine;
use serde::Serialize;

use super::moderation;

/// The `hard_case:*` reserved reason emitted (into the community scope) when the
/// existence gate FAILS SECURE — a quiesced/unmoderated community is auditable,
/// NOT silent (the anti-soft-censorship discipline, FSD §A.2 / §9 #11).
/// Upstream-ask: add this to the CEG §7.8 closed `hard_case:*` reason set.
pub const HARD_CASE_COMMUNITY_UNMODERATED: &str = "community_unmoderated";

/// The `hard_case:*` reason for an auto-promotion event (FSD §A.3 / §9 #11).
pub const HARD_CASE_COMMUNITY_MODERATOR_PROMOTED: &str = "community_moderator_promoted";

/// The `hard_case:*` reason emitted when the community quiesces because the
/// merit signal **could not be read at all** — DISTINCT from
/// [`HARD_CASE_COMMUNITY_UNMODERATED`], which means the merit signal WAS read
/// and named nobody (CIRISServer#357 part 1).
///
/// The two are different facts and used to render identically: a lapsed
/// community reads `0` merit for every member because its ledger is
/// federation-tier-only and CC 4.5.4 / §11.11 refuses it federation, so
/// "measured zero merit" and "could not measure" were the same `0` and the
/// ranking silently degraded from *promote the most proven member* to *promote
/// whoever sorts first*. An operator seeing this reason knows the verdict is
/// **an unread instrument, not a finding** — the remedy is to restore a
/// `moderate`-duty holder by the community's own ceremony (CC 4.5.13 recovery /
/// CIRISConstitution#59 reverse quorum), not to trust a ranking.
/// Upstream-ask: add this to the CEG §7.8 closed `hard_case:*` reason set,
/// alongside the two above.
pub const HARD_CASE_COMMUNITY_MERIT_UNREADABLE: &str = "community_merit_unreadable";

/// **COMPOSE the CC 4.5.4 per-key predicate across the roster.** True iff ANY
/// current member of `community_key_id` is a live named moderator (owner-bound
/// authority root, zero-hop or via a live `moderate`-scoped chain).
///
/// This is the existence test: a community may operate iff this is true.
/// Fail-secure: an unknown community / empty roster ⇒ `false` (no moderator ⇒
/// MUST NOT operate).
pub async fn community_has_live_moderator(
    engine: &Engine,
    community_key_id: &str,
) -> Result<bool, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let Some(community) = directory
        .lookup_community(community_key_id)
        .await
        .map_err(|e| format!("lookup_community: {e}"))?
    else {
        // Unknown community: fail-secure (cannot establish a moderator).
        return Ok(false);
    };
    for member in &community.members {
        // COMPOSE persist's per-key predicate (owner-bound + scoped-chain walk).
        let named = admission::is_named_moderator(
            directory.as_ref(),
            &member.key_id,
            community_key_id,
            admission::DELEGATION_SCOPE_MODERATE,
        )
        .await
        .map_err(|e| format!("is_named_moderator: {e}"))?;
        if named {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The existence-gate verdict for a community.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ExistenceVerdict {
    /// ≥1 live named moderator → the community may federate / operate.
    Operate {
        /// Whether the live moderator was already present (vs would need
        /// auto-promotion). Always `true` here — `Operate` means present.
        moderator_present: bool,
    },
    /// No live moderator, but a merit candidate exists → auto-promote, THEN
    /// operate. Carries the deterministic pick (the caller emits the promotion
    /// `delegates_to(community → candidate, moderate)` under the community's
    /// consensus protocol — never a unilateral act).
    AutoPromote {
        /// The deterministic merit pick (FSD §A.3 ranking).
        candidate_key_id: String,
        /// The `hard_case:*` reason the promotion emits for audit.
        hard_case: &'static str,
    },
    /// No live moderator AND no eligible candidate → **FAIL SECURE.** The
    /// community MUST NOT federate; it is quiesced (stops admitting new
    /// community content + members), and emits the audit `hard_case`.
    Quiesce {
        /// The `hard_case:*` reason emitted so the failure is auditable, not
        /// silent.
        hard_case: &'static str,
    },
}

/// **The existence gate (CC 4.5.4).** Decide whether `community_key_id` may
/// operate:
///
/// 1. If a live named moderator exists → [`ExistenceVerdict::Operate`].
/// 2. Else if merit was READ and named a qualified member →
///    [`ExistenceVerdict::AutoPromote`] (the deterministic pick; the caller
///    ratifies it under the community's consensus protocol — the promotion is
///    signed, attributable, revocable, NEVER a coup).
/// 3. Else → [`ExistenceVerdict::Quiesce`] (FAIL SECURE — no unmoderated window,
///    ever; better no group than an unmoderated one), carrying the `hard_case`
///    that says WHICH kind of nothing was found:
///    [`HARD_CASE_COMMUNITY_UNMODERATED`] (merit was read; nobody qualified) or
///    [`HARD_CASE_COMMUNITY_MERIT_UNREADABLE`] (merit could not be read at all —
///    CIRISServer#357).
pub async fn existence_verdict(
    engine: &Engine,
    community_key_id: &str,
) -> Result<ExistenceVerdict, String> {
    if community_has_live_moderator(engine, community_key_id).await? {
        return Ok(ExistenceVerdict::Operate {
            moderator_present: true,
        });
    }
    match auto_promotion_outcome(engine, community_key_id).await? {
        PromotionOutcome::Candidate { key_id, .. } => Ok(ExistenceVerdict::AutoPromote {
            candidate_key_id: key_id,
            hard_case: HARD_CASE_COMMUNITY_MODERATOR_PROMOTED,
        }),
        PromotionOutcome::NoQualifiedCandidate => Ok(ExistenceVerdict::Quiesce {
            hard_case: HARD_CASE_COMMUNITY_UNMODERATED,
        }),
        // FAIL CLOSED (CIRISServer#357 part 1). Promoting on unreadable merit is
        // not promoting on merit — and it is worse than not promoting, because
        // the verdict SHAPE is indistinguishable from a real merit promotion.
        PromotionOutcome::MeritUnreadable { .. } => Ok(ExistenceVerdict::Quiesce {
            hard_case: HARD_CASE_COMMUNITY_MERIT_UNREADABLE,
        }),
    }
}

/// The outcome of the merit read + rank — **three answers, not two**
/// (CIRISServer#357 part 1).
///
/// The predecessor returned `Option<String>`, which had room for only two: a
/// candidate, or `None`. "Merit was read and named nobody" and "merit could not
/// be read" both had to land on `None`… except they did not even do that: an
/// unreadable ledger reads `0` for everyone, `0` sorts as a legitimate rank, and
/// the function returned `Some(whoever sorted first)`. The missing third answer
/// is why an unmeasured signal came back wearing a measurement's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionOutcome {
    /// Merit WAS read, and this member is the deterministic merit pick.
    Candidate {
        /// The winning member.
        key_id: String,
        /// The merit it won on — always ≥ 1 (a member with no proven record is
        /// not a merit candidate; see [`auto_promotion_outcome`]).
        track_record: u64,
    },
    /// Merit WAS read for every eligible member and named nobody: either the
    /// roster has no eligible (owner-bound) member at all, or none of them has
    /// any track record. A real, measured nothing.
    NoQualifiedCandidate,
    /// Merit **could not be read** — the ranking never ran. Distinct from the
    /// measured nothing above, and the whole point of #357.
    MeritUnreadable {
        /// Which unreadability (see [`moderation::MeritUnreadable`]).
        reason: moderation::MeritUnreadable,
    },
}

/// **Auto-promotion-by-merit (CC 4.5.4 / FSD §A.3).** Decide who — if anyone —
/// should be auto-granted `moderate` when the last named moderator lapses.
///
/// Eligibility: the member must be **owner-bound** (a real provisioned
/// accountable identity, or an occurrence of one — persist's `is_steward_bound`).
/// A bare unowned node can never become the moderator.
///
/// Qualification: the member must have a **positive read merit signal**. A
/// zero-merit member is not "the most proven member"; picking one is the
/// arbitrary choice this function exists to avoid, so an all-zero eligible set
/// yields no candidate rather than the earliest joiner.
///
/// Deterministic ranking over the qualified set (so every node computes the SAME
/// promotion — no split-brain on "who is the moderator now"):
/// 1. highest [`moderation::read_track_record`] (descending),
/// 2. tiebreak: earliest membership (`joined_at` ascending),
/// 3. final tiebreak: lexicographically smallest `key_id`.
///
/// ## FAIL CLOSED on an unreadable signal (CIRISServer#357 part 1)
///
/// Before ranking, the merit vector is checked for READABILITY:
///
/// - any per-member read that ERRORED (no directory / ledger read failed) ⇒
///   [`PromotionOutcome::MeritUnreadable`]. Those used to be silent zeroes.
/// - **every** eligible member reading `0` while the community has NO live
///   moderator ⇒ [`PromotionOutcome::MeritUnreadable`] with
///   [`moderation::MeritUnreadable::FederationTierClosed`]. This is the #357
///   seam: `read_track_record` walks the federation tier, CC 4.5.4 / §11.11
///   refuses federation to a moderator-less community (persist
///   `CommunityHasNoModerator`, and #589 made promotion face the full admission
///   stack), so its ledger cannot be written where the ranking looks. An all-zero
///   vector there is not a measurement of merit — it is the shape of an
///   instrument that is not connected. Ranking on it produced
///   `AutoPromote { candidate: <the member with no record at all> }`, correct in
///   shape and wrong in fact, with nothing in the verdict to say so.
///
/// The live-moderator check is what keeps this from over-firing: with the tier
/// OPEN (a moderated community), an all-zero vector IS a measurement, and the
/// answer is the honest [`PromotionOutcome::NoQualifiedCandidate`].
///
/// Cost of failing closed: a lapsed community whose merit ledger never reached
/// federation tier no longer auto-promotes at all. That is deliberate — CC
/// 4.5.4's posture is *better no group than an unmoderated one*, the community
/// can still appoint by its own consensus ceremony (CC 4.5.13 recovery), and a
/// promotion that cannot state its own basis is not a merit promotion.
pub async fn auto_promotion_outcome(
    engine: &Engine,
    community_key_id: &str,
) -> Result<PromotionOutcome, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let Some(community) = directory
        .lookup_community(community_key_id)
        .await
        .map_err(|e| format!("lookup_community: {e}"))?
    else {
        return Ok(PromotionOutcome::NoQualifiedCandidate);
    };

    // Score each eligible (owner-bound) member. A read that could not happen
    // STOPS the ranking — it is never folded into a rankable number.
    let mut ranked: Vec<RankedMember> = Vec::new();
    for member in &community.members {
        let eligible = admission::is_steward_bound(directory.as_ref(), &member.key_id)
            .await
            .map_err(|e| format!("is_steward_bound: {e}"))?;
        if !eligible {
            continue;
        }
        let track_record =
            match moderation::read_track_record(engine, &member.key_id, community_key_id).await {
                Ok(n) => n,
                Err(reason) => return Ok(PromotionOutcome::MeritUnreadable { reason }),
            };
        ranked.push(RankedMember {
            key_id: member.key_id.clone(),
            track_record,
            joined_at: member.joined_at,
        });
    }

    if ranked.is_empty() {
        // Measured: no member is eligible to hold the duty at all.
        return Ok(PromotionOutcome::NoQualifiedCandidate);
    }

    // #357: an all-zero vector from a community that CANNOT REACH the tier the
    // ledger lives on is an unread instrument, not a finding.
    if ranked.iter().all(|m| m.track_record == 0)
        && !community_has_live_moderator(engine, community_key_id).await?
    {
        return Ok(PromotionOutcome::MeritUnreadable {
            reason: moderation::MeritUnreadable::FederationTierClosed {
                community_key_id: community_key_id.to_owned(),
            },
        });
    }

    // Qualification: no record, no merit claim.
    ranked.retain(|m| m.track_record > 0);
    if ranked.is_empty() {
        return Ok(PromotionOutcome::NoQualifiedCandidate);
    }

    // Deterministic sort: track_record desc, joined_at asc, key_id asc.
    ranked.sort_by(|a, b| {
        b.track_record
            .cmp(&a.track_record)
            .then_with(|| a.joined_at.cmp(&b.joined_at))
            .then_with(|| a.key_id.cmp(&b.key_id))
    });

    let winner = ranked.into_iter().next().expect("non-empty after retain");
    Ok(PromotionOutcome::Candidate {
        key_id: winner.key_id,
        track_record: winner.track_record,
    })
}

struct RankedMember {
    key_id: String,
    track_record: u64,
    joined_at: chrono::DateTime<chrono::Utc>,
}

/// The deterministic ranking, exposed as a pure function for testing + for a
/// caller that already holds the (eligible member, track_record) set. Returns
/// the winning `key_id`. Same ORDER as [`auto_promotion_outcome`].
///
/// **Ranking only — qualification and readability are the caller's.** This
/// function will happily order an all-zero set and hand back the first one;
/// `auto_promotion_outcome` is where a zero-merit member is refused and where an
/// unreadable merit vector stops the ranking from running at all (#357).
pub fn rank_candidates(
    mut members: Vec<(String, u64, chrono::DateTime<chrono::Utc>)>,
) -> Option<String> {
    members.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    members.into_iter().next().map(|m| m.0)
}

/// True iff `member` is an eligible auto-promotion candidate (owner-bound). A
/// thin re-export of persist's leaf for the caller / tests.
pub async fn is_eligible_candidate(engine: &Engine, member: &CommunityMember) -> bool {
    let Some(directory) = engine.sqlite_backend() else {
        return false;
    };
    admission::is_steward_bound(directory.as_ref(), &member.key_id)
        .await
        .unwrap_or(false)
}

// ─── HTTP surface ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct NamedState {
    engine: Arc<Engine>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// `GET /v1/safety/named-moderator/:community_key_id` — the CC 4.5.4 existence
/// status: does the community have a live moderator, would it auto-promote, or is
/// it quiesced (fail-secure)?
async fn named_status(
    State(st): State<NamedState>,
    Path(community_key_id): Path<String>,
) -> Response {
    match existence_verdict(&st.engine, &community_key_id).await {
        Ok(verdict) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "community_key_id": community_key_id,
                "existence": verdict,
                // Honest framing kept TRUE on the wire: the invariant fails
                // SECURE — a community without a nameable moderator cannot
                // federate (better no group than an unmoderated one).
                "fails_secure": true,
            })),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The named-moderator status router.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route(
            "/v1/safety/named-moderator/{community_key_id}",
            axum::routing::get(named_status),
        )
        .with_state(NamedState { engine })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn t(day: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 6, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn ranking_prefers_highest_track_record() {
        let winner = rank_candidates(vec![
            ("alice".into(), 2, t(1)),
            ("bob".into(), 9, t(5)),
            ("carol".into(), 5, t(2)),
        ]);
        assert_eq!(winner.as_deref(), Some("bob")); // highest track record
    }

    #[test]
    fn ranking_tiebreaks_on_earliest_membership() {
        // Equal track record → earliest joined_at wins.
        let winner = rank_candidates(vec![("late".into(), 5, t(10)), ("early".into(), 5, t(2))]);
        assert_eq!(winner.as_deref(), Some("early"));
    }

    #[test]
    fn ranking_final_tiebreak_is_lexicographic_key_id() {
        // Equal track record AND equal joined_at → lexicographic key_id.
        let winner = rank_candidates(vec![("zeta".into(), 5, t(2)), ("alpha".into(), 5, t(2))]);
        assert_eq!(winner.as_deref(), Some("alpha"));
    }

    #[test]
    fn empty_candidate_set_has_no_winner() {
        // No eligible member ⇒ no winner ⇒ the community fails secure (quiesce).
        assert_eq!(rank_candidates(vec![]), None);
    }

    /// CIRISServer#357 — the three answers must stay THREE. The defect was a
    /// two-answer shape (`Option<String>`) into which a third fact was folded;
    /// the fix is only a fix while "read and found nobody" and "could not read"
    /// remain distinguishable, both as values and as operator-readable text.
    ///
    /// The `LedgerReadFailed` / `NoDirectory` arms cannot be reached from the
    /// integration harness (nothing can force a sqlite read to fail), so this is
    /// where their distinctness is held.
    #[test]
    fn the_three_promotion_answers_are_mutually_distinct() {
        use moderation::MeritUnreadable;
        let candidate = PromotionOutcome::Candidate {
            key_id: "k".into(),
            track_record: 1,
        };
        let nobody = PromotionOutcome::NoQualifiedCandidate;
        let unreadable = |r: MeritUnreadable| PromotionOutcome::MeritUnreadable { reason: r };

        assert_ne!(candidate, nobody);
        assert_ne!(nobody, unreadable(MeritUnreadable::NoDirectory));
        assert_ne!(candidate, unreadable(MeritUnreadable::NoDirectory));

        // Each unreadability is its own fact, not a shared "something went
        // wrong" — an operator must not have to guess which instrument failed.
        let reasons = [
            MeritUnreadable::NoDirectory,
            MeritUnreadable::LedgerReadFailed {
                detail: "disk i/o".into(),
            },
            MeritUnreadable::FederationTierClosed {
                community_key_id: "community:x".into(),
            },
        ];
        for (i, a) in reasons.iter().enumerate() {
            assert!(!a.to_string().is_empty(), "every reason must say something");
            for b in reasons.iter().skip(i + 1) {
                assert_ne!(a, b);
                assert_ne!(
                    a.to_string(),
                    b.to_string(),
                    "two unreadabilities must not render identically — that is \
                     the very collapse #357 is about"
                );
            }
        }
        // And none of them is the zero that WAS measured.
        assert_ne!(
            MeritUnreadable::FederationTierClosed {
                community_key_id: "community:x".into(),
            }
            .to_string(),
            String::new()
        );
    }
}
