//! **The crossing's SHAPE is decided by edge, and the copy it replaced was
//! blind.**
//!
//! `attestation_crossing::enter_mesh_at` composes persist's two v39 verbs, and
//! it used to decide for itself whether a widening was needed:
//!
//! ```text
//! if placed.cohort_scope() == target.cohort_scope() { return Ok(crossed); }
//! ```
//!
//! That compares the wire STRING. Every `community` audience spells that field
//! `"community"` — the cohort's identity lives beside it, in the envelope — so a
//! row placed in community **A**, asked for community **B**, compared EQUAL. The
//! function returned `Crossed`, [`is_placed`] said yes, and the row was still
//! visible to A alone. The same held for two families.
//!
//! It now asks `ciris_edge::replication::attestation_bind::share_plan`, the pure
//! half of edge's `share`, which compares `Audience` values — and an `Audience`
//! carries the cohort id.
//!
//! This file pins BOTH halves, because either alone is unconvincing: that edge's
//! rule refuses the motion, and that the string it replaced genuinely cannot
//! tell the two cohorts apart. The second is the exhibit. Without it "we changed
//! the comparison" is a preference; with it, it is a defect report.
//!
//! Pure — no engine, no directory, no signer. `share_plan` is decidable from the
//! row and the target alone, which is also the property that lets `enter_mesh_at`
//! refuse BEFORE the tier crossing instead of after it.
//!
//! [`is_placed`]: ciris_server::attestation_crossing::is_placed

use ciris_edge::replication::attestation_bind::{share_plan, SharePlan};
use ciris_persist::federation::types::{attestation_tier, attestation_type, cohort_scope};
use ciris_persist::federation::{Attestation, Audience};

/// A federation-tier row already placed in ONE named community.
///
/// `community_key_id` is the name persist's `envelope_cohort_target` resolves
/// (and edge's `FIELD_COMMUNITY_ID`); a row that named the cohort under a key
/// nothing reads would resolve to `Audience::Community` with no id and refuse
/// for the wrong reason.
fn row_in_community(community: &str) -> Attestation {
    let now = chrono::Utc::now();
    Attestation {
        attestation_id: format!("row-in-{community}"),
        attesting_key_id: "author-key".to_owned(),
        attested_key_id: "author-key".to_owned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            // `share_plan`'s first refusal is a row with no information type, so
            // a fixture without one would never reach the audience comparison
            // this file is about.
            "dimension": "chat:message:v1",
            "community_key_id": community,
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: "sig".to_owned(),
        scrub_signature_pqc: None,
        scrub_key_id: "author-key".to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::COMMUNITY.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// THE EXHIBIT: the rule `enter_mesh_at` used to apply cannot see the
/// difference between two communities.
///
/// If this ever fails — because `cohort_scope` grew a per-cohort spelling — the
/// old comparison would have been sound after all and this file's premise needs
/// re-deriving. It is asserted rather than asserted-in-prose for exactly that
/// reason.
#[test]
fn the_cohort_scope_string_is_blind_to_which_cohort() {
    let a = Audience::Community {
        community_key_id: "room-a".to_owned(),
    };
    let b = Audience::Community {
        community_key_id: "room-b".to_owned(),
    };
    assert_eq!(
        a.cohort_scope(),
        b.cohort_scope(),
        "two DIFFERENT communities must still spell `cohort_scope` the same way \
         — that is why comparing the string reported a re-targeting as a no-op"
    );
    assert_ne!(
        a, b,
        "the `Audience` itself carries the cohort id, which is what makes edge's \
         `share_plan` able to answer the question the string cannot"
    );
}

/// And edge's rule refuses it, by name.
///
/// A re-targeting is not a widening: `community → community` is not strictly
/// wider, so there is no `supersedes` to write. To reach a different cohort the
/// producer authors a row THERE; to take one back, they withdraw it
/// (CC 4.4.3.3.1). What must never happen is the motion reporting success.
#[test]
fn edge_refuses_a_sideways_move_between_two_communities() {
    let row = row_in_community("room-a");
    let err = share_plan(
        &row,
        &Audience::Community {
            community_key_id: "room-b".to_owned(),
        },
    )
    .expect_err(
        "re-targeting a community row at a DIFFERENT community must be refused — \
         if this is now Ok, `enter_mesh_at` will run `enter_mesh` and then a \
         widening that persist refuses, leaving the row in the mesh on the way \
         to reporting an error",
    );
    assert!(
        err.contains("room-a") || err.to_lowercase().contains("wider"),
        "the refusal must NAME the audience axis so an operator can act on it; got: {err}"
    );
}

/// The control: the same row, asked for the audience it already has, is a no-op
/// — so the fix did not turn every idempotent call into a refusal.
#[test]
fn the_same_community_is_still_already_there() {
    let row = row_in_community("room-a");
    assert_eq!(
        share_plan(
            &row,
            &Audience::Community {
                community_key_id: "room-a".to_owned(),
            },
        )
        .expect("a row asked for its own audience is idempotent, not a refusal"),
        SharePlan::AlreadyThere,
        "a federation-tier row already at the target audience has nothing to do"
    );
}

/// And a genuine widening still plans as one. Without this the two tests above
/// would also pass on a `share_plan` that refused everything.
#[test]
fn a_genuine_widening_still_plans_as_one() {
    let row = row_in_community("room-a");
    assert_eq!(
        share_plan(&row, &Audience::Federation)
            .expect("community → federation is strictly wider and must plan"),
        SharePlan::Widen(Audience::Federation),
        "the row is already in the mesh, so the plan is the widening alone"
    );
}
