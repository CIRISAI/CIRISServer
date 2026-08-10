//! **The wire vocabularies, served to the operator UI** — `GET /v1/vocabulary`.
//!
//! Every value an operator SELECTS must come from the substrate's own vocabulary,
//! never from a literal typed into a client. This route is how that is possible.
//!
//! # Why this exists rather than a list in the client
//!
//! A hand-mirrored literal is the defect this repo has spent months eliminating —
//! `tests/envelope_vocabulary_single_source.rs` exists because a hand-copied
//! envelope key COMPILES and SKEWS THE WIRE. A hardcoded scope list in a Kotlin
//! client has both halves of that: a scope added upstream never appears in the
//! picker, and a typo does not fail to compile — it renders a plausible option
//! that no gate accepts. The operator selects it, the act is refused, and the
//! refusal names the scope they chose.
//!
//! So the sets are read from `ciris_persist::federation::types` at request time.
//! **Nothing in this file spells a vocabulary member.** Adding a scope upstream
//! makes it appear here with no change on this side, which is the entire point;
//! if you find yourself typing a member into this file, the design has failed.
//!
//! # The axis split is constitutional, not cosmetic
//!
//! `delegation_scope` carries three axes and persist enforces the boundary at the
//! write gate (CC 4.4.3.4.3 — *infrastructure must not have agency*):
//!
//! - `INFRA` — what infrastructure may do (`infra:serve`, `infra:attest`, …)
//! - `AGENCY` — what an actor with agency may do (`agency:*`)
//! - `MODERATION` — what a moderator may do (`slash`, `moderate`, `review`, `takedown`)
//!
//! They are shipped as SEPARATE sets alongside `all`, because a picker is never
//! "choose a scope" in the abstract — it is "choose what this delegation
//! authorises", and the ACT fixes the axis. `refuse-writes` needs `slash`;
//! blessing a canonical needs `infra:serve` + `infra:attest`. A screen offering
//! all twenty invites an operator to grant agency to infrastructure and learn
//! about CC 4.4.3.4.3 from a refusal.
//!
//! `all` is still served, because a VALIDATOR needs the union — `scope` is one
//! wire field and any member is legal in it. Union for checking, subsets for
//! choosing; neither consumer re-deriving the other's list is the whole reason
//! both are here (CIRISPersist#625).

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use ciris_persist::federation::types::{
    attestation_type, cohort_scope, consent_state, delegation_scope, device_class, identity_type,
    transmission_principle,
};
use serde_json::json;

/// `GET /v1/vocabulary` — every enumerable wire vocabulary, for populating pickers.
pub const ROUTE: &str = "/v1/vocabulary";

/// Read-only; the sets are compile-time constants, so there is no state to hold.
#[derive(Clone)]
pub struct VocabularyState;

/// The vocabularies, exactly as persist defines them.
///
/// Shape is `{ "<name>": { "all": [...], "<subset>": [...] } }` so a client can
/// bind one picker per (vocabulary, axis) without knowing which vocabularies have
/// axes. A vocabulary with no axis simply has one key.
async fn get_vocabulary(State(_): State<VocabularyState>) -> impl IntoResponse {
    Json(json!({
        // Sourced, never spelled. Every array below is a persist constant.
        "delegation_scope": {
            "all": delegation_scope::ALL,
            // The constitutional axis (CC 4.4.3.4.3). See the module docs: a
            // picker binds ONE of these, chosen by the act it authorises.
            "infra": delegation_scope::INFRA,
            "agency": delegation_scope::AGENCY,
            "moderation": delegation_scope::MODERATION,
        },
        "identity_type":          { "all": identity_type::ALL },
        "attestation_type":       { "all": attestation_type::ALL },
        "cohort_scope":           { "all": cohort_scope::ALL },
        "device_class":           { "all": device_class::ALL },
        "transmission_principle": { "all": transmission_principle::ALL },
        "consent_state":          { "all": consent_state::ALL },
    }))
}

/// The vocabulary router. Deliberately UNGATED: these are the substrate's public
/// value sets, not node state. Gating them would mean a login screen could not
/// render a device-class picker, and there is nothing here an operator could not
/// read from the persist source.
pub fn router() -> Router {
    Router::new()
        .route(ROUTE, get(get_vocabulary))
        .with_state(VocabularyState)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every vocabulary the UI binds is non-empty and served.
    ///
    /// The zero-denominator rule applies to vocabularies too: an empty set does
    /// not render an empty picker, it renders a picker the operator cannot use,
    /// and they will report it as "the dropdown is broken" rather than "the
    /// substrate exposes no members".
    #[tokio::test]
    async fn every_vocabulary_is_served_and_non_empty() {
        let body = get_vocabulary(State(VocabularyState)).await.into_response();
        let bytes = axum::body::to_bytes(body.into_body(), usize::MAX)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let obj = v.as_object().expect("object");

        assert_eq!(obj.len(), 7, "all seven vocabularies are served");
        for (name, sets) in obj {
            let sets = sets.as_object().expect("sets object");
            assert!(!sets.is_empty(), "{name} has no sets");
            for (axis, members) in sets {
                let members = members.as_array().expect("array");
                assert!(
                    !members.is_empty(),
                    "{name}.{axis} is EMPTY — a picker bound to it cannot be used"
                );
            }
        }
    }

    /// The axis subsets partition without inventing members.
    ///
    /// A subset containing a value absent from `all` would offer the operator a
    /// scope no validator accepts — the exact failure this route exists to make
    /// impossible, reintroduced by a bad partition.
    #[test]
    fn every_axis_member_is_also_in_all() {
        for (axis, set) in [
            ("infra", delegation_scope::INFRA),
            ("agency", delegation_scope::AGENCY),
            ("moderation", delegation_scope::MODERATION),
        ] {
            assert!(!set.is_empty(), "{axis} is empty");
            for m in set {
                assert!(
                    delegation_scope::ALL.contains(m),
                    "delegation_scope::{axis} offers {m:?}, which is not in ALL — \
                     a picker bound to it would propose a scope no gate accepts"
                );
            }
        }
    }

    /// This file spells no vocabulary member.
    ///
    /// The one property that keeps the route honest. If a member is ever typed
    /// here, upstream additions stop appearing and this route becomes the second
    /// copy it was built to avoid.
    #[test]
    fn this_module_hardcodes_no_member() {
        let src = include_str!("vocabulary_surface.rs");
        let code: String = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("//!") && !t.starts_with("///")
            })
            .collect::<Vec<_>>()
            .join("\n");

        let mut leaked = Vec::new();
        for m in delegation_scope::ALL
            .iter()
            .chain(identity_type::ALL)
            .chain(attestation_type::ALL)
            .chain(cohort_scope::ALL)
            .chain(transmission_principle::ALL)
            .chain(consent_state::ALL)
        {
            if code.contains(&format!("\"{m}\"")) {
                leaked.push(*m);
            }
        }
        assert!(
            leaked.is_empty(),
            "vocabulary_surface.rs spells member(s) {leaked:?} as literals. Source them \
             from ciris_persist::federation::types instead — a literal here stops \
             upstream additions from reaching the picker, which is what this route exists \
             to prevent."
        );
    }
}
