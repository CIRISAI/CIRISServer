//! **The operations catalogue** — every graded act this node offers, enumerated.
//!
//! `GET /v1/operations`, the companion to [`crate::vocabulary_surface`]. That route
//! answers *"what values may I choose?"*; this one answers *"what may I do, what
//! does it cost, and what undoes it?"*
//!
//! # Why this exists
//!
//! Adding an operation used to be a full cycle: a route here, a method in the
//! Kotlin client, a card in the moderation screen, and a hardcoded opinion — in
//! the client — about the op's tier, its required scope, and whether it could be
//! reversed. Four places, three of them downstream, and nothing failing if they
//! disagreed.
//!
//! That is the same defect this repo asked CIRISPersist#625 to fix one layer down,
//! committed here: **fifteen `OP_*` constants with no `ALL`, seven
//! `REQUIRED_SCOPE_*` with no table binding them to an op, and reversal pairs that
//! existed only in prose.** A client could not render the ladder without
//! re-deriving all three by hand.
//!
//! With this catalogue, adding an operation is adding a row. The UI renders what
//! it is told, so a new op appears with its correct tier, scope and inverse, and
//! an op whose scope changes cannot go on showing the old one.
//!
//! # What a row carries, and why each field is load-bearing
//!
//! - `route` — so the client does not build URLs from op names. `refuse_writes`
//!   posts to `/v1/admin/refuse-writes`; the underscore/hyphen split is real and
//!   has bitten before.
//! - `tier` — the ladder position. Ordered by IRREVERSIBILITY, not blast radius.
//! - `scope` — the delegation scope the caller must hold, drawn from persist's
//!   vocabulary, never spelled here.
//! - `quorum` — how many independent chains. Tier 3 needs more than one; a UI that
//!   assumed 1 would collect one signature and fail at commit.
//! - `reverses` — the op that undoes this one, or `None`. **A UI must be able to
//!   say "this is undoable by X" BEFORE the operator commits**, which is exactly
//!   when it matters and exactly when prose in a Rust doc-comment is unreachable.
//! - `reaches_substrate` — whether the act changes what the substrate accepts, as
//!   opposed to only what this node records. The two tier-4 acts and their
//!   reversals do; annotate does not. This is the difference between "we noted it"
//!   and "the door is shut", and an operator is entitled to know which they are
//!   about to perform.

use axum::{response::IntoResponse, routing::get, Json, Router};
use ciris_persist::federation::hard_case::admin_op;
use ciris_persist::federation::types::delegation_scope;
use serde_json::json;

/// `GET /v1/operations` — the graded-act ladder, enumerated.
pub const ROUTE: &str = "/v1/operations";

/// One graded act.
pub struct Operation {
    /// Stable op token — the same string the ledger records as `admin_action:{op}`.
    pub op: &'static str,
    /// The route to POST to. Not derivable from `op`: see the module docs.
    pub route: &'static str,
    /// Ladder position. `None` for the read-only preview, which is not graded.
    pub tier: Option<u8>,
    /// The delegation scope the caller must hold, from persist's vocabulary.
    pub scope: Option<&'static str>,
    /// Independent delegation chains required.
    pub quorum: usize,
    /// The op that undoes this one.
    pub reverses: Option<&'static str>,
    /// Whether the act changes what the SUBSTRATE accepts, not just what this node
    /// records.
    pub reaches_substrate: bool,
}

/// Every graded act, in ladder order.
///
/// The single source. `scope` values come from `delegation_scope`, so a scope
/// renamed upstream fails to compile HERE rather than rendering a stale option in
/// a picker.
///
/// Note `quarantine` takes `slash`, not `moderate`: the FSD ladder says tier 2 is
/// `moderate` and persist's admission door says `slash`. The substrate wins, and
/// this table states the enforced value rather than the documented one — a
/// catalogue that repeated the FSD would send operators to collect an authority
/// the gate then refuses.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        op: "preview",
        route: "/v1/admin/preview",
        tier: None,
        scope: None,
        quorum: 0,
        reverses: None,
        reaches_substrate: false,
    },
    Operation {
        op: "annotate",
        route: "/v1/admin/annotate",
        tier: Some(0),
        scope: Some(delegation_scope::SCOPE_REVIEW),
        quorum: 1,
        reverses: None,
        reaches_substrate: false,
    },
    Operation {
        op: "throttle",
        route: "/v1/admin/throttle",
        tier: Some(1),
        scope: Some(delegation_scope::SCOPE_MODERATE),
        quorum: 1,
        reverses: Some("throttle_release"),
        reaches_substrate: false,
    },
    Operation {
        op: "throttle_release",
        route: "/v1/admin/un-throttle",
        tier: Some(1),
        scope: Some(delegation_scope::SCOPE_MODERATE),
        quorum: 1,
        reverses: None,
        reaches_substrate: false,
    },
    Operation {
        op: admin_op::QUARANTINE,
        route: "/v1/admin/quarantine",
        tier: Some(2),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 1,
        reverses: Some(admin_op::QUARANTINE_RELEASE),
        reaches_substrate: false,
    },
    Operation {
        op: admin_op::QUARANTINE_RELEASE,
        route: "/v1/admin/un-quarantine",
        tier: Some(2),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 1,
        reverses: None,
        reaches_substrate: true,
    },
    Operation {
        op: "descend",
        route: "/v1/admin/descend",
        tier: Some(3),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 2,
        reverses: None,
        reaches_substrate: true,
    },
    Operation {
        op: admin_op::DE_ADMISSION,
        route: "/v1/admin/deadmit",
        tier: Some(4),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 1,
        reverses: Some(crate::admin_ops::OP_RE_ADMISSION),
        reaches_substrate: true,
    },
    Operation {
        op: "re_admission",
        route: "/v1/admin/re-admit",
        tier: Some(4),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 1,
        reverses: None,
        reaches_substrate: true,
    },
    Operation {
        op: "refuse_writes",
        route: "/v1/admin/refuse-writes",
        tier: Some(4),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 1,
        reverses: Some("accept_writes"),
        reaches_substrate: true,
    },
    Operation {
        op: "accept_writes",
        route: "/v1/admin/accept-writes",
        tier: Some(4),
        scope: Some(delegation_scope::SCOPE_SLASH),
        quorum: 1,
        reverses: None,
        reaches_substrate: true,
    },
];

/// How a client runs an op over many subjects — **and the limit that makes it
/// painful today**.
///
/// `Selection.attesting_key_id` is `Option<String>`: ONE key. Acting on 61
/// exposed keys is currently 61 preview→commit pairs.
///
/// **That is a limitation, not a design.** The safety property the ladder
/// actually needs is *what was previewed is what executes* — one HASH, not one
/// SUBJECT. A preview over a 61-key selection yields one hash over that row set
/// and is equally TOCTOU-closed, with one authority walk and one ledger entry
/// saying "these 61, for this reason". Per-subject iteration buys no safety and
/// costs an operator 61 decisions where they made one.
///
/// It also does not survive the mesh this is built for. At millions of nodes a
/// moderation act must address a SET — by list or by predicate — or it cannot be
/// performed at all. `Selection` is already a predicate query in every other
/// dimension; only the key fields are singular, and `dimension_prefixes` in the
/// same struct is already an OR-combined `Vec<String>`.
///
/// Tracked as CIRISPersist#627 (set-valued key predicates in `AttestationFilter`,
/// pushed into the query as `IN (…)`, never an application-side loop — the #343
/// rule). Until it lands, a client batches and reports per subject; after it
/// lands, this constant changes and the client stops looping.
pub const SELECTION_CARDINALITY: &str = "one_subject_per_act_pending_persist_627";

async fn get_operations() -> impl IntoResponse {
    Json(json!({
        "selection_cardinality": SELECTION_CARDINALITY,
        // Every mutating call carries these, whatever the op.
        "commit_fields": ["selection", "selection_hash", "delegation_id", "reason"],
        "operations": OPERATIONS.iter().map(|o| json!({
            "op": o.op,
            "route": o.route,
            "tier": o.tier,
            "scope": o.scope,
            "quorum": o.quorum,
            "reverses": o.reverses,
            "reaches_substrate": o.reaches_substrate,
        })).collect::<Vec<_>>(),
    }))
}

/// The operations router. Ungated for the same reason as the vocabulary: knowing
/// an act EXISTS and what authority it needs is not itself privileged, and a UI
/// must render the ladder — including the rungs the operator cannot reach — to
/// explain why one is unavailable.
pub fn router() -> Router {
    Router::new().route(ROUTE, get(get_operations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every catalogued route is one the server actually registers.
    ///
    /// The failure this prevents is specific and silent: a catalogue entry with a
    /// wrong route renders a button that 404s. The client trusts this table
    /// completely — it does not build URLs — so a typo here IS a broken control,
    /// not a cosmetic error.
    #[test]
    fn every_catalogued_route_is_registered() {
        let src = include_str!("admin_ops.rs");
        let mut missing = Vec::new();
        for o in OPERATIONS {
            if !src.contains(&format!("\"{}\"", o.route)) {
                missing.push(o.route);
            }
        }
        assert!(
            missing.is_empty(),
            "catalogued route(s) {missing:?} are not registered in admin_ops.rs — \
             the UI would render a control that 404s. Checked {} operations.",
            OPERATIONS.len()
        );
    }

    /// Every scope named is a real delegation scope.
    ///
    /// Sourced from persist so this cannot drift, but asserted anyway: the
    /// catalogue is what tells an operator which authority to go and obtain, and
    /// sending them for a scope no gate accepts wastes a ceremony.
    #[test]
    fn every_scope_is_in_the_substrate_vocabulary() {
        for o in OPERATIONS {
            if let Some(s) = o.scope {
                assert!(
                    delegation_scope::ALL.contains(&s),
                    "operation {:?} requires scope {s:?}, absent from delegation_scope::ALL",
                    o.op
                );
                assert!(
                    delegation_scope::MODERATION.contains(&s),
                    "operation {:?} requires {s:?}, which is not a MODERATION scope. \
                     Graded acts on other keys are moderation authority; if this is \
                     deliberate the axis split needs revisiting, not this assertion.",
                    o.op
                );
            }
        }
    }

    /// Reversals point at real ops, and are not circular.
    ///
    /// A UI states "undoable by X" before the operator commits. If X does not
    /// exist, that promise is false at the moment it is most load-bearing.
    #[test]
    fn reversals_resolve_and_do_not_loop() {
        let ops: BTreeSet<&str> = OPERATIONS.iter().map(|o| o.op).collect();
        for o in OPERATIONS {
            let Some(r) = o.reverses else { continue };
            assert!(
                ops.contains(r),
                "{:?} reverses {r:?}, which is not an op",
                o.op
            );
            let rev = OPERATIONS.iter().find(|x| x.op == r).expect("present");
            assert_ne!(
                rev.reverses,
                Some(o.op),
                "{:?} and {r:?} reverse each other — a UI walking the chain would not terminate",
                o.op
            );
        }
    }

    /// Op tokens are unique, and every one is a CONSTANT rather than a literal.
    ///
    /// The ledger records `admin_action:{op}`. A token that drifts from the
    /// constant the handler uses produces a catalogue naming an act the audit
    /// trail calls something else, and no query joins them.
    ///
    /// **The vocabulary is split across two repos, which is what this catches.**
    /// Persist's `admin_op` vocabulary is OPEN — it names `quarantine`,
    /// `quarantine_release` and `de_admission` itself, and the rest are minted in
    /// `admin_ops.rs`. The first version of this table guessed the tokens from
    /// the ROUTES and got all three wrong: `/v1/admin/un-quarantine` records
    /// `quarantine_release`, and `/v1/admin/deadmit` records `de_admission`.
    ///
    /// So the rule is that a token must come from a constant, never a literal.
    /// The persist-owned three are sourced from `admin_op::*` and are therefore
    /// correct by construction; the rest must appear in `admin_ops.rs`. A literal
    /// added here would satisfy neither and fail below.
    #[test]
    fn op_tokens_are_unique_and_match_the_ledger() {
        let ops: Vec<&str> = OPERATIONS.iter().map(|o| o.op).collect();
        let uniq: BTreeSet<&str> = ops.iter().copied().collect();
        assert_eq!(ops.len(), uniq.len(), "duplicate op token in the catalogue");

        // Owned by persist and sourced from its constants — correct by
        // construction, and NOT findable in admin_ops.rs.
        let persist_owned: BTreeSet<&str> = [
            admin_op::QUARANTINE,
            admin_op::QUARANTINE_RELEASE,
            admin_op::DE_ADMISSION,
        ]
        .into_iter()
        .collect();

        let src = include_str!("admin_ops.rs");
        let mut unbacked = Vec::new();
        let mut checked = 0usize;
        for o in OPERATIONS {
            if o.op == "preview" {
                continue; // read-only, not a graded act, no OP_ constant
            }
            if persist_owned.contains(o.op) {
                continue;
            }
            checked += 1;
            if !src.contains(&format!("= \"{}\"", o.op)) {
                unbacked.push(o.op);
            }
        }
        assert!(
            checked > 0,
            "checked ZERO locally-minted tokens — the exemption list has swallowed the \
             whole catalogue and this test proves nothing"
        );
        assert!(
            unbacked.is_empty(),
            "op token(s) {unbacked:?} have no matching OP_* constant in admin_ops.rs and \
             are not persist-owned — the catalogue and the audit ledger would name the \
             same act differently. Checked {checked} locally-minted token(s)."
        );
    }

    /// The catalogue covers the ladder it claims to.
    ///
    /// A zero denominator, and a partial one, are both failures: a catalogue
    /// missing tier 4 renders a UI with no write door and no indication one exists.
    #[test]
    fn the_ladder_is_complete() {
        assert!(!OPERATIONS.is_empty(), "empty catalogue");
        let tiers: BTreeSet<u8> = OPERATIONS.iter().filter_map(|o| o.tier).collect();
        for t in 0..=4u8 {
            assert!(
                tiers.contains(&t),
                "tier {t} has no operation in the catalogue"
            );
        }
    }
}
