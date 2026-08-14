//! **The graded admin-op ladder** — tiers 0–4 (CIRISServer#346, adoption debt
//! #361), plus tiers S and R (CIRISServer#345). The owner-gated routes that
//! make the substrate's removal primitives reachable from this node.
//!
//! Every primitive these routes call shipped in persist and had **zero callers
//! here** (#361: seven for seven). The mesh was manageable; this node could not
//! manage it. This module is the caller.
//!
//! Tiers 0–4 all act on someone else. The two rungs that do not are the last
//! two sections of this file: **tier S** (self-directed — and the only rung
//! reachable under partition) and **tier R** (subject-side — the reader's own
//! accept/refuse policy, which is the property NoCeM actually had).
//!
//! ```text
//! POST /v1/admin/preview      read-only  -> exact row set + counts + SELECTION HASH
//! POST /v1/admin/annotate     tier 0     scope: review
//! POST /v1/admin/throttle     tier 1     scope: moderate     (+ un_throttle)
//! POST /v1/admin/quarantine   tier 2     scope: moderate*    (+ un_quarantine)
//! POST /v1/admin/descend      tier 3     scope: slash + QUORUM
//! POST /v1/admin/deadmit      tier 4     scope: slash        (+ re_admit)
//! POST /v1/admin/refuse-writes tier 4    scope: slash        (+ accept_writes)
//! ```
//!
//! `*` — see [`REQUIRED_SCOPE_QUARANTINE`]. The FSD ladder says tier 2 is
//! `moderate`; persist's own admission door says `slash`. The substrate wins.
//!
//! # Tier 4 is two acts, not one (CIRISServer#375)
//!
//! `deadmit` writes a signed [`Revocation`] on the append-only key plane, and
//! says so in its own response: *"evidence a reader folds, **not a door that
//! slams**"* — signature verification, the replication cursors and row ingest
//! all deliberately keep working, because refusing a compromised key's older
//! rows would destroy the evidence needed to adjudicate the compromise. That is
//! the right act for a **compromised** key.
//!
//! `refuse-writes` emits persist's AV-77 `revocation:peer_admission:v1` row,
//! which `check_peer_deadmission` reads at `put_attestation` to refuse that
//! key's NEXT write — the only primitive in the stack that stops a hostile
//! admitted peer. `compose::arm_peer_deadmission_gate` armed it at boot and
//! refused to serve if the arming did not stick; nothing here emitted the row,
//! so the one control that closes the door was armed, proven armed, and
//! unreachable. This is the caller.
//!
//! Same rung and the same `slash` authority, walked by the same
//! [`resolve_authority`], because both act on a key. Separate routes and
//! separate `admin_action:{op}` suffixes because they reach different things,
//! and a ledger that spelled them alike could not answer *"which did we do?"*.
//! `refuse-writes` takes ONE chain rather than tier 3's quorum for the reason
//! the 344-failure audit gave: gating is ordered by irreversibility, not by
//! blast radius, and this reversal genuinely reaches the substrate. Two of the
//! ladder's reversals do — `un-quarantine` restores what this node SERVES,
//! `accept-writes` restores what it ACCEPTS — and they are the two rungs whose
//! reversal is more than a record.
//!
//! # The five properties, each gated by a test in `tests/admin_ops.rs`
//!
//! 1. **Preview-hash commit.** Every mutating call presents the hash its
//!    preview returned; a mismatch REFUSES ([`SELECTION_HASH_VERSION`],
//!    [`selection_hash`]). What was previewed is what executes — TOCTOU-closed,
//!    and the left-pad rule: a retraction needs a blast-radius check, as a gate
//!    rather than a convenience. The preview is an [`AttestationFilter`]
//!    push-down (the UI's filter IS the query filter) — the #343 read pattern
//!    `graph_config::live_config_rows` established, never the whole-corpus
//!    self-authored scan that cost a 152-second boot phase.
//! 2. **Authority in the artifact.** `{delegation_id, reason}` are REQUIRED in
//!    every tombstone and the call is refused without them. Persist enforces
//!    this independently at `record_hard_case`
//!    (`check_admin_action_attribution`) and at the quarantine door
//!    (`QuarantineRefusalReason::Unattributed`); this module refuses first so
//!    the operator gets a localizable reason instead of a substrate error.
//!    *An action that does not carry its own authority cannot be told from an
//!    unauthorized one once the actor is gone.*
//! 3. **Reversal ops exist.** `un_throttle`, `un_quarantine`, `re_admit` are
//!    routes, not adjectives. What each one actually reverses is reported
//!    honestly per op — see [`ReversalReach`].
//! 4. **Tier 3 takes quorum, not one delegation chain.** It is the only
//!    irreversible op, and gating by irreversibility rather than blast radius
//!    is the correction the 344-failure audit forced.
//!    [`DESCEND_QUORUM_MIN`] distinct authority roots, each independently
//!    re-derived from this node's own verified state.
//! 5. **Tier 3 accepts an optional `after:`** — the time-bounded judgement a
//!    key compromise needs. It is a real [`AttestationFilter::window`]
//!    push-down, so it changes the selection AND the hash.
//!
//! # Authority is re-derived, never asserted (#377)
//!
//! A caller names a `delegation_id`. This module does NOT trust it: it resolves
//! the row, requires it to be a live `delegates_to` **to the acting key**, and
//! then re-walks `reachable_under_scope(issuer → actor, scope)` — persist's own
//! §11.10 walk (⊆-attenuation, `sub_delegation` deputization, per-edge
//! `withdraws` skipping, depth ≤
//! [`MAX_MODERATION_DELEGATION_DEPTH`](ciris_persist::federation::admission::MAX_MODERATION_DELEGATION_DEPTH)).
//! The recorded `delegation_id` is therefore an id that WAS checked, not one
//! that was merely written down.
//!
//! # Why `CapabilityVerb::Wipe`
//!
//! Every route here is gated on the never-delegatable
//! [`Wipe`](crate::auth::gate::CapabilityVerb::Wipe) verb rather than a new
//! per-tier verb. Consequence, stated rather than discovered later: **no
//! delegated bearer token may run a graded admin op — only the owner
//! directly.** The graded part of the authority is the persist-side delegation
//! scope (`review` / `moderate` / `slash`), which is where the ladder actually
//! lives; the verb layer is about what a *delegated session* may do, and the
//! fail-secure answer there is "none of this".
//!
//! # Operator-facing strings
//!
//! Every human-readable string is a `{id, text}` pair, like
//! [`crate::peer::consent_disclosure_json`]. `id` is a stable message key;
//! `text` is the English source. **Never hand a UI a pre-formatted sentence.**
//! The ids are wire-stable: renaming one silently un-translates that string in
//! every locale. If the MEANING changes, mint a new id (`…:v2`).
//!
//! # Tier S — self-directed (CIRISServer#345)
//!
//! ```text
//! GET  /v1/admin/self                    the three standings, never folded together
//! POST /v1/admin/self/shed               shed my own load        (+ resume-load)
//! POST /v1/admin/self/stop-accepting     stop accepting          (+ resume-accepting)
//! POST /v1/admin/self/compelled          declare legal compulsion(+ compulsion-lifted)
//! ```
//!
//! Every rung above acts on someone else. Tier S is the only one available
//! under **partition** — a node that cannot reach its peers can still act on
//! itself — so every call on it is local: the owner-binding walk, the config
//! write and the tombstone all touch this node's own database and nothing
//! else. See [`SelfAct`].
//!
//! Its authority is the **owner-binding**, re-derived exactly like every other
//! rung's ([`REQUIRED_SCOPE_SELF_DIRECTED`]) and additionally required to be
//! issued by the party [`is_steward_bound`](crate::auth::ownership::is_steward_bound)
//! resolves as this node's responsible party — a third party's `infra:serve`
//! grant is not the owner's.
//!
//! # Tier R — subject-side / per-reader (CIRISServer#345)
//!
//! ```text
//! POST /v1/admin/reader/fold             read-only: what THIS reader does with what it holds
//! POST /v1/admin/reader/honour           adopt one judgement
//! POST /v1/admin/reader/decline          refuse one judgement   (a NORMAL outcome)
//! ```
//!
//! NoCeM's actual property: a signed judgement takes effect at a consumer that
//! *chose* to honour that signer. Tiers 1–4 apply automatically at the
//! consumer, which is the property NoCeM was invented to avoid; tier R is the
//! reader's own accept/refuse policy over other parties' judgements, and a
//! decline is a **first-class outcome, never an error**.
//!
//! The reader's policy is not invented here: it is this node's own
//! subscription set
//! ([`trusted_roots_of`](ciris_persist::federation::trust_root::trusted_roots_of)),
//! composed with persist's own scoped-delegation walk and folded by persist's
//! own **pure** [`fold_quarantine`](ciris_persist::federation::quarantine::fold_quarantine).
//! Only the *which signers* predicate is ours — the same shape
//! `fold_mesh_config(…, roots, …)` already takes. See [`ReaderDecision`].
//!
//! # Deliberately NOT here
//!
//! Everything on the mesh-config plane; that surface is
//! [`crate::mesh_config_surface`]. Tier S writes NOTHING there — see
//! [`SelfAct::enforcement`] for what each self-directed act does and does not
//! reach, stated in the response rather than left to be assumed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ciris_persist::ceg::list::federation::AttestationFilter;
use ciris_persist::federation::admission::{
    DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW, DELEGATION_SCOPE_SLASH,
    MAX_MODERATION_DELEGATION_DEPTH,
};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::hard_case::{
    admin_action_event, admin_action_kind, admin_field, admin_op, HardCaseEvent, HardCaseFilter,
};
use ciris_persist::federation::quarantine;
use ciris_persist::federation::trust_root::trusted_roots_of;
use ciris_persist::federation::types::{
    attestation_type, cohort_scope, Attestation, Revocation, SignedRevocation,
};
use ciris_persist::prelude::{CallerScope, Engine};

use crate::auth::gate::CapabilityVerb;
use crate::auth::ownership::{is_steward_bound, INFRA_SERVE};
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

// ═══════════════════════════════════════════════════════════════════════════
//  Vocabulary
// ═══════════════════════════════════════════════════════════════════════════

/// The delegation scope tier 0 (`annotate`) requires — a signed judgement with
/// no effect until honoured needs the review duty, nothing more.
pub const REQUIRED_SCOPE_ANNOTATE: &str = DELEGATION_SCOPE_REVIEW;

/// The delegation scope tier 1 (`throttle` / `un_throttle`) requires.
pub const REQUIRED_SCOPE_THROTTLE: &str = DELEGATION_SCOPE_MODERATE;

/// The delegation scope tier 2 (`quarantine` / `un_quarantine`) requires.
///
/// **This is `slash`, and the FSD ladder says `moderate`.** The divergence is
/// persist's, and persist is right to own it: a quarantine marker takes
/// something away, so
/// `check_delegated_duty_scores_admission`'s `QUARANTINE_DIMENSION_PREFIX` arm
/// gates it on `slash` — *"there is no laxer path for the harsher op"*. A route
/// that advertised `moderate` here would be advertising an authority the
/// substrate refuses at the door, which is the worst of both: the operator is
/// told they may act and the write fails anyway.
pub const REQUIRED_SCOPE_QUARANTINE: &str = DELEGATION_SCOPE_SLASH;

/// The delegation scope tier 3 (`descend`) requires — of EVERY quorum member.
pub const REQUIRED_SCOPE_DESCEND: &str = DELEGATION_SCOPE_SLASH;

/// The delegation scope tier 4 (`deadmit` / `re_admit`) requires.
pub const REQUIRED_SCOPE_DEADMIT: &str = DELEGATION_SCOPE_SLASH;

/// The delegation scope tier 4's **write-door** arm (`refuse_writes` /
/// `accept_writes`) requires.
///
/// The SAME scope, walked by the SAME [`resolve_authority`], as the revocation
/// arm beside it. Stated as its own constant rather than reusing
/// [`REQUIRED_SCOPE_DEADMIT`] by aliasing, so that a future change to one act's
/// authority is a visible change to one line and not an accident to the other —
/// but it is deliberately the same value: **there is no laxer path for the
/// harsher op.** That inversion has been found in this repo before (the FSD
/// ladder advertised `moderate` for tier 2 while persist's own door required
/// `slash`), and refusing a key's next write is strictly harsher than recording
/// a revocation a reader may or may not fold.
pub const REQUIRED_SCOPE_REFUSE_WRITES: &str = DELEGATION_SCOPE_SLASH;

/// **Tier 3 quorum floor** — distinct authority ROOTS (not distinct
/// `delegation_id`s: two chains from one root are one authority wearing two
/// hats) that must each independently reach the acting key under `slash`.
///
/// Two, not three: the audit's correction was that tier 3 needed *more than one
/// delegation chain*, and a floor that cannot be met is a floor that gets
/// bypassed. Raising it is a one-line change with a test that reads the
/// constant.
pub const DESCEND_QUORUM_MIN: usize = 2;

/// `admin_action:{op}` suffix for tier 0. Persist's `admin_op` vocabulary is
/// OPEN (`ADMIN_ACTION_PREFIX` + any suffix); it names `quarantine`,
/// `quarantine_release` and `de_admission` itself, and the rest are minted
/// here.
pub const OP_ANNOTATE: &str = "annotate";
/// `admin_action:{op}` suffix for tier 1.
pub const OP_THROTTLE: &str = "throttle";
/// `admin_action:{op}` suffix for the tier 1 reversal.
pub const OP_THROTTLE_RELEASE: &str = "throttle_release";
/// `admin_action:{op}` suffix for tier 3.
pub const OP_DESCEND: &str = "descend";
/// `admin_action:{op}` suffix for the tier 4 reversal.
pub const OP_RE_ADMISSION: &str = "re_admission";
/// `admin_action:{op}` suffix for the tier 4 **write-door** act (AV-77).
///
/// Deliberately NOT `admin_op::DE_ADMISSION`, which the revocation arm beside it
/// already uses. They are two different acts — one stops the next write, one
/// records evidence a reader folds — and a ledger that spells them the same way
/// cannot answer *"which one did we actually do?"* after the fact. The
/// confusion IS the bug this route was filed against (CIRISServer#375).
pub const OP_REFUSE_WRITES: &str = "refuse_writes";
/// `admin_action:{op}` suffix for the reversal of [`OP_REFUSE_WRITES`] — the
/// only reversal on the ladder that reaches the substrate's WRITE door
/// (`un-quarantine` reaches the serve path; the other two are records).
pub const OP_ACCEPT_WRITES: &str = "accept_writes";

/// **The delegation scope every tier S and tier R op requires.**
///
/// `infra:serve` — "serve reads / relay / store / transport", the scope the CC
/// 3.2 owner-binding stamps
/// ([`OWNER_BINDING_INFRA_SCOPES`](crate::auth::ownership::OWNER_BINDING_INFRA_SCOPES)).
/// Both families change what THIS node does with its own serving: tier S sheds
/// or closes it, tier R decides whose judgements it honours about what it
/// serves. Neither is a duty over another party, so neither takes a moderation
/// scope a third party granted — which is also why tier S survives partition:
/// the only chain it walks is the one its owner already gave it.
pub const REQUIRED_SCOPE_SELF_DIRECTED: &str = INFRA_SERVE;

/// `admin_action:{op}` suffix — tier S, "shed my own load".
pub const OP_SELF_SHED: &str = "self_shed";
/// `admin_action:{op}` suffix — the tier S shed reversal.
pub const OP_SELF_SHED_RELEASE: &str = "self_shed_release";
/// `admin_action:{op}` suffix — tier S, "stop accepting".
pub const OP_SELF_STOP_ACCEPTING: &str = "self_stop_accepting";
/// `admin_action:{op}` suffix — the tier S stop-accepting reversal.
pub const OP_SELF_ACCEPTING_RESUMED: &str = "self_accepting_resumed";
/// `admin_action:{op}` suffix — tier S, "declare legal compulsion". **Its own
/// op, never a flavour of [`OP_SELF_STOP_ACCEPTING`]**: a reader has to be able
/// to tell *this node chose to stop* from *this node was made to stop*.
pub const OP_SELF_COMPELLED: &str = "self_compelled";
/// `admin_action:{op}` suffix — a declared compulsion has ended.
pub const OP_SELF_COMPULSION_LIFTED: &str = "self_compulsion_lifted";

/// `admin_action:{op}` suffix — tier R, "I honour this judgement".
pub const OP_READER_HONOUR: &str = "reader_honour";
/// `admin_action:{op}` suffix — tier R, "I do not honour this judgement".
/// Recorded as its own act because a decline is a decision, and the whole point
/// of the rung is that it is not an error.
pub const OP_READER_DECLINE: &str = "reader_decline";

/// Hard ceiling on the judgement set one tier R fold reads. A fold an operator
/// cannot read is not evidence.
///
/// **Above the ceiling the fold REFUSES; it never truncates.** Folding a
/// truncated marker set is fail-open by construction — drop the governing
/// withhold off the end of a page and the fold reports `not_quarantined`, which
/// is a release nobody signed. See [`judgement_page_refusal`].
pub const MAX_JUDGEMENT_PAGE: usize = 2_000;

/// Default page size for a preview. A bound, not a working set.
pub const DEFAULT_PREVIEW_LIMIT: i64 = 500;

/// Hard ceiling on a preview page. A selection an operator cannot read is a
/// selection they cannot ratify, and the hash would be a rubber stamp.
pub const MAX_PREVIEW_LIMIT: i64 = 2_000;

/// Version tag inside the selection-hash preimage. Bumping it invalidates every
/// outstanding preview by construction — which is the point: a hash whose
/// meaning changed silently is worse than no hash.
pub const SELECTION_HASH_VERSION: &str = "ciris-admin-selection:v1";

/// The locale the `text` half of every `{id, text}` pair is written in.
const SOURCE_LOCALE: &str = "en";

// ═══════════════════════════════════════════════════════════════════════════
//  Localizable strings
// ═══════════════════════════════════════════════════════════════════════════

/// One localizable string: a stable key plus its English source.
fn m(id: &str, text: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "text": text })
}

/// A refusal: a **stable program token** the caller can branch on, plus the
/// `{id, text}` pair a UI renders. Never a pre-formatted sentence.
fn refusal(code: StatusCode, token: &str, id: &str, text: &str) -> Response {
    (
        code,
        Json(serde_json::json!({
            "refused": true,
            "refusal": token,
            "source_locale": SOURCE_LOCALE,
            "message": m(id, text),
        })),
    )
        .into_response()
}

/// A non-refusal error (substrate unavailable, bad JSON) in the same shape, so
/// a caller has ONE response contract.
fn err(code: StatusCode, token: &str, id: &str, text: String) -> Response {
    (
        code,
        Json(serde_json::json!({
            "refused": true,
            "refusal": token,
            "source_locale": SOURCE_LOCALE,
            "message": m(id, &text),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
//  State + the owner gate
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct AdminOpsState {
    engine: Arc<Engine>,
}

/// THIS node's federation `key_id` — the ACTING key of every op here, the key
/// whose delegated authority is re-walked, and the identity every tombstone is
/// signed under.
///
/// **Resolved from the engine, never accepted as a parameter**
/// (CIRISServer#372 Level 2). It used to ride in [`AdminOpsState`] from
/// `compose`'s `cfg.key_id`, which begins life as the `--key-id` CLI *label*.
/// The key whose authority is walked and the key that signs the resulting
/// revocation must be ONE identity — in the embedded fold the label and the
/// engine signer differ, and an op authorised under one key but signed under
/// another is exactly the producer/attester disagreement `scorer.rs` names.
async fn self_key_id(st: &AdminOpsState) -> Result<String, Response> {
    crate::self_identity::resolve(&st.engine, "admin_ops")
        .await
        .map_err(|e| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                crate::self_identity::REFUSAL_TOKEN,
                crate::self_identity::MESSAGE_ID,
                format!("{} ({e})", crate::self_identity::MESSAGE_TEXT),
            )
        })
}

/// Owner-authority gate. Identical spine to
/// [`crate::federation_admin`]'s: `resolve_bearer → SessionCaller →
/// SYSTEM_ADMIN + FullAccess`. Both, so neither a role-permission drift nor a
/// permission-only check can silently widen who may remove other people's rows.
async fn require_owner(st: &AdminOpsState, headers: &HeaderMap) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_absent",
            "admin.refusal.session_absent",
            "No session token was presented. Graded admin operations are owner-only.",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(refusal(
            StatusCode::FORBIDDEN,
            "not_owner",
            "admin.refusal.not_owner",
            "Graded admin operations require the owner (SYSTEM_ADMIN) role.",
        )),
        Ok(None) => Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "admin.refusal.session_invalid",
            "That session is invalid or expired.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "admin.refusal.store_unavailable",
            format!("The substrate could not be read: {e}"),
        )),
    }
}

/// The gate stack every route in this module runs, in this order: serve-only
/// floor (an unowned node performs no judgement on anyone's behalf) → owner
/// session → the never-delegatable `Wipe` verb.
///
/// **Returns THIS node's resolved signing identity** so every route runs on the
/// one value the gate itself was evaluated against — the node whose
/// owner-binding was walked here and the node whose delegated authority is
/// re-walked below cannot be two different keys (CIRISServer#372 Level 2).
async fn gate(st: &AdminOpsState, headers: &HeaderMap) -> Result<String, Response> {
    let node_key_id = self_key_id(st).await?;
    if crate::auth::gate::require_owner_bound(&st.engine, &node_key_id)
        .await
        .is_err()
    {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "node_unowned",
            "admin.refusal.node_unowned",
            "This node has no responsible party (owner-binding), so it performs no graded \
             admin operation on anyone's behalf. Claim ownership first.",
        ));
    }
    let caller = require_owner(st, headers).await?;
    if let Some(resp) = crate::auth::gate::require_verb(&caller, CapabilityVerb::Wipe) {
        return Err(resp);
    }
    Ok(node_key_id)
}

// ═══════════════════════════════════════════════════════════════════════════
//  Selection — the UI's filter IS the query filter (#343)
// ═══════════════════════════════════════════════════════════════════════════

/// The operator's selection. Every field is an [`AttestationFilter`] predicate
/// pushed into the QUERY — there is no application-side `continue` anywhere in
/// this module, which is the whole #343 lesson.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct Selection {
    /// Rows authored BY this key (the key being judged, in almost every op).
    ///
    /// Singular; kept because most acts name one subject and because every
    /// stored selection predates the plural. Prefer [`Self::attesting_key_ids`]
    /// for a set — the two are OR-combined, not exclusive.
    #[serde(default)]
    pub attesting_key_id: Option<String>,
    /// Rows authored ABOUT this key.
    #[serde(default)]
    pub attested_key_id: Option<String>,
    /// **Rows authored BY ANY of these keys** (CIRISPersist#627, persist v30.9.0).
    ///
    /// One act, a whole population. Until persist made its own filter
    /// set-valued, a moderation act could name exactly one subject, so clearing
    /// the 61 exposed keys of CIRISServer#383 meant 61 preview→commit pairs —
    /// 61 hashes, 61 reasons, 61 authority walks against a tier-4 door. At the
    /// scale this mesh is for, that is not slow, it is unusable.
    ///
    /// The guarantee was never harmed by this: preview-hash commit is a property
    /// of the HASH, not of the cardinality. A preview over 61 keys yields one
    /// hash over that row set, is exactly as TOCTOU-closed, and audits BETTER —
    /// one decision, one reason, one ledger entry naming the set, rather than 61
    /// rows a reader has to infer were a single act.
    ///
    /// OR-combined with the singular field and pushed into the query as
    /// `IN (…)`. Still no application-side loop: that is the #343 rule, and
    /// moving the loop from the query into the operator would have broken it
    /// just as thoroughly as moving it into this module.
    #[serde(default)]
    pub attesting_key_ids: Vec<String>,
    /// **Rows authored ABOUT ANY of these keys** — see [`Self::attesting_key_ids`].
    #[serde(default)]
    pub attested_key_ids: Vec<String>,
    /// `scores` / `delegates_to` / `withdraws` / …
    #[serde(default)]
    pub attestation_type: Option<String>,
    /// Hierarchical dimension prefixes, OR-combined.
    #[serde(default)]
    pub dimension_prefixes: Vec<String>,
    /// Exact dimension match, AND-composed with the prefix set.
    #[serde(default)]
    pub dimension_exact: Option<String>,
    /// Rows naming this subject.
    #[serde(default)]
    pub subject_key_id: Option<String>,
    /// **The time bound.** Half-open `[after, before)` on `asserted_at`,
    /// pushed down as [`AttestationFilter::window`]. Tier 3's optional
    /// `after:` is this field — the time-bounded judgement a key compromise
    /// needs, and it changes the selection hash because it changes the
    /// selection.
    #[serde(default)]
    pub after: Option<DateTime<Utc>>,
    /// Upper bound of the window. Omitted ⇒ "now" at preview time is NOT used
    /// (that would make the hash time-varying); omitted means unbounded above.
    #[serde(default)]
    pub before: Option<DateTime<Utc>>,
    /// Page bound, clamped to [`MAX_PREVIEW_LIMIT`].
    #[serde(default)]
    pub limit: Option<i64>,
}

impl Selection {
    /// Trim / drop-empty / sort / dedupe, so two spellings of one selection
    /// hash identically.
    fn normalized(&self) -> Self {
        /// Trim, drop blanks, dedupe — a set with an empty string in it would
        /// otherwise widen the predicate to a key that cannot exist.
        fn v(xs: &[String]) -> Vec<String> {
            let mut out: Vec<String> = xs
                .iter()
                .map(|x| x.trim().to_owned())
                .filter(|x| !x.is_empty())
                .collect();
            out.sort();
            out.dedup();
            out
        }
        fn s(v: &Option<String>) -> Option<String> {
            v.as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
        }
        let mut prefixes: Vec<String> = self
            .dimension_prefixes
            .iter()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .collect();
        prefixes.sort();
        prefixes.dedup();
        Self {
            attesting_key_id: s(&self.attesting_key_id),
            attested_key_id: s(&self.attested_key_id),
            attesting_key_ids: v(&self.attesting_key_ids),
            attested_key_ids: v(&self.attested_key_ids),
            attestation_type: s(&self.attestation_type),
            dimension_prefixes: prefixes,
            dimension_exact: s(&self.dimension_exact),
            subject_key_id: s(&self.subject_key_id),
            after: self.after,
            before: self.before,
            limit: Some(self.effective_limit()),
        }
    }

    fn effective_limit(&self) -> i64 {
        self.limit
            .unwrap_or(DEFAULT_PREVIEW_LIMIT)
            .clamp(1, MAX_PREVIEW_LIMIT)
    }

    /// Is this selection empty of every predicate? An unpredicated selection is
    /// "the whole corpus", which is not a blast radius anyone reviewed.
    fn is_unpredicated(&self) -> bool {
        let n = self.normalized();
        n.attesting_key_id.is_none()
            && n.attested_key_id.is_none()
            && n.attesting_key_ids.is_empty()
            && n.attested_key_ids.is_empty()
            && n.attestation_type.is_none()
            && n.dimension_prefixes.is_empty()
            && n.dimension_exact.is_none()
            && n.subject_key_id.is_none()
            && n.after.is_none()
            && n.before.is_none()
    }

    /// The push-down. `AttestationFilter` is `#[non_exhaustive]` — persist owns
    /// its shape and may add predicates — so this is build-then-set: a new
    /// field arrives as a default we did not have to notice, rather than as a
    /// compile break.
    ///
    /// **`window` is a closed pair, and the open side needs a sentinel that is
    /// safe under a TEXT comparison** — see [`open_upper_bound`]. This mattered
    /// the moment persist v30.0.0 made the axis bind and not one release before.
    fn to_filter(&self) -> AttestationFilter {
        let n = self.normalized();
        let mut f = AttestationFilter::default();
        f.attesting_key_id = n.attesting_key_id;
        f.attested_key_id = n.attested_key_id;
        // OR-combined with the singular by persist's `merge_key_predicate`,
        // emitted as IN(…) / = ANY(…). Set here, never iterated here.
        f.attesting_key_ids = n.attesting_key_ids;
        f.attested_key_ids = n.attested_key_ids;
        f.attestation_type = n.attestation_type;
        f.dimension_prefixes = n.dimension_prefixes;
        f.dimension_exact = n.dimension_exact;
        f.subject_key_id = n.subject_key_id;
        f.window = match (n.after, n.before) {
            (None, None) => None,
            (a, b) => Some((
                a.unwrap_or_else(open_lower_bound),
                b.unwrap_or_else(open_upper_bound),
            )),
        };
        f
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Preview + the selection hash
// ═══════════════════════════════════════════════════════════════════════════

/// One previewed row, projected to what an operator ratifies.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewRow {
    pub attestation_id: String,
    pub attesting_key_id: String,
    pub attested_key_id: String,
    pub attestation_type: String,
    pub dimension: Option<String>,
    pub asserted_at: DateTime<Utc>,
    pub cohort_scope: String,
}

/// What a preview produced — the exact row set, the blast-radius counts, and
/// the hash a commit must present.
#[derive(Debug, Clone)]
pub struct Preview {
    pub rows: Vec<PreviewRow>,
    /// Distinct `attesting_key_id`s — the KEYS an op acts on.
    pub targets: Vec<String>,
    /// Rows per attester. The blast-radius check, in the shape an operator
    /// reads: "this touches 3 keys and 9,811 of them are one key's liveness".
    pub per_attester: BTreeMap<String, usize>,
    /// `true` when the page filled to the limit — the selection may be larger
    /// than what was hashed, and a commit therefore acts on a PAGE.
    pub truncated: bool,
    /// Where the `[after, before)` window was actually enforced. See
    /// [`WindowEnforcement`].
    pub window_enforced: WindowEnforcement,
    pub selection_hash: String,
}

/// **The open-ended side of a one-sided window, as a value the substrate's
/// comparison can actually order.**
///
/// `AttestationFilter::window` is a CLOSED `(start, end)` pair, so `after:` with
/// no `before:` has to supply an upper bound. The obvious sentinel —
/// `DateTime::<Utc>::MAX_UTC` — is **wrong here, and silently**: persist stores
/// `asserted_at` as `to_rfc3339()` TEXT and binds the window the same way, so
/// the predicate is a *string* comparison. `MAX_UTC` formats as
/// `+262143-12-31T…`, and `'+'` (0x2B) sorts BELOW `'2'` (0x32) — so
/// `asserted_at < MAX_UTC` is false for **every** row with a four-digit year and
/// an `after:`-only selection returns NOTHING.
///
/// This was harmless for as long as `list_attestations` ignored the axis, and
/// became a fail-closed selection the moment persist v30.0.0 (#596 item 2) made
/// it bind. It was caught by [`WindowEnforcement`] being measured rather than
/// declared: the in-process filter is still the authority, so the *selection*
/// was never wrong — the push-down over-narrowed, and the page came back empty.
///
/// The sentinels stay inside the four-digit-year range, where lexicographic
/// order and chronological order agree. **The stated assumption:** a row whose
/// `asserted_at` falls outside years 0000–9999 would sort outside these bounds
/// and be missed. No producer in this federation can emit one — persist's own
/// `list_scores` handle has compared this column as text since v17.4.0 — and the
/// in-process filter would still be correct about every row that came back.
fn open_upper_bound() -> DateTime<Utc> {
    "9999-12-31T23:59:59Z".parse().expect("in-range sentinel")
}

/// The lower twin of [`open_upper_bound`]. `MIN_UTC` happens to compare
/// correctly (`'-'` sorts below `'2'`, so `>=` admits everything), but relying
/// on that is relying on an accident of two sign characters; this one is
/// ordered for the same stated reason its twin is.
fn open_lower_bound() -> DateTime<Utc> {
    "0000-01-01T00:00:00Z".parse().expect("in-range sentinel")
}

/// **Where the time window was enforced — MEASURED, not asserted.**
///
/// `AttestationFilter::window` is a v17.4.0 axis that `list_attestations`
/// accepted and silently dropped until persist v30.0.0 (CIRISPersist#596 item
/// 2): its predicate builder emitted nine axes and nothing for `window`, `tier`
/// or `attester_filter`, so a caller setting `window` got a bound that was never
/// applied. That is the same silent-narrowing class `dimension_exact` was in
/// until v17.5.2 (#461), and it mattered here specifically: a preview that
/// ignored `after:` hands an operator a selection hash over a blast radius
/// larger than the one they were shown and then ratify.
///
/// **The axis now binds, so the window is pushed DOWN** — which also fixes the
/// page-bound interaction, because the substrate's `limit` now bounds the
/// windowed set rather than the whole corpus.
///
/// The in-process filter is kept anyway, and this enum is how it earns its
/// keep: it is no longer the enforcement, it is the WITNESS. A row the substrate
/// returns that does not satisfy the window is dropped here and flips the report
/// to [`Application`](Self::Application) — so if the push-down ever stops
/// binding again, the blast radius still narrows correctly AND the response says
/// out loud where it was narrowed. A value that is checked rather than declared
/// cannot go stale the way the sentence this replaced did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEnforcement {
    /// No window was asked for.
    None,
    /// Asked for, and every row the substrate returned already satisfied it —
    /// the push-down bound (persist v30.0.0 / #596 item 2).
    Substrate,
    /// Asked for, and this node had to drop at least one row the substrate
    /// returned. **The push-down did not bind**: the selection is still correct,
    /// but the page bound was applied to a wider set, so a windowed selection
    /// can come back short while [`Preview::truncated`] is set.
    Application,
}

impl WindowEnforcement {
    fn token(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Substrate => "substrate",
            Self::Application => "application",
        }
    }
}

/// The selection hash: SHA-256 over a canonical, versioned preimage covering
/// **both** the normalized filter and the exact set of row ids it returned.
///
/// Covering the row ids (not just the filter) is what closes TOCTOU: a row that
/// arrives between preview and commit changes the hash, so the commit refuses
/// and the operator re-previews. Covering the filter too means a hash cannot be
/// replayed against a different question that happened to return the same rows.
///
/// Ids are SORTED, so the hash is a function of the row SET and never of the
/// order the substrate happened to page them in.
#[must_use]
pub fn selection_hash(selection: &Selection, row_ids: &[String]) -> String {
    let n = selection.normalized();
    let mut pre = String::with_capacity(256 + row_ids.len() * 40);
    pre.push_str(SELECTION_HASH_VERSION);
    pre.push('\n');
    let f = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_owned());
    let t = |o: &Option<DateTime<Utc>>| o.map(|d| d.to_rfc3339()).unwrap_or_else(|| "-".to_owned());
    pre.push_str(&format!("attesting={}\n", f(&n.attesting_key_id)));
    pre.push_str(&format!("attested={}\n", f(&n.attested_key_id)));
    pre.push_str(&format!("type={}\n", f(&n.attestation_type)));
    pre.push_str(&format!("dimension_exact={}\n", f(&n.dimension_exact)));
    pre.push_str(&format!("subject={}\n", f(&n.subject_key_id)));
    pre.push_str(&format!("after={}\n", t(&n.after)));
    pre.push_str(&format!("before={}\n", t(&n.before)));
    pre.push_str(&format!("limit={}\n", n.effective_limit()));
    for p in &n.dimension_prefixes {
        pre.push_str(&format!("prefix={p}\n"));
    }
    let mut ids: Vec<&String> = row_ids.iter().collect();
    ids.sort();
    pre.push_str(&format!("rows={}\n", ids.len()));
    for id in ids {
        pre.push_str(&format!("row={id}\n"));
    }
    hex::encode(Sha256::digest(pre.as_bytes()))
}

/// Run the preview. **The filter is in the QUERY.**
///
/// The caller admission is the node authenticated AS ITSELF — the same honest
/// scope `graph_config::live_config_rows` resolves. `build_caller_admission` is
/// the only public path to an admission (no public constructor, AV-44 forge
/// resistance), so this cannot fabricate authority it does not hold.
async fn run_preview(
    engine: &Arc<Engine>,
    node_key_id: &str,
    selection: &Selection,
) -> Result<Preview, String> {
    let admission = ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned())
        .await
        .map_err(|e| format!("resolve caller admission: {e}"))?;
    let limit = selection.effective_limit();
    let page = engine
        .list_attestations(
            selection.to_filter(),
            None,
            limit,
            CallerScope::Authenticated { admission },
        )
        .await
        .map_err(|e| format!("list attestations: {e}"))?;

    // The page bound is the substrate's, and since persist v30.0.0 (#596 item
    // 2) it bounds the WINDOWED set — the window is a real push-down. Measured
    // before the in-process re-check for the same reason as before: a short
    // page must never be mistaken for a complete one.
    let truncated = i64::try_from(page.items.len()).unwrap_or(i64::MAX) >= limit;
    let n = selection.normalized();
    let asked_for_window = n.after.is_some() || n.before.is_some();
    let in_window = |a: &ciris_persist::federation::types::Attestation| {
        n.after.is_none_or(|start| a.asserted_at >= start)
            && n.before.is_none_or(|end| a.asserted_at < end)
    };
    // The witness: did the push-down actually bind? Counted over what came
    // back, so the reported enforcement point is a measurement rather than a
    // claim about persist's version.
    let dropped_here = page.items.iter().filter(|a| !in_window(a)).count();
    let window_enforced = match (asked_for_window, dropped_here) {
        (false, _) => WindowEnforcement::None,
        (true, 0) => WindowEnforcement::Substrate,
        (true, _) => WindowEnforcement::Application,
    };

    let mut per_attester: BTreeMap<String, usize> = BTreeMap::new();
    let rows: Vec<PreviewRow> = page
        .items
        .iter()
        .filter(|a| in_window(a))
        .map(|a| {
            *per_attester.entry(a.attesting_key_id.clone()).or_insert(0) += 1;
            PreviewRow {
                attestation_id: a.attestation_id.clone(),
                attesting_key_id: a.attesting_key_id.clone(),
                attested_key_id: a.attested_key_id.clone(),
                attestation_type: a.attestation_type.clone(),
                // The envelope KEY comes from persist, never a hand-mirrored
                // literal (SRV-1/#322) — a rename upstream must break the
                // build, not silently skew the projection.
                dimension: a
                    .attestation_envelope
                    .get(paths::DIMENSION)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                asserted_at: a.asserted_at,
                cohort_scope: a.cohort_scope.clone(),
            }
        })
        .collect();
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    let targets: Vec<String> = per_attester.keys().cloned().collect();
    Ok(Preview {
        selection_hash: selection_hash(selection, &ids),
        rows,
        targets,
        per_attester,
        truncated,
        window_enforced,
    })
}

fn preview_json(p: &Preview) -> serde_json::Value {
    let mut out = serde_json::json!({
        "selection_hash": p.selection_hash,
        "counts": {
            "rows": p.rows.len(),
            "targets": p.targets.len(),
            "per_attester": p.per_attester,
            "truncated": p.truncated,
        },
        "window_enforced": p.window_enforced.token(),
        "targets": p.targets,
        "rows": p.rows,
    });
    // Emitted ONLY on the Application arm, which since persist v30.0.0 (#596
    // item 2) means the push-down did not bind and this node narrowed the page
    // itself. The sentence is unchanged and still describes exactly that case —
    // re-wording it would leave 28 locale bundles holding a translation of
    // different content, which is worse than an id that renders raw.
    if p.window_enforced == WindowEnforcement::Application {
        out["window_note"] = m(
            "admin.preview.window_in_application",
            "The time window is applied by this node, not by the substrate query: the \
             general attestation read does not honour the window axis. The page bound is \
             applied first, so a windowed selection can come back short.",
        );
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
//  The commit envelope — attribution, authority, hash
// ═══════════════════════════════════════════════════════════════════════════

/// The fields EVERY mutating call carries.
#[derive(Debug, Clone, Deserialize)]
pub struct Commit {
    /// The selection this op runs over — byte-for-byte what was previewed.
    pub selection: Selection,
    /// The hash the preview returned. A mismatch refuses.
    pub selection_hash: String,
    /// **MANDATORY.** The `delegates_to` attestation id the actor acts UNDER.
    pub delegation_id: String,
    /// **MANDATORY.** Free text: WHY. Recorded, never interpreted.
    pub reason: String,
}

/// A delegation this module RESOLVED and RE-WALKED — never one it merely read
/// off the request.
#[derive(Debug, Clone)]
struct AuthorityProof {
    delegation_id: String,
    /// The root the scoped chain was walked FROM.
    issuer_key_id: String,
}

/// The scope set a `delegates_to` envelope declares — bare string OR array, the
/// two wire shapes the substrate walk accepts.
///
/// **This is persist's own parse, called** (v30.0.0 / CIRISPersist#596 item 3b).
/// It used to be a copy, because `delegation_scope_set` was `pub(crate)` and the
/// only public authority predicate was the issuer-to-target walk, which answers
/// a different question (see [`resolve_authority`]). A second implementation of
/// an authority rule is the split-truth shape a rule stated in one place and
/// re-derived in another always becomes, so the copy was marked for deletion the
/// day it was exported. This is that deletion.
fn delegation_scopes(envelope: &serde_json::Value) -> BTreeSet<String> {
    ciris_persist::federation::admission::delegation_scope_set(envelope)
        .into_iter()
        .collect()
}

/// Resolve + re-derive one delegation under `scope`. Refusals are named.
async fn resolve_authority(
    engine: &Arc<Engine>,
    actor_key_id: &str,
    delegation_id: &str,
    scope: &str,
) -> Result<AuthorityProof, Response> {
    let id = delegation_id.trim();
    if id.is_empty() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "attribution_absent",
            "admin.refusal.attribution_absent",
            "delegation_id is required. An action that does not carry its own authority \
             cannot be told from an unauthorized one once the actor is gone.",
        ));
    }
    let row = match engine.federation_directory().get_attestation(id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(refusal(
                StatusCode::FORBIDDEN,
                "authority_unresolved",
                "admin.refusal.authority_unresolved",
                "The named delegation is not a row this node holds, so its scope cannot be \
                 checked. This node does not act on an authority it cannot verify.",
            ))
        }
        Err(e) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The substrate could not be read: {e}"),
            ))
        }
    };
    if row.attestation_type != attestation_type::DELEGATES_TO {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_not_a_delegation",
            "admin.refusal.authority_not_a_delegation",
            "The named delegation id is not a delegates_to row.",
        ));
    }
    if row.attested_key_id != actor_key_id {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_not_to_actor",
            "admin.refusal.authority_not_to_actor",
            "The named delegation was not granted to this node, so this node is not the \
             party it authorizes.",
        ));
    }
    // **The row must itself carry the scope**, not merely descend from an issuer
    // who granted it somewhere else. `reachable_under_scope` answers *"does this
    // ISSUER reach this ACTOR under S"* — which is true the moment the issuer
    // granted S by ANY edge, so on its own it would let a `review` delegation be
    // recorded as the authority for a `slash` act. The tombstone names THIS row,
    // so THIS row is what has to bear the scope.
    if !delegation_scopes(&row.attestation_envelope).contains(scope) {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_scope_absent",
            "admin.refusal.authority_scope_absent",
            "The named delegation does not carry the scope this operation requires. \
             Another delegation from the same issuer might, but the act would then \
             record an authority it was not taken under.",
        ));
    }
    match engine
        .reachable_under_scope(
            &row.attesting_key_id,
            actor_key_id,
            scope,
            MAX_MODERATION_DELEGATION_DEPTH,
        )
        .await
    {
        Ok(true) => Ok(AuthorityProof {
            delegation_id: id.to_owned(),
            issuer_key_id: row.attesting_key_id,
        }),
        Ok(false) => Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_scope_unreachable",
            "admin.refusal.authority_scope_unreachable",
            "No live delegation chain carrying the scope this operation requires reaches \
             this node from that issuer. Authority is re-derived from this node's own \
             verified state, never taken from the request.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "admin.refusal.store_unavailable",
            format!("The delegation walk could not complete: {e}"),
        )),
    }
}

/// What a commit established: the preview it re-ran, and the authority it
/// re-derived.
struct Committed {
    preview: Preview,
    authority: AuthorityProof,
    /// Every distinct authority root, for the quorum ops.
    quorum_roots: BTreeSet<String>,
    quorum_delegation_ids: Vec<String>,
}

/// The shared commit gate: attribution → authority → **re-preview and compare
/// the hash**. In that order, so an unattributed call is refused before any
/// substrate work happens.
///
/// `node_key_id` is the value [`gate`] resolved from the engine — passed down
/// rather than re-derived so the authority walked here is provably walked from
/// the same identity the gate authorised (CIRISServer#372 Level 2).
async fn commit_gate(
    st: &AdminOpsState,
    node_key_id: &str,
    c: &Commit,
    scope: &str,
    extra_delegation_ids: &[String],
    quorum_min: usize,
) -> Result<Committed, Response> {
    if c.reason.trim().is_empty() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "attribution_absent",
            "admin.refusal.reason_absent",
            "reason is required. An action with no recorded reason is indistinguishable \
             from an unauthorized one once the actor is gone.",
        ));
    }
    if c.selection.is_unpredicated() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "selection_unpredicated",
            "admin.refusal.selection_unpredicated",
            "The selection carries no predicate at all, which means the whole corpus. \
             Name what you are acting on.",
        ));
    }

    let authority = resolve_authority(&st.engine, node_key_id, &c.delegation_id, scope).await?;
    let mut quorum_roots: BTreeSet<String> = BTreeSet::new();
    quorum_roots.insert(authority.issuer_key_id.clone());
    let mut quorum_delegation_ids = vec![authority.delegation_id.clone()];
    for extra in extra_delegation_ids {
        let proof = resolve_authority(&st.engine, node_key_id, extra, scope).await?;
        quorum_roots.insert(proof.issuer_key_id);
        quorum_delegation_ids.push(proof.delegation_id);
    }
    if quorum_roots.len() < quorum_min {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "refused": true,
                "refusal": "quorum_insufficient",
                "source_locale": SOURCE_LOCALE,
                "message": m(
                    "admin.refusal.quorum_insufficient",
                    "This operation is irreversible and takes a quorum of distinct \
                     authorities, not one delegation chain. Two chains from the same root \
                     are one authority wearing two hats.",
                ),
                "quorum_required": quorum_min,
                "quorum_distinct_roots": quorum_roots.len(),
            })),
        )
            .into_response());
    }

    let preview = run_preview(&st.engine, node_key_id, &c.selection)
        .await
        .map_err(|e| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The preview could not be re-run: {e}"),
            )
        })?;
    if preview.selection_hash != c.selection_hash.trim() {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "refused": true,
                "refusal": "preview_hash_mismatch",
                "source_locale": SOURCE_LOCALE,
                "message": m(
                    "admin.refusal.preview_hash_mismatch",
                    "What you previewed is not what would execute — the selection has \
                     changed since the preview. Re-run the preview and ratify the new hash.",
                ),
                "presented_selection_hash": c.selection_hash.trim(),
                "current_selection_hash": preview.selection_hash,
                "current": preview_json(&preview),
            })),
        )
            .into_response());
    }
    Ok(Committed {
        preview,
        authority,
        quorum_roots,
        quorum_delegation_ids,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
//  The attributed tombstone
// ═══════════════════════════════════════════════════════════════════════════

/// Build the attributed `hard_case:admin_action:{op}` row, using persist's OWN
/// builder for the required attribution keys and adding the context this ladder
/// carries. The builder cannot stop a caller passing empties; the gate at
/// `record_hard_case` is the one that has to hold — and it does, on all three
/// backends.
fn tombstone(
    op: &str,
    target_key_id: &str,
    delegation_id: &str,
    reason: &str,
    at: DateTime<Utc>,
    extra: serde_json::Value,
) -> HardCaseEvent {
    let mut ev = admin_action_event(
        op,
        target_key_id,
        Some(target_key_id),
        delegation_id,
        reason,
        at,
    );
    if let (Some(detail), Some(more)) = (ev.detail.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            detail.insert(k.clone(), v.clone());
        }
    }
    ev
}

/// The context every tombstone in this module carries beyond the mandatory
/// `{delegation_id, reason}`: WHAT was selected, and under WHICH authorities.
fn tombstone_context(c: &Committed, selection: &Selection) -> serde_json::Value {
    serde_json::json!({
        "selection_hash": c.preview.selection_hash,
        "selection_rows": c.preview.rows.len(),
        "selection_truncated": c.preview.truncated,
        "selection_after": selection.after.map(|d| d.to_rfc3339()),
        "quorum_roots": c.quorum_roots.iter().cloned().collect::<Vec<_>>(),
        "quorum_delegation_ids": c.quorum_delegation_ids,
    })
}

/// Record one tombstone. A failure here is FATAL to the op's report for that
/// target: the whole point of the ladder is that the act and its authority land
/// together.
async fn record(engine: &Arc<Engine>, ev: HardCaseEvent) -> Result<String, String> {
    let id = ev.event_id.clone();
    engine
        .federation_directory()
        .record_hard_case(ev)
        .await
        .map(|()| id)
        .map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
//  Reversal reach — what a reversal actually reverses
// ═══════════════════════════════════════════════════════════════════════════

/// How far a reversal op actually reaches in persist v28.2.0. The prior FSD
/// claimed tiers 1/2/4 were reversible and shipped no route that reversed
/// anything; these routes exist, and each one says what it undoes rather than
/// leaving a reader to assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReversalReach {
    /// The substrate state flips. `un_quarantine`: a `quarantine:released:v1`
    /// marker supersedes the withhold and `resolve_quarantine` folds to
    /// `released` — the serve paths stop withholding.
    Substrate,
    /// Nothing in the substrate changes because nothing in the substrate
    /// enforced the original op either. `un_throttle`: symmetric with
    /// `throttle`.
    Symmetric,
    /// The original act's row SURVIVES and this reversal is evidence only.
    /// `re_admit`: revocations are append-only, `fold_key_statement_standing`
    /// composes restrictions and never leniencies, and persist exposes no
    /// un-revoke at any layer.
    EvidenceOnly,
}

impl ReversalReach {
    fn token(self) -> &'static str {
        match self {
            Self::Substrate => "substrate",
            Self::Symmetric => "symmetric",
            Self::EvidenceOnly => "evidence_only",
        }
    }

    fn note(self) -> serde_json::Value {
        match self {
            Self::Substrate => m(
                "admin.reversal.substrate",
                "The substrate state is reversed: this node stops withholding the key's rows.",
            ),
            Self::Symmetric => m(
                "admin.reversal.symmetric",
                "Nothing in the substrate is reversed because nothing in the substrate \
                 enforced the original judgement. Both acts are recorded evidence.",
            ),
            Self::EvidenceOnly => m(
                "admin.reversal.evidence_only",
                "The original row survives and is still folded by every reader. This \
                 reversal is recorded evidence, not an undo — the substrate exposes no \
                 un-revoke.",
            ),
        }
    }
}

fn reversal_json(r: ReversalReach) -> serde_json::Value {
    serde_json::json!({ "reach": r.token(), "note": r.note() })
}

// ═══════════════════════════════════════════════════════════════════════════
//  POST /v1/admin/preview
// ═══════════════════════════════════════════════════════════════════════════

async fn preview(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let node_key_id = match gate(&st, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let selection: Selection = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    match run_preview(&st.engine, &node_key_id, &selection).await {
        Ok(p) => {
            let mut out = preview_json(&p);
            out["source_locale"] = serde_json::json!(SOURCE_LOCALE);
            out["note"] = m(
                "admin.preview.note",
                "This is exactly what a commit will act on. Present the selection hash \
                 with the commit; if the selection has changed, the commit refuses.",
            );
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(e) => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "admin.refusal.store_unavailable",
            format!("The preview could not be run: {e}"),
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 0 / tier 1 — judgement-only ops
// ═══════════════════════════════════════════════════════════════════════════

/// What a judgement-only op IS: its `admin_action:{op}` suffix, the delegation
/// scope it takes, its rung, and the honest statement of what it enforces.
struct JudgementOp<'a> {
    op: &'a str,
    scope: &'a str,
    tier: u8,
    enforcement: serde_json::Value,
    reversal: Option<ReversalReach>,
}

/// Shared body for the ops whose entire effect is an attributed tombstone.
async fn judgement_only(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    spec: JudgementOp<'_>,
) -> Response {
    let JudgementOp {
        op,
        scope,
        tier,
        enforcement,
        reversal,
    } = spec;
    let node_key_id = match gate(st, headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let c: Commit = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let committed = match commit_gate(st, &node_key_id, &c, scope, &[], 1).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut recorded = Vec::new();
    let mut failed = Vec::new();
    for target in &committed.preview.targets {
        let ev = tombstone(
            op,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            now,
            context.clone(),
        );
        match record(&st.engine, ev).await {
            Ok(id) => recorded.push(serde_json::json!({ "target_key_id": target, "event_id": id })),
            Err(e) => failed.push(serde_json::json!({ "target_key_id": target, "error": e })),
        }
    }
    tracing::warn!(
        op,
        tier,
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed"
    );
    let mut out = serde_json::json!({
        "op": op,
        "tier": tier,
        "source_locale": SOURCE_LOCALE,
        "required_scope": scope,
        "selection_hash": committed.preview.selection_hash,
        "counts": {
            "rows": committed.preview.rows.len(),
            "targets": committed.preview.targets.len(),
            "truncated": committed.preview.truncated,
        },
        "recorded": recorded,
        "failed": failed,
        "enforcement": enforcement,
    });
    if let Some(r) = reversal {
        out["reversal"] = reversal_json(r);
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn annotate(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_ANNOTATE,
            scope: REQUIRED_SCOPE_ANNOTATE,
            tier: 0,
            enforcement: m(
                "admin.enforcement.annotate",
                "A signed judgement with no effect until a reader honours it. Nothing is \
                 withheld, throttled or removed.",
            ),
            reversal: None,
        },
    )
    .await
}

/// Tier 1 enforcement note. **This is the honest one.**
fn throttle_enforcement() -> serde_json::Value {
    m(
        "admin.enforcement.throttle",
        "Recorded as an attributed judgement only. This substrate has no \
         recipient-authored per-key admission budget: the peer write quota is a fixed \
         runaway-loop backstop, not a policy surface a throttle can key on. Nothing \
         changes what this node accepts from the named keys.",
    )
}

async fn throttle(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_THROTTLE,
            scope: REQUIRED_SCOPE_THROTTLE,
            tier: 1,
            enforcement: throttle_enforcement(),
            reversal: None,
        },
    )
    .await
}

async fn un_throttle(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_THROTTLE_RELEASE,
            scope: REQUIRED_SCOPE_THROTTLE,
            tier: 1,
            enforcement: throttle_enforcement(),
            reversal: Some(ReversalReach::Symmetric),
        },
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 2 — quarantine / un-quarantine (the REAL substrate marker)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
struct QuarantineRequest {
    #[serde(flatten)]
    commit: Commit,
    /// The community whose authority the marker is filed under. Persist's
    /// `slash` gate resolves the duty-holders from THIS community's named
    /// moderators — a marker with no community names no authority.
    community_id: String,
}

/// Build a signed quarantine marker WITHOUT storing it, because
/// `record_quarantine_marker` takes an already-assembled, already-signed row
/// and does the storing itself.
///
/// **persist v30.0.0 (CIRISPersist#601 item 3 / #596 item 3) closed the gap this
/// function was built around.** Every sanctioned emit helper
/// (`emit_attestation_self`, `emit_with_local_signer`, `assemble_and_put`)
/// canonicalized, signed, assembled **and put** in one step, so the one door
/// built for this op could not be reached through the chokepoint built to stop
/// hand-rolled rows — and this was that hand-rolled row. `assemble` now splits
/// the recipe from the put, so the marker is produced by the same code path
/// every other federation-tier row is, carrying the same admission gates (#293
/// subject canonicality, #527 cohort_scope validate-never-default) that a
/// hand-rolled row skipped by construction.
async fn build_marker(
    engine: &Arc<Engine>,
    subject_key_id: &str,
    envelope: serde_json::Value,
) -> Result<Attestation, String> {
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .map_err(|e| format!("type the quarantine-marker envelope: {e}"))?;
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        core,
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(subject_key_id.to_owned());
    engine
        .assemble_attestation_self(input)
        .await
        .map(|s| s.attestation)
        .map_err(|e| format!("assemble quarantine marker: {e}"))
}

/// Shared body for quarantine + un-quarantine: same gates, different marker.
async fn quarantine_op(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    release: bool,
) -> Response {
    let node_key_id = match gate(st, headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let req: QuarantineRequest = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    if req.community_id.trim().is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "community_absent",
            "admin.refusal.community_absent",
            "community_id is required: a quarantine is filed under a community's authority, \
             and a marker that names no community names no authority.",
        );
    }
    let c = req.commit;
    let committed = match commit_gate(st, &node_key_id, &c, REQUIRED_SCOPE_QUARANTINE, &[], 1).await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let op = if release {
        admin_op::QUARANTINE_RELEASE
    } else {
        admin_op::QUARANTINE
    };
    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        // A release must name the withhold it lifts — resolve it from THIS
        // node's own fold rather than asking the caller to carry a row id.
        let releases = if release {
            match st.engine.resolve_quarantine(target, now).await {
                Ok(fold) if fold.withholds() => fold.marker_id,
                Ok(fold) => {
                    results.push(serde_json::json!({
                        "target_key_id": target,
                        "outcome": "skipped",
                        "reason": "not_withheld",
                        "state": fold.state.as_str(),
                        "message": m(
                            "admin.quarantine.not_withheld",
                            "This key is not currently withheld here, so there is nothing to \
                             release.",
                        ),
                    }));
                    continue;
                }
                Err(e) => {
                    results.push(serde_json::json!({
                        "target_key_id": target, "outcome": "error", "error": e.to_string(),
                    }));
                    continue;
                }
            }
        } else {
            None
        };
        let envelope = if release {
            let Some(marker_id) = releases else {
                results.push(serde_json::json!({
                    "target_key_id": target, "outcome": "skipped", "reason": "not_withheld",
                }));
                continue;
            };
            quarantine::release_envelope(
                target,
                req.community_id.trim(),
                &marker_id,
                &committed.authority.delegation_id,
                &c.reason,
            )
        } else {
            quarantine::withhold_envelope(
                target,
                req.community_id.trim(),
                &committed.authority.delegation_id,
                &c.reason,
            )
        };
        let marker = match build_marker(&st.engine, target, envelope).await {
            Ok(m) => m,
            Err(e) => {
                results.push(serde_json::json!({
                    "target_key_id": target, "outcome": "error", "error": e,
                }));
                continue;
            }
        };
        match st.engine.record_quarantine_marker(&marker).await {
            Ok(outcome) => match outcome.refusal() {
                None => {
                    let ev = tombstone(
                        op,
                        target,
                        &committed.authority.delegation_id,
                        &c.reason,
                        now,
                        context.clone(),
                    );
                    let event_id = record(&st.engine, ev).await;
                    results.push(serde_json::json!({
                        "target_key_id": target,
                        "outcome": "admitted",
                        "marker_id": marker.attestation_id,
                        "event_id": event_id.ok(),
                    }));
                }
                Some(reason) => results.push(serde_json::json!({
                    "target_key_id": target,
                    "outcome": "refused",
                    // The substrate's OWN stable token — never re-spelled here.
                    "reason": reason.as_str(),
                })),
            },
            Err(e) => results.push(serde_json::json!({
                "target_key_id": target, "outcome": "error", "error": e.to_string(),
            })),
        }
    }
    tracing::warn!(
        op,
        tier = 2,
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed"
    );
    let mut out = serde_json::json!({
        "op": op,
        "tier": 2,
        "source_locale": SOURCE_LOCALE,
        "required_scope": REQUIRED_SCOPE_QUARANTINE,
        "selection_hash": committed.preview.selection_hash,
        "community_id": req.community_id.trim(),
        "results": results,
        "enforcement": m(
            "admin.enforcement.quarantine",
            "A signed marker, not a command: nothing is deleted and nothing is rewritten. \
             This node's serve paths stop handing the named keys' rows and blobs to peers; \
             a peer that folds differently simply does not receive them from us.",
        ),
    });
    if release {
        out["reversal"] = reversal_json(ReversalReach::Substrate);
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn quarantine_route(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    quarantine_op(&st, &headers, &body, false).await
}

async fn un_quarantine_route(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    quarantine_op(&st, &headers, &body, true).await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 3 — force descent (quorum; the only irreversible op)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
struct DescendRequest {
    #[serde(flatten)]
    commit: Commit,
    /// The OTHER authorities' delegation ids. Each is resolved and re-walked
    /// exactly as the primary one is; the quorum counts distinct ROOTS.
    #[serde(default)]
    quorum_delegation_ids: Vec<String>,
}

async fn descend(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let node_key_id = match gate(&st, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let req: DescendRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let c = req.commit;
    let committed = match commit_gate(
        &st,
        &node_key_id,
        &c,
        REQUIRED_SCOPE_DESCEND,
        &req.quorum_delegation_ids,
        DESCEND_QUORUM_MIN,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    // **Property 5, and the wall it runs into.**
    //
    // `after:` bounds the JUDGEMENT: only statements made after that instant
    // are in doubt. The only payload-descent primitive this substrate exposes
    // over an actor is unbounded — it takes the whole corpus or none of it.
    // Driving an unbounded eviction from a bounded judgement is exactly the
    // DigiNotar error: the long tail of a total revocation is measured in the
    // things that were fine and died anyway. So a bounded descent records its
    // judgement and REFUSES the payload leg, naming the op that IS bounded.
    let bounded = c.selection.after.is_some();
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        let payload = if bounded {
            serde_json::json!({
                "performed": false,
                "refusal": "bounded_descent_unsupported",
                "message": m(
                    "admin.descend.bounded_unsupported",
                    "A time-bounded judgement cannot drive an unbounded eviction. The \
                     substrate's only actor-keyed descent takes the whole corpus, which \
                     would destroy the history this bound deliberately leaves standing. \
                     The time-bounded removal that IS implemented is de-admission with a \
                     history bound.",
                ),
            })
        } else {
            match st.engine.evict_actor(target, now).await {
                Ok(report) => serde_json::json!({
                    "performed": true,
                    "report": serde_json::to_value(&report).unwrap_or(serde_json::Value::Null),
                }),
                Err(e) => serde_json::json!({
                    "performed": false, "refusal": "evict_failed", "error": e.to_string(),
                }),
            }
        };
        let ev = tombstone(
            OP_DESCEND,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            now,
            {
                let mut ctx = context.clone();
                if let Some(o) = ctx.as_object_mut() {
                    o.insert("bounded".into(), serde_json::json!(bounded));
                    o.insert("payload_descent".into(), payload.clone());
                }
                ctx
            },
        );
        let event_id = record(&st.engine, ev).await;
        results.push(serde_json::json!({
            "target_key_id": target,
            "event_id": event_id.as_ref().ok(),
            "event_error": event_id.err(),
            "payload_descent": payload,
        }));
    }
    tracing::warn!(
        op = OP_DESCEND,
        tier = 3,
        bounded,
        delegation_id = %committed.authority.delegation_id,
        quorum_roots = committed.quorum_roots.len(),
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "IRREVERSIBLE graded admin op committed"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "op": OP_DESCEND,
            "tier": 3,
            "source_locale": SOURCE_LOCALE,
            "required_scope": REQUIRED_SCOPE_DESCEND,
            "selection_hash": committed.preview.selection_hash,
            "quorum": {
                "required": DESCEND_QUORUM_MIN,
                "distinct_roots": committed.quorum_roots.len(),
                "roots": committed.quorum_roots.iter().cloned().collect::<Vec<_>>(),
                "delegation_ids": committed.quorum_delegation_ids,
            },
            "bounded": bounded,
            "after": c.selection.after.map(|d| d.to_rfc3339()),
            "results": results,
            "irreversible": m(
                "admin.enforcement.descend",
                "Irreversible by design. Descent never terminates at zero — the blur and \
                 the tombstone survive — but what was shed is not coming back.",
            ),
            "not_reached": m(
                "admin.descend.not_reached",
                "The selected attestation rows themselves are not descended. Every payload \
                 carrier on this substrate is sealed inside its own signature, so its bytes \
                 cannot be dropped without making the row read as forged; erasability is \
                 decided at mint and nothing minted today is erasable.",
            ),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 4 — de-admit / re-admit
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
struct DeadmitRequest {
    #[serde(flatten)]
    commit: Commit,
    /// **The history bound.** The last instant this key's statements are still
    /// stood behind. Omitted ⇒ all-or-nothing, which is what an unbounded
    /// revocation has always meant.
    ///
    /// It rides here as well as on the selection because this is where persist
    /// actually implements it (`Revocation::revoked_after`) — the FSD put the
    /// time bound on tier 3 and the substrate put it on tier 4.
    #[serde(default)]
    after: Option<DateTime<Utc>>,
}

async fn deadmit(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let node_key_id = match gate(&st, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let req: DeadmitRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let c = req.commit;
    let committed = match commit_gate(&st, &node_key_id, &c, REQUIRED_SCOPE_DEADMIT, &[], 1).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // The bound the selection carries is the operator's stated compromise
    // instant; an explicit `after` on the body wins, so a de-admission can be
    // bounded without re-scoping the preview.
    let bound = req.after.or(c.selection.after);
    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        match put_revocation_for(
            &st.engine,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            bound,
            now,
        )
        .await
        {
            Ok(revocation_id) => {
                let ev = tombstone(
                    admin_op::DE_ADMISSION,
                    target,
                    &committed.authority.delegation_id,
                    &c.reason,
                    now,
                    {
                        let mut ctx = context.clone();
                        if let Some(o) = ctx.as_object_mut() {
                            o.insert("revocation_id".into(), serde_json::json!(revocation_id));
                            o.insert(
                                "revoked_after".into(),
                                serde_json::json!(bound.map(|d| d.to_rfc3339())),
                            );
                        }
                        ctx
                    },
                );
                let event_id = record(&st.engine, ev).await;
                results.push(serde_json::json!({
                    "target_key_id": target,
                    "outcome": "revoked",
                    "revocation_id": revocation_id,
                    "event_id": event_id.ok(),
                }));
            }
            // `refused` and `error` are DIFFERENT outcomes: the first is the
            // substrate answering "no" about authority, the second is it not
            // answering. A UI that renders them alike sends an operator to
            // debug a healthy node.
            Err(f) => results.push(serde_json::json!({
                "target_key_id": target,
                "outcome": if f.refusal == "federation_delegated_scope_unauthorized" {
                    "refused"
                } else {
                    "error"
                },
                // `reason` — the SAME field quarantine puts its substrate token
                // in, not a parallel one. One union, one name per concept, or
                // the client grows a second code path for the same idea.
                "reason": f.refusal,
                "message": f.message,
                "error": f.detail,
            })),
        }
    }
    tracing::warn!(
        op = admin_op::DE_ADMISSION,
        tier = 4,
        bounded = bound.is_some(),
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "op": admin_op::DE_ADMISSION,
            "tier": 4,
            "source_locale": SOURCE_LOCALE,
            "required_scope": REQUIRED_SCOPE_DEADMIT,
            "selection_hash": committed.preview.selection_hash,
            "revoked_after": bound.map(|d| d.to_rfc3339()),
            "results": results,
            "enforcement": m(
                "admin.enforcement.deadmit",
                "A signed revocation on the ordinary append-only plane. It is evidence a \
                 reader folds, not a door that slams: signature verification, the \
                 replication cursors and row ingest all deliberately keep working, because \
                 refusing a compromised key's older rows would destroy the evidence needed \
                 to adjudicate the compromise.",
            ),
        })),
    )
        .into_response()
}

/// Mint + store one signed [`Revocation`]. The history bound is
/// **envelope-bound**: the typed `revoked_after` must be mirrored, to the
/// second, by a `revoked_after` in the SIGNED envelope, or persist refuses the
/// row. An unsigned leniency field is an attacker's field.
async fn put_revocation_for(
    engine: &Arc<Engine>,
    revoked_key_id: &str,
    delegation_id: &str,
    reason: &str,
    revoked_after: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<String, DeAdmitFailure> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let revoking_key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| DeAdmitFailure::local("derive acting key_id", e))?;
    // ── THE ENVELOPE MUST NAME WHAT IT REVOKES (CIRISPersist#659) ────────────
    //
    // This built the envelope and the row side by side and required them to
    // agree — the CIRISServer#402 class, on the de-conferral plane. persist v31
    // refuses it, and its own account of the pre-#659 state says why plainly:
    // the scrub signature covered `revocation_envelope` and nothing else, so
    // `revocation_id`, `revoked_key_id`, `revoking_key_id`, `reason`,
    // `revoked_at`, `effective_at` and `scrub_timestamp` were UNSIGNED columns.
    // One validly-signed revocation, minted by a legitimately slash-conferred
    // moderator against a key it really did name, could be re-submitted with ANY
    // OTHER `revoked_key_id` at unboundedly many ids, and every gate returned
    // Ok(()) — the signature still verified. A single conferral bought an
    // unbounded de-conferral primitive.
    //
    // On a mesh with no platform owner that is the sanction plane: de-admission
    // IS the moderation system, and there is nobody to appeal a forged one to.
    //
    // ORDER MATTERS. `bind_revocation_into_envelope` truncates the row's three
    // instants to substrate resolution and stamps the envelope FROM the truncated
    // columns — so the row is built first, bound second, and only THEN
    // canonicalized and signed. Re-reading `now` after the bind, or signing bytes
    // built before it, puts us straight back to two authors for one fact.
    let mut envelope = serde_json::json!({
        "reason": reason,
        "delegation_id": delegation_id,
    });
    if let Some(bound) = revoked_after {
        // NOT stamped by the binder: `check_revocation_bound` owns this field and
        // its refusal taxonomy, and a producer that writes the bound into the
        // envelope while leaving the column unset must still be REFUSED rather
        // than silently repaired. So we set both, and truncate at the producer's
        // hand exactly as the binder does for its own three.
        envelope[ciris_persist::federation::register::REVOKED_AFTER_ENVELOPE_FIELD] = serde_json::json!(
            ciris_persist::federation::admission::truncate_to_substrate_resolution(bound)
                .to_rfc3339()
        );
    }

    let mut revocation = Revocation {
        revocation_id: crate::ids::new_id(),
        revoked_key_id: revoked_key_id.to_owned(),
        revoking_key_id: revoking_key_id.clone(),
        reason: Some(reason.to_owned()),
        revoked_at: now,
        effective_at: now,
        revocation_envelope: envelope,
        // Filled from the bytes the binder produces, below — a hash of anything
        // else would cover an envelope this row does not carry.
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: revoking_key_id,
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        observed_region: ciris_persist::federation::verify_coord::region::US.to_owned(),
        revoked_after: revoked_after
            .map(ciris_persist::federation::admission::truncate_to_substrate_resolution),
        persist_row_hash: String::new(),
    };
    ciris_persist::federation::admission::bind_revocation_into_envelope(&mut revocation)
        .map_err(|e| DeAdmitFailure::local("bind the revocation subject into its envelope", e))?;

    // Sign the BOUND envelope — these bytes now name the key being de-admitted.
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&revocation.revocation_envelope)
            .map_err(|e| DeAdmitFailure::local("canonicalize revocation", e))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| DeAdmitFailure::local("hybrid-sign revocation", e))?;
    revocation.original_content_hash = hex::encode(Sha256::digest(&canonical));
    revocation.scrub_signature_classical = B64.encode(&sig.classical.signature);
    revocation.scrub_signature_pqc = Some(B64.encode(&sig.pqc.signature));

    let id = revocation.revocation_id.clone();
    engine
        .federation_directory()
        .put_revocation(SignedRevocation { revocation })
        .await
        .map_err(|e| DeAdmitFailure::of(&e))?;
    Ok(id)
}

/// Why one target's de-admission did not land, in the shape the rest of this
/// module refuses in: a **stable token** to branch on plus a localizable
/// `{id, text}` pair — never a store-internal `Display` string.
///
/// This exists because of the one refusal an operator is overwhelmingly most
/// likely to meet. persist v30.10.0 made third-party revocation require `slash`
/// conferred by a root this node trusts (CIRISPersist#596 item 1), and
/// CIRISServer#383's 61 leaked QA keys are blocked on exactly that grant. Until
/// this, that arrived in the UI as `DelegatedScopeUnauthorized { signer: ...,
/// on_behalf_of: ..., scope: "slash" }` — a Rust debug format, in one locale,
/// naming no remedy. An operator reading it cannot tell "this node lacks
/// authority" from "the substrate is broken", and those want opposite responses.
///
/// The distinction the taxonomy has to preserve: **not permitted** is a verdict
/// about authority, and every other failure is the machinery not answering.
/// Collapsing them is the "distinct zeroes" shape — a refusal that means "we
/// asked and were told no" must never render like "we could not ask".
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DeAdmitFailure {
    /// Stable program token — the persist `kind()` where there is one.
    pub refusal: String,
    pub message: serde_json::Value,
    /// The substrate's own words, kept for the log/debug pane. Additive: the
    /// localized pair above is what a UI renders.
    pub detail: String,
}

impl DeAdmitFailure {
    /// A failure BEFORE the substrate is reached (key derivation, canonicalize,
    /// sign). Not a refusal — nothing declined the act, this node could not
    /// form it — so it gets the machinery-failed string, never the
    /// authority one.
    fn local(stage: &str, e: impl std::fmt::Display) -> Self {
        Self {
            refusal: "deadmit_local_failure".to_owned(),
            message: m(
                "admin.deadmit.failed.local",
                "This node could not build the revocation. Nothing was changed, and this is not \
                 an authority refusal — the act was never put to the substrate. The stage that \
                 failed is in `error`.",
            ),
            detail: format!("{stage}: {e}"),
        }
    }

    fn of(e: &ciris_persist::federation::Error) -> Self {
        use ciris_persist::federation::Error as E;
        // Each arm passes LITERAL (id, text) to `m` — the shape
        // check_localization_sync.py scans for. A `format!` here would compile
        // fine and silently leave the string unlocalizable in 29 languages,
        // which is why the duty name is written out rather than interpolated:
        // de-admission is gated on `slash` and nothing else.
        let message = match e {
            E::DelegatedScopeUnauthorized { .. } => m(
                "admin.deadmit.refused.no_slash_grant",
                "This node is not authorised to de-admit someone else's key. Revoking a key that \
                 is not your own is a moderation act, and it needs the `slash` duty granted to \
                 this node by a trust root it accepts. Nothing was changed. Ask an accord holder \
                 to delegate `slash` for federation duties to this node, then run the same \
                 selection again — the preview hash still applies.",
            ),
            E::NodeIdentityUnset { .. } => m(
                "admin.deadmit.refused.node_identity_unset",
                "This node has no federation identity yet, so it cannot sign a revocation or \
                 resolve whether it holds the authority to issue one. Complete node setup first.",
            ),
            _ => m(
                "admin.deadmit.failed.substrate",
                "The revocation could not be written. This is not an authority refusal — the \
                 substrate did not complete the act. The technical detail is in `error`.",
            ),
        };
        Self {
            refusal: e.kind().to_owned(),
            message,
            detail: e.to_string(),
        }
    }
}

async fn re_admit(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_RE_ADMISSION,
            scope: REQUIRED_SCOPE_DEADMIT,
            tier: 4,
            enforcement: m(
                "admin.enforcement.re_admit",
                "Recorded as an attributed reversal. The revocation row survives and every \
                 reader still folds it: restrictions compose and leniencies do not, and no \
                 layer of this substrate exposes an un-revoke.",
            ),
            reversal: Some(ReversalReach::EvidenceOnly),
        },
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 4, the WRITE DOOR — refuse-writes / accept-writes (AV-77)
// ═══════════════════════════════════════════════════════════════════════════
//
//  CIRISServer#375. `deadmit` above writes a `Revocation` and says, correctly,
//  that it is "evidence a reader folds, not a door that slams". This is the
//  door. `compose::arm_peer_deadmission_gate` arms persist's AV-77 gate at boot
//  and refuses to serve if the arming did not stick — and until now nothing in
//  this server emitted the row that gate reads, so the one control that stops a
//  hostile admitted peer's NEXT write was armed, proven armed, and unreachable.
//
//  Two acts, not one rung renamed: a COMPROMISED key wants its history readable
//  (revocation), a HOSTILE one wants its next write stopped (this). Both are
//  tier 4 because both act on a key under `slash`; they are separate routes and
//  separate `admin_action:{op}` suffixes because they reach different things and
//  an operator has to be able to tell afterwards which was done.

/// **Does this node refuse that key's writes right now — and is that knowable?**
///
/// Three values because there are three facts, and the third is the dangerous
/// one: rendered as "admitted" it is a false clean, which is the shape
/// `FSD/RCA_INGEST_REJECTION_2026-08-05.md` cost 71 hours of a dead plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionStanding {
    /// A live de-admission THIS node authored names the key: its next write
    /// into this corpus is refused.
    Refused,
    /// No live de-admission this node authored names the key.
    Admitted,
    /// The corpus could not be read, so this node **does not know**. Not a
    /// zero, and never to be folded into [`Admitted`](Self::Admitted).
    Unreadable,
}

impl AdmissionStanding {
    /// The stable program token a caller branches on.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Admitted => "admitted",
            Self::Unreadable => "unreadable",
        }
    }

    fn note(self) -> serde_json::Value {
        match self {
            Self::Refused => m(
                "admin.admission.standing.refused",
                "This node holds a live de-admission of this key that it authored itself, so \
                 the key's next write into this node's corpus is refused at the substrate's \
                 own door.",
            ),
            Self::Admitted => m(
                "admin.admission.standing.admitted",
                "No live de-admission authored by this node names this key, so its writes are \
                 admitted here. This says nothing about any other node: de-admission is local \
                 to the corpus that emits it.",
            ),
            Self::Unreadable => m(
                "admin.admission.standing.unreadable",
                "This node could not read its own admission state for this key, so it does \
                 not know whether that key's writes are refused. This is NOT 'admitted' — do \
                 not render it as one.",
            ),
        }
    }
}

fn standing_json(s: AdmissionStanding) -> serde_json::Value {
    serde_json::json!({ "standing": s.token(), "message": s.note() })
}

/// **Ask persist, never re-derive.** The de-admission rule is
/// `check_peer_deadmission`: this node's own rows, its own tombstone fold, its
/// own expiry check. Re-implementing any of that here would be the two-lists
/// class (#541) on the one control that stops an abuser.
///
/// persist exposes the rule as a predicate over a candidate ROW, so this asks
/// it the operator's actual question — *"would a write from `peer` be refused
/// here?"* — with a probe row. The probe is **never signed, never stored and
/// never leaves this function**: `check_peer_deadmission` reads exactly two of
/// its fields (`attesting_key_id`, and the envelope `dimension`, for the
/// exemption arm that lets a node always lift its own denial), and the probe
/// carries a dimension-less envelope so that arm is not taken.
///
/// The `de-admitted` discriminator is persist's own idiom, used by persist
/// itself at `substrate_machine.rs` (`msg.contains(PEER_DEADMISSION_DIMENSION)`)
/// and by its `bootstrap_admission` witnesses — matched on the CONSTANT, so a
/// rename upstream breaks the build rather than silently turning every refusal
/// into `Unreadable`.
async fn read_admission_standing(
    engine: &Arc<Engine>,
    node_key_id: &str,
    peer_key_id: &str,
) -> AdmissionStanding {
    use ciris_persist::federation::admission::PEER_DEADMISSION_DIMENSION;
    use ciris_persist::federation::Error as FederationError;

    let epoch = DateTime::<Utc>::MIN_UTC;
    let probe = Attestation {
        attestation_id: String::new(),
        attesting_key_id: peer_key_id.to_owned(),
        attested_key_id: peer_key_id.to_owned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        asserted_at: epoch,
        expires_at: None,
        // Deliberately dimension-less: a probe carrying
        // `PEER_DEADMISSION_DIMENSION` would take the exemption arm and every
        // key would read as admitted.
        attestation_envelope: serde_json::json!({}),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: peer_key_id.to_owned(),
        scrub_timestamp: epoch,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    let directory = engine.federation_directory();
    match ciris_persist::federation::admission::check_peer_deadmission(
        directory.as_ref(),
        &probe,
        node_key_id,
    )
    .await
    {
        Ok(()) => AdmissionStanding::Admitted,
        Err(FederationError::InvalidArgument(msg)) if msg.contains(PEER_DEADMISSION_DIMENSION) => {
            AdmissionStanding::Refused
        }
        Err(e) => {
            tracing::warn!(
                peer_key_id,
                error = %e,
                "could not read this node's own de-admission standing for a peer — reporting \
                 `unreadable`, NOT `admitted`"
            );
            AdmissionStanding::Unreadable
        }
    }
}

/// **Is the substrate actually consulting this node's de-admissions?**
///
/// AV-77's refusal predicate compares a writer against the key the host
/// declared with `set_self_key_id`. Emitting the row while that is unset — or
/// set to some OTHER key — writes a sanction that refuses nothing, which is the
/// exact condition `compose::arm_peer_deadmission_gate` refuses to boot over:
/// *"a silently-dormant sanction gate is strictly worse than no gate, because
/// operators will believe de-admission works."*
///
/// Kept as a separate axis from [`AdmissionStanding`] on purpose. "This node
/// holds a de-admission of K" and "the substrate is reading this node's
/// de-admissions at all" are two questions, and one field answering both is the
/// house's dominant defect class.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeadmissionGate {
    /// Declared, and it is the identity this node signs as.
    Armed,
    /// No identity declared — the gate is inert.
    Dormant,
    /// An identity IS declared and it is not the one this node signs as, so a
    /// de-admission signed here is not the "me" the gate folds.
    ForeignIdentity(String),
}

impl DeadmissionGate {
    fn token(&self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Dormant => "dormant",
            Self::ForeignIdentity(_) => "foreign_identity",
        }
    }

    /// The refusal for an act that would not take effect. `None` when armed.
    fn refusal(&self) -> Option<Response> {
        match self {
            Self::Armed => None,
            Self::Dormant => Some(refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "deadmission_gate_dormant",
                "admin.refusal.deadmission_gate_dormant",
                "This node has not declared its own identity to the substrate, so the \
                 de-admission gate is dormant: the row would be written and would refuse \
                 nothing. Refused rather than handed back as done — a sanction gate that \
                 silently does nothing is worse than no gate, because an operator will \
                 believe de-admission works. This is a node-configuration fault, not a \
                 fault of the request.",
            )),
            Self::ForeignIdentity(_) => Some(refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "deadmission_gate_foreign_identity",
                "admin.refusal.deadmission_gate_foreign_identity",
                "The identity this node signs as and the identity the de-admission gate \
                 compares writers against are two different keys, so a de-admission signed \
                 here would never be folded as this node's own and would refuse nothing. \
                 This is a node-configuration fault, not a fault of the request.",
            )),
        }
    }
}

/// Resolve the gate axis. `node_key_id` is the identity [`gate`] already
/// resolved from the engine — the key `emit_attestation_self` will stamp — so
/// this compares the signer against the declaration rather than two labels.
fn deadmission_gate(engine: &Arc<Engine>, node_key_id: &str) -> DeadmissionGate {
    match engine.self_key_id() {
        Some(declared) if declared == node_key_id => DeadmissionGate::Armed,
        Some(declared) => DeadmissionGate::ForeignIdentity(declared),
        None => DeadmissionGate::Dormant,
    }
}

/// The AV-77 envelope. The de-admitted peer is named by the ROW's
/// `attested_key_id` and NOT here: that is the column
/// `check_peer_deadmission` folds over, so a second copy in the envelope could
/// only ever disagree with the one that decides (persist says so itself, at
/// `substrate_machine::deadmission_envelope`).
///
/// `score` is negative because the constant's contract says so ("`score < 0` —
/// the denial"); the gate keys on `{type, attested_key_id, dimension,
/// tombstone, expiry}` and never reads it. Emitting the documented shape keeps
/// this a witness for the contract rather than for today's implementation.
///
/// `{delegation_id, reason}` ride IN the signed envelope, not only in this
/// node's local `hard_case` ledger: the row replicates, and an act that does
/// not carry its own authority cannot be told from an unauthorized one once the
/// actor is gone. Keys come from persist's own attribution vocabulary
/// (`admin_field`), never hand-mirrored literals (SRV-1/#322).
fn deadmission_envelope(delegation_id: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        (paths::DIMENSION): ciris_persist::federation::admission::PEER_DEADMISSION_DIMENSION,
        "score": -1.0,
        "confidence": 1.0,
        (admin_field::DELEGATION_ID): delegation_id,
        (admin_field::REASON): reason,
    })
}

/// The `withdraws` that LIFTS one de-admission row. Persist's own envelope
/// builder supplies the two `references_*` keys its precedence fold reads
/// (`references_attestation_id_from_envelope`); the attribution is added for
/// the same reason the de-admission carries it.
fn accept_writes_envelope(
    deadmission_id: &str,
    delegation_id: &str,
    reason: &str,
) -> serde_json::Value {
    let mut envelope = ciris_persist::federation::withdraws_attestation_envelope(
        deadmission_id,
        attestation_type::SCORES,
    );
    if let Some(o) = envelope.as_object_mut() {
        o.insert(
            admin_field::DELEGATION_ID.to_owned(),
            serde_json::json!(delegation_id),
        );
        o.insert(admin_field::REASON.to_owned(), serde_json::json!(reason));
    }
    envelope
}

/// Emit one federation-tier row about `peer_key_id` through the sanctioned
/// chokepoint. Never a hand-rolled 21-field `Attestation`: `emit_attestation_self`
/// derives the attester from the engine's own signer (#247), canonicalizes,
/// hybrid-signs and faces every admission gate a stored row faces.
async fn emit_about_peer(
    engine: &Arc<Engine>,
    attestation_type: &str,
    peer_key_id: &str,
    envelope: serde_json::Value,
) -> Result<String, String> {
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .map_err(|e| format!("type the envelope: {e}"))?;
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        attestation_type,
        core,
        // Federation scope, deliberately: persist's own description of AV-77 is
        // "a signed, replicable, revocable CEG attestation about whose claims
        // this node accepts". A peer that folds it reaches its OWN conclusion —
        // which is what makes isolation of a real abuser emergent rather than
        // decreed by whoever emitted first.
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(peer_key_id.to_owned());
    engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| e.to_string())
}

/// Every live de-admission row THIS node authored about `peer_key_id`, as an
/// [`AttestationFilter`] push-down — the UI's filter IS the query filter (#343),
/// never a whole-corpus scan filtered in this process.
///
/// "Live" is decided by [`read_admission_standing`] (persist's fold), not here:
/// this only finds the candidate rows a lift must reference. Withdrawing a row
/// that some other `withdraws` already killed is a no-op the substrate dedups,
/// so over-collecting is safe and under-collecting is not.
async fn deadmission_rows_for(
    engine: &Arc<Engine>,
    node_key_id: &str,
    peer_key_id: &str,
) -> Result<Vec<String>, String> {
    let admission = ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned())
        .await
        .map_err(|e| format!("resolve caller admission: {e}"))?;
    let mut filter = AttestationFilter::default();
    filter.attesting_key_id = Some(node_key_id.to_owned());
    filter.attested_key_id = Some(peer_key_id.to_owned());
    filter.attestation_type = Some(attestation_type::SCORES.to_owned());
    filter.dimension_exact =
        Some(ciris_persist::federation::admission::PEER_DEADMISSION_DIMENSION.to_owned());
    let page = engine
        .list_attestations(
            filter,
            None,
            MAX_PREVIEW_LIMIT,
            CallerScope::Authenticated { admission },
        )
        .await
        .map_err(|e| format!("list de-admissions: {e}"))?;
    Ok(page
        .items
        .iter()
        .map(|a| a.attestation_id.clone())
        .collect())
}

/// What `refuse-writes` reaches — including the half that is a limit.
fn refuse_writes_enforcement() -> serde_json::Value {
    m(
        "admin.enforcement.refuse_writes",
        "This node refuses the named keys' next write into its own corpus, at the substrate's \
         own door and before any other gate runs. It is LOCAL by design: no node decrees \
         another node's admission set, because a globally-effective de-admission would itself \
         be a censorship weapon. Isolation of a genuine abuser is emergent — it arrives when \
         many nodes independently reach the same conclusion — and is never decreed from here.",
    )
}

/// What `refuse-writes` does NOT reach. Said in the response, because an
/// operator who infers more than this delivers will stop looking.
fn refuse_writes_not_reached() -> serde_json::Value {
    m(
        "admin.refuse_writes.not_reached",
        "It unwrites nothing. Rows these keys already wrote here are untouched and still \
         served — quarantine is the op that stops serving them. Rows that already replicated \
         to peers are not recalled and cannot be. The keys are not removed, their signatures \
         still verify, and they go on writing to every other node, including this node's \
         peers, from which those rows may arrive here again by replication. One exemption \
         survives on purpose so that a node can always lift its own denial, and it does not \
         ask who is writing: a de-admitted key may still write de-admission rows here \
         (CIRISPersist#608).",
    )
}

/// How `refuse-writes` is undone — the honest reversibility statement.
fn refuse_writes_reversal() -> serde_json::Value {
    m(
        "admin.refuse_writes.reversal",
        "Reversible, and the reversal reaches the substrate rather than merely recording a \
         change of mind: POST /v1/admin/accept-writes withdraws the de-admission and the \
         key's writes are admitted here again. Two of this ladder's reversals reach the \
         substrate — releasing a quarantine, which restores what this node SERVES, and this \
         one, which restores what it ACCEPTS. Both rows survive and stay readable: 'refused \
         and then re-admitted' is not the same fact as 'never refused'.",
    )
}

/// One target's outcome, in the shape the two routes share.
fn write_door_result(
    target: &str,
    outcome: &str,
    before: AdmissionStanding,
    after: AdmissionStanding,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut out = serde_json::json!({
        "target_key_id": target,
        "outcome": outcome,
        "standing_before": standing_json(before),
        "standing_after": standing_json(after),
    });
    if let (Some(o), Some(more)) = (out.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            o.insert(k.clone(), v.clone());
        }
    }
    out
}

/// `POST /v1/admin/refuse-writes` — **tier 4's write door.** Emit the AV-77
/// de-admission the substrate's own put-gate reads.
async fn refuse_writes(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let node_key_id = match gate(&st, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // Refused BEFORE any delegation is walked: an act that cannot take effect
    // is not a question about the operator's authority, and the operator's next
    // move is to fix the node rather than the request.
    let gate_state = deadmission_gate(&st.engine, &node_key_id);
    if let Some(resp) = gate_state.refusal() {
        tracing::error!(
            node_key_id = %node_key_id,
            declared = ?st.engine.self_key_id(),
            gate = gate_state.token(),
            "refused a de-admission because the AV-77 gate would not enforce it"
        );
        return resp;
    }
    let c: Commit = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let committed =
        match commit_gate(&st, &node_key_id, &c, REQUIRED_SCOPE_REFUSE_WRITES, &[], 1).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        let before = read_admission_standing(&st.engine, &node_key_id, target).await;
        if before == AdmissionStanding::Refused {
            results.push(write_door_result(
                target,
                "already_refused",
                before,
                before,
                serde_json::json!({
                    "message": m(
                        "admin.refuse_writes.already_refused",
                        "This key is already de-admitted here, so nothing was written and \
                         the standing is unchanged.",
                    ),
                }),
            ));
            continue;
        }
        // `Unreadable` does NOT stop the act. This is the restrictive
        // direction, and declining to sanction because a read failed would be
        // failing open on the one control that stops an abuser. The response
        // reports the unreadable `standing_before` rather than hiding it.
        let envelope = deadmission_envelope(&committed.authority.delegation_id, &c.reason);
        match emit_about_peer(&st.engine, attestation_type::SCORES, target, envelope).await {
            Ok(deadmission_id) => {
                let after = read_admission_standing(&st.engine, &node_key_id, target).await;
                let ev = tombstone(
                    OP_REFUSE_WRITES,
                    target,
                    &committed.authority.delegation_id,
                    &c.reason,
                    now,
                    {
                        let mut ctx = context.clone();
                        if let Some(o) = ctx.as_object_mut() {
                            o.insert("deadmission_id".into(), serde_json::json!(deadmission_id));
                            o.insert("standing_before".into(), serde_json::json!(before.token()));
                            o.insert("standing_after".into(), serde_json::json!(after.token()));
                        }
                        ctx
                    },
                );
                let event_id = record(&st.engine, ev).await;
                results.push(write_door_result(
                    target,
                    "refused",
                    before,
                    after,
                    serde_json::json!({
                        "deadmission_id": deadmission_id,
                        "event_id": event_id.ok(),
                    }),
                ));
            }
            Err(e) => results.push(write_door_result(
                target,
                "error",
                before,
                before,
                serde_json::json!({ "error": e }),
            )),
        }
    }
    tracing::warn!(
        op = OP_REFUSE_WRITES,
        tier = 4,
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed — this node now REFUSES those keys' writes"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "op": OP_REFUSE_WRITES,
            "tier": 4,
            "source_locale": SOURCE_LOCALE,
            "required_scope": REQUIRED_SCOPE_REFUSE_WRITES,
            "selection_hash": committed.preview.selection_hash,
            "deadmission_gate": gate_state.token(),
            "results": results,
            "enforcement": refuse_writes_enforcement(),
            "not_reached": refuse_writes_not_reached(),
            "reversal": refuse_writes_reversal(),
        })),
    )
        .into_response()
}

/// `POST /v1/admin/accept-writes` — the reversal, and the only one on this
/// ladder that reaches the substrate's write door.
async fn accept_writes(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let node_key_id = match gate(&st, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let c: Commit = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let committed =
        match commit_gate(&st, &node_key_id, &c, REQUIRED_SCOPE_REFUSE_WRITES, &[], 1).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // A dormant gate does NOT block the lift. Withdrawing a de-admission is the
    // lenient direction, the rows to withdraw are found by this node's own
    // authorship rather than by the declaration, and refusing to lift a
    // sanction because the sanction was not being enforced would leave the row
    // standing to bite the moment the node is configured correctly. The state
    // is reported so an operator is never told a lift "worked" without also
    // being told the gate it lifts was not running.
    let gate_state = deadmission_gate(&st.engine, &node_key_id);

    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        let before = read_admission_standing(&st.engine, &node_key_id, target).await;
        match before {
            AdmissionStanding::Admitted => {
                results.push(write_door_result(
                    target,
                    "not_refused",
                    before,
                    before,
                    serde_json::json!({
                        "message": m(
                            "admin.accept_writes.not_refused",
                            "This key is not de-admitted here, so there is nothing to lift.",
                        ),
                    }),
                ));
                continue;
            }
            // Unlike the restrictive direction, a lift STOPS on an unreadable
            // standing: there is nothing safe to do without knowing which rows
            // hold the denial, and emitting a withdraws against a guess is how
            // a lift silently misses the row that matters.
            AdmissionStanding::Unreadable => {
                results.push(write_door_result(
                    target,
                    "error",
                    before,
                    before,
                    serde_json::json!({
                        "error": "the de-admission standing could not be read, so this node \
                                  does not know what it would be lifting",
                    }),
                ));
                continue;
            }
            AdmissionStanding::Refused => {}
        }
        let rows = match deadmission_rows_for(&st.engine, &node_key_id, target).await {
            Ok(rows) => rows,
            Err(e) => {
                results.push(write_door_result(
                    target,
                    "error",
                    before,
                    before,
                    serde_json::json!({ "error": e }),
                ));
                continue;
            }
        };
        let mut withdrew = Vec::new();
        let mut errors = Vec::new();
        for deadmission_id in &rows {
            let envelope = accept_writes_envelope(
                deadmission_id,
                &committed.authority.delegation_id,
                &c.reason,
            );
            match emit_about_peer(&st.engine, attestation_type::WITHDRAWS, target, envelope).await {
                Ok(id) => withdrew.push(serde_json::json!({
                    "deadmission_id": deadmission_id, "withdraws_id": id,
                })),
                Err(e) => errors.push(serde_json::json!({
                    "deadmission_id": deadmission_id, "error": e,
                })),
            }
        }
        let after = read_admission_standing(&st.engine, &node_key_id, target).await;
        let ev = tombstone(
            OP_ACCEPT_WRITES,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            now,
            {
                let mut ctx = context.clone();
                if let Some(o) = ctx.as_object_mut() {
                    o.insert("withdrew".into(), serde_json::json!(withdrew));
                    o.insert("standing_before".into(), serde_json::json!(before.token()));
                    o.insert("standing_after".into(), serde_json::json!(after.token()));
                }
                ctx
            },
        );
        let event_id = record(&st.engine, ev).await;
        results.push(write_door_result(
            target,
            if after == AdmissionStanding::Admitted {
                "accepted"
            } else {
                "error"
            },
            before,
            after,
            serde_json::json!({
                "withdrew": withdrew,
                "errors": errors,
                "event_id": event_id.ok(),
            }),
        ));
    }
    tracing::warn!(
        op = OP_ACCEPT_WRITES,
        tier = 4,
        gate = gate_state.token(),
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed — this node accepts those keys' writes again"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "op": OP_ACCEPT_WRITES,
            "tier": 4,
            "source_locale": SOURCE_LOCALE,
            "required_scope": REQUIRED_SCOPE_REFUSE_WRITES,
            "selection_hash": committed.preview.selection_hash,
            "deadmission_gate": gate_state.token(),
            "results": results,
            "enforcement": m(
                "admin.enforcement.accept_writes",
                "This node stops refusing the named keys' writes: the de-admission it \
                 authored is withdrawn and the substrate admits their next write again. Both \
                 the de-admission and this withdrawal survive as readable history.",
            ),
            "not_reached": m(
                "admin.accept_writes.not_reached",
                "It restores nothing that was refused while the de-admission stood. Those \
                 writes were rejected at the door and never landed here; if the peer still \
                 holds them it has to send them again. Nothing else about the key changes.",
            ),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier S — self-directed (the only rung available under partition)
// ═══════════════════════════════════════════════════════════════════════════

/// One of the three self-directed acts. **Three axes, and they are never
/// folded together.**
///
/// The third is not a flavour of the second. *"This node chose to stop"* and
/// *"this node was made to stop"* are the same observable — nothing arriving —
/// with opposite meanings, and the only party who can tell them apart is the
/// node itself, at the moment it acts. Collapsing them destroys the one signal
/// every downstream party has, so they are separate ops, separate axes and
/// separate standings, all the way through the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfAct {
    /// *Shed my own load* — carry less.
    ShedLoad,
    /// *Stop accepting* — take on nothing new. A CHOICE this node made.
    StopAccepting,
    /// *I am under legal compulsion* — force applied from outside the mesh.
    /// Not a choice, and never recorded as one.
    LegalCompulsion,
}

impl SelfAct {
    /// The three, in declaration order. **The closed set** — a fourth act must
    /// appear here or the standing read will not show it, which is the
    /// silently-missing-axis failure this module exists to avoid.
    pub const ALL: &'static [Self] = &[Self::ShedLoad, Self::StopAccepting, Self::LegalCompulsion];

    /// The standing axis this act moves. Stable program token.
    #[must_use]
    pub const fn axis(self) -> &'static str {
        match self {
            Self::ShedLoad => "load_shed",
            Self::StopAccepting => "accepting",
            Self::LegalCompulsion => "legal_compulsion",
        }
    }

    /// The `admin_action:{op}` suffix of the DECLARATION.
    #[must_use]
    pub const fn assert_op(self) -> &'static str {
        match self {
            Self::ShedLoad => OP_SELF_SHED,
            Self::StopAccepting => OP_SELF_STOP_ACCEPTING,
            Self::LegalCompulsion => OP_SELF_COMPELLED,
        }
    }

    /// The `admin_action:{op}` suffix of the LIFT.
    #[must_use]
    pub const fn lift_op(self) -> &'static str {
        match self {
            Self::ShedLoad => OP_SELF_SHED_RELEASE,
            Self::StopAccepting => OP_SELF_ACCEPTING_RESUMED,
            Self::LegalCompulsion => OP_SELF_COMPULSION_LIFTED,
        }
    }

    /// **What this act actually reaches**, per the tier 1 precedent: when a
    /// rung has no substrate, the route says so in its own response rather than
    /// letting an operator infer an effect that does not happen.
    fn enforcement(self) -> serde_json::Value {
        match self {
            Self::ShedLoad => m(
                "admin.self.enforcement.shed",
                "Recorded as this node's own attributed declaration, and nothing more. The \
                 mesh-config plane that would carry a load ceiling is authored by trust roots, \
                 and this node runs no consumer of the folded values yet, so no loop changes \
                 what it carries. What changes is the record: an operator, a peer or a later \
                 audit can tell that this node chose to carry less, under whose authority, and \
                 when.",
            ),
            Self::StopAccepting => m(
                "admin.self.enforcement.stop_accepting",
                "Recorded as this node's own attributed declaration that it is taking on \
                 nothing new. Nothing in this substrate enforces it: the receive plane is \
                 peer-blind and the per-peer write quota is a fixed runaway-loop backstop, not \
                 a policy surface a stop can key on. The declaration is the artifact — and it \
                 is the one a peer reads to stop offering.",
            ),
            Self::LegalCompulsion => m(
                "admin.self.enforcement.compelled",
                "Recorded on its own axis, as its own act. This is a statement about force \
                 applied from OUTSIDE the mesh, and by itself it changes nothing this node \
                 does — deliberately. A compelled node may be made to keep serving, to stop, \
                 or to hand something over; folding any of those into 'this node stopped \
                 accepting' would destroy the only signal a downstream party has for telling \
                 a choice from a compulsion.",
            ),
        }
    }

    /// The reversal's note. Symmetric with [`Self::enforcement`] because the
    /// declaration reached nothing, so the lift reverses nothing but the
    /// standing — which is exactly what [`ReversalReach::Symmetric`] means.
    fn lift_note(self) -> serde_json::Value {
        match self {
            Self::LegalCompulsion => m(
                "admin.self.lift.compelled",
                "Recorded as a distinct act: a compulsion that ENDED is not a compulsion that \
                 never happened. The declaration it lifts survives, and both remain readable.",
            ),
            _ => m(
                "admin.self.lift.voluntary",
                "Recorded as a distinct act. The declaration it lifts survives, and both \
                 remain readable — 'declared and lifted' is not 'never declared'.",
            ),
        }
    }
}

/// **The standing on one tier S axis — four values, and three of them are
/// zeroes that must never render alike.**
///
/// `FSD/RCA_INGEST_REJECTION_2026-08-05.md` is what a collapsed zero cost: a
/// dead plane invisible for 71 hours because "no signal" and "nothing wrong"
/// were the same rendering. The three here are:
///
/// - [`NeverDeclared`](Self::NeverDeclared) — this node has never declared one;
/// - [`Lifted`](Self::Lifted) — it declared one and lifted it. Not the same
///   fact, and the difference is the entire history of the axis;
/// - [`Unreadable`](Self::Unreadable) — the ledger could not be read, so this
///   node **does not know**. This is the dangerous one: rendered as "nothing in
///   force" it is a false clean, which is exactly the check that nearly
///   reported a dead node healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfStanding {
    /// Declared, not lifted.
    InForce,
    /// Declared and then lifted.
    Lifted,
    /// No act on this axis has ever been recorded here.
    NeverDeclared,
    /// The ledger read failed. **Not** a zero.
    Unreadable,
}

impl SelfStanding {
    /// The stable program token a caller branches on.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::InForce => "in_force",
            Self::Lifted => "lifted",
            Self::NeverDeclared => "never_declared",
            Self::Unreadable => "unreadable",
        }
    }

    fn note(self) -> serde_json::Value {
        match self {
            Self::InForce => m(
                "admin.self.standing.in_force",
                "This node declared this and has not lifted it.",
            ),
            Self::Lifted => m(
                "admin.self.standing.lifted",
                "This node declared this and lifted it again. That is not the same fact as \
                 never having declared it.",
            ),
            Self::NeverDeclared => m(
                "admin.self.standing.never_declared",
                "This node has never declared this. That is not the same fact as having \
                 declared and lifted it, and not the same fact as being unable to read.",
            ),
            Self::Unreadable => m(
                "admin.self.standing.unreadable",
                "The record could not be read, so this node does not know its own standing on \
                 this axis. This is NOT 'nothing in force' — do not render it as one.",
            ),
        }
    }
}

/// One axis's folded standing, with the evidence that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfFold {
    pub axis: &'static str,
    pub standing: SelfStanding,
    /// The governing act's `event_id`.
    pub event_id: Option<String>,
    /// When the standing took effect — the governing act's instant. `None` for
    /// both non-facts.
    pub since: Option<DateTime<Utc>>,
    pub delegation_id: Option<String>,
    pub reason: Option<String>,
    /// How many times this axis has been DECLARED here, ever.
    pub declarations: usize,
    /// How many times it has been LIFTED here, ever.
    pub lifts: usize,
}

/// Read one string field off an admin-action event's `detail`, using persist's
/// own field vocabulary (never a hand-mirrored literal — SRV-1/#322).
fn detail_str(ev: &HardCaseEvent, key: &str) -> Option<String> {
    ev.detail
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
}

/// **The pure fold** over one axis — a function of
/// `(act, node_key_id, events, now)` and nothing else, so it is testable
/// without a substrate and cannot depend on the order rows arrived in.
///
/// # Ordering
///
/// Newest wins, by `(emitted_at, declaration-beats-lift, event_id)`. The last
/// two are not decoration, and they are the same two persist's own
/// [`fold_quarantine`](ciris_persist::federation::quarantine::fold_quarantine)
/// and `fold_mesh_config` use:
///
/// - `emitted_at` alone is not a total order. Persist keys an admin-action
///   `event_id` on the whole second, so a declaration and a lift recorded
///   inside one second are two rows at one instant — reachable by ordinary
///   operator haste, not only by construction;
/// - **at a tie the DECLARATION wins.** Shed, stop and compulsion are the
///   restrictive states and their lifts are the leniencies; resolving a
///   collision toward the leniency is the fail-open direction. A wrongly-held
///   declaration is recoverable by another lift; a wrongly-lifted one is
///   recoverable by nothing, because the operator has already been told they
///   are running;
/// - `event_id` breaks the remainder.
#[must_use]
pub fn fold_self_standing(
    act: SelfAct,
    node_key_id: &str,
    events: &[HardCaseEvent],
    now: DateTime<Utc>,
) -> SelfFold {
    let assert_kind = admin_action_kind(act.assert_op());
    let lift_kind = admin_action_kind(act.lift_op());
    let mut mine: Vec<&HardCaseEvent> = events
        .iter()
        .filter(|e| {
            (e.kind == assert_kind || e.kind == lift_kind)
                && e.target_key_id.as_deref() == Some(node_key_id)
                && e.emitted_at <= now
        })
        .collect();
    let declarations = mine.iter().filter(|e| e.kind == assert_kind).count();
    let lifts = mine.len() - declarations;
    if mine.is_empty() {
        return SelfFold {
            axis: act.axis(),
            standing: SelfStanding::NeverDeclared,
            event_id: None,
            since: None,
            delegation_id: None,
            reason: None,
            declarations: 0,
            lifts: 0,
        };
    }
    // Sorts ASCENDING; the last element governs. `declaration_rank` is 1 for a
    // declaration and 0 for a lift — restriction sorts LAST, i.e. wins.
    let declaration_rank = |e: &HardCaseEvent| u8::from(e.kind == assert_kind);
    mine.sort_by(|a, b| {
        a.emitted_at
            .cmp(&b.emitted_at)
            .then_with(|| declaration_rank(a).cmp(&declaration_rank(b)))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    let governing = mine[mine.len() - 1];
    SelfFold {
        axis: act.axis(),
        standing: if governing.kind == assert_kind {
            SelfStanding::InForce
        } else {
            SelfStanding::Lifted
        },
        event_id: Some(governing.event_id.clone()),
        since: Some(governing.emitted_at),
        delegation_id: detail_str(governing, admin_field::DELEGATION_ID),
        reason: detail_str(governing, admin_field::REASON),
        declarations,
        lifts,
    }
}

/// Read one axis's ledger. **Both kinds are pushed into the query** — the
/// `kind` predicate is real SQL on every backend — so this is never the
/// whole-corpus scan that cost a 152-second boot phase (#343).
async fn read_self_axis(
    engine: &Arc<Engine>,
    node_key_id: &str,
    act: SelfAct,
    now: DateTime<Utc>,
) -> Result<SelfFold, String> {
    let directory = engine.federation_directory();
    let mut events: Vec<HardCaseEvent> = Vec::new();
    for op in [act.assert_op(), act.lift_op()] {
        let page = directory
            .list_hard_case_events(HardCaseFilter {
                kind: Some(admin_action_kind(op)),
                since: None,
            })
            .await
            .map_err(|e| e.to_string())?;
        events.extend(page);
    }
    Ok(fold_self_standing(act, node_key_id, &events, now))
}

fn self_fold_json(f: &SelfFold) -> serde_json::Value {
    serde_json::json!({
        "axis": f.axis,
        "standing": f.standing.token(),
        "message": f.standing.note(),
        "since": f.since.map(|d| d.to_rfc3339()),
        "event_id": f.event_id,
        "delegation_id": f.delegation_id,
        "reason": f.reason,
        "counts": { "declarations": f.declarations, "lifts": f.lifts },
    })
}

/// The unreadable standing for one axis — built explicitly rather than by
/// letting an error path fall through to a default, because the default of a
/// standing is a zero and this is not one.
fn self_axis_unreadable(act: SelfAct) -> SelfFold {
    SelfFold {
        axis: act.axis(),
        standing: SelfStanding::Unreadable,
        event_id: None,
        since: None,
        delegation_id: None,
        reason: None,
        declarations: 0,
        lifts: 0,
    }
}

/// The note every tier S response carries: WHY this rung exists.
fn partition_note() -> serde_json::Value {
    m(
        "admin.self.partition",
        "Every act on this rung is local: the owner-binding walk, the ledger write and this \
         read all touch this node's own database and nothing else. It is the only rung \
         available while partitioned — every other rung has to reach someone.",
    )
}

/// `GET /v1/admin/self` — the three standings, side by side, never folded
/// together.
///
/// Returns **503 when any axis is unreadable**, with that axis's standing still
/// rendered as [`SelfStanding::Unreadable`]. Both halves say the same thing on
/// purpose: a client that reads only the status and a client that reads only
/// the body must each be unable to conclude "nothing in force".
async fn self_standing(State(st): State<AdminOpsState>, headers: HeaderMap) -> Response {
    let node_key_id = match self_key_id(&st).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
    let now = Utc::now();
    let mut standings = serde_json::Map::new();
    let mut errors = serde_json::Map::new();
    for &act in SelfAct::ALL {
        let fold = match read_self_axis(&st.engine, &node_key_id, act, now).await {
            Ok(f) => f,
            Err(e) => {
                errors.insert(act.axis().to_owned(), serde_json::json!(e));
                self_axis_unreadable(act)
            }
        };
        standings.insert(act.axis().to_owned(), self_fold_json(&fold));
    }
    let unreadable = !errors.is_empty();
    let mut out = serde_json::json!({
        "source_locale": SOURCE_LOCALE,
        "tier": "S",
        "node_key_id": node_key_id,
        "standings": standings,
        "partition": partition_note(),
        "distinct_zeroes": m(
            "admin.self.distinct_zeroes",
            "Three of the four standings are zeroes and they mean different things: never \
             declared, declared and lifted, and could not be read. Render them differently.",
        ),
    });
    if unreadable {
        out["unreadable_axes"] = serde_json::Value::Object(errors);
        return (StatusCode::SERVICE_UNAVAILABLE, Json(out)).into_response();
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// The body of every tier S act. **No selection and no selection hash** — and
/// that is a considered divergence from tiers 0–4, not an omission.
///
/// The hash exists to bind an operator's ratification to an exact row SET, so
/// a commit cannot act on a blast radius nobody reviewed. A tier S act selects
/// nothing: its subject is this node, the row count is zero, and there is no
/// window between preview and commit for anything to change. What the tier does
/// keep is the property that actually carries here — attribution — and it adds
/// one tiers 0–4 do not have: the authority must be **the owner's own**.
#[derive(Debug, Clone, Deserialize)]
pub struct SelfCommit {
    /// **MANDATORY.** The owner's `delegates_to` id this act is taken under.
    pub delegation_id: String,
    /// **MANDATORY.** Free text: WHY. Recorded, never interpreted.
    pub reason: String,
    /// Read only by [`SelfAct::LegalCompulsion`], and optional there: an
    /// operator under a gag order may be unable to name the authority
    /// compelling them. Recorded verbatim, never interpreted, and its ABSENCE
    /// is not a defect — "compelled, cannot say by whom" is a real and common
    /// state, and refusing to record the act without it would mean the most
    /// constrained operator is the one who cannot leave a trace.
    #[serde(default)]
    pub compelled_by: Option<String>,
}

/// Resolve the authority for a self-directed or reader act: the ordinary
/// re-derivation, **plus** the requirement that the issuer is this node's
/// responsible party.
///
/// `infra:serve` is a scope any number of parties could grant this node. Only
/// one of them is its owner, and a self-directed act is the owner's own — so
/// the chain is re-walked exactly as every other rung's is
/// ([`resolve_authority`]) and then the issuer is compared against
/// [`is_steward_bound`], the same single-owner projection `auth::gate` uses.
async fn resolve_owner_authority(
    st: &AdminOpsState,
    delegation_id: &str,
) -> Result<AuthorityProof, Response> {
    let node_key_id = self_key_id(st).await?;
    let proof = resolve_authority(
        &st.engine,
        &node_key_id,
        delegation_id,
        REQUIRED_SCOPE_SELF_DIRECTED,
    )
    .await?;
    let Some(owner) = is_steward_bound(&st.engine, &node_key_id).await else {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "node_unowned",
            "admin.refusal.node_unowned",
            "This node has no responsible party (owner-binding), so it performs no graded \
             admin operation on anyone's behalf. Claim ownership first.",
        ));
    };
    // An OCCURRENCE of the owner issues as the owner (CIRISServer#391): the
    // delegation is the self's act whichever of the self's devices signed it.
    if !crate::auth::verify::signer_acts_for(&st.engine, &proof.issuer_key_id, &owner).await {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_not_the_owner",
            "admin.refusal.authority_not_the_owner",
            "A self-directed act is the owner's own. The named delegation carries the right \
             scope but was not issued by this node's responsible party, and a third party's \
             serve grant is not the owner's.",
        ));
    }
    Ok(proof)
}

/// Shared body for all six tier S routes.
async fn self_act_route(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    act: SelfAct,
    declaring: bool,
) -> Response {
    let node_key_id = match self_key_id(st).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(resp) = gate(st, headers).await {
        return resp;
    }
    let c: SelfCommit = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    if c.reason.trim().is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "attribution_absent",
            "admin.refusal.reason_absent",
            "reason is required. An action with no recorded reason is indistinguishable \
             from an unauthorized one once the actor is gone.",
        );
    }
    let authority = match resolve_owner_authority(st, &c.delegation_id).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let op = if declaring {
        act.assert_op()
    } else {
        act.lift_op()
    };
    let now = Utc::now();
    let mut context = serde_json::json!({
        "axis": act.axis(),
        "act": if declaring { "declaration" } else { "lift" },
        "self_directed": true,
        "issuer_key_id": authority.issuer_key_id,
    });
    // `compelled_by` rides ONLY on the compulsion declaration. Recording it on
    // any other act would let a voluntary stop carry the marks of a compelled
    // one, which is the conflation this tier is built to prevent.
    if act == SelfAct::LegalCompulsion && declaring {
        if let Some(o) = context.as_object_mut() {
            o.insert(
                "compelled_by".into(),
                serde_json::json!(c
                    .compelled_by
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())),
            );
        }
    }
    let ev = tombstone(
        op,
        &node_key_id,
        &authority.delegation_id,
        &c.reason,
        now,
        context,
    );
    let event_id = match record(&st.engine, ev).await {
        Ok(id) => id,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The self-directed act could not be recorded: {e}"),
            )
        }
    };
    tracing::warn!(
        op,
        tier = "S",
        axis = act.axis(),
        delegation_id = %authority.delegation_id,
        reason = %c.reason,
        "self-directed admin act recorded"
    );

    // Re-read the axis so the caller sees the standing this act produced,
    // folded by the same function the standing route runs — never a second
    // answer assembled from what we just wrote.
    let standing = match read_self_axis(&st.engine, &node_key_id, act, now).await {
        Ok(f) => f,
        Err(_) => self_axis_unreadable(act),
    };
    let mut out = serde_json::json!({
        "op": op,
        "tier": "S",
        "axis": act.axis(),
        "source_locale": SOURCE_LOCALE,
        "required_scope": REQUIRED_SCOPE_SELF_DIRECTED,
        "delegation_id": authority.delegation_id,
        "event_id": event_id,
        "standing": self_fold_json(&standing),
        "enforcement": act.enforcement(),
        "partition": partition_note(),
    });
    if !declaring {
        out["reversal"] = reversal_json(ReversalReach::Symmetric);
        out["lift"] = act.lift_note();
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn self_shed(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    self_act_route(&st, &headers, &body, SelfAct::ShedLoad, true).await
}

async fn self_resume_load(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    self_act_route(&st, &headers, &body, SelfAct::ShedLoad, false).await
}

async fn self_stop_accepting(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    self_act_route(&st, &headers, &body, SelfAct::StopAccepting, true).await
}

async fn self_resume_accepting(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    self_act_route(&st, &headers, &body, SelfAct::StopAccepting, false).await
}

async fn self_compelled(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    self_act_route(&st, &headers, &body, SelfAct::LegalCompulsion, true).await
}

async fn self_compulsion_lifted(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    self_act_route(&st, &headers, &body, SelfAct::LegalCompulsion, false).await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier R — subject-side / per-reader (NoCeM's actual property)
// ═══════════════════════════════════════════════════════════════════════════

/// The `detail` key naming WHICH judgement a reader decision is about.
///
/// Server-minted, and it has to be: persist's
/// [`admin_field`](ciris_persist::federation::hard_case::admin_field) owns
/// `delegation_id` / `reason` / `op` — the three keys its own attribution gate
/// reads — and has no vocabulary for a judgement reference, because no persist
/// op takes one.
pub const READER_JUDGEMENT_FIELD: &str = "judgement_id";

/// **What THIS reader does with one judgement.** Four outcomes, and three of
/// them are "not honoured" for three different reasons — the same discipline
/// [`SelfStanding`] applies to the self axes, applied per judgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderDecision {
    /// This reader decided to honour it. The signer need not be subscribed —
    /// deliberate adoption of one judgement is a first-class act.
    HonouredExplicit,
    /// No explicit decision, and the signer is in this reader's subscription
    /// set, so it is honoured by policy.
    HonouredBySubscription,
    /// No explicit decision and the signer is not subscribed. **Not honoured,
    /// and nobody decided that** — distinct from a decline, which is a
    /// decision, and the distinction is what tells an operator whether they
    /// have looked at this judgement yet.
    UndecidedUnsubscribed,
    /// This reader refused it. **A normal outcome, never an error.**
    Declined,
}

impl ReaderDecision {
    /// The stable program token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::HonouredExplicit => "honoured_explicit",
            Self::HonouredBySubscription => "honoured_by_subscription",
            Self::UndecidedUnsubscribed => "undecided_unsubscribed",
            Self::Declined => "declined",
        }
    }

    /// Does this judgement enter this reader's fold?
    #[must_use]
    pub const fn honoured(self) -> bool {
        matches!(self, Self::HonouredExplicit | Self::HonouredBySubscription)
    }

    fn note(self) -> serde_json::Value {
        match self {
            Self::HonouredExplicit => m(
                "admin.reader.decision.honoured_explicit",
                "This reader adopted this judgement deliberately.",
            ),
            Self::HonouredBySubscription => m(
                "admin.reader.decision.honoured_by_subscription",
                "No explicit decision was recorded; this reader subscribes to the signer, so \
                 the judgement is honoured by policy.",
            ),
            Self::UndecidedUnsubscribed => m(
                "admin.reader.decision.undecided_unsubscribed",
                "This reader does not subscribe to the signer and has recorded no decision. \
                 The judgement is not honoured, and that is nobody's decision yet — which is \
                 a different fact from having refused it.",
            ),
            Self::Declined => m(
                "admin.reader.decision.declined",
                "This reader refused this judgement. A normal outcome: an issued judgement is \
                 advisory to each reader, and refusing one is the property the whole rung \
                 exists for.",
            ),
        }
    }
}

/// The standing of a whole tier R read. Same three-way discipline: an empty
/// answer and an unanswerable one never render alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderStanding {
    /// Judgements were held and classified.
    Decided,
    /// This node holds no judgement about that subject at all.
    NoJudgementsHeld,
    /// A read failed, so this reader does not know what it holds.
    Unreadable,
}

impl ReaderStanding {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Decided => "decided",
            Self::NoJudgementsHeld => "no_judgements_held",
            Self::Unreadable => "unreadable",
        }
    }

    fn note(self) -> serde_json::Value {
        match self {
            Self::Decided => m(
                "admin.reader.standing.decided",
                "Every judgement this node holds about that subject is listed with what this \
                 reader does about it.",
            ),
            Self::NoJudgementsHeld => m(
                "admin.reader.standing.none_held",
                "This node holds no judgement about that subject. Nobody has judged it here — \
                 which is not the same as this node being unable to say.",
            ),
            Self::Unreadable => m(
                "admin.reader.standing.unreadable",
                "This reader could not read its own state, so it cannot say what it honours. \
                 This is NOT 'no judgements' and NOT 'nothing withheld' — an unreadable policy \
                 rendered as an empty one silently drops every restriction it carried.",
            ),
        }
    }
}

/// Is this judgement set too large to fold? **Refuses; never truncates.**
///
/// Pure, so the boundary is testable without building 2,000 markers: a fold
/// over a truncated page can lose the governing withhold and report
/// `not_quarantined`, which is a release nobody signed.
#[must_use]
pub const fn judgement_page_refusal(held: usize) -> Option<usize> {
    if held > MAX_JUDGEMENT_PAGE {
        Some(MAX_JUDGEMENT_PAGE)
    } else {
        None
    }
}

/// Every judgement this node holds about `subject_key_id`.
///
/// Persist's own gatherer (`markers_about`) is private, so the READ is mirrored
/// here — but the PREDICATE is persist's
/// ([`is_marker_dimension`](ciris_persist::federation::quarantine::is_marker_dimension))
/// and the envelope key is persist's ([`paths::DIMENSION`]), so nothing that
/// decides *what counts as a judgement* is restated. The same mirroring
/// [`delegation_scopes`] documents, for the same reason, and the same test
/// obligation: `tests/admin_ops.rs` asserts this gatherer plus persist's fold
/// agrees with persist's own `resolve_quarantine` over the identical subject.
async fn judgements_about(
    engine: &Arc<Engine>,
    subject_key_id: &str,
) -> Result<Vec<Attestation>, String> {
    let rows = engine
        .federation_directory()
        .list_attestations_for(subject_key_id)
        .await
        .map_err(|e| format!("list judgements: {e}"))?;
    Ok(rows
        .into_iter()
        .filter(|r| {
            r.attestation_envelope
                .get(paths::DIMENSION)
                .and_then(|v| v.as_str())
                .is_some_and(quarantine::is_marker_dimension)
        })
        .collect())
}

/// This reader's subscription set, and which of `signers` it admits.
///
/// Two persist walks and no third rule of our own:
/// [`trusted_roots_of`] is this node's own live trust edges (persist's leg-1
/// predicate, not a re-filter of `list_attestations_by`), and
/// `reachable_under_scope` is the §11.10 scoped-delegation walk every other
/// rung here uses. A signer is admitted if it IS a subscribed root or a
/// `slash`-bearing chain reaches it from one.
///
/// A failure on either walk is an error, never an empty set: an empty
/// subscription set honours nothing, which withholds nothing, which is the
/// fail-OPEN direction — a read error would silently release every quarantine
/// this reader had adopted.
async fn reader_subscription(
    engine: &Arc<Engine>,
    node_key_id: &str,
    signers: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> Result<(Vec<String>, BTreeSet<String>), String> {
    let directory = engine.federation_directory();
    let roots = trusted_roots_of(directory.as_ref(), node_key_id, now)
        .await
        .map_err(|e| format!("read subscription set: {e}"))?;
    let mut admitted: BTreeSet<String> = BTreeSet::new();
    for signer in signers {
        if roots.iter().any(|r| r == signer) {
            admitted.insert(signer.clone());
            continue;
        }
        for root in &roots {
            let reaches = engine
                .reachable_under_scope(
                    root,
                    signer,
                    DELEGATION_SCOPE_SLASH,
                    MAX_MODERATION_DELEGATION_DEPTH,
                )
                .await
                .map_err(|e| format!("subscription walk: {e}"))?;
            if reaches {
                admitted.insert(signer.clone());
                break;
            }
        }
    }
    Ok((roots, admitted))
}

/// This reader's explicit decisions, keyed by judgement id: `true` = declined.
///
/// # Ordering
///
/// Newest wins; **at a tie the HONOUR wins**, and the argument is different
/// from tier S's. Neither decision is inherently the restrictive one — honouring
/// a *release* marker is a relaxation — so the tie is resolved on EVIDENCE
/// rather than on state: the outcome that keeps the judgement inside the row
/// set persist's fold sees is the one that loses no information, and persist's
/// own fold then applies its own withhold-beats-release rule to what it is
/// given. Two rules, two layers, neither reimplementing the other.
async fn reader_decisions(engine: &Arc<Engine>) -> Result<BTreeMap<String, bool>, String> {
    let directory = engine.federation_directory();
    let mut events: Vec<(HardCaseEvent, bool)> = Vec::new();
    for (op, declined) in [(OP_READER_HONOUR, false), (OP_READER_DECLINE, true)] {
        let page = directory
            .list_hard_case_events(HardCaseFilter {
                kind: Some(admin_action_kind(op)),
                since: None,
            })
            .await
            .map_err(|e| format!("read reader decisions: {e}"))?;
        events.extend(page.into_iter().map(|e| (e, declined)));
    }
    // Ascending; the last write for a judgement governs. `declined` sorts
    // BEFORE `honoured` so an honour at the same instant is the survivor.
    events.sort_by(|(a, da), (b, db)| {
        a.emitted_at
            .cmp(&b.emitted_at)
            .then_with(|| db.cmp(da))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    let mut out: BTreeMap<String, bool> = BTreeMap::new();
    for (ev, declined) in events {
        if let Some(id) = detail_str(&ev, READER_JUDGEMENT_FIELD) {
            out.insert(id, declined);
        }
    }
    Ok(out)
}

/// The classification rule, alone and pure.
///
/// An explicit decision always beats the subscription default — in **both**
/// directions. A decline overrides a subscribed signer (the reader's refusal is
/// the whole rung) and an honour adopts an unsubscribed one (adoption is a
/// decision too).
#[must_use]
pub const fn classify_judgement(explicit: Option<bool>, subscribed: bool) -> ReaderDecision {
    match explicit {
        Some(true) => ReaderDecision::Declined,
        Some(false) => ReaderDecision::HonouredExplicit,
        None if subscribed => ReaderDecision::HonouredBySubscription,
        None => ReaderDecision::UndecidedUnsubscribed,
    }
}

/// What one tier R read produced.
struct ReaderFold {
    standing: ReaderStanding,
    /// `(judgement, decision)` for everything held about the subject.
    judgements: Vec<(Attestation, ReaderDecision)>,
    roots: Vec<String>,
    /// This reader's fold — persist's own, over the honoured subset.
    reader: quarantine::QuarantineFold,
    /// What this node's SERVE paths do today — persist's own, over everything
    /// held. The two differ exactly when the reader has declined something.
    node: quarantine::QuarantineFold,
}

/// Run one tier R read over `subject_key_id`.
///
/// **`fold_quarantine` is called twice and written zero times.** It is persist's
/// pure fold, and the only thing that differs between the two calls is which
/// rows are handed to it — which is the whole of what "the reader decides"
/// means, and the reason this rung needs no fold of its own.
async fn run_reader_fold(
    engine: &Arc<Engine>,
    node_key_id: &str,
    subject_key_id: &str,
    now: DateTime<Utc>,
) -> Result<ReaderFold, String> {
    let held = judgements_about(engine, subject_key_id).await?;
    if let Some(cap) = judgement_page_refusal(held.len()) {
        return Err(format!(
            "this node holds {} judgements about that subject, above the {cap} a single fold \
             will read; folding a truncated set would report a release nobody signed",
            held.len()
        ));
    }
    let signers: BTreeSet<String> = held.iter().map(|r| r.attesting_key_id.clone()).collect();
    let (roots, subscribed) = reader_subscription(engine, node_key_id, &signers, now).await?;
    let explicit = reader_decisions(engine).await?;

    let judgements: Vec<(Attestation, ReaderDecision)> = held
        .iter()
        .map(|r| {
            let decision = classify_judgement(
                explicit.get(&r.attestation_id).copied(),
                subscribed.contains(&r.attesting_key_id),
            );
            (r.clone(), decision)
        })
        .collect();
    let honoured: Vec<Attestation> = judgements
        .iter()
        .filter(|(_, d)| d.honoured())
        .map(|(r, _)| r.clone())
        .collect();

    Ok(ReaderFold {
        standing: if held.is_empty() {
            ReaderStanding::NoJudgementsHeld
        } else {
            ReaderStanding::Decided
        },
        reader: quarantine::fold_quarantine(subject_key_id, &honoured, now),
        node: quarantine::fold_quarantine(subject_key_id, &held, now),
        judgements,
        roots,
    })
}

fn reader_fold_json(subject_key_id: &str, f: &ReaderFold) -> serde_json::Value {
    let judgements: Vec<serde_json::Value> = f
        .judgements
        .iter()
        .map(|(r, d)| {
            serde_json::json!({
                "judgement_id": r.attestation_id,
                "signer_key_id": r.attesting_key_id,
                "dimension": r.attestation_envelope.get(paths::DIMENSION)
                    .and_then(|v| v.as_str()),
                "asserted_at": r.asserted_at.to_rfc3339(),
                "decision": d.token(),
                "honoured": d.honoured(),
                "message": d.note(),
            })
        })
        .collect();
    let diverges = f.reader.state != f.node.state;
    serde_json::json!({
        "source_locale": SOURCE_LOCALE,
        "tier": "R",
        "subject_key_id": subject_key_id,
        "standing": f.standing.token(),
        "message": f.standing.note(),
        "subscription": { "roots": f.roots, "count": f.roots.len() },
        "counts": { "judgements_held": f.judgements.len() },
        "judgements": judgements,
        "reader_fold": f.reader,
        "node_fold": f.node,
        "diverges": diverges,
        "advisory": m(
            "admin.reader.advisory",
            "An issued judgement is advisory to each reader. `reader_fold` is what THIS \
             reader's policy makes of what it holds; `node_fold` is what this node's serve \
             paths do today, which is to honour every marker the substrate admitted. They can \
             differ, and when they do the difference is the substrate gap: there is no \
             reader-policy hook in the serve-side fold, so a decline is recorded and reported \
             and does not yet stop this node withholding.",
        ),
    })
}

#[derive(Debug, Clone, Deserialize)]
struct ReaderFoldRequest {
    /// Whose judgements to read — the key the held judgements are ABOUT.
    subject_key_id: String,
}

async fn reader_fold_route(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let node_key_id = match self_key_id(&st).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
    let req: ReaderFoldRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let subject = req.subject_key_id.trim();
    if subject.is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "subject_absent",
            "admin.refusal.subject_absent",
            "subject_key_id is required: a reader fold is about one subject's judgements, and \
             an unnamed subject is every subject.",
        );
    }
    match run_reader_fold(&st.engine, &node_key_id, subject, Utc::now()).await {
        Ok(f) => (StatusCode::OK, Json(reader_fold_json(subject, &f))).into_response(),
        // The unreadable standing is rendered on BOTH halves: a 503 a client
        // ignores must not leave it a body that reads like an empty policy.
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "source_locale": SOURCE_LOCALE,
                "tier": "R",
                "subject_key_id": subject,
                "standing": ReaderStanding::Unreadable.token(),
                "message": ReaderStanding::Unreadable.note(),
                "refusal": "reader_state_unreadable",
                "error": e,
            })),
        )
            .into_response(),
    }
}

/// The body of a reader decision. Like tier S, **no selection hash**: the
/// object is one immutable signed row named by its own id, so there is no set
/// to ratify and no window in which it could change under the operator.
#[derive(Debug, Clone, Deserialize)]
pub struct ReaderCommit {
    /// The `attestation_id` of the judgement being honoured or declined.
    pub judgement_id: String,
    /// **MANDATORY.** The owner's `delegates_to` id this decision is taken
    /// under.
    pub delegation_id: String,
    /// **MANDATORY.** Free text: WHY. Recorded, never interpreted.
    pub reason: String,
}

/// Shared body for honour + decline: same gates, opposite decision, and the
/// SAME status code — a decline is not an error path.
async fn reader_decision_route(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    declining: bool,
) -> Response {
    let node_key_id = match self_key_id(st).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(resp) = gate(st, headers).await {
        return resp;
    }
    let c: ReaderCommit = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    if c.reason.trim().is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "attribution_absent",
            "admin.refusal.reason_absent",
            "reason is required. An action with no recorded reason is indistinguishable \
             from an unauthorized one once the actor is gone.",
        );
    }
    let authority = match resolve_owner_authority(st, &c.delegation_id).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    // The judgement must be a row this node HOLDS, and must be a judgement.
    let judgement_id = c.judgement_id.trim();
    let row = match st
        .engine
        .federation_directory()
        .get_attestation(judgement_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return refusal(
                StatusCode::NOT_FOUND,
                "judgement_unresolved",
                "admin.refusal.judgement_unresolved",
                "That judgement is not a row this node holds, so this reader has nothing to \
                 decide about. A reader decides what it HOLDS; it does not pre-refuse what it \
                 has never seen.",
            )
        }
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The substrate could not be read: {e}"),
            )
        }
    };
    let dimension = row
        .attestation_envelope
        .get(paths::DIMENSION)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    if !quarantine::is_marker_dimension(&dimension) {
        return refusal(
            StatusCode::BAD_REQUEST,
            "not_a_judgement",
            "admin.refusal.not_a_judgement",
            "That row is not a judgement this rung can decide about. Tier R is the reader's \
             policy over other parties' JUDGEMENTS, and an ordinary attestation is not one.",
        );
    }
    let Some(subject) = row
        .attestation_envelope
        .get(quarantine::field::QUARANTINES)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "judgement_subjectless",
            "admin.refusal.judgement_subjectless",
            "That judgement names no subject, so honouring or declining it would change \
             nothing about anyone. This node does not record a decision it cannot apply.",
        );
    };

    let op = if declining {
        OP_READER_DECLINE
    } else {
        OP_READER_HONOUR
    };
    let now = Utc::now();
    let mut ev = tombstone(
        op,
        subject,
        &authority.delegation_id,
        &c.reason,
        now,
        serde_json::json!({
            READER_JUDGEMENT_FIELD: judgement_id,
            "judgement_signer_key_id": row.attesting_key_id,
            "judgement_dimension": dimension,
            "decision": if declining { "declined" } else { "honoured" },
        }),
    );
    // Persist keys an admin-action `event_id` on `(op, target, second)`, and
    // the target of a reader decision is the judgement's SUBJECT — so two
    // decisions about two judgements naming one subject inside one second would
    // collapse onto each other. They are two acts, so the judgement id joins
    // the key. Persist's prefix and shape are otherwise untouched.
    ev.event_id = format!("{}:{judgement_id}", ev.event_id);
    let event_id = match record(&st.engine, ev).await {
        Ok(id) => id,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The reader decision could not be recorded: {e}"),
            )
        }
    };
    tracing::warn!(
        op,
        tier = "R",
        judgement_id,
        subject,
        delegation_id = %authority.delegation_id,
        reason = %c.reason,
        "reader decision recorded"
    );

    let mut out = serde_json::json!({
        "op": op,
        "tier": "R",
        "source_locale": SOURCE_LOCALE,
        "required_scope": REQUIRED_SCOPE_SELF_DIRECTED,
        "judgement_id": judgement_id,
        "subject_key_id": subject,
        "delegation_id": authority.delegation_id,
        "event_id": event_id,
        "outcome": if declining { "declined" } else { "honoured" },
        // Stated in the payload, not only in the status code: a decline is a
        // decision this rung is FOR, and a client that branches on shape rather
        // than on 2xx must not read it as a failure.
        "refused": false,
        "message": if declining {
            ReaderDecision::Declined.note()
        } else {
            ReaderDecision::HonouredExplicit.note()
        },
    });
    // Show the state this decision produced, through the same read the fold
    // route runs.
    match run_reader_fold(&st.engine, &node_key_id, subject, now).await {
        Ok(f) => out["standing"] = reader_fold_json(subject, &f),
        Err(e) => {
            out["standing"] = serde_json::json!({
                "standing": ReaderStanding::Unreadable.token(),
                "message": ReaderStanding::Unreadable.note(),
                "error": e,
            });
        }
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn reader_honour(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    reader_decision_route(&st, &headers, &body, false).await
}

async fn reader_decline(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    reader_decision_route(&st, &headers, &body, true).await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════════════════

/// The graded admin-op router.
///
/// **It takes no key id** (CIRISServer#372 Level 2). THIS node's #247 DERIVED
/// federation key id — the ACTING key whose delegated authority every op
/// re-walks, and the identity `emit_attestation_self` / `sign_hybrid` sign as —
/// is resolved per request from the engine that will actually sign (see
/// [`self_key_id`]). There is no argument here for a caller, a harness or a CLI
/// label to disagree with.
pub fn router(engine: Arc<Engine>) -> Router {
    let state = AdminOpsState { engine };
    Router::new()
        .route("/v1/admin/preview", axum::routing::post(preview))
        .route("/v1/admin/annotate", axum::routing::post(annotate))
        .route("/v1/admin/throttle", axum::routing::post(throttle))
        .route("/v1/admin/un-throttle", axum::routing::post(un_throttle))
        .route(
            "/v1/admin/quarantine",
            axum::routing::post(quarantine_route),
        )
        .route(
            "/v1/admin/un-quarantine",
            axum::routing::post(un_quarantine_route),
        )
        .route("/v1/admin/descend", axum::routing::post(descend))
        .route("/v1/admin/deadmit", axum::routing::post(deadmit))
        .route("/v1/admin/re-admit", axum::routing::post(re_admit))
        // Tier 4's WRITE DOOR (AV-77) — deliberately not spelled `deadmit`.
        .route(
            "/v1/admin/refuse-writes",
            axum::routing::post(refuse_writes),
        )
        .route(
            "/v1/admin/accept-writes",
            axum::routing::post(accept_writes),
        )
        // Tier S — self-directed. The read is a GET because it is a read.
        .route("/v1/admin/self", axum::routing::get(self_standing))
        .route("/v1/admin/self/shed", axum::routing::post(self_shed))
        .route(
            "/v1/admin/self/resume-load",
            axum::routing::post(self_resume_load),
        )
        .route(
            "/v1/admin/self/stop-accepting",
            axum::routing::post(self_stop_accepting),
        )
        .route(
            "/v1/admin/self/resume-accepting",
            axum::routing::post(self_resume_accepting),
        )
        .route(
            "/v1/admin/self/compelled",
            axum::routing::post(self_compelled),
        )
        .route(
            "/v1/admin/self/compulsion-lifted",
            axum::routing::post(self_compulsion_lifted),
        )
        // Tier R — subject-side.
        .route(
            "/v1/admin/reader/fold",
            axum::routing::post(reader_fold_route),
        )
        .route(
            "/v1/admin/reader/honour",
            axum::routing::post(reader_honour),
        )
        .route(
            "/v1/admin/reader/decline",
            axum::routing::post(reader_decline),
        )
        .with_state(state)
}

// ═══════════════════════════════════════════════════════════════════════════
//  The pure halves — unit-tested here, because a router cannot reach them all
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    /// The singular and plural coexist — persist OR-combines them, so naming one
    /// key and a set in the same act selects the union, not the intersection.
    #[test]
    fn singular_and_plural_key_predicates_coexist() {
        let sel = Selection {
            attested_key_id: Some("solo".into()),
            attested_key_ids: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let f = sel.to_filter();
        assert_eq!(f.attested_key_id.as_deref(), Some("solo"));
        assert_eq!(f.attested_key_ids, vec!["a".to_string(), "b".to_string()]);
        assert!(!sel.is_unpredicated());
    }

    /// **A set of keys is ONE act** (CIRISPersist#627, persist v30.9.0).
    ///
    /// Clearing the 61 exposed keys of CIRISServer#383 used to be 61
    /// preview→commit pairs. The set now reaches the QUERY — asserted on the
    /// filter, because the whole point is that no loop appears on this side.
    #[test]
    fn a_key_set_reaches_the_filter_as_a_set() {
        let sel = Selection {
            attested_key_ids: vec![
                "  leaked-a  ".into(),
                "leaked-b".into(),
                "leaked-a".into(), // duplicate
                "   ".into(),      // blank
            ],
            ..Default::default()
        };
        let f = sel.to_filter();
        assert_eq!(
            f.attested_key_ids,
            vec!["leaked-a".to_string(), "leaked-b".to_string()],
            "trimmed, de-duplicated, blanks dropped — a blank would widen the \
             predicate to a key that cannot exist"
        );
        assert!(
            f.attested_key_id.is_none(),
            "the singular stays empty; persist OR-combines the two"
        );
    }

    /// A set IS a predicate. Treating an act with 61 named subjects as
    /// "unpredicated" would refuse the exact operation this unblocks — and the
    /// refusal names selection_unpredicated, which would read as nonsense to an
    /// operator who just pasted 61 keys.
    #[test]
    fn a_key_set_alone_is_a_predicate() {
        let sel = Selection {
            attested_key_ids: vec!["k1".into()],
            ..Default::default()
        };
        assert!(!sel.is_unpredicated());

        let blanks = Selection {
            attested_key_ids: vec!["   ".into()],
            ..Default::default()
        };
        assert!(
            blanks.is_unpredicated(),
            "a set of blanks predicates NOTHING and must not pass the gate"
        );
        assert!(Selection::default().is_unpredicated());
    }

    use super::*;

    const NODE: &str = "node-under-test";

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + secs, 0).expect("instant")
    }

    fn act_event(op: &str, target: &str, when: DateTime<Utc>, suffix: &str) -> HardCaseEvent {
        let mut ev = admin_action_event(op, target, Some(target), "deleg-1", "because", when);
        ev.event_id = format!("{}:{suffix}", ev.event_id);
        ev
    }

    #[test]
    fn an_axis_with_no_acts_is_never_declared_and_carries_no_instant() {
        let f = fold_self_standing(SelfAct::ShedLoad, NODE, &[], at(0));
        assert_eq!(f.standing, SelfStanding::NeverDeclared);
        assert!(f.since.is_none() && f.event_id.is_none());
        assert_eq!((f.declarations, f.lifts), (0, 0));
    }

    #[test]
    fn a_declaration_then_a_lift_is_lifted_and_not_never_declared() {
        let events = vec![
            act_event(OP_SELF_SHED, NODE, at(0), "a"),
            act_event(OP_SELF_SHED_RELEASE, NODE, at(10), "b"),
        ];
        let f = fold_self_standing(SelfAct::ShedLoad, NODE, &events, at(100));
        assert_eq!(f.standing, SelfStanding::Lifted);
        assert_eq!((f.declarations, f.lifts), (1, 1));
        assert_eq!(f.since, Some(at(10)));
        assert_ne!(
            SelfStanding::Lifted.token(),
            SelfStanding::NeverDeclared.token()
        );
    }

    /// **The write door's three zeroes, at the source.**
    ///
    /// `tests/admin_ops.rs` drives the `admitted → refused → admitted`
    /// transition through the real route, but it cannot drive `Unreadable`
    /// without a broken store — and that is the one that kills, because
    /// rendered as `Admitted` it is a false clean. So the distinctness is
    /// pinned here, over the values the routes actually emit rather than over
    /// the bundle they are looked up in.
    #[test]
    fn the_three_admission_standings_never_render_alike() {
        let all = [
            AdmissionStanding::Refused,
            AdmissionStanding::Admitted,
            AdmissionStanding::Unreadable,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    a.token(),
                    b.token(),
                    "two standings share one program token, so a caller cannot branch on them"
                );
                assert_ne!(
                    a.note(),
                    b.note(),
                    "two standings render the same sentence, so an operator cannot tell them \
                     apart"
                );
            }
        }
        let unreadable = AdmissionStanding::Unreadable.note();
        let text = unreadable["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("NOT 'admitted'"),
            "the unreadable standing must say IN THE STRING AN OPERATOR READS that it is not \
             the clean one — a distinct token nobody renders is not a distinct fact: {text}"
        );
    }

    #[test]
    fn at_an_identical_instant_the_declaration_wins() {
        // Persist keys an admin-action event_id on the whole second, so this is
        // reachable by ordinary haste. Resolving it toward the lift would tell
        // an operator they are running when they declared they are not.
        let events = vec![
            act_event(OP_SELF_COMPELLED, NODE, at(5), "zzz"),
            act_event(OP_SELF_COMPULSION_LIFTED, NODE, at(5), "aaa"),
        ];
        let f = fold_self_standing(SelfAct::LegalCompulsion, NODE, &events, at(100));
        assert_eq!(
            f.standing,
            SelfStanding::InForce,
            "the restriction survives a tie, whichever event_id sorts first"
        );
    }

    #[test]
    fn the_axes_never_read_each_others_acts() {
        let events = vec![act_event(OP_SELF_STOP_ACCEPTING, NODE, at(0), "a")];
        assert_eq!(
            fold_self_standing(SelfAct::StopAccepting, NODE, &events, at(1)).standing,
            SelfStanding::InForce
        );
        assert_eq!(
            fold_self_standing(SelfAct::LegalCompulsion, NODE, &events, at(1)).standing,
            SelfStanding::NeverDeclared,
            "a node that chose to stop has NOT declared a compulsion"
        );
        assert_eq!(
            fold_self_standing(SelfAct::ShedLoad, NODE, &events, at(1)).standing,
            SelfStanding::NeverDeclared
        );
    }

    #[test]
    fn another_nodes_acts_are_not_this_nodes_standing() {
        let events = vec![act_event(OP_SELF_SHED, "some-other-node", at(0), "a")];
        assert_eq!(
            fold_self_standing(SelfAct::ShedLoad, NODE, &events, at(1)).standing,
            SelfStanding::NeverDeclared
        );
    }

    #[test]
    fn a_future_dated_act_does_not_govern_yet() {
        let events = vec![act_event(OP_SELF_SHED, NODE, at(500), "a")];
        assert_eq!(
            fold_self_standing(SelfAct::ShedLoad, NODE, &events, at(0)).standing,
            SelfStanding::NeverDeclared
        );
    }

    /// The branch no router test can reach on a healthy substrate, and the one
    /// the RCA is about: an unreadable standing must not be a zero.
    #[test]
    fn unreadable_is_not_a_zero_on_either_half() {
        for &act in SelfAct::ALL {
            let u = self_axis_unreadable(act);
            assert_eq!(u.standing, SelfStanding::Unreadable);
            assert_eq!(u.axis, act.axis());
        }
        let ids: BTreeSet<String> = [
            SelfStanding::InForce,
            SelfStanding::Lifted,
            SelfStanding::NeverDeclared,
            SelfStanding::Unreadable,
        ]
        .iter()
        .map(|s| {
            s.note()["id"]
                .as_str()
                .expect("every standing note carries an id")
                .to_owned()
        })
        .collect();
        assert_eq!(
            ids.len(),
            4,
            "four standings must render four different sentences: {ids:?}"
        );
    }

    #[test]
    fn every_self_act_has_its_own_axis_ops_and_notes() {
        let axes: BTreeSet<&str> = SelfAct::ALL.iter().map(|a| a.axis()).collect();
        let ops: BTreeSet<&str> = SelfAct::ALL
            .iter()
            .flat_map(|a| [a.assert_op(), a.lift_op()])
            .collect();
        let notes: BTreeSet<String> = SelfAct::ALL
            .iter()
            .map(|a| a.enforcement()["id"].as_str().expect("id").to_owned())
            .collect();
        assert_eq!(axes.len(), 3);
        assert_eq!(ops.len(), 6, "six ops, none shared: {ops:?}");
        assert_eq!(notes.len(), 3, "three enforcement notes: {notes:?}");
    }

    #[test]
    fn an_explicit_reader_decision_beats_the_subscription_in_both_directions() {
        assert_eq!(
            classify_judgement(Some(true), true),
            ReaderDecision::Declined,
            "a decline overrides a subscribed signer — that is the whole rung"
        );
        assert_eq!(
            classify_judgement(Some(false), false),
            ReaderDecision::HonouredExplicit,
            "adopting an unsubscribed signer's judgement is a decision too"
        );
        assert_eq!(
            classify_judgement(None, true),
            ReaderDecision::HonouredBySubscription
        );
        assert_eq!(
            classify_judgement(None, false),
            ReaderDecision::UndecidedUnsubscribed
        );
        assert!(ReaderDecision::HonouredBySubscription.honoured());
        assert!(!ReaderDecision::UndecidedUnsubscribed.honoured());
    }

    #[test]
    fn the_four_reader_decisions_render_four_different_sentences() {
        let ids: BTreeSet<String> = [
            ReaderDecision::HonouredExplicit,
            ReaderDecision::HonouredBySubscription,
            ReaderDecision::UndecidedUnsubscribed,
            ReaderDecision::Declined,
        ]
        .iter()
        .map(|d| d.note()["id"].as_str().expect("id").to_owned())
        .collect();
        assert_eq!(ids.len(), 4, "{ids:?}");
        let standings: BTreeSet<String> = [
            ReaderStanding::Decided,
            ReaderStanding::NoJudgementsHeld,
            ReaderStanding::Unreadable,
        ]
        .iter()
        .map(|s| s.note()["id"].as_str().expect("id").to_owned())
        .collect();
        assert_eq!(
            standings.len(),
            3,
            "'nothing held' and 'could not read' are different sentences: {standings:?}"
        );
    }

    #[test]
    fn an_oversized_judgement_set_refuses_rather_than_truncating() {
        assert_eq!(judgement_page_refusal(0), None);
        assert_eq!(judgement_page_refusal(MAX_JUDGEMENT_PAGE), None);
        assert_eq!(
            judgement_page_refusal(MAX_JUDGEMENT_PAGE + 1),
            Some(MAX_JUDGEMENT_PAGE),
            "one over the ceiling REFUSES; a truncated fold reports a release nobody signed"
        );
    }
}
