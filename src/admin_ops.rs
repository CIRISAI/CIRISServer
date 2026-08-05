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
//! ```
//!
//! `*` — see [`REQUIRED_SCOPE_QUARANTINE`]. The FSD ladder says tier 2 is
//! `moderate`; persist's own admission door says `slash`. The substrate wins.
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
    attestation_tier, attestation_type, cohort_scope, Attestation, Revocation, SignedRevocation,
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
    /// THIS node's federation `key_id` — the ACTING key of every op here, and
    /// the key whose delegated authority is re-walked.
    node_key_id: String,
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
async fn gate(st: &AdminOpsState, headers: &HeaderMap) -> Result<(), Response> {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
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
    Ok(())
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
    #[serde(default)]
    pub attesting_key_id: Option<String>,
    /// Rows authored ABOUT this key.
    #[serde(default)]
    pub attested_key_id: Option<String>,
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
    fn to_filter(&self) -> AttestationFilter {
        let n = self.normalized();
        let mut f = AttestationFilter::default();
        f.attesting_key_id = n.attesting_key_id;
        f.attested_key_id = n.attested_key_id;
        f.attestation_type = n.attestation_type;
        f.dimension_prefixes = n.dimension_prefixes;
        f.dimension_exact = n.dimension_exact;
        f.subject_key_id = n.subject_key_id;
        f.window = match (n.after, n.before) {
            (None, None) => None,
            (a, b) => Some((
                a.unwrap_or(DateTime::<Utc>::MIN_UTC),
                b.unwrap_or(DateTime::<Utc>::MAX_UTC),
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

/// **Where the time window is enforced — stated, because it is not where it
/// should be.**
///
/// `AttestationFilter::window` is a v17.4.0 axis and `list_attestations` on
/// sqlite does not read it: its predicate builder emits `attesting_key_id`,
/// `attested_key_id`, `attestation_type`, `pqc_completed`,
/// `dimension_prefixes`, `dimension_exact`, `valid_at`, `confidence_floor`,
/// `subject_key_id` and the scope gate — and nothing for `window`, `tier` or
/// `attester_filter`. Only the `list_scores` / `resolve_scores` handles run the
/// shared builder that does, and those join the subject table, so they cannot
/// serve a general selection.
///
/// This is the same silent-narrowing class `dimension_exact` was in until
/// v17.5.2 (#461): the caller sets a predicate, the substrate returns rows that
/// do not satisfy it, and nothing says so. A preview that silently ignored
/// `after:` would hand an operator a hash over a blast radius twice the size
/// they asked to ratify — so the window IS enforced, in this process, and the
/// response says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEnforcement {
    /// No window was asked for.
    None,
    /// Enforced in this process over the substrate's page, because
    /// `list_attestations` does not honour the axis. The page bound is applied
    /// BEFORE this filter, so a windowed selection can come back short while
    /// [`Preview::truncated`] is set.
    Application,
}

impl WindowEnforcement {
    fn token(self) -> &'static str {
        match self {
            Self::None => "none",
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

    // The page bound is the substrate's; `truncated` is measured BEFORE the
    // window filter, so a short windowed page is never mistaken for a complete
    // one.
    let truncated = i64::try_from(page.items.len()).unwrap_or(i64::MAX) >= limit;
    let n = selection.normalized();
    let window_enforced = if n.after.is_some() || n.before.is_some() {
        WindowEnforcement::Application
    } else {
        WindowEnforcement::None
    };
    let in_window = |a: &ciris_persist::federation::types::Attestation| {
        n.after.is_none_or(|start| a.asserted_at >= start)
            && n.before.is_none_or(|end| a.asserted_at < end)
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
/// Hand-parsed here because persist's own `delegation_scope_set` is
/// `pub(crate)`: there is **no public predicate for "does THIS delegation row
/// carry scope S"**, only the issuer-to-target walk, which answers a different
/// question (see [`resolve_authority`]). This mirrors persist's parse exactly;
/// if it is ever exported, delete this and compose it.
fn delegation_scopes(envelope: &serde_json::Value) -> BTreeSet<String> {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => std::iter::once(s.clone()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => BTreeSet::new(),
    }
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
async fn commit_gate(
    st: &AdminOpsState,
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

    let authority = resolve_authority(&st.engine, &st.node_key_id, &c.delegation_id, scope).await?;
    let mut quorum_roots: BTreeSet<String> = BTreeSet::new();
    quorum_roots.insert(authority.issuer_key_id.clone());
    let mut quorum_delegation_ids = vec![authority.delegation_id.clone()];
    for extra in extra_delegation_ids {
        let proof = resolve_authority(&st.engine, &st.node_key_id, extra, scope).await?;
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

    let preview = run_preview(&st.engine, &st.node_key_id, &c.selection)
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
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
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
    match run_preview(&st.engine, &st.node_key_id, &selection).await {
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
    if let Err(resp) = gate(st, headers).await {
        return resp;
    }
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
    let committed = match commit_gate(st, &c, scope, &[], 1).await {
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
/// Every sanctioned emit helper persist exposes (`emit_attestation_self`,
/// `emit_with_local_signer`, `assemble_and_put`) canonicalizes, signs, assembles
/// **and puts** in one step. There is no assemble-only variant, so the one door
/// built for this op cannot be reached through the chokepoint built to stop
/// hand-rolled rows. This is that hand-rolled row, kept to one function.
async fn build_marker(
    engine: &Arc<Engine>,
    subject_key_id: &str,
    envelope: serde_json::Value,
) -> Result<Attestation, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive acting key_id: {e}"))?;
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize marker: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| format!("hybrid-sign marker: {e}"))?;
    let now = Utc::now();
    Ok(Attestation {
        attestation_id: crate::ids::new_id(),
        attesting_key_id: key_id.clone(),
        attested_key_id: subject_key_id.to_owned(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id,
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

/// Shared body for quarantine + un-quarantine: same gates, different marker.
async fn quarantine_op(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    release: bool,
) -> Response {
    if let Err(resp) = gate(st, headers).await {
        return resp;
    }
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
    let committed = match commit_gate(st, &c, REQUIRED_SCOPE_QUARANTINE, &[], 1).await {
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
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
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
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
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
    let committed = match commit_gate(&st, &c, REQUIRED_SCOPE_DEADMIT, &[], 1).await {
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
            Err(e) => results.push(serde_json::json!({
                "target_key_id": target, "outcome": "error", "error": e,
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
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let revoking_key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive acting key_id: {e}"))?;
    let mut envelope = serde_json::json!({
        "revoked_key_id": revoked_key_id,
        "revoking_key_id": revoking_key_id,
        "reason": reason,
        "delegation_id": delegation_id,
        "effective_at": now.to_rfc3339(),
    });
    if let Some(bound) = revoked_after {
        envelope[ciris_persist::federation::register::REVOKED_AFTER_ENVELOPE_FIELD] =
            serde_json::json!(bound.to_rfc3339());
    }
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize revocation: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| format!("hybrid-sign revocation: {e}"))?;
    let revocation = Revocation {
        revocation_id: crate::ids::new_id(),
        revoked_key_id: revoked_key_id.to_owned(),
        revoking_key_id: revoking_key_id.clone(),
        reason: Some(reason.to_owned()),
        revoked_at: now,
        effective_at: now,
        revocation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: revoking_key_id,
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        observed_region: ciris_persist::federation::verify_coord::region::US.to_owned(),
        revoked_after,
        persist_row_hash: String::new(),
    };
    let id = revocation.revocation_id.clone();
    engine
        .federation_directory()
        .put_revocation(SignedRevocation { revocation })
        .await
        .map_err(|e| e.to_string())?;
    Ok(id)
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
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
    let now = Utc::now();
    let mut standings = serde_json::Map::new();
    let mut errors = serde_json::Map::new();
    for &act in SelfAct::ALL {
        let fold = match read_self_axis(&st.engine, &st.node_key_id, act, now).await {
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
        "node_key_id": st.node_key_id,
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
    let proof = resolve_authority(
        &st.engine,
        &st.node_key_id,
        delegation_id,
        REQUIRED_SCOPE_SELF_DIRECTED,
    )
    .await?;
    let Some(owner) = is_steward_bound(&st.engine, &st.node_key_id).await else {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "node_unowned",
            "admin.refusal.node_unowned",
            "This node has no responsible party (owner-binding), so it performs no graded \
             admin operation on anyone's behalf. Claim ownership first.",
        ));
    };
    if proof.issuer_key_id != owner {
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
        &st.node_key_id,
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
    let standing = match read_self_axis(&st.engine, &st.node_key_id, act, now).await {
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
    match run_reader_fold(&st.engine, &st.node_key_id, subject, Utc::now()).await {
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
    match run_reader_fold(&st.engine, &st.node_key_id, subject, now).await {
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

/// The graded admin-op router. `node_key_id` is THIS node's #247 DERIVED
/// federation key id — the ACTING key whose delegated authority every op
/// re-walks, and the identity `emit_attestation_self` / `sign_hybrid` sign as.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    let state = AdminOpsState {
        engine,
        node_key_id,
    };
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
